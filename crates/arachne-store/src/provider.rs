//! The `Storage` seam: one record store per workspace scope. The runtime
//! owns save, read back and adopt; a provider only opens and creates stores.
//! `SqliteProvider` is the default. `MemoryProvider` keeps stores in process
//! memory for tests and can inject faults.
use crate::{Change, FreshnessAnchor, Index, MAX_RECORD_BYTES, Result, Store, index_digest};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use zeroize::Zeroizing;

/// One authenticated record store. `commit` is all or nothing.
pub trait Storage: Send {
    fn revision(&self) -> u64;
    fn freshness(&self) -> FreshnessAnchor;
    /// Keys from the accepted index with `prefix`, in byte order.
    fn keys(&self, prefix: &[u8]) -> Vec<Vec<u8>>;
    fn get(&self, name: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn commit(&mut self, expected_revision: u64, changes: &[Change<'_>]) -> Result<u64>;
}

impl Storage for Store {
    fn revision(&self) -> u64 {
        Store::revision(self)
    }
    fn freshness(&self) -> FreshnessAnchor {
        Store::freshness(self)
    }
    fn keys(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        Store::keys(self, prefix).map(<[u8]>::to_vec).collect()
    }
    fn get(&self, name: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Store::get(self, name)
    }
    fn commit(&mut self, expected_revision: u64, changes: &[Change<'_>]) -> Result<u64> {
        Store::commit(self, expected_revision, changes)
    }
}

/// Opens the one store of a scope (a workspace ID).
pub trait StorageProvider: Send + Sync {
    /// The existing store of `scope`, or `None` when none was created.
    fn open(&self, scope: [u8; 32]) -> Result<Option<Box<dyn Storage>>>;
    /// A new, empty store of `scope`. Fails when one exists.
    fn create(&self, scope: [u8; 32]) -> Result<Box<dyn Storage>>;
}

/// Encrypted SQLite files in a private host directory, one per scope. The
/// root key is the host's storage root; it is not the endpoint secret.
pub struct SqliteProvider {
    directory: PathBuf,
    root: Zeroizing<[u8; 32]>,
}

impl SqliteProvider {
    pub fn new(directory: &Path, root: [u8; 32]) -> Self {
        Self {
            directory: directory.to_path_buf(),
            root: Zeroizing::new(root),
        }
    }

    /// The file of `scope`: `<directory>/<hex scope>.arachne`.
    pub fn path(&self, scope: [u8; 32]) -> PathBuf {
        let name: String = scope.iter().map(|byte| format!("{byte:02x}")).collect();
        self.directory.join(format!("{name}.arachne"))
    }
}

impl StorageProvider for SqliteProvider {
    fn open(&self, scope: [u8; 32]) -> Result<Option<Box<dyn Storage>>> {
        let path = self.path(scope);
        match std::fs::metadata(&path) {
            Ok(_) => Ok(Some(Box::new(Store::open_existing(&path, &self.root, scope)?))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    fn create(&self, scope: [u8; 32]) -> Result<Box<dyn Storage>> {
        Ok(Box::new(Store::create(&self.path(scope), &self.root, scope)?))
    }
}

#[derive(Clone, Default)]
struct Records {
    revision: u64,
    values: BTreeMap<Vec<u8>, Zeroizing<Vec<u8>>>,
}

#[derive(Default)]
struct Shared {
    stores: Mutex<BTreeMap<[u8; 32], Arc<Mutex<Records>>>>,
    fail_commit: AtomicBool,
    corrupt_reads: AtomicBool,
}

/// Stores in process memory. Clones share the stores, so a test can close a
/// client and restore the same state in a new one. Not durable.
#[derive(Clone, Default)]
pub struct MemoryProvider(Arc<Shared>);

impl MemoryProvider {
    /// The next commit of any store fails and changes nothing.
    pub fn fail_next_commit(&self) {
        self.0.fail_commit.store(true, Ordering::SeqCst);
    }
    /// Reads return a value that differs from the one committed.
    pub fn corrupt_reads(&self, on: bool) {
        self.0.corrupt_reads.store(on, Ordering::SeqCst);
    }
    /// The committed value of a record, for tests that inspect storage.
    pub fn value(&self, scope: [u8; 32], name: &[u8]) -> Option<Vec<u8>> {
        let stores = self.0.stores.lock().ok()?;
        let records = stores.get(&scope)?.lock().ok()?;
        records.values.get(name).map(|value| value.to_vec())
    }
    /// Replace one record without a commit, as an attacker or a disk fault can.
    pub fn tamper(&self, scope: [u8; 32], name: &[u8], value: Option<&[u8]>) {
        if let Some(records) = self.0.stores.lock().unwrap().get(&scope) {
            let mut records = records.lock().unwrap();
            match value {
                Some(value) => records.values.insert(name.to_vec(), Zeroizing::new(value.to_vec())),
                None => records.values.remove(name),
            };
        }
    }
}

struct MemoryStorage {
    shared: Arc<Shared>,
    records: Arc<Mutex<Records>>,
}

impl MemoryStorage {
    fn records(&self) -> std::sync::MutexGuard<'_, Records> {
        self.records.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Storage for MemoryStorage {
    fn revision(&self) -> u64 {
        self.records().revision
    }
    fn freshness(&self) -> FreshnessAnchor {
        let records = self.records();
        let index: Index = records
            .values
            .iter()
            .map(|(name, value)| (name.clone(), Sha256::digest(value.as_slice()).into()))
            .collect();
        FreshnessAnchor {
            revision: records.revision,
            digest: index_digest(&index),
        }
    }
    fn keys(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        self.records()
            .values
            .keys()
            .filter(|name| name.starts_with(prefix))
            .cloned()
            .collect()
    }
    fn get(&self, name: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let mut value = self.records().values.get(name).cloned();
        if self.shared.corrupt_reads.load(Ordering::SeqCst)
            && let Some(value) = &mut value
        {
            value.push(0xa5);
        }
        Ok(value)
    }
    fn commit(&mut self, expected_revision: u64, changes: &[Change<'_>]) -> Result<u64> {
        let mut records = self.records();
        if expected_revision != records.revision {
            return Err("stale record revision".into());
        }
        if self.shared.fail_commit.swap(false, Ordering::SeqCst) {
            return Err("injected commit failure".into());
        }
        let mut next = records.clone();
        let mut names = std::collections::BTreeSet::new();
        for (name, value) in changes {
            if name.is_empty() || !names.insert(*name) {
                return Err("invalid record change".into());
            }
            match value {
                Some(value) if value.len() > MAX_RECORD_BYTES => {
                    return Err("record exceeds byte budget".into());
                }
                Some(value) => {
                    next.values
                        .insert(name.to_vec(), Zeroizing::new(value.to_vec()));
                }
                None => {
                    next.values.remove(*name);
                }
            }
        }
        next.revision = records
            .revision
            .checked_add(1)
            .ok_or("record revision exhausted")?;
        *records = next;
        Ok(records.revision)
    }
}

impl StorageProvider for MemoryProvider {
    fn open(&self, scope: [u8; 32]) -> Result<Option<Box<dyn Storage>>> {
        let stores = self.0.stores.lock().map_err(|_| "memory storage poisoned")?;
        Ok(stores.get(&scope).map(|records| {
            Box::new(MemoryStorage {
                shared: Arc::clone(&self.0),
                records: Arc::clone(records),
            }) as Box<dyn Storage>
        }))
    }
    fn create(&self, scope: [u8; 32]) -> Result<Box<dyn Storage>> {
        let mut stores = self.0.stores.lock().map_err(|_| "memory storage poisoned")?;
        if stores.contains_key(&scope) {
            return Err("record store already exists".into());
        }
        let records = Arc::new(Mutex::new(Records::default()));
        stores.insert(scope, Arc::clone(&records));
        Ok(Box::new(MemoryStorage {
            shared: Arc::clone(&self.0),
            records,
        }))
    }
}
