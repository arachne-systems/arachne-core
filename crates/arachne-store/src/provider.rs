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
    /// Commit `changes`, first giving `before` the anchor the commit will
    /// produce. If `before` fails, nothing is committed.
    fn commit_anchored(
        &mut self,
        expected_revision: u64,
        changes: &[Change<'_>],
        before: &mut dyn FnMut(FreshnessAnchor) -> Result<()>,
    ) -> Result<u64>;
    fn commit(&mut self, expected_revision: u64, changes: &[Change<'_>]) -> Result<u64> {
        self.commit_anchored(expected_revision, changes, &mut |_| Ok(()))
    }
}

/// The freshness anchors of one scope in the host's monotonic storage (for
/// example a hardware-backed keystore or counter). `current` is the anchor of
/// the last confirmed commit; `next` is set just before a commit and names
/// the state that commit produces, so a crash between the commit and its
/// confirmation still restores.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorSlots {
    pub current: FreshnessAnchor,
    pub next: Option<FreshnessAnchor>,
}

impl AnchorSlots {
    /// Whether a store with `anchor` is the latest one these slots allow.
    pub fn accepts(&self, anchor: FreshnessAnchor) -> bool {
        anchor == self.current || self.next == Some(anchor)
    }
}

/// Host storage that an attacker who replaces the database files cannot roll
/// back. With it, restore requires a matching anchor.
pub trait AnchorStore: Send + Sync {
    fn load(&self, scope: [u8; 32]) -> Result<Option<AnchorSlots>>;
    fn save(&self, scope: [u8; 32], slots: AnchorSlots) -> Result<()>;
}

/// Anchors in process memory (tests), with a fault switch.
#[derive(Default)]
pub struct MemoryAnchors {
    slots: Mutex<BTreeMap<[u8; 32], AnchorSlots>>,
    fail_confirmations: AtomicBool,
}

impl MemoryAnchors {
    /// Saves that confirm a commit (no `next` slot) fail while on.
    pub fn fail_confirmations(&self, on: bool) {
        self.fail_confirmations.store(on, Ordering::SeqCst);
    }
}

impl AnchorStore for MemoryAnchors {
    fn load(&self, scope: [u8; 32]) -> Result<Option<AnchorSlots>> {
        Ok(self
            .slots
            .lock()
            .map_err(|_| "anchor storage poisoned")?
            .get(&scope)
            .copied())
    }
    fn save(&self, scope: [u8; 32], slots: AnchorSlots) -> Result<()> {
        if slots.next.is_none() && self.fail_confirmations.load(Ordering::SeqCst) {
            return Err("injected anchor confirmation failure".into());
        }
        self.slots
            .lock()
            .map_err(|_| "anchor storage poisoned")?
            .insert(scope, slots);
        Ok(())
    }
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
    fn commit_anchored(
        &mut self,
        expected_revision: u64,
        changes: &[Change<'_>],
        before: &mut dyn FnMut(FreshnessAnchor) -> Result<()>,
    ) -> Result<u64> {
        Store::commit_anchored(self, expected_revision, changes, before)
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

struct Shared {
    stores: Mutex<BTreeMap<[u8; 32], Arc<Mutex<Records>>>>,
    fail_commit: AtomicBool,
    corrupt_reads: AtomicBool,
    root: Zeroizing<[u8; 32]>,
}

/// Stores in process memory. Clones share the stores, so a test can close a
/// client and restore the same state in a new one. Not durable.
#[derive(Clone)]
pub struct MemoryProvider(Arc<Shared>);

impl Default for MemoryProvider {
    fn default() -> Self {
        let mut root = Zeroizing::new([0; 32]);
        getrandom::fill(root.as_mut()).expect("randomness for a memory storage root");
        Self(Arc::new(Shared {
            stores: Mutex::default(),
            fail_commit: AtomicBool::new(false),
            corrupt_reads: AtomicBool::new(false),
            root,
        }))
    }
}

impl MemoryProvider {
    /// The storage root of these stores: random, shared by clones.
    pub fn root(&self) -> [u8; 32] {
        *self.0.root
    }

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

fn anchor_of(records: &Records) -> FreshnessAnchor {
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
        anchor_of(&self.records())
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
    fn commit_anchored(
        &mut self,
        expected_revision: u64,
        changes: &[Change<'_>],
        before: &mut dyn FnMut(FreshnessAnchor) -> Result<()>,
    ) -> Result<u64> {
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
        before(anchor_of(&next))?;
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
