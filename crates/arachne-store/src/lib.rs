//! Encrypted, atomic local records. No transport, group protocol or payload types.
//! The host supplies a private directory, protected root key and expected scope.
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use zeroize::Zeroizing;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
/// None deletes a record. An empty value is a valid stored value.
pub type Change<'a> = (&'a [u8], Option<&'a [u8]>);
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;
/// The one store file format this build reads and writes. It is kept in
/// SQLite `user_version` and in the authenticated head, so a changed header
/// fails authentication. An older format needs a migration in
/// `MIGRATIONS`; there is none, because format 1 is the first.
pub const STORE_FORMAT: u32 = 1;
/// `MIGRATIONS[n]` upgrades format `n + 1` to `n + 2` in place.
const MIGRATIONS: &[fn(&Connection) -> Result<()>] = &[];
const _: () = assert!(MIGRATIONS.len() + 1 == STORE_FORMAT as usize);
const HEAD_BYTES: usize = 4 + 8 + 32;
const MAX_KEY_BYTES: usize = 1024;
const OVERHEAD: usize = 12 + 16;
const RECORD_SCHEMA: &str =
    "CREATE TABLE records (name BLOB PRIMARY KEY, sealed BLOB NOT NULL) WITHOUT ROWID";
const HEAD_SCHEMA: &str =
    "CREATE TABLE head (id INTEGER PRIMARY KEY CHECK(id=0), sealed BLOB NOT NULL)";
pub(crate) type Index = BTreeMap<Vec<u8>, [u8; 32]>;

/// A store file in a format this build does not read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FormatNotSupported {
    pub found: u32,
    pub supported: u32,
}

impl std::fmt::Display for FormatNotSupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.found > self.supported {
            write!(
                f,
                "record store format {} is newer than supported format {}",
                self.found, self.supported
            )
        } else {
            write!(
                f,
                "record store format {} is not supported (supported format {}; no legacy reader)",
                self.found, self.supported
            )
        }
    }
}

impl std::error::Error for FormatNotSupported {}

#[cfg(test)]
thread_local! {
    /// Test hook: the next `create` stops after its file exists and before
    /// the store is initialized, as a crash would.
    pub(crate) static FAIL_CREATE_AFTER_FILE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// Caller-owned proof of the accepted record head. Persist it outside the
/// store when rollback detection must survive a whole-file restore.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreshnessAnchor {
    pub revision: u64,
    pub digest: [u8; 32],
}

impl FreshnessAnchor {
    /// Big-endian revision followed by the digest; stable for host storage and FFI.
    pub const ENCODED_LEN: usize = 40;

    pub fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0; Self::ENCODED_LEN];
        bytes[..8].copy_from_slice(&self.revision.to_be_bytes());
        bytes[8..].copy_from_slice(&self.digest);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err("invalid freshness anchor length".into());
        }
        Ok(Self {
            revision: u64::from_be_bytes(bytes[..8].try_into()?),
            digest: bytes[8..].try_into()?,
        })
    }
}

/// One exclusive local owner. Reopen authenticates every retained record before
/// exposing state. Whole-store rollback requires an external anchor to detect.
pub struct Store {
    connection: Connection,
    key: Zeroizing<[u8; 32]>,
    scope: [u8; 32],
    revision: u64,
    index: Index,
}

pub(crate) fn index_digest(index: &Index) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"data-fabric/record-index/v1");
    for (name, digest) in index {
        hash.update((name.len() as u32).to_be_bytes());
        hash.update(name);
        hash.update(digest);
    }
    hash.finalize().into()
}

impl Store {
    /// A new, empty store at `path`. Fails when the file exists.
    ///
    /// Atomic: the store is built in a temporary file in the same directory
    /// and linked into place only when complete. A crash leaves either no
    /// store or a complete one, never an empty file that cannot open.
    pub fn create(path: &Path, root: &[u8; 32], scope: [u8; 32]) -> Result<Self> {
        let directory = path.parent().ok_or("record store path has no directory")?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("invalid record store file name")?;
        let prefix = format!(".{name}.tmp-");
        // Leftovers of a crashed creation are never a store.
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|file| file.starts_with(&prefix))
            {
                std::fs::remove_file(entry.path())?;
            }
        }
        if std::fs::symlink_metadata(path).is_ok() {
            return Err("record store already exists".into());
        }
        let mut suffix = [0; 8];
        getrandom::fill(&mut suffix).map_err(|_| "record randomness failed")?;
        let suffix: String = suffix.iter().map(|byte| format!("{byte:02x}")).collect();
        let temporary = directory.join(format!("{prefix}{suffix}"));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        drop(options.open(&temporary)?);
        let built = (|| -> Result<()> {
            #[cfg(test)]
            if FAIL_CREATE_AFTER_FILE.with(|fail| fail.replace(false)) {
                return Err("injected crash during record store creation".into());
            }
            let store = Self::connect(&temporary, root, scope)?;
            let head = store.seal_head(0, &store.index)?;
            let mut connection = store.connection;
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(RECORD_SCHEMA, [])?;
            tx.execute(HEAD_SCHEMA, [])?;
            tx.execute("INSERT INTO head(id,sealed) VALUES(0,?1)", [&head])?;
            tx.pragma_update(None, "user_version", STORE_FORMAT)?;
            tx.commit()?;
            connection.close().map_err(|(_, error)| error)?;
            std::fs::File::open(&temporary)?.sync_all()?;
            std::fs::hard_link(&temporary, path)?;
            Ok(())
        })();
        #[cfg(test)]
        if let Err(error) = built {
            // A crash would leave the temporary file; the next create removes it.
            return Err(error);
        }
        std::fs::remove_file(&temporary)?;
        built?;
        #[cfg(unix)]
        std::fs::File::open(directory)?.sync_all()?;
        Self::open_existing(path, root, scope)
    }

    /// The existing store at `path`. Never creates a file.
    pub fn open_existing(path: &Path, root: &[u8; 32], scope: [u8; 32]) -> Result<Self> {
        std::fs::metadata(path)?;
        let mut store = Self::connect(path, root, scope)?;
        let found: u32 = store
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if found == 0 || found > STORE_FORMAT {
            return Err(Box::new(FormatNotSupported {
                found,
                supported: STORE_FORMAT,
            }));
        }
        for migration in &MIGRATIONS[found as usize - 1..] {
            migration(&store.connection)?;
        }
        // An untrusted DB must not install triggers that silently alter commits.
        let schema: Vec<(String, String)> = store
            .connection
            .prepare(
                "SELECT name,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY name",
            )?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<std::result::Result<_, _>>()?;
        if schema
            != [
                ("head".into(), HEAD_SCHEMA.into()),
                ("records".into(), RECORD_SCHEMA.into()),
            ]
        {
            return Err("unexpected record store schema".into());
        }
        let sealed: Option<Vec<u8>> = store
            .connection
            .query_row("SELECT sealed FROM head WHERE id=0", [], |row| row.get(0))
            .optional()?;
        let sealed = sealed.ok_or("record head missing")?;
        if sealed.len() != OVERHEAD + HEAD_BYTES {
            return Err("invalid record head".into());
        }
        let head = store.unseal(0, b"", &sealed)?;
        if head[..4] != STORE_FORMAT.to_be_bytes() {
            return Err("record head format differs from the store header".into());
        }
        store.revision = u64::from_be_bytes(head[4..12].try_into()?);
        {
            let mut statement = store
                .connection
                .prepare("SELECT name,sealed FROM records ORDER BY name")?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let name = row.get_ref(0)?.as_blob()?;
                let sealed = row.get_ref(1)?.as_blob()?;
                Self::validate_key(name)?;
                if !(OVERHEAD..=OVERHEAD + MAX_RECORD_BYTES).contains(&sealed.len()) {
                    return Err("invalid encrypted record size".into());
                }
                store
                    .index
                    .insert(name.to_vec(), Sha256::digest(sealed).into());
            }
        }
        if head[12..] != index_digest(&store.index) {
            return Err("record set authentication failed".into());
        }
        Ok(store)
    }

    /// The existing store at `path`, or a new one when it is absent.
    pub fn open(path: &Path, root: &[u8; 32], scope: [u8; 32]) -> Result<Self> {
        if std::fs::symlink_metadata(path).is_ok() {
            Self::open_existing(path, root, scope)
        } else {
            Self::create(path, root, scope)
        }
    }

    /// One exclusive connection with this store's settings and key.
    fn connect(path: &Path, root: &[u8; 32], scope: [u8; 32]) -> Result<Self> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(std::time::Duration::from_millis(100))?;
        connection.set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            (MAX_RECORD_BYTES + MAX_KEY_BYTES + 4096) as i32,
        )?;
        connection.execute_batch(
            "PRAGMA locking_mode=EXCLUSIVE;
             PRAGMA journal_mode=DELETE;
             PRAGMA synchronous=FULL;
             PRAGMA secure_delete=ON;
             PRAGMA trusted_schema=OFF;",
        )?;
        let mut key = Zeroizing::new([0; 32]);
        hkdf::Hkdf::<Sha256>::new(Some(b"data-fabric/record-store/v1"), root)
            .expand(&scope, key.as_mut())
            .map_err(|_| "storage key derivation failed")?;
        Ok(Self {
            connection,
            key,
            scope,
            revision: 0,
            index: Index::new(),
        })
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn freshness(&self) -> FreshnessAnchor {
        FreshnessAnchor {
            revision: self.revision,
            digest: index_digest(&self.index),
        }
    }

    pub fn verify_freshness(&self, expected: FreshnessAnchor) -> Result<()> {
        if self.freshness() != expected {
            return Err("record store freshness anchor mismatch".into());
        }
        Ok(())
    }

    /// Keys from the authenticated accepted index, in byte order. Values still
    /// pass their integrity check when read; no plaintext values are retained here.
    pub fn keys<'a>(&'a self, prefix: &'a [u8]) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.index
            .range(prefix.to_vec()..)
            .take_while(move |(name, _)| name.starts_with(prefix))
            .map(|(name, _)| name.as_slice())
    }

    pub fn get(&self, name: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Self::validate_key(name)?;
        let value: Option<Vec<u8>> = self
            .connection
            .query_row("SELECT sealed FROM records WHERE name=?1", [name], |r| {
                r.get(0)
            })
            .optional()?;
        match (self.index.get(name), value) {
            (None, None) => Ok(None),
            (Some(expected), Some(sealed))
                if *expected == <[u8; 32]>::from(Sha256::digest(&sealed)) =>
            {
                Ok(Some(self.unseal(1, name, &sealed)?))
            }
            _ => Err("record differs from accepted head".into()),
        }
    }

    /// Commit the complete operation before adopting its state or emitting its
    /// packets. A failed commit leaves this owner at the prior revision; if I/O
    /// makes the outcome uncertain, close/reopen before attempting another write.
    pub fn commit(&mut self, expected_revision: u64, changes: &[Change<'_>]) -> Result<u64> {
        self.commit_anchored(expected_revision, changes, &mut |_| Ok(()))
    }

    /// `commit`, but first give the anchor this commit will produce to
    /// `before` (to save it in monotonic storage). If `before` fails,
    /// nothing is committed.
    pub fn commit_anchored(
        &mut self,
        expected_revision: u64,
        changes: &[Change<'_>],
        before: &mut dyn FnMut(FreshnessAnchor) -> Result<()>,
    ) -> Result<u64> {
        if expected_revision != self.revision {
            return Err("stale record revision".into());
        }
        let prior: Vec<u8> =
            self.connection
                .query_row("SELECT sealed FROM head WHERE id=0", [], |row| row.get(0))?;
        let prior = self.unseal(0, b"", &prior)?;
        if prior.len() != HEAD_BYTES
            || prior[..4] != STORE_FORMAT.to_be_bytes()
            || prior[4..12] != self.revision.to_be_bytes()
            || prior[12..] != index_digest(&self.index)
        {
            return Err("record head differs from accepted state".into());
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or("record revision exhausted")?;
        let mut names = BTreeSet::new();
        let mut sealed = Vec::with_capacity(changes.len());
        // ponytail: O(record count) index copy/hash, but only changed ciphertext
        // rows are rewritten; introduce an incremental index if measurement needs it.
        let mut index = self.index.clone();
        for (name, value) in changes {
            Self::validate_key(name)?;
            if !names.insert(*name) {
                return Err("duplicate record change".into());
            }
            let value = match value {
                Some(value) => {
                    if value.len() > MAX_RECORD_BYTES {
                        return Err("record exceeds byte budget".into());
                    }
                    let packet = self.seal(1, name, value)?;
                    index.insert(name.to_vec(), Sha256::digest(&packet).into());
                    Some(packet)
                }
                None => {
                    index.remove(*name);
                    None
                }
            };
            sealed.push((*name, value));
        }
        let head = self.seal_head(revision, &index)?;
        before(FreshnessAnchor {
            revision,
            digest: index_digest(&index),
        })?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for (name, value) in &sealed {
            match value {
                Some(value) => {
                    tx.execute(
                    "INSERT INTO records(name,sealed) VALUES(?1,?2) ON CONFLICT(name) DO UPDATE SET sealed=excluded.sealed",
                    params![name, value],
                )?;
                }
                None => {
                    tx.execute("DELETE FROM records WHERE name=?1", [name])?;
                }
            }
        }
        tx.execute("UPDATE head SET sealed=?1 WHERE id=0", [&head])?;
        tx.commit()?;
        self.index = index;
        self.revision = revision;
        Ok(revision)
    }

    fn validate_key(name: &[u8]) -> Result<()> {
        if name.is_empty() || name.len() > MAX_KEY_BYTES {
            return Err("invalid record key".into());
        }
        Ok(())
    }
    fn aad(&self, kind: u8, name: &[u8]) -> Vec<u8> {
        let mut aad = b"data-fabric/record/v1".to_vec();
        aad.extend(self.scope);
        aad.push(kind);
        aad.extend((name.len() as u32).to_be_bytes());
        aad.extend(name);
        aad
    }
    fn seal_head(&self, revision: u64, index: &Index) -> Result<Vec<u8>> {
        let mut plain = Zeroizing::new(STORE_FORMAT.to_be_bytes().to_vec());
        plain.extend(revision.to_be_bytes());
        plain.extend(index_digest(index));
        self.seal(0, b"", &plain)
    }
    fn seal(&self, kind: u8, name: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0; 12];
        getrandom::fill(&mut nonce).map_err(|_| "record randomness failed")?;
        let cipher =
            Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| "invalid storage key")?;
        let mut packet = nonce.to_vec();
        packet.extend(
            cipher
                .encrypt(
                    (&nonce).into(),
                    Payload {
                        msg: plain,
                        aad: &self.aad(kind, name),
                    },
                )
                .map_err(|_| "record protection failed")?,
        );
        Ok(packet)
    }
    fn unseal(&self, kind: u8, name: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if sealed.len() < OVERHEAD {
            return Err("truncated encrypted record".into());
        }
        let cipher =
            Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| "invalid storage key")?;
        let nonce: &[u8; 12] = sealed[..12].try_into()?;
        Ok(Zeroizing::new(
            cipher
                .decrypt(
                    nonce.into(),
                    Payload {
                        msg: &sealed[12..],
                        aad: &self.aad(kind, name),
                    },
                )
                .map_err(|_| "record authentication failed")?,
        ))
    }
}

mod provider;
pub use provider::{
    AnchorSlots, AnchorStore, MemoryAnchors, MemoryProvider, SqliteProvider, Storage,
    StorageProvider,
};

#[cfg(test)]
mod tests;
