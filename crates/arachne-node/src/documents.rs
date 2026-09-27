//! Iroh Docs handlers and the Core-only workspace floor snapshot seam.
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use futures_util::StreamExt;
use iroh::{Endpoint, EndpointAddr, endpoint::Connection, protocol::ProtocolHandler};
use iroh_blobs::{
    BlobsProtocol,
    api::Store,
    store::{fs::FsStore, mem::MemStore},
};
use iroh_docs::{Author, Capability, NamespaceSecret, api::Doc, protocol::Docs, store::Query};
use iroh_gossip::net::Gossip;
use tokio::sync::Mutex;

use crate::{Error, PeerId, Result, WorkspaceId};

const FLOOR_KEY_PREFIX: &[u8] = b"\0arachne/ptt-floor/v1\0";
const MAX_FLOOR_KEY: usize = 128;
const MAX_FLOOR_VALUE: usize = 8 * 1024;
const MAX_FLOOR_RECORDS: u64 = 512;
// ponytail: retry polled reads at 1 Hz; use sync-failure events if faster recovery is needed.
const SYNC_RETRY_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FloorDocumentEntry {
    pub author: PeerId,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

struct Scope {
    workspace: WorkspaceId,
    revision: u64,
    doc: Doc,
    members: Vec<PeerId>,
    sync_peers: Vec<iroh::EndpointAddr>,
    last_sync: Instant,
}

#[derive(Clone)]
pub(super) struct Documents {
    docs: Docs,
    gossip: Gossip,
    blobs: Store,
    author: Author,
    scope: Arc<Mutex<Option<Scope>>>,
}

impl Documents {
    pub(super) async fn new(endpoint: Endpoint, path: Option<PathBuf>) -> Result<Self> {
        let (blobs, docs) = if let Some(path) = path {
            let blobs_path = path.join("blobs");
            let docs_path = path.join("docs");
            std::fs::create_dir_all(&blobs_path).map_err(transport)?;
            std::fs::create_dir_all(&docs_path).map_err(transport)?;
            let blobs = FsStore::load(blobs_path).await.map_err(transport)?;
            ((*blobs).clone(), Docs::persistent(docs_path))
        } else {
            let blobs = MemStore::default();
            ((*blobs).clone(), Docs::memory())
        };
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let docs = docs
            .spawn(endpoint.clone(), blobs.clone(), gossip.clone())
            .await
            .map_err(transport)?;
        let author = Author::from_bytes(&endpoint.secret_key().to_bytes());
        docs.author_import(author.clone())
            .await
            .map_err(transport)?;
        Ok(Self {
            docs,
            gossip,
            blobs,
            author,
            scope: Arc::new(Mutex::new(None)),
        })
    }

    pub(super) async fn configure(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        namespace_key: &[u8; 32],
        members: Vec<PeerId>,
        peers: Vec<EndpointAddr>,
    ) -> Result<()> {
        let secret = NamespaceSecret::from_bytes(namespace_key);
        let namespace = secret.id();
        let mut scope = self.scope.lock().await;
        if let Some(current) = scope.as_mut()
            && current.workspace == workspace
            && current.revision == revision
            && current.doc.id() == namespace
        {
            current.members = members;
            sync_scope(current, peers).await?;
            return Ok(());
        }

        let doc = self
            .docs
            .import_namespace(Capability::Write(secret))
            .await
            .map_err(transport)?;
        doc.start_sync(peers.clone()).await.map_err(transport)?;
        if let Some(old) = scope.take() {
            let old_id = old.doc.id();
            let _ = old.doc.leave().await;
            self.docs.drop_doc(old_id).await.map_err(transport)?;
        }
        *scope = Some(Scope {
            workspace,
            revision,
            doc,
            members,
            sync_peers: peers,
            last_sync: Instant::now(),
        });
        Ok(())
    }

    pub(super) async fn sync_peers(&self, peers: Vec<EndpointAddr>) -> Result<()> {
        if let Some(scope) = self.scope.lock().await.as_mut() {
            sync_scope(scope, peers).await?;
        }
        Ok(())
    }

    pub(super) async fn scope_members(&self) -> Option<(WorkspaceId, u64, Vec<PeerId>)> {
        self.scope
            .lock()
            .await
            .as_ref()
            .map(|scope| (scope.workspace, scope.revision, scope.members.clone()))
    }

    pub(super) async fn invalidate_if_mismatched(
        &self,
        workspace: WorkspaceId,
        revision: u64,
    ) -> Result<()> {
        let mut scope = self.scope.lock().await;
        if scope
            .as_ref()
            .is_some_and(|current| current.workspace != workspace || current.revision != revision)
        {
            if let Some(old) = scope.take() {
                let id = old.doc.id();
                let _ = old.doc.leave().await;
                self.docs.drop_doc(id).await.map_err(transport)?;
            }
        }
        Ok(())
    }

    pub(super) async fn write(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        if key.is_empty() || key.len() > MAX_FLOOR_KEY || value.len() > MAX_FLOOR_VALUE {
            return Err(Error::TooLarge);
        }
        let scope = self.scope.lock().await;
        let scope = current_scope(scope.as_ref(), workspace, revision)?;
        scope
            .doc
            .set_bytes(
                self.author.id(),
                storage_key(self.author.id().as_bytes(), key),
                value.to_vec(),
            )
            .await
            .map_err(transport)?;
        Ok(())
    }

    pub(super) async fn read(
        &self,
        workspace: WorkspaceId,
        revision: u64,
    ) -> Result<Vec<FloorDocumentEntry>> {
        let scope = self.scope.lock().await;
        let scope = current_scope(scope.as_ref(), workspace, revision)?;
        let query = Query::single_latest_per_key()
            .key_prefix(FLOOR_KEY_PREFIX)
            .limit(MAX_FLOOR_RECORDS + 1);
        let entries = scope.doc.get_many(query).await.map_err(transport)?;
        tokio::pin!(entries);
        let mut result = Vec::new();
        while let Some(entry) = entries.next().await {
            let entry = entry.map_err(transport)?;
            let key = entry.key();
            let start = FLOOR_KEY_PREFIX.len();
            let end = start + 32;
            if key.len() <= end + 1 || !key.starts_with(FLOOR_KEY_PREFIX) || key[end] != b'/' {
                return Err(Error::InvalidFrame);
            }
            let author: PeerId = key[start..end]
                .try_into()
                .map_err(|_| Error::InvalidFrame)?;
            let value = self
                .blobs
                .get_bytes(entry.content_hash())
                .await
                .map_err(transport)?;
            if value.len() > MAX_FLOOR_VALUE {
                return Err(Error::TooLarge);
            }
            result.push(FloorDocumentEntry {
                author: entry.author().to_bytes(),
                key: key[end + 1..].to_vec(),
                value: value.to_vec(),
            });
            if author != result.last().unwrap().author {
                return Err(Error::InvalidFrame);
            }
            if result.len() > MAX_FLOOR_RECORDS as usize {
                return Err(Error::TooLarge);
            }
        }
        Ok(result)
    }

    pub(super) async fn handle_docs(&self, connection: Connection) -> Result<()> {
        self.docs.accept(connection).await.map_err(transport)
    }

    pub(super) async fn handle_blobs(&self, connection: Connection) -> Result<()> {
        BlobsProtocol::new(&self.blobs, None)
            .accept(connection)
            .await
            .map_err(transport)
    }

    pub(super) async fn handle_gossip(&self, connection: Connection) -> Result<()> {
        self.gossip
            .handle_connection(connection)
            .await
            .map_err(transport)
    }

    pub(super) async fn close(&self) {
        if let Some(scope) = self.scope.lock().await.take() {
            let _ = scope.doc.leave().await;
        }
        self.docs.shutdown().await;
        if let Err(error) = self.blobs.shutdown().await {
            tracing::debug!(%error, "Docs Blobs store shutdown failed");
        }
        if let Err(error) = self.gossip.shutdown().await {
            tracing::debug!(%error, "Docs Gossip shutdown failed");
        }
    }
}

fn current_scope<'a>(
    scope: Option<&'a Scope>,
    workspace: WorkspaceId,
    revision: u64,
) -> Result<&'a Scope> {
    scope
        .filter(|scope| scope.workspace == workspace && scope.revision == revision)
        .ok_or(Error::Rejected)
}

async fn sync_scope(scope: &mut Scope, peers: Vec<EndpointAddr>) -> Result<()> {
    if scope.sync_peers == peers && scope.last_sync.elapsed() < SYNC_RETRY_INTERVAL {
        return Ok(());
    }
    scope.last_sync = Instant::now();
    scope.sync_peers = peers.clone();
    scope.doc.start_sync(peers).await.map_err(transport)?;
    Ok(())
}

fn storage_key(author: &[u8; 32], key: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(FLOOR_KEY_PREFIX.len() + 33 + key.len());
    result.extend_from_slice(FLOOR_KEY_PREFIX);
    result.extend_from_slice(author);
    result.push(b'/');
    result.extend_from_slice(key);
    result
}

fn transport(error: impl std::fmt::Display) -> Error {
    Error::Transport(error.to_string())
}
