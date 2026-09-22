//! Authorized immutable byte transfers. Catalogs and recipient grants belong to
//! the caller; this module binds a short-lived read capability to a verified
//! workspace endpoint and runs the standard iroh-blobs range/verification engine.
//! No file bytes enter the message journal and no file-size ceiling is imposed.
use std::{
    collections::{BTreeMap, HashSet},
    io,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use arachne_routing::RoutingTable;
use futures_util::StreamExt;
use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use iroh_blobs::{
    Hash,
    api::{
        TempTag,
        blobs::{AddPathOptions, ExportMode, ExportOptions, ImportMode},
        remote::GetProgressItem,
    },
    get,
    protocol::Request,
    provider::{self, events::EventSender},
    store::{fs::FsStore, gc_run_once},
    util::{RecvStream as BlobReader, SendStream as BlobWriter},
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OnceCell, Semaphore, watch};

use crate::{ALPN, Error, PeerId, Result, WorkspaceId, connections::Connections, transport};

pub(crate) const STREAM_KIND: u8 = 1;
const ADMISSION_LIFETIME: Duration = Duration::from_secs(120);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Transmitted only inside an authenticated, recipient-scoped application
/// message. The hash identifies bytes; neither a hash nor this token alone is
/// authority. Serving also requires the bound endpoint and current membership.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceTicket {
    pub hash: [u8; 32],
    pub size: u64,
    pub grant: [u8; 32],
}

struct ReadGrant {
    workspace: WorkspaceId,
    revision: u64,
    peer: PeerId,
    path: PathBuf,
    expires: Instant,
    tag: TempTag,
}

struct Shared {
    connections: Connections,
    routing: Arc<Mutex<RoutingTable>>,
    store: OnceCell<(PathBuf, FsStore)>,
    grants: StdMutex<BTreeMap<[u8; 32], Arc<ReadGrant>>>,
    changed: watch::Sender<u64>,
    serving: Semaphore,
    downloading: Mutex<()>,
    collecting: Mutex<()>,
    closed: AtomicBool,
}

#[derive(Clone)]
pub struct ResourceTransfers(Arc<Shared>);

impl ResourceTransfers {
    pub(crate) fn new(connections: Connections, routing: Arc<Mutex<RoutingTable>>) -> Self {
        Self(Arc::new(Shared {
            connections,
            routing,
            store: OnceCell::new(),
            grants: StdMutex::new(BTreeMap::new()),
            changed: watch::channel(0).0,
            serving: Semaphore::new(4),
            downloading: Mutex::new(()),
            collecting: Mutex::new(()),
            closed: AtomicBool::new(false),
        }))
    }

    async fn store(&self, root: &Path) -> Result<FsStore> {
        if !root.is_absolute() {
            return Err(Error::Rejected);
        }
        let (path, store) = self
            .0
            .store
            .get_or_try_init(|| async {
                let store = FsStore::load(root).await.map_err(transport)?;
                // One resumable partial per workspace. Unreferenced old import
                // indexes/outboards are reclaimed; immutable source files are external.
                gc_run_once(&store, &mut HashSet::new())
                    .await
                    .map_err(transport)?;
                Ok::<_, Error>((root.to_owned(), store))
            })
            .await?;
        if path != root {
            return Err(Error::Rejected);
        }
        Ok(store.clone())
    }

    async fn authorize(&self, workspace: WorkspaceId, revision: u64, peer: PeerId) -> Result<()> {
        if self.0.closed.load(Ordering::Acquire) {
            return Err(Error::Rejected);
        }
        let routing = self.0.routing.lock().await;
        routing.authorizes_endpoint(workspace, revision, self.0.connections.id())?;
        routing.authorizes_endpoint(workspace, revision, peer)?;
        Ok(())
    }

    /// Caller has already checked this resource's public/direct audience. The
    /// source must be an application-owned immutable snapshot, not a live file.
    pub async fn prepare(
        &self,
        root: &Path,
        path: &Path,
        workspace: WorkspaceId,
        revision: u64,
        peer: PeerId,
    ) -> Result<ResourceTicket> {
        let generation = *self.0.changed.borrow();
        self.authorize(workspace, revision, peer).await?;
        if !path.is_absolute() {
            return Err(Error::Rejected);
        }
        let metadata = tokio::fs::metadata(path).await.map_err(transport)?;
        if !metadata.is_file() {
            return Err(Error::Rejected);
        }
        let store = self.store(root).await?;
        let tag = store
            .add_path_with_opts(AddPathOptions {
                path: path.to_owned(),
                mode: ImportMode::TryReference,
                format: iroh_blobs::BlobFormat::Raw,
            })
            .temp_tag()
            .await
            .map_err(transport)?;
        self.authorize(workspace, revision, peer).await?;
        let mut token = [0; 32];
        getrandom::fill(&mut token).map_err(transport)?;
        let ticket = ResourceTicket {
            hash: *tag.hash().as_bytes(),
            size: metadata.len(),
            grant: token,
        };
        {
            let mut grants = self.0.grants.lock().unwrap();
            if generation != *self.0.changed.borrow() {
                return Err(Error::Rejected);
            }
            grants
                .retain(|_, grant| grant.expires > Instant::now() || Arc::strong_count(grant) > 1);
            if grants.len() >= 64 {
                return Err(Error::Backpressure);
            }
            grants.insert(
                token,
                Arc::new(ReadGrant {
                    workspace,
                    revision,
                    peer,
                    path: path.to_owned(),
                    expires: Instant::now() + ADMISSION_LIFETIME,
                    tag,
                }),
            );
        }
        self.collect(&store).await?;
        Ok(ticket)
    }

    /// Withdraw before deleting a source, or pass None when serving preferences
    /// change. Active streams are cancelled too, not just future admissions.
    pub fn revoke(&self, path: Option<&Path>) {
        let mut grants = self.0.grants.lock().unwrap();
        grants.retain(|_, grant| path.is_some_and(|path| grant.path != path));
        self.policy_changed();
    }

    pub(crate) fn policy_changed(&self) {
        self.0
            .changed
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }

    async fn collect(&self, store: &FsStore) -> Result<()> {
        let _serial = self.0.collecting.lock().await;
        gc_run_once(store, &mut HashSet::new())
            .await
            .map_err(transport)
    }

    async fn admitted(&self, token: &[u8; 32], grant: &ReadGrant) -> Result<()> {
        self.authorize(grant.workspace, grant.revision, grant.peer)
            .await?;
        if !self.0.grants.lock().unwrap().contains_key(token) {
            return Err(Error::Rejected);
        }
        Ok(())
    }

    pub(crate) async fn serve(
        &self,
        connection: &Connection,
        send: &mut SendStream,
        recv: &mut RecvStream,
    ) -> Result<()> {
        let _slot = self
            .0
            .serving
            .try_acquire()
            .map_err(|_| Error::Backpressure)?;
        let mut changes = self.0.changed.subscribe();
        let mut token = [0; 32];
        tokio::time::timeout(crate::TIMEOUT, recv.read_exact(&mut token))
            .await
            .map_err(|_| Error::Timeout("resource admission"))?
            .map_err(transport)?;
        let grant = self
            .0
            .grants
            .lock()
            .unwrap()
            .get(&token)
            .cloned()
            .ok_or(Error::Rejected)?;
        if grant.peer != *connection.remote_id().as_bytes() || grant.expires <= Instant::now() {
            return Err(Error::Rejected);
        }
        self.admitted(&token, &grant).await?;
        let (_, store) = self.0.store.get().ok_or(Error::Rejected)?;
        let mut pair = provider::StreamPair::new(
            connection.stable_id() as u64,
            SizedReader {
                inner: recv,
                size: None,
                header: [0; 8],
                read: 0,
            },
            IdleWriter(send),
            EventSender::default(),
        );
        let request = tokio::time::timeout(crate::TIMEOUT, pair.read_request())
            .await
            .map_err(|_| Error::Timeout("blob request"))?
            .map_err(transport)?;
        let Request::Get(request) = request else {
            return Err(Error::Rejected);
        };
        // No push, collections, observe or get-many surface. A grant covers only
        // one raw immutable blob, including its authenticated resume ranges.
        if request.hash != grant.tag.hash() || !request.ranges.is_blob() {
            return Err(Error::Rejected);
        }
        let transfer = provider::handle_get(pair, store.as_ref().clone(), request);
        tokio::pin!(transfer);
        loop {
            tokio::select! {
                result = &mut transfer => return result.map_err(transport),
                result = changes.changed() => {
                    result.map_err(transport)?;
                    self.admitted(&token, &grant).await?;
                }
            }
        }
    }

    /// Standard verified range download; retains at most one partial in this
    /// workspace store. `target` is a private caller-owned temporary path.
    /// The caller reserves disk/quota using the authenticated advertised size.
    #[allow(clippy::too_many_arguments)]
    pub async fn fetch(
        &self,
        root: &Path,
        target: &Path,
        workspace: WorkspaceId,
        revision: u64,
        peer: PeerId,
        ticket: ResourceTicket,
        progress: watch::Sender<u64>,
    ) -> Result<()> {
        let _slot = self
            .0
            .downloading
            .try_lock()
            .map_err(|_| Error::Backpressure)?;
        self.authorize(workspace, revision, peer).await?;
        if !target.is_absolute() {
            return Err(Error::Rejected);
        }
        let store = self.store(root).await?;
        let hash = Hash::from_bytes(ticket.hash);
        store
            .tags()
            .set(b"partial", hash)
            .await
            .map_err(transport)?;
        self.collect(&store).await?;
        let local = store.remote().local(hash).await.map_err(transport)?;
        progress.send_replace(local.local_bytes());
        if !local.is_complete() {
            let mut changes = self.0.changed.subscribe();
            let connection =
                tokio::time::timeout(IDLE_TIMEOUT, self.0.connections.connect(peer, ALPN))
                    .await
                    .map_err(|_| Error::Timeout("resource connect"))??;
            self.authorize(workspace, revision, peer).await?;
            let (mut send, recv) = connection.open_bi().await.map_err(transport)?;
            send.write_all(&[STREAM_KIND]).await.map_err(transport)?;
            send.write_all(&ticket.grant).await.map_err(transport)?;
            let reader = SizedReader {
                inner: recv,
                size: Some(ticket.size),
                header: [0; 8],
                read: 0,
            };
            let pair = get::StreamPair::new(connection.stable_id() as u64, reader, send);
            let transfer = store.remote().fetch(pair, hash);
            let mut events = transfer.stream();
            let idle = tokio::time::sleep(IDLE_TIMEOUT);
            tokio::pin!(idle);
            let result = loop {
                tokio::select! {
                    event = events.next() => match event {
                        Some(GetProgressItem::Progress(bytes)) => {
                            progress.send_replace(bytes);
                            idle.as_mut().reset(tokio::time::Instant::now() + IDLE_TIMEOUT);
                        }
                        Some(GetProgressItem::Done(_)) => break Ok(()),
                        Some(GetProgressItem::Error(error)) => break Err(transport(error)),
                        None => break Err(Error::Rejected),
                    },
                    _ = &mut idle => break Err(Error::Timeout("resource progress")),
                    result = changes.changed() => {
                        if let Err(error) = result.map_err(transport) { break Err(error); }
                        if let Err(error) = self.authorize(workspace, revision, peer).await { break Err(error); }
                    }
                }
            };
            // Flush verified partial ranges even when the peer disappears.
            drop(events);
            store.sync_db().await.map_err(transport)?;
            result?;
        }
        self.authorize(workspace, revision, peer).await?;
        store
            .export_with_opts(ExportOptions {
                hash,
                target: target.to_owned(),
                mode: ExportMode::TryReference,
            })
            .await
            .map_err(transport)?;
        if tokio::fs::metadata(target).await.map_err(transport)?.len() != ticket.size {
            return Err(Error::Rejected);
        }
        store.tags().delete(b"partial").await.map_err(transport)?;
        self.collect(&store).await?;
        progress.send_replace(ticket.size);
        Ok(())
    }

    /// Clear only the private resumable transfer, not retained/published files.
    pub async fn clear_partial(&self, root: &Path) -> Result<()> {
        let _slot = self.0.downloading.lock().await;
        if root.exists() {
            let store = self.store(root).await?;
            store.tags().delete(b"partial").await.map_err(transport)?;
            self.collect(&store).await?;
        }
        Ok(())
    }

    pub(crate) async fn close(&self) {
        self.stop();
        if let Some((_, store)) = self.0.store.get() {
            let _ = store.shutdown().await;
        }
    }

    pub(crate) fn stop(&self) {
        self.0.closed.store(true, Ordering::Release);
        self.revoke(None);
    }
}

/// Check the standard blob size header before its decoder/storage sees it.
/// Advertised length is a resource integrity boundary, not a file-size limit.
struct SizedReader<R> {
    inner: R,
    size: Option<u64>,
    header: [u8; 8],
    read: usize,
}

impl<R> SizedReader<R> {
    fn validate(&mut self, bytes: &[u8]) -> io::Result<()> {
        let Some(size) = self.size else {
            return Ok(());
        };
        let length = (8 - self.read).min(bytes.len());
        self.header[self.read..self.read + length].copy_from_slice(&bytes[..length]);
        self.read += length;
        if self.read == 8 && u64::from_le_bytes(self.header) != size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "resource length differs from grant",
            ));
        }
        Ok(())
    }
}

impl<R: BlobReader> BlobReader for SizedReader<R> {
    async fn recv_bytes(&mut self, len: usize) -> io::Result<Bytes> {
        let bytes = io_idle(self.inner.recv_bytes(len)).await?;
        self.validate(&bytes)?;
        Ok(bytes)
    }
    async fn recv_bytes_exact(&mut self, len: usize) -> io::Result<Bytes> {
        let bytes = io_idle(self.inner.recv_bytes_exact(len)).await?;
        self.validate(&bytes)?;
        Ok(bytes)
    }
    async fn recv_exact(&mut self, target: &mut [u8]) -> io::Result<()> {
        io_idle(self.inner.recv_exact(target)).await?;
        self.validate(target)
    }
    fn stop(&mut self, code: VarInt) -> io::Result<()> {
        BlobReader::stop(&mut self.inner, code)
    }
    fn id(&self) -> u64 {
        BlobReader::id(&self.inner)
    }
}

async fn io_idle<T>(operation: impl std::future::Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout(IDLE_TIMEOUT, operation)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "resource stream stalled"))?
}

/// A peer keeping QUIC alive without reading must release scarce serve slots.
/// This limits idle I/O, never the duration or size of a progressing transfer.
struct IdleWriter<'a>(&'a mut SendStream);
impl BlobWriter for IdleWriter<'_> {
    async fn send_bytes(&mut self, bytes: Bytes) -> io::Result<()> {
        io_idle(BlobWriter::send_bytes(self.0, bytes)).await
    }
    async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        io_idle(BlobWriter::send(self.0, bytes)).await
    }
    async fn sync(&mut self) -> io::Result<()> {
        io_idle(BlobWriter::sync(self.0)).await
    }
    fn reset(&mut self, code: VarInt) -> io::Result<()> {
        BlobWriter::reset(self.0, code)
    }
    async fn stopped(&mut self) -> io::Result<Option<VarInt>> {
        io_idle(BlobWriter::stopped(self.0)).await
    }
    fn id(&self) -> u64 {
        BlobWriter::id(self.0)
    }
}

#[tokio::test(start_paused = true)]
async fn idle_deadline_is_not_a_transfer_duration_limit() {
    let error = io_idle(std::future::pending::<io::Result<()>>())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    let started = tokio::time::Instant::now();
    for _ in 0..3 {
        io_idle(async {
            tokio::time::sleep(IDLE_TIMEOUT / 2).await;
            Ok(())
        })
        .await
        .unwrap();
    }
    assert!(started.elapsed() > IDLE_TIMEOUT);
}
