//! Authorized MoQ transport over the node's existing Iroh endpoint.
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex as StdMutex, Weak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use arachne_routing::RoutingTable;
use iroh::{EndpointAddr, PublicKey, endpoint::Connection};
use iroh_moq::{Moq, MoqSession};
use moq_net::{Timestamp, broadcast, group, track};
use serde::{Deserialize, Serialize};
use tokio::{sync::Mutex, task::JoinHandle};

use crate::{
    AdmissionReport, DeliveryClass, DeliveryQueue, Error, Frame, Operation, PeerId, Result, Topic,
    WorkspaceId, connections::Connections, wire,
};

const SESSION_TIMEOUT: Duration = Duration::from_secs(10);

/// Counters for the distinct MoQ data path. A queued packet is not a remote receipt.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct MoqMetrics {
    pub sessions_total: u64,
    pub sessions_active: usize,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub rejected_sessions: u64,
    pub interest_sync_pending: usize,
    pub last_error: Option<String>,
}

#[derive(Default)]
struct Counters {
    sessions_total: AtomicU64,
    sessions_active: AtomicUsize,
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    rejected_sessions: AtomicU64,
    interest_sync_pending: AtomicUsize,
    last_error: StdMutex<Option<String>>,
}

impl Counters {
    fn snapshot(&self) -> MoqMetrics {
        MoqMetrics {
            sessions_total: self.sessions_total.load(Ordering::Relaxed),
            sessions_active: self.sessions_active.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            rejected_sessions: self.rejected_sessions.load(Ordering::Relaxed),
            interest_sync_pending: self.interest_sync_pending.load(Ordering::Relaxed),
            last_error: self.last_error.lock().unwrap().clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Scope {
    workspace: WorkspaceId,
    revision: u64,
}

struct Route {
    scope: Scope,
    topic: Topic,
    moq: Moq,
    broadcast: broadcast::Producer,
    track: track::Producer,
    workers: StdMutex<Vec<JoinHandle<()>>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    sequence: u64,
    #[serde(with = "wire::envelope_payload")]
    frame: Vec<u8>,
}

struct Inner {
    connections: Connections,
    routing: Arc<Mutex<RoutingTable>>,
    events: DeliveryQueue,
    local: PeerId,
    routes: Mutex<BTreeMap<PeerId, Arc<Route>>>,
    counters: Arc<Counters>,
    stopped: AtomicBool,
}

#[derive(Clone)]
pub(super) struct Streams(Arc<Inner>);

impl Streams {
    pub(super) fn new(
        connections: Connections,
        routing: Arc<Mutex<RoutingTable>>,
        events: DeliveryQueue,
    ) -> Self {
        let local = connections.id();
        Self(Arc::new(Inner {
            connections,
            routing,
            events,
            local,
            routes: Mutex::new(BTreeMap::new()),
            counters: Arc::default(),
            stopped: AtomicBool::new(false),
        }))
    }

    pub(super) async fn enable(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        peer: PeerId,
        topic: Topic,
    ) -> Result<()> {
        if self.0.stopped.load(Ordering::Acquire) || peer == self.0.local {
            return Err(Error::Rejected);
        }
        let scope = Scope {
            workspace,
            revision,
        };
        self.authorize(scope, peer, &topic).await?;
        let key = PublicKey::from_bytes(&peer).map_err(transport)?;
        {
            let routes = self.0.routes.lock().await;
            if let Some(route) = routes.get(&peer) {
                return if route.scope == scope && route.topic == topic {
                    Ok(())
                } else {
                    // ponytail: one peer route per node, matching the one-workspace/one-channel MVD.
                    Err(Error::Rejected)
                };
            }
        }

        let moq = Moq::new(self.0.connections.endpoint());
        // Subscribe before publishing the route. An outbound dial can complete
        // immediately after the peer installs the matching route.
        let incoming = moq.incoming_sessions();
        let path = path(workspace, self.0.local, revision);
        let broadcast = moq.publish(path.as_str()).map_err(transport)?;
        let track = broadcast
            .create_track(topic.as_str(), None)
            .map_err(transport)?;
        let route = Arc::new(Route {
            scope,
            topic: topic.clone(),
            moq: moq.clone(),
            broadcast,
            track,
            workers: StdMutex::new(Vec::new()),
        });
        let inserted = {
            let mut routes = self.0.routes.lock().await;
            if routes.contains_key(&peer) {
                false
            } else {
                routes.insert(peer, route.clone());
                true
            }
        };
        if !inserted {
            route.stop().await;
            return Err(Error::Rejected);
        }
        let worker = tokio::spawn(run_peer(
            incoming,
            self.0.connections.clone(),
            self.0.local,
            peer,
            scope,
            topic,
            self.0.routing.clone(),
            self.0.events.clone(),
            Arc::downgrade(&self.0.counters),
        ));
        route.workers.lock().unwrap().push(worker);

        // A deterministic dialer avoids duplicate sessions when both peers opt in.
        let mut dialed_session = None;
        if self.0.local < peer {
            let _permit = match self.0.connections.dial_capacity(iroh_moq::ALPN) {
                Ok(permit) => permit,
                Err(error) => {
                    self.remove_route(peer).await;
                    return Err(error);
                }
            };
            let result =
                tokio::time::timeout(SESSION_TIMEOUT, moq.connect(EndpointAddr::new(key))).await;
            drop(_permit);
            match result {
                Ok(Ok(session)) => dialed_session = Some(session),
                Ok(Err(error)) => {
                    self.remove_route(peer).await;
                    return Err(transport(error));
                }
                Err(_) => {
                    self.remove_route(peer).await;
                    return Err(Error::Timeout("dial MoQ"));
                }
            }
        }
        if let Some(session) = dialed_session {
            let worker = tokio::spawn(reconnect_peer(
                moq,
                EndpointAddr::new(key),
                self.0.connections.clone(),
                session,
                Arc::downgrade(&self.0.counters),
            ));
            route.workers.lock().unwrap().push(worker);
        }
        Ok(())
    }

    async fn authorize(&self, scope: Scope, peer: PeerId, topic: &Topic) -> Result<()> {
        authorize(&self.0.routing, self.0.local, scope, peer, topic).await
    }

    pub(super) async fn accept_connection(
        &self,
        peer: PeerId,
        connection: Connection,
    ) -> Result<()> {
        let route = self.0.routes.lock().await.get(&peer).cloned();
        let Some(route) = route else {
            self.0
                .counters
                .rejected_sessions
                .fetch_add(1, Ordering::Relaxed);
            return Err(Error::Rejected);
        };
        if self.0.local < peer
            || self
                .authorize(route.scope, peer, &route.topic)
                .await
                .is_err()
        {
            self.0
                .counters
                .rejected_sessions
                .fetch_add(1, Ordering::Relaxed);
            return Err(Error::Rejected);
        }
        use iroh::protocol::ProtocolHandler;
        route
            .moq
            .protocol_handler()
            .accept(connection)
            .await
            .map_err(transport)
    }

    pub(super) async fn any_enabled(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        topic: &Topic,
        peers: &[PeerId],
    ) -> bool {
        let routes = self.0.routes.lock().await;
        peers.iter().any(|peer| {
            routes.get(peer).is_some_and(|route| {
                route.scope
                    == (Scope {
                        workspace,
                        revision,
                    })
                    && route.topic == *topic
            })
        })
    }

    pub(super) async fn publish_selected(
        &self,
        sequence: u64,
        peers: Vec<PeerId>,
        frame: Frame,
    ) -> Result<AdmissionReport> {
        let frame = Arc::new(frame);
        let bytes = wire::encode(frame.as_ref())?;
        let envelope = wire::encode(&Envelope {
            sequence,
            frame: bytes.clone(),
        })?;
        let routes = self.0.routes.lock().await.clone();
        let mut report = AdmissionReport::default();
        for peer in peers {
            let (result, used_moq) = if peer == self.0.local {
                (
                    super::apply(
                        &self.0.routing,
                        &self.0.events,
                        self.0.local,
                        self.0.local,
                        self.0.local,
                        wire::decode(&bytes)?,
                    )
                    .await,
                    false,
                )
            } else if let Some(route) = routes.get(&peer).filter(|route| {
                route.scope
                    == (Scope {
                        workspace: frame.workspace,
                        revision: frame.revision,
                    })
                    && route.topic.as_str() == frame.topic
            }) {
                (
                    self.authorize(route.scope, peer, &route.topic)
                        .await
                        .and_then(|()| route.publish(sequence, envelope.clone())),
                    true,
                )
            } else {
                (
                    super::send_frame(
                        &self.0.connections,
                        &self.0.routing,
                        peer,
                        frame.as_ref(),
                        &bytes,
                    )
                    .await,
                    false,
                )
            };
            match result {
                Ok(()) if used_moq => {
                    report.queued = true;
                    self.0.counters.packets_sent.fetch_add(1, Ordering::Relaxed);
                }
                Ok(()) => report.admitted.push(peer),
                Err(error) => report.failed.push((peer, error)),
            }
        }
        report.admitted.sort_unstable();
        report.failed.sort_unstable_by_key(|(peer, _)| *peer);
        Ok(report)
    }

    pub(super) async fn policy_changed(&self) {
        let routes = self.0.routes.lock().await.clone();
        let mut removed = Vec::new();
        for (peer, route) in routes {
            let current = self
                .0
                .routing
                .lock()
                .await
                .installed_revision(route.scope.workspace);
            // The receive window permits old frames, but a live MoQ route must use the current scope.
            if current != Some(route.scope.revision)
                || self
                    .authorize(route.scope, peer, &route.topic)
                    .await
                    .is_err()
            {
                removed.push(peer);
            }
        }
        for peer in removed {
            self.remove_route(peer).await;
        }
    }

    async fn remove_route(&self, peer: PeerId) {
        let route = self.0.routes.lock().await.remove(&peer);
        if let Some(route) = route {
            route.stop().await;
        }
    }

    pub(super) fn metrics(&self) -> MoqMetrics {
        self.0.counters.snapshot()
    }

    pub(super) async fn close(&self) {
        self.0.stopped.store(true, Ordering::Release);
        let routes = std::mem::take(&mut *self.0.routes.lock().await);
        for (_, route) in routes {
            route.stop().await;
        }
    }

    pub(super) fn stop(&self) {
        if self.0.stopped.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let streams = self.clone();
            handle.spawn(async move { streams.close().await });
        } else if let Ok(mut routes) = self.0.routes.try_lock() {
            for (_, route) in std::mem::take(&mut *routes) {
                route.abort();
            }
        }
    }
}

impl Route {
    fn publish(&self, sequence: u64, envelope: Vec<u8>) -> Result<()> {
        let mut group = self
            .track
            .create_group(group::Info::from(sequence))
            .map_err(transport)?;
        group
            .write_frame(Timestamp::now(), envelope)
            .map_err(transport)?;
        group.finish().map_err(transport)
    }

    async fn stop(&self) {
        let workers = std::mem::take(&mut *self.workers.lock().unwrap());
        for worker in workers {
            worker.abort();
            let _ = worker.await;
        }
        let _ = self.track.finish();
        self.broadcast.finish();
        self.moq.shutdown().await;
    }

    fn abort(&self) {
        for worker in std::mem::take(&mut *self.workers.lock().unwrap()) {
            worker.abort();
        }
        let _ = self.track.finish();
        self.broadcast.finish();
    }
}

async fn reconnect_peer(
    moq: Moq,
    address: EndpointAddr,
    connections: Connections,
    mut session: MoqSession,
    counters: Weak<Counters>,
) {
    let mut delay = Duration::from_millis(250);
    loop {
        let reason = session.closed().await;
        if let Some(counters) = counters.upgrade() {
            *counters.last_error.lock().unwrap() = Some(format!(
                "reconnect {}: closed {reason}; transport={:?}",
                address.id,
                session.conn().close_reason(),
            ));
        }
        tokio::time::sleep(delay).await;
        let permit = match connections.dial_capacity(iroh_moq::ALPN) {
            Ok(permit) => permit,
            Err(_) => {
                delay = (delay * 2).min(Duration::from_secs(5));
                continue;
            }
        };
        let result = tokio::time::timeout(SESSION_TIMEOUT, moq.connect(address.clone())).await;
        drop(permit);
        match result {
            Ok(Ok(reconnected)) => {
                if let Some(counters) = counters.upgrade() {
                    *counters.last_error.lock().unwrap() = Some(format!(
                        "reconnect {}: connected; reused={}",
                        address.id,
                        session.conn().stable_id() == reconnected.conn().stable_id(),
                    ));
                }
                session = reconnected;
                delay = Duration::from_millis(250);
            }
            other => {
                if let Some(counters) = counters.upgrade() {
                    *counters.last_error.lock().unwrap() =
                        Some(format!("reconnect {}: dial failed {other:?}", address.id,));
                }
                delay = (delay * 2).min(Duration::from_secs(5));
            }
        }
    }
}

async fn authorize(
    routing: &Mutex<RoutingTable>,
    local: PeerId,
    scope: Scope,
    peer: PeerId,
    topic: &Topic,
) -> Result<()> {
    let routing = routing.lock().await;
    routing.authorizes_endpoint(scope.workspace, scope.revision, local)?;
    routing.authorizes_endpoint(scope.workspace, scope.revision, peer)?;
    routing.direct_recipients(scope.workspace, scope.revision, local, topic, &[peer])?;
    if !routing
        .publishers(scope.workspace, scope.revision, local, topic)?
        .contains(&peer)
    {
        return Err(Error::Rejected);
    }
    Ok(())
}

async fn run_peer(
    mut incoming: iroh_moq::IncomingSessionStream,
    connections: Connections,
    local: PeerId,
    peer: PeerId,
    scope: Scope,
    topic: Topic,
    routing: Arc<Mutex<RoutingTable>>,
    events: DeliveryQueue,
    counters: Weak<Counters>,
) {
    while let Some(session) = incoming.next().await {
        if *session.remote_id().as_bytes() != peer
            || session.dialed() != (local < peer)
            || authorize(&routing, local, scope, peer, &topic)
                .await
                .is_err()
        {
            if let Some(counters) = counters.upgrade() {
                counters.rejected_sessions.fetch_add(1, Ordering::Relaxed);
            }
            session.close(moq_net::Error::Cancel);
            continue;
        }
        if let Some(counters) = counters.upgrade() {
            counters
                .interest_sync_pending
                .fetch_add(1, Ordering::Relaxed);
        }
        let interest = announce_interest(&connections, &routing, local, peer, scope, &topic).await;
        if let Some(counters) = counters.upgrade() {
            counters
                .interest_sync_pending
                .fetch_sub(1, Ordering::Relaxed);
        }
        if let Err(error) = interest {
            if let Some(counters) = counters.upgrade() {
                *counters.last_error.lock().unwrap() = Some(format!("interest: {error}"));
            }
            tracing::warn!(
                target: "data_fabric_transport",
                peer = %session.remote_id(),
                route = "moq",
                ?error,
                "PTT_MOQ_INTEREST_SYNC_FAILED",
            );
            session.close(moq_net::Error::Cancel);
            continue;
        }
        if let Some(counters) = counters.upgrade() {
            counters.sessions_total.fetch_add(1, Ordering::Relaxed);
            counters.sessions_active.fetch_add(1, Ordering::Relaxed);
        }
        let _active = ActiveSession(counters.upgrade());
        tracing::info!(target: "data_fabric_transport", peer = %session.remote_id(), workspace = %hex(&scope.workspace), revision = scope.revision, topic = topic.as_str(), route = "moq", "PTT_MOQ_SESSION_ESTABLISHED");
        if let Err(error) = receive_session(
            &session, local, peer, scope, &topic, &routing, &events, &counters,
        )
        .await
        {
            if let Some(counters) = counters.upgrade() {
                *counters.last_error.lock().unwrap() = Some(format!("receive: {error}"));
            }
            tracing::info!(target: "data_fabric_transport", peer = %session.remote_id(), route = "moq", ?error, "PTT_MOQ_SESSION_CLOSED");
            session.close(moq_net::Error::Cancel);
        }
    }
}

async fn announce_interest(
    connections: &Connections,
    routing: &Mutex<RoutingTable>,
    local: PeerId,
    peer: PeerId,
    scope: Scope,
    topic: &Topic,
) -> Result<()> {
    if !routing
        .lock()
        .await
        .subscribed(scope.workspace, scope.revision, local, topic)
        .unwrap_or(false)
    {
        return Ok(());
    }
    let frame = Frame {
        workspace: scope.workspace,
        revision: scope.revision,
        topic: topic.as_str().into(),
        delivery: DeliveryClass::Critical,
        operation: Operation::Subscribe,
    };
    let bytes = wire::encode(&frame)?;
    super::send_frame(connections, routing, peer, &frame, &bytes).await
}

struct ActiveSession(Option<Arc<Counters>>);

impl Drop for ActiveSession {
    fn drop(&mut self) {
        if let Some(counters) = self.0.take() {
            counters.sessions_active.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

async fn receive_session(
    session: &MoqSession,
    local: PeerId,
    peer: PeerId,
    scope: Scope,
    topic: &Topic,
    routing: &Mutex<RoutingTable>,
    events: &DeliveryQueue,
    counters: &Weak<Counters>,
) -> Result<()> {
    let path = path(scope.workspace, peer, scope.revision);
    let broadcast = tokio::time::timeout(SESSION_TIMEOUT, session.subscribe(path.as_str()))
        .await
        .map_err(|_| Error::Timeout("subscribe MoQ broadcast"))?
        .map_err(transport)?;
    let track = broadcast.track(topic.as_str()).map_err(transport)?;
    // The zero-age default skips a group as soon as its successor arrives.
    // Keep the publisher's bounded window so bursts do not discard adjacent frames.
    let mut subscriber = track
        .subscribe(Some(
            track::Subscription::default().with_max_age(track::DEFAULT_MAX_AGE),
        ))
        .await
        .map_err(transport)?;
    let closed = session.closed();
    tokio::pin!(closed);
    loop {
        let next_group = tokio::select! {
            group = subscriber.recv_group() => group.map_err(transport)?,
            reason = &mut closed => return Err(transport(reason)),
        };
        let Some(mut group) = next_group else {
            return Ok(());
        };
        let sequence = group.sequence;
        let Some(frame) = group.read_frame().await.map_err(transport)? else {
            return Err(Error::InvalidFrame);
        };
        if frame.payload.len() > super::MAX_FRAME
            || group.read_frame().await.map_err(transport)?.is_some()
        {
            return Err(Error::TooLarge);
        }
        let envelope = wire::decode::<Envelope>(&frame.payload)?;
        if envelope.sequence != sequence {
            return Err(Error::InvalidFrame);
        }
        let frame = wire::decode::<Frame>(&envelope.frame)?;
        if frame.workspace != scope.workspace
            || frame.revision != scope.revision
            || frame.topic != topic.as_str()
            || !matches!(
                frame.operation,
                Operation::Publish(_) | Operation::DirectPublish { .. }
            )
        {
            return Err(Error::Rejected);
        }
        super::apply(routing, events, local, peer, peer, frame).await?;
        if let Some(counters) = counters.upgrade() {
            counters.packets_received.fetch_add(1, Ordering::Relaxed);
        }
        tracing::info!(target: "data_fabric_transport", peer = %session.remote_id(), sequence, route = "moq", "PTT_MOQ_PACKET_RECEIVED");
    }
}

fn path(workspace: WorkspaceId, author: PeerId, revision: u64) -> String {
    format!(
        "workspace/{}/author/{}/epoch/{revision}",
        hex(&workspace),
        hex(&author)
    )
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn transport(error: impl std::fmt::Display) -> Error {
    Error::Transport(error.to_string())
}

pub(super) fn is_moq_alpn(alpn: &[u8]) -> bool {
    iroh_moq::alpns()
        .into_iter()
        .any(|candidate| candidate == alpn)
}
