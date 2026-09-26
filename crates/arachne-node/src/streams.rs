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
use futures_util::{FutureExt, StreamExt, stream::FuturesUnordered};
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
// At most 1 MiB of validated-size envelopes per peer, independent of the
// upstream MoQ cache. Each reader also ends at the existing live replay window.
const MAX_GROUP_READS: usize = 8;

/// Counters for the distinct MoQ data path. A queued packet is not a remote receipt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct MoqMetrics {
    pub sessions_total: u64,
    pub sessions_active: usize,
    pub packets_sent: u64,
    pub packets_received: u64,
    /// Groups yielded by a receive subscription, before its first frame is read.
    pub groups_received: u64,
    /// First frames read from received groups, before envelope validation.
    pub frames_received: u64,
    /// Received groups whose second frame read confirmed a clean end.
    pub groups_completed: u64,
    pub rejected_sessions: u64,
}

#[derive(Default)]
struct Counters {
    sessions_total: AtomicU64,
    sessions_active: AtomicUsize,
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    groups_received: AtomicU64,
    frames_received: AtomicU64,
    groups_completed: AtomicU64,
    rejected_sessions: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> MoqMetrics {
        MoqMetrics {
            sessions_total: self.sessions_total.load(Ordering::Relaxed),
            sessions_active: self.sessions_active.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            groups_received: self.groups_received.load(Ordering::Relaxed),
            frames_received: self.frames_received.load(Ordering::Relaxed),
            groups_completed: self.groups_completed.load(Ordering::Relaxed),
            rejected_sessions: self.rejected_sessions.load(Ordering::Relaxed),
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

        // Reject a route we cannot start, while keeping connection work out of
        // the caller's workspace pump. Later retries share the same dial budget.
        let permit = self.0.connections.dial_capacity(iroh_moq::ALPN)?;
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
            if let std::collections::btree_map::Entry::Vacant(entry) = routes.entry(peer) {
                entry.insert(route.clone());
                true
            } else {
                false
            }
        };
        if !inserted {
            route.stop().await;
            return Err(Error::Rejected);
        }
        drop(permit);
        let worker = tokio::spawn(run_peer(
            incoming,
            moq,
            EndpointAddr::new(key),
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
        if self
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

    pub(super) async fn enabled_peers(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        topic: &Topic,
    ) -> Vec<PeerId> {
        let routes = self.0.routes.lock().await;
        routes
            .iter()
            .filter_map(|(peer, route)| {
                (route.scope
                    == (Scope {
                        workspace,
                        revision,
                    })
                    && route.topic == *topic)
                    .then_some(*peer)
            })
            .collect()
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
                    let publisher_hop = routes.get(&peer).map(|route| route.moq.origin().hop().id());
                    tracing::info!(target: "data_fabric_transport", peer = %hex(&peer), workspace = %hex(&frame.workspace), revision = frame.revision, sequence, ?publisher_hop, route = "moq", "PTT_MOQ_PACKET_ENQUEUED");
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

// One peer task borrows the existing transport, routing and delivery owners.
#[allow(clippy::too_many_arguments)]
async fn run_peer(
    mut incoming: iroh_moq::IncomingSessionStream,
    moq: Moq,
    address: EndpointAddr,
    connections: Connections,
    local: PeerId,
    peer: PeerId,
    scope: Scope,
    topic: Topic,
    routing: Arc<Mutex<RoutingTable>>,
    events: DeliveryQueue,
    counters: Weak<Counters>,
) {
    let mut selected = None;
    let mut delay = Duration::ZERO;
    loop {
        let session = if let Some(session) = selected.take() {
            session
        } else {
            let dial = async {
                tokio::time::sleep(delay).await;
                let _permit = connections.dial_capacity(iroh_moq::ALPN)?;
                tokio::time::timeout(SESSION_TIMEOUT, moq.connect(address.clone()))
                    .await
                    .map_err(|_| Error::Timeout("dial MoQ"))?
                    .map_err(transport)
            };
            tokio::select! {
                biased;
                session = incoming.next() => match session {
                    Some(session) => session,
                    None => return,
                },
                result = dial => match result {
                    Ok(session) => session,
                    Err(error) => {
                        tracing::debug!(target: "data_fabric_transport", ?peer, ?error, "MOQ_DIAL_FAILED");
                        delay = (delay * 2).clamp(Duration::from_millis(250), Duration::from_secs(5));
                        continue;
                    }
                },
            }
        };
        delay = Duration::from_millis(250);
        if *session.remote_id().as_bytes() != peer
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
        tracing::info!(target: "data_fabric_transport", peer = %hex(&peer), connection = session.conn().stable_id(), dialed = session.dialed(), version = ?session.session().version(), route = "moq", "PTT_MOQ_SESSION_SELECTED");
        let receive = async {
            announce_interest(&connections, &routing, local, peer, scope, &topic).await?;
            receive_session(
                &session, local, peer, scope, &topic, &routing, &events, &counters,
            )
            .await
        };
        tokio::pin!(receive);
        loop {
            tokio::select! {
                // A restarted peer can dial us before our old QUIC session
                // times out. Keep one receive subscription per peer. Iroh MoQ
                // owns duplicate connection lifetime; closing an unused one
                // here can close the session the other peer still consumes.
                next = incoming.next() => match next {
                    Some(next) if next.conn().stable_id() == session.conn().stable_id() => continue,
                    Some(next) => {
                        tracing::info!(target: "data_fabric_transport", peer = %hex(&peer), previous_connection = session.conn().stable_id(), selected_connection = next.conn().stable_id(), dialed = next.dialed(), route = "moq", "PTT_MOQ_SESSION_REPLACED");
                        selected = Some(next);
                        break;
                    }
                    None => return,
                },
                result = &mut receive => {
                    if let Err(error) = result {
                        tracing::info!(target: "data_fabric_transport", peer = %hex(&peer), connection = session.conn().stable_id(), route = "moq", ?error, "PTT_MOQ_SESSION_CLOSED");
                    }
                    session.close(moq_net::Error::Cancel);
                    break;
                }
            }
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
    // The new MoQ handshake can precede expiry of a pre-restart data connection.
    // Refresh its cache ownership without cancelling other in-flight exchanges.
    connections.forget(peer, super::ALPN).await;
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

// Keep the authenticated stream scope explicit at the receive boundary.
#[allow(clippy::too_many_arguments)]
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
    // Observe only an already available announcement. Diagnostics must not
    // add a wait or change which transport the receive loop selects. The first
    // hop names this publisher incarnation; a missing/zero hop is unknown.
    let publisher_hop = session
        .announced()
        .routed(path.as_str())
        .now_or_never()
        .flatten()
        .and_then(|route| route.hops.iter().next().map(|hop| hop.id()))
        .filter(|hop| *hop != 0);
    let track = broadcast.track(topic.as_str()).map_err(transport)?;
    // Lite05 encodes start 0 as omitted, which starts at the latest group even
    // with max_age set. Protected sequences start at 1: request that floor and
    // let max_age bound the recent window instead of discarding its prefix.
    let mut subscriber = track
        .subscribe(Some(
            track::Subscription::default()
                .with_start(track::Position::group(1))
                .with_max_age(track::DEFAULT_MAX_AGE),
        ))
        .await
        .map_err(transport)?;
    if let Some(counters) = counters.upgrade() {
        counters.sessions_total.fetch_add(1, Ordering::Relaxed);
        counters.sessions_active.fetch_add(1, Ordering::Relaxed);
    }
    let _active = ActiveSession(counters.upgrade());
    tracing::info!(target: "data_fabric_transport", peer = %hex(&peer), connection = session.conn().stable_id(), ?publisher_hop, workspace = %hex(&scope.workspace), revision = scope.revision, topic = topic.as_str(), route = "moq", "PTT_MOQ_SESSION_ESTABLISHED");
    let closed = session.closed();
    tokio::pin!(closed);
    let mut pending = FuturesUnordered::new();
    let mut ended = false;
    loop {
        if ended && pending.is_empty() {
            return Ok(());
        }
        let (sequence, frame) = tokio::select! {
            biased;
            // This remains polled while any group waits for a header, payload
            // or EOF. Dropping this function drops all its group readers.
            reason = &mut closed => return Err(transport(reason)),
            completed = pending.next(), if !pending.is_empty() => {
                completed.expect("nonempty group readers")?
            }
            next = subscriber.recv_group(), if !ended && pending.len() < MAX_GROUP_READS => {
                match next.map_err(transport)? {
                    Some(group) => {
                        if let Some(counters) = counters.upgrade() {
                            counters.groups_received.fetch_add(1, Ordering::Relaxed);
                        }
                        pending.push(read_group(group, counters));
                    }
                    None => ended = true,
                }
                continue;
            }
        };
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
        tracing::info!(target: "data_fabric_transport", peer = %hex(&peer), connection = session.conn().stable_id(), ?publisher_hop, sequence, route = "moq", "PTT_MOQ_PACKET_RECEIVED");
    }
}

/// Read one independent envelope. A peer cannot hold a reader forever, even
/// when all slots are occupied. The deadline is the live replay window, not a
/// reconnect timeout. Protocol errors still end the authenticated session.
async fn read_group(mut group: group::Consumer, counters: &Weak<Counters>) -> Result<(u64, Frame)> {
    tokio::time::timeout(track::DEFAULT_MAX_AGE, async {
        let sequence = group.sequence;
        let Some(mut frame) = group.next_frame().await.map_err(transport)? else {
            return Err(Error::InvalidFrame);
        };
        if frame.size > super::MAX_FRAME as u64 {
            return Err(Error::TooLarge);
        }
        let payload = frame.read_all().await.map_err(transport)?;
        if let Some(counters) = counters.upgrade() {
            counters.frames_received.fetch_add(1, Ordering::Relaxed);
        }
        // Inspect the next header, without assembling a forbidden second body.
        if group.next_frame().await.map_err(transport)?.is_some() {
            return Err(Error::TooLarge);
        }
        if let Some(counters) = counters.upgrade() {
            counters.groups_completed.fetch_add(1, Ordering::Relaxed);
        }
        let envelope = wire::decode::<Envelope>(&payload)?;
        if envelope.sequence != sequence {
            return Err(Error::InvalidFrame);
        }
        Ok((sequence, wire::decode::<Frame>(&envelope.frame)?))
    })
    .await
    .map_err(|_| Error::Timeout("read MoQ group"))?
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Node, Permissions};

    #[tokio::test]
    async fn incomplete_group_payload_does_not_block_a_later_group() {
        unfinished_group_does_not_block(true, false).await;
    }

    #[tokio::test]
    async fn incomplete_group_end_does_not_block_a_later_group() {
        unfinished_group_does_not_block(false, false).await;
    }

    #[tokio::test]
    async fn closing_cancels_an_incomplete_group_payload() {
        unfinished_group_does_not_block(true, true).await;
    }

    #[tokio::test]
    async fn closing_cancels_an_incomplete_group_end() {
        unfinished_group_does_not_block(false, true).await;
    }

    #[tokio::test]
    async fn oversized_group_header_is_rejected_before_its_body_arrives() {
        let broadcast = broadcast::Info::new().produce();
        let track = broadcast.create_track("bounded", None).unwrap();
        let mut group = track.create_group(group::Info::from(1u64)).unwrap();
        let consumer = group.consume();
        let _unfinished = group
            .create_frame(moq_net::frame::Info {
                size: (super::super::MAX_FRAME + 1) as u64,
                timestamp: Timestamp::now(),
            })
            .unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            read_group(consumer, &Weak::new()),
        )
        .await
        .expect("oversized header waited for its body");
        assert!(matches!(result, Err(Error::TooLarge)));
    }

    #[tokio::test]
    async fn malformed_groups_still_fail_closed() {
        let broadcast = broadcast::Info::new().produce();
        let track = broadcast.create_track("malformed", None).unwrap();
        for (index, frames) in [vec![], vec![vec![0xff]], vec![vec![0], vec![0]]]
            .into_iter()
            .enumerate()
        {
            let mut group = track.create_group(group::Info::from(index + 1)).unwrap();
            for frame in frames {
                group.write_frame(Timestamp::now(), frame).unwrap();
            }
            group.finish().unwrap();
            assert!(read_group(group.consume(), &Weak::new()).await.is_err());
        }
        let mut group = track.create_group(group::Info::from(9u64)).unwrap();
        group
            .write_frame(
                Timestamp::now(),
                wire::encode(&Envelope {
                    sequence: 10,
                    frame: vec![],
                })
                .unwrap(),
            )
            .unwrap();
        group.finish().unwrap();
        assert!(matches!(
            read_group(group.consume(), &Weak::new()).await,
            Err(Error::InvalidFrame)
        ));
    }

    #[tokio::test]
    async fn all_occupied_readers_expire_at_the_live_window() {
        let broadcast = broadcast::Info::new().produce();
        let track = broadcast.create_track("stalled", None).unwrap();
        let mut producers = Vec::new();
        let counters = Weak::new();
        let mut pending = FuturesUnordered::new();
        for sequence in 1..=MAX_GROUP_READS {
            let producer = track.create_group(group::Info::from(sequence)).unwrap();
            pending.push(read_group(producer.consume(), &counters));
            producers.push(producer);
        }
        let started = std::time::Instant::now();
        tokio::time::timeout(track::DEFAULT_MAX_AGE + Duration::from_secs(1), async {
            while let Some(result) = pending.next().await {
                assert!(matches!(result, Err(Error::Timeout("read MoQ group"))));
            }
        })
        .await
        .expect("stalled group readers kept their slots forever");
        assert!(started.elapsed() >= track::DEFAULT_MAX_AGE);
        assert_eq!(producers.len(), MAX_GROUP_READS);
    }

    async fn unfinished_group_does_not_block(partial_payload: bool, close_while_blocked: bool) {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (sender, _sender_messages) =
                Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let (receiver, mut messages) =
                Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let workspace = [54; 32];
            let topic = Topic::new("shared/stream").unwrap();
            let policy = BTreeMap::from([
                (sender.id(), Permissions::AllTopics),
                (receiver.id(), Permissions::AllTopics),
            ]);
            for (node, peer) in [(&sender, &receiver), (&receiver, &sender)] {
                node.install_verified_policy(workspace, 1, policy.clone())
                    .await
                    .unwrap();
                node.subscribe(workspace, 1, topic.clone()).await.unwrap();
                node.add_address_hint(peer.id(), peer.address())
                    .await
                    .unwrap();
                node.enable_moq_delivery(workspace, 1, peer.id(), topic.clone())
                    .await
                    .unwrap();
            }
            while sender.moq_metrics().sessions_active != 1
                || receiver.moq_metrics().sessions_active != 1
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            // The public publisher always finishes its group. Inject the
            // interrupted wire producer at the real authorized route instead
            // of changing the public API to expose malformed publications.
            let route = sender
                .streams
                .0
                .routes
                .lock()
                .await
                .get(&receiver.id())
                .cloned()
                .unwrap();
            let envelope = wire::encode(&Envelope {
                sequence: 1,
                frame: wire::encode(&Frame {
                    workspace,
                    revision: 1,
                    topic: topic.as_str().into(),
                    delivery: DeliveryClass::Critical,
                    operation: Operation::Publish(b"unfinished".to_vec()),
                })
                .unwrap(),
            })
            .unwrap();
            let mut blocked = route.track.create_group(group::Info::from(1u64)).unwrap();
            let mut partial = if partial_payload {
                let mut frame = blocked
                    .create_frame(moq_net::frame::Info {
                        size: envelope.len() as u64,
                        timestamp: Timestamp::now(),
                    })
                    .unwrap();
                frame
                    .write(envelope[..envelope.len() / 2].to_vec())
                    .unwrap();
                Some(frame)
            } else {
                blocked
                    .write_frame(Timestamp::now(), envelope.clone())
                    .unwrap();
                None
            };
            while receiver.moq_metrics().groups_received != 1
                || (!partial_payload && receiver.moq_metrics().frames_received != 1)
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(receiver.moq_metrics().groups_completed, 0);
            // A complete burst larger than the read window must drain under
            // backpressure while the first independent group remains blocked.
            let complete_count = MAX_GROUP_READS * 2;
            for sequence in 2..2 + complete_count as u64 {
                sender
                    .publish_protected_with_class(
                        workspace,
                        1,
                        topic.clone(),
                        sequence,
                        DeliveryClass::Critical,
                        sequence.to_be_bytes().to_vec(),
                    )
                    .await
                    .unwrap();
            }
            let delivered = tokio::time::timeout(Duration::from_secs(1), async {
                let mut sequences = std::collections::BTreeSet::new();
                while sequences.len() < complete_count {
                    let message = messages.recv().await.unwrap();
                    assert_eq!(message.sender, sender.id());
                    assert_eq!(message.payload.len(), 8);
                    let sequence =
                        u64::from_be_bytes(message.payload.as_slice().try_into().unwrap());
                    assert!((2..2 + complete_count as u64).contains(&sequence));
                    assert!(sequences.insert(sequence), "duplicate complete group");
                }
            })
            .await;
            assert!(
                delivered.is_ok(),
                "an unfinished group blocked independent complete groups: {:?}",
                receiver.moq_metrics()
            );
            if close_while_blocked {
                let counters = Arc::clone(&receiver.streams.0.counters);
                let closing = tokio::spawn(receiver.close());
                tokio::time::timeout(Duration::from_secs(1), async {
                    while counters.sessions_active.load(Ordering::Relaxed) != 0 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("close kept an incomplete receive session alive");
                tokio::time::timeout(Duration::from_secs(6), closing)
                    .await
                    .unwrap()
                    .unwrap();
                drop(partial);
                drop(blocked);
            } else {
                if let Some(mut frame) = partial.take() {
                    frame
                        .write(envelope[envelope.len() / 2..].to_vec())
                        .unwrap();
                    frame.finish().unwrap();
                }
                drop(partial);
                blocked.finish().unwrap();
                let earlier = tokio::time::timeout(Duration::from_secs(1), messages.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(earlier.sender, sender.id());
                assert_eq!(earlier.payload, b"unfinished");
                assert_eq!(
                    receiver.moq_metrics().packets_received,
                    (complete_count + 1) as u64
                );
                drop(blocked);
                receiver.close().await;
            }
            sender.close().await;
        })
        .await
        .expect("unfinished group fixture timed out");
    }
}
