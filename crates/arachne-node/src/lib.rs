//! Direct-peer live pub/sub assembled over the portable routing module.
//!
//! Experimental: callers supply VERIFIED policies and peer address hints. No
//! invitation verification, group encryption, retained delivery or identity
//! storage yet. This module must not be presented as secure group management.
//! Traffic is direct QUIC/TLS, bound to the authenticated peer's identity; no
//! forwarding through other endpoints. Only locally installed policies authorize.
use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

mod budget;
mod connections;
mod control;
mod overlay;
pub mod resources;
mod wire;
pub use budget::{CapacityCounts, ConnectionBudget};
pub use control::{ControlClient, ControlRequest, ControlTiming, InquiryResponder, MAX_CONTROL_REPLY, Timing};

use connections::Connections;
use arachne_routing::RoutingTable;
pub use arachne_routing::{PeerId, Permissions, Topic, WorkspaceId};
use futures_util::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{Mutex, mpsc, watch},
    task::JoinHandle,
};

const ALPN: &[u8] = b"data-fabric/pubsub-experiment/1";
const MAX_PAYLOAD: usize = 16 * 1024;
const MAX_RECIPIENTS: usize = 64;
const MAX_FRAME: usize = 128 * 1024;
const TIMEOUT: Duration = Duration::from_secs(5);
const CONNECTION_IDLE: Duration = Duration::from_secs(60);
const CRITICAL_QUEUE: usize = 256;
const CURRENT_QUEUE: usize = 64;
const BULK_QUEUE: usize = 64;

/// Address discovery and path policy; never workspace authority.
#[derive(Clone, Copy, Debug)]
pub enum NetworkProfile {
    Direct,
    Lan,
    Nearby,
    Wan,
    RelayOnly,
    WanOnly,
    #[cfg(feature = "tor")]
    Tor,
}

impl NetworkProfile {
    fn settings(self) -> (Option<&'static str>, bool, bool, bool) {
        match self {
            Self::Direct => (None, false, false, true),
            Self::Lan => (Some("data-fabric"), false, false, true),
            Self::Nearby => (Some("arachne-nearby"), false, false, true),
            Self::Wan => (Some("data-fabric"), true, false, false),
            Self::RelayOnly => (None, true, true, false),
            Self::WanOnly => (None, true, false, false),
            #[cfg(feature = "tor")]
            Self::Tor => (None, false, true, false),
        }
    }

    fn uses_tor(self) -> bool {
        #[cfg(feature = "tor")]
        return matches!(self, Self::Tor);

        #[cfg(not(feature = "tor"))]
        false
    }
}

/// Caller-supplied relay transport settings for a controlled qualification or
/// an operator-managed relay deployment.
#[derive(Clone, Debug)]
pub struct RelayOptions {
    pub(crate) map: iroh::RelayMap,
    pub(crate) tls: iroh::tls::CaTlsConfig,
}

impl RelayOptions {
    pub fn new(map: iroh::RelayMap, tls: iroh::tls::CaTlsConfig) -> Self {
        Self { map, tls }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("routing rejected: {0:?}")]
    Routing(#[from] arachne_routing::Error),
    #[error("transport: {0}")]
    Transport(String),
    #[error("unknown peer address")]
    MissingPeer,
    #[error("control request not sent: {0}")]
    ControlNotSent(&'static str),
    #[error("message exceeds limit")]
    TooLarge,
    #[error("peer rejected operation")]
    Rejected,
    #[error("operation deadline exceeded during {0}; admission outcome may be unknown")]
    Timeout(&'static str),
    #[error("operation cancelled because the local session closed")]
    Cancelled,
    #[error("invalid frame")]
    InvalidFrame,
    #[error("consumer queue full or closed")]
    Backpressure,
    #[error("peer has no announced subscription to this topic")]
    NotSubscribed,
}
type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub workspace: WorkspaceId,
    pub revision: u64,
    pub sender: PeerId,
    /// Authenticated endpoint that handed this frame to us. Equal to `sender`
    /// for direct traffic; forwarding code must never treat it as the author.
    pub received_from: PeerId,
    pub topic: Topic,
    pub payload: Vec<u8>,
    /// Nonempty only for a direct publication. These are workspace member IDs;
    /// endpoint selection is authenticated transport metadata, not application identity.
    pub recipients: Vec<[u8; 32]>,
    pub delivery: DeliveryClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
/// Payload-neutral queue behavior declared by the publishing adapter.
pub enum DeliveryClass {
    #[default]
    Critical,
    Current {
        replacement_key: [u8; 32],
    },
    Bulk,
}

type CurrentKey = (
    WorkspaceId,
    u64,
    String,
    PeerId,
    PeerId,
    [u8; 32],
    Vec<[u8; 32]>,
);

#[derive(Default)]
struct DeliveryState {
    critical: VecDeque<Message>,
    current: BTreeMap<CurrentKey, Message>,
    bulk: VecDeque<Message>,
    critical_run: u8,
    bulk_turn: bool,
}

#[derive(Clone, Default)]
struct DeliveryQueue {
    state: Arc<StdMutex<DeliveryState>>,
    changed: Arc<tokio::sync::Notify>,
    closed: Arc<AtomicBool>,
}

impl DeliveryQueue {
    fn push(&self, message: Message) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Backpressure);
        }
        let mut state = self.state.lock().unwrap();
        match message.delivery {
            DeliveryClass::Critical if state.critical.len() < CRITICAL_QUEUE => {
                state.critical.push_back(message)
            }
            DeliveryClass::Current { replacement_key } => {
                let key = (
                    message.workspace,
                    message.revision,
                    message.topic.as_str().into(),
                    message.sender,
                    message.received_from,
                    replacement_key,
                    message.recipients.clone(),
                );
                if state.current.len() == CURRENT_QUEUE && !state.current.contains_key(&key) {
                    return Err(Error::Backpressure);
                }
                state.current.insert(key, message);
            }
            DeliveryClass::Bulk if state.bulk.len() < BULK_QUEUE => state.bulk.push_back(message),
            _ => return Err(Error::Backpressure),
        }
        drop(state);
        self.changed.notify_one();
        Ok(())
    }

    fn pop(&self) -> Option<Message> {
        let mut state = self.state.lock().unwrap();
        if state.critical_run < 8
            && let Some(message) = state.critical.pop_front()
        {
            state.critical_run += 1;
            return Some(message);
        }
        let lower = if state.bulk_turn {
            state
                .bulk
                .pop_front()
                .or_else(|| state.current.pop_first().map(|(_, message)| message))
        } else {
            state
                .current
                .pop_first()
                .map(|(_, message)| message)
                .or_else(|| state.bulk.pop_front())
        };
        if lower.is_some() {
            state.critical_run = 0;
            state.bulk_turn = !state.bulk_turn;
            return lower;
        }
        state.critical.pop_front()
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
}

pub struct MessageReceiver {
    queue: DeliveryQueue,
}

impl MessageReceiver {
    /// Snapshot of all delivery classes, without consuming the next message.
    pub fn is_empty(&self) -> bool {
        let state = self.queue.state.lock().unwrap();
        state.critical.is_empty() && state.current.is_empty() && state.bulk.is_empty()
    }

    pub fn try_recv(&mut self) -> std::result::Result<Message, mpsc::error::TryRecvError> {
        self.queue.pop().ok_or_else(|| {
            if self.queue.closed.load(Ordering::Acquire) {
                mpsc::error::TryRecvError::Disconnected
            } else {
                mpsc::error::TryRecvError::Empty
            }
        })
    }

    pub async fn recv(&mut self) -> Option<Message> {
        loop {
            let notify = self.queue.changed.clone();
            let changed = notify.notified();
            match self.try_recv() {
                Ok(message) => return Some(message),
                Err(mpsc::error::TryRecvError::Disconnected) => return None,
                Err(mpsc::error::TryRecvError::Empty) => changed.await,
            }
        }
    }
}

/// Acceptance of an operation. Publications enter consumer queues; this is not
/// a delivery/read receipt. Subscription operations update interest. A timeout
/// may have occurred after admission; retry semantics are not implemented yet.
#[derive(Debug, Default)]
pub struct AdmissionReport {
    pub admitted: Vec<PeerId>,
    pub failed: Vec<(PeerId, Error)>,
    /// A bounded live overlay accepted this publication locally. This is not a
    /// remote admission, delivery, retention or read receipt.
    pub queued: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    workspace: WorkspaceId,
    revision: u64,
    #[serde(deserialize_with = "wire::topic")]
    topic: String,
    delivery: DeliveryClass,
    operation: Operation,
}

#[derive(Serialize, Deserialize)]
enum Operation {
    Subscribe,
    Unsubscribe,
    Publish(#[serde(with = "wire::payload")] Vec<u8>),
    DirectPublish {
        #[serde(with = "wire::payload")]
        payload: Vec<u8>,
        #[serde(deserialize_with = "wire::recipients")]
        recipients: Vec<[u8; 32]>,
    },
}

/// Local endpoint counters. These include transport overhead and retransmission,
/// not application delivery receipts. They reset when the endpoint is opened.
#[derive(Debug, serde::Serialize)]
pub struct TransportMetrics {
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub receive_queue: usize,
    pub paths: Vec<PeerPath>,
    pub paths_limited: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct PeerPath {
    pub endpoint: PeerId,
    pub route: &'static str,
    pub rtt_ms: u64,
}

pub struct Node {
    controls: mpsc::Receiver<ControlRequest>,
    control_inbox: control::ControlInbox,
    control_signal: Arc<tokio::sync::Notify>,
    control_cancel: watch::Sender<bool>,
    deferred_controls: std::collections::VecDeque<ControlRequest>,
    connections: Connections,
    routing: Arc<Mutex<RoutingTable>>,
    resources: resources::ResourceTransfers,
    events: DeliveryQueue,
    overlays: Arc<Mutex<BTreeMap<WorkspaceId, Arc<overlay::Overlay>>>>,
    membership: overlay::MembershipInbox,
    listener: JoinHandle<()>,
}

impl Node {
    pub fn transport_metrics(&self) -> TransportMetrics {
        let mut metrics = self.connections.metrics();
        let queue = self.events.state.lock().unwrap();
        metrics.receive_queue = queue.critical.len() + queue.current.len() + queue.bulk.len();
        metrics
    }

    /// Bind a directly reachable local address. Public discovery, relays and
    /// port mapping are disabled. Fresh identity on every bind in this version.
    pub async fn bind(address: SocketAddr) -> Result<(Self, MessageReceiver)> {
        Self::bind_with_profile(
            address,
            None,
            NetworkProfile::Direct,
            ConnectionBudget::default(),
        )
        .await
    }

    /// Bind using a caller-owned, securely generated and stored 32-byte endpoint
    /// credential. This restores transport identity only, never workspace authority.
    /// The caller must prevent concurrent endpoint instances using this credential.
    pub async fn bind_with_identity(
        address: SocketAddr,
        secret: &[u8; 32],
    ) -> Result<(Self, MessageReceiver)> {
        Self::bind_with_profile(
            address,
            Some(secret),
            NetworkProfile::Direct,
            ConnectionBudget::default(),
        )
        .await
    }

    /// Opt in to local-network address advertisement/lookup. This publishes the
    /// endpoint key and addresses, never workspace names or membership authority.
    /// Public lookup services and relay transports remain disabled.
    pub async fn bind_lan(address: SocketAddr) -> Result<(Self, MessageReceiver)> {
        Self::bind_with_profile(
            address,
            None,
            NetworkProfile::Lan,
            ConnectionBudget::default(),
        )
        .await
    }

    /// Opt in to LAN lookup while retaining a workspace-scoped endpoint identity.
    /// Advertises this endpoint key and addresses, never membership authority.
    pub async fn bind_lan_with_identity(
        address: SocketAddr,
        secret: &[u8; 32],
    ) -> Result<(Self, MessageReceiver)> {
        Self::bind_with_profile(
            address,
            Some(secret),
            NetworkProfile::Lan,
            ConnectionBudget::default(),
        )
        .await
    }

    /// Local device-level invitation discovery, isolated from workspace endpoint discovery.
    pub async fn bind_nearby_with_identity(
        address: SocketAddr,
        secret: &[u8; 32],
    ) -> Result<(Self, MessageReceiver)> {
        Self::bind_with_profile(
            address,
            Some(secret),
            NetworkProfile::Nearby,
            ConnectionBudget::default(),
        )
        .await
    }

    /// Opt in to Iroh's public Pkarr address lookup and relay network while
    /// retaining LAN lookup. These services provide routes, never membership.
    pub async fn bind_wan_with_identity(
        address: SocketAddr,
        secret: &[u8; 32],
    ) -> Result<(Self, MessageReceiver)> {
        Self::bind_with_profile(
            address,
            Some(secret),
            NetworkProfile::Wan,
            ConnectionBudget::default(),
        )
        .await
    }

    /// Diagnostic WAN profile that forces authenticated traffic through Iroh
    /// relays while leaving the device's Wi-Fi connection intact.
    pub async fn bind_relay_with_identity(
        address: SocketAddr,
        secret: &[u8; 32],
    ) -> Result<(Self, MessageReceiver)> {
        Self::bind_with_profile(
            address,
            Some(secret),
            NetworkProfile::RelayOnly,
            ConnectionBudget::default(),
        )
        .await
    }

    /// Diagnostic WAN profile that uses only public endpoint lookup and ignores
    /// LAN discovery and saved IP hints while retaining direct Iroh paths.
    pub async fn bind_wan_only_with_identity(
        address: SocketAddr,
        secret: &[u8; 32],
    ) -> Result<(Self, MessageReceiver)> {
        Self::bind_with_profile(
            address,
            Some(secret),
            NetworkProfile::WanOnly,
            ConnectionBudget::default(),
        )
        .await
    }

    /// Bind using Tor's custom transport and an endpoint identity that derives
    /// the onion address. Requires a local Tor daemon on ports 9050 and 9051.
    #[cfg(feature = "tor")]
    pub async fn bind_tor_with_identity(secret: &[u8; 32]) -> Result<(Self, MessageReceiver)> {
        Self::bind_with_profile(
            SocketAddr::from(([0, 0, 0, 0], 0)),
            Some(secret),
            NetworkProfile::Tor,
            ConnectionBudget::default(),
        )
        .await
    }

    /// Bind an independently identified endpoint using host-owned shared device
    /// capacity. Clone the same budget for each workspace and discovery endpoint.
    pub async fn bind_with_profile(
        address: SocketAddr,
        secret: Option<&[u8; 32]>,
        profile: NetworkProfile,
        budget: ConnectionBudget,
    ) -> Result<(Self, MessageReceiver)> {
        Self::bind_with_profile_and_relays(address, secret, profile, budget, None).await
    }

    /// Bind with a caller-supplied relay map and TLS trust configuration.
    ///
    /// This is intended for controlled relay qualification and operator-managed
    /// relay deployments. The caller must select `NetworkProfile::RelayOnly`
    /// when direct paths must be excluded.
    pub async fn bind_with_profile_and_relay(
        address: SocketAddr,
        secret: Option<&[u8; 32]>,
        profile: NetworkProfile,
        budget: ConnectionBudget,
        relay: RelayOptions,
    ) -> Result<(Self, MessageReceiver)> {
        Self::bind_with_profile_and_relays(address, secret, profile, budget, Some(relay)).await
    }

    async fn bind_with_profile_and_relays(
        address: SocketAddr,
        secret: Option<&[u8; 32]>,
        profile: NetworkProfile,
        budget: ConnectionBudget,
        relay: Option<RelayOptions>,
    ) -> Result<(Self, MessageReceiver)> {
        let connections = Connections::bind(
            address,
            profile,
            secret.map(iroh::SecretKey::from_bytes),
            budget.clone(),
            vec![ALPN.to_vec(), control::ALPN.to_vec()],
            relay,
        )
        .await?;
        let routing = Arc::new(Mutex::new(RoutingTable::default()));
        let resources = resources::ResourceTransfers::new(connections.clone(), routing.clone());
        let events = DeliveryQueue::default();
        let receiver = MessageReceiver {
            queue: events.clone(),
        };
        let (control_inbox, controls, control_signal) = control::ControlInbox::new(512);
        let (control_cancel, _) = watch::channel(false);
        let node_control_inbox = control_inbox.clone();
        let overlays: Arc<Mutex<BTreeMap<WorkspaceId, Arc<overlay::Overlay>>>> =
            Arc::new(Mutex::new(BTreeMap::new()));
        let accepted_connections = connections.clone();
        let shared = routing.clone();
        let output = events.clone();
        let accepted_overlays = overlays.clone();
        let accepted_resources = resources.clone();
        let listener = tokio::spawn(async move {
            // Handshakes release their slot before application work. Slow data
            // peers cannot occupy the slots needed to reach the control budget.
            let handshake_capacity = budget.handshakes;
            let [data_capacity, control_capacity] = budget.exchanges;
            let mut workers = tokio::task::JoinSet::new();
            while let Some(incoming) = accepted_connections.accept().await {
                while workers.try_join_next().is_some() {}
                let Ok(permit) = handshake_capacity.clone().try_acquire_owned() else {
                    incoming.refuse();
                    continue;
                };
                let control_inbox = control_inbox.clone();
                let control_capacity = control_capacity.clone();
                let data_capacity = data_capacity.clone();
                let routing = shared.clone();
                let overlays = accepted_overlays.clone();
                let connections = accepted_connections.clone();
                let output = output.clone();
                let resources = accepted_resources.clone();
                workers.spawn(async move {
                    let mut stage = "accept connection";
                    let mut remote = None;
                    let mut connection_id = None;
                    let mut observed_connection = None;
                    let result = async {
                        let observed_address = incoming.remote_addr();
                        let connection = tokio::time::timeout(TIMEOUT, incoming).await
                            .map_err(|_| Error::Timeout("accept connection"))?.map_err(transport)?;
                        drop(permit);
                        observed_connection = Some(connection.clone());
                        let sender = *connection.remote_id().as_bytes();
                        remote = Some(connection.remote_id());
                        connection_id = Some(connection.stable_id());
                        let is_control = connection.alpn() == control::ALPN;
                        let overlay = {
                            let overlays = overlays.lock().await;
                            overlays
                                .values()
                                .find(|overlay| overlay.alpn.as_slice() == connection.alpn())
                                .map(|overlay| {
                                    (
                                        overlay.workspace,
                                        overlay.revision(),
                                        overlay.gossip.clone(),
                                    )
                                })
                        };
                        if let Some((workspace, revision, gossip)) = overlay {
                            routing
                                .lock()
                                .await
                                .authorizes_endpoint(workspace, revision, sender)?;
                            stage = "accept gossip";
                            tokio::time::timeout(control::CONTROL_TIMEOUT, gossip.handle_connection(connection))
                                .await.map_err(|_| Error::Timeout("accept gossip"))?.map_err(transport)?;
                            return Ok(());
                        }
                        // A removed overlay's already-negotiated ALPN must never
                        // be interpreted as the direct-frame schema.
                        if !is_control && connection.alpn() != ALPN {
                            return Err(Error::InvalidFrame);
                        }
                        // An idle exchange link may give way when the device is full.
                        let connection_key = connection.stable_id();
                        connections.mark_evictable(connection_key);
                        let (capacity, budget) = if is_control {
                            (control_capacity, control::CONTROL_TIMEOUT)
                        } else {
                            (data_capacity, TIMEOUT)
                        };
                        let address = match observed_address {
                            iroh::endpoint::IncomingAddr::Ip(address) => Some(address),
                            _ => None,
                        };
                        stage = "receive exchanges";
                        tracing::info!(target: "data_fabric_transport", ?remote, ?connection_id, paths = ?connection.paths(), "TRANSPORT_RECEIVE_CONNECTED");
                        let connection = &connection;
                        let connections = &connections;
                        let routing = &routing;
                        let output = &output;
                        let control_inbox = &control_inbox;
                        let resources = &resources;
                        let mut exchanges = stream::FuturesUnordered::new();
                        let idle = tokio::time::sleep(CONNECTION_IDLE);
                        tokio::pin!(idle);
                        loop {
                            tokio::select! {
                                streams = connection.accept_bi() => {
                                    let Ok((mut send, mut recv)) = streams else { return Ok(()); };
                                    let Ok(permit) = capacity.clone().try_acquire_owned() else {
                                        let _ = send.reset(1u8.into());
                                        let _ = recv.stop(1u8.into());
                                        continue;
                                    };
                                    idle.as_mut().reset(tokio::time::Instant::now() + CONNECTION_IDLE);
                                    let guard = connections.exchange(connection_key);
                                    exchanges.push(async move {
                                        let _permit = permit;
                                        let _guard = guard;
                                        let result = async {
                                            if !is_control {
                                                let mut kind = [0; 1];
                                                tokio::time::timeout(TIMEOUT, recv.read_exact(&mut kind)).await
                                                    .map_err(|_| Error::Timeout("stream kind"))?.map_err(transport)?;
                                                match kind[0] {
                                                    resources::STREAM_KIND => return resources.serve(connection, &mut send, &mut recv).await,
                                                    0 => (),
                                                    _ => return Err(Error::InvalidFrame),
                                                }
                                            }
                                            tokio::time::timeout(budget, async {
                                              if is_control {
                                                control::receive(connection, control_inbox, address, (&mut send, &mut recv)).await
                                              } else {
                                                receive_frame(connection, connections, routing, output, address, (&mut send, &mut recv)).await
                                              }
                                            }).await.map_err(|_| Error::Timeout("receive exchange"))?
                                        }.await;
                                        // Dropping a QUIC SendStream finishes it. An
                                        // abandoned/expired exchange must reset instead
                                        // of looking like a successful empty reply.
                                        if result.is_err() {
                                            let _ = send.reset(1u8.into());
                                            let _ = recv.stop(1u8.into());
                                        }
                                        tracing::info!(target: "data_fabric_transport", ?remote, ?connection_id, is_control, ?result, "TRANSPORT_EXCHANGE_END");
                                    });
                                }
                                _ = exchanges.next(), if !exchanges.is_empty() => {
                                    idle.as_mut().reset(tokio::time::Instant::now() + CONNECTION_IDLE);
                                }
                                _ = &mut idle, if exchanges.is_empty() => {
                                    connection.close(0u8.into(), b"idle");
                                    return Ok(());
                                }
                            }
                        }
                    }
                    .await;
                    tracing::info!(target: "data_fabric_transport", ?remote, ?connection_id, stage, ?result, "TRANSPORT_RECEIVE_END");
                    if result.is_err() {
                        tracing::info!(target: "data_fabric_transport", ?remote, ?connection_id,
                            stats = ?observed_connection.as_ref().map(|connection| connection.stats()),
                            "TRANSPORT_RECEIVE_STATS");
                    }
                });
            }
        });
        let control_signal_for_membership = control_signal.clone();
        Ok((
            Self {
                controls,
                control_inbox: node_control_inbox,
                control_signal,
                control_cancel,
                deferred_controls: std::collections::VecDeque::new(),
                connections,
                routing,
                resources,
                events,
                overlays,
                membership: overlay::MembershipInbox::new(control_signal_for_membership),
                listener,
            },
            receiver,
        ))
    }

    pub fn id(&self) -> PeerId {
        self.connections.id()
    }

    /// A session-local cancellation latch for outbound control exchanges.
    pub fn control_cancellation(&self) -> watch::Sender<bool> {
        self.control_cancel.clone()
    }

    /// Next membership step received by gossip, as (workspace, opaque bytes).
    /// Delivered without a policy revision check (ADR 0008): the caller must
    /// verify the step itself against its own saved state before using it.
    pub fn poll_membership_gossip(&self) -> Option<(WorkspaceId, Vec<u8>)> {
        self.membership.pop()
    }

    /// Wait for one queued membership envelope for `workspace`.
    /// The caller owns the deadline; no polling interval is introduced here.
    pub async fn wait_for_membership_gossip(&self, workspace: WorkspaceId) -> Option<Vec<u8>> {
        loop {
            let notified = self.control_signal.notified();
            if let Some(payload) = self.membership.pop_for(workspace) {
                return Some(payload);
            }
            notified.await;
        }
    }

    /// Broadcast a committed membership step on the workspace overlay's
    /// reserved membership topic. Owned so the host can spawn it. Ok(false)
    /// means no overlay or no remote member to send to.
    pub fn broadcast_membership(
        &self,
        workspace: WorkspaceId,
        payload: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<bool>> + Send + 'static {
        let overlays = self.overlays.clone();
        let sender = self.id();
        async move {
            let Some(overlay) = overlays.lock().await.get(&workspace).cloned() else {
                return Ok(false);
            };
            overlay.broadcast_membership(sender, payload).await
        }
    }
    pub fn address(&self) -> SocketAddr {
        self.connections.address()
    }

    /// Wait until the endpoint has an active relay connection.
    ///
    /// This is only needed by callers that explicitly selected a relay-only
    /// profile. It is event-driven and does not add a polling delay or fallback.
    pub async fn wait_online(&self) {
        self.connections.wait_online().await;
    }

    pub fn resources(&self) -> resources::ResourceTransfers {
        self.resources.clone()
    }

    /// Android cannot detect host network changes from native code. The Java
    /// connectivity callback must forward them so Iroh can rebind its sockets.
    pub async fn network_change(&self) {
        self.connections.network_change().await;
    }

    pub async fn add_address_hint(&self, peer: PeerId, address: SocketAddr) -> Result<()> {
        self.connections.add_address_hint(peer, address).await?;
        let overlays = self
            .overlays
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for overlay in overlays {
            let authorized = self
                .routing
                .lock()
                .await
                .authorizes_endpoint(overlay.workspace, overlay.revision(), peer)
                .is_ok();
            if authorized && peer != self.id() {
                if overlay.is_joined() {
                    overlay.join_peer(peer).await?;
                } else {
                    tracing::info!(target: "data_fabric_transport", peer = %iroh::EndpointId::from_bytes(&peer).map(|p| p.fmt_short().to_string()).unwrap_or_default(), "GOSSIP_OVERLAY_REBUILD_ON_HINT");
                    let peers = self
                        .routing
                        .lock()
                        .await
                        .authorized_endpoints(overlay.workspace, overlay.revision())?;
                    let replacement = overlay::Overlay::prepare(
                        &self.connections,
                        overlay.workspace,
                        overlay.revision(),
                        peers,
                        self.routing.clone(),
                        self.events.clone(),
                        self.membership.clone(),
                    )
                    .await?;
                    self.overlays
                        .lock()
                        .await
                        .insert(overlay.workspace, Arc::new(replacement));
                }
            }
        }
        Ok(())
    }

    /// Remember an authenticated return path without synchronously changing
    /// any workspace gossip overlay. Control-plane observations use this
    /// narrow path so a presence reply cannot wait on peer discovery.
    pub async fn remember_observed(&self, peer: PeerId, address: SocketAddr) {
        self.connections.remember_observed(peer, address).await;
    }

    /// A cached route is only a hint. Callers must separately authorize any
    /// workspace metadata they share with it.
    pub async fn address_hint(&self, peer: PeerId) -> Option<SocketAddr> {
        self.connections.address_hint(peer).await
    }

    /// Whether the configured Iroh transport can resolve a destination from
    /// its authenticated endpoint ID without a socket address hint.
    pub fn can_dial_by_peer_id(&self) -> bool {
        self.connections.can_dial_by_peer_id()
    }

    /// Endpoints passively observed on the application-named local mDNS service.
    /// These are route hints only and carry no workspace or human identity claim.
    pub async fn nearby_peers(&self) -> Vec<PeerId> {
        self.connections.nearby_peers(true).await
    }

    /// Return a bounded batch for workspace advertisement queries.
    pub async fn nearby_workspace_peers(&self) -> Vec<PeerId> {
        self.connections.nearby_peers(false).await
    }

    /// Trusted application seam. Never invoke with an unverified network policy.
    /// The caller resolves member/device bindings into endpoint permissions; this
    /// module neither establishes those bindings nor verifies admin authority.
    pub async fn install_verified_policy(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        endpoint_permissions: BTreeMap<PeerId, Permissions>,
    ) -> Result<()> {
        let replace_overlay = self.overlays.lock().await.contains_key(&workspace);
        let peers = endpoint_permissions.keys().copied().collect::<Vec<_>>();
        self.routing.lock().await.install_verified_policy(
            workspace,
            revision,
            endpoint_permissions,
        )?;
        self.resources.policy_changed();
        if replace_overlay {
            if !peers.contains(&self.id()) {
                self.connections
                    .authorize_gossip(overlay::alpn(workspace), Vec::new())
                    .await;
                self.overlays.lock().await.remove(&workspace);
                return Ok(());
            }
            self.connections
                .authorize_gossip(overlay::alpn(workspace), peers.clone())
                .await;
            // An epoch that only adds members keeps the swarm: rebuilding it on
            // every admission dropped all neighbors mid-broadcast (ADR 0008).
            let existing = self.overlays.lock().await.get(&workspace).cloned();
            if existing.is_some_and(|overlay| overlay.advance(revision, &peers)) {
                return Ok(());
            }
            let candidate = overlay::Overlay::prepare(
                &self.connections,
                workspace,
                revision,
                peers,
                self.routing.clone(),
                self.events.clone(),
                self.membership.clone(),
            )
            .await?;
            self.overlays
                .lock()
                .await
                .insert(workspace, Arc::new(candidate));
        }
        Ok(())
    }

    /// Enable one bounded workspace-wide live overlay after installing a verified
    /// policy. Direct-recipient publications keep their acknowledged path.
    pub async fn enable_gossip(&self, workspace: WorkspaceId, revision: u64) -> Result<()> {
        if self
            .overlays
            .lock()
            .await
            .get(&workspace)
            .is_some_and(|overlay| overlay.revision() == revision)
        {
            return Ok(());
        }
        let peers = self
            .routing
            .lock()
            .await
            .authorized_endpoints(workspace, revision)?;
        self.connections
            .authorize_gossip(overlay::alpn(workspace), peers.clone())
            .await;
        let candidate = overlay::Overlay::prepare(
            &self.connections,
            workspace,
            revision,
            peers,
            self.routing.clone(),
            self.events.clone(),
            self.membership.clone(),
        )
        .await?;
        self.overlays
            .lock()
            .await
            .insert(workspace, Arc::new(candidate));
        Ok(())
    }

    /// Read the current routing policy under the same lock used for data routing.
    /// The callback must be bounded, synchronous and must not reenter this node.
    /// Owned results may leave the lock; policy references cannot escape it.
    pub async fn with_routing_policy<T>(&self, inspect: impl FnOnce(&RoutingTable) -> T) -> T {
        let routing = self.routing.lock().await;
        inspect(&routing)
    }

    /// Current maintained live neighbors for a workspace overlay. Zero means
    /// no overlay or no connected neighbor; it is not a workspace member count.
    pub async fn live_neighbor_count(&self, workspace: WorkspaceId) -> usize {
        self.overlays
            .lock()
            .await
            .get(&workspace)
            .map_or(0, |overlay| overlay.neighbor_count())
    }

    /// Authenticated direct neighbors in the bounded workspace Gossip view.
    /// These are advisory retrieval candidates, not proof that history exists.
    pub async fn live_neighbors(&self, workspace: WorkspaceId) -> Vec<PeerId> {
        self.overlays
            .lock()
            .await
            .get(&workspace)
            .map_or_else(Vec::new, |overlay| overlay.neighbors())
    }

    /// Wait for the native Gossip overlay to observe at least one neighbor.
    /// The caller owns the deadline; no polling interval is introduced here.
    pub async fn wait_for_gossip_neighbor(&self, workspace: WorkspaceId) -> bool {
        let Some(overlay) = self.overlays.lock().await.get(&workspace).cloned() else {
            return false;
        };
        overlay.wait_for_neighbor().await
    }

    pub async fn subscribe(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        topic: Topic,
    ) -> Result<AdmissionReport> {
        self.interest(workspace, revision, topic, true).await
    }

    pub async fn unsubscribe(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        topic: Topic,
    ) -> Result<AdmissionReport> {
        self.interest(workspace, revision, topic, false).await
    }

    async fn interest(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        topic: Topic,
        subscribe: bool,
    ) -> Result<AdmissionReport> {
        self.prepare_interest(workspace, revision, topic, subscribe)
            .await?
            .await
    }

    /// Apply local interest before returning an owned remote announcement.
    /// Hosts may schedule this future without holding their session lock. They
    /// must serialize announcements; dropping one does not undo local interest.
    pub async fn prepare_interest(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        topic: Topic,
        subscribe: bool,
    ) -> Result<impl std::future::Future<Output = Result<AdmissionReport>> + Send + 'static> {
        let mut peers = {
            let mut routing = self.routing.lock().await;
            let peers = routing.publishers(workspace, revision, self.id(), &topic)?;
            if subscribe {
                routing.subscribe(workspace, revision, self.id(), topic.clone())?;
            } else {
                routing.unsubscribe(workspace, revision, self.id(), &topic)?;
            }
            peers
        };
        let local = self.id();
        let admitted_local = peers.contains(&local);
        peers.retain(|peer| *peer != local);
        // Local interest is already installed. A delayed self-announcement must
        // never overwrite a more recent local unsubscribe.
        let remote = self.fanout(
            peers,
            Frame {
                workspace,
                revision,
                topic: topic.as_str().into(),
                delivery: DeliveryClass::Critical,
                operation: if subscribe {
                    Operation::Subscribe
                } else {
                    Operation::Unsubscribe
                },
            },
        );
        Ok(async move {
            let mut report = remote.await?;
            if admitted_local {
                report.admitted.push(local);
                report.admitted.sort_unstable();
            }
            Ok(report)
        })
    }

    pub async fn publish(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        topic: Topic,
        payload: Vec<u8>,
    ) -> Result<AdmissionReport> {
        self.publish_with_class(workspace, revision, topic, DeliveryClass::Critical, payload)
            .await
    }

    pub async fn publish_with_class(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        topic: Topic,
        delivery: DeliveryClass,
        payload: Vec<u8>,
    ) -> Result<AdmissionReport> {
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::TooLarge);
        }
        let overlay = self.overlays.lock().await.get(&workspace).cloned();
        if let Some(overlay) = overlay {
            if overlay.revision() != revision {
                return Err(Error::Routing(arachne_routing::Error::WrongPolicyRevision));
            }
            let recipients =
                self.routing
                    .lock()
                    .await
                    .recipients(workspace, revision, self.id(), &topic)?;
            let mut report = AdmissionReport::default();
            if recipients.contains(&self.id()) {
                apply(
                    &self.routing,
                    &self.events,
                    self.id(),
                    self.id(),
                    self.id(),
                    Frame {
                        workspace,
                        revision,
                        topic: topic.as_str().into(),
                        delivery,
                        operation: Operation::Publish(payload.clone()),
                    },
                )
                .await?;
                report.admitted.push(self.id());
            }
            report.queued = overlay
                .broadcast(self.id(), &topic, delivery, payload)
                .await?;
            return Ok(report);
        }
        let peers = self
            .routing
            .lock()
            .await
            .recipients(workspace, revision, self.id(), &topic)?;
        self.fanout(
            peers,
            Frame {
                workspace,
                revision,
                topic: topic.as_str().into(),
                delivery,
                operation: Operation::Publish(payload),
            },
        )
        .await
    }

    /// Send to authorized subscribers within the resolved audience. Each selected
    /// endpoint without announced interest gets a non-admission result.
    pub async fn publish_to(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        topic: Topic,
        endpoints: Vec<PeerId>,
        recipients: Vec<[u8; 32]>,
        payload: Vec<u8>,
    ) -> Result<AdmissionReport> {
        self.publish_to_with_class(
            workspace,
            revision,
            topic,
            endpoints,
            recipients,
            DeliveryClass::Critical,
            payload,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn publish_to_with_class(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        topic: Topic,
        endpoints: Vec<PeerId>,
        recipients: Vec<[u8; 32]>,
        delivery: DeliveryClass,
        payload: Vec<u8>,
    ) -> Result<AdmissionReport> {
        if payload.len() > MAX_PAYLOAD
            || recipients.is_empty()
            || recipients.len() > MAX_RECIPIENTS
            || recipients.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Error::Rejected);
        }
        let peers = self.routing.lock().await.direct_recipients(
            workspace,
            revision,
            self.id(),
            &topic,
            &endpoints,
        )?;
        let skipped: Vec<_> = endpoints
            .into_iter()
            .filter(|peer| peers.binary_search(peer).is_err())
            .collect();
        let mut report = self
            .fanout(
                peers,
                Frame {
                    workspace,
                    revision,
                    topic: topic.as_str().into(),
                    delivery,
                    operation: Operation::DirectPublish {
                        payload,
                        recipients,
                    },
                },
            )
            .await?;
        report
            .failed
            .extend(skipped.into_iter().map(|peer| (peer, Error::NotSubscribed)));
        report.failed.sort_unstable_by_key(|(peer, _)| *peer);
        Ok(report)
    }

    fn fanout(
        &self,
        peers: Vec<PeerId>,
        frame: Frame,
    ) -> impl std::future::Future<Output = Result<AdmissionReport>> + Send + 'static {
        let connections = self.connections.clone();
        let routing = self.routing.clone();
        let events = self.events.clone();
        let local = self.id();
        async move {
            let bytes = wire::encode(&frame)?;
            let mut report = AdmissionReport::default();
            // ponytail: 16 concurrent operations per fanout; connection reuse and a
            // sparse overlay still need measurement before large-workspace claims.
            let mut pending = stream::iter(peers.into_iter().map(|peer| {
                let frame = &frame;
                let bytes = &bytes;
                let connections = &connections;
                let routing = &routing;
                let events = &events;
                async move {
                    let result = if peer == local {
                        match wire::decode(bytes) {
                            Ok(copy) => apply(routing, events, local, local, local, copy).await,
                            Err(_) => Err(Error::InvalidFrame),
                        }
                    } else {
                        send_frame(connections, routing, peer, frame, bytes).await
                    };
                    (peer, result)
                }
            }))
            .buffer_unordered(16);
            while let Some((peer, result)) = pending.next().await {
                match result {
                    Ok(()) => report.admitted.push(peer),
                    Err(error) => report.failed.push((peer, error)),
                }
            }
            // Preserve the public report's deterministic peer order.
            report.admitted.sort_unstable();
            report.failed.sort_unstable_by_key(|(peer, _)| *peer);
            Ok(report)
        }
    }

    pub async fn close(mut self) {
        self.resources.close().await;
        self.overlays.lock().await.clear();
        self.connections.close().await;
        self.listener.abort();
        let _ = (&mut self.listener).await;

    }
}

async fn receive_frame(
    connection: &iroh::endpoint::Connection,
    connections: &Connections,
    routing: &Mutex<RoutingTable>,
    output: &DeliveryQueue,
    address: Option<SocketAddr>,
    (send, recv): (
        &mut iroh::endpoint::SendStream,
        &mut iroh::endpoint::RecvStream,
    ),
) -> Result<()> {
    let sender = *connection.remote_id().as_bytes();
    let bytes = recv.read_to_end(MAX_FRAME).await.map_err(transport)?;
    tracing::info!(target: "data_fabric_transport", remote = %connection.remote_id(), connection_id = connection.stable_id(), bytes = bytes.len(), "TRANSPORT_FRAME_RECEIVED");
    let outcome = match wire::decode::<Frame>(&bytes) {
        Ok(frame) => apply(routing, output, connections.id(), sender, sender, frame).await,
        Err(_) => Err(Error::InvalidFrame),
    };
    // Reusing transport identity never caches workspace authority. Remember an
    // observed direct path only after this particular frame is authorized.
    if outcome.is_ok()
        && let Some(address) = address
    {
        connections.remember_observed(sender, address).await;
    }
    tracing::info!(target: "data_fabric_transport", remote = %connection.remote_id(), connection_id = connection.stable_id(), ?outcome, "TRANSPORT_ADMISSION");
    send.write_all(&[u8::from(outcome.is_ok())])
        .await
        .map_err(transport)?;
    send.finish().map_err(transport)?;
    Ok(())
}

async fn send_frame(
    connections: &Connections,
    routing: &Mutex<RoutingTable>,
    peer: PeerId,
    frame: &Frame,
    bytes: &[u8],
) -> Result<()> {
    let key = iroh::PublicKey::from_bytes(&peer).map_err(transport)?;
    let mut stage = "connect";
    let mut observed_connection = None;
    tracing::info!(target: "data_fabric_transport", remote = %key, bytes = bytes.len(), "TRANSPORT_SEND_BEGIN");
    let result = tokio::time::timeout(connections.operation_timeout(), async {
        let connection = connections.connect(peer, ALPN).await?;
        observed_connection = Some(connection.clone());
        tracing::info!(target: "data_fabric_transport", remote = %key, connection_id = connection.stable_id(), paths = ?connection.paths(), "TRANSPORT_SEND_CONNECTED");
        stage = "open stream";
        let (mut send, mut recv) = connection.open_bi().await.map_err(transport)?;
        // Connection establishment can outlive a policy change. Recheck at
        // outbound admission; already-admitted bytes may remain in flight.
        stage = "recheck authorization";
        let topic = Topic::new(frame.topic.clone())?;
        let routing = routing.lock().await;
        let allowed = match &frame.operation {
            Operation::Publish(_) => {
                routing.recipients(frame.workspace, frame.revision, connections.id(), &topic)?
            }
            Operation::DirectPublish { .. } => routing.direct_recipients(
                frame.workspace,
                frame.revision,
                connections.id(),
                &topic,
                &[peer],
            )?,
            _ => {
                routing.publishers(frame.workspace, frame.revision, connections.id(), &topic)?
            }
        };
        if !allowed.contains(&peer) {
            return Err(Error::Routing(arachne_routing::Error::Denied));
        }
        drop(routing);
        stage = "write frame";
        send.write_all(&[0]).await.map_err(transport)?;
        send.write_all(bytes).await.map_err(transport)?;
        send.finish().map_err(transport)?;
        stage = "read acknowledgment";
        let ack = recv.read_to_end(1).await.map_err(transport)?;
        if ack == [1] {
            Ok(())
        } else {
            Err(Error::Rejected)
        }
    })
    .await
    .map_err(|_| Error::Timeout(stage))
    .and_then(|result| result);
    tracing::info!(target: "data_fabric_transport", remote = %key, stage, ?result, "TRANSPORT_SEND_END");
    if result.is_err() {
        tracing::info!(target: "data_fabric_transport", remote = %key,
            stats = ?observed_connection.as_ref().map(|connection| connection.stats()),
            "TRANSPORT_SEND_STATS");
    }
    result
}

impl Drop for Node {
    fn drop(&mut self) {
        self.resources.stop();
        self.events.close();
        self.listener.abort();
    }
}

fn transport(error: impl std::fmt::Display) -> Error {
    Error::Transport(error.to_string())
}

async fn apply(
    routing: &Mutex<RoutingTable>,
    events: &DeliveryQueue,
    local: PeerId,
    sender: PeerId,
    received_from: PeerId,
    frame: Frame,
) -> Result<()> {
    let topic = Topic::new(frame.topic)?;
    let delivery = frame.delivery;
    let mut routing = routing.lock().await;
    match frame.operation {
        Operation::Subscribe => {
            routing.subscribe(frame.workspace, frame.revision, sender, topic)?
        }
        Operation::Unsubscribe => {
            routing.unsubscribe(frame.workspace, frame.revision, sender, &topic)?
        }
        Operation::Publish(payload) => {
            if payload.len() > MAX_PAYLOAD {
                return Err(Error::TooLarge);
            }
            let recipients = routing.recipients(frame.workspace, frame.revision, sender, &topic)?;
            if !recipients.contains(&local) {
                return Err(Error::Rejected);
            }
            events.push(Message {
                workspace: frame.workspace,
                revision: frame.revision,
                sender,
                received_from,
                topic,
                payload,
                recipients: Vec::new(),
                delivery,
            })?;
        }
        Operation::DirectPublish {
            payload,
            recipients,
        } => {
            if payload.len() > MAX_PAYLOAD
                || recipients.is_empty()
                || recipients.len() > MAX_RECIPIENTS
                || recipients.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(Error::Rejected);
            }
            let recipient_endpoints = routing.direct_recipients(
                frame.workspace,
                frame.revision,
                sender,
                &topic,
                &[local],
            )?;
            if recipient_endpoints != [local] {
                return Err(Error::Rejected);
            }
            events.push(Message {
                workspace: frame.workspace,
                revision: frame.revision,
                sender,
                received_from,
                topic,
                payload,
                recipients,
                delivery,
            })?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn receiver_checks_local_interest_even_if_sender_routes_a_direct_frame() {
    let routing = Mutex::new(RoutingTable::default());
    let events = DeliveryQueue::default();
    let mut received = MessageReceiver {
        queue: events.clone(),
    };
    let topic = Topic::new("streams/opaque").unwrap();
    routing
        .lock()
        .await
        .install_verified_policy(
            [9; 32],
            1,
            BTreeMap::from([
                ([1; 32], Permissions::AllTopics),
                ([2; 32], Permissions::AllTopics),
            ]),
        )
        .unwrap();
    let frame = || Frame {
        workspace: [9; 32],
        revision: 1,
        topic: topic.as_str().into(),
        delivery: DeliveryClass::Critical,
        operation: Operation::DirectPublish {
            payload: vec![0, 255],
            recipients: vec![[3; 32]],
        },
    };
    assert!(
        apply(&routing, &events, [2; 32], [1; 32], [1; 32], frame())
            .await
            .is_err(),
        "receiver admitted a direct frame without local interest"
    );
    routing
        .lock()
        .await
        .subscribe([9; 32], 1, [2; 32], topic.clone())
        .unwrap();
    apply(&routing, &events, [2; 32], [1; 32], [1; 32], frame())
        .await
        .unwrap();
    assert_eq!(received.recv().await.unwrap().payload, vec![0, 255]);
    routing
        .lock()
        .await
        .unsubscribe([9; 32], 1, [2; 32], &topic)
        .unwrap();
    assert!(
        apply(&routing, &events, [2; 32], [1; 32], [1; 32], frame())
            .await
            .is_err(),
        "stale sender interest defeated local unsubscribe"
    );
    assert!(received.try_recv().is_err());
}
