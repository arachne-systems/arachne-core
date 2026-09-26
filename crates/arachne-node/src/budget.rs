//! Host-owned capacity shared by independent workspace endpoints. Permits are
//! resources, not authorization; cancellation and connection close return them.
use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex as StdMutex, RwLock},
    time::{Duration, Instant},
};

use iroh::endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks, Side};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{Error, PeerId, Result};

/// Clone one budget into all endpoints on a device. Workspace identities and
/// connection caches remain independent. Data cannot consume the control reserve.
#[derive(Clone, Debug)]
pub struct ConnectionBudget {
    connections: [Arc<Semaphore>; 2],
    /// Control connections of endpoints no installed policy names (joiners,
    /// probes). Taken together with a control slot, so members always keep
    /// the other half of the control slots.
    stranger_connections: Arc<Semaphore>,
    /// Recent new connections per stranger key, for the per-key rate limit.
    stranger_arrivals: Arc<StdMutex<HashMap<PeerId, (Instant, u32)>>>,
    dials: [Arc<Semaphore>; 2],
    /// Gossip's own dial slots. Shared with data, dials to offline peers held
    /// every slot and a gossip link to a live member waited behind them
    /// (tablet HEWN, 50 closed joiners, 2026-09-18).
    gossip_dials: Arc<Semaphore>,
    /// Established connections, for making room when a plane is full.
    tracked: Arc<StdMutex<HashMap<usize, Tracked>>>,
    evicted: Arc<std::sync::atomic::AtomicU64>,
    refused: Arc<std::sync::atomic::AtomicU64>,
    pub(crate) handshakes: Arc<Semaphore>,
    pub(crate) exchanges: [Arc<Semaphore>; 2],
    /// Stranger control exchanges, taken together with a control exchange.
    pub(crate) stranger_exchanges: Arc<Semaphore>,
}

const GOSSIP_DIALS: usize = 8;
/// New connections one stranger key may open per window. Joiners reuse one
/// cached connection; many new ones from a key are a flood.
const STRANGER_ARRIVALS: u32 = 8;
const STRANGER_WINDOW: Duration = Duration::from_secs(10);
/// Stranger keys whose arrivals are remembered. Keys cost nothing to make:
/// when full, a new stranger waits for a window to end.
const MAX_STRANGER_KEYS: usize = 4096;
/// A connection must be this long without an exchange before it can be
/// closed to make room.
const EVICTABLE_AFTER: Duration = Duration::from_secs(1);
/// How long a new connection waits for an evicted one's slot.
const EVICTION_WAIT: Duration = Duration::from_millis(500);

/// Connections closed to make room, and connections refused for lack of it,
/// since this device started.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct CapacityCounts {
    pub evicted: u64,
    pub refused: u64,
}

#[derive(Debug)]
struct Tracked {
    plane: usize,
    handle: iroh::endpoint::WeakConnectionHandle,
    last_active: Instant,
    /// Exchanges in progress on this connection. One is never closed.
    busy: usize,
    /// Only incoming exchange connections: never gossip links (HyParView
    /// manages those) or this node's own outgoing cache.
    evictable: bool,
    /// No installed policy named the remote when it connected.
    stranger: bool,
}

/// Marks one exchange on a connection; the connection is busy until it drops.
pub(crate) struct ExchangeGuard {
    tracked: Arc<StdMutex<HashMap<usize, Tracked>>>,
    id: usize,
}

impl Drop for ExchangeGuard {
    fn drop(&mut self) {
        if let Some(entry) = self.tracked.lock().unwrap().get_mut(&self.id) {
            entry.busy = entry.busy.saturating_sub(1);
            entry.last_active = Instant::now();
        }
    }
}

impl Default for ConnectionBudget {
    fn default() -> Self {
        // Control is short-lived admission/chat coordination traffic. Keep it
        // bounded, but large enough to queue a shared-link burst without
        // rejecting peers before the application can drain the inbox.
        // Control dials: 16. With 4, dials to offline members (up to the dial
        // timeout each) filled every slot and a live owner got Backpressure on
        // ~4 of 5 catch-up queries (tablets, 2026-09-18).
        Self::new([64, 512], [16, 16])
    }
}

impl ConnectionBudget {
    #[cfg(test)]
    pub(crate) fn control_dials_available(&self) -> usize {
        self.dials[1].available_permits()
    }

    pub(crate) fn gossip_dials(&self) -> Arc<Semaphore> {
        self.gossip_dials.clone()
    }

    #[cfg(test)]
    fn with_gossip_dials(mut self, permits: usize) -> Self {
        self.gossip_dials = Arc::new(Semaphore::new(permits));
        self
    }

    fn new(connections: [usize; 2], dials: [usize; 2]) -> Self {
        let exchanges = [32, 512];
        Self {
            connections: connections.map(|n| Arc::new(Semaphore::new(n))),
            stranger_connections: Arc::new(Semaphore::new((connections[1] / 2).max(1))),
            stranger_arrivals: Arc::default(),
            dials: dials.map(|n| Arc::new(Semaphore::new(n))),
            gossip_dials: Arc::new(Semaphore::new(GOSSIP_DIALS)),
            tracked: Arc::default(),
            evicted: Arc::default(),
            refused: Arc::default(),
            handshakes: Arc::new(Semaphore::new(512)),
            exchanges: exchanges.map(|n| Arc::new(Semaphore::new(n))),
            stranger_exchanges: Arc::new(Semaphore::new(exchanges[1] / 2)),
        }
    }

    /// Count a new connection from a stranger key; false when over its rate.
    fn stranger_arrival(&self, peer: PeerId) -> bool {
        let now = Instant::now();
        let mut arrivals = self.stranger_arrivals.lock().unwrap();
        if arrivals.len() >= MAX_STRANGER_KEYS && !arrivals.contains_key(&peer) {
            arrivals.retain(|_, (start, _)| now.saturating_duration_since(*start) < STRANGER_WINDOW);
            if arrivals.len() >= MAX_STRANGER_KEYS {
                return false;
            }
        }
        let (start, count) = arrivals.entry(peer).or_insert((now, 0));
        if now.saturating_duration_since(*start) >= STRANGER_WINDOW {
            (*start, *count) = (now, 0);
        }
        *count += 1;
        *count <= STRANGER_ARRIVALS
    }

    /// Take a slot, making room by closing an idle link of this plane if
    /// needed. A stranger may close only a stranger's link.
    async fn acquire(
        &self,
        slots: &Arc<Semaphore>,
        plane: usize,
        stranger: bool,
    ) -> Option<OwnedSemaphorePermit> {
        if let Ok(permit) = slots.clone().try_acquire_owned() {
            return Some(permit);
        }
        if !self.evict_idle(plane, stranger) {
            return None;
        }
        tokio::time::timeout(EVICTION_WAIT, slots.clone().acquire_owned())
            .await
            .ok()
            .and_then(|permit| permit.ok())
    }

    pub(crate) fn capacity_counts(&self) -> CapacityCounts {
        CapacityCounts {
            evicted: self.evicted.load(std::sync::atomic::Ordering::Relaxed),
            refused: self.refused.load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// An incoming exchange connection may be closed to make room when idle.
    pub(crate) fn mark_evictable(&self, id: usize) {
        if let Some(entry) = self.tracked.lock().unwrap().get_mut(&id) {
            entry.evictable = true;
        }
    }

    /// An exchange runs on this connection now.
    pub(crate) fn is_busy(&self, id: usize) -> bool {
        self.tracked
            .lock()
            .unwrap()
            .get(&id)
            .is_some_and(|entry| entry.busy != 0)
    }

    pub(crate) fn exchange(&self, id: usize) -> ExchangeGuard {
        if let Some(entry) = self.tracked.lock().unwrap().get_mut(&id) {
            entry.busy += 1;
            entry.last_active = Instant::now();
        }
        ExchangeGuard {
            tracked: self.tracked.clone(),
            id,
        }
    }

    /// Close the longest-idle evictable connection of this plane, a
    /// stranger's first. A device full of idle joiner links refused its
    /// members (500-joiner run, HEWN, 2026-09-19): an idle link now gives way
    /// instead. `only_strangers`: a member's link never gives way to a stranger.
    fn evict_idle(&self, plane: usize, only_strangers: bool) -> bool {
        let now = Instant::now();
        let victim = {
            let tracked = self.tracked.lock().unwrap();
            tracked
                .values()
                .filter(|entry| entry.plane == plane && entry.evictable && entry.busy == 0)
                .filter(|entry| entry.stranger || !only_strangers)
                .filter(|entry| now.saturating_duration_since(entry.last_active) >= EVICTABLE_AFTER)
                .min_by_key(|entry| (!entry.stranger, entry.last_active))
                .and_then(|entry| entry.handle.upgrade())
        };
        let Some(connection) = victim else {
            return false;
        };
        self.evicted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(target: "data_fabric_transport", remote = %connection.remote_id().fmt_short(), "CONNECTION_EVICTED_IDLE");
        connection.close(0u32.into(), b"idle; device connection capacity");
        true
    }

    pub(crate) fn dial(&self, alpn: &[u8]) -> Result<OwnedSemaphorePermit> {
        self.dials[plane(alpn)]
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Backpressure)
    }
}

fn plane(alpn: &[u8]) -> usize {
    usize::from(alpn == crate::control::ALPN)
}

impl ConnectionBudget {
    /// Admit an established connection into its plane's slots. A stranger
    /// takes a stranger slot too, and is rate limited per key.
    async fn admit(&self, connection: &Connection, stranger: bool) -> AfterHandshakeOutcome {
        let plane = plane(connection.alpn());
        let stranger = stranger && plane == 1;
        let remote = *connection.remote_id().as_bytes();
        let refuse = |reason: &'static [u8]| {
            self.refused
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::info!(target: "data_fabric_transport", remote = %connection.remote_id().fmt_short(), plane, stranger, "CONNECTION_REFUSED_CAPACITY");
            AfterHandshakeOutcome::Reject {
                error_code: 429u32.into(),
                reason: reason.to_vec(),
            }
        };
        if stranger && !self.stranger_arrival(remote) {
            return refuse(b"stranger connection rate");
        }
        let stranger_permit = if stranger {
            match self.acquire(&self.stranger_connections, plane, true).await {
                Some(permit) => Some(permit),
                None => return refuse(b"device connection capacity"),
            }
        } else {
            None
        };
        let Some(permit) = self.acquire(&self.connections[plane], plane, stranger).await else {
            return refuse(b"device connection capacity");
        };
        let id = connection.stable_id();
        let handle = connection.weak_handle();
        self.tracked.lock().unwrap().insert(
            id,
            Tracked {
                plane,
                handle: handle.clone(),
                last_active: Instant::now(),
                busy: 0,
                evictable: false,
                stranger,
            },
        );
        // Iroh's weak close future does not keep an otherwise idle connection
        // alive. No endpoint reference cycle or strong observer ownership.
        let closed = handle.closed();
        let tracked = self.tracked.clone();
        tokio::spawn(async move {
            let _permits = (permit, stranger_permit);
            closed.await;
            tracked.lock().unwrap().remove(&id);
        });
        AfterHandshakeOutcome::Accept
    }
}

/// Endpoints the installed policies of one local endpoint name. Kept current
/// by its Node; a connection from any other key has no workspace authority.
#[derive(Clone, Debug, Default)]
pub(crate) struct Members(Arc<RwLock<BTreeSet<PeerId>>>);

impl Members {
    pub(crate) fn replace(&self, members: BTreeSet<PeerId>) {
        *self.0.write().unwrap() = members;
    }

    pub(crate) fn contains(&self, peer: &PeerId) -> bool {
        self.0.read().unwrap().contains(peer)
    }
}

/// Handshake admission of one endpoint: the data plane only for policy
/// members, and the shared budget with strangers kept to their own share.
#[derive(Debug)]
pub(crate) struct Admission {
    pub(crate) budget: ConnectionBudget,
    pub(crate) members: Members,
}

impl EndpointHooks for Admission {
    async fn after_handshake<'a>(&'a self, connection: &'a Connection) -> AfterHandshakeOutcome {
        // Only who reaches this device is a stranger: its own calls (a
        // joiner calling an owner) never use the stranger share. Outgoing
        // data dials go only to endpoints routing selected.
        let stranger = connection.side() == Side::Server
            && !self.members.contains(connection.remote_id().as_bytes());
        if stranger && connection.alpn() == crate::ALPN {
            tracing::info!(target: "data_fabric_transport", remote = %connection.remote_id().fmt_short(), "DATA_HANDSHAKE_REJECTED_STRANGER");
            return AfterHandshakeOutcome::Reject {
                error_code: 403u32.into(),
                reason: b"not a workspace member".to_vec(),
            };
        }
        self.budget.admit(connection, stranger).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NetworkProfile, Node, Permissions, Topic, connections::Connections};
    use iroh::{Endpoint, EndpointAddr, endpoint::presets};
    use std::collections::BTreeMap;
    use std::time::Duration;

    async fn full_server() -> crate::Node {
        // One incoming control connection fits; the next must make room.
        crate::Node::bind_with_profile(
            "127.0.0.1:0".parse().unwrap(),
            None,
            NetworkProfile::Direct,
            ConnectionBudget::new([4, 1], [4, 4]),
        )
        .await
        .unwrap()
        .0
    }

    async fn serve_one(server: &mut crate::Node) {
        loop {
            if let Some(request) = server.poll_control() {
                request.respond(vec![1]).unwrap();
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// A full device refused every new peer while idle joiner links held all
    /// control slots: members JOSA and BIG RED could not reach the owner during
    /// a 500-joiner run (2026-09-19). The longest-idle link now makes room.
    #[tokio::test]
    async fn a_new_peer_takes_the_slot_of_the_longest_idle_connection() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let mut server = full_server().await;
            let (idle, _) = crate::Node::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let (newcomer, _) = crate::Node::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            for client in [&idle, &newcomer] {
                client
                    .add_address_hint(server.id(), server.address())
                    .await
                    .unwrap();
            }
            let first = tokio::spawn(idle.request_control(server.id(), b"first"));
            serve_one(&mut server).await;
            first.await.unwrap().unwrap();
            tokio::time::sleep(Duration::from_millis(1300)).await;
            let second = tokio::spawn(newcomer.request_control(server.id(), b"second"));
            serve_one(&mut server).await;
            assert_eq!(
                second.await.unwrap().unwrap(),
                vec![1],
                "the new peer was refused"
            );
            // A device run must be able to tell that eviction happened.
            assert_eq!(
                server.connection_capacity(),
                crate::CapacityCounts {
                    evicted: 1,
                    refused: 0
                }
            );
        })
        .await
        .unwrap();
    }

    /// A link that still owes a reply is never closed to make room, however
    /// long the host takes: the owner held joiner requests for up to 10 s.
    #[tokio::test]
    async fn a_connection_waiting_for_its_reply_is_never_evicted() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let mut server = full_server().await;
            let (waiting, _) = crate::Node::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let (newcomer, _) = crate::Node::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            for client in [&waiting, &newcomer] {
                client
                    .add_address_hint(server.id(), server.address())
                    .await
                    .unwrap();
            }
            let pending = tokio::spawn(waiting.request_control(server.id(), b"pending"));
            let request = loop {
                if let Some(request) = server.poll_control() {
                    break request;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            };
            tokio::time::sleep(Duration::from_millis(1300)).await;
            assert!(
                newcomer
                    .request_control(server.id(), b"second")
                    .await
                    .is_err(),
                "a busy link was closed to make room"
            );
            assert_eq!(server.connection_capacity().refused, 1);
            request.respond(vec![7]).unwrap();
            assert_eq!(pending.await.unwrap().unwrap(), vec![7]);
        })
        .await
        .unwrap();
    }

    /// Only an endpoint an installed policy names reaches the data plane. A
    /// stranger used to be admitted and could hold the data exchanges and
    /// blob slots before any membership check (A7).
    #[tokio::test]
    async fn a_stranger_is_refused_at_the_data_handshake() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let (server, _) = crate::Node::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let member = iroh::SecretKey::from_bytes(&[61; 32]);
            let stranger = iroh::SecretKey::from_bytes(&[62; 32]);
            server
                .install_verified_policy(
                    [63; 32],
                    1,
                    std::collections::BTreeMap::from([
                        (server.id(), crate::Permissions::AllTopics),
                        (*member.public().as_bytes(), crate::Permissions::AllTopics),
                    ]),
                )
                .await
                .unwrap();
            let address = EndpointAddr::new(iroh::PublicKey::from_bytes(&server.id()).unwrap())
                .with_ip_addr(server.address());
            let dial = |secret: iroh::SecretKey| {
                let address = address.clone();
                async move {
                    let endpoint = Endpoint::builder(presets::Minimal)
                        .clear_relay_transports()
                        .clear_ip_transports()
                        .bind_addr("127.0.0.1:0")
                        .unwrap()
                        .secret_key(secret)
                        .bind()
                        .await
                        .unwrap();
                    let connection = endpoint.connect(address, crate::ALPN).await.unwrap();
                    (endpoint, connection)
                }
            };
            let (_stranger_endpoint, refused) = dial(stranger).await;
            let reason = tokio::time::timeout(Duration::from_secs(5), refused.closed())
                .await
                .expect("a stranger's data link stayed open");
            assert!(
                format!("{reason:?}").contains("not a workspace member"),
                "{reason:?}"
            );
            let (_member_endpoint, admitted) = dial(member).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert!(admitted.close_reason().is_none());
            server.close().await;
        })
        .await
        .unwrap();
    }

    /// Strangers (joiners, probes) get at most half of the control slots,
    /// and a stranger may close only another stranger's idle link to make
    /// room: a flood of new keys can never push a member off the device.
    #[tokio::test]
    async fn strangers_use_half_the_control_slots_and_never_evict_a_member() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let (mut server, _) = crate::Node::bind_with_profile(
                "127.0.0.1:0".parse().unwrap(),
                None,
                NetworkProfile::Direct,
                ConnectionBudget::new([4, 2], [4, 4]),
            )
            .await
            .unwrap();
            let bind = || crate::Node::bind("127.0.0.1:0".parse().unwrap());
            let (member, _) = bind().await.unwrap();
            let (first, _) = bind().await.unwrap();
            let (second, _) = bind().await.unwrap();
            server
                .install_verified_policy(
                    [64; 32],
                    1,
                    std::collections::BTreeMap::from([
                        (server.id(), crate::Permissions::AllTopics),
                        (member.id(), crate::Permissions::AllTopics),
                    ]),
                )
                .await
                .unwrap();
            for client in [&member, &first, &second] {
                client
                    .add_address_hint(server.id(), server.address())
                    .await
                    .unwrap();
            }
            // A stranger waiting for its reply holds the one stranger slot.
            let pending = tokio::spawn(first.request_control(server.id(), b"pending"));
            let held = loop {
                if let Some(request) = server.poll_control() {
                    break request;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            };
            // Refused at once; a queued request would wait for its reply.
            let refused = tokio::time::timeout(
                Duration::from_secs(3),
                second.request_control(server.id(), b"second"),
            )
            .await;
            assert!(
                matches!(refused, Ok(Err(_))),
                "a second stranger took the member slot"
            );
            let reached = tokio::spawn(member.request_control(server.id(), b"member"));
            serve_one(&mut server).await;
            assert_eq!(reached.await.unwrap().unwrap(), vec![1]);
            held.respond(vec![7]).unwrap();
            assert_eq!(pending.await.unwrap().unwrap(), vec![7]);
            // Both links are idle now. A new stranger may take only the
            // idle stranger's slot, never the member's.
            tokio::time::sleep(Duration::from_millis(1300)).await;
            let third = tokio::spawn(second.request_control(server.id(), b"third"));
            serve_one(&mut server).await;
            assert_eq!(third.await.unwrap().unwrap(), vec![1]);
            assert!(
                member
                    .connections
                    .live_alpns()
                    .contains(&crate::control::ALPN.to_vec()),
                "the member's idle link was closed for a stranger"
            );
            server.close().await;
        })
        .await
        .unwrap();
    }

    /// The stranger share limits who reaches this device, not whom it
    /// calls: a joiner's own calls to endpoints it has no policy for must
    /// not use it up.
    #[tokio::test]
    async fn outgoing_calls_never_take_the_stranger_share() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let (client, _) = crate::Node::bind_with_profile(
                "127.0.0.1:0".parse().unwrap(),
                None,
                NetworkProfile::Direct,
                ConnectionBudget::new([4, 2], [4, 4]),
            )
            .await
            .unwrap();
            let bind = || crate::Node::bind("127.0.0.1:0".parse().unwrap());
            let (mut first, _) = bind().await.unwrap();
            let (mut second, _) = bind().await.unwrap();
            for server in [&first, &second] {
                client
                    .add_address_hint(server.id(), server.address())
                    .await
                    .unwrap();
            }
            let held = tokio::spawn(client.request_control(first.id(), b"held"));
            let request = loop {
                if let Some(request) = first.poll_control() {
                    break request;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            };
            let other = tokio::spawn(client.request_control(second.id(), b"other"));
            tokio::time::timeout(Duration::from_secs(5), serve_one(&mut second))
                .await
                .unwrap_or_else(|_| {
                    panic!("an outgoing call was refused by the caller's own stranger share")
                });
            assert_eq!(
                other.await.unwrap().unwrap(),
                vec![1],
                "an outgoing call was refused by the caller's own stranger share"
            );
            request.respond(vec![7]).unwrap();
            assert_eq!(held.await.unwrap().unwrap(), vec![7]);
            client.close().await;
        })
        .await
        .unwrap();
    }

    /// A gossip dial to a silent peer held its dial slot until Iroh gave up,
    /// with the overlay still running. The dial deadline returns the slot.
    #[tokio::test]
    async fn a_gossip_dial_to_a_silent_peer_returns_its_slot_at_the_dial_deadline() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let budget = ConnectionBudget::default().with_gossip_dials(1);
            let (node, _) = crate::Node::bind_with_profile(
                "127.0.0.1:0".parse().unwrap(),
                Some(&[65; 32]),
                NetworkProfile::Direct,
                budget.clone(),
            )
            .await
            .unwrap();
            let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let silent = *iroh::SecretKey::from_bytes(&[66; 32]).public().as_bytes();
            node.add_address_hint(silent, blackhole.local_addr().unwrap())
                .await
                .unwrap();
            let workspace = [67; 32];
            node.install_verified_policy(
                workspace,
                1,
                std::collections::BTreeMap::from([
                    (node.id(), crate::Permissions::AllTopics),
                    (silent, crate::Permissions::AllTopics),
                ]),
            )
            .await
            .unwrap();
            node.enable_gossip(workspace, 1, &workspace).await.unwrap();
            while budget.gossip_dials.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
            let started = Instant::now();
            while budget.gossip_dials.available_permits() == 0 {
                assert!(
                    started.elapsed() < crate::TIMEOUT + Duration::from_secs(2),
                    "the silent dial held its slot past the dial deadline"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            node.close().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn native_gossip_dials_use_their_own_capacity_and_release_on_cancel_and_success() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let budget = ConnectionBudget::new([4, 1], [1, 1]).with_gossip_dials(1);
            let node = Connections::bind(
                "127.0.0.1:0".parse().unwrap(),
                &crate::NodeOptions::new(NetworkProfile::Direct),
                None,
                budget.clone(),
                vec![],
            )
            .await
            .unwrap();
            let alpn = crate::overlay::ALPN;
            let peer = Endpoint::builder(presets::Minimal)
                .clear_relay_transports()
                .clear_ip_transports()
                .bind_addr("127.0.0.1:0")
                .unwrap()
                .alpns(vec![alpn.to_vec()])
                .bind()
                .await
                .unwrap();
            let id = *peer.id().as_bytes();
            node.add_address_hint(id, peer.bound_sockets()[0])
                .await
                .unwrap();
            let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let unreachable = iroh::SecretKey::from_bytes(&[223; 32]).public();
            node.add_address_hint(*unreachable.as_bytes(), blackhole.local_addr().unwrap())
                .await
                .unwrap();
            node.authorize_gossip([0; 32], vec![id, *unreachable.as_bytes()]);
            let spawn_gossip = || {
                iroh_gossip::net::Gossip::builder()
                    .alpn(alpn)
                    .dial_capacity(node.gossip_dial_capacity())
                    .spawn(node.endpoint())
            };
            let topic = iroh_gossip::TopicId::from_bytes([4; 32]);
            let reserved = budget.gossip_dials().try_acquire_owned().unwrap();
            // Data dials never wait on, or take, gossip slots.
            let data = budget.dial(crate::ALPN).unwrap();
            let queued = spawn_gossip();
            let queued_topic = queued.subscribe(topic, vec![peer.id()]).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(50), peer.accept())
                    .await
                    .is_err(),
                "gossip cannot emit a handshake while its own dial slot is held"
            );
            queued.shutdown().await.unwrap();
            drop(queued_topic);
            drop(queued);
            drop(reserved);
            drop(data);
            let gossip = spawn_gossip();
            let subscription = gossip.subscribe(topic, vec![peer.id()]).await.unwrap();
            let connected = peer.accept().await.unwrap().await.unwrap();
            while budget.gossip_dials.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
            assert!(connected.close_reason().is_none());
            gossip.shutdown().await.unwrap();
            drop(subscription);
            drop(gossip);
            let cancelled = spawn_gossip();
            let subscription = cancelled.subscribe(topic, vec![unreachable]).await.unwrap();
            while budget.gossip_dials.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
            // A gossip dial to an offline peer leaves data and control free.
            assert!(budget.dial(crate::ALPN).is_ok());
            assert!(budget.dial(crate::control::ALPN).is_ok());
            cancelled.shutdown().await.unwrap();
            drop(subscription);
            drop(cancelled);
            while budget.gossip_dials.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
            node.close().await;
            peer.close().await;
            assert_eq!(budget.gossip_dials.available_permits(), 1);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn independent_endpoints_share_capacity_and_control_reserve_without_retaining_links() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let budget = ConnectionBudget::new([1, 1], [1, 1]);
            let dial = budget.dial(crate::ALPN).unwrap();
            assert!(budget.clone().dial(crate::ALPN).is_err());
            assert!(budget.dial(crate::control::ALPN).is_ok());
            drop(dial);
            let first = Connections::bind(
                "127.0.0.1:0".parse().unwrap(),
                &crate::NodeOptions::new(NetworkProfile::Direct),
                None,
                budget.clone(),
                vec![],
            )
            .await
            .unwrap();
            let second = Connections::bind(
                "127.0.0.1:0".parse().unwrap(),
                &crate::NodeOptions::new(NetworkProfile::Direct),
                None,
                budget.clone(),
                vec![],
            )
            .await
            .unwrap();
            assert_ne!(
                first.id(),
                second.id(),
                "capacity must not unify identities"
            );
            let gossip = crate::overlay::ALPN;
            let peer = Endpoint::builder(presets::Minimal)
                .clear_relay_transports()
                .clear_ip_transports()
                .bind_addr("127.0.0.1:0")
                .unwrap()
                .alpns(vec![
                    gossip.to_vec(),
                    crate::ALPN.to_vec(),
                    crate::control::ALPN.to_vec(),
                ])
                .bind()
                .await
                .unwrap();
            let id = *peer.id().as_bytes();
            first.authorize_gossip([0; 32], vec![id]);
            second
                .add_address_hint(id, peer.bound_sockets()[0])
                .await
                .unwrap();
            // Native gossip bypasses the request cache, but not the endpoint's
            // shared established-connection gate.
            let endpoint = first.endpoint();
            let (gossip_link, remote) = tokio::join!(
                endpoint.connect(
                    EndpointAddr::new(peer.id()).with_ip_addr(peer.bound_sockets()[0]),
                    gossip
                ),
                async { peer.accept().await.unwrap().await }
            );
            let gossip_link = gossip_link.unwrap();
            let remote = remote.unwrap();
            assert_eq!(budget.connections[0].available_permits(), 0);
            let (rejected, _) = tokio::join!(second.connect(id, crate::ALPN), async {
                peer.accept().await.unwrap().await
            });
            assert!(
                rejected.is_err(),
                "another endpoint must not get a fresh budget"
            );
            let (control, remote_control) =
                tokio::join!(second.connect(id, crate::control::ALPN), async {
                    peer.accept().await.unwrap().await
                });
            let control = control.unwrap();
            let _remote_control = remote_control.unwrap();
            assert!(
                control.close_reason().is_none(),
                "gossip/data cannot consume control capacity"
            );
            // Drop, do not explicitly close: the budget observer must not keep
            // this native link alive merely to account for it.
            drop(gossip_link);
            remote.closed().await;
            while budget.connections[0].available_permits() == 0 {
                tokio::task::yield_now().await;
            }
            // A cancelled unreachable dial returns capacity immediately, even
            // though Iroh's own connection timeout has not fired.
            let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let unreachable = *iroh::SecretKey::from_bytes(&[222; 32]).public().as_bytes();
            first
                .add_address_hint(unreachable, blackhole.local_addr().unwrap())
                .await
                .unwrap();
            let caller = first.clone();
            let pending =
                tokio::spawn(async move { caller.connect(unreachable, crate::ALPN).await });
            while budget.dials[0].available_permits() != 0 {
                tokio::task::yield_now().await;
            }
            assert!(matches!(
                second.connect(id, crate::ALPN).await,
                Err(Error::Backpressure)
            ));
            pending.abort();
            assert!(pending.await.unwrap_err().is_cancelled());
            assert_eq!(budget.dials[0].available_permits(), 1);
            first
                .add_address_hint(first.id(), first.address())
                .await
                .unwrap();
            assert!(first.connect(first.id(), crate::ALPN).await.is_err());
            assert_eq!(
                budget.dials[0].available_permits(),
                1,
                "failed self-dial returns its slot"
            );
            let (data, remote_data) = tokio::join!(second.connect(id, crate::ALPN), async {
                peer.accept().await.unwrap().await
            });
            let data = data.unwrap();
            let _remote_data = remote_data.unwrap();
            first.close().await;
            assert!(
                data.close_reason().is_none(),
                "closing one workspace must not close another"
            );
            second.close().await;
            peer.close().await;
            while budget
                .connections
                .iter()
                .any(|s| s.available_permits() == 0)
            {
                tokio::task::yield_now().await;
            }
            assert_eq!(budget.dials[0].available_permits(), 1);
            assert_eq!(budget.dials[1].available_permits(), 1);
        })
        .await
        .unwrap();
    }

    #[cfg(feature = "moq")]
    #[tokio::test]
    async fn exhausted_moq_dial_capacity_is_explicit_and_control_still_works() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let mut secrets = [[51; 32], [52; 32]];
            secrets.sort_by_key(|secret| *iroh::SecretKey::from_bytes(secret).public().as_bytes());
            let (dialer, _) = Node::bind_with_profile(
                "127.0.0.1:0".parse().unwrap(),
                Some(&secrets[0]),
                NetworkProfile::Direct,
                ConnectionBudget::new([4, 1], [0, 1]),
            )
            .await
            .unwrap();
            let (mut listener, _) =
                Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &secrets[1])
                    .await
                    .unwrap();
            let topic = Topic::new("ptt/audio").unwrap();
            let policy = BTreeMap::from([
                (dialer.id(), Permissions::AllTopics),
                (listener.id(), Permissions::AllTopics),
            ]);
            dialer
                .add_address_hint(listener.id(), listener.address())
                .await
                .unwrap();
            listener
                .add_address_hint(dialer.id(), dialer.address())
                .await
                .unwrap();
            dialer
                .install_verified_policy([61; 32], 1, policy.clone())
                .await
                .unwrap();
            listener
                .install_verified_policy([61; 32], 1, policy)
                .await
                .unwrap();
            listener
                .enable_moq_delivery([61; 32], 1, dialer.id(), topic.clone())
                .await
                .unwrap();
            assert!(matches!(
                dialer
                    .enable_moq_delivery([61; 32], 1, listener.id(), topic)
                    .await,
                Err(Error::Backpressure)
            ));

            let control = tokio::time::timeout(Duration::from_secs(5), async {
                let request = dialer.request_control(listener.id(), b"control-reserve");
                tokio::pin!(request);
                loop {
                    tokio::select! {
                        result = &mut request => break result,
                        _ = tokio::time::sleep(Duration::from_millis(5)) => {
                            if let Some(request) = listener.poll_control() {
                                request.respond(b"control-ok".to_vec()).unwrap();
                            }
                        }
                    }
                }
            })
            .await
            .unwrap()
            .unwrap();
            assert_eq!(control, b"control-ok");
            dialer.close().await;
            listener.close().await;
        })
        .await
        .unwrap();
    }
}
