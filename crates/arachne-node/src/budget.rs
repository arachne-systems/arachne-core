//! Host-owned capacity shared by independent workspace endpoints. Permits are
//! resources, not authorization; cancellation and connection close return them.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};

use iroh::endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{Error, Result};

/// Clone one budget into all endpoints on a device. Workspace identities and
/// connection caches remain independent. Data cannot consume the control reserve.
#[derive(Clone, Debug)]
pub struct ConnectionBudget {
    connections: [Arc<Semaphore>; 2],
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
}

const GOSSIP_DIALS: usize = 8;
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
        Self {
            connections: connections.map(|n| Arc::new(Semaphore::new(n))),
            dials: dials.map(|n| Arc::new(Semaphore::new(n))),
            gossip_dials: Arc::new(Semaphore::new(GOSSIP_DIALS)),
            tracked: Arc::default(),
            evicted: Arc::default(),
            refused: Arc::default(),
            handshakes: Arc::new(Semaphore::new(512)),
            exchanges: [32, 512].map(|n| Arc::new(Semaphore::new(n))),
        }
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

    /// Close the longest-idle evictable connection of this plane. A device
    /// full of idle joiner links refused its members (500-joiner run, HEWN,
    /// 2026-09-19): an idle link now gives way instead.
    fn evict_idle(&self, plane: usize) -> bool {
        let now = Instant::now();
        let victim = {
            let tracked = self.tracked.lock().unwrap();
            tracked
                .values()
                .filter(|entry| entry.plane == plane && entry.evictable && entry.busy == 0)
                .filter(|entry| now.saturating_duration_since(entry.last_active) >= EVICTABLE_AFTER)
                .min_by_key(|entry| entry.last_active)
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

impl EndpointHooks for ConnectionBudget {
    async fn after_handshake<'a>(&'a self, connection: &'a Connection) -> AfterHandshakeOutcome {
        let plane = plane(connection.alpn());
        let slots = self.connections[plane].clone();
        let permit = match slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let waited = if self.evict_idle(plane) {
                    tokio::time::timeout(EVICTION_WAIT, slots.acquire_owned())
                        .await
                        .ok()
                        .and_then(|permit| permit.ok())
                } else {
                    None
                };
                match waited {
                    Some(permit) => permit,
                    None => {
                        self.refused
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        tracing::info!(target: "data_fabric_transport", remote = %connection.remote_id().fmt_short(), plane, "CONNECTION_REFUSED_CAPACITY");
                        return AfterHandshakeOutcome::Reject {
                            error_code: 429u32.into(),
                            reason: b"device connection capacity".to_vec(),
                        };
                    }
                }
            }
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
            },
        );
        // Iroh's weak close future does not keep an otherwise idle connection
        // alive. No endpoint reference cycle or strong observer ownership.
        let closed = handle.closed();
        let tracked = self.tracked.clone();
        tokio::spawn(async move {
            let _permit = permit;
            closed.await;
            tracked.lock().unwrap().remove(&id);
        });
        AfterHandshakeOutcome::Accept
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NetworkProfile, connections::Connections};
    use iroh::{Endpoint, EndpointAddr, endpoint::presets};
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

    #[tokio::test]
    async fn native_gossip_dials_use_their_own_capacity_and_release_on_cancel_and_success() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let budget = ConnectionBudget::new([4, 1], [1, 1]).with_gossip_dials(1);
            let node = Connections::bind(
                "127.0.0.1:0".parse().unwrap(),
                NetworkProfile::Direct,
                None,
                budget.clone(),
                vec![],
                None,
            )
            .await
            .unwrap();
            let alpn = b"arachne/workspace-gossip/1/dial-test";
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
            node.authorize_gossip(alpn.to_vec(), vec![id, *unreachable.as_bytes()])
                .await;
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
                NetworkProfile::Direct,
                None,
                budget.clone(),
                vec![],
                None,
            )
            .await
            .unwrap();
            let second = Connections::bind(
                "127.0.0.1:0".parse().unwrap(),
                NetworkProfile::Direct,
                None,
                budget.clone(),
                vec![],
                None,
            )
            .await
            .unwrap();
            assert_ne!(
                first.id(),
                second.id(),
                "capacity must not unify identities"
            );
            let gossip = b"arachne/workspace-gossip/1/budget-test";
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
            first.authorize_gossip(gossip.to_vec(), vec![id]).await;
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
}
