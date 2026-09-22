use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Instant,
};

use futures_util::StreamExt;
use iroh::{
    Endpoint, EndpointAddr, PublicKey,
    address_lookup::memory::MemoryLookup,
    endpoint::{AfterHandshakeOutcome, BeforeConnectOutcome, EndpointHooks, presets},
};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use tokio::sync::{Mutex, OnceCell};

use super::{ConnectionBudget, Error, NetworkProfile, PeerId, RelayOptions, Result, transport};

const MAX_ADDRESS_HINTS: usize = 4096;
const MAX_CACHED_CONNECTIONS: usize = 32;
const MAX_CONTROL_CONNECTIONS: usize = 32;
/// First wait after a failed dial; doubles per consecutive failure.
const UNREACHABLE_BACKOFF: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_UNREACHABLE_BACKOFF: std::time::Duration = std::time::Duration::from_secs(120);
const TOR_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(240);
const TOR_OPERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

// The owning Connections instance supplies the local endpoint identity.
// A peer path/address is deliberately absent from this key.
type PeerProtocol = (PeerId, Vec<u8>);

struct CachedConnection {
    connection: Arc<OnceCell<Arc<iroh::endpoint::Connection>>>,
    last_used: Instant,
}

#[derive(Debug, Default)]
struct ObservedConnections {
    live: Vec<iroh::endpoint::WeakConnectionHandle>,
    limited: bool,
}

#[derive(Clone, Debug, Default)]
struct ConnectionObserver(Arc<RwLock<ObservedConnections>>);

impl EndpointHooks for ConnectionObserver {
    async fn after_handshake<'a>(
        &'a self,
        connection: &'a iroh::endpoint::Connection,
    ) -> AfterHandshakeOutcome {
        if connection
            .alpn()
            .starts_with(super::overlay::ALPN_PREFIX)
        {
            tracing::info!(
                target: "data_fabric_transport",
                peer = %connection.remote_id().fmt_short(),
                "GOSSIP_HANDSHAKE_ACCEPTED"
            );
        }
        let mut observed = self.0.write().unwrap();
        observed
            .live
            .retain(|weak| weak.upgrade().is_some_and(|c| c.close_reason().is_none()));
        // Diagnostic observation must neither retain connections nor grow with
        // untrusted connection attempts. Report the ceiling rather than invent paths.
        if observed.live.len() < 256 {
            observed.live.push(connection.weak_handle());
        } else {
            observed.limited = true;
        }
        AfterHandshakeOutcome::Accept
    }
}

#[derive(Clone, Debug, Default)]
struct GossipAuthorization(Arc<RwLock<BTreeMap<Vec<u8>, BTreeSet<PeerId>>>>);

impl GossipAuthorization {
    fn allows(&self, alpn: &[u8], peer: PeerId) -> bool {
        self.0
            .read()
            .unwrap()
            .get(alpn)
            .is_some_and(|allowed| allowed.contains(&peer))
    }
}

impl EndpointHooks for GossipAuthorization {
    async fn before_connect<'a>(
        &'a self,
        remote: &'a EndpointAddr,
        alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        let allowed = !alpn.starts_with(super::overlay::ALPN_PREFIX)
            || self.allows(alpn, *remote.id.as_bytes());
        if allowed {
            BeforeConnectOutcome::Accept
        } else {
            tracing::warn!(
                target: "data_fabric_transport",
                peer = %remote.id.fmt_short(),
                "GOSSIP_CONNECT_REJECTED"
            );
            BeforeConnectOutcome::Reject
        }
    }

    async fn after_handshake<'a>(
        &'a self,
        connection: &'a iroh::endpoint::Connection,
    ) -> AfterHandshakeOutcome {
        let allowed = !connection
            .alpn()
            .starts_with(super::overlay::ALPN_PREFIX)
            || self.allows(connection.alpn(), *connection.remote_id().as_bytes());
        if allowed {
            AfterHandshakeOutcome::Accept
        } else {
            tracing::warn!(
                target: "data_fabric_transport",
                peer = %connection.remote_id().fmt_short(),
                "GOSSIP_HANDSHAKE_REJECTED"
            );
            AfterHandshakeOutcome::Reject {
                error_code: 403u32.into(),
                reason: b"workspace endpoint denied".to_vec(),
            }
        }
    }
}

/// Wait before redialing a peer after `failures` consecutive dial timeouts:
/// 5 s, doubling, capped at 120 s.
fn unreachable_backoff(failures: u32) -> std::time::Duration {
    UNREACHABLE_BACKOFF
        .saturating_mul(1 << failures.saturating_sub(1).min(5))
        .min(MAX_UNREACHABLE_BACKOFF)
}

/// Device paths and Iroh endpoint lifecycle. Workspace authorization and
/// dissemination stay in `Node`; an address is only a dial hint.
#[derive(Clone)]
pub(super) struct Connections {
    endpoint: Endpoint,
    budget: ConnectionBudget,
    bound_address: SocketAddr,
    addresses: Arc<Mutex<BTreeMap<PeerId, SocketAddr>>>,
    memory: MemoryLookup,
    alpns: Arc<Mutex<BTreeSet<Vec<u8>>>>,
    gossip_authorization: GossipAuthorization,
    observer: ConnectionObserver,
    outgoing: Arc<Mutex<BTreeMap<PeerProtocol, CachedConnection>>>,
    nearby: Arc<Mutex<BTreeSet<PeerId>>>,
    nearby_listener: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Peers whose last dial failed: retry time and consecutive failures.
    /// Dials to offline members must not hold the few control dial slots.
    unreachable: Arc<Mutex<BTreeMap<PeerId, (Instant, u32)>>>,
    address_lookup: bool,
    use_ip_hints: bool,
    tor: bool,
    #[cfg(feature = "tor")]
    _tor_transport: Option<Arc<iroh_tor_transport::TorCustomTransport>>,
}

impl Connections {
    pub(super) async fn bind(
        address: SocketAddr,
        profile: NetworkProfile,
        secret: Option<iroh::SecretKey>,
        budget: ConnectionBudget,
        alpns: Vec<Vec<u8>>,
        relay: Option<RelayOptions>,
    ) -> Result<Self> {
        let (mdns_service, wan_lookup, relay_only, use_ip_hints) = profile.settings();
        #[cfg(feature = "tor")]
        let tor_transport = if profile.uses_tor() {
            if relay.is_some() {
                return Err(Error::Transport(
                    "Tor profile cannot be combined with an Iroh relay".into(),
                ));
            }
            let secret = secret.clone().ok_or_else(|| {
                Error::Transport("Tor profile requires a stable endpoint identity".into())
            })?;
            Some(
                iroh_tor_transport::TorCustomTransport::builder()
                    .build(secret)
                    .await
                    .map_err(transport)?,
            )
        } else {
            None
        };
        let gossip_authorization = GossipAuthorization::default();
        let observer = ConnectionObserver::default();
        #[cfg(feature = "tor")]
        let builder = if let Some(tor_transport) = tor_transport.as_ref() {
            Endpoint::builder(tor_transport.preset())
        } else if wan_lookup {
            Endpoint::builder(presets::N0)
        } else {
            Endpoint::builder(presets::Minimal)
                .clear_relay_transports()
                .clear_ip_transports()
        };
        #[cfg(not(feature = "tor"))]
        let builder = if wan_lookup {
            Endpoint::builder(presets::N0)
        } else {
            Endpoint::builder(presets::Minimal)
                .clear_relay_transports()
                .clear_ip_transports()
        };
        let memory = MemoryLookup::new();
        let mut builder = if relay_only {
            builder.clear_ip_transports()
        } else {
            builder.bind_addr(address).map_err(transport)?
        }
        .alpns(alpns.clone())
        .hooks(gossip_authorization.clone())
        .hooks(budget.clone())
        .hooks(observer.clone());
        if !profile.uses_tor() {
            builder = builder.address_lookup(memory.clone());
        }
        // Disable GSO on Android x86_64: multi-packet replies fail on the tested
        // emulator path.
        #[cfg(all(target_os = "android", target_arch = "x86_64"))]
        {
            builder = builder.transport_config(
                iroh::endpoint::QuicTransportConfig::builder()
                    .enable_segmentation_offload(false)
                    .build(),
            );
        }
        if let Some(secret) = secret {
            builder = builder.secret_key(secret);
        }
        if let Some(relay) = relay {
            builder = builder
                .relay_mode(iroh::RelayMode::Custom(relay.map))
                .ca_tls_config(relay.tls);
        }
        let endpoint = builder.bind().await.map_err(transport)?;
        let mdns = if let Some(service_name) = mdns_service {
            let lookup = MdnsAddressLookup::builder()
                .service_name(service_name)
                .build(endpoint.id())
                .map_err(transport)?;
            endpoint
                .address_lookup()
                .map_err(transport)?
                .add(lookup.clone());
            Some(lookup)
        } else {
            None
        };
        let nearby = Arc::new(Mutex::new(BTreeSet::new()));
        let nearby_listener = mdns.as_ref().map(|lookup| {
            let lookup = lookup.clone();
            let nearby = nearby.clone();
            let own = endpoint.id();
            tokio::spawn(async move {
                let mut events = lookup.subscribe().await;
                while let Some(event) = events.next().await {
                    match event {
                        DiscoveryEvent::Discovered { endpoint_info, .. } => {
                            let endpoint = endpoint_info.endpoint_id;
                            if endpoint != own {
                                let mut discovered = nearby.lock().await;
                                if discovered.len() < 16 {
                                    discovered.insert(*endpoint.as_bytes());
                                }
                            }
                        }
                        DiscoveryEvent::Expired { endpoint_id } => {
                            nearby.lock().await.remove(endpoint_id.as_bytes());
                        }
                        _ => {}
                    }
                }
            })
        });
        let bound_address = endpoint.bound_sockets().first().copied().unwrap_or(address);
        Ok(Self {
            endpoint,
            budget,
            bound_address,
            addresses: Arc::new(Mutex::new(BTreeMap::new())),
            memory,
            alpns: Arc::new(Mutex::new(alpns.into_iter().collect())),
            gossip_authorization,
            observer,
            outgoing: Arc::new(Mutex::new(BTreeMap::new())),
            nearby,
            nearby_listener: Arc::new(Mutex::new(nearby_listener)),
            unreachable: Arc::new(Mutex::new(BTreeMap::new())),
            address_lookup: mdns_service.is_some() || wan_lookup || profile.uses_tor(),
            use_ip_hints,
            tor: profile.uses_tor(),
            #[cfg(feature = "tor")]
            _tor_transport: tor_transport,
        })
    }

    pub(super) async fn accept(&self) -> Option<iroh::endpoint::Incoming> {
        self.endpoint.accept().await
    }

    pub(super) fn id(&self) -> PeerId {
        *self.endpoint.id().as_bytes()
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.bound_address
    }

    pub(super) fn operation_timeout(&self) -> std::time::Duration {
        if self.tor {
            TOR_OPERATION_TIMEOUT
        } else {
            super::TIMEOUT
        }
    }

    pub(super) fn endpoint(&self) -> Endpoint {
        self.endpoint.clone()
    }

    pub(super) async fn wait_online(&self) {
        self.endpoint.online().await;
    }

    pub(super) fn capacity_counts(&self) -> super::budget::CapacityCounts {
        self.budget.capacity_counts()
    }

    pub(super) fn mark_evictable(&self, id: usize) {
        self.budget.mark_evictable(id);
    }

    pub(super) fn exchange(&self, id: usize) -> super::budget::ExchangeGuard {
        self.budget.exchange(id)
    }

    pub(super) fn gossip_dial_capacity(&self) -> Arc<tokio::sync::Semaphore> {
        self.budget.gossip_dials()
    }

    pub(super) fn metrics(&self) -> super::TransportMetrics {
        let counters = &self.endpoint.metrics().socket;
        let mut observed = self.observer.0.write().unwrap();
        let mut paths = Vec::new();
        observed.live.retain(|weak| {
            let Some(connection) = weak.upgrade().filter(|c| c.close_reason().is_none()) else {
                return false;
            };
            for path in connection.paths().iter().filter(|path| path.is_selected()) {
                paths.push(super::PeerPath {
                    endpoint: *connection.remote_id().as_bytes(),
                    route: if path.is_ip() {
                        "direct"
                    } else if path.is_relay() {
                        "relay"
                    } else if self.tor {
                        "tor"
                    } else {
                        "custom"
                    },
                    rtt_ms: path.rtt().as_millis().min(u64::MAX as u128) as u64,
                });
            }
            true
        });
        super::TransportMetrics {
            received_bytes: counters
                .recv_data_ipv4
                .get()
                .saturating_add(counters.recv_data_ipv6.get())
                .saturating_add(counters.recv_data_relay.get())
                .saturating_add(counters.recv_data_custom.get()),
            sent_bytes: counters
                .send_ipv4
                .get()
                .saturating_add(counters.send_ipv6.get())
                .saturating_add(counters.send_relay.get()),
            receive_queue: 0,
            paths,
            paths_limited: observed.limited,
        }
    }

    pub(super) async fn add_alpn(&self, alpn: Vec<u8>) {
        let mut alpns = self.alpns.lock().await;
        if alpns.insert(alpn) {
            self.endpoint.set_alpns(alpns.iter().cloned().collect());
        }
    }

    pub(super) async fn authorize_gossip(&self, alpn: Vec<u8>, peers: Vec<PeerId>) {
        self.gossip_authorization
            .0
            .write()
            .unwrap()
            .insert(alpn.clone(), peers.into_iter().collect());
        self.add_alpn(alpn).await;
    }

    pub(super) async fn network_change(&self) {
        // Paths change with the network: earlier failures say nothing now.
        self.unreachable.lock().await.clear();
        self.endpoint.network_change().await;
    }

    pub(super) async fn add_address_hint(&self, peer: PeerId, address: SocketAddr) -> Result<()> {
        let key = PublicKey::from_bytes(&peer).map_err(transport)?;
        if self.tor {
            return Ok(());
        }
        let mut addresses = self.addresses.lock().await;
        if addresses.len() >= MAX_ADDRESS_HINTS && !addresses.contains_key(&peer) {
            return Err(Error::TooLarge);
        }
        addresses.insert(peer, address);
        self.unreachable.lock().await.remove(&peer);
        self.memory
            .add_endpoint_info(EndpointAddr::new(key).with_ip_addr(address));
        Ok(())
    }

    pub(super) async fn address_hint(&self, peer: PeerId) -> Option<SocketAddr> {
        self.addresses.lock().await.get(&peer).copied()
    }

    pub(super) fn can_dial_by_peer_id(&self) -> bool {
        self.address_lookup
    }

    pub(super) async fn remember_observed(&self, peer: PeerId, address: SocketAddr) {
        if self.tor {
            return;
        }
        let mut addresses = self.addresses.lock().await;
        // The peer just reached us, so it is reachable again.
        self.unreachable.lock().await.remove(&peer);
        if addresses.len() < MAX_ADDRESS_HINTS || addresses.contains_key(&peer) {
            addresses.insert(peer, address);
            if let Ok(key) = PublicKey::from_bytes(&peer) {
                self.memory
                    .add_endpoint_info(EndpointAddr::new(key).with_ip_addr(address));
            }
        }
    }

    pub(super) async fn connect(
        &self,
        peer: PeerId,
        alpn: &[u8],
    ) -> Result<Arc<iroh::endpoint::Connection>> {
        if self
            .unreachable
            .lock()
            .await
            .get(&peer)
            .is_some_and(|(retry, _)| Instant::now() < *retry)
        {
            return Err(Error::Transport(
                "peer recently unreachable; retrying later".into(),
            ));
        }
        let control = alpn == super::control::ALPN;
        let budget = if control {
            MAX_CONTROL_CONNECTIONS
        } else {
            MAX_CACHED_CONNECTIONS
        };
        let slot = {
            let mut outgoing = self.outgoing.lock().await;
            outgoing.retain(|_, cached| {
                cached
                    .connection
                    .get()
                    .is_none_or(|c| c.close_reason().is_none())
            });
            let key = (peer, alpn.to_vec());
            let same_plane = |key: &PeerProtocol| (key.1 == super::control::ALPN) == control;
            if !outgoing.contains_key(&key)
                && outgoing.keys().filter(|key| same_plane(key)).count() >= budget
            {
                // Only idle ownership may be evicted: never close a connection
                // another exchange or an in-progress dial is using.
                let idle = outgoing
                    .iter()
                    .filter(|(key, cached)| {
                        same_plane(key)
                            && Arc::strong_count(&cached.connection) == 1
                            && cached
                                .connection
                                .get()
                                .is_none_or(|c| Arc::strong_count(c) == 1)
                    })
                    .min_by_key(|(_, cached)| cached.last_used)
                    .map(|(key, _)| key.clone());
                let idle = idle.ok_or(Error::Backpressure)?;
                outgoing.remove(&idle);
            }
            let cached = outgoing.entry(key).or_insert_with(|| CachedConnection {
                connection: Arc::new(OnceCell::new()),
                last_used: Instant::now(),
            });
            cached.last_used = Instant::now();
            cached.connection.clone()
        };
        // Single-flight per endpoint + protocol, without holding the cache lock
        // across a dial. Cancellation/failure leaves the cell available to retry
        // on a later exchange; application requests themselves are never replayed.
        slot.get_or_try_init(|| async { self.dial(peer, alpn).await.map(Arc::new) })
            .await
            .cloned()
    }

    async fn dial(&self, peer: PeerId, alpn: &[u8]) -> Result<iroh::endpoint::Connection> {
        let key = PublicKey::from_bytes(&peer).map_err(transport)?;
        let hint = if self.use_ip_hints && !self.tor {
            self.address_hint(peer).await
        } else {
            None
        };
        let destination = match hint {
            Some(address) => EndpointAddr::new(key).with_ip_addr(address),
            None if self.address_lookup => EndpointAddr::new(key),
            None => return Err(Error::MissingPeer),
        };
        let _permit = self.budget.dial(alpn)?;
        // Bounded here, not only by callers, so a failed dial is recorded:
        // a caller's timeout drops this future and would hide the failure.
        let attempt = |destination: EndpointAddr, limit| async move {
            match tokio::time::timeout(limit, self.endpoint.connect(destination, alpn)).await {
                Ok(result) => result.map_err(transport),
                Err(_) => Err(Error::Timeout("connect")),
            }
        };
        // Iroh owns direct/relay/address-lookup path selection. Its current
        // Endpoint::connect contract tries configured address lookup when a
        // supplied direct address is unreachable, so racing a second connect
        // with a timer only creates duplicate dials and can strand a reply on
        // a path the peer has not settled yet.
        let outcome = if self.tor {
            // Tor hidden-service descriptors can take up to two minutes to
            // propagate. Retry failed SOCKS connects within a bounded window.
            let deadline = Instant::now() + TOR_DIAL_TIMEOUT;
            let mut delay = std::time::Duration::from_secs(3);
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break Err(Error::Timeout("Tor connect"));
                }
                match attempt(
                    destination.clone(),
                    remaining.min(std::time::Duration::from_secs(30)),
                )
                .await
                {
                    Ok(connection) => break Ok(connection),
                    Err(_) if Instant::now() < deadline => {
                        tokio::time::sleep(
                            delay.min(deadline.saturating_duration_since(Instant::now())),
                        )
                        .await;
                        delay = delay
                            .saturating_mul(2)
                            .min(std::time::Duration::from_secs(15));
                    }
                    Err(error) => break Err(error),
                }
            }
        } else {
            attempt(destination, super::TIMEOUT).await
        };
        let mut unreachable = self.unreachable.lock().await;
        match &outcome {
            Ok(_) => {
                unreachable.remove(&peer);
            }
            // Only silence marks a peer unreachable. A peer that answers, even
            // with a refusal such as a full connection budget, is reachable.
            Err(Error::Timeout(_)) => {
                let failures = unreachable
                    .get(&peer)
                    .map_or(0, |(_, failures)| *failures)
                    .saturating_add(1);
                unreachable.insert(
                    peer,
                    (Instant::now() + unreachable_backoff(failures), failures),
                );
            }
            Err(Error::Transport(_)) if self.tor => {
                let failures = unreachable
                    .get(&peer)
                    .map_or(0, |(_, failures)| *failures)
                    .saturating_add(1);
                unreachable.insert(
                    peer,
                    (Instant::now() + unreachable_backoff(failures), failures),
                );
            }
            Err(_) => {}
        }
        outcome
    }

    /// Close and forget the cached connection to `peer` for `alpn`. A request
    /// was sent on it and no reply came: on tablets such a connection stayed
    /// broken (iroh dropped the reply's packets on a path the other side did
    /// not know) and every retry on it waited out the full deadline again. The
    /// next dial gets a fresh connection.
    pub(super) async fn discard(&self, peer: PeerId, alpn: &[u8]) {
        let cached = self.outgoing.lock().await.remove(&(peer, alpn.to_vec()));
        if let Some(connection) = cached.and_then(|cached| cached.connection.get().cloned()) {
            connection.close(0u8.into(), b"stalled");
        }
    }

    pub(super) async fn nearby_peers(&self, _first_result: bool) -> Vec<PeerId> {
        self.nearby.lock().await.iter().copied().take(16).collect()
    }

    pub(super) async fn close(&self) {
        if let Some(listener) = self.nearby_listener.lock().await.take() {
            listener.abort();
            let _ = listener.await;
        }
        self.endpoint.close().await;
        self.outgoing.lock().await.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "tor")]
    #[test]
    fn tor_profile_uses_endpoint_id_resolution_without_ip_hints() {
        let (mdns, wan_lookup, relay_only, use_ip_hints) = NetworkProfile::Tor.settings();
        assert_eq!((mdns, wan_lookup, relay_only, use_ip_hints), (None, false, true, false));
        assert!(NetworkProfile::Tor.uses_tor());
    }

    #[tokio::test]
    async fn reuse_is_single_flight_protocol_scoped_and_never_evicts_busy_exchanges() {
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            // Private test ALPNs let one endpoint exercise the complete cache
            // budget without requiring a separate OS socket for every entry.
            let mut alpns: Vec<_> = (0..=MAX_CACHED_CONNECTIONS)
                .map(|i| format!("test-cache/{i}").into_bytes())
                .collect();
            alpns.push(super::super::control::ALPN.to_vec());
            let peer = Endpoint::builder(presets::Minimal)
                .clear_relay_transports()
                .clear_ip_transports()
                .bind_addr("127.0.0.1:0")
                .unwrap()
                .alpns(alpns.clone())
                .bind()
                .await
                .unwrap();
            let endpoint = peer.clone();
            let server = tokio::spawn(async move {
                let mut workers = tokio::task::JoinSet::new();
                while let Some(incoming) = endpoint.accept().await {
                    workers.spawn(async move {
                        incoming.await.unwrap().closed().await;
                    });
                }
                while let Some(result) = workers.join_next().await {
                    result.unwrap();
                }
            });
            let cache = Connections::bind(
                "127.0.0.1:0".parse().unwrap(),
                NetworkProfile::Direct,
                None,
                ConnectionBudget::default(),
                vec![],
                None,
            )
            .await
            .unwrap();
            let id = *peer.id().as_bytes();
            assert!(matches!(
                cache.connect(id, &alpns[0]).await,
                Err(Error::MissingPeer)
            ));
            cache
                .add_address_hint(id, peer.bound_sockets()[0])
                .await
                .unwrap();
            let mut busy =
                futures_util::future::join_all((0..8).map(|_| cache.connect(id, &alpns[0])))
                    .await
                    .into_iter()
                    .collect::<Result<Vec<_>>>()
                    .unwrap();
            let first = busy[0].stable_id();
            assert!(
                busy.iter()
                    .all(|connection| connection.stable_id() == first)
            );
            for alpn in &alpns[1..MAX_CACHED_CONNECTIONS] {
                let connection = cache.connect(id, alpn).await.unwrap();
                assert_eq!(connection.alpn(), alpn);
                assert_ne!(connection.stable_id(), first);
                busy.push(connection);
            }
            assert!(matches!(
                cache.connect(id, &alpns[MAX_CACHED_CONNECTIONS]).await,
                Err(Error::Backpressure)
            ));
            assert!(
                busy.iter()
                    .all(|connection| connection.close_reason().is_none())
            );
            // Busy data dials/leases cannot consume the control reserve.
            let control = cache
                .connect(id, super::super::control::ALPN)
                .await
                .unwrap();
            assert_eq!(control.alpn(), super::super::control::ALPN);
            drop(busy);
            // A completed exchange releases its lease. Capacity can now be
            // reclaimed without imposing a workspace member-count limit.
            let extra = cache
                .connect(id, &alpns[MAX_CACHED_CONNECTIONS])
                .await
                .unwrap();
            assert_eq!(extra.alpn(), alpns[MAX_CACHED_CONNECTIONS]);
            assert_eq!(
                cache.outgoing.lock().await.len(),
                MAX_CACHED_CONNECTIONS + 1
            );
            let fresh = cache.connect(id, &alpns[0]).await.unwrap();
            assert_ne!(fresh.stable_id(), first);
            cache.close().await;
            assert!(cache.outgoing.lock().await.is_empty());
            peer.close().await;
            server.await.unwrap();
        })
        .await
        .unwrap();
    }

    /// After a large admission wave most members may be offline. Each dial to
    /// one used to hold a control dial slot for the full timeout, so presence,
    /// catch-up and recovery rotations starved the few live peers: on tablets
    /// every send to the live owner failed with Backpressure (2026-09-18).
    #[tokio::test]
    async fn an_unreachable_peer_backs_off_without_holding_dial_capacity() {
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            let alpn = super::super::control::ALPN.to_vec();
            let cache = Connections::bind(
                "127.0.0.1:0".parse().unwrap(),
                NetworkProfile::Direct,
                None,
                ConnectionBudget::default(),
                vec![],
                None,
            )
            .await
            .unwrap();
            let dead = *iroh::SecretKey::generate().public().as_bytes();
            let nowhere = std::net::UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap();
            cache.add_address_hint(dead, nowhere).await.unwrap();
            assert!(cache.connect(dead, &alpn).await.is_err());
            // Within the backoff: refused at once, no dial slot taken.
            let refused = cache.connect(dead, &alpn).await.unwrap_err();
            assert!(
                refused.to_string().contains("recently unreachable"),
                "{refused}"
            );
            assert_eq!(cache.budget.control_dials_available(), 16);
            // New address information ends the backoff: the next call dials again.
            cache.add_address_hint(dead, nowhere).await.unwrap();
            let redialed = cache.connect(dead, &alpn).await.unwrap_err();
            assert!(
                !redialed.to_string().contains("recently unreachable"),
                "{redialed}"
            );
            cache.close().await;
        })
        .await
        .unwrap();
    }

    #[test]
    fn unreachable_backoff_doubles_from_five_seconds_to_a_two_minute_cap() {
        let seconds = |failures| unreachable_backoff(failures).as_secs();
        assert_eq!(
            [seconds(1), seconds(2), seconds(3), seconds(4), seconds(5)],
            [5, 10, 20, 40, 80]
        );
        assert_eq!(seconds(6), 120);
        assert_eq!(seconds(60), 120);
        assert_eq!(seconds(u32::MAX), 120);
    }

    /// A network change says nothing about earlier failures: the next call
    /// must dial again instead of refusing from the backoff.
    #[tokio::test]
    async fn a_network_change_ends_every_backoff() {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let alpn = super::super::control::ALPN.to_vec();
            let cache = Connections::bind(
                "127.0.0.1:0".parse().unwrap(),
                NetworkProfile::Direct,
                None,
                ConnectionBudget::default(),
                vec![],
                None,
            )
            .await
            .unwrap();
            let dead = *iroh::SecretKey::generate().public().as_bytes();
            let nowhere = std::net::UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap();
            cache.add_address_hint(dead, nowhere).await.unwrap();
            assert!(cache.connect(dead, &alpn).await.is_err());
            assert!(
                cache
                    .connect(dead, &alpn)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("recently unreachable")
            );
            cache.network_change().await;
            let redialed = cache.connect(dead, &alpn).await.unwrap_err();
            assert!(
                !redialed.to_string().contains("recently unreachable"),
                "{redialed}"
            );
            cache.close().await;
        })
        .await
        .unwrap();
    }

    /// After a request's reply never arrives the connection is discarded, so
    /// the retry cannot land on the same broken connection.
    #[tokio::test]
    async fn a_discarded_connection_is_replaced_on_the_next_dial() {
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            let alpn = super::super::control::ALPN.to_vec();
            let peer = Endpoint::builder(presets::Minimal)
                .clear_relay_transports()
                .bind_addr("127.0.0.1:0")
                .unwrap()
                .alpns(vec![alpn.clone()])
                .bind()
                .await
                .unwrap();
            let endpoint = peer.clone();
            let server = tokio::spawn(async move {
                while let Some(incoming) = endpoint.accept().await {
                    tokio::spawn(async move {
                        if let Ok(connection) = incoming.await {
                            connection.closed().await;
                        }
                    });
                }
            });
            let cache = Connections::bind(
                "127.0.0.1:0".parse().unwrap(),
                NetworkProfile::Direct,
                None,
                ConnectionBudget::default(),
                vec![],
                None,
            )
            .await
            .unwrap();
            let id = *peer.id().as_bytes();
            cache
                .add_address_hint(id, peer.bound_sockets()[0])
                .await
                .unwrap();
            let first = cache.connect(id, &alpn).await.unwrap();
            let again = cache.connect(id, &alpn).await.unwrap();
            assert_eq!(
                again.stable_id(),
                first.stable_id(),
                "a healthy connection is reused"
            );
            cache.discard(id, &alpn).await;
            assert!(
                first.close_reason().is_some(),
                "the discarded connection is closed"
            );
            let fresh = cache.connect(id, &alpn).await.unwrap();
            assert_ne!(
                fresh.stable_id(),
                first.stable_id(),
                "the next dial is a new connection"
            );
            cache.close().await;
            peer.close().await;
            server.abort();
        })
        .await
        .unwrap();
    }

    /// A peer that restarts or moves network comes back at a new address.
    /// The saved hint then points nowhere; address lookup (mDNS, public
    /// lookup) still knows the current address and must be used, or the
    /// peer stays unreachable until someone re-enters its address by hand
    /// (measured on tablets 2026-09-18: every member query failed with
    /// "connect" after the owner restarted on a new port).
    #[tokio::test]
    async fn a_stale_address_hint_falls_back_to_address_lookup() {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let alpn = super::super::control::ALPN.to_vec();
            let peer = Endpoint::builder(presets::Minimal)
                .clear_relay_transports()
                .bind_addr("127.0.0.1:0")
                .unwrap()
                .alpns(vec![alpn.clone()])
                .bind()
                .await
                .unwrap();
            let endpoint = peer.clone();
            let server = tokio::spawn(async move {
                while let Some(incoming) = endpoint.accept().await {
                    tokio::spawn(async move {
                        if let Ok(connection) = incoming.await {
                            connection.closed().await;
                        }
                    });
                }
            });
            // An address where the peer no longer listens.
            let stale = std::net::UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap();
            let mut cache = Connections::bind(
                "127.0.0.1:0".parse().unwrap(),
                NetworkProfile::Direct,
                None,
                ConnectionBudget::default(),
                vec![],
                None,
            )
            .await
            .unwrap();
            // Stand-in for a lookup service that knows the current address.
            cache.address_lookup = true;
            let id = *peer.id().as_bytes();
            cache.add_address_hint(id, stale).await.unwrap();
            cache.memory.add_endpoint_info(
                EndpointAddr::new(peer.id()).with_ip_addr(peer.bound_sockets()[0]),
            );
            let connection = cache.connect(id, &alpn).await.unwrap();
            assert_eq!(connection.alpn(), alpn.as_slice());
            cache.close().await;
            peer.close().await;
            server.abort();
        })
        .await
        .unwrap();
    }
}
