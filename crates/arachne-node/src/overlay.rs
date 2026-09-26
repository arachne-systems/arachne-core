use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use futures_util::StreamExt;
use iroh::EndpointId;
use iroh_gossip::{
    TopicId,
    api::{Event, GossipSender},
    net::Gossip,
    proto::HyparviewConfig,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    sync::{Mutex, Notify},
    task::JoinHandle,
};

use super::{
    DeliveryClass, DeliveryQueue, Error, PeerId, Result, RoutingTable, Topic, WorkspaceId, apply,
    wire,
};

/// One gossip protocol name for every workspace: the ALPN is visible in the
/// TLS ClientHello. The dialer names its overlay by a keyed tag, sent as the
/// first stream inside the encrypted connection.
pub(super) const ALPN: &[u8] = b"arachne/gossip/1";
/// Keyed workspace tag length; the whole first stream of a gossip link.
pub(super) const TAG: usize = 32;
const MAX_BOOTSTRAPS: usize = 3;
const BOOTSTRAP_RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(35),
    Duration::from_secs(70),
    Duration::from_secs(120),
];
/// The one overlay topic delivered across policy revisions, so a policy
/// change never rebuilds the gossip swarm (see docs/architecture.md#membership-gossip-vocabulary).
/// Only self-authenticating membership steps may use it.
pub(super) const MEMBERSHIP_TOPIC: &str = "arachne/membership/1";
/// Membership steps queued per (workspace, author). A flooding member fills
/// only its own queue; steps are taken round-robin across authors.
const MAX_MEMBERSHIP_PER_SENDER: usize = 8;
/// Authors with queued steps. Only verified overlay members can author one.
const MAX_MEMBERSHIP_SENDERS: usize = 64;
/// Steps queued across all authors (each up to a frame).
const MAX_MEMBERSHIP_QUEUE: usize = 64;

/// Queued membership steps of one workspace author: (revision, bytes).
type SenderQueue = std::collections::VecDeque<(u64, Vec<u8>)>;

#[derive(Default)]
struct MembershipQueues {
    by_sender: std::collections::BTreeMap<(WorkspaceId, PeerId), SenderQueue>,
    /// Steps queued across all authors.
    total: usize,
    /// Authors with queued steps, in the order they are served.
    turn: std::collections::VecDeque<(WorkspaceId, PeerId)>,
}

impl MembershipQueues {
    /// Take the next step of the first author in turn that matches.
    fn take(&mut self, matches: impl Fn(&WorkspaceId) -> bool) -> Option<(WorkspaceId, Vec<u8>)> {
        let index = self.turn.iter().position(|(workspace, _)| matches(workspace))?;
        let key = self.turn.remove(index)?;
        let queue = self.by_sender.get_mut(&key)?;
        let (_, payload) = queue.pop_front()?;
        self.total -= 1;
        if queue.is_empty() {
            self.by_sender.remove(&key);
        } else {
            self.turn.push_back(key);
        }
        Some((key.0, payload))
    }
}

/// Membership steps received by gossip, waiting for the host. Bounded per
/// author and in authors; an arrival wakes the host through the control signal.
#[derive(Clone)]
pub(super) struct MembershipInbox {
    queues: Arc<StdMutex<MembershipQueues>>,
    signal: Arc<Notify>,
}

impl MembershipInbox {
    pub(super) fn new(signal: Arc<Notify>) -> Self {
        Self {
            queues: Arc::default(),
            signal,
        }
    }

    /// Queue a step from a verified author. When the author's queue is full,
    /// a step of a newer policy revision replaces its oldest-revision step;
    /// otherwise the new step is dropped.
    fn offer(&self, workspace: WorkspaceId, sender: PeerId, revision: u64, payload: Vec<u8>) {
        let mut queues = self.queues.lock().unwrap();
        let key = (workspace, sender);
        let author_full = queues
            .by_sender
            .get(&key)
            .is_some_and(|queue| queue.len() >= MAX_MEMBERSHIP_PER_SENDER);
        // A full author queue replaces within itself; otherwise the step
        // needs room in the whole inbox.
        if !author_full && queues.total >= MAX_MEMBERSHIP_QUEUE {
            tracing::warn!(target: "data_fabric_transport", "GOSSIP_MEMBERSHIP_QUEUE_FULL");
            return;
        }
        if !queues.by_sender.contains_key(&key) {
            if queues.by_sender.len() >= MAX_MEMBERSHIP_SENDERS {
                tracing::warn!(target: "data_fabric_transport", "GOSSIP_MEMBERSHIP_QUEUE_FULL");
                return;
            }
            queues.turn.push_back(key);
        }
        let queue = queues.by_sender.entry(key).or_default();
        if author_full {
            let oldest = queue
                .iter()
                .enumerate()
                .min_by_key(|(_, (revision, _))| *revision)
                .map(|(index, (revision, _))| (index, *revision));
            match oldest {
                Some((index, oldest)) if oldest < revision => {
                    queue.remove(index);
                }
                _ => {
                    tracing::warn!(target: "data_fabric_transport", "GOSSIP_MEMBERSHIP_SENDER_QUEUE_FULL");
                    return;
                }
            }
        }
        queue.push_back((revision, payload));
        // A replacement keeps the count; a new step adds one.
        if !author_full {
            queues.total += 1;
        }
        drop(queues);
        self.signal.notify_one();
    }

    pub(super) fn has_pending(&self) -> bool {
        self.queues.lock().unwrap().total != 0
    }

    pub(super) fn pop(&self) -> Option<(WorkspaceId, Vec<u8>)> {
        self.queues.lock().unwrap().take(|_| true)
    }

    pub(super) fn pop_for(&self, workspace: WorkspaceId) -> Option<Vec<u8>> {
        self.queues
            .lock()
            .unwrap()
            .take(|scope| *scope == workspace)
            .map(|(_, payload)| payload)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    workspace: WorkspaceId,
    revision: u64,
    /// The author. Bound by the author's signature (`seal`/`open`), never by
    /// the gossip link, which may be a relaying member.
    sender: PeerId,
    #[serde(deserialize_with = "wire::topic")]
    topic: String,
    delivery: DeliveryClass,
    #[serde(with = "wire::envelope_payload")]
    payload: Vec<u8>,
}

/// Gossip relays an envelope through other members, so the link peer is not
/// its author. The author signs the encoded envelope with its endpoint key;
/// the signature follows the envelope bytes on the wire.
const SIGNATURE: usize = 64;
const SIGNATURE_DOMAIN: &[u8] = b"arachne/gossip-envelope/1\0";

fn seal(envelope: &Envelope, secret: &iroh::SecretKey) -> Result<Vec<u8>> {
    let mut bytes = wire::encode(envelope)?;
    let signature = secret.sign(&[SIGNATURE_DOMAIN, &bytes].concat());
    bytes.extend_from_slice(&signature.to_bytes());
    if bytes.len() > super::MAX_FRAME {
        return Err(Error::TooLarge);
    }
    Ok(bytes)
}

/// Decode an envelope whose author signature verifies against its sender.
fn open(bytes: &[u8]) -> Result<Envelope> {
    let split = bytes
        .len()
        .checked_sub(SIGNATURE)
        .ok_or(Error::InvalidFrame)?;
    let (body, signature) = bytes.split_at(split);
    let envelope: Envelope = wire::decode(body)?;
    let signature = iroh::Signature::from_bytes(signature.try_into().map_err(|_| Error::InvalidFrame)?);
    iroh::PublicKey::from_bytes(&envelope.sender)
        .map_err(|_| Error::InvalidFrame)?
        .verify(&[SIGNATURE_DOMAIN, body].concat(), &signature)
        .map_err(|_| Error::InvalidFrame)?;
    Ok(envelope)
}

pub(super) struct Overlay {
    pub(super) workspace: WorkspaceId,
    /// Current policy revision. Advanced in place when a new revision only
    /// adds members, so the swarm and its neighbors survive an epoch change.
    revision: std::sync::atomic::AtomicU64,
    /// Endpoints authorized in the current revision.
    peers: StdMutex<BTreeSet<PeerId>>,
    /// Keyed workspace tag a dialer sends first on each gossip link.
    pub(super) tag: [u8; TAG],
    pub(super) gossip: Gossip,
    sender: GossipSender,
    /// This endpoint's key: every envelope it authors is signed with it.
    secret: iroh::SecretKey,
    neighbors: Arc<StdMutex<BTreeSet<PeerId>>>,
    changed: Arc<Notify>,
    /// How long a broadcast waits for a first neighbor (profile deadline).
    join_timeout: Duration,
    receiver: JoinHandle<()>,
    bootstrap_retry: Option<JoinHandle<()>>,
    /// HyParView shuffle interval and first bootstrap retry delay in use.
    pub(super) intervals: (Duration, Duration),
}

impl Overlay {
    pub(super) fn revision(&self) -> u64 {
        self.revision.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Move to a new policy revision without rebuilding the swarm, when the
    /// new revision keeps every current member (admissions only add). False
    /// when a member was removed: the caller rebuilds so its links drop.
    pub(super) fn advance(&self, revision: u64, peers: &[PeerId]) -> bool {
        let next: BTreeSet<PeerId> = peers.iter().copied().collect();
        let mut current = self.peers.lock().unwrap();
        if !current.is_subset(&next) {
            return false;
        }
        *current = next;
        self.revision
            .store(revision, std::sync::atomic::Ordering::Release);
        true
    }

    pub(super) fn is_joined(&self) -> bool {
        !self.neighbors.lock().unwrap().is_empty()
    }

    pub(super) fn neighbor_count(&self) -> usize {
        self.neighbors.lock().unwrap().len()
    }

    pub(super) fn neighbors(&self) -> Vec<PeerId> {
        self.neighbors.lock().unwrap().iter().copied().collect()
    }

    pub(super) async fn wait_for_neighbor(&self) -> bool {
        loop {
            let changed = self.changed.notified();
            if self.is_joined() {
                return true;
            }
            changed.await;
        }
    }

    // Construction binds the authenticated scope to the existing shared owners.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn prepare(
        connections: &super::Connections,
        workspace: WorkspaceId,
        tag: [u8; TAG],
        revision: u64,
        peers: Vec<PeerId>,
        routing: Arc<Mutex<RoutingTable>>,
        events: DeliveryQueue,
        membership: MembershipInbox,
    ) -> Result<Self> {
        let endpoint = connections.endpoint();
        let secret = endpoint.secret_key().clone();
        let local = *endpoint.id().as_bytes();
        let local_index = peers.binary_search(&local).map_err(|_| Error::Rejected)?;
        let peers_set: BTreeSet<PeerId> = peers.iter().copied().collect();
        let digest = digest(workspace);
        let scale = connections.timer_scale();
        let config = HyparviewConfig {
            shuffle_interval: HyparviewConfig::default().shuffle_interval * scale,
            ..HyparviewConfig::default()
        };
        let retry_delays = BOOTSTRAP_RETRY_DELAYS.map(|delay| delay * scale);
        let intervals = (config.shuffle_interval, retry_delays[0]);
        let gossip = Gossip::builder()
            .alpn(ALPN)
            .connect_preamble(tag.to_vec())
            .dial_timeout(connections.timeouts().dial)
            .dial_capacity(connections.gossip_dial_capacity())
            .max_message_size(super::MAX_FRAME)
            .membership_config(config)
            .spawn(endpoint);
        // Peers we know how to reach come first. Roster order alone picked
        // offline members after a wave of joiners, and the overlay never met
        // the live ones (tablet BIG RED, 2026-09-18).
        let mut ordered: Vec<PeerId> = peers
            .iter()
            .cycle()
            .skip(local_index + 1)
            .take(peers.len() - 1)
            .copied()
            .collect();
        let mut reachable = Vec::new();
        for peer in &ordered {
            if connections.can_dial_by_peer_id() || connections.address_hint(*peer).await.is_some() {
                reachable.push(*peer);
            }
        }
        ordered.retain(|peer| !reachable.contains(peer));
        reachable.extend(ordered);
        let candidates = reachable
            .into_iter()
            .filter_map(|peer| match EndpointId::from_bytes(&peer) {
                Ok(peer) => Some(peer),
                Err(_) => {
                    tracing::warn!(target: "data_fabric_gossip", "GOSSIP_BOOTSTRAP_INVALID_ENDPOINT");
                    None
                }
            })
            .collect::<Vec<_>>();
        let bootstraps = candidates
            .iter()
            .take(MAX_BOOTSTRAPS)
            .copied()
            .collect::<Vec<_>>();
        tracing::info!(target: "data_fabric_transport", revision, members = peers.len(), bootstraps = ?bootstraps, "GOSSIP_OVERLAY_PREPARED");
        let topic = gossip
            .subscribe(TopicId::from_bytes(digest), bootstraps)
            .await
            .map_err(super::transport)?;
        let (sender, mut received) = topic.split();
        let neighbors = Arc::new(StdMutex::new(BTreeSet::new()));
        let changed = Arc::new(Notify::new());
        let observed = neighbors.clone();
        let notify = changed.clone();
        let receiver = tokio::spawn(async move {
            while let Some(event) = received.next().await {
                match event {
                    Ok(Event::NeighborUp(peer)) => {
                        tracing::info!(target: "data_fabric_transport", %peer, "GOSSIP_NEIGHBOR_UP");
                        observed.lock().unwrap().insert(*peer.as_bytes());
                        notify.notify_waiters();
                    }
                    Ok(Event::NeighborDown(peer)) => {
                        tracing::info!(target: "data_fabric_transport", %peer, "GOSSIP_NEIGHBOR_DOWN");
                        observed.lock().unwrap().remove(peer.as_bytes());
                        notify.notify_waiters();
                    }
                    Ok(Event::Received(message)) => {
                        let envelope = match open(&message.content) {
                            Ok(value) if value.workspace == workspace => value,
                            _ => {
                                tracing::warn!(target: "data_fabric_gossip", "GOSSIP_ENVELOPE_REJECTED");
                                continue;
                            }
                        };
                        // Crosses revisions on purpose: a member behind by an
                        // epoch must still hear the step that moves it on.
                        if envelope.topic == MEMBERSHIP_TOPIC {
                            tracing::info!(target: "data_fabric_transport", bytes = envelope.payload.len(), from = %message.delivered_from.fmt_short(), "GOSSIP_MEMBERSHIP_RECEIVED");
                            membership.offer(envelope.workspace, envelope.sender, envelope.revision, envelope.payload);
                            continue;
                        }
                        // Only membership messages may use the frame-sized bound.
                        if envelope.payload.len() > super::MAX_PAYLOAD {
                            tracing::warn!(target: "data_fabric_gossip", "GOSSIP_ENVELOPE_REJECTED");
                            continue;
                        }
                        let frame = super::Frame {
                            workspace: envelope.workspace,
                            revision: envelope.revision,
                            topic: envelope.topic,
                            delivery: envelope.delivery,
                            operation: super::Operation::Publish(envelope.payload),
                        };
                        if let Err(error) = apply(
                            &routing,
                            &events,
                            local,
                            envelope.sender,
                            *message.delivered_from.as_bytes(),
                            frame,
                        )
                        .await
                        {
                            tracing::warn!(target: "data_fabric_gossip", ?error, "GOSSIP_PUBLICATION_REJECTED");
                        }
                    }
                    Ok(Event::Lagged) => {
                        tracing::warn!(target: "data_fabric_transport", "GOSSIP_RECEIVER_LAGGED");
                    }
                    Err(error) => {
                        tracing::warn!(target: "data_fabric_gossip", %error, "GOSSIP_RECEIVER_FAILED");
                        break;
                    }
                }
            }
        });
        // Gossip discards a bootstrap after its first failed dial. Tor has no
        // address-hint update to trigger a rejoin, so an early hidden-service
        // timeout otherwise leaves this overlay isolated forever.
        let bootstrap_retry = (!candidates.is_empty()).then(|| {
            let sender = sender.clone();
            let retry_neighbors = neighbors.clone();
            let retry_changed = changed.clone();
            tokio::spawn(async move {
                let mut failures = 0u32;
                loop {
                    let delay = retry_delays[failures.min(2) as usize];
                    tokio::select! {
                        _ = tokio::time::sleep(delay) => {
                            if !retry_neighbors.lock().unwrap().is_empty() {
                                failures = 0;
                                continue;
                            }
                        }
                        _ = retry_changed.notified() => {
                            failures = 0;
                            continue;
                        }
                    }
                    let start = failures as usize * MAX_BOOTSTRAPS % candidates.len();
                    let batch = candidates
                        .iter()
                        .cycle()
                        .skip(start)
                        .take(candidates.len().min(MAX_BOOTSTRAPS))
                        .copied()
                        .collect();
                    failures = failures.saturating_add(1);
                    tracing::info!(target: "data_fabric_transport", attempt = failures, peers = candidates.len(), "GOSSIP_BOOTSTRAP_RETRY");
                    if let Err(error) = sender.join_peers(batch).await {
                        tracing::warn!(target: "data_fabric_transport", attempt = failures, %error, "GOSSIP_BOOTSTRAP_RETRY_FAILED");
                    }
                }
            })
        });
        Ok(Self {
            workspace,
            revision: std::sync::atomic::AtomicU64::new(revision),
            peers: StdMutex::new(peers_set),
            tag,
            gossip,
            sender,
            secret,
            neighbors,
            changed,
            join_timeout: connections.timeouts().gossip_join,
            receiver,
            bootstrap_retry,
            intervals,
        })
    }

    /// Broadcast an envelope authored and signed by this endpoint.
    pub(super) async fn broadcast(
        &self,
        topic: &Topic,
        delivery: DeliveryClass,
        payload: Vec<u8>,
    ) -> Result<bool> {
        // The current authorized set, not the count at creation: an overlay
        // created with only this member is advanced in place as members join
        // (tablet HEWN skipped every broadcast while its creation count said 0).
        if self.peers.lock().unwrap().len() <= 1 {
            return Ok(false);
        }
        let changed = self.changed.notified();
        if self.neighbors.lock().unwrap().is_empty() {
            tokio::time::timeout(self.join_timeout, changed)
                .await
                .map_err(|_| Error::MissingPeer)?;
            if self.neighbors.lock().unwrap().is_empty() {
                return Err(Error::MissingPeer);
            }
        }
        let bytes = seal(
            &Envelope {
                workspace: self.workspace,
                revision: self.revision(),
                sender: *self.secret.public().as_bytes(),
                topic: topic.as_str().into(),
                delivery,
                payload,
            },
            &self.secret,
        )?;
        self.sender
            .broadcast(bytes.into())
            .await
            .map_err(super::transport)?;
        Ok(true)
    }

    pub(super) async fn broadcast_membership(
        &self,
        payload: Vec<u8>,
    ) -> Result<bool> {
        if payload.len() > wire::envelope_payload::MAX {
            return Err(Error::TooLarge);
        }
        let topic = Topic::new(MEMBERSHIP_TOPIC).map_err(|_| Error::Rejected)?;
        tracing::info!(target: "data_fabric_transport", bytes = payload.len(), neighbors = self.neighbor_count(), "GOSSIP_MEMBERSHIP_SENT");
        self.broadcast(&topic, DeliveryClass::Critical, payload)
            .await
    }

    pub(super) async fn join_peer(&self, peer: PeerId) -> Result<()> {
        let peer = EndpointId::from_bytes(&peer).map_err(super::transport)?;
        self.sender
            .join_peers(vec![peer])
            .await
            .map_err(super::transport)
    }
}

impl Drop for Overlay {
    fn drop(&mut self) {
        self.receiver.abort();
        if let Some(retry) = &self.bootstrap_retry {
            retry.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NetworkProfile, Node, Permissions};
    use std::{collections::BTreeMap, net::SocketAddr};

    #[tokio::test]
    async fn isolated_gossip_overlay_retries_after_a_route_appears() {
        tokio::time::timeout(Duration::from_secs(50), async {
            let bind = || "127.0.0.1:0".parse::<SocketAddr>().unwrap();
            let (a, _) = Node::bind_with_profile(
                bind(),
                Some(&[81; 32]),
                NetworkProfile::Direct,
                Default::default(),
            )
            .await
            .unwrap();
            let (b, _) = Node::bind_with_profile(
                bind(),
                Some(&[82; 32]),
                NetworkProfile::Direct,
                Default::default(),
            )
            .await
            .unwrap();
            let workspace = [83; 32];
            let policy = BTreeMap::from([
                (a.id(), Permissions::AllTopics),
                (b.id(), Permissions::AllTopics),
            ]);
            for node in [&a, &b] {
                node.install_verified_policy(workspace, 1, policy.clone())
                    .await
                    .unwrap();
                node.enable_gossip(workspace, 1, &workspace).await.unwrap();
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
            assert!(a.live_neighbors(workspace).await.is_empty());
            assert!(b.live_neighbors(workspace).await.is_empty());

            // Update discovery without triggering Node's immediate join path;
            // the retry task must recover the failed initial bootstrap itself.
            a.connections
                .add_address_hint(b.id(), b.address())
                .await
                .unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(42);
            loop {
                if a.live_neighbors(workspace).await.contains(&b.id())
                    && b.live_neighbors(workspace).await.contains(&a.id())
                {
                    break;
                }
                assert!(tokio::time::Instant::now() < deadline);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            a.close().await;
            b.close().await;
        })
        .await
        .expect("isolated overlay did not recover after its bootstrap route appeared");
    }

    /// A client's ALPN is sent in clear in the TLS ClientHello. It must not
    /// name the workspace; the overlay is found inside the encrypted channel.
    #[tokio::test]
    async fn gossip_links_use_one_fixed_alpn_for_every_workspace() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let bind = || "127.0.0.1:0".parse::<SocketAddr>().unwrap();
            let (a, _) = Node::bind_with_identity(bind(), &[84; 32]).await.unwrap();
            let (b, _) = Node::bind_with_identity(bind(), &[85; 32]).await.unwrap();
            a.add_address_hint(b.id(), b.address()).await.unwrap();
            b.add_address_hint(a.id(), a.address()).await.unwrap();
            let policy = BTreeMap::from([
                (a.id(), Permissions::AllTopics),
                (b.id(), Permissions::AllTopics),
            ]);
            let workspaces = [[86; 32], [87; 32]];
            for workspace in workspaces {
                for node in [&a, &b] {
                    node.install_verified_policy(workspace, 1, policy.clone())
                        .await
                        .unwrap();
                    node.enable_gossip(workspace, 1, &workspace).await.unwrap();
                }
            }
            for workspace in workspaces {
                while !a.live_neighbors(workspace).await.contains(&b.id()) {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
            let fixed: [&[u8]; 3] = [b"arachne/data/1", b"arachne/control/1", b"arachne/gossip/1"];
            let alpns = a.connections.live_alpns();
            assert!(!alpns.is_empty());
            for alpn in alpns {
                assert!(
                    fixed.contains(&alpn.as_slice()),
                    "{}",
                    String::from_utf8_lossy(&alpn)
                );
            }
            a.close().await;
            b.close().await;
        })
        .await
        .unwrap();
    }

    /// A member of one overlay cannot learn whether this endpoint is in another
    /// workspace: a tag it may not use closes exactly like an unknown tag.
    #[tokio::test]
    async fn a_foreign_tag_closes_like_an_unknown_tag() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let bind = || "127.0.0.1:0".parse::<SocketAddr>().unwrap();
            let (a, _) = Node::bind_with_identity(bind(), &[88; 32]).await.unwrap();
            let prober = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .clear_relay_transports()
                .clear_ip_transports()
                .bind_addr("127.0.0.1:0")
                .unwrap()
                .secret_key(iroh::SecretKey::from_bytes(&[89; 32]))
                .bind()
                .await
                .unwrap();
            let prober_id = *prober.id().as_bytes();
            let (mine, other) = ([90; 32], [91; 32]);
            let outsider = *iroh::SecretKey::from_bytes(&[92; 32]).public().as_bytes();
            for (workspace, member) in [(mine, prober_id), (other, outsider)] {
                a.install_verified_policy(
                    workspace,
                    1,
                    BTreeMap::from([
                        (a.id(), Permissions::AllTopics),
                        (member, Permissions::AllTopics),
                    ]),
                )
                .await
                .unwrap();
                a.enable_gossip(workspace, 1, &workspace).await.unwrap();
            }
            let address = iroh::EndpointAddr::new(iroh::PublicKey::from_bytes(&a.id()).unwrap())
                .with_ip_addr(a.address());
            let send_tag = |tag: [u8; TAG]| {
                let prober = prober.clone();
                let address = address.clone();
                async move {
                    let connection = prober.connect(address, ALPN).await.unwrap();
                    let mut stream = connection.open_uni().await.unwrap();
                    stream.write_all(&tag).await.unwrap();
                    stream.finish().unwrap();
                    connection
                }
            };
            let mut reasons = Vec::new();
            for probe in [tag(&other, other), [7; TAG]] {
                let connection = send_tag(probe).await;
                reasons.push(format!("{:?}", connection.closed().await));
            }
            assert!(reasons[0].contains("gossip denied"), "{}", reasons[0]);
            assert_eq!(reasons[0], reasons[1]);
            // Its own overlay's tag is admitted.
            let admitted = send_tag(tag(&mine, mine)).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert!(admitted.close_reason().is_none());
            a.close().await;
            prober.close().await;
        })
        .await
        .unwrap();
    }

    /// Gossip relays, so the author is not the link peer. A member could
    /// claim another member as sender; the envelope must prove its author.
    #[tokio::test]
    async fn a_member_cannot_publish_as_another_member_over_gossip() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let bind = || "127.0.0.1:0".parse::<SocketAddr>().unwrap();
            let (a, _) = Node::bind_with_identity(bind(), &[93; 32]).await.unwrap();
            let (b, _) = Node::bind_with_identity(bind(), &[94; 32]).await.unwrap();
            let (c, mut received) = Node::bind_with_identity(bind(), &[95; 32]).await.unwrap();
            let workspace = [96; 32];
            let topic = Topic::new("streams/opaque").unwrap();
            let policy = BTreeMap::from([
                (a.id(), Permissions::AllTopics),
                (b.id(), Permissions::AllTopics),
                (c.id(), Permissions::AllTopics),
            ]);
            for node in [&a, &b, &c] {
                node.install_verified_policy(workspace, 1, policy.clone())
                    .await
                    .unwrap();
            }
            c.subscribe(workspace, 1, topic.clone()).await.unwrap();
            a.add_address_hint(c.id(), c.address()).await.unwrap();
            c.add_address_hint(a.id(), a.address()).await.unwrap();
            for node in [&a, &c] {
                node.enable_gossip(workspace, 1, &workspace).await.unwrap();
            }
            while !a.live_neighbors(workspace).await.contains(&c.id()) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let overlay = a.overlays.lock().await.get(&workspace).cloned().unwrap();
            let forged = wire::encode(&Envelope {
                workspace,
                revision: 1,
                sender: b.id(),
                topic: topic.as_str().into(),
                delivery: DeliveryClass::Critical,
                payload: b"forged".to_vec(),
            })
            .unwrap();
            overlay.sender.broadcast(forged.into()).await.unwrap();
            a.publish(workspace, 1, topic.clone(), b"genuine".to_vec())
                .await
                .unwrap();
            let first = tokio::time::timeout(Duration::from_secs(5), received.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                (first.sender, first.payload.as_slice()),
                (a.id(), &b"genuine"[..]),
                "a forged sender was accepted"
            );
            for node in [a, b, c] {
                node.close().await;
            }
        })
        .await
        .unwrap();
    }

    /// A policy that removes a member rebuilds the overlay; the old swarm's
    /// links must close with it, and the removed member cannot link again.
    #[tokio::test]
    async fn removing_a_member_closes_its_gossip_link() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let bind = || "127.0.0.1:0".parse::<SocketAddr>().unwrap();
            let (a, _) = Node::bind_with_identity(bind(), &[101; 32]).await.unwrap();
            let (b, _) = Node::bind_with_identity(bind(), &[102; 32]).await.unwrap();
            let (c, _) = Node::bind_with_identity(bind(), &[103; 32]).await.unwrap();
            let workspace = [104; 32];
            let policy = BTreeMap::from([
                (a.id(), Permissions::AllTopics),
                (b.id(), Permissions::AllTopics),
                (c.id(), Permissions::AllTopics),
            ]);
            for node in [&a, &b, &c] {
                node.install_verified_policy(workspace, 1, policy.clone())
                    .await
                    .unwrap();
            }
            for node in [&b, &c] {
                node.add_address_hint(a.id(), a.address()).await.unwrap();
                a.add_address_hint(node.id(), node.address()).await.unwrap();
            }
            for node in [&a, &b, &c] {
                node.enable_gossip(workspace, 1, &workspace).await.unwrap();
            }
            let gossip_link = |node: &Node, peer: PeerId| {
                node.connections
                    .live_links()
                    .contains(&(peer, ALPN.to_vec()))
            };
            while !(a.live_neighbors(workspace).await.contains(&c.id()) && gossip_link(&a, c.id()))
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let current = BTreeMap::from([
                (a.id(), Permissions::AllTopics),
                (b.id(), Permissions::AllTopics),
            ]);
            a.install_verified_policy(workspace, 2, current).await.unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while gossip_link(&a, c.id()) {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the removed member's gossip link stayed open"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(!a.live_neighbors(workspace).await.contains(&c.id()));
            // The removed member still holds the old policy and dials again.
            c.add_address_hint(a.id(), a.address()).await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
            assert!(!gossip_link(&a, c.id()), "the removed member linked again");
            assert!(!a.live_neighbors(workspace).await.contains(&c.id()));
            for node in [a, b, c] {
                node.close().await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn discovery_and_protocol_names_say_arachne() {
        assert_eq!(crate::ALPN, b"arachne/data/1");
        assert_eq!(crate::control::ALPN, b"arachne/control/1");
        assert_eq!(NetworkProfile::Lan.settings().0, Some("arachne"));
        assert_eq!(NetworkProfile::Wan.settings().0, Some("arachne"));
        assert_eq!(NetworkProfile::Direct.settings().0, None);
    }

    #[test]
    fn bootstrap_retry_backoff_is_bounded() {
        assert_eq!(
            BOOTSTRAP_RETRY_DELAYS,
            [
                Duration::from_secs(35),
                Duration::from_secs(70),
                Duration::from_secs(120),
            ]
        );
    }
}

/// The tag that names a workspace overlay on a gossip link. `key` is a
/// secret shared by the workspace members and stable across policy
/// revisions, so a party without it cannot link a tag to a workspace.
pub(super) fn tag(key: &[u8; 32], workspace: WorkspaceId) -> [u8; TAG] {
    let mut hash = Sha256::new();
    hash.update(b"arachne/gossip-tag/1\0");
    hash.update(key);
    hash.update(workspace);
    hash.finalize().into()
}

fn digest(workspace: WorkspaceId) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"arachne/workspace-gossip/1\0");
    hash.update(workspace);
    hash.finalize().into()
}

#[tokio::test]
async fn membership_inbox_wakes_and_scopes_queued_payloads() {
    let signal = Arc::new(Notify::new());
    let inbox = MembershipInbox::new(signal.clone());
    let notified = signal.notified();
    inbox.offer([1; 32], [7; 32], 1, vec![1]);
    notified.await;
    inbox.offer([2; 32], [7; 32], 1, vec![2]);
    assert_eq!(inbox.pop_for([2; 32]), Some(vec![2]));
    assert_eq!(inbox.pop_for([1; 32]), Some(vec![1]));
}

/// One member flooding membership gossip must not crowd another member's
/// step out of the inbox: the next step may be the one that removes it.
#[test]
fn a_flooding_member_cannot_crowd_out_another_members_step() {
    let inbox = MembershipInbox::new(Arc::new(Notify::new()));
    for step in 0..128_u64 {
        inbox.offer([1; 32], [2; 32], 1, step.to_be_bytes().to_vec());
    }
    inbox.offer([1; 32], [3; 32], 1, b"from-b".to_vec());
    // A full author queue takes a newer revision's step over its oldest.
    inbox.offer([1; 32], [2; 32], 2, b"next-revision".to_vec());
    let drained: Vec<_> = std::iter::from_fn(|| inbox.pop()).collect();
    assert!(
        drained.iter().any(|(_, payload)| payload == b"from-b"),
        "the other member's step was dropped after {} queued",
        drained.len()
    );
    // Authors are served in turn, and one author holds a bounded share.
    assert_eq!(drained[1].1, b"from-b");
    assert_eq!(drained.len(), MAX_MEMBERSHIP_PER_SENDER + 1);
    assert!(drained.iter().any(|(_, payload)| payload == b"next-revision"));
}

/// Many authors together still hold a bounded inbox: at most 64 steps of
/// frame size, as before the per-author queues.
#[test]
fn many_authors_together_stay_within_the_inbox_bound() {
    let inbox = MembershipInbox::new(Arc::new(Notify::new()));
    for author in 0..32_u8 {
        for step in 0..MAX_MEMBERSHIP_PER_SENDER as u8 {
            inbox.offer([1; 32], [author; 32], 1, vec![step]);
        }
    }
    assert_eq!(std::iter::from_fn(|| inbox.pop()).count(), 64);
}

#[test]
fn compact_gossip_preserves_author_and_payload_and_rejects_bad_frames() {
    for size in [1024, super::MAX_PAYLOAD] {
        let payload: Vec<_> = (0_u32..)
            .flat_map(|i| Sha256::digest(i.to_be_bytes()))
            .take(size)
            .collect();
        for delivery in [
            DeliveryClass::Critical,
            DeliveryClass::Current {
                replacement_key: [187; 32],
            },
            DeliveryClass::Bulk,
        ] {
            let mut envelope = Envelope {
                workspace: [171; 32],
                revision: u64::MAX,
                sender: [199; 32],
                topic: "streams/opaque".into(),
                delivery,
                payload: payload.clone(),
            };
            let json = serde_json::to_vec(&envelope).unwrap();
            let bytes = wire::encode(&envelope).unwrap();
            let decoded: Envelope = wire::decode(&bytes).unwrap();
            assert_eq!(serde_json::to_vec(&decoded).unwrap(), json);
            assert!(bytes.len() * 2 < json.len());
            if delivery == DeliveryClass::Critical {
                println!(
                    "gossip payload={size} json={} binary={}",
                    json.len(),
                    bytes.len()
                );
            }
            for end in [0, 1, 32, bytes.len() - 1] {
                assert!(wire::decode::<Envelope>(&bytes[..end]).is_err());
            }
            let mut trailing = bytes;
            trailing.push(0);
            assert!(wire::decode::<Envelope>(&trailing).is_err());
            // Decoding allows a frame-sized payload (membership steps); the
            // receive loop holds every data topic to MAX_PAYLOAD.
            envelope.payload = vec![0; wire::envelope_payload::MAX + 1];
            assert!(wire::decode::<Envelope>(&wire::encode(&envelope).unwrap()).is_err());
        }
    }
    // Only the sender's own key opens an envelope; any changed byte fails.
    let author = iroh::SecretKey::from_bytes(&[5; 32]);
    let other = iroh::SecretKey::from_bytes(&[6; 32]);
    let envelope = |sender: &iroh::SecretKey| Envelope {
        workspace: [171; 32],
        revision: 1,
        sender: *sender.public().as_bytes(),
        topic: "streams/opaque".into(),
        delivery: DeliveryClass::Critical,
        payload: vec![1, 2, 3],
    };
    let sealed = seal(&envelope(&author), &author).unwrap();
    assert_eq!(open(&sealed).unwrap().payload, vec![1, 2, 3]);
    for index in [0, 40, sealed.len() - 1] {
        let mut changed = sealed.clone();
        changed[index] ^= 1;
        assert!(open(&changed).is_err());
    }
    assert!(open(&seal(&envelope(&other), &author).unwrap()).is_err());
    assert!(open(&wire::encode(&envelope(&author)).unwrap()).is_err());
    assert_ne!(tag(&[0; 32], [1; 32]), tag(&[0; 32], [2; 32]));
    assert_ne!(tag(&[0; 32], [1; 32]), tag(&[1; 32], [1; 32]));
}
