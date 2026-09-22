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

pub(super) const ALPN_PREFIX: &[u8] = b"arachne/workspace-gossip/1/";
const JOIN_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_BOOTSTRAPS: usize = 3;
const BOOTSTRAP_RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(35),
    Duration::from_secs(70),
    Duration::from_secs(120),
];
/// The one overlay topic delivered across policy revisions (ADR 0008). Only
/// self-authenticating membership steps may use it.
pub(super) const MEMBERSHIP_TOPIC: &str = "arachne/membership/1";
const MAX_MEMBERSHIP_QUEUE: usize = 64;

/// One membership message received by gossip: its workspace and opaque bytes.
type MembershipMessage = (WorkspaceId, Vec<u8>);

/// Membership steps received by gossip, waiting for the host. Bounded; an
/// arrival wakes the host through the control signal.
#[derive(Clone)]
pub(super) struct MembershipInbox {
    queue: Arc<StdMutex<std::collections::VecDeque<MembershipMessage>>>,
    signal: Arc<Notify>,
}

impl MembershipInbox {
    pub(super) fn new(signal: Arc<Notify>) -> Self {
        Self {
            queue: Arc::default(),
            signal,
        }
    }

    fn offer(&self, workspace: WorkspaceId, payload: Vec<u8>) {
        let mut queue = self.queue.lock().unwrap();
        if queue.len() >= MAX_MEMBERSHIP_QUEUE {
            tracing::warn!(target: "data_fabric_transport", "GOSSIP_MEMBERSHIP_QUEUE_FULL");
            return;
        }
        queue.push_back((workspace, payload));
        drop(queue);
        self.signal.notify_one();
    }

    pub(super) fn pop(&self) -> Option<(WorkspaceId, Vec<u8>)> {
        self.queue.lock().unwrap().pop_front()
    }

    pub(super) fn pop_for(&self, workspace: WorkspaceId) -> Option<Vec<u8>> {
        let mut queue = self.queue.lock().unwrap();
        let index = queue.iter().position(|(scope, _)| *scope == workspace)?;
        queue.remove(index).map(|(_, payload)| payload)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    workspace: WorkspaceId,
    revision: u64,
    sender: PeerId,
    #[serde(deserialize_with = "wire::topic")]
    topic: String,
    delivery: DeliveryClass,
    #[serde(with = "wire::envelope_payload")]
    payload: Vec<u8>,
}

pub(super) struct Overlay {
    pub(super) workspace: WorkspaceId,
    /// Current policy revision. Advanced in place when a new revision only
    /// adds members, so the swarm and its neighbors survive an epoch change.
    revision: std::sync::atomic::AtomicU64,
    /// Endpoints authorized in the current revision.
    peers: StdMutex<BTreeSet<PeerId>>,
    pub(super) alpn: Vec<u8>,
    pub(super) gossip: Gossip,
    sender: GossipSender,
    neighbors: Arc<StdMutex<BTreeSet<PeerId>>>,
    changed: Arc<Notify>,
    receiver: JoinHandle<()>,
    bootstrap_retry: Option<JoinHandle<()>>,
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

    pub(super) async fn prepare(
        connections: &super::Connections,
        workspace: WorkspaceId,
        revision: u64,
        peers: Vec<PeerId>,
        routing: Arc<Mutex<RoutingTable>>,
        events: DeliveryQueue,
        membership: MembershipInbox,
    ) -> Result<Self> {
        let endpoint = connections.endpoint();
        let local = *endpoint.id().as_bytes();
        let local_index = peers.binary_search(&local).map_err(|_| Error::Rejected)?;
        let peers_set: BTreeSet<PeerId> = peers.iter().copied().collect();
        let digest = digest(workspace);
        let alpn = alpn(workspace);
        let config = HyparviewConfig::default();
        let gossip = Gossip::builder()
            .alpn(&alpn)
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
                        let envelope = match wire::decode::<Envelope>(&message.content) {
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
                            membership.offer(envelope.workspace, envelope.payload);
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
                    let delay = BOOTSTRAP_RETRY_DELAYS[failures.min(2) as usize];
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
            alpn,
            gossip,
            sender,
            neighbors,
            changed,
            receiver,
            bootstrap_retry,
        })
    }

    pub(super) async fn broadcast(
        &self,
        sender: PeerId,
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
            tokio::time::timeout(JOIN_TIMEOUT, changed)
                .await
                .map_err(|_| Error::MissingPeer)?;
            if self.neighbors.lock().unwrap().is_empty() {
                return Err(Error::MissingPeer);
            }
        }
        let bytes = wire::encode(&Envelope {
            workspace: self.workspace,
            revision: self.revision(),
            sender,
            topic: topic.as_str().into(),
            delivery,
            payload,
        })?;
        self.sender
            .broadcast(bytes.into())
            .await
            .map_err(super::transport)?;
        Ok(true)
    }

    pub(super) async fn broadcast_membership(
        &self,
        sender: PeerId,
        payload: Vec<u8>,
    ) -> Result<bool> {
        if payload.len() > wire::envelope_payload::MAX {
            return Err(Error::TooLarge);
        }
        let topic = Topic::new(MEMBERSHIP_TOPIC).map_err(|_| Error::Rejected)?;
        tracing::info!(target: "data_fabric_transport", bytes = payload.len(), neighbors = self.neighbor_count(), "GOSSIP_MEMBERSHIP_SENT");
        self.broadcast(sender, &topic, DeliveryClass::Critical, payload)
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
                node.enable_gossip(workspace, 1).await.unwrap();
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

pub(super) fn alpn(workspace: WorkspaceId) -> Vec<u8> {
    let mut value = ALPN_PREFIX.to_vec();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest(workspace) {
        value.push(HEX[(byte >> 4) as usize]);
        value.push(HEX[(byte & 0x0f) as usize]);
    }
    value
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
    inbox.offer([1; 32], vec![1]);
    notified.await;
    inbox.offer([2; 32], vec![2]);
    assert_eq!(inbox.pop_for([2; 32]), Some(vec![2]));
    assert_eq!(inbox.pop_for([1; 32]), Some(vec![1]));
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
    assert_ne!(alpn([1; 32]), alpn([2; 32]));
    assert!(alpn([1; 32]).starts_with(b"arachne/workspace-gossip/1/"));
}
