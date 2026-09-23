//! Workspace reachability over authenticated control, independent of application topics.
use super::*;
use std::time::Instant;

const PREFIX: &[u8; 5] = b"DFPR\x01";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const FRESH: Duration = Duration::from_secs(70);
const MAX_HEADS: usize = 8;

struct Seen {
    at: Instant,
    epoch: u64,
    fingerprint: [u8; 32],
    name_head: [u8; 32],
    instance: [u8; 16],
}

struct ObservedGroupHead {
    peer: [u8; 32],
    head: arachne_delivery::wire::GroupHead,
    at: Instant,
}

pub(super) struct Presence {
    seen: BTreeMap<[u8; 32], Seen>,
    pending: Vec<PendingControl<()>>,
    group_pending: Vec<PendingControl<()>>,
    queued: VecDeque<[u8; 32]>,
    group_queued: VecDeque<[u8; 32]>,
    group_unsupported: BTreeSet<[u8; 32]>,
    group_heads: Vec<ObservedGroupHead>,
    head_cursor: BTreeMap<[u8; 32], usize>,
    next: Option<Instant>,
    epoch: Option<u64>,
    instance: [u8; 16],
    announce: bool,
}

impl Presence {
    pub fn new() -> Result<Self, String> {
        let mut instance = [0; 16];
        getrandom::getrandom(&mut instance).map_err(|error| error.to_string())?;
        Ok(Self {
            seen: BTreeMap::new(),
            pending: Vec::new(),
            group_pending: Vec::new(),
            queued: VecDeque::new(),
            group_queued: VecDeque::new(),
            group_unsupported: BTreeSet::new(),
            group_heads: Vec::new(),
            head_cursor: BTreeMap::new(),
            next: None,
            epoch: None,
            instance,
            announce: false,
        })
    }

    pub fn cancel(&mut self) {
        self.pending.clear();
        self.group_pending.clear();
        self.queued.clear();
        self.group_queued.clear();
        self.group_heads.clear();
    }

    pub(super) fn announce_next(&mut self) {
        self.announce = true;
        self.next = None;
    }

    pub(super) fn group_tail_through(
        &self,
        author: [u8; 32],
        topics: &BTreeSet<Topic>,
        after: u64,
        now: Instant,
    ) -> Option<u64> {
        let selection = arachne_delivery::selection_digest(topics);
        self.group_heads
            .iter()
            .filter(|observed| {
                observed.head.author == author
                    && observed.head.selection == selection
                    && observed.head.after == after
                    && now.saturating_duration_since(observed.at) < FRESH
            })
            .map(|observed| observed.head.through)
            .max()
            .filter(|through| *through > after)
    }
}

fn queue_group_heads(presence: &mut Presence, peer: [u8; 32]) {
    if !presence.group_unsupported.contains(&peer)
        && !presence.group_queued.contains(&peer)
        && !presence
            .group_pending
            .iter()
            .any(|pending| pending.peer == peer)
    {
        presence.group_queued.push_back(peer);
    }
}

fn base_packet(
    owner: &arachne_security::Workspace,
    instance: [u8; 16],
    announce: bool,
) -> Result<Vec<u8>, String> {
    let mut bytes = PREFIX.to_vec();
    bytes.push(u8::from(announce));
    bytes.extend(instance);
    bytes.extend(owner.id());
    bytes.extend(owner.epoch().to_be_bytes());
    bytes.extend(owner.epoch_fingerprint());
    bytes.extend(owner.workspace_name_head().map_err(str::to_owned)?);
    Ok(bytes)
}

/// Harness-seam presence packet with zero delivery heads (see `crate::harness`).
/// A joiner with no publications legitimately advertises no heads; receivers
/// treat a zero head count as an ordinary presence refresh. Grants no authority.
#[doc(hidden)]
pub fn harness_presence_packet(
    owner: &arachne_security::Workspace,
    instance: [u8; 16],
    announce: bool,
) -> Vec<u8> {
    let mut bytes = base_packet(owner, instance, announce).expect("workspace name head");
    bytes.push(0);
    bytes
}

fn packet(session: &mut Session, peer: [u8; 32], announce: bool) -> Result<Vec<u8>, String> {
    let owner = session.workspace.as_ref().ok_or("no workspace")?;
    let recipient = owner.member_id_for_endpoint(peer).map_err(str::to_owned)?;
    let mut heads = match session.inbox.as_ref() {
        Some(inbox) => inbox
            .direct_heads_for(owner, recipient)
            .map_err(str::to_owned)?,
        None => Vec::new(),
    };
    let local = session.node.id();
    heads.retain(|head| {
        session
            .runtime
            .block_on(session.node.with_routing_policy(|policy| {
                policy
                    .subscribed(head.workspace, head.policy_revision, peer, &head.topic)
                    .unwrap_or(false)
                    && (head.author == owner.member().unwrap().id()
                        || head.recipients.contains(&owner.member().unwrap().id()))
                    && local != peer
            }))
    });
    let mut bytes = base_packet(owner, session.presence.instance, announce)?;
    let start = session
        .presence
        .head_cursor
        .get(&peer)
        .copied()
        .unwrap_or(0)
        .min(heads.len());
    let count = heads.len().min(MAX_HEADS);
    bytes.push(count as u8);
    for offset in 0..count {
        let encoded = heads[(start + offset) % heads.len()]
            .to_wire()
            .map_err(str::to_owned)?;
        bytes.extend((encoded.len() as u16).to_be_bytes());
        bytes.extend(encoded);
    }
    if heads.len() > MAX_HEADS {
        session
            .presence
            .head_cursor
            .insert(peer, (start + count) % heads.len());
    } else {
        session.presence.head_cursor.remove(&peer);
    }
    Ok(bytes)
}

fn observe(session: &mut Session, peer: [u8; 32], bytes: &[u8]) -> Result<bool, String> {
    let owner = session.workspace.as_ref().ok_or("no workspace")?;
    if bytes.len() < 127
        || !bytes.starts_with(PREFIX)
        || bytes[5] > 1
        || bytes[22..54] != owner.id()
        || peer == session.node.id()
        || owner.member_id_for_endpoint(peer).is_err()
    {
        return Err("invalid workspace presence".into());
    }
    let instance = bytes[6..22].try_into().unwrap();
    let announce = bytes[5] == 1;
    let mut heads = Vec::new();
    let count = bytes[126] as usize;
    if count > MAX_HEADS {
        return Err("invalid workspace presence".into());
    }
    let mut cursor = 127_usize;
    for _ in 0..count {
        let end = cursor.checked_add(2).ok_or("invalid workspace presence")?;
        let length = u16::from_be_bytes(
            bytes
                .get(cursor..end)
                .ok_or("invalid workspace presence")?
                .try_into()
                .unwrap(),
        ) as usize;
        cursor = end;
        let end = cursor
            .checked_add(length)
            .ok_or("invalid workspace presence")?;
        heads.push(
            arachne_delivery::wire::DirectHead::from_wire(
                bytes.get(cursor..end).ok_or("invalid workspace presence")?,
            )
            .map_err(str::to_owned)?,
        );
        cursor = end;
    }
    if cursor != bytes.len() {
        return Err("invalid workspace presence".into());
    }
    let next_inbox = session.inbox.clone().map(|mut next| {
        // Heads are advisory gap triggers. A peer can still have an older
        // subscription view, so a stale or revoked head must not poison the
        // authenticated presence/name response.
        for head in &heads {
            let subscribed = session
                .runtime
                .block_on(session.node.with_routing_policy(|policy| {
                    policy
                        .subscribed(
                            head.workspace,
                            head.policy_revision,
                            session.node.id(),
                            &head.topic,
                        )
                        .unwrap_or(false)
                }));
            if !subscribed {
                continue;
            }
            if let Ok(Some(candidate)) = next.stage_direct_head(owner, peer, head) {
                next = candidate;
            }
        }
        next
    });
    if let Some(next) = next_inbox {
        session.inbox = Some(next);
    }
    let restarted = announce
        || session
            .presence
            .seen
            .get(&peer)
            .is_some_and(|seen| seen.instance != instance);
    if restarted {
        session
            .presence
            .group_heads
            .retain(|observed| observed.peer != peer);
        session.presence.group_unsupported.remove(&peer);
        session
            .presence
            .group_queued
            .retain(|queued| *queued != peer);
        session
            .presence
            .group_pending
            .retain(|pending| pending.peer != peer);
    }
    session.presence.seen.insert(
        peer,
        Seen {
            at: Instant::now(),
            epoch: u64::from_be_bytes(bytes[54..62].try_into().unwrap()),
            fingerprint: bytes[62..94].try_into().unwrap(),
            name_head: bytes[94..126].try_into().unwrap(),
            instance,
        },
    );
    Ok(restarted)
}

fn observe_group_heads(session: &mut Session, peer: [u8; 32], bytes: &[u8]) -> Result<(), String> {
    let owner = session.workspace.as_ref().ok_or("no workspace")?;
    let query = arachne_delivery::wire::GroupHeadsQuery {
        workspace: owner.id(),
        epoch: owner.epoch(),
    };
    let heads = match arachne_delivery::wire::parse_group_heads_reply(&query, bytes) {
        Ok(heads) => heads,
        Err(_) if !bytes.starts_with(b"DFGP") => {
            session
                .presence
                .group_heads
                .retain(|observed| observed.peer != peer);
            session.presence.group_unsupported.insert(peer);
            return Ok(());
        }
        Err(error) => return Err(error.to_owned()),
    };
    owner.member_id_for_endpoint(peer).map_err(str::to_owned)?;
    session
        .presence
        .group_heads
        .retain(|observed| observed.peer != peer);
    let now = Instant::now();
    for head in heads {
        if owner.endpoints_for_members(&[head.author]).is_ok() {
            session.presence.group_heads.push(ObservedGroupHead {
                peer,
                head,
                at: now,
            });
        }
    }
    session.presence.group_unsupported.remove(&peer);
    Ok(())
}

pub(super) fn receive(
    session: &mut Session,
    peer: [u8; 32],
    bytes: &[u8],
) -> Result<Vec<u8>, String> {
    if observe(session, peer, bytes)? {
        session.interests.repair();
        // A committed/restarted peer announces before its first steady
        // presence. Use that event to exchange signed member profiles too;
        // epoch/name heads can stay identical after a join, so waiting for a
        // head difference leaves the joiner's display name unknown forever.
        let _ = super::membership::start_query_if_needed(session, peer);
    }
    if session.inbox.is_some() {
        queue_group_heads(&mut session.presence, peer);
    }
    // The authenticated presence response must not fail because an optional
    // native reconciliation query could not be started. The sender needs our
    // current head to initiate that query itself.
    let response = packet(session, peer, false)?;
    let _ = reconcile_seen(session);
    Ok(response)
}

pub(super) fn status(presence: &Presence, peer: [u8; 32], now: Instant) -> &'static str {
    match presence.seen.get(&peer) {
        None => "unknown",
        Some(seen) if now.saturating_duration_since(seen.at) < FRESH => "reachable",
        Some(_) => "stale",
    }
}

/// Local monotonic observation age; neither membership nor delivery evidence.
pub(super) fn contact_age(presence: &Presence, peer: [u8; 32], now: Instant) -> Option<Duration> {
    presence
        .seen
        .get(&peer)
        .map(|seen| now.saturating_duration_since(seen.at))
}

pub(super) fn fresh_for(age: Duration) -> Duration {
    FRESH.saturating_sub(age)
}

/// Presence is processed by the native control drain.  Use that authenticated
/// observation directly to start reconciliation; the host's display refresh
/// must not be the membership trigger.
fn reconcile_seen(session: &mut Session) -> Result<Option<[u8; 32]>, String> {
    let owner = session.workspace.as_ref().ok_or("no workspace")?;
    let epoch = owner.epoch();
    let fingerprint = owner.epoch_fingerprint();
    let name_head = owner.workspace_name_head().map_err(str::to_owned)?;
    let now = Instant::now();
    let ahead: Vec<(u64, [u8; 32])> = session
        .presence
        .seen
        .iter()
        .filter(|(_, seen)| now.saturating_duration_since(seen.at) < FRESH && seen.epoch > epoch)
        .map(|(peer, seen)| (seen.epoch, *peer))
        .collect();
    let before = session.membership_head.clone();
    for (head, peer) in ahead {
        super::membership::note_head(session, head, peer);
    }
    if session.membership_head != before {
        session.node.control_signal().notify_one();
    }
    let sync_peer = session
        .presence
        .seen
        .iter()
        .find(|(_, seen)| {
            now.saturating_duration_since(seen.at) < FRESH
                && ((seen.epoch > epoch && session.membership_head.is_none())
                    || (seen.epoch == epoch
                        && (seen.fingerprint != fingerprint || seen.name_head != name_head)))
        })
        .map(|(peer, _)| *peer);
    if let Some(peer) = sync_peer {
        super::membership::start_query_if_needed(session, peer)?;
    }
    Ok(sync_peer)
}

pub(super) fn poll(session: &mut Session, announce: bool) -> Result<Value, String> {
    let (workspace, epoch, peers) = {
        let owner = session.workspace.as_ref().ok_or("no workspace")?;
        let peers: BTreeSet<_> = owner
            .member_endpoints()
            .map_err(str::to_owned)?
            .into_iter()
            .filter(|peer| *peer != session.node.id())
            .collect();
        (owner.id(), owner.epoch(), peers)
    };
    session.presence.seen.retain(|peer, _| peers.contains(peer));
    session
        .presence
        .head_cursor
        .retain(|peer, _| peers.contains(peer));
    let now = Instant::now();
    session.presence.group_heads.retain(|observed| {
        peers.contains(&observed.peer) && now.saturating_duration_since(observed.at) < FRESH
    });
    session
        .presence
        .group_unsupported
        .retain(|peer| peers.contains(peer));
    session
        .presence
        .group_queued
        .retain(|peer| peers.contains(peer));
    session
        .presence
        .group_pending
        .retain(|pending| peers.contains(&pending.peer));
    let mut response_errors = 0_u32;
    let mut response_error = None;
    if announce || session.presence.epoch != Some(epoch) {
        // A newly accepted epoch or reconnect supersedes in-flight old observations.
        session.presence.pending.clear();
        session.presence.group_pending.clear();
        session.presence.queued.clear();
        session.presence.group_queued.clear();
        session.presence.group_heads.clear();
        session.presence.group_unsupported.clear();
        session.presence.head_cursor.clear();
        session.presence.next = None;
        session.presence.epoch = Some(epoch);
        session.presence.announce = true;
        session.interests.repair();
    }
    let mut i = 0;
    while i < session.presence.pending.len() {
        if !session.presence.pending[i].task.is_finished() {
            i += 1;
            continue;
        }
        let mut done = session.presence.pending.swap_remove(i);
        match session.runtime.block_on(&mut done.task) {
            Ok(Ok(bytes)) => match observe(session, done.peer, &bytes) {
                Ok(restarted) => {
                    if restarted {
                        session.interests.repair();
                    }
                    if session.inbox.is_some() {
                        queue_group_heads(&mut session.presence, done.peer);
                    }
                }
                Err(error) => {
                    response_errors = response_errors.saturating_add(1);
                    response_error.get_or_insert(error);
                }
            },
            Ok(Err(error)) => {
                response_errors = response_errors.saturating_add(1);
                response_error.get_or_insert(error.to_string());
            }
            Err(error) => {
                response_errors = response_errors.saturating_add(1);
                response_error.get_or_insert(error.to_string());
            }
        }
    }
    let mut i = 0;
    while i < session.presence.group_pending.len() {
        if !session.presence.group_pending[i].task.is_finished() {
            i += 1;
            continue;
        }
        let mut done = session.presence.group_pending.swap_remove(i);
        match session.runtime.block_on(&mut done.task) {
            Ok(Ok(bytes)) => {
                if let Err(error) = observe_group_heads(session, done.peer, &bytes) {
                    response_errors = response_errors.saturating_add(1);
                    response_error.get_or_insert(error);
                }
            }
            Ok(Err(error)) => {
                response_errors = response_errors.saturating_add(1);
                response_error.get_or_insert(error.to_string());
            }
            Err(error) => {
                response_errors = response_errors.saturating_add(1);
                response_error.get_or_insert(error.to_string());
            }
        }
    }
    if session.presence.pending.is_empty()
        && session.presence.queued.is_empty()
        && session.presence.next.is_none_or(|next| now >= next)
    {
        session.presence.queued.extend(peers);
        session.presence.next = Some(now + REFRESH_INTERVAL);
    }
    // ponytail: bounded direct-peer fanout; a measured gossip overlay replaces
    // all-peer refresh rounds before claiming large-workspace convergence.
    while session.presence.pending.len() < 16 {
        let Some(peer) = session.presence.queued.pop_front() else {
            break;
        };
        let bytes = packet(session, peer, session.presence.announce)?;
        let request = session.node.request_control(peer, &bytes);
        let task = session.runtime.spawn(async move {
            tokio::time::timeout(REQUEST_TIMEOUT, request)
                .await
                .map_err(|_| arachne_node::Error::Timeout("presence response"))?
        });
        session.presence.pending.push(PendingControl {
            query: (),
            peer,
            task,
        });
    }
    while session.presence.group_pending.len() < 16 && session.inbox.is_some() {
        let Some(peer) = session.presence.group_queued.pop_front() else {
            break;
        };
        let query = arachne_delivery::wire::GroupHeadsQuery { workspace, epoch }.to_wire();
        let control = session.node.control_client();
        let task = session.runtime.spawn(async move {
            tokio::time::timeout(
                REQUEST_TIMEOUT,
                super::request_control_retry_once(control, peer, &query),
            )
            .await
            .map_err(|_| arachne_node::Error::Timeout("group-head response"))?
        });
        session.presence.group_pending.push(PendingControl {
            query: (),
            peer,
            task,
        });
    }
    if session.presence.queued.is_empty() {
        session.presence.announce = false;
    }
    // A fresh peer at a newer epoch has the steps: pull the range from it
    // (ADR 0009). Same-epoch name/profile changes start an authenticated query
    // from this Rust-side observation, not from a host refresh timer.
    let sync_peer = reconcile_seen(session)?;
    Ok(json!({"state":"workspace_presence", "sync_peer":sync_peer,
        "response_errors":response_errors, "response_error":response_error}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn presence_expires_on_monotonic_deadline() {
        let mut presence = Presence::new().unwrap();
        let now = Instant::now();
        assert_eq!(status(&presence, [92; 32], now), "unknown");
        assert_eq!(contact_age(&presence, [92; 32], now), None);
        presence.seen.insert(
            [92; 32],
            Seen {
                at: now,
                epoch: 0,
                fingerprint: [0; 32],
                name_head: [0; 32],
                instance: [0; 16],
            },
        );
        assert_eq!(status(&presence, [92; 32], now), "reachable");
        assert_eq!(status(&presence, [92; 32], now + FRESH), "stale");
        assert_eq!(contact_age(&presence, [92; 32], now), Some(Duration::ZERO));
        let age = contact_age(&presence, [92; 32], now + FRESH + Duration::from_secs(5)).unwrap();
        assert_eq!(age, FRESH + Duration::from_secs(5));
        assert_eq!(fresh_for(age), Duration::ZERO);
        assert_eq!(
            fresh_for(Duration::from_secs(5)),
            FRESH - Duration::from_secs(5)
        );
    }

    #[test]
    fn announced_peer_starts_profile_reconcile() {
        let (owner, _, endpoints) = super::membership::admit_members(221, "Member", 1);
        let peer = endpoints[0];
        let packet = harness_presence_packet(&owner, [7; 16], true);
        let mut session = super::membership::bare_test_session(owner);

        receive(&mut session, peer, &packet).unwrap();

        assert!(session.membership_update.is_some());
    }
}
