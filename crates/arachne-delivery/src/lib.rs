//! Bounded publisher retention index. No transport, disk writes or payload parsing.
//! Its snapshot must commit atomically with the matching sender security snapshot.
pub mod catalog;
pub mod current;
pub mod inbox;
mod publisher;
pub mod wire;
pub use publisher::{PUBLISHER_BUDGET, PublisherLog};

use arachne_routing::{PublicationContext, Topic};
use arachne_security::{MAX_APPLICATION_CIPHERTEXT, MAX_RECOVERY_PACKETS, RecoveryRequest};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAGIC: &[u8] = b"DFRL\x03";
pub const MAX_TOPICS: usize = 64;
pub const MAX_PACKETS_PER_TOPIC: usize = 32;
pub const MAX_RETAINED_BYTES: usize = 512 * 1024;
pub const MAX_SNAPSHOT_BYTES: usize = MAX_RETAINED_BYTES + 16 * 1024;

/// Time as whole seconds since the Unix epoch (UTC). Every delivery expiry
/// (`expires_at`, `retain_until`) is in this unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixSeconds(pub u64);

/// Clock difference tolerated between members. A receiver or holder judges an
/// expiry that another member's clock set as passed only this long after it.
pub const EXPIRY_SKEW_SECONDS: u64 = 120;

impl UnixSeconds {
    pub fn now() -> Result<Self, &'static str> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| Self(elapsed.as_secs()))
            .map_err(|_| "system clock is before Unix epoch")
    }

    /// An expiry set by another member (author, authority) has not passed,
    /// allowing `EXPIRY_SKEW_SECONDS` for clock difference.
    pub fn before_remote_expiry(self, expires_at: u64) -> bool {
        expires_at.saturating_add(EXPIRY_SKEW_SECONDS) > self.0
    }

    /// An expiry set by this node's own clock has not passed. No skew.
    pub fn before_local_expiry(self, expires_at: u64) -> bool {
        expires_at > self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedPublication {
    pub sequence: u64,
    pub context: PublicationContext,
    pub ciphertext: Vec<u8>,
}
impl RetainedPublication {
    fn weight(&self) -> usize {
        self.context.authenticated_bytes().len() + self.ciphertext.len() + 12
    }
}
#[derive(Clone, Default)]
struct History {
    evicted_through: u64,
    records: VecDeque<RetainedPublication>,
}

/// Append-only sequence within one author/workspace/epoch, with bounded retention.
/// Eviction watermarks never disappear: a missing range cannot become "complete"
/// merely because all its old packets were evicted. `PublisherLog` keeps one
/// per retained epoch.
#[derive(Clone)]
pub struct EpochLog {
    workspace: [u8; 32],
    author: [u8; 32],
    epoch: u64,
    head: u64,
    bytes: usize,
    topics: BTreeMap<Topic, History>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RangeError {
    Invalid,
    Unavailable,
    Empty,
    TooLarge,
}
impl std::fmt::Display for RangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for RangeError {}

/// Expected publisher scope and requested exact-topic history. Transport must
/// bind the requester separately; a peer field in this query would not authenticate it.
#[derive(Clone)]
pub struct RangeQuery {
    pub workspace: [u8; 32],
    pub author: [u8; 32],
    pub epoch: u64,
    pub policy_revision: u64,
    pub after: u64,
    pub through: u64,
    pub topics: BTreeSet<Topic>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RetrievalError {
    Denied,
    History(RangeError),
}
impl std::fmt::Display for RetrievalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for RetrievalError {}

pub struct RetainedRange<'a> {
    request: RecoveryRequest,
    records: Vec<&'a RetainedPublication>,
}
impl RetainedRange<'_> {
    pub fn request(&self) -> &RecoveryRequest {
        &self.request
    }
    pub fn records(&self) -> &[&RetainedPublication] {
        &self.records
    }
    pub fn sign_offer(&self, owner: &arachne_security::Workspace) -> Result<Vec<u8>, &'static str> {
        let contexts: Vec<_> = self
            .records
            .iter()
            .map(|r| r.context.authenticated_bytes())
            .collect();
        let packets: Vec<_> = contexts
            .iter()
            .zip(&self.records)
            .map(|(context, record)| (context.as_slice(), record.ciphertext.as_slice()))
            .collect();
        owner.sign_recovery_offer(&self.request, &packets)
    }
}
impl EpochLog {
    pub fn new(workspace: [u8; 32], author: [u8; 32], epoch: u64) -> Self {
        Self {
            workspace,
            author,
            epoch,
            head: 0,
            bytes: 0,
            topics: BTreeMap::new(),
        }
    }
    pub fn head(&self) -> u64 {
        self.head
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// New publications only. Retransmit existing ciphertext without appending.
    /// Duplicate-ID detection covers retained records, not all historical IDs.
    pub fn append(
        &mut self,
        context: PublicationContext,
        ciphertext: Vec<u8>,
    ) -> Result<u64, &'static str> {
        if context.workspace != self.workspace
            || ciphertext.is_empty()
            || ciphertext.len() > MAX_APPLICATION_CIPHERTEXT
        {
            return Err("invalid retained publication");
        }
        if !self.topics.contains_key(&context.topic) && self.topics.len() == MAX_TOPICS {
            return Err("retention topic limit");
        }
        if self
            .topics
            .values()
            .flat_map(|h| &h.records)
            .any(|r| r.context.id == context.id)
        {
            return Err("publication already retained");
        }
        let sequence = self
            .head
            .checked_add(1)
            .ok_or("publisher sequence exhausted")?;
        if context.sequence.map(|number| number.get()) != Some(sequence) {
            return Err("authenticated sequence does not match publisher index");
        }
        let topic = context.topic.clone();
        let record = RetainedPublication {
            sequence,
            context,
            ciphertext,
        };
        self.bytes += record.weight();
        self.topics
            .entry(topic.clone())
            .or_default()
            .records
            .push_back(record);
        self.head = sequence;
        if self.topics[&topic].records.len() > MAX_PACKETS_PER_TOPIC {
            self.evict(&topic);
        }
        // ponytail: scan at most 64 topic heads; replace only if profiling requires it.
        while self.bytes > MAX_RETAINED_BYTES {
            assert!(self.evict_oldest());
        }
        Ok(sequence)
    }
    pub(crate) fn evict_oldest(&mut self) -> bool {
        let oldest = self
            .topics
            .iter()
            .filter_map(|(topic, h)| h.records.front().map(|r| (r.sequence, topic)))
            .min_by_key(|(seq, _)| *seq)
            .map(|(_, topic)| topic.clone());
        if let Some(topic) = oldest {
            self.evict(&topic);
            true
        } else {
            false
        }
    }
    fn evict(&mut self, topic: &Topic) {
        let history = self.topics.get_mut(topic).unwrap();
        let record = history.records.pop_front().unwrap();
        history.evicted_through = record.sequence;
        self.bytes -= record.weight();
    }

    /// Exact-topic selection over a fixed (after, through] range. Topic ACLs are
    /// the caller's responsibility. Include required progress topics explicitly.
    /// Empty selections succeed; unavailable/overlarge ranges never become partial success.
    pub fn select(
        &self,
        after: u64,
        through: u64,
        topics: &BTreeSet<Topic>,
    ) -> Result<RetainedRange<'_>, RangeError> {
        if after >= through || through > self.head || topics.is_empty() || topics.len() > MAX_TOPICS
        {
            return Err(RangeError::Invalid);
        }
        let mut records = Vec::new();
        for topic in topics {
            if let Some(history) = self.topics.get(topic) {
                if after < history.evicted_through {
                    return Err(RangeError::Unavailable);
                }
                records.extend(
                    history
                        .records
                        .iter()
                        .filter(|r| r.sequence > after && r.sequence <= through),
                );
                if records.len() > MAX_RECOVERY_PACKETS {
                    return Err(RangeError::TooLarge);
                }
            }
        }
        records.sort_by_key(|r| r.sequence);
        Ok(RetainedRange {
            request: RecoveryRequest {
                workspace: self.workspace,
                author: self.author,
                epoch: self.epoch,
                selection: selection_digest(topics),
                after,
                through,
            },
            records,
        })
    }

    /// Encoding contains ciphertext plus sensitive metadata. Authenticate/encrypt
    /// the complete host record, including the paired security snapshot, at rest.
    pub fn snapshot(&self) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend(self.workspace);
        bytes.extend(self.author);
        bytes.extend(self.epoch.to_be_bytes());
        bytes.extend(self.head.to_be_bytes());
        bytes.extend((self.topics.len() as u16).to_be_bytes());
        for (topic, history) in &self.topics {
            bytes.push(topic.as_str().len() as u8);
            bytes.extend(topic.as_str().as_bytes());
            bytes.extend(history.evicted_through.to_be_bytes());
            bytes.extend((history.records.len() as u16).to_be_bytes());
            for record in &history.records {
                bytes.extend(record.sequence.to_be_bytes());
                bytes.extend(record.context.revision.to_be_bytes());
                bytes.extend(record.context.id);
                bytes.extend((record.ciphertext.len() as u32).to_be_bytes());
                bytes.extend(&record.ciphertext);
            }
        }
        debug_assert!(bytes.len() <= MAX_SNAPSHOT_BYTES);
        bytes
    }

    /// Expected scope must come from accepted security state. This validates the
    /// codec, not authenticity of arbitrary bytes or correctness of a hostile index.
    pub fn restore(
        workspace: [u8; 32],
        author: [u8; 32],
        epoch: u64,
        bytes: &[u8],
    ) -> Result<Self, &'static str> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err("retention snapshot exceeds bounds");
        }
        let mut input = bytes;
        if take(&mut input, 5)? != MAGIC
            || take(&mut input, 32)? != workspace
            || take(&mut input, 32)? != author
            || number64(&mut input)? != epoch
        {
            return Err("wrong retention snapshot scope");
        }
        let mut log = Self::new(workspace, author, epoch);
        log.head = number64(&mut input)?;
        let count = number16(&mut input)?;
        if count > MAX_TOPICS {
            return Err("retention topic limit");
        }
        let mut previous = None;
        let mut sequences = BTreeSet::new();
        let mut ids = BTreeSet::new();
        let mut highest = 0;
        for _ in 0..count {
            let length = take(&mut input, 1)?[0] as usize;
            let topic = Topic::new(
                std::str::from_utf8(take(&mut input, length)?)
                    .map_err(|_| "invalid topic encoding")?,
            )
            .map_err(|_| "invalid retained topic")?;
            if previous.as_ref().is_some_and(|p| p >= &topic) {
                return Err("noncanonical retention topics");
            }
            previous = Some(topic.clone());
            let evicted_through = number64(&mut input)?;
            if evicted_through > log.head
                || (evicted_through != 0 && !sequences.insert(evicted_through))
            {
                return Err("invalid or duplicate eviction watermark");
            }
            highest = highest.max(evicted_through);
            let count = number16(&mut input)?;
            if count > MAX_PACKETS_PER_TOPIC {
                return Err("retention packet limit");
            }
            let mut history = History {
                evicted_through,
                records: VecDeque::new(),
            };
            let mut last = evicted_through;
            for _ in 0..count {
                let sequence = number64(&mut input)?;
                let authenticated_sequence =
                    Some(std::num::NonZeroU64::new(sequence).ok_or("zero publisher sequence")?);
                let revision = number64(&mut input)?;
                let id = take(&mut input, 16)?.try_into().unwrap();
                let length = u32::from_be_bytes(take(&mut input, 4)?.try_into().unwrap()) as usize;
                if sequence <= last
                    || sequence > log.head
                    || !sequences.insert(sequence)
                    || !ids.insert(id)
                    || length == 0
                    || length > MAX_APPLICATION_CIPHERTEXT
                {
                    return Err("invalid retained packet");
                }
                let record = RetainedPublication {
                    sequence,
                    context: PublicationContext {
                        sequence: authenticated_sequence,
                        workspace,
                        revision,
                        topic: topic.clone(),
                        id,
                    },
                    ciphertext: take(&mut input, length)?.to_vec(),
                };
                log.bytes += record.weight();
                if log.bytes > MAX_RETAINED_BYTES {
                    return Err("retained bytes exceed limit");
                }
                last = sequence;
                highest = highest.max(sequence);
                history.records.push_back(record);
            }
            if history.records.is_empty() && evicted_through == 0 {
                return Err("empty unobserved topic");
            }
            log.topics.insert(topic, history);
        }
        if !input.is_empty() || highest != log.head {
            return Err("invalid retention tail or head");
        }
        Ok(log)
    }
}

/// Authorize historical disclosure independently of which current member holds
/// the publisher-signed bytes. The holder never becomes the packet author.
pub(crate) fn authorize_history(
    owner: &arachne_security::Workspace,
    policy: &arachne_routing::RoutingTable,
    requester: [u8; 32],
    author: [u8; 32],
    revision: u64,
    topics: &BTreeSet<Topic>,
) -> Result<(), RetrievalError> {
    if topics.is_empty() || topics.len() > MAX_TOPICS {
        return Err(RetrievalError::Denied);
    }
    let endpoints = owner
        .member_endpoints()
        .map_err(|_| RetrievalError::Denied)?;
    let author_endpoint = owner
        .endpoints_for_members(&[author])
        .map_err(|_| RetrievalError::Denied)?[0];
    if !endpoints.contains(&requester) {
        return Err(RetrievalError::Denied);
    }
    for topic in topics {
        let publishers = policy
            .publishers(owner.id(), revision, requester, topic)
            .map_err(|_| RetrievalError::Denied)?;
        if !publishers.contains(&author_endpoint) {
            return Err(RetrievalError::Denied);
        }
    }
    Ok(())
}
/// Canonical exact-topic selection binding. Query validation separately enforces
/// nonempty selections and topic-count bounds before signing or network use.
pub fn selection_digest(topics: &BTreeSet<Topic>) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"data-fabric/exact-topic-selection/v1\0");
    hash.update((topics.len() as u16).to_be_bytes());
    for topic in topics {
        hash.update([topic.as_str().len() as u8]);
        hash.update(topic.as_str().as_bytes());
    }
    hash.finalize().into()
}

fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Result<&'a [u8], &'static str> {
    let (head, tail) = bytes
        .split_at_checked(count)
        .ok_or("truncated retention snapshot")?;
    *bytes = tail;
    Ok(head)
}
fn number64(bytes: &mut &[u8]) -> Result<u64, &'static str> {
    Ok(u64::from_be_bytes(take(bytes, 8)?.try_into().unwrap()))
}
fn number16(bytes: &mut &[u8]) -> Result<usize, &'static str> {
    Ok(u16::from_be_bytes(take(bytes, 2)?.try_into().unwrap()) as usize)
}

#[test]
fn retention_watermarks_scope_and_snapshot_bounds() {
    let mut log = EpochLog::new([1; 32], [2; 32], 3);
    // Publications are appended in id order, so the id is also the sequence.
    let context = |topic: &str, id: u128| PublicationContext {
        sequence: std::num::NonZeroU64::new(id as u64),
        workspace: [1; 32],
        revision: 7,
        topic: Topic::new(topic).unwrap(),
        id: id.to_be_bytes(),
    };
    let quiet = BTreeSet::from([Topic::new("quiet").unwrap()]);
    let busy = BTreeSet::from([Topic::new("busy").unwrap()]);
    log.append(context("quiet", 1), vec![1]).unwrap();
    for id in 2..52 {
        log.append(context("busy", id), vec![2]).unwrap();
    }
    log.append(context("quiet", 52), vec![3]).unwrap();
    let range = log.select(0, 52, &quiet).unwrap();
    assert_eq!(
        range
            .records()
            .iter()
            .map(|r| r.sequence)
            .collect::<Vec<_>>(),
        [1, 52]
    );
    assert_eq!(
        log.select(0, 52, &busy).err(),
        Some(RangeError::Unavailable)
    );
    assert!(log.select(0, 53, &quiet).is_err());
    let snapshot = log.snapshot();
    let restored = EpochLog::restore([1; 32], [2; 32], 3, &snapshot).unwrap();
    assert_eq!(snapshot, restored.snapshot());
    assert_eq!(restored.select(0, 52, &quiet).unwrap().records().len(), 2);
    assert!(restored.select(0, 52, &busy).is_err());
    for cut in [0, 4, 5, 37, 69, 85, snapshot.len() - 1] {
        assert!(EpochLog::restore([1; 32], [2; 32], 3, &snapshot[..cut]).is_err());
    }
    let mut collision = snapshot.clone();
    // First canonical topic is "busy"; its eviction sequence cannot also be
    // the sequence of the still-retained first quiet publication.
    let floor_offset = 5 + 32 + 32 + 8 + 8 + 2 + 1 + "busy".len();
    collision[floor_offset..floor_offset + 8].copy_from_slice(&1u64.to_be_bytes());
    assert!(EpochLog::restore([1; 32], [2; 32], 3, &collision).is_err());
    let mut trailing = snapshot.clone();
    trailing.push(0);
    assert!(EpochLog::restore([1; 32], [2; 32], 3, &trailing).is_err());
    assert!(EpochLog::restore([9; 32], [2; 32], 3, &snapshot).is_err());
    assert!(EpochLog::restore([1; 32], [9; 32], 3, &snapshot).is_err());
    assert!(EpochLog::restore([1; 32], [2; 32], 4, &snapshot).is_err());
    assert!(EpochLog::restore([1; 32], [2; 32], 3, &vec![0; MAX_SNAPSHOT_BYTES + 1]).is_err());
    assert!(log.append(context("quiet", 52), vec![4]).is_err());
    assert!(log.append(context("quiet", 53), vec![]).is_err());
    assert_eq!(log.head(), 52);
    for id in 53..90 {
        log.append(context("large", id), vec![5; MAX_APPLICATION_CIPHERTEXT])
            .unwrap();
    }
    assert!(log.bytes <= MAX_RETAINED_BYTES);
    assert!(log.snapshot().len() <= MAX_SNAPSHOT_BYTES);
    assert!(log.select(0, log.head(), &quiet).is_err()); // Byte-budget eviction cannot erase the watermark.
    let restored = EpochLog::restore([1; 32], [2; 32], 3, &log.snapshot()).unwrap();
    assert!(restored.select(0, restored.head(), &quiet).is_err());
    let mut many = EpochLog::new([1; 32], [2; 32], 3);
    for id in 0..MAX_TOPICS {
        many.append(context(&format!("topic/{id:02}"), id as u128 + 1), vec![1])
            .unwrap();
    }
    assert_eq!(
        many.append(context("overflow", MAX_TOPICS as u128 + 1), vec![1]),
        Err("retention topic limit")
    );
    // An unsequenced (legacy) publication is never retained.
    let mut unsequenced = context("topic/00", MAX_TOPICS as u128 + 1);
    unsequenced.sequence = None;
    assert!(many.append(unsequenced, vec![1]).is_err());
    let all = many.topics.keys().cloned().collect();
    assert_eq!(
        many.select(0, many.head(), &all).err(),
        Some(RangeError::TooLarge)
    );
    let before = many.snapshot();
    let mut wrong = context("topic/00", 999);
    wrong.workspace = [9; 32];
    assert!(many.append(wrong, vec![1]).is_err());
    assert_eq!(before, many.snapshot());
    many.head = u64::MAX;
    assert!(many.append(context("topic/00", 999), vec![1]).is_err());
}

#[test]
fn restored_index_builds_offer_for_selected_real_objects() {
    use arachne_security::{PendingJoin, Workspace};
    let admin = Workspace::create([1; 32], "Publisher").unwrap();
    let (registered, invite, checkpoint) = admin.prepare_invitation(0, false, false).unwrap();
    let admin = registered.workspace;
    let pending = PendingJoin::from_invitation(&invite, &checkpoint, [2; 32], "Reader").unwrap();
    let prepared = admin
        .prepare_admission([2; 32], pending.admission_request().unwrap())
        .unwrap();
    let mut proof = pending.join_proof().unwrap();
    proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let receiver = pending
        .prepare_workspace(&proof, &prepared.welcome)
        .unwrap();
    let mut sender = prepared.workspace;
    let mut log = PublisherLog::new(&sender).unwrap();
    for id in 1..=52u128 {
        let topic = if id == 1 || id == 52 { "quiet" } else { "busy" };
        let context = PublicationContext {
            sequence: std::num::NonZeroU64::new(id as u64),
            workspace: sender.id(),
            revision: 7,
            topic: Topic::new(topic).unwrap(),
            id: id.to_be_bytes(),
        };
        let packet = sender
            .protect_object(
                context.topic.namespace().as_bytes(),
                &context.authenticated_bytes(),
                &id.to_be_bytes(),
            )
            .unwrap();
        log.append(context, packet).unwrap();
    }
    let log = PublisherLog::restore(&sender, &log.snapshot()).unwrap();
    let topics = BTreeSet::from([Topic::new("quiet").unwrap()]);
    let mut policy = arachne_routing::RoutingTable::default();
    let owner_access = arachne_routing::Permissions::Selected {
        publish: BTreeSet::from([Topic::new("quiet").unwrap(), Topic::new("busy").unwrap()]),
        subscribe: BTreeSet::new(),
    };
    let reader_access = arachne_routing::Permissions::Selected {
        publish: BTreeSet::new(),
        subscribe: topics.clone(),
    };
    // A stale routing entry for a nonmember cannot establish membership.
    policy
        .install_verified_policy(
            sender.id(),
            7,
            BTreeMap::from([
                (sender.endpoint(), owner_access.clone()),
                (receiver.endpoint(), reader_access.clone()),
                ([99; 32], reader_access.clone()),
            ]),
        )
        .unwrap();
    let cutoff = wire::CutoffQuery {
        workspace: sender.id(),
        author: sender.member().unwrap().id(),
        epoch: sender.epoch(),
        policy_revision: 7,
        topics: topics.clone(),
        nonce: [62; 32],
    };
    let signed_head =
        wire::serve_cutoff(&log, &sender, &policy, receiver.endpoint(), &cutoff).unwrap();
    assert_eq!(
        wire::verify_cutoff_reply(&receiver, &cutoff, &signed_head).unwrap(),
        Some(52)
    );
    assert_eq!(
        wire::serve_cutoff(&log, &sender, &policy, [99; 32], &cutoff).unwrap(),
        wire::denied_reply()
    );
    let mut unreadable = cutoff.clone();
    unreadable.topics.insert(Topic::new("busy").unwrap());
    assert_eq!(
        wire::serve_cutoff(&log, &sender, &policy, receiver.endpoint(), &unreadable).unwrap(),
        wire::denied_reply()
    );
    let mut query = RangeQuery {
        workspace: sender.id(),
        author: sender.member().unwrap().id(),
        epoch: sender.epoch(),
        policy_revision: 7,
        after: 0,
        through: 52,
        topics: topics.clone(),
    };
    assert_eq!(
        log.authorized_range(&sender, &policy, [99; 32], &query)
            .err(),
        Some(RetrievalError::Denied)
    );
    query.topics.insert(Topic::new("busy").unwrap());
    // Hidden missing history must not leak as Unavailable to an unauthorized reader.
    assert_eq!(
        log.authorized_range(&sender, &policy, receiver.endpoint(), &query)
            .err(),
        Some(RetrievalError::Denied)
    );
    query.topics = topics.clone();
    query.workspace = [99; 32];
    assert_eq!(
        log.authorized_range(&sender, &policy, receiver.endpoint(), &query)
            .err(),
        Some(RetrievalError::Denied)
    );
    query.workspace = sender.id();
    query.epoch += 1;
    assert_eq!(
        log.authorized_range(&sender, &policy, receiver.endpoint(), &query)
            .err(),
        Some(RetrievalError::Denied)
    );
    query.epoch = sender.epoch();
    query.policy_revision = 6;
    assert_eq!(
        log.authorized_range(&sender, &policy, receiver.endpoint(), &query)
            .err(),
        Some(RetrievalError::Denied)
    );
    query.policy_revision = 7;
    // Busy publications exist in (1, 51], but no selected quiet publication.
    // The receiver needs an author-signed empty selection, not an advisory status.
    let empty_query = RangeQuery {
        workspace: query.workspace,
        author: query.author,
        epoch: query.epoch,
        policy_revision: query.policy_revision,
        after: 1,
        through: 51,
        topics: query.topics.clone(),
    };
    let empty_response =
        wire::serve_range(&log, &sender, &policy, receiver.endpoint(), &empty_query).unwrap();
    let wire::RangeReply::Offered(empty_proof) =
        wire::verify_reply(&receiver, &empty_query, &empty_response).unwrap()
    else {
        panic!("empty selected range must be author-authenticated");
    };
    assert!(empty_proof.packets().is_empty());
    assert!(wire::verify_reply(&receiver, &query, &empty_response).is_err());
    let mut damaged_empty = empty_response.clone();
    // Last byte is packet count; the preceding byte is part of the signature.
    let signature_byte = damaged_empty.len() - 2;
    damaged_empty[signature_byte] ^= 1;
    assert!(wire::verify_reply(&receiver, &empty_query, &damaged_empty).is_err());
    assert!(matches!(
        wire::verify_reply(&receiver, &empty_query, b"DFRP\x01\x04").unwrap(),
        wire::RangeReply::Rejected(RetrievalError::History(RangeError::Empty))
    ));
    let denied_empty = wire::serve_range(&log, &sender, &policy, [99; 32], &empty_query).unwrap();
    assert!(matches!(
        wire::verify_reply(&receiver, &empty_query, &denied_empty).unwrap(),
        wire::RangeReply::Rejected(RetrievalError::Denied)
    ));
    let range = log
        .authorized_range(&sender, &policy, receiver.endpoint(), &query)
        .unwrap();
    let encoded = range.sign_offer(&sender).unwrap();
    let encoded_query = query.to_wire().unwrap();
    let wire_query = RangeQuery::from_wire(&encoded_query).unwrap();
    assert_eq!(wire_query.to_wire().unwrap(), encoded_query);
    let response =
        wire::serve_range(&log, &sender, &policy, receiver.endpoint(), &wire_query).unwrap();
    let wire::RangeReply::Offered(wire_proof) =
        wire::verify_reply(&receiver, &query, &response).unwrap()
    else {
        panic!("expected range")
    };
    assert_eq!(wire_proof.packets().len(), 2);
    for (decoded, retained) in wire_proof.packets().iter().zip(range.records()) {
        assert_eq!(decoded.context, retained.context);
        assert_eq!(decoded.ciphertext, retained.ciphertext);
    }
    for cut in [0, 5, 6, 8, response.len() - 1] {
        assert!(wire::verify_reply(&receiver, &query, &response[..cut]).is_err());
    }
    let mut corrupt = response.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(wire::verify_reply(&receiver, &query, &corrupt).is_err());
    corrupt = response.clone();
    corrupt.push(0);
    assert!(wire::verify_reply(&receiver, &query, &corrupt).is_err());
    let count_at = 8 + u16::from_be_bytes(response[6..8].try_into().unwrap()) as usize;
    let mut omitted_all = response[..count_at + 1].to_vec();
    omitted_all[count_at] = 0;
    assert!(wire::verify_reply(&receiver, &query, &omitted_all).is_err());
    let first = count_at + 1;
    let ciphertext_length_at = first + 8 + 1 + response[first + 8] as usize + 16;
    let second = ciphertext_length_at
        + 4
        + u32::from_be_bytes(
            response[ciphertext_length_at..ciphertext_length_at + 4]
                .try_into()
                .unwrap(),
        ) as usize;
    let mut omitted = response[..second].to_vec();
    omitted[count_at] = 1;
    assert!(wire::verify_reply(&receiver, &query, &omitted).is_err());
    let mut reordered = response[..first].to_vec();
    reordered.extend(&response[second..]);
    reordered.extend(&response[first..second]);
    assert!(wire::verify_reply(&receiver, &query, &reordered).is_err());
    let mut large = PublisherLog::new(&sender).unwrap();
    for id in 1u128..=8 {
        large
            .append(
                PublicationContext {
                    sequence: std::num::NonZeroU64::new(id as u64),
                    workspace: sender.id(),
                    revision: 7,
                    topic: Topic::new("quiet").unwrap(),
                    id: id.to_be_bytes(),
                },
                vec![1; MAX_APPLICATION_CIPHERTEXT],
            )
            .unwrap();
    }
    let large_query = RangeQuery {
        through: 8,
        ..RangeQuery::from_wire(&encoded_query).unwrap()
    };
    let rejected =
        wire::serve_range(&large, &sender, &policy, receiver.endpoint(), &large_query).unwrap();
    assert!(matches!(
        wire::verify_reply(&receiver, &large_query, &rejected).unwrap(),
        wire::RangeReply::Rejected(RetrievalError::History(RangeError::TooLarge))
    ));
    let denied = wire::serve_range(&log, &sender, &policy, [99; 32], &query).unwrap();
    assert!(matches!(
        wire::verify_reply(&receiver, &query, &denied).unwrap(),
        wire::RangeReply::Rejected(RetrievalError::Denied)
    ));

    let verified = receiver
        .verify_recovery_offer(range.request(), &encoded)
        .unwrap();
    let contexts: Vec<_> = range
        .records()
        .iter()
        .map(|r| r.context.authenticated_bytes())
        .collect();
    let packets: Vec<_> = contexts
        .iter()
        .zip(range.records())
        .map(|(c, r)| (c.as_slice(), r.ciphertext.as_slice()))
        .collect();
    verified.verify_packets(&packets).unwrap();
    assert!(verified.verify_packets(&packets[1..]).is_err());
    // Objects carry no ratchet state: any number of decryptions is side-effect
    // free; delivery dedup is the inbox's job.
    for _ in 0..2 {
        for ((context, packet), id) in packets.iter().zip([1u128, 52]) {
            let message = receiver
                .unprotect_object(b"quiet", context, packet)
                .unwrap()
                .message;
            verified.verify_origin(&message).unwrap();
            wire_proof.verify_origin(&message).unwrap();
            assert_eq!(message.payload, id.to_be_bytes());
        }
    }
    drop(verified);
    drop(wire_proof);
    policy
        .install_verified_policy(
            sender.id(),
            8,
            BTreeMap::from([
                (sender.endpoint(), owner_access.clone()),
                (
                    receiver.endpoint(),
                    arachne_routing::Permissions::Selected {
                        publish: BTreeSet::new(),
                        subscribe: BTreeSet::from([Topic::new("busy").unwrap()]),
                    },
                ),
            ]),
        )
        .unwrap();
    query.policy_revision = 8;
    assert_eq!(
        log.authorized_range(&sender, &policy, receiver.endpoint(), &query)
            .err(),
        Some(RetrievalError::Denied)
    );
    query.topics = BTreeSet::from([Topic::new("busy").unwrap()]);
    assert_eq!(
        log.authorized_range(&sender, &policy, receiver.endpoint(), &query)
            .err(),
        Some(RetrievalError::History(RangeError::Unavailable))
    );
    policy
        .install_verified_policy(
            sender.id(),
            9,
            BTreeMap::from([
                (sender.endpoint(), arachne_routing::Permissions::default()),
                (receiver.endpoint(), reader_access),
            ]),
        )
        .unwrap();
    query.policy_revision = 9;
    query.topics = topics;
    assert_eq!(
        log.authorized_range(&sender, &policy, receiver.endpoint(), &query)
            .err(),
        Some(RetrievalError::Denied)
    );
}

