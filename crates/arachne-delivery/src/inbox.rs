//! Bounded replay evidence and durable pending objects. Stage -> save -> adopt;
//! acknowledge only after the application durably accepts the stable identity.
use super::*;
use serde::{Deserialize, Serialize};

const MAGIC: &[u8] = b"DFOI\x02";
/// Binary inbox state (A6f). Earlier versions are rejected.
const CACHE_MAGIC: &[u8] = b"DFIC\x05";
/// Replay windows: one per (author, epoch) that sent to this member.
const MAX_REPLAY_WINDOWS: usize = 4096;
/// Accepted counters tracked above one replay floor. An author's counter is
/// shared by all its topics and audiences, so a receiver sees a sparse subset;
/// the window is bounded by accepted entries, not by counter span. When it is
/// full, the floor moves up to the oldest entry and older unseen counters are
/// given up as lost.
pub const REPLAY_ENTRIES: usize = 1024;
const MAX_PENDING_OBJECTS: usize = 512;
/// Pending objects one author may hold in this inbox.
pub const MAX_PENDING_OBJECTS_PER_AUTHOR: usize = 128;
/// Pending payload bytes one author may hold in this inbox.
pub const MAX_PENDING_BYTES_PER_AUTHOR: usize = 32 * 1024;
/// Pending payload bytes of all authors together.
pub const MAX_PENDING_BYTES: usize = 96 * 1024;
/// Refusal when one author's pending objects fill its quota.
pub const AUTHOR_QUOTA_EXHAUSTED: &str = "author pending quota exhausted";
/// Refusal when all authors' pending objects fill the inbox.
pub const PENDING_INBOX_FULL: &str = "pending inbox full";

/// True when a refused object can be accepted after the application
/// acknowledges or rejects pending objects. Recovery stops at such a refusal
/// and continues later; it does not skip the object.
pub fn drains_with_application(error: &str) -> bool {
    error == AUTHOR_QUOTA_EXHAUSTED || error == PENDING_INBOX_FULL
}
/// Encoded bound of the inbox. With `PUBLISHER_BUDGET` it fits one workspace
/// attachment: saving never evicts publisher history to make room, and the
/// operation that would grow the inbox past it fails instead.
pub const INBOX_BUDGET: usize =
    arachne_security::MAX_WORKSPACE_ATTACHMENT - 9 - crate::PUBLISHER_BUDGET;
/// Retained third-party proofs (ranges and current views) together. The one
/// that expires first gives way.
const MAX_RETAINED_PROOF_BYTES: usize = wire::MAX_REPLY_BYTES + 4 * 1024;
/// Recently accepted publication ids kept for cross-epoch dedup.
pub const RECENT_IDS: usize = 256;
const MAX_RETAINED_RANGES: usize = 4;
const MAX_RETAINED_CURRENT_VIEWS: usize = 4;
const MAX_RECOVERY_SELECTIONS: usize = 64;
const MAX_DIRECT_STREAMS: usize = 256;
/// Retained direct records per recipient scope.
const DIRECT_WINDOW: usize = MAX_PACKETS_PER_TOPIC;
// Recovery copies are optional; pending application objects and replay floors
// are not. Bound encoded copies across all audiences, not just packet counts.
const MAX_DIRECT_RETAINED_BYTES: usize = 32 * 1024;

/// Dedup for one author's sender counters in one epoch. Separate from pending
/// storage: acknowledging an object never reopens its counter.
#[derive(Clone)]
struct Replay {
    author: [u8; 32],
    epoch: u64,
    /// Counters at or below this were given up as lost (window moved past).
    lost_through: u64,
    /// Every counter at or below `floor` is closed: accepted or lost.
    floor: u64,
    /// Accepted counters above `floor`: at most `REPLAY_ENTRIES`.
    seen: BTreeSet<u64>,
}

/// Stable publication identity, independent of epoch and counter.
fn publication_identity(author: [u8; 32], id: [u8; 16]) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"arachne/publication-identity/v1\0");
    hash.update(author);
    hash.update(id);
    hash.finalize()[..16].try_into().unwrap()
}

enum ReplayState {
    New,
    Duplicate,
    Lost,
}

impl Replay {
    fn state(&self, counter: u64) -> ReplayState {
        if counter <= self.lost_through {
            ReplayState::Lost
        } else if counter <= self.floor || self.seen.contains(&counter) {
            ReplayState::Duplicate
        } else {
            ReplayState::New
        }
    }

    fn accept(&mut self, counter: u64) {
        self.seen.insert(counter);
        while self.seen.remove(&(self.floor + 1)) {
            self.floor += 1;
        }
        // Bound the window: a gap below many accepted objects is given up, so
        // it cannot pin state forever. Late objects inside the window still
        // fill their gap.
        while self.seen.len() > REPLAY_ENTRIES {
            let oldest = self.seen.pop_first().expect("nonempty seen set");
            self.lost_through = oldest - 1;
            self.floor = oldest;
            while self.seen.remove(&(self.floor + 1)) {
                self.floor += 1;
            }
        }
    }

    fn valid(&self) -> bool {
        self.lost_through <= self.floor
            && self.seen.first().is_none_or(|first| *first > self.floor + 1)
            && self.seen.len() <= REPLAY_ENTRIES
    }
}

/// Authenticated plaintext waiting for the application. It no longer needs
/// the epoch key, so it survives epoch changes and key eviction.
#[derive(Clone)]
struct Pending {
    author: [u8; 32],
    endpoint: [u8; 32],
    epoch: u64,
    counter: u64,
    revision: u64,
    topic: String,
    id: [u8; 16],
    sequence: u64,
    recipients: Vec<[u8; 32]>,
    current: Option<CurrentReceipt>,
    payload: Vec<u8>,
}

impl Pending {
    /// Encoded size in the inbox snapshot (see `Snapshot::encode`).
    fn weight(topic: usize, recipients: usize, current: bool, payload: usize) -> usize {
        32 + 32 + 8 * 3 + 1 + topic + 16 + 8 + 1 + 32 * recipients + 1
            + if current { 72 } else { 0 }
            + 4
            + payload
    }

    fn encoded_len(&self) -> usize {
        Self::weight(
            self.topic.len(),
            self.recipients.len(),
            self.current.is_some(),
            self.payload.len(),
        )
    }
}

#[derive(Clone, PartialEq, Eq)]
struct CurrentReceipt {
    selector: [u8; 32],
    replacement_key: [u8; 32],
    expires_at: u64,
    tombstone: bool,
}

impl From<current::CurrentMetadata> for CurrentReceipt {
    fn from(value: current::CurrentMetadata) -> Self {
        Self {
            selector: value.selector,
            replacement_key: value.replacement_key,
            expires_at: value.expires_at,
            tombstone: value.tombstone,
        }
    }
}

impl From<&CurrentReceipt> for current::CurrentMetadata {
    fn from(value: &CurrentReceipt) -> Self {
        Self {
            selector: value.selector,
            replacement_key: value.replacement_key,
            expires_at: value.expires_at,
            tombstone: value.tombstone,
        }
    }
}

#[derive(Clone)]
struct RetainedRange {
    query: Vec<u8>,
    reply: Vec<u8>,
    expires_at: u64,
}

#[derive(Clone)]
struct RetainedCurrentView {
    query: Vec<u8>,
    reply: Vec<u8>,
    expires_at: u64,
}

#[derive(Clone)]
struct SelectionProgress {
    author: [u8; 32],
    epoch: u64,
    selection: [u8; 32],
    through: u64,
}

#[derive(Clone)]
struct CurrentProgress {
    authority: [u8; 32],
    revision: u64,
    topic: String,
    selector: [u8; 32],
    cut: u64,
    digest: [u8; 32],
}

#[derive(Clone)]
struct DirectRecord {
    revision: u64,
    id: [u8; 16],
    sequence: u64,
    object: Vec<u8>,
}

#[derive(Clone)]
struct DirectStream {
    author: [u8; 32],
    revision: u64,
    topic: String,
    recipients: Vec<[u8; 32]>,
    floor: u64,
    recovery_floor: u64,
    known_head: u64,
    records: Vec<DirectRecord>,
}

impl DirectStream {
    /// Evict the oldest recovery copy and move the floor to it. Sequences
    /// between the old floor and that copy were never received: they are
    /// given up as missed (B7e). Returns how many.
    fn evict_first(&mut self) -> u64 {
        let expected = self.floor.max(self.recovery_floor).saturating_add(1);
        let sequence = self.records.remove(0).sequence;
        self.floor = self.floor.max(sequence);
        sequence.saturating_sub(expected)
    }

    /// True when `sequence` is at or below the floor: accepted, evicted, or
    /// given up as missed. A late copy of such a sequence is dropped.
    fn closed(&self, sequence: u64) -> bool {
        sequence <= self.floor.max(self.recovery_floor)
    }

    fn effective_head(&self) -> u64 {
        self.known_head.max(
            self.records
                .last()
                .map_or(self.floor.max(self.recovery_floor), |record| {
                    record.sequence
                }),
        )
    }
}

#[derive(Clone)]
pub struct ObjectInbox {
    workspace: [u8; 32],
    /// The local accepted epoch. Replay state and pending objects from the
    /// receive window are kept across epoch changes (`advance`).
    epoch: u64,
    // ponytail: linear lookup up to 4,096 windows; index if measured load requires it.
    replay: Vec<Replay>,
    /// Arrival order.
    pending: Vec<Pending>,
    /// Recently accepted (author, publication id) digests, across epochs. A
    /// copy that the author re-publishes under a new epoch or counter is a
    /// duplicate.
    recent: VecDeque<[u8; 16]>,
    /// Round-robin service: acknowledgement tick of each delivery scope that
    /// has pending work.
    clock: u64,
    served: Vec<([u8; 32], u64)>,
    retained_ranges: Vec<RetainedRange>,
    retained_current_views: Vec<RetainedCurrentView>,
    current: Option<Box<current::CurrentViewIndex>>,
    progress: Vec<SelectionProgress>,
    current_progress: Vec<CurrentProgress>,
    direct: Vec<DirectStream>,
    /// Direct sequences given up as missed since this inbox was created or
    /// restored (B7e). Not persisted: a staging step reports the difference
    /// between its candidate and the adopted state.
    missed: u64,
}

/// Decoded state part of an inbox snapshot. Binary, canonical, bounded:
/// payloads and objects are raw bytes, not JSON number arrays.
struct Snapshot {
    workspace: [u8; 32],
    epoch: u64,
    replay: Vec<Replay>,
    pending: Vec<Pending>,
    recent: VecDeque<[u8; 16]>,
    clock: u64,
    served: Vec<([u8; 32], u64)>,
    progress: Vec<SelectionProgress>,
    current_progress: Vec<CurrentProgress>,
    direct: Vec<DirectStream>,
}

mod codec {
    //! Byte helpers for the inbox snapshot. Lengths are checked on read.
    use super::super::{number64, take};

    pub(super) fn u64(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend(value.to_be_bytes());
    }
    pub(super) fn count(bytes: &mut Vec<u8>, value: usize) {
        bytes.extend((value as u32).to_be_bytes());
    }
    pub(super) fn blob(bytes: &mut Vec<u8>, value: &[u8]) {
        count(bytes, value.len());
        bytes.extend(value);
    }
    pub(super) fn text(bytes: &mut Vec<u8>, value: &str) {
        bytes.push(value.len() as u8);
        bytes.extend(value.as_bytes());
    }
    /// LEB128: sparse replay counters as small deltas.
    pub(super) fn varint(bytes: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            bytes.push(value as u8 | 0x80);
            value >>= 7;
        }
        bytes.push(value as u8);
    }

    pub(super) fn read_u64(input: &mut &[u8]) -> Result<u64, &'static str> {
        number64(input)
    }
    pub(super) fn read_count(input: &mut &[u8], limit: usize) -> Result<usize, &'static str> {
        let value = u32::from_be_bytes(take(input, 4)?.try_into().unwrap()) as usize;
        if value > limit {
            return Err("inbox snapshot count exceeds bound");
        }
        Ok(value)
    }
    pub(super) fn read_blob(input: &mut &[u8], limit: usize) -> Result<Vec<u8>, &'static str> {
        let length = read_count(input, limit)?;
        Ok(take(input, length)?.to_vec())
    }
    pub(super) fn read_text(input: &mut &[u8]) -> Result<String, &'static str> {
        let length = take(input, 1)?[0] as usize;
        String::from_utf8(take(input, length)?.to_vec()).map_err(|_| "invalid inbox text")
    }
    pub(super) fn read_array<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], &'static str> {
        Ok(take(input, N)?.try_into().unwrap())
    }
    pub(super) fn read_varint(input: &mut &[u8]) -> Result<u64, &'static str> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = take(input, 1)?[0];
            value |= u64::from(byte & 0x7f)
                .checked_shl(shift)
                .filter(|part| part >> shift == u64::from(byte & 0x7f))
                .ok_or("invalid varint")?;
            if byte & 0x80 == 0 {
                if byte == 0 && shift != 0 {
                    return Err("noncanonical varint");
                }
                return Ok(value);
            }
        }
        Err("invalid varint")
    }
}

fn encode_recipients(bytes: &mut Vec<u8>, recipients: &[[u8; 32]]) {
    bytes.push(recipients.len() as u8);
    for recipient in recipients {
        bytes.extend(recipient);
    }
}

fn decode_recipients(input: &mut &[u8]) -> Result<Vec<[u8; 32]>, &'static str> {
    let count = take(input, 1)?[0] as usize;
    if count > 64 {
        return Err("too many inbox recipients");
    }
    (0..count).map(|_| codec::read_array(input)).collect()
}

impl DirectStream {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend(self.author);
        codec::u64(bytes, self.revision);
        codec::text(bytes, &self.topic);
        encode_recipients(bytes, &self.recipients);
        codec::u64(bytes, self.floor);
        codec::u64(bytes, self.recovery_floor);
        codec::u64(bytes, self.known_head);
        codec::count(bytes, self.records.len());
        for record in &self.records {
            codec::u64(bytes, record.revision);
            bytes.extend(record.id);
            codec::u64(bytes, record.sequence);
            codec::blob(bytes, &record.object);
        }
    }

    fn decode(input: &mut &[u8]) -> Result<Self, &'static str> {
        let author = codec::read_array(input)?;
        let revision = codec::read_u64(input)?;
        let topic = codec::read_text(input)?;
        let recipients = decode_recipients(input)?;
        let floor = codec::read_u64(input)?;
        let recovery_floor = codec::read_u64(input)?;
        let known_head = codec::read_u64(input)?;
        let count = codec::read_count(input, DIRECT_WINDOW)?;
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            records.push(DirectRecord {
                revision: codec::read_u64(input)?,
                id: codec::read_array(input)?,
                sequence: codec::read_u64(input)?,
                object: codec::read_blob(input, arachne_security::MAX_APPLICATION_CIPHERTEXT)?,
            });
        }
        Ok(Self {
            author,
            revision,
            topic,
            recipients,
            floor,
            recovery_floor,
            known_head,
            records,
        })
    }

    fn encoded_len(&self) -> usize {
        32 + 8 + 1 + self.topic.len() + 1 + 32 * self.recipients.len() + 24 + 4
            + self
                .records
                .iter()
                .map(|record| 8 + 16 + 8 + 4 + record.object.len())
                .sum::<usize>()
    }
}

impl Snapshot {
    fn encode(inbox: &ObjectInbox, bytes: &mut Vec<u8>) {
        bytes.extend(inbox.workspace);
        codec::u64(bytes, inbox.epoch);
        codec::count(bytes, inbox.replay.len());
        for replay in &inbox.replay {
            bytes.extend(replay.author);
            codec::u64(bytes, replay.epoch);
            codec::u64(bytes, replay.lost_through);
            codec::u64(bytes, replay.floor);
            codec::count(bytes, replay.seen.len());
            let mut previous = replay.floor;
            for counter in &replay.seen {
                codec::varint(bytes, counter - previous);
                previous = *counter;
            }
        }
        codec::count(bytes, inbox.pending.len());
        for pending in &inbox.pending {
            bytes.extend(pending.author);
            bytes.extend(pending.endpoint);
            codec::u64(bytes, pending.epoch);
            codec::u64(bytes, pending.counter);
            codec::u64(bytes, pending.revision);
            codec::text(bytes, &pending.topic);
            bytes.extend(pending.id);
            codec::u64(bytes, pending.sequence);
            encode_recipients(bytes, &pending.recipients);
            match &pending.current {
                None => bytes.push(0),
                Some(current) => {
                    bytes.push(1 + u8::from(current.tombstone));
                    bytes.extend(current.selector);
                    bytes.extend(current.replacement_key);
                    codec::u64(bytes, current.expires_at);
                }
            }
            codec::blob(bytes, &pending.payload);
        }
        codec::count(bytes, inbox.recent.len());
        for identity in &inbox.recent {
            bytes.extend(identity);
        }
        codec::u64(bytes, inbox.clock);
        codec::count(bytes, inbox.served.len());
        for (scope, tick) in &inbox.served {
            bytes.extend(scope);
            codec::u64(bytes, *tick);
        }
        codec::count(bytes, inbox.progress.len());
        for progress in &inbox.progress {
            bytes.extend(progress.author);
            codec::u64(bytes, progress.epoch);
            bytes.extend(progress.selection);
            codec::u64(bytes, progress.through);
        }
        codec::count(bytes, inbox.current_progress.len());
        for progress in &inbox.current_progress {
            bytes.extend(progress.authority);
            codec::u64(bytes, progress.revision);
            codec::text(bytes, &progress.topic);
            bytes.extend(progress.selector);
            codec::u64(bytes, progress.cut);
            bytes.extend(progress.digest);
        }
        codec::count(bytes, inbox.direct.len());
        for stream in &inbox.direct {
            stream.encode(bytes);
        }
    }

    fn decode(input: &mut &[u8]) -> Result<Self, &'static str> {
        let workspace = codec::read_array(input)?;
        let epoch = codec::read_u64(input)?;
        let count = codec::read_count(input, MAX_REPLAY_WINDOWS)?;
        let mut replay = Vec::with_capacity(count);
        for _ in 0..count {
            let author = codec::read_array(input)?;
            let epoch = codec::read_u64(input)?;
            let lost_through = codec::read_u64(input)?;
            let floor = codec::read_u64(input)?;
            let seen_count = codec::read_count(input, REPLAY_ENTRIES)?;
            let mut seen = BTreeSet::new();
            let mut previous = floor;
            for _ in 0..seen_count {
                let delta = codec::read_varint(input)?;
                previous = previous
                    .checked_add(delta)
                    .filter(|_| delta != 0)
                    .ok_or("invalid replay counter")?;
                seen.insert(previous);
            }
            replay.push(Replay {
                author,
                epoch,
                lost_through,
                floor,
                seen,
            });
        }
        let count = codec::read_count(input, MAX_PENDING_OBJECTS)?;
        let mut pending = Vec::with_capacity(count);
        for _ in 0..count {
            let author = codec::read_array(input)?;
            let endpoint = codec::read_array(input)?;
            let epoch = codec::read_u64(input)?;
            let counter = codec::read_u64(input)?;
            let revision = codec::read_u64(input)?;
            let topic = codec::read_text(input)?;
            let id = codec::read_array(input)?;
            let sequence = codec::read_u64(input)?;
            let recipients = decode_recipients(input)?;
            let current = match take(input, 1)?[0] {
                0 => None,
                flag @ (1 | 2) => Some(CurrentReceipt {
                    selector: codec::read_array(input)?,
                    replacement_key: codec::read_array(input)?,
                    expires_at: codec::read_u64(input)?,
                    tombstone: flag == 2,
                }),
                _ => return Err("invalid pending current marker"),
            };
            let payload = codec::read_blob(input, arachne_security::MAX_APPLICATION_PAYLOAD)?;
            pending.push(Pending {
                author,
                endpoint,
                epoch,
                counter,
                revision,
                topic,
                id,
                sequence,
                recipients,
                current,
                payload,
            });
        }
        let count = codec::read_count(input, RECENT_IDS)?;
        let recent = (0..count)
            .map(|_| codec::read_array(input))
            .collect::<Result<_, _>>()?;
        let clock = codec::read_u64(input)?;
        let count = codec::read_count(input, MAX_PENDING_OBJECTS)?;
        let served = (0..count)
            .map(|_| Ok((codec::read_array(input)?, codec::read_u64(input)?)))
            .collect::<Result<_, &'static str>>()?;
        let count = codec::read_count(input, MAX_RECOVERY_SELECTIONS)?;
        let mut progress = Vec::with_capacity(count);
        for _ in 0..count {
            progress.push(SelectionProgress {
                author: codec::read_array(input)?,
                epoch: codec::read_u64(input)?,
                selection: codec::read_array(input)?,
                through: codec::read_u64(input)?,
            });
        }
        let count = codec::read_count(input, current::MAX_CURRENT_SELECTIONS)?;
        let mut current_progress = Vec::with_capacity(count);
        for _ in 0..count {
            current_progress.push(CurrentProgress {
                authority: codec::read_array(input)?,
                revision: codec::read_u64(input)?,
                topic: codec::read_text(input)?,
                selector: codec::read_array(input)?,
                cut: codec::read_u64(input)?,
                digest: codec::read_array(input)?,
            });
        }
        let count = codec::read_count(input, MAX_DIRECT_STREAMS)?;
        let direct = (0..count)
            .map(|_| DirectStream::decode(input))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            workspace,
            epoch,
            replay,
            pending,
            recent,
            clock,
            served,
            progress,
            current_progress,
            direct,
        })
    }
}

pub enum InboxStage {
    Duplicate,
    OutsideWindow,
    Prepared(Box<ObjectInbox>),
}

pub struct PendingObject {
    pub context: PublicationContext,
    pub message: arachne_security::ApplicationMessage,
    /// The author's epoch for this object; with `counter` it is unique.
    pub epoch: u64,
    pub counter: u64,
    pub recipients: Vec<[u8; 32]>,
    pub current: Option<current::CurrentMetadata>,
}

/// A caller-local scheduling hint, never an acknowledgement or rejection.
/// Deferring the entire scope prevents later objects in it from overtaking.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeferredDeliveryStream {
    pub member: [u8; 32],
    pub revision: u64,
    pub topic: String,
    pub recipients: Vec<[u8; 32]>,
}

impl From<&PendingObject> for DeferredDeliveryStream {
    fn from(pending: &PendingObject) -> Self {
        Self {
            member: pending.message.member,
            revision: pending.context.revision,
            topic: pending.context.topic.as_str().to_owned(),
            recipients: pending.recipients.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectGap {
    pub author: [u8; 32],
    pub revision: u64,
    pub topic: Topic,
    pub recipients: Vec<[u8; 32]>,
    pub after: u64,
    pub through: u64,
}

fn audience_aad(
    owner: &arachne_security::Workspace,
    context: &PublicationContext,
    recipients: &[[u8; 32]],
) -> Result<Vec<u8>, &'static str> {
    if recipients.is_empty() {
        context
            .sequence
            .ok_or("object publication requires sequence")?;
        Ok(context.authenticated_bytes())
    } else {
        let aad = context.direct_authenticated_bytes(recipients)?;
        if !recipients.contains(&owner.member().ok_or("member required")?.id()) {
            return Err("object audience excludes local member");
        }
        Ok(aad)
    }
}

fn receipt_aad(
    owner: &arachne_security::Workspace,
    context: &PublicationContext,
    recipients: &[[u8; 32]],
    current: Option<&CurrentReceipt>,
) -> Result<Vec<u8>, &'static str> {
    match current {
        Some(current) if recipients.is_empty() => {
            Ok(current::CurrentMetadata::from(current).authenticated_context(context))
        }
        Some(_) => Err("current value cannot have direct recipients"),
        None => audience_aad(owner, context, recipients),
    }
}

impl ObjectInbox {
    pub fn new(workspace: [u8; 32], epoch: u64) -> Self {
        Self {
            workspace,
            epoch,
            replay: Vec::new(),
            pending: Vec::new(),
            recent: VecDeque::new(),
            clock: 0,
            served: Vec::new(),
            retained_ranges: Vec::new(),
            retained_current_views: Vec::new(),
            current: None,
            progress: Vec::new(),
            current_progress: Vec::new(),
            direct: Vec::new(),
            missed: 0,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Carry delivery state across an accepted membership step from
    /// `previous` to `next`. Pending objects are kept: they are already
    /// authenticated plaintext. Replay windows, recovery progress, retained
    /// ranges and direct recovery copies are kept for epochs inside `next`'s
    /// receive window. Current views are per epoch and start empty. Save the
    /// result with `next` before adoption.
    pub fn advance(
        &self,
        previous: &arachne_security::Workspace,
        next: &arachne_security::Workspace,
    ) -> Result<Self, &'static str> {
        self.validate_owner(previous)?;
        if next.id() != self.workspace || next.epoch() <= self.epoch {
            return Err("inbox cannot advance to this owner");
        }
        let oldest = next.oldest_receive_epoch();
        let member = |id: &[u8; 32]| next.endpoints_for_members(&[*id]).is_ok();
        let before: BTreeSet<_> = previous.member_endpoints()?.into_iter().collect();
        let admits = next
            .member_endpoints()?
            .iter()
            .any(|endpoint| !before.contains(endpoint));
        let mut advanced = self.clone();
        advanced.epoch = next.epoch();
        advanced.replay.retain(|replay| replay.epoch >= oldest);
        advanced.progress.retain(|progress| progress.epoch >= oldest);
        // Retained third-party ranges: only from current members, and none
        // from before a join (a holder never serves pre-join history).
        advanced.retained_ranges.retain(|range| {
            RangeQuery::from_wire(&range.query).is_ok_and(|query| {
                query.epoch >= oldest
                    && member(&query.author)
                    && (!admits || query.epoch >= next.epoch())
            })
        });
        advanced.current = None;
        advanced.retained_current_views.clear();
        advanced.current_progress.clear();
        let mut missed = 0;
        for stream in &mut advanced.direct {
            while let Some(record) = stream.records.first() {
                if arachne_security::object_epoch(&record.object).is_some_and(|epoch| epoch >= oldest)
                {
                    break;
                }
                // B7f-2: copies that left the receive window move the floor
                // past any gap before them; those sequences are missed, as
                // on an eviction (B7e).
                missed += stream.evict_first();
            }
        }
        advanced.missed = advanced.missed.saturating_add(missed);
        // A direct scope that names a removed member ends: its copies can no
        // longer be authenticated or served to that audience.
        advanced.direct.retain(|stream| {
            (!stream.records.is_empty() || stream.known_head != 0)
                && member(&stream.author)
                && stream.recipients.iter().all(member)
        });
        advanced.snapshot()?;
        Ok(advanced)
    }

    /// Move to a winning branch (ADR A2 step 8). `current` is the owner on
    /// the losing branch, `fork_epoch` the fork epoch F, `next` the owner
    /// after the winning steps. The epoch numbers above F exist on both
    /// branches with different keys, so every per-epoch record above F is
    /// dropped: a replay window from the losing epoch F+1 would otherwise
    /// refuse the winning epoch F+1's objects. Pending objects are
    /// authenticated plaintext and stay. Save the result with `next`.
    pub fn rebase(
        &self,
        current: &arachne_security::Workspace,
        fork_epoch: u64,
        next: &arachne_security::Workspace,
    ) -> Result<Self, &'static str> {
        self.validate_owner(current)?;
        if next.id() != self.workspace || fork_epoch >= current.epoch() || next.epoch() <= fork_epoch
        {
            return Err("inbox cannot rebase to this owner");
        }
        let oldest = next.oldest_receive_epoch();
        let kept = |epoch: u64| epoch >= oldest && epoch <= fork_epoch;
        let member = |id: &[u8; 32]| next.endpoints_for_members(&[*id]).is_ok();
        let mut moved = self.clone();
        moved.epoch = next.epoch();
        moved.replay.retain(|replay| kept(replay.epoch));
        moved.progress.retain(|progress| kept(progress.epoch));
        moved.retained_ranges.retain(|range| {
            RangeQuery::from_wire(&range.query)
                .is_ok_and(|query| kept(query.epoch) && member(&query.author))
        });
        moved.current = None;
        moved.retained_current_views.clear();
        moved.current_progress.clear();
        for stream in &mut moved.direct {
            stream.records.retain(|record| {
                arachne_security::object_epoch(&record.object).is_some_and(kept)
            });
        }
        moved.direct.retain(|stream| {
            (!stream.records.is_empty() || stream.known_head != 0)
                && member(&stream.author)
                && stream.recipients.iter().all(member)
        });
        moved.snapshot()?;
        Ok(moved)
    }

    /// Direct sequences given up as missed since this inbox was created or
    /// restored: a record window overflow moved a scope floor past a gap
    /// (B7e). The difference between a staged candidate and the current state
    /// is the misses of that step.
    pub fn missed_direct(&self) -> u64 {
        self.missed
    }

    pub fn recovery_progress(&self, author: [u8; 32], epoch: u64, topics: &BTreeSet<Topic>) -> u64 {
        let selection = selection_digest(topics);
        self.progress
            .iter()
            .find(|progress| {
                progress.author == author
                    && progress.epoch == epoch
                    && progress.selection == selection
            })
            .map_or(0, |progress| progress.through)
    }

    /// Add or replace one publisher-owned latest value. The returned inbox must
    /// be saved atomically with the already protected publication and owner.
    /// `expires_at` is in `UnixSeconds`.
    #[allow(clippy::too_many_arguments)]
    pub fn stage_current(
        &self,
        owner: &arachne_security::Workspace,
        context: PublicationContext,
        selector: [u8; 32],
        replacement_key: [u8; 32],
        expires_at: u64,
        tombstone: bool,
        packet: Vec<u8>,
        now: UnixSeconds,
    ) -> Result<Self, &'static str> {
        self.validate_owner(owner)?;
        let authority = owner.member().ok_or("member required")?.id();
        let mut next = self.clone();
        next.current
            .get_or_insert_with(|| {
                Box::new(current::CurrentViewIndex::new(
                    owner.id(),
                    authority,
                    owner.epoch(),
                ))
            })
            .insert(
                context,
                selector,
                replacement_key,
                expires_at,
                tombstone,
                packet,
                now,
            )?;
        next.snapshot()?;
        Ok(next)
    }

    pub fn serve_current(
        &self,
        owner: &arachne_security::Workspace,
        policy: &arachne_routing::RoutingTable,
        requester: [u8; 32],
        query: &current::CurrentViewQuery,
        now: UnixSeconds,
    ) -> Result<Vec<u8>, &'static str> {
        self.validate_owner(owner)?;
        if let Some(index) = &self.current {
            let reply = index.serve(owner, policy, requester, query)?;
            if reply != current::CurrentView::denied_wire() {
                return Ok(reply);
            }
        }
        let topics = BTreeSet::from([query.topic.clone()]);
        if query.workspace != self.workspace
            || query.epoch != self.epoch
            || super::authorize_history(
                owner,
                policy,
                requester,
                query.authority,
                query.policy_revision,
                &topics,
            )
            .is_err()
        {
            return Ok(current::CurrentView::denied_wire());
        }
        let encoded = query.to_wire()?;
        let Some(view) = self
            .retained_current_views
            .iter()
            .find(|view| view.query == encoded && now.before_remote_expiry(view.expires_at))
        else {
            return Ok(current::CurrentView::denied_wire());
        };
        current::verify_wire_reply(owner, query, &view.reply)?
            .ok_or("retained current view is invalid")?;
        Ok(view.reply.clone())
    }

    /// Verify and stage one exact current view. Coverage advances only in the
    /// returned candidate, which the host saves before exposing pending values.
    pub fn accept_current_view(
        &self,
        owner: &arachne_security::Workspace,
        query: &current::CurrentViewQuery,
        reply: &[u8],
        now: UnixSeconds,
    ) -> Result<(Self, usize, usize), &'static str> {
        self.validate_owner(owner)?;
        let view =
            current::verify_wire_reply(owner, query, reply)?.ok_or("current view unavailable")?;
        let digest: [u8; 32] = Sha256::digest(reply).into();
        let key = (
            query.authority,
            query.policy_revision,
            query.topic.as_str(),
            query.selector,
        );
        let position = self.current_progress.iter().position(|progress| {
            (
                progress.authority,
                progress.revision,
                progress.topic.as_str(),
                progress.selector,
            ) == key
        });
        if let Some(progress) = position.map(|index| &self.current_progress[index]) {
            if view.cut < progress.cut {
                return Err("current-view rollback");
            }
            if view.cut == progress.cut {
                return if digest == progress.digest {
                    Ok((self.clone(), 0, 0))
                } else {
                    Err("conflicting current view")
                };
            }
        } else if self.current_progress.len() == current::MAX_CURRENT_SELECTIONS {
            return Err("current-view selection capacity exhausted");
        }
        let expected_endpoint = owner.endpoints_for_members(&[query.authority])?[0];
        let mut next = self.clone();
        let mut pending = 0;
        let mut stale = 0;
        for value in &view.values {
            // The authority's clock set the expiry: allow clock skew.
            if !now.before_remote_expiry(value.expires_at) {
                stale += 1;
                continue;
            }
            let (context, ciphertext) = PublicationContext::unpack(
                query.workspace,
                query.policy_revision,
                query.topic.clone(),
                &value.packet,
            )?;
            let metadata = current::CurrentMetadata {
                selector: query.selector,
                replacement_key: value.replacement_key,
                expires_at: value.expires_at,
                tombstone: value.tombstone,
            };
            let authenticated = owner.unprotect_object(
                context.topic.namespace().as_bytes(),
                &metadata.authenticated_context(&context),
                ciphertext,
            )?;
            if authenticated.message.member != query.authority
                || authenticated.message.endpoint != expected_endpoint
            {
                return Err("current-view value has wrong author");
            }
            match next.stage_live_current(owner, &context, metadata, ciphertext)? {
                InboxStage::Prepared(candidate) => {
                    next = *candidate;
                    pending += 1;
                }
                InboxStage::Duplicate => {}
                InboxStage::OutsideWindow => return Err("current value outside receive window"),
            }
        }
        let progress = CurrentProgress {
            authority: query.authority,
            revision: query.policy_revision,
            topic: query.topic.as_str().into(),
            selector: query.selector,
            cut: view.cut,
            digest,
        };
        if let Some(index) = position {
            next.current_progress[index] = progress;
        } else {
            next.current_progress.push(progress);
            next.current_progress.sort_by(|a, b| {
                (a.authority, a.revision, &a.topic, a.selector).cmp(&(
                    b.authority,
                    b.revision,
                    &b.topic,
                    b.selector,
                ))
            });
        }
        next.snapshot()?;
        Ok((next, pending, stale))
    }

    /// Accept only contiguous progress from the exact publisher-signed range.
    /// The returned candidate must be saved with the workspace before adoption.
    pub fn accept_recovery_coverage(
        &self,
        owner: &arachne_security::Workspace,
        query: &RangeQuery,
        reply: &[u8],
    ) -> Result<Self, &'static str> {
        self.accept_recovery_prefix(owner, query, reply, query.through)
    }

    /// Accept progress through `through` inside one verified publisher-signed
    /// range (B7b). The signature covers the whole range, so every record with
    /// a sequence at or below `through` is the complete prefix. The caller
    /// passes the last sequence it admitted or found duplicate; records above
    /// it were not recorded and come again by a later request.
    pub fn accept_recovery_prefix(
        &self,
        owner: &arachne_security::Workspace,
        query: &RangeQuery,
        reply: &[u8],
        through: u64,
    ) -> Result<Self, &'static str> {
        self.validate_owner(owner)?;
        if through <= query.after || through > query.through {
            return Err("recovery progress outside the signed range");
        }
        if query.workspace != self.workspace || !owner.in_receive_window(query.epoch) {
            return Err("recovery coverage has wrong workspace or epoch");
        }
        if !matches!(
            wire::verify_reply(owner, query, reply)?,
            wire::RangeReply::Offered(_)
        ) {
            return Err("only an authenticated range can advance recovery");
        }
        let selection = selection_digest(&query.topics);
        let position = self.progress.iter().position(|progress| {
            progress.author == query.author
                && progress.epoch == query.epoch
                && progress.selection == selection
        });
        let current = position.map_or(0, |index| self.progress[index].through);
        if through <= current {
            return Ok(self.clone());
        }
        if query.after != current {
            return Err("recovery range does not continue accepted progress");
        }
        if position.is_none() && self.progress.len() == MAX_RECOVERY_SELECTIONS {
            return Err("recovery selection capacity exhausted");
        }
        let mut next = self.clone();
        if let Some(index) = position {
            next.progress[index].through = through;
        } else {
            next.progress.push(SelectionProgress {
                author: query.author,
                epoch: query.epoch,
                selection,
                through,
            });
            next.progress
                .sort_by_key(|progress| (progress.author, progress.epoch, progress.selection));
        }
        next.snapshot()?;
        Ok(next)
    }

    fn validate_owner(&self, owner: &arachne_security::Workspace) -> Result<(), &'static str> {
        if self.workspace != owner.id() || self.epoch != owner.epoch() {
            return Err("inbox epoch/workspace not current");
        }
        Ok(())
    }

    fn context(&self, pending: &Pending) -> Result<PublicationContext, &'static str> {
        Ok(PublicationContext {
            workspace: self.workspace,
            revision: pending.revision,
            topic: Topic::new(pending.topic.clone()).map_err(|_| "invalid inbox topic")?,
            id: pending.id,
            sequence: std::num::NonZeroU64::new(pending.sequence),
        })
    }

    /// Caller must already have checked routing authorization and current local
    /// subscription. Returned candidates contain no application callback.
    pub fn stage(
        &self,
        owner: &arachne_security::Workspace,
        context: &PublicationContext,
        object: &[u8],
    ) -> Result<InboxStage, &'static str> {
        self.stage_with_recipients(owner, context, &[], object)
    }

    /// Preserve an authenticated audience in this recipient's local inbox.
    /// This is not publisher retention or authorization to serve other peers.
    pub fn stage_with_recipients(
        &self,
        owner: &arachne_security::Workspace,
        context: &PublicationContext,
        recipients: &[[u8; 32]],
        object: &[u8],
    ) -> Result<InboxStage, &'static str> {
        self.stage_scoped(owner, context, recipients, None, object)
    }

    pub fn stage_live_current(
        &self,
        owner: &arachne_security::Workspace,
        context: &PublicationContext,
        metadata: current::CurrentMetadata,
        object: &[u8],
    ) -> Result<InboxStage, &'static str> {
        self.stage_scoped(owner, context, &[], Some(metadata.into()), object)
    }

    fn stage_scoped(
        &self,
        owner: &arachne_security::Workspace,
        context: &PublicationContext,
        recipients: &[[u8; 32]],
        current: Option<CurrentReceipt>,
        object: &[u8],
    ) -> Result<InboxStage, &'static str> {
        self.validate_owner(owner)?;
        if context.workspace != self.workspace {
            return Err("wrong inbox workspace");
        }
        let sequence = context.sequence.map_or(0, |n| n.get());
        let aad = receipt_aad(owner, context, recipients, current.as_ref())?;
        let authenticated =
            owner.unprotect_object(context.topic.namespace().as_bytes(), &aad, object)?;
        let author = authenticated.message.member;
        let counter = authenticated.counter;
        let epoch = authenticated.epoch;
        let position = self
            .replay
            .iter()
            .position(|replay| replay.author == author && replay.epoch == epoch);
        if let Some(index) = position {
            match self.replay[index].state(counter) {
                ReplayState::Duplicate => return Ok(InboxStage::Duplicate),
                ReplayState::Lost => return Ok(InboxStage::OutsideWindow),
                ReplayState::New => {}
            }
        } else if self.replay.len() == MAX_REPLAY_WINDOWS {
            return Err("inbox replay capacity exhausted");
        }
        let identity = publication_identity(author, context.id);
        if self.recent.contains(&identity) {
            return Ok(InboxStage::Duplicate);
        }
        // B7e: a direct sequence at or below its scope floor was accepted or
        // given up as missed. A late copy is dropped, never delivered after
        // newer objects of the scope.
        if !recipients.is_empty()
            && sequence != 0
            && self.direct.iter().any(|stream| {
                stream.author == author
                    && stream.revision == context.revision
                    && stream.topic == context.topic.as_str()
                    && stream.recipients == recipients
                    && stream.closed(sequence)
            })
        {
            return Ok(InboxStage::Duplicate);
        }
        // Never discard an undelivered object to make room. The object is not
        // recorded, so it can come again (live or by recovery) after the
        // application drains work. One author cannot use up everyone's space.
        // The author is charged the encoded size, metadata included.
        let size = Pending::weight(
            context.topic.as_str().len(),
            recipients.len(),
            current.is_some(),
            authenticated.message.payload.len(),
        );
        let (author_objects, author_bytes) = self
            .pending
            .iter()
            .filter(|pending| pending.author == author)
            .fold((0, 0), |(count, bytes), pending| {
                (count + 1, bytes + pending.encoded_len())
            });
        if (author_objects >= MAX_PENDING_OBJECTS_PER_AUTHOR
            || author_bytes + size > MAX_PENDING_BYTES_PER_AUTHOR)
            && !self.fills_blocking_gap(author, context, recipients)
        {
            return Err(AUTHOR_QUOTA_EXHAUSTED);
        }
        let total: usize = self.pending.iter().map(Pending::encoded_len).sum();
        if self.pending.len() == MAX_PENDING_OBJECTS || total + size > MAX_PENDING_BYTES {
            return Err(PENDING_INBOX_FULL);
        }
        let mut next = self.clone();
        let index = position.unwrap_or_else(|| {
            next.replay.push(Replay {
                author,
                epoch,
                lost_through: 0,
                floor: 0,
                seen: BTreeSet::new(),
            });
            next.replay.len() - 1
        });
        next.replay[index].accept(counter);
        next.recent.push_back(identity);
        if next.recent.len() > RECENT_IDS {
            next.recent.pop_front();
        }
        next.pending.push(Pending {
            author,
            endpoint: authenticated.message.endpoint,
            epoch,
            counter,
            revision: context.revision,
            topic: context.topic.as_str().into(),
            id: context.id,
            sequence,
            recipients: recipients.to_vec(),
            current,
            payload: authenticated.message.payload,
        });
        if !recipients.is_empty() && context.sequence.is_some() {
            next.retain_direct(author, context, recipients, object)?;
        }
        next.snapshot()?; // Enforce encoded-byte bound before returning a candidate.
        Ok(InboxStage::Prepared(Box::new(next)))
    }

    /// Assign the next sequence inside one explicit recipient scope. Group and
    /// unrelated private traffic cannot create a false gap in this stream.
    pub fn next_direct_sequence(
        &self,
        owner: &arachne_security::Workspace,
        revision: u64,
        topic: &Topic,
        recipients: &[[u8; 32]],
    ) -> Result<std::num::NonZeroU64, &'static str> {
        self.validate_owner(owner)?;
        owner.endpoints_for_members(recipients)?;
        let author = owner.member().ok_or("member required")?.id();
        let head = self
            .direct
            .iter()
            .find(|stream| {
                stream.author == author
                    && stream.revision == revision
                    && stream.topic == topic.as_str()
                    && stream.recipients == recipients
            })
            .map(DirectStream::effective_head)
            .unwrap_or(0);
        std::num::NonZeroU64::new(head.checked_add(1).ok_or("direct sequence exhausted")?)
            .ok_or("direct sequence exhausted")
    }

    /// Retain the sender's exact signed object without presenting it back to the
    /// local application. Only members named in the audience can receive/serve it.
    pub fn stage_sent_direct(
        &self,
        owner: &arachne_security::Workspace,
        context: &PublicationContext,
        recipients: &[[u8; 32]],
        object: &[u8],
    ) -> Result<Self, &'static str> {
        self.validate_owner(owner)?;
        if recipients.contains(&owner.member().ok_or("member required")?.id()) {
            return Err("direct sender cannot be a recipient");
        }
        owner.endpoints_for_members(recipients)?;
        let authenticated = owner.unprotect_object(
            context.topic.namespace().as_bytes(),
            &context.direct_authenticated_bytes(recipients)?,
            object,
        )?;
        if authenticated.message.member != owner.member().unwrap().id()
            || authenticated.message.endpoint != owner.endpoint()
        {
            return Err("direct recovery author mismatch");
        }
        let mut next = self.clone();
        next.retain_direct(authenticated.message.member, context, recipients, object)?;
        next.snapshot()?;
        Ok(next)
    }

    /// Return the earliest known hole followed by a signed later publication.
    /// A missing tail with no observed cutoff remains unknown, never invented.
    pub fn next_direct_gap(
        &self,
        owner: &arachne_security::Workspace,
    ) -> Result<Option<DirectGap>, &'static str> {
        self.validate_owner(owner)?;
        let member = owner.member().ok_or("member required")?.id();
        for stream in &self.direct {
            if !stream.recipients.contains(&member) {
                continue;
            }
            let mut expected = stream.floor.max(stream.recovery_floor).saturating_add(1);
            for record in &stream.records {
                if record.sequence > expected {
                    let after = expected - 1;
                    return Ok(Some(DirectGap {
                        author: stream.author,
                        revision: stream.revision,
                        topic: Topic::new(stream.topic.clone())
                            .map_err(|_| "invalid direct topic")?,
                        recipients: stream.recipients.clone(),
                        after,
                        through: record
                            .sequence
                            .min(after.saturating_add(MAX_RECOVERY_PACKETS as u64)),
                    }));
                }
                if record.sequence == expected {
                    expected = expected.checked_add(1).ok_or("direct sequence exhausted")?;
                }
            }
            if stream.effective_head() >= expected {
                let after = expected - 1;
                return Ok(Some(DirectGap {
                    author: stream.author,
                    revision: stream.revision,
                    topic: Topic::new(stream.topic.clone()).map_err(|_| "invalid direct topic")?,
                    recipients: stream.recipients.clone(),
                    after,
                    through: stream
                        .effective_head()
                        .min(after.saturating_add(MAX_RECOVERY_PACKETS as u64)),
                }));
            }
        }
        Ok(None)
    }

    /// Heads are advisory gap triggers sent only to their intended audience.
    /// Recovered objects still carry the original author's cryptographic proof.
    pub fn direct_heads_for(
        &self,
        owner: &arachne_security::Workspace,
        recipient: [u8; 32],
    ) -> Result<Vec<wire::DirectHead>, &'static str> {
        self.validate_owner(owner)?;
        owner.endpoints_for_members(&[recipient])?;
        let mut heads = self
            .direct
            .iter()
            .filter(|stream| stream.recipients.contains(&recipient))
            .map(|stream| {
                Ok(wire::DirectHead {
                    workspace: self.workspace,
                    author: stream.author,
                    epoch: self.epoch,
                    policy_revision: stream.revision,
                    topic: Topic::new(stream.topic.clone()).map_err(|_| "invalid direct topic")?,
                    recipients: stream.recipients.clone(),
                    through: stream.effective_head(),
                })
            })
            .collect::<Result<Vec<_>, &'static str>>()?;
        heads.sort_by(|a, b| {
            (a.author, a.policy_revision, &a.topic, &a.recipients).cmp(&(
                b.author,
                b.policy_revision,
                &b.topic,
                &b.recipients,
            ))
        });
        Ok(heads)
    }

    pub fn stage_direct_head(
        &self,
        owner: &arachne_security::Workspace,
        announcer: [u8; 32],
        head: &wire::DirectHead,
    ) -> Result<Option<Self>, &'static str> {
        self.validate_owner(owner)?;
        let local = owner.member().ok_or("member required")?.id();
        let announcer = owner.member_id_for_endpoint(announcer)?;
        head.to_wire()?;
        if head.workspace != self.workspace
            || !owner.in_receive_window(head.epoch)
            || !head.recipients.contains(&local)
            || (announcer != head.author && !head.recipients.contains(&announcer))
        {
            return Err("direct head is outside authenticated audience");
        }
        owner.endpoints_for_members(&head.recipients)?;
        let mut next = self.clone();
        let position = next.direct.iter().position(|stream| {
            stream.author == head.author
                && stream.revision == head.policy_revision
                && stream.topic == head.topic.as_str()
                && stream.recipients == head.recipients
        });
        let index = match position {
            Some(index) if next.direct[index].effective_head() >= head.through => return Ok(None),
            Some(index) => index,
            None => {
                if next.direct.len() == MAX_DIRECT_STREAMS {
                    return Err("direct recovery stream capacity exhausted");
                }
                next.direct.push(DirectStream {
                    author: head.author,
                    revision: head.policy_revision,
                    topic: head.topic.as_str().into(),
                    recipients: head.recipients.clone(),
                    floor: 0,
                    recovery_floor: 0,
                    known_head: 0,
                    records: Vec::new(),
                });
                next.direct.len() - 1
            }
        };
        next.direct[index].known_head = head.through;
        next.snapshot()?;
        Ok(Some(next))
    }

    fn retain_direct(
        &mut self,
        author: [u8; 32],
        context: &PublicationContext,
        recipients: &[[u8; 32]],
        object: &[u8],
    ) -> Result<(), &'static str> {
        let sequence = context
            .sequence
            .ok_or("direct recovery requires sequence")?
            .get();
        let position = self.direct.iter().position(|stream| {
            stream.author == author
                && stream.revision == context.revision
                && stream.topic == context.topic.as_str()
                && stream.recipients == recipients
        });
        let index = match position {
            Some(index) => index,
            None => {
                if self.direct.len() == MAX_DIRECT_STREAMS {
                    return Err("direct recovery stream capacity exhausted");
                }
                self.direct.push(DirectStream {
                    author,
                    revision: context.revision,
                    topic: context.topic.as_str().into(),
                    recipients: recipients.to_vec(),
                    floor: 0,
                    recovery_floor: 0,
                    known_head: 0,
                    records: Vec::new(),
                });
                self.direct.len() - 1
            }
        };
        let stream = &mut self.direct[index];
        if let Some(known) = stream
            .records
            .iter()
            .find(|record| record.sequence == sequence)
        {
            if known.revision == context.revision
                && known.id == context.id
                && known.object == object
            {
                return Ok(());
            }
            return Err("conflicting direct recovery sequence");
        }
        if stream.records.iter().any(|record| record.id == context.id) {
            return Err("direct recovery identity reused");
        }
        stream.records.push(DirectRecord {
            revision: context.revision,
            id: context.id,
            sequence,
            object: object.to_vec(),
        });
        stream.records.sort_by_key(|record| record.sequence);
        stream.known_head = stream.known_head.max(sequence);
        if stream.records.len() > DIRECT_WINDOW {
            self.missed += stream.evict_first();
        }
        // The encoded size is the persisted byte budget.
        while self.direct.iter().map(DirectStream::encoded_len).sum::<usize>()
            > MAX_DIRECT_RETAINED_BYTES
        {
            let stream = self
                .direct
                .iter_mut()
                .filter(|stream| !stream.records.is_empty())
                .max_by_key(|stream| {
                    stream
                        .records
                        .iter()
                        .map(|record| record.object.len())
                        .sum::<usize>()
                })
                .ok_or("direct recovery metadata capacity exhausted")?;
            self.missed += stream.evict_first();
        }
        Ok(())
    }

    pub fn serve_direct_range(
        &self,
        owner: &arachne_security::Workspace,
        policy: &arachne_routing::RoutingTable,
        requester: [u8; 32],
        query: &wire::DirectRangeQuery,
    ) -> Result<Vec<u8>, &'static str> {
        self.validate_owner(owner)?;
        let requester_member = owner.member_id_for_endpoint(requester).ok();
        let holder = owner.member().ok_or("member required")?.id();
        let topics = BTreeSet::from([query.topic.clone()]);
        if query.workspace != self.workspace
            || !owner.in_receive_window(query.epoch)
            || !query
                .recipients
                .contains(&requester_member.unwrap_or([0; 32]))
            || (holder != query.author && !query.recipients.contains(&holder))
            || super::authorize_history(
                owner,
                policy,
                requester,
                query.author,
                query.policy_revision,
                &topics,
            )
            .is_err()
        {
            return Ok(wire::unavailable_direct_reply());
        }
        let Some(stream) = self.direct.iter().find(|stream| {
            stream.author == query.author
                && stream.revision == query.policy_revision
                && stream.topic == query.topic.as_str()
                && stream.recipients == query.recipients
        }) else {
            return Ok(wire::unavailable_direct_reply());
        };
        if query.after < stream.floor {
            return Ok(wire::unavailable_direct_reply());
        }
        let records: Vec<_> = stream
            .records
            .iter()
            .filter(|record| record.sequence > query.after && record.sequence <= query.through)
            .map(|record| {
                (
                    record.revision,
                    record.id,
                    record.sequence,
                    record.object.as_slice(),
                )
            })
            .collect();
        wire::direct_offer(query, records).or_else(|_| Ok(wire::unavailable_direct_reply()))
    }

    pub fn stage_direct_range(
        &self,
        owner: &arachne_security::Workspace,
        query: &wire::DirectRangeQuery,
        reply: &[u8],
    ) -> Result<(Self, usize), &'static str> {
        let packets = match wire::verify_direct_reply(owner, query, reply)? {
            wire::DirectRangeReply::Unavailable => return Err("direct recovery unavailable"),
            wire::DirectRangeReply::Offered(packets) => packets,
        };
        let mut next = self.clone();
        let mut count = 0;
        // B7c: the reply is verified whole and holds every sequence in
        // (after, through] in order. Admit the in-order prefix that fits the
        // pending bounds. The first refused record and all after it are not
        // recorded, so the stream keeps its gap from there and
        // `next_direct_gap` asks for the rest after the application drains.
        for packet in packets {
            let staged = next.stage_with_recipients(
                owner,
                &packet.context,
                &query.recipients,
                &packet.ciphertext,
            );
            let staged = match staged {
                // Nothing fits yet: report the refusal, claim nothing.
                Err(error) if drains_with_application(error) && count == 0 => {
                    return Err(error);
                }
                Err(error) if drains_with_application(error) => break,
                staged => staged?,
            };
            match staged {
                InboxStage::Prepared(candidate) => {
                    next = *candidate;
                    count += 1;
                }
                InboxStage::Duplicate => {}
                InboxStage::OutsideWindow => return Err("direct recovery outside receive window"),
            }
        }
        Ok((next, count))
    }

    /// Persist an explicit miss after every authorized source has failed to
    /// supply the range, allowing later samples to resume in order.
    pub fn skip_direct_gap(
        &self,
        owner: &arachne_security::Workspace,
        query: &wire::DirectRangeQuery,
    ) -> Result<(Self, u64), &'static str> {
        self.validate_owner(owner)?;
        let mut next = self.clone();
        let stream = next
            .direct
            .iter_mut()
            .find(|stream| {
                stream.author == query.author
                    && stream.revision == query.policy_revision
                    && stream.topic == query.topic.as_str()
                    && stream.recipients == query.recipients
            })
            .ok_or("unknown direct recovery stream")?;
        let mut expected = stream.floor.max(stream.recovery_floor).saturating_add(1);
        let mut next_record = None;
        for record in &stream.records {
            if record.sequence > expected {
                next_record = Some(record.sequence);
                break;
            }
            if record.sequence == expected {
                expected = expected.checked_add(1).ok_or("direct sequence exhausted")?;
            }
        }
        let after = expected - 1;
        let advertised = next_record.unwrap_or_else(|| stream.effective_head());
        if advertised < expected {
            return Err("direct recovery gap no longer exists");
        }
        let through = advertised.min(after.saturating_add(MAX_RECOVERY_PACKETS as u64));
        if query.after != after || query.through != through {
            return Err("direct recovery gap changed");
        }
        let through_is_present = next_record == Some(through);
        stream.recovery_floor = if through_is_present {
            through - 1
        } else {
            through
        };
        next.snapshot()?;
        Ok((next, through - expected + u64::from(!through_is_present)))
    }

    /// Committed incoming objects still awaiting application acknowledgement,
    /// including objects waiting behind an ordered-delivery gap.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// A direct object waits while an earlier sequence of its scope is missing.
    fn behind_direct_gap(&self, pending: &Pending) -> bool {
        if pending.recipients.is_empty() || pending.sequence == 0 {
            return false;
        }
        self.direct.iter().any(|direct| {
            if direct.author != pending.author
                || direct.revision != pending.revision
                || direct.topic != pending.topic
                || direct.recipients != pending.recipients
            {
                return false;
            }
            let mut expected = direct.floor.max(direct.recovery_floor).saturating_add(1);
            for record in &direct.records {
                if record.sequence > expected {
                    return pending.sequence >= record.sequence;
                }
                if record.sequence == expected {
                    expected = expected.saturating_add(1);
                }
            }
            false
        })
    }

    /// B7c: true when a direct object is the next missing sequence of its
    /// scope and every pending object of its author waits behind a direct gap.
    /// The application can then acknowledge nothing of this author, so the
    /// quota alone would block the gap for good. Such an object may go over the
    /// author quota. Once admitted it is deliverable, so the author has
    /// deliverable work again and the next object meets the quota: the author
    /// is over its quota by one object at most.
    fn fills_blocking_gap(
        &self,
        author: [u8; 32],
        context: &PublicationContext,
        recipients: &[[u8; 32]],
    ) -> bool {
        let Some(sequence) = context.sequence.map(|sequence| sequence.get()) else {
            return false;
        };
        if recipients.is_empty() {
            return false;
        }
        let mut author_pending = self
            .pending
            .iter()
            .filter(|pending| pending.author == author)
            .peekable();
        if author_pending.peek().is_none()
            || !author_pending.all(|pending| self.behind_direct_gap(pending))
        {
            return false;
        }
        let expected = self
            .direct
            .iter()
            .find(|stream| {
                stream.author == author
                    && stream.revision == context.revision
                    && stream.topic == context.topic.as_str()
                    && stream.recipients == recipients
            })
            .map_or(1, |stream| {
                let mut expected = stream.floor.max(stream.recovery_floor).saturating_add(1);
                for record in &stream.records {
                    if record.sequence == expected {
                        expected = expected.saturating_add(1);
                    } else if record.sequence > expected {
                        break;
                    }
                }
                expected
            });
        sequence == expected
    }

    fn same_scope(a: &Pending, b: &Pending) -> bool {
        a.author == b.author
            && a.revision == b.revision
            && a.topic == b.topic
            && a.recipients == b.recipients
    }

    /// Returns authenticated pending work without consuming it. Call repeatedly
    /// after restart until the application has durably accepted it and ack saved.
    pub fn pending(
        &self,
        owner: &arachne_security::Workspace,
    ) -> Result<Option<PendingObject>, &'static str> {
        self.pending_excluding(owner, &[])
    }

    /// Poll without consuming work, skipping only the supplied delivery scopes.
    /// Hints apply to this call only; durable receipts and epoch guards are unchanged.
    pub fn pending_excluding(
        &self,
        owner: &arachne_security::Workspace,
        deferred: &[DeferredDeliveryStream],
    ) -> Result<Option<PendingObject>, &'static str> {
        self.validate_owner(owner)?;
        if deferred.len() > 64 {
            return Err("too many deferred delivery streams");
        }
        for scope in deferred {
            if scope.revision == 0
                || Topic::new(scope.topic.clone()).is_err()
                || scope.recipients.len() > 64
                || scope.recipients.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err("invalid deferred delivery stream");
            }
        }
        let deferred_scope = |pending: &Pending| {
            deferred.iter().any(|scope| {
                scope.member == pending.author
                    && scope.revision == pending.revision
                    && scope.topic == pending.topic
                    && scope.recipients == pending.recipients
            })
        };
        // Round robin: the eligible scope served longest ago goes first (ties:
        // earliest arrival), so one busy author cannot starve the others.
        let Some((_, first)) = self
            .pending
            .iter()
            .enumerate()
            .filter(|(_, pending)| !deferred_scope(pending) && !self.behind_direct_gap(pending))
            .min_by_key(|(arrival, pending)| (self.last_served(pending), *arrival))
        else {
            return Ok(None);
        };
        // Inside one scope, the author's order goes first.
        let chosen = self
            .pending
            .iter()
            .filter(|pending| Self::same_scope(pending, first) && !self.behind_direct_gap(pending))
            .min_by_key(|pending| (pending.epoch, pending.counter))
            .unwrap_or(first);
        Ok(Some(self.pending_object(chosen)?))
    }

    fn scope_key(pending: &Pending) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"arachne/delivery-scope/v1\0");
        hash.update(pending.author);
        hash.update(pending.revision.to_be_bytes());
        hash.update([pending.topic.len() as u8]);
        hash.update(pending.topic.as_bytes());
        for recipient in &pending.recipients {
            hash.update(recipient);
        }
        hash.finalize().into()
    }

    fn last_served(&self, pending: &Pending) -> u64 {
        let key = Self::scope_key(pending);
        self.served
            .iter()
            .find(|(scope, _)| *scope == key)
            .map_or(0, |(_, tick)| *tick)
    }

    fn pending_object(&self, pending: &Pending) -> Result<PendingObject, &'static str> {
        Ok(PendingObject {
            context: self.context(pending)?,
            message: arachne_security::ApplicationMessage {
                member: pending.author,
                endpoint: pending.endpoint,
                payload: pending.payload.clone(),
            },
            epoch: pending.epoch,
            counter: pending.counter,
            recipients: pending.recipients.clone(),
            current: pending.current.as_ref().map(Into::into),
        })
    }

    fn resolve(
        &self,
        author: [u8; 32],
        topic: &Topic,
        counter: u64,
        id: [u8; 16],
    ) -> Result<Self, &'static str> {
        let position = self
            .pending
            .iter()
            .position(|pending| {
                pending.author == author
                    && pending.topic == topic.as_str()
                    && pending.counter == counter
                    && pending.id == id
            })
            .ok_or("unknown pending object")?;
        let mut next = self.clone();
        // The replay window still records the counter: resolved objects are
        // never delivered again.
        let resolved = next.pending.remove(position);
        let key = Self::scope_key(&resolved);
        next.clock = next.clock.checked_add(1).ok_or("service clock exhausted")?;
        next.served.retain(|(scope, _)| *scope != key);
        next.served.push((key, next.clock));
        // Keep ticks only for scopes that still have work.
        let live: BTreeSet<_> = next.pending.iter().map(Self::scope_key).collect();
        next.served.retain(|(scope, _)| live.contains(scope));
        Ok(next)
    }

    /// Stage acknowledgement; save this inbox with the owner/publisher before
    /// forgetting pending work. Duplicate application attempts need the same ID.
    pub fn acknowledge(
        &self,
        author: [u8; 32],
        topic: &Topic,
        counter: u64,
        id: [u8; 16],
    ) -> Result<Self, &'static str> {
        self.resolve(author, topic, counter, id)
    }

    /// Persist permanent application rejection while retaining replay identity.
    pub fn reject(
        &self,
        author: [u8; 32],
        topic: &Topic,
        counter: u64,
        id: [u8; 16],
    ) -> Result<Self, &'static str> {
        self.resolve(author, topic, counter, id)
    }

    /// Retain an exact publisher-signed range after local verification. A holder
    /// may later replay only this request/reply pair; it cannot widen coverage or
    /// replace the original author's signature.
    pub fn retain_range(
        &self,
        owner: &arachne_security::Workspace,
        query: &RangeQuery,
        reply: &[u8],
        expires_at: u64,
        now: UnixSeconds,
    ) -> Result<Self, &'static str> {
        self.validate_owner(owner)?;
        // `expires_at` is this holder's own retention limit: no skew.
        if !now.before_local_expiry(expires_at) {
            return Err("retained range expiry must be in the future");
        }
        if !matches!(
            wire::verify_reply(owner, query, reply)?,
            wire::RangeReply::Offered(_)
        ) {
            return Err("only an authenticated range offer can be retained");
        }
        let encoded = query.to_wire()?;
        let mut next = self.clone();
        next.retained_ranges
            .retain(|range| now.before_local_expiry(range.expires_at));
        if let Some(range) = next
            .retained_ranges
            .iter_mut()
            .find(|range| range.query == encoded)
        {
            range.reply = reply.to_vec();
            range.expires_at = expires_at;
        } else {
            if next.retained_ranges.len() == MAX_RETAINED_RANGES {
                let oldest = next
                    .retained_ranges
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, range)| range.expires_at)
                    .map(|(index, _)| index)
                    .unwrap();
                next.retained_ranges.remove(oldest);
            }
            next.retained_ranges.push(RetainedRange {
                query: encoded,
                reply: reply.to_vec(),
                expires_at,
            });
        }
        next.retained_ranges.sort_by(|a, b| a.query.cmp(&b.query));
        next.trim_proofs()?;
        next.snapshot()?;
        Ok(next)
    }

    /// Retain one exact authority-signed view only while at least one signed
    /// value remains fresh. Empty or fully stale views cannot become replayed
    /// claims that a disconnected authority still has no current value.
    pub fn retain_current_view(
        &self,
        owner: &arachne_security::Workspace,
        query: &current::CurrentViewQuery,
        reply: &[u8],
        now: UnixSeconds,
    ) -> Result<Self, &'static str> {
        self.validate_owner(owner)?;
        // The authority's clock set these expiries: allow clock skew.
        let expires_at = current::verify_wire_reply(owner, query, reply)?
            .ok_or("only an authenticated current view can be retained")?
            .values
            .iter()
            .map(|value| value.expires_at)
            .max()
            .filter(|expires_at| now.before_remote_expiry(*expires_at))
            .ok_or("current view has no fresh value")?;
        let encoded = query.to_wire()?;
        let mut next = self.clone();
        next.retained_current_views
            .retain(|view| now.before_remote_expiry(view.expires_at));
        if let Some(view) = next
            .retained_current_views
            .iter_mut()
            .find(|view| view.query == encoded)
        {
            view.reply = reply.to_vec();
            view.expires_at = expires_at;
        } else {
            // Same rule as retained ranges: the view that expires first
            // gives way.
            if next.retained_current_views.len() == MAX_RETAINED_CURRENT_VIEWS {
                let oldest = next
                    .retained_current_views
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, view)| view.expires_at)
                    .map(|(index, _)| index)
                    .unwrap();
                next.retained_current_views.remove(oldest);
            }
            next.retained_current_views.push(RetainedCurrentView {
                query: encoded,
                reply: reply.to_vec(),
                expires_at,
            });
        }
        next.retained_current_views
            .sort_by(|a, b| a.query.cmp(&b.query));
        next.trim_proofs()?;
        next.snapshot()?;
        Ok(next)
    }

    /// Keep retained proofs inside their byte budget: the proof (range or
    /// current view) that expires first is evicted.
    fn trim_proofs(&mut self) -> Result<(), &'static str> {
        loop {
            let bytes: usize = self
                .retained_ranges
                .iter()
                .map(|range| range.query.len() + range.reply.len() + 16)
                .chain(
                    self.retained_current_views
                        .iter()
                        .map(|view| view.query.len() + view.reply.len() + 16),
                )
                .sum();
            if bytes <= MAX_RETAINED_PROOF_BYTES {
                return Ok(());
            }
            let range = self
                .retained_ranges
                .iter()
                .enumerate()
                .min_by_key(|(_, range)| range.expires_at)
                .map(|(index, range)| (range.expires_at, index));
            let view = self
                .retained_current_views
                .iter()
                .enumerate()
                .min_by_key(|(_, view)| view.expires_at)
                .map(|(index, view)| (view.expires_at, index));
            match (range, view) {
                (Some(range), Some(view)) if view.0 < range.0 => {
                    self.retained_current_views.remove(view.1);
                }
                (Some(range), _) => {
                    self.retained_ranges.remove(range.1);
                }
                (None, Some(view)) => {
                    self.retained_current_views.remove(view.1);
                }
                (None, None) => return Err("retained proof exceeds budget"),
            }
        }
    }

    /// Serve only a still-current exact proof to a currently authorized reader.
    /// Missing and expired copies are reported as unavailable, never complete.
    pub fn serve_range(
        &self,
        owner: &arachne_security::Workspace,
        policy: &arachne_routing::RoutingTable,
        requester: [u8; 32],
        query: &RangeQuery,
        now: UnixSeconds,
    ) -> Result<Vec<u8>, &'static str> {
        self.validate_owner(owner)?;
        if query.workspace != self.workspace || !owner.in_receive_window(query.epoch) {
            return Ok(wire::denied_reply());
        }
        if super::authorize_history(
            owner,
            policy,
            requester,
            query.author,
            query.policy_revision,
            &query.topics,
        )
        .is_err()
        {
            return Ok(wire::denied_reply());
        }
        let encoded = query.to_wire()?;
        let Some(range) = self
            .retained_ranges
            .iter()
            .find(|range| range.query == encoded && now.before_local_expiry(range.expires_at))
        else {
            return Ok(wire::unavailable_reply());
        };
        if !matches!(
            wire::verify_reply(owner, query, &range.reply)?,
            wire::RangeReply::Offered(_)
        ) {
            return Err("retained range proof is invalid");
        }
        Ok(range.reply.clone())
    }

    /// Offer the furthest still-current exact author-signed range that starts at
    /// the requester's durable cursor. The holder cannot alter its coverage.
    pub fn serve_available_range(
        &self,
        owner: &arachne_security::Workspace,
        policy: &arachne_routing::RoutingTable,
        requester: [u8; 32],
        request: &wire::AvailableRangeQuery,
        now: UnixSeconds,
    ) -> Result<Vec<u8>, &'static str> {
        self.validate_owner(owner)?;
        if request.workspace != self.workspace || !owner.in_receive_window(request.epoch) {
            return Ok(wire::unavailable_available_reply());
        }
        if super::authorize_history(
            owner,
            policy,
            requester,
            request.author,
            request.policy_revision,
            &request.topics,
        )
        .is_err()
        {
            return Ok(wire::unavailable_available_reply());
        }
        let candidate = self
            .retained_ranges
            .iter()
            .filter(|range| now.before_local_expiry(range.expires_at))
            .filter_map(|range| {
                RangeQuery::from_wire(&range.query)
                    .ok()
                    .map(|query| (range, query))
            })
            .filter(|(_, query)| request.matches(query))
            .max_by_key(|(_, query)| query.through);
        let Some((range, query)) = candidate else {
            return Ok(wire::unavailable_available_reply());
        };
        if !matches!(
            wire::verify_reply(owner, &query, &range.reply)?,
            wire::RangeReply::Offered(_)
        ) {
            return Err("retained range proof is invalid");
        }
        wire::available_offer(&query, &range.reply)
    }

    fn snapshot(&self) -> Result<Vec<u8>, &'static str> {
        let mut bytes = CACHE_MAGIC.to_vec();
        Snapshot::encode(self, &mut bytes);
        bytes.push(self.retained_ranges.len() as u8);
        for range in &self.retained_ranges {
            bytes.extend(range.expires_at.to_be_bytes());
            bytes.extend((range.query.len() as u32).to_be_bytes());
            bytes.extend(&range.query);
            bytes.extend((range.reply.len() as u32).to_be_bytes());
            bytes.extend(&range.reply);
        }
        bytes.push(self.retained_current_views.len() as u8);
        for view in &self.retained_current_views {
            bytes.extend(view.expires_at.to_be_bytes());
            bytes.extend((view.query.len() as u32).to_be_bytes());
            bytes.extend(&view.query);
            bytes.extend((view.reply.len() as u32).to_be_bytes());
            bytes.extend(&view.reply);
        }
        let current = self
            .current
            .as_ref()
            .map(|index| index.snapshot())
            .transpose()?
            .unwrap_or_default();
        bytes.extend((current.len() as u32).to_be_bytes());
        bytes.extend(current);
        if bytes.len() > INBOX_BUDGET {
            return Err("inbox byte capacity exhausted");
        }
        Ok(bytes)
    }

    /// Encrypt/authenticate all state under the existing host storage key. Host
    /// atomically writes and reads back this entire bundle before adopting it.
    pub fn seal(
        &self,
        owner: &arachne_security::Workspace,
        key: &arachne_security::StorageKey,
        publisher: &PublisherLog,
    ) -> Result<Vec<u8>, &'static str> {
        owner.seal_with_attachment(key, &self.snapshot_with_publisher(owner, publisher)?)
    }

    /// Native persistence payload. Store atomically with the matching security
    /// owner; these bytes are not independently encrypted or authenticated.
    pub fn snapshot_with_publisher(
        &self,
        owner: &arachne_security::Workspace,
        publisher: &PublisherLog,
    ) -> Result<Vec<u8>, &'static str> {
        self.validate_owner(owner)?;
        publisher.validate_owner(owner)?;
        let inbox = self.snapshot()?;
        // Each part has its own budget, and the budgets fit the attachment:
        // saving never evicts publisher history to make room for the inbox.
        let log = publisher.snapshot();
        if log.len() > crate::PUBLISHER_BUDGET
            || 9 + log.len() + inbox.len() > arachne_security::MAX_WORKSPACE_ATTACHMENT
        {
            return Err("combined object delivery state exceeds bound");
        }
        let mut bytes = MAGIC.to_vec();
        bytes.extend((log.len() as u32).to_be_bytes());
        bytes.extend(log);
        bytes.extend(inbox);
        Ok(bytes)
    }

    pub fn restore(
        key: &arachne_security::StorageKey,
        endpoint: [u8; 32],
        workspace: [u8; 32],
        sealed: &[u8],
    ) -> Result<(arachne_security::Workspace, PublisherLog, Self), &'static str> {
        let (owner, attachment) =
            arachne_security::Workspace::restore_with_attachment(key, endpoint, workspace, sealed)?;
        let (publisher, inbox) = Self::restore_snapshot(&owner, &attachment)?;
        Ok((owner, publisher, inbox))
    }

    /// Validate delivery records against an already restored security owner.
    pub fn restore_snapshot(
        owner: &arachne_security::Workspace,
        attachment: &[u8],
    ) -> Result<(PublisherLog, Self), &'static str> {
        if attachment.len() > arachne_security::MAX_WORKSPACE_ATTACHMENT {
            return Err("combined object delivery state exceeds bound");
        }
        let mut bytes = attachment;
        if take(&mut bytes, 5)? != MAGIC {
            return Err("unsupported object delivery bundle");
        }
        let length = u32::from_be_bytes(take(&mut bytes, 4)?.try_into().unwrap()) as usize;
        let publisher = PublisherLog::restore(owner, take(&mut bytes, length)?)?;
        let (parsed, ranges, retained_current_views, current) = if bytes.starts_with(CACHE_MAGIC) {
            let has_current = true;
            let has_retained_current = true;
            let mut input = &bytes[5..];
            let parsed = Snapshot::decode(&mut input)?;
            let count = take(&mut input, 1)?[0] as usize;
            if count > MAX_RETAINED_RANGES {
                return Err("retained range capacity exceeded");
            }
            let mut ranges = Vec::with_capacity(count);
            let mut previous_query: Option<Vec<u8>> = None;
            for _ in 0..count {
                let expires_at = u64::from_be_bytes(take(&mut input, 8)?.try_into().unwrap());
                let query_len =
                    u32::from_be_bytes(take(&mut input, 4)?.try_into().unwrap()) as usize;
                let query = take(&mut input, query_len)?.to_vec();
                RangeQuery::from_wire(&query)?;
                let reply_len =
                    u32::from_be_bytes(take(&mut input, 4)?.try_into().unwrap()) as usize;
                let reply = take(&mut input, reply_len)?.to_vec();
                if expires_at == 0 || reply.len() > wire::MAX_REPLY_BYTES {
                    return Err("invalid retained range");
                }
                if previous_query
                    .as_ref()
                    .is_some_and(|previous| previous >= &query)
                {
                    return Err("noncanonical retained ranges");
                }
                previous_query = Some(query.clone());
                ranges.push(RetainedRange {
                    query,
                    reply,
                    expires_at,
                });
            }
            let mut retained_current_views = Vec::new();
            if has_retained_current {
                let count = take(&mut input, 1)?[0] as usize;
                if count > MAX_RETAINED_CURRENT_VIEWS {
                    return Err("retained current-view capacity exceeded");
                }
                let mut previous_query: Option<Vec<u8>> = None;
                for _ in 0..count {
                    let expires_at = u64::from_be_bytes(take(&mut input, 8)?.try_into().unwrap());
                    let query_len =
                        u32::from_be_bytes(take(&mut input, 4)?.try_into().unwrap()) as usize;
                    let query = take(&mut input, query_len)?.to_vec();
                    current::CurrentViewQuery::from_wire(&query)?;
                    let reply_len =
                        u32::from_be_bytes(take(&mut input, 4)?.try_into().unwrap()) as usize;
                    let reply = take(&mut input, reply_len)?.to_vec();
                    if expires_at == 0
                        || reply.len() > wire::MAX_REPLY_BYTES
                        || previous_query
                            .as_ref()
                            .is_some_and(|previous| previous >= &query)
                    {
                        return Err("invalid retained current view");
                    }
                    previous_query = Some(query.clone());
                    retained_current_views.push(RetainedCurrentView {
                        query,
                        reply,
                        expires_at,
                    });
                }
            }
            let current = if has_current {
                let length = u32::from_be_bytes(take(&mut input, 4)?.try_into().unwrap()) as usize;
                if length == 0 {
                    None
                } else {
                    Some(Box::new(current::CurrentViewIndex::restore(
                        owner.id(),
                        owner.member().ok_or("member required")?.id(),
                        owner.epoch(),
                        take(&mut input, length)?,
                    )?))
                }
            } else {
                None
            };
            if !input.is_empty() {
                return Err("trailing retained range bytes");
            }
            (parsed, ranges, retained_current_views, current)
        } else {
            return Err("unsupported object inbox snapshot");
        };
        let inbox = Self {
            workspace: parsed.workspace,
            epoch: parsed.epoch,
            replay: parsed.replay,
            pending: parsed.pending,
            recent: parsed.recent,
            clock: parsed.clock,
            served: parsed.served,
            retained_ranges: ranges,
            retained_current_views,
            current,
            progress: parsed.progress,
            current_progress: parsed.current_progress,
            direct: parsed.direct,
            missed: 0,
        };
        inbox.validate_owner(owner)?;
        for range in &inbox.retained_ranges {
            let query = RangeQuery::from_wire(&range.query)?;
            if query.workspace != owner.id()
                || !owner.in_receive_window(query.epoch)
                || !matches!(
                    wire::verify_reply(owner, &query, &range.reply)?,
                    wire::RangeReply::Offered(_)
                )
            {
                return Err("invalid retained range proof");
            }
        }
        for retained in &inbox.retained_current_views {
            let query = current::CurrentViewQuery::from_wire(&retained.query)?;
            let view = current::verify_wire_reply(owner, &query, &retained.reply)?
                .ok_or("invalid retained current-view proof")?;
            if query.workspace != owner.id()
                || query.epoch != owner.epoch()
                || view.values.iter().map(|value| value.expires_at).max()
                    != Some(retained.expires_at)
            {
                return Err("invalid retained current-view proof");
            }
        }
        let oldest = owner.oldest_receive_epoch();
        let mut windows = BTreeSet::new();
        if inbox.replay.len() > MAX_REPLAY_WINDOWS
            || inbox.replay.iter().any(|replay| {
                !replay.valid()
                    || replay.epoch < oldest
                    || replay.epoch > owner.epoch()
                    || !windows.insert((replay.author, replay.epoch))
            })
        {
            return Err("invalid inbox replay window");
        }
        if inbox.pending.len() > MAX_PENDING_OBJECTS {
            return Err("pending inbox capacity exceeded");
        }
        let live: BTreeSet<_> = inbox.pending.iter().map(Self::scope_key).collect();
        let mut scopes = BTreeSet::new();
        if inbox.recent.len() > RECENT_IDS
            || inbox.served.iter().any(|(scope, tick)| {
                *tick == 0 || *tick > inbox.clock || !live.contains(scope) || !scopes.insert(*scope)
            })
        {
            return Err("invalid inbox service state");
        }
        let mut identities = BTreeSet::new();
        for pending in &inbox.pending {
            let context = inbox.context(pending)?;
            // Pending objects were authenticated at receipt; the replay window
            // of a still-retained epoch must record them.
            let recorded = inbox
                .replay
                .iter()
                .find(|replay| replay.author == pending.author && replay.epoch == pending.epoch)
                .is_none_or(|replay| {
                    matches!(replay.state(pending.counter), ReplayState::Duplicate)
                });
            if !identities.insert((pending.author, pending.epoch, pending.counter))
                || !recorded
                || pending.epoch > owner.epoch()
                || pending.payload.len() > arachne_security::MAX_APPLICATION_PAYLOAD
                || (pending.current.is_some() && !pending.recipients.is_empty())
                || (pending.recipients.is_empty() && context.sequence.is_none())
                || pending.recipients.len() > 64
                || pending.recipients.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err("invalid pending object");
            }
        }
        if inbox.progress.len() > MAX_RECOVERY_SELECTIONS
            || inbox.progress.iter().any(|progress| {
                progress.through == 0 || !owner.in_receive_window(progress.epoch)
            })
            || inbox.progress.windows(2).any(|pair| {
                (pair[0].author, pair[0].epoch, pair[0].selection)
                    >= (pair[1].author, pair[1].epoch, pair[1].selection)
            })
        {
            return Err("invalid recovery selection progress");
        }
        if inbox.current_progress.len() > current::MAX_CURRENT_SELECTIONS
            || inbox.current_progress.windows(2).any(|pair| {
                (
                    pair[0].authority,
                    pair[0].revision,
                    &pair[0].topic,
                    pair[0].selector,
                ) >= (
                    pair[1].authority,
                    pair[1].revision,
                    &pair[1].topic,
                    pair[1].selector,
                )
            })
            || inbox.current_progress.iter().any(|progress| {
                Topic::new(progress.topic.clone()).is_err()
                    || owner.endpoints_for_members(&[progress.authority]).is_err()
            })
        {
            return Err("invalid current-view progress");
        }
        if inbox.direct.len() > MAX_DIRECT_STREAMS {
            return Err("direct recovery stream capacity exceeded");
        }
        let local = owner.member().ok_or("member required")?.id();
        let mut direct_streams = BTreeSet::new();
        for stream in &inbox.direct {
            let effective_head = stream.effective_head();
            if (stream.records.is_empty() && stream.known_head == 0)
                || stream.records.len() > DIRECT_WINDOW
                || stream.floor > effective_head
                || stream.recovery_floor > effective_head
                || (stream.known_head != 0
                    && stream
                        .records
                        .last()
                        .is_some_and(|record| stream.known_head < record.sequence))
                || stream.recipients.is_empty()
                || stream.recipients.len() > 64
                || stream.recipients.windows(2).any(|pair| pair[0] >= pair[1])
                || stream.recipients.contains(&stream.author)
                || (stream.author != local && !stream.recipients.contains(&local))
                || !direct_streams.insert((
                    stream.author,
                    stream.revision,
                    &stream.topic,
                    &stream.recipients,
                ))
            {
                return Err("invalid direct recovery stream");
            }
            owner.endpoints_for_members(&stream.recipients)?;
            let topic = Topic::new(stream.topic.clone()).map_err(|_| "invalid direct topic")?;
            let mut previous = stream.floor;
            let mut ids = BTreeSet::new();
            for record in &stream.records {
                let context = PublicationContext {
                    workspace: owner.id(),
                    revision: stream.revision,
                    topic: topic.clone(),
                    id: record.id,
                    sequence: std::num::NonZeroU64::new(record.sequence),
                };
                let authenticated = owner.unprotect_object(
                    topic.namespace().as_bytes(),
                    &context.direct_authenticated_bytes(&stream.recipients)?,
                    &record.object,
                )?;
                if record.revision != stream.revision
                    || record.sequence <= previous
                    || !ids.insert(record.id)
                    || authenticated.message.member != stream.author
                {
                    return Err("invalid direct recovery record");
                }
                previous = record.sequence;
            }
        }
        Ok((publisher, inbox))
    }
}

/// Register an unregistered invitation and fold the registration commit into
/// `admin`. Callers with other already-joined members must additionally apply
/// `registered.action`/`registered.commit` via `prepare_management_update`.
#[cfg(test)]
fn issue_registered_invitation(
    admin: arachne_security::Workspace,
) -> (
    arachne_security::Workspace,
    arachne_security::Invitation,
    Vec<u8>,
) {
    let (registered, invite, checkpoint) = admin.prepare_invitation(0, false, false).unwrap();
    (registered.workspace, invite, checkpoint)
}

#[test]
fn current_value_survives_authenticated_delivery_bundle() {
    use arachne_routing::{Permissions, RoutingTable};
    use arachne_security::{PendingJoin, StorageKey, Workspace};

    let admin = Workspace::create(crate::test_key(1), "Publisher").unwrap();
    let (admin, invite, checkpoint) = issue_registered_invitation(admin);
    let join = PendingJoin::from_invitation(&invite, &checkpoint, crate::test_key(2), "Reader").unwrap();
    let prepared = admin
        .prepare_admission(crate::test_endpoint(2), join.admission_request().unwrap())
        .unwrap();
    let mut proof = join.join_proof().unwrap();
    proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let reader = join.prepare_workspace(&proof, &prepared.welcome).unwrap();
    let mut owner = prepared.workspace;
    let topic = Topic::new("streams/opaque").unwrap();
    let context = PublicationContext {
        workspace: owner.id(),
        revision: 7,
        topic: topic.clone(),
        id: [9; 16],
        sequence: std::num::NonZeroU64::new(1),
    };
    let metadata = current::CurrentMetadata {
        selector: [7; 32],
        replacement_key: [8; 32],
        expires_at: 100,
        tombstone: false,
    };
    let object = owner
        .protect_object(
            context.topic.namespace().as_bytes(),
            &metadata.authenticated_context(&context),
            b"latest",
        )
        .unwrap();
    let packet = context.packet(&object).unwrap();
    let mut publisher = PublisherLog::new(&owner).unwrap();
    publisher.append(context.clone(), object).unwrap();
    let inbox = ObjectInbox::new(owner.id(), owner.epoch())
        .stage_current(
            &owner,
            context.clone(),
            metadata.selector,
            metadata.replacement_key,
            metadata.expires_at,
            metadata.tombstone,
            packet,
            UnixSeconds(0),
        )
        .unwrap();
    let key = StorageKey::derive(&[3; 32]).unwrap();
    let sealed = inbox.seal(&owner, &key, &publisher).unwrap();
    let (restored_owner, _, restored) =
        ObjectInbox::restore(&key, crate::test_endpoint(1), owner.id(), &sealed).unwrap();
    let query = current::CurrentViewQuery {
        workspace: owner.id(),
        authority: owner.member().unwrap().id(),
        epoch: owner.epoch(),
        policy_revision: 7,
        topic,
        selector: [7; 32],
    };
    let mut policy = RoutingTable::default();
    policy
        .install_verified_policy(
            owner.id(),
            7,
            BTreeMap::from([
                (crate::test_endpoint(1), Permissions::AllTopics),
                (crate::test_endpoint(2), Permissions::AllTopics),
            ]),
        )
        .unwrap();
    let reply = restored
        .serve_current(&restored_owner, &policy, crate::test_endpoint(2), &query, UnixSeconds(50))
        .unwrap();
    let verified = current::verify_wire_reply(&reader, &query, &reply)
        .unwrap()
        .unwrap();
    assert_eq!(verified.cut, 1);
    assert_eq!(verified.values[0].replacement_key, [8; 32]);
    let (accepted, pending_count, stale_count) = ObjectInbox::new(reader.id(), reader.epoch())
        .accept_current_view(&reader, &query, &reply, UnixSeconds(50))
        .unwrap();
    assert_eq!((pending_count, stale_count), (1, 0));
    assert_eq!(
        accepted.pending(&reader).unwrap().unwrap().message.payload,
        b"latest"
    );
    assert_eq!(
        accepted
            .accept_current_view(&reader, &query, &reply, UnixSeconds(50))
            .unwrap()
            .1,
        0
    );
    let reader_publisher =
        PublisherLog::new(&reader).unwrap();
    let accepted_sealed = accepted.seal(&reader, &key, &reader_publisher).unwrap();
    let (restored_reader, _, restored_accepted) =
        ObjectInbox::restore(&key, crate::test_endpoint(2), reader.id(), &accepted_sealed).unwrap();
    assert_eq!(
        restored_accepted
            .accept_current_view(&restored_reader, &query, &reply, UnixSeconds(50))
            .unwrap()
            .1,
        0
    );
    // Expiry 100 was set by the authority's clock. A reader whose clock is
    // ahead by less than the skew allowance still accepts the value.
    let (_, pending_count, stale_count) = ObjectInbox::new(reader.id(), reader.epoch())
        .accept_current_view(
            &reader,
            &query,
            &reply,
            UnixSeconds(100 + EXPIRY_SKEW_SECONDS - 1),
        )
        .unwrap();
    assert_eq!((pending_count, stale_count), (1, 0));
    let (_, pending_count, stale_count) = ObjectInbox::new(reader.id(), reader.epoch())
        .accept_current_view(&reader, &query, &reply, UnixSeconds(100 + EXPIRY_SKEW_SECONDS))
        .unwrap();
    assert_eq!((pending_count, stale_count), (0, 1));
    let (received_context, ciphertext) = PublicationContext::unpack(
        owner.id(),
        7,
        query.topic.clone(),
        &verified.values[0].packet,
    )
    .unwrap();
    let mut altered = metadata;
    altered.expires_at += 1;
    assert!(
        ObjectInbox::new(reader.id(), reader.epoch())
            .stage_live_current(&reader, &received_context, altered, ciphertext)
            .is_err()
    );
    let InboxStage::Prepared(received) = ObjectInbox::new(reader.id(), reader.epoch())
        .stage_live_current(&reader, &received_context, metadata, ciphertext)
        .unwrap()
    else {
        panic!("current value was not staged")
    };
    let pending = received.pending(&reader).unwrap().unwrap();
    assert_eq!(pending.message.payload, b"latest");
    assert_eq!(pending.current, Some(metadata));
}

#[test]
fn repeated_direct_transfers_fit_storage_without_losing_pending_or_sequence() {
    use arachne_security::{PendingJoin, StorageKey, Workspace};

    let admin = Workspace::create(crate::test_key(1), "Publisher").unwrap();
    let (admin, invite, checkpoint) = issue_registered_invitation(admin);
    let join = PendingJoin::from_invitation(&invite, &checkpoint, crate::test_key(2), "Reader").unwrap();
    let prepared = admin
        .prepare_admission(crate::test_endpoint(2), join.admission_request().unwrap())
        .unwrap();
    let mut proof = join.join_proof().unwrap();
    proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let mut reader = join.prepare_workspace(&proof, &prepared.welcome).unwrap();
    let mut sender = prepared.workspace;
    let mut log = PublisherLog::new(&sender).unwrap();
    let context = |workspace, topic: Topic, sequence: u64, id: u128| PublicationContext {
        workspace,
        revision: 7,
        topic,
        id: id.to_be_bytes(),
        sequence: std::num::NonZeroU64::new(sequence),
    };
    // Fill publisher history as well as direct recovery; independent limits
    // must not overflow the one persisted attachment when combined.
    for sequence in 1..=64 {
        let ctx = context(
            sender.id(),
            Topic::new(format!("history/{}", sequence % 2)).unwrap(),
            sequence,
            sequence.into(),
        );
        let object = sender
            .protect_object(ctx.topic.namespace().as_bytes(), &ctx.authenticated_bytes(), &vec![5; 12 * 1024])
            .unwrap();
        log.append(ctx, object).unwrap();
    }
    let pending_context = context(sender.id(), Topic::new("commands/pending").unwrap(), 1, 900);
    let audience = [sender.member().unwrap().id()];
    let pending_object = reader
        .protect_object(
            pending_context.topic.namespace().as_bytes(),
            &pending_context
                .direct_authenticated_bytes(&audience)
                .unwrap(),
            b"keep pending",
        )
        .unwrap();
    let InboxStage::Prepared(inbox) = ObjectInbox::new(sender.id(), sender.epoch())
        .stage_with_recipients(&sender, &pending_context, &audience, &pending_object)
        .unwrap()
    else {
        panic!("not staged")
    };
    let mut inbox = *inbox;
    let recipients = [reader.member().unwrap().id()];
    let topic = Topic::new("resources/chunks").unwrap();
    let key = StorageKey::derive(&[9; 32]).unwrap();
    for sequence in 1..=160 {
        assert_eq!(
            inbox
                .next_direct_sequence(&sender, 7, &topic, &recipients)
                .unwrap()
                .get(),
            sequence
        );
        let ctx = context(
            sender.id(),
            topic.clone(),
            sequence,
            1000 + u128::from(sequence),
        );
        let object = sender
            .protect_object(
                ctx.topic.namespace().as_bytes(),
                &ctx.direct_authenticated_bytes(&recipients).unwrap(),
                &vec![7; 6 * 1024],
            )
            .unwrap();
        inbox = inbox
            .stage_sent_direct(&sender, &ctx, &recipients, &object)
            .unwrap();
        let saved = inbox.seal(&sender, &key, &log).unwrap();
        (sender, log, inbox) = ObjectInbox::restore(&key, crate::test_endpoint(1), sender.id(), &saved).unwrap();
        assert_eq!(log.head(), 64);
        assert_eq!(
            inbox.pending(&sender).unwrap().unwrap().message.payload,
            b"keep pending"
        );
        assert!(
            inbox.direct.iter().map(DirectStream::encoded_len).sum::<usize>()
                <= MAX_DIRECT_RETAINED_BYTES
        );
    }
    assert!(matches!(
        inbox
            .stage_with_recipients(&sender, &pending_context, &audience, &pending_object)
            .unwrap(),
        InboxStage::Duplicate
    ));
    assert!(matches!(
        log.select(0, 64, &BTreeSet::from([Topic::new("history/0").unwrap()])),
        Err(RangeError::Unavailable)
    ));
    let stream = inbox
        .direct
        .iter_mut()
        .find(|stream| stream.topic == topic.as_str())
        .unwrap();
    stream.floor = stream.known_head;
    stream.records.clear();
    assert_eq!(
        inbox
            .next_direct_sequence(&sender, 7, &topic, &recipients)
            .unwrap()
            .get(),
        161
    );
}

#[test]
fn deferred_streams_preserve_order_identity_and_restart() {
    use arachne_security::{PendingJoin, StorageKey, Workspace};

    let admin = Workspace::create(crate::test_key(1), "Publisher").unwrap();
    let (admin, invite, checkpoint) = issue_registered_invitation(admin);
    let join = PendingJoin::from_invitation(&invite, &checkpoint, crate::test_key(2), "Reader").unwrap();
    let prepared = admin
        .prepare_admission(crate::test_endpoint(2), join.admission_request().unwrap())
        .unwrap();
    let mut proof = join.join_proof().unwrap();
    proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let reader = join.prepare_workspace(&proof, &prepared.welcome).unwrap();
    let mut sender = prepared.workspace;
    let mut inbox = ObjectInbox::new(reader.id(), reader.epoch());
    for number in 1u64..=5 {
        let context = PublicationContext {
            workspace: reader.id(),
            revision: if number == 3 { 8 } else { 7 },
            topic: Topic::new(if number == 4 {
                "other/topic"
            } else {
                "chat/messages"
            })
            .unwrap(),
            id: u128::from(number).to_be_bytes(),
            sequence: (number != 5).then(|| std::num::NonZeroU64::new(number).unwrap()),
        };
        let recipients = if number == 5 {
            vec![reader.member().unwrap().id()]
        } else {
            vec![]
        };
        let aad = audience_aad(&reader, &context, &recipients).unwrap();
        let object = sender
            .protect_object(context.topic.namespace().as_bytes(), &aad, &[number as u8])
            .unwrap();
        let InboxStage::Prepared(next) = inbox
            .stage_with_recipients(&reader, &context, &recipients, &object)
            .unwrap()
        else {
            panic!("new object was not staged")
        };
        inbox = *next;
    }
    let first = inbox.pending(&reader).unwrap().unwrap();
    let mut deferred = Vec::new();
    // A later object in the deferred scope (ID 2) must never overtake ID 1.
    // A different revision, audience, or topic can still make progress.
    for number in [1u128, 3, 4, 5] {
        let pending = inbox
            .pending_excluding(&reader, &deferred)
            .unwrap()
            .unwrap();
        assert_eq!(pending.context.id, number.to_be_bytes());
        deferred.push(DeferredDeliveryStream::from(&pending));
    }
    assert!(
        inbox
            .pending_excluding(&reader, &deferred)
            .unwrap()
            .is_none()
    );
    assert_eq!(inbox.pending_count(), 5);
    let mut another_member = deferred[0].clone();
    another_member.member[0] ^= 1;
    assert_eq!(
        inbox
            .pending_excluding(&reader, &[another_member])
            .unwrap()
            .unwrap()
            .context
            .id,
        first.context.id
    );
    let again = inbox.pending(&reader).unwrap().unwrap();
    assert_eq!(again.context, first.context);
    assert_eq!(again.counter, first.counter);
    assert_eq!(again.message.member, first.message.member);
    assert_eq!(again.message.payload, first.message.payload);

    let key = StorageKey::derive(&[3; 32]).unwrap();
    let publisher = PublisherLog::new(&reader).unwrap();
    let sealed = inbox.seal(&reader, &key, &publisher).unwrap();
    let (restored_reader, _, restored) =
        ObjectInbox::restore(&key, crate::test_endpoint(2), reader.id(), &sealed).unwrap();
    assert_eq!(restored.pending_count(), 5);
    let restored_first = restored.pending(&restored_reader).unwrap().unwrap();
    assert_eq!(restored_first.context, first.context);
    assert_eq!(restored_first.counter, first.counter);
    assert_eq!(restored_first.message.member, first.message.member);
    let acknowledged = restored
        .acknowledge(
            first.message.member,
            &first.context.topic,
            first.counter,
            first.context.id,
        )
        .unwrap();
    assert_eq!(
        acknowledged
            .pending(&restored_reader)
            .unwrap()
            .unwrap()
            .context
            .id,
        // Round robin: another scope goes before the served one continues.
        3u128.to_be_bytes()
    );
    assert_eq!(acknowledged.pending_count(), 4);
    assert!(
        ObjectInbox::new(reader.id(), reader.epoch() + 1)
            .pending_excluding(&reader, &deferred)
            .is_err()
    );
    assert!(
        ObjectInbox::new([0; 32], reader.epoch())
            .pending_excluding(&reader, &deferred)
            .is_err()
    );
}

#[test]
fn permanent_rejection_is_durable_and_unblocks_the_next_object() {
    use arachne_security::{PendingJoin, StorageKey, Workspace};

    let admin = Workspace::create(crate::test_key(1), "Publisher").unwrap();
    let (admin, invite, checkpoint) = issue_registered_invitation(admin);
    let join = PendingJoin::from_invitation(&invite, &checkpoint, crate::test_key(2), "Reader").unwrap();
    let prepared = admin
        .prepare_admission(crate::test_endpoint(2), join.admission_request().unwrap())
        .unwrap();
    let mut proof = join.join_proof().unwrap();
    proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let reader = join.prepare_workspace(&proof, &prepared.welcome).unwrap();
    let mut sender = prepared.workspace;
    let topic = Topic::new("atak/native/v1/features").unwrap();
    let context = |sequence: u64| PublicationContext {
        workspace: reader.id(),
        revision: 7,
        topic: topic.clone(),
        id: u128::from(sequence).to_be_bytes(),
        sequence: std::num::NonZeroU64::new(sequence),
    };
    let first = context(1);
    let second = context(2);
    let first_object = sender
        .protect_object(
            first.topic.namespace().as_bytes(),
            &first.authenticated_bytes(),
            b"invalid native bytes",
        )
        .unwrap();
    let second_object = sender
        .protect_object(
            second.topic.namespace().as_bytes(),
            &second.authenticated_bytes(),
            b"valid later object",
        )
        .unwrap();
    let InboxStage::Prepared(inbox) = ObjectInbox::new(reader.id(), reader.epoch())
        .stage(&reader, &first, &first_object)
        .unwrap()
    else {
        panic!("first object was not staged")
    };
    let InboxStage::Prepared(inbox) = inbox.stage(&reader, &second, &second_object).unwrap() else {
        panic!("second object was not staged")
    };
    let pending = inbox.pending(&reader).unwrap().unwrap();
    let rejected = inbox
        .reject(
            pending.message.member,
            &topic,
            pending.counter,
            pending.context.id,
        )
        .unwrap();
    assert_eq!(
        rejected.pending(&reader).unwrap().unwrap().message.payload,
        b"valid later object"
    );
    assert_eq!(rejected.pending_count(), 1);
    assert!(matches!(
        rejected.stage(&reader, &first, &first_object).unwrap(),
        InboxStage::Duplicate
    ));

    let key = StorageKey::derive(&[3; 32]).unwrap();
    let publisher = PublisherLog::new(&reader).unwrap();
    let sealed = rejected.seal(&reader, &key, &publisher).unwrap();
    let (restored_reader, _, restored) =
        ObjectInbox::restore(&key, crate::test_endpoint(2), reader.id(), &sealed).unwrap();
    assert_eq!(restored.pending_count(), 1);
    assert_eq!(
        restored
            .pending(&restored_reader)
            .unwrap()
            .unwrap()
            .message
            .payload,
        b"valid later object"
    );
}

#[test]
fn durable_pending_objects_and_bounded_topic_replay() {
    use arachne_security::{PendingJoin, StorageKey, Workspace};
    use std::{
        fs::{self, File, OpenOptions},
        io::Write,
    };
    let admin = Workspace::create(crate::test_key(1), "Publisher").unwrap();
    let (admin, invite, checkpoint) = issue_registered_invitation(admin);
    let join = PendingJoin::from_invitation(&invite, &checkpoint, crate::test_key(2), "Reader").unwrap();
    let prepared = admin
        .prepare_admission(crate::test_endpoint(2), join.admission_request().unwrap())
        .unwrap();
    let mut proof = join.join_proof().unwrap();
    proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let reader = join.prepare_workspace(&proof, &prepared.welcome).unwrap();
    let mut sender = prepared.workspace;
    let key = StorageKey::derive(&[11; 32]).unwrap();
    let publisher = PublisherLog::new(&reader).unwrap();
    let mut inbox = ObjectInbox::new(reader.id(), reader.epoch());
    let chat = Topic::new("chat/messages/v1").unwrap();
    let context = |number: u64, topic: Topic| PublicationContext {
        workspace: reader.id(),
        revision: 7,
        id: u128::from(number).to_be_bytes(),
        sequence: std::num::NonZeroU64::new(number),
        topic,
    };
    let older = context(1, chat.clone());
    let mut direct = context(99, Topic::new("streams/opaque").unwrap());
    direct.sequence = None;
    let recipients = [reader.member().unwrap().id()];
    let object = sender
        .protect_object(
            direct.topic.namespace().as_bytes(),
            &direct.direct_authenticated_bytes(&recipients).unwrap(),
            b"recipient only",
        )
        .unwrap();
    assert!(inbox.stage(&reader, &direct, &object).is_err());
    assert!(
        inbox
            .stage_with_recipients(&sender, &direct, &recipients, &object)
            .is_err()
    );
    assert!(
        inbox
            .stage_with_recipients(&reader, &direct, &[[99; 32]], &object)
            .is_err()
    );
    let InboxStage::Prepared(scoped) = inbox
        .stage_with_recipients(&reader, &direct, &recipients, &object)
        .unwrap()
    else {
        panic!("recipient object was not staged")
    };
    assert!(matches!(
        scoped
            .stage_with_recipients(&reader, &direct, &recipients, &object)
            .unwrap(),
        InboxStage::Duplicate
    ));
    let missing_tail = context(2, Topic::new("streams/private").unwrap());
    let missing_tail_object = sender
        .protect_object(
            missing_tail.topic.namespace().as_bytes(),
            &missing_tail
                .direct_authenticated_bytes(&recipients)
                .unwrap(),
            b"after gap",
        )
        .unwrap();
    let InboxStage::Prepared(gapped) = ObjectInbox::new(reader.id(), reader.epoch())
        .stage_with_recipients(&reader, &missing_tail, &recipients, &missing_tail_object)
        .unwrap()
    else {
        panic!("direct object was not staged")
    };
    assert!(gapped.pending(&reader).unwrap().is_none());
    let query = wire::DirectRangeQuery {
        workspace: reader.id(),
        author: sender.member().unwrap().id(),
        epoch: reader.epoch(),
        policy_revision: 7,
        topic: missing_tail.topic.clone(),
        recipients: recipients.to_vec(),
        after: 0,
        through: 2,
    };
    let (skipped, missing) = gapped.skip_direct_gap(&reader, &query).unwrap();
    assert_eq!(missing, 1);
    assert_eq!(
        skipped.pending(&reader).unwrap().unwrap().message.payload,
        b"after gap"
    );
    let snapshot = scoped.seal(&reader, &key, &publisher).unwrap();
    let (restored_reader, _, restored) =
        ObjectInbox::restore(&key, crate::test_endpoint(2), reader.id(), &snapshot).unwrap();
    let pending = restored.pending(&restored_reader).unwrap().unwrap();
    assert_eq!(pending.recipients, recipients);
    assert_eq!(pending.message.payload, b"recipient only");
    let older_object = sender
        .protect_object(b"chat", &older.authenticated_bytes(), b"missed chat")
        .unwrap();
    for _ in 0..10_000 {
        sender
            .protect_object(b"unsubscribed", b"unsubscribed/feed", b"opaque")
            .unwrap();
    }
    let newer = context(10_002, chat.clone());
    let newer_object = sender
        .protect_object(b"chat", &newer.authenticated_bytes(), b"live chat")
        .unwrap();
    let prepared = |inbox: &ObjectInbox, context: &PublicationContext, bytes: &[u8]| match inbox
        .stage(&reader, context, bytes)
        .unwrap()
    {
        InboxStage::Prepared(value) => *value,
        _ => panic!("new object was not staged"),
    };
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "inbox-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    fs::create_dir_all(&directory).unwrap();
    let file = directory.join("state.bin");
    let save_restore = |candidate: &ObjectInbox| {
        let sealed = candidate.seal(&reader, &key, &publisher).unwrap();
        let temporary = directory.join("next.bin");
        let mut out = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .unwrap();
        out.write_all(&sealed).unwrap();
        out.sync_all().unwrap();
        drop(out);
        fs::rename(temporary, &file).unwrap();
        File::open(&directory).unwrap().sync_all().unwrap();
        let readback = fs::read(&file).unwrap();
        assert_eq!(readback, sealed);
        let (_, _, restored) =
            ObjectInbox::restore(&key, reader.endpoint(), reader.id(), &readback).unwrap();
        restored
    };
    inbox = save_restore(&prepared(&inbox, &newer, &newer_object));
    let pending = inbox.pending(&reader).unwrap().unwrap();
    assert_eq!(pending.message.payload, b"live chat");
    // Crash after application acceptance but BEFORE saving acknowledgement:
    // restart offers the same stable identity, so the adapter can retry safely.
    let again = save_restore(&inbox).pending(&reader).unwrap().unwrap();
    assert_eq!(again.context, pending.context);
    assert_eq!(again.counter, pending.counter);
    assert!(
        inbox
            .acknowledge(pending.message.member, &chat, pending.counter, [0; 16])
            .is_err()
    );
    inbox = save_restore(
        &inbox
            .acknowledge(
                pending.message.member,
                &chat,
                pending.counter,
                pending.context.id,
            )
            .unwrap(),
    );
    assert!(inbox.pending(&reader).unwrap().is_none());
    assert!(matches!(
        inbox.stage(&reader, &newer, &newer_object).unwrap(),
        InboxStage::Duplicate
    ));
    inbox = save_restore(&prepared(&inbox, &older, &older_object));
    assert_eq!(
        inbox.pending(&reader).unwrap().unwrap().message.payload,
        b"missed chat"
    );
    assert!(matches!(
        inbox.stage(&reader, &older, &older_object).unwrap(),
        InboxStage::Duplicate
    ));
    let pending = inbox.pending(&reader).unwrap().unwrap();
    inbox = save_restore(
        &inbox
            .acknowledge(
                pending.message.member,
                &chat,
                pending.counter,
                pending.context.id,
            )
            .unwrap(),
    );
    for number in 10_003..11_027 {
        let ctx = context(number, chat.clone());
        let object = sender
            .protect_object(ctx.topic.namespace().as_bytes(), &ctx.authenticated_bytes(), b"chat")
            .unwrap();
        inbox = prepared(&inbox, &ctx, &object);
        let pending = inbox.pending(&reader).unwrap().unwrap();
        inbox = inbox
            .acknowledge(
                pending.message.member,
                &chat,
                pending.counter,
                pending.context.id,
            )
            .unwrap();
        if number % 128 == 0 {
            inbox = save_restore(&inbox);
        }
    }
    inbox = save_restore(&inbox);
    // 1,024 later accepted counters close the window below them.
    assert_eq!(inbox.replay.len(), 1);
    assert!(inbox.replay[0].seen.len() <= REPLAY_ENTRIES);
    assert!(inbox.replay[0].lost_through >= 1);
    assert!(matches!(
        inbox.stage(&reader, &older, &older_object).unwrap(),
        InboxStage::OutsideWindow
    ));
    assert!(matches!(
        inbox.stage(&reader, &newer, &newer_object).unwrap(),
        InboxStage::Duplicate
    ));
    // Replay state stays small after 1,025 acknowledged objects.
    assert!(inbox.snapshot().unwrap().len() < 6 * 1024);
    // Topic floors are independent; a feed does not retire chat receipts.
    let feed = Topic::new("feeds/opaque").unwrap();
    let first_feed = context(20_000, feed.clone());
    let first_feed_object = sender
        .protect_object(
            first_feed.topic.namespace().as_bytes(),
            &first_feed.authenticated_bytes(),
            b"pending",
        )
        .unwrap();
    inbox = prepared(&inbox, &first_feed, &first_feed_object);
    for number in 20_001..20_032 {
        let ctx = context(number, feed.clone());
        let object = sender
            .protect_object(ctx.topic.namespace().as_bytes(), &ctx.authenticated_bytes(), b"pending")
            .unwrap();
        inbox = prepared(&inbox, &ctx, &object);
    }
    // No per-topic receipt window: pending objects never displace each other.
    let ctx = context(20_032, feed.clone());
    let object = sender
        .protect_object(ctx.topic.namespace().as_bytes(), &ctx.authenticated_bytes(), b"33rd")
        .unwrap();
    inbox = prepared(&inbox, &ctx, &object);
    assert_eq!(inbox.pending_count(), 33);
    let restored = save_restore(&inbox);
    assert_eq!(
        restored.pending(&reader).unwrap().unwrap().context,
        first_feed
    );
    let mut tampered = first_feed_object.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(inbox.stage(&reader, &first_feed, &tampered).is_err());
    let wrong = ObjectInbox::new(reader.id(), reader.epoch() + 1);
    assert!(
        wrong
            .stage(&reader, &first_feed, &first_feed_object)
            .is_err()
    );
    assert!(
        ObjectInbox::restore(
            &StorageKey::derive(&[12; 32]).unwrap(),
            reader.endpoint(),
            reader.id(),
            &fs::read(&file).unwrap()
        )
        .is_err()
    );
    println!(
        "OBJECT_INBOX skipped=10000 subsequent=1024 pending_survives_save_restore=true duplicate_and_expired_replay_rejected=true receipt_window=32 pending_eviction=backpressure adapter_exactly_once=not_proven"
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn retained_publisher_proof_survives_holder_restart_and_expires() {
    use arachne_routing::{Permissions, RoutingTable};
    use arachne_security::{PendingJoin, StorageKey, Workspace};

    let admin = Workspace::create(crate::test_key(1), "Publisher").unwrap();
    let (admin, invite, checkpoint) = issue_registered_invitation(admin);
    let holder_join =
        PendingJoin::from_invitation(&invite, &checkpoint, crate::test_key(2), "Holder").unwrap();
    let prepared = admin
        .prepare_admission(crate::test_endpoint(2), holder_join.admission_request().unwrap())
        .unwrap();
    let mut holder_proof = holder_join.join_proof().unwrap();
    holder_proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let holder = holder_join
        .prepare_workspace(&holder_proof, &prepared.welcome)
        .unwrap();
    let admin = prepared.workspace;

    // `holder` is already a member, so the invitation registration commit
    // must be applied to it too or it forks from `admin`.
    let (registered, invite, checkpoint) = admin.prepare_invitation(0, false, false).unwrap();
    let admin = registered.workspace;
    let holder = match holder
        .prepare_management_update(registered.action, &registered.commit)
        .unwrap()
    {
        arachne_security::PreparedManagementUpdate::Active(workspace) => *workspace,
        _ => panic!("member stays active"),
    };
    let reader_join =
        PendingJoin::from_invitation(&invite, &checkpoint, crate::test_key(3), "Reader").unwrap();
    let prepared = admin
        .prepare_admission(crate::test_endpoint(3), reader_join.admission_request().unwrap())
        .unwrap();
    let mut reader_proof = reader_join.join_proof().unwrap();
    reader_proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let reader = reader_join
        .prepare_workspace(&reader_proof, &prepared.welcome)
        .unwrap();
    let holder = holder
        .prepare_admission_update(&prepared.authorization, &prepared.commit)
        .unwrap();
    let mut author = prepared.workspace;

    let topic = Topic::new("streams/opaque").unwrap();
    let mut policy = RoutingTable::default();
    let permissions = |reader: bool| Permissions::Selected {
        publish: if reader {
            BTreeSet::new()
        } else {
            BTreeSet::from([topic.clone()])
        },
        subscribe: if reader {
            BTreeSet::from([topic.clone()])
        } else {
            BTreeSet::new()
        },
    };
    policy
        .install_verified_policy(
            author.id(),
            1,
            BTreeMap::from([
                (crate::test_endpoint(1), permissions(false)),
                (crate::test_endpoint(2), permissions(true)),
                (crate::test_endpoint(3), permissions(true)),
            ]),
        )
        .unwrap();
    let context = PublicationContext {
        workspace: author.id(),
        revision: 1,
        topic: topic.clone(),
        id: [7; 16],
        sequence: std::num::NonZeroU64::new(1),
    };
    let ciphertext = author
        .protect_object(
            context.topic.namespace().as_bytes(),
            &context.authenticated_bytes(),
            b"retained",
        )
        .unwrap();
    let mut author_log =
        PublisherLog::new(&author).unwrap();
    author_log.append(context, ciphertext).unwrap();
    let query = RangeQuery {
        workspace: author.id(),
        author: author.member().unwrap().id(),
        epoch: author.epoch(),
        policy_revision: 1,
        after: 0,
        through: 1,
        topics: BTreeSet::from([topic.clone()]),
    };
    let reply = wire::serve_range(&author_log, &author, &policy, crate::test_endpoint(2), &query).unwrap();
    let inbox = ObjectInbox::new(holder.id(), holder.epoch())
        .retain_range(&holder, &query, &reply, 200, UnixSeconds(100))
        .unwrap();
    let key = StorageKey::derive(&[9; 32]).unwrap();
    let holder_log = PublisherLog::new(&holder).unwrap();
    let saved = inbox.seal(&holder, &key, &holder_log).unwrap();
    let (holder, _, inbox) =
        ObjectInbox::restore(&key, holder.endpoint(), holder.id(), &saved).unwrap();

    let relayed = inbox
        .serve_range(&holder, &policy, crate::test_endpoint(3), &query, UnixSeconds(150))
        .unwrap();
    assert_eq!(relayed, reply);
    assert!(matches!(
        wire::verify_reply(&reader, &query, &relayed).unwrap(),
        wire::RangeReply::Offered(_)
    ));
    let reader_inbox = ObjectInbox::new(reader.id(), reader.epoch())
        .accept_recovery_coverage(&reader, &query, &relayed)
        .unwrap();
    assert_eq!(
        reader_inbox.recovery_progress(query.author, query.epoch, &query.topics),
        1
    );
    let reader_key = StorageKey::derive(&[10; 32]).unwrap();
    let reader_log = PublisherLog::new(&reader).unwrap();
    let saved = reader_inbox
        .seal(&reader, &reader_key, &reader_log)
        .unwrap();
    let (_, _, restored_reader_inbox) =
        ObjectInbox::restore(&reader_key, reader.endpoint(), reader.id(), &saved).unwrap();
    assert_eq!(
        restored_reader_inbox.recovery_progress(query.author, query.epoch, &query.topics),
        1
    );

    let current_context = PublicationContext {
        workspace: author.id(),
        revision: 1,
        topic: topic.clone(),
        id: [8; 16],
        sequence: std::num::NonZeroU64::new(2),
    };
    let metadata = current::CurrentMetadata {
        selector: [4; 32],
        replacement_key: [5; 32],
        expires_at: 200,
        tombstone: false,
    };
    let object = author
        .protect_object(
            current_context.topic.namespace().as_bytes(),
            &metadata.authenticated_context(&current_context),
            b"latest",
        )
        .unwrap();
    let packet = current_context.packet(&object).unwrap();
    let author_inbox = ObjectInbox::new(author.id(), author.epoch())
        .stage_current(
            &author,
            current_context,
            metadata.selector,
            metadata.replacement_key,
            metadata.expires_at,
            metadata.tombstone,
            packet,
            UnixSeconds(0),
        )
        .unwrap();
    let current_query = current::CurrentViewQuery {
        workspace: author.id(),
        authority: author.member().unwrap().id(),
        epoch: author.epoch(),
        policy_revision: 1,
        topic: topic.clone(),
        selector: metadata.selector,
    };
    let current_reply = author_inbox
        .serve_current(&author, &policy, crate::test_endpoint(2), &current_query, UnixSeconds(100))
        .unwrap();
    let inbox = inbox
        .retain_current_view(&holder, &current_query, &current_reply, UnixSeconds(100))
        .unwrap();
    let saved = inbox.seal(&holder, &key, &holder_log).unwrap();
    let (holder, _, inbox) =
        ObjectInbox::restore(&key, holder.endpoint(), holder.id(), &saved).unwrap();
    let relayed = inbox
        .serve_current(&holder, &policy, crate::test_endpoint(3), &current_query, UnixSeconds(150))
        .unwrap();
    assert_eq!(relayed, current_reply);
    let (_, pending, stale) = ObjectInbox::new(reader.id(), reader.epoch())
        .accept_current_view(&reader, &current_query, &relayed, UnixSeconds(150))
        .unwrap();
    assert_eq!((pending, stale), (1, 0));
    assert_eq!(
        inbox
            // The authority's expiry (200) plus the skew allowance has passed.
            .serve_current(
                &holder,
                &policy,
                crate::test_endpoint(3),
                &current_query,
                UnixSeconds(200 + EXPIRY_SKEW_SECONDS),
            )
            .unwrap(),
        current::CurrentView::denied_wire()
    );
    assert_eq!(
        inbox
            // The holder's own retention limit (200): no skew.
            .serve_range(&holder, &policy, crate::test_endpoint(3), &query, UnixSeconds(200))
            .unwrap(),
        wire::unavailable_reply()
    );
    let mut removed_reader_policy = RoutingTable::default();
    removed_reader_policy
        .install_verified_policy(
            holder.id(),
            1,
            BTreeMap::from([(crate::test_endpoint(1), permissions(false)), (crate::test_endpoint(2), permissions(true))]),
        )
        .unwrap();
    assert_eq!(
        inbox
            .serve_range(&holder, &removed_reader_policy, crate::test_endpoint(3), &query, UnixSeconds(150))
            .unwrap(),
        wire::denied_reply()
    );
    assert_eq!(
        inbox
            .serve_current(
                &holder,
                &removed_reader_policy,
                crate::test_endpoint(3),
                &current_query,
                UnixSeconds(150)
            )
            .unwrap(),
        current::CurrentView::denied_wire()
    );
}
