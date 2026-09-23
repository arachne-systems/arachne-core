//! Bounded replay evidence and durable pending objects. Stage -> save -> adopt;
//! acknowledge only after the application durably accepts the stable identity.
use super::*;
use serde::{Deserialize, Serialize};

const MAGIC: &[u8] = b"DFOI\x01";
const LEGACY_CACHE_MAGIC: &[u8] = b"DFIC\x01";
const CURRENT_CACHE_MAGIC: &[u8] = b"DFIC\x02";
const CACHE_MAGIC: &[u8] = b"DFIC\x03";
const MAX_STREAMS: usize = 4096;
const WINDOW: usize = MAX_PACKETS_PER_TOPIC;
const MAX_RETAINED_RANGES: usize = 4;
const MAX_RETAINED_CURRENT_VIEWS: usize = 4;
const MAX_RECOVERY_SELECTIONS: usize = 64;
const MAX_DIRECT_STREAMS: usize = 256;
// Recovery copies are optional; pending application objects and replay floors
// are not. Bound encoded copies across all audiences, not just packet counts.
const MAX_DIRECT_RETAINED_BYTES: usize = 128 * 1024;

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    counter: u64,
    revision: u64,
    id: [u8; 16],
    sequence: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    recipients: Vec<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    current: Option<CurrentReceipt>,
    digest: [u8; 32],
    /// None means durably resolved; `rejected` distinguishes application refusal.
    pending: Option<Vec<u8>>,
    /// The application permanently rejected this authenticated object.
    #[serde(default, skip_serializing_if = "is_false")]
    rejected: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentReceipt {
    selector: [u8; 32],
    replacement_key: [u8; 32],
    expires_at: u64,
    #[serde(default)]
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stream {
    author: [u8; 32],
    topic: String,
    /// Counters at/below this boundary remain rejected after receipts expire.
    floor: u64,
    receipts: Vec<Receipt>,
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionProgress {
    author: [u8; 32],
    selection: [u8; 32],
    through: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentProgress {
    authority: [u8; 32],
    revision: u64,
    topic: String,
    selector: [u8; 32],
    cut: u64,
    digest: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectRecord {
    revision: u64,
    id: [u8; 16],
    sequence: u64,
    object: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectStream {
    author: [u8; 32],
    revision: u64,
    topic: String,
    recipients: Vec<[u8; 32]>,
    floor: u64,
    #[serde(default)]
    recovery_floor: u64,
    #[serde(default)]
    known_head: u64,
    records: Vec<DirectRecord>,
}

impl DirectStream {
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

#[derive(Clone, Serialize)]
pub struct ObjectInbox {
    workspace: [u8; 32],
    epoch: u64,
    // ponytail: linear lookup up to 4,096 streams; index if measured load requires it.
    streams: Vec<Stream>,
    #[serde(skip)]
    retained_ranges: Vec<RetainedRange>,
    #[serde(skip)]
    retained_current_views: Vec<RetainedCurrentView>,
    #[serde(skip)]
    current: Option<Box<current::CurrentViewIndex>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    progress: Vec<SelectionProgress>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    current_progress: Vec<CurrentProgress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    legacy_receive_snapshot: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    direct: Vec<DirectStream>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    workspace: [u8; 32],
    epoch: u64,
    streams: Vec<Stream>,
    #[serde(default)]
    progress: Vec<SelectionProgress>,
    #[serde(default)]
    current_progress: Vec<CurrentProgress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    legacy_receive_snapshot: Option<Vec<u8>>,
    #[serde(default)]
    direct: Vec<DirectStream>,
}

pub enum InboxStage {
    Duplicate,
    OutsideWindow,
    Prepared(Box<ObjectInbox>),
}

pub struct PendingObject {
    pub context: PublicationContext,
    pub message: arachne_security::ApplicationMessage,
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

/// An observed hole in a publisher's selected group sequence. A missing tail
/// without a later packet remains unknown, while an initial hole behind an
/// evicted receipt window is ambiguous.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupGap {
    pub author: [u8; 32],
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
            streams: Vec::new(),
            retained_ranges: Vec::new(),
            retained_current_views: Vec::new(),
            current: None,
            progress: Vec::new(),
            current_progress: Vec::new(),
            legacy_receive_snapshot: None,
            direct: Vec::new(),
        }
    }

    /// Preserve pre-object receive evidence during an explicit host cutover.
    /// This does not make legacy MLS ciphertext independently recoverable.
    pub fn with_legacy_receipts(&self, received: Option<&crate::receive::ReceiveJournal>) -> Self {
        let mut next = self.clone();
        next.legacy_receive_snapshot = received.map(|r| r.snapshot());
        next
    }

    pub fn legacy_receipts(&self) -> Result<Option<crate::receive::ReceiveJournal>, &'static str> {
        self.legacy_receive_snapshot
            .as_ref()
            .map(|bytes| crate::receive::ReceiveJournal::restore(self.workspace, self.epoch, bytes))
            .transpose()
    }

    pub fn recovery_progress(&self, author: [u8; 32], topics: &BTreeSet<Topic>) -> u64 {
        let selection = selection_digest(topics);
        self.progress
            .iter()
            .find(|progress| progress.author == author && progress.selection == selection)
            .map_or(0, |progress| progress.through)
    }

    fn group_progress_and_gap(
        &self,
        owner: &arachne_security::Workspace,
        author: [u8; 32],
        topics: &BTreeSet<Topic>,
    ) -> Result<(u64, Option<GroupGap>, bool), &'static str> {
        self.validate_owner(owner)?;
        if topics.is_empty() || topics.len() > MAX_TOPICS {
            return Err("invalid group recovery topic selection");
        }
        owner.endpoints_for_members(&[author])?;
        let progress = self.recovery_progress(author, topics);
        let mut sequences = BTreeSet::new();
        let mut may_have_evicted = false;
        for stream in &self.streams {
            if stream.author != author {
                continue;
            }
            may_have_evicted |= stream.floor > 0;
            sequences.extend(
                stream
                    .receipts
                    .iter()
                    .filter(|receipt| receipt.recipients.is_empty() && receipt.sequence > progress)
                    .map(|receipt| receipt.sequence),
            );
        }
        let mut previous = progress;
        let mut prefix_unknown = false;
        for sequence in sequences {
            if sequence <= previous {
                continue;
            }
            if sequence > previous.saturating_add(1) {
                if previous == progress && may_have_evicted {
                    previous = sequence;
                    prefix_unknown = true;
                    continue;
                }
                return Ok((
                    previous,
                    Some(GroupGap {
                        author,
                        after: previous,
                        through: (sequence - 1)
                            .min(previous.saturating_add(MAX_RECOVERY_PACKETS as u64)),
                    }),
                    !prefix_unknown,
                ));
            }
            previous = sequence;
        }
        if previous == progress && may_have_evicted {
            prefix_unknown = true;
        }
        Ok((previous, None, !prefix_unknown))
    }

    /// Highest contiguous group sequence proved by retained receipts or a
    /// previously accepted range. Receipts from every topic prove publisher
    /// cursor slots; a gap remains before the cursor until recovery.
    pub fn group_received_through(
        &self,
        owner: &arachne_security::Workspace,
        author: [u8; 32],
        topics: &BTreeSet<Topic>,
    ) -> Result<Option<u64>, &'static str> {
        self.group_progress_and_gap(owner, author, topics)
            .map(|(through, _, known)| known.then_some(through))
    }

    /// Return the first observed gap in the author's group sequence. Publisher
    /// sequence numbers span topics, so any retained group receipt from this
    /// author proves that global cursor slot arrived, even when its topic is not
    /// selected for recovery. An unreceived publication on an unknown topic
    /// remains indistinguishable from a miss. Once the bounded receipt window
    /// has evicted its first record, an initial gap is suppressed because that
    /// delivery status is unknowable.
    pub fn next_group_gap(
        &self,
        owner: &arachne_security::Workspace,
        author: [u8; 32],
        topics: &BTreeSet<Topic>,
    ) -> Result<Option<GroupGap>, &'static str> {
        self.group_progress_and_gap(owner, author, topics)
            .map(|(_, gap, _)| gap)
    }

    /// Add or replace one publisher-owned latest value. The returned inbox must
    /// be saved atomically with the already protected publication and owner.
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
        now: u64,
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
            .find(|view| view.query == encoded && view.expires_at > now)
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
        now: u64,
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
            if value.expires_at <= now {
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
            let authenticated =
                owner.unprotect_object(&metadata.authenticated_context(&context), ciphertext)?;
            if authenticated.message.member != query.authority
                || authenticated.message.endpoint != expected_endpoint
            {
                return Err("current-view value has wrong author");
            }
            match next.stage_live_current(owner, &context, metadata, now, ciphertext)? {
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
        self.validate_owner(owner)?;
        if query.workspace != self.workspace || query.epoch != self.epoch {
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
            progress.author == query.author && progress.selection == selection
        });
        let current = position.map_or(0, |index| self.progress[index].through);
        if query.through <= current {
            return Ok(self.clone());
        }
        if query.after != current {
            let received_through =
                self.group_received_through(owner, query.author, &query.topics)?;
            if query.after < current
                || received_through.is_none_or(|received_through| received_through < query.after)
            {
                return Err("recovery range does not continue accepted progress");
            }
        }
        if position.is_none() && self.progress.len() == MAX_RECOVERY_SELECTIONS {
            return Err("recovery selection capacity exhausted");
        }
        let mut next = self.clone();
        if let Some(index) = position {
            next.progress[index].through = query.through;
        } else {
            next.progress.push(SelectionProgress {
                author: query.author,
                selection,
                through: query.through,
            });
            next.progress
                .sort_by_key(|progress| (progress.author, progress.selection));
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

    fn context(
        &self,
        stream: &Stream,
        receipt: &Receipt,
    ) -> Result<PublicationContext, &'static str> {
        Ok(PublicationContext {
            workspace: self.workspace,
            revision: receipt.revision,
            topic: Topic::new(stream.topic.clone()).map_err(|_| "invalid inbox topic")?,
            id: receipt.id,
            sequence: std::num::NonZeroU64::new(receipt.sequence),
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
        self.stage_scoped(owner, context, recipients, None, true, object)
    }

    /// Preserve the publisher cursor, but queue only the newest unexpired value
    /// for a selector and replacement key.
    pub fn stage_live_current(
        &self,
        owner: &arachne_security::Workspace,
        context: &PublicationContext,
        metadata: current::CurrentMetadata,
        now: u64,
        object: &[u8],
    ) -> Result<InboxStage, &'static str> {
        if context.sequence.is_none() {
            return Err("current value lacks publisher sequence");
        }
        self.stage_scoped(
            owner,
            context,
            &[],
            Some(metadata.into()),
            metadata.expires_at > now,
            object,
        )
    }

    fn stage_scoped(
        &self,
        owner: &arachne_security::Workspace,
        context: &PublicationContext,
        recipients: &[[u8; 32]],
        current: Option<CurrentReceipt>,
        pending: bool,
        object: &[u8],
    ) -> Result<InboxStage, &'static str> {
        self.validate_owner(owner)?;
        if context.workspace != self.workspace {
            return Err("wrong inbox workspace");
        }
        let sequence = context.sequence.map_or(0, |n| n.get());
        let aad = receipt_aad(owner, context, recipients, current.as_ref())?;
        let authenticated = owner.unprotect_object(&aad, object)?;
        let author = authenticated.message.member;
        let counter = authenticated.counter;
        let digest: [u8; 32] = Sha256::digest(object).into();
        let position = self
            .streams
            .iter()
            .position(|s| s.author == author && s.topic == context.topic.as_str());
        if let Some(index) = position {
            let stream = &self.streams[index];
            if counter <= stream.floor {
                return Ok(InboxStage::OutsideWindow);
            }
            if let Some(known) = stream.receipts.iter().find(|r| r.counter == counter) {
                if known.digest != digest
                    || self.context(stream, known)? != *context
                    || known.recipients != recipients
                    || known.current != current
                {
                    return Err("conflicting object identity");
                }
                return Ok(InboxStage::Duplicate);
            }
            if stream.receipts.iter().any(|r| r.id == context.id) {
                return Err("publication identity reused");
            }
            if stream.receipts.len() == WINDOW && counter < stream.receipts[0].counter {
                return Ok(InboxStage::OutsideWindow);
            }
        } else if self.streams.len() == MAX_STREAMS {
            return Err("inbox stream capacity exhausted");
        }
        let mut next = self.clone();
        let index = position.unwrap_or_else(|| {
            next.streams.push(Stream {
                author,
                topic: context.topic.as_str().into(),
                floor: 0,
                receipts: Vec::new(),
            });
            next.streams.len() - 1
        });
        let stream = &mut next.streams[index];
        let has_newer_current = current.as_ref().is_some_and(|current| {
            context.sequence.is_some_and(|sequence| {
                stream.receipts.iter().any(|receipt| {
                    receipt.revision == context.revision
                        && receipt.sequence > sequence.get()
                        && receipt.current.as_ref().is_some_and(|known| {
                            known.selector == current.selector
                                && known.replacement_key == current.replacement_key
                        })
                })
            })
        });
        if let (Some(current), Some(sequence)) = (current.as_ref(), context.sequence) {
            for receipt in &mut stream.receipts {
                if receipt.revision == context.revision
                    && receipt.sequence < sequence.get()
                    && receipt.current.as_ref().is_some_and(|known| {
                        known.selector == current.selector
                            && known.replacement_key == current.replacement_key
                    })
                {
                    receipt.pending = None;
                }
            }
        }
        stream.receipts.push(Receipt {
            counter,
            revision: context.revision,
            id: context.id,
            sequence,
            recipients: recipients.to_vec(),
            current,
            digest,
            pending: (pending && !has_newer_current).then(|| object.to_vec()),
            rejected: false,
        });
        stream.receipts.sort_by_key(|r| r.counter);
        if stream.receipts.len() > WINDOW {
            // Never discard an undelivered object to make room. Caller drains
            // pending application work and retries the SAME incoming object.
            if stream.receipts[0].pending.is_some() {
                return Err("pending inbox window full");
            }
            stream.floor = stream.receipts.remove(0).counter;
        }
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
        let authenticated =
            owner.unprotect_object(&context.direct_authenticated_bytes(recipients)?, object)?;
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
            || head.epoch != self.epoch
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
        if stream.records.len() > WINDOW {
            stream.floor = stream.records.remove(0).sequence;
        }
        // ponytail: bounded JSON measurement matches the persisted byte budget;
        // maintain incremental encoded weights if profiling warrants it.
        while serde_json::to_vec(&self.direct)
            .map_err(|_| "direct recovery encoding failed")?
            .len()
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
            stream.floor = stream.floor.max(stream.records.remove(0).sequence);
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
            || query.epoch != self.epoch
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
        for packet in packets {
            match next.stage_with_recipients(
                owner,
                &packet.context,
                &query.recipients,
                &packet.ciphertext,
            )? {
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
        self.streams
            .iter()
            .flat_map(|stream| &stream.receipts)
            .filter(|receipt| receipt.pending.is_some())
            .count()
    }

    /// Returns authenticated pending work without consuming it. Call repeatedly
    /// after restart until the application has durably accepted it and ack saved.
    pub fn pending(
        &self,
        owner: &arachne_security::Workspace,
    ) -> Result<Option<PendingObject>, &'static str> {
        self.pending_excluding(owner, &[])
    }

    /// Poll pending work as of the supplied Unix time, skipping expired current
    /// values without changing the durable receipt or publisher cursor.
    pub fn pending_at(
        &self,
        owner: &arachne_security::Workspace,
        now: u64,
    ) -> Result<Option<PendingObject>, &'static str> {
        self.pending_excluding_at(owner, &[], now)
    }

    /// Poll without consuming work, skipping only the supplied delivery scopes.
    /// Hints apply to this call only; durable receipts and epoch guards are unchanged.
    pub fn pending_excluding(
        &self,
        owner: &arachne_security::Workspace,
        deferred: &[DeferredDeliveryStream],
    ) -> Result<Option<PendingObject>, &'static str> {
        self.pending_excluding_at(owner, deferred, 0)
    }

    /// Poll without consuming work, skipping deferred scopes and expired
    /// current values.
    pub fn pending_excluding_at(
        &self,
        owner: &arachne_security::Workspace,
        deferred: &[DeferredDeliveryStream],
        now: u64,
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
        for stream in &self.streams {
            for receipt in &stream.receipts {
                if let Some(object) = &receipt.pending {
                    if receipt
                        .current
                        .as_ref()
                        .is_some_and(|current| current.expires_at <= now)
                    {
                        continue;
                    }
                    if deferred.iter().any(|scope| {
                        scope.member == stream.author
                            && scope.revision == receipt.revision
                            && scope.topic == stream.topic
                            && scope.recipients == receipt.recipients
                    }) {
                        continue;
                    }
                    let context = self.context(stream, receipt)?;
                    if !receipt.recipients.is_empty()
                        && context.sequence.is_some()
                        && self.direct.iter().any(|direct| {
                            if direct.author != stream.author
                                || direct.revision != context.revision
                                || direct.topic != context.topic.as_str()
                                || direct.recipients != receipt.recipients
                            {
                                return false;
                            }
                            let mut expected =
                                direct.floor.max(direct.recovery_floor).saturating_add(1);
                            for record in &direct.records {
                                if record.sequence > expected {
                                    return context.sequence.unwrap().get() >= record.sequence;
                                }
                                if record.sequence == expected {
                                    expected = expected.saturating_add(1);
                                }
                            }
                            false
                        })
                    {
                        continue;
                    }
                    let aad = receipt_aad(
                        owner,
                        &context,
                        &receipt.recipients,
                        receipt.current.as_ref(),
                    )?;
                    let authenticated = owner.unprotect_object(&aad, object)?;
                    if authenticated.counter != receipt.counter
                        || authenticated.message.member != stream.author
                        || <[u8; 32]>::from(Sha256::digest(object)) != receipt.digest
                    {
                        return Err("pending object identity mismatch");
                    }
                    return Ok(Some(PendingObject {
                        context,
                        message: authenticated.message,
                        counter: receipt.counter,
                        recipients: receipt.recipients.clone(),
                        current: receipt.current.as_ref().map(Into::into),
                    }));
                }
            }
        }
        Ok(None)
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
        let mut next = self.clone();
        let stream = next
            .streams
            .iter_mut()
            .find(|s| s.author == author && s.topic == topic.as_str())
            .ok_or("unknown pending stream")?;
        let receipt = stream
            .receipts
            .iter_mut()
            .find(|r| r.counter == counter && r.id == id)
            .ok_or("unknown pending object")?;
        receipt.pending = None;
        receipt.rejected = false;
        Ok(next)
    }

    /// Persist permanent application rejection while retaining replay identity.
    pub fn reject(
        &self,
        author: [u8; 32],
        topic: &Topic,
        counter: u64,
        id: [u8; 16],
    ) -> Result<Self, &'static str> {
        let mut next = self.clone();
        let receipt = next
            .streams
            .iter_mut()
            .find(|stream| stream.author == author && stream.topic == topic.as_str())
            .and_then(|stream| {
                stream
                    .receipts
                    .iter_mut()
                    .find(|receipt| receipt.counter == counter && receipt.id == id)
            })
            .ok_or("unknown pending object")?;
        if receipt.pending.is_none() {
            return Err("object is not pending");
        }
        receipt.pending = None;
        receipt.rejected = true;
        Ok(next)
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
        now: u64,
    ) -> Result<Self, &'static str> {
        self.validate_owner(owner)?;
        if expires_at <= now {
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
        next.retained_ranges.retain(|range| range.expires_at > now);
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
        now: u64,
    ) -> Result<Self, &'static str> {
        self.validate_owner(owner)?;
        let expires_at = current::verify_wire_reply(owner, query, reply)?
            .ok_or("only an authenticated current view can be retained")?
            .values
            .iter()
            .map(|value| value.expires_at)
            .max()
            .filter(|expires_at| *expires_at > now)
            .ok_or("current view has no fresh value")?;
        let encoded = query.to_wire()?;
        let mut next = self.clone();
        next.retained_current_views
            .retain(|view| view.expires_at > now);
        if let Some(view) = next
            .retained_current_views
            .iter_mut()
            .find(|view| view.query == encoded)
        {
            view.reply = reply.to_vec();
            view.expires_at = expires_at;
        } else {
            if next.retained_current_views.len() == MAX_RETAINED_CURRENT_VIEWS {
                return Err("retained current-view capacity exhausted");
            }
            next.retained_current_views.push(RetainedCurrentView {
                query: encoded,
                reply: reply.to_vec(),
                expires_at,
            });
        }
        next.retained_current_views
            .sort_by(|a, b| a.query.cmp(&b.query));
        next.snapshot()?;
        Ok(next)
    }

    /// Serve only a still-current exact proof to a currently authorized reader.
    /// Missing and expired copies are reported as unavailable, never complete.
    pub fn serve_range(
        &self,
        owner: &arachne_security::Workspace,
        policy: &arachne_routing::RoutingTable,
        requester: [u8; 32],
        query: &RangeQuery,
        now: u64,
    ) -> Result<Vec<u8>, &'static str> {
        self.validate_owner(owner)?;
        if query.workspace != self.workspace || query.epoch != self.epoch {
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
            .find(|range| range.query == encoded && range.expires_at > now)
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
        now: u64,
    ) -> Result<Vec<u8>, &'static str> {
        self.validate_owner(owner)?;
        if request.workspace != self.workspace || request.epoch != self.epoch {
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
            .filter(|range| range.expires_at > now)
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
        let json = serde_json::to_vec(self).map_err(|_| "inbox encoding failed")?;
        let mut bytes = CACHE_MAGIC.to_vec();
        bytes.extend((json.len() as u32).to_be_bytes());
        bytes.extend(json);
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
        if bytes.len() > arachne_security::MAX_WORKSPACE_ATTACHMENT {
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
        // Inbox receipts and pending objects take precedence over optional
        // publisher history. Snapshot eviction keeps the signed head and each
        // topic's unavailable-history watermark, never claiming empty coverage.
        let mut retained = publisher.clone();
        let log = loop {
            let log = retained.snapshot();
            if 9 + log.len() + inbox.len() <= arachne_security::MAX_WORKSPACE_ATTACHMENT {
                break log;
            }
            if !retained.evict_oldest() {
                return Err("combined object delivery state exceeds bound");
            }
        };
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
        let publisher = PublisherLog::restore(
            owner.id(),
            owner.member().ok_or("member required")?.id(),
            owner.epoch(),
            take(&mut bytes, length)?,
        )?;
        let (json, ranges, retained_current_views, current) = if bytes.starts_with(CACHE_MAGIC)
            || bytes.starts_with(CURRENT_CACHE_MAGIC)
            || bytes.starts_with(LEGACY_CACHE_MAGIC)
        {
            let has_current =
                bytes.starts_with(CACHE_MAGIC) || bytes.starts_with(CURRENT_CACHE_MAGIC);
            let has_retained_current = bytes.starts_with(CACHE_MAGIC);
            let mut input = &bytes[5..];
            let length = u32::from_be_bytes(take(&mut input, 4)?.try_into().unwrap()) as usize;
            let json = take(&mut input, length)?;
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
            (json, ranges, retained_current_views, current)
        } else {
            (bytes, Vec::new(), Vec::new(), None)
        };
        let parsed: Snapshot =
            serde_json::from_slice(json).map_err(|_| "invalid inbox snapshot")?;
        let inbox = Self {
            workspace: parsed.workspace,
            epoch: parsed.epoch,
            streams: parsed.streams,
            retained_ranges: ranges,
            retained_current_views,
            current,
            progress: parsed.progress,
            current_progress: parsed.current_progress,
            legacy_receive_snapshot: parsed.legacy_receive_snapshot,
            direct: parsed.direct,
        };
        inbox.validate_owner(owner)?;
        inbox.legacy_receipts()?;
        for range in &inbox.retained_ranges {
            let query = RangeQuery::from_wire(&range.query)?;
            if query.workspace != owner.id()
                || query.epoch != owner.epoch()
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
        if inbox.streams.len() > MAX_STREAMS {
            return Err("inbox stream capacity exceeded");
        }
        if inbox.progress.len() > MAX_RECOVERY_SELECTIONS
            || inbox.progress.iter().any(|progress| progress.through == 0)
            || inbox.progress.windows(2).any(|pair| {
                (pair[0].author, pair[0].selection) >= (pair[1].author, pair[1].selection)
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
                || stream.records.len() > WINDOW
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
        let mut streams = BTreeSet::new();
        for stream in &inbox.streams {
            if !streams.insert((stream.author, &stream.topic))
                || stream.receipts.is_empty()
                || stream.receipts.len() > WINDOW
            {
                return Err("invalid inbox stream");
            }
            let mut previous = stream.floor;
            let mut ids = BTreeSet::new();
            for receipt in &stream.receipts {
                let context = inbox.context(stream, receipt)?;
                let aad = receipt_aad(
                    owner,
                    &context,
                    &receipt.recipients,
                    receipt.current.as_ref(),
                )?;
                if receipt.counter <= previous || !ids.insert(receipt.id) {
                    return Err("invalid inbox receipt order");
                }
                previous = receipt.counter;
                if receipt.rejected && receipt.pending.is_some() {
                    return Err("rejected inbox object is still pending");
                }
                if let Some(object) = &receipt.pending {
                    let message = owner.unprotect_object(&aad, object)?;
                    if message.counter != receipt.counter
                        || message.message.member != stream.author
                        || <[u8; 32]>::from(Sha256::digest(object)) != receipt.digest
                    {
                        return Err("invalid pending object");
                    }
                }
            }
        }
        Ok((publisher, inbox))
    }
}

#[test]
fn current_value_survives_authenticated_delivery_bundle() {
    use arachne_routing::{Permissions, RoutingTable};
    use arachne_security::{PendingJoin, StorageKey, Workspace};

    let admin = Workspace::create([1; 32], "Publisher").unwrap();
    let (invite, checkpoint) = admin.issue_invitation().unwrap();
    let join = PendingJoin::from_invitation(&invite, &checkpoint, [2; 32], "Reader").unwrap();
    let prepared = admin
        .prepare_admission([2; 32], join.admission_request().unwrap())
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
        .protect_object(&metadata.authenticated_context(&context), b"latest")
        .unwrap();
    let packet = context.packet(&object).unwrap();
    let mut publisher = PublisherLog::new(owner.id(), owner.member().unwrap().id(), owner.epoch());
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
        )
        .unwrap();
    let key = StorageKey::derive(&[3; 32]).unwrap();
    let sealed = inbox.seal(&owner, &key, &publisher).unwrap();
    let (restored_owner, _, restored) =
        ObjectInbox::restore(&key, [1; 32], owner.id(), &sealed).unwrap();
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
                ([1; 32], Permissions::AllTopics),
                ([2; 32], Permissions::AllTopics),
            ]),
        )
        .unwrap();
    let reply = restored
        .serve_current(&restored_owner, &policy, [2; 32], &query, 50)
        .unwrap();
    let verified = current::verify_wire_reply(&reader, &query, &reply)
        .unwrap()
        .unwrap();
    assert_eq!(verified.cut, 1);
    assert_eq!(verified.values[0].replacement_key, [8; 32]);
    let (accepted, pending_count, stale_count) = ObjectInbox::new(reader.id(), reader.epoch())
        .accept_current_view(&reader, &query, &reply, 50)
        .unwrap();
    assert_eq!((pending_count, stale_count), (1, 0));
    assert_eq!(
        accepted.pending(&reader).unwrap().unwrap().message.payload,
        b"latest"
    );
    assert_eq!(
        accepted
            .accept_current_view(&reader, &query, &reply, 50)
            .unwrap()
            .1,
        0
    );
    let reader_publisher =
        PublisherLog::new(reader.id(), reader.member().unwrap().id(), reader.epoch());
    let accepted_sealed = accepted.seal(&reader, &key, &reader_publisher).unwrap();
    let (restored_reader, _, restored_accepted) =
        ObjectInbox::restore(&key, [2; 32], reader.id(), &accepted_sealed).unwrap();
    assert_eq!(
        restored_accepted
            .accept_current_view(&restored_reader, &query, &reply, 50)
            .unwrap()
            .1,
        0
    );
    let (_, pending_count, stale_count) = ObjectInbox::new(reader.id(), reader.epoch())
        .accept_current_view(&reader, &query, &reply, 100)
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
            .stage_live_current(&reader, &received_context, altered, 50, ciphertext)
            .is_err()
    );
    let InboxStage::Prepared(received) = ObjectInbox::new(reader.id(), reader.epoch())
        .stage_live_current(&reader, &received_context, metadata, 50, ciphertext)
        .unwrap()
    else {
        panic!("current value was not staged")
    };
    let pending = received.pending(&reader).unwrap().unwrap();
    assert_eq!(pending.message.payload, b"latest");
    assert_eq!(pending.current, Some(metadata));
}

#[test]
fn current_pending_coalesces_to_newest_replacement_and_expires() {
    use arachne_security::{PendingJoin, Workspace};

    let admin = Workspace::create([1; 32], "Publisher").unwrap();
    let (invite, checkpoint) = admin.issue_invitation().unwrap();
    let join = PendingJoin::from_invitation(&invite, &checkpoint, [2; 32], "Reader").unwrap();
    let prepared = admin
        .prepare_admission([2; 32], join.admission_request().unwrap())
        .unwrap();
    let mut proof = join.join_proof().unwrap();
    proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let reader = join.prepare_workspace(&proof, &prepared.welcome).unwrap();
    let mut sender = prepared.workspace;
    let topic = Topic::new("feeds/pli").unwrap();
    let metadata = current::CurrentMetadata {
        selector: [4; 32],
        replacement_key: [5; 32],
        expires_at: 100,
        tombstone: false,
    };
    let mut publications = Vec::new();
    for sequence in 1..=2 {
        let context = PublicationContext {
            workspace: reader.id(),
            revision: 7,
            topic: topic.clone(),
            id: [sequence as u8; 16],
            sequence: std::num::NonZeroU64::new(sequence),
        };
        let object = sender
            .protect_object(&metadata.authenticated_context(&context), &[sequence as u8])
            .unwrap();
        publications.push((context, object));
    }
    let mut inbox = ObjectInbox::new(reader.id(), reader.epoch());
    for (context, object) in publications.into_iter().rev() {
        let InboxStage::Prepared(next) = inbox
            .stage_live_current(&reader, &context, metadata, 0, &object)
            .unwrap()
        else {
            panic!("current value was not staged")
        };
        inbox = *next;
    }

    assert_eq!(inbox.pending_count(), 1);
    let pending = inbox.pending(&reader).unwrap().unwrap();
    assert_eq!(pending.context.sequence.unwrap().get(), 2);
    assert_eq!(pending.message.payload, [2]);
    assert_eq!(
        inbox
            .pending_at(&reader, 99)
            .unwrap()
            .unwrap()
            .context
            .sequence
            .unwrap()
            .get(),
        2
    );
    assert!(inbox.pending_at(&reader, 100).unwrap().is_none());
}

#[test]
fn repeated_direct_transfers_fit_storage_without_losing_pending_or_sequence() {
    use arachne_security::{PendingJoin, StorageKey, Workspace};

    let admin = Workspace::create([1; 32], "Publisher").unwrap();
    let (invite, checkpoint) = admin.issue_invitation().unwrap();
    let join = PendingJoin::from_invitation(&invite, &checkpoint, [2; 32], "Reader").unwrap();
    let prepared = admin
        .prepare_admission([2; 32], join.admission_request().unwrap())
        .unwrap();
    let mut proof = join.join_proof().unwrap();
    proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let mut reader = join.prepare_workspace(&proof, &prepared.welcome).unwrap();
    let mut sender = prepared.workspace;
    let mut log = PublisherLog::new(sender.id(), sender.member().unwrap().id(), sender.epoch());
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
            .protect_object(&ctx.authenticated_bytes(), &vec![5; 12 * 1024])
            .unwrap();
        log.append(ctx, object).unwrap();
    }
    let pending_context = context(sender.id(), Topic::new("commands/pending").unwrap(), 1, 900);
    let audience = [sender.member().unwrap().id()];
    let pending_object = reader
        .protect_object(
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
                &ctx.direct_authenticated_bytes(&recipients).unwrap(),
                &vec![7; 6 * 1024],
            )
            .unwrap();
        inbox = inbox
            .stage_sent_direct(&sender, &ctx, &recipients, &object)
            .unwrap();
        let saved = inbox.seal(&sender, &key, &log).unwrap();
        (sender, log, inbox) = ObjectInbox::restore(&key, [1; 32], sender.id(), &saved).unwrap();
        assert_eq!(log.head(), 64);
        assert_eq!(
            inbox.pending(&sender).unwrap().unwrap().message.payload,
            b"keep pending"
        );
        assert!(serde_json::to_vec(&inbox.direct).unwrap().len() <= MAX_DIRECT_RETAINED_BYTES);
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

    let admin = Workspace::create([1; 32], "Publisher").unwrap();
    let (invite, checkpoint) = admin.issue_invitation().unwrap();
    let join = PendingJoin::from_invitation(&invite, &checkpoint, [2; 32], "Reader").unwrap();
    let prepared = admin
        .prepare_admission([2; 32], join.admission_request().unwrap())
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
        let object = sender.protect_object(&aad, &[number as u8]).unwrap();
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
    for number in [1u128, 3, 5, 4] {
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
    let publisher = PublisherLog::new(reader.id(), reader.member().unwrap().id(), reader.epoch());
    let sealed = inbox.seal(&reader, &key, &publisher).unwrap();
    let (restored_reader, _, restored) =
        ObjectInbox::restore(&key, [2; 32], reader.id(), &sealed).unwrap();
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
        2u128.to_be_bytes()
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
fn group_pending_orders_chat_and_counts_other_topic_cursor_slots() {
    use arachne_security::{PendingJoin, Workspace};

    let admin = Workspace::create([1; 32], "Publisher").unwrap();
    let (invite, checkpoint) = admin.issue_invitation().unwrap();
    let join = PendingJoin::from_invitation(&invite, &checkpoint, [2; 32], "Reader").unwrap();
    let prepared = admin
        .prepare_admission([2; 32], join.admission_request().unwrap())
        .unwrap();
    let mut proof = join.join_proof().unwrap();
    proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let reader = join.prepare_workspace(&proof, &prepared.welcome).unwrap();
    let mut sender = prepared.workspace;
    let chat = Topic::new("chat/messages").unwrap();
    let other = Topic::new("feeds/pli").unwrap();
    let context = |sequence: u64, topic: Topic| PublicationContext {
        workspace: reader.id(),
        revision: 7,
        topic,
        id: [sequence as u8; 16],
        sequence: std::num::NonZeroU64::new(sequence),
    };
    let first = context(1, chat.clone());
    let other_topic = context(2, other);
    let second = context(3, chat.clone());
    let metadata = current::CurrentMetadata {
        selector: [4; 32],
        replacement_key: [5; 32],
        expires_at: 100,
        tombstone: false,
    };
    let first_object = sender
        .protect_object(&first.authenticated_bytes(), b"first")
        .unwrap();
    let other_object = sender
        .protect_object(
            &metadata.authenticated_context(&other_topic),
            b"current state",
        )
        .unwrap();
    let second_object = sender
        .protect_object(&second.authenticated_bytes(), b"second")
        .unwrap();
    let InboxStage::Prepared(inbox) = ObjectInbox::new(reader.id(), reader.epoch())
        .stage(&reader, &second, &second_object)
        .unwrap()
    else {
        panic!("second object was not staged")
    };
    let InboxStage::Prepared(inbox) = inbox.stage(&reader, &first, &first_object).unwrap() else {
        panic!("first object was not staged")
    };
    let pending = inbox.pending(&reader).unwrap().unwrap();
    assert_eq!(pending.message.payload, b"first");
    let chat_topics = BTreeSet::from([chat]);
    assert!(
        inbox
            .next_group_gap(&reader, pending.message.member, &chat_topics)
            .unwrap()
            .is_some()
    );
    let InboxStage::Prepared(inbox) = inbox
        .stage_live_current(&reader, &other_topic, metadata, 0, &other_object)
        .unwrap()
    else {
        panic!("other-topic object was not staged")
    };
    assert!(
        inbox
            .next_group_gap(&reader, pending.message.member, &chat_topics)
            .unwrap()
            .is_none()
    );
}

#[test]
fn permanent_rejection_is_durable_and_unblocks_the_next_object() {
    use arachne_security::{PendingJoin, StorageKey, Workspace};

    let admin = Workspace::create([1; 32], "Publisher").unwrap();
    let (invite, checkpoint) = admin.issue_invitation().unwrap();
    let join = PendingJoin::from_invitation(&invite, &checkpoint, [2; 32], "Reader").unwrap();
    let prepared = admin
        .prepare_admission([2; 32], join.admission_request().unwrap())
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
        .protect_object(&first.authenticated_bytes(), b"invalid native bytes")
        .unwrap();
    let second_object = sender
        .protect_object(&second.authenticated_bytes(), b"valid later object")
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
    assert!(rejected.streams[0].receipts[0].rejected);
    assert!(matches!(
        rejected.stage(&reader, &first, &first_object).unwrap(),
        InboxStage::Duplicate
    ));

    let key = StorageKey::derive(&[3; 32]).unwrap();
    let publisher = PublisherLog::new(reader.id(), reader.member().unwrap().id(), reader.epoch());
    let sealed = rejected.seal(&reader, &key, &publisher).unwrap();
    let (restored_reader, _, restored) =
        ObjectInbox::restore(&key, [2; 32], reader.id(), &sealed).unwrap();
    assert!(restored.streams[0].receipts[0].rejected);
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
    let admin = Workspace::create([1; 32], "Publisher").unwrap();
    let (invite, checkpoint) = admin.issue_invitation().unwrap();
    let join = PendingJoin::from_invitation(&invite, &checkpoint, [2; 32], "Reader").unwrap();
    let prepared = admin
        .prepare_admission([2; 32], join.admission_request().unwrap())
        .unwrap();
    let mut proof = join.join_proof().unwrap();
    proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let reader = join.prepare_workspace(&proof, &prepared.welcome).unwrap();
    let mut sender = prepared.workspace;
    let key = StorageKey::derive(&[11; 32]).unwrap();
    let publisher = PublisherLog::new(reader.id(), reader.member().unwrap().id(), reader.epoch());
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
        ObjectInbox::restore(&key, [2; 32], reader.id(), &snapshot).unwrap();
    let pending = restored.pending(&restored_reader).unwrap().unwrap();
    assert_eq!(pending.recipients, recipients);
    assert_eq!(pending.message.payload, b"recipient only");
    let older_object = sender
        .protect_object(&older.authenticated_bytes(), b"missed chat")
        .unwrap();
    for _ in 0..10_000 {
        sender
            .protect_object(b"unsubscribed/feed", b"opaque")
            .unwrap();
    }
    let newer = context(10_002, chat.clone());
    let newer_object = sender
        .protect_object(&newer.authenticated_bytes(), b"live chat")
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
            .protect_object(&ctx.authenticated_bytes(), b"chat")
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
    assert_eq!(inbox.streams[0].receipts.len(), WINDOW);
    assert!(inbox.streams[0].floor > 0);
    assert!(matches!(
        inbox.stage(&reader, &older, &older_object).unwrap(),
        InboxStage::OutsideWindow
    ));
    assert!(matches!(
        inbox.stage(&reader, &newer, &newer_object).unwrap(),
        InboxStage::OutsideWindow
    ));
    assert!(inbox.snapshot().unwrap().len() < 12 * 1024);
    // Topic floors are independent; a feed does not retire chat receipts.
    let feed = Topic::new("feeds/opaque").unwrap();
    let first_feed = context(20_000, feed.clone());
    let first_feed_object = sender
        .protect_object(&first_feed.authenticated_bytes(), b"pending")
        .unwrap();
    inbox = prepared(&inbox, &first_feed, &first_feed_object);
    for number in 20_001..20_032 {
        let ctx = context(number, feed.clone());
        let object = sender
            .protect_object(&ctx.authenticated_bytes(), b"pending")
            .unwrap();
        inbox = prepared(&inbox, &ctx, &object);
    }
    let full = inbox.snapshot().unwrap();
    let ctx = context(20_032, feed.clone());
    let object = sender
        .protect_object(&ctx.authenticated_bytes(), b"would evict pending")
        .unwrap();
    assert!(matches!(
        inbox.stage(&reader, &ctx, &object),
        Err("pending inbox window full")
    ));
    assert_eq!(inbox.snapshot().unwrap(), full);
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
fn signed_recovery_skips_only_a_durable_group_receipt_prefix() {
    use arachne_routing::{Permissions, RoutingTable};
    use arachne_security::{PendingJoin, Workspace};

    let admin = Workspace::create([1; 32], "Publisher").unwrap();
    let (invite, checkpoint) = admin.issue_invitation().unwrap();
    let join = PendingJoin::from_invitation(&invite, &checkpoint, [2; 32], "Reader").unwrap();
    let prepared = admin
        .prepare_admission([2; 32], join.admission_request().unwrap())
        .unwrap();
    let mut proof = join.join_proof().unwrap();
    proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let reader = join.prepare_workspace(&proof, &prepared.welcome).unwrap();
    let mut author = prepared.workspace;
    let topic = Topic::new("chat/messages").unwrap();
    let mut policy = RoutingTable::default();
    policy
        .install_verified_policy(
            author.id(),
            1,
            BTreeMap::from([
                (
                    [1; 32],
                    Permissions::Selected {
                        publish: BTreeSet::from([topic.clone()]),
                        subscribe: BTreeSet::new(),
                    },
                ),
                (
                    [2; 32],
                    Permissions::Selected {
                        publish: BTreeSet::new(),
                        subscribe: BTreeSet::from([topic.clone()]),
                    },
                ),
            ]),
        )
        .unwrap();
    let first = PublicationContext {
        workspace: author.id(),
        revision: 1,
        topic: topic.clone(),
        id: [1; 16],
        sequence: std::num::NonZeroU64::new(1),
    };
    let second = PublicationContext {
        id: [2; 16],
        sequence: std::num::NonZeroU64::new(2),
        ..first.clone()
    };
    let first_object = author
        .protect_object(&first.authenticated_bytes(), b"already received")
        .unwrap();
    let second_object = author
        .protect_object(&second.authenticated_bytes(), b"recovery tail")
        .unwrap();
    let mut log = PublisherLog::new(author.id(), author.member().unwrap().id(), author.epoch());
    log.append(first.clone(), first_object.clone()).unwrap();
    log.append(second, second_object).unwrap();
    let query = RangeQuery {
        workspace: reader.id(),
        author: author.member().unwrap().id(),
        epoch: reader.epoch(),
        policy_revision: 1,
        after: 1,
        through: 2,
        topics: BTreeSet::from([topic.clone()]),
    };
    let reply = wire::serve_range(&log, &author, &policy, reader.endpoint(), &query).unwrap();
    let InboxStage::Prepared(received) =
        ObjectInbox::new(reader.id(), reader.epoch())
            .stage(&reader, &first, &first_object)
            .unwrap()
    else {
        panic!("received prefix was not staged")
    };
    assert_eq!(
        received
            .group_received_through(&reader, query.author, &query.topics)
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        received
            .accept_recovery_coverage(&reader, &query, &reply)
            .unwrap()
            .recovery_progress(query.author, &query.topics),
        2
    );
    assert!(matches!(
        ObjectInbox::new(reader.id(), reader.epoch())
            .accept_recovery_coverage(&reader, &query, &reply),
        Err("recovery range does not continue accepted progress")
    ));
}

#[test]
fn retained_publisher_proof_survives_holder_restart_and_expires() {
    use arachne_routing::{Permissions, RoutingTable};
    use arachne_security::{PendingJoin, StorageKey, Workspace};

    let admin = Workspace::create([1; 32], "Publisher").unwrap();
    let (invite, checkpoint) = admin.issue_invitation().unwrap();
    let holder_join =
        PendingJoin::from_invitation(&invite, &checkpoint, [2; 32], "Holder").unwrap();
    let prepared = admin
        .prepare_admission([2; 32], holder_join.admission_request().unwrap())
        .unwrap();
    let mut holder_proof = holder_join.join_proof().unwrap();
    holder_proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let holder = holder_join
        .prepare_workspace(&holder_proof, &prepared.welcome)
        .unwrap();
    let admin = prepared.workspace;

    let (invite, checkpoint) = admin.issue_invitation().unwrap();
    let reader_join =
        PendingJoin::from_invitation(&invite, &checkpoint, [3; 32], "Reader").unwrap();
    let prepared = admin
        .prepare_admission([3; 32], reader_join.admission_request().unwrap())
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
                ([1; 32], permissions(false)),
                ([2; 32], permissions(true)),
                ([3; 32], permissions(true)),
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
        .protect_object(&context.authenticated_bytes(), b"retained")
        .unwrap();
    let mut author_log =
        PublisherLog::new(author.id(), author.member().unwrap().id(), author.epoch());
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
    let reply = wire::serve_range(&author_log, &author, &policy, [2; 32], &query).unwrap();
    let inbox = ObjectInbox::new(holder.id(), holder.epoch())
        .retain_range(&holder, &query, &reply, 200, 100)
        .unwrap();
    let key = StorageKey::derive(&[9; 32]).unwrap();
    let holder_log = PublisherLog::new(holder.id(), holder.member().unwrap().id(), holder.epoch());
    let saved = inbox.seal(&holder, &key, &holder_log).unwrap();
    let (holder, _, inbox) =
        ObjectInbox::restore(&key, holder.endpoint(), holder.id(), &saved).unwrap();

    let relayed = inbox
        .serve_range(&holder, &policy, [3; 32], &query, 150)
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
        reader_inbox.recovery_progress(query.author, &query.topics),
        1
    );
    let reader_key = StorageKey::derive(&[10; 32]).unwrap();
    let reader_log = PublisherLog::new(reader.id(), reader.member().unwrap().id(), reader.epoch());
    let saved = reader_inbox
        .seal(&reader, &reader_key, &reader_log)
        .unwrap();
    let (_, _, restored_reader_inbox) =
        ObjectInbox::restore(&reader_key, reader.endpoint(), reader.id(), &saved).unwrap();
    assert_eq!(
        restored_reader_inbox.recovery_progress(query.author, &query.topics),
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
        .protect_object(&metadata.authenticated_context(&current_context), b"latest")
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
        .serve_current(&author, &policy, [2; 32], &current_query, 100)
        .unwrap();
    let inbox = inbox
        .retain_current_view(&holder, &current_query, &current_reply, 100)
        .unwrap();
    let saved = inbox.seal(&holder, &key, &holder_log).unwrap();
    let (holder, _, inbox) =
        ObjectInbox::restore(&key, holder.endpoint(), holder.id(), &saved).unwrap();
    let relayed = inbox
        .serve_current(&holder, &policy, [3; 32], &current_query, 150)
        .unwrap();
    assert_eq!(relayed, current_reply);
    let (_, pending, stale) = ObjectInbox::new(reader.id(), reader.epoch())
        .accept_current_view(&reader, &current_query, &relayed, 150)
        .unwrap();
    assert_eq!((pending, stale), (1, 0));
    assert_eq!(
        inbox
            .serve_current(&holder, &policy, [3; 32], &current_query, 200)
            .unwrap(),
        current::CurrentView::denied_wire()
    );
    assert_eq!(
        inbox
            .serve_range(&holder, &policy, [3; 32], &query, 200)
            .unwrap(),
        wire::unavailable_reply()
    );
    let mut removed_reader_policy = RoutingTable::default();
    removed_reader_policy
        .install_verified_policy(
            holder.id(),
            1,
            BTreeMap::from([([1; 32], permissions(false)), ([2; 32], permissions(true))]),
        )
        .unwrap();
    assert_eq!(
        inbox
            .serve_range(&holder, &removed_reader_policy, [3; 32], &query, 150)
            .unwrap(),
        wire::denied_reply()
    );
    assert_eq!(
        inbox
            .serve_current(
                &holder,
                &removed_reader_policy,
                [3; 32],
                &current_query,
                150
            )
            .unwrap(),
        current::CurrentView::denied_wire()
    );
}
