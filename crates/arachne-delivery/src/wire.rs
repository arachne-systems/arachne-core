//! Bounded direct-publisher control records. Verification never advances MLS.
//! Rejections are advisory transport replies, not signed coverage/cursor updates.
use super::*;
use arachne_security::{ApplicationMessage, VerifiedRecoveryOffer, Workspace};

const QUERY: &[u8] = b"DFRQ\x01";
const REPLY: &[u8] = b"DFRP\x01";
const SEQUENCED_REPLY: &[u8] = b"DFRP\x02";
pub const MAX_QUERY_BYTES: usize = 32 * 1024;
pub const MAX_REPLY_BYTES: usize = 128 * 1024;

const CUTOFF_QUERY: &[u8] = b"DFCQ\x01";
const AVAILABLE_QUERY: &[u8] = b"DFHQ\x01";
const AVAILABLE_REPLY: &[u8] = b"DFHP\x01";
const DIRECT_QUERY: &[u8] = b"DFDQ\x01";
const DIRECT_REPLY: &[u8] = b"DFDP\x01";
const DIRECT_HEAD: &[u8] = b"DFDH\x01";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectHead {
    pub workspace: [u8; 32],
    pub author: [u8; 32],
    pub epoch: u64,
    pub policy_revision: u64,
    pub topic: Topic,
    pub recipients: Vec<[u8; 32]>,
    pub through: u64,
}

impl DirectHead {
    fn validate(&self) -> Result<(), &'static str> {
        if self.through == 0
            || self.recipients.is_empty()
            || self.recipients.len() > 64
            || self.recipients.windows(2).any(|pair| pair[0] >= pair[1])
            || self.recipients.contains(&self.author)
        {
            return Err("invalid direct head");
        }
        Ok(())
    }

    pub fn to_wire(&self) -> Result<Vec<u8>, &'static str> {
        self.validate()?;
        let mut bytes = DIRECT_HEAD.to_vec();
        bytes.extend(self.workspace);
        bytes.extend(self.author);
        for value in [self.epoch, self.policy_revision, self.through] {
            bytes.extend(value.to_be_bytes());
        }
        write_topic(&mut bytes, &self.topic);
        bytes.push(self.recipients.len() as u8);
        for recipient in &self.recipients {
            bytes.extend(recipient);
        }
        Ok(bytes)
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_QUERY_BYTES {
            return Err("direct head exceeds bound");
        }
        let mut input = bytes;
        if take(&mut input, 5)? != DIRECT_HEAD {
            return Err("wrong direct head format");
        }
        let workspace = take(&mut input, 32)?.try_into().unwrap();
        let author = take(&mut input, 32)?.try_into().unwrap();
        let epoch = number64(&mut input)?;
        let policy_revision = number64(&mut input)?;
        let through = number64(&mut input)?;
        let topic = read_topic(&mut input)?;
        let count = take(&mut input, 1)?[0] as usize;
        let mut recipients = Vec::with_capacity(count);
        for _ in 0..count {
            recipients.push(take(&mut input, 32)?.try_into().unwrap());
        }
        if !input.is_empty() {
            return Err("trailing direct head");
        }
        let head = Self {
            workspace,
            author,
            epoch,
            policy_revision,
            topic,
            recipients,
            through,
        };
        head.validate()?;
        Ok(head)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectRangeQuery {
    pub workspace: [u8; 32],
    pub author: [u8; 32],
    pub epoch: u64,
    pub policy_revision: u64,
    pub topic: Topic,
    pub recipients: Vec<[u8; 32]>,
    pub after: u64,
    pub through: u64,
}

impl DirectRangeQuery {
    fn validate(&self) -> Result<(), &'static str> {
        if self.after >= self.through
            || self.through - self.after > MAX_RECOVERY_PACKETS as u64
            || self.recipients.is_empty()
            || self.recipients.len() > 64
            || self.recipients.windows(2).any(|pair| pair[0] >= pair[1])
            || self.recipients.contains(&self.author)
        {
            return Err("invalid direct recovery query");
        }
        Ok(())
    }

    pub fn to_wire(&self) -> Result<Vec<u8>, &'static str> {
        self.validate()?;
        let mut bytes = DIRECT_QUERY.to_vec();
        bytes.extend(self.workspace);
        bytes.extend(self.author);
        for value in [self.epoch, self.policy_revision, self.after, self.through] {
            bytes.extend(value.to_be_bytes());
        }
        write_topic(&mut bytes, &self.topic);
        bytes.push(self.recipients.len() as u8);
        for recipient in &self.recipients {
            bytes.extend(recipient);
        }
        Ok(bytes)
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_QUERY_BYTES {
            return Err("direct recovery query exceeds bound");
        }
        let mut input = bytes;
        if take(&mut input, 5)? != DIRECT_QUERY {
            return Err("wrong direct recovery query format");
        }
        let workspace = take(&mut input, 32)?.try_into().unwrap();
        let author = take(&mut input, 32)?.try_into().unwrap();
        let epoch = number64(&mut input)?;
        let policy_revision = number64(&mut input)?;
        let after = number64(&mut input)?;
        let through = number64(&mut input)?;
        let topic = read_topic(&mut input)?;
        let count = take(&mut input, 1)?[0] as usize;
        let mut recipients = Vec::with_capacity(count);
        for _ in 0..count {
            recipients.push(take(&mut input, 32)?.try_into().unwrap());
        }
        if !input.is_empty() {
            return Err("trailing direct recovery query");
        }
        let query = Self {
            workspace,
            author,
            epoch,
            policy_revision,
            topic,
            recipients,
            after,
            through,
        };
        query.validate()?;
        Ok(query)
    }
}

pub enum DirectRangeReply {
    Offered(Vec<RecoveredPacket>),
    Unavailable,
}

pub fn unavailable_direct_reply() -> Vec<u8> {
    [DIRECT_REPLY, &[1]].concat()
}

pub fn direct_offer<'a>(
    query: &DirectRangeQuery,
    records: impl IntoIterator<Item = (u64, [u8; 16], u64, &'a [u8])>,
) -> Result<Vec<u8>, &'static str> {
    query.validate()?;
    let records: Vec<_> = records.into_iter().collect();
    if records.len() != (query.through - query.after) as usize {
        return Err("incomplete direct recovery range");
    }
    let mut bytes = DIRECT_REPLY.to_vec();
    bytes.push(0);
    bytes.push(records.len() as u8);
    for (expected, (revision, id, sequence, object)) in
        (query.after + 1..=query.through).zip(records)
    {
        if sequence != expected || object.is_empty() || object.len() > MAX_APPLICATION_CIPHERTEXT {
            return Err("invalid direct recovery record");
        }
        bytes.extend(revision.to_be_bytes());
        bytes.extend(id);
        bytes.extend(sequence.to_be_bytes());
        bytes.extend((object.len() as u32).to_be_bytes());
        bytes.extend(object);
    }
    if bytes.len() > MAX_REPLY_BYTES {
        return Err("direct recovery reply exceeds bound");
    }
    Ok(bytes)
}

pub fn verify_direct_reply(
    owner: &Workspace,
    query: &DirectRangeQuery,
    bytes: &[u8],
) -> Result<DirectRangeReply, &'static str> {
    query.validate()?;
    if bytes.len() > MAX_REPLY_BYTES {
        return Err("direct recovery reply exceeds bound");
    }
    let mut input = bytes;
    if take(&mut input, 5)? != DIRECT_REPLY {
        return Err("wrong direct recovery reply format");
    }
    match take(&mut input, 1)?[0] {
        1 if input.is_empty() => return Ok(DirectRangeReply::Unavailable),
        0 => {}
        _ => return Err("invalid direct recovery reply status"),
    }
    let count = take(&mut input, 1)?[0] as usize;
    if count != (query.through - query.after) as usize {
        return Err("incomplete direct recovery reply");
    }
    let mut packets = Vec::with_capacity(count);
    for expected in query.after + 1..=query.through {
        let revision = number64(&mut input)?;
        let id = take(&mut input, 16)?.try_into().unwrap();
        let sequence = number64(&mut input)?;
        let length = number32(&mut input)?;
        if sequence != expected || length == 0 || length > MAX_APPLICATION_CIPHERTEXT {
            return Err("invalid direct recovery packet");
        }
        let context = PublicationContext {
            workspace: query.workspace,
            revision,
            topic: query.topic.clone(),
            id,
            sequence: std::num::NonZeroU64::new(sequence),
        };
        let object = take(&mut input, length)?.to_vec();
        let authenticated = owner.unprotect_object(
            &context.direct_authenticated_bytes(&query.recipients)?,
            &object,
        )?;
        if authenticated.message.member != query.author {
            return Err("direct recovery author mismatch");
        }
        packets.push(RecoveredPacket {
            context,
            ciphertext: object,
        });
    }
    if !input.is_empty() {
        return Err("trailing direct recovery reply");
    }
    Ok(DirectRangeReply::Offered(packets))
}

#[test]
fn direct_offer_accepts_the_maximum_sequence() {
    let query = DirectRangeQuery {
        workspace: [1; 32],
        author: [2; 32],
        epoch: 3,
        policy_revision: 4,
        topic: Topic::new("direct/recovery").unwrap(),
        recipients: vec![[5; 32]],
        after: u64::MAX - 1,
        through: u64::MAX,
    };
    let records = [(6, [7; 16], u64::MAX, &b"ciphertext"[..])];

    assert!(direct_offer(&query, records).is_ok());
}

#[derive(Clone)]
pub struct AvailableRangeQuery {
    pub workspace: [u8; 32],
    pub author: [u8; 32],
    pub epoch: u64,
    pub policy_revision: u64,
    pub after: u64,
    pub topics: BTreeSet<Topic>,
}

impl AvailableRangeQuery {
    pub fn to_wire(&self) -> Result<Vec<u8>, &'static str> {
        if self.topics.is_empty() || self.topics.len() > MAX_TOPICS {
            return Err("invalid available-range selection");
        }
        let mut bytes = AVAILABLE_QUERY.to_vec();
        bytes.extend(self.workspace);
        bytes.extend(self.author);
        for value in [self.epoch, self.policy_revision, self.after] {
            bytes.extend(value.to_be_bytes());
        }
        bytes.push(self.topics.len() as u8);
        for topic in &self.topics {
            write_topic(&mut bytes, topic);
        }
        Ok(bytes)
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_QUERY_BYTES {
            return Err("available-range query exceeds bound");
        }
        let mut input = bytes;
        if take(&mut input, 5)? != AVAILABLE_QUERY {
            return Err("wrong available-range query format");
        }
        let query = Self {
            workspace: take(&mut input, 32)?.try_into().unwrap(),
            author: take(&mut input, 32)?.try_into().unwrap(),
            epoch: number64(&mut input)?,
            policy_revision: number64(&mut input)?,
            after: number64(&mut input)?,
            topics: read_topics(&mut input)?,
        };
        if !input.is_empty() {
            return Err("trailing available-range query");
        }
        Ok(query)
    }

    pub fn matches(&self, range: &RangeQuery) -> bool {
        self.workspace == range.workspace
            && self.author == range.author
            && self.epoch == range.epoch
            && self.policy_revision == range.policy_revision
            && self.after == range.after
            && self.topics == range.topics
    }
}

pub fn available_offer(query: &RangeQuery, reply: &[u8]) -> Result<Vec<u8>, &'static str> {
    let query = query.to_wire()?;
    let size = AVAILABLE_REPLY.len() + 1 + 4 + query.len() + reply.len();
    if size > MAX_REPLY_BYTES {
        return Err("available-range reply exceeds bound");
    }
    let mut bytes = AVAILABLE_REPLY.to_vec();
    bytes.push(0);
    bytes.extend((query.len() as u32).to_be_bytes());
    bytes.extend(query);
    bytes.extend(reply);
    Ok(bytes)
}

pub fn unavailable_available_reply() -> Vec<u8> {
    [AVAILABLE_REPLY, &[1]].concat()
}

pub fn parse_available_reply(
    request: &AvailableRangeQuery,
    bytes: &[u8],
) -> Result<Option<(RangeQuery, Vec<u8>)>, &'static str> {
    if bytes.len() > MAX_REPLY_BYTES {
        return Err("available-range reply exceeds bound");
    }
    let mut input = bytes;
    if take(&mut input, 5)? != AVAILABLE_REPLY {
        return Err("wrong available-range reply format");
    }
    match take(&mut input, 1)?[0] {
        1 if input.is_empty() => return Ok(None),
        0 => {}
        _ => return Err("invalid available-range reply status"),
    }
    let query_length = number32(&mut input)?;
    let query = RangeQuery::from_wire(take(&mut input, query_length)?)?;
    if !request.matches(&query) {
        return Err("available range does not match request");
    }
    if input.is_empty() {
        return Err("missing available-range proof");
    }
    Ok(Some((query, input.to_vec())))
}

#[derive(Clone)]
pub struct CutoffQuery {
    pub workspace: [u8; 32],
    pub author: [u8; 32],
    pub epoch: u64,
    pub policy_revision: u64,
    pub topics: BTreeSet<Topic>,
    pub nonce: [u8; 32],
}
impl CutoffQuery {
    pub fn request(&self) -> Result<arachne_security::RecoveryCutoffRequest, &'static str> {
        if self.topics.is_empty() || self.topics.len() > MAX_TOPICS {
            return Err("invalid cutoff selection");
        }
        Ok(arachne_security::RecoveryCutoffRequest {
            workspace: self.workspace,
            author: self.author,
            epoch: self.epoch,
            policy_revision: self.policy_revision,
            selection: selection_digest(&self.topics),
            nonce: self.nonce,
        })
    }
    pub fn to_wire(&self) -> Result<Vec<u8>, &'static str> {
        self.request()?;
        let mut bytes = CUTOFF_QUERY.to_vec();
        bytes.extend(self.workspace);
        bytes.extend(self.author);
        bytes.extend(self.epoch.to_be_bytes());
        bytes.extend(self.policy_revision.to_be_bytes());
        bytes.extend(self.nonce);
        bytes.push(self.topics.len() as u8);
        for topic in &self.topics {
            write_topic(&mut bytes, topic);
        }
        Ok(bytes)
    }
    pub fn from_wire(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_QUERY_BYTES {
            return Err("cutoff query exceeds bound");
        }
        let mut input = bytes;
        if take(&mut input, 5)? != CUTOFF_QUERY {
            return Err("wrong cutoff query format");
        }
        let query = Self {
            workspace: take(&mut input, 32)?.try_into().unwrap(),
            author: take(&mut input, 32)?.try_into().unwrap(),
            epoch: number64(&mut input)?,
            policy_revision: number64(&mut input)?,
            nonce: take(&mut input, 32)?.try_into().unwrap(),
            topics: read_topics(&mut input)?,
        };
        if !input.is_empty() {
            return Err("trailing cutoff query");
        }
        Ok(query)
    }
}

/// Use adopted state and the current routing policy under the host's shared lock.
/// Denial reveals no head. A signed head proves neither availability nor delivery.
pub fn serve_cutoff(
    log: &PublisherLog,
    owner: &Workspace,
    policy: &arachne_routing::RoutingTable,
    requester: [u8; 32],
    query: &CutoffQuery,
) -> Result<Vec<u8>, &'static str> {
    if log
        .authorize_history(
            owner,
            policy,
            requester,
            (query.workspace, query.author, query.epoch),
            query.policy_revision,
            &query.topics,
        )
        .is_err()
    {
        return Ok(denied_reply());
    }
    let after = query
        .topics
        .iter()
        .filter_map(|t| log.topics.get(t))
        .map(|h| h.evicted_through)
        .max()
        .unwrap_or(0);
    owner.sign_recovery_window(&query.request()?, after, log.head())
}

/// None is a generic advisory denial, not a zero head. Caller owns nonce lifetime.
pub fn verify_cutoff_reply(
    owner: &Workspace,
    query: &CutoffQuery,
    bytes: &[u8],
) -> Result<Option<u64>, &'static str> {
    let request = query.request()?;
    if bytes == denied_reply() {
        return Ok(None);
    }
    owner.verify_recovery_cutoff(&request, bytes).map(Some)
}

impl RangeQuery {
    pub fn recovery_request(&self) -> Result<RecoveryRequest, &'static str> {
        if self.after >= self.through || self.topics.is_empty() || self.topics.len() > MAX_TOPICS {
            return Err("invalid range query");
        }
        Ok(RecoveryRequest {
            workspace: self.workspace,
            author: self.author,
            epoch: self.epoch,
            selection: selection_digest(&self.topics),
            after: self.after,
            through: self.through,
        })
    }
    pub fn to_wire(&self) -> Result<Vec<u8>, &'static str> {
        self.recovery_request()?;
        let mut bytes = QUERY.to_vec();
        bytes.extend(self.workspace);
        bytes.extend(self.author);
        for value in [self.epoch, self.policy_revision, self.after, self.through] {
            bytes.extend(value.to_be_bytes());
        }
        bytes.push(self.topics.len() as u8);
        for topic in &self.topics {
            write_topic(&mut bytes, topic);
        }
        Ok(bytes)
    }
    pub fn from_wire(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_QUERY_BYTES {
            return Err("range query exceeds bound");
        }
        let mut input = bytes;
        if take(&mut input, 5)? != QUERY {
            return Err("wrong range query format");
        }
        let workspace = take(&mut input, 32)?.try_into().unwrap();
        let author = take(&mut input, 32)?.try_into().unwrap();
        let epoch = number64(&mut input)?;
        let policy_revision = number64(&mut input)?;
        let after = number64(&mut input)?;
        let through = number64(&mut input)?;
        let topics = read_topics(&mut input)?;
        if !input.is_empty() {
            return Err("trailing range query");
        }
        let query = Self {
            workspace,
            author,
            epoch,
            policy_revision,
            after,
            through,
            topics,
        };
        query.recovery_request()?;
        Ok(query)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct RecoveredPacket {
    pub context: PublicationContext,
    pub ciphertext: Vec<u8>,
}
pub struct VerifiedRange<'a> {
    proof: VerifiedRecoveryOffer<'a>,
    packets: Vec<RecoveredPacket>,
}
impl VerifiedRange<'_> {
    pub fn packets(&self) -> &[RecoveredPacket] {
        &self.packets
    }
    /// Required after decrypting each packet in a disposable candidate owner.
    pub fn verify_origin(&self, message: &ApplicationMessage) -> Result<(), &'static str> {
        self.proof.verify_origin(message)
    }
}
pub enum RangeReply<'a> {
    Offered(VerifiedRange<'a>),
    /// Never advance a cursor or discard ratchet keys from this advisory status.
    Rejected(RetrievalError),
}

/// Generic refusal for unsupported/malformed requests or inactive retention.
/// It exposes no membership, policy or history detail and grants no coverage.
pub fn denied_reply() -> Vec<u8> {
    rejected(RetrievalError::Denied)
}

pub fn unavailable_reply() -> Vec<u8> {
    rejected(RetrievalError::History(RangeError::Unavailable))
}

fn rejected(error: RetrievalError) -> Vec<u8> {
    let status = match error {
        RetrievalError::Denied => 1,
        RetrievalError::History(RangeError::Invalid) => 2,
        RetrievalError::History(RangeError::Unavailable) => 3,
        RetrievalError::History(RangeError::Empty) => 4,
        RetrievalError::History(RangeError::TooLarge) => 5,
    };
    let mut bytes = REPLY.to_vec();
    bytes.push(status);
    bytes
}

/// Caller binds requester to authenticated transport and supplies current policy.
/// A denied request does not reveal whether history exists. No partial success.
pub fn serve_range(
    log: &PublisherLog,
    owner: &Workspace,
    policy: &arachne_routing::RoutingTable,
    requester: [u8; 32],
    query: &RangeQuery,
) -> Result<Vec<u8>, &'static str> {
    let range = match log.authorized_range(owner, policy, requester, query) {
        Ok(range) => range,
        Err(error) => return Ok(rejected(error)),
    };
    let offer = range.sign_offer(owner)?;
    let sequenced = range.records().iter().any(|r| r.context.sequence.is_some());
    let size = 9
        + offer.len()
        + range
            .records()
            .iter()
            .map(|r| {
                8 + 1
                    + r.context.topic.as_str().len()
                    + 16
                    + 4
                    + r.ciphertext.len()
                    + if sequenced { 8 } else { 0 }
            })
            .sum::<usize>();
    if size > MAX_REPLY_BYTES {
        return Ok(rejected(RetrievalError::History(RangeError::TooLarge)));
    }
    let mut bytes = if sequenced { SEQUENCED_REPLY } else { REPLY }.to_vec();
    bytes.push(0);
    bytes.extend((offer.len() as u16).to_be_bytes());
    bytes.extend(offer);
    bytes.push(range.records().len() as u8);
    for record in range.records() {
        bytes.extend(record.context.revision.to_be_bytes());
        write_topic(&mut bytes, &record.context.topic);
        bytes.extend(record.context.id);
        if sequenced {
            bytes.extend(record.context.sequence.map_or(0, |n| n.get()).to_be_bytes());
        }
        bytes.extend((record.ciphertext.len() as u32).to_be_bytes());
        bytes.extend(&record.ciphertext);
    }
    Ok(bytes)
}

/// Return the next bounded publisher-signed range after a receiver's durable
/// cursor. The authenticated requester learns no history state on denial.
pub fn serve_available_range(
    log: &PublisherLog,
    owner: &Workspace,
    policy: &arachne_routing::RoutingTable,
    requester: [u8; 32],
    request: &AvailableRangeQuery,
) -> Result<Vec<u8>, &'static str> {
    if log
        .authorize_history(
            owner,
            policy,
            requester,
            (request.workspace, request.author, request.epoch),
            request.policy_revision,
            &request.topics,
        )
        .is_err()
    {
        return Ok(unavailable_available_reply());
    }
    if request.after >= log.head() {
        return Ok(unavailable_available_reply());
    }
    let query = RangeQuery {
        workspace: request.workspace,
        author: request.author,
        epoch: request.epoch,
        policy_revision: request.policy_revision,
        after: request.after,
        through: log
            .head()
            .min(request.after.saturating_add(MAX_RECOVERY_PACKETS as u64)),
        topics: request.topics.clone(),
    };
    let reply = serve_range(log, owner, policy, requester, &query)?;
    available_offer(&query, &reply).or_else(|_| Ok(unavailable_available_reply()))
}

/// The query is locally established. Validate all framing, scope, contexts and
/// ordered hashes before allowing any use of decrypted data or ratchet progress.
pub fn verify_reply<'a>(
    owner: &'a Workspace,
    query: &RangeQuery,
    bytes: &[u8],
) -> Result<RangeReply<'a>, &'static str> {
    let expected = query.recovery_request()?;
    if bytes.len() > MAX_REPLY_BYTES {
        return Err("range reply exceeds bound");
    }
    let mut input = bytes;
    let magic = take(&mut input, 5)?;
    if magic != REPLY && magic != SEQUENCED_REPLY {
        return Err("wrong range reply format");
    }
    let status = take(&mut input, 1)?[0];
    if status != 0 {
        if !input.is_empty() {
            return Err("trailing rejection");
        }
        return Ok(RangeReply::Rejected(match status {
            1 => RetrievalError::Denied,
            2 => RetrievalError::History(RangeError::Invalid),
            3 => RetrievalError::History(RangeError::Unavailable),
            4 => RetrievalError::History(RangeError::Empty),
            5 => RetrievalError::History(RangeError::TooLarge),
            _ => return Err("unknown range status"),
        }));
    }
    let length = number16(&mut input)?;
    let offer = take(&mut input, length)?;
    let count = take(&mut input, 1)?[0] as usize;
    if count > MAX_RECOVERY_PACKETS {
        return Err("invalid reply packet count");
    }
    let mut packets = Vec::with_capacity(count);
    let mut ids = BTreeSet::new();
    let mut last_sequence = query.after;
    for _ in 0..count {
        let revision = number64(&mut input)?;
        let topic = read_topic(&mut input)?;
        let id = take(&mut input, 16)?.try_into().unwrap();
        let sequence = if magic == SEQUENCED_REPLY {
            std::num::NonZeroU64::new(number64(&mut input)?)
        } else {
            None
        };
        if let Some(number) = sequence {
            if number.get() <= last_sequence || number.get() > query.through {
                return Err("publisher sequence outside ordered requested range");
            }
            last_sequence = number.get();
        }
        if !query.topics.contains(&topic) || !ids.insert(id) {
            return Err("unexpected topic or repeated publication ID");
        }
        let length = u32::from_be_bytes(take(&mut input, 4)?.try_into().unwrap()) as usize;
        if length == 0 || length > MAX_APPLICATION_CIPHERTEXT {
            return Err("invalid reply ciphertext length");
        }
        packets.push(RecoveredPacket {
            context: PublicationContext {
                sequence,
                workspace: query.workspace,
                revision,
                topic,
                id,
            },
            ciphertext: take(&mut input, length)?.to_vec(),
        });
    }
    if !input.is_empty() {
        return Err("trailing range reply");
    }
    let proof = owner.verify_recovery_offer(&expected, offer)?;
    let contexts: Vec<_> = packets
        .iter()
        .map(|p| p.context.authenticated_bytes())
        .collect();
    let slices: Vec<_> = contexts
        .iter()
        .zip(&packets)
        .map(|(c, p)| (c.as_slice(), p.ciphertext.as_slice()))
        .collect();
    proof.verify_packets(&slices)?;
    Ok(RangeReply::Offered(VerifiedRange { proof, packets }))
}
fn read_topics(input: &mut &[u8]) -> Result<BTreeSet<Topic>, &'static str> {
    let count = take(input, 1)?[0] as usize;
    if count == 0 || count > MAX_TOPICS {
        return Err("invalid query topic count");
    }
    let mut topics = BTreeSet::new();
    for _ in 0..count {
        let topic = read_topic(input)?;
        if topics.last().is_some_and(|last| last >= &topic) {
            return Err("noncanonical query topics");
        }
        topics.insert(topic);
    }
    Ok(topics)
}

fn write_topic(bytes: &mut Vec<u8>, topic: &Topic) {
    bytes.push(topic.as_str().len() as u8);
    bytes.extend(topic.as_str().as_bytes());
}
fn read_topic(bytes: &mut &[u8]) -> Result<Topic, &'static str> {
    let length = take(bytes, 1)?[0] as usize;
    Topic::new(std::str::from_utf8(take(bytes, length)?).map_err(|_| "invalid topic encoding")?)
        .map_err(|_| "invalid wire topic")
}
fn number32(bytes: &mut &[u8]) -> Result<usize, &'static str> {
    Ok(u32::from_be_bytes(take(bytes, 4)?.try_into().unwrap()) as usize)
}

#[test]
fn query_and_status_framing_are_bounded_and_canonical() {
    let query = RangeQuery {
        workspace: [1; 32],
        author: [2; 32],
        epoch: 3,
        policy_revision: 4,
        after: 5,
        through: 6,
        topics: BTreeSet::from([Topic::new("aaa").unwrap(), Topic::new("bbb").unwrap()]),
    };
    let cutoff = CutoffQuery {
        workspace: query.workspace,
        author: query.author,
        epoch: query.epoch,
        policy_revision: query.policy_revision,
        topics: query.topics.clone(),
        nonce: [8; 32],
    };
    let encoded_cutoff = cutoff.to_wire().unwrap();
    assert_eq!(
        CutoffQuery::from_wire(&encoded_cutoff)
            .unwrap()
            .to_wire()
            .unwrap(),
        encoded_cutoff
    );
    for cut in 0..encoded_cutoff.len() {
        assert!(CutoffQuery::from_wire(&encoded_cutoff[..cut]).is_err());
    }
    let mut malformed = encoded_cutoff.clone();
    malformed.push(0);
    assert!(CutoffQuery::from_wire(&malformed).is_err());
    malformed = encoded_cutoff.clone();
    malformed[117] = 0;
    assert!(CutoffQuery::from_wire(&malformed).is_err());
    malformed = encoded_cutoff.clone();
    malformed[123..126].copy_from_slice(b"aaa");
    assert!(CutoffQuery::from_wire(&malformed).is_err());
    malformed[123..126].copy_from_slice(b"000");
    assert!(CutoffQuery::from_wire(&malformed).is_err());
    assert!(CutoffQuery::from_wire(&vec![0; MAX_QUERY_BYTES + 1]).is_err());
    let empty = CutoffQuery {
        topics: BTreeSet::new(),
        ..cutoff.clone()
    };
    assert!(empty.to_wire().is_err());
    let encoded = query.to_wire().unwrap();
    assert_eq!(
        encoded,
        RangeQuery::from_wire(&encoded).unwrap().to_wire().unwrap()
    );
    for cut in 0..encoded.len() {
        assert!(RangeQuery::from_wire(&encoded[..cut]).is_err());
    }
    let mut changed = encoded.clone();
    changed.extend([0]);
    assert!(RangeQuery::from_wire(&changed).is_err());
    changed = encoded.clone();
    changed[107..110].copy_from_slice(b"aaa"); // Duplicate second topic.
    assert!(RangeQuery::from_wire(&changed).is_err());
    changed[107..110].copy_from_slice(b"000"); // Unsorted topic.
    assert!(RangeQuery::from_wire(&changed).is_err());
    assert!(RangeQuery::from_wire(&vec![0; MAX_QUERY_BYTES + 1]).is_err());
    let largest = RangeQuery {
        topics: (0..64)
            .map(|i| Topic::new(format!("t{i:03}/{}", "a".repeat(123))).unwrap())
            .collect(),
        ..query
    };
    assert!(largest.to_wire().unwrap().len() <= MAX_QUERY_BYTES);
    assert_eq!(
        largest.to_wire().unwrap(),
        RangeQuery::from_wire(&largest.to_wire().unwrap())
            .unwrap()
            .to_wire()
            .unwrap()
    );
    let largest_cutoff = CutoffQuery {
        topics: largest.topics.clone(),
        ..cutoff.clone()
    };
    assert!(largest_cutoff.to_wire().unwrap().len() <= MAX_QUERY_BYTES);
    assert_eq!(
        CutoffQuery::from_wire(&largest_cutoff.to_wire().unwrap())
            .unwrap()
            .to_wire()
            .unwrap(),
        largest_cutoff.to_wire().unwrap()
    );
    let owner = Workspace::create([1; 32], "Reader").unwrap();
    assert_eq!(
        verify_cutoff_reply(&owner, &cutoff, &denied_reply()).unwrap(),
        None
    );
    assert!(verify_cutoff_reply(&owner, &cutoff, b"DFRP\x01\x04").is_err());
    assert!(verify_cutoff_reply(&owner, &cutoff, &vec![0; MAX_REPLY_BYTES + 1]).is_err());
    for error in [
        RetrievalError::Denied,
        RetrievalError::History(RangeError::Invalid),
        RetrievalError::History(RangeError::Unavailable),
        RetrievalError::History(RangeError::Empty),
        RetrievalError::History(RangeError::TooLarge),
    ] {
        let mut reply = rejected(error);
        assert!(matches!(
            verify_reply(&owner, &largest, &reply).unwrap(),
            RangeReply::Rejected(_)
        ));
        reply.push(0);
        assert!(verify_reply(&owner, &largest, &reply).is_err());
    }
    assert!(verify_reply(&owner, &largest, b"DFRP\x01\x06").is_err());
    assert!(verify_reply(&owner, &largest, &vec![0; MAX_REPLY_BYTES + 1]).is_err());
}
