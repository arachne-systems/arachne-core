//! Exact receive evidence. Stage and persist with the matching receiver owner.
//! No automatic eviction: forgetting a record is not proof of unreceived data.
use super::*;
use arachne_security::ApplicationMessage;

const MAGIC: &[u8] = b"DFRR\x02";
const LEGACY_MAGIC: &[u8] = b"DFRR\x01";
const DELIVERY_MAGIC: &[u8] = b"DFDL\x01";
pub const MAX_RECEIVE_RECORDS: usize = 256;
pub const MAX_RECOVERY_SELECTIONS: usize = 64;
pub const MAX_RECEIVE_SNAPSHOT: usize =
    49 + 80 * MAX_RECEIVE_RECORDS + 72 * MAX_RECOVERY_SELECTIONS;

/// Trusted host candidate. Save/read back the whole snapshot before adopting
/// owner/receipts or releasing publications. This is not an application outbox.
pub struct StagedRecovery {
    pub owner: arachne_security::Workspace,
    pub received: ReceiveJournal,
    /// Legacy sealed bundle from stage_recovery; empty from prepare_recovery.
    pub snapshot: Vec<u8>,
    pub publications: Vec<(PublicationContext, ApplicationMessage)>,
    pub already_received: usize,
}
pub enum RecoveryStage {
    AlreadyCovered,
    Prepared(Box<StagedRecovery>),
    Rejected(RetrievalError),
}

impl PublisherLog {
    /// Stage all three components together; the host must atomically save this
    /// entire record before adopting security, history or receive evidence.
    pub fn seal_with_receipts(
        &self,
        owner: &arachne_security::Workspace,
        key: &arachne_security::StorageKey,
        received: &ReceiveJournal,
    ) -> Result<Vec<u8>, &'static str> {
        self.validate_owner(owner)?;
        if received.workspace != owner.id() || received.epoch != owner.epoch() {
            return Err("receive journal does not match security owner");
        }
        let publisher = self.snapshot();
        let receipts = received.snapshot();
        if 9 + publisher.len() + receipts.len() > arachne_security::MAX_WORKSPACE_ATTACHMENT {
            return Err("combined delivery state exceeds attachment bound");
        }
        let mut attachment = DELIVERY_MAGIC.to_vec();
        attachment.extend((publisher.len() as u32).to_be_bytes());
        attachment.extend(publisher);
        attachment.extend(receipts);
        owner.seal_with_attachment(key, &attachment)
    }

    /// DFRL migration preserves history and starts with no receive evidence.
    /// Legacy restore_sealed deliberately rejects DFDL rather than losing receipts.
    pub fn restore_with_receipts(
        key: &arachne_security::StorageKey,
        endpoint: [u8; 32],
        workspace: [u8; 32],
        sealed: &[u8],
    ) -> Result<(arachne_security::Workspace, Self, ReceiveJournal), &'static str> {
        let (owner, attachment) =
            arachne_security::Workspace::restore_with_attachment(key, endpoint, workspace, sealed)?;
        let author = owner
            .member()
            .ok_or("publisher requires member identity")?
            .id();
        let (log, received) = if attachment.starts_with(super::MAGIC)
            || attachment.starts_with(super::SEQUENCED_MAGIC)
        {
            (
                Self::restore(owner.id(), author, owner.epoch(), &attachment)?,
                ReceiveJournal::new(owner.id(), owner.epoch()),
            )
        } else {
            let mut input = attachment.as_slice();
            if take(&mut input, 5)? != DELIVERY_MAGIC {
                return Err("unsupported delivery state");
            }
            let length = u32::from_be_bytes(take(&mut input, 4)?.try_into().unwrap()) as usize;
            let publisher = take(&mut input, length)?;
            (
                Self::restore(owner.id(), author, owner.epoch(), publisher)?,
                ReceiveJournal::restore(owner.id(), owner.epoch(), input)?,
            )
        };
        Ok((owner, log, received))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveStatus {
    Unseen,
    Known,
    Conflicting,
}
#[derive(Clone)]
pub struct ReceiveJournal {
    workspace: [u8; 32],
    epoch: u64,
    records: BTreeMap<([u8; 32], [u8; 16]), [u8; 32]>,
    progress: BTreeMap<([u8; 32], [u8; 32]), u64>,
}
impl ReceiveJournal {
    /// The host establishes the requested range and current local authorization.
    /// No active state is changed, even if a later packet fails after earlier
    /// decryptions. Unknown MLS errors never count as duplicate evidence.
    pub fn stage_recovery(
        &self,
        owner: &arachne_security::Workspace,
        key: &arachne_security::StorageKey,
        publisher: &PublisherLog,
        query: &RangeQuery,
        reply: &[u8],
    ) -> Result<RecoveryStage, &'static str> {
        let mut result = self.prepare_recovery(owner, publisher, query, reply)?;
        if let RecoveryStage::Prepared(staged) = &mut result {
            staged.snapshot = publisher.seal_with_receipts(&staged.owner, key, &staged.received)?;
        }
        Ok(result)
    }

    /// Prepare native state without a legacy storage envelope. The host must
    /// commit owner and receive evidence together before releasing publications.
    pub fn prepare_recovery(
        &self,
        owner: &arachne_security::Workspace,
        publisher: &PublisherLog,
        query: &RangeQuery,
        reply: &[u8],
    ) -> Result<RecoveryStage, &'static str> {
        publisher.validate_owner(owner)?;
        if self.workspace != owner.id() || self.epoch != owner.epoch() {
            return Err("receive journal does not match security owner");
        }
        let offer = match wire::verify_reply(owner, query, reply)? {
            wire::RangeReply::Rejected(error) => return Ok(RecoveryStage::Rejected(error)),
            wire::RangeReply::Offered(offer) => offer,
        };
        let selection = (query.author, selection_digest(&query.topics));
        let after = self.progress.get(&selection).copied().unwrap_or(0);
        if query.through <= after {
            return Ok(RecoveryStage::AlreadyCovered);
        }
        if query.after != after {
            return Err("recovery range does not continue accepted progress");
        }
        if !self.progress.contains_key(&selection) && self.progress.len() == MAX_RECOVERY_SELECTIONS
        {
            return Err("recovery selection capacity exhausted");
        }
        let mut candidate = owner.provisional_copy()?;
        let mut received = self.clone();
        let mut publications = Vec::new();
        let mut already_received = 0;
        for packet in offer.packets() {
            match received.check(query.author, &packet.context, &packet.ciphertext)? {
                ReceiveStatus::Known => already_received += 1,
                ReceiveStatus::Conflicting => return Err("conflicting received publication"),
                ReceiveStatus::Unseen => {
                    let message = candidate.unprotect_application(
                        &packet.context.authenticated_bytes(),
                        &packet.ciphertext,
                    )?;
                    offer.verify_origin(&message)?;
                    received.record_verified(&message, &packet.context, &packet.ciphertext)?;
                    publications.push((packet.context.clone(), message));
                }
            }
        }
        received.progress.insert(selection, query.through);
        Ok(RecoveryStage::Prepared(Box::new(StagedRecovery {
            owner: candidate,
            received,
            snapshot: Vec::new(),
            publications,
            already_received,
        })))
    }

    pub fn new(workspace: [u8; 32], epoch: u64) -> Self {
        Self {
            workspace,
            epoch,
            records: BTreeMap::new(),
            progress: BTreeMap::new(),
        }
    }
    /// None means no accepted range for this exact selection. Progress covers
    /// the publisher's retained-index sequence, not pre-activation traffic or
    /// application delivery. Candidate progress becomes accepted only on commit.
    pub fn progress(&self, author: [u8; 32], topics: &BTreeSet<Topic>) -> Option<u64> {
        self.progress
            .get(&(author, selection_digest(topics)))
            .copied()
    }
    fn digest(
        &self,
        context: &PublicationContext,
        packet: &[u8],
    ) -> Result<[u8; 32], &'static str> {
        if context.workspace != self.workspace
            || packet.is_empty()
            || packet.len() > MAX_APPLICATION_CIPHERTEXT
        {
            return Err("invalid receive record scope or packet");
        }
        let context = context.authenticated_bytes();
        let mut digest = Sha256::new();
        digest.update(b"data-fabric/receive-record/v1\0");
        digest.update((context.len() as u32).to_be_bytes());
        digest.update(context);
        digest.update((packet.len() as u32).to_be_bytes());
        digest.update(packet);
        Ok(digest.finalize().into())
    }
    /// Recovery callers first verify the complete offer and its author. Unseen
    /// means no retained evidence, not proof that the packet was never received.
    pub fn check(
        &self,
        author: [u8; 32],
        context: &PublicationContext,
        packet: &[u8],
    ) -> Result<ReceiveStatus, &'static str> {
        let digest = self.digest(context, packet)?;
        Ok(match self.records.get(&(author, context.id)) {
            None => ReceiveStatus::Unseen,
            Some(known) if *known == digest => ReceiveStatus::Known,
            Some(_) => ReceiveStatus::Conflicting,
        })
    }
    /// Call only after successful application authentication/context/origin
    /// verification. This is staged evidence until host persistence/adoption.
    pub fn record_verified(
        &mut self,
        message: &ApplicationMessage,
        context: &PublicationContext,
        packet: &[u8],
    ) -> Result<(), &'static str> {
        match self.check(message.member, context, packet)? {
            ReceiveStatus::Known => return Ok(()),
            ReceiveStatus::Conflicting => return Err("conflicting received publication"),
            ReceiveStatus::Unseen => (),
        }
        if self.records.len() == MAX_RECEIVE_RECORDS {
            return Err("receive evidence capacity exhausted");
        }
        self.records
            .insert((message.member, context.id), self.digest(context, packet)?);
        Ok(())
    }
    /// Metadata-only codec; authenticate the whole host record, including the
    /// receiver security snapshot. It provides no rollback protection itself.
    pub fn snapshot(&self) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend(self.workspace);
        bytes.extend(self.epoch.to_be_bytes());
        bytes.extend((self.records.len() as u16).to_be_bytes());
        for ((author, id), digest) in &self.records {
            bytes.extend(author);
            bytes.extend(id);
            bytes.extend(digest);
        }
        bytes.extend((self.progress.len() as u16).to_be_bytes());
        for ((author, selection), through) in &self.progress {
            bytes.extend(author);
            bytes.extend(selection);
            bytes.extend(through.to_be_bytes());
        }
        bytes
    }
    pub fn restore(workspace: [u8; 32], epoch: u64, bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_RECEIVE_SNAPSHOT {
            return Err("receive snapshot exceeds bound");
        }
        let mut input = bytes;
        let version = take(&mut input, 5)?;
        if (version != MAGIC && version != LEGACY_MAGIC)
            || take(&mut input, 32)? != workspace
            || number64(&mut input)? != epoch
        {
            return Err("wrong receive snapshot scope");
        }
        let count = number16(&mut input)?;
        if count > MAX_RECEIVE_RECORDS || input.len() < count * 80 {
            return Err("invalid receive snapshot length");
        }
        let mut journal = Self::new(workspace, epoch);
        for _ in 0..count {
            let author = take(&mut input, 32)?.try_into().unwrap();
            let id = take(&mut input, 16)?.try_into().unwrap();
            if journal
                .records
                .last_key_value()
                .is_some_and(|(last, _)| last >= &(author, id))
            {
                return Err("noncanonical receive records");
            }
            journal
                .records
                .insert((author, id), take(&mut input, 32)?.try_into().unwrap());
        }
        if version == MAGIC {
            let count = number16(&mut input)?;
            if count > MAX_RECOVERY_SELECTIONS || input.len() != count * 72 {
                return Err("invalid recovery progress length");
            }
            for _ in 0..count {
                let author = take(&mut input, 32)?.try_into().unwrap();
                let selection = take(&mut input, 32)?.try_into().unwrap();
                let through = number64(&mut input)?;
                if through == 0
                    || journal
                        .progress
                        .last_key_value()
                        .is_some_and(|(last, _)| last >= &(author, selection))
                {
                    return Err("noncanonical recovery progress");
                }
                journal.progress.insert((author, selection), through);
            }
        }
        if !input.is_empty() {
            return Err("trailing receive snapshot");
        }
        Ok(journal)
    }
}

#[test]
fn combined_delivery_state_rejects_corruption_and_scope_mismatch() {
    use arachne_security::{StorageKey, Workspace};
    let owner = Workspace::create([1; 32], "Publisher").unwrap();
    let key = StorageKey::derive(&[9; 32]).unwrap();
    let log = PublisherLog::new(owner.id(), owner.member().unwrap().id(), owner.epoch());
    let received = ReceiveJournal::new(owner.id(), owner.epoch());
    let saved = log.seal_with_receipts(&owner, &key, &received).unwrap();
    assert!(
        log.seal_with_receipts(&owner, &key, &ReceiveJournal::new([0; 32], owner.epoch()))
            .is_err()
    );
    assert!(
        log.seal_with_receipts(
            &owner,
            &key,
            &ReceiveJournal::new(owner.id(), owner.epoch() + 1)
        )
        .is_err()
    );
    assert!(
        PublisherLog::new(owner.id(), [0; 32], owner.epoch())
            .seal_with_receipts(&owner, &key, &received)
            .is_err()
    );
    assert!(PublisherLog::restore_with_receipts(&key, [2; 32], owner.id(), &saved).is_err());
    assert!(PublisherLog::restore_with_receipts(&key, [1; 32], [0; 32], &saved).is_err());
    let mut tampered = saved.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(PublisherLog::restore_with_receipts(&key, [1; 32], owner.id(), &tampered).is_err());
    let (_, attachment) =
        Workspace::restore_with_attachment(&key, [1; 32], owner.id(), &saved).unwrap();
    // These malformed attachments have valid outer authentication: the delivery
    // decoder must reject them without relying on AEAD to catch structural errors.
    let mut malformed = vec![attachment[..attachment.len() - 1].to_vec()];
    let mut trailing = attachment.to_vec();
    trailing.push(0);
    malformed.push(trailing);
    for length in [0u32, u32::MAX] {
        let mut bytes = attachment.to_vec();
        bytes[5..9].copy_from_slice(&length.to_be_bytes());
        malformed.push(bytes);
    }
    let mut unsupported = attachment.to_vec();
    unsupported[4] = 2;
    malformed.push(unsupported);
    let mut wrong_epoch = attachment.to_vec();
    let receipt_offset = 9 + log.snapshot().len();
    wrong_epoch[receipt_offset + 37..receipt_offset + 45]
        .copy_from_slice(&(owner.epoch() + 1).to_be_bytes());
    malformed.push(wrong_epoch);
    for bytes in malformed {
        let sealed = owner.seal_with_attachment(&key, &bytes).unwrap();
        assert!(PublisherLog::restore_with_receipts(&key, [1; 32], owner.id(), &sealed).is_err());
    }
    // Synthetic opaque records exercise aggregate storage bounds, not MLS.
    let mut full_log = log.clone();
    for n in 0u128..64 {
        full_log
            .append(
                PublicationContext {
                    sequence: None,
                    workspace: owner.id(),
                    revision: 1,
                    topic: Topic::new(format!("{n:03}")).unwrap(),
                    id: n.to_be_bytes(),
                },
                vec![1; 8090],
            )
            .unwrap();
    }
    let mut full_receipts = received.clone();
    for n in 0u128..MAX_RECEIVE_RECORDS as u128 {
        full_receipts
            .records
            .insert(([1; 32], n.to_be_bytes()), [2; 32]);
    }
    assert!(full_log.seal(&owner, &key).is_ok());
    assert_eq!(
        full_log
            .seal_with_receipts(&owner, &key, &full_receipts)
            .unwrap_err(),
        "combined delivery state exceeds attachment bound"
    );
}

#[test]
fn exact_receive_evidence_is_scoped_bounded_and_non_evicting() {
    let mut journal = ReceiveJournal::new([1; 32], 3);
    let message = ApplicationMessage {
        member: [2; 32],
        endpoint: [4; 32],
        payload: vec![],
    };
    // Synthetic verified-message objects here test only the journal's codec and
    // bounds. The separate MLS test establishes real authentication behavior.
    let context = |id: u128| PublicationContext {
        sequence: None,
        workspace: [1; 32],
        revision: 7,
        topic: Topic::new("sample").unwrap(),
        id: id.to_be_bytes(),
    };
    for id in 0..MAX_RECEIVE_RECORDS {
        journal
            .record_verified(&message, &context(id as u128), &[1])
            .unwrap();
    }
    assert_eq!(
        journal.check(message.member, &context(0), &[1]).unwrap(),
        ReceiveStatus::Known
    );
    assert_eq!(
        journal.check(message.member, &context(0), &[2]).unwrap(),
        ReceiveStatus::Conflicting
    );
    assert_eq!(
        journal.check([9; 32], &context(0), &[1]).unwrap(),
        ReceiveStatus::Unseen
    );
    let mut changed = context(0);
    changed.revision += 1;
    assert_eq!(
        journal.check(message.member, &changed, &[1]).unwrap(),
        ReceiveStatus::Conflicting
    );
    let before = journal.snapshot();
    journal
        .record_verified(&message, &context(0), &[1])
        .unwrap();
    assert!(
        journal
            .record_verified(&message, &context(999), &[1])
            .is_err()
    );
    assert!(
        journal
            .record_verified(&message, &context(0), &[2])
            .is_err()
    );
    assert_eq!(journal.snapshot(), before);
    assert_eq!(before.len(), 49 + 80 * MAX_RECEIVE_RECORDS);
    let restored = ReceiveJournal::restore([1; 32], 3, &before).unwrap();
    assert_eq!(restored.snapshot(), before);
    assert!(ReceiveJournal::restore([9; 32], 3, &before).is_err());
    assert!(ReceiveJournal::restore([1; 32], 4, &before).is_err());
    assert!(ReceiveJournal::restore([1; 32], 3, &before[..before.len() - 1]).is_err());
    assert!(ReceiveJournal::restore([1; 32], 3, &vec![0; MAX_RECEIVE_SNAPSHOT + 1]).is_err());
    let mut duplicate = before.clone();
    duplicate.copy_within(47..127, 127);
    assert!(ReceiveJournal::restore([1; 32], 3, &duplicate).is_err());
    let mut legacy = before[..before.len() - 2].to_vec();
    legacy[4] = 1;
    let migrated = ReceiveJournal::restore([1; 32], 3, &legacy).unwrap();
    assert_eq!(migrated.records, journal.records);
    assert!(migrated.progress.is_empty());
    legacy.push(0);
    assert!(ReceiveJournal::restore([1; 32], 3, &legacy).is_err());
    // Synthetic metadata exercises the bounded canonical progress codec.
    for n in 0..MAX_RECOVERY_SELECTIONS {
        journal
            .progress
            .insert(([2; 32], [n as u8; 32]), n as u64 + 1);
    }
    let encoded = journal.snapshot();
    assert_eq!(encoded.len(), MAX_RECEIVE_SNAPSHOT);
    assert_eq!(
        ReceiveJournal::restore([1; 32], 3, &encoded)
            .unwrap()
            .snapshot(),
        encoded
    );
    let offset = before.len();
    let mut duplicate = encoded.clone();
    duplicate.copy_within(offset..offset + 72, offset + 72);
    assert!(ReceiveJournal::restore([1; 32], 3, &duplicate).is_err());
    let mut zero = encoded.clone();
    zero[offset + 64..offset + 72].fill(0);
    assert!(ReceiveJournal::restore([1; 32], 3, &zero).is_err());
    let mut excessive = encoded.clone();
    excessive[offset - 2..offset].copy_from_slice(&65u16.to_be_bytes());
    assert!(ReceiveJournal::restore([1; 32], 3, &excessive).is_err());
}

#[test]
fn live_then_recovery_skips_exact_receipts_but_not_lost_keys() {
    use arachne_security::{PendingJoin, StorageKey, Workspace};
    let admin = Workspace::create([1; 32], "Publisher").unwrap();
    let (invite, checkpoint) = admin.issue_invitation().unwrap();
    let pending = PendingJoin::from_invitation(&invite, &checkpoint, [2; 32], "Reader").unwrap();
    let prepared = admin
        .prepare_admission([2; 32], pending.admission_request().unwrap())
        .unwrap();
    let mut join = pending.join_proof().unwrap();
    join.apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let reader = pending.prepare_workspace(&join, &prepared.welcome).unwrap();
    let mut sender = prepared.workspace;
    let key = StorageKey::derive(&[9; 32]).unwrap();
    let pristine = reader.seal(&key).unwrap();
    let id = reader.id();
    let author = sender.member().unwrap().id();
    let mut log = PublisherLog::new(id, author, sender.epoch());
    let topic = Topic::new("sample").unwrap();
    for number in 1u128..=8 {
        let context = PublicationContext {
            sequence: if number == 1 {
                None
            } else {
                std::num::NonZeroU64::new(number as u64)
            },
            workspace: id,
            revision: 1,
            topic: topic.clone(),
            id: number.to_be_bytes(),
        };
        let packet = sender
            .protect_application(&context.authenticated_bytes(), &number.to_be_bytes())
            .unwrap();
        log.append(context, packet).unwrap();
    }
    let mut policy = arachne_routing::RoutingTable::default();
    policy
        .install_verified_policy(
            id,
            1,
            BTreeMap::from([
                (
                    [1; 32],
                    arachne_routing::Permissions::Selected {
                        publish: BTreeSet::from([topic.clone(), Topic::new("busy").unwrap()]),
                        subscribe: BTreeSet::new(),
                    },
                ),
                (
                    [2; 32],
                    arachne_routing::Permissions::Selected {
                        publish: BTreeSet::new(),
                        subscribe: BTreeSet::from([topic.clone()]),
                    },
                ),
            ]),
        )
        .unwrap();
    let query = RangeQuery {
        workspace: id,
        author,
        epoch: sender.epoch(),
        policy_revision: 1,
        after: 0,
        through: 8,
        topics: BTreeSet::from([topic]),
    };
    let response = wire::serve_range(&log, &sender, &policy, [2; 32], &query).unwrap();
    assert_eq!(&response[..5], b"DFRP\x02");
    let offer_len = u16::from_be_bytes(response[6..8].try_into().unwrap()) as usize;
    let first_sequence_offset = 9 + offer_len + 8 + 1 + "sample".len() + 16;
    let mut invented = response.clone();
    invented[first_sequence_offset..first_sequence_offset + 8].copy_from_slice(&1u64.to_be_bytes());
    assert!(wire::verify_reply(&reader, &query, &invented).is_err());
    invented[first_sequence_offset..first_sequence_offset + 8]
        .copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        wire::verify_reply(&reader, &query, &invented).err(),
        Some("publisher sequence outside ordered requested range")
    );
    assert!(wire::verify_reply(&reader, &query, &response[..response.len() - 1]).is_err());
    let wire::RangeReply::Offered(mixed) = wire::verify_reply(&reader, &query, &response).unwrap()
    else {
        panic!("expected mixed-format offered range");
    };
    assert_eq!(mixed.packets()[0].context.sequence, None);
    assert_eq!(mixed.packets()[7].context.sequence.unwrap().get(), 8);

    let records = log.select(0, 8, &query.topics).unwrap();
    let first = records.records()[0];
    let last = records.records()[7];

    // Positive path: a committed live packet appears again in a complete offer.
    let mut reader = Workspace::restore(&key, [2; 32], id, &pristine).unwrap();
    let mut journal = ReceiveJournal::new(id, reader.epoch());
    let message = reader
        .unprotect_application(&first.context.authenticated_bytes(), &first.ciphertext)
        .unwrap();
    journal
        .record_verified(&message, &first.context, &first.ciphertext)
        .unwrap();
    let mut outgoing = PublisherLog::new(id, reader.member().unwrap().id(), reader.epoch());
    let outgoing_context = PublicationContext {
        sequence: None,
        workspace: id,
        revision: 1,
        topic: Topic::new("reply").unwrap(),
        id: [99; 16],
    };
    let outgoing_ciphertext = reader
        .protect_application(&outgoing_context.authenticated_bytes(), b"retained reply")
        .unwrap();
    outgoing
        .append(outgoing_context, outgoing_ciphertext.clone())
        .unwrap();
    // Migration cannot manufacture receipts for earlier receptions.
    let legacy = outgoing.seal(&reader, &key).unwrap();
    let (_, migrated, empty) =
        PublisherLog::restore_with_receipts(&key, [2; 32], id, &legacy).unwrap();
    assert_eq!(migrated.snapshot(), outgoing.snapshot());
    assert_eq!(
        empty
            .check(author, &first.context, &first.ciphertext)
            .unwrap(),
        ReceiveStatus::Unseen
    );
    let saved = outgoing
        .seal_with_receipts(&reader, &key, &journal)
        .unwrap();
    assert!(PublisherLog::restore_sealed(&key, [2; 32], id, &saved).is_err());
    let (reader, outgoing, journal) =
        PublisherLog::restore_with_receipts(&key, [2; 32], id, &saved).unwrap();
    let wire::RangeReply::Offered(offer) = wire::verify_reply(&reader, &query, &response).unwrap()
    else {
        panic!("expected offer")
    };
    // A correctly signed but invalid later ciphertext must discard all earlier
    // staged ratchet changes. Signature authenticity does not imply valid MLS.
    let mut corrupt_log = log.clone();
    corrupt_log
        .topics
        .get_mut(&Topic::new("sample").unwrap())
        .unwrap()
        .records[2]
        .ciphertext[0] ^= 1;
    let corrupt_reply = wire::serve_range(&corrupt_log, &sender, &policy, [2; 32], &query).unwrap();
    assert!(matches!(
        wire::verify_reply(&reader, &query, &corrupt_reply).unwrap(),
        wire::RangeReply::Offered(_)
    ));
    assert!(
        journal
            .stage_recovery(&reader, &key, &outgoing, &query, &corrupt_reply)
            .is_err()
    );
    let mut full = journal.clone();
    // Synthetic unrelated receipt metadata fills the bound. Actual MLS decryption
    // of the next wanted packet still occurs before capacity rejection.
    for n in 0u128..255 {
        full.records.insert(([99; 32], n.to_be_bytes()), [7; 32]);
    }
    let full_before = full.snapshot();
    assert_eq!(
        full.stage_recovery(&reader, &key, &outgoing, &query, &response)
            .err(),
        Some("receive evidence capacity exhausted")
    );
    assert_eq!(full.snapshot(), full_before);

    assert!(matches!(
        journal
            .stage_recovery(&reader, &key, &outgoing, &query, &wire::denied_reply())
            .unwrap(),
        RecoveryStage::Rejected(RetrievalError::Denied)
    ));
    let RecoveryStage::Prepared(staged) = journal
        .stage_recovery(&reader, &key, &outgoing, &query, &response)
        .unwrap()
    else {
        panic!("expected prepared recovery");
    };
    assert_eq!(staged.already_received, 1);
    assert_eq!(
        staged
            .publications
            .iter()
            .map(|(_, m)| m.payload.clone())
            .collect::<Vec<_>>(),
        (2u128..=8)
            .map(|n| n.to_be_bytes().to_vec())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        journal
            .check(author, &last.context, &last.ciphertext)
            .unwrap(),
        ReceiveStatus::Unseen
    );
    // The failed candidate did not damage the active receiver: the valid retry
    // above decrypted all seven messages. Its result is still only staged in RAM.
    assert_eq!(staged.owner.id(), id);
    assert_eq!(staged.owner.epoch(), reader.epoch());
    let expected_receipts = staged.received.snapshot();
    let saved = staged.snapshot;
    let (restored_owner, restored_outgoing, restored) =
        PublisherLog::restore_with_receipts(&key, [2; 32], id, &saved).unwrap();
    assert_eq!(restored.snapshot(), expected_receipts);
    assert_eq!(restored.progress(author, &query.topics), Some(8));
    assert_eq!(journal.progress(author, &query.topics), None);
    assert!(matches!(
        restored
            .stage_recovery(&restored_owner, &key, &restored_outgoing, &query, &response)
            .unwrap(),
        RecoveryStage::AlreadyCovered
    ));
    assert_eq!(restored_outgoing.snapshot(), outgoing.snapshot());
    assert_eq!(restored_outgoing.head(), 1);
    assert_eq!(
        restored_outgoing
            .select(0, 1, &BTreeSet::from([Topic::new("reply").unwrap()]))
            .unwrap()
            .records()[0]
            .ciphertext,
        outgoing_ciphertext
    );
    for packet in offer.packets() {
        assert_eq!(
            restored
                .check(author, &packet.context, &packet.ciphertext)
                .unwrap(),
            ReceiveStatus::Known
        );
    }
    drop(offer);
    assert_eq!(restored.progress([99; 32], &query.topics), None);
    assert_eq!(
        restored.progress(author, &BTreeSet::from([Topic::new("busy").unwrap()])),
        None
    );
    // No selected publications in (8,12], but the index contains busy traffic.
    let mut later_sender =
        Workspace::restore(&key, [1; 32], id, &sender.seal(&key).unwrap()).unwrap();
    let mut later_log = log.clone();
    for n in 9u128..=12 {
        let context = PublicationContext {
            sequence: None,
            workspace: id,
            revision: 1,
            topic: Topic::new("busy").unwrap(),
            id: n.to_be_bytes(),
        };
        let ciphertext = later_sender
            .protect_application(&context.authenticated_bytes(), &n.to_be_bytes())
            .unwrap();
        later_log.append(context, ciphertext).unwrap();
    }
    let mut continuation = RangeQuery {
        workspace: id,
        author,
        epoch: reader.epoch(),
        policy_revision: 1,
        after: 8,
        through: 12,
        topics: query.topics.clone(),
    };
    for invalid_after in [7, 9] {
        continuation.after = invalid_after;
        let reply =
            wire::serve_range(&later_log, &later_sender, &policy, [2; 32], &continuation).unwrap();
        assert_eq!(
            restored
                .stage_recovery(
                    &restored_owner,
                    &key,
                    &restored_outgoing,
                    &continuation,
                    &reply
                )
                .err(),
            Some("recovery range does not continue accepted progress")
        );
    }
    continuation.after = 8;
    assert!(matches!(
        restored
            .stage_recovery(
                &restored_owner,
                &key,
                &restored_outgoing,
                &continuation,
                b"DFRP\x01\x04"
            )
            .unwrap(),
        RecoveryStage::Rejected(RetrievalError::History(RangeError::Empty))
    ));
    assert_eq!(restored.progress(author, &query.topics), Some(8));
    let reply =
        wire::serve_range(&later_log, &later_sender, &policy, [2; 32], &continuation).unwrap();
    let RecoveryStage::Prepared(empty) = restored
        .stage_recovery(
            &restored_owner,
            &key,
            &restored_outgoing,
            &continuation,
            &reply,
        )
        .unwrap()
    else {
        panic!("expected signed empty continuation");
    };
    assert!(empty.publications.is_empty());
    assert_eq!(empty.received.progress(author, &query.topics), Some(12));
    assert_eq!(restored.progress(author, &query.topics), Some(8));
    let (_, _, committed) =
        PublisherLog::restore_with_receipts(&key, [2; 32], id, &empty.snapshot).unwrap();
    assert_eq!(committed.progress(author, &query.topics), Some(12));
    let mut full_selections = journal.clone();
    for n in 0..MAX_RECOVERY_SELECTIONS {
        full_selections
            .progress
            .insert(([99; 32], [n as u8; 32]), 1);
    }
    assert_eq!(
        full_selections
            .stage_recovery(&reader, &key, &outgoing, &query, &response)
            .err(),
        Some("recovery selection capacity exhausted")
    );

    // Counterexample: accepting generation 7 first loses an older wanted key.
    let mut late = Workspace::restore(&key, [2; 32], id, &pristine).unwrap();
    let mut journal = ReceiveJournal::new(id, late.epoch());
    let message = late
        .unprotect_application(&last.context.authenticated_bytes(), &last.ciphertext)
        .unwrap();
    journal
        .record_verified(&message, &last.context, &last.ciphertext)
        .unwrap();
    let saved = late
        .seal_with_attachment(&key, &journal.snapshot())
        .unwrap();
    let (late, bytes) = Workspace::restore_with_attachment(&key, [2; 32], id, &saved).unwrap();
    let journal = ReceiveJournal::restore(id, late.epoch(), &bytes).unwrap();
    assert!(matches!(
        wire::verify_reply(&late, &query, &response).unwrap(),
        wire::RangeReply::Offered(_)
    ));
    assert_eq!(
        journal
            .check(author, &first.context, &first.ciphertext)
            .unwrap(),
        ReceiveStatus::Unseen
    );
    assert_eq!(
        journal
            .check(author, &last.context, &last.ciphertext)
            .unwrap(),
        ReceiveStatus::Known
    );
    let late_outgoing = PublisherLog::new(id, late.member().unwrap().id(), late.epoch());
    assert_eq!(
        journal
            .stage_recovery(&late, &key, &late_outgoing, &query, &response)
            .err(),
        Some("application authentication or replay check failed")
    );
    let (mut missing, _) = Workspace::restore_with_attachment(&key, [2; 32], id, &saved).unwrap();
    let missing_error = missing
        .unprotect_application(&first.context.authenticated_bytes(), &first.ciphertext)
        .unwrap_err();
    let (mut duplicate, _) = Workspace::restore_with_attachment(&key, [2; 32], id, &saved).unwrap();
    let replay_error = duplicate
        .unprotect_application(&last.context.authenticated_bytes(), &last.ciphertext)
        .unwrap_err();
    assert_eq!(missing_error, replay_error);
    assert_eq!(
        missing_error,
        "application authentication or replay check failed"
    );
    // Never turn that shared error into "already delivered" for the unknown packet.
    assert_eq!(journal.snapshot(), bytes.as_slice());
}
