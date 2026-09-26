//! B7e: when the receiver evicts direct recovery copies, the scope floor
//! moves past a gap. The skipped sequence is recorded as missed, and a late
//! copy of it is dropped: it is never delivered after newer objects.
use arachne_delivery::inbox::{InboxStage, ObjectInbox};
use arachne_routing::{PublicationContext, Topic};
use arachne_security::{EndpointKey, EndpointSigner, PendingJoin, Workspace};

const REVISION: u64 = 1;
/// One more than the per-scope record window (32).
const LIVE_THROUGH: u64 = 34;

fn author_and_reader() -> (Workspace, Workspace) {
    let admin_key = EndpointKey::generate().unwrap();
    let reader_key = EndpointKey::generate().unwrap();
    let admin = Workspace::create(&admin_key, "Publisher").unwrap();
    let (registered, invite, checkpoint) =
        admin.prepare_invitation(u64::MAX, false, false).unwrap();
    let admin = registered.workspace.provisional_copy().unwrap();
    let join = PendingJoin::from_invitation(&invite, &checkpoint, &reader_key, "Reader").unwrap();
    let prepared = admin
        .prepare_admission(reader_key.endpoint(), join.admission_request().unwrap())
        .unwrap();
    let mut proof = join.join_proof().unwrap();
    proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let reader = join.prepare_workspace(&proof, &prepared.welcome).unwrap();
    let author = prepared.workspace.provisional_copy().unwrap();
    (author, reader)
}

fn direct(author: &mut Workspace, reader: [u8; 32], sequence: u64) -> (PublicationContext, Vec<u8>) {
    let topic = Topic::new("direct/eviction").unwrap();
    let context = PublicationContext {
        workspace: author.id(),
        revision: REVISION,
        topic: topic.clone(),
        id: u128::from(sequence).to_be_bytes(),
        sequence: std::num::NonZeroU64::new(sequence),
    };
    let object = author
        .protect_object(
            topic.namespace().as_bytes(),
            &context.direct_authenticated_bytes(&[reader]).unwrap(),
            &sequence.to_be_bytes(),
        )
        .unwrap();
    (context, object)
}

fn sequence_of(payload: &[u8]) -> u64 {
    u64::from_be_bytes(payload.try_into().unwrap())
}

#[test]
fn eviction_past_a_gap_drops_the_late_object() {
    let (mut author, reader) = author_and_reader();
    let recipient = [reader.member().unwrap().id()];
    let mut inbox = ObjectInbox::new(reader.id(), reader.epoch());
    // Sequence 1 is lost live. 2..=34 arrive and wait behind the gap until
    // the 33rd copy overflows the record window.
    let late = direct(&mut author, recipient[0], 1);
    for sequence in 2..=LIVE_THROUGH {
        let (context, object) = direct(&mut author, recipient[0], sequence);
        let InboxStage::Prepared(next) = inbox
            .stage_with_recipients(&reader, &context, &recipient, &object)
            .unwrap()
        else {
            panic!("live object was not new")
        };
        inbox = *next;
        if sequence < LIVE_THROUGH {
            assert!(inbox.pending(&reader).unwrap().is_none());
        }
    }
    // The eviction gave the gap up (the miss count is reported by the
    // runtime, see arachne-runtime tests/direct_eviction_miss.rs).
    assert!(inbox.next_direct_gap(&reader).unwrap().is_none());
    // The late copy of sequence 1 is dropped, not delivered after newer ones.
    assert!(matches!(
        inbox
            .stage_with_recipients(&reader, &late.0, &recipient, &late.1)
            .unwrap(),
        InboxStage::Duplicate
    ));
    let mut delivered = Vec::new();
    while let Some(pending) = inbox.pending(&reader).unwrap() {
        delivered.push(sequence_of(&pending.message.payload));
        inbox = inbox
            .acknowledge(
                pending.message.member,
                &pending.context.topic,
                pending.counter,
                pending.context.id,
            )
            .unwrap();
        // A late copy stays dropped after the application drains.
        assert!(matches!(
            inbox
                .stage_with_recipients(&reader, &late.0, &recipient, &late.1)
                .unwrap(),
            InboxStage::Duplicate
        ));
    }
    assert_eq!(delivered, (2..=LIVE_THROUGH).collect::<Vec<_>>());
}

#[test]
fn a_late_object_below_an_explicit_miss_is_dropped() {
    let (mut author, reader) = author_and_reader();
    let recipient = [reader.member().unwrap().id()];
    let late = direct(&mut author, recipient[0], 1);
    let (context, object) = direct(&mut author, recipient[0], 2);
    let InboxStage::Prepared(inbox) = ObjectInbox::new(reader.id(), reader.epoch())
        .stage_with_recipients(&reader, &context, &recipient, &object)
        .unwrap()
    else {
        panic!("live object was not new")
    };
    let query = arachne_delivery::wire::DirectRangeQuery {
        workspace: reader.id(),
        author: author.member().unwrap().id(),
        epoch: reader.epoch(),
        policy_revision: REVISION,
        topic: context.topic.clone(),
        recipients: recipient.to_vec(),
        after: 0,
        through: 2,
    };
    let (inbox, missing) = inbox.skip_direct_gap(&reader, &query).unwrap();
    assert_eq!(missing, 1);
    assert!(matches!(
        inbox
            .stage_with_recipients(&reader, &late.0, &recipient, &late.1)
            .unwrap(),
        InboxStage::Duplicate
    ));
    assert_eq!(inbox.pending_count(), 1);
}

/// B7f-2: when an epoch change moves a direct scope's floor past a gap (its
/// copies left the receive window), the skipped sequences count as missed,
/// the same as an eviction (B7e).
#[test]
fn an_epoch_change_past_a_gap_counts_the_skipped_sequences_as_missed() {
    let (mut author, mut reader) = author_and_reader();
    let recipient = [reader.member().unwrap().id()];
    // Sequence 1 is lost live; 2 waits behind the gap.
    let (context, object) = direct(&mut author, recipient[0], 2);
    let InboxStage::Prepared(inbox) = ObjectInbox::new(reader.id(), reader.epoch())
        .stage_with_recipients(&reader, &context, &recipient, &object)
        .unwrap()
    else {
        panic!("live object was not new")
    };
    let mut inbox = *inbox;
    assert_eq!(inbox.missed_direct(), 0);
    // The workspace moves past the receive window: the author registers
    // invitations and the reader follows each step.
    for _ in 0..=arachne_security::RECEIVE_EPOCHS {
        let (prepared, _, _) = author.prepare_invitation(u64::MAX, false, false).unwrap();
        let next = match reader
            .prepare_management_update(prepared.action, &prepared.commit)
            .unwrap()
        {
            arachne_security::PreparedManagementUpdate::Active(next) => *next,
            arachne_security::PreparedManagementUpdate::Removed(_) => panic!("reader removed"),
        };
        inbox = inbox.advance(&reader, &next).unwrap();
        author = prepared.workspace;
        reader = next;
    }
    // The copy of sequence 2 left the window; the floor passed sequence 1.
    assert_eq!(inbox.missed_direct(), 1);
    assert!(inbox.next_direct_gap(&reader).unwrap().is_none());
}
