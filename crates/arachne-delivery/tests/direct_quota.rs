//! B7c: direct recovery under the per-author pending quota. Other pending
//! objects of the same author must not block recovery for good: the verified
//! range is admitted as an in-order prefix, and a gap that holds back all of
//! the author's pending objects can always be filled by one object.
use arachne_delivery::inbox::{AUTHOR_QUOTA_EXHAUSTED, InboxStage, ObjectInbox};
use arachne_delivery::wire;
use arachne_routing::{Permissions, PublicationContext, RoutingTable, Topic};
use arachne_security::{PendingJoin, Workspace};
use std::collections::{BTreeMap, BTreeSet};
mod common;
use common::{test_endpoint, test_key};

const REVISION: u64 = 1;

fn author_and_reader() -> (Workspace, Workspace) {
    let admin = Workspace::create(test_key(1), "Publisher").unwrap();
    let (registered, invite, checkpoint) =
        admin.prepare_invitation(u64::MAX, false, false).unwrap();
    let admin = registered.workspace.provisional_copy().unwrap();
    let join = PendingJoin::from_invitation(&invite, &checkpoint, test_key(2), "Reader").unwrap();
    let prepared = admin
        .prepare_admission(test_endpoint(2), join.admission_request().unwrap())
        .unwrap();
    let mut proof = join.join_proof().unwrap();
    proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let reader = join.prepare_workspace(&proof, &prepared.welcome).unwrap();
    let author = prepared.workspace.provisional_copy().unwrap();
    assert_eq!(author.epoch(), reader.epoch());
    (author, reader)
}

fn policy(workspace: [u8; 32], topics: &BTreeSet<Topic>) -> RoutingTable {
    let mut policy = RoutingTable::default();
    policy
        .install_verified_policy(
            workspace,
            REVISION,
            BTreeMap::from([
                (
                    test_endpoint(1),
                    Permissions::Selected {
                        publish: topics.clone(),
                        subscribe: BTreeSet::new(),
                    },
                ),
                (
                    test_endpoint(2),
                    Permissions::Selected {
                        publish: BTreeSet::new(),
                        subscribe: topics.clone(),
                    },
                ),
            ]),
        )
        .unwrap();
    policy
}

struct Setup {
    author: Workspace,
    reader: Workspace,
    recipients: Vec<[u8; 32]>,
    policy: RoutingTable,
}

fn setup(topics: &[&str]) -> Setup {
    let (author, reader) = author_and_reader();
    let topics = topics
        .iter()
        .map(|topic| Topic::new(*topic).unwrap())
        .collect::<BTreeSet<_>>();
    Setup {
        policy: policy(author.id(), &topics),
        recipients: vec![reader.member().unwrap().id()],
        author,
        reader,
    }
}

/// The payload starts with (scope tag, sequence) so the test can check order.
fn payload(tag: u8, sequence: u64, size: usize) -> Vec<u8> {
    let mut payload = vec![tag; size];
    payload[1..9].copy_from_slice(&sequence.to_be_bytes());
    payload
}

/// Send the next direct object of `topic` and keep the sender copy in
/// `sender_inbox`. Returns (context, object) for live delivery.
fn send_direct(
    setup: &mut Setup,
    sender_inbox: &mut ObjectInbox,
    topic: &Topic,
    tag: u8,
    size: usize,
) -> (PublicationContext, Vec<u8>) {
    let sequence = sender_inbox
        .next_direct_sequence(&setup.author, REVISION, topic, &setup.recipients)
        .unwrap();
    let context = PublicationContext {
        workspace: setup.author.id(),
        revision: REVISION,
        topic: topic.clone(),
        id: [
            tag,
            sequence.get() as u8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
        sequence: Some(sequence),
    };
    let object = setup
        .author
        .protect_object(
            topic.namespace().as_bytes(),
            &context
                .direct_authenticated_bytes(&setup.recipients)
                .unwrap(),
            &payload(tag, sequence.get(), size),
        )
        .unwrap();
    *sender_inbox = sender_inbox
        .stage_sent_direct(&setup.author, &context, &setup.recipients, &object)
        .unwrap();
    (context, object)
}

fn send_group(
    setup: &mut Setup,
    topic: &Topic,
    number: u64,
    size: usize,
) -> (PublicationContext, Vec<u8>) {
    let context = PublicationContext {
        workspace: setup.author.id(),
        revision: REVISION,
        topic: topic.clone(),
        id: [b'g', number as u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        sequence: std::num::NonZeroU64::new(number),
    };
    let object = setup
        .author
        .protect_object(
            topic.namespace().as_bytes(),
            &context.authenticated_bytes(),
            &payload(b'g', number, size),
        )
        .unwrap();
    (context, object)
}

fn receive(
    inbox: ObjectInbox,
    reader: &Workspace,
    context: &PublicationContext,
    recipients: &[[u8; 32]],
    object: &[u8],
) -> ObjectInbox {
    match inbox
        .stage_with_recipients(reader, context, recipients, object)
        .unwrap()
    {
        InboxStage::Prepared(next) => *next,
        _ => panic!("live object was not new"),
    }
}

/// Fetch the reader's next direct gap from the holder and stage it.
fn recover_next_gap(
    setup: &Setup,
    holder: &ObjectInbox,
    inbox: &ObjectInbox,
) -> Option<Result<(ObjectInbox, usize), &'static str>> {
    let gap = inbox.next_direct_gap(&setup.reader).unwrap()?;
    let query = wire::DirectRangeQuery {
        workspace: setup.reader.id(),
        author: gap.author,
        epoch: setup.reader.epoch(),
        policy_revision: gap.revision,
        topic: gap.topic,
        recipients: gap.recipients,
        after: gap.after,
        through: gap.through,
    };
    let reply = holder
        .serve_direct_range(
            &setup.author,
            &setup.policy,
            setup.reader.endpoint(),
            &query,
        )
        .unwrap();
    Some(inbox.stage_direct_range(&setup.reader, &query, &reply))
}

/// Deliver and acknowledge the next deliverable object. Returns (tag, sequence).
fn deliver_one(inbox: &mut ObjectInbox, reader: &Workspace) -> Option<(u8, u64)> {
    let pending = inbox.pending(reader).unwrap()?;
    let payload = &pending.message.payload;
    let seen = (
        payload[0],
        u64::from_be_bytes(payload[1..9].try_into().unwrap()),
    );
    *inbox = inbox
        .acknowledge(
            pending.message.member,
            &pending.context.topic,
            pending.counter,
            pending.context.id,
        )
        .unwrap();
    Some(seen)
}

/// Pending group objects of the same author leave room for only part of a
/// direct range. Recovery admits the prefix that fits, and the rest follows
/// after the application acknowledges.
#[test]
fn direct_recovery_admits_the_prefix_that_fits_the_author_quota() {
    let direct = Topic::new("direct/a").unwrap();
    let group = Topic::new("group/g").unwrap();
    let mut setup = setup(&["direct/a", "group/g"]);
    let mut holder = ObjectInbox::new(setup.author.id(), setup.author.epoch());
    let mut inbox = ObjectInbox::new(setup.reader.id(), setup.reader.epoch());
    // Two deliverable 10 KiB group objects of the same author wait.
    for number in 1..=2 {
        let (context, object) = send_group(&mut setup, &group, number, 10 * 1024);
        inbox = receive(inbox, &setup.reader, &context, &[], &object);
    }
    // Three 5 KiB direct objects; only the last arrives live.
    let mut last = None;
    for _ in 1..=3 {
        last = Some(send_direct(
            &mut setup,
            &mut holder,
            &direct,
            b'a',
            5 * 1024,
        ));
    }
    let (context, object) = last.unwrap();
    let recipients = setup.recipients.clone();
    inbox = receive(inbox, &setup.reader, &context, &recipients, &object);

    // The whole verified range (0, 3] does not fit; its first record does.
    let (next, count) = recover_next_gap(&setup, &holder, &inbox)
        .unwrap()
        .expect("prefix of the direct range must be admitted");
    assert_eq!(count, 1);
    inbox = next;
    let gap = inbox.next_direct_gap(&setup.reader).unwrap().unwrap();
    assert_eq!((gap.after, gap.through), (1, 3));

    // The application acknowledges one object per cycle.
    let mut delivered = Vec::new();
    let mut cycles = 0;
    loop {
        cycles += 1;
        assert!(cycles < 16, "direct recovery made no progress");
        if let Some(seen) = deliver_one(&mut inbox, &setup.reader) {
            delivered.push(seen);
        }
        match recover_next_gap(&setup, &holder, &inbox) {
            None => break,
            Some(Ok((next, _))) => inbox = next,
            Some(Err(error)) => assert_eq!(error, AUTHOR_QUOTA_EXHAUSTED),
        }
    }
    while let Some(seen) = deliver_one(&mut inbox, &setup.reader) {
        delivered.push(seen);
    }
    let direct_order: Vec<u64> = delivered
        .iter()
        .filter(|(tag, _)| *tag == b'a')
        .map(|(_, sequence)| *sequence)
        .collect();
    assert_eq!(direct_order, vec![1, 2, 3]);
    let group_order: Vec<u64> = delivered
        .iter()
        .filter(|(tag, _)| *tag == b'g')
        .map(|(_, sequence)| *sequence)
        .collect();
    assert_eq!(group_order, vec![1, 2]);
    assert_eq!(delivered.len(), 5);
}

/// Every pending object of the author waits behind a direct gap, so the
/// application can acknowledge nothing. The object that fills the gap is
/// still admitted, once: the author may go over its quota by one object only.
#[test]
fn a_gap_that_holds_back_all_pending_objects_can_always_be_filled() {
    let scope_a = Topic::new("direct/a").unwrap();
    let scope_b = Topic::new("direct/b").unwrap();
    let mut setup = setup(&["direct/a", "direct/b"]);
    let recipients = setup.recipients.clone();
    // One holder per scope: sender copies have their own 32 KiB budget.
    let mut holder_a = ObjectInbox::new(setup.author.id(), setup.author.epoch());
    let mut holder_b = ObjectInbox::new(setup.author.id(), setup.author.epoch());
    let mut inbox = ObjectInbox::new(setup.reader.id(), setup.reader.epoch());
    const SIZE: usize = 7 * 1024;
    let mut sent_a = Vec::new();
    for _ in 1..=4 {
        sent_a.push(send_direct(&mut setup, &mut holder_a, &scope_a, b'a', SIZE));
    }
    let mut sent_b = Vec::new();
    for _ in 1..=2 {
        sent_b.push(send_direct(&mut setup, &mut holder_b, &scope_b, b'b', SIZE));
    }
    // A2..A4 and B2 arrive live; A1 and B1 are lost. All four wait.
    for (context, object) in sent_a[1..].iter().chain(&sent_b[1..]) {
        inbox = receive(inbox, &setup.reader, context, &recipients, object);
    }
    assert!(inbox.pending(&setup.reader).unwrap().is_none());
    assert_eq!(inbox.pending_count(), 4);

    // Recovery of A1 fills the gap even though the quota is full.
    let (next, count) = recover_next_gap(&setup, &holder_a, &inbox)
        .unwrap()
        .expect("the gap that blocks every pending object must be fillable");
    assert_eq!(count, 1);
    inbox = next;
    // Only one object over the quota: now the author has deliverable work,
    // so B1 waits for the application like any other object.
    let gap = inbox.next_direct_gap(&setup.reader).unwrap().unwrap();
    assert_eq!(gap.topic, scope_b);
    assert_eq!(
        recover_next_gap(&setup, &holder_b, &inbox).unwrap().err(),
        Some(AUTHOR_QUOTA_EXHAUSTED)
    );
    // The same gap filler from live traffic is also refused now.
    assert_eq!(
        inbox
            .stage_with_recipients(&setup.reader, &sent_b[0].0, &recipients, &sent_b[0].1)
            .err(),
        Some(AUTHOR_QUOTA_EXHAUSTED)
    );
    let mut delivered = Vec::new();
    for _ in 0..4 {
        delivered.push(deliver_one(&mut inbox, &setup.reader).unwrap());
    }
    assert_eq!(delivered, vec![(b'a', 1), (b'a', 2), (b'a', 3), (b'a', 4)]);
    let (next, count) = recover_next_gap(&setup, &holder_b, &inbox)
        .unwrap()
        .unwrap();
    assert_eq!(count, 1);
    inbox = next;
    assert!(inbox.next_direct_gap(&setup.reader).unwrap().is_none());
    assert_eq!(deliver_one(&mut inbox, &setup.reader), Some((b'b', 1)));
    assert_eq!(deliver_one(&mut inbox, &setup.reader), Some((b'b', 2)));
    assert!(deliver_one(&mut inbox, &setup.reader).is_none());
}

/// A flooding author still hits the quota with direct traffic when some of
/// its objects are deliverable.
#[test]
fn deliverable_direct_flood_still_hits_the_author_quota() {
    let scope = Topic::new("direct/a").unwrap();
    let mut setup = setup(&["direct/a"]);
    let recipients = setup.recipients.clone();
    let mut holder = ObjectInbox::new(setup.author.id(), setup.author.epoch());
    let mut inbox = ObjectInbox::new(setup.reader.id(), setup.reader.epoch());
    let mut refused = 0;
    for _ in 1..=8 {
        let (context, object) = send_direct(&mut setup, &mut holder, &scope, b'a', 7 * 1024);
        match inbox.stage_with_recipients(&setup.reader, &context, &recipients, &object) {
            Ok(InboxStage::Prepared(next)) => inbox = *next,
            Ok(_) => panic!("live object was not new"),
            Err(error) => {
                assert_eq!(error, AUTHOR_QUOTA_EXHAUSTED);
                refused += 1;
            }
        }
    }
    assert_eq!(inbox.pending_count(), 4);
    assert_eq!(refused, 4);
}
