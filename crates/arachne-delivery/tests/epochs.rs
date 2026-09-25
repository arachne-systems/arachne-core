//! A3: delivery state survives membership steps. Two members at different
//! epochs during a partition exchange data after the partition heals.
mod common;
use common::{test_endpoint, test_key};
use arachne_delivery::inbox::{InboxStage, ObjectInbox};
use arachne_delivery::{PublisherLog, RangeQuery, RetrievalError, wire};
use arachne_routing::{Permissions, PublicationContext, RoutingTable, Topic};
use arachne_security::{
    ManagementAction, PendingJoin, PreparedManagementUpdate, StorageKey, Workspace,
};
use std::collections::{BTreeMap, BTreeSet};

const REVISION: u64 = 7;

fn active(update: PreparedManagementUpdate) -> Workspace {
    match update {
        PreparedManagementUpdate::Active(workspace) => *workspace,
        PreparedManagementUpdate::Removed(_) => panic!("unexpected removal"),
    }
}

/// Register an invitation (one commit), then admit `endpoint` with it.
/// Returns the admin after both steps, the invitation commit and the admission.
fn admit(
    admin: Workspace,
    label: u64,
    name: &str,
) -> (
    Workspace,
    Workspace,
    arachne_security::PreparedManagement,
    arachne_security::PreparedAdmission,
) {
    let (registered, invite, checkpoint) = admin.prepare_invitation(u64::MAX, false, false).unwrap();
    let admin = registered.workspace.provisional_copy().unwrap();
    let endpoint = test_endpoint(label);
    let join = PendingJoin::from_invitation(&invite, &checkpoint, test_key(label), name).unwrap();
    let prepared = admin
        .prepare_admission(endpoint, join.admission_request().unwrap())
        .unwrap();
    let mut proof = join.join_proof().unwrap();
    proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let joined = join.prepare_workspace(&proof, &prepared.welcome).unwrap();
    let admin = prepared.workspace.provisional_copy().unwrap();
    (admin, joined, registered, prepared)
}

fn context(workspace: [u8; 32], sequence: u64, id: u8) -> PublicationContext {
    PublicationContext {
        workspace,
        revision: REVISION,
        topic: Topic::new("chat/room").unwrap(),
        id: [id; 16],
        sequence: std::num::NonZeroU64::new(sequence),
    }
}

fn publish(
    author: &mut Workspace,
    log: &mut PublisherLog,
    id: u8,
) -> (PublicationContext, Vec<u8>) {
    let context = context(author.id(), log.head() + 1, id);
    let object = author
        .protect_object(b"chat", &context.authenticated_bytes(), &[id])
        .unwrap();
    log.append(context.clone(), object.clone()).unwrap();
    (context, object)
}

fn stage(
    inbox: &ObjectInbox,
    owner: &Workspace,
    context: &PublicationContext,
    object: &[u8],
) -> ObjectInbox {
    match inbox.stage(owner, context, object).unwrap() {
        InboxStage::Prepared(next) => *next,
        _ => panic!("object was not new"),
    }
}

fn policy(workspace: [u8; 32]) -> RoutingTable {
    let mut policy = RoutingTable::default();
    policy
        .install_verified_policy(
            workspace,
            REVISION,
            BTreeMap::from([
                (test_endpoint(1), Permissions::AllTopics),
                (test_endpoint(2), Permissions::AllTopics),
                (test_endpoint(3), Permissions::AllTopics),
            ]),
        )
        .unwrap();
    policy
}

fn range(author: &Workspace, epoch: u64, through: u64) -> RangeQuery {
    RangeQuery {
        workspace: author.id(),
        author: author.member().unwrap().id(),
        epoch,
        policy_revision: REVISION,
        after: 0,
        through,
        topics: BTreeSet::from([Topic::new("chat/room").unwrap()]),
    }
}

fn acknowledge(inbox: &ObjectInbox, owner: &Workspace) -> (ObjectInbox, u8) {
    let pending = inbox.pending(owner).unwrap().unwrap();
    let next = inbox
        .acknowledge(
            pending.message.member,
            &pending.context.topic,
            pending.counter,
            pending.context.id,
        )
        .unwrap();
    (next, pending.message.payload[0])
}

#[test]
fn fair_scheduling_gap_fill_and_cross_epoch_dedup() {
    // A (admin) and B both send to C.
    let (a, b, _, _) = admit(Workspace::create(test_key(1), "A").unwrap(), 2, "B");
    let (mut a, c, registered, admission) = admit(a, 3, "C");
    let mut b = active(
        b.prepare_management_update(registered.action, &registered.commit)
            .unwrap(),
    )
    .prepare_admission_update(&admission.authorization, &admission.commit)
    .unwrap();
    assert_eq!((a.epoch(), b.epoch()), (c.epoch(), c.epoch()));
    let mut a_log = PublisherLog::new(&a).unwrap();
    let mut b_log = PublisherLog::new(&b).unwrap();
    let mut inbox = ObjectInbox::new(c.id(), c.epoch());

    // A floods five objects before B's one arrives. B is not starved: each
    // scope gets a turn in round-robin order once work is acknowledged.
    for id in 1..=5 {
        let (context, object) = publish(&mut a, &mut a_log, id);
        inbox = stage(&inbox, &c, &context, &object);
    }
    let (context, object) = publish(&mut b, &mut b_log, 50);
    inbox = stage(&inbox, &c, &context, &object);
    let mut order = Vec::new();
    while inbox.pending_count() > 0 {
        let (next, payload) = acknowledge(&inbox, &c);
        inbox = next;
        order.push(payload);
    }
    assert_eq!(order, [1, 50, 2, 3, 4, 5]);

    // Late (recovered) objects fill gaps below newer ones; replays stay out.
    let objects: Vec<_> = (60..65).map(|id| publish(&mut a, &mut a_log, id)).collect();
    for index in [0, 2, 4, 1, 3] {
        let (context, object) = &objects[index];
        inbox = stage(&inbox, &c, context, object);
    }
    for (context, object) in &objects {
        assert!(matches!(
            inbox.stage(&c, context, object).unwrap(),
            InboxStage::Duplicate
        ));
    }
    assert_eq!(inbox.pending_count(), 5);

    // The same publication re-published under a new epoch (ADR A2 step 10)
    // is a duplicate: its stable id was already delivered.
    let (first_context, _) = &objects[0];
    let previous = a.provisional_copy().unwrap();
    let (registered, _, _) = a.prepare_invitation(u64::MAX, false, false).unwrap();
    a = registered.workspace;
    let c_next = active(
        c.prepare_management_update(registered.action, &registered.commit)
            .unwrap(),
    );
    inbox = inbox.advance(&c, &c_next).unwrap();
    a_log = a_log.advance(&previous, &a).unwrap();
    let mut again = first_context.clone();
    again.sequence = std::num::NonZeroU64::new(a_log.head() + 1);
    let republished = a
        .protect_object(b"chat", &again.authenticated_bytes(), &[60])
        .unwrap();
    assert!(matches!(
        inbox.stage(&c_next, &again, &republished).unwrap(),
        InboxStage::Duplicate
    ));
}

#[test]
fn per_author_quota_and_binary_pending_storage() {
    let (a, b, _, _) = admit(Workspace::create(test_key(1), "A").unwrap(), 2, "B");
    let (mut a, c, registered, admission) = admit(a, 3, "C");
    let mut b = active(
        b.prepare_management_update(registered.action, &registered.commit)
            .unwrap(),
    )
    .prepare_admission_update(&admission.authorization, &admission.commit)
    .unwrap();
    let mut a_log = PublisherLog::new(&a).unwrap();
    let mut b_log = PublisherLog::new(&b).unwrap();
    let c_log = PublisherLog::new(&c).unwrap();
    let mut inbox = ObjectInbox::new(c.id(), c.epoch());
    let size = |inbox: &ObjectInbox| inbox.snapshot_with_publisher(&c, &c_log).unwrap().len();

    // Pending payloads are stored as bytes: a 12 KiB payload costs about
    // 12 KiB, not 3.5 times that.
    let payload = vec![0xa5; arachne_security::MAX_APPLICATION_PAYLOAD];
    let big = |author: &mut Workspace, log: &mut PublisherLog, id: u8| {
        let context = context(author.id(), log.head() + 1, id);
        let object = author
            .protect_object(b"chat", &context.authenticated_bytes(), &payload)
            .unwrap();
        log.append(context.clone(), object.clone()).unwrap();
        (context, object)
    };
    let empty = size(&inbox);
    let (context, object) = big(&mut a, &mut a_log, 1);
    inbox = stage(&inbox, &c, &context, &object);
    let grown = size(&inbox) - empty;
    assert!(
        grown < payload.len() + 512,
        "one pending object costs {grown} bytes"
    );

    // One author cannot fill the inbox: its quota ends first...
    let mut accepted = 1;
    let refused = loop {
        let (context, object) = big(&mut a, &mut a_log, 1 + accepted as u8);
        match inbox.stage(&c, &context, &object) {
            Ok(InboxStage::Prepared(next)) => {
                inbox = *next;
                accepted += 1;
            }
            Ok(_) => panic!("fresh object was not new"),
            Err(error) => break (error, context, object),
        }
    };
    assert_eq!(refused.0, "author pending quota exhausted");
    assert_eq!(
        accepted,
        arachne_delivery::inbox::MAX_PENDING_BYTES_PER_AUTHOR / payload.len()
    );
    // ...while another author still gets in.
    let (context, object) = big(&mut b, &mut b_log, 90);
    inbox = stage(&inbox, &c, &context, &object);
    // The refused object was not recorded: after the application drains
    // some work, the same object is accepted.
    let (drained, _) = acknowledge(&inbox, &c);
    inbox = stage(&drained, &c, &refused.1, &refused.2);
    // Many tiny objects cannot fill the inbox either: metadata counts.
    let mut tiny = ObjectInbox::new(c.id(), c.epoch());
    let mut sent = 0usize;
    let error = loop {
        let mut context = crate::context(a.id(), a_log.head() + 1, 0);
        context.id = (1_000_000 + sent as u128).to_be_bytes();
        let object = a
            .protect_object(b"chat", &context.authenticated_bytes(), &[1])
            .unwrap();
        a_log.append(context.clone(), object.clone()).unwrap();
        match tiny.stage(&c, &context, &object) {
            Ok(InboxStage::Prepared(next)) => {
                tiny = *next;
                sent += 1;
            }
            Ok(_) => panic!("fresh object was not new"),
            Err(error) => break error,
        }
    };
    assert_eq!(error, "author pending quota exhausted");
    assert!(sent <= arachne_delivery::inbox::MAX_PENDING_OBJECTS_PER_AUTHOR);
    let (context, object) = publish(&mut b, &mut b_log, 91);
    stage(&tiny, &c, &context, &object);
    // The binary codec round-trips and rejects truncation and trailing bytes.
    let bytes = inbox.snapshot_with_publisher(&c, &c_log).unwrap();
    let (_, restored) = ObjectInbox::restore_snapshot(&c, &bytes).unwrap();
    assert_eq!(restored.snapshot_with_publisher(&c, &c_log).unwrap(), bytes);
    for cut in (0..bytes.len()).step_by(997) {
        assert!(ObjectInbox::restore_snapshot(&c, &bytes[..cut]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ObjectInbox::restore_snapshot(&c, &trailing).is_err());
}

#[test]
fn publisher_history_never_shrinks_to_make_room_for_inbox_state() {
    let (mut a, mut b, _, _) = admit(Workspace::create(test_key(1), "A").unwrap(), 2, "B");
    let mut a_log = PublisherLog::new(&a).unwrap();
    let payload = vec![7; arachne_security::MAX_APPLICATION_PAYLOAD];
    for id in 0..40u8 {
        let context = context(a.id(), a_log.head() + 1, id);
        let object = a
            .protect_object(b"chat", &context.authenticated_bytes(), &payload)
            .unwrap();
        a_log.append(context, object).unwrap();
    }
    assert!(a_log.snapshot().len() <= arachne_delivery::PUBLISHER_BUDGET);
    // B sends A many direct objects; A keeps recovery copies of them.
    let mut a_inbox = ObjectInbox::new(a.id(), a.epoch());
    let audience = [a.member().unwrap().id()];
    let topic = Topic::new("chat/direct").unwrap();
    for id in 0..16u8 {
        let context = PublicationContext {
            workspace: b.id(),
            revision: REVISION,
            topic: topic.clone(),
            id: [100 + id; 16],
            sequence: std::num::NonZeroU64::new(u64::from(id) + 1),
        };
        let object = b
            .protect_object(
                b"chat",
                &context.direct_authenticated_bytes(&audience).unwrap(),
                &payload,
            )
            .unwrap();
        let InboxStage::Prepared(next) = a_inbox
            .stage_with_recipients(&a, &context, &audience, &object)
            .unwrap()
        else {
            panic!("direct object was not new")
        };
        (a_inbox, _) = acknowledge(&next, &a);
    }
    // Saving never evicts publisher history silently: what is restored is
    // exactly what was retained.
    let bytes = a_inbox.snapshot_with_publisher(&a, &a_log).unwrap();
    let (restored_log, _) = ObjectInbox::restore_snapshot(&a, &bytes).unwrap();
    assert_eq!(restored_log.snapshot(), a_log.snapshot());
    let _ = &mut b;
}

fn direct(
    author: &mut Workspace,
    inbox: &ObjectInbox,
    recipient: [u8; 32],
    id: u8,
) -> (PublicationContext, Vec<u8>) {
    let topic = Topic::new("chat/direct").unwrap();
    let context = PublicationContext {
        workspace: author.id(),
        revision: REVISION,
        topic: topic.clone(),
        id: [id; 16],
        sequence: Some(
            inbox
                .next_direct_sequence(author, REVISION, &topic, &[recipient])
                .unwrap(),
        ),
    };
    let object = author
        .protect_object(
            b"chat",
            &context.direct_authenticated_bytes(&[recipient]).unwrap(),
            &[id],
        )
        .unwrap();
    (context, object)
}

#[test]
fn state_that_names_a_removed_member_does_not_block_restore() {
    let (mut a, mut b, _, _) = admit(Workspace::create(test_key(1), "A").unwrap(), 2, "B");
    let a_member = a.member().unwrap().id();
    let b_member = b.member().unwrap().id();
    let mut a_log = PublisherLog::new(&a).unwrap();
    let mut b_log = PublisherLog::new(&b).unwrap();
    let mut a_inbox = ObjectInbox::new(a.id(), a.epoch());
    let b_inbox = ObjectInbox::new(b.id(), b.epoch());
    // A sends B a direct object (A keeps a sender copy) and B sends A one.
    let (context, object) = direct(&mut a, &a_inbox, b_member, 1);
    a_inbox = a_inbox
        .stage_sent_direct(&a, &context, &[b_member], &object)
        .unwrap();
    let (context, object) = direct(&mut b, &b_inbox, a_member, 2);
    let InboxStage::Prepared(next) = a_inbox
        .stage_with_recipients(&a, &context, &[a_member], &object)
        .unwrap()
    else {
        panic!("direct object was not new")
    };
    (a_inbox, _) = acknowledge(&next, &a);
    // A holds a retained range authored by B.
    publish(&mut b, &mut b_log, 3);
    let query = range(&b, b.epoch(), 1);
    let reply = wire::serve_range(&b_log, &b, &policy(b.id()), a.endpoint(), &query).unwrap();
    a_inbox = a_inbox
        .retain_range(
            &a,
            &query,
            &reply,
            u64::MAX,
            arachne_delivery::UnixSeconds(0),
        )
        .unwrap();
    publish(&mut a, &mut a_log, 4);

    // A removes B. The carried state still saves and restores.
    let removed = a
        .prepare_management(ManagementAction::Remove(b_member))
        .unwrap()
        .workspace;
    let a_inbox = a_inbox.advance(&a, &removed).unwrap();
    let a_log = a_log.advance(&a, &removed).unwrap();
    let bytes = a_inbox.snapshot_with_publisher(&removed, &a_log).unwrap();
    ObjectInbox::restore_snapshot(&removed, &bytes).unwrap();
}

#[test]
fn members_at_different_epochs_exchange_data_after_a_partition_heals() {
    // A and B share an epoch.
    let (mut a, mut b, _, _) = admit(Workspace::create(test_key(1), "A").unwrap(), 2, "B");
    let start = a.epoch();
    assert_eq!(b.epoch(), start);
    let mut a_log = PublisherLog::new(&a).unwrap();
    let mut b_log = PublisherLog::new(&b).unwrap();
    let mut a_inbox = ObjectInbox::new(a.id(), start);
    let mut b_inbox = ObjectInbox::new(b.id(), start);

    // Before the partition B receives A's first object and has not acked it.
    let (a0_context, a0) = publish(&mut a, &mut a_log, 10);
    b_inbox = stage(&b_inbox, &b, &a0_context, &a0);
    // B sends one object that A misses.
    let (b1_context, b1) = publish(&mut b, &mut b_log, 21);
    // A holds a copy of B's range for third-party recovery.
    let held = range(&b, start, 1);
    let held_reply = wire::serve_range(&b_log, &b, &policy(b.id()), a.endpoint(), &held).unwrap();
    a_inbox = a_inbox
        .retain_range(
            &a,
            &held,
            &held_reply,
            u64::MAX,
            arachne_delivery::UnixSeconds(0),
        )
        .unwrap();

    // Partition. A admits C: two epochs. B does not see the commits.
    let previous_a = a.provisional_copy().unwrap();
    let (next_a, c, registered, admission) = admit(a, 3, "C");
    a = next_a;
    assert_eq!(a.epoch(), start + 2);
    // A's delivery state moves forward in the same steps it would be staged.
    let middle = registered.workspace.provisional_copy().unwrap();
    a_log = a_log.advance(&previous_a, &middle).unwrap().advance(&middle, &a).unwrap();
    a_inbox = a_inbox
        .advance(&previous_a, &middle)
        .unwrap()
        .advance(&middle, &a)
        .unwrap();
    assert_eq!(a_log.epochs(), vec![start, start + 1, start + 2]);
    // A holder never serves pre-join history: the held copy of the old
    // epoch is dropped when a member joins.
    assert_eq!(
        a_inbox
            .serve_range(
                &a,
                &policy(a.id()),
                c.endpoint(),
                &held,
                arachne_delivery::UnixSeconds(1)
            )
            .unwrap(),
        wire::unavailable_reply()
    );
    // Both sides keep sending in their own epoch.
    let (a1_context, a1) = publish(&mut a, &mut a_log, 11);
    let (b2_context, b2) = publish(&mut b, &mut b_log, 22);

    // Heal. A (two epochs ahead) accepts B's live object from the old epoch.
    a_inbox = stage(&a_inbox, &a, &b2_context, &b2);
    // B cannot read A's newer epoch yet; nothing is recorded.
    assert_eq!(
        b_inbox.stage(&b, &a1_context, &a1).err(),
        Some("object epoch ahead")
    );
    // A recovers what it missed from B's log of the old epoch.
    let query = range(&b, start, b_log.head());
    let reply = wire::serve_range(&b_log, &b, &policy(b.id()), a.endpoint(), &query).unwrap();
    let wire::RangeReply::Offered(offer) = wire::verify_reply(&a, &query, &reply).unwrap() else {
        panic!("A could not recover B's old epoch");
    };
    for packet in offer.packets() {
        if let InboxStage::Prepared(next) = a_inbox.stage(&a, &packet.context, &packet.ciphertext).unwrap() {
            a_inbox = *next;
        }
    }
    let mut received = Vec::new();
    while let Some(pending) = a_inbox.pending(&a).unwrap() {
        received.push(pending.message.payload[0]);
        a_inbox = a_inbox
            .acknowledge(pending.message.member, &pending.context.topic, pending.counter, pending.context.id)
            .unwrap();
    }
    received.sort_unstable();
    assert_eq!(received, [21, 22]);
    // The live copy of a recovered object is a duplicate.
    assert!(matches!(
        a_inbox.stage(&a, &b1_context, &b1).unwrap(),
        InboxStage::Duplicate
    ));

    // B catches up; its pending object and its old log are carried.
    let previous_b = b.provisional_copy().unwrap();
    let b_middle = active(
        b.prepare_management_update(registered.action, &registered.commit)
            .unwrap(),
    );
    b = b_middle
        .prepare_admission_update(&admission.authorization, &admission.commit)
        .unwrap();
    assert_eq!(b.epoch(), a.epoch());
    b_inbox = b_inbox
        .advance(&previous_b, &b_middle)
        .unwrap()
        .advance(&b_middle, &b)
        .unwrap();
    b_log = b_log
        .advance(&previous_b, &b_middle)
        .unwrap()
        .advance(&b_middle, &b)
        .unwrap();
    assert_eq!(b_inbox.pending_count(), 1);
    b_inbox = stage(&b_inbox, &b, &a1_context, &a1);
    let first = b_inbox.pending(&b).unwrap().unwrap();
    assert_eq!(first.message.payload, [10]);
    assert_eq!(first.epoch, start);

    // The carried state survives save and restore at the new epoch.
    let key = StorageKey::derive(&[9; 32]).unwrap();
    let sealed = b_inbox.seal(&b, &key, &b_log).unwrap();
    let (b, b_log, b_inbox) = ObjectInbox::restore(&key, test_endpoint(2), b.id(), &sealed).unwrap();
    assert_eq!(b_inbox.pending_count(), 2);
    assert_eq!(b_log.epochs(), vec![start, start + 1, start + 2]);

    // Who may recover: current members that were members in that epoch.
    // A still gets B's old epoch after B advanced.
    let old = range(&b, start, 2);
    assert!(b_log.authorized_range(&b, &policy(b.id()), a.endpoint(), &old).is_ok());
    // C joined after it: denied, although C is a current member.
    assert_eq!(
        b_log
            .authorized_range(&b, &policy(b.id()), c.endpoint(), &old)
            .err(),
        Some(RetrievalError::Denied)
    );
    // C cannot decrypt the old epoch either.
    assert_eq!(
        c.unprotect_object(b"chat", &a0_context.authenticated_bytes(), &a0)
            .unwrap_err(),
        "object epoch expired"
    );

    // A removal is never delayed by pending objects: A holds one from B.
    let (mut b, mut b_log) = (b, b_log);
    let (b3_context, b3) = publish(&mut b, &mut b_log, 23);
    let a_inbox = stage(&a_inbox, &a, &b3_context, &b3);
    let removal = a
        .prepare_management(ManagementAction::Remove(b.member().unwrap().id()))
        .unwrap();
    let a_removed = removal.workspace;
    let a_inbox = a_inbox.advance(&a, &a_removed).unwrap();
    // Accepted before the removal, it is still delivered.
    assert_eq!(
        a_inbox.pending(&a_removed).unwrap().unwrap().message.payload,
        [23]
    );
    // After the removal, B's objects fail, also in the old epoch.
    let (b4_context, b4) = publish(&mut b, &mut b_log, 24);
    assert_eq!(
        a_inbox.stage(&a_removed, &b4_context, &b4).err(),
        Some("object author not current")
    );
    // B gets nothing from A's retained history; C still does.
    let a_log = a_log.advance(&a, &a_removed).unwrap();
    let mine = range(&a_removed, a.epoch(), a_log.epoch_log(a.epoch()).unwrap().head());
    let policy = policy(a.id());
    assert_eq!(
        a_log
            .authorized_range(&a_removed, &policy, b.endpoint(), &mine)
            .err(),
        Some(RetrievalError::Denied)
    );
    assert!(
        a_log
            .authorized_range(&a_removed, &policy, c.endpoint(), &mine)
            .is_ok()
    );
}
