//! B7 on the object path: automatic recovery of large objects is served as
//! the largest author-signed prefix that fits one reply, and the requester
//! continues from it until the whole history is covered.
mod common;
use common::{test_endpoint, test_key};
use arachne_delivery::inbox::{InboxStage, ObjectInbox};
use arachne_delivery::{PublisherLog, wire};
use arachne_routing::{Permissions, PublicationContext, RoutingTable, Topic};
use arachne_security::{MAX_APPLICATION_PAYLOAD, PendingJoin, Workspace};
use std::collections::{BTreeMap, BTreeSet};

const REVISION: u64 = 1;

/// Register an invitation, then admit `[2; 32]`. Returns (author, reader)
/// at the same epoch.
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

#[test]
fn automatic_recovery_serves_byte_bounded_prefix_and_continues() {
    let (mut sender, reader) = author_and_reader();
    let id = sender.id();
    let author = sender.member().unwrap().id();
    let topic = Topic::new("sample").unwrap();
    let topics = BTreeSet::from([topic.clone()]);
    let mut log = PublisherLog::new(&sender).unwrap();
    // Fourteen full-size objects fit the 192 KiB publisher budget but not
    // one 128 KiB reply.
    let head = 14u64;
    for number in 1..=head {
        let context = PublicationContext {
            sequence: std::num::NonZeroU64::new(number),
            workspace: id,
            revision: REVISION,
            topic: topic.clone(),
            id: u128::from(number).to_be_bytes(),
        };
        let mut payload = vec![number as u8; MAX_APPLICATION_PAYLOAD];
        payload[..8].copy_from_slice(&number.to_be_bytes());
        let object = sender
            .protect_object(
                topic.namespace().as_bytes(),
                &context.authenticated_bytes(),
                &payload,
            )
            .unwrap();
        log.append(context, object).unwrap();
    }
    assert_eq!(log.head(), head);
    assert!(head as usize * MAX_APPLICATION_PAYLOAD > wire::MAX_REPLY_BYTES);
    let mut policy = RoutingTable::default();
    policy
        .install_verified_policy(
            id,
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
    let epoch = sender.epoch();
    let mut inbox = ObjectInbox::new(reader.id(), reader.epoch());
    let mut delivered = Vec::new();
    let mut ranges = Vec::new();
    while inbox.recovery_progress(author, epoch, &topics) < head {
        assert!(ranges.len() < head as usize, "recovery made no progress");
        let after = inbox.recovery_progress(author, epoch, &topics);
        let request = wire::AvailableRangeQuery {
            workspace: id,
            author,
            epoch,
            policy_revision: REVISION,
            after,
            topics: topics.clone(),
        };
        let reply =
            wire::serve_available_range(&log, &sender, &policy, reader.endpoint(), &request)
                .unwrap();
        assert!(reply.len() <= wire::MAX_REPLY_BYTES);
        let (query, reply) = wire::parse_available_reply(&request, &reply)
            .unwrap()
            .expect("holder must serve the largest prefix that fits");
        assert_eq!(query.after, after);
        assert!(query.through > query.after && query.through <= head);
        let offer = match wire::verify_reply(&reader, &query, &reply).unwrap() {
            wire::RangeReply::Offered(offer) => offer,
            wire::RangeReply::Rejected(error) => panic!("holder rejected range: {error:?}"),
        };
        // Every sequence in (after, through] is present; nothing beyond.
        let sequences: Vec<u64> = offer
            .packets()
            .iter()
            .map(|packet| packet.context.sequence.unwrap().get())
            .collect();
        assert_eq!(sequences, ((after + 1)..=query.through).collect::<Vec<_>>());
        for packet in offer.packets() {
            let InboxStage::Prepared(next) = inbox
                .stage(&reader, &packet.context, &packet.ciphertext)
                .unwrap()
            else {
                panic!("recovered object was not new")
            };
            // The application drains each object; the per-author pending
            // quota is far below one reply of full-size objects.
            let pending = next.pending(&reader).unwrap().unwrap();
            assert_eq!(pending.message.payload.len(), MAX_APPLICATION_PAYLOAD);
            let number = u64::from_be_bytes(pending.message.payload[..8].try_into().unwrap());
            assert_eq!(pending.context.sequence.unwrap().get(), number);
            delivered.push(number);
            inbox = next
                .acknowledge(
                    pending.message.member,
                    &pending.context.topic,
                    pending.counter,
                    pending.context.id,
                )
                .unwrap();
        }
        inbox = inbox
            .accept_recovery_coverage(&reader, &query, &reply)
            .unwrap();
        // Progress is exactly the served `through`; nothing is claimed beyond.
        assert_eq!(
            inbox.recovery_progress(author, epoch, &topics),
            query.through
        );
        ranges.push((query, reply));
    }
    assert!(
        ranges.len() > 1,
        "full-size history must span several ranges"
    );
    assert!(ranges[0].0.through < head);
    assert_eq!(delivered, (1..=head).collect::<Vec<_>>());
    // A replayed earlier partial range grants nothing new.
    let replayed = inbox
        .accept_recovery_coverage(&reader, &ranges[0].0, &ranges[0].1)
        .unwrap();
    assert_eq!(replayed.recovery_progress(author, epoch, &topics), head);
    let wire::RangeReply::Offered(offer) =
        wire::verify_reply(&reader, &ranges[0].0, &ranges[0].1).unwrap()
    else {
        panic!("retained range no longer verifies")
    };
    for packet in offer.packets() {
        assert!(matches!(
            inbox
                .stage(&reader, &packet.context, &packet.ciphertext)
                .unwrap(),
            InboxStage::Duplicate
        ));
    }
}
