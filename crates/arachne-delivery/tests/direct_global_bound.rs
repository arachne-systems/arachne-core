//! B7d: can the all-authors pending bound (96 KiB, 512 objects) stall direct
//! delivery? That needs every pending object to wait behind a direct gap
//! while the gap filler is refused as `pending inbox full`. Three authors
//! fill one reader with gap-blocked direct objects at several sizes. After
//! every arrival the invariant is checked: when the application has nothing
//! deliverable, every gap filler is still admitted.
//!
//! Finding: the stall is not reachable today. An object stays behind a gap
//! only while its stream keeps the records above the gap, and the receiver
//! keeps at most 32 KiB (`MAX_DIRECT_RETAINED_BYTES`) and 32 records per
//! scope. Evicting a record moves the scope floor past the gap, so the
//! objects above it become deliverable. Gap-blocked objects therefore stay far
//! below the 96 KiB / 512 object bound (at most 185 one-byte objects here).
//! If that retention rule changes, this test fails and the all-authors bound
//! needs a gap-filler exemption like the per-author one (B7c).
use arachne_delivery::inbox::{InboxStage, ObjectInbox, PENDING_INBOX_FULL};
use arachne_routing::{PublicationContext, Topic};
use arachne_security::{PendingJoin, PreparedManagementUpdate, Workspace};
mod common;
use common::{test_endpoint, test_key};

const REVISION: u64 = 1;

fn active(update: PreparedManagementUpdate) -> Workspace {
    match update {
        PreparedManagementUpdate::Active(workspace) => *workspace,
        PreparedManagementUpdate::Removed(_) => panic!("unexpected removal"),
    }
}

/// Admin (author 1) admits authors 2 and 3, then the reader. Every earlier
/// member applies each later step. Returns ([authors], reader) at one epoch.
fn three_authors_and_reader() -> (Vec<Workspace>, Workspace) {
    let mut admin = Workspace::create(test_key(1), "Author 1").unwrap();
    let mut members: Vec<Workspace> = Vec::new();
    for (label, name) in [(2, "Author 2"), (3, "Author 3"), (4, "Reader")] {
        let (registered, invite, checkpoint) =
            admin.prepare_invitation(u64::MAX, false, false).unwrap();
        let invited = registered.workspace.provisional_copy().unwrap();
        let join = PendingJoin::from_invitation(&invite, &checkpoint, test_key(label), name).unwrap();
        let admission = invited
            .prepare_admission(test_endpoint(label), join.admission_request().unwrap())
            .unwrap();
        let mut proof = join.join_proof().unwrap();
        proof
            .apply_add(&admission.authorization, &admission.commit)
            .unwrap();
        let joined = join.prepare_workspace(&proof, &admission.welcome).unwrap();
        members = members
            .into_iter()
            .map(|member| {
                active(
                    member
                        .prepare_management_update(registered.action, &registered.commit)
                        .unwrap(),
                )
                .prepare_admission_update(&admission.authorization, &admission.commit)
                .unwrap()
            })
            .collect();
        admin = admission.workspace.provisional_copy().unwrap();
        members.push(joined);
    }
    let reader = members.pop().unwrap();
    let mut authors = vec![admin];
    authors.extend(members);
    for author in &authors {
        assert_eq!(author.epoch(), reader.epoch());
    }
    (authors, reader)
}

fn direct_object(
    author: &mut Workspace,
    reader: [u8; 32],
    scope: u8,
    sequence: u64,
    size: usize,
) -> (PublicationContext, Vec<u8>) {
    let topic = Topic::new(format!("direct/{scope}")).unwrap();
    let mut id = [0; 16];
    id[0] = scope;
    id[8..].copy_from_slice(&sequence.to_be_bytes());
    let context = PublicationContext {
        workspace: author.id(),
        revision: REVISION,
        topic: topic.clone(),
        id,
        sequence: std::num::NonZeroU64::new(sequence),
    };
    let object = author
        .protect_object(
            topic.namespace().as_bytes(),
            &context.direct_authenticated_bytes(&[reader]).unwrap(),
            &vec![scope; size],
        )
        .unwrap();
    (context, object)
}

#[test]
fn gap_blocked_objects_of_three_authors_never_stall_the_global_bound() {
    for size in [1usize, 256, 1024, 4 * 1024, 8 * 1024, 12 * 1024] {
        let (mut authors, reader) = three_authors_and_reader();
        let recipient = [reader.member().unwrap().id()];
        let mut inbox = ObjectInbox::new(reader.id(), reader.epoch());
        // Each author opens several scopes so the reader holds many small
        // gapped streams. Sequence 1 of every scope is lost.
        let mut fillers = Vec::new();
        for (index, author) in authors.iter_mut().enumerate() {
            for scope in 0..4u8 {
                let scope = index as u8 * 10 + scope;
                fillers.push((index, direct_object(author, recipient[0], scope, 1, size)));
            }
        }
        let mut arrived = 0;
        let mut globally_refused = 0;
        let mut all_blocked_max = 0;
        'fill: for sequence in 2..=40u64 {
            for (index, author) in authors.iter_mut().enumerate() {
                for scope in 0..4u8 {
                    let scope = index as u8 * 10 + scope;
                    let (context, object) =
                        direct_object(author, recipient[0], scope, sequence, size);
                    match inbox.stage_with_recipients(&reader, &context, &recipient, &object) {
                        Ok(InboxStage::Prepared(next)) => {
                            inbox = *next;
                            arrived += 1;
                        }
                        Ok(_) => panic!("live object was not new"),
                        Err(error) => {
                            if error == PENDING_INBOX_FULL {
                                globally_refused += 1;
                            }
                            if globally_refused > 64 {
                                break 'fill;
                            }
                        }
                    }
                    // The invariant: with nothing deliverable, no gap filler
                    // is refused by the all-authors bound.
                    if inbox.pending(&reader).unwrap().is_none() && inbox.pending_count() > 0 {
                        all_blocked_max = all_blocked_max.max(inbox.pending_count());
                        for (_, (context, object)) in &fillers {
                            let result = inbox.stage_with_recipients(
                                &reader, context, &recipient, object,
                            );
                            assert!(
                                !matches!(result, Err(error) if error == PENDING_INBOX_FULL),
                                "size {size}: {} pending objects all wait behind gaps, \
                                 and a gap filler is refused as pending inbox full",
                                inbox.pending_count()
                            );
                        }
                    }
                }
            }
        }
        assert!(arrived > 0, "size {size}: nothing arrived");
        eprintln!(
            "size {size}: arrived {arrived}, pending {}, deliverable {}, globally refused {globally_refused}, most pending while all blocked {all_blocked_max}",
            inbox.pending_count(),
            inbox.pending(&reader).unwrap().is_some()
        );
    }
}
