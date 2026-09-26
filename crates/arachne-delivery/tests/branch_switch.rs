//! ADR A2 step 8 and 10: delivery state moves to a winning branch.
//!
//! A member on a losing branch goes back to the fork epoch F and replays the
//! winning steps. Its publisher log keeps the epochs at and below F, returns
//! its own publications from the losing epochs (for re-publication), and
//! starts the winning epoch. Its inbox moves to the winning epoch too, even
//! though the epoch number does not grow.
mod common;
use arachne_delivery::PublisherLog;
use arachne_delivery::inbox::{InboxStage, ObjectInbox};
use arachne_routing::{PublicationContext, Topic};
use arachne_security::{ManagementAction, PendingJoin, PreparedManagementUpdate, Workspace};
use common::{test_endpoint, test_key};

fn active(update: PreparedManagementUpdate) -> Workspace {
    match update {
        PreparedManagementUpdate::Active(workspace) => *workspace,
        PreparedManagementUpdate::Removed(_) => panic!("unexpected removal"),
    }
}

fn context(workspace: [u8; 32], sequence: u64, id: u8) -> PublicationContext {
    PublicationContext {
        workspace,
        revision: 7,
        topic: Topic::new("chat/room").unwrap(),
        id: [id; 16],
        sequence: std::num::NonZeroU64::new(sequence),
    }
}

#[test]
fn a_switch_keeps_the_common_epochs_and_returns_the_losing_publications() {
    let admin = Workspace::create(test_key(1), "A").unwrap();
    let (registered, invite, checkpoint) =
        admin.prepare_invitation(u64::MAX, false, false).unwrap();
    let admin = registered.workspace;
    let join = PendingJoin::from_invitation(&invite, &checkpoint, test_key(2), "B").unwrap();
    let prepared = admin
        .prepare_admission(test_endpoint(2), join.admission_request().unwrap())
        .unwrap();
    let mut proof = join.join_proof().unwrap();
    proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let mut member = join.prepare_workspace(&proof, &prepared.welcome).unwrap();
    let admin = prepared.workspace;
    let fork = member.epoch();

    // One publication at the fork epoch: it is on both branches.
    let mut log = PublisherLog::new(&member).unwrap();
    let common = context(member.id(), 1, 1);
    let object = member
        .protect_object(b"chat", &common.authenticated_bytes(), b"common")
        .unwrap();
    log.append(common.clone(), object).unwrap();
    let at_fork = member.provisional_copy().unwrap();
    let inbox = ObjectInbox::new(member.id(), member.epoch());

    // Two competing steps out of the fork epoch.
    let mut losing = admin
        .prepare_management(ManagementAction::CreateInvitation([8; 32], 0, false))
        .unwrap();
    let winning = admin
        .prepare_management(ManagementAction::CreateInvitation([9; 32], 0, false))
        .unwrap();
    let mut on_loser = active(
        member
            .prepare_management_update(losing.action, &losing.commit)
            .unwrap(),
    );
    let mut log = log.advance(&at_fork, &on_loser).unwrap();
    let inbox = inbox.advance(&at_fork, &on_loser).unwrap();
    let foreign = context(member.id(), 1, 3);
    let object = losing
        .workspace
        .protect_object(
            b"chat",
            &foreign.authenticated_bytes(),
            b"foreign losing data",
        )
        .unwrap();
    let InboxStage::Prepared(inbox) = inbox.stage(&on_loser, &foreign, &object).unwrap() else {
        panic!("foreign object was not accepted")
    };
    assert!(
        !inbox
            .pending(&on_loser)
            .unwrap()
            .unwrap()
            .from_losing_branch
    );
    let lost = context(member.id(), 1, 2);
    let object = on_loser
        .protect_object(b"chat", &lost.authenticated_bytes(), b"lost")
        .unwrap();
    log.append(lost.clone(), object.clone()).unwrap();

    let on_winner = active(
        at_fork
            .prepare_management_update(winning.action, &winning.commit)
            .unwrap(),
    );
    assert_eq!(on_winner.epoch(), on_loser.epoch());
    assert_ne!(on_winner.epoch_fingerprint(), on_loser.epoch_fingerprint());
    // `advance` refuses: the epoch does not grow.
    assert!(log.advance(&on_loser, &on_winner).is_err());
    assert!(inbox.advance(&on_loser, &on_winner).is_err());

    let (rebased, losing_logs) = log.rebase(&on_loser, &at_fork, &on_winner).unwrap();
    assert_eq!(rebased.epochs(), vec![fork, fork + 1]);
    assert_eq!(rebased.epoch(), on_winner.epoch());
    assert_eq!(rebased.head(), 0);
    assert_eq!(rebased.epoch_log(fork).unwrap().head(), 1);
    // The saved log restores against the winning owner only.
    let snapshot = ObjectInbox::new(on_winner.id(), on_winner.epoch())
        .snapshot_with_publisher(&on_winner, &rebased)
        .unwrap();
    ObjectInbox::restore_snapshot(&on_winner, &snapshot).unwrap();
    assert!(ObjectInbox::restore_snapshot(&on_loser, &snapshot).is_err());
    // The losing publication comes back, and its author can still open it.
    assert_eq!(losing_logs.len(), 1);
    assert_eq!(losing_logs[0].epoch(), fork + 1);
    let records = losing_logs[0].publications();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].context, lost);
    let opened = on_loser
        .unprotect_object(
            b"chat",
            &records[0].context.authenticated_bytes(),
            &records[0].ciphertext,
        )
        .unwrap();
    assert_eq!(opened.message.payload, b"lost");
    // A rebase must name the current owner and a fork below it.
    assert!(log.rebase(&on_winner, &at_fork, &on_winner).is_err());
    assert!(log.rebase(&on_loser, &on_loser, &on_winner).is_err());

    let moved = inbox.rebase(&on_loser, fork, &on_winner).unwrap();
    assert_eq!(moved.epoch(), on_winner.epoch());
    let pending = moved.pending(&on_winner).unwrap().unwrap();
    assert!(
        pending.from_losing_branch,
        "foreign plaintext must identify its losing branch"
    );
    assert_eq!(pending.message.payload, b"foreign losing data");
    let snapshot = moved.snapshot_with_publisher(&on_winner, &rebased).unwrap();
    let (_, restored) = ObjectInbox::restore_snapshot(&on_winner, &snapshot).unwrap();
    assert!(
        restored
            .pending(&on_winner)
            .unwrap()
            .unwrap()
            .from_losing_branch
    );
    // The inbox has no branch fingerprint; it checks the epoch only.
    assert!(inbox.rebase(&at_fork, fork, &on_winner).is_err());
    assert!(
        inbox
            .rebase(&on_loser, on_loser.epoch(), &on_winner)
            .is_err()
    );
    let _ = &mut on_loser;
}
