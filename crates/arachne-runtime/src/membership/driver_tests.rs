//! A stream of served inquiries must not starve completed reconciliation.
use super::*;

fn query_fixture(branch_mismatch: bool) -> (Session, Vec<u8>) {
    let (owner, members, _) = admit_members(45, "Ready query", 1);
    let peer = members[0].endpoint();
    let basis = StateBasis {
        epoch: owner.epoch(),
        fingerprint: owner.epoch_fingerprint(),
        name_head: owner.workspace_name_head().unwrap(),
    };
    let mut fingerprint = owner.epoch_fingerprint();
    if branch_mismatch {
        fingerprint[0] ^= 1;
    }
    let reply = encode_reply(&json!({
        "workspace": owner.id(), "after": owner.epoch(), "epoch": owner.epoch(),
        "epoch_fingerprint": fingerprint, "state": "membership_current",
        "profiles": [],
    }))
    .unwrap();
    let mut session = bare_test_session(owner);
    session.membership.update = Some(PendingControl {
        query: basis,
        peer,
        task: session.runtime.spawn(std::future::pending()),
    });
    (session, reply)
}

fn complete_query(session: &mut Session, bytes: Vec<u8>) {
    let task = session.runtime.spawn(async move { Ok(bytes) });
    let pending = session.membership.update.as_mut().unwrap();
    pending.task.abort();
    pending.task = task;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while !session
        .membership
        .update
        .as_ref()
        .unwrap()
        .task
        .is_finished()
    {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
}

#[test]
fn served_inquiries_do_not_starve_a_completed_membership_query() {
    let (mut session, bytes) = query_fixture(false);
    complete_query(&mut session, bytes);
    lock_profiles(&session.membership.profiles).note_answered(None);
    let value = crate::ops::admission::drive_workspace(&mut session).unwrap();
    assert_eq!(
        value["membership_state"], "membership_current",
        "a completed membership result must run before another inquiry notice"
    );
    assert!(session.membership.update.is_none());
    assert!(
        take_answered(&session).is_some(),
        "the served inquiry notice is retained"
    );
}

#[test]
fn an_unfinished_membership_query_does_not_delay_a_served_inquiry_notice() {
    let (mut session, _) = query_fixture(false);
    lock_profiles(&session.membership.profiles).note_answered(None);
    let value = crate::ops::admission::drive_workspace(&mut session).unwrap();
    assert_eq!(value["state"], "membership_replied");
    assert_eq!(value["remote_receipt"], false);
    assert!(take_answered(&session).is_none());
    session.membership.update.take().unwrap().task.abort();
}

#[test]
fn served_inquiries_do_not_starve_a_completed_branch_mismatch() {
    let (mut session, bytes) = query_fixture(true);
    complete_query(&mut session, bytes);
    lock_profiles(&session.membership.profiles).note_answered(None);
    let value = crate::ops::admission::drive_workspace(&mut session).unwrap();
    assert_eq!(value["state"], "membership_branch_mismatch");
    assert!(session.membership.update.is_none());
    assert!(
        session.membership.fork.is_running(),
        "branch comparison has started"
    );
    assert!(
        take_answered(&session).is_some(),
        "the served inquiry notice is retained"
    );
}
