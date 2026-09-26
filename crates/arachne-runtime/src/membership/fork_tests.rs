//! ADR A2 runtime fork regression checks. In-process MLS; no network exchange.
use super::*;
use crate::ops::candidate::{AdoptKind, adopt};
use arachne_security::{ManagementAction, PreparedManagementUpdate, StorageKey, Workspace};

fn owner(session: &Session) -> &Workspace {
    session.workspace.as_deref().unwrap()
}
fn adopt_staged(session: &mut Session) {
    let token = session.transition.staged.as_ref().unwrap().snapshot.clone();
    adopt(session, AdoptKind::Admission, token).unwrap();
}

#[test]
fn a_competing_removal_switches_only_after_candidate_adoption() {
    let (admin, members, _) = admit_members(2, "Member", 2);
    let target = members[0].member().unwrap().id();
    let promotion = admin
        .prepare_management(ManagementAction::Promote(members[1].member().unwrap().id()))
        .unwrap();
    let PreparedManagementUpdate::Active(second_admin) = members[1]
        .prepare_step_update(&promotion.authorization, &promotion.commit)
        .unwrap()
    else {
        panic!("promotion removed member")
    };
    let admin = promotion.workspace;
    let fork_epoch = admin.epoch();
    let removal = admin
        .prepare_management(ManagementAction::Remove(target))
        .unwrap();
    let expected = removal.workspace.epoch_fingerprint();
    let packet = offer_packet(
        &admin,
        fork_epoch,
        &removal.authorization,
        &removal.commit,
        false,
    )
    .unwrap();
    let mut session = bare_test_session(*second_admin);
    session.storage_key = Some(StorageKey::derive(&[81; 32]).unwrap());
    stage_management(
        &mut session,
        ManagementAction::CreateInvitation([9; 32], 0, false),
    )
    .unwrap();
    adopt_staged(&mut session);
    let old = owner(&session).epoch_fingerprint();
    assert_ne!(old, expected);
    let result = receive_offer(&mut session, &packet);
    assert!(
        result.is_ok(),
        "valid winning step must stage a switch: {result:?}"
    );
    assert_eq!(
        owner(&session).epoch_fingerprint(),
        old,
        "staging changes no authority"
    );
    adopt_staged(&mut session);
    assert_eq!(owner(&session).epoch_fingerprint(), expected);
    assert!(
        receive_offer(&mut session, &packet).is_err(),
        "an exact replay retains its generic rejection"
    );
    assert!(
        !owner(&session)
            .member_roster()
            .unwrap()
            .iter()
            .any(|m| m.id == target)
    );
}

#[test]
fn a_lower_key_below_the_snapshot_window_stages_orphaning_and_blocks_sends() {
    let (admin, members, _) = admit_members(3, "Member", 1);
    let fork_epoch = admin.epoch();
    let removal = admin
        .prepare_management(ManagementAction::Remove(members[0].member().unwrap().id()))
        .unwrap();
    let packet = offer_packet(
        &admin,
        fork_epoch,
        &removal.authorization,
        &removal.commit,
        false,
    )
    .unwrap();
    let mut session = bare_test_session(admin);
    session.storage_key = Some(StorageKey::derive(&[82; 32]).unwrap());
    stage_management(
        &mut session,
        ManagementAction::CreateInvitation([7; 32], 0, false),
    )
    .unwrap();
    adopt_staged(&mut session);
    session
        .membership
        .fork
        .retained
        .as_mut()
        .unwrap()
        .settle_through(fork_epoch);
    let before = owner(&session).epoch_fingerprint();
    let value = receive_offer(&mut session, &packet).unwrap();
    assert_eq!(value["branch_state"], "orphaned");
    adopt_staged(&mut session);
    assert_eq!(owner(&session).epoch_fingerprint(), before);
    assert!(fork::require_send(&session).is_err());
}

#[test]
fn a_higher_key_does_not_orphan_a_settled_winner() {
    let (admin, members, _) = admit_members(4, "Member", 1);
    let fork_epoch = admin.epoch();
    let lower = admin
        .prepare_management(ManagementAction::Remove(members[0].member().unwrap().id()))
        .unwrap();
    let higher = admin.prepare_self_update().unwrap();
    let packet = offer_packet(
        &admin,
        fork_epoch,
        &arachne_security::MembershipAuthorization::SelfUpdate,
        &higher.commit,
        false,
    )
    .unwrap();
    let mut session = bare_test_session(admin);
    session.storage_key = Some(StorageKey::derive(&[83; 32]).unwrap());
    stage_prepared(&mut session, lower).unwrap();
    adopt_staged(&mut session);
    session
        .membership
        .fork
        .retained
        .as_mut()
        .unwrap()
        .settle_through(fork_epoch);
    let before = owner(&session).epoch_fingerprint();
    let value = receive_offer(&mut session, &packet).unwrap();
    assert_eq!(value["state"], "membership_branch_kept");
    assert!(session.transition.staged.is_none());
    assert_eq!(owner(&session).epoch_fingerprint(), before);
    fork::require_send(&session).unwrap();
}

#[test]
fn a_branch_snapshot_must_match_its_declared_epoch() {
    let (admin, members, _) = admit_members(5, "Member", 1);
    let epoch = admin.epoch();
    let removal = admin
        .prepare_management(ManagementAction::Remove(members[0].member().unwrap().id()))
        .unwrap();
    let packet = offer_packet(
        &admin,
        epoch,
        &removal.authorization,
        &removal.commit,
        false,
    )
    .unwrap();
    let mut session = bare_test_session(admin);
    session.storage_key = Some(StorageKey::derive(&[84; 32]).unwrap());
    stage_management(
        &mut session,
        ManagementAction::CreateInvitation([7; 32], 0, false),
    )
    .unwrap();
    adopt_staged(&mut session);
    let wrong = owner(&session)
        .seal_branch_snapshot(session.storage_key.as_ref().unwrap())
        .unwrap();
    let mut branch = arachne_security::BranchState::new(epoch);
    branch.retain(epoch, wrong).unwrap();
    session.membership.fork.retained = Some(branch);
    assert!(
        receive_offer(&mut session, &packet)
            .unwrap_err()
            .to_string()
            .contains("wrong epoch")
    );
    assert!(session.transition.staged.is_none());
}

#[test]
fn branch_rows_are_bounded_contiguous_and_only_hints() {
    let query = wire::BranchQuery {
        workspace: [1; 32],
        from: 7,
        until: 9,
    };
    let bytes = wire::encode_branch_query(&query).unwrap();
    assert_eq!(wire::decode_branch_query(&bytes).unwrap().from, 7);
    let mut reply = wire::BranchReply {
        workspace: [1; 32],
        from: 7,
        head: 9,
        fingerprint: [2; 32],
        rows: vec![wire::BranchRow {
            epoch: 7,
            class: 255,
            digest: [3; 32],
        }],
    };
    let bytes = wire::encode_branch_reply(&reply).unwrap();
    // Even an invalid class remains a hint. No fork key is made from it.
    assert_eq!(
        wire::decode_branch_reply(&bytes).unwrap().rows[0].class,
        255
    );
    reply.rows[0].epoch = 8;
    assert!(wire::decode_branch_reply(&wire::encode_branch_reply(&reply).unwrap()).is_err());
    reply.rows = (0..=wire::MAX_BRANCH_ROWS)
        .map(|n| wire::BranchRow {
            epoch: 7 + n as u64,
            class: 0,
            digest: [0; 32],
        })
        .collect();
    assert!(wire::encode_branch_reply(&reply).is_err());
}

fn active(workspace: PreparedManagementUpdate) -> Workspace {
    match workspace {
        PreparedManagementUpdate::Active(workspace) => *workspace,
        PreparedManagementUpdate::Removed(_) => panic!("unexpected removal"),
    }
}

fn two_admins(count: u16) -> (Workspace, Workspace, Vec<Workspace>) {
    let (admin, mut members, _) = admit_members(6, "Member", count + 1);
    for member in &mut members {
        while member.epoch() < admin.epoch() {
            let (authorization, commit) = admin.history_step(member.epoch()).unwrap().unwrap();
            *member = match &authorization {
                arachne_security::MembershipAuthorization::Admission(auth) => {
                    member.prepare_admission_update(auth, &commit).unwrap()
                }
                arachne_security::MembershipAuthorization::AdmissionBatch(auths) => member
                    .prepare_admission_batch_update(auths, &commit)
                    .unwrap(),
                _ => active(member.prepare_step_update(&authorization, &commit).unwrap()),
            };
        }
    }
    let promote = admin
        .prepare_management(ManagementAction::Promote(members[0].member().unwrap().id()))
        .unwrap();
    for member in &mut members {
        *member = active(
            member
                .prepare_step_update(&promote.authorization, &promote.commit)
                .unwrap(),
        );
    }
    (promote.workspace, members.remove(0), members)
}

#[test]
fn competing_removes_are_carried_and_quarantine_sends_until_both_apply() {
    let (first, second, mut members) = two_admins(3);
    let targets = [
        members[0].member().unwrap().id(),
        members[1].member().unwrap().id(),
    ];
    let first_remove = first
        .prepare_management(ManagementAction::Remove(targets[0]))
        .unwrap();
    let second_remove = second
        .prepare_management(ManagementAction::Remove(targets[1]))
        .unwrap();
    let key = |change: &arachne_security::PreparedManagement| {
        arachne_security::fork_key(&change.authorization, &change.commit)
    };
    let (winner, loser) = if key(&first_remove) < key(&second_remove) {
        (first_remove, second_remove)
    } else {
        (second_remove, first_remove)
    };
    let mut session = bare_test_session(members.remove(2));
    session.storage_key = Some(StorageKey::derive(&[85; 32]).unwrap());
    let fork_epoch = owner(&session).epoch();
    let losing = owner_wire_step(
        owner(&session),
        &loser.authorization,
        &loser.commit,
        usize::MAX,
    )
    .unwrap();
    stage_update(&mut session, join_step_from_wire(&losing).unwrap()).unwrap();
    adopt_staged(&mut session);
    let packet = offer_packet(
        &first,
        fork_epoch,
        &winner.authorization,
        &winner.commit,
        false,
    )
    .unwrap();
    receive_offer(&mut session, &packet).unwrap();
    adopt_staged(&mut session);
    assert!(
        fork::require_send(&session).is_err(),
        "losing Remove must quarantine sends until it is carried"
    );
    // Branch records restore the quarantine before any new publication.
    let records = fork::records(&session, false).unwrap();
    let mut restored = bare_test_session(owner(&session).provisional_copy().unwrap());
    restored.storage_key = Some(StorageKey::derive(&[85; 32]).unwrap());
    fork::restore(&mut restored, &records).unwrap();
    assert!(fork::require_send(&restored).is_err());
    let (_, encoded) = records
        .iter()
        .find(|(name, _)| name.starts_with(b"runtime/branch/order/"))
        .unwrap();
    let mut receiver = bare_test_session(owner(&session).provisional_copy().unwrap());
    receiver.storage_key = Some(StorageKey::derive(&[85; 32]).unwrap());
    let mut forged = arachne_security::OrderStep::from_bytes(encoded).unwrap();
    forged.order.signature[0] ^= 1;
    assert!(
        fork::receive_order(&mut receiver, &forged.to_bytes().unwrap())
            .unwrap()
            .is_none()
    );
    fork::require_send(&receiver).unwrap();
    assert!(
        fork::receive_order(&mut receiver, encoded)
            .unwrap()
            .is_some()
    );
    fork::require_send(&receiver).unwrap();
    adopt_staged(&mut receiver);
    assert!(fork::require_send(&receiver).is_err());
    assert!(
        fork::receive_order(&mut receiver, encoded)
            .unwrap()
            .is_none(),
        "duplicate order must not stage another candidate"
    );
    // Quarantine stops encryption, but a received membership step still works.
    let update = winner.workspace.prepare_self_update().unwrap();
    let bytes = owner_wire_step(
        &winner.workspace,
        &arachne_security::MembershipAuthorization::SelfUpdate,
        &update.commit,
        usize::MAX,
    )
    .unwrap();
    stage_update(&mut receiver, join_step_from_wire(&bytes).unwrap()).unwrap();
    adopt_staged(&mut receiver);
    assert!(fork::require_send(&receiver).is_err());
    let staged = stage_gossiped_step(&mut session).unwrap();
    assert!(staged.is_some(), "the driver must commit a carried order");
    adopt_staged(&mut session);
    fork::require_send(&session).unwrap();
    let roster = owner(&session).member_roster().unwrap();
    assert!(roster.iter().all(|member| !targets.contains(&member.id)));
    let staged = stage_gossiped_step(&mut restored).unwrap();
    assert!(staged.is_some());
    adopt_staged(&mut restored);
    fork::require_send(&restored).unwrap();
}

#[test]
fn a_winner_carries_a_verified_losing_remove_without_switching() {
    let (first, second, mut members) = two_admins(3);
    let first_remove = first
        .prepare_management(ManagementAction::Remove(members[0].member().unwrap().id()))
        .unwrap();
    let second_remove = second
        .prepare_management(ManagementAction::Remove(members[1].member().unwrap().id()))
        .unwrap();
    let key = |change: &arachne_security::PreparedManagement| {
        arachne_security::fork_key(&change.authorization, &change.commit)
    };
    let (winner, loser) = if key(&first_remove) < key(&second_remove) {
        (first_remove, second_remove)
    } else {
        (second_remove, first_remove)
    };
    let mut session = bare_test_session(members.remove(2));
    session.storage_key = Some(StorageKey::derive(&[86; 32]).unwrap());
    let fork_epoch = owner(&session).epoch();
    let winning = owner_wire_step(
        owner(&session),
        &winner.authorization,
        &winner.commit,
        usize::MAX,
    )
    .unwrap();
    stage_update(&mut session, join_step_from_wire(&winning).unwrap()).unwrap();
    adopt_staged(&mut session);
    let fingerprint = owner(&session).epoch_fingerprint();
    let losing = offer_packet(
        &first,
        fork_epoch,
        &loser.authorization,
        &loser.commit,
        false,
    )
    .unwrap();
    let value = receive_offer(&mut session, &losing).unwrap();
    assert_eq!(value["branch_state"], "carried_revocation_received");
    adopt_staged(&mut session);
    assert_eq!(owner(&session).epoch_fingerprint(), fingerprint);
    assert!(fork::require_send(&session).is_err());
    assert!(stage_gossiped_step(&mut session).unwrap().is_some());
    adopt_staged(&mut session);
    fork::require_send(&session).unwrap();
    assert_eq!(owner(&session).member_count(), 3);
}
