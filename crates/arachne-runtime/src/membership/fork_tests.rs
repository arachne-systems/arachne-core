//! ADR A2 runtime fork regression checks. In-process MLS; no network exchange.
use super::*;
use crate::ops::candidate::{AdoptKind, adopt};
use arachne_security::{ManagementAction, PreparedManagementUpdate, Workspace};

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
    stage_management(
        &mut session,
        ManagementAction::CreateInvitation([7; 32], 0, false),
    )
    .unwrap();
    adopt_staged(&mut session);
    let wrong = owner(&session)
        .seal_branch_snapshot(&persistence::record_key(&session).unwrap())
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
