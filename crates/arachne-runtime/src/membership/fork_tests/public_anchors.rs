//! Public evidence must outlive private rollback keys.
use super::*;

#[test]
fn a_winner_carries_after_its_private_rollback_snapshot_is_gone() {
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
    let fork_epoch = owner(&session).epoch();
    let winning = JoinStep::binary(
        encode_step(&winner.authorization, &winner.commit).unwrap(),
        None,
    );
    stage_update(&mut session, winning).unwrap();
    adopt_staged(&mut session);
    session
        .membership
        .fork
        .retained
        .as_mut()
        .unwrap()
        .settle_through(fork_epoch);
    assert!(
        session
            .membership
            .fork
            .retained
            .as_ref()
            .unwrap()
            .snapshot(fork_epoch)
            .is_none()
    );
    let fingerprint = owner(&session).epoch_fingerprint();

    // Restore records after private retention ends, before the loser returns.
    let records = fork::records(&session, false).unwrap();
    let mut restored = bare_test_session(owner(&session).provisional_copy().unwrap());
    fork::restore(&mut restored, &records, owner(&session)).unwrap();
    let losing = JoinStep::binary(
        encode_step(&loser.authorization, &loser.commit).unwrap(),
        None,
    );
    let value = fork::stage(&mut restored, fork_epoch, losing).unwrap();
    assert_eq!(
        value["branch_state"], "carried_revocation_received",
        "a winner must retain public evidence after private rollback ends"
    );
    assert_eq!(owner(&restored).epoch_fingerprint(), fingerprint);
    fork::require_send(&restored).unwrap();
    adopt_staged(&mut restored);
    assert_eq!(owner(&restored).epoch_fingerprint(), fingerprint);
    assert!(fork::require_send(&restored).is_err());
    assert!(
        restored
            .membership
            .fork
            .retained
            .as_ref()
            .unwrap()
            .snapshot(fork_epoch)
            .is_none()
    );
    assert!(stage_gossiped_step(&mut restored).unwrap().is_some());
    adopt_staged(&mut restored);
    fork::require_send(&restored).unwrap();
    assert!(
        owner(&restored)
            .member_roster()
            .unwrap()
            .iter()
            .all(|member| !targets.contains(&member.id))
    );
}

fn native_node(secret: u8, provider: &arachne_store::MemoryProvider) -> Session {
    let context = crate::context::Context::for_tests();
    let (node, receiver) = context
        .handle()
        .block_on(Node::bind_with_profile(
            ([127, 0, 0, 1], 0).into(),
            Some(&[secret; 32]),
            arachne_node::NetworkProfile::Direct,
            arachne_node::ConnectionBudget::default(),
        ))
        .unwrap();
    let committed = crate::committed_view::Published::new(None);
    node.set_inquiry_responder(committed.responder());
    let mut session = Session::new(
        node,
        receiver,
        context,
        committed,
        presence::Presence::new().unwrap(),
    );
    session.storage = Some(crate::StorageConfig::memory(provider));
    session.activity = crate::WorkspaceActivity {
        phase: WorkspacePhase::Active,
        reason: None,
    };
    session
}

fn anchor_name(epoch: u64) -> Vec<u8> {
    let mut name = b"runtime/branch/anchor/".to_vec();
    name.extend(epoch.to_be_bytes());
    name
}

fn snapshot_name(epoch: u64) -> Vec<u8> {
    let mut name = b"runtime/branch/snapshot/".to_vec();
    name.extend(epoch.to_be_bytes());
    name
}

#[test]
fn public_evidence_survives_native_settlement_and_two_restarts() {
    let providers: Vec<_> = (0..3)
        .map(|_| arachne_store::MemoryProvider::default())
        .collect();
    let mut nodes: Vec<_> = providers
        .iter()
        .enumerate()
        .map(|(i, provider)| native_node(231 + i as u8, provider))
        .collect();
    let mut workspaces = super::proof_pages::grow(&nodes, 3);
    for key in [[81; 32], [82; 32]] {
        let change = workspaces[0]
            .prepare_management(ManagementAction::CreateInvitation(key, 0, false))
            .unwrap();
        for workspace in &mut workspaces[1..] {
            let PreparedManagementUpdate::Active(next) = workspace
                .prepare_step_update(&change.authorization, &change.commit)
                .unwrap()
            else {
                panic!("not removed")
            };
            *workspace = *next;
        }
        workspaces[0] = change.workspace;
    }
    let first = workspaces[0]
        .prepare_management(ManagementAction::DisableInvitation([81; 32]))
        .unwrap();
    let second = workspaces[1]
        .prepare_management(ManagementAction::DisableInvitation([82; 32]))
        .unwrap();
    let key = |change: &arachne_security::PreparedManagement| {
        arachne_security::fork_key(&change.authorization, &change.commit)
    };
    let (winner, loser) = if key(&first) < key(&second) {
        (first, second)
    } else {
        (second, first)
    };
    let observer = workspaces.pop().unwrap();
    let workspace = observer.id();
    let epoch = observer.epoch();
    let members: Vec<_> = observer
        .member_roster()
        .unwrap()
        .iter()
        .map(|member| member.id)
        .collect();
    let mut session = nodes.pop().unwrap();
    persistence::commit_created(&mut session, &observer, None, None).unwrap();
    crate::session::commit_workspace(&mut session, observer);
    stage_update(
        &mut session,
        JoinStep::binary(
            encode_step(&winner.authorization, &winner.commit).unwrap(),
            None,
        ),
    )
    .unwrap();
    adopt_staged(&mut session);
    let fingerprint = owner(&session).epoch_fingerprint();
    let pin = providers[2]
        .value(workspace, &anchor_name(epoch))
        .expect("public pin saved with winning step");
    assert!(
        providers[2]
            .value(workspace, &snapshot_name(epoch))
            .is_some()
    );

    for member in members {
        fork::observe(&mut session, member, epoch + 1, fingerprint);
    }
    assert!(fork::stage_settlement(&mut session).unwrap().is_some());
    assert!(
        providers[2]
            .value(workspace, &snapshot_name(epoch))
            .is_some(),
        "staging deletes no private state"
    );
    adopt_staged(&mut session);
    assert!(
        providers[2]
            .value(workspace, &snapshot_name(epoch))
            .is_none()
    );
    assert_eq!(
        providers[2].value(workspace, &anchor_name(epoch)),
        Some(pin.clone())
    );
    drop(session);
    drop(nodes);
    drop(workspaces);

    let mut session = native_node(233, &providers[2]);
    persistence::restore(&mut session, workspace, None).unwrap();
    assert!(
        session
            .membership
            .fork
            .retained
            .as_ref()
            .unwrap()
            .snapshot(epoch)
            .is_none()
    );
    assert_eq!(owner(&session).epoch_fingerprint(), fingerprint);
    let losing = JoinStep::binary(
        encode_step(&loser.authorization, &loser.commit).unwrap(),
        None,
    );
    let value = fork::stage(&mut session, epoch, losing).unwrap();
    assert_eq!(value["branch_state"], "carried_revocation_received");
    fork::require_send(&session).unwrap();
    adopt_staged(&mut session);
    assert_eq!(owner(&session).epoch_fingerprint(), fingerprint);
    assert_eq!(fork::shared_orders(&session).len(), 1);
    fork::require_send(&session).unwrap();
    assert!(
        providers[2]
            .value(workspace, &snapshot_name(epoch))
            .is_none()
    );
    drop(session);

    let mut session = native_node(233, &providers[2]);
    persistence::restore(&mut session, workspace, None).unwrap();
    assert_eq!(
        fork::shared_orders(&session).len(),
        1,
        "restart preserves pending revocation"
    );
    assert!(fork::stage_carried(&mut session).unwrap().is_some());
    adopt_staged(&mut session);
    fork::require_send(&session).unwrap();
    let controls = owner(&session).invitation_controls().unwrap();
    for key in [[81; 32], [82; 32]] {
        assert!(
            !controls
                .iter()
                .find(|control| control.key == key)
                .unwrap()
                .enabled
        );
    }
    assert!(
        providers[2]
            .value(workspace, &snapshot_name(epoch))
            .is_none()
    );
}

#[test]
fn public_anchor_records_reject_wrong_epochs_workspaces_and_excess_bytes() {
    let (workspace, _, _) = admit_members(1, "Public anchor", 1);
    let mut session = bare_test_session(workspace);
    let epoch = owner(&session).epoch();
    stage_management(
        &mut session,
        ManagementAction::CreateInvitation([91; 32], 0, false),
    )
    .unwrap();
    adopt_staged(&mut session);
    let records = fork::records(&session, false).unwrap();
    assert!(records.contains_key(&anchor_name(epoch)));
    let mut restored = bare_test_session(owner(&session).provisional_copy().unwrap());

    let mut wrong_epoch = records.clone();
    let pin = wrong_epoch.remove(&anchor_name(epoch)).unwrap();
    wrong_epoch.insert(anchor_name(epoch + 1), pin);
    assert!(fork::restore(&mut restored, &wrong_epoch, owner(&session)).is_err());
    let (other, _, _) = admit_members(2, "Other public anchor", 1);
    let mut wrong_workspace = records.clone();
    wrong_workspace.insert(
        anchor_name(epoch),
        zeroize::Zeroizing::new(other.public_checkpoint_pin().unwrap()),
    );
    assert!(fork::restore(&mut restored, &wrong_workspace, owner(&session)).is_err());
    let mut oversized = records.clone();
    oversized.insert(
        anchor_name(epoch),
        zeroize::Zeroizing::new(vec![0; arachne_security::MAX_CHECKPOINT_PIN + 1]),
    );
    assert!(fork::restore(&mut restored, &oversized, owner(&session)).is_err());
    let mut too_many = records.clone();
    let pin = records.get(&anchor_name(epoch)).unwrap();
    for index in 0..=arachne_security::ORDER_WINDOW + 1 {
        too_many.insert(anchor_name(epoch + index), pin.clone());
    }
    assert!(
        fork::restore(&mut restored, &too_many, owner(&session))
            .unwrap_err()
            .to_string()
            .contains("invalid public anchor record")
    );
    let mut empty = records;
    empty.insert(anchor_name(epoch), zeroize::Zeroizing::new(Vec::new()));
    assert!(fork::restore(&mut restored, &empty, owner(&session)).is_err());
}

#[test]
fn public_anchors_expire_at_the_existing_order_window() {
    let workspace = Workspace::create(crate::test_key(8_887), "Public expiry").unwrap();
    let mut session = bare_test_session(workspace);
    let epoch = owner(&session).epoch();
    for step in 0..=arachne_security::ORDER_WINDOW {
        let mut key = [0; 32];
        key[..8].copy_from_slice(&(step + 1).to_be_bytes());
        stage_management(
            &mut session,
            ManagementAction::CreateInvitation(key, 0, false),
        )
        .unwrap();
        adopt_staged(&mut session);
        let records = fork::records(&session, false).unwrap();
        let count = records
            .keys()
            .filter(|name| name.starts_with(b"runtime/branch/anchor/"))
            .count();
        assert!(count <= arachne_security::ORDER_WINDOW as usize + 1);
        if step < arachne_security::ORDER_WINDOW {
            assert!(records.contains_key(&anchor_name(epoch)));
        } else {
            assert!(!records.contains_key(&anchor_name(epoch)));
        }
    }
}

#[test]
fn a_winners_carried_remove_stays_quarantined_across_native_restart() {
    let providers: Vec<_> = (0..3)
        .map(|_| arachne_store::MemoryProvider::default())
        .collect();
    let mut nodes: Vec<_> = providers
        .iter()
        .enumerate()
        .map(|(i, provider)| native_node(241 + i as u8, provider))
        .collect();
    let mut workspaces = super::proof_pages::grow(&nodes, 3);
    let targets = [
        workspaces[0].member().unwrap().id(),
        workspaces[1].member().unwrap().id(),
    ];
    let first = workspaces[0]
        .prepare_management(ManagementAction::Remove(targets[1]))
        .unwrap();
    let second = workspaces[1]
        .prepare_management(ManagementAction::Remove(targets[0]))
        .unwrap();
    let key = |change: &arachne_security::PreparedManagement| {
        arachne_security::fork_key(&change.authorization, &change.commit)
    };
    let (winner, loser) = if key(&first) < key(&second) {
        (first, second)
    } else {
        (second, first)
    };
    let observer = workspaces.pop().unwrap();
    let workspace = observer.id();
    let epoch = observer.epoch();
    let mut session = nodes.pop().unwrap();
    persistence::commit_created(&mut session, &observer, None, None).unwrap();
    crate::session::commit_workspace(&mut session, observer);
    stage_update(
        &mut session,
        JoinStep::binary(
            encode_step(&winner.authorization, &winner.commit).unwrap(),
            None,
        ),
    )
    .unwrap();
    adopt_staged(&mut session);

    // Model an exhausted private byte budget while the 64-epoch order is
    // still valid. The next real candidate must save the missing snapshot.
    session
        .membership
        .fork
        .retained
        .as_mut()
        .unwrap()
        .settle_through(epoch);
    let advance = winner.workspace.prepare_self_update().unwrap();
    stage_update(
        &mut session,
        JoinStep::binary(
            encode_step(
                &arachne_security::MembershipAuthorization::SelfUpdate,
                &advance.commit,
            )
            .unwrap(),
            None,
        ),
    )
    .unwrap();
    adopt_staged(&mut session);
    let fingerprint = owner(&session).epoch_fingerprint();
    assert!(
        providers[2]
            .value(workspace, &snapshot_name(epoch))
            .is_none()
    );
    assert!(providers[2].value(workspace, &anchor_name(epoch)).is_some());
    drop(session);
    drop(nodes);
    drop(workspaces);

    let mut session = native_node(243, &providers[2]);
    persistence::restore(&mut session, workspace, None).unwrap();
    let losing = JoinStep::binary(
        encode_step(&loser.authorization, &loser.commit).unwrap(),
        None,
    );
    assert_eq!(
        fork::stage(&mut session, epoch, losing).unwrap()["branch_state"],
        "carried_revocation_received"
    );
    assert_eq!(owner(&session).epoch_fingerprint(), fingerprint);
    fork::require_send(&session).unwrap();
    adopt_staged(&mut session);
    assert!(fork::require_send(&session).is_err());
    assert_eq!(owner(&session).epoch_fingerprint(), fingerprint);
    drop(session);

    let mut session = native_node(243, &providers[2]);
    persistence::restore(&mut session, workspace, None).unwrap();
    assert!(fork::require_send(&session).is_err());
    assert_recovery_activity(&mut session, "branch_send_quarantined");
    assert!(fork::stage_carried(&mut session).unwrap().is_some());
    adopt_staged(&mut session);
    fork::require_send(&session).unwrap();
    assert_eq!(owner(&session).member_count(), 1);
    assert!(
        owner(&session)
            .member_roster()
            .unwrap()
            .iter()
            .all(|member| !targets.contains(&member.id))
    );
    assert!(
        providers[2]
            .value(workspace, &snapshot_name(epoch))
            .is_none()
    );
}

#[test]
fn a_branch_switch_discards_public_pins_from_the_losing_suffix() {
    let (admin, observer, members) = two_admins(2);
    let epoch = admin.epoch();
    let winning = admin
        .prepare_management(ManagementAction::Remove(members[0].member().unwrap().id()))
        .unwrap();
    let mut session = bare_test_session(observer);
    for key in [[95; 32], [96; 32]] {
        stage_management(
            &mut session,
            ManagementAction::CreateInvitation(key, 0, false),
        )
        .unwrap();
        adopt_staged(&mut session);
    }
    let records = fork::records(&session, false).unwrap();
    assert!(records.contains_key(&anchor_name(epoch)));
    assert!(records.contains_key(&anchor_name(epoch + 1)));
    let step = JoinStep::binary(
        encode_step(&winning.authorization, &winning.commit).unwrap(),
        None,
    );
    assert_eq!(
        fork::stage(&mut session, epoch, step).unwrap()["branch_state"],
        "branch_switch_staged"
    );
    adopt_staged(&mut session);
    let records = fork::records(&session, false).unwrap();
    assert!(records.contains_key(&anchor_name(epoch)));
    assert!(!records.contains_key(&anchor_name(epoch + 1)));
}
