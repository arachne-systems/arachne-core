//! ADR A2 T1/T4/T13. Real MLS and store adoption; packets move in process.
//! The schedule replaces only the network, so a seed fixes partitions and
//! arrival order. Runtime offer verification, carry and retry all run.
use super::*;
use std::collections::BTreeSet;

fn transfer(source: &Workspace, target: &mut Session) -> bool {
    let local = owner(target);
    let start = source
        .history_start()
        .unwrap()
        .max(local.history_start().unwrap());
    let common_head = source.epoch().min(local.epoch());
    let different = (start..common_head)
        .find(|epoch| source.branch_key(*epoch).unwrap() != local.branch_key(*epoch).unwrap());
    let epoch = different.or_else(|| (source.epoch() > local.epoch()).then_some(local.epoch()));
    let Some(epoch) = epoch else { return false };
    let (authorization, commit) = source.history_step(epoch).unwrap().unwrap();
    let packet = offer_packet(source, epoch, &authorization, &commit, false).unwrap();
    receive_offer(target, &packet).unwrap();
    assert!(
        target.transition.removal.is_none(),
        "a fixture administrator was removed"
    );
    if target.transition.staged.is_some() {
        adopt_staged(target);
        true
    } else {
        false
    }
}

fn catch_up(owner: &Workspace, member: &mut Workspace) {
    while member.epoch() < owner.epoch() {
        let (authorization, commit) = owner.history_step(member.epoch()).unwrap().unwrap();
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

fn next_random(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

fn heal(nodes: &mut [Session], mut seed: u64) {
    for round in 0..128 {
        let mut edges = Vec::new();
        for source in 0..nodes.len() {
            for target in 0..nodes.len() {
                if source != target {
                    edges.push((source, target));
                }
            }
        }
        for index in (1..edges.len()).rev() {
            let other = next_random(&mut seed) as usize % (index + 1);
            edges.swap(index, other);
        }
        for (source, target) in edges {
            let source = owner(&nodes[source]).provisional_copy().unwrap();
            transfer(&source, &mut nodes[target]);
        }
        for node in nodes.iter_mut() {
            let staged = fork::stage_carried(node).unwrap().is_some()
                || fork::stage_retry(node).unwrap().is_some();
            if staged {
                adopt_staged(node);
            }
        }
        let fingerprint = owner(&nodes[0]).epoch_fingerprint();
        if nodes.iter().all(|node| {
            owner(node).epoch_fingerprint() == fingerprint
                && !fork::has_carried_work(node)
                && !fork::has_retry_work(node)
        }) {
            for node in nodes.iter() {
                fork::require_send(node).unwrap();
            }
            return;
        }
        assert!(
            round < 127,
            "partitions did not converge; seed={seed}; epochs={:?}",
            nodes
                .iter()
                .map(|node| owner(node).epoch())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn a_longer_partition_loses_to_a_remove_and_cannot_restore_the_removed_member() {
    let (first, second, members) = two_admins(2);
    let removed = members[0].member().unwrap().id();
    let promoted = members[1].member().unwrap().id();
    let epoch = first.epoch();
    let mut nodes = vec![bare_test_session(first), bare_test_session(second)];
    stage_management(&mut nodes[0], ManagementAction::Remove(removed)).unwrap();
    adopt_staged(&mut nodes[0]);
    stage_management(&mut nodes[1], ManagementAction::Promote(promoted)).unwrap();
    adopt_staged(&mut nodes[1]);
    stage_management(
        &mut nodes[1],
        ManagementAction::CreateInvitation([121; 32], 0, false),
    )
    .unwrap();
    adopt_staged(&mut nodes[1]);
    assert_eq!(owner(&nodes[1]).epoch(), epoch + 2);
    let mut excluded = members[0].provisional_copy().unwrap();
    for parent in epoch..owner(&nodes[1]).epoch() {
        let (auth, commit) = owner(&nodes[1]).history_step(parent).unwrap().unwrap();
        excluded = active(excluded.prepare_step_update(&auth, &commit).unwrap());
    }
    heal(&mut nodes, 1);
    for node in &nodes {
        let roster = owner(node).member_roster().unwrap();
        assert!(!roster.iter().any(|member| member.id == removed));
        assert!(
            roster
                .iter()
                .any(|member| member.id == promoted && member.administrator)
        );
    }
    let mut sender = owner(&nodes[0]).provisional_copy().unwrap();
    let object = sender
        .protect_object(b"chat", b"after heal", b"new data")
        .unwrap();
    assert!(
        owner(&nodes[1])
            .unprotect_object(b"chat", b"after heal", &object)
            .is_ok()
    );
    assert!(
        excluded
            .unprotect_object(b"chat", b"after heal", &object)
            .is_err()
    );
}

fn three_administrators() -> (Vec<Workspace>, Vec<Workspace>) {
    let (first, second, mut members) = two_admins(4);
    let promotion = first
        .prepare_management(ManagementAction::Promote(members[0].member().unwrap().id()))
        .unwrap();
    let second = active(
        second
            .prepare_step_update(&promotion.authorization, &promotion.commit)
            .unwrap(),
    );
    for member in &mut members {
        *member = active(
            member
                .prepare_step_update(&promotion.authorization, &promotion.commit)
                .unwrap(),
        );
    }
    (
        vec![promotion.workspace, second, members.remove(0)],
        members,
    )
}

#[test]
fn all_six_arrival_orders_give_three_observers_the_same_branch() {
    let (administrators, observers) = three_administrators();
    let changes: Vec<_> = administrators
        .iter()
        .enumerate()
        .map(|(index, admin)| {
            admin
                .prepare_management(ManagementAction::CreateInvitation(
                    [index as u8 + 151; 32],
                    0,
                    false,
                ))
                .unwrap()
        })
        .collect();
    let mut expected = None;
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        for observer in &observers {
            let mut node = bare_test_session(observer.provisional_copy().unwrap());
            for index in order {
                transfer(&changes[index].workspace, &mut node);
            }
            let fingerprint = owner(&node).epoch_fingerprint();
            assert_eq!(
                *expected.get_or_insert(fingerprint),
                fingerprint,
                "arrival order {order:?}"
            );
            assert!(
                !fork::has_retry_work(&node),
                "an observer never retries another member's action"
            );
        }
    }
}

#[test]
fn a_fork_below_sixty_four_snapshots_requires_fresh_admission() {
    let (first, second, members) = two_admins(1);
    let epoch = first.epoch();
    let stale_member = second.member().unwrap().id();
    let removal = first
        .prepare_management(ManagementAction::Remove(members[0].member().unwrap().id()))
        .unwrap();
    let mut node = bare_test_session(second);
    for index in 0..65u8 {
        let mut key = [181; 32];
        key[0] = index;
        stage_management(&mut node, ManagementAction::CreateInvitation(key, 0, false)).unwrap();
        adopt_staged(&mut node);
    }
    assert!(
        node.membership
            .fork
            .retained
            .as_ref()
            .unwrap()
            .snapshot(epoch)
            .is_none()
    );
    let value = receive_offer(
        &mut node,
        &offer_packet(
            &first,
            epoch,
            &removal.authorization,
            &removal.commit,
            false,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(value["branch_state"], "orphaned");
    adopt_staged(&mut node);
    let records = fork::records(&node, false).unwrap();
    let mut restored = bare_test_session(owner(&node).provisional_copy().unwrap());
    restored.storage = node.storage.clone();
    fork::restore(&mut restored, &records, owner(&node)).unwrap();
    assert!(fork::require_send(&restored).is_err());

    // An administrator must remove the stale identity and authorize a fresh
    // KeyPackage. Old state alone grants no path back into the winner.
    let removed_stale = removal
        .workspace
        .prepare_management(ManagementAction::Remove(stale_member))
        .unwrap();
    let (registered, invitation, checkpoint) = removed_stale
        .workspace
        .prepare_invitation(0, false, false)
        .unwrap();
    let pending = arachne_security::PendingJoin::from_invitation(
        &invitation,
        &checkpoint,
        crate::test_key(77_001),
        "Readmitted member",
    )
    .unwrap();
    let fresh = registered
        .workspace
        .prepare_admission(
            crate::test_endpoint(77_001),
            pending.admission_request().unwrap(),
        )
        .unwrap();
    let mut proof = pending.join_proof().unwrap();
    proof
        .apply_add(&fresh.authorization, &fresh.commit)
        .unwrap();
    let fresh_member = pending.prepare_workspace(&proof, &fresh.welcome).unwrap();
    let mut fresh_node = bare_test_session(fresh_member);
    fork::require_send(&fresh_node).unwrap();
    let mut sender = fresh.workspace;
    let object = sender
        .protect_object(b"chat", b"fresh", b"readmitted")
        .unwrap();
    assert!(
        owner(&fresh_node)
            .unprotect_object(b"chat", b"fresh", &object)
            .is_ok()
    );
    assert!(
        owner(&restored)
            .unprotect_object(b"chat", b"fresh", &object)
            .is_err()
    );
    assert!(start_self_update(&mut fresh_node, std::time::Instant::now()).unwrap());
}

#[test]
fn two_hundred_seeded_three_partition_schedules_converge_and_preserve_removes() {
    let (administrators, members) = three_administrators();
    let targets: Vec<_> = members
        .iter()
        .map(|member| member.member().unwrap().id())
        .collect();
    for seed in 1..=200u64 {
        let mut random = seed;
        let mut removed = BTreeSet::new();
        let mut nodes: Vec<_> = administrators
            .iter()
            .map(|admin| bare_test_session(admin.provisional_copy().unwrap()))
            .collect();
        for (partition, node) in nodes.iter_mut().enumerate() {
            let count = 1 + next_random(&mut random) % 3;
            for index in 0..count {
                let operation = next_random(&mut random) % 4;
                let roster = owner(node).member_roster().unwrap();
                let available: Vec<_> = roster
                    .iter()
                    .filter(|member| {
                        targets.contains(&member.id) && (operation != 1 || !member.administrator)
                    })
                    .map(|member| member.id)
                    .collect();
                let action = if operation <= 1 && !available.is_empty() {
                    let target = available[next_random(&mut random) as usize % available.len()];
                    if operation == 0 {
                        removed.insert(target);
                        ManagementAction::Remove(target)
                    } else {
                        ManagementAction::Promote(target)
                    }
                } else if operation == 2 {
                    assert!(
                        start_self_update(
                            node,
                            std::time::Instant::now() + self_update::SELF_UPDATE_INTERVAL
                        )
                        .unwrap()
                    );
                    adopt_staged(node);
                    continue;
                } else {
                    let mut key = [seed as u8; 32];
                    key[0] = partition as u8;
                    key[1] = index as u8;
                    ManagementAction::CreateInvitation(key, 0, false)
                };
                stage_management(node, action).unwrap();
                adopt_staged(node);
            }
        }
        heal(&mut nodes, random);
        for node in &nodes {
            let roster = owner(node).member_roster().unwrap();
            assert!(
                roster.iter().all(|member| !removed.contains(&member.id)),
                "seed {seed}: an adopted Remove was lost during convergence"
            );
        }
        if seed % 25 == 0 {
            eprintln!("A2 convergence: {seed}/200 seeds passed");
        }
    }
}

#[test]
fn a_later_losing_remove_survives_its_issuers_demotion_on_the_winner() {
    let (administrators, members) = three_administrators();
    let issuer = administrators[0].member().unwrap().id();
    let target = members[0].member().unwrap().id();
    let mut nodes: Vec<_> = administrators.into_iter().map(bare_test_session).collect();
    stage_management(
        &mut nodes[0],
        ManagementAction::CreateInvitation([201; 32], 0, false),
    )
    .unwrap();
    adopt_staged(&mut nodes[0]);
    stage_management(&mut nodes[0], ManagementAction::Remove(target)).unwrap();
    adopt_staged(&mut nodes[0]);
    // Demote wins at the first difference. The later losing Remove was
    // signed while its issuer was still an administrator on that branch.
    stage_management(&mut nodes[1], ManagementAction::Demote(issuer)).unwrap();
    adopt_staged(&mut nodes[1]);
    heal(&mut nodes, 83);
    for node in &nodes {
        let roster = owner(node).member_roster().unwrap();
        assert!(!roster.iter().any(|member| member.id == target));
        assert!(
            roster
                .iter()
                .any(|member| member.id == issuer && !member.administrator)
        );
    }
}

#[test]
fn the_only_administrators_self_update_loses_to_a_members_committed_leave() {
    let (admin, mut members, _) = admit_members(15, "Member", 2);
    for member in &mut members {
        catch_up(&admin, member);
    }
    let leaving = members.remove(0);
    let carrier = members.remove(0);
    let departed = leaving.member().unwrap().id();
    let leave = carrier
        .prepare_revocation(&arachne_security::OrderStep::new(
            leaving.leave_order().unwrap(),
        ))
        .unwrap();
    let mut nodes = vec![bare_test_session(admin), bare_test_session(carrier)];
    assert!(
        start_self_update(
            &mut nodes[0],
            std::time::Instant::now() + self_update::SELF_UPDATE_INTERVAL,
        )
        .unwrap()
    );
    adopt_staged(&mut nodes[0]);
    stage_prepared(&mut nodes[1], leave).unwrap();
    adopt_staged(&mut nodes[1]);
    heal(&mut nodes, 84);
    for node in &nodes {
        let roster = owner(node).member_roster().unwrap();
        assert_eq!(
            roster.iter().filter(|member| member.administrator).count(),
            1
        );
        assert!(!roster.iter().any(|member| member.id == departed));
    }
}

#[test]
fn a_carried_remove_expires_after_the_order_window_and_releases_quarantine() {
    let (admin, mut members, _) = admit_members(16, "Member", 3);
    for member in &mut members {
        catch_up(&admin, member);
    }
    let target = members.remove(0).member().unwrap().id();
    let mut sender = members.remove(0);
    let observer = members.remove(0);
    let order = arachne_security::OrderStep::new(
        admin
            .issue_revocation(arachne_security::RevocationKind::Remove, target)
            .unwrap(),
    );
    let mut nodes = vec![bare_test_session(admin), bare_test_session(observer)];
    for node in &mut nodes {
        assert!(
            fork::receive_order(node, &order.to_bytes().unwrap())
                .unwrap()
                .is_some()
        );
        adopt_staged(node);
        assert!(fork::require_send(node).is_err());
    }
    let mut last_valid = Vec::new();
    for index in 0..=arachne_security::ORDER_WINDOW {
        let update = sender.prepare_self_update().unwrap();
        let wire = owner_wire_step(
            &sender,
            &arachne_security::MembershipAuthorization::SelfUpdate,
            &update.commit,
            usize::MAX,
        )
        .unwrap();
        sender = update.workspace;
        for node in &mut nodes {
            stage_update(node, join_step_from_wire(&wire).unwrap()).unwrap();
            adopt_staged(node);
            if index < arachne_security::ORDER_WINDOW {
                assert!(fork::require_send(node).is_err());
            } else {
                fork::require_send(node).unwrap();
                assert_eq!(activity_value(node)["state"], "active");
            }
        }
        if index + 1 == arachne_security::ORDER_WINDOW {
            last_valid = fork::records(&nodes[0], false)
                .unwrap()
                .into_iter()
                .find(|(name, _)| name.starts_with(b"runtime/branch/order/"))
                .unwrap()
                .1
                .to_vec();
        }
    }
    for node in &mut nodes {
        assert!(fork::receive_order(node, &last_valid).unwrap().is_none());
        fork::require_send(node).unwrap();
        assert!(
            owner(node)
                .member_roster()
                .unwrap()
                .iter()
                .any(|member| member.id == target)
        );
    }
}
