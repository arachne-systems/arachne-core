//! ADR A2 runtime fork regression checks. In-process MLS; no network exchange.
use super::*;
use crate::ops::candidate::{AdoptKind, adopt};
use crate::session::{activity_value, activity_view};
use arachne_security::{ManagementAction, PreparedManagementUpdate, Workspace};

mod convergence;

fn owner(session: &Session) -> &Workspace {
    session.workspace.as_deref().unwrap()
}
fn adopt_staged(session: &mut Session) {
    let token = session.transition.staged.as_ref().unwrap().snapshot.clone();
    adopt(session, AdoptKind::Admission, token).unwrap();
}

fn assert_recovery_activity(session: &mut Session, reason: &str) {
    let expected = json!({"state": "recovering", "reason": reason});
    assert_eq!(activity_value(session), expected);
    assert_eq!(
        serde_json::to_value(activity_view(session)).unwrap(),
        expected
    );
    assert_eq!(
        serde_json::to_value(crate::ops::workspace::state(session).unwrap()).unwrap()["activity"],
        expected,
    );
    assert_eq!(
        serde_json::to_value(crate::ops::workspace::metrics(session).unwrap()).unwrap()["activity"],
        expected,
    );
    assert_eq!(session.activity.phase, WorkspacePhase::Active);
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
    assert_recovery_activity(&mut session, "branch_orphaned");
    assert!(
        !start_self_update(
            &mut session,
            std::time::Instant::now() + self_update::SELF_UPDATE_INTERVAL,
        )
        .unwrap(),
        "an orphan must not stage an automatic self-update"
    );
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

#[test]
fn a_branch_reply_starts_at_the_responders_available_history() {
    let (first, second, _) = two_admins(1);
    let from = first.history_start().unwrap();
    let available = second.history_start().unwrap();
    assert!(
        available > from,
        "the joiner starts from a later checkpoint"
    );
    let query = wire::encode_branch_query(&wire::BranchQuery {
        workspace: first.id(),
        from,
        until: first.epoch(),
    })
    .unwrap();
    let reply = fork::reply(Some(&second), first.endpoint(), &query);
    let reply = wire::decode_branch_reply(&reply).unwrap();
    assert_eq!(
        reply.rows.first().map(|row| row.epoch),
        Some(available),
        "an old caller cursor must not hide the responder's available branch"
    );
    assert_eq!(reply.from, available);
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
    assert_recovery_activity(&mut session, "branch_send_quarantined");
    assert!(
        !start_self_update(
            &mut session,
            std::time::Instant::now() + self_update::SELF_UPDATE_INTERVAL,
        )
        .unwrap(),
        "send quarantine must not stage an automatic self-update"
    );
    // Branch records restore the quarantine before any new publication.
    let records = fork::records(&session, false).unwrap();
    let mut restored = bare_test_session(owner(&session).provisional_copy().unwrap());
    fork::restore(&mut restored, &records).unwrap();
    assert!(fork::require_send(&restored).is_err());
    assert_recovery_activity(&mut restored, "branch_send_quarantined");
    let (_, encoded) = records
        .iter()
        .find(|(name, _)| name.starts_with(b"runtime/branch/order/"))
        .unwrap();
    let mut receiver = bare_test_session(owner(&session).provisional_copy().unwrap());
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
    let token = session.transition.staged.as_ref().unwrap().snapshot.clone();
    let adopted = adopt(&mut session, AdoptKind::Admission, token).unwrap();
    assert_eq!(
        serde_json::to_value(adopted).unwrap()["activity"]["state"],
        "active"
    );
    fork::require_send(&session).unwrap();
    assert_eq!(
        activity_value(&session),
        json!({"state": "active", "reason": null})
    );
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

#[test]
fn settlement_needs_every_prior_member_on_the_same_next_chain() {
    let (admin, mut members, _) = admit_members(7, "Observer", 1);
    let observer = members.remove(0);
    let observer_id = observer.member().unwrap().id();
    let epoch = admin.epoch();
    let mut session = bare_test_session(admin);
    stage_management(
        &mut session,
        ManagementAction::CreateInvitation([88; 32], 0, false),
    )
    .unwrap();
    adopt_staged(&mut session);
    assert!(
        session
            .membership
            .fork
            .retained
            .as_ref()
            .unwrap()
            .snapshot(epoch)
            .is_some()
    );
    fork::observe(
        &mut session,
        observer_id,
        epoch,
        observer.epoch_fingerprint(),
    );
    assert!(
        fork::stage_settlement(&mut session).unwrap().is_none(),
        "a report at E does not settle E"
    );
    fork::observe(&mut session, observer_id, epoch + 1, [0; 32]);
    assert!(
        fork::stage_settlement(&mut session).unwrap().is_none(),
        "another branch cannot settle this one"
    );
    let fingerprint = owner(&session).epoch_fingerprint();
    fork::observe(&mut session, observer_id, epoch + 1, fingerprint);
    assert!(
        fork::stage_settlement(&mut session).unwrap().is_some(),
        "every old member reached E+1: stage deletion"
    );
    assert!(
        session
            .membership
            .fork
            .retained
            .as_ref()
            .unwrap()
            .snapshot(epoch)
            .is_some(),
        "deletion waits for durable adoption"
    );
    adopt_staged(&mut session);
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
    let records = fork::records(&session, false).unwrap();
    let mut restored = bare_test_session(owner(&session).provisional_copy().unwrap());
    fork::restore(&mut restored, &records).unwrap();
    assert!(
        restored
            .membership
            .fork
            .retained
            .as_ref()
            .unwrap()
            .snapshot(epoch)
            .is_none()
    );
}

#[test]
fn removal_epoch_waits_for_the_window_when_the_removed_member_cannot_report() {
    let (admin, members, _) = admit_members(8, "Member", 2);
    let removed = members[0].member().unwrap().id();
    let survivor = members[1].member().unwrap().id();
    let epoch = admin.epoch();
    let mut session = bare_test_session(admin);
    stage_management(&mut session, ManagementAction::Remove(removed)).unwrap();
    adopt_staged(&mut session);
    let fingerprint = owner(&session).epoch_fingerprint();
    fork::observe(&mut session, survivor, epoch + 1, fingerprint);
    assert!(fork::stage_settlement(&mut session).unwrap().is_none());
    assert!(
        session
            .membership
            .fork
            .retained
            .as_ref()
            .unwrap()
            .snapshot(epoch)
            .is_some()
    );
}

#[test]
fn own_losing_publication_is_reencrypted_once_with_its_stable_id() {
    for kind in 0..4 {
        check_own_republication(kind);
    }
}

fn check_own_republication(kind: u8) {
    use crate::ops::publication::{self, CurrentPublication, StagePublicationArgs};
    use arachne_delivery::inbox::{InboxStage, ObjectInbox};
    use arachne_routing::PublicationContext;
    let (first, second, mut members) = two_admins(2);
    let removed = members.remove(0);
    let removal = first
        .prepare_management(ManagementAction::Remove(removed.member().unwrap().id()))
        .unwrap();
    let losing = second
        .prepare_management(ManagementAction::CreateInvitation([91; 32], 0, false))
        .unwrap();
    let on_loser = active(
        removed
            .prepare_step_update(&losing.authorization, &losing.commit)
            .unwrap(),
    );
    let mut session = bare_test_session(members.remove(0));
    let fork_epoch = owner(&session).epoch();
    let encoded = encode_step(&losing.authorization, &losing.commit).unwrap();
    stage_update(&mut session, JoinStep::binary(encoded, None)).unwrap();
    adopt_staged(&mut session);
    let id = [92; 16];
    let mut recipients = match kind {
        1 => vec![first.member().unwrap().id(), removed.member().unwrap().id()],
        3 => vec![first.member().unwrap().id()],
        _ => Vec::new(),
    };
    recipients.sort_unstable();
    let current = (kind == 2).then_some(CurrentPublication {
        selector: [12; 32],
        replacement_key: [13; 32],
        expires_at: u64::MAX,
        tombstone: false,
    });
    let staged = publication::stage(
        &mut session,
        StagePublicationArgs {
            workspace: None,
            revision: 7,
            topic: "chat/room".to_owned(),
            id,
            payload: b"retained on the losing branch".to_vec(),
            recipients,
            current,
            bulk: false,
        },
    )
    .unwrap();
    let accepted_before_switch = if kind == 3 {
        let receiver = active(
            first
                .prepare_step_update(&losing.authorization, &losing.commit)
                .unwrap(),
        );
        let WorkspaceTransition::RoutedPublication(context, _, packet, _, recipients) =
            &session.transition.staged.as_ref().unwrap().transition
        else {
            panic!("publication")
        };
        let (_, ciphertext) = PublicationContext::unpack(
            context.workspace,
            context.revision,
            context.topic.clone(),
            packet,
        )
        .unwrap();
        let InboxStage::Prepared(inbox) = ObjectInbox::new(receiver.id(), receiver.epoch())
            .stage_with_recipients(&receiver, context, recipients, ciphertext)
            .unwrap()
        else {
            panic!("new direct object")
        };
        let pending = inbox.pending(&receiver).unwrap().unwrap();
        let inbox = inbox
            .acknowledge(
                pending.message.member,
                &context.topic,
                pending.counter,
                pending.context.id,
            )
            .unwrap();
        Some((receiver, inbox))
    } else {
        None
    };
    adopt(&mut session, AdoptKind::Publication, staged.snapshot).unwrap();
    let packet = offer_packet(
        &first,
        fork_epoch,
        &removal.authorization,
        &removal.commit,
        false,
    )
    .unwrap();
    receive_offer(&mut session, &packet).unwrap();
    adopt_staged(&mut session);
    let branch_records = fork::records(&session, false).unwrap();
    assert!(branch_records.contains_key(b"runtime/branch/republications".as_slice()));
    let mut restored = bare_test_session(owner(&session).provisional_copy().unwrap());
    restored.delivery.publisher = session.delivery.publisher.clone();
    restored.delivery.inbox = session.delivery.inbox.clone();
    fork::restore(&mut restored, &branch_records).unwrap();
    session = restored;
    assert!(
        fork::stage_republication(&mut session).unwrap().is_some(),
        "own losing data must survive the switch for re-publication"
    );
    let WorkspaceTransition::Republication(context, _, packet, _, recipients) =
        &session.transition.staged.as_ref().unwrap().transition
    else {
        panic!("expected recovery publication")
    };
    let context = context.clone();
    let recipients = recipients.clone();
    let live = (kind == 2)
        .then(|| arachne_delivery::current::LiveCurrentPacket::from_wire(packet).unwrap());
    let (_, ciphertext) = PublicationContext::unpack(
        context.workspace,
        context.revision,
        context.topic.clone(),
        live.as_ref()
            .map_or(packet.as_slice(), |live| live.packet.as_slice()),
    )
    .unwrap();
    let ciphertext = ciphertext.to_vec();
    let aad = if let Some(live) = &live {
        live.metadata.authenticated_context(&context)
    } else if recipients.is_empty() {
        context.authenticated_bytes()
    } else {
        context.direct_authenticated_bytes(&recipients).unwrap()
    };
    adopt_staged(&mut session);
    assert!(
        fork::stage_republication(&mut session).unwrap().is_none(),
        "one saved publication drains one recovery item"
    );
    assert_eq!(context.id, id);
    let opened = removal
        .workspace
        .unprotect_object(b"chat", &aad, &ciphertext)
        .unwrap();
    assert_eq!(opened.message.payload, b"retained on the losing branch");
    assert!(
        on_loser
            .unprotect_object(b"chat", &aad, &ciphertext)
            .is_err(),
        "the removed member cannot open the new object"
    );
    let inbox = ObjectInbox::new(removal.workspace.id(), removal.workspace.epoch());
    let staged = if let Some(live) = live {
        inbox.stage_live_current(&removal.workspace, &context, live.metadata, &ciphertext)
    } else {
        inbox.stage_with_recipients(&removal.workspace, &context, &recipients, &ciphertext)
    }
    .unwrap();
    let InboxStage::Prepared(inbox) = staged else {
        panic!("expected new publication")
    };
    assert!(
        inbox.pending(&removal.workspace).unwrap().is_some(),
        "re-published kind {kind} must not wait behind a lost sequence"
    );
    if let Some((receiver, prior)) = accepted_before_switch {
        let prior = prior
            .rebase(&receiver, fork_epoch, &removal.workspace)
            .unwrap();
        let staged = prior
            .stage_with_recipients(&removal.workspace, &context, &recipients, &ciphertext)
            .unwrap();
        let InboxStage::Prepared(prior) = staged else {
            panic!("a duplicate direct object must retain its new branch sequence proof")
        };
        assert!(
            prior.pending(&removal.workspace).unwrap().is_none(),
            "stable id suppresses a second application delivery"
        );
        let staged = publication::stage(
            &mut session,
            StagePublicationArgs {
                workspace: None,
                revision: 7,
                topic: "chat/room".to_owned(),
                id: [93; 16],
                payload: b"next".to_vec(),
                recipients: recipients.clone(),
                current: None,
                bulk: false,
            },
        )
        .unwrap();
        let WorkspaceTransition::RoutedPublication(context, _, packet, _, recipients) =
            &session.transition.staged.as_ref().unwrap().transition
        else {
            panic!("publication")
        };
        let (_, ciphertext) = PublicationContext::unpack(
            context.workspace,
            context.revision,
            context.topic.clone(),
            packet,
        )
        .unwrap();
        let InboxStage::Prepared(next) = prior
            .stage_with_recipients(&removal.workspace, context, recipients, ciphertext)
            .unwrap()
        else {
            panic!("new direct object")
        };
        assert_eq!(
            next.pending(&removal.workspace)
                .unwrap()
                .unwrap()
                .message
                .payload,
            b"next"
        );
        adopt(&mut session, AdoptKind::Publication, staged.snapshot).unwrap();
    }
}

#[test]
fn the_losing_administrator_retries_its_own_action_once() {
    let (first, second, members) = two_admins(2);
    let epoch = first.epoch();
    let mut first = bare_test_session(first);
    let mut second = bare_test_session(second);
    stage_management(
        &mut first,
        ManagementAction::Promote(members[0].member().unwrap().id()),
    )
    .unwrap();
    stage_management(
        &mut second,
        ManagementAction::CreateInvitation([94; 32], 0, false),
    )
    .unwrap();
    adopt_staged(&mut first);
    adopt_staged(&mut second);
    let (winner, loser) =
        if owner(&first).branch_key(epoch).unwrap() < owner(&second).branch_key(epoch).unwrap() {
            (&first, &mut second)
        } else {
            (&second, &mut first)
        };
    let (lost_auth, _) = owner(loser).history_step(epoch).unwrap().unwrap();
    let (auth, commit) = owner(winner).history_step(epoch).unwrap().unwrap();
    receive_offer(
        loser,
        &offer_packet(owner(winner), epoch, &auth, &commit, false).unwrap(),
    )
    .unwrap();
    adopt_staged(loser);
    assert_eq!(
        owner(loser).epoch_fingerprint(),
        owner(winner).epoch_fingerprint()
    );
    let records = fork::records(loser, false).unwrap();
    let mut restored = bare_test_session(owner(loser).provisional_copy().unwrap());
    restored.storage = loser.storage.clone();
    fork::restore(&mut restored, &records).unwrap();
    *loser = restored;
    assert!(
        fork::stage_retry(loser).unwrap().is_some(),
        "the losing administrator must retry its own valid action"
    );
    adopt_staged(loser);
    let (retried_auth, _) = owner(loser).history_step(epoch + 1).unwrap().unwrap();
    match (lost_auth, retried_auth) {
        (
            arachne_security::MembershipAuthorization::Management(expected),
            arachne_security::MembershipAuthorization::Management(actual),
        ) => assert_eq!(expected, actual),
        _ => panic!("expected management retry"),
    }
    assert!(fork::stage_retry(loser).unwrap().is_none());
    let records = fork::records(loser, false).unwrap();
    let mut restored = bare_test_session(owner(loser).provisional_copy().unwrap());
    restored.storage = loser.storage.clone();
    fork::restore(&mut restored, &records).unwrap();
    *loser = restored;
    // A second loss does not reset the one-retry allowance, even after restart.
    let removal = owner(winner)
        .prepare_management(ManagementAction::Remove(members[1].member().unwrap().id()))
        .unwrap();
    receive_offer(
        loser,
        &offer_packet(
            owner(winner),
            epoch + 1,
            &removal.authorization,
            &removal.commit,
            false,
        )
        .unwrap(),
    )
    .unwrap();
    adopt_staged(loser);
    let value = fork::stage_retry(loser).unwrap().unwrap();
    assert_eq!(value["branch_state"], "action_lost");
    assert_eq!(value["reason"], "retry_already_used");
    let before = owner(loser).epoch();
    adopt_staged(loser);
    assert_eq!(owner(loser).epoch(), before);
    assert!(fork::stage_retry(loser).unwrap().is_none());
}
