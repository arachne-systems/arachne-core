mod common;
use arachne_security::{
    Invitation, ManagementAction, OrderStep, PendingJoin, PreparedManagementUpdate, RevocationKind,
    StorageKey, Workspace,
};
use common::{test_endpoint, test_key};

/// A registered reusable link and the owner that holds its registration.
fn register(owner: &Workspace) -> (Workspace, Invitation, Vec<u8>) {
    let (registration, invite, checkpoint) = owner.prepare_invitation(0, false, false).unwrap();
    (registration.workspace, invite, checkpoint)
}

fn add(
    owner: &Workspace,
    (invite, checkpoint): (&Invitation, &[u8]),
    endpoint: u8,
) -> (Workspace, Workspace, arachne_security::PreparedAdmission) {
    let join =
        PendingJoin::from_invitation(invite, checkpoint, test_key(u64::from(endpoint)), "Member")
            .unwrap();
    let admitted = owner
        .prepare_admission(
            test_endpoint(u64::from(endpoint)),
            join.admission_request().unwrap(),
        )
        .unwrap();
    let mut proof = join.join_proof().unwrap();
    // A reused link replays every step since its checkpoint, ending with this Add.
    for (authorization, commit) in admitted
        .workspace
        .membership_history(
            test_endpoint(u64::from(endpoint)),
            join.admission_request().unwrap(),
            checkpoint,
        )
        .unwrap()
    {
        proof.apply_transition(&authorization, &commit).unwrap();
    }
    let member = join.prepare_workspace(&proof, &admitted.welcome).unwrap();
    (
        admitted.workspace.provisional_copy().unwrap(),
        member,
        admitted,
    )
}

#[test]
fn member_departure_requires_own_signature_rotates_keys_and_survives_restore() {
    let (admin, invite, checkpoint) = register(&Workspace::create(test_key(1), "Admin").unwrap());
    let (admin, member, _) = add(&admin, (&invite, &checkpoint), 2);
    let (admin, helper, joined) = add(&admin, (&invite, &checkpoint), 3);
    let member = member
        .prepare_admission_update(&joined.authorization, &joined.commit)
        .unwrap();
    let order = member.leave_order().unwrap();
    assert_eq!(order.kind, RevocationKind::Leave);
    let id = order.target;
    let mut bad = order.clone();
    bad.signature[0] ^= 1;
    assert!(helper.prepare_revocation(&OrderStep::new(bad)).is_err());
    // A leave order names only its signer.
    let mut other = order.clone();
    other.target = admin.member().unwrap().id();
    assert!(helper.prepare_revocation(&OrderStep::new(other)).is_err());
    assert!(
        member
            .issue_revocation(RevocationKind::Leave, admin.member().unwrap().id())
            .is_err()
    );
    let step = OrderStep::new(order);
    assert!(
        Workspace::create(test_key(4), "Other group")
            .unwrap()
            .prepare_revocation(&step)
            .is_err()
    );
    assert!(admin.leave_order().is_err()); // No silent abandonment of the remaining team.
    let change = helper.prepare_revocation(&step).unwrap(); // No administrator required online.
    let PreparedManagementUpdate::Active(admin) = admin
        .prepare_step_update(&change.authorization, &change.commit)
        .unwrap()
    else {
        panic!("wrong member ended")
    };
    let PreparedManagementUpdate::Removed(ended) = member
        .prepare_step_update(&change.authorization, &change.commit)
        .unwrap()
    else {
        panic!("departed owner retained keys")
    };
    assert_eq!(admin.member_count(), 2);
    assert!(admin.member_roster().unwrap().iter().all(|m| m.id != id));
    assert!(admin.prepare_revocation(&step).is_err()); // Replay cannot leave another membership.
    let key = StorageKey::derive(&[9; 32]).unwrap();
    let sealed = ended.seal(&key).unwrap();
    assert_eq!(
        arachne_security::RemovedMembership::restore(&key, member.endpoint(), member.id(), &sealed)
            .unwrap(),
        ended
    );
    let restored = Workspace::restore(
        &key,
        helper.endpoint(),
        helper.id(),
        &change.workspace.seal(&key).unwrap(),
    )
    .unwrap();
    assert_eq!(restored.member_count(), 2);
}

#[test]
fn last_member_can_end_locally_but_admin_must_handover_a_team() {
    let solo = Workspace::create(test_key(1), "Admin").unwrap();
    let ended = solo.prepare_solo_leave().unwrap();
    let key = StorageKey::derive(&[9; 32]).unwrap();
    assert_eq!(
        arachne_security::RemovedMembership::restore(
            &key,
            solo.endpoint(),
            solo.id(),
            &ended.seal(&key).unwrap()
        )
        .unwrap(),
        ended
    );
    let (solo, invite, checkpoint) = register(&solo);
    let (admin, member, _) = add(&solo, (&invite, &checkpoint), 2);
    assert!(admin.prepare_solo_leave().is_err());
    assert!(member.prepare_solo_leave().is_err());
    let promotion = admin
        .prepare_management(ManagementAction::Promote(member.member().unwrap().id()))
        .unwrap();
    let PreparedManagementUpdate::Active(member) = member
        .prepare_step_update(&promotion.authorization, &promotion.commit)
        .unwrap()
    else {
        panic!()
    };
    let order = promotion.workspace.leave_order().unwrap();
    assert!(member.prepare_revocation(&OrderStep::new(order)).is_ok());
}
