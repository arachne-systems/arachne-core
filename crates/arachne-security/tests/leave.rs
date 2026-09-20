use arachne_security::{
    ManagementAction, PendingJoin, PreparedManagementUpdate, StorageKey, Workspace,
};

fn add(
    owner: &Workspace,
    endpoint: u8,
) -> (Workspace, Workspace, arachne_security::PreparedAdmission) {
    let (invite, checkpoint) = owner.issue_invitation().unwrap();
    let join =
        PendingJoin::from_invitation(&invite, &checkpoint, [endpoint; 32], "Member").unwrap();
    let admitted = owner
        .prepare_admission([endpoint; 32], join.admission_request().unwrap())
        .unwrap();
    let mut proof = join.join_proof().unwrap();
    proof
        .apply_add(&admitted.authorization, &admitted.commit)
        .unwrap();
    let member = join.prepare_workspace(&proof, &admitted.welcome).unwrap();
    (
        admitted.workspace.provisional_copy().unwrap(),
        member,
        admitted,
    )
}

#[test]
fn member_departure_requires_own_signature_rotates_keys_and_survives_restore() {
    let (admin, member, _) = add(&Workspace::create([1; 32], "Admin").unwrap(), 2);
    let (admin, helper, joined) = add(&admin, 3);
    let member = member
        .prepare_admission_update(&joined.authorization, &joined.commit)
        .unwrap();
    let action = member.leave_action().unwrap();
    let ManagementAction::Leave(id, signature) = action else {
        panic!("wrong intent")
    };
    let mut bad = signature;
    bad[0] ^= 1;
    assert!(
        helper
            .prepare_management(ManagementAction::Leave(id, bad))
            .is_err()
    );
    assert!(
        helper
            .prepare_management(ManagementAction::Leave(
                admin.member().unwrap().id(),
                signature
            ))
            .is_err()
    );
    assert!(
        Workspace::create([4; 32], "Other group")
            .unwrap()
            .prepare_management(action)
            .is_err()
    );
    assert!(admin.leave_action().is_err()); // No silent abandonment of the remaining team.
    let change = helper.prepare_management(action).unwrap(); // No administrator required online.
    let PreparedManagementUpdate::Active(admin) = admin
        .prepare_management_update(action, &change.commit)
        .unwrap()
    else {
        panic!("wrong member ended")
    };
    let PreparedManagementUpdate::Removed(ended) = member
        .prepare_management_update(action, &change.commit)
        .unwrap()
    else {
        panic!("departed owner retained keys")
    };
    assert_eq!(admin.member_count(), 2);
    assert!(admin.member_roster().unwrap().iter().all(|m| m.id != id));
    assert!(admin.prepare_management(action).is_err()); // Replay cannot leave another membership.
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
    let solo = Workspace::create([1; 32], "Admin").unwrap();
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
    let (admin, member, _) = add(&solo, 2);
    assert!(admin.prepare_solo_leave().is_err());
    assert!(member.prepare_solo_leave().is_err());
    let promotion = admin
        .prepare_management(ManagementAction::Promote(member.member().unwrap().id()))
        .unwrap();
    let PreparedManagementUpdate::Active(member) = member
        .prepare_management_update(promotion.action, &promotion.commit)
        .unwrap()
    else {
        panic!()
    };
    let action = promotion.workspace.leave_action().unwrap();
    assert!(member.prepare_management(action).is_ok());
}
