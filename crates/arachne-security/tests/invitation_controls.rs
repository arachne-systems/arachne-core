use arachne_security::{
    ManagementAction, PendingJoin, PreparedManagement, PreparedManagementUpdate, Workspace,
};

fn apply(owner: &Workspace, change: &PreparedManagement) -> Workspace {
    let PreparedManagementUpdate::Active(owner) = owner
        .prepare_management_update(change.action, &change.commit)
        .unwrap()
    else {
        panic!()
    };
    *owner
}
fn joined(
    owner: &Workspace,
    invite: &arachne_security::Invitation,
    checkpoint: &[u8],
    endpoint: u8,
) -> (Workspace, Workspace) {
    let pending =
        PendingJoin::from_invitation(invite, checkpoint, [endpoint; 32], "Attendee").unwrap();
    let admitted = owner
        .prepare_admission([endpoint; 32], pending.admission_request().unwrap())
        .unwrap();
    let mut proof = pending.join_proof().unwrap();
    // Exercise the old-invitation history through each accepted policy change.
    for (auth, commit) in admitted
        .workspace
        .membership_history(
            [endpoint; 32],
            pending.admission_request().unwrap(),
            checkpoint,
        )
        .unwrap()
    {
        proof.apply_transition(&auth, &commit).unwrap();
    }
    let member = pending
        .prepare_workspace(&proof, &admitted.welcome)
        .unwrap();
    (admitted.workspace, member)
}

#[test]
fn open_event_link_is_reusable_without_admin_and_disable_survives_history() {
    let admin = Workspace::create([1; 32], "Organizer").unwrap();
    let (created, invite, checkpoint) = admin.prepare_invitation(0, false, false).unwrap();
    assert!(
        created
            .workspace
            .retained_invitation_checkpoint(&created.action)
            .is_some()
    );
    let storage_key = arachne_security::StorageKey::derive(&[8; 32]).unwrap();
    let restored = Workspace::restore(
        &storage_key,
        created.workspace.endpoint(),
        created.workspace.id(),
        &created.workspace.seal(&storage_key).unwrap(),
    )
    .unwrap();
    assert!(
        restored
            .retained_invitation_checkpoint(&created.action)
            .is_some()
    );
    let mut records = created.workspace.export_records().unwrap();
    let saved = records
        .iter_mut()
        .find(|(name, _)| name.starts_with(b"security/invitation-checkpoint/"))
        .unwrap()
        .1;
    let end = saved.len() - 1;
    saved[end] ^= 1;
    assert!(
        Workspace::restore_records(
            created.workspace.endpoint(),
            created.workspace.id(),
            &records,
        )
        .is_err()
    );
    let (admin, helper) = joined(&created.workspace, &invite, &checkpoint, 2);
    let restored = Workspace::restore(
        &storage_key,
        admin.endpoint(),
        admin.id(),
        &admin.seal(&storage_key).unwrap(),
    )
    .unwrap();
    assert!(
        restored
            .retained_invitation_checkpoint(&created.action)
            .is_some()
    );
    let (helper, _) = joined(&helper, &invite, &checkpoint, 3); // Organizer need not handle this join.
    let id = helper.invitation_controls().unwrap().1[0].key;
    assert!(
        helper
            .prepare_management(ManagementAction::DisableInvitation(id))
            .is_err()
    );
    // Synchronize the organizer before disabling the event link.
    let (auth, commit) = helper
        .membership_update_for(admin.endpoint(), admin.epoch())
        .unwrap()
        .unwrap();
    let arachne_security::MembershipAuthorization::Admission(auth) = auth else {
        panic!()
    };
    let admin = admin.prepare_admission_update(&auth, &commit).unwrap();
    let disable = admin
        .prepare_management(ManagementAction::DisableInvitation(id))
        .unwrap();
    assert!(
        disable
            .workspace
            .retained_invitation_checkpoint(&created.action)
            .is_none()
    );
    let helper = apply(&helper, &disable);
    let next =
        PendingJoin::from_invitation(&invite, &checkpoint, [4; 32], "Late attendee").unwrap();
    assert!(
        helper
            .prepare_admission([4; 32], next.admission_request().unwrap())
            .err()
            .unwrap()
            .contains("disabled")
    );
    assert_eq!(helper.member_count(), 3); // Disabling a link does not remove anyone.
    let key = arachne_security::StorageKey::derive(&[9; 32]).unwrap();
    let restored = Workspace::restore(
        &key,
        helper.endpoint(),
        helper.id(),
        &helper.seal(&key).unwrap(),
    )
    .unwrap();
    assert!(!restored.invitation_controls().unwrap().1[0].enabled);
}

#[test]
fn personal_invitation_admits_only_the_approved_request_through_an_ordinary_member() {
    let admin = Workspace::create([1; 32], "Admin").unwrap();
    let (open, token, checkpoint) = admin.prepare_invitation(0, false, false).unwrap();
    let (admin, helper) = joined(&open.workspace, &token, &checkpoint, 2);
    let (personal, token, checkpoint) = admin.prepare_invitation(0, true, false).unwrap();
    let helper = apply(&helper, &personal);
    let intended =
        PendingJoin::from_invitation(&token, &checkpoint, [3; 32], "Invited person").unwrap();
    let copied = PendingJoin::from_invitation(&token, &checkpoint, [4; 32], "Copied link").unwrap();
    assert!(
        helper
            .prepare_admission([3; 32], intended.admission_request().unwrap())
            .is_err()
    );
    assert!(
        helper
            .prepare_invitation_approval(intended.admission_request().unwrap())
            .is_err()
    );
    let approval = personal
        .workspace
        .prepare_invitation_approval(intended.admission_request().unwrap())
        .unwrap();
    let helper = apply(&helper, &approval);
    assert!(
        helper
            .prepare_admission([4; 32], copied.admission_request().unwrap())
            .is_err()
    );
    let accepted = helper
        .prepare_admission([3; 32], intended.admission_request().unwrap())
        .unwrap();
    let mut proof = intended.join_proof().unwrap();
    for (auth, commit) in accepted
        .workspace
        .membership_history([3; 32], intended.admission_request().unwrap(), &checkpoint)
        .unwrap()
    {
        proof.apply_transition(&auth, &commit).unwrap();
    }
    assert!(
        intended
            .prepare_workspace(&proof, &accepted.welcome)
            .is_ok()
    );
    assert!(
        accepted
            .workspace
            .prepare_admission([3; 32], intended.admission_request().unwrap())
            .is_err()
    );
    assert!(
        accepted
            .workspace
            .retained_admission([3; 32], intended.admission_request().unwrap())
            .unwrap()
            .is_some()
    ); // Retry the same join, never create another.
}

#[test]
fn automatic_personal_invitation_binds_only_the_first_request() {
    let admin = Workspace::create([1; 32], "Admin").unwrap();
    let (created, token, checkpoint) = admin.prepare_invitation(0, true, true).unwrap();
    let intended =
        PendingJoin::from_invitation(&token, &checkpoint, [2; 32], "Invited person").unwrap();
    let copied = PendingJoin::from_invitation(&token, &checkpoint, [3; 32], "Copied link").unwrap();
    assert!(created.workspace.invitation_controls().unwrap().1[0].automatic());
    assert_eq!(
        created
            .workspace
            .prepare_admission([2; 32], intended.admission_request().unwrap())
            .err()
            .unwrap(),
        arachne_security::INVITATION_AUTOMATIC_APPROVAL_REQUIRED
    );
    let approval = created
        .workspace
        .prepare_invitation_approval(intended.admission_request().unwrap())
        .unwrap();
    assert!(!approval.workspace.invitation_controls().unwrap().1[0].automatic());
    assert!(
        approval
            .workspace
            .prepare_admission([2; 32], intended.admission_request().unwrap())
            .is_ok()
    );
    assert!(
        approval
            .workspace
            .prepare_admission([3; 32], copied.admission_request().unwrap())
            .is_err()
    );
}

#[test]
fn expiry_rejects_new_requests_and_roles_cannot_reset_invitation_controls() {
    let admin = Workspace::create([1; 32], "Admin").unwrap();
    assert!(admin.prepare_invitation(1, false, false).is_err());
    let (token, checkpoint) = admin.issue_invitation().unwrap();
    let id = token.key();
    let expired = admin
        .prepare_management(ManagementAction::CreateInvitation(id, 1, false))
        .unwrap();
    let pending = PendingJoin::from_invitation(&token, &checkpoint, [2; 32], "Too late").unwrap();
    assert!(
        expired
            .workspace
            .prepare_admission([2; 32], pending.admission_request().unwrap())
            .is_err()
    );
    let (fresh, token, checkpoint) = expired
        .workspace
        .prepare_invitation(0, false, false)
        .unwrap();
    let (admin, member) = joined(&fresh.workspace, &token, &checkpoint, 2);
    let promotion = admin
        .prepare_management(ManagementAction::Promote(member.member().unwrap().id()))
        .unwrap();
    assert_eq!(
        promotion.workspace.invitation_controls().unwrap(),
        admin.invitation_controls().unwrap()
    );
    assert!(
        member
            .prepare_management(ManagementAction::DisableInvitation(id))
            .is_err()
    );
}

#[test]
fn request_access_approves_and_declines_each_saved_request_independently() {
    let admin = Workspace::create([21; 32], "Organizer").unwrap();
    let (created, token, checkpoint) = admin.prepare_request_invitation(0).unwrap();
    let requests: Vec<_> = (22..=24)
        .map(|endpoint| {
            PendingJoin::from_invitation(&token, &checkpoint, [endpoint; 32], "Attendee").unwrap()
        })
        .collect();
    let first = created
        .workspace
        .prepare_invitation_approval(requests[0].admission_request().unwrap())
        .unwrap();
    // Approving a second person must not replace the first person's authority.
    let second = first
        .workspace
        .prepare_invitation_approval(requests[1].admission_request().unwrap())
        .unwrap();
    let declined = second
        .workspace
        .prepare_invitation_decline(requests[2].admission_request().unwrap())
        .unwrap();
    let records = declined.workspace.export_records().unwrap();
    let mut owner = Workspace::restore_records(
        declined.workspace.endpoint(),
        declined.workspace.id(),
        &records,
    )
    .unwrap();
    assert!(
        owner
            .prepare_admission([24; 32], requests[2].admission_request().unwrap())
            .err()
            .unwrap()
            .contains("disabled")
    );
    for (index, pending) in requests[..2].iter().enumerate() {
        let endpoint = [22 + index as u8; 32];
        let admitted = owner
            .prepare_admission(endpoint, pending.admission_request().unwrap())
            .unwrap();
        let mut proof = pending.join_proof().unwrap();
        for (auth, commit) in admitted
            .workspace
            .membership_history(endpoint, pending.admission_request().unwrap(), &checkpoint)
            .unwrap()
        {
            proof.apply_transition(&auth, &commit).unwrap();
        }
        assert!(pending.prepare_workspace(&proof, &admitted.welcome).is_ok());
        owner = admitted.workspace;
        assert!(
            owner
                .retained_admission(endpoint, pending.admission_request().unwrap())
                .unwrap()
                .is_some()
        );
    }
    let extra =
        PendingJoin::from_invitation(&token, &checkpoint, [25; 32], "Still waiting").unwrap();
    assert!(
        owner
            .prepare_admission([25; 32], extra.admission_request().unwrap())
            .is_err()
    );
    let stopped = owner
        .prepare_management(ManagementAction::DisableInvitation(token.key()))
        .unwrap();
    assert!(
        stopped
            .workspace
            .prepare_invitation_approval(extra.admission_request().unwrap())
            .is_err()
    );
    assert_eq!(owner.member_count(), 3);
}
