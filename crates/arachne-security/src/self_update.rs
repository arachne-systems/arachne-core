//! Member self-update (ADR A2 step 5).
//!
//! A member commits an empty commit with an update path: no proposals, no
//! extension change, the same credential, signature key, capabilities and
//! leaf extensions. It refreshes the member's leaf and path keys, which gives
//! post-compromise security, and it fills the tree nodes on the member's
//! direct path, so later commits encrypt to fewer nodes (B3c).
//!
//! It is fork class 4: it never displaces an administrator step. How often a
//! member sends one is runtime policy, not a validity rule.
use super::{MembershipAuthorization, PreparedManagementUpdate, Workspace};
use openmls_traits::OpenMlsProvider;

/// A staged self-update. Save `workspace` before adopting it or sending
/// `commit`; the original owner is unchanged.
pub struct PreparedSelfUpdate {
    pub workspace: Workspace,
    pub commit: Vec<u8>,
}

impl Workspace {
    /// Prepare this member's own update path commit.
    pub fn prepare_self_update(&self) -> Result<PreparedSelfUpdate, &'static str> {
        let mut candidate = self.provisional_copy()?;
        let commit = candidate
            .group
            .commit_builder()
            .force_self_update(true)
            .load_psks(candidate.provider.storage())
            .map_err(|_| "self update state failed")?
            .build(
                candidate.provider.rand(),
                candidate.provider.crypto(),
                &candidate._signer,
                |_| true,
            )
            .map_err(|_| "self update preparation failed")?
            .stage_commit(&candidate.provider)
            .map_err(|_| "self update staging failed")?
            .into_contents()
            .0
            .to_bytes()
            .map_err(|_| "self update encoding failed")?;
        let authorization = MembershipAuthorization::SelfUpdate;
        let mut proof = super::MembershipVerifier::from_workspace(self)?;
        proof.apply_transition(&authorization, &commit)?;
        super::object::retain_receive_epoch(&candidate.provider, &candidate.group)?;
        candidate
            .group
            .merge_pending_commit(&candidate.provider)
            .map_err(|_| "self update merge failed")?;
        candidate.join_history = Some(self.append_history(authorization, &commit)?);
        if !proof.matches_workspace(&candidate)? {
            return Err("self update branch mismatch");
        }
        Ok(PreparedSelfUpdate {
            workspace: candidate,
            commit,
        })
    }

    /// Stage another member's verified self-update.
    pub fn prepare_self_update_update(
        &self,
        commit: &[u8],
    ) -> Result<PreparedManagementUpdate, &'static str> {
        self.prepare_step_update(&MembershipAuthorization::SelfUpdate, commit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::order::tests::{follow, team};
    use crate::{ForkClass, ManagementAction, fork_key, winner};
    use openmls::prelude::*;

    fn active(update: PreparedManagementUpdate) -> Workspace {
        match update {
            PreparedManagementUpdate::Active(owner) => *owner,
            PreparedManagementUpdate::Removed(_) => panic!("self update removed a member"),
        }
    }

    fn own_leaf_key(owner: &Workspace) -> Vec<u8> {
        let index = owner.group.own_leaf_index();
        owner
            .group
            .members()
            .find(|m| m.index == index)
            .unwrap()
            .encryption_key
    }

    /// ADR A2 T10: a member's self-update is accepted, rotates its leaf key,
    /// and loses to an administrator step at the same epoch.
    #[test]
    fn a_member_self_update_is_accepted_and_rotates_its_keys() {
        let (admin, members) = team(2);
        let [member, other] = <[Workspace; 2]>::try_from(members).ok().unwrap();
        let before = own_leaf_key(&member);
        let update = member.prepare_self_update().unwrap();
        assert_ne!(own_leaf_key(&update.workspace), before);
        let admin_after = active(admin.prepare_self_update_update(&update.commit).unwrap());
        let other = active(other.prepare_self_update_update(&update.commit).unwrap());
        for owner in [&admin_after, &other] {
            assert_eq!(owner.epoch_fingerprint(), update.workspace.epoch_fingerprint());
        }
        // Replay: history and records carry the step.
        for owner in [&admin_after, &other, &update.workspace] {
            let records = owner.export_records().unwrap();
            Workspace::restore_records(owner.endpoint(), owner.id(), &records).unwrap();
        }
        // An administrator step at the same epoch wins, whatever the hash.
        let promote = admin
            .prepare_management(ManagementAction::Promote(other.member().unwrap().id()))
            .unwrap();
        let self_key = fork_key(&MembershipAuthorization::SelfUpdate, &update.commit);
        assert_eq!(self_key.class(), ForkClass::SelfUpdate);
        let admin_key = fork_key(&promote.authorization, &promote.commit);
        assert_eq!(winner(self_key, admin_key), admin_key);
        // A self-update is a history step like any other.
        let bytes =
            crate::encode_membership_step(&MembershipAuthorization::SelfUpdate, &update.commit)
                .unwrap();
        assert!(matches!(
            crate::decode_membership_step(&bytes).unwrap().0,
            MembershipAuthorization::SelfUpdate
        ));
        // The same commit is not accepted as another kind of step.
        assert!(
            admin
                .verify_step(
                    &MembershipAuthorization::Management(ManagementAction::Promote(
                        member.member().unwrap().id()
                    )),
                    &update.commit
                )
                .is_err()
        );
        let _ = follow;
    }

    /// ADR A2 T10: a self-update that changes anything but its own keys is
    /// rejected.
    #[test]
    fn a_self_update_with_proposals_or_changes_is_rejected() {
        let (admin, members) = team(2);
        let [mut member, other] = <[Workspace; 2]>::try_from(members).ok().unwrap();
        let reject = |commit: &[u8], expected: &str| {
            assert_eq!(
                admin
                    .verify_step(&MembershipAuthorization::SelfUpdate, commit)
                    .err(),
                Some(expected)
            );
        };
        // A policy change.
        let changed = member
            .group
            .update_group_context_extensions(
                &member.provider,
                member.group.extensions().clone(),
                &member._signer,
            )
            .unwrap()
            .0
            .to_bytes()
            .unwrap();
        reject(&changed, "self update carries proposals");
        member
            .group
            .clear_pending_commit(member.provider.storage())
            .unwrap();
        // A removal.
        let index = member
            .group
            .members()
            .find(|m| m.signature_key == other._signer.public())
            .unwrap()
            .index;
        let removal = member
            .group
            .remove_members(&member.provider, &member._signer, &[index])
            .unwrap()
            .0
            .to_bytes()
            .unwrap();
        reject(&removal, "self update carries proposals");
        member
            .group
            .clear_pending_commit(member.provider.storage())
            .unwrap();
        // A changed leaf: new capabilities.
        let capabilities = Capabilities::new(
            None,
            None,
            Some(&[ExtensionType::Unknown(crate::AUTHORITY), ExtensionType::Unknown(0xff42)]),
            None,
            None,
        );
        let leaf = member
            .group
            .commit_builder()
            .force_self_update(true)
            .leaf_node_parameters(
                LeafNodeParameters::builder()
                    .with_capabilities(capabilities)
                    .build(),
            )
            .load_psks(member.provider.storage())
            .unwrap()
            .build(
                member.provider.rand(),
                member.provider.crypto(),
                &member._signer,
                |_| true,
            )
            .unwrap()
            .stage_commit(&member.provider)
            .unwrap()
            .into_contents()
            .0
            .to_bytes()
            .unwrap();
        reject(&leaf, "self update changed the member leaf");
        // An administrator step is not a self-update either.
        let promote = admin
            .prepare_management(ManagementAction::Promote(other.member().unwrap().id()))
            .unwrap();
        assert!(
            member
                .verify_step(&MembershipAuthorization::SelfUpdate, &promote.commit)
                .is_err()
        );
    }
}
