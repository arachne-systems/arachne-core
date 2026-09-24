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

    /// A raw self-update by a member that tracks the group with raw MLS
    /// processing. Measurement only: it skips the Workspace history.
    fn raw_self_update(owner: &mut Workspace) -> Vec<u8> {
        let commit = owner
            .group
            .commit_builder()
            .force_self_update(true)
            .load_psks(owner.provider.storage())
            .unwrap()
            .build(
                owner.provider.rand(),
                owner.provider.crypto(),
                &owner._signer,
                |_| true,
            )
            .unwrap()
            .stage_commit(&owner.provider)
            .unwrap()
            .into_contents()
            .0
            .to_bytes()
            .unwrap();
        owner.group.merge_pending_commit(&owner.provider).unwrap();
        commit
    }

    fn raw_apply(owner: &mut Workspace, commit: &[u8]) {
        use openmls::prelude::tls_codec::Deserialize;
        let message = MlsMessageIn::tls_deserialize_exact(commit)
            .unwrap()
            .try_into_protocol_message()
            .unwrap();
        let processed = owner.group.process_message(&owner.provider, message).unwrap();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            panic!("not a commit")
        };
        owner
            .group
            .merge_staged_commit(&owner.provider, *staged)
            .unwrap();
    }

    /// Sizes of management commits in one grown workspace.
    #[derive(Debug, Default)]
    struct Sizes {
        members: usize,
        registration: usize,
        remove: usize,
        /// Largest self-update commit sent while growing (policy B only).
        largest_self_update: usize,
        /// First self-update of an early member at the end (policy A only).
        first_self_update: usize,
    }

    /// Grow a workspace to `size` members in batches of 128, one fresh link
    /// per batch. With `self_update`, every new member self-updates right
    /// after its batch joins (policy B); otherwise nobody does (policy A).
    fn grow(size: usize, self_update: bool) -> Sizes {
        use crate::history::tests::endpoint;
        use crate::{AdmissionAssessment, MAX_ADMISSION_BATCH, PendingJoin};
        let mut owner = Workspace::create([90; 32], "Owner").unwrap();
        let mut sizes = Sizes::default();
        let mut probe: Option<Workspace> = None;
        let mut next = 0;
        let mut link = None;
        while owner.member_count() < size {
            // Policy A reuses one link: a registration past ~785 members no
            // longer fits the 64 KiB bound (B3c). Policy B registers a fresh
            // link per batch so each joiner replays one step.
            if link.is_none() || self_update {
                let (registration, invitation, checkpoint) =
                    owner.prepare_invitation(0, false, false).unwrap();
                owner = registration.workspace;
                link = Some((invitation, checkpoint));
            }
            let (invitation, checkpoint) = link.as_ref().unwrap();
            let (invitation, checkpoint) = (invitation, checkpoint.as_slice());
            let count = (size - owner.member_count()).min(MAX_ADMISSION_BATCH);
            let range = next..next + count;
            next = range.end;
            let joins: Vec<_> = range
                .clone()
                .map(|i| {
                    PendingJoin::from_invitation(invitation, checkpoint, endpoint(i), "Member")
                        .unwrap()
                })
                .collect();
            let requests: Vec<_> = joins
                .iter()
                .map(|join| join.admission_request().unwrap().to_vec())
                .collect();
            let validated: Vec<_> = range
                .clone()
                .zip(&requests)
                .map(|(i, request)| match owner.assess_admission(endpoint(i), request).unwrap() {
                    AdmissionAssessment::Ready(validated) => validated,
                    _ => panic!("open invitation needs no approval"),
                })
                .collect();
            let entries: Vec<_> = range
                .clone()
                .zip(requests.iter().zip(&validated))
                .map(|(i, (request, validated))| (endpoint(i), request.as_slice(), validated))
                .collect();
            let prepared = owner.prepare_validated_admission_batch(&entries).unwrap();
            let authorization = if count == 1 {
                MembershipAuthorization::Admission(prepared.replies[0].authorization.clone())
            } else {
                MembershipAuthorization::AdmissionBatch(
                    prepared.replies.iter().map(|r| r.authorization.clone()).collect(),
                )
            };
            if let Some(probe) = probe.as_mut() {
                raw_apply(probe, &prepared.commit);
            }
            owner = prepared.workspace;
            let join = |join: &PendingJoin| {
                let mut proof = join.join_proof().unwrap();
                proof.apply_transition(&authorization, &prepared.commit).unwrap();
                join.prepare_workspace(&proof, &prepared.welcome).unwrap()
            };
            if probe.is_none() && !self_update {
                probe = Some(join(&joins[0]));
            }
            if self_update {
                let mut members: Vec<Workspace> = joins.iter().map(join).collect();
                for i in 0..members.len() {
                    let commit = raw_self_update(&mut members[i]);
                    sizes.largest_self_update = sizes.largest_self_update.max(commit.len());
                    owner = active(owner.prepare_self_update_update(&commit).unwrap());
                    for member in &mut members[i + 1..] {
                        raw_apply(member, &commit);
                    }
                }
            }
        }
        sizes.members = owner.member_count();
        // Raw commits on copies: the 64 KiB verifier bound would refuse the
        // large ones, and the point is to measure them. A registration is a
        // policy (GroupContextExtensions) commit with a path.
        let mut copy = owner.provisional_copy().unwrap();
        let extensions = copy.group.extensions().clone();
        sizes.registration = copy
            .group
            .update_group_context_extensions(&copy.provider, extensions, &copy._signer)
            .unwrap()
            .0
            .to_bytes()
            .unwrap()
            .len();
        let mut copy = owner.provisional_copy().unwrap();
        let own = copy.group.own_leaf_index();
        let target = copy.group.members().find(|m| m.index != own).unwrap().index;
        sizes.remove = copy
            .group
            .remove_members(&copy.provider, &copy._signer, &[target])
            .unwrap()
            .0
            .to_bytes()
            .unwrap()
            .len();
        if let Some(mut probe) = probe {
            sizes.first_self_update = raw_self_update(&mut probe).len();
        }
        sizes
    }

    /// B3c: members that self-update after joining shrink later management
    /// commits. Small size so the check runs in every test pass.
    #[test]
    fn self_updates_after_joining_shrink_management_commits() {
        let without = grow(33, false);
        let with = grow(33, true);
        eprintln!("B3c 33 members: without {without:?}, with {with:?}");
        assert!(with.registration * 2 < without.registration, "{with:?} vs {without:?}");
        assert!(with.remove * 2 < without.remove, "{with:?} vs {without:?}");
    }

    /// B3c measurement. Run alone, in release:
    /// `cargo test --release -p arachne-security --lib b3c_measure -- --ignored --nocapture --test-threads=1`
    #[test]
    #[ignore]
    fn b3c_measure_management_commit_sizes() {
        let sizes: Vec<usize> = std::env::var("B3C_SIZES")
            .ok()
            .map(|v| v.split(',').map(|s| s.parse().unwrap()).collect())
            .unwrap_or_else(|| vec![385, 769, 1025]);
        for size in sizes {
            let without = grow(size, false);
            eprintln!("B3c policy=none {without:?}");
            let with = grow(size, true);
            eprintln!("B3c policy=self_update_after_join {with:?}");
        }
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
