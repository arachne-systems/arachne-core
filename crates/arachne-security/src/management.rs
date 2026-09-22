//! Exact administrator actions, verified against the receiver's accepted state.
//! Verification alone does not adopt, persist, disseminate or finalize a change.
use super::{AUTHORITY, JoinProof, Workspace, bootstrap, storage};
use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls::prelude::*;
use openmls_traits::{OpenMlsProvider, crypto::OpenMlsCrypto, signatures::Signer};

/// One authenticated membership or invitation-management intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementAction {
    Promote([u8; 32]),
    Demote([u8; 32]),
    Remove([u8; 32]),
    /// A member's signature authorizes only their own departure from this branch.
    Leave([u8; 32], [u8; 64]),
    CreateInvitation([u8; 32], u64, bool),
    CreateAutomaticInvitation([u8; 32], u64),
    CreateRequestInvitation([u8; 32], u64),
    DeclineInvitationRequest([u8; 32], [u8; 32]),
    DisableInvitation([u8; 32]),
    ApproveInvitation([u8; 32], [u8; 32]),
}

impl ManagementAction {
    pub fn target(self) -> [u8; 32] {
        match self {
            Self::Promote(id)
            | Self::Demote(id)
            | Self::Remove(id)
            | Self::Leave(id, _)
            | Self::CreateInvitation(id, ..)
            | Self::CreateRequestInvitation(id, ..)
            | Self::DeclineInvitationRequest(id, _)
            | Self::CreateAutomaticInvitation(id, ..)
            | Self::DisableInvitation(id)
            | Self::ApproveInvitation(id, _) => id,
        }
    }
    fn removes(self) -> bool {
        matches!(self, Self::Remove(_) | Self::Leave(..))
    }
}

fn leave_payload(context: &GroupContext, member: [u8; 32]) -> Result<Vec<u8>, &'static str> {
    let mut bytes = b"data-fabric/leave/v1\0".to_vec();
    bytes.extend(
        context
            .tls_serialize_detached()
            .map_err(|_| "leave context encoding failed")?,
    );
    bytes.extend(member);
    Ok(bytes)
}

fn verify_leave(
    crypto: &impl OpenMlsCrypto,
    context: &GroupContext,
    key: &[u8],
    action: ManagementAction,
) -> Result<(), &'static str> {
    if let ManagementAction::Leave(id, signature) = action {
        crypto
            .verify_signature(
                super::SUITE.signature_algorithm(),
                &leave_payload(context, id)?,
                key,
                &signature,
            )
            .map_err(|_| "invalid leave signature or membership branch")?;
    }
    Ok(())
}

/// Provisional local change. Save the returned workspace before adopting it or
/// distributing the commit; the original owner is unchanged.
pub struct PreparedManagement {
    pub workspace: Workspace,
    pub action: ManagementAction,
    pub commit: Vec<u8>,
}

/// One provisional receiver result. Hosts must persist the matching variant
/// before adoption, and must never configure data delivery from Removed.
pub enum PreparedManagementUpdate {
    Active(Box<Workspace>),
    Removed(super::RemovedMembership),
}

impl Workspace {
    /// Sign a departure from this exact membership branch. Another admitted
    /// member must commit it; signing alone neither leaves nor changes keys.
    pub fn leave_action(&self) -> Result<ManagementAction, &'static str> {
        let member = self.member().ok_or("member identity required")?;
        let roster = self.member_roster()?;
        if roster
            .iter()
            .any(|m| m.id == member.id() && m.administrator)
            && roster.iter().filter(|m| m.administrator).count() == 1
        {
            return Err("Make another member an administrator before leaving.");
        }
        let signature = self
            ._signer
            .sign(&leave_payload(
                super::MembershipVerifier::from_workspace(self)?
                    .group
                    .group_context(),
                member.id(),
            )?)
            .map_err(|_| "leave signing failed")?
            .try_into()
            .map_err(|_| "invalid leave signature length")?;
        Ok(ManagementAction::Leave(member.id(), signature))
    }

    /// A one-member workspace has no peer to notify or remaining keys to rotate.
    /// Persist this terminal record before shutting down its local owner.
    pub fn prepare_solo_leave(&self) -> Result<super::RemovedMembership, &'static str> {
        if self.member_count() != 1 {
            return Err("another member must accept the departure");
        }
        let member = self.member().ok_or("member identity required")?;
        use sha2::Digest;
        Ok(super::RemovedMembership::verified(
            self.id,
            self.endpoint,
            member.clone(),
            self.epoch(),
            sha2::Sha256::digest(leave_payload(
                super::MembershipVerifier::from_workspace(self)?
                    .group
                    .group_context(),
                member.id(),
            )?)
            .into(),
        )
        .for_solo_leave())
    }

    /// Copy accepted state for one provisional operation without serializing it.
    /// Discard rejected candidates; persist an accepted candidate before adopting
    /// it or emitting its output. Never use copies as independent senders: their
    /// ratchets and counters start at the same position.
    pub fn provisional_copy(&self) -> Result<Workspace, &'static str> {
        // ponytail: copies the full native state; use provider transactions if
        // measured staging memory or latency requires incremental copies.
        let provider = storage::copy_provider(&self.provider)?;
        let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&self.id))
            .map_err(|_| "workspace state copy failed")?
            .ok_or("missing workspace state copy")?;
        let signer = openmls_basic_credential::SignatureKeyPair::read(
            provider.storage(),
            self._signer.public(),
            super::SUITE.signature_algorithm(),
        )
        .ok_or("missing workspace signer")?;
        Ok(Workspace {
            provider,
            group,
            _signer: signer,
            id: self.id,
            endpoint: self.endpoint,
            member: self.member.clone(),
            admissions: self.admissions.clone(),
            join_history: self.join_history.clone(),
            invitation_checkpoints: self.invitation_checkpoints.clone(),
        })
    }

    pub fn prepare_management(
        &self,
        action: ManagementAction,
    ) -> Result<PreparedManagement, &'static str> {
        let mut admins = bootstrap::authority(self.group.extensions())?;
        if !matches!(action, ManagementAction::Leave(..))
            && !admins.iter().any(|key| key == self._signer.public())
        {
            return Err("management actor is not an administrator");
        }
        if matches!(
            action,
            ManagementAction::CreateInvitation(..)
                | ManagementAction::CreateRequestInvitation(..)
                | ManagementAction::DeclineInvitationRequest(..)
                | ManagementAction::CreateAutomaticInvitation(..)
                | ManagementAction::DisableInvitation(_)
                | ManagementAction::ApproveInvitation(..)
        ) {
            return super::invitation_controls::prepare(self, action);
        }
        let id = action.target();
        let target = self
            .group
            .members()
            .find(|m| bootstrap::binding(&m.credential).is_ok_and(|b| b.0 == id))
            .ok_or("management target is not a current member")?;
        verify_leave(
            self.provider.crypto(),
            super::MembershipVerifier::from_workspace(self)?
                .group
                .group_context(),
            &target.signature_key,
            action,
        )?;
        let had_role = admins.contains(&target.signature_key);
        match action {
            ManagementAction::CreateInvitation(..)
            | ManagementAction::CreateRequestInvitation(..)
            | ManagementAction::DeclineInvitationRequest(..)
            | ManagementAction::CreateAutomaticInvitation(..)
            | ManagementAction::DisableInvitation(_)
            | ManagementAction::ApproveInvitation(..) => unreachable!(),
            ManagementAction::Promote(_) => {
                if had_role {
                    return Err("member is already an administrator");
                }
                admins.push(target.signature_key.clone());
                admins.sort();
            }
            ManagementAction::Demote(_) => {
                if !had_role {
                    return Err("member is not an administrator");
                }
                admins.retain(|key| key != &target.signature_key);
            }
            ManagementAction::Remove(_) | ManagementAction::Leave(..) => {
                if target.index == self.group.own_leaf_index() {
                    return Err("self removal requires a separate leave operation");
                }
                admins.retain(|key| key != &target.signature_key);
            }
        }
        if admins.is_empty() {
            return Err("cannot remove the last administrator");
        }
        let mut candidate = self.provisional_copy()?;
        let role_change = !action.removes() || had_role;
        let mut builder = candidate.group.commit_builder();
        if action.removes() {
            builder = builder.propose_removals([target.index]);
        }
        if role_change {
            let bytes =
                super::invitation_controls::replace_admins(self.group.extensions(), &admins)?;
            let extensions = Extensions::from_vec(
                self.group
                    .extensions()
                    .iter()
                    .map(|e| {
                        if e.extension_type() == ExtensionType::Unknown(AUTHORITY) {
                            Extension::Unknown(AUTHORITY, UnknownExtension(bytes.clone()))
                        } else {
                            e.clone()
                        }
                    })
                    .collect(),
            )
            .map_err(|_| "invalid management extensions")?;
            builder = builder
                .propose_group_context_extensions(extensions)
                .map_err(|_| "management proposal failed")?;
        }
        let commit = builder
            .load_psks(candidate.provider.storage())
            .map_err(|_| "management proposal state failed")?
            .build(
                candidate.provider.rand(),
                candidate.provider.crypto(),
                &candidate._signer,
                |_| true,
            )
            .map_err(|_| "management preparation failed")?
            .stage_commit(&candidate.provider)
            .map_err(|_| "management staging failed")?
            .into_contents()
            .0
            .to_bytes()
            .map_err(|_| "management encoding failed")?;
        let mut proof = super::MembershipVerifier::from_workspace(self)?;
        proof.apply_transition(&super::MembershipAuthorization::Management(action), &commit)?;
        candidate
            .group
            .merge_pending_commit(&candidate.provider)
            .map_err(|_| "management merge failed")?;
        candidate.join_history =
            Some(self.append_history(super::MembershipAuthorization::Management(action), &commit)?);
        if !proof.matches_workspace(&candidate)? {
            return Err("management branch mismatch");
        }
        Ok(PreparedManagement {
            workspace: candidate,
            action,
            commit,
        })
    }

    /// Stage verified management without changing this owner. Removal returns
    /// metadata without group keys, for replacement of the active saved record.
    pub fn prepare_management_update(
        &self,
        action: ManagementAction,
        commit: &[u8],
    ) -> Result<PreparedManagementUpdate, &'static str> {
        self.verify_management(action, commit)?;
        let mut proof = super::MembershipVerifier::from_workspace(self)?;
        proof.apply_transition(&super::MembershipAuthorization::Management(action), commit)?;
        let mut candidate = self.provisional_copy()?;
        let processed = candidate
            .group
            .process_message(
                &candidate.provider,
                MlsMessageIn::tls_deserialize_exact(commit)
                    .map_err(|_| "invalid management commit")?
                    .try_into_protocol_message()
                    .map_err(|_| "expected management commit")?,
            )
            .map_err(|_| "management authentication failed")?;
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err("not a management commit");
        };
        candidate
            .group
            .merge_staged_commit(&candidate.provider, *staged)
            .map_err(|_| "management merge failed")?;
        if !candidate.group.is_active() {
            let member = self.member().ok_or("removed owner lacks member identity")?;
            if !action.removes() || action.target() != member.id() {
                return Err("removal does not match local member");
            }
            use sha2::Digest;
            return Ok(PreparedManagementUpdate::Removed(
                super::RemovedMembership::verified(
                    self.id,
                    self.endpoint,
                    member.clone(),
                    proof.epoch(),
                    sha2::Sha256::digest(commit).into(),
                ),
            ));
        }
        candidate.join_history =
            Some(self.append_history(super::MembershipAuthorization::Management(action), commit)?);
        candidate.prune_invitation_checkpoints()?;
        if !proof.matches_workspace(&candidate)? {
            return Err("management branch mismatch");
        }
        Ok(PreparedManagementUpdate::Active(Box::new(candidate)))
    }

    /// Authenticate an exact public MLS management commit without changing this
    /// owner. The expected action is untrusted until it matches the signed commit.
    /// This checks one branch; it cannot establish global finality across partitions.
    pub fn verify_management(
        &self,
        action: ManagementAction,
        commit: &[u8],
    ) -> Result<(), &'static str> {
        JoinProof::from_workspace(self)?.verify_management(action, commit)?;
        // PublicGroup checks signatures/policy but cannot check membership tags.
        // Use a disposable private owner as well; never consume the live state.
        let provider = storage::copy_provider(&self.provider)?;
        let mut group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&self.id))
            .map_err(|_| "workspace state copy failed")?
            .ok_or("missing workspace state copy")?;
        let message = MlsMessageIn::tls_deserialize_exact(commit)
            .map_err(|_| "invalid management commit")?
            .try_into_protocol_message()
            .map_err(|_| "expected management commit")?;
        let processed = group
            .process_message(&provider, message)
            .map_err(|_| "management authentication failed")?;
        if !matches!(
            processed.into_content(),
            ProcessedMessageContent::StagedCommitMessage(_)
        ) {
            return Err("not a management commit");
        }
        Ok(())
    }
}

pub(super) fn verify(
    crypto: &impl OpenMlsCrypto,
    group: &PublicGroup,
    sender: &Sender,
    staged: &StagedCommit,
    action: ManagementAction,
) -> Result<(), &'static str> {
    let Sender::Member(actor_index) = sender else {
        return Err("management actor is not a member");
    };
    let members: Vec<_> = group.members().collect();
    let actor = members
        .iter()
        .find(|m| m.index == *actor_index)
        .ok_or("unknown management actor")?;
    let before = bootstrap::authority(group.group_context().extensions())?;
    if !matches!(action, ManagementAction::Leave(..)) && !before.contains(&actor.signature_key) {
        return Err("management actor is not an administrator");
    }
    if matches!(
        action,
        ManagementAction::CreateInvitation(..)
            | ManagementAction::CreateRequestInvitation(..)
            | ManagementAction::DeclineInvitationRequest(..)
            | ManagementAction::CreateAutomaticInvitation(..)
            | ManagementAction::DisableInvitation(_)
            | ManagementAction::ApproveInvitation(..)
    ) {
        return super::invitation_controls::verify(group, sender, actor, staged, action);
    }
    let id = action.target();
    let mut target = None;
    for member in &members {
        if bootstrap::binding(&member.credential)?.0 == id {
            if target.is_some() {
                return Err("ambiguous management target");
            }
            target = Some(member);
        }
    }
    let target = target.ok_or("management target is not a current member")?;
    verify_leave(crypto, group.group_context(), &target.signature_key, action)?;
    if before
        .iter()
        .any(|key| members.iter().filter(|m| &m.signature_key == key).count() != 1)
    {
        return Err("administrator key must identify one current member");
    }
    let was_admin = before.contains(&target.signature_key);
    let mut expected = before.clone();
    match action {
        ManagementAction::CreateInvitation(..)
        | ManagementAction::CreateRequestInvitation(..)
        | ManagementAction::DeclineInvitationRequest(..)
        | ManagementAction::CreateAutomaticInvitation(..)
        | ManagementAction::DisableInvitation(_)
        | ManagementAction::ApproveInvitation(..) => unreachable!(),
        ManagementAction::Promote(_) => {
            if was_admin {
                return Err("member is already an administrator");
            }
            if members
                .iter()
                .filter(|m| m.signature_key == target.signature_key)
                .count()
                != 1
            {
                return Err("administrator key must identify one current member");
            }
            expected.push(target.signature_key.clone());
            expected.sort();
        }
        ManagementAction::Demote(_) => {
            if !was_admin {
                return Err("member is not an administrator");
            }
            expected.retain(|key| key != &target.signature_key);
        }
        ManagementAction::Remove(_) | ManagementAction::Leave(..) => {
            if target.index == actor.index {
                return Err("self removal requires a separate leave operation");
            }
            expected.retain(|key| key != &target.signature_key);
        }
    }
    if expected.is_empty() {
        return Err("cannot remove the last administrator");
    }
    if super::invitation_controls::policy_bytes(group.group_context().extensions())?
        != super::invitation_controls::policy_bytes(staged.group_context().extensions())?
    {
        return Err("member management changed invitation controls");
    }
    let after = bootstrap::authority(staged.group_context().extensions())?;
    if expected != after {
        return Err("management authority change does not match intent");
    }
    let unrelated = |ext: &Extensions<GroupContext>| {
        ext.iter()
            .filter(|e| e.extension_type() != ExtensionType::Unknown(AUTHORITY))
            .cloned()
            .collect::<Vec<_>>()
    };
    if unrelated(group.group_context().extensions())
        != unrelated(staged.group_context().extensions())
    {
        return Err("management cannot change unrelated group policy");
    }
    if let Some(leaf) = staged.update_path_leaf_node()
        && (leaf.credential() != &actor.credential
            || leaf.signature_key().as_slice() != actor.signature_key)
    {
        return Err("management cannot replace committer identity");
    }
    let mut removals = 0;
    let mut roles = 0;
    for proposal in staged.queued_proposals() {
        if proposal.sender() != sender
            || proposal.proposal_or_ref_type() != ProposalOrRefType::Proposal
        {
            return Err("management requires inline actor-authored proposals");
        }
        match proposal.proposal() {
            Proposal::Remove(remove) if action.removes() && remove.removed() == target.index => {
                removals += 1
            }
            Proposal::GroupContextExtensions(_) => roles += 1,
            _ => return Err("management includes an unrelated proposal"),
        }
    }
    if removals != usize::from(action.removes()) || roles != usize::from(before != expected) {
        return Err("management proposal count does not match intent");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PendingJoin, StorageKey};
    use openmls::prelude::tls_codec::Deserialize;
    use openmls_traits::OpenMlsProvider;

    fn add(admin: Workspace, endpoint: u8) -> (Workspace, Workspace, crate::PreparedAdmission) {
        let (invite, checkpoint) = admin.issue_invitation().unwrap();
        let pending =
            PendingJoin::from_invitation(&invite, &checkpoint, [endpoint; 32], "Field member")
                .unwrap();
        let prepared = admin
            .prepare_admission([endpoint; 32], pending.admission_request().unwrap())
            .unwrap();
        let mut proof = pending.join_proof().unwrap();
        proof
            .apply_add(&prepared.authorization, &prepared.commit)
            .unwrap();
        let member = pending
            .prepare_workspace(&proof, &prepared.welcome)
            .unwrap();
        (admin, member, prepared)
    }
    fn pair() -> (Workspace, Workspace) {
        let (_, member, prepared) = add(Workspace::create([1; 32], "Coordinator").unwrap(), 2);
        (prepared.workspace, member)
    }

    #[test]
    fn incremental_verification_has_no_workspace_lifetime_counter() {
        let (mut admin, member) = pair();
        let checkpoint = admin.join_checkpoint().unwrap();
        use sha2::{Digest, Sha256};
        let mut verifier = crate::MembershipVerifier::from_trusted_checkpoint(
            admin.id(),
            Sha256::digest(&checkpoint).into(),
            &checkpoint,
        )
        .unwrap();
        let id = member.member().unwrap().id();
        // Raw MLS generation isolates verification from the legacy snapshot and
        // inline history format. This is not a runtime persistence/scale claim.
        for sequence in 0..128 {
            let mut keys = vec![admin._signer.public().to_vec()];
            let (action, wrong) = if sequence % 2 == 0 {
                keys.push(member._signer.public().to_vec());
                (ManagementAction::Promote(id), ManagementAction::Demote(id))
            } else {
                (ManagementAction::Demote(id), ManagementAction::Promote(id))
            };
            let commit = role_commit(&mut admin, keys);
            let epoch = verifier.epoch();
            assert!(
                verifier
                    .apply_transition(&crate::MembershipAuthorization::Management(wrong), &commit,)
                    .is_err()
            );
            assert_eq!(verifier.epoch(), epoch);
            verifier
                .apply_transition(&crate::MembershipAuthorization::Management(action), &commit)
                .unwrap_or_else(|error| panic!("transition {}: {error}", sequence + 1));
            assert!(
                verifier
                    .apply_transition(&crate::MembershipAuthorization::Management(action), &commit)
                    .is_err()
            );
            assert_eq!(verifier.epoch(), epoch + 1);
            admin.group.merge_pending_commit(&admin.provider).unwrap();
            assert!(verifier.matches_workspace(&admin).unwrap());
        }
        assert_eq!(verifier.epoch(), 129);
    }
    fn extensions(owner: &Workspace, mut keys: Vec<Vec<u8>>) -> Extensions<GroupContext> {
        keys.sort();
        let mut encoded = vec![1, keys.len() as u8];
        encoded.extend(keys.into_iter().flatten());
        Extensions::from_vec(
            owner
                .group
                .extensions()
                .iter()
                .map(|e| {
                    if e.extension_type() == ExtensionType::Unknown(AUTHORITY) {
                        Extension::Unknown(AUTHORITY, UnknownExtension(encoded.clone()))
                    } else {
                        e.clone()
                    }
                })
                .collect(),
        )
        .unwrap()
    }
    fn role_commit(owner: &mut Workspace, keys: Vec<Vec<u8>>) -> Vec<u8> {
        owner
            .group
            .update_group_context_extensions(
                &owner.provider,
                extensions(owner, keys),
                &owner._signer,
            )
            .unwrap()
            .0
            .to_bytes()
            .unwrap()
    }
    // Test-only merge after the production receiver guard succeeds. No product
    // management save/adopt/history support is implied by this helper.
    fn accept(owner: &mut Workspace, action: ManagementAction, commit: &[u8]) {
        owner.verify_management(action, commit).unwrap();
        let message = MlsMessageIn::tls_deserialize_exact(commit)
            .unwrap()
            .try_into_protocol_message()
            .unwrap();
        let processed = owner
            .group
            .process_message(&owner.provider, message)
            .unwrap();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            panic!("not commit")
        };
        owner
            .group
            .merge_staged_commit(&owner.provider, *staged)
            .unwrap();
    }
    #[test]
    fn exact_promotion_and_demotion_with_creator_absent() {
        let (mut admin, mut member) = pair();
        let member_id = member.member().unwrap().id();
        let keys = vec![
            admin._signer.to_public_vec(),
            member._signer.to_public_vec(),
        ];
        let commit = role_commit(&mut admin, keys);
        let epoch = member.epoch();
        member
            .verify_management(ManagementAction::Promote(member_id), &commit)
            .unwrap();
        assert_eq!(member.epoch(), epoch);
        assert!(
            member
                .verify_management(ManagementAction::Demote(member_id), &commit)
                .is_err()
        );
        assert!(
            member
                .verify_management(ManagementAction::Promote([99; 32]), &commit)
                .is_err()
        );
        let unrelated = Workspace::create([9; 32], "Other workspace").unwrap();
        assert!(
            unrelated
                .verify_management(ManagementAction::Promote(member_id), &commit)
                .is_err()
        );
        let mut tampered = commit.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(
            member
                .verify_management(ManagementAction::Promote(member_id), &tampered)
                .is_err()
        );
        accept(&mut member, ManagementAction::Promote(member_id), &commit);
        admin.group.merge_pending_commit(&admin.provider).unwrap();
        assert!(
            member
                .verify_management(ManagementAction::Promote(member_id), &commit)
                .is_err()
        );
        assert!(member.issue_invitation().is_ok());
        // A current second admin may demote the absent creator, without waiting
        // for it. The old snapshot is an independent receiver at the parent epoch.
        let key = StorageKey::derive(&[8; 32]).unwrap();
        let snapshot = admin.seal(&key).unwrap();
        let admin_id = admin.member().unwrap().id();
        let workspace = admin.id();
        drop(admin);
        let next_keys = vec![member._signer.to_public_vec()];
        let demotion = role_commit(&mut member, next_keys);
        let mut returning = Workspace::restore(&key, [1; 32], workspace, &snapshot).unwrap();
        accept(
            &mut returning,
            ManagementAction::Demote(admin_id),
            &demotion,
        );
        assert!(returning.issue_invitation().is_err());
        assert_eq!(returning.member_count(), 2);
    }
    #[test]
    fn ordinary_member_cannot_promote_or_remove() {
        let (admin, mut member) = pair();
        let member_id = member.member().unwrap().id();
        let keys = vec![
            admin._signer.to_public_vec(),
            member._signer.to_public_vec(),
        ];
        let attack = role_commit(&mut member, keys);
        assert_eq!(
            admin.verify_management(ManagementAction::Promote(member_id), &attack),
            Err("management actor is not an administrator")
        );
        member
            .group
            .clear_pending_commit(member.provider.storage())
            .unwrap();
        let index = member
            .group
            .members()
            .find(|m| m.signature_key == admin._signer.public())
            .unwrap()
            .index;
        let attack = member
            .group
            .remove_members(&member.provider, &member._signer, &[index])
            .unwrap()
            .0
            .to_bytes()
            .unwrap();
        assert_eq!(
            admin.verify_management(
                ManagementAction::Remove(admin.member().unwrap().id()),
                &attack
            ),
            Err("management actor is not an administrator")
        );
    }
    #[test]
    fn exact_removal_and_last_admin_guard() {
        let (mut admin, mut member) = pair();
        let id = member.member().unwrap().id();
        let index = admin
            .group
            .members()
            .find(|m| m.signature_key == member._signer.public())
            .unwrap()
            .index;
        let removal = admin
            .group
            .remove_members(&admin.provider, &admin._signer, &[index])
            .unwrap()
            .0
            .to_bytes()
            .unwrap();
        member
            .verify_management(ManagementAction::Remove(id), &removal)
            .unwrap();
        assert!(
            member
                .verify_management(
                    ManagementAction::Remove(admin.member().unwrap().id()),
                    &removal
                )
                .is_err()
        );
        accept(&mut member, ManagementAction::Remove(id), &removal);
        assert!(!member.group.is_active());
        admin
            .group
            .clear_pending_commit(admin.provider.storage())
            .unwrap();
        let last = role_commit(&mut admin, vec![]);
        assert_eq!(
            admin.verify_management(
                ManagementAction::Demote(admin.member().unwrap().id()),
                &last
            ),
            Err("cannot remove the last administrator")
        );
    }
    fn trio() -> (Workspace, Workspace, Workspace) {
        let (admin, second) = pair();
        let (_, third, prepared) = add(admin, 3);
        let second = second
            .prepare_admission_update(&prepared.authorization, &prepared.commit)
            .unwrap();
        (prepared.workspace, second, third)
    }
    fn two_admins() -> (Workspace, Workspace, Workspace) {
        let (mut admin, mut second, mut third) = trio();
        let id = second.member().unwrap().id();
        let keys = vec![
            admin._signer.to_public_vec(),
            second._signer.to_public_vec(),
        ];
        let commit = role_commit(&mut admin, keys);
        accept(&mut second, ManagementAction::Promote(id), &commit);
        accept(&mut third, ManagementAction::Promote(id), &commit);
        admin.group.merge_pending_commit(&admin.provider).unwrap();
        (admin, second, third)
    }
    #[test]
    fn administrator_removal_excludes_keys_and_old_invites() {
        let (mut admin, mut removed, mut survivor) = two_admins();
        let removed_id = removed.member().unwrap().id();
        let (invite, checkpoint) = removed.issue_invitation().unwrap();
        let pending =
            PendingJoin::from_invitation(&invite, &checkpoint, [4; 32], "Late arrival").unwrap();
        let ext = extensions(&admin, vec![admin._signer.to_public_vec()]);
        let index = admin
            .group
            .members()
            .find(|m| m.signature_key == removed._signer.public())
            .unwrap()
            .index;
        let commit = admin
            .group
            .commit_builder()
            .propose_removals([index])
            .propose_group_context_extensions(ext)
            .unwrap()
            .load_psks(admin.provider.storage())
            .unwrap()
            .build(
                admin.provider.rand(),
                admin.provider.crypto(),
                &admin._signer,
                |_| true,
            )
            .unwrap()
            .stage_commit(&admin.provider)
            .unwrap()
            .into_contents()
            .0
            .to_bytes()
            .unwrap();
        accept(&mut survivor, ManagementAction::Remove(removed_id), &commit);
        admin.group.merge_pending_commit(&admin.provider).unwrap();
        assert_eq!(survivor.member_count(), 2);
        assert!(
            !survivor
                .member_endpoints()
                .unwrap()
                .contains(&removed.endpoint())
        );
        let fresh = admin
            .protect_object(b"test", b"current members only")
            .unwrap();
        assert_eq!(
            survivor
                .unprotect_object(b"test", &fresh)
                .unwrap()
                .message
                .payload,
            b"current members only"
        );
        assert!(removed.unprotect_object(b"test", &fresh).is_err());
        let stale = removed
            .protect_object(b"test", b"old admin publication")
            .unwrap();
        assert!(survivor.unprotect_object(b"test", &stale).is_err());
        assert_eq!(
            admin
                .prepare_admission([4; 32], pending.admission_request().unwrap())
                .err(),
            Some("invitation issuer is no longer an administrator")
        );
    }
    #[test]
    fn competing_admin_actions_do_not_silently_overwrite_accepted_state() {
        let (mut admin, mut second, mut observer) = two_admins();
        let admin_id = admin.member().unwrap().id();
        let second_id = second.member().unwrap().id();
        let first_keys = vec![admin._signer.to_public_vec()];
        let other_keys = vec![second._signer.to_public_vec()];
        let first = role_commit(&mut admin, first_keys);
        let other = role_commit(&mut second, other_keys);
        observer
            .verify_management(ManagementAction::Demote(second_id), &first)
            .unwrap();
        observer
            .verify_management(ManagementAction::Demote(admin_id), &other)
            .unwrap();
        accept(&mut observer, ManagementAction::Demote(second_id), &first);
        let epoch = observer.epoch();
        assert!(
            observer
                .verify_management(ManagementAction::Demote(admin_id), &other)
                .is_err()
        );
        assert_eq!(observer.epoch(), epoch);
        // Explicit rejection is evidence of no overwrite, not branch convergence.
    }
    #[test]
    fn an_exact_action_does_not_authorize_bulk_role_or_policy_changes() {
        let (mut admin, second, third) = trio();
        let id = second.member().unwrap().id();
        let keys = vec![
            admin._signer.to_public_vec(),
            second._signer.to_public_vec(),
            third._signer.to_public_vec(),
        ];
        let bulk = role_commit(&mut admin, keys);
        assert_eq!(
            second.verify_management(ManagementAction::Promote(id), &bulk),
            Err("management authority change does not match intent")
        );
        admin
            .group
            .clear_pending_commit(admin.provider.storage())
            .unwrap();
        let keys = vec![
            admin._signer.to_public_vec(),
            second._signer.to_public_vec(),
        ];
        let ext = Extensions::from_vec(
            extensions(&admin, keys)
                .iter()
                .map(|e| {
                    if e.extension_type() == ExtensionType::RequiredCapabilities {
                        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                            &[ExtensionType::Unknown(AUTHORITY)],
                            &[],
                            &[CredentialType::Basic],
                        ))
                    } else {
                        e.clone()
                    }
                })
                .collect(),
        )
        .unwrap();
        let changed = admin
            .group
            .update_group_context_extensions(&admin.provider, ext, &admin._signer)
            .unwrap()
            .0
            .to_bytes()
            .unwrap();
        assert_eq!(
            second.verify_management(ManagementAction::Promote(id), &changed),
            Err("management cannot change unrelated group policy")
        );
    }
    #[test]
    fn staged_role_change_restores_and_old_invitation_crosses_mixed_history() {
        let admin = Workspace::create([1; 32], "Coordinator").unwrap();
        let (old_invitation, old_checkpoint) = admin.issue_invitation().unwrap();
        let (mut admin, helper) = {
            let (_, helper, prepared) = add(admin, 2);
            (prepared.workspace, helper)
        };
        let key = StorageKey::derive(&[7; 32]).unwrap();
        let helper_id = helper.member().unwrap().id();
        let before = helper.epoch();
        let action = ManagementAction::Promote(helper_id);
        assert!(helper.prepare_management(action).is_err());
        let prepared = admin.prepare_management(action).unwrap();
        assert_eq!(admin.epoch(), before);
        let PreparedManagementUpdate::Active(promoted) = helper
            .prepare_management_update(action, &prepared.commit)
            .unwrap()
        else {
            panic!("promotion removed member")
        };
        assert_eq!(helper.epoch(), before);
        assert!(helper.issue_invitation().is_err());
        assert_eq!(
            &promoted
                .join_history
                .as_ref()
                .unwrap()
                .inline(promoted.id())
                .unwrap()[..5],
            b"DFJH\x02"
        );
        let snapshot = promoted.seal(&key).unwrap();
        let promoted = Workspace::restore(&key, [2; 32], helper.id(), &snapshot).unwrap();
        let mut records = promoted.export_records().unwrap();
        let promoted = Workspace::restore_records([2; 32], helper.id(), &records).unwrap();
        let history_key = records
            .keys()
            .find(|name| name.starts_with(b"security/history/step/"))
            .unwrap()
            .clone();
        let bytes = records.get_mut(&history_key).unwrap();
        assert_eq!(bytes[0], 0); // Admission authorization record.
        bytes[33] ^= 1; // Administrator grant signature; publicly verifiable.
        assert!(Workspace::restore_records([2; 32], helper.id(), &records).is_err());
        assert!(promoted.issue_invitation().is_ok());
        admin = prepared.workspace;
        let saved_admin = admin.seal(&key).unwrap();
        admin = Workspace::restore(&key, [1; 32], admin.id(), &saved_admin).unwrap();
        let late =
            PendingJoin::from_invitation(&old_invitation, &old_checkpoint, [3; 32], "Late member")
                .unwrap();
        let request = late.admission_request().unwrap();
        for owner in [&admin, &promoted] {
            let steps = owner
                .membership_history([3; 32], request, &old_checkpoint)
                .unwrap();
            assert_eq!(steps.len(), 2);
            let mut proof = late.join_proof().unwrap();
            for (auth, commit) in steps {
                proof.apply_transition(&auth, &commit).unwrap();
            }
            assert!(proof.matches_workspace(owner).unwrap());
            assert_eq!(
                owner
                    .admission_history([3; 32], request, &old_checkpoint)
                    .err(),
                Some("membership history requires management support")
            );
        }
        drop(admin);
        drop(helper);
        let admitted = promoted.prepare_admission([3; 32], request).unwrap();
        let steps = admitted
            .workspace
            .membership_history([3; 32], request, &old_checkpoint)
            .unwrap();
        let mut proof = late.join_proof().unwrap();
        for (auth, commit) in &steps {
            proof.apply_transition(auth, commit).unwrap();
        }
        let joined = late.prepare_workspace(&proof, &admitted.welcome).unwrap();
        let restored =
            Workspace::restore(&key, [3; 32], joined.id(), &joined.seal(&key).unwrap()).unwrap();
        assert_eq!(restored.member_count(), 3);
        assert_eq!(restored.epoch(), 3);
        let encoded = proof.history();
        assert!(
            JoinProof::from_history(joined.id(), old_invitation.checkpoint_digest(), encoded)
                .unwrap()
                .matches_workspace(&restored)
                .unwrap()
        );
        // Wrong tags, intent, truncation and replay must not advance accepted proof.
        let prefix = 41 + u32::from_be_bytes(encoded[37..41].try_into().unwrap()) as usize;
        let mut bad = encoded.to_vec();
        bad[prefix] = 99;
        assert!(
            JoinProof::from_history(joined.id(), old_invitation.checkpoint_digest(), &bad).is_err()
        );
        for length in [4, 40, prefix + 1, encoded.len() - 1] {
            assert!(
                JoinProof::from_history(
                    joined.id(),
                    old_invitation.checkpoint_digest(),
                    &encoded[..length]
                )
                .is_err()
            );
        }
        let mut wrong = late.join_proof().unwrap();
        wrong.apply_transition(&steps[0].0, &steps[0].1).unwrap();
        let epoch = wrong.epoch();
        assert!(
            wrong
                .apply_management(ManagementAction::Demote(helper_id), &steps[1].1)
                .is_err()
        );
        assert_eq!(wrong.epoch(), epoch);
        wrong.apply_transition(&steps[1].0, &steps[1].1).unwrap();
        assert!(wrong.apply_transition(&steps[1].0, &steps[1].1).is_err());
    }
    #[test]
    fn staged_removal_restores_survivor_without_reopening_removed_owner() {
        let (admin, mut removed, survivor) = trio();
        let action = ManagementAction::Remove(removed.member().unwrap().id());
        let prepared = admin.prepare_management(action).unwrap();
        let PreparedManagementUpdate::Active(updated) = survivor
            .prepare_management_update(action, &prepared.commit)
            .unwrap()
        else {
            panic!("survivor removed")
        };
        assert_eq!(admin.epoch(), 2);
        assert_eq!(survivor.epoch(), 2);
        let PreparedManagementUpdate::Removed(record) = removed
            .prepare_management_update(action, &prepared.commit)
            .unwrap()
        else {
            panic!("removed recipient returned active state")
        };
        assert_eq!(record.epoch(), 3);
        let key = StorageKey::derive(&[9; 32]).unwrap();
        let sealed_removal = record.seal(&key).unwrap();
        let restored_removal = crate::RemovedMembership::restore(
            &key,
            removed.endpoint(),
            removed.id(),
            &sealed_removal,
        )
        .unwrap();
        assert_eq!(record, restored_removal);
        assert!(
            Workspace::restore(&key, removed.endpoint(), removed.id(), &sealed_removal).is_err()
        );
        assert_eq!(removed.epoch(), 2);
        let key = StorageKey::derive(&[9; 32]).unwrap();
        let restored = Workspace::restore(
            &key,
            survivor.endpoint(),
            survivor.id(),
            &updated.seal(&key).unwrap(),
        )
        .unwrap();
        assert_eq!(restored.member_count(), 2);
        assert_eq!(restored.epoch(), 3);
        let mut sender = prepared.workspace;
        let payload = sender
            .protect_object(b"removal", b"surviving members")
            .unwrap();
        assert_eq!(
            restored
                .unprotect_object(b"removal", &payload)
                .unwrap()
                .message
                .payload,
            b"surviving members"
        );
        assert!(removed.unprotect_object(b"removal", &payload).is_err());
        let stale = removed.protect_object(b"removal", b"old member").unwrap();
        assert!(restored.unprotect_object(b"removal", &stale).is_err());
    }
    #[test]
    fn removed_record_is_context_bound_and_cannot_restore_active_keys() {
        use crate::RemovedMembership;
        let (admin, removed, _) = trio();
        let key = StorageKey::derive(&[5; 32]).unwrap();
        let action = ManagementAction::Remove(removed.member().unwrap().id());
        let prepared = admin.prepare_management(action).unwrap();
        let mut bad_commit = prepared.commit.clone();
        *bad_commit.last_mut().unwrap() ^= 1;
        assert!(
            removed
                .prepare_management_update(action, &bad_commit)
                .is_err()
        );
        assert!(
            removed
                .prepare_management_update(
                    ManagementAction::Remove(admin.member().unwrap().id()),
                    &prepared.commit
                )
                .is_err()
        );
        let PreparedManagementUpdate::Removed(record) = removed
            .prepare_management_update(action, &prepared.commit)
            .unwrap()
        else {
            panic!("removed recipient returned keys")
        };
        let workspace = removed.id();
        let endpoint = removed.endpoint();
        let active = removed.seal(&key).unwrap();
        assert_eq!(record.member(), removed.member().unwrap());
        assert_eq!(record.workspace_id(), workspace);
        assert_eq!(record.endpoint(), endpoint);
        use sha2::Digest;
        assert_eq!(
            record.commit_digest().as_slice(),
            sha2::Sha256::digest(&prepared.commit).as_slice()
        );
        drop(removed);
        let sealed = record.seal(&key).unwrap();
        assert!(sealed.len() <= crate::MAX_SEALED_REMOVAL);
        assert_ne!(sealed, record.seal(&key).unwrap());
        assert_eq!(
            RemovedMembership::restore(&key, endpoint, workspace, &sealed).unwrap(),
            record
        );
        assert!(Workspace::restore(&key, endpoint, workspace, &sealed).is_err());
        assert!(RemovedMembership::restore(&key, endpoint, workspace, &active).is_err());
        assert!(
            RemovedMembership::restore(
                &StorageKey::derive(&[6; 32]).unwrap(),
                endpoint,
                workspace,
                &sealed
            )
            .is_err()
        );
        assert!(RemovedMembership::restore(&key, [9; 32], workspace, &sealed).is_err());
        assert!(RemovedMembership::restore(&key, endpoint, [9; 32], &sealed).is_err());
        for length in 0..sealed.len() {
            assert!(
                RemovedMembership::restore(&key, endpoint, workspace, &sealed[..length]).is_err()
            );
        }
        for offset in [0, 4, 5, 37, 49, sealed.len() - 1] {
            let mut bad = sealed.clone();
            bad[offset] ^= 1;
            assert!(RemovedMembership::restore(&key, endpoint, workspace, &bad).is_err());
        }
        let plain = key
            .unprotect(b"DFRM\x01", workspace, endpoint, &sealed)
            .unwrap();
        for malformed in [
            {
                let mut v = plain.to_vec();
                v[..8].fill(0);
                v
            },
            {
                let mut v = plain.to_vec();
                v[8..40].fill(0);
                v
            },
            {
                let mut v = plain.to_vec();
                v[40..44].copy_from_slice(&u32::MAX.to_be_bytes());
                v
            },
            {
                let mut v = plain.to_vec();
                v.push(0);
                v
            },
        ] {
            let bad = key
                .protect(
                    &admin.provider,
                    b"DFRM\x01",
                    workspace,
                    endpoint,
                    &malformed,
                )
                .unwrap();
            assert!(RemovedMembership::restore(&key, endpoint, workspace, &bad).is_err());
        }
    }
}

#[test]
fn provisional_copy_exceeds_legacy_size_and_isolates_sender_state() {
    let owner = Workspace::create([1; 32], "Publisher").unwrap();
    // An opaque provider record crosses the old serialization size boundary.
    owner.provider.storage().values.write().unwrap().insert(
        b"test/large-native-record".to_vec(),
        vec![7; storage::MAX_PLAIN],
    );
    let key = super::StorageKey::derive(&[2; 32]).unwrap();
    assert!(owner.seal(&key).is_err());
    let before = owner.export_records().unwrap();
    let mut candidate = owner.provisional_copy().unwrap();
    assert_eq!(candidate.export_records().unwrap(), before);
    candidate
        .protect_object(b"stream", b"provisional output")
        .unwrap();
    assert_eq!(candidate.object_counter().unwrap(), 1);
    assert_eq!(owner.object_counter().unwrap(), 0);
    assert_eq!(owner.export_records().unwrap(), before);
    // Dropping a rejected candidate must leave the next attempt unchanged.
    drop(candidate);
    assert_eq!(
        owner.provisional_copy().unwrap().export_records().unwrap(),
        before
    );
}
