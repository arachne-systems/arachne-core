//! Branch comparison from this node's own verified history (ADR A2 step 8).
//!
//! A node that meets a peer on another branch compares the fork keys of the
//! two chains epoch by epoch. It computes both keys itself: its own from the
//! steps it adopted, the peer's by verifying the peer's step against the
//! public state that its own history gives at that epoch (correction 5: a
//! peer's claimed class is never trusted). Head announcements are signed by
//! the member's MLS key, so a relay cannot forge another member's report.
use super::{ForkKey, MembershipAuthorization, SUITE, Workspace, bootstrap, fork_key};
use openmls::prelude::{
    MlsMessageBodyIn, MlsMessageIn,
    tls_codec::{Deserialize, Serialize},
};
use openmls_traits::{OpenMlsProvider, crypto::OpenMlsCrypto, signatures::Signer};

const ANNOUNCEMENT_DOMAIN: &[u8] = b"arachne/announcement/v1";

fn announcement(workspace: [u8; 32], message: &[u8]) -> Vec<u8> {
    let mut bytes = ANNOUNCEMENT_DOMAIN.to_vec();
    bytes.extend(workspace);
    bytes.extend((message.len() as u32).to_be_bytes());
    bytes.extend(message);
    bytes
}

impl Workspace {
    /// A bounded security-only rollback snapshot. Delivery state is kept
    /// separately. This uses record encoding rather than the legacy bundle
    /// ceiling, and is sealed with a distinct record family.
    pub fn seal_branch_snapshot(&self, key: &super::StorageKey) -> Result<Vec<u8>, &'static str> {
        use zeroize::Zeroizing;
        let records = self.export_branch_records()?;
        let mut plain = Zeroizing::new((records.len() as u32).to_be_bytes().to_vec());
        for (name, value) in records {
            let size = plain
                .len()
                .checked_add(8 + name.len() + value.len())
                .ok_or("branch snapshot exceeds size limit")?;
            if size + 65 > super::MAX_BRANCH_SNAPSHOT {
                return Err("branch snapshot exceeds size limit");
            }
            plain.extend((name.len() as u32).to_be_bytes());
            plain.extend(name);
            plain.extend((value.len() as u32).to_be_bytes());
            plain.extend(value.as_slice());
        }
        key.protect_record(&self.provider, b"DFBS\x01", self.id, self.endpoint, &plain)
    }

    pub fn restore_branch_snapshot(
        key: &super::StorageKey,
        endpoint: [u8; 32],
        workspace: [u8; 32],
        sealed: &[u8],
    ) -> Result<Self, &'static str> {
        use super::storage::{number, take};
        use zeroize::Zeroizing;
        let plain = key.unprotect_record(
            b"DFBS\x01",
            workspace,
            endpoint,
            sealed,
            super::MAX_BRANCH_SNAPSHOT,
        )?;
        let mut bytes = plain.as_slice();
        let count = number(&mut bytes)?;
        if count > bytes.len() / 8 {
            return Err("invalid branch record count");
        }
        let mut records = super::SecurityRecords::new();
        for _ in 0..count {
            let length = number(&mut bytes)?;
            let name = take(&mut bytes, length)?.to_vec();
            let length = number(&mut bytes)?;
            let value = Zeroizing::new(take(&mut bytes, length)?.to_vec());
            if records.insert(name, value).is_some() {
                return Err("duplicate branch record");
            }
        }
        if !bytes.is_empty() {
            return Err("trailing branch snapshot bytes");
        }
        Self::restore_records(endpoint, workspace, &records)
    }

    /// Attach only the accepted history before this snapshot's epoch. The
    /// public verifier must end at exactly the restored MLS state. Losing
    /// suffix admissions and invitation checkpoints are not copied.
    pub fn restore_branch_history(&mut self, current: &Workspace) -> Result<(), &'static str> {
        if self.id != current.id
            || self.endpoint != current.endpoint
            || self.epoch() > current.epoch()
        {
            return Err("branch snapshot does not belong to this workspace");
        }
        let Some(mut history) = current.join_history.clone() else {
            if self.epoch() != current.epoch() {
                return Err("common branch history is missing");
            }
            return Ok(());
        };
        let start = history.verifier(self.id)?.epoch();
        let count = self
            .epoch()
            .checked_sub(start)
            .ok_or("common branch history is missing")? as usize;
        if count > history.steps.len() {
            return Err("common branch history is missing");
        }
        history.steps.truncate(count);
        history.verify(self)?;
        self.join_history = Some(history);
        self.admissions = current
            .admissions
            .iter()
            .filter(|entry| entry.reply.epoch <= self.epoch())
            .cloned()
            .collect();
        // Keep links issued at or before this common state. A losing-suffix
        // link cannot cross the fork; an older valid link must still serve
        // the exact checkpoint that its invitation pins.
        self.invitation_checkpoints.clear();
        for saved in &current.invitation_checkpoints {
            if bootstrap::checkpoint_info(&saved.checkpoint)?
                .epoch()
                .as_u64()
                <= self.epoch()
            {
                self.invitation_checkpoints.push(saved.clone());
            }
        }
        self.prune_invitation_checkpoints()?;
        self.verify_retained_invitation_checkpoints()?;
        Ok(())
    }

    /// First epoch of this chain's retained step history. Steps out of
    /// epochs at or above it (and below the current epoch) are retained.
    pub fn history_start(&self) -> Result<u64, &'static str> {
        match &self.join_history {
            Some(history) => Ok(bootstrap::checkpoint_info(&history.checkpoint)?
                .epoch()
                .as_u64()),
            None => Ok(self.epoch()),
        }
    }

    /// This chain's step out of `epoch`, if it is retained.
    pub fn history_step(
        &self,
        epoch: u64,
    ) -> Result<Option<(MembershipAuthorization, Vec<u8>)>, &'static str> {
        if epoch >= self.epoch() {
            return Ok(None);
        }
        self.membership_update_for(self.endpoint, epoch)
    }

    /// Fork key of this chain's step out of `epoch`. The step was verified
    /// when this node adopted it, so its class is trusted.
    pub fn branch_key(&self, epoch: u64) -> Result<Option<ForkKey>, &'static str> {
        Ok(self
            .history_step(epoch)?
            .map(|(authorization, commit)| fork_key(&authorization, &commit)))
    }

    /// Verify a step out of `epoch` from another branch against the public
    /// state this node's own history gives at `epoch`, and return its fork
    /// key. Fails when `epoch` is outside the retained history: a node never
    /// accepts a peer's claim about a step it cannot verify.
    pub fn verify_branch_step(
        &self,
        epoch: u64,
        authorization: &MembershipAuthorization,
        commit: &[u8],
    ) -> Result<ForkKey, &'static str> {
        let mut verifier = self.branch_verifier(epoch)?;
        verifier.apply_transition(authorization, commit)?;
        Ok(fork_key(authorization, commit))
    }

    fn branch_verifier(&self, epoch: u64) -> Result<super::MembershipVerifier, &'static str> {
        let history = match &self.join_history {
            Some(history) => history.clone(),
            None => super::history::MembershipHistory::from_workspace(self)?,
        };
        let mut verifier = history.verifier(self.id)?;
        if verifier.epoch() > epoch || epoch > self.epoch() {
            return Err("branch step is outside the retained history");
        }
        for (step_authorization, step_commit) in &history.steps {
            if verifier.epoch() == epoch {
                break;
            }
            verifier.apply_transition(step_authorization, step_commit)?;
        }
        if verifier.epoch() != epoch {
            return Err("branch step is outside the retained history");
        }
        Ok(verifier)
    }

    /// Signed public GroupInfo without the ratchet tree. This contains no
    /// private keys. A retained pin can prove an old accepted state after
    /// its private rollback snapshot has been deleted.
    pub fn public_checkpoint_pin(&self) -> Result<Vec<u8>, &'static str> {
        let pin = self
            .group
            .export_group_info_with_additional_extensions(
                self.provider.crypto(),
                &self._signer,
                false,
                Vec::new(),
            )
            .map_err(|_| "checkpoint creation failed")?
            .to_bytes()
            .map_err(|_| "checkpoint encoding failed")?;
        if pin.len() > bootstrap::MAX_CHECKPOINT_PIN {
            return Err("checkpoint pin exceeds bounds");
        }
        Ok(pin)
    }

    /// Read a bounded public pin's epoch and workspace binding. Structure
    /// only; `public_checkpoint_from_pin` verifies it against accepted history.
    pub fn checkpoint_pin_epoch(&self, pin: &[u8]) -> Result<u64, &'static str> {
        if pin.is_empty() || pin.len() > bootstrap::MAX_CHECKPOINT_PIN {
            return Err("checkpoint pin exceeds bounds");
        }
        let message =
            MlsMessageIn::tls_deserialize_exact(pin).map_err(|_| "invalid checkpoint pin")?;
        let MlsMessageBodyIn::GroupInfo(info) = message.extract() else {
            return Err("expected GroupInfo");
        };
        if info.group_id().as_slice() != self.id || info.ciphersuite() != SUITE {
            return Err("wrong checkpoint workspace");
        }
        if info.extensions().ratchet_tree().is_some() {
            return Err("invalid checkpoint pin");
        }
        Ok(info.epoch().as_u64())
    }

    /// Rebuild the public tree from accepted history, then verify the saved
    /// pin's signature and exact GroupContext. This needs no old private key.
    pub fn public_checkpoint_from_pin(
        &self,
        epoch: u64,
        pin: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if self.checkpoint_pin_epoch(pin)? != epoch {
            return Err("checkpoint pin has the wrong epoch");
        }
        let verifier = self.branch_verifier(epoch)?;
        let tree = verifier
            .group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(|_| "checkpoint encoding failed")?;
        let checkpoint =
            bootstrap::checkpoint_from_parts(pin, &tree, bootstrap::CheckpointBound::Wire)?;
        let checked = super::MembershipVerifier::from_proof_checkpoint(self.id, &checkpoint, 0)?;
        if super::order::context_hash(checked.group.group_context())?
            != super::order::context_hash(verifier.group.group_context())?
        {
            return Err("checkpoint pin is from another branch");
        }
        Ok(checkpoint)
    }

    /// Sign a short announcement (a membership head) with this member's MLS
    /// signature key, bound to this workspace.
    pub fn sign_announcement(&self, message: &[u8]) -> Result<[u8; 64], &'static str> {
        self._signer
            .sign(&announcement(self.id, message))
            .map_err(|_| "announcement signing failed")?
            .try_into()
            .map_err(|_| "invalid announcement signature length")
    }

    /// Verify an announcement from the member at `endpoint` in this roster.
    /// Returns the member id.
    pub fn verify_announcement(
        &self,
        endpoint: [u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<[u8; 32], &'static str> {
        for member in self.group.members() {
            let (id, bound) = bootstrap::binding(&member.credential)?;
            if bound == endpoint {
                self.provider
                    .crypto()
                    .verify_signature(
                        SUITE.signature_algorithm(),
                        &announcement(self.id, message),
                        &member.signature_key,
                        signature,
                    )
                    .map_err(|_| "invalid announcement signature")?;
                return Ok(id);
            }
        }
        Err("announcement author is not a current member")
    }
}

#[cfg(test)]
mod tests {
    use crate::order::tests::{follow, team};
    use crate::{ManagementAction, MembershipAuthorization, Workspace, fork_key};
    use openmls_traits::OpenMlsProvider;

    fn id(owner: &Workspace) -> [u8; 32] {
        owner.member().unwrap().id()
    }

    #[test]
    fn a_peer_step_on_another_branch_verifies_and_gets_its_own_key() {
        let (admin, members) = team(2);
        let [first, second] = <[Workspace; 2]>::try_from(members).ok().unwrap();
        let fork = admin.epoch();
        // Two competing steps out of the same epoch.
        let promote = admin
            .prepare_management(ManagementAction::Promote(id(&first)))
            .unwrap();
        let invite = admin
            .prepare_management(ManagementAction::CreateInvitation([9; 32], 0, false))
            .unwrap();
        let on_promote = follow(&second, &promote);
        assert!(on_promote.history_start().unwrap() <= fork);
        let (auth, commit) = on_promote.history_step(fork).unwrap().unwrap();
        assert_eq!(commit, promote.commit);
        assert_eq!(
            on_promote.branch_key(fork).unwrap(),
            Some(fork_key(&promote.authorization, &promote.commit))
        );
        assert_eq!(
            fork_key(&auth, &commit),
            fork_key(&promote.authorization, &promote.commit)
        );
        // No step out of the current epoch yet.
        assert_eq!(on_promote.branch_key(on_promote.epoch()).unwrap(), None);
        // The other branch's step verifies against this node's state at the fork.
        assert_eq!(
            on_promote
                .verify_branch_step(fork, &invite.authorization, &invite.commit)
                .unwrap(),
            fork_key(&invite.authorization, &invite.commit)
        );
        // A relabelled step fails: the class comes only from a verified step.
        let relabelled =
            MembershipAuthorization::Management(ManagementAction::Promote(id(&second)));
        assert!(
            on_promote
                .verify_branch_step(fork, &relabelled, &invite.commit)
                .is_err()
        );
        // A step for another epoch fails.
        assert!(
            on_promote
                .verify_branch_step(fork + 1, &invite.authorization, &invite.commit)
                .is_err()
        );
        // Below the retained history nothing can be verified.
        assert!(
            on_promote
                .verify_branch_step(0, &invite.authorization, &invite.commit)
                .is_err()
        );
        let _ = first;
    }

    #[test]
    fn a_branch_snapshot_is_sealed_bounded_and_bound_to_the_endpoint() {
        let (owner, _) = team(1);
        let key = crate::StorageKey::derive(&[81; 32]).unwrap();
        // Storage fields not used by MLS make the record snapshot larger
        // than the old128KiB workspace bundle without building a big group.
        owner
            .provider
            .storage()
            .values
            .write()
            .unwrap()
            .insert(b"branch-snapshot-test".to_vec(), vec![42; 160 * 1024]);
        assert!(owner.seal(&key).is_err());
        let bytes = owner.seal_branch_snapshot(&key).unwrap();
        let restored =
            Workspace::restore_branch_snapshot(&key, owner.endpoint(), owner.id(), &bytes).unwrap();
        assert_eq!(restored.epoch_fingerprint(), owner.epoch_fingerprint());
        assert!(Workspace::restore_branch_snapshot(&key, [0; 32], owner.id(), &bytes).is_err());
        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(
            Workspace::restore_branch_snapshot(&key, owner.endpoint(), owner.id(), &corrupt)
                .is_err()
        );
        owner.provider.storage().values.write().unwrap().insert(
            b"branch-snapshot-test".to_vec(),
            vec![42; crate::MAX_BRANCH_SNAPSHOT],
        );
        assert_eq!(
            owner.seal_branch_snapshot(&key).unwrap_err(),
            "branch snapshot exceeds size limit"
        );
    }

    #[test]
    fn a_snapshot_restores_only_history_that_reaches_its_exact_state() {
        let (owner, members) = team(1);
        let key = crate::StorageKey::derive(&[82; 32]).unwrap();
        let at_fork = owner.seal_branch_snapshot(&key).unwrap();
        let promote = owner
            .prepare_management(ManagementAction::Promote(id(&members[0])))
            .unwrap();
        let invite = owner
            .prepare_management(ManagementAction::CreateInvitation([8; 32], 0, false))
            .unwrap();
        let mut restored =
            Workspace::restore_branch_snapshot(&key, owner.endpoint(), owner.id(), &at_fork)
                .unwrap();
        assert!(restored.admissions.is_empty());
        assert!(restored.join_history.is_none());
        restored.restore_branch_history(&promote.workspace).unwrap();
        assert_eq!(
            restored.history_start().unwrap(),
            owner.history_start().unwrap()
        );
        assert_eq!(restored.epoch_fingerprint(), owner.epoch_fingerprint());
        let wrong = invite.workspace.seal_branch_snapshot(&key).unwrap();
        let mut wrong =
            Workspace::restore_branch_snapshot(&key, owner.endpoint(), owner.id(), &wrong).unwrap();
        assert!(wrong.restore_branch_history(&promote.workspace).is_err());
    }

    #[test]
    fn restoring_a_common_branch_keeps_its_links_and_excludes_losing_links() {
        let (owner, _) = team(1);
        let (common, _, _) = owner.prepare_invitation(0, false, false).unwrap();
        let MembershipAuthorization::Management(common_action) = &common.authorization else {
            panic!()
        };
        let key = crate::StorageKey::derive(&[83; 32]).unwrap();
        let snapshot = common.workspace.seal_branch_snapshot(&key).unwrap();
        let (losing, _, _) = common
            .workspace
            .prepare_invitation(0, false, false)
            .unwrap();
        let MembershipAuthorization::Management(losing_action) = &losing.authorization else {
            panic!()
        };
        let mut restored =
            Workspace::restore_branch_snapshot(&key, owner.endpoint(), owner.id(), &snapshot)
                .unwrap();
        restored.restore_branch_history(&losing.workspace).unwrap();
        assert!(
            restored
                .retained_invitation_checkpoint(common_action)
                .is_some(),
            "a link issued before the fork must remain available"
        );
        assert!(
            restored
                .retained_invitation_checkpoint(losing_action)
                .is_none(),
            "a losing-suffix link must not cross the fork"
        );
        restored.verify_retained_invitation_checkpoints().unwrap();
    }

    #[test]
    fn an_announcement_verifies_only_for_its_member_and_bytes() {
        let (admin, members) = team(2);
        let [first, second] = <[Workspace; 2]>::try_from(members).ok().unwrap();
        let signature = first.sign_announcement(b"head 7").unwrap();
        assert_eq!(
            second
                .verify_announcement(first.endpoint(), b"head 7", &signature)
                .unwrap(),
            id(&first)
        );
        assert!(
            second
                .verify_announcement(first.endpoint(), b"head 8", &signature)
                .is_err()
        );
        assert!(
            second
                .verify_announcement(admin.endpoint(), b"head 7", &signature)
                .is_err()
        );
        assert!(
            second
                .verify_announcement([3; 32], b"head 7", &signature)
                .is_err()
        );
    }

    #[test]
    fn a_saved_public_pin_rebuilds_only_its_accepted_branch() {
        let (common, _) = team(2);
        let pin = common.public_checkpoint_pin().unwrap();
        let epoch = common.epoch();
        let winning = common.prepare_self_update().unwrap().workspace;
        let checkpoint = winning.public_checkpoint_from_pin(epoch, &pin).unwrap();
        assert_eq!(checkpoint, common.public_checkpoint().unwrap());
        assert!(winning.public_checkpoint_from_pin(epoch + 1, &pin).is_err());
        let mut forged = pin.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(winning.public_checkpoint_from_pin(epoch, &forged).is_err());
        assert!(winning.checkpoint_pin_epoch(&[]).is_err());
        assert!(
            winning
                .checkpoint_pin_epoch(&vec![0; crate::MAX_CHECKPOINT_PIN + 1])
                .is_err()
        );
        let (other, _) = team(1);
        assert!(
            winning
                .public_checkpoint_from_pin(epoch, &other.public_checkpoint_pin().unwrap())
                .is_err()
        );

        let losing = common.prepare_self_update().unwrap().workspace;
        assert_ne!(winning.epoch_fingerprint(), losing.epoch_fingerprint());
        assert!(
            winning
                .public_checkpoint_from_pin(
                    losing.epoch(),
                    &losing.public_checkpoint_pin().unwrap()
                )
                .is_err()
        );
    }
}
