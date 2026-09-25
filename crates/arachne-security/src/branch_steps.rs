//! Branch comparison from this node's own verified history (ADR A2 step 8).
//!
//! A node that meets a peer on another branch compares the fork keys of the
//! two chains epoch by epoch. It computes both keys itself: its own from the
//! steps it adopted, the peer's by verifying the peer's step against the
//! public state that its own history gives at that epoch (correction 5: a
//! peer's claimed class is never trusted). Head announcements are signed by
//! the member's MLS key, so a relay cannot forge another member's report.
use super::{ForkKey, MembershipAuthorization, SUITE, Workspace, bootstrap, fork_key};
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
        verifier.apply_transition(authorization, commit)?;
        Ok(fork_key(authorization, commit))
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

    fn id(owner: &Workspace) -> [u8; 32] {
        owner.member().unwrap().id()
    }

    #[test]
    fn a_peer_step_on_another_branch_verifies_and_gets_its_own_key() {
        let (admin, members) = team(2);
        let [first, second] = <[Workspace; 2]>::try_from(members).ok().unwrap();
        let fork = admin.epoch();
        // Two competing steps out of the same epoch.
        let promote = admin.prepare_management(ManagementAction::Promote(id(&first))).unwrap();
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
        assert_eq!(fork_key(&auth, &commit), fork_key(&promote.authorization, &promote.commit));
        // No step out of the current epoch yet.
        assert_eq!(on_promote.branch_key(on_promote.epoch()).unwrap(), None);
        // The other branch's step verifies against this node's state at the fork.
        assert_eq!(
            on_promote.verify_branch_step(fork, &invite.authorization, &invite.commit).unwrap(),
            fork_key(&invite.authorization, &invite.commit)
        );
        // A relabelled step fails: the class comes only from a verified step.
        let relabelled = MembershipAuthorization::Management(ManagementAction::Promote(id(&second)));
        assert!(on_promote.verify_branch_step(fork, &relabelled, &invite.commit).is_err());
        // A step for another epoch fails.
        assert!(on_promote.verify_branch_step(fork + 1, &invite.authorization, &invite.commit).is_err());
        // Below the retained history nothing can be verified.
        assert!(on_promote.verify_branch_step(0, &invite.authorization, &invite.commit).is_err());
        let _ = first;
    }

    #[test]
    fn an_announcement_verifies_only_for_its_member_and_bytes() {
        let (admin, members) = team(2);
        let [first, second] = <[Workspace; 2]>::try_from(members).ok().unwrap();
        let signature = first.sign_announcement(b"head 7").unwrap();
        assert_eq!(
            second.verify_announcement(first.endpoint(), b"head 7", &signature).unwrap(),
            id(&first)
        );
        assert!(second.verify_announcement(first.endpoint(), b"head 8", &signature).is_err());
        assert!(second.verify_announcement(admin.endpoint(), b"head 7", &signature).is_err());
        assert!(second.verify_announcement([3; 32], b"head 7", &signature).is_err());
    }
}
