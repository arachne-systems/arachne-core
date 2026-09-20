//! Accepted control records, independent of the legacy inline transfer format.
use super::{JoinProof, MembershipAuthorization, MembershipVerifier, Workspace, storage};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub(super) struct MembershipHistory {
    pub checkpoint: Vec<u8>,
    pub steps: Vec<(MembershipAuthorization, Vec<u8>)>,
}

impl MembershipHistory {
    pub fn from_inline(bytes: &[u8]) -> Result<Self, &'static str> {
        let steps = JoinProof::history_steps(bytes)?;
        let mut rest = &bytes[37..];
        let length = storage::number(&mut rest)?;
        let checkpoint = storage::take(&mut rest, length)?.to_vec();
        if Sha256::digest(&checkpoint).as_slice() != &bytes[5..37] {
            return Err("history checkpoint mismatch");
        }
        Ok(Self { checkpoint, steps })
    }

    pub fn from_workspace(owner: &Workspace) -> Result<Self, &'static str> {
        Self::from_inline(JoinProof::from_workspace(owner)?.history())
    }

    pub fn verifier(&self, workspace: [u8; 32]) -> Result<MembershipVerifier, &'static str> {
        MembershipVerifier::from_trusted_checkpoint(
            workspace,
            Sha256::digest(&self.checkpoint).into(),
            &self.checkpoint,
        )
    }

    pub fn verify(&self, owner: &Workspace) -> Result<(), &'static str> {
        let mut verifier = self.verifier(owner.id())?;
        for (auth, commit) in &self.steps {
            verifier.apply_transition(auth, commit)?;
        }
        if !verifier.matches_workspace(owner)? {
            return Err("saved history does not match workspace");
        }
        Ok(())
    }

    /// Compatibility serialization only. This budget must not limit the owner
    /// or the incremental record store; an oversized legacy export fails closed.
    pub fn inline(&self, workspace: [u8; 32]) -> Result<Vec<u8>, &'static str> {
        let mut proof = JoinProof::from_trusted_checkpoint(
            workspace,
            Sha256::digest(&self.checkpoint).into(),
            &self.checkpoint,
        )?;
        for (auth, commit) in &self.steps {
            proof.apply_transition(auth, commit)?;
        }
        Ok(proof.history().to_vec())
    }
}

impl Workspace {
    /// The caller has verified the transition against this exact accepted owner.
    /// Keeps record retention separate from incremental public verification.
    pub(super) fn append_history(
        &self,
        authorization: MembershipAuthorization,
        commit: &[u8],
    ) -> Result<MembershipHistory, &'static str> {
        let mut history = match &self.join_history {
            Some(history) => history.clone(),
            None => MembershipHistory::from_workspace(self)?,
        };
        history.steps.push((authorization, commit.to_vec()));
        Ok(history)
    }
}
