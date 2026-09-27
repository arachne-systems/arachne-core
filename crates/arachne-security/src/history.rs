//! Accepted control records, independent of the legacy inline transfer format.
use super::{JoinProof, MembershipAuthorization, MembershipVerifier, Workspace, storage};

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
        if super::bootstrap::checkpoint_digest(&checkpoint)?.as_slice() != &bytes[5..37] {
            return Err("history checkpoint mismatch");
        }
        Ok(Self { checkpoint, steps })
    }

    pub fn from_workspace(owner: &Workspace) -> Result<Self, &'static str> {
        Self::from_inline(JoinProof::from_workspace(owner)?.history())
    }

    pub fn verifier(&self, workspace: [u8; 32]) -> Result<MembershipVerifier, &'static str> {
        MembershipVerifier::from_local_checkpoint(
            workspace,
            super::bootstrap::checkpoint_digest(&self.checkpoint)?,
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
        let mut proof = JoinProof::from_local_checkpoint(
            workspace,
            super::bootstrap::checkpoint_digest(&self.checkpoint)?,
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

#[cfg(test)]
pub(crate) mod tests {
    use crate::{
        AdmissionAssessment, MAX_ADMISSION_BATCH, ManagementAction, MembershipAuthorization,
        PendingJoin, PreparedManagementUpdate, Workspace,
    };

    pub(crate) fn endpoint(index: usize) -> [u8; 32] {
        crate::test_endpoint(1_000_000 + index as u64)
    }

    /// An owner and one early member, both grown to at least `size` members
    /// through batch admissions from one early invitation.
    pub(crate) fn grown(seed: u8, size: usize) -> (Workspace, Workspace) {
        let owner =
            Workspace::create(crate::test_key(u64::from(seed)), "Large workspace owner").unwrap();
        let (registration, invitation, checkpoint) =
            owner.prepare_invitation(0, false, false).unwrap();
        let mut owner = registration.workspace;
        let joiner = |index: usize| {
            PendingJoin::from_invitation(
                &invitation,
                &checkpoint,
                crate::test_key_for(endpoint(index)),
                "Member",
            )
            .unwrap()
        };
        let early = joiner(0);
        let request = early.admission_request().unwrap().to_vec();
        let AdmissionAssessment::Ready(validated) =
            owner.assess_admission(endpoint(0), &request).unwrap()
        else {
            panic!("open invitation needs no approval");
        };
        let prepared = owner
            .prepare_validated_admission_batch(&[(endpoint(0), request.as_slice(), &validated)])
            .unwrap();
        let mut proof = early.join_proof().unwrap();
        proof
            .apply_transition(
                &MembershipAuthorization::Admission(prepared.replies[0].authorization.clone()),
                &prepared.commit,
            )
            .unwrap();
        let mut member = early.prepare_workspace(&proof, &prepared.welcome).unwrap();
        owner = prepared.workspace;
        let mut next = 1;
        while owner.member_count() < size {
            let range = next..(next + MAX_ADMISSION_BATCH);
            let joins: Vec<_> = range.clone().map(joiner).collect();
            let requests: Vec<_> = joins
                .iter()
                .map(|join| join.admission_request().unwrap().to_vec())
                .collect();
            let validated: Vec<_> = range
                .clone()
                .zip(&requests)
                .map(|(index, request)| {
                    match owner.assess_admission(endpoint(index), request).unwrap() {
                        AdmissionAssessment::Ready(validated) => validated,
                        _ => panic!("open invitation needs no approval"),
                    }
                })
                .collect();
            let entries: Vec<_> = range
                .clone()
                .zip(requests.iter().zip(&validated))
                .map(|(index, (request, validated))| {
                    (endpoint(index), request.as_slice(), validated)
                })
                .collect();
            let prepared = owner.prepare_validated_admission_batch(&entries).unwrap();
            let authorizations: Vec<_> = prepared
                .replies
                .iter()
                .map(|reply| reply.authorization.clone())
                .collect();
            member = member
                .prepare_admission_batch_update(&authorizations, &prepared.commit)
                .unwrap();
            owner = prepared.workspace;
            next = range.end;
        }
        (owner, member)
    }

    /// ADR A2 step 3: the inline history and the step records are codec v3.
    /// Records written by version 1 or 2 are rejected with one clear error.
    #[test]
    fn history_and_records_are_version_three_and_older_versions_are_rejected() {
        use crate::step::FORMAT_NOT_SUPPORTED;
        let (owner, member) = grown(207, 3);
        for workspace in [&owner, &member] {
            let history = workspace.join_history.as_ref().unwrap();
            let inline = history.inline(workspace.id()).unwrap();
            assert_eq!(&inline[..5], b"DFJH\x03");
            let digest: [u8; 32] = inline[5..37].try_into().unwrap();
            crate::JoinProof::from_history(workspace.id(), digest, &inline).unwrap();
            for old in [1, 2] {
                let mut bytes = inline.clone();
                bytes[4] = old;
                assert_eq!(
                    crate::JoinProof::from_history(workspace.id(), digest, &bytes).err(),
                    Some(FORMAT_NOT_SUPPORTED)
                );
                assert_eq!(
                    super::MembershipHistory::from_inline(&bytes).err(),
                    Some(FORMAT_NOT_SUPPORTED)
                );
            }
            let mut records = workspace.export_records().unwrap();
            let meta = records.get_mut(&b"security/meta"[..]).unwrap();
            assert_eq!(&meta[..5], b"DFWR\x03");
            meta[4] = 2;
            assert_eq!(
                Workspace::restore_records(workspace.endpoint(), workspace.id(), &records).err(),
                Some(FORMAT_NOT_SUPPORTED)
            );
            // Step records use the v3 step codec: kind tag, then class.
            let records = workspace.export_records().unwrap();
            for (name, value) in &records {
                if name.starts_with(b"security/history/step/") {
                    let class = crate::ForkClass::from_u8(value[1]).unwrap();
                    assert!(matches!(
                        (value[0], class),
                        (0 | 11, crate::ForkClass::Admission) | (1..=10, _)
                    ));
                }
            }
        }
    }

    /// B3b: a member restored without a join history rebuilds one from its own
    /// state. That is local state, so the wire bound for received checkpoints
    /// must not apply; past ~250 members it rejected a valid management commit
    /// the administrator had already adopted (a fork).
    #[test]
    fn a_member_restored_without_join_history_accepts_management_past_three_hundred_members() {
        let (owner, mut member) = grown(206, 310);
        member.join_history = None;
        let records = member.export_records().unwrap();
        let restored = Workspace::restore_records(endpoint(0), member.id(), &records).unwrap();
        assert!(restored.join_history.is_none());
        let own_id = restored.member().unwrap().id();
        let target = owner
            .member_roster()
            .unwrap()
            .into_iter()
            .find(|m| !m.administrator && m.id != own_id)
            .unwrap()
            .id;
        let action = ManagementAction::Remove(target);
        let prepared = owner.prepare_management(action).unwrap();
        let PreparedManagementUpdate::Active(updated) = restored
            .prepare_step_update(&prepared.authorization, &prepared.commit)
            .unwrap_or_else(|error| {
                panic!(
                    "restored member at {} members rejected management: {error}",
                    restored.member_count()
                )
            })
        else {
            panic!("removal of another member removed this member")
        };
        assert_eq!(updated.epoch(), prepared.workspace.epoch());
        // The rebuilt history is local state; it must also persist and restore.
        let records = updated.export_records().unwrap();
        let again = Workspace::restore_records(endpoint(0), updated.id(), &records).unwrap();
        assert_eq!(again.epoch(), prepared.workspace.epoch());
    }
}
