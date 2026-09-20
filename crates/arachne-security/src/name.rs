//! Administrator-signed presentation metadata; changing it never rotates data keys.
use super::{MembershipVerifier, SUITE, Workspace, bootstrap, history::MembershipHistory};
use openmls::prelude::{tls_codec::Serialize, *};
use openmls_traits::{OpenMlsProvider, crypto::OpenMlsCrypto, signatures::Signer};
use sha2::{Digest, Sha256};

pub(super) const EXTENSION: u16 = 0xff01;
const CURRENT: &[u8] = b"data-fabric/workspace-name/current/v1";
const STEP: &[u8] = b"data-fabric/workspace-name/step/v1/";
const CHECKPOINT: &[u8] = b"data-fabric/workspace-name/checkpoint/v1";
const MISSING: &[u8] = b"data-fabric/workspace-name/missing/v1";
const MAGIC: &[u8] = b"DFNM\x01";
const CHECKPOINT_MAGIC: &[u8] = b"DFNC\x01";
pub const MAX_WORKSPACE_NAME_RECORD: usize = 5 + 32 + 8 + 32 + 32 + 8 + 32 + 320 + 64;
pub const MAX_WORKSPACE_NAME_CHECKPOINT: usize = MAX_WORKSPACE_NAME_RECORD;

pub fn validate_workspace_name(name: &str) -> Result<&str, &'static str> {
    if name.chars().any(|c| {
        c.is_control()
            || matches!(c,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    }) {
        return Err(
            "workspace name must be 1–80 characters without control or bidirectional formatting characters",
        );
    }
    let name = name.trim();
    if name.is_empty() || name.len() > 320 || name.chars().count() > 80 {
        return Err(
            "workspace name must be 1–80 characters without control or bidirectional formatting characters",
        );
    }
    Ok(name)
}

#[derive(Clone, Default)]
pub(super) struct NameState {
    pub revision: u64,
    pub head: [u8; 32],
    pub name: Option<String>,
}
impl NameState {
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 41 || bytes.len() > 361 || bytes[0] != 1 {
            return Err("invalid workspace name checkpoint");
        }
        let revision = u64::from_be_bytes(bytes[1..9].try_into().unwrap());
        let head = bytes[9..41].try_into().unwrap();
        let name = std::str::from_utf8(&bytes[41..]).map_err(|_| "invalid workspace name text")?;
        if revision == 0 && head == [0; 32] && name.is_empty() {
            return Ok(Self::default());
        }
        if revision == 0 || head == [0; 32] || validate_workspace_name(name)? != name {
            return Err("invalid workspace name checkpoint");
        }
        Ok(Self {
            revision,
            head,
            name: Some(name.to_owned()),
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![1];
        bytes.extend(self.revision.to_be_bytes());
        bytes.extend(self.head);
        if let Some(name) = &self.name {
            bytes.extend(name.as_bytes());
        }
        bytes
    }
}

pub struct PreparedWorkspaceName {
    pub workspace: Workspace,
    pub record: Vec<u8>,
}

pub struct PreparedWorkspaceNameCheckpoint {
    pub workspace: Workspace,
    pub missing: u64,
}

fn branch(context: &GroupContext) -> Result<[u8; 32], &'static str> {
    Ok(Sha256::digest(
        context
            .tls_serialize_detached()
            .map_err(|_| "group context encoding failed")?,
    )
    .into())
}

impl Workspace {
    pub(super) fn name_state(&self) -> Result<NameState, &'static str> {
        let state = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| "storage unavailable")?;
        state
            .get(CURRENT)
            .map(|bytes| NameState::decode(bytes))
            .transpose()
            .map(|n| n.unwrap_or_default())
    }
    pub fn workspace_name(&self) -> Result<Option<String>, &'static str> {
        Ok(self.name_state()?.name)
    }
    pub fn workspace_name_head(&self) -> Result<[u8; 32], &'static str> {
        Ok(self.name_state()?.head)
    }
    pub fn workspace_name_revision(&self) -> Result<u64, &'static str> {
        Ok(self.name_state()?.revision)
    }
    pub fn workspace_name_missing_history(&self) -> Result<u64, &'static str> {
        let state = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| "storage unavailable")?;
        state.get(MISSING).map_or(Ok(0), |bytes| {
            bytes
                .as_slice()
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| "invalid workspace name missing-history count")
        })
    }
    pub(super) fn initialize_name_checkpoint(&self, state: &NameState) -> Result<(), &'static str> {
        self.provider
            .storage()
            .values
            .write()
            .map_err(|_| "storage unavailable")?
            .insert(CURRENT.to_vec(), state.encode());
        Ok(())
    }
    pub(super) fn name_checkpoint_extension(&self) -> Result<Vec<Extension>, &'static str> {
        let state = self.name_state()?;
        Ok(if state.name.is_some() {
            vec![Extension::Unknown(
                EXTENSION,
                UnknownExtension(state.encode()),
            )]
        } else {
            vec![]
        })
    }
    pub fn prepare_workspace_name(
        &self,
        name: &str,
    ) -> Result<PreparedWorkspaceName, &'static str> {
        let name = validate_workspace_name(name)?;
        let prior = self.name_state()?;
        if prior.name.as_deref() == Some(name) {
            return Err("workspace already has this name");
        }
        let mut record = MAGIC.to_vec();
        record.extend(self.id());
        record.extend(
            prior
                .revision
                .checked_add(1)
                .ok_or("workspace name revision exhausted")?
                .to_be_bytes(),
        );
        record.extend(prior.head);
        record.extend(self.member().ok_or("member profile required")?.id());
        record.extend(self.epoch().to_be_bytes());
        record.extend(branch(
            MembershipVerifier::from_workspace(self)?
                .group
                .group_context(),
        )?);
        record.extend(name.as_bytes());
        record.extend(
            self._signer
                .sign(&record)
                .map_err(|_| "workspace name signing failed")?,
        );
        let workspace = self.prepare_workspace_name_update(&record)?;
        let checkpoint = workspace.sign_workspace_name_checkpoint()?;
        workspace
            .provider
            .storage()
            .values
            .write()
            .map_err(|_| "storage unavailable")?
            .insert(CHECKPOINT.to_vec(), checkpoint);
        Ok(PreparedWorkspaceName { workspace, record })
    }

    pub fn sign_workspace_name_checkpoint(&self) -> Result<Vec<u8>, &'static str> {
        let state = self.name_state()?;
        let member = self.member().ok_or("member profile required")?;
        if state.name.is_none()
            || !self
                .member_roster()?
                .iter()
                .any(|entry| entry.id == member.id() && entry.administrator)
        {
            return Err("workspace name checkpoint requires a current administrator");
        }
        let mut bytes = CHECKPOINT_MAGIC.to_vec();
        bytes.extend(self.id());
        bytes.extend(state.revision.to_be_bytes());
        bytes.extend(state.head);
        bytes.extend(member.id());
        bytes.extend(self.epoch().to_be_bytes());
        bytes.extend(branch(
            MembershipVerifier::from_workspace(self)?
                .group
                .group_context(),
        )?);
        bytes.extend(state.name.unwrap().as_bytes());
        bytes.extend(
            self._signer
                .sign(&bytes)
                .map_err(|_| "workspace name checkpoint signing failed")?,
        );
        Ok(bytes)
    }

    fn verify_workspace_name_checkpoint(&self, bytes: &[u8]) -> Result<NameState, &'static str> {
        if bytes.len() < 214
            || bytes.len() > MAX_WORKSPACE_NAME_CHECKPOINT
            || !bytes.starts_with(CHECKPOINT_MAGIC)
            || bytes[5..37] != self.id()
        {
            return Err("invalid workspace name checkpoint");
        }
        let revision = u64::from_be_bytes(bytes[37..45].try_into().unwrap());
        let head: [u8; 32] = bytes[45..77].try_into().unwrap();
        let author: [u8; 32] = bytes[77..109].try_into().unwrap();
        let epoch = u64::from_be_bytes(bytes[109..117].try_into().unwrap());
        let end = bytes.len() - 64;
        let name = std::str::from_utf8(&bytes[149..end])
            .map_err(|_| "invalid workspace name checkpoint text")?;
        if revision == 0
            || head == [0; 32]
            || validate_workspace_name(name)? != name
            || epoch != self.epoch()
            || bytes[117..149]
                != branch(
                    MembershipVerifier::from_workspace(self)?
                        .group
                        .group_context(),
                )?
        {
            return Err("workspace name checkpoint does not match current membership");
        }
        let admins = bootstrap::authority(self.group.extensions())?;
        let members: Vec<_> = self.group.members().collect();
        let member = members
            .iter()
            .find(|member| bootstrap::binding(&member.credential).is_ok_and(|(id, _)| id == author))
            .ok_or("workspace name checkpoint author is not a current member")?;
        if !admins.contains(&member.signature_key) {
            return Err("workspace name checkpoint author is not a current administrator");
        }
        self.provider
            .crypto()
            .verify_signature(
                SUITE.signature_algorithm(),
                &bytes[..end],
                &member.signature_key,
                &bytes[end..],
            )
            .map_err(|_| "workspace name checkpoint signature invalid")?;
        Ok(NameState {
            revision,
            head,
            name: Some(name.to_owned()),
        })
    }

    pub fn workspace_name_checkpoint(&self) -> Result<Option<Vec<u8>>, &'static str> {
        if let Ok(checkpoint) = self.sign_workspace_name_checkpoint() {
            return Ok(Some(checkpoint));
        }
        let stored = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| "storage unavailable")?
            .get(CHECKPOINT)
            .cloned();
        Ok(stored.filter(|bytes| {
            self.verify_workspace_name_checkpoint(bytes)
                .is_ok_and(|state| {
                    self.name_state()
                        .is_ok_and(|current| state.encode() == current.encode())
                })
        }))
    }

    pub fn prepare_workspace_name_checkpoint(
        &self,
        checkpoint: &[u8],
    ) -> Result<PreparedWorkspaceNameCheckpoint, &'static str> {
        let state = self.verify_workspace_name_checkpoint(checkpoint)?;
        let previous = self.name_state()?;
        let missing = state
            .revision
            .checked_sub(previous.revision)
            .filter(|missing| *missing > 0)
            .ok_or("workspace name checkpoint does not advance accepted name")?;
        let total = self
            .workspace_name_missing_history()?
            .checked_add(missing)
            .ok_or("workspace name missing-history count exhausted")?;
        let candidate = self.provisional_copy()?;
        let mut values = candidate
            .provider
            .storage()
            .values
            .write()
            .map_err(|_| "storage unavailable")?;
        values.insert(CURRENT.to_vec(), state.encode());
        values.insert(CHECKPOINT.to_vec(), checkpoint.to_vec());
        values.insert(MISSING.to_vec(), total.to_be_bytes().to_vec());
        drop(values);
        Ok(PreparedWorkspaceNameCheckpoint {
            workspace: candidate,
            missing,
        })
    }
    fn name_authority_at(&self, epoch: u64) -> Result<MembershipVerifier, &'static str> {
        if epoch == self.epoch() {
            return MembershipVerifier::from_workspace(self);
        }
        let history = self
            .join_history
            .as_ref()
            .ok_or("workspace name authority history unavailable")?;
        let mut verifier = history.verifier(self.id())?;
        if verifier.epoch() > epoch {
            return Err("workspace name predates accepted history");
        }
        for (auth, commit) in &history.steps {
            if verifier.epoch() == epoch {
                break;
            }
            verifier.apply_transition(auth, commit)?;
        }
        if verifier.epoch() != epoch {
            return Err("workspace name authority history unavailable");
        }
        Ok(verifier)
    }
    /// Accept exactly the next name on this branch. No caller may install a peer's
    /// checkpoint over existing accepted state; only a new join has that baseline.
    pub fn prepare_workspace_name_update(&self, record: &[u8]) -> Result<Workspace, &'static str> {
        if record.len() < 214
            || record.len() > MAX_WORKSPACE_NAME_RECORD
            || !record.starts_with(MAGIC)
            || record[5..37] != self.id()
        {
            return Err("invalid workspace name record");
        }
        let previous = self.name_state()?;
        let revision = u64::from_be_bytes(record[37..45].try_into().unwrap());
        if previous.revision.checked_add(1) != Some(revision) || record[45..77] != previous.head {
            return Err("workspace name update does not extend accepted name");
        }
        let author: [u8; 32] = record[77..109].try_into().unwrap();
        if !self
            .member_roster()?
            .iter()
            .any(|m| m.id == author && m.administrator)
        {
            return Err("workspace name author is not a current administrator");
        }
        let epoch = u64::from_be_bytes(record[109..117].try_into().unwrap());
        let end = record.len() - 64;
        let name =
            std::str::from_utf8(&record[149..end]).map_err(|_| "invalid workspace name text")?;
        if validate_workspace_name(name)? != name || previous.name.as_deref() == Some(name) {
            return Err("invalid workspace name change");
        }
        let verifier = self.name_authority_at(epoch)?;
        if record[117..149] != branch(verifier.group.group_context())? {
            return Err("workspace name membership branch mismatch");
        }
        let admins = bootstrap::authority(verifier.group.group_context().extensions())?;
        let members: Vec<_> = verifier.group.members().collect();
        let member = members
            .iter()
            .find(|m| bootstrap::binding(&m.credential).is_ok_and(|(id, _)| id == author))
            .ok_or("workspace name author is not a member")?;
        if !admins.contains(&member.signature_key)
            || members
                .iter()
                .filter(|m| m.signature_key == member.signature_key)
                .count()
                != 1
        {
            return Err("workspace name author is not an administrator");
        }
        self.provider
            .crypto()
            .verify_signature(
                SUITE.signature_algorithm(),
                &record[..end],
                &member.signature_key,
                &record[end..],
            )
            .map_err(|_| "workspace name signature invalid")?;
        let mut candidate = self.provisional_copy()?;
        // Preserve the authority branch needed after a later role/membership change.
        if candidate.join_history.is_none() {
            candidate.join_history = Some(MembershipHistory::from_workspace(self)?);
        }
        candidate.initialize_name_checkpoint(&NameState {
            revision,
            head: Sha256::digest(record).into(),
            name: Some(name.to_owned()),
        })?;
        candidate
            .provider
            .storage()
            .values
            .write()
            .map_err(|_| "storage unavailable")?
            .insert([STEP, &previous.head].concat(), record.to_vec());
        candidate
            .provider
            .storage()
            .values
            .write()
            .map_err(|_| "storage unavailable")?
            .remove(CHECKPOINT);
        Ok(candidate)
    }
    /// One bounded next record, regardless of how many changes the workspace has made.
    pub fn next_workspace_name(&self, after: [u8; 32]) -> Result<Option<Vec<u8>>, &'static str> {
        Ok(self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| "storage unavailable")?
            .get([STEP, &after].concat().as_slice())
            .cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ManagementAction, PendingJoin, PreparedManagementUpdate, StorageKey};

    fn accept_role(owner: &Workspace, change: &crate::PreparedManagement) -> Workspace {
        let PreparedManagementUpdate::Active(next) = owner
            .prepare_management_update(change.action, &change.commit)
            .unwrap()
        else {
            panic!("unexpected removal")
        };
        *next
    }
    fn pair() -> (Workspace, Workspace) {
        let admin = Workspace::create_named([1; 32], "Alex", Some("Storm Assessment")).unwrap();
        let (invite, checkpoint) = admin.issue_invitation().unwrap();
        let pending =
            PendingJoin::from_invitation(&invite, &checkpoint, [2; 32], "Jordan").unwrap();
        let add = admin
            .prepare_admission([2; 32], pending.admission_request().unwrap())
            .unwrap();
        let mut proof = pending.join_proof().unwrap();
        proof.apply_add(&add.authorization, &add.commit).unwrap();
        let member = pending.prepare_workspace(&proof, &add.welcome).unwrap();
        (add.workspace, member)
    }
    #[test]
    fn names_validate_original_text_and_preserve_distinct_workspace_identity() {
        for name in [
            "",
            " ",
            "\nStorm",
            "Storm\t",
            "Storm\u{202e}",
            "\u{061c}Storm",
            "Storm\u{2069}",
        ] {
            assert!(validate_workspace_name(name).is_err(), "{name:?}");
        }
        assert!(validate_workspace_name(&"x".repeat(81)).is_err());
        assert!(validate_workspace_name(&"🌲".repeat(80)).is_ok());
        let a = Workspace::create_named([1; 32], "Alex", Some(" Storm Assessment ")).unwrap();
        let b = Workspace::create_named([2; 32], "Alex", Some("Storm Assessment")).unwrap();
        assert_eq!(
            a.workspace_name().unwrap().as_deref(),
            Some("Storm Assessment")
        );
        assert_ne!(a.id(), b.id());
        assert_eq!(a.epoch(), 0);
    }
    #[test]
    fn current_admin_checkpoint_recovers_missing_name_without_trusting_demoted_signer() {
        let (mut admin, member) = pair();
        let member_id = member.member().unwrap().id();
        let promotion = admin
            .prepare_management(ManagementAction::Promote(member_id))
            .unwrap();
        let member = accept_role(&member, &promotion);
        admin = promotion.workspace;

        // The returning member retains the old label while its still-authorized
        // key creates the legitimate next record for the online administrator.
        let renamed = member.prepare_workspace_name("Valley Recovery").unwrap();
        admin = admin
            .prepare_workspace_name_update(&renamed.record)
            .unwrap();
        let demotion = admin
            .prepare_management(ManagementAction::Demote(member_id))
            .unwrap();
        let member = accept_role(&member, &demotion);
        admin = demotion.workspace;
        assert_eq!(
            member.prepare_workspace_name_update(&renamed.record).err(),
            Some("workspace name author is not a current administrator")
        );

        let checkpoint = admin.sign_workspace_name_checkpoint().unwrap();
        let mut forged = checkpoint.clone();
        forged[77..109].copy_from_slice(&member_id);
        let end = forged.len() - 64;
        forged.truncate(end);
        let signature = member._signer.sign(&forged).unwrap();
        forged.extend(signature);
        assert_eq!(
            member.prepare_workspace_name_checkpoint(&forged).err(),
            Some("workspace name checkpoint author is not a current administrator")
        );

        let key = StorageKey::derive(&[72; 32]).unwrap();
        let stale = Workspace::restore(
            &key,
            member.endpoint(),
            member.id(),
            &member.seal(&key).unwrap(),
        )
        .unwrap();
        let recovered = member
            .prepare_workspace_name_checkpoint(&checkpoint)
            .unwrap();
        assert_eq!(recovered.missing, 1);
        assert_eq!(
            recovered.workspace.workspace_name().unwrap().as_deref(),
            Some("Valley Recovery")
        );
        assert_eq!(
            recovered
                .workspace
                .workspace_name_missing_history()
                .unwrap(),
            1
        );

        // A non-administrator can relay the exact current-admin checkpoint; it
        // cannot sign or replace it.
        let relayed = recovered
            .workspace
            .workspace_name_checkpoint()
            .unwrap()
            .unwrap();
        assert_eq!(relayed, checkpoint);
        let relayed = stale.prepare_workspace_name_checkpoint(&relayed).unwrap();
        assert_eq!(relayed.missing, 1);
        assert_eq!(
            relayed.workspace.workspace_name_missing_history().unwrap(),
            1
        );
    }
    #[test]
    fn authority_replay_conflict_legacy_and_restart_preserve_keys_and_history() {
        let (mut admin, mut member) = pair();
        let id = admin.id();
        let creator = admin.member().unwrap().id();
        let key = StorageKey::derive(&[71; 32]).unwrap();
        assert!(member.prepare_workspace_name("Unauthorized").is_err());
        let retained = admin.protect_object(b"chat", b"Keep this history").unwrap();
        let fingerprint = admin.epoch_fingerprint();
        let change = admin.prepare_workspace_name("Valley Recovery").unwrap();
        assert_eq!(
            admin.workspace_name().unwrap().as_deref(),
            Some("Storm Assessment")
        );
        assert_eq!(change.workspace.epoch_fingerprint(), fingerprint);
        let mut forged = change.record.clone();
        let end = forged.len() - 64;
        forged[77..109].copy_from_slice(&member.member().unwrap().id());
        let signature = member._signer.sign(&forged[..end]).unwrap();
        forged[end..].copy_from_slice(&signature);
        assert!(member.prepare_workspace_name_update(&forged).is_err());
        member = member
            .prepare_workspace_name_update(&change.record)
            .unwrap();
        assert!(
            member
                .prepare_workspace_name_update(&change.record)
                .is_err()
        );
        assert_eq!(
            member
                .unprotect_object(b"chat", &retained)
                .unwrap()
                .message
                .payload,
            b"Keep this history"
        );
        admin = change.workspace;
        assert_eq!(admin.id(), id);
        assert_eq!(admin.member().unwrap().id(), creator);
        let promotion = admin
            .prepare_management(ManagementAction::Promote(member.member().unwrap().id()))
            .unwrap();
        member = accept_role(&member, &promotion);
        admin = promotion.workspace;
        let concurrent = admin.prepare_workspace_name("Western Sector").unwrap();
        let renamed = member.prepare_workspace_name("Mountain Search").unwrap();
        admin = admin
            .prepare_workspace_name_update(&renamed.record)
            .unwrap();
        assert!(
            admin
                .prepare_workspace_name_update(&concurrent.record)
                .is_err()
        );
        member = renamed.workspace;
        let records = member.export_records().unwrap();
        member = Workspace::restore_records([2; 32], id, &records).unwrap();
        member = Workspace::restore(&key, [2; 32], id, &member.seal(&key).unwrap()).unwrap();
        assert_eq!(
            member.workspace_name().unwrap().as_deref(),
            Some("Mountain Search")
        );
        let (invite, checkpoint) = member.issue_invitation().unwrap();
        assert_eq!(
            invite
                .join_proof(&checkpoint)
                .unwrap()
                .workspace_name()
                .unwrap()
                .as_deref(),
            Some("Mountain Search")
        );
        let old = member
            .prepare_workspace_name("Signed before demotion")
            .unwrap();
        let demotion = admin
            .prepare_management(ManagementAction::Demote(member.member().unwrap().id()))
            .unwrap();
        member = accept_role(&member, &demotion);
        admin = demotion.workspace;
        assert!(member.prepare_workspace_name("Forbidden").is_err());
        assert_eq!(
            admin.prepare_workspace_name_update(&old.record).err(),
            Some("workspace name author is not a current administrator")
        );
        // A removed/demoted signer cannot manufacture a backdated record either.
        let mut backdated = old.record.clone();
        let end = backdated.len() - 64;
        let signature = member._signer.sign(&backdated[..end]).unwrap();
        backdated[end..].copy_from_slice(&signature);
        assert!(admin.prepare_workspace_name_update(&backdated).is_err());

        let legacy = Workspace::create([3; 32], "Legacy admin").unwrap();
        let legacy =
            Workspace::restore(&key, [3; 32], legacy.id(), &legacy.seal(&key).unwrap()).unwrap();
        assert_eq!(legacy.workspace_name().unwrap(), None);
        let initialized = legacy.prepare_workspace_name("Existing Operation").unwrap();
        assert_eq!(initialized.workspace.id(), legacy.id());
        assert_eq!(
            initialized.workspace.epoch_fingerprint(),
            legacy.epoch_fingerprint()
        );
        assert_eq!(
            initialized.workspace.workspace_name().unwrap().as_deref(),
            Some("Existing Operation")
        );
    }

    #[test]
    fn admission_helper_cannot_replace_invitation_name_and_bad_saved_metadata_fails_restore() {
        let (admin, helper) = pair();
        let (invite, checkpoint) = admin.issue_invitation().unwrap();
        let pending = PendingJoin::from_invitation(&invite, &checkpoint, [3; 32], "Sam").unwrap();
        helper
            .initialize_name_checkpoint(&NameState {
                revision: 999,
                head: [99; 32],
                name: Some("Helper forgery".into()),
            })
            .unwrap();
        let add = helper
            .prepare_admission([3; 32], pending.admission_request().unwrap())
            .unwrap();
        let mut proof = pending.join_proof().unwrap();
        proof.apply_add(&add.authorization, &add.commit).unwrap();
        let joined = pending.prepare_workspace(&proof, &add.welcome).unwrap();
        assert_eq!(
            joined.workspace_name().unwrap().as_deref(),
            Some("Storm Assessment")
        );

        let key = StorageKey::derive(&[77; 32]).unwrap();
        let owner = admin.provisional_copy().unwrap();
        owner
            .provider
            .storage()
            .values
            .write()
            .unwrap()
            .insert(CURRENT.to_vec(), vec![1]);
        assert!(
            Workspace::restore(
                &key,
                owner.endpoint(),
                owner.id(),
                &owner.seal(&key).unwrap()
            )
            .is_err()
        );
        assert!(
            Workspace::restore_records(
                owner.endpoint(),
                owner.id(),
                &owner.export_records().unwrap()
            )
            .is_err()
        );
    }
}
