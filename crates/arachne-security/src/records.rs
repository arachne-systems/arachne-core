//! Native persistence seam. Values contain secrets and must go only to a trusted
//! encrypted store, never JSON/JNI/network responses or logs.
use super::{
    AdmissionAuthorization, MembershipAuthorization, Workspace,
    history::MembershipHistory,
    invitation::RetainedAdmission,
    storage::{self, number, take},
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub type SecurityRecords = BTreeMap<Vec<u8>, Zeroizing<Vec<u8>>>;
const META: &[u8] = b"security/meta";
const PROVIDER: &[u8] = b"security/provider/";
const ADMISSION: &[u8] = b"security/admission/";
const CHECKPOINT: &[u8] = b"security/history/checkpoint";
const STEP: &[u8] = b"security/history/step/";
const INVITATION_CHECKPOINT: &[u8] = b"security/invitation-checkpoint/";

fn named(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    [prefix, suffix].concat()
}
fn blob(out: &mut Vec<u8>, value: &[u8]) -> Result<(), &'static str> {
    out.extend(
        u32::try_from(value.len())
            .map_err(|_| "record value too large")?
            .to_be_bytes(),
    );
    out.extend(value);
    Ok(())
}
fn read_blob(bytes: &mut &[u8]) -> Result<Vec<u8>, &'static str> {
    let length = number(bytes)?;
    Ok(take(bytes, length)?.to_vec())
}
fn read_count(bytes: &mut &[u8]) -> Result<usize, &'static str> {
    usize::try_from(u64::from_be_bytes(take(bytes, 8)?.try_into().unwrap()))
        .map_err(|_| "record count too large")
}
fn put_auth(out: &mut Vec<u8>, auth: &AdmissionAuthorization) {
    out.extend(auth.invitation_key);
    out.extend(auth.grant_signature);
    out.extend(auth.redemption_signature);
}
fn read_auth(bytes: &mut &[u8]) -> Result<AdmissionAuthorization, &'static str> {
    Ok(AdmissionAuthorization {
        invitation_key: take(bytes, 32)?.try_into().unwrap(),
        grant_signature: take(bytes, 64)?.try_into().unwrap(),
        redemption_signature: take(bytes, 64)?.try_into().unwrap(),
    })
}
fn step(auth: &MembershipAuthorization, commit: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut bytes = Zeroizing::new(Vec::new());
    match auth {
        MembershipAuthorization::Admission(auth) => {
            bytes.push(0);
            put_auth(&mut bytes, auth);
        }
        MembershipAuthorization::AdmissionBatch(auths) => {
            if auths.is_empty() || auths.len() > super::MAX_ADMISSION_BATCH {
                return Err("invalid admission batch size");
            }
            bytes.push(11);
            bytes.extend((auths.len() as u16).to_be_bytes());
            for auth in auths {
                put_auth(&mut bytes, auth);
            }
        }
        MembershipAuthorization::Management(action) => {
            let (tag, id) = match action {
                super::ManagementAction::Promote(id) => (1, id),
                super::ManagementAction::Demote(id) => (2, id),
                super::ManagementAction::Remove(id) => (3, id),
                super::ManagementAction::Leave(id, _) => (4, id),
                super::ManagementAction::CreateInvitation(id, ..) => (5, id),
                super::ManagementAction::CreateAutomaticInvitation(id, ..) => (8, id),
                super::ManagementAction::CreateRequestInvitation(id, ..) => (9, id),
                super::ManagementAction::DeclineInvitationRequest(id, _) => (10, id),
                super::ManagementAction::DisableInvitation(id) => (6, id),
                super::ManagementAction::ApproveInvitation(id, _) => (7, id),
            };
            bytes.push(tag);
            bytes.extend(id);
            if let super::ManagementAction::Leave(_, signature) = action {
                bytes.extend(signature);
            }
            if let super::ManagementAction::CreateInvitation(_, expires, personal) = action {
                bytes.extend(expires.to_be_bytes());
                bytes.push(u8::from(*personal));
            }
            if let super::ManagementAction::CreateAutomaticInvitation(_, expires)
            | super::ManagementAction::CreateRequestInvitation(_, expires) = action
            {
                bytes.extend(expires.to_be_bytes());
            }
            if let super::ManagementAction::ApproveInvitation(_, package)
            | super::ManagementAction::DeclineInvitationRequest(_, package) = action
            {
                bytes.extend(package);
            }
        }
    }
    blob(&mut bytes, commit)?;
    Ok(bytes)
}
fn read_step(mut bytes: &[u8]) -> Result<(MembershipAuthorization, Vec<u8>), &'static str> {
    let auth = match take(&mut bytes, 1)?[0] {
        0 => MembershipAuthorization::Admission(read_auth(&mut bytes)?),
        11 => {
            let count = u16::from_be_bytes(take(&mut bytes, 2)?.try_into().unwrap()) as usize;
            if count == 0 || count > super::MAX_ADMISSION_BATCH {
                return Err("invalid admission batch size");
            }
            MembershipAuthorization::AdmissionBatch(
                (0..count)
                    .map(|_| read_auth(&mut bytes))
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
        tag @ 1..=10 => {
            let id = take(&mut bytes, 32)?.try_into().unwrap();
            MembershipAuthorization::Management(match tag {
                1 => super::ManagementAction::Promote(id),
                2 => super::ManagementAction::Demote(id),
                3 => super::ManagementAction::Remove(id),
                4 => super::ManagementAction::Leave(id, take(&mut bytes, 64)?.try_into().unwrap()),
                5 => super::ManagementAction::CreateInvitation(
                    id,
                    u64::from_be_bytes(take(&mut bytes, 8)?.try_into().unwrap()),
                    match take(&mut bytes, 1)?[0] {
                        0 => false,
                        1 => true,
                        _ => return Err("invalid invitation mode"),
                    },
                ),
                6 => super::ManagementAction::DisableInvitation(id),
                7 => super::ManagementAction::ApproveInvitation(
                    id,
                    take(&mut bytes, 32)?.try_into().unwrap(),
                ),
                9 => super::ManagementAction::CreateRequestInvitation(
                    id,
                    u64::from_be_bytes(take(&mut bytes, 8)?.try_into().unwrap()),
                ),
                10 => super::ManagementAction::DeclineInvitationRequest(
                    id,
                    take(&mut bytes, 32)?.try_into().unwrap(),
                ),
                _ => super::ManagementAction::CreateAutomaticInvitation(
                    id,
                    u64::from_be_bytes(take(&mut bytes, 8)?.try_into().unwrap()),
                ),
            })
        }
        _ => return Err("unknown membership history action"),
    };
    let commit = read_blob(&mut bytes)?;
    if commit.is_empty() || !bytes.is_empty() {
        return Err("invalid membership record");
    }
    Ok((auth, commit))
}

impl Workspace {
    /// Local secret-bearing records. The storage adapter must atomically commit
    /// the complete change set with associated delivery state before adoption.
    /// No transport, database or host-language representation is selected here.
    pub fn export_records(&self) -> Result<SecurityRecords, &'static str> {
        let mut records = SecurityRecords::new();
        let provider = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| "storage unavailable")?;
        let mut meta = Zeroizing::new(b"DFWR\x02".to_vec());
        meta.extend(self.id);
        meta.extend(self.endpoint);
        meta.extend(self.epoch().to_be_bytes());
        meta.push(u8::from(self.member.is_some()));
        if let Some(member) = &self.member {
            storage::write_profile(&mut meta, member);
        }
        meta.extend((provider.len() as u64).to_be_bytes());
        meta.extend((self.admissions.len() as u64).to_be_bytes());
        meta.push(u8::from(self.join_history.is_some()));
        for (key, value) in provider.iter() {
            records.insert(named(PROVIDER, key), Zeroizing::new(value.clone()));
        }
        for entry in &self.admissions {
            let mut bytes = Zeroizing::new(Vec::new());
            bytes.extend(entry.endpoint);
            bytes.extend(entry.issuer);
            bytes.extend(entry.reply.epoch.to_be_bytes());
            put_auth(&mut bytes, &entry.reply.authorization);
            blob(&mut bytes, &entry.reply.commit)?;
            blob(&mut bytes, &entry.reply.welcome)?;
            if records
                .insert(named(ADMISSION, &entry.digest), bytes)
                .is_some()
            {
                return Err("duplicate retained admission");
            }
        }
        if let Some(history) = &self.join_history {
            meta.extend((history.steps.len() as u64).to_be_bytes());
            records.insert(
                CHECKPOINT.to_vec(),
                Zeroizing::new(history.checkpoint.clone()),
            );
            for (index, (auth, commit)) in history.steps.iter().enumerate() {
                records.insert(
                    named(STEP, &(index as u64).to_be_bytes()),
                    step(auth, commit)?,
                );
            }
        }
        meta.extend((self.invitation_checkpoints.len() as u64).to_be_bytes());
        for saved in &self.invitation_checkpoints {
            let mut value = Zeroizing::new(saved.grant.to_vec());
            value.extend(&saved.checkpoint);
            records.insert(named(INVITATION_CHECKPOINT, &saved.grant[101..133]), value);
        }
        records.insert(META.to_vec(), meta);
        Ok(records)
    }

    /// Restore only authenticated local records from the expected workspace and
    /// endpoint. This is not a decoder for unauthenticated peer-supplied state.
    pub fn restore_records(
        endpoint: [u8; 32],
        id: [u8; 32],
        records: &SecurityRecords,
    ) -> Result<Self, &'static str> {
        let mut meta = records
            .get(META)
            .ok_or("security metadata missing")?
            .as_slice();
        let version = take(&mut meta, 5)?;
        if !matches!(version, b"DFWR\x01" | b"DFWR\x02")
            || take(&mut meta, 32)? != id
            || take(&mut meta, 32)? != endpoint
        {
            return Err("security record scope mismatch");
        }
        let epoch = u64::from_be_bytes(take(&mut meta, 8)?.try_into().unwrap());
        let member = match take(&mut meta, 1)?[0] {
            0 => None,
            1 => Some(storage::read_profile(&mut meta)?),
            _ => return Err("invalid stored profile flag"),
        };
        let provider_count = read_count(&mut meta)?;
        let admission_count = read_count(&mut meta)?;
        let history_count = match take(&mut meta, 1)?[0] {
            0 => None,
            1 => Some(read_count(&mut meta)?),
            _ => return Err("invalid stored history flag"),
        };
        let invitation_checkpoint_count = if version == b"DFWR\x02" {
            read_count(&mut meta)?
        } else {
            0
        };
        if invitation_checkpoint_count > super::invitation::MAX_RETAINED_CHECKPOINTS {
            return Err("invalid invitation checkpoint count");
        }
        let expected = [
            1usize,
            provider_count,
            admission_count,
            usize::from(history_count.is_some()),
            history_count.unwrap_or(0),
            invitation_checkpoint_count,
        ]
        .into_iter()
        .try_fold(0usize, |sum, n| sum.checked_add(n))
        .ok_or("record count overflow")?;
        if expected != records.len() || !meta.is_empty() {
            return Err("security record set incomplete");
        }
        let provider = OpenMlsRustCrypto::default();
        {
            let mut target = provider
                .storage()
                .values
                .write()
                .map_err(|_| "storage unavailable")?;
            for (name, value) in records {
                if let Some(key) = name.strip_prefix(PROVIDER) {
                    target.insert(key.to_vec(), value.to_vec());
                }
            }
            if target.len() != provider_count {
                return Err("provider record set incomplete");
            }
        }
        let mut admissions = Vec::new();
        let mut shared = super::invitation::SharedReplies::default();
        let mut epochs = BTreeMap::new();
        for (name, value) in records {
            let Some(digest) = name.strip_prefix(ADMISSION) else {
                continue;
            };
            let digest = digest
                .try_into()
                .map_err(|_| "invalid admission record key")?;
            let mut bytes = value.as_slice();
            let endpoint = take(&mut bytes, 32)?.try_into().unwrap();
            let issuer = take(&mut bytes, 32)?.try_into().unwrap();
            let admitted_epoch = u64::from_be_bytes(take(&mut bytes, 8)?.try_into().unwrap());
            if admitted_epoch == 0 || admitted_epoch > epoch {
                return Err("invalid admission record epoch");
            }
            let authorization = read_auth(&mut bytes)?;
            let commit = read_blob(&mut bytes)?;
            let welcome = read_blob(&mut bytes)?;
            if !bytes.is_empty() || commit.is_empty() || welcome.is_empty() {
                return Err("invalid admission record");
            }
            if epochs
                .entry(admitted_epoch)
                .or_insert_with(|| commit.clone())
                != &commit
            {
                return Err("admission records disagree on shared epoch commit");
            }
            admissions.push(RetainedAdmission {
                digest,
                endpoint,
                issuer,
                reply: shared.reply(admitted_epoch, commit, welcome, authorization),
            });
        }
        if admissions.len() != admission_count {
            return Err("admission record set incomplete");
        }
        admissions.sort_by_key(|entry| entry.reply.epoch);
        let history = if let Some(count) = history_count {
            let checkpoint = records
                .get(CHECKPOINT)
                .ok_or("history checkpoint missing")?
                .to_vec();
            let mut steps = Vec::new();
            for index in 0..count {
                steps.push(read_step(
                    records
                        .get(&named(STEP, &(index as u64).to_be_bytes()))
                        .ok_or("history record missing")?,
                )?);
            }
            Some(MembershipHistory { checkpoint, steps })
        } else {
            None
        };
        let mut invitation_checkpoints = Vec::new();
        for (name, value) in records {
            let Some(key) = name.strip_prefix(INVITATION_CHECKPOINT) else {
                continue;
            };
            if key.len() != 32 || value.len() <= super::invitation::PUBLIC {
                return Err("invalid invitation checkpoint record");
            }
            let grant: [u8; super::invitation::PUBLIC] =
                value[..super::invitation::PUBLIC].try_into().unwrap();
            if grant[101..133] != *key {
                return Err("invitation checkpoint record key mismatch");
            }
            invitation_checkpoints.push(super::invitation::RetainedInvitationCheckpoint {
                grant,
                checkpoint: value[super::invitation::PUBLIC..].to_vec(),
            });
        }
        if invitation_checkpoints.len() != invitation_checkpoint_count {
            return Err("invitation checkpoint record set incomplete");
        }
        Self::restore_owner(
            provider,
            endpoint,
            id,
            epoch,
            member,
            admissions,
            history,
            invitation_checkpoints,
        )
    }
}
