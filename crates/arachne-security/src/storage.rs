//! Bounded encrypted provider snapshot. Host owns atomic file replacement.
use super::{MemberProfile, SUITE, Workspace, credential_identity};
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{OpenMlsProvider, random::OpenMlsRand};
use zeroize::Zeroizing;

const LEGACY: &[u8; 5] = b"DFWS\x01";
const MAGIC: &[u8; 5] = b"DFWS\x02";
const WITH_HISTORY: &[u8; 5] = b"DFWS\x04";
const WITH_INVITATION_CHECKPOINTS: &[u8; 5] = b"DFWS\x05";
const WITH_ADMISSIONS: &[u8; 5] = b"DFWS\x03";
const HEADER: usize = 5 + 32 + 12;
pub(super) const MAX_PLAIN: usize = 128 * 1024;
const MAX_RECORDS: usize = 256;
pub const MAX_SEALED_WORKSPACE: usize = HEADER + MAX_PLAIN + 16;
const BUNDLE: &[u8; 5] = b"DFWB\x01";
pub const MAX_WORKSPACE_ATTACHMENT: usize = 528 * 1024;
pub const MAX_SEALED_BUNDLE: usize =
    HEADER + 16 + 8 + MAX_SEALED_WORKSPACE + MAX_WORKSPACE_ATTACHMENT;

/// Derived storage key has a distinct cryptographic purpose from endpoint TLS.
/// Root material is supplied by the host's protected credential store.
pub struct StorageKey(Zeroizing<[u8; 32]>);
impl StorageKey {
    pub fn derive(root: &[u8; 32]) -> Result<Self, &'static str> {
        let mut key = Zeroizing::new([0; 32]);
        hkdf::Hkdf::<sha2::Sha256>::new(Some(b"data-fabric/storage/v1"), root)
            .expand(b"workspace-snapshot/aes256gcm", key.as_mut())
            .map_err(|_| "storage key derivation failed")?;
        Ok(Self(key))
    }
}

pub(super) fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Result<&'a [u8], &'static str> {
    let (head, tail) = bytes
        .split_at_checked(count)
        .ok_or("truncated protected state")?;
    *bytes = tail;
    Ok(head)
}
pub(super) fn number(bytes: &mut &[u8]) -> Result<usize, &'static str> {
    Ok(u32::from_be_bytes(take(bytes, 4)?.try_into().unwrap()) as usize)
}
pub(super) fn write_profile(bytes: &mut Vec<u8>, member: &MemberProfile) {
    bytes.extend(member.id);
    bytes.extend((member.display_name.len() as u32).to_be_bytes());
    bytes.extend(member.display_name.as_bytes());
}
pub(super) fn read_profile(bytes: &mut &[u8]) -> Result<MemberProfile, &'static str> {
    let id = take(bytes, 32)?.try_into().unwrap();
    let length = number(bytes)?;
    if length > 256 {
        return Err("member name exceeds bounds");
    }
    let name = std::str::from_utf8(take(bytes, length)?).map_err(|_| "invalid member name")?;
    let profile = MemberProfile::new(id, name)?;
    if profile.display_name() != name {
        return Err("noncanonical member name");
    }
    Ok(profile)
}
pub(super) fn encode_provider(
    provider: &OpenMlsRustCrypto,
    mut prefix: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let state = provider
        .storage()
        .values
        .read()
        .map_err(|_| "storage unavailable")?;
    if state.len() > MAX_RECORDS {
        return Err("protected state exceeds bounds");
    }
    let size = state
        .iter()
        .try_fold(prefix.len() + 4, |total, (k, v)| {
            total
                .checked_add(8)?
                .checked_add(k.len())?
                .checked_add(v.len())
        })
        .ok_or("protected state exceeds bounds")?;
    if size > MAX_PLAIN {
        return Err("protected state exceeds bounds");
    }
    let additional = size - prefix.len();
    prefix.reserve(additional);
    prefix.extend((state.len() as u32).to_be_bytes());
    let mut entries: Vec<_> = state.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    for (k, v) in entries {
        prefix.extend((k.len() as u32).to_be_bytes());
        prefix.extend((v.len() as u32).to_be_bytes());
        prefix.extend(k);
        prefix.extend(v);
    }
    Ok(prefix)
}

/// Copy an in-memory owner without routing it through a legacy file-size budget.
pub(super) fn copy_provider(
    provider: &OpenMlsRustCrypto,
) -> Result<OpenMlsRustCrypto, &'static str> {
    let records = provider
        .storage()
        .values
        .read()
        .map_err(|_| "storage unavailable")?
        .clone();
    let copy = OpenMlsRustCrypto::default();
    *copy
        .storage()
        .values
        .write()
        .map_err(|_| "storage unavailable")? = records;
    Ok(copy)
}
pub(super) fn decode_provider(bytes: &mut &[u8]) -> Result<OpenMlsRustCrypto, &'static str> {
    let count = number(bytes)?;
    if count > MAX_RECORDS {
        return Err("protected state exceeds bounds");
    }
    let provider = OpenMlsRustCrypto::default();
    {
        let mut state = provider
            .storage()
            .values
            .write()
            .map_err(|_| "storage unavailable")?;
        for _ in 0..count {
            let klen = number(bytes)?;
            let vlen = number(bytes)?;
            let k = take(bytes, klen)?.to_vec();
            let v = take(bytes, vlen)?.to_vec();
            if state.insert(k, v).is_some() {
                return Err("duplicate protected record");
            }
        }
    }
    if !bytes.is_empty() {
        return Err("trailing protected state");
    }
    Ok(provider)
}
impl StorageKey {
    pub(super) fn protect(
        &self,
        provider: &OpenMlsRustCrypto,
        magic: &[u8; 5],
        id: [u8; 32],
        endpoint: [u8; 32],
        plain: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if plain.len() > MAX_PLAIN {
            return Err("protected state exceeds bounds");
        }
        self.protect_record(provider, magic, id, endpoint, plain)
    }
    // Callers enforce their record-family bounds before encrypting.
    fn protect_record(
        &self,
        provider: &OpenMlsRustCrypto,
        magic: &[u8; 5],
        id: [u8; 32],
        endpoint: [u8; 32],
        plain: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        let nonce = provider
            .rand()
            .random_array::<12>()
            .map_err(|_| "snapshot randomness failed")?;
        let mut result = magic.to_vec();
        result.extend(id);
        result.extend(nonce);
        let mut aad = result.clone();
        aad.extend(endpoint);
        let cipher =
            Aes256Gcm::new_from_slice(self.0.as_ref()).map_err(|_| "invalid storage key")?;
        let encrypted = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plain,
                    aad: &aad,
                },
            )
            .map_err(|_| "snapshot protection failed")?;
        result.extend(encrypted);
        Ok(result)
    }
    pub(super) fn unprotect(
        &self,
        magic: &[u8; 5],
        id: [u8; 32],
        endpoint: [u8; 32],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        self.unprotect_record(magic, id, endpoint, sealed, MAX_SEALED_WORKSPACE)
    }
    fn unprotect_record(
        &self,
        magic: &[u8; 5],
        id: [u8; 32],
        endpoint: [u8; 32],
        sealed: &[u8],
        max_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        if sealed.len() < HEADER + 16
            || sealed.len() > max_bytes
            || !sealed.starts_with(magic)
            || sealed[5..37] != id
        {
            return Err("invalid protected snapshot");
        }
        let mut aad = sealed[..HEADER].to_vec();
        aad.extend(endpoint);
        let nonce: &[u8; 12] = sealed[37..HEADER].try_into().unwrap();
        let cipher =
            Aes256Gcm::new_from_slice(self.0.as_ref()).map_err(|_| "invalid storage key")?;
        Ok(Zeroizing::new(
            cipher
                .decrypt(
                    nonce.into(),
                    Payload {
                        msg: &sealed[HEADER..],
                        aad: &aad,
                    },
                )
                .map_err(|_| "snapshot authentication failed")?,
        ))
    }
}
impl Workspace {
    /// One authenticated host record for security state and opaque local state.
    /// Host must atomically replace it before adopting state or releasing packets.
    /// This binds the bytes together; it does not validate the attachment's meaning
    /// or prevent rollback to an older authentic record.
    pub fn seal_with_attachment(
        &self,
        key: &StorageKey,
        attachment: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if attachment.len() > MAX_WORKSPACE_ATTACHMENT {
            return Err("workspace attachment exceeds bounds");
        }
        let security = self.seal(key)?;
        let mut plain = Zeroizing::new(Vec::with_capacity(8 + security.len() + attachment.len()));
        plain.extend((security.len() as u32).to_be_bytes());
        plain.extend(security);
        plain.extend((attachment.len() as u32).to_be_bytes());
        plain.extend(attachment);
        key.protect_record(&self.provider, BUNDLE, self.id, self.endpoint, &plain)
    }

    /// Authenticate the whole record before exposing either component. The caller
    /// must validate the attachment against the restored owner before adoption.
    pub fn restore_with_attachment(
        key: &StorageKey,
        endpoint: [u8; 32],
        id: [u8; 32],
        sealed: &[u8],
    ) -> Result<(Self, Zeroizing<Vec<u8>>), &'static str> {
        let plain = key.unprotect_record(BUNDLE, id, endpoint, sealed, MAX_SEALED_BUNDLE)?;
        let mut bytes = plain.as_slice();
        let length = number(&mut bytes)?;
        if length > MAX_SEALED_WORKSPACE {
            return Err("bundled security state exceeds bounds");
        }
        let security = take(&mut bytes, length)?;
        let length = number(&mut bytes)?;
        if length > MAX_WORKSPACE_ATTACHMENT || bytes.len() != length {
            return Err("invalid workspace attachment length");
        }
        let workspace = Self::restore(key, endpoint, id, security)?;
        Ok((workspace, Zeroizing::new(bytes.to_vec())))
    }

    pub fn seal(&self, key: &StorageKey) -> Result<Vec<u8>, &'static str> {
        let mut prefix = Zeroizing::new(self.epoch().to_be_bytes().to_vec());
        if let Some(member) = &self.member {
            write_profile(&mut prefix, member);
        }
        if !self.invitation_checkpoints.is_empty() {
            prefix.push(u8::from(self.join_history.is_some()));
        }
        if let Some(history) = &self.join_history {
            let history = history.inline(self.id)?;
            if history.len() > MAX_PLAIN {
                return Err("join history exceeds snapshot bounds");
            }
            prefix.extend((history.len() as u32).to_be_bytes());
            prefix.extend(&history);
        }
        if !self.admissions.is_empty()
            || self.join_history.is_some()
            || !self.invitation_checkpoints.is_empty()
        {
            if self.member.is_none() || self.admissions.len() > super::invitation::MAX_ADMISSIONS {
                return Err("invalid admission retention");
            }
            prefix.extend((self.admissions.len() as u32).to_be_bytes());
            for entry in &self.admissions {
                prefix.extend(entry.digest);
                prefix.extend(entry.endpoint);
                prefix.extend(entry.issuer);
                prefix.extend(entry.reply.epoch.to_be_bytes());
                prefix.extend(entry.reply.authorization.invitation_key);
                prefix.extend(entry.reply.authorization.grant_signature);
                prefix.extend(entry.reply.authorization.redemption_signature);
                for value in [&entry.reply.commit, &entry.reply.welcome] {
                    if value.is_empty() || value.len() > MAX_PLAIN {
                        return Err("admission response exceeds bounds");
                    }
                    prefix.extend((value.len() as u32).to_be_bytes());
                    prefix.extend_from_slice(value);
                }
            }
        }
        if !self.invitation_checkpoints.is_empty() {
            prefix.extend((self.invitation_checkpoints.len() as u32).to_be_bytes());
            for saved in &self.invitation_checkpoints {
                prefix.extend(saved.grant);
                prefix.extend((saved.checkpoint.len() as u32).to_be_bytes());
                prefix.extend(&saved.checkpoint);
            }
        }
        let plain = encode_provider(&self.provider, prefix)?;
        key.protect(
            &self.provider,
            if !self.invitation_checkpoints.is_empty() {
                WITH_INVITATION_CHECKPOINTS
            } else if self.join_history.is_some() {
                WITH_HISTORY
            } else if !self.admissions.is_empty() {
                WITH_ADMISSIONS
            } else if self.member.is_some() {
                MAGIC
            } else {
                LEGACY
            },
            self.id,
            self.endpoint,
            &plain,
        )
    }
    pub fn restore(
        key: &StorageKey,
        endpoint: [u8; 32],
        id: [u8; 32],
        sealed: &[u8],
    ) -> Result<Self, &'static str> {
        let magic = if sealed.starts_with(LEGACY) {
            LEGACY
        } else if sealed.starts_with(WITH_INVITATION_CHECKPOINTS) {
            WITH_INVITATION_CHECKPOINTS
        } else if sealed.starts_with(WITH_HISTORY) {
            WITH_HISTORY
        } else if sealed.starts_with(WITH_ADMISSIONS) {
            WITH_ADMISSIONS
        } else {
            MAGIC
        };
        let plain = key.unprotect(magic, id, endpoint, sealed)?;
        let mut bytes = plain.as_slice();
        let epoch = u64::from_be_bytes(take(&mut bytes, 8)?.try_into().unwrap());
        let member = if magic != LEGACY {
            Some(read_profile(&mut bytes)?)
        } else {
            None
        };
        let has_history = if magic == WITH_INVITATION_CHECKPOINTS {
            match take(&mut bytes, 1)?[0] {
                0 => false,
                1 => true,
                _ => return Err("invalid stored history flag"),
            }
        } else {
            magic == WITH_HISTORY
        };
        let join_history = if has_history {
            let length = number(&mut bytes)?;
            Some(super::history::MembershipHistory::from_inline(take(
                &mut bytes, length,
            )?)?)
        } else {
            None
        };
        let mut admissions = Vec::new();
        let mut shared = super::invitation::SharedReplies::default();
        if magic == WITH_ADMISSIONS || magic == WITH_HISTORY || magic == WITH_INVITATION_CHECKPOINTS
        {
            let count = number(&mut bytes)?;
            if (count == 0 && magic == WITH_ADMISSIONS) || count > super::invitation::MAX_ADMISSIONS
            {
                return Err("invalid admission retention count");
            }
            let mut digests = std::collections::BTreeSet::new();
            let mut prior_epoch = 0;
            for _ in 0..count {
                let digest = take(&mut bytes, 32)?.try_into().unwrap();
                let remote = take(&mut bytes, 32)?.try_into().unwrap();
                let issuer = take(&mut bytes, 32)?.try_into().unwrap();
                let admitted_epoch = u64::from_be_bytes(take(&mut bytes, 8)?.try_into().unwrap());
                if !digests.insert(digest)
                    || admitted_epoch <= prior_epoch
                    || admitted_epoch > epoch
                {
                    return Err("invalid admission history");
                }
                prior_epoch = admitted_epoch;
                let authorization = super::AdmissionAuthorization {
                    invitation_key: take(&mut bytes, 32)?.try_into().unwrap(),
                    grant_signature: take(&mut bytes, 64)?.try_into().unwrap(),
                    redemption_signature: take(&mut bytes, 64)?.try_into().unwrap(),
                };
                let mut read_blob = || -> Result<Vec<u8>, &'static str> {
                    let length = number(&mut bytes)?;
                    if length == 0 || length > MAX_PLAIN {
                        return Err("admission response exceeds bounds");
                    }
                    Ok(take(&mut bytes, length)?.to_vec())
                };
                let commit = read_blob()?;
                let welcome = read_blob()?;
                admissions.push(super::invitation::RetainedAdmission {
                    digest,
                    endpoint: remote,
                    issuer,
                    reply: shared.reply(admitted_epoch, commit, welcome, authorization),
                });
            }
        }
        let mut invitation_checkpoints = Vec::new();
        if magic == WITH_INVITATION_CHECKPOINTS {
            let count = number(&mut bytes)?;
            if count == 0 || count > super::invitation::MAX_RETAINED_CHECKPOINTS {
                return Err("invalid invitation checkpoint count");
            }
            for _ in 0..count {
                let grant = take(&mut bytes, super::invitation::PUBLIC)?
                    .try_into()
                    .unwrap();
                let length = number(&mut bytes)?;
                if length == 0 || length > 64 * 1024 {
                    return Err("invalid retained invitation checkpoint");
                }
                invitation_checkpoints.push(super::invitation::RetainedInvitationCheckpoint {
                    grant,
                    checkpoint: take(&mut bytes, length)?.to_vec(),
                });
            }
        }
        let provider = decode_provider(&mut bytes)?;
        Self::restore_owner(
            provider,
            endpoint,
            id,
            epoch,
            member,
            admissions,
            join_history,
            invitation_checkpoints,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn restore_owner(
        provider: OpenMlsRustCrypto,
        endpoint: [u8; 32],
        id: [u8; 32],
        epoch: u64,
        member: Option<MemberProfile>,
        admissions: Vec<super::invitation::RetainedAdmission>,
        join_history: Option<super::history::MembershipHistory>,
        invitation_checkpoints: Vec<super::invitation::RetainedInvitationCheckpoint>,
    ) -> Result<Self, &'static str> {
        let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&id))
            .map_err(|_| "invalid stored group")?
            .ok_or("missing stored group")?;
        if group.group_id().as_slice() != id
            || group.epoch().as_u64() != epoch
            || group.ciphersuite() != SUITE
            || !group.is_active()
            || group.pending_commit().is_some()
        {
            return Err("workspace state mismatch");
        }
        let own = group
            .members()
            .find(|m| m.index == group.own_leaf_index())
            .ok_or("missing own credential")?;
        let credential = BasicCredential::try_from(own.credential.clone())
            .map_err(|_| "invalid own credential")?;
        if credential.identity() != credential_identity(endpoint, member.as_ref()) {
            return Err("workspace endpoint mismatch");
        }
        let signer = SignatureKeyPair::read(
            provider.storage(),
            &own.signature_key,
            SUITE.signature_algorithm(),
        )
        .ok_or("missing workspace signer")?;
        let workspace = Self {
            provider,
            _signer: signer,
            group,
            id,
            endpoint,
            member,
            admissions,
            join_history,
            invitation_checkpoints,
        };
        if let Some(history) = &workspace.join_history {
            history.verify(&workspace)?;
        }
        workspace.verify_retained_invitation_checkpoints()?;
        workspace.object_counter()?;
        workspace.name_state()?;
        Ok(workspace)
    }
}

#[test]
fn protected_snapshot_restores_and_rejects_wrong_context() {
    let key = StorageKey::derive(&[7; 32]).unwrap();
    let workspace = Workspace::create([1; 32], "Alex Morgan").unwrap();
    let id = workspace.id();
    let profile = workspace.member().unwrap().clone();
    let sealed = workspace.seal(&key).unwrap();
    assert_ne!(sealed, workspace.seal(&key).unwrap());
    drop(workspace);
    let mut restored = Workspace::restore(&key, [1; 32], id, &sealed).unwrap();
    assert_eq!(restored.id(), id);
    assert_eq!(restored.member(), Some(&profile));
    assert_eq!(restored.epoch(), 0);
    assert_eq!(restored.member_count(), 1);
    restored
        .group
        .create_message(&restored.provider, &restored._signer, b"after restore")
        .unwrap();
    let sealed_again = restored.seal(&key).unwrap();
    assert!(Workspace::restore(&key, [1; 32], id, &sealed_again).is_ok());
    assert!(
        Workspace::restore(&StorageKey::derive(&[8; 32]).unwrap(), [1; 32], id, &sealed).is_err()
    );
    assert!(Workspace::restore(&key, [2; 32], id, &sealed).is_err());
    assert!(Workspace::restore(&key, [1; 32], [9; 32], &sealed).is_err());
    for index in [0, 5, 37, HEADER, sealed.len() - 1] {
        let mut bad = sealed.clone();
        bad[index] ^= 1;
        assert!(Workspace::restore(&key, [1; 32], id, &bad).is_err());
    }
    assert!(Workspace::restore(&key, [1; 32], id, &sealed[..sealed.len() - 1]).is_err());
    let mut trailing = sealed.clone();
    trailing.push(0);
    assert!(Workspace::restore(&key, [1; 32], id, &trailing).is_err());
    assert!(Workspace::restore(&key, [1; 32], id, &vec![0; MAX_SEALED_WORKSPACE + 1]).is_err());
}

#[test]
fn legacy_snapshot_keeps_credential_and_has_no_invented_profile() {
    let provider = OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap();
    signer.store(provider.storage()).unwrap();
    let id = [4; 32];
    let endpoint = [5; 32];
    let credential = CredentialWithKey {
        credential: BasicCredential::new(credential_identity(endpoint, None)).into(),
        signature_key: signer.to_public_vec().into(),
    };
    let group = MlsGroup::new_with_group_id(
        &provider,
        &signer,
        &MlsGroupCreateConfig::builder().ciphersuite(SUITE).build(),
        GroupId::from_slice(&id),
        credential,
    )
    .unwrap();
    let workspace = Workspace {
        provider,
        _signer: signer,
        group,
        id,
        endpoint,
        member: None,
        admissions: Vec::new(),
        join_history: None,
        invitation_checkpoints: Vec::new(),
    };
    let key = StorageKey::derive(&[6; 32]).unwrap();
    let sealed = workspace.seal(&key).unwrap();
    assert!(sealed.starts_with(LEGACY));
    let restored = Workspace::restore(&key, endpoint, id, &sealed).unwrap();
    assert_eq!(restored.member(), None);
    assert_eq!(restored._signer.public(), workspace._signer.public());
    assert!(restored.seal(&key).unwrap().starts_with(LEGACY));
}

#[test]
fn profile_must_match_the_stored_mls_credential() {
    let key = StorageKey::derive(&[7; 32]).unwrap();
    let mut workspace = Workspace::create([1; 32], "Alex").unwrap();
    workspace.member.as_mut().unwrap().id = [99; 32];
    // Even a correctly encrypted snapshot cannot substitute a different member
    // ID for the ID bound into the stored MLS credential.
    let sealed = workspace.seal(&key).unwrap();
    assert!(Workspace::restore(&key, [1; 32], workspace.id(), &sealed).is_err());
}

#[test]
fn combined_record_authenticates_both_parts_and_preserves_legacy_bounds() {
    let key = StorageKey::derive(&[7; 32]).unwrap();
    let owner = Workspace::create([1; 32], "Alex").unwrap();
    let id = owner.id();
    let attachment = vec![42; MAX_WORKSPACE_ATTACHMENT];
    let sealed = owner.seal_with_attachment(&key, &attachment).unwrap();
    assert!(sealed.len() <= MAX_SEALED_BUNDLE);
    assert!(sealed.len() > MAX_SEALED_WORKSPACE);
    let (restored, actual) =
        Workspace::restore_with_attachment(&key, [1; 32], id, &sealed).unwrap();
    assert_eq!(restored.member(), owner.member());
    assert_eq!(actual.as_slice(), attachment);
    assert!(Workspace::restore(&key, [1; 32], id, &sealed).is_err());
    assert!(Workspace::restore_with_attachment(&key, [2; 32], id, &sealed).is_err());
    assert!(Workspace::restore_with_attachment(&key, [1; 32], [9; 32], &sealed).is_err());
    assert!(
        Workspace::restore_with_attachment(
            &StorageKey::derive(&[8; 32]).unwrap(),
            [1; 32],
            id,
            &sealed
        )
        .is_err()
    );
    for offset in [0, 5, 37, HEADER, sealed.len() - 1] {
        let mut bad = sealed.clone();
        bad[offset] ^= 1;
        assert!(Workspace::restore_with_attachment(&key, [1; 32], id, &bad).is_err());
    }
    assert!(
        Workspace::restore_with_attachment(&key, [1; 32], id, &sealed[..sealed.len() - 1]).is_err()
    );
    let mut trailing = sealed.clone();
    trailing.push(0);
    assert!(Workspace::restore_with_attachment(&key, [1; 32], id, &trailing).is_err());
    assert!(
        owner
            .seal_with_attachment(&key, &vec![0; MAX_WORKSPACE_ATTACHMENT + 1])
            .is_err()
    );
    assert!(
        Workspace::restore_with_attachment(&key, [1; 32], id, &vec![0; MAX_SEALED_BUNDLE + 1])
            .is_err()
    );
    let legacy = owner.seal(&key).unwrap();
    assert!(Workspace::restore(&key, [1; 32], id, &legacy).is_ok());
    assert!(Workspace::restore_with_attachment(&key, [1; 32], id, &legacy).is_err());
    // Valid encryption does not make malformed inner framing acceptable.
    for (security, length, tail) in [
        (legacy.as_slice(), 2u32, vec![1]),
        (legacy.as_slice(), 0, vec![1]),
        (
            legacy.as_slice(),
            (MAX_WORKSPACE_ATTACHMENT + 1) as u32,
            vec![],
        ),
        (&[][..], 0, vec![]),
    ] {
        let mut plain = (security.len() as u32).to_be_bytes().to_vec();
        plain.extend(security);
        plain.extend(length.to_be_bytes());
        plain.extend(tail);
        let bad = key
            .protect_record(&owner.provider, BUNDLE, id, [1; 32], &plain)
            .unwrap();
        assert!(Workspace::restore_with_attachment(&key, [1; 32], id, &bad).is_err());
    }
}

/// Explicit capacity gate: diagnostics report sizes only, never keys or payloads.
#[test]
fn twelve_member_snapshot_capacity() {
    let key = StorageKey::derive(&[201; 32]).unwrap();
    let mut owner = Workspace::create([200; 32], "Capacity publisher").unwrap();
    for member in 1..12u8 {
        let (invite, checkpoint) = owner.issue_invitation().unwrap();
        let pending = super::PendingJoin::from_invitation(
            &invite,
            &checkpoint,
            [member; 32],
            "Capacity member",
        )
        .unwrap();
        let next = owner
            .prepare_admission([member; 32], pending.admission_request().unwrap())
            .unwrap()
            .workspace;
        let state = next.provider.storage().values.read().unwrap();
        let provider_bytes: usize = 4 + state
            .iter()
            .map(|(k, v)| 8 + k.len() + v.len())
            .sum::<usize>();
        let reply_bytes: usize = next
            .admissions
            .iter()
            .map(|a| 96 + 8 + 32 + 64 + 64 + 8 + a.reply.commit.len() + a.reply.welcome.len())
            .sum();
        let history_bytes = next
            .join_history
            .as_ref()
            .map_or(0, |h| 4 + h.inline(next.id()).unwrap().len());
        println!(
            "members={} provider_records={} provider_bytes={} retained_reply_bytes={} history_bytes={} snapshot_limit={}",
            next.member_count(),
            state.len(),
            provider_bytes,
            reply_bytes,
            history_bytes,
            MAX_PLAIN
        );
        drop(state);
        let sealed = next.seal(&key).expect("12-member durable snapshot gate");
        owner = Workspace::restore(&key, [200; 32], next.id(), &sealed).unwrap();
    }
    assert_eq!(owner.member_count(), 12);
}
