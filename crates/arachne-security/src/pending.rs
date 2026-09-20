//! A recoverable join request. No membership is implied by owning this state.
use super::{
    AUTHORITY, JoinProof, MemberProfile, SUITE, StorageKey, Workspace, credential_identity, storage,
};
use openmls::prelude::{
    tls_codec::{Deserialize, Serialize},
    *,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{OpenMlsProvider, random::OpenMlsRand, storage::StorageProvider};
use zeroize::Zeroizing;

const LEGACY: &[u8; 5] = b"DFPJ\x01";
const MAGIC: &[u8; 5] = b"DFPJ\x02";
const MAX_PACKAGE: usize = 16 * 1024;
pub const MAX_WELCOME: usize = 64 * 1024;

pub struct PendingJoin {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    member: MemberProfile,
    endpoint: [u8; 32],
    workspace: [u8; 32],
    checkpoint_digest: [u8; 32],
    package: KeyPackage,
    request: Option<Vec<u8>>,
    checkpoint: Option<Vec<u8>>,
    invitation: Option<Zeroizing<Vec<u8>>>,
}
impl PendingJoin {
    /// Workspace and checkpoint digest must come from the trusted invitation.
    /// Persist this owner before transmitting its KeyPackage/redemption request.
    pub(crate) fn new(
        workspace: [u8; 32],
        checkpoint_digest: [u8; 32],
        endpoint: [u8; 32],
        display_name: &str,
    ) -> Result<Self, &'static str> {
        if workspace == [0; 32] || checkpoint_digest == [0; 32] || endpoint == [0; 32] {
            return Err("invalid join context");
        }
        let provider = OpenMlsRustCrypto::default();
        let member = MemberProfile::new(
            provider
                .rand()
                .random_array::<32>()
                .map_err(|_| "member randomness failed")?,
            display_name,
        )?;
        let signer = SignatureKeyPair::new(SUITE.signature_algorithm())
            .map_err(|_| "credential creation failed")?;
        signer
            .store(provider.storage())
            .map_err(|_| "credential storage failed")?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(credential_identity(endpoint, Some(&member))).into(),
            signature_key: signer.to_public_vec().into(),
        };
        let package = KeyPackage::builder()
            .leaf_node_capabilities(Capabilities::new(
                None,
                None,
                Some(&[ExtensionType::Unknown(AUTHORITY)]),
                None,
                None,
            ))
            .build(SUITE, &provider, &signer, credential)
            .map_err(|_| "KeyPackage creation failed")?
            .key_package()
            .clone();
        Ok(Self {
            provider,
            signer,
            member,
            endpoint,
            workspace,
            checkpoint_digest,
            package,
            request: None,
            checkpoint: None,
            invitation: None,
        })
    }

    /// Start from a compact bearer before an authorized member has supplied
    /// the checkpoint. The bearer stays inside the encrypted pending record;
    /// callers receive only the public pending metadata.
    pub fn from_compact_invitation(
        invitation: &super::Invitation,
        endpoint: [u8; 32],
        display_name: &str,
    ) -> Result<Self, &'static str> {
        let mut pending = Self::new(invitation.workspace_id(), invitation.checkpoint_digest(), endpoint, display_name)?;
        pending.invitation = Some(invitation.export_secret_token());
        Ok(pending)
    }
    pub fn from_invitation(
        invitation: &super::Invitation,
        checkpoint: &[u8],
        endpoint: [u8; 32],
        display_name: &str,
    ) -> Result<Self, &'static str> {
        invitation.join_proof(checkpoint)?;
        let mut pending = Self::new(
            invitation.workspace_id(),
            invitation.checkpoint_digest(),
            endpoint,
            display_name,
        )?;
        pending.request = Some(invitation.request(&pending.package)?);
        pending.checkpoint = Some(checkpoint.to_vec());
        Ok(pending)
    }

    pub fn deferred_invitation(&self) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        self.invitation
            .clone()
            .ok_or("pending join has no deferred invitation")
    }

    /// Complete a compact pending join after Rust has authenticated a
    /// checkpoint, preserving the same member identity and KeyPackage.
    pub fn complete_checkpoint(&mut self, checkpoint: &[u8]) -> Result<(), &'static str> {
        if self.request.is_some() || self.checkpoint.is_some() {
            return Err("pending join already has a checkpoint");
        }
        let token = self
            .invitation
            .as_deref()
            .ok_or("pending join has no deferred invitation")?;
        let invitation = super::Invitation::from_bytes(token)?;
        invitation.join_proof(checkpoint)?;
        self.request = Some(invitation.request(&self.package)?);
        self.checkpoint = Some(checkpoint.to_vec());
        self.invitation = None;
        Ok(())
    }
    pub fn personal_invitation(&self) -> Result<bool, &'static str> {
        let request = super::invitation::decode_request(&self.provider, self.admission_request()?)?;
        Ok(self
            .join_proof()?
            .invitation_control(request.authorization.invitation_key)?
            .is_some_and(|c| c.personal))
    }

    pub fn join_proof(&self) -> Result<JoinProof, &'static str> {
        JoinProof::from_trusted_checkpoint(
            self.workspace,
            self.checkpoint_digest,
            self.checkpoint
                .as_deref()
                .ok_or("pending join has no saved checkpoint")?,
        )
    }
    pub fn workspace_name(&self) -> Result<Option<String>, &'static str> {
        if self.checkpoint.is_none() {
            return Ok(None);
        }
        self.join_proof()?.workspace_name()
    }
    pub fn admission_request(&self) -> Result<&[u8], &'static str> {
        self.request
            .as_deref()
            .ok_or("pending join has no saved invitation authorization")
    }
    /// Public checkpoint pinned by the saved invitation; contains roster metadata.
    /// Send only as part of this authorized admission attempt.
    pub fn admission_checkpoint(&self) -> Result<&[u8], &'static str> {
        self.checkpoint
            .as_deref()
            .ok_or("pending join has no saved checkpoint")
    }
    pub fn workspace_id(&self) -> [u8; 32] {
        self.workspace
    }
    pub fn member(&self) -> &MemberProfile {
        &self.member
    }
    pub fn key_package(&self) -> Result<Vec<u8>, &'static str> {
        let bytes = self
            .package
            .tls_serialize_detached()
            .map_err(|_| "KeyPackage encoding failed")?;
        if bytes.len() > MAX_PACKAGE {
            return Err("KeyPackage exceeds bounds");
        }
        Ok(bytes)
    }
    pub fn seal(&self, key: &StorageKey) -> Result<Vec<u8>, &'static str> {
        let mut prefix = Zeroizing::new(self.checkpoint_digest.to_vec());
        if let Some(request) = &self.request {
            prefix.extend((request.len() as u32).to_be_bytes());
            prefix.extend(request);
            let checkpoint = self
                .checkpoint
                .as_ref()
                .ok_or("pending join has no saved checkpoint")?;
            prefix.extend((checkpoint.len() as u32).to_be_bytes());
            prefix.extend(checkpoint);
        } else if let Some(invitation) = &self.invitation {
            prefix.extend((invitation.len() as u32).to_be_bytes());
            prefix.extend(invitation.as_slice());
        } else {
            prefix.extend(0u32.to_be_bytes());
        }
        storage::write_profile(&mut prefix, &self.member);
        let package = self.key_package()?;
        prefix.extend((package.len() as u32).to_be_bytes());
        prefix.extend(package);
        let plain = storage::encode_provider(&self.provider, prefix)?;
        key.protect(
            &self.provider,
            if self.request.is_some() {
                MAGIC
            } else {
                LEGACY
            },
            self.workspace,
            self.endpoint,
            &plain,
        )
    }
    pub fn restore(
        key: &StorageKey,
        endpoint: [u8; 32],
        workspace: [u8; 32],
        sealed: &[u8],
    ) -> Result<Self, &'static str> {
        let magic = if sealed.starts_with(LEGACY) {
            LEGACY
        } else {
            MAGIC
        };
        let plain = key.unprotect(magic, workspace, endpoint, sealed)?;
        let mut bytes = plain.as_slice();
        let checkpoint_digest = storage::take(&mut bytes, 32)?.try_into().unwrap();
        let request = if magic == MAGIC {
            let length = storage::number(&mut bytes)?;
            if length > super::invitation::MAX_REQUEST {
                return Err("saved request exceeds bounds");
            }
            Some(storage::take(&mut bytes, length)?.to_vec())
        } else {
            None
        };
        let checkpoint = if magic == MAGIC {
            let length = storage::number(&mut bytes)?;
            if length > MAX_WELCOME {
                return Err("saved checkpoint exceeds bounds");
            }
            Some(storage::take(&mut bytes, length)?.to_vec())
        } else {
            None
        };
        let invitation = if magic == LEGACY {
            let length = storage::number(&mut bytes)?;
            if length > super::invitation::TOKEN_SIZE {
                return Err("saved invitation exceeds bounds");
            }
            if length == 0 {
                None
            } else {
                Some(Zeroizing::new(storage::take(&mut bytes, length)?.to_vec()))
            }
        } else {
            None
        };
        if let Some(token) = &invitation {
            let parsed = super::Invitation::from_bytes(token)?;
            if parsed.workspace_id() != workspace
                || parsed.checkpoint_digest() != checkpoint_digest
            {
                return Err("saved invitation does not match pending identity");
            }
        }
        let member = storage::read_profile(&mut bytes)?;
        let length = storage::number(&mut bytes)?;
        if length > MAX_PACKAGE {
            return Err("KeyPackage exceeds bounds");
        }
        let package = KeyPackageIn::tls_deserialize_exact(storage::take(&mut bytes, length)?)
            .map_err(|_| "invalid stored KeyPackage")?;
        let provider = storage::decode_provider(&mut bytes)?;
        let package = package
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|_| "stored KeyPackage invalid or expired")?;
        let credential = BasicCredential::try_from(package.leaf_node().credential().clone())
            .map_err(|_| "invalid join credential")?;
        if package.ciphersuite() != SUITE
            || credential.identity() != credential_identity(endpoint, Some(&member))
        {
            return Err("join identity mismatch");
        }
        let bundle: KeyPackageBundle = provider
            .storage()
            .key_package(
                &package
                    .hash_ref(provider.crypto())
                    .map_err(|_| "invalid KeyPackage reference")?,
            )
            .map_err(|_| "KeyPackage storage unavailable")?
            .ok_or("missing private KeyPackage")?;
        if bundle.key_package() != &package {
            return Err("stored KeyPackage mismatch");
        }
        if let Some(request) = &request {
            let decoded = super::invitation::decode_request(&provider, request)?;
            if decoded.workspace != workspace
                || decoded.checkpoint_digest != checkpoint_digest
                || decoded.package != package
            {
                return Err("saved request does not match pending identity");
            }
            let proof = JoinProof::from_trusted_checkpoint(
                workspace,
                checkpoint_digest,
                checkpoint.as_deref().ok_or("missing saved checkpoint")?,
            )?;
            if !proof.authorizes_issuer(&decoded.issuer)? {
                return Err("saved invitation issuer is not a checkpoint administrator");
            }
        }
        let signer = SignatureKeyPair::read(
            provider.storage(),
            package.leaf_node().signature_key().as_slice(),
            SUITE.signature_algorithm(),
        )
        .ok_or("missing join signer")?;
        Ok(Self {
            provider,
            signer,
            member,
            endpoint,
            workspace,
            checkpoint_digest,
            package,
            request,
            checkpoint,
            invitation,
        })
    }
    /// Prepare a joined owner only after MLS validation and authorized branch
    /// matching. This leaves pending state intact even when OpenMLS consumes a
    /// KeyPackage while rejecting a Welcome. The host must atomically save the
    /// returned workspace before retiring pending state or reporting success.
    /// The host's credential lock must prevent concurrent active owners.
    pub fn prepare_workspace(
        &self,
        proof: &JoinProof,
        welcome: &[u8],
    ) -> Result<Workspace, &'static str> {
        if proof.checkpoint_digest != self.checkpoint_digest {
            return Err("join proof belongs to another invitation");
        }
        if welcome.len() > MAX_WELCOME {
            return Err("Welcome exceeds bounds");
        }
        let message =
            MlsMessageIn::tls_deserialize_exact(welcome).map_err(|_| "invalid Welcome encoding")?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err("expected Welcome");
        };
        let provider = storage::copy_provider(&self.provider)?;
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(false)
            .build();
        let group = StagedWelcome::new_from_welcome(
            &provider,
            &config,
            welcome,
            Some(proof.export_ratchet_tree().into()),
        )
            .map_err(|_| "Welcome validation failed")?
            .into_group(&provider)
            .map_err(|_| "Welcome group creation failed")?;
        if group.group_id().as_slice() != self.workspace || group.ciphersuite() != SUITE {
            return Err("Welcome belongs to another workspace");
        }
        let own = group
            .members()
            .find(|m| m.index == group.own_leaf_index())
            .ok_or("missing admitted identity")?;
        if own.signature_key != self.signer.public()
            || own.credential != *self.package.leaf_node().credential()
        {
            return Err("Welcome changed join identity");
        }
        let signer = SignatureKeyPair::read(
            provider.storage(),
            self.signer.public(),
            SUITE.signature_algorithm(),
        )
        .ok_or("missing join signer")?;
        let workspace = Workspace {
            provider,
            _signer: signer,
            group,
            id: self.workspace,
            endpoint: self.endpoint,
            member: Some(self.member.clone()),
            admissions: Vec::new(),
            join_history: Some(super::history::MembershipHistory::from_inline(
                proof.history(),
            )?),
            invitation_checkpoints: Vec::new(),
        };
        if !proof.matches_workspace(&workspace)? {
            return Err("Welcome does not match authorized branch");
        }
        workspace.initialize_name_checkpoint(&proof.name_checkpoint)?;
        Ok(workspace)
    }
}

#[test]
fn compact_pending_invitation_survives_restart_and_becomes_admission_ready() {
    let admin = Workspace::create([4; 32], "Coordinator").unwrap();
    let (invitation, checkpoint) = admin.issue_invitation().unwrap();
    let pending = PendingJoin::from_compact_invitation(&invitation, [5; 32], "Field helper").unwrap();
    let member = pending.member().clone();
    let key = StorageKey::derive(&[6; 32]).unwrap();
    let sealed = pending.seal(&key).unwrap();
    assert!(sealed.starts_with(LEGACY));
    drop(pending);

    let mut restored = PendingJoin::restore(&key, [5; 32], admin.id(), &sealed).unwrap();
    assert_eq!(restored.member(), &member);
    assert_eq!(restored.deferred_invitation().unwrap().as_slice(), invitation.export_secret_token().as_slice());
    assert!(restored.admission_request().is_err());
    restored.complete_checkpoint(&checkpoint).unwrap();
    assert!(!restored.admission_request().unwrap().is_empty());
    assert!(restored.deferred_invitation().is_err());
}

#[test]
fn pending_identity_recovers_and_rejected_welcome_does_not_consume_it() {
    use super::bootstrap::{grant, redemption};
    use super::{AdmissionAuthorization, MAX_SEALED_WORKSPACE};
    use openmls_traits::signatures::Signer;
    use sha2::{Digest, Sha256};
    let mut admin = Workspace::create([1; 32], "Coordinator").unwrap();
    let checkpoint = admin.join_checkpoint().unwrap();
    let digest = Sha256::digest(&checkpoint).into();
    let mut proof = JoinProof::from_trusted_checkpoint(admin.id(), digest, &checkpoint).unwrap();
    let pending = PendingJoin::new(admin.id(), digest, [2; 32], "Jordan Lee").unwrap();
    let member = pending.member().clone();
    let package = pending.key_package().unwrap();
    let key = StorageKey::derive(&[3; 32]).unwrap();
    let sealed = pending.seal(&key).unwrap();
    assert_ne!(sealed, pending.seal(&key).unwrap());
    assert!(sealed.starts_with(LEGACY));
    drop(pending);
    let pending = PendingJoin::restore(&key, [2; 32], admin.id(), &sealed).unwrap();
    assert_eq!(pending.member(), &member);
    assert_eq!(pending.key_package().unwrap(), package);
    assert!(PendingJoin::restore(&key, [9; 32], admin.id(), &sealed).is_err());
    assert!(PendingJoin::restore(&key, [2; 32], [9; 32], &sealed).is_err());
    assert!(
        PendingJoin::restore(
            &StorageKey::derive(&[4; 32]).unwrap(),
            [2; 32],
            admin.id(),
            &sealed
        )
        .is_err()
    );
    assert!(
        PendingJoin::restore(
            &key,
            [2; 32],
            admin.id(),
            &vec![0; MAX_SEALED_WORKSPACE + 1]
        )
        .is_err()
    );
    assert!(Workspace::restore(&key, [2; 32], admin.id(), &sealed).is_err());
    assert!(PendingJoin::restore(&key, [1; 32], admin.id(), &admin.seal(&key).unwrap()).is_err());
    for index in [0, 5, 37, 49, sealed.len() - 1] {
        let mut bad = sealed.clone();
        bad[index] ^= 1;
        assert!(PendingJoin::restore(&key, [2; 32], admin.id(), &bad).is_err());
    }
    let package = KeyPackageIn::tls_deserialize_exact(&package)
        .unwrap()
        .validate(admin.provider.crypto(), ProtocolVersion::Mls10)
        .unwrap();
    let invite = SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap();
    let invitation_key = invite.public().try_into().unwrap();
    let auth = AdmissionAuthorization {
        invitation_key,
        grant_signature: admin
            ._signer
            .sign(&grant(admin.group.group_id(), &invitation_key))
            .unwrap()
            .try_into()
            .unwrap(),
        redemption_signature: invite
            .sign(&redemption(admin.group.group_id(), &invitation_key, &package).unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let (commit, welcome, _) = admin
        .group
        .add_members(&admin.provider, &admin._signer, &[package])
        .unwrap();
    let welcome = welcome.to_bytes().unwrap();
    // This reaches successful MLS validation but fails branch authorization.
    assert_eq!(
        pending.prepare_workspace(&proof, &welcome).err(),
        Some("Welcome does not match authorized branch")
    );
    proof.apply_add(&auth, &commit.to_bytes().unwrap()).unwrap();
    let mut damaged = welcome.clone();
    let end = damaged.len() - 1;
    damaged[end] ^= 1;
    assert!(pending.prepare_workspace(&proof, &damaged).is_err());
    let mut trailing = welcome.clone();
    trailing.push(0);
    assert!(pending.prepare_workspace(&proof, &trailing).is_err());
    let joined = pending.prepare_workspace(&proof, &welcome).unwrap();
    assert_eq!(joined.member(), Some(&member));
    assert_eq!(joined.member_count(), 2);
    assert_eq!(pending.member(), &member);
    assert_eq!(
        pending.key_package().unwrap(),
        pending.package.tls_serialize_detached().unwrap()
    );
    admin.group.merge_pending_commit(&admin.provider).unwrap();
    let other_checkpoint = admin.join_checkpoint().unwrap();
    let other_proof = JoinProof::from_trusted_checkpoint(
        admin.id(),
        Sha256::digest(&other_checkpoint).into(),
        &other_checkpoint,
    )
    .unwrap();
    assert_eq!(
        pending.prepare_workspace(&other_proof, &welcome).err(),
        Some("join proof belongs to another invitation")
    );
    let saved = joined.seal(&key).unwrap();
    drop(joined);
    let mut joined = Workspace::restore(&key, [2; 32], admin.id(), &saved).unwrap();
    assert_eq!(joined.member(), Some(&member));
    let publication = joined
        .group
        .create_message(
            &joined.provider,
            &joined._signer,
            b"after joining and restart",
        )
        .unwrap();
    let publication = MlsMessageIn::tls_deserialize_exact(publication.to_bytes().unwrap())
        .unwrap()
        .try_into_protocol_message()
        .unwrap();
    let message = admin
        .group
        .process_message(&admin.provider, publication)
        .unwrap();
    let ProcessedMessageContent::ApplicationMessage(message) = message.into_content() else {
        panic!("not application data")
    };
    assert_eq!(message.into_bytes(), b"after joining and restart");
}

// ponytail: checkpoint is inline within the 128KiB pending snapshot cap; move it
// to protected content storage when larger roster checkpoints must be supported.
