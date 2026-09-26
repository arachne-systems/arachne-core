//! Portable workspace security owner. No ATAK, transport or payload types.
//! Legacy hosts persist encrypted snapshots; trusted native adapters can persist
//! separate secret-bearing records in an authenticated encrypted store.
mod bootstrap;
mod gossip_key;
mod history;
mod records;
pub use records::SecurityRecords;
mod admission;
pub use admission::{
    AdmissionAttempt, AdmissionEnqueue, AdmissionQueue, AdmissionQueueError,
    MAX_ADMISSION_QUEUE_BYTES, MAX_ADMISSION_QUEUE_ITEMS,
};
mod management;
mod name;
pub use name::{
    MAX_WORKSPACE_NAME_CHECKPOINT, MAX_WORKSPACE_NAME_RECORD, PreparedWorkspaceName,
    PreparedWorkspaceNameCheckpoint, validate_workspace_name,
};
mod profile;
pub use profile::{MAX_MEMBER_PROFILE, MemberIdentity};
// ADR A2: commit fork choice and branch retention. Not wired yet.
mod fork;
pub use fork::{FORK_KEY_BYTES, ForkClass, ForkKey, fork_key, winner};
mod branch;
mod branch_steps;
pub use branch::{
    BranchDecision, BranchState, MAX_BRANCH_RECORD, MAX_BRANCH_SNAPSHOT, MAX_ROLLBACK_BYTES,
    PreparedBranchSwitch, ROLLBACK_EPOCHS,
};
mod order;
pub use order::{
    AnchorProof, MAX_ANCHOR_PROOF, ORDER_WINDOW, OrderStep, RevocationKind, RevocationOrder,
};
mod self_update;
pub use self_update::PreparedSelfUpdate;
mod step;
pub use step::{FORMAT_NOT_SUPPORTED, decode_membership_step, encode_membership_step};
mod removed;
pub use management::{ManagementAction, PreparedManagement, PreparedManagementUpdate};
pub use removed::{MAX_SEALED_REMOVAL, RemovedMembership};
mod message;
mod object;
pub use object::{AuthenticatedObject, MAX_OBJECT_NAMESPACE, RECEIVE_EPOCHS, object_epoch};
mod recovery;
pub use message::{
    ApplicationMessage, MAX_APPLICATION_CIPHERTEXT, MAX_APPLICATION_CONTEXT,
    MAX_APPLICATION_PAYLOAD,
};
pub use recovery::{
    MAX_RECOVERY_PACKETS, RecoveryCutoffRequest, RecoveryRequest, VerifiedRecoveryOffer,
};
mod invitation;
mod invitation_controls;
pub use invitation_controls::{
    INVITATION_APPROVAL_REQUIRED, INVITATION_AUTOMATIC_APPROVAL_REQUIRED, INVITATION_CONTROLS_FULL,
    INVITATION_DISABLED, INVITATION_EXPIRED, InvitationControl,
};
mod pending;
pub use invitation::{
    AdmissionAssessment, AdmissionReply, Invitation, PreparedAdmission, PreparedAdmissionBatch,
    ValidatedAdmission,
};
mod storage;
pub use bootstrap::{
    AdmissionAuthorization, HISTORY_CHUNK_STEPS, JoinProof, MAX_CHECKPOINT, MAX_CHECKPOINT_PIN,
    MAX_CHECKPOINT_TREE, MAX_JOIN_HISTORY_BYTES, MAX_JOIN_HISTORY_STEPS, MembershipAuthorization,
    MAX_MEMBERSHIP_COMMIT, MembershipVerifier, admission_asserted_time, checkpoint_digest,
};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{OpenMlsProvider, random::OpenMlsRand};
pub use pending::{MAX_WELCOME, PendingJoin};
pub use storage::{
    MAX_SEALED_BUNDLE, MAX_SEALED_PENDING_JOIN, MAX_SEALED_WORKSPACE, MAX_WORKSPACE_ATTACHMENT,
    StorageKey,
};

const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const AUTHORITY: u16 = 0xff00; // Candidate encoding shared with admission experiment.
pub const MAX_ADMISSION_BATCH: usize = 128;

/// Workspace-scoped identity and chosen local display name. Names are not credentials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberProfile {
    id: [u8; 32],
    display_name: String,
    service: bool,
}
impl MemberProfile {
    fn new(id: [u8; 32], name: &str) -> Result<Self, &'static str> {
        Self::new_kind(id, name, false)
    }
    fn new_kind(id: [u8; 32], name: &str, service: bool) -> Result<Self, &'static str> {
        let name = name.trim();
        if name.is_empty() || name.len() > 256 || name.chars().count() > 80
            || name.chars().any(|c| c.is_control() || matches!(c,
                '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
        {
            return Err("member name must be 1–80 characters without control characters");
        }
        Ok(Self {
            id,
            display_name: name.to_owned(),
            service,
        })
    }
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
    pub fn is_service(&self) -> bool {
        self.service
    }
}

/// Credential identity prefix of a member: then member id, then endpoint.
const MEMBER_IDENTITY: &[u8] = b"data-fabric/member/v3/";
/// Leaf extension with the endpoint key's signature (ADR A2 step 6).
const ENDPOINT_BINDING: u16 = 0xff01;
const ENDPOINT_BINDING_DOMAIN: &[u8] = b"arachne/endpoint-binding/v1";

/// The transport endpoint key (the Iroh Ed25519 key). It signs the binding
/// between a workspace member and its endpoint, so no leaf can claim an
/// endpoint whose key did not consent. Signatures are plain Ed25519 over the
/// raw message, as Iroh's `SecretKey::sign` produces.
pub trait EndpointSigner {
    /// The Ed25519 public key, which is the endpoint id.
    fn endpoint(&self) -> [u8; 32];
    /// Plain Ed25519 signature over `message`.
    fn sign_endpoint(&self, message: &[u8]) -> Result<[u8; 64], &'static str>;
}

/// An Ed25519 endpoint key held in memory. For hosts and tests without an
/// Iroh key; production hosts implement [`EndpointSigner`] for their key.
pub struct EndpointKey(SignatureKeyPair);

impl EndpointKey {
    pub fn generate() -> Result<Self, &'static str> {
        SignatureKeyPair::new(SignatureScheme::ED25519)
            .map(Self)
            .map_err(|_| "endpoint key generation failed")
    }
}

impl EndpointSigner for EndpointKey {
    fn endpoint(&self) -> [u8; 32] {
        self.0.public().try_into().expect("Ed25519 public key")
    }
    fn sign_endpoint(&self, message: &[u8]) -> Result<[u8; 64], &'static str> {
        use openmls_traits::signatures::Signer;
        self.0
            .sign(message)
            .map_err(|_| "endpoint signing failed")?
            .try_into()
            .map_err(|_| "invalid endpoint signature length")
    }
}

/// A process-wide endpoint key per test label. Tests name endpoints by small
/// labels; the endpoint itself is the key's public key.
#[cfg(test)]
fn test_keys() -> &'static std::sync::Mutex<std::collections::HashMap<u64, &'static EndpointKey>> {
    static KEYS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<u64, &'static EndpointKey>>,
    > = std::sync::OnceLock::new();
    KEYS.get_or_init(Default::default)
}

#[cfg(test)]
pub(crate) fn test_key(label: u64) -> &'static EndpointKey {
    test_keys()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(label)
        .or_insert_with(|| Box::leak(Box::new(EndpointKey::generate().unwrap())))
}

#[cfg(test)]
pub(crate) fn test_endpoint(label: u64) -> [u8; 32] {
    test_key(label).endpoint()
}

/// The test key whose public key is `endpoint`.
#[cfg(test)]
pub(crate) fn test_key_for(endpoint: [u8; 32]) -> &'static EndpointKey {
    let key = test_keys()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .values()
        .copied()
        .find(|key| key.endpoint() == endpoint);
    key.expect("endpoint has no test key")
}

fn endpoint_binding_message(workspace: [u8; 32], member: [u8; 32], signature_key: &[u8]) -> Vec<u8> {
    let mut message = ENDPOINT_BINDING_DOMAIN.to_vec();
    message.extend(workspace);
    message.extend(member);
    message.extend((signature_key.len() as u32).to_be_bytes());
    message.extend(signature_key);
    message
}

/// Leaf extensions that bind `member` and its MLS key to the endpoint.
fn endpoint_binding(
    endpoint: &dyn EndpointSigner,
    workspace: [u8; 32],
    member: [u8; 32],
    signature_key: &[u8],
) -> Result<Extensions<LeafNode>, &'static str> {
    let signature =
        endpoint.sign_endpoint(&endpoint_binding_message(workspace, member, signature_key))?;
    Extensions::single(Extension::Unknown(
        ENDPOINT_BINDING,
        UnknownExtension(signature.to_vec()),
    ))
    .map_err(|_| "invalid endpoint binding extension")
}

/// Capabilities every member leaf declares.
fn leaf_capabilities() -> Capabilities {
    Capabilities::new(
        None,
        None,
        Some(&[
            ExtensionType::Unknown(AUTHORITY),
            ExtensionType::Unknown(ENDPOINT_BINDING),
        ]),
        None,
        None,
    )
}

fn credential_identity(endpoint: [u8; 32], member: Option<&MemberProfile>) -> Vec<u8> {
    let mut identity = if let Some(member) = member {
        let mut bytes = MEMBER_IDENTITY.to_vec();
        bytes.extend(member.id);
        bytes
    } else {
        b"data-fabric/candidate-endpoint/v1/".to_vec()
    };
    identity.extend(endpoint);
    identity
}

/// Owns cryptographic state without exposing OpenMLS objects. Secret-bearing
/// storage records are restricted to the trusted native persistence seam.
pub struct Workspace {
    provider: OpenMlsRustCrypto,
    _signer: SignatureKeyPair,
    group: MlsGroup,
    id: [u8; 32],
    endpoint: [u8; 32],
    member: Option<MemberProfile>,
    admissions: Vec<invitation::RetainedAdmission>,
    join_history: Option<history::MembershipHistory>,
    invitation_checkpoints: Vec<invitation::RetainedInvitationCheckpoint>,
}

/// Bytes held by one workspace's state, by part. Diagnostic only: it counts
/// payload bytes, not allocator overhead.
#[derive(Debug, Default, Clone, Copy)]
pub struct MemoryReport {
    pub records: usize,
    pub record_bytes: usize,
    pub history_steps: usize,
    pub history_bytes: usize,
    pub admissions: usize,
    pub admission_bytes: usize,
    pub checkpoint_bytes: usize,
}

impl Workspace {
    pub fn memory_report(&self) -> MemoryReport {
        let mut report = MemoryReport::default();
        if let Ok(values) = self.provider.storage().values.read() {
            report.records = values.len();
            report.record_bytes = values.iter().map(|(key, value)| key.len() + value.len()).sum();
        }
        if let Some(history) = &self.join_history {
            report.history_steps = history.steps.len();
            report.history_bytes = history.checkpoint.len() + history.steps.iter().map(|(_, commit)| commit.len()).sum::<usize>();
        }
        report.admissions = self.admissions.len();
        // Shared batch bytes count once: the number is the memory held.
        let mut seen = std::collections::HashSet::new();
        for admission in &self.admissions {
            for bytes in [&admission.reply.commit, &admission.reply.welcome] {
                if seen.insert(bytes.as_ptr()) {
                    report.admission_bytes += bytes.len();
                }
            }
        }
        report.checkpoint_bytes = self.invitation_checkpoints.iter().map(|checkpoint| checkpoint.checkpoint.len()).sum();
        report
    }

    pub fn create_named(
        endpoint: &dyn EndpointSigner,
        display_name: &str,
        workspace_name: Option<&str>,
    ) -> Result<Self, &'static str> {
        let owner = Self::create(endpoint, display_name)?;
        match workspace_name {
            Some(name) => Ok(owner.prepare_workspace_name(name)?.workspace),
            None => Ok(owner),
        }
    }
    /// Create a workspace. `endpoint` is this device's transport key; it signs
    /// the endpoint binding in the creator's leaf (ADR A2 step 6).
    pub fn create(endpoint: &dyn EndpointSigner, display_name: &str) -> Result<Self, &'static str> {
        let signer_endpoint = endpoint;
        let endpoint = signer_endpoint.endpoint();
        if endpoint == [0; 32] {
            return Err("invalid workspace-facing endpoint");
        }
        let provider = OpenMlsRustCrypto::default();
        let member = MemberProfile::new(
            provider
                .rand()
                .random_array::<32>()
                .map_err(|_| "member randomness failed")?,
            display_name,
        )?;
        let id = provider
            .rand()
            .random_array::<32>()
            .map_err(|_| "workspace randomness failed")?;
        let signer = SignatureKeyPair::new(SUITE.signature_algorithm())
            .map_err(|_| "credential creation failed")?;
        signer
            .store(provider.storage())
            .map_err(|_| "credential storage failed")?;
        let identity = credential_identity(endpoint, Some(&member));
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity).into(),
            signature_key: signer.to_public_vec().into(),
        };
        // Every invitation must be registered; a new workspace has none.
        let mut authority = vec![2, 1];
        authority.extend(signer.public());
        authority.extend(0u16.to_be_bytes());
        let extensions = Extensions::from_vec(vec![
            Extension::Unknown(AUTHORITY, UnknownExtension(authority)),
            Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                &[
                    ExtensionType::Unknown(AUTHORITY),
                    ExtensionType::Unknown(ENDPOINT_BINDING),
                ],
                &[],
                &[],
            )),
        ])
        .map_err(|_| "invalid workspace extensions")?;
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(SUITE)
            // Public MLS handshakes permit invitation checkpoint replay. They
            // contain roster metadata and require an authorized outer channel.
            // MLS application messages remain PrivateMessage ciphertext.
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .capabilities(leaf_capabilities())
            .with_leaf_node_extensions(endpoint_binding(
                signer_endpoint,
                id,
                member.id,
                signer.public(),
            )?)
            .map_err(|_| "invalid endpoint binding extension")?
            .with_group_context_extensions(extensions)
            .build();
        let group = MlsGroup::new_with_group_id(
            &provider,
            &signer,
            &config,
            GroupId::from_slice(&id),
            credential,
        )
        .map_err(|_| "workspace creation failed")?;
        gossip_key::generate(&provider)?;
        Ok(Self {
            provider,
            _signer: signer,
            group,
            id,
            endpoint,
            member: Some(member),
            admissions: Vec::new(),
            join_history: None,
            invitation_checkpoints: Vec::new(),
        })
    }

    /// None identifies a legacy snapshot without a chosen member profile.
    pub fn member(&self) -> Option<&MemberProfile> {
        self.member.as_ref()
    }
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
    /// This owner's workspace-scoped transport identity, not a device-global ID.
    pub fn endpoint(&self) -> [u8; 32] {
        self.endpoint
    }
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }
    /// Compare accepted epochs between already authenticated workspace members.
    /// Equality is not authority, global finality, or a branch-merge decision.
    pub fn epoch_fingerprint(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"data-fabric/epoch-fingerprint/v1\0");
        hash.update(self.id);
        hash.update(self.epoch().to_be_bytes());
        hash.update(self.group.epoch_authenticator().as_slice());
        hash.finalize().into()
    }
    /// Verified workspace-facing transport endpoints for a routing projection.
    /// This is membership, not topic permission or a global device directory.
    pub fn member_endpoints(&self) -> Result<Vec<[u8; 32]>, &'static str> {
        self.group
            .members()
            .map(|member| Ok(bootstrap::binding(&member.credential)?.1))
            .collect()
    }

    /// Resolve a canonical direct recipient scope through the accepted roster.
    /// Endpoint keys are a transport result, never caller supplied authority.
    pub fn endpoints_for_members(
        &self,
        members: &[[u8; 32]],
    ) -> Result<Vec<[u8; 32]>, &'static str> {
        if members.is_empty()
            || members.len() > 64
            || members.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err("invalid direct recipient scope");
        }
        let bindings: Vec<_> = self
            .group
            .members()
            .map(|member| bootstrap::binding(&member.credential))
            .collect::<Result<_, _>>()?;
        members
            .iter()
            .map(|member| {
                bindings
                    .iter()
                    .find_map(|(id, endpoint)| (id == member).then_some(*endpoint))
                    .ok_or("direct recipient is not a current member")
            })
            .collect()
    }

    pub fn member_count(&self) -> usize {
        self.group.members().count()
    }
}

#[test]
fn creation_owns_distinct_groups_and_initial_authority() {
    struct Zero;
    impl EndpointSigner for Zero {
        fn endpoint(&self) -> [u8; 32] {
            [0; 32]
        }
        fn sign_endpoint(&self, _: &[u8]) -> Result<[u8; 64], &'static str> {
            Ok([0; 64])
        }
    }
    assert!(Workspace::create(&Zero, "Alex").is_err());
    let a = Workspace::create(crate::test_key(1), "Alex").unwrap();
    let b = Workspace::create(crate::test_key(2), "Alex").unwrap();
    assert_ne!(a.id(), b.id());
    assert_ne!(a.member().unwrap().id(), b.member().unwrap().id());
    assert_ne!(a.member().unwrap().id(), a.id());
    assert_ne!(a.member().unwrap().id(), a.endpoint);
    assert_eq!(
        a.member().unwrap().display_name(),
        b.member().unwrap().display_name()
    );
    assert_eq!(
        MemberProfile::new([1; 32], "  Álex Morgan  ")
            .unwrap()
            .display_name(),
        "Álex Morgan"
    );
    for name in [
        "",
        "  ",
        "Alex\nMorgan",
        "Alex\u{202e}Morgan",
        &"a".repeat(81),
        &"😀".repeat(65),
    ] {
        assert!(Workspace::create(crate::test_key(1), name).is_err());
    }
    assert_eq!(a.epoch(), 0);
    assert_eq!(a.member_count(), 1);
    let admins = &a.group.extensions().unknown(AUTHORITY).unwrap().0;
    assert_eq!(&admins[..2], &[2, 1]);
    assert_eq!(&admins[2..34], a._signer.public());
    assert_eq!(&admins[34..], &[0, 0]);
}
