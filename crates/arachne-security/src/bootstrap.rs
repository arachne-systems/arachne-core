//! Public membership proof for a prospective joiner. No group secrets are needed.
//! The checkpoint digest must come from the user's trusted invitation, never
//! from the peer response carrying the checkpoint. Wire invitation UX is separate.
use super::{AUTHORITY, SUITE, Workspace};
use openmls::prelude::{
    tls_codec::{Deserialize, Serialize},
    *,
};
use openmls::treesync::RatchetTree;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{OpenMlsProvider, crypto::OpenMlsCrypto};
use sha2::{Digest, Sha256};

/// Largest membership commit a verifier accepts. Raised from 64 KiB with the
/// runtime transport (B3c): steps now travel binary in 128 KiB pages, and a
/// commit grows about 82 bytes per member that never self-updated, so 96 KiB
/// holds about 1,170 such members.
pub const MAX_MEMBERSHIP_COMMIT: usize = 96 * 1024;
const MAX_BYTES: usize = MAX_MEMBERSHIP_COMMIT;
/// Bound for this device's own group state re-read for verification. It never
/// crosses the network, so the 64 KiB wire bound does not apply: GroupInfo
/// with the ratchet tree passes 64 KiB near 250 members (measured ~255 B per
/// member), and members then rejected every later update.
const MAX_LOCAL_STATE_BYTES: usize = 8 * 1024 * 1024;
// ponytail: bounded in-memory/history replay budget. Checkpoint rollover
// (below) removes the 64-step ceiling; this byte budget still applies.
const MAX_HISTORY_BYTES: usize = 2 * 1024 * 1024;

/// Transitions one chunk of a join history carries. A branch longer than this
/// is verified chunk by chunk: rollover adds a chunk, it never widens one, so
/// no single request, reply page or `StageJoin` call ever carries more steps
/// than it always did.
pub const HISTORY_CHUNK_STEPS: usize = 64;
/// Chunks a joiner will roll through from one pinned invitation checkpoint.
const MAX_HISTORY_CHUNKS: usize = 64;
/// Transitions a joiner will replay from one pinned invitation checkpoint.
pub const MAX_JOIN_HISTORY_STEPS: usize = HISTORY_CHUNK_STEPS * MAX_HISTORY_CHUNKS;
/// Bytes a joiner will accept across a whole paged history exchange, including
/// pages it has not yet verified. A reachable but hostile member must not be
/// able to grow a pending join's memory one page at a time.
pub const MAX_JOIN_HISTORY_BYTES: usize = MAX_HISTORY_BYTES;

/// Inline join history: magic and version, checkpoint digest, u32 checkpoint
/// length, checkpoint, then steps in the v3 step codec (`step.rs`).
const HISTORY_VERSION: &[u8; 5] = b"DFJH\x03";

/// Invitation checkpoint codec: `DFCK\x01`, u32 pin length, pin, u32 tree
/// length, tree. The pin is signed MLS GroupInfo without the ratchet tree; an
/// invitation pins SHA-256 of the pin only. The tree is the TLS-encoded ratchet
/// tree at the pin's epoch. It is bound by the pin's signed tree hash, which
/// `PublicGroup::from_external` checks, so a substituted tree fails.
const CHECKPOINT_MAGIC: &[u8; 5] = b"DFCK\x01";
/// Wire bound for a checkpoint pin: GroupContext, extensions and signature.
pub const MAX_CHECKPOINT_PIN: usize = 64 * 1024;
/// Wire bound for a checkpoint tree. About 270 bytes per member (measured at
/// 385 and 1,025 members), so this admits about 2,900 members; see the B3a
/// harness tests. It is sized so a sealed pending join, which holds one
/// checkpoint, still fits one 1 MiB host record.
pub const MAX_CHECKPOINT_TREE: usize = 768 * 1024;
/// Wire bound for a whole encoded checkpoint. Issuer and joiner apply the same
/// parts bounds, so an issuer never produces a checkpoint a joiner rejects.
pub const MAX_CHECKPOINT: usize = 13 + MAX_CHECKPOINT_PIN + MAX_CHECKPOINT_TREE;

/// Where checkpoint bytes came from: a peer (wire bounds), or this device's own
/// accepted state (local-state bound only).
#[derive(Clone, Copy)]
pub(super) enum CheckpointBound {
    Wire,
    Local,
}

pub(super) struct CheckpointParts<'a> {
    pub pin: &'a [u8],
    pub tree: &'a [u8],
}

pub(super) fn checkpoint_parts(
    bytes: &[u8],
    bound: CheckpointBound,
) -> Result<CheckpointParts<'_>, &'static str> {
    use super::storage::{number, take};
    let limit = match bound {
        CheckpointBound::Wire => MAX_CHECKPOINT,
        CheckpointBound::Local => MAX_LOCAL_STATE_BYTES,
    };
    if bytes.len() > limit {
        return Err("checkpoint exceeds bounds");
    }
    let mut rest = bytes
        .strip_prefix(CHECKPOINT_MAGIC)
        .ok_or("invalid checkpoint")?;
    let length = number(&mut rest)?;
    if length == 0 || (matches!(bound, CheckpointBound::Wire) && length > MAX_CHECKPOINT_PIN) {
        return Err("checkpoint exceeds bounds");
    }
    let pin = take(&mut rest, length)?;
    let length = number(&mut rest)?;
    if length == 0 || (matches!(bound, CheckpointBound::Wire) && length > MAX_CHECKPOINT_TREE) {
        return Err("checkpoint exceeds bounds");
    }
    let tree = take(&mut rest, length)?;
    if !rest.is_empty() {
        return Err("invalid checkpoint");
    }
    Ok(CheckpointParts { pin, tree })
}

/// The digest an invitation pins for these checkpoint bytes: SHA-256 of the
/// pin. Structure only; this does not verify the checkpoint.
pub fn checkpoint_digest(bytes: &[u8]) -> Result<[u8; 32], &'static str> {
    Ok(Sha256::digest(checkpoint_parts(bytes, CheckpointBound::Local)?.pin).into())
}

/// The signed GroupInfo a checkpoint pins. Structure only.
pub(super) fn checkpoint_info(bytes: &[u8]) -> Result<openmls::messages::group_info::VerifiableGroupInfo, &'static str> {
    let parts = checkpoint_parts(bytes, CheckpointBound::Local)?;
    let message =
        MlsMessageIn::tls_deserialize_exact(parts.pin).map_err(|_| "invalid checkpoint")?;
    let MlsMessageBodyIn::GroupInfo(info) = message.extract() else {
        return Err("expected GroupInfo");
    };
    Ok(info)
}

fn encode_checkpoint(
    group: &MlsGroup,
    crypto: &impl OpenMlsCrypto,
    signer: &impl openmls_traits::signatures::Signer,
    extensions: Vec<Extension>,
    bound: CheckpointBound,
) -> Result<Vec<u8>, &'static str> {
    let pin = group
        .export_group_info_with_additional_extensions(crypto, signer, false, extensions)
        .map_err(|_| "checkpoint creation failed")?
        .to_bytes()
        .map_err(|_| "checkpoint encoding failed")?;
    let tree = group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .map_err(|_| "checkpoint encoding failed")?;
    let mut bytes = CHECKPOINT_MAGIC.to_vec();
    for part in [&pin, &tree] {
        bytes.extend(
            u32::try_from(part.len())
                .map_err(|_| "checkpoint exceeds bounds")?
                .to_be_bytes(),
        );
        bytes.extend(part);
    }
    // The same check every receiver applies.
    checkpoint_parts(&bytes, bound)?;
    Ok(bytes)
}

/// Public checkpoint of a member's state for an anchor proof. It uses the
/// wire bounds because other members replay it.
pub(super) fn public_checkpoint(workspace: &Workspace) -> Result<Vec<u8>, &'static str> {
    encode_checkpoint(
        &workspace.group,
        workspace.provider.crypto(),
        &workspace._signer,
        Vec::new(),
        CheckpointBound::Wire,
    )
}

impl Workspace {
    /// This device's own accepted state as a checkpoint, for local verification.
    fn local_checkpoint(&self) -> Result<Vec<u8>, &'static str> {
        encode_checkpoint(
            &self.group,
            self.provider.crypto(),
            &self._signer,
            Vec::new(),
            CheckpointBound::Local,
        )
        .map_err(|_| "group comparison export failed")
    }
}

/// Domain tag of an Add's authenticated data (ADR A2 step 2). The rest is the
/// committer's asserted Unix time in seconds, as a big-endian u64.
const ASSERTED_TIME: &[u8] = b"arachne/asserted-time/v1";

pub(super) fn asserted_time_aad(time: u64) -> Vec<u8> {
    let mut aad = ASSERTED_TIME.to_vec();
    aad.extend(time.to_be_bytes());
    aad
}

/// The committer's asserted time in an admission commit. Parsing only: it
/// does not verify the commit. A host can compare it with its own clock and
/// warn on a large difference; verifiers never reject for that.
pub fn admission_asserted_time(commit: &[u8]) -> Option<u64> {
    asserted_time(public_message_aad(commit)?).ok()
}

fn asserted_time(aad: &[u8]) -> Result<u64, &'static str> {
    aad.strip_prefix(ASSERTED_TIME)
        .and_then(|time| <[u8; 8]>::try_from(time).ok())
        .map(u64::from_be_bytes)
        .ok_or("admission requires the committer's asserted time")
}

/// Authenticated data of a public MLS message, read from its TLS encoding:
/// version, wire format, then `FramedContent` up to `authenticated_data`.
/// Parsing only; OpenMLS exposes the AAD only after verification.
pub(super) fn public_message_aad(message: &[u8]) -> Option<&[u8]> {
    fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Option<&'a [u8]> {
        let (head, rest) = bytes.split_at_checked(count)?;
        *bytes = rest;
        Some(head)
    }
    // RFC 9000 variable-length integer, as RFC 9420 uses for vector lengths.
    fn vector<'a>(bytes: &mut &'a [u8]) -> Option<&'a [u8]> {
        let first = *bytes.first()?;
        let size = 1usize << (first >> 6);
        if size == 8 {
            return None;
        }
        let mut length = u64::from(first & 0x3f);
        for byte in &take(bytes, size)?[1..] {
            length = (length << 8) | u64::from(*byte);
        }
        take(bytes, usize::try_from(length).ok()?)
    }
    let mut bytes = message;
    // mls10, public_message
    if take(&mut bytes, 4)? != [0, 1, 0, 1] {
        return None;
    }
    vector(&mut bytes)?; // group_id
    take(&mut bytes, 8)?; // epoch
    match take(&mut bytes, 1)?[0] {
        1 | 2 => {
            take(&mut bytes, 4)?; // member leaf index or external sender index
        }
        3 | 4 => {}
        _ => return None,
    }
    vector(&mut bytes)
}

/// Public proof of an ordinary-member invitation and its exact redemption.
/// No bearer private key is carried here. Fields are untrusted until verified.
#[derive(Clone)]
pub struct AdmissionAuthorization {
    pub invitation_key: [u8; 32],
    pub grant_signature: [u8; 64],
    pub redemption_signature: [u8; 64],
}

/// Authorization for one exact membership transition. Tags cannot substitute
/// for checking the signed MLS commit against its parent state.
#[derive(Clone)]
pub enum MembershipAuthorization {
    Admission(AdmissionAuthorization),
    AdmissionBatch(Vec<AdmissionAuthorization>),
    /// Promote and invitation create / approve / decline. The committer must
    /// be an administrator. Remove, Demote and DisableInvitation are rejected
    /// here: they need a signed order (`Revocation`).
    Management(super::ManagementAction),
    /// Remove, Leave, Demote, DisableInvitation (ADR A2 step 4). Any member
    /// may commit a valid order.
    Revocation(super::OrderStep),
    /// A member's own update path (ADR A2 step 5): an empty commit with an
    /// update path, no proposals, no extension change and the same
    /// credential, key, capabilities and leaf extensions. It gives members
    /// post-compromise security and merges their unmerged tree nodes.
    SelfUpdate,
}

impl MembershipAuthorization {
    /// The member this step removes, if it removes one.
    pub fn removed_member(&self) -> Option<[u8; 32]> {
        match self {
            Self::Revocation(step) if step.order.kind.removes() => Some(step.order.target),
            _ => None,
        }
    }
}

/// Tracks a branch from a trusted checkpoint. This does not settle competing
/// branches, authenticate a real-world group name, or establish MLS membership.
pub struct JoinProof {
    pub(super) checkpoint_digest: [u8; 32],
    verifier: MembershipVerifier,
    pub(super) name_checkpoint: super::name::NameState,
    history: Vec<u8>,
    /// Verified transitions already carried by `history`. Tracked rather than
    /// re-parsed on every append, which was quadratic in the branch length.
    steps: usize,
}

/// A candidate history produced before the transition is verified. It is
/// adopted only once the verifier has accepted the same transition.
struct AppendedHistory {
    history: Vec<u8>,
    steps: usize,
}

/// Incrementally verifies exact membership transitions from a trusted checkpoint.
/// Holds the current public roster, not a lifetime log or secret group keys.
/// The caller retains the checkpoint and accepted transitions for durable replay;
/// verification does not persist them, establish membership, or resolve forks.
pub struct MembershipVerifier {
    pub(super) provider: OpenMlsRustCrypto,
    pub(super) group: PublicGroup,
    /// Nesting depth of anchor proofs this verifier replays (0 at top level).
    pub(super) proof_depth: u8,
}

pub(super) fn authority(
    extensions: &Extensions<GroupContext>,
) -> Result<Vec<Vec<u8>>, &'static str> {
    let bytes = &extensions.unknown(AUTHORITY).ok_or("missing authority")?.0;
    if bytes.len() < 2
        || bytes[0] != 2
        || !(1..=64).contains(&bytes[1])
        || bytes.len() < 2 + usize::from(bytes[1]) * 32
    {
        return Err("invalid authority encoding");
    }
    let end = 2 + usize::from(bytes[1]) * 32;
    super::invitation_controls::decode(&bytes[end..])?;
    let keys: Vec<Vec<u8>> = bytes[2..end]
        .as_chunks::<32>()
        .0
        .iter()
        .map(|key| key.to_vec())
        .collect();
    if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("noncanonical authority");
    }
    Ok(keys)
}

pub(super) fn binding(credential: &Credential) -> Result<([u8; 32], [u8; 32]), &'static str> {
    let credential =
        BasicCredential::try_from(credential.clone()).map_err(|_| "unsupported credential")?;
    let bytes = credential
        .identity()
        .strip_prefix(super::MEMBER_IDENTITY)
        .ok_or("member credential upgrade required")?;
    if bytes.len() != 64 || bytes[..32] == [0; 32] || bytes[32..] == [0; 32] {
        return Err("invalid member binding");
    }
    Ok((
        bytes[..32].try_into().unwrap(),
        bytes[32..].try_into().unwrap(),
    ))
}

/// Verify a leaf's endpoint binding (ADR A2 step 6): the endpoint named in
/// its credential signed (workspace, member id, MLS signature key). A leaf
/// without a valid binding is rejected; no leaf can claim an endpoint whose
/// key did not consent. Returns the leaf's (member id, endpoint).
pub(super) fn verify_endpoint_binding(
    crypto: &impl OpenMlsCrypto,
    workspace: &GroupId,
    leaf: &LeafNode,
) -> Result<([u8; 32], [u8; 32]), &'static str> {
    let (member, endpoint) = binding(leaf.credential())?;
    let workspace: [u8; 32] = workspace
        .as_slice()
        .try_into()
        .map_err(|_| "invalid workspace id")?;
    let signature = leaf
        .extensions()
        .unknown(super::ENDPOINT_BINDING)
        .ok_or("member leaf has no endpoint binding")?;
    crypto
        .verify_signature(
            SignatureScheme::ED25519,
            &super::endpoint_binding_message(workspace, member, leaf.signature_key().as_slice()),
            &endpoint,
            &signature.0,
        )
        .map_err(|_| "invalid endpoint binding")?;
    Ok((member, endpoint))
}

/// A committer's new path leaf keeps its credential, key and extensions,
/// so its endpoint binding stays valid.
pub(super) fn check_path_leaf(
    group: &PublicGroup,
    actor: LeafNodeIndex,
    leaf: &LeafNode,
) -> Result<(), &'static str> {
    let old = group.leaf(actor).ok_or("unknown committer")?;
    if leaf.credential() != old.credential()
        || leaf.signature_key() != old.signature_key()
        || leaf.extensions() != old.extensions()
    {
        return Err("commit cannot replace committer identity");
    }
    Ok(())
}

pub(super) fn grant(group: &GroupId, key: &[u8; 32]) -> Vec<u8> {
    // Matches the bounded ordinary-member grant exercised by the admission gate.
    let mut bytes = b"data-fabric/candidate-invite/v1/ordinary-member".to_vec();
    bytes.extend((group.as_slice().len() as u32).to_be_bytes());
    bytes.extend(group.as_slice());
    bytes.extend(key);
    bytes
}

pub(super) fn redemption(
    group: &GroupId,
    key: &[u8; 32],
    package: &KeyPackage,
) -> Result<Vec<u8>, &'static str> {
    let mut bytes = b"data-fabric/candidate-redemption/v1".to_vec();
    bytes.extend(grant(group, key));
    bytes.extend(
        package
            .tls_serialize_detached()
            .map_err(|_| "KeyPackage encoding failed")?,
    );
    Ok(bytes)
}

impl Workspace {
    /// Public, signed MLS state containing the roster. Only distribute to
    /// authorized recipients; an invitation must bind its digest separately.
    pub fn join_checkpoint(&self) -> Result<Vec<u8>, &'static str> {
        if self.member().is_none() {
            return Err("member credential upgrade required");
        }
        if !authority(self.group.extensions())?
            .iter()
            .any(|key| key == self._signer.public())
        {
            return Err("only an administrator may issue a checkpoint");
        }
        encode_checkpoint(
            &self.group,
            self.provider.crypto(),
            &self._signer,
            self.name_checkpoint_extension()?,
            CheckpointBound::Wire,
        )
    }
}

impl MembershipVerifier {
    /// The expected digest comes from the trusted invitation, not from the peer
    /// supplying the checkpoint. The signed checkpoint includes roster metadata.
    pub fn from_trusted_checkpoint(
        workspace: [u8; 32],
        digest: [u8; 32],
        bytes: &[u8],
    ) -> Result<Self, &'static str> {
        Self::from_checkpoint_within(workspace, digest, bytes, CheckpointBound::Wire)
    }

    /// See [`JoinProof::from_local_checkpoint`]: own accepted state only.
    pub(super) fn from_local_checkpoint(
        workspace: [u8; 32],
        digest: [u8; 32],
        bytes: &[u8],
    ) -> Result<Self, &'static str> {
        Self::from_checkpoint_within(workspace, digest, bytes, CheckpointBound::Local)
    }

    fn from_checkpoint_within(
        workspace: [u8; 32],
        digest: [u8; 32],
        bytes: &[u8],
        bound: CheckpointBound,
    ) -> Result<Self, &'static str> {
        let parts = checkpoint_parts(bytes, bound)?;
        if <[u8; 32]>::from(Sha256::digest(parts.pin)) != digest {
            return Err("checkpoint does not match invitation");
        }
        let message =
            MlsMessageIn::tls_deserialize_exact(parts.pin).map_err(|_| "invalid checkpoint")?;
        let MlsMessageBodyIn::GroupInfo(info) = message.extract() else {
            return Err("expected GroupInfo");
        };
        if info.group_id().as_slice() != workspace || info.ciphersuite() != SUITE {
            return Err("wrong checkpoint workspace");
        }
        // One canonical form: the tree travels beside the pin, never inside it.
        if info.extensions().ratchet_tree().is_some() {
            return Err("invalid checkpoint");
        }
        // Bound by the pinned GroupInfo's tree hash in `from_external` below.
        let tree = RatchetTreeIn::tls_deserialize_exact(parts.tree)
            .map_err(|_| "invalid checkpoint tree")?;
        let provider = OpenMlsRustCrypto::default();
        let (group, _) = PublicGroup::from_external(
            provider.crypto(),
            provider.storage(),
            tree,
            info,
            ProposalStore::new(),
        )
        .map_err(|_| "invalid checkpoint signature or tree")?;
        let admins = authority(group.group_context().extensions())?;
        let members: Vec<_> = group.members().collect();
        let mut ids = std::collections::BTreeSet::new();
        let mut endpoints = std::collections::BTreeSet::new();
        for member in &members {
            let leaf = group.leaf(member.index).ok_or("invalid checkpoint tree")?;
            let (id, endpoint) =
                verify_endpoint_binding(provider.crypto(), group.group_id(), leaf)?;
            if !ids.insert(id) || !endpoints.insert(endpoint) {
                return Err("duplicate member binding");
            }
        }
        if !admins
            .iter()
            .all(|key| members.iter().any(|member| &member.signature_key == key))
        {
            return Err("administrator is not a member");
        }
        Ok(Self {
            provider,
            group,
            proof_depth: 0,
        })
    }

    /// Public state from an anchor proof's checkpoint. It is not trusted by
    /// itself: `order::verify` trusts it only after the winning steps from it
    /// reach the verifier's own state.
    pub(super) fn from_proof_checkpoint(
        workspace: [u8; 32],
        bytes: &[u8],
        depth: u8,
    ) -> Result<Self, &'static str> {
        let parts = checkpoint_parts(bytes, CheckpointBound::Wire)?;
        let digest = Sha256::digest(parts.pin).into();
        let mut verifier =
            Self::from_checkpoint_within(workspace, digest, bytes, CheckpointBound::Wire)?;
        verifier.proof_depth = depth;
        Ok(verifier)
    }

    /// Validate one bounded commit against current authority and advance exactly
    /// one epoch. The caller must retain accepted records separately for replay.
    pub fn apply_transition(
        &mut self,
        authorization: &MembershipAuthorization,
        commit: &[u8],
    ) -> Result<(), &'static str> {
        match authorization {
            MembershipAuthorization::Admission(auth) => self.apply_add(auth, commit),
            MembershipAuthorization::AdmissionBatch(auths) => self.apply_add_batch(auths, commit),
            MembershipAuthorization::Management(action) => self.apply_management(*action, commit),
            MembershipAuthorization::SelfUpdate => {
                let staged = self.self_update_commit(commit)?;
                self.group
                    .merge_commit(self.provider.storage(), staged)
                    .map_err(|_| "public self-update merge failed")?;
                Ok(())
            }
            MembershipAuthorization::Revocation(step) => {
                let staged = self.revocation_commit(step, commit)?;
                self.group
                    .merge_commit(self.provider.storage(), staged)
                    .map_err(|_| "public revocation merge failed")?;
                Ok(())
            }
        }
    }

    fn apply_management(
        &mut self,
        action: super::ManagementAction,
        commit: &[u8],
    ) -> Result<(), &'static str> {
        let staged = self.management_commit(action, commit)?;
        self.group
            .merge_commit(self.provider.storage(), staged)
            .map_err(|_| "public management merge failed")?;
        Ok(())
    }

    /// Verify one member self-update against this parent state (ADR A2 step 5).
    fn self_update_commit(&self, commit: &[u8]) -> Result<StagedCommit, &'static str> {
        if commit.is_empty() || commit.len() > MAX_BYTES {
            return Err("self update commit exceeds bounds");
        }
        let message = MlsMessageIn::tls_deserialize_exact(commit)
            .map_err(|_| "invalid self update commit")?
            .try_into_protocol_message()
            .map_err(|_| "expected self update commit")?;
        let processed = self
            .group
            .process_message(self.provider.crypto(), message)
            .map_err(|_| "invalid self update signature or epoch")?;
        let Sender::Member(index) = *processed.sender() else {
            return Err("self update sender is not a member");
        };
        if !processed.aad().is_empty() {
            return Err("self update carries authenticated data");
        }
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err("not a self update commit");
        };
        // RFC 9420 does not let a committer include its own Update; the
        // commit is empty and carries only the path.
        if staged.queued_proposals().next().is_some() {
            return Err("self update carries proposals");
        }
        let leaf = staged
            .update_path_leaf_node()
            .ok_or("self update requires an update path")?;
        let old = self.group.leaf(index).ok_or("unknown self update sender")?;
        if leaf.credential() != old.credential()
            || leaf.signature_key() != old.signature_key()
            || leaf.capabilities() != old.capabilities()
            || leaf.extensions() != old.extensions()
        {
            return Err("self update changed the member leaf");
        }
        if staged.group_context().extensions() != self.group.group_context().extensions() {
            return Err("self update changed group policy");
        }
        Ok(*staged)
    }

    /// Verify one revocation step against this parent state (ADR A2 step 4).
    fn revocation_commit(
        &self,
        step: &super::OrderStep,
        commit: &[u8],
    ) -> Result<StagedCommit, &'static str> {
        if commit.is_empty() || commit.len() > MAX_BYTES {
            return Err("management commit exceeds bounds");
        }
        let message = MlsMessageIn::tls_deserialize_exact(commit)
            .map_err(|_| "invalid management commit")?
            .try_into_protocol_message()
            .map_err(|_| "expected management commit")?;
        let processed = self
            .group
            .process_message(self.provider.crypto(), message)
            .map_err(|_| "invalid management signature or epoch")?;
        if processed.aad() != super::order::commit_aad(&step.order) {
            return Err("revocation commit does not carry its order");
        }
        let sender = processed.sender().clone();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err("not a management commit");
        };
        super::order::verify(self, step)?;
        super::management::verify_revocation(&self.group, &sender, &staged, &step.order)?;
        Ok(*staged)
    }

    fn apply_add(
        &mut self,
        authorization: &AdmissionAuthorization,
        commit: &[u8],
    ) -> Result<(), &'static str> {
        self.apply_add_batch(std::slice::from_ref(authorization), commit)
    }

    fn apply_add_batch(
        &mut self,
        authorizations: &[AdmissionAuthorization],
        commit: &[u8],
    ) -> Result<(), &'static str> {
        if authorizations.is_empty() || authorizations.len() > super::MAX_ADMISSION_BATCH {
            return Err("invalid admission batch size");
        }
        if commit.is_empty() || commit.len() > MAX_BYTES {
            return Err("admission commit exceeds bounds");
        }
        let message = MlsMessageIn::tls_deserialize_exact(commit)
            .map_err(|_| "invalid admission commit")?
            .try_into_protocol_message()
            .map_err(|_| "expected admission commit")?;
        let processed = self
            .group
            .process_message(self.provider.crypto(), message)
            .map_err(|_| "invalid admission signature or epoch")?;
        let Sender::Member(index) = processed.sender() else {
            return Err("committer is not a member");
        };
        let actor = self
            .group
            .members()
            .find(|member| member.index == *index)
            .ok_or("unknown committer")?;
        let admins = authority(self.group.group_context().extensions())?;
        // ADR A2 step 2: only administrators commit Adds.
        if !admins.contains(&actor.signature_key) {
            return Err("only an administrator may commit an Add");
        }
        // Every verifier checks expiry against the committer's signed time,
        // never its own clock, so all verifiers reach the same answer.
        let asserted = asserted_time(processed.aad())?;
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err("not a commit");
        };
        let adds: Vec<_> = staged.add_proposals().collect();
        if adds.len() != authorizations.len() {
            return Err("admission authorizes only Add proposals");
        }
        // The only policy change an admission may carry is disabling the
        // single-use approvals it consumes, inline from the committer.
        let admitted: Vec<_> = authorizations
            .iter()
            .zip(&adds)
            .map(|(auth, add)| (auth.invitation_key, add.add_proposal().key_package()))
            .collect();
        let policy = super::invitation_controls::consumed(
            self.group.group_context().extensions(),
            &admitted,
        )?;
        let policy_proposals = staged
            .queued_proposals()
            .filter(|p| matches!(p.proposal(), Proposal::GroupContextExtensions(_)))
            .count();
        if staged.queued_proposals().count() != authorizations.len() + usize::from(policy.is_some())
            || policy_proposals != usize::from(policy.is_some())
            || !staged.queued_proposals().all(|p| {
                !matches!(p.proposal(), Proposal::GroupContextExtensions(_))
                    || (p.sender() == &Sender::Member(actor.index)
                        && p.proposal_or_ref_type() == ProposalOrRefType::Proposal)
            })
            || staged.group_context().extensions()
                != policy
                    .as_ref()
                    .unwrap_or(self.group.group_context().extensions())
        {
            return Err("invitation authorizes only Adds without policy changes");
        }
        if let Some(leaf) = staged.update_path_leaf_node() {
            check_path_leaf(&self.group, actor.index, leaf)?;
        }
        let mut bindings = std::collections::BTreeSet::new();
        let crypto = self.provider.crypto();
        for (authorization, add) in authorizations.iter().zip(adds) {
            let package = add.add_proposal().key_package();
            let (id, endpoint) =
                verify_endpoint_binding(crypto, self.group.group_id(), package.leaf_node())?;
            if !bindings.insert((id, endpoint))
                || self.group.members().any(|member| {
                    binding(&member.credential)
                        .map(|(existing_id, existing_endpoint)| {
                            existing_id == id || existing_endpoint == endpoint
                        })
                        .unwrap_or(true)
                })
            {
                return Err("duplicate member binding");
            }
            super::invitation_controls::check(
                self.group.group_context().extensions(),
                authorization.invitation_key,
                Some(asserted),
                package,
            )?;
            if !admins.iter().any(|admin| {
                crypto
                    .verify_signature(
                        SUITE.signature_algorithm(),
                        &grant(self.group.group_id(), &authorization.invitation_key),
                        admin,
                        &authorization.grant_signature,
                    )
                    .is_ok()
            }) {
                return Err("unapproved invitation");
            }
            crypto
                .verify_signature(
                    SUITE.signature_algorithm(),
                    &redemption(
                        self.group.group_id(),
                        &authorization.invitation_key,
                        package,
                    )?,
                    &authorization.invitation_key,
                    &authorization.redemption_signature,
                )
                .map_err(|_| "redemption does not match Add")?;
        }
        self.group
            .merge_commit(self.provider.storage(), *staged)
            .map_err(|_| "public state merge failed")?;
        Ok(())
    }

    pub(super) fn authorizes_issuer(&self, issuer: &[u8]) -> Result<bool, &'static str> {
        Ok(authority(self.group.group_context().extensions())?
            .iter()
            .any(|key| key == issuer))
    }

    pub(super) fn from_workspace(workspace: &Workspace) -> Result<Self, &'static str> {
        let bytes = workspace.local_checkpoint()?;
        Self::from_local_checkpoint(workspace.id(), checkpoint_digest(&bytes)?, &bytes)
    }

    pub(super) fn member_for_endpoint(
        &self,
        endpoint: [u8; 32],
    ) -> Result<Option<[u8; 32]>, &'static str> {
        for member in self.group.members() {
            let (id, bound_endpoint) = binding(&member.credential)?;
            if bound_endpoint == endpoint {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    pub fn epoch(&self) -> u64 {
        self.group.group_context().epoch().as_u64()
    }

    fn management_commit(
        &self,
        action: super::ManagementAction,
        commit: &[u8],
    ) -> Result<StagedCommit, &'static str> {
        if super::ForkClass::of_action(&action) < super::ForkClass::Management {
            return Err("revocation requires a signed order");
        }
        if commit.is_empty() || commit.len() > MAX_BYTES {
            return Err("management commit exceeds bounds");
        }
        let message = MlsMessageIn::tls_deserialize_exact(commit)
            .map_err(|_| "invalid management commit")?
            .try_into_protocol_message()
            .map_err(|_| "expected management commit")?;
        let processed = self
            .group
            .process_message(self.provider.crypto(), message)
            .map_err(|_| "invalid management signature or epoch")?;
        let sender = processed.sender().clone();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err("not a management commit");
        };
        super::management::verify(&self.group, &sender, &staged, action)?;
        Ok(*staged)
    }

    /// Compare context, confirmation tag and complete tree with an independently
    /// MLS-validated workspace. Public proof alone cannot validate Welcome secrets.
    pub fn matches_workspace(&self, workspace: &Workspace) -> Result<bool, &'static str> {
        Ok(
            self.group.group_context() == workspace.group.public_group().group_context()
                && self.group.confirmation_tag() == workspace.group.confirmation_tag()
                && self.group.export_ratchet_tree() == workspace.group.export_ratchet_tree(),
        )
    }
}

impl JoinProof {
    pub(super) fn export_ratchet_tree(&self) -> RatchetTree {
        self.verifier.group.export_ratchet_tree()
    }

    pub fn from_trusted_checkpoint(
        workspace: [u8; 32],
        digest: [u8; 32],
        bytes: &[u8],
    ) -> Result<Self, &'static str> {
        Self::from_checkpoint_within(workspace, digest, bytes, CheckpointBound::Wire)
    }

    /// A checkpoint this device holds as its own accepted state (a saved join
    /// history, or one rebuilt from its own group). It never came from a peer
    /// in this call, so the local-state bound applies, not the wire bound.
    pub(super) fn from_local_checkpoint(
        workspace: [u8; 32],
        digest: [u8; 32],
        bytes: &[u8],
    ) -> Result<Self, &'static str> {
        Self::from_checkpoint_within(workspace, digest, bytes, CheckpointBound::Local)
    }

    fn from_checkpoint_within(
        workspace: [u8; 32],
        digest: [u8; 32],
        bytes: &[u8],
        bound: CheckpointBound,
    ) -> Result<Self, &'static str> {
        let verifier = MembershipVerifier::from_checkpoint_within(workspace, digest, bytes, bound)?;
        let info = checkpoint_info(bytes)?;
        let name_checkpoint = info
            .extensions()
            .unknown(super::name::EXTENSION)
            .map(|e| super::name::NameState::decode(&e.0))
            .transpose()?
            .unwrap_or_default();
        let mut history = HISTORY_VERSION.to_vec();
        history.extend(digest);
        history.extend((bytes.len() as u32).to_be_bytes());
        history.extend(bytes);
        Ok(Self {
            checkpoint_digest: digest,
            name_checkpoint,
            verifier,
            history,
            steps: 0,
        })
    }

    pub fn workspace_name(&self) -> Result<Option<String>, &'static str> {
        Ok(self.name_checkpoint.name.clone())
    }
    pub fn history(&self) -> &[u8] {
        &self.history
    }

    pub(super) fn history_steps(
        encoded: &[u8],
    ) -> Result<Vec<(MembershipAuthorization, Vec<u8>)>, &'static str> {
        Self::history_steps_with_limit(encoded, MAX_HISTORY_BYTES)
    }

    fn history_steps_with_limit(
        encoded: &[u8],
        limit: usize,
    ) -> Result<Vec<(MembershipAuthorization, Vec<u8>)>, &'static str> {
        use super::storage::{number, take};
        if encoded.len() > limit {
            return Err("invalid join history");
        }
        if !encoded.starts_with(HISTORY_VERSION) {
            return Err(if encoded.starts_with(b"DFJH") {
                super::step::FORMAT_NOT_SUPPORTED
            } else {
                "invalid join history"
            });
        }
        let mut bytes = &encoded[5..];
        take(&mut bytes, 32)?;
        let length = number(&mut bytes)?;
        take(&mut bytes, length)?;
        let mut steps = Vec::new();
        while !bytes.is_empty() {
            // A branch longer than one chunk is verified chunk by chunk, so the
            // stored form carries the whole branch while every call, request and
            // page still handles at most HISTORY_CHUNK_STEPS of it.
            if steps.len() == MAX_JOIN_HISTORY_STEPS {
                return Err("join history exceeds step bounds");
            }
            steps.push(super::step::read_step(&mut bytes)?);
        }
        Ok(steps)
    }

    pub fn from_history(
        workspace: [u8; 32],
        digest: [u8; 32],
        encoded: &[u8],
    ) -> Result<Self, &'static str> {
        use super::storage::{number, take};
        // Bounded by `history_steps` (MAX_HISTORY_BYTES); the checkpoint
        // inside keeps its wire bound in `from_trusted_checkpoint`.
        let steps = Self::history_steps(encoded)?;
        let mut bytes = &encoded[5..];
        if take(&mut bytes, 32)? != digest {
            return Err("history checkpoint mismatch");
        }
        let length = number(&mut bytes)?;
        let checkpoint = take(&mut bytes, length)?;
        let mut proof = Self::from_trusted_checkpoint(workspace, digest, checkpoint)?;
        for (authorization, commit) in steps {
            proof.apply_transition(&authorization, &commit)?;
        }
        Ok(proof)
    }

    pub fn invitation_control(
        &self,
        key: [u8; 32],
    ) -> Result<Option<super::InvitationControl>, &'static str> {
        let controls =
            super::invitation_controls::decode(&super::invitation_controls::policy_bytes(
                self.verifier.group.group_context().extensions(),
            )?)?;
        Ok(controls.into_iter().find(|c| c.key == key))
    }

    pub fn apply_transition(
        &mut self,
        authorization: &MembershipAuthorization,
        commit: &[u8],
    ) -> Result<(), &'static str> {
        match authorization {
            MembershipAuthorization::Admission(auth) => self.apply_add(auth, commit),
            MembershipAuthorization::AdmissionBatch(auths) => {
                let appended = self.appended_history(authorization, commit)?;
                self.verifier.apply_add_batch(auths, commit)?;
                self.adopt_history(appended);
                Ok(())
            }
            MembershipAuthorization::Management(action) => self.apply_management(*action, commit),
            MembershipAuthorization::Revocation(_) | MembershipAuthorization::SelfUpdate => {
                let appended = self.appended_history(authorization, commit)?;
                self.verifier.apply_transition(authorization, commit)?;
                self.adopt_history(appended);
                Ok(())
            }
        }
    }

    fn appended_history(
        &self,
        authorization: &MembershipAuthorization,
        commit: &[u8],
    ) -> Result<AppendedHistory, &'static str> {
        if self.steps >= MAX_JOIN_HISTORY_STEPS || commit.is_empty() || commit.len() > MAX_BYTES {
            return Err("membership history exceeds bounds");
        }
        let mut history = self.history.clone();
        super::step::write_step(&mut history, authorization, commit)?;
        if history.len() > MAX_HISTORY_BYTES {
            return Err("membership history exceeds bounds");
        }
        Ok(AppendedHistory {
            history,
            steps: self.steps + 1,
        })
    }

    fn adopt_history(&mut self, appended: AppendedHistory) {
        self.history = appended.history;
        self.steps = appended.steps;
    }

    pub(super) fn from_workspace(workspace: &Workspace) -> Result<Self, &'static str> {
        let bytes = workspace.local_checkpoint()?;
        Self::from_local_checkpoint(workspace.id(), checkpoint_digest(&bytes)?, &bytes)
    }

    pub fn apply_management(
        &mut self,
        action: super::ManagementAction,
        commit: &[u8],
    ) -> Result<(), &'static str> {
        let appended =
            self.appended_history(&MembershipAuthorization::Management(action), commit)?;
        self.verifier.apply_management(action, commit)?;
        self.adopt_history(appended);
        Ok(())
    }
    pub fn apply_add(
        &mut self,
        authorization: &AdmissionAuthorization,
        commit: &[u8],
    ) -> Result<(), &'static str> {
        let appended = self.appended_history(
            &MembershipAuthorization::Admission(authorization.clone()),
            commit,
        )?;
        self.verifier.apply_add(authorization, commit)?;
        self.adopt_history(appended);
        Ok(())
    }
    pub(super) fn authorizes_issuer(&self, issuer: &[u8]) -> Result<bool, &'static str> {
        self.verifier.authorizes_issuer(issuer)
    }
    pub fn epoch(&self) -> u64 {
        self.verifier.epoch()
    }
    pub fn matches_workspace(&self, workspace: &Workspace) -> Result<bool, &'static str> {
        self.verifier.matches_workspace(workspace)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemberProfile, credential_identity};
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::signatures::Signer;

    struct Candidate {
        provider: OpenMlsRustCrypto,
        signer: SignatureKeyPair,
        profile: MemberProfile,
        endpoint: [u8; 32],
        package: KeyPackage,
    }
    impl Candidate {
        fn new(n: u8, workspace: [u8; 32]) -> Self {
            Self::bound_by(n, workspace, crate::test_key(u64::from(n) + 10))
        }
        /// A candidate whose endpoint is test key `n + 10`, with the binding
        /// signed by `binder` (a wrong key makes an invalid binding).
        fn bound_by(n: u8, workspace: [u8; 32], binder: &dyn crate::EndpointSigner) -> Self {
            Self::build(n, Some((workspace, binder)))
        }
        /// A candidate whose leaf carries no endpoint binding.
        fn unbound(n: u8) -> Self {
            Self::build(n, None)
        }
        fn build(n: u8, binding: Option<([u8; 32], &dyn crate::EndpointSigner)>) -> Self {
            let provider = OpenMlsRustCrypto::default();
            let signer = SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap();
            signer.store(provider.storage()).unwrap();
            let profile = MemberProfile::new([n; 32], "Alex").unwrap();
            let endpoint = crate::test_endpoint(u64::from(n) + 10);
            let credential = CredentialWithKey {
                credential: BasicCredential::new(credential_identity(endpoint, Some(&profile)))
                    .into(),
                signature_key: signer.to_public_vec().into(),
            };
            let mut builder = KeyPackage::builder().leaf_node_capabilities(crate::leaf_capabilities());
            if let Some((workspace, binder)) = binding {
                builder = builder.leaf_node_extensions(
                    crate::endpoint_binding(binder, workspace, profile.id(), signer.public())
                        .unwrap(),
                );
            }
            let package = builder
                .build(SUITE, &provider, &signer, credential)
                .unwrap()
                .key_package()
                .clone();
            Self {
                provider,
                signer,
                profile,
                endpoint,
                package,
            }
        }
        fn join(self, id: [u8; 32], welcome: MlsMessageOut) -> Workspace {
            let MlsMessageBodyIn::Welcome(welcome) =
                MlsMessageIn::tls_deserialize_exact(welcome.to_bytes().unwrap())
                    .unwrap()
                    .extract()
            else {
                panic!("not a Welcome")
            };
            let config = MlsGroupJoinConfig::builder()
                .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                .use_ratchet_tree_extension(true)
                .build();
            let group = StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)
                .unwrap()
                .into_group(&self.provider)
                .unwrap();
            Workspace {
                provider: self.provider,
                _signer: self.signer,
                group,
                id,
                endpoint: self.endpoint,
                member: Some(self.profile),
                admissions: Vec::new(),
                join_history: None,
                invitation_checkpoints: Vec::new(),
            }
        }
    }

    fn now_for_test() -> u64 {
        crate::invitation_controls::now().unwrap()
    }

    /// A raw administrator Add that carries `time` as its asserted time.
    fn add_raw(owner: &mut Workspace, package: &KeyPackage, time: u64) -> (Vec<u8>, MlsMessageOut) {
        owner.group.set_aad(asserted_time_aad(time));
        let (commit, welcome, _) = owner
            .group
            .add_members(&owner.provider, &owner._signer, std::slice::from_ref(package))
            .unwrap();
        (commit.to_bytes().unwrap(), welcome)
    }

    /// ADR A2 T12: the committer's asserted time, not the verifier's clock,
    /// decides expiry. Every verifier reaches the same answer.
    #[test]
    fn asserted_time_decides_invitation_expiry_for_every_verifier() {
        let invite = SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap();
        let invitation_key: [u8; 32] = invite.public().try_into().unwrap();
        // Expiry far in the past of every verifier's clock.
        let expires_at = 1_000;
        let mut admin = Workspace::create(crate::test_key(1), "Coordinator")
            .unwrap()
            .prepare_management(crate::ManagementAction::CreateInvitation(
                invitation_key,
                expires_at,
                false,
            ))
            .unwrap()
            .workspace;
        let checkpoint = admin.join_checkpoint().unwrap();
        let digest = checkpoint_digest(&checkpoint).unwrap();
        let candidate = Candidate::new(3, admin.id());
        let authorization = AdmissionAuthorization {
            invitation_key,
            grant_signature: admin
                ._signer
                .sign(&grant(admin.group.group_id(), &invitation_key))
                .unwrap()
                .try_into()
                .unwrap(),
            redemption_signature: invite
                .sign(&redemption(admin.group.group_id(), &invitation_key, &candidate.package).unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        };
        let (late, _) = add_raw(&mut admin, &candidate.package, expires_at);
        assert_eq!(admission_asserted_time(&late), Some(expires_at));
        admin
            .group
            .clear_pending_commit(admin.provider.storage())
            .unwrap();
        let (in_time, _) = add_raw(&mut admin, &candidate.package, expires_at - 1);
        for _ in 0..2 {
            let mut joiner = JoinProof::from_trusted_checkpoint(admin.id(), digest, &checkpoint).unwrap();
            let mut member =
                MembershipVerifier::from_trusted_checkpoint(admin.id(), digest, &checkpoint).unwrap();
            assert_eq!(
                joiner.apply_add(&authorization, &late),
                Err(crate::INVITATION_EXPIRED)
            );
            assert_eq!(
                member.apply_transition(&MembershipAuthorization::Admission(authorization.clone()), &late),
                Err(crate::INVITATION_EXPIRED)
            );
            // Before expiry by the committer's time: accepted, although every
            // local clock is long past the expiry.
            joiner.apply_add(&authorization, &in_time).unwrap();
            member
                .apply_transition(&MembershipAuthorization::Admission(authorization.clone()), &in_time)
                .unwrap();
            assert_eq!(joiner.epoch(), 2);
            assert_eq!(member.epoch(), 2);
        }
    }

    /// ADR A2 T11: every verifier rejects a leaf whose endpoint binding is
    /// missing, signed by another key, or made for another workspace.
    #[test]
    fn a_leaf_without_a_valid_endpoint_binding_is_rejected() {
        let invite = SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap();
        let invitation_key: [u8; 32] = invite.public().try_into().unwrap();
        let mut admin = Workspace::create(crate::test_key(1), "Coordinator")
            .unwrap()
            .prepare_management(crate::ManagementAction::CreateInvitation(
                invitation_key,
                0,
                false,
            ))
            .unwrap()
            .workspace;
        let checkpoint = admin.join_checkpoint().unwrap();
        let digest = checkpoint_digest(&checkpoint).unwrap();
        // The creator's own leaf is bound.
        verify_endpoint_binding(
            admin.provider.crypto(),
            admin.group.group_id(),
            admin.group.own_leaf_node().unwrap(),
        )
        .unwrap();
        let authorize = |admin: &Workspace, package: &KeyPackage| AdmissionAuthorization {
            invitation_key,
            grant_signature: admin
                ._signer
                .sign(&grant(admin.group.group_id(), &invitation_key))
                .unwrap()
                .try_into()
                .unwrap(),
            redemption_signature: invite
                .sign(&redemption(admin.group.group_id(), &invitation_key, package).unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        };
        let cases = [
            (
                Candidate::bound_by(7, admin.id(), crate::test_key(999)),
                "invalid endpoint binding",
            ),
            (
                Candidate::bound_by(8, [9; 32], crate::test_key(18)),
                "invalid endpoint binding",
            ),
            (Candidate::unbound(9), "member leaf has no endpoint binding"),
        ];
        for (candidate, error) in cases {
            let authorization = authorize(&admin, &candidate.package);
            let (commit, _) = add_raw(&mut admin, &candidate.package, now_for_test());
            admin
                .group
                .clear_pending_commit(admin.provider.storage())
                .unwrap();
            let mut proof = JoinProof::from_trusted_checkpoint(admin.id(), digest, &checkpoint).unwrap();
            assert_eq!(proof.apply_add(&authorization, &commit), Err(error));
        }
        let good = Candidate::new(10, admin.id());
        let authorization = authorize(&admin, &good.package);
        let (commit, _) = add_raw(&mut admin, &good.package, now_for_test());
        let mut proof = JoinProof::from_trusted_checkpoint(admin.id(), digest, &checkpoint).unwrap();
        proof.apply_add(&authorization, &commit).unwrap();
    }

    #[test]
    fn trusted_checkpoint_rejects_substitution_and_unauthorized_branch() {
        let invalid = BasicCredential::new(credential_identity(
            [0; 32],
            Some(&MemberProfile::new([1; 32], "Alex").unwrap()),
        ))
        .into();
        assert!(binding(&invalid).is_err());
        let invite = SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap();
        let invitation_key = invite.public().try_into().unwrap();
        let mut admin = Workspace::create(crate::test_key(1), "Coordinator")
            .unwrap()
            .prepare_management(crate::ManagementAction::CreateInvitation(
                invitation_key,
                0,
                false,
            ))
            .unwrap()
            .workspace;
        let checkpoint = admin.join_checkpoint().unwrap();
        let digest: [u8; 32] = checkpoint_digest(&checkpoint).unwrap();
        let mut proof =
            JoinProof::from_trusted_checkpoint(admin.id(), digest, &checkpoint).unwrap();
        assert!(proof.matches_workspace(&admin).unwrap());
        let other = Workspace::create(crate::test_key(2), "Coordinator")
            .unwrap()
            .join_checkpoint()
            .unwrap();
        assert!(JoinProof::from_trusted_checkpoint(admin.id(), digest, &other).is_err());
        assert!(JoinProof::from_trusted_checkpoint([99; 32], digest, &checkpoint).is_err());
        // The last byte is in the tree, outside the pinned digest: the pin's
        // signed tree hash must still reject the substituted tree.
        let mut damaged = checkpoint.clone();
        let end = damaged.len() - 1;
        damaged[end] ^= 1;
        assert_eq!(checkpoint_digest(&damaged).unwrap(), digest);
        assert!(JoinProof::from_trusted_checkpoint(admin.id(), digest, &damaged).is_err());
        // A tree from another group with the same pin also fails.
        let parts = checkpoint_parts(&checkpoint, CheckpointBound::Wire).unwrap();
        let other_parts = checkpoint_parts(&other, CheckpointBound::Wire).unwrap();
        let mut swapped = CHECKPOINT_MAGIC.to_vec();
        for part in [parts.pin, other_parts.tree] {
            swapped.extend((part.len() as u32).to_be_bytes());
            swapped.extend(part);
        }
        assert!(JoinProof::from_trusted_checkpoint(admin.id(), digest, &swapped).is_err());
        // A damaged pin: even a caller supplying the damaged hash cannot bypass
        // MLS signature validation.
        let mut damaged = checkpoint.clone();
        damaged[9 + parts.pin.len() - 1] ^= 1;
        assert!(
            JoinProof::from_trusted_checkpoint(
                admin.id(),
                checkpoint_digest(&damaged).unwrap(),
                &damaged
            )
            .is_err()
        );
        assert!(
            JoinProof::from_trusted_checkpoint(admin.id(), [0; 32], &vec![0; MAX_CHECKPOINT + 1])
                .is_err()
        );

        let helper = Candidate::new(3, admin.id());
        let grant_signature = admin
            ._signer
            .sign(&grant(admin.group.group_id(), &invitation_key))
            .unwrap()
            .try_into()
            .unwrap();
        let authorize = |group: &GroupId, package: &KeyPackage| AdmissionAuthorization {
            invitation_key,
            grant_signature,
            redemption_signature: invite
                .sign(&redemption(group, &invitation_key, package).unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        };
        let helper_auth = authorize(admin.group.group_id(), &helper.package);
        // An Add without the committer's asserted time is rejected.
        let (untimed, _, _) = admin
            .group
            .add_members(
                &admin.provider,
                &admin._signer,
                std::slice::from_ref(&helper.package),
            )
            .unwrap();
        assert_eq!(
            proof.apply_add(&helper_auth, &untimed.to_bytes().unwrap()),
            Err("admission requires the committer's asserted time")
        );
        admin
            .group
            .clear_pending_commit(admin.provider.storage())
            .unwrap();
        let (commit, welcome) = add_raw(&mut admin, &helper.package, now_for_test());
        let mut invalid_auth = authorize(admin.group.group_id(), &helper.package);
        invalid_auth.grant_signature[0] ^= 1;
        // Epochs start at 1: the invitation registration is epoch 1.
        assert!(proof.apply_add(&invalid_auth, &commit).is_err());
        assert_eq!(proof.epoch(), 1);
        let mut trailing = commit.clone();
        trailing.push(0);
        assert!(proof.apply_add(&helper_auth, &trailing).is_err());
        assert_eq!(proof.epoch(), 1);
        proof.apply_add(&helper_auth, &commit).unwrap();
        assert!(proof.apply_add(&helper_auth, &commit).is_err()); // replay
        assert_eq!(proof.epoch(), 2);
        admin.group.merge_pending_commit(&admin.provider).unwrap();
        let mut helper = helper.join(admin.id(), welcome);
        assert!(proof.matches_workspace(&helper).unwrap());
        assert!(helper.join_checkpoint().is_err()); // ordinary member cannot issue a new trust root

        // ADR A2 step 2 (T10): an ordinary member cannot commit an Add, even
        // for a valid grant and redemption. Only administrators admit.
        let joined = Candidate::new(4, admin.id());
        let joined_auth = authorize(helper.group.group_id(), &joined.package);
        let (member_commit, _) = add_raw(&mut helper, &joined.package, now_for_test());
        assert_eq!(
            proof.apply_add(&joined_auth, &member_commit),
            Err("only an administrator may commit an Add")
        );
        assert_eq!(proof.epoch(), 2);
        helper
            .group
            .clear_pending_commit(helper.provider.storage())
            .unwrap();

        // An independent copy of the administrator at the same epoch.
        let mut fork = admin.provisional_copy().unwrap();
        let (commit, welcome) = add_raw(&mut admin, &joined.package, now_for_test());
        let mismatched = authorize(admin.group.group_id(), &Candidate::new(5, admin.id()).package);
        assert!(proof.apply_add(&mismatched, &commit).is_err());
        assert_eq!(proof.epoch(), 2);
        proof.apply_add(&joined_auth, &commit).unwrap();
        admin.group.merge_pending_commit(&admin.provider).unwrap();
        let mut joined = joined.join(admin.id(), welcome);
        assert!(proof.matches_workspace(&joined).unwrap());
        assert!(!proof.matches_workspace(&fork).unwrap()); // same ID and admin, older branch
        let encrypted = joined
            .group
            .create_message(
                &joined.provider,
                &joined._signer,
                b"arbitrary application bytes",
            )
            .unwrap();
        let message = MlsMessageIn::tls_deserialize_exact(encrypted.to_bytes().unwrap()).unwrap();
        assert!(matches!(
            message.extract(),
            MlsMessageBodyIn::PrivateMessage(_)
        ));

        // A fully MLS-valid unauthorized Welcome at the SAME epoch/ID/admin
        // roster is not the authorized branch. This catches more than staleness.
        // The grant is signed by an ordinary member, not an administrator.
        let before_fork = fork.join_checkpoint().unwrap();
        let uninvited = Candidate::new(6, admin.id());
        let mut forged = authorize(fork.group.group_id(), &uninvited.package);
        forged.grant_signature = helper
            ._signer
            .sign(&grant(fork.group.group_id(), &invitation_key))
            .unwrap()
            .try_into()
            .unwrap();
        let (bad_commit, bad_welcome) = add_raw(&mut fork, &uninvited.package, now_for_test());
        fork.group.merge_pending_commit(&fork.provider).unwrap();
        let uninvited = uninvited.join(fork.id(), bad_welcome);
        assert_eq!(uninvited.epoch(), proof.epoch());
        assert_eq!(uninvited.id(), joined.id());
        assert_eq!(uninvited.group.extensions(), joined.group.extensions());
        assert!(!proof.matches_workspace(&uninvited).unwrap());
        // Verify authorization rejection from the correct previous epoch too.
        // A separate verifier starts at the pre-fork checkpoint, so this
        // negative assertion tests grant authority rather than epoch mismatch.
        let mut fork_proof = JoinProof::from_trusted_checkpoint(
            admin.id(),
            checkpoint_digest(&before_fork).unwrap(),
            &before_fork,
        )
        .unwrap();
        assert_eq!(
            fork_proof.apply_add(&forged, &bad_commit),
            Err("unapproved invitation")
        );
        assert_eq!(fork_proof.epoch(), 2);
        assert_eq!(proof.epoch(), 3);
        assert!(proof.matches_workspace(&joined).unwrap());
    }
}
