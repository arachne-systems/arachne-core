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

const MAX_BYTES: usize = 64 * 1024;
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
    Management(super::ManagementAction),
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
    provider: OpenMlsRustCrypto,
    pub(super) group: PublicGroup,
}

pub(super) fn authority(
    extensions: &Extensions<GroupContext>,
) -> Result<Vec<Vec<u8>>, &'static str> {
    let bytes = &extensions.unknown(AUTHORITY).ok_or("missing authority")?.0;
    if bytes.len() < 2
        || !matches!(bytes[0], 1 | 2)
        || !(1..=64).contains(&bytes[1])
        || bytes.len() < 2 + usize::from(bytes[1]) * 32
    {
        return Err("invalid authority encoding");
    }
    let end = 2 + usize::from(bytes[1]) * 32;
    if bytes[0] == 1 {
        if bytes.len() != end {
            return Err("invalid authority length");
        }
    } else {
        super::invitation_controls::decode(&bytes[end..])?;
    }
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
        .strip_prefix(b"data-fabric/candidate-member/v2/")
        .ok_or("member credential upgrade required")?;
    if bytes.len() != 64 || bytes[..32] == [0; 32] || bytes[32..] == [0; 32] {
        return Err("invalid member binding");
    }
    Ok((
        bytes[..32].try_into().unwrap(),
        bytes[32..].try_into().unwrap(),
    ))
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
        let bytes = self
            .group
            .export_group_info_with_additional_extensions(
                self.provider.crypto(),
                &self._signer,
                true,
                self.name_checkpoint_extension()?,
            )
            .map_err(|_| "checkpoint creation failed")?
            .to_bytes()
            .map_err(|_| "checkpoint encoding failed")?;
        if bytes.len() > MAX_BYTES {
            return Err("checkpoint exceeds bounds");
        }
        Ok(bytes)
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
        Self::from_checkpoint_within(workspace, digest, bytes, MAX_BYTES)
    }

    fn from_checkpoint_within(
        workspace: [u8; 32],
        digest: [u8; 32],
        bytes: &[u8],
        limit: usize,
    ) -> Result<Self, &'static str> {
        if bytes.len() > limit {
            return Err("checkpoint exceeds bounds");
        }
        if <[u8; 32]>::from(Sha256::digest(bytes)) != digest {
            return Err("checkpoint does not match invitation");
        }
        let message =
            MlsMessageIn::tls_deserialize_exact(bytes).map_err(|_| "invalid checkpoint")?;
        let MlsMessageBodyIn::GroupInfo(info) = message.extract() else {
            return Err("expected GroupInfo");
        };
        if info.group_id().as_slice() != workspace || info.ciphersuite() != SUITE {
            return Err("wrong checkpoint workspace");
        }
        let tree = info
            .extensions()
            .ratchet_tree()
            .ok_or("missing checkpoint tree")?
            .ratchet_tree()
            .clone();
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
            let (id, endpoint) = binding(&member.credential)?;
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
        Ok(Self { provider, group })
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
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err("not a commit");
        };
        if staged.queued_proposals().count() != authorizations.len()
            || staged.group_context().extensions() != self.group.group_context().extensions()
        {
            return Err("invitation authorizes only Adds without policy changes");
        }
        if let Some(leaf) = staged.update_path_leaf_node()
            && (leaf.credential() != &actor.credential
                || leaf.signature_key().as_slice() != actor.signature_key)
        {
            return Err("admission cannot replace committer identity");
        }
        let adds: Vec<_> = staged.add_proposals().collect();
        if adds.len() != authorizations.len() {
            return Err("admission authorizes only Add proposals");
        }
        let mut bindings = std::collections::BTreeSet::new();
        let admins = authority(self.group.group_context().extensions())?;
        let crypto = self.provider.crypto();
        for (authorization, add) in authorizations.iter().zip(adds) {
            let package = add.add_proposal().key_package();
            let (id, endpoint) = binding(package.leaf_node().credential())?;
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
                None,
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
        let bytes = workspace
            .group
            .export_group_info(workspace.provider.crypto(), &workspace._signer, true)
            .map_err(|_| "group comparison export failed")?
            .to_bytes()
            .map_err(|_| "group comparison encoding failed")?;
        Self::from_checkpoint_within(workspace.id(), Sha256::digest(&bytes).into(), &bytes, MAX_LOCAL_STATE_BYTES)
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

    pub(super) fn verify_management(
        &self,
        action: super::ManagementAction,
        commit: &[u8],
    ) -> Result<(), &'static str> {
        self.management_commit(action, commit).map(|_| ())
    }

    fn management_commit(
        &self,
        action: super::ManagementAction,
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
        let sender = processed.sender().clone();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err("not a management commit");
        };
        super::management::verify(
            self.provider.crypto(),
            &self.group,
            &sender,
            &staged,
            action,
        )?;
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
        if bytes.len() > MAX_BYTES - 41 {
            return Err("checkpoint exceeds inline history bounds");
        }
        let verifier = MembershipVerifier::from_trusted_checkpoint(workspace, digest, bytes)?;
        let message =
            MlsMessageIn::tls_deserialize_exact(bytes).map_err(|_| "invalid checkpoint")?;
        let MlsMessageBodyIn::GroupInfo(info) = message.extract() else {
            return Err("expected GroupInfo");
        };
        let name_checkpoint = info
            .extensions()
            .unknown(super::name::EXTENSION)
            .map(|e| super::name::NameState::decode(&e.0))
            .transpose()?
            .unwrap_or_default();
        let mut history = b"DFJH\x01".to_vec();
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
        if encoded.len() > limit
            || !(encoded.starts_with(b"DFJH\x01") || encoded.starts_with(b"DFJH\x02"))
        {
            return Err("invalid join history");
        }
        let version = encoded[4];
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
            steps.push(Self::read_step(&mut bytes, version == 2)?);
        }
        Ok(steps)
    }

    fn read_step(
        rest: &mut &[u8],
        tagged: bool,
    ) -> Result<(MembershipAuthorization, Vec<u8>), &'static str> {
        use super::storage::{number, take};
        let mut bytes = *rest;
        let step = {
            let tag = if tagged { take(&mut bytes, 1)?[0] } else { 0 };
            let authorization = match tag {
                0 => MembershipAuthorization::Admission(AdmissionAuthorization {
                    invitation_key: take(&mut bytes, 32)?.try_into().unwrap(),
                    grant_signature: take(&mut bytes, 64)?.try_into().unwrap(),
                    redemption_signature: take(&mut bytes, 64)?.try_into().unwrap(),
                }),
                11 => {
                    let count = u16::from_be_bytes(take(&mut bytes, 2)?.try_into().unwrap()) as usize;
                    if count == 0 || count > super::MAX_ADMISSION_BATCH {
                        return Err("invalid admission batch size");
                    }
                    MembershipAuthorization::AdmissionBatch(
                        (0..count)
                            .map(|_| {
                                Ok(AdmissionAuthorization {
                                    invitation_key: take(&mut bytes, 32)?.try_into().unwrap(),
                                    grant_signature: take(&mut bytes, 64)?.try_into().unwrap(),
                                    redemption_signature: take(&mut bytes, 64)?.try_into().unwrap(),
                                })
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                    )
                }
                1..=10 => {
                    let id = take(&mut bytes, 32)?.try_into().unwrap();
                    MembershipAuthorization::Management(match tag {
                        1 => super::ManagementAction::Promote(id),
                        2 => super::ManagementAction::Demote(id),
                        3 => super::ManagementAction::Remove(id),
                        4 => super::ManagementAction::Leave(
                            id,
                            take(&mut bytes, 64)?.try_into().unwrap(),
                        ),
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
            let length = number(&mut bytes)?;
            if length == 0 {
                return Err("empty membership history commit");
            }
            (authorization, take(&mut bytes, length)?.to_vec())
        };
        *rest = bytes;
        Ok(step)
    }

    pub fn from_history(
        workspace: [u8; 32],
        digest: [u8; 32],
        encoded: &[u8],
    ) -> Result<Self, &'static str> {
        use super::storage::{number, take};
        if encoded.len() > MAX_BYTES {
            return Err("invalid join history");
        }
        let steps = Self::history_steps(encoded)?;
        let mut bytes = &encoded[5..];
        if take(&mut bytes, 32)? != digest {
            return Err("history checkpoint mismatch");
        }
        let length = number(&mut bytes)?;
        let checkpoint = take(&mut bytes, length)?;
        let mut proof = Self::from_trusted_checkpoint(workspace, digest, checkpoint)?;
        if encoded[4] == 2 {
            proof.history[4] = 2;
        }
        for (authorization, commit) in steps {
            proof.apply_transition(&authorization, &commit)?;
        }
        Ok(proof)
    }

    pub fn invitation_control(
        &self,
        key: [u8; 32],
    ) -> Result<Option<super::InvitationControl>, &'static str> {
        let (_, controls) =
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
        if history[4] == 1 && !matches!(authorization, MembershipAuthorization::Admission(_)) {
            let steps = Self::history_steps_with_limit(&self.history, MAX_HISTORY_BYTES)?;
            let length = u32::from_be_bytes(history[37..41].try_into().unwrap()) as usize;
            history.truncate(41 + length);
            history[4] = 2;
            for (auth, bytes) in &steps {
                Self::write_step(&mut history, auth, bytes);
            }
        }
        Self::write_step(&mut history, authorization, commit);
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

    fn write_step(history: &mut Vec<u8>, authorization: &MembershipAuthorization, commit: &[u8]) {
        match authorization {
            MembershipAuthorization::Admission(auth) => {
                if history[4] >= 2 {
                    history.push(0);
                }
                history.extend(auth.invitation_key);
                history.extend(auth.grant_signature);
                history.extend(auth.redemption_signature);
            }
            MembershipAuthorization::AdmissionBatch(auths) => {
                history.push(11);
                history.extend((auths.len() as u16).to_be_bytes());
                for auth in auths {
                    history.extend(auth.invitation_key);
                    history.extend(auth.grant_signature);
                    history.extend(auth.redemption_signature);
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
                history.push(tag);
                history.extend(id);
                if let super::ManagementAction::Leave(_, signature) = action {
                    history.extend(signature);
                }
                if let super::ManagementAction::CreateInvitation(_, expires, personal) = action {
                    history.extend(expires.to_be_bytes());
                    history.push(u8::from(*personal));
                }
                if let super::ManagementAction::CreateAutomaticInvitation(_, expires)
                | super::ManagementAction::CreateRequestInvitation(_, expires) = action
                {
                    history.extend(expires.to_be_bytes());
                }
                if let super::ManagementAction::ApproveInvitation(_, package)
                | super::ManagementAction::DeclineInvitationRequest(_, package) = action
                {
                    history.extend(package);
                }
            }
        }
        history.extend((commit.len() as u32).to_be_bytes());
        history.extend(commit);
    }

    pub(super) fn from_workspace(workspace: &Workspace) -> Result<Self, &'static str> {
        let bytes = workspace
            .group
            .export_group_info(workspace.provider.crypto(), &workspace._signer, true)
            .map_err(|_| "group comparison export failed")?
            .to_bytes()
            .map_err(|_| "group comparison encoding failed")?;
        Self::from_trusted_checkpoint(workspace.id(), Sha256::digest(&bytes).into(), &bytes)
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
    pub(super) fn verify_management(
        &self,
        action: super::ManagementAction,
        commit: &[u8],
    ) -> Result<(), &'static str> {
        self.verifier.verify_management(action, commit)
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
        fn new(n: u8) -> Self {
            let provider = OpenMlsRustCrypto::default();
            let signer = SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap();
            signer.store(provider.storage()).unwrap();
            let profile = MemberProfile::new([n; 32], "Alex").unwrap();
            let endpoint = [n + 10; 32];
            let credential = CredentialWithKey {
                credential: BasicCredential::new(credential_identity(endpoint, Some(&profile)))
                    .into(),
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

    #[test]
    fn trusted_checkpoint_rejects_substitution_and_unauthorized_branch() {
        let invalid = BasicCredential::new(credential_identity(
            [0; 32],
            Some(&MemberProfile::new([1; 32], "Alex").unwrap()),
        ))
        .into();
        assert!(binding(&invalid).is_err());
        let mut admin = Workspace::create([1; 32], "Coordinator").unwrap();
        let checkpoint = admin.join_checkpoint().unwrap();
        let digest: [u8; 32] = Sha256::digest(&checkpoint).into();
        let mut proof =
            JoinProof::from_trusted_checkpoint(admin.id(), digest, &checkpoint).unwrap();
        assert!(proof.matches_workspace(&admin).unwrap());
        let other = Workspace::create([2; 32], "Coordinator")
            .unwrap()
            .join_checkpoint()
            .unwrap();
        assert!(JoinProof::from_trusted_checkpoint(admin.id(), digest, &other).is_err());
        assert!(JoinProof::from_trusted_checkpoint([99; 32], digest, &checkpoint).is_err());
        let mut damaged = checkpoint.clone();
        let end = damaged.len() - 1;
        damaged[end] ^= 1;
        assert!(JoinProof::from_trusted_checkpoint(admin.id(), digest, &damaged).is_err());
        // Even a caller supplying the damaged hash cannot bypass MLS signature validation.
        assert!(
            JoinProof::from_trusted_checkpoint(
                admin.id(),
                Sha256::digest(&damaged).into(),
                &damaged
            )
            .is_err()
        );
        assert!(
            JoinProof::from_trusted_checkpoint(admin.id(), [0; 32], &vec![0; MAX_BYTES + 1])
                .is_err()
        );

        let helper = Candidate::new(3);
        let invite = SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap();
        let invitation_key = invite.public().try_into().unwrap();
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
        let (commit, welcome, _) = admin
            .group
            .add_members(
                &admin.provider,
                &admin._signer,
                std::slice::from_ref(&helper.package),
            )
            .unwrap();
        let commit = commit.to_bytes().unwrap();
        let mut invalid_auth = authorize(admin.group.group_id(), &helper.package);
        invalid_auth.grant_signature[0] ^= 1;
        assert!(proof.apply_add(&invalid_auth, &commit).is_err());
        assert_eq!(proof.epoch(), 0);
        let mut trailing = commit.clone();
        trailing.push(0);
        assert!(proof.apply_add(&helper_auth, &trailing).is_err());
        assert_eq!(proof.epoch(), 0);
        proof.apply_add(&helper_auth, &commit).unwrap();
        assert!(proof.apply_add(&helper_auth, &commit).is_err()); // replay
        assert_eq!(proof.epoch(), 1);
        admin.group.merge_pending_commit(&admin.provider).unwrap();
        let mut helper = helper.join(admin.id(), welcome);
        assert!(proof.matches_workspace(&helper).unwrap());
        assert!(helper.join_checkpoint().is_err()); // ordinary member cannot issue a new trust root

        // Admin is no longer involved. An ordinary helper fulfills the existing grant.
        let fork_key = crate::StorageKey::derive(&[42; 32]).unwrap();
        let fork_snapshot = helper.seal(&fork_key).unwrap();
        let mut fork =
            Workspace::restore(&fork_key, helper.endpoint, helper.id(), &fork_snapshot).unwrap();
        let joined = Candidate::new(4);
        let joined_auth = authorize(helper.group.group_id(), &joined.package);
        let (commit, welcome, _) = helper
            .group
            .add_members(
                &helper.provider,
                &helper._signer,
                std::slice::from_ref(&joined.package),
            )
            .unwrap();
        let commit = commit.to_bytes().unwrap();
        let mismatched = authorize(helper.group.group_id(), &Candidate::new(5).package);
        assert!(proof.apply_add(&mismatched, &commit).is_err());
        assert_eq!(proof.epoch(), 1);
        proof.apply_add(&joined_auth, &commit).unwrap();
        helper.group.merge_pending_commit(&helper.provider).unwrap();
        let mut joined = joined.join(helper.id(), welcome);
        assert!(proof.matches_workspace(&joined).unwrap());
        assert!(!proof.matches_workspace(&admin).unwrap()); // same ID and admin, older branch
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
        let uninvited = Candidate::new(6);
        let mut forged = authorize(fork.group.group_id(), &uninvited.package);
        forged.grant_signature = fork
            ._signer
            .sign(&grant(fork.group.group_id(), &invitation_key))
            .unwrap()
            .try_into()
            .unwrap();
        let (bad_commit, bad_welcome, _) = fork
            .group
            .add_members(
                &fork.provider,
                &fork._signer,
                std::slice::from_ref(&uninvited.package),
            )
            .unwrap();
        fork.group.merge_pending_commit(&fork.provider).unwrap();
        let uninvited = uninvited.join(fork.id(), bad_welcome);
        assert_eq!(uninvited.epoch(), proof.epoch());
        assert_eq!(uninvited.id(), joined.id());
        assert_eq!(uninvited.group.extensions(), joined.group.extensions());
        assert!(!proof.matches_workspace(&uninvited).unwrap());
        // Verify authorization rejection from the correct previous epoch too.
        // A separate verifier starts at the pre-fork checkpoint, so this
        // negative assertion tests grant authority rather than epoch mismatch.
        let before_fork = admin.join_checkpoint().unwrap();
        let mut fork_proof = JoinProof::from_trusted_checkpoint(
            admin.id(),
            Sha256::digest(&before_fork).into(),
            &before_fork,
        )
        .unwrap();
        assert_eq!(
            fork_proof.apply_add(&forged, &bad_commit.to_bytes().unwrap()),
            Err("unapproved invitation")
        );
        assert_eq!(fork_proof.epoch(), 1);
        assert_eq!(proof.epoch(), 2);
        assert!(proof.matches_workspace(&joined).unwrap());
    }
}
