//! Fixed ordinary-member invitation and request codec. No addresses or UI types.
use super::{
    AdmissionAuthorization, JoinProof, MembershipAuthorization, SUITE, Workspace, bootstrap,
    storage,
};
use openmls::prelude::{
    tls_codec::{Deserialize, Serialize},
    *,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{OpenMlsProvider, crypto::OpenMlsCrypto, signatures::Signer};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

const TOKEN: &[u8; 5] = b"DFIV\x01";
const REQUEST: &[u8; 5] = b"DFJR\x01";
pub(super) const PUBLIC: usize = 261;
pub(super) const TOKEN_SIZE: usize = PUBLIC + 32;
const REQUEST_HEADER: usize = 5 + PUBLIC + 64;
const CHECKPOINT_REQUEST_SIZE: usize = PUBLIC + 64;
pub(super) const MAX_REQUEST: usize = REQUEST_HEADER + 16 * 1024;
pub(super) const MAX_RETAINED_CHECKPOINTS: usize = 256;
const MAX_RETAINED_CHECKPOINT_BYTES: usize = 2 * 1024 * 1024;

/// Reusable bearer authorization. Never log or publish its secret token.
/// Receiving it via a trusted human/application channel establishes the initial
/// workspace trust root; self-consistent signatures alone do not identify a person.
pub struct Invitation {
    grant: [u8; PUBLIC],
    secret: Zeroizing<[u8; 32]>,
}

#[derive(Clone)]
pub(super) struct RetainedInvitationCheckpoint {
    pub grant: [u8; PUBLIC],
    pub checkpoint: Vec<u8>,
}

/// Accepted membership transitions in epoch order, each with the authorization
/// that permitted it.
type MembershipSteps = Vec<(MembershipAuthorization, Vec<u8>)>;

/// One accepted transition, borrowed from wherever this owner already keeps it.
/// Retained admissions store the authorization and commit separately from the
/// join history's steps, so this names both without copying either.
enum AcceptedStep<'a> {
    History(&'a (MembershipAuthorization, Vec<u8>)),
    Admission(&'a RetainedAdmission),
}

impl AcceptedStep<'_> {
    fn commit(&self) -> &[u8] {
        match self {
            Self::History((_, commit)) => commit,
            Self::Admission(admission) => &admission.reply.commit,
        }
    }
    fn to_step(&self) -> (MembershipAuthorization, Vec<u8>) {
        match self {
            Self::History((authorization, commit)) => (authorization.clone(), commit.clone()),
            Self::Admission(admission) => (
                MembershipAuthorization::Admission(admission.reply.authorization.clone()),
                admission.reply.commit.to_vec(),
            ),
        }
    }
}

/// Place one accepted transition at its epoch. Transitions outside the range
/// are ignored; a second, different commit for an epoch already filled means
/// the records disagree, and `None` sends the caller to full verification.
fn place_accepted<'a>(
    slots: &mut [Option<AcceptedStep<'a>>],
    start: u64,
    candidate: AcceptedStep<'a>,
) -> Option<()> {
    let epoch = commit_epoch(candidate.commit())?;
    let Some(index) = epoch
        .checked_sub(start)
        .and_then(|index| usize::try_from(index).ok())
    else {
        return Some(());
    };
    match slots.get_mut(index) {
        None => Some(()),
        Some(Some(existing)) if existing.commit() != candidate.commit() => None,
        Some(Some(_)) => Some(()),
        Some(slot) => {
            *slot = Some(candidate);
            Some(())
        }
    }
}

/// The epoch a signed commit advances from. Reading the epoch is parsing, not
/// verification: callers must already know the commit is one they accepted.
fn commit_epoch(commit: &[u8]) -> Option<u64> {
    MlsMessageIn::tls_deserialize_exact(commit)
        .ok()
        .and_then(|message| message.try_into_protocol_message().ok())
        .map(|message| message.epoch().as_u64())
}

/// The epoch a checkpoint describes, without building the public group. Used
/// only for checkpoints this owner issued and retained itself.
fn checkpoint_epoch(checkpoint: &[u8]) -> Result<u64, &'static str> {
    let message =
        MlsMessageIn::tls_deserialize_exact(checkpoint).map_err(|_| "invalid checkpoint")?;
    let MlsMessageBodyIn::GroupInfo(info) = message.extract() else {
        return Err("expected GroupInfo");
    };
    Ok(info.epoch().as_u64())
}

fn binding_message(grant: &[u8]) -> Vec<u8> {
    let mut bytes = b"data-fabric/invitation-checkpoint/v1/".to_vec();
    bytes.extend(&grant[..197]);
    bytes
}
fn checkpoint_request_message(grant: &[u8], requester: [u8; 32], responder: [u8; 32]) -> Vec<u8> {
    let mut bytes = b"data-fabric/invitation-checkpoint-request/v1/".to_vec();
    bytes.extend(grant);
    bytes.extend(requester);
    bytes.extend(responder);
    bytes
}
fn verify_grant(provider: &OpenMlsRustCrypto, grant: &[u8]) -> Result<(), &'static str> {
    if grant.len() != PUBLIC || !grant.starts_with(TOKEN) {
        return Err("invalid invitation format");
    }
    let workspace = GroupId::from_slice(&grant[5..37]);
    let invite_key = grant[101..133].try_into().unwrap();
    provider
        .crypto()
        .verify_signature(
            SUITE.signature_algorithm(),
            &bootstrap::grant(&workspace, invite_key),
            &grant[69..101],
            &grant[133..197],
        )
        .map_err(|_| "invalid invitation grant signature")?;
    provider
        .crypto()
        .verify_signature(
            SUITE.signature_algorithm(),
            &binding_message(grant),
            &grant[69..101],
            &grant[197..261],
        )
        .map_err(|_| "invalid invitation checkpoint signature")
}
impl Invitation {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != TOKEN_SIZE {
            return Err("invalid invitation size");
        }
        let provider = OpenMlsRustCrypto::default();
        verify_grant(&provider, &bytes[..PUBLIC])?;
        let value = Self {
            grant: bytes[..PUBLIC].try_into().unwrap(),
            secret: Zeroizing::new(bytes[PUBLIC..].try_into().unwrap()),
        };
        let signer = value.signer();
        let challenge = b"data-fabric/invitation-key-check/v1";
        let signature = signer
            .sign(challenge)
            .map_err(|_| "invalid invitation key")?;
        provider
            .crypto()
            .verify_signature(
                SUITE.signature_algorithm(),
                challenge,
                &value.grant[101..133],
                &signature,
            )
            .map_err(|_| "invitation bearer key mismatch")?;
        Ok(value)
    }
    pub fn export_secret_token(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(self.grant.to_vec());
        bytes.extend(self.secret.as_slice());
        bytes
    }
    pub fn key(&self) -> [u8; 32] {
        self.grant[101..133].try_into().unwrap()
    }
    pub fn workspace_id(&self) -> [u8; 32] {
        self.grant[5..37].try_into().unwrap()
    }
    pub fn checkpoint_digest(&self) -> [u8; 32] {
        self.grant[37..69].try_into().unwrap()
    }
    pub fn public_grant(&self) -> &[u8] {
        &self.grant
    }
    pub fn join_proof(&self, checkpoint: &[u8]) -> Result<JoinProof, &'static str> {
        let proof = JoinProof::from_trusted_checkpoint(
            self.workspace_id(),
            self.checkpoint_digest(),
            checkpoint,
        )?;
        if !proof.authorizes_issuer(&self.grant[69..101])? {
            return Err("invitation issuer is not a checkpoint administrator");
        }
        Ok(proof)
    }
    /// Prove bearer possession without transmitting the invitation secret.
    /// Both authenticated Iroh endpoint identities are bound to prevent replay
    /// through a substituted bootstrap peer.
    pub fn checkpoint_request(
        &self,
        requester: [u8; 32],
        responder: [u8; 32],
    ) -> Result<Vec<u8>, &'static str> {
        if requester == [0; 32] || responder == [0; 32] || requester == responder {
            return Err("invalid checkpoint request endpoints");
        }
        let mut bytes = self.grant.to_vec();
        bytes.extend(
            self.signer()
                .sign(&checkpoint_request_message(
                    &self.grant,
                    requester,
                    responder,
                ))
                .map_err(|_| "checkpoint request signing failed")?,
        );
        Ok(bytes)
    }
    fn signer(&self) -> SignatureKeyPair {
        SignatureKeyPair::from_raw(
            SUITE.signature_algorithm(),
            self.secret.to_vec(),
            self.grant[101..133].to_vec(),
        )
    }
    pub(super) fn request(&self, package: &KeyPackage) -> Result<Vec<u8>, &'static str> {
        let proof = self
            .signer()
            .sign(&bootstrap::redemption(
                &GroupId::from_slice(&self.workspace_id()),
                self.grant[101..133].try_into().unwrap(),
                package,
            )?)
            .map_err(|_| "redemption signing failed")?;
        let mut bytes = REQUEST.to_vec();
        bytes.extend(self.grant);
        bytes.extend(proof);
        bytes.extend(
            package
                .tls_serialize_detached()
                .map_err(|_| "KeyPackage encoding failed")?,
        );
        if bytes.len() > MAX_REQUEST {
            return Err("admission request exceeds bounds");
        }
        Ok(bytes)
    }
}

pub struct ValidatedAdmission {
    pub(super) workspace: [u8; 32],
    pub(super) checkpoint_digest: [u8; 32],
    pub(super) issuer: [u8; 32],
    pub(super) package: KeyPackage,
    pub(super) authorization: AdmissionAuthorization,
    digest: [u8; 32],
    endpoint: [u8; 32],
}
pub(super) fn decode_request(
    provider: &OpenMlsRustCrypto,
    bytes: &[u8],
) -> Result<ValidatedAdmission, &'static str> {
    decode_request_with_grant_check(provider, bytes, true)
}

fn decode_request_with_grant_check(
    provider: &OpenMlsRustCrypto,
    bytes: &[u8],
    check_grant: bool,
) -> Result<ValidatedAdmission, &'static str> {
    if bytes.len() <= REQUEST_HEADER || bytes.len() > MAX_REQUEST || !bytes.starts_with(REQUEST) {
        return Err("invalid admission request");
    }
    let grant = &bytes[5..5 + PUBLIC];
    if check_grant {
        verify_grant(provider, grant)?;
    }
    let package = KeyPackageIn::tls_deserialize_exact(&bytes[REQUEST_HEADER..])
        .map_err(|_| "invalid admission KeyPackage")?
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|_| "admission KeyPackage invalid or expired")?;
    if package.ciphersuite() != SUITE {
        return Err("wrong admission ciphersuite");
    }
    let workspace: [u8; 32] = grant[5..37].try_into().unwrap();
    let authorization = AdmissionAuthorization {
        invitation_key: grant[101..133].try_into().unwrap(),
        grant_signature: grant[133..197].try_into().unwrap(),
        redemption_signature: bytes[5 + PUBLIC..REQUEST_HEADER].try_into().unwrap(),
    };
    provider
        .crypto()
        .verify_signature(
            SUITE.signature_algorithm(),
            &bootstrap::redemption(
                &GroupId::from_slice(&workspace),
                &authorization.invitation_key,
                &package,
            )?,
            &authorization.invitation_key,
            &authorization.redemption_signature,
        )
        .map_err(|_| "redemption does not match KeyPackage")?;
    Ok(ValidatedAdmission {
        workspace,
        checkpoint_digest: grant[37..69].try_into().unwrap(),
        issuer: grant[69..101].try_into().unwrap(),
        package,
        authorization,
        digest: Sha256::digest(bytes).into(),
        endpoint: [0; 32],
    })
}

pub enum AdmissionAssessment {
    Ready(ValidatedAdmission),
    ApprovalRequired(ValidatedAdmission),
    AutomaticApprovalRequired(ValidatedAdmission),
}

/// Exact response retained with the group transition. A retry must reuse these bytes.
#[derive(Clone)]
pub struct AdmissionReply {
    pub epoch: u64,
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
    pub authorization: AdmissionAuthorization,
}
#[derive(Clone)]
pub(super) struct RetainedAdmission {
    pub digest: [u8; 32],
    pub endpoint: [u8; 32],
    pub issuer: [u8; 32],
    pub reply: RetainedReply,
}

/// A retained reply. One batch admits up to 16 joiners with one commit and
/// one Welcome; every joiner's entry points at the same bytes, and a
/// workspace copy copies pointers only. At 500 members the 16 copies per batch
/// held 4.1 MB per workspace copy (host measurement, 2026-09-19).
#[derive(Clone)]
pub(super) struct RetainedReply {
    pub epoch: u64,
    pub commit: std::sync::Arc<[u8]>,
    pub welcome: std::sync::Arc<[u8]>,
    pub authorization: AdmissionAuthorization,
}

impl RetainedReply {
    fn to_reply(&self) -> AdmissionReply {
        AdmissionReply {
            epoch: self.epoch,
            commit: self.commit.to_vec(),
            welcome: self.welcome.to_vec(),
            authorization: self.authorization.clone(),
        }
    }
}

/// Restores share each epoch's commit and Welcome again, as a batch did.
type SharedReplyParts = (std::sync::Arc<[u8]>, std::sync::Arc<[u8]>);

#[derive(Default)]
pub(super) struct SharedReplies(std::collections::HashMap<u64, SharedReplyParts>);

impl SharedReplies {
    pub fn reply(&mut self, epoch: u64, commit: Vec<u8>, welcome: Vec<u8>, authorization: AdmissionAuthorization) -> RetainedReply {
        let (commit, welcome) = match self.0.get(&epoch) {
            Some((shared_commit, shared_welcome)) if **shared_commit == *commit && **shared_welcome == *welcome => {
                (shared_commit.clone(), shared_welcome.clone())
            }
            _ => {
                let pair: SharedReplyParts = (commit.into(), welcome.into());
                self.0.insert(epoch, pair.clone());
                pair
            }
        };
        RetainedReply { epoch, commit, welcome, authorization }
    }
}
// Legacy inline snapshot format only; not a membership or incremental-store limit.
pub(super) const MAX_ADMISSIONS: usize = 16;

/// Provisional membership transition. The host must atomically retain the new
/// workspace AND response/history before adopting it or sending these messages.
pub struct PreparedAdmission {
    pub workspace: Workspace,
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
    pub authorization: AdmissionAuthorization,
}

/// One MLS transition for a bounded set of independently authenticated joins.
/// Each retained reply points at the same commit and Welcome.
pub struct PreparedAdmissionBatch {
    pub workspace: Workspace,
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
    pub replies: Vec<AdmissionReply>,
}
impl Workspace {
    /// Serve only the exact current checkpoint to a holder of this invitation.
    pub fn checkpoint_for_invitation(
        &self,
        requester: [u8; 32],
        responder: [u8; 32],
        request: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if request.len() != CHECKPOINT_REQUEST_SIZE
            || requester == [0; 32]
            || responder != self.endpoint
            || requester == responder
        {
            return Err("invalid invitation checkpoint request");
        }
        let (grant, signature) = request.split_at(PUBLIC);
        verify_grant(&self.provider, grant)?;
        self.provider
            .crypto()
            .verify_signature(
                SUITE.signature_algorithm(),
                &checkpoint_request_message(grant, requester, responder),
                &grant[101..133],
                signature,
            )
            .map_err(|_| "invalid invitation checkpoint proof")?;
        if grant[5..37] != self.id() {
            return Err("invitation belongs to another workspace");
        }
        let digest: [u8; 32] = grant[37..69].try_into().unwrap();
        let checkpoint = match self
            .join_history
            .as_ref()
            .filter(|history| <[u8; 32]>::from(Sha256::digest(&history.checkpoint)) == digest)
        {
            Some(history) => {
                history.verify(self)?;
                history.checkpoint.clone()
            }
            None => match self
                .invitation_checkpoints
                .iter()
                .find(|saved| saved.grant.as_slice() == grant)
            {
                Some(saved) => saved.checkpoint.clone(),
                None => self.join_checkpoint()?,
            },
        };
        let proof = JoinProof::from_trusted_checkpoint(self.id(), digest, &checkpoint)?;
        if !proof.authorizes_issuer(&grant[69..101])? {
            return Err("invitation issuer is not a checkpoint administrator");
        }
        Ok(checkpoint)
    }

    /// Verify the invitation holder and reconstruct the exact accepted branch
    /// from its pinned checkpoint before admitting or replying. Missing history
    /// is an error; it must not become a new Add with an unusable Welcome.
    pub fn admission_history(
        &self,
        remote_endpoint: [u8; 32],
        request: &[u8],
        checkpoint: &[u8],
    ) -> Result<Vec<(AdmissionAuthorization, Vec<u8>)>, &'static str> {
        self.membership_history(remote_endpoint, request, checkpoint)?
            .into_iter()
            .map(|(auth, commit)| match auth {
                MembershipAuthorization::Admission(auth) => Ok((auth, commit)),
                MembershipAuthorization::AdmissionBatch(_) => {
                    Err("admission history requires membership support")
                }
                MembershipAuthorization::Management(_) => {
                    Err("membership history requires management support")
                }
            })
            .collect()
    }

    /// Everything an arriving admission must satisfy on its own account:
    /// a decodable, signed request, live invitation controls, the pinned
    /// workspace, the bound endpoint and a current administrator as issuer.
    /// None of this is ever reused between requests.
    fn authorize_history_request(
        &self,
        remote_endpoint: [u8; 32],
        request: &[u8],
    ) -> Result<ValidatedAdmission, &'static str> {
        let parsed = decode_request(&self.provider, request)?;
        if self.retained_admission(remote_endpoint, request)?.is_none() {
            super::invitation_controls::check(
                self.group.extensions(),
                parsed.authorization.invitation_key,
                Some(super::invitation_controls::now()?),
                &parsed.package,
            )?;
        }
        if parsed.workspace != self.id()
            || bootstrap::binding(parsed.package.leaf_node().credential())?.1 != remote_endpoint
            || !bootstrap::authority(self.group.extensions())?.contains(&parsed.issuer.to_vec())
        {
            return Err("unauthorized admission history request");
        }
        Ok(parsed)
    }

    /// Whether this admission's pinned history can be served, without building
    /// the history. Admission intake only needs the answer; only the reply path
    /// needs the transitions, so intake does not pay to materialize and discard
    /// them.
    pub fn check_membership_history(
        &self,
        remote_endpoint: [u8; 32],
        request: &[u8],
        checkpoint: &[u8],
    ) -> Result<(), &'static str> {
        let parsed = self.authorize_history_request(remote_endpoint, request)?;
        if let Some(start) = self.retained_checkpoint_start(&parsed, checkpoint)?
            && self.accepted_range(start).is_some()
        {
            return Ok(());
        }
        // Not retained, or the records do not cover the range: the only honest
        // answer is the full one. Authorization is not repeated for it.
        self.authorized_membership_history(&parsed, checkpoint)
            .map(|_| ())
    }

    pub fn membership_history(
        &self,
        remote_endpoint: [u8; 32],
        request: &[u8],
        checkpoint: &[u8],
    ) -> Result<Vec<(MembershipAuthorization, Vec<u8>)>, &'static str> {
        let request = self.authorize_history_request(remote_endpoint, request)?;
        self.authorized_membership_history(&request, checkpoint)
    }

    fn authorized_membership_history(
        &self,
        request: &ValidatedAdmission,
        checkpoint: &[u8],
    ) -> Result<Vec<(MembershipAuthorization, Vec<u8>)>, &'static str> {
        // This owner issued this checkpoint, retained it with its authenticated
        // invitation transition, and proved it an ancestor of the accepted
        // branch then and again at every restore. Its own branch only extends,
        // so that proof stays good; replaying it commit by commit for every
        // arriving request is redundant work, and the cost of that replay grows
        // with the branch. Everything above this point -- the request decode,
        // invitation controls, issuer authority and endpoint binding -- is
        // per-request and is not skipped.
        if let Some(steps) = self.retained_checkpoint_steps(request, checkpoint)? {
            return Ok(steps);
        }
        let mut proof = super::MembershipVerifier::from_trusted_checkpoint(
            self.id(),
            request.checkpoint_digest,
            checkpoint,
        )?;
        if !proof.authorizes_issuer(&request.issuer)? || proof.epoch() > self.epoch() {
            return Err("invitation checkpoint is not an authorized ancestor");
        }
        // Stored history is verified at restore and extended only with an
        // accepted transition. When the requester pins that exact checkpoint,
        // replaying the owner's entire branch on every request is redundant.
        if let Some(history) = &self.join_history
            && history.checkpoint == checkpoint
        {
            return Ok(history.steps.clone());
        }
        self.advance_membership_proof(&mut proof)
    }

    /// The epoch a joiner pinning this checkpoint must be advanced from, when
    /// the checkpoint is one this owner issued and retained itself. `None`
    /// means it is not, so the caller falls back to full verification.
    fn retained_checkpoint_start(
        &self,
        request: &ValidatedAdmission,
        checkpoint: &[u8],
    ) -> Result<Option<u64>, &'static str> {
        let Some(saved) = self.invitation_checkpoints.iter().find(|saved| {
            saved.checkpoint == checkpoint
                && <[u8; 32]>::from(Sha256::digest(&saved.checkpoint))
                    == request.checkpoint_digest
                && saved.grant[69..101] == request.issuer
                && saved.grant[101..133] == request.authorization.invitation_key
        }) else {
            return Ok(None);
        };
        let start = checkpoint_epoch(&saved.checkpoint)?;
        if start > self.epoch() {
            return Err("invitation checkpoint is not an authorized ancestor");
        }
        Ok(Some(start))
    }

    /// Borrow this owner's accepted transition for every epoch from `start` to
    /// the head, in order. Nothing is copied: the result points into the
    /// owner's own records, so a caller that only needs to know the range
    /// exists pays no allocation for the transitions themselves. `None` means
    /// the records are incomplete or disagree about an epoch in that range, so
    /// the caller falls back to full verification rather than guessing.
    fn accepted_range(&self, start: u64) -> Option<Vec<AcceptedStep<'_>>> {
        let span = usize::try_from(self.epoch().checked_sub(start)?).ok()?;
        let mut slots: Vec<Option<AcceptedStep<'_>>> = Vec::new();
        slots.resize_with(span, || None);
        // The retained join history is the authoritative ordered log, so it is
        // placed first; retained admissions only fill epochs it does not cover.
        if let Some(history) = &self.join_history {
            for step in &history.steps {
                place_accepted(&mut slots, start, AcceptedStep::History(step))?;
            }
            // The retained history is authoritative. Once it covers the whole
            // requested range, scanning the retry index only reparses the same
            // commits and adds duplicate work to every admission.
            if slots.iter().all(Option::is_some) {
                return slots.into_iter().collect();
            }
        }
        for admission in &self.admissions {
            place_accepted(&mut slots, start, AcceptedStep::Admission(admission))?;
        }
        slots.into_iter().collect()
    }

    /// Transitions from a checkpoint this owner issued and retained itself,
    /// taken from its own accepted records rather than replayed. Only the
    /// requested range is copied, and only for a caller that needs to send it.
    fn retained_checkpoint_steps(
        &self,
        request: &ValidatedAdmission,
        checkpoint: &[u8],
    ) -> Result<Option<MembershipSteps>, &'static str> {
        let Some(start) = self.retained_checkpoint_start(request, checkpoint)? else {
            return Ok(None);
        };
        Ok(self
            .accepted_range(start)
            .map(|range| range.iter().map(AcceptedStep::to_step).collect()))
    }

    fn advance_membership_proof(
        &self,
        proof: &mut super::MembershipVerifier,
    ) -> Result<Vec<(MembershipAuthorization, Vec<u8>)>, &'static str> {
        if proof.epoch() > self.epoch() {
            return Err("invitation checkpoint is not an authorized ancestor");
        }
        let mut candidates = match &self.join_history {
            Some(history) => history.steps.clone(),
            None => Vec::new(),
        };
        candidates.extend(self.admissions.iter().map(|a| {
            (
                MembershipAuthorization::Admission(a.reply.authorization.clone()),
                a.reply.commit.to_vec(),
            )
        }));
        let mut steps = Vec::new();
        while proof.epoch() < self.epoch() {
            let next = candidates
                .iter()
                .find(|(_, commit)| {
                    MlsMessageIn::tls_deserialize_exact(commit)
                        .ok()
                        .and_then(|m| m.try_into_protocol_message().ok())
                        .is_some_and(|m| m.epoch().as_u64() == proof.epoch())
                })
                .ok_or("invitation history unavailable")?;
            proof.apply_transition(&next.0, &next.1)?;
            steps.push(next.clone());
        }
        if !proof.matches_workspace(self)? {
            return Err("invitation checkpoint conflicts with accepted branch");
        }
        Ok(steps)
    }

    /// Look up a byte-identical retry from the authenticated endpoint. Only use
    /// this on the adopted, durably saved owner; this method does not perform I/O.
    pub fn retained_admission(
        &self,
        remote_endpoint: [u8; 32],
        request: &[u8],
    ) -> Result<Option<AdmissionReply>, &'static str> {
        if request.len() <= REQUEST_HEADER || request.len() > MAX_REQUEST {
            return Err("invalid admission request size");
        }
        let digest: [u8; 32] = Sha256::digest(request).into();
        let Some(entry) = self.admissions.iter().find(|entry| entry.digest == digest) else {
            return Ok(None);
        };
        if entry.endpoint != remote_endpoint {
            return Err("admission retry endpoint mismatch");
        }
        if !bootstrap::authority(self.group.extensions())?.contains(&entry.issuer.to_vec()) {
            return Err("invitation issuer is no longer an administrator");
        }
        if !self.group.members().any(|member| {
            bootstrap::binding(&member.credential)
                .is_ok_and(|(_, endpoint)| endpoint == remote_endpoint)
        }) {
            return Err("admitted member is no longer authorized");
        }
        Ok(Some(entry.reply.to_reply()))
    }

    /// Returns a secret bearer token owner and the public checkpoint it pins.
    /// Checkpoint distribution/retention is part of invitation handoff.
    pub fn issue_invitation(&self) -> Result<(Invitation, Vec<u8>), &'static str> {
        let checkpoint = self.join_checkpoint()?;
        let (private, public) = self
            .provider
            .crypto()
            .signature_key_gen(SUITE.signature_algorithm())
            .map_err(|_| "invitation randomness failed")?;
        let private = Zeroizing::new(private);
        let mut grant = [0; PUBLIC];
        grant[..5].copy_from_slice(TOKEN);
        grant[5..37].copy_from_slice(&self.id());
        grant[37..69].copy_from_slice(&Sha256::digest(&checkpoint));
        grant[69..101].copy_from_slice(self._signer.public());
        grant[101..133].copy_from_slice(&public);
        let signature = self
            ._signer
            .sign(&bootstrap::grant(
                self.group.group_id(),
                public
                    .as_slice()
                    .try_into()
                    .map_err(|_| "invalid invitation public key")?,
            ))
            .map_err(|_| "invitation signing failed")?;
        grant[133..197].copy_from_slice(&signature);
        let signature = self
            ._signer
            .sign(&binding_message(&grant))
            .map_err(|_| "checkpoint signing failed")?;
        grant[197..261].copy_from_slice(&signature);
        Ok((
            Invitation {
                grant,
                secret: Zeroizing::new(
                    private
                        .as_slice()
                        .try_into()
                        .map_err(|_| "invalid invitation private key")?,
                ),
            },
            checkpoint,
        ))
    }
    /// Register a reusable link in shared policy before releasing its bearer
    /// token. The caller must persist the returned workspace before sharing.
    pub fn prepare_invitation(
        &self,
        expires_at: u64,
        personal: bool,
        automatic: bool,
    ) -> Result<(super::PreparedManagement, Invitation, Vec<u8>), &'static str> {
        self.prepare_invitation_mode(expires_at, personal, automatic, false)
    }

    pub fn prepare_request_invitation(
        &self,
        expires_at: u64,
    ) -> Result<(super::PreparedManagement, Invitation, Vec<u8>), &'static str> {
        self.prepare_invitation_mode(expires_at, true, false, true)
    }

    fn prepare_invitation_mode(
        &self,
        expires_at: u64,
        personal: bool,
        automatic: bool,
        request_access: bool,
    ) -> Result<(super::PreparedManagement, Invitation, Vec<u8>), &'static str> {
        if expires_at != 0 && expires_at <= super::invitation_controls::now()? {
            return Err("Choose an expiry in the future.");
        }
        let (mut invitation, _) = self.issue_invitation()?;
        let key = invitation.grant[101..133].try_into().unwrap();
        if automatic && !personal {
            return Err("Only a personal invitation can use automatic approval.");
        }
        let action = if request_access {
            super::ManagementAction::CreateRequestInvitation(key, expires_at)
        } else if automatic {
            super::ManagementAction::CreateAutomaticInvitation(key, expires_at)
        } else {
            super::ManagementAction::CreateInvitation(key, expires_at, personal)
        };
        let mut prepared = self.prepare_management(action)?;
        let checkpoint = prepared.workspace.join_checkpoint()?;
        invitation.grant[37..69].copy_from_slice(&Sha256::digest(&checkpoint));
        let binding = binding_message(&invitation.grant);
        invitation.grant[197..261].copy_from_slice(
            &self
                ._signer
                .sign(&binding)
                .map_err(|_| "checkpoint signing failed")?,
        );
        prepared.workspace.retain_invitation_checkpoint(
            action,
            invitation.public_grant(),
            &checkpoint,
        )?;
        Ok((prepared, invitation, checkpoint))
    }

    /// Retain one admin-signed public checkpoint carried with its authenticated
    /// invitation-management transition. The bearer secret is never retained.
    pub fn retain_invitation_checkpoint(
        &mut self,
        action: super::ManagementAction,
        grant: &[u8],
        checkpoint: &[u8],
    ) -> Result<(), &'static str> {
        self.prune_invitation_checkpoints()?;
        let key = match action {
            super::ManagementAction::CreateInvitation(key, ..)
            | super::ManagementAction::CreateRequestInvitation(key, ..)
            | super::ManagementAction::CreateAutomaticInvitation(key, ..) => key,
            _ => return Err("checkpoint requires an invitation creation"),
        };
        verify_grant(&self.provider, grant)?;
        if grant[5..37] != self.id() || grant[101..133] != key {
            return Err("invitation checkpoint does not match action");
        }
        let digest: [u8; 32] = grant[37..69].try_into().unwrap();
        let proof = JoinProof::from_trusted_checkpoint(self.id(), digest, checkpoint)?;
        if !proof.authorizes_issuer(&grant[69..101])? || !proof.matches_workspace(self)? {
            return Err("invitation checkpoint does not match accepted workspace");
        }
        if self
            .invitation_checkpoints
            .iter()
            .any(|saved| saved.grant.as_slice() == grant)
        {
            return Ok(());
        }
        let total = self
            .invitation_checkpoints
            .iter()
            .try_fold(checkpoint.len(), |sum, saved| {
                sum.checked_add(saved.checkpoint.len())
            })
            .ok_or("retained invitation checkpoints exceed bounds")?;
        if self.invitation_checkpoints.len() >= MAX_RETAINED_CHECKPOINTS
            || total > MAX_RETAINED_CHECKPOINT_BYTES
        {
            return Err("retained invitation checkpoints exceed bounds");
        }
        self.invitation_checkpoints
            .push(RetainedInvitationCheckpoint {
                grant: grant
                    .try_into()
                    .map_err(|_| "invalid invitation grant size")?,
                checkpoint: checkpoint.to_vec(),
            });
        Ok(())
    }

    pub(super) fn prune_invitation_checkpoints(&mut self) -> Result<(), &'static str> {
        let now = super::invitation_controls::now()?;
        let (_, controls) = self.invitation_controls()?;
        self.invitation_checkpoints.retain(|saved| {
            let key: [u8; 32] = saved.grant[101..133].try_into().unwrap();
            controls.iter().any(|control| {
                control.key == key
                    && control.enabled
                    && (control.expires_at == 0 || control.expires_at > now)
            })
        });
        Ok(())
    }

    pub(super) fn verify_retained_invitation_checkpoints(&self) -> Result<(), &'static str> {
        if self.invitation_checkpoints.len() > MAX_RETAINED_CHECKPOINTS
            || self
                .invitation_checkpoints
                .iter()
                .try_fold(0usize, |sum, saved| sum.checked_add(saved.checkpoint.len()))
                .is_none_or(|total| total > MAX_RETAINED_CHECKPOINT_BYTES)
        {
            return Err("retained invitation checkpoints exceed bounds");
        }
        if self.invitation_checkpoints.is_empty() {
            return Ok(());
        }
        let (_, controls) = self.invitation_controls()?;
        for saved in &self.invitation_checkpoints {
            verify_grant(&self.provider, &saved.grant)?;
            let key: [u8; 32] = saved.grant[101..133].try_into().unwrap();
            if saved.grant[5..37] != self.id() || !controls.iter().any(|control| control.key == key)
            {
                return Err("retained invitation checkpoint is not registered");
            }
            let digest: [u8; 32] = saved.grant[37..69].try_into().unwrap();
            let mut proof = super::MembershipVerifier::from_trusted_checkpoint(
                self.id(),
                digest,
                &saved.checkpoint,
            )?;
            if !proof.authorizes_issuer(&saved.grant[69..101])?
                || self.advance_membership_proof(&mut proof).is_err()
            {
                return Err("retained invitation checkpoint does not match workspace");
            }
        }
        Ok(())
    }

    pub fn retained_invitation_checkpoint(
        &self,
        action: &super::ManagementAction,
    ) -> Option<(&[u8], &[u8])> {
        let key = match action {
            super::ManagementAction::CreateInvitation(key, ..)
            | super::ManagementAction::CreateRequestInvitation(key, ..)
            | super::ManagementAction::CreateAutomaticInvitation(key, ..) => key,
            _ => return None,
        };
        self.invitation_checkpoints
            .iter()
            .find(|saved| saved.grant[101..133] == *key)
            .map(|saved| (saved.grant.as_slice(), saved.checkpoint.as_slice()))
    }

    pub fn prepare_invitation_approval(
        &self,
        bytes: &[u8],
    ) -> Result<super::PreparedManagement, &'static str> {
        let request = decode_request(&self.provider, bytes)?;
        if request.workspace != self.id() {
            return Err("Join request belongs to another workspace.");
        }
        let (_, controls) = self.invitation_controls()?;
        let control = controls
            .iter()
            .find(|c| c.key == request.authorization.invitation_key)
            .ok_or("unknown invitation")?;
        if control.expires_at != 0 && super::invitation_controls::now()? >= control.expires_at {
            return Err("This invitation has expired.");
        }
        self.prepare_management(super::ManagementAction::ApproveInvitation(
            control.key,
            super::invitation_controls::package_digest(&request.package)?,
        ))
    }

    pub fn prepare_invitation_decline(
        &self,
        bytes: &[u8],
    ) -> Result<super::PreparedManagement, &'static str> {
        let request = decode_request(&self.provider, bytes)?;
        if request.workspace != self.id() {
            return Err("Join request belongs to another workspace.");
        }
        let (_, controls) = self.invitation_controls()?;
        let control = controls
            .iter()
            .find(|c| c.key == request.authorization.invitation_key)
            .ok_or("unknown invitation")?;
        if !control.personal {
            return Err("Only personal invitation requests can be declined.");
        }
        self.prepare_management(if control.request_access() {
            super::ManagementAction::DeclineInvitationRequest(
                control.key,
                super::invitation_controls::package_digest(&request.package)?,
            )
        } else {
            super::ManagementAction::DisableInvitation(control.key)
        })
    }

    /// remote_endpoint MUST come from authenticated transport, not request JSON.
    /// The original owner is unchanged on both success and rejection.
    /// One retained update for an authenticated endpoint. Current members may
    /// retrieve history; a former member may retrieve only its own exact removal
    /// from a parent state that proves its binding, never subsequent roster data.
    pub fn membership_update_for(
        &self,
        endpoint: [u8; 32],
        after: u64,
    ) -> Result<Option<(MembershipAuthorization, Vec<u8>)>, &'static str> {
        let current = self.member_id_for_endpoint(endpoint).is_ok();
        if let Some(history) = &self.join_history {
            if current {
                // Restored history is verified once and extended only by
                // accepted transitions. Index it directly instead of replaying
                // the full history for every step in a range catch-up.
                let start = checkpoint_epoch(&history.checkpoint)?;
                if let Some((auth, commit)) = after
                    .checked_sub(start)
                    .and_then(|offset| usize::try_from(offset).ok())
                    .and_then(|index| history.steps.get(index))
                {
                    return Ok(Some((auth.clone(), commit.clone())));
                }
            } else {
                let mut proof = history.verifier(self.id)?;
                for (auth, commit) in &history.steps {
                    if proof.epoch() == after {
                        let terminal = match auth {
                            MembershipAuthorization::Management(
                                super::ManagementAction::Remove(id)
                                | super::ManagementAction::Leave(id, _),
                            ) => proof.member_for_endpoint(endpoint)? == Some(*id),
                            _ => false,
                        };
                        if terminal {
                            return Ok(Some((auth.clone(), commit.clone())));
                        }
                        return Ok(None);
                    }
                    proof.apply_transition(auth, commit)?;
                }
            }
        }
        Ok(if current {
            self.admission_update_after(after)
        } else {
            None
        })
    }

    /// Return the next locally retained admission for an existing member's epoch.
    /// None means this owner has no such retained step, not that the requester is current.
    /// The host must authorize the requester before sharing workspace metadata.
    pub fn admission_update_after(
        &self,
        epoch: u64,
    ) -> Option<(MembershipAuthorization, Vec<u8>)> {
        let next = epoch.checked_add(1)?;
        let entries: Vec<_> = self
            .admissions
            .iter()
            .filter(|entry| entry.reply.epoch == next)
            .collect();
        let first = entries.first()?;
        let authorization = if entries.len() == 1 {
            MembershipAuthorization::Admission(first.reply.authorization.clone())
        } else {
            MembershipAuthorization::AdmissionBatch(
                entries
                    .iter()
                    .map(|entry| entry.reply.authorization.clone())
                    .collect(),
            )
        };
        Some((authorization, first.reply.commit.to_vec()))
    }

    /// Prepare an existing member's next epoch from an authorized ordinary-member Add.
    /// Leaves this owner unchanged on success or failure. The caller must save the
    /// returned owner before adoption and resolve old-epoch pending delivery explicitly.
    /// This is not a policy-change, removal or concurrent-branch merge operation.
    pub fn prepare_admission_update(
        &self,
        authorization: &AdmissionAuthorization,
        commit: &[u8],
    ) -> Result<Workspace, &'static str> {
        self.prepare_admission_batch_update(std::slice::from_ref(authorization), commit)
    }

    /// Prepare an existing member's next epoch from a bounded batch Add.
    pub fn prepare_admission_batch_update(
        &self,
        authorizations: &[AdmissionAuthorization],
        commit: &[u8],
    ) -> Result<Workspace, &'static str> {
        if authorizations.is_empty() || authorizations.len() > super::MAX_ADMISSION_BATCH {
            return Err("invalid admission batch size");
        }
        let authorization = if let [authorization] = authorizations {
            MembershipAuthorization::Admission(authorization.clone())
        } else {
            MembershipAuthorization::AdmissionBatch(authorizations.to_vec())
        };
        let mut proof = super::MembershipVerifier::from_workspace(self)?;
        proof.apply_transition(&authorization, commit)?;
        let provider = storage::copy_provider(&self.provider)?;
        let mut group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&self.id()))
            .map_err(|_| "group copy failed")?
            .ok_or("missing group copy")?;
        let signer = SignatureKeyPair::read(
            provider.storage(),
            self._signer.public(),
            SUITE.signature_algorithm(),
        )
        .ok_or("missing copied signer")?;
        let message = MlsMessageIn::tls_deserialize_exact(commit)
            .map_err(|_| "invalid admission commit")?
            .try_into_protocol_message()
            .map_err(|_| "expected admission commit")?;
        let processed = group
            .process_message(&provider, message)
            .map_err(|_| "admission update authentication failed")?;
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err("not an admission commit");
        };
        group
            .merge_staged_commit(&provider, *staged)
            .map_err(|_| "admission update merge failed")?;
        let updated = Workspace {
            provider,
            _signer: signer,
            group,
            id: self.id,
            endpoint: self.endpoint,
            member: self.member.clone(),
            admissions: self.admissions.clone(),
            invitation_checkpoints: self.invitation_checkpoints.clone(),
            // Received Adds have no local Welcome/retry entry to retain their
            // commit. Keep the verified history even on a creator's first update.
            join_history: Some(self.append_history(authorization, commit)?),
        };
        if !proof.matches_workspace(&updated)? {
            return Err("admission update does not match authorized branch");
        }
        Ok(updated)
    }

    fn check_validated_admission(
        &self,
        remote_endpoint: [u8; 32],
        request: &ValidatedAdmission,
    ) -> Result<(), &'static str> {
        if request.workspace != self.id() {
            return Err("admission belongs to another workspace");
        }
        super::invitation_controls::check(
            self.group.extensions(),
            request.authorization.invitation_key,
            Some(super::invitation_controls::now()?),
            &request.package,
        )?;
        if !bootstrap::authority(self.group.extensions())?.contains(&request.issuer.to_vec()) {
            return Err("invitation issuer is no longer an administrator");
        }
        let (member_id, endpoint) = bootstrap::binding(request.package.leaf_node().credential())?;
        if endpoint != remote_endpoint {
            return Err("admission endpoint mismatch");
        }
        for member in self.group.members() {
            let existing = bootstrap::binding(&member.credential)?;
            if existing.0 == member_id || existing.1 == endpoint {
                return Err("member already admitted");
            }
        }
        Ok(())
    }

    /// Authenticate and classify a request without creating an MLS commit.
    /// Hosts can retain this result while an owner queues the transition.
    pub fn assess_admission(
        &self,
        remote_endpoint: [u8; 32],
        bytes: &[u8],
    ) -> Result<AdmissionAssessment, &'static str> {
        let trusted_grant = bytes
            .get(5..5 + PUBLIC)
            .is_some_and(|grant| {
                self.invitation_checkpoints
                    .iter()
                    .any(|saved| saved.grant.as_slice() == grant)
            });
        let mut request = decode_request_with_grant_check(&self.provider, bytes, !trusted_grant)?;
        request.endpoint = remote_endpoint;
        if request.workspace != self.id() {
            return Err("admission belongs to another workspace");
        }
        if let Err(error) = self.check_validated_admission(remote_endpoint, &request) {
            return match error {
                super::INVITATION_APPROVAL_REQUIRED => Ok(AdmissionAssessment::ApprovalRequired(request)),
                super::INVITATION_AUTOMATIC_APPROVAL_REQUIRED => {
                    Ok(AdmissionAssessment::AutomaticApprovalRequired(request))
                }
                _ => Err(error),
            };
        }
        Ok(AdmissionAssessment::Ready(request))
    }

    pub fn prepare_admission(
        &self,
        remote_endpoint: [u8; 32],
        bytes: &[u8],
    ) -> Result<PreparedAdmission, &'static str> {
        let request = match self.assess_admission(remote_endpoint, bytes)? {
            AdmissionAssessment::Ready(request) => request,
            AdmissionAssessment::ApprovalRequired(_) => {
                return Err(super::INVITATION_APPROVAL_REQUIRED)
            }
            AdmissionAssessment::AutomaticApprovalRequired(_) => {
                return Err(super::INVITATION_AUTOMATIC_APPROVAL_REQUIRED)
            }
        };
        self.prepare_validated_admission(remote_endpoint, bytes, &request)
    }

    /// Prepare the commit from a request already authenticated by
    /// [`Workspace::assess_admission`]. The current workspace policy is still
    /// checked because a queued invitation may expire or be consumed first.
    pub fn prepare_validated_admission(
        &self,
        remote_endpoint: [u8; 32],
        bytes: &[u8],
        request: &ValidatedAdmission,
    ) -> Result<PreparedAdmission, &'static str> {
        let prepared = self.prepare_validated_admission_batch(&[(remote_endpoint, bytes, request)])?;
        let reply = prepared.replies.into_iter().next().unwrap();
        Ok(PreparedAdmission {
            workspace: prepared.workspace,
            commit: prepared.commit,
            welcome: prepared.welcome,
            authorization: reply.authorization,
        })
    }

    /// Prepare one bounded MLS transition for already authenticated requests.
    /// Authentication and policy checks happen once per request; MLS state is
    /// cloned and advanced once for the whole batch.
    pub fn prepare_validated_admission_batch(
        &self,
        admissions: &[([u8; 32], &[u8], &ValidatedAdmission)],
    ) -> Result<PreparedAdmissionBatch, &'static str> {
        if admissions.is_empty() || admissions.len() > super::MAX_ADMISSION_BATCH {
            return Err("invalid admission batch size");
        }
        let profile = std::env::var_os("ARACHNE_PROFILE_ADMISSION").is_some();
        let profile_started = std::time::Instant::now();
        let mut bindings = BTreeSet::new();
        let mut packages = Vec::with_capacity(admissions.len());
        for (remote_endpoint, bytes, request) in admissions {
            let digest: [u8; 32] = Sha256::digest(bytes).into();
            if request.endpoint != *remote_endpoint || request.digest != digest {
                return Err("validated admission does not match request");
            }
            self.check_validated_admission(*remote_endpoint, request)?;
            if !bindings.insert(bootstrap::binding(request.package.leaf_node().credential())?) {
                return Err("duplicate member binding");
            }
            packages.push(request.package.clone());
        }
        let provider = storage::copy_provider(&self.provider)?;
        let mut group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&self.id()))
            .map_err(|_| "group copy failed")?
            .ok_or("missing group copy")?;
        let signer = SignatureKeyPair::read(
            provider.storage(),
            self._signer.public(),
            SUITE.signature_algorithm(),
        )
        .ok_or("missing copied signer")?;
        // Older saved groups need public handshakes for the admission proof;
        // this configuration change is confined to the provisional transition.
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(false)
            .build();
        group
            .set_configuration(provider.storage(), &config)
            .map_err(|_| "admission configuration failed")?;
        let (commit, welcome, _) = group
            .add_members_without_update(&provider, &signer, &packages)
            .map_err(|_| "admission preparation failed")?;
        let commit = commit.to_bytes().map_err(|_| "commit encoding failed")?;
        let welcome = welcome.to_bytes().map_err(|_| "Welcome encoding failed")?;
        if welcome.len() > 64 * 1024 {
            if profile {
                eprintln!("admission_profile welcome_len={}", welcome.len());
            }
            return Err("Welcome exceeds bounds");
        }
        group
            .merge_pending_commit(&provider)
            .map_err(|_| "admission merge failed")?;
        let epoch = group.epoch().as_u64();
        let replies: Vec<_> = admissions
            .iter()
            .map(|(_, _, request)| AdmissionReply {
                epoch,
                commit: commit.clone(),
                welcome: welcome.clone(),
                authorization: request.authorization.clone(),
            })
            .collect();
        let mut retained_admissions = self.admissions.clone();
        let shared_commit: std::sync::Arc<[u8]> = commit.as_slice().into();
        let shared_welcome: std::sync::Arc<[u8]> = welcome.as_slice().into();
        for ((remote_endpoint, bytes, request), reply) in admissions.iter().zip(&replies) {
            retained_admissions.push(RetainedAdmission {
                digest: Sha256::digest(bytes).into(),
                endpoint: *remote_endpoint,
                issuer: request.issuer,
                reply: RetainedReply {
                    epoch: reply.epoch,
                    commit: shared_commit.clone(),
                    welcome: shared_welcome.clone(),
                    authorization: reply.authorization.clone(),
                },
            });
        }
        let authorizations: Vec<_> = replies
            .iter()
            .map(|reply| reply.authorization.clone())
            .collect();
        let authorization = if let [authorization] = authorizations.as_slice() {
            MembershipAuthorization::Admission(authorization.clone())
        } else {
            MembershipAuthorization::AdmissionBatch(authorizations)
        };
        let join_history = if replies.len() == 1 {
            self.join_history
                .as_ref()
                .map(|_| self.append_history(authorization.clone(), &commit))
                .transpose()?
        } else {
            Some(self.append_history(authorization, &commit)?)
        };
        if profile {
            eprintln!(
                "admission_profile batch={} commit_ms={}",
                replies.len(),
                profile_started.elapsed().as_millis()
            );
        }
        Ok(PreparedAdmissionBatch {
            workspace: Workspace {
                provider,
                _signer: signer,
                group,
                id: self.id,
                endpoint: self.endpoint,
                member: self.member.clone(),
                admissions: retained_admissions,
                invitation_checkpoints: self.invitation_checkpoints.clone(),
                join_history,
            },
            commit,
            welcome,
            replies,
        })
    }
}

#[test]
fn checkpoint_request_keeps_the_bearer_secret_local_and_binds_both_endpoints() {
    let admin = Workspace::create([1; 32], "Coordinator").unwrap();
    let (invitation, checkpoint) = admin.issue_invitation().unwrap();
    let token = invitation.export_secret_token();
    let request = invitation.checkpoint_request([2; 32], [1; 32]).unwrap();
    assert_eq!(request.len(), CHECKPOINT_REQUEST_SIZE);
    assert_eq!(&request[..PUBLIC], &token[..PUBLIC]);
    assert!(!request.windows(32).any(|part| part == &token[PUBLIC..]));
    assert_eq!(
        admin
            .checkpoint_for_invitation([2; 32], [1; 32], &request)
            .unwrap(),
        checkpoint
    );
    assert!(
        admin
            .checkpoint_for_invitation([3; 32], [1; 32], &request)
            .is_err()
    );
    assert!(
        admin
            .checkpoint_for_invitation([2; 32], [9; 32], &request)
            .is_err()
    );
    let mut tampered = request;
    tampered[PUBLIC] ^= 1;
    assert!(
        admin
            .checkpoint_for_invitation([2; 32], [1; 32], &tampered)
            .is_err()
    );
}

#[test]
fn signed_invitation_survives_pending_restart_and_offline_issuer() {
    use super::{PendingJoin, StorageKey};
    let admin = Workspace::create([1; 32], "Coordinator").unwrap();
    let (invitation, checkpoint) = admin.issue_invitation().unwrap();
    let token = invitation.export_secret_token();
    assert_eq!(token.len(), TOKEN_SIZE);
    let invitation = Invitation::from_bytes(&token).unwrap();
    assert_eq!(
        invitation.export_secret_token().as_slice(),
        token.as_slice()
    );
    for length in 0..TOKEN_SIZE {
        assert!(Invitation::from_bytes(&token[..length]).is_err());
    }
    let mut trailing = token.to_vec();
    trailing.push(0);
    assert!(Invitation::from_bytes(&trailing).is_err());
    for index in [0, 4, 5, 37, 69, 101, 133, 197, 261, 292] {
        let mut bad = Zeroizing::new(token.to_vec());
        bad[index] ^= 1;
        assert!(Invitation::from_bytes(&bad).is_err());
    }
    let other = Workspace::create([9; 32], "Coordinator").unwrap();
    assert!(
        invitation
            .join_proof(&other.join_checkpoint().unwrap())
            .is_err()
    );
    let pending =
        PendingJoin::from_invitation(&invitation, &checkpoint, [2; 32], "Field helper").unwrap();
    let key = StorageKey::derive(&[7; 32]).unwrap();
    let request = pending.admission_request().unwrap().to_vec();
    let member = pending.member().clone();
    let sealed = pending.seal(&key).unwrap();
    assert!(sealed.starts_with(b"DFPJ\x02"));
    drop(pending);
    let pending = PendingJoin::restore(&key, [2; 32], admin.id(), &sealed).unwrap();
    assert_eq!(pending.admission_request().unwrap(), request);
    assert_eq!(pending.member(), &member);
    let mut proof = pending.join_proof().unwrap();
    assert!(admin.prepare_admission([3; 32], &request).is_err());
    assert!(other.prepare_admission([2; 32], &request).is_err());
    for index in [0, 5, 42, 106, 202, 266, request.len() - 1] {
        let mut bad = request.clone();
        bad[index] ^= 1;
        assert!(admin.prepare_admission([2; 32], &bad).is_err());
    }
    let mut extra = request.clone();
    extra.push(0);
    assert!(admin.prepare_admission([2; 32], &extra).is_err());
    let first = admin.prepare_admission([2; 32], &request).unwrap();
    assert_eq!(admin.epoch(), 0);
    assert_eq!(admin.member_count(), 1);
    assert!(
        admin
            .retained_admission([2; 32], &request)
            .unwrap()
            .is_none()
    );
    let snapshot = first.workspace.seal(&key).unwrap();
    assert!(snapshot.starts_with(b"DFWS\x03"));
    // Authenticated malformed format must fail at the bounded parser too.
    let plain = key
        .unprotect(b"DFWS\x03", admin.id(), [1; 32], &snapshot)
        .unwrap();
    let count_offset = 8 + 32 + 4 + admin.member().unwrap().display_name().len();
    for count in [0u32, MAX_ADMISSIONS as u32 + 1, u32::MAX] {
        let mut invalid = plain.clone();
        invalid[count_offset..count_offset + 4].copy_from_slice(&count.to_be_bytes());
        let sealed = key
            .protect(&admin.provider, b"DFWS\x03", admin.id(), [1; 32], &invalid)
            .unwrap();
        assert!(Workspace::restore(&key, [1; 32], admin.id(), &sealed).is_err());
    }
    let mut invalid = plain.clone();
    let epoch_offset = count_offset + 4 + 96;
    invalid[epoch_offset..epoch_offset + 8].copy_from_slice(&2u64.to_be_bytes());
    let sealed = key
        .protect(&admin.provider, b"DFWS\x03", admin.id(), [1; 32], &invalid)
        .unwrap();
    assert!(Workspace::restore(&key, [1; 32], admin.id(), &sealed).is_err());
    let expected_commit = first.commit.clone();
    let expected_welcome = first.welcome.clone();
    drop(first);
    // The candidate and reply survive together; recovery does not run Add again.
    let recovered = Workspace::restore(&key, [1; 32], admin.id(), &snapshot).unwrap();
    assert_eq!(recovered.epoch(), 1);
    assert_eq!(recovered.member_count(), 2);
    assert!(recovered.retained_admission([3; 32], &request).is_err());
    let mut changed_request = request.clone();
    *changed_request.last_mut().unwrap() ^= 1;
    assert!(
        recovered
            .retained_admission([2; 32], &changed_request)
            .unwrap()
            .is_none()
    );
    let retry = recovered
        .retained_admission([2; 32], &request)
        .unwrap()
        .unwrap();
    assert_eq!(retry.commit, expected_commit);
    assert_eq!(retry.welcome, expected_welcome);
    assert_eq!(retry.epoch, 1);
    proof
        .apply_add(&retry.authorization, &retry.commit)
        .unwrap();
    let helper = pending.prepare_workspace(&proof, &retry.welcome).unwrap();
    let mut tampered = snapshot.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(Workspace::restore(&key, [1; 32], admin.id(), &tampered).is_err());
    assert!(
        Workspace::restore(&key, [1; 32], admin.id(), &snapshot[..snapshot.len() - 1]).is_err()
    );
    assert_eq!(helper.member(), Some(&member));
    assert!(helper.issue_invitation().is_err());
    let encoded = proof.history();
    assert!(JoinProof::from_history(admin.id(), [0; 32], encoded).is_err());
    assert!(
        JoinProof::from_history(
            admin.id(),
            invitation.checkpoint_digest(),
            &encoded[..encoded.len() - 1]
        )
        .is_err()
    );
    let mut altered = encoded.to_vec();
    let checkpoint_length = u32::from_be_bytes(altered[37..41].try_into().unwrap()) as usize;
    altered[41 + checkpoint_length + 32] ^= 1; // Administrator grant signature, not the secret-only membership MAC.
    assert!(JoinProof::from_history(admin.id(), invitation.checkpoint_digest(), &altered).is_err());
    let helper_snapshot = helper.seal(&key).unwrap();
    assert!(helper_snapshot.starts_with(b"DFWS\x04"));
    drop(helper);
    let helper = Workspace::restore(&key, [2; 32], admin.id(), &helper_snapshot).unwrap();
    let admin_state = recovered.seal(&key).unwrap();
    let workspace_id = admin.id();
    drop(recovered);
    drop(admin);
    // The issuer is gone. The same preissued token works through an ordinary member.
    let newcomer =
        PendingJoin::from_invitation(&invitation, &checkpoint, [3; 32], "Jordan Lee").unwrap();
    let request = newcomer.admission_request().unwrap();
    assert_eq!(
        helper
            .admission_history([3; 32], request, &checkpoint)
            .unwrap()
            .len(),
        1
    );
    assert!(
        helper
            .admission_history([9; 32], request, &checkpoint)
            .is_err()
    );
    let mut bad_checkpoint = checkpoint.clone();
    *bad_checkpoint.last_mut().unwrap() ^= 1;
    assert!(
        helper
            .admission_history([3; 32], request, &bad_checkpoint)
            .is_err()
    );
    let mut bad_request = request.to_vec();
    bad_request[5 + 133] ^= 1;
    assert!(
        helper
            .admission_history([3; 32], &bad_request, &checkpoint)
            .is_err()
    );
    let mut missing = Workspace::restore(&key, [2; 32], workspace_id, &helper_snapshot).unwrap();
    missing.join_history = None;
    assert_eq!(
        missing
            .admission_history([3; 32], request, &checkpoint)
            .err(),
        Some("invitation history unavailable")
    );
    assert_eq!(missing.epoch(), 1);
    assert_eq!(missing.member_count(), 2);
    let second = helper
        .prepare_admission([3; 32], newcomer.admission_request().unwrap())
        .unwrap();
    assert_eq!(helper.epoch(), 1);
    assert_eq!(helper.member_count(), 2);
    proof
        .apply_add(&second.authorization, &second.commit)
        .unwrap();
    let joined = newcomer.prepare_workspace(&proof, &second.welcome).unwrap();
    assert_eq!(joined.member_count(), 3);
    assert_eq!(joined.member().unwrap().display_name(), "Jordan Lee");
    assert_eq!(
        second
            .workspace
            .prepare_admission([3; 32], newcomer.admission_request().unwrap())
            .err(),
        Some("member already admitted")
    );
    assert_eq!(
        second
            .workspace
            .prepare_admission([4; 32], newcomer.admission_request().unwrap())
            .err(),
        Some("admission endpoint mismatch")
    );
    // Durability/response retention must prevent retry from becoming another Add.
    let joined_state = joined.seal(&key).unwrap();
    let mut joined = Workspace::restore(&key, [3; 32], workspace_id, &joined_state).unwrap();
    let updated_admin = Workspace::restore(&key, [1; 32], workspace_id, &admin_state)
        .unwrap()
        .prepare_admission_update(&second.authorization, &second.commit)
        .unwrap();
    let mut helper = second.workspace;
    let encrypted = joined
        .group
        .create_message(&joined.provider, &joined._signer, b"generic fabric payload")
        .unwrap();
    let wire = MlsMessageIn::tls_deserialize_exact(encrypted.to_bytes().unwrap())
        .unwrap()
        .try_into_protocol_message()
        .unwrap();
    let message = helper
        .group
        .process_message(&helper.provider, wire)
        .unwrap();
    let ProcessedMessageContent::ApplicationMessage(message) = message.into_content() else {
        panic!("not application data")
    };
    assert_eq!(message.into_bytes(), b"generic fabric payload");
    let returning = Workspace::restore(&key, [1; 32], workspace_id, &admin_state).unwrap();
    assert_eq!(returning.epoch(), 1);
    let mut bad = second.authorization.clone();
    bad.grant_signature[0] ^= 1;
    assert!(
        returning
            .prepare_admission_update(&bad, &second.commit)
            .is_err()
    );
    let mut bad_commit = second.commit.clone();
    *bad_commit.last_mut().unwrap() ^= 1;
    assert!(
        returning
            .prepare_admission_update(&second.authorization, &bad_commit)
            .is_err()
    );
    assert_eq!(returning.epoch(), 1); // Rejection and preparation never mutate the accepted owner.
    assert!(
        updated_admin
            .prepare_admission_update(&second.authorization, &second.commit)
            .is_err()
    );
    let stored_update = updated_admin.seal(&key).unwrap();
    let mut returning = Workspace::restore(&key, [1; 32], workspace_id, &stored_update).unwrap();
    assert_eq!(returning.epoch(), 2);
    assert_eq!(returning.member_count(), 3);
    // A restored creator must relay the helper's accepted Add, not only Adds
    // it originated. This history must not depend on retaining a Welcome reply.
    let (_, relayed) = returning
        .membership_update_for([2; 32], 1)
        .unwrap()
        .expect("restored creator retains the helper admission");
    assert_eq!(relayed, second.commit);
    assert!(
        returning
            .membership_update_for([9; 32], 1)
            .unwrap()
            .is_none()
    );
    let later =
        PendingJoin::from_invitation(&invitation, &checkpoint, [8; 32], "Later member").unwrap();
    assert_eq!(
        returning
            .membership_history([8; 32], later.admission_request().unwrap(), &checkpoint,)
            .unwrap()
            .len(),
        2
    );
    let sample = joined
        .protect_object(b"feed/opaque", b"third member sample")
        .unwrap();
    assert_eq!(
        returning
            .unprotect_object(b"feed/opaque", &sample)
            .unwrap()
            .message
            .payload,
        b"third member sample"
    );
    let reply = returning
        .protect_object(b"chat", b"returning member reply")
        .unwrap();
    for reader in [&helper, &joined] {
        assert_eq!(
            reader
                .unprotect_object(b"chat", &reply)
                .unwrap()
                .message
                .payload,
            b"returning member reply"
        );
    }
    // An ordinary existing member carries its anchored authorization history forward too.
    let (next_invite, next_checkpoint) = returning.issue_invitation().unwrap();
    let fourth =
        PendingJoin::from_invitation(&next_invite, &next_checkpoint, [4; 32], "Second service")
            .unwrap();
    let fourth_add = returning
        .prepare_admission([4; 32], fourth.admission_request().unwrap())
        .unwrap();
    let helper_updated = helper
        .prepare_admission_update(&fourth_add.authorization, &fourth_add.commit)
        .unwrap();
    let helper_saved = helper_updated.seal(&key).unwrap();
    let helper_updated = Workspace::restore(&key, [2; 32], workspace_id, &helper_saved).unwrap();
    assert_eq!(helper_updated.member_count(), 4);
    let mut fourth_proof = fourth.join_proof().unwrap();
    fourth_proof
        .apply_add(&fourth_add.authorization, &fourth_add.commit)
        .unwrap();
    let mut fourth = fourth
        .prepare_workspace(&fourth_proof, &fourth_add.welcome)
        .unwrap();
    let sample = fourth
        .protect_object(b"feed/opaque", b"fourth member sample")
        .unwrap();
    assert_eq!(
        helper_updated
            .unprotect_object(b"feed/opaque", &sample)
            .unwrap()
            .message
            .payload,
        b"fourth member sample"
    );
    // A different valid admission from the same parent must not merge silently.
    let competing =
        PendingJoin::from_invitation(&next_invite, &next_checkpoint, [5; 32], "Competing service")
            .unwrap();
    let fork = helper
        .prepare_admission([5; 32], competing.admission_request().unwrap())
        .unwrap();
    assert!(
        helper_updated
            .prepare_admission_update(&fork.authorization, &fork.commit)
            .is_err()
    );
    assert_eq!(helper_updated.member_count(), 4);
}

/// FUT-35: the owner must not re-verify its own already-accepted branch for
/// every arriving admission. When the pinned checkpoint is one this owner
/// issued and retained, the transitions come from its own records instead --
/// and they must be exactly the transitions full verification would produce,
/// including after a restore, and only for the invitation they belong to.
#[test]
fn retained_checkpoint_preflight_matches_full_verification_and_survives_restore() {
    use super::{PendingJoin, StorageKey};
    let admin = Workspace::create([1; 32], "Organizer").unwrap();
    let (created, invitation, checkpoint) = admin.prepare_invitation(0, false, false).unwrap();
    let mut owner = created.workspace;
    assert!(
        owner
            .retained_invitation_checkpoint(&created.action)
            .is_some(),
        "a registered invitation retains the checkpoint it pinned"
    );

    // Grow the accepted branch so a full replay has real work to do.
    for endpoint in 2..6u8 {
        let pending =
            PendingJoin::from_invitation(&invitation, &checkpoint, [endpoint; 32], "Attendee")
                .unwrap();
        owner = owner
            .prepare_admission([endpoint; 32], pending.admission_request().unwrap())
            .unwrap()
            .workspace;
    }

    let later =
        PendingJoin::from_invitation(&invitation, &checkpoint, [9; 32], "Later member").unwrap();
    let request = later.admission_request().unwrap();
    let fast = owner
        .membership_history([9; 32], request, &checkpoint)
        .unwrap();

    // Force the slow path by dropping the retention, and require the same
    // answer. A cheaper preflight that accepted a different branch, or a
    // differently tagged one, would break the joiner it is meant to serve.
    let mut without_retention = owner.seal(&StorageKey::derive(&[7; 32]).unwrap()).unwrap();
    let mut stripped = Workspace::restore(
        &StorageKey::derive(&[7; 32]).unwrap(),
        owner.endpoint(),
        owner.id(),
        &without_retention,
    )
    .unwrap();
    stripped.invitation_checkpoints.clear();
    let slow = stripped
        .membership_history([9; 32], request, &checkpoint)
        .unwrap();
    assert_eq!(fast.len(), slow.len(), "fast path lost or invented a step");
    for (fast, slow) in fast.iter().zip(&slow) {
        assert_eq!(fast.1, slow.1, "fast path chose a different commit");
    }

    // The retention is durable, so a restarted owner keeps the cheap path.
    without_retention.clear();
    let sealed = owner.seal(&StorageKey::derive(&[8; 32]).unwrap()).unwrap();
    let restored = Workspace::restore(
        &StorageKey::derive(&[8; 32]).unwrap(),
        owner.endpoint(),
        owner.id(),
        &sealed,
    )
    .unwrap();
    assert!(
        restored
            .retained_checkpoint_steps(
                &decode_request(&restored.provider, request).unwrap(),
                &checkpoint,
            )
            .unwrap()
            .is_some(),
        "a restarted owner must still take the retained-checkpoint path"
    );

    // A request that does not belong to this invitation never takes it.
    let (other, other_invitation, other_checkpoint) =
        owner.prepare_invitation(0, false, false).unwrap();
    let owner = other.workspace;
    let outsider = PendingJoin::from_invitation(
        &other_invitation,
        &other_checkpoint,
        [10; 32],
        "Other link",
    )
    .unwrap();
    let parsed = decode_request(&owner.provider, outsider.admission_request().unwrap()).unwrap();
    assert!(
        owner
            .retained_checkpoint_steps(&parsed, &checkpoint)
            .unwrap()
            .is_none(),
        "another invitation's checkpoint must not match this request"
    );
}

#[test]
fn batch_replies_share_one_commit_and_welcome_across_copies_and_restores() {
    use super::{PendingJoin, StorageKey};
    let owner = Workspace::create([1; 32], "Organizer").unwrap();
    let (invitation, checkpoint) = owner.issue_invitation().unwrap();
    let mut requests = Vec::new();
    for endpoint in 2..5u8 {
        let pending =
            PendingJoin::from_invitation(&invitation, &checkpoint, [endpoint; 32], "Attendee")
                .unwrap();
        requests.push(([endpoint; 32], pending.admission_request().unwrap().to_vec()));
    }
    let validated: Vec<_> = requests
        .iter()
        .map(|(endpoint, request)| match owner.assess_admission(*endpoint, request).unwrap() {
            AdmissionAssessment::Ready(validated) => validated,
            _ => panic!("invitation unexpectedly needs approval"),
        })
        .collect();
    let entries: Vec<_> = requests
        .iter()
        .zip(&validated)
        .map(|((endpoint, request), validated)| (*endpoint, request.as_slice(), validated))
        .collect();
    let prepared = owner.prepare_validated_admission_batch(&entries).unwrap();
    let shared = prepared.commit.len() + prepared.welcome.len();
    let owner = prepared.workspace;

    // One batch is one commit and one Welcome in memory, however many joiners it admits.
    let assert_shared = |workspace: &Workspace| {
        assert_eq!(workspace.admissions.len(), 3);
        let first = &workspace.admissions[0].reply;
        for entry in &workspace.admissions[1..] {
            assert_eq!(entry.reply.commit.as_ptr(), first.commit.as_ptr());
            assert_eq!(entry.reply.welcome.as_ptr(), first.welcome.as_ptr());
        }
        assert_eq!(workspace.memory_report().admission_bytes, shared);
    };
    assert_shared(&owner);

    // A provisional copy points at the same bytes instead of copying them.
    let copy = owner.provisional_copy().unwrap();
    assert_shared(&copy);
    assert_eq!(
        copy.admissions[0].reply.commit.as_ptr(),
        owner.admissions[0].reply.commit.as_ptr()
    );

    // The record format is unchanged: a restored owner exports the same bytes
    // and shares the batch again.
    let records = owner.export_records().unwrap();
    let restored = Workspace::restore_records([1; 32], owner.id(), &records).unwrap();
    assert_shared(&restored);
    assert_eq!(restored.export_records().unwrap(), records);
    for (endpoint, request) in &requests {
        let before = owner.retained_admission(*endpoint, request).unwrap().unwrap();
        let after = restored.retained_admission(*endpoint, request).unwrap().unwrap();
        assert_eq!((before.epoch, &before.commit, &before.welcome), (after.epoch, &after.commit, &after.welcome));
    }

    // The sealed snapshot is unchanged too: seal, restore, and seal again give
    // the same plaintext.
    let single = Workspace::create([1; 32], "Organizer").unwrap();
    let (invitation, checkpoint) = single.issue_invitation().unwrap();
    let pending =
        PendingJoin::from_invitation(&invitation, &checkpoint, [2; 32], "Attendee").unwrap();
    let single = single
        .prepare_admission([2; 32], pending.admission_request().unwrap())
        .unwrap()
        .workspace;
    let key = StorageKey::derive(&[7; 32]).unwrap();
    let sealed = single.seal(&key).unwrap();
    let reopened = Workspace::restore(&key, [1; 32], single.id(), &sealed).unwrap();
    let resealed = reopened.seal(&key).unwrap();
    let plain = |bytes: &[u8]| {
        let magic: &[u8; 5] = bytes[..5].try_into().unwrap();
        key.unprotect(magic, single.id(), [1; 32], bytes).unwrap()
    };
    assert_eq!(resealed[..5], sealed[..5]);
    assert_eq!(plain(&resealed), plain(&sealed));
}
