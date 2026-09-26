//! Bounded next-membership-transition retrieval over authenticated peer control requests.
//! Replies contain no Welcome, bearer invitation or private group state.
use super::*;
use crate::errors::{self, security};
use crate::ops::management::{StagedCandidate, StagedChange, StagedRemoval};
use arachne_api::{ApiError, ErrorCode};
#[cfg(test)]
mod fork_tests;
pub(crate) mod fork;
pub(crate) mod self_update;
pub(crate) mod wire;
pub(super) use wire::encode_reply;

/// The accepted local state an exchange was based on, not a remote claim.
#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct StateBasis {
    epoch: u64,
    fingerprint: [u8; 32],
    name_head: [u8; 32],
}

impl StateBasis {
    /// Harness-seam constructor (see `crate::harness`); grants no authority.
    #[doc(hidden)]
    pub fn new(epoch: u64, fingerprint: [u8; 32], name_head: [u8; 32]) -> Self {
        Self {
            epoch,
            fingerprint,
            name_head,
        }
    }
}
/// A management intent from the host. Remove, Demote and DisableInvitation
/// become signed revocation orders when staged; a departure is not an
/// intent here (it is a leave order another member commits).
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(
    tag = "kind",
    content = "member",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum WireManagement {
    Promote([u8; 32]),
    Demote([u8; 32]),
    Remove([u8; 32]),
    CreateInvitation {
        key: [u8; 32],
        expires_at: u64,
        personal: bool,
    },
    CreateAutomaticInvitation {
        key: [u8; 32],
        expires_at: u64,
    },
    CreateRequestInvitation {
        key: [u8; 32],
        expires_at: u64,
    },
    DeclineInvitationRequest {
        key: [u8; 32],
        package: [u8; 32],
    },
    DisableInvitation([u8; 32]),
    ApproveInvitation {
        key: [u8; 32],
        package: [u8; 32],
    },
}
impl WireManagement {
    pub(super) fn action(&self) -> Result<arachne_security::ManagementAction, ApiError> {
        Ok(match self {
            Self::Promote(id) => arachne_security::ManagementAction::Promote(*id),
            Self::Demote(id) => arachne_security::ManagementAction::Demote(*id),
            Self::Remove(id) => arachne_security::ManagementAction::Remove(*id),
            Self::CreateInvitation {
                key,
                expires_at,
                personal,
            } => arachne_security::ManagementAction::CreateInvitation(*key, *expires_at, *personal),
            Self::CreateAutomaticInvitation { key, expires_at } => {
                arachne_security::ManagementAction::CreateAutomaticInvitation(*key, *expires_at)
            }
            Self::CreateRequestInvitation { key, expires_at } => {
                arachne_security::ManagementAction::CreateRequestInvitation(*key, *expires_at)
            }
            Self::DeclineInvitationRequest { key, package } => {
                arachne_security::ManagementAction::DeclineInvitationRequest(*key, *package)
            }
            Self::ApproveInvitation { key, package } => {
                arachne_security::ManagementAction::ApproveInvitation(*key, *package)
            }
            Self::DisableInvitation(key) => {
                arachne_security::ManagementAction::DisableInvitation(*key)
            }
        })
    }
}

/// One membership step as the host carries it. The general form is the
/// binary step codec (`step`, `DFMS\x03`), which carries every kind,
/// including signed revocation orders and self-updates. A joiner may also
/// carry its own admission in the redemption form (`commit` and
/// `authorization`, as the admission reply names them). `kind` is
/// informational only; the binary step is what is verified.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct JoinStep {
    #[serde(default)]
    step: Option<Vec<u8>>,
    #[serde(default)]
    #[allow(dead_code)]
    kind: Option<String>,
    #[serde(default)]
    commit: Option<Vec<u8>>,
    #[serde(default)]
    authorization: Option<JoinAuthorization>,
    #[serde(default)]
    invitation_checkpoint: Option<InvitationCheckpoint>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InvitationCheckpoint {
    pub(super) grant: Vec<u8>,
    pub(super) checkpoint: Vec<u8>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinAuthorization {
    invitation_key: [u8; 32],
    grant_signature: Vec<u8>,
    redemption_signature: Vec<u8>,
}
impl JoinStep {
    /// One admission step, as a joiner's host carries it back.
    pub(crate) fn admission(
        commit: Vec<u8>,
        invitation_key: [u8; 32],
        grant_signature: Vec<u8>,
        redemption_signature: Vec<u8>,
    ) -> Self {
        Self {
            step: None,
            kind: None,
            commit: Some(commit),
            authorization: Some(JoinAuthorization {
                invitation_key,
                grant_signature,
                redemption_signature,
            }),
            invitation_checkpoint: None,
        }
    }

    /// A step in the binary codec, with the invitation checkpoint a
    /// registration carries.
    pub(crate) fn binary(step: Vec<u8>, invitation_checkpoint: Option<(Vec<u8>, Vec<u8>)>) -> Self {
        Self {
            step: Some(step),
            kind: None,
            commit: None,
            authorization: None,
            invitation_checkpoint: invitation_checkpoint
                .map(|(grant, checkpoint)| InvitationCheckpoint { grant, checkpoint }),
        }
    }

    /// The authorization and the exact commit bytes. Structure only: the
    /// caller verifies the step against its own state.
    pub(super) fn parts(
        &self,
    ) -> Result<(arachne_security::MembershipAuthorization, Vec<u8>), ApiError> {
        match (&self.step, &self.commit, &self.authorization) {
            (Some(step), None, None) => {
                if step.len() > MAX_WIRE_STEP {
                    return Err(ApiError::limit_reached(
                        "membership step",
                        MAX_WIRE_STEP as u64,
                        "membership step exceeds transport bound",
                    ));
                }
                arachne_security::decode_membership_step(step)
                    .map_err(|reason| ApiError::invalid_input("step", reason))
            }
            (None, Some(commit), Some(auth)) => Ok((
                arachne_security::MembershipAuthorization::Admission(
                    arachne_security::AdmissionAuthorization {
                        invitation_key: auth.invitation_key,
                        grant_signature: auth.grant_signature.clone().try_into().map_err(
                            |_| ApiError::invalid_input("step", "invalid grant signature length"),
                        )?,
                        redemption_signature: auth.redemption_signature.clone().try_into().map_err(
                            |_| {
                                ApiError::invalid_input(
                                    "step",
                                    "invalid redemption signature length",
                                )
                            },
                        )?,
                    },
                ),
                commit.clone(),
            )),
            _ => Err(ApiError::invalid_input(
                "step",
                "membership step requires a binary step or an admission commit and authorization",
            )),
        }
    }

    pub(super) fn take_invitation_checkpoint(&mut self) -> Option<InvitationCheckpoint> {
        self.invitation_checkpoint.take()
    }
}

/// Largest encoded membership step this runtime accepts, stores or sends.
/// A step (with any anchor proof it carries) above this bound is refused on
/// receipt and never committed, so no node holds a step it cannot serve or
/// store: a history record holds up to 1 MiB, and a step must fit one
/// control reply. It bounds anchor proofs far below the security crate's
/// 2 MiB decoder bound.
pub(crate) const MAX_WIRE_STEP: usize =
    arachne_security::MAX_MEMBERSHIP_COMMIT + MAX_STEP_AUTHORIZATION;

/// The largest authorization a step carries besides its commit: a full
/// admission batch (key and two signatures per admission) and the codec
/// header. Anchor proofs must fit in this too.
const MAX_STEP_AUTHORIZATION: usize = 20 * 1024 + 1024;

/// The transport cap and the verifier bound move together (B3c): one step
/// of the largest verifiable size, plus the reply envelope, fits one
/// control reply, so every step a node accepts it can also serve.
const _: () = assert!(
    arachne_security::MAX_MEMBERSHIP_COMMIT
        + arachne_security::MAX_ADMISSION_BATCH * (32 + 64 + 64)
        + 16
        <= MAX_WIRE_STEP
);
const _: () = assert!(MAX_WIRE_STEP + 1024 <= arachne_node::MAX_CONTROL_REPLY);

/// A short, informational name for a step's kind.
pub(crate) fn step_kind(auth: &arachne_security::MembershipAuthorization) -> &'static str {
    use arachne_security::{ManagementAction as A, MembershipAuthorization as M, RevocationKind as R};
    match auth {
        M::Admission(_) => "admission",
        M::AdmissionBatch(_) => "admission_batch",
        M::SelfUpdate => "self_update",
        M::Revocation(step) => match step.order.kind {
            R::Remove => "remove",
            R::Leave => "leave",
            R::Demote => "demote",
            R::DisableInvitation => "disable_invitation",
        },
        M::Management(action) => match action {
            A::Promote(_) => "promote",
            A::Demote(_) => "demote",
            A::Remove(_) => "remove",
            A::CreateInvitation(..) => "create_invitation",
            A::CreateAutomaticInvitation(..) => "create_automatic_invitation",
            A::CreateRequestInvitation(..) => "create_request_invitation",
            A::DeclineInvitationRequest(..) => "decline_invitation_request",
            A::DisableInvitation(_) => "disable_invitation",
            A::ApproveInvitation(..) => "approve_invitation",
        },
    }
}

/// Encode one step in the binary codec, bounded by the transport cap.
pub(crate) fn encode_step(
    auth: &arachne_security::MembershipAuthorization,
    commit: &[u8],
) -> Result<Vec<u8>, ApiError> {
    let step = arachne_security::encode_membership_step(auth, commit)
        .map_err(|reason| ApiError::invalid_input("step", reason))?;
    if step.len() > MAX_WIRE_STEP {
        return Err(ApiError::limit_reached(
            "membership step",
            MAX_WIRE_STEP as u64,
            "membership step exceeds transport bound",
        ));
    }
    Ok(step)
}

/// The host JSON of one step: the binary step and its kind.
pub(crate) fn step_json(auth: &arachne_security::MembershipAuthorization, commit: &[u8]) -> Value {
    match arachne_security::encode_membership_step(auth, commit) {
        Ok(step) => json!({"step": step, "kind": step_kind(auth)}),
        Err(_) => Value::Null,
    }
}

/// Whether this member is an administrator of its committed state.
pub(crate) fn is_administrator(owner: &arachne_security::Workspace) -> bool {
    let Some(own) = owner.member().map(|member| member.id()) else {
        return false;
    };
    owner
        .member_roster()
        .is_ok_and(|roster| roster.iter().any(|m| m.id == own && m.administrator))
}

/// Step bytes one history page carries: a control reply is 128 KiB, and the
/// rest holds the envelope and optional records (B3c). A single step larger
/// than this still travels alone when it fits the reply.
pub(crate) const PAGE_STEP_BYTES: usize = 96 * 1024;

/// Encode one step for the peer wire. The invitation checkpoint rides along
/// only while the whole step stays within `room`; it is optional.
pub(crate) fn wire_step(
    step: &[u8],
    invitation_checkpoint: Option<(&[u8], &[u8])>,
    room: usize,
) -> Result<Vec<u8>, ApiError> {
    if step.len() > MAX_WIRE_STEP {
        return Err(ApiError::limit_reached(
            "membership step",
            MAX_WIRE_STEP as u64,
            "membership step exceeds transport bound",
        ));
    }
    if invitation_checkpoint.is_some()
        && let Ok(bytes) = wire::encode_wire_step(&wire::WireStep {
            step,
            invitation_checkpoint,
        })
        && bytes.len() <= room
    {
        return Ok(bytes);
    }
    wire::encode_wire_step(&wire::WireStep {
        step,
        invitation_checkpoint: None,
    })
    .map_err(ApiError::internal)
}

/// The wire form of one host-JSON step (`step` and an optional
/// `invitation_checkpoint`).
pub(crate) fn wire_step_from_json(value: &Value, room: usize) -> Result<Vec<u8>, ApiError> {
    let invalid = || ApiError::invalid_input("step", "invalid membership step");
    let step: Vec<u8> = serde_json::from_value(value["step"].clone()).map_err(|_| invalid())?;
    let checkpoint = value
        .get("invitation_checkpoint")
        .map(|checkpoint| {
            let part = |name: &str| {
                serde_json::from_value::<Vec<u8>>(checkpoint[name].clone()).map_err(|_| invalid())
            };
            Ok::<_, ApiError>((part("grant")?, part("checkpoint")?))
        })
        .transpose()?;
    wire_step(
        &step,
        checkpoint
            .as_ref()
            .map(|(grant, checkpoint)| (grant.as_slice(), checkpoint.as_slice())),
        room,
    )
}

/// The host JSON of one wire step.
pub(crate) fn wire_step_json(bytes: &[u8]) -> Result<Value, String> {
    let step = wire::decode_wire_step(bytes)?;
    let (authorization, _) = arachne_security::decode_membership_step(step.step)
        .map_err(|_| "invalid membership step")?;
    let mut value = json!({"step": step.step, "kind": step_kind(&authorization)});
    if let Some((grant, checkpoint)) = step.invitation_checkpoint {
        value["invitation_checkpoint"] = json!({"grant":grant,"checkpoint":checkpoint});
    }
    Ok(value)
}

/// The step a peer sent, for staging.
pub(crate) fn join_step_from_wire(bytes: &[u8]) -> Result<JoinStep, ApiError> {
    let step = wire::decode_wire_step(bytes)
        .map_err(|reason| ApiError::invalid_input("step", reason))?;
    Ok(JoinStep::binary(
        step.step.to_vec(),
        step.invitation_checkpoint
            .map(|(grant, checkpoint)| (grant.to_vec(), checkpoint.to_vec())),
    ))
}

/// This owner's wire step, with the invitation checkpoint it retained.
fn owner_wire_step(
    owner: &arachne_security::Workspace,
    auth: &arachne_security::MembershipAuthorization,
    commit: &[u8],
    room: usize,
) -> Result<Vec<u8>, ApiError> {
    let step = encode_step(auth, commit)?;
    let checkpoint = match auth {
        arachne_security::MembershipAuthorization::Management(action) => {
            owner.retained_invitation_checkpoint(action)
        }
        _ => None,
    };
    wire_step(&step, checkpoint, room)
}

fn step_with_retained_checkpoint(
    owner: &arachne_security::Workspace,
    auth: &arachne_security::MembershipAuthorization,
    commit: &[u8],
) -> Value {
    let mut value = step_json(auth, commit);
    if let arachne_security::MembershipAuthorization::Management(action) = auth
        && let Some((grant, checkpoint)) = owner.retained_invitation_checkpoint(action)
    {
        value["invitation_checkpoint"] = json!({"grant":grant,"checkpoint":checkpoint});
    }
    value
}

pub(super) fn reply(
    owner: Option<&arachne_security::Workspace>,
    peer: [u8; 32],
    bytes: &[u8],
) -> Value {
    let denied = json!({"state":"membership_denied"});
    let Some(owner) = owner else { return denied };
    let Ok(query) = wire::decode_query(bytes) else {
        return denied;
    };
    if query.workspace != owner.id() {
        return denied;
    }
    let after = query.basis.epoch;
    let step = match owner.membership_update_for(peer, after) {
        Ok(step) => step,
        Err(_) => return denied,
    };
    let current = owner.member_id_for_endpoint(peer).is_ok();
    if step.is_none() && !current {
        return denied;
    }
    // A terminal notification does not expose subsequent membership activity.
    let epoch = if current {
        owner.epoch()
    } else {
        let Some(epoch) = after.checked_add(1) else {
            return denied;
        };
        epoch
    };
    let mut result = json!({"workspace":owner.id(), "after":after, "epoch":epoch});
    if current {
        result["epoch_fingerprint"] = json!(owner.epoch_fingerprint());
    }
    if let Some((authorization, commit)) = step {
        result["state"] = json!("membership_update_available");
        result["step"] = step_with_retained_checkpoint(owner, &authorization, &commit);
    } else {
        result["state"] = json!(if after == owner.epoch() {
            "membership_current"
        } else {
            "membership_unavailable"
        });
    }
    result
}

// Per-request/wire chunk bound: a single merge_profiles call carries at most this
// many profiles. Mirrors the ≤64-per-call chunking Kotlin's WorkspaceMembers.kt
// publishes against (REQUEST_PROFILE_LIMIT) and the membership/wire.rs query
// shape (peer replies carry at most one retained profile). This bounds one
// request's cost, not how many profiles the session retains across calls --
// see MAX_PROFILE_SET_BYTES below for that.
const MAX_REQUEST_PROFILES: usize = 64;

// Peer profile-digest comparison hints are a bounded LRU cache of distinct
// peers (fixed-size 32-byte digests, evicting the oldest peer on overflow),
// not the member-profile retention path this issue is about: unaffected by
// the MAX_PROFILES -> MAX_PROFILE_SET_BYTES change above.
const MAX_PEER_PROFILE_SUMMARIES: usize = 64;

// Session-only profile retention is bounded by bytes rather than member count.
// Profiles are not included in export_records; overflow is reported to callers.
pub(super) const MAX_PROFILE_SET_BYTES: usize = 4 * 128 * 1024;

/// Merges verified incoming profiles into the retained set and returns whether
/// the byte budget forced any of them to be dropped. Budget pressure is a
/// presentation concern, never a membership-control failure: this never
/// returns `Err` for running out of budget. It retains whatever fits and
/// silently completes the merge for the rest -- "silently" for the merge
/// itself, but every caller surfaces the returned overflow flag as an
/// explicit signal in its reply rather than dropping it unnoticed. `Err` is
/// reserved for malformed input (an over-count or over-size batch, or no
/// workspace/own profile to merge against), which is a different failure
/// class from a healthy retained set simply being full.
/// Budget-parameterized so a test can exceed a small budget with a handful of
/// real admitted members instead of the ~1,300 needed to exceed
/// MAX_PROFILE_SET_BYTES for real; every production caller (`roster`,
/// `reply_with_profiles`, `poll`) fixes the budget at MAX_PROFILE_SET_BYTES.
fn merge_profiles_with_budget(
    session: &mut Session,
    profiles: &[Vec<u8>],
    budget: usize,
) -> Result<bool, ApiError> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    merge_into(
        owner,
        &mut lock_profiles(&session.membership.profiles),
        profiles,
        budget,
    )
}

/// Retained signed member profiles. Shared by the host and the inquiry
/// responder, so a membership query is answered without the host.
/// Every holder takes the lock for one short, I/O-free step.
#[derive(Default)]
pub(super) struct ProfileSet {
    retained: std::collections::BTreeMap<[u8; 32], Vec<u8>>,
    cursor: Option<[u8; 32]>,
    pub(super) service: bool,
    /// The committed state (epoch, fingerprint) every retained profile was
    /// last verified against. A profile verified at one state stays valid at
    /// that state, so the set is checked again only when the state changes,
    /// not on each query (503 signature checks per query on the owner).
    checked: Option<(u64, [u8; 32])>,
    /// Profiles an inquiry answer retained first, for the host to gossip.
    to_gossip: VecDeque<Vec<u8>>,
    /// A query answered without the host that the host has not heard of:
    /// `Some(peer)` when the querier is a current member.
    answered: Option<Option<[u8; 32]>>,
}

pub(super) type Profiles = Arc<Mutex<ProfileSet>>;

pub(super) fn lock_profiles(profiles: &Profiles) -> std::sync::MutexGuard<'_, ProfileSet> {
    profiles.lock().unwrap_or_else(|error| error.into_inner())
}

impl ProfileSet {
    fn queue_gossip(&mut self, bytes: Vec<u8>) {
        hold_profile(&mut self.to_gossip, bytes);
    }

    /// Record a query the inquiry responder answered, for the host.
    pub(super) fn note_answered(&mut self, peer: Option<[u8; 32]>) {
        let earlier = self.answered.flatten();
        self.answered = Some(peer.or(earlier));
    }
}

fn merge_into(
    owner: &arachne_security::Workspace,
    set: &mut ProfileSet,
    profiles: &[Vec<u8>],
    budget: usize,
) -> Result<bool, ApiError> {
    if profiles.len() > MAX_REQUEST_PROFILES
        || profiles
            .iter()
            .any(|p| p.len() > arachne_security::MAX_MEMBER_PROFILE)
    {
        return Err(ApiError::invalid_input("profiles", "member profile cache exceeds bounds"));
    }
    let state = (owner.epoch(), owner.epoch_fingerprint());
    // An answer in progress may hold a view older than the last commit.
    // It must not remove names that the newer state verified.
    let behind = set.checked.is_some_and(|(epoch, _)| owner.epoch() < epoch);
    if !behind && set.checked != Some(state) {
        set.retained
            .retain(|_, bytes| owner.verify_member_profile(bytes).is_ok());
        set.checked = Some(state);
    }
    let own = if set.service {
        owner.sign_service_profile()
    } else {
        owner.sign_member_profile()
    }
    .map_err(security(ErrorCode::InvalidInput))?;
    let own_id = owner.member().ok_or_else(|| ApiError::wrong_state("member profile required"))?.id();

    // Verify and de-duplicate the incoming batch. Unverifiable profiles are
    // dropped here, same as before -- that is not a bound rejection.
    let mut incoming = std::collections::BTreeMap::new();
    for bytes in profiles {
        if let Ok(profile) = owner.verify_member_profile(bytes)
            && profile.id() != own_id
        {
            incoming.insert(profile.id(), bytes.clone());
        }
    }

    let mut total_bytes = set.retained.values().map(Vec::len).sum::<usize>();
    total_bytes -= set.retained.get(&own_id).map_or(0, Vec::len);
    total_bytes += own.len();

    // Retain whatever fits the budget; drop the rest and report overflow
    // rather than failing the merge (a full budget must never brick a
    // control operation -- FUT-37 kickback #1). This walks incoming in id
    // order (BTreeMap), so which profiles get dropped is deterministic, not
    // caller-order-dependent.
    let mut overflowed = false;
    let mut to_retain = std::collections::BTreeMap::new();
    for (id, bytes) in incoming {
        let existing = set.retained.get(&id).map_or(0, Vec::len);
        let projected = total_bytes - existing + bytes.len();
        if projected > budget {
            overflowed = true;
            continue;
        }
        total_bytes = projected;
        to_retain.insert(id, bytes);
    }

    set.retained.insert(own_id, own);
    set.retained.extend(to_retain);
    Ok(overflowed)
}

pub(super) fn roster(session: &mut Session, profiles: &[Vec<u8>]) -> Result<RosterReply, ApiError> {
    roster_with_budget(session, profiles, MAX_PROFILE_SET_BYTES)
}

/// One member as the roster shows it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct RosterMember {
    pub id: [u8; 32],
    pub endpoint: [u8; 32],
    pub administrator: bool,
    #[serde(rename = "self")]
    pub self_member: bool,
    pub display_name: Option<String>,
    pub last_contact_age_ms: Option<u64>,
    pub presence_fresh_for_ms: Option<u64>,
    pub kind: &'static str,
    pub presence: &'static str,
}

/// The member roster with retained signed names.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct RosterReply {
    pub workspace: [u8; 32],
    pub workspace_name: Option<String>,
    pub workspace_name_revision: u64,
    pub workspace_name_head: [u8; 32],
    pub epoch: u64,
    pub members: Vec<RosterMember>,
    pub profiles: Vec<Vec<u8>>,
    /// `Some(false)`: the byte budget dropped at least one incoming profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profiles_retained: Option<bool>,
}

/// Budget-parameterized for the same reason as `merge_profiles_with_budget`.
fn roster_with_budget(
    session: &mut Session,
    profiles: &[Vec<u8>],
    budget: usize,
) -> Result<RosterReply, ApiError> {
    let overflowed = merge_profiles_with_budget(session, profiles, budget)?;
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    let own_id = owner
        .member()
        .ok_or_else(|| ApiError::wrong_state("member profile required"))?
        .id();
    let set = lock_profiles(&session.membership.profiles);
    let members = owner
        .member_roster()
        .map_err(security(ErrorCode::Internal))?
        .into_iter()
        .map(|member| {
            let now = std::time::Instant::now();
            let contact_age = (member.id != own_id)
                .then(|| presence::contact_age(&session.presence, member.endpoint, now))
                .flatten();
            let profile = set
                .retained
                .get(&member.id)
                .and_then(|bytes| owner.verify_member_profile(bytes).ok());
            RosterMember {
                id: member.id,
                endpoint: member.endpoint,
                administrator: member.administrator,
                self_member: member.id == own_id,
                display_name: profile
                    .as_ref()
                    .map(|profile| profile.display_name().to_owned()),
                last_contact_age_ms: contact_age
                    .map(|age| age.as_millis().min(u64::MAX as u128) as u64),
                presence_fresh_for_ms: contact_age
                    .map(|age| presence::fresh_for(age).as_millis() as u64),
                kind: if profile.as_ref().is_some_and(|profile| profile.is_service()) {
                    "service"
                } else {
                    "person"
                },
                presence: if member.id == own_id {
                    "self"
                } else {
                    presence::status(&session.presence, member.endpoint, now)
                },
            }
        })
        .collect::<Vec<_>>();
    // Distinguishable, non-silent signal that the byte budget dropped at
    // least one incoming profile this call -- never an Err (FUT-37 kickback
    // #1): a full retention budget must not fail a membership-control
    // operation, and member_roster is reachable from the same control-adjacent
    // paths (PollMembershipUpdate, open/refresh), not just presentation.
    Ok(RosterReply {
        workspace: owner.id(),
        workspace_name: owner
            .workspace_name()
            .map_err(security(ErrorCode::Internal))?,
        workspace_name_revision: owner
            .workspace_name_revision()
            .map_err(security(ErrorCode::Internal))?,
        workspace_name_head: owner
            .workspace_name_head()
            .map_err(security(ErrorCode::Internal))?,
        epoch: owner.epoch(),
        members,
        profiles: set.retained.values().cloned().collect(),
        profiles_retained: overflowed.then_some(false),
    })
}

#[cfg(test)]
fn roster_value(session: &mut Session, profiles: &[Vec<u8>]) -> Result<Value, ApiError> {
    Ok(serde_json::to_value(roster(session, profiles)?).unwrap())
}

#[cfg(test)]
fn roster_with_budget_value(
    session: &mut Session,
    profiles: &[Vec<u8>],
    budget: usize,
) -> Result<Value, ApiError> {
    Ok(serde_json::to_value(roster_with_budget(session, profiles, budget)?).unwrap())
}

fn profiles_digest(owner: &arachne_security::Workspace, set: &ProfileSet) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"arachne/profile-set/1\0");
    hash.update(owner.id());
    hash.update(owner.epoch_fingerprint());
    for (id, profile) in &set.retained {
        hash.update(id);
        hash.update((profile.len() as u64).to_be_bytes());
        hash.update(profile);
    }
    hash.finalize().into()
}

fn profile_page(
    owner: &arachne_security::Workspace,
    set: &mut ProfileSet,
    peer: [u8; 32],
) -> Vec<Vec<u8>> {
    let own_id = owner.member().unwrap().id();
    let requester = owner.member_id_for_endpoint(peer).unwrap();
    let mut candidates = set
        .retained
        .keys()
        .copied()
        .filter(|id| *id != own_id && *id != requester);
    let retained = candidates
        .clone()
        .find(|id| set.cursor.is_none_or(|after| *id > after))
        .or_else(|| candidates.next());
    let mut profiles = vec![set.retained[&own_id].clone()];
    if let Some(id) = retained {
        set.cursor = Some(id);
        profiles.push(set.retained[&id].clone());
    }
    profiles
}

/// The host path for a membership query: the same answer the inquiry
/// responder gives, then the newly learned names go out by gossip at once.
pub(super) fn reply_with_profiles(session: &mut Session, peer: [u8; 32], bytes: &[u8]) -> Value {
    let result = answer_query(
        session.workspace.as_deref(),
        &mut lock_profiles(&session.membership.profiles),
        peer,
        bytes,
        MAX_PROFILE_SET_BYTES,
    );
    send_queued_profiles(session);
    result
}

/// Gossip the profiles that membership queries retained first.
pub(super) fn send_queued_profiles(session: &Session) {
    let queued = std::mem::take(&mut lock_profiles(&session.membership.profiles).to_gossip);
    for bytes in queued {
        broadcast_profile(session, &bytes);
    }
}

/// The host-facing notice for queries the inquiry responder answered since
/// the host last heard: the same event the host path returns for a query.
pub(super) fn take_answered(session: &Session) -> Option<Value> {
    let peer = lock_profiles(&session.membership.profiles).answered.take()?;
    let mut event = json!({"state":"membership_replied", "remote_receipt":false});
    if let Some(peer) = peer {
        event["peer"] = json!(peer);
    }
    Some(event)
}

/// Answer a membership query from one committed workspace and the shared
/// profile set, with or without the host. It writes only to
/// `set`: the querier's carried profiles, verified against this roster, the
/// page cursor, and the gossip queue. Budget-parameterized for the same
/// reason as `merge_profiles_with_budget`.
pub(super) fn answer_query(
    owner: Option<&arachne_security::Workspace>,
    set: &mut ProfileSet,
    peer: [u8; 32],
    bytes: &[u8],
    budget: usize,
) -> Value {
    let mut result = reply(owner, peer, bytes);
    if result["state"] == "membership_denied" {
        return result;
    }
    let owner = owner.unwrap(); // reply denies without a workspace
    let query = wire::decode_query(bytes).unwrap(); // reply already validated the complete query
    let current = owner.member_id_for_endpoint(peer).is_ok();
    if current && result["state"] == "membership_current" {
        let after = query.basis.name_head;
        if let (Ok(head), Ok(next)) = (
            owner.workspace_name_head(),
            owner.next_workspace_name(after),
        ) {
            result["name_head"] = json!(head);
            result["name_revision"] = json!(owner.workspace_name_revision().ok());
            if let Some(record) = next {
                result["name_record"] = json!(record);
            }
            if after != head
                && let Ok(Some(checkpoint)) = owner.workspace_name_checkpoint()
            {
                result["name_checkpoint"] = json!(checkpoint);
            }
        }
    }
    if current {
        let profiles: Vec<_> = query
            .profiles
            .iter()
            .filter(|p| !p.is_empty())
            .map(|p| p.to_vec())
            .collect();
        // A full retention budget is presentation pressure, not grounds to
        // deny an otherwise-valid membership reply (FUT-37 kickback #1):
        // only a malformed batch (Err) still denies here. Budget overflow
        // (Ok(true)) is carried as a metadata signal instead.
        // The overflow flag itself is not sent to the peer: each side
        // displays from its own retained set and learns its own overflow
        // through its own host-facing member_roster call, and an already
        // existing signal -- a profiles_digest mismatch -- already tells the
        // peer the two retained sets differ. Adding a field here would also
        // change the postcard-encoded wire envelope (Metadata in wire.rs),
        // which is a cross-version compatibility break outside this fix's
        // scope. Only a malformed batch (Err) still denies here.
        let id = |bytes: &[u8]| {
            owner
                .verify_member_profile(bytes)
                .ok()
                .map(|profile| profile.id())
        };
        let known: Vec<Option<Vec<u8>>> = profiles
            .iter()
            .map(|bytes| id(bytes).and_then(|id| set.retained.get(&id).cloned()))
            .collect();
        if merge_into(owner, set, &profiles, budget).is_err() {
            return json!({"state":"membership_denied"});
        }
        // A name this node just learned travels on to every member by gossip:
        // replies carry only two names each, so pulled names lagged.
        for (bytes, before) in profiles.iter().zip(known) {
            let retained = id(bytes).is_some_and(|id| set.retained.get(&id) == Some(bytes));
            if retained && before.as_ref() != Some(bytes) {
                set.queue_gossip(bytes.clone());
            }
        }
        let digest = profiles_digest(owner, set);
        result["profiles_digest"] = json!(digest);
        if digest != query.profiles_digest {
            result["profiles"] = json!(profile_page(owner, set, peer));
        }
        // Optional presentation must not crowd out a membership transition.
        if wire::encode_reply(&result).is_err() {
            result.as_object_mut().unwrap().remove("profiles");
        }
    }
    result
}

fn agreement(owner: &arachne_security::Workspace, value: &Value) -> Result<&'static str, ApiError> {
    if value["epoch"] != owner.epoch() {
        return Err(ApiError::epoch_mismatch("current membership reply has a different epoch"));
    }
    let fingerprint = value
        .get("epoch_fingerprint")
        .and_then(|v| serde_json::from_value::<[u8; 32]>(v.clone()).ok());
    Ok(match fingerprint {
        None => "membership_unverified",
        Some(remote) if remote != owner.epoch_fingerprint() => "membership_branch_mismatch",
        Some(_) => "membership_current",
    })
}

/// A peer that failed a membership query is skipped this long, unless every peer is.
const MEMBERSHIP_PEER_COOLDOWN: Duration = Duration::from_secs(60);
/// Presence contact this recent marks a peer as likely reachable.
const MEMBERSHIP_PEER_RECENT: Duration = Duration::from_secs(120);

pub(super) struct PeerChoice {
    pub(super) endpoint: [u8; 32],
    /// An administrator, or a peer with recent presence contact.
    pub(super) preferred: bool,
    /// Failed a membership query within the cooldown.
    pub(super) cooling: bool,
}

/// Next peer to ask for membership updates, round-robin after `after` within
/// the best non-empty tier: preferred and not cooling; preferred; not cooling;
/// all. A cooling preferred peer (usually one that just restarted) is a better
/// bet than members never heard from. `peers` must be sorted by endpoint.
pub(super) fn choose_membership_peer(
    peers: &[PeerChoice],
    after: Option<[u8; 32]>,
) -> Option<[u8; 32]> {
    let tiers: [&dyn Fn(&PeerChoice) -> bool; 4] = [
        &|peer| peer.preferred && !peer.cooling,
        &|peer| peer.preferred,
        &|peer| !peer.cooling,
        &|_| true,
    ];
    tiers.iter().find_map(|tier| {
        let mut eligible = peers
            .iter()
            .filter(|peer| tier(peer))
            .map(|peer| peer.endpoint)
            .peekable();
        let first = *eligible.peek()?;
        Some(
            eligible
                .find(|peer| after.is_none_or(|after| *peer > after))
                .unwrap_or(first),
        )
    })
}

/// One membership reconciliation step, from the host or a drive op.
pub(crate) enum Reconcile {
    /// The next peer to ask, round-robin after `after`.
    NextPeer { after: Option<[u8; 32]> },
    /// Offer the step after `after` to `peer`.
    Offer { peer: [u8; 32], after: u64 },
    /// Offer the staged administrator promotion to `peer` before adoption.
    OfferStaged { peer: [u8; 32] },
    /// The outcome of the pending offer, if finished.
    PollOffer,
    /// Ask `peer` for the next step.
    Fetch { peer: [u8; 32], replace_pending: bool },
    /// The outcome of the pending query, if finished.
    PollUpdate,
}

/// Run one reconciliation step. The reply is an open event (typed with
/// `Event` in ADR step 4); `null` means nothing finished yet.
pub(crate) fn reconcile(session: &mut Session, step: Reconcile) -> Result<Value, ApiError> {
    poll_with_budget(session, step, MAX_PROFILE_SET_BYTES)
}

/// Start one authenticated membership query from a native work signal.  The
/// host may still request this explicitly for diagnostics, but normal
/// convergence does not need a peer walk or a Kotlin retry loop.
pub(super) fn start_query_if_needed(
    session: &mut Session,
    peer: [u8; 32],
) -> Result<bool, ApiError> {
    if session.membership.update.is_some() {
        return Ok(false);
    }
    if session
        .membership.peer_failures
        .get(&peer)
        .is_some_and(|failed| failed.elapsed() < MEMBERSHIP_PEER_COOLDOWN)
    {
        return Ok(false);
    }
    start_query(session, peer, false, MAX_PROFILE_SET_BYTES)?;
    Ok(true)
}

fn start_query(
    session: &mut Session,
    peer: [u8; 32],
    replace_pending: bool,
    budget: usize,
) -> Result<(), ApiError> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    if session.membership.update.is_some() && !replace_pending {
        return Err(ApiError::wrong_state("membership query already pending"));
    }
    if peer == session.node.id() || owner.member_id_for_endpoint(peer).is_err() {
        return Err(ApiError::invalid_input("peer", "membership query requires another admitted peer"));
    }
    drop(session.membership.update.take());
    let basis = StateBasis {
        epoch: owner.epoch(),
        fingerprint: owner.epoch_fingerprint(),
        name_head: owner.workspace_name_head().map_err(security(ErrorCode::Internal))?,
    };
    let workspace = owner.id();
    merge_profiles_with_budget(session, &[], budget)?;
    let owner = session
        .workspace
        .as_deref()
        .ok_or_else(errors::no_workspace)?;
    let mut set = lock_profiles(&session.membership.profiles);
    let digest = profiles_digest(owner, &set);
    let profiles = if session.membership.peer_profile_summaries.get(&peer) == Some(&digest) {
        Vec::new()
    } else {
        profile_page(owner, &mut set, peer)
    };
    drop(set);
    let query = wire::encode_query(&wire::Query {
        workspace,
        basis,
        profiles_digest: digest,
        profiles: [
            profiles.first().map_or(&[], Vec::as_slice),
            profiles.get(1).map_or(&[], Vec::as_slice),
        ],
    })
    // Our own query; a failure here is a runtime bug, not the peer's.
    .map_err(ApiError::internal)?;
    // The reply is an outbound event, so it does not enqueue a control
    // request locally. Wake the existing host drain when it completes.
    let request = session.node.request_control(peer, &query);
    let wake = session.node.control_signal();
    let task = session.runtime.spawn(async move {
        let reply = request.await;
        wake.notify_one();
        reply
    });
    session.membership.update = Some(PendingControl {
        query: basis,
        peer,
        task,
    });
    Ok(())
}

fn queue_membership_offer(
    session: &mut Session,
    peer: [u8; 32],
    after: u64,
    authorization: arachne_security::MembershipAuthorization,
    commit: Vec<u8>,
    requires_adoption: bool,
) -> Result<Value, ApiError> {
    if session.membership.offer.is_some() {
        return Err(ApiError::wrong_state("membership offer already pending"));
    }
    let packet = offer_packet(
        session
            .workspace
            .as_ref()
            .ok_or_else(errors::no_workspace)?,
        after,
        &authorization,
        &commit,
        requires_adoption,
    )?;
    // The outcome wakes the host drain, as a query reply does: a staged
    // self-update waits on it (B3c).
    let request = session.node.request_control(peer, &packet);
    let wake = session.node.control_signal();
    let task = session.runtime.spawn(async move {
        let reply = request.await;
        wake.notify_one();
        reply
    });
    session.membership.offer = Some(PendingControl {
        query: after,
        peer,
        task,
    });
    session.membership.offer_requires_adoption = requires_adoption;
    Ok(json!({"state":"membership_offer_pending"}))
}

/// Budget-parameterized for the same reason as `merge_profiles_with_budget`:
/// lets a test drive FetchMembershipUpdate/PollMembershipUpdate's profile
/// merge into overflow with a handful of real admitted members.
fn poll_with_budget(
    session: &mut Session,
    request: Reconcile,
    budget: usize,
) -> Result<Value, ApiError> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    match request {
        Reconcile::NextPeer { after } => {
            let now = std::time::Instant::now();
            session.membership.peer_failures.retain(|_, failed| {
                now.saturating_duration_since(*failed) < MEMBERSHIP_PEER_COOLDOWN
            });
            let mut peers = owner
                .member_roster()
                .map_err(security(ErrorCode::Internal))?
                .into_iter()
                .filter(|member| member.endpoint != session.node.id())
                .map(|member| PeerChoice {
                    endpoint: member.endpoint,
                    preferred: member.administrator
                        || presence::contact_age(&session.presence, member.endpoint, now)
                            .is_some_and(|age| age < MEMBERSHIP_PEER_RECENT),
                    cooling: session
                        .membership.peer_failures
                        .contains_key(&member.endpoint),
                })
                .collect::<Vec<_>>();
            peers.sort_unstable_by_key(|peer| peer.endpoint);
            let peer = choose_membership_peer(&peers, after);
            let member = peer
                .as_ref()
                .map(|peer| owner.member_id_for_endpoint(*peer))
                .transpose()
                .map_err(security(ErrorCode::InvalidInput))?;
            Ok(json!({"peer":peer,"member":member,"epoch":owner.epoch()}))
        }
        Reconcile::Offer { peer, after } => {
            if session.membership.offer.is_some() {
                return Err(ApiError::wrong_state("membership offer already pending"));
            }
            if peer == session.node.id() || owner.member_id_for_endpoint(peer).is_err() {
                return Err(ApiError::invalid_input("peer", "membership offer requires another admitted peer"));
            }
            let Some((authorization, commit)) = owner
                .membership_update_for(peer, after)
                .map_err(security(ErrorCode::InvalidInput))?
            else {
                return Ok(json!({"state":"membership_offer_unavailable","next_after":0}));
            };
            queue_membership_offer(session, peer, after, authorization, commit, false)
        }
        Reconcile::OfferStaged { peer } => {
            let (after, action, commit) = {
                let owner = session
                    .workspace
                    .as_ref()
                    .ok_or_else(errors::no_workspace)?;
                if peer == session.node.id() || owner.member_id_for_endpoint(peer).is_err() {
                    return Err(ApiError::invalid_input("peer", "membership offer requires another admitted peer"));
                }
                let staged = session
                    .transition.staged
                    .as_ref()
                    .ok_or_else(|| ApiError::wrong_state("workspace candidate is not staged"))?;
                let WorkspaceTransition::Management(action, authorization, commit) =
                    &staged.transition
                else {
                    return Err(ApiError::wrong_state("staged membership offer requires a management transition"));
                };
                if !matches!(action, arachne_security::ManagementAction::Promote(_)) {
                    return Err(ApiError::unsupported("staged membership offer only supports administrator promotion"));
                }
                (owner.epoch(), authorization.clone(), commit.clone())
            };
            queue_membership_offer(session, peer, after, action, commit, true)
        }
        Reconcile::PollOffer => {
            if !session
                .membership.offer
                .as_ref()
                .is_some_and(|pending| pending.task.is_finished())
            {
                return Ok(Value::Null);
            }
            let requires_adoption = session.membership.offer_requires_adoption;
            session.membership.offer_requires_adoption = false;
            let mut pending = session.membership.offer.take().unwrap();
            let bytes = session
                .runtime
                .block_on(&mut pending.task)
                .map_err(|_| ApiError::internal("membership offer task failed"))?
                .map_err(errors::node)?;
            if requires_adoption && bytes.as_slice() != [1] {
                return Err(ApiError::not_authorized("membership peer rejected the staged administrator handoff"));
            }
            if !matches!(bytes.as_slice(), [0] | [1] | [OFFER_PULL]) {
                return Err(ApiError::transport_failed(None, "invalid membership offer acknowledgment"));
            }
            let next = pending
                .query
                .checked_add(1)
                .filter(|next| *next < owner.epoch())
                .unwrap_or(0);
            // Peer acknowledgments are availability only. They never install local authority.
            Ok(json!({"state":"membership_offer_finished","peer":pending.peer,"next_after":next}))
        }
        Reconcile::Fetch {
            peer,
            replace_pending,
        } => {
            start_query(session, peer, replace_pending, budget)?;
            Ok(json!({"state":"membership_update_pending"}))
        }
        Reconcile::PollUpdate => {
            if !session
                .membership.update
                .as_ref()
                .is_some_and(|pending| pending.task.is_finished())
            {
                return Ok(Value::Null);
            }
            let mut pending = session.membership.update.take().unwrap();
            let bytes = match session
                .runtime
                .block_on(&mut pending.task)
                .map_err(|_| ApiError::internal("membership query task failed"))
                .and_then(|reply| reply.map_err(errors::node))
            {
                Ok(bytes) => bytes,
                Err(_error) => {
                    session
                        .membership.peer_failures
                        .insert(pending.peer, std::time::Instant::now());
                    // Reconciliation is advisory. A peer that is offline or
                    // saturated must not turn the workspace driver into a
                    // failed control operation; cooldown above prevents a
                    // tight retry loop and the next presence can retry it.
                    return Ok(json!({
                        "state":"membership_unavailable",
                        "peer":pending.peer,
                        "transport":true
                    }));
                }
            };
            session.membership.peer_failures.remove(&pending.peer);
            if owner.epoch() != pending.query.epoch
                || owner.epoch_fingerprint() != pending.query.fingerprint
                || owner.workspace_name_head().map_err(security(ErrorCode::Internal))? != pending.query.name_head
                || owner.member_id_for_endpoint(pending.peer).is_err()
            {
                return Ok(json!({"state":"membership_update_stale"}));
            }
            let mut value = wire::decode_reply(&bytes)
                .map_err(|reason| ApiError::transport_failed(None, reason))?;
            if value["state"] == "membership_denied" {
                return Ok(value);
            }
            if value["workspace"] != json!(owner.id())
                || value["after"] != pending.query.epoch
                || !matches!(
                    value["state"].as_str(),
                    Some(
                        "membership_update_available"
                            | "membership_current"
                            | "membership_unavailable"
                    )
                )
            {
                return Err(ApiError::transport_failed(None, "membership reply does not match query"));
            }
            let membership_head = value["epoch"].as_u64();
            if value["state"] == "membership_current" {
                let state = agreement(owner, &value)?;
                if state != "membership_current" {
                    let result = json!({"state":state,"workspace":owner.id(),"epoch":owner.epoch(),"peer":pending.peer});
                    if state == "membership_branch_mismatch" { fork::start(session, pending.peer); }
                    return Ok(result);
                }
            }
            if let Some(profiles) = value.get("profiles") {
                let profiles: Vec<Vec<u8>> = serde_json::from_value(profiles.clone())
                    .map_err(|_| ApiError::transport_failed(None, "invalid member profiles"))?;
                // A full retention budget must never fail PollMembershipUpdate
                // (FUT-37 kickback #1): the membership transition already
                // decoded into `value` is real and must still be returned.
                // Only a malformed batch (Err) still fails the poll; budget
                // overflow is carried through as a reply signal instead.
                if merge_profiles_with_budget(session, &profiles, budget)? {
                    value["profiles_retained"] = json!(false);
                }
            }
            if let Some(digest) = value.get("profiles_digest") {
                let digest = serde_json::from_value(digest.clone())
                    .map_err(|_| ApiError::transport_failed(None, "invalid profiles summary"))?;
                // Only a peer's comparison hint, never authority for a profile.
                if !session.membership.peer_profile_summaries.contains_key(&pending.peer)
                    && session.membership.peer_profile_summaries.len() >= MAX_PEER_PROFILE_SUMMARIES
                {
                    session.membership.peer_profile_summaries.pop_first();
                }
                session.membership.peer_profile_summaries.insert(pending.peer, digest);
                // The peer holds names we do not: walk its set once, in
                // pages, unless we already walked this exact set.
                let owner = session
                    .workspace
                    .as_deref()
                    .ok_or_else(errors::no_workspace)?;
                let ours = profiles_digest(owner, &lock_profiles(&session.membership.profiles));
                if ours != digest && session.membership.profiles_walked.get(&pending.peer) != Some(&digest) {
                    start_profile_pull(session, pending.peer, None, digest);
                }
            }
            if value["state"] == "membership_current"
                && let Some(head) = value.get("name_head")
            {
                let head: [u8; 32] = serde_json::from_value(head.clone())
                    .map_err(|_| ApiError::transport_failed(None, "invalid workspace name head"))?;
                let owner = session
                    .workspace
                    .as_ref()
                    .ok_or_else(errors::no_workspace)?;
                if head != owner.workspace_name_head().map_err(security(ErrorCode::Internal))? {
                    let mut rejected_record = None;
                    let mut rejection_reason = None;
                    if let Some(record) = value.get("name_record") {
                        let record: Vec<u8> = serde_json::from_value(record.clone())
                            .map_err(|_| ApiError::transport_failed(None, "invalid workspace name record"))?;
                        if record.len() > arachne_security::MAX_WORKSPACE_NAME_RECORD {
                            return Err(ApiError::limit_reached("workspace name record", arachne_security::MAX_WORKSPACE_NAME_RECORD as u64, "workspace name record exceeds bound"));
                        }
                        match owner.prepare_workspace_name_update(&record) {
                            Ok(_) => {
                                return Ok(
                                    json!({"state":"workspace_name_update_available","name_record":record,"peer":pending.peer}),
                                );
                            }
                            Err(reason) => {
                                rejection_reason = Some(reason);
                                rejected_record = Some(record);
                            }
                        }
                    }
                    let ours = owner.workspace_name_revision().map_err(security(ErrorCode::Internal))?;
                    let remote_revision = value["name_revision"].as_u64();
                    if remote_revision.is_some_and(|revision| revision < ours) {
                        return Ok(json!({
                            "state":"workspace_name_peer_behind",
                            "peer":pending.peer,
                            "name_revision":value["name_revision"],
                            "local_name_revision":ours,
                            "local_workspace_name":owner.workspace_name().map_err(security(ErrorCode::Internal))?,
                            "name_head":head,
                            "local_name_head":owner.workspace_name_head().map_err(security(ErrorCode::Internal))?,
                            "name_update_rejected":rejection_reason,
                        }));
                    }
                    if remote_revision.is_some_and(|revision| revision == ours) {
                        return Ok(json!({
                            "state":"workspace_name_conflict",
                            "peer":pending.peer,
                            "name_revision":value["name_revision"],
                            "local_name_revision":ours,
                            "local_workspace_name":owner.workspace_name().map_err(security(ErrorCode::Internal))?,
                            "name_head":head,
                            "local_name_head":owner.workspace_name_head().map_err(security(ErrorCode::Internal))?,
                            "name_update_rejected":rejection_reason,
                        }));
                    }
                    if let Some(checkpoint) = value.get("name_checkpoint") {
                        let checkpoint: Vec<u8> = serde_json::from_value(checkpoint.clone())
                            .map_err(|_| ApiError::transport_failed(None, "invalid workspace name checkpoint"))?;
                        if checkpoint.len() > arachne_security::MAX_WORKSPACE_NAME_CHECKPOINT {
                            return Err(ApiError::limit_reached("workspace name checkpoint", arachne_security::MAX_WORKSPACE_NAME_CHECKPOINT as u64, "workspace name checkpoint exceeds bound"));
                        }
                        return Ok(json!({"state":"workspace_name_checkpoint_available",
                            "name_checkpoint":checkpoint,"peer":pending.peer}));
                    }
                    if let Some(record) = rejected_record {
                        return Ok(
                            json!({"state":"workspace_name_update_available","name_record":record,"peer":pending.peer}),
                        );
                    }
                    // A peer behind this accepted chain can learn from our next poll response.
                    if owner
                        .next_workspace_name(head)
                        .map_err(security(ErrorCode::Internal))?
                        .is_none()
                    {
                        return Ok(
                            json!({"state":"workspace_name_unavailable","peer":pending.peer}),
                        );
                    }
                }
            }
            if let Some(head) = membership_head {
                // The authenticated reply also identifies this peer's newest
                // committed epoch. Keep it as a pull hint so losing a later
                // gossip/presence announcement cannot strand a bounded range
                // catch-up at an earlier head.
                note_head(session, head, pending.peer);
            }
            // A peer at a lower epoch cannot extend ours: it is behind, not in
            // conflict, and head gossip catches it up. Reported as
            // unavailable, it raised "Membership differs" on the owner (fix16c).
            if value["state"] == "membership_unavailable"
                && value["epoch"]
                    .as_u64()
                    .is_some_and(|epoch| epoch < pending.query.epoch)
            {
                value["state"] = json!("membership_peer_behind");
            }
            // Availability is the peer's claim. StageAdmissionUpdate validates
            // the complete signed authorization and commit against local state.
            Ok(value)
        }
    }
}

/// Admits `count` real members (in-process MLS, no networking) against a
/// fresh owner workspace, named "{name_prefix} {i}", and returns the final
/// owner plus each admitted member's own Workspace (so it can sign its own
/// profile) and endpoint. Slow: admission is MLS-crypto-bound (roughly
/// 0.9s/admission measured locally), so keep `count` as small as each test
/// allows.
#[cfg(test)]
pub(super) fn admit_members(
    seed: u8,
    name_prefix: &str,
    count: u16,
) -> (
    arachne_security::Workspace,
    Vec<arachne_security::Workspace>,
    Vec<[u8; 32]>,
) {
    let _ = seed;
    let owner_key = arachne_security::EndpointKey::generate().unwrap();
    let (registered, invitation, checkpoint) =
        arachne_security::Workspace::create(&owner_key, "Coordinator")
            .unwrap()
            .prepare_invitation(0, false, false)
            .unwrap();
    let mut owner = registered.workspace;
    let mut members = Vec::with_capacity(count as usize);
    let mut endpoints = Vec::with_capacity(count as usize);
    for i in 0..count {
        let key = arachne_security::EndpointKey::generate().unwrap();
        let endpoint = arachne_security::EndpointSigner::endpoint(&key);
        let pending = arachne_security::PendingJoin::from_invitation(
            &invitation,
            &checkpoint,
            &key,
            &format!("{name_prefix} {i}"),
        )
        .unwrap();
        let request = pending.admission_request().unwrap();
        let prepared = owner.prepare_admission(endpoint, request).unwrap();
        let mut proof = pending.join_proof().unwrap();
        // One registered link: each joiner replays every step since its checkpoint.
        for (authorization, commit) in prepared
            .workspace
            .membership_history(endpoint, request, &checkpoint)
            .unwrap()
        {
            proof.apply_transition(&authorization, &commit).unwrap();
        }
        let member = pending
            .prepare_workspace(&proof, &prepared.welcome)
            .unwrap();
        owner = prepared.workspace;
        members.push(member);
        endpoints.push(endpoint);
    }
    (owner, members, endpoints)
}

/// Builds a real arachne-runtime Session directly, bypassing
/// super::create()/REGISTRY entirely: REGISTRY enforces a process-wide
/// 8-node cap that tests::real_node_lifecycle_rejects_stale_handles_and_releases_capacity
/// relies on being exact, and this crate's test binary runs tests
/// concurrently by default. A real bound Node is still required (Session is
/// not Node-optional), just one the test owns and closes itself (on Drop,
/// at the end of the test).
#[cfg(test)]
pub(super) fn bare_test_session(workspace: impl Into<Arc<arachne_security::Workspace>>) -> Session {
    let context = crate::context::Context::for_tests();
    let (node, receiver) = context
        .handle()
        .block_on(Node::bind_with_profile(
            ([0, 0, 0, 0], 0).into(),
            None,
            arachne_node::NetworkProfile::Direct,
            arachne_node::ConnectionBudget::default(),
        ))
        .unwrap();
    let committed = super::committed_view::Published::new(None);
    let mut session = Session::new(
        node,
        receiver,
        context,
        committed,
        presence::Presence::new().unwrap(),
    );
    session.activity = super::WorkspaceActivity {
        phase: super::WorkspacePhase::Active,
        reason: None,
    };
    // Staging needs record storage; each bare session has its own.
    let workspace: Arc<arachne_security::Workspace> = workspace.into();
    session.storage = Some(super::StorageConfig::memory(&arachne_store::MemoryProvider::default()));
    super::persistence::commit_created(&mut session, &workspace, None, None).unwrap();
    session.workspace = Some(workspace);
    session
}

// FUT-37: the owner's in-session profile cache must retain every admitted
// member's profile across calls, not just the first MAX_PROFILES (64) of
// them. Before the fix, `merge_profiles` gated new-member inserts on
// `session.member_profiles.len() < MAX_PROFILES`, silently dropping the
// 65th+ profile while still returning `Ok`, so `member_roster` never
// displayed their names. Profiles are published in two calls (64 then 36)
// to mirror the real client's chunked publication and to exercise
// retention *across* calls, not just within one.
#[test]
fn member_roster_retains_profiles_for_100_admitted_members() {
    let (owner, members, _) = admit_members(9, "Field member", 100);
    let profiles: Vec<Vec<u8>> = members
        .iter()
        .map(|member| member.sign_member_profile().unwrap())
        .collect();

    let mut session = bare_test_session(owner);
    let session = &mut session;
    // Two calls of <= MAX_REQUEST_PROFILES each: this is the same wire chunk
    // bound Kotlin's WorkspaceMembers.kt publishes against (REQUEST_PROFILE_LIMIT
    // = 64); retention must grow across these calls, not just within one.
    roster_value(session, &profiles[..64]).unwrap();
    let reply2 = roster_value(session, &profiles[64..]).unwrap();

    let owner = session.workspace.as_ref().unwrap();
    let own_id = owner.member().unwrap().id();
    let names: std::collections::BTreeSet<String> = reply2["members"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["id"] != json!(own_id))
        .map(|m| {
            m["display_name"]
                .as_str()
                .expect("every admitted member must have a retained, displayable name")
                .to_owned()
        })
        .collect();
    assert_eq!(
        names.len(),
        100,
        "expected all 100 member names to be retained and displayed, got {}",
        names.len()
    );
    for i in 0..100 {
        assert!(
            names.contains(&format!("Field member {i}")),
            "member {i}'s name was not retained past the old 64-profile cap"
        );
    }
    assert_eq!(
        reply2.get("profiles_retained"),
        None,
        "the full budget was nowhere close to exhausted by 100 small profiles"
    );

    // AC: a profile that a genuine bound rejects (per-profile size) still
    // produces a distinguishable, non-Ok signal -- never a silent Ok.
    let oversized = vec![0u8; arachne_security::MAX_MEMBER_PROFILE + 1];
    assert!(roster_value(session, &[oversized]).is_err());
}

// FUT-37 PR #102 kickback #1: a full retention *byte budget* is presentation
// pressure, not grounds to fail a membership-control operation. Before this
// fix, merge_profiles returned Err once the budget was exhausted, and that
// Err propagated straight through member_roster (Err out of execute_request)
// and through PollMembershipUpdate's `merge_profiles(session, &profiles)?`
// (failing the poll even though a real membership_update/membership_current
// reply had already been decoded) -- the exact #88 "silent, then a hard
// failure at scale" pattern, just at the control layer instead of a display
// layer. Uses `_with_budget` seams (budget-parameterized, but otherwise the
// exact same code every production caller runs) so 3 real admissions are
// enough to exceed the test's tiny budget, instead of the ~1,300 needed to
// exceed the real MAX_PROFILE_SET_BYTES.
#[test]
fn budget_pressure_never_fails_member_roster_or_poll_membership_update() {
    let (owner, members, endpoints) = admit_members(11, "Overflow member", 3);
    let profiles: Vec<Vec<u8>> = members
        .iter()
        .map(|member| member.sign_member_profile().unwrap())
        .collect();
    let own_len = owner.sign_member_profile().unwrap().len();
    let member_len = profiles[0].len();
    assert!(
        profiles.iter().all(|p| p.len() == member_len),
        "these three members' names are the same length, so their signed profiles should be too"
    );
    // Fits the owner's own profile plus exactly one member's; a second
    // member's profile does not fit.
    let tiny_budget = own_len + member_len + 8;

    let mut session = bare_test_session(owner);
    let session = &mut session;

    // member_roster (host API / the "open"/refresh surface): must succeed
    // and signal overflow, never Err, once the budget can't hold every
    // profile it's handed.
    let reply1 = roster_with_budget_value(session, &profiles[..1], tiny_budget).unwrap();
    assert_eq!(
        reply1.get("profiles_retained"),
        None,
        "the first profile alone must fit the budget"
    );
    let reply2 = roster_with_budget_value(session, &profiles[1..2], tiny_budget).unwrap();
    assert_eq!(
        reply2["profiles_retained"],
        json!(false),
        "member_roster must signal that the byte budget dropped a profile, not silently succeed as if nothing was lost"
    );
    assert_eq!(
        reply2["members"].as_array().unwrap().len(),
        4,
        "member_roster must still return the full membership list (all admitted members) even though one profile's presentation didn't fit the byte budget"
    );

    // PollMembershipUpdate (control path): construct a synthetic peer reply,
    // exactly as reply_with_profiles_with_budget would build one, carrying a
    // profile that overflows the same tiny (already-full) budget, and
    // confirm PollMembershipUpdate still returns the real membership state
    // -- never `membership_denied`, never Err -- while carrying the overflow
    // signal.
    let owner = session.workspace.as_ref().unwrap();
    let peer_reply = json!({
        "workspace": owner.id(),
        "after": owner.epoch(),
        "epoch": owner.epoch(),
        "epoch_fingerprint": owner.epoch_fingerprint(),
        "state": "membership_current",
        "profiles": [profiles[2].clone()],
    });
    let bytes = encode_reply(&peer_reply).unwrap();
    session.membership.update = Some(PendingControl {
        query: StateBasis {
            epoch: owner.epoch(),
            fingerprint: owner.epoch_fingerprint(),
            name_head: owner.workspace_name_head().unwrap(),
        },
        peer: endpoints[0],
        task: session
            .runtime
            .spawn(async move { Ok::<Vec<u8>, arachne_node::Error>(bytes) }),
    });
    while !session
        .membership.update
        .as_ref()
        .unwrap()
        .task
        .is_finished()
    {
        std::thread::yield_now();
    }
    let result = poll_with_budget(session, Reconcile::PollUpdate, tiny_budget).unwrap();
    assert_ne!(
        result["state"],
        json!("membership_denied"),
        "PollMembershipUpdate must not deny a real membership reply because of profile-budget pressure"
    );
    assert_eq!(
        result["profiles_retained"],
        json!(false),
        "PollMembershipUpdate must surface the overflow signal from locally merging the peer's profiles, not silently drop it"
    );
}

// Measured, not assumed: a signed profile is header, workspace, member id,
// name and signature. At a typical name it is ~150 bytes; the largest
// possible is 390. So MAX_PROFILE_SET_BYTES holds ~3,500 typical and 1,344
// largest profiles: it was not what held names at ~250 of 503 on the tablets.
#[test]
fn a_signed_profile_is_about_150_bytes_and_the_retained_set_fits_1000_members() {
    let name = "Field member 123";
    let key = arachne_security::EndpointKey::generate().unwrap();
    let workspace = arachne_security::Workspace::create(&key, name).unwrap();
    let profile = workspace.sign_member_profile().unwrap();
    assert_eq!(profile.len(), 5 + 32 + 32 + name.len() + 64);
    assert_eq!(profile.len(), 149);
    assert_eq!(arachne_security::MAX_MEMBER_PROFILE, 390);
    assert!(MAX_PROFILE_SET_BYTES / profile.len() > 3_500);
    const { assert!(MAX_PROFILE_SET_BYTES >= 1_000 * arachne_security::MAX_MEMBER_PROFILE) };
}

// A join wave: names arrive by gossip before the steps that admit their
// members reach this node (three tablets, 500 joiners, 2026-09-19: names
// stopped at ~250 of 503). Every held name must survive until its step lands.
#[test]
fn gossiped_names_from_a_join_wave_survive_until_their_steps_land() {
    // Past the old 128-name hold; 300 in-process admissions exceed the
    // invitation checkpoint bound in `admit_members`.
    const WAVE: u16 = 200;
    let (owner, members, _) = admit_members(13, "Wave member", WAVE);
    let profiles: Vec<Vec<u8>> = members
        .iter()
        .map(|member| member.sign_member_profile().unwrap())
        .collect();
    // The first joiner, still at the epoch it joined: every later joiner is
    // unknown to it, so their names wait.
    let mut session = bare_test_session(members.into_iter().next().unwrap());
    for bytes in &profiles[1..] {
        take_gossiped_profile(&mut session, bytes.clone());
    }
    // The later steps land: this node now holds the latest committed state.
    super::commit_workspace(&mut session, owner);
    stage_gossiped_step(&mut session).unwrap();
    let roster = roster_value(&mut session, &[]).unwrap();
    let named = roster["members"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|member| member["self"] == false && !member["display_name"].is_null())
        .count();
    assert_eq!(
        named,
        usize::from(WAVE) - 1,
        "names were dropped while their steps were on the way"
    );
}

// The responder answers from the view it read, and a commit can replace
// that view while the answer is in progress. An older view must not remove
// names that a newer commit already verified.
#[test]
fn an_answer_from_an_older_view_keeps_names_a_newer_commit_verified() {
    let (owner, members, _) = admit_members(17, "Late view member", 3);
    let profiles: Vec<Vec<u8>> = members
        .iter()
        .map(|member| member.sign_member_profile().unwrap())
        .collect();
    let newest_id = owner.verify_member_profile(&profiles[2]).unwrap().id();
    let mut set = ProfileSet::default();
    merge_into(&owner, &mut set, &profiles, MAX_PROFILE_SET_BYTES).unwrap();
    assert!(set.retained.contains_key(&newest_id));
    // A view from the first admission's epoch: the later members are unknown to it.
    let older = &members[0];
    assert!(older.epoch() < owner.epoch());
    merge_into(older, &mut set, &[], MAX_PROFILE_SET_BYTES).unwrap();
    assert!(
        set.retained.contains_key(&newest_id),
        "an older view removed a newer member's name"
    );
    assert_eq!(
        set.checked,
        Some((owner.epoch(), owner.epoch_fingerprint()))
    );
}

// Names a member missed (a gossip it did not get, a restart) come back from
// one peer in pages. Before, each membership reply carried one retained name
// picked by the answerer's own cursor: 69 missing names took 69 or more
// queries, 5 s apart on a device, and every other querier moved the cursor.
#[test]
fn missing_names_come_back_from_one_peer_in_pages() {
    const MEMBERS: u16 = 70;
    let (owner, members, endpoints) = admit_members(16, "Paged member", MEMBERS);
    let profiles: Vec<Vec<u8>> = members
        .iter()
        .map(|member| member.sign_member_profile().unwrap())
        .collect();
    let owner = Arc::new(owner);
    let answerer_endpoint = owner.endpoint();
    let mut answerer = bare_test_session(owner.clone());
    for chunk in profiles.chunks(MAX_REQUEST_PROFILES) {
        roster_value(&mut answerer, chunk).unwrap();
    }
    // The newest member holds the latest state but no other member's name.
    let requester_endpoint = *endpoints.last().unwrap();
    let mut requester = bare_test_session(members.into_iter().last().unwrap());
    let ready = |session: &mut Session, reply: Vec<u8>| {
        session
            .runtime
            .spawn(async move { Ok::<Vec<u8>, arachne_node::Error>(reply) })
    };
    let settle = |task: &tokio::task::JoinHandle<Result<Vec<u8>, arachne_node::Error>>| {
        while !task.is_finished() {
            std::thread::yield_now();
        }
    };

    // One membership query, carried in-process.
    let basis = StateBasis::new(
        owner.epoch(),
        owner.epoch_fingerprint(),
        owner.workspace_name_head().unwrap(),
    );
    let (digest, carried) = {
        let mut set = lock_profiles(&requester.membership.profiles);
        let own = requester.workspace.clone().unwrap();
        merge_into(&own, &mut set, &[], MAX_PROFILE_SET_BYTES).unwrap();
        (
            profiles_digest(&own, &set),
            profile_page(&own, &mut set, answerer_endpoint),
        )
    };
    let query = wire::encode_query(&wire::Query {
        workspace: owner.id(),
        basis,
        profiles_digest: digest,
        profiles: [
            carried.first().map_or(&[], Vec::as_slice),
            carried.get(1).map_or(&[], Vec::as_slice),
        ],
    })
    .unwrap();
    let reply = encode_reply(&reply_with_profiles(
        &mut answerer,
        requester_endpoint,
        &query,
    ))
    .unwrap();
    let task = ready(&mut requester, reply);
    settle(&task);
    requester.membership.update = Some(PendingControl {
        query: basis,
        peer: answerer_endpoint,
        task,
    });
    let polled = reconcile(&mut requester, Reconcile::PollUpdate).unwrap();
    assert_eq!(polled["state"], "membership_current", "{polled}");

    // Its page pulls, carried in-process: three pages hold 70 names.
    for _ in 0..usize::from(MEMBERS).div_ceil(wire::MAX_PAGE_PROFILES) + 1 {
        let Some(after) = requester
            .membership.profile_pull
            .as_ref()
            .map(|pending| pending.query.after)
        else {
            break;
        };
        let query = wire::encode_profile_query(&wire::ProfileQuery {
            workspace: owner.id(),
            after,
        })
        .unwrap();
        let page = profile_page_reply(
            Some(&owner),
            &lock_profiles(&answerer.membership.profiles),
            requester_endpoint,
            &query,
        );
        let task = ready(&mut requester, page);
        settle(&task);
        requester.membership.profile_pull.as_mut().unwrap().task = task;
        stage_gossiped_step(&mut requester).unwrap();
    }
    let roster = roster_value(&mut requester, &[]).unwrap();
    let named = roster["members"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|member| member["self"] == false && !member["display_name"].is_null())
        .count();
    assert_eq!(
        named,
        usize::from(MEMBERS),
        "missing names did not come back in pages"
    );
    assert!(requester.membership.profile_pull.is_none(), "the walk did not end");
}

#[test]
fn a_range_serves_consecutive_steps_to_members_only() {
    let (owner, _, endpoints) = admit_members(12, "Range member", 3);
    let member = endpoints[0];
    let query = |after, until| {
        wire::encode_range_query(&wire::RangeQuery {
            workspace: owner.id(),
            after,
            until,
        })
        .unwrap()
    };
    let steps = |bytes: &[u8]| {
        let reply = wire::decode_range_reply(bytes).unwrap();
        (
            reply.after,
            reply
                .steps
                .iter()
                .map(|step| step.to_vec())
                .collect::<Vec<_>>(),
        )
    };
    // From the member's own epoch to the head, in order, as single pulls give them.
    let (after, range) = steps(&range_reply(Some(&owner), member, &query(1, owner.epoch())));
    assert_eq!(after, 1);
    assert_eq!(range.len() as u64, owner.epoch() - 1);
    for (next, step) in (1..).zip(&range) {
        let (authorization, commit) = owner.membership_update_for(member, next).unwrap().unwrap();
        // Binary on the wire (B3c): the step codec, not JSON numbers.
        let wire = wire::decode_wire_step(step).unwrap();
        assert!(wire.step.starts_with(b"DFMS\x03"));
        assert_eq!(
            wire.step,
            arachne_security::encode_membership_step(&authorization, &commit).unwrap()
        );
        assert!(join_step_from_wire(step).unwrap().parts().is_ok());
    }
    // Never past the requested end or the local head.
    assert_eq!(
        steps(&range_reply(Some(&owner), member, &query(1, 2)))
            .1
            .len(),
        1
    );
    assert_eq!(
        steps(&range_reply(Some(&owner), member, &query(1, u64::MAX)))
            .1
            .len(),
        range.len()
    );
    // A stranger, another workspace or a malformed query learns nothing.
    assert!(
        steps(&range_reply(
            Some(&owner),
            [200; 32],
            &query(1, owner.epoch())
        ))
        .1
        .is_empty()
    );
    let other = wire::encode_range_query(&wire::RangeQuery {
        workspace: [9; 32],
        after: 1,
        until: 3,
    })
    .unwrap();
    assert!(
        steps(&range_reply(Some(&owner), member, &other))
            .1
            .is_empty()
    );
    let good = query(1, owner.epoch());
    assert!(
        steps(&range_reply(Some(&owner), member, &good[..good.len() - 1]))
            .1
            .is_empty()
    );
    assert!(steps(&range_reply(None, member, &good)).1.is_empty());
}

#[test]
fn membership_metadata_requires_an_admitted_peer_and_exact_workspace_query() {
    let key = arachne_security::EndpointKey::generate().unwrap();
    let owner = arachne_security::Workspace::create(&key, "Coordinator").unwrap();
    let own = owner.endpoint();
    let make_query = |epoch| {
        wire::encode_query(&wire::Query {
            workspace: owner.id(),
            basis: StateBasis {
                epoch,
                fingerprint: owner.epoch_fingerprint(),
                name_head: owner.workspace_name_head().unwrap(),
            },
            profiles_digest: [0; 32],
            profiles: [&[], &[]],
        })
        .unwrap()
    };
    let mut query = make_query(0);
    assert_eq!(
        reply(Some(&owner), own, &query)["state"],
        "membership_current"
    );
    assert_eq!(
        reply(Some(&owner), [2; 32], &query)["state"],
        "membership_denied"
    );
    assert_eq!(reply(None, own, &query)["state"], "membership_denied");
    for length in 0..query.len() {
        assert_eq!(
            reply(Some(&owner), own, &query[..length])["state"],
            "membership_denied"
        );
    }
    query[5] ^= 1;
    assert_eq!(
        reply(Some(&owner), own, &query)["state"],
        "membership_denied"
    );
    query[5] ^= 1;
    query = make_query(1);
    assert_eq!(
        reply(Some(&owner), own, &query)["state"],
        "membership_unavailable"
    );
    query.push(0);
    assert_eq!(
        reply(Some(&owner), own, &query)["state"],
        "membership_denied"
    );
}

#[test]
fn equal_epoch_needs_matching_fingerprint_and_malformed_claims_are_not_current() {
    let key = arachne_security::EndpointKey::generate().unwrap();
    let owner = arachne_security::Workspace::create(&key, "Coordinator").unwrap();
    let mut response = json!({"epoch":owner.epoch(),"epoch_fingerprint":owner.epoch_fingerprint()});
    assert_eq!(agreement(&owner, &response).unwrap(), "membership_current");
    for invalid in [
        Value::Null,
        json!([]),
        json!(vec![0; 31]),
        json!(vec![256; 32]),
        json!("invalid"),
    ] {
        response["epoch_fingerprint"] = invalid;
        assert_eq!(
            agreement(&owner, &response).unwrap(),
            "membership_unverified"
        );
    }
    response
        .as_object_mut()
        .unwrap()
        .remove("epoch_fingerprint");
    assert_eq!(
        agreement(&owner, &response).unwrap(),
        "membership_unverified"
    );
    let mut different = owner.epoch_fingerprint();
    different[0] ^= 1;
    response["epoch_fingerprint"] = json!(different);
    assert_eq!(
        agreement(&owner, &response).unwrap(),
        "membership_branch_mismatch"
    );
    response["epoch"] = json!(owner.epoch() + 1);
    assert!(agreement(&owner, &response).is_err());
}

/// An administrator's clock this far from ours is worth a warning. It is
/// never a reason to reject: verifiers must agree, and clocks differ.
const ADMISSION_CLOCK_SKEW: Duration = Duration::from_secs(10 * 60);

/// Warn when an admission's asserted time is far from the local clock
/// (ADR A2 section 7). Verification already checked it against expiry.
fn warn_on_clock_skew(commit: &[u8]) {
    let Some(asserted) = arachne_security::admission_asserted_time(commit) else {
        return;
    };
    let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return;
    };
    let skew = now.as_secs().abs_diff(asserted);
    if skew > ADMISSION_CLOCK_SKEW.as_secs() {
        tracing::warn!(target: "data_fabric_transport", skew_seconds = skew, "ADMISSION_CLOCK_SKEW");
    }
}

pub(super) fn stage_update(
    session: &mut Session,
    mut step: JoinStep,
) -> Result<StagedChange, ApiError> {
    check_epoch_transition(session)?;
    session.membership.staged_step_received = false;
    let (authorization, commit) = step.parts()?;
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    let invitation_checkpoint = step.take_invitation_checkpoint();
    if invitation_checkpoint.is_some()
        && !matches!(
            authorization,
            arachne_security::MembershipAuthorization::Management(_)
        )
    {
        return Err(ApiError::invalid_input(
            "step",
            "only an invitation step can carry an invitation checkpoint",
        ));
    }
    let prepared = match &authorization {
        arachne_security::MembershipAuthorization::Admission(auth) => {
            warn_on_clock_skew(&commit);
            arachne_security::PreparedManagementUpdate::Active(Box::new(
                owner
                    .prepare_admission_update(auth, &commit)
                    .map_err(security(ErrorCode::InvalidInput))?,
            ))
        }
        arachne_security::MembershipAuthorization::AdmissionBatch(auths) => {
            warn_on_clock_skew(&commit);
            arachne_security::PreparedManagementUpdate::Active(Box::new(
                owner
                    .prepare_admission_batch_update(auths, &commit)
                    .map_err(security(ErrorCode::InvalidInput))?,
            ))
        }
        // Class 2 management, revocation orders and self-updates are all
        // verified against this state by the same step update.
        _ => {
            let mut prepared = owner
                .prepare_step_update(&authorization, &commit)
                .map_err(security(ErrorCode::InvalidInput))?;
            if let (
                Some(checkpoint),
                arachne_security::MembershipAuthorization::Management(action),
            ) = (invitation_checkpoint, &authorization)
            {
                let arachne_security::PreparedManagementUpdate::Active(workspace) = &mut prepared
                else {
                    return Err(ApiError::invalid_input("step", "removal cannot carry an invitation checkpoint"));
                };
                workspace
                    .retain_invitation_checkpoint(*action, &checkpoint.grant, &checkpoint.checkpoint)
                    .map_err(security(ErrorCode::InvalidInput))?;
            }
            prepared
        }
    };
    let prepared = match prepared {
        arachne_security::PreparedManagementUpdate::Active(workspace) => *workspace,
        arachne_security::PreparedManagementUpdate::Removed(removed) => {
            return stage_removal(session, removed).map(StagedChange::Removal);
        }
    };
    let (publisher, inbox) = super::carry_delivery(session, &prepared)?;
    let snapshot = seal_state(session.records.is_some())?;
    let value = StagedCandidate::new(
        prepared.id(),
        prepared
            .workspace_name()
            .map_err(security(ErrorCode::Internal))?,
        snapshot.clone(),
    );
    session.transition.staged = Some(StagedWorkspace {
        publisher,
        inbox,
        transition: WorkspaceTransition::Admission,
        workspace: prepared,
        snapshot,
    });
    session.membership.staged_step_received = true;
    Ok(StagedChange::Candidate(value))
}

/// Head announcement: workspace, epoch, committing member's endpoint.
const GOSSIP_HEAD: &[u8] = b"DFMH\x02";
/// A range pull that gets no reply gives up after this; pull still recovers.
/// Longer than the 5 s connect limit, so the logs tell the two apart.
const RANGE_PULL_TIMEOUT: Duration = Duration::from_secs(10);
const GOSSIP_PROFILE: &[u8] = b"DFPG\x01";
/// Names waiting here, for members not admitted yet or for the host to
/// gossip, bounded by bytes rather than count: a whole join wave of 1,000
/// members with the longest names fits (390 KB; ~150 KB at typical names).
/// A count of 128 dropped most of a 500-joiner wave's names.
const MAX_HELD_PROFILE_BYTES: usize = 1_000 * arachne_security::MAX_MEMBER_PROFILE;

/// Hold a profile, dropping the oldest held ones past the byte bound.
fn hold_profile(held: &mut VecDeque<Vec<u8>>, bytes: Vec<u8>) {
    let mut total = held.iter().map(Vec::len).sum::<usize>() + bytes.len();
    while total > MAX_HELD_PROFILE_BYTES
        && let Some(oldest) = held.pop_front()
    {
        total -= oldest.len();
    }
    held.push_back(bytes);
}

/// The member a profile belongs to, when it verifies against this roster.
fn profile_id(session: &Session, bytes: &[u8]) -> Option<[u8; 32]> {
    session
        .workspace
        .as_ref()?
        .verify_member_profile(bytes)
        .ok()
        .map(|profile| profile.id())
}

/// Send a member's signed profile to the workspace overlay. Best effort.
fn broadcast_profile(session: &Session, bytes: &[u8]) {
    let Some(owner) = session.workspace.as_ref() else {
        return;
    };
    let mut payload = GOSSIP_PROFILE.to_vec();
    payload.extend(owner.id());
    payload.extend(bytes);
    let send = session.node.broadcast_membership(owner.id(), payload);
    session.runtime.spawn(async move {
        let _ = send.await;
    });
}

/// Keep a gossiped profile: merge it when its member is in this roster, else
/// hold it (bounded) until the step that admits the member lands here.
fn take_gossiped_profile(session: &mut Session, bytes: Vec<u8>) {
    if profile_id(session, &bytes).is_some() {
        let _ = merge_profiles_with_budget(session, &[bytes], MAX_PROFILE_SET_BYTES);
    } else {
        hold_profile(&mut session.membership.profiles_pending, bytes);
    }
}

/// A committed step may admit members whose names wait here. Only a held
/// name whose member id is now in the roster is verified, so a large held set
/// costs one roster read per commit, not a roster scan per name per poll.
pub(super) fn retain_held_profiles(session: &mut Session) {
    let Some(owner) = session.workspace.as_ref() else {
        return;
    };
    if session.membership.profiles_pending.is_empty() {
        return;
    }
    let Ok(roster) = owner.member_roster() else {
        return;
    };
    let members: BTreeSet<[u8; 32]> = roster.into_iter().map(|member| member.id).collect();
    let (ready, waiting): (Vec<Vec<u8>>, Vec<Vec<u8>>) =
        std::mem::take(&mut session.membership.profiles_pending)
            .into_iter()
            .partition(|bytes| {
                bytes
                    .get(37..69)
                    .is_some_and(|id| members.contains(<&[u8; 32]>::try_from(id).unwrap()))
            });
    session.membership.profiles_pending = waiting.into();
    for chunk in ready.chunks(MAX_REQUEST_PROFILES) {
        let _ = merge_profiles_with_budget(session, chunk, MAX_PROFILE_SET_BYTES);
    }
}

/// Outcome counts for membership gossip, so a device run can tell a send that
/// never happened from one that was slow.
#[derive(Default)]
pub(super) struct GossipCounts {
    sent: std::sync::atomic::AtomicU64,
    no_overlay: std::sync::atomic::AtomicU64,
    failed: std::sync::atomic::AtomicU64,
    received: std::sync::atomic::AtomicU64,
    staged: std::sync::atomic::AtomicU64,
    rejected: std::sync::atomic::AtomicU64,
    range_pulled: std::sync::atomic::AtomicU64,
    range_failed: std::sync::atomic::AtomicU64,
}

impl GossipCounts {
    fn add(counter: &std::sync::atomic::AtomicU64) {
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn metrics(&self) -> crate::client::MembershipGossipMetrics {
        let get = |counter: &std::sync::atomic::AtomicU64| {
            counter.load(std::sync::atomic::Ordering::Relaxed)
        };
        crate::client::MembershipGossipMetrics {
            sent: get(&self.sent),
            no_overlay: get(&self.no_overlay),
            failed: get(&self.failed),
            received: get(&self.received),
            staged: get(&self.staged),
            rejected: get(&self.rejected),
            range_pulled: get(&self.range_pulled),
            range_failed: get(&self.range_failed),
        }
    }
}
const MAX_GOSSIP_STEPS_AHEAD: usize = 32;

/// A non-administrator author when there is one; the local endpoint spreads
/// members over the choices. `authors` is never empty here.
fn pick_author(authors: &[[u8; 32]], administrators: &[[u8; 32]], local: [u8; 32]) -> [u8; 32] {
    let members: Vec<[u8; 32]> = authors
        .iter()
        .copied()
        .filter(|author| !administrators.contains(author))
        .collect();
    let choices = if members.is_empty() {
        authors
    } else {
        &members
    };
    choices[usize::from(local[0]) % choices.len()]
}

#[test]
fn range_pulls_prefer_members_and_spread_over_them() {
    let admin = [1; 32];
    assert_eq!(
        pick_author(&[admin], &[admin], [0; 32]),
        admin,
        "the admin when it is the only author"
    );
    let authors = [admin, [2; 32], [3; 32]];
    let picks: std::collections::BTreeSet<_> = (0..4u8)
        .map(|n| pick_author(&authors, &[admin], [n; 32]))
        .collect();
    assert_eq!(
        picks,
        [[2; 32], [3; 32]].into(),
        "members, never the admin, and both of them"
    );
}

fn hex_prefix(peer: &[u8; 32]) -> String {
    peer[..5].iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Members announcing one head that a member keeps as pull sources.
const MAX_HEAD_AUTHORS: usize = 8;

/// Remember a member that has the newest epoch heard, from gossip or presence.
/// Only the newest head is kept; its authors spread the range pulls.
pub(super) fn note_head(session: &mut Session, head: u64, author: [u8; 32]) {
    let Some(epoch) = session.workspace.as_ref().map(|owner| owner.epoch()) else {
        return;
    };
    if head <= epoch || author == session.node.id() {
        return;
    }
    match &mut session.membership.head {
        Some((known, _)) if head < *known => {}
        Some((known, authors)) if head == *known => {
            if !authors.contains(&author) && authors.len() < MAX_HEAD_AUTHORS {
                authors.push(author);
            }
        }
        _ => session.membership.head = Some((head, vec![author])),
    }
}

/// Announce this node's epoch after it commits, and after it
/// reaches the newest head it heard, so members that are behind pull from
/// many members, not all from the owner. Only the head travels by gossip: a
/// lost announcement is replaced by the next one. Best effort; never blocks.
pub(super) fn announce_head(session: &mut Session) {
    let Some(owner) = session.workspace.as_ref() else {
        return;
    };
    let mut payload = GOSSIP_HEAD.to_vec();
    payload.extend(owner.id());
    payload.extend(owner.epoch().to_be_bytes());
    payload.extend(session.node.id());
    payload.extend(owner.epoch_fingerprint());
    let key = owner.epoch().checked_sub(1).and_then(|epoch| owner.branch_key(epoch).ok().flatten());
    payload.extend(key.map_or([255; arachne_security::FORK_KEY_BYTES], |key| key.to_bytes()));
    let Ok(signature) = owner.sign_announcement(&payload) else { return };
    payload.extend(signature);
    let send = session.node.broadcast_membership(owner.id(), payload);
    // A failed broadcast is not an error for the commit: members pull. The
    // outcome is counted (sent / no overlay or no member / failed).
    let counts = session.membership.gossip_counts.clone();
    session.runtime.spawn(async move {
        match send.await {
            Ok(true) => GossipCounts::add(&counts.sent),
            Ok(false) => GossipCounts::add(&counts.no_overlay),
            Err(_) => GossipCounts::add(&counts.failed),
        }
    });
}

/// Stage the next gossiped membership step that extends this node's epoch,
/// if any. Steps from further ahead wait, bounded, until their turn. The step
/// is verified exactly as a pulled one; the gossip sender grants nothing.
pub(super) fn stage_gossiped_step(session: &mut Session) -> Result<Option<Value>, ApiError> {
    let Some(epoch) = session.workspace.as_ref().map(|owner| owner.epoch()) else {
        return Ok(None);
    };
    let id = session.workspace.as_ref().map(|owner| owner.id()).unwrap();
    while let Some((workspace, payload)) = session.node.poll_membership_gossip() {
        GossipCounts::add(&session.membership.gossip_counts.received);
        if workspace == id
            && payload.len() > GOSSIP_PROFILE.len() + 32
            && payload.starts_with(GOSSIP_PROFILE)
            && payload[GOSSIP_PROFILE.len()..GOSSIP_PROFILE.len() + 32] == id
        {
            take_gossiped_profile(session, payload[GOSSIP_PROFILE.len() + 32..].to_vec());
            continue;
        }
        if workspace == id
            && payload.len() == GOSSIP_HEAD.len() + 72 + 32 + arachne_security::FORK_KEY_BYTES + 64
            && payload.starts_with(GOSSIP_HEAD)
            && payload[GOSSIP_HEAD.len()..GOSSIP_HEAD.len() + 32] == id
        {
            let at = GOSSIP_HEAD.len() + 32;
            let head = u64::from_be_bytes(payload[at..at + 8].try_into().unwrap());
            let author: [u8; 32] = payload[at + 8..at + 40].try_into().unwrap();
            let signed = payload.len() - 64;
            let signature = payload[signed..].try_into().unwrap();
            let owner = session.workspace.as_ref().unwrap();
            if owner.verify_announcement(author, &payload[..signed], &signature).is_err() { continue }
            let fingerprint = &payload[at + 40..at + 72];
            if head == owner.epoch() && fingerprint != owner.epoch_fingerprint() {
                fork::start(session, author);
            }
            note_head(session, head, author);
            continue;
        }
    }
    if let Some(staged) = fork::poll(session)? { return Ok(Some(staged)) }
    finish_range_pull(session);
    finish_profile_pull(session);
    session
        .membership.steps_ahead
        .retain(|after, _| *after >= epoch);
    if session
        .membership.head
        .as_ref()
        .is_some_and(|(head, _)| *head <= epoch)
    {
        session.membership.head = None;
    }
    start_range_pull(session, epoch);
    let Some(bytes) = session.membership.steps_ahead.remove(&epoch) else {
        return Ok(None);
    };
    let Ok(step) = join_step_from_wire(&bytes) else {
        return Ok(None);
    };
    match stage_update(session, step).and_then(|change| serde_json::to_value(change).map_err(errors::encode)) {
        Ok(mut value) => {
            // No requester waits on this step: the host saves and adopts
            // without sending a reply.
            value["queued"] = json!(true);
            value["gossip"] = json!(true);
            GossipCounts::add(&session.membership.gossip_counts.staged);
            Ok(Some(value))
        }
        // A step may name a parent on a competing branch. Ask the peer
        // for the first divergence before applying any fork choice.
        Err(_) => {
            if let Some(peer) = session.membership.head.as_ref().and_then(|(_, peers)| peers.first()).copied() {
                fork::start(session, peer);
            }
            GossipCounts::add(&session.membership.gossip_counts.rejected);
            Ok(None)
        }
    }
}

/// Pull the steps toward an announced head from the member that committed it,
/// in one exchange. That member is alive: it sent the head a
/// moment ago. One pull at a time; its reply wakes the host.
fn start_range_pull(session: &mut Session, epoch: u64) {
    if session.membership.range_pull.is_some() || session.membership.steps_ahead.contains_key(&epoch) {
        return;
    }
    let Some(owner) = session.workspace.as_ref() else {
        return;
    };
    let Some((head, authors)) = session.membership.head.as_mut() else {
        return;
    };
    authors.retain(|author| owner.member_id_for_endpoint(*author).is_ok());
    if *head <= epoch || authors.is_empty() {
        session.membership.head = None;
        return;
    }
    let head = *head;
    // Prefer a member over an administrator: during a join wave the admin's
    // one control queue is full of joiners and a pull waited past its limit
    // (tablets JOSA and BIG RED, fix16). Members that are behind pick
    // different authors, so pulls spread.
    let administrators: Vec<[u8; 32]> = owner
        .member_roster()
        .map(|roster| {
            roster
                .into_iter()
                .filter(|member| member.administrator)
                .map(|member| member.endpoint)
                .collect()
        })
        .unwrap_or_default();
    let author = pick_author(authors, &administrators, session.node.id());
    tracing::info!(target: "data_fabric_transport", after = epoch, until = head, peer = %hex_prefix(&author), "RANGE_PULL_START");
    let Ok(query) = wire::encode_range_query(&wire::RangeQuery {
        workspace: owner.id(),
        after: epoch,
        until: head,
    }) else {
        return;
    };
    let request = session.node.request_control(author, &query);
    let wake = session.node.control_signal();
    let task = session.runtime.spawn(async move {
        let reply = tokio::time::timeout(RANGE_PULL_TIMEOUT, request)
            .await
            .unwrap_or(Err(arachne_node::Error::Timeout("membership range")));
        wake.notify_one();
        reply
    });
    session.membership.range_pull = Some(PendingControl {
        query: epoch,
        peer: author,
        task,
    });
}

/// Hold the pulled steps where gossiped steps wait, so they are staged in
/// order through the same verifier. A failed or empty pull drops the head;
/// the next announcement, presence or the roster pull recovers.
fn finish_range_pull(session: &mut Session) {
    if !session
        .membership.range_pull
        .as_ref()
        .is_some_and(|pending| pending.task.is_finished())
    {
        return;
    }
    let mut pending = session.membership.range_pull.take().unwrap();
    let id = session.workspace.as_ref().map(|owner| owner.id());
    let reply = session
        .runtime
        .block_on(&mut pending.task)
        .map_err(|error| error.to_string())
        .and_then(|reply| reply.map_err(|error| error.to_string()));
    let error = reply.as_ref().err().cloned();
    let bytes = reply.ok();
    let mut pulled = 0;
    if let Some(bytes) = bytes
        && let Ok(reply) = wire::decode_range_reply(&bytes)
        && Some(reply.workspace) == id
        && reply.after == pending.query
    {
        for (after, step) in (pending.query..).zip(reply.steps) {
            if !session.membership.steps_ahead.contains_key(&after)
                && session.membership.steps_ahead.len() >= MAX_GOSSIP_STEPS_AHEAD
            {
                break;
            }
            session
                .membership.steps_ahead
                .entry(after)
                .or_insert_with(|| step.to_vec());
            pulled += 1;
        }
    }
    tracing::info!(target: "data_fabric_transport", after = pending.query, peer = %hex_prefix(&pending.peer), pulled, error, "RANGE_PULL_END");
    if pulled == 0 {
        // Try the head's other authors; with none left, fall back to pull.
        GossipCounts::add(&session.membership.gossip_counts.range_failed);
        if let Some((_, authors)) = session.membership.head.as_mut() {
            authors.retain(|author| *author != pending.peer);
            if authors.is_empty() {
                session.membership.head = None;
            }
        }
    } else {
        GossipCounts::add(&session.membership.gossip_counts.range_pulled);
    }
}

pub(super) const PROFILE_QUERY_PREFIX: &[u8] = b"DFPQ";

/// One page pull of a peer's retained signed names: where it starts, and the
/// peer's profile digest the walk is for.
pub(super) struct ProfilePull {
    pub(super) after: Option<[u8; 32]>,
    digest: [u8; 32],
}

/// Serve retained signed names after one member id, in id order, to a current
/// member. A pure read of the shared set, answered without the host.
/// Refusal is an empty page: it reveals nothing.
pub(super) fn profile_page_reply(
    owner: Option<&arachne_security::Workspace>,
    set: &ProfileSet,
    peer: [u8; 32],
    bytes: &[u8],
) -> Vec<u8> {
    use std::ops::Bound;
    let (workspace, profiles) = match (owner, wire::decode_profile_query(bytes)) {
        (Some(owner), Ok(query))
            if query.workspace == owner.id() && owner.member_id_for_endpoint(peer).is_ok() =>
        {
            let start = query.after.map_or(Bound::Unbounded, Bound::Excluded);
            let profiles = set
                .retained
                .range((start, Bound::Unbounded))
                .take(wire::MAX_PAGE_PROFILES)
                .map(|(_, bytes)| bytes.as_slice())
                .collect();
            (owner.id(), profiles)
        }
        _ => ([0; 32], Vec::new()),
    };
    wire::encode_profile_page(&wire::ProfilePage {
        workspace,
        profiles,
    })
    .unwrap_or_default()
}

/// Ask `peer` for one page of its names. A membership reply carries at most
/// one retained name, picked by the answerer's cursor, so names a member
/// missed (a gossip it did not get, a restart) came back one per query, 5 s
/// apart on a device. One pull at a time; its reply wakes the host.
fn start_profile_pull(
    session: &mut Session,
    peer: [u8; 32],
    after: Option<[u8; 32]>,
    digest: [u8; 32],
) {
    if session.membership.profile_pull.is_some() {
        return;
    }
    let Some(owner) = session.workspace.as_ref() else {
        return;
    };
    let Ok(query) = wire::encode_profile_query(&wire::ProfileQuery {
        workspace: owner.id(),
        after,
    }) else {
        return;
    };
    let request = session.node.request_control(peer, &query);
    let wake = session.node.control_signal();
    let task = session.runtime.spawn(async move {
        let reply = tokio::time::timeout(RANGE_PULL_TIMEOUT, request)
            .await
            .unwrap_or(Err(arachne_node::Error::Timeout("member profiles")));
        wake.notify_one();
        reply
    });
    session.membership.profile_pull = Some(PendingControl {
        query: ProfilePull { after, digest },
        peer,
        task,
    });
}

/// Retain a pulled page through the same verifier as every other name, and
/// ask for the next page while pages are full and still carry names this
/// roster verifies. A peer cannot keep a member walking with made-up names.
fn finish_profile_pull(session: &mut Session) {
    if !session
        .membership.profile_pull
        .as_ref()
        .is_some_and(|pending| pending.task.is_finished())
    {
        return;
    }
    let mut pending = session.membership.profile_pull.take().unwrap();
    let bytes = session
        .runtime
        .block_on(&mut pending.task)
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    let id = session.workspace.as_ref().map(|owner| owner.id());
    // A lost, malformed or foreign page ends the walk for this peer set, like
    // the last page: an older peer that does not serve pages is not asked
    // again until its names change, so it holds the one pull slot (up to
    // 10 s) at most once per digest.
    let profiles: Option<(bool, Vec<Vec<u8>>)> = wire::decode_profile_page(&bytes)
        .ok()
        .filter(|page| Some(page.workspace) == id)
        .map(|page| {
            let full = page.profiles.len() == wire::MAX_PAGE_PROFILES;
            (
                full,
                page.profiles
                    .iter()
                    .map(|profile| profile.to_vec())
                    .collect(),
            )
        });
    if let Some((full, profiles)) = profiles {
        let verified = profiles
            .iter()
            .any(|bytes| profile_id(session, bytes).is_some());
        let _ = merge_profiles_with_budget(session, &profiles, MAX_PROFILE_SET_BYTES);
        let last = profiles
            .last()
            .and_then(|bytes| bytes.get(37..69))
            .and_then(|id| <[u8; 32]>::try_from(id).ok());
        let progressed =
            last.is_some_and(|last| pending.query.after.is_none_or(|after| last > after));
        if full && progressed && verified {
            start_profile_pull(session, pending.peer, last, pending.query.digest);
            return;
        }
    }
    if !session.membership.profiles_walked.contains_key(&pending.peer)
        && session.membership.profiles_walked.len() >= MAX_PEER_PROFILE_SUMMARIES
    {
        session.membership.profiles_walked.pop_first();
    }
    session
        .membership.profiles_walked
        .insert(pending.peer, pending.query.digest);
}

/// Serve consecutive steps to a current member, bounded by count and by the
/// control reply size. Refusal is an empty range: it reveals nothing.
pub(super) fn range_reply(
    owner: Option<&arachne_security::Workspace>,
    peer: [u8; 32],
    bytes: &[u8],
) -> Vec<u8> {
    let (workspace, after, steps) = match (owner, wire::decode_range_query(bytes)) {
        (Some(owner), Ok(query))
            if query.workspace == owner.id() && owner.member_id_for_endpoint(peer).is_ok() =>
        {
            (owner.id(), query.after, range_page(owner, peer, query.after, query.until))
        }
        _ => ([0; 32], 0, Vec::new()),
    };
    tracing::info!(target: "data_fabric_transport", after, peer = %hex_prefix(&peer), steps = steps.len(), "RANGE_SERVED");
    let steps = steps.iter().map(Vec::as_slice).collect();
    wire::encode_range_reply(&wire::RangeReply {
        workspace,
        after,
        steps,
    })
    .unwrap_or_default()
}

/// One page of consecutive steps from `after` toward `until`: at most
/// `PAGE_STEP_BYTES` of steps, but always the first step when it alone fits
/// the reply. The requester asks again from where the page ended (the
/// cursor is `after` plus the steps it got), so it applies page by page.
fn range_page(
    owner: &arachne_security::Workspace,
    peer: [u8; 32],
    after: u64,
    until: u64,
) -> Vec<Vec<u8>> {
    let mut steps: Vec<Vec<u8>> = Vec::new();
    let mut size = 0;
    let mut next = after;
    while next < until.min(owner.epoch()) && steps.len() < wire::MAX_RANGE_STEPS {
        let Ok(Some((authorization, commit))) = owner.membership_update_for(peer, next) else {
            break;
        };
        let room = PAGE_STEP_BYTES.saturating_sub(size);
        let Ok(step) = owner_wire_step(owner, &authorization, &commit, room) else {
            break;
        };
        let budget = if steps.is_empty() {
            RANGE_REPLY_STEP_ROOM
        } else {
            PAGE_STEP_BYTES
        };
        if size + step.len() > budget {
            break;
        }
        size += step.len();
        steps.push(step);
        next += 1;
    }
    steps
}

/// Room for the steps of a range reply: the reply bound less its envelope
/// (prefix, workspace, cursor and per-step lengths).
const RANGE_REPLY_STEP_ROOM: usize = arachne_node::MAX_CONTROL_REPLY - 1024;
const _: () = assert!(MAX_WIRE_STEP + 64 <= RANGE_REPLY_STEP_ROOM);

/// Accept a carrier's signed next transition, not the carrier as membership authority.
/// Responses reveal no roster, fingerprint, current epoch, Welcome or invitation.
/// `DFMO\x02 | workspace | u64 after | wire step`: a member offers the step
/// that extends `after`. A control request is at most 32 KiB.
const OFFER: &[u8; 5] = b"DFMO\x02";
const OFFER_HEADER: usize = 5 + 32 + 8;
const MAX_OFFER: usize = 32 * 1024;
/// `DFMD\x01 | workspace | u64 after | step digest | u32 step size`: an
/// offer of a committed step too large for one control request. The
/// receiver pulls the step over the paged range channel from the offerer.
///
/// Why not raise the request bound instead: every control request, from
/// any authenticated peer, may then be that large, and the node queues up
/// to 512 of them. A digest keeps the request small and moves the bytes to
/// the reply side, which is already 128 KiB and paged.
pub(super) const OFFER_DIGEST: &[u8; 5] = b"DFMD\x01";
const OFFER_DIGEST_LEN: usize = OFFER_HEADER + 32 + 4;
/// Acknowledgment of a digest offer: the receiver will pull the step.
const OFFER_PULL: u8 = 2;

/// The packet that offers one step. A step that does not fit one control
/// request goes by digest when it is committed; a staged step (an offer
/// that must be adopted before the offerer adopts) must fit, because a
/// staged step cannot be served from committed history.
fn offer_packet(
    owner: &arachne_security::Workspace,
    after: u64,
    authorization: &arachne_security::MembershipAuthorization,
    commit: &[u8],
    staged: bool,
) -> Result<Vec<u8>, ApiError> {
    let step = owner_wire_step(owner, authorization, commit, MAX_OFFER - OFFER_HEADER)?;
    let mut packet = if OFFER_HEADER + step.len() <= MAX_OFFER {
        OFFER.to_vec()
    } else if staged {
        return Err(ApiError::limit_reached(
            "control request",
            MAX_OFFER as u64,
            "a staged membership offer exceeds the control request bound",
        ));
    } else {
        OFFER_DIGEST.to_vec()
    };
    packet.extend(owner.id());
    packet.extend(after.to_be_bytes());
    if packet.starts_with(OFFER) {
        packet.extend(step);
    } else {
        use sha2::{Digest, Sha256};
        let encoded = encode_step(authorization, commit)?;
        packet.extend(Sha256::digest(&encoded));
        packet.extend((encoded.len() as u32).to_be_bytes());
    }
    Ok(packet)
}

/// A digest offer: remember the offerer as a source for the next epoch, so
/// the range pull fetches and verifies the step. The digest names the step;
/// verification, not the digest, decides whether it applies.
pub(super) fn receive_offer_digest(
    session: &mut Session,
    peer: [u8; 32],
    packet: &[u8],
) -> Result<Value, ApiError> {
    if packet.len() != OFFER_DIGEST_LEN || !packet.starts_with(OFFER_DIGEST) {
        return Err(ApiError::invalid_input("offer", "invalid membership offer"));
    }
    let owner = session.workspace.as_ref().ok_or_else(errors::no_workspace)?;
    owner
        .member_id_for_endpoint(peer)
        .map_err(security(ErrorCode::NotMember))?;
    let size = u32::from_be_bytes(packet[OFFER_DIGEST_LEN - 4..].try_into().unwrap()) as usize;
    if packet[5..37] != owner.id()
        || packet[37..45] != owner.epoch().to_be_bytes()
        || size == 0
        || size > MAX_WIRE_STEP
    {
        return Err(ApiError::epoch_mismatch("membership offer does not extend current epoch"));
    }
    note_head(session, owner.epoch() + 1, peer);
    Ok(json!({"state":"membership_offer_pull","peer":peer}))
}

pub(super) fn receive_offer(session: &mut Session, packet: &[u8]) -> Result<Value, ApiError> {
    if packet.len() <= OFFER_HEADER || packet.len() > MAX_OFFER || !packet.starts_with(OFFER) {
        return Err(ApiError::invalid_input("offer", "invalid membership offer"));
    }
    let owner = session.workspace.as_ref().ok_or_else(|| ApiError::wrong_state("no workspace"))?;
    let after = u64::from_be_bytes(packet[37..45].try_into().unwrap());
    if packet[5..37] != owner.id() || after > owner.epoch() {
        return Err(ApiError::epoch_mismatch("membership offer does not extend current epoch"));
    }
    let step = join_step_from_wire(&packet[OFFER_HEADER..])
        .map_err(|_| ApiError::invalid_input("offer", "invalid offered transition"))?;
    if after < owner.epoch() {
        return fork::stage(session, after, step);
    }
    serde_json::to_value(stage_update(session, step)?).map_err(errors::encode)
}

pub(super) fn stage_management(
    session: &mut Session,
    action: arachne_security::ManagementAction,
) -> Result<StagedCandidate, ApiError> {
    check_epoch_transition(session)?;
    let prepared = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?
        .prepare_management(action)
        .map_err(security(ErrorCode::InvalidInput))?;
    stage_prepared(session, prepared)
}

pub(super) fn stage_prepared(
    session: &mut Session,
    prepared: arachne_security::PreparedManagement,
) -> Result<StagedCandidate, ApiError> {
    // Never commit a step (with any anchor proof it carries) that no member
    // could receive: receivers refuse steps above the transport bound.
    encode_step(&prepared.authorization, &prepared.commit)?;
    let (publisher, inbox) = super::carry_delivery(session, &prepared.workspace)?;
    let snapshot = seal_state(session.records.is_some())?;
    let value = StagedCandidate::new(
        prepared.workspace.id(),
        prepared
            .workspace
            .workspace_name()
            .map_err(security(ErrorCode::Internal))?,
        snapshot.clone(),
    );
    session.transition.staged = Some(StagedWorkspace {
        publisher,
        inbox,
        transition: WorkspaceTransition::Management(
            prepared.action,
            prepared.authorization,
            prepared.commit,
        ),
        workspace: prepared.workspace,
        snapshot,
    });
    Ok(value)
}

/// Start this member's self-update when the policy says it is due (B3c,
/// ADR A2 section 7). Returns `None` when nothing starts.
///
/// The member stages its update path commit and offers it to an
/// administrator, who must adopt it before the member does (the staged
/// offer handshake). Until fork resolution exists (ADR A2 steps 8-13), a
/// local self-update that raced an administrator's commit at the same epoch
/// would strand this member on a losing branch. The only administrator
/// stages its own and adopts it directly. Only a node that has reached the
/// newest head it heard starts one.
pub(crate) fn start_self_update(
    session: &mut Session,
    now: std::time::Instant,
) -> Result<Option<Value>, ApiError> {
    if crate::ops::admission_busy(session)
        || session.membership.offer.is_some()
        || !session.membership.steps_ahead.is_empty()
        || session.membership.range_pull.is_some()
    {
        return Ok(None);
    }
    let Some(owner) = session.workspace.as_ref() else {
        return Ok(None);
    };
    if session
        .membership
        .head
        .as_ref()
        .is_some_and(|(head, _)| *head > owner.epoch())
        || !session
            .membership
            .self_update
            .due(now, owner.needs_self_update())
    {
        return Ok(None);
    }
    let own = owner.member().map(|member| member.id());
    let roster = owner.member_roster().map_err(security(ErrorCode::WrongState))?;
    let administrator = roster
        .iter()
        .any(|member| Some(member.id) == own && member.administrator);
    let mut admins: Vec<PeerChoice> = roster
        .iter()
        .filter(|member| member.administrator && Some(member.id) != own)
        .map(|member| PeerChoice {
            endpoint: member.endpoint,
            preferred: presence::contact_age(&session.presence, member.endpoint, now)
                .is_some_and(|age| age < MEMBERSHIP_PEER_RECENT),
            cooling: session
                .membership
                .peer_failures
                .get(&member.endpoint)
                .is_some_and(|failed| {
                    now.saturating_duration_since(*failed) < MEMBERSHIP_PEER_COOLDOWN
                }),
        })
        .collect();
    admins.sort_unstable_by_key(|peer| peer.endpoint);
    let peer = choose_membership_peer(&admins, None);
    // Every administrator failed recently (for example all are offline):
    // defer without staging, so gossip and range steps keep landing.
    let reachable = peer.is_some_and(|peer| {
        admins
            .iter()
            .any(|admin| admin.endpoint == peer && !admin.cooling)
    });
    if !reachable && (peer.is_some() || !administrator) {
        session.membership.self_update.refused(now);
        return Ok(None);
    }
    let epoch = owner.epoch();
    let prepared = owner
        .prepare_self_update()
        .map_err(security(ErrorCode::WrongState))?;
    encode_step(&arachne_security::MembershipAuthorization::SelfUpdate, &prepared.commit)?;
    let (publisher, inbox) = super::carry_delivery(session, &prepared.workspace)?;
    let snapshot = seal_state(session.records.is_some())?;
    let mut value = serde_json::to_value(StagedCandidate::new(
        prepared.workspace.id(),
        prepared
            .workspace
            .workspace_name()
            .map_err(security(ErrorCode::WrongState))?,
        snapshot.clone(),
    ))
    .map_err(errors::encode)?;
    value["self_update"] = json!(true);
    let commit = prepared.commit.clone();
    session.transition.staged = Some(StagedWorkspace {
        publisher,
        inbox,
        transition: WorkspaceTransition::SelfUpdate(prepared.commit),
        workspace: prepared.workspace,
        snapshot,
    });
    let Some(peer) = peer else {
        // The only administrator: no one else commits at this epoch.
        return Ok(Some(value));
    };
    if let Err(error) = queue_membership_offer(
        session,
        peer,
        epoch,
        arachne_security::MembershipAuthorization::SelfUpdate,
        commit,
        true,
    ) {
        session.transition.staged = None;
        session.membership.self_update.refused(now);
        return Err(error);
    }
    session.membership.self_update_offered = Some(peer);
    Ok(Some(json!({"state":"self_update_offered","peer":peer})))
}

/// This member's self-update offer is still out.
pub(crate) fn self_update_pending(session: &Session) -> bool {
    session.membership.self_update_offered.is_some()
}

/// The outcome of this member's self-update offer, once it finished:
/// `Some(true)` when the administrator adopted it (the staged candidate may
/// now be saved and adopted), `Some(false)` when it was refused or failed
/// (the candidate is discarded). `None` while it is pending.
pub(crate) fn finish_self_update_offer(
    session: &mut Session,
    now: std::time::Instant,
) -> Option<bool> {
    let peer = session.membership.self_update_offered?;
    let outcome = poll_with_budget(session, Reconcile::PollOffer, MAX_PROFILE_SET_BYTES);
    if matches!(outcome, Ok(Value::Null)) {
        return None;
    }
    session.membership.self_update_offered = None;
    let accepted = outcome.is_ok();
    if !accepted {
        // Unreachable (not a refusal): try another administrator next time.
        if outcome
            .as_ref()
            .is_err_and(|error| error.code() != ErrorCode::NotAuthorized)
        {
            session.membership.peer_failures.insert(peer, now);
        }
        if matches!(
            session.transition.staged.as_ref().map(|staged| &staged.transition),
            Some(WorkspaceTransition::SelfUpdate(_))
        ) {
            session.transition.staged = None;
        }
        session.membership.self_update.refused(now);
    }
    Some(accepted)
}

/// `DFLV\x02 | u64 epoch | revocation order`: a signed departure that the
/// receiving member commits (ADR A2 section 3). The order is anchored at the
/// leaver's state, so the receiver must be at the same epoch.
const LEAVE: &[u8; 5] = b"DFLV\x02";

fn leave_parts(bytes: &[u8]) -> Result<(u64, arachne_security::RevocationOrder), ApiError> {
    let invalid = || ApiError::invalid_input("request", "invalid leave request");
    let body = bytes.strip_prefix(LEAVE).ok_or_else(invalid)?;
    if body.len() <= 8 {
        return Err(invalid());
    }
    let order = arachne_security::RevocationOrder::from_bytes(&body[8..]).map_err(|_| invalid())?;
    if order.kind != arachne_security::RevocationKind::Leave {
        return Err(ApiError::invalid_input("request", "expected a signed leave order"));
    }
    Ok((u64::from_be_bytes(body[..8].try_into().unwrap()), order))
}

/// The committed step carries exactly this leave order.
fn carries_order(
    auth: &arachne_security::MembershipAuthorization,
    order: &arachne_security::RevocationOrder,
) -> bool {
    matches!(auth, arachne_security::MembershipAuthorization::Revocation(step)
        if step.order.digest() == order.digest())
}

pub(super) fn leave_reply(
    owner: &arachne_security::Workspace,
    peer: [u8; 32],
    bytes: &[u8],
) -> Result<Vec<u8>, ApiError> {
    let (epoch, order) = leave_parts(bytes)?;
    let (auth, commit) = owner
        .membership_update_for(peer, epoch)
        .map_err(security(ErrorCode::InvalidInput))?
        .ok_or_else(|| ApiError::wrong_state("leave outcome unavailable"))?;
    if !carries_order(&auth, &order) {
        return Err(ApiError::invalid_input("request", "leave outcome does not match request"));
    }
    encode_step(&auth, &commit)
}

pub(super) fn receive_leave(
    session: &mut Session,
    peer: [u8; 32],
    bytes: &[u8],
) -> Result<Value, ApiError> {
    let (epoch, order) = leave_parts(bytes)?;
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    if leave_reply(owner, peer, bytes).is_ok() {
        return Ok(json!({"state":"reply_ready","leaving":true}));
    }
    if owner.epoch() != epoch
        || order.anchor_epoch != epoch
        || owner.member_id_for_endpoint(peer).map_err(security(ErrorCode::NotMember))? != order.target
    {
        return Err(ApiError::not_authorized("leave requester does not match member or epoch"));
    }
    check_epoch_transition(session)?;
    let prepared = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?
        .prepare_revocation(&arachne_security::OrderStep::new(order))
        .map_err(security(ErrorCode::InvalidInput))?;
    let mut staged = stage_prepared(session, prepared)?;
    staged.leaving = Some(true);
    serde_json::to_value(staged).map_err(errors::encode)
}

pub(super) fn leave_via_peer(
    session: &mut Session,
    peer: [u8; 32],
) -> Result<StagedChange, ApiError> {
    check_epoch_transition(session)?;
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    if peer == owner.endpoint() || owner.member_id_for_endpoint(peer).is_err() {
        return Err(ApiError::invalid_input("peer", "leave requires another admitted peer"));
    }
    let order = owner.leave_order().map_err(security(ErrorCode::WrongState))?;
    let mut packet = LEAVE.to_vec();
    packet.extend(owner.epoch().to_be_bytes());
    packet.extend(order.to_bytes());
    let bytes = session.runtime.block_on(session.node.request_control(peer, &packet)).map_err(|_| {
        ApiError::peer_unreachable(
            Some(arachne_api::EndpointId::from_bytes(peer)),
            "Couldn't finish leaving. Resume this workspace and try again when another member is reachable.",
        )
    })?;
    let refused = || {
        ApiError::transport_failed(
            Some(arachne_api::EndpointId::from_bytes(peer)),
            "The other member couldn't accept the departure. Synchronize and try again.",
        )
    };
    if bytes.len() > MAX_WIRE_STEP {
        return Err(refused());
    }
    let (auth, _) = arachne_security::decode_membership_step(&bytes).map_err(|_| refused())?;
    if !carries_order(&auth, &order) {
        return Err(ApiError::transport_failed(Some(arachne_api::EndpointId::from_bytes(peer)), "leave reply does not match request"));
    }
    stage_update(session, JoinStep::binary(bytes, None))
}

pub(super) fn stage_removal(
    session: &mut Session,
    removed: arachne_security::RemovedMembership,
) -> Result<StagedRemoval, ApiError> {
    super::transition_activity(session, super::WorkspacePhase::Leaving, None)?;
    let snapshot = super::seal_state(session.records.is_some())?;
    let value = StagedRemoval {
        workspace: removed.workspace_id(),
        snapshot: snapshot.clone(),
        state: "awaiting_save",
        removed: true,
        durable: false,
        activity: crate::session::activity_view(session),
    };
    session.transition.removal = Some((removed, snapshot));
    Ok(value)
}

#[cfg(test)]
fn choice(n: u8, preferred: bool, cooling: bool) -> PeerChoice {
    PeerChoice {
        endpoint: [n; 32],
        preferred,
        cooling,
    }
}

/// A backlog after a large admission wave must not wait on a full pass over
/// offline members: each unreachable peer costs a connect timeout (~5 s on
/// tablets, measured 2026-09-18), and the rotation reached the one live
/// administrator once per ~73 peers.
#[test]
fn membership_peer_choice_prefers_reachable_or_administrator_peers() {
    let peers = [
        choice(1, false, false),
        choice(2, false, false),
        choice(3, true, false),
        choice(4, false, false),
        choice(5, true, false),
    ];
    assert_eq!(choose_membership_peer(&peers, None), Some([3; 32]));
    // Round-robin within the preferred tier, wrapping.
    assert_eq!(choose_membership_peer(&peers, Some([3; 32])), Some([5; 32]));
    assert_eq!(choose_membership_peer(&peers, Some([5; 32])), Some([3; 32]));
}

#[test]
fn membership_peer_choice_skips_recent_failures_until_nothing_else_is_left() {
    // A preferred peer that failed recently is skipped while another preferred peer is fine.
    let peers = [
        choice(1, true, false),
        choice(2, true, true),
        choice(3, false, false),
    ];
    assert_eq!(choose_membership_peer(&peers, Some([1; 32])), Some([1; 32]));
    // With every preferred peer cooling, retry them rather than falling through
    // to never-contacted members: on tablets the owner cooled for 60 s after its
    // own restart and members spent that time on ~250 offline joiners, 5 s each.
    let peers = [
        choice(1, false, false),
        choice(2, true, true),
        choice(3, false, true),
    ];
    assert_eq!(choose_membership_peer(&peers, None), Some([2; 32]));
    assert_eq!(choose_membership_peer(&peers, Some([2; 32])), Some([2; 32]));
    // No preferred peer at all: not-cooling peers, then everyone.
    let peers = [choice(1, false, false), choice(3, false, true)];
    assert_eq!(choose_membership_peer(&peers, Some([1; 32])), Some([1; 32]));
    // Everyone cooling: keep the old full rotation rather than stop asking.
    let all_cooling = [choice(1, false, true), choice(2, true, true)];
    assert_eq!(
        choose_membership_peer(&all_cooling, Some([1; 32])),
        Some([2; 32])
    );
    assert_eq!(choose_membership_peer(&[], None), None);
}

/// B3c: a committed step larger than one control request is offered by
/// digest and pulled over the paged range channel; a staged step, which
/// cannot be served before adoption, must fit inline.
#[test]
fn a_committed_step_too_large_for_one_request_is_offered_by_digest() {
    let (owner, _, endpoints) = admit_members(31, "Offer member", 1);
    let authorization = arachne_security::MembershipAuthorization::SelfUpdate;
    let small = offer_packet(&owner, owner.epoch(), &authorization, &[1; 100], false).unwrap();
    assert!(small.starts_with(OFFER));
    let large = vec![1; MAX_OFFER];
    let digest = offer_packet(&owner, owner.epoch(), &authorization, &large, false).unwrap();
    assert!(digest.starts_with(OFFER_DIGEST));
    assert_eq!(digest.len(), OFFER_DIGEST_LEN);
    assert_eq!(
        offer_packet(&owner, owner.epoch(), &authorization, &large, true)
            .unwrap_err()
            .code(),
        ErrorCode::LimitReached
    );
    let epoch = owner.epoch();
    let mut session = bare_test_session(owner);
    // A stranger or a stale epoch is refused; a member becomes a pull source.
    assert!(receive_offer_digest(&mut session, [250; 32], &digest).is_err());
    let mut stale = digest.clone();
    stale[44] ^= 1;
    assert!(receive_offer_digest(&mut session, endpoints[0], &stale).is_err());
    let value = receive_offer_digest(&mut session, endpoints[0], &digest).unwrap();
    assert_eq!(value["state"], "membership_offer_pull");
    assert_eq!(session.membership.head, Some((epoch + 1, vec![endpoints[0]])));
}

/// A revocation step whose anchor proof would make it larger than one
/// control reply is refused on receipt, before verification: no node
/// accepts a step it could not store or send on.
#[test]
fn a_step_with_an_anchor_proof_past_the_transport_bound_is_refused() {
    let order = arachne_security::RevocationOrder {
        kind: arachne_security::RevocationKind::Remove,
        target: [4; 32],
        issuer: [5; 32],
        anchor_epoch: 3,
        anchor_context: [6; 32],
        signature: [7; 64],
    };
    let step = |checkpoint: usize| {
        arachne_security::encode_membership_step(
            &arachne_security::MembershipAuthorization::Revocation(
                arachne_security::OrderStep::with_proof(
                    order.clone(),
                    arachne_security::AnchorProof {
                        checkpoint: vec![8; checkpoint],
                        winning: vec![],
                        losing: vec![],
                    },
                ),
            ),
            b"commit",
        )
        .unwrap()
    };
    let small = step(1024);
    assert!(JoinStep::binary(small.clone(), None).parts().is_ok());
    assert!(wire_step(&small, None, usize::MAX).is_ok());
    let large = step(MAX_WIRE_STEP);
    assert!(large.len() > MAX_WIRE_STEP);
    let refused = JoinStep::binary(large.clone(), None).parts().err().unwrap();
    assert_eq!(refused.code(), ErrorCode::LimitReached);
    assert_eq!(wire_step(&large, None, usize::MAX).unwrap_err().code(), ErrorCode::LimitReached);
    let (authorization, commit) = arachne_security::decode_membership_step(&large).unwrap();
    assert_eq!(encode_step(&authorization, &commit).unwrap_err().code(), ErrorCode::LimitReached);
}

/// B3c, runtime level (no network): past 785 members a link registration
/// and a Remove succeed once members self-updated. The owner commits both;
/// the runtime bounds each step, serves it as one binary range page
/// (range_reply) and decodes it (JoinStep); a member verifies it with
/// prepare_step_update, the call stage_update makes. Staging itself cannot
/// run at this size yet: the OpenMLS tree record is over the store's 1 MiB
/// record bound (A3g/A5), see the note below.
///
/// Growth: batches of 128 through the security API, one fresh link per
/// batch. After each batch, its first and last joiners self-update (the
/// policy's "right after the Welcome"); the owner applies each. The
/// populated interior nodes collapse the owner's copath, so every commit
/// stays under the old 64 KiB bound even though most members never
/// self-updated. Without self-updates a registration at 897 members was
/// over 64 KiB (ADR A2, B3c measurements).
#[test]
#[ignore = "B3c capacity run: ~900 members; slow in debug"]
fn a_registration_and_remove_past_785_members_succeed_after_self_updates() {
    use arachne_security::{
        AdmissionAssessment, EndpointKey, EndpointSigner, MAX_ADMISSION_BATCH,
        MembershipAuthorization, PendingJoin, PreparedManagementUpdate,
    };
    const MEMBERS: usize = 900;
    let started = std::time::Instant::now();
    let active = |update: PreparedManagementUpdate| match update {
        PreparedManagementUpdate::Active(workspace) => *workspace,
        PreparedManagementUpdate::Removed(_) => panic!("unexpected removal"),
    };
    let owner_key = EndpointKey::generate().unwrap();
    let grow = |with_self_updates: bool| {
        let mut owner = arachne_security::Workspace::create(&owner_key, "Owner").unwrap();
        let mut receiver: Option<(arachne_security::Workspace, [u8; 32])> = None;
        let mut self_updates = 0;
        while owner.member_count() < MEMBERS {
            let (registration, invitation, checkpoint) =
                owner.prepare_invitation(0, false, false).unwrap();
            owner = registration.workspace;
            let count = (MEMBERS - owner.member_count()).min(MAX_ADMISSION_BATCH);
            let keys: Vec<_> = (0..count).map(|_| EndpointKey::generate().unwrap()).collect();
            let joins: Vec<_> = keys
                .iter()
                .map(|key| PendingJoin::from_invitation(&invitation, &checkpoint, key, "Member").unwrap())
                .collect();
            let requests: Vec<_> = joins
                .iter()
                .map(|join| join.admission_request().unwrap().to_vec())
                .collect();
            let validated: Vec<_> = keys
                .iter()
                .zip(&requests)
                .map(|(key, request)| match owner.assess_admission(key.endpoint(), request).unwrap() {
                    AdmissionAssessment::Ready(validated) => validated,
                    _ => panic!("open invitation needs no approval"),
                })
                .collect();
            let entries: Vec<_> = keys
                .iter()
                .zip(requests.iter().zip(&validated))
                .map(|(key, (request, validated))| (key.endpoint(), request.as_slice(), validated))
                .collect();
            let prepared = owner.prepare_validated_admission_batch(&entries).unwrap();
            let authorization = if count == 1 {
                MembershipAuthorization::Admission(prepared.replies[0].authorization.clone())
            } else {
                MembershipAuthorization::AdmissionBatch(
                    prepared.replies.iter().map(|reply| reply.authorization.clone()).collect(),
                )
            };
            owner = prepared.workspace;
            let join = |index: usize| {
                let mut proof = joins[index].join_proof().unwrap();
                proof.apply_transition(&authorization, &prepared.commit).unwrap();
                joins[index].prepare_workspace(&proof, &prepared.welcome).unwrap()
            };
            if !with_self_updates {
                continue;
            }
            // The batch's first and last joiners self-update, in turn.
            let mut last = join(count - 1);
            if count > 1 {
                let first = join(0).prepare_self_update().unwrap();
                owner = active(owner.prepare_self_update_update(&first.commit).unwrap());
                last = active(last.prepare_self_update_update(&first.commit).unwrap());
                self_updates += 1;
            }
            let update = last.prepare_self_update().unwrap();
            owner = active(owner.prepare_self_update_update(&update.commit).unwrap());
            self_updates += 1;
            receiver = Some((update.workspace, keys[count - 1].endpoint()));
        }
        (owner, receiver, self_updates)
    };
    // Counterfactual: nobody self-updates. A registration at this size is
    // over the old 64 KiB bound, and now within MAX_MEMBERSHIP_COMMIT.
    let (plain, _, _) = grow(false);
    let registration = plain.prepare_invitation(0, false, false).unwrap().0;
    eprintln!("B3c runtime: registration without self-updates {} bytes", registration.commit.len());
    assert!(registration.commit.len() > 64 * 1024);
    assert!(registration.commit.len() <= arachne_security::MAX_MEMBERSHIP_COMMIT);
    drop((plain, registration));
    let (owner, receiver, self_updates) = grow(true);
    let (receiver, receiver_endpoint) = receiver.unwrap();
    assert!(owner.member_count() > 785);
    eprintln!(
        "B3c runtime: {} members, {self_updates} self-updates, {} without, grown in {:?}",
        owner.member_count(),
        owner.members_without_self_update(),
        started.elapsed()
    );

    // The runtime cannot persist a workspace this large yet: the OpenMLS
    // tree record passes the store's 1 MiB record bound (~1.37 MB at 900
    // members), so staging with native records fails before any commit is
    // made. The owner therefore commits through the security API; the
    // runtime's transport bound, binary range page and step decoding are
    // exercised, and the receiver verifies with prepare_step_update, the
    // call stage_update makes.
    let tree = owner
        .export_records()
        .unwrap()
        .iter()
        .map(|(name, value)| (value.len(), name.starts_with(b"security/provider/Tree")))
        .filter(|(_, tree)| *tree)
        .map(|(size, _)| size)
        .max()
        .unwrap_or(0);
    eprintln!("B3c runtime: largest OpenMLS tree record {tree} bytes");
    let mut owner = owner;
    let mut receiver = receiver;
    let mut sizes = Vec::new();
    for change in ["registration", "remove"] {
        let after = owner.epoch();
        let prepared = match change {
            "registration" => owner.prepare_invitation(0, false, false).unwrap().0,
            _ => {
                let target = owner
                    .member_roster()
                    .unwrap()
                    .into_iter()
                    .find(|member| !member.administrator && member.endpoint != receiver_endpoint)
                    .unwrap()
                    .id;
                owner
                    .prepare_management(arachne_security::ManagementAction::Remove(target))
                    .unwrap()
            }
        };
        // The runtime's commit-side bound (stage_prepared).
        encode_step(&prepared.authorization, &prepared.commit).unwrap();
        sizes.push((change, prepared.commit.len()));
        // The old 64 KiB bound: the self-updates did the work, not the raise.
        assert!(prepared.commit.len() < 64 * 1024, "{change}: {} bytes", prepared.commit.len());
        owner = prepared.workspace;
        // The member pulls it as one binary range page.
        let query = wire::encode_range_query(&wire::RangeQuery {
            workspace: owner.id(),
            after,
            until: owner.epoch(),
        })
        .unwrap();
        let page = range_reply(Some(&owner), receiver_endpoint, &query);
        assert!(page.len() <= arachne_node::MAX_CONTROL_REPLY);
        let reply = wire::decode_range_reply(&page).unwrap();
        assert_eq!((reply.after, reply.steps.len()), (after, 1));
        let (authorization, commit) = join_step_from_wire(reply.steps[0]).unwrap().parts().unwrap();
        assert_eq!(
            step_kind(&authorization),
            if change == "remove" { "remove" } else { "create_invitation" }
        );
        receiver = active(receiver.prepare_step_update(&authorization, &commit).unwrap());
        assert_eq!(receiver.epoch_fingerprint(), owner.epoch_fingerprint());
    }
    eprintln!("B3c runtime: commit sizes {sizes:?}, total {:?}", started.elapsed());
}

/// A member whose administrators all failed recently defers its
/// self-update without staging, so steps keep landing while the
/// administrators are offline (B3c policy).
#[test]
fn a_self_update_waits_while_every_administrator_is_unreachable() {
    let (owner, members, _) = admit_members(41, "Waiting member", 1);
    let admin = owner.endpoint();
    let mut session = bare_test_session(members.into_iter().next().unwrap());
    let now = std::time::Instant::now();
    session.membership.peer_failures.insert(admin, now);
    assert!(start_self_update(&mut session, now).unwrap().is_none());
    assert!(session.transition.staged.is_none());
    // Deferred, not retried at once.
    session.membership.peer_failures.clear();
    assert!(start_self_update(&mut session, now).unwrap().is_none());
    // Due again after the wait: the stored session stages and offers it.
    let later = now + self_update::SELF_UPDATE_RETRY;
    let started = start_self_update(&mut session, later).unwrap().unwrap();
    assert_eq!(started["state"], "self_update_offered");
    assert!(session.transition.staged.is_some());
}
