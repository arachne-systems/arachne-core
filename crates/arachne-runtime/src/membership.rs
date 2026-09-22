//! Bounded next-membership-transition retrieval over authenticated peer control requests.
//! Replies contain no Welcome, bearer invitation or private group state.
use super::*;
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
    Leave {
        id: [u8; 32],
        signature: Vec<u8>,
    },
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
    pub(super) fn action(&self) -> Result<arachne_security::ManagementAction, String> {
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
            Self::Leave { id, signature } => arachne_security::ManagementAction::Leave(
                *id,
                signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| "invalid leave signature length")?,
            ),
        })
    }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct JoinStep {
    pub commit: Vec<u8>,
    authorization: Option<JoinAuthorization>,
    admission_batch: Option<Vec<JoinAuthorization>>,
    management: Option<WireManagement>,
    invitation_checkpoint: Option<InvitationCheckpoint>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct InvitationCheckpoint {
    grant: Vec<u8>,
    checkpoint: Vec<u8>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinAuthorization {
    invitation_key: [u8; 32],
    grant_signature: Vec<u8>,
    redemption_signature: Vec<u8>,
}
impl JoinStep {
    pub(super) fn authorization(&self) -> Result<arachne_security::MembershipAuthorization, String> {
        let admission = |auth: &JoinAuthorization| {
            Ok(arachne_security::AdmissionAuthorization {
                invitation_key: auth.invitation_key,
                grant_signature: auth
                    .grant_signature
                    .clone()
                    .try_into()
                    .map_err(|_| "invalid grant signature length")?,
                redemption_signature: auth
                    .redemption_signature
                    .clone()
                    .try_into()
                    .map_err(|_| "invalid redemption signature length")?,
            })
        };
        match (&self.authorization, &self.admission_batch, &self.management) {
            (Some(auth), None, None) => Ok(arachne_security::MembershipAuthorization::Admission(
                admission(auth)?,
            )),
            (None, Some(auths), None) if !auths.is_empty() => {
                Ok(arachne_security::MembershipAuthorization::AdmissionBatch(
                    auths.iter().map(admission).collect::<Result<_, String>>()?,
                ))
            }
            (None, None, Some(action)) => Ok(arachne_security::MembershipAuthorization::Management(
                action.action()?,
            )),
            _ => Err("membership step requires exactly one authorization kind".into()),
        }
    }
}
pub(super) fn step_json(auth: &arachne_security::MembershipAuthorization, commit: &[u8]) -> Value {
    let mut value = json!({"commit":commit});
    match auth {
        arachne_security::MembershipAuthorization::Admission(auth) => {
            value["authorization"] = json!({
            "invitation_key":auth.invitation_key, "grant_signature":auth.grant_signature.as_slice(),
            "redemption_signature":auth.redemption_signature.as_slice()})
        }
        arachne_security::MembershipAuthorization::AdmissionBatch(auths) => {
            value["admission_batch"] = json!(
                auths
                    .iter()
                    .map(|auth| json!({
                        "invitation_key":auth.invitation_key,
                        "grant_signature":auth.grant_signature.as_slice(),
                        "redemption_signature":auth.redemption_signature.as_slice()
                    }))
                    .collect::<Vec<_>>()
            );
        }
        arachne_security::MembershipAuthorization::Management(action) => {
            let action = match action {
                arachne_security::ManagementAction::Promote(id) => WireManagement::Promote(*id),
                arachne_security::ManagementAction::Demote(id) => WireManagement::Demote(*id),
                arachne_security::ManagementAction::Remove(id) => WireManagement::Remove(*id),
                arachne_security::ManagementAction::CreateInvitation(key, expires_at, personal) => {
                    WireManagement::CreateInvitation {
                        key: *key,
                        expires_at: *expires_at,
                        personal: *personal,
                    }
                }
                arachne_security::ManagementAction::CreateAutomaticInvitation(key, expires_at) => {
                    WireManagement::CreateAutomaticInvitation {
                        key: *key,
                        expires_at: *expires_at,
                    }
                }
                arachne_security::ManagementAction::ApproveInvitation(key, package) => {
                    WireManagement::ApproveInvitation {
                        key: *key,
                        package: *package,
                    }
                }
                arachne_security::ManagementAction::CreateRequestInvitation(key, expires_at) => {
                    WireManagement::CreateRequestInvitation {
                        key: *key,
                        expires_at: *expires_at,
                    }
                }
                arachne_security::ManagementAction::DeclineInvitationRequest(key, package) => {
                    WireManagement::DeclineInvitationRequest {
                        key: *key,
                        package: *package,
                    }
                }
                arachne_security::ManagementAction::DisableInvitation(key) => {
                    WireManagement::DisableInvitation(*key)
                }
                arachne_security::ManagementAction::Leave(id, signature) => WireManagement::Leave {
                    id: *id,
                    signature: signature.to_vec(),
                },
            };
            value["management"] = json!(action);
        }
    }
    value
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
) -> Result<bool, String> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?;
    merge_into(
        owner,
        &mut lock_profiles(&session.profiles),
        profiles,
        budget,
    )
}

/// Retained signed member profiles. Shared by the host and the inquiry
/// responder, so a membership query is answered without the host (ADR 0010).
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
) -> Result<bool, String> {
    if profiles.len() > MAX_REQUEST_PROFILES
        || profiles
            .iter()
            .any(|p| p.len() > arachne_security::MAX_MEMBER_PROFILE)
    {
        return Err("member profile cache exceeds bounds".into());
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
    .map_err(str::to_owned)?;
    let own_id = owner.member().ok_or("member profile required")?.id();

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

pub(super) fn roster(session: &mut Session, profiles: &[Vec<u8>]) -> Result<Value, String> {
    roster_with_budget(session, profiles, MAX_PROFILE_SET_BYTES)
}

/// Budget-parameterized for the same reason as `merge_profiles_with_budget`.
fn roster_with_budget(
    session: &mut Session,
    profiles: &[Vec<u8>],
    budget: usize,
) -> Result<Value, String> {
    let overflowed = merge_profiles_with_budget(session, profiles, budget)?;
    let owner = session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?;
    let own_id = owner.member().ok_or("member profile required")?.id();
    let set = lock_profiles(&session.profiles);
    let members = owner
        .member_roster()
        .map_err(str::to_owned)?
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
            let name = profile
                .as_ref()
                .map(|profile| profile.display_name().to_owned());
            json!({"id":member.id,"endpoint":member.endpoint,"administrator":member.administrator,
            "self":member.id == own_id,"display_name":name,
            "last_contact_age_ms":contact_age.map(|age| age.as_millis().min(u64::MAX as u128) as u64),
            "presence_fresh_for_ms":contact_age.map(|age| presence::fresh_for(age).as_millis() as u64),
            "kind":if profile.as_ref().is_some_and(|profile| profile.is_service()) { "service" } else { "person" },
            "presence": if member.id == own_id { "self" } else {
                presence::status(&session.presence, member.endpoint, now)
            }})
        })
        .collect::<Vec<_>>();
    let mut result = json!({"workspace":owner.id(),"workspace_name":owner.workspace_name().map_err(str::to_owned)?,
        "workspace_name_revision":owner.workspace_name_revision().map_err(str::to_owned)?,
        "workspace_name_head":owner.workspace_name_head().map_err(str::to_owned)?,"epoch":owner.epoch(),"members":members,
        "profiles":set.retained.values().collect::<Vec<_>>()});
    // Distinguishable, non-silent signal that the byte budget dropped at
    // least one incoming profile this call -- never an Err (FUT-37 kickback
    // #1): a full retention budget must not fail a membership-control
    // operation, and member_roster is reachable from the same control-adjacent
    // paths (PollMembershipUpdate, open/refresh), not just presentation.
    if overflowed {
        result["profiles_retained"] = json!(false);
    }
    Ok(result)
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
        &mut lock_profiles(&session.profiles),
        peer,
        bytes,
        MAX_PROFILE_SET_BYTES,
    );
    send_queued_profiles(session);
    result
}

/// Gossip the profiles that membership queries retained first (ADR 0008).
pub(super) fn send_queued_profiles(session: &Session) {
    let queued = std::mem::take(&mut lock_profiles(&session.profiles).to_gossip);
    for bytes in queued {
        broadcast_profile(session, &bytes);
    }
}

/// The host-facing notice for queries the inquiry responder answered since
/// the host last heard: the same event the host path returns for a query.
pub(super) fn take_answered(session: &Session) -> Option<Value> {
    let peer = lock_profiles(&session.profiles).answered.take()?;
    let mut event = json!({"state":"membership_replied", "remote_receipt":false});
    if let Some(peer) = peer {
        event["peer"] = json!(peer);
    }
    Some(event)
}

/// Answer a membership query from one committed workspace and the shared
/// profile set, with or without the host (ADR 0010). It writes only to
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
        // A name this node just learned travels on to every member by gossip
        // (ADR 0008): replies carry only two names each, so pulled names lagged.
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

fn agreement(owner: &arachne_security::Workspace, value: &Value) -> Result<&'static str, String> {
    if value["epoch"] != owner.epoch() {
        return Err("current membership reply has a different epoch".into());
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

pub(super) fn poll(session: &mut Session, request: Request) -> Result<Value, String> {
    poll_with_budget(session, request, MAX_PROFILE_SET_BYTES)
}

/// Start one authenticated membership query from a native work signal.  The
/// host may still request this explicitly for diagnostics, but normal
/// convergence does not need a peer walk or a Kotlin retry loop.
pub(super) fn start_query_if_needed(
    session: &mut Session,
    peer: [u8; 32],
) -> Result<bool, String> {
    if session.membership_update.is_some() {
        return Ok(false);
    }
    if session
        .membership_peer_failures
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
) -> Result<(), String> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?;
    if session.membership_update.is_some() && !replace_pending {
        return Err("membership query already pending".into());
    }
    if peer == session.node.id() || owner.member_id_for_endpoint(peer).is_err() {
        return Err("membership query requires another admitted peer".into());
    }
    drop(session.membership_update.take());
    let basis = StateBasis {
        epoch: owner.epoch(),
        fingerprint: owner.epoch_fingerprint(),
        name_head: owner.workspace_name_head().map_err(str::to_owned)?,
    };
    let workspace = owner.id();
    merge_profiles_with_budget(session, &[], budget)?;
    let owner = session
        .workspace
        .as_deref()
        .ok_or("session has no workspace")?;
    let mut set = lock_profiles(&session.profiles);
    let digest = profiles_digest(owner, &set);
    let profiles = if session.peer_profile_summaries.get(&peer) == Some(&digest) {
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
    })?;
    // The reply is an outbound event, so it does not enqueue a control
    // request locally. Wake the existing host drain when it completes.
    let request = session.node.request_control(peer, &query);
    let wake = session.node.control_signal();
    let task = session.runtime.spawn(async move {
        let reply = request.await;
        wake.notify_one();
        reply
    });
    session.membership_update = Some(PendingControl {
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
) -> Result<Value, String> {
    if session.membership_offer.is_some() {
        return Err("membership offer already pending".into());
    }
    let packet = {
        let owner = session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?;
        let mut packet = b"DFMO\x01".to_vec();
        packet.extend(owner.id());
        packet.extend(after.to_be_bytes());
        packet.extend(
            serde_json::to_vec(&step_with_retained_checkpoint(
                owner,
                &authorization,
                &commit,
            ))
            .map_err(|e| e.to_string())?,
        );
        if packet.len() > 32 * 1024 {
            return Err("membership offer exceeds control bound".into());
        }
        packet
    };
    let task = session
        .runtime
        .spawn(session.node.request_control(peer, &packet));
    session.membership_offer = Some(PendingControl {
        query: after,
        peer,
        task,
    });
    session.membership_offer_requires_adoption = requires_adoption;
    Ok(json!({"state":"membership_offer_pending"}))
}

/// Budget-parameterized for the same reason as `merge_profiles_with_budget`:
/// lets a test drive FetchMembershipUpdate/PollMembershipUpdate's profile
/// merge into overflow with a handful of real admitted members.
fn poll_with_budget(
    session: &mut Session,
    request: Request,
    budget: usize,
) -> Result<Value, String> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?;
    match request {
        Request::NextMembershipPeer { after } => {
            let now = std::time::Instant::now();
            session.membership_peer_failures.retain(|_, failed| {
                now.saturating_duration_since(*failed) < MEMBERSHIP_PEER_COOLDOWN
            });
            let mut peers = owner
                .member_roster()
                .map_err(str::to_owned)?
                .into_iter()
                .filter(|member| member.endpoint != session.node.id())
                .map(|member| PeerChoice {
                    endpoint: member.endpoint,
                    preferred: member.administrator
                        || presence::contact_age(&session.presence, member.endpoint, now)
                            .is_some_and(|age| age < MEMBERSHIP_PEER_RECENT),
                    cooling: session
                        .membership_peer_failures
                        .contains_key(&member.endpoint),
                })
                .collect::<Vec<_>>();
            peers.sort_unstable_by_key(|peer| peer.endpoint);
            let peer = choose_membership_peer(&peers, after);
            let member = peer
                .as_ref()
                .map(|peer| owner.member_id_for_endpoint(*peer))
                .transpose()
                .map_err(str::to_owned)?;
            Ok(json!({"peer":peer,"member":member,"epoch":owner.epoch()}))
        }
        Request::OfferMembershipUpdate { peer, after } => {
            if session.membership_offer.is_some() {
                return Err("membership offer already pending".into());
            }
            if peer == session.node.id() || owner.member_id_for_endpoint(peer).is_err() {
                return Err("membership offer requires another admitted peer".into());
            }
            let Some((authorization, commit)) = owner
                .membership_update_for(peer, after)
                .map_err(str::to_owned)?
            else {
                return Ok(json!({"state":"membership_offer_unavailable","next_after":0}));
            };
            queue_membership_offer(session, peer, after, authorization, commit, false)
        }
        Request::OfferStagedMembershipUpdate { peer } => {
            let (after, action, commit) = {
                let owner = session
                    .workspace
                    .as_ref()
                    .ok_or("session has no workspace")?;
                if peer == session.node.id() || owner.member_id_for_endpoint(peer).is_err() {
                    return Err("membership offer requires another admitted peer".into());
                }
                let staged = session
                    .staged_workspace
                    .as_ref()
                    .ok_or("workspace candidate is not staged")?;
                let WorkspaceTransition::Management(action, commit) = &staged.transition else {
                    return Err("staged membership offer requires a management transition".into());
                };
                if !matches!(action, arachne_security::ManagementAction::Promote(_)) {
                    return Err("staged membership offer only supports administrator promotion".into());
                }
                (owner.epoch(), *action, commit.clone())
            };
            queue_membership_offer(
                session,
                peer,
                after,
                arachne_security::MembershipAuthorization::Management(action),
                commit,
                true,
            )
        }
        Request::PollMembershipOffer {} => {
            if !session
                .membership_offer
                .as_ref()
                .is_some_and(|pending| pending.task.is_finished())
            {
                return Ok(Value::Null);
            }
            let requires_adoption = session.membership_offer_requires_adoption;
            session.membership_offer_requires_adoption = false;
            let mut pending = session.membership_offer.take().unwrap();
            let bytes = session
                .runtime
                .block_on(&mut pending.task)
                .map_err(|_| "membership offer task failed")?
                .map_err(|e| e.to_string())?;
            if requires_adoption && bytes.as_slice() != [1] {
                return Err("membership peer rejected the staged administrator handoff".into());
            }
            if !matches!(bytes.as_slice(), [0] | [1]) {
                return Err("invalid membership offer acknowledgment".into());
            }
            let next = pending
                .query
                .checked_add(1)
                .filter(|next| *next < owner.epoch())
                .unwrap_or(0);
            // Peer acknowledgments are availability only. They never install local authority.
            Ok(json!({"state":"membership_offer_finished","peer":pending.peer,"next_after":next}))
        }
        Request::FetchMembershipUpdate {
            peer,
            replace_pending,
        } => {
            start_query(session, peer, replace_pending, budget)?;
            Ok(json!({"state":"membership_update_pending"}))
        }
        Request::PollMembershipUpdate {} => {
            if !session
                .membership_update
                .as_ref()
                .is_some_and(|pending| pending.task.is_finished())
            {
                return Ok(Value::Null);
            }
            let mut pending = session.membership_update.take().unwrap();
            let bytes = match session
                .runtime
                .block_on(&mut pending.task)
                .map_err(|_| "membership query task failed".to_owned())
                .and_then(|reply| reply.map_err(|e| e.to_string()))
            {
                Ok(bytes) => bytes,
                Err(_error) => {
                    session
                        .membership_peer_failures
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
            session.membership_peer_failures.remove(&pending.peer);
            if owner.epoch() != pending.query.epoch
                || owner.epoch_fingerprint() != pending.query.fingerprint
                || owner.workspace_name_head().map_err(str::to_owned)? != pending.query.name_head
                || owner.member_id_for_endpoint(pending.peer).is_err()
            {
                return Ok(json!({"state":"membership_update_stale"}));
            }
            let mut value = wire::decode_reply(&bytes)?;
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
                return Err("membership reply does not match query".into());
            }
            let membership_head = value["epoch"].as_u64();
            if value["state"] == "membership_current" {
                let state = agreement(owner, &value)?;
                if state != "membership_current" {
                    // A peer disagreement is not authority to replace local state.
                    return Ok(
                        json!({"state":state,"workspace":owner.id(),"epoch":owner.epoch(),"peer":pending.peer}),
                    );
                }
            }
            if let Some(profiles) = value.get("profiles") {
                let profiles: Vec<Vec<u8>> = serde_json::from_value(profiles.clone())
                    .map_err(|_| "invalid member profiles")?;
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
                    .map_err(|_| "invalid profiles summary")?;
                // Only a peer's comparison hint, never authority for a profile.
                if !session.peer_profile_summaries.contains_key(&pending.peer)
                    && session.peer_profile_summaries.len() >= MAX_PEER_PROFILE_SUMMARIES
                {
                    session.peer_profile_summaries.pop_first();
                }
                session.peer_profile_summaries.insert(pending.peer, digest);
                // The peer holds names we do not: walk its set once, in
                // pages, unless we already walked this exact set.
                let owner = session
                    .workspace
                    .as_deref()
                    .ok_or("session has no workspace")?;
                let ours = profiles_digest(owner, &lock_profiles(&session.profiles));
                if ours != digest && session.profiles_walked.get(&pending.peer) != Some(&digest) {
                    start_profile_pull(session, pending.peer, None, digest);
                }
            }
            if value["state"] == "membership_current"
                && let Some(head) = value.get("name_head")
            {
                let head: [u8; 32] = serde_json::from_value(head.clone())
                    .map_err(|_| "invalid workspace name head")?;
                let owner = session
                    .workspace
                    .as_ref()
                    .ok_or("session has no workspace")?;
                if head != owner.workspace_name_head().map_err(str::to_owned)? {
                    let mut rejected_record = None;
                    let mut rejection_reason = None;
                    if let Some(record) = value.get("name_record") {
                        let record: Vec<u8> = serde_json::from_value(record.clone())
                            .map_err(|_| "invalid workspace name record")?;
                        if record.len() > arachne_security::MAX_WORKSPACE_NAME_RECORD {
                            return Err("workspace name record exceeds bound".into());
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
                    let ours = owner.workspace_name_revision().map_err(str::to_owned)?;
                    let remote_revision = value["name_revision"].as_u64();
                    if remote_revision.is_some_and(|revision| revision < ours) {
                        return Ok(json!({
                            "state":"workspace_name_peer_behind",
                            "peer":pending.peer,
                            "name_revision":value["name_revision"],
                            "local_name_revision":ours,
                            "local_workspace_name":owner.workspace_name().map_err(str::to_owned)?,
                            "name_head":head,
                            "local_name_head":owner.workspace_name_head().map_err(str::to_owned)?,
                            "name_update_rejected":rejection_reason,
                        }));
                    }
                    if remote_revision.is_some_and(|revision| revision == ours) {
                        return Ok(json!({
                            "state":"workspace_name_conflict",
                            "peer":pending.peer,
                            "name_revision":value["name_revision"],
                            "local_name_revision":ours,
                            "local_workspace_name":owner.workspace_name().map_err(str::to_owned)?,
                            "name_head":head,
                            "local_name_head":owner.workspace_name_head().map_err(str::to_owned)?,
                            "name_update_rejected":rejection_reason,
                        }));
                    }
                    if let Some(checkpoint) = value.get("name_checkpoint") {
                        let checkpoint: Vec<u8> = serde_json::from_value(checkpoint.clone())
                            .map_err(|_| "invalid workspace name checkpoint")?;
                        if checkpoint.len() > arachne_security::MAX_WORKSPACE_NAME_CHECKPOINT {
                            return Err("workspace name checkpoint exceeds bound".into());
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
                        .map_err(str::to_owned)?
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
            // conflict, and head gossip catches it up (ADR 0009). Reported as
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
        _ => unreachable!(),
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
    let mut owner = arachne_security::Workspace::create([seed; 32], "Coordinator").unwrap();
    let mut members = Vec::with_capacity(count as usize);
    let mut endpoints = Vec::with_capacity(count as usize);
    for i in 0..count {
        let endpoint = [
            i as u8,
            (i >> 8) as u8,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
            seed,
        ];
        let (invitation, checkpoint) = owner.issue_invitation().unwrap();
        let pending = arachne_security::PendingJoin::from_invitation(
            &invitation,
            &checkpoint,
            endpoint,
            &format!("{name_prefix} {i}"),
        )
        .unwrap();
        let prepared = owner
            .prepare_admission(endpoint, pending.admission_request().unwrap())
            .unwrap();
        let mut proof = pending.join_proof().unwrap();
        proof
            .apply_add(&prepared.authorization, &prepared.commit)
            .unwrap();
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
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (node, receiver) = runtime
        .block_on(Node::bind_with_profile(
            ([0, 0, 0, 0], 0).into(),
            None,
            NetworkProfile::Direct,
            ConnectionBudget::default(),
        ))
        .unwrap();
    let committed = super::committed_view::Published::new(None);
    Session {
        resources: resources::Jobs::default(),
        presence: presence::Presence::new().unwrap(),
        interests: interest::Updates::default(),
        records: None,
        membership_update: None,
        membership_offer: None,
        membership_offer_requires_adoption: false,
        membership_peer_failures: BTreeMap::new(),
        staged_step_received: false,
        gossip_steps_ahead: BTreeMap::new(),
        membership_head: None,
        range_pull: None,
        gossip_counts: Arc::default(),
        profile_pull: None,
        profiles_walked: BTreeMap::new(),
        gossip_profiles_pending: Default::default(),
        cutoff: None,
        current_view: None,
        ready_current_view: None,
        range: None,
        ready_range: None,
        direct_range: None,
        ready_direct_range: None,
        direct_miss: None,
        recovered: VecDeque::new(),
        publisher: None,
        received: None,
        inbox: None,
        inbound_admission: None,
        admission_queue: arachne_security::AdmissionQueue::new(),
        admission_metadata: BTreeMap::new(),
        admission_waiters: super::admission_waiters::AdmissionWaiters::new(
            super::MAX_ADMISSION_WAITERS,
        ),
        admission_pushes: Vec::new(),
        pending_approvals: BTreeMap::new(),
        staged_approval_id: None,
        queued_admission_in_flight: Vec::new(),
        admission_reads_since_stage: 0,
        nearby_workspaces: BTreeMap::new(),
        nearby_identity: None,
        staged_workspace: None,
        staged_removal: None,
        profiles: committed.profiles(),
        peer_profile_summaries: BTreeMap::new(),
        workspace: Some(workspace.into()),
        committed,
        pending_join: None,
        join_lifecycle: None,
        checkpoint_exchange: None,
        join_exchange: None,
        activity: super::WorkspaceActivity {
            phase: super::WorkspacePhase::Active,
            reason: None,
        },
        join_history_prefix: Vec::new(),
        storage_key: None,
        overlay_paths: 0,
        node,
        receiver,
        runtime,
    }
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
    roster(session, &profiles[..64]).unwrap();
    let reply2 = roster(session, &profiles[64..]).unwrap();

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
    assert!(roster(session, &[oversized]).is_err());
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
    let reply1 = roster_with_budget(session, &profiles[..1], tiny_budget).unwrap();
    assert_eq!(
        reply1.get("profiles_retained"),
        None,
        "the first profile alone must fit the budget"
    );
    let reply2 = roster_with_budget(session, &profiles[1..2], tiny_budget).unwrap();
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
    session.membership_update = Some(PendingControl {
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
        .membership_update
        .as_ref()
        .unwrap()
        .task
        .is_finished()
    {
        std::thread::yield_now();
    }
    let result = poll_with_budget(session, Request::PollMembershipUpdate {}, tiny_budget).unwrap();
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
    let workspace = arachne_security::Workspace::create([14; 32], name).unwrap();
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
    let roster = roster(&mut session, &[]).unwrap();
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
    let answerer_endpoint = [16; 32]; // admit_members creates the owner at [seed; 32]
    let mut answerer = bare_test_session(owner.clone());
    for chunk in profiles.chunks(MAX_REQUEST_PROFILES) {
        roster(&mut answerer, chunk).unwrap();
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
        let mut set = lock_profiles(&requester.profiles);
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
    requester.membership_update = Some(PendingControl {
        query: basis,
        peer: answerer_endpoint,
        task,
    });
    let polled = poll(&mut requester, Request::PollMembershipUpdate {}).unwrap();
    assert_eq!(polled["state"], "membership_current", "{polled}");

    // Its page pulls, carried in-process: three pages hold 70 names.
    for _ in 0..usize::from(MEMBERS).div_ceil(wire::MAX_PAGE_PROFILES) + 1 {
        let Some(after) = requester
            .profile_pull
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
            &lock_profiles(&answerer.profiles),
            requester_endpoint,
            &query,
        );
        let task = ready(&mut requester, page);
        settle(&task);
        requester.profile_pull.as_mut().unwrap().task = task;
        stage_gossiped_step(&mut requester).unwrap();
    }
    let roster = roster(&mut requester, &[]).unwrap();
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
    assert!(requester.profile_pull.is_none(), "the walk did not end");
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
        assert_eq!(
            *step,
            serde_json::to_vec(&step_with_retained_checkpoint(
                &owner,
                &authorization,
                &commit
            ))
            .unwrap()
        );
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
    let owner = arachne_security::Workspace::create([1; 32], "Coordinator").unwrap();
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
        reply(Some(&owner), [1; 32], &query)["state"],
        "membership_current"
    );
    assert_eq!(
        reply(Some(&owner), [2; 32], &query)["state"],
        "membership_denied"
    );
    assert_eq!(reply(None, [1; 32], &query)["state"], "membership_denied");
    for length in 0..query.len() {
        assert_eq!(
            reply(Some(&owner), [1; 32], &query[..length])["state"],
            "membership_denied"
        );
    }
    query[5] ^= 1;
    assert_eq!(
        reply(Some(&owner), [1; 32], &query)["state"],
        "membership_denied"
    );
    query[5] ^= 1;
    query = make_query(1);
    assert_eq!(
        reply(Some(&owner), [1; 32], &query)["state"],
        "membership_unavailable"
    );
    query.push(0);
    assert_eq!(
        reply(Some(&owner), [1; 32], &query)["state"],
        "membership_denied"
    );
}

#[test]
fn equal_epoch_needs_matching_fingerprint_and_malformed_claims_are_not_current() {
    let owner = arachne_security::Workspace::create([7; 32], "Coordinator").unwrap();
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

pub(super) fn stage_update(session: &mut Session, step: JoinStep) -> Result<Value, String> {
    check_epoch_transition(session)?;
    session.staged_step_received = false;
    let authorization = step.authorization()?;
    let owner = session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?;
    let invitation_checkpoint = step.invitation_checkpoint;
    let prepared = match authorization {
        arachne_security::MembershipAuthorization::Admission(auth) => {
            if invitation_checkpoint.is_some() {
                return Err("admission update cannot carry an invitation checkpoint".into());
            }
            arachne_security::PreparedManagementUpdate::Active(Box::new(
                owner
                    .prepare_admission_update(&auth, &step.commit)
                    .map_err(str::to_owned)?,
            ))
        }
        arachne_security::MembershipAuthorization::AdmissionBatch(auths) => {
            if invitation_checkpoint.is_some() {
                return Err("admission update cannot carry an invitation checkpoint".into());
            }
            arachne_security::PreparedManagementUpdate::Active(Box::new(
                owner
                    .prepare_admission_batch_update(&auths, &step.commit)
                    .map_err(str::to_owned)?,
            ))
        }
        arachne_security::MembershipAuthorization::Management(action) => {
            let mut prepared = owner
                .prepare_management_update(action, &step.commit)
                .map_err(str::to_owned)?;
            if let Some(checkpoint) = invitation_checkpoint {
                let arachne_security::PreparedManagementUpdate::Active(workspace) = &mut prepared
                else {
                    return Err("removal cannot carry an invitation checkpoint".into());
                };
                workspace
                    .retain_invitation_checkpoint(action, &checkpoint.grant, &checkpoint.checkpoint)
                    .map_err(str::to_owned)?;
            }
            prepared
        }
    };
    let key = session
        .storage_key
        .as_ref()
        .ok_or("session has no protected root key")?;
    let prepared = match prepared {
        arachne_security::PreparedManagementUpdate::Active(workspace) => *workspace,
        arachne_security::PreparedManagementUpdate::Removed(removed) => {
            return stage_removal(session, removed);
        }
    };
    let snapshot = seal_state(session.records.is_some(), &prepared, key, None, None, None)?;
    let value = json!({"workspace":prepared.id(), "workspace_name":prepared.workspace_name().map_err(str::to_owned)?, "snapshot":snapshot,
            "state":"awaiting_save", "durable":false});
    session.staged_workspace = Some(StagedWorkspace {
        publisher: None,
        received: None,
        inbox: None,
        transition: WorkspaceTransition::Admission,
        workspace: prepared,
        snapshot,
    });
    session.staged_step_received = true;
    Ok(value)
}

/// Head announcement: workspace, epoch, committing member's endpoint (ADR 0009).
const GOSSIP_HEAD: &[u8] = b"DFMH\x01";
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
        hold_profile(&mut session.gossip_profiles_pending, bytes);
    }
}

/// A committed step may admit members whose names wait here. Only a held
/// name whose member id is now in the roster is verified, so a large held set
/// costs one roster read per commit, not a roster scan per name per poll.
pub(super) fn retain_held_profiles(session: &mut Session) {
    let Some(owner) = session.workspace.as_ref() else {
        return;
    };
    if session.gossip_profiles_pending.is_empty() {
        return;
    }
    let Ok(roster) = owner.member_roster() else {
        return;
    };
    let members: BTreeSet<[u8; 32]> = roster.into_iter().map(|member| member.id).collect();
    let (ready, waiting): (Vec<Vec<u8>>, Vec<Vec<u8>>) =
        std::mem::take(&mut session.gossip_profiles_pending)
            .into_iter()
            .partition(|bytes| {
                bytes
                    .get(37..69)
                    .is_some_and(|id| members.contains(<&[u8; 32]>::try_from(id).unwrap()))
            });
    session.gossip_profiles_pending = waiting.into();
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

    pub(super) fn json(&self) -> Value {
        let get = |counter: &std::sync::atomic::AtomicU64| {
            counter.load(std::sync::atomic::Ordering::Relaxed)
        };
        json!({"sent":get(&self.sent), "no_overlay":get(&self.no_overlay), "failed":get(&self.failed),
            "received":get(&self.received), "staged":get(&self.staged), "rejected":get(&self.rejected),
            "range_pulled":get(&self.range_pulled), "range_failed":get(&self.range_failed)})
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
    match &mut session.membership_head {
        Some((known, _)) if head < *known => {}
        Some((known, authors)) if head == *known => {
            if !authors.contains(&author) && authors.len() < MAX_HEAD_AUTHORS {
                authors.push(author);
            }
        }
        _ => session.membership_head = Some((head, vec![author])),
    }
}

/// Announce this node's epoch (ADR 0009): after it commits, and after it
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
    let send = session.node.broadcast_membership(owner.id(), payload);
    // A failed broadcast is not an error for the commit: members pull. The
    // outcome is counted (sent / no overlay or no member / failed).
    let counts = session.gossip_counts.clone();
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
pub(super) fn stage_gossiped_step(session: &mut Session) -> Result<Option<Value>, String> {
    let Some(epoch) = session.workspace.as_ref().map(|owner| owner.epoch()) else {
        return Ok(None);
    };
    let id = session.workspace.as_ref().map(|owner| owner.id()).unwrap();
    while let Some((workspace, payload)) = session.node.poll_membership_gossip() {
        GossipCounts::add(&session.gossip_counts.received);
        if workspace == id
            && payload.len() > GOSSIP_PROFILE.len() + 32
            && payload.starts_with(GOSSIP_PROFILE)
            && payload[GOSSIP_PROFILE.len()..GOSSIP_PROFILE.len() + 32] == id
        {
            take_gossiped_profile(session, payload[GOSSIP_PROFILE.len() + 32..].to_vec());
            continue;
        }
        if workspace == id
            && payload.len() == GOSSIP_HEAD.len() + 72
            && payload.starts_with(GOSSIP_HEAD)
            && payload[GOSSIP_HEAD.len()..GOSSIP_HEAD.len() + 32] == id
        {
            let at = GOSSIP_HEAD.len() + 32;
            let head = u64::from_be_bytes(payload[at..at + 8].try_into().unwrap());
            let author: [u8; 32] = payload[at + 8..at + 40].try_into().unwrap();
            note_head(session, head, author);
            continue;
        }
    }
    finish_range_pull(session);
    finish_profile_pull(session);
    session
        .gossip_steps_ahead
        .retain(|after, _| *after >= epoch);
    if session
        .membership_head
        .as_ref()
        .is_some_and(|(head, _)| *head <= epoch)
    {
        session.membership_head = None;
    }
    start_range_pull(session, epoch);
    let Some(bytes) = session.gossip_steps_ahead.remove(&epoch) else {
        return Ok(None);
    };
    let Ok(step) = serde_json::from_slice::<JoinStep>(&bytes) else {
        return Ok(None);
    };
    match stage_update(session, step) {
        Ok(mut value) => {
            // No requester waits on this step: the host saves and adopts
            // without sending a reply.
            value["queued"] = json!(true);
            value["gossip"] = json!(true);
            GossipCounts::add(&session.gossip_counts.staged);
            Ok(Some(value))
        }
        // A step that does not verify is dropped; pull recovers.
        Err(_) => {
            GossipCounts::add(&session.gossip_counts.rejected);
            Ok(None)
        }
    }
}

/// Pull the steps toward an announced head from the member that committed it,
/// in one exchange (ADR 0009). That member is alive: it sent the head a
/// moment ago. One pull at a time; its reply wakes the host.
fn start_range_pull(session: &mut Session, epoch: u64) {
    if session.range_pull.is_some() || session.gossip_steps_ahead.contains_key(&epoch) {
        return;
    }
    let Some(owner) = session.workspace.as_ref() else {
        return;
    };
    let Some((head, authors)) = session.membership_head.as_mut() else {
        return;
    };
    authors.retain(|author| owner.member_id_for_endpoint(*author).is_ok());
    if *head <= epoch || authors.is_empty() {
        session.membership_head = None;
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
    session.range_pull = Some(PendingControl {
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
        .range_pull
        .as_ref()
        .is_some_and(|pending| pending.task.is_finished())
    {
        return;
    }
    let mut pending = session.range_pull.take().unwrap();
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
            if !session.gossip_steps_ahead.contains_key(&after)
                && session.gossip_steps_ahead.len() >= MAX_GOSSIP_STEPS_AHEAD
            {
                break;
            }
            session
                .gossip_steps_ahead
                .entry(after)
                .or_insert_with(|| step.to_vec());
            pulled += 1;
        }
    }
    tracing::info!(target: "data_fabric_transport", after = pending.query, peer = %hex_prefix(&pending.peer), pulled, error, "RANGE_PULL_END");
    if pulled == 0 {
        // Try the head's other authors; with none left, fall back to pull.
        GossipCounts::add(&session.gossip_counts.range_failed);
        if let Some((_, authors)) = session.membership_head.as_mut() {
            authors.retain(|author| *author != pending.peer);
            if authors.is_empty() {
                session.membership_head = None;
            }
        }
    } else {
        GossipCounts::add(&session.gossip_counts.range_pulled);
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
/// member. A pure read of the shared set, answered without the host
/// (ADR 0010). Refusal is an empty page: it reveals nothing.
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
    if session.profile_pull.is_some() {
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
    session.profile_pull = Some(PendingControl {
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
        .profile_pull
        .as_ref()
        .is_some_and(|pending| pending.task.is_finished())
    {
        return;
    }
    let mut pending = session.profile_pull.take().unwrap();
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
    if !session.profiles_walked.contains_key(&pending.peer)
        && session.profiles_walked.len() >= MAX_PEER_PROFILE_SUMMARIES
    {
        session.profiles_walked.pop_first();
    }
    session
        .profiles_walked
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
            let mut steps = Vec::new();
            let mut size = 256;
            let mut next = query.after;
            while next < query.until.min(owner.epoch()) && steps.len() < wire::MAX_RANGE_STEPS {
                let Ok(Some((authorization, commit))) = owner.membership_update_for(peer, next)
                else {
                    break;
                };
                let Ok(step) = serde_json::to_vec(&step_with_retained_checkpoint(
                    owner,
                    &authorization,
                    &commit,
                )) else {
                    break;
                };
                size += step.len() + 8;
                if size > arachne_node::MAX_CONTROL_REPLY {
                    break;
                }
                steps.push(step);
                next += 1;
            }
            (owner.id(), query.after, steps)
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

/// Accept a carrier's signed next transition, not the carrier as membership authority.
/// Responses reveal no roster, fingerprint, current epoch, Welcome or invitation.
pub(super) fn receive_offer(session: &mut Session, packet: &[u8]) -> Result<Value, String> {
    if packet.len() <= 45 || packet.len() > 32 * 1024 || !packet.starts_with(b"DFMO\x01") {
        return Err("invalid membership offer".into());
    }
    let owner = session.workspace.as_ref().ok_or("no workspace")?;
    if packet[5..37] != owner.id() || packet[37..45] != owner.epoch().to_be_bytes() {
        return Err("membership offer does not extend current epoch".into());
    }
    let step: JoinStep =
        serde_json::from_slice(&packet[45..]).map_err(|_| "invalid offered transition")?;
    stage_update(session, step)
}

pub(super) fn stage_management(
    session: &mut Session,
    action: arachne_security::ManagementAction,
) -> Result<Value, String> {
    check_epoch_transition(session)?;
    let prepared = session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?
        .prepare_management(action)
        .map_err(str::to_owned)?;
    stage_prepared(session, prepared)
}

pub(super) fn stage_prepared(
    session: &mut Session,
    prepared: arachne_security::PreparedManagement,
) -> Result<Value, String> {
    let snapshot = seal_state(
        session.records.is_some(),
        &prepared.workspace,
        session
            .storage_key
            .as_ref()
            .ok_or("session has no protected root key")?,
        None,
        None,
        None,
    )?;
    let value = json!({"workspace":prepared.workspace.id(), "workspace_name":prepared.workspace.workspace_name().map_err(str::to_owned)?, "snapshot":snapshot, "state":"awaiting_save", "durable":false});
    session.staged_workspace = Some(StagedWorkspace {
        publisher: None,
        received: None,
        inbox: None,
        transition: WorkspaceTransition::Management(prepared.action, prepared.commit),
        workspace: prepared.workspace,
        snapshot,
    });
    Ok(value)
}

const LEAVE: &[u8; 5] = b"DFLV\x01";

fn leave_parts(bytes: &[u8]) -> Result<(u64, arachne_security::ManagementAction), String> {
    if bytes.len() <= 13 || bytes.len() > 2048 || !bytes.starts_with(LEAVE) {
        return Err("invalid leave request".into());
    }
    let wire: WireManagement =
        serde_json::from_slice(&bytes[13..]).map_err(|_| "invalid leave request")?;
    let action = wire.action()?;
    if !matches!(action, arachne_security::ManagementAction::Leave(..)) {
        return Err("expected self-authorized leave".into());
    }
    Ok((u64::from_be_bytes(bytes[5..13].try_into().unwrap()), action))
}

pub(super) fn leave_reply(
    owner: &arachne_security::Workspace,
    peer: [u8; 32],
    bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let (epoch, action) = leave_parts(bytes)?;
    let (auth, commit) = owner
        .membership_update_for(peer, epoch)
        .map_err(str::to_owned)?
        .ok_or("leave outcome unavailable")?;
    if !matches!(&auth, arachne_security::MembershipAuthorization::Management(accepted) if *accepted == action)
    {
        return Err("leave outcome does not match request".into());
    }
    serde_json::to_vec(&step_json(&auth, &commit)).map_err(|e| e.to_string())
}

pub(super) fn receive_leave(
    session: &mut Session,
    peer: [u8; 32],
    bytes: &[u8],
) -> Result<Value, String> {
    let (epoch, action) = leave_parts(bytes)?;
    let owner = session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?;
    if leave_reply(owner, peer, bytes).is_ok() {
        return Ok(json!({"state":"reply_ready","leaving":true}));
    }
    if owner.epoch() != epoch
        || owner.member_id_for_endpoint(peer).map_err(str::to_owned)? != action.target()
    {
        return Err("leave requester does not match member or epoch".into());
    }
    let mut value = stage_management(session, action)?;
    value["leaving"] = json!(true);
    Ok(value)
}

pub(super) fn leave_via_peer(session: &mut Session, peer: [u8; 32]) -> Result<Value, String> {
    check_epoch_transition(session)?;
    let owner = session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?;
    if peer == owner.endpoint() || owner.member_id_for_endpoint(peer).is_err() {
        return Err("leave requires another admitted peer".into());
    }
    let action = owner.leave_action().map_err(str::to_owned)?;
    let arachne_security::ManagementAction::Leave(id, signature) = action else {
        unreachable!()
    };
    let mut packet = LEAVE.to_vec();
    packet.extend(owner.epoch().to_be_bytes());
    packet.extend(
        serde_json::to_vec(&WireManagement::Leave {
            id,
            signature: signature.to_vec(),
        })
        .map_err(|e| e.to_string())?,
    );
    let bytes = session.runtime.block_on(session.node.request_control(peer, &packet)).map_err(|_| "Couldn't finish leaving. Resume this workspace and try again when another member is reachable.")?;
    let step: JoinStep = serde_json::from_slice(&bytes).map_err(
        |_| "The other member couldn't accept the departure. Synchronize and try again.",
    )?;
    if !matches!(step.authorization()?, arachne_security::MembershipAuthorization::Management(accepted) if accepted == action)
    {
        return Err("leave reply does not match request".into());
    }
    stage_update(session, step)
}

pub(super) fn stage_removal(
    session: &mut Session,
    removed: arachne_security::RemovedMembership,
) -> Result<Value, String> {
    super::transition_activity(session, super::WorkspacePhase::Leaving, None)?;
    let snapshot = if session.records.is_some() {
        persistence::candidate_token()?
    } else {
        removed
            .seal(
                session
                    .storage_key
                    .as_ref()
                    .ok_or("session has no protected root key")?,
            )
            .map_err(str::to_owned)?
    };
    let mut value = json!({"workspace":removed.workspace_id(), "snapshot":snapshot, "state":"awaiting_save", "removed":true, "durable":false});
    value["activity"] = super::activity_value(session);
    session.staged_removal = Some((removed, snapshot));
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
