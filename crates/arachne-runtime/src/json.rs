//! The deprecated JSON dispatcher (ADR A1/A4).
//!
//! **Deprecated.** `execute` and `execute_stored` decode one JSON request,
//! call the typed op through `ops::run`, and encode its reply. They remain
//! only because the SDK's hand bindings still call them; they are deleted in
//! ADR step 9. New code uses the typed [`crate::Client`]. The `*_with_code`
//! twins return [`ApiError`], so a binding can pass `ApiError::code()`
//! through its ABI; the plain functions return the same text as before.

use arachne_api::ApiError;
use serde::Deserialize;
use serde_json::Value;

use crate::errors;
use crate::ops::candidate::{self, AdoptArgs};
use crate::ops::{self, Op, admission, debug, invitation, join, management, membership, nearby, policy, publication,
    receive, recovery, workspace,
};

/// Maximum JSON request or metadata size in bytes.
pub const MAX_REQUEST: usize = 128 * 1024;


#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Request {
    Resource(debug::ResourceArgs),
    WorkspaceMetrics {},
    WorkspaceState {},
    ResetWorkspace {},
    DiscardWorkspaceCandidate {},
    NetworkChange {},
    NearbyEndpoints {},
    SetNearbyIdentity(nearby::IdentityArgs),
    NearbyWorkspaces {},
    SetNearbyWorkspace(nearby::AdvertiseArgs),
    SendNearbyInvitation(nearby::SendInvitationArgs),
    PollWorkspacePresence(membership::PresenceArgs),
    FetchMembershipUpdate(membership::FetchUpdateArgs),
    PollMembershipUpdate {},
    NextMembershipPeer(membership::NextPeerArgs),
    OfferMembershipUpdate(membership::OfferArgs),
    OfferStagedMembershipUpdate(membership::OfferStagedArgs),
    PollMembershipOffer {},
    FetchRecoveryRange(recovery::FetchRangeArgs),
    PollRecoveryRange {},
    NextDirectGap {},
    FetchDirectRecovery(recovery::FetchDirectArgs),
    PollDirectRecovery {},
    StageDirectRecovery {},
    StageDirectMiss {},
    CancelDirectRecovery {},
    StageRecoveryRange(recovery::StageRangeArgs),
    AdoptRecovery(AdoptArgs),
    CancelRecoveryRange {},
    PollRecoveryCutoff {},
    DiscoverRecoveryCutoff(recovery::CutoffArgs),
    FetchCurrentView(recovery::FetchCurrentViewArgs),
    PollCurrentView {},
    StageCurrentView {},
    AdoptCurrentView(AdoptArgs),
    CancelCurrentView {},
    FetchInvitationCheckpoint(join::FetchCheckpointArgs),
    #[serde(rename = "request_admission")]
    JoinViaPeer(join::RequestAdmissionArgs),
    StageNetworkPublication(publication::StagePublicationArgs),
    PollPendingObject(receive::PollPendingArgs),
    StageObjectAcknowledgement(receive::ResolveArgs),
    StageObjectRejection(receive::ResolveArgs),
    PollProtected {},
    EndpointInfo {},
    /// One control request to a peer by endpoint key, with an optional
    /// address hint; returns the peer's reply bytes. No workspace authority is
    /// involved. Used by the debug rig link to dial its controller.
    ControlExchange(debug::ControlExchangeArgs),
    AdoptPublication(AdoptArgs),
    AdoptReception(AdoptArgs),
    PollAdmission(admission::PollAdmissionArgs),
    /// Drive one ordered workspace transition. With native record storage,
    /// Rust persists and adopts its candidate before answering a peer; hosts
    /// receive only the resulting projection.
    DriveWorkspace {},
    ListAdmissionApprovals(admission::ListApprovalsArgs),
    AcknowledgeAdmissionApproval(admission::AcknowledgeApprovalArgs),
    SendAdmissionReply {},
    StageJoin(join::StageJoinArgs),
    AdoptJoin(AdoptArgs),
    // Trusted host seam only: endpoint must come from authenticated transport.
    StageAdmission(admission::AdmissionArgs),
    MemberRoster(management::RosterArgs),
    UseServiceProfile {},
    LeaveViaPeer(management::PeerArgs),
    StageSoloLeave {},
    StageManagement(management::ManagementArgs),
    StageInvitation(invitation::StageInvitationArgs),
    StageInvitationApproval(invitation::DecisionArgs),
    StageInvitationDecline(invitation::DecisionArgs),
    InvitationControls {},
    StageWorkspaceName(management::WorkspaceNameArgs),
    StageWorkspaceNameUpdate(management::WorkspaceNameUpdateArgs),
    StageWorkspaceNameCheckpoint(management::WorkspaceNameCheckpointArgs),
    InspectInvitation(invitation::InspectArgs),
    StageAdmissionUpdate(management::AdmissionUpdateArgs),
    AdoptAdmission(AdoptArgs),
    RetainedAdmission(admission::AdmissionArgs),
    BeginJoin(join::BeginJoinArgs),
    DriveJoin {},
    SealPendingJoin {},
    RestorePendingJoin(join::RestorePendingJoinArgs),
    CreateWorkspace(workspace::CreateArgs),
    SealWorkspace {},
    RestoreWorkspace(workspace::RestoreArgs),
    AddAddressHint(policy::AddressHintArgs),
    // Explicit all-member topic default; endpoints come from verified membership.
    InstallWorkspacePolicy(policy::WorkspacePolicyArgs),
    InstallMemberPolicy(policy::MemberPolicyArgs),
    // Development fixture only; rejected when the session owns a workspace.
    InstallVerifiedPolicy(policy::VerifiedPolicyArgs),
    SetInterest(policy::InterestArgs),
    PollInterest {},
    Subscribe(policy::TopicArgs),
    Unsubscribe(policy::TopicArgs),
    Publish(policy::PublishArgs),
    Poll {},
}




/// The op of a request, for the guards.
pub(crate) fn op(request: &Request) -> Op {
    match request {
        Request::Resource { .. } => Op::Resource,
        Request::WorkspaceMetrics { .. } => Op::WorkspaceMetrics,
        Request::WorkspaceState { .. } => Op::WorkspaceState,
        Request::ResetWorkspace { .. } => Op::ResetWorkspace,
        Request::DiscardWorkspaceCandidate { .. } => Op::DiscardWorkspaceCandidate,
        Request::NetworkChange { .. } => Op::NetworkChange,
        Request::NearbyEndpoints { .. } => Op::NearbyEndpoints,
        Request::SetNearbyIdentity { .. } => Op::SetNearbyIdentity,
        Request::NearbyWorkspaces { .. } => Op::NearbyWorkspaces,
        Request::SetNearbyWorkspace { .. } => Op::SetNearbyWorkspace,
        Request::SendNearbyInvitation { .. } => Op::SendNearbyInvitation,
        Request::PollWorkspacePresence { .. } => Op::PollWorkspacePresence,
        Request::FetchMembershipUpdate { .. } => Op::FetchMembershipUpdate,
        Request::PollMembershipUpdate { .. } => Op::PollMembershipUpdate,
        Request::NextMembershipPeer { .. } => Op::NextMembershipPeer,
        Request::OfferMembershipUpdate { .. } => Op::OfferMembershipUpdate,
        Request::OfferStagedMembershipUpdate { .. } => Op::OfferStagedMembershipUpdate,
        Request::PollMembershipOffer { .. } => Op::PollMembershipOffer,
        Request::FetchRecoveryRange { .. } => Op::FetchRecoveryRange,
        Request::PollRecoveryRange { .. } => Op::PollRecoveryRange,
        Request::NextDirectGap { .. } => Op::NextDirectGap,
        Request::FetchDirectRecovery { .. } => Op::FetchDirectRecovery,
        Request::PollDirectRecovery { .. } => Op::PollDirectRecovery,
        Request::StageDirectRecovery { .. } => Op::StageDirectRecovery,
        Request::StageDirectMiss { .. } => Op::StageDirectMiss,
        Request::CancelDirectRecovery { .. } => Op::CancelDirectRecovery,
        Request::StageRecoveryRange { .. } => Op::StageRecoveryRange,
        Request::AdoptRecovery { .. } => Op::AdoptRecovery,
        Request::CancelRecoveryRange { .. } => Op::CancelRecoveryRange,
        Request::PollRecoveryCutoff { .. } => Op::PollRecoveryCutoff,
        Request::DiscoverRecoveryCutoff { .. } => Op::DiscoverRecoveryCutoff,
        Request::FetchCurrentView { .. } => Op::FetchCurrentView,
        Request::PollCurrentView { .. } => Op::PollCurrentView,
        Request::StageCurrentView { .. } => Op::StageCurrentView,
        Request::AdoptCurrentView { .. } => Op::AdoptCurrentView,
        Request::CancelCurrentView { .. } => Op::CancelCurrentView,
        Request::FetchInvitationCheckpoint { .. } => Op::FetchInvitationCheckpoint,
        Request::JoinViaPeer { .. } => Op::RequestAdmission,
        Request::StageNetworkPublication { .. } => Op::StageNetworkPublication,
        Request::PollPendingObject { .. } => Op::PollPendingObject,
        Request::StageObjectAcknowledgement { .. } => Op::StageObjectAcknowledgement,
        Request::StageObjectRejection { .. } => Op::StageObjectRejection,
        Request::PollProtected { .. } => Op::PollProtected,
        Request::EndpointInfo { .. } => Op::EndpointInfo,
        Request::ControlExchange { .. } => Op::ControlExchange,
        Request::AdoptPublication { .. } => Op::AdoptPublication,
        Request::AdoptReception { .. } => Op::AdoptReception,
        Request::PollAdmission { .. } => Op::PollAdmission,
        Request::DriveWorkspace { .. } => Op::DriveWorkspace,
        Request::ListAdmissionApprovals { .. } => Op::ListAdmissionApprovals,
        Request::AcknowledgeAdmissionApproval { .. } => Op::AcknowledgeAdmissionApproval,
        Request::SendAdmissionReply { .. } => Op::SendAdmissionReply,
        Request::StageJoin { .. } => Op::StageJoin,
        Request::AdoptJoin { .. } => Op::AdoptJoin,
        Request::StageAdmission { .. } => Op::StageAdmission,
        Request::MemberRoster { .. } => Op::MemberRoster,
        Request::UseServiceProfile { .. } => Op::UseServiceProfile,
        Request::LeaveViaPeer { .. } => Op::LeaveViaPeer,
        Request::StageSoloLeave { .. } => Op::StageSoloLeave,
        Request::StageManagement { .. } => Op::StageManagement,
        Request::StageInvitation { .. } => Op::StageInvitation,
        Request::StageInvitationApproval { .. } => Op::StageInvitationApproval,
        Request::StageInvitationDecline { .. } => Op::StageInvitationDecline,
        Request::InvitationControls { .. } => Op::InvitationControls,
        Request::StageWorkspaceName { .. } => Op::StageWorkspaceName,
        Request::StageWorkspaceNameUpdate { .. } => Op::StageWorkspaceNameUpdate,
        Request::StageWorkspaceNameCheckpoint { .. } => Op::StageWorkspaceNameCheckpoint,
        Request::InspectInvitation { .. } => Op::InspectInvitation,
        Request::StageAdmissionUpdate { .. } => Op::StageAdmissionUpdate,
        Request::AdoptAdmission { .. } => Op::AdoptAdmission,
        Request::RetainedAdmission { .. } => Op::RetainedAdmission,
        Request::BeginJoin { .. } => Op::BeginJoin,
        Request::DriveJoin { .. } => Op::DriveJoin,
        Request::SealPendingJoin { .. } => Op::SealPendingJoin,
        Request::RestorePendingJoin { .. } => Op::RestorePendingJoin,
        Request::CreateWorkspace { .. } => Op::CreateWorkspace,
        Request::SealWorkspace { .. } => Op::SealWorkspace,
        Request::RestoreWorkspace { .. } => Op::RestoreWorkspace,
        Request::AddAddressHint { .. } => Op::AddAddressHint,
        Request::InstallWorkspacePolicy { .. } => Op::InstallWorkspacePolicy,
        Request::InstallMemberPolicy { .. } => Op::InstallMemberPolicy,
        Request::InstallVerifiedPolicy { .. } => Op::InstallVerifiedPolicy,
        Request::SetInterest { .. } => Op::SetInterest,
        Request::PollInterest { .. } => Op::PollInterest,
        Request::Subscribe { .. } => Op::Subscribe,
        Request::Unsubscribe { .. } => Op::Unsubscribe,
        Request::Publish { .. } => Op::Publish,
        Request::Poll { .. } => Op::Poll,
    }
}

/// Decode, guard and run one request; the reply as JSON.
fn run(handle: i64, request: Request) -> Result<Value, ApiError> {
    ops::run(handle, op(&request), |session| dispatch(session, request))
}

/// One decoded request to its op.
pub(crate) fn dispatch(session: &mut crate::Session, request: Request) -> Result<Value, ApiError> {
    fn reply(value: impl serde::Serialize) -> Result<Value, ApiError> {
        serde_json::to_value(value).map_err(errors::encode)
    }
    match request {
        Request::PollAdmission(args) => admission::poll(session, args),
        Request::DriveWorkspace {} => admission::drive_workspace(session),
        Request::ListAdmissionApprovals(args) => reply(admission::list_approvals(session, args)?),
        Request::AcknowledgeAdmissionApproval(args) => {
            reply(admission::acknowledge_approval(session, args)?)
        }
        Request::SendAdmissionReply {} => reply(admission::send_reply(session)?),
        Request::StageAdmission(args) => reply(admission::stage(session, args)?),
        Request::RetainedAdmission(args) => reply(admission::retained(session, args)?),
        Request::BeginJoin(args) => reply(join::begin(session, args)?),
        Request::DriveJoin {} => join::drive(session),
        Request::SealPendingJoin {} => reply(join::seal_pending(session)?),
        Request::RestorePendingJoin(args) => reply(join::restore_pending(session, args)?),
        Request::FetchInvitationCheckpoint(args) => reply(join::fetch_checkpoint(session, args)?),
        Request::JoinViaPeer(args) => join::request_admission(session, args),
        Request::StageJoin(args) => reply(join::stage(session, args)?),
        Request::AdoptAdmission(args) => reply(candidate::adopt_admission(session, args)?),
        Request::AdoptJoin(args) => reply(candidate::adopt_join(session, args)?),
        Request::AdoptPublication(args) => reply(candidate::adopt_publication(session, args)?),
        Request::AdoptReception(args) => reply(candidate::adopt_reception(session, args)?),
        Request::AdoptRecovery(args) => reply(candidate::adopt_recovery(session, args)?),
        Request::AdoptCurrentView(args) => reply(candidate::adopt_current_view(session, args)?),
        Request::ResetWorkspace {} => reply(workspace::reset(session)?),
        Request::DiscardWorkspaceCandidate {} => reply(workspace::discard_candidate(session)?),
        Request::WorkspaceState {} => reply(workspace::state(session)?),
        Request::WorkspaceMetrics {} => reply(workspace::metrics(session)?),
        Request::CreateWorkspace(args) => reply(workspace::create(session, args)?),
        Request::SealWorkspace {} => reply(workspace::seal(session)?),
        Request::RestoreWorkspace(args) => reply(workspace::restore(session, args)?),
        Request::Resource(args) => debug::resource(session, args),
        Request::EndpointInfo {} => reply(debug::endpoint_info(session)?),
        Request::ControlExchange(args) => reply(debug::control_exchange(session, args)?),
        Request::NetworkChange {} => reply(debug::network_change(session)?),
        Request::AddAddressHint(args) => reply(policy::add_address_hint(session, args)?),
        Request::InstallWorkspacePolicy(args) => {
            reply(policy::install_workspace_policy(session, args)?)
        }
        Request::InstallMemberPolicy(args) => reply(policy::install_member_policy(session, args)?),
        Request::InstallVerifiedPolicy(args) => {
            reply(policy::install_verified_policy(session, args)?)
        }
        Request::SetInterest(args) => reply(policy::set_interest(session, args)?),
        Request::PollInterest {} => policy::poll_interest(session),
        Request::Subscribe(args) => reply(policy::subscribe(session, args)?),
        Request::Unsubscribe(args) => reply(policy::unsubscribe(session, args)?),
        Request::Publish(args) => reply(policy::publish(session, args)?),
        Request::Poll {} => reply(policy::poll(session)?),
        Request::NearbyEndpoints {} => reply(nearby::endpoints(session)?),
        Request::NearbyWorkspaces {} => reply(nearby::workspaces(session)?),
        Request::SetNearbyWorkspace(args) => reply(nearby::advertise(session, args)?),
        Request::SetNearbyIdentity(args) => reply(nearby::set_identity(session, args)?),
        Request::SendNearbyInvitation(args) => reply(nearby::send_invitation(session, args)?),
        Request::PollWorkspacePresence(args) => reply(membership::poll_presence(session, args)?),
        Request::FetchMembershipUpdate(args) => membership::fetch_update(session, args),
        Request::PollMembershipUpdate {} => membership::poll_update(session),
        Request::NextMembershipPeer(args) => membership::next_peer(session, args),
        Request::OfferMembershipUpdate(args) => membership::offer_update(session, args),
        Request::OfferStagedMembershipUpdate(args) => membership::offer_staged(session, args),
        Request::PollMembershipOffer {} => membership::poll_offer(session),
        Request::MemberRoster(args) => reply(management::member_roster(session, args)?),
        Request::UseServiceProfile {} => reply(management::use_service_profile(session)?),
        Request::StageManagement(args) => reply(management::stage(session, args)?),
        Request::LeaveViaPeer(args) => reply(management::leave_via_peer(session, args)?),
        Request::StageSoloLeave {} => reply(management::stage_solo_leave(session)?),
        Request::StageAdmissionUpdate(args) => {
            reply(management::stage_admission_update(session, args)?)
        }
        Request::StageWorkspaceName(args) => reply(management::stage_workspace_name(session, args)?),
        Request::StageWorkspaceNameUpdate(args) => {
            reply(management::stage_workspace_name_update(session, args)?)
        }
        Request::StageWorkspaceNameCheckpoint(args) => {
            reply(management::stage_workspace_name_checkpoint(session, args)?)
        }
        Request::StageInvitation(args) => reply(invitation::stage(session, args)?),
        Request::StageInvitationApproval(args) => reply(invitation::stage_approval(session, args)?),
        Request::StageInvitationDecline(args) => reply(invitation::stage_decline(session, args)?),
        Request::InvitationControls {} => reply(invitation::controls(session)?),
        Request::InspectInvitation(args) => reply(invitation::inspect(session, args)?),
        Request::StageNetworkPublication(args) => reply(publication::stage(session, args)?),
        Request::PollProtected {} => reply(receive::poll_protected(session)?),
        Request::PollPendingObject(args) => reply(receive::poll_pending(session, args)?),
        Request::StageObjectAcknowledgement(args) => reply(receive::acknowledge(session, args)?),
        Request::StageObjectRejection(args) => reply(receive::reject(session, args)?),
        Request::FetchRecoveryRange(args) => reply(recovery::fetch_range(session, args)?),
        Request::PollRecoveryRange {} => reply(recovery::poll_range(session)?),
        Request::CancelRecoveryRange {} => reply(recovery::cancel_range(session)?),
        Request::StageRecoveryRange(args) => reply(recovery::stage_range(session, args)?),
        Request::NextDirectGap {} => reply(recovery::next_direct_gap(session)?),
        Request::FetchDirectRecovery(args) => reply(recovery::fetch_direct(session, args)?),
        Request::PollDirectRecovery {} => reply(recovery::poll_direct(session)?),
        Request::CancelDirectRecovery {} => reply(recovery::cancel_direct(session)?),
        Request::StageDirectRecovery {} => reply(recovery::stage_direct(session)?),
        Request::StageDirectMiss {} => reply(recovery::stage_direct_miss(session)?),
        Request::FetchCurrentView(args) => reply(recovery::fetch_current_view(session, args)?),
        Request::PollCurrentView {} => reply(recovery::poll_current_view(session)?),
        Request::StageCurrentView {} => reply(recovery::stage_current_view(session)?),
        Request::CancelCurrentView {} => reply(recovery::cancel_current_view(session)?),
        Request::DiscoverRecoveryCutoff(args) => reply(recovery::discover_cutoff(session, args)?),
        Request::PollRecoveryCutoff {} => reply(recovery::poll_cutoff(session)?),
    }
}

/// Execute a bounded JSON request. Staged security changes require save/readback/adopt.
///
/// **Deprecated** (ADR step 9): use [`crate::Client`]. Errors are the same
/// text as before; [`execute_with_code`] gives the typed error.
pub fn execute(handle: i64, bytes: &[u8]) -> Result<Vec<u8>, String> {
    execute_with_code(handle, bytes).map_err(errors::text)
}

/// [`execute`] with the typed error, so a binding can read `code()`.
pub fn execute_with_code(handle: i64, bytes: &[u8]) -> Result<Vec<u8>, ApiError> {
    if bytes.len() > MAX_REQUEST {
        return Err(ApiError::invalid_input("request", "request exceeds limit"));
    }
    let request: Request = serde_json::from_slice(bytes).map_err(errors::decode("request"))?;
    serde_json::to_vec(&run(handle, request)?).map_err(errors::encode)
}

/// Largest binary snapshot `execute_stored` accepts or returns: a sealed
/// workspace bundle, or a sealed pending join, which carries its invitation
/// checkpoint (up to `MAX_CHECKPOINT`, B3a) and so can be the larger one.
pub const MAX_STORED_SNAPSHOT: usize =
    if arachne_security::MAX_SEALED_BUNDLE > arachne_security::MAX_SEALED_PENDING_JOIN {
        arachne_security::MAX_SEALED_BUNDLE
    } else {
        arachne_security::MAX_SEALED_PENDING_JOIN
    };
// A pending join, with its checkpoint, is saved as one host record.
const _: () = assert!(arachne_security::MAX_SEALED_PENDING_JOIN <= arachne_store::MAX_RECORD_BYTES);

// Binary snapshots never pass through the JSON request size bound. Metadata is
// independently bounded and cannot supply a second, ambiguous snapshot value.
/// Execute metadata with a binary snapshot; return metadata and snapshot separately.
/// The caller must durably save and read back staged snapshots before adopting them.
///
/// **Deprecated** (ADR step 9): use [`crate::Client`].
pub fn execute_stored(
    handle: i64,
    metadata: &[u8],
    snapshot: &[u8],
) -> Result<[Vec<u8>; 2], String> {
    execute_stored_with_code(handle, metadata, snapshot).map_err(errors::text)
}

/// [`execute_stored`] with the typed error.
pub fn execute_stored_with_code(
    handle: i64,
    metadata: &[u8],
    snapshot: &[u8],
) -> Result<[Vec<u8>; 2], ApiError> {
    let invalid = |reason: &str| ApiError::invalid_input("request", reason);
    if metadata.len() > MAX_REQUEST || snapshot.len() > MAX_STORED_SNAPSHOT {
        return Err(invalid("stored request exceeds limit"));
    }
    // Parse original bytes strictly before a generic map can hide duplicate fields.
    let mut request: Request =
        serde_json::from_slice(metadata).map_err(errors::decode("request"))?;
    let value: Value = serde_json::from_slice(metadata).map_err(errors::decode("request"))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("request must be an object"))?;
    if object.contains_key("snapshot") {
        return Err(invalid("snapshot must use the binary argument"));
    }
    let stored = matches!(
        object.get("op").and_then(Value::as_str),
        Some(
            "restore_workspace"
                | "restore_pending_join"
                | "adopt_admission"
                | "adopt_join"
                | "adopt_publication"
                | "adopt_reception"
                | "adopt_recovery"
                | "adopt_current_view"
        )
    );
    let binary_welcome = matches!(request, Request::StageJoin { .. }) && !snapshot.is_empty();
    if binary_welcome {
        if object.contains_key("welcome") {
            return Err(invalid("Welcome must have exactly one representation"));
        }
        if snapshot.len() > arachne_security::MAX_WELCOME {
            return Err(invalid("Welcome exceeds binary input bound"));
        }
        if let Request::StageJoin(join::StageJoinArgs { welcome, .. }) = &mut request {
            *welcome = snapshot.to_vec();
        }
    }
    if !stored && !binary_welcome && !snapshot.is_empty() {
        return Err(invalid("operation does not accept a snapshot"));
    }
    if stored {
        let target = match &mut request {
            Request::RestoreWorkspace(workspace::RestoreArgs { snapshot, .. })
            | Request::RestorePendingJoin(join::RestorePendingJoinArgs { snapshot, .. })
            | Request::AdoptAdmission(AdoptArgs { snapshot })
            | Request::AdoptJoin(AdoptArgs { snapshot })
            | Request::AdoptPublication(AdoptArgs { snapshot })
            | Request::AdoptReception(AdoptArgs { snapshot })
            | Request::AdoptRecovery(AdoptArgs { snapshot })
            | Request::AdoptCurrentView(AdoptArgs { snapshot }) => snapshot,
            _ => unreachable!(),
        };
        *target = snapshot.to_vec();
    }
    let mut response = run(handle, request)?;
    // ponytail: current dispatcher builds bounded JSON values internally; move
    // snapshots into a typed result if measured allocation cost warrants it.
    let snapshot = response
        .as_object_mut()
        .and_then(|v| v.remove("snapshot"))
        .map(serde_json::from_value::<Vec<u8>>)
        .transpose()
        .map_err(errors::encode)?
        .unwrap_or_default();
    if snapshot.len() > MAX_STORED_SNAPSHOT {
        return Err(ApiError::limit_reached(
            "stored snapshot",
            MAX_STORED_SNAPSHOT as u64,
            "stored response exceeds limit; close and restore",
        ));
    }
    Ok([serde_json::to_vec(&response).map_err(errors::encode)?, snapshot])
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InvitationInspection {
    invitation: Vec<u8>,
    checkpoint: Vec<u8>,
}

/// Verify invitation presentation without allocating an endpoint or join identity.
pub fn inspect_invitation(request: &[u8]) -> Result<Vec<u8>, String> {
    if request.len() > MAX_REQUEST {
        return Err("request exceeds limit".into());
    }
    let request: InvitationInspection =
        serde_json::from_slice(request).map_err(|e| e.to_string())?;
    serde_json::to_vec(
        &invitation::inspected_invitation(&request.invitation, &request.checkpoint)
            .map_err(errors::text)?,
    )
    .map_err(|e| e.to_string())
}
