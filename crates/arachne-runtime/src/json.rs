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

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::*;

    #[test]
    fn real_node_lifecycle_rejects_stale_handles_and_releases_capacity() {
        assert!(describe(0).is_err());
        assert!(close(-1).is_err());
        let handles: Vec<_> = (0..8).map(|_| create(None).unwrap()).collect();
        assert!(create(None).is_err());
        for handle in &handles {
            let info: serde_json::Value =
                serde_json::from_str(&describe(*handle).unwrap()).unwrap();
            assert_eq!(info["endpoint_key"].as_array().unwrap().len(), 32);
            assert_eq!(info["workspace_ready"], false);
            close(*handle).unwrap();
            assert!(describe(*handle).is_err());
            assert!(close(*handle).is_err());
        }
        let next = create(None).unwrap();
        assert!(next > *handles.last().unwrap());
        close(next).unwrap();

        // Exercise the same request dispatcher exported over JNI with real peers.
        let a = create(None).unwrap();
        let b = create(None).unwrap();
        let ai: Value = serde_json::from_str(&describe(a).unwrap()).unwrap();
        let bi: Value = serde_json::from_str(&describe(b).unwrap()).unwrap();
        let call = |handle, value: Value| -> Result<Value, String> {
            serde_json::from_slice(&execute(handle, &serde_json::to_vec(&value).unwrap())?)
                .map_err(|e| e.to_string())
        };
        let issue_invitation = |handle: i64| -> Value {
            let staged = call(
                handle,
                json!({"op":"stage_invitation","personal":false,"expires_at":0}),
            )
            .unwrap();
            call(
                handle,
                json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
            )
            .unwrap()["issued_invitation"]
                .clone()
        };
        // Read the next pending inbox object and durably acknowledge it.
        let take_pending = |handle: i64| -> Value {
            let pending = call(handle, json!({"op":"poll_pending_object"})).unwrap();
            assert!(!pending.is_null(), "expected a pending object");
            let staged = call(
                handle,
                json!({"op":"stage_object_acknowledgement", "member":pending["member"],
                "topic":pending["topic"], "counter":pending["counter"], "id":pending["id"]}),
            )
            .unwrap();
            call(
                handle,
                json!({"op":"adopt_reception","snapshot":staged["snapshot"]}),
            )
            .unwrap();
            pending
        };
        assert_eq!(
            call(a, json!({"op":"network_change"})).unwrap(),
            json!({"notified":true})
        );
        for (handle, other) in [(a, &bi), (b, &ai)] {
            let port = other["bound_address"]
                .as_str()
                .unwrap()
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .port();
            call(
                handle,
                json!({"op":"add_address_hint", "peer":other["endpoint_key"],
                "address":format!("127.0.0.1:{port}")}),
            )
            .unwrap();
            call(
                handle,
                json!({"op":"install_verified_policy", "workspace":vec![7;32], "revision":1,
                "endpoints":[
                    {"peer":ai["endpoint_key"], "publish":["streams/sample"], "subscribe":[]},
                    {"peer":bi["endpoint_key"], "publish":[], "subscribe":["streams/sample"]}
                ]}),
            )
            .unwrap();
        }
        call(b, json!({"op":"subscribe", "workspace":vec![7;32], "revision":1, "topic":"streams/sample"})).unwrap();
        for payload in [vec![0, 255, 17], br#"{"event":"changed"}"#.to_vec()] {
            let outcome = call(
                a,
                json!({"op":"publish", "workspace":vec![7;32], "revision":1,
                "topic":"streams/sample", "payload":payload}),
            )
            .unwrap();
            assert_eq!(outcome["admitted"], json!([bi["endpoint_key"]]));
            assert_eq!(outcome["failed"], json!([]));
            let received = call(b, json!({"op":"poll"})).unwrap();
            assert_eq!(received["payload"], json!(payload));
            assert_eq!(received["workspace"], json!(vec![7; 32]));
            assert_eq!(received["sender"], ai["endpoint_key"]);
        }
        assert_eq!(call(b, json!({"op":"poll"})).unwrap(), Value::Null);
        assert!(
            call(
                b,
                json!({"op":"publish", "workspace":vec![7;32], "revision":1,
            "topic":"streams/sample", "payload":[1]})
            )
            .is_err()
        );
        assert!(call(a, json!({"op":"poll", "unexpected":true})).is_err());
        assert!(execute(a, &vec![b' '; MAX_REQUEST + 1]).is_err());
        call(b, json!({"op":"unsubscribe", "workspace":vec![7;32], "revision":1, "topic":"streams/sample"})).unwrap();
        assert_eq!(
            call(
                a,
                json!({"op":"publish", "workspace":vec![7;32], "revision":1,
            "topic":"streams/sample", "payload":[1]})
            )
            .unwrap()["admitted"],
            json!([])
        );
        close(a).unwrap();
        close(b).unwrap();
        assert!(call(a, json!({"op":"poll"})).is_err());

        let mut admin = create(Some(&[41; 32])).unwrap();
        let joiner = create(Some(&[42; 32])).unwrap();
        let created = call(
            admin,
            json!({"op":"create_workspace","display_name":"Coordinator"}),
        )
        .unwrap();
        // The invitation must be registered before it is sealed as the
        // rollback target below, otherwise restoring to `old` would make the
        // admission look up a key that was never committed to policy.
        let invite = issue_invitation(admin);
        let old = call(admin, json!({"op":"seal_workspace"})).unwrap();
        let pending = call(
            joiner,
            json!({"op":"begin_join","invitation":invite["invitation"],
            "checkpoint":invite["checkpoint"],"display_name":"Field member"}),
        )
        .unwrap();
        let stage = json!({"op":"stage_admission","authenticated_endpoint":pending["endpoint"],"request":pending["admission_request"]});
        let retry = json!({"op":"retained_admission","authenticated_endpoint":pending["endpoint"],"request":pending["admission_request"]});
        let prepared = call(admin, stage.clone()).unwrap();
        assert!(prepared.get("welcome").is_none());
        assert!(call(admin, retry.clone()).is_err());
        assert!(call(admin, json!({"op":"seal_workspace"})).is_err());
        assert!(
            call(
                admin,
                json!({"op":"adopt_admission","snapshot":old["snapshot"]})
            )
            .is_err()
        );
        close(admin).unwrap(); // No candidate saved: the old durable state wins.
        admin = create(Some(&[41; 32])).unwrap();
        let restored = call(admin, json!({"op":"restore_workspace","workspace":created["workspace"],"snapshot":old["snapshot"]})).unwrap();
        assert_eq!(restored["members"], 1);
        assert!(call(admin, retry.clone()).is_err());
        let saved = call(admin, stage).unwrap();
        close(admin).unwrap(); // Candidate saved, adoption reply lost: restore it directly.
        admin = create(Some(&[41; 32])).unwrap();
        let restored = call(admin, json!({"op":"restore_workspace","workspace":created["workspace"],"snapshot":saved["snapshot"]})).unwrap();
        assert_eq!(restored["members"], 2);
        // +1: registering the invitation now costs an epoch before the
        // admission commit that seated the second member.
        assert_eq!(restored["epoch"], 2);
        let reply = call(admin, retry.clone()).unwrap();
        assert_eq!(reply["welcome"], call(admin, retry).unwrap()["welcome"]);
        call(
            joiner,
            json!({"op":"add_address_hint", "peer":invite["peer"],
            "address":serde_json::from_str::<Value>(&describe(admin).unwrap()).unwrap()["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
        )
        .unwrap();
        let peer = invite["peer"].clone();
        let requesting = std::thread::spawn(move || {
            let request =
                serde_json::to_vec(&json!({"op":"request_admission","peer":peer})).unwrap();
            serde_json::from_slice::<Value>(&execute(joiner, &request).unwrap()).unwrap()
        });
        // The result is retained, so this request is an inquiry: the
        // committed view answers it and the host is never asked.
        let mut network_reply = requesting.join().unwrap();
        assert_eq!(
            call(admin, json!({"op":"poll_admission"})).unwrap(),
            Value::Null
        );
        // The joiner reports the wire size of every page it accepted; a
        // one-page history still reports its single page.
        let pages = network_reply
            .as_object_mut()
            .unwrap()
            .remove("history_page_bytes")
            .unwrap();
        assert_eq!(pages.as_array().unwrap().len(), 1);
        assert!(
            pages[0].as_u64().unwrap() as usize <= arachne_node::MAX_CONTROL_REPLY,
            "a served page must stay inside the control-reply bound"
        );
        // The reply carries the admission once, as its binary step; the
        // Welcome and authorization ride on the final page.
        let commits = network_reply
            .as_object_mut()
            .unwrap()
            .remove("commits")
            .unwrap();
        assert_eq!(commits.as_array().unwrap().len(), 1);
        assert_eq!(commits[0]["kind"], "admission");
        let step: Vec<u8> = serde_json::from_value(commits[0]["step"].clone()).unwrap();
        let (_, commit) = arachne_security::decode_membership_step(&step).unwrap();
        assert_eq!(json!(commit), reply["commit"]);
        let mut expected = reply.clone();
        expected.as_object_mut().unwrap().remove("commit");
        assert_eq!(network_reply, expected);
        let join = json!({"op":"stage_join", "welcome":reply["welcome"],
            "commits":[{"commit":reply["commit"], "authorization":reply["authorization"]}]});
        let mut invalid = join.clone();
        invalid["commits"][0]["authorization"]["grant_signature"] = json!([1]);
        assert!(call(joiner, invalid).is_err());
        assert!(call(joiner, json!({"op":"seal_pending_join"})).is_ok());
        let staged_join = call(joiner, join).unwrap();
        assert!(
            call(
                joiner,
                json!({"op":"adopt_admission","snapshot":staged_join["snapshot"]})
            )
            .is_err()
        );
        let adopted = call(
            joiner,
            json!({"op":"adopt_join","snapshot":staged_join["snapshot"]}),
        )
        .unwrap();
        assert_eq!(adopted["members"], 2);
        assert!(call(joiner, json!({"op":"seal_pending_join"})).is_err());
        close(joiner).unwrap();
        let joiner = create(Some(&[42; 32])).unwrap();
        let restored = call(joiner,json!({"op":"restore_workspace","workspace":created["workspace"],"snapshot":staged_join["snapshot"]})).unwrap();
        assert_eq!(restored["member"], pending["member"]);
        // Production routing obtains endpoints from the restored MLS roster.
        let member_policy =
            json!({"op":"install_member_policy","revision":17,"topics":["streams/sample"]});
        for handle in [admin, joiner] {
            assert!(call(handle, json!({"op":"install_verified_policy","workspace":created["workspace"],"revision":17,"endpoints":[]})).is_err());
            assert!(
                call(
                    handle,
                    json!({"op":"install_member_policy","revision":17,"topics":[]})
                )
                .is_err()
            );
            assert!(
                call(
                    handle,
                    json!({"op":"install_member_policy","revision":17,"topics":["bad topic"]})
                )
                .is_err()
            );
            let installed = call(handle, member_policy.clone()).unwrap();
            assert_eq!(installed["members"], 2);
            assert_eq!(installed["revision"], 17);
            assert!(call(handle, member_policy.clone()).is_err());
        }
        // The policy authorizes real peer subscription without injecting keys.
        let admin_info: Value = serde_json::from_str(&describe(admin).unwrap()).unwrap();
        call(joiner, json!({"op":"add_address_hint","peer":admin_info["endpoint_key"],
            "address":admin_info["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")})).unwrap();
        let subscribed = call(joiner, json!({"op":"subscribe","workspace":created["workspace"],"revision":17,"topic":"streams/sample"})).unwrap();
        assert_eq!(subscribed["admitted"].as_array().unwrap().len(), 2);
        assert!(subscribed["failed"].as_array().unwrap().is_empty());
        assert!(call(joiner, json!({"op":"subscribe","workspace":created["workspace"],"revision":17,"topic":"streams/other"})).is_err());
        let staged_binary = execute_stored(admin, &serde_json::to_vec(&json!({"op":"stage_network_publication","revision":17,"topic":"streams/sample","id":vec![10;16],"payload":[0,255,77]})).unwrap(), &[]).unwrap();
        let mut staged_network: Value = serde_json::from_slice(&staged_binary[0]).unwrap();
        assert!(staged_network.get("snapshot").is_none());
        assert!(!staged_binary[1].is_empty());
        staged_network["snapshot"] = json!(staged_binary[1]);
        assert!(staged_network.get("ciphertext").is_none());
        assert_eq!(
            call(joiner, json!({"op":"poll_protected"})).unwrap(),
            Value::Null
        );
        assert!(
            call(
                admin,
                json!({"op":"adopt_publication","snapshot":saved["snapshot"]})
            )
            .is_err()
        );
        let snapshot: Vec<u8> = serde_json::from_value(staged_network["snapshot"].clone()).unwrap();
        assert!(
            execute_stored(
                admin,
                br#"{"op":"adopt_publication","op":"adopt_publication"}"#,
                &snapshot
            )
            .is_err()
        );
        let mut damaged = snapshot.clone();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(execute_stored(admin, br#"{"op":"adopt_publication"}"#, &damaged).is_err());
        assert_eq!(
            call(joiner, json!({"op":"poll_protected"})).unwrap(),
            Value::Null
        );
        assert!(
            execute_stored(
                admin,
                br#"{"op":"adopt_publication","snapshot":[]}"#,
                &snapshot
            )
            .is_err()
        );
        assert!(execute_stored(admin, br#"{"op":"endpoint_info"}"#, &snapshot).is_err());
        assert!(
            execute_stored(
                admin,
                br#"{"op":"adopt_publication"}"#,
                &vec![0; MAX_STORED_SNAPSHOT + 1]
            )
            .is_err()
        );
        let sent = execute_stored(admin, br#"{"op":"adopt_publication"}"#, &snapshot).unwrap();
        assert!(sent[1].is_empty());
        let sent: Value = serde_json::from_slice(&sent[0]).unwrap();
        assert!(sent["admission"]["admitted"].as_array().unwrap().is_empty());
        assert_eq!(sent["admission"]["queued"], true);
        assert!(sent["admission"]["failed"].as_array().unwrap().is_empty());
        assert!(sent.get("ciphertext").is_none());
        // Changing only the asserted publisher order invalidates real MLS
        // authentication. The original live packet must remain decryptable.
        let (mut tampered_context, ciphertext) = {
            let shared = session(admin).unwrap();
            let guard = shared.lock().unwrap();
            let log = guard.as_ref().unwrap().delivery.publisher.as_ref().unwrap();
            let retained = log
                .select(
                    0,
                    1,
                    &BTreeSet::from([Topic::new("streams/sample").unwrap()]),
                )
                .unwrap();
            let record = retained.records()[0];
            assert_eq!(record.context.sequence.unwrap().get(), record.sequence);
            (record.context.clone(), record.ciphertext.clone())
        };
        tampered_context.sequence = std::num::NonZeroU64::new(2);
        {
            let shared = session(joiner).unwrap();
            let guard = shared.lock().unwrap();
            let owner = guard.as_ref().unwrap().workspace.as_ref().unwrap();
            assert!(
                owner
                    .unprotect_object(
                        b"streams",
                        &tampered_context.authenticated_bytes(),
                        &ciphertext
                    )
                    .is_err()
            );
        }
        // The raw MLS application ops are gone; objects are the only path.
        for op in ["stage_publication", "stage_reception", "enable_object_delivery"] {
            assert!(call(joiner, json!({"op":op})).is_err());
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        let network_received = loop {
            let received = call(joiner, json!({"op":"poll_protected"})).unwrap();
            if !received.is_null() {
                break received;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        };
        assert!(network_received.get("payload").is_none());
        assert_eq!(network_received["state"], "awaiting_reception_save");
        call(
            joiner,
            json!({"op":"adopt_reception","snapshot":network_received["snapshot"]}),
        )
        .unwrap();
        let delivered_network = take_pending(joiner);
        assert_eq!(delivered_network["payload"], json!([0, 255, 77]));
        assert_eq!(delivered_network["sequence"], 1);
        assert_eq!(delivered_network["id"], json!(vec![10; 16]));
        assert_eq!(delivered_network["member"], created["member"]["id"]);
        assert_eq!(delivered_network["topic"], "streams/sample");
        assert!(call(joiner, json!({"op":"poll"})).is_err());
        call(admin, json!({"op":"subscribe","workspace":created["workspace"],"revision":17,"topic":"streams/sample"})).unwrap();
        let reverse = call(joiner, json!({"op":"stage_network_publication","revision":17,"topic":"streams/sample","id":vec![11;16],"payload":[9]})).unwrap();
        let sent = call(
            joiner,
            json!({"op":"adopt_publication","snapshot":reverse["snapshot"]}),
        )
        .unwrap();
        assert_eq!(sent["admission"]["admitted"].as_array().unwrap().len(), 1);
        assert_eq!(sent["admission"]["queued"], true);
        assert!(sent["admission"]["failed"].as_array().unwrap().is_empty());
        assert_eq!(
            call(joiner, json!({"op":"poll_protected"})).unwrap(),
            Value::Null
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        let incoming = loop {
            let incoming = call(admin, json!({"op":"poll_protected"})).unwrap();
            if !incoming.is_null() {
                break incoming;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        };
        call(
            admin,
            json!({"op":"adopt_reception","snapshot":incoming["snapshot"]}),
        )
        .unwrap();
        let reverse_delivered = take_pending(admin);
        assert_eq!(reverse_delivered["payload"], json!([9]));
        assert_eq!(reverse_delivered["member"], pending["member"]["id"]);
        assert!(call(admin, json!({"op":"publish","workspace":created["workspace"],"revision":1,"topic":"sample","payload":[1]})).is_err());
        assert!(call(joiner, json!({"op":"poll"})).is_err());
        assert!(
            call(
                joiner,
                json!({"op":"adopt_reception","snapshot":staged_join["snapshot"]})
            )
            .is_err()
        );
        let [_, received] = execute_stored(joiner, br#"{"op":"seal_workspace"}"#, &[]).unwrap();
        close(joiner).unwrap();
        let joiner = create(Some(&[42; 32])).unwrap();
        execute_stored(
            joiner,
            &serde_json::to_vec(
                &json!({"op":"restore_workspace","workspace":created["workspace"]}),
            )
            .unwrap(),
            &received,
        )
        .unwrap();
        // The acknowledged object stays acknowledged after restore.
        assert!(call(joiner, json!({"op":"poll_pending_object"})).unwrap().is_null());
        // Simulate process ownership loss after candidate persistence but before
        // adoption. No filesystem/power-loss claim: the record is held in RAM.
        let request = serde_json::to_vec(&json!({"op":"stage_network_publication","revision":17,"topic":"streams/sample","id":vec![12;16],"payload":[7]})).unwrap();
        let candidate = execute_stored(admin, &request, &[]).unwrap();
        assert!(candidate[1].starts_with(b"DFWB\x01"));
        let (head, retained) = {
            let shared = session(admin).unwrap();
            let guard = shared.lock().unwrap();
            let session = guard.as_ref().unwrap();
            assert_eq!(session.delivery.publisher.as_ref().unwrap().head(), 1);
            let log = session
                .transition.staged
                .as_ref()
                .unwrap()
                .publisher
                .as_ref()
                .unwrap();
            assert_eq!(log.head(), 2);
            let range = log
                .select(
                    1,
                    2,
                    &BTreeSet::from([Topic::new("streams/sample").unwrap()]),
                )
                .unwrap();
            (log.head(), range.records()[0].ciphertext.clone())
        };
        close(admin).unwrap();
        admin = create(Some(&[41; 32])).unwrap();
        let restore =
            serde_json::to_vec(&json!({"op":"restore_workspace","workspace":created["workspace"]}))
                .unwrap();
        let mut corrupt = candidate[1].clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(execute_stored(admin, &restore, &corrupt).is_err());
        execute_stored(admin, &restore, &candidate[1]).unwrap();
        {
            let shared = session(admin).unwrap();
            let guard = shared.lock().unwrap();
            let log = guard.as_ref().unwrap().delivery.publisher.as_ref().unwrap();
            assert_eq!(log.head(), head);
            let range = log
                .select(
                    1,
                    2,
                    &BTreeSet::from([Topic::new("streams/sample").unwrap()]),
                )
                .unwrap();
            assert_eq!(range.records()[0].ciphertext, retained);
        }
        let next = execute_stored(admin, &serde_json::to_vec(&json!({"op":"stage_network_publication","revision":17,"topic":"streams/sample","id":vec![13;16],"payload":[7]})).unwrap(), &[]).unwrap();
        assert_ne!(candidate[1], next[1]);
        {
            let shared = session(admin).unwrap();
            let guard = shared.lock().unwrap();
            let log = guard
                .as_ref()
                .unwrap()
                .transition.staged
                .as_ref()
                .unwrap()
                .publisher
                .as_ref()
                .unwrap();
            assert_eq!(log.head(), 3);
            let range = log
                .select(
                    2,
                    3,
                    &BTreeSet::from([Topic::new("streams/sample").unwrap()]),
                )
                .unwrap();
            assert_ne!(range.records()[0].ciphertext, retained);
            let range = log
                .select(
                    1,
                    3,
                    &BTreeSet::from([Topic::new("streams/sample").unwrap()]),
                )
                .unwrap();
            let packets: Vec<_> = range.records().iter().map(|r| (*r).clone()).collect();
            drop(guard);
            let shared = session(joiner).unwrap();
            let guard = shared.lock().unwrap();
            // The committed workspace is never edited in place; read on a copy.
            let reader = guard
                .as_ref()
                .unwrap()
                .workspace
                .as_ref()
                .unwrap()
                .provisional_copy()
                .unwrap();
            for packet in packets {
                let context = packet.context.authenticated_bytes();
                // Objects carry no ratchet: decryption is repeatable and
                // side-effect free; the inbox suppresses replays.
                for _ in 0..2 {
                    assert_eq!(
                        reader
                            .unprotect_object(b"streams", &context, &packet.ciphertext)
                            .unwrap()
                            .message
                            .payload,
                        [7]
                    );
                }
            }
        }
        // Admission polling remains available while another candidate is
        // staged so a retry can retrieve an already accepted result.
        assert!(call(admin, json!({"op":"poll_admission"})).is_ok());
        execute_stored(admin, br#"{"op":"adopt_publication"}"#, &next[1]).unwrap();
        call(
            admin,
            json!({"op":"install_member_policy","revision":17,"topics":["streams/sample"]}),
        )
        .unwrap();
        // Exercise actual control dispatch and the node's installed policy.
        let (peer, address, query) = {
            let shared = session(admin).unwrap();
            let guard = shared.lock().unwrap();
            let owner = guard.as_ref().unwrap();
            let workspace = owner.workspace.as_ref().unwrap();
            (
                owner.node.id(),
                std::net::SocketAddr::from(([127, 0, 0, 1], owner.node.address().port())),
                arachne_delivery::RangeQuery {
                    workspace: workspace.id(),
                    author: workspace.member().unwrap().id(),
                    epoch: workspace.epoch(),
                    policy_revision: 17,
                    after: 1,
                    through: 2,
                    topics: BTreeSet::from([Topic::new("streams/sample").unwrap()]),
                },
            )
        };
        // Restoration does not invent authorization. Before the host installs
        // its accepted routing projection, discovery must fail locally.
        assert_eq!(
            call(
                joiner,
                json!({"op":"discover_recovery_cutoff", "peer":peer,
            "revision":17, "topics":["streams/sample"]})
            )
            .unwrap_err(),
            "UnknownWorkspace"
        );
        assert_eq!(
            call(admin, json!({"op":"poll_admission"})).unwrap(),
            Value::Null
        );
        call(
            joiner,
            json!({"op":"install_member_policy", "revision":17,
            "topics":["streams/sample"]}),
        )
        .unwrap();
        let poll_recovery = || {
            let deadline = std::time::Instant::now() + Duration::from_secs(4);
            loop {
                let result = call(admin, json!({"op":"poll_admission"})).unwrap();
                if result != Value::Null {
                    assert_eq!(result["state"], "recovery_replied");
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "recovery dispatch deadline"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        let poll_result = |handle, operation: &str| {
            let deadline = std::time::Instant::now() + Duration::from_secs(4);
            loop {
                let result = call(handle, json!({"op":operation}));
                if !matches!(&result, Ok(Value::Null)) {
                    break result;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "cutoff completion deadline"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        let poll_cutoff = |handle| poll_result(handle, "poll_recovery_cutoff");
        let poll_range = |handle| poll_result(handle, "poll_recovery_range");
        let exchange = |encoded_query: Vec<u8>| {
            let worker = std::thread::spawn(move || {
                let shared = session(joiner).unwrap();
                let guard = shared.lock().unwrap();
                let owner = guard.as_ref().unwrap();
                owner.runtime.block_on(async {
                    owner.node.add_address_hint(peer, address).await.unwrap();
                    owner
                        .node
                        .request_control(peer, &encoded_query)
                        .await
                        .unwrap()
                })
            });
            poll_recovery();
            worker.join().unwrap()
        };
        let cutoff = arachne_delivery::wire::CutoffQuery {
            workspace: query.workspace,
            author: query.author,
            epoch: query.epoch,
            policy_revision: query.policy_revision,
            topics: query.topics.clone(),
            nonce: [61; 32],
        };
        let cutoff_reply = exchange(cutoff.to_wire().unwrap());
        let discover_request = json!({"op":"discover_recovery_cutoff", "peer":peer,
            "revision":17, "topics":["streams/sample"]});
        // Normal receiver operation owns its nonce and verifies the response.
        let pending = call(joiner, discover_request.clone()).unwrap();
        assert_eq!(pending["state"], "recovery_cutoff_pending");
        assert!(call(joiner, discover_request.clone()).is_err());
        poll_recovery();
        let observed = poll_cutoff(joiner).unwrap();
        assert_eq!(
            call(joiner, json!({"op":"poll_recovery_cutoff"})).unwrap(),
            Value::Null
        );
        assert_eq!(observed["state"], "recovery_cutoff_observed");
        assert_eq!(observed["head"], 3);
        assert_eq!(observed["author"], created["member"]["id"]);
        assert_eq!(observed["accepted_through"], 0);
        assert_eq!(observed["accepted_progress"], false);
        assert!(observed.get("snapshot").is_none() && observed.get("nonce").is_none());
        // Start both peers before servicing either, as serialized Kotlin workers
        // will do. Both starts must return so their existing pollers can run.
        let (joiner_peer, joiner_address) = {
            let shared = session(joiner).unwrap();
            let guard = shared.lock().unwrap();
            let owner = guard.as_ref().unwrap();
            (
                owner.node.id(),
                std::net::SocketAddr::from(([127, 0, 0, 1], owner.node.address().port())),
            )
        };
        call(
            admin,
            json!({"op":"add_address_hint", "peer":joiner_peer,
            "address":joiner_address.to_string()}),
        )
        .unwrap();
        let reverse_request = json!({"op":"discover_recovery_cutoff", "peer":joiner_peer,
            "revision":17, "topics":["streams/sample"]});
        assert_eq!(
            call(joiner, discover_request.clone()).unwrap()["state"],
            "recovery_cutoff_pending"
        );
        assert_eq!(
            call(admin, reverse_request.clone()).unwrap()["state"],
            "recovery_cutoff_pending"
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        let mut completed = BTreeMap::new();
        while completed.len() < 2 {
            for handle in [admin, joiner] {
                call(handle, json!({"op":"poll_admission"})).unwrap();
                let result = call(handle, json!({"op":"poll_recovery_cutoff"})).unwrap();
                if result != Value::Null {
                    assert_eq!(result["state"], "recovery_cutoff_observed");
                    assert!(completed.insert(handle, result).is_none());
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "crossed cutoff deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(completed[&admin]["head"], 1);
        assert_eq!(completed[&joiner]["head"], 3);
        for invalid in [
            json!({"op":"discover_recovery_cutoff", "peer":vec![99;32], "revision":17, "topics":["streams/sample"]}),
            json!({"op":"discover_recovery_cutoff", "peer":peer, "revision":16, "topics":["streams/sample"]}),
            json!({"op":"discover_recovery_cutoff", "peer":peer, "revision":17, "topics":["streams/other"]}),
            json!({"op":"discover_recovery_cutoff", "peer":peer, "revision":17, "topics":["streams/sample","streams/sample"]}),
            json!({"op":"discover_recovery_cutoff", "peer":peer, "revision":17, "topics":[]}),
            json!({"op":"discover_recovery_cutoff", "peer":peer, "revision":17, "topics":["streams/sample"], "nonce":vec![1;32]}),
        ] {
            assert!(call(joiner, invalid).is_err());
        }
        assert_eq!(
            call(admin, json!({"op":"poll_admission"})).unwrap(),
            Value::Null
        );

        {
            let shared = session(joiner).unwrap();
            let guard = shared.lock().unwrap();
            let reader = guard.as_ref().unwrap().workspace.as_ref().unwrap();
            assert_eq!(
                arachne_delivery::wire::verify_cutoff_reply(reader, &cutoff, &cutoff_reply)
                    .unwrap(),
                Some(3)
            );
            let mut next_request = cutoff.clone();
            next_request.nonce[0] ^= 1;
            assert!(
                arachne_delivery::wire::verify_cutoff_reply(reader, &next_request, &cutoff_reply)
                    .is_err()
            );
        }
        assert_eq!(
            exchange(b"DFCQ\x02".to_vec()),
            arachne_delivery::wire::denied_reply()
        );
        let reply = exchange(query.to_wire().unwrap());
        {
            let shared = session(joiner).unwrap();
            let guard = shared.lock().unwrap();
            let reader = guard.as_ref().unwrap().workspace.as_ref().unwrap();
            let arachne_delivery::wire::RangeReply::Offered(range) =
                arachne_delivery::wire::verify_reply(reader, &query, &reply).unwrap()
            else {
                panic!("expected wire recovery offer")
            };
            assert_eq!(range.packets().len(), 1);
            assert_eq!(range.packets()[0].ciphertext, retained);
            assert_eq!(range.packets()[0].context.id, [12; 16]);
        }
        let fetch_request = json!({"op":"fetch_recovery_range", "peer":peer, "revision":17,
            "topics":["streams/sample"], "after":1, "through":2});
        assert_eq!(
            call(joiner, fetch_request.clone()).unwrap()["state"],
            "recovery_range_pending"
        );
        assert!(call(joiner, fetch_request.clone()).is_err());
        assert!(call(joiner, discover_request.clone()).is_err());
        poll_recovery();
        let ready = poll_range(joiner).unwrap();
        assert_eq!(ready["state"], "recovery_range_ready");
        assert_eq!(ready["packet_count"], 1);
        assert_eq!(ready["accepted_progress"], false);
        assert!(ready.get("payload").is_none() && ready.get("snapshot").is_none());
        {
            let shared = session(joiner).unwrap();
            let guard = shared.lock().unwrap();
            let owner = guard.as_ref().unwrap();
            let ready = owner.recovery.ready_range.as_ref().unwrap();
            let arachne_delivery::wire::RangeReply::Offered(range) =
                arachne_delivery::wire::verify_reply(
                    owner.workspace.as_ref().unwrap(),
                    &ready.query,
                    &ready.reply,
                )
                .unwrap()
            else {
                panic!("expected retained verified range")
            };
            assert_eq!(range.packets()[0].ciphertext, retained);
            assert_eq!(range.packets()[0].context.id, [12; 16]);
        }
        assert_eq!(
            call(joiner, json!({"op":"poll_recovery_range"})).unwrap(),
            Value::Null
        );
        assert!(call(joiner, fetch_request.clone()).is_err());
        call(joiner, json!({"op":"cancel_recovery_range"})).unwrap();
        for invalid in [
            json!({"op":"fetch_recovery_range", "peer":peer, "revision":17,"topics":["streams/sample"],"after":2,"through":2}),
            json!({"op":"fetch_recovery_range", "peer":peer, "revision":16,"topics":["streams/sample"],"after":1,"through":2}),
            json!({"op":"fetch_recovery_range", "peer":vec![99;32], "revision":17,"topics":["streams/sample"],"after":1,"through":2}),
            json!({"op":"fetch_recovery_range", "peer":peer, "revision":17,"topics":["streams/sample","streams/sample"],"after":1,"through":2}),
        ] {
            assert!(call(joiner, invalid).is_err());
        }
        assert_eq!(
            call(admin, json!({"op":"poll_admission"})).unwrap(),
            Value::Null
        );
        let mut stale = arachne_delivery::RangeQuery::from_wire(&query.to_wire().unwrap()).unwrap();
        stale.policy_revision = 16;
        assert_eq!(
            exchange(stale.to_wire().unwrap()),
            arachne_delivery::wire::denied_reply()
        );
        assert_eq!(
            exchange(b"DFRQ\x02".to_vec()),
            arachne_delivery::wire::denied_reply()
        );
        call(
            admin,
            json!({"op":"install_member_policy","revision":18,"topics":["streams/other"]}),
        )
        .unwrap();
        assert_eq!(
            exchange(query.to_wire().unwrap()),
            arachne_delivery::wire::denied_reply()
        );
        assert_eq!(
            exchange(cutoff.to_wire().unwrap()),
            arachne_delivery::wire::denied_reply()
        );
        let mut revoked_cutoff = cutoff.clone();
        revoked_cutoff.policy_revision = 18;
        assert_eq!(
            exchange(revoked_cutoff.to_wire().unwrap()),
            arachne_delivery::wire::denied_reply()
        );
        call(joiner, fetch_request.clone()).unwrap();
        poll_recovery();
        let rejected = poll_range(joiner).unwrap();
        assert_eq!(rejected["state"], "recovery_range_rejected");
        assert_eq!(rejected["reason"], "Denied");
        assert!(
            session(joiner)
                .unwrap()
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .recovery.ready_range
                .is_none()
        );
        // Receiver still has revision 17; current publisher policy denies it.
        call(joiner, discover_request.clone()).unwrap();
        poll_recovery();
        let denied = poll_cutoff(joiner).unwrap();
        assert_eq!(denied["state"], "recovery_cutoff_denied");
        assert!(denied.get("head").is_none());
        stale.policy_revision = 18;
        assert_eq!(
            exchange(stale.to_wire().unwrap()),
            arachne_delivery::wire::denied_reply()
        );
        // An authorized topic with no publications in this retained range still
        // receives signed coverage through normal dispatch over real Iroh.
        stale.topics = BTreeSet::from([Topic::new("streams/other").unwrap()]);
        let empty_reply = exchange(stale.to_wire().unwrap());
        {
            let shared = session(joiner).unwrap();
            let guard = shared.lock().unwrap();
            let reader = guard.as_ref().unwrap().workspace.as_ref().unwrap();
            let arachne_delivery::wire::RangeReply::Offered(range) =
                arachne_delivery::wire::verify_reply(reader, &stale, &empty_reply).unwrap()
            else {
                panic!("expected signed empty recovery offer")
            };
            assert!(range.packets().is_empty());
        }
        assert_eq!(
            call(admin, json!({"op":"poll_admission"})).unwrap(),
            Value::Null
        );
        // A response requested under old local authority cannot be exposed after
        // policy advances, even if the remote signature itself remains valid.
        call(joiner, discover_request.clone()).unwrap();
        poll_recovery();
        call(
            joiner,
            json!({"op":"install_member_policy", "revision":18, "topics":["streams/other"]}),
        )
        .unwrap();
        assert!(poll_cutoff(joiner).is_err());
        assert_eq!(
            call(joiner, json!({"op":"poll_recovery_cutoff"})).unwrap(),
            Value::Null
        );
        let empty_request = json!({"op":"fetch_recovery_range", "peer":peer, "revision":18,
            "topics":["streams/other"], "after":1, "through":2});
        call(joiner, empty_request.clone()).unwrap();
        poll_recovery();
        let empty = poll_range(joiner).unwrap();
        assert_eq!(empty["state"], "recovery_range_ready");
        assert_eq!(empty["packet_count"], 0);
        call(joiner, json!({"op":"cancel_recovery_range"})).unwrap();
        call(joiner, empty_request.clone()).unwrap();
        poll_recovery();
        call(
            joiner,
            json!({"op":"install_member_policy", "revision":19, "topics":["streams/other"]}),
        )
        .unwrap();
        assert!(poll_range(joiner).is_err());
        assert!(
            session(joiner)
                .unwrap()
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .recovery.ready_range
                .is_none()
        );
        let mut cancelled_request = empty_request;
        cancelled_request["revision"] = json!(19);
        call(joiner, cancelled_request).unwrap();
        let aborted_range = {
            let shared = session(joiner).unwrap();
            let guard = shared.lock().unwrap();
            guard
                .as_ref()
                .unwrap()
                .recovery.range
                .as_ref()
                .unwrap()
                .task
                .abort_handle()
        };
        call(joiner, json!({"op":"cancel_recovery_range"})).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while !aborted_range.is_finished() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        // Recovery actually decrypts a publication missed by this receiver. The
        // selected topic has no earlier traffic, so prior live ratchet use does
        // not masquerade as successful catch-up of already consumed packets.
        call(
            admin,
            json!({"op":"install_member_policy", "revision":19,
            "topics":["streams/other"]}),
        )
        .unwrap();
        for id in 90..97 {
            let missed = call(
                admin,
                json!({"op":"stage_network_publication", "revision":19,
                "topic":"streams/other", "id":vec![id;16], "payload":[id]}),
            )
            .unwrap();
            call(
                admin,
                json!({"op":"adopt_publication", "snapshot":missed["snapshot"]}),
            )
            .unwrap();
        }
        let head = {
            let shared = session(admin).unwrap();
            let guard = shared.lock().unwrap();
            guard.as_ref().unwrap().delivery.publisher.as_ref().unwrap().head()
        };
        let recover = json!({"op":"fetch_recovery_range", "peer":peer, "revision":19,
            "topics":["streams/other"], "after":0, "through":head});
        call(joiner, recover.clone()).unwrap();
        // A newer live application is queued while the range request is pending.
        // Decrypting it now could discard the keys for the first missed records.
        call(
            joiner,
            json!({"op":"subscribe", "workspace":created["workspace"],
            "revision":19, "topic":"streams/other"}),
        )
        .unwrap();
        let live = call(
            admin,
            json!({"op":"stage_network_publication", "revision":19,
            "topic":"streams/other", "id":vec![107;16], "payload":[8]}),
        )
        .unwrap();
        call(
            admin,
            json!({"op":"adopt_publication", "snapshot":live["snapshot"]}),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let shared = session(joiner).unwrap();
            if !shared.lock().unwrap().as_ref().unwrap().receiver.is_empty() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "newer live packet was not queued"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        poll_recovery();
        assert_eq!(poll_range(joiner).unwrap()["packet_count"], 7);
        let [metadata, recovery_snapshot] =
            execute_stored(joiner, br#"{"op":"stage_recovery_range"}"#, &[]).unwrap();
        let metadata: Value = serde_json::from_slice(&metadata).unwrap();
        assert_eq!(metadata["state"], "awaiting_recovery_save");
        assert_eq!(metadata["publication_count"], 7);
        assert!(metadata.get("payload").is_none() && metadata.get("snapshot").is_none());
        assert!(
            execute_stored(joiner, br#"{"op":"adopt_reception"}"#, &recovery_snapshot).is_err()
        );
        let mut corrupt = recovery_snapshot.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(execute_stored(joiner, br#"{"op":"adopt_recovery"}"#, &corrupt).is_err());
        let adopted =
            execute_stored(joiner, br#"{"op":"adopt_recovery"}"#, &recovery_snapshot).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&adopted[0]).unwrap()["publication_count"],
            7
        );
        // Recovered objects wait in the durable inbox like live ones.
        for id in 90..97 {
            let recovered = take_pending(joiner);
            assert_eq!(recovered["payload"], json!([id]));
            assert_eq!(recovered["id"], json!(vec![id; 16]));
            assert_eq!(recovered["topic"], "streams/other");
        }
        assert!(call(joiner, json!({"op":"poll_pending_object"})).unwrap().is_null());
        assert!(execute_stored(joiner, br#"{"op":"adopt_recovery"}"#, &recovery_snapshot).is_err());
        call(joiner, recover.clone()).unwrap();
        poll_recovery();
        poll_range(joiner).unwrap();
        assert_eq!(
            call(joiner, json!({"op":"stage_recovery_range"})).unwrap()["state"],
            "recovery_no_new_objects"
        );
        // Ordinary outgoing traffic must preserve the newly adopted receive state.
        let outgoing = call(
            joiner,
            json!({"op":"stage_network_publication", "revision":19,
            "topic":"streams/other", "id":vec![91;16], "payload":[7]}),
        )
        .unwrap();
        call(
            joiner,
            json!({"op":"adopt_publication", "snapshot":outgoing["snapshot"]}),
        )
        .unwrap();
        let live = poll_result(joiner, "poll_protected").unwrap();
        assert!(live.get("payload").is_none());
        call(
            joiner,
            json!({"op":"adopt_reception", "snapshot":live["snapshot"]}),
        )
        .unwrap();
        assert_eq!(take_pending(joiner)["payload"], json!([8]));
        // The live object was already received: recovery finds nothing new.
        let mut continuation = recover;
        continuation["after"] = json!(head);
        continuation["through"] = json!(head + 1);
        call(joiner, continuation).unwrap();
        poll_recovery();
        poll_range(joiner).unwrap();
        assert_eq!(
            call(joiner, json!({"op":"stage_recovery_range"})).unwrap()["state"],
            "recovery_no_new_objects"
        );
        let [_, durable] = execute_stored(joiner, br#"{"op":"seal_workspace"}"#, &[]).unwrap();
        let mut pending_on_close = discover_request;
        pending_on_close["revision"] = json!(19);
        pending_on_close["topics"] = json!(["streams/other"]);
        call(joiner, pending_on_close).unwrap();
        let task = {
            let shared = session(joiner).unwrap();
            let guard = shared.lock().unwrap();
            guard
                .as_ref()
                .unwrap()
                .recovery.cutoff
                .as_ref()
                .unwrap()
                .task
                .abort_handle()
        };
        close(joiner).unwrap();
        assert!(task.is_finished());
        let restored = create(Some(&[42; 32])).unwrap();
        execute_stored(
            restored,
            &serde_json::to_vec(&json!({"op":"restore_workspace",
            "workspace":created["workspace"]}))
            .unwrap(),
            &durable,
        )
        .unwrap();
        {
            let shared = session(restored).unwrap();
            let guard = shared.lock().unwrap();
            let session = guard.as_ref().unwrap();
            assert!(session.delivery.publisher.as_ref().unwrap().head() > 0);
            assert_eq!(session.delivery.inbox.as_ref().unwrap().pending_count(), 0);
        }
        assert!(call(restored, json!({"op":"poll_pending_object"})).unwrap().is_null());
        call(
            admin,
            json!({"op":"install_member_policy", "revision":20,"topics":["streams/objects"]}),
        )
        .unwrap();
        let send_object = |number: u8| {
            let staged = call(
                admin,
                json!({"op":"stage_network_publication", "revision":20,
                "topic":"streams/objects", "id":vec![number;16], "payload":[number]}),
            )
            .unwrap();
            call(
                admin,
                json!({"op":"adopt_publication", "snapshot":staged["snapshot"]}),
            )
            .unwrap()
        };
        let current = call(
            admin,
            json!({"op":"stage_network_publication", "revision":20,
                "topic":"streams/objects", "id":vec![100;16], "payload":[100],
                "current":{"selector":vec![7;32], "replacement_key":vec![8;32],
                    "expires_at":u64::MAX}}),
        )
        .unwrap();
        call(
            admin,
            json!({"op":"adopt_publication", "snapshot":current["snapshot"]}),
        )
        .unwrap();
        let missed = send_object(101);
        let after = missed["sequence"].as_u64().unwrap() - 1;
        let connect_objects = |handle| {
            call(
                handle,
                json!({"op":"add_address_hint","peer":peer,"address":address.to_string()}),
            )
            .unwrap();
            call(
                handle,
                json!({"op":"install_member_policy", "revision":20,"topics":["streams/objects"]}),
            )
            .unwrap();
            call(handle, json!({"op":"subscribe", "workspace":created["workspace"],"revision":20,"topic":"streams/objects"})).unwrap();
        };
        connect_objects(restored);
        let live = send_object(102);
        assert_eq!(live["admission"]["queued"], true);
        let staged = poll_result(restored, "poll_protected").unwrap();
        assert!(staged.get("payload").is_none());
        call(
            restored,
            json!({"op":"adopt_reception", "snapshot":staged["snapshot"]}),
        )
        .unwrap();
        let pending = call(restored, json!({"op":"poll_pending_object"})).unwrap();
        assert_eq!(pending["payload"], json!([102]));
        assert_eq!(
            call(restored, json!({"op":"poll_pending_object"})).unwrap(),
            pending
        );
        let [_, pending_snapshot] =
            execute_stored(restored, br#"{"op":"seal_workspace"}"#, &[]).unwrap();
        close(restored).unwrap();
        let restored = create(Some(&[42; 32])).unwrap();
        execute_stored(
            restored,
            &serde_json::to_vec(
                &json!({"op":"restore_workspace","workspace":created["workspace"]}),
            )
            .unwrap(),
            &pending_snapshot,
        )
        .unwrap();
        assert_eq!(
            call(restored, json!({"op":"poll_pending_object"})).unwrap(),
            pending
        );
        let ack =|handle, pending: &Value| {
            let request = json!({"op":"stage_object_acknowledgement", "member":pending["member"],
                "topic":pending["topic"], "id":pending["id"], "counter":pending["counter"]});
            let mut wrong = request.clone();
            wrong["id"] = json!(vec![0; 16]);
            assert!(call(handle, wrong).is_err());
            let staged = call(handle, request).unwrap();
            let snapshot: Vec<u8> = serde_json::from_value(staged["snapshot"].clone()).unwrap();
            assert_eq!(
                execute_stored(handle, br#"{"op":"adopt_publication"}"#, &snapshot).unwrap_err(),
                "wrong adoption lifecycle phase"
            );
            execute_stored(handle, br#"{"op":"adopt_reception"}"#, &snapshot).unwrap();
        };
        ack(restored, &pending);
        assert_eq!(
            call(restored, json!({"op":"poll_pending_object"})).unwrap(),
            Value::Null
        );
        connect_objects(restored);
        let next = call(restored, json!({"op":"next_membership_peer"})).unwrap();
        assert_eq!(next["peer"], json!(peer));
        let authority = next["member"].clone();
        call(
            restored,
            json!({"op":"fetch_current_view", "authority":authority,
                "revision":20, "topic":"streams/objects", "selector":vec![7;32]}),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let ready = loop {
            let response = call(admin, json!({"op":"poll_admission"})).unwrap();
            assert!(response.is_null() || response["state"] == "current_view_replied");
            let response = call(restored, json!({"op":"poll_current_view"})).unwrap();
            if !response.is_null() {
                break response;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "current-view control deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(ready["state"], "current_view_ready");
        assert_eq!(ready["automatic_source"], true);
        assert_eq!(ready["cut"], 1);
        assert_eq!(ready["value_count"], 1);
        let staged = call(restored, json!({"op":"stage_current_view"})).unwrap();
        assert_eq!(staged["state"], "awaiting_current_view_save");
        assert_eq!(staged["pending"], 1);
        assert!(call(restored, json!({"op":"poll_pending_object"})).is_err());
        call(
            restored,
            json!({"op":"adopt_current_view", "snapshot":staged["snapshot"]}),
        )
        .unwrap();
        let current = call(restored, json!({"op":"poll_pending_object"})).unwrap();
        assert_eq!(current["payload"], json!([100]));
        assert_eq!(current["current"]["replacement_key"], json!(vec![8; 32]));
        ack(restored, &current);
        call(
            restored,
            json!({"op":"fetch_recovery_range", "peer":peer, "revision":20,
            "topics":["streams/objects"], "after":after, "through":live["sequence"]}),
        )
        .unwrap();
        poll_recovery();
        poll_range(restored).unwrap();
        let [metadata, snapshot] =
            execute_stored(restored, br#"{"op":"stage_recovery_range"}"#, &[]).unwrap();
        let metadata: Value = serde_json::from_slice(&metadata).unwrap();
        assert_eq!(metadata["publication_count"], 1); // live object already acknowledged
        execute_stored(restored, br#"{"op":"adopt_recovery"}"#, &snapshot).unwrap();
        let recovered = call(restored, json!({"op":"poll_pending_object"})).unwrap();
        assert_eq!(recovered["payload"], json!([101]));
        ack(restored, &recovered);
        let [_, snapshot] = execute_stored(restored, br#"{"op":"seal_workspace"}"#, &[]).unwrap();
        close(restored).unwrap();
        let restored = create(Some(&[42; 32])).unwrap();
        execute_stored(
            restored,
            &serde_json::to_vec(
                &json!({"op":"restore_workspace","workspace":created["workspace"]}),
            )
            .unwrap(),
            &snapshot,
        )
        .unwrap();
        assert_eq!(
            call(restored, json!({"op":"poll_pending_object"})).unwrap(),
            Value::Null
        );
        connect_objects(restored);
        call(
            restored,
            json!({"op":"fetch_recovery_range", "peer":peer,"revision":20,
            "topics":["streams/objects"],"after":after,"through":live["sequence"]}),
        )
        .unwrap();
        poll_recovery();
        poll_range(restored).unwrap();
        assert_eq!(
            call(restored, json!({"op":"stage_recovery_range"})).unwrap()["state"],
            "recovery_no_new_objects"
        );
        let current_live = call(
            admin,
            json!({"op":"stage_network_publication", "revision":20,
                "topic":"streams/objects", "id":vec![109;16], "payload":[109],
                "current":{"selector":vec![7;32], "replacement_key":vec![8;32],
                    "expires_at":u64::MAX}}),
        )
        .unwrap();
        call(
            admin,
            json!({"op":"adopt_publication", "snapshot":current_live["snapshot"]}),
        )
        .unwrap();
        let staged = poll_result(restored, "poll_protected").unwrap();
        call(
            restored,
            json!({"op":"adopt_reception", "snapshot":staged["snapshot"]}),
        )
        .unwrap();
        let current_pending = call(restored, json!({"op":"poll_pending_object"})).unwrap();
        assert_eq!(current_pending["payload"], json!([109]));
        assert_eq!(current_pending["current"]["selector"], json!(vec![7; 32]));
        assert_eq!(
            current_pending["current"]["replacement_key"],
            json!(vec![8; 32])
        );
        ack(restored, &current_pending);
        for number in 110..150 {
            send_object(number);
        }
        call(restored, json!({"op":"discover_recovery_cutoff", "peer":peer,"revision":20,"topics":["streams/objects"]})).unwrap();
        poll_recovery();
        let window = poll_cutoff(restored).unwrap();
        assert!(window["retained_after"].as_u64().unwrap() > after);
        assert_eq!(window["accepted_through"], 0);
        call(restored, json!({"op":"fetch_recovery_range", "peer":peer,"revision":20,
            "topics":["streams/objects"],"after":window["retained_after"],"through":window["head"]})).unwrap();
        poll_recovery();
        poll_range(restored).unwrap();
        let [metadata, snapshot] =
            execute_stored(restored, br#"{"op":"stage_recovery_range"}"#, &[]).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&metadata).unwrap()["publication_count"],
            32
        );
        execute_stored(restored, br#"{"op":"adopt_recovery"}"#, &snapshot).unwrap();
        let service = create(Some(&[43; 32])).unwrap();
        // Registering the link is itself a membership step the restored
        // member must accept before the service's Add.
        let staged_link = call(
            admin,
            json!({"op":"stage_invitation","personal":false,"expires_at":0}),
        )
        .unwrap();
        let registration = call(
            admin,
            json!({"op":"adopt_admission","snapshot":staged_link["snapshot"]}),
        )
        .unwrap();
        let invite = registration["issued_invitation"].clone();
        let pending_service = call(
            service,
            json!({"op":"begin_join", "invitation":invite["invitation"],
            "checkpoint":invite["checkpoint"], "display_name":"Air traffic feed"}),
        )
        .unwrap();
        let admission = json!({"op":"stage_admission", "authenticated_endpoint":pending_service["endpoint"],
            "request":pending_service["admission_request"]});
        let [_, saved] =
            execute_stored(admin, &serde_json::to_vec(&admission).unwrap(), &[]).unwrap();
        execute_stored(admin, br#"{"op":"adopt_admission"}"#, &saved).unwrap();
        let response = call(
            admin,
            json!({"op":"retained_admission", "authenticated_endpoint":pending_service["endpoint"],
            "request":pending_service["admission_request"]}),
        )
        .unwrap();
        let step = json!({"commit":response["commit"], "authorization":response["authorization"]});
        let fetch = || {
            call(
                restored,
                json!({"op":"fetch_membership_update", "peer":peer}),
            )
            .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                call(admin, json!({"op":"poll_admission"})).unwrap();
                let result = call(restored, json!({"op":"poll_membership_update"})).unwrap();
                if result != Value::Null {
                    break result;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "membership query deadline"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        let fetched = fetch();
        assert_eq!(fetched["state"], "membership_update_available");
        assert_eq!(fetched["step"]["step"], registration["step"]["step"]);
        assert!(fetched.get("welcome").is_none());
        drop(admission);
        let pending_count = || {
            session(restored)
                .unwrap()
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .delivery.inbox
                .as_ref()
                .unwrap()
                .pending_count()
        };
        // 32 recovered objects are still pending: neither the registration
        // step nor the Add is delayed, and each candidate carries them (A3).
        assert_eq!(pending_count(), 32);
        let registered = json!({"op":"stage_admission_update", "step":fetched["step"]});
        let [_, saved] =
            execute_stored(restored, &serde_json::to_vec(&registered).unwrap(), &[]).unwrap();
        execute_stored(restored, br#"{"op":"adopt_admission"}"#, &saved).unwrap();
        assert_eq!(pending_count(), 32);
        let fetched = fetch();
        assert_eq!(fetched["state"], "membership_update_available");
        assert_eq!(fetched["step"], step);
        assert!(fetched.get("welcome").is_none());
        let update = json!({"op":"stage_admission_update", "step":fetched["step"]});
        assert_eq!(pending_count(), 32);
        let [_, saved] =
            execute_stored(restored, &serde_json::to_vec(&update).unwrap(), &[]).unwrap();
        let mut altered = saved.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(execute_stored(restored, br#"{"op":"adopt_admission"}"#, &altered).is_err());
        assert!(execute_stored(restored, br#"{"op":"adopt_reception"}"#, &saved).is_err());
        close(restored).unwrap(); // Saved candidate survives before explicit adoption.
        let restored = create(Some(&[42; 32])).unwrap();
        let [metadata, _] = execute_stored(
            restored,
            &serde_json::to_vec(
                &json!({"op":"restore_workspace", "workspace":created["workspace"]}),
            )
            .unwrap(),
            &saved,
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&metadata).unwrap()["members"],
            3
        );
        for number in 118..150 {
            let pending = call(restored, json!({"op":"poll_pending_object"})).unwrap();
            assert_eq!(pending["payload"], json!([number]));
            ack(restored, &pending);
        }
        println!(
            "NATIVE_OBJECT_INBOX live_pending_restart=true acknowledgement_restart=true missed_recovery=true pending_carried_across_epoch=true adapter_callback=not_exercised"
        );
        assert!(call(restored, update).is_err()); // replay
        let [_, saved] = execute_stored(
            service,
            &serde_json::to_vec(
                &json!({"op":"stage_join", "commits":[step], "welcome":response["welcome"]}),
            )
            .unwrap(),
            &[],
        )
        .unwrap();
        let [metadata, _] = execute_stored(service, br#"{"op":"adopt_join"}"#, &saved).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&metadata).unwrap()["members"],
            3
        );
        close(service).unwrap();
        close(restored).unwrap();
        close(admin).unwrap();
    }
}
