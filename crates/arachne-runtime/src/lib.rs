//! Portable blocking Arachne session runtime shared by native clients and language bindings.
//! No membership API is implied by creating an authenticated transport endpoint.
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{
        Arc, Mutex,
    },
    time::Duration,
};

use arachne_node::{
    AdmissionReport, Node, Topic,
};
use serde_json::{Value, json};

mod client;
mod committed_view;
mod context;
mod deadline;
mod errors;
mod events;
mod json;
mod ops;
mod registry;
mod session;
pub use registry::{
    cancel, close, create, create_lan, create_nearby, create_relay, create_relay_with_options,
    create_wan, create_wan_only, create_with_options, describe, wait_for_work,
    create_with_deadline, next_event, resume, set_deadline, suspend, wait_for_work_timeout,
    wake,
};
#[cfg(feature = "tor")]
pub use registry::create_tor;
use registry::{session, shutdown_session};
use ops::admission::{
    ADMISSION_HISTORY_PAGE_REQUEST, admission_packet, admission_reply_page,
    parse_admission_history_page_packet, pinned_checkpoint,
};
use ops::join::{
    INVITATION_CHECKPOINT_REQUEST, JoinLifecycle,
    invitation_checkpoint_page, pending_metadata,
};
pub(crate) use session::{
    MembershipState, PendingAdmissionApproval, PendingControl, QueuedAdmission, Session,
    StagedWorkspace, TransportSummary, WorkspaceTransition,
};
use session::{
    carry_delivery, check_epoch_transition, commit_workspace, seal_state,
    transition_activity,
};
mod interest;
mod membership;

/// Wire-format helpers exposed ONLY for the capacity harness
/// (`tests/invitation_link_capacity.rs`). Not a stable API and not a
/// permission grant: these encode/decode DFMQ frames; all authorization
/// still happens at the receiving member.
#[doc(hidden)]
pub mod harness {
    pub use crate::membership::StateBasis;
    pub use crate::membership::wire::{Query, decode_reply, encode_query};
    pub use crate::presence::harness_presence_packet;

    /// The session workspace's gossip tag key, so a qualification harness can
    /// join raw nodes to the same overlay. The host already holds this state.
    pub fn gossip_tag_key(handle: i64) -> Result<[u8; 32], String> {
        let shared = crate::session(handle).map_err(crate::errors::text)?;
        let guard = shared.lock().map_err(|_| "node session unavailable")?;
        guard
            .as_ref()
            .ok_or("node is closed")?
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?
            .gossip_tag_key()
            .map_err(str::to_owned)
    }
}
mod admission_waiters;
mod persistence;
pub(crate) mod presence;
mod resources;
mod work_signal;
mod workspace_activity;
pub use arachne_api::{ApiError, ErrorCode, Event, Limits, PowerProfile};
pub use context::{Context, ContextConfig, RuntimeConfig};
pub use client::{
    AdmissionApproval, AdmissionApprovalPage, AdmissionAuthorization, InvitationCheckpoint,
    InvitationControl, InvitationKind, MemberAction, NearbyAdvertisement, NearbyEndpoint,
    NearbyMode, NearbyScan, PresenceRound, RemovedMembership, AdmissionReply, Client, ClientConfig, ConnectivityReport,
    ConnectionCapacityMetrics, ControlTimingMetrics, DeliveryFailure, DeliveryReport,
    DurationSummary, EndpointInfo, Error, ErrorKind, InterestObservation, InvitationDetails,
    InvitationInfo, JoinAdmissionStep, JoinRequest, MemberInfo, MemberKind,
    MembershipGossipMetrics, MemberRoster, Network, PeerPolicy, PeerRoute, Presence, Publication,
    PublicationCandidate, PublicationCurrent, ProtectedReceptionCandidate,
    ReceivedProtectedPublication, RecoveryAdoption, RecoveryCandidate, RecoveryRangeReady,
    RecoveryRangeRequest, RecoveryRangeStatus, RecoveryStage, Result as ClientResult, RouteHint,
    RouteKind, WorkspaceCandidate, WorkspaceInfo, WorkspaceMetrics, WorkspaceState,
};
pub use client::{OperatorRelay, RelayTrust, TransportInfo, TransportOptions, TransportTimeouts};
pub use arachne_store::FreshnessAnchor;
pub use persistence::{
    enable_record_storage, record_freshness, restore_record_storage,
    restore_record_storage_with_freshness, save_candidate,
};
pub use workspace_activity::{Activity as WorkspaceActivity, Phase as WorkspacePhase};
pub use errors::legacy_text;
pub use json::{
    MAX_REQUEST, MAX_STORED_SNAPSHOT, execute, execute_stored, execute_stored_with_code,
    execute_with_code, inspect_invitation,
};


const MAX_WORKSPACE_OVERLAY_PATHS: usize = 5;
// JSON commit/authorization arrays must fit both the 32 KiB membership offer
// request and the 128 KiB admission reply. The lower MLS seam supports 128;
// this transport adapter deliberately uses the smaller safe batch.
const MAX_RUNTIME_ADMISSION_BATCH: usize = 16;
// Half of the 512 control-exchange reserve (arachne-node budget.rs). Presence,
// profile and recovery exchanges always keep the other half.
pub(crate) const MAX_ADMISSION_WAITERS: usize = 256;

/// Stable host-facing vocabulary for the admission lifecycle.
pub mod admission_state {
    pub const QUEUED: &str = "admission_queued";
    pub const APPROVAL_PENDING: &str = "approval_pending";
    pub const APPROVAL_REQUESTED: &str = "approval_requested";
    pub const REPLIED: &str = "admission_replied";
    pub const UNAVAILABLE: &str = "admission_unavailable";
    pub const RECOVERY_REQUIRED: &str = "admission_recovery_required";
    pub const MEMBER_ALREADY_ADMITTED: &str = "member_already_admitted";
    pub const RECOVERY_REMOVE_AND_REINVITE: &str = "remove_and_reinvite";
    pub const NOT_SENT: &str = "admission_not_sent";
    /// The request was sent and the exchange ended with no reply. Ask again at
    /// once: the result may already be retained.
    pub const WAITING: &str = "admission_waiting";
}



fn report(value: AdmissionReport) -> DeliveryReport {
    DeliveryReport {
        admitted: value.admitted,
        queued: value.queued,
        failed: value
            .failed
            .into_iter()
            .map(|(peer, error)| DeliveryFailure {
                peer,
                error: error.to_string(),
            })
            .collect(),
    }
}

/// `report` as a JSON value, for replies that are still JSON.
fn report_value(value: AdmissionReport) -> Value {
    serde_json::to_value(report(value)).unwrap_or(Value::Null)
}

#[cfg(test)]
mod large_invitation_tests;

