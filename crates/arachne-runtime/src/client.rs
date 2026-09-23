use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    WorkspacePhase, cancel, close, create, create_lan, create_nearby, create_relay, create_wan,
    create_wan_only, describe, enable_record_storage as enable_runtime_record_storage, execute,
    execute_stored, restore_record_storage as restore_runtime_record_storage,
    save_candidate as save_runtime_candidate, wait_for_work,
};
#[cfg(feature = "tor")]
use crate::create_tor;

/// Address discovery and transport selection for a typed runtime client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Network {
    Direct,
    Lan,
    Nearby,
    Wan,
    RelayOnly,
    WanOnly,
    #[cfg(feature = "tor")]
    Tor,
}

/// Configuration for one workspace-facing runtime client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientConfig {
    pub network: Network,
    pub secret: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Closed,
    InvalidInput,
    Capacity,
    Storage,
    Transport,
    Cancelled,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct EndpointInfo {
    pub endpoint_key: [u8; 32],
    pub bound_address: String,
    pub workspace_ready: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceState {
    pub endpoint_key: [u8; 32],
    pub workspace: Option<[u8; 32]>,
    pub workspace_ready: bool,
    pub durable: bool,
    pub phase: WorkspacePhase,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceInfo {
    pub workspace: [u8; 32],
    pub workspace_name: Option<String>,
    pub epoch: u64,
    pub member_count: usize,
    pub durable: bool,
    pub phase: WorkspacePhase,
    pub reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberKind {
    Person,
    Service,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Presence {
    SelfMember,
    Unknown,
    Reachable,
    Stale,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberInfo {
    pub id: [u8; 32],
    pub endpoint: [u8; 32],
    pub administrator: bool,
    pub self_member: bool,
    pub display_name: Option<String>,
    pub kind: MemberKind,
    pub presence: Presence,
    pub last_contact_age_ms: Option<u64>,
    pub presence_fresh_for_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberRoster {
    pub workspace: [u8; 32],
    pub workspace_name: Option<String>,
    pub workspace_name_revision: u64,
    pub workspace_name_head: [u8; 32],
    pub epoch: u64,
    pub members: Vec<MemberInfo>,
    pub profile_count: usize,
    pub profiles_retained: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspacePresenceStatus {
    pub sync_peer: Option<[u8; 32]>,
    pub response_errors: u32,
    pub response_error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteHint {
    pub peer: [u8; 32],
    pub address: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvitationInfo {
    pub workspace: [u8; 32],
    pub workspace_name: Option<String>,
    pub invitation: Vec<u8>,
    pub invitation_key: [u8; 32],
    pub checkpoint: Vec<u8>,
    pub peer: [u8; 32],
    pub bootstrap_peers: Vec<[u8; 32]>,
    pub address: String,
    pub routes: Vec<RouteHint>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvitationDetails {
    pub workspace: [u8; 32],
    pub invitation_key: [u8; 32],
    pub workspace_name: Option<String>,
    pub epoch: u64,
    pub personal: bool,
    pub automatic: bool,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JoinRequest {
    pub workspace: [u8; 32],
    pub member: [u8; 32],
    pub endpoint: [u8; 32],
    pub admission_request: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdmissionAuthorization {
    pub invitation_key: [u8; 32],
    pub grant_signature: Vec<u8>,
    pub redemption_signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JoinAdmissionStep {
    pub commit: Vec<u8>,
    pub authorization: AdmissionAuthorization,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct AdmissionReply {
    pub workspace: [u8; 32],
    pub epoch: u64,
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
    pub authorization: AdmissionAuthorization,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceCandidate {
    pub workspace: [u8; 32],
    pub snapshot: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteKind {
    Direct,
    Relay,
    Tor,
    Custom(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerRoute {
    pub member: [u8; 32],
    pub route: RouteKind,
    pub rtt_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectivityReport {
    pub workspace: [u8; 32],
    pub paths: Vec<PeerRoute>,
    pub paths_limited: bool,
    pub receive_queue: usize,
    pub repair_jobs: usize,
}

/// A bounded, read-only snapshot for native adapters and diagnostics.
///
/// The snapshot contains local workspace state and counters only. It does not
/// initiate repair, dialing, admission or publication work. Qualification
/// receipts use a separate redacted projection; do not export this value as a
/// public telemetry record because its path members are workspace-local IDs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceMetrics {
    pub workspace: [u8; 32],
    pub phase: WorkspacePhase,
    pub reason: Option<String>,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub receive_queue: usize,
    pub admission_queue: usize,
    pub admission_queue_bytes: usize,
    pub admission_waiters: usize,
    pub admission_in_flight: usize,
    pub approval_pending: usize,
    pub pending_objects: usize,
    pub repair_jobs: usize,
    pub gossip_neighbors: usize,
    pub control_timing: ControlTimingMetrics,
    pub membership_gossip: MembershipGossipMetrics,
    pub connection_capacity: ConnectionCapacityMetrics,
    pub paths: Vec<PeerRoute>,
    pub paths_limited: bool,
}

/// A duration series measured in microseconds since the endpoint started.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub struct DurationSummary {
    pub count: u64,
    pub total_us: u64,
    pub max_us: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub struct ControlTimingMetrics {
    pub inquiry: DurationSummary,
    pub host_wait: DurationSummary,
    pub host_service: DurationSummary,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub struct MembershipGossipMetrics {
    pub sent: u64,
    pub no_overlay: u64,
    pub failed: u64,
    pub received: u64,
    pub staged: u64,
    pub rejected: u64,
    pub range_pulled: u64,
    pub range_failed: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub struct ConnectionCapacityMetrics {
    pub evicted: u64,
    pub refused: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PeerPolicy {
    pub peer: [u8; 32],
    pub publish: Vec<String>,
    pub subscribe: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryFailure {
    pub peer: [u8; 32],
    pub error: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryReport {
    pub admitted: Vec<[u8; 32]>,
    pub queued: bool,
    pub failed: Vec<DeliveryFailure>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationCandidate {
    pub workspace: [u8; 32],
    pub snapshot: Vec<u8>,
}

/// Current-value metadata for a protected publication.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicationCurrent {
    pub selector: [u8; 32],
    pub replacement_key: [u8; 32],
    pub expires_at: u64,
    pub tombstone: bool,
}

/// An authenticated object retained by the inbox pending application handling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingObject {
    pub workspace: [u8; 32],
    pub revision: u64,
    pub topic: String,
    pub id: [u8; 16],
    pub sequence: Option<u64>,
    pub member: [u8; 32],
    pub endpoint: [u8; 32],
    pub payload: Vec<u8>,
    pub counter: u64,
    pub recipients: Vec<[u8; 32]>,
    pub current: Option<PublicationCurrent>,
}

/// A protected incoming publication staged for caller-owned save/adopt.
/// The authenticated plaintext is withheld until `adopt_protected_reception`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedReceptionCandidate {
    pub workspace: [u8; 32],
    pub snapshot: Vec<u8>,
}

/// An authenticated protected publication released by candidate adoption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedProtectedPublication {
    pub workspace: [u8; 32],
    pub revision: u64,
    pub member: [u8; 32],
    pub endpoint: [u8; 32],
    pub topic: String,
    pub id: [u8; 16],
    pub sequence: Option<u64>,
    pub payload: Vec<u8>,
    pub recipients: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterestObservation {
    pub workspace: [u8; 32],
    pub revision: u64,
    pub topic: String,
    pub subscribed: bool,
    pub admission: DeliveryReport,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Publication {
    pub workspace: [u8; 32],
    pub revision: u64,
    pub sender: [u8; 32],
    pub topic: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredPublication {
    pub workspace: [u8; 32],
    pub revision: u64,
    pub member: [u8; 32],
    pub endpoint: [u8; 32],
    pub topic: String,
    pub id: [u8; 16],
    pub sequence: Option<u64>,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRangeRequest {
    pub peer: Option<[u8; 32]>,
    pub author: Option<[u8; 32]>,
    pub revision: u64,
    pub topics: Vec<String>,
    pub after: Option<u64>,
    pub through: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupObjectRecoveryRequest {
    pub peer: [u8; 32],
    pub author: [u8; 32],
    pub revision: u64,
    pub topics: Vec<String>,
    pub after: u64,
    pub through: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCutoffRequest {
    pub peer: [u8; 32],
    pub revision: u64,
    pub topics: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCutoff {
    pub workspace: [u8; 32],
    pub author: [u8; 32],
    pub peer: [u8; 32],
    pub epoch: u64,
    pub revision: u64,
    pub topics: Vec<String>,
    pub head: u64,
    pub retained_after: u64,
    pub accepted_through: u64,
    /// None when the bounded inbox cannot prove the cursor prefix.
    pub received_through: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryCutoffStatus {
    Pending,
    Observed(RecoveryCutoff),
    Denied,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupRecoveryGap {
    pub author: [u8; 32],
    pub topics: Vec<String>,
    pub after: u64,
    pub through: u64,
    /// Present when an authorized peer advertised live group objects.
    pub relay_peer: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupObjectRecoveryReady {
    pub peer: [u8; 32],
    pub author: [u8; 32],
    pub revision: u64,
    pub topics: Vec<String>,
    pub after: u64,
    pub through: u64,
    pub packet_count: usize,
    pub retained_bytes: usize,
    pub attempted: usize,
    pub accepted_progress: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupObjectRecoveryStatus {
    Pending { candidate_count: usize },
    Ready(GroupObjectRecoveryReady),
    Empty { peer: [u8; 32], attempted: usize },
    SourceUnavailable { attempted: usize, reason: Option<String> },
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRangeReady {
    pub workspace: [u8; 32],
    pub author: [u8; 32],
    pub peer: [u8; 32],
    pub epoch: u64,
    pub revision: u64,
    pub after: u64,
    pub through: u64,
    pub packet_count: usize,
    pub retained_bytes: usize,
    pub automatic_source: bool,
    pub attempted: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryRangeStatus {
    Pending {
        candidate_count: usize,
        automatic_source: bool,
    },
    Ready(RecoveryRangeReady),
    SourceWaiting {
        automatic_source: bool,
    },
    SourceUnavailable {
        attempted: usize,
        reason: String,
        automatic_source: bool,
    },
    Rejected {
        reason: String,
    },
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCandidate {
    pub workspace: [u8; 32],
    pub snapshot: Vec<u8>,
    pub publication_count: usize,
    pub already_received: usize,
    pub durable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryStage {
    Candidate(RecoveryCandidate),
    AlreadyCovered,
    NoNewObjects,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryAdoption {
    pub workspace: [u8; 32],
    pub epoch: u64,
    pub member_count: usize,
    pub durable: bool,
    pub recovered_publications: usize,
    pub missing_publications: usize,
}

/// Typed adopter seam over the portable runtime. The JSON dispatcher remains
/// private to adapters; consumers use typed lifecycle operations here.
pub struct Client {
    handle: Option<i64>,
}

impl Client {
    pub fn open(config: ClientConfig) -> Result<Self> {
        let handle = match config.network {
            Network::Direct => {
                create(config.secret.as_ref()).map_err(|message| map_error(&message))
            }
            Network::Lan => create_required_secret(config.secret.as_ref(), "LAN", create_lan),
            Network::Nearby => {
                create_required_secret(config.secret.as_ref(), "nearby", create_nearby)
            }
            Network::Wan => create_required_secret(config.secret.as_ref(), "WAN", create_wan),
            Network::RelayOnly => {
                create_required_secret(config.secret.as_ref(), "relay-only", create_relay)
            }
            Network::WanOnly => {
                create_required_secret(config.secret.as_ref(), "WAN-only", create_wan_only)
            }
            #[cfg(feature = "tor")]
            Network::Tor => create_required_secret(config.secret.as_ref(), "Tor", create_tor),
        };
        Ok(Self {
            handle: Some(handle?),
        })
    }

    pub fn endpoint(&self) -> Result<EndpointInfo> {
        let description = describe(self.handle()?).map_err(|message| map_error(&message))?;
        serde_json::from_str(&description).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid endpoint description: {parse_error}"),
            )
        })
    }

    pub fn workspace_state(&self) -> Result<WorkspaceState> {
        let endpoint_key = self.endpoint()?.endpoint_key;
        let response = self.request(json!({"op": "workspace_state"}))?;
        let activity = response
            .get("activity")
            .ok_or_else(|| error(ErrorKind::Internal, "workspace state has no activity"))?;
        let projection: ActivityProjection =
            serde_json::from_value(activity.clone()).map_err(|parse_error| {
                error(
                    ErrorKind::Internal,
                    format!("invalid workspace activity: {parse_error}"),
                )
            })?;
        Ok(WorkspaceState {
            endpoint_key,
            workspace: response
                .get("workspace")
                .map(|value| serde_json::from_value(value.clone()))
                .transpose()
                .map_err(|parse_error| {
                    error(
                        ErrorKind::Internal,
                        format!("invalid workspace id: {parse_error}"),
                    )
                })?,
            workspace_ready: response
                .get("workspace_ready")
                .and_then(Value::as_bool)
                .ok_or_else(|| error(ErrorKind::Internal, "workspace state has no readiness"))?,
            durable: response
                .get("durable")
                .and_then(Value::as_bool)
                .ok_or_else(|| error(ErrorKind::Internal, "workspace state has no durability"))?,
            phase: projection.phase,
            reason: projection.reason,
        })
    }

    pub fn create_workspace(
        &self,
        display_name: &str,
        workspace_name: Option<&str>,
    ) -> Result<WorkspaceInfo> {
        let response = self.request(json!({
            "op": "create_workspace",
            "display_name": display_name,
            "workspace_name": workspace_name,
        }))?;
        let raw: RawWorkspaceInfo = serde_json::from_value(response).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid workspace creation result: {parse_error}"),
            )
        })?;
        Ok(WorkspaceInfo {
            workspace: raw.workspace,
            workspace_name: raw.workspace_name,
            epoch: raw.epoch,
            member_count: raw.members,
            durable: raw.durable,
            phase: raw.activity.phase,
            reason: raw.activity.reason,
        })
    }

    pub fn begin_join(
        &self,
        invitation: &[u8],
        checkpoint: &[u8],
        display_name: &str,
    ) -> Result<JoinRequest> {
        self.begin_join_with_peers(invitation, checkpoint, display_name, &[])
    }

    /// Begin joining with known peers for the admission exchange.
    pub fn begin_join_with_peers(
        &self,
        invitation: &[u8],
        checkpoint: &[u8],
        display_name: &str,
        peers: &[[u8; 32]],
    ) -> Result<JoinRequest> {
        let response = self.request(json!({
            "op": "begin_join",
            "invitation": invitation,
            "checkpoint": checkpoint,
            "display_name": display_name,
            "peers": peers,
        }))?;
        let raw: RawJoinRequest = serde_json::from_value(response).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid join request: {parse_error}"),
            )
        })?;
        Ok(JoinRequest {
            workspace: raw.workspace,
            member: raw.member.id,
            endpoint: raw.endpoint,
            admission_request: raw
                .admission_request
                .ok_or_else(|| error(ErrorKind::InvalidInput, "invitation has no admission request"))?,
        })
    }

    /// Advance a join restored from native record storage.
    pub fn drive_join(&self) -> Result<Value> {
        self.request(json!({"op": "drive_join"}))
    }

    pub fn stage_admission(
        &self,
        authenticated_endpoint: [u8; 32],
        request: &[u8],
    ) -> Result<WorkspaceCandidate> {
        let metadata = serde_json::to_vec(&json!({
            "op": "stage_admission",
            "authenticated_endpoint": authenticated_endpoint,
            "request": request,
        }))
        .map_err(|parse_error| error(ErrorKind::Internal, parse_error.to_string()))?;
        let [metadata, snapshot] = execute_stored(self.handle()?, &metadata, &[])
            .map_err(|message| map_error(&message))?;
        parse_workspace_candidate(&metadata, snapshot, "admission")
    }

    pub fn adopt_admission(&self, snapshot: &[u8]) -> Result<WorkspaceInfo> {
        let [metadata, _] = execute_stored(
            self.handle()?,
            br#"{"op":"adopt_admission"}"#,
            snapshot,
        )
        .map_err(|message| map_error(&message))?;
        parse_workspace_info(&metadata, "admission adoption")
    }

    pub fn retained_admission(
        &self,
        authenticated_endpoint: [u8; 32],
        request: &[u8],
    ) -> Result<AdmissionReply> {
        let response = self.request(json!({
            "op": "retained_admission",
            "authenticated_endpoint": authenticated_endpoint,
            "request": request,
        }))?;
        serde_json::from_value(response).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid admission reply: {parse_error}"),
            )
        })
    }

    pub fn stage_join(
        &self,
        welcome: &[u8],
        commits: &[JoinAdmissionStep],
    ) -> Result<WorkspaceCandidate> {
        let metadata = serde_json::to_vec(&json!({
            "op": "stage_join",
            "commits": commits,
        }))
        .map_err(|parse_error| error(ErrorKind::Internal, parse_error.to_string()))?;
        let [metadata, snapshot] = execute_stored(self.handle()?, &metadata, welcome)
            .map_err(|message| map_error(&message))?;
        parse_workspace_candidate(&metadata, snapshot, "join")
    }

    pub fn adopt_join(&self, snapshot: &[u8]) -> Result<WorkspaceInfo> {
        let [metadata, _] = execute_stored(
            self.handle()?,
            br#"{"op":"adopt_join"}"#,
            snapshot,
        )
        .map_err(|message| map_error(&message))?;
        parse_workspace_info(&metadata, "join adoption")
    }

    /// Enable encrypted native storage for this client's workspace.
    pub fn enable_record_storage(&self, path: &Path, root: &[u8; 32]) -> Result<()> {
        enable_runtime_record_storage(self.handle()?, path, root)
            .map_err(|message| error(ErrorKind::Storage, message))
    }

    /// Restore a workspace from encrypted native storage.
    pub fn restore_record_storage(
        &self,
        path: &Path,
        root: &[u8; 32],
        workspace: [u8; 32],
    ) -> Result<Value> {
        restore_runtime_record_storage(self.handle()?, path, root, workspace)
            .map_err(|message| error(ErrorKind::Storage, message))
    }

    /// Save the exact staged snapshot before adopting it.
    pub fn save_candidate(&self, snapshot: &[u8]) -> Result<()> {
        save_runtime_candidate(self.handle()?, snapshot)
            .map_err(|message| error(ErrorKind::Storage, message))
    }

    pub fn member_roster(&self) -> Result<MemberRoster> {
        let response = self.request(json!({"op": "member_roster"}))?;
        let raw: RawMemberRoster = serde_json::from_value(response).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid member roster: {parse_error}"),
            )
        })?;
        let members = raw
            .members
            .into_iter()
            .map(MemberInfo::try_from)
            .collect::<Result<Vec<_>>>()?;
        Ok(MemberRoster {
            workspace: raw.workspace,
            workspace_name: raw.workspace_name,
            workspace_name_revision: raw.workspace_name_revision,
            workspace_name_head: raw.workspace_name_head,
            epoch: raw.epoch,
            members,
            profile_count: raw.profiles.len(),
            profiles_retained: raw.profiles_retained.unwrap_or(true),
        })
    }

    /// Mark this session's signed workspace profile as a service.
    /// This grants no membership or publication rights.
    pub fn use_service_profile(&self) -> Result<()> {
        self.request(json!({"op": "use_service_profile"}))?;
        Ok(())
    }

    pub fn issue_invitation(&self) -> Result<InvitationInfo> {
        let response = self.request(json!({"op": "issue_invitation"}))?;
        let raw: RawInvitationInfo = serde_json::from_value(response).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid invitation: {parse_error}"),
            )
        })?;
        Ok(InvitationInfo {
            workspace: raw.workspace,
            workspace_name: raw.workspace_name,
            invitation: raw.invitation,
            invitation_key: raw.invitation_key,
            checkpoint: raw.checkpoint,
            peer: raw.peer,
            bootstrap_peers: raw.bootstrap_peers,
            address: raw.address,
            routes: raw
                .routes
                .into_iter()
                .map(|route| RouteHint {
                    peer: route.peer,
                    address: route.address,
                })
                .collect(),
        })
    }

    pub fn inspect_invitation(
        &self,
        invitation: &[u8],
        checkpoint: &[u8],
    ) -> Result<InvitationDetails> {
        let response = self.request(json!({
            "op": "inspect_invitation",
            "invitation": invitation,
            "checkpoint": checkpoint,
        }))?;
        let raw: RawInvitationDetails =
            serde_json::from_value(response).map_err(|parse_error| {
                error(
                    ErrorKind::Internal,
                    format!("invalid invitation details: {parse_error}"),
                )
            })?;
        Ok(InvitationDetails {
            workspace: raw.workspace,
            invitation_key: raw.invitation_key,
            workspace_name: raw.workspace_name,
            epoch: raw.epoch,
            personal: raw.personal_invitation,
            automatic: raw.automatic_approval,
            expires_at: raw.expires_at,
        })
    }

    pub fn connectivity(&self) -> Result<ConnectivityReport> {
        let metrics = self.metrics()?;
        Ok(ConnectivityReport {
            workspace: metrics.workspace,
            paths: metrics.paths,
            paths_limited: metrics.paths_limited,
            receive_queue: metrics.receive_queue,
            repair_jobs: metrics.repair_jobs,
        })
    }

    pub fn metrics(&self) -> Result<WorkspaceMetrics> {
        let response = self.request(json!({"op": "workspace_metrics"}))?;
        let raw: RawWorkspaceMetrics =
            serde_json::from_value(response).map_err(|parse_error| {
                error(
                    ErrorKind::Internal,
                    format!("invalid workspace metrics: {parse_error}"),
                )
            })?;
        Ok(WorkspaceMetrics {
            workspace: raw.workspace,
            phase: raw.activity.phase,
            reason: raw.activity.reason,
            received_bytes: raw.received_bytes,
            sent_bytes: raw.sent_bytes,
            receive_queue: raw.receive_queue,
            admission_queue: raw.admission_queue,
            admission_queue_bytes: raw.admission_queue_bytes,
            admission_waiters: raw.admission_waiters,
            admission_in_flight: raw.admission_in_flight,
            approval_pending: raw.approval_pending,
            pending_objects: raw.pending_objects,
            repair_jobs: raw.repair_jobs,
            gossip_neighbors: raw.gossip_neighbors,
            control_timing: raw.control_timing,
            membership_gossip: raw.membership_gossip,
            connection_capacity: raw.connection_capacity,
            paths: raw
                .paths
                .into_iter()
                .map(|path| PeerRoute {
                    member: path.member,
                    route: match path.route.as_str() {
                        "direct" => RouteKind::Direct,
                        "relay" => RouteKind::Relay,
                        "tor" => RouteKind::Tor,
                        other => RouteKind::Custom(other.to_owned()),
                    },
                    rtt_ms: path.rtt_ms,
                })
                .collect(),
            paths_limited: raw.paths_limited,
        })
    }

    pub fn network_change(&self) -> Result<()> {
        self.request(json!({"op": "network_change"}))?;
        Ok(())
    }

    pub fn cancel(&self) -> Result<()> {
        cancel(self.handle()?).map_err(|message| map_error(&message))
    }

    pub fn wait_for_work(&self) -> Result<bool> {
        wait_for_work(self.handle()?).map_err(|message| map_error(&message))
    }

    /// Service one queued peer-control exchange and report whether one was served.
    pub fn poll_control(&self) -> Result<bool> {
        Ok(!self.request(json!({"op": "poll_admission"}))?.is_null())
    }

    pub fn poll_workspace_presence(&self, announce: bool) -> Result<WorkspacePresenceStatus> {
        let raw: RawWorkspacePresenceStatus = serde_json::from_value(self.request(json!({
            "op": "poll_workspace_presence",
            "announce": announce,
        }))?)
        .map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid workspace presence status: {parse_error}"),
            )
        })?;
        if raw.state != "workspace_presence" {
            return Err(error(
                ErrorKind::Internal,
                format!("unknown workspace presence state: {}", raw.state),
            ));
        }
        Ok(WorkspacePresenceStatus {
            sync_peer: raw.sync_peer,
            response_errors: raw.response_errors,
            response_error: raw.response_error,
        })
    }

    pub fn add_address_hint(&self, peer: [u8; 32], address: &str) -> Result<()> {
        self.request(json!({
            "op": "add_address_hint",
            "peer": peer,
            "address": address,
        }))?;
        Ok(())
    }

    pub fn install_policy(
        &self,
        workspace: [u8; 32],
        revision: u64,
        endpoints: &[PeerPolicy],
    ) -> Result<()> {
        self.request(json!({
            "op": "install_verified_policy",
            "workspace": workspace,
            "revision": revision,
            "endpoints": endpoints,
        }))?;
        Ok(())
    }

    pub fn install_workspace_policy(&self, revision: u64) -> Result<()> {
        self.request(json!({
            "op": "install_workspace_policy",
            "revision": revision,
        }))?;
        Ok(())
    }

    /// Stage object-delivery state. Save the candidate snapshot before adoption
    /// when record storage is enabled.
    pub fn enable_object_delivery(&self) -> Result<WorkspaceCandidate> {
        let [metadata, snapshot] =
            execute_stored(self.handle()?, br#"{"op":"enable_object_delivery"}"#, &[])
                .map_err(|message| map_error(&message))?;
        parse_workspace_candidate(&metadata, snapshot, "object delivery")
    }

    pub fn adopt_object_delivery(&self, candidate: &WorkspaceCandidate) -> Result<()> {
        self.adopt_object_candidate(candidate, false)
    }

    /// Poll one durable inbox object. Acknowledgement or rejection must be
    /// staged and adopted only after the application has durably handled it.
    pub fn poll_pending_object(&self) -> Result<Option<PendingObject>> {
        self.poll_pending_object_excluding(&[])
    }

    pub fn poll_pending_object_excluding(
        &self,
        deferred: &[arachne_delivery::inbox::DeferredDeliveryStream],
    ) -> Result<Option<PendingObject>> {
        let response = self.request(json!({
            "op": "poll_pending_object",
            "deferred": deferred,
        }))?;
        if response.is_null() {
            return Ok(None);
        }
        let raw: RawPendingObject = serde_json::from_value(response).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid pending object: {parse_error}"),
            )
        })?;
        Ok(Some(PendingObject {
            workspace: raw.workspace,
            revision: raw.revision,
            topic: raw.topic,
            id: raw.id,
            sequence: raw.sequence,
            member: raw.member,
            endpoint: raw.endpoint,
            payload: raw.payload,
            counter: raw.counter,
            recipients: raw.recipients,
            current: raw.current,
        }))
    }

    pub fn stage_object_acknowledgement(
        &self,
        pending: &PendingObject,
    ) -> Result<WorkspaceCandidate> {
        self.stage_object_receipt(pending, false)
    }

    pub fn stage_object_rejection(&self, pending: &PendingObject) -> Result<WorkspaceCandidate> {
        self.stage_object_receipt(pending, true)
    }

    /// Adopt an acknowledgement or rejection after saving its exact snapshot.
    pub fn adopt_object_receipt(&self, candidate: &WorkspaceCandidate) -> Result<()> {
        self.adopt_object_candidate(candidate, true)
    }

    fn stage_object_receipt(
        &self,
        pending: &PendingObject,
        rejected: bool,
    ) -> Result<WorkspaceCandidate> {
        let request = serde_json::to_vec(&json!({
            "op": if rejected {
                "stage_object_rejection"
            } else {
                "stage_object_acknowledgement"
            },
            "member": pending.member,
            "topic": pending.topic,
            "counter": pending.counter,
            "id": pending.id,
        }))
        .map_err(|parse_error| error(ErrorKind::Internal, parse_error.to_string()))?;
        let [metadata, snapshot] =
            execute_stored(self.handle()?, &request, &[]).map_err(|message| map_error(&message))?;
        let value: Value = serde_json::from_slice(&metadata).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid object receipt candidate: {parse_error}"),
            )
        })?;
        if value.get("state").and_then(Value::as_str) != Some("awaiting_reception_save") {
            return Err(error(
                ErrorKind::Internal,
                "object receipt has no adoptable snapshot",
            ));
        }
        let candidate = parse_workspace_candidate(&metadata, snapshot, "object receipt")?;
        if candidate.workspace != pending.workspace || candidate.snapshot.is_empty() {
            return Err(error(
                ErrorKind::Internal,
                "object receipt candidate does not match pending object",
            ));
        }
        Ok(candidate)
    }

    fn adopt_object_candidate(
        &self,
        candidate: &WorkspaceCandidate,
        allow_rejection: bool,
    ) -> Result<()> {
        let [metadata, _] = execute_stored(
            self.handle()?,
            br#"{"op":"adopt_reception"}"#,
            &candidate.snapshot,
        )
        .map_err(|message| map_error(&message))?;
        let response: Value = serde_json::from_slice(&metadata).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid object-delivery adoption: {parse_error}"),
            )
        })?;
        let state = response.get("state").and_then(Value::as_str);
        if state != Some("inbox_adopted")
            && !(allow_rejection && state == Some("inbox_rejection_adopted"))
        {
            return Err(error(
                ErrorKind::Internal,
                "object inbox candidate was not adopted",
            ));
        }
        let workspace: [u8; 32] =
            serde_json::from_value(response["workspace"].clone()).map_err(|parse_error| {
                error(
                    ErrorKind::Internal,
                    format!("invalid adopted object-inbox workspace: {parse_error}"),
                )
            })?;
        if workspace != candidate.workspace {
            return Err(error(
                ErrorKind::Internal,
                "object inbox candidate workspace mismatch",
            ));
        }
        Ok(())
    }

    pub fn stage_protected_publication(
        &self,
        workspace: [u8; 32],
        revision: u64,
        topic: &str,
        id: [u8; 16],
        payload: Vec<u8>,
    ) -> Result<PublicationCandidate> {
        self.stage_protected_publication_with_current(workspace, revision, topic, id, payload, None)
    }

    pub fn stage_protected_publication_with_current(
        &self,
        workspace: [u8; 32],
        revision: u64,
        topic: &str,
        id: [u8; 16],
        payload: Vec<u8>,
        current: Option<PublicationCurrent>,
    ) -> Result<PublicationCandidate> {
        let request = serde_json::to_vec(&json!({
            "op": "stage_network_publication",
            "revision": revision,
            "topic": topic,
            "id": id,
            "payload": payload,
            "current": current,
        }))
        .map_err(|parse_error| error(ErrorKind::Internal, parse_error.to_string()))?;
        let [metadata, snapshot] =
            execute_stored(self.handle()?, &request, &[]).map_err(|message| map_error(&message))?;
        let value: Value = serde_json::from_slice(&metadata).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid publication candidate: {parse_error}"),
            )
        })?;
        let candidate_workspace = value
            .get("workspace")
            .ok_or_else(|| error(ErrorKind::Internal, "publication candidate has no workspace"))
            .and_then(|value| {
                serde_json::from_value(value.clone()).map_err(|parse_error| {
                    error(
                        ErrorKind::Internal,
                        format!("invalid publication candidate workspace: {parse_error}"),
                    )
                })
            })?;
        if candidate_workspace != workspace {
            return Err(error(
                ErrorKind::Internal,
                "publication candidate workspace mismatch",
            ));
        }
        Ok(PublicationCandidate {
            workspace: candidate_workspace,
            snapshot,
        })
    }

    pub fn adopt_protected_publication(&self, snapshot: &[u8]) -> Result<DeliveryReport> {
        let [metadata, _] = execute_stored(
            self.handle()?,
            br#"{"op":"adopt_publication"}"#,
            snapshot,
        )
        .map_err(|message| map_error(&message))?;
        let value: Value = serde_json::from_slice(&metadata).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid publication result: {parse_error}"),
            )
        })?;
        if let Some(message) = value.get("network_error").and_then(Value::as_str) {
            return Err(error(ErrorKind::Transport, message));
        }
        let admission = value
            .get("admission")
            .ok_or_else(|| error(ErrorKind::Internal, "publication result has no admission"))?;
        serde_json::from_value::<RawDeliveryReport>(admission.clone())
            .map(Into::into)
            .map_err(|parse_error| {
                error(
                    ErrorKind::Internal,
                    format!("invalid publication admission: {parse_error}"),
                )
            })
    }

    /// Stage one protected incoming publication without exposing its plaintext.
    /// Save the exact snapshot before adoption whenever record storage is enabled.
    pub fn poll_protected(&self) -> Result<Option<ProtectedReceptionCandidate>> {
        let [metadata, snapshot] =
            execute_stored(self.handle()?, br#"{"op":"poll_protected"}"#, &[])
                .map_err(|message| map_error(&message))?;
        let value: Value = serde_json::from_slice(&metadata).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid protected reception candidate: {parse_error}"),
            )
        })?;
        if value.is_null() {
            if snapshot.is_empty() {
                return Ok(None);
            }
            return Err(error(
                ErrorKind::Internal,
                "empty protected reception returned a snapshot",
            ));
        }
        let raw: RawProtectedReceptionCandidate =
            serde_json::from_value(value).map_err(|parse_error| {
                error(
                    ErrorKind::Internal,
                    format!("invalid protected reception candidate: {parse_error}"),
                )
            })?;
        if raw.state != "awaiting_reception_save" || snapshot.is_empty() {
            return Err(error(
                ErrorKind::Internal,
                "protected reception has no adoptable snapshot",
            ));
        }
        Ok(Some(ProtectedReceptionCandidate {
            workspace: raw.workspace,
            snapshot,
        }))
    }

    /// Adopt a staged protected reception and release its authenticated payload.
    pub fn adopt_protected_reception(
        &self,
        snapshot: &[u8],
    ) -> Result<ReceivedProtectedPublication> {
        let [metadata, _] = execute_stored(
            self.handle()?,
            br#"{"op":"adopt_reception"}"#,
            snapshot,
        )
        .map_err(|message| map_error(&message))?;
        let raw: RawProtectedPublication =
            serde_json::from_slice(&metadata).map_err(|parse_error| {
                error(
                    ErrorKind::Internal,
                    format!("invalid adopted protected publication: {parse_error}"),
                )
            })?;
        Ok(ReceivedProtectedPublication {
            workspace: raw.workspace,
            revision: raw.revision,
            member: raw.member,
            endpoint: raw.endpoint,
            topic: raw.topic,
            id: raw.id,
            sequence: raw.sequence,
            payload: raw.payload,
            recipients: raw.recipients,
        })
    }

    pub fn set_interest(
        &self,
        workspace: [u8; 32],
        revision: u64,
        topic: &str,
        subscribed: bool,
    ) -> Result<()> {
        self.request(json!({
            "op": "set_interest",
            "workspace": workspace,
            "revision": revision,
            "topic": topic,
            "subscribed": subscribed,
        }))?;
        Ok(())
    }

    pub fn poll_interest(&self) -> Result<Option<InterestObservation>> {
        let response = self.request(json!({"op": "poll_interest"}))?;
        if response.is_null()
            || matches!(
                response.get("state").and_then(Value::as_str),
                Some("interest_pending")
            )
        {
            return Ok(None);
        }
        if response.get("state").and_then(Value::as_str) == Some("interest_failed") {
            return Err(error(
                ErrorKind::Transport,
                response
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("interest update failed"),
            ));
        }
        let raw: RawInterestObservation =
            serde_json::from_value(response).map_err(|parse_error| {
                error(
                    ErrorKind::Internal,
                    format!("invalid interest observation: {parse_error}"),
                )
            })?;
        Ok(Some(InterestObservation {
            workspace: raw.workspace,
            revision: raw.revision,
            topic: raw.topic,
            subscribed: raw.subscribed,
            admission: raw.admission.into(),
        }))
    }

    pub fn publish(
        &self,
        workspace: [u8; 32],
        revision: u64,
        topic: &str,
        payload: Vec<u8>,
    ) -> Result<DeliveryReport> {
        let response = self.request(json!({
            "op": "publish",
            "workspace": workspace,
            "revision": revision,
            "topic": topic,
            "payload": payload,
        }))?;
        serde_json::from_value::<RawDeliveryReport>(response)
            .map(Into::into)
            .map_err(|parse_error| {
                error(
                    ErrorKind::Internal,
                    format!("invalid delivery report: {parse_error}"),
                )
            })
    }

    pub fn poll(&self) -> Result<Option<Publication>> {
        let response = self.request(json!({"op": "poll"}))?;
        if response.is_null() {
            return Ok(None);
        }
        serde_json::from_value::<RawPublication>(response)
            .map(Into::into)
            .map(Some)
            .map_err(|parse_error| {
                error(
                    ErrorKind::Internal,
                    format!("invalid publication: {parse_error}"),
                )
            })
    }

    pub fn poll_recovered_publication(&self) -> Result<Option<RecoveredPublication>> {
        let response = self.request(json!({"op": "poll_recovered_publication"}))?;
        if response.is_null() {
            return Ok(None);
        }
        serde_json::from_value::<RawRecoveredPublication>(response)
            .map(Into::into)
            .map(Some)
            .map_err(|parse_error| {
                error(
                    ErrorKind::Internal,
                    format!("invalid recovered publication: {parse_error}"),
                )
            })
    }

    pub fn fetch_recovery_range(
        &self,
        request: RecoveryRangeRequest,
    ) -> Result<RecoveryRangeStatus> {
        let response = self.request(json!({
            "op": "fetch_recovery_range",
            "peer": request.peer,
            "author": request.author,
            "revision": request.revision,
            "topics": request.topics,
            "after": request.after,
            "through": request.through,
        }))?;
        parse_recovery_range_status(response)
    }

    pub fn poll_recovery_range(&self) -> Result<Option<RecoveryRangeStatus>> {
        let response = self.request(json!({"op": "poll_recovery_range"}))?;
        if response.is_null() {
            return Ok(None);
        }
        parse_recovery_range_status(response).map(Some)
    }

    pub fn next_group_gap(
        &self,
        author: [u8; 32],
        topics: Vec<String>,
    ) -> Result<Option<GroupRecoveryGap>> {
        let response = self.request(json!({
            "op": "next_group_gap",
            "author": author,
            "topics": topics,
        }))?;
        if response.is_null() {
            return Ok(None);
        }
        let raw: RawGroupRecoveryGap = serde_json::from_value(response).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid group recovery gap: {parse_error}"),
            )
        })?;
        if raw.state != "group_recovery_needed" {
            return Err(error(
                ErrorKind::Internal,
                format!("unknown group recovery gap state: {}", raw.state),
            ));
        }
        Ok(Some(GroupRecoveryGap {
            author: raw.author,
            topics: raw.topics,
            after: raw.after,
            through: raw.through,
            relay_peer: raw.relay_peer,
        }))
    }

    pub fn fetch_group_objects(
        &self,
        request: GroupObjectRecoveryRequest,
    ) -> Result<GroupObjectRecoveryStatus> {
        parse_group_object_recovery_status(self.request(json!({
            "op": "fetch_group_objects",
            "peer": request.peer,
            "author": request.author,
            "revision": request.revision,
            "topics": request.topics,
            "after": request.after,
            "through": request.through,
        }))?)
    }

    pub fn poll_group_objects(&self) -> Result<Option<GroupObjectRecoveryStatus>> {
        let response = self.request(json!({"op": "poll_group_objects"}))?;
        if response.is_null() {
            return Ok(None);
        }
        parse_group_object_recovery_status(response).map(Some)
    }

    pub fn cancel_group_objects(&self) -> Result<()> {
        match parse_group_object_recovery_status(
            self.request(json!({"op": "cancel_group_objects"}))?,
        )? {
            GroupObjectRecoveryStatus::Cancelled => Ok(()),
            _ => Err(error(
                ErrorKind::Internal,
                "invalid group-object recovery cancellation response",
            )),
        }
    }

    pub fn stage_group_objects(&self) -> Result<RecoveryStage> {
        let [metadata, snapshot] =
            execute_stored(self.handle()?, br#"{"op":"stage_group_objects"}"#, &[])
                .map_err(|message| map_error(&message))?;
        let value: Value = serde_json::from_slice(&metadata).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid group-object recovery stage: {parse_error}"),
            )
        })?;
        match value.get("state").and_then(Value::as_str) {
            Some("awaiting_recovery_save") => {
                let raw: RawRecoveryCandidate =
                    serde_json::from_value(value).map_err(|parse_error| {
                        error(
                            ErrorKind::Internal,
                            format!("invalid group-object recovery candidate: {parse_error}"),
                        )
                    })?;
                Ok(RecoveryStage::Candidate(RecoveryCandidate {
                    workspace: raw.workspace,
                    snapshot,
                    publication_count: raw.publication_count,
                    already_received: raw.already_received,
                    durable: raw.durable,
                }))
            }
            Some("group_object_recovery_already_covered") => Ok(RecoveryStage::AlreadyCovered),
            Some(state) => Err(error(
                ErrorKind::Internal,
                format!("unknown group-object recovery stage: {state}"),
            )),
            None => Err(error(
                ErrorKind::Internal,
                "group-object recovery stage has no state",
            )),
        }
    }

    pub fn discover_recovery_cutoff(
        &self,
        request: RecoveryCutoffRequest,
    ) -> Result<RecoveryCutoffStatus> {
        parse_recovery_cutoff_status(self.request(json!({
            "op": "discover_recovery_cutoff",
            "peer": request.peer,
            "revision": request.revision,
            "topics": request.topics,
        }))?)
    }

    pub fn poll_recovery_cutoff(&self) -> Result<Option<RecoveryCutoffStatus>> {
        let response = self.request(json!({"op": "poll_recovery_cutoff"}))?;
        if response.is_null() {
            return Ok(None);
        }
        parse_recovery_cutoff_status(response).map(Some)
    }

    pub fn cancel_recovery_range(&self) -> Result<()> {
        match parse_recovery_range_status(self.request(json!({
            "op": "cancel_recovery_range"
        }))?)? {
            RecoveryRangeStatus::Cancelled => Ok(()),
            _ => Err(error(
                ErrorKind::Internal,
                "invalid recovery cancellation response",
            )),
        }
    }

    pub fn stage_recovery_range(&self, retain_until: u64) -> Result<RecoveryStage> {
        let metadata = serde_json::to_vec(&json!({
            "op": "stage_recovery_range",
            "retain_until": retain_until,
        }))
        .map_err(|parse_error| error(ErrorKind::Internal, parse_error.to_string()))?;
        let [metadata, snapshot] = execute_stored(self.handle()?, &metadata, &[])
            .map_err(|message| map_error(&message))?;
        let value: Value = serde_json::from_slice(&metadata).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid recovery stage: {parse_error}"),
            )
        })?;
        let state = value
            .get("state")
            .and_then(Value::as_str)
            .ok_or_else(|| error(ErrorKind::Internal, "recovery stage has no state"))?;
        match state {
            "awaiting_recovery_save" => {
                let raw: RawRecoveryCandidate =
                    serde_json::from_value(value).map_err(|parse_error| {
                        error(
                            ErrorKind::Internal,
                            format!("invalid recovery candidate: {parse_error}"),
                        )
                    })?;
                Ok(RecoveryStage::Candidate(RecoveryCandidate {
                    workspace: raw.workspace,
                    snapshot,
                    publication_count: raw.publication_count,
                    already_received: raw.already_received,
                    durable: raw.durable,
                }))
            }
            "recovery_already_covered" => Ok(RecoveryStage::AlreadyCovered),
            "recovery_no_new_objects" => Ok(RecoveryStage::NoNewObjects),
            other => Err(error(
                ErrorKind::Internal,
                format!("unknown recovery stage: {other}"),
            )),
        }
    }

    pub fn adopt_recovery(&self, snapshot: &[u8]) -> Result<RecoveryAdoption> {
        let [metadata, _] = execute_stored(
            self.handle()?,
            br#"{"op":"adopt_recovery"}"#,
            snapshot,
        )
        .map_err(|message| map_error(&message))?;
        let raw: RawRecoveryAdoption = serde_json::from_slice(&metadata).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid recovery adoption: {parse_error}"),
            )
        })?;
        let (recovered_publications, missing_publications) = match raw.state.as_str() {
            "recovery_adopted" => (raw.publication_count, 0),
            "direct_miss_adopted" => (0, raw.missing_count),
            other => {
                return Err(error(
                    ErrorKind::Internal,
                    format!("unknown recovery adoption: {other}"),
                ));
            }
        };
        Ok(RecoveryAdoption {
            workspace: raw.workspace,
            epoch: raw.epoch,
            member_count: raw.members,
            durable: raw.durable,
            recovered_publications,
            missing_publications,
        })
    }

    pub fn close(&mut self) -> Result<()> {
        let handle = self
            .handle
            .take()
            .ok_or_else(|| error(ErrorKind::Closed, "client is closed"))?;
        close(handle).map_err(|message| map_error(&message))
    }

    fn handle(&self) -> Result<i64> {
        self.handle
            .ok_or_else(|| error(ErrorKind::Closed, "client is closed"))
    }

    fn request(&self, request: Value) -> Result<Value> {
        let bytes = serde_json::to_vec(&request).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("request encoding failed: {parse_error}"),
            )
        })?;
        let reply = execute(self.handle()?, &bytes).map_err(|message| map_error(&message))?;
        serde_json::from_slice(&reply).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("response decoding failed: {parse_error}"),
            )
        })
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = close(handle);
        }
    }
}

#[derive(Deserialize)]
struct ActivityProjection {
    #[serde(rename = "state")]
    phase: WorkspacePhase,
    reason: Option<String>,
}

#[derive(Deserialize)]
struct RawWorkspaceInfo {
    workspace: [u8; 32],
    workspace_name: Option<String>,
    epoch: u64,
    members: usize,
    durable: bool,
    activity: ActivityProjection,
}

#[derive(Deserialize)]
struct RawJoinMember {
    id: [u8; 32],
}

#[derive(Deserialize)]
struct RawJoinRequest {
    workspace: [u8; 32],
    endpoint: [u8; 32],
    member: RawJoinMember,
    admission_request: Option<Vec<u8>>,
}

#[derive(Deserialize)]
struct RawWorkspaceCandidate {
    workspace: [u8; 32],
}

#[derive(Deserialize)]
struct RawMemberRoster {
    workspace: [u8; 32],
    workspace_name: Option<String>,
    workspace_name_revision: u64,
    workspace_name_head: [u8; 32],
    epoch: u64,
    members: Vec<RawMemberInfo>,
    #[serde(default)]
    profiles: Vec<Vec<u8>>,
    profiles_retained: Option<bool>,
}

#[derive(Deserialize)]
struct RawMemberInfo {
    id: [u8; 32],
    endpoint: [u8; 32],
    administrator: bool,
    #[serde(rename = "self")]
    self_member: bool,
    display_name: Option<String>,
    kind: String,
    presence: String,
    last_contact_age_ms: Option<u64>,
    presence_fresh_for_ms: Option<u64>,
}

#[derive(Deserialize)]
struct RawInvitationInfo {
    workspace: [u8; 32],
    workspace_name: Option<String>,
    invitation: Vec<u8>,
    invitation_key: [u8; 32],
    checkpoint: Vec<u8>,
    peer: [u8; 32],
    #[serde(default)]
    bootstrap_peers: Vec<[u8; 32]>,
    address: String,
    #[serde(default)]
    routes: Vec<RawRouteHint>,
}

#[derive(Deserialize)]
struct RawInvitationDetails {
    workspace: [u8; 32],
    invitation_key: [u8; 32],
    workspace_name: Option<String>,
    epoch: u64,
    personal_invitation: bool,
    automatic_approval: bool,
    expires_at: u64,
}

#[derive(Deserialize)]
struct RawRouteHint {
    peer: [u8; 32],
    address: String,
}

#[derive(Deserialize)]
struct RawWorkspaceMetrics {
    workspace: [u8; 32],
    activity: ActivityProjection,
    received_bytes: u64,
    sent_bytes: u64,
    receive_queue: usize,
    admission_queue: usize,
    admission_queue_bytes: usize,
    admission_waiters: usize,
    admission_in_flight: usize,
    approval_pending: usize,
    pending_objects: usize,
    repair_jobs: usize,
    gossip_neighbors: usize,
    control_timing: ControlTimingMetrics,
    membership_gossip: MembershipGossipMetrics,
    connection_capacity: ConnectionCapacityMetrics,
    paths: Vec<RawPeerRoute>,
    paths_limited: bool,
}

#[derive(Deserialize)]
struct RawPeerRoute {
    member: [u8; 32],
    route: String,
    rtt_ms: u64,
}

fn parse_workspace_info(bytes: &[u8], context: &str) -> Result<WorkspaceInfo> {
    let raw: RawWorkspaceInfo = serde_json::from_slice(bytes).map_err(|parse_error| {
        error(
            ErrorKind::Internal,
            format!("invalid {context} result: {parse_error}"),
        )
    })?;
    Ok(WorkspaceInfo {
        workspace: raw.workspace,
        workspace_name: raw.workspace_name,
        epoch: raw.epoch,
        member_count: raw.members,
        durable: raw.durable,
        phase: raw.activity.phase,
        reason: raw.activity.reason,
    })
}

fn parse_workspace_candidate(
    metadata: &[u8],
    snapshot: Vec<u8>,
    context: &str,
) -> Result<WorkspaceCandidate> {
    let raw: RawWorkspaceCandidate = serde_json::from_slice(metadata).map_err(|parse_error| {
        error(
            ErrorKind::Internal,
            format!("invalid {context} candidate: {parse_error}"),
        )
    })?;
    Ok(WorkspaceCandidate {
        workspace: raw.workspace,
        snapshot,
    })
}

impl TryFrom<RawMemberInfo> for MemberInfo {
    type Error = Error;

    fn try_from(value: RawMemberInfo) -> Result<Self> {
        let kind = match value.kind.as_str() {
            "person" => MemberKind::Person,
            "service" => MemberKind::Service,
            _ => return Err(error(ErrorKind::Internal, "invalid member kind")),
        };
        let presence = match value.presence.as_str() {
            "self" => Presence::SelfMember,
            "unknown" => Presence::Unknown,
            "reachable" => Presence::Reachable,
            "stale" => Presence::Stale,
            _ => return Err(error(ErrorKind::Internal, "invalid member presence")),
        };
        Ok(Self {
            id: value.id,
            endpoint: value.endpoint,
            administrator: value.administrator,
            self_member: value.self_member,
            display_name: value.display_name,
            kind,
            presence,
            last_contact_age_ms: value.last_contact_age_ms,
            presence_fresh_for_ms: value.presence_fresh_for_ms,
        })
    }
}

#[derive(Deserialize)]
struct RawDeliveryReport {
    admitted: Vec<[u8; 32]>,
    queued: bool,
    failed: Vec<RawDeliveryFailure>,
}

#[derive(Deserialize)]
struct RawDeliveryFailure {
    peer: [u8; 32],
    error: String,
}

#[derive(Deserialize)]
struct RawInterestObservation {
    workspace: [u8; 32],
    revision: u64,
    topic: String,
    subscribed: bool,
    admission: RawDeliveryReport,
}

#[derive(Deserialize)]
struct RawPublication {
    workspace: [u8; 32],
    revision: u64,
    sender: [u8; 32],
    topic: String,
    payload: Vec<u8>,
}

#[derive(Deserialize)]
struct RawProtectedReceptionCandidate {
    workspace: [u8; 32],
    state: String,
}

#[derive(Deserialize)]
struct RawPendingObject {
    workspace: [u8; 32],
    revision: u64,
    topic: String,
    id: [u8; 16],
    #[serde(default)]
    sequence: Option<u64>,
    member: [u8; 32],
    endpoint: [u8; 32],
    payload: Vec<u8>,
    counter: u64,
    #[serde(default)]
    recipients: Vec<[u8; 32]>,
    #[serde(default)]
    current: Option<PublicationCurrent>,
}

#[derive(Deserialize)]
struct RawProtectedPublication {
    workspace: [u8; 32],
    revision: u64,
    member: [u8; 32],
    endpoint: [u8; 32],
    topic: String,
    id: [u8; 16],
    sequence: Option<u64>,
    payload: Vec<u8>,
    #[serde(default)]
    recipients: Vec<[u8; 32]>,
}

#[derive(Deserialize)]
struct RawRecoveredPublication {
    workspace: [u8; 32],
    revision: u64,
    member: [u8; 32],
    endpoint: [u8; 32],
    topic: String,
    id: [u8; 16],
    sequence: Option<u64>,
    payload: Vec<u8>,
}

#[derive(Deserialize)]
struct RawRecoveryRangePending {
    candidate_count: usize,
    automatic_source: bool,
}

#[derive(Deserialize)]
struct RawRecoveryCutoffObserved {
    workspace: [u8; 32],
    author: [u8; 32],
    peer: [u8; 32],
    epoch: u64,
    revision: u64,
    topics: Vec<String>,
    head: u64,
    retained_after: u64,
    accepted_through: u64,
    #[serde(default)]
    received_through: Option<u64>,
}

#[derive(Deserialize)]
struct RawRecoveryRangeReady {
    workspace: [u8; 32],
    author: [u8; 32],
    peer: [u8; 32],
    epoch: u64,
    revision: u64,
    after: u64,
    through: u64,
    packet_count: usize,
    retained_bytes: usize,
    automatic_source: bool,
    #[serde(default)]
    attempted: Option<usize>,
}

#[derive(Deserialize)]
struct RawRecoverySourceUnavailable {
    attempted: usize,
    reason: String,
    automatic_source: bool,
}

#[derive(Deserialize)]
struct RawGroupRecoveryGap {
    state: String,
    author: [u8; 32],
    topics: Vec<String>,
    after: u64,
    through: u64,
    #[serde(default)]
    relay_peer: Option<[u8; 32]>,
}

#[derive(Deserialize)]
struct RawWorkspacePresenceStatus {
    state: String,
    sync_peer: Option<[u8; 32]>,
    response_errors: u32,
    response_error: Option<String>,
}

#[derive(Deserialize)]
struct RawGroupObjectRecoveryStatus {
    state: String,
    #[serde(default)]
    candidate_count: Option<usize>,
    #[serde(default)]
    peer: Option<[u8; 32]>,
    #[serde(default)]
    author: Option<[u8; 32]>,
    #[serde(default)]
    revision: Option<u64>,
    #[serde(default)]
    topics: Vec<String>,
    #[serde(default)]
    after: Option<u64>,
    #[serde(default)]
    through: Option<u64>,
    #[serde(default)]
    packet_count: Option<usize>,
    #[serde(default)]
    retained_bytes: Option<usize>,
    #[serde(default)]
    attempted: Option<usize>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    accepted_progress: bool,
}

#[derive(Deserialize)]
struct RawRecoveryCandidate {
    workspace: [u8; 32],
    #[serde(default)]
    publication_count: usize,
    #[serde(default)]
    already_received: usize,
    durable: bool,
}

#[derive(Deserialize)]
struct RawRecoveryAdoption {
    workspace: [u8; 32],
    epoch: u64,
    members: usize,
    durable: bool,
    state: String,
    #[serde(default)]
    publication_count: usize,
    #[serde(default)]
    missing_count: usize,
}

fn parse_group_object_recovery_status(value: Value) -> Result<GroupObjectRecoveryStatus> {
    let raw: RawGroupObjectRecoveryStatus =
        serde_json::from_value(value).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid group-object recovery status: {parse_error}"),
            )
        })?;
    if raw.accepted_progress {
        return Err(error(
            ErrorKind::Internal,
            "group-object recovery changed signed range progress",
        ));
    }
    let missing = |field: &str| {
        error(
            ErrorKind::Internal,
            format!("group-object recovery status is missing {field}"),
        )
    };
    match raw.state.as_str() {
        "group_object_recovery_pending" => Ok(GroupObjectRecoveryStatus::Pending {
            candidate_count: raw
                .candidate_count
                .ok_or_else(|| missing("candidate count"))?,
        }),
        "group_object_recovery_ready" => {
            Ok(GroupObjectRecoveryStatus::Ready(GroupObjectRecoveryReady {
                peer: raw.peer.ok_or_else(|| missing("peer"))?,
                author: raw.author.ok_or_else(|| missing("author"))?,
                revision: raw.revision.ok_or_else(|| missing("revision"))?,
                topics: raw.topics,
                after: raw.after.ok_or_else(|| missing("after cursor"))?,
                through: raw.through.ok_or_else(|| missing("through cursor"))?,
                packet_count: raw.packet_count.ok_or_else(|| missing("packet count"))?,
                retained_bytes: raw
                    .retained_bytes
                    .ok_or_else(|| missing("retained bytes"))?,
                attempted: raw.attempted.ok_or_else(|| missing("attempt count"))?,
                accepted_progress: raw.accepted_progress,
            }))
        }
        "group_object_recovery_empty" => Ok(GroupObjectRecoveryStatus::Empty {
            peer: raw.peer.ok_or_else(|| missing("peer"))?,
            attempted: raw.attempted.ok_or_else(|| missing("attempt count"))?,
        }),
        "group_object_source_unavailable" => Ok(GroupObjectRecoveryStatus::SourceUnavailable {
            attempted: raw.attempted.ok_or_else(|| missing("attempt count"))?,
            reason: raw.reason,
        }),
        "group_object_recovery_cancelled" => Ok(GroupObjectRecoveryStatus::Cancelled),
        other => Err(error(
            ErrorKind::Internal,
            format!("unknown group-object recovery state: {other}"),
        )),
    }
}

fn parse_recovery_range_status(value: Value) -> Result<RecoveryRangeStatus> {
    let state = value
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| error(ErrorKind::Internal, "recovery range has no state"))?;
    match state {
        "recovery_range_pending" => {
            let raw: RawRecoveryRangePending =
                serde_json::from_value(value).map_err(|parse_error| {
                    error(
                        ErrorKind::Internal,
                        format!("invalid recovery range status: {parse_error}"),
                    )
                })?;
            Ok(RecoveryRangeStatus::Pending {
                candidate_count: raw.candidate_count,
                automatic_source: raw.automatic_source,
            })
        }
        "recovery_range_ready" => {
            let raw: RawRecoveryRangeReady =
                serde_json::from_value(value).map_err(|parse_error| {
                    error(
                        ErrorKind::Internal,
                        format!("invalid recovery range: {parse_error}"),
                    )
                })?;
            Ok(RecoveryRangeStatus::Ready(RecoveryRangeReady {
                workspace: raw.workspace,
                author: raw.author,
                peer: raw.peer,
                epoch: raw.epoch,
                revision: raw.revision,
                after: raw.after,
                through: raw.through,
                packet_count: raw.packet_count,
                retained_bytes: raw.retained_bytes,
                automatic_source: raw.automatic_source,
                attempted: raw.attempted,
            }))
        }
        "recovery_source_waiting" => Ok(RecoveryRangeStatus::SourceWaiting {
            automatic_source: value
                .get("automatic_source")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        }),
        "recovery_source_unavailable" => {
            let raw: RawRecoverySourceUnavailable =
                serde_json::from_value(value).map_err(|parse_error| {
                    error(
                        ErrorKind::Internal,
                        format!("invalid recovery source status: {parse_error}"),
                    )
                })?;
            Ok(RecoveryRangeStatus::SourceUnavailable {
                attempted: raw.attempted,
                reason: raw.reason,
                automatic_source: raw.automatic_source,
            })
        }
        "recovery_range_rejected" => Ok(RecoveryRangeStatus::Rejected {
            reason: value
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("recovery range rejected")
                .to_owned(),
        }),
        "recovery_range_cancelled" => Ok(RecoveryRangeStatus::Cancelled),
        other => Err(error(
            ErrorKind::Internal,
            format!("unknown recovery range state: {other}"),
        )),
    }
}

fn parse_recovery_cutoff_status(value: Value) -> Result<RecoveryCutoffStatus> {
    match value.get("state").and_then(Value::as_str) {
        Some("recovery_cutoff_pending") => Ok(RecoveryCutoffStatus::Pending),
        Some("recovery_cutoff_observed") => {
            let raw: RawRecoveryCutoffObserved =
                serde_json::from_value(value).map_err(|parse_error| {
                    error(
                        ErrorKind::Internal,
                        format!("invalid recovery cutoff: {parse_error}"),
                    )
                })?;
            Ok(RecoveryCutoffStatus::Observed(RecoveryCutoff {
                workspace: raw.workspace,
                author: raw.author,
                peer: raw.peer,
                epoch: raw.epoch,
                revision: raw.revision,
                topics: raw.topics,
                head: raw.head,
                retained_after: raw.retained_after,
                accepted_through: raw.accepted_through,
                received_through: raw.received_through,
            }))
        }
        Some("recovery_cutoff_denied") => Ok(RecoveryCutoffStatus::Denied),
        _ => Err(error(ErrorKind::Internal, "unknown recovery cutoff status")),
    }
}

impl From<RawDeliveryReport> for DeliveryReport {
    fn from(value: RawDeliveryReport) -> Self {
        Self {
            admitted: value.admitted,
            queued: value.queued,
            failed: value
                .failed
                .into_iter()
                .map(|failure| DeliveryFailure {
                    peer: failure.peer,
                    error: failure.error,
                })
                .collect(),
        }
    }
}

impl From<RawPublication> for Publication {
    fn from(value: RawPublication) -> Self {
        Self {
            workspace: value.workspace,
            revision: value.revision,
            sender: value.sender,
            topic: value.topic,
            payload: value.payload,
        }
    }
}

impl From<RawRecoveredPublication> for RecoveredPublication {
    fn from(value: RawRecoveredPublication) -> Self {
        Self {
            workspace: value.workspace,
            revision: value.revision,
            member: value.member,
            endpoint: value.endpoint,
            topic: value.topic,
            id: value.id,
            sequence: value.sequence,
            payload: value.payload,
        }
    }
}

fn error(kind: ErrorKind, message: impl Into<String>) -> Error {
    Error {
        kind,
        message: message.into(),
    }
}

fn map_error(message: &str) -> Error {
    let lower = message.to_ascii_lowercase();
    let kind = if lower.contains("invalid or closed") || lower == "node is closed" {
        ErrorKind::Closed
    } else if lower.contains("limit") || lower.contains("capacity") || lower.contains("queue") {
        ErrorKind::Capacity
    } else if lower.contains("storage") || lower.contains("snapshot") || lower.contains("record") {
        ErrorKind::Storage
    } else if lower.contains("cancel") {
        ErrorKind::Cancelled
    } else if lower.contains("transport")
        || lower.contains("peer")
        || lower.contains("address")
        || lower.contains("timeout")
        || lower.contains("route")
        || lower.contains("connection")
    {
        ErrorKind::Transport
    } else if lower.contains("invalid")
        || lower.contains("requires")
        || lower.contains("must ")
        || lower.contains("unknown")
    {
        ErrorKind::InvalidInput
    } else {
        ErrorKind::Internal
    };
    error(kind, message)
}

fn create_required_secret(
    secret: Option<&[u8; 32]>,
    name: &str,
    create: fn(&[u8; 32]) -> std::result::Result<i64, String>,
) -> Result<i64> {
    let secret = secret
        .ok_or_else(|| error(ErrorKind::InvalidInput, format!("{name} requires a secret")))?;
    create(secret).map_err(|message| map_error(&message))
}

#[cfg(test)]
mod group_object_recovery_tests {
    use super::*;

    #[test]
    fn ready_status_preserves_advisory_only_coverage() {
        let ready = parse_group_object_recovery_status(json!({
            "state": "group_object_recovery_ready",
            "peer": vec![1; 32],
            "author": vec![2; 32],
            "revision": 3,
            "topics": ["chat/main"],
            "after": 4,
            "through": 5,
            "packet_count": 1,
            "retained_bytes": 120,
            "attempted": 1,
            "accepted_progress": false,
        }))
        .unwrap();
        assert_eq!(
            ready,
            GroupObjectRecoveryStatus::Ready(GroupObjectRecoveryReady {
                peer: [1; 32],
                author: [2; 32],
                revision: 3,
                topics: vec!["chat/main".into()],
                after: 4,
                through: 5,
                packet_count: 1,
                retained_bytes: 120,
                attempted: 1,
                accepted_progress: false,
            })
        );
        assert!(
            parse_group_object_recovery_status(json!({
                "state": "group_object_recovery_ready",
                "peer": vec![1; 32],
                "author": vec![2; 32],
                "revision": 3,
                "topics": ["chat/main"],
                "after": 4,
                "through": 5,
                "packet_count": 1,
                "retained_bytes": 120,
                "attempted": 1,
                "accepted_progress": true,
            }))
            .is_err()
        );
    }
}
