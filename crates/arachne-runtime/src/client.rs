use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use arachne_api::{ApiError, ErrorCode};

use crate::ops::{self, Op, admission, candidate, invitation, join, management, publication, receive};
use crate::persistence;
use crate::{
    FreshnessAnchor, Session, WorkspacePhase, cancel, close, create_with_options, describe,
    wait_for_work,
};

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
    /// Relay, lookup and deadline overrides. `Default` keeps the profile's.
    pub transport: TransportOptions,
}

/// Transport overrides on top of a `Network` profile. Every field left
/// `None` keeps the profile default.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TransportOptions {
    /// Operator relays. They replace n0's public relays.
    pub relay: Option<OperatorRelay>,
    /// n0's public DNS/Pkarr address lookup and publishing. `Some(false)`
    /// keeps a WAN endpoint away from n0; pair it with `relay`.
    pub public_lookup: Option<bool>,
    /// Deadlines for a slow or constrained link.
    pub timeouts: Option<TransportTimeouts>,
}

/// Relays run by the deployment operator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorRelay {
    /// Relay URLs, for example `https://relay.example.org`.
    pub urls: Vec<String>,
    /// How the relays' TLS certificates are checked.
    pub trust: RelayTrust,
}

/// TLS trust for operator relays.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayTrust {
    /// The built-in WebPKI roots.
    WebPki,
    /// Only these DER-encoded root certificates, for a private CA.
    CustomRoots(Vec<Vec<u8>>),
}

/// Transport deadlines. Each must be nonzero.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub struct TransportTimeouts {
    /// One data exchange or resource admission, including its dial.
    pub operation: std::time::Duration,
    /// One dial.
    pub dial: std::time::Duration,
    /// How long a live broadcast waits for a first overlay neighbor.
    pub gossip_join: std::time::Duration,
    /// How long `close` waits for peers to acknowledge the close. It blocks
    /// the caller, so keep it short. The default is 5 s on every network.
    pub close_drain: std::time::Duration,
}

/// The transport services an endpoint was bound with.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub struct TransportInfo {
    /// n0's public lookup is in use.
    pub public_lookup: bool,
    /// Operator relays replace n0's relays.
    pub operator_relay: bool,
    /// The endpoint can find a peer by key alone (mDNS, n0 lookup or Tor).
    pub peer_id_lookup: bool,
    pub timeouts: TransportTimeouts,
}

impl Network {
    fn profile(self) -> arachne_node::NetworkProfile {
        use arachne_node::NetworkProfile;
        match self {
            Network::Direct => NetworkProfile::Direct,
            Network::Lan => NetworkProfile::Lan,
            Network::Nearby => NetworkProfile::Nearby,
            Network::Wan => NetworkProfile::Wan,
            Network::RelayOnly => NetworkProfile::RelayOnly,
            Network::WanOnly => NetworkProfile::WanOnly,
            #[cfg(feature = "tor")]
            Network::Tor => NetworkProfile::Tor,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Network::Direct => "direct",
            Network::Lan => "LAN",
            Network::Nearby => "nearby",
            Network::Wan => "WAN",
            Network::RelayOnly => "relay-only",
            Network::WanOnly => "WAN-only",
            #[cfg(feature = "tor")]
            Network::Tor => "Tor",
        }
    }
}

impl TransportOptions {
    /// The node options for `network` with these overrides applied.
    fn node_options(&self, network: Network) -> Result<arachne_node::NodeOptions> {
        let invalid = |message: &str| error(ErrorKind::InvalidInput, message);
        let mut options = arachne_node::NodeOptions::new(network.profile());
        if let Some(lookup) = self.public_lookup {
            options.public_lookup = lookup;
        }
        if let Some(timeouts) = self.timeouts {
            if timeouts.operation.is_zero()
                || timeouts.dial.is_zero()
                || timeouts.gossip_join.is_zero()
                || timeouts.close_drain.is_zero()
            {
                return Err(invalid("transport timeouts must be nonzero"));
            }
            options.timeouts = arachne_node::Timeouts {
                operation: timeouts.operation,
                dial: timeouts.dial,
                gossip_join: timeouts.gossip_join,
                close_drain: timeouts.close_drain,
            };
        }
        if let Some(relay) = &self.relay {
            let roots = match &relay.trust {
                RelayTrust::WebPki => Vec::new(),
                RelayTrust::CustomRoots(roots) if roots.is_empty() => {
                    return Err(invalid("operator relay custom roots must not be empty"));
                }
                RelayTrust::CustomRoots(roots) => roots.clone(),
            };
            options.relay = Some(
                arachne_node::RelayOptions::operator(relay.urls.iter().map(String::as_str), roots)
                    .map_err(invalid)?,
            );
        }
        Ok(options)
    }
}

/// A coarse error class. It is derived from [`Error::code`] by a fixed
/// table (see [`ErrorKind::of`]); new code should read the code.
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

impl ErrorKind {
    /// The class of a code. This is the whole table; there is no text guess.
    ///
    /// | Codes                         | Kind           |
    /// | ----------------------------- | -------------- |
    /// | 1 closed                      | `Closed`       |
    /// | 2 cancelled, 3 deadline       | `Cancelled`    |
    /// | 100-199 input and state       | `InvalidInput` |
    /// | 200-299 capacity and limits   | `Capacity`     |
    /// | 300-399 storage, candidates   | `Storage`      |
    /// | 400-499 transport             | `Transport`    |
    /// | 500-699 authorization, group  | `InvalidInput` |
    /// | 900 internal                  | `Internal`     |
    ///
    /// One exception: the runtime reports an unknown session handle as
    /// `InvalidId`; for the client's own handle that means the session was
    /// closed, so it is `Closed`.
    pub fn of(error: &ApiError) -> Self {
        if *error == crate::errors::unknown_handle() {
            return ErrorKind::Closed;
        }
        match error.code().as_u32() {
            1 => ErrorKind::Closed,
            2 | 3 => ErrorKind::Cancelled,
            100..=199 | 500..=699 => ErrorKind::InvalidInput,
            200..=299 => ErrorKind::Capacity,
            300..=399 => ErrorKind::Storage,
            400..=499 => ErrorKind::Transport,
            _ => ErrorKind::Internal,
        }
    }
}

/// A client error: the runtime's typed [`ApiError`] and its coarse kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    error: ApiError,
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    /// The stable code. Programs branch on this.
    pub fn code(&self) -> ErrorCode {
        self.error.code()
    }

    /// The typed error from the runtime.
    pub fn api_error(&self) -> &ApiError {
        &self.error
    }

}

impl From<ApiError> for Error {
    fn from(error: ApiError) -> Self {
        Self {
            kind: ErrorKind::of(&error),
            message: crate::errors::legacy_text(&error),
            error,
        }
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
    pub transport: TransportInfo,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RouteHint {
    pub peer: [u8; 32],
    pub address: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdmissionReply {
    pub workspace: [u8; 32],
    pub epoch: u64,
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
    pub authorization: AdmissionAuthorization,
}

/// The kind of invitation link to register.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvitationKind {
    /// Anyone with the link may join until it expires or is disabled.
    Reusable,
    /// One person; an administrator approves the first join request.
    Personal,
    /// One person; the first join request is approved automatically.
    PersonalAutomatic,
    /// One person asks for access; an administrator approves or declines.
    RequestAccess,
}

/// An administrator action on a member or an invitation link.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberAction {
    Promote([u8; 32]),
    Demote([u8; 32]),
    Remove([u8; 32]),
    DisableInvitation([u8; 32]),
}

/// One registered invitation link and its controls.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvitationControl {
    pub number: usize,
    pub key: [u8; 32],
    pub expires_at: u64,
    pub enabled: bool,
    pub personal: bool,
    pub automatic: bool,
    pub request_access: bool,
    pub approved: bool,
}

/// This member's removal, adopted. The session has ended.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemovedMembership {
    pub workspace: [u8; 32],
    pub epoch: u64,
    pub member: [u8; 32],
    pub commit_digest: [u8; 32],
}

/// A nearby endpoint and the name it announced, if it answered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NearbyEndpoint {
    pub endpoint: [u8; 32],
    pub name: Option<String>,
}

/// How a nearby workspace admits people.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NearbyMode {
    /// A person asks; an administrator approves.
    RequestAccess,
    /// Anyone nearby with the link may join.
    OpenJoining,
}

/// One workspace a nearby device advertises.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NearbyAdvertisement {
    pub peer: [u8; 32],
    pub mode: NearbyMode,
    pub workspace_name: Option<String>,
    pub invitation: Vec<u8>,
}

/// The result of one nearby workspace scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NearbyScan {
    pub workspaces: Vec<NearbyAdvertisement>,
    pub endpoints_checked: usize,
    /// The scan did not reach every nearby endpoint.
    pub limited: bool,
}

/// The outcome of one presence round.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresenceRound {
    /// A member this round started a membership query with.
    pub sync_peer: Option<[u8; 32]>,
    /// Answers that failed, and the first failure's text.
    pub response_errors: u32,
    pub response_error: Option<String>,
}

/// A verified invitation checkpoint and the member that served it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvitationCheckpoint {
    pub workspace: [u8; 32],
    pub checkpoint: Vec<u8>,
    pub peer: [u8; 32],
}

/// One admission request that waits for an administrator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionApproval {
    pub attempt_id: [u8; 32],
    pub endpoint: [u8; 32],
    pub request: Vec<u8>,
    pub display_name: Option<String>,
    /// The invitation approves automatically once an administrator binds it.
    pub automatic: bool,
    /// The host was told about this request.
    pub delivered: bool,
    /// The administrator's UI marked it as seen.
    pub acknowledged: bool,
}

/// One page of pending approvals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionApprovalPage {
    pub approvals: Vec<AdmissionApproval>,
    /// No more rows after this page.
    pub complete: bool,
    /// Pass as `after` for the next page.
    pub next_after: Option<[u8; 32]>,
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
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DurationSummary {
    pub count: u64,
    pub total_us: u64,
    pub max_us: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControlTimingMetrics {
    pub inquiry: DurationSummary,
    pub host_wait: DurationSummary,
    pub host_service: DurationSummary,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeliveryFailure {
    pub peer: [u8; 32],
    pub error: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicationCurrent {
    pub selector: [u8; 32],
    pub replacement_key: [u8; 32],
    /// Unix seconds (UTC), by the author's clock. Receivers and holders allow
    /// `arachne_delivery::EXPIRY_SKEW_SECONDS` of clock difference.
    pub expires_at: u64,
    pub tombstone: bool,
}

/// A protected incoming publication staged for caller-owned save/adopt.
/// The authenticated plaintext is withheld until `adopt_protected_reception`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedReceptionCandidate {
    pub workspace: [u8; 32],
    pub snapshot: Vec<u8>,
}

/// An authenticated pending object from the durable inbox.
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
    /// Author sender counter; identifies the object for acknowledgement.
    pub counter: u64,
    /// Present for a latest-value (current) publication.
    pub current: Option<PublicationCurrent>,
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
pub struct RecoveryRangeRequest {
    pub peer: Option<[u8; 32]>,
    pub author: Option<[u8; 32]>,
    pub revision: u64,
    pub topics: Vec<String>,
    pub after: Option<u64>,
    pub through: Option<u64>,
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
    pub durable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryStage {
    Candidate(RecoveryCandidate),
    AlreadyCovered,
    NoNewObjects,
    /// Automatic recovery: nothing fits the pending bounds until the
    /// application acknowledges or rejects pending objects. No progress was
    /// claimed; request the range again after draining.
    AwaitingApplication,
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
        if config.network != Network::Direct && config.secret.is_none() {
            return Err(error(
                ErrorKind::InvalidInput,
                format!("{} requires a secret", config.network.name()),
            ));
        }
        let options = config.transport.node_options(config.network)?;
        let handle = create_with_options(config.secret.as_ref(), options)
            .map_err(legacy)?;
        Ok(Self {
            handle: Some(handle),
        })
    }

    pub fn endpoint(&self) -> Result<EndpointInfo> {
        let description = describe(self.handle()?).map_err(legacy)?;
        serde_json::from_str(&description).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid endpoint description: {parse_error}"),
            )
        })
    }

    pub fn workspace_state(&self) -> Result<WorkspaceState> {
        let endpoint_key = self.endpoint()?.endpoint_key;
        let state = self.call(Op::WorkspaceState, ops::workspace::state)?;
        Ok(WorkspaceState {
            endpoint_key,
            workspace: state.workspace,
            workspace_ready: state.workspace_ready,
            durable: state.durable,
            phase: state.activity.phase,
            reason: state.activity.reason,
        })
    }

    pub fn create_workspace(
        &self,
        display_name: &str,
        workspace_name: Option<&str>,
    ) -> Result<WorkspaceInfo> {
        let opened = self.call(Op::CreateWorkspace, |session| {
            ops::workspace::create(
                session,
                ops::workspace::CreateArgs {
                    display_name: display_name.to_owned(),
                    workspace_name: workspace_name.map(str::to_owned),
                },
            )
        })?;
        Ok(opened_info(opened))
    }

    /// Seal the workspace for a host without native record storage.
    pub fn seal_workspace(&self) -> Result<WorkspaceCandidate> {
        let sealed = self.call(Op::SealWorkspace, ops::workspace::seal)?;
        Ok(WorkspaceCandidate {
            workspace: sealed.workspace,
            snapshot: stored_output(sealed.snapshot)?,
        })
    }

    /// Restore a sealed workspace into this empty session. A sealed removal
    /// ends the session and gives `WrongState`.
    pub fn restore_workspace(&self, workspace: [u8; 32], snapshot: &[u8]) -> Result<WorkspaceInfo> {
        stored_input(snapshot)?;
        let restored = self.call(Op::RestoreWorkspace, |session| {
            ops::workspace::restore(
                session,
                ops::workspace::RestoreArgs {
                    workspace,
                    snapshot: snapshot.to_vec(),
                },
            )
        })?;
        match restored {
            ops::workspace::RestoreReply::Opened(opened) => Ok(opened_info(opened)),
            ops::workspace::RestoreReply::Removed(_) => Err(Error::from(ApiError::wrong_state(
                "this member was removed",
            ))),
        }
    }

    /// Forget all workspace state. Returns whether anything changed.
    pub fn reset_workspace(&self) -> Result<bool> {
        Ok(self.call(Op::ResetWorkspace, ops::workspace::reset)?.changed)
    }

    /// Drop the staged candidate. Returns whether one was staged.
    pub fn discard_workspace_candidate(&self) -> Result<bool> {
        Ok(self
            .call(Op::DiscardWorkspaceCandidate, ops::workspace::discard_candidate)?
            .discarded)
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
        let pending = self.call(Op::BeginJoin, |session| {
            join::begin(
                session,
                join::BeginJoinArgs {
                    invitation: invitation.to_vec(),
                    checkpoint: checkpoint.to_vec(),
                    display_name: display_name.to_owned(),
                    peers: peers.to_vec(),
                },
            )
        })?;
        join_request(pending)
    }

    /// Advance a join restored from native record storage.
    pub fn drive_join(&self) -> Result<Value> {
        self.call(Op::DriveJoin, join::drive)
    }

    /// Ask one member for admission now (the host-driven path; `drive_join`
    /// does this natively). The reply is the member's answer, passed on as
    /// an open event (typed in ADR step 4).
    pub fn request_admission(&self, peer: [u8; 32]) -> Result<Value> {
        self.call(Op::RequestAdmission, |session| {
            join::request_admission(session, join::RequestAdmissionArgs { peer })
        })
    }

    /// Fetch and verify the current checkpoint of a compact invitation from
    /// one of up to three members.
    pub fn fetch_invitation_checkpoint(
        &self,
        invitation: &[u8],
        peers: &[[u8; 32]],
    ) -> Result<InvitationCheckpoint> {
        let found = self.call(Op::FetchInvitationCheckpoint, |session| {
            join::fetch_checkpoint(
                session,
                join::FetchCheckpointArgs {
                    peer: None,
                    peers: peers.to_vec(),
                    invitation: invitation.to_vec(),
                },
            )
        })?;
        Ok(InvitationCheckpoint {
            workspace: found.workspace,
            checkpoint: found.checkpoint,
            peer: found.peer,
        })
    }

    /// Seal the pending join for a host without native storage.
    pub fn seal_pending_join(&self) -> Result<WorkspaceCandidate> {
        let sealed = self.call(Op::SealPendingJoin, join::seal_pending)?;
        Ok(WorkspaceCandidate {
            workspace: sealed.workspace,
            snapshot: sealed.snapshot,
        })
    }

    /// Restore a pending join sealed by `seal_pending_join`.
    pub fn restore_pending_join(&self, workspace: [u8; 32], snapshot: &[u8]) -> Result<JoinRequest> {
        stored_input(snapshot)?;
        let pending = self.call(Op::RestorePendingJoin, |session| {
            join::restore_pending(
                session,
                join::RestorePendingJoinArgs {
                    workspace,
                    snapshot: snapshot.to_vec(),
                },
            )
        })?;
        join_request(pending)
    }

    pub fn stage_admission(
        &self,
        authenticated_endpoint: [u8; 32],
        request: &[u8],
    ) -> Result<WorkspaceCandidate> {
        let staged = self.call(Op::StageAdmission, |session| {
            admission::stage(
                session,
                admission::AdmissionArgs {
                    authenticated_endpoint,
                    request: request.to_vec(),
                },
            )
        })?;
        Ok(WorkspaceCandidate {
            workspace: staged.workspace,
            snapshot: stored_output(staged.snapshot)?,
        })
    }

    pub fn adopt_admission(&self, snapshot: &[u8]) -> Result<WorkspaceInfo> {
        self.adopt(Op::AdoptAdmission, candidate::adopt_admission, snapshot)
            .map(workspace_info)
    }

    pub fn retained_admission(
        &self,
        authenticated_endpoint: [u8; 32],
        request: &[u8],
    ) -> Result<AdmissionReply> {
        self.call(Op::RetainedAdmission, |session| {
            admission::retained(
                session,
                admission::AdmissionArgs {
                    authenticated_endpoint,
                    request: request.to_vec(),
                },
            )
        })
    }

    /// Drive one owner transition with native record storage: serve one
    /// queued control request, or stage, save and adopt the next admission
    /// batch, then answer its requesters. The reply is an open event; it is
    /// typed with `Event` in ADR step 4.
    pub fn drive_workspace(&self) -> Result<Value> {
        self.call(Op::DriveWorkspace, admission::drive_workspace)
    }

    /// One page of admission requests that wait for an administrator,
    /// after `after` (an attempt ID), at most `limit` (1 to 64, default 64).
    pub fn admission_approvals(
        &self,
        after: Option<[u8; 32]>,
        limit: Option<usize>,
    ) -> Result<AdmissionApprovalPage> {
        let page = self.call(Op::ListAdmissionApprovals, |session| {
            admission::list_approvals(session, admission::ListApprovalsArgs { after, limit })
        })?;
        Ok(AdmissionApprovalPage {
            approvals: page
                .approvals
                .into_iter()
                .map(|row| AdmissionApproval {
                    attempt_id: row.attempt_id,
                    endpoint: row.endpoint,
                    request: row.request,
                    display_name: row.display_name,
                    automatic: row.automatic,
                    delivered: row.delivered,
                    acknowledged: row.acknowledged,
                })
                .collect(),
            complete: page.complete,
            next_after: page.next_after,
        })
    }

    /// Mark a pending approval as seen by the administrator's UI.
    pub fn acknowledge_admission_approval(&self, attempt_id: [u8; 32]) -> Result<()> {
        self.call(Op::AcknowledgeAdmissionApproval, |session| {
            admission::acknowledge_approval(session, admission::AcknowledgeApprovalArgs { attempt_id })
        })?;
        Ok(())
    }

    /// Answer the held admission, leave or offer exchange after its
    /// transition is durable. `false`: the requester expired; its result
    /// stays retained for a retry.
    pub fn send_admission_reply(&self) -> Result<bool> {
        Ok(self.call(Op::SendAdmissionReply, admission::send_reply)?.queued)
    }

    pub fn stage_join(
        &self,
        welcome: &[u8],
        commits: &[JoinAdmissionStep],
    ) -> Result<WorkspaceCandidate> {
        if welcome.len() > arachne_security::MAX_WELCOME {
            return Err(Error::from(ApiError::invalid_input(
                "request",
                "Welcome exceeds binary input bound",
            )));
        }
        let commits = commits
            .iter()
            .map(|step| {
                crate::membership::JoinStep::admission(
                    step.commit.clone(),
                    step.authorization.invitation_key,
                    step.authorization.grant_signature.clone(),
                    step.authorization.redemption_signature.clone(),
                )
            })
            .collect();
        let staged = self.call(Op::StageJoin, |session| {
            join::stage(
                session,
                join::StageJoinArgs {
                    commits,
                    welcome: welcome.to_vec(),
                },
            )
        })?;
        Ok(WorkspaceCandidate {
            workspace: staged.workspace,
            snapshot: stored_output(staged.snapshot)?,
        })
    }

    pub fn adopt_join(&self, snapshot: &[u8]) -> Result<WorkspaceInfo> {
        self.adopt(Op::AdoptJoin, candidate::adopt_join, snapshot)
            .map(workspace_info)
    }

    /// Enable encrypted native storage for this client's workspace.
    pub fn enable_record_storage(&self, path: &Path, root: &[u8; 32]) -> Result<()> {
        self.stored(|session| persistence::enable(session, path, root))
    }

    /// Restore a workspace from encrypted native storage.
    pub fn restore_record_storage(
        &self,
        path: &Path,
        root: &[u8; 32],
        workspace: [u8; 32],
    ) -> Result<Value> {
        self.restore_record_storage_with_freshness(path, root, workspace, None)
    }

    /// Restore, rejecting a store that does not match the host's saved anchor.
    pub fn restore_record_storage_with_freshness(
        &self,
        path: &Path,
        root: &[u8; 32],
        workspace: [u8; 32],
        expected: Option<FreshnessAnchor>,
    ) -> Result<Value> {
        self.stored(|session| {
            let restored = persistence::restore(session, path, root, workspace, expected)?;
            serde_json::to_value(restored).map_err(crate::errors::encode)
        })
    }

    /// Anchor after the latest native commit. With record storage enabled, read
    /// it after every call and save it outside the database.
    pub fn record_freshness(&self) -> Result<FreshnessAnchor> {
        self.stored(persistence::freshness)
    }

    /// Save the exact staged snapshot before adopting it.
    pub fn save_candidate(&self, snapshot: &[u8]) -> Result<()> {
        self.stored(|session| persistence::commit_candidate(session, snapshot))
    }

    /// A native storage call. These report every failure as `Storage`, as
    /// before; `code()` gives the exact failure.
    fn stored<T>(
        &self,
        body: impl FnOnce(&mut Session) -> std::result::Result<T, ApiError>,
    ) -> Result<T> {
        persistence::with_session(self.handle()?, body).map_err(|api| {
            let mut error = Error::from(api);
            if error.kind != ErrorKind::Closed {
                error.kind = ErrorKind::Storage;
            }
            error
        })
    }

    pub fn member_roster(&self) -> Result<MemberRoster> {
        let raw = self.call(Op::MemberRoster, |session| {
            management::member_roster(session, management::RosterArgs::default())
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
        self.call(Op::UseServiceProfile, management::use_service_profile)?;
        Ok(())
    }

    /// Register a reusable invitation link in shared policy. The link is
    /// released only by `adopt_invitation`, after the candidate is saved.
    pub fn stage_invitation(&self, expires_at: u64) -> Result<WorkspaceCandidate> {
        self.stage_invitation_of(expires_at, InvitationKind::Reusable)
    }

    /// Register an invitation link of `kind`. Adopt it with
    /// `adopt_invitation` after the candidate is saved.
    pub fn stage_invitation_of(
        &self,
        expires_at: u64,
        kind: InvitationKind,
    ) -> Result<WorkspaceCandidate> {
        let (personal, automatic, request_access) = match kind {
            InvitationKind::Reusable => (false, false, false),
            InvitationKind::Personal => (true, false, false),
            InvitationKind::PersonalAutomatic => (true, true, false),
            InvitationKind::RequestAccess => (true, false, true),
        };
        let staged = self.call(Op::StageInvitation, |session| {
            invitation::stage(
                session,
                invitation::StageInvitationArgs {
                    expires_at,
                    personal,
                    automatic,
                    request_access,
                },
            )
        })?;
        candidate_of(staged)
    }

    /// Approve (bind) a personal invitation for one join request. Adopt the
    /// candidate with `adopt_admission`.
    pub fn stage_invitation_approval(
        &self,
        request: &[u8],
        attempt_id: Option<[u8; 32]>,
    ) -> Result<WorkspaceCandidate> {
        let staged = self.call(Op::StageInvitationApproval, |session| {
            invitation::stage_approval(
                session,
                invitation::DecisionArgs {
                    request: request.to_vec(),
                    attempt_id,
                },
            )
        })?;
        candidate_of(staged)
    }

    /// Decline a personal invitation request. Adopt the candidate with
    /// `adopt_admission`.
    pub fn stage_invitation_decline(
        &self,
        request: &[u8],
        attempt_id: Option<[u8; 32]>,
    ) -> Result<WorkspaceCandidate> {
        let staged = self.call(Op::StageInvitationDecline, |session| {
            invitation::stage_decline(
                session,
                invitation::DecisionArgs {
                    request: request.to_vec(),
                    attempt_id,
                },
            )
        })?;
        candidate_of(staged)
    }

    /// The registered invitation links, numbered for people.
    pub fn invitation_controls(&self) -> Result<Vec<InvitationControl>> {
        let reply = self.call(Op::InvitationControls, invitation::controls)?;
        Ok(reply
            .invitations
            .into_iter()
            .map(|row| InvitationControl {
                number: row.number,
                key: row.key,
                expires_at: row.expires_at,
                enabled: row.enabled,
                personal: row.personal,
                automatic: row.automatic,
                request_access: row.request_access,
                approved: row.approved,
            })
            .collect())
    }

    /// Stage an administrator action. Adopt it with `adopt_admission`.
    pub fn stage_management(&self, action: MemberAction) -> Result<WorkspaceCandidate> {
        use crate::membership::WireManagement;
        let action = match action {
            MemberAction::Promote(member) => WireManagement::Promote(member),
            MemberAction::Demote(member) => WireManagement::Demote(member),
            MemberAction::Remove(member) => WireManagement::Remove(member),
            MemberAction::DisableInvitation(key) => WireManagement::DisableInvitation(key),
        };
        let staged = self.call(Op::StageManagement, |session| {
            management::stage(session, management::ManagementArgs { action })
        })?;
        candidate_of(staged)
    }

    /// Rename the workspace. Adopt the candidate with `adopt_admission`.
    pub fn stage_workspace_name(&self, workspace_name: &str) -> Result<WorkspaceCandidate> {
        let staged = self.call(Op::StageWorkspaceName, |session| {
            management::stage_workspace_name(
                session,
                management::WorkspaceNameArgs {
                    workspace_name: workspace_name.to_owned(),
                },
            )
        })?;
        candidate_of(staged)
    }

    /// Leave through another member, who commits the departure. Adopt the
    /// staged removal with `adopt_removal`; that ends the session.
    pub fn leave_via_peer(&self, peer: [u8; 32]) -> Result<WorkspaceCandidate> {
        let staged = self.call(Op::LeaveViaPeer, |session| {
            management::leave_via_peer(session, management::PeerArgs { peer })
        })?;
        change_candidate(staged)
    }

    /// The last member leaves alone. Adopt with `adopt_removal`.
    pub fn stage_solo_leave(&self) -> Result<WorkspaceCandidate> {
        let staged = self.call(Op::StageSoloLeave, management::stage_solo_leave)?;
        Ok(WorkspaceCandidate {
            workspace: staged.workspace,
            snapshot: stored_output(staged.snapshot)?,
        })
    }

    /// Adopt a saved removal of this member. The session ends: later calls
    /// give `Closed`.
    pub fn adopt_removal(&self, snapshot: &[u8]) -> Result<RemovedMembership> {
        stored_input(snapshot)?;
        let reply = self.call(Op::AdoptAdmission, |session| {
            candidate::adopt_admission(
                session,
                candidate::AdoptArgs {
                    snapshot: snapshot.to_vec(),
                },
            )
        })?;
        match reply {
            candidate::AdoptReply::Removed(removed) => Ok(RemovedMembership {
                workspace: removed.workspace,
                epoch: removed.epoch,
                member: removed.member.id,
                commit_digest: removed.commit_digest,
            }),
            candidate::AdoptReply::Adopted(_) => Err(Error::from(ApiError::wrong_state(
                "the candidate was not a removal",
            ))),
        }
    }

    /// Adopt a staged invitation registration and return its bearer link.
    pub fn adopt_invitation(&self, snapshot: &[u8]) -> Result<InvitationInfo> {
        let adopted = self.adopt(Op::AdoptAdmission, candidate::adopt_admission, snapshot)?;
        let issued = adopted.issued_invitation.ok_or_else(|| {
            error(ErrorKind::InvalidInput, "candidate did not issue an invitation")
        })?;
        Ok(issued)
    }

    pub fn inspect_invitation(
        &self,
        invitation: &[u8],
        checkpoint: &[u8],
    ) -> Result<InvitationDetails> {
        let raw = self.call(Op::InspectInvitation, |session| {
            invitation::inspect(
                session,
                invitation::InspectArgs {
                    invitation: invitation.to_vec(),
                    checkpoint: checkpoint.to_vec(),
                },
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
        let raw = self.call(Op::WorkspaceMetrics, ops::workspace::metrics)?;
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
                    route: match path.route {
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

    /// One presence round with the workspace's members: send this node's
    /// head to each and read their answers. `announce` marks a restart.
    pub fn poll_presence(&self, announce: bool) -> Result<PresenceRound> {
        let round = self.call(Op::PollWorkspacePresence, |session| {
            ops::membership::poll_presence(session, ops::membership::PresenceArgs { announce })
        })?;
        Ok(PresenceRound {
            sync_peer: round.sync_peer,
            response_errors: round.response_errors,
            response_error: round.response_error,
        })
    }

    /// Ask `peer` for the membership step after this node's epoch. Read the
    /// answer with `poll_membership_update`.
    pub fn fetch_membership_update(&self, peer: [u8; 32], replace_pending: bool) -> Result<()> {
        self.call(Op::FetchMembershipUpdate, |session| {
            ops::membership::fetch_update(
                session,
                ops::membership::FetchUpdateArgs {
                    peer,
                    replace_pending,
                },
            )
        })?;
        Ok(())
    }

    /// The answer to `fetch_membership_update`, once it arrived. The value
    /// is an open event (typed with `Event` in ADR step 4).
    pub fn poll_membership_update(&self) -> Result<Option<Value>> {
        let event = self.call(Op::PollMembershipUpdate, ops::membership::poll_update)?;
        Ok((!event.is_null()).then_some(event))
    }

    /// Nearby endpoints on the local network and the names they announce.
    pub fn nearby_endpoints(&self) -> Result<Vec<NearbyEndpoint>> {
        let found = self.call(Op::NearbyEndpoints, ops::nearby::endpoints)?;
        Ok(found
            .endpoints
            .iter()
            .map(|endpoint| NearbyEndpoint {
                endpoint: *endpoint,
                name: found
                    .names
                    .iter()
                    .find(|name| name.id == *endpoint)
                    .map(|name| name.name.clone()),
            })
            .collect())
    }

    /// Workspaces that nearby devices advertise.
    pub fn nearby_workspaces(&self) -> Result<NearbyScan> {
        let found = self.call(Op::NearbyWorkspaces, ops::nearby::workspaces)?;
        Ok(NearbyScan {
            workspaces: found
                .workspaces
                .into_iter()
                .map(|workspace| NearbyAdvertisement {
                    peer: workspace.peer,
                    mode: if workspace.mode == "request_access" {
                        NearbyMode::RequestAccess
                    } else {
                        NearbyMode::OpenJoining
                    },
                    workspace_name: workspace.workspace_name,
                    invitation: workspace.invitation,
                })
                .collect(),
            endpoints_checked: found.endpoints_checked,
            limited: found.limited,
        })
    }

    /// Advertise one workspace's invitation to nearby devices. Returns
    /// whether this device now advertises anything.
    pub fn advertise_nearby_workspace(
        &self,
        workspace: Option<[u8; 32]>,
        mode: NearbyMode,
        invitation: &[u8],
        workspace_name: Option<&str>,
    ) -> Result<bool> {
        self.nearby_advertisement(ops::nearby::AdvertiseArgs {
            mode: Some(
                match mode {
                    NearbyMode::RequestAccess => "request_access",
                    NearbyMode::OpenJoining => "open_joining",
                }
                .to_owned(),
            ),
            invitation: invitation.to_vec(),
            workspace_name: workspace_name.map(str::to_owned),
            workspace,
        })
    }

    /// Stop advertising `workspace`, or every workspace for `None`.
    pub fn withdraw_nearby_workspace(&self, workspace: Option<[u8; 32]>) -> Result<bool> {
        self.nearby_advertisement(ops::nearby::AdvertiseArgs {
            workspace,
            ..Default::default()
        })
    }

    fn nearby_advertisement(&self, args: ops::nearby::AdvertiseArgs) -> Result<bool> {
        let state = self.call(Op::SetNearbyWorkspace, |session| {
            ops::nearby::advertise(session, args)
        })?;
        Ok(state.state == "nearby_workspace_advertised")
    }

    /// The name this device answers to nearby identity asks.
    pub fn set_nearby_identity(&self, name: &str) -> Result<()> {
        self.call(Op::SetNearbyIdentity, |session| {
            ops::nearby::set_identity(
                session,
                ops::nearby::IdentityArgs {
                    name: name.to_owned(),
                },
            )
        })?;
        Ok(())
    }

    /// Hand an invitation to one nearby device.
    pub fn send_nearby_invitation(&self, peer: [u8; 32], invitation: &[u8]) -> Result<()> {
        self.call(Op::SendNearbyInvitation, |session| {
            ops::nearby::send_invitation(
                session,
                ops::nearby::SendInvitationArgs {
                    peer,
                    invitation: invitation.to_vec(),
                },
            )
        })?;
        Ok(())
    }

    pub fn network_change(&self) -> Result<()> {
        self.call(Op::NetworkChange, ops::debug::network_change)?;
        Ok(())
    }

    pub fn cancel(&self) -> Result<()> {
        cancel(self.handle()?).map_err(legacy)
    }

    pub fn wait_for_work(&self) -> Result<bool> {
        wait_for_work(self.handle()?).map_err(legacy)
    }

    /// Service one queued peer-control exchange and report whether one was served.
    pub fn poll_control(&self) -> Result<bool> {
        let event = self.call(Op::PollAdmission, |session| {
            admission::poll(session, admission::PollAdmissionArgs { profile: false })
        })?;
        Ok(!event.is_null())
    }

    pub fn add_address_hint(&self, peer: [u8; 32], address: &str) -> Result<()> {
        self.call(Op::AddAddressHint, |session| {
            ops::policy::add_address_hint(
                session,
                ops::policy::AddressHintArgs {
                    peer,
                    address: address.to_owned(),
                },
            )
        })
    }

    /// Fixture: install a caller-made routing policy. Rejected once the
    /// session owns a workspace.
    pub fn install_policy(
        &self,
        workspace: [u8; 32],
        revision: u64,
        endpoints: &[PeerPolicy],
    ) -> Result<()> {
        let endpoints = endpoints
            .iter()
            .map(|policy| ops::policy::EndpointPolicy {
                peer: policy.peer,
                publish: policy.publish.clone(),
                subscribe: policy.subscribe.clone(),
            })
            .collect();
        self.call(Op::InstallVerifiedPolicy, |session| {
            ops::policy::install_verified_policy(
                session,
                ops::policy::VerifiedPolicyArgs {
                    workspace,
                    revision,
                    endpoints,
                },
            )
        })
    }

    /// Route every topic between all members at `revision` (epoch + 1).
    pub fn install_workspace_policy(&self, revision: u64) -> Result<()> {
        self.call(Op::InstallWorkspacePolicy, |session| {
            ops::policy::install_workspace_policy(
                session,
                ops::policy::WorkspacePolicyArgs { revision },
            )
        })?;
        Ok(())
    }

    /// Route only `topics` between all members at `revision`.
    pub fn install_member_policy(&self, revision: u64, topics: &[&str]) -> Result<()> {
        self.call(Op::InstallMemberPolicy, |session| {
            ops::policy::install_member_policy(
                session,
                ops::policy::MemberPolicyArgs {
                    revision,
                    topics: topics.iter().map(|topic| (*topic).to_owned()).collect(),
                },
            )
        })?;
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
        let staged = self.call(Op::StageNetworkPublication, |session| {
            publication::stage(
                session,
                publication::StagePublicationArgs {
                    workspace: Some(workspace),
                    revision,
                    topic: topic.to_owned(),
                    id,
                    payload,
                    recipients: Vec::new(),
                    current: current.map(|current| publication::CurrentPublication {
                        selector: current.selector,
                        replacement_key: current.replacement_key,
                        expires_at: current.expires_at,
                        tombstone: current.tombstone,
                    }),
                    bulk: false,
                },
            )
        })?;
        if staged.workspace != workspace {
            return Err(error(
                ErrorKind::Internal,
                "publication candidate workspace mismatch",
            ));
        }
        Ok(PublicationCandidate {
            workspace: staged.workspace,
            snapshot: stored_output(staged.snapshot)?,
        })
    }

    pub fn adopt_protected_publication(&self, snapshot: &[u8]) -> Result<DeliveryReport> {
        let adopted = self.adopt(Op::AdoptPublication, candidate::adopt_publication, snapshot)?;
        let outcome = adopted
            .publication
            .ok_or_else(|| error(ErrorKind::Internal, "publication result has no admission"))?;
        if let Some(message) = outcome.network_error {
            return Err(error(ErrorKind::Transport, message));
        }
        outcome
            .admission
            .ok_or_else(|| error(ErrorKind::Internal, "publication result has no admission"))
    }

    /// Stage one protected incoming publication without exposing its plaintext.
    /// Save the exact snapshot before adoption whenever record storage is enabled.
    pub fn poll_protected(&self) -> Result<Option<ProtectedReceptionCandidate>> {
        let staged = self.call(Op::PollProtected, receive::poll_protected)?;
        staged
            .map(|staged| {
                Ok(ProtectedReceptionCandidate {
                    workspace: staged.workspace,
                    snapshot: stored_output(staged.snapshot)?,
                })
            })
            .transpose()
    }

    /// Adopt a staged inbox candidate: a reception from `poll_protected`, or an
    /// acknowledgement or rejection. A received object then waits in the
    /// durable inbox; read it with `poll_pending_object`.
    pub fn adopt_protected_reception(&self, snapshot: &[u8]) -> Result<()> {
        self.adopt(Op::AdoptReception, candidate::adopt_reception, snapshot)?;
        Ok(())
    }

    /// The next authenticated object that the application has not yet
    /// acknowledged or rejected. It stays pending (also after a restart) until
    /// an acknowledgement or rejection is adopted: delivery is at least once.
    pub fn poll_pending_object(&self) -> Result<Option<ReceivedProtectedPublication>> {
        let pending = self.call(Op::PollPendingObject, |session| {
            receive::poll_pending(session, receive::PollPendingArgs::default())
        })?;
        Ok(pending.map(|pending| ReceivedProtectedPublication {
            workspace: pending.workspace,
            revision: pending.revision,
            member: pending.member,
            endpoint: pending.endpoint,
            topic: pending.topic,
            id: pending.id,
            sequence: pending.sequence,
            payload: pending.payload,
            recipients: pending.recipients,
            counter: pending.counter,
            current: pending.current,
        }))
    }

    /// Stage the application's durable acceptance of a pending object. Save
    /// the snapshot, then `adopt_protected_reception`.
    pub fn stage_object_acknowledgement(
        &self,
        object: &ReceivedProtectedPublication,
    ) -> Result<ProtectedReceptionCandidate> {
        self.stage_inbox_resolution(Op::StageObjectAcknowledgement, receive::acknowledge, object)
    }

    /// Stage a permanent application rejection of a pending object. Its
    /// identity stays recorded, so it is never delivered again.
    pub fn stage_object_rejection(
        &self,
        object: &ReceivedProtectedPublication,
    ) -> Result<ProtectedReceptionCandidate> {
        self.stage_inbox_resolution(Op::StageObjectRejection, receive::reject, object)
    }

    fn stage_inbox_resolution(
        &self,
        op: Op,
        stage: fn(&mut Session, receive::ResolveArgs) -> std::result::Result<publication::StagedObject, ApiError>,
        object: &ReceivedProtectedPublication,
    ) -> Result<ProtectedReceptionCandidate> {
        let staged = self.call(op, |session| {
            stage(
                session,
                receive::ResolveArgs {
                    member: object.member,
                    topic: object.topic.clone(),
                    counter: object.counter,
                    id: object.id,
                },
            )
        })?;
        Ok(ProtectedReceptionCandidate {
            workspace: staged.workspace,
            snapshot: stored_output(staged.snapshot)?,
        })
    }

    pub fn set_interest(
        &self,
        workspace: [u8; 32],
        revision: u64,
        topic: &str,
        subscribed: bool,
    ) -> Result<()> {
        self.call(Op::SetInterest, |session| {
            ops::policy::set_interest(
                session,
                ops::policy::InterestArgs {
                    workspace,
                    revision,
                    topic: topic.to_owned(),
                    subscribed,
                },
            )
        })?;
        Ok(())
    }

    pub fn poll_interest(&self) -> Result<Option<InterestObservation>> {
        // The interest outcome is still an open event (typed in ADR step 4).
        let response = self.call(Op::PollInterest, ops::policy::poll_interest)?;
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

    /// Fixture: an unprotected publication. Rejected once the session owns
    /// a workspace.
    pub fn publish(
        &self,
        workspace: [u8; 32],
        revision: u64,
        topic: &str,
        payload: Vec<u8>,
    ) -> Result<DeliveryReport> {
        self.call(Op::Publish, |session| {
            ops::policy::publish(
                session,
                ops::policy::PublishArgs {
                    workspace,
                    revision,
                    topic: topic.to_owned(),
                    payload,
                },
            )
        })
    }

    /// Fixture: the next unprotected message.
    pub fn poll(&self) -> Result<Option<Publication>> {
        let message = self.call(Op::Poll, ops::policy::poll)?;
        Ok(message.map(|message| Publication {
            workspace: message.workspace,
            revision: message.revision,
            sender: message.sender,
            topic: message.topic,
            payload: message.payload,
        }))
    }

    pub fn fetch_recovery_range(
        &self,
        request: RecoveryRangeRequest,
    ) -> Result<RecoveryRangeStatus> {
        let status = self.call(Op::FetchRecoveryRange, |session| {
            ops::recovery::fetch_range(
                session,
                ops::recovery::FetchRangeArgs {
                    peer: request.peer,
                    author: request.author,
                    revision: request.revision,
                    topics: request.topics,
                    after: request.after,
                    through: request.through,
                },
            )
        })?;
        Ok(range_status(status))
    }

    pub fn poll_recovery_range(&self) -> Result<Option<RecoveryRangeStatus>> {
        Ok(self
            .call(Op::PollRecoveryRange, ops::recovery::poll_range)?
            .map(range_status))
    }

    pub fn cancel_recovery_range(&self) -> Result<()> {
        self.call(Op::CancelRecoveryRange, ops::recovery::cancel_range)?;
        Ok(())
    }

    /// `retain_until` is Unix seconds (UTC) by this node's clock; 0 keeps no
    /// copy for third-party recovery.
    pub fn stage_recovery_range(&self, retain_until: u64) -> Result<RecoveryStage> {
        let staged = self.call(Op::StageRecoveryRange, |session| {
            ops::recovery::stage_range(session, ops::recovery::StageRangeArgs { retain_until })
        })?;
        match staged {
            ops::recovery::RecoveryStaged::Candidate(candidate) => {
                Ok(RecoveryStage::Candidate(RecoveryCandidate {
                    workspace: candidate.workspace,
                    snapshot: stored_output(candidate.snapshot)?,
                    publication_count: candidate.publication_count.unwrap_or(0),
                    durable: candidate.durable,
                }))
            }
            ops::recovery::RecoveryStaged::Nothing(nothing) => match nothing.state {
                "recovery_already_covered" => Ok(RecoveryStage::AlreadyCovered),
                "recovery_no_new_objects" => Ok(RecoveryStage::NoNewObjects),
                "recovery_awaiting_application" => Ok(RecoveryStage::AwaitingApplication),
                other => Err(error(
                    ErrorKind::Internal,
                    format!("unknown recovery stage: {other}"),
                )),
            },
        }
    }

    pub fn adopt_recovery(&self, snapshot: &[u8]) -> Result<RecoveryAdoption> {
        let adopted = self.adopt(Op::AdoptRecovery, candidate::adopt_recovery, snapshot)?;
        let (recovered_publications, missing_publications) = match adopted.state {
            Some("recovery_adopted") => (
                adopted.publication_count.unwrap_or(0),
                adopted.missing_count.unwrap_or(0) as usize,
            ),
            Some("direct_miss_adopted") => (0, adopted.missing_count.unwrap_or(0) as usize),
            other => {
                return Err(error(
                    ErrorKind::Internal,
                    format!("unknown recovery adoption: {other:?}"),
                ));
            }
        };
        Ok(RecoveryAdoption {
            workspace: adopted.workspace,
            epoch: adopted.epoch,
            member_count: adopted.members,
            durable: adopted.durable,
            recovered_publications,
            missing_publications,
        })
    }

    pub fn close(&mut self) -> Result<()> {
        let handle = self
            .handle
            .take()
            .ok_or_else(|| error(ErrorKind::Closed, "client is closed"))?;
        close(handle).map_err(legacy)
    }

    /// Run one typed op on this client's session (guards and wake-ups
    /// included; see `ops::run`).
    fn call<T>(
        &self,
        op: Op,
        body: impl FnOnce(&mut Session) -> std::result::Result<T, ApiError>,
    ) -> Result<T> {
        ops::run(self.handle()?, op, body).map_err(Error::from)
    }

    /// Adopt a saved candidate with the adopt op of its kind.
    fn adopt(
        &self,
        op: Op,
        adopt: fn(&mut Session, candidate::AdoptArgs) -> std::result::Result<candidate::AdoptReply, ApiError>,
        snapshot: &[u8],
    ) -> Result<candidate::Adopted> {
        stored_input(snapshot)?;
        let reply = self.call(op, |session| {
            adopt(
                session,
                candidate::AdoptArgs {
                    snapshot: snapshot.to_vec(),
                },
            )
        })?;
        reply.adopted().map_err(Error::from)
    }

    fn handle(&self) -> Result<i64> {
        self.handle
            .ok_or_else(|| error(ErrorKind::Closed, "client is closed"))
    }

}

impl Drop for Client {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = close(handle);
        }
    }
}

/// The bound `execute_stored` puts on a snapshot the host passes in.
fn stored_input(snapshot: &[u8]) -> Result<()> {
    if snapshot.len() > crate::MAX_STORED_SNAPSHOT {
        return Err(Error::from(ApiError::invalid_input(
            "request",
            "stored request exceeds limit",
        )));
    }
    Ok(())
}

/// The bound `execute_stored` puts on a snapshot the runtime returns.
fn stored_output(snapshot: Vec<u8>) -> Result<Vec<u8>> {
    if snapshot.len() > crate::MAX_STORED_SNAPSHOT {
        return Err(Error::from(ApiError::limit_reached(
            "stored snapshot",
            crate::MAX_STORED_SNAPSHOT as u64,
            "stored response exceeds limit; close and restore",
        )));
    }
    Ok(snapshot)
}

fn candidate_of(staged: management::StagedCandidate) -> Result<WorkspaceCandidate> {
    Ok(WorkspaceCandidate {
        workspace: staged.workspace,
        snapshot: stored_output(staged.snapshot)?,
    })
}

fn change_candidate(staged: management::StagedChange) -> Result<WorkspaceCandidate> {
    match staged {
        management::StagedChange::Candidate(candidate) => candidate_of(candidate),
        management::StagedChange::Removal(removal) => Ok(WorkspaceCandidate {
            workspace: removal.workspace,
            snapshot: stored_output(removal.snapshot)?,
        }),
    }
}

fn join_request(pending: join::PendingJoinInfo) -> Result<JoinRequest> {
    Ok(JoinRequest {
        workspace: pending.workspace,
        member: pending.member.id,
        endpoint: pending.endpoint,
        admission_request: pending
            .admission_request
            .ok_or_else(|| error(ErrorKind::InvalidInput, "invitation has no admission request"))?,
    })
}

fn range_status(status: ops::recovery::RangeStatus) -> RecoveryRangeStatus {
    use ops::recovery::RangeStatus as S;
    match status {
        S::RecoveryRangePending {
            candidate_count,
            automatic_source,
            ..
        } => RecoveryRangeStatus::Pending {
            candidate_count,
            automatic_source,
        },
        S::RecoveryRangeReady(ready) => RecoveryRangeStatus::Ready(RecoveryRangeReady {
            workspace: ready.workspace,
            author: ready.author,
            peer: ready.peer,
            epoch: ready.epoch,
            revision: ready.revision,
            after: ready.after,
            through: ready.through,
            packet_count: ready.packet_count,
            retained_bytes: ready.retained_bytes,
            automatic_source: ready.automatic_source,
            attempted: ready.attempted,
        }),
        // The runtime only waits for a source when it looks automatically.
        S::RecoverySourceWaiting { .. } => RecoveryRangeStatus::SourceWaiting {
            automatic_source: true,
        },
        S::RecoverySourceUnavailable {
            attempted,
            reason,
            automatic_source,
            ..
        } => RecoveryRangeStatus::SourceUnavailable {
            attempted,
            reason,
            automatic_source,
        },
        S::RecoveryRangeRejected { reason, .. } => RecoveryRangeStatus::Rejected { reason },
        S::RecoveryRangeCancelled { .. } => RecoveryRangeStatus::Cancelled,
    }
}

fn opened_info(opened: ops::workspace::WorkspaceOpened) -> WorkspaceInfo {
    WorkspaceInfo {
        workspace: opened.workspace,
        workspace_name: opened.workspace_name,
        epoch: opened.epoch,
        member_count: opened.members,
        durable: opened.durable,
        phase: opened.activity.phase,
        reason: opened.activity.reason,
    }
}

fn workspace_info(adopted: candidate::Adopted) -> WorkspaceInfo {
    WorkspaceInfo {
        workspace: adopted.workspace,
        workspace_name: adopted.workspace_name,
        epoch: adopted.epoch,
        member_count: adopted.members,
        durable: adopted.durable,
        phase: adopted.activity.phase,
        reason: adopted.activity.reason,
    }
}

impl TryFrom<crate::membership::RosterMember> for MemberInfo {
    type Error = Error;

    fn try_from(value: crate::membership::RosterMember) -> Result<Self> {
        let kind = match value.kind {
            "person" => MemberKind::Person,
            "service" => MemberKind::Service,
            _ => return Err(error(ErrorKind::Internal, "invalid member kind")),
        };
        let presence = match value.presence {
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

/// An error the client itself finds (bad arguments, a reply it cannot use).
fn error(kind: ErrorKind, message: impl Into<String>) -> Error {
    let message = message.into();
    let api = match kind {
        ErrorKind::Closed => ApiError::Closed,
        ErrorKind::InvalidInput => ApiError::invalid_input("", message.clone()),
        ErrorKind::Capacity => ApiError::capacity_exceeded("", 0, message.clone()),
        ErrorKind::Storage => ApiError::storage_failed(message.clone()),
        ErrorKind::Transport => ApiError::transport_failed(None, message.clone()),
        ErrorKind::Cancelled => ApiError::Cancelled,
        ErrorKind::Internal => ApiError::internal(message.clone()),
    };
    Error {
        kind,
        message,
        error: api,
    }
}

/// A `String` error from a free function that has no typed twin yet.
fn legacy(message: String) -> Error {
    Error::from(crate::errors::legacy(message))
}

#[test]
fn error_kind_comes_from_the_code_table() {
    let cases = [
        (ApiError::Closed, ErrorKind::Closed),
        (crate::errors::unknown_handle(), ErrorKind::Closed),
        (ApiError::Cancelled, ErrorKind::Cancelled),
        (ApiError::DeadlineExceeded, ErrorKind::Cancelled),
        (ApiError::invalid_input("topic", "bad"), ErrorKind::InvalidInput),
        (ApiError::wrong_state("busy"), ErrorKind::InvalidInput),
        (ApiError::limit_reached("sessions", 8, "node limit reached"), ErrorKind::Capacity),
        (ApiError::candidate_stale("old"), ErrorKind::Storage),
        (
            crate::errors::node(arachne_node::Error::Transport(
                "aborted by peer: connection limit for unknown endpoints".into(),
            )),
            ErrorKind::Transport,
        ),
        (ApiError::invitation_expired("late"), ErrorKind::InvalidInput),
        (ApiError::epoch_mismatch("moved"), ErrorKind::InvalidInput),
        (ApiError::internal("bug"), ErrorKind::Internal),
    ];
    for (api, kind) in cases {
        let error = Error::from(api.clone());
        assert_eq!(error.kind(), kind, "{api:?}");
        assert_eq!(error.code(), api.code());
    }
}
