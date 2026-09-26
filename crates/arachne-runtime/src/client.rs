use serde::{Deserialize, Serialize};
use serde_json::Value;

use arachne_api::{ApiError, Event};
pub use arachne_api::{AttemptId, EndpointId, Key32, MemberId, RecordId, WorkspaceId};
use std::sync::Arc;

use crate::ops::candidate::CandidateKind;
use crate::ops::{
    self, Op, admission, candidate, invitation, join, management, publication, receive,
};
use crate::persistence;
use crate::{FreshnessAnchor, Session, StorageConfig, WorkspacePhase};

/// The kinds `adopt_admission` accepts.
const WORKSPACE_KINDS: &[CandidateKind] = &[
    CandidateKind::Admission,
    CandidateKind::Management,
    CandidateKind::WorkspaceName,
    CandidateKind::SelfUpdate,
];

pub use arachne_api::Network;

/// Configuration for one workspace-facing runtime client.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ClientConfig {
    pub network: Network,
    pub secret: Option<Vec<u8>>,
    /// Relay, lookup and deadline overrides. `Default` keeps the profile's.
    pub transport: TransportOptions,
    /// Record storage. Required to create, join or restore a workspace.
    pub storage: Option<Arc<StorageConfig>>,
}

/// Transport overrides on top of a `Network` profile. Every field left
/// `None` keeps the profile default.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct TransportOptions {
    /// Operator relays. They replace n0's public relays.
    pub relay: Option<OperatorRelay>,
    /// n0's public DNS/Pkarr address lookup and publishing. `Some(false)`
    /// keeps a WAN endpoint away from n0; pair it with `relay`.
    pub public_lookup: Option<bool>,
    /// Deadlines for a slow or constrained link.
    pub timeouts: Option<TransportTimeouts>,
    /// Per-op deadline for this client's blocking ops, and for its bind.
    /// At the deadline an op fails with `DeadlineExceeded` and the session
    /// stays usable. `Client::set_deadline` changes it later.
    pub deadline: Option<std::time::Duration>,
}

/// Relays run by the deployment operator.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct OperatorRelay {
    /// Relay URLs, for example `https://relay.example.org`.
    pub urls: Vec<String>,
    /// How the relays' TLS certificates are checked.
    pub trust: RelayTrust,
}

/// TLS trust for operator relays.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum RelayTrust {
    /// The built-in WebPKI roots.
    WebPki,
    /// Only these DER-encoded root certificates, for a private CA.
    CustomRoots(Vec<Vec<u8>>),
}

/// Transport deadlines. Each must be nonzero.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
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
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct TransportInfo {
    /// n0's public lookup is in use.
    pub public_lookup: bool,
    /// Operator relays replace n0's relays.
    pub operator_relay: bool,
    /// The endpoint can find a peer by key alone (mDNS, n0 lookup or Tor).
    pub peer_id_lookup: bool,
    pub timeouts: TransportTimeouts,
}

fn network_profile(network: Network) -> Result<arachne_node::NetworkProfile> {
    use arachne_node::NetworkProfile as P;
    Ok(match network {
        Network::Direct => P::Direct,
        Network::Lan => P::Lan,
        Network::Nearby => P::Nearby,
        Network::Wan => P::Wan,
        Network::RelayOnly => P::RelayOnly,
        Network::WanOnly => P::WanOnly,
        #[cfg(feature = "tor")]
        Network::Tor => P::Tor,
        _ => {
            return Err(ApiError::unsupported(
                "network is not supported by this build",
            ));
        }
    })
}

impl TransportOptions {
    /// The node options for `network` with these overrides applied.
    fn node_options(&self, network: Network) -> Result<arachne_node::NodeOptions> {
        let invalid = |message: &str| error(ErrorKind::InvalidInput, message);
        let mut options = arachne_node::NodeOptions::new(network_profile(network)?);
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

// The local constructor chooses an explicit code; this is not an exported error model.
#[derive(Clone, Copy)]
enum ErrorKind {
    Closed,
    InvalidInput,
    Transport,
    Internal,
}

pub type Result<T> = std::result::Result<T, ApiError>;

// A session that disappeared during a Client call was closed. Unknown caller-supplied
// handles in the JSON adapter remain InvalidId.
fn client_error(error: ApiError) -> ApiError {
    if error == crate::errors::unknown_handle() {
        ApiError::Closed
    } else {
        error
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct EndpointInfo {
    #[serde(with = "crate::client_wire::id")]
    pub endpoint_key: EndpointId,
    pub bound_address: String,
    pub workspace_ready: bool,
    pub transport: TransportInfo,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct WorkspaceState {
    pub endpoint_key: EndpointId,
    pub workspace: Option<WorkspaceId>,
    pub workspace_ready: bool,
    pub durable: bool,
    pub phase: WorkspacePhase,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct WorkspaceInfo {
    pub workspace: WorkspaceId,
    pub workspace_name: Option<String>,
    pub epoch: u64,
    pub member_count: u64,
    pub durable: bool,
    pub phase: WorkspacePhase,
    pub reason: Option<String>,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum MemberKind {
    Person,
    Service,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum Presence {
    SelfMember,
    Unknown,
    Reachable,
    Stale,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MemberInfo {
    pub id: MemberId,
    pub endpoint: EndpointId,
    pub administrator: bool,
    pub self_member: bool,
    pub display_name: Option<String>,
    pub kind: MemberKind,
    pub presence: Presence,
    pub last_contact_age_ms: Option<u64>,
    pub presence_fresh_for_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MemberRoster {
    pub workspace: WorkspaceId,
    pub workspace_name: Option<String>,
    pub workspace_name_revision: u64,
    pub workspace_name_head: Key32,
    pub epoch: u64,
    pub members: Vec<MemberInfo>,
    pub profile_count: u64,
    pub profiles_retained: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RouteHint {
    #[serde(with = "crate::client_wire::id")]
    pub peer: EndpointId,
    pub address: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct InvitationInfo {
    #[serde(with = "crate::client_wire::id")]
    pub workspace: WorkspaceId,
    pub workspace_name: Option<String>,
    pub invitation: Vec<u8>,
    #[serde(with = "crate::client_wire::id")]
    pub invitation_key: Key32,
    pub checkpoint: Vec<u8>,
    #[serde(with = "crate::client_wire::id")]
    pub peer: EndpointId,
    #[serde(with = "crate::client_wire::many")]
    pub bootstrap_peers: Vec<EndpointId>,
    pub address: String,
    pub routes: Vec<RouteHint>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct InvitationDetails {
    pub workspace: WorkspaceId,
    pub invitation_key: Key32,
    pub workspace_name: Option<String>,
    pub epoch: u64,
    pub personal: bool,
    pub automatic: bool,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct JoinRequest {
    pub workspace: WorkspaceId,
    pub member: MemberId,
    pub endpoint: EndpointId,
    pub admission_request: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AdmissionAuthorization {
    #[serde(with = "crate::client_wire::id")]
    pub invitation_key: Key32,
    pub grant_signature: Vec<u8>,
    pub redemption_signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct JoinAdmissionStep {
    pub commit: Vec<u8>,
    pub authorization: AdmissionAuthorization,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AdmissionReply {
    #[serde(with = "crate::client_wire::id")]
    pub workspace: WorkspaceId,
    pub epoch: u64,
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
    pub authorization: AdmissionAuthorization,
}

/// The kind of invitation link to register.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
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
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum MemberAction {
    Promote(MemberId),
    Demote(MemberId),
    Remove(MemberId),
    DisableInvitation(Key32),
}

/// One registered invitation link and its controls.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct InvitationControl {
    pub number: u64,
    pub key: Key32,
    pub expires_at: u64,
    pub enabled: bool,
    pub personal: bool,
    pub automatic: bool,
    pub request_access: bool,
    pub approved: bool,
}

/// This member's removal, adopted. The session has ended.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RemovedMembership {
    pub workspace: WorkspaceId,
    pub epoch: u64,
    pub member: MemberId,
    pub commit_digest: Key32,
}

/// A nearby endpoint and the name it announced, if it answered.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct NearbyEndpoint {
    pub endpoint: EndpointId,
    pub name: Option<String>,
}

/// How a nearby workspace admits people.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum NearbyMode {
    /// A person asks; an administrator approves.
    RequestAccess,
    /// Anyone nearby with the link may join.
    OpenJoining,
}

/// One workspace a nearby device advertises.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct NearbyAdvertisement {
    pub peer: EndpointId,
    pub mode: NearbyMode,
    pub workspace_name: Option<String>,
    pub invitation: Vec<u8>,
}

/// The result of one nearby workspace scan.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct NearbyScan {
    pub workspaces: Vec<NearbyAdvertisement>,
    pub endpoints_checked: u64,
    /// The scan did not reach every nearby endpoint.
    pub limited: bool,
}

/// The outcome of one presence round.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PresenceRound {
    /// A member this round started a membership query with.
    pub sync_peer: Option<EndpointId>,
    /// Answers that failed, and the first failure's text.
    pub response_errors: u32,
    pub response_error: Option<String>,
}

/// A verified invitation checkpoint and the member that served it.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct InvitationCheckpoint {
    pub workspace: WorkspaceId,
    pub checkpoint: Vec<u8>,
    pub peer: EndpointId,
}

/// One admission request that waits for an administrator.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AdmissionApproval {
    pub attempt_id: AttemptId,
    pub endpoint: EndpointId,
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
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AdmissionApprovalPage {
    pub approvals: Vec<AdmissionApproval>,
    /// No more rows after this page.
    pub complete: bool,
    /// Pass as `after` for the next page.
    pub next_after: Option<AttemptId>,
}

/// What `restore_workspace` found in record storage.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum RestoredWorkspace {
    Active(WorkspaceInfo),
    Joining(RestoredJoin),
    /// This member was removed. The session has ended.
    Removed(RemovedMembership),
}

/// A restored pending join. `admission_request` is `None` until the
/// invitation checkpoint is known.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RestoredJoin {
    pub workspace: WorkspaceId,
    pub member: MemberId,
    pub endpoint: EndpointId,
    pub admission_request: Option<Vec<u8>>,
}

/// The staged candidate inside every typed candidate: the client it
/// belongs to and its token, which is taken when it is adopted or discarded.
#[derive(Debug)]
struct Staged {
    client: i64,
    token: std::sync::Mutex<Option<Vec<u8>>>,
}

impl Staged {
    fn new(client: i64, token: Vec<u8>) -> Self {
        Self {
            client,
            token: std::sync::Mutex::new(Some(token)),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Vec<u8>>> {
        self.token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Drop it in core. `false`: it was already used or is no longer staged.
    fn discard(&self) -> Result<bool> {
        let mut token = self.lock();
        let Some(staged) = token.as_ref() else {
            return Ok(false);
        };
        let discarded = ops::run(self.client, Op::DiscardCandidate, |session| {
            candidate::discard(session, staged)
        })?;
        *token = None;
        Ok(discarded)
    }
}

impl Drop for Staged {
    /// A candidate dropped without adoption is discarded in core.
    fn drop(&mut self) {
        if let Some(token) = self.lock().take() {
            let _ = ops::run(self.client, Op::DiscardCandidate, |session| {
                candidate::discard(session, &token)
            });
        }
    }
}

macro_rules! candidate_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        ///
        /// Opaque, bound to the client that staged it, and usable one time:
        /// adopt it with its own adopt method, or `discard` it. Dropping it
        /// without adoption discards it.
        #[derive(Debug)]
        #[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
        pub struct $name {
            workspace: [u8; 32],
            staged: Staged,
        }

        impl $name {
            fn new(client: i64, workspace: [u8; 32], token: Vec<u8>) -> Arc<Self> {
                Arc::new(Self {
                    workspace,
                    staged: Staged::new(client, token),
                })
            }

        }

        #[cfg_attr(feature = "uniffi", uniffi::export)]
        impl $name {
            pub fn workspace(&self) -> WorkspaceId {
                self.workspace.into()
            }

            /// Drop the staged change. `false`: it was already used or is no
            /// longer staged. A candidate already in storage cannot be
            /// discarded (`WrongState`).
            pub fn discard(&self) -> Result<bool> {
                self.staged.discard()
            }
        }
    };
}

candidate_type!(
    /// An admission, administrator action or workspace name change. Adopt it
    /// with `adopt_admission`.
    WorkspaceCandidate
);
candidate_type!(
    /// An invitation registration. Adopt it with `adopt_invitation`.
    InvitationCandidate
);
candidate_type!(
    /// This member's removal. Adopt it with `adopt_removal`; that ends the session.
    RemovalCandidate
);
candidate_type!(
    /// A join. Adopt it with `adopt_join`.
    JoinCandidate
);

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum RouteKind {
    Direct,
    Relay,
    Tor,
    Custom { name: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PeerRoute {
    pub member: MemberId,
    pub route: RouteKind,
    pub rtt_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ConnectivityReport {
    pub workspace: WorkspaceId,
    pub paths: Vec<PeerRoute>,
    pub paths_limited: bool,
    pub receive_queue: u64,
    pub repair_jobs: u64,
}

/// A bounded, read-only snapshot for native adapters and diagnostics.
///
/// The snapshot contains local workspace state and counters only. It does not
/// initiate repair, dialing, admission or publication work. Qualification
/// receipts use a separate redacted projection; do not export this value as a
/// public telemetry record because its path members are workspace-local IDs.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct WorkspaceMetrics {
    pub workspace: WorkspaceId,
    pub phase: WorkspacePhase,
    pub reason: Option<String>,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub receive_queue: u64,
    pub admission_queue: u64,
    pub admission_queue_bytes: u64,
    pub admission_waiters: u64,
    pub admission_in_flight: u64,
    pub approval_pending: u64,
    pub pending_objects: u64,
    pub repair_jobs: u64,
    pub gossip_neighbors: u64,
    pub control_timing: ControlTimingMetrics,
    pub membership_gossip: MembershipGossipMetrics,
    pub connection_capacity: ConnectionCapacityMetrics,
    pub paths: Vec<PeerRoute>,
    pub paths_limited: bool,
}

/// A duration series measured in microseconds since the endpoint started.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct DurationSummary {
    pub count: u64,
    pub total_us: u64,
    pub max_us: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ControlTimingMetrics {
    pub inquiry: DurationSummary,
    pub host_wait: DurationSummary,
    pub host_service: DurationSummary,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
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
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ConnectionCapacityMetrics {
    pub evicted: u64,
    pub refused: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PeerPolicy {
    #[serde(with = "crate::client_wire::id")]
    pub peer: EndpointId,
    pub publish: Vec<String>,
    pub subscribe: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct DeliveryFailure {
    #[serde(with = "crate::client_wire::id")]
    pub peer: EndpointId,
    pub error: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct DeliveryReport {
    #[serde(with = "crate::client_wire::many")]
    pub admitted: Vec<EndpointId>,
    pub queued: bool,
    pub failed: Vec<DeliveryFailure>,
}

candidate_type!(
    /// A protected publication. Adopt it with `adopt_protected_publication`.
    PublicationCandidate
);

/// Current-value metadata for a protected publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PublicationCurrent {
    #[serde(with = "crate::client_wire::id")]
    pub selector: Key32,
    #[serde(with = "crate::client_wire::id")]
    pub replacement_key: Key32,
    /// Unix seconds (UTC), by the author's clock. Receivers and holders allow
    /// `arachne_delivery::EXPIRY_SKEW_SECONDS` of clock difference.
    pub expires_at: u64,
    pub tombstone: bool,
}

/// Delivery mode for a protected publication. The default is `Critical`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum PublicationMode {
    /// Use the Critical queue.
    #[default]
    Critical,
    /// Use the Bulk queue.
    Bulk,
    /// Publish a replaceable current value to the workspace.
    Current { metadata: PublicationCurrent },
}

/// Audience and delivery mode for a protected publication.
/// The default is an empty audience (workspace members) and `Critical` mode.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PublicationOptions {
    /// Empty means the workspace audience. Otherwise, provide at most 64 current
    /// member IDs, sorted in ascending byte order, without duplicates or self.
    /// A directed audience cannot use `Current` mode.
    pub recipients: Vec<MemberId>,
    pub mode: PublicationMode,
}

candidate_type!(
    /// A protected incoming publication, or an acknowledgement or rejection
    /// of a pending object. The authenticated plaintext is withheld until
    /// `adopt_protected_reception`.
    ProtectedReceptionCandidate
);

/// An authenticated pending object from the durable inbox.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ReceivedProtectedPublication {
    pub workspace: WorkspaceId,
    pub revision: u64,
    pub member: MemberId,
    pub endpoint: EndpointId,
    pub topic: String,
    pub id: RecordId,
    pub sequence: Option<u64>,
    pub payload: Vec<u8>,
    pub recipients: Vec<MemberId>,
    /// The author epoch in which this object was authenticated.
    pub epoch: u64,
    /// True after this node leaves the branch on which it accepted the object.
    pub from_losing_branch: bool,
    /// Author sender counter; identifies the object for acknowledgement.
    pub counter: u64,
    /// Present for a latest-value (current) publication.
    pub current: Option<PublicationCurrent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct InterestObservation {
    pub workspace: WorkspaceId,
    pub revision: u64,
    pub topic: String,
    pub subscribed: bool,
    pub admission: DeliveryReport,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Publication {
    pub workspace: WorkspaceId,
    pub revision: u64,
    pub sender: EndpointId,
    pub topic: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RecoveryRangeRequest {
    pub peer: Option<EndpointId>,
    pub author: Option<MemberId>,
    pub revision: u64,
    pub topics: Vec<String>,
    /// None continues saved full-history progress. Some selects an independent tail.
    pub after: Option<u64>,
    /// None asks a holder for its bounded available range after the cursor.
    pub through: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RecoveryRangeReady {
    pub workspace: WorkspaceId,
    pub author: MemberId,
    pub peer: EndpointId,
    pub epoch: u64,
    pub revision: u64,
    pub after: u64,
    pub through: u64,
    pub packet_count: u64,
    pub retained_bytes: u64,
    pub automatic_source: bool,
    pub attempted: Option<u64>,
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum RecoveryRangeStatus {
    Pending {
        candidate_count: u64,
        automatic_source: bool,
    },
    Ready(RecoveryRangeReady),
    SourceWaiting {
        automatic_source: bool,
    },
    SourceUnavailable {
        attempted: u64,
        reason: String,
        automatic_source: bool,
    },
    Rejected {
        reason: String,
    },
    Cancelled,
}

/// A recovery range. Adopt it with `adopt_recovery`.
#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct RecoveryCandidate {
    candidate: Arc<ProtectedReceptionCandidate>,
    publication_count: u64,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl RecoveryCandidate {
    pub fn workspace(&self) -> WorkspaceId {
        self.candidate.workspace()
    }

    /// Objects the range brings into the durable inbox.
    pub fn publication_count(&self) -> u64 {
        self.publication_count
    }

    /// See [`WorkspaceCandidate::discard`].
    pub fn discard(&self) -> Result<bool> {
        self.candidate.discard()
    }
}

#[derive(Debug)]
#[non_exhaustive]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum RecoveryStage {
    Candidate(Arc<RecoveryCandidate>),
    AlreadyCovered,
    NoNewObjects,
    /// Automatic recovery: nothing fits the pending bounds until the
    /// application acknowledges or rejects pending objects. No progress was
    /// claimed; request the range again after draining.
    AwaitingApplication,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RecoveryAdoption {
    pub workspace: WorkspaceId,
    pub epoch: u64,
    pub member_count: u64,
    pub durable: bool,
    pub recovered_publications: u64,
    pub missing_publications: u64,
}

/// Typed adopter seam over the portable runtime. The JSON dispatcher remains
/// private to adapters; consumers use typed lifecycle operations here.
///
/// A `Client` is `Send + Sync`. `close`, `wake`, `wait_for_work` and
/// `next_event` may run on any thread while another thread waits.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct Client {
    handle: i64,
    context: std::sync::Arc<crate::Context>,
    closed: std::sync::atomic::AtomicBool,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Client {
    /// Open a client in the process default context
    /// ([`Context::default_shared`](crate::Context::default_shared)).
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn open(config: ClientConfig) -> Result<Arc<Self>> {
        let context = crate::Context::default_shared()?;
        Self::open_in(context, config)
    }

    /// Open a client in `context`. Storage and other per-client setup
    /// attach here, after the session is registered.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn open_in(context: Arc<crate::Context>, config: ClientConfig) -> Result<Arc<Self>> {
        let options = config.transport.node_options(config.network)?;
        if config.network != Network::Direct && config.secret.is_none() {
            return Err(error(
                ErrorKind::InvalidInput,
                format!("{:?} requires a secret", config.network),
            ));
        }
        let secret = config
            .secret
            .as_deref()
            .map(|bytes| {
                <[u8; 32]>::try_from(bytes)
                    .map_err(|_| ApiError::invalid_input("secret", "secret must contain 32 bytes"))
            })
            .transpose()?;
        let handle = crate::registry::open(
            &context,
            secret.as_ref(),
            options,
            config.transport.deadline,
        )?;
        let client = Arc::new(Self {
            handle,
            context: Arc::clone(&context),
            closed: std::sync::atomic::AtomicBool::new(false),
        });
        if let Some(storage) = config.storage {
            client.stored(|session| persistence::attach(session, storage.as_ref().clone()))?;
        }
        Ok(client)
    }

    /// Features and limits of this client's context.
    pub fn capabilities(&self) -> Result<arachne_api::Capabilities> {
        self.handle()?;
        let networks = Network::ALL
            .iter()
            .copied()
            .filter(|network| network_profile(*network).is_ok())
            .collect();
        Ok(arachne_api::Capabilities::new(
            networks,
            vec![arachne_api::Feature::ResourceTransfer],
            self.context.limits(),
        ))
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
            workspace: raw.workspace.into(),
            invitation_key: raw.invitation_key.into(),
            workspace_name: raw.workspace_name,
            epoch: raw.epoch,
            personal: raw.personal_invitation,
            automatic: raw.automatic_approval,
            expires_at: raw.expires_at,
        })
    }

    pub fn endpoint(&self) -> Result<EndpointInfo> {
        let description = crate::registry::endpoint_value(self.handle()?).map_err(client_error)?;
        serde_json::from_value(description).map_err(|parse_error| {
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
            workspace: state.workspace.map(Into::into),
            workspace_ready: state.workspace_ready,
            durable: state.durable,
            phase: state.activity.phase,
            reason: state.activity.reason,
        })
    }

    pub fn create_workspace(
        &self,
        display_name: &str,
        workspace_name: Option<String>,
    ) -> Result<WorkspaceInfo> {
        let opened = self.call(Op::CreateWorkspace, |session| {
            ops::workspace::create(
                session,
                ops::workspace::CreateArgs {
                    display_name: display_name.to_owned(),
                    workspace_name,
                },
            )
        })?;
        Ok(opened_info(opened))
    }

    /// Restore the workspace stored for `workspace`: an active workspace, a
    /// pending join, or this member's removal (the session then ends). With
    /// `expected`, the store must match that saved anchor exactly.
    pub fn restore_workspace(
        &self,
        workspace: WorkspaceId,
        expected: Option<FreshnessAnchor>,
    ) -> Result<RestoredWorkspace> {
        let restored = self.call(Op::RestoreWorkspace, |session| {
            persistence::restore(session, workspace.to_bytes(), expected)
        })?;
        Ok(match restored {
            persistence::Restored::Opened(opened) => RestoredWorkspace::Active(opened_info(opened)),
            persistence::Restored::Pending(pending) => RestoredWorkspace::Joining(RestoredJoin {
                workspace: pending.workspace.into(),
                member: pending.member.id.into(),
                endpoint: pending.endpoint.into(),
                admission_request: pending.admission_request,
            }),
            persistence::Restored::Removed(removed) => {
                RestoredWorkspace::Removed(RemovedMembership {
                    workspace: removed.removed.workspace.into(),
                    epoch: removed.removed.epoch,
                    member: removed.removed.member.id.into(),
                    commit_digest: removed.removed.commit_digest.into(),
                })
            }
        })
    }

    /// Forget all workspace state. Returns whether anything changed.
    pub fn reset_workspace(&self) -> Result<bool> {
        Ok(self
            .call(Op::ResetWorkspace, ops::workspace::reset)?
            .changed)
    }

    /// Members whose leaf still comes from their KeyPackage: they never
    /// self-updated. Each adds about 82 bytes to every management commit
    /// (B3c), so a host can predict commit size and nudge those members.
    pub fn members_without_self_update(&self) -> Result<u64> {
        self.call(Op::WorkspaceState, |session| {
            Ok(session
                .workspace
                .as_ref()
                .ok_or_else(crate::errors::no_workspace)?
                .members_without_self_update() as u64)
        })
    }

    /// Drop the staged candidate. Returns whether one was staged.
    pub fn discard_workspace_candidate(&self) -> Result<bool> {
        Ok(self
            .call(
                Op::DiscardWorkspaceCandidate,
                ops::workspace::discard_candidate,
            )?
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
        peers: &[EndpointId],
    ) -> Result<JoinRequest> {
        let pending = self.call(Op::BeginJoin, |session| {
            join::begin(
                session,
                join::BeginJoinArgs {
                    invitation: invitation.to_vec(),
                    checkpoint: checkpoint.to_vec(),
                    display_name: display_name.to_owned(),
                    peers: peers.iter().copied().map(EndpointId::to_bytes).collect(),
                },
            )
        })?;
        join_request(pending)
    }

    /// Fetch and verify the current checkpoint of a compact invitation from
    /// one of up to three members.
    pub fn fetch_invitation_checkpoint(
        &self,
        invitation: &[u8],
        peers: &[EndpointId],
    ) -> Result<InvitationCheckpoint> {
        let found = self.call(Op::FetchInvitationCheckpoint, |session| {
            join::fetch_checkpoint(
                session,
                join::FetchCheckpointArgs {
                    peer: None,
                    peers: peers.iter().copied().map(EndpointId::to_bytes).collect(),
                    invitation: invitation.to_vec(),
                },
            )
        })?;
        Ok(InvitationCheckpoint {
            workspace: found.workspace.into(),
            checkpoint: found.checkpoint,
            peer: found.peer.into(),
        })
    }

    pub fn stage_admission(
        &self,
        authenticated_endpoint: EndpointId,
        request: &[u8],
    ) -> Result<Arc<WorkspaceCandidate>> {
        let staged = self.call(Op::StageAdmission, |session| {
            admission::stage(
                session,
                admission::AdmissionArgs {
                    authenticated_endpoint: authenticated_endpoint.to_bytes(),
                    request: request.to_vec(),
                },
            )
        })?;
        Ok(WorkspaceCandidate::new(
            self.handle()?,
            staged.workspace,
            staged.snapshot,
        ))
    }

    /// Adopt an admission, administrator action or name change. Core saves
    /// it, reads it back, then adopts it.
    ///
    /// Only its own kind compiles:
    /// ```compile_fail
    /// # fn wrong(client: &arachne_runtime::Client, c: &arachne_runtime::InvitationCandidate) {
    /// client.adopt_admission(c);
    /// # }
    /// ```
    pub fn adopt_admission(&self, candidate: &WorkspaceCandidate) -> Result<WorkspaceInfo> {
        self.adopt(Op::AdoptAdmission, &candidate.staged, WORKSPACE_KINDS)?
            .adopted()
            .map(workspace_info)
            .map_err(client_error)
    }

    pub fn retained_admission(
        &self,
        authenticated_endpoint: EndpointId,
        request: &[u8],
    ) -> Result<AdmissionReply> {
        self.call(Op::RetainedAdmission, |session| {
            admission::retained(
                session,
                admission::AdmissionArgs {
                    authenticated_endpoint: authenticated_endpoint.to_bytes(),
                    request: request.to_vec(),
                },
            )
        })
    }

    /// One page of admission requests that wait for an administrator,
    /// after `after` (an attempt ID), at most `limit` (1 to 64, default 64).
    pub fn admission_approvals(
        &self,
        after: Option<AttemptId>,
        limit: Option<u64>,
    ) -> Result<AdmissionApprovalPage> {
        let page = self.call(Op::ListAdmissionApprovals, |session| {
            admission::list_approvals(
                session,
                admission::ListApprovalsArgs {
                    after: after.map(AttemptId::to_bytes),
                    limit: limit
                        .map(|value| {
                            usize::try_from(value).map_err(|_| {
                                ApiError::invalid_input("limit", "count exceeds native bound")
                            })
                        })
                        .transpose()?,
                },
            )
        })?;
        Ok(AdmissionApprovalPage {
            approvals: page
                .approvals
                .into_iter()
                .map(|row| AdmissionApproval {
                    attempt_id: row.attempt_id.into(),
                    endpoint: row.endpoint.into(),
                    request: row.request,
                    display_name: row.display_name,
                    automatic: row.automatic,
                    delivered: row.delivered,
                    acknowledged: row.acknowledged,
                })
                .collect(),
            complete: page.complete,
            next_after: page.next_after.map(Into::into),
        })
    }

    /// Mark a pending approval as seen by the administrator's UI.
    pub fn acknowledge_admission_approval(&self, attempt_id: AttemptId) -> Result<()> {
        self.call(Op::AcknowledgeAdmissionApproval, |session| {
            admission::acknowledge_approval(
                session,
                admission::AcknowledgeApprovalArgs {
                    attempt_id: attempt_id.to_bytes(),
                },
            )
        })?;
        Ok(())
    }

    /// Answer the held admission, leave or offer exchange after its
    /// transition is durable. `false`: the requester expired; its result
    /// stays retained for a retry.
    pub fn send_admission_reply(&self) -> Result<bool> {
        Ok(self
            .call(Op::SendAdmissionReply, admission::send_reply)?
            .queued)
    }

    pub fn stage_join(
        &self,
        welcome: &[u8],
        commits: &[JoinAdmissionStep],
    ) -> Result<Arc<JoinCandidate>> {
        if welcome.len() > arachne_security::MAX_WELCOME {
            return Err(client_error(ApiError::invalid_input(
                "request",
                "Welcome exceeds binary input bound",
            )));
        }
        let commits = commits
            .iter()
            .map(|step| {
                crate::membership::JoinStep::admission(
                    step.commit.clone(),
                    step.authorization.invitation_key.to_bytes(),
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
        Ok(JoinCandidate::new(
            self.handle()?,
            staged.workspace,
            staged.snapshot,
        ))
    }

    pub fn adopt_join(&self, candidate: &JoinCandidate) -> Result<WorkspaceInfo> {
        self.adopt(Op::AdoptJoin, &candidate.staged, &[CandidateKind::Join])?
            .adopted()
            .map(workspace_info)
            .map_err(client_error)
    }

    /// Anchor after the latest record commit. Without a monotonic anchor
    /// store, read it after every call and save it outside the database.
    pub fn record_freshness(&self) -> Result<FreshnessAnchor> {
        self.stored(persistence::freshness)
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
            workspace: raw.workspace.into(),
            workspace_name: raw.workspace_name,
            workspace_name_revision: raw.workspace_name_revision,
            workspace_name_head: raw.workspace_name_head.into(),
            epoch: raw.epoch,
            members,
            profile_count: raw.profiles.len() as u64,
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
    pub fn stage_invitation(&self, expires_at: u64) -> Result<Arc<InvitationCandidate>> {
        self.stage_invitation_of(expires_at, InvitationKind::Reusable)
    }

    /// Register an invitation link of `kind`. Adopt it with
    /// `adopt_invitation` after the candidate is saved.
    pub fn stage_invitation_of(
        &self,
        expires_at: u64,
        kind: InvitationKind,
    ) -> Result<Arc<InvitationCandidate>> {
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
        Ok(InvitationCandidate::new(
            self.handle()?,
            staged.workspace,
            staged.snapshot,
        ))
    }

    /// Approve (bind) a personal invitation for one join request. Adopt the
    /// candidate with `adopt_admission`.
    pub fn stage_invitation_approval(
        &self,
        request: &[u8],
        attempt_id: Option<AttemptId>,
    ) -> Result<Arc<WorkspaceCandidate>> {
        let staged = self.call(Op::StageInvitationApproval, |session| {
            invitation::stage_approval(
                session,
                invitation::DecisionArgs {
                    request: request.to_vec(),
                    attempt_id: attempt_id.map(AttemptId::to_bytes),
                },
            )
        })?;
        self.candidate_of(staged)
    }

    /// Decline a personal invitation request. Adopt the candidate with
    /// `adopt_admission`.
    pub fn stage_invitation_decline(
        &self,
        request: &[u8],
        attempt_id: Option<AttemptId>,
    ) -> Result<Arc<WorkspaceCandidate>> {
        let staged = self.call(Op::StageInvitationDecline, |session| {
            invitation::stage_decline(
                session,
                invitation::DecisionArgs {
                    request: request.to_vec(),
                    attempt_id: attempt_id.map(AttemptId::to_bytes),
                },
            )
        })?;
        self.candidate_of(staged)
    }

    /// The registered invitation links, numbered for people.
    pub fn invitation_controls(&self) -> Result<Vec<InvitationControl>> {
        let reply = self.call(Op::InvitationControls, invitation::controls)?;
        Ok(reply
            .invitations
            .into_iter()
            .map(|row| InvitationControl {
                number: row.number as u64,
                key: row.key.into(),
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
    pub fn stage_management(&self, action: MemberAction) -> Result<Arc<WorkspaceCandidate>> {
        use crate::membership::WireManagement;
        let action = match action {
            MemberAction::Promote(member) => WireManagement::Promote(member.to_bytes()),
            MemberAction::Demote(member) => WireManagement::Demote(member.to_bytes()),
            MemberAction::Remove(member) => WireManagement::Remove(member.to_bytes()),
            MemberAction::DisableInvitation(key) => {
                WireManagement::DisableInvitation(key.to_bytes())
            }
        };
        let staged = self.call(Op::StageManagement, |session| {
            management::stage(session, management::ManagementArgs { action })
        })?;
        self.candidate_of(staged)
    }

    /// Rename the workspace. Adopt the candidate with `adopt_admission`.
    pub fn stage_workspace_name(&self, workspace_name: &str) -> Result<Arc<WorkspaceCandidate>> {
        let staged = self.call(Op::StageWorkspaceName, |session| {
            management::stage_workspace_name(
                session,
                management::WorkspaceNameArgs {
                    workspace_name: workspace_name.to_owned(),
                },
            )
        })?;
        self.candidate_of(staged)
    }

    /// Leave through another member, who commits the departure. Adopt the
    /// staged removal with `adopt_removal`; that ends the session.
    pub fn leave_via_peer(&self, peer: EndpointId) -> Result<Arc<RemovalCandidate>> {
        let staged = self.call(Op::LeaveViaPeer, |session| {
            management::leave_via_peer(
                session,
                management::PeerArgs {
                    peer: peer.to_bytes(),
                },
            )
        })?;
        match staged {
            management::StagedChange::Removal(removal) => Ok(RemovalCandidate::new(
                self.handle()?,
                removal.workspace,
                removal.snapshot,
            )),
            // The peer answered with a step that does not remove this
            // member: drop it, it is not what the caller asked for.
            management::StagedChange::Candidate(candidate) => {
                drop(self.candidate_of(candidate)?);
                Err(client_error(ApiError::wrong_state(
                    "the peer's step does not remove this member",
                )))
            }
        }
    }

    /// The last member leaves alone. Adopt with `adopt_removal`.
    pub fn stage_solo_leave(&self) -> Result<Arc<RemovalCandidate>> {
        let staged = self.call(Op::StageSoloLeave, management::stage_solo_leave)?;
        Ok(RemovalCandidate::new(
            self.handle()?,
            staged.workspace,
            staged.snapshot,
        ))
    }

    /// Adopt a saved removal of this member. The session ends: later calls
    /// give `Closed`.
    pub fn adopt_removal(&self, candidate: &RemovalCandidate) -> Result<RemovedMembership> {
        let reply = self.adopt(
            Op::AdoptAdmission,
            &candidate.staged,
            &[CandidateKind::Removal],
        )?;
        match reply {
            candidate::AdoptReply::Removed(removed) => Ok(RemovedMembership {
                workspace: removed.workspace.into(),
                epoch: removed.epoch,
                member: removed.member.id.into(),
                commit_digest: removed.commit_digest.into(),
            }),
            candidate::AdoptReply::Adopted(_) => Err(client_error(ApiError::wrong_state(
                "the candidate was not a removal",
            ))),
        }
    }

    /// Adopt a staged invitation registration and return its bearer link.
    pub fn adopt_invitation(&self, candidate: &InvitationCandidate) -> Result<InvitationInfo> {
        let adopted = self
            .adopt(
                Op::AdoptAdmission,
                &candidate.staged,
                &[CandidateKind::Invitation],
            )?
            .adopted()?;
        let issued = adopted.issued_invitation.ok_or_else(|| {
            error(
                ErrorKind::InvalidInput,
                "candidate did not issue an invitation",
            )
        })?;
        Ok(issued)
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
            workspace: raw.workspace.into(),
            phase: raw.activity.phase,
            reason: raw.activity.reason,
            received_bytes: raw.received_bytes,
            sent_bytes: raw.sent_bytes,
            receive_queue: raw.receive_queue as u64,
            admission_queue: raw.admission_queue as u64,
            admission_queue_bytes: raw.admission_queue_bytes as u64,
            admission_waiters: raw.admission_waiters as u64,
            admission_in_flight: raw.admission_in_flight as u64,
            approval_pending: raw.approval_pending as u64,
            pending_objects: raw.pending_objects as u64,
            repair_jobs: raw.repair_jobs as u64,
            gossip_neighbors: raw.gossip_neighbors as u64,
            control_timing: raw.control_timing,
            membership_gossip: raw.membership_gossip,
            connection_capacity: raw.connection_capacity,
            paths: raw
                .paths
                .into_iter()
                .map(|path| PeerRoute {
                    member: path.member.into(),
                    route: match path.route {
                        "direct" => RouteKind::Direct,
                        "relay" => RouteKind::Relay,
                        "tor" => RouteKind::Tor,
                        other => RouteKind::Custom {
                            name: other.to_owned(),
                        },
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
            sync_peer: round.sync_peer.map(Into::into),
            response_errors: round.response_errors,
            response_error: round.response_error,
        })
    }

    /// Ask `peer` for the membership step after this node's epoch. Read the
    /// answer with `poll_membership_update`.
    pub fn fetch_membership_update(&self, peer: EndpointId, replace_pending: bool) -> Result<()> {
        self.call(Op::FetchMembershipUpdate, |session| {
            ops::membership::fetch_update(
                session,
                ops::membership::FetchUpdateArgs {
                    peer: peer.to_bytes(),
                    replace_pending,
                },
            )
        })?;
        Ok(())
    }

    /// Nearby endpoints on the local network and the names they announce.
    pub fn nearby_endpoints(&self) -> Result<Vec<NearbyEndpoint>> {
        let found = self.call(Op::NearbyEndpoints, ops::nearby::endpoints)?;
        Ok(found
            .endpoints
            .iter()
            .map(|endpoint| NearbyEndpoint {
                endpoint: (*endpoint).into(),
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
                    peer: workspace.peer.into(),
                    mode: if workspace.mode == "request_access" {
                        NearbyMode::RequestAccess
                    } else {
                        NearbyMode::OpenJoining
                    },
                    workspace_name: workspace.workspace_name,
                    invitation: workspace.invitation,
                })
                .collect(),
            endpoints_checked: found.endpoints_checked as u64,
            limited: found.limited,
        })
    }

    /// Advertise one workspace's invitation to nearby devices. Returns
    /// whether this device now advertises anything.
    pub fn advertise_nearby_workspace(
        &self,
        workspace: Option<WorkspaceId>,
        mode: NearbyMode,
        invitation: &[u8],
        workspace_name: Option<String>,
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
            workspace_name,
            workspace: workspace.map(WorkspaceId::to_bytes),
        })
    }

    /// Stop advertising `workspace`, or every workspace for `None`.
    pub fn withdraw_nearby_workspace(&self, workspace: Option<WorkspaceId>) -> Result<bool> {
        self.nearby_advertisement(ops::nearby::AdvertiseArgs {
            workspace: workspace.map(WorkspaceId::to_bytes),
            ..Default::default()
        })
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
    pub fn send_nearby_invitation(&self, peer: EndpointId, invitation: &[u8]) -> Result<()> {
        self.call(Op::SendNearbyInvitation, |session| {
            ops::nearby::send_invitation(
                session,
                ops::nearby::SendInvitationArgs {
                    peer: peer.to_bytes(),
                    invitation: invitation.to_vec(),
                },
            )
        })?;
        Ok(())
    }

    pub fn moq_metrics(&self) -> Result<StreamMetrics> {
        #[cfg(not(feature = "moq"))]
        {
            Err(ApiError::unsupported(
                "stream transport is not enabled in this build",
            ))
        }
        #[cfg(feature = "moq")]
        {
            self.call(Op::MoqMetrics, |session| {
                let raw = session.node.moq_metrics();
                Ok(StreamMetrics {
                    sessions_total: raw.sessions_total,
                    sessions_active: raw.sessions_active as u64,
                    packets_sent: raw.packets_sent,
                    packets_received: raw.packets_received,
                    groups_received: raw.groups_received,
                    frames_received: raw.frames_received,
                    groups_completed: raw.groups_completed,
                    rejected_sessions: raw.rejected_sessions,
                })
            })
        }
    }

    /// Opt an authenticated endpoint and topic into protected MoQ delivery.
    pub fn enable_moq_delivery(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        peer_endpoint: EndpointId,
        topic: &str,
    ) -> Result<()> {
        #[cfg(not(feature = "moq"))]
        {
            let _ = (workspace, revision, peer_endpoint, topic);
            Err(ApiError::unsupported(
                "stream transport is not enabled in this build",
            ))
        }
        #[cfg(feature = "moq")]
        {
            self.call(Op::EnableMoqDelivery, |session| {
                let topic = arachne_node::Topic::new(topic.to_owned())
                    .map_err(|error| ApiError::invalid_input("topic", error.to_string()))?;
                session
                    .runtime
                    .block_on(session.node.enable_moq_delivery(
                        workspace.to_bytes(),
                        revision,
                        peer_endpoint.to_bytes(),
                        topic,
                    ))
                    .map_err(crate::errors::node)
            })
        }
    }

    pub fn network_change(&self) -> Result<()> {
        self.call(Op::NetworkChange, ops::debug::network_change)?;
        Ok(())
    }

    /// Interrupt the blocking op in flight (its outbound control
    /// exchanges). Not sticky: the latch clears when that op ends, so the
    /// next op runs normally.
    pub fn cancel(&self) -> Result<()> {
        crate::registry::cancel_session(self.handle()?).map_err(client_error)
    }

    /// Park until the session may have work, up to `timeout` (`None`: no
    /// timeout). Holds no client or session lock. `Ok(true)`: drain the
    /// queues (or call `next_event`), then call again. `Ok(false)`: the
    /// timeout passed, `wake` was called, or the client closed.
    pub fn wait_for_work(&self, timeout: Option<std::time::Duration>) -> Result<bool> {
        crate::registry::wait_session_for(self.handle()?, timeout).map_err(client_error)
    }

    /// Release one waiter (`wait_for_work` or `next_event`) without work,
    /// for example at host shutdown.
    pub fn wake(&self) -> Result<()> {
        crate::registry::wake_session(self.handle()?).map_err(client_error)
    }

    /// The next event of any queue, up to `timeout` (`None`: no timeout).
    /// `Ok(None)`: the timeout passed, `wake` was called, or the client
    /// closed while it waited. Queue events repeat until the host drains
    /// the queue with its poll call; a ready job reports once. After
    /// `close`, it fails with `Closed`.
    pub fn next_event(&self, timeout: Option<std::time::Duration>) -> Result<Option<Event>> {
        crate::events::next(self.handle()?, timeout).map_err(client_error)
    }

    /// Give each later blocking op this deadline. At the deadline the op
    /// fails with `DeadlineExceeded` and the session stays usable.
    pub fn set_deadline(&self, deadline: Option<std::time::Duration>) {
        if let Ok(handle) = self.handle()
            && let Ok(entry) = crate::registry::entry(handle)
        {
            entry.set_deadline(deadline);
        }
    }

    /// Service one queued peer-control exchange and report whether one was served.
    pub fn poll_control(&self) -> Result<bool> {
        let event = self.call(Op::PollAdmission, |session| {
            admission::poll(session, admission::PollAdmissionArgs { profile: false })
        })?;
        Ok(!event.is_null())
    }

    pub fn add_address_hint(&self, peer: EndpointId, address: &str) -> Result<()> {
        self.call(Op::AddAddressHint, |session| {
            ops::policy::add_address_hint(
                session,
                ops::policy::AddressHintArgs {
                    peer: peer.to_bytes(),
                    address: address.to_owned(),
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
    pub fn install_member_policy(&self, revision: u64, topics: &[String]) -> Result<()> {
        self.call(Op::InstallMemberPolicy, |session| {
            ops::policy::install_member_policy(
                session,
                ops::policy::MemberPolicyArgs {
                    revision,
                    topics: topics.to_vec(),
                },
            )
        })?;
        Ok(())
    }

    /// Stage a workspace publication with the default `Critical` delivery mode.
    pub fn stage_protected_publication(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        topic: &str,
        id: RecordId,
        payload: Vec<u8>,
    ) -> Result<Arc<PublicationCandidate>> {
        self.stage_protected_publication_with_current(workspace, revision, topic, id, payload, None)
    }

    /// Stage a workspace publication. `None` uses `Critical`; `Some` uses `Current`.
    pub fn stage_protected_publication_with_current(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        topic: &str,
        id: RecordId,
        payload: Vec<u8>,
        current: Option<PublicationCurrent>,
    ) -> Result<Arc<PublicationCandidate>> {
        self.stage_protected_publication_with_options(
            workspace,
            revision,
            topic,
            id,
            payload,
            PublicationOptions {
                recipients: Vec::new(),
                mode: current.map_or(PublicationMode::Critical, |metadata| {
                    PublicationMode::Current { metadata }
                }),
            },
        )
    }

    /// Stage a protected publication with an explicit audience and delivery mode.
    /// Core validates the audience and saves the publication when it is adopted.
    pub fn stage_protected_publication_with_options(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        topic: &str,
        id: RecordId,
        payload: Vec<u8>,
        options: PublicationOptions,
    ) -> Result<Arc<PublicationCandidate>> {
        let (current, bulk) = match options.mode {
            PublicationMode::Critical => (None, false),
            PublicationMode::Bulk => (None, true),
            PublicationMode::Current { metadata } => (Some(metadata), false),
        };
        let staged = self.call(Op::StageNetworkPublication, |session| {
            publication::stage(
                session,
                publication::StagePublicationArgs {
                    workspace: Some(workspace.to_bytes()),
                    revision,
                    topic: topic.to_owned(),
                    id: id.to_bytes(),
                    payload,
                    recipients: options
                        .recipients
                        .into_iter()
                        .map(MemberId::to_bytes)
                        .collect(),
                    current: current.map(|current| publication::CurrentPublication {
                        selector: current.selector.to_bytes(),
                        replacement_key: current.replacement_key.to_bytes(),
                        expires_at: current.expires_at,
                        tombstone: current.tombstone,
                    }),
                    bulk,
                },
            )
        })?;
        if staged.workspace != workspace.to_bytes() {
            return Err(error(
                ErrorKind::Internal,
                "publication candidate workspace mismatch",
            ));
        }
        Ok(PublicationCandidate::new(
            self.handle()?,
            staged.workspace,
            staged.snapshot,
        ))
    }

    pub fn adopt_protected_publication(
        &self,
        candidate: &PublicationCandidate,
    ) -> Result<DeliveryReport> {
        let adopted = self
            .adopt(
                Op::AdoptPublication,
                &candidate.staged,
                &[CandidateKind::Publication],
            )?
            .adopted()?;
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
    /// Adopt it with `adopt_protected_reception`; core saves it first.
    pub fn poll_protected(&self) -> Result<Option<Arc<ProtectedReceptionCandidate>>> {
        let staged = self.call(Op::PollProtected, receive::poll_protected)?;
        staged
            .map(|staged| {
                Ok(ProtectedReceptionCandidate::new(
                    self.handle()?,
                    staged.workspace,
                    staged.snapshot,
                ))
            })
            .transpose()
    }

    /// Adopt a staged inbox candidate: a reception from `poll_protected`, or an
    /// acknowledgement or rejection. A received object then waits in the
    /// durable inbox; read it with `poll_pending_object`.
    pub fn adopt_protected_reception(&self, candidate: &ProtectedReceptionCandidate) -> Result<()> {
        self.adopt(
            Op::AdoptReception,
            &candidate.staged,
            &[CandidateKind::Reception],
        )?
        .adopted()?;
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
            workspace: pending.workspace.into(),
            revision: pending.revision,
            member: pending.member.into(),
            endpoint: pending.endpoint.into(),
            topic: pending.topic,
            id: pending.id.into(),
            sequence: pending.sequence,
            payload: pending.payload,
            recipients: pending.recipients.into_iter().map(Into::into).collect(),
            counter: pending.counter,
            epoch: pending.epoch,
            from_losing_branch: pending.from_losing_branch,
            current: pending.current,
        }))
    }

    /// Stage the application's durable acceptance of a pending object. Save
    /// then adopt it with `adopt_protected_reception`.
    pub fn stage_object_acknowledgement(
        &self,
        object: &ReceivedProtectedPublication,
    ) -> Result<Arc<ProtectedReceptionCandidate>> {
        self.stage_inbox_resolution(Op::StageObjectAcknowledgement, receive::acknowledge, object)
    }

    /// Stage a permanent application rejection of a pending object. Its
    /// identity stays recorded, so it is never delivered again.
    pub fn stage_object_rejection(
        &self,
        object: &ReceivedProtectedPublication,
    ) -> Result<Arc<ProtectedReceptionCandidate>> {
        self.stage_inbox_resolution(Op::StageObjectRejection, receive::reject, object)
    }

    pub fn set_interest(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        topic: &str,
        subscribed: bool,
    ) -> Result<()> {
        self.call(Op::SetInterest, |session| {
            ops::policy::set_interest(
                session,
                ops::policy::InterestArgs {
                    workspace: workspace.to_bytes(),
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
            workspace: raw.workspace.into(),
            revision: raw.revision,
            topic: raw.topic,
            subscribed: raw.subscribed,
            admission: raw.admission.into(),
        }))
    }

    pub fn fetch_recovery_range(
        &self,
        request: RecoveryRangeRequest,
    ) -> Result<RecoveryRangeStatus> {
        self.fetch_recovery_range_at(request, None)
    }

    /// `fetch_recovery_range` for an earlier author epoch that is still in
    /// the receive window (A3f). `None` is the current epoch.
    pub fn fetch_recovery_range_at(
        &self,
        request: RecoveryRangeRequest,
        epoch: Option<u64>,
    ) -> Result<RecoveryRangeStatus> {
        let status = self.call(Op::FetchRecoveryRange, |session| {
            ops::recovery::fetch_range(
                session,
                ops::recovery::FetchRangeArgs {
                    peer: request.peer.map(EndpointId::to_bytes),
                    author: request.author.map(MemberId::to_bytes),
                    revision: request.revision,
                    topics: request.topics,
                    after: request.after,
                    through: request.through,
                    epoch,
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
        self.recovery_stage(staged)
    }

    pub fn adopt_recovery(&self, candidate: &RecoveryCandidate) -> Result<RecoveryAdoption> {
        let adopted = self
            .adopt(
                Op::AdoptRecovery,
                &candidate.candidate.staged,
                &[CandidateKind::Recovery],
            )?
            .adopted()?;
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
            workspace: adopted.workspace.into(),
            epoch: adopted.epoch,
            member_count: adopted.members as u64,
            durable: adopted.durable,
            recovered_publications: recovered_publications as u64,
            missing_publications: missing_publications as u64,
        })
    }

    /// Close the session. Idempotent, and callable from any thread: it
    /// interrupts the op in flight, releases every waiter, and later calls
    /// fail with `Closed`. Bounded by the close drain deadline.
    pub fn close(&self) -> Result<()> {
        if self.closed.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return Ok(());
        }
        crate::registry::close_session(self.handle)
    }
}

impl Client {
    /// A native storage call. These report every failure as `Storage`, as
    /// before; `code()` gives the exact failure.
    fn stored<T>(
        &self,
        body: impl FnOnce(&mut Session) -> std::result::Result<T, ApiError>,
    ) -> Result<T> {
        persistence::with_session(self.handle()?, body).map_err(client_error)
    }

    fn nearby_advertisement(&self, args: ops::nearby::AdvertiseArgs) -> Result<bool> {
        let state = self.call(Op::SetNearbyWorkspace, |session| {
            ops::nearby::advertise(session, args)
        })?;
        Ok(state.state == "nearby_workspace_advertised")
    }

    /// `set_deadline`, as a builder.
    pub fn with_deadline(self: Arc<Self>, deadline: std::time::Duration) -> Arc<Self> {
        self.set_deadline(Some(deadline));
        self
    }

    /// Fixture: install a caller-made routing policy. Rejected once the
    /// session owns a workspace.
    #[cfg(feature = "test-fixtures")]
    pub fn install_policy(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        endpoints: &[PeerPolicy],
    ) -> Result<()> {
        let endpoints = endpoints
            .iter()
            .map(|policy| ops::policy::EndpointPolicy {
                peer: policy.peer.to_bytes(),
                publish: policy.publish.clone(),
                subscribe: policy.subscribe.clone(),
            })
            .collect();
        self.call(Op::InstallVerifiedPolicy, |session| {
            ops::policy::install_verified_policy(
                session,
                ops::policy::VerifiedPolicyArgs {
                    workspace: workspace.to_bytes(),
                    revision,
                    endpoints,
                },
            )
        })
    }

    fn stage_inbox_resolution(
        &self,
        op: Op,
        stage: fn(
            &mut Session,
            receive::ResolveArgs,
        ) -> std::result::Result<publication::StagedObject, ApiError>,
        object: &ReceivedProtectedPublication,
    ) -> Result<Arc<ProtectedReceptionCandidate>> {
        let staged = self.call(op, |session| {
            stage(
                session,
                receive::ResolveArgs {
                    member: object.member.to_bytes(),
                    topic: object.topic.clone(),
                    counter: object.counter,
                    id: object.id.to_bytes(),
                },
            )
        })?;
        Ok(ProtectedReceptionCandidate::new(
            self.handle()?,
            staged.workspace,
            staged.snapshot,
        ))
    }

    /// Fixture: an unprotected publication. Rejected once the session owns
    /// a workspace.
    #[cfg(feature = "test-fixtures")]
    pub fn publish(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        topic: &str,
        payload: Vec<u8>,
    ) -> Result<DeliveryReport> {
        self.call(Op::Publish, |session| {
            ops::policy::publish(
                session,
                ops::policy::PublishArgs {
                    workspace: workspace.to_bytes(),
                    revision,
                    topic: topic.to_owned(),
                    payload,
                },
            )
        })
    }

    /// Fixture: the next unprotected message.
    #[cfg(feature = "test-fixtures")]
    pub fn poll(&self) -> Result<Option<Publication>> {
        let message = self.call(Op::Poll, ops::policy::poll)?;
        Ok(message.map(|message| Publication {
            workspace: message.workspace.into(),
            revision: message.revision,
            sender: message.sender.into(),
            topic: message.topic,
            payload: message.payload,
        }))
    }

    /// Run one typed op on this client's session (guards and wake-ups
    /// included; see `ops::run`).
    fn call<T>(
        &self,
        op: Op,
        body: impl FnOnce(&mut Session) -> std::result::Result<T, ApiError>,
    ) -> Result<T> {
        ops::run(self.handle()?, op, body).map_err(client_error)
    }

    /// Adopt `staged` if it belongs to this client, is unused, and is one of
    /// `kinds`. Every check runs before anything changes.
    fn adopt(
        &self,
        op: Op,
        staged: &Staged,
        kinds: &[CandidateKind],
    ) -> Result<candidate::AdoptReply> {
        if staged.client != self.handle()? {
            return Err(client_error(ApiError::wrong_state(
                "candidate belongs to another client",
            )));
        }
        let mut token = staged.lock();
        let value = token
            .clone()
            .ok_or_else(|| ApiError::candidate_stale("candidate was already used or discarded"))?;
        let reply = self.call(op, |session| candidate::adopt_exact(session, kinds, value))?;
        *token = None;
        Ok(reply)
    }

    fn candidate_of(&self, staged: management::StagedCandidate) -> Result<Arc<WorkspaceCandidate>> {
        Ok(WorkspaceCandidate::new(
            self.handle()?,
            staged.workspace,
            staged.snapshot,
        ))
    }

    fn handle(&self) -> Result<i64> {
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(error(ErrorKind::Closed, "client is closed"));
        }
        Ok(self.handle)
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if !self.closed.swap(true, std::sync::atomic::Ordering::AcqRel) {
            let _ = crate::registry::close_session(self.handle);
        }
    }
}

fn join_request(pending: join::PendingJoinInfo) -> Result<JoinRequest> {
    Ok(JoinRequest {
        workspace: pending.workspace.into(),
        member: pending.member.id.into(),
        endpoint: pending.endpoint.into(),
        admission_request: pending.admission_request.ok_or_else(|| {
            error(
                ErrorKind::InvalidInput,
                "invitation has no admission request",
            )
        })?,
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
            candidate_count: candidate_count as u64,
            automatic_source,
        },
        S::RecoveryRangeReady(ready) => RecoveryRangeStatus::Ready(RecoveryRangeReady {
            workspace: ready.workspace.into(),
            author: ready.author.into(),
            peer: ready.peer.into(),
            epoch: ready.epoch,
            revision: ready.revision,
            after: ready.after,
            through: ready.through,
            packet_count: ready.packet_count as u64,
            retained_bytes: ready.retained_bytes as u64,
            automatic_source: ready.automatic_source,
            attempted: ready.attempted.map(|value| value as u64),
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
            attempted: attempted as u64,
            reason,
            automatic_source,
        },
        S::RecoveryRangeRejected { reason, .. } => RecoveryRangeStatus::Rejected { reason },
        S::RecoveryRangeCancelled { .. } => RecoveryRangeStatus::Cancelled,
    }
}

fn opened_info(opened: ops::workspace::WorkspaceOpened) -> WorkspaceInfo {
    WorkspaceInfo {
        workspace: opened.workspace.into(),
        workspace_name: opened.workspace_name,
        epoch: opened.epoch,
        member_count: opened.members as u64,
        durable: opened.durable,
        phase: opened.activity.phase,
        reason: opened.activity.reason,
    }
}

fn workspace_info(adopted: candidate::Adopted) -> WorkspaceInfo {
    WorkspaceInfo {
        workspace: adopted.workspace.into(),
        workspace_name: adopted.workspace_name,
        epoch: adopted.epoch,
        member_count: adopted.members as u64,
        durable: adopted.durable,
        phase: adopted.activity.phase,
        reason: adopted.activity.reason,
    }
}

impl TryFrom<crate::membership::RosterMember> for MemberInfo {
    type Error = ApiError;

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
            id: value.id.into(),
            endpoint: value.endpoint.into(),
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
            admitted: value.admitted.into_iter().map(Into::into).collect(),
            queued: value.queued,
            failed: value
                .failed
                .into_iter()
                .map(|failure| DeliveryFailure {
                    peer: failure.peer.into(),
                    error: failure.error,
                })
                .collect(),
        }
    }
}

impl From<RawPublication> for Publication {
    fn from(value: RawPublication) -> Self {
        Self {
            workspace: value.workspace.into(),
            revision: value.revision,
            sender: value.sender.into(),
            topic: value.topic,
            payload: value.payload,
        }
    }
}

/// An error the client itself finds (bad arguments, a reply it cannot use).
fn error(kind: ErrorKind, message: impl Into<String>) -> ApiError {
    let message = message.into();
    match kind {
        ErrorKind::Closed => ApiError::Closed,
        ErrorKind::InvalidInput => ApiError::invalid_input("", message),
        ErrorKind::Transport => ApiError::transport_failed(None, message),
        ErrorKind::Internal => ApiError::internal(message),
    }
}

/// Counters of the stream transport. Queued data is not a remote receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct StreamMetrics {
    pub sessions_total: u64,
    pub sessions_active: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    /// Groups returned by the subscriber, across all peers.
    pub groups_received: u64,
    /// First frames returned by their group readers.
    pub frames_received: u64,
    /// Groups whose second read confirmed the expected clean end.
    pub groups_completed: u64,
    pub rejected_sessions: u64,
}

mod recovery;
pub use recovery::*;

mod resources;
pub use resources::*;

mod progress;
pub use progress::*;

/// Native publication defaults for foreign bindings: workspace audience and
/// `Critical` mode. Set `recipients` for a directed audience, or `mode` for Bulk
/// or Current delivery.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn default_publication_options() -> PublicationOptions {
    PublicationOptions::default()
}

/// Native transport defaults for foreign bindings.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn default_transport_options() -> TransportOptions {
    TransportOptions::default()
}

/// Start with the profile defaults; attach a persistent key and storage before
/// opening a workspace client.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn default_client_config(network: Network) -> ClientConfig {
    ClientConfig {
        network,
        secret: None,
        transport: TransportOptions::default(),
        storage: None,
    }
}

#[cfg(test)]
mod publication_tests;
