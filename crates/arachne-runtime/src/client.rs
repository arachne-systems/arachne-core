use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;

use crate::{
    WorkspacePhase, cancel, close, create, create_lan, create_nearby, create_relay, create_wan,
    create_wan_only, describe, execute, execute_stored, wait_for_work,
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
pub enum RouteKind {
    Direct,
    Relay,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct PublicationCurrent {
    pub selector: [u8; 32],
    pub replacement_key: [u8; 32],
    pub expires_at: u64,
    pub tombstone: bool,
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

    /// Begin joining from an invitation. The returned projection is intentionally
    /// left as JSON while the join protocol continues to evolve.
    pub fn begin_join(
        &self,
        invitation: &[u8],
        display_name: &str,
        peers: &[[u8; 32]],
    ) -> Result<Value> {
        self.request(json!({
            "op": "begin_join",
            "invitation": invitation,
            "display_name": display_name,
            "peers": peers,
        }))
    }

    pub fn drive_join(&self) -> Result<Value> {
        self.request(json!({"op": "drive_join"}))
    }

    pub fn drive_workspace(&self) -> Result<Value> {
        self.request(json!({"op": "drive_workspace"}))
    }

    /// Pull and durably adopt membership commits from an admitted peer until
    /// this client agrees with a current member.
    pub fn refresh_membership(&self) -> Result<MemberRoster> {
        self.drive_workspace()?;
        loop {
            let next = self.request(json!({"op": "next_membership_peer"}))?;
            let peer: Option<[u8; 32]> = serde_json::from_value(next["peer"].clone())
                .map_err(|parse_error| error(ErrorKind::Internal, parse_error.to_string()))?;
            let Some(peer) = peer else {
                return self.member_roster();
            };
            self.request(json!({"op": "fetch_membership_update", "peer": peer}))?;
            let update = loop {
                let update = self.request(json!({"op": "poll_membership_update"}))?;
                if !update.is_null() {
                    break update;
                }
                let _ = self.wait_for_work()?;
            };
            match update["state"].as_str() {
                Some("membership_current") => return self.member_roster(),
                Some("membership_update_available") => {
                    let request = serde_json::to_vec(&json!({
                        "op": "stage_admission_update",
                        "step": update["step"],
                    }))
                    .map_err(|parse_error| error(ErrorKind::Internal, parse_error.to_string()))?;
                    let [metadata, snapshot] = execute_stored(self.handle()?, &request, &[])
                        .map_err(|message| map_error(&message))?;
                    let staged: Value =
                        serde_json::from_slice(&metadata).map_err(|parse_error| {
                            error(
                                ErrorKind::Internal,
                                format!("invalid membership candidate: {parse_error}"),
                            )
                        })?;
                    if staged["state"] != "awaiting_save" || snapshot.is_empty() {
                        return Err(error(
                            ErrorKind::Internal,
                            "membership update did not return a staged snapshot",
                        ));
                    }
                    self.save_candidate(&snapshot)?;
                    execute_stored(self.handle()?, br#"{"op":"adopt_admission"}"#, &snapshot)
                        .map_err(|message| map_error(&message))?;
                }
                Some(state) => {
                    return Err(error(
                        ErrorKind::Transport,
                        format!("membership refresh stopped in state {state}"),
                    ));
                }
                None => {
                    return Err(error(ErrorKind::Internal, "membership update has no state"));
                }
            }
        }
    }

    pub fn use_service_profile(&self) -> Result<()> {
        self.request(json!({"op": "use_service_profile"}))?;
        Ok(())
    }

    pub fn enable_record_storage(&self, path: &Path, root: &[u8; 32]) -> Result<()> {
        crate::enable_record_storage(self.handle()?, path, root)
            .map_err(|message| map_error(&message))
    }

    pub fn restore_record_storage(
        &self,
        path: &Path,
        root: &[u8; 32],
        workspace: [u8; 32],
    ) -> Result<Value> {
        crate::restore_record_storage(self.handle()?, path, root, workspace)
            .map_err(|message| map_error(&message))
    }

    pub fn save_candidate(&self, token: &[u8]) -> Result<()> {
        crate::save_candidate(self.handle()?, token).map_err(|message| map_error(&message))
    }

    /// Enable durable group-object reception, committing its exact snapshot
    /// before adoption when this client has record storage.
    pub fn enable_object_delivery(&self) -> Result<()> {
        let durable = self.workspace_state()?.durable;
        let [metadata, snapshot] =
            execute_stored(self.handle()?, br#"{"op":"enable_object_delivery"}"#, &[])
                .map_err(|message| map_error(&message))?;
        let staged: Value = serde_json::from_slice(&metadata).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid object-delivery result: {parse_error}"),
            )
        })?;
        if staged.get("state").and_then(Value::as_str) == Some("object_delivery_enabled") {
            return Ok(());
        }
        if staged.get("state").and_then(Value::as_str) != Some("awaiting_reception_save")
            || snapshot.is_empty()
        {
            return Err(error(
                ErrorKind::Internal,
                "object delivery did not return a staged workspace snapshot",
            ));
        }
        if durable {
            self.save_candidate(&snapshot)?;
        }
        let [metadata, _] =
            execute_stored(self.handle()?, br#"{"op":"adopt_reception"}"#, &snapshot)
                .map_err(|message| map_error(&message))?;
        let adopted: Value = serde_json::from_slice(&metadata).map_err(|parse_error| {
            error(
                ErrorKind::Internal,
                format!("invalid object-delivery adoption: {parse_error}"),
            )
        })?;
        if adopted.get("state").and_then(Value::as_str) != Some("inbox_adopted") {
            return Err(error(
                ErrorKind::Internal,
                "object delivery was not adopted",
            ));
        }
        Ok(())
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
        let response = self.request(json!({"op": "workspace_metrics"}))?;
        let raw: RawConnectivityReport =
            serde_json::from_value(response).map_err(|parse_error| {
                error(
                    ErrorKind::Internal,
                    format!("invalid connectivity report: {parse_error}"),
                )
            })?;
        Ok(ConnectivityReport {
            workspace: raw.workspace,
            paths: raw
                .paths
                .into_iter()
                .map(|path| PeerRoute {
                    member: path.member,
                    route: match path.route.as_str() {
                        "direct" => RouteKind::Direct,
                        "relay" => RouteKind::Relay,
                        other => RouteKind::Custom(other.to_owned()),
                    },
                    rtt_ms: path.rtt_ms,
                })
                .collect(),
            paths_limited: raw.paths_limited,
            receive_queue: raw.receive_queue,
            repair_jobs: raw.repair_jobs,
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
            .ok_or_else(|| {
                error(
                    ErrorKind::Internal,
                    "publication candidate has no workspace",
                )
            })
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
        let [metadata, _] =
            execute_stored(self.handle()?, br#"{"op":"adopt_publication"}"#, snapshot)
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
struct RawConnectivityReport {
    workspace: [u8; 32],
    paths: Vec<RawPeerRoute>,
    paths_limited: bool,
    receive_queue: usize,
    repair_jobs: usize,
}

#[derive(Deserialize)]
struct RawPeerRoute {
    member: [u8; 32],
    route: String,
    rtt_ms: u64,
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
