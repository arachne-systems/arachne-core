//! Typed lifecycle progress and opaque peer protocol data.
//! Wire decoding stays inside Core; callers cannot edit an admission history.
use super::*;
use crate::workspace_activity::Activity;
use serde::de::DeserializeOwned;

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[serde(rename_all = "snake_case")]
pub enum AdmissionStatusKind {
    AdmissionNotSent,
    AdmissionPending,
    AdmissionWaiting,
    AdmissionQueued,
    ApprovalPending,
    ApprovalRequested,
    AdmissionUnavailable,
    AdmissionRecoveryRequired,
    AdmissionReplied,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AdmissionStatus {
    pub state: AdmissionStatusKind,
    pub peer: Option<EndpointId>,
    pub reason: Option<String>,
    pub recovery: Option<String>,
    pub checkpoint_pending: bool,
}

/// A peer's admission history. Stage it on the client that requested it.
/// Membership authorization is verified by the native stage operation.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct AdmissionGrant {
    client: i64,
    workspace: WorkspaceId,
    epoch: u64,
    welcome: Vec<u8>,
    commits: Vec<crate::membership::JoinStep>,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl AdmissionGrant {
    pub fn workspace(&self) -> WorkspaceId {
        self.workspace
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn history_steps(&self) -> u64 {
        self.commits.len() as u64
    }
}

#[non_exhaustive]
#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum AdmissionResponse {
    Status { status: AdmissionStatus },
    Granted { grant: Arc<AdmissionGrant> },
}

#[non_exhaustive]
#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum JoinProgress {
    Status { status: AdmissionStatus },
    AwaitingAdoption { candidate: Arc<JoinCandidate> },
    Joined { workspace: WorkspaceInfo },
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum MemberUpdateState {
    Available,
    Current,
    Unavailable,
    Denied,
    Stale,
    PeerBehind,
    BranchMismatch,
    NameUpdateAvailable,
    NameCheckpointAvailable,
    NamePeerBehind,
    NameConflict,
    NameUnavailable,
    AwaitingAdoption,
    /// A new advisory state. It grants no rights and carries no mutable protocol data.
    Other {
        name: String,
    },
}

#[non_exhaustive]
#[derive(Clone, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum MembershipCandidate {
    Workspace { candidate: Arc<WorkspaceCandidate> },
    Removal { candidate: Arc<RemovalCandidate> },
}

enum MemberPayload {
    Step(crate::membership::JoinStep),
    NameRecord(Vec<u8>),
    NameCheckpoint(Vec<u8>),
    Candidate(MembershipCandidate),
    None,
}

/// A decoded peer update. Only Core can construct it. Its state is a peer's
/// observation until `stage_membership_update` verifies and stages the change.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct MemberUpdate {
    client: i64,
    state: MemberUpdateState,
    workspace: Option<WorkspaceId>,
    epoch: Option<u64>,
    peer: Option<EndpointId>,
    fingerprint: Option<Key32>,
    payload: MemberPayload,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl MemberUpdate {
    pub fn state(&self) -> MemberUpdateState {
        self.state.clone()
    }
    pub fn workspace(&self) -> Option<WorkspaceId> {
        self.workspace
    }
    pub fn epoch(&self) -> Option<u64> {
        self.epoch
    }
    pub fn peer(&self) -> Option<EndpointId> {
        self.peer
    }
    pub fn fingerprint(&self) -> Option<Key32> {
        self.fingerprint
    }
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum WorkspaceProgressState {
    Idle,
    WorkspaceCommitted,
    WorkspaceReplyReady,
    WorkspaceNameCommitted,
    SelfUpdateCommitted,
    MembershipReplied,
    AdmissionQueued,
    AdmissionReplied,
    ApprovalRequested,
    NearbyInvitationReceived,
    NearbyInvitationRejected,
    PresenceReplied,
    ControlServed,
    /// A new local advisory event. Read the typed activity and roster for authority.
    Other {
        name: String,
    },
}

/// One admission notice. An attempt ID is present after native queuing;
/// rejected pre-queue requests can still carry an approval notice.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AdmissionNotice {
    pub attempt_id: Option<AttemptId>,
    pub endpoint: EndpointId,
    pub request: Vec<u8>,
    pub display_name: Option<String>,
    pub automatic: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct WorkspaceProgress {
    pub state: WorkspaceProgressState,
    pub activity: Activity,
    pub presence: Option<PresenceRound>,
    pub workspace: Option<WorkspaceId>,
    pub epoch: Option<u64>,
    pub member_count: Option<u64>,
    pub peer: Option<EndpointId>,
    pub accepted: Option<bool>,
    pub reply_queued: Option<bool>,
    pub remote_receipt: bool,
    pub reason: Option<String>,
    pub approval: Option<AdmissionNotice>,
    pub nearby_invitation: Option<Vec<u8>>,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Client {
    /// Advance a stored join. A pushed admission can return a candidate; adopt
    /// it through `adopt_join`. All other committed results are already durable.
    pub fn drive_join(&self) -> Result<JoinProgress> {
        let handle = self.handle()?;
        self.call(Op::DriveJoin, |session| {
            let value = join::drive(session)?;
            match value.get("state").and_then(Value::as_str) {
                Some("workspace_joined") => Ok(JoinProgress::Joined {
                    workspace: workspace_result(&value, &projected_activity(session))?,
                }),
                Some("awaiting_join_save") => {
                    let staged = session
                        .transition
                        .staged
                        .as_ref()
                        .ok_or_else(|| ApiError::candidate_stale("join candidate is gone"))?;
                    Ok(JoinProgress::AwaitingAdoption {
                        candidate: JoinCandidate::new(
                            handle,
                            staged.workspace.id(),
                            staged.snapshot.clone(),
                        ),
                    })
                }
                _ => Ok(JoinProgress::Status {
                    status: admission_status(&value)?,
                }),
            }
        })
    }

    pub fn request_admission(&self, peer: EndpointId) -> Result<AdmissionResponse> {
        let handle = self.handle()?;
        let value = self.call(Op::RequestAdmission, |session| {
            join::request_admission(
                session,
                join::RequestAdmissionArgs {
                    peer: peer.to_bytes(),
                },
            )
        })?;
        if value.get("state").is_some() {
            return Ok(AdmissionResponse::Status {
                status: admission_status(&value)?,
            });
        }
        Ok(AdmissionResponse::Granted {
            grant: Arc::new(AdmissionGrant {
                client: handle,
                workspace: id_required(&value, "workspace")?,
                epoch: field(&value, "epoch")?,
                welcome: field(&value, "welcome")?,
                commits: field(&value, "commits")?,
            }),
        })
    }

    /// Stage the exact received history, including management and self-update steps.
    pub fn stage_join_grant(&self, grant: &AdmissionGrant) -> Result<Arc<JoinCandidate>> {
        let handle = self.handle()?;
        if grant.client != handle {
            return Err(ApiError::wrong_state(
                "admission grant belongs to another client",
            ));
        }
        let staged = self.call(Op::StageJoin, |session| {
            join::stage(
                session,
                join::StageJoinArgs {
                    commits: grant.commits.clone(),
                    welcome: grant.welcome.clone(),
                },
            )
        })?;
        Ok(JoinCandidate::new(
            handle,
            staged.workspace,
            staged.snapshot,
        ))
    }

    /// Serve one queued operation and advance native durable lifecycle work.
    /// Presence remains part of the result from this same drive operation.
    pub fn drive_workspace(&self) -> Result<WorkspaceProgress> {
        self.call(Op::DriveWorkspace, |session| {
            let value = admission::drive_workspace(session)?;
            workspace_progress(value, projected_activity(session))
        })
    }

    pub fn poll_membership_update(&self) -> Result<Option<Arc<MemberUpdate>>> {
        let handle = self.handle()?;
        self.call(Op::PollMembershipUpdate, |session| {
            let value = ops::membership::poll_update(session)?;
            if value.is_null() {
                return Ok(None);
            }
            let name: String = field(&value, "state")?;
            let payload = match name.as_str() {
                "membership_update_available" => MemberPayload::Step(field(&value, "step")?),
                "workspace_name_update_available" => {
                    MemberPayload::NameRecord(field(&value, "name_record")?)
                }
                "workspace_name_checkpoint_available" => {
                    MemberPayload::NameCheckpoint(field(&value, "name_checkpoint")?)
                }
                _ if value.get("candidate").is_some() => {
                    MemberPayload::Candidate(staged_member(session, handle)?)
                }
                _ => MemberPayload::None,
            };
            Ok(Some(Arc::new(MemberUpdate {
                client: handle,
                state: member_state(&name),
                workspace: id_optional(&value, "workspace")?,
                epoch: optional(&value, "epoch")?,
                peer: id_optional(&value, "peer")?,
                fingerprint: id_optional(&value, "epoch_fingerprint")?,
                payload,
            })))
        })
    }

    pub fn stage_membership_update(&self, update: &MemberUpdate) -> Result<MembershipCandidate> {
        let handle = self.handle()?;
        if update.client != handle {
            return Err(ApiError::wrong_state(
                "membership update belongs to another client",
            ));
        }
        match &update.payload {
            MemberPayload::Candidate(candidate) => Ok(candidate.clone()),
            MemberPayload::Step(step) => self.call(Op::StageAdmissionUpdate, |session| {
                management::stage_admission_update(
                    session,
                    management::AdmissionUpdateArgs { step: step.clone() },
                )?;
                staged_member(session, handle)
            }),
            MemberPayload::NameRecord(record) => {
                self.call(Op::StageWorkspaceNameUpdate, |session| {
                    management::stage_workspace_name_update(
                        session,
                        management::WorkspaceNameUpdateArgs {
                            name_record: record.clone(),
                        },
                    )?;
                    staged_member(session, handle)
                })
            }
            MemberPayload::NameCheckpoint(checkpoint) => {
                self.call(Op::StageWorkspaceNameCheckpoint, |session| {
                    management::stage_workspace_name_checkpoint(
                        session,
                        management::WorkspaceNameCheckpointArgs {
                            name_checkpoint: checkpoint.clone(),
                        },
                    )?;
                    staged_member(session, handle)
                })
            }
            MemberPayload::None => Err(ApiError::wrong_state(
                "membership observation has no change to stage",
            )),
        }
    }
}

fn staged_member(session: &Session, handle: i64) -> Result<MembershipCandidate> {
    let (kind, token) = candidate::staged(session)
        .ok_or_else(|| ApiError::candidate_stale("membership candidate is gone"))?;
    if let Some((removed, _)) = &session.transition.removal {
        return Ok(MembershipCandidate::Removal {
            candidate: RemovalCandidate::new(handle, removed.workspace_id(), token.to_vec()),
        });
    }
    if !WORKSPACE_KINDS.contains(&kind) {
        return Err(ApiError::wrong_state(
            "candidate is not a membership change",
        ));
    }
    let workspace = session
        .transition
        .staged
        .as_ref()
        .ok_or_else(|| ApiError::candidate_stale("membership candidate is gone"))?
        .workspace
        .id();
    Ok(MembershipCandidate::Workspace {
        candidate: WorkspaceCandidate::new(handle, workspace, token.to_vec()),
    })
}

fn field<T: DeserializeOwned>(value: &Value, name: &str) -> Result<T> {
    serde_json::from_value(value.get(name).cloned().unwrap_or(Value::Null))
        .map_err(|_| ApiError::transport_failed(None, format!("invalid protocol field: {name}")))
}
fn optional<T: DeserializeOwned>(value: &Value, name: &str) -> Result<Option<T>> {
    field(value, name)
}
fn id_optional<T: crate::client_wire::WireId>(value: &Value, name: &str) -> Result<Option<T>> {
    optional::<Vec<u8>>(value, name)?
        .map(|bytes| T::from_wire(&bytes))
        .transpose()
}
fn id_required<T: crate::client_wire::WireId>(value: &Value, name: &str) -> Result<T> {
    id_optional(value, name)?
        .ok_or_else(|| ApiError::transport_failed(None, format!("missing protocol field: {name}")))
}
fn admission_status(value: &Value) -> Result<AdmissionStatus> {
    Ok(AdmissionStatus {
        state: field(value, "state")?,
        peer: id_optional(value, "peer")?,
        reason: optional(value, "reason")?,
        recovery: optional(value, "recovery")?,
        checkpoint_pending: value.get("phase").and_then(Value::as_str) == Some("checkpoint"),
    })
}
fn workspace_result(value: &Value, activity: &Activity) -> Result<WorkspaceInfo> {
    Ok(WorkspaceInfo {
        workspace: id_required(value, "workspace")?,
        workspace_name: optional(value, "workspace_name")?,
        epoch: field(value, "epoch")?,
        member_count: field(value, "members")?,
        durable: field(value, "durable")?,
        phase: activity.phase,
        reason: activity.reason.clone(),
    })
}
fn member_state(name: &str) -> MemberUpdateState {
    match name {
        "membership_update_available" => MemberUpdateState::Available,
        "membership_current" => MemberUpdateState::Current,
        "membership_unavailable" => MemberUpdateState::Unavailable,
        "membership_denied" => MemberUpdateState::Denied,
        "membership_update_stale" => MemberUpdateState::Stale,
        "membership_peer_behind" => MemberUpdateState::PeerBehind,
        "membership_branch_mismatch" => MemberUpdateState::BranchMismatch,
        "workspace_name_update_available" => MemberUpdateState::NameUpdateAvailable,
        "workspace_name_checkpoint_available" => MemberUpdateState::NameCheckpointAvailable,
        "workspace_name_peer_behind" => MemberUpdateState::NamePeerBehind,
        "workspace_name_conflict" => MemberUpdateState::NameConflict,
        "workspace_name_unavailable" => MemberUpdateState::NameUnavailable,
        "awaiting_save" => MemberUpdateState::AwaitingAdoption,
        _ => MemberUpdateState::Other {
            name: name.to_owned(),
        },
    }
}
fn workspace_progress(value: Value, activity: Activity) -> Result<WorkspaceProgress> {
    let name = value.get("state").and_then(Value::as_str).unwrap_or("");
    let state = match name {
        "" => WorkspaceProgressState::Idle,
        "workspace_committed" => WorkspaceProgressState::WorkspaceCommitted,
        "workspace_reply_ready" => WorkspaceProgressState::WorkspaceReplyReady,
        "workspace_name_committed" => WorkspaceProgressState::WorkspaceNameCommitted,
        "self_update_committed" => WorkspaceProgressState::SelfUpdateCommitted,
        "membership_replied" => WorkspaceProgressState::MembershipReplied,
        "admission_queued" => WorkspaceProgressState::AdmissionQueued,
        "admission_replied" => WorkspaceProgressState::AdmissionReplied,
        "approval_requested" => WorkspaceProgressState::ApprovalRequested,
        "nearby_invitation_received" => WorkspaceProgressState::NearbyInvitationReceived,
        "nearby_invitation_rejected" => WorkspaceProgressState::NearbyInvitationRejected,
        "presence_replied" => WorkspaceProgressState::PresenceReplied,
        "profile_replied"
        | "invitation_checkpoint_replied"
        | "nearby_identity_replied"
        | "nearby_workspace_replied"
        | "recovery_range_replied"
        | "current_view_replied" => WorkspaceProgressState::ControlServed,
        _ => WorkspaceProgressState::Other {
            name: name.to_owned(),
        },
    };
    let presence = value
        .get("presence")
        .filter(|v| !v.is_null())
        .map(|round| {
            Ok(PresenceRound {
                sync_peer: id_optional(round, "sync_peer")?,
                response_errors: field(round, "response_errors")?,
                response_error: optional(round, "response_error")?,
            })
        })
        .transpose()?;
    let approval = if name == "approval_requested" {
        Some(AdmissionNotice {
            attempt_id: id_optional(&value, "attempt_id")?,
            endpoint: id_required(&value, "endpoint")?,
            request: field(&value, "request")?,
            display_name: optional(&value, "display_name")?,
            automatic: optional(&value, "automatic")?.unwrap_or(false),
        })
    } else {
        None
    };
    Ok(WorkspaceProgress {
        state,
        activity,
        presence,
        workspace: id_optional(&value, "workspace")?,
        epoch: optional(&value, "epoch")?,
        member_count: optional(&value, "members")?,
        peer: id_optional(&value, "peer")?,
        accepted: optional(&value, "accepted")?,
        reply_queued: optional(&value, "reply_queued")?,
        remote_receipt: optional(&value, "remote_receipt")?.unwrap_or(false),
        reason: optional(&value, "reason")?,
        approval,
        nearby_invitation: if name == "nearby_invitation_received" {
            optional(&value, "invitation")?
        } else {
            None
        },
    })
}

impl std::fmt::Debug for AdmissionGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionGrant")
            .field("workspace", &self.workspace)
            .field("epoch", &self.epoch)
            .field("history_steps", &self.commits.len())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for MemberUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemberUpdate")
            .field("state", &self.state)
            .field("workspace", &self.workspace)
            .field("epoch", &self.epoch)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}
fn projected_activity(session: &Session) -> Activity {
    let view = crate::session::activity_view(session);
    Activity {
        phase: view.phase,
        reason: view.reason,
    }
}
