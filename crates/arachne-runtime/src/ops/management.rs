//! Membership management: promote, demote, remove, leave (through a peer or
//! alone), a received membership step, the workspace name, and the member
//! roster.

use arachne_api::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};

use crate::errors::{self, security};
use crate::membership::{self, JoinStep, RosterReply, WireManagement};
use crate::session::{check_epoch_transition, seal_state};
use crate::workspace_activity::ActivityView;
use crate::{Session, StagedWorkspace, WorkspaceTransition};

/// A membership or workspace candidate that awaits the host's save.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct StagedCandidate {
    pub workspace: [u8; 32],
    pub workspace_name: Option<String>,
    /// The opaque candidate token; adopt it with the matching adopt op.
    #[serde(rename = "candidate")]
    pub snapshot: Vec<u8>,
    pub state: &'static str,
    pub durable: bool,
    /// A received leave request staged this removal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaving: Option<bool>,
    /// Workspace name history steps this checkpoint added, and still missing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_history_missing_added: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_history_missing: Option<u64>,
}

impl StagedCandidate {
    pub(crate) fn new(workspace: [u8; 32], workspace_name: Option<String>, snapshot: Vec<u8>) -> Self {
        Self {
            workspace,
            workspace_name,
            snapshot,
            state: "awaiting_save",
            durable: false,
            leaving: None,
            name_history_missing_added: None,
            name_history_missing: None,
        }
    }
}

/// This member's own removal, staged; adopting it ends the session.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct StagedRemoval {
    pub workspace: [u8; 32],
    /// The opaque candidate token; adopt it with the matching adopt op.
    #[serde(rename = "candidate")]
    pub snapshot: Vec<u8>,
    pub state: &'static str,
    pub removed: bool,
    pub durable: bool,
    pub activity: ActivityView,
}

/// A staged membership step: a new state, or this member's removal.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum StagedChange {
    Candidate(StagedCandidate),
    Removal(StagedRemoval),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagementArgs {
    pub action: WireManagement,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PeerArgs {
    pub peer: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionUpdateArgs {
    pub step: JoinStep,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RosterArgs {
    #[serde(default)]
    pub profiles: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspaceNameArgs {
    pub workspace_name: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspaceNameUpdateArgs {
    pub name_record: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspaceNameCheckpointArgs {
    pub name_checkpoint: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct StateReply {
    pub state: &'static str,
}

/// Stage one administrator action: promote, demote, remove, or an
/// invitation control change.
pub(crate) fn stage(session: &mut Session, args: ManagementArgs) -> Result<StagedCandidate, ApiError> {
    let action = args.action.action()?;
    membership::stage_management(session, action)
}

/// Leave through another member, who commits the departure.
pub(crate) fn leave_via_peer(session: &mut Session, args: PeerArgs) -> Result<StagedChange, ApiError> {
    membership::leave_via_peer(session, args.peer)
}

/// The last member leaves alone.
pub(crate) fn stage_solo_leave(session: &mut Session) -> Result<StagedRemoval, ApiError> {
    check_epoch_transition(session)?;
    let ended = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?
        .prepare_solo_leave()
        .map_err(security(ErrorCode::WrongState))?;
    membership::stage_removal(session, ended)
}

/// Stage a membership step fetched from a peer.
pub(crate) fn stage_admission_update(
    session: &mut Session,
    args: AdmissionUpdateArgs,
) -> Result<StagedChange, ApiError> {
    membership::stage_update(session, args.step)
}

pub(crate) fn member_roster(session: &mut Session, args: RosterArgs) -> Result<RosterReply, ApiError> {
    membership::roster(session, &args.profiles)
}

/// Mark this session's signed workspace profile as a service. This grants
/// no membership or publication rights.
pub(crate) fn use_service_profile(session: &mut Session) -> Result<StateReply, ApiError> {
    membership::lock_profiles(&session.membership.profiles).service = true;
    Ok(StateReply {
        state: "service_profile",
    })
}

/// Rename the workspace (an administrator's signed name record).
pub(crate) fn stage_workspace_name(
    session: &mut Session,
    args: WorkspaceNameArgs,
) -> Result<StagedCandidate, ApiError> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    let workspace = owner
        .prepare_workspace_name(&args.workspace_name)
        .map_err(security(ErrorCode::InvalidInput))?
        .workspace;
    stage_name(session, workspace, None)
}

/// Apply a peer's next signed name record.
pub(crate) fn stage_workspace_name_update(
    session: &mut Session,
    args: WorkspaceNameUpdateArgs,
) -> Result<StagedCandidate, ApiError> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    let workspace = owner
        .prepare_workspace_name_update(&args.name_record)
        .map_err(security(ErrorCode::InvalidInput))?;
    stage_name(session, workspace, None)
}

/// Apply a peer's name checkpoint.
pub(crate) fn stage_workspace_name_checkpoint(
    session: &mut Session,
    args: WorkspaceNameCheckpointArgs,
) -> Result<StagedCandidate, ApiError> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    let prepared = owner
        .prepare_workspace_name_checkpoint(&args.name_checkpoint)
        .map_err(security(ErrorCode::InvalidInput))?;
    stage_name(session, prepared.workspace, Some(prepared.missing))
}

fn stage_name(
    session: &mut Session,
    workspace: arachne_security::Workspace,
    missing: Option<u64>,
) -> Result<StagedCandidate, ApiError> {
    let snapshot = seal_state(session.records.is_some())?;
    let mut value = StagedCandidate::new(
        workspace.id(),
        workspace
            .workspace_name()
            .map_err(security(ErrorCode::Internal))?,
        snapshot.clone(),
    );
    if let Some(missing) = missing {
        value.name_history_missing_added = Some(missing);
        value.name_history_missing = Some(
            workspace
                .workspace_name_missing_history()
                .map_err(security(ErrorCode::Internal))?,
        );
    }
    session.transition.staged = Some(StagedWorkspace {
        publisher: session.delivery.publisher.clone(),
        inbox: session.delivery.inbox.clone(),
        transition: WorkspaceTransition::WorkspaceName,
        workspace,
        snapshot,
    });
    Ok(value)
}
