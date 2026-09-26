//! Invitations: register a link (ordinary, personal, automatic, or
//! request-access), approve or decline a personal request, list the
//! controls, and inspect a link before joining.

use arachne_api::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};

use crate::client::{InvitationInfo, RouteHint};
use crate::errors::{self, security};
use crate::membership;
use crate::ops::admission::pending_approval_id;
use crate::ops::management::StagedCandidate;
use crate::session::check_epoch_transition;
use crate::{Session, WorkspaceTransition};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StageInvitationArgs {
    pub expires_at: u64,
    pub personal: bool,
    #[serde(default)]
    pub automatic: bool,
    #[serde(default)]
    pub request_access: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DecisionArgs {
    pub request: Vec<u8>,
    #[serde(default)]
    pub attempt_id: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InspectArgs {
    pub invitation: Vec<u8>,
    pub checkpoint: Vec<u8>,
}

/// One registered invitation link and its controls.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ControlRow {
    pub number: usize,
    pub key: [u8; 32],
    pub expires_at: u64,
    pub enabled: bool,
    pub personal: bool,
    pub automatic: bool,
    pub request_access: bool,
    pub approved: bool,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ControlsReply {
    pub invitations: Vec<ControlRow>,
}

/// What an invitation link says, verified against its checkpoint.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct InspectedInvitation {
    pub workspace: [u8; 32],
    pub invitation_key: [u8; 32],
    pub workspace_name: Option<String>,
    pub epoch: u64,
    pub personal_invitation: bool,
    pub automatic_approval: bool,
    pub expires_at: u64,
}

/// Register an invitation link in shared policy. The link is released only
/// by adoption, after the candidate is saved.
pub(crate) fn stage(session: &mut Session, args: StageInvitationArgs) -> Result<StagedCandidate, ApiError> {
    check_epoch_transition(session)?;
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    if args.request_access && (!args.personal || args.automatic) {
        return Err(ApiError::invalid_input(
            "request_access",
            "invalid request-access mode",
        ));
    }
    let (prepared, invitation, checkpoint) = if args.request_access {
        owner.prepare_request_invitation(args.expires_at)
    } else {
        owner.prepare_invitation(args.expires_at, args.personal, args.automatic)
    }
    .map_err(security(ErrorCode::InvalidInput))?;
    let action = prepared.action;
    let commit = prepared.commit.clone();
    let value = membership::stage_prepared(session, prepared)?;
    session.transition.staged.as_mut().unwrap().transition =
        WorkspaceTransition::Invitation(Box::new(invitation), checkpoint, action, commit);
    Ok(value)
}

/// Bind a personal invitation to one join request.
pub(crate) fn stage_approval(session: &mut Session, args: DecisionArgs) -> Result<StagedCandidate, ApiError> {
    check_epoch_transition(session)?;
    let pending_id = pending_approval_id(session, &args.request, args.attempt_id)?;
    let prepared = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?
        .prepare_invitation_approval(&args.request)
        .map_err(security(ErrorCode::InvalidInput))?;
    let value = membership::stage_prepared(session, prepared)?;
    session.admission.staged_approval_id = pending_id;
    Ok(value)
}

/// Decline a personal invitation request.
pub(crate) fn stage_decline(session: &mut Session, args: DecisionArgs) -> Result<StagedCandidate, ApiError> {
    check_epoch_transition(session)?;
    let pending_id = pending_approval_id(session, &args.request, args.attempt_id)?;
    let prepared = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?
        .prepare_invitation_decline(&args.request)
        .map_err(security(ErrorCode::InvalidInput))?;
    let value = membership::stage_prepared(session, prepared)?;
    session.admission.staged_approval_id = pending_id;
    Ok(value)
}

/// The registered invitation links, numbered for people.
pub(crate) fn controls(session: &mut Session) -> Result<ControlsReply, ApiError> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    let controls = owner
        .invitation_controls()
        .map_err(security(ErrorCode::Internal))?;
    Ok(ControlsReply {
        invitations: controls
            .iter()
            .filter(|control| !control.is_request_decision(&controls))
            .enumerate()
            .map(|(index, control)| ControlRow {
                number: index + 1,
                key: control.key,
                expires_at: control.expires_at,
                enabled: control.enabled,
                personal: control.personal,
                automatic: control.automatic(),
                request_access: control.request_access(),
                approved: control.approved(),
            })
            .collect(),
    })
}

pub(crate) fn inspect(_session: &mut Session, args: InspectArgs) -> Result<InspectedInvitation, ApiError> {
    inspected_invitation(&args.invitation, &args.checkpoint)
}

/// Verify an invitation presentation without an endpoint or join identity.
pub(crate) fn inspected_invitation(
    invitation: &[u8],
    checkpoint: &[u8],
) -> Result<InspectedInvitation, ApiError> {
    let invitation = arachne_security::Invitation::from_bytes(invitation)
        .map_err(security(ErrorCode::InvitationInvalid))?;
    let proof = invitation
        .join_proof(checkpoint)
        .map_err(security(ErrorCode::InvitationInvalid))?;
    let control = proof
        .invitation_control(invitation.key())
        .map_err(security(ErrorCode::InvitationInvalid))?;
    Ok(InspectedInvitation {
        workspace: invitation.workspace_id(),
        invitation_key: invitation.key(),
        workspace_name: proof
            .workspace_name()
            .map_err(security(ErrorCode::InvitationInvalid))?,
        epoch: proof.epoch(),
        personal_invitation: control.as_ref().is_some_and(|control| control.personal),
        automatic_approval: control.as_ref().is_some_and(|control| control.automatic()),
        expires_at: control.map_or(0, |control| control.expires_at),
    })
}

/// The link a new member uses: the bearer token, its checkpoint, and up to
/// three bootstrap peers with their IPv4 route hints.
pub(crate) fn invitation_envelope(
    session: &Session,
    invitation: &arachne_security::Invitation,
    checkpoint: Vec<u8>,
) -> Result<InvitationInfo, ApiError> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    let mut members = owner
        .member_endpoints()
        .map_err(security(ErrorCode::Internal))?;
    members.sort_unstable();
    let bootstrap_peers = std::iter::once(session.node.id())
        .chain(
            members
                .iter()
                .copied()
                .filter(|peer| *peer != session.node.id()),
        )
        .take(3)
        .collect::<Vec<_>>();
    let mut routes = Vec::new();
    for peer in members {
        if peer != session.node.id()
            && let Some(address) = session.runtime.block_on(session.node.address_hint(peer))
            && address.is_ipv4()
            && !address.ip().is_unspecified()
        {
            routes.push(RouteHint {
                peer,
                address: address.to_string(),
            });
            if routes.len() == 7 {
                break;
            }
        }
    }
    Ok(InvitationInfo {
        workspace: owner.id(),
        workspace_name: owner
            .workspace_name()
            .map_err(security(ErrorCode::Internal))?,
        invitation: invitation.export_secret_token().as_slice().to_vec(),
        invitation_key: invitation.key(),
        checkpoint,
        peer: session.node.id(),
        bootstrap_peers,
        address: session.node.address().to_string(),
        routes,
    })
}
