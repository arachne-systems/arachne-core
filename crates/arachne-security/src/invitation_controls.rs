//! Invitation controls in the existing authority extension. A disabled grant
//! cannot authorize a later Add on this branch. Wall-clock expiry is checked
//! when handling a new request, independently of replaying accepted history.
use super::{AUTHORITY, ManagementAction, PreparedManagement, Workspace, bootstrap};
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;

pub const INVITATION_DISABLED: &str =
    "This invitation has been disabled. Ask an administrator for a new link.";
pub const INVITATION_EXPIRED: &str =
    "This invitation has expired. Ask an administrator for a new link.";
pub const INVITATION_APPROVAL_REQUIRED: &str =
    "This personal invitation needs administrator approval for your join request.";
pub const INVITATION_AUTOMATIC_APPROVAL_REQUIRED: &str =
    "This personal invitation is waiting for an administrator to bind its first join request.";
const AUTOMATIC_APPROVAL: [u8; 32] = [0xff; 32];
const REQUEST_ACCESS: [u8; 32] = [0xfe; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationControl {
    pub key: [u8; 32],
    pub expires_at: u64,
    pub enabled: bool,
    pub personal: bool,
    pub approved_package: [u8; 32],
}

impl InvitationControl {
    pub fn automatic(&self) -> bool {
        self.personal && self.approved_package == AUTOMATIC_APPROVAL
    }

    pub fn approved(&self) -> bool {
        self.personal
            && self.approved_package != [0; 32]
            && !self.automatic()
            && !self.request_access()
    }

    pub fn request_access(&self) -> bool {
        self.personal && self.approved_package == REQUEST_ACCESS
    }

    pub fn is_request_decision(&self, controls: &[Self]) -> bool {
        controls.iter().any(|parent| {
            parent.request_access() && self.key == decision_key(parent.key, self.approved_package)
        })
    }
}

// Domain separation keeps decisions bound to both the invitation and exact request.
fn decision_key(invitation: [u8; 32], package: [u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"data-fabric/invitation-request/v1\0");
    hash.update(invitation);
    hash.update(package);
    hash.finalize().into()
}

fn decide(
    controls: &mut Vec<InvitationControl>,
    parent: &InvitationControl,
    package: [u8; 32],
    approved: bool,
) -> Result<(), &'static str> {
    if !parent.enabled || [[0; 32], AUTOMATIC_APPROVAL, REQUEST_ACCESS].contains(&package) {
        return Err("invalid or disabled invitation request");
    }
    let key = decision_key(parent.key, package);
    if controls.iter().any(|c| c.key == key) {
        return Err("join request already decided");
    }
    controls.push(InvitationControl {
        key,
        expires_at: parent.expires_at,
        enabled: approved,
        personal: true,
        approved_package: package,
    });
    Ok(())
}

pub(super) fn decode(bytes: &[u8]) -> Result<(bool, Vec<InvitationControl>), &'static str> {
    if bytes.len() < 3 || bytes.len() > 16 * 1024 || bytes[0] > 1 {
        return Err("invalid invitation controls");
    }
    let count = u16::from_be_bytes(bytes[1..3].try_into().unwrap()) as usize;
    if bytes.len() != 3 + count * 74 {
        return Err("invalid invitation control length");
    }
    let mut controls = Vec::with_capacity(count);
    for row in bytes[3..].as_chunks::<74>().0 {
        let key: [u8; 32] = row[..32].try_into().unwrap();
        if row[40] > 1
            || row[41] > 1
            || key == [0; 32]
            || controls.iter().any(|c: &InvitationControl| c.key == key)
        {
            return Err("invalid invitation control");
        }
        controls.push(InvitationControl {
            key,
            expires_at: u64::from_be_bytes(row[32..40].try_into().unwrap()),
            enabled: row[40] == 1,
            personal: row[41] == 1,
            approved_package: row[42..74].try_into().unwrap(),
        });
    }
    Ok((bytes[0] == 1, controls))
}

pub(super) fn policy_bytes(extensions: &Extensions<GroupContext>) -> Result<Vec<u8>, &'static str> {
    let keys = bootstrap::authority(extensions)?;
    let bytes = &extensions.unknown(AUTHORITY).ok_or("missing authority")?.0;
    Ok(if bytes[0] == 1 {
        vec![1, 0, 0]
    } else {
        bytes[2 + keys.len() * 32..].to_vec()
    })
}

pub(super) fn replace_admins(
    extensions: &Extensions<GroupContext>,
    admins: &[Vec<u8>],
) -> Result<Vec<u8>, &'static str> {
    let old = &extensions.unknown(AUTHORITY).ok_or("missing authority")?.0;
    let mut bytes = vec![old[0], admins.len() as u8];
    bytes.extend(admins.iter().flatten());
    if old[0] == 2 {
        bytes.extend(policy_bytes(extensions)?);
    }
    Ok(bytes)
}

pub(super) fn check(
    extensions: &Extensions<GroupContext>,
    key: [u8; 32],
    now: Option<u64>,
    package: &KeyPackage,
) -> Result<(), &'static str> {
    let (legacy, controls) = decode(&policy_bytes(extensions)?)?;
    match controls.iter().find(|c| c.key == key) {
        Some(c) if !c.enabled => Err(INVITATION_DISABLED),
        Some(c) if c.expires_at != 0 && now.is_some_and(|n| n >= c.expires_at) => {
            Err(INVITATION_EXPIRED)
        }
        Some(c) if c.automatic() => Err(INVITATION_AUTOMATIC_APPROVAL_REQUIRED),
        Some(c) if c.request_access() => {
            let package = package_digest(package)?;
            match controls
                .iter()
                .find(|decision| decision.key == decision_key(c.key, package))
            {
                Some(decision) if !decision.enabled => Err(INVITATION_DISABLED),
                Some(decision) if decision.personal && decision.approved_package == package => {
                    Ok(())
                }
                _ => Err(INVITATION_APPROVAL_REQUIRED),
            }
        }
        Some(c) if c.personal && !c.approved() => Err(INVITATION_APPROVAL_REQUIRED),
        Some(c) if c.personal && c.approved_package != package_digest(package)? => {
            Err(INVITATION_APPROVAL_REQUIRED)
        }
        Some(_) => Ok(()),
        None if legacy => Ok(()),
        None => Err(INVITATION_DISABLED),
    }
}

pub(super) fn package_digest(package: &KeyPackage) -> Result<[u8; 32], &'static str> {
    use openmls::prelude::tls_codec::Serialize;
    use sha2::{Digest, Sha256};
    Ok(Sha256::digest(
        package
            .tls_serialize_detached()
            .map_err(|_| "join request encoding failed")?,
    )
    .into())
}

pub(super) fn now() -> Result<u64, &'static str> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| "device clock is invalid")
}

fn changed(
    extensions: &Extensions<GroupContext>,
    action: ManagementAction,
) -> Result<Extensions<GroupContext>, &'static str> {
    let (mut legacy, mut controls) = decode(&policy_bytes(extensions)?)?;
    match action {
        ManagementAction::CreateInvitation(key, expires_at, personal) => {
            if key == [0; 32] || controls.iter().any(|c| c.key == key) {
                return Err("invitation already registered or invalid");
            }
            controls.push(InvitationControl {
                key,
                expires_at,
                enabled: true,
                personal,
                approved_package: [0; 32],
            });
        }
        ManagementAction::CreateAutomaticInvitation(key, expires_at)
        | ManagementAction::CreateRequestInvitation(key, expires_at) => {
            if key == [0; 32] || controls.iter().any(|c| c.key == key) {
                return Err("invitation already registered or invalid");
            }
            controls.push(InvitationControl {
                key,
                expires_at,
                enabled: true,
                personal: true,
                approved_package: if matches!(action, ManagementAction::CreateRequestInvitation(..))
                {
                    REQUEST_ACCESS
                } else {
                    AUTOMATIC_APPROVAL
                },
            });
        }
        ManagementAction::ApproveInvitation(key, package) => {
            let parent = controls
                .iter()
                .find(|c| c.key == key)
                .cloned()
                .ok_or("unknown invitation")?;
            if parent.request_access() {
                decide(&mut controls, &parent, package, true)?;
            } else {
                let control = controls
                    .iter_mut()
                    .find(|c| c.key == key)
                    .ok_or("unknown personal invitation")?;
                if !control.personal
                    || !control.enabled
                    || (control.approved_package != [0; 32] && !control.automatic())
                    || package == [0; 32]
                    || package == AUTOMATIC_APPROVAL
                    || package == REQUEST_ACCESS
                {
                    return Err("personal invitation is already approved or disabled");
                }
                control.approved_package = package;
            }
        }
        ManagementAction::DeclineInvitationRequest(key, package) => {
            let parent = controls
                .iter()
                .find(|c| c.key == key)
                .cloned()
                .ok_or("unknown invitation")?;
            if !parent.request_access() {
                return Err("expected a request-access invitation");
            }
            decide(&mut controls, &parent, package, false)?;
        }
        ManagementAction::DisableInvitation(key) => {
            if key == [0; 32] {
                if !legacy {
                    return Err("older invitations already disabled");
                }
                legacy = false;
            } else {
                let control = controls
                    .iter_mut()
                    .find(|c| c.key == key)
                    .ok_or("unknown invitation")?;
                if !control.enabled {
                    return Err("invitation already disabled");
                }
                control.enabled = false;
            }
        }
        _ => return Err("expected invitation control action"),
    }
    let admins = bootstrap::authority(extensions)?;
    let mut bytes = vec![2, admins.len() as u8];
    bytes.extend(admins.into_iter().flatten());
    let mut policy = vec![u8::from(legacy)];
    policy.extend((controls.len() as u16).to_be_bytes());
    for c in controls {
        policy.extend(c.key);
        policy.extend(c.expires_at.to_be_bytes());
        policy.push(u8::from(c.enabled));
        policy.push(u8::from(c.personal));
        policy.extend(c.approved_package);
    }
    decode(&policy)?;
    bytes.extend(policy);
    Extensions::from_vec(
        extensions
            .iter()
            .map(|e| {
                if e.extension_type() == ExtensionType::Unknown(AUTHORITY) {
                    Extension::Unknown(AUTHORITY, UnknownExtension(bytes.clone()))
                } else {
                    e.clone()
                }
            })
            .collect(),
    )
    .map_err(|_| "invalid invitation policy")
}

impl Workspace {
    pub fn invitation_controls(&self) -> Result<(bool, Vec<InvitationControl>), &'static str> {
        decode(&policy_bytes(self.group.extensions())?)
    }
}

pub(super) fn prepare(
    owner: &Workspace,
    action: ManagementAction,
) -> Result<PreparedManagement, &'static str> {
    let extensions = changed(owner.group.extensions(), action)?;
    let mut candidate = owner.provisional_copy()?;
    let commit = candidate
        .group
        .commit_builder()
        .propose_group_context_extensions(extensions)
        .map_err(|_| "invitation control proposal failed")?
        .load_psks(candidate.provider.storage())
        .map_err(|_| "invitation control state failed")?
        .build(
            candidate.provider.rand(),
            candidate.provider.crypto(),
            &candidate._signer,
            |_| true,
        )
        .map_err(|_| "invitation control preparation failed")?
        .stage_commit(&candidate.provider)
        .map_err(|_| "invitation control staging failed")?
        .into_contents()
        .0
        .to_bytes()
        .map_err(|_| "invitation control encoding failed")?;
    let mut proof = super::MembershipVerifier::from_workspace(owner)?;
    proof.apply_transition(&super::MembershipAuthorization::Management(action), &commit)?;
    candidate
        .group
        .merge_pending_commit(&candidate.provider)
        .map_err(|_| "invitation control merge failed")?;
    candidate.join_history =
        Some(owner.append_history(super::MembershipAuthorization::Management(action), &commit)?);
    candidate.prune_invitation_checkpoints()?;
    if !proof.matches_workspace(&candidate)? {
        return Err("invitation control branch mismatch");
    }
    Ok(PreparedManagement {
        workspace: candidate,
        action,
        commit,
    })
}

pub(super) fn verify(
    group: &PublicGroup,
    sender: &Sender,
    actor: &Member,
    staged: &StagedCommit,
    action: ManagementAction,
) -> Result<(), &'static str> {
    if staged.group_context().extensions() != &changed(group.group_context().extensions(), action)?
    {
        return Err("invitation action changed unrelated policy");
    }
    if let Some(leaf) = staged.update_path_leaf_node()
        && (leaf.credential() != &actor.credential
            || leaf.signature_key().as_slice() != actor.signature_key)
    {
        return Err("invitation action replaced actor identity");
    }
    if staged.queued_proposals().count() != 1
        || !staged.queued_proposals().all(|p| {
            p.sender() == sender
                && p.proposal_or_ref_type() == ProposalOrRefType::Proposal
                && matches!(p.proposal(), Proposal::GroupContextExtensions(_))
        })
    {
        return Err("invitation action requires exactly its inline policy proposal");
    }
    Ok(())
}
