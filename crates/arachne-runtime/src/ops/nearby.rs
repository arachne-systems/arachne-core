//! Nearby: device-level discovery of endpoints and advertised workspaces on
//! the local network, and handing an invitation to a nearby device. Nothing
//! here grants membership.

use std::collections::BTreeMap;
use std::time::Duration;

use arachne_api::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Session;
use crate::errors::{self, security};

pub(crate) const NEARBY_INVITATION: &[u8; 5] = b"DFNI\x01";
pub(crate) const NEARBY_WORKSPACE: &[u8; 5] = b"DFNW\x01";
const NEARBY_WORKSPACE_LIST: &[u8; 5] = b"DFNW\x02";
pub(crate) const NEARBY_IDENTITY: &[u8; 5] = b"DFND\x01";
const MAX_NEARBY_WORKSPACES: usize = 16;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentityArgs {
    pub name: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdvertiseArgs {
    pub mode: Option<String>,
    #[serde(default)]
    pub invitation: Vec<u8>,
    #[serde(default)]
    pub workspace_name: Option<String>,
    #[serde(default)]
    pub workspace: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SendInvitationArgs {
    pub peer: [u8; 32],
    pub invitation: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NearbyName {
    pub id: [u8; 32],
    pub name: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NearbyEndpoints {
    pub endpoints: Vec<[u8; 32]>,
    pub names: Vec<NearbyName>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NearbyWorkspace {
    pub peer: [u8; 32],
    pub mode: &'static str,
    pub workspace_name: Option<String>,
    pub invitation: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NearbyWorkspaces {
    pub workspaces: Vec<NearbyWorkspace>,
    pub endpoints_checked: usize,
    pub limited: bool,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct NearbyState {
    pub state: &'static str,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct InvitationSent {
    pub state: &'static str,
    pub peer: [u8; 32],
}

/// Nearby endpoints and the names they announce (750 ms per ask).
pub(crate) fn endpoints(session: &mut Session) -> Result<NearbyEndpoints, ApiError> {
    let peers = session.runtime.block_on(session.node.nearby_peers());
    let names = session.runtime.block_on(async {
        let mut queries = tokio::task::JoinSet::new();
        for peer in &peers {
            let peer = *peer;
            let request = session.node.request_control(peer, NEARBY_IDENTITY);
            queries.spawn(async move {
                tokio::time::timeout(Duration::from_millis(750), request)
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .and_then(|reply| String::from_utf8(reply).ok())
                    .map(|name| NearbyName { id: peer, name })
            });
        }
        let mut names = Vec::new();
        while let Some(Ok(Some(name))) = queries.join_next().await {
            names.push(name);
        }
        names
    });
    Ok(NearbyEndpoints {
        endpoints: peers,
        names,
    })
}

/// Workspaces that nearby devices advertise (3 s per ask).
pub(crate) fn workspaces(session: &mut Session) -> Result<NearbyWorkspaces, ApiError> {
    let peers = session
        .runtime
        .block_on(session.node.nearby_workspace_peers());
    let peer_count = peers.len();
    let (found, checked) = session.runtime.block_on(async {
        let mut queries = tokio::task::JoinSet::new();
        for peer in peers {
            let request = session.node.request_control(peer, NEARBY_WORKSPACE);
            queries.spawn(async move {
                tokio::time::timeout(Duration::from_secs(3), request)
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .map(|reply| (peer, reply))
            });
        }
        let mut advertisements = BTreeMap::<Vec<u8>, NearbyWorkspace>::new();
        let mut checked = 0usize;
        while let Some(Ok(Some((peer, reply)))) = queries.join_next().await {
            checked += 1;
            for payload in nearby_workspace_payloads(&reply) {
                let Some((&mode, payload)) = payload.split_first() else {
                    continue;
                };
                let (workspace_name, invitation) = match mode {
                    1 | 2 => (None, payload),
                    3 | 4 if payload.len() >= 2 => {
                        let length = u16::from_be_bytes([payload[0], payload[1]]) as usize;
                        if !(1..=320).contains(&length) || payload.len() < length + 2 {
                            continue;
                        }
                        let Ok(name) = std::str::from_utf8(&payload[2..2 + length]) else {
                            continue;
                        };
                        if arachne_security::validate_workspace_name(name).is_err() {
                            continue;
                        }
                        (Some(name), &payload[2 + length..])
                    }
                    _ => continue,
                };
                if invitation.is_empty() || invitation.len() > 2048 {
                    continue;
                }
                advertisements
                    .entry(invitation.to_vec())
                    .or_insert_with(|| NearbyWorkspace {
                        peer,
                        mode: if mode == 1 || mode == 3 {
                            "request_access"
                        } else {
                            "open_joining"
                        },
                        workspace_name: workspace_name.map(str::to_owned),
                        invitation: invitation.to_vec(),
                    });
            }
        }
        (advertisements.into_values().collect::<Vec<_>>(), checked)
    });
    Ok(NearbyWorkspaces {
        workspaces: found,
        endpoints_checked: checked,
        limited: peer_count == 16 || checked < peer_count,
    })
}

/// Advertise (or withdraw) one workspace invitation to nearby devices.
pub(crate) fn advertise(session: &mut Session, args: AdvertiseArgs) -> Result<NearbyState, ApiError> {
    let AdvertiseArgs {
        mode,
        invitation,
        workspace_name,
        workspace,
    } = args;
    if let Some(name) = &workspace_name {
        arachne_security::validate_workspace_name(name)
            .map_err(security(ErrorCode::InvalidInput))?;
    }
    let encoded = match mode.as_deref() {
        None if invitation.is_empty() && workspace_name.is_none() => None,
        Some("request_access" | "open_joining")
            if !invitation.is_empty() && invitation.len() <= 2048 =>
        {
            let mut value = vec![
                if mode.as_deref() == Some("request_access") {
                    1
                } else {
                    2
                } + if workspace_name.is_some() { 2 } else { 0 },
            ];
            if let Some(name) = &workspace_name {
                value.extend((name.len() as u16).to_be_bytes());
                value.extend(name.as_bytes());
            }
            value.extend(&invitation);
            Some(value)
        }
        _ => {
            return Err(ApiError::invalid_input(
                "mode",
                "invalid nearby workspace advertisement",
            ));
        }
    };
    if let Some(encoded) = encoded {
        let key = nearby_workspace_key(workspace, &invitation);
        if !session.nearby.workspaces.contains_key(&key)
            && session.nearby.workspaces.len() >= MAX_NEARBY_WORKSPACES
        {
            return Err(ApiError::limit_reached(
                "nearby workspace advertisements",
                MAX_NEARBY_WORKSPACES as u64,
                "nearby workspace advertisement limit reached",
            ));
        }
        session.nearby.workspaces.insert(key, encoded);
    } else if let Some(workspace) = workspace {
        session.nearby.workspaces.remove(&workspace);
    } else {
        session.nearby.workspaces.clear();
    }
    Ok(NearbyState {
        state: if session.nearby.workspaces.is_empty() {
            "nearby_workspace_private"
        } else {
            "nearby_workspace_advertised"
        },
    })
}

/// The name this device answers to nearby identity asks.
pub(crate) fn set_identity(session: &mut Session, args: IdentityArgs) -> Result<NearbyState, ApiError> {
    arachne_security::validate_workspace_name(&args.name)
        .map_err(security(ErrorCode::InvalidInput))?;
    session.nearby.identity = Some(args.name.trim().to_owned());
    Ok(NearbyState {
        state: "nearby_identity_set",
    })
}

/// Hand an invitation to one nearby device.
pub(crate) fn send_invitation(
    session: &mut Session,
    args: SendInvitationArgs,
) -> Result<InvitationSent, ApiError> {
    if args.invitation.is_empty() || args.invitation.len() > 2048 {
        return Err(ApiError::invalid_input(
            "invitation",
            "invalid nearby invitation length",
        ));
    }
    let mut packet = NEARBY_INVITATION.to_vec();
    packet.extend((args.invitation.len() as u16).to_be_bytes());
    packet.extend(&args.invitation);
    let reply = session
        .runtime
        .block_on(session.node.request_control(args.peer, &packet))
        .map_err(errors::node)?;
    if reply != [1] {
        return Err(ApiError::not_authorized("nearby device rejected invitation"));
    }
    Ok(InvitationSent {
        state: "nearby_invitation_sent",
        peer: args.peer,
    })
}

fn nearby_workspace_key(workspace: Option<[u8; 32]>, invitation: &[u8]) -> [u8; 32] {
    workspace
        .or_else(|| {
            arachne_security::Invitation::from_bytes(invitation)
                .ok()
                .map(|value| value.workspace_id())
        })
        .unwrap_or_else(|| Sha256::digest(invitation).into())
}

/// This device's advertisement answer: one payload, or a list.
pub(crate) fn nearby_workspace_reply(advertisements: &BTreeMap<[u8; 32], Vec<u8>>) -> Vec<u8> {
    match advertisements.len() {
        0 => Vec::new(),
        1 => advertisements.values().next().cloned().unwrap_or_default(),
        count => {
            let mut reply = NEARBY_WORKSPACE_LIST.to_vec();
            reply.push(count as u8);
            for payload in advertisements.values() {
                reply.extend((payload.len() as u16).to_be_bytes());
                reply.extend(payload);
            }
            reply
        }
    }
}

fn nearby_workspace_payloads(reply: &[u8]) -> Vec<&[u8]> {
    if reply.is_empty() {
        return Vec::new();
    }
    if !reply.starts_with(NEARBY_WORKSPACE_LIST) {
        return vec![reply];
    }
    let Some(&count) = reply.get(NEARBY_WORKSPACE_LIST.len()) else {
        return Vec::new();
    };
    if count == 0 || count as usize > MAX_NEARBY_WORKSPACES {
        return Vec::new();
    }
    let mut offset = NEARBY_WORKSPACE_LIST.len() + 1;
    let mut payloads = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let Some(length) = reply.get(offset..offset + 2) else {
            return Vec::new();
        };
        let length = u16::from_be_bytes([length[0], length[1]]) as usize;
        offset += 2;
        if length == 0 || length > 4096 || offset + length > reply.len() {
            return Vec::new();
        }
        payloads.push(&reply[offset..offset + length]);
        offset += length;
    }
    if offset != reply.len() {
        return Vec::new();
    }
    payloads
}
