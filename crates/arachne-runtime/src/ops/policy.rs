//! Routing policy and interest: address hints, the verified routing policy
//! that membership derives, topic interest, and the unprotected fixtures
//! (`install_verified_policy`, `publish`, `poll`) that only a session
//! without a workspace may use.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::time::Duration;

use arachne_api::{ApiError, ErrorCode};
use arachne_node::{Node, Permissions, Topic};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;

use crate::client::DeliveryReport;
use crate::errors::{self, security};
use crate::{MAX_WORKSPACE_OVERLAY_PATHS, Session, interest, report};

/// A peer's topic permissions in a fixture policy.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(feature = "test-fixtures")]
pub(crate) struct EndpointPolicy {
    pub(crate) peer: [u8; 32],
    pub(crate) publish: Vec<String>,
    pub(crate) subscribe: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AddressHintArgs {
    pub peer: [u8; 32],
    pub address: String,
}

/// Explicit all-member topic default; endpoints come from verified membership.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspacePolicyArgs {
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MemberPolicyArgs {
    pub revision: u64,
    pub topics: Vec<String>,
}

/// Development fixture only; rejected when the session owns a workspace.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(feature = "test-fixtures")]
pub(crate) struct VerifiedPolicyArgs {
    pub workspace: [u8; 32],
    pub revision: u64,
    pub endpoints: Vec<EndpointPolicy>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InterestArgs {
    pub workspace: [u8; 32],
    pub revision: u64,
    pub topic: String,
    pub subscribed: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TopicArgs {
    pub workspace: [u8; 32],
    pub revision: u64,
    pub topic: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(feature = "test-fixtures")]
pub(crate) struct PublishArgs {
    pub workspace: [u8; 32],
    pub revision: u64,
    pub topic: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct PolicyInstalled {
    pub workspace: [u8; 32],
    pub revision: u64,
    pub members: usize,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct InterestQueued {
    pub state: &'static str,
    pub queued: usize,
}

/// An unprotected fixture message.
#[derive(Clone, Debug, Serialize)]
#[cfg(feature = "test-fixtures")]
pub(crate) struct FixtureMessage {
    pub workspace: [u8; 32],
    pub revision: u64,
    pub sender: [u8; 32],
    pub topic: String,
    pub payload: Vec<u8>,
}

/// These ops end at a 10 s deadline, or at the op deadline when it comes
/// first (policy install and its gossip join); the outcome may then be
/// partial.
fn with_deadline<T>(
    op_deadline: Option<std::time::Instant>,
    runtime: &tokio::runtime::Handle,
    work: impl Future<Output = Result<T, ApiError>>,
) -> Result<T, ApiError> {
    runtime.block_on(async {
        tokio::time::timeout(
            crate::deadline::cap(op_deadline, Duration::from_secs(10)),
            work,
        )
        .await
        .map_err(|_| ApiError::DeadlineExceeded)?
    })
}

fn topics(names: Vec<String>) -> Result<BTreeSet<Topic>, ApiError> {
    names
        .into_iter()
        .map(Topic::new)
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(errors::routing)
}

pub(crate) fn add_address_hint(
    session: &mut Session,
    args: AddressHintArgs,
) -> Result<(), ApiError> {
    with_deadline(session.op_deadline, &session.runtime, async {
        session
            .node
            .add_address_hint(
                args.peer,
                args.address
                    .parse()
                    .map_err(|_| ApiError::invalid_input("address", "invalid socket address"))?,
            )
            .await
            .map_err(errors::node)?;
        session.interests.repair();
        Ok(())
    })
}

/// Route every topic between all members at `revision` (the next epoch).
pub(crate) fn install_workspace_policy(
    session: &mut Session,
    args: WorkspacePolicyArgs,
) -> Result<PolicyInstalled, ApiError> {
    let revision = args.revision;
    with_deadline(session.op_deadline, &session.runtime, async {
        let owner = session
            .workspace
            .as_ref()
            .ok_or_else(errors::no_workspace)?;
        if owner.epoch().checked_add(1) != Some(revision) {
            return Err(ApiError::policy_mismatch(
                "workspace policy revision must match current epoch",
            ));
        }
        let policy = owner
            .member_endpoints()
            .map_err(security(ErrorCode::Internal))?
            .into_iter()
            .map(|endpoint| (endpoint, Permissions::AllTopics))
            .collect();
        install_gossip_policy(
            &session.node,
            &mut session.overlay_paths,
            owner.id(),
            revision,
            policy,
            owner
                .gossip_tag_key()
                .map_err(security(ErrorCode::Internal))?,
        )
        .await?;
        session.interests.replace_revision(owner.id(), revision);
        Ok(PolicyInstalled {
            workspace: owner.id(),
            revision,
            members: owner.member_count(),
        })
    })
}

/// Route only `topics` between all members.
pub(crate) fn install_member_policy(
    session: &mut Session,
    args: MemberPolicyArgs,
) -> Result<PolicyInstalled, ApiError> {
    let MemberPolicyArgs {
        revision,
        topics: names,
    } = args;
    with_deadline(session.op_deadline, &session.runtime, async {
        let workspace = session
            .workspace
            .as_ref()
            .ok_or_else(errors::no_workspace)?;
        let topics = topics(names)?;
        if topics.is_empty() {
            return Err(ApiError::invalid_input(
                "topics",
                "member policy requires an explicit topic set",
            ));
        }
        let mut policy = BTreeMap::new();
        for endpoint in workspace
            .member_endpoints()
            .map_err(security(ErrorCode::Internal))?
        {
            if policy
                .insert(
                    endpoint,
                    Permissions::Selected {
                        publish: topics.clone(),
                        subscribe: topics.clone(),
                    },
                )
                .is_some()
            {
                return Err(ApiError::internal("duplicate member endpoint"));
            }
        }
        install_gossip_policy(
            &session.node,
            &mut session.overlay_paths,
            workspace.id(),
            revision,
            policy,
            workspace
                .gossip_tag_key()
                .map_err(security(ErrorCode::Internal))?,
        )
        .await?;
        session.interests.replace_revision(workspace.id(), revision);
        Ok(PolicyInstalled {
            workspace: workspace.id(),
            revision,
            members: workspace.member_count(),
        })
    })
}

/// Fixture: install a caller-made policy. The guards reject it once the
/// session owns a workspace.
#[cfg(feature = "test-fixtures")]
pub(crate) fn install_verified_policy(
    session: &mut Session,
    args: VerifiedPolicyArgs,
) -> Result<(), ApiError> {
    with_deadline(session.op_deadline, &session.runtime, async {
        let mut policy = BTreeMap::new();
        for endpoint in args.endpoints {
            let access = Permissions::Selected {
                publish: topics(endpoint.publish)?,
                subscribe: topics(endpoint.subscribe)?,
            };
            if policy.insert(endpoint.peer, access).is_some() {
                return Err(ApiError::invalid_input("endpoints", "duplicate endpoint"));
            }
        }
        session
            .node
            .install_verified_policy(args.workspace, args.revision, policy)
            .await
            .map_err(errors::node)?;
        session
            .interests
            .replace_revision(args.workspace, args.revision);
        Ok(())
    })
}

pub(crate) fn set_interest(
    session: &mut Session,
    args: InterestArgs,
) -> Result<InterestQueued, ApiError> {
    session.interests.set(
        &session.node,
        &session.runtime,
        interest::Update {
            workspace: args.workspace,
            revision: args.revision,
            topic: args.topic,
            subscribed: args.subscribed,
        },
    )
}

/// The next interest outcome: an open event (typed in ADR step 4).
pub(crate) fn poll_interest(session: &mut Session) -> Result<Value, ApiError> {
    Ok(session.interests.poll(&session.node, &session.runtime))
}

fn interest_idle(session: &Session) -> Result<(), ApiError> {
    if !session.interests.is_idle() {
        // A blocking legacy operation cannot bypass queued newer choices.
        return Err(ApiError::wrong_state(
            "interest repair is active; use set_interest",
        ));
    }
    Ok(())
}

pub(crate) fn subscribe(
    session: &mut Session,
    args: TopicArgs,
) -> Result<DeliveryReport, ApiError> {
    interest_idle(session)?;
    with_deadline(session.op_deadline, &session.runtime, async {
        let topic = Topic::new(args.topic).map_err(errors::routing)?;
        Ok(report(
            session
                .node
                .subscribe(args.workspace, args.revision, topic)
                .await
                .map_err(errors::node)?,
        ))
    })
}

pub(crate) fn unsubscribe(
    session: &mut Session,
    args: TopicArgs,
) -> Result<DeliveryReport, ApiError> {
    interest_idle(session)?;
    with_deadline(session.op_deadline, &session.runtime, async {
        let topic = Topic::new(args.topic).map_err(errors::routing)?;
        Ok(report(
            session
                .node
                .unsubscribe(args.workspace, args.revision, topic)
                .await
                .map_err(errors::node)?,
        ))
    })
}

/// Fixture: an unprotected publication, rejected once the session owns a
/// workspace.
#[cfg(feature = "test-fixtures")]
pub(crate) fn publish(
    session: &mut Session,
    args: PublishArgs,
) -> Result<DeliveryReport, ApiError> {
    with_deadline(session.op_deadline, &session.runtime, async {
        let topic = Topic::new(args.topic).map_err(errors::routing)?;
        Ok(report(
            session
                .node
                .publish(args.workspace, args.revision, topic, args.payload)
                .await
                .map_err(errors::node)?,
        ))
    })
}

/// Fixture: the next unprotected message.
#[cfg(feature = "test-fixtures")]
pub(crate) fn poll(session: &mut Session) -> Result<Option<FixtureMessage>, ApiError> {
    match session.receiver.try_recv() {
        Ok(message) => Ok(Some(FixtureMessage {
            workspace: message.workspace,
            revision: message.revision,
            sender: message.sender,
            topic: message.topic.as_str().to_owned(),
            payload: message.payload,
        })),
        Err(mpsc::error::TryRecvError::Empty) => Ok(None),
        Err(mpsc::error::TryRecvError::Disconnected) => {
            Err(ApiError::internal("event receiver closed"))
        }
    }
}

/// Install a verified policy and join its gossip overlay, within the
/// device-wide overlay path budget.
pub(crate) async fn install_gossip_policy(
    node: &Node,
    reserved: &mut crate::context::OverlayPaths,
    workspace: [u8; 32],
    revision: u64,
    policy: BTreeMap<[u8; 32], Permissions>,
    tag_key: [u8; 32],
) -> Result<(), ApiError> {
    let desired = policy
        .keys()
        .filter(|peer| **peer != node.id())
        .count()
        .min(MAX_WORKSPACE_OVERLAY_PATHS);
    let additional = desired.saturating_sub(reserved.held());
    reserved.reserve(additional)?;
    let result = async {
        node.install_verified_policy(workspace, revision, policy)
            .await
            .map_err(errors::node)?;
        // A stable members-only key: the overlay tag does not reveal the
        // workspace to a party that knows only its ID.
        node.enable_gossip(workspace, revision, &tag_key)
            .await
            .map_err(errors::node)
    }
    .await;
    if let Err(error) = result {
        reserved.release(additional);
        return Err(error);
    }
    if reserved.held() > desired {
        reserved.release(reserved.held() - desired);
    }
    Ok(())
}
