//! Protected receive: stage one incoming object into the durable inbox, read
//! the next pending object, and stage its acknowledgement or rejection.
//! Each staged change is adopted with `adopt_reception` (`ops::candidate`).

use arachne_api::{ApiError, ErrorCode};
use arachne_routing::PublicationContext;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::client::PublicationCurrent;
use crate::errors::{self, delivery, security};
use crate::ops::publication::{StagedObject, hold_object, publisher_or_new, stage_object};
use crate::session::seal_state;
use crate::{Session, WorkspaceTransition};

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PollPendingArgs {
    #[serde(default)]
    pub deferred: Vec<arachne_delivery::inbox::DeferredDeliveryStream>,
}

/// Identifies one pending object for its acknowledgement or rejection.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolveArgs {
    pub member: [u8; 32],
    pub topic: String,
    pub counter: u64,
    pub id: [u8; 16],
}

/// An authenticated object that waits in the durable inbox.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct PendingObject {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<PublicationCurrent>,
}

/// Stage one incoming protected publication without exposing its plaintext.
/// `None`: nothing arrived, or it was a duplicate.
pub(crate) fn poll_protected(session: &mut Session) -> Result<Option<StagedObject>, ApiError> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    session
        .storage_key
        .as_ref()
        .ok_or_else(errors::no_root_key)?;
    // Bounded drain of local echoes. ATAK already owns its own outgoing
    // event; MLS cannot decrypt its own sent application ciphertext.
    let mut incoming = None;
    for _ in 0..256 {
        match session.receiver.try_recv() {
            Ok(message) if message.sender == session.node.id() => continue,
            Ok(message) => {
                incoming = Some(message);
                break;
            }
            Err(mpsc::error::TryRecvError::Empty) => return Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                return Err(ApiError::internal("event receiver closed"));
            }
        }
    }
    let Some(message) = incoming else {
        return Ok(None);
    };
    let candidate = owner
        .provisional_copy()
        .map_err(security(ErrorCode::Internal))?;
    let publisher = session.delivery.publisher.clone();
    // Object delivery is the only receive path.
    let inbox = session
        .delivery
        .inbox
        .clone()
        .unwrap_or_else(|| arachne_delivery::inbox::ObjectInbox::new(owner.id(), owner.epoch()));
    if message.workspace != owner.id() {
        return Err(ApiError::not_authorized("wrong workspace"));
    }
    let (current, packet) = if message.payload.starts_with(b"DFVL") {
        let live = arachne_delivery::current::LiveCurrentPacket::from_wire(&message.payload)
            .map_err(delivery(ErrorCode::TransportFailed))?;
        (Some(live.metadata), live.packet)
    } else {
        (None, message.payload)
    };
    let (context, ciphertext) =
        PublicationContext::unpack(message.workspace, message.revision, message.topic, &packet)
            .map_err(|reason| ApiError::transport_failed(None, reason))?;
    if current.is_some() && !message.recipients.is_empty() {
        return Err(ApiError::not_authorized(
            "current values require group object delivery",
        ));
    }
    if !message.recipients.is_empty() {
        let member = owner
            .member()
            .ok_or_else(|| ApiError::wrong_state("direct receiver lacks member identity"))?
            .id();
        if message.recipients.binary_search(&member).is_err() {
            return Err(ApiError::not_authorized(
                "direct publication excludes local member",
            ));
        }
    }
    let aad = if let Some(current) = current {
        current.authenticated_context(&context)
    } else if message.recipients.is_empty() {
        context.authenticated_bytes()
    } else {
        context
            .direct_authenticated_bytes(&message.recipients)
            .map_err(|reason| ApiError::transport_failed(None, reason))?
    };
    let authenticated = owner
        .unprotect_object(context.topic.namespace().as_bytes(), &aad, ciphertext)
        .map_err(security(ErrorCode::NotAuthorized))?;
    if authenticated.message.endpoint != message.sender {
        return Err(ApiError::not_authorized("direct author mismatch"));
    }
    let stage = match current {
        Some(metadata) => inbox.stage_live_current(owner, &context, metadata, ciphertext),
        None => inbox.stage_with_recipients(owner, &context, &message.recipients, ciphertext),
    }
    .map_err(delivery(ErrorCode::InvalidInput))?;
    let inbox = match stage {
        arachne_delivery::inbox::InboxStage::Prepared(next) => *next,
        arachne_delivery::inbox::InboxStage::Duplicate => return Ok(None),
        arachne_delivery::inbox::InboxStage::OutsideWindow => {
            return Err(ApiError::epoch_mismatch("object outside receive window"));
        }
    };
    let publisher = match publisher {
        Some(publisher) => publisher,
        None => arachne_delivery::PublisherLog::new(owner).map_err(delivery(ErrorCode::Internal))?,
    };
    stage_object(
        session,
        candidate,
        publisher,
        inbox,
        WorkspaceTransition::Inbox,
        "awaiting_reception_save",
    )
    .map(Some)
}

/// The next authenticated object the application has not yet acknowledged
/// or rejected, skipping the `deferred` streams.
pub(crate) fn poll_pending(
    session: &mut Session,
    args: PollPendingArgs,
) -> Result<Option<PendingObject>, ApiError> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    session
        .storage_key
        .as_ref()
        .ok_or_else(errors::no_root_key)?;
    let Some(inbox) = session.delivery.inbox.as_ref() else {
        return Ok(None);
    };
    let Some(pending) = inbox
        .pending_excluding(owner, &args.deferred)
        .map_err(delivery(ErrorCode::InvalidInput))?
    else {
        return Ok(None);
    };
    Ok(Some(PendingObject {
        workspace: pending.context.workspace,
        revision: pending.context.revision,
        topic: pending.context.topic.as_str().to_owned(),
        id: pending.context.id,
        sequence: pending.context.sequence.map(|n| n.get()),
        member: pending.message.member,
        endpoint: pending.message.endpoint,
        payload: pending.message.payload,
        counter: pending.counter,
        recipients: pending.recipients,
        current: pending.current.map(|current| PublicationCurrent {
            selector: current.selector,
            replacement_key: current.replacement_key,
            expires_at: current.expires_at,
            tombstone: current.tombstone,
        }),
    }))
}

/// Stage the application's durable acceptance of a pending object.
pub(crate) fn acknowledge(session: &mut Session, args: ResolveArgs) -> Result<StagedObject, ApiError> {
    resolve(session, args, false)
}

/// Stage a permanent rejection of a pending object. Its identity stays
/// recorded, so it is never delivered again.
pub(crate) fn reject(session: &mut Session, args: ResolveArgs) -> Result<StagedObject, ApiError> {
    resolve(session, args, true)
}

fn resolve(session: &mut Session, args: ResolveArgs, rejected: bool) -> Result<StagedObject, ApiError> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    session
        .storage_key
        .as_ref()
        .ok_or_else(errors::no_root_key)?;
    let inbox = session
        .delivery
        .inbox
        .as_ref()
        .ok_or_else(|| ApiError::wrong_state("no object delivery state"))?;
    let topic = arachne_node::Topic::new(args.topic).map_err(errors::routing)?;
    let inbox = if rejected {
        inbox.reject(args.member, &topic, args.counter, args.id)
    } else {
        inbox.acknowledge(args.member, &topic, args.counter, args.id)
    }
    .map_err(delivery(ErrorCode::InvalidInput))?;
    let publisher = publisher_or_new(session, owner)?;
    let key = session
        .storage_key
        .as_ref()
        .ok_or_else(errors::no_root_key)?;
    // The inbox change is sealed with the committed workspace state.
    let snapshot = seal_state(
        session.records.is_some(),
        owner,
        key,
        Some(&publisher),
        Some(&inbox),
    )?;
    let candidate = owner
        .provisional_copy()
        .map_err(security(ErrorCode::Internal))?;
    Ok(hold_object(
        session,
        candidate,
        publisher,
        inbox,
        snapshot,
        if rejected {
            WorkspaceTransition::InboxRejected
        } else {
            WorkspaceTransition::Inbox
        },
        "awaiting_reception_save",
        None,
    ))
}
