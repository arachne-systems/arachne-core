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
        .records
        .as_ref()
        .ok_or_else(crate::persistence::storage_required)?;
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
        .records
        .as_ref()
        .ok_or_else(crate::persistence::storage_required)?;
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
        .records
        .as_ref()
        .ok_or_else(crate::persistence::storage_required)?;
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
    // The inbox change is sealed with the committed workspace state.
    let snapshot = seal_state(session.records.is_some())?;
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

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn pending_object_query_bounds_and_gap_epoch_guard() {
        use arachne_delivery::{
            PublisherLog,
            inbox::{InboxStage, ObjectInbox},
        };
        use arachne_routing::PublicationContext;
        use arachne_security::{PendingJoin, Workspace};

        let root = [103; 32];
        let provider = arachne_store::MemoryProvider::default();
        let handle = create(Some(&root)).unwrap();
        attach_storage(handle, StorageConfig::memory(&provider)).unwrap();
        let call = |request: Value| -> Result<Value, String> {
            serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap())?)
                .map_err(|error| error.to_string())
        };
        let description: Value = serde_json::from_str(&describe(handle).unwrap()).unwrap();
        let endpoint = serde_json::from_value(description["endpoint_key"].clone()).unwrap();
        let admin_key = arachne_security::EndpointKey::generate().unwrap();
        let mut admin = Workspace::create(&admin_key, "Publisher").unwrap();
        let secret = iroh::SecretKey::from_bytes(&root);
        let (registered, invitation, checkpoint) = admin.prepare_invitation(0, false, false).unwrap();
        admin = registered.workspace;
        let join =
            PendingJoin::from_invitation(
                &invitation,
                &checkpoint,
                &arachne_node::IrohEndpointSigner(&secret),
                "Reader",
            )
            .unwrap();
        let prepared = admin
            .prepare_admission(endpoint, join.admission_request().unwrap())
            .unwrap();
        let mut proof = join.join_proof().unwrap();
        proof
            .apply_add(&prepared.authorization, &prepared.commit)
            .unwrap();
        let reader = join.prepare_workspace(&proof, &prepared.welcome).unwrap();
        let mut sender = prepared.workspace;
        let mut inbox = ObjectInbox::new(reader.id(), reader.epoch());
        for direct in [true, false] {
            let context = PublicationContext {
                workspace: reader.id(),
                revision: 7,
                topic: Topic::new("chat/messages").unwrap(),
                id: [if direct { 1 } else { 2 }; 16],
                sequence: std::num::NonZeroU64::new(2),
            };
            let recipients = if direct {
                vec![reader.member().unwrap().id()]
            } else {
                vec![]
            };
            let aad = if direct {
                context.direct_authenticated_bytes(&recipients).unwrap()
            } else {
                context.authenticated_bytes()
            };
            let object = sender
                .protect_object(context.topic.namespace().as_bytes(), &aad, b"pending")
                .unwrap();
            let InboxStage::Prepared(next) = inbox
                .stage_with_recipients(&reader, &context, &recipients, &object)
                .unwrap()
            else {
                panic!("object was not staged")
            };
            inbox = *next;
        }
        let publisher =
            PublisherLog::new(&reader).unwrap();
        harness::seed_workspace(&provider, &reader, Some(&publisher), Some(&inbox)).unwrap();
        call(json!({"op":"restore_workspace","workspace":reader.id()})).unwrap();
        let pending = call(json!({"op":"poll_pending_object"})).unwrap();
        assert_eq!(pending["id"], json!(vec![2; 16]));
        assert_eq!(
            call(json!({"op":"poll_pending_object","deferred":[]})).unwrap(),
            pending
        );
        let scope = json!({"member":pending["member"], "revision":pending["revision"],
            "topic":pending["topic"], "recipients":pending["recipients"]});
        let poll = |deferred: Value| call(json!({"op":"poll_pending_object","deferred":deferred}));
        // The group is deferred and the direct object still waits behind sequence 1.
        assert_eq!(poll(json!([scope])).unwrap(), Value::Null);
        assert_eq!(poll(json!(vec![scope.clone(); 64])).unwrap(), Value::Null);
        assert_eq!(
            poll(json!(vec![scope.clone(); 65])).unwrap_err(),
            "too many deferred delivery streams"
        );
        let mut audience = scope.clone();
        audience["recipients"] = json!((0..64u8).map(|number| [number; 32]).collect::<Vec<_>>());
        assert_eq!(poll(json!([audience])).unwrap(), pending);
        for (field, value) in [
            ("revision", json!(0)),
            ("topic", json!("")),
            ("topic", json!("chat//messages")),
            ("topic", json!("a".repeat(129))),
            ("recipients", json!(vec![[1; 32], [1; 32]])),
            ("recipients", json!(vec![[2; 32], [1; 32]])),
            (
                "recipients",
                json!((0..65u8).map(|number| [number; 32]).collect::<Vec<_>>()),
            ),
        ] {
            let mut invalid = scope.clone();
            invalid[field] = value;
            assert_eq!(
                poll(json!([invalid])).unwrap_err(),
                "invalid deferred delivery stream"
            );
        }
        for (field, value) in [
            ("member", json!(vec![1; 31])),
            ("author", json!(vec![1; 32])),
            ("revision", json!(-1)),
            ("recipients", json!(vec![[1; 31]])),
        ] {
            let mut invalid = scope.clone();
            invalid[field] = value;
            assert!(poll(json!([invalid])).is_err());
        }
        assert!(poll(Value::Null).is_err());
        assert_eq!(call(json!({"op":"poll_pending_object"})).unwrap(), pending);
        {
            let shared = session(handle).unwrap();
            let mut locked = shared.lock().unwrap();
            // Pending application objects never block a membership step (A3).
            check_epoch_transition(locked.as_mut().unwrap()).unwrap();
        }
        let staged = call(
            json!({"op":"stage_object_acknowledgement", "member":pending["member"],
            "topic":pending["topic"], "counter":pending["counter"], "id":pending["id"]}),
        )
        .unwrap();
        call(json!({"op":"adopt_reception","candidate":staged["candidate"]})).unwrap();
        assert_eq!(
            call(json!({"op":"poll_pending_object"})).unwrap(),
            Value::Null
        );
        {
            let shared = session(handle).unwrap();
            let mut locked = shared.lock().unwrap();
            let owner = locked.as_mut().unwrap();
            assert_eq!(owner.delivery.inbox.as_ref().unwrap().pending_count(), 1);
            check_epoch_transition(owner).unwrap();
        }
        close(handle).unwrap();
    }
}
