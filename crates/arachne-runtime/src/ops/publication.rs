//! Protected publication: stage an outgoing object (group or direct, with
//! optional latest-value metadata), then adopt it; the adopt step sends it
//! (`ops::candidate`).

use arachne_api::{ApiError, ErrorCode};
use arachne_routing::PublicationContext;
use serde::{Deserialize, Serialize};

use crate::errors::{self, delivery, security};
use crate::session::seal_state;
use crate::{Session, StagedWorkspace, WorkspaceTransition};

/// Latest-value metadata of a protected publication.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CurrentPublication {
    pub(crate) selector: [u8; 32],
    pub(crate) replacement_key: [u8; 32],
    pub(crate) expires_at: u64,
    #[serde(default)]
    pub(crate) tombstone: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StagePublicationArgs {
    /// When present, must name the session workspace; checked before staging.
    #[serde(default)]
    pub workspace: Option<[u8; 32]>,
    pub revision: u64,
    pub topic: String,
    pub id: [u8; 16],
    pub payload: Vec<u8>,
    /// Empty is a normal topic publication. A nonempty scope contains
    /// canonical workspace member identities for a direct publication.
    #[serde(default)]
    pub recipients: Vec<[u8; 32]>,
    #[serde(default)]
    pub current: Option<CurrentPublication>,
    #[serde(default)]
    pub bulk: bool,
}

/// An object candidate (outgoing publication or inbox change) that awaits
/// the host's save.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct StagedObject {
    pub workspace: [u8; 32],
    /// The opaque candidate token; adopt it with the matching adopt op.
    #[serde(rename = "candidate")]
    pub snapshot: Vec<u8>,
    pub state: &'static str,
    pub durable: bool,
    /// B7e: direct sequences given up when this step moved a floor past a gap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_count: Option<u64>,
}

/// B5: a publication names the session workspace, checked before anything
/// is staged so the session stays usable.
pub(crate) fn check_workspace(
    session: &Session,
    workspace: Option<[u8; 32]>,
) -> Result<(), ApiError> {
    crate::membership::fork::require_send(session)?;
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    if workspace.is_some_and(|workspace| workspace != owner.id()) {
        return Err(ApiError::invalid_input(
            "workspace",
            "invalid publication workspace for this session",
        ));
    }
    Ok(())
}

/// The session's publisher log, or a new one for the owner's current epoch.
pub(crate) fn publisher_or_new(
    session: &Session,
    owner: &arachne_security::Workspace,
) -> Result<arachne_delivery::PublisherLog, ApiError> {
    match &session.delivery.publisher {
        Some(publisher) => Ok(publisher.clone()),
        None => arachne_delivery::PublisherLog::new(owner).map_err(delivery(ErrorCode::Internal)),
    }
}

/// B7e: the direct sequences a candidate inbox gave up that the committed
/// inbox had not, reported as `missing_count`.
pub(crate) fn missed_since_commit(
    session: &Session,
    candidate: Option<&arachne_delivery::inbox::ObjectInbox>,
) -> Option<u64> {
    let before = session
        .delivery
        .inbox
        .as_ref()
        .map_or(0, arachne_delivery::inbox::ObjectInbox::missed_direct);
    let missed = candidate
        .map_or(0, arachne_delivery::inbox::ObjectInbox::missed_direct)
        .saturating_sub(before);
    (missed > 0).then_some(missed)
}

/// Seal and hold one object candidate. Shared by publication and reception.
pub(crate) fn stage_object(
    session: &mut Session,
    candidate: arachne_security::Workspace,
    publisher: arachne_delivery::PublisherLog,
    inbox: arachne_delivery::inbox::ObjectInbox,
    transition: WorkspaceTransition,
    state: &'static str,
) -> Result<StagedObject, ApiError> {
    let snapshot = seal_state(session.records.is_some())?;
    let missing_count = missed_since_commit(session, Some(&inbox));
    Ok(hold_object(
        session,
        candidate,
        publisher,
        inbox,
        snapshot,
        transition,
        state,
        missing_count,
    ))
}

/// Hold one sealed object candidate for the host's save.
#[allow(clippy::too_many_arguments)]
pub(crate) fn hold_object(
    session: &mut Session,
    candidate: arachne_security::Workspace,
    publisher: arachne_delivery::PublisherLog,
    inbox: arachne_delivery::inbox::ObjectInbox,
    snapshot: Vec<u8>,
    transition: WorkspaceTransition,
    state: &'static str,
    missing_count: Option<u64>,
) -> StagedObject {
    let value = StagedObject {
        workspace: candidate.id(),
        snapshot: snapshot.clone(),
        state,
        durable: false,
        missing_count,
    };
    session.transition.staged = Some(StagedWorkspace {
        publisher: Some(publisher),
        inbox: Some(inbox),
        transition,
        workspace: candidate,
        snapshot,
    });
    value
}

/// Stage one outgoing protected object. Adopting it sends it.
pub(crate) fn stage(
    session: &mut Session,
    args: StagePublicationArgs,
) -> Result<StagedObject, ApiError> {
    stage_publication(session, args, false)
}

pub(crate) fn stage_republication(
    session: &mut Session,
    args: StagePublicationArgs,
) -> Result<StagedObject, ApiError> {
    stage_publication(session, args, true)
}

fn stage_publication(
    session: &mut Session,
    args: StagePublicationArgs,
    recovering: bool,
) -> Result<StagedObject, ApiError> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    session
        .records
        .as_ref()
        .ok_or_else(crate::persistence::storage_required)?;
    // Reject before anything is staged so the session stays usable.
    check_workspace(session, args.workspace)?;
    let StagePublicationArgs {
        workspace: _,
        revision,
        topic,
        id,
        payload,
        recipients,
        current,
        bulk,
    } = args;
    let mut candidate = owner
        .provisional_copy()
        .map_err(security(ErrorCode::Internal))?;
    let mut publisher = session.delivery.publisher.clone();
    // Object delivery is the only receive path.
    let mut inbox =
        Some(session.delivery.inbox.clone().unwrap_or_else(|| {
            arachne_delivery::inbox::ObjectInbox::new(owner.id(), owner.epoch())
        }));
    if bulk && current.is_some() {
        return Err(ApiError::invalid_input(
            "bulk",
            "current publication cannot be bulk",
        ));
    }
    if !recipients.is_empty()
        && (recipients.len() > 64 || recipients.windows(2).any(|pair| pair[0] >= pair[1]))
    {
        return Err(ApiError::invalid_input(
            "recipients",
            "invalid direct recipient scope",
        ));
    }
    let self_member = owner
        .member()
        .ok_or_else(|| ApiError::wrong_state("publisher requires member identity"))?
        .id();
    if recipients.contains(&self_member) {
        return Err(ApiError::invalid_input(
            "recipients",
            "direct recipient cannot be sender",
        ));
    }
    let current = current.map(|value| arachne_delivery::current::CurrentMetadata {
        selector: value.selector,
        replacement_key: value.replacement_key,
        expires_at: value.expires_at,
        tombstone: value.tombstone,
    });
    let delivery_class = match current {
        Some(current) => arachne_node::DeliveryClass::Current {
            replacement_key: current.replacement_key,
        },
        None if bulk => arachne_node::DeliveryClass::Bulk,
        None => arachne_node::DeliveryClass::Critical,
    };
    if current.is_some() && !recipients.is_empty() {
        return Err(ApiError::invalid_input(
            "current",
            "current values require group object delivery",
        ));
    }
    let mut endpoints = if recipients.is_empty() {
        Vec::new()
    } else {
        owner
            .endpoints_for_members(&recipients)
            .map_err(security(ErrorCode::InvalidInput))?
    };
    endpoints.sort_unstable();
    let topic = arachne_node::Topic::new(topic).map_err(errors::routing)?;
    let context = PublicationContext {
        sequence: if recipients.is_empty() {
            Some(
                std::num::NonZeroU64::new(
                    publisher
                        .as_ref()
                        .map_or(0, |log| log.head())
                        .checked_add(1)
                        .ok_or_else(|| {
                            ApiError::limit_reached(
                                "publisher sequence",
                                u64::MAX,
                                "publisher sequence exhausted",
                            )
                        })?,
                )
                .unwrap(),
            )
        } else if let Some(inbox) = inbox.as_ref() {
            Some(
                inbox
                    .next_direct_sequence(owner, revision, &topic, &recipients)
                    .map_err(delivery(ErrorCode::InvalidInput))?,
            )
        } else {
            None
        },
        workspace: owner.id(),
        revision,
        topic,
        id,
    };
    let aad = if let Some(current) = current {
        current.authenticated_context(&context)
    } else if recipients.is_empty() {
        context.authenticated_bytes()
    } else {
        context
            .direct_authenticated_bytes(&recipients)
            .map_err(|reason| ApiError::invalid_input("recipients", reason))?
    };
    // Independent authenticated objects: each has its own sender
    // counter and decrypts without any ratchet state.
    let ciphertext = candidate
        .protect_object(context.topic.namespace().as_bytes(), &aad, &payload)
        .map_err(security(ErrorCode::InvalidInput))?;
    // Start retention with the first routed publication after activation.
    // No coverage for pre-activation data or old epochs is advertised.
    if recipients.is_empty() && publisher.is_none() {
        publisher = Some(
            arachne_delivery::PublisherLog::new(owner).map_err(delivery(ErrorCode::Internal))?,
        );
    }
    let packet = context
        .packet(&ciphertext)
        .map_err(|reason| ApiError::invalid_input("payload", reason))?;
    if let Some(current) = current {
        let now = arachne_delivery::UnixSeconds::now().map_err(delivery(ErrorCode::Internal))?;
        inbox = Some(
            inbox
                .as_ref()
                .ok_or_else(|| ApiError::wrong_state("current values require object delivery"))?
                .stage_current(
                    &candidate,
                    context.clone(),
                    current.selector,
                    current.replacement_key,
                    current.expires_at,
                    current.tombstone,
                    packet.clone(),
                    now,
                )
                .map_err(delivery(ErrorCode::InvalidInput))?,
        );
    }
    let packet = match current {
        Some(metadata) => arachne_delivery::current::LiveCurrentPacket { metadata, packet }
            .to_wire()
            .map_err(delivery(ErrorCode::InvalidInput))?,
        None => packet,
    };
    if !recipients.is_empty() && context.sequence.is_some() {
        inbox = Some(
            inbox
                .as_ref()
                .ok_or_else(|| ApiError::wrong_state("direct recovery requires object delivery"))?
                .stage_sent_direct(&candidate, &context, &recipients, &ciphertext)
                .map_err(delivery(ErrorCode::InvalidInput))?,
        );
    }
    if recipients.is_empty() {
        publisher
            .as_mut()
            .unwrap()
            .append(
                context.clone(),
                if current.is_some() {
                    packet.clone()
                } else {
                    ciphertext
                },
            )
            .map_err(delivery(ErrorCode::InvalidInput))?;
    }
    let transition = if recovering {
        WorkspaceTransition::Republication(context, delivery_class, packet, endpoints, recipients)
    } else {
        WorkspaceTransition::RoutedPublication(
            context,
            delivery_class,
            packet,
            endpoints,
            recipients,
        )
    };
    let publisher = match publisher {
        Some(publisher) => publisher,
        None => {
            arachne_delivery::PublisherLog::new(owner).map_err(delivery(ErrorCode::Internal))?
        }
    };
    let inbox = inbox.expect("object delivery inbox");
    // Self-update policy (B3c): count objects this member sends.
    session.membership.self_update.record_sent(1);
    stage_object(
        session,
        candidate,
        publisher,
        inbox,
        transition,
        if recovering {
            "awaiting_save"
        } else {
            "awaiting_publication_save"
        },
    )
}
