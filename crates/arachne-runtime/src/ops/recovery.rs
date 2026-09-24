//! Recovery, direct recovery and current view. For now this module holds the
//! serving side (answers to peers' queries); the host ops move here with the
//! recovery group (ADR step 2).

use arachne_api::{ApiError, ErrorCode};
use serde_json::{Value, json};

use crate::Session;
use crate::errors::{self, delivery};

/// A peer's continuity query: range, available range, cutoff, current view
/// or direct range.
pub(crate) fn is_query(payload: &[u8]) -> bool {
    payload.starts_with(b"DFRQ")
        || payload.starts_with(b"DFHQ")
        || payload.starts_with(b"DFCQ")
        || payload.starts_with(b"DFVQ")
        || payload.starts_with(b"DFDQ")
}

/// Answer one continuity query from committed state. Never serves staged
/// state (the guards reject polls while adoption is pending).
pub(crate) fn serve(
    session: &mut Session,
    incoming: arachne_node::ControlRequest,
) -> Result<Value, ApiError> {
    let reply = match session.workspace.as_ref() {
        Some(owner) => {
            let now = arachne_delivery::UnixSeconds::now().map_err(delivery(ErrorCode::Internal))?;
            session
                .runtime
                .block_on(session.node.with_routing_policy(|policy| {
                    if incoming.payload().starts_with(b"DFDQ") {
                        match (
                            session.delivery.inbox.as_ref(),
                            arachne_delivery::wire::DirectRangeQuery::from_wire(
                                incoming.payload(),
                            ),
                        ) {
                            (Some(inbox), Ok(query)) => inbox.serve_direct_range(
                                owner,
                                policy,
                                incoming.peer(),
                                &query,
                            ),
                            _ => Ok(arachne_delivery::wire::unavailable_direct_reply()),
                        }
                    } else if incoming.payload().starts_with(b"DFVQ") {
                        match (
                            session.delivery.inbox.as_ref(),
                            arachne_delivery::current::CurrentViewQuery::from_wire(
                                incoming.payload(),
                            ),
                        ) {
                            (Some(inbox), Ok(query)) => inbox.serve_current(
                                owner,
                                policy,
                                incoming.peer(),
                                &query,
                                now,
                            ),
                            _ => Ok(arachne_delivery::current::CurrentView::denied_wire()),
                        }
                    } else if incoming.payload().starts_with(b"DFCQ") {
                        match (
                            session.delivery.publisher.as_ref(),
                            arachne_delivery::wire::CutoffQuery::from_wire(
                                incoming.payload(),
                            ),
                        ) {
                            (Some(log), Ok(query)) => arachne_delivery::wire::serve_cutoff(
                                log,
                                owner,
                                policy,
                                incoming.peer(),
                                &query,
                            ),
                            _ => Ok(arachne_delivery::wire::denied_reply()),
                        }
                    } else if incoming.payload().starts_with(b"DFHQ") {
                        let Ok(query) =
                            arachne_delivery::wire::AvailableRangeQuery::from_wire(
                                incoming.payload(),
                            )
                        else {
                            return Ok(
                                arachne_delivery::wire::unavailable_available_reply(),
                            );
                        };
                        if owner.member().map(|member| member.id()) == Some(query.author) {
                            match session.delivery.publisher.as_ref() {
                                Some(log) => arachne_delivery::wire::serve_available_range(
                                    log,
                                    owner,
                                    policy,
                                    incoming.peer(),
                                    &query,
                                ),
                                None => Ok(
                                    arachne_delivery::wire::unavailable_available_reply(),
                                ),
                            }
                        } else {
                            match session.delivery.inbox.as_ref() {
                                Some(inbox) => inbox.serve_available_range(
                                    owner,
                                    policy,
                                    incoming.peer(),
                                    &query,
                                    now,
                                ),
                                None => Ok(
                                    arachne_delivery::wire::unavailable_available_reply(),
                                ),
                            }
                        }
                    } else {
                        let Ok(query) =
                            arachne_delivery::RangeQuery::from_wire(incoming.payload())
                        else {
                            return Ok(arachne_delivery::wire::denied_reply());
                        };
                        if owner.member().map(|member| member.id()) == Some(query.author) {
                            match session.delivery.publisher.as_ref() {
                                Some(log) => arachne_delivery::wire::serve_range(
                                    log,
                                    owner,
                                    policy,
                                    incoming.peer(),
                                    &query,
                                ),
                                None => Ok(arachne_delivery::wire::denied_reply()),
                            }
                        } else {
                            match session.delivery.inbox.as_ref() {
                                Some(inbox) => inbox.serve_range(
                                    owner,
                                    policy,
                                    incoming.peer(),
                                    &query,
                                    now,
                                ),
                                None => Ok(arachne_delivery::wire::denied_reply()),
                            }
                        }
                    }
                }))
                .map_err(delivery(ErrorCode::Internal))?
        }
        None if incoming.payload().starts_with(b"DFVQ") => {
            arachne_delivery::current::CurrentView::denied_wire()
        }
        None if incoming.payload().starts_with(b"DFHQ") => {
            arachne_delivery::wire::unavailable_available_reply()
        }
        None if incoming.payload().starts_with(b"DFDQ") => {
            arachne_delivery::wire::unavailable_direct_reply()
        }
        None => arachne_delivery::wire::denied_reply(),
    };
    let state = if incoming.payload().starts_with(b"DFVQ") {
        "current_view_replied"
    } else if incoming.payload().starts_with(b"DFDQ") {
        "direct_recovery_replied"
    } else {
        "recovery_replied"
    };
    incoming.respond(reply).map_err(errors::node)?;
    Ok(json!({"state":state, "remote_receipt":false}))
}
