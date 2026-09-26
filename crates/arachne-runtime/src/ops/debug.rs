//! Endpoint-level ops that involve no workspace authority: endpoint info,
//! the debug rig's raw control exchange, a network change, and resource
//! transfer jobs.

use arachne_api::ApiError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::errors;
use crate::{Session, resources};

/// One control request to a peer by endpoint key, with an optional address
/// hint; returns the peer's reply bytes. No workspace authority is involved.
/// Used by the debug rig link to dial its controller.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ControlExchangeArgs {
    pub peer: [u8; 32],
    pub address: Option<String>,
    pub payload: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResourceArgs {
    pub request: resources::Request,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct EndpointBinding {
    pub endpoint_key: [u8; 32],
    pub bound_address: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ControlReply {
    pub reply: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct Notified {
    pub notified: bool,
}

pub(crate) fn endpoint_info(session: &mut Session) -> Result<EndpointBinding, ApiError> {
    Ok(EndpointBinding {
        endpoint_key: session.node.id(),
        bound_address: session.node.address().to_string(),
    })
}

pub(crate) fn control_exchange(
    session: &mut Session,
    args: ControlExchangeArgs,
) -> Result<ControlReply, ApiError> {
    if let Some(address) = args.address {
        let address: std::net::SocketAddr = address
            .parse()
            .map_err(|_| ApiError::invalid_input("address", "invalid address hint"))?;
        session
            .runtime
            .block_on(session.node.add_address_hint(args.peer, address))
            .map_err(errors::node)?;
    }
    let reply = session
        .runtime
        .block_on(session.node.request_control(args.peer, &args.payload))
        .map_err(errors::node)?;
    Ok(ControlReply { reply })
}

/// The host saw a network change: re-bind paths and replay interest.
pub(crate) fn network_change(session: &mut Session) -> Result<Notified, ApiError> {
    session.runtime.block_on(session.node.network_change());
    session.interests.repair();
    Ok(Notified { notified: true })
}

/// One resource transfer step. The reply is the job's state (an open
/// event, typed in ADR step 4).
pub(crate) fn resource(session: &mut Session, args: ResourceArgs) -> Result<Value, ApiError> {
    resources::execute(session, args.request)
}
