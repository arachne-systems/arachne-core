//! Membership reconciliation from the host: presence rounds, membership
//! queries and offers. The replies of the query and offer ops are open
//! events (typed with `Event` in ADR step 4).

use arachne_api::ApiError;
use serde::Deserialize;
use serde_json::Value;

use crate::Session;
use crate::membership::{self, Reconcile};
use crate::presence::{self, PresenceReply};

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PresenceArgs {
    #[serde(default)]
    pub announce: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FetchUpdateArgs {
    pub peer: [u8; 32],
    #[serde(default)]
    pub replace_pending: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NextPeerArgs {
    pub after: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OfferArgs {
    pub peer: [u8; 32],
    pub after: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OfferStagedArgs {
    pub peer: [u8; 32],
}

/// One presence round with the workspace's members.
pub(crate) fn poll_presence(
    session: &mut Session,
    args: PresenceArgs,
) -> Result<PresenceReply, ApiError> {
    presence::poll(session, args.announce)
}

pub(crate) fn fetch_update(
    session: &mut Session,
    args: FetchUpdateArgs,
) -> Result<Value, ApiError> {
    membership::reconcile(
        session,
        Reconcile::Fetch {
            peer: args.peer,
            replace_pending: args.replace_pending,
        },
    )
}

pub(crate) fn poll_update(session: &mut Session) -> Result<Value, ApiError> {
    membership::reconcile(session, Reconcile::PollUpdate)
}

pub(crate) fn next_peer(session: &mut Session, args: NextPeerArgs) -> Result<Value, ApiError> {
    membership::reconcile(session, Reconcile::NextPeer { after: args.after })
}

pub(crate) fn offer_update(session: &mut Session, args: OfferArgs) -> Result<Value, ApiError> {
    membership::reconcile(
        session,
        Reconcile::Offer {
            peer: args.peer,
            after: args.after,
        },
    )
}

pub(crate) fn offer_staged(
    session: &mut Session,
    args: OfferStagedArgs,
) -> Result<Value, ApiError> {
    membership::reconcile(session, Reconcile::OfferStaged { peer: args.peer })
}

pub(crate) fn poll_offer(session: &mut Session) -> Result<Value, ApiError> {
    membership::reconcile(session, Reconcile::PollOffer)
}
