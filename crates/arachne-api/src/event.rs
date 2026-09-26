use serde::{Deserialize, Serialize};

/// One event from `Client::next_event` (ADR step 4). An event names the
/// queue or job that has work; the host then calls that queue's poll or
/// stage call. It carries no payload, so no data is copied twice.
///
/// Queue events (`Control`, `MembershipChanged`, `ProtectedReceived`,
/// `PublicationReceived`) repeat until the host drains the queue. Job
/// events (`RecoveryReady`, `CurrentViewReady`, `InterestChanged`,
/// `Presence`) come once per ready job.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// Reserved; admission requests arrive as `Control`.
    AdmissionRequest,
    /// Membership steps from gossip: `poll_membership_update`.
    MembershipChanged,
    /// A protected delivery: `poll_protected`.
    ProtectedReceived,
    /// A recovery range ended: `poll_recovery_range`.
    RecoveryReady,
    /// A current-view repair ended: `poll_current_view`.
    CurrentViewReady,
    /// An interest announcement ended: `poll_interest`.
    InterestChanged,
    /// A presence answer came back: `poll_presence`.
    Presence,
    /// Reserved; nearby invitations arrive as `Control`.
    NearbyInvitation,
    /// The runtime ended the session (for example a removal). Call `close`.
    Closed,
    /// Peer control requests wait (admission, profile, presence, nearby):
    /// `poll_admission` / `poll_control` until it has nothing.
    Control,
    /// An unprotected fixture publication (no workspace): `poll`.
    PublicationReceived,
}
