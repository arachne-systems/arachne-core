use serde::{Deserialize, Serialize};

/// One event from `Client::next_event` (ADR step 4).
///
/// Skeleton: the variants name the event kinds from the ADR. Their payloads
/// are added in step 4, together with the event queue. That change increments
/// `API_VERSION`.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    AdmissionRequest,
    MembershipChanged,
    ProtectedReceived,
    RecoveryReady,
    CurrentViewReady,
    InterestChanged,
    Presence,
    NearbyInvitation,
    Closed,
}
