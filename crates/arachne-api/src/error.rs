//! The one error model of the public API (ADR A1/A4, decision 3).
//!
//! Programs read [`ApiError::code`]. The message text is for people only.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ids::EndpointId;

/// A stable numeric error code.
///
/// Ranges:
///
/// | Range   | Meaning                          |
/// | ------- | -------------------------------- |
/// | 1-99    | Lifecycle (closed, cancelled)    |
/// | 100-199 | Input and state                  |
/// | 200-299 | Capacity and limits              |
/// | 300-399 | Storage and candidates           |
/// | 400-499 | Transport and peers              |
/// | 500-599 | Authorization and membership     |
/// | 600-699 | Group consistency                |
/// | 900-999 | Internal                         |
///
/// Rules: a number is never changed and never reused. New codes are added only
/// at the end of a range. A new code increments [`crate::API_VERSION`]. The
/// golden test in `tests/error_codes.rs` pins every value.
///
/// On the wire (serde) a code is its number.
#[non_exhaustive]
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ErrorCode {
    Closed = 1,
    Cancelled = 2,
    DeadlineExceeded = 3,
    InvalidInput = 100,
    InvalidId = 101,
    WrongState = 102,
    Unsupported = 103,
    /// A resource is full for now (a queue, a worker pool); retry later.
    CapacityExceeded = 200,
    /// A fixed limit is reached (sessions, advertisements, overlay paths).
    LimitReached = 201,
    StorageFailed = 300,
    StorageCorrupt = 301,
    /// A staged candidate no longer matches the state it was staged from
    /// (ADR decision 5). It stays in the storage range on purpose: a
    /// candidate is a staged storage record, and "stale" means its stored
    /// basis moved. Numbers never move, so this is also the stable place.
    CandidateStale = 302,
    /// Stored data has a format this build does not read: newer than it
    /// supports, or older than the first supported format (no legacy readers).
    FormatNotSupported = 303,
    PeerUnreachable = 400,
    Timeout = 401,
    TransportFailed = 402,
    NotAuthorized = 500,
    InvitationInvalid = 501,
    InvitationExpired = 502,
    NotMember = 503,
    EpochMismatch = 600,
    PolicyMismatch = 601,
    Internal = 900,
}

impl ErrorCode {
    /// Every code, in numeric order.
    pub const ALL: &'static [ErrorCode] = &[
        Self::Closed,
        Self::Cancelled,
        Self::DeadlineExceeded,
        Self::InvalidInput,
        Self::InvalidId,
        Self::WrongState,
        Self::Unsupported,
        Self::CapacityExceeded,
        Self::LimitReached,
        Self::StorageFailed,
        Self::StorageCorrupt,
        Self::CandidateStale,
        Self::FormatNotSupported,
        Self::PeerUnreachable,
        Self::Timeout,
        Self::TransportFailed,
        Self::NotAuthorized,
        Self::InvitationInvalid,
        Self::InvitationExpired,
        Self::NotMember,
        Self::EpochMismatch,
        Self::PolicyMismatch,
        Self::Internal,
    ];

    /// The stable number of this code.
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// The code for a stable number, or `None` for an unknown number.
    pub const fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            1 => Self::Closed,
            2 => Self::Cancelled,
            3 => Self::DeadlineExceeded,
            100 => Self::InvalidInput,
            101 => Self::InvalidId,
            102 => Self::WrongState,
            103 => Self::Unsupported,
            200 => Self::CapacityExceeded,
            201 => Self::LimitReached,
            300 => Self::StorageFailed,
            301 => Self::StorageCorrupt,
            302 => Self::CandidateStale,
            303 => Self::FormatNotSupported,
            400 => Self::PeerUnreachable,
            401 => Self::Timeout,
            402 => Self::TransportFailed,
            500 => Self::NotAuthorized,
            501 => Self::InvitationInvalid,
            502 => Self::InvitationExpired,
            503 => Self::NotMember,
            600 => Self::EpochMismatch,
            601 => Self::PolicyMismatch,
            900 => Self::Internal,
            _ => return None,
        })
    }

    /// The stable snake_case name of this code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Cancelled => "cancelled",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::InvalidInput => "invalid_input",
            Self::InvalidId => "invalid_id",
            Self::WrongState => "wrong_state",
            Self::Unsupported => "unsupported",
            Self::CapacityExceeded => "capacity_exceeded",
            Self::LimitReached => "limit_reached",
            Self::StorageFailed => "storage_failed",
            Self::StorageCorrupt => "storage_corrupt",
            Self::CandidateStale => "candidate_stale",
            Self::FormatNotSupported => "format_not_supported",
            Self::PeerUnreachable => "peer_unreachable",
            Self::Timeout => "timeout",
            Self::TransportFailed => "transport_failed",
            Self::NotAuthorized => "not_authorized",
            Self::InvitationInvalid => "invitation_invalid",
            Self::InvitationExpired => "invitation_expired",
            Self::NotMember => "not_member",
            Self::EpochMismatch => "epoch_mismatch",
            Self::PolicyMismatch => "policy_mismatch",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(self.as_u32())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u32::deserialize(deserializer)?;
        Self::from_u32(value)
            .ok_or_else(|| serde::de::Error::custom(format_args!("unknown error code {value}")))
    }
}

/// The error of every public operation.
///
/// Make it where the failure happens. Do not guess it from message text.
///
/// # Pairing rule
///
/// Variants that carry a `code` accept only codes from their own group:
///
/// | Variant         | Codes                                              |
/// | --------------- | -------------------------------------------------- |
/// | `Storage`       | 300-399 (`StorageFailed`, `StorageCorrupt`, `CandidateStale`, `FormatNotSupported`) |
/// | `Transport`     | 400-499                                            |
/// | `Authorization` | 500-599                                            |
/// | `State`         | `WrongState`, `Unsupported`, 600-699               |
///
/// The fields of an enum variant are public in Rust, so the compiler cannot
/// stop a wrong pair. Make errors with the checked constructors
/// ([`ApiError::new`] and the named ones such as [`ApiError::timeout`]); they
/// always pick the right variant. [`ApiError::is_well_formed`] checks a value,
/// and deserialization rejects a wrong pair.
///
/// # No secrets
///
/// `detail`, `reason`, `resource` and `kind` are for people. They must never
/// hold key material, invitation tokens, snapshots, plaintext payloads or
/// other secret bytes. Put only fixed text, lengths, counts and public IDs in
/// them.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(
    tag = "error",
    rename_all = "snake_case",
    try_from = "UncheckedApiError"
)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum ApiError {
    #[error("closed")]
    Closed,
    #[error("cancelled")]
    Cancelled,
    #[error("deadline exceeded")]
    DeadlineExceeded,
    #[error("invalid input `{field}`: {reason}")]
    InvalidInput { field: String, reason: String },
    /// Not in the ADR sketch; added so `ErrorCode::InvalidId` has a variant.
    #[error("invalid {kind} id: {reason}")]
    InvalidId { kind: String, reason: String },
    /// A resource is full for now (a queue, a worker pool). A later retry can
    /// succeed. `limit` is 0 when the bound is not one fixed number.
    #[error("capacity exceeded for {resource} (limit {limit}): {detail}")]
    CapacityExceeded {
        resource: String,
        limit: u64,
        #[serde(default)]
        detail: String,
    },
    /// A fixed limit is reached (sessions, advertisements, overlay paths).
    /// It stays reached until something is released. `limit` is 0 when the
    /// bound is not one fixed number. Added in API version 2.
    #[error("limit reached for {resource} (limit {limit}): {detail}")]
    LimitReached {
        resource: String,
        limit: u64,
        #[serde(default)]
        detail: String,
    },
    #[error("storage error ({code}): {detail}")]
    Storage { code: ErrorCode, detail: String },
    #[error("transport error ({code}): {detail}")]
    Transport {
        code: ErrorCode,
        peer: Option<EndpointId>,
        detail: String,
    },
    #[error("authorization error ({code}): {detail}")]
    Authorization { code: ErrorCode, detail: String },
    #[error("state error ({code}): {detail}")]
    State { code: ErrorCode, detail: String },
    #[error("internal error: {detail}")]
    Internal { detail: String },
}

/// The serde twin of [`ApiError`] without the pairing check.
#[derive(Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
enum UncheckedApiError {
    Closed,
    Cancelled,
    DeadlineExceeded,
    InvalidInput {
        field: String,
        reason: String,
    },
    InvalidId {
        kind: String,
        reason: String,
    },
    CapacityExceeded {
        resource: String,
        limit: u64,
        #[serde(default)]
        detail: String,
    },
    LimitReached {
        resource: String,
        limit: u64,
        #[serde(default)]
        detail: String,
    },
    Storage {
        code: ErrorCode,
        detail: String,
    },
    Transport {
        code: ErrorCode,
        peer: Option<EndpointId>,
        detail: String,
    },
    Authorization {
        code: ErrorCode,
        detail: String,
    },
    State {
        code: ErrorCode,
        detail: String,
    },
    Internal {
        detail: String,
    },
}

impl TryFrom<UncheckedApiError> for ApiError {
    type Error = String;

    fn try_from(value: UncheckedApiError) -> Result<Self, String> {
        use UncheckedApiError as U;
        let error = match value {
            U::Closed => Self::Closed,
            U::Cancelled => Self::Cancelled,
            U::DeadlineExceeded => Self::DeadlineExceeded,
            U::InvalidInput { field, reason } => Self::InvalidInput { field, reason },
            U::InvalidId { kind, reason } => Self::InvalidId { kind, reason },
            U::CapacityExceeded {
                resource,
                limit,
                detail,
            } => Self::CapacityExceeded {
                resource,
                limit,
                detail,
            },
            U::LimitReached {
                resource,
                limit,
                detail,
            } => Self::LimitReached {
                resource,
                limit,
                detail,
            },
            U::Storage { code, detail } => Self::Storage { code, detail },
            U::Transport { code, peer, detail } => Self::Transport { code, peer, detail },
            U::Authorization { code, detail } => Self::Authorization { code, detail },
            U::State { code, detail } => Self::State { code, detail },
            U::Internal { detail } => Self::Internal { detail },
        };
        if error.is_well_formed() {
            Ok(error)
        } else {
            Err(format!(
                "error code {} does not belong to this variant",
                error.code().as_u32()
            ))
        }
    }
}

impl ApiError {
    /// The stable code. Programs branch on this, never on the text.
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Closed => ErrorCode::Closed,
            Self::Cancelled => ErrorCode::Cancelled,
            Self::DeadlineExceeded => ErrorCode::DeadlineExceeded,
            Self::InvalidInput { .. } => ErrorCode::InvalidInput,
            Self::InvalidId { .. } => ErrorCode::InvalidId,
            Self::CapacityExceeded { .. } => ErrorCode::CapacityExceeded,
            Self::LimitReached { .. } => ErrorCode::LimitReached,
            Self::Storage { code, .. }
            | Self::Transport { code, .. }
            | Self::Authorization { code, .. }
            | Self::State { code, .. } => *code,
            Self::Internal { .. } => ErrorCode::Internal,
        }
    }

    /// Whether a `code` field belongs to its variant (see the pairing rule).
    /// Values made by the constructors are always well formed.
    pub fn is_well_formed(&self) -> bool {
        use ErrorCode as C;
        match self {
            Self::Storage { code, .. } => {
                matches!(
                    code,
                    C::StorageFailed
                        | C::StorageCorrupt
                        | C::CandidateStale
                        | C::FormatNotSupported
                )
            }
            Self::Transport { code, .. } => {
                matches!(code, C::PeerUnreachable | C::Timeout | C::TransportFailed)
            }
            Self::Authorization { code, .. } => matches!(
                code,
                C::NotAuthorized | C::InvitationInvalid | C::InvitationExpired | C::NotMember
            ),
            Self::State { code, .. } => matches!(
                code,
                C::WrongState | C::Unsupported | C::EpochMismatch | C::PolicyMismatch
            ),
            _ => true,
        }
    }

    /// The human text without the code prefix: the `detail` or `reason`, or
    /// a fixed word for the variants without text.
    pub fn message(&self) -> &str {
        match self {
            Self::Closed => "closed",
            Self::Cancelled => "cancelled",
            Self::DeadlineExceeded => "deadline exceeded",
            Self::InvalidInput { reason, .. } | Self::InvalidId { reason, .. } => reason,
            Self::CapacityExceeded { detail, .. }
            | Self::LimitReached { detail, .. }
            | Self::Storage { detail, .. }
            | Self::Transport { detail, .. }
            | Self::Authorization { detail, .. }
            | Self::State { detail, .. }
            | Self::Internal { detail } => detail,
        }
    }

    /// The error for any code, with its right variant. Fields that the code
    /// does not name get neutral values (empty `field`/`kind`/`resource`,
    /// `limit` 0, no peer). Prefer a named constructor when one fits.
    pub fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        use ErrorCode as C;
        let detail = detail.into();
        match code {
            C::Closed => Self::Closed,
            C::Cancelled => Self::Cancelled,
            C::DeadlineExceeded => Self::DeadlineExceeded,
            C::InvalidInput => Self::InvalidInput {
                field: String::new(),
                reason: detail,
            },
            C::InvalidId => Self::InvalidId {
                kind: String::new(),
                reason: detail,
            },
            C::CapacityExceeded => Self::CapacityExceeded {
                resource: String::new(),
                limit: 0,
                detail,
            },
            C::LimitReached => Self::LimitReached {
                resource: String::new(),
                limit: 0,
                detail,
            },
            C::StorageFailed | C::StorageCorrupt | C::CandidateStale | C::FormatNotSupported => {
                Self::Storage { code, detail }
            }
            C::PeerUnreachable | C::Timeout | C::TransportFailed => Self::Transport {
                code,
                peer: None,
                detail,
            },
            C::NotAuthorized | C::InvitationInvalid | C::InvitationExpired | C::NotMember => {
                Self::Authorization { code, detail }
            }
            C::WrongState | C::Unsupported | C::EpochMismatch | C::PolicyMismatch => {
                Self::State { code, detail }
            }
            C::Internal => Self::Internal { detail },
        }
    }

    pub fn invalid_input(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidInput {
            field: field.into(),
            reason: reason.into(),
        }
    }

    pub fn invalid_id(kind: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidId {
            kind: kind.into(),
            reason: reason.into(),
        }
    }

    pub fn wrong_state(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::WrongState, detail)
    }

    pub fn unsupported(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unsupported, detail)
    }

    pub fn capacity_exceeded(
        resource: impl Into<String>,
        limit: u64,
        detail: impl Into<String>,
    ) -> Self {
        Self::CapacityExceeded {
            resource: resource.into(),
            limit,
            detail: detail.into(),
        }
    }

    pub fn limit_reached(
        resource: impl Into<String>,
        limit: u64,
        detail: impl Into<String>,
    ) -> Self {
        Self::LimitReached {
            resource: resource.into(),
            limit,
            detail: detail.into(),
        }
    }

    pub fn storage_failed(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::StorageFailed, detail)
    }

    pub fn storage_corrupt(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::StorageCorrupt, detail)
    }

    pub fn candidate_stale(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::CandidateStale, detail)
    }

    pub fn format_not_supported(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::FormatNotSupported, detail)
    }

    pub fn peer_unreachable(peer: Option<EndpointId>, detail: impl Into<String>) -> Self {
        Self::transport(ErrorCode::PeerUnreachable, peer, detail)
    }

    pub fn timeout(peer: Option<EndpointId>, detail: impl Into<String>) -> Self {
        Self::transport(ErrorCode::Timeout, peer, detail)
    }

    pub fn transport_failed(peer: Option<EndpointId>, detail: impl Into<String>) -> Self {
        Self::transport(ErrorCode::TransportFailed, peer, detail)
    }

    fn transport(code: ErrorCode, peer: Option<EndpointId>, detail: impl Into<String>) -> Self {
        Self::Transport {
            code,
            peer,
            detail: detail.into(),
        }
    }

    pub fn not_authorized(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotAuthorized, detail)
    }

    pub fn invitation_invalid(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvitationInvalid, detail)
    }

    pub fn invitation_expired(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvitationExpired, detail)
    }

    pub fn not_member(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotMember, detail)
    }

    pub fn epoch_mismatch(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::EpochMismatch, detail)
    }

    pub fn policy_mismatch(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::PolicyMismatch, detail)
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self::Internal {
            detail: detail.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ErrorCode;

    /// No wildcard arm: a new variant does not compile until it is added
    /// here, and then this test fails until it is also in `ErrorCode::ALL`
    /// (and so in the golden table test).
    fn listed(code: ErrorCode) -> bool {
        use ErrorCode::*;
        match code {
            Closed | Cancelled | DeadlineExceeded | InvalidInput | InvalidId | WrongState
            | Unsupported | CapacityExceeded | LimitReached | StorageFailed | StorageCorrupt
            | CandidateStale | FormatNotSupported | PeerUnreachable | Timeout | TransportFailed
            | NotAuthorized | InvitationInvalid | InvitationExpired | NotMember | EpochMismatch
            | PolicyMismatch | Internal => ErrorCode::ALL.contains(&code),
        }
    }

    #[test]
    fn all_lists_every_variant_in_numeric_order() {
        for number in 0..=1000 {
            if let Some(code) = ErrorCode::from_u32(number) {
                assert!(listed(code), "{code:?} missing from ALL");
                assert_eq!(code.as_u32(), number);
            }
        }
        assert!(ErrorCode::ALL.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(ErrorCode::ALL.len(), 23);
    }
}

#[cfg(feature = "uniffi")]
#[uniffi::export]
impl ErrorCode {
    /// Stable numeric code; independent of a language enum's ordinal.
    pub fn number(&self) -> u32 {
        self.as_u32()
    }
}
