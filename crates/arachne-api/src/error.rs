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
pub enum ErrorCode {
    Closed = 1,
    Cancelled = 2,
    DeadlineExceeded = 3,
    InvalidInput = 100,
    InvalidId = 101,
    WrongState = 102,
    Unsupported = 103,
    CapacityExceeded = 200,
    LimitReached = 201,
    StorageFailed = 300,
    StorageCorrupt = 301,
    CandidateStale = 302,
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
/// Variants that carry a `code` take a code from their range: `Storage` takes
/// 3xx, `Transport` 4xx, `Authorization` 5xx, and `State` takes 102, 103 or 6xx.
// TODO(ADR A1/A4 step 7): `cfg_attr(feature = "uniffi", derive(uniffi::Error))`.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
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
    #[error("capacity exceeded for {resource} (limit {limit})")]
    CapacityExceeded { resource: String, limit: u64 },
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
            Self::Storage { code, .. }
            | Self::Transport { code, .. }
            | Self::Authorization { code, .. }
            | Self::State { code, .. } => *code,
            Self::Internal { .. } => ErrorCode::Internal,
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
            | CandidateStale | PeerUnreachable | Timeout | TransportFailed | NotAuthorized
            | InvitationInvalid | InvitationExpired | NotMember | EpochMismatch
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
        assert_eq!(ErrorCode::ALL.len(), 22);
    }
}
