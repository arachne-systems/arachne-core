//! Golden table for `ErrorCode`. These numbers and names cross the ABI and
//! are read by programs. Never edit an existing row. Add new rows only at the
//! end of a range. If this test fails, you changed the wire contract.

use arachne_api::{ApiError, EndpointId, ErrorCode};

/// (code, number, stable name, range floor)
const GOLDEN: &[(ErrorCode, u32, &str, u32)] = &[
    (ErrorCode::Closed, 1, "closed", 0),
    (ErrorCode::Cancelled, 2, "cancelled", 0),
    (ErrorCode::DeadlineExceeded, 3, "deadline_exceeded", 0),
    (ErrorCode::InvalidInput, 100, "invalid_input", 100),
    (ErrorCode::InvalidId, 101, "invalid_id", 100),
    (ErrorCode::WrongState, 102, "wrong_state", 100),
    (ErrorCode::Unsupported, 103, "unsupported", 100),
    (ErrorCode::CapacityExceeded, 200, "capacity_exceeded", 200),
    (ErrorCode::LimitReached, 201, "limit_reached", 200),
    (ErrorCode::StorageFailed, 300, "storage_failed", 300),
    (ErrorCode::StorageCorrupt, 301, "storage_corrupt", 300),
    (ErrorCode::CandidateStale, 302, "candidate_stale", 300),
    (ErrorCode::FormatNotSupported, 303, "format_not_supported", 300),
    (ErrorCode::PeerUnreachable, 400, "peer_unreachable", 400),
    (ErrorCode::Timeout, 401, "timeout", 400),
    (ErrorCode::TransportFailed, 402, "transport_failed", 400),
    (ErrorCode::NotAuthorized, 500, "not_authorized", 500),
    (ErrorCode::InvitationInvalid, 501, "invitation_invalid", 500),
    (ErrorCode::InvitationExpired, 502, "invitation_expired", 500),
    (ErrorCode::NotMember, 503, "not_member", 500),
    (ErrorCode::EpochMismatch, 600, "epoch_mismatch", 600),
    (ErrorCode::PolicyMismatch, 601, "policy_mismatch", 600),
    (ErrorCode::Internal, 900, "internal", 900),
];

#[test]
fn every_code_matches_the_golden_table() {
    for &(code, number, name, _) in GOLDEN {
        assert_eq!(code.as_u32(), number, "{code:?} number changed");
        assert_eq!(ErrorCode::from_u32(number), Some(code), "{number} lookup");
        assert_eq!(code.as_str(), name, "{code:?} name changed");
        assert_eq!(code.to_string(), name);
    }
}

#[test]
fn golden_table_covers_every_code_exactly_once() {
    assert_eq!(ErrorCode::ALL.len(), GOLDEN.len());
    for code in ErrorCode::ALL {
        assert_eq!(
            GOLDEN.iter().filter(|row| row.0 == *code).count(),
            1,
            "{code:?} must have exactly one golden row"
        );
    }
    let mut numbers: Vec<u32> = GOLDEN.iter().map(|row| row.1).collect();
    numbers.sort_unstable();
    numbers.dedup();
    assert_eq!(numbers.len(), GOLDEN.len(), "numbers must be unique");
}

#[test]
fn every_code_is_inside_its_documented_range() {
    for &(code, number, _, floor) in GOLDEN {
        let ceiling = if floor == 0 { 99 } else { floor + 99 };
        assert!(
            (floor..=ceiling).contains(&number) && number != 0,
            "{code:?}={number} is outside {floor}..={ceiling}"
        );
    }
}

#[test]
fn unknown_numbers_are_rejected() {
    for number in [0, 4, 99, 104, 202, 304, 403, 504, 602, 899, 901, u32::MAX] {
        assert_eq!(ErrorCode::from_u32(number), None, "{number}");
    }
}

#[test]
fn api_error_code_is_derived_from_the_variant() {
    let peer = EndpointId::from_bytes([7; 32]);
    let cases = [
        (ApiError::Closed, ErrorCode::Closed),
        (ApiError::Cancelled, ErrorCode::Cancelled),
        (ApiError::DeadlineExceeded, ErrorCode::DeadlineExceeded),
        (
            ApiError::InvalidInput {
                field: "topic".into(),
                reason: "empty".into(),
            },
            ErrorCode::InvalidInput,
        ),
        (
            ApiError::InvalidId {
                kind: "workspace".into(),
                reason: "length".into(),
            },
            ErrorCode::InvalidId,
        ),
        (
            ApiError::CapacityExceeded {
                resource: "sessions".into(),
                limit: 8,
                detail: String::new(),
            },
            ErrorCode::CapacityExceeded,
        ),
        (
            ApiError::limit_reached("sessions", 8, "node limit reached"),
            ErrorCode::LimitReached,
        ),
        (
            ApiError::Storage {
                code: ErrorCode::CandidateStale,
                detail: String::new(),
            },
            ErrorCode::CandidateStale,
        ),
        (
            ApiError::Transport {
                code: ErrorCode::PeerUnreachable,
                peer: Some(peer),
                detail: String::new(),
            },
            ErrorCode::PeerUnreachable,
        ),
        (
            ApiError::Authorization {
                code: ErrorCode::NotMember,
                detail: String::new(),
            },
            ErrorCode::NotMember,
        ),
        (
            ApiError::State {
                code: ErrorCode::WrongState,
                detail: String::new(),
            },
            ErrorCode::WrongState,
        ),
        (
            ApiError::Internal {
                detail: String::new(),
            },
            ErrorCode::Internal,
        ),
    ];
    for (error, code) in cases {
        assert_eq!(error.code(), code, "{error:?}");
    }
}

#[test]
fn api_error_message_is_human_text() {
    let error = ApiError::CapacityExceeded {
        resource: "sessions".into(),
        limit: 8,
        detail: "queue full".into(),
    };
    let text = error.to_string();
    assert!(text.contains("sessions"), "{text}");
    assert!(text.contains('8'), "{text}");
}

#[test]
fn every_code_has_a_checked_constructor_with_its_right_variant() {
    for code in ErrorCode::ALL {
        let error = ApiError::new(*code, "text");
        assert_eq!(error.code(), *code, "{code:?}");
        assert!(error.is_well_formed(), "{code:?}");
    }
    let peer = Some(EndpointId::from_bytes([1; 32]));
    let named = [
        (ApiError::invalid_input("f", "r"), ErrorCode::InvalidInput),
        (ApiError::invalid_id("k", "r"), ErrorCode::InvalidId),
        (ApiError::wrong_state("d"), ErrorCode::WrongState),
        (ApiError::unsupported("d"), ErrorCode::Unsupported),
        (ApiError::capacity_exceeded("q", 1, "d"), ErrorCode::CapacityExceeded),
        (ApiError::limit_reached("q", 1, "d"), ErrorCode::LimitReached),
        (ApiError::storage_failed("d"), ErrorCode::StorageFailed),
        (ApiError::storage_corrupt("d"), ErrorCode::StorageCorrupt),
        (ApiError::candidate_stale("d"), ErrorCode::CandidateStale),
        (ApiError::format_not_supported("d"), ErrorCode::FormatNotSupported),
        (ApiError::peer_unreachable(peer, "d"), ErrorCode::PeerUnreachable),
        (ApiError::timeout(peer, "d"), ErrorCode::Timeout),
        (ApiError::transport_failed(None, "d"), ErrorCode::TransportFailed),
        (ApiError::not_authorized("d"), ErrorCode::NotAuthorized),
        (ApiError::invitation_invalid("d"), ErrorCode::InvitationInvalid),
        (ApiError::invitation_expired("d"), ErrorCode::InvitationExpired),
        (ApiError::not_member("d"), ErrorCode::NotMember),
        (ApiError::epoch_mismatch("d"), ErrorCode::EpochMismatch),
        (ApiError::policy_mismatch("d"), ErrorCode::PolicyMismatch),
        (ApiError::internal("d"), ErrorCode::Internal),
    ];
    for (error, code) in named {
        assert_eq!(error.code(), code, "{error:?}");
        assert!(error.is_well_formed(), "{error:?}");
        assert_eq!(error.message(), if code == ErrorCode::InvalidInput || code == ErrorCode::InvalidId { "r" } else { "d" });
    }
}

#[test]
fn a_code_from_another_group_is_not_well_formed_and_does_not_deserialize() {
    let wrong = ApiError::Storage {
        code: ErrorCode::Timeout,
        detail: String::new(),
    };
    assert!(!wrong.is_well_formed());
    let value = serde_json::to_value(&wrong).unwrap();
    assert!(serde_json::from_value::<ApiError>(value).is_err());
    for (variant, code) in [
        ("transport", ErrorCode::NotMember),
        ("authorization", ErrorCode::StorageFailed),
        ("state", ErrorCode::Internal),
        ("storage", ErrorCode::WrongState),
    ] {
        let value = serde_json::json!({"error": variant, "code": code, "detail": ""});
        assert!(serde_json::from_value::<ApiError>(value).is_err(), "{variant}");
    }
    let good = serde_json::json!({"error": "state", "code": 600, "detail": "x"});
    assert_eq!(
        serde_json::from_value::<ApiError>(good).unwrap().code(),
        ErrorCode::EpochMismatch
    );
}
