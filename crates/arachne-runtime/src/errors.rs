//! The one place where failures from lower crates become [`ApiError`]
//! (ADR A1/A4, decision 3).
//!
//! Rules:
//!
//! - Runtime code makes its own errors at the source with a named
//!   constructor (`ApiError::wrong_state`, ...), never from message text.
//! - `arachne-security` and `arachne-delivery` still return `&'static str`.
//!   Their text goes through [`security`] and [`delivery`]. Each looks the
//!   exact text up in its table below. A text that is not in the table gets
//!   the code that the call site gives (the call site knows which operation
//!   failed). There is no substring matching.
//! - `arachne-node` and `arachne-routing` errors map from their enum variants
//!   ([`node`], [`routing`]). `arachne-store` errors are storage failures.
//! - The detail text keeps the lower crate's words, so the deprecated JSON
//!   dispatcher still returns the same text (see [`legacy_text`]).
//! - No secret goes into an error. The lower crates return fixed text, and
//!   runtime errors hold only fixed text, counts and public IDs.

use arachne_api::{ApiError, ErrorCode};

/// Security texts with their own code. Keyed on the exported constants where
/// `arachne-security` has them, so a changed text there cannot silently stop
/// matching. The literal rows are covered by tests that make the error
/// through a real call.
const SECURITY: &[(&str, ErrorCode)] = &[
    (arachne_security::INVITATION_DISABLED, ErrorCode::InvitationInvalid),
    (arachne_security::INVITATION_EXPIRED, ErrorCode::InvitationExpired),
    (arachne_security::INVITATION_APPROVAL_REQUIRED, ErrorCode::NotAuthorized),
    (
        arachne_security::INVITATION_AUTOMATIC_APPROVAL_REQUIRED,
        ErrorCode::NotAuthorized,
    ),
    (arachne_security::INVITATION_CONTROLS_FULL, ErrorCode::LimitReached),
    ("member already admitted", ErrorCode::NotAuthorized),
    ("invalid or disabled invitation request", ErrorCode::InvitationInvalid),
    ("invitation belongs to another workspace", ErrorCode::InvitationInvalid),
    ("checkpoint does not match invitation", ErrorCode::InvitationInvalid),
    ("invalid invitation format", ErrorCode::InvitationInvalid),
    ("invalid invitation size", ErrorCode::InvitationInvalid),
    ("current members only", ErrorCode::NotMember),
    ("direct recipient is not a current member", ErrorCode::NotMember),
    ("management target is not a current member", ErrorCode::NotMember),
    ("member is already an administrator", ErrorCode::WrongState),
    ("member is not an administrator", ErrorCode::NotAuthorized),
    ("object epoch ahead", ErrorCode::EpochMismatch),
    ("object epoch expired", ErrorCode::EpochMismatch),
];

/// Delivery texts with their own code.
const DELIVERY: &[(&str, ErrorCode)] = &[
    ("too many deferred delivery streams", ErrorCode::LimitReached),
    ("too many inbox recipients", ErrorCode::LimitReached),
    ("pending inbox full", ErrorCode::CapacityExceeded),
    ("pending inbox capacity exceeded", ErrorCode::CapacityExceeded),
    ("author pending quota exhausted", ErrorCode::CapacityExceeded),
    ("retained range capacity exceeded", ErrorCode::CapacityExceeded),
    ("retained current-view capacity exceeded", ErrorCode::CapacityExceeded),
    ("current-view selection capacity exceeded", ErrorCode::CapacityExceeded),
    ("direct recovery stream capacity exceeded", ErrorCode::CapacityExceeded),
    ("inbox epoch/workspace not current", ErrorCode::EpochMismatch),
    ("recovery coverage has wrong workspace or epoch", ErrorCode::EpochMismatch),
    ("current-view scope is not current", ErrorCode::EpochMismatch),
    ("current-view rollback", ErrorCode::CandidateStale),
    ("object author not current", ErrorCode::NotMember),
];

fn lookup(table: &[(&str, ErrorCode)], text: &str) -> Option<ErrorCode> {
    table
        .iter()
        .find(|(known, _)| *known == text)
        .map(|(_, code)| *code)
}

/// Map a security text. `fallback` is the code of the failed operation.
pub(crate) fn security(fallback: ErrorCode) -> impl Fn(&'static str) -> ApiError {
    move |text| ApiError::new(lookup(SECURITY, text).unwrap_or(fallback), text)
}

/// Map a delivery text. `fallback` is the code of the failed operation.
pub(crate) fn delivery(fallback: ErrorCode) -> impl Fn(&'static str) -> ApiError {
    move |text| ApiError::new(lookup(DELIVERY, text).unwrap_or(fallback), text)
}

/// Map a node error by its variant. The detail keeps the node's text.
pub(crate) fn node(error: arachne_node::Error) -> ApiError {
    use arachne_node::Error as E;
    let detail = error.to_string();
    match error {
        E::Routing(inner) => routing_with_detail(inner, detail),
        E::Transport(_) | E::InvalidFrame | E::Rejected => {
            ApiError::transport_failed(None, detail)
        }
        E::MissingPeer | E::ControlNotSent(_) => ApiError::peer_unreachable(None, detail),
        E::TooLarge => ApiError::invalid_input("payload", detail),
        E::Timeout(_) => ApiError::timeout(None, detail),
        E::Cancelled => ApiError::Cancelled,
        E::Backpressure => ApiError::capacity_exceeded("consumer queue", 0, detail),
        E::NotSubscribed => ApiError::wrong_state(detail),
    }
}

/// Map a routing error by its variant.
pub(crate) fn routing(error: arachne_routing::Error) -> ApiError {
    let detail = error.to_string();
    routing_with_detail(error, detail)
}

fn routing_with_detail(error: arachne_routing::Error, detail: String) -> ApiError {
    use arachne_routing::Error as E;
    match error {
        E::InvalidTopic => ApiError::invalid_input("topic", detail),
        E::LimitExceeded => ApiError::limit_reached("routing", 0, detail),
        E::UnknownWorkspace => ApiError::wrong_state(detail),
        E::WrongPolicyRevision => ApiError::policy_mismatch(detail),
        E::Denied => ApiError::not_authorized(detail),
    }
}

/// A native record store failure.
pub(crate) fn store(error: Box<dyn std::error::Error + Send + Sync>) -> ApiError {
    if error
        .downcast_ref::<arachne_store::FormatNotSupported>()
        .is_some()
    {
        return ApiError::format_not_supported(error.to_string());
    }
    ApiError::storage_failed(error.to_string())
}

/// A request or reply that did not decode.
pub(crate) fn decode(field: &str) -> impl Fn(serde_json::Error) -> ApiError + '_ {
    move |error| ApiError::invalid_input(field, error.to_string())
}

/// A value this runtime made that did not encode. Never expected.
pub(crate) fn encode(error: serde_json::Error) -> ApiError {
    ApiError::internal(error.to_string())
}

/// A background task that ended without a result (aborted or panicked).
pub(crate) fn task(detail: &'static str) -> impl Fn(tokio::task::JoinError) -> ApiError {
    move |_| ApiError::internal(detail)
}

pub(crate) fn closed() -> ApiError {
    ApiError::Closed
}

/// A handle that is not in the registry: never issued, or already closed.
pub(crate) fn unknown_handle() -> ApiError {
    ApiError::invalid_id("node handle", "invalid or closed node handle")
}

pub(crate) fn no_workspace() -> ApiError {
    ApiError::wrong_state("session has no workspace")
}

pub(crate) fn no_pending_join() -> ApiError {
    ApiError::wrong_state("session has no pending join")
}

pub(crate) fn poisoned<T>(what: &'static str) -> impl Fn(T) -> ApiError {
    move |_| ApiError::internal(what)
}

/// The text that the JSON dispatcher and the `String` free functions return.
/// It is the same text as before the error model (ADR step 2): the lower
/// crate's words or the runtime's own sentence, without a code prefix.
pub fn legacy_text(error: &ApiError) -> String {
    match error {
        ApiError::Closed => "node is closed".into(),
        ApiError::Cancelled => arachne_node::Error::Cancelled.to_string(),
        ApiError::DeadlineExceeded => "operation deadline exceeded; outcome may be partial".into(),
        other => other.message().to_owned(),
    }
}

/// `legacy_text` for `map_err` on the `String` free functions.
pub(crate) fn text(error: ApiError) -> String {
    legacy_text(&error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exported_security_constants_have_their_codes() {
        let map = security(ErrorCode::Internal);
        assert_eq!(
            map(arachne_security::INVITATION_DISABLED).code(),
            ErrorCode::InvitationInvalid
        );
        assert_eq!(
            map(arachne_security::INVITATION_EXPIRED).code(),
            ErrorCode::InvitationExpired
        );
        assert_eq!(
            map(arachne_security::INVITATION_CONTROLS_FULL).code(),
            ErrorCode::LimitReached
        );
        // Text keeps the security crate's words.
        assert_eq!(
            legacy_text(&map(arachne_security::INVITATION_DISABLED)),
            arachne_security::INVITATION_DISABLED
        );
    }

    #[test]
    fn unknown_texts_take_the_call_site_code_not_a_guess() {
        // "limit" and "invalid" in the text do not change the code.
        let error = security(ErrorCode::InvitationInvalid)("some limit is invalid");
        assert_eq!(error.code(), ErrorCode::InvitationInvalid);
        let error = delivery(ErrorCode::InvalidInput)("queue storage peer timeout");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
    }

    #[test]
    fn tables_have_unique_keys_and_well_formed_codes() {
        for table in [SECURITY, DELIVERY] {
            for (index, (text, code)) in table.iter().enumerate() {
                assert!(
                    table[..index].iter().all(|(other, _)| other != text),
                    "duplicate row {text}"
                );
                assert!(ApiError::new(*code, *text).is_well_formed());
            }
        }
    }

    /// A stranger refused at the handshake sees the node's `Transport`
    /// variant, whatever words the transport's reason uses. Mapped from the
    /// enum, not the text.
    #[test]
    fn node_errors_map_by_variant() {
        use arachne_node::Error as E;
        let cases = [
            (
                E::Transport("aborted by peer: connection limit for unknown endpoints".into()),
                ErrorCode::TransportFailed,
            ),
            (
                E::Transport("the cryptographic handshake failed: stranger queue full".into()),
                ErrorCode::TransportFailed,
            ),
            (E::Rejected, ErrorCode::TransportFailed),
            (E::MissingPeer, ErrorCode::PeerUnreachable),
            (E::ControlNotSent("connect"), ErrorCode::PeerUnreachable),
            (E::Timeout("presence response"), ErrorCode::Timeout),
            (E::Cancelled, ErrorCode::Cancelled),
            (E::Backpressure, ErrorCode::CapacityExceeded),
            (E::TooLarge, ErrorCode::InvalidInput),
            (E::InvalidFrame, ErrorCode::TransportFailed),
            (E::NotSubscribed, ErrorCode::WrongState),
            (
                E::Routing(arachne_routing::Error::Denied),
                ErrorCode::NotAuthorized,
            ),
            (
                E::Routing(arachne_routing::Error::WrongPolicyRevision),
                ErrorCode::PolicyMismatch,
            ),
        ];
        for (error, code) in cases {
            let text = error.to_string();
            let mapped = node(error);
            assert_eq!(mapped.code(), code, "{text}");
            assert_eq!(legacy_text(&mapped), text);
        }
    }

    #[test]
    fn legacy_text_of_unit_variants_is_the_old_text() {
        assert_eq!(legacy_text(&closed()), "node is closed");
        assert_eq!(
            legacy_text(&unknown_handle()),
            "invalid or closed node handle"
        );
        assert_eq!(
            legacy_text(&node(arachne_node::Error::Cancelled)),
            "operation cancelled because the local session closed"
        );
    }

    /// Ratchet on `Internal`: every site that gives `ErrorCode::Internal`
    /// (a named `internal` error or an `Internal` fallback for lower-crate
    /// text). The count may only go down. When you remove one, lower
    /// `CEILING` to the new count. Do not raise it: pick the right code at
    /// the source instead.
    #[test]
    fn internal_fallbacks_only_go_down() {
        const CEILING: usize = 88;
        fn count(dir: &std::path::Path) -> usize {
            let mut total = 0;
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    total += count(&path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&path).unwrap();
                    // Split so this test does not count itself.
                    total += text.matches(concat!("ApiError::", "internal(")).count()
                        + text.matches(concat!("(ErrorCode::", "Internal)")).count();
                }
            }
            total
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let sites = count(&src);
        assert!(
            sites <= CEILING,
            "{sites} Internal sites, ceiling {CEILING}: give the new error its real code"
        );
        assert!(
            sites == CEILING,
            "{sites} Internal sites: lower CEILING from {CEILING} to {sites}"
        );
    }
}
