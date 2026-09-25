//! The public contract of Arachne (ADR A1/A4).
//!
//! This crate is the single source of truth for public types: ID newtypes,
//! [`ApiError`] with stable [`ErrorCode`]s, [`Event`], [`Network`],
//! [`Capabilities`] and [`API_VERSION`]. It has no I/O and no async runtime.
//!
//! `arachne-runtime` returns [`ApiError`] from its typed operations (ADR
//! step 2). The per-op request and result structs stay in the runtime until
//! the JSON dispatcher is removed (step 9): the JSON wire carries IDs as byte
//! arrays, while the ID newtypes here serialize as hex.
//!
//! Compatibility: every public enum is `#[non_exhaustive]`. A new variant,
//! code or public field increments [`API_VERSION`]. Foreign bindings must keep
//! a default branch.
//!
//! TODO(ADR step 7): optional `uniffi` feature with `cfg_attr` derives and
//! `uniffi::setup_scaffolding!()`.

mod capabilities;
mod error;
mod event;
mod ids;
mod limits;
mod network;

pub use capabilities::{Capabilities, Feature};
pub use error::{ApiError, ErrorCode};
pub use event::Event;
pub use ids::{
    AttemptId, EndpointId, MAX_TOPIC_LEN, MemberId, PublicationId, RecordId, TopicName, WorkspaceId,
};
pub use limits::Limits;
pub use network::Network;

/// The version of the public contract. It increments for every change to a
/// public type, variant, error code or op. Before 1.0 there is no
/// compatibility promise; the SDK checks this value at load.
///
/// History: 1 = first contract (ADR step 1). 2 = `ApiError::LimitReached`
/// and a `detail` field on `ApiError::CapacityExceeded` (ADR step 2).
/// 3 = `Limits` (ADR step 3).
pub const API_VERSION: u32 = 3;
