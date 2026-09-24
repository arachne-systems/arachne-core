//! The public contract of Arachne (ADR A1/A4).
//!
//! This crate is the single source of truth for public types: ID newtypes,
//! [`ApiError`] with stable [`ErrorCode`]s, [`Event`], [`Network`],
//! [`Capabilities`] and [`API_VERSION`]. It has no I/O and no async runtime.
//!
//! Step 1 of the ADR migration adds this crate only. No other crate uses it
//! yet. Typed request and result structs arrive with the op extraction (step 2).
//!
//! Compatibility: every public enum is `#[non_exhaustive]`. A new variant,
//! code or public field increments [`API_VERSION`]. Foreign bindings must keep
//! a default branch.
//!
//! With the `uniffi` feature the public types derive UniFFI metadata (ADR
//! step 7). The feature is off by default, so core stays free of UniFFI.

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod capabilities;
mod error;
mod event;
mod ids;
mod network;

pub use capabilities::{Capabilities, Feature};
pub use error::{ApiError, ErrorCode};
pub use event::Event;
pub use ids::{
    AttemptId, EndpointId, MAX_TOPIC_LEN, MemberId, PublicationId, RecordId, TopicName, WorkspaceId,
};
pub use network::Network;

/// The version of the public contract. It increments for every change to a
/// public type, variant, error code or op. Before 1.0 there is no
/// compatibility promise; the SDK checks this value at load.
pub const API_VERSION: u32 = 1;
