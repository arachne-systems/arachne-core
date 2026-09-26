use serde::{Deserialize, Serialize};

use crate::{API_VERSION, Limits, Network};

/// An optional runtime feature that a host can test for.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum Feature {
    ResourceTransfer,
}

/// What this build and client support (returned by `Client::capabilities`,
/// ADR step 6).
///
/// Limits belong to the client's runtime context.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Capabilities {
    pub api_version: u32,
    pub networks: Vec<Network>,
    pub features: Vec<Feature>,
    pub limits: Limits,
}

impl Capabilities {
    /// Sets `api_version` to [`API_VERSION`].
    pub fn new(networks: Vec<Network>, features: Vec<Feature>, limits: Limits) -> Self {
        Self {
            api_version: API_VERSION,
            networks,
            features,
            limits,
        }
    }
}
