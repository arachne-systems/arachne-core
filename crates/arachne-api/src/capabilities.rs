use serde::{Deserialize, Serialize};

use crate::{API_VERSION, Network};

/// An optional runtime feature that a host can test for.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    ResourceTransfer,
}

/// What this build and client support (returned by `Client::capabilities`,
/// ADR step 6).
///
/// The ADR also lists `limits`. That field is added with `Context` and
/// `Limits` (step 3), because `Limits` is defined there.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Capabilities {
    pub api_version: u32,
    pub networks: Vec<Network>,
    pub features: Vec<Feature>,
}

impl Capabilities {
    /// Sets `api_version` to [`API_VERSION`].
    pub fn new(networks: Vec<Network>, features: Vec<Feature>) -> Self {
        Self {
            api_version: API_VERSION,
            networks,
            features,
        }
    }
}
