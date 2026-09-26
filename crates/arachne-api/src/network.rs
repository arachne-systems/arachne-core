use serde::{Deserialize, Serialize};

/// A network mode for a client.
///
/// `Tor` always exists, so generated bindings are the same for every build.
/// When the runtime is built without Tor, opening a client with `Tor` gives
/// `ErrorCode::Unsupported` and `Capabilities::networks` does not list it.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum Network {
    Direct,
    Lan,
    Nearby,
    Wan,
    RelayOnly,
    WanOnly,
    Tor,
}

impl Network {
    /// Every network mode.
    pub const ALL: &'static [Network] = &[
        Self::Direct,
        Self::Lan,
        Self::Nearby,
        Self::Wan,
        Self::RelayOnly,
        Self::WanOnly,
        Self::Tor,
    ];
}
