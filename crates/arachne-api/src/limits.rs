use serde::{Deserialize, Serialize};

/// Resource limits of one runtime `Context` (ADR step 3). Every session of
/// the context counts toward them; two contexts never share them.
///
/// The defaults suit a desktop host and parallel tests. A phone host sets
/// lower values, for example `Limits::default().with_max_sessions(8)`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Live sessions (endpoints). Sessions that are still binding count too.
    pub max_sessions: u32,
    /// Gossip overlay paths over all sessions. One workspace uses at most 5.
    pub max_overlay_paths: u32,
}

impl Limits {
    /// Default session cap. It was a fixed 8 before the `Context`.
    pub const DEFAULT_MAX_SESSIONS: u32 = 64;
    /// Five overlay paths for each default session.
    pub const DEFAULT_MAX_OVERLAY_PATHS: u32 = Self::DEFAULT_MAX_SESSIONS * 5;

    pub fn with_max_sessions(mut self, value: u32) -> Self {
        self.max_sessions = value;
        self
    }

    pub fn with_max_overlay_paths(mut self, value: u32) -> Self {
        self.max_overlay_paths = value;
        self
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_sessions: Self::DEFAULT_MAX_SESSIONS,
            max_overlay_paths: Self::DEFAULT_MAX_OVERLAY_PATHS,
        }
    }
}

/// How often background work runs (ADR step 4). `Low` is for an Android
/// host in the background: longer presence and interest intervals.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerProfile {
    #[default]
    Normal,
    Low,
}
