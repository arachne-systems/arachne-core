//! Member self-update policy (ADR A2 section 7, B3c).
//!
//! A member commits its own update path right after it adopts a Welcome
//! (while its leaf still comes from its KeyPackage), then every 24 hours or
//! every 10,000 objects it sent. Each member that never self-updated adds
//! about 82 bytes to every management commit, so this keeps registrations and
//! Removes small in large workspaces. The policy is local: a rate is never a
//! validity rule, because a rule that differs between nodes causes forks.
//!
//! A member saves and adopts its update before it announces the new head.
//! Verified fork choice resolves a race with another authorized commit.
use std::time::{Duration, Instant};

/// Self-update at least this often.
pub(crate) const SELF_UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Self-update after this many sent objects.
pub(crate) const SELF_UPDATE_OBJECTS: u64 = 10_000;

/// When this member self-updates next. The clock and the object counter are
/// inputs, so tests control them.
#[derive(Clone, Debug)]
pub(crate) struct SelfUpdatePolicy {
    /// The last own self-update, or when this session started.
    last: Instant,
    /// Objects sent since `last`.
    sent: u64,
}

impl SelfUpdatePolicy {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            last: now,
            sent: 0,
        }
    }

    /// Count objects this member sent.
    pub(crate) fn record_sent(&mut self, objects: u64) {
        self.sent = self.sent.saturating_add(objects);
    }

    /// Whether a self-update is due. `needs_self_update` is true while this
    /// member's leaf still comes from its KeyPackage (right after a Welcome).
    pub(crate) fn due(&self, now: Instant, needs_self_update: bool) -> bool {
        needs_self_update
            || self.sent >= SELF_UPDATE_OBJECTS
            || now.saturating_duration_since(self.last) >= SELF_UPDATE_INTERVAL
    }

    /// This member's self-update was adopted.
    pub(crate) fn updated(&mut self, now: Instant) {
        self.last = now;
        self.sent = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_self_update_is_due_after_a_welcome_a_day_or_ten_thousand_objects() {
        let start = Instant::now();
        let mut policy = SelfUpdatePolicy::new(start);
        // A leaf from a KeyPackage (a Welcome just adopted): due at once.
        assert!(policy.due(start, true));
        assert!(!policy.due(start, false));
        // Not before 24 hours.
        assert!(!policy.due(start + SELF_UPDATE_INTERVAL - Duration::from_secs(1), false));
        assert!(policy.due(start + SELF_UPDATE_INTERVAL, false));
        // Or 10,000 sent objects, counted in any steps.
        policy.record_sent(SELF_UPDATE_OBJECTS - 1);
        assert!(!policy.due(start, false));
        policy.record_sent(1);
        assert!(policy.due(start, false));
        // An adopted self-update resets both.
        let later = start + Duration::from_secs(5);
        policy.updated(later);
        assert!(!policy.due(later, false));
        assert!(!policy.due(later + SELF_UPDATE_INTERVAL - Duration::from_secs(1), false));
        assert!(policy.due(later + SELF_UPDATE_INTERVAL, false));
    }

}
