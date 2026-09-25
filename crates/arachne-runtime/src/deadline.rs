//! Per-op deadlines (ADR step 4). A session has an optional deadline for
//! each blocking op, set by `Client::set_deadline`, `TransportOptions::deadline`
//! or the handle call `set_deadline`. `ops::run` arms it: at the deadline it
//! stops the op's control exchanges, and every other bounded wait inside
//! the op (policy install, gossip join during a send, the endpoint bind)
//! takes the smaller of its own limit and the time left.

use std::time::{Duration, Instant};

/// The smaller of `limit` and the time left before `deadline`.
pub(crate) fn cap(deadline: Option<Instant>, limit: Duration) -> Duration {
    deadline.map_or(limit, |deadline| {
        limit.min(deadline.saturating_duration_since(Instant::now()))
    })
}

/// A wait limited by `cap` ended: `DeadlineExceeded` when the op deadline
/// is what ended it, else the wait's own error.
pub(crate) fn expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wait_takes_the_smaller_of_its_limit_and_the_time_left() {
        let limit = Duration::from_secs(10);
        assert_eq!(cap(None, limit), limit);
        let soon = Instant::now() + Duration::from_millis(200);
        assert!(cap(Some(soon), limit) <= Duration::from_millis(200));
        let late = Instant::now() + Duration::from_secs(60);
        assert_eq!(cap(Some(late), limit), limit);
        let past = Instant::now() - Duration::from_millis(1);
        assert_eq!(cap(Some(past), limit), Duration::ZERO);
        assert!(expired(Some(past)));
        assert!(!expired(Some(late)));
        assert!(!expired(None));
    }

    #[test]
    fn a_bounded_wait_ends_at_the_op_deadline() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let deadline = Some(Instant::now() + Duration::from_millis(100));
        let started = Instant::now();
        let waited = runtime.block_on(async {
            tokio::time::timeout(
                cap(deadline, Duration::from_secs(10)),
                std::future::pending::<()>(),
            )
            .await
        });
        assert!(waited.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(expired(deadline));
    }
}
