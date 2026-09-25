//! The runtime's notice to its host that a step is ready. No data, no authority.
//! The waiter uses std primitives so a parked host thread never depends on the
//! session's tokio runtime staying alive. It holds no session or client lock,
//! so `close` and `wake` from another thread always reach a parked waiter.
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct State {
    pending: bool,
    /// `wake` calls not yet taken by a waiter.
    wakes: usize,
    closed: bool,
}

/// Why a wait returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Wake {
    /// Work may be ready (spurious is allowed).
    Work,
    /// `wake` was called; there may be no work.
    Woken,
    TimedOut,
    Closed,
}

#[derive(Default)]
pub(crate) struct WorkSignal {
    state: Mutex<State>,
    ready: Condvar,
}

impl WorkSignal {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    pub(crate) fn raise(&self) {
        self.state().pending = true;
        self.ready.notify_all();
    }

    /// Release one waiter without work (host shutdown or UI). Kept until a
    /// waiter takes it, like `raise`.
    pub(crate) fn wake(&self) {
        self.state().wakes += 1;
        self.ready.notify_all();
    }

    pub(crate) fn close(&self) {
        self.state().closed = true;
        self.ready.notify_all();
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.state().closed
    }

    /// Park until raised, woken, closed, or `timeout` (`None`: no timeout).
    /// Level-style: one raise covers any number of arrivals, because the host
    /// drains until empty before it waits again.
    pub(crate) fn wait_for(&self, timeout: Option<Duration>) -> Wake {
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        let mut state = self.state();
        loop {
            if state.closed {
                return Wake::Closed;
            }
            if state.pending {
                state.pending = false;
                return Wake::Work;
            }
            if state.wakes > 0 {
                state.wakes -= 1;
                return Wake::Woken;
            }
            state = match deadline {
                None => self
                    .ready
                    .wait(state)
                    .unwrap_or_else(|error| error.into_inner()),
                Some(deadline) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Wake::TimedOut;
                    }
                    self.ready
                        .wait_timeout(state, deadline - now)
                        .unwrap_or_else(|error| error.into_inner())
                        .0
                }
            };
        }
    }

    /// Park with no timeout. `true`: work may be ready (a bare `wake` counts;
    /// spurious `true` is allowed). `false`: closed.
    pub(crate) fn wait(&self) -> bool {
        self.wait_for(None) != Wake::Closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn raise_before_wait_is_kept_and_close_wins() {
        let signal = Arc::new(WorkSignal::default());
        signal.raise();
        assert!(signal.wait());
        let parked = Arc::clone(&signal);
        let waiter = std::thread::spawn(move || parked.wait());
        signal.close();
        assert!(!waiter.join().unwrap());
        assert!(!signal.wait());
    }

    #[test]
    fn a_timed_wait_returns_on_timeout_wake_and_close() {
        let signal = Arc::new(WorkSignal::default());
        let started = Instant::now();
        assert_eq!(signal.wait_for(Some(Duration::from_millis(50))), Wake::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(50));
        signal.wake();
        assert_eq!(signal.wait_for(Some(Duration::ZERO)), Wake::Woken);
        // A wake is taken once.
        assert_eq!(signal.wait_for(Some(Duration::ZERO)), Wake::TimedOut);
        let parked = Arc::clone(&signal);
        let waiter = std::thread::spawn(move || parked.wait_for(Some(Duration::from_secs(30))));
        std::thread::sleep(Duration::from_millis(50));
        let closing = Instant::now();
        signal.close();
        assert_eq!(waiter.join().unwrap(), Wake::Closed);
        assert!(closing.elapsed() < Duration::from_secs(2));
    }
}
