//! The runtime's notice to its host that a step is ready. No data, no authority.
//! The waiter uses std primitives so a parked host thread never depends on the
//! session's tokio runtime staying alive.
use std::sync::{Condvar, Mutex};

#[derive(Default)]
struct State {
    pending: bool,
    closed: bool,
}

#[derive(Default)]
pub(super) struct WorkSignal {
    state: Mutex<State>,
    ready: Condvar,
}

impl WorkSignal {
    pub(super) fn raise(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.pending = true;
        self.ready.notify_all();
    }

    pub(super) fn close(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.closed = true;
        self.ready.notify_all();
    }

    /// Park until raised or closed. Level-style: one raise covers any number of
    /// arrivals, because the host drains until empty before it waits again.
    pub(super) fn wait(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        while !state.pending && !state.closed {
            state = self
                .ready
                .wait(state)
                .unwrap_or_else(|error| error.into_inner());
        }
        state.pending = false;
        !state.closed
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
}
