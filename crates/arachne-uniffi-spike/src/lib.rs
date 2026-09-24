//! Throwaway spike for ADR A1/A4 step 7. Not production.
//!
//! It proves that one Rust surface (the `arachne-api` types plus one exported
//! object) generates working Kotlin, Swift, Python and Go bindings. The
//! `SpikeClient` copies the lifecycle rules of ADR step 4: `next_event`
//! blocks with a timeout, `wake()` releases one waiter without an event, and
//! `close(&self)` from any thread releases all waiters. After `close`, calls
//! give `ApiError::Closed`.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use arachne_api::{API_VERSION, ApiError, Capabilities, EndpointId, Event, Feature, Network};

uniffi::setup_scaffolding!();

#[derive(Default)]
struct State {
    closed: bool,
    wake_pending: bool,
    queue: VecDeque<Event>,
}

/// The spike client. Foreign code holds it as an object (`Arc<SpikeClient>`).
#[derive(uniffi::Object)]
pub struct SpikeClient {
    network: Network,
    state: Mutex<State>,
    signal: Condvar,
}

impl SpikeClient {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn check_open(&self) -> Result<(), ApiError> {
        if self.lock().closed {
            Err(ApiError::Closed)
        } else {
            Ok(())
        }
    }
}

#[uniffi::export]
impl SpikeClient {
    /// Opens a client. `Network::Tor` gives `Unsupported` (code 103), as the
    /// ADR says for a build without the `tor` feature.
    #[uniffi::constructor]
    pub fn new(network: Network) -> Result<Self, ApiError> {
        if network == Network::Tor {
            return Err(ApiError::State {
                code: arachne_api::ErrorCode::Unsupported,
                detail: "tor is not in this build".into(),
            });
        }
        Ok(Self {
            network,
            state: Mutex::new(State::default()),
            signal: Condvar::new(),
        })
    }

    /// Parses a hex endpoint ID. A bad string gives `InvalidId` (code 101).
    pub fn parse_endpoint(&self, hex: String) -> Result<EndpointId, ApiError> {
        self.check_open()?;
        EndpointId::from_hex(&hex)
    }

    /// Takes a typed `EndpointId`. A bad foreign string fails in the UniFFI
    /// lift step (`custom_type!` `try_lift`), before this body runs.
    pub fn describe_peer(&self, peer: EndpointId) -> Result<String, ApiError> {
        self.check_open()?;
        Ok(format!("peer {peer} on {:?}", self.network))
    }

    /// A `#[non_exhaustive]` record built by its constructor.
    pub fn capabilities(&self) -> Capabilities {
        Capabilities::new(
            Network::ALL
                .iter()
                .copied()
                .filter(|n| *n != Network::Tor)
                .collect(),
            vec![Feature::ResourceTransfer],
        )
    }

    pub fn api_version(&self) -> u32 {
        API_VERSION
    }

    /// Queues an event, so tests can see a real `Event` value cross.
    pub fn push_event(&self, event: Event) -> Result<(), ApiError> {
        let mut state = self.lock();
        if state.closed {
            return Err(ApiError::Closed);
        }
        state.queue.push_back(event);
        drop(state);
        self.signal.notify_one();
        Ok(())
    }

    /// Blocks until an event, `wake()`, `close()` or the timeout.
    ///
    /// Returns `None` on timeout, on `wake()` and after `close()`. It holds
    /// no lock while it waits, so `close()` from another thread is not
    /// blocked.
    pub fn next_event(&self, timeout_ms: u64) -> Option<Event> {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let mut state = self.lock();
        loop {
            if state.closed {
                return None;
            }
            if let Some(event) = state.queue.pop_front() {
                return Some(event);
            }
            if state.wake_pending {
                state.wake_pending = false;
                return None;
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            state = self
                .signal
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .0;
        }
    }

    /// Releases one waiter without an event.
    pub fn wake(&self) {
        self.lock().wake_pending = true;
        self.signal.notify_one();
    }

    /// Idempotent. Releases all waiters. Later calls give `Closed` (code 1).
    pub fn close(&self) {
        self.lock().closed = true;
        self.signal.notify_all();
    }

    pub fn is_closed(&self) -> bool {
        self.lock().closed
    }
}

/// Rust-side checks. The same behavior is checked from each language by
/// the tests in `crates/arachne-uniffi-spike/tests-foreign/`.
#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use arachne_api::ErrorCode;

    use super::*;

    #[test]
    fn bad_hex_gives_code_101() {
        let client = SpikeClient::new(Network::Direct).unwrap();
        let err = client.parse_endpoint("zz".into()).unwrap_err();
        assert_eq!(err.code().as_u32(), 101);
        assert_eq!(err.code(), ErrorCode::InvalidId);
    }

    #[test]
    fn close_releases_a_parked_waiter() {
        let client = Arc::new(SpikeClient::new(Network::Lan).unwrap());
        let waiter = {
            let client = client.clone();
            thread::spawn(move || {
                let start = Instant::now();
                (client.next_event(30_000), start.elapsed())
            })
        };
        thread::sleep(Duration::from_millis(200));
        client.close();
        let (event, elapsed) = waiter.join().unwrap();
        assert_eq!(event, None);
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
        assert_eq!(
            client.parse_endpoint(String::new()).unwrap_err().code(),
            ErrorCode::Closed
        );
    }

    #[test]
    fn non_exhaustive_needs_a_wildcard_outside_the_crate() {
        // `Event` is `#[non_exhaustive]` in arachne-api, so this match needs
        // `_`. Removing it is a compile error (E0004).
        let name = match Event::Presence {
            Event::Presence => "presence",
            _ => "other",
        };
        assert_eq!(name, "presence");
    }
}
