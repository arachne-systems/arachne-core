//! The session registry and session lifecycle: create (bind) an endpoint,
//! look up a live session, describe, cancel, park, and close it. The
//! device-wide overlay path budget lives here too.
//!
//! The typed functions return [`ApiError`]; the public `String` functions keep
//! the old text through [`errors::text`].

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use arachne_api::{ApiError, ErrorCode};
use arachne_node::{ConnectionBudget, NetworkProfile, Node, NodeOptions, RelayOptions};
use serde_json::{Value, json};
use tokio::sync::watch;

use crate::errors;
use crate::session::activity_value;
use crate::{Session, TransportSummary, committed_view, presence, resources, work_signal};

pub(crate) struct Registry {
    pub(crate) next: i64,
    // Slots held by startups binding outside the lock; they count toward the cap.
    pub(crate) reserved: usize,
    pub(crate) sessions: BTreeMap<i64, SharedSession>,
    // Kept outside the session mutex: a parked host never blocks `execute`.
    pub(crate) signals: BTreeMap<i64, Arc<work_signal::WorkSignal>>,
    pub(crate) cancellations: BTreeMap<i64, watch::Sender<bool>>,
    pub(crate) transports: BTreeMap<i64, TransportSummary>,
    pub(crate) connection_budget: ConnectionBudget,
}

pub(crate) type SharedSession = Arc<Mutex<Option<Session>>>;

// ponytail: Startup reserves a slot under the registry lock and binds outside it; sessions
// are capped at eight; replace the registry
// with owned sessions when the secured capacity harness requires more. Data operations take only
// their session lock; a slow peer cannot hold the global registry during fanout.
pub(crate) static REGISTRY: std::sync::LazyLock<Mutex<Registry>> = std::sync::LazyLock::new(|| {
    Mutex::new(Registry {
        next: 1,
        reserved: 0,
        sessions: BTreeMap::new(),
        signals: BTreeMap::new(),
        cancellations: BTreeMap::new(),
        transports: BTreeMap::new(),
        connection_budget: ConnectionBudget::default(),
    })
});
pub(crate) const MAX_SESSIONS: usize = 8;

impl Registry {
    /// Claim a handle and a session slot for a startup that binds outside the lock.
    pub(crate) fn reserve(&mut self) -> Result<i64, ApiError> {
        if self.sessions.len() + self.reserved >= MAX_SESSIONS || self.next == i64::MAX {
            return Err(ApiError::limit_reached(
                "sessions",
                MAX_SESSIONS as u64,
                "node limit reached",
            ));
        }
        let handle = self.next;
        self.next += 1;
        self.reserved += 1;
        Ok(handle)
    }

    pub(crate) fn release(&mut self) {
        self.reserved -= 1;
    }
}

/// Returns an unused startup slot to the registry if startup fails.
pub(crate) struct Reservation {
    pub(crate) armed: bool,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.armed {
            if let Ok(mut registry) = REGISTRY.lock() {
                registry.release();
            }
        }
    }
}

pub(crate) const MAX_DEVICE_OVERLAY_PATHS: usize = 24;
pub(crate) static DEVICE_OVERLAY_PATHS: AtomicUsize = AtomicUsize::new(0);

/// Create an endpoint session. Credentials must be unique to this workspace-facing endpoint.
/// Blocking: invoke outside an async runtime. Call `close` to release its resources.
pub fn create(secret: Option<&[u8; 32]>) -> Result<i64, String> {
    create_endpoint(secret, NodeOptions::new(NetworkProfile::Direct))
}

/// Opt in to local endpoint advertisement and lookup. No public discovery or relay.
/// Uses the supplied workspace-scoped identity; discovery does not grant membership.
pub fn create_lan(secret: &[u8; 32]) -> Result<i64, String> {
    create_endpoint(Some(secret), NodeOptions::new(NetworkProfile::Lan))
}

/// Advertise a device-level nearby-invitation endpoint on the local network.
pub fn create_nearby(secret: &[u8; 32]) -> Result<i64, String> {
    create_endpoint(Some(secret), NodeOptions::new(NetworkProfile::Nearby))
}

/// Opt in to Iroh's public Pkarr lookup and relay network, with LAN discovery
/// retained as a local fallback. External services provide routes, not authority.
pub fn create_wan(secret: &[u8; 32]) -> Result<i64, String> {
    create_endpoint(Some(secret), NodeOptions::new(NetworkProfile::Wan))
}

/// Force Iroh relay paths for a diagnostic WAN check while preserving the
/// caller's network connection and workspace-scoped endpoint identity.
pub fn create_relay(secret: &[u8; 32]) -> Result<i64, String> {
    create_endpoint(Some(secret), NodeOptions::new(NetworkProfile::RelayOnly))
}

/// Use a caller-supplied relay map for controlled qualification or an
/// operator-managed relay deployment.
pub fn create_relay_with_options(secret: &[u8; 32], relay: RelayOptions) -> Result<i64, String> {
    create_endpoint(
        Some(secret),
        NodeOptions {
            relay: Some(relay),
            ..NodeOptions::new(NetworkProfile::RelayOnly)
        },
    )
}

/// Use public endpoint lookup without LAN discovery or saved address hints.
/// Direct Iroh paths remain enabled for a diagnostic WAN check.
pub fn create_wan_only(secret: &[u8; 32]) -> Result<i64, String> {
    create_endpoint(Some(secret), NodeOptions::new(NetworkProfile::WanOnly))
}

/// Create a Tor-only endpoint using the supplied stable endpoint identity.
#[cfg(feature = "tor")]
pub fn create_tor(secret: &[u8; 32]) -> Result<i64, String> {
    create_endpoint(Some(secret), NodeOptions::new(NetworkProfile::Tor))
}

/// Create an endpoint session with explicit node options: the profile, an
/// operator relay, n0 lookup on or off, and transport deadlines.
pub fn create_with_options(
    secret: Option<&[u8; 32]>,
    options: NodeOptions,
) -> Result<i64, String> {
    create_endpoint(secret, options)
}

pub(crate) fn create_endpoint(secret: Option<&[u8; 32]>, options: NodeOptions) -> Result<i64, String> {
    open(secret, options).map_err(errors::text)
}

/// Bind an endpoint and register its session. Returns the new handle.
pub(crate) fn open(secret: Option<&[u8; 32]>, options: NodeOptions) -> Result<i64, ApiError> {
    let profile = options.profile;
    let transport = TransportSummary {
        public_lookup: options.public_lookup,
        operator_relay: options.relay.is_some(),
        timeouts: options.timeouts,
    };
    // Hold the registry only to reserve; a bind can take seconds and every
    // other session's lookup needs this lock.
    let (handle, connection_budget) = {
        let mut registry = REGISTRY
            .lock()
            .map_err(errors::poisoned("node registry unavailable"))?;
        (registry.reserve()?, registry.connection_budget.clone())
    };
    let mut reservation = Reservation { armed: true };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| ApiError::internal(e.to_string()))?;
    #[cfg(test)]
    tests::pause_bind(secret);
    let (node, receiver) = runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(10), async {
                let address = ([0, 0, 0, 0], 0).into();
                let bound =
                    Node::bind_with_options(address, secret, options, connection_budget).await?;
                if matches!(profile, NetworkProfile::RelayOnly) {
                    bound.0.wait_online().await;
                }
                Ok::<_, arachne_node::Error>(bound)
            })
            .await
        })
        .map_err(|_| ApiError::timeout(None, "node startup timed out"))?
        .map_err(errors::node)?;
    let signal = Arc::new(work_signal::WorkSignal::default());
    let committed = committed_view::Published::new(Some(Arc::clone(&signal)));
    node.set_inquiry_responder(committed.responder());
    let arrivals = node.control_signal();
    let forward = Arc::clone(&signal);
    // Ends with the runtime at close. It only forwards; it holds no session state.
    runtime.spawn(async move {
        loop {
            arrivals.notified().await;
            forward.raise();
        }
    });
    let cancellation = node.control_cancellation();
    let presence = presence::Presence::new()?;
    let storage_key = secret
        .map(arachne_security::StorageKey::derive)
        .transpose()
        .map_err(errors::security(ErrorCode::InvalidInput))?;
    let shared = Arc::new(Mutex::new(Some(Session::new(
        node,
        receiver,
        runtime,
        committed,
        storage_key,
        presence,
    ))));
    let mut registry = REGISTRY
        .lock()
        .map_err(errors::poisoned("node registry unavailable"))?;
    registry.signals.insert(handle, signal);
    registry.cancellations.insert(handle, cancellation);
    registry.transports.insert(handle, transport);
    registry.sessions.insert(handle, shared);
    registry.release();
    reservation.armed = false;
    Ok(handle)
}

pub(crate) fn session(handle: i64) -> Result<SharedSession, ApiError> {
    REGISTRY
        .lock()
        .map_err(errors::poisoned("node registry unavailable"))?
        .sessions
        .get(&handle)
        .cloned()
        .ok_or_else(errors::unknown_handle)
}

/// Return endpoint metadata for a live session.
pub fn describe(handle: i64) -> Result<String, String> {
    endpoint_value(handle)
        .map(|value| value.to_string())
        .map_err(errors::text)
}

/// Endpoint metadata for a live session, as `EndpointInfo` JSON.
pub(crate) fn endpoint_value(handle: i64) -> Result<Value, ApiError> {
    let transport = REGISTRY
        .lock()
        .map_err(errors::poisoned("node registry unavailable"))?
        .transports
        .get(&handle)
        .copied()
        .ok_or_else(errors::unknown_handle)?;
    let shared = session(handle)?;
    let guard = shared
        .lock()
        .map_err(errors::poisoned("node session unavailable"))?;
    let session = guard.as_ref().ok_or_else(errors::closed)?;
    Ok(json!({
        "endpoint_key": session.node.id(),
        "bound_address": session.node.address().to_string(),
        "workspace_ready": session.workspace.is_some(),
        "activity": activity_value(session),
        "transport": {
            "public_lookup": transport.public_lookup,
            "operator_relay": transport.operator_relay,
            "peer_id_lookup": session.node.can_dial_by_peer_id(),
            "timeouts": {
                "operation": transport.timeouts.operation,
                "dial": transport.timeouts.dial,
                "gossip_join": transport.timeouts.gossip_join,
                "close_drain": transport.timeouts.close_drain,
            },
        },
    }))
}

/// Stop a session and release its transport, tasks and runtime.
pub fn close(handle: i64) -> Result<(), String> {
    close_session(handle).map_err(errors::text)
}

/// `close`, typed.
pub(crate) fn close_session(handle: i64) -> Result<(), ApiError> {
    let (shared, signal, cancellation, _) = {
        let mut registry = REGISTRY
            .lock()
            .map_err(errors::poisoned("node registry unavailable"))?;
        let shared = registry
            .sessions
            .remove(&handle)
            .ok_or_else(errors::unknown_handle)?;
        (
            shared,
            registry.signals.remove(&handle),
            registry.cancellations.remove(&handle),
            registry.transports.remove(&handle),
        )
    };
    if let Some(cancellation) = cancellation {
        cancellation.send_replace(true);
    }
    if let Some(signal) = signal {
        signal.close();
    }
    // A lookup racing with close sees either the prior admitted operation or None.
    let session = shared
        .lock()
        .map_err(errors::poisoned("node session unavailable"))?
        .take();
    // A removed membership has already shut down its owner. Release its registry
    // handle normally; a second close still rejects the missing handle.
    session.map(shutdown_session).unwrap_or(Ok(()))
}

/// Interrupt outbound control exchanges. The owner still calls `close` to
/// release the endpoint once its serial JNI request returns.
pub fn cancel(handle: i64) -> Result<(), String> {
    cancel_session(handle).map_err(errors::text)
}

/// `cancel`, typed.
pub(crate) fn cancel_session(handle: i64) -> Result<(), ApiError> {
    let cancellation = REGISTRY
        .lock()
        .map_err(errors::poisoned("node registry unavailable"))?
        .cancellations
        .get(&handle)
        .cloned()
        .ok_or_else(errors::unknown_handle)?;
    cancellation.send_replace(true);
    Ok(())
}

/// Park the calling thread until this session may have work, without holding the
/// session lock. `Ok(true)`: drain with `poll_admission` until it returns null,
/// then call again. `Ok(false)`: the session closed. Spurious `true` is allowed.
pub fn wait_for_work(handle: i64) -> Result<bool, String> {
    wait_session(handle).map_err(errors::text)
}

/// `wait_for_work`, typed.
pub(crate) fn wait_session(handle: i64) -> Result<bool, ApiError> {
    let signal = REGISTRY
        .lock()
        .map_err(errors::poisoned("node registry unavailable"))?
        .signals
        .get(&handle)
        .cloned()
        .ok_or_else(errors::unknown_handle)?;
    Ok(signal.wait())
}

/// Time `shutdown_session` allows for local teardown after the peer drain.
const LOCAL_TEARDOWN: Duration = Duration::from_secs(2);

pub(crate) fn shutdown_session(mut session: Session) -> Result<(), ApiError> {
    release_overlay_paths(&DEVICE_OVERLAY_PATHS, session.overlay_paths);
    session.overlay_paths = 0;
    session.presence.cancel();
    session.interests.cancel();
    drop(session.join.exchange.take());
    drop(session.join.checkpoint_exchange.take());
    drop(session.recovery.cutoff.take());
    drop(session.recovery.current_view.take());
    session.recovery.ready_current_view = None;
    drop(session.recovery.range.take());
    session.resources = resources::Jobs::default();
    // `Node::close` bounds its peer drain by the close drain deadline (5 s by
    // default, host-overridable). This guard only catches a stuck local
    // teardown, so it allows the drain plus a small margin for the local work.
    let deadline = session.node.timeouts().close_drain + LOCAL_TEARDOWN;
    let result = session
        .runtime
        .block_on(async { tokio::time::timeout(deadline, session.node.close()).await });
    session.runtime.shutdown_timeout(Duration::from_secs(2));
    result.map_err(|_| ApiError::timeout(None, "node shutdown timed out"))
}

pub(crate) fn reserve_overlay_paths(total: &AtomicUsize, additional: usize) -> bool {
    total
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current
                .checked_add(additional)
                .filter(|next| *next <= MAX_DEVICE_OVERLAY_PATHS)
        })
        .is_ok()
}

pub(crate) fn release_overlay_paths(total: &AtomicUsize, count: usize) {
    if count != 0 {
        let previous = total.fetch_sub(count, Ordering::AcqRel);
        debug_assert!(previous >= count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type BindPause = (
        [u8; 32],
        std::sync::mpsc::Sender<()>,
        std::sync::mpsc::Receiver<()>,
    );
    static BIND_PAUSE: Mutex<Option<BindPause>> = Mutex::new(None);

    /// Hold one endpoint bind (matched by secret) until the test releases it.
    pub(crate) fn pause_bind(secret: Option<&[u8; 32]>) {
        let pause = {
            let mut slot = BIND_PAUSE.lock().unwrap();
            match (&*slot, secret) {
                (Some((expected, _, _)), Some(secret)) if expected == secret => slot.take(),
                _ => None,
            }
        };
        if let Some((_, entered, release)) = pause {
            let _ = entered.send(());
            // Returns when the test sends or drops its release handle.
            let _ = release.recv();
        }
    }

    #[test]
    fn startup_reservations_count_toward_the_session_cap() {
        let mut registry = Registry {
            next: 1,
            reserved: 0,
            sessions: BTreeMap::new(),
            signals: BTreeMap::new(),
            cancellations: BTreeMap::new(),
            transports: BTreeMap::new(),
            connection_budget: ConnectionBudget::default(),
        };
        let handles: Vec<_> = (0..MAX_SESSIONS)
            .map(|_| registry.reserve().unwrap())
            .collect();
        assert_eq!(handles, (1..=MAX_SESSIONS as i64).collect::<Vec<_>>());
        let limit = registry.reserve().unwrap_err();
        assert_eq!(limit.code(), ErrorCode::LimitReached);
        assert_eq!(errors::text(limit), "node limit reached");
        // A failed startup returns its slot; handles are never reused.
        registry.release();
        assert_eq!(registry.reserve().unwrap(), MAX_SESSIONS as i64 + 1);
    }

    #[test]
    fn slow_endpoint_bind_does_not_block_other_sessions() {
        let other = create(Some(&[91; 32])).unwrap();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        *BIND_PAUSE.lock().unwrap() = Some(([92; 32], entered_tx, release_rx));
        let creator = std::thread::spawn(|| create(Some(&[92; 32])));
        let entered = entered_rx.recv_timeout(Duration::from_secs(30));
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let probe = std::thread::spawn(move || {
            let _ = done_tx.send(describe(other).and_then(|_| cancel(other)));
        });
        // The timeout bounds only the failing case; an unblocked probe returns at once.
        let probed = done_rx.recv_timeout(Duration::from_secs(5));
        // Release the paused bind before any assertion so a failure cannot
        // leave the registry locked for later tests.
        drop(release_tx);
        let created = creator.join().unwrap();
        probe.join().unwrap();
        entered.expect("paused bind did not start");
        let probed = probed.expect("another session waited on a slow endpoint bind");
        probed.unwrap();
        close(created.unwrap()).unwrap();
        close(other).unwrap();
    }

    #[test]
    fn overlay_path_budget_fails_closed_and_releases() {
        let total = AtomicUsize::new(0);
        assert!(reserve_overlay_paths(&total, MAX_DEVICE_OVERLAY_PATHS));
        assert!(!reserve_overlay_paths(&total, 1));
        release_overlay_paths(&total, MAX_DEVICE_OVERLAY_PATHS);
        assert_eq!(total.load(Ordering::Acquire), 0);
        assert!(reserve_overlay_paths(&total, 5));
        assert_eq!(total.load(Ordering::Acquire), 5);
    }
}
