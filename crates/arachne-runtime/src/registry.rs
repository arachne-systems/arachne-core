//! The session registry and session lifecycle: create (bind) an endpoint,
//! look up a live session, describe, cancel, park, and close it. Each
//! session belongs to a [`Context`], which owns the limits and the runtime.
//!
//! The typed functions return [`ApiError`]; the public `String` functions keep
//! the old text through [`errors::text`].

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::Duration,
};

use arachne_api::ApiError;
use arachne_node::{NetworkProfile, Node, NodeOptions, RelayOptions};
use serde_json::{Value, json};
use tokio::sync::watch;

use crate::context::Context;
use crate::errors;
use crate::session::activity_value;
use crate::{Session, TransportSummary, committed_view, presence, resources, work_signal};

pub(crate) type SharedSession = Arc<Mutex<Option<Session>>>;

/// One live session and the handles that stay outside its mutex, so a
/// parked host never blocks `execute`.
pub(crate) struct Entry {
    pub(crate) context: Arc<Context>,
    pub(crate) shared: SharedSession,
    pub(crate) signal: Arc<work_signal::WorkSignal>,
    pub(crate) cancellation: watch::Sender<bool>,
    pub(crate) transport: TransportSummary,
    /// Counts deadline timers, so a late timer never cancels a later op.
    pub(crate) generation: Arc<Mutex<u64>>,
    /// Per-op deadline of this session (`None`: only each wait's own limit).
    pub(crate) deadline: Mutex<Option<Duration>>,
}

impl Entry {
    pub(crate) fn deadline(&self) -> Option<Duration> {
        *self
            .deadline
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    pub(crate) fn set_deadline(&self, deadline: Option<Duration>) {
        *self
            .deadline
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = deadline;
    }

    /// Start a deadline for one op: at `deadline` it interrupts the op's
    /// outbound control exchanges. `DeadlineTimer::finish` ends it.
    pub(crate) fn arm_deadline(self: Arc<Self>, deadline: Duration) -> DeadlineTimer {
        let token = {
            let mut generation = self
                .generation
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            *generation += 1;
            *generation
        };
        let fired = Arc::new(AtomicBool::new(false));
        let generation = Arc::clone(&self.generation);
        let cancellation = self.cancellation.clone();
        let fire = Arc::clone(&fired);
        let task = self.context.handle().spawn(async move {
            tokio::time::sleep(deadline).await;
            let current = generation.lock().unwrap_or_else(|error| error.into_inner());
            if *current == token {
                fire.store(true, Ordering::Release);
                cancellation.send_replace(true);
            }
        });
        DeadlineTimer {
            entry: self,
            fired,
            task,
        }
    }
}

/// One op's deadline. Its task ends at `finish` or at the deadline.
pub(crate) struct DeadlineTimer {
    entry: Arc<Entry>,
    fired: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl DeadlineTimer {
    /// End the deadline. `true`: it fired while the op ran. The cancel it
    /// sent is cleared unless the session is closing.
    pub(crate) fn finish(self) -> bool {
        // Under the generation lock, so a timer cannot fire after this.
        *self
            .entry
            .generation
            .lock()
            .unwrap_or_else(|error| error.into_inner()) += 1;
        self.task.abort();
        let fired = self.fired.load(Ordering::Acquire);
        if fired && !self.entry.signal.is_closed() {
            crate::ops::clear_cancel(&self.entry.cancellation);
        }
        fired
    }
}

/// Handle index over all contexts. It has no cap and no budget; each
/// context owns its own limits. Data operations take only their session
/// lock, and a bind never holds this lock.
static DIRECTORY: std::sync::LazyLock<Mutex<BTreeMap<i64, Arc<Entry>>>> =
    std::sync::LazyLock::new(|| Mutex::new(BTreeMap::new()));
/// Handles are unique in the process and never reused.
static NEXT_HANDLE: AtomicI64 = AtomicI64::new(1);

fn directory() -> Result<std::sync::MutexGuard<'static, BTreeMap<i64, Arc<Entry>>>, ApiError> {
    DIRECTORY
        .lock()
        .map_err(errors::poisoned("node registry unavailable"))
}

pub(crate) fn entry(handle: i64) -> Result<Arc<Entry>, ApiError> {
    directory()?
        .get(&handle)
        .cloned()
        .ok_or_else(errors::unknown_handle)
}

fn default_context() -> Result<Arc<Context>, ApiError> {
    Context::default_shared()
}

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
pub fn create_with_options(secret: Option<&[u8; 32]>, options: NodeOptions) -> Result<i64, String> {
    create_endpoint(secret, options)
}

pub(crate) fn create_endpoint(
    secret: Option<&[u8; 32]>,
    options: NodeOptions,
) -> Result<i64, String> {
    default_context()
        .and_then(|context| open(&context, secret, options, None))
        .map_err(errors::text)
}

/// Bind an endpoint in `context` and register its session. Returns the new handle.
pub(crate) fn open(
    context: &Arc<Context>,
    secret: Option<&[u8; 32]>,
    options: NodeOptions,
    deadline: Option<Duration>,
) -> Result<i64, ApiError> {
    let bind_deadline = deadline.map(|deadline| std::time::Instant::now() + deadline);
    let profile = options.profile;
    let transport = TransportSummary {
        public_lookup: options.public_lookup,
        operator_relay: options.relay.is_some(),
        timeouts: options.timeouts,
    };
    // Hold the table only to reserve; a bind can take seconds.
    let reservation = context.reserve()?;
    let handle = NEXT_HANDLE
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
            (next < i64::MAX).then_some(next + 1)
        })
        .map_err(|_| ApiError::limit_reached("sessions", i64::MAX as u64, "node limit reached"))?;
    let runtime = context.handle().clone();
    let connection_budget = context.budget();
    #[cfg(test)]
    tests::pause_bind(secret);
    let (node, receiver) = runtime
        .block_on(async {
            tokio::time::timeout(crate::deadline::cap(bind_deadline, BIND_WAIT), async {
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
        .map_err(|_| {
            if crate::deadline::expired(bind_deadline) {
                ApiError::DeadlineExceeded
            } else {
                ApiError::timeout(None, "node startup timed out")
            }
        })?
        .map_err(errors::node)?;
    node.set_timer_scale(context.timer_scale());
    let signal = Arc::new(work_signal::WorkSignal::default());
    let committed = committed_view::Published::new(Some(Arc::clone(&signal)));
    node.set_inquiry_responder(committed.responder());
    let arrivals = node.control_signal();
    let forward = Arc::clone(&signal);
    // It only forwards and holds no session state. The runtime is shared,
    // so the session aborts it at shutdown.
    let forwarder = runtime.spawn(async move {
        loop {
            arrivals.notified().await;
            forward.raise();
        }
    });
    let cancellation = node.control_cancellation();
    let presence = presence::Presence::new()?;
    let mut session = Session::new(node, receiver, Arc::clone(context), committed, presence);
    session.tasks.push(forwarder.abort_handle());
    let entry = Arc::new(Entry {
        context: Arc::clone(context),
        shared: Arc::new(Mutex::new(Some(session))),
        signal,
        cancellation,
        transport,
        generation: Arc::default(),
        deadline: Mutex::new(deadline),
    });
    directory()?.insert(handle, Arc::clone(&entry));
    reservation.commit(handle);
    // After the commit: either `Context::suspend` sees this session or this
    // check sees the flag, so a session opened during a suspend is covered.
    if context.is_suspended()
        && let Ok(mut guard) = entry.shared.lock()
        && let Some(session) = guard.as_mut()
    {
        runtime.block_on(session.node.suspend());
    }
    Ok(handle)
}

pub(crate) fn session(handle: i64) -> Result<SharedSession, ApiError> {
    Ok(Arc::clone(&entry(handle)?.shared))
}

/// Return endpoint metadata for a live session.
pub fn describe(handle: i64) -> Result<String, String> {
    endpoint_value(handle)
        .map(|value| value.to_string())
        .map_err(errors::text)
}

/// Endpoint metadata for a live session, as `EndpointInfo` JSON.
pub(crate) fn endpoint_value(handle: i64) -> Result<Value, ApiError> {
    let entry = entry(handle)?;
    let transport = entry.transport;
    let guard = entry
        .shared
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
    let entry = directory()?
        .remove(&handle)
        .ok_or_else(errors::unknown_handle)?;
    entry.context.remove(handle);
    entry.cancellation.send_replace(true);
    entry.signal.close();
    // A lookup racing with close sees either the prior admitted operation or None.
    let session = entry
        .shared
        .lock()
        .map_err(errors::poisoned("node session unavailable"))?
        .take();
    // A removed membership has already shut down its owner. Release its registry
    // handle normally; a second close still rejects the missing handle.
    session.map(shutdown_session).unwrap_or(Ok(()))
}

/// Interrupt the outbound control exchanges of the op in flight. Not
/// sticky (ADR step 4): the latch clears when that op ends. The owner still
/// calls `close` to release the endpoint.
pub fn cancel(handle: i64) -> Result<(), String> {
    cancel_session(handle).map_err(errors::text)
}

/// `cancel`, typed.
pub(crate) fn cancel_session(handle: i64) -> Result<(), ApiError> {
    entry(handle)?.cancellation.send_replace(true);
    Ok(())
}

/// Park up to `timeout_ms` for work (the SDK form of `wait_for_work`, ADR
/// step 4), without holding the session lock. `Ok(true)`: work may be ready.
/// `Ok(false)`: the timeout passed, `wake` was called, or the session closed.
pub fn wait_for_work_timeout(handle: i64, timeout_ms: u64) -> Result<bool, String> {
    wait_session_for(handle, Some(Duration::from_millis(timeout_ms))).map_err(errors::text)
}

/// Release one waiter of this session without work (host shutdown or UI).
pub fn wake(handle: i64) -> Result<(), String> {
    wake_session(handle).map_err(errors::text)
}

/// The next event of this session as JSON (`{"kind": ...}`), or `None`
/// when `timeout_ms` passed, `wake` was called, or the session closed while
/// it waited.
pub fn next_event(handle: i64, timeout_ms: u64) -> Result<Option<String>, String> {
    let event = crate::events::next(handle, Some(Duration::from_millis(timeout_ms)))
        .map_err(errors::text)?;
    event
        .map(|event| serde_json::to_string(&event).map_err(|error| error.to_string()))
        .transpose()
}

/// Create an endpoint session in the default context whose blocking ops
/// (and this bind) end at `deadline_ms` with `DeadlineExceeded` (the SDK
/// form of `TransportOptions::deadline`). 0: no deadline.
pub fn create_with_deadline(
    secret: Option<&[u8; 32]>,
    options: NodeOptions,
    deadline_ms: u64,
) -> Result<i64, String> {
    let deadline = (deadline_ms != 0).then(|| Duration::from_millis(deadline_ms));
    default_context()
        .and_then(|context| open(&context, secret, options, deadline))
        .map_err(errors::text)
}

/// Give each later blocking op of this session a deadline of
/// `deadline_ms` (0: none). At the deadline the op fails with
/// `DeadlineExceeded` (code 3) and the session stays usable.
pub fn set_deadline(handle: i64, deadline_ms: u64) -> Result<(), String> {
    entry(handle)
        .map(|entry| {
            entry.set_deadline((deadline_ms != 0).then(|| Duration::from_millis(deadline_ms)))
        })
        .map_err(errors::text)
}

/// Suspend the background work of every session of the default context
/// (Android host in the background). See `Context::suspend`.
pub fn suspend() -> Result<(), String> {
    default_context()
        .and_then(|context| context.suspend())
        .map_err(errors::text)
}

/// Restart what `suspend` stopped. See `Context::resume`.
pub fn resume() -> Result<(), String> {
    default_context()
        .and_then(|context| context.resume())
        .map_err(errors::text)
}

pub(crate) fn wait_session_for(handle: i64, timeout: Option<Duration>) -> Result<bool, ApiError> {
    let signal = Arc::clone(&entry(handle)?.signal);
    Ok(signal.wait_for(timeout) == work_signal::Wake::Work)
}

pub(crate) fn wake_session(handle: i64) -> Result<(), ApiError> {
    entry(handle)?.signal.wake();
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
    let signal = Arc::clone(&entry(handle)?.signal);
    Ok(signal.wait())
}

/// The longest an endpoint bind waits (a relay-only bind waits for its relay).
const BIND_WAIT: Duration = Duration::from_secs(10);

/// Time `shutdown_session` allows for local teardown after the peer drain.
const LOCAL_TEARDOWN: Duration = Duration::from_secs(2);

pub(crate) fn shutdown_session(mut session: Session) -> Result<(), ApiError> {
    session.overlay_paths.release_all();
    for task in session.tasks.drain(..) {
        task.abort();
    }
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
    // The runtime is shared by the context; the session's tasks end with
    // the node and with the aborts above, not with a runtime shutdown.
    let runtime = session.runtime.clone();
    let result =
        runtime.block_on(async { tokio::time::timeout(deadline, session.node.close()).await });
    result.map_err(|_| ApiError::timeout(None, "node shutdown timed out"))
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
}
