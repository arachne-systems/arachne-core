//! The owned runtime context (ADR A1/A4 step 3). A `Context` holds what was
//! process-wide before: the limits, the connection budget, the overlay path
//! budget, one shared Tokio runtime, and its session table. Two contexts in
//! one process share nothing, so tests make their own and run in parallel.
//!
//! The handle-based entry points (`create`, `execute`, `close`, ...) use a
//! lazy default context, [`Context::default_shared`]. Session handles are
//! unique in the process, so `execute(handle)` finds the session of any
//! context through a small handle index (no caps and no budget in it).

use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use arachne_api::{ApiError, Limits};
use arachne_node::{ConnectionBudget, NodeOptions};
use tokio::runtime::{Handle, Runtime, RuntimeFlavor};

use crate::{client, errors, registry};

/// Where a context runs its async work.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum RuntimeConfig {
    /// One multi-thread runtime that the context owns, for all its sessions.
    Owned { workers: usize },
    /// A multi-thread runtime of the host (Rust hosts only). The host keeps
    /// it running while the context has sessions.
    Handle(Handle),
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        let workers = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(2)
            .clamp(2, 4);
        Self::Owned { workers }
    }
}

/// Configuration of one [`Context`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct ContextConfig {
    pub limits: Limits,
    pub runtime: RuntimeConfig,
}

impl ContextConfig {
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    pub fn with_runtime(mut self, runtime: RuntimeConfig) -> Self {
        self.runtime = runtime;
        self
    }
}

/// Owns the sessions of one host and everything they share.
pub struct Context {
    limits: Limits,
    // Held only to keep an owned runtime alive; `Drop` shuts it down.
    owned: Mutex<Option<Runtime>>,
    handle: Handle,
    budget: ConnectionBudget,
    overlay: Arc<OverlayBudget>,
    table: Mutex<Table>,
}

#[derive(Default)]
struct Table {
    live: BTreeSet<i64>,
    // Slots of startups that bind outside the lock; they count toward the cap.
    reserved: usize,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Context")
            .field("limits", &self.limits)
            .field("sessions", &self.session_count())
            .finish_non_exhaustive()
    }
}

static DEFAULT: OnceLock<Result<Arc<Context>, ApiError>> = OnceLock::new();

impl Context {
    pub fn new(config: ContextConfig) -> Result<Arc<Self>, ApiError> {
        let (owned, handle) = match config.runtime {
            RuntimeConfig::Owned { workers } => {
                if workers == 0 {
                    return Err(ApiError::invalid_input("workers", "must be at least 1"));
                }
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(workers)
                    .thread_name("arachne-runtime")
                    .enable_all()
                    .build()
                    .map_err(|error| ApiError::internal(error.to_string()))?;
                let handle = runtime.handle().clone();
                (Some(runtime), handle)
            }
            RuntimeConfig::Handle(handle) => {
                // Blocking calls run futures with `Handle::block_on`; only a
                // multi-thread runtime drives I/O and timers on its own workers.
                if handle.runtime_flavor() != RuntimeFlavor::MultiThread {
                    return Err(ApiError::invalid_input(
                        "runtime",
                        "the host runtime must be multi-thread",
                    ));
                }
                (None, handle)
            }
        };
        Ok(Arc::new(Self {
            limits: config.limits,
            owned: Mutex::new(owned),
            handle,
            budget: ConnectionBudget::default(),
            overlay: Arc::new(OverlayBudget {
                used: AtomicUsize::new(0),
                max: config.limits.max_overlay_paths as usize,
            }),
            table: Mutex::new(Table::default()),
        }))
    }

    /// The lazy process default, for the handle API and foreign bindings.
    pub fn default_shared() -> Result<Arc<Self>, ApiError> {
        DEFAULT
            .get_or_init(|| Self::new(ContextConfig::default()))
            .clone()
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Open a typed client in this context.
    pub fn open(self: &Arc<Self>, config: client::ClientConfig) -> client::Result<client::Client> {
        client::Client::open_in(self, config)
    }

    /// Bind an endpoint in this context and return its session handle, for
    /// hosts that use the handle API (`execute`, `close`).
    pub fn create_with_options(
        self: &Arc<Self>,
        secret: Option<&[u8; 32]>,
        options: NodeOptions,
    ) -> Result<i64, ApiError> {
        registry::open(self, secret, options)
    }

    /// Live sessions of this context.
    pub fn session_count(&self) -> usize {
        self.table.lock().map(|table| table.live.len()).unwrap_or(0)
    }

    /// Tasks alive on this context's runtime (test and diagnostics hook).
    #[doc(hidden)]
    pub fn alive_tasks(&self) -> usize {
        self.handle.metrics().num_alive_tasks()
    }

    pub(crate) fn handle(&self) -> &Handle {
        &self.handle
    }

    pub(crate) fn budget(&self) -> ConnectionBudget {
        self.budget.clone()
    }

    pub(crate) fn overlay_paths(&self) -> OverlayPaths {
        OverlayPaths {
            budget: Arc::clone(&self.overlay),
            held: 0,
        }
    }

    /// Claim a session slot for a startup that binds outside the lock.
    pub(crate) fn reserve(&self) -> Result<Reservation<'_>, ApiError> {
        let mut table = self
            .table
            .lock()
            .map_err(errors::poisoned("node registry unavailable"))?;
        let max = self.limits.max_sessions as usize;
        if table.live.len() + table.reserved >= max {
            return Err(ApiError::limit_reached(
                "sessions",
                max as u64,
                "node limit reached",
            ));
        }
        table.reserved += 1;
        Ok(Reservation {
            context: self,
            armed: true,
        })
    }

    pub(crate) fn remove(&self, handle: i64) {
        if let Ok(mut table) = self.table.lock() {
            table.live.remove(&handle);
        }
    }

    #[cfg(test)]
    pub(crate) fn for_tests() -> Arc<Self> {
        Self::new(ContextConfig {
            runtime: RuntimeConfig::Owned { workers: 2 },
            ..ContextConfig::default()
        })
        .unwrap()
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // The last reference may go away on any thread, even inside async
        // code; `shutdown_background` never blocks and never panics there.
        let owned = self.owned.get_mut().ok().and_then(Option::take);
        if let Some(runtime) = owned {
            runtime.shutdown_background();
        }
    }
}

/// A session slot held while its endpoint binds. Dropped unarmed after the
/// session is in the table; dropped armed, it returns the slot.
pub(crate) struct Reservation<'a> {
    context: &'a Context,
    armed: bool,
}

impl Reservation<'_> {
    /// Move the slot to the live table under `handle`.
    pub(crate) fn commit(mut self, handle: i64) {
        if let Ok(mut table) = self.context.table.lock() {
            table.reserved -= 1;
            table.live.insert(handle);
            self.armed = false;
        }
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if self.armed
            && let Ok(mut table) = self.context.table.lock()
        {
            table.reserved -= 1;
        }
    }
}

/// The gossip overlay paths of all sessions of one context.
pub(crate) struct OverlayBudget {
    used: AtomicUsize,
    max: usize,
}

/// The overlay paths one session holds. Dropping it returns them.
pub(crate) struct OverlayPaths {
    budget: Arc<OverlayBudget>,
    held: usize,
}

impl OverlayPaths {
    pub(crate) fn held(&self) -> usize {
        self.held
    }

    /// Take `additional` more paths, or fail closed at the context limit.
    pub(crate) fn reserve(&mut self, additional: usize) -> Result<(), ApiError> {
        let max = self.budget.max;
        self.budget
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(additional)
                    .filter(|next| *next <= max)
            })
            .map_err(|_| {
                ApiError::limit_reached(
                    "device overlay paths",
                    max as u64,
                    "device overlay path limit reached",
                )
            })?;
        self.held += additional;
        Ok(())
    }

    pub(crate) fn release(&mut self, count: usize) {
        let count = count.min(self.held);
        if count != 0 {
            self.budget.used.fetch_sub(count, Ordering::AcqRel);
            self.held -= count;
        }
    }

    pub(crate) fn release_all(&mut self) {
        self.release(self.held);
    }
}

impl Drop for OverlayPaths {
    fn drop(&mut self) {
        self.release_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arachne_api::ErrorCode;

    fn small(max_sessions: u32, max_overlay_paths: u32) -> Arc<Context> {
        Context::new(ContextConfig {
            limits: Limits::default()
                .with_max_sessions(max_sessions)
                .with_max_overlay_paths(max_overlay_paths),
            runtime: RuntimeConfig::Owned { workers: 1 },
        })
        .unwrap()
    }

    #[test]
    fn startup_reservations_count_toward_the_session_cap() {
        let context = small(2, 10);
        let first = context.reserve().unwrap();
        let second = context.reserve().unwrap();
        let limit = context.reserve().err().unwrap();
        assert_eq!(limit.code(), ErrorCode::LimitReached);
        assert_eq!(errors::text(limit), "node limit reached");
        // A failed startup returns its slot.
        drop(first);
        second.commit(7);
        assert_eq!(context.session_count(), 1);
        context.reserve().unwrap().commit(8);
        assert!(context.reserve().is_err());
        context.remove(7);
        assert!(context.reserve().is_ok());
    }

    #[test]
    fn overlay_path_budget_fails_closed_and_releases() {
        let context = small(2, 24);
        let mut first = context.overlay_paths();
        let mut second = context.overlay_paths();
        first.reserve(24).unwrap();
        let limit = second.reserve(1).unwrap_err();
        assert_eq!(limit.code(), ErrorCode::LimitReached);
        assert_eq!(errors::text(limit), "device overlay path limit reached");
        first.release(19);
        second.reserve(5).unwrap();
        assert_eq!(first.held() + second.held(), 10);
        // A dropped session returns what it held.
        drop(first);
        second.reserve(19).unwrap();
        assert!(second.reserve(1).is_err());
    }

    #[test]
    fn contexts_do_not_share_the_overlay_budget() {
        let one = small(1, 5);
        let two = small(1, 5);
        let mut a = one.overlay_paths();
        let mut b = two.overlay_paths();
        a.reserve(5).unwrap();
        b.reserve(5).unwrap();
    }
}
