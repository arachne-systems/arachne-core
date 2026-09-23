//! Bounded host-handled request/reply over authenticated Iroh transport.
//! Transport identity is not workspace authorization; the host validates payloads.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::oneshot;

pub(super) const ALPN: &[u8] = b"data-fabric/control/1";
// Durable host control includes queueing and persistence; data/dial budgets stay short.
pub(super) const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REQUEST: usize = 32 * 1024;
/// Maximum encoded control reply, for preflight before committing a side effect.
pub const MAX_CONTROL_REPLY: usize = MAX_FRAME;

/// Answers an inquiry: a control request that asks for committed state and
/// changes nothing. `None` means "not an inquiry" and passes the request to the
/// host queue unchanged. It runs off the network workers and may run many at
/// once, so it must only read. This layer does not know what is being asked;
/// the responder validates the peer and the payload.
pub type InquiryResponder = Arc<dyn Fn(PeerId, &[u8]) -> Option<Vec<u8>> + Send + Sync>;

/// One duration series, in microseconds.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Timing {
    pub count: u64,
    pub total_us: u64,
    pub max_us: u64,
}

/// Where control requests spent their time. `inquiry`: answered by the
/// inquiry responder, whole service time. `host_wait`: queued until the host took it.
/// `host_service`: taken by the host until it replied.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ControlTiming {
    pub inquiry: Timing,
    pub host_wait: Timing,
    pub host_service: Timing,
}

#[derive(Default)]
struct Series {
    count: AtomicU64,
    total_us: AtomicU64,
    max_us: AtomicU64,
}
impl Series {
    fn add(&self, elapsed: Duration) {
        let us = elapsed.as_micros().min(u64::MAX as u128) as u64;
        self.count.fetch_add(1, Ordering::Relaxed);
        self.total_us.fetch_add(us, Ordering::Relaxed);
        self.max_us.fetch_max(us, Ordering::Relaxed);
    }
    fn get(&self) -> Timing {
        Timing {
            count: self.count.load(Ordering::Relaxed),
            total_us: self.total_us.load(Ordering::Relaxed),
            max_us: self.max_us.load(Ordering::Relaxed),
        }
    }
}

#[derive(Default)]
pub(super) struct TimingCounters {
    inquiry: Series,
    host_wait: Series,
    host_service: Series,
}
impl TimingCounters {
    fn snapshot(&self) -> ControlTiming {
        ControlTiming {
            inquiry: self.inquiry.get(),
            host_wait: self.host_wait.get(),
            host_service: self.host_service.get(),
        }
    }
}

pub struct ControlRequest {
    peer: PeerId,
    remote_address: Option<SocketAddr>,
    payload: Vec<u8>,
    reply: oneshot::Sender<Vec<u8>>,
    timing: Arc<TimingCounters>,
    queued: std::time::Instant,
    taken: Option<std::time::Instant>,
}
impl ControlRequest {
    /// Observed path only. The caller must validate workspace authorization
    /// before retaining this as a dial hint.
    pub fn remote_address(&self) -> Option<SocketAddr> {
        self.remote_address
    }
    pub fn peer(&self) -> PeerId {
        self.peer
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// Time since the request reached this node's queue.
    pub fn waited(&self) -> Duration {
        self.queued.elapsed()
    }

    pub fn expired(&self) -> bool {
        self.reply.is_closed()
    }
    /// Respond only after application authorization and required durable writes.
    pub fn respond(self, bytes: Vec<u8>) -> Result<()> {
        if bytes.len() > MAX_FRAME {
            return Err(Error::TooLarge);
        }
        if let Some(taken) = self.taken {
            self.timing.host_service.add(taken.elapsed());
        }
        self.reply.send(bytes).map_err(|_| Error::Rejected)
    }
    /// The host took this request from the queue: its wait ends, its service starts.
    fn take(mut self) -> Self {
        if self.taken.is_none() {
            self.timing.host_wait.add(self.queued.elapsed());
            self.taken = Some(std::time::Instant::now());
        }
        self
    }
}

/// The control inbox and its arrival signal travel together, so a request can
/// never be queued without waking the host.
#[derive(Clone)]
pub(super) struct ControlInbox {
    sender: mpsc::Sender<ControlRequest>,
    signal: Arc<tokio::sync::Notify>,
    responder: Arc<std::sync::RwLock<Option<InquiryResponder>>>,
    timing: Arc<TimingCounters>,
}
impl ControlInbox {
    pub(super) fn new(
        capacity: usize,
    ) -> (
        Self,
        mpsc::Receiver<ControlRequest>,
        Arc<tokio::sync::Notify>,
    ) {
        let (sender, receiver) = mpsc::channel(capacity);
        let signal = Arc::new(tokio::sync::Notify::new());
        (
            Self {
                sender,
                signal: signal.clone(),
                responder: Arc::default(),
                timing: Arc::default(),
            },
            receiver,
            signal,
        )
    }
    pub(super) fn set_responder(&self, responder: InquiryResponder) {
        *self
            .responder
            .write()
            .unwrap_or_else(|error| error.into_inner()) = Some(responder);
    }
    pub(super) fn timing(&self) -> ControlTiming {
        self.timing.snapshot()
    }
    /// Let the inquiry responder answer first. It runs on the blocking pool: a
    /// slow inquiry (history verification) must not hold a network worker.
    async fn inquire(&self, peer: PeerId, payload: Vec<u8>) -> (Vec<u8>, Option<Vec<u8>>) {
        let responder = self
            .responder
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        let Some(responder) = responder else {
            return (payload, None);
        };
        let started = std::time::Instant::now();
        let answered = tokio::task::spawn_blocking(move || {
            let answer = responder(peer, &payload);
            (payload, answer)
        })
        .await;
        match answered {
            Ok((payload, answer)) => {
                if answer.is_some() {
                    self.timing.inquiry.add(started.elapsed());
                }
                (payload, answer)
            }
            // A responder that panicked answered nothing; the request is lost with it.
            Err(_) => (Vec::new(), Some(Vec::new())),
        }
    }
    /// `notify_one` stores one permit when nobody waits. One permit is enough:
    /// the host drains until empty before it waits again.
    fn offer(&self, request: ControlRequest) -> Result<()> {
        self.sender
            .try_send(request)
            .map_err(|_| Error::Backpressure)?;
        self.signal.notify_one();
        Ok(())
    }
}

/// A new connection often opens on the relay and moves to a direct path once
/// holepunching succeeds, tens of milliseconds later. On tablets a reply of
/// several packets that crossed that move was never read (a 7 KB join reply
/// written 11 ms after the request, the joiner timing out at 30 s, on every
/// retry; 2026-09-18). Give a relay-only connection a short window to settle on
/// a direct path before sending. A peer reachable only through the relay costs
/// this window once per new connection.
/// Both ends call it: the requester before sending, the responder before
/// writing a reply (on tablets the responder's own view of the connection
/// switched to direct 22 ms before it wrote a 7 KB reply that never arrived).
/// When a switch happens while waiting, a short grace lets both ends finish
/// the path handoff before several packets go out on the new path.
async fn settle_on_direct_path(connection: &iroh::endpoint::Connection) {
    use futures_util::StreamExt;
    let direct = |paths: &iroh::endpoint::PathList<'_>| {
        paths.iter().any(|path| path.is_selected() && path.is_ip())
    };
    if direct(&connection.paths()) {
        return;
    }
    let mut stream = connection.paths_stream();
    let switched = tokio::time::timeout(DIRECT_PATH_SETTLE, async {
        while let Some(paths) = stream.next().await {
            if direct(&paths) {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    if switched {
        tokio::time::sleep(PATH_SWITCH_GRACE).await;
    }
}

const DIRECT_PATH_SETTLE: Duration = Duration::from_millis(750);
const PATH_SWITCH_GRACE: Duration = Duration::from_millis(250);

pub(super) async fn receive(
    connection: &iroh::endpoint::Connection,
    inbox: &ControlInbox,
    remote_address: Option<SocketAddr>,
    (send, recv): (
        &mut iroh::endpoint::SendStream,
        &mut iroh::endpoint::RecvStream,
    ),
) -> Result<()> {
    tracing::info!(target: "data_fabric_transport", remote = %connection.remote_id(), "CONTROL_ACCEPT_STREAM");
    let payload = recv.read_to_end(MAX_REQUEST).await.map_err(transport)?;
    tracing::info!(target: "data_fabric_transport", bytes = payload.len(), "CONTROL_REQUEST_READ");
    let (reply, response) = oneshot::channel();
    // Settle while the reply is prepared, not after: it costs no extra
    // time when the reply takes longer than the path switch.
    let settled = settle_on_direct_path(connection);
    let peer = *connection.remote_id().as_bytes();
    let (payload, answer) = inbox.inquire(peer, payload).await;
    let bytes = if let Some(bytes) = answer {
        if bytes.len() > MAX_FRAME {
            return Err(Error::TooLarge);
        }
        tracing::info!(target: "data_fabric_transport", "CONTROL_INQUIRY_ANSWERED");
        bytes
    } else {
        inbox.offer(ControlRequest {
            peer,
            remote_address,
            payload,
            reply,
            timing: inbox.timing.clone(),
            queued: std::time::Instant::now(),
            taken: None,
        })?;
        tokio::select! {
            response = response => response.map_err(|_| Error::Rejected)?,
            _ = send.stopped() => return Err(Error::Rejected),
        }
    };
    settled.await;
    tracing::info!(target: "data_fabric_transport", bytes = bytes.len(), paths = ?connection.paths(), "CONTROL_REPLY_WRITE");
    send.write_all(&bytes).await.map_err(transport)?;
    send.finish().map_err(transport)?;
    tracing::info!(target: "data_fabric_transport", "CONTROL_REPLY_FINISHED");
    Ok(())
}

/// Cloneable outbound control handle. It owns only the connection and
/// cancellation handles, so a runtime task can finish a multi-request
/// exchange without borrowing the mutable node queue.
#[derive(Clone)]
pub struct ControlClient {
    connections: super::connections::Connections,
    control_cancel: watch::Sender<bool>,
}

impl ControlClient {
    /// Retry a request only after the caller confirmed no bytes were sent.
    /// Clear the failed-dial cooldown for this peer before consuming that retry.
    pub fn retry_control(
        &self,
        peer: PeerId,
        payload: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send + 'static {
        let connections = self.connections.clone();
        let client = self.clone();
        let payload = payload.to_vec();
        async move {
            connections.clear_unreachable(peer).await;
            client.request_control(peer, &payload).await
        }
    }

    pub fn request_control(
        self,
        peer: PeerId,
        payload: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send + 'static {
        let payload = (payload.len() <= MAX_REQUEST).then(|| payload.to_vec());
        let connections = self.connections.clone();
        let mut cancelled = self.control_cancel.subscribe();
        async move {
            if *cancelled.borrow() {
                return Err(Error::Cancelled);
            }
            tokio::select! {
            _ = cancelled.changed() => Err(Error::Cancelled),
            outcome = async {
            let payload = payload.ok_or(Error::TooLarge)?;
            let mut stage = "connect";
            let mut observed = None;
            let operation_timeout = connections.operation_timeout();
            let outcome = tokio::time::timeout(CONTROL_TIMEOUT.max(operation_timeout), async {
            let connection = tokio::time::timeout(operation_timeout, connections.connect(peer, ALPN))
                .await.map_err(|_| Error::Timeout("control connect"))?
                ?;
            observed = Some(connection.clone());
            settle_on_direct_path(&connection).await;
            stage = "open stream";
            tracing::info!(target: "data_fabric_transport", paths = ?connection.paths(), "CONTROL_CLIENT_CONNECTED");
            let (mut send, mut recv) = connection.open_bi().await.map_err(transport)?;
            stage = "write request";
            send.write_all(&payload).await.map_err(transport)?;
            send.finish().map_err(transport)?;
            stage = "read response";
            tracing::info!(target: "data_fabric_transport", bytes = payload.len(), "CONTROL_REQUEST_SENT");
            let reply = recv.read_to_end(MAX_FRAME).await.map_err(transport)?;
            tracing::info!(target: "data_fabric_transport", bytes = reply.len(), "CONTROL_REPLY_READ");
            Ok(reply)
        })
        .await
        .map_err(|_| Error::Timeout("control response")).and_then(|result| result);
            tracing::info!(target: "data_fabric_transport", stage, success = outcome.is_ok(),
                error = outcome.as_ref().err().map(ToString::to_string), "CONTROL_CLIENT_END");
            if outcome.is_err()
                && let Some(connection) = observed
            {
                tracing::info!(target: "data_fabric_transport", paths = ?connection.paths(), stats = ?connection.stats(), "CONTROL_CLIENT_FAILURE");
            }
            // Sent but no reply: do not reuse this connection for the retry.
            if outcome.is_err() && matches!(stage, "read response" | "write request") {
                connections.discard(peer, ALPN).await;
            }
            // No control bytes can have left before write_all is entered. Once
            // writing starts, preserve uncertainty even for a partial write.
            match outcome {
                Err(_) if matches!(stage, "connect" | "open stream") => {
                    Err(Error::ControlNotSent(stage))
                }
                other => other,
            }
            } => outcome,
            }
        }
    }
}

impl Node {
    /// Poll at most eight queued requests, dropping expired requests. No workspace
    /// membership is implied; the peer is derived from the TLS connection.
    /// Raised once per queued control request. It carries no data; the caller
    /// still polls to learn what arrived.
    pub fn control_signal(&self) -> Arc<tokio::sync::Notify> {
        self.control_signal.clone()
    }

    /// True while requests set aside by `poll_control_matching` wait.
    pub fn has_deferred_controls(&self) -> bool {
        !self.deferred_controls.is_empty()
    }

    /// Wake the host for requests already queued, for example ones set aside
    /// while a membership commit was pending. Arrivals raise this themselves.
    pub fn rearm_control_signal(&self) {
        self.control_signal.notify_one();
    }

    pub fn poll_control(&mut self) -> Option<ControlRequest> {
        for _ in 0..8 {
            let request = self
                .deferred_controls
                .pop_front()
                .or_else(|| self.controls.try_recv().ok())?;
            if !request.expired() {
                return Some(request.take());
            }
        }
        None
    }

    /// Answer inquiries from committed state before they reach the host queue.
    pub fn set_inquiry_responder(&self, responder: InquiryResponder) {
        self.control_inbox.set_responder(responder);
    }

    /// Connections closed to make room or refused, device-wide.
    pub fn connection_capacity(&self) -> super::budget::CapacityCounts {
        self.connections.capacity_counts()
    }

    /// Where control requests spent their time since this node started.
    pub fn control_timing(&self) -> ControlTiming {
        self.control_inbox.timing()
    }

    /// Find a request without consuming unrelated control traffic. Used while a
    /// membership commit is pending so admission intake can continue without
    /// reordering recovery or membership-control messages.
    pub fn poll_control_matching(
        &mut self,
        matches: impl Fn(&[u8]) -> bool,
    ) -> Option<ControlRequest> {
        self.poll_control_first(matches, 8)
    }

    /// Take the first matching request from up to `depth` newly queued ones
    /// plus those already set aside; the rest keep their order. For short
    /// requests that must not wait behind a long queue (ADR 0009).
    pub fn poll_control_first(
        &mut self,
        matches: impl Fn(&[u8]) -> bool,
        depth: usize,
    ) -> Option<ControlRequest> {
        let mut scanned = Vec::with_capacity(16);
        while let Some(request) = self.deferred_controls.pop_front() {
            scanned.push(request);
        }
        for _ in 0..depth {
            let Ok(request) = self.controls.try_recv() else {
                break;
            };
            scanned.push(request);
        }
        let selected = scanned
            .iter()
            .position(|request| !request.expired() && matches(request.payload()))
            .map(|index| scanned.remove(index).take());
        self.deferred_controls.extend(scanned);
        selected
    }

    pub fn control_client(&self) -> ControlClient {
        ControlClient {
            connections: self.connections.clone(),
            control_cancel: self.control_cancel.clone(),
        }
    }

    /// Own the bounded request so a host can spawn it without borrowing its node
    /// or holding an application session lock across the network wait.
    pub fn request_control(
        &self,
        peer: PeerId,
        payload: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send + 'static {
        self.control_client().request_control(peer, payload)
    }
}
