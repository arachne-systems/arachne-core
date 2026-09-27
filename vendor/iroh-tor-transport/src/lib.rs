// Modified by Arachne Systems from iroh-tor-transport 0.1.0; see ARACHNE-PATCH.md.
//! Tor hidden service utilities for iroh.
//!
//! This crate provides utilities for creating Tor hidden services that can be used
//! as a custom transport for iroh networking.

mod control;
mod onion;

use std::{collections::HashMap, future::Future, io, num::NonZeroUsize, sync::Arc, time::Duration};

use bytes::Bytes;
use iroh::{
    EndpointId, SecretKey, TransportAddr,
    address_lookup::{self, AddressLookup, EndpointData, EndpointInfo, Item},
    endpoint::{
        Builder,
        presets::{Minimal, Preset},
        transports::{CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit},
    },
};
use iroh_base::CustomAddr;
use n0_error::{e, stack_error};
use n0_future::{boxed::BoxFuture, stream};
use n0_watcher::Watchable;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};
use tokio_socks::tcp::Socks5Stream;

pub use crate::control::ControlError;
use crate::{
    control::TorControl,
    onion::{ExpandedSecretKey, OnionAddressV3},
};

/// Errors that can occur when building a Tor transport.
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum BuildError {
    /// Failed to bind the local TCP listener.
    #[error("Failed to bind local listener")]
    BindListener {
        #[error(std_err)]
        source: io::Error,
    },
    /// Failed to connect to the Tor control port.
    #[error("Failed to connect to Tor control port")]
    ControlConnect {
        #[error(std_err)]
        source: io::Error,
    },
    /// Failed to load Tor protocol info.
    #[error("Failed to load Tor protocol info")]
    ProtocolInfo {
        #[error(std_err)]
        source: ControlError,
    },
    /// Failed to determine Tor auth method.
    #[error("Failed to determine Tor auth method")]
    AuthMethod {
        #[error(std_err)]
        source: io::Error,
    },
    /// Failed to authenticate with Tor.
    #[error("Failed to authenticate with Tor")]
    Auth {
        #[error(std_err)]
        source: ControlError,
    },
    /// Failed to create hidden service.
    #[error("Failed to create hidden service")]
    CreateOnion {
        #[error(std_err)]
        source: ControlError,
    },
}

/// Convert an iroh SecretKey to a Tor v3 secret key.
fn iroh_to_tor_secret_key(key: &SecretKey) -> ExpandedSecretKey {
    ExpandedSecretKey::from_seed(&key.to_bytes())
}

/// Get the onion address for an iroh `EndpointId` (public key only).
///
/// Always `Some`: an `EndpointId` is already a validated Ed25519 public key,
/// which is what torut checked here.
pub(crate) fn onion_address_from_endpoint(endpoint: EndpointId) -> Option<OnionAddressV3> {
    Some(OnionAddressV3::from_public_key(endpoint.as_bytes()))
}

/// A packet carried over the Tor stream transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TorPacket {
    /// Source endpoint id (32 bytes).
    pub from: EndpointId,
    /// Raw packet payload.
    pub data: Bytes,
    /// Segment size to split up data (optional).
    pub segment_size: Option<u16>,
}

const FLAG_SEGMENT_SIZE: u8 = 0x01;
// noq-proto's maximum UDP payload. The Tor framing layer must reject larger
// lengths before allocation because it runs before Iroh authenticates a peer.
const MAX_PACKET_SIZE: usize = 65_527;
/// Transport id for the Tor user transport.
const TOR_USER_TRANSPORT_ID: u64 = 0x544f52;

/// Build a user transport address for the Tor transport.
fn tor_user_addr(endpoint: EndpointId) -> CustomAddr {
    CustomAddr::from_parts(TOR_USER_TRANSPORT_ID, endpoint.as_bytes())
}

/// Discovery service that maps any `EndpointId` to its Tor user transport address.
#[derive(Debug, Clone)]
struct TorAddressLookup;

impl AddressLookup for TorAddressLookup {
    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<n0_future::boxed::BoxStream<Result<Item, address_lookup::Error>>> {
        let info = EndpointInfo {
            endpoint_id,
            data: EndpointData::new(vec![TransportAddr::Custom(tor_user_addr(endpoint_id))]),
        };
        Some(Box::pin(stream::once(Ok(Item::new(
            info,
            "tor-user-addr",
            None,
        )))))
    }
}

fn parse_user_addr(addr: &CustomAddr) -> io::Result<EndpointId> {
    if addr.id() != TOR_USER_TRANSPORT_ID {
        return Err(io::Error::other("unexpected transport id"));
    }
    let data = addr.data();
    if data.len() != 32 {
        return Err(io::Error::other("unexpected endpoint id length"));
    }
    let bytes: [u8; 32] = data
        .try_into()
        .map_err(|_| io::Error::other("endpoint id bytes"))?;
    EndpointId::from_bytes(&bytes).map_err(io::Error::other)
}

/// Read a single packet from a stream. Returns `Ok(None)` on clean EOF.
pub(crate) async fn read_tor_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<Option<TorPacket>> {
    let mut flags = [0u8; 1];
    let mut read = 0usize;
    while read < flags.len() {
        let n = reader.read(&mut flags[read..]).await?;
        if n == 0 {
            return Ok(None);
        }
        read += n;
    }

    let mut from_bytes = [0u8; 32];
    reader.read_exact(&mut from_bytes).await?;
    let from = EndpointId::from_bytes(&from_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let segment_size = if flags[0] & FLAG_SEGMENT_SIZE != 0 {
        let mut size_bytes = [0u8; 2];
        reader.read_exact(&mut size_bytes).await?;
        Some(u16::from_be_bytes(size_bytes))
    } else {
        None
    };

    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_PACKET_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Tor packet exceeds Iroh datagram limit",
        ));
    }

    let mut data = vec![0u8; len];
    reader.read_exact(&mut data).await?;

    Ok(Some(TorPacket {
        from,
        data: Bytes::from(data),
        segment_size,
    }))
}

/// Write a single packet to a stream.
pub(crate) async fn write_tor_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    packet: &TorPacket,
) -> io::Result<()> {
    if packet.data.len() > MAX_PACKET_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Tor packet exceeds Iroh datagram limit",
        ));
    }
    let mut flags = 0u8;
    if packet.segment_size.is_some() {
        flags |= FLAG_SEGMENT_SIZE;
    }
    writer.write_all(&[flags]).await?;
    writer.write_all(packet.from.as_bytes()).await?;
    if let Some(segment_size) = packet.segment_size {
        writer.write_all(&segment_size.to_be_bytes()).await?;
    }
    let len = u32::try_from(packet.data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "packet too large"))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&packet.data).await?;
    writer.flush().await?;
    Ok(())
}

/// A service that reads framed packets from a stream and dispatches them to a channel.
#[derive(Clone)]
pub(crate) struct TorPacketService {
    sender: tokio::sync::mpsc::Sender<TorPacket>,
    read_timeout: Duration,
}

impl TorPacketService {
    /// Create a new service with the given handler.
    pub(crate) fn new(sender: tokio::sync::mpsc::Sender<TorPacket>) -> Self {
        Self {
            sender,
            read_timeout: INBOUND_READ_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_read_timeout(
        sender: tokio::sync::mpsc::Sender<TorPacket>,
        read_timeout: Duration,
    ) -> Self {
        Self {
            sender,
            read_timeout,
        }
    }

    /// Handle packets on a single stream until EOF.
    pub(crate) async fn handle_stream(&self, mut stream: TcpStream) -> io::Result<()> {
        loop {
            let packet = tokio::time::timeout(self.read_timeout, read_tor_packet(&mut stream))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "Tor packet read timed out")
                })??;
            let Some(packet) = packet else {
                return Ok(());
            };
            let _ = self.sender.try_send(packet);
        }
    }
}

async fn accept_streams(
    io: Arc<TorStreamIo>,
    service: TorPacketService,
    permits: Arc<tokio::sync::Semaphore>,
) {
    loop {
        let permit = match permits.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => return,
        };
        match io.accept().await {
            Ok(stream) => {
                let service = service.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = service.handle_stream(stream).await;
                });
            }
            Err(err) => {
                tracing::warn!("Tor accept loop stopped: {err:#}");
                return;
            }
        }
    }
}

/// IO for Tor-backed streams.
pub(crate) struct TorStreamIo {
    accept: Box<dyn Fn() -> BoxFuture<io::Result<TcpStream>> + Send + Sync>,
    connect: Box<dyn Fn(EndpointId) -> BoxFuture<io::Result<TcpStream>> + Send + Sync>,
}

impl TorStreamIo {
    /// Create a new IO wrapper from accept/connect functions.
    pub(crate) fn new<Accept, Connect, AcceptFut, ConnectFut>(
        accept: Accept,
        connect: Connect,
    ) -> Self
    where
        Accept: Fn() -> AcceptFut + Send + Sync + 'static,
        AcceptFut: Future<Output = io::Result<TcpStream>> + Send + 'static,
        Connect: Fn(EndpointId) -> ConnectFut + Send + Sync + 'static,
        ConnectFut: Future<Output = io::Result<TcpStream>> + Send + 'static,
    {
        Self {
            accept: Box::new(move || Box::pin(accept())),
            connect: Box::new(move |endpoint| Box::pin(connect(endpoint))),
        }
    }

    /// Connect to the remote endpoint's stream transport.
    fn connect(&self, endpoint: EndpointId) -> BoxFuture<io::Result<TcpStream>> {
        (self.connect)(endpoint)
    }

    /// Accept the next incoming stream.
    fn accept(&self) -> BoxFuture<io::Result<TcpStream>> {
        (self.accept)()
    }
}

/// Packet writer that reuses per-endpoint streams.
pub(crate) struct TorPacketSender {
    io: Arc<TorStreamIo>,
    streams: Mutex<HashMap<EndpointId, Arc<Mutex<TcpStream>>>>,
}

const MAX_CACHED_STREAMS: usize = 64;

impl TorPacketSender {
    /// Create a new sender with the provided connector.
    pub(crate) fn new(io: Arc<TorStreamIo>) -> Self {
        Self {
            io,
            streams: Mutex::new(HashMap::new()),
        }
    }

    /// Send a packet to the given endpoint, reusing an existing stream when available.
    pub(crate) async fn send(&self, to: EndpointId, packet: &TorPacket) -> io::Result<()> {
        let stream = self.get_or_connect(to).await?;
        let mut guard = stream.lock().await;
        match write_tor_packet(&mut *guard, packet).await {
            Ok(()) => Ok(()),
            Err(err) => {
                drop(guard);
                let mut streams = self.streams.lock().await;
                if streams
                    .get(&to)
                    .is_some_and(|cached| Arc::ptr_eq(cached, &stream))
                {
                    streams.remove(&to);
                }
                Err(err)
            }
        }
    }

    async fn get_or_connect(&self, to: EndpointId) -> io::Result<Arc<Mutex<TcpStream>>> {
        if let Some(existing) = self.streams.lock().await.get(&to).cloned() {
            return Ok(existing);
        }

        let stream = self.io.connect(to).await?;
        let stream = Arc::new(Mutex::new(stream));

        let mut guard = self.streams.lock().await;
        if let Some(existing) = guard.get(&to) {
            return Ok(existing.clone());
        }
        if guard.len() >= MAX_CACHED_STREAMS {
            let idle = guard
                .iter()
                .find(|(_, stream)| Arc::strong_count(stream) == 1)
                .map(|(endpoint, _)| *endpoint)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::WouldBlock, "Tor stream capacity exhausted")
                })?;
            guard.remove(&idle);
        }
        guard.insert(to, stream.clone());
        Ok(stream)
    }

    /// Close and remove a cached stream for the given endpoint.
    #[allow(dead_code)]
    pub(crate) async fn close(&self, to: EndpointId) -> io::Result<()> {
        let stream = self.streams.lock().await.remove(&to);
        if let Some(stream) = stream {
            let mut guard = stream.lock().await;
            guard.shutdown().await?;
        }
        Ok(())
    }

    /// Close and remove all cached streams.
    #[allow(dead_code)]
    pub(crate) async fn close_all(&self) -> io::Result<()> {
        let streams: Vec<_> = self.streams.lock().await.drain().map(|(_, v)| v).collect();
        for stream in streams {
            let mut guard = stream.lock().await;
            guard.shutdown().await?;
        }
        Ok(())
    }
}

const MAX_INBOUND_STREAMS: usize = 64;
const INBOUND_READ_TIMEOUT: Duration = Duration::from_secs(30);
// With the 65,527-byte Iroh datagram ceiling this retains at most about 4 MiB
// of packet bodies. Queue saturation drops datagrams, matching UDP semantics.
const DEFAULT_RECV_CAPACITY: usize = 64;
const DEFAULT_SOCKS_PORT: u16 = 9050;
const DEFAULT_CONTROL_PORT: u16 = 9051;
const DEFAULT_ONION_PORT: u16 = 9999;

/// Builder for [`TorCustomTransport`].
///
/// # Defaults
///
/// - SOCKS5 proxy port: 9050
/// - Control port: 9051
/// - Onion service port: 9999
#[derive(Clone, Default)]
pub struct TorCustomTransportBuilder {
    socks_port: u16,
    control_port: u16,
    onion_port: u16,
    #[cfg(test)]
    io: Option<Arc<TorStreamIo>>,
}

impl TorCustomTransportBuilder {
    /// Set the SOCKS5 proxy port (default: 9050).
    pub fn socks_port(mut self, port: u16) -> Self {
        self.socks_port = port;
        self
    }

    /// Set the Tor control port (default: 9051).
    pub fn control_port(mut self, port: u16) -> Self {
        self.control_port = port;
        self
    }

    /// Set the onion service port (default: 9999).
    pub fn onion_port(mut self, port: u16) -> Self {
        self.onion_port = port;
        self
    }

    /// Override with custom IO (for testing with local TCP instead of Tor).
    #[cfg(test)]
    pub(crate) fn io(mut self, io: Arc<TorStreamIo>) -> Self {
        self.io = Some(io);
        self
    }

    /// Build the transport.
    ///
    /// This connects to the Tor control port, creates a hidden service,
    /// and sets up the transport IO.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - The iroh secret key for this endpoint
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Cannot bind the local listener
    /// - Cannot connect to the Tor control port
    /// - Cannot authenticate with Tor
    /// - Cannot create the hidden service
    pub async fn build(self, secret_key: SecretKey) -> Result<Arc<TorCustomTransport>, BuildError> {
        let local_id = secret_key.public();

        #[cfg(test)]
        if let Some(io) = self.io {
            return Ok(Arc::new(TorCustomTransport {
                local_id,
                io,
                control_conn: None,
            }));
        }

        // Bind local listener
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|err| e!(BuildError::BindListener, err))?;
        let local_addr = listener
            .local_addr()
            .map_err(|err| e!(BuildError::BindListener, err))?;
        let listener = Arc::new(listener);

        // Connect to Tor control port and create hidden service
        let control_addr = format!("127.0.0.1:{}", self.control_port);
        let stream = TcpStream::connect(&control_addr)
            .await
            .map_err(|err| e!(BuildError::ControlConnect, err))?;
        let mut conn = TorControl::new(stream);
        let auth_data = conn
            .protocol_info()
            .await
            .map_err(|err| e!(BuildError::ProtocolInfo, err))?;
        let auth_method = auth_data
            .auth_data()
            .await
            .map_err(|err| e!(BuildError::AuthMethod, err))?;
        if let Some(auth) = auth_method {
            conn.authenticate(&auth)
                .await
                .map_err(|err| e!(BuildError::Auth, err))?;
        }

        // Create the hidden service
        let tor_key = iroh_to_tor_secret_key(&secret_key);
        let onion_addr = OnionAddressV3::from_public_key(local_id.as_bytes());
        match conn
            .add_onion_v3(&tor_key, self.onion_port, local_addr)
            .await
        {
            Ok(Some(service_id))
                if OnionAddressV3::from_service_id(&service_id) != Some(onion_addr) =>
            {
                // Tor derived a different address from the key than the one
                // peers derive from our EndpointId: nobody could reach us.
                return Err(e!(
                    BuildError::CreateOnion,
                    ControlError::Protocol("Tor reported a different onion address")
                ));
            }
            Ok(_) => {}
            Err(ControlError::Status { code: 552, .. }) => {
                // Service already exists, that's fine
            }
            Err(err) => return Err(e!(BuildError::CreateOnion, err)),
        }

        tracing::info!("Hidden service created: {}:{}", onion_addr, self.onion_port);

        let socks_addr: std::net::SocketAddr =
            format!("127.0.0.1:{}", self.socks_port).parse().unwrap();
        let onion_port = self.onion_port;
        let io = Arc::new(TorStreamIo::new(
            move || {
                let listener = listener.clone();
                async move {
                    let (stream, _) = listener.accept().await?;
                    Ok(stream)
                }
            },
            move |endpoint| async move {
                let onion = onion_address_from_endpoint(endpoint).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid endpoint id")
                })?;
                let onion_addr = onion.to_string();
                let stream = Socks5Stream::connect(socks_addr, (onion_addr.as_str(), onion_port))
                    .await
                    .map_err(io::Error::other)?;
                Ok(stream.into_inner())
            },
        ));

        Ok(Arc::new(TorCustomTransport {
            local_id,
            io,
            control_conn: Some(Arc::new(conn)),
        }))
    }
}

/// A Tor-backed user transport factory for iroh.
///
/// This holds the configuration and IO for the Tor transport. The actual
/// transport instance is created when iroh calls `bind()` during endpoint setup.
///
/// Use `TorCustomTransport::builder()` to create and configure.
///
/// # Example
///
/// ```ignore
/// let transport = TorCustomTransport::builder(secret_key).build().await;
///
/// Endpoint::builder(transport.preset())
///     .secret_key(secret_key)
///     .bind()
///     .await?
/// ```
#[derive(Clone)]
pub struct TorCustomTransport {
    local_id: EndpointId,
    io: Arc<TorStreamIo>,
    /// Keep the control connection alive to maintain the ephemeral hidden service.
    /// The hidden service is removed when this connection is dropped.
    /// Wrapped in Arc so it can be shared with TorCustomEndpoint.
    #[allow(dead_code)]
    control_conn: Option<Arc<TorControl<TcpStream>>>,
}

impl TorCustomTransport {
    /// Create a builder for configuring a Tor user transport.
    pub fn builder() -> TorCustomTransportBuilder {
        TorCustomTransportBuilder {
            socks_port: DEFAULT_SOCKS_PORT,
            control_port: DEFAULT_CONTROL_PORT,
            onion_port: DEFAULT_ONION_PORT,
            #[cfg(test)]
            io: None,
        }
    }

    /// Returns a discovery service for this transport.
    ///
    /// The discovery service maps any `EndpointId` to its Tor user transport address.
    pub fn discovery(&self) -> impl AddressLookup {
        TorAddressLookup
    }

    /// Returns a preset that configures an endpoint to use this Tor transport.
    ///
    /// The preset adds the Tor user transport factory and discovery service.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let transport = TorCustomTransport::builder(sk.clone()).build().await;
    ///
    /// Endpoint::builder(transport.preset())
    ///     .secret_key(sk)
    ///     .bind()
    ///     .await?
    /// ```
    pub fn preset(self: &Arc<Self>) -> impl Preset {
        TorPreset {
            factory: self.clone(),
        }
    }
}

impl std::fmt::Debug for TorCustomTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorCustomTransport")
            .field("local_id", &self.local_id)
            .finish()
    }
}

impl CustomTransport for TorCustomTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let (tx, rx) = tokio::sync::mpsc::channel(DEFAULT_RECV_CAPACITY);
        let service = TorPacketService::new(tx);
        let sender = Arc::new(TorPacketSender::new(self.io.clone()));
        let watchable = Watchable::new(vec![tor_user_addr(self.local_id)]);

        tokio::spawn(accept_streams(
            self.io.clone(),
            service,
            Arc::new(tokio::sync::Semaphore::new(MAX_INBOUND_STREAMS)),
        ));

        Ok(Box::new(TorCustomEndpoint {
            local_id: self.local_id,
            watchable,
            receiver: rx,
            sender,
        }))
    }
}

/// Internal preset for configuring an iroh endpoint to use the Tor transport.
struct TorPreset {
    factory: Arc<dyn CustomTransport>,
}

impl Preset for TorPreset {
    fn apply(self, builder: Builder) -> Builder {
        // `Minimal` sets the mandatory crypto provider (ring or aws-lc-rs,
        // depending on the enabled iroh tls feature). The rest is Tor-specific.
        Minimal
            .apply(builder)
            .clear_ip_transports()
            .clear_relay_transports()
            .clear_address_lookup()
            .add_custom_transport(self.factory)
            .address_lookup(TorAddressLookup)
    }
}

/// Active Tor user endpoint created by [`TorCustomTransport::bind()`].
///
/// This is the actual endpoint that handles sending and receiving packets.
/// Note: The control connection (and thus the hidden service) is kept alive by
/// the `Arc<TorCustomTransport>` that the user holds. The user must keep it alive
/// for the lifetime of the endpoint.
struct TorCustomEndpoint {
    local_id: EndpointId,
    watchable: Watchable<Vec<CustomAddr>>,
    receiver: tokio::sync::mpsc::Receiver<TorPacket>,
    sender: Arc<TorPacketSender>,
}

impl std::fmt::Debug for TorCustomEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorCustomEndpoint")
            .field("local_id", &self.local_id)
            .finish()
    }
}

struct TorCustomSender {
    local_id: EndpointId,
    sender: Arc<TorPacketSender>,
}

impl std::fmt::Debug for TorCustomSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorCustomSender")
            .field("local_id", &self.local_id)
            .finish()
    }
}

impl CustomSender for TorCustomSender {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        addr.id() == TOR_USER_TRANSPORT_ID && addr.data().len() == 32
    }

    fn poll_send(
        &self,
        _cx: &mut std::task::Context,
        dst: &CustomAddr,
        _src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let to = parse_user_addr(dst).map_err(io::Error::other)?;
        let segment_size = transmit
            .segment_size
            .map(|size| u16::try_from(size).map_err(|_| io::Error::other("segment size too large")))
            .transpose()?;
        let chunk_size = segment_size
            .map(|s| s as usize)
            .unwrap_or(transmit.contents.len().max(1));

        for chunk in transmit.contents.chunks(chunk_size) {
            let packet = TorPacket {
                from: self.local_id,
                data: Bytes::copy_from_slice(chunk),
                segment_size,
            };
            let sender = self.sender.clone();
            tokio::spawn(async move {
                let _ = sender.send(to, &packet).await;
            });
        }

        std::task::Poll::Ready(Ok(()))
    }
}

impl CustomEndpoint for TorCustomEndpoint {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.watchable.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(TorCustomSender {
            local_id: self.local_id,
            sender: self.sender.clone(),
        })
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        NonZeroUsize::new(32).unwrap()
    }

    fn poll_recv(
        &mut self,
        cx: &mut std::task::Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> std::task::Poll<io::Result<usize>> {
        let n = bufs.len().min(metas.len()).min(recv_infos.len());
        if n == 0 {
            return std::task::Poll::Ready(Ok(0));
        }

        let mut filled = 0usize;
        while filled < n {
            match self.receiver.poll_recv(cx) {
                std::task::Poll::Pending => {
                    if filled == 0 {
                        return std::task::Poll::Pending;
                    }
                    break;
                }
                std::task::Poll::Ready(None) => {
                    return std::task::Poll::Ready(Err(io::Error::other("packet channel closed")));
                }
                std::task::Poll::Ready(Some(packet)) => {
                    if bufs[filled].len() < packet.data.len() {
                        continue;
                    }
                    bufs[filled][..packet.data.len()].copy_from_slice(&packet.data);
                    metas[filled].len = packet.data.len();
                    metas[filled].stride = packet
                        .segment_size
                        .map(|s| s as usize)
                        .unwrap_or(packet.data.len());
                    recv_infos[filled] = RecvInfo::new(tor_user_addr(packet.from), None);
                    filled += 1;
                }
            }
        }

        if filled > 0 {
            std::task::Poll::Ready(Ok(filled))
        } else {
            std::task::Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests;
