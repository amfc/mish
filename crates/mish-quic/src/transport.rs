//! [`QuicTransport`]: a [`mish_ssp::Transport`] over QUIC unreliable datagrams,
//! plus helpers to stand up client/server endpoints.
//!
//! QUIC gives us crypto, congestion control, and — crucially for a *mobile*
//! shell — **connection migration**: the same logical connection survives the
//! client's IP/port changing (Wi-Fi → cellular, NAT rebinding, laptop resume).
//! We carry every SSP instruction in one unreliable datagram; loss is handled by
//! the SSP layer, not by QUIC retransmission.

use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::Bytes;
use mish_ssp::transport::{Transport, TransportError};
use quinn::{Connection, Endpoint};
use rustls::pki_types::CertificateDer;

use crate::config;

/// Errors setting up or running a QUIC transport.
#[derive(thiserror::Error, Debug)]
pub enum QuicError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("connect: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("connection: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("endpoint closed before a connection arrived")]
    NoConnection,
}

/// A live QUIC connection exposed as an unreliable datagram [`Transport`].
#[derive(Clone)]
pub struct QuicTransport {
    conn: Connection,
}

impl QuicTransport {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    /// The underlying connection (for migration, stats, close, …).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// The peer's current address — changes when the connection migrates.
    pub fn remote_address(&self) -> SocketAddr {
        self.conn.remote_address()
    }
}

#[async_trait]
impl Transport for QuicTransport {
    async fn send(&self, datagram: Bytes) -> Result<(), TransportError> {
        // send_datagram is synchronous: it enqueues into the current congestion
        // window or fails. We treat "no room"/"too large" as a drop (the SSP
        // layer re-diffs and retries); only a lost connection is fatal.
        use quinn::SendDatagramError::*;
        match self.conn.send_datagram(datagram) {
            Ok(()) => Ok(()),
            Err(ConnectionLost(_)) => Err(TransportError::Closed),
            Err(e @ (UnsupportedByPeer | Disabled | TooLarge)) => {
                Err(TransportError::Send(e.to_string()))
            }
        }
    }

    async fn recv(&self) -> Result<Bytes, TransportError> {
        match self.conn.read_datagram().await {
            Ok(bytes) => Ok(bytes),
            Err(_) => Err(TransportError::Closed),
        }
    }

    fn max_datagram_size(&self) -> usize {
        // Floor to a conservative MTU if the connection can't report a size yet,
        // so the fragmenter never produces 1-byte fragments.
        self.conn.max_datagram_size().unwrap_or(1200).max(512)
    }
}

/// Build a server endpoint bound to `addr` (use port 0 for an ephemeral port).
/// Returns the endpoint and the self-signed certificate clients should trust.
pub fn server_endpoint(addr: SocketAddr) -> Result<(Endpoint, CertificateDer<'static>), QuicError> {
    let (server_config, cert) = config::self_signed_server_config();
    let endpoint = Endpoint::server(server_config, addr)?;
    Ok((endpoint, cert))
}

/// Build a server endpoint from an already-bound `std` UDP socket and a
/// pre-built server config. Used by `mish-server`, which binds the socket and
/// prints its port *before* daemonizing (and before any tokio runtime exists),
/// then constructs the endpoint here inside the runtime. Must be called within a
/// tokio runtime context.
pub fn server_from_socket(
    socket: std::net::UdpSocket,
    server_config: quinn::ServerConfig,
) -> Result<Endpoint, QuicError> {
    let runtime = std::sync::Arc::new(quinn::TokioRuntime);
    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        runtime,
    )?;
    Ok(endpoint)
}

/// Build a client endpoint bound to `addr` (port 0 for ephemeral) that trusts a
/// specific server certificate.
pub fn client_endpoint(
    addr: SocketAddr,
    server_cert: CertificateDer<'static>,
) -> Result<Endpoint, QuicError> {
    let mut endpoint = Endpoint::client(addr)?;
    endpoint.set_default_client_config(config::client_config_trusting(server_cert));
    Ok(endpoint)
}

/// Build a mutual-auth client endpoint: trusts `server_cert` and presents the
/// minted client cert/key so the authenticating server accepts the connection.
pub fn authenticated_client_endpoint(
    addr: SocketAddr,
    server_cert_der: &[u8],
    client_cert_der: &[u8],
    client_key_der: &[u8],
) -> Result<Endpoint, QuicError> {
    let mut endpoint = Endpoint::client(addr)?;
    endpoint.set_default_client_config(config::authenticated_client_config(
        server_cert_der,
        client_cert_der,
        client_key_der,
    ));
    Ok(endpoint)
}

/// Build a client endpoint that accepts any server certificate (testing only).
pub fn insecure_client_endpoint(addr: SocketAddr) -> Result<Endpoint, QuicError> {
    let mut endpoint = Endpoint::client(addr)?;
    endpoint.set_default_client_config(config::insecure_client_config());
    Ok(endpoint)
}

/// Accept the next inbound connection on `endpoint` and wrap it as a transport.
pub async fn accept(endpoint: &Endpoint) -> Result<QuicTransport, QuicError> {
    let incoming = endpoint.accept().await.ok_or(QuicError::NoConnection)?;
    let conn = incoming.await?;
    Ok(QuicTransport::new(conn))
}

/// Connect to `server` (using the endpoint's default client config).
pub async fn connect(
    endpoint: &Endpoint,
    server: SocketAddr,
    server_name: &str,
) -> Result<QuicTransport, QuicError> {
    let conn = endpoint.connect(server, server_name)?.await?;
    Ok(QuicTransport::new(conn))
}

/// Convenience: a fully self-contained server endpoint bound to an OS-chosen
/// loopback port. Returns the endpoint, its bound address, and the cert.
pub fn loopback_server() -> Result<(Endpoint, SocketAddr, CertificateDer<'static>), QuicError> {
    let (endpoint, cert) = server_endpoint("127.0.0.1:0".parse().unwrap())?;
    let addr = endpoint.local_addr()?;
    Ok((endpoint, addr, cert))
}

/// Convenience: a client endpoint bound to a loopback ephemeral port.
pub fn loopback_client() -> Result<Endpoint, QuicError> {
    insecure_client_endpoint("127.0.0.1:0".parse().unwrap())
}

/// Convenience: a mutual-auth server endpoint on a loopback port. Returns the
/// endpoint, its address, and the [`SessionAuth`](crate::config::SessionAuth) to
/// hand to a client (the client cert/key it must present + the server cert).
pub fn loopback_authenticated_server(
) -> Result<(Endpoint, SocketAddr, crate::config::SessionAuth), QuicError> {
    let (server_config, auth) = config::authenticated_server_config();
    let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())?;
    let addr = endpoint.local_addr()?;
    Ok((endpoint, addr, auth))
}
