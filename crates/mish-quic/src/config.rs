//! QUIC/TLS configuration helpers.
//!
//! Builds endpoint configs with the **unreliable datagram extension enabled**.
//! The *live screen* rides datagrams (loss-tolerant latest-wins state sync); a
//! small, bounded number of **reliable bidirectional streams** are allowed for
//! request/response **side-channels** (e.g. scrollback history) that want
//! ordered, flow-controlled, reliable delivery without bloating the per-frame
//! diff. Streams live inside the same mutually-authenticated connection, so they
//! add no new auth surface. Also provides a self-signed server cert and an
//! insecure (accept-any-cert) client verifier for local testing.

use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, ServerConfig, TransportConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DistinguishedName, SignatureScheme};

/// Datagram receive buffer (bytes): holds datagrams that have arrived but not yet
/// been read. Modest — the driver drains promptly and the SSP layer keeps
/// instructions small (a full repaint is a handful of MTU-sized fragments).
const DATAGRAM_RECV_BUFFER: usize = 256 * 1024;
/// Datagram *send* buffer (bytes): deliberately small. SSP is latest-wins, so if
/// the link stalls we want stale screen diffs **dropped** (quinn evicts oldest
/// when full) and the next send to re-diff to the current screen — not a backlog
/// of obsolete frames played out late (bufferbloat). 64 KiB is dozens of frames'
/// headroom for normal bursts while still bounding stall-time latency.
const DATAGRAM_SEND_BUFFER: usize = 64 * 1024;

/// Install the ring crypto provider as the process default, once. rustls 0.23
/// requires a default provider for the convenience constructors we use.
pub fn init_crypto() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Max concurrent inbound bidi streams a peer may open. Side-channels are mostly
/// short-lived request/response exchanges (one stream per in-flight history
/// fetch), but **port forwarding** maps each live forwarded TCP connection to one
/// bidi stream, so the cap doubles as the ceiling on concurrent tunneled
/// connections. 256 comfortably covers a browser's connection fan-out while still
/// bounding memory; per-stream flow control bounds each stream's buffering, and
/// forwarding is opt-in (`-L`/`-R`) and default-deny on the server
/// (`--allow-forward`).
const MAX_SIDE_CHANNELS: u32 = 256;

/// Transport config shared by client and server: datagrams on, plus a bounded
/// number of reliable bidi streams for side-channels (scrollback, …).
fn transport_config() -> Arc<TransportConfig> {
    let mut tc = TransportConfig::default();
    tc.datagram_receive_buffer_size(Some(DATAGRAM_RECV_BUFFER));
    tc.datagram_send_buffer_size(DATAGRAM_SEND_BUFFER);
    // Allow a bounded number of reliable bidi streams for side-channels; no uni
    // streams (every side-channel is request/response, so it needs both halves).
    tc.max_concurrent_bidi_streams(MAX_SIDE_CHANNELS.into());
    tc.max_concurrent_uni_streams(0u8.into());
    // Keep idle connections alive across roaming gaps (mosh tolerates long naps).
    tc.keep_alive_interval(Some(Duration::from_secs(5)));
    tc.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
    // The assumed RTT before the first sample sizes the first PTO. quinn's default
    // (333 ms) means an early-lost packet on a fast link waits a third of a second
    // to recover — terrible for an interactive first keystroke / reconnect. 100 ms
    // is a safe floor: above realistic LAN/metro RTTs (so no spurious early
    // retransmits) but ~3× faster recovery than the default.
    tc.initial_rtt(Duration::from_millis(100));
    // Ask the peer not to sit on ACKs: the default lets a receiver delay an ACK up
    // to ~25 ms, which loosens our RTT estimate and PTO. For tiny interactive
    // datagrams the ACK cost is negligible, so cap the delay at 5 ms — tighter RTT
    // and faster loss detection on the echo path (quinn↔quinn only).
    let mut ack = quinn::AckFrequencyConfig::default();
    ack.max_ack_delay(Some(Duration::from_millis(5)));
    tc.ack_frequency_config(Some(ack));
    // Congestion controller. Cubic (quinn default) multiplicatively collapses the
    // window on loss, throttling our interactive datagrams under heavy/bursty loss
    // — exactly where we trail mosh (which has no congestion control at all). BBR
    // estimates bandwidth instead of reacting to loss, keeping datagrams flowing.
    // Opt-in via MISH_CC=bbr while we A/B it.
    if std::env::var("MISH_CC").as_deref() == Ok("bbr") {
        tc.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    }
    Arc::new(tc)
}

/// A self-signed server config plus the certificate (DER) clients should trust.
pub fn self_signed_server_config() -> (ServerConfig, CertificateDer<'static>) {
    init_crypto();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("self-signed cert generation");
    let cert_der = cert.cert.der().clone();
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let mut server_config = ServerConfig::with_single_cert(vec![cert_der.clone()], key_der.into())
        .expect("valid single-cert server config");
    server_config.transport_config(transport_config());
    (server_config, cert_der)
}

/// The credentials a server mints for one session: its own cert plus the
/// **client** cert/key the client must present. All three are handed to the
/// client over the SSH-authenticated `MISH CONNECT` channel; possession of the
/// client key is what authenticates the client to the server (mosh's shared-key
/// model, expressed as mutual TLS).
pub struct SessionAuth {
    /// Server certificate (DER) — the client pins it to authenticate the server.
    pub server_cert_der: Vec<u8>,
    /// Client certificate (DER) — the server pins it to authenticate the client.
    pub client_cert_der: Vec<u8>,
    /// Client private key (PKCS#8 DER) — transmitted over SSH; the client
    /// presents it during the QUIC/TLS handshake.
    pub client_key_der: Vec<u8>,
}

/// A QUIC server config that **requires and pins a specific client certificate**
/// (mutual authentication), plus the [`SessionAuth`] to hand to the client. This
/// closes the input-injection gap: only a peer presenting the minted client cert
/// — transmitted solely over the authenticated SSH channel — can connect.
pub fn authenticated_server_config() -> (ServerConfig, SessionAuth) {
    init_crypto();
    let (rustls_server, auth) = authenticated_rustls_server();
    let qsc = QuicServerConfig::try_from(rustls_server).expect("TLS13 quic server config");
    let mut server_config = ServerConfig::with_crypto(Arc::new(qsc));
    server_config.transport_config(transport_config());
    (server_config, auth)
}

/// Build the underlying rustls server config (with the pinned client-cert
/// verifier) and the session credentials. Split out so tests can inspect TLS
/// properties — notably that 0-RTT/early-data is off (see `early_data_is_off`).
fn authenticated_rustls_server() -> (rustls::ServerConfig, SessionAuth) {
    let server = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("server cert generation");
    let client = rcgen::generate_simple_self_signed(vec!["mish-client".to_string()])
        .expect("client cert generation");

    let server_cert_der = server.cert.der().clone();
    let server_key = PrivatePkcs8KeyDer::from(server.key_pair.serialize_der());
    let client_cert_der = client.cert.der().clone();

    let verifier = Arc::new(PinnedClientCertVerifier::new(
        client_cert_der.clone().into_owned(),
    ));
    let rustls_server = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server_cert_der.clone()],
            PrivateKeyDer::Pkcs8(server_key),
        )
        .expect("valid mutual-auth server config");
    // NOTE: we never set `max_early_data_size`, so it stays at rustls's default of
    // 0 — 0-RTT / TLS early data is OFF. This is deliberate: 0-RTT early data is
    // replayable, and a replayed first UserStream frame (keystrokes — a
    // non-idempotent PTY side effect) before the receiver has anti-replay state
    // would be an injection path. Screen-state diffs are idempotent and
    // sequence-numbered (replays are no-ops), but keystrokes are not. Keeping
    // early data off closes this; `early_data_is_off` pins it if session
    // resumption is ever added for fast reattach.

    let auth = SessionAuth {
        server_cert_der: server_cert_der.to_vec(),
        client_cert_der: client_cert_der.to_vec(),
        client_key_der: client.key_pair.serialize_der(),
    };
    (rustls_server, auth)
}

/// A client config that trusts the given server cert **and presents the minted
/// client cert/key** so the mutual-auth server accepts it.
pub fn authenticated_client_config(
    server_cert_der: &[u8],
    client_cert_der: &[u8],
    client_key_der: &[u8],
) -> ClientConfig {
    init_crypto();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(server_cert_der.to_vec()))
        .expect("add trusted server cert");
    let client_chain = vec![CertificateDer::from(client_cert_der.to_vec())];
    let client_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key_der.to_vec()));

    let rustls_client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(client_chain, client_key)
        .expect("valid mutual-auth client config");
    let qcc = QuicClientConfig::try_from(rustls_client).expect("TLS13 quic client config");
    let mut client_config = ClientConfig::new(Arc::new(qcc));
    client_config.transport_config(transport_config());
    client_config
}

/// A client config that trusts a specific server certificate.
pub fn client_config_trusting(cert: CertificateDer<'static>) -> ClientConfig {
    init_crypto();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).expect("add trusted cert");
    let mut client_config =
        ClientConfig::with_root_certificates(Arc::new(roots)).expect("valid client config");
    client_config.transport_config(transport_config());
    client_config
}

/// A client config that accepts **any** server certificate. For local testing
/// only — never use against an untrusted network.
pub fn insecure_client_config() -> ClientConfig {
    init_crypto();
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new()))
        .with_no_client_auth();
    let qcc = QuicClientConfig::try_from(crypto).expect("TLS13 quic client config");
    let mut client_config = ClientConfig::new(Arc::new(qcc));
    client_config.transport_config(transport_config());
    client_config
}

/// A `ServerCertVerifier` that accepts everything (testing only).
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Self {
        Self(Arc::new(rustls::crypto::ring::default_provider()))
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A `ClientCertVerifier` that accepts **exactly one** client certificate (by
/// DER equality). The pinned cert is minted per session and delivered only over
/// the authenticated SSH channel, so presenting it proves the peer is the
/// SSH-authenticated party. Chain/CA/EKU validation is deliberately bypassed
/// (the cert is self-signed and pinned); the TLS signature is still verified, so
/// the client must actually hold the matching private key.
#[derive(Debug)]
struct PinnedClientCertVerifier {
    pinned: CertificateDer<'static>,
    provider: Arc<CryptoProvider>,
    /// We advertise no acceptable-CA hints (the client already knows its cert).
    no_hints: Vec<DistinguishedName>,
}

impl PinnedClientCertVerifier {
    fn new(pinned: CertificateDer<'static>) -> Self {
        Self {
            pinned,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            no_hints: Vec::new(),
        }
    }
}

impl ClientCertVerifier for PinnedClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.no_hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.pinned.as_ref() {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "client certificate not recognized".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 0-RTT / TLS early data must be OFF on the server (max_early_data_size == 0).
    /// Early data is replayable; a replayed first UserStream keystroke frame would
    /// be an injection path. This regression-pins the safe default so enabling
    /// session resumption later can't silently turn early data on.
    #[test]
    fn early_data_is_off() {
        init_crypto();
        let (rustls_server, _auth) = authenticated_rustls_server();
        assert_eq!(
            rustls_server.max_early_data_size, 0,
            "0-RTT early data must remain disabled (replay-injection risk)"
        );
    }

    /// Security seam #0 — the auth decision. The pinned client-cert verifier is
    /// the whole "only the SSH-authenticated party may connect" property: it must
    /// accept a certificate **iff** it is byte-identical to the pinned one. A
    /// false-accept is a total auth bypass, so sweep the equality boundary
    /// adversarially (a different valid cert with the same subject, every
    /// single-bit flip of the pinned DER, truncation/extension/prefix/empty) and
    /// confirm only the exact cert is accepted — and that attacker-supplied
    /// intermediates never change the verdict.
    #[test]
    fn pinned_client_verifier_accepts_only_the_exact_cert() {
        init_crypto();
        let mint = || {
            rcgen::generate_simple_self_signed(vec!["mish-client".to_string()])
                .unwrap()
                .cert
                .der()
                .clone()
        };
        let pinned = mint();
        let other = mint(); // a *different* valid self-signed cert, same subject
        let v = PinnedClientCertVerifier::new(pinned.clone());
        let now = UnixTime::now();

        // Exact pinned cert → accepted.
        assert!(v.verify_client_cert(&pinned, &[], now).is_ok());

        // Everything that isn't byte-identical → rejected.
        let pin = pinned.as_ref();
        let mut adversarial: Vec<Vec<u8>> = vec![
            other.as_ref().to_vec(),
            Vec::new(),
            pin[..pin.len() - 1].to_vec(), // truncated
            [pin, &[0u8]].concat(),        // extended
            pin[..pin.len() / 2].to_vec(), // prefix
        ];
        for i in 0..pin.len() {
            let mut flipped = pin.to_vec();
            flipped[i] ^= 0x01; // flip one bit at each position
            adversarial.push(flipped);
        }
        for bytes in adversarial {
            assert_ne!(
                bytes.as_slice(),
                pin,
                "test bug: perturbation equals pinned"
            );
            let cert = CertificateDer::from(bytes);
            assert!(
                v.verify_client_cert(&cert, &[], now).is_err(),
                "verifier accepted a non-pinned client certificate"
            );
        }

        // Only the end-entity is consulted: attacker-supplied intermediates can't
        // turn a wrong cert into an accept, nor a right cert into a reject.
        let bogus = CertificateDer::from(vec![0u8; 48]);
        assert!(v
            .verify_client_cert(&pinned, std::slice::from_ref(&bogus), now)
            .is_ok());
        assert!(v
            .verify_client_cert(&other, std::slice::from_ref(&pinned), now)
            .is_err());
    }

    /// Client side of seam #0 — server pinning. The client trusts exactly the one
    /// server cert it read over SSH (a RootCertStore with that single cert), so a
    /// MITM on the hostile UDP path can't impersonate the user's host. This is the
    /// honest-user protection: sweep the server verifier and confirm it accepts
    /// the genuine pinned cert but rejects any other (a different valid cert with
    /// the same name, every single-bit flip of the pinned DER, truncation/empty).
    #[test]
    fn server_pin_rejects_any_cert_but_the_one_read_over_ssh() {
        use rustls::client::danger::ServerCertVerifier;
        use rustls::client::WebPkiServerVerifier;
        use rustls::pki_types::ServerName;

        init_crypto();
        let mint = || {
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .unwrap()
                .cert
                .der()
                .clone()
        };
        let pinned = mint();
        let other = mint(); // a different valid self-signed cert, same name

        // Build the exact verifier the client uses: WebPKI against a root store
        // holding only the pinned cert.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(pinned.clone()).unwrap();
        let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        let now = UnixTime::now();

        // The genuine host cert (what the user read over SSH) is accepted.
        assert!(
            verifier
                .verify_server_cert(&pinned, &[], &name, &[], now)
                .is_ok(),
            "client rejected the genuine pinned server cert"
        );

        // Any other server cert → rejected (no impersonation).
        let pin = pinned.as_ref();
        let mut adversarial: Vec<Vec<u8>> = vec![
            other.as_ref().to_vec(),
            Vec::new(),
            pin[..pin.len() - 1].to_vec(),
        ];
        for i in 0..pin.len() {
            let mut f = pin.to_vec();
            f[i] ^= 0x01;
            adversarial.push(f);
        }
        for bytes in adversarial {
            let cert = CertificateDer::from(bytes);
            assert!(
                verifier
                    .verify_server_cert(&cert, &[], &name, &[], now)
                    .is_err(),
                "client accepted a non-pinned server cert — MITM impersonation"
            );
        }
    }
}
