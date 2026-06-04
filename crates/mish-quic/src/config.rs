//! QUIC/TLS configuration helpers.
//!
//! Builds endpoint configs with the **unreliable datagram extension enabled**
//! and streams disabled — mish carries everything in datagrams, so we want a
//! pure-datagram QUIC connection. Also provides a self-signed server cert and an
//! insecure (accept-any-cert) client verifier for local testing.

use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, ServerConfig, TransportConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::SignatureScheme;

/// Datagram receive/send buffer sizes (bytes). Generous; the SSP layer keeps
/// instructions small.
const DATAGRAM_BUFFER: usize = 1024 * 1024;

/// Install the ring crypto provider as the process default, once. rustls 0.23
/// requires a default provider for the convenience constructors we use.
pub fn init_crypto() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Transport config shared by client and server: datagrams on, streams off.
fn transport_config() -> Arc<TransportConfig> {
    let mut tc = TransportConfig::default();
    tc.datagram_receive_buffer_size(Some(DATAGRAM_BUFFER));
    tc.datagram_send_buffer_size(DATAGRAM_BUFFER);
    // We don't use QUIC streams at all.
    tc.max_concurrent_bidi_streams(0u8.into());
    tc.max_concurrent_uni_streams(0u8.into());
    // Keep idle connections alive across roaming gaps (mosh tolerates long naps).
    tc.keep_alive_interval(Some(Duration::from_secs(5)));
    tc.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
    Arc::new(tc)
}

/// A self-signed server config plus the certificate (DER) clients should trust.
pub fn self_signed_server_config() -> (ServerConfig, CertificateDer<'static>) {
    init_crypto();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("self-signed cert generation");
    let cert_der = cert.cert.der().clone();
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let mut server_config =
        ServerConfig::with_single_cert(vec![cert_der.clone()], key_der.into())
            .expect("valid single-cert server config");
    server_config.transport_config(transport_config());
    (server_config, cert_der)
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
