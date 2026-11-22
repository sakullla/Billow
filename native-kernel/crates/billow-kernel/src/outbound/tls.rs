//! TLS client used by trojan, vless, anytls and `tls: true` socks5/http outbounds.
//!
//! Verification uses the platform trust store (rustls-native-certs, which on
//! iOS/Android/macOS/Windows consults the OS anchors) plus the anchors from the
//! top-level `tls:` block of the loaded configuration; `skip-cert-verify`
//! replaces both with "accept any certificate", exactly like Mihomo's option.
//! The certificate name is `sni` when set, else the configured server name.
//!
//! The anchors are built once per kernel ([`ClientTls`]) and passed to every
//! outbound dial, so two kernels in one process (tests, a host that switches
//! configurations) cannot inherit each other's private authorities.

use std::io;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::proxies::TlsSettings;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

/// Trust anchors for one kernel: the platform store plus the configuration's
/// `tls.custom-cert`/`tls.certificate` entries. Built once at start so the
/// platform store is not re-read on every dial.
#[derive(Debug, Clone)]
pub struct ClientTls {
    roots: Arc<RootCertStore>,
    extra: usize,
}

impl ClientTls {
    pub fn new(extra: &[rustls_pki_types::CertificateDer<'static>]) -> ClientTls {
        let mut store = RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        let _ = store.add_parsable_certificates(native.certs);
        let before = store.len();
        let _ = store.add_parsable_certificates(extra.to_vec());
        let extra = store.len() - before;
        ClientTls {
            roots: Arc::new(store),
            extra,
        }
    }

    /// Number of configured anchors that actually became trust anchors.
    pub fn extra_roots(&self) -> usize {
        self.extra
    }

    pub fn roots(&self) -> &RootCertStore {
        &self.roots
    }
}

/// Parse a PEM bundle into DER certificates (config errors keep their tag).
pub fn parse_pem_certs(
    pem: &str,
) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, crate::config::ConfigError> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            crate::config::ConfigError::InvalidValue(format!("tls certificate PEM: {e}"))
        })?;
    if certs.is_empty() {
        return Err(crate::config::ConfigError::InvalidValue(
            "tls certificate PEM contains no CERTIFICATE block".to_string(),
        ));
    }
    Ok(certs)
}

#[derive(Debug)]
struct AcceptAny {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAny {
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
        dss: &DigitallySignedStruct,
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
        dss: &DigitallySignedStruct,
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

pub fn client_config(
    settings: &TlsSettings,
    tls: &ClientTls,
) -> io::Result<Arc<ClientConfig>> {
    client_config_with(settings, tls, &settings.alpn, false, true)
}

/// TLS client configuration for a QUIC handshake: QUIC requires TLS 1.3 and a
/// non-empty ALPN list, and `disable-sni` (TUIC) turns SNI off while keeping the
/// certificate name for verification.
pub fn quic_client_config(
    settings: &TlsSettings,
    tls: &ClientTls,
    alpn: &[String],
    enable_sni: bool,
) -> io::Result<Arc<ClientConfig>> {
    client_config_with(settings, tls, alpn, true, enable_sni)
}

/// ShadowQUIC's JLS client configuration: TLS 1.3 only, the recorded-random
/// provider, a verifier that accepts the camouflage certificate after JLS
/// authentication, and no resumption (JLS requires no PSK binder and a real
/// `0-RTT` handshake would need the pinned session marker). The SNI/certificate
/// name is passed separately to `Endpoint::connect_with`; the pinned type has
/// no `skip-cert-verify` option, and an unauthenticated peer cannot reach the
/// verifier anyway because the JLS wrapper aborts on a bad ServerHello.
pub fn jls_quic_client_config(
    tls: &ClientTls,
    alpn: &[String],
    state: Arc<crate::outbound::jls::JlsState>,
) -> io::Result<Arc<ClientConfig>> {
    use rustls::client::WebPkiServerVerifier;

    let provider = crate::outbound::jls::provider();
    let inner: Arc<dyn ServerCertVerifier> = WebPkiServerVerifier::builder_with_provider(
        Arc::new(tls.roots().clone()),
        provider.clone(),
    )
    .build()
    .map_err(io::Error::other)?;
    let verifier = Arc::new(crate::outbound::jls::JlsVerifier::new(inner, state));
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?;
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    config.enable_sni = true;
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}

fn client_config_with(
    settings: &TlsSettings,
    tls: &ClientTls,
    alpn: &[String],
    tls13_only: bool,
    enable_sni: bool,
) -> io::Result<Arc<ClientConfig>> {
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone());
    let builder = if tls13_only {
        builder
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
    } else {
        builder
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
    };
    let mut config = if settings.skip_cert_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny { provider }))
            .with_no_client_auth()
    } else {
        builder
            .with_root_certificates(tls.roots().clone())
            .with_no_client_auth()
    };
    config.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    config.enable_sni = enable_sni;
    Ok(Arc::new(config))
}

/// Raw TCP first (so `server` may be an IP while `sni` names the host), then TLS.
pub async fn wrap(
    stream: TcpStream,
    server: &str,
    settings: &TlsSettings,
    tls: &ClientTls,
) -> io::Result<TlsStream<TcpStream>> {
    wrap_stream(stream, server, settings, tls).await
}

/// TLS over any established byte stream (a `dialer-proxy` tunnel, a socket).
pub async fn wrap_stream<S>(
    stream: S,
    server: &str,
    settings: &TlsSettings,
    tls: &ClientTls,
) -> io::Result<TlsStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let name = settings.sni.clone().unwrap_or_else(|| server.to_string());
    let server_name = ServerName::try_from(name.clone()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid TLS server name '{name}': {e}"),
        )
    })?;
    let config = client_config(settings, tls)?;
    tokio_rustls::TlsConnector::from(config)
        .connect(server_name, stream)
        .await
        .map_err(|e| {
            let kind = if e.kind() == io::ErrorKind::InvalidData {
                io::ErrorKind::InvalidData
            } else {
                io::ErrorKind::ConnectionAborted
            };
            io::Error::new(kind, format!("TLS to {name} failed: {e}"))
        })
}
