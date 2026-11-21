//! TLS client used by trojan, vless, and `tls: true` socks5/http outbounds.
//!
//! Verification uses the platform trust store (rustls-native-certs, which on
//! iOS/Android/macOS/Windows consults the OS anchors); `skip-cert-verify`
//! replaces it with "accept any certificate", exactly like Mihomo's option.
//! The certificate name is `sni` when set, else the configured server name.

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

/// Process-wide extra roots from the configuration (`tls.custom-cert`).
/// Installed once at kernel start; every TLS client of this process uses them.
static EXTRA_ROOTS: std::sync::OnceLock<Vec<rustls_pki_types::CertificateDer<'static>>> =
    std::sync::OnceLock::new();

/// Install configuration-provided roots (first kernel in the process wins;
/// a later, different set is reported so the host can restart instead of
/// silently keeping stale anchors).
pub fn install_extra_roots(
    certs: Vec<rustls_pki_types::CertificateDer<'static>>,
) -> Result<(), String> {
    match EXTRA_ROOTS.set(certs) {
        Ok(()) => Ok(()),
        Err(_) => {
            let current = EXTRA_ROOTS.get().map(Vec::len).unwrap_or(0);
            Err(format!(
                "TLS extra roots were already installed in this process ({current} certificates); a configuration with different tls roots needs a new process"
            ))
        }
    }
}

pub fn extra_roots_installed() -> usize {
    EXTRA_ROOTS.get().map(Vec::len).unwrap_or(0)
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

/// Trust anchors: the platform store plus configured extra roots. When both
/// are empty the store stays empty and every verification fails loudly (never
/// a silent skip).
pub fn roots() -> RootCertStore {
    let mut store = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    let _ = store.add_parsable_certificates(native.certs);
    if let Some(extra) = EXTRA_ROOTS.get() {
        let _ = store.add_parsable_certificates(extra.clone());
    }
    store
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

pub fn client_config(settings: &TlsSettings) -> io::Result<Arc<ClientConfig>> {
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?;
    let mut config = if settings.skip_cert_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny { provider }))
            .with_no_client_auth()
    } else {
        builder
            .with_root_certificates(roots())
            .with_no_client_auth()
    };
    config.alpn_protocols = settings
        .alpn
        .iter()
        .map(|a| a.as_bytes().to_vec())
        .collect();
    Ok(Arc::new(config))
}

/// Raw TCP first (so `server` may be an IP while `sni` names the host), then TLS.
pub async fn wrap(
    stream: TcpStream,
    server: &str,
    settings: &TlsSettings,
) -> io::Result<TlsStream<TcpStream>> {
    let name = settings.sni.clone().unwrap_or_else(|| server.to_string());
    let server_name = ServerName::try_from(name.clone()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid TLS server name '{name}': {e}"),
        )
    })?;
    let config = client_config(settings)?;
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
