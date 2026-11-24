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
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{ring, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::proxies::TlsSettings;

/// Names the pinned `component/tls.GetFingerprint` recognises. rustls cannot
/// emit a uTLS ClientHello, so these are applied as the closest rustls
/// profile: the browser key-exchange list (X25519 + P-256, no P-384), which is
/// what every recognised uTLS preset offers. Unknown names keep the standard
/// handshake, exactly like the pinned fallback (`GetFingerprint` warns and the
/// caller continues with `crypto/tls`).
pub fn known_client_fingerprint(name: &str) -> bool {
    matches!(
        name,
        "chrome"
            | "firefox"
            | "safari"
            | "ios"
            | "android"
            | "edge"
            | "360"
            | "qq"
            | "random"
            | "chrome120"
            | "firefox120"
            | "safari16"
            | "chrome_psk"
            | "chrome_psk_shuffle"
            | "chrome_padding_psk_shuffle"
            | "chrome_pq"
            | "chrome_pq_psk"
            | "randomized"
    )
}

/// Provider with the client-fingerprint approximation applied.
fn provider_for(fingerprint: Option<&str>) -> Arc<CryptoProvider> {
    let mut base = ring::default_provider();
    if let Some(name) = fingerprint {
        if known_client_fingerprint(name) {
            base.kx_groups.retain(|group| {
                group.name() == rustls::NamedGroup::X25519
                    || group.name() == rustls::NamedGroup::secp256r1
            });
        }
    }
    Arc::new(base)
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

/// `fingerprint`: accept the handshake when any presented certificate matches
/// the SHA-256 pin. A leaf match skips the chain/name check (the pinned
/// `NewFingerprintVerifier` returns before verifying); a non-leaf match
/// verifies the chain with the pinned certificate as the anchor.
#[derive(Debug)]
struct PinnedVerifier {
    pins: Vec<Vec<u8>>,
    name_cert_verify: Option<String>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        use sha2::{Digest, Sha256};
        let digest = |der: &[u8]| Sha256::digest(der).to_vec();
        if self
            .pins
            .iter()
            .any(|pin| pin.as_slice() == digest(end_entity.as_ref()).as_slice())
        {
            // Matching the leaf is the pin: the pinned verifier accepts here
            // without a name or chain check.
            return Ok(ServerCertVerified::assertion());
        }
        for (index, cert) in intermediates.iter().enumerate() {
            if !self
                .pins
                .iter()
                .any(|pin| pin.as_slice() == digest(cert.as_ref()).as_slice())
            {
                continue;
            }
            let mut roots = RootCertStore::empty();
            roots.add(cert.clone()).map_err(|error| {
                rustls::Error::General(format!("pinned intermediate is not a CA: {error}"))
            })?;
            let verifier = WebPkiServerVerifier::builder_with_provider(
                Arc::new(roots),
                self.provider.clone(),
            )
            .build()
            .map_err(|error| rustls::Error::General(error.to_string()))?;
            let name = match &self.name_cert_verify {
                Some(name) => ServerName::try_from(name.clone()).map_err(|error| {
                    rustls::Error::General(format!("invalid name-cert-verify: {error}"))
                })?,
                None => server_name.clone(),
            };
            // `intermediates[..index]` are the certificates between the leaf
            // and the pinned anchor.
            return verifier.verify_server_cert(
                end_entity,
                &intermediates[..index],
                &name,
                ocsp,
                now,
            );
        }
        Err(rustls::Error::General(
            "certificate fingerprints do not match".to_string(),
        ))
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

/// `name-cert-verify`: verify the chain against this name while the SNI stays
/// `sni`/`server` (pinned `ca.NewNameCertVerifier`).
#[derive(Debug)]
struct NameVerifier {
    inner: Arc<WebPkiServerVerifier>,
    name: ServerName<'static>,
}

impl ServerCertVerifier for NameVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, &self.name, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Load `certificate`/`private-key`: inline PEM when the value contains a PEM
/// header, otherwise a file path (the pinned loader also tries inline first).
fn client_auth(
    settings: &TlsSettings,
) -> io::Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>> {
    match (&settings.certificate, &settings.private_key) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "options 'certificate' and 'private-key' must be set together",
        )),
        (Some(certificate), Some(private_key)) => {
            let cert_pem = read_material(certificate)?;
            let key_pem = read_material(private_key)?;
            let certs = parse_pem_certs(&cert_pem).map_err(io::Error::other)?;
            let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_pem.as_bytes()))
                .map_err(io::Error::other)?
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "private-key holds no key block")
                })?;
            Ok(Some((certs, key)))
        }
    }
}

fn read_material(value: &str) -> io::Result<String> {
    if value.contains("-----BEGIN") {
        Ok(value.to_string())
    } else {
        std::fs::read_to_string(value)
    }
}

pub fn client_config(
    settings: &TlsSettings,
    tls: &ClientTls,
) -> io::Result<Arc<ClientConfig>> {
    client_config_with(settings, tls, &settings.alpn, Versions::Any, true, true)
}

/// ShadowTLS v2's camouflage handshake. TLS 1.3 session tickets would be
/// written by the camouflage host after the handshake completes; the pinned
/// client (uTLS with no session cache) never reads them, and the ShadowTLS v2
/// read-hash must end on the last write the server made before the first
/// application record. A ticket that rustls reads but the server hashed as a
/// later write makes the HMAC frame unrecognisable (`hashcode mismatch`), so
/// the handshake advertises no resumption at all: the pinned client's
/// behaviour and the only deterministic hash boundary.
pub fn shadow_tls_client_config(
    settings: &TlsSettings,
    tls: &ClientTls,
) -> io::Result<Arc<ClientConfig>> {
    client_config_with(settings, tls, &settings.alpn, Versions::Any, true, false)
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
    client_config_with(settings, tls, alpn, Versions::Tls13Only, enable_sni, true)
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

/// JLS over TCP (anytls `jls-opts`): TLS 1.3 only with the recorded-random
/// provider, no resumption (a PSK binder would have to be recomputed after the
/// random is replaced) and a verifier that trusts theServerHello-authenticated
/// camouflage certificate. The certificate still has to verify on the fallback
/// path where the ServerHello did not authenticate the account, which is the
/// pinned client's behaviour.
pub fn jls_tcp_client_config(
    settings: &TlsSettings,
    tls: &ClientTls,
    state: Arc<crate::outbound::jls::JlsState>,
) -> io::Result<Arc<ClientConfig>> {
    use rustls::client::WebPkiServerVerifier;

    let provider = crate::outbound::jls::provider();
    let inner: Arc<dyn ServerCertVerifier> = if let Some(pins) = &settings.fingerprint {
        Arc::new(PinnedVerifier {
            pins: vec![pins.clone()],
            name_cert_verify: settings.name_cert_verify.clone(),
            provider: provider.clone(),
        })
    } else if let Some(name) = &settings.name_cert_verify {
        let name = ServerName::try_from(name.clone()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid name-cert-verify '{name}': {error}"),
            )
        })?;
        let inner =
            WebPkiServerVerifier::builder_with_provider(Arc::new(tls.roots().clone()), provider)
                .build()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        Arc::new(NameVerifier { inner, name })
    } else if settings.skip_cert_verify {
        Arc::new(AcceptAny { provider })
    } else {
        WebPkiServerVerifier::builder_with_provider(Arc::new(tls.roots().clone()), provider)
            .build()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?
    };
    let verifier = Arc::new(crate::outbound::jls::JlsVerifier::new(inner, state));
    let builder = ClientConfig::builder_with_provider(crate::outbound::jls::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?;
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = settings
        .alpn
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    config.enable_sni = true;
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}

/// Protocol versions a caller allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Versions {
    Any,
    Tls13Only,
    /// ShadowTLS v1 only works over TLS 1.2: its camouflage relay stops at a
    /// cleartext Finished, which TLS 1.3 does not send.
    Tls12Only,
}

/// ShadowTLS v1's camouflage handshake: TLS 1.2 only, as the pinned client sets
/// `MaxVersion = VersionTLS12` for that version.
pub fn client_config_tls12(
    settings: &TlsSettings,
    tls: &ClientTls,
) -> io::Result<Arc<ClientConfig>> {
    client_config_with(settings, tls, &settings.alpn, Versions::Tls12Only, true, true)
}

fn client_config_with(
    settings: &TlsSettings,
    tls: &ClientTls,
    alpn: &[String],
    versions: Versions,
    enable_sni: bool,
    resumption: bool,
) -> io::Result<Arc<ClientConfig>> {
    let provider = provider_for(settings.client_fingerprint.as_deref());
    let builder = ClientConfig::builder_with_provider(provider.clone());
    let builder = match versions {
        Versions::Any => builder
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?,
        Versions::Tls13Only => builder
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?,
        Versions::Tls12Only => builder
            .with_protocol_versions(&[&rustls::version::TLS12])
            .map_err(io::Error::other)?,
    };
    let builder = if let Some(pins) = &settings.fingerprint {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
                pins: vec![pins.clone()],
                name_cert_verify: settings.name_cert_verify.clone(),
                provider: provider.clone(),
            }))
    } else if let Some(name) = &settings.name_cert_verify {
        let name = ServerName::try_from(name.clone()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid name-cert-verify '{name}': {error}"),
            )
        })?;
        let inner = WebPkiServerVerifier::builder_with_provider(
            Arc::new(tls.roots().clone()),
            provider.clone(),
        )
        .build()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NameVerifier {
                inner,
                name,
            }))
    } else if settings.skip_cert_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny { provider }))
    } else {
        builder.with_root_certificates(tls.roots().clone())
    };
    let mut config = match client_auth(settings)? {
        Some((certs, key)) => builder
            .with_client_auth_cert(certs, key)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?,
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    config.enable_sni = enable_sni;
    if !resumption {
        config.resumption = rustls::client::Resumption::disabled();
    }
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
