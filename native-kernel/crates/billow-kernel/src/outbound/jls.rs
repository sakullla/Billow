//! ShadowQUIC JLS authentication (`transport/shadowquic` + `jls-tls`).
//!
//! ShadowQUIC does not add a TLS extension in the RFC 6066 sense. JLS replaces
//! the 32-byte `random` field of the TLS 1.3 ClientHello/ServerHello with an
//! AES-256-GCM ciphertext derived from the account:
//!
//! ```text
//! auth_data   = the whole handshake message with `random` zeroed
//!               (and every PSK-binder byte zeroed)
//! key         = SHA-256(password || auth_data)
//! nonce       = SHA-256(username || auth_data)          (32 bytes)
//! fake_random = AES-256-GCM(key, nonce, random[0..16])  (16 + 16 tag bytes)
//! ```
//!
//! The server opens the ClientHello random with each configured account and
//! seals the ServerHello random with the account that authenticated the
//! client. A client therefore authenticates by sealing its own random and
//! verifies the server by opening the ServerHello one. After successful JLS
//! authentication the pinned client skips certificate verification: the
//! certificate is camouflage, not identity.
//!
//! ## Reaching the `random` field from `rustls`
//!
//! `rustls` hashes and serialises the ClientHello internally, so a
//! post-processing hook would break the handshake transcript. This module does
//! not patch `rustls`; instead it builds the ClientHello twice with a
//! deterministic, recorded randomness stream:
//!
//! 1. a dry session emits the ClientHello with a real random `random`;
//! 2. the dry handshake message (random zeroed) gives `auth_data`, and the
//!    sealed value is computed;
//! 3. a second session replays the exact same randomness, except the one fill
//!    that produced the `random` field, which now returns the sealed value.
//!
//! The replay is safe because both sessions use the same OS-seeded stream for
//! the session id and the ephemeral X25519 key share; the dry ClientHello is
//! never sent. The second ClientHello is checked byte-for-byte against
//! "dry ClientHello with the random replaced" and the connection aborts if
//! that invariant ever breaks (a future rustls change fails loudly instead of
//! silently dropping JLS).
//!
//! `rustls` normally takes X25519 key material from the crypto library's own
//! RNG, which would make the two sessions differ. The provider below supplies a
//! small X25519 key exchange that uses the same recorded stream, so the key
//! share is identical in both passes.

use std::any::Any;
use std::cell::RefCell;
use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use aes::Aes256;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::AesGcm;
use quinn_proto::crypto::{
    ClientConfig as CryptoClientConfig, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys,
    PacketKey, Session,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, ConnectionId, Side, TransportError, TransportErrorCode};
use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    ActiveKeyExchange, CryptoProvider, GetRandomFailed, SecureRandom, SharedSecret,
    SupportedKxGroup,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, NamedGroup, SignatureScheme};
use sha2::{Digest, Sha256};
use typenum::U32;
use x25519_dalek::{PublicKey, StaticSecret};

use quinn::crypto::rustls::QuicClientConfig;

/// TLS handshake type bytes used by the JLS message walk.
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const HANDSHAKE_SERVER_HELLO: u8 = 2;
const HANDSHAKE_HEADER: usize = 4;
const RANDOM_OFFSET_IN_BODY: usize = 2;
const RANDOM_LEN: usize = 32;
const EXT_PRE_SHARED_KEY: u16 = 41;

/// JLS uses AES-256-GCM with the 32-byte SHA-256 nonce, not the usual 12-byte
/// GCM nonce.
type Aes256Gcm32 = AesGcm<Aes256, U32>;

/// Account material carried by the outbound (`username`/`password`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JlsCredentials {
    pub username: String,
    pub password: String,
}

/// Per-connection authentication result, shared with the certificate verifier.
#[derive(Debug)]
pub struct JlsState {
    phase: AtomicU8,
}

const PHASE_PENDING: u8 = 0;
const PHASE_AUTHENTICATED: u8 = 1;
const PHASE_REJECTED: u8 = 2;

impl JlsState {
    pub fn new() -> JlsState {
        JlsState {
            phase: AtomicU8::new(PHASE_PENDING),
        }
    }

    pub fn authenticated(&self) -> bool {
        self.phase.load(Ordering::Acquire) == PHASE_AUTHENTICATED
    }

    pub fn rejected(&self) -> bool {
        self.phase.load(Ordering::Acquire) == PHASE_REJECTED
    }

    fn mark_authenticated(&self) {
        self.phase.store(PHASE_AUTHENTICATED, Ordering::Release);
    }

    fn mark_rejected(&self) {
        self.phase.store(PHASE_REJECTED, Ordering::Release);
    }
}

impl Default for JlsState {
    fn default() -> Self {
        JlsState::new()
    }
}

fn derive_key(credentials: &JlsCredentials, auth_data: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(credentials.password.as_bytes());
    hash.update(auth_data);
    hash.finalize().into()
}

fn derive_nonce(credentials: &JlsCredentials, auth_data: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(credentials.username.as_bytes());
    hash.update(auth_data);
    hash.finalize().into()
}

fn cipher(credentials: &JlsCredentials, auth_data: &[u8]) -> Option<Aes256Gcm32> {
    Aes256Gcm32::new_from_slice(&derive_key(credentials, auth_data)).ok()
}

/// Seal a 16-byte seed into the 32-byte `random` field.
pub fn seal_random(
    credentials: &JlsCredentials,
    auth_data: &[u8],
    seed: &[u8],
) -> Option<[u8; RANDOM_LEN]> {
    if seed.len() != RANDOM_LEN / 2 {
        return None;
    }
    let cipher = cipher(credentials, auth_data)?;
    let nonce = derive_nonce(credentials, auth_data);
    let sealed = cipher
        .encrypt(aes_gcm::Nonce::<U32>::from_slice(&nonce), seed)
        .ok()?;
    sealed.try_into().ok()
}

/// Open the 32-byte `random` field; `true` means the account authenticated it.
pub fn verify_random(credentials: &JlsCredentials, auth_data: &[u8], random: &[u8]) -> bool {
    if random.len() != RANDOM_LEN {
        return false;
    }
    let Some(cipher) = cipher(credentials, auth_data) else {
        return false;
    };
    let nonce = derive_nonce(credentials, auth_data);
    matches!(
        cipher.decrypt(aes_gcm::Nonce::<U32>::from_slice(&nonce), random),
        Ok(plain) if plain.len() == RANDOM_LEN / 2
    )
}

/// Recover the 16-byte seed from a sealed `random` (used by vectors and tests).
pub fn open_random(
    credentials: &JlsCredentials,
    auth_data: &[u8],
    random: &[u8],
) -> Option<[u8; RANDOM_LEN / 2]> {
    if random.len() != RANDOM_LEN {
        return None;
    }
    let cipher = cipher(credentials, auth_data)?;
    let nonce = derive_nonce(credentials, auth_data);
    let plain = cipher
        .decrypt(aes_gcm::Nonce::<U32>::from_slice(&nonce), random)
        .ok()?;
    plain.try_into().ok()
}

/// One handshake message: `(type, body_offset, total_len)`.
fn handshake_message(data: &[u8]) -> Option<(u8, usize, usize)> {
    if data.len() < HANDSHAKE_HEADER {
        return None;
    }
    let len = (usize::from(data[1]) << 16) | (usize::from(data[2]) << 8) | usize::from(data[3]);
    let total = HANDSHAKE_HEADER.checked_add(len)?;
    if data.len() < total {
        return None;
    }
    Some((data[0], HANDSHAKE_HEADER, total))
}

/// Offset of the 32-byte random within the complete message.
fn random_range(message: &[u8]) -> Option<std::ops::Range<usize>> {
    let (_, body, total) = handshake_message(message)?;
    let start = body
        .checked_add(RANDOM_OFFSET_IN_BODY)
        .filter(|start| start + RANDOM_LEN <= total)?;
    Some(start..start + RANDOM_LEN)
}

/// Parse the extensions vector of a ClientHello/ServerHello body.
fn extensions(body: &[u8]) -> Option<(usize, usize)> {
    // legacy_version(2) + random(32) + session_id(1 + n) + cipher_suites(2 + n)
    // + compression_methods(1 + n) + extensions(2 + n)
    let mut at = 0usize;
    at = at.checked_add(2 + RANDOM_LEN)?;
    let session = *body.get(at)? as usize;
    at = at.checked_add(1 + session)?;
    let suites = {
        let hi = *body.get(at)? as usize;
        let lo = *body.get(at + 1)? as usize;
        (hi << 8) | lo
    };
    at = at.checked_add(2 + suites)?;
    let compression = *body.get(at)? as usize;
    at = at.checked_add(1 + compression)?;
    let ext_len = {
        let hi = *body.get(at)? as usize;
        let lo = *body.get(at + 1)? as usize;
        (hi << 8) | lo
    };
    at = at.checked_add(2)?;
    let end = at.checked_add(ext_len)?;
    if end > body.len() {
        return None;
    }
    Some((at, end))
}

/// Zero every PSK binder byte, matching `jlsZeroPSKBinders` on the server.
fn zero_psk_binders(message: &mut [u8]) -> Option<()> {
    let (_, body_offset, total) = handshake_message(message)?;
    if total != message.len() || message[0] != HANDSHAKE_CLIENT_HELLO {
        return None;
    }
    // Extensions are addressed relative to the body; the offsets returned by
    // `extensions` are body-relative too.
    let body = &mut message[body_offset..total];
    let (mut at, end) = extensions(body)?;
    while at + 4 <= end {
        let kind = (usize::from(body[at]) << 8) | usize::from(body[at + 1]);
        let len = (usize::from(body[at + 2]) << 8) | usize::from(body[at + 3]);
        let data = at + 4;
        let data_end = data.checked_add(len)?;
        if data_end > end {
            return None;
        }
        if kind == usize::from(EXT_PRE_SHARED_KEY) {
            // identities<7..2^16-1> then binders<33..2^16-1>: each binder is
            // u8 length + bytes; only the bytes are zeroed.
            let identities_len = (usize::from(body[data]) << 8) | usize::from(body[data + 1]);
            let mut pos = data + 2 + identities_len;
            if pos + 2 > data_end {
                return None;
            }
            let binders_len = (usize::from(body[pos]) << 8) | usize::from(body[pos + 1]);
            pos += 2;
            let binders_end = pos.checked_add(binders_len)?;
            if binders_end > data_end {
                return None;
            }
            while pos < binders_end {
                let binder = usize::from(body[pos]);
                pos += 1;
                if pos + binder > binders_end {
                    return None;
                }
                for byte in &mut body[pos..pos + binder] {
                    *byte = 0;
                }
                pos += binder;
            }
        }
        at = data_end;
    }
    Some(())
}

/// JLS auth data for a ClientHello: the full message with `random` and the PSK
/// binders zeroed. This is exactly what the pinned server reconstructs from
/// `clientHelloMsg.original`.
pub fn client_hello_auth_data(message: &[u8]) -> Option<Vec<u8>> {
    if message.first().copied() != Some(HANDSHAKE_CLIENT_HELLO) {
        return None;
    }
    let (_, _, total) = handshake_message(message)?;
    let mut data = message[..total].to_vec();
    let range = random_range(&data)?;
    data[range].fill(0);
    zero_psk_binders(&mut data)?;
    Some(data)
}

/// JLS auth data for a ServerHello: the full message with `random` zeroed.
pub fn server_hello_auth_data(message: &[u8]) -> Option<Vec<u8>> {
    if message.first().copied() != Some(HANDSHAKE_SERVER_HELLO) {
        return None;
    }
    let (_, _, total) = handshake_message(message)?;
    let mut data = message[..total].to_vec();
    let range = random_range(&data)?;
    data[range].fill(0);
    Some(data)
}

/// The pinned client regenerates a seed when the sealed value looks like a TLS
/// downgrade canary or a HelloRetryRequest random. The comparison is only the
/// final 8 bytes (the canary length).
fn forbidden_random_suffix(random: &[u8]) -> bool {
    const CANARY_LEN: usize = 8;
    const TLS12: &[u8; 8] = b"DOWNGRD\x01";
    const TLS11: &[u8; 8] = b"DOWNGRD\x00";
    if random.len() < CANARY_LEN {
        return false;
    }
    let suffix = &random[random.len() - CANARY_LEN..];
    if suffix == TLS12 || suffix == TLS11 {
        return true;
    }
    // SHA-256("HelloRetryRequest") is the RFC 8446 HRR random; its last 8 bytes
    // are what the pinned helper compares.
    const HRR: [u8; 32] = [
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
        0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
        0x33, 0x9c,
    ];
    suffix == &HRR[HRR.len() - CANARY_LEN..]
}

/// Deterministic randomness log shared by the dry and replay sessions.
#[derive(Debug)]
pub struct JlsRng {
    state: Mutex<RngState>,
}

#[derive(Debug)]
struct RngState {
    mode: RngMode,
    calls: Vec<Vec<u8>>,
    next: usize,
}

#[derive(Debug)]
enum RngMode {
    /// Generate fresh OS randomness and record every fill.
    Record,
    /// Replay a recorded log, replacing one fill with the sealed random.
    Replay {
        override_call: usize,
        sealed: [u8; RANDOM_LEN],
    },
}

impl JlsRng {
    fn recording() -> Arc<JlsRng> {
        Arc::new(JlsRng {
            state: Mutex::new(RngState {
                mode: RngMode::Record,
                calls: Vec::new(),
                next: 0,
            }),
        })
    }

    /// Clone the recorded log and replace `override_call` with `sealed`.
    fn replay(source: &Arc<JlsRng>, override_call: usize, sealed: [u8; RANDOM_LEN]) -> Arc<JlsRng> {
        let calls = match source.state.lock() {
            Ok(state) => state.calls.clone(),
            Err(poisoned) => poisoned.into_inner().calls.clone(),
        };
        Arc::new(JlsRng {
            state: Mutex::new(RngState {
                mode: RngMode::Replay {
                    override_call,
                    sealed,
                },
                calls,
                next: 0,
            }),
        })
    }

    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        let index = state.next;
        state.next += 1;
        match &state.mode {
            RngMode::Record => {
                rand::rngs::OsRng.fill_bytes(buf);
                state.calls.push(buf.to_vec());
                Ok(())
            }
            RngMode::Replay {
                override_call,
                sealed,
            } => {
                if index == *override_call {
                    if buf.len() != RANDOM_LEN {
                        return Err(GetRandomFailed);
                    }
                    buf.copy_from_slice(sealed);
                    return Ok(());
                }
                let Some(call) = state.calls.get(index) else {
                    // The real session consumed randomness the dry session did
                    // not; the replay itself is no longer trustworthy.
                    return Err(GetRandomFailed);
                };
                if call.len() != buf.len() {
                    return Err(GetRandomFailed);
                }
                buf.copy_from_slice(call);
                Ok(())
            }
        }
    }

    fn recorded_calls(&self) -> Vec<Vec<u8>> {
        match self.state.lock() {
            Ok(state) => state.calls.clone(),
            Err(poisoned) => poisoned.into_inner().calls.clone(),
        }
    }
}

thread_local! {
    static ACTIVE_RNG: RefCell<Option<Arc<JlsRng>>> = const { RefCell::new(None) };
}

/// `CryptoProvider`'s `SecureRandom` is a `'static` reference. The value it
/// reads is thread-local and set only for the synchronous `start_session`
/// call; any randomness requested outside that window fails the handshake
/// instead of falling back to an unrecorded source.
#[derive(Debug)]
struct ThreadRandom;

static THREAD_RANDOM: ThreadRandom = ThreadRandom;

impl SecureRandom for ThreadRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        ACTIVE_RNG.with(|cell| match cell.borrow().as_ref() {
            Some(rng) => rng.fill(buf),
            None => Err(GetRandomFailed),
        })
    }
}

fn set_active_rng(rng: Option<Arc<JlsRng>>) {
    ACTIVE_RNG.with(|cell| *cell.borrow_mut() = rng);
}

struct ActiveRngGuard;

impl Drop for ActiveRngGuard {
    fn drop(&mut self) {
        set_active_rng(None);
    }
}

#[derive(Debug)]
struct JlsX25519;

static JLS_X25519: JlsX25519 = JlsX25519;

struct JlsX25519Exchange {
    secret: StaticSecret,
    public: [u8; 32],
}

impl fmt::Debug for JlsX25519Exchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JlsX25519Exchange").finish_non_exhaustive()
    }
}

impl SupportedKxGroup for JlsX25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, TlsError> {
        let mut seed = [0u8; 32];
        THREAD_RANDOM
            .fill(&mut seed)
            .map_err(|_| TlsError::General("JLS: no randomness for X25519".to_string()))?;
        let secret = StaticSecret::from(seed);
        let public = PublicKey::from(&secret).to_bytes();
        Ok(Box::new(JlsX25519Exchange { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl ActiveKeyExchange for JlsX25519Exchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, TlsError> {
        let peer: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| TlsError::General("JLS: invalid X25519 peer key".to_string()))?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(TlsError::General(
                "JLS: X25519 shared secret is a small-order point".to_string(),
            ));
        }
        Ok(SharedSecret::from(shared.as_bytes().as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

/// Crypto provider with the recorded X25519 group. The cipher suites and
/// signature algorithms are `ring`'s; only randomness and the key share are
/// redirected.
pub fn provider() -> Arc<CryptoProvider> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups = vec![&JLS_X25519];
    provider.secure_random = &THREAD_RANDOM;
    Arc::new(provider)
}

/// Certificate verifier that trusts the JLS-authenticated camouflage
/// certificate and otherwise delegates to the normal verifier (the pinned
/// client does the same). A failed JLS check aborts the handshake, so this is
/// only the path for a server that did not authenticate.
#[derive(Debug)]
pub struct JlsVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    state: Arc<JlsState>,
}

impl JlsVerifier {
    pub fn new(inner: Arc<dyn ServerCertVerifier>, state: Arc<JlsState>) -> JlsVerifier {
        JlsVerifier { inner, state }
    }
}

impl ServerCertVerifier for JlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if self.state.authenticated() {
            return Ok(ServerCertVerified::assertion());
        }
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn jls_transport_error(reason: &'static str) -> TransportError {
    TransportError {
        // TLS alert 42 (bad_certificate) is the closest QUIC mapping for an
        // authentication failure and terminates the handshake.
        code: TransportErrorCode::crypto(42),
        frame: None,
        reason: reason.to_string(),
    }
}

/// quinn crypto config that seals the ClientHello random and verifies the
/// ServerHello one.
pub struct JlsClientConfig {
    inner: Arc<QuicClientConfig>,
    credentials: JlsCredentials,
    state: Arc<JlsState>,
}

impl JlsClientConfig {
    pub fn new(
        inner: QuicClientConfig,
        credentials: JlsCredentials,
        state: Arc<JlsState>,
    ) -> JlsClientConfig {
        JlsClientConfig {
            inner: Arc::new(inner),
            credentials,
            state,
        }
    }
}

impl CryptoClientConfig for JlsClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        let guard = ActiveRngGuard;
        let setup = build_session(&self, version, server_name, params);
        drop(guard);
        match setup {
            Ok((session, pending, keys)) => Ok(Box::new(JlsSession {
                inner: session,
                pending,
                pending_keys: keys,
                credentials: self.credentials.clone(),
                state: self.state.clone(),
                server_hello: Vec::new(),
                server_hello_done: false,
                fatal: None,
            })),
            Err(reason) => {
                // Keep the connection constructible; the first handshake read
                // reports the JLS setup failure explicitly instead of sending
                // an unauthenticated shadowquic request.
                set_active_rng(Some(JlsRng::recording()));
                let result = self
                    .inner
                    .clone()
                    .start_session(version, server_name, params);
                set_active_rng(None);
                let inner = result?;
                Ok(Box::new(JlsSession {
                    inner,
                    pending: Vec::new(),
                    pending_keys: None,
                    credentials: self.credentials.clone(),
                    state: self.state.clone(),
                    server_hello: Vec::new(),
                    server_hello_done: true,
                    fatal: Some(jls_transport_error(reason)),
                }))
            }
        }
    }
}

/// Build the dry and replay sessions and check the substituted ClientHello.
fn build_session(
    config: &Arc<JlsClientConfig>,
    version: u32,
    server_name: &str,
    params: &TransportParameters,
) -> Result<(Box<dyn Session>, Vec<u8>, Option<Keys>), &'static str> {
    // Extremely rarely the sealed random ends in a canary suffix; the pinned
    // client regenerates the seed. Retry with fresh randomness a few times.
    for _attempt in 0..4 {
        let dry_rng = JlsRng::recording();
        set_active_rng(Some(dry_rng.clone()));
        let mut dry = config
            .inner
            .clone()
            .start_session(version, server_name, params)
            .map_err(|_| "JLS: dry rustls session could not start")?;
        let mut dry_hello = Vec::new();
        let _ = dry.write_handshake(&mut dry_hello);
        let (_, _, total) =
            handshake_message(&dry_hello).ok_or("JLS: rustls emitted no complete ClientHello")?;
        if total != dry_hello.len() {
            return Err("JLS: rustls emitted data after the ClientHello");
        }
        let auth_data = client_hello_auth_data(&dry_hello)
            .ok_or("JLS: client hello authentication data could not be built")?;
        let range = random_range(&dry_hello).ok_or("JLS: client hello random is missing")?;
        let seed = &dry_hello[range.clone()];
        let seed = &seed[..RANDOM_LEN / 2];
        let sealed = seal_random(&config.credentials, &auth_data, seed)
            .ok_or("JLS: the client hello random could not be sealed")?;
        if forbidden_random_suffix(&sealed) {
            continue;
        }

        // Locate the one recorded fill that produced this random. The random
        // itself is a 32-byte fill; the session id and the X25519 key share are
        // also 32-byte fills, so match by value.
        let calls = dry_rng.recorded_calls();
        let mut override_call = None;
        for (index, call) in calls.iter().enumerate() {
            if call.as_slice() == &dry_hello[range.clone()] {
                override_call = Some(index);
                break;
            }
        }
        let override_call =
            override_call.ok_or("JLS: the client hello random fill was not recorded")?;

        let real_rng = JlsRng::replay(&dry_rng, override_call, sealed);
        set_active_rng(Some(real_rng));
        let mut real = config
            .inner
            .clone()
            .start_session(version, server_name, params)
            .map_err(|_| "JLS: replay rustls session could not start")?;
        let mut real_hello = Vec::new();
        let keys = real.write_handshake(&mut real_hello);

        let mut expected = dry_hello.clone();
        expected[range.clone()].copy_from_slice(&sealed);
        if real_hello != expected {
            return Err("JLS: replay ClientHello differs from the dry ClientHello");
        }
        return Ok((real, real_hello, keys));
    }
    Err("JLS: no acceptable sealed random after retries")
}

/// `Session` wrapper that verifies the server's ServerHello random before
/// handing the handshake bytes to rustls.
struct JlsSession {
    inner: Box<dyn Session>,
    /// The ClientHello produced inside `start_session`; quinn must receive it
    /// from the first `write_handshake`.
    pending: Vec<u8>,
    pending_keys: Option<Keys>,
    credentials: JlsCredentials,
    state: Arc<JlsState>,
    server_hello: Vec<u8>,
    server_hello_done: bool,
    fatal: Option<TransportError>,
}

impl Session for JlsSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        self.inner.initial_keys(dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.inner.handshake_data()
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        self.inner.early_crypto()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.inner.early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        if let Some(error) = self.fatal.take() {
            return Err(error);
        }
        if !self.server_hello_done {
            self.server_hello.extend_from_slice(buf);
            if let Some((kind, _, total)) = handshake_message(&self.server_hello) {
                if kind != HANDSHAKE_SERVER_HELLO {
                    self.state.mark_rejected();
                    return Err(jls_transport_error(
                        "shadowquic: JLS expected a ServerHello first",
                    ));
                }
                let message = &self.server_hello[..total];
                let auth_data = server_hello_auth_data(message)
                    .ok_or_else(|| jls_transport_error("shadowquic: malformed JLS ServerHello"))?;
                let range = random_range(message).ok_or_else(|| {
                    jls_transport_error("shadowquic: JLS ServerHello random is missing")
                })?;
                if verify_random(&self.credentials, &auth_data, &message[range]) {
                    self.state.mark_authenticated();
                } else {
                    self.state.mark_rejected();
                    return Err(jls_transport_error(
                        "shadowquic: JLS ServerHello did not authenticate the account",
                    ));
                }
                self.server_hello_done = true;
                self.server_hello.clear();
            }
        }
        self.inner.read_handshake(buf)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        self.inner.transport_parameters()
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        if !self.pending.is_empty() {
            buf.extend_from_slice(&self.pending);
            self.pending.clear();
            return self.pending_keys.take();
        }
        self.inner.write_handshake(buf)
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        self.inner.next_1rtt_keys()
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.inner.is_valid_retry(orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials() -> JlsCredentials {
        JlsCredentials {
            username: "alice".to_string(),
            password: "correct horse battery staple".to_string(),
        }
    }

    /// A minimal but well-formed TLS 1.3 ClientHello.
    fn client_hello(seed: [u8; 16]) -> Vec<u8> {
        let mut random = [0u8; RANDOM_LEN];
        random[..16].copy_from_slice(&seed);
        // The last 16 bytes are the second random half; keep them arbitrary.
        for (index, byte) in random[16..].iter_mut().enumerate() {
            *byte = index as u8;
        }
        // body: legacy_version(2) + random(32) + session_id(1) + suites(2+2)
        // + compression(1+1) + extensions(2+0)
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&random);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&[0x00, 0x00]);
        let mut message = vec![HANDSHAKE_CLIENT_HELLO];
        message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        message.extend_from_slice(&body);
        message
    }

    #[test]
    fn seal_and_verify_round_trip() {
        let hello = client_hello([7u8; 16]);
        let auth = client_hello_auth_data(&hello).expect("auth data");
        let sealed = seal_random(&credentials(), &auth, &[7u8; 16]).expect("seal");
        assert_eq!(sealed.len(), RANDOM_LEN);
        assert!(verify_random(&credentials(), &auth, &sealed));
        assert_eq!(open_random(&credentials(), &auth, &sealed), Some([7u8; 16]));

        let mut wrong = credentials();
        wrong.password = "wrong".to_string();
        assert!(!verify_random(&wrong, &auth, &sealed));

        let mut tampered = sealed;
        tampered[0] ^= 1;
        assert!(!verify_random(&credentials(), &auth, &tampered));
    }

    #[test]
    fn auth_data_zeroes_the_random_and_keeps_the_message_length() {
        let hello = client_hello([0x22u8; 16]);
        let auth = client_hello_auth_data(&hello).expect("auth data");
        assert_eq!(auth.len(), hello.len());
        let range = random_range(&hello).unwrap();
        assert!(auth[range.clone()].iter().all(|byte| *byte == 0));
        assert_eq!(&auth[..range.start], &hello[..range.start]);
        assert_eq!(&auth[range.end..], &hello[range.end..]);
    }

    #[test]
    fn server_hello_auth_data_zeroes_only_the_random() {
        let mut hello = client_hello([0x33u8; 16]);
        hello[0] = HANDSHAKE_SERVER_HELLO;
        let auth = server_hello_auth_data(&hello).expect("auth data");
        let range = random_range(&hello).unwrap();
        assert!(auth[range.clone()].iter().all(|byte| *byte == 0));
        assert_eq!(&auth[range.end..], &hello[range.end..]);
    }

    #[test]
    fn rejects_truncated_and_wrong_messages() {
        let hello = client_hello([1u8; 16]);
        assert!(client_hello_auth_data(&hello[..hello.len() - 1]).is_none());
        assert!(server_hello_auth_data(&hello).is_none());
        assert!(client_hello_auth_data(&[]).is_none());
    }

    #[test]
    fn replay_returns_recorded_bytes_and_the_override() {
        let record = JlsRng::recording();
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        record.fill(&mut first).unwrap();
        record.fill(&mut second).unwrap();
        assert_eq!(record.recorded_calls().len(), 2);

        let replay = JlsRng::replay(&record, 1, [0xaa; 32]);
        let mut again_first = [0u8; 32];
        let mut again_second = [0u8; 32];
        replay.fill(&mut again_first).unwrap();
        replay.fill(&mut again_second).unwrap();
        assert_eq!(again_first, first);
        assert_eq!(again_second, [0xaa; 32]);
    }

    #[test]
    fn canary_suffix_is_detected() {
        let mut random = [0u8; 32];
        random[24..].copy_from_slice(b"DOWNGRD\x01");
        assert!(forbidden_random_suffix(&random));
        random[24..].copy_from_slice(b"DOWNGRD\x00");
        assert!(forbidden_random_suffix(&random));
        random[24..].copy_from_slice(b"NOTACANA");
        assert!(!forbidden_random_suffix(&random));
    }

    fn from_hex(text: &str) -> Vec<u8> {
        assert_eq!(text.len() % 2, 0, "odd hex length");
        text.as_bytes()
            .chunks(2)
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    b'A'..=b'F' => byte - b'A' + 10,
                    other => panic!("bad hex byte {other}"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    fn vectors() -> (JlsCredentials, Vec<u8>, Vec<u8>) {
        let text = include_str!("../../tests/data/shadowquic-jls.txt");
        let mut username = None;
        let mut password = None;
        let mut client_hello = None;
        let mut server_hello = None;
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key {
                "username" => username = Some(value.to_string()),
                "password" => password = Some(value.to_string()),
                "client_hello" => client_hello = Some(from_hex(value)),
                "server_hello" => server_hello = Some(from_hex(value)),
                _ => {}
            }
        }
        (
            JlsCredentials {
                username: username.expect("vector username"),
                password: password.expect("vector password"),
            },
            client_hello.expect("vector client hello"),
            server_hello.expect("vector server hello"),
        )
    }

    /// Cross-check against `jls-tls` itself: the vector is a real handshake
    /// captured by `tool/kernel-compat/peers/shadowquic-jls-vectors`.
    #[test]
    fn verifies_locked_jls_client_and_server_hellos() {
        let (credentials, client_hello, server_hello) = vectors();

        let client_auth = client_hello_auth_data(&client_hello).expect("client auth data");
        let client_range = random_range(&client_hello).expect("client random range");
        let sealed = &client_hello[client_range.clone()];
        assert!(
            verify_random(&credentials, &client_auth, sealed),
            "the Rust JLS key/nonce/GCM derivation must open the pinned client random"
        );
        let seed = open_random(&credentials, &client_auth, sealed).expect("open seed");
        let resealed = seal_random(&credentials, &client_auth, &seed).expect("reseal");
        assert_eq!(
            &resealed[..],
            sealed,
            "sealing is deterministic and matches"
        );
        let mut wrong = credentials.clone();
        wrong.username.push('x');
        assert!(!verify_random(&wrong, &client_auth, sealed));

        let server_auth = server_hello_auth_data(&server_hello).expect("server auth data");
        let server_range = random_range(&server_hello).expect("server random range");
        assert!(
            verify_random(&credentials, &server_auth, &server_hello[server_range]),
            "the Rust JLS derivation must open the pinned server random"
        );
    }
}
