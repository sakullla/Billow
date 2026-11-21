//! Strict parsing of the `proxies` list (the protocol outbounds of T4).
//!
//! Every entry is decoded against an explicit option table copied from the
//! pinned Mihomo v1.19.34 source (`adapter/outbound/*.go`). A key the pinned
//! type does not know is ignored exactly as Mihomo ignores it (its decoder
//! tolerates extra keys, so rejecting one would reject a valid
//! configuration); a known option this kernel does not implement fails when
//! its value asks for something, with the index, name, type and the option,
//! e.g.
//!
//! ```text
//! [unsupported] proxies[0] (name=s1, type=hysteria2): option 'up' is not implemented
//! ```
//!
//! So a configuration is never accepted with a silently ignored field.

use std::collections::BTreeMap;
use std::fmt;

use crate::config::ConfigError;
use crate::keys::{parse_uuid, Secret};

/// Shadowsocks AEAD 2017 ciphers (16/32-byte keys, 16-byte tags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsCipher {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20IetfPoly1305,
}

impl SsCipher {
    pub fn key_len(self) -> usize {
        match self {
            SsCipher::Aes128Gcm => 16,
            SsCipher::Aes256Gcm | SsCipher::Chacha20IetfPoly1305 => 32,
        }
    }

    /// Size of the pre-shared key (Mihomo `aeadList` KeySize: 16/24/32), which
    /// differs from the AEAD key length only for aes-192-gcm (not supported).
    pub fn psk_len(self) -> usize {
        self.key_len()
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "aes-128-gcm" => Some(SsCipher::Aes128Gcm),
            "aes-256-gcm" => Some(SsCipher::Aes256Gcm),
            "chacha20-ietf-poly1305" => Some(SsCipher::Chacha20IetfPoly1305),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            SsCipher::Aes128Gcm => "aes-128-gcm",
            SsCipher::Aes256Gcm => "aes-256-gcm",
            SsCipher::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
        }
    }
}

/// TLS settings shared by trojan, vless and the TLS variants of socks5/http.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsSettings {
    /// Server name indication / certificate name; defaults to `server`.
    pub sni: Option<String>,
    /// Also the `Host` value of a WebSocket upgrade.
    pub skip_cert_verify: bool,
    pub alpn: Vec<String>,
}

/// WebSocket transport options (`ws-opts`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WsSettings {
    /// Request path; default `/`.
    pub path: String,
    /// Extra request headers; `Host` is honoured as an override of the
    /// upgrade request's Host (the TLS name still comes from `sni`/`server`).
    pub headers: Vec<(String, String)>,
    pub max_early_data: u64,
    pub early_data_header_name: Option<String>,
    /// Key-less `Upgrade: websocket` handshake followed by raw bytes, as the
    /// pinned client/server do for Xray's HTTP upgrade.
    pub v2ray_http_upgrade: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Outbound {
    pub server: String,
    pub port: u16,
    pub username: Option<Secret>,
    pub password: Option<Secret>,
    pub tls: bool,
    pub tls_settings: TlsSettings,
    /// `dialer-proxy`: reach this server through another configured proxy.
    pub dialer_proxy: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpOutbound {
    pub server: String,
    pub port: u16,
    pub username: Option<Secret>,
    pub password: Option<Secret>,
    pub tls: bool,
    pub tls_settings: TlsSettings,
    /// Extra header lines on the CONNECT request (`headers`); `Host`, `User-Agent`
    /// and proxy authorization headers are fixed by the client.
    pub headers: Vec<(String, String)>,
    pub dialer_proxy: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowsocksOutbound {
    pub server: String,
    pub port: u16,
    pub cipher: SsCipher,
    pub password: Secret,
    /// Shadowsocks AEAD UDP datagrams to the server (Mihomo's SS UDP).
    pub udp: bool,
    pub dialer_proxy: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanOutbound {
    pub server: String,
    pub port: u16,
    pub password: Secret,
    pub tls_settings: TlsSettings,
    pub network: TrojanNetwork,
    pub udp: bool,
    pub dialer_proxy: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrojanNetwork {
    Tcp,
    Ws(WsSettings),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessOutbound {
    pub server: String,
    pub port: u16,
    pub uuid: [u8; 16],
    pub flow: Option<String>,
    pub tls: bool,
    pub tls_settings: TlsSettings,
    pub network: VlessNetwork,
    pub dialer_proxy: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VlessNetwork {
    Tcp,
    Ws(WsSettings),
}

/// AnyTLS (Mihomo `adapter/outbound/anytls.go`): TLS to the server with a
/// SHA-256 password prefix, then a session-multiplexed stream per connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnytlsOutbound {
    pub server: String,
    pub port: u16,
    pub password: Secret,
    pub tls_settings: TlsSettings,
    pub dialer_proxy: Option<String>,
}

/// VMess body cipher (`cipher:` in the pinned `VmessOption`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessCipher {
    /// `auto`: chacha20-poly1305, or aes-128-gcm on the 64-bit targets Mihomo
    /// selects it for (amd64, arm64, s390x). Both are implemented, so the
    /// resolved value is stored explicitly instead of re-deciding at dial time.
    Aes128Gcm,
    Chacha20Poly1305,
    None,
}

impl VmessCipher {
    /// Resolve the configured value the way `transport/vmess.NewClient` does.
    pub fn resolve(name: &str) -> Option<Self> {
        match name {
            "aes-128-gcm" => Some(VmessCipher::Aes128Gcm),
            "chacha20-poly1305" => Some(VmessCipher::Chacha20Poly1305),
            "none" => Some(VmessCipher::None),
            "auto" => Some(if cfg!(any(
                target_arch = "x86_64",
                target_arch = "aarch64",
                target_arch = "s390x"
            )) {
                VmessCipher::Aes128Gcm
            } else {
                VmessCipher::Chacha20Poly1305
            }),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            VmessCipher::Aes128Gcm => "aes-128-gcm",
            VmessCipher::Chacha20Poly1305 => "chacha20-poly1305",
            VmessCipher::None => "none",
        }
    }

    /// AEAD tag length of one body record.
    pub fn overhead(self) -> usize {
        match self {
            VmessCipher::None => 0,
            _ => 16,
        }
    }
}

/// VMess transport (`network:`). Only the byte-stream transports are
/// implemented: `tcp` (optionally over TLS) and `ws` (over TLS, as the pinned
/// VMess listener serves it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmessNetwork {
    Tcp,
    Ws(WsSettings),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmessOutbound {
    pub server: String,
    pub port: u16,
    pub uuid: [u8; 16],
    /// `alterId`: the AEAD header this kernel speaks is the `alterId: 0`
    /// protocol; a non-zero value selects the legacy MD5 header and is
    /// rejected at load time.
    pub alter_id: u16,
    pub cipher: VmessCipher,
    pub tls: bool,
    pub tls_settings: TlsSettings,
    pub network: VmessNetwork,
    pub dialer_proxy: Option<String>,
}

/// TrustTunnel (`transport/trusttunnel`): TLS + HTTP/2 `CONNECT` with Basic
/// proxy authentication. Only the TCP transport is implemented; UDP (`_udp2`),
/// ICMP (`_icmp`) and the QUIC variant are rejected at load time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustTunnelOutbound {
    pub server: String,
    pub port: u16,
    pub username: Secret,
    pub password: Secret,
    pub tls_settings: TlsSettings,
    pub dialer_proxy: Option<String>,
}

/// mieru transport protocol. Only the TCP stream (the protocol's own encoded
/// segments over TCP) is implemented; `transport: UDP` is rejected at load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MieruTransport {
    Tcp,
}

/// mieru (`adapter/outbound/mieru.go` wrapping the GPL-3.0 `enfein/mieru`
/// v3.39.0 module). The wire format is implemented independently from the
/// published protocol description; one TCP session per underlay connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruOutbound {
    pub server: String,
    pub port: Option<u16>,
    pub port_range: Option<(u16, u16)>,
    pub transport: MieruTransport,
    pub username: Secret,
    pub password: Secret,
    pub dialer_proxy: Option<String>,
}

/// Sudoku AEAD method (`aead-method`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SudokuAead {
    Chacha20Poly1305,
    Aes128Gcm,
    None,
}

/// Sudoku multiplex mode. `auto` only reuses an HTTP tunnel connection, which
/// this kernel does not implement, so it behaves like `off` on the legacy
/// mask; `on` (the session mux) is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SudokuMultiplex {
    Off,
    Auto,
}

/// Sudoku (`adapter/outbound/sudoku.go`): table-driven obfuscation, a record
/// layer and the KIP handshake. Only the legacy HTTP mask and TCP sessions
/// are implemented; the HTTP tunnel modes, session multiplexing and UoT are
/// rejected at load with the reason recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SudokuOutbound {
    pub server: String,
    pub port: u16,
    pub key: Secret,
    pub aead_method: SudokuAead,
    pub padding_min: u8,
    pub padding_max: u8,
    pub table_type: String,
    pub custom_table: Option<String>,
    pub custom_tables: Vec<String>,
    pub enable_pure_downlink: bool,
    pub http_mask: bool,
    pub path_root: Option<String>,
    pub multiplex: SudokuMultiplex,
    pub dialer_proxy: Option<String>,
}

/// Snell (`transport/snell`). Versions 1-3 share one request header and an
/// Argon2id-derived AEAD record layer; v4+ change the record layer and are
/// rejected explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnellOutbound {
    pub server: String,
    pub port: u16,
    pub psk: Secret,
    pub version: u8,
    pub obfs: Option<SnellObfs>,
    pub dialer_proxy: Option<String>,
}

/// Snell v2+ HTTP obfuscation (`obfs-opts: {mode: http, host: ...}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnellObfs {
    pub host: String,
}

/// MASQUE (RFC 9298 CONNECT-UDP over HTTP/3). Only the CONNECT-UDP data path
/// is implemented: one QUIC/HTTP/3 association, one request stream per
/// destination, UDP payloads in `DATAGRAM` capsules. The pinned adapter's
/// Cloudflare WARP CONNECT-IP flow (`private-key`/`public-key`, `uri`, `ip`,
/// `ipv6`, `mtu`, `ip-stack`, `remote-dns-resolve`/`dns`) and the `h2` /
/// `h3-l4proxy` networks are rejected by name at load time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasqueOutbound {
    pub server: String,
    pub port: u16,
    pub tls_settings: TlsSettings,
    /// `handshake-timeout` in seconds; 0 keeps the dial timeout.
    pub handshake_timeout: u64,
    /// `udp`: CONNECT-UDP is the only implemented mode, so `false` leaves an
    /// outbound that refuses every dial explicitly.
    pub udp: bool,
}

/// ShadowsocksR stream cipher (`transport/shadowsocks/shadowstream`). Only the
/// stream ciphers are reachable from SSR; AEAD ciphers are not in Mihomo's SSR
/// cipher list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrCipher {
    Dummy,
    Rc4Md5,
    Aes128Cfb,
    Aes192Cfb,
    Aes256Cfb,
    Aes128Ctr,
    Aes192Ctr,
    Aes256Ctr,
    ChaCha20,
    ChaCha20Ietf,
    XChaCha20,
}

impl SsrCipher {
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_uppercase().as_str() {
            "NONE" | "DUMMY" => Some(SsrCipher::Dummy),
            "RC4-MD5" => Some(SsrCipher::Rc4Md5),
            "AES-128-CFB" => Some(SsrCipher::Aes128Cfb),
            "AES-192-CFB" => Some(SsrCipher::Aes192Cfb),
            "AES-256-CFB" => Some(SsrCipher::Aes256Cfb),
            "AES-128-CTR" => Some(SsrCipher::Aes128Ctr),
            "AES-192-CTR" => Some(SsrCipher::Aes192Ctr),
            "AES-256-CTR" => Some(SsrCipher::Aes256Ctr),
            "CHACHA20" => Some(SsrCipher::ChaCha20),
            "CHACHA20-IETF" => Some(SsrCipher::ChaCha20Ietf),
            "XCHACHA20" => Some(SsrCipher::XChaCha20),
            _ => None,
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            SsrCipher::Dummy | SsrCipher::Rc4Md5 => 16,
            SsrCipher::Aes128Cfb | SsrCipher::Aes128Ctr => 16,
            SsrCipher::Aes192Cfb | SsrCipher::Aes192Ctr => 24,
            SsrCipher::Aes256Cfb | SsrCipher::Aes256Ctr => 32,
            SsrCipher::ChaCha20 | SsrCipher::ChaCha20Ietf | SsrCipher::XChaCha20 => 32,
        }
    }

    pub fn iv_len(self) -> usize {
        match self {
            SsrCipher::Dummy => 0,
            SsrCipher::Rc4Md5 | SsrCipher::Aes128Cfb | SsrCipher::Aes192Cfb
            | SsrCipher::Aes256Cfb | SsrCipher::Aes128Ctr | SsrCipher::Aes192Ctr
            | SsrCipher::Aes256Ctr => 16,
            SsrCipher::ChaCha20 => 8,
            SsrCipher::ChaCha20Ietf => 12,
            SsrCipher::XChaCha20 => 24,
        }
    }
}

/// SSR protocol plugin (`transport/ssr/protocol`). `origin` is a pass-through;
/// the others add an authentication block and per-record integrity checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrProtocolKind {
    Origin,
    AuthSha1V4,
    AuthAes128Md5,
    AuthAes128Sha1,
    AuthChainA,
    AuthChainB,
}

impl SsrProtocolKind {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "origin" => Some(SsrProtocolKind::Origin),
            "auth_sha1_v4" => Some(SsrProtocolKind::AuthSha1V4),
            "auth_aes128_md5" => Some(SsrProtocolKind::AuthAes128Md5),
            "auth_aes128_sha1" => Some(SsrProtocolKind::AuthAes128Sha1),
            "auth_chain_a" => Some(SsrProtocolKind::AuthChainA),
            "auth_chain_b" => Some(SsrProtocolKind::AuthChainB),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            SsrProtocolKind::Origin => "origin",
            SsrProtocolKind::AuthSha1V4 => "auth_sha1_v4",
            SsrProtocolKind::AuthAes128Md5 => "auth_aes128_md5",
            SsrProtocolKind::AuthAes128Sha1 => "auth_aes128_sha1",
            SsrProtocolKind::AuthChainA => "auth_chain_a",
            SsrProtocolKind::AuthChainB => "auth_chain_b",
        }
    }

    /// The plugin's own overhead, added to the obfs overhead.
    pub fn overhead(self) -> usize {
        match self {
            SsrProtocolKind::Origin => 0,
            SsrProtocolKind::AuthSha1V4 => 7,
            SsrProtocolKind::AuthAes128Md5 | SsrProtocolKind::AuthAes128Sha1 => 9,
            SsrProtocolKind::AuthChainA | SsrProtocolKind::AuthChainB => 4,
        }
    }
}

/// SSR obfs plugin (`transport/ssr/obfs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrObfsKind {
    Plain,
    HttpSimple,
    HttpPost,
    RandomHead,
    Tls12TicketAuth,
    Tls12TicketFastAuth,
}

impl SsrObfsKind {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "plain" => Some(SsrObfsKind::Plain),
            "http_simple" => Some(SsrObfsKind::HttpSimple),
            "http_post" => Some(SsrObfsKind::HttpPost),
            "random_head" => Some(SsrObfsKind::RandomHead),
            "tls1.2_ticket_auth" => Some(SsrObfsKind::Tls12TicketAuth),
            "tls1.2_ticket_fastauth" => Some(SsrObfsKind::Tls12TicketFastAuth),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            SsrObfsKind::Plain => "plain",
            SsrObfsKind::HttpSimple => "http_simple",
            SsrObfsKind::HttpPost => "http_post",
            SsrObfsKind::RandomHead => "random_head",
            SsrObfsKind::Tls12TicketAuth => "tls1.2_ticket_auth",
            SsrObfsKind::Tls12TicketFastAuth => "tls1.2_ticket_fastauth",
        }
    }

    /// The obfs overhead the protocol plugin folds into its padding schedule.
    pub fn overhead(self) -> usize {
        match self {
            SsrObfsKind::Tls12TicketAuth | SsrObfsKind::Tls12TicketFastAuth => 5,
            _ => 0,
        }
    }
}

/// ShadowsocksR (`adapter/outbound/shadowsocksr.go`). The SSR stack is
/// cipher + obfs + protocol; every stream cipher, protocol and obfs the pinned
/// type registers is implemented here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsrOutbound {
    pub server: String,
    pub port: u16,
    pub password: Secret,
    pub cipher: SsrCipher,
    pub protocol: SsrProtocolKind,
    pub protocol_param: Option<String>,
    pub obfs: SsrObfsKind,
    pub obfs_param: Option<String>,
    pub udp: bool,
    pub dialer_proxy: Option<String>,
}

/// SSH (`adapter/outbound/ssh.go`): an SSH client that opens one
/// `direct-tcpip` channel per dial. Host keys are accepted without
/// verification unless `host-key` pins them, matching Mihomo's
/// `InsecureIgnoreHostKey` default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshOutbound {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: Option<Secret>,
    /// Inline PEM (`-----BEGIN ... PRIVATE KEY-----`); a file path is rejected
    /// by name because the loader has no config-relative path root.
    pub private_key: Option<Secret>,
    pub private_key_passphrase: Option<Secret>,
    /// Authorized-key lines the server key must match; empty accepts any key.
    pub host_key: Vec<String>,
    /// `host-key-algorithms`, in preference order.
    pub host_key_algorithms: Vec<String>,
    pub dialer_proxy: Option<String>,
}

/// Gost relay v2 (`transport/gost/relay.go`): a versioned request header with
/// optional user authentication and target address, then the raw byte stream.
/// The TCP relay, the UDP association and the optional TLS and smux wrappers
/// are implemented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GostRelayOutbound {
    pub server: String,
    pub port: u16,
    /// `forward: true` omits the target-address feature, so the relay server
    /// uses its own configured forward target.
    pub forward: bool,
    pub tls: bool,
    pub tls_settings: TlsSettings,
    /// `mux: true` wraps the server connection in an smux session (one stream
    /// per dial).
    pub mux: bool,
    /// `udp: true` allows UDP associations.
    pub udp: bool,
    pub username: Option<Secret>,
    pub password: Option<Secret>,
    pub dialer_proxy: Option<String>,
}


/// Hysteria2 (`adapter/outbound/hysteria2.go`, `sing-quic/hysteria2`): HTTP/3
/// authentication then one bidirectional QUIC stream per TCP session. Port
/// hopping, the Salamander/Gecko obfuscators, realm and UDP are rejected by
/// name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hysteria2Outbound {
    pub server: String,
    pub port: u16,
    pub password: Secret,
    pub tls_settings: TlsSettings,
    pub alpn: Vec<String>,
    pub receive_bps: u64,
    pub handshake_timeout: u64,
    pub dialer_proxy: Option<String>,
}

/// Hysteria v1 (`adapter/outbound/hysteria.go`, `transport/hysteria/core`):
/// QUIC with a binary control hello and one bidirectional stream per TCP
/// session. Port hopping, the XPlus obfuscator, the `faketcp`/`wechat`
/// transports and UDP datagrams are rejected by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HysteriaOutbound {
    pub server: String,
    pub port: u16,
    pub auth: Vec<u8>,
    pub tls_settings: TlsSettings,
    pub alpn: Vec<String>,
    pub send_bps: u64,
    pub receive_bps: u64,
    pub dialer_proxy: Option<String>,
}

/// TUIC v5 (`adapter/outbound/tuic.go`, `transport/tuic/v5`). One QUIC
/// connection carries a unidirectional authentication stream (`uuid` +
/// TLS-exporter token) and one bidirectional stream per TCP session. Only the
/// v5 `uuid`/`password` form is implemented; the legacy v4 `token` form needs
/// BLAKE3 and is rejected by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuicOutbound {
    pub server: String,
    pub port: u16,
    pub uuid: [u8; 16],
    pub password: Secret,
    /// `ip`: dial this address while the certificate name stays `server`/`sni`.
    pub ip: Option<String>,
    pub tls_settings: TlsSettings,
    pub alpn: Vec<String>,
    pub disable_sni: bool,
    pub heartbeat_interval: u64,
    pub request_timeout: u64,
    pub dialer_proxy: Option<String>,
}

/// One enabled proxy entry. `DIRECT` and `REJECT` are built in and cannot be
/// redefined (Mihomo rejects the duplicate name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxy {
    pub name: String,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Socks5(Socks5Outbound),
    Http(HttpOutbound),
    Shadowsocks(ShadowsocksOutbound),
    Trojan(TrojanOutbound),
    Vless(VlessOutbound),
    Anytls(AnytlsOutbound),
    Vmess(VmessOutbound),
    Snell(SnellOutbound),
    TrustTunnel(TrustTunnelOutbound),
    GostRelay(GostRelayOutbound),
    Ssh(SshOutbound),
    Ssr(SsrOutbound),
    Tuic(TuicOutbound),
    Hysteria(HysteriaOutbound),
    Hysteria2(Hysteria2Outbound),
    Mieru(MieruOutbound),
    Sudoku(SudokuOutbound),
    Masque(MasqueOutbound),
}

impl Protocol {
    fn dialer_proxy(&self) -> Option<&str> {
        match self {
            Protocol::Socks5(p) => p.dialer_proxy.as_deref(),
            Protocol::Http(p) => p.dialer_proxy.as_deref(),
            Protocol::Shadowsocks(p) => p.dialer_proxy.as_deref(),
            Protocol::Trojan(p) => p.dialer_proxy.as_deref(),
            Protocol::Vless(p) => p.dialer_proxy.as_deref(),
            Protocol::Anytls(p) => p.dialer_proxy.as_deref(),
            Protocol::Vmess(p) => p.dialer_proxy.as_deref(),
            Protocol::Snell(p) => p.dialer_proxy.as_deref(),
            Protocol::TrustTunnel(p) => p.dialer_proxy.as_deref(),
            Protocol::GostRelay(p) => p.dialer_proxy.as_deref(),
            Protocol::Ssh(p) => p.dialer_proxy.as_deref(),
            Protocol::Ssr(p) => p.dialer_proxy.as_deref(),
            Protocol::Tuic(p) => p.dialer_proxy.as_deref(),
            Protocol::Hysteria(p) => p.dialer_proxy.as_deref(),
            Protocol::Hysteria2(p) => p.dialer_proxy.as_deref(),
            Protocol::Mieru(p) => p.dialer_proxy.as_deref(),
            Protocol::Sudoku(p) => p.dialer_proxy.as_deref(),
            Protocol::Masque(_) => None,
        }
    }
}

impl Proxy {
    pub fn type_name(&self) -> &'static str {
        match self.protocol {
            Protocol::Socks5(_) => "socks5",
            Protocol::Http(_) => "http",
            Protocol::Shadowsocks(_) => "ss",
            Protocol::Trojan(_) => "trojan",
            Protocol::Vless(_) => "vless",
            Protocol::Anytls(_) => "anytls",
            Protocol::Vmess(_) => "vmess",
            Protocol::Snell(_) => "snell",
            Protocol::TrustTunnel(_) => "trusttunnel",
            Protocol::GostRelay(_) => "gost-relay",
            Protocol::Ssh(_) => "ssh",
            Protocol::Ssr(_) => "ssr",
            Protocol::Tuic(_) => "tuic",
            Protocol::Hysteria(_) => "hysteria",
            Protocol::Hysteria2(_) => "hysteria2",
            Protocol::Mieru(_) => "mieru",
            Protocol::Sudoku(_) => "sudoku",
            Protocol::Masque(_) => "masque",
        }
    }

    pub fn server(&self) -> (&str, u16) {
        match &self.protocol {
            Protocol::Socks5(p) => (&p.server, p.port),
            Protocol::Http(p) => (&p.server, p.port),
            Protocol::Shadowsocks(p) => (&p.server, p.port),
            Protocol::Trojan(p) => (&p.server, p.port),
            Protocol::Vless(p) => (&p.server, p.port),
            Protocol::Anytls(p) => (&p.server, p.port),
            Protocol::Vmess(p) => (&p.server, p.port),
            Protocol::Snell(p) => (&p.server, p.port),
            Protocol::TrustTunnel(p) => (&p.server, p.port),
            Protocol::GostRelay(p) => (&p.server, p.port),
            Protocol::Ssh(p) => (&p.server, p.port),
            Protocol::Ssr(p) => (&p.server, p.port),
            Protocol::Tuic(p) => (&p.server, p.port),
            Protocol::Hysteria(p) => (&p.server, p.port),
            Protocol::Hysteria2(p) => (&p.server, p.port),
            Protocol::Mieru(p) => (
                &p.server,
                p.port
                    .or(p.port_range.map(|(first, _)| first))
                    .unwrap_or(0),
            ),
            Protocol::Sudoku(p) => (&p.server, p.port),
            Protocol::Masque(p) => (&p.server, p.port),
        }
    }

    /// ShadowTLS (the SS/structure listener) is exposed as `type: ss` with a
    /// `plugin`; that combination is reported unsupported, never accepted silently.
    pub fn udp_enabled(&self) -> bool {
        match &self.protocol {
            Protocol::Shadowsocks(p) => p.udp,
            Protocol::Trojan(p) => p.udp,
            Protocol::Ssr(p) => p.udp,
            Protocol::GostRelay(p) => p.udp,
            Protocol::Masque(p) => p.udp,
            _ => false,
        }
    }
}

impl fmt::Display for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (server, port) = self.server();
        write!(f, "{}:{}:{server}:{port}", self.name, self.type_name())
    }
}

/// Values that ask for nothing, as the pinned decoder accepts them: a disabled
/// boolean, an empty string, an empty list/map, or a map whose every value is
/// itself such a no-op (for example `smux: {enabled: false}` or
/// `ech-opts: {enable: false}`). Such a key changes no behaviour in Mihomo, so
/// rejecting it would reject a valid configuration (R2); it is accepted and
/// ignored instead.
fn is_noop_value(value: &serde_yaml::Value) -> bool {
    match value {
        serde_yaml::Value::Null => true,
        serde_yaml::Value::Bool(flag) => !*flag,
        serde_yaml::Value::String(text) => text.is_empty(),
        serde_yaml::Value::Number(number) => number.as_i64() == Some(0) || number.as_u64() == Some(0),
        serde_yaml::Value::Sequence(items) => items.iter().all(is_noop_value),
        serde_yaml::Value::Mapping(map) => map.iter().all(|(_, item)| is_noop_value(item)),
        serde_yaml::Value::Tagged(tagged) => is_noop_value(&tagged.value),
    }
}

/// Blocks Mihomo validates even when empty: `reality-opts` requires a
/// `public-key` and `jls-opts` a `password`/`username`, so their empty form is
/// not a no-op - Mihomo's own `-t` rejects it.
const REQUIRED_FIELDS: &[&str] = &["reality-opts", "jls-opts"];

/// Blocks that require TLS in the pinned version: with TLS off Mihomo rejects
/// them (`REALITY requires TLS`, `ShadowTLS requires TLS`, ...) instead of
/// ignoring them, so the kernel must reject them too.
const REQUIRES_TLS: &[&str] = &["reality-opts", "shadow-tls-opts", "restls-opts", "jls-opts"];

/// Whether a known-but-unimplemented option asks for nothing.
///
/// `is_noop_value` covers the generic shapes; two options carry their switch in
/// a field, so `{enable: false, config: ...}` is disabled even though `config`
/// is set, and `plugin-opts` is only read when `plugin` is set.
fn option_is_noop(key: &str, value: &serde_yaml::Value, plugin_set: bool) -> bool {
    match key {
        // Mihomo's ECH options are only applied when `enable` is true.
        "ech-opts" => match value.as_mapping() {
            Some(map) => {
                let enabled = match map.get(serde_yaml::Value::String("enable".to_string())) {
                    Some(serde_yaml::Value::Bool(flag)) => *flag,
                    Some(serde_yaml::Value::String(text)) => text == "true",
                    _ => false,
                };
                !enabled
            }
            None => is_noop_value(value),
        },
        // The plugin options are ignored unless a plugin is configured.
        "plugin-opts" => !plugin_set || is_noop_value(value),
        _ => is_noop_value(value),
    }
}

/// Options every outbound embeds through the pinned `BasicOption`, so they are
/// part of every type's table.
const BASIC_OPTIONS: &[&str] = &[
    "tfo",
    "mptcp",
    "interface-name",
    "routing-mark",
    "ip-version",
    "dialer-proxy",
];

/// Options that only shape a TLS handshake. With TLS off, Mihomo ignores them,
/// so they are no-ops for `socks5`/`http` (and `vless` without `tls: true`).
fn is_tls_option(key: &str) -> bool {
    matches!(
        key,
        "sni"
            | "skip-cert-verify"
            | "alpn"
            | "name-cert-verify"
            | "fingerprint"
            | "certificate"
            | "private-key"
            | "client-fingerprint"
            | "ech-opts"
            | "reality-opts"
    )
}

/// Parse the `proxies` value. Returns the proxies in file order.
pub fn parse_proxies(value: &serde_yaml::Value) -> Result<Vec<Proxy>, ConfigError> {
    let Some(seq) = value.as_sequence() else {
        if value.is_null() {
            return Ok(Vec::new());
        }
        return Err(ConfigError::InvalidValue(
            "proxies must be a list".to_string(),
        ));
    };
    if seq.is_empty() {
        return Ok(Vec::new());
    }
    let mut proxies: Vec<Proxy> = Vec::with_capacity(seq.len());
    for (index, item) in seq.iter().enumerate() {
        let mapping = item.as_mapping().ok_or_else(|| {
            ConfigError::InvalidValue(format!("proxies[{index}] must be a mapping"))
        })?;
        let proxy = parse_proxy(mapping, index)?;
        if matches!(
            proxy.name.as_str(),
            "DIRECT" | "REJECT" | "REJECT-DROP" | "COMPATIBLE" | "PASS" | "PASS-RULE" | "GLOBAL"
        ) {
            return Err(ConfigError::InvalidValue(format!(
                "proxies[{index}]: proxy name '{}' is reserved by Mihomo",
                proxy.name
            )));
        }
        if let Some(first) = proxies.iter().position(|p| p.name == proxy.name) {
            return Err(ConfigError::InvalidValue(format!(
                "proxies[{index}]: duplicate proxy name '{}' (also proxies[{first}])",
                proxy.name
            )));
        }
        proxies.push(proxy);
    }
    validate_dialer_chain(&proxies)?;
    validate_udp_chains(&proxies)?;
    Ok(proxies)
}

/// A `udp: true` proxy with a `dialer-proxy` needs one SOCKS5 hop: its UDP
/// relay is the only association this kernel can build, and that is what
/// Mihomo's `proxydialer.ListenPacket` uses. Rejecting anything else here makes
/// the limitation visible in `--check` instead of letting a UDP association
/// dial the server directly while TCP goes through the chain.
fn validate_udp_chains(proxies: &[Proxy]) -> Result<(), ConfigError> {
    let index = |name: &str| proxies.iter().position(|proxy| proxy.name == name);
    for (i, proxy) in proxies.iter().enumerate() {
        if !proxy.udp_enabled() {
            continue;
        }
        let mut hops: Vec<&Proxy> = vec![proxy];
        while hops.len() < 9 {
            let next = hops
                .last()
                .and_then(|hop| hop.dialer_proxy())
                .and_then(index);
            match next {
                Some(next) if !hops.iter().any(|hop| std::ptr::eq(*hop, &proxies[next])) => {
                    hops.push(&proxies[next]);
                }
                _ => break,
            }
        }
        match hops.len() {
            1 => {}
            2 => {
                let hop = hops[1];
                if !matches!(hop.protocol, Protocol::Socks5(_)) {
                    return Err(ConfigError::Unsupported(format!(
                        "proxies[{i}] (name={}, type={}): option 'udp' with 'dialer-proxy' '{}' (type={}) is not implemented: only a socks5 hop can carry a UDP association",
                        proxy.name,
                        proxy.type_name(),
                        hop.name,
                        hop.type_name()
                    )));
                }
            }
            _ => {
                return Err(ConfigError::Unsupported(format!(
                    "proxies[{i}] (name={}, type={}): option 'udp' with a multi-hop 'dialer-proxy' chain is not implemented (at most one socks5 hop)",
                    proxy.name,
                    proxy.type_name()
                )))
            }
        }
    }
    Ok(())
}

/// `dialer-proxy` must name a configured proxy (Mihomo also accepts group
/// names; groups are T5, so a group name fails here explicitly) and the
/// references must not form a cycle - the same rules as Mihomo's
/// `validateDialerProxies` (`config/utils.go`).
fn validate_dialer_chain(proxies: &[Proxy]) -> Result<(), ConfigError> {
    let index = |name: &str| proxies.iter().position(|p| p.name == name);
    for (i, proxy) in proxies.iter().enumerate() {
        match proxy.protocol.dialer_proxy() {
            None | Some("") => {}
            Some(target) => {
                if let Some(j) = index(target) {
                    if j == i {
                        return Err(ConfigError::InvalidValue(format!(
                            "proxies[{i}] (name={}): dialer-proxy '{target}' refers to itself",
                            proxy.name
                        )));
                    }
                } else {
                    return Err(ConfigError::ConfigFailed(format!(
                        "proxies[{i}] (name={}): dialer-proxy '{target}' not found (configured proxies: {}; proxy groups are not implemented)",
                        proxy.name,
                        proxies.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", ")
                    )));
                }
            }
        }
    }
    for (start, proxy) in proxies.iter().enumerate() {
        let mut seen = vec![start];
        let mut current = start;
        while let Some(next) = proxies[current].protocol.dialer_proxy().and_then(index) {
            if seen.contains(&next) {
                return Err(ConfigError::InvalidValue(format!(
                    "proxies[{start}] (name={}) has circular dialer-proxy dependency",
                    proxy.name
                )));
            }
            seen.push(next);
            current = next;
        }
    }
    Ok(())
}

impl Proxy {
    /// `dialer-proxy` target name of this proxy.
    pub fn dialer_proxy(&self) -> Option<&str> {
        self.protocol.dialer_proxy()
    }
}

/// Field access for one mapping with error text naming the proxy.
struct Entry<'a> {
    mapping: &'a serde_yaml::Mapping,
    index: usize,
    name: String,
    kind: String,
    used: std::collections::BTreeSet<String>,
}

impl<'a> Entry<'a> {
    fn prefix(&self) -> String {
        format!(
            "proxies[{}] (name={}, type={})",
            self.index,
            display(&self.name),
            display(&self.kind)
        )
    }

    fn unsupported(&self, what: impl fmt::Display) -> ConfigError {
        ConfigError::Unsupported(format!("{}: {what}", self.prefix()))
    }

    fn invalid(&self, what: impl fmt::Display) -> ConfigError {
        ConfigError::InvalidValue(format!("{}: {what}", self.prefix()))
    }

    fn get(&mut self, key: &str) -> Option<&'a serde_yaml::Value> {
        let key_value = serde_yaml::Value::String(key.to_string());
        let value = self.mapping.get(&key_value)?;
        self.used.insert(key.to_string());
        Some(value)
    }

    fn string(&mut self, key: &str) -> Result<Option<String>, ConfigError> {
        let Some(value) = self.get(key) else {
            return Ok(None);
        };
        match value {
            serde_yaml::Value::String(s) => Ok(Some(s.clone())),
            serde_yaml::Value::Null => Ok(None),
            // Weakly-typed input, as Mihomo's decoder accepts it.
            serde_yaml::Value::Number(n) => Ok(Some(n.to_string())),
            serde_yaml::Value::Bool(b) => Ok(Some(b.to_string())),
            other => Err(self.invalid(format!(
                "option '{key}' must be a string, found {}",
                crate::config::kind_name(other)
            ))),
        }
    }

    fn bool(&mut self, key: &str) -> Result<Option<bool>, ConfigError> {
        let Some(value) = self.get(key) else {
            return Ok(None);
        };
        match value {
            serde_yaml::Value::Bool(b) => Ok(Some(*b)),
            serde_yaml::Value::String(s) if s == "true" || s == "false" => Ok(Some(s == "true")),
            serde_yaml::Value::Null => Ok(None),
            other => Err(self.invalid(format!(
                "option '{key}' must be a boolean, found {}",
                crate::config::kind_name(other)
            ))),
        }
    }

    fn int(&mut self, key: &str) -> Result<Option<i64>, ConfigError> {
        let Some(value) = self.get(key) else {
            return Ok(None);
        };
        match value {
            serde_yaml::Value::Number(n) => n
                .as_i64()
                .map(Some)
                .ok_or_else(|| self.invalid(format!("option '{key}' must be an integer"))),
            serde_yaml::Value::String(s) => s.parse::<i64>().map(Some).map_err(|_| {
                self.invalid(format!("option '{key}' must be an integer, found '{s}'"))
            }),
            serde_yaml::Value::Null => Ok(None),
            other => Err(self.invalid(format!(
                "option '{key}' must be an integer, found {}",
                crate::config::kind_name(other)
            ))),
        }
    }

    /// Snell `obfs-opts`: `{mode: http|tls, host: <name>}`. Only the HTTP
    /// simple-obfs layer is implemented; `tls` (the fake TLS handshake) is
    /// rejected by name.
    fn snell_obfs(&mut self) -> Result<Option<SnellObfs>, ConfigError> {
        let Some(value) = self.get("obfs-opts") else {
            return Ok(None);
        };
        let Some(map) = value.as_mapping() else {
            if value.is_null() {
                return Ok(None);
            }
            return Err(self.invalid("option 'obfs-opts' must be a mapping"));
        };
        let mut mode = String::new();
        let mut host = "bing.com".to_string();
        for (key, item) in map {
            let key = key
                .as_str()
                .ok_or_else(|| self.invalid("obfs-opts keys must be strings"))?;
            match key {
                "mode" => match item {
                    serde_yaml::Value::String(text) => mode = text.clone(),
                    serde_yaml::Value::Null => {}
                    other => {
                        return Err(self.invalid(format!(
                            "option 'obfs-opts.mode' must be a string, found {}",
                            crate::config::kind_name(other)
                        )))
                    }
                },
                "host" => match item {
                    serde_yaml::Value::String(text) => host = text.clone(),
                    serde_yaml::Value::Null => {}
                    other => {
                        return Err(self.invalid(format!(
                            "option 'obfs-opts.host' must be a string, found {}",
                            crate::config::kind_name(other)
                        )))
                    }
                },
                other => {
                    return Err(
                        self.unsupported(format!("option 'obfs-opts.{other}' is not implemented"))
                    )
                }
            }
        }
        match mode.as_str() {
            "" => Ok(None),
            "http" => Ok(Some(SnellObfs { host })),
            other => Err(self.unsupported(format!(
                "option 'obfs-opts.mode' value '{other}' is not implemented (http)"
            ))),
        }
    }

    fn port(&mut self) -> Result<u16, ConfigError> {
        let Some(value) = self.get("port") else {
            return Err(self.invalid("missing required option 'port'"));
        };
        let port = match value {
            serde_yaml::Value::Number(n) => n.as_u64(),
            serde_yaml::Value::String(s) => s.parse::<u64>().ok(),
            _ => None,
        };
        match port {
            Some(p) if (1..=u16::MAX as u64).contains(&p) => Ok(p as u16),
            _ => Err(self.invalid(format!(
                "option 'port' {value:?} is not a port in 1..=65535"
            ))),
        }
    }

    fn server(&mut self) -> Result<String, ConfigError> {
        let server = self
            .string("server")?
            .ok_or_else(|| self.invalid("missing required option 'server'"))?;
        if server.is_empty() || server.chars().any(|c| c.is_whitespace()) {
            return Err(self.invalid("option 'server' must be a host name or IP without spaces"));
        }
        Ok(server)
    }

    fn required_string(&mut self, key: &str) -> Result<String, ConfigError> {
        match self.string(key)? {
            Some(v) if !v.is_empty() => Ok(v),
            Some(_) => Err(self.invalid(format!("option '{key}' must not be empty"))),
            None => Err(self.invalid(format!("missing required option '{key}'"))),
        }
    }

    /// TLS options the type declares: `socks5` has no `sni`/`alpn`, `http` no
    /// `alpn` (Mihomo ignores those there, so reading them would apply a value
    /// the reference ignores).
    fn tls_settings(
        &mut self,
        sni: bool,
        alpn: bool,
    ) -> Result<TlsSettings, ConfigError> {
        let sni = if sni {
            self.string("sni")?.filter(|s| !s.is_empty())
        } else {
            None
        };
        let skip = self.bool("skip-cert-verify")?.unwrap_or(false);
        let alpn = if alpn { self.string_list("alpn")? } else { Vec::new() };
        Ok(TlsSettings {
            sni,
            skip_cert_verify: skip,
            alpn,
        })
    }

    fn string_list(&mut self, key: &str) -> Result<Vec<String>, ConfigError> {
        let Some(value) = self.get(key) else {
            return Ok(Vec::new());
        };
        match value {
            serde_yaml::Value::Sequence(items) => items
                .iter()
                .map(|item| match item {
                    serde_yaml::Value::String(s) => Ok(s.clone()),
                    other => Err(self.invalid(format!(
                        "option '{key}' entries must be strings, found {}",
                        crate::config::kind_name(other)
                    ))),
                })
                .collect(),
            serde_yaml::Value::Null => Ok(Vec::new()),
            other => Err(self.invalid(format!(
                "option '{key}' must be a list, found {}",
                crate::config::kind_name(other)
            ))),
        }
    }

    fn string_map(&mut self, key: &str) -> Result<Vec<(String, String)>, ConfigError> {
        let Some(value) = self.get(key) else {
            return Ok(Vec::new());
        };
        match value {
            serde_yaml::Value::Mapping(map) => map
                .iter()
                .map(|(k, v)| match (k, v) {
                    (serde_yaml::Value::String(k), serde_yaml::Value::String(v)) => {
                        Ok((k.clone(), v.clone()))
                    }
                    _ => Err(self.invalid(format!("option '{key}' must map strings to strings"))),
                })
                .collect(),
            serde_yaml::Value::Null => Ok(Vec::new()),
            other => Err(self.invalid(format!(
                "option '{key}' must be a mapping, found {}",
                crate::config::kind_name(other)
            ))),
        }
    }

    /// `ws-opts` / `grpc-opts` / `h2-opts` / `http-opts` / `reality-opts` blocks.
    /// Only `ws-opts` with the common fields is implemented; the other blocks
    /// are left to [`Entry::reject_unknown`], which rejects them when they
    /// carry content and accepts the empty/disabled form Mihomo accepts.
    /// A nested option block; `null` is the same as absent, anything else
    /// must be a mapping (as the pinned decoder expects).
    fn block(&mut self, key: &str) -> Result<Option<&'a serde_yaml::Mapping>, ConfigError> {
        let Some(value) = self.get(key) else {
            return Ok(None);
        };
        match value {
            serde_yaml::Value::Mapping(map) => Ok(Some(map)),
            serde_yaml::Value::Null => Ok(None),
            other => Err(self.invalid(format!(
                "option '{key}' must be a mapping, found {}",
                crate::config::kind_name(other)
            ))),
        }
    }

    fn ws_settings(&mut self) -> Result<WsSettings, ConfigError> {
        let default_ws = || WsSettings {
            path: "/".to_string(),
            ..WsSettings::default()
        };
        let Some(value) = self.get("ws-opts") else {
            return Ok(default_ws());
        };
        let Some(map) = value.as_mapping() else {
            if value.is_null() {
                return Ok(default_ws());
            }
            return Err(self.invalid("option 'ws-opts' must be a mapping"));
        };
        let mut ws = WsSettings {
            path: "/".to_string(),
            ..WsSettings::default()
        };
        for (k, v) in map {
            let key = k
                .as_str()
                .ok_or_else(|| self.invalid("ws-opts keys must be strings"))?;
            match key {
                "path" => match v {
                    serde_yaml::Value::String(s) => ws.path = s.clone(),
                    serde_yaml::Value::Null => {}
                    other => {
                        return Err(self.invalid(format!(
                            "option 'ws-opts.path' must be a string, found {}",
                            crate::config::kind_name(other)
                        )))
                    }
                },
                "headers" => {
                    let serde_yaml::Value::Mapping(headers) = v else {
                        return Err(self.invalid("option 'ws-opts.headers' must be a mapping"));
                    };
                    for (hk, hv) in headers {
                        match (hk, hv) {
                            (serde_yaml::Value::String(hk), serde_yaml::Value::String(hv)) => {
                                ws.headers.push((hk.clone(), hv.clone()))
                            }
                            _ => {
                                return Err(self.invalid(
                                    "option 'ws-opts.headers' must map strings to strings",
                                ))
                            }
                        }
                    }
                }
                "max-early-data" => match v {
                    serde_yaml::Value::Number(n) => ws.max_early_data = n.as_u64().unwrap_or(0),
                    serde_yaml::Value::Null => {}
                    other => {
                        return Err(self.invalid(format!(
                            "option 'ws-opts.max-early-data' must be a number, found {}",
                            crate::config::kind_name(other)
                        )))
                    }
                },
                "early-data-header-name" => match v {
                    serde_yaml::Value::String(s) => ws.early_data_header_name = Some(s.clone()),
                    serde_yaml::Value::Null => {}
                    other => {
                        return Err(self.invalid(format!(
                            "option 'ws-opts.early-data-header-name' must be a string, found {}",
                            crate::config::kind_name(other)
                        )))
                    }
                },
                "v2ray-http-upgrade" => match v {
                    serde_yaml::Value::Bool(b) => ws.v2ray_http_upgrade = *b,
                    serde_yaml::Value::Null => {}
                    other => {
                        return Err(self.invalid(format!(
                            "option 'ws-opts.v2ray-http-upgrade' must be a boolean, found {}",
                            crate::config::kind_name(other)
                        )))
                    }
                },
                "v2ray-http-upgrade-fast-open" => match v {
                    serde_yaml::Value::Bool(false) | serde_yaml::Value::Null => {}
                    serde_yaml::Value::Bool(true) => {
                        return Err(self.unsupported(
                            "option 'ws-opts.v2ray-http-upgrade-fast-open' is not implemented",
                        ))
                    }
                    other => {
                        return Err(self.invalid(format!(
                        "option 'ws-opts.v2ray-http-upgrade-fast-open' must be a boolean, found {}",
                        crate::config::kind_name(other)
                    )))
                    }
                },
                other => {
                    return Err(
                        self.unsupported(format!("option 'ws-opts.{other}' is not implemented"))
                    )
                }
            }
        }
        if ws.max_early_data > 0
            || ws
                .early_data_header_name
                .as_deref()
                .is_some_and(|name| !name.is_empty())
        {
            return Err(self.unsupported("ws early data ('ws-opts.max-early-data' / 'ws-opts.early-data-header-name') is not implemented"));
        }
        if !ws.path.starts_with('/') {
            return Err(self.invalid("option 'ws-opts.path' must start with '/'"));
        }
        Ok(ws)
    }

    /// Reject every key this proxy's parser did not honour.
    ///
    /// `mihomo_options` is the option table of the pinned type: a key that is
    /// in it but was not read by the parser is a real Mihomo option this
    /// kernel does not implement, so it fails instead of being ignored. A key
    /// outside the table is not a Mihomo option at all (Mihomo's decoder
    /// rejects it too). Only keys in `used` - the ones the parser read and
    /// honoured - pass, which is what keeps the capability statements in
    /// `tool/kernel-compat/evidence/rust-mapping.json` honest.
    fn reject_unknown(
        &self,
        mihomo_options: &[&str],
        tls_enabled: bool,
        network: Option<&str>,
    ) -> Result<(), ConfigError> {
        for (key, value) in self.mapping {
            let Some(key) = key.as_str() else {
                return Err(self.invalid("option names must be strings"));
            };
            let key = key.replace('_', "-");
            if self.used.contains(&key) {
                continue;
            }
            // Not part of this type's table in the pinned version: Mihomo's
            // decoder tolerates extra keys (a newer option, a typo, an option
            // of another proxy type), so the same file must load here. A key
            // is only "known but unimplemented" when this type declares it.
            if !mihomo_options.contains(&key.as_str()) && !BASIC_OPTIONS.contains(&key.as_str()) {
                continue;
            }
            // A transport block for a transport the configuration did not
            // select is ignored by Mihomo (only the selected `network` is
            // read), so it changes nothing here either.
            if let Some(selected) = network {
                let transport = match key.as_str() {
                    "grpc-opts" => Some("grpc"),
                    "http-opts" => Some("http"),
                    "h2-opts" => Some("h2"),
                    "xhttp-opts" => Some("xhttp"),
                    _ => None,
                };
                if let Some(transport) = transport {
                    if transport != selected {
                        continue;
                    }
                }
            }
            let plugin_set = self
                .mapping
                .get(serde_yaml::Value::String("plugin".to_string()))
                .and_then(|plugin| plugin.as_str())
                .is_some_and(|plugin| !plugin.is_empty());
            let noop = option_is_noop(&key, value, plugin_set);
            if REQUIRED_FIELDS.contains(&key.as_str()) && noop {
                return Err(self.unsupported(format!(
                    "option '{key}' must set its required fields (Mihomo rejects the empty block)"
                )));
            }
            if !tls_enabled && REQUIRES_TLS.contains(&key.as_str()) && !noop {
                return Err(self.unsupported(format!(
                    "option '{key}' requires 'tls: true' (Mihomo rejects it without TLS)"
                )));
            }
            // A TLS-only option with TLS off is ignored by Mihomo, and a value
            // that asks for nothing is ignored as well: both are valid
            // configurations, so they load and have no effect here either.
            if !tls_enabled && is_tls_option(&key) {
                continue;
            }
            if noop {
                continue;
            }
            return Err(self.unsupported(format!("option '{key}' is not implemented")));
        }
        Ok(())
    }
}

fn parse_proxy(mapping: &serde_yaml::Mapping, index: usize) -> Result<Proxy, ConfigError> {
    let key_name = serde_yaml::Value::String("name".to_string());
    let key_type = serde_yaml::Value::String("type".to_string());
    let name = match mapping.get(&key_name) {
        Some(serde_yaml::Value::String(s)) if !s.is_empty() => s.clone(),
        Some(_) => format!("<proxies[{index}]>"),
        None => {
            return Err(ConfigError::InvalidValue(format!(
                "proxies[{index}]: missing required option 'name'"
            )))
        }
    };
    let kind = match mapping.get(&key_type) {
        Some(serde_yaml::Value::String(s)) if !s.is_empty() => s.clone(),
        Some(_) => "<missing>".to_string(),
        None => "<missing>".to_string(),
    };
    let mut entry = Entry {
        mapping,
        index,
        name,
        kind,
        used: ["name", "type"].into_iter().map(str::to_string).collect(),
    };
    let name = entry.name.clone();
    let kind = entry.kind.clone();
    let protocol = match kind.as_str() {
        "socks5" => Protocol::Socks5(parse_socks5(&mut entry)?),
        "http" => Protocol::Http(parse_http(&mut entry)?),
        "ss" => Protocol::Shadowsocks(parse_shadowsocks(&mut entry)?),
        "trojan" => Protocol::Trojan(parse_trojan(&mut entry)?),
        "vless" => Protocol::Vless(parse_vless(&mut entry)?),
        "anytls" => Protocol::Anytls(parse_anytls(&mut entry)?),
        "vmess" => Protocol::Vmess(parse_vmess(&mut entry)?),
        "snell" => Protocol::Snell(parse_snell(&mut entry)?),
        "trusttunnel" => Protocol::TrustTunnel(parse_trusttunnel(&mut entry)?),
        "gost-relay" => Protocol::GostRelay(parse_gost_relay(&mut entry)?),
        "ssh" => Protocol::Ssh(parse_ssh(&mut entry)?),
        "ssr" => Protocol::Ssr(parse_ssr(&mut entry)?),
        "tuic" => Protocol::Tuic(parse_tuic(&mut entry)?),
        "hysteria" => Protocol::Hysteria(parse_hysteria(&mut entry)?),
        "hysteria2" => Protocol::Hysteria2(parse_hysteria2(&mut entry)?),
        "mieru" => Protocol::Mieru(parse_mieru(&mut entry)?),
        "sudoku" => Protocol::Sudoku(parse_sudoku(&mut entry)?),
        "masque" => Protocol::Masque(parse_masque(&mut entry)?),
        "shadowquic" => {
            return Err(entry.unsupported(
                "protocol type 'shadowquic' is not implemented: the pinned client (transport/shadowquic + jls-tls) requires JLS, a custom TLS extension and a modified QUIC stack; rustls/quinn cannot express it, and no JLS crate is in the offline cargo cache",
            ))
        }
        "wireguard" => {
            return Err(entry.unsupported(
                "protocol type 'wireguard' is not implemented: the pinned outbound terminates WireGuard (Noise IK, cookie, transport keys) and exposes TCP/UDP through a gVisor netstack; this kernel has no WireGuard transport or IP stack (device/TUN ownership is T6/T7) and no boringtun/wireguard crate is in the offline cargo cache",
            ))
        }
        "tailscale" => {
            return Err(entry.unsupported(
                "protocol type 'tailscale' is not implemented: the pinned outbound (with_gvisor) embeds the tailscale.com control plane and a gVisor netstack; device/TUN ownership is T6/T7 and no Rust tailscale stack is available offline",
            ))
        }
        "zerotier" => {
            return Err(entry.unsupported(
                "protocol type 'zerotier' is not implemented: the pinned outbound wraps zerotier-go (identity, planet, control protocol, crypto) plus a gVisor netstack; device/TUN ownership is T6/T7 and no Rust zerotier stack is available offline",
            ))
        }
        "easytier" => {
            return Err(entry.unsupported(
                "protocol type 'easytier' is not implemented: the pinned outbound embeds the easytier-go host/instance (peer discovery, encryption, KCP/QUIC proxies) plus a netstack; device/TUN ownership is T6/T7 and no Rust easytier stack is available offline",
            ))
        }
        "openvpn" => {
            return Err(entry.unsupported(
                "protocol type 'openvpn' is not implemented: the pinned outbound implements OpenVPN (TLS control channel, data ciphers, tls-auth/tls-crypt) and exposes TCP/UDP through a gVisor netstack; device/TUN ownership is T6/T7 and no Rust OpenVPN stack is available offline",
            ))
        }

        other => {
            return Err(ConfigError::Unsupported(format!(
                "{}: protocol type '{other}' is not implemented (implemented: socks5, http, ss, trojan, vless, anytls, vmess, snell, trusttunnel, gost-relay, ssh, ssr, tuic, hysteria, hysteria2, mieru, sudoku, masque)",
                entry.prefix()
            )))
        }
    };
    Ok(Proxy { name, protocol })
}

fn parse_socks5(entry: &mut Entry<'_>) -> Result<Socks5Outbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    let username = entry
        .string("username")?
        .filter(|s| !s.is_empty())
        .map(Secret::new);
    let password = entry
        .string("password")?
        .filter(|s| !s.is_empty())
        .map(Secret::new);
    let tls = entry.bool("tls")?.unwrap_or(false);
    let tls_settings = entry.tls_settings(false, false)?;
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    // `udp: false` states the same thing this outbound does (no UDP); `true`
    // would need a UDP association this kernel does not open to a SOCKS5 peer.
    if entry.bool("udp")?.unwrap_or(false) {
        return Err(entry.unsupported(
            "option 'udp' is not implemented for socks5 (UDP over proxies is implemented for ss and trojan)",
        ));
    }
    let allowed = [
        "dialer-proxy",
        "name",
        "type",
        "server",
        "port",
        "username",
        "password",
        "tls",
        "udp",
        "skip-cert-verify",
        "name-cert-verify",
        "fingerprint",
        "certificate",
        "private-key",
        "ip-version",
    ];
    entry.reject_unknown(&allowed, tls, None)?;
    if password.is_some() && username.is_none() {
        return Err(entry.invalid("option 'password' requires 'username'"));
    }
    Ok(Socks5Outbound {
        server,
        port,
        username,
        password,
        tls,
        tls_settings,
        dialer_proxy,
    })
}

fn parse_http(entry: &mut Entry<'_>) -> Result<HttpOutbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    let username = entry
        .string("username")?
        .filter(|s| !s.is_empty())
        .map(Secret::new);
    let password = entry
        .string("password")?
        .filter(|s| !s.is_empty())
        .map(Secret::new);
    let tls = entry.bool("tls")?.unwrap_or(false);
    let tls_settings = entry.tls_settings(true, false)?;
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    let headers = entry.string_map("headers")?;
    // Mihomo's HTTP outbound has no `udp` option at all, so any occurrence is
    // rejected by the option check below (it is absent from the table).
    let allowed = [
        "dialer-proxy",
        "name",
        "type",
        "server",
        "port",
        "username",
        "password",
        "tls",
        "sni",
        "skip-cert-verify",
        "name-cert-verify",
        "fingerprint",
        "certificate",
        "private-key",
        "headers",
        "ip-version",
    ];
    entry.reject_unknown(&allowed, tls, None)?;
    if password.is_some() && username.is_none() {
        return Err(entry.invalid("option 'password' requires 'username'"));
    }
    for (key, _) in &headers {
        if [
            "host",
            "user-agent",
            "proxy-authorization",
            "proxy-connection",
            "content-length",
        ]
        .iter()
        .any(|fixed| key.eq_ignore_ascii_case(fixed))
        {
            return Err(entry.unsupported(format!(
                "request header '{key}' (fixed by the CONNECT client) is not implemented"
            )));
        }
    }
    Ok(HttpOutbound {
        server,
        port,
        username,
        password,
        tls,
        tls_settings,
        headers,
        dialer_proxy,
    })
}

fn parse_shadowsocks(entry: &mut Entry<'_>) -> Result<ShadowsocksOutbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    let cipher_name = entry.required_string("cipher")?;
    let cipher = SsCipher::from_name(&cipher_name).ok_or_else(|| {
        entry.unsupported(format!(
            "option 'cipher' value '{cipher_name}' is not implemented (supported: aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305)"
        ))
    })?;
    let password = Secret::new(entry.required_string("password")?);
    let udp = entry.bool("udp")?.unwrap_or(false);
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    let plugin = entry.string("plugin")?;
    // `plugin-opts` is only read when a plugin is configured (see
    // `option_is_noop`); with no plugin it is a no-op, as in Mihomo.
    let _ = entry.get("plugin-opts");
    let allowed = [
        "dialer-proxy",
        "name",
        "type",
        "server",
        "port",
        "password",
        "cipher",
        "udp",
        "plugin",
        "plugin-opts",
        "udp-over-tcp",
        "udp-over-tcp-version",
        "client-fingerprint",
        "ip-version",
    ];
    entry.reject_unknown(&allowed, false, None)?;
    if let Some(plugin) = plugin.filter(|p| !p.is_empty()) {
        return Err(entry.unsupported(format!(
            "option 'plugin' value '{plugin}' is not implemented"
        )));
    }
    Ok(ShadowsocksOutbound {
        server,
        port,
        cipher,
        password,
        udp,
        dialer_proxy,
    })
}

fn parse_trojan(entry: &mut Entry<'_>) -> Result<TrojanOutbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    let password = Secret::new(entry.required_string("password")?);
    if password.expose().len() > 56 {
        return Err(entry.invalid("option 'password' longer than 56 bytes"));
    }
    let tls_settings = entry.tls_settings(true, true)?;
    let network = entry
        .string("network")?
        .unwrap_or_else(|| "tcp".to_string());
    let ws = entry.ws_settings()?;
    let selected = network.clone();
    let network = match network.as_str() {
        "tcp" => TrojanNetwork::Tcp,
        "ws" => TrojanNetwork::Ws(ws),
        other => {
            return Err(entry.unsupported(format!(
                "option 'network' value '{other}' is not implemented (tcp, ws)"
            )))
        }
    };
    let udp = entry.bool("udp")?.unwrap_or(false);
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    let allowed = [
        "dialer-proxy",
        "name",
        "type",
        "server",
        "port",
        "password",
        "alpn",
        "sni",
        "skip-cert-verify",
        "name-cert-verify",
        "fingerprint",
        "certificate",
        "private-key",
        "udp",
        "network",
        "ech-opts",
        "shadow-tls-opts",
        "restls-opts",
        "jls-opts",
        "reality-opts",
        "grpc-opts",
        "ws-opts",
        "ss-opts",
        "client-fingerprint",
        "ip-version",
    ];
    entry.reject_unknown(&allowed, true, Some(selected.as_str()))?;
    Ok(TrojanOutbound {
        server,
        port,
        password,
        tls_settings,
        network,
        udp,
        dialer_proxy,
    })
}

fn parse_vless(entry: &mut Entry<'_>) -> Result<VlessOutbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    let uuid_raw = entry.required_string("uuid")?;
    let uuid = parse_uuid(&uuid_raw).map_err(|e| entry.invalid(format!("option 'uuid': {e}")))?;
    let flow = entry.string("flow")?.filter(|s| !s.is_empty());
    if let Some(flow) = &flow {
        return Err(ConfigError::Unsupported(format!(
            "{}: option 'flow' value '{flow}' is not implemented",
            entry.prefix()
        )));
    }
    if let Some(encryption) = entry
        .string("encryption")?
        .filter(|s| !s.is_empty() && s != "none")
    {
        return Err(entry.unsupported(format!(
            "option 'encryption' value '{encryption}' is not implemented (only 'none')"
        )));
    }
    let tls = entry.bool("tls")?.unwrap_or(false);
    let mut tls_settings = entry.tls_settings(true, true)?;
    // `servername` is the pinned type's alias for `sni`.
    if tls_settings.sni.is_none() {
        tls_settings.sni = entry.string("servername")?.filter(|value| !value.is_empty());
    }
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    let network = entry
        .string("network")?
        .unwrap_or_else(|| "tcp".to_string());
    let ws = entry.ws_settings()?;
    let selected = network.clone();
    let network = match network.as_str() {
        "tcp" => VlessNetwork::Tcp,
        "ws" => VlessNetwork::Ws(ws),
        other => return Err(entry.unsupported(format!("option 'network' value '{other}' is not implemented (tcp is always accepted, ws over tls)"))),
    };
    if matches!(network, VlessNetwork::Ws(_)) && !tls {
        // Mihomo runs VLESS with tls: true against `listeners: type: vless`.
        return Err(entry.unsupported(
            "option 'network: ws' requires 'tls: true' (not implemented without TLS)",
        ));
    }
    if let Some(value) = entry.bool("udp")? {
        if value {
            return Err(entry.unsupported("option 'udp' is not implemented for vless"));
        }
    }
    for key in ["packet-addr", "xudp"] {
        if entry.bool(key)?.unwrap_or(false) {
            return Err(entry.unsupported(format!("option '{key}' is not implemented")));
        }
    }
    for key in ["packet-encoding", "ws-headers"] {
        if entry
            .get(key)
            .is_some_and(|value| !is_noop_value(value))
        {
            return Err(entry.unsupported(format!("option '{key}' is not implemented")));
        }
    }
    let allowed = [
        "dialer-proxy",
        "name",
        "type",
        "server",
        "port",
        "uuid",
        "flow",
        "tls",
        "alpn",
        "udp",
        "packet-addr",
        "xudp",
        "packet-encoding",
        "encryption",
        "network",
        "sni",
        "skip-cert-verify",
        "name-cert-verify",
        "fingerprint",
        "certificate",
        "private-key",
        "ech-opts",
        "shadow-tls-opts",
        "restls-opts",
        "jls-opts",
        "reality-opts",
        "http-opts",
        "h2-opts",
        "grpc-opts",
        "ws-opts",
        "xhttp-opts",
        "ws-headers",
        "servername",
        "client-fingerprint",
        "ip-version",
    ];
    entry.reject_unknown(&allowed, tls, Some(selected.as_str()))?;
    Ok(VlessOutbound {
        server,
        port,
        uuid,
        flow: None,
        tls,
        tls_settings,
        network,
        dialer_proxy,
    })
}

fn parse_anytls(entry: &mut Entry<'_>) -> Result<AnytlsOutbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    let password = Secret::new(entry.required_string("password")?);
    let tls_settings = entry.tls_settings(true, true)?;
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    for key in [
        "client-metadata",
        "idle-session-check-interval",
        "idle-session-timeout",
        "min-idle-session",
    ] {
        if entry
            .get(key)
            .is_some_and(|value| !is_noop_value(value))
        {
            return Err(entry.unsupported(format!("option '{key}' is not implemented")));
        }
    }
    if entry.bool("disable-reuse")?.unwrap_or(false) {
        return Err(entry.unsupported("option 'disable-reuse' is not implemented"));
    }
    if entry.bool("udp")?.unwrap_or(false) {
        return Err(entry.unsupported("option 'udp' is not implemented for anytls"));
    }
    let allowed = [
        "dialer-proxy",
        "name",
        "type",
        "server",
        "port",
        "password",
        "alpn",
        "sni",
        "skip-cert-verify",
        "name-cert-verify",
        "fingerprint",
        "certificate",
        "private-key",
        "udp",
        "client-metadata",
        "idle-session-check-interval",
        "idle-session-timeout",
        "min-idle-session",
        "disable-reuse",
        "client-fingerprint",
        "ech-opts",
        "shadow-tls-opts",
        "restls-opts",
        "jls-opts",
        "ip-version",
    ];
    entry.reject_unknown(&allowed, true, None)?;
    Ok(AnytlsOutbound {
        server,
        port,
        password,
        tls_settings,
        dialer_proxy,
    })
}

/// VMess (`adapter/outbound/vmess.go`, `transport/vmess`). Only the AEAD
/// header (`alterId: 0`) and the `tcp`/`ws` byte-stream transports are
/// implemented; every other option the pinned type declares is either a
/// transport this kernel rejects by name or a UDP/mux feature that has no
/// implementation here yet.
fn parse_vmess(entry: &mut Entry<'_>) -> Result<VmessOutbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    let uuid_raw = entry.required_string("uuid")?;
    let uuid = parse_uuid(&uuid_raw).map_err(|e| entry.invalid(format!("option 'uuid': {e}")))?;
    // Mihomo's decoder reports `alterId` and `cipher` as unset fields when they
    // are absent, so a VMess entry without them is invalid there too.
    let alter_id = entry
        .int("alterId")?
        .ok_or_else(|| entry.invalid("missing required option 'alterId' (Mihomo requires it)"))?;
    if alter_id != 0 {
        return Err(entry.unsupported(format!(
            "option 'alterId' value {alter_id} is not implemented (only the AEAD header, alterId 0)"
        )));
    }
    let cipher_name = entry.string("cipher")?.ok_or_else(|| {
        entry.invalid("missing required option 'cipher' (Mihomo requires it; use 'auto')")
    })?;
    let cipher = VmessCipher::resolve(&cipher_name).ok_or_else(|| {
        entry.unsupported(format!(
            "option 'cipher' value '{cipher_name}' is not implemented (auto, aes-128-gcm, chacha20-poly1305, none)"
        ))
    })?;
    let tls = entry.bool("tls")?.unwrap_or(false);
    let mut tls_settings = entry.tls_settings(true, true)?;
    // `servername` is the pinned type's alias for the TLS name.
    if tls_settings.sni.is_none() {
        tls_settings.sni = entry.string("servername")?.filter(|value| !value.is_empty());
    }
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    let network_name = entry
        .string("network")?
        .unwrap_or_else(|| "tcp".to_string());
    let ws = entry.ws_settings()?;
    let selected = network_name.clone();
    let network = match network_name.as_str() {
        "tcp" => VmessNetwork::Tcp,
        "ws" => VmessNetwork::Ws(ws),
        other => {
            return Err(entry.unsupported(format!(
                "option 'network' value '{other}' is not implemented (tcp, ws)"
            )))
        }
    };
    if matches!(network, VmessNetwork::Ws(_)) && !tls {
        return Err(entry.unsupported(
            "option 'network: ws' requires 'tls: true' (the VMess WebSocket listener is TLS-only here)",
        ));
    }
    if entry.bool("udp")?.unwrap_or(false) {
        return Err(entry.unsupported(
            "option 'udp' is not implemented for vmess (no VMess UDP command)",
        ));
    }
    for key in [
        "packet-addr",
        "xudp",
        "global-padding",
        "authenticated-length",
    ] {
        if entry.bool(key)?.unwrap_or(false) {
            return Err(entry.unsupported(format!("option '{key}' is not implemented")));
        }
    }
    if entry
        .string("packet-encoding")?
        .filter(|value| !value.is_empty())
        .is_some()
    {
        return Err(entry.unsupported("option 'packet-encoding' is not implemented"));
    }
    let allowed = [
        "dialer-proxy",
        "name",
        "type",
        "server",
        "port",
        "uuid",
        "alterId",
        "cipher",
        "udp",
        "network",
        "tls",
        "alpn",
        "sni",
        "servername",
        "skip-cert-verify",
        "name-cert-verify",
        "fingerprint",
        "certificate",
        "private-key",
        "ech-opts",
        "shadow-tls-opts",
        "restls-opts",
        "jls-opts",
        "reality-opts",
        "tlsmirror-opts",
        "mekya-opts",
        "mkcp-opts",
        "http-opts",
        "h2-opts",
        "grpc-opts",
        "ws-opts",
        "packet-addr",
        "xudp",
        "packet-encoding",
        "global-padding",
        "authenticated-length",
        "client-fingerprint",
        "ip-version",
    ];
    entry.reject_unknown(&allowed, tls, Some(selected.as_str()))?;
    Ok(VmessOutbound {
        server,
        port,
        uuid,
        alter_id: alter_id as u16,
        cipher,
        tls,
        tls_settings,
        network,
        dialer_proxy,
    })
}

/// Snell (`transport/snell`): versions 1-3 over a raw TCP stream. `version`
/// defaults to 1 (Mihomo's outbound default); 4-6 change the record layer and
/// are rejected by name.
fn parse_snell(entry: &mut Entry<'_>) -> Result<SnellOutbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    let psk = Secret::new(entry.required_string("psk")?);
    let version = entry.int("version")?.unwrap_or(1);
    if !(1..=3).contains(&version) {
        return Err(entry.unsupported(format!(
            "option 'version' value {version} is not implemented (snell v1, v2, v3)"
        )));
    }
    if entry.bool("reuse")?.unwrap_or(false) {
        return Err(entry.unsupported(
            "option 'reuse' is not implemented (one stream per connection)",
        ));
    }
    if let Some(mode) = entry.string("mode")?.filter(|value| !value.is_empty()) {
        return Err(entry.unsupported(format!(
            "option 'mode' value '{mode}' is not implemented (v6 record layer)"
        )));
    }
    let obfs = entry.snell_obfs()?;
    if obfs.is_some() && version < 2 {
        return Err(entry.invalid("option 'obfs-opts' requires version 2 or newer"));
    }
    if entry.bool("udp")?.unwrap_or(false) {
        return Err(entry.unsupported(
            "option 'udp' is not implemented for snell (no UDP command)",
        ));
    }
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    let allowed = [
        "dialer-proxy",
        "name",
        "type",
        "server",
        "port",
        "psk",
        "udp",
        "version",
        "reuse",
        "mode",
        "obfs-opts",
        "client-fingerprint",
        "ip-version",
    ];
    entry.reject_unknown(&allowed, false, None)?;
    Ok(SnellOutbound {
        server,
        port,
        psk,
        version: version as u8,
        obfs,
        dialer_proxy,
    })
}

/// mieru (`adapter/outbound/mieru.go`). The pinned type validates
/// `transport` (`TCP`/`UDP`), `username`/`password`, `multiplexing` and
/// `handshake-mode` names, and decodes `traffic-pattern`. This kernel
/// implements the TCP single-session stream; the UDP transport, mieru
/// multiplexing levels and traffic patterns are rejected with the reason
/// recorded instead of being ignored.
fn parse_mieru(entry: &mut Entry<'_>) -> Result<MieruOutbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.int("port")?;
    let port_range = entry
        .string("port-range")?
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let (port, port_range) = match (port, port_range) {
        (Some(port), None) => {
            if !(1..=65535).contains(&port) {
                return Err(entry.invalid("option 'port' must be between 1 and 65535"));
            }
            (Some(port as u16), None)
        }
        (None, Some(range)) => {
            let (first, last) = range
                .split_once('-')
                .and_then(|(a, b)| {
                    Some((a.trim().parse::<u16>().ok()?, b.trim().parse::<u16>().ok()?))
                })
                .filter(|(first, last)| *first >= 1 && first <= last)
                .ok_or_else(|| {
                    entry.invalid("option 'port-range' must be 'begin-end' within 1..=65535")
                })?;
            (None, Some((first, last)))
        }
        (None, None) => {
            return Err(entry.invalid("either 'port' or 'port-range' must be set"));
        }
        (Some(_), Some(_)) => {
            return Err(entry.invalid("options 'port' and 'port-range' cannot both be set"));
        }
    };
    finish_mieru(entry, server, port, port_range)
}

fn finish_mieru(
    entry: &mut Entry<'_>,
    server: String,
    port: Option<u16>,
    port_range: Option<(u16, u16)>,
) -> Result<MieruOutbound, ConfigError> {
    let transport = match entry.string("transport")? {
        Some(value) => match value.as_str() {
            "TCP" => MieruTransport::Tcp,
            "UDP" => {
                return Err(entry.unsupported(
                    "option 'transport' value 'UDP' is not implemented: only the mieru TCP stream is ported (the UDP protocol uses per-datagram nonces and its own fragment sizing)",
                ))
            }
            other => {
                return Err(entry.invalid(format!(
                    "option 'transport' must be TCP or UDP, found '{other}'"
                )))
            }
        },
        None => {
            return Err(entry.invalid("missing required option 'transport' (TCP)"));
        }
    };
    let username = entry.required_string("username")?;
    let password = entry.required_string("password")?;
    if entry.bool("udp")?.unwrap_or(false) {
        return Err(entry.unsupported(
            "option 'udp' is not implemented for mieru: the UDP associate wrapper is not ported",
        ));
    }
    if let Some(multiplexing) = entry.string("multiplexing")?.filter(|v| !v.is_empty()) {
        match multiplexing.as_str() {
            "MULTIPLEXING_DEFAULT" | "MULTIPLEXING_OFF" => {}
            "MULTIPLEXING_LOW" | "MULTIPLEXING_MIDDLE" | "MULTIPLEXING_HIGH" => {
                return Err(entry.unsupported(format!(
                    "option 'multiplexing' value '{multiplexing}' is not implemented: this kernel opens one session per underlay connection and does not port the mieru mux layer",
                )))
            }
            other => {
                return Err(entry.invalid(format!(
                    "option 'multiplexing' value '{other}' is not a mieru multiplexing level"
                )))
            }
        }
    }
    if let Some(mode) = entry.string("handshake-mode")?.filter(|v| !v.is_empty()) {
        match mode.as_str() {
            // Both modes perform the same handshake; NO_WAIT only defers it
            // until the first write, and the kernel dials eagerly either way.
            "HANDSHAKE_DEFAULT" | "HANDSHAKE_STANDARD" | "HANDSHAKE_NO_WAIT" => {}
            other => {
                return Err(entry.invalid(format!(
                    "option 'handshake-mode' value '{other}' is not a mieru handshake mode"
                )))
            }
        }
    }
    if let Some(pattern) = entry.string("traffic-pattern")?.filter(|v| !v.is_empty()) {
        return Err(entry.unsupported(format!(
            "option 'traffic-pattern' value '{pattern}' is not implemented: it changes padding, nonce rewriting, low-entropy payloads and TCP fragmentation on the wire",
        )));
    }
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    let allowed = [
        "name",
        "type",
        "server",
        "port",
        "port-range",
        "transport",
        "udp",
        "username",
        "password",
        "multiplexing",
        "handshake-mode",
        "traffic-pattern",
        "dialer-proxy",
        "ip-version",
    ];
    entry.reject_unknown(&allowed, false, None)?;
    Ok(MieruOutbound {
        server,
        port,
        port_range,
        transport,
        username: Secret::new(username),
        password: Secret::new(password),
        dialer_proxy,
    })
}

/// Sudoku (`adapter/outbound/sudoku.go`). The pinned type validates the AEAD
/// method, the padding range, the table type and the HTTP mask mode; this
/// kernel implements the legacy mask and TCP sessions and rejects the tunnel
/// modes, the session mux and UoT with the reason recorded.
fn parse_sudoku(entry: &mut Entry<'_>) -> Result<SudokuOutbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    let key = Secret::new(entry.required_string("key")?);
    if key.expose().trim().is_empty() {
        return Err(entry.invalid("option 'key' must not be empty"));
    }
    let aead_method = match entry.string("aead-method")?.unwrap_or_default().as_str() {
        "" | "chacha20-poly1305" => SudokuAead::Chacha20Poly1305,
        "aes-128-gcm" => SudokuAead::Aes128Gcm,
        "none" => SudokuAead::None,
        other => {
            return Err(entry.invalid(format!(
                "option 'aead-method' value '{other}' must be one of: aes-128-gcm, chacha20-poly1305, none"
            )))
        }
    };
    let (padding_min, padding_max) = sudoku_padding(entry)?;
    let table_type = match entry.string("table-type")?.filter(|v| !v.trim().is_empty()) {
        Some(value) => {
            if crate::outbound::sudoku::table::AsciiMode::parse(&value).is_none() {
                return Err(entry.invalid(format!(
                    "option 'table-type' value '{value}' must be prefer_ascii, prefer_entropy, up_ascii_down_entropy or up_entropy_down_ascii"
                )));
            }
            value
        }
        None => "prefer_entropy".to_string(),
    };
    let custom_table = entry
        .string("custom-table")?
        .filter(|v| !v.trim().is_empty());
    let custom_tables = entry
        .string_list("custom-tables")?
        .into_iter()
        .filter(|v| !v.trim().is_empty())
        .collect::<Vec<_>>();
    for pattern in custom_table.iter().chain(custom_tables.iter()) {
        if !crate::outbound::sudoku::table::validate_custom_pattern(pattern) {
            return Err(entry.invalid(format!(
                "custom table pattern '{pattern}' must have 8 symbols with exactly 2 x, 2 p and 4 v"
            )));
        }
    }
    let enable_pure_downlink = entry.bool("enable-pure-downlink")?.unwrap_or(true);
    // `http-mask-tls`/`http-mask-host` only shape the HTTP tunnel modes, which
    // are rejected above; with the legacy mask (and with the mask disabled)
    // Mihomo ignores them, so reading them is only about not rejecting a
    // valid configuration.
    let _ = entry.bool("http-mask-tls")?;
    let _ = entry.string("http-mask-host")?;
    if entry.bool("udp")?.unwrap_or(false) {
        return Err(entry.unsupported(
            "option 'udp' is not implemented for sudoku: the UDP-over-TCP (UoT) association is not ported",
        ));
    }

    // The HTTP mask block and its flat aliases; the pinned decoder lets the
    // block win where both are set.
    let mut http_mask = entry.bool("http-mask")?.unwrap_or(true);
    let mut http_mask_mode = entry.string("http-mask-mode")?.unwrap_or_default();
    let mut path_root = entry.string("path-root")?.filter(|v| !v.trim().is_empty());
    let mut multiplex_name = entry.string("multiplex")?.unwrap_or_default();
    let legacy_multiplex = entry
        .string("http-mask-multiplex")?
        .unwrap_or_default();
    if !legacy_multiplex.trim().is_empty() {
        multiplex_name = legacy_multiplex;
    }
    if let Some(block) = entry.block("httpmask")? {
        http_mask = !block
            .get("disable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if let Some(mode) = block.get("mode").and_then(|v| v.as_str()) {
            if !mode.trim().is_empty() {
                http_mask_mode = mode.to_string();
            }
        }
        if let Some(root) = block.get("path-root").and_then(|v| v.as_str()) {
            if !root.trim().is_empty() {
                path_root = Some(root.to_string());
            }
        }
        if let Some(mux) = block.get("multiplex").and_then(|v| v.as_str()) {
            if !mux.trim().is_empty() {
                multiplex_name = mux.to_string();
            }
        }
    }
    let mode = http_mask_mode.trim().to_ascii_lowercase();
    match mode.as_str() {
        "" | "legacy" => {}
        "stream" | "poll" | "auto" | "ws" => {
            return Err(entry.unsupported(format!(
                "option 'http-mask-mode' value '{mode}' is not implemented: the HTTP tunnel layer (split-stream/poll/WebSocket) is a mihomo extension over Sudoku and is not ported; the legacy mask is"
            )))
        }
        other => {
            return Err(entry.invalid(format!(
                "option 'http-mask-mode' value '{other}' must be one of: legacy, stream, poll, auto, ws"
            )))
        }
    }
    let multiplex = match multiplex_name.trim().to_ascii_lowercase().as_str() {
        "" | "off" => SudokuMultiplex::Off,
        "auto" => SudokuMultiplex::Auto,
        "on" => {
            return Err(entry.unsupported(
                "option 'multiplex' value 'on' is not implemented: the Sudoku session mux (KIPTypeStartMux, stream ids, credit windows) is not ported; one target per connection is",
            ))
        }
        other => {
            return Err(entry.invalid(format!(
                "option 'multiplex' value '{other}' must be one of: off, auto, on"
            )))
        }
    };
    if let Some(root) = path_root.as_deref() {
        if crate::outbound::sudoku::codec::normalized_path_root(root).is_none() {
            return Err(entry.invalid(
                "option 'path-root' must be a single path segment of [A-Za-z0-9_-]",
            ));
        }
    }
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    let allowed = [
        "name",
        "type",
        "server",
        "port",
        "key",
        "aead-method",
        "padding-min",
        "padding-max",
        "table-type",
        "enable-pure-downlink",
        "http-mask",
        "http-mask-mode",
        "http-mask-tls",
        "http-mask-host",
        "path-root",
        "multiplex",
        "http-mask-multiplex",
        "httpmask",
        "custom-table",
        "custom-tables",
        "udp",
        "dialer-proxy",
        "ip-version",
    ];
    entry.reject_unknown(&allowed, false, None)?;
    Ok(SudokuOutbound {
        server,
        port,
        key,
        aead_method,
        padding_min,
        padding_max,
        table_type,
        custom_table,
        custom_tables,
        enable_pure_downlink,
        http_mask,
        path_root,
        multiplex,
        dialer_proxy,
    })
}

/// `ResolvePadding`: each bound defaults independently, and a single bound
/// that would make the range invalid pulls the other one along.
fn sudoku_padding(entry: &mut Entry<'_>) -> Result<(u8, u8), ConfigError> {
    let min = entry.int("padding-min")?;
    let max = entry.int("padding-max")?;
    let range = |value: Option<i64>, name: &str| -> Result<Option<u8>, ConfigError> {
        match value {
            Some(value) if !(0..=100).contains(&value) => Err(entry.invalid(format!(
                "option '{name}' must be between 0 and 100"
            ))),
            Some(value) => Ok(Some(value as u8)),
            None => Ok(None),
        }
    };
    let min = range(min, "padding-min")?;
    let max = range(max, "padding-max")?;
    let (mut low, mut high) = (min.unwrap_or(10), max.unwrap_or(30));
    if min.is_none() && max.is_some() && high < low {
        low = high;
    }
    if max.is_none() && min.is_some() && high < low {
        high = low;
    }
    if high < low {
        return Err(entry.invalid("option 'padding-max' must be >= 'padding-min'"));
    }
    Ok((low, high))
}

/// TrustTunnel (`adapter/outbound/trusttunnel.go`): TLS + HTTP/2 CONNECT with
/// `username`/`password` Basic auth. The UDP (`_udp2`), ICMP (`_icmp`), QUIC
/// and pooled-multiplexing options are rejected by name.
fn parse_trusttunnel(entry: &mut Entry<'_>) -> Result<TrustTunnelOutbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    let username = Secret::new(entry.string("username")?.unwrap_or_default());
    let password = Secret::new(entry.string("password")?.unwrap_or_default());
    let tls_settings = entry.tls_settings(true, true)?;
    if !tls_settings.alpn.is_empty()
        && !tls_settings.alpn.iter().any(|value| value == "h2")
    {
        return Err(entry.unsupported(
            "option 'alpn' without 'h2' is not implemented (TrustTunnel requires the h2 protocol)",
        ));
    }
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    if entry.bool("udp")?.unwrap_or(false) {
        return Err(entry.unsupported(
            "option 'udp' is not implemented for trusttunnel (the `_udp2` multiplex is not implemented)",
        ));
    }
    for key in ["quic", "health-check"] {
        if entry.bool(key)?.unwrap_or(false) {
            return Err(entry.unsupported(format!("option '{key}' is not implemented")));
        }
    }
    for key in ["max-connections", "min-streams", "max-streams"] {
        if entry.int(key)?.unwrap_or(0) != 0 {
            return Err(entry.unsupported(format!(
                "option '{key}' is not implemented (one stream per connection)"
            )));
        }
    }
    for key in ["congestion-controller", "bbr-profile"] {
        if entry
            .string(key)?
            .is_some_and(|value| !value.is_empty())
        {
            return Err(entry.unsupported(format!(
                "option '{key}' is not implemented (QUIC only)"
            )));
        }
    }
    if entry.int("cwnd")?.unwrap_or(0) != 0 {
        return Err(entry.unsupported("option 'cwnd' is not implemented (QUIC only)"));
    }
    let allowed = [
        "dialer-proxy",
        "name",
        "type",
        "server",
        "port",
        "username",
        "password",
        "alpn",
        "sni",
        "skip-cert-verify",
        "name-cert-verify",
        "fingerprint",
        "certificate",
        "private-key",
        "ech-opts",
        "client-fingerprint",
        "udp",
        "health-check",
        "quic",
        "congestion-controller",
        "cwnd",
        "bbr-profile",
        "max-connections",
        "min-streams",
        "max-streams",
        "ip-version",
    ];
    entry.reject_unknown(&allowed, true, None)?;
    Ok(TrustTunnelOutbound {
        server,
        port,
        username,
        password,
        tls_settings,
        dialer_proxy,
    })
}

/// ShadowsocksR (`adapter/outbound/shadowsocksr.go`). The pinned type requires
/// `cipher`, `password`, `protocol` and `obfs`; every cipher, protocol and obfs
/// value it registers is implemented, and `udp: true` opens the pinned UDP
/// association (protocol plugin over the cipher, no obfs).
fn parse_ssr(entry: &mut Entry<'_>) -> Result<SsrOutbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    let cipher_name = entry.required_string("cipher")?;
    let cipher = SsrCipher::from_name(&cipher_name).ok_or_else(|| {
        entry.unsupported(format!(
            "option 'cipher' value '{cipher_name}' is not implemented (SSR stream ciphers: rc4-md5, aes-128/192/256-cfb, aes-128/192/256-ctr, chacha20, chacha20-ietf, xchacha20, none)"
        ))
    })?;
    let password = entry
        .string("password")?
        .ok_or_else(|| entry.invalid("missing required option 'password' (Mihomo requires it)"))?;
    let protocol_name = entry.required_string("protocol")?;
    let protocol = SsrProtocolKind::from_name(&protocol_name).ok_or_else(|| {
        entry.unsupported(format!(
            "option 'protocol' value '{protocol_name}' is not implemented (origin, auth_sha1_v4, auth_aes128_md5, auth_aes128_sha1, auth_chain_a, auth_chain_b)"
        ))
    })?;
    let obfs_name = entry.required_string("obfs")?;
    let obfs = SsrObfsKind::from_name(&obfs_name).ok_or_else(|| {
        entry.unsupported(format!(
            "option 'obfs' value '{obfs_name}' is not implemented (plain, http_simple, http_post, random_head, tls1.2_ticket_auth, tls1.2_ticket_fastauth)"
        ))
    })?;
    let protocol_param = entry.string("protocol-param")?.filter(|s| !s.is_empty());
    let obfs_param = entry.string("obfs-param")?.filter(|s| !s.is_empty());
    let udp = entry.bool("udp")?.unwrap_or(false);
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    let allowed = [
        "dialer-proxy",
        "name",
        "type",
        "server",
        "port",
        "password",
        "cipher",
        "obfs",
        "obfs-param",
        "protocol",
        "protocol-param",
        "udp",
        "ip-version",
    ];
    entry.reject_unknown(&allowed, false, None)?;
    Ok(SsrOutbound {
        server,
        port,
        password: Secret::new(password),
        cipher,
        protocol,
        protocol_param,
        obfs,
        obfs_param,
        udp,
        dialer_proxy,
    })
}

/// SSH (`adapter/outbound/ssh.go`): password and inline-PEM public-key
/// authentication, one `direct-tcpip` channel per dial. The pinned outbound
/// reuses one SSH client for every session; this kernel opens one connection
/// per dial (same wire behaviour, no shared-client lifecycle).
fn parse_ssh(entry: &mut Entry<'_>) -> Result<SshOutbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    // The pinned `SshOption.UserName` has no `omitempty`, so Mihomo reports
    // "unset fields: username" when it is absent; an empty value is accepted.
    let username = entry
        .string("username")?
        .ok_or_else(|| entry.invalid("missing required option 'username' (Mihomo requires it)"))?;
    let password = entry
        .string("password")?
        .filter(|value| !value.is_empty())
        .map(Secret::new);
    let private_key = entry
        .string("private-key")?
        .filter(|value| !value.is_empty());
    let private_key_passphrase = entry
        .string("private-key-passphrase")?
        .filter(|value| !value.is_empty())
        .map(Secret::new);
    if let Some(pem) = &private_key {
        if !pem.contains("PRIVATE KEY") {
            return Err(entry.unsupported(
                "option 'private-key' file paths are not implemented (inline PEM only)",
            ));
        }
        let parsed = russh::keys::PrivateKey::from_openssh(pem.as_bytes()).map_err(|e| {
            entry.invalid(format!("option 'private-key' is not a valid PEM key: {e}"))
        })?;
        if parsed.is_encrypted() {
            let Some(passphrase) = &private_key_passphrase else {
                return Err(entry.invalid(
                    "option 'private-key' is encrypted but 'private-key-passphrase' is absent",
                ));
            };
            parsed.decrypt(passphrase.expose().as_bytes()).map_err(|e| {
                entry.invalid(format!("option 'private-key-passphrase' does not decrypt the key: {e}"))
            })?;
        }
    }
    let host_key = entry.string_list("host-key")?;
    for line in &host_key {
        russh::keys::PublicKey::from_openssh(line).map_err(|e| {
            entry.invalid(format!("option 'host-key' is not an authorized key: {e}"))
        })?;
    }
    let host_key_algorithms = entry.string_list("host-key-algorithms")?;
    for name in &host_key_algorithms {
        use std::str::FromStr;
        russh::keys::Algorithm::from_str(name).map_err(|e| {
            entry.invalid(format!("option 'host-key-algorithms' entry '{name}': {e}"))
        })?;
    }
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    let allowed = [
        "dialer-proxy",
        "name",
        "type",
        "server",
        "port",
        "username",
        "password",
        "private-key",
        "private-key-passphrase",
        "host-key",
        "host-key-algorithms",
        "ip-version",
    ];
    entry.reject_unknown(&allowed, false, None)?;
    Ok(SshOutbound {
        server,
        port,
        username,
        password,
        private_key: private_key.map(Secret::new),
        private_key_passphrase,
        host_key,
        host_key_algorithms,
        dialer_proxy,
    })
}

/// Gost relay (`adapter/outbound/gost_relay.go`, `transport/gost/relay.go`):
/// TCP relay with optional TLS, user authentication and target-address
/// feature, plus the `udp` association and the `mux` smux session.
fn parse_gost_relay(entry: &mut Entry<'_>) -> Result<GostRelayOutbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    let forward = entry.bool("forward")?.unwrap_or(false);
    let tls = entry.bool("tls")?.unwrap_or(false);
    let mux = entry.bool("mux")?.unwrap_or(false);
    let udp = entry.bool("udp")?.unwrap_or(false);
    let tls_settings = entry.tls_settings(true, false)?;
    let username = entry
        .string("username")?
        .filter(|value| !value.is_empty())
        .map(Secret::new);
    let password = entry
        .string("password")?
        .filter(|value| !value.is_empty())
        .map(Secret::new);
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    let allowed = [
        "dialer-proxy",
        "name",
        "type",
        "server",
        "port",
        "forward",
        "udp",
        "tls",
        "mux",
        "sni",
        "username",
        "password",
        "skip-cert-verify",
        "name-cert-verify",
        "fingerprint",
        "certificate",
        "private-key",
        "client-fingerprint",
        "ip-version",
    ];
    entry.reject_unknown(&allowed, tls, None)?;
    Ok(GostRelayOutbound {
        server,
        port,
        forward,
        tls,
        tls_settings,
        mux,
        udp,
        username,
        password,
        dialer_proxy,
    })
}

/// Hysteria2 (`adapter/outbound/hysteria2.go`). `up`/`down` are optional
/// rate hints; the HTTP/3 auth exchange and TCP streams are implemented.
fn parse_hysteria2(entry: &mut Entry<'_>) -> Result<Hysteria2Outbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    let password = Secret::new(entry.string("password")?.unwrap_or_default());
    let tls_settings = entry.tls_settings(true, true)?;
    let alpn = entry.string_list("alpn")?;
    let up = entry.string("up")?;
    if up.as_deref().is_some_and(|value| !value.is_empty()) {
        return Err(entry.unsupported(
            "option 'up' is not implemented: the pinned client uses it to cap the Brutal sender's TX rate; quinn has no Brutal controller, so the value would be ignored",
        ));
    }
    let down = entry.string("down")?.filter(|value| !value.is_empty());
    let receive_bps = down
        .as_deref()
        .map(crate::outbound::hysteria::string_to_bps)
        .unwrap_or(0);
    if down.is_some() && receive_bps == 0 {
        return Err(entry.invalid(format!(
            "option 'down' value '{}' is not a rate",
            down.as_deref().unwrap_or_default()
        )));
    }
    let handshake_timeout = match entry.int("handshake-timeout")? {
        Some(value) if value < 0 => {
            return Err(entry.invalid("option 'handshake-timeout' must not be negative"))
        }
        Some(value) => value as u64,
        None => 0,
    };
    if let Some(ports) = entry.string("ports")?.filter(|value| !value.is_empty()) {
        return Err(entry.unsupported(format!(
            "option 'ports' value '{ports}' is not implemented (port hopping)"
        )));
    }
    if entry
        .string("hop-interval")?
        .is_some_and(|value| !value.is_empty())
    {
        return Err(entry.unsupported("option 'hop-interval' is not implemented (port hopping)"));
    }
    if let Some(obfs) = entry.string("obfs")?.filter(|value| !value.is_empty()) {
        return Err(entry.unsupported(format!(
            "option 'obfs' value '{obfs}' is not implemented (Salamander/Gecko packet obfuscation)"
        )));
    }
    // Only read when obfs is set; without it Mihomo ignores the password too.
    let _ = entry.string("obfs-password")?;
    // The packet-size knobs are only applied by the pinned client when an obfs
    // is selected; without one they ask for nothing, so they load.
    let _ = entry.int("obfs-min-packet-size")?;
    let _ = entry.int("obfs-max-packet-size")?;
    if entry.int("udp-mtu")?.unwrap_or(0) != 0 {
        return Err(entry.unsupported("option 'udp-mtu' is not implemented (UDP relay)"));
    }
    for key in ["cwnd"] {
        if entry.int(key)?.unwrap_or(0) != 0 {
            return Err(entry.unsupported(format!("option '{key}' is not implemented")));
        }
    }
    if entry
        .string("bbr-profile")?
        .is_some_and(|value| !value.is_empty())
    {
        return Err(entry.unsupported("option 'bbr-profile' is not implemented"));
    }
    for key in [
        "initial-stream-receive-window",
        "max-stream-receive-window",
        "initial-connection-receive-window",
        "max-connection-receive-window",
    ] {
        if entry.int(key)?.unwrap_or(0) != 0 {
            return Err(entry.unsupported(format!("option '{key}' is not implemented")));
        }
    }
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    let allowed = [
        "dialer-proxy",
        "name",
        "type",
        "server",
        "port",
        "ports",
        "hop-interval",
        "up",
        "down",
        "password",
        "obfs",
        "obfs-password",
        "obfs-min-packet-size",
        "obfs-max-packet-size",
        "sni",
        "skip-cert-verify",
        "name-cert-verify",
        "fingerprint",
        "certificate",
        "private-key",
        "alpn",
        "cwnd",
        "bbr-profile",
        "udp-mtu",
        "handshake-timeout",
        "realm-opts",
        "initial-stream-receive-window",
        "max-stream-receive-window",
        "initial-connection-receive-window",
        "max-connection-receive-window",
        "ech-opts",
        "client-fingerprint",
        "ip-version",
    ];
    entry.reject_unknown(&allowed, true, None)?;
    Ok(Hysteria2Outbound {
        server,
        port,
        password,
        tls_settings,
        alpn,
        receive_bps,
        handshake_timeout,
        dialer_proxy,
    })
}

/// Hysteria v1 (`adapter/outbound/hysteria.go`). `up` and `down` are required
/// by the pinned type; they only tune congestion control, which this client
/// leaves to quinn. Port hopping, the XPlus obfuscator, the `faketcp`/`wechat`
/// transports and UDP datagrams are rejected by name.
fn parse_hysteria(entry: &mut Entry<'_>) -> Result<HysteriaOutbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    let up = entry.required_string("up")?;
    let down = entry.required_string("down")?;
    let up_speed = entry.int("up-speed")?.unwrap_or(0);
    let down_speed = entry.int("down-speed")?.unwrap_or(0);
    let send_bps = if up_speed != 0 {
        (up_speed.max(0) as u64).saturating_mul(125_000)
    } else {
        crate::outbound::hysteria::string_to_bps(&up)
    };
    let receive_bps = if down_speed != 0 {
        (down_speed.max(0) as u64).saturating_mul(125_000)
    } else {
        crate::outbound::hysteria::string_to_bps(&down)
    };
    if send_bps == 0 {
        return Err(entry.invalid(format!(
            "option 'up' value '{up}' is not a rate (use e.g. '50 Mbps' or '1000000')"
        )));
    }
    if receive_bps == 0 {
        return Err(entry.invalid(format!(
            "option 'down' value '{down}' is not a rate (use e.g. '50 Mbps' or '1000000')"
        )));
    }
    let auth = match entry.string("auth")?.filter(|value| !value.is_empty()) {
        Some(encoded) => crate::outbound::hysteria::decode_base64(&encoded)
            .map_err(|e| entry.invalid(format!("option 'auth': {e}")))?,
        None => entry
            .string("auth-str")?
            .filter(|value| !value.is_empty())
            .map(|value| value.into_bytes())
            .unwrap_or_default(),
    };
    if let Some(protocol) = entry
        .string("obfs-protocol")?
        .or(entry.string("protocol")?)
        .filter(|value| !value.is_empty())
    {
        if protocol != "udp" {
            return Err(entry.unsupported(format!(
                "option 'protocol' value '{protocol}' is not implemented (udp)"
            )));
        }
    }
    if let Some(obfs) = entry.string("obfs")?.filter(|value| !value.is_empty()) {
        return Err(entry.unsupported(format!(
            "option 'obfs' value '{obfs}' is not implemented (XPlus obfuscator)"
        )));
    }
    if let Some(ports) = entry.string("ports")?.filter(|value| !value.is_empty()) {
        return Err(entry.unsupported(format!(
            "option 'ports' value '{ports}' is not implemented (port hopping)"
        )));
    }
    if entry.int("hop-interval")?.unwrap_or(0) != 0 {
        return Err(entry.unsupported("option 'hop-interval' is not implemented (port hopping)"));
    }
    for key in ["recv-window-conn", "recv-window"] {
        if entry.int(key)?.unwrap_or(0) != 0 {
            return Err(entry.unsupported(format!("option '{key}' is not implemented")));
        }
    }
    if entry.bool("disable-mtu-discovery")?.unwrap_or(false) {
        return Err(entry.unsupported("option 'disable-mtu-discovery' is not implemented"));
    }
    if entry.bool("fast-open")?.unwrap_or(false) {
        return Err(entry.unsupported("option 'fast-open' is not implemented"));
    }
    let tls_settings = entry.tls_settings(true, true)?;
    let alpn = entry.string_list("alpn")?;
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    let allowed = [
        "dialer-proxy",
        "name",
        "type",
        "server",
        "port",
        "ports",
        "protocol",
        "obfs-protocol",
        "up",
        "up-speed",
        "down",
        "down-speed",
        "auth",
        "auth-str",
        "obfs",
        "sni",
        "skip-cert-verify",
        "name-cert-verify",
        "fingerprint",
        "certificate",
        "private-key",
        "alpn",
        "recv-window-conn",
        "recv-window",
        "disable-mtu-discovery",
        "fast-open",
        "hop-interval",
        "ech-opts",
        "client-fingerprint",
        "ip-version",
    ];
    entry.reject_unknown(&allowed, true, None)?;
    Ok(HysteriaOutbound {
        server,
        port,
        auth,
        tls_settings,
        alpn,
        send_bps,
        receive_bps,
        dialer_proxy,
    })
}

/// TUIC (`adapter/outbound/tuic.go`, `transport/tuic/v5`). `uuid`/`password`
/// select the v5 protocol; the legacy v4 `token` (BLAKE3 TKN) is rejected.
/// Options that only tune a pooled client (congestion controller, receive
/// windows, MTU discovery, 0-RTT) or the UDP relay are rejected by name when
/// they ask for something, instead of being silently ignored.
fn parse_tuic(entry: &mut Entry<'_>) -> Result<TuicOutbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    if let Some(token) = entry.string("token")?.filter(|value| !value.is_empty()) {
        let _ = token;
        return Err(entry.unsupported(
            "option 'token' selects the legacy TUIC v4 protocol (BLAKE3 TKN), which is not implemented; use 'uuid' and 'password' (v5)",
        ));
    }
    let uuid_raw = entry.string("uuid")?.unwrap_or_default();
    let uuid = if uuid_raw.is_empty() {
        [0u8; 16]
    } else {
        parse_uuid(&uuid_raw).map_err(|e| entry.invalid(format!("option 'uuid': {e}")))?
    };
    let password = Secret::new(entry.string("password")?.unwrap_or_default());
    let ip = entry.string("ip")?.filter(|value| !value.is_empty());
    let mut tls_settings = entry.tls_settings(true, true)?;
    let disable_sni = entry.bool("disable-sni")?.unwrap_or(false);
    // The pinned client sets both `ServerName = ""` and
    // `InsecureSkipVerify = true` for `disable-sni` (TLS needs one of them).
    if disable_sni {
        tls_settings.skip_cert_verify = true;
    }
    let heartbeat_interval = match entry.int("heartbeat-interval")? {
        Some(value) if value < 0 => {
            return Err(entry.invalid("option 'heartbeat-interval' must not be negative"))
        }
        Some(0) | None => 10_000,
        Some(value) => value as u64,
    };
    let request_timeout = match entry.int("request-timeout")? {
        Some(value) if value < 0 => {
            return Err(entry.invalid("option 'request-timeout' must not be negative"))
        }
        Some(0) | None => 8_000,
        Some(value) => value as u64,
    };
    if let Some(mode) = entry.string("udp-relay-mode")?.filter(|value| !value.is_empty()) {
        if mode == "quic" {
            return Err(entry.unsupported(
                "option 'udp-relay-mode' value 'quic' is not implemented (TUIC UDP datagram relay)",
            ));
        }
    }
    for key in [
        "congestion-controller",
        "bbr-profile",
        "max-udp-relay-packet-size",
        "cwnd",
        "recv-window-conn",
        "recv-window",
        "max-datagram-frame-size",
        "udp-over-stream-version",
    ] {
        let requested = if key == "congestion-controller" || key == "bbr-profile" {
            entry.string(key)?.filter(|value| !value.is_empty()).is_some()
        } else {
            entry.int(key)?.unwrap_or(0) != 0
        };
        if requested {
            return Err(entry.unsupported(format!(
                "option '{key}' is not implemented (one QUIC connection per dial; UDP relay and congestion tuning are not wired)"
            )));
        }
    }
    for key in [
        "reduce-rtt",
        "fast-open",
        "disable-mtu-discovery",
        "udp-over-stream",
    ] {
        if entry.bool(key)?.unwrap_or(false) {
            return Err(entry.unsupported(format!("option '{key}' is not implemented")));
        }
    }
    // A per-connection stream cap is trivially honoured: this client opens at
    // most one bidirectional stream per dial, so any positive limit holds.
    let _ = entry.int("max-open-streams")?;
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    let allowed = [
        "dialer-proxy",
        "name",
        "type",
        "server",
        "port",
        "token",
        "uuid",
        "password",
        "ip",
        "heartbeat-interval",
        "alpn",
        "reduce-rtt",
        "request-timeout",
        "udp-relay-mode",
        "congestion-controller",
        "disable-sni",
        "max-udp-relay-packet-size",
        "fast-open",
        "max-open-streams",
        "cwnd",
        "bbr-profile",
        "skip-cert-verify",
        "name-cert-verify",
        "fingerprint",
        "certificate",
        "private-key",
        "recv-window-conn",
        "recv-window",
        "disable-mtu-discovery",
        "max-datagram-frame-size",
        "sni",
        "ech-opts",
        "udp-over-stream",
        "udp-over-stream-version",
        "client-fingerprint",
        "ip-version",
    ];
    entry.reject_unknown(&allowed, true, None)?;
    Ok(TuicOutbound {
        server,
        port,
        uuid,
        password,
        ip,
        tls_settings,
        alpn: entry.string_list("alpn")?,
        disable_sni,
        heartbeat_interval,
        request_timeout,
        dialer_proxy,
    })
}

/// MASQUE (`adapter/outbound/masque.go` + `transport/masque`): the pinned
/// adapter is a Cloudflare WARP client that pins the endpoint key, presents a
/// generated ECDSA certificate and sends `cf-connect-ip` (RFC 9484) into a
/// userspace IP stack. This kernel implements the RFC 9298 CONNECT-UDP data
/// path instead (see `outbound/masque.rs`), so every option that only selects
/// the CONNECT-IP/WARP flow is rejected by name instead of being dropped.
fn parse_masque(entry: &mut Entry<'_>) -> Result<MasqueOutbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    if let Some(network) = entry.string("network")?.filter(|value| !value.is_empty()) {
        let mode = match network.as_str() {
            "h2" => "HTTP/2 CONNECT-IP",
            "h3-l4proxy" => "the h3-l4proxy L4 client",
            _ => "a non-HTTP/3 transport",
        };
        return Err(entry.unsupported(format!(
            "option 'network' value '{network}' ({mode}) is not implemented: it belongs to the pinned Cloudflare WARP CONNECT-IP adapter; this kernel implements RFC 9298 CONNECT-UDP over HTTP/3"
        )));
    }
    for key in ["private-key", "public-key"] {
        if entry
            .string(key)?
            .filter(|value| !value.is_empty())
            .is_some()
        {
            return Err(entry.unsupported(format!(
                "option '{key}' is not implemented: the pinned adapter uses the ECDSA key pair for the Cloudflare WARP client certificate and endpoint pinning (cf-connect-ip); this kernel implements RFC 9298 CONNECT-UDP and does not use that registration"
            )));
        }
    }
    if let Some(uri) = entry.string("uri")?.filter(|value| !value.is_empty()) {
        return Err(entry.unsupported(format!(
            "option 'uri' value '{uri}' is not implemented: it selects the pinned CONNECT-IP request URI; CONNECT-UDP derives the request path from the destination"
        )));
    }
    for key in ["ip", "ipv6"] {
        if entry
            .string(key)?
            .filter(|value| !value.is_empty())
            .is_some()
        {
            return Err(entry.unsupported(format!(
                "option '{key}' is not implemented: it configures the pinned CONNECT-IP tunnel's local address and needs an IP stack (RFC 9484); this kernel implements CONNECT-UDP only"
            )));
        }
    }
    if entry.int("mtu")?.unwrap_or(0) != 0 {
        return Err(entry.unsupported(
            "option 'mtu' is not implemented: it sizes the pinned CONNECT-IP IP stack; CONNECT-UDP keeps UDP payloads whole",
        ));
    }
    if entry
        .block("ip-stack")?
        .is_some_and(|block| !block.is_empty())
    {
        return Err(entry.unsupported(
            "option 'ip-stack' is not implemented: it selects the pinned CONNECT-IP userspace stack (mips/gVisor); this kernel has no IP stack",
        ));
    }
    if entry.bool("remote-dns-resolve")?.unwrap_or(false) {
        return Err(entry.unsupported(
            "option 'remote-dns-resolve' is not implemented: it resolves through the pinned CONNECT-IP tunnel's own resolver",
        ));
    }
    if !entry.string_list("dns")?.is_empty() {
        return Err(entry.unsupported(
            "option 'dns' is not implemented: it configures the pinned CONNECT-IP tunnel's resolver",
        ));
    }
    if entry
        .string("congestion-controller")?
        .filter(|value| !value.is_empty())
        .is_some()
        || entry
            .string("bbr-profile")?
            .filter(|value| !value.is_empty())
            .is_some()
        || entry.int("cwnd")?.unwrap_or(0) != 0
    {
        return Err(entry.unsupported(
            "options 'congestion-controller'/'cwnd'/'bbr-profile' are not implemented: one QUIC connection per UDP association, with quinn's default congestion controller",
        ));
    }
    if entry
        .string("dialer-proxy")?
        .filter(|value| !value.is_empty())
        .is_some()
    {
        return Err(entry.unsupported(
            "option 'dialer-proxy' is not implemented for masque: a QUIC endpoint cannot be reached through the supported socks5 TCP hop, so the server is always dialled locally",
        ));
    }
    let udp = entry.bool("udp")?.unwrap_or(false);
    let handshake_timeout = match entry.int("handshake-timeout")? {
        Some(value) if value < 0 => {
            return Err(entry.invalid("option 'handshake-timeout' must not be negative"))
        }
        Some(value) => value as u64,
        None => 0,
    };
    let tls_settings = entry.tls_settings(true, false)?;
    // A pinned placeholder: the adapter sets the option but never verifies a
    // certificate name (it pins the endpoint key instead), so it is a no-op.
    let _ = entry.string("name-cert-verify")?;
    let allowed = [
        "name",
        "type",
        "server",
        "port",
        "private-key",
        "public-key",
        "ip",
        "ipv6",
        "uri",
        "sni",
        "mtu",
        "udp",
        "handshake-timeout",
        "skip-cert-verify",
        "name-cert-verify",
        "network",
        "congestion-controller",
        "cwnd",
        "bbr-profile",
        "ip-stack",
        "remote-dns-resolve",
        "dns",
    ];
    entry.reject_unknown(&allowed, true, None)?;
    Ok(MasqueOutbound {
        server,
        port,
        tls_settings,
        handshake_timeout,
        udp,
    })
}

fn display(raw: &str) -> String {
    if raw.is_empty() {
        "-".to_string()
    } else {
        raw.to_string()
    }
}

/// Names of supported protocols, for diagnostics.
pub fn supported_protocol_names() -> &'static [&'static str] {
    &[
        "socks5",
        "http",
        "ss",
        "trojan",
        "vless",
        "anytls",
        "vmess",
        "snell",
        "trusttunnel",
        "gost-relay",
        "ssh",
        "ssr",
        "tuic",
        "hysteria",
        "hysteria2",
        "mieru",
        "sudoku",
        "masque",
    ]
}

/// Options the pinned `BasicOption` declares for every outbound and this
/// kernel does not implement; kept here so the capability report has one list.
pub fn unsupported_common_options() -> BTreeMap<&'static str, &'static str> {
    ["tfo", "mptcp", "interface-name", "routing-mark", "ip-version"]
        .into_iter()
        .map(|key| (key, "no implementation in the Rust runtime (T4)"))
        .collect()
}
