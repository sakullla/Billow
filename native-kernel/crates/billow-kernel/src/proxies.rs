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
//!
//! One option table is GPL-derived: [`SudokuOutbound`] and `parse_sudoku` are
//! translated from Mihomo `adapter/outbound/sudoku.go` (GPL-3.0). Only those
//! items are GPL-derived; the rest of this file is original MIT code. See
//! `native-kernel/THIRD_PARTY_NOTICES.md`.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::config::ConfigError;
use crate::keys::{parse_uuid, Secret};
use crate::outbound::ipstack::IpPrefix;

/// Shadowsocks AEAD 2017 ciphers (16/24/32-byte keys, 16-byte tags).
///
/// The pinned `core.PickCipher` also has the stream-cipher list and the
/// ChaCha8/AES-CCM AEADs; those are registered by name in the T28 parity
/// evidence instead of being silently accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsCipher {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    Chacha20IetfPoly1305,
    Xchacha20IetfPoly1305,
}

impl SsCipher {
    pub fn key_len(self) -> usize {
        match self {
            SsCipher::Aes128Gcm => 16,
            SsCipher::Aes192Gcm => 24,
            SsCipher::Aes256Gcm
            | SsCipher::Chacha20IetfPoly1305
            | SsCipher::Xchacha20IetfPoly1305 => 32,
        }
    }

    /// Size of the pre-shared key (Mihomo `aeadList` KeySize: 16/24/32). The
    /// KDF output and the AEAD key size are the same for every implemented
    /// entry, including aes-192-gcm.
    pub fn psk_len(self) -> usize {
        self.key_len()
    }

    /// AEAD nonce size: 24 bytes for XChaCha20-Poly1305, 12 for the rest.
    pub fn nonce_len(self) -> usize {
        match self {
            SsCipher::Xchacha20IetfPoly1305 => 24,
            _ => 12,
        }
    }

    /// The list shown in "not implemented" errors.
    pub const SUPPORTED: &'static str =
        "aes-128-gcm, aes-192-gcm, aes-256-gcm, chacha20-ietf-poly1305, xchacha20-ietf-poly1305";

    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Some(SsCipher::Aes128Gcm),
            "aes-192-gcm" => Some(SsCipher::Aes192Gcm),
            "aes-256-gcm" => Some(SsCipher::Aes256Gcm),
            "chacha20-ietf-poly1305" => Some(SsCipher::Chacha20IetfPoly1305),
            "xchacha20-ietf-poly1305" => Some(SsCipher::Xchacha20IetfPoly1305),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            SsCipher::Aes128Gcm => "aes-128-gcm",
            SsCipher::Aes192Gcm => "aes-192-gcm",
            SsCipher::Aes256Gcm => "aes-256-gcm",
            SsCipher::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
            SsCipher::Xchacha20IetfPoly1305 => "xchacha20-ietf-poly1305",
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
    /// `name-cert-verify`: verify the chain against this name while SNI stays
    /// `sni`/`server` (Mihomo `ca.NewNameCertVerifier`).
    pub name_cert_verify: Option<String>,
    /// `fingerprint`: a SHA-256 certificate pin (hex, colons allowed). Mihomo
    /// accepts a match on any presented certificate; a leaf match skips the
    /// chain/name check, a non-leaf match verifies the chain with that
    /// certificate as the anchor.
    pub fingerprint: Option<Vec<u8>>,
    /// `certificate` / `private-key`: inline PEM or a file path loaded when the
    /// TLS handshake is built (Mihomo's `NewTLSKeyPairLoader`).
    pub certificate: Option<String>,
    pub private_key: Option<String>,
    /// `client-fingerprint`: the pinned engine hands this name to uTLS. rustls
    /// cannot reproduce a uTLS ClientHello byte for byte, so a known name is
    /// applied as the closest rustls profile (the browser key-exchange list)
    /// and an unknown name keeps the standard handshake, exactly like the
    /// pinned `GetFingerprint` fallback. `None`/`none` is the standard client.
    pub client_fingerprint: Option<String>,
}

/// `ip-version` (Mihomo `constant.DNSPrefer`): controls which addresses a
/// proxy-server name resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpVersion {
    #[default]
    Dual,
    V4Only,
    V6Only,
    V4Prefer,
    V6Prefer,
}

impl IpVersion {
    /// The pinned `UnmarshalText` maps any unknown spelling to `dual`.
    pub fn parse(value: &str) -> IpVersion {
        match value.trim().to_ascii_lowercase().as_str() {
            "ipv4" => IpVersion::V4Only,
            "ipv6" => IpVersion::V6Only,
            "ipv4-prefer" => IpVersion::V4Prefer,
            "ipv6-prefer" => IpVersion::V6Prefer,
            _ => IpVersion::Dual,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            IpVersion::Dual => "dual",
            IpVersion::V4Only => "ipv4",
            IpVersion::V6Only => "ipv6",
            IpVersion::V4Prefer => "ipv4-prefer",
            IpVersion::V6Prefer => "ipv6-prefer",
        }
    }
}

/// Socket-shaping options every outbound embeds through Mihomo's
/// `BasicOption`: they apply to the connection to the proxy server, not to the
/// target stream.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DialerOptions {
    /// TCP Fast Open on the proxy-server connection.
    pub tfo: bool,
    /// Multipath TCP (`IPPROTO_MPTCP`, Linux only).
    pub mptcp: bool,
    /// Bind the socket to this interface.
    pub interface_name: Option<String>,
    /// `SO_MARK` on Linux; accepted and logged as unsupported elsewhere, as
    /// the pinned dialer does.
    pub routing_mark: u32,
    pub ip_version: IpVersion,
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
    /// SOCKS5 `UDP ASSOCIATE` to this server (RFC 1928 datagram relay).
    pub udp: bool,
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
    /// `udp-over-tcp`: carry UDP datagrams as UoT inside the Shadowsocks TCP
    /// stream (`sing` UoT v2 by default, `udp-over-tcp-version: 1` legacy).
    pub udp_over_tcp: bool,
    pub udp_over_tcp_version: u8,
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
    /// `ss-opts: {enabled: true, ...}`: an extra Shadowsocks AEAD layer over
    /// the TLS stream (the pinned `core.Cipher.StreamConn` wrapper).
    pub ss_opts: Option<TrojanSsOpts>,
    pub dialer_proxy: Option<String>,
}

/// The pinned `TrojanSSOption`. `method` defaults to `AES-128-GCM`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanSsOpts {
    pub cipher: SsCipher,
    pub password: Secret,
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
    /// `udp: true`: the pinned server accepts the UDP command, XUDP or the
    /// packet-addr framing (the resolved mode is stored below).
    pub udp: bool,
    pub packet_addr: bool,
    pub xudp: bool,
    pub packet_encoding: Option<String>,
    pub dialer_proxy: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VlessNetwork {
    Tcp,
    Ws(WsSettings),
}

/// AnyTLS (Mihomo `adapter/outbound/anytls.go`): TLS to the server with a
/// SHA-256 password prefix, then a session-multiplexed stream per connection.
///
/// The TLS-layer security mode of an AnyTLS outbound (`ShadowTLSOpts` /
/// `JLSOpts` in the pinned type). At most one may be set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnytlsSecurity {
    None,
    /// `shadow-tls-opts`: a camouflage TLS handshake, then ShadowTLS framing.
    ShadowTls {
        password: Secret,
        /// Pinned version number (0 is normalised to 2).
        version: u8,
    },
    /// `jls-opts`: the JLS-sealed ClientHello/ServerHello.
    Jls { username: Secret, password: Secret },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnytlsOutbound {
    pub server: String,
    pub port: u16,
    pub password: Secret,
    pub tls_settings: TlsSettings,
    /// `shadow-tls-opts` / `jls-opts`; mutually exclusive in the pinned type.
    pub security: AnytlsSecurity,
    /// `udp: true`: datagrams travel as UoT over a dedicated AnyTLS stream.
    pub udp: bool,
    /// `client-metadata`: the `client=` value of the session settings frame.
    pub client_metadata: Option<String>,
    /// Session reuse knobs; seconds as the pinned type declares them.
    pub idle_session_check_interval: u64,
    pub idle_session_timeout: u64,
    pub min_idle_session: usize,
    pub disable_reuse: bool,
    /// Idle-session pool shared by every connection of this outbound. It is
    /// not part of the configuration identity, so equality ignores it.
    pub session_pool: Arc<crate::outbound::anytls::AnytlsPool>,
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
    /// `network: mkcp` / `kcp` plus the `mkcp-opts` block.
    Mkcp(MkcpOptions),
    /// `network: mekya` plus the `mekya-opts` block (whose KCP settings run
    /// over the HTTP/2 bundle stream).
    Mekya(MekyaOptions),
}

/// VMess `mekya-opts` (pinned `MekyaOptions`). `kcp` reuses the mKCP tuning.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MekyaOptions {
    pub url: String,
    pub h2_pool_size: u32,
    pub max_write_delay: u32,
    pub max_request_size: u32,
    pub polling_interval_initial: u32,
    pub max_write_size: u32,
    pub max_write_duration_ms: u32,
    pub max_simultaneous_write_connection: u32,
    pub packet_writing_buffer: u32,
    pub kcp: MkcpOptions,
}

/// VMess `mkcp-opts` (pinned `MKCPOptions`). Every field is a tuning knob;
/// `0`/empty keeps the pinned default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MkcpOptions {
    pub mtu: u32,
    pub tti: u32,
    pub uplink_capacity: u32,
    pub downlink_capacity: u32,
    pub congestion: bool,
    pub write_buffer: u32,
    pub read_buffer: u32,
    pub seed: String,
    pub header: String,
}

/// VMess `tlsmirror-opts` (pinned `TLSMirrorOptions`). Only `primary-key`
/// selects the transport; the feature-specific extras are rejected at load.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsMirrorOptions {
    pub primary_key: String,
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
    /// `udp: true` with `xudp`/`packet-addr` (Mihomo's VMess UDP modes).
    pub udp: bool,
    pub packet_addr: bool,
    pub xudp: bool,
    pub packet_encoding: Option<String>,
    pub tlsmirror: Option<TlsMirrorOptions>,
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
/// mask; `on` enables the Sudoku session mux (`KIPTypeStartMux`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SudokuMultiplex {
    Off,
    Auto,
    On,
}

// SPDX-License-Identifier: GPL-3.0-only
//
// Derived from Mihomo `transport/sudoku` (GPL-3.0), `adapter/outbound/sudoku.go`
// (option names, defaults and validation). Only the Sudoku option table below
// and `parse_sudoku` are GPL-derived; the rest of `proxies.rs` is original MIT
// code. See `native-kernel/THIRD_PARTY_NOTICES.md`.
/// Sudoku (`adapter/outbound/sudoku.go`): table-driven obfuscation, a record
/// layer and the KIP handshake. TCP sessions, the legacy HTTP mask, the pure
/// and packed downlink codecs and the session mux (`multiplex: on`) are
/// implemented; the HTTP tunnel modes and UoT are rejected at load with the
/// reason recorded. The module is a GPL-3.0-derived translation (T17).
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

/// ShadowQUIC (`adapter/outbound/shadowquic.go` + `transport/shadowquic`):
/// QUIC with JLS authentication. The pinned client has no `tls` or
/// `skip-cert-verify` option (JLS replaces certificate verification) and no
/// `udp` option (the base outbound advertises UDP unconditionally). The
/// private mihomo Brutal negotiation is implemented: `up`/`down` are the
/// Brutal rates, `cwnd`/`bbr-profile` tune the initial window and
/// `congestion-controller` selects quinn's controller. `zero-rtt` and QUIC v2
/// are named residuals (no session-ticket cache / no v2 in quinn 0.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowQuicOutbound {
    pub server: String,
    pub port: u16,
    /// JLS account (`username`/`password`); empty values are accepted and
    /// simply fail authentication against a real server.
    pub username: String,
    pub password: String,
    /// Certificates are camouflage after JLS authentication; `sni` still
    /// selects the name that is sent.
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub udp_over_stream: bool,
    /// `keep-alive-interval` in milliseconds; 0 disables keep-alive.
    pub keep_alive_interval: u64,
    /// `congestion-controller`: cubic/new_reno/bbr/bbr_meta_v2.
    pub congestion_controller: Option<String>,
    /// `up`/`down`: the Brutal TX/RX rate hints (bytes/second).
    pub send_bps: u64,
    pub receive_bps: u64,
    /// Initial congestion window in packets (pinned default 32).
    pub cwnd: u32,
    /// `bbr-profile`: conservative/standard/aggressive (initial-window
    /// approximation, as quinn's BBR has no profile selector).
    pub bbr_profile: Option<String>,
    /// `recv-window-conn`; the kernel's budget default when the option is 0.
    pub recv_window_conn: u32,
    /// `recv-window`; the kernel's budget default when the option is 0.
    pub recv_window: u32,
    pub disable_mtu_discovery: bool,
    pub max_datagram_frame_size: usize,
    pub max_open_streams: u64,
}

/// One `peers:` entry of the pinned WireGuard outbound
/// (`adapter/outbound/wireguard.go` `WireGuardPeerOption`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireguardPeerOutbound {
    pub server: String,
    pub port: u16,
    /// Base64 of the peer's 32-byte Curve25519 public key.
    pub public_key: String,
    /// Base64 of the optional 32-byte pre-shared key.
    pub preshared_key: Option<Secret>,
    /// Exactly three reserved header bytes (WARP-style endpoints) or empty.
    pub reserved: Vec<u8>,
    /// CIDRs this peer is allowed to carry; the pinned single-peer form
    /// defaults to `0.0.0.0/0` and/or `::/0` when `ip`/`ipv6` are set.
    pub allowed_ips: Vec<String>,
}

/// WireGuard (`adapter/outbound/wireguard.go` + the pinned `wireguard-go`
/// device and its userspace IP stack).
///
/// The Noise IK handshake and the transport data messages are implemented in
/// `outbound/wireguard.rs` and verified against a controlled peer built from
/// the locked `metacubex/wireguard-go` device. The IP stack, TUN device and
/// the TCP/UDP socket layer inside the tunnel are the T6/T7 device layer: this
/// outbound loads a valid configuration, validates its keys and then refuses
/// every dial with that device gap named. `amnezia-wg-option`, an explicit
/// `ip-stack` mode, `remote-dns-resolve`/`dns` and endpoint refresh are
/// rejected at load because they ask for a device/stack feature this kernel
/// does not have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireguardOutbound {
    /// Base64 of the local 32-byte Curve25519 private key.
    pub private_key: Secret,
    /// `ip`/`ipv6` local addresses (also the single-peer allowed-IP source).
    pub ip: Option<String>,
    pub ipv6: Option<String>,
    /// Device worker count; 0 selects the pinned default. Used by T6/T7.
    pub workers: u16,
    /// Tunnel MTU, default 1408 as the pinned outbound.
    pub mtu: u32,
    /// States the UDP capability the device has; the transport is UDP.
    pub udp: bool,
    /// Keepalive interval in seconds (0 disables it).
    pub persistent_keepalive: u16,
    pub peers: Vec<WireguardPeerOutbound>,
}

/// OpenVPN (`adapter/outbound/openvpn.go` + `transport/openvpn`).
///
/// The control channel (UDP or TCP framing, hard reset, reliable ACK layer,
/// TLS 1.3 client authentication, key-method 2 exchange and PUSH_REPLY) and
/// the AEAD data channel are implemented in `outbound/openvpn.rs`. The pinned
/// adapter then runs the data channel over a userspace IP stack; that device
/// layer is T6/T7, so this outbound loads and validates a configuration and
/// refuses every dial with the device gap named. `tls-auth`/`tls-crypt`,
/// compression, CBC data ciphers and `tcp` are rejected at load with the
/// missing piece named instead of being loaded as compatible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenVpnOutbound {
    pub server: String,
    pub port: u16,
    /// `udp` (default) or `tcp`; the transport is UDP only in this kernel.
    pub proto: String,
    /// `tun` is the only device type the pinned adapter accepts.
    pub dev: String,
    /// Normalized primary cipher; `AES-128-GCM` when unset.
    pub cipher: String,
    /// `data-ciphers` offered for negotiation (normalized).
    pub data_ciphers: Vec<String>,
    pub data_cipher_fallback: Option<String>,
    /// Normalized `auth` (data-channel HMAC/keying material); `SHA256` when unset.
    pub auth: String,
    /// `comp-lzo`; only the disabled form is implemented.
    pub comp_lzo: String,
    /// Inline CA certificate PEM (the pinned type has no path form).
    pub ca: Secret,
    pub cert: Option<Secret>,
    pub key: Option<Secret>,
    pub tls_auth: Option<Secret>,
    pub key_direction: Option<String>,
    pub tls_crypt: Option<Secret>,
    pub tls_crypt_v2: Option<Secret>,
    pub username: Option<Secret>,
    pub password: Option<Secret>,
    pub peer_info: Vec<(String, String)>,
    pub ping: u16,
    pub ping_restart: u16,
    pub tran_window: i64,
    pub handshake_timeout: u16,
    pub mtu: u16,
    pub udp: bool,
    pub remote_dns_resolve: bool,
    pub dns: Vec<String>,
}

impl OpenVpnOutbound {
    /// The cipher the data channel starts with (first `data-ciphers` entry or
    /// `cipher`).
    pub fn primary_cipher(&self) -> &str {
        self.data_ciphers
            .first()
            .map(String::as_str)
            .unwrap_or(&self.cipher)
    }
}

/// Tailscale (`adapter/outbound/tailscale.go`): the pinned adapter embeds
/// `tsnet` (the control-plane Noise protocol, DERP relays and a WireGuard data
/// path) and a userspace netstack. T19 implements the control-plane Noise
/// transport, the HTTP/2 control request and the DERP frame codec in
/// `outbound/tailscale.rs`; the TCP/UDP socket layer inside the tunnel stays
/// with T6/T7, so every `dial()` names that gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleOutbound {
    /// `hostname`; the `tsnet` default when unset.
    pub hostname: Option<String>,
    /// `auth-key`: the node registration key.
    pub auth_key: Option<Secret>,
    /// `control-url`; `https://controlplane.tailscale.com` when unset.
    pub control_url: Option<String>,
    /// `state-dir`; the pinned default is `tailscale`.
    pub state_dir: String,
    /// `ephemeral`: do not store the node in the control plane.
    pub ephemeral: bool,
    /// `udp`: the data plane carries UDP; the T6/T7 stack supplies it.
    pub udp: bool,
    pub accept_routes: Option<bool>,
    pub exit_node: Option<String>,
    pub exit_node_allow_lan_access: Option<bool>,
}

/// One `orbit:` entry (`world` + `seed` node address).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZerotierOrbit {
    pub world: u64,
    pub seed: u64,
}

/// ZeroTier (`adapter/outbound/zerotier.go` + the locked `zerotier-go`).
///
/// T19 implements identity generation/parsing, planet/moon parsing, the VL1
/// packet armor and HELLO/OK/WHOIS/ECHO verbs, and the VL2 frame payload in
/// `outbound/zerotier.rs`. The pinned adapter also runs a userspace IP stack
/// and the network-controller membership exchange; those are T6/T7 and T5, so
/// this outbound loads, validates its identity/planet and refuses every
/// `dial()` with that gap named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZerotierOutbound {
    pub network_id: u64,
    /// `state-dir`; the pinned default is `zerotier`.
    pub state_dir: String,
    pub identity_secret: Option<Secret>,
    /// Path to a serialized planet; the pinned default planet when unset.
    pub planet: Option<String>,
    pub mtu: u16,
    /// Normalized `ip-stack.mode` (`auto` when unset).
    pub ip_stack_mode: String,
    pub physical_mtu: u16,
    pub udp: bool,
    pub remote_dns_resolve: bool,
    pub dns: Vec<String>,
    pub low_bandwidth: bool,
    pub encrypted_hello: bool,
    pub primary_port: u16,
    pub secondary_port: u16,
    /// Normalized `tcp-fallback-mode` (`auto` when unset).
    pub tcp_fallback_mode: String,
    pub tcp_fallback_relay: String,
    pub orbit: Vec<ZerotierOrbit>,
}

/// EasyTier (`adapter/outbound/easytier.go` + the pinned `easytier-go`).
///
/// `outbound/easytier.rs` is an LGPL-3.0-or-later derivative of the locked
/// EasyTier source: network secret digest, peer-manager frame,
/// `HandshakeRequest`/PingPong, Noise XX handshake and secure-datagram
/// AES-GCM/ChaCha20 data path. The userspace IP stack/TUN and OSPF/route
/// exchange remain T6/T7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EasytierOutbound {
    pub network_name: String,
    pub network_secret: Secret,
    pub hostname: Option<String>,
    pub ipv4: Option<String>,
    pub dhcp: bool,
    pub peers: Vec<String>,
    pub listeners: Vec<String>,
    pub no_listener: Option<bool>,
    pub mapped_listeners: Vec<String>,
    pub exit_nodes: Vec<String>,
    pub proxy_networks: Vec<String>,
    pub instance_name: String,
    pub state_dir: String,
    pub udp: bool,
    pub accept_dns: Option<bool>,
    pub enable_exit_node: Option<bool>,
    pub enable_encryption: bool,
    pub encryption_algorithm: String,
    pub private_mode: Option<bool>,
    pub latency_first: Option<bool>,
    pub disable_p2p: Option<bool>,
    pub enable_kcp_proxy: Option<bool>,
    pub disable_kcp_input: Option<bool>,
    pub enable_quic_proxy: Option<bool>,
    pub disable_quic_input: Option<bool>,
    pub mtu: u16,
    pub tld_dns_zone: Option<String>,
    pub secure_mode: Option<bool>,
    pub local_private_key: Option<Secret>,
    pub local_public_key: Option<Secret>,
}

/// MASQUE over HTTP/3, in the two shapes the pinned adapter serves:
///
/// * the RFC 9298 CONNECT-UDP subset (T14): a server with `udp: true`, one
///   request stream per destination and UDP payloads in `DATAGRAM` capsules;
/// * the pinned Cloudflare WARP CONNECT-IP client (RFC 9484): `private-key`
///   and `public-key` (the ECDSA client identity and the pinned endpoint key),
///   `ip`/`ipv6` local addresses, `uri`, `mtu`, `ip-stack`,
///   `remote-dns-resolve`/`dns`. The tunnel carries whole IP packets, which
///   this kernel terminates for UDP only: TCP needs a TCP state machine the
///   kernel does not have, so a TCP dial through it is refused by name.
///
/// The `h2` CONNECT-IP variant and `h3-l4proxy` are still rejected by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasqueOutbound {
    pub server: String,
    pub port: u16,
    pub tls_settings: TlsSettings,
    /// `handshake-timeout` in seconds; 0 keeps the dial timeout.
    pub handshake_timeout: u64,
    /// QUIC congestion controller selected by `congestion-controller`
    /// (`cubic`, `new_reno`, `bbr`); `None` keeps quinn's default.
    pub congestion_controller: Option<String>,
    /// Initial congestion window in packets (`cwnd`, pinned default 32 when a
    /// controller is selected).
    pub cwnd: u32,
    /// `udp`: for CONNECT-IP this enables the UDP-over-IP association; for
    /// CONNECT-UDP it is the only implemented mode, so `false` leaves an
    /// outbound that refuses every dial explicitly.
    pub udp: bool,
    /// `Some` when the configuration carries the WARP CONNECT-IP shape.
    pub connect_ip: Option<MasqueConnectIp>,
}

/// The pinned Cloudflare WARP CONNECT-IP configuration
/// (`adapter/outbound/masque.go`, `MasqueOption`). Every field is validated at
/// load, so a configuration Mihomo accepts for this shape loads here too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasqueConnectIp {
    /// base64 SEC1 `ECPrivateKey` (P-256); redacted in debug output.
    pub private_key: Secret,
    /// base64 DER `SubjectPublicKeyInfo` of the endpoint (P-256).
    pub public_key: Secret,
    /// The decoded endpoint key, used as the TLS pin.
    pub public_key_der: Vec<u8>,
    /// `uri` (default `https://cloudflareaccess.com`) and the request fields
    /// derived from it: the URI must be absolute https and template-free.
    pub uri: String,
    pub uri_authority: String,
    pub uri_path: String,
    /// Local addresses from `ip`/`ipv6` (at least one), in prefix order.
    pub local: Vec<IpPrefix>,
    /// `mtu` (pinned default 1280).
    pub mtu: u16,
    /// `ip-stack.mode` normalized (`auto` when unset).
    pub ip_stack_mode: String,
    /// `remote-dns-resolve`: resolve through the tunnel's own name servers.
    pub remote_dns_resolve: bool,
    /// `dns`: UDP name servers used when `remote-dns-resolve` is set.
    pub dns: Vec<SocketAddr>,
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
/// authentication then one bidirectional QUIC stream per TCP session, or one
/// QUIC datagram session for UDP (always enabled, as the pinned outbound sets
/// `UDP: true`). Port hopping, the Salamander/Gecko obfuscators and realm are
/// implemented; `ech-opts` is rejected at load, and a `dialer-proxy` chain is
/// refused by name at dial/association time (never bypassed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hysteria2Outbound {
    pub server: String,
    pub port: u16,
    pub password: Secret,
    pub tls_settings: TlsSettings,
    pub alpn: Vec<String>,
    /// `up`: the Brutal sender's TX rate hint (bytes/second).
    pub send_bps: u64,
    pub receive_bps: u64,
    pub handshake_timeout: u64,
    /// BBR initial congestion window in packets (pinned default 32, one
    /// packet = 1200 bytes). `0` keeps quinn's default.
    pub cwnd: u32,
    /// QUIC receive windows (`initial-*`/`max-*` share one value in quinn).
    pub stream_receive_window: Option<u32>,
    pub connection_receive_window: Option<u32>,
    /// `ports` (expanded) + `hop-interval` (seconds, possibly a range).
    pub ports: Vec<u16>,
    pub hop_interval: (u64, u64),
    /// `obfs: salamander|gecko` with its password.
    pub obfs: Option<String>,
    pub obfs_password: Option<Secret>,
    /// `obfs-min-packet-size` / `obfs-max-packet-size`: the Gecko on-wire
    /// packet-size range (pinned defaults 512/1200); ignored by Salamander.
    pub obfs_min_packet_size: u32,
    pub obfs_max_packet_size: u32,
    /// `udp-mtu`: Hysteria UDP session payload MTU (pinned default 1197).
    pub udp_mtu: u16,
    /// `bbr-profile`: conservative/standard/aggressive.
    pub bbr_profile: Option<String>,
    /// `realm-opts`: realm rendezvous configuration.
    pub realm: Option<Hysteria2Realm>,
    pub dialer_proxy: Option<String>,
}

/// `realm-opts` as the pinned `Hysteria2RealmOption` declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hysteria2Realm {
    pub server_url: String,
    pub token: Option<Secret>,
    pub realm_id: Option<String>,
    pub stun_servers: Vec<String>,
    pub tls_settings: TlsSettings,
}

/// Hysteria v1 (`adapter/outbound/hysteria.go`, `transport/hysteria/core`):
/// QUIC with a binary control hello and one bidirectional stream per TCP
/// session. Port hopping, the XPlus obfuscator and the `wechat` transport are
/// implemented at the UDP socket boundary; `faketcp` needs a raw-socket TCP
/// stack that neither this kernel nor the pinned non-Linux build provides and
/// is refused at dial time. `fast-open` defers the server response to the
/// first read, as the pinned `NewEarlyConn` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HysteriaOutbound {
    pub server: String,
    pub port: u16,
    pub auth: Vec<u8>,
    pub tls_settings: TlsSettings,
    pub alpn: Vec<String>,
    pub send_bps: u64,
    pub receive_bps: u64,
    /// `ports` (expanded) and `hop-interval` in seconds (pinned default 10).
    pub ports: Vec<u16>,
    pub hop_interval: u64,
    /// `obfs`: the XPlus key (`None` disables the obfuscator).
    pub obfs: Option<String>,
    /// `protocol`/`obfs-protocol`: udp (default), wechat or faketcp.
    pub protocol: HysteriaProtocol,
    pub fast_open: bool,
    pub stream_receive_window: Option<u32>,
    pub connection_receive_window: Option<u32>,
    pub disable_mtu_discovery: bool,
    pub dialer_proxy: Option<String>,
}

/// Hysteria v1 packet transport (`HysteriaOption.Protocol`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HysteriaProtocol {
    Udp,
    WeChat,
    FakeTcp,
}

/// TUIC (`adapter/outbound/tuic.go`). One QUIC connection carries a
/// unidirectional authentication stream and one bidirectional stream per TCP
/// session. Two authentication shapes exist: v5 `uuid` + TLS-exporter token
/// (the default) and v4 `token` (BLAKE3 TKN), selected exactly like the pinned
/// `NewTuic`: a non-empty `token` means v4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuicOutbound {
    pub server: String,
    pub port: u16,
    /// `token`: the legacy v4 shared secret. When set, `uuid`/`password` are
    /// ignored and the v4 framing is used.
    pub token: Option<Secret>,
    pub uuid: [u8; 16],
    pub password: Secret,
    /// `ip`: dial this address while the certificate name stays `server`/`sni`.
    pub ip: Option<String>,
    pub tls_settings: TlsSettings,
    pub alpn: Vec<String>,
    pub disable_sni: bool,
    pub heartbeat_interval: u64,
    pub request_timeout: u64,
    /// `udp-relay-mode`: `quic` sends each packet on its own uni stream, the
    /// default `native` sends QUIC datagrams.
    pub udp_relay_mode: TuicRelayMode,
    /// `udp-over-stream`: UDP carried inside a TCP-style stream to the pinned
    /// `sp[.v2].udp-over-tcp.arpa` destination.
    pub udp_over_stream: bool,
    /// `udp-over-stream-version`: 1 (legacy, per-packet destination) or 2
    /// (initial request; the pinned default is 1).
    pub udp_over_stream_version: u8,
    /// `max-datagram-frame-size` after the pinned derivation/clamp (default
    /// `max-udp-relay-packet-size + packet overhead`, capped at 1400).
    pub max_datagram_frame_size: usize,
    /// `max-udp-relay-packet-size` after the pinned derivation (the v5 form is
    /// additionally clamped to `MaxFragSizeV5`).
    pub max_udp_relay_packet_size: usize,
    /// `reduce-rtt`: the pinned client passes `DialEarly` to quic-go. That only
    /// sends 0-RTT data after a session ticket was cached, and the pinned TUIC
    /// adapter never configures a `ClientSessionCache` (contrast shadowquic,
    /// which does), so with the pinned engine this always falls back to a full
    /// handshake. Kept as parsed configuration for parity and evidence.
    pub reduce_rtt: bool,
    /// `fast-open`: the v4 client returns the stream before the connect
    /// response arrives (the v5 client has no early response; the flag only
    /// reaches the TCP-style dialer there, which a QUIC socket never uses).
    pub fast_open: bool,
    /// `congestion-controller`: cubic, new_reno or bbr (the pinned default is
    /// quic-go's cubic).
    pub congestion_controller: Option<String>,
    /// Initial congestion window in packets (pinned default 32).
    pub cwnd: u32,
    /// `bbr-profile`: conservative/standard/aggressive. quinn's BBR has no
    /// profile selector; the profile maps to the initial window.
    pub bbr_profile: Option<String>,
    pub stream_receive_window: Option<u32>,
    pub connection_receive_window: Option<u32>,
    pub disable_mtu_discovery: bool,
    pub dialer_proxy: Option<String>,
}

/// TUIC UDP relay carrier (`udp-relay-mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuicRelayMode {
    /// Each packet is its own QUIC uni stream (`udp-relay-mode: quic`).
    Quic,
    /// QUIC datagrams (the pinned default when `udp-relay-mode` is unset).
    Native,
}

impl TuicRelayMode {
    fn parse(value: Option<&str>) -> TuicRelayMode {
        match value {
            Some("quic") => TuicRelayMode::Quic,
            _ => TuicRelayMode::Native,
        }
    }
}

/// One enabled proxy entry. `DIRECT` and `REJECT` are built in and cannot be
/// redefined (Mihomo rejects the duplicate name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxy {
    pub name: String,
    pub protocol: Protocol,
    /// `BasicOption` socket-shaping options (tfo/mptcp/interface-name/
    /// routing-mark/ip-version), parsed once for every outbound type.
    pub dialer: DialerOptions,
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
    ShadowQuic(ShadowQuicOutbound),
    Wireguard(WireguardOutbound),
    OpenVpn(OpenVpnOutbound),
    Tailscale(TailscaleOutbound),
    Zerotier(ZerotierOutbound),
    Easytier(EasytierOutbound),
}

impl Protocol {
    /// Override the `dialer-proxy` chain target (proxy providers).
    fn set_dialer_proxy(&mut self, value: Option<String>) -> bool {
        match self {
            Protocol::Socks5(p) => p.dialer_proxy = value,
            Protocol::Http(p) => p.dialer_proxy = value,
            Protocol::Shadowsocks(p) => p.dialer_proxy = value,
            Protocol::Trojan(p) => p.dialer_proxy = value,
            Protocol::Vless(p) => p.dialer_proxy = value,
            Protocol::Anytls(p) => p.dialer_proxy = value,
            Protocol::Vmess(p) => p.dialer_proxy = value,
            Protocol::Snell(p) => p.dialer_proxy = value,
            Protocol::TrustTunnel(p) => p.dialer_proxy = value,
            Protocol::GostRelay(p) => p.dialer_proxy = value,
            Protocol::Ssh(p) => p.dialer_proxy = value,
            Protocol::Ssr(p) => p.dialer_proxy = value,
            Protocol::Tuic(p) => p.dialer_proxy = value,
            Protocol::Hysteria(p) => p.dialer_proxy = value,
            Protocol::Hysteria2(p) => p.dialer_proxy = value,
            Protocol::Mieru(p) => p.dialer_proxy = value,
            Protocol::Sudoku(p) => p.dialer_proxy = value,
            Protocol::Masque(_)
            | Protocol::ShadowQuic(_)
            | Protocol::Wireguard(_)
            | Protocol::OpenVpn(_)
            | Protocol::Tailscale(_)
            | Protocol::Zerotier(_)
            | Protocol::Easytier(_) => return false,
        }
        true
    }

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
            Protocol::ShadowQuic(_) => None,
            Protocol::Wireguard(_) => None,
            Protocol::OpenVpn(_) => None,
            Protocol::Tailscale(_) => None,
            Protocol::Zerotier(_) => None,
            Protocol::Easytier(_) => None,
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
            Protocol::ShadowQuic(_) => "shadowquic",
            Protocol::Wireguard(_) => "wireguard",
            Protocol::OpenVpn(_) => "openvpn",
            Protocol::Tailscale(_) => "tailscale",
            Protocol::Zerotier(_) => "zerotier",
            Protocol::Easytier(_) => "easytier",
        }
    }

    /// The pinned `AdapterType.String()` spelling, which is what a group's
    /// `exclude-type` is compared against (`"Shadowsocks"`, `"Socks5"`, ...).
    pub fn adapter_type_name(&self) -> &'static str {
        match self.protocol {
            Protocol::Socks5(_) => "Socks5",
            Protocol::Http(_) => "Http",
            Protocol::Shadowsocks(_) => "Shadowsocks",
            Protocol::Trojan(_) => "Trojan",
            Protocol::Vless(_) => "Vless",
            Protocol::Anytls(_) => "AnyTLS",
            Protocol::Vmess(_) => "Vmess",
            Protocol::Snell(_) => "Snell",
            Protocol::TrustTunnel(_) => "TrustTunnel",
            Protocol::GostRelay(_) => "GostRelay",
            Protocol::Ssh(_) => "Ssh",
            Protocol::Ssr(_) => "ShadowsocksR",
            Protocol::Tuic(_) => "Tuic",
            Protocol::Hysteria(_) => "Hysteria",
            Protocol::Hysteria2(_) => "Hysteria2",
            Protocol::Mieru(_) => "Mieru",
            Protocol::Sudoku(_) => "Sudoku",
            Protocol::Masque(_) => "Masque",
            Protocol::ShadowQuic(_) => "ShadowQuic",
            Protocol::Wireguard(_) => "WireGuard",
            Protocol::OpenVpn(_) => "OpenVPN",
            Protocol::Tailscale(_) => "Tailscale",
            Protocol::Zerotier(_) => "ZeroTier",
            Protocol::Easytier(_) => "EasyTier",
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
            Protocol::ShadowQuic(p) => (&p.server, p.port),
            Protocol::Wireguard(p) => p
                .peers
                .first()
                .map(|peer| (peer.server.as_str(), peer.port))
                .unwrap_or(("", 0)),
            Protocol::OpenVpn(p) => (&p.server, p.port),
            Protocol::Tailscale(p) => (&p.state_dir, 0),
            Protocol::Zerotier(p) => (&p.state_dir, 0),
            Protocol::Easytier(p) => (&p.state_dir, 0),
        }
    }

    /// ShadowTLS (the SS/structure listener) is exposed as `type: ss` with a
    /// `plugin`; that combination is reported unsupported, never accepted silently.
    pub fn udp_enabled(&self) -> bool {
        match &self.protocol {
            Protocol::Socks5(p) => p.udp,
            Protocol::Shadowsocks(p) => p.udp,
            Protocol::Trojan(p) => p.udp,
            Protocol::Ssr(p) => p.udp,
            Protocol::GostRelay(p) => p.udp,
            Protocol::Masque(p) => p.udp,
            // Hysteria2 enables UDP unconditionally in the pinned outbound
            // (`UDP: true`); the option has no `udp` field, so a config's
            // `udp: true` is a tolerated no-op and `udp: false` is ignored.
            Protocol::Hysteria2(_) => true,
            // Hysteria v1 also sets `UDP: true` in the pinned outbound
            // (`ProxyInfo.UDP`); its `udp=1` QUIC datagram session is
            // implemented in `outbound::udp::HysteriaUdp`.
            Protocol::Hysteria(_) => true,
            Protocol::Tuic(_) => true,
            Protocol::ShadowQuic(_) => true,
            Protocol::Tailscale(p) => p.udp,
            Protocol::Zerotier(p) => p.udp,
            Protocol::Easytier(p) => p.udp,
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

/// `fingerprint`: SHA-256 certificate pin. The pinned `NewFingerprintVerifier`
/// strips colons, hex-decodes and requires exactly 32 bytes; browser names are
/// rejected with a message pointing at `client-fingerprint`.
fn parse_fingerprint(encoded: &str) -> Result<Vec<u8>, String> {
    let compact = encoded.trim().replace(':', "");
    let bytes = hex::decode(&compact).map_err(|error| format!("not a hex string: {error}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "expected a SHA-256 fingerprint (32 bytes), found {} bytes; browser fingerprints belong to 'client-fingerprint'",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// quinn's flow-control window from the pinned `initial-*`/`max-*` pair: the
/// maximum wins when set (quinn uses one value for both), else the initial.
fn receive_window(
    entry: &mut Entry<'_>,
    initial: &str,
    maximum: &str,
) -> Result<Option<u32>, ConfigError> {
    let mut chosen = None;
    for key in [initial, maximum] {
        match entry.int(key)? {
            Some(value) if value < 0 => {
                return Err(entry.invalid(format!("option '{key}' must not be negative")))
            }
            Some(0) | None => {}
            Some(value) => {
                let value = u32::try_from(value)
                    .map_err(|_| entry.invalid(format!("option '{key}' is out of range")))?;
                chosen = Some(value);
            }
        }
    }
    Ok(chosen)
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
///
/// Hysteria2 and Hysteria v1 are exempt: their UDP association is a QUIC
/// socket that cannot ride any hop, and [`crate::outbound::udp::Hysteria2Udp::connect`]
/// / [`crate::outbound::udp::HysteriaUdp::connect`] refuse a chain by name at
/// association time. The pinned client accepts the configuration, and
/// rejecting it here would reject the whole file (every unrelated proxy, and
/// TCP) even when the chained proxy is never used, so the limitation stays a
/// per-association error instead of a load-time one.
fn validate_udp_chains(proxies: &[Proxy]) -> Result<(), ConfigError> {
    let index = |name: &str| proxies.iter().position(|proxy| proxy.name == name);
    for (i, proxy) in proxies.iter().enumerate() {
        if !proxy.udp_enabled()
            || matches!(proxy.protocol, Protocol::Hysteria2(_) | Protocol::Hysteria(_))
        {
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
            2 if matches!(proxy.protocol, Protocol::Socks5(_)) => {
                return Err(ConfigError::Unsupported(format!(
                    "proxies[{i}] (name={}, type=socks5): option 'udp' with 'dialer-proxy' is not implemented (the SOCKS5 UDP association dials the server directly)",
                    proxy.name
                )))
            }
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

    /// Apply a proxy-provider `dialer-proxy` override; `false` when the
    /// protocol has no dialer-proxy concept (the caller reports it by name).
    pub fn set_dialer_proxy(&mut self, value: Option<String>) -> bool {
        self.protocol.set_dialer_proxy(value)
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

    fn required_string(&mut self, key: &str) -> Result<String, ConfigError> {        match self.string(key)? {
            Some(v) if !v.is_empty() => Ok(v),
            Some(_) => Err(self.invalid(format!("option '{key}' must not be empty"))),
            None => Err(self.invalid(format!("missing required option '{key}'"))),
        }
    }

    /// `client-fingerprint` for the families whose pinned type declares it.
    /// The pinned `GetFingerprint` treats an empty/`none` value as "standard
    /// handshake" and warns for unknown names instead of failing; the value is
    /// kept so the TLS builder can apply its rustls approximation.
    fn client_fingerprint(&mut self) -> Result<Option<String>, ConfigError> {
        Ok(self
            .string("client-fingerprint")?
            .filter(|value| !value.is_empty() && value != "none"))
    }

    /// TLS options the type declares: `socks5` has no `sni`/`alpn`, `http` no
    /// `alpn` (Mihomo ignores those there, so identifying them would apply a
    /// value the reference ignores). `tls` gates the certificate-identity
    /// options: Mihomo ignores them entirely when TLS is off.
    fn tls_settings(
        &mut self,
        sni: bool,
        alpn: bool,
        tls: bool,
    ) -> Result<TlsSettings, ConfigError> {
        let sni = if sni {
            self.string("sni")?.filter(|s| !s.is_empty())
        } else {
            None
        };
        let skip = self.bool("skip-cert-verify")?.unwrap_or(false);
        let alpn = if alpn { self.string_list("alpn")? } else { Vec::new() };
        let mut settings = TlsSettings {
            sni,
            skip_cert_verify: skip,
            alpn,
            ..TlsSettings::default()
        };
        if tls {
            settings.name_cert_verify = self
                .string("name-cert-verify")?
                .filter(|s| !s.is_empty());
            settings.certificate = self
                .string("certificate")?
                .filter(|s| !s.is_empty());
            settings.private_key = self
                .string("private-key")?
                .filter(|s| !s.is_empty());
            if let Some(encoded) = self.string("fingerprint")?.filter(|s| !s.is_empty()) {
                settings.fingerprint = Some(parse_fingerprint(&encoded).map_err(|error| {
                    self.invalid(format!("option 'fingerprint': {error}"))
                })?);
            }
        }
        Ok(settings)
    }

    /// `BasicOption` socket options, parsed for every outbound type. They are
    /// marked used here so a protocol parser does not have to know about them;
    /// mesh adapters still reject the forms they cannot apply.
    fn dialer_options(&mut self) -> Result<DialerOptions, ConfigError> {
        let tfo = self.bool("tfo")?.unwrap_or(false);
        let mptcp = self.bool("mptcp")?.unwrap_or(false);
        let interface_name = self
            .string("interface-name")?
            .filter(|value| !value.is_empty());
        let routing_mark = match self.int("routing-mark")? {
            Some(value) if value < 0 => {
                return Err(self.invalid("option 'routing-mark' must not be negative"))
            }
            Some(0) | None => 0,
            Some(value) => u32::try_from(value)
                .map_err(|_| self.invalid("option 'routing-mark' is out of range"))?,
        };
        let ip_version = match self.string("ip-version")? {
            Some(value) => IpVersion::parse(&value),
            None => IpVersion::default(),
        };
        Ok(DialerOptions {
            tfo,
            mptcp,
            interface_name,
            routing_mark,
            ip_version,
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
    let dialer = entry.dialer_options()?;
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
        "shadowquic" => Protocol::ShadowQuic(parse_shadowquic(&mut entry)?),
        "wireguard" => Protocol::Wireguard(parse_wireguard(&mut entry)?),
        "tailscale" => Protocol::Tailscale(parse_tailscale(&mut entry)?),
        "zerotier" => Protocol::Zerotier(parse_zerotier(&mut entry)?),
        "easytier" => Protocol::Easytier(parse_easytier(&mut entry)?),
        "openvpn" => Protocol::OpenVpn(parse_openvpn(&mut entry)?),

        other => {
            return Err(ConfigError::Unsupported(format!(
                "{}: protocol type '{other}' is not implemented (implemented: socks5, http, ss, trojan, vless, anytls, vmess, snell, trusttunnel, gost-relay, ssh, ssr, tuic, hysteria, hysteria2, mieru, sudoku, masque, shadowquic, wireguard, openvpn, tailscale, zerotier)",
                entry.prefix()
            )))
        }
    };
    Ok(Proxy {
        name,
        protocol,
        dialer,
    })
}

/// Basic options shared by every outbound. The mesh adapters dial their own
/// control/physical sockets, so the device-shaping forms are rejected with the
/// T6/T7 boundary instead of being accepted without effect.
fn reject_device_basic(entry: &mut Entry<'_>) -> Result<(), ConfigError> {
    if entry.bool("tfo")?.unwrap_or(false) {
        return Err(entry.unsupported("option 'tfo' is not implemented for mesh outbounds (the T6/T7 device layer owns the socket)"));
    }
    if entry.bool("mptcp")?.unwrap_or(false) {
        return Err(entry.unsupported("option 'mptcp' is not implemented for mesh outbounds"));
    }
    if entry.string("interface-name")?.filter(|v| !v.is_empty()).is_some() {
        return Err(entry.unsupported("option 'interface-name' requires the T6/T7 device layer"));
    }
    if entry.int("routing-mark")?.unwrap_or(0) != 0 {
        return Err(entry.unsupported("option 'routing-mark' requires the T6/T7 device layer"));
    }
    if entry.string("ip-version")?.filter(|v| !v.is_empty()).is_some() {
        return Err(entry.unsupported("option 'ip-version' is not implemented for mesh outbounds"));
    }
    if entry.string("dialer-proxy")?.filter(|v| !v.is_empty()).is_some() {
        return Err(entry.unsupported("option 'dialer-proxy' is not implemented for mesh outbounds (their control sockets are dialled locally)"));
    }
    Ok(())
}

/// Families whose local socket is not the stream dialer (QUIC/packet-device
/// adapters) still name the BasicOption forms they cannot apply, so a
/// configuration never looks accepted while the knob is dropped.
fn reject_unwired_basic(entry: &mut Entry<'_>, kind: &str) -> Result<(), ConfigError> {
    if entry.bool("tfo")?.unwrap_or(false) {
        return Err(entry.unsupported(format!(
            "option 'tfo' is not implemented for {kind} (its socket is not created by the stream dialer)"
        )));
    }
    if entry.bool("mptcp")?.unwrap_or(false) {
        return Err(entry.unsupported(format!(
            "option 'mptcp' is not implemented for {kind} (its socket is not created by the stream dialer)"
        )));
    }
    if entry
        .string("interface-name")?
        .filter(|value| !value.is_empty())
        .is_some()
    {
        return Err(entry.unsupported(format!(
            "option 'interface-name' is not implemented for {kind}"
        )));
    }
    if entry.int("routing-mark")?.unwrap_or(0) != 0 {
        return Err(entry.unsupported(format!(
            "option 'routing-mark' is not implemented for {kind}"
        )));
    }
    if entry
        .string("ip-version")?
        .filter(|value| !value.is_empty())
        .is_some()
    {
        return Err(entry.unsupported(format!(
            "option 'ip-version' is not implemented for {kind}"
        )));
    }
    Ok(())
}

fn parse_tailscale(entry: &mut Entry<'_>) -> Result<TailscaleOutbound, ConfigError> {
    reject_device_basic(entry)?;
    let hostname = entry.string("hostname")?.filter(|v| !v.is_empty());
    if hostname.is_some() {
        return Err(entry.unsupported(
            "option 'hostname' requires Tailscale node registration, which is not implemented (the control-base/DERP protocol layers do not register a node)",
        ));
    }
    let auth_key = entry.string("auth-key")?.filter(|v| !v.is_empty()).map(Secret::new);
    if auth_key.is_some() {
        return Err(entry.unsupported(
            "option 'auth-key' requires Tailscale node registration, which is not implemented",
        ));
    }
    let control_url = entry.string("control-url")?.filter(|v| !v.is_empty());
    if let Some(url) = &control_url {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(entry.invalid("option 'control-url' must be an http(s) URL"));
        }
    }
    if entry.string("state-dir")?.filter(|v| !v.is_empty()).is_some() {
        return Err(entry.unsupported(
            "option 'state-dir' requires Tailscale node registration/state persistence, which is not implemented",
        ));
    }
    if entry.bool("ephemeral")?.unwrap_or(false) {
        return Err(entry.unsupported(
            "option 'ephemeral' requires Tailscale node registration, which is not implemented",
        ));
    }
    let udp = entry.bool("udp")?.unwrap_or(false);
    if entry.bool("accept-routes")?.unwrap_or(false) {
        return Err(entry.unsupported(
            "option 'accept-routes: true' requires Tailscale control-plane prefs, which are not implemented",
        ));
    }
    if entry.string("exit-node")?.filter(|v| !v.is_empty()).is_some() {
        return Err(entry.unsupported(
            "option 'exit-node' requires Tailscale control-plane prefs, which are not implemented",
        ));
    }
    if entry.bool("exit-node-allow-lan-access")?.unwrap_or(false) {
        return Err(entry.unsupported(
            "option 'exit-node-allow-lan-access: true' requires Tailscale control-plane prefs, which are not implemented",
        ));
    }
    entry.reject_unknown(
        &[
            "hostname",
            "auth-key",
            "control-url",
            "state-dir",
            "ephemeral",
            "udp",
            "accept-routes",
            "exit-node",
            "exit-node-allow-lan-access",
        ],
        false,
        None,
    )?;
    Ok(TailscaleOutbound {
        hostname: None,
        auth_key: None,
        control_url,
        state_dir: "tailscale".to_string(),
        ephemeral: false,
        udp,
        accept_routes: None,
        exit_node: None,
        exit_node_allow_lan_access: None,
    })
}

fn parse_zerotier(entry: &mut Entry<'_>) -> Result<ZerotierOutbound, ConfigError> {
    reject_device_basic(entry)?;
    let network = entry.required_string("network")?;
    let network_id = crate::outbound::zerotier::parse_network_id(&network)
        .map_err(|_| entry.invalid("option 'network' must be a 16-digit ZeroTier network ID"))?;
    let state_dir = entry
        .string("state-dir")?
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "zerotier".to_string());
    let identity_secret = entry
        .string("identity-secret")?
        .filter(|v| !v.is_empty())
        .map(Secret::new);
    if let Some(secret) = &identity_secret {
        crate::outbound::zerotier::Identity::parse(secret.expose())
            .map_err(|e| entry.invalid(format!("option 'identity-secret': {e}")))?;
    }
    let planet = entry.string("planet")?.filter(|v| !v.is_empty());
    let mtu = match entry.int("mtu")? {
        Some(value) if value != 0 && !(1280..=10000).contains(&value) => {
            return Err(entry.invalid("option 'mtu' must be between 1280 and 10000"))
        }
        Some(value) => value as u16,
        None => 0,
    };
    let physical_mtu = match entry.int("physical-mtu")? {
        Some(value) if value != 0 && !(510..=10324).contains(&value) => {
            return Err(entry.invalid("option 'physical-mtu' must be between 510 and 10324"))
        }
        Some(value) => value as u16,
        None => 0,
    };
    let ip_stack_mode = if let Some(block) = entry.block("ip-stack")? {
        let mut mode = "auto".to_string();
        for (key, value) in block {
            let key = key.as_str().ok_or_else(|| entry.invalid("ip-stack keys must be strings"))?;
            match key {
                "mode" => {
                    mode = value.as_str().unwrap_or("").to_ascii_lowercase();
                    if mode.is_empty() {
                        mode = "auto".to_string();
                    }
                }
                other => {
                    return Err(entry.unsupported(format!(
                        "option 'ip-stack.{other}' requires the T6/T7 userspace IP stack"
                    )))
                }
            }
        }
        if !matches!(mode.as_str(), "auto" | "gvisor" | "mips") {
            return Err(entry.invalid(format!(
                "option 'ip-stack.mode' value '{mode}' is not one of auto, gvisor, mips"
            )));
        }
        return Err(entry.unsupported(
            "option 'ip-stack' requires the userspace IP stack and TUN device owned by T6/T7",
        ));
    } else {
        "auto".to_string()
    };
    let udp = entry.bool("udp")?.unwrap_or(false);
    let remote_dns_resolve = entry.bool("remote-dns-resolve")?.unwrap_or(false);
    let dns = entry.string_list("dns")?;
    if remote_dns_resolve || !dns.is_empty() {
        return Err(entry.unsupported(
            "options 'remote-dns-resolve'/'dns' require the T6/T7 userspace IP stack resolver",
        ));
    }
    let low_bandwidth = entry.bool("low-bandwidth")?.unwrap_or(false);
    let encrypted_hello = entry.bool("encrypted-hello")?.unwrap_or(false);
    let primary_port = match entry.int("primary-port")? {
        Some(value) if (1..=65535).contains(&value) => value as u16,
        Some(_) => return Err(entry.invalid("option 'primary-port' must be a port in 1..=65535")),
        None => 0,
    };
    let secondary_port = match entry.int("secondary-port")? {
        Some(value) if (1..=65535).contains(&value) => value as u16,
        Some(_) => return Err(entry.invalid("option 'secondary-port' must be a port in 1..=65535")),
        None => 0,
    };
    let tcp_fallback_mode = entry
        .string("tcp-fallback-mode")?
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "auto".to_string())
        .to_ascii_lowercase();
    if !matches!(tcp_fallback_mode.as_str(), "auto" | "force" | "disable") {
        return Err(entry.invalid("option 'tcp-fallback-mode' must be auto, force or disable"));
    }
    let tcp_fallback_relay = entry.string("tcp-fallback-relay")?.unwrap_or_default();
    if tcp_fallback_mode == "force" || !tcp_fallback_relay.is_empty() {
        return Err(entry.unsupported(
            "options 'tcp-fallback-mode: force'/'tcp-fallback-relay' require the ZeroTier TCP fallback transport, which is not implemented",
        ));
    }
    let mut orbit = Vec::new();
    if let Some(value) = entry.get("orbit") {
        let items = value
            .as_sequence()
            .ok_or_else(|| entry.invalid("option 'orbit' must be a list"))?;
        let mut worlds = std::collections::BTreeSet::new();
        for item in items {
            let map = item
                .as_mapping()
                .ok_or_else(|| entry.invalid("each 'orbit' entry must be a mapping"))?;
            let mut world = None;
            let mut seed = None;
            for (key, value) in map {
                let key = key.as_str().ok_or_else(|| entry.invalid("orbit keys must be strings"))?;
                let text = value
                    .as_str()
                    .ok_or_else(|| entry.invalid(format!("orbit.{key} must be a string")))?;
                match key {
                    "world" => {
                        if text.len() != 16 {
                            return Err(entry.invalid("orbit.world must be a 16-digit hexadecimal ID"));
                        }
                        world = u64::from_str_radix(text, 16).ok().filter(|v| *v != 0);
                        if world.is_none() {
                            return Err(entry.invalid("orbit.world is not a hexadecimal ID"));
                        }
                    }
                    "seed" => {
                        if text.len() != 10 {
                            return Err(entry.invalid("orbit.seed must be a 10-digit node ID"));
                        }
                        seed = u64::from_str_radix(text, 16).ok().filter(|v| *v != 0);
                        if seed.is_none() {
                            return Err(entry.invalid("orbit.seed is not a hexadecimal node ID"));
                        }
                    }
                    other => {
                        return Err(entry.unsupported(format!("option 'orbit.{other}' is not implemented")))
                    }
                }
            }
            let (Some(world), Some(seed)) = (world, seed) else {
                return Err(entry.invalid("each 'orbit' entry requires 'world' and 'seed'"));
            };
            if !worlds.insert(world) {
                return Err(entry.invalid(format!("duplicate orbit world {world:016x}")));
            }
            orbit.push(ZerotierOrbit { world, seed });
        }
    }
    if entry.string("remote-trace-target")?.filter(|v| !v.is_empty()).is_some() {
        return Err(entry.unsupported("option 'remote-trace-target' is not implemented"));
    }
    if entry.int("remote-trace-level")?.unwrap_or(0) != 0 {
        return Err(entry.unsupported("option 'remote-trace-level' is not implemented"));
    }
    entry.reject_unknown(
        &[
            "network",
            "state-dir",
            "identity-secret",
            "planet",
            "mtu",
            "ip-stack",
            "physical-mtu",
            "udp",
            "remote-dns-resolve",
            "dns",
            "low-bandwidth",
            "encrypted-hello",
            "primary-port",
            "secondary-port",
            "tcp-fallback-mode",
            "tcp-fallback-relay",
            "orbit",
            "remote-trace-target",
            "remote-trace-level",
        ],
        false,
        None,
    )?;
    Ok(ZerotierOutbound {
        network_id,
        state_dir,
        identity_secret,
        planet,
        mtu,
        ip_stack_mode,
        physical_mtu,
        udp,
        remote_dns_resolve,
        dns,
        low_bandwidth,
        encrypted_hello,
        primary_port,
        secondary_port,
        tcp_fallback_mode,
        tcp_fallback_relay,
        orbit,
    })
}

fn parse_easytier(entry: &mut Entry<'_>) -> Result<EasytierOutbound, ConfigError> {
    reject_device_basic(entry)?;
    let network_name = entry.string("network-name")?.unwrap_or_default();
    let network_secret = entry.string("network-secret")?.unwrap_or_default();
    let hostname = entry.string("hostname")?.filter(|v| !v.is_empty());
    if hostname.is_some() {
        return Err(entry.unsupported(
            "option 'hostname' requires the EasyTier OSPF/route host-identity exchange, which is not implemented in the cleartext host/discovery translation",
        ));
    }
    let ipv4 = entry.string("ipv4")?.filter(|v| !v.is_empty());
    if let Some(ipv4) = &ipv4 {
        let (address, prefix) = ipv4
            .split_once('/')
            .ok_or_else(|| entry.invalid("option 'ipv4' must be an IPv4 prefix such as 10.144.0.10/24"))?;
        if address.parse::<std::net::Ipv4Addr>().is_err()
            || prefix.parse::<u8>().map_or(true, |bits| bits > 32)
        {
            return Err(entry.invalid("option 'ipv4' must be an IPv4 prefix such as 10.144.0.10/24"));
        }
    }
    let dhcp = entry.bool("dhcp")?.unwrap_or(false);
    if dhcp || ipv4.is_some() {
        return Err(entry.unsupported(
            "options 'ipv4'/'dhcp' require the EasyTier OSPF/route address assignment, which is not implemented in the cleartext host/discovery translation",
        ));
    }
    let peers = entry.string_list("peers")?;
    let listeners = entry.string_list("listeners")?;
    let no_listener = entry.bool("no-listener")?;
    let mapped_listeners = entry.string_list("mapped-listeners")?;
    if !mapped_listeners.is_empty() {
        return Err(entry.unsupported("option 'mapped-listeners' is not implemented"));
    }
    for (option, endpoints) in [("peers", &peers), ("listeners", &listeners)] {
        if endpoints
            .iter()
            .any(|value| !(value.starts_with("udp://") || value.starts_with("tcp://") || value.starts_with("wg://") || value.starts_with("quic://")))
        {
            return Err(entry.invalid(format!(
                "each '{option}' entry must be a udp://, tcp://, wg:// or quic:// URL"
            )));
        }
    }
    if peers.is_empty() && listeners.is_empty() && no_listener != Some(true) {
        return Err(entry.invalid("EasyTier requires at least one peer or listener (or 'no-listener: true')"));
    }
    let exit_nodes = entry.string_list("exit-nodes")?;
    if !exit_nodes.is_empty() {
        return Err(entry.unsupported("option 'exit-nodes' is not implemented"));
    }
    let proxy_networks = entry.string_list("proxy-networks")?;
    if !proxy_networks.is_empty() {
        return Err(entry.unsupported("option 'proxy-networks' is not implemented"));
    }
    let instance_name = entry
        .string("instance-name")?
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| entry.name.clone());
    let state_dir = entry
        .string("state-dir")?
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| format!("easytier/{instance_name}"));
    let udp = entry.bool("udp")?.unwrap_or(false);
    let accept_dns = entry.bool("accept-dns")?;
    if accept_dns == Some(true) {
        return Err(entry.unsupported("option 'accept-dns' requires the EasyTier DNS integration (T5)"));
    }
    let enable_exit_node = entry.bool("enable-exit-node")?;
    if enable_exit_node == Some(true) {
        return Err(entry.unsupported("option 'enable-exit-node' is not implemented"));
    }
    let enable_encryption = entry.bool("enable-encryption")?.unwrap_or(false);
    let encryption_algorithm = entry
        .string("encryption-algorithm")?
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "aes-gcm".to_string())
        .to_ascii_lowercase();
    if !matches!(encryption_algorithm.as_str(), "aes-gcm" | "chacha20") {
        return Err(entry.invalid("option 'encryption-algorithm' must be aes-gcm or chacha20"));
    }
    let secure_mode = entry.bool("secure-mode")?;
    if enable_encryption && secure_mode != Some(true) {
        return Err(entry.unsupported(
            "option 'enable-encryption' requires 'secure-mode: true' (the source enables data encryption only through the Noise/secure-datagram session)",
        ));
    }
    let private_mode = entry.bool("private-mode")?;
    if private_mode == Some(true) {
        return Err(entry.unsupported("option 'private-mode' is not implemented"));
    }
    let latency_first = entry.bool("latency-first")?;
    if latency_first == Some(true) {
        return Err(entry.unsupported("option 'latency-first' is not implemented"));
    }
    let disable_p2p = entry.bool("disable-p2p")?;
    let enable_kcp_proxy = entry.bool("enable-kcp-proxy")?;
    if enable_kcp_proxy == Some(true) {
        return Err(entry.unsupported("option 'enable-kcp-proxy' is not implemented"));
    }
    let disable_kcp_input = entry.bool("disable-kcp-input")?;
    let enable_quic_proxy = entry.bool("enable-quic-proxy")?;
    if enable_quic_proxy == Some(true) {
        return Err(entry.unsupported("option 'enable-quic-proxy' is not implemented"));
    }
    let disable_quic_input = entry.bool("disable-quic-input")?;
    let mtu = match entry.int("mtu")? {
        Some(value) if value != 0 && !(576..=65535).contains(&value) => {
            return Err(entry.invalid("option 'mtu' must be between 576 and 65535"))
        }
        Some(value) => value as u16,
        None => 0,
    };
    let tld_dns_zone = entry.string("tld-dns-zone")?.filter(|v| !v.is_empty());
    if tld_dns_zone.is_some() {
        return Err(entry.unsupported("option 'tld-dns-zone' is not implemented (T5 DNS)"));
    }
    let local_private_key = entry.string("local-private-key")?.filter(|v| !v.is_empty()).map(Secret::new);
    let local_public_key = entry.string("local-public-key")?.filter(|v| !v.is_empty()).map(Secret::new);
    if (local_private_key.is_some() || local_public_key.is_some()) && secure_mode != Some(true) {
        return Err(entry.unsupported(
            "options 'local-private-key'/'local-public-key' require 'secure-mode: true'",
        ));
    }
    if let Some(private_key) = &local_private_key {
        let private = crate::outbound::easytier::parse_private_key(private_key.expose())
            .map_err(|_| entry.invalid("option 'local-private-key' must be a base64 32-byte X25519 key"))?;
        if let Some(public_key) = &local_public_key {
            let public = crate::outbound::easytier::parse_public_key(public_key.expose())
                .map_err(|_| entry.invalid("option 'local-public-key' must be a base64 32-byte X25519 key"))?;
            if crate::outbound::easytier::derive_public_key(&private) != public {
                return Err(entry.invalid(
                    "option 'local-public-key' does not match 'local-private-key'",
                ));
            }
        }
    } else if local_public_key.is_some() && secure_mode == Some(true) {
        return Err(entry.invalid("option 'local-public-key' requires 'local-private-key'"));
    }
    entry.reject_unknown(
        &[
            "network-name",
            "network-secret",
            "hostname",
            "ipv4",
            "dhcp",
            "peers",
            "listeners",
            "no-listener",
            "mapped-listeners",
            "exit-nodes",
            "proxy-networks",
            "instance-name",
            "state-dir",
            "udp",
            "accept-dns",
            "enable-exit-node",
            "enable-encryption",
            "encryption-algorithm",
            "private-mode",
            "latency-first",
            "disable-p2p",
            "enable-kcp-proxy",
            "disable-kcp-input",
            "enable-quic-proxy",
            "disable-quic-input",
            "mtu",
            "tld-dns-zone",
            "secure-mode",
            "local-private-key",
            "local-public-key",
        ],
        false,
        None,
    )?;
    Ok(EasytierOutbound {
        network_name,
        network_secret: Secret::new(network_secret),
        hostname,
        ipv4,
        dhcp,
        peers,
        listeners,
        no_listener,
        mapped_listeners,
        exit_nodes,
        proxy_networks,
        instance_name,
        state_dir,
        udp,
        accept_dns,
        enable_exit_node,
        enable_encryption,
        encryption_algorithm,
        private_mode,
        latency_first,
        disable_p2p,
        enable_kcp_proxy,
        disable_kcp_input,
        enable_quic_proxy,
        disable_quic_input,
        mtu,
        tld_dns_zone,
        secure_mode,
        local_private_key,
        local_public_key,
    })
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
    let tls_settings = entry.tls_settings(false, false, tls)?;
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    // SOCKS5 `UDP ASSOCIATE` (RFC 1928): the control connection stays open and
    // datagrams carry the SOCKS5 address header to the relay the server names.
    let udp = entry.bool("udp")?.unwrap_or(false);
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
        udp,
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
    let tls_settings = entry.tls_settings(true, false, tls)?;
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
            "option 'cipher' value '{cipher_name}' is not implemented (supported: {})",
            SsCipher::SUPPORTED
        ))
    })?;
    let password = Secret::new(entry.required_string("password")?);
    let udp = entry.bool("udp")?.unwrap_or(false);
    let udp_over_tcp = entry.bool("udp-over-tcp")?.unwrap_or(false);
    let version = entry.int("udp-over-tcp-version")?.unwrap_or(0);
    let udp_over_tcp_version = match version {
        0 | 2 => 2,
        1 => 1,
        other => {
            return Err(entry.unsupported(format!(
                "option 'udp-over-tcp-version' value {other} is not implemented (1 or 2)"
            )))
        }
    };
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
        // Pinned `NewShadowSocks`: UoT implies UDP.
        udp: udp || udp_over_tcp,
        udp_over_tcp,
        udp_over_tcp_version,
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
    let tls_settings = entry.tls_settings(true, true, true)?;
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
    let ss_opts = parse_trojan_ss_opts(entry)?;
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
        ss_opts,
        dialer_proxy,
    })
}

/// `ss-opts` of trojan: a bare Shadowsocks AEAD layer over the TLS stream.
fn parse_trojan_ss_opts(entry: &mut Entry<'_>) -> Result<Option<TrojanSsOpts>, ConfigError> {
    let Some(block) = entry.block("ss-opts")? else {
        return Ok(None);
    };
    let enabled = block
        .get(serde_yaml::Value::String("enabled".to_string()))
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    if !enabled {
        // The pinned type leaves `ssCipher` nil when `enabled` is false, even
        // if the other fields are present.
        return Ok(None);
    }
    let password = block
        .get(serde_yaml::Value::String("password".to_string()))
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    if password.is_empty() {
        return Err(entry.invalid("option 'ss-opts.password' is required when ss-opts is enabled"));
    }
    let method = block
        .get(serde_yaml::Value::String("method".to_string()))
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("AES-128-GCM")
        .to_string();
    let cipher = SsCipher::from_name(&method).ok_or_else(|| {
        entry.unsupported(format!(
            "option 'ss-opts.method' value '{method}' is not implemented (supported: {})",
            SsCipher::SUPPORTED
        ))
    })?;
    Ok(Some(TrojanSsOpts {
        cipher,
        password: Secret::new(password),
    }))
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
    let mut tls_settings = entry.tls_settings(true, true, tls)?;
    tls_settings.client_fingerprint = entry.client_fingerprint()?;
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
    let udp = entry.bool("udp")?.unwrap_or(false);
    let packet_addr_flag = entry.bool("packet-addr")?.unwrap_or(false);
    let xudp_flag = entry.bool("xudp")?.unwrap_or(false);
    let packet_encoding = entry.string("packet-encoding")?.filter(|value| !value.is_empty());
    // Pinned `NewVless`: `packetaddr`/`packet` select packet-addr, anything
    // else keeps `packet-addr` and turns XUDP on whenever packet-addr is off
    // (so the default `udp: true` is XUDP). XUDP then wins over packet-addr.
    let (mut packet_addr, xudp) = match packet_encoding.as_deref() {
        Some("packetaddr") | Some("packet") => (true, false),
        _ => (packet_addr_flag, if !packet_addr_flag { true } else { xudp_flag }),
    };
    if xudp {
        packet_addr = false;
    }
    // The pinned `VlessOption` declares `ws-headers` but no code path reads it
    // (`WSOpts.Headers` is the one applied), so accepting it is exact parity.
    let _ = entry.string_map("ws-headers")?;
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
        udp,
        packet_addr,
        xudp,
        packet_encoding,
        dialer_proxy,
    })
}

/// The pinned `session.NewClient` normalisation: `<= 5s` becomes 30s.
fn normalize_anytls_seconds(value: Option<i64>) -> u64 {
    match value {
        Some(seconds) if seconds > 5 => seconds as u64,
        _ => 30,
    }
}

fn parse_anytls(entry: &mut Entry<'_>) -> Result<AnytlsOutbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    let password = Secret::new(entry.required_string("password")?);
    let mut tls_settings = entry.tls_settings(true, true, true)?;
    tls_settings.client_fingerprint = entry.client_fingerprint()?;
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    // Session reuse (pinned `session.NewClient`): an interval or timeout at or
    // below 5s (including 0/negative) is normalised to the pinned 30s default;
    // a value above 5s is kept as configured.
    let idle_session_check_interval = normalize_anytls_seconds(entry.int("idle-session-check-interval")?);
    let idle_session_timeout = normalize_anytls_seconds(entry.int("idle-session-timeout")?);
    let min_idle_session = match entry.int("min-idle-session")? {
        Some(value) if value < 0 => {
            return Err(entry.invalid("option 'min-idle-session' must not be negative"))
        }
        Some(value) => value as usize,
        None => 0,
    };
    let disable_reuse = entry.bool("disable-reuse")?.unwrap_or(false);
    let udp = entry.bool("udp")?.unwrap_or(false);
    let client_metadata = entry.string("client-metadata")?.filter(|s| !s.is_empty());
    let security = parse_anytls_security(entry)?;
    let session_pool = crate::outbound::anytls::AnytlsPool::new(
        idle_session_check_interval,
        idle_session_timeout,
        min_idle_session,
        disable_reuse,
    );
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
        security,
        udp,
        client_metadata,
        idle_session_check_interval,
        idle_session_timeout,
        min_idle_session,
        disable_reuse,
        session_pool,
        dialer_proxy,
    })
}

fn parse_anytls_security(entry: &mut Entry<'_>) -> Result<AnytlsSecurity, ConfigError> {
    // ShadowTLS (pinned `ShadowTLSOptions.Parse`): both fields empty is no-op.
    let mut shadow = None;
    if let Some(block) = entry.block("shadow-tls-opts")? {
        reject_block_keys(entry, "shadow-tls-opts", block, &["password", "version"])?;
        let password = block_string(entry, "shadow-tls-opts", block, "password")?;
        let version = block_int(entry, "shadow-tls-opts", block, "version")?;
        if !password.is_empty() || version != 0 {
            match version {
                // Version 1 is a plain camouflage TLS handshake followed by the
                // framed protocol on the raw connection; it is implemented and
                // verified against the pinned listener.
                1 => shadow = Some((Secret::new(password), 1u8)),
                // Version 2 is the pinned default (`version: 0` -> 2) and is
                // implemented and verified against the pinned listener.
                0 | 2 => shadow = Some((Secret::new(password), 2u8)),
                3 => {
                    return Err(entry.unsupported(
                        "option 'shadow-tls-opts' version 3 is not implemented: it carries the account in the ClientHello session id, which rustls generates internally (a rewrite would invalidate the handshake transcript); set 'version: 1' for the implemented mode",
                    ))
                }
                other => {
                    return Err(entry.invalid(format!(
                        "option 'shadow-tls-opts' version {other} is unknown (Mihomo accepts 1, 2 or 3)"
                    )))
                }
            }
        }
    }
    // JLS (pinned `NewConfig`): `username` and `password` are required.
    let mut jls = None;
    if let Some(block) = entry.block("jls-opts")? {
        reject_block_keys(entry, "jls-opts", block, &["username", "password"])?;
        let username = block_string(entry, "jls-opts", block, "username")?;
        let password = block_string(entry, "jls-opts", block, "password")?;
        if username.is_empty() || password.is_empty() {
            return Err(entry.unsupported(
                "option 'jls-opts' must set its required fields 'username' and 'password' (Mihomo rejects the empty block)",
            ));
        }
        jls = Some((Secret::new(username), Secret::new(password)));
    }
    // Restls is a different TLS camouflage implementation; it stays a named
    // rejection rather than being accepted and ignored.
    if entry
        .mapping
        .get(serde_yaml::Value::String("restls-opts".to_string()))
        .is_some_and(|value| !is_noop_value(value))
    {
        return Err(entry.unsupported(
            "option 'restls-opts' is not implemented: the pinned anytls outbound wraps TLS in Restls, which rewrites the TLS handshake bytes rustls has already authenticated",
        ));
    }
    match (shadow, jls) {
        (None, None) => Ok(AnytlsSecurity::None),
        (Some((password, version)), None) => {
            Ok(AnytlsSecurity::ShadowTls { password, version })
        }
        (None, Some((username, password))) => Ok(AnytlsSecurity::Jls { username, password }),
        (Some(_), Some(_)) => Err(entry.unsupported(
            "option 'shadow-tls-opts' and 'jls-opts' are mutually exclusive (Mihomo rejects the combination: security modes are mutually exclusive: ShadowTLS, JLS)",
        )),
    }
}

fn reject_block_keys(
    entry: &Entry<'_>,
    option: &str,
    block: &serde_yaml::Mapping,
    allowed: &[&str],
) -> Result<(), ConfigError> {
    for key in block.keys() {
        let Some(key) = key.as_str() else {
            return Err(entry.invalid(format!("option '{option}' keys must be strings")));
        };
        let key = key.replace('_', "-");
        if !allowed.contains(&key.as_str()) {
            return Err(entry.unsupported(format!(
                "option '{option}.{key}' is not implemented"
            )));
        }
    }
    Ok(())
}

fn block_string(
    entry: &Entry<'_>,
    option: &str,
    block: &serde_yaml::Mapping,
    key: &str,
) -> Result<String, ConfigError> {
    match block.get(serde_yaml::Value::String(key.to_string())) {
        None | Some(serde_yaml::Value::Null) => Ok(String::new()),
        Some(serde_yaml::Value::String(value)) => Ok(value.clone()),
        Some(other) => Err(entry.invalid(format!(
            "option '{option}.{key}' must be a string, found {}",
            crate::config::kind_name(other)
        ))),
    }
}

fn block_int(
    entry: &Entry<'_>,
    option: &str,
    block: &serde_yaml::Mapping,
    key: &str,
) -> Result<i64, ConfigError> {
    match block.get(serde_yaml::Value::String(key.to_string())) {
        None | Some(serde_yaml::Value::Null) => Ok(0),
        Some(serde_yaml::Value::Number(value)) => {
            value.as_i64().ok_or_else(|| {
                entry.invalid(format!("option '{option}.{key}' must be an integer"))
            })
        }
        Some(other) => Err(entry.invalid(format!(
            "option '{option}.{key}' must be an integer, found {}",
            crate::config::kind_name(other)
        ))),
    }
}

fn block_bool(
    entry: &Entry<'_>,
    option: &str,
    block: &serde_yaml::Mapping,
    key: &str,
) -> Result<bool, ConfigError> {
    match block.get(serde_yaml::Value::String(key.to_string())) {
        None | Some(serde_yaml::Value::Null) => Ok(false),
        Some(serde_yaml::Value::Bool(value)) => Ok(*value),
        Some(other) => Err(entry.invalid(format!(
            "option '{option}.{key}' must be a boolean, found {}",
            crate::config::kind_name(other)
        ))),
    }
}

fn block_string_list(
    entry: &Entry<'_>,
    option: &str,
    block: &serde_yaml::Mapping,
    key: &str,
) -> Result<Vec<String>, ConfigError> {
    match block.get(serde_yaml::Value::String(key.to_string())) {
        None | Some(serde_yaml::Value::Null) => Ok(Vec::new()),
        Some(serde_yaml::Value::Sequence(values)) => {
            let mut out = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    serde_yaml::Value::String(text) => out.push(text.clone()),
                    other => {
                        return Err(entry.invalid(format!(
                            "option '{option}.{key}' must be a list of strings, found {}",
                            crate::config::kind_name(other)
                        )))
                    }
                }
            }
            Ok(out)
        }
        Some(serde_yaml::Value::String(text)) => Ok(vec![text.clone()]),
        Some(other) => Err(entry.invalid(format!(
            "option '{option}.{key}' must be a list of strings, found {}",
            crate::config::kind_name(other)
        ))),
    }
}

/// Expand the pinned `utils.NewUnsignedRanges` syntax (`200/204/401-429`).
/// Empty and `*` are the empty list. Rejects more than 28 ranges, like the
/// pinned parser.
fn parse_port_ranges(value: &str, option: &str) -> Result<Vec<u16>, String> {
    let value = value.trim();
    if value.is_empty() || value == "*" {
        return Ok(Vec::new());
    }
    let normalized = value.replace(',', "/");
    let terms: Vec<&str> = normalized.split('/').collect();
    if terms.len() > 28 {
        return Err(format!(
            "option '{option}': too many ranges (maximum 28)"
        ));
    }
    let mut ports = Vec::new();
    for term in terms {
        let term = term.trim();
        if term.is_empty() {
            continue;
        }
        let (start, end) = match term.split_once('-') {
            Some((start, end)) => (
                start.trim().trim_matches(['[', ']']).parse::<u16>(),
                end.trim().trim_matches(['[', ']']).parse::<u16>(),
            ),
            None => {
                let port = term.trim_matches(['[', ']']).parse::<u16>();
                (port.clone(), port)
            }
        };
        let start = start.map_err(|_| format!("option '{option}': invalid range '{term}'"))?;
        let end = end.map_err(|_| format!("option '{option}': invalid range '{term}'"))?;
        if end < start {
            return Err(format!("option '{option}': invalid range '{term}'"));
        }
        ports.extend(start..=end);
    }
    Ok(ports)
}

/// Parse `hop-interval` with the pinned `NewUnsignedRange` + defaults (empty
/// 30 s, minimum 5 s, reversed range collapses to its start).
fn parse_hop_interval(entry: &Entry<'_>, value: Option<String>) -> Result<(u64, u64), ConfigError> {
    let raw = value.unwrap_or_default();
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok((30, 30));
    }
    let (upper, lower) = match raw.split_once('-') {
        Some((start, end)) => (
            start.trim().trim_matches(['[', ']']).parse::<u64>(),
            end.trim().trim_matches(['[', ']']).parse::<u64>(),
        ),
        None => {
            let value = raw.trim_matches(['[', ']']).parse::<u64>();
            (value.clone(), value)
        }
    };
    let mut start = upper.map_err(|_| entry.invalid("option 'hop-interval' is not a range"))?;
    let mut end = lower.map_err(|_| entry.invalid("option 'hop-interval' is not a range"))?;
    if start == 0 {
        start = 30;
    } else if start < 5 {
        start = 5;
    }
    if end < start {
        end = start;
    }
    Ok((start, end))
}

/// VMess (`adapter/outbound/vmess.go`, `transport/vmess`). Only the AEAD
/// header (`alterId: 0`) and the `tcp`/`ws` byte-stream transports are
/// implemented; every other option the pinned type declares is either a
/// transport this kernel rejects by name or a UDP/mux feature that has no
/// implementation here yet.
/// `tlsmirror-opts` (`TLSMirrorOptions`). The pinned decoder ignores unknown
/// keys, so `{enabled: true}` is a no-op and an absent `primary-key` selects
/// nothing. The feature extras this client does not implement are named only
/// when they are enabled.
fn parse_tlsmirror_options(
    entry: &mut Entry<'_>,
) -> Result<Option<TlsMirrorOptions>, ConfigError> {
    let Some(block) = entry.block("tlsmirror-opts")? else {
        return Ok(None);
    };
    let primary_key = block_string(entry, "tlsmirror-opts", block, "primary-key")?;
    if primary_key.is_empty() {
        return Ok(None);
    }
    for key in [
        "explicit-nonce-ciphersuites",
        "transport-layer-padding",
        "connection-enrolment",
        "embedded-traffic-generator",
    ] {
        if let Some(value) = block.get(serde_yaml::Value::String(key.to_string())) {
            if !is_noop_value(value) {
                return Err(entry.unsupported(format!(
                    "option 'tlsmirror-opts.{key}' is not implemented (only the plain TLS 1.3 record layer is)"
                )));
            }
        }
    }
    if block_bool(entry, "tlsmirror-opts", block, "sequence-watermarking-enabled")? {
        return Err(entry.unsupported(
            "option 'tlsmirror-opts.sequence-watermarking-enabled' is not implemented",
        ));
    }
    // Timing-only field; accepted and not otherwise observable.
    let _ = block.get(serde_yaml::Value::String("defer-instance-derived-write-time".to_string()));
    Ok(Some(TlsMirrorOptions { primary_key }))
}

/// `mekya-opts` (pinned `MekyaOptions.Build`). A `network` other than mekya
/// ignores the block, as the pinned decoder does.
fn parse_mekya_options(entry: &mut Entry<'_>) -> Result<MekyaOptions, ConfigError> {
    let Some(block) = entry.block("mekya-opts")? else {
        return Ok(MekyaOptions::default());
    };
    let keys = [
        "url",
        "h2-pool-size",
        "max-write-delay",
        "max-request-size",
        "polling-interval-initial",
        "max-write-size",
        "max-write-duration-ms",
        "max-simultaneous-write-connection",
        "packet-writing-buffer",
        "kcp",
    ];
    reject_block_keys(entry, "mekya-opts", block, &keys)?;
    let mut value = MekyaOptions::default();
    value.url = block_string(entry, "mekya-opts", block, "url")?;
    for (key, slot) in [
        ("h2-pool-size", &mut value.h2_pool_size),
        ("max-write-delay", &mut value.max_write_delay),
        ("max-request-size", &mut value.max_request_size),
        ("polling-interval-initial", &mut value.polling_interval_initial),
        ("max-write-size", &mut value.max_write_size),
        ("max-write-duration-ms", &mut value.max_write_duration_ms),
        (
            "max-simultaneous-write-connection",
            &mut value.max_simultaneous_write_connection,
        ),
        ("packet-writing-buffer", &mut value.packet_writing_buffer),
    ] {
        let read = block_int(entry, "mekya-opts", block, key)?;
        if !(0..=i64::from(u32::MAX)).contains(&read) {
            return Err(entry.invalid(format!("option 'mekya-opts.{key}' is out of range")));
        }
        *slot = read as u32;
    }
    if let Some(kcp) = block.get(serde_yaml::Value::String("kcp".to_string())) {
        let kcp = kcp.as_mapping().ok_or_else(|| {
            entry.invalid("option 'mekya-opts.kcp' must be a mapping")
        })?;
        value.kcp = parse_mkcp_block(entry, "mekya-opts.kcp", kcp)?;
    }
    Ok(value)
}

/// `mkcp-opts` (pinned `MKCPOptions.Build`). A block for another network is
/// not read by the pinned type, so it is only parsed when `network` selects it.
fn parse_mkcp_options(entry: &mut Entry<'_>) -> Result<MkcpOptions, ConfigError> {
    let Some(block) = entry.block("mkcp-opts")? else {
        return Ok(MkcpOptions::default());
    };
    parse_mkcp_block(entry, "mkcp-opts", block)
}

fn parse_mkcp_block(
    entry: &Entry<'_>,
    option: &str,
    block: &serde_yaml::Mapping,
) -> Result<MkcpOptions, ConfigError> {
    let keys = [
        "mtu",
        "tti",
        "uplink-capacity",
        "downlink-capacity",
        "congestion",
        "write-buffer",
        "read-buffer",
        "seed",
        "header",
    ];
    reject_block_keys(entry, option, block, &keys)?;
    let mut value = MkcpOptions::default();
    for (key, slot) in [
        ("mtu", &mut value.mtu),
        ("tti", &mut value.tti),
        ("uplink-capacity", &mut value.uplink_capacity),
        ("downlink-capacity", &mut value.downlink_capacity),
        ("write-buffer", &mut value.write_buffer),
        ("read-buffer", &mut value.read_buffer),
    ] {
        let read = block_int(entry, option, block, key)?;
        if read < 0 || read > i64::from(u32::MAX) {
            return Err(entry.invalid(format!("option '{option}.{key}' is out of range")));
        }
        *slot = read as u32;
    }
    value.congestion = block_bool(entry, option, block, "congestion")?;
    value.seed = block_string(entry, option, block, "seed")?;
    value.header = block_string(entry, option, block, "header")?;
    if !matches!(
        value.header.to_ascii_lowercase().as_str(),
        "" | "none" | "noop" | "srtp" | "utp" | "wechat-video" | "wechat" | "dtls" | "wireguard"
    ) {
        return Err(entry.invalid(format!(
            "option '{option}.header' value '{}' is unknown",
            value.header
        )));
    }
    Ok(value)
}

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
    let mut tls_settings = entry.tls_settings(true, true, tls)?;
    tls_settings.client_fingerprint = entry.client_fingerprint()?;
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
        "mkcp" | "kcp" => VmessNetwork::Mkcp(parse_mkcp_options(entry)?),
        "mekya" => VmessNetwork::Mekya(parse_mekya_options(entry)?),
        other => {
            return Err(entry.unsupported(format!(
                "option 'network' value '{other}' is not implemented (tcp, ws, mkcp, mekya)"
            )))
        }
    };
    if matches!(network, VmessNetwork::Ws(_)) && !tls {
        return Err(entry.unsupported(
            "option 'network: ws' requires 'tls: true' (the VMess WebSocket listener is TLS-only here)",
        ));
    }
    let udp = entry.bool("udp")?.unwrap_or(false);
    let packet_addr_flag = entry.bool("packet-addr")?.unwrap_or(false);
    let xudp_flag = entry.bool("xudp")?.unwrap_or(false);
    let packet_encoding = entry.string("packet-encoding")?.filter(|value| !value.is_empty());
    // Pinned `NewVmess`: `packetaddr`/`packet` select packet-addr, `xudp`
    // selects XUDP, and XUDP wins over packet-addr. Unlike vless there is no
    // XUDP default, so plain `command 2` remains possible.
    let mut packet_addr = packet_addr_flag;
    let mut xudp = xudp_flag;
    match packet_encoding.as_deref() {
        Some("packetaddr") | Some("packet") => {
            packet_addr = true;
            xudp = false;
        }
        Some("xudp") => xudp = true,
        _ => {}
    }
    if xudp {
        packet_addr = false;
    }
    let tlsmirror = parse_tlsmirror_options(entry)?;
    if tlsmirror.is_some() && !tls {
        return Err(entry.invalid(
            "option 'tlsmirror-opts' requires 'tls: true' (the pinned security mode is TLS-only)",
        ));
    }
    for key in ["global-padding", "authenticated-length"] {
        if entry.bool(key)?.unwrap_or(false) {
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
        udp,
        packet_addr,
        xudp,
        packet_encoding,
        tlsmirror,
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

// SPDX-License-Identifier: GPL-3.0-only
//
// Derived from Mihomo `transport/sudoku` (GPL-3.0), `adapter/outbound/sudoku.go`.
// Only this parser and the `SudokuOutbound` option table are GPL-derived; the
// rest of `proxies.rs` is original MIT code. See `THIRD_PARTY_NOTICES.md`.
/// Sudoku (`adapter/outbound/sudoku.go`). The pinned type validates the AEAD
/// method, the padding range, the table type and the HTTP mask mode; this
/// kernel implements the legacy mask, TCP sessions and the session mux, and
/// rejects the tunnel modes and UoT with the reason recorded.
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
                "option 'http-mask-mode' value '{mode}' is not implemented: the HTTP tunnel layer (`transport/sudoku/obfs/httpmask/tunnel_*`, split-stream/poll/WebSocket) is a mihomo extension over Sudoku and is not ported; the legacy header mask is"
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
        "on" => SudokuMultiplex::On,
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
    let tls_settings = entry.tls_settings(true, true, true)?;
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
    let tls_settings = entry.tls_settings(true, false, tls)?;
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
    let mut tls_settings = entry.tls_settings(true, true, true)?;
    tls_settings.client_fingerprint = entry.client_fingerprint()?;
    let alpn = entry.string_list("alpn")?;
    let up = entry.string("up")?.filter(|value| !value.is_empty());
    let send_bps = match up {
        Some(value) => {
            let rate = crate::outbound::hysteria::string_to_bps(&value);
            if rate == 0 {
                return Err(entry.invalid(format!(
                    "option 'up' value '{value}' is not a rate (use e.g. '50 Mbps' or '1000000')"
                )));
            }
            rate
        }
        None => 0,
    };
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
    let ports_value = entry.string("ports")?;
    let ports = match ports_value {
        Some(value) if !value.trim().is_empty() => {
            parse_port_ranges(&value, "ports").map_err(|error| entry.invalid(error))?
        }
        _ => Vec::new(),
    };
    let hop_interval_value = entry.string("hop-interval")?;
    let hop_interval = parse_hop_interval(entry, hop_interval_value)?;
    let obfs = entry.string("obfs")?.filter(|value| !value.is_empty());
    let obfs_password = entry
        .string("obfs-password")?
        .filter(|value| !value.is_empty())
        .map(Secret::new);
    if let Some(kind) = &obfs {
        if kind != "salamander" && kind != "gecko" {
            return Err(entry.invalid(format!(
                "option 'obfs' value '{kind}' is unknown (salamander, gecko)"
            )));
        }
        if obfs_password.is_none() {
            return Err(entry.invalid("option 'obfs' requires 'obfs-password'"));
        }
    }
    // The packet-size knobs are only applied by the pinned client when a Gecko
    // obfs is selected; without one they ask for nothing, so they load.
    let obfs_min_packet_size = entry.int("obfs-min-packet-size")?.unwrap_or(0);
    let obfs_max_packet_size = entry.int("obfs-max-packet-size")?.unwrap_or(0);
    let obfs_min_packet_size = if obfs_min_packet_size < 0 {
        return Err(entry.invalid("option 'obfs-min-packet-size' must not be negative"));
    } else {
        u32::try_from(obfs_min_packet_size)
            .map_err(|_| entry.invalid("option 'obfs-min-packet-size' is out of range"))?
    };
    let obfs_max_packet_size = if obfs_max_packet_size < 0 {
        return Err(entry.invalid("option 'obfs-max-packet-size' must not be negative"));
    } else {
        u32::try_from(obfs_max_packet_size)
            .map_err(|_| entry.invalid("option 'obfs-max-packet-size' is out of range"))?
    };
    if obfs.as_deref() == Some("gecko") {
        let min = if obfs_min_packet_size == 0 {
            512
        } else {
            obfs_min_packet_size
        };
        let max = if obfs_max_packet_size == 0 {
            1200
        } else {
            obfs_max_packet_size
        };
        if min == 0 || min > max || max > 2048 {
            return Err(entry.invalid(
                "obfs packet sizes must satisfy 0 < min <= max <= 2048",
            ));
        }
    }
    let udp_mtu = match entry.int("udp-mtu")? {
        Some(value) if value < 0 || value > i64::from(u16::MAX) => {
            return Err(entry.invalid("option 'udp-mtu' is out of range"))
        }
        Some(value) if value != 0 => value as u16,
        _ => 0,
    };
    let cwnd = match entry.int("cwnd")? {
        Some(value) if value < 0 => {
            return Err(entry.invalid("option 'cwnd' must not be negative"))
        }
        Some(0) | None => 0,
        Some(value) => u32::try_from(value)
            .map_err(|_| entry.invalid("option 'cwnd' is out of range"))?,
    };
    let bbr_profile = entry.string("bbr-profile")?.filter(|value| !value.is_empty());
    if let Some(profile) = &bbr_profile {
        if !matches!(profile.as_str(), "conservative" | "standard" | "aggressive") {
            return Err(entry.invalid(format!(
                "option 'bbr-profile' value '{profile}' is unknown (conservative, standard, aggressive)"
            )));
        }
    }
    let realm = parse_hysteria2_realm(entry)?;
    // The pinned `hysteria2.NewClient` rejects a non-empty port pool together
    // with realm rendezvous: the punch owns the UDP socket and the port hop
    // would rewrite the same destination.
    if realm.is_some() && !ports.is_empty() {
        return Err(entry.invalid("realm and port hopping are mutually exclusive"));
    }
    // quinn exposes one receive window per stream/connection (it uses the same
    // value as both the initial and maximum): take the maximum when both are
    // set, otherwise the initial one.
    let stream_receive_window = receive_window(
        entry,
        "initial-stream-receive-window",
        "max-stream-receive-window",
    )?;
    let connection_receive_window = receive_window(
        entry,
        "initial-connection-receive-window",
        "max-connection-receive-window",
    )?;
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
        send_bps,
        receive_bps,
        handshake_timeout,
        cwnd,
        stream_receive_window,
        connection_receive_window,
        ports,
        hop_interval,
        obfs,
        obfs_password,
        obfs_min_packet_size,
        obfs_max_packet_size,
        udp_mtu,
        bbr_profile,
        realm,
        dialer_proxy,
    })
}

/// `realm-opts` (`Hysteria2RealmOption`). A disabled or empty block is a
/// no-op; an enabled block requires `server-url` exactly like the pinned
/// `realm.NewControlClient`.
fn parse_hysteria2_realm(
    entry: &mut Entry<'_>,
) -> Result<Option<Hysteria2Realm>, ConfigError> {
    let Some(block) = entry.block("realm-opts")? else {
        return Ok(None);
    };
    let keys = [
        "enable",
        "server-url",
        "token",
        "realm-id",
        "stun-servers",
        "sni",
        "skip-cert-verify",
        "name-cert-verify",
        "fingerprint",
        "certificate",
        "private-key",
        "alpn",
    ];
    reject_block_keys(entry, "realm-opts", block, &keys)?;
    let enable = block_bool(entry, "realm-opts", block, "enable")?;
    if !enable {
        return Ok(None);
    }
    let server_url = block_string(entry, "realm-opts", block, "server-url")?;
    if server_url.is_empty() {
        return Err(entry.invalid(
            "option 'realm-opts.server-url' is required when realm is enabled",
        ));
    }
    let token = {
        let value = block_string(entry, "realm-opts", block, "token")?;
        if value.is_empty() {
            None
        } else {
            Some(Secret::new(value))
        }
    };
    let realm_id = Some(block_string(entry, "realm-opts", block, "realm-id")?)
        .filter(|value| !value.is_empty());
    let stun_servers = block_string_list(entry, "realm-opts", block, "stun-servers")?;
    let mut tls_settings = TlsSettings {
        sni: Some(block_string(entry, "realm-opts", block, "sni")?)
            .filter(|value| !value.is_empty()),
        skip_cert_verify: block_bool(entry, "realm-opts", block, "skip-cert-verify")?,
        alpn: block_string_list(entry, "realm-opts", block, "alpn")?,
        ..Default::default()
    };
    tls_settings.name_cert_verify = Some(block_string(
        entry,
        "realm-opts",
        block,
        "name-cert-verify",
    )?)
    .filter(|value| !value.is_empty());
    // `fingerprint` is the pinned SHA-256 certificate pin (DER, not SPKI) and
    // must be applied even when `skip-cert-verify` is true: `GetTLSConfig`
    // installs the fingerprint verifier and only then sets InsecureSkipVerify.
    let fingerprint = block_string(entry, "realm-opts", block, "fingerprint")?;
    if !fingerprint.is_empty() {
        tls_settings.fingerprint = Some(parse_fingerprint(&fingerprint).map_err(|error| {
            entry.invalid(format!("option 'realm-opts.fingerprint': {error}"))
        })?);
    }
    let certificate = block_string(entry, "realm-opts", block, "certificate")?;
    if !certificate.is_empty() {
        tls_settings.certificate = Some(certificate);
    }
    let private_key = block_string(entry, "realm-opts", block, "private-key")?;
    if !private_key.is_empty() {
        tls_settings.private_key = Some(private_key);
    }
    validate_realm_tls_material(entry, &tls_settings)?;
    Ok(Some(Hysteria2Realm {
        server_url,
        token,
        realm_id,
        stun_servers,
        tls_settings,
    }))
}

/// Validate the realm-control client identity at load, like the pinned
/// `NewTLSKeyPairLoader` does when `GetTLSConfig` builds the control client:
/// both fields are required together, an inline PEM is parsed, and a path must
/// be absolute (the kernel has no configuration-directory resolver, so a
/// relative path would otherwise be read from the process CWD — silently
/// different from the pinned `C.Path.Resolve`).
fn validate_realm_tls_material(
    entry: &Entry<'_>,
    settings: &TlsSettings,
) -> Result<(), ConfigError> {
    match (&settings.certificate, &settings.private_key) {
        (None, None) => return Ok(()),
        (Some(_), None) | (None, Some(_)) => {
            return Err(entry.invalid(
                "options 'realm-opts.certificate' and 'realm-opts.private-key' must be set together",
            ))
        }
        (Some(_), Some(_)) => {}
    }
    for (name, value) in [
        ("certificate", settings.certificate.as_deref().unwrap_or_default()),
        ("private-key", settings.private_key.as_deref().unwrap_or_default()),
    ] {
        if value.contains("-----BEGIN") {
            continue;
        }
        let path = std::path::Path::new(value);
        if !path.is_absolute() {
            return Err(entry.invalid(format!(
                "option 'realm-opts.{name}' must be an inline PEM or an absolute path (relative paths are not resolvable)"
            )));
        }
        if !path.is_file() {
            return Err(entry.invalid(format!(
                "option 'realm-opts.{name}' file '{value}' does not exist"
            )));
        }
    }
    crate::outbound::tls::client_auth(settings).map_err(|error| {
        entry.invalid(format!(
            "option 'realm-opts.certificate'/'realm-opts.private-key': {error}"
        ))
    })?;
    Ok(())
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
    let protocol = {
        let raw = entry
            .string("obfs-protocol")?
            .filter(|value| !value.is_empty())
            .or(entry.string("protocol")?.filter(|value| !value.is_empty()));
        match raw.as_deref() {
            None | Some("udp") => HysteriaProtocol::Udp,
            // The pinned transport spells it `wechat-video`; the adapter
            // accepts `wechat` as the same shape (`wechat` is what the docs
            // call it).
            Some("wechat") | Some("wechat-video") => HysteriaProtocol::WeChat,
            Some("faketcp") => HysteriaProtocol::FakeTcp,
            Some(other) => {
                return Err(entry.unsupported(format!(
                    "option 'protocol' value '{other}' is not implemented (udp, wechat-video, faketcp)"
                )))
            }
        }
    };
    let obfs = entry.string("obfs")?.filter(|value| !value.is_empty());
    let ports = match entry.string("ports")?.filter(|value| !value.trim().is_empty()) {
        Some(value) => parse_port_ranges(&value, "ports").map_err(|error| entry.invalid(error))?,
        None => Vec::new(),
    };
    let hop_interval = match entry.int("hop-interval")? {
        Some(value) if value < 0 => {
            return Err(entry.invalid("option 'hop-interval' must not be negative"))
        }
        Some(0) | None => 10,
        Some(value) => value as u64,
    };
    let stream_receive_window = receive_window(entry, "recv-window-conn", "")?;
    let connection_receive_window = receive_window(entry, "recv-window", "")?;
    let disable_mtu_discovery = entry.bool("disable-mtu-discovery")?.unwrap_or(false);
    let fast_open = entry.bool("fast-open")?.unwrap_or(false);
    let tls_settings = entry.tls_settings(true, true, true)?;
    let mut tls_settings = tls_settings;
    tls_settings.client_fingerprint = entry.client_fingerprint()?;
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
        ports,
        hop_interval,
        obfs,
        protocol,
        fast_open,
        stream_receive_window,
        connection_receive_window,
        disable_mtu_discovery,
        dialer_proxy,
    })
}

/// TUIC (`adapter/outbound/tuic.go`). A non-empty `token` selects the legacy
/// v4 protocol (BLAKE3 TKN); otherwise `uuid`/`password` select v5. The UDP
/// relay (`native` datagrams or `quic` uni streams), UoT, datagram sizing,
/// congestion tuning, `fast-open` and `reduce-rtt` (parsed; the pinned adapter
/// also has no TLS session cache, so both fall back to a full handshake) are
/// parsed per the pinned derivation.
fn parse_tuic(entry: &mut Entry<'_>) -> Result<TuicOutbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    let token = entry
        .string("token")?
        .filter(|value| !value.is_empty())
        .map(Secret::new);
    let uuid_raw = entry.string("uuid")?.unwrap_or_default();
    let uuid = if uuid_raw.is_empty() {
        [0u8; 16]
    } else {
        parse_uuid(&uuid_raw).map_err(|e| entry.invalid(format!("option 'uuid': {e}")))?
    };
    if token.is_none() && uuid_raw.is_empty() {
        return Err(entry.invalid(
            "missing authentication: set 'uuid' and 'password' (v5) or 'token' (v4)",
        ));
    }
    let password = Secret::new(entry.string("password")?.unwrap_or_default());
    let ip = entry.string("ip")?.filter(|value| !value.is_empty());
    let mut tls_settings = entry.tls_settings(true, true, true)?;
    tls_settings.client_fingerprint = entry.client_fingerprint()?;
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
    let udp_relay_mode = {
        let raw = entry.string("udp-relay-mode")?.filter(|value| !value.is_empty());
        if let Some(mode) = raw.as_deref() {
            if mode != "quic" && mode != "native" {
                return Err(entry.invalid(format!(
                    "option 'udp-relay-mode' value '{mode}' is unknown (quic, native)"
                )));
            }
        }
        TuicRelayMode::parse(raw.as_deref())
    };
    // Congestion tuning maps onto quinn's transport config. cubic/new_reno/bbr
    // exist in quinn; the pinned meta BBR v2 is an alias of bbr, while the old
    // meta BBR v1 controller has no quinn equivalent and is named.
    let congestion_controller = match entry
        .string("congestion-controller")?
        .filter(|value| !value.is_empty())
    {
        None => None,
        Some(value) => match value.as_str() {
            // `bbr_meta_v2` falls through to the same sender as `bbr` in the
            // pinned `common.SetCongestionController`. `bbr_meta_v1` is the
            // legacy meta BBR sender; quinn exposes one BBR controller
            // (v2-shaped), so selecting it is the closest available
            // approximation and is recorded as such.
            "cubic" | "new_reno" | "bbr" | "bbr_meta_v1" | "bbr_meta_v2" => Some(value),
            other => {
                return Err(entry.unsupported(format!(
                    "option 'congestion-controller' value '{other}' is not implemented (cubic, new_reno, bbr, bbr_meta_v1, bbr_meta_v2)"
                )))
            }
        },
    };
    let bbr_profile = entry.string("bbr-profile")?.filter(|value| !value.is_empty());
    if let Some(profile) = &bbr_profile {
        if !matches!(profile.as_str(), "conservative" | "standard" | "aggressive") {
            return Err(entry.invalid(format!(
                "option 'bbr-profile' value '{profile}' is unknown (conservative, standard, aggressive)"
            )));
        }
    }
    let cwnd = match entry.int("cwnd")? {
        Some(value) if value < 0 => {
            return Err(entry.invalid("option 'cwnd' must not be negative"))
        }
        Some(0) | None => 0,
        Some(value) => u32::try_from(value)
            .map_err(|_| entry.invalid("option 'cwnd' is out of range"))?,
    };
    let stream_receive_window = receive_window(entry, "recv-window-conn", "")?;
    let connection_receive_window = receive_window(entry, "recv-window", "")?;
    let disable_mtu_discovery = entry.bool("disable-mtu-discovery")?.unwrap_or(false);
    // Parity: the pinned TUIC adapter passes `reduce-rtt` as quic-go's
    // `DialEarly` but never sets `tls.Config.ClientSessionCache`, so it has no
    // ticket to resume from and the call falls back to a full handshake (the
    // shadowquic adapter sets the cache explicitly). Parsing the flag is
    // therefore the matching behaviour; it is not a hidden rejection.
    let reduce_rtt = entry.bool("reduce-rtt")?.unwrap_or(false);
    let fast_open = entry.bool("fast-open")?.unwrap_or(false);
    let udp_over_stream = entry.bool("udp-over-stream")?.unwrap_or(false);
    let udp_over_stream_version = match entry.int("udp-over-stream-version")? {
        Some(value) if value < 0 => {
            return Err(entry.invalid("option 'udp-over-stream-version' must be positive"))
        }
        Some(0) | None => 1u8,
        Some(1) => 1,
        Some(2) => 2,
        Some(value) => {
            return Err(entry.invalid(format!(
                "option 'udp-over-stream-version' value {value} is unknown (1, 2)"
            )))
        }
    };
    // The pinned `NewTuic` derives the datagram/frame bounds:
    //   overhead = v4 PacketOverHead (27) or v5 (29, an IPv6 address)
    //   max-datagram-frame-size default = max-udp-relay-packet-size + overhead
    //   max-datagram-frame-size is capped at 1400
    //   max-udp-relay-packet-size = max-datagram-frame-size - overhead
    // and clamps the v5 relay packet to `MaxFragSizeV5` (1200 - 29 - 3 =
    // 1168). v4 has no fragment clamp.
    let overhead = if token.is_some() { 27usize } else { 29usize };
    let requested_packet = match entry.int("max-udp-relay-packet-size")? {
        Some(value) if value < 0 => {
            return Err(entry.invalid("option 'max-udp-relay-packet-size' must not be negative"))
        }
        Some(0) | None => 1252usize,
        Some(value) => usize::try_from(value)
            .map_err(|_| entry.invalid("option 'max-udp-relay-packet-size' is out of range"))?,
    };
    let requested_frame = match entry.int("max-datagram-frame-size")? {
        Some(value) if value < 0 => {
            return Err(entry.invalid("option 'max-datagram-frame-size' must not be negative"))
        }
        Some(0) | None => requested_packet + overhead,
        Some(value) => usize::try_from(value)
            .map_err(|_| entry.invalid("option 'max-datagram-frame-size' is out of range"))?,
    };
    let max_datagram_frame_size = requested_frame.min(1400);
    let mut max_udp_relay_packet_size = max_datagram_frame_size.saturating_sub(overhead);
    if token.is_none() {
        max_udp_relay_packet_size = max_udp_relay_packet_size.min(1168);
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
        token,
        uuid,
        password,
        ip,
        tls_settings,
        alpn: entry.string_list("alpn")?,
        disable_sni,
        heartbeat_interval,
        request_timeout,
        udp_relay_mode,
        udp_over_stream,
        udp_over_stream_version,
        max_datagram_frame_size,
        max_udp_relay_packet_size,
        reduce_rtt,
        fast_open,
        congestion_controller,
        cwnd,
        bbr_profile,
        stream_receive_window,
        connection_receive_window,
        disable_mtu_discovery,
        dialer_proxy,
    })
}


/// MASQUE (`adapter/outbound/masque.go` + `transport/masque`). Two shapes:
///
/// * a bare server (`udp: true`) is the RFC 9298 CONNECT-UDP subset
///   (`outbound/masque.rs`);
/// * `private-key`/`public-key` (with `ip`/`ipv6`) is the pinned Cloudflare
///   WARP CONNECT-IP client (`outbound/masque_ip.rs`): the keys are parsed and
///   validated here (P-256 only, as the pinned adapter's ECDSA assertion),
///   `uri` becomes the request URI, `ip`/`ipv6` the tunnel's local addresses,
///   `mtu` its packet bound, `ip-stack` the userspace-stack selection and
///   `remote-dns-resolve`/`dns` the tunnel's resolver. The `h2` CONNECT-IP
///   variant, `h3-l4proxy`, the QUIC congestion-controller options and
///   `dialer-proxy` are still rejected by name.
fn parse_masque(entry: &mut Entry<'_>) -> Result<MasqueOutbound, ConfigError> {
    reject_unwired_basic(entry, "masque")?;
    let server = entry.server()?;
    let port = entry.port()?;
    if let Some(network) = entry.string("network")?.filter(|value| !value.is_empty()) {
        let mode = match network.as_str() {
            "h2" => "HTTP/2 CONNECT-IP",
            "h3-l4proxy" => "the h3-l4proxy L4 client",
            _ => "a non-HTTP/3 transport",
        };
        return Err(entry.unsupported(format!(
            "option 'network' value '{network}' ({mode}) is not implemented: this kernel implements CONNECT-IP over HTTP/3 (`network` unset) and the RFC 9298 CONNECT-UDP subset"
        )));
    }
    let private_key = entry.string("private-key")?.filter(|value| !value.is_empty());
    let public_key = entry.string("public-key")?.filter(|value| !value.is_empty());
    let uri = entry.string("uri")?.filter(|value| !value.is_empty());
    let ip = entry.string("ip")?.filter(|value| !value.is_empty());
    let ipv6 = entry.string("ipv6")?.filter(|value| !value.is_empty());
    let mtu = match entry.int("mtu")? {
        Some(value) if !(0..=65535).contains(&value) => {
            return Err(entry.invalid("option 'mtu' must be in 0..=65535"))
        }
        Some(value) => value as u16,
        None => 0,
    };
    let ip_stack = entry.block("ip-stack")?;
    let remote_dns_resolve = entry.bool("remote-dns-resolve")?.unwrap_or(false);
    let dns = entry.string_list("dns")?;

    let mut ip_stack_mode = "auto".to_string();
    let mut ip_stack_options = 0usize;
    if let Some(block) = ip_stack {
        for (key, value) in block {
            let key = key
                .as_str()
                .ok_or_else(|| entry.invalid("ip-stack keys must be strings"))?;
            ip_stack_options += 1;
            match key {
                "mode" => {
                    let mode = value.as_str().unwrap_or("").to_ascii_lowercase();
                    match mode.as_str() {
                        "" | "auto" | "mips" => ip_stack_mode = mode,
                        "gvisor" => {
                            return Err(entry.unsupported(
                                "option 'ip-stack.mode' value 'gvisor' is not implemented: gVisor's userspace stack is the build-tagged `with_gvisor` dependency of the pinned binary, which this kernel does not link; the in-tree UDP-only IP stack is used instead",
                            ))
                        }
                        other => {
                            return Err(entry.invalid(format!(
                                "option 'ip-stack.mode' value '{other}' is not valid; expected auto, gvisor, or mips"
                            )))
                        }
                    }
                }
                "congestion-controller" => {
                    let controller = value.as_str().unwrap_or("").to_ascii_lowercase();
                    // These select the TCP congestion controller of the
                    // userspace stack; this kernel terminates UDP only, so the
                    // value is validated and has no effect (registered as a
                    // TCP-over-tunnel gap, never a silent success).
                    match controller.as_str() {
                        "" | "cubic" | "reno" | "bbr" | "bbr3" => {}
                        other => {
                            return Err(entry.invalid(format!(
                                "option 'ip-stack.congestion-controller' value '{other}' is not valid; expected cubic, reno, bbr, or bbr3"
                            )))
                        }
                    }
                }
                other => {
                    return Err(entry.unsupported(format!(
                        "option 'ip-stack.{other}' is not implemented: the pinned userspace stack has only 'mode' and 'congestion-controller'"
                    )))
                }
            }
        }
    }

    let connect_ip = if private_key.is_some()
        || public_key.is_some()
        || uri.is_some()
        || ip.is_some()
        || ipv6.is_some()
        || mtu != 0
        || ip_stack_options > 0
        || remote_dns_resolve
        || !dns.is_empty()
    {
        let private_key = private_key.ok_or_else(|| {
            entry.invalid(
                "option 'private-key' is required for the Cloudflare WARP CONNECT-IP shape; a plain server without it selects the RFC 9298 CONNECT-UDP subset",
            )
        })?;
        let public_key = public_key.ok_or_else(|| {
            entry.invalid("option 'public-key' is required for the Cloudflare WARP CONNECT-IP shape")
        })?;
        // Validate the key material now, as the pinned adapter does while
        // constructing the outbound; the identity is rebuilt at connect.
        crate::outbound::warp::parse_private_key(&private_key)
            .map_err(|error| entry.invalid(error))?;
        let public_key_der = crate::outbound::warp::parse_public_key(&public_key)
            .map_err(|error| entry.invalid(error))?;
        let mut local = Vec::new();
        for (key, value) in [("ip", &ip), ("ipv6", &ipv6)] {
            if let Some(value) = value {
                let prefix = IpPrefix::parse(value)
                    .map_err(|error| entry.invalid(format!("option '{key}': {error}")))?;
                let expected_v4 = key == "ip";
                if prefix.addr.is_ipv4() != expected_v4 {
                    return Err(entry.invalid(format!(
                        "option '{key}' value '{value}' is not an {} address",
                        if expected_v4 { "IPv4" } else { "IPv6" }
                    )));
                }
                local.push(prefix);
            }
        }
        if local.is_empty() {
            return Err(entry.invalid(
                "missing local address: the CONNECT-IP shape needs 'ip' and/or 'ipv6' (the pinned `Prefixes` refuses an empty address list)",
            ));
        }
        let uri = uri.unwrap_or_else(|| crate::outbound::masque_ip::DEFAULT_WARP_URI.to_string());
        let (uri_authority, uri_path) = crate::outbound::masque_ip::parse_connect_uri(&uri)
            .map_err(|error| entry.invalid(error))?;
        let mut servers = Vec::new();
        for value in &dns {
            let server = parse_masque_dns_server(value)
                .map_err(|error| entry.invalid(format!("option 'dns': {error}")))?;
            servers.push(server);
        }
        let mtu = if mtu == 0 {
            crate::outbound::ipstack::DEFAULT_MTU
        } else if usize::from(mtu) < crate::outbound::ipstack::MIN_MTU {
            return Err(entry.invalid(format!(
                "option 'mtu' value {mtu} is below the IPv4 minimum of {}",
                crate::outbound::ipstack::MIN_MTU
            )));
        } else {
            mtu
        };
        Some(MasqueConnectIp {
            private_key: Secret::new(private_key),
            public_key: Secret::new(public_key),
            public_key_der,
            uri,
            uri_authority,
            uri_path,
            local,
            mtu,
            ip_stack_mode,
            remote_dns_resolve,
            dns: servers,
        })
    } else {
        None
    };

    let congestion_controller = match entry
        .string("congestion-controller")?
        .filter(|value| !value.is_empty())
    {
        None => None,
        Some(value) => match value.as_str() {
            // `bbr_meta_v2` falls through to the same sender as `bbr` in the
            // pinned `common.SetCongestionController`; only the old meta BBR
            // v1 controller has no quinn equivalent.
            "cubic" | "new_reno" | "bbr" | "bbr_meta_v2" => Some(value),
            "bbr_meta_v1" => {
                return Err(entry.unsupported(
                    "option 'congestion-controller' value 'bbr_meta_v1' is not implemented (quinn has only its BBR v2-style controller; the pinned meta BBR v1 sender is absent)",
                ))
            }
            other => {
                return Err(entry.unsupported(format!(
                    "option 'congestion-controller' value '{other}' is not implemented (cubic, new_reno, bbr, bbr_meta_v2)"
                )))
            }
        },
    };
    if entry
        .string("bbr-profile")?
        .is_some_and(|value| !value.is_empty())
    {
        return Err(entry.unsupported(
            "option 'bbr-profile' is not implemented: quinn's BBR controller has no profile selector",
        ));
    }
    let cwnd = match entry.int("cwnd")? {
        Some(value) if value < 0 => {
            return Err(entry.invalid("option 'cwnd' must not be negative"))
        }
        Some(0) | None => 0,
        Some(value) => u32::try_from(value)
            .map_err(|_| entry.invalid("option 'cwnd' is out of range"))?,
    };
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
    let tls_settings = entry.tls_settings(true, false, false)?;
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
        congestion_controller,
        cwnd,
        udp,
        connect_ip,
    })
}

/// One `dns` entry of the pinned resolver: a UDP name server. Accepted forms
/// are `1.1.1.1`, `1.1.1.1:53`, `[fd00::1]`, `[fd00::1]:53` and
/// `udp://<the same>`. DoH/DoT/TCP name servers and the `#param` suffixes need
/// transports this kernel does not have, so they are refused by name.
fn parse_masque_dns_server(value: &str) -> Result<SocketAddr, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("empty name server".to_string());
    }
    if let Some((_, params)) = value.split_once('#') {
        if !params.is_empty() {
            return Err(format!(
                "'{value}': name server parameters ('#...') are not implemented"
            ));
        }
    }
    let rest = match value.split_once("://") {
        Some((scheme, rest)) => {
            if !scheme.eq_ignore_ascii_case("udp") {
                return Err(format!(
                    "'{value}': only udp:// name servers are implemented (DNS over TCP/DoT/DoH needs transports the CONNECT-IP tunnel does not carry)"
                ));
            }
            rest
        }
        None => value,
    };
    let rest = rest.trim_end_matches('/');
    let (host, port) = if let Some(bracketed) = rest.strip_prefix('[') {
        let (host, tail) = bracketed
            .split_once(']')
            .ok_or_else(|| format!("'{value}': unbalanced IPv6 brackets"))?;
        let port = match tail.strip_prefix(':') {
            Some(port) => port
                .parse::<u16>()
                .map_err(|_| format!("'{value}': invalid port '{port}'"))?,
            None if tail.is_empty() => 53,
            None => return Err(format!("'{value}': unexpected '{tail}' after the address")),
        };
        (host.to_string(), port)
    } else {
        match rest.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (
                host.to_string(),
                port.parse::<u16>()
                    .map_err(|_| format!("'{value}': invalid port '{port}'"))?,
            ),
            _ => (rest.to_string(), 53),
        }
    };
    let ip: IpAddr = host
        .parse()
        .map_err(|_| format!("'{value}': '{host}' is not an IP address (name servers are not resolved recursively)"))?;
    if port == 0 {
        return Err(format!("'{value}': port 0 is not a name server port"));
    }
    Ok(SocketAddr::new(ip, port))
}

/// WireGuard (`adapter/outbound/wireguard.go`): the Noise IK transport is
/// implemented (`outbound/wireguard.rs`); the userspace IP stack that turns
/// the tunnel into TCP/UDP sockets is T6/T7, so `ip-stack`, `remote-dns-resolve`
/// and `dns` are rejected by name.
fn parse_wireguard(entry: &mut Entry<'_>) -> Result<WireguardOutbound, ConfigError> {
    reject_unwired_basic(entry, "wireguard")?;
    let private_key_text = entry.required_string("private-key")?;
    if crate::outbound::wireguard::decode_key(&private_key_text).is_err() {
        return Err(entry.invalid("option 'private-key' must be base64 of 32 bytes"));
    }
    let private_key = Secret::new(private_key_text);
    let ip = entry.string("ip")?.filter(|value| !value.is_empty());
    let ipv6 = entry.string("ipv6")?.filter(|value| !value.is_empty());
    for (key, value) in [("ip", &ip), ("ipv6", &ipv6)] {
        if let Some(value) = value {
            if parse_wireguard_prefix(value).is_none() {
                return Err(entry.invalid(format!(
                    "option '{key}' value '{value}' is not an IP address or CIDR prefix"
                )));
            }
        }
    }
    let workers = match entry.int("workers")? {
        Some(value) if value < 0 => return Err(entry.invalid("option 'workers' must not be negative")),
        Some(value) => u16::try_from(value)
            .map_err(|_| entry.invalid("option 'workers' is too large"))?,
        None => 0,
    };
    let mtu = match entry.int("mtu")? {
        Some(value) if value < 0 => return Err(entry.invalid("option 'mtu' must not be negative")),
        Some(value) => u32::try_from(value).map_err(|_| entry.invalid("option 'mtu' is too large"))?,
        None => 0,
    };
    let udp = entry.bool("udp")?.unwrap_or(false);
    let persistent_keepalive = match entry.int("persistent-keepalive")? {
        Some(value) if !(0..=65535).contains(&value) => {
            return Err(entry.invalid("option 'persistent-keepalive' must be in 0..=65535"))
        }
        Some(value) => value as u16,
        None => 0,
    };
    if let Some(block) = entry.block("ip-stack")? {
        for (key, value) in block {
            let key = key
                .as_str()
                .ok_or_else(|| entry.invalid("ip-stack keys must be strings"))?;
            match key {
                "mode" => {
                    let mode = value.as_str().unwrap_or("").to_ascii_lowercase();
                    if !mode.is_empty() && mode != "auto" {
                        return Err(entry.unsupported(format!(
                            "option 'ip-stack.mode' value '{mode}' is not implemented: the userspace IP stack (mips/gVisor) and its TUN device belong to the T6/T7 device layer; the WireGuard transport itself is implemented and exposed to that layer"
                        )));
                    }
                }
                "congestion-controller" => {
                    if value.as_str().is_some_and(|value| !value.is_empty()) {
                        return Err(entry.unsupported(
                            "option 'ip-stack.congestion-controller' is not implemented: it configures the T6/T7 userspace IP stack",
                        ));
                    }
                }
                other => {
                    return Err(entry.unsupported(format!(
                        "option 'ip-stack.{other}' is not implemented"
                    )))
                }
            }
        }
    }
    if entry
        .block("amnezia-wg-option")?
        .is_some_and(|block| !block.is_empty())
    {
        return Err(entry.unsupported(
            "option 'amnezia-wg-option' is not implemented: AmneziaWG adds its own header obfuscation (jc/jmin/jmax/s1..s4/h1..h4, v1.5/v2/v3 variants) implemented by the pinned amneziawg-go device; no AmneziaWG crate or device is available offline, so this kernel speaks plain WireGuard only",
        ));
    }
    if entry.bool("remote-dns-resolve")?.unwrap_or(false) {
        return Err(entry.unsupported(
            "option 'remote-dns-resolve' is not implemented: it resolves through the pinned userspace IP stack's resolver (T6/T7 device layer)",
        ));
    }
    if !entry.string_list("dns")?.is_empty() {
        return Err(entry.unsupported(
            "option 'dns' is not implemented: it configures the pinned userspace IP stack's resolver (T6/T7 device layer)",
        ));
    }
    if entry.int("refresh-server-ip-interval")?.unwrap_or(0) != 0 {
        return Err(entry.unsupported(
            "option 'refresh-server-ip-interval' is not implemented: it is a runtime endpoint-resolution loop around the pinned device; the transport resolves the peer endpoint once per connection",
        ));
    }
    if entry
        .string("dialer-proxy")?
        .filter(|value| !value.is_empty())
        .is_some()
    {
        return Err(entry.unsupported(
            "option 'dialer-proxy' is not implemented for wireguard: the tunnel is one UDP socket and cannot be reached through the supported socks5 TCP hop",
        ));
    }

    let mut peers = Vec::new();
    if let Some(value) = entry.get("peers") {
        let Some(sequence) = value.as_sequence() else {
            if value.is_null() {
                return finish_wireguard(entry, private_key, ip, ipv6, workers, mtu, udp, persistent_keepalive, Vec::new());
            }
            return Err(entry.invalid("option 'peers' must be a list"));
        };
        for (index, item) in sequence.iter().enumerate() {
            let Some(mapping) = item.as_mapping() else {
                return Err(entry.invalid(format!("option 'peers[{index}]' must be a mapping")));
            };
            peers.push(parse_wireguard_peer(entry, index, mapping)?);
        }
    }

    if peers.is_empty() {
        // The pinned type also accepts one peer at the top level (the
        // `WireGuardPeerOption` fields are embedded in `WireGuardOption`).
        let public_key = entry.string("public-key")?.filter(|value| !value.is_empty());
        if let Some(public_key) = public_key {
            if crate::outbound::wireguard::decode_key(&public_key).is_err() {
                return Err(entry.invalid("option 'public-key' must be base64 of 32 bytes"));
            }
            let preshared_key = entry
                .string("pre-shared-key")?
                .filter(|value| !value.is_empty())
                .map(Secret::new);
            if let Some(key) = &preshared_key {
                if crate::outbound::wireguard::decode_key(key.expose()).is_err() {
                    return Err(entry.invalid(
                        "option 'pre-shared-key' must be base64 of 32 bytes",
                    ));
                }
            }
            let reserved_value = entry.get("reserved");
            let reserved = parse_wireguard_reserved(entry, "reserved", reserved_value)?;
            let allowed_ips = entry.string_list("allowed-ips")?;
            let allowed_ips = if allowed_ips.is_empty() {
                let mut defaults = Vec::new();
                if ip.is_some() {
                    defaults.push("0.0.0.0/0".to_string());
                }
                if ipv6.is_some() {
                    defaults.push("::/0".to_string());
                }
                defaults
            } else {
                allowed_ips
            };
            let server = entry.string("server")?.unwrap_or_default();
            let port = match entry.int("port")? {
                Some(value) if (1..=65535).contains(&value) => value as u16,
                Some(_) => return Err(entry.invalid("option 'port' must be in 1..=65535")),
                None => 0,
            };
            if server.is_empty() || port == 0 {
                return Err(entry.invalid(
                    "a single WireGuard peer needs 'server' and 'port' (or put the peer in 'peers')",
                ));
            }
            peers.push(WireguardPeerOutbound {
                server,
                port,
                public_key,
                preshared_key,
                reserved,
                allowed_ips,
            });
        }
    }

    finish_wireguard(entry, private_key, ip, ipv6, workers, mtu, udp, persistent_keepalive, peers)
}

#[allow(clippy::too_many_arguments)]
fn finish_wireguard(
    entry: &mut Entry<'_>,
    private_key: Secret,
    ip: Option<String>,
    ipv6: Option<String>,
    workers: u16,
    mtu: u32,
    udp: bool,
    persistent_keepalive: u16,
    peers: Vec<WireguardPeerOutbound>,
) -> Result<WireguardOutbound, ConfigError> {
    if peers.is_empty() {
        return Err(entry.invalid(
            "missing required option 'peers' (or the single-peer 'public-key'/'server'/'port' form)",
        ));
    }
    // The single-peer fields are part of the pinned type even when `peers:`
    // is used; Mihomo ignores them then, so reading them is a no-op here.
    let _ = entry.string("public-key")?;
    let _ = entry.string("pre-shared-key")?;
    let _ = entry.string_list("allowed-ips")?;
    let _ = entry.string("server")?;
    let _ = entry.int("port")?;
    entry.get("reserved");
    let allowed = [
        "name",
        "type",
        "private-key",
        "ip",
        "ipv6",
        "workers",
        "mtu",
        "udp",
        "persistent-keepalive",
        "ip-stack",
        "amnezia-wg-option",
        "peers",
        "remote-dns-resolve",
        "dns",
        "refresh-server-ip-interval",
        "server",
        "port",
        "public-key",
        "pre-shared-key",
        "reserved",
        "allowed-ips",
        "dialer-proxy",
    ];
    entry.reject_unknown(&allowed, false, None)?;
    Ok(WireguardOutbound {
        private_key,
        ip,
        ipv6,
        workers,
        mtu,
        udp,
        persistent_keepalive,
        peers,
    })
}

fn parse_wireguard_peer(
    entry: &Entry<'_>,
    index: usize,
    mapping: &serde_yaml::Mapping,
) -> Result<WireguardPeerOutbound, ConfigError> {
    let mut server = None;
    let mut port = 0u16;
    let mut public_key = None;
    let mut preshared_key = None;
    let mut reserved_value = None;
    let mut allowed_ips = Vec::new();
    for (key, value) in mapping {
        let Some(key) = key.as_str() else {
            return Err(entry.invalid(format!("option 'peers[{index}]' keys must be strings")));
        };
        match key {
            "server" => server = Some(wireguard_peer_string(value).unwrap_or_default()),
            "port" => {
                let parsed = match value {
                    serde_yaml::Value::Number(number) => number.as_u64(),
                    serde_yaml::Value::String(text) => text.parse::<u64>().ok(),
                    _ => None,
                };
                port = match parsed {
                    Some(value) if (1..=65535).contains(&value) => value as u16,
                    Some(_) => {
                        return Err(entry.invalid(format!(
                            "option 'peers[{index}].port' must be in 1..=65535"
                        )))
                    }
                    None => 0,
                };
            }
            "public-key" => {
                public_key = wireguard_peer_string(value);
            }
            "pre-shared-key" => {
                preshared_key = wireguard_peer_string(value).map(Secret::new);
            }
            "reserved" => reserved_value = Some(value),
            "allowed-ips" => {
                if let serde_yaml::Value::Sequence(items) = value {
                    for item in items {
                        if let serde_yaml::Value::String(item) = item {
                            allowed_ips.push(item.clone());
                        } else {
                            return Err(entry.invalid(format!(
                                "option 'peers[{index}].allowed-ips' entries must be strings"
                            )));
                        }
                    }
                } else if !value.is_null() {
                    return Err(entry.invalid(format!(
                        "option 'peers[{index}].allowed-ips' must be a list"
                    )));
                }
            }
            // The pinned decoder tolerates keys it does not know, and the peer
            // table above is complete for v1.19.34.
            _ => {}
        }
    }
    let public_key = public_key
        .filter(|value| !value.is_empty())
        .ok_or_else(|| entry.invalid(format!("missing required option 'peers[{index}].public-key'")))?;
    if crate::outbound::wireguard::decode_key(&public_key).is_err() {
        return Err(entry.invalid(format!(
            "option 'peers[{index}].public-key' must be base64 of 32 bytes"
        )));
    }
    if let Some(key) = &preshared_key {
        if crate::outbound::wireguard::decode_key(key.expose()).is_err() {
            return Err(entry.invalid(format!(
                "option 'peers[{index}].pre-shared-key' must be base64 of 32 bytes"
            )));
        }
    }
    if allowed_ips.is_empty() {
        return Err(entry.invalid(format!(
            "missing required option 'peers[{index}].allowed-ips' (the pinned device rejects a peer without one)"
        )));
    }
    for allowed in &allowed_ips {
        if parse_wireguard_prefix(allowed).is_none() {
            return Err(entry.invalid(format!(
                "option 'peers[{index}].allowed-ips' value '{allowed}' is not an IP prefix"
            )));
        }
    }
    let reserved = parse_wireguard_reserved(entry, &format!("peers[{index}].reserved"), reserved_value)?;
    let server = server.unwrap_or_default();
    if server.is_empty() || port == 0 {
        return Err(entry.invalid(format!(
            "option 'peers[{index}]' needs 'server' and 'port'"
        )));
    }
    Ok(WireguardPeerOutbound {
        server,
        port,
        public_key,
        preshared_key,
        reserved,
        allowed_ips,
    })
}

fn wireguard_peer_string(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(text) => Some(text.clone()),
        serde_yaml::Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn parse_wireguard_reserved(
    entry: &Entry<'_>,
    name: &str,
    value: Option<&serde_yaml::Value>,
) -> Result<Vec<u8>, ConfigError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Some(items) = value.as_sequence() else {
        if value.is_null() {
            return Ok(Vec::new());
        }
        return Err(entry.invalid(format!("option '{name}' must be a list of three bytes")));
    };
    if items.is_empty() {
        return Ok(Vec::new());
    }
    if items.len() != 3 {
        return Err(entry.invalid(format!(
            "option '{name}' must have exactly 3 bytes (the pinned device rejects any other length)"
        )));
    }
    let mut bytes = Vec::with_capacity(3);
    for item in items {
        let byte = match item {
            serde_yaml::Value::Number(number) => number.as_u64(),
            serde_yaml::Value::String(text) => text.parse::<u64>().ok(),
            _ => None,
        };
        match byte {
            Some(byte) if byte <= 255 => bytes.push(byte as u8),
            _ => {
                return Err(entry.invalid(format!(
                    "option '{name}' entries must be bytes in 0..=255"
                )))
            }
        }
    }
    Ok(bytes)
}

fn parse_wireguard_prefix(value: &str) -> Option<(std::net::IpAddr, u8)> {
    use std::net::IpAddr;
    match value.split_once('/') {
        Some((address, prefix)) => {
            let address = address.parse::<IpAddr>().ok()?;
            let prefix = prefix.parse::<u8>().ok()?;
            let max = if address.is_ipv4() { 32 } else { 128 };
            (prefix <= max).then_some((address, prefix))
        }
        None => value.parse::<IpAddr>().ok().map(|address| {
            let max = if address.is_ipv4() { 32 } else { 128 };
            (address, max)
        }),
    }
}

fn openvpn_cipher(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_uppercase();
    match normalized.as_str() {
        "" => Some("AES-128-GCM".to_string()),
        "AES-CBC" => Some("AES-128-CBC".to_string()),
        "AES-128-GCM" | "AES-192-GCM" | "AES-256-GCM" | "CHACHA20-POLY1305"
        | "AES-128-CBC" | "AES-192-CBC" | "AES-256-CBC" => Some(normalized),
        _ => None,
    }
}

fn openvpn_is_aead(cipher: &str) -> bool {
    matches!(
        cipher,
        "AES-128-GCM" | "AES-192-GCM" | "AES-256-GCM" | "CHACHA20-POLY1305"
    )
}

fn openvpn_auth(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_uppercase();
    match normalized.as_str() {
        "" => Some("SHA256".to_string()),
        "MD5" | "SHA1" | "SHA256" | "SHA384" | "SHA512" => Some(normalized),
        "SHA-1" => Some("SHA1".to_string()),
        _ => None,
    }
}

fn parse_openvpn(entry: &mut Entry<'_>) -> Result<OpenVpnOutbound, ConfigError> {
    reject_unwired_basic(entry, "openvpn")?;
    let server = entry.server()?;
    let port = entry.port()?;
    let proto = match entry.string("proto")?.unwrap_or_default() {
        value if value.trim().is_empty() => "udp".to_string(),
        value => match value.trim().to_ascii_lowercase().as_str() {
            "udp" | "udp4" => "udp".to_string(),
            "tcp" | "tcp-client" | "tcp4" | "tcp4-client" => "tcp".to_string(),
            other => {
                return Err(entry.unsupported(format!(
                    "option 'proto' value '{other}' is not implemented (udp and tcp are supported)"
                )))
            }
        },
    };
    let dev = entry.string("dev")?.unwrap_or_else(|| "tun".to_string());
    if !dev.eq_ignore_ascii_case("tun") {
        return Err(entry.unsupported(format!(
            "option 'dev' value '{dev}' is not implemented: the pinned adapter accepts only 'tun'"
        )));
    }
    let cipher = match entry.string("cipher")? {
        Some(value) => openvpn_cipher(&value).ok_or_else(|| {
            entry.invalid(format!("option 'cipher' value '{value}' is not an OpenVPN cipher"))
        })?,
        None => "AES-128-GCM".to_string(),
    };
    if !openvpn_is_aead(&cipher) {
        return Err(entry.unsupported(format!(
            "option 'cipher' value '{cipher}' is not implemented: the CBC data channel (CBC + HMAC padding) is not implemented; AEAD ciphers AES-128/192/256-GCM and CHACHA20-POLY1305 are"
        )));
    }
    let mut data_ciphers = Vec::new();
    // The pinned type is `[]string`; YAML usually supplies a sequence, but
    // the Go decoder also accepts one colon-separated string.
    let raw_data_ciphers = match entry.get("data-ciphers") {
        Some(serde_yaml::Value::String(value)) => vec![value.clone()],
        Some(serde_yaml::Value::Sequence(_)) => entry.string_list("data-ciphers")?,
        Some(serde_yaml::Value::Null) | None => Vec::new(),
        Some(other) => {
            return Err(entry.invalid(format!(
                "option 'data-ciphers' must be a list or a colon-separated string, found {}",
                crate::config::kind_name(other)
            )))
        }
    };
    for value in raw_data_ciphers {
        // The pinned option is a colon-separated list in each string.
        for item in value.split(':') {
            let normalized = openvpn_cipher(item).ok_or_else(|| {
                entry.invalid(format!(
                    "option 'data-ciphers' value '{item}' is not an OpenVPN cipher"
                ))
            })?;
            if !openvpn_is_aead(&normalized) {
                return Err(entry.unsupported(format!(
                    "option 'data-ciphers' value '{normalized}' is not implemented: only the AEAD data ciphers are (the CBC data channel is not)"
                )));
            }
            data_ciphers.push(normalized);
        }
    }
    let data_cipher_fallback = entry
        .string("data-ciphers-fallback")?
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            openvpn_cipher(&value).ok_or_else(|| {
                entry.invalid(format!(
                    "option 'data-ciphers-fallback' value '{value}' is not an OpenVPN cipher"
                ))
            })
        })
        .transpose()?;
    if let Some(fallback) = &data_cipher_fallback {
        if !openvpn_is_aead(fallback) {
            return Err(entry.unsupported(format!(
                "option 'data-ciphers-fallback' value '{fallback}' is not implemented: only AEAD data ciphers are"
            )));
        }
    }
    let auth = match entry.string("auth")? {
        Some(value) => openvpn_auth(&value).ok_or_else(|| {
            entry.invalid(format!("option 'auth' value '{value}' is not an OpenVPN auth digest"))
        })?,
        None => "SHA256".to_string(),
    };
    let comp_lzo = entry.string("comp-lzo")?.unwrap_or_default();
    if matches!(comp_lzo.trim().to_ascii_lowercase().as_str(), "yes" | "adaptive") {
        return Err(entry.unsupported(
            "option 'comp-lzo' is not implemented: OpenVPN compression changes the data channel payload (LZO/LZ4 framing) and the pinned adapter only accepts the disabled form",
        ));
    }
    let ca = Secret::new(entry.required_string("ca")?);
    if !ca.expose().contains("BEGIN CERTIFICATE") {
        return Err(entry.invalid(
            "option 'ca' must be an inline PEM certificate (the pinned type has no file-path form)",
        ));
    }
    let cert = entry.string("cert")?.filter(|value| !value.is_empty()).map(Secret::new);
    let key = entry.string("key")?.filter(|value| !value.is_empty()).map(Secret::new);
    if cert.is_some() != key.is_some() {
        return Err(entry.invalid(
            "options 'cert' and 'key' must be set together (the pinned TLS client needs both or neither)",
        ));
    }
    if let Some(cert) = &cert {
        if !cert.expose().contains("BEGIN CERTIFICATE") {
            return Err(entry.invalid("option 'cert' must be an inline PEM certificate"));
        }
    }
    if let Some(key) = &key {
        if !key.expose().contains("PRIVATE KEY") {
            return Err(entry.invalid("option 'key' must be an inline PEM private key"));
        }
    }
    let tls_auth = entry.string("tls-auth")?.filter(|value| !value.is_empty()).map(Secret::new);
    let tls_crypt = entry.string("tls-crypt")?.filter(|value| !value.is_empty()).map(Secret::new);
    let tls_crypt_v2 = entry
        .string("tls-crypt-v2")?
        .filter(|value| !value.is_empty())
        .map(Secret::new);
    if let Some(value) = [&tls_auth, &tls_crypt, &tls_crypt_v2].into_iter().find(|value| value.is_some()) {
        let name = if tls_auth.is_some() {
            "tls-auth"
        } else if tls_crypt.is_some() {
            "tls-crypt"
        } else {
            "tls-crypt-v2"
        };
        let _ = value;
        return Err(entry.unsupported(format!(
            "option '{name}' is not implemented: protecting control packets needs the OpenVPN static-key codec (HMAC-SHA1/SHA256, AES-256-CTR and the tls-crypt-v2 wrapped key); the control channel itself is implemented and verified without it"
        )));
    }
    let key_direction = entry.string("key-direction")?.filter(|value| !value.is_empty());
    let username = entry.string("username")?.filter(|value| !value.is_empty()).map(Secret::new);
    let password = entry.string("password")?.filter(|value| !value.is_empty()).map(Secret::new);
    let peer_info = entry.string_map("peer-info")?;
    let ping = wireguard_u16(entry, "ping", 0)?;
    let ping_restart = wireguard_u16(entry, "ping-restart", 0)?;
    let tran_window = match entry.int("tran-window")? {
        Some(value) if value < 0 => {
            return Err(entry.invalid("option 'tran-window' must not be negative"))
        }
        Some(value) => value,
        None => 0,
    };
    let handshake_timeout = wireguard_u16(entry, "handshake-timeout", 0)?;
    let mtu = wireguard_u16(entry, "mtu", 0)?;
    let udp = entry.bool("udp")?.unwrap_or(false);
    if let Some(block) = entry.block("ip-stack")? {
        for (key, value) in block {
            let key = key
                .as_str()
                .ok_or_else(|| entry.invalid("ip-stack keys must be strings"))?;
            match key {
                "mode" => {
                    let mode = value.as_str().unwrap_or("").to_ascii_lowercase();
                    if !mode.is_empty() && mode != "auto" {
                        return Err(entry.unsupported(format!(
                            "option 'ip-stack.mode' value '{mode}' is not implemented: the userspace IP stack and TUN device belong to the T6/T7 device layer; the OpenVPN control and data channels are implemented and exposed to that layer"
                        )));
                    }
                }
                "congestion-controller" => {
                    if value.as_str().is_some_and(|value| !value.is_empty()) {
                        return Err(entry.unsupported(
                            "option 'ip-stack.congestion-controller' is not implemented: it configures the T6/T7 userspace IP stack",
                        ));
                    }
                }
                other => {
                    return Err(entry.unsupported(format!(
                        "option 'ip-stack.{other}' is not implemented"
                    )))
                }
            }
        }
    }
    let remote_dns_resolve = entry.bool("remote-dns-resolve")?.unwrap_or(false);
    if remote_dns_resolve {
        return Err(entry.unsupported(
            "option 'remote-dns-resolve' is not implemented: it resolves through the pinned userspace IP stack's resolver (T6/T7 device layer)",
        ));
    }
    let dns = entry.string_list("dns")?;
    if !dns.is_empty() {
        return Err(entry.unsupported(
            "option 'dns' is not implemented: it configures the pinned userspace IP stack's resolver (T6/T7 device layer)",
        ));
    }
    if entry
        .string("dialer-proxy")?
        .filter(|value| !value.is_empty())
        .is_some()
    {
        return Err(entry.unsupported(
            "option 'dialer-proxy' is not implemented for openvpn: the control channel is one UDP/TCP socket and cannot be reached through the supported socks5 TCP hop",
        ));
    }
    let allowed = [
        "name",
        "type",
        "server",
        "port",
        "proto",
        "dev",
        "cipher",
        "data-ciphers",
        "data-ciphers-fallback",
        "auth",
        "comp-lzo",
        "ca",
        "cert",
        "key",
        "tls-auth",
        "key-direction",
        "tls-crypt",
        "tls-crypt-v2",
        "username",
        "password",
        "peer-info",
        "ping",
        "ping-restart",
        "tran-window",
        "handshake-timeout",
        "mtu",
        "udp",
        "ip-stack",
        "remote-dns-resolve",
        "dns",
        "dialer-proxy",
    ];
    entry.reject_unknown(&allowed, false, None)?;
    Ok(OpenVpnOutbound {
        server,
        port,
        proto,
        dev,
        cipher,
        data_ciphers,
        data_cipher_fallback,
        auth,
        comp_lzo,
        ca,
        cert,
        key,
        tls_auth,
        key_direction,
        tls_crypt,
        tls_crypt_v2,
        username,
        password,
        peer_info,
        ping,
        ping_restart,
        tran_window,
        handshake_timeout,
        mtu,
        udp,
        remote_dns_resolve,
        dns,
    })
}

fn wireguard_u16(entry: &mut Entry<'_>, key: &str, default: u16) -> Result<u16, ConfigError> {
    match entry.int(key)? {
        Some(value) if !(0..=65535).contains(&value) => {
            Err(entry.invalid(format!("option '{key}' must be in 0..=65535")))
        }
        Some(value) => Ok(value as u16),
        None => Ok(default),
    }
}

/// ShadowQUIC (`adapter/outbound/shadowquic.go`). Option policy:
///
/// * transport tuning (`recv-window*`, `max-open-streams`,
///   `max-datagram-frame-size`, `disable-mtu-discovery`, `keep-alive-interval`,
///   `alpn`, `sni`, `udp-over-stream`) is applied to the quinn endpoint;
/// * the pinned defaults for `quic-versions` are v1; quinn 0.11 implements
///   only v1, so a `v2` request is rejected by name;
/// * `zero-rtt` needs the pinned session ticket + JLS marker (0-RTT only works
///   after an authenticated ticket), so `true` is rejected;
/// * `congestion-controller`, `cwnd`, `bbr-profile`, `up` and `down` select
///   mihomo's private Brutal controller, which quinn does not have; only their
///   no-op values are accepted.
fn parse_shadowquic(entry: &mut Entry<'_>) -> Result<ShadowQuicOutbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    let username = entry.string("username")?.unwrap_or_default();
    let password = entry.string("password")?.unwrap_or_default();
    let sni = entry.string("sni")?.filter(|value| !value.is_empty());
    let alpn = entry.string_list("alpn")?;
    let udp_over_stream = entry.bool("udp-over-stream")?.unwrap_or(false);

    if entry.bool("zero-rtt")?.unwrap_or(false) {
        return Err(entry.unsupported(
            "option 'zero-rtt' is not implemented: 0-RTT needs the pinned JLS-marked TLS session ticket and a resumption cache; this client always performs a full authenticated handshake",
        ));
    }

    let keep_alive_interval = match entry.int("keep-alive-interval")? {
        Some(value) if value < 0 => {
            return Err(entry.invalid("option 'keep-alive-interval' must not be negative"))
        }
        Some(value) => value as u64,
        None => 0,
    };

    let quic_versions = entry.string_list("quic-versions")?;
    for version in &quic_versions {
        let normalized = version.trim().to_ascii_lowercase().replace('_', "-");
        match normalized.as_str() {
            "v1" | "1" | "rfc9000" | "rfc-9000" => {}
            "v2" | "2" | "rfc9369" | "rfc-9369" => {
                return Err(entry.unsupported(
                    "option 'quic-versions' value 'v2' is not implemented: quinn 0.11 supports QUIC v1 only",
                ))
            }
            other => {
                return Err(entry.invalid(format!(
                    "option 'quic-versions' value '{other}' is invalid (supported: v1)"
                )))
            }
        }
    }

    let congestion_controller = match entry
        .string("congestion-controller")?
        .filter(|value| !value.is_empty())
    {
        None => None,
        Some(value) => match value.as_str() {
            // `bbr_meta_v1` is the pinned legacy meta BBR sender; quinn 0.11
            // ships one BBR controller (v2-shaped), so the v1 name maps to it
            // as the closest approximation instead of rejecting a valid
            // pinned value at load.
            "cubic" | "new_reno" | "bbr" | "bbr_meta_v1" | "bbr_meta_v2" => Some(value),
            other => {
                return Err(entry.unsupported(format!(
                    "option 'congestion-controller' value '{other}' is not implemented (cubic, new_reno, bbr, bbr_meta_v1, bbr_meta_v2)"
                )))
            }
        },
    };
    let bbr_profile = entry.string("bbr-profile")?.filter(|value| !value.is_empty());
    if let Some(profile) = &bbr_profile {
        if !matches!(profile.as_str(), "conservative" | "standard" | "aggressive") {
            return Err(entry.invalid(format!(
                "option 'bbr-profile' value '{profile}' is unknown (conservative, standard, aggressive)"
            )));
        }
    }
    let cwnd = match entry.int("cwnd")? {
        Some(value) if value < 0 => {
            return Err(entry.invalid("option 'cwnd' must not be negative"))
        }
        Some(0) | None => 0,
        Some(value) => u32::try_from(value)
            .map_err(|_| entry.invalid("option 'cwnd' is out of range"))?,
    };
    // The pinned `utils.StringToBps` maps an unparsable string to 0, which
    // keeps Brutal disabled for that side; it never fails the configuration.
    let send_bps = entry
        .string("up")?
        .map(|value| crate::outbound::hysteria::string_to_bps(&value))
        .unwrap_or(0);
    let receive_bps = entry
        .string("down")?
        .map(|value| crate::outbound::hysteria::string_to_bps(&value))
        .unwrap_or(0);

    let recv_window_conn = match entry.int("recv-window-conn")? {
        Some(value) if value < 0 => {
            return Err(entry.invalid("option 'recv-window-conn' must not be negative"))
        }
        Some(value) if value > i64::from(u32::MAX) => {
            return Err(entry.invalid("option 'recv-window-conn' is too large"))
        }
        Some(value) if value > 0 => value as u32,
        _ => 512 * 1024,
    };
    let recv_window = match entry.int("recv-window")? {
        Some(value) if value < 0 => {
            return Err(entry.invalid("option 'recv-window' must not be negative"))
        }
        Some(value) if value > i64::from(u32::MAX) => {
            return Err(entry.invalid("option 'recv-window' is too large"))
        }
        Some(value) if value > 0 => value as u32,
        _ => 2 * 1024 * 1024,
    };
    let disable_mtu_discovery = entry.bool("disable-mtu-discovery")?.unwrap_or(false);
    let max_datagram_frame_size = match entry.int("max-datagram-frame-size")? {
        Some(value) if value < 0 || value > 0xffff => {
            return Err(entry.invalid(
                "option 'max-datagram-frame-size' must be between 0 and 65535",
            ))
        }
        Some(value) if value > 0 => value as usize,
        _ => 1400,
    };
    let max_open_streams = match entry.int("max-open-streams")? {
        Some(value) if value < 0 => {
            return Err(entry.invalid("option 'max-open-streams' must not be negative"))
        }
        Some(value) if value > 0 => value as u64,
        _ => 1024,
    };
    if entry
        .string("dialer-proxy")?
        .filter(|value| !value.is_empty())
        .is_some()
    {
        return Err(entry.unsupported(
            "option 'dialer-proxy' is not implemented for shadowquic: a QUIC endpoint cannot be reached through the supported socks5 TCP hop, so the server is always dialled locally",
        ));
    }

    let allowed = [
        "name",
        "type",
        "server",
        "port",
        "username",
        "password",
        "sni",
        "alpn",
        "quic-versions",
        "udp-over-stream",
        "zero-rtt",
        "keep-alive-interval",
        "congestion-controller",
        "up",
        "down",
        "cwnd",
        "bbr-profile",
        "recv-window-conn",
        "recv-window",
        "disable-mtu-discovery",
        "max-datagram-frame-size",
        "max-open-streams",
    ];
    entry.reject_unknown(&allowed, true, None)?;
    Ok(ShadowQuicOutbound {
        server,
        port,
        username,
        password,
        sni,
        alpn,
        udp_over_stream,
        keep_alive_interval,
        congestion_controller,
        send_bps,
        receive_bps,
        cwnd,
        bbr_profile,
        recv_window_conn,
        recv_window,
        disable_mtu_discovery,
        max_datagram_frame_size,
        max_open_streams,
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
        "shadowquic",
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
