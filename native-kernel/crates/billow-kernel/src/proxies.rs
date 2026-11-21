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

/// ShadowsocksR (`adapter/outbound/shadowsocksr.go`). The SSR stack is
/// cipher + obfs + protocol; this kernel implements the stream ciphers, the
/// `origin` protocol and the `plain` obfs. Other protocol/obfs plugins are
/// rejected by name instead of being skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsrOutbound {
    pub server: String,
    pub port: u16,
    pub password: Secret,
    pub cipher: SsrCipher,
    pub protocol: String,
    pub protocol_param: Option<String>,
    pub obfs: String,
    pub obfs_param: Option<String>,
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
/// Only the TCP relay and the optional TLS wrapper are implemented; UDP and
/// smux multiplexing are rejected by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GostRelayOutbound {
    pub server: String,
    pub port: u16,
    /// `forward: true` omits the target-address feature, so the relay server
    /// uses its own configured forward target.
    pub forward: bool,
    pub tls: bool,
    pub tls_settings: TlsSettings,
    pub username: Option<Secret>,
    pub password: Option<Secret>,
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
        }
    }

    /// ShadowTLS (the SS/structure listener) is exposed as `type: ss` with a
    /// `plugin`; that combination is reported unsupported, never accepted silently.
    pub fn udp_enabled(&self) -> bool {
        match &self.protocol {
            Protocol::Shadowsocks(p) => p.udp,
            Protocol::Trojan(p) => p.udp,
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
        "mieru" => {
            return Err(entry.unsupported(
                "protocol type 'mieru' is not implemented: it wraps the external enfein/mieru v3.39.0 module (encrypted underlay, padding, multiplexing); T11 deferred it pending a vendor/port decision",
            ))
        }
        "masque" => {
            return Err(entry.unsupported(
                "protocol type 'masque' is not implemented: HTTP/3 CONNECT-IP/CONNECT-UDP needs the QUIC stack and an IP stack aligned with T10/T7; T11 deferred it",
            ))
        }
        "sudoku" => {
            return Err(entry.unsupported(
                "protocol type 'sudoku' is not implemented: ~13.6k lines of custom crypto/KIP/multiplexing; T11 deferred it pending a split into its own task",
            ))
        }
        other => {
            return Err(ConfigError::Unsupported(format!(
                "{}: protocol type '{other}' is not implemented (implemented: socks5, http, ss, trojan, vless, anytls, vmess, snell, trusttunnel, gost-relay, ssh, ssr)",
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
/// `cipher`, `password`, `protocol` and `obfs`; only the stream ciphers plus
/// `protocol: origin` and `obfs: plain` are implemented here. The SSR plugin
/// layers (`auth_*`, `tls1.2_ticket_*`, `http_simple`, ...) are rejected by
/// name so no configuration is loaded as compatible with a layer that would
/// change the wire format.
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
    let protocol = entry.required_string("protocol")?;
    if protocol != "origin" {
        return Err(entry.unsupported(format!(
            "option 'protocol' value '{protocol}' is not implemented (origin)"
        )));
    }
    let obfs = entry.required_string("obfs")?;
    if obfs != "plain" {
        return Err(entry.unsupported(format!(
            "option 'obfs' value '{obfs}' is not implemented (plain)"
        )));
    }
    // `origin`/`plain` ignore their parameter in the pinned implementation.
    let protocol_param = entry.string("protocol-param")?.filter(|s| !s.is_empty());
    let obfs_param = entry.string("obfs-param")?.filter(|s| !s.is_empty());
    if entry.bool("udp")?.unwrap_or(false) {
        return Err(entry.unsupported(
            "option 'udp' is not implemented for ssr (no UDP association)",
        ));
    }
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
/// feature. `udp` and `mux` are declared by the pinned type but need a UDP
/// association or an smux session this kernel does not implement.
fn parse_gost_relay(entry: &mut Entry<'_>) -> Result<GostRelayOutbound, ConfigError> {
    let server = entry.server()?;
    let port = entry.port()?;
    let forward = entry.bool("forward")?.unwrap_or(false);
    let tls = entry.bool("tls")?.unwrap_or(false);
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
    if entry.bool("udp")?.unwrap_or(false) {
        return Err(entry.unsupported(
            "option 'udp' is not implemented for gost-relay (no UDP association)",
        ));
    }
    if entry.bool("mux")?.unwrap_or(false) {
        return Err(entry.unsupported(
            "option 'mux' is not implemented for gost-relay (no smux session)",
        ));
    }
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
        username,
        password,
        dialer_proxy,
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
        "socks5", "http", "ss", "trojan", "vless", "anytls", "vmess", "snell", "trusttunnel",
        "gost-relay", "ssh", "ssr",
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
