//! Strict parsing of the `proxies` list (the protocol outbounds of T4).
//!
//! Every entry is decoded against an explicit option table copied from the
//! pinned Mihomo v1.19.34 source (`adapter/outbound/*.go`). Unknown keys,
//! unsupported protocols and unsupported values fail with the index, name,
//! type and the exact option, e.g.
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
    /// Extra request headers; `Host` is honoured as an override.
    pub headers: Vec<(String, String)>,
    pub max_early_data: u64,
    pub early_data_header_name: Option<String>,
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

/// Option tables from the pinned source. An option that is present in the
/// mapping but listed as unsupported fails; an unknown key fails too (Mihomo's
/// decoder errors with `invalid map key`).
const COMMON_UNSUPPORTED: &[&str] = &[
    "tfo",
    "mptcp",
    "interface-name",
    "routing-mark",
    "smux",
    "udp-over-tcp",
    "udp-over-tcp-version",
    "dialer-proxy",
    "ech-opts",
    "shadow-tls-opts",
    "restls-opts",
    "jls-opts",
    "fingerprint",
    "certificate",
    "private-key",
    "name-cert-verify",
];

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
    Ok(proxies)
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

    fn tls_settings(&mut self) -> Result<TlsSettings, ConfigError> {
        let sni = self.string("sni")?.filter(|s| !s.is_empty());
        let skip = self.bool("skip-cert-verify")?.unwrap_or(false);
        let alpn = self.string_list("alpn")?;
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
    /// Only `ws-opts` with the common fields is implemented; a present block is
    /// otherwise rejected before looking at its fields.
    fn ws_settings(&mut self) -> Result<WsSettings, ConfigError> {
        for key in [
            "reality-opts",
            "grpc-opts",
            "http-opts",
            "h2-opts",
            "xhttp-opts",
        ] {
            if self.get(key).is_some() {
                return Err(self.unsupported(format!("option '{key}' is not implemented")));
            }
        }
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
        if ws.max_early_data > 0 || ws.early_data_header_name.is_some() {
            return Err(self.unsupported("ws early data ('ws-opts.max-early-data' / 'ws-opts.early-data-header-name') is not implemented"));
        }
        if !ws.path.starts_with('/') {
            return Err(self.invalid("option 'ws-opts.path' must start with '/'"));
        }
        Ok(ws)
    }

    /// Report a key that the protocol's option table does not contain.
    fn reject_unknown(&self, allowed: &[&str]) -> Result<(), ConfigError> {
        for (key, _) in self.mapping {
            let Some(key) = key.as_str() else {
                return Err(self.invalid("option names must be strings"));
            };
            let key = key.replace('_', "-");
            if allowed.contains(&key.as_str()) || self.used.contains(&key) {
                continue;
            }
            if COMMON_UNSUPPORTED.contains(&key.as_str()) {
                return Err(self.unsupported(format!("option '{key}' is not implemented")));
            }
            return Err(self.unsupported(format!(
                "option '{key}' is not implemented (not a Mihomo {} option either)",
                self.kind
            )));
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
        other => {
            return Err(ConfigError::Unsupported(format!(
                "{}: protocol type '{other}' is not implemented (implemented: socks5, http, ss, trojan, vless, anytls)",
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
    let tls_settings = entry.tls_settings()?;
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
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
        "alpn",
        "name-cert-verify",
        "fingerprint",
        "certificate",
        "private-key",
        "ip-version",
    ];
    entry.reject_unknown(&allowed)?;
    if tls_settings.skip_cert_verify && !tls {
        // Mihomo ignores skip-cert-verify without tls; say so instead of pretending.
        return Err(entry.unsupported(
            "option 'skip-cert-verify' without 'tls: true' has no effect and is not implemented",
        ));
    }
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
    let tls_settings = entry.tls_settings()?;
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    let headers = entry.string_map("headers")?;
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
        "alpn",
        "name-cert-verify",
        "fingerprint",
        "certificate",
        "private-key",
        "headers",
        "ip-version",
    ];
    entry.reject_unknown(&allowed)?;
    if tls_settings.skip_cert_verify && !tls {
        return Err(entry.unsupported(
            "option 'skip-cert-verify' without 'tls: true' has no effect and is not implemented",
        ));
    }
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
    let has_plugin_opts = entry.get("plugin-opts").is_some();
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
    entry.reject_unknown(&allowed)?;
    if let Some(plugin) = plugin.filter(|p| !p.is_empty()) {
        return Err(entry.unsupported(format!(
            "option 'plugin' value '{plugin}' is not implemented"
        )));
    }
    if has_plugin_opts {
        return Err(entry.unsupported("option 'plugin-opts' without 'plugin' is not implemented"));
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
    let tls_settings = entry.tls_settings()?;
    let network = entry
        .string("network")?
        .unwrap_or_else(|| "tcp".to_string());
    let ws = entry.ws_settings()?;
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
    entry.reject_unknown(&allowed)?;
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
    let tls_settings = entry.tls_settings()?;
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    let network = entry
        .string("network")?
        .unwrap_or_else(|| "tcp".to_string());
    let ws = entry.ws_settings()?;
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
        if entry.get(key).is_some() {
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
        "client-fingerprint",
        "ip-version",
    ];
    entry.reject_unknown(&allowed)?;
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
    let tls_settings = entry.tls_settings()?;
    let dialer_proxy = entry.string("dialer-proxy")?.filter(|s| !s.is_empty());
    for key in [
        "client-metadata",
        "idle-session-check-interval",
        "idle-session-timeout",
        "min-idle-session",
    ] {
        if entry.get(key).is_some() {
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
    entry.reject_unknown(&allowed)?;
    Ok(AnytlsOutbound {
        server,
        port,
        password,
        tls_settings,
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
    &["socks5", "http", "ss", "trojan", "vless", "anytls"]
}

/// Options accepted for every outbound in the pinned source but without a
/// backend in this kernel; kept here so the capability report has one list.
pub fn unsupported_common_options() -> BTreeMap<&'static str, &'static str> {
    COMMON_UNSUPPORTED
        .iter()
        .map(|key| (*key, "no implementation in the Rust runtime (T4)"))
        .collect()
}
