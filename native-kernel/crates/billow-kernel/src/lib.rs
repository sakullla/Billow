//! Billow native Rust kernel — the embeddable proxy engine (T2-T4).
//!
//! An embeddable proxy engine without any Tauri dependency (the crate also
//! builds as a `staticlib` for the iOS Network Extension). The standalone
//! process lives in the separate `billow-kernel-cli` crate.
//!
//! Supported today: a clash-style YAML with `mixed-port` (legacy `socks-port`
//! alias) talking SOCKS5 CONNECT and HTTP CONNECT on one port, inbound
//! `authentication`, inline rules `DOMAIN`, `DOMAIN-SUFFIX`, `GEOSITE`,
//! `IP-CIDR`, `IP-CIDR6`, `MATCH` with `DIRECT`/`REJECT`, and protocol
//! outbounds `socks5`, `http`, `ss` (AEAD 2017), `trojan`, `vless`,
//! `anytls`, `vmess`, `snell`, `trusttunnel`, `gost-relay`, `ssh`, `ssr`,
//! `tuic` (v5), `hysteria` (v1), `hysteria2`, `mieru` (TCP sessions) and
//! `sudoku` (TCP with the legacy HTTP mask) with the transports they need
//! (TLS, WebSocket, QUIC, HTTP/3 auth, `dialer-proxy` through a socks5 hop). A
//! rule or protocol option the kernel does not
//! implement fails configuration loading when its value asks for something; a
//! key the pinned type does not declare is ignored exactly as Mihomo ignores
//! it, so a valid upstream configuration loads. DNS, proxy groups, providers
//! and the control API are T5.
//!
//! ```no_run
//! # fn main() -> anyhow::Result<()> {
//! let yaml = "mixed-port: 17890\nproxies:\n  - {name: p, type: socks5, server: 127.0.0.1, port: 1080}\nrules:\n  - MATCH,p\n";
//! let (mut kernel, warnings) = billow_kernel::Kernel::start_from_yaml(yaml, None, billow_kernel::Limits::default())?;
//! println!("{}", kernel.identity().to_line());
//! assert!(warnings.is_empty());
//! kernel.stop()?;
//! # Ok(())
//! # }
//! ```

pub mod config;
pub mod engine;
pub mod identity;
pub mod inbound;
pub mod rules;

pub use config::{
    load_config, Action, Config, ConfigError, GeoSiteDatabase, LoadedConfig, Matcher,
};
pub use engine::{Kernel, Limits, StartError, Stats, VERSION};
pub use identity::Identity;
pub use rules::RuleSet;

/// Re-exported so hosts can format a start failure without naming `anyhow`.
impl StartError {
    /// `invalid_yaml`, `invalid_value`, `unsupported`, `bind` or `limits`.
    pub fn tag(&self) -> &'static str {
        match self {
            StartError::Config(e) => e.tag(),
            StartError::Bind { .. } => "bind",
            StartError::Limits(_) => "limits",
        }
    }
}
pub mod keys;
pub mod outbound;
pub mod proxies;
