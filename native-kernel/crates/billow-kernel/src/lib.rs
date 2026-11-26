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
//! `sudoku` (GPL-3.0-derived translation, TCP) with the transports they need
//! (TLS, WebSocket, QUIC, HTTP/3 auth, `dialer-proxy` through a socks5 hop). A
//! rule or protocol option the kernel does not
//! implement fails configuration loading when its value asks for something; a
//! key the pinned type does not declare is ignored exactly as Mihomo ignores
//! it, so a valid upstream configuration loads. Proxy groups (T23: select,
//! url-test, fallback, load-balance, nested groups, provider `use`, filters,
//! health checks and a selection cache) and T22 DNS/hosts (UDP/TCP/DoT/DoH
//! upstreams, nameserver policies, fallback filters, fake-ip, the optional DNS
//! server and rule-time resolution) are implemented; the control API is T25.
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
pub(crate) mod controller;
pub mod dns;
pub mod engine;
pub mod geodata;
pub mod groups;
pub mod identity;
pub mod inbound;
pub mod provider;
pub mod rules;

pub use config::{
    load_config, Action, Config, ConfigError, ControllerConfig, CorsConfig, ExpectedStatus,
    GeoSiteDatabase, GroupKind, LoadBalanceStrategy, LoadedConfig, Matcher, NetworkKind, InType,
    ProfileConfig, ProxyGroup, TunConfig,
};
pub use dns::{
    DnsConfig, DnsError, DnsService, EnhancedMode, FakeIpFilterMode, HostValue, HostsConfig,
    HostsTable, NameServer, NameServerNet, NameServerPolicy,
};
pub use controller::LogBus;
pub use engine::{Kernel, KernelOptions, Limits, StartError, Stats, VERSION};
pub use groups::{
    GroupError, GroupRegistry, GroupStatus, MemberHealth, Selected, SelectionCache,
};
pub use identity::Identity;
pub use provider::{ProviderUpdate, RuleProviders};
pub use rules::{RuleSet, Target};

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

/// Host-agnostic device data plane. Compiled with `device-vpn`, which the
/// `ios-vpn` and `android-vpn` features turn on; the userspace IP stack is
/// shared so a desktop TUN (T6) can reuse it.
#[cfg(feature = "device-vpn")]
pub mod tunnel;

/// iOS Packet Tunnel C ABI (`include/billow_ios_vpn.h`), `--features ios-vpn`.
#[cfg(feature = "ios-vpn")]
pub mod ios_vpn;

/// Android VpnService file-descriptor data plane and its C ABI,
/// `--features android-vpn`.
#[cfg(all(feature = "android-vpn", unix))]
pub mod android_vpn;

/// Desktop TUN data plane: platform device creation, route planning and the
/// shared packet pump (`--features desktop-tun`).
#[cfg(feature = "desktop-tun")]
pub mod desktop_tun;
