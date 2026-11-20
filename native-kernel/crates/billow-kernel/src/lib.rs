//! Billow native Rust kernel — first slice (T2).
//!
//! An embeddable proxy engine without any Tauri dependency (the crate also
//! builds as a `staticlib` for the iOS Network Extension). The standalone
//! process lives in the separate `billow-kernel-cli` crate.
//!
//! Supported today: a clash-style YAML with `mixed-port` (legacy `socks-port`
//! alias) talking SOCKS5 CONNECT and HTTP CONNECT on one port; inline rules
//! `DOMAIN`, `DOMAIN-SUFFIX`, `GEOSITE`, `IP-CIDR`, `IP-CIDR6`, `MATCH` with
//! `DIRECT`/`REJECT`. Every other key, rule or option fails configuration
//! loading instead of being ignored. Protocol outbounds, DNS and the control
//! API are later tasks (T4/T5).
//!
//! ```no_run
//! # fn main() -> anyhow::Result<()> {
//! let yaml = "mixed-port: 17890\nrules:\n  - MATCH,DIRECT\n";
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
