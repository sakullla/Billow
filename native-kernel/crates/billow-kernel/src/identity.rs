//! Checkable instance identity: uuid, pid, version, listener and configuration digest.

use std::net::SocketAddr;
use std::path::Path;
use std::process;

use crate::config::Config;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Fresh per kernel instance so logs from restarts can be told apart.
    pub uuid: String,
    pub pid: u32,
    pub version: String,
    /// Actual bound listener.
    pub listen: SocketAddr,
    /// `--port` override, when one was used.
    pub port_override: Option<u16>,
    /// SHA-256 of the YAML text, with `sha256:` prefix.
    pub config_digest: String,
    pub rules: usize,
    pub geosite_dir: Option<String>,
    pub state_dir: Option<String>,
    /// What this instance actually implements; never claims more than it does.
    pub features: String,
}

impl Identity {
    pub(crate) fn new(
        version: &str,
        listen: SocketAddr,
        config: &Config,
        geosite_dir: &Option<std::path::PathBuf>,
        rules: usize,
    ) -> Self {
        Identity {
            uuid: uuid::Uuid::new_v4().to_string(),
            pid: process::id(),
            version: version.to_string(),
            listen,
            port_override: None,
            config_digest: config.digest.clone(),
            rules,
            geosite_dir: geosite_dir.as_deref().map(path_string),
            state_dir: None,
            features: config.feature_summary(),
        }
    }

    /// Host-supplied metadata (e.g. an App Group directory for the iOS extension).
    pub fn with_state_dir(mut self, dir: Option<&Path>) -> Self {
        self.state_dir = dir.map(path_string);
        self
    }

    pub fn with_port_override(mut self, port: Option<u16>) -> Self {
        self.port_override = port;
        self
    }

    pub fn set_port_override(&mut self, port: Option<u16>) {
        self.port_override = port;
    }

    /// Single-line, pasteable identity record.
    pub fn to_line(&self) -> String {
        let dir = |v: &Option<String>| v.clone().unwrap_or_else(|| "-".to_string());
        format!(
            "instance={} pid={} version={} listen={} overridden_port={} config={} rules={} geosite_dir={} state_dir={}",
            self.uuid,
            self.pid,
            self.version,
            self.listen,
            self.port_override.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string()),
            self.config_digest,
            self.rules,
            dir(&self.geosite_dir),
            dir(&self.state_dir),
        )
    }
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
