//! Prepares a host `config.yaml` for a device tunnel.
//!
//! Both device entries (the iOS Packet Tunnel and the Android VpnService
//! process) receive the file the launcher wrote and need a Rust-specific view
//! of it:
//!
//! * a `tun` block with `enable: true` is removed. On iOS the Packet Tunnel
//!   owns the device route; on Android the host hands the established TUN fd
//!   to [`crate::android_vpn`] and passes it as a launch argument, never as a
//!   configuration key. The shared file keeps the block for Mihomo;
//! * `rule-providers.*.path` / `proxy-providers.*.path` files referenced
//!   outside the version directory are copied next to the config and the path
//!   is rewritten to the basename (a sandboxed extension cannot read the host
//!   sandbox);
//! * the result is written to `config.rust.yaml` beside the shared file.

use std::path::{Path, PathBuf};

/// One Rust-specific view of the shared `config.yaml`.
#[derive(Debug)]
pub struct Staged {
    pub yaml: String,
    pub path: PathBuf,
}

/// Stages `yaml` into `home/config.rust.yaml` and returns both the in-memory
/// text and the file path the tunnel reloads from.
pub fn stage_config(home: &Path, yaml: &str) -> Result<Staged, String> {
    let mut value: serde_yaml::Value = serde_yaml::from_str(yaml)
        .map_err(|error| format!("device-staging: config.yaml is not YAML: {error}"))?;
    let mapping = value
        .as_mapping_mut()
        .ok_or_else(|| "device-staging: config.yaml top level must be a mapping".to_string())?;
    if block_enabled(mapping.get(serde_yaml::Value::String("tun".into()))) {
        mapping.remove(serde_yaml::Value::String("tun".into()));
        tracing::warn!(
            "tun.enable was removed for the Rust engine: the device tunnel owns the TUN"
        );
    }
    for group in ["rule-providers", "proxy-providers"] {
        let Some(providers) = mapping
            .get_mut(serde_yaml::Value::String(group.into()))
            .and_then(serde_yaml::Value::as_mapping_mut)
        else {
            continue;
        };
        for (_name, provider) in providers.iter_mut() {
            let Some(entry) = provider.as_mapping_mut() else {
                continue;
            };
            let key = serde_yaml::Value::String("path".into());
            let Some(raw) = entry.get(&key).and_then(serde_yaml::Value::as_str) else {
                continue;
            };
            let raw = raw.to_string();
            let source = if Path::new(&raw).is_absolute() {
                PathBuf::from(&raw)
            } else {
                home.join(&raw)
            };
            let Some(name) = source.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if source.is_file() {
                let destination = home.join(name);
                if source != destination {
                    std::fs::copy(&source, &destination).map_err(|error| {
                        format!("device-staging: copy {}: {error}", source.display())
                    })?;
                }
                entry.insert(key, serde_yaml::Value::String(name.to_string()));
            }
        }
    }
    let yaml = serde_yaml::to_string(&value)
        .map_err(|error| format!("device-staging: serialize config: {error}"))?;
    let path = home.join("config.rust.yaml");
    std::fs::write(&path, &yaml)
        .map_err(|error| format!("device-staging: write {}: {error}", path.display()))?;
    Ok(Staged { yaml, path })
}

fn block_enabled(block: Option<&serde_yaml::Value>) -> bool {
    match block {
        Some(serde_yaml::Value::Bool(value)) => *value,
        Some(serde_yaml::Value::Mapping(mapping)) => mapping
            .get(serde_yaml::Value::String("enable".into()))
            .and_then(serde_yaml::Value::as_bool)
            .unwrap_or(false),
        _ => false,
    }
}
