//! Kernel engine selection shared by the profile lifecycle and the UI.
//!
//! Billow ships two independent engines: the bundled Mihomo process and the
//! native Rust kernel (`billow-kernel`). The selected engine is user state; the
//! running engine is whatever process the lifecycle actually started, and the
//! two are reported separately so the UI never claims a switch that did not
//! happen. Older installations have no stored selection and keep Mihomo.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Which kernel binary serves proxy traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Engine {
    /// Bundled MetaCubeX Mihomo; the historical default and the release-channel owner.
    #[default]
    Mihomo,
    /// Billow's native Rust kernel, shipped in the same installer.
    Rust,
}

impl Engine {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mihomo => "mihomo",
            Self::Rust => "rust",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Mihomo => "Mihomo",
            Self::Rust => "Rust",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "mihomo" => Ok(Self::Mihomo),
            "rust" => Ok(Self::Rust),
            _ => Err("没有这个内核引擎".to_string()),
        }
    }
}

/// What the running process reported about itself. `instance` is the kernel's
/// own identity line (UUID/PID/listener), so a restart is distinguishable from
/// the previous instance even when the version did not change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineIdentity {
    pub engine: Engine,
    pub version: Option<String>,
    pub instance: Option<String>,
}

/// One engine's availability for the settings card. `available` means the
/// packaged binary exists; `version` is the packaged version when known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EngineInfo {
    pub id: String,
    pub label: String,
    pub available: bool,
    pub version: Option<String>,
    pub running: bool,
    pub instance: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnginesState {
    pub selected: String,
    pub running: Option<String>,
    pub failure: Option<String>,
    pub mihomo: EngineInfo,
    pub rust: EngineInfo,
}

/// Version record written next to the bundled Rust kernel by the packaging step.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RustKernelManifest {
    pub version: String,
}

/// Reads the packaged Rust kernel version without executing the binary.
pub fn rust_kernel_version(manifest: &Path) -> Option<String> {
    let text = std::fs::read_to_string(manifest).ok()?;
    let value: RustKernelManifest = serde_json::from_str(&text).ok()?;
    let version = value.version.trim();
    (!version.is_empty()).then(|| version.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_state_defaults_to_mihomo_and_only_two_engines_exist() {
        assert_eq!(Engine::default(), Engine::Mihomo);
        assert_eq!(Engine::parse("mihomo").unwrap(), Engine::Mihomo);
        assert_eq!(Engine::parse(" Rust ").unwrap(), Engine::Rust);
        assert!(Engine::parse("").is_err());
        assert!(Engine::parse("clash").is_err());
        // An older `profiles.json` has no engine field at all.
        let legacy: serde_json::Value = serde_json::json!({ "next_id": 1 });
        let mut value = legacy.clone();
        assert_eq!(value.as_object_mut().unwrap().remove("engine"), None);
        let engine: Engine = serde_json::from_value(serde_json::Value::Null).unwrap_or_default();
        assert_eq!(engine, Engine::Mihomo);
    }

    #[test]
    fn manifest_version_is_optional_and_trimmed() {
        let dir = std::env::temp_dir().join(format!("billow-engine-manifest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rust-kernel.json");
        std::fs::write(&path, br#"{ "version": " 0.1.0 " }"#).unwrap();
        assert_eq!(rust_kernel_version(&path).as_deref(), Some("0.1.0"));
        std::fs::write(&path, br#"{ "version": "" }"#).unwrap();
        assert!(rust_kernel_version(&path).is_none());
        assert!(rust_kernel_version(&dir.join("missing.json")).is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
