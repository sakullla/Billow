use std::io::Read;
use std::time::Duration;

use semver::Version;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
pub struct AndroidUpdate {
    version: String,
    body: String,
    url: String,
}

fn parse_release(value: &Value, current: &str) -> Result<Option<AndroidUpdate>, String> {
    if value["draft"].as_bool() != Some(false) || value["prerelease"].as_bool() != Some(false) {
        return Ok(None);
    }
    let tag = value["tag_name"].as_str().ok_or("版本信息缺少版本号")?;
    let version = Version::parse(tag.strip_prefix('v').unwrap_or(tag)).map_err(|_| "版本号格式无效")?;
    let current = Version::parse(current).map_err(|_| "当前版本号格式无效")?;
    if version <= current || !version.pre.is_empty() {
        return Ok(None);
    }
    let name = format!("Billow_{version}_arm64.apk");
    let expected = format!("https://github.com/sakullla/Billow/releases/download/{tag}/{name}");
    let asset = value["assets"].as_array().and_then(|assets| assets.iter().find(|asset| {
        asset["name"].as_str() == Some(name.as_str())
            && asset["browser_download_url"].as_str() == Some(expected.as_str())
            && asset["size"].as_u64().unwrap_or(0) > 0
    }));
    if asset.is_none() {
        return Err("新版发布中没有可用的 ARM64 安装包".to_string());
    }
    Ok(Some(AndroidUpdate {
        version: version.to_string(),
        body: value["body"].as_str().unwrap_or("").to_string(),
        url: expected,
    }))
}

#[tauri::command]
pub async fn check_android_app_update() -> Result<Option<AndroidUpdate>, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let response = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(15))
            .build()
            .get("https://api.github.com/repos/sakullla/Billow/releases/latest")
            .set("User-Agent", "Billow")
            .set("Accept", "application/vnd.github+json")
            .call();
        let response = match response {
            Ok(response) => response,
            Err(ureq::Error::Status(404, _)) => return Ok(None),
            Err(error) => return Err(format!("无法检查更新：{error}")),
        };
        let mut body = String::new();
        response.into_reader().take(2 * 1024 * 1024).read_to_string(&mut body)
            .map_err(|error| error.to_string())?;
        let value = serde_json::from_str(&body).map_err(|error| format!("版本信息无效：{error}"))?;
        parse_release(&value, env!("CARGO_PKG_VERSION"))
    }).await.map_err(|error| error.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release() -> Value {
        serde_json::json!({
            "tag_name": "v0.2.0", "draft": false, "prerelease": false,
            "body": "Updates", "assets": [{
                "name": "Billow_0.2.0_arm64.apk", "size": 100,
                "browser_download_url": "https://github.com/sakullla/Billow/releases/download/v0.2.0/Billow_0.2.0_arm64.apk"
            }]
        })
    }

    #[test]
    fn android_updates_only_offer_newer_stable_releases() {
        let value = release();
        assert_eq!(parse_release(&value, "0.1.0").unwrap().unwrap().version, "0.2.0");
        assert!(parse_release(&value, "0.2.0").unwrap().is_none());
        assert!(parse_release(&value, "0.10.0").unwrap().is_none());
        let mut draft = value.clone();
        draft["draft"] = true.into();
        assert!(parse_release(&draft, "0.1.0").unwrap().is_none());
        let mut preview = value;
        preview["prerelease"] = true.into();
        assert!(parse_release(&preview, "0.1.0").unwrap().is_none());
    }

    #[test]
    fn android_updates_reject_missing_and_external_assets() {
        let mut value = release();
        value["assets"][0]["browser_download_url"] = "https://example.com/update.apk".into();
        assert!(parse_release(&value, "0.1.0").is_err());
        value["assets"] = serde_json::json!([]);
        assert!(parse_release(&value, "0.1.0").is_err());
    }
}
