//! iOS Packet Tunnel host commands.
//!
//! The Tauri app on iOS cannot start the two extensions itself: Network
//! Extension management lives in the host target's Swift code
//! (`network-extension/Host/BillowMobileBridge.swift`). This module is the
//! Rust side of that bridge. It keeps the command and error shape stable on
//! every platform:
//!
//! * iOS calls the C ABI exported by `BillowMobileBridge.swift`;
//! * desktop and Android compile the same commands and answer the stable
//!   `notIos` code (11) instead of failing to build or silently doing nothing.
//!
//! Error codes are the `BillowVPNError.Code` values used by the extensions
//! (0 providerFailed … 10 hostNotReady) plus the local `notIos`/`badResponse`
//! codes. The frontend displays `message` and can branch on `code`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `notIos`: the host has no NetworkExtension bridge on this platform.
pub const CODE_NOT_IOS: i32 = 11;
/// `badResponse`: the host bridge returned malformed JSON or an unknown shape.
pub const CODE_BAD_RESPONSE: i32 = 12;

const ERROR_DOMAIN: &str = "app.billow.client.ios_vpn";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IosVpnError {
    pub code: i32,
    pub message: String,
    pub domain: String,
}

impl IosVpnError {
    fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            domain: ERROR_DOMAIN.to_string(),
        }
    }

    pub(crate) fn host(message: impl Into<String>) -> Self {
        Self::new(CODE_BAD_RESPONSE, message)
    }

    pub(crate) fn not_ios_error() -> Self {
        Self::not_ios()
    }

    fn not_ios() -> Self {
        Self::new(
            CODE_NOT_IOS,
            "iOS NetworkExtension commands are only available in the iOS app",
        )
    }

    fn bad_response(message: impl Into<String>) -> Self {
        Self::new(CODE_BAD_RESPONSE, message)
    }
}

impl std::fmt::Display for IosVpnError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} (code {})", self.message, self.code)
    }
}

impl std::error::Error for IosVpnError {}

/// One engine row for the settings card. Mirrors
/// `BillowMobileEntry.EngineState` in the host target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IosEngineState {
    pub engine: String,
    pub installed: bool,
    pub connected: bool,
    pub version: Option<String>,
    pub engine_version: Option<String>,
    pub last_error: Option<String>,
}

/// `ProviderStatus` written by either extension; used when a session replies
/// to the host `status` message. Mirrors `Shared/ProviderSupport.swift`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IosStatus {
    pub extension_id: String,
    pub engine: String,
    pub embedded_version: Option<String>,
    pub running: bool,
    pub version: Option<String>,
    pub loopback_port: Option<u16>,
    pub loopback_listen: Option<String>,
    pub last_error: Option<String>,
    pub error_code: Option<i32>,
    pub started_at: Option<String>,
    /// Live counters + process peak RSS. Published by the Rust extension's
    /// `billow_ios_vpn_stats`; absent for Mihomo and older builds. The Swift
    /// host carries the same object in `ProviderStatus.stats` (reply, bridge
    /// and `status/<engine>.json`), so `ios_vpn_status("rust").stats` exposes
    /// these counters whenever the extension replied.
    #[serde(default)]
    pub stats: Option<IosStats>,
}

/// The Rust extension's `stats` object (`billow_ios_vpn_stats`). Every field is
/// optional so a reply without a counter still decodes; key names mirror the
/// JSON emitted by the kernel and the extension's status reply.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IosStats {
    pub running: Option<bool>,
    pub version: Option<String>,
    pub generation: Option<u64>,
    pub reloads: Option<u64>,
    pub peak_rss_bytes: Option<u64>,
    pub in_packets: Option<u64>,
    pub in_bytes: Option<u64>,
    pub out_packets: Option<u64>,
    pub out_bytes: Option<u64>,
    pub tcp_opened: Option<u64>,
    pub tcp_closed: Option<u64>,
    pub tcp_rejected: Option<u64>,
    pub tcp_flows: Option<u64>,
    pub tcp_flow_high: Option<u64>,
    pub udp_datagrams: Option<u64>,
    pub udp_replies: Option<u64>,
    pub udp_flows: Option<u64>,
    pub udp_flow_high: Option<u64>,
    pub dns_queries: Option<u64>,
    pub dns_failures: Option<u64>,
    pub invalid_packets: Option<u64>,
    pub fragments: Option<u64>,
    pub unsupported_protocols: Option<u64>,
    pub icmp_dropped: Option<u64>,
    pub dropped_inbound: Option<u64>,
    pub dropped_egress: Option<u64>,
    pub queue_high: Option<u64>,
    pub queued_packets: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IosPrepareResult {
    pub version: String,
    pub engines: Vec<String>,
    pub files: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IosSelected {
    pub selected: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostRequest {
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "stagedDir", skip_serializing_if = "Option::is_none")]
    pub staged_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keeping: Option<Vec<String>>,
}

impl HostRequest {
    fn new(command: &str) -> Self {
        Self {
            command: command.to_string(),
            engine: None,
            version: None,
            staged_dir: None,
            keeping: None,
        }
    }

    fn engine(mut self, engine: &str) -> Self {
        self.engine = Some(engine.to_string());
        self
    }

    fn version(mut self, version: &str) -> Self {
        self.version = Some(version.to_string());
        self
    }

    fn staged_dir(mut self, staged_dir: &str) -> Self {
        self.staged_dir = Some(staged_dir.to_string());
        self
    }

    fn keeping(mut self, keeping: Vec<String>) -> Self {
        self.keeping = Some(keeping);
        self
    }
}

#[derive(Debug, Deserialize)]
struct HostResponse {
    ok: bool,
    #[serde(default)]
    data: Option<Value>,
    #[serde(default)]
    error: Option<HostError>,
}

#[derive(Debug, Deserialize)]
struct HostError {
    #[serde(default)]
    code: i32,
    #[serde(default)]
    message: String,
    #[serde(default)]
    domain: String,
}

/// Transport seam for unit tests; the production implementation is the C ABI
/// exported by the host Swift target.
pub(crate) trait HostTransport {
    fn request(&self, payload: &str) -> Result<String, IosVpnError>;
}

pub(crate) struct PlatformTransport;

impl HostTransport for PlatformTransport {
    fn request(&self, payload: &str) -> Result<String, IosVpnError> {
        #[cfg(target_os = "ios")]
        {
            use std::ffi::{CStr, CString};

            unsafe extern "C" {
                fn billow_mobile_request(request: *const std::ffi::c_char)
                    -> *mut std::ffi::c_char;
                fn billow_mobile_free(pointer: *mut std::ffi::c_char);
            }

            let request = CString::new(payload).map_err(|_| {
                IosVpnError::bad_response("request contained a NUL byte")
            })?;
            let pointer = unsafe { billow_mobile_request(request.as_ptr()) };
            if pointer.is_null() {
                return Err(IosVpnError::bad_response(
                    "host bridge returned no response (BillowMobileBridge.swift missing?)",
                ));
            }
            let text = unsafe { CStr::from_ptr(pointer) }
                .to_string_lossy()
                .into_owned();
            unsafe { billow_mobile_free(pointer) };
            Ok(text)
        }
        #[cfg(not(target_os = "ios"))]
        {
            let _ = payload;
            Err(IosVpnError::not_ios())
        }
    }
}

pub(crate) fn dispatch<T: HostTransport>(
    transport: &T,
    request: &HostRequest,
) -> Result<Value, IosVpnError> {
    let payload = serde_json::to_string(request)
        .map_err(|error| IosVpnError::bad_response(format!("request encoding failed: {error}")))?;
    let text = transport.request(&payload)?;
    let response: HostResponse = serde_json::from_str(&text).map_err(|error| {
        IosVpnError::bad_response(format!("host bridge returned invalid JSON: {error}"))
    })?;
    if response.ok {
        return Ok(response.data.unwrap_or(Value::Null));
    }
    let error = response.error.unwrap_or(HostError {
        code: 0,
        message: "host bridge rejected the request without a message".to_string(),
        domain: ERROR_DOMAIN.to_string(),
    });
    Err(IosVpnError {
        code: error.code,
        message: if error.message.is_empty() {
            "host bridge error".to_string()
        } else {
            error.message
        },
        domain: if error.domain.is_empty() {
            ERROR_DOMAIN.to_string()
        } else {
            error.domain
        },
    })
}

fn decode<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, IosVpnError> {
    serde_json::from_value(value)
        .map_err(|error| IosVpnError::bad_response(format!("host response shape: {error}")))
}

fn run<T: Send + 'static>(
    call: impl FnOnce() -> Result<T, IosVpnError> + Send + 'static,
) -> impl std::future::Future<Output = Result<T, IosVpnError>> {
    async move {
        tauri::async_runtime::spawn_blocking(call)
            .await
            .map_err(|error| IosVpnError::bad_response(format!("host bridge task failed: {error}")))?
    }
}

#[tauri::command]
pub async fn ios_vpn_engines() -> Result<Vec<IosEngineState>, IosVpnError> {
    run(|| decode(dispatch(&PlatformTransport, &HostRequest::new("engines"))?)).await
}

#[tauri::command]
pub async fn ios_vpn_active_version() -> Result<Option<String>, IosVpnError> {
    run(|| {
        let value = dispatch(&PlatformTransport, &HostRequest::new("activeVersion"))?;
        Ok(value.as_str().map(str::to_string))
    })
    .await
}

#[tauri::command]
pub async fn ios_vpn_selected() -> Result<IosSelected, IosVpnError> {
    run(|| decode(dispatch(&PlatformTransport, &HostRequest::new("selected"))?)).await
}

#[tauri::command]
pub async fn ios_vpn_prepare(
    version: String,
    staged_dir: String,
    engine: Option<String>,
) -> Result<IosPrepareResult, IosVpnError> {
    run(move || {
        let mut request = HostRequest::new("prepare")
            .version(&version)
            .staged_dir(&staged_dir);
        if let Some(engine) = engine {
            request = request.engine(&engine);
        }
        decode(dispatch(&PlatformTransport, &request)?)
    })
    .await
}

#[tauri::command]
pub async fn ios_vpn_select(engine: String) -> Result<IosSelected, IosVpnError> {
    run(move || {
        decode(dispatch(
            &PlatformTransport,
            &HostRequest::new("select").engine(&engine),
        )?)
    })
    .await
}

#[tauri::command]
pub async fn ios_vpn_connect(engine: String, version: String) -> Result<(), IosVpnError> {
    run(move || {
        dispatch(
            &PlatformTransport,
            &HostRequest::new("connect").engine(&engine).version(&version),
        )?;
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn ios_vpn_disconnect() -> Result<(), IosVpnError> {
    run(|| {
        dispatch(&PlatformTransport, &HostRequest::new("disconnect"))?;
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn ios_vpn_status(engine: String) -> Result<Option<IosStatus>, IosVpnError> {
    run(move || status(&PlatformTransport, &engine)).await
}

/// Shared by the command and the tests: an absent status reply is `Ok(None)`,
/// a present one carries the same `stats` object the extension sent.
fn status<T: HostTransport>(
    transport: &T,
    engine: &str,
) -> Result<Option<IosStatus>, IosVpnError> {
    let value = dispatch(transport, &HostRequest::new("status").engine(engine))?;
    if value.is_null() {
        return Ok(None);
    }
    decode(value).map(Some)
}

#[tauri::command]
pub async fn ios_vpn_reload(engine: String) -> Result<(), IosVpnError> {
    run(move || {
        dispatch(
            &PlatformTransport,
            &HostRequest::new("reload").engine(&engine),
        )?;
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn ios_vpn_prune(keeping: Vec<String>) -> Result<(), IosVpnError> {
    run(move || {
        dispatch(
            &PlatformTransport,
            &HostRequest::new("prune").keeping(keeping),
        )?;
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Mock {
        reply: String,
        seen: RefCell<Vec<String>>,
    }

    impl Mock {
        fn new(reply: &str) -> Self {
            Self {
                reply: reply.to_string(),
                seen: RefCell::new(Vec::new()),
            }
        }
    }

    impl HostTransport for Mock {
        fn request(&self, payload: &str) -> Result<String, IosVpnError> {
            self.seen.borrow_mut().push(payload.to_string());
            Ok(self.reply.clone())
        }
    }

    #[test]
    fn engines_decode_the_host_rows() {
        let mock = Mock::new(
            r#"{"ok":true,"data":[{"engine":"rust","installed":true,"connected":false,
                "version":"v1","engineVersion":"billow-rust 0.1.0","lastError":null}]}"#,
        );
        let value = dispatch(&mock, &HostRequest::new("engines")).unwrap();
        let rows: Vec<IosEngineState> = decode(value).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].engine, "rust");
        assert!(rows[0].installed);
        assert!(!rows[0].connected);
        assert_eq!(rows[0].engine_version.as_deref(), Some("billow-rust 0.1.0"));
        assert_eq!(rows[0].last_error, None);
    }

    #[test]
    fn host_errors_keep_the_stable_code_and_domain() {
        let mock = Mock::new(
            r#"{"ok":false,"error":{"code":4,"message":"libapp.a not linked",
                "domain":"app.billow.client.vpn"}}"#,
        );
        let error = dispatch(&mock, &HostRequest::new("connect")).unwrap_err();
        assert_eq!(error.code, 4);
        assert_eq!(error.message, "libapp.a not linked");
        assert_eq!(error.domain, "app.billow.client.vpn");
    }

    #[test]
    fn malformed_host_replies_are_named() {
        let mock = Mock::new("not json");
        let error = dispatch(&mock, &HostRequest::new("status")).unwrap_err();
        assert_eq!(error.code, CODE_BAD_RESPONSE);
        assert!(error.message.contains("invalid JSON"));
    }

    #[test]
    fn request_payload_uses_the_host_field_names() {
        let mock = Mock::new(r#"{"ok":true,"data":{}}"#);
        let request = HostRequest::new("prepare")
            .version("v1")
            .staged_dir("/tmp/stage")
            .engine("rust");
        dispatch(&mock, &request).unwrap();
        let seen = mock.seen.borrow();
        let sent: Value = serde_json::from_str(&seen[0]).unwrap();
        assert_eq!(sent["command"], "prepare");
        assert_eq!(sent["stagedDir"], "/tmp/stage");
        assert_eq!(sent["engine"], "rust");
        assert!(sent.get("keeping").is_none());
    }

    #[test]
    fn connect_payload_carries_engine_and_version() {
        let mock = Mock::new(r#"{"ok":true,"data":{}}"#);
        dispatch(
            &mock,
            &HostRequest::new("connect").engine("rust").version("v7"),
        )
        .unwrap();
        let seen = mock.seen.borrow();
        let sent: Value = serde_json::from_str(&seen[0]).unwrap();
        assert_eq!(sent["command"], "connect");
        assert_eq!(sent["engine"], "rust");
        assert_eq!(sent["version"], "v7");
    }

    #[test]
    fn null_status_is_not_an_error() {
        let mock = Mock::new(r#"{"ok":true,"data":null}"#);
        let value = dispatch(
            &mock,
            &HostRequest::new("status").engine("rust"),
        )
        .unwrap();
        assert!(value.is_null());
    }

    #[test]
    fn status_reply_carries_the_rust_stats_for_the_r4_entry() {
        let mock = Mock::new(
            r#"{"ok":true,"data":{
                "extensionId":"app.billow.client.rust","engine":"rust",
                "embeddedVersion":"billow-rust 0.1.0","running":true,
                "version":"v7","loopbackPort":null,"loopbackListen":null,
                "lastError":null,"errorCode":null,
                "startedAt":"2026-11-24T00:00:00Z",
                "stats":{"running":true,"version":"billow-rust 0.1.0",
                    "generation":3,"reloads":2,"peakRssBytes":28491776,
                    "tcpFlows":8,"tcpOpened":12,"tcpClosed":4,
                    "queuedPackets":0,"queueHigh":7,
                    "udpFlows":2,"dnsQueries":5}
            }}"#,
        );
        let status = status(&mock, "rust").unwrap().expect("status");
        assert!(status.running);
        assert_eq!(status.version.as_deref(), Some("v7"));
        let stats = status.stats.expect("stats passthrough");
        assert_eq!(stats.generation, Some(3));
        assert_eq!(stats.reloads, Some(2));
        assert_eq!(stats.peak_rss_bytes, Some(28_491_776));
        assert_eq!(stats.tcp_flows, Some(8));
        assert_eq!(stats.tcp_opened, Some(12));
        assert_eq!(stats.queued_packets, Some(0));
        assert_eq!(stats.queue_high, Some(7));
        assert_eq!(stats.dns_queries, Some(5));
    }

    #[test]
    fn status_reply_without_stats_stays_compatible() {
        let mock = Mock::new(
            r#"{"ok":true,"data":{
                "extensionId":"app.billow.client.mihomo","engine":"mihomo",
                "embeddedVersion":"v1.19.34","running":true,"version":"v1",
                "loopbackPort":1234,"loopbackListen":"127.0.0.1:1234",
                "lastError":null,"errorCode":null,"startedAt":null
            }}"#,
        );
        let status = status(&mock, "mihomo").unwrap().expect("status");
        assert_eq!(status.loopback_port, Some(1234));
        assert_eq!(status.stats, None);
    }

    #[test]
    fn stats_keys_unknown_to_this_build_do_not_break_decoding() {
        let mock = Mock::new(
            r#"{"ok":true,"data":{
                "extensionId":"app.billow.client.rust","engine":"rust",
                "embeddedVersion":null,"running":false,"version":null,
                "loopbackPort":null,"loopbackListen":null,"lastError":null,
                "errorCode":null,"startedAt":null,
                "stats":{"generation":1,"futureCounter":99}
            }}"#,
        );
        let status = status(&mock, "rust").unwrap().expect("status");
        assert_eq!(status.stats.unwrap().generation, Some(1));
    }

    #[cfg(not(target_os = "ios"))]
    #[test]
    fn non_ios_platform_reports_not_ios() {
        let error = PlatformTransport
            .request(r#"{"command":"engines"}"#)
            .unwrap_err();
        assert_eq!(error.code, CODE_NOT_IOS);
    }
}
