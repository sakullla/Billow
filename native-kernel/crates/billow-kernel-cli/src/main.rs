//! Standalone process entry for the Billow native Rust kernel.
//!
//! This crate only wires process arguments, logging, SIGINT/SIGTERM and the
//! identity banner around the public `billow_kernel` API; T6 reuses that API
//! for the desktop/Android process lifecycle.

use std::path::PathBuf;
use std::process::ExitCode;

use billow_kernel::{Kernel, Limits};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "billow-kernel",
    version,
    about = "Billow native Rust kernel (first slice: mixed HTTP CONNECT + SOCKS5, DIRECT/REJECT)"
)]
struct Args {
    /// Clash-style YAML; only the implemented subset is accepted, other keys fail.
    config: PathBuf,
    /// Override the mixed listener port (diagnostic; recorded in the identity).
    #[arg(long)]
    port: Option<u16>,
    /// Directory with geodata (GeoSite.dat, GeoIP.dat or Country.mmdb, ASN.mmdb).
    #[arg(long, alias = "geodata-dir")]
    geosite_dir: Option<PathBuf>,
    /// Per-direction copy buffer in bytes.
    #[arg(long, default_value_t = 16 * 1024)]
    buffer_bytes: usize,
    /// Concurrent session cap.
    #[arg(long, default_value_t = 256)]
    max_sessions: usize,
    /// Directory for the selection cache (`profile.store-selected`).
    #[arg(long)]
    cache_dir: Option<PathBuf>,
    /// Fix a group selection before traffic, e.g. `--select PROXY=node-b`
    /// (repeatable). Persisted when the configuration enables
    /// `profile.store-selected` and a cache directory is set.
    #[arg(long = "select", value_name = "GROUP=MEMBER")]
    selections: Vec<String>,
    /// Run every group/provider health check once after start.
    #[arg(long)]
    probe_groups: bool,
    /// Wait this many milliseconds after start, then print group state.
    #[arg(long, default_value_t = 0)]
    wait_ms: u64,
    /// Print one machine-readable `GROUPS {...}` line with the group list,
    /// current selections and per-member health.
    #[arg(long)]
    print_groups: bool,
    /// Validate the configuration and rule set, then exit without listening.
    #[arg(long)]
    check: bool,
    /// Run the Android VpnService data plane on an inherited TUN fd: read
    /// device IP packets from it and write emitted packets back instead of
    /// only serving the mixed listener. The host passes the fd number after
    /// clearing FD_CLOEXEC (`BillowVpnService.establishTun`).
    #[cfg(feature = "android-vpn")]
    #[arg(long, value_name = "FD")]
    tun_fd: Option<i32>,
    /// Create and carry a desktop TUN device (macOS utun / Linux /dev/net/tun /
    /// Windows Wintun) instead of only serving the mixed listener. Requires the
    /// `desktop-tun` build and the host's TUN authorization; `--check` still
    /// only validates the configuration and never creates a device.
    #[cfg(feature = "desktop-tun")]
    #[arg(long)]
    tun: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match real_main(args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn real_main(args: Args) -> Result<ExitCode, String> {
    let yaml = std::fs::read_to_string(&args.config)
        .map_err(|e| format!("[invalid_yaml] {}: {e}", args.config.display()))?;
    // Relative provider paths resolve against the configuration file's
    // directory and must stay under it (or `SAFE_PATHS`), matching the pinned
    // `C.Path` home root rather than whatever directory launched the process.
    let base_dir = args
        .config
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    #[cfg(feature = "android-vpn")]
    if let Some(fd) = args.tun_fd {
        // The Android host hands the VpnService TUN fd to this process instead
        // of writing `tun.file-descriptor` into the YAML. Stage the shared file
        // first (the staging removes the launcher `tun`/`sniffer` blocks) and
        // start the fd pump; `--check` keeps its single meaning below.
        if args.check {
            return Err("--tun-fd and --check cannot be combined".to_string());
        }
        #[cfg(feature = "desktop-tun")]
        if args.tun {
            return Err("--tun-fd and --tun cannot be combined".to_string());
        }
        install_line_logger(tracing::Level::INFO, billow_kernel::LogBus::new());
        return run_android_tunnel(&args, &yaml, &base_dir, fd);
    }
    #[cfg(feature = "desktop-tun")]
    if args.tun && !args.check {
        install_line_logger(tracing::Level::INFO, billow_kernel::LogBus::new());
        return run_desktop_tunnel(&args, &yaml, &base_dir);
    }
    // Validate before starting threads so a rejected configuration exits non-zero with its explicit reason.
    let loaded = billow_kernel::load_config(&yaml, &args.config.display().to_string())
        .map_err(|e| format!("[{}] {e}", e.tag()))?;
    let max_level = match loaded.config.log_level.as_deref() {
        Some("silent") | Some("error") => tracing::Level::ERROR,
        Some("debug") => tracing::Level::DEBUG,
        _ => tracing::Level::INFO,
    };
    let log_bus = billow_kernel::LogBus::new();
    install_line_logger(max_level, log_bus.clone());
    for warning in &loaded.warnings {
        tracing::warn!("{warning}");
    }

    let mut config = loaded.config.clone();
    if let Some(port) = args.port {
        config.listen.set_port(port);
    }
    let options = billow_kernel::KernelOptions {
        cache_dir: args
            .cache_dir
            .clone()
            .or_else(|| Some(base_dir.clone())),
        log_bus: Some(log_bus.clone()),
    };
    if args.check {
        let (mut kernel, _) = start(
            &billow_kernel::LoadedConfig {
                config,
                warnings: loaded.warnings.clone(),
            },
            &args,
            &base_dir,
            &options,
        )?;
        println!("{}", kernel.identity().to_line());
        kernel.stop().map_err(|e| e.to_string())?;
        println!("configuration accepted");
        return Ok(ExitCode::SUCCESS);
    }

    // A `tun` block that asks for a device must not be silently ignored just
    // because this launch only serves the mixed listener.
    if config.tun.enable {
        return Err(
            "[unsupported] tun.enable is true but this launch does not create a desktop TUN \
             (pass --tun on a desktop-tun build; Android uses --tun-fd and iOS uses the Packet Tunnel)"
                .to_string(),
        );
    }

    // Register the stop handlers before the kernel binds anything, so a signal
    // that arrives during startup is still observed instead of killing the
    // process through the default disposition.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let mut stop = runtime.block_on(StopSignals::install())?;

    let (mut kernel, _) = start(
        &billow_kernel::LoadedConfig {
            config,
            warnings: loaded.warnings.clone(),
        },
        &args,
        &base_dir,
        &options,
    )?;
    let identity = kernel.identity().clone();
    println!("{}", identity.to_line());
    println!("features: {}", identity.features);

    if args.print_groups || args.probe_groups || args.wait_ms > 0 || !args.selections.is_empty() {
        run_diagnostics(&kernel, &args)?;
        // A scripted diagnostic session: report, stop, and exit instead of
        // waiting for a signal. (Selection-only invocations without
        // `--print-groups`/`--wait-ms` keep running below.)
        if args.print_groups || args.probe_groups || args.wait_ms > 0 {
            kernel.stop().map_err(|e| e.to_string())?;
            return Ok(ExitCode::SUCCESS);
        }
    }

    let reason = runtime.block_on(stop.wait());
    tracing::info!(reason, "stop requested");
    kernel.stop().map_err(|e| e.to_string())?;
    let stats = kernel.stats();
    println!(
        "stopped instance={} accepted={} active={} completed={} rejected={} failed={} bytes_up={} bytes_down={}",
        identity.uuid, stats.accepted, stats.active, stats.completed, stats.rejected, stats.failed, stats.bytes_up, stats.bytes_down
    );
    Ok(ExitCode::SUCCESS)
}

/// Runs the Android VpnService data plane on an inherited TUN fd.
#[cfg(feature = "android-vpn")]
fn run_android_tunnel(
    args: &Args,
    yaml: &str,
    base_dir: &std::path::Path,
    fd: i32,
) -> Result<ExitCode, String> {
    use billow_kernel::android_vpn::{AndroidVpn, AndroidVpnOptions};
    use billow_kernel::tunnel::TunnelOptions;

    let options = AndroidVpnOptions {
        tunnel: TunnelOptions {
            limits: Limits {
                buffer_size: args.buffer_bytes,
                max_sessions: args.max_sessions,
                ..Limits::default()
            },
            ..TunnelOptions::default()
        },
        ..AndroidVpnOptions::default()
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    // Same startup-race guard as the plain runner: install the handlers before
    // the engine starts.
    let mut stop = runtime.block_on(StopSignals::install())?;
    let vpn = AndroidVpn::start(fd, yaml, base_dir.to_path_buf(), options)
        .map_err(|error| format!("android-vpn: {error}"))?;
    let identity = vpn
        .identity()
        .ok_or_else(|| "android-vpn: the engine did not start".to_string())?;
    println!("{}", identity.to_line());
    println!("features: {}", identity.features);
    println!("tun_fd: {fd}");

    let reason = runtime.block_on(wait_for_android_stop(&vpn, &mut stop));
    let fd_lost = reason == FD_LOST;
    tracing::info!(reason, "stop requested");
    vpn.stop();
    // Staged by `AndroidVpn::start`; the next launch rewrites it.
    let _ = std::fs::remove_file(base_dir.join("config.rust.yaml"));
    let stats = vpn.stats();
    println!(
        "stopped instance={} accepted={} active={} rejected={} failed={} inPackets={} outPackets={} fdReads={} fdWritten={}",
        identity.uuid,
        stats.tunnel.tcp_opened,
        stats.tunnel.tcp_flows,
        stats.tunnel.tcp_rejected,
        stats.tunnel.invalid_packets,
        stats.tunnel.in_packets,
        stats.tunnel.out_packets,
        stats.fd.reads,
        stats.fd.written
    );
    if fd_lost {
        // The host only samples process liveness for the Rust engine, so an
        // exited child (non-zero) is the signal that the data plane is gone.
        eprintln!(
            "error: android-vpn: the inherited TUN fd stopped carrying packets; \
             exiting so the host can release the VPN"
        );
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// The fd pump ending on its own (a revoked VPN, the VpnService side closing
/// the descriptor, or a hard read/write error) is a data-plane failure, not a
/// stop request. The host can only observe process liveness for the Rust
/// engine, so this returns and the process exits non-zero instead of waiting
/// for a signal with a dead data plane.
#[cfg(feature = "android-vpn")]
const FD_LOST: &str = "tun-fd closed";

#[cfg(feature = "android-vpn")]
async fn wait_for_android_stop(
    vpn: &billow_kernel::android_vpn::AndroidVpn,
    stop: &mut StopSignals,
) -> &'static str {
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(250));
    loop {
        tokio::select! {
            reason = stop.wait() => return reason,
            _ = ticker.tick() => {
                if !vpn.stats().running {
                    return FD_LOST;
                }
            }
        }
    }
}

/// Runs the desktop TUN data plane (`--tun`).
#[cfg(feature = "desktop-tun")]
fn run_desktop_tunnel(
    args: &Args,
    yaml: &str,
    base_dir: &std::path::Path,
) -> Result<ExitCode, String> {
    use billow_kernel::desktop_tun::{DesktopTun, DesktopTunOptions};
    use billow_kernel::tunnel::TunnelOptions;

    let options = DesktopTunOptions {
        tunnel: TunnelOptions {
            limits: Limits {
                buffer_size: args.buffer_bytes,
                max_sessions: args.max_sessions,
                ..Limits::default()
            },
            ..TunnelOptions::default()
        },
        ..DesktopTunOptions::default()
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let mut stop = runtime.block_on(StopSignals::install())?;
    let tun = DesktopTun::start(yaml, base_dir.to_path_buf(), options)?;
    let identity = tun
        .identity()
        .ok_or_else(|| "desktop-tun: the engine did not start".to_string())?;
    println!("{}", identity.to_line());
    println!("features: {}", identity.features);
    println!("tun_device: {}", tun.device_name());
    if let Some(interface) = tun.bound_interface() {
        println!("tun_interface: {interface}");
    }

    let reason = runtime.block_on(wait_for_desktop_stop(&tun, &mut stop));
    let lost = reason == TUN_LOST;
    tracing::info!(reason, "stop requested");
    tun.stop();
    let (tunnel, pump) = tun.stats();
    println!(
        "stopped instance={} accepted={} active={} rejected={} failed={} inPackets={} outPackets={} tunReads={} tunWritten={}",
        identity.uuid,
        tunnel.tcp_opened,
        tunnel.tcp_flows,
        tunnel.tcp_rejected,
        tunnel.invalid_packets,
        tunnel.in_packets,
        tunnel.out_packets,
        pump.reads,
        pump.written
    );
    if lost {
        eprintln!(
            "error: desktop-tun: the TUN device stopped carrying packets; \
             exiting so the host can release TUN ownership"
        );
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// The desktop pump ending on its own (a revoked authorization or a device
/// failure) is a data-plane failure, not a stop request.
#[cfg(feature = "desktop-tun")]
const TUN_LOST: &str = "tun device lost";

#[cfg(feature = "desktop-tun")]
async fn wait_for_desktop_stop(
    tun: &billow_kernel::desktop_tun::DesktopTun,
    stop: &mut StopSignals,
) -> &'static str {
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(250));
    loop {
        tokio::select! {
            reason = stop.wait() => return reason,
            _ = ticker.tick() => {
                if !tun.running() {
                    return TUN_LOST;
                }
            }
        }
    }
}

/// Apply scripted selections, wait for health checks, then print the group
/// state. Used by hosts/tests and the T23 differential probe.
fn run_diagnostics(kernel: &Kernel, args: &Args) -> Result<(), String> {
    for selection in &args.selections {
        let (group, member) = selection.split_once('=').ok_or_else(|| {
            format!("--select expects GROUP=MEMBER, got '{selection}'")
        })?;
        kernel
            .select_group(group, member)
            .map_err(|error| format!("--select {group}={member}: {error}"))?;
    }
    if args.wait_ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(args.wait_ms));
    }
    if args.probe_groups {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let probed = runtime.block_on(kernel.groups().probe_all());
        tracing::info!(probed, "explicit health check finished");
    }
    if args.print_groups {
        println!("GROUPS {}", groups_json(kernel));
    }
    Ok(())
}

fn groups_json(kernel: &Kernel) -> String {
    let mut out = String::from("{\"groups\":[");
    for (index, status) in kernel.group_statuses().iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"name\":{},\"type\":{},\"now\":{},\"all\":[{}],\"testUrl\":{},\"expectedStatus\":{},\"hidden\":{},\"members\":[{}]}}",
            json_string(&status.name),
            json_string(status.kind),
            json_string(&status.now),
            status
                .all
                .iter()
                .map(|name| json_string(name))
                .collect::<Vec<_>>()
                .join(","),
            json_string(&status.test_url),
            json_string(&status.expected_status),
            status.hidden,
            status
                .members
                .iter()
                .map(|member| format!(
                    "{{\"name\":{},\"alive\":{},\"delay\":{}}}",
                    json_string(&member.name),
                    member.alive,
                    member
                        .delay
                        .map(|delay| delay.to_string())
                        .unwrap_or_else(|| "null".to_string())
                ))
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    out.push_str("]}");
    out
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if (other as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", other as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn start(
    loaded: &billow_kernel::LoadedConfig,
    args: &Args,
    base_dir: &std::path::Path,
    options: &billow_kernel::KernelOptions,
) -> Result<(Kernel, Vec<String>), String> {
    let limits = Limits {
        buffer_size: args.buffer_bytes,
        max_sessions: args.max_sessions,
        ..Limits::default()
    };
    let (mut kernel, warnings) = Kernel::start_with_options(
        loaded,
        args.geosite_dir.clone(),
        base_dir.to_path_buf(),
        limits,
        options,
    )
    .map_err(|e| format!("[{}] {e}", e.tag()))?;
    let identity = kernel.identity().clone().with_port_override(args.port);
    kernel.set_identity(identity);
    Ok((kernel, warnings))
}

/// Stop signals, installed before the kernel starts so a signal that arrives
/// during startup is not handled by the default (process-killing) disposition.
struct StopSignals {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}

impl StopSignals {
    async fn install() -> Result<Self, String> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            Ok(Self {
                interrupt: signal(SignalKind::interrupt())
                    .map_err(|e| format!("SIGINT handler: {e}"))?,
                terminate: signal(SignalKind::terminate())
                    .map_err(|e| format!("SIGTERM handler: {e}"))?,
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }

    async fn wait(&mut self) -> &'static str {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = self.interrupt.recv() => "SIGINT",
                _ = self.terminate.recv() => "SIGTERM",
            }
        }
        #[cfg(not(unix))]
        {
            // Windows/Linux hosts drive lifecycle through the library API (T6);
            // this fallback only covers Ctrl+C in a console.
            let _ = tokio::signal::ctrl_c().await;
            "ctrl_c"
        }
    }
}

/// Line logger: `HH:MM:SS.mmm LEVEL target: message field=value ...`.
fn install_line_logger(max_level: tracing::Level, log_bus: billow_kernel::LogBus) {
    struct LineLogger {
        max_level: tracing::Level,
        log_bus: billow_kernel::LogBus,
    }
    struct Fields<'a>(&'a mut String);
    impl tracing::field::Visit for Fields<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, " {}={:?}", field.name(), value);
        }
    }
    impl tracing::Subscriber for LineLogger {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            *metadata.level() <= self.max_level
        }
        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(self.max_level.into())
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let metadata = event.metadata();
            if !self.enabled(metadata) {
                return;
            }
            let mut fields = String::new();
            event.record(&mut Fields(&mut fields));
            eprintln!(
                "[{} {:<5} {}]{}",
                now_stamp(),
                metadata.level(),
                metadata.target(),
                fields
            );
            let level = match *metadata.level() {
                tracing::Level::ERROR => "error",
                tracing::Level::WARN => "warning",
                tracing::Level::INFO => "info",
                tracing::Level::DEBUG | tracing::Level::TRACE => "debug",
            };
            let payload = fields.trim_start().to_string();
            if !payload.is_empty() {
                self.log_bus.publish(level, payload);
            }
        }
    }
    let _ = tracing::subscriber::set_global_default(LineLogger { max_level, log_bus });
}

fn now_stamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let millis = now.as_millis() % 1000;
    let secs = now.as_secs() % 86_400;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        secs / 3600,
        secs / 60 % 60,
        secs % 60,
        millis
    )
}
