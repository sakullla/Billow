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
    /// Validate the configuration and rule set, then exit without listening.
    #[arg(long)]
    check: bool,
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
    // Validate before starting threads so a rejected configuration exits non-zero with its explicit reason.
    let loaded = billow_kernel::load_config(&yaml, &args.config.display().to_string())
        .map_err(|e| format!("[{}] {e}", e.tag()))?;
    let max_level = match loaded.config.log_level.as_deref() {
        Some("silent") | Some("error") => tracing::Level::ERROR,
        Some("debug") => tracing::Level::DEBUG,
        _ => tracing::Level::INFO,
    };
    install_line_logger(max_level);
    for warning in &loaded.warnings {
        tracing::warn!("{warning}");
    }

    let mut config = loaded.config.clone();
    if let Some(port) = args.port {
        config.listen.set_port(port);
    }
    // Relative provider paths resolve against the configuration file's
    // directory and must stay under it (or `SAFE_PATHS`), matching the pinned
    // `C.Path` home root rather than whatever directory launched the process.
    let base_dir = args
        .config
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    if args.check {
        let (mut kernel, _) = start(
            &billow_kernel::LoadedConfig {
                config,
                warnings: loaded.warnings.clone(),
            },
            &args,
            &base_dir,
        )?;
        println!("{}", kernel.identity().to_line());
        kernel.stop().map_err(|e| e.to_string())?;
        println!("configuration accepted");
        return Ok(ExitCode::SUCCESS);
    }

    let (mut kernel, _) = start(
        &billow_kernel::LoadedConfig {
            config,
            warnings: loaded.warnings.clone(),
        },
        &args,
        &base_dir,
    )?;
    let identity = kernel.identity().clone();
    println!("{}", identity.to_line());
    println!("features: {}", identity.features);

    let reason = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?
        .block_on(wait_for_stop());
    tracing::info!(reason, "stop requested");
    kernel.stop().map_err(|e| e.to_string())?;
    let stats = kernel.stats();
    println!(
        "stopped instance={} accepted={} active={} completed={} rejected={} failed={} bytes_up={} bytes_down={}",
        identity.uuid, stats.accepted, stats.active, stats.completed, stats.rejected, stats.failed, stats.bytes_up, stats.bytes_down
    );
    Ok(ExitCode::SUCCESS)
}

fn start(
    loaded: &billow_kernel::LoadedConfig,
    args: &Args,
    base_dir: &std::path::Path,
) -> Result<(Kernel, Vec<String>), String> {
    let limits = Limits {
        buffer_size: args.buffer_bytes,
        max_sessions: args.max_sessions,
        ..Limits::default()
    };
    let (mut kernel, warnings) =
        Kernel::start_with_dir(loaded, args.geosite_dir.clone(), base_dir.to_path_buf(), limits)
            .map_err(|e| format!("[{}] {e}", e.tag()))?;
    let identity = kernel.identity().clone().with_port_override(args.port);
    kernel.set_identity(identity);
    Ok((kernel, warnings))
}

async fn wait_for_stop() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut interrupt = signal(SignalKind::interrupt()).expect("SIGINT handler");
        let mut terminate = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = interrupt.recv() => "SIGINT",
            _ = terminate.recv() => "SIGTERM",
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

/// Line logger: `HH:MM:SS.mmm LEVEL target: message field=value ...`.
fn install_line_logger(max_level: tracing::Level) {
    struct LineLogger {
        max_level: tracing::Level,
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
        }
    }
    let _ = tracing::subscriber::set_global_default(LineLogger { max_level });
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
