//! Desktop TUN data plane (feature `desktop-tun`).
//!
//! [`DesktopTun::start`] creates the platform device (macOS `utun`, Linux
//! `/dev/net/tun`, Windows Wintun), assigns the device addresses and the split
//! default routes, starts the engine through [`Tunnel`] (the same T7 userspace
//! IP stack used by the iOS/Android entries) and pumps whole IP packets in
//! both directions through [`pump`].
//!
//! Ownership rules:
//! * a successful start owns the device, the routes and the process-global
//!   physical-interface binding; [`DesktopTun::stop`] (also `Drop`) removes
//!   exactly what this process added, clears the binding and closes the device;
//! * a failure while assigning addresses/routes rolls back every command that
//!   already ran before returning the named error;
//! * `--check` never calls this module; it only loads the configuration.

pub mod device;
pub mod framing;
pub mod pump;
pub mod route_plan;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::config::{load_config, TunConfig};
use crate::identity::Identity;
use crate::tunnel::{Tunnel, TunnelOptions, TunnelStats};

pub use device::{Framing, TunDevice};
pub use pump::{Pump, PumpStats};
pub use route_plan::{Command, DefaultRoute, Platform, RoutePlan};

/// Tunables of the desktop data plane.
#[derive(Debug, Clone)]
pub struct DesktopTunOptions {
    /// Shared T7 data-plane options (MTU/DNS hijack are taken from `tun`).
    pub tunnel: TunnelOptions,
    /// Emitted packets held before the device writer drops them.
    pub egress_queue: usize,
}

impl Default for DesktopTunOptions {
    fn default() -> Self {
        DesktopTunOptions {
            tunnel: TunnelOptions::default(),
            egress_queue: 256,
        }
    }
}

/// A running desktop TUN.
pub struct DesktopTun {
    tunnel: Arc<Tunnel>,
    device: Arc<dyn TunDevice>,
    pump: Mutex<Option<Pump>>,
    teardown: Vec<Command>,
    /// Physical interface this process bound kernel-originated sockets to.
    bound_interface: Option<String>,
    /// Set when the device/pump ended on its own (revoked permission, driver
    /// failure) rather than through [`DesktopTun::stop`].
    lost: AtomicBool,
    stopped: AtomicBool,
}

impl DesktopTun {
    /// Start from `config_yaml`; `base_dir` is the profile home the engine
    /// resolves providers under.
    pub fn start(
        config_yaml: &str,
        base_dir: PathBuf,
        options: DesktopTunOptions,
    ) -> Result<DesktopTun, String> {
        let config_path = base_dir.join("config.yaml");
        Self::start_at(config_yaml, config_path, base_dir, options)
    }

    /// [`DesktopTun::start`] with an explicit configuration file (the host may
    /// write `runtime-<nanos>.yaml` beside the profile).
    pub fn start_at(
        config_yaml: &str,
        config_path: PathBuf,
        base_dir: PathBuf,
        options: DesktopTunOptions,
    ) -> Result<DesktopTun, String> {
        let loaded = load_config(config_yaml, &config_path.display().to_string())
            .map_err(|error| format!("desktop-tun: configuration: {error}"))?;
        let tun = loaded.config.tun.clone();
        if !tun.enable {
            return Err("desktop-tun: tun.enable is false; no device is created".to_string());
        }
        let platform = Platform::current().ok_or_else(|| {
            "desktop-tun: this host has no implemented TUN backend (macOS, Linux and Windows only)"
                .to_string()
        })?;
        let physical = if tun.auto_detect_interface {
            detect_default_route(platform)
        } else {
            None
        };
        if tun.auto_detect_interface && physical.is_none() {
            tracing::warn!(
                "desktop-tun: auto-detect-interface did not find a physical default route; kernel-originated sockets are not interface-bound"
            );
        }
        let addresses = route_plan::DeviceAddresses::from_config(&loaded.config);
        if platform == Platform::Linux && tun.auto_route {
            check_linux_precheck(&tun, !addresses.v6.is_empty())?;
        }
        let device = device::create(&tun)?;
        let routes = route_plan::plan(
            platform,
            device.name(),
            &tun,
            &addresses,
            physical.as_ref(),
            tun.effective_mtu(),
        )?;
        let dns = plan_dns(platform, device.name(), &tun, &addresses)?;
        let mut plan = routes;
        plan.up.extend(dns.up);
        let mut down = dns.down;
        down.extend(plan.down);
        plan.down = down;
        apply_plan(&plan, &mut |command| run_command(command))?;

        let bound_interface = physical.as_ref().map(|route| route.interface.clone());
        if let Some(interface) = &bound_interface {
            // Anti-loop: every kernel-originated socket (proxy server, DIRECT
            // TCP/UDP, DNS queries) leaves through the physical interface
            // instead of the TUN that just captured the default route.
            crate::outbound::set_default_interface(Some(interface.clone()));
        }

        let tunnel_options = TunnelOptions {
            mtu: tun.effective_mtu(),
            dns_hijack: effective_dns_hijack(&tun, &addresses),
            ..options.tunnel
        };
        let tunnel = match Tunnel::start_at(
            config_yaml,
            config_path,
            base_dir,
            tunnel_options,
            None,
        ) {
            Ok(tunnel) => Arc::new(tunnel),
            Err(error) => {
                rollback(&plan);
                crate::outbound::set_default_interface(None);
                return Err(format!("desktop-tun: engine: {error}"));
            }
        };
        let pump = match Pump::start(tunnel.clone(), device.clone(), options.egress_queue) {
            Ok(pump) => pump,
            Err(error) => {
                tunnel.stop();
                rollback(&plan);
                crate::outbound::set_default_interface(None);
                return Err(error);
            }
        };
        tracing::info!(
            device = device.name(),
            mtu = tun.effective_mtu(),
            interface = bound_interface.as_deref().unwrap_or("-"),
            "desktop TUN started"
        );
        Ok(DesktopTun {
            tunnel,
            device,
            pump: Mutex::new(Some(pump)),
            teardown: plan.down,
            bound_interface,
            lost: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
        })
    }

    /// Interface name the platform assigned (`utunN`, `billow0`, `Billow`).
    pub fn device_name(&self) -> &str {
        self.device.name()
    }

    /// Physical interface kernel-originated sockets are bound to, when
    /// `auto-detect-interface` found one.
    pub fn bound_interface(&self) -> Option<&str> {
        self.bound_interface.as_deref()
    }

    pub fn identity(&self) -> Option<Identity> {
        self.tunnel.identity()
    }

    /// Tunnel counters plus the device-side counters.
    pub fn stats(&self) -> (TunnelStats, PumpStats) {
        let pump = self
            .pump
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(Pump::stats)
            .unwrap_or(PumpStats {
                reads: 0,
                written: 0,
                dropped: 0,
                read_errors: 0,
                write_errors: 0,
            });
        (self.tunnel.stats(), pump)
    }

    /// True while the device and both pump threads are alive.
    pub fn running(&self) -> bool {
        if self.stopped.load(Ordering::SeqCst) {
            return false;
        }
        let running = self
            .pump
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(Pump::running)
            .unwrap_or(false);
        if !running {
            self.lost.store(true, Ordering::SeqCst);
        }
        running
    }

    /// True when the pump ended on its own (revoked device/permission).
    pub fn lost(&self) -> bool {
        self.lost.load(Ordering::SeqCst)
    }

    /// Reload the same configuration file. The TUN shape (device, addresses,
    /// routes) is fixed for this device lifetime; a changed `tun` block is a
    /// restart, which the host performs for the Rust engine.
    pub fn reload(&self) -> Result<Vec<String>, String> {
        self.tunnel.reload()
    }

    /// Stop the pump, the engine, remove this process's routes and close the
    /// device. Idempotent.
    pub fn stop(&self) {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(pump) = self
            .pump
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_mut()
        {
            pump.stop();
        }
        self.tunnel.stop();
        for command in &self.teardown {
            if let Err(error) = run_command(command) {
                tracing::debug!(command = %command.render(), %error, "desktop TUN teardown command failed");
            }
        }
        if self.bound_interface.is_some() {
            crate::outbound::set_default_interface(None);
        }
        tracing::info!(device = self.device.name(), "desktop TUN stopped");
    }
}

impl Drop for DesktopTun {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Run a plan's address and route commands; on any failure run the plan's
/// teardown before returning the named error.
pub fn apply_plan(
    plan: &RoutePlan,
    runner: &mut dyn FnMut(&Command) -> Result<(), String>,
) -> Result<(), String> {
    for command in plan.address.iter().chain(plan.up.iter()) {
        if let Err(error) = runner(command) {
            rollback_with(plan, runner);
            return Err(format!("desktop-tun: {}: {error}", command.render()));
        }
    }
    Ok(())
}

fn rollback(plan: &RoutePlan) {
    rollback_with(plan, &mut |command| run_command(command));
}

fn rollback_with(plan: &RoutePlan, runner: &mut dyn FnMut(&Command) -> Result<(), String>) {
    for command in &plan.down {
        if let Err(error) = runner(command) {
            tracing::debug!(command = %command.render(), %error, "desktop TUN rollback command failed");
        }
    }
}

fn run_command(command: &Command) -> Result<(), String> {
    run_capture(command).map(|_| ())
}

fn run_capture(command: &Command) -> Result<String, String> {
    let output = ProcessCommand::new(&command.program)
        .args(&command.args)
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    Err(if detail.is_empty() {
        format!("exit status {}", output.status)
    } else {
        detail.to_string()
    })
}

/// The pinned hijack set: configured `dns-hijack` plus the device DNS
/// addresses (`tun4+1:53`, `tun6+1:53`).
pub fn effective_dns_hijack(tun: &TunConfig, addresses: &route_plan::DeviceAddresses) -> Vec<SocketAddr> {
    let mut targets = tun.dns_hijack.clone();
    let (v4, v6) = addresses.dns_servers();
    for ip in [v4, v6].into_iter().flatten() {
        let target = SocketAddr::new(ip, 53);
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    targets
}

/// Refuse to overwrite an existing policy table/rule. Runs before the device
/// is created so a conflict cannot leave a half-installed TUN.
fn check_linux_precheck(tun: &TunConfig, ipv6: bool) -> Result<(), String> {
    let commands = route_plan::linux_precheck_commands(tun, ipv6);
    let rules = run_precheck_capture(&commands[0])?;
    let routes = run_precheck_capture(&commands[1])?;
    let rules = route_plan::linux_precheck_rule_result(rules.success, &rules.stdout, &rules.stderr)?;
    let routes = route_plan::linux_precheck_route_result(
        routes.success,
        &routes.stdout,
        &routes.stderr,
        tun.iproute2_table_index,
    )?;
    if let Some(conflict) = route_plan::linux_conflict(
        &rules,
        &routes,
        tun.iproute2_table_index,
        tun.iproute2_rule_index,
    ) {
        return Err(conflict);
    }
    if ipv6 {
        let rules6 = run_precheck_capture(&commands[2])?;
        let routes6 = run_precheck_capture(&commands[3])?;
        let rules6 = route_plan::linux_precheck_rule_result(rules6.success, &rules6.stdout, &rules6.stderr)?;
        let routes6 = route_plan::linux_precheck_route_result(
            routes6.success,
            &routes6.stdout,
            &routes6.stderr,
            tun.iproute2_table_index,
        )?;
        if let Some(conflict) = route_plan::linux_conflict(
            &rules6,
            &routes6,
            tun.iproute2_table_index,
            tun.iproute2_rule_index,
        ) {
            return Err(conflict);
        }
    }
    Ok(())
}

struct PrecheckCapture {
    success: bool,
    stdout: String,
    stderr: String,
}

/// Read-only precheck command: a spawn failure is wrapped, never a bare OS
/// error, so the host reports a named Linux precheck failure.
fn run_precheck_capture(command: &Command) -> Result<PrecheckCapture, String> {
    let output = ProcessCommand::new(&command.program)
        .args(&command.args)
        .output()
        .map_err(|error| {
            format!(
                "desktop-tun: Linux route precheck failed: {}: {error}",
                command.render()
            )
        })?;
    Ok(PrecheckCapture {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// Build the system-DNS command set for `dns-mode`. Capture commands (macOS
/// service lookup / saved servers, Windows saved servers) run here so the
/// generated teardown can restore the previous resolver configuration.
fn plan_dns(
    platform: Platform,
    device: &str,
    tun: &TunConfig,
    addresses: &route_plan::DeviceAddresses,
) -> Result<RoutePlan, String> {
    if !tun.dns_mode.touches_system_resolver() {
        return Ok(RoutePlan::default());
    }
    let (v4, v6) = addresses.dns_servers();
    if v4.is_none() && v6.is_none() {
        return Err("desktop-tun: dns-mode needs a usable TUN address + 1".to_string());
    }
    match platform {
        Platform::Linux => Ok(route_plan::plan_dns_linux(device, v4, v6)),
        Platform::Macos => {
            let Some(order) = command_output(
                "/usr/sbin/networksetup",
                &["-listnetworkserviceorder"],
            )
            .or_else(|| command_output("networksetup", &["-listnetworkserviceorder"]))
            else {
                tracing::warn!(
                    "desktop-tun: dns-mode cannot run `networksetup -listnetworkserviceorder`; the system resolver is left unchanged"
                );
                return Ok(RoutePlan::default());
            };
            let Some(service) = route_plan::parse_macos_service_order(&order, device) else {
                tracing::warn!(
                    device,
                    "desktop-tun: dns-mode found no networksetup service for this interface (utun interfaces have none); the system resolver is left unchanged"
                );
                return Ok(RoutePlan::default());
            };
            let saved = command_output("networksetup", &["-getdnsservers", service.as_str()])
                .map(|text| route_plan::parse_macos_dns_servers(&text))
                .unwrap_or_default();
            Ok(route_plan::plan_dns_macos(&service, &saved, v4, v6))
        }
        Platform::Windows => {
            let name = format!("name={device}");
            let saved4 = command_output(
                "netsh",
                &["interface", "ipv4", "show", "dnsservers", name.as_str()],
            )
            .map(|text| route_plan::parse_windows_dns_servers(&text))
            .unwrap_or_else(|| {
                tracing::warn!(
                    device,
                    "desktop-tun: dns-mode could not capture the previous Windows IPv4 DNS servers; restore falls back to DHCP"
                );
                Vec::new()
            });
            let saved6 = command_output(
                "netsh",
                &["interface", "ipv6", "show", "dnsservers", name.as_str()],
            )
            .map(|text| route_plan::parse_windows_dns_servers(&text))
            .unwrap_or_else(|| {
                tracing::warn!(
                    device,
                    "desktop-tun: dns-mode could not capture the previous Windows IPv6 DNS servers; restore falls back to DHCP"
                );
                Vec::new()
            });
            Ok(route_plan::plan_dns_windows(device, &saved4, &saved6, v4, v6))
        }
    }
}

/// Detect the physical default interface/gateway for `auto-detect-interface`.
pub fn detect_default_route(platform: Platform) -> Option<DefaultRoute> {    match platform {
        Platform::Macos => command_output("/sbin/route", &["-n", "get", "default"])
            .and_then(|text| route_plan::parse_macos_default(&text)),
        Platform::Linux => ["ip", "/sbin/ip", "/usr/sbin/ip"]
            .iter()
            .find_map(|program| {
                command_output(program, &["route", "show", "default"])
                    .and_then(|text| route_plan::parse_linux_default(&text))
            }),
        Platform::Windows => {
            let script = "$r=Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1; \
                          Write-Output ($r.InterfaceAlias + '|' + $r.NextHop)";
            command_output(
                "powershell",
                &["-NoProfile", "-NonInteractive", "-Command", script],
            )
            .and_then(|text| route_plan::parse_windows_default(&text))
        }
    }
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = ProcessCommand::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Validate the `tun` block without creating anything. `--check` uses this so a
/// configuration can be accepted on a host without root/administrator rights.
pub fn validate_only(config_yaml: &str, path: &str) -> Result<TunConfig, String> {
    let loaded = load_config(config_yaml, path).map_err(|error| error.to_string())?;
    Ok(loaded.config.tun)
}
