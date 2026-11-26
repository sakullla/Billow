//! Desktop TUN route/interface command planning.
//!
//! Everything here is a pure function over the parsed [`TunConfig`] and the
//! detected physical default route, so the command set a platform would run is
//! inspectable in tests without touching the host network. Execution lives in
//! [`super`]; a failed command rolls the already-applied set back through
//! [`RoutePlan::down`].
//!
//! Auto-route deliberately installs `0.0.0.0/1` + `128.0.0.0/1` (and the IPv6
//! halves) instead of replacing `0.0.0.0/0`, so stopping or crashing the kernel
//! cannot leave the machine without a default route.

use std::net::IpAddr;

use crate::config::TunConfig;

/// The device address the pinned desktop adapter assigns by default: the
/// `dns.fake-ip-range` gateway (`198.18.0.1`) narrowed to /30.
pub const TUN_IPV4: &str = "198.18.0.1/30";
/// The pinned default IPv6 device address.
pub const TUN_IPV6: &str = "fdfe:dcba:9876::1/126";

/// Host family the runner is executing on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Macos,
    Linux,
    Windows,
}

impl Platform {
    pub fn current() -> Option<Platform> {
        #[cfg(target_os = "macos")]
        {
            Some(Platform::Macos)
        }
        #[cfg(target_os = "linux")]
        {
            Some(Platform::Linux)
        }
        #[cfg(target_os = "windows")]
        {
            Some(Platform::Windows)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            None
        }
    }
}

/// One external command. Arguments are always a vector so no shell quoting or
/// interpolation is involved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub program: String,
    pub args: Vec<String>,
}

impl Command {
    pub fn new(program: impl Into<String>, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Command {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    /// Stable text for logs and failure messages.
    pub fn render(&self) -> String {
        let mut out = self.program.clone();
        for arg in &self.args {
            out.push(' ');
            if arg.contains(' ') {
                out.push('"');
                out.push_str(arg);
                out.push('"');
            } else {
                out.push_str(arg);
            }
        }
        out
    }
}

/// Physical default route detected for anti-loop binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    pub interface: String,
    pub gateway: Option<IpAddr>,
}

/// The address and route commands for one TUN lifetime.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutePlan {
    /// Assign the device addresses (and MTU).
    pub address: Vec<Command>,
    /// Install the split routes.
    pub up: Vec<Command>,
    /// Remove everything in reverse order. Safe to run after a partial apply.
    pub down: Vec<Command>,
}

pub fn plan(
    platform: Platform,
    device: &str,
    tun: &TunConfig,
    default: Option<&DefaultRoute>,
    mtu: usize,
) -> Result<RoutePlan, String> {
    if device.trim().is_empty() {
        return Err("desktop-tun: the device has no interface name".to_string());
    }
    if tun.strict_route && default.is_none() {
        return Err(
            "desktop-tun: tun.strict-route requires a detected physical default interface; \
             enable auto-detect-interface or provide a reachable default route"
                .to_string(),
        );
    }
    if !tun.route_exclude_address.is_empty() && default.and_then(|route| route.gateway).is_none() {
        return Err(
            "desktop-tun: tun.route-exclude-address needs the physical default gateway \
             (auto-detect-interface must find one)"
                .to_string(),
        );
    }
    if let (Some(default), Some(gateway)) = (default, default.and_then(|route| route.gateway)) {
        for prefix in &tun.route_exclude_address {
            if prefix.contains(':') != gateway.is_ipv6() {
                return Err(format!(
                    "desktop-tun: tun.route-exclude-address '{prefix}' needs a {}-family physical gateway, \
                     but the detected gateway is {gateway}",
                    if prefix.contains(':') { "IPv6" } else { "IPv4" }
                ));
            }
        }
        let _ = default;
    }
    let mut plan = RoutePlan::default();
    let mut down = Vec::new();
    match platform {
        Platform::Macos => plan_macos(&mut plan, &mut down, device, tun, default, mtu),
        Platform::Linux => plan_linux(&mut plan, &mut down, device, tun, default, mtu),
        Platform::Windows => plan_windows(&mut plan, &mut down, device, tun, default, mtu),
    }
    // Teardown is the reverse of setup: routes first, then addresses.
    down.reverse();
    plan.down = down;
    Ok(plan)
}

fn split_prefix(prefix: &str) -> (&str, bool) {
    (prefix, prefix.contains(':'))
}

fn plan_macos(
    plan: &mut RoutePlan,
    down: &mut Vec<Command>,
    device: &str,
    tun: &TunConfig,
    default: Option<&DefaultRoute>,
    mtu: usize,
) {
    const IFCONFIG: &str = "/sbin/ifconfig";
    const ROUTE: &str = "/sbin/route";
    plan.address.push(Command::new(
        IFCONFIG,
        [
            device,
            "inet",
            "198.18.0.1",
            "198.18.0.1",
            "netmask",
            "255.255.255.252",
            "up",
        ],
    ));
    plan.address.push(Command::new(
        IFCONFIG,
        [device, "inet6", TUN_IPV6, "up"],
    ));
    plan.address
        .push(Command::new(IFCONFIG, [device, "mtu", &mtu.to_string()]));
    // Addresses disappear with the utun descriptor; still record the commands
    // so an explicit stop has a deterministic teardown.
    down.push(Command::new(IFCONFIG, [device, "down"]));
    if tun.auto_route {
        for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
            plan.up.push(Command::new(
                ROUTE,
                ["-n", "add", "-inet", prefix, "-interface", device],
            ));
            down.push(Command::new(
                ROUTE,
                ["-n", "delete", "-inet", prefix, "-interface", device],
            ));
        }
        for prefix in ["::/1", "8000::/1"] {
            plan.up.push(Command::new(
                ROUTE,
                ["-n", "add", "-inet6", prefix, "-interface", device],
            ));
            down.push(Command::new(
                ROUTE,
                ["-n", "delete", "-inet6", prefix, "-interface", device],
            ));
        }
    }
    for prefix in &tun.route_address {
        let (prefix, _) = split_prefix(prefix);
        let family = if prefix.contains(':') { "-inet6" } else { "-inet" };
        plan.up
            .push(Command::new(ROUTE, ["-n", "add", family, prefix, "-interface", device]));
        down.push(Command::new(
            ROUTE,
            ["-n", "delete", family, prefix, "-interface", device],
        ));
    }
    for prefix in &tun.route_exclude_address {
        let Some(gateway) = default.and_then(|route| route.gateway) else {
            continue;
        };
        let (prefix, _) = split_prefix(prefix);
        let family = if prefix.contains(':') { "-inet6" } else { "-inet" };
        plan.up
            .push(Command::new(ROUTE, ["-n", "add", family, prefix, &gateway.to_string()]));
        down.push(Command::new(
            ROUTE,
            ["-n", "delete", family, prefix, &gateway.to_string()],
        ));
    }
}

fn plan_linux(
    plan: &mut RoutePlan,
    down: &mut Vec<Command>,
    device: &str,
    tun: &TunConfig,
    default: Option<&DefaultRoute>,
    mtu: usize,
) {
    const IP: &str = "ip";
    plan.address.push(Command::new(
        IP,
        ["addr", "add", TUN_IPV4, "dev", device],
    ));
    plan.address
        .push(Command::new(IP, ["-6", "addr", "add", TUN_IPV6, "dev", device]));
    plan.address.push(Command::new(
        IP,
        ["link", "set", "dev", device, "mtu", &mtu.to_string(), "up"],
    ));
    down.push(Command::new(IP, ["addr", "del", TUN_IPV4, "dev", device]));
    down.push(Command::new(IP, ["-6", "addr", "del", TUN_IPV6, "dev", device]));
    down.push(Command::new(IP, ["link", "set", "dev", device, "down"]));
    if tun.auto_route {
        for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
            plan.up
                .push(Command::new(IP, ["route", "add", prefix, "dev", device]));
            down.push(Command::new(IP, ["route", "del", prefix, "dev", device]));
        }
        for prefix in ["::/1", "8000::/1"] {
            plan.up
                .push(Command::new(IP, ["-6", "route", "add", prefix, "dev", device]));
            down.push(Command::new(IP, ["-6", "route", "del", prefix, "dev", device]));
        }
    }
    for prefix in &tun.route_address {
        let (prefix, v6) = split_prefix(prefix);
        let args: Vec<&str> = if v6 {
            vec!["-6", "route", "add", prefix, "dev", device]
        } else {
            vec!["route", "add", prefix, "dev", device]
        };
        plan.up.push(Command::new(IP, args.iter().copied()));
        let args: Vec<&str> = if v6 {
            vec!["-6", "route", "del", prefix, "dev", device]
        } else {
            vec!["route", "del", prefix, "dev", device]
        };
        down.push(Command::new(IP, args.iter().copied()));
    }
    for prefix in &tun.route_exclude_address {
        let Some(default) = default else { continue };
        let Some(gateway) = default.gateway else { continue };
        let (prefix, v6) = split_prefix(prefix);
        let gateway = gateway.to_string();
        let args: Vec<&str> = if v6 {
            vec!["-6", "route", "add", prefix, "via", &gateway, "dev", &default.interface]
        } else {
            vec!["route", "add", prefix, "via", &gateway, "dev", &default.interface]
        };
        plan.up.push(Command::new(IP, args.iter().copied()));
        let args: Vec<&str> = if v6 {
            vec!["-6", "route", "del", prefix, "via", &gateway, "dev", &default.interface]
        } else {
            vec!["route", "del", prefix, "via", &gateway, "dev", &default.interface]
        };
        down.push(Command::new(IP, args.iter().copied()));
    }
}

fn plan_windows(
    plan: &mut RoutePlan,
    down: &mut Vec<Command>,
    device: &str,
    tun: &TunConfig,
    default: Option<&DefaultRoute>,
    mtu: usize,
) {
    const NETSH: &str = "netsh";
    let name_arg = format!("name={device}");
    let mtu_arg = format!("mtu={mtu}");
    plan.address.push(Command::new(
        NETSH,
        [
            "interface",
            "ipv4",
            "set",
            "address",
            name_arg.as_str(),
            "static",
            "198.18.0.1",
            "255.255.255.252",
        ],
    ));
    plan.address.push(Command::new(
        NETSH,
        [
            "interface",
            "ipv6",
            "add",
            "address",
            device,
            TUN_IPV6,
        ],
    ));
    plan.address.push(Command::new(
        NETSH,
        [
            "interface",
            "ipv4",
            "set",
            "subinterface",
            device,
            mtu_arg.as_str(),
            "store=active",
        ],
    ));
    down.push(Command::new(
        NETSH,
        [
            "interface",
            "ipv6",
            "delete",
            "address",
            device,
            TUN_IPV6,
        ],
    ));
    down.push(Command::new(
        NETSH,
        [
            "interface",
            "ipv4",
            "delete",
            "address",
            name_arg.as_str(),
            "addr=198.18.0.1",
        ],
    ));
    if tun.auto_route {
        for (prefix, v6) in [
            ("0.0.0.0/1", false),
            ("128.0.0.0/1", false),
            ("::/1", true),
            ("8000::/1", true),
        ] {
            let family = if v6 { "ipv6" } else { "ipv4" };
            plan.up.push(Command::new(
                NETSH,
                ["interface", family, "add", "route", prefix, device],
            ));
            down.push(Command::new(
                NETSH,
                ["interface", family, "delete", "route", prefix, device],
            ));
        }
    }
    for prefix in &tun.route_address {
        let (prefix, v6) = split_prefix(prefix);
        let family = if v6 { "ipv6" } else { "ipv4" };
        plan.up.push(Command::new(
            NETSH,
            ["interface", family, "add", "route", prefix, device],
        ));
        down.push(Command::new(
            NETSH,
            ["interface", family, "delete", "route", prefix, device],
        ));
    }
    for prefix in &tun.route_exclude_address {
        let Some(default) = default else { continue };
        let Some(gateway) = default.gateway else { continue };
        let (prefix, v6) = split_prefix(prefix);
        let family = if v6 { "ipv6" } else { "ipv4" };
        let gateway = gateway.to_string();
        plan.up.push(Command::new(
            NETSH,
            [
                "interface",
                family,
                "add",
                "route",
                prefix,
                &default.interface,
                &gateway,
            ],
        ));
        down.push(Command::new(
            NETSH,
            [
                "interface",
                family,
                "delete",
                "route",
                prefix,
                &default.interface,
                &gateway,
            ],
        ));
    }
}

/// Parse `route -n get default` on macOS.
pub fn parse_macos_default(output: &str) -> Option<DefaultRoute> {
    let mut interface = None;
    let mut gateway = None;
    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else { continue };
        match key.trim() {
            "interface" => interface = Some(value.trim().to_string()),
            "gateway" => gateway = value.trim().parse::<IpAddr>().ok(),
            _ => {}
        }
    }
    let interface = interface.filter(|name| !name.is_empty())?;
    Some(DefaultRoute { interface, gateway })
}

/// Parse `ip route show default` on Linux.
pub fn parse_linux_default(output: &str) -> Option<DefaultRoute> {
    let line = output
        .lines()
        .find(|line| line.trim_start().starts_with("default"))?;
    let mut words = line.split_whitespace();
    let mut gateway = None;
    let mut interface = None;
    while let Some(word) = words.next() {
        match word {
            "via" => gateway = words.next().and_then(|value| value.parse::<IpAddr>().ok()),
            "dev" => interface = words.next().map(str::to_string),
            _ => {}
        }
    }
    let interface = interface.filter(|name| !name.is_empty())?;
    Some(DefaultRoute { interface, gateway })
}

/// Parse the PowerShell default-route probe on Windows. The probe emits
/// `alias|gateway`; a two-line `route print` style answer is accepted too.
pub fn parse_windows_default(output: &str) -> Option<DefaultRoute> {
    let mut lines = output.lines().map(str::trim).filter(|line| !line.is_empty());
    let first = lines.next()?;
    let (interface, gateway) = match first.split_once('|') {
        Some((interface, gateway)) => (interface.trim(), gateway.trim()),
        None => (first, lines.next().unwrap_or("")),
    };
    if interface.is_empty() || interface.eq_ignore_ascii_case("alias") {
        return None;
    }
    Some(DefaultRoute {
        interface: interface.to_string(),
        gateway: gateway.parse::<IpAddr>().ok(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> TunConfig {
        TunConfig {
            enable: true,
            auto_detect_interface: true,
            ..TunConfig::default()
        }
    }

    fn route() -> DefaultRoute {
        DefaultRoute {
            interface: "en0".to_string(),
            gateway: Some("192.168.1.1".parse().unwrap()),
        }
    }

    fn rendered(commands: &[Command]) -> Vec<String> {
        commands.iter().map(Command::render).collect()
    }

    #[test]
    fn macos_plans_split_defaults_and_teardown() {
        let plan = plan(Platform::Macos, "utun7", &base(), Some(&route()), 1400).unwrap();
        let up = rendered(&plan.up);
        assert!(up.contains(&"/sbin/route -n add -inet 0.0.0.0/1 -interface utun7".to_string()), "{up:?}");
        assert!(up.contains(&"/sbin/route -n add -inet 128.0.0.0/1 -interface utun7".to_string()));
        assert!(up.contains(&"/sbin/route -n add -inet6 ::/1 -interface utun7".to_string()));
        assert!(up.contains(&"/sbin/route -n add -inet6 8000::/1 -interface utun7".to_string()));
        assert!(rendered(&plan.address)
            .contains(&"/sbin/ifconfig utun7 inet6 fdfe:dcba:9876::1/126 up".to_string()));
        assert!(rendered(&plan.address).contains(&"/sbin/ifconfig utun7 mtu 1400".to_string()));
        let down = rendered(&plan.down);
        assert!(down.iter().any(|line| line.contains("delete -inet 0.0.0.0/1")));
        assert_eq!(down.last().unwrap(), "/sbin/ifconfig utun7 down");
    }

    #[test]
    fn linux_plans_routes_and_exclusions() {
        let mut tun = base();
        tun.route_address = vec!["10.0.0.0/8".to_string()];
        tun.route_exclude_address = vec!["192.168.0.0/16".to_string()];
        let plan = plan(Platform::Linux, "billow0", &tun, Some(&route()), 1500).unwrap();
        let up = rendered(&plan.up);
        assert!(up.contains(&"ip route add 0.0.0.0/1 dev billow0".to_string()), "{up:?}");
        assert!(up.contains(&"ip -6 route add 8000::/1 dev billow0".to_string()));
        assert!(up.contains(&"ip route add 10.0.0.0/8 dev billow0".to_string()));
        assert!(up.contains(&"ip route add 192.168.0.0/16 via 192.168.1.1 dev en0".to_string()));
        assert!(rendered(&plan.address).contains(&"ip addr add 198.18.0.1/30 dev billow0".to_string()));
        assert!(rendered(&plan.down).iter().any(|line| line.contains("route del 0.0.0.0/1")));
    }

    #[test]
    fn windows_plans_netsh_commands() {
        let plan = plan(Platform::Windows, "Billow", &base(), Some(&route()), 1500).unwrap();
        let up = rendered(&plan.up);
        assert!(up.contains(&"netsh interface ipv4 add route 0.0.0.0/1 Billow".to_string()), "{up:?}");
        assert!(up.contains(&"netsh interface ipv6 add route 8000::/1 Billow".to_string()));
        assert!(rendered(&plan.address)
            .contains(&"netsh interface ipv4 set address name=Billow static 198.18.0.1 255.255.255.252".to_string()));
    }

    #[test]
    fn auto_route_false_leaves_the_default_route_alone() {
        let mut tun = base();
        tun.auto_route = false;
        let plan = plan(Platform::Linux, "billow0", &tun, Some(&route()), 1500).unwrap();
        assert!(plan.up.is_empty());
    }

    #[test]
    fn strict_route_or_exclusions_without_a_gateway_fail_by_name() {
        let mut tun = base();
        tun.strict_route = true;
        let error = plan(Platform::Linux, "billow0", &tun, None, 1500).unwrap_err();
        assert!(error.contains("strict-route"), "{error}");
        let mut tun = base();
        tun.route_exclude_address = vec!["192.168.0.0/16".to_string()];
        let no_gateway = DefaultRoute {
            interface: "en0".to_string(),
            gateway: None,
        };
        let error = plan(Platform::Linux, "billow0", &tun, Some(&no_gateway), 1500).unwrap_err();
        assert!(error.contains("route-exclude-address"), "{error}");
    }

    #[test]
    fn default_route_parsers() {
        let mac = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n";
        assert_eq!(
            parse_macos_default(mac),
            Some(DefaultRoute {
                interface: "en0".to_string(),
                gateway: Some("192.168.1.1".parse().unwrap())
            })
        );
        let linux = "default via 192.168.1.1 dev en0 proto dhcp src 192.168.1.2 metric 100\n";
        assert_eq!(
            parse_linux_default(linux),
            Some(DefaultRoute {
                interface: "en0".to_string(),
                gateway: Some("192.168.1.1".parse().unwrap())
            })
        );
        assert_eq!(
            parse_linux_default("default dev wg0 scope link\n"),
            Some(DefaultRoute {
                interface: "wg0".to_string(),
                gateway: None
            })
        );
        assert_eq!(
            parse_windows_default("Wi-Fi\r\n192.168.1.1\r\n"),
            Some(DefaultRoute {
                interface: "Wi-Fi".to_string(),
                gateway: Some("192.168.1.1".parse().unwrap())
            })
        );
        assert_eq!(parse_macos_default("garbage"), None);
    }
}
