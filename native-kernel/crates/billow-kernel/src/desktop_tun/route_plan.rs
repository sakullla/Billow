//! Desktop TUN route/interface command planning.
//!
//! Everything here is a pure function over the parsed [`TunConfig`], the device
//! addresses and the detected physical default route, so the command set a
//! platform would run is inspectable in tests without touching the host
//! network. Execution lives in [`super`]; a failed command rolls the
//! already-applied set back through [`RoutePlan::down`].
//!
//! Route ranges follow pinned `sing-tun` `BuildAutoRouteRanges`:
//! * a non-empty `route-address` installs **only** those prefixes (macOS also
//!   adds the device prefix itself);
//! * otherwise the platform auto range is installed (macOS uses the sub-ranges
//!   that leave `0.0.0.0/8`/`::/8` local; Linux/Windows use the full default);
//! * `route-exclude-address` is a set difference over those ranges, not a
//!   separate route via the physical gateway.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::ipnet_like::IpNet;
use crate::config::{Config, TunConfig};

/// Physical default route detected for anti-loop binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    pub interface: String,
    pub gateway: Option<IpAddr>,
}

/// Device addresses assigned to the TUN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAddresses {
    pub v4: IpNet,
    pub v6: Vec<IpNet>,
}

impl DeviceAddresses {
    /// The pinned TUN address: the `dns.fake-ip-range` address narrowed to /30.
    pub fn from_config(config: &Config) -> DeviceAddresses {
        let range = config
            .dns
            .fake_ip_range
            .unwrap_or_else(|| "198.18.0.1/16".parse().expect("pinned default fake-ip range"));
        let v4 = IpNet::new(range.network(), 30)
            .unwrap_or_else(|_| "198.18.0.1/30".parse().expect("pinned default tun address"));
        let v6 = if config.ipv6 {
            config
                .tun
                .inet6_address
                .iter()
                .filter_map(|prefix| prefix.parse::<IpNet>().ok())
                .collect()
        } else {
            Vec::new()
        };
        DeviceAddresses { v4, v6 }
    }

    /// `tun4+1` and `tun6+1`, the addresses pinned `DNSServerAddress` hands to
    /// the system resolver.
    pub fn dns_servers(&self) -> (Option<IpAddr>, Option<IpAddr>) {
        let v4 = next_address(self.v4.network());
        let v6 = self.v6.first().and_then(|prefix| next_address(prefix.network()));
        (v4, v6)
    }
}

pub fn next_address(address: IpAddr) -> Option<IpAddr> {
    match address {
        IpAddr::V4(addr) => Some(IpAddr::V4(Ipv4Addr::from(u32::from(addr).checked_add(1)?))),
        IpAddr::V6(addr) => Some(IpAddr::V6(Ipv6Addr::from(u128::from(addr).checked_add(1)?))),
    }
}

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

/// The address, route and DNS commands for one TUN lifetime.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutePlan {
    /// Assign the device addresses (and MTU).
    pub address: Vec<Command>,
    /// Install the split routes and any DNS settings.
    pub up: Vec<Command>,
    /// Remove everything in reverse order. Safe to run after a partial apply.
    pub down: Vec<Command>,
}

pub fn plan(
    platform: Platform,
    device: &str,
    tun: &TunConfig,
    addresses: &DeviceAddresses,
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
    let mut plan = RoutePlan::default();
    let mut down = Vec::new();
    match platform {
        Platform::Macos => plan_addresses_macos(&mut plan, &mut down, device, tun, addresses, mtu),
        Platform::Linux => plan_addresses_linux(&mut plan, &mut down, device, tun, addresses, mtu),
        Platform::Windows => plan_addresses_windows(&mut plan, &mut down, device, tun, addresses, mtu),
    }
    if tun.auto_route {
        let mut v4 = route_ranges(&tun.route_address, false);
        let mut v6 = if addresses.v6.is_empty() {
            Vec::new()
        } else {
            route_ranges(&tun.route_address, true)
        };
        let v4_route_nonnempty = !v4.is_empty();
        let v6_route_nonempty = !v6.is_empty();
        if v4.is_empty() {
            v4 = auto_ranges(platform, false);
        } else if platform == Platform::Macos && v4_route_nonnempty {
            // Pinned darwin adds the TUN subnet itself so the interface address
            // is reachable through the device.
            push_unique(&mut v4, addresses.v4.masked().to_string());
        }
        if !addresses.v6.is_empty() {
            if v6.is_empty() {
                v6 = auto_ranges(platform, true);
            } else if platform == Platform::Macos && v6_route_nonempty {
                for prefix in &addresses.v6 {
                    push_unique(&mut v6, prefix.masked().to_string());
                }
            }
        }
        let v4_excludes = route_ranges(&tun.route_exclude_address, false);
        let v6_excludes = route_ranges(&tun.route_exclude_address, true);
        v4 = subtract_prefixes(&v4, &v4_excludes);
        v6 = subtract_prefixes(&v6, &v6_excludes);
        match platform {
            Platform::Macos => plan_routes_macos(&mut plan, &mut down, device, &v4, &v6),
            Platform::Linux => plan_routes_linux(
                &mut plan,
                &mut down,
                device,
                &v4,
                &v6,
                tun.iproute2_table_index,
                tun.iproute2_rule_index,
            ),
            Platform::Windows => plan_routes_windows(&mut plan, &mut down, device, &v4, &v6),
        }
    }
    down.reverse();
    plan.down = down;
    Ok(plan)
}

fn push_unique(list: &mut Vec<String>, value: String) {
    if !list.contains(&value) {
        list.push(value);
    }
}

fn route_ranges(prefixes: &[String], ipv6: bool) -> Vec<String> {
    prefixes
        .iter()
        .filter(|prefix| prefix.contains(':') == ipv6)
        .cloned()
        .collect()
}

/// Pinned `BuildAutoRouteRanges` per platform.
pub fn auto_ranges(platform: Platform, ipv6: bool) -> Vec<String> {
    match (platform, ipv6) {
        (Platform::Macos, false) => vec![
            "1.0.0.0/8".to_string(),
            "2.0.0.0/7".to_string(),
            "4.0.0.0/6".to_string(),
            "8.0.0.0/5".to_string(),
            "16.0.0.0/4".to_string(),
            "32.0.0.0/3".to_string(),
            "64.0.0.0/2".to_string(),
            "128.0.0.0/1".to_string(),
        ],
        (Platform::Macos, true) => vec![
            "100::/8".to_string(),
            "200::/7".to_string(),
            "400::/6".to_string(),
            "800::/5".to_string(),
            "1000::/4".to_string(),
            "2000::/3".to_string(),
            "4000::/2".to_string(),
            "8000::/1".to_string(),
        ],
        (_, false) => vec!["0.0.0.0/0".to_string()],
        (_, true) => vec!["::/0".to_string()],
    }
}

fn plan_addresses_macos(
    plan: &mut RoutePlan,
    down: &mut Vec<Command>,
    device: &str,
    _tun: &TunConfig,
    addresses: &DeviceAddresses,
    mtu: usize,
) {
    const IFCONFIG: &str = "/sbin/ifconfig";
    let v4 = &addresses.v4;
    let v4_addr = v4.network().to_string();
    let v4_mask = mask_string(v4);
    plan.address.push(Command::new(
        IFCONFIG,
        [
            device,
            "inet",
            v4_addr.as_str(),
            v4_addr.as_str(),
            "netmask",
            v4_mask.as_str(),
            "up",
        ],
    ));
    for v6 in &addresses.v6 {
        let prefix = v6.to_string();
        plan.address
            .push(Command::new(IFCONFIG, [device, "inet6", prefix.as_str(), "up"]));
    }
    plan.address
        .push(Command::new(IFCONFIG, [device, "mtu", &mtu.to_string()]));
    down.push(Command::new(IFCONFIG, [device, "down"]));
}

fn plan_addresses_linux(
    plan: &mut RoutePlan,
    down: &mut Vec<Command>,
    device: &str,
    _tun: &TunConfig,
    addresses: &DeviceAddresses,
    mtu: usize,
) {
    const IP: &str = "ip";
    plan.address.push(Command::new(
        IP,
        ["addr", "add", &addresses.v4.to_string(), "dev", device],
    ));
    for v6 in &addresses.v6 {
        let prefix = v6.to_string();
        plan.address
            .push(Command::new(IP, ["-6", "addr", "add", prefix.as_str(), "dev", device]));
    }
    plan.address.push(Command::new(
        IP,
        ["link", "set", "dev", device, "mtu", &mtu.to_string(), "up"],
    ));
    down.push(Command::new(
        IP,
        ["addr", "del", &addresses.v4.to_string(), "dev", device],
    ));
    for v6 in &addresses.v6 {
        let prefix = v6.to_string();
        down.push(Command::new(
            IP,
            ["-6", "addr", "del", prefix.as_str(), "dev", device],
        ));
    }
    down.push(Command::new(IP, ["link", "set", "dev", device, "down"]));
}

fn plan_addresses_windows(
    plan: &mut RoutePlan,
    down: &mut Vec<Command>,
    device: &str,
    _tun: &TunConfig,
    addresses: &DeviceAddresses,
    mtu: usize,
) {
    const NETSH: &str = "netsh";
    let name_arg = format!("name={device}");
    let mtu_arg = format!("mtu={mtu}");
    let v4 = &addresses.v4;
    let v4_addr = v4.network().to_string();
    let v4_mask = mask_string(v4);
    plan.address.push(Command::new(
        NETSH,
        [
            "interface",
            "ipv4",
            "set",
            "address",
            name_arg.as_str(),
            "static",
            v4_addr.as_str(),
            v4_mask.as_str(),
        ],
    ));
    for v6 in &addresses.v6 {
        let prefix = v6.to_string();
        plan.address.push(Command::new(
            NETSH,
            ["interface", "ipv6", "add", "address", device, prefix.as_str()],
        ));
    }
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
    plan.address.push(Command::new(
        NETSH,
        ["interface", "ipv4", "set", "interface", device, "metric=0"],
    ));
    plan.address.push(Command::new(
        NETSH,
        ["interface", "ipv6", "set", "interface", device, "metric=0"],
    ));
    down.push(Command::new(
        NETSH,
        ["interface", "ipv6", "set", "interface", device, "metric=automatic"],
    ));
    down.push(Command::new(
        NETSH,
        ["interface", "ipv4", "set", "interface", device, "metric=automatic"],
    ));
    for v6 in &addresses.v6 {
        let prefix = v6.to_string();
        down.push(Command::new(
            NETSH,
            ["interface", "ipv6", "delete", "address", device, prefix.as_str()],
        ));
    }
    let delete_addr = format!("addr={v4_addr}");
    down.push(Command::new(
        NETSH,
        [
            "interface",
            "ipv4",
            "delete",
            "address",
            name_arg.as_str(),
            delete_addr.as_str(),
        ],
    ));
}

fn plan_routes_macos(
    plan: &mut RoutePlan,
    down: &mut Vec<Command>,
    device: &str,
    v4: &[String],
    v6: &[String],
) {
    const ROUTE: &str = "/sbin/route";
    for prefix in v4 {
        plan.up.push(Command::new(
            ROUTE,
            ["-n", "add", "-inet", prefix, "-interface", device],
        ));
        down.push(Command::new(
            ROUTE,
            ["-n", "delete", "-inet", prefix, "-interface", device],
        ));
    }
    for prefix in v6 {
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

fn plan_routes_linux(
    plan: &mut RoutePlan,
    down: &mut Vec<Command>,
    device: &str,
    v4: &[String],
    v6: &[String],
    table: u32,
    rule: u32,
) {
    const IP: &str = "ip";
    let table = table.to_string();
    let rule = rule.to_string();
    for prefix in v4 {
        plan.up.push(Command::new(
            IP,
            ["route", "add", prefix, "dev", device, "table", table.as_str()],
        ));
        down.push(Command::new(
            IP,
            ["route", "del", prefix, "dev", device, "table", table.as_str()],
        ));
    }
    for prefix in v6 {
        plan.up.push(Command::new(
            IP,
            ["-6", "route", "add", prefix, "dev", device, "table", table.as_str()],
        ));
        down.push(Command::new(
            IP,
            ["-6", "route", "del", prefix, "dev", device, "table", table.as_str()],
        ));
    }
    if !v4.is_empty() {
        plan.up.push(Command::new(
            IP,
            ["rule", "add", "priority", rule.as_str(), "lookup", table.as_str()],
        ));
        down.push(Command::new(
            IP,
            ["rule", "del", "priority", rule.as_str(), "lookup", table.as_str()],
        ));
    }
    if !v6.is_empty() {
        plan.up.push(Command::new(
            IP,
            ["-6", "rule", "add", "priority", rule.as_str(), "lookup", table.as_str()],
        ));
        down.push(Command::new(
            IP,
            ["-6", "rule", "del", "priority", rule.as_str(), "lookup", table.as_str()],
        ));
    }
}

fn plan_routes_windows(
    plan: &mut RoutePlan,
    down: &mut Vec<Command>,
    device: &str,
    v4: &[String],
    v6: &[String],
) {
    const NETSH: &str = "netsh";
    for prefix in v4 {
        let prefix_arg = format!("prefix={prefix}");
        let interface_arg = format!("interface={device}");
        plan.up.push(Command::new(
            NETSH,
            [
                "interface",
                "ipv4",
                "add",
                "route",
                prefix_arg.as_str(),
                interface_arg.as_str(),
                "metric=0",
            ],
        ));
        down.push(Command::new(
            NETSH,
            [
                "interface",
                "ipv4",
                "delete",
                "route",
                prefix_arg.as_str(),
                interface_arg.as_str(),
            ],
        ));
    }
    for prefix in v6 {
        let prefix_arg = format!("prefix={prefix}");
        let interface_arg = format!("interface={device}");
        plan.up.push(Command::new(
            NETSH,
            [
                "interface",
                "ipv6",
                "add",
                "route",
                prefix_arg.as_str(),
                interface_arg.as_str(),
                "metric=0",
            ],
        ));
        down.push(Command::new(
            NETSH,
            [
                "interface",
                "ipv6",
                "delete",
                "route",
                prefix_arg.as_str(),
                interface_arg.as_str(),
            ],
        ));
    }
}

fn mask_string(prefix: &IpNet) -> String {
    match prefix.network() {
        IpAddr::V4(_) => {
            let bits = prefix.prefix();
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            Ipv4Addr::from(mask).to_string()
        }
        IpAddr::V6(_) => format!("/{}", prefix.prefix()),
    }
}

/// Subtract every exclude prefix from every range and return minimal CIDRs.
pub fn subtract_prefixes(ranges: &[String], excludes: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for range in ranges {
        let Ok(prefix) = range.parse::<IpNet>() else {
            continue;
        };
        let mut pieces = vec![prefix_range(&prefix)];
        for exclude in excludes {
            let Ok(exclude) = exclude.parse::<IpNet>() else {
                continue;
            };
            let exclude = prefix_range(&exclude);
            let mut next = Vec::new();
            for piece in pieces {
                subtract_range(piece, exclude, &mut next);
            }
            pieces = next;
            if pieces.is_empty() {
                break;
            }
        }
        for piece in pieces {
            out.extend(range_to_prefixes(piece));
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntRange {
    V4(u32, u32),
    V6(u128, u128),
}

fn prefix_range(prefix: &IpNet) -> IntRange {
    match prefix.network() {
        IpAddr::V4(addr) => {
            let bits = prefix.prefix();
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            let start = u32::from(addr) & mask;
            let end = start | !mask;
            IntRange::V4(start, end)
        }
        IpAddr::V6(addr) => {
            let bits = prefix.prefix();
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            let start = u128::from(addr) & mask;
            let end = start | !mask;
            IntRange::V6(start, end)
        }
    }
}

fn subtract_range(range: IntRange, exclude: IntRange, out: &mut Vec<IntRange>) {
    match (range, exclude) {
        (IntRange::V4(start, end), IntRange::V4(x_start, x_end)) => {
            if x_end < start || x_start > end {
                out.push(range);
            } else {
                if start < x_start {
                    out.push(IntRange::V4(start, x_start - 1));
                }
                if x_end < end {
                    out.push(IntRange::V4(x_end + 1, end));
                }
            }
        }
        (IntRange::V6(start, end), IntRange::V6(x_start, x_end)) => {
            if x_end < start || x_start > end {
                out.push(range);
            } else {
                if start < x_start {
                    out.push(IntRange::V6(start, x_start - 1));
                }
                if x_end < end {
                    out.push(IntRange::V6(x_end + 1, end));
                }
            }
        }
        _ => out.push(range),
    }
}

fn range_to_prefixes(range: IntRange) -> Vec<String> {
    match range {
        IntRange::V4(start, end) => prefixes_v4(start, end),
        IntRange::V6(start, end) => prefixes_v6(start, end),
    }
}

fn prefixes_v4(mut start: u32, end: u32) -> Vec<String> {
    let mut out = Vec::new();
    while start <= end {
        let block_bits = if start == 0 {
            32
        } else {
            start.trailing_zeros().min(32)
        };
        let remaining = u64::from(end - start) + 1;
        let mut size = block_bits;
        while size > 0 && (1u64 << size) > remaining {
            size -= 1;
        }
        let prefix = 32 - size;
        out.push(format!("{}/{}", Ipv4Addr::from(start), prefix));
        let step = 1u64 << size;
        match u64::from(start).checked_add(step) {
            Some(next) if next <= u64::from(u32::MAX) => start = next as u32,
            _ => break,
        }
    }
    out
}

fn prefixes_v6(mut start: u128, end: u128) -> Vec<String> {
    let mut out = Vec::new();
    if start == 0 && end == u128::MAX {
        out.push("::/0".to_string());
        return out;
    }
    while start <= end {
        let block_bits = if start == 0 {
            128
        } else {
            start.trailing_zeros().min(128)
        };
        let remaining = end.saturating_sub(start).saturating_add(1);
        let max_bits = if remaining == 0 {
            0
        } else {
            127 - remaining.leading_zeros()
        };
        let size = block_bits.min(max_bits);
        let prefix = 128 - size;
        out.push(format!("{}/{}", Ipv6Addr::from(start), prefix));
        if size == 128 {
            break;
        }
        let step = 1u128 << size;
        match start.checked_add(step) {
            Some(next) => start = next,
            None => break,
        }
    }
    out
}

/// Read-only precheck commands for the Linux policy-routing table/rule.
pub fn linux_precheck_commands(tun: &TunConfig, ipv6: bool) -> Vec<Command> {
    let table = tun.iproute2_table_index.to_string();
    let mut commands = vec![
        Command::new("ip", ["rule", "show"]),
        Command::new("ip", ["route", "show", "table", table.as_str()]),
    ];
    if ipv6 {
        commands.push(Command::new("ip", ["-6", "rule", "show"]));
        commands.push(Command::new("ip", ["-6", "route", "show", "table", table.as_str()]));
    }
    commands
}

/// Name a pre-existing table/priority conflict instead of overwriting it.
pub fn linux_conflict(
    rules: &str,
    routes: &str,
    table: u32,
    rule: u32,
) -> Option<String> {
    let table_text = table.to_string();
    let rule_prefix = format!("{rule}:");
    for line in rules.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if line.starts_with(&rule_prefix)
            || line.contains(&format!("priority {rule} "))
            || line.contains(&format!("lookup {table_text}"))
        {
            return Some(format!(
                "desktop-tun: Linux policy rule priority {rule} or lookup table {table} is already in use; refusing to overwrite it"
            ));
        }
    }
    if !routes.trim().is_empty() {
        return Some(format!(
            "desktop-tun: Linux routing table {table} already has routes; refusing to overwrite it"
        ));
    }
    None
}

/// Linux systemd-resolved DNS commands.
pub fn plan_dns_linux(device: &str, v4: Option<IpAddr>, v6: Option<IpAddr>) -> RoutePlan {
    let mut servers = Vec::new();
    if let Some(v4) = v4 {
        servers.push(v4.to_string());
    }
    if let Some(v6) = v6 {
        servers.push(v6.to_string());
    }
    if servers.is_empty() {
        return RoutePlan::default();
    }
    let mut plan = RoutePlan::default();
    let mut args = vec!["dns".to_string(), device.to_string()];
    args.extend(servers);
    plan.up.push(Command::new("resolvectl", args));
    plan.up.push(Command::new(
        "resolvectl",
        ["domain", device, "~."],
    ));
    plan.up.push(Command::new(
        "resolvectl",
        ["default-route", device, "true"],
    ));
    plan.down
        .push(Command::new("resolvectl", ["revert", device]));
    plan
}

/// macOS `networksetup` DNS commands. `saved` is the `-getdnsservers` output
/// parsed before the change (empty means "no explicit servers").
pub fn plan_dns_macos(
    service: &str,
    saved: &[String],
    v4: Option<IpAddr>,
    v6: Option<IpAddr>,
) -> RoutePlan {
    let mut plan = RoutePlan::default();
    let mut servers = Vec::new();
    if let Some(v4) = v4 {
        servers.push(v4.to_string());
    }
    if let Some(v6) = v6 {
        servers.push(v6.to_string());
    }
    if servers.is_empty() {
        return plan;
    }
    let mut args = vec!["-setdnsservers".to_string(), service.to_string()];
    args.extend(servers);
    plan.up.push(Command::new("networksetup", args));
    let mut restore = vec!["-setdnsservers".to_string(), service.to_string()];
    if saved.is_empty() {
        restore.push("Empty".to_string());
    } else {
        restore.extend(saved.iter().cloned());
    }
    plan.down.push(Command::new("networksetup", restore));
    plan
}

/// Windows `netsh` DNS commands; `saved4`/`saved6` are the previously
/// configured static servers (empty means DHCP).
pub fn plan_dns_windows(
    device: &str,
    saved4: &[String],
    saved6: &[String],
    v4: Option<IpAddr>,
    v6: Option<IpAddr>,
) -> RoutePlan {
    let mut plan = RoutePlan::default();
    if let Some(v4) = v4 {
        plan.up.push(Command::new(
            "netsh",
            [
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                &format!("name={device}"),
                "static",
                &v4.to_string(),
                "primary",
            ],
        ));
        plan.down.push(restore_windows_dns(device, "ipv4", saved4));
    }
    if let Some(v6) = v6 {
        plan.up.push(Command::new(
            "netsh",
            [
                "interface",
                "ipv6",
                "set",
                "dnsservers",
                &format!("name={device}"),
                "static",
                &v6.to_string(),
                "primary",
            ],
        ));
        plan.down.push(restore_windows_dns(device, "ipv6", saved6));
    }
    plan
}

fn restore_windows_dns(device: &str, family: &str, saved: &[String]) -> Command {
    let name = format!("name={device}");
    match saved.first() {
        Some(server) => Command::new(
            "netsh",
            [
                "interface",
                family,
                "set",
                "dnsservers",
                name.as_str(),
                "static",
                server,
                "primary",
            ],
        ),
        None => Command::new(
            "netsh",
            [
                "interface",
                family,
                "set",
                "dnsservers",
                name.as_str(),
                "dhcp",
            ],
        ),
    }
}

/// Parse `networksetup -listnetworkserviceorder` for the service owning
/// `device`.
pub fn parse_macos_service_order(output: &str, device: &str) -> Option<String> {
    let mut current: Option<String> = None;
    for line in output.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix('(') {
            if let Some((_index, name)) = rest.split_once(") ") {
                current = Some(name.trim().to_string());
            }
        }
        if let Some(rest) = line.strip_prefix("(Hardware Port:") {
            if let Some((_port, tail)) = rest.split_once("Device: ") {
                if tail.trim().trim_end_matches(')').trim() == device {
                    return current;
                }
            }
        }
    }
    None
}

/// Parse `networksetup -getdnsservers`; the "There aren't any" line is empty.
pub fn parse_macos_dns_servers(output: &str) -> Vec<String> {
    let mut servers = Vec::new();
    for line in output.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if line.starts_with("There aren") {
            continue;
        }
        servers.push(line.to_string());
    }
    servers
}

/// Parse the `netsh interface ipvX show dnsservers` static list.
pub fn parse_windows_dns_servers(output: &str) -> Vec<String> {
    let mut servers = Vec::new();
    let mut in_static = false;
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("Statically Configured DNS Servers") {
            in_static = true;
            if let Some((_, rest)) = line.split_once(':') {
                let rest = rest.trim();
                if let Ok(addr) = rest.parse::<IpAddr>() {
                    servers.push(addr.to_string());
                }
            }
            continue;
        }
        if in_static {
            if line.is_empty() || line.contains(':') {
                in_static = false;
                continue;
            }
            if let Ok(addr) = line.parse::<IpAddr>() {
                servers.push(addr.to_string());
            }
        }
    }
    servers
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

    fn addresses() -> DeviceAddresses {
        DeviceAddresses {
            v4: "198.18.0.1/30".parse().unwrap(),
            v6: vec!["fdfe:dcba:9876::1/126".parse().unwrap()],
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
    fn macos_auto_ranges_use_pinned_subranges() {
        let plan = plan(Platform::Macos, "utun7", &base(), &addresses(), Some(&route()), 1400).unwrap();
        let up = rendered(&plan.up);
        assert!(up.contains(&"/sbin/route -n add -inet 1.0.0.0/8 -interface utun7".to_string()), "{up:?}");
        assert!(up.contains(&"/sbin/route -n add -inet 128.0.0.0/1 -interface utun7".to_string()));
        assert!(up.contains(&"/sbin/route -n add -inet6 8000::/1 -interface utun7".to_string()));
        assert!(!up.iter().any(|line| line.contains("0.0.0.0/8 ")), "{up:?}");
        assert!(!up.iter().any(|line| line.contains("0.0.0.0/1 ")), "{up:?}");
        assert!(rendered(&plan.address)
            .contains(&"/sbin/ifconfig utun7 inet6 fdfe:dcba:9876::1/126 up".to_string()));
        assert!(rendered(&plan.address)
            .contains(&"/sbin/ifconfig utun7 inet 198.18.0.1 198.18.0.1 netmask 255.255.255.252 up".to_string()));
    }

    #[test]
    fn route_address_replaces_auto_ranges() {
        let mut tun = base();
        tun.route_address = vec!["10.0.0.0/8".to_string()];
        let mac = plan(Platform::Macos, "utun7", &tun, &addresses(), Some(&route()), 1500).unwrap();
        let up = rendered(&mac.up);
        assert!(up.contains(&"/sbin/route -n add -inet 10.0.0.0/8 -interface utun7".to_string()), "{up:?}");
        assert!(up.contains(&"/sbin/route -n add -inet 198.18.0.0/30 -interface utun7".to_string()), "{up:?}");
        assert!(!up.iter().any(|line| line.contains("1.0.0.0/8")), "{up:?}");
        let linux = plan(Platform::Linux, "billow0", &tun, &addresses(), Some(&route()), 1500).unwrap();
        let up = rendered(&linux.up);
        assert_eq!(
            up,
            vec![
                "ip route add 10.0.0.0/8 dev billow0 table 2022",
                "ip -6 route add ::/0 dev billow0 table 2022",
                "ip rule add priority 9000 lookup 2022",
                "ip -6 rule add priority 9000 lookup 2022",
            ]
        );
    }

    #[test]
    fn exclude_addresses_are_subtracted_from_the_ranges() {
        let mut tun = base();
        tun.route_exclude_address = vec!["192.168.0.0/16".to_string()];
        let plan = plan(Platform::Linux, "billow0", &tun, &addresses(), Some(&route()), 1500).unwrap();
        let up = rendered(&plan.up);
        assert!(!up.iter().any(|line| line.contains("192.168.0.0/16 ")), "{up:?}");
        assert!(!up.iter().any(|line| line.contains("via ")), "{up:?}");
        assert!(up.iter().any(|line| line.contains("0.0.0.0/1 ")), "{up:?}");
    }

    #[test]
    fn ipv6_false_omits_addresses_and_routes() {
        let tun = base();
        let mut addresses = addresses();
        addresses.v6.clear();
        let plan = plan(Platform::Linux, "billow0", &tun, &addresses, Some(&route()), 1500).unwrap();
        assert!(rendered(&plan.address).iter().all(|line| !line.contains("-6")));
        assert!(rendered(&plan.up).iter().all(|line| !line.contains("::/0")));
    }

    #[test]
    fn subtract_prefixes_splits_a_cidr() {
        let result = subtract_prefixes(&["0.0.0.0/0".to_string()], &["192.168.0.0/16".to_string()]);
        assert!(!result.contains(&"0.0.0.0/0".to_string()));
        assert!(!result.contains(&"192.168.0.0/16".to_string()));
        let joined = result.join(" ");
        assert!(joined.contains("0.0.0.0/1"), "{joined}");
        assert!(joined.contains("128.0.0.0/2"), "{joined}");
        assert_eq!(
            subtract_prefixes(&["::/0".to_string()], &["8000::/1".to_string()]),
            vec!["::/1".to_string()]
        );
    }

    #[test]
    fn strict_route_or_exclusions_without_a_gateway_fail_by_name() {
        let mut tun = base();
        tun.strict_route = true;
        let error = plan(Platform::Linux, "billow0", &tun, &addresses(), None, 1500).unwrap_err();
        assert!(error.contains("strict-route"), "{error}");
        let mut tun = base();
        tun.route_exclude_address = vec!["192.168.0.0/16".to_string()];
        let no_gateway = DefaultRoute {
            interface: "en0".to_string(),
            gateway: None,
        };
        // Exclusions are a set difference and no longer need a gateway.
        assert!(plan(Platform::Linux, "billow0", &tun, &addresses(), Some(&no_gateway), 1500).is_ok());
    }

    #[test]
    fn linux_policy_precheck_and_windows_metrics_are_explicit() {
        let tun = base();
        let commands = linux_precheck_commands(&tun, true);
        let rendered: Vec<String> = commands.iter().map(Command::render).collect();
        assert_eq!(
            rendered,
            vec![
                "ip rule show",
                "ip route show table 2022",
                "ip -6 rule show",
                "ip -6 route show table 2022",
            ]
        );
        assert!(linux_conflict("", "", 2022, 9000).is_none());
        assert!(linux_conflict(
            "9000: from all lookup 2022",
            "",
            2022,
            9000
        )
        .unwrap()
        .contains("9000"));
        assert!(linux_conflict("", "default dev eth0", 2022, 9000)
            .unwrap()
            .contains("2022"));

        let plan = plan(Platform::Windows, "Billow", &tun, &addresses(), Some(&route()), 1500)
            .unwrap();
        let address: Vec<String> = plan.address.iter().map(Command::render).collect();
        assert!(address.contains(&"netsh interface ipv4 set interface Billow metric=0".to_string()), "{address:?}");
        let up: Vec<String> = plan.up.iter().map(Command::render).collect();
        assert!(up.contains(
            &"netsh interface ipv4 add route prefix=0.0.0.0/0 interface=Billow metric=0"
                .to_string()
        ), "{up:?}");
        let down: Vec<String> = plan.down.iter().map(Command::render).collect();
        assert!(down.contains(
            &"netsh interface ipv4 set interface Billow metric=automatic".to_string()
        ), "{down:?}");
    }

    #[test]
    fn dns_plans_construct_and_restore() {
        let v4 = Some("198.18.0.2".parse().unwrap());
        let v6 = Some("fdfe:dcba:9876::2".parse().unwrap());
        let linux = plan_dns_linux("billow0", v4, v6);
        assert_eq!(
            rendered(&linux.up),
            vec![
                "resolvectl dns billow0 198.18.0.2 fdfe:dcba:9876::2",
                "resolvectl domain billow0 ~.",
                "resolvectl default-route billow0 true",
            ]
        );
        assert_eq!(rendered(&linux.down), vec!["resolvectl revert billow0"]);
        let mac = plan_dns_macos("Wi-Fi", &[], v4, v6);
        assert_eq!(
            rendered(&mac.up),
            vec!["networksetup -setdnsservers Wi-Fi 198.18.0.2 fdfe:dcba:9876::2"]
        );
        assert_eq!(
            rendered(&mac.down),
            vec!["networksetup -setdnsservers Wi-Fi Empty"]
        );
        let restored = plan_dns_macos("Wi-Fi", &["1.1.1.1".to_string()], v4, None);
        assert_eq!(
            rendered(&restored.down),
            vec!["networksetup -setdnsservers Wi-Fi 1.1.1.1"]
        );
        let windows = plan_dns_windows("Billow", &[], &[], v4, v6);
        assert!(rendered(&windows.up)[0].contains("name=Billow static 198.18.0.2 primary"));
        assert!(rendered(&windows.down).iter().any(|line| line.contains("dhcp")));
    }

    #[test]
    fn macos_and_windows_dns_parsers() {
        let order = "(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n(2) USB\n(Hardware Port: USB, Device: en5)\n";
        assert_eq!(parse_macos_service_order(order, "en5").as_deref(), Some("USB"));
        assert_eq!(parse_macos_service_order(order, "en9"), None);
        assert_eq!(
            parse_macos_dns_servers("There aren't any DNS Servers set on Wi-Fi.\n"),
            Vec::<String>::new()
        );
        assert_eq!(
            parse_macos_dns_servers("8.8.8.8\n1.1.1.1\n"),
            vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]
        );
        let netsh = "Configuration for interface \"Billow\"\n    Statically Configured DNS Servers: 1.1.1.1\n                                          8.8.8.8\n    Register with which suffix: Primary only\n";
        assert_eq!(
            parse_windows_dns_servers(netsh),
            vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]
        );
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
            parse_windows_default("Wi-Fi\r\n192.168.1.1\r\n"),
            Some(DefaultRoute {
                interface: "Wi-Fi".to_string(),
                gateway: Some("192.168.1.1".parse().unwrap())
            })
        );
        assert_eq!(parse_macos_default("garbage"), None);
    }
}
