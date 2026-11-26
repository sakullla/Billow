# T34 desktop TUN evidence

Date: 2026-11-26. Host: macOS arm64 (darwin 25.x), non-root. Workspace: `native-kernel`.

## What was implemented

- `desktop-tun = ["device-vpn"]` in `billow-kernel`; `billow-kernel-cli` exposes
  `--tun` and the desktop packaging script builds with `--features desktop-tun`.
- Strict `tun` parsing in `config.rs`: `enable`, `device`, `stack`, `mtu`,
  `auto-route`, `auto-detect-interface`, `strict-route`, `dns-hijack`,
  `dns-mode`, `inet6-address`, `route-address`, `route-exclude-address`.
  - `stack: mips|mixed|gvisor` loads and is **served by the in-tree userspace
    IP stack**, not the pinned MipsSoft/gVisor implementation (recorded as a
    warning).
  - `stack: system`, `file-descriptor`, `dns-mode` outside
    `disabled/native/hijack`, non-53/failed `dns-hijack` entries, non-IPv6
    `inet6-address` entries and any other key fail by name.
  - `dns-hijack` is an address-port set (`tcp://`/`udp://` scheme stripped,
    `any` -> `0.0.0.0`, `[::]:53` supported). Hijack matches pinned
    `ShouldHijackDns`: exact target, or an unspecified entry for any target on
    port 53. An unlisted target goes through the normal flow.
- `src/desktop_tun/`:
  - macOS `utun` control socket, `UTUN_OPT_IFNAME`, 4-byte big-endian
    `AF_INET=2`/`AF_INET6=30` framing (strip on read, add on write). A
    `tun.device: utunN` selects that unit; any other non-empty name is rejected.
  - Linux `/dev/net/tun` with `TUNSETIFF | IFF_TUN | IFF_NO_PI` (raw IP;
    15-byte name check stays platform-specific).
  - Windows Wintun via the shipped `wintun.dll`
    (`WintunOpenAdapter` then `WintunCreateAdapter`, `WintunStartSession`,
    receive/allocate/send); a full send ring is a counted drop, not a pump
    stop. Adapter names are validated against the Windows alias rules.
  - The IPv4 device address is derived from `dns.fake-ip-range` (pinned:
    address part narrowed to /30; absent = `198.18.0.1/30`). IPv6 uses
    `tun.inet6-address` (default `fdfe:dcba:9876::1/126`); `ipv6: false`
    clears the IPv6 address, auto ranges and DNS server. `tun.mtu` absent
    means 9000 (pinned sing-tun).
  - Routes follow pinned `BuildAutoRouteRanges`: a non-empty `route-address`
    installs only those prefixes (macOS also adds the TUN subnet); otherwise
    macOS installs `1.0.0.0/8, 2.0.0.0/7, 4.0.0.0/6, 8.0.0.0/5, 16.0.0.0/4,
    32.0.0.0/3, 64.0.0.0/2, 128.0.0.0/1` (IPv6 mirrors it with `100::/8`
    ... `8000::/1`), while Linux/Windows use the pinned full `0.0.0.0/0` /
    `::/0`. `route-exclude-address` is an integer-prefix set difference over
    the chosen ranges (no `via` gateway route). `strict-route` requires a
    detected physical interface and is registered as a weak semantic in the
    config warning.
  - `dns-mode: native|hijack` points the system resolver at `tun4+1` /
    `tun6+1`: Linux `resolvectl dns/domain/default-route` (down: `revert`),
    Windows `netsh interface ipv4/ipv6 set dnsservers` with the previous static
    list captured for restore, macOS `networksetup -setdnsservers` for the
    service owning the interface with `-getdnsservers` saved for restore. A
    utun has no networksetup service, so macOS logs a named warning and leaves
    the resolver unchanged. `dns-mode` defaults to disabled.
  - `auto-detect-interface` parses `route -n get default` (macOS),
    `ip route show default` (Linux) or a PowerShell `Get-NetRoute` probe
    (Windows). The interface is installed as a process-wide default bind used
    by proxy-server dials, DIRECT TCP/UDP and DNS queries (`outbound::
    set_default_interface` / `connect_bound` / `bind_udp_str`), so the TUN
    cannot re-capture the kernel's own traffic. The same binding now covers
    mKCP (`udp_socket_std_blocking`, keeping its blocking read loop), provider
    downloads (`tcp_stream_std_blocking`), group/controller DIRECT probes and
    DNS bootstrap queries.
  - Reader thread feeds `Tunnel::ingest` (the T7 userspace stack); the bounded
    `PacketSink` queue plus a writer thread writes replies. Stop removes the
    routes/addresses/DNS changes this process added, clears the interface bind
    and closes the device; a failed address/route/DNS apply runs the same
    teardown first.
- Host (`src-tauri/src/profile.rs`): desktop `Engine::Rust` no longer strips
  `tun`; `tun_enable` is written as `tun.enable` and the launch adds `--tun`.
  Android keeps the VpnService fd/`--tun-fd` and the stripped block; iOS keeps
  the Packet Tunnel. `TunGrant` now authorizes the selected engine binary on
  macOS and the Windows elevated helper can launch the Rust kernel with
  `--tun`. `--check` only validates.
- Packaging: `tool/prepare_desktop_runtime.mjs` passes `--features
  desktop-tun` and copies `wintun.dll` next to the Rust kernel for Windows.

## Commands run and results

All commands used an isolated `CARGO_TARGET_DIR` under the session temp dir and
`--test-threads=1`.

| Command | Result |
| --- | --- |
| `cargo test --manifest-path native-kernel/Cargo.toml --locked -- --test-threads=1` | pass: 480 passed, 0 failed (across suites; lib 212, ignored cases are separate) |
| `cargo test --manifest-path native-kernel/Cargo.toml --features desktop-tun --locked -- --test-threads=1` | pass: 528 passed, 0 failed (full suite plus `desktop_tunnel` 14 passed/1 ignored and `desktop_cli` 2/0) |
| `cargo test --features android-vpn --test android_tunnel` | pass: 9/9 (shared `Tunnel::set_sink`/pump change does not regress the fd data plane) |
| `cargo check --features ios-vpn` | pass |
| `cargo test --manifest-path src-tauri/Cargo.toml --lib -- --test-threads=1` | pass: 252 passed, 0 failed, 10 ignored |
| `node --test tool/kernel-compat/runner.test.mjs` | pass: 10/10 |

Manual non-root probe of the real binary (no privilege):

```
billow-kernel <config with tun.enable/stack gvisor> --tun
exit=1
error: desktop-tun: opening a utun was denied (Operation not permitted (os error 1));
       run the kernel through the TunGrant authorization (setuid root) or as root
```

That is the required named failure: the process does not start, so the host's
snapshot cannot read as TUN-taken-over.

Targeted new tests:

- `tests/desktop_tunnel.rs`
  - `tun_config_accepts_the_billow_desktop_shape_and_rejects_by_name`
  - `utun_framing_matches_darwin_address_families`
  - `fd_pump_carries_udp_ip_packets_both_ways` (UnixDatagram pair; UDP both ways)
  - `dns_hijack_matching_is_exact_or_unspecified`
  - `a_listed_dns_target_is_hijacked_and_an_unlisted_one_is_not`
  - `an_unspecified_dns_hijack_entry_answers_any_port_53_target`
  - `a_tcp_dns_query_is_hijacked_only_for_a_matching_target`
  - `route_plan_follows_pinned_auto_route_and_exclusion`
  - `ipv6_false_and_custom_inet6_addresses_change_the_plan`
  - `device_address_comes_from_fake_ip_range`
  - `dns_plans_construct_and_restore`
  - `a_failed_route_command_rolls_the_plan_back`
  - `start_with_tun_disabled_fails_before_creating_a_device`
  - `real_utun_can_be_created_and_closed` (`#[ignore]`)
- `src/desktop_tun/route_plan.rs` unit tests: pinned macOS sub-ranges,
  route-address replacement, set-difference exclusion, DNS command/restore,
  default-route and DNS parsers.
- `src/outbound/mod.rs` unit tests: process-interface bind and blocking
  UDP/TCP helpers (mKCP/provider path).
- `tests/desktop_cli.rs`
  - `check_validates_a_tun_configuration_without_creating_a_device`
  - `a_rejected_tun_shape_exits_non_zero_with_its_name`
- `src-tauri` profile tests:
  - `desktop_rust_keeps_the_tun_block_and_follows_the_launcher_switch`
  - `android_rust_still_strips_the_tun_block_for_the_vpn_fd`

## Not verified / preserved boundaries

- `tool/kernel-compat/option-probe.mjs` enumerates proxy/protocol options only;
  it has no `tun` rows, so `option-matrix.txt` is unchanged. The tun disposition
  is recorded in `rust-mapping.json` and this file.
- **Real desktop device takeover has not been run on any platform.** Creating a
  macOS `utun` needs root or the `TunGrant` setuid authorization; this host has
  neither. The real-device test is `#[ignore]`d and its failure/absence must not
  be read as a pass.
- Linux `/dev/net/tun` and Windows Wintun device creation and `ip`/`netsh`
  route execution are cfg-complete but were not run here (no Linux/Windows
  host). Their real-platform acceptance remains pending.
- Auto-route ranges, route-exclude set difference, DNS-hijack targeting and
  DNS command/restore plans are covered by pure tests plus the UnixDatagram
  pump and the real macOS lo0 interface bind; the end-to-end "TUN captures the
  machine and the engine still reaches the internet" check needs a privileged
  host.
- `dns-mode` command execution was not run on any platform (no root and no
  Linux/Windows host); macOS utun has no networksetup service so the resolver
  is left unchanged with a named warning. Windows restore is best-effort (the
  first saved static server); a localized `netsh` output may not parse and
  falls back to DHCP.
- `stack` is not a MipsSoft or gVisor implementation; only the name is
  accepted and mapped to the in-tree userspace IP stack.
- `strict-route` is implemented as "require a detected physical interface and
  bind kernel-originated sockets to it"; pinned fwmark/rule/table details are
  not claimed and the loader emits an explicit warning.
