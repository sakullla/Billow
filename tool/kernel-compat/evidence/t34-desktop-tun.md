# T34 desktop TUN evidence

Date: 2026-11-26. Host: macOS arm64 (darwin 25.x), non-root. Workspace: `native-kernel`.

## What was implemented

- `desktop-tun = ["device-vpn"]` in `billow-kernel`; `billow-kernel-cli` exposes
  `--tun` and the desktop packaging script builds with `--features desktop-tun`.
- Strict `tun` parsing in `config.rs`: `enable`, `device`, `stack`, `mtu`,
  `auto-route`, `auto-detect-interface`, `strict-route`, `dns-hijack`,
  `route-address`, `route-exclude-address`.
  - `stack: mips|mixed|gvisor` loads and is **served by the in-tree userspace
    IP stack**, not the pinned MipsSoft/gVisor implementation (recorded as a
    warning).
  - `stack: system`, `file-descriptor`, and any other key fail by name.
  - `route-address`/`route-exclude-address` must be CIDR prefixes.
- `src/desktop_tun/`:
  - macOS `utun` control socket, `UTUN_OPT_IFNAME`, 4-byte big-endian
    `AF_INET=2`/`AF_INET6=30` framing (strip on read, add on write).
  - Linux `/dev/net/tun` with `TUNSETIFF | IFF_TUN | IFF_NO_PI` (raw IP).
  - Windows Wintun via the shipped `wintun.dll`
    (`WintunCreateAdapter`/`WintunStartSession`/receive/allocate/send).
  - Device addresses follow pinned defaults: `198.18.0.1/30` and
    `fdfe:dcba:9876::1/126`; `tun.mtu` absent means 9000 (pinned sing-tun).
  - Auto-route uses `0.0.0.0/1` + `128.0.0.0/1` and `::/1` + `8000::/1`, never
    replacing the physical default route. `route-address` goes through the
    device; `route-exclude-address` goes through the detected physical gateway;
    `strict-route` requires a detected physical interface or fails by name.
  - `auto-detect-interface` parses `route -n get default` (macOS),
    `ip route show default` (Linux) or a PowerShell `Get-NetRoute` probe
    (Windows). The interface is installed as a process-wide default bind used
    by proxy-server dials, DIRECT TCP/UDP and DNS queries (`outbound::
    set_default_interface` / `connect_bound` / `bind_udp_str`), so the TUN
    cannot re-capture the kernel's own traffic. This mirrors Mihomo's
    `dialer.DefaultInterfaceFinder`.
  - Reader thread feeds `Tunnel::ingest` (the T7 userspace stack); the bounded
    `PacketSink` queue plus a writer thread writes replies. Stop removes the
    routes/addresses this process added, clears the interface bind and closes
    the device; a failed address/route apply runs the same teardown first.
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
| `cargo test --manifest-path native-kernel/Cargo.toml --locked -- --test-threads=1` | pass: 478 passed, 0 failed (across suites; lib 210, ignored cases are separate) |
| `cargo test --manifest-path native-kernel/Cargo.toml --features desktop-tun --locked -- --test-threads=1` | pass: 516 passed, 0 failed (full suite plus `desktop_tunnel` 7 passed/1 ignored and `desktop_cli` 2/0) |
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
  - `macos_linux_windows_route_plans_use_split_defaults`
  - `a_failed_route_command_rolls_the_plan_back`
  - `start_with_tun_disabled_fails_before_creating_a_device`
  - `real_utun_can_be_created_and_closed` (`#[ignore]`)
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
- Auto-route split routes, route-exclude gateways, DNS hijack over a real TUN
  and anti-loop binding are covered only as command plans plus the
  UnixDatagram pump; the end-to-end "TUN captures the machine and the engine
  still reaches the internet" check needs a privileged host.
- `stack` is not a MipsSoft or gVisor implementation; only the name is
  accepted and mapped to the in-tree userspace IP stack.
- `strict-route` is implemented as "require a detected physical interface and
  bind kernel-originated sockets to it"; pinned fwmark/rule/table details are
  not claimed.
