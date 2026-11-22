# T7 iOS Rust tunnel: FFI, userspace IP stack and what was actually run

Workflow: `2026-11-20-native-rust-kernel` / Task T7 (attempt T7-A1).
Date: 2026-11-23. Host: macOS (arm64), Xcode 27.2, iOS 27.2 SDK, rustc 1.98.1.

This note records the implementation and the verification that was executed.
Nothing about a physical iPhone is claimed: no iPhone was connected
(`xcrun devicectl list devices` reported the iPhone 15 Pro Max as unavailable),
so R3/R4 device measurements are pending — see
[`docs/testing/2026-11-23-ios-rust-extension-memory.md`](../../../docs/testing/2026-11-23-ios-rust-extension-memory.md).

## What the extension links

| Piece | Path | Notes |
| --- | --- | --- |
| C ABI header | `src-tauri/gen/apple/network-extension/RustExtension/include/billow_ios_vpn.h` | one contract for the extension and the kernel |
| C ABI implementation | `native-kernel/crates/billow-kernel/src/ios_vpn.rs` | `--features ios-vpn`, off by default |
| data plane | `native-kernel/crates/billow-kernel/src/tunnel/` | `mod.rs` (flows/queues), `tcp_server.rs` (passive TCP), `udp.rs` (associations), `route.rs` (rules/groups/outbound + DIRECT) |
| archive | `libbillow_kernel.a` -> `src-tauri/gen/apple/Externals/arm64/<device|simulator>/rust/libapp.a` | `node tool/ios/build-rust-kernel.mjs --platform device|simulator|all`; offline, `Cargo.lock` is the source |
| Swift glue | `network-extension/RustExtension/{BillowRustEngine.swift,RustTunnelProvider.swift,RustKernelBridge.c}` | start/stop, packetFlow both directions, reload, status/stats |
| host selection | `network-extension/Host/BillowVPNManager.swift` | `setSelected` also writes `<AppGroup>/engine.json` |

`billow-kernel` is a `staticlib`; the extension's "Resolve Rust kernel" phase
(`resolve-mihomo.sh` -> `resolve-symbol.sh`) finds the archive and links it with
`-force_load`, defining `BILLOW_RUST_KERNEL_LINKED=1`. Without the archive the
extension still builds and reports `engineNotAvailable` (code 4).

## C ABI

Implemented exactly as declared in `billow_ios_vpn.h`:

| Symbol | Behaviour |
| --- | --- |
| `billow_ios_vpn_start(port, ctx, home, &error)` | reads `<home>/config.yaml`, starts the engine and the data plane; failure sets a `malloc`'d message (freed with `billow_ios_vpn_free_error`/`free`); a running tunnel is stopped first so a restart is safe |
| `billow_ios_vpn_drain(packets, max_count, &count)` | copies `[4B big-endian length][IP packet]` records out of the bounded egress queue (polling route); `-1` when no tunnel runs, `-2` on a null argument. The buffer must hold `max_count * (4 + 65535)` bytes |
| `billow_ios_vpn_write(packet, length)` | device ingress; accepts a `drain` record **or** a bare IP packet (an IP version nibble 4/6 is never a length prefix); the bytes are copied before returning |
| `billow_ios_vpn_stop()` | stops the data plane and the engine, releases every buffer; no callback from earlier calls is used afterwards |
| `billow_ios_vpn_version(buf, size)` | `billow-rust 0.1.0`; the extension's link gate is "non-empty answer + linked flag" |
| `billow_ios_vpn_selected()` | `1` rust / `0` mihomo / `-1` host never wrote state; reads `<AppGroup>/engine.json` for the directory recorded by `set_home` |
| `billow_ios_vpn_set_home(home)` | records `<AppGroup>/versions/<version>/` before `selected` runs (the ABI has no path argument) |
| `billow_ios_vpn_reload(&error)` | re-reads `<home>/config.yaml`; a rejected reload keeps the running generation; an accepted one closes every flow/association |
| `billow_ios_vpn_stats(buf, size)` | one JSON object with the counters **and this process's peak RSS** (`getrusage(RUSAGE_SELF).ru_maxrss`, bytes on Darwin); two-call sizing (`null`, 0 returns the required length) |
| `billow_ios_vpn_free_error(error)` | `free` |

Ownership rules are in the header and repeated in `ios_vpn.rs`: the tunnel
never keeps a packet pointer, `port->write` is called synchronously from a
tunnel thread, and `stop` joins/finishes every task before returning.

## Data plane (userspace IP)

* **IPv4/IPv6** parsing is the shared `outbound::ipstack` codec (also used by
  MASQUE CONNECT-IP, so a desktop TUN in T6 can reuse it). IPv4 options are not
  walked; fragments and IPv6 extension headers are refused **by name** and
  counted (`fragments`, `unsupported_protocols`), never reassembled or
  silently dropped without a counter.
* **TCP** is terminated in userspace by `tunnel::tcp_server::ServerTcp`
  (passive open: SYN -> SYN-ACK with the tunnel MSS, third ACK, data/ACK,
  half-close, RST). One task per flow, spliced onto the routed upstream
  socket. Out-of-order data is dropped and re-ACKed with the current `RCV.NXT`
  (the device retransmits), so no per-flow reordering map is allocated.
* **UDP** goes through the engine's outbound UDP associations: `DIRECT`, `ss`,
  `trojan`, `ssr`, `masque`, `shadowquic` (the same association types the mixed
  listener uses). Families without a UDP association in this kernel are
  refused **by name** (`unsupported_protocols`) instead of being sent the wrong
  way. Associations are per proxy and shared by destination, exactly like the
  pinned `UDP ASSOCIATE`.
* **Routing** mirrors `engine::serve_request`/`serve_udp_associate`: destination
  -> `preHandleMetadata` (hosts/fake-ip) -> rule decision -> proxy group ->
  `DIRECT` or `dial_chain` (dialer-proxy chain, proxy-server DNS). `IN-TYPE,TUN`
  now loads and matches (`InType::Tun`), and the flow registers in the
  connection registry so `/connections` lists it.
* **DNS**: `:53` is hijacked (UDP and TCP) and answered by the generation's
  `DnsService` (`answer_query`), matching the pinned tun `dns-hijack`; TCP DNS
  uses the 2-byte length framing. Failures are counted, not silently answered.
* **Rejections**: ICMP/ICMPv6 are counted and dropped; an unhandled IPv4
  protocol gets an ICMP protocol-unreachable; a stray TCP segment gets a
  correctly addressed RST; a REJECT rule closes the flow with RST.

## Bounds (R3/R4 inputs)

| Bound | Value | Where |
| --- | --- | --- |
| TCP flows at once | 128 (`TunnelOptions::max_tcp_flows`), a new SYN beyond it gets RST | `tunnel/mod.rs` |
| UDP flows at once | 256, idle flows expire after 60 s | `tunnel/mod.rs` |
| inbound queue per TCP flow / UDP datagrams | 32 packets / 256 datagrams (`try_send`, full = counted drop) | `TunnelOptions` |
| egress queue (polling route only) | 128 packets, full = counted drop; callback route has no queue | `Inner::emit` |
| UDP associations | 8, one 64 KiB receive buffer each, idle 60 s | `tunnel/udp.rs` |
| TCP send/receive buffer | 64 KiB / 64 KiB per flow | `tunnel/tcp_server.rs` |
| relay copy buffer | 16 KiB per direction | `TunnelOptions::buffer_size` |
| DNS concurrency | 32 in-flight queries | `tunnel/mod.rs` |
| connection registry | inherited engine limits (`max_sessions`) | `engine::Limits` |

`billow_ios_vpn_stats` exposes the live/high-water values needed to check them:
`tcpFlows`/`tcpFlowHigh`, `udpFlows`/`udpFlowHigh`, `queueHigh`/`queuedPackets`,
`droppedInbound`/`droppedEgress`, `generation`/`reloads`, `peakRssBytes`.

## Reload

`billow_ios_vpn_reload` loads `<home>/config.yaml` again through
`Kernel::reload` (a rejected reload keeps the current generation). On success
every TCP flow is closed (its task exits, the old generation `Arc` drops), the
UDP task drops its associations and direct sockets and refreshes its session
snapshot, and the egress queue is cleared. `generation` increments, so a host
can correlate samples with a configuration generation.

## Executed verification

Full log: [`t7-ios-build.log`](t7-ios-build.log),
[`t7-ios-simulator-smoke.log`](t7-ios-simulator-smoke.log).

| Check | Result |
| --- | --- |
| `cargo build -p billow-kernel --features ios-vpn --target aarch64-apple-ios --release` | ok |
| `cargo build -p billow-kernel --features ios-vpn --target aarch64-apple-ios-sim --release` | ok |
| `cargo test -p billow-kernel --features ios-vpn --lib` | 187 passed, 1 ignored (includes 20 tunnel unit tests: 7 for the passive TCP endpoint, 13 for ingest/bounds/reload/stats) |
| `cargo test -p billow-kernel --features ios-vpn --test ios_tunnel` | 5 passed: TCP both directions + half-close, UDP both directions, DNS hijack via a local upstream, REJECT -> RST, reload releases the flow index and keeps forwarding |
| `cargo test -p billow-kernel` (default features, no tunnel compiled) | all suites pass; desktop/Android builds unchanged |
| `xcodegen generate` + `xcodebuild -scheme BillowRust -sdk iphonesimulator CODE_SIGNING_ALLOWED=NO` | ok; archive linked with `-force_load`; `billow_ios_vpn_*` defined in `BillowRust.debug.dylib` (10 exported Rust symbols incl. `billow_rust_kernel_write`) |
| `xcodebuild -scheme BillowRust -configuration release -sdk iphoneos CODE_SIGNING_ALLOWED=NO` | ok; device archive linked (appex 11 MB on disk, not a memory measurement) |
| `xcrun swiftc -typecheck` of `network-extension/Shared` + `Host` (host target) | ok after fixing two pre-existing host defects that made the target uncompilable: `BillowVPNManager.swift` redeclared `AppGroupStore.readStatus(engine:)`, and `ResourcesInstaller.prepare` called `prepareVersion(engine:)` instead of `engines:options:`. `Shared/PacketPump.swift` still needs the Mihomo Go module header, so it is excluded from that typecheck |
| `tool/ios/verify-rust-kernel.sh` (arm64-apple-ios27.2-simulator binary spawned in the booted simulator) | 20/20 checks pass: version, stats sizing/JSON, `selected` before host state, missing-`config.yaml` error text, start with a real config, device UDP datagram -> DIRECT -> host echo server -> reply through `port->write`, stats while running, reload, stop, restart |

## Not verified (explicit gaps)

1. **Physical iPhone**: no device was connected. R3 (<= 40,000,000 bytes
   peak for the whole extension) and R4 (repeatable reclaim) have a sampling
   interface and a scenario table but **no measurements**. Any number in this
   note about memory is simulator/host `ru_maxrss` (≈ 25-28 MB for the smoke
   process) and must not be read as the extension's device peak.
2. **Host settings entry**: the Swift host API (`BillowVPNManager`,
   `ResourcesInstaller`, `BillowMobileEntry`) now typechecks and `setSelected`
   writes `engine.json`, but no Tauri command (`ios_vpn_prepare/select/
   connect/...`) or TS entry calls it yet, so "start both extensions from the
   app's real settings screen" is not wired (and the host target still cannot be
   built with plain `xcodebuild`: its pre-build phase runs `tauri ios
   xcode-script`). The extension-level start/stop path is exercised only from
   the simulator smoke and the Rust tests.
3. **Resource staging for the Rust engine**: `home/config.yaml` must exist and
   must enable a listener (`mixed-port`, `port` or `socks-port`); the engine
   always binds its mixed listener and rejects a configuration without one.
   Billow profiles set `mixed-port`, but the iOS stager must keep it and must
   copy the geo assets next to `config.yaml` (the tunnel passes `home` as the
   geodata directory). This belongs to the host wiring above.
4. **UDP over `gost-relay`, `sudoku`, `tuic`, `hysteria*`, `mieru`, `wireguard`,
   `openvpn`, `tailscale`, `zerotier`, `easytier`**: no UDP association is
   implemented for those families in this kernel; the tunnel drops such
   datagrams and counts them (`unsupportedProtocols`) instead of misrouting.
   TCP through any implemented outbound works.
5. **Large configurations**: the archive carries the whole engine. The
   extension links nothing else of the kernel's test/CLI code, but the device
   slice size and the per-config memory footprint still need a device
   measurement.
6. **`billow_ios_vpn_drain` buffer contract**: a polling host must size the
   buffer as `max_count * (4 + 65535)`. The extension's main route uses
   `port->write` and never calls `drain`, so this only affects hosts/tests.
