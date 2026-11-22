# T7 iOS Rust tunnel: FFI, userspace IP stack and what was actually run

Workflow: `2026-11-20-native-rust-kernel` / Task T7 (attempts T7-A1 + T7-A2
repair + T7-A3 repair). Date: 2026-11-23/24. Host: macOS (arm64), Xcode 27.2, iOS 27.2 SDK,
rustc 1.98.1.

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
  way. T7-A2 keys each flow by its device 4-tuple `(src, dst)`: DIRECT owns one
  connected socket per flow and a proxied flow owns its own association, so a
  reply from a remote shared by two device sockets is delivered only to the
  flow that sent the datagram.
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
| `xcrun swiftc -typecheck` of `network-extension/Shared` + `Host` (host target) | A2: ok only after fixing two pre-existing host defects and **excluding** `Shared/PacketPump.swift`. T7-A3 found that this exclusion hid a real host build failure (the host compiled the Mihomo ingest branch); `BILLOW_ENGINE_HOST` now makes the full, unfiltered host source set pass — see the T7-A3 section below |
| `tool/ios/verify-rust-kernel.sh` (arm64-apple-ios27.2-simulator binary spawned in the booted simulator) | 20/20 checks pass: version, stats sizing/JSON, `selected` before host state, missing-`config.yaml` error text, start with a real config, device UDP datagram -> DIRECT -> host echo server -> reply through `port->write`, stats while running, reload, stop, restart |

## Not verified (explicit gaps)

1. **Physical iPhone**: no device was connected. R3 (<= 40,000,000 bytes
   peak for the whole extension) and R4 (repeatable reclaim) have a sampling
   interface and a scenario table but **no measurements**. Any number in this
   note about memory is simulator/host `ru_maxrss` (≈ 25-28 MB for the smoke
   process) and must not be read as the extension's device peak.
2. **Host settings entry**: T7-A2 wired `BillowMobileBridge.swift`,
   `src-tauri/src/ios_vpn.rs`, `src/lib/backend.ts` and the settings kernel
   tab; the host target now checks with
   `cargo check --target aarch64-apple-ios` and the full Swift host/shared
   source set type-checks with `BILLOW_ENGINE_HOST` (T7-A3). It is still not
   executed on a device (same physical-iPhone gap as item 1), and plain
   `xcodebuild` still cannot run the Tauri pre-build phase
   (`tauri ios xcode-script`).
3. **Resource staging for the Rust engine**: the host stages the active
   profile and `stage_config` writes `config.rust.yaml` inside the version
   directory. It preserves `mixed-port`, copies referenced provider files and
   geo assets into `home`, removes `tun.enable: true` with a warning (the iOS
   Packet Tunnel owns the device route), and since T7-A3 removes
   `sniffer.enable: true` with a warning too (this kernel does not implement
   sniffing; domain rules then see the destination IP/DNS result instead of a
   sniffed SNI/Host). Other enabled blocks the engine rejects still fail with
   the engine's named error instead of starting silently.
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
   `port->write` and never calls `drain`, so this only affects hosts/tests. The
   `billow_rust_kernel_drain` C wrapper now derives `max_count` from the
   caller's byte `length` (`length / (4 + 65535)`), so it cannot overrun a
   caller-sized buffer.

## T7-A2 repair (2026-11-24)

Review findings addressed:

| Finding | Change |
| --- | --- |
| P0 host entry missing | `BillowMobileBridge.swift` (`@_cdecl billow_mobile_request/free`) exposes engines/prepare/select/connect/disconnect/status/reload/prune; `src-tauri/src/ios_vpn.rs` wraps it as Tauri commands with stable codes (11 `notIos`, 12 `badResponse`); `src/lib/backend.ts`, the store and the settings kernel tab call it; `src-tauri/permissions/ios-vpn.toml` and `capabilities/default.json` grant the commands. |
| P1 manifest overwrite | `AppGroupStore.prepareVersion` merges the version directory and unions `manifest.engines`; `ResourcesInstaller.prepare` can prepare both engines. `tool/ios/verify-app-group.sh` asserts a second prepare keeps the first engine and both `validatedResources` pass. |
| P1 Rust staging / `tun` | `stage_config` in `native-kernel/.../ios_vpn.rs` writes `config.rust.yaml`, preserves `mixed-port`, copies referenced provider files into `home`, rewrites paths, removes `tun.enable: true`; `Tunnel::start_at` and reload use it. Host `ios_vpn_prepare_active` stages effective YAML + geo + referenced files. |
| P1 UDP fan-out | `UdpReply` carries `(device src, device dst)`; DIRECT uses one connected socket per flow, proxied flows use one association per flow. `concurrent_device_sockets_to_one_remote_keep_their_replies` covers two sockets to one remote. |
| P2 stop/drain | `Tunnel::stop` waits for `shutdown_timeout(5 s)`; `ios_vpn_start`/`reload` no longer hold the global state lock while stopping/reloading (state stores `Arc<Tunnel>`); `billow_rust_kernel_drain` uses the caller's `length`. |

Execution evidence for this attempt:

| Command | Result |
| --- | --- |
| `cargo test -p billow-kernel --features ios-vpn` | 191 lib tests + 43 resources + 15 … suites pass; `ios_tunnel` 6 passed including the new two-socket UDP test; new `ios_vpn::tests::staging_*` pass |
| `cargo test -p billow-kernel` (default) | all suites pass (no tunnel compiled) |
| `cargo test --manifest-path src-tauri/Cargo.toml ios_vpn` | 7 passed: request field names (prepare + connect), row decode, host error code/domain, malformed response, null status, non-iOS code 11 |
| `cargo check --manifest-path src-tauri/Cargo.toml` | host macOS ok |
| `cargo check --manifest-path src-tauri/Cargo.toml --target aarch64-apple-ios` | ok after enabling the iOS `rquickjs` bindgen feature and adding the `ios` branch to `current_desktop_os` |
| `xcrun swiftc -typecheck` Shared + Host (iOS 15 simulator) | ok; App Intents marked `@available(iOS 16.0, *)`, host gets `BILLOW_ENGINE_MIHOMO` |
| `tool/ios/verify-app-group.sh` | `ok: one version validates for mihomo and rust; later prepares preserve both` |
| `node tool/ios/build-rust-kernel.mjs --platform device|simulator` | both archives rebuilt (88.6/88.7 MiB) |
| `xcodegen generate` + `xcodebuild -scheme BillowRust -sdk iphonesimulator CODE_SIGNING_ALLOWED=NO` | BUILD SUCCEEDED; `BillowMobileBridge.swift` is in the host target and the shared resource code still compiles with `BILLOW_ENGINE_RUST` |
| `tool/ios/verify-rust-kernel.sh` | 20/20 checks pass (UDP reply through `port->write`, reload, stop, restart) |
| `cargo test -p billow-kernel --features ios-vpn` with an independent `CARGO_TARGET_DIR` | all suites pass; `ios_tunnel` 6/6 |
| `cargo test -p billow-kernel` with the same independent target | all suites pass |
| `npm test` / `npm run build` | 341 frontend tests pass; type-check + vite build pass |

Still not executed: physical-device R3/R4, `.github` iOS CI, and a real
`npx tauri ios build` with a Team.

## T7-A3 repair (2026-11-24)

Review finding: the host target (`billow_iOS`) did not compile. A2 gave the
host `SWIFT_ACTIVE_COMPILATION_CONDITIONS=BILLOW_ENGINE_MIHOMO`, while the
host Sources also contain `Shared/PacketPump.swift`; its `#if
BILLOW_ENGINE_MIHOMO` branch calls `GoMihomoReadPacket`, a symbol only the
Mihomo extension declares (`@_silgen_name`) and links (`libmihomo_ios`). The
A2 typecheck had excluded `PacketPump.swift`, which hid this.

| Fix | Where |
| --- | --- |
| Distinct host condition `BILLOW_ENGINE_HOST` (host `ProviderSupport.engine == "host"`; the host never writes a provider status file) | `network-extension/Shared/ProviderSupport.swift`, `project.yml`, `billow.xcodeproj/project.pbxproj` |
| `PacketPump.swift` is explicitly extension-only (`#if BILLOW_ENGINE_MIHOMO \|\| BILLOW_ENGINE_RUST`), so the host compiles neither ingest branch | `network-extension/Shared/PacketPump.swift` |
| `sniffer.enable: true` is stripped like `tun.enable: true`, with a warning that sniffing is not implemented (instead of failing the start in `config.rs`) | `native-kernel/crates/billow-kernel/src/ios_vpn.rs` |
| Superseded `versions/<hash>` directories are pruned after a prepare, keeping any version a connected extension reports; the host prune also unions a running `status/<engine>.json` version | `src/lib/store.ts`, `Host/ResourcesInstaller.swift` |
| `installed` comes from the embedded `.appex` (`Bundle.main.builtInPlugInsURL`, bundle id check), not from `status != nil`; the settings row says "未启动" for an installed but idle extension | `Host/BillowVPNManager.swift`, `Host/BillowMobileEntry.swift`, `src/views/SettingsView.vue` |
| Repeatable host/extension typecheck with the real source sets | `tool/ios/verify-host-sources.sh`, `npm run ios:verify-host` |

Execution evidence for this attempt:

| Command | Result |
| --- | --- |
| `tool/ios/verify-host-sources.sh` | **ok**: host (`BILLOW_ENGINE_HOST`: `Shared/*.swift` + `Host/*.swift` + `Sources/billow/main.mm`), `BillowMihomo` (`Shared` + `MihomoExtension`) and `BillowRust` (`Shared` + `RustExtension`, bridging header) all type-check against the iPhoneSimulator SDK. Nothing is excluded; `PacketPump.swift` is in the host command. Log: [`t7-ios-a3-host-typecheck.log`](t7-ios-a3-host-typecheck.log) |
| `xcodebuild -project billow.xcodeproj -scheme billow_iOS -configuration debug -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO …` | **blocked before Swift compilation** by the pre-build phase: `tauri ios xcode-script` needs `src-tauri/gen/apple/.tauri/cli-options-server.json`, which only a running `tauri ios dev/build` creates. This is the same Tauri-pre-build gap reported by A2, not a host-source error. Excerpt: [`t7-ios-a3-xcodebuild.log`](t7-ios-a3-xcodebuild.log) |
| `xcodebuild -scheme BillowRust` / `-scheme BillowMihomo` (debug, iPhoneSimulator, unsigned) | both **BUILD SUCCEEDED**; this compiles `PacketPump.swift` once with `BILLOW_ENGINE_RUST` and once with `BILLOW_ENGINE_MIHOMO` and links the extension, while the host condition excludes both branches |
| `cargo test -p billow-kernel --features ios-vpn` | 192 lib + 43 resources + 15 + 19 + 32 + 6 + 50 + 32 + 15 + 11 + 1 + 1 tests pass, 1 ignored; includes the new `ios_vpn::tests::staging_strips_enabled_sniffer_so_the_config_loader_accepts_it` |
| `cargo test -p billow-kernel` (default) | all suites pass (160 lib, no tunnel compiled) |
| `cargo test --manifest-path src-tauri/Cargo.toml ios_vpn` | 7 passed |
| `tool/ios/verify-app-group.sh` | ok (both engines in one version) |
| `tool/ios/verify-rust-kernel.sh` | PASS (20 checks; UDP reply, reload, stop, restart) |
| `npm test` / `npm run build` | 342 tests pass (new prune test); type-check + Vite build pass |

Still not executed: physical-device R3/R4, a signed `tauri ios build`, and a
plain `xcodebuild billow_iOS` that completes the Tauri pre-build phase.
