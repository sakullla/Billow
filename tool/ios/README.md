# iOS host and Packet Tunnel extensions (T3)

Source of truth: `src-tauri/gen/apple/project.yml` (xcodegen). Do not edit
`billow.xcodeproj` by hand; regenerate it. `src-tauri/tauri.ios.conf.json` is
not needed: the host bundle id, entitlements and extension embedding all live
in `project.yml`.

| Target | Kind | Bundle id | Sources |
| --- | --- | --- | --- |
| `billow_iOS` | app | `app.billow.client` | Tauri `Sources/`, `network-extension/Host`, `network-extension/Shared` |
| `BillowMihomo` | packet-tunnel extension | `app.billow.client.mihomo` | `network-extension/Shared`, `network-extension/MihomoExtension`, `libmihomo_ios.a` |
| `BillowRust` | packet-tunnel extension (Rust kernel via libapp.a, T7) | `app.billow.client.rust` | `network-extension/Shared`, `network-extension/RustExtension` + `Externals/arm64/<platform>/rust/libapp.a` |

Both extensions are embedded and signed with the host and carry
`com.apple.developer.networking.networkextension = packet-tunnel-provider`
plus the App Group `group.app.billow.client` (same for the host). Neither
extension links `libapp.a` or runs Tauri's "Build Rust Code" script.

## Build

```sh
node tool/ios/build-mihomo-ios.mjs --platform device      # libmihomo_ios.a (Externals/, git-ignored)
node tool/ios/build-mihomo-ios.mjs --platform simulator
node tool/ios/build-rust-kernel.mjs --platform device     # libapp.a = billow-kernel --features ios-vpn (offline)
node tool/ios/build-rust-kernel.mjs --platform simulator
tool/ios/build.sh --platform device                 # archives + xcodegen + both extensions (CODE_SIGNING_ALLOWED=NO)
tool/ios/build.sh --platform simulator
tool/ios/verify-mihomo-archive.sh simulator        # link + run a probe against the Mihomo archive
tool/ios/verify-rust-kernel.sh                     # link + run the Rust kernel smoke in the booted simulator
npm run ios:rust-kernel && npm run ios:verify-rust # the same two steps via package.json
```

`tool/ios/build-rust-kernel.mjs` builds the `billow-kernel` staticlib with
`--features ios-vpn`, copies it to
`src-tauri/gen/apple/Externals/arm64/<platform>/rust/libapp.a` and fails if
the archive does not export `billow_ios_vpn_start/_drain`. It uses the
workspace `Cargo.lock` (no downloads) and asks `cargo metadata` for the target
directory, so a shared `CARGO_TARGET_DIR` works.

`tool/ios/build-mihomo-ios.mjs` verifies the pinned tarball
(`tool/ios/mihomo-ios.json`: MetaCubeX/mihomo v1.19.34,
commit `0455d0d28c4526937380505153e65a843d8612e8`, sha256
`db0cc414…c0cfe`, tags `with_gvisor,cmfa`), copies
`src-tauri/gen/apple/mihomo-ios/` (Go bridge + `go.mod`/`go.sum`) into a
temp module, runs `go vet`, then `GOOS=ios GOARCH=arm64 CGO_ENABLED=1
go build -buildmode=c-archive`. The cgo header is installed as the Swift
module `Externals/arm64/<platform>/include/billow_mihomo_bridge/`.

Host (`billow_iOS`) signing-free compile is not possible with plain
xcodebuild: the target's pre-build script runs `tauri ios xcode-script`,
which only works inside `npx tauri ios build` / `tauri ios dev`. Use
`npx tauri ios build --debug --ci` on a machine with a Team.

The Rust host target can still be checked without signing:

```sh
cargo check --manifest-path src-tauri/Cargo.toml --target aarch64-apple-ios
```

T7-A2 fixed the two pre-existing host blockers this exposed: `rquickjs` 0.14
ships no iOS bindings (the iOS target now enables its `bindgen` feature, like
Android), and `current_desktop_os()` had no `ios` branch. The host also gets
`BILLOW_ENGINE_MIHOMO` in `project.yml` because `Shared/ProviderSupport.swift`
requires exactly one engine identity, and the App Intents are marked
`@available(iOS 16.0, *)` while the deployment target stays 15.0.

## Engineers' notes (verified on macOS 27.2, Xcode 27.2, Go 1.26.2)

- `GOOS=ios` exists from Go 1.26. `-buildmode=c-archive` requires a `main`
  package; `main()` never runs. Exports are `GoMihomoStart/Version/Reload/
  NetworkChanged/Shutdown/ReadPacket/WritePackets/LoopbackStart/Stop`.
- Go must be *called by* Swift, never the reverse through Go-owned symbols:
  a `//export`ed Go function lives in a host-linked object inside the
  archive, so code the Go linker placed cannot callback into it. The write
  path therefore passes Swift `@convention(c)` function pointers to
  `GoMihomoStart`, and Go calls them through a C helper in its preamble.
  Verified on the iOS simulator (Swift closure -> Go -> C call).
- The darwin Go runtime references `res_9_ninit/nclose/nsearch`; iOS ships no
  libresolv. `tool/ios/mihomo-resolv-stub.c` (compiled into the extension;
  never exercised because mihomo resolves through its own resolver) satisfies
  the linker.
- Archive size is ~165 MB (c-archive carries host-linked Go runtime objects
  for every dependency, no dead-code stripping). Thinned size in the `.appex`
  must be measured on device (T7, memory budget R3).
- `packetFlow.readPackets/writePackets` in the iOS 27 SDK use `[Data]`;
  Swift owns one outstanding read (PacketPump) and writePackets is called
  synchronously from Go.
- BillowRust's base configuration `build/rust-kernel/linked.xcconfig` is a
  committed seed that the "Resolve Rust kernel" phase rewrites on every build
  (xcodegen requires the file to exist before any phase runs).
- Entitlements are static in the three `*.entitlements` files. Ad-hoc signing
  (`CODE_SIGN_IDENTITY=-`) refuses them for device builds ("entitlements that
  require signing with a development certificate"), which is the expected
  behaviour without a Team.

## Data path (Mihomo extension)

`packetFlow.readPackets` -> `PacketPump` -> `GoMihomoReadPacket` (one IP
packet) -> sing-tun gVisor stack (routes from config.yaml, DNS `:53` hijack
to the configured `dns`) -> mihomo `tunnel.HandleTCPConn/HandleUDPPacket` ->
egress `WritePackets` -> `writePackets`. Source mapping to the pinned tree is
in the header of `src-tauri/gen/apple/mihomo-ios/bridge.go`.

## Host API (T7, wired)

`network-extension/Host/BillowMobileBridge.swift` exports one C ABI,
`billow_mobile_request(json)` / `billow_mobile_free(ptr)`, implemented on top
of `BillowVPNManager`, `ResourcesInstaller` and `BillowMobileEntry`.
`src-tauri/src/ios_vpn.rs` wraps it as Tauri commands; `src/lib/backend.ts`
and the settings kernel tab call them. On desktop and Android the same
commands exist and answer code 11 (`notIos`) instead of failing to build.

| Command | Host call |
| --- | --- |
| `ios_vpn_engines` -> `[{engine, installed, connected, version, engineVersion, lastError}]` | `BillowMobileEntry.engineStates()` |
| `ios_vpn_active_version` -> `String?` | `BillowMobileEntry.activeVersion()` |
| `ios_vpn_selected` / `ios_vpn_select(engine)` | App Group `engine.json` via `BillowVPNManager.selected/setSelected` |
| `ios_vpn_prepare(version, stagedDir, engine?)` | `ResourcesInstaller.prepare(version:engines:stagedDir:)`; the engine list defaults to both |
| `ios_vpn_prepare_active(version?, engine?)` | host-only: stage the active profile (effective YAML + referenced rule sets + geo) and then call `ios_vpn_prepare`; version defaults to a content hash |
| `ios_vpn_connect(engine, version)` | `connect(engine:requestedVersion:)` then `waitForState(.connected)`; a timeout/refusal carries `describeLastError` |
| `ios_vpn_disconnect()` | `disconnect()` |
| `ios_vpn_reload(engine)` | `reload(engine:)` (sendProviderMessage `reload`) |
| `ios_vpn_status(engine)` | `status(of:)` |
| `ios_vpn_prune(keeping)` | `ResourcesInstaller.prune(keeping:)` |

Error codes (`BillowVPNError.domain`, `code`): 0 providerFailed,
1 resourceInvalid, 2 engineStartFailed, 3 configurationMissing,
4 engineNotAvailable, 5 networkUnavailable, 6 engineStopped,
7 loopbackFailed, 8 unsupportedCommand, 9 tunnelSetupFailed,
10 hostNotReady. The Rust bridge adds 11 `notIos` and 12 `badResponse`.
Status is also written to the App Group `status/<engine>.json` so the host
can explain a start failure without a session.

Both engines validate the same `versions/<version>`: `prepareVersion` merges
the directory and the `manifest.engines` list instead of removing the version,
and `tool/ios/verify-app-group.sh` runs the dual-engine manifest smoke on the
host without signing.

## Rust extension wiring (T7)

BillowRust is startable in both states. Swift owns `startTunnel`, settings and
`readPackets`; the Rust data plane is reached only through C shims, never
through `@_silgen_name` (the linker rejects undefined Swift-referenced C
symbols in an extension):

```
BillowRustEngine.swift
  └─ RustKernelBridge.c            (compile-time switch BILLOW_RUST_KERNEL_LINKED)
       ├─ unlinked: kernel_image_present()=0, start() returns -2
       │            -> BillowVPNError.engineNotAvailable (code 4)
       └─ linked:   calls the C ABI of libapp.a
```

1. `tool/ios/build.sh` (or the BillowRust "Resolve Rust kernel" phase via
   `network-extension/RustExtension/resolve-mihomo.sh`) looks for
   `src-tauri/gen/apple/Externals/arm64/rust/libapp.a` (override:
   `BILLOW_RUST_KERNEL_ARCHIVE`). To exercise the linked branch before the
   real kernel exists:
   `BILLOW_RUST_KERNEL_ARCHIVE=/path/libapp.a tool/ios/build.sh --platform device`
   prints `BillowRust: linking Rust kernel <path>` and writes
   `OTHER_LDFLAGS = $(inherited) -force_load "<path>"` into
   `build/rust-kernel/linked.xcconfig`. When the archive contains
   `billow_ios_vpn_start` it is linked with `-force_load` and
   `BILLOW_RUST_KERNEL_LINKED=1` is defined for C and Swift. No archive: the
   extension builds and starts, then fails with code 4 and writes that status
   to the App Group (`status/rust.json`), so the host engine selector can show
   and test both engines.
2. The kernel implements the C ABI in
   `network-extension/RustExtension/include/billow_ios_vpn.h`
   (`native-kernel/crates/billow-kernel/src/ios_vpn.rs`, `--features ios-vpn`):
   `billow_ios_vpn_start(port, ctx, home, &err)`,
   `billow_ios_vpn_drain(packets, maxCount, &count)`,
   `billow_ios_vpn_write(packet, length)`, `billow_ios_vpn_stop()`,
   `billow_ios_vpn_version(buf, size)`, `billow_ios_vpn_selected()`,
   `billow_ios_vpn_set_home(home)`, `billow_ios_vpn_reload(&err)`,
   `billow_ios_vpn_stats(buf, size)`, `billow_ios_vpn_free_error(err)`.
   `billow_ios_vpn_selected()` returns 1 when the app state selects the Rust
   kernel, 0 for Mihomo and -1 before any state exists (BillowRust reports
   code 10 `hostNotReady` then). The state is the App Group file
   `<AppGroup>/engine.json` (`{"selected":"rust"}`), written by
   `BillowVPNManager.setSelected`; `billow_ios_vpn_set_home` records the
   directory because `selected` has no path argument.
3. `home` is `<AppGroup>/versions/<active>/` with the validated `config.yaml`
   and assets; Rust parses it there and keeps all state under that directory.
4. Data path: `packetFlow.readPackets` -> `BillowRustEngine.rustIngest` ->
   `billow_rust_kernel_write` (the documented `billow_ios_vpn_write`, one
   record = `[4-byte big-endian length][IP packet]`). Egress goes through the
   `port->write` callback into `packetFlow.writePackets`; `drain` exists for
   polling hosts and tests (its buffer must hold `maxCount * (4 + 65535)`).
   Inside `libapp.a` the userspace IP stack terminates the device's TCP
   (`tunnel/tcp_server.rs`) and UDP (`tunnel/udp.rs`), routes every flow
   through the engine (rules, groups, `dialer-proxy`, DIRECT, DNS `:53`
   hijack) and emits reply packets. IPv4 fragments, IPv6 extension headers,
   ICMP and unhandled protocols are refused and counted by name.
5. Error/status parity: a Rust start failure is mapped by
   `BillowRustEngine` to `BillowVPNError.domain` code 2 with the Rust message
   (code 4 unlinked, code 10 `hostNotReady`); the status reply now also carries
   a `stats` object (`billow_ios_vpn_stats`: counters, high-water marks,
   `peakRssBytes`) and `reload` re-reads `config.yaml` (see
   `docs/testing/2026-11-23-ios-rust-extension-memory.md` for the R3/R4
   sampling entry).
6. `tool/ios/verify-rust-kernel.sh` compiles
   `tool/ios/rust-kernel-smoke.c` against the simulator archive and runs it in
   the booted simulator: version, stats, the missing-config error, start with a
   real `config.yaml`, one UDP datagram through DIRECT to a host echo server
   and back through `port->write`, reload, stop and restart. It is a code/ABI
   smoke, not a device memory measurement.
7. Configuration staging is implemented on both sides (T7-A2). The host
   `ios_vpn_prepare_active` writes the active profile's effective YAML plus
   referenced rule sets and the four geo assets into a staging directory,
   rewriting paths to basenames, then `ios_vpn_prepare` copies it into
   `versions/<version>`. Inside the extension `stage_config` reads the shared
   `config.yaml` and writes `config.rust.yaml` in the same `home`:
   - `mixed-port` (and any other listener key) is preserved because the engine
     binds its mixed listener;
   - `tun.enable: true` is removed with a stable warning, because the iOS
     Packet Tunnel already owns the device route (Mihomo keeps the original
     block in `config.yaml`);
   - `rule-providers.*.path` / `proxy-providers.*.path` files outside the
     version directory are copied next to the config and rewritten to their
     basenames.
   `reload` re-reads the shared `config.yaml`, restages `config.rust.yaml` and
   then reloads the engine. Extra `billow_rust_kernel_drain` derives its record
   count from the caller's byte capacity.

For the reverse path (Rust packets into mihomo for fair switching), the
Mihomo archive exports `GoMihomoLoopbackStart("127.0.0.1:<port>", fraction)`:
the Rust data plane forwards selected TCP/UDP to it, and those flows go
through mihomo's rules/DNS. T3 did not verify this path (needs T7).
