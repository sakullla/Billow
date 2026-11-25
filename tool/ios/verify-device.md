# Device verification entry (T3 / T7 / T29) — NOT EXECUTED

T3 ran on macOS 27.2 / Xcode 27.2 / Go 1.26.2 with no Apple signing identity
assigned to a Team, no provisioned device and no controlled remote endpoint.

T29 re-ran the unsigned/simulator side on 2026-11-24 (macOS 27.0, Xcode 27.2,
iOS 27.2 SDK, candidate `billow-kernel 0.1.0` sha256
`be00302e352abc51d36cb040183d2f9a927b04719e79e7261893a6f6a3e51521`):
`tool/ios/verify-rust-kernel.sh` passed, `tool/ios/verify-host-sources.sh`
passed, and all four `BillowRust`/`BillowMihomo` simulator/device builds
succeeded with `CODE_SIGNING_ALLOWED=NO`. The physical iPhone 15 Pro Max and
iPad are still `unavailable` in `xcrun devicectl list devices`, so every device
step below remains unexecuted. Simulator results are not R3/R4 evidence.

## Prerequisites

- Apple Developer Team with the Network Extension capability; bundle ids
  `app.billow.client`, `app.billow.client.mihomo`, `app.billow.client.rust`
  and App Group `group.app.billow.client` registered for all three.
- `DEVELOPMENT_TEAM=<team>` in `src-tauri/gen/apple/project.yml` (xcodegen
  setting) or passed with `xcodebuild DEVELOPMENT_TEAM=...`.
- iPhone UDID registered; trust the Mac.
- Controlled endpoints: an HTTP/TCP echo on a host you own and a DNS name
  served by a UDP resolver you control (record what the server observed).

## Steps

1. `node tool/ios/build-mihomo-ios.mjs --platform device`
2. `cd src-tauri/gen/apple && xcodegen generate`
3. Host + IPA: `npx tauri ios build --export-method debugging --ci`
   (runs "Build Rust Code" -> libapp.a, compiles host, embeds both extensions)
4. Install: `xcrun devicectl device install app --device <UDID> "<ipa or .app>"`
5. Prepare resources from the app's real settings page: Settings → 内核 →
   iOS 扩展 → **准备当前配置**. This calls `ios_vpn_prepare_active` (stage the
   active profile, rewrite referenced paths, copy geo) and
   `ios_vpn_prepare(version, engines = [mihomo, rust])`. The same
   `versions/<version>` must validate for both extensions; the command answers
   `{version, engines, files}` and the engine rows show the active version.
6. Check identity from the same card: the Mihomo row reports the embedded
   version `v1.19.34`; after **连接** the VPN system icon appears and
   `ios_vpn_status("mihomo")` reports
   `extensionId == app.billow.client.mihomo`. Select Rust and **连接** again:
   with `Externals/arm64/device/rust/libapp.a` linked, `ios_vpn_status("rust")`
   reports `billow-rust 0.1.0`; without the archive the row shows code 4
   (`engineNotAvailable`) from `status/rust.json`. Each connect must produce
   exactly one completion: connected, or the mapped error (4, 10
   `hostNotReady`, or 2 with the Rust message).
   **Current host surface:** `ios_vpn_status` returns
   `extensionId/engine/embeddedVersion/running/version/loopbackPort/loopbackListen/lastError/errorCode/startedAt/stats`.
   Both extensions now reply with the same `ProviderStatus` JSON as their
   `status/<engine>.json`, and `ProviderStatus.stats` carries the Rust
   extension's `billow_ios_vpn_stats` object. So `ios_vpn_status("rust").stats`
   exposes `generation/reloads/peakRssBytes/tcpFlows/queuedPackets/...` when the
   Rust extension is running; Mihomo and old builds return `null`. These are
   host-read values only: no device measurement exists yet, and R3 peak still
   comes from Instruments.
7. Traffic: request the controlled TCP HTTP endpoint and a UDP DNS query to
   the controlled resolver from another app; confirm payloads on the server
   side, the system VPN counters, and the extension logs. Structured
   `tcpOpened/udpReplies/dnsQueries` are part of
   `ios_vpn_status("rust").stats` (T7-A4 host passthrough); reading the
   extension log is still useful as a cross-check. Two device sockets to the
   same remote must not receive each other's UDP replies (per-flow NAT key).
8. Stop/restart three times (**断开** / **连接**); each start must report a
   fresh `startedAt` and no stale error; re-check after a Wi-Fi -> cellular
   switch (path monitor re-applies settings). **重载** calls
   `ios_vpn_reload`; verify traffic still flows and the extension reload log is
   present. `ios_vpn_status("rust").stats` must show `generation == +1` and
   `tcpFlows == 0` after the reload; `status/rust.json` keeps the snapshot
   written at reload/stop.
9. Failure paths: corrupt a file in `versions/<v>/` -> start must fail with
   code 1 (fileMismatch) and the previous version must stay listed; remove
   the App Group entitlement -> code 1 "App Group unavailable".
10. Runtime failure: after a connected Mihomo tunnel, break the network path
    (airplane mode toggle) and confirm the provider does not call the start
    completion again: the tunnel reasserts, `status/mihomo.json` records
    `networkUnavailable` (code 5) or the pump error, and the system restarts
    the extension. The same check applies after killing a Rust worker if T7
    surfaces a runtime error.

Record device, iOS version, app build, each status JSON and server captures
in the T3/T7 evidence notes. Exit criteria for T3 here: one start/stop cycle
with a Mihomo status showing the pinned version and one controlled TCP and
UDP exchange observed at the endpoint.

## T7 — Rust extension

Build both kernel archives before the host build and keep the extension
linked (`resolve-mihomo.sh` prints `BillowRust: linking Rust kernel <path>`):

```sh
node tool/ios/build-rust-kernel.mjs --platform all
# linked.xcconfig is read at project load, so resolve the device archive
# explicitly before a device build; otherwise a stale simulator path can be
# linked into the device appex (observed in T29).
(cd src-tauri/gen/apple && SRCROOT="$PWD" SDKROOT="$(xcrun --sdk iphoneos --show-sdk-path)" \
  sh network-extension/RustExtension/resolve-mihomo.sh)
xcodebuild -project src-tauri/gen/apple/billow.xcodeproj -scheme BillowRust \
  -configuration release -sdk iphoneos -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO build
```

For a simulator build, point `SDKROOT` at `iphonesimulator` (or let the
simulator archive be selected) before `xcodebuild -sdk iphonesimulator`; the
same toggle applies to `BillowMihomo`.

Simulator smoke (no signing): `tool/ios/verify-rust-kernel.sh` — version,
stats, missing-config error, start with a real `config.yaml`, one UDP datagram
through DIRECT to a host echo server and back through `port->write`, reload,
stop/restart. It proves the ABI and the data path on the simulator only.
Installing a standalone `.appex` with `simctl` and launching its bundle id
does **not** exercise the Packet Tunnel provider: T29's attempt crashed in
`NSExtensionMain` (`EXC_BREAKPOINT`) because no host app activated it. A real
check needs the signed host + provisioning profile on a device.

Device checks that still need the iPhone:

1. `ios_vpn_status("rust")` reports `extensionId == app.billow.client.rust`
   and the embedded `billow-rust 0.1.0` once running, plus `stats` from
   `billow_ios_vpn_stats` (T7-A4 host passthrough). R3 peak still comes from
   Instruments; `stats.peakRssBytes` is an RSS cross-check only.
2. Start the Rust extension from the app's real settings screen with the same
   configuration version the Mihomo extension uses (`status/<engine>.json`
   both present, exactly one start completion).
3. Traffic both ways: a controlled TCP HTTP request and a UDP DNS query from
   another app; confirm the payloads at the endpoint and in the extension
   logs. `ios_vpn_status("rust").stats` exposes
   `tcpOpened/udpReplies/dnsQueries`.
4. `reload` from the host (`ProviderCommand.reload`) returns ok and traffic
   continues. `ios_vpn_status("rust").stats` must show `generation` +1 and
   `tcpFlows == 0`; `status/rust.json` is a snapshot written at start/reload/
   stop, so use the live reply for per-round R4 values.
5. Memory and reclaim: follow
   `docs/testing/2026-11-23-ios-rust-extension-memory.md` (R3 ≤ 40,000,000
   bytes `phys_footprint` per scenario, R4 repeatable idle baseline). Use
   `xcrun xctrace record --template 'Allocations' --instrument 'VM Tracker'
   --attach <BillowRust-PID>` (`VM Tracker` is an instrument, not a template);
   record device model, iOS version, app build, PID and the raw trace. R4
   counters come from `ios_vpn_status("rust").stats`; no device run exists in
   this repository yet.
6. Failure paths: missing `config.yaml` → code 2 with the path; unlinked
   archive → code 4; no `engine.json` → code 10.

No device was connected during T7-A1 or T29-A1, so none of the device items
above have results. The T7 simulator/host records are in
`tool/kernel-compat/evidence/t7-ios-ffi.md`; the T29 re-run, exact build
commands, hashes and blockers are in
`tool/kernel-compat/evidence/t29-platform-matrix.md`.
