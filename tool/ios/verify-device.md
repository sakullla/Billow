# Device verification entry (T3 / T7) — NOT EXECUTED

T3 ran on macOS 27.2 / Xcode 27.2 / Go 1.26.2 with no Apple signing identity
assigned to a Team, no provisioned device and no controlled remote endpoint.
Everything below needs that environment.

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
5. Prepare resources (host Settings, T6): stage config.yaml + geo, call
   `ios_vpn_prepare`, then `ios_vpn_connect(engine: "mihomo", version)`.
   `ios_vpn_prepare` validates both engines' names, so the same version can be
   started by either extension.
6. Check identity: `ios_vpn_status("mihomo")` reports
   `extensionId == app.billow.client.mihomo` and the embedded version
   `v1.19.34`; VPN system icon appears; `ios_vpn_status("rust")` reports a
   stable per-engine state: with `Externals/arm64/rust/libapp.a` linked
   (T7 kernel) `billow_ios_vpn_version` non-empty and `running` false while
   not connected; without the archive code 4 (`engineNotAvailable`) written to
   `status/rust.json`. Selecting "rust" and starting must produce exactly one
   completion: connected, or the mapped error (4, 10 `hostNotReady`, or 2 with
   the Rust message).
7. Traffic: request the controlled TCP HTTP endpoint and a UDP DNS query to
   the controlled resolver from another app; confirm payloads on the server
   side and the VPN interface via `nscurl`/app logs.
8. Stop/restart three times (`ios_vpn_disconnect`/`connect`); each start must
   report a fresh `startedAt` and no stale error; re-check after a Wi-Fi ->
   cellular switch (path monitor re-applies settings).
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

Build the kernel archive before the host build and keep the extension linked
(`resolve-mihomo.sh` prints `BillowRust: linking Rust kernel <path>`):

```sh
node tool/ios/build-rust-kernel.mjs --platform device
(cd src-tauri/gen/apple && SRCROOT="$PWD" SDKROOT="$(xcrun --sdk iphoneos --show-sdk-path)" \
  sh network-extension/RustExtension/resolve-mihomo.sh)
```

Simulator smoke (no signing): `tool/ios/verify-rust-kernel.sh` — version,
stats, missing-config error, start with a real `config.yaml`, one UDP datagram
through DIRECT to a host echo server and back through `port->write`, reload,
stop/restart. It proves the ABI and the data path on the simulator only.

Device checks that still need the iPhone:

1. `ios_vpn_status("rust")` reports `extensionId == app.billow.client.rust`,
   the embedded `billow-rust 0.1.0`, and `stats.peakRssBytes` once running.
2. Start the Rust extension from the app's real settings screen with the same
   configuration version the Mihomo extension uses (`status/<engine>.json`
   both present, exactly one start completion).
3. Traffic both ways: a controlled TCP HTTP request and a UDP DNS query from
   another app; confirm the payloads at the endpoint and in
   `status/rust.json`/`stats` (`tcpOpened`, `udpReplies`, `dnsQueries`).
4. `reload` from the host (`ProviderCommand.reload`) returns ok and `stats`
   shows `generation` +1, `tcpFlows == 0`.
5. Memory and reclaim: follow
   `docs/testing/2026-11-23-ios-rust-extension-memory.md` (R3 ≤ 40,000,000
   bytes `phys_footprint` per scenario, R4 repeatable idle baseline). Attach
   `xctrace --template 'VM Tracker' --attach BillowRust`; record device model,
   iOS version, app build, PID and the stats JSON for every scenario.
6. Failure paths: missing `config.yaml` → code 2 with the path; unlinked
   archive → code 4; no `engine.json` → code 10.

No device was connected during T7-A1, so none of the device items above have
results; the simulator smoke and the host tests are recorded in
`tool/kernel-compat/evidence/t7-ios-ffi.md`.
