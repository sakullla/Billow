# Device verification entry (T3) — NOT EXECUTED

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
6. Check identity: `ios_vpn_status("mihomo")` reports
   `extensionId == app.billow.client.mihomo` and the embedded version
   `v1.19.34`; VPN system icon appears; `ios_vpn_status("rust")` still reports
   the placeholder failure code 4.
7. Traffic: request the controlled TCP HTTP endpoint and a UDP DNS query to
   the controlled resolver from another app; confirm payloads on the server
   side and the VPN interface via `nscurl`/app logs.
8. Stop/restart three times (`ios_vpn_disconnect`/`connect`); each start must
   report a fresh `startedAt` and no stale error; re-check after a Wi-Fi ->
   cellular switch (path monitor re-applies settings).
9. Failure paths: corrupt a file in `versions/<v>/` -> start must fail with
   code 1 (fileMismatch) and the previous version must stay listed; remove
   the App Group entitlement -> code 1 "App Group unavailable".

Record device, iOS version, app build, each status JSON and server captures
in the T3/T7 evidence notes. Exit criteria for T3 here: one start/stop cycle
with a Mihomo status showing the pinned version and one controlled TCP and
UDP exchange observed at the endpoint.
