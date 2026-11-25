#!/usr/bin/env bash
# Type-checks the real Swift source set of every iOS target with the
# compilation condition that target gets from project.yml. No signing, archive
# or device is needed, but every file in the target is included (nothing is
# excluded to hide an undefined symbol).
#
#   tool/ios/verify-host-sources.sh
#
# Catches the T7-A2 regression where the host compiled Shared/PacketPump.swift
# with BILLOW_ENGINE_MIHOMO and referenced the Go symbol that only the Mihomo
# extension links.
set -euo pipefail

cd "$(dirname "$0")/../.."
sdk=$(xcrun --sdk iphonesimulator --show-sdk-path)
target="arm64-apple-ios15.0-simulator"
root=src-tauri/gen/apple/network-extension
shared=("$root"/Shared/*.swift)
common=(-typecheck -swift-version 5 -target "$target" -sdk "$sdk")

echo "== host (BILLOW_ENGINE_HOST): billed target Sources = Shared + Host"
xcrun swiftc "${common[@]}" -D BILLOW_ENGINE_HOST \
  "${shared[@]}" "$root"/Host/*.swift
echo "   ok"

echo "== BillowMihomo (BILLOW_ENGINE_MIHOMO): Shared + MihomoExtension"
xcrun swiftc "${common[@]}" -D BILLOW_ENGINE_MIHOMO \
  "${shared[@]}" "$root"/MihomoExtension/*.swift
echo "   ok"

echo "== BillowRust (BILLOW_ENGINE_RUST): Shared + RustExtension"
xcrun swiftc "${common[@]}" -D BILLOW_ENGINE_RUST \
  -import-objc-header "$root/RustExtension/BillowRust-Bridging-Header.h" \
  -I "$root/RustExtension/include" \
  "${shared[@]}" "$root"/RustExtension/*.swift
echo "   ok"

echo "== ProviderStatus codec (reply + stats + status file keys)"
# Runs the real Shared model on the macOS host; no simulator/device needed.
cat "$root"/Shared/BillowVPNError.swift tool/ios/status-codec-smoke.swift | xcrun swift -

echo "== host non-Swift entry (Sources/billow/main.mm)"
xcrun clang++ -fsyntax-only -std=c++17 -target "$target" -isysroot "$sdk" \
  -I src-tauri/gen/apple/Sources/billow src-tauri/gen/apple/Sources/billow/main.mm
echo "   ok"

echo "ok: all three iOS Swift targets type-check with their own condition"
