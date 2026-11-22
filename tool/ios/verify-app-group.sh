#!/usr/bin/env bash
# Compiles the real App Group resource code for the host and runs the
# dual-engine manifest smoke (T7). No signing or device is needed.
#
#   tool/ios/verify-app-group.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
out=$(mktemp -d "${TMPDIR:-/tmp}/billow-app-group.XXXXXX")
trap 'rm -rf "$out"' EXIT
binary="$out/app-group-manifest-smoke"

xcrun swiftc \
  -D BILLOW_ENGINE_RUST \
  -target "$(uname -m)-apple-macosx13.0" \
  -o "$binary" \
  src-tauri/gen/apple/network-extension/Shared/AppGroupStore.swift \
  src-tauri/gen/apple/network-extension/Shared/ProviderSupport.swift \
  src-tauri/gen/apple/network-extension/Shared/BillowVPNError.swift \
  tool/ios/app-group-manifest-smoke.swift \
  -framework CryptoKit -framework NetworkExtension

"$binary"
