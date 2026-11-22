#!/usr/bin/env bash
# Compiles tool/ios/rust-kernel-smoke.c against the iOS-simulator Rust kernel
# archive and runs it inside the booted simulator (T7).
#
#   tool/ios/verify-rust-kernel.sh [--platform simulator|device]
#
# The simulator run is real iOS code (the same libapp.a the BillowRust
# extension links), but it is not a device measurement: R3/R4 on a physical
# iPhone still needs the hardware (tool/ios/verify-device.md).
set -euo pipefail

cd "$(dirname "$0")/../.."
platform=simulator
while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform) platform=$2; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

if [[ "$platform" != simulator ]]; then
  echo "error: only the simulator smoke is automated; a device run needs signing (see tool/ios/verify-device.md)" >&2
  exit 2
fi

archive=src-tauri/gen/apple/Externals/arm64/simulator/rust/libapp.a
if [[ ! -f "$archive" ]]; then
  node tool/ios/build-rust-kernel.mjs --platform simulator
fi

sdk_path=$(xcrun --sdk iphonesimulator --show-sdk-path)
sdk_version=$(xcrun --sdk iphonesimulator --show-sdk-version)
out=$(mktemp -d "${TMPDIR:-/tmp}/billow-smoke.XXXXXX")
binary="$out/rust-kernel-smoke"

echo "== clang rust-kernel-smoke (arm64-apple-ios${sdk_version}-simulator)"
xcrun -sdk iphonesimulator clang \
  -target "arm64-apple-ios${sdk_version}-simulator" \
  -isysroot "$sdk_path" \
  -O1 -g \
  -I src-tauri/gen/apple/network-extension/RustExtension/include \
  tool/ios/rust-kernel-smoke.c \
  "$archive" \
  -framework Security -framework SystemConfiguration -framework CoreFoundation \
  -lc++ \
  -o "$binary"

if ! xcrun simctl list devices booted | grep -q "Booted"; then
  echo "error: no booted simulator; boot one with 'xcrun simctl boot <device>'" >&2
  exit 2
fi

port_file="$out/echo-port"
node -e '
const socket = require("node:dgram").createSocket("udp4");
socket.on("message", (message, remote) => socket.send(message, remote.port, remote.address));
socket.bind(0, "127.0.0.1", () => console.log(socket.address().port));
' >"$port_file" &
echo_pid=$!
trap 'kill "$echo_pid" 2>/dev/null || true; rm -rf "$out"' EXIT
for _ in $(seq 1 50); do
  [[ -s "$port_file" ]] && break
  sleep 0.1
done
echo_port=$(head -1 "$port_file")
echo "== simctl spawn booted rust-kernel-smoke (UDP echo :$echo_port on the host)"
xcrun simctl spawn booted "$binary" "$echo_port"
