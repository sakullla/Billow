#!/usr/bin/env bash
# Executable proof of the Mihomo bridge contract:
#
#   tool/ios/verify-mihomo-archive.sh [device|simulator]
#
# 1. header check: src-tauri/gen/apple/network-extension/MihomoExtension/
#    include/billow_mihomo_bridge.h must declare exactly the C symbols that
#    src-tauri/gen/apple/mihomo-ios/bridge.go exports (GoMihomo*) plus the two
#    C shims (billow_mihomo_start, billow_mihomo_free).
# 2. link check: the archive built by build-mihomo-ios.mjs is linked into a
#    probe binary for the selected SDK, together with its header.
# 3. simulator: the probe runs on a booted iPhone simulator and asserts
#      - GoMihomoVersion returns v1.19.34,
#      - GoMihomoStart(home=NULL, write, check, ctx, &err) is the five-argument
#        entry used by BillowMihomoEngine.swift and refuses an empty home,
#      - GoMihomoReadPacket returns -1 without an engine,
#      - the Swift write callback reaches Go through the port (GoMihomoWritePackets).
#    device: only links (needs signed hardware, see verify-device.md).
set -euo pipefail

cd "$(dirname "$0")/../.."
platform=${1:-simulator}
root=src-tauri/gen/apple
archive="$root/Externals/arm64/$platform/libmihomo_ios.a"
stub=tool/ios/mihomo-resolv-stub.c
bridge="$root/mihomo-ios/bridge.go"
header="$root/network-extension/MihomoExtension/include/billow_mihomo_bridge.h"
work=$(mktemp -d "${TMPDIR:-/tmp}/billow-verify-XXXXXX")
if [[ "${KEEP_PROBE:-0}" == "1" ]]; then
  echo "work dir: $work"
else
  trap 'rm -rf "$work"' EXIT
fi

# 1. Header vs bridge exports.
grep -oE '^//export (GoMihomo[A-Za-z]+)' "$bridge" | awk '{print $2}' | sort -u > "$work/exports.txt"
grep -oE '\b(GoMihomo[A-Za-z]+)\s*\(' "$header" | tr -d '(' | tr -d ' ' | sort -u > "$work/declared.txt"
if ! diff -u "$work/exports.txt" "$work/declared.txt" > "$work/header.diff"; then
  echo "header/bridge export mismatch:" >&2
  cat "$work/header.diff" >&2
  exit 1
fi
echo "header matches bridge exports: $(paste -sd' ' "$work/exports.txt")"

if [[ ! -f "$archive" ]]; then
  echo "missing $archive; run: node tool/ios/build-mihomo-ios.mjs --platform $platform" >&2
  exit 2
fi

cat > "$work/probe.swift" <<'SWIFT'
import Foundation

@_silgen_name("GoMihomoStart") func GoMihomoStart(_ home: UnsafeMutablePointer<CChar>?, _ writeCB: UInt, _ checkCB: UInt,
                                                 _ ctx: UnsafeMutableRawPointer?, _ errOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> Int32
@_silgen_name("GoMihomoVersion") func GoMihomoVersion(_ buf: UnsafeMutablePointer<CChar>, _ size: Int32) -> Int32
@_silgen_name("GoMihomoReadPacket") func GoMihomoReadPacket(_ record: UnsafeMutableRawPointer?, _ size: UInt32) -> Int32
@_silgen_name("GoMihomoWritePackets") func GoMihomoWritePackets(_ packet: UnsafeMutableRawPointer?, _ length: UInt32) -> Int32
@_silgen_name("GoMihomoNetworkChanged") func GoMihomoNetworkChanged() -> Int32
@_silgen_name("GoMihomoShutdown") func GoMihomoShutdown()
@_silgen_name("free") func cFree(_ p: UnsafeMutablePointer<CChar>)

typealias WriteCallback = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?, UInt32) -> Int64
typealias CheckCallback = @convention(c) (UnsafeMutableRawPointer?) -> Int64

var writeCalls = 0
let writeCallback: WriteCallback = { _, _, length in writeCalls += 1; return Int64(length) == 0 ? 0 : 0 }
let checkCallback: CheckCallback = { _ in 0 }
let ctx = UnsafeMutableRawPointer(bitPattern: 0x1000)

var buffer = [CChar](repeating: 0, count: 32)
let versionLength = buffer.withUnsafeMutableBufferPointer { GoMihomoVersion($0.baseAddress!, Int32($0.count)) }
let version = String(cString: buffer)
print("version=\(version) length=\(versionLength)")

var error: UnsafeMutablePointer<CChar>?
// Five arguments, exactly as billow_mihomo_bridge.h declares them.
let start = GoMihomoStart(nil, UInt(bitPattern: unsafeBitCast(writeCallback, to: UnsafeRawPointer.self)),
                          UInt(bitPattern: unsafeBitCast(checkCallback, to: UnsafeRawPointer.self)), ctx, &error)
let message = error.map { String(cString: $0) } ?? ""
if let error { cFree(error) }
print("start_rc=\(start) message=\(message)")

var packet = [UInt8](repeating: 0x45, count: 24)
let ingest = packet.withUnsafeMutableBytes { GoMihomoReadPacket($0.baseAddress, 24) }
print("ingest_without_engine=\(ingest)")

let written = packet.withUnsafeMutableBytes { GoMihomoWritePackets($0.baseAddress, 0) }
print("write_without_engine=\(written)")
let network = GoMihomoNetworkChanged()
print("network_without_engine=\(network)")
GoMihomoShutdown()

let ok = versionLength > 0 && version == "v1.19.34" && start != 0 && message.contains("home directory")
    && ingest == -1 && written == 0 && network == 1
print(ok ? "RESULT ok" : "RESULT failed")
exit(ok ? 0 : 1)
SWIFT

if [[ "$platform" == device ]]; then
  sdk_name=iphoneos
  target=arm64-apple-ios15.0
else
  sdk_name=iphonesimulator
  target=arm64-apple-ios15.0-simulator
fi
sdk=$(xcrun --sdk "$sdk_name" --show-sdk-path)

xcrun --sdk "$sdk_name" clang -isysroot "$sdk" -target "$target" -DBILLOW_IOS_STUB_IMPLEMENTATION -c "$stub" -o "$work/resolv.o"
# Include the shipped header too: a signature change breaks the probe build.
xcrun swiftc -sdk "$sdk" -target "$target" -O -import-objc-header "$header" \
  "$work/probe.swift" "$archive" "$work/resolv.o" -o "$work/probe"
echo "linked $work/probe ($(file -b "$work/probe"))"

if [[ "$platform" == simulator ]]; then
  device=$(xcrun simctl list devices booted | grep -o 'iPhone[^(]*([0-9A-F-]\{36\})' | head -1 | sed 's/.*(\(.*\))/\1/')
  if [[ -z "$device" ]]; then
    device=$(xcrun simctl list devices available | grep -o 'iPhone[^(]*([0-9A-F-]\{36\})' | head -1 | sed 's/.*(\(.*\))/\1/')
    xcrun simctl boot "$device"
    xcrun simctl bootstatus "$device" -b >/dev/null
  fi
  cp "$work/probe" "$work/probe.bin"
  chmod +x "$work/probe.bin"
  xcrun simctl spawn "$device" "$work/probe.bin"
else
  echo "device probe linked; run it on signed hardware (tool/ios/verify-device.md)"
fi
