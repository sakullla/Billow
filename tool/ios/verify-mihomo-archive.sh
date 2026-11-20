#!/usr/bin/env bash
# Links the built Mihomo c-archive into a probe binary for one SDK and runs it
# on the simulator when possible. This is the executable proof that the
# libmihomo_ios.a produced by build-mihomo-ios.mjs is a linkable iOS archive.
#
#   tool/ios/verify-mihomo-archive.sh [device|simulator]
#
# device:    links an arm64 iOS 15 executable (not runnable here without a
#            signed device; exit status 0 means "linked").
# simulator: links for arm64-apple-ios15.0-simulator and runs the probe in a
#            booted iPhone simulator; the probe asserts that the engine
#            refuses to start without an App Group home directory.
set -euo pipefail

cd "$(dirname "$0")/../.."
platform=${1:-simulator}
root=src-tauri/gen/apple
archive="$root/Externals/arm64/$platform/libmihomo_ios.a"
stub=tool/ios/mihomo-resolv-stub.c
work=$(mktemp -d "${TMPDIR:-/tmp}/billow-verify-XXXXXX")
trap 'rm -rf "$work"' EXIT

if [[ ! -f "$archive" ]]; then
  echo "missing $archive; run: node tool/ios/build-mihomo-ios.mjs --platform $platform" >&2
  exit 2
fi

cat > "$work/probe.swift" <<'SWIFT'
import Foundation

@_silgen_name("GoMihomoVersion") func GoMihomoVersion(_ buf: UnsafeMutablePointer<CChar>, _ size: Int32) -> Int32
@_silgen_name("GoMihomoStart") func GoMihomoStart(_ home: UnsafeMutablePointer<CChar>, _ err: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32
@_silgen_name("GoMihomoReadPacket") func GoMihomoReadPacket(_ record: UnsafeMutableRawPointer, _ size: UInt32) -> Int32
@_silgen_name("GoMihomoShutdown") func GoMihomoShutdown()

var buffer = [CChar](repeating: 0, count: 32)
let n = GoMihomoVersion(&buffer, Int32(buffer.count))
let version = String(cString: buffer)
print("version=\(version)")

var err: UnsafeMutablePointer<CChar>?
let rc = GoMihomoStart(UnsafeMutablePointer<CChar>(bitPattern: 0)!, &err)
let message = err.map { String(cString: $0) } ?? ""
print("start_rc=\(rc) message=\(message)")

var packet = [UInt8](repeating: 0, count: 24)
let ingest = GoMihomoReadPacket(&packet, 24)
print("ingest_without_engine=\(ingest)")
GoMihomoShutdown()

var ok = n > 0 && version == "v1.19.34" && rc != 0 && message.contains("home directory") && ingest == -1
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

xcrun --sdk "$sdk_name" clang -isysroot "$sdk" -target "$target" -c "$stub" -o "$work/resolv.o"
xcrun swiftc -sdk "$sdk" -target "$target" -O "$work/probe.swift" "$archive" "$work/resolv.o" -o "$work/probe"
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
