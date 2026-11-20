#!/usr/bin/env bash
# Reproducible iOS build of the two Packet Tunnel extensions and the
# xcodegen project of the host (Mihomo + Rust placeholder).
#
#   tool/ios/build.sh [--platform device|simulator|all] [--sign]
#
# Step 1 downloads the pinned mihomo source (network access on first run; cached in a temp dir).
#
# Steps
#   1. node tool/ios/build-mihomo-ios.mjs --platform device|simulator
#        pinned MetaCubeX/mihomo v1.19.34 c-archive + Swift module header
#   2. (cd src-tauri/gen/apple && xcodegen generate)
#        project.yml is the only source of truth for billow.xcodeproj
#   3. xcodebuild build -sdk iphoneos|iphonesimulator CODE_SIGNING_ALLOWED=NO
#        for BillowMihomo and BillowRust
#   4. (signed only) `npx tauri ios build` builds libapp.a through the
#      "Build Rust Code" script and the host, then exports the IPA
#
# The host target cannot be compiled by plain xcodebuild without signing:
# its pre-build script calls `tauri ios xcode-script`, which only works inside
# a running `tauri ios build` session. Unsigned host compile evidence is the
# xcodegen + `xcodebuild -list`/`-showBuildSettings` output and the signed
# command below (see tool/ios/verify-device.md).
#
# --sign signs with the identity of DEVELOPMENT_TEAM and exports the IPA.
set -euo pipefail

cd "$(dirname "$0")/../.."
root=src-tauri/gen/apple
platforms=(device)
sign=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform) platforms=("$2"); shift 2 ;;
    --sign) sign=1; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
if [[ "${platforms[0]}" == all ]]; then
  platforms=(device simulator)
fi

for platform in "${platforms[@]}"; do
  node tool/ios/build-mihomo-ios.mjs --platform "$platform"
done

# xcodegen rejects a missing Externals source directory; the Rust build script
# creates it during a signed build, so provide it for the unsigned path too.
mkdir -p "$root/Externals/arm64/device" "$root/Externals/arm64/simulator"
(cd "$root" && xcodegen generate)
# BillowRust's base configuration is rewritten by its "Resolve Rust kernel"
# phase; xcodebuild needs the file to exist before any phase runs, so seed the
# unlinked fallback first (the phase replaces it on every build).
mkdir -p "$root/build/rust-kernel"
(cd "$root" && sh network-extension/RustExtension/resolve-mihomo.sh)

build_extensions() {
  local sdk=$1 dest=$2
  for target in BillowMihomo BillowRust; do
    echo "== xcodebuild $target ($sdk)"
    if (cd "$root" && xcodebuild build \
      -project billow.xcodeproj -scheme "$target" -configuration debug \
      -sdk "$sdk" -destination "$dest" CODE_SIGNING_ALLOWED=NO -quiet); then
      echo "ok $target ($sdk)"
    else
      echo "failed $target ($sdk)" >&2
      exit 1
    fi
  done
}

for platform in "${platforms[@]}"; do
  if [[ "$platform" == device ]]; then
    build_extensions iphoneos "generic/platform=iOS"
  else
    build_extensions iphonesimulator "generic/platform=iOS Simulator"
  fi
done

echo "== host project (xcodegen check: targets/schemes)"
(cd "$root" && xcodebuild -list -project billow.xcodeproj)

if [[ $sign -eq 1 ]]; then
  echo "== signed host + IPA via tauri ios build"
  npm run build
  npx tauri ios build --export-method debugging --ci
fi
