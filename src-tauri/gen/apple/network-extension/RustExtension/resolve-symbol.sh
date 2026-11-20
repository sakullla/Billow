#!/bin/sh
# Finds the Rust kernel archive (libapp.a) for the current SDK.
#
# Inputs: SRCROOT (gen/apple) and SDKROOT (set by Xcode when this file is
# compiled by the RustKernelBridge.c compile phase).
# Search order:
#   $SRCROOT/Externals/arm64/rust/libapp.a          (tool/ios/build.sh copy)
#   $SRCROOT/Externals/arm64/<platform>/rust/libapp.a
# Prints the absolute path, or nothing when absent.
# XcodeUserDefaultOverrides.plist (dev only): BILLOW_RUST_KERNEL_ARCHIVE
# overrides the search so a libapp.a built elsewhere can be exercised.
if [ -n "${BILLOW_RUST_KERNEL_ARCHIVE:-}" ] && [ -f "$BILLOW_RUST_KERNEL_ARCHIVE" ]; then
  printf '%s' "$BILLOW_RUST_KERNEL_ARCHIVE"
  exit 0
fi
if [ -z "${SRCROOT:-}" ] || [ -z "${SDKROOT:-}" ]; then
  exit 0
fi
platform_dir=device
case "$SDKROOT" in
  *iPhoneSimulator.platform*) platform_dir=simulator ;;
esac
for candidate in \
  "$SRCROOT/Externals/arm64/rust/libapp.a" \
  "$SRCROOT/Externals/arm64/$platform_dir/rust/libapp.a"; do
  if [ -f "$candidate" ]; then
    printf '%s' "$candidate"
    exit 0
  fi
done
exit 0
