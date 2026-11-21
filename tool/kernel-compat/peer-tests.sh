#!/bin/sh
# Controlled real-peer run for the Rust kernel (native-kernel/tests/mihomo_peers.rs).
#
# The peer tests are #[ignore]d by default. The cargo test process starts the
# peer from its own working directory (native-kernel/crates/billow-kernel), so
# KC_MIHOMO_BIN must be an absolute path; this script resolves the repository
# root, the locked cache and the pinned binary, then runs the cases serially.
#
#   tool/kernel-compat/peer-tests.sh
#   KC_MIHOMO_BIN=/abs/path/mihomo tool/kernel-compat/peer-tests.sh <test filter>
#
# A missing baseline is fetched and checksum-verified with baseline.mjs, which
# uses the version and checksum pinned by src-tauri/desktop-kernel.json.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cache=${KC_CACHE_DIR:-"$root/tool/kernel-compat/.cache"}

if [ -n "${KC_MIHOMO_BIN:-}" ]; then
    bin=$KC_MIHOMO_BIN
else
    bin=$(node "$root/tool/kernel-compat/baseline.mjs" --json --cache "$cache" 2>/dev/null \
        | sed -n 's/.*"binary": *"\([^"]*\)".*/\1/p')
fi

if [ -z "$bin" ] || [ ! -x "$bin" ]; then
    echo "no pinned Mihomo binary: set KC_MIHOMO_BIN or run" >&2
    echo "  node tool/kernel-compat/baseline.mjs --cache $cache" >&2
    exit 2
fi

case "$bin" in
    /*) ;;
    *) bin=$(CDPATH= cd -- "$(dirname -- "$bin")" && pwd)/$(basename -- "$bin") ;;
esac

echo "peer: $bin" >&2
KC_MIHOMO_BIN="$bin" cargo test \
    --manifest-path "$root/native-kernel/Cargo.toml" --locked \
    --test mihomo_peers -- --ignored --test-threads=1 "$@"
