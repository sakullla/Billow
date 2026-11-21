#!/bin/sh
# Controlled peer run for the families the pinned Mihomo has no listener for.
#
# The peers are local processes/threads, not Mihomo:
#   - gost-relay: a loopback relay v2 server in tests/protocols.rs, written from
#     transport/gost/relay.go (request/response header, auth, address feature).
#   - ssh: a loopback SSH server built on russh, accepting password/public-key
#     auth and opening direct-tcpip channels.
#   - ssr: a loopback SSR server for `protocol: origin`/`obfs: plain`, plus the
#     pinned Go cipher vectors in tool/kernel-compat/peers/ssr-cipher-vectors.
#
# The Rust peer cases are part of the default `cargo test` suite too; this
# script is the explicit controlled entry point and also checks that the Go
# cipher vectors still match the pinned source. It needs `go` (and network
# access on the first run, because the vector program imports the locked tree).
#
#   tool/kernel-compat/family-peers.sh
#   tool/kernel-compat/family-peers.sh gost_relay   # pass a test filter
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
filter=${1:-}

echo "== pinned SSR cipher vectors (Go) =="
vectors=$(cd "$root/tool/kernel-compat/peers/ssr-cipher-vectors" && go run .)
printf '%s\n' "$vectors"
printf '%s\n' "$vectors" | grep -q 'AES-256-CFB .*cipher=7af17ea8b72264fd45cbcfa97a61a72460' || {
    echo "SSR cipher vector mismatch" >&2
    exit 1
}
printf '%s\n' "$vectors" | grep -q 'XCHACHA20 .*cipher=63d6daa424afc78a6f0ed041efd39daf31' || {
    echo "SSR xchacha20 vector mismatch" >&2
    exit 1
}

echo "== controlled Rust peers (gost-relay, ssh, ssr) =="
if [ -n "$filter" ]; then
    cargo test --manifest-path "$root/native-kernel/Cargo.toml" --locked \
        --test protocols -- --test-threads=1 "$filter"
else
    for filter in gost_relay ssh_outbound ssr_outbound; do
        cargo test --manifest-path "$root/native-kernel/Cargo.toml" --locked \
            --test protocols -- --test-threads=1 "$filter"
    done
fi
