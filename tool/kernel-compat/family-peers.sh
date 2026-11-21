#!/bin/sh
# Controlled peer run for the families the pinned Mihomo has no listener for.
#
# The peers are local processes/threads, not Mihomo:
#   - gost-relay: a loopback relay v2 server in tests/protocols.rs, written from
#     transport/gost/relay.go (request/response header, auth, address feature,
#     the UDP association and the version-1 smux session).
#   - ssh: a loopback SSH server built on russh, accepting password/public-key
#     auth and opening direct-tcpip channels.
#   - ssr: the Go peer in tool/kernel-compat/peers/ssr-plugins is the server side
#     of the pinned `protocol/*` and `obfs/*` wire formats (cipher + every
#     protocol plugin + every obfs plugin + the UDP association). The same
#     program runs the *pinned* client packages against itself (`-client`), so
#     the Rust client is checked against a peer that the locked client accepts.
#     tool/kernel-compat/peers/ssr-cipher-vectors prints the pinned cipher
#     keystreams.
#
# The Rust peer cases are part of the default `cargo test` suite too; this
# script is the explicit controlled entry point and also runs the pinned-client
# cross-check. It needs `go` (the replace directive points at the locked source
# tree under tool/kernel-compat/.cache/source).
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

echo "== independent Go SSR server (origin/plain) =="
peer_bin=$(mktemp "${TMPDIR:-/tmp}/billow-ssr-server.XXXXXX")
(cd "$root/tool/kernel-compat/peers/ssr-server" && GOFLAGS=-mod=mod go build -o "$peer_bin" .)

echo "== independent Go SSR plugin peer =="
plugins_bin=$(mktemp "${TMPDIR:-/tmp}/billow-ssr-plugins.XXXXXX")
(cd "$root/tool/kernel-compat/peers/ssr-plugins" && GOFLAGS=-mod=mod go build -o "$plugins_bin" .)
echo "-- pinned XorShift128Plus vectors --"
"$plugins_bin" -vectors

echo "-- pinned client packages against the plugin peer (every protocol x obfs) --"
"$plugins_bin" -echo -listen 127.0.0.1:0 >"$plugins_bin.addr" 2>/dev/null &
echo_pid=$!
trap 'kill $echo_pid 2>/dev/null || true' EXIT INT TERM
i=0
while [ ! -s "$plugins_bin.addr" ] && [ "$i" -lt 50 ]; do
    sleep 0.1
    i=$((i + 1))
done
echo_addr=$(head -n 1 "$plugins_bin.addr" | sed 's/^READY //')

port=18400
cases=0
for protocol in origin auth_sha1_v4 auth_aes128_md5 auth_aes128_sha1 auth_chain_a auth_chain_b; do
    for obfs in plain http_simple http_post random_head tls1.2_ticket_auth tls1.2_ticket_fastauth; do
        port=$((port + 1))
        "$plugins_bin" -listen "127.0.0.1:$port" -cipher aes-256-cfb -password ssr-plugin-pass \
            -protocol "$protocol" -obfs "$obfs" >/dev/null 2>&1 &
        peer=$!
        sleep 0.2
        out=$("$plugins_bin" -client -listen "127.0.0.1:$port" -cipher aes-256-cfb \
            -password ssr-plugin-pass -protocol "$protocol" -obfs "$obfs" \
            -target "$echo_addr" -marker "pinned-$protocol-$obfs" 2>&1 || true)
        kill $peer 2>/dev/null || true
        wait $peer 2>/dev/null || true
        case "$out" in
            *"CLIENT OK"*) ;;
            *)
                echo "pinned client failed for $protocol/$obfs: $out" >&2
                exit 1
                ;;
        esac
        cases=$((cases + 1))
    done
done
echo "pinned client accepted $cases protocol/obfs combinations"
kill $echo_pid 2>/dev/null || true
wait $echo_pid 2>/dev/null || true

echo "== Rust client against the same Go peer (matrix, auth failure, large payloads, UDP) =="
KC_SSR_PEER_BIN="$peer_bin" KC_SSR_PLUGINS_BIN="$plugins_bin" cargo test \
    --manifest-path "$root/native-kernel/Cargo.toml" --locked \
    --test independent_peers -- --ignored --test-threads=1

echo "== controlled Rust peers (gost-relay incl. udp/mux, ssh, ssr origin/plain) =="
if [ -n "$filter" ]; then
    cargo test --manifest-path "$root/native-kernel/Cargo.toml" --locked \
        --test protocols -- --test-threads=1 "$filter"
else
    for filter in gost_relay ssh_outbound ssr_outbound; do
        cargo test --manifest-path "$root/native-kernel/Cargo.toml" --locked \
            --test protocols -- --test-threads=1 "$filter"
    done
fi
