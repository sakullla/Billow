# Kernel compatibility harness

Differential entry point for R2: it reads the shipped-kernel manifests, locks the matching
Mihomo v1.19.34 source, indexes its configuration surface, and runs the same fixture against
two explicitly provided kernel executables while recording what a controlled local endpoint
actually received. Since T4 the index also carries the Rust kernel's own coverage statement
per upstream entry, and the protocol families have real-peer evidence next to it.

## Commands

```sh
# Baseline binary named by src-tauri/desktop-kernel.json (checksum from the manifest)
node tool/kernel-compat/baseline.mjs --json --cache tool/kernel-compat/.cache

# Lock the Android-pinned source commit, verify its archive checksum and build the probe
node tool/kernel-compat/source.mjs --cache tool/kernel-compat/.cache

# Static capability index (fields, protocols, listeners, groups, rules, platforms, unmapped)
node tool/kernel-compat/capability.mjs --cache tool/kernel-compat/.cache \
  --out tool/kernel-compat/evidence/source-capabilities.json

# Rust kernel CLI (workspace member billow-kernel-cli, binary billow-kernel)
cargo build --release --manifest-path native-kernel/Cargo.toml --locked -p billow-kernel-cli

# Controlled peers for families with no Mihomo listener (gost-relay, ssh, ssr)
# and the T16/T19 device/mesh families (WireGuard via the locked wireguard-go
# device, OpenVPN 2.7.9 via the Homebrew binary with --dev null, and the
# tailscale/zerotier/EasyTier peers built from the locked Go modules),
# the independent Go SSR server and the pinned SSR stream-cipher vectors;
# needs `go`
tool/kernel-compat/family-peers.sh

# Black-box observation harness kept as the T17-A1 record (no Sudoku client
# existed then; T17-A2 translated the pinned module instead, see
# evidence/t17-translation.md). The harness spawns the release binary as both
# ends and records the wire through a loopback relay.
# needs `python3`, `curl`, `node`
python3 tool/kernel-compat/sudoku-observe.py probe
python3 tool/kernel-compat/sudoku-observe.py reject

# Option matrix: no-op forms must load in both engines, enabled forms must be
# rejected by the kernel with the field named (exit 1 on any violation)
node tool/kernel-compat/option-probe.mjs --rust <path-to-billow-kernel> \
  --mihomo <path-to-mihomo> --out tool/kernel-compat/evidence/option-matrix.txt

# Differential run; pass each kernel explicitly (repeatable --fixture, --report-name)
node tool/kernel-compat/runner.mjs \
  --mihomo <path-to-mihomo> --rust <path-to-billow-kernel> \
  --cache tool/kernel-compat/.cache --report-dir tool/kernel-compat/evidence \
  --fixture tool/kernel-compat/fixtures/direct-ip.yaml

# T24 rules/providers/GEO differential: the same rule and provider files are
# served from a loopback HTTP server and read from temp directories, then each
# CONNECT is sent to the pinned Mihomo and the Rust kernel. GeoSite.dat/
# GeoIP.dat are generated from the pinned protobuf shapes; MRS is the checked-in
# Tauri fixture. Pass --mmdb-dir with decompressed Country.mmdb/ASN.mmdb to add
# the MaxMind and IP-ASN cases (brotli -dk src-tauri/resources/runtime/geo/*.mmdb.br).
node tool/kernel-compat/t24-differential.mjs \
  --mihomo <path-to-mihomo> --rust <path-to-billow-kernel> \
  --out tool/kernel-compat/evidence/t24-differential.json \
  [--mmdb-dir <dir-with-Country.mmdb-and-ASN.mmdb>]

# T22 DNS/hosts/fake-ip differential: controlled UDP/TCP/DoT/DoH DNS fixtures
# with fixed answers, a silent port for the timeout case, and a loopback SOCKS5
# hop for respect-rules. Both engines answer on dns.listen with the same
# effective config; rcode/address/TTL and the CONNECT cases are compared.
node tool/kernel-compat/t22-differential.mjs \
  --mihomo <path-to-mihomo> --rust <path-to-billow-kernel> \
  --out tool/kernel-compat/evidence/t22-dns.json

# T23 group/selection/health differential: every member is a loopback HTTP
# CONNECT node (a health node answers the probe HEAD with a fixed or sequenced
# delay/status); Mihomo is driven through its external-controller and the Rust
# kernel through --select/--probe-groups/--print-groups. 27 cases plus the
# selection cache across a restart; the cases include startup/lazy probing for
# groups, providers and nested groups, the ten-second url-test computation
# cache, lazy re-probing of a nested group after its parent was probed,
# disabled-provider registration probing its own URL, empty-fallback/REJECT
# blocking, and a two-sample tolerance comparison.
node tool/kernel-compat/t23-differential.mjs \
  --mihomo <path-to-mihomo> --rust <path-to-billow-kernel> \
  --out tool/kernel-compat/evidence/t23-differential.json

# T25 control-API differential: the same YAML drives both external-controller
# listeners through auth failures, routing/status mistakes, CORS preflight,
# /configs GET/PATCH/PUT reload, selection/delay, providers (update success and
# failure), connections (list + DELETE), /traffic and /logs first frames, the
# Unix socket and the TLS listener. Both engines get a self-signed certificate
# generated with openssl inside each engine's home directory.
node tool/kernel-compat/t25-differential.mjs \
  --mihomo <path-to-mihomo> --rust <path-to-billow-kernel> \
  --out tool/kernel-compat/evidence/t25-differential.json

# T5 combined differential: one configuration with fake-ip DNS, hosts,
# yaml/text/mrs/http rule-providers, a proxy-provider, RULE-SET/GEOSITE/GEOIP
# rules, select/url-test/fallback groups, the controller and real ss/trojan/ssr
# outbounds. The ss/trojan peers are pinned Mihomo `listeners:` processes; the
# ssr peer is peers/ssr-server (built with go). The same CONNECT sequence
# compares DNS answers, rule outcome, group selection, provider update/reload
# semantics and what the echo receiver got. The generated Billow desktop/Android
# artifacts are loaded with --check/-t. Run `brotli -dk
# src-tauri/resources/runtime/geo/*.mmdb.br` and pass --mmdb-dir to add the T22
# mmdb `!geoip-code` case to that differential.
node tool/kernel-compat/t5-differential.mjs \
  --mihomo <path-to-mihomo> --rust <path-to-billow-kernel> \
  --out tool/kernel-compat/evidence/t5-integration.json \
  --effective-dir tool/kernel-compat/evidence/t5-effective
```

The Rust binary's path follows the cargo target directory: `native-kernel/target/release/billow-kernel`
in a default checkout, or `$CARGO_TARGET_DIR/release/billow-kernel` (for example
`~/.cache/cargo-target/release/billow-kernel`) when that variable is set. The runner never
guesses: pass the built path with `--rust`.

`node --test tool/kernel-compat/runner.test.mjs` is the acceptance command in the execution
plan. It downloads the pinned baseline and source on first use and caches them under
`tool/kernel-compat/.cache/` (gitignored); no source tree or binary is committed.

Exit status: 0 only when every provided engine passes every fixture and the locked-source
reference either passes or is not applicable. A missing engine (for example before T2 ships a
Rust executable) is recorded as `missing`, makes the run exit 2, and is never reported as
compatible.

## Engine command lines

The two engines are called differently; the runner adapts per engine and does not relax any
judgement for either:

| Engine | identity | config test | run | stop |
| --- | --- | --- | --- | --- |
| mihomo | `-v` (banner) | `-t -d <dir> -f <config>` | `-d <dir> -f <config>` | SIGTERM |
| rust (`billow-kernel`) | `--version` | `<config> --check --port <port>` | `<config> --port <port>` | SIGTERM |

The Rust CLI rejects `mixed-port: 0`, so the runner always passes the allocated port with
`--port` as well as writing it into the YAML. A Rust kernel start that fails before listening
is recorded as `startup-failed` with the CLI's own stderr (for example
`[unsupported] unsupported configuration: top-level key 'sniffer' with enable: true is not
implemented (sniffing is T7)`); that is the remaining coverage gap, never a pass. The Rust CLI accepts only
HTTP CONNECT (a forward GET is rejected with `405`/`unsupported_protocol`), so fixtures for it
use `method: connect`.

## Rust coverage and real-peer evidence

Two checked-in files describe what the Rust kernel does with the pinned version:

- `evidence/rust-mapping.json` — one status per upstream entry (`implemented`, `partial`,
  `unimplemented`), with the options it accepts, the options it rejects and the test that
  observes the behaviour. `capability.mjs` merges it into `source-capabilities.json` as
  `rustMapping` on every config field, protocol, listener, group and rule, and into
  `coverage` (`mapped` counts only `implemented` entries; `partial` names what is missing).
  An entry without a Rust statement is `unimplemented`, never compatible.
- `evidence/protocol-peers.json` (with `protocol-peers-run.log`) — the controlled real-peer
  matrix: each family (TCP and, for ss/trojan, UDP), its positive and negative cases, the
  exact test command, the peer binary identity and the platform condition. Loopback-only
  evidence that needs a test-controlled certificate or UDP echo is named separately. It is produced by
  `native-kernel/tests/mihomo_peers.rs` (ignored by default):

  ```sh
  # resolves the repository root, the cache and the pinned binary
  tool/kernel-compat/peer-tests.sh

  # or explicitly; cargo test runs from native-kernel/crates/billow-kernel,
  # so the path must be absolute
  KC_MIHOMO_BIN=/Users/yanggeng/github/Billow/tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
    cargo test --manifest-path native-kernel/Cargo.toml --locked \
    --test mihomo_peers -- --ignored --test-threads=1
  ```

  A family without a passing peer case is not recorded as verified. The log is the last
  complete passing run; the same command occasionally ends a case with the tunnel
  established but nothing received (the peer's log shows its listener up and no connection)
  after many cases in one test process, so the suite is run serially and rerun once in that
  case — a rerun is never recorded as a first-attempt pass.

  T10 added TUIC v5 and Hysteria2 to the same pinned-Mihomo matrix (their
  listeners are UDP-only, so the readiness check waits for the process instead
  of a TCP connect), plus Hysteria v1 against a controlled `quinn` server in
  `native-kernel/tests/quic_peers.rs` because the pinned tree has no Hysteria
  v1 listener. `evidence/t10-feasibility.json` records each family's status,
  the QUIC dependency profile (quinn 0.11.12, offline cache, missing
  h3/qpack/WireGuard/mesh crates), the device/TUN ownership (T6/T7) and
  the memory note T7 uses for the 40 MB budget. The TUIC/Hysteria2 wrong
  password cases are in the same matrix; the `quic_peers` cases are part of the
  default suite. `crates/billow-kernel-cli/tests/family_cli.rs` drives a real
  `billow-kernel` process tunnel through TUIC, Hysteria v1 and Hysteria2. The
  option matrix includes the three T10 families (184 no-op / 215 enabled,
  problems 0), including the Hysteria2 `up` rejection and the TUIC
  `request-timeout` use; `t10-feasibility.json` also records the Hysteria v1
  peer gap (no pinned Mihomo listener).

  T15 added `shadowquic` to the pinned-Mihomo matrix: TCP, UDP over QUIC
  datagrams, UDP over `udp-over-stream`, and a wrong-password case. JLS has no
  Rust crate, so `src/outbound/jls.rs` implements the seal in-tree and
  `peers/shadowquic-jls-vectors` uses the locked `jls-tls` package only to emit
  real hello vectors (committed under
  `native-kernel/crates/billow-kernel/tests/data/`). The full BSD-3-Clause
  license for `jls-tls` is in `native-kernel/THIRD_PARTY_NOTICES.md`; the
  ShadowQUIC transport provenance, black-box observation matrix and no-copy
  audit (with its residual caveat) are in `evidence/t15-cleanroom.md`. The
  option matrix has 287 no-op / 304 enabled cases with 0 problems, including
  the shadowquic `zero-rtt`/`quic-versions: v2`/Brutal/BasicOption rejections
  and the T17 sudoku baseline/`multiplex`/`httpmask` rows.
  `t10-feasibility.json` records shadowquic as implemented by T15; the
  remaining follow-up owners are the device families.

  T13 removed the first `sudoku` port, an unlabelled GPL-3.0 derivative of the
  pinned `transport/sudoku`, and kept the clean-room `mieru` client.
  `evidence/t13-a3-sudoku-removal.md` records the deletion inventory, the grep
  audit and the license reasoning. T17-A2 later translated the pinned module
  under the Owner authorization recorded in the T17 recipe (see below), so the
  type is implemented again, now with GPL-3.0 headers and notices. The mieru
  option rows stay (5 no-op / 8 enabled) and its five pinned-Mihomo peer cases
  are part of `peer-tests.sh` (66 cases, including the T17 sudoku cases).

  T19 added the mesh adapters. `peers/tailscale-peer` uses the locked
  BSD-3-Clause `controlbase.Server` for the Noise transport and an HTTP/2
  server for `/machine/map`, plus a DERP greeting/client-info/ping echo;
  `peers/zerotier-peer` uses the locked MPL-2.0 `zerotier-go` packet/identity
  code to parse the Rust HELLO and build OK. `native-kernel/tests/mesh_peers.rs`
  covers success, authentication failure and a boundary for those two families.
  T20 translated the locked LGPL-3.0-or-later EasyTier source for the
  cleartext host/discovery path (`DefaultHasher` digest, 16-byte little-endian
  frame, HandshakeRequest/PingPong), Noise XX and the secure-datagram
  AES-GCM/ChaCha20 data path; `peers/easytier-peer` runs the pinned wasm core
  as a test fixture. The dependency/licence/decision records are
  `evidence/t19-mesh.md` and `evidence/t20-easytier.md`.

  T17-A1 tried a clean-room `sudoku` client and produced none: the protocol is
  not specified at byte level anywhere public and the pinned listener rejects a
  foreign handshake with `INVALID_SUDOKU_MAP_MISS`. `sudoku-observe.py` and
  `evidence/t17-cleanroom.md`+`t17-observe.log` record those measurements and
  remain the history. T17-A2 then translated the pinned GPL-3.0
  `transport/sudoku` under the Owner authorization recorded in the T17 recipe
  (`docs/sakullla-workflow/2026-11-20-native-rust-kernel/02-technical-solution.md`);
  `type: sudoku` now loads (TCP, legacy HTTP mask, pure/packed downlink, mux)
  and the HTTP tunnel modes and UoT are rejected by name. The licence and
  verification record is `evidence/t17-translation.md`, the differential vectors
  are in `peers/sudoku-vectors/`, and the 13 pinned-peer cases are part of
  `peer-tests.sh`.

T23 fills `groups` and `configFields.proxy-groups`/`profile` in the mapping:
`select`/`url-test`/`fallback`/`load-balance` are implemented (load-balance
partial), `relay` is a named rejection because pinned v1.19.34 removed it, and
`evidence/t22-dns.md` records the DNS/hosts differential and its named gaps;
`evidence/t25-controller.md` records the control API surface, the 49-case
differential (47 equal, 2 named divergences) and the unimplemented endpoints;
`evidence/t23-groups.md` records the 27-case differential plus the persistence
case (including startup probes under the default lazy config, provider snapshot
re-checks, the url-test computation-cache window, nested lazy re-probing,
disabled-provider URL registration, empty-fallback blocking and
probe-through-dialer-proxy) and the unit suite.

`evidence/option-matrix.txt` is the probe's output, one line per option with the
Rust and Mihomo verdicts. `noop` rows must be accepted by both (a valid Mihomo
configuration that the kernel rejects is a compatibility failure), `impl` rows
are options that are implemented and must load (`t27-option-parity.{json,md}`),
and `enabled` rows must be rejected by the kernel with the field named;
Mihomo's own verdict is recorded so a form Mihomo already rejects is not counted
as a gap. The probe exits 1 on any violation.

T27 reduced the first batch from 304 enabled / 250 `rust=reject, mihomo=accept`
rows to 179 enabled / 135 disagreements (0 problems, 50 implemented cases):
`BasicOption` knobs (tfo/mptcp/interface-name/routing-mark/ip-version) for every
first-batch family, TLS identities (fingerprint/name-cert-verify/certificate/
private-key), QUIC congestion/window/MTU tuning for TUIC, Hysteria2 and
Hysteria v1, the vless `ws-headers` inert key and socks5 `UDP ASSOCIATE`. The
repair pass (T27-A2) made SSH dial through the shared socket dialer (so its
`BasicOption` knobs are no longer skipped by russh), added socks5 `udp: true`
to the TUN data plane, added a real mTLS client-identity case, scoped chained
UDP dials to the hop's socket options, and made `cwnd` BBR-only as pinned. The
remaining per-family gaps, their proposed owners (T28/T29/decision) and the
platform conditions are listed in `evidence/t27-option-parity.md`; raw logs are
in `evidence/t27-a2/`.

T28 moved 179 enabled / 135 disagreements to 151 enabled / 107 disagreements
(55 implemented, 289 no-op, 0 problems; 10 of the removed rows were duplicates
T27 emitted twice): `BasicOption` knobs for mieru/sudoku, the UDP-relevant
socket knobs for the shadowquic QUIC endpoint, masque/TUIC
`congestion-controller`/`cwnd` on the quinn endpoint, trojan `ss-opts`, and the
T27 ss/ssr UDP server-name/proxy-DNS boundary.

The T28-A3 delivery repair is value-level (the option rows do not move):
`ss`/`trojan ss-opts` now build five AEADs (`aes-128/192/256-gcm`,
`chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`, the 24-byte XChaCha nonce
included), and `bbr_meta_v2` is accepted as the pinned alias of `bbr` while the
old meta BBR v1 controller stays a named rejection. The remaining
`ss`-pinned names (shadowstream, ChaCha8/AES-CCM/GCM-SIV/AEGIS/AEZ/Deoxys/LEA/
Ascon AEADs and `none`) and the remaining `core.PickCipher` names (ChaCha8/
AES-CCM/stream ciphers and `DUMMY`) plus `bbr_meta_v1` are registered as
value-level gaps. T28-A5 is an evidence-only repair: the trojan `ss-opts` pinned
set is 21 accepted / 16 named rejections (not 33/28), because
`rabbit128-poly1305`, GCM-SIV, AEGIS, AEZ, Deoxys, LEA-GCM and Ascon are
rejected by the pinned engine too (`mihomo -t`: `cipher not supported`), and
the `ss` 39-name set is attributed to `sing-shadowsocks2` rather than
`core.PickCipher`. The 107 enabled rows are attributed per family in
`evidence/t28-option-parity.md`: easytier/wireguard/openvpn need the T6/T7
userspace stack, the TLS families need uTLS or TLS-in-TLS handshakes, and the
UDP/XUDP/UoT rows need protocol work; none is silently accepted. The groups
flake in `provider_registration_keeps_the_first_expected_status_for_a_shared_url`
was a test-readiness bug (the CONNECT-accept counter is observed before
`record_health`), fixed by waiting for the recorded `/shared` outcome. Details,
value-level gaps, per-family owners and unverified boundaries are in
`evidence/t28-option-parity.{json,md}`.

The T30 closure (`evidence/t30-option-closure.{json,md}`) moves vless/anytls/
ss/vmess datagram and UoT/session rows to implemented and verifies them against
the pinned listeners; anytls UoT, ss UoT and vmess plain UDP open one
association per destination and honour the same single-SOCKS5 `dialer-proxy`
hop as TCP. The four `client-fingerprint` rows stay approximations (closest
rustls profile, no uTLS ClientHello) and are counted as residuals, not parity.
T31 closes the target families further: anytls ShadowTLS v2 is implemented
(the HMAC read digest is framed inside the first application record and the
camouflage handshake disables TLS 1.3 tickets so the digest ends on the pinned
server's last write); hysteria2 `ports`/`hop-interval` (wrapped
`quinn::AsyncUdpSocket`), `obfs: salamander`, `obfs: gecko` (long-header
fragmentation/padding/reassembly), `realm-opts` (control HTTP `/connect` +
STUN + HYRLMv1 punching, then QUIC over the punched socket; the control TLS
block applies `fingerprint` as a SHA-256 certificate-DER pin even with
`skip-cert-verify`, presents `certificate`/`private-key` as an mTLS client
identity, validates that material at load, and rejects `realm-opts` together
with a non-empty `ports` pool), `up` (Brutal
window), `udp` (the pinned QUIC datagram session: session/packet/fragment
header, per-message destination routing, `udp-mtu` fragmentation with packet-id
reassembly, relayed on the mixed and TUN paths), `udp-mtu` and `bbr-profile`
(BBR initial-window mapping, profile over `cwnd`) are implemented and verified
against the pinned hysteria2 and
`hysteria2-realm` listeners; vmess `network: mkcp`/`kcp` (KCP over UDP with the
pinned auth/header modes) and `network: mekya` (KCP over HTTP/2 bundle
requests) are implemented and verified against the pinned vmess listener;
vmess `tlsmirror-opts` is the pinned carrier-TLS + hidden AES-GCM record layer
(primary-key, TLS 1.3) and is verified against the pinned vmess listener's
`tlsmirror-config` with a real TLS destination. The remaining target-family
gap is `hysteria2 ech-opts`; a hysteria2 `dialer-proxy` chain is refused by
name (a QUIC socket cannot ride a SOCKS5 UDP hop). Both are named in the
mapping and this README.

`runner.test.mjs` checks both files: every mapping entry must name an entry that exists in
the pinned source, every `implemented`/`partial` claim must cite at least one test, every
`partial` claim must say what is missing, and every family in the peer matrix must have a
positive and a negative case with the peer command.

## Fixture knobs

- `connect` (default) tunnels GET through HTTP CONNECT; `forward` sends a plain absolute-form
  GET. Each tag host is a valid domain under `probe.invalid`.
- `connect-host`/`connect-port`: the CONNECT authority; use it when a fixture must not
  depend on a hosts entry.
- `forward-host`: the authority for a forward request when the fixture brings its own
  `hosts` table (the runner then leaves that table untouched).
- Both `connect-host` and `forward-host` present: the runner injects no hosts table.
- `reference-only: true`: a request only the locked-source reference sends (it always relays
  to the running echo); kernels skip it, and it is not a pass claim for a kernel.
- `reference-only` requests and REJECT/control expectations are `not-applicable` for the
  reference, which has no rule engine and no controller.
- `request-port`: pins the echo port (used by fixtures whose rule routes a fixed address).

## What a run does

- Each engine gets its own loopback ports, temporary directory and YAML file (the fixture's
  `mixed-port`/`external-controller` are replaced; nothing else is edited).
- Tagged requests are sent to that engine: `connect` (HTTP CONNECT through the mixed inbound)
  or `forward` (plain absolute-form GET). Each tag host is a valid domain mapped by the
  fixture `hosts` entry to the loopback echo, so the echo's receipt of the same tag proves
  the request crossed the engine and reached the controlled endpoint.
- Config rejection is checked with the engine's own config test, and the locked source's
  parser must agree; a divergence is reported instead of a silent pass.
- Children are stopped with SIGTERM then SIGKILL, the listening port must be released, and
  the temporary directory is removed. Failures, timeouts and missing markers are recorded
  with a category, never converted into a pass.

## Reference scope

The reference is a probe built from the locked source (`probe/src/main.go`). It uses the
pinned parser for config acceptance and item parsing, and a small mixed-inbound replica that
relays one TCP session to the echo. It has no rule engine and no controller, so REJECT cases
and control-API cases are reported as `not-applicable` rather than as passes.

## Coverage boundary

Covered by the current fixtures: config acceptance/rejection, HTTP CONNECT and forward
requests on the mixed inbound through a hosts-mapped DIRECT exit, an address-routed CONNECT
accepted by both engines, REJECT, selector switching through the control API, and unknown
proxy targets. A valid configuration using `hosts`, `proxies`/`proxy-groups`, `lan-allowed-ips`
and a forward request (`fixtures/full-config.yaml`) is accepted by Mihomo and rejected by the
Rust kernel with `[unsupported]` because `hosts` (T5) is still missing; the report keeps that
difference as an open gap.

The fixtures are about the inbound/rules/config surface. Protocol outbounds are verified
against the same pinned binary in `native-kernel/tests/mihomo_peers.rs` and summarised in
`evidence/protocol-peers.json`, because a fixture would need a real proxy peer, not just the
echo endpoint. Current gaps, recorded rather than hidden:

- `hosts`, DNS answer contents, `proxy-groups`, providers, the full controller and rule
  families beyond the fixtures are T5; the capability index lists every one of them as
  `unimplemented` for the Rust kernel.
- SOCKS5/HTTP inbound UDP (`UDP ASSOCIATE`), TUN/system-proxy takeover and every platform
  other than macOS arm64 are not covered by these runs.
- The capability index keeps every free-form field and platform-only construct under
  `unmapped`; those entries are never reported as compatible.
