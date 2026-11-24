# T28 option parity (second batch)

Driven by the first-batch matrix (`t27-option-parity.{json,md}`) and the T28
outcomes. The current matrix is `evidence/option-matrix.txt`, produced with the
pinned Mihomo v1.19.34 binary and a release build of the `billow-kernel` CLI:

```
cargo build --release --manifest-path native-kernel/Cargo.toml --locked -p billow-kernel-cli
node tool/kernel-compat/option-probe.mjs \
  --rust <built billow-kernel> \
  --mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
  --out tool/kernel-compat/evidence/option-matrix.txt
```

| cases | T27 | T28-A2 | T28-A3 | T28-A4 | T28-A5 |
| --- | ---: | ---: | ---: | ---: | ---: |
| no-op (must load) | 287 | 289 | 289 | 289 | 289 |
| implemented (must load) | 50 | 55 | 55 | 55 | 55 |
| enabled (must be rejected) | 179 | 151 | 151 | 151 | 151 |
| rust reject / mihomo accept | 135 | 107 | 107 | 107 | 107 |
| problems | 0 | 0 | 0 | 0 | 0 |

T28-A2 removed 28 enabled rows (10 of them duplicate rows T27 emitted twice for
mieru/sudoku; the other 18 are real option moves: mieru 5, sudoku 5, shadowquic
5, masque 2, trojan 1) and added two no-op rows (shadowquic `tfo`/`mptcp`).
T28-A3 is a delivery-repair pass: it closes the two value-level gaps the T28
review found without moving an option-level row, so the counts stay
151 enabled / 107 disagreements with 0 problems. T28-A4 is a second repair
pass: it does not move an option-level row either (the option-probe counts are
unchanged); it completes the value-level cipher registration for both `ss` and
trojan `ss-opts` (the implemented five were being presented as the complete
pinned set), corrects the default-suite ignored count, and fixes the BBR initial
window per family. The value-level gaps are listed separately below because the
probe classifies options, not values inside an implemented option. T28-A5 is an
evidence-only repair: it reclassifies the trojan `ss-opts` pinned-accepted set
after probing every name with the pinned binary, records the T22/T24
differentials that were missing from the A4 validation block, and does not move
an option-level row (the probe counts above are unchanged).

The 151 enabled rows still contain three duplicate rows that two T27 input
lists emit (mieru `udp`, mieru `traffic-pattern`, sudoku `udp`); two of those
(mieru `udp`, sudoku `udp`) are inside the 107, which is therefore 105 unique
rows. They are left visible instead of silently deduped.

## Implemented in this batch (T28-A2)

- **mieru / sudoku BasicOption knobs.** Both outbounds already dial their server
  with `connect_tcp`, so `tfo`, `mptcp`, `interface-name`, `routing-mark` and
  `ip-version` are now parsed and applied to that socket instead of being
  rejected. Covered by
  `tests/config.rs::t28_tcp_basic_options_reach_the_shared_dialer_families`.
- **shadowquic QUIC endpoint knobs.** `interface-name`, `routing-mark` and
  `ip-version` reach `quic::connect`'s `udp_socket_std` / address filter;
  `tfo`/`mptcp` are accepted no-ops because the pinned packet dialer cannot
  apply TCP options to a QUIC UDP socket. Same test, plus the enabled rows are
  gone from the matrix.
- **masque QUIC controller.** `congestion-controller` and `cwnd` are mapped
  onto the quinn endpoint for both CONNECT-IP and CONNECT-UDP (T28-A3 also
  accepts the pinned `bbr_meta_v2` alias of `bbr`); `bbr-profile` stays a named
  rejection (quinn has no profile selector) and an unknown controller is
  rejected by value. Covered by
  `tests/config.rs::t28_masque_quic_controller_and_trojan_ss_opts_are_parsed`
  and `src/outbound/tuic.rs::tests::cwnd_only_applies_to_bbr`.
- **trojan `ss-opts`.** `{enabled: true, method, password}` wraps the TLS/WS
  stream in the Shadowsocks AEAD layer before the trojan header, matching the
  pinned `core.Cipher.StreamConn`; a disabled block is a no-op, an unknown
  method or a missing password is a named rejection.
- **ss/ssr UDP server resolution (T27 boundary).** `outbound::udp::resolve_all`
  now uses the shared resolver, so the proxy-server name follows
  `ip-version`/`proxy-server-nameserver` instead of the OS resolver. The spawned
  association re-enters the `PROXY_DNS` task-local scope in both the TUN
  (`tunnel/udp.rs`) and mixed (`engine.rs`) paths.

## Value-level gaps closed in T28-A3

- **Shadowsocks cipher set (ss and trojan `ss-opts`).** `SsCipher` now follows
  the pinned `sing-shadowsocks2` names for the `ss` outbound and the pinned
  `core.PickCipher` names for trojan `ss-opts` for the five AEADs this kernel can build:
  `aes-128-gcm`, `aes-192-gcm` (24-byte key), `aes-256-gcm`,
  `chacha20-ietf-poly1305` and `xchacha20-ietf-poly1305` (24-byte nonce; the
  nonce counter is now sized per cipher). The TCP stream, the UDP datagram codec
  and the bare `ss-opts` layer share the same implementation. Proven by
  `src/outbound/shadowsocks.rs::tests::connect_layer_roundtrips_every_implemented_cipher`,
  `...::datagram_codec_roundtrips_every_implemented_cipher`, the independent
  peers `tests/protocols.rs::shadowsocks_{aes_192_gcm,xchacha20_ietf_poly1305}_roundtrip`
  (the peer builds the AEAD from public crates, not from the client's type) and
  `tests/config.rs::t28_masque_quic_controller_and_trojan_ss_opts_are_parsed`.
- **masque/TUIC `bbr_meta_v2`.** Pinned `common.SetCongestionController` treats
  `bbr_meta_v2` as a fallthrough alias of `bbr` (same v2 BBR sender), so it now
  selects quinn's BBR controller with the same `cwnd`-derived initial window.
  `bbr_meta_v1` (the old meta BBR sender) has no quinn equivalent and is
  rejected by value with the controller named.

T28-A5 note: those five AEADs are the *implemented* set, not the pinned
acceptance set. The pinned `ss` outbound accepts 39 method names through
`sing-shadowsocks2`; trojan `ss-opts` accepts **21** through `core.PickCipher`
(the five AEADs, `chacha8-ietf-poly1305`, `xchacha8-ietf-poly1305`,
`aes-128/192/256-ccm`, the ten shadowstream ciphers and `DUMMY`). The other 16
pinned-accepted trojan names are named rejections. Twelve names that A4 listed
as pinned-accepted (`rabbit128-poly1305`, `aes-128-gcm-siv`, `aes-256-gcm-siv`,
`aegis-128l`, `aegis-256`, `aez-384`, `deoxys-ii-256-128`, `lea-128-gcm`,
`lea-192-gcm`, `lea-256-gcm`, `ascon128`, `ascon128a`) are rejected by the
pinned engine too: `mihomo -t` reports `cipher not supported` for each. They are
listed as pinned-and-Rust rejections below, not as pinned-accepted gaps.

## Value-level gaps still registered

These values sit inside implemented options, so the option-level matrix rows
stay green. They fail at load with the value named and are not silently
skipped. T28-A5 re-derived both sets value by value: each name below was run
through the pinned v1.19.34 binary (`mihomo -t`) and matched against the locked
`sing-shadowsocks2` registry (for `ss`) and `core.PickCipher` table (for trojan
`ss-opts`). The 2022 methods need a base64 PSK of the key length (a plain string
is rejected by the pinned decoder), so their pinned verdicts were taken with
valid base64 keys.

### `ss.cipher` — 34 named rejections

Implemented (5): `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`,
`chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`.

Pinned accepts and this kernel rejects by name (34). The pinned `ss` outbound
registers these through `sing-shadowsocks2`; `core.PickCipher` is the trojan
`ss-opts` table and is not the `ss` method registry:

- legacy AEAD additions (17): `chacha8-ietf-poly1305`,
  `xchacha8-ietf-poly1305`, `rabbit128-poly1305`, `aes-128-ccm`,
  `aes-192-ccm`, `aes-256-ccm`, `aes-128-gcm-siv`, `aes-256-gcm-siv`,
  `aegis-128l`, `aegis-256`, `aez-384`, `deoxys-ii-256-128`, `lea-128-gcm`,
  `lea-192-gcm`, `lea-256-gcm`, `ascon128`, `ascon128a`;
- shadowstream (10): `aes-128-ctr`, `aes-192-ctr`, `aes-256-ctr`,
  `aes-128-cfb`, `aes-192-cfb`, `aes-256-cfb`, `rc4-md5`, `chacha20-ietf`,
  `xchacha20`, `chacha20`;
- unencrypted (1): `none`;
- AEAD-2022 (6): `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`,
  `2022-blake3-chacha20-poly1305`, `2022-blake3-chacha8-poly1305`,
  `2022-blake3-aes-128-ccm`, `2022-blake3-aes-256-ccm`.

`DUMMY` is not an `ss` method in the pinned engine either, so both reject it.

### `trojan.ss-opts.method` — 16 named rejections

Implemented (5): the same AEADs as `ss`.

Pinned accepts and this kernel rejects by name (16):

- AEAD additions `core.PickCipher` does accept (5): `chacha8-ietf-poly1305`,
  `xchacha8-ietf-poly1305`, `aes-128-ccm`, `aes-192-ccm`, `aes-256-ccm`;
- the same 10 shadowstream names;
- `DUMMY` (the pinned unencrypted passthrough; case-insensitive like the other
  names).

Pinned rejects too (19): the other 12 legacy AEAD names
(`rabbit128-poly1305`, `aes-128-gcm-siv`, `aes-256-gcm-siv`, `aegis-128l`,
`aegis-256`, `aez-384`, `deoxys-ii-256-128`, `lea-128-gcm`, `lea-192-gcm`,
`lea-256-gcm`, `ascon128`, `ascon128a`; each was run through `mihomo -t` and
reported `cipher not supported`), plus `none` and the six `2022-blake3-*`
names.

Both families share `SsCipher`, whose parser rejects every name outside the
five implemented AEADs with `option 'cipher' / 'ss-opts.method' value '<name>'
is not implemented`, so the lists above are the complete named-rejection set:
34 pinned-accepted names for `ss`, and 16 pinned-accepted plus 19 pinned-rejected
names for trojan `ss-opts` (no pinned-accepted value is missing).
Implementing `none`/`DUMMY` would need a
separate unframed path (no salt/chunk layer; `ss` `none` still prefixes the
SOCKS address, trojan `DUMMY` is a pure passthrough), and the six 2022 methods
need the AEAD-2022 record layout plus a BLAKE3 KDF; both stay registered gaps
rather than approximated.

| family / option | implemented values | named rejections | owner |
| --- | --- | --- | --- |
| `ss.cipher` | aes-128/192/256-gcm, chacha20-ietf-poly1305, xchacha20-ietf-poly1305 | 34 pinned-accepted (`sing-shadowsocks2`): 17 legacy AEAD additions, 10 shadowstream, `none`, 6 `2022-blake3-*` | requirement decision or a cipher follow-up (unframed + shadowstream + 2022 records) |
| `trojan.ss-opts.method` | same five AEADs | 16 pinned-accepted (`core.PickCipher`): 5 AEAD additions, 10 shadowstream, `DUMMY`; the 12 GCM-SIV/AEGIS/AEZ/Deoxys/LEA/Ascon names, `none` and the 6 `2022-blake3-*` are rejected by the pinned engine too | requirement decision or a cipher follow-up |
| `tuic`/`masque` `congestion-controller` | cubic, new_reno, bbr, bbr_meta_v2 | bbr_meta_v1 | requirement decision (meta BBR v1 dependency) |

## Per-family remaining ownership (107 rows)

No enabled row moved in T28-A3, T28-A4 or T28-A5. The owners below name the dependency that
blocks the behaviour; they are not implementation claims. Every listed value
is still rejected at load with its key/value named.

| family | rows | owner / blocking dependency |
| --- | ---: | --- |
| easytier | 20 | T6/T7 userspace IP stack/TUN + EasyTier OSPF/route host identity: `hostname`, `ipv4`, `dhcp`, `mapped-listeners`, `exit-nodes`, `proxy-networks`, `accept-dns`, `enable-exit-node`, `private-mode`, `latency-first`, `enable-kcp-proxy`, `enable-quic-proxy`, `tld-dns-zone`, `tfo`, `mptcp`, `interface-name`, `routing-mark`, `ip-version`, `enable-encryption` alone, `local-private-key` alone |
| wireguard | 11 | T6/T7 userspace IP stack + AmneziaWG + stack resolver: `amnezia-wg-option`, `dns`, `interface-name`, `ip-stack.congestion-controller`, `ip-stack.mode`, `ip-version`, `mptcp`, `refresh-server-ip-interval`, `remote-dns-resolve`, `routing-mark`, `tfo` |
| tuic | 9 | TUIC v4 `token`/BLAKE3, UDP relay (`udp-relay-mode`, `udp-over-stream`, datagram sizes), 0-RTT (`reduce-rtt`, `fast-open`), `bbr-profile`, uTLS `client-fingerprint` |
| anytls | 9 | UoT `udp`, session-reuse pool (`client-metadata`, `idle-session-*`, `min-idle-session`, `disable-reuse`), TLS-in-TLS (`shadow-tls-opts`, `jls-opts`), uTLS |
| vmess | 8 | UDP/XUDP (`udp`, `xudp`, `packet-addr`, `packet-encoding`), mKCP, mekya, TLS-mirror, uTLS |
| shadowquic | 7 | JLS 0-RTT, QUIC v2, private Brutal (`congestion-controller`, `cwnd`, `up`, `down`), `bbr-profile` |
| openvpn | 7 | T6/T7 userspace IP stack + `tls-auth`/`tls-crypt`, compression, CBC data channel, stack DNS |
| hysteria2 | 7 | port hopping (`ports`, `hop-interval`), Salamander/Gecko obfs, Brutal `up`, `realm-opts`, `udp-mtu`, `bbr-profile` |
| hysteria | 6 | port hopping, XPlus obfs, `protocol: faketcp|wechat`, `fast-open`, uTLS |
| vless | 5 | UDP/XUDP, `packet-encoding`, `packet-addr`, uTLS |
| masque | 4 | `network: h2`, `network: h3-l4proxy`, `ip-stack.mode: gvisor`, `bbr-profile` (plus the `bbr_meta_v1` value) |
| trojan | 3 | `shadow-tls-opts`, `jls-opts`, uTLS |
| sudoku | 3 | UoT `udp`, `http-mask-mode: stream|poll|auto|ws` |
| mieru | 3 | UDP association, multiplexing levels, `traffic-pattern` |
| trusttunnel | 2 | UDP, uTLS |
| ss | 2 | `udp-over-tcp`, `udp-over-tcp-version` (UoT framing) |
| gost-relay | 1 | uTLS `client-fingerprint` |

Cross-family causes: **device/IP stack** (easytier 20 + wireguard 11 +
openvpn 7 = 38 rows) is T6/T7 work or a requirement narrowing; **uTLS
fingerprints** account for 9 rows across the TLS families; **UDP/XUDP/UoT
associations** account for 8 rows (ss 2, sudoku, mieru, anytls, vless, vmess,
trusttunnel); the rest are protocol-specific transports (port hopping/obfs,
mKCP/mekya, private Brutal, QUIC v2, XPlus, TLS-in-TLS, H2/l4proxy/gVisor).

## Validation for this attempt (T28-A5)

T28-A5 changed no Rust source (evidence/README only), so the T28-A4 full-suite
numbers below remain the source-of-truth run; this attempt rebuilt the current
tree and re-ran the checks affected by the repair. No port was left bound and no
process was left running.

- Default suite (T28-A4 full run, unchanged source): pass, 420 passed / 0 failed
  / 92 ignored by design across every test binary (lib 165 passed + 1 ignored
  benchmark `rule_rows_large_catalog_benchmark`, config 48, controller 15,
  dns 19, groups 32, protocols 60 + 2 ignored, quic_peers 32, resources 15 + 1
  ignored, sessions 11, shadowquic_stream 1, CLI 11, family_cli 10 + 1 ignored,
  CLI integration 1; the peer suites are `#[ignore]`: independent_peers 7,
  mesh_peers 5, mihomo_peers 66, openvpn_peer 4, wireguard_peer 5 → 92
  ignored). The earlier "91" text missed the lib benchmark.
- T28-A5 spot run of the default suite: `cargo test --manifest-path
  native-kernel/Cargo.toml --locked -p billow-kernel --test config --test
  protocols` → config 48 passed / 0 failed / 0 ignored; protocols 60 passed /
  0 failed / 2 ignored (the two peer cases need the Go toolchain).
- Groups suite: 32/32 in the T28-A4 default run; the T28-A3 flake fix (wait on
  the recorded `/shared` dead outcome, not just `node.connections`) is
  unchanged: before that fix 5/15 loaded runs failed, after it 16/16 + 12/12
  single runs and 4/4 full suites passed.
- option-probe rerun with the freshly built release CLI: 289 no-op / 55
  implemented / 151 enabled / 107 disagreements / 0 problems (exit 0). The
  regenerated matrix differs from `evidence/option-matrix.txt` only in the
  header binary path, so the committed matrix still describes the same run.
- BBR initial window: `congestion_tuning` takes the family's QUIC
  `InitialPacketSize`. TUIC keeps quic-go's default 1280, masque sets the
  pinned 1242; the unit test
  `src/outbound/tuic.rs::tests::cwnd_only_applies_to_bbr` checks 64/32 packets
  against both sizes (the previous code used a flat 1200 for both).
- CLI stop handlers: `StopSignals::install()` runs before the kernel binds, so
  a SIGINT/SIGTERM that arrives during startup is observed instead of ending
  the process through the default disposition; the Android fd-lost loop shares
  the same pre-installed handler.
- Value-level checks against the pinned binary (T28-A5, complete set): all 39
  pinned `ss` method names were run through `mihomo -t` (39 accepted through
  `sing-shadowsocks2`; `DUMMY` rejected) and all 33 `trojan.ss-opts` names were
  run against `core.PickCipher` (21 accepted; the 12 legacy AEAD names report
  `cipher not supported`; `none` rejected). Spot checks: `ss` with `ascon128`
  or `aes-256-ctr` loads in Mihomo and fails here naming `value '<name>'`;
  trojan `ss-opts` with `chacha8-ietf-poly1305`/`aes-128-ccm` loads in Mihomo
  and fails here naming `ss-opts.method`, while `ascon128`/`lea-256-gcm` are
  rejected by both, `DUMMY` loads in Mihomo and fails here, and `none` /
  `2022-blake3-*` are rejected by both. `DUMMY` is rejected by both for `ss`.
- Differentials: T22 and T24 were re-run against this build. T22: 23 cases,
  22 pass, 1 skipped (`fallback-geoip-code-mmdb-negated` needs `--mmdb-dir`),
  0 differ/knownDifference/unexpected/startupFailed. T24: 38 cases, 36 pass,
  2 skipped, 0 differ/unexpected; `framingDifferences` is 9 in this run — it
  counts the pre-normalization inbound framing (Mihomo's 200-then-close can
  surface as `timeout` or `closed`) and varies run to run (8 in T27-A2, 6 in
  T24, 4 in T8), so it is not a rule-compatibility claim. T5 (12/12), T23
  (28 pass) and T25 (47/49 equal, 2 known divergences) are unchanged from
  T28-A4 with 0 differ/unexpected.
- `node --test tool/kernel-compat/runner.test.mjs`: 10/10 pass.
- Capability index: `node tool/kernel-compat/capability.mjs --out
  tool/kernel-compat/evidence/source-capabilities.json` regenerated it from the
  updated `rust-mapping.json`; coverage is now 62 mapped / 33 partial / 60
  unimplemented (155 total) instead of the stale 55/32/68. The trojan
  `notImplemented` list no longer carries the implemented
  `ip-version`/`tfo`/`mptcp`/`interface-name`/`routing-mark` entries.

## Unverified boundaries

- trojan `ss-opts` is proven at the AEAD-layer and parse level (now for five
  ciphers) but no peer test runs it against a real trojan server with
  `ss-opts`.
- masque/TUIC controller mapping is proven by parse tests plus the quinn
  option wiring; no live CONNECT-IP/TUIC peer exercises the selected
  controller.
- shadowquic socket knobs are parse/endpoint wiring only; no peer test proves
  `interface-name`/`routing-mark` on the QUIC socket.
- mieru/sudoku BasicOption knobs are parse + shared-dialer wiring; their normal
  peer tests do not re-run with a bound interface.
- DNS (DoQ/system/dhcp/h3/ECS) and sniffer/tun option work from the T28 outcome
  is not implemented in this attempt.
- easytier/openvpn/wireguard data-plane rows are blocked on T6/T7; their
  control-plane translations are tested but no configuration option that needs
  the userspace stack is claimed.
