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

| cases | T27 | T28-A2 | T28-A3 |
| --- | ---: | ---: | ---: |
| no-op (must load) | 287 | 289 | 289 |
| implemented (must load) | 50 | 55 | 55 |
| enabled (must be rejected) | 179 | 151 | 151 |
| rust reject / mihomo accept | 135 | 107 | 107 |
| problems | 0 | 0 | 0 |

T28-A2 removed 28 enabled rows (10 of them duplicate rows T27 emitted twice for
mieru/sudoku; the other 18 are real option moves: mieru 5, sudoku 5, shadowquic
5, masque 2, trojan 1) and added two no-op rows (shadowquic `tfo`/`mptcp`).
T28-A3 is a delivery-repair pass: it closes the two value-level gaps the T28
review found without moving an option-level row, so the counts stay
151 enabled / 107 disagreements with 0 problems. The value-level gaps are
listed separately below because the probe classifies options, not values inside
an implemented option.

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
  the pinned `core.PickCipher` names for the five AEADs this kernel can build:
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

## Value-level gaps still registered

These values sit inside implemented options, so the option-level matrix rows
stay green. They fail at load with the value named and are not silently
skipped.

| family / option | implemented values | named rejections | owner |
| --- | --- | --- | --- |
| `ss.cipher`, `trojan.ss-opts.method` | aes-128/192/256-gcm, chacha20-ietf-poly1305, xchacha20-ietf-poly1305 | chacha8-ietf-poly1305, xchacha8-ietf-poly1305, aes-128/192/256-ccm, rc4-md5, aes-128/192/256-ctr, aes-128/192/256-cfb, chacha20, chacha20-ietf, xchacha20 | requirement decision or a cipher follow-up (needs the pinned shadowstream framing or reduced-round/CCM primitives) |
| `tuic`/`masque` `congestion-controller` | cubic, new_reno, bbr, bbr_meta_v2 | bbr_meta_v1 | requirement decision (meta BBR v1 dependency) |

## Per-family remaining ownership (107 rows)

No enabled row moved in T28-A3. The owners below name the dependency that
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

## Validation for this attempt (T28-A3)

All commands ran in an independent `CARGO_TARGET_DIR`
(`.../opencode/t28-target` and `.../t28-release-target`); no port was left
bound and no process was left running.

- `cargo test --manifest-path native-kernel/Cargo.toml --locked`: pass,
  420 passed / 0 failed / 91 ignored by design across every test binary
  (lib 165, config 48, controller 15, dns 19, groups 32, protocols 60,
  quic_peers 32, resources 15, sessions 11, shadowquic_stream 1, CLI 11,
  family_cli 10, CLI integration 1; the peer suites are `#[ignore]`:
  independent_peers 7, mesh_peers 5, mihomo_peers 66, openvpn_peer 4,
  wireguard_peer 5, plus 2+1 in protocols/resources and 1 in family_cli).
- Groups suite: 32/32, four runs (three under CPU load with 8 busy
  processes, one after the final wait-condition edit). The flake fix is test-side: `node.connections` counts the
  accepted CONNECT before the response is read and `record_health` runs, so
  the old wait could observe the group while the `/shared` URL still had no
  record (`AliveForTestUrl`'s `alive = true` fallback). The test now waits for
  the recorded dead outcome, so a regression to the later 204 would time out
  instead of flaking. Before the fix: 5/15 runs failed under the same load;
  after: 16/16 + 12/12 single runs and 4/4 full-suite runs passed.
- option-probe with the current release CLI: 289 no-op / 55 implemented / 151
  enabled / 107 disagreements / 0 problems (exit 0).
- Value-level checks against the pinned binary: `ss` with `aes-192-gcm` or
  `xchacha20-ietf-poly1305` loads in both engines; `aes-256-cfb` and
  `chacha8-ietf-poly1305` load in Mihomo and are named rejections here; the
  WARP masque shape with `bbr_meta_v2` loads in both, `bbr_meta_v1` loads only
  in Mihomo and is named here.
- Differentials rerun against this build: T5 12/12 scenarios; T22 23 cases
  (22 pass, 1 skipped); T23 27 cases + persistence (28 pass); T24 38 cases
  (36 pass, 2 skipped, 6 recorded framing notes); T25 47/49 equal with the 2
  known divergences; 0 differ/unexpected everywhere.
- `node --test tool/kernel-compat/runner.test.mjs`: 10/10 pass.

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
