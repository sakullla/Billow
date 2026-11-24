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

| cases | T27 | T28 |
| --- | ---: | ---: |
| no-op (must load) | 287 | 289 |
| implemented (must load) | 50 | 55 |
| enabled (must be rejected) | 179 | 151 |
| rust reject / mihomo accept | 135 | 107 |
| problems | 0 | 0 |

10 of the 28 removed enabled rows were duplicate rows T27 emitted twice for
mieru/sudoku; the other 18 are real option moves (mieru 5, sudoku 5, shadowquic
5, masque 2, trojan 1). The two new no-op rows are shadowquic `tfo: true` and
`mptcp: true`, which both engines accept and neither applies to a UDP QUIC
socket.

## Implemented in this batch

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
- **masque QUIC controller.** `congestion-controller: cubic|new_reno|bbr` and
  `cwnd` are mapped onto the quinn endpoint for both CONNECT-IP and CONNECT-UDP;
  `bbr-profile` stays a named rejection (quinn has no profile selector) and an
  unknown controller is rejected by name. Covered by
  `tests/config.rs::t28_masque_quic_controller_and_trojan_ss_opts_are_parsed`.
- **trojan `ss-opts`.** `{enabled: true, method, password}` wraps the TLS/WS
  stream in the Shadowsocks AEAD layer before the trojan header, matching the
  pinned `core.Cipher.StreamConn`; a disabled block is a no-op, an unknown
  method or a missing password is a named rejection. The AEAD layer itself is
  tested by
  `src/outbound/shadowsocks.rs::tests::connect_layer_seals_the_first_payload_without_an_address_frame`;
  the TCP and UDP trojan paths both use it.
- **ss/ssr UDP server resolution (T27 boundary).** `outbound::udp::resolve_all`
  now uses the shared resolver, so the proxy-server name follows
  `ip-version`/`proxy-server-nameserver` instead of the OS resolver. The spawned
  association re-enters the `PROXY_DNS` task-local scope in both the TUN
  (`tunnel/udp.rs`) and mixed (`engine.rs`) paths. Covered by
  `tests/protocols.rs::shadowsocks_udp_server_name_uses_proxy_server_nameserver`,
  `tests/ios_tunnel.rs::spawned_tun_udp_association_uses_proxy_server_nameserver`
  and `src/outbound/udp.rs::resolve_all_applies_the_scoped_ip_version_to_a_literal`.

## Per-family remaining gaps (only families touched here)

| family | enabled before | enabled after | remaining named rejections |
| --- | ---: | ---: | --- |
| mieru | 15 | 5 | `udp: true` (UDP association), multiplexing levels, `traffic-pattern` |
| sudoku | 13 | 3 | `udp: true` (UoT), `http-mask-mode: stream/poll/auto/ws` |
| shadowquic | 12 | 7 | `zero-rtt`, `quic-versions: [v2]`, private Brutal `congestion-controller`, `bbr-profile`, `cwnd`, `up`, `down` |
| masque | 7 | 5 | `network: h2`, `network: h3-l4proxy`, `bbr-profile`, `ip-stack.mode: gvisor`, `dialer-proxy` |
| trojan | 7 | 6 | `reality-opts`, `ech-opts`, `shadow-tls-opts`, `restls-opts`, `jls-opts`, `client-fingerprint` |

Untouched families remain as T27 recorded them: **easytier** (21 enabled rows),
**openvpn** (12), and the DNS/sniffer/tun top-level surface. T28 does not claim
them as implemented; the matrix keeps every row visible with the field name in
the rejection.

## Validation for this attempt

- `cargo check -p billow-kernel --locked`: pass.
- `cargo test -p billow-kernel --locked --no-fail-fast`: all binaries pass
  (163 + 48 + 15 + 19 + 32 + 58 + 32 + 15 + 11 + 1 + 1; 77 ignored by design).
- `cargo test -p billow-kernel --locked --features ios-vpn`: pass
  (195 + 48 + 15 + 19 + 32 + 8 + 58 + 32 + 15 + 11 + 1 + 1).
- `cargo test -p billow-kernel --locked --features android-vpn`: pass
  (185 + 9 + 48 + 15 + 19 + 32 + 58 + 32 + 15 + 11 + 1 + 1).
- `node --test tool/kernel-compat/runner.test.mjs`: 10/10 pass.
- Differentials rerun against this build:
  - T22 DNS: 23 cases, 22 pass, 0 differ/unexpected, 1 skipped.
  - T23 groups: 27 cases + persistence, 28 pass, 0 differ/unexpected.
  - T24 rules/providers: 38 cases, 36 pass, 0 differ/unexpected, 2 skipped
    (the existing known framing differences are recorded in the report).
  - T25 control API: 47/49 equal, 2 known divergences, 0 unexpected.
  - T5 combined: 12/12 scenarios pass, 0 differ, start/stop clean.

## Unverified boundaries

- trojan `ss-opts` is proven at the AEAD-layer and parse level; no peer test
  runs it against a real trojan server with `ss-opts`.
- masque controller/cwnd mapping is proven by parse tests plus the quinn
  option wiring; no live CONNECT-IP peer exercises the selected controller.
- shadowquic socket knobs are parse/endpoint wiring only; no peer test proves
  `interface-name`/`routing-mark` on the QUIC socket.
- mieru/sudoku BasicOption knobs are parse + shared-dialer wiring; their normal
  peer tests do not re-run with a bound interface.
- DNS (DoQ/system/dhcp/h3/ECS) and sniffer/tun option work from the T28 outcome
  is not implemented in this attempt.
