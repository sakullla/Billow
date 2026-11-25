# T33 option closure: masque, mieru, sudoku, trojan, trusttunnel, gost-relay

Baseline: `evidence/option-matrix.txt` (T32: 291 no-op / 110 implemented / 99
enabled, 0 problems). After T33 the same matrix is **291 no-op / 119
implemented / 90 enabled, 0 problems**, produced with the pinned Mihomo
v1.19.34 binary and the debug `billow-kernel` CLI built in an independent
`CARGO_TARGET_DIR` (the matrix header records the exact path; unlike the T32
note this is a debug build, which does not change load/reject classification):

```
cargo build --manifest-path native-kernel/Cargo.toml --locked -p billow-kernel-cli
node tool/kernel-compat/option-probe.mjs \
  --rust <built billow-kernel> \
  --mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
  --out tool/kernel-compat/evidence/option-matrix.txt
```

| target family | before (rust=reject rows) | after | closed | named residual |
| --- | ---: | ---: | --- | --- |
| masque | 5 | 4 | `bbr-profile`, `congestion-controller: bbr_meta_v1` | `network: h2`, `h3-l4proxy`, `ip-stack.mode: gvisor` |
| mieru | 5 | 5 | — | `udp`, `multiplexing`, `traffic-pattern` |
| sudoku | 3 | 1 | `udp` | `http-mask-mode` |
| trojan | 6 | 3 | `shadow-tls-opts`, `jls-opts`, `client-fingerprint` | — (the 3 left are `mihomo=reject`: `reality-opts`, `ech-opts`, `restls-opts`) |
| trusttunnel | 11 | 9 | `udp`, `client-fingerprint` | — (the 9 left are `mihomo=reject`) |
| gost-relay | 1 | 0 | `client-fingerprint` | — |

Counts are matrix rows; the probe lists a few keys twice (family-level and
value-level registered gaps both exist, e.g. mieru `udp`/`traffic-pattern`).
Every remaining `rust=reject mihomo=accept` row of these families is listed in
the residuals section with its pinned source path.

## Implemented and verified

| family | option | implementation | evidence |
| --- | --- | --- | --- |
| trojan | `shadow-tls-opts` (v1/v2) | The T31 anytls security layer is now shared: `AnytlsSecurity`/`parse_anytls_security` became `TlsSecurity`/`parse_tls_security`, `TrojanOutbound` carries the mode, and `trojan::wrap_security` replaces the plain rustls handshake with `shadow_tls::wrap` (the trojan header then travels in the ShadowTLS plaintext records). Missing/0/2 selects the pinned default 2; `version: 3` keeps the session-id rejection. | `tests/mihomo_peers.rs::trojan_over_shadow_tls_v2_reaches_the_receiving_side_through_mihomo`, `tests/config.rs::trojan_shadow_tls_jls_and_client_fingerprint_load` |
| trojan | `jls-opts` | Same parser; `trojan::wrap_security` uses `tls_io::connect_jls`. Required `username`/`password` and the ShadowTLS/JLS mutual exclusion match the pinned type. | `tests/mihomo_peers.rs::trojan_over_jls_reaches_the_receiving_side_through_mihomo`, same config test |
| trojan | `client-fingerprint` | Parsed into `TlsSettings.client_fingerprint`, applied as the rustls profile approximation (T30 category). | config test, option matrix `impl` row |
| trusttunnel | `udp: true` | `TrustTunnelUdp` opens the pinned `_udp2` h2 CONNECT stream: request `u32 length | source 16+2 | destination 16+2 | u8 app-name length | mihomo | payload`, reply `u32 length | source 16+2 | local 16+2 | payload`. IPv4 sits in the last four bytes, `::1` is not decoded as IPv4, and one association serves every destination. The record has no address-type field, so the mixed inbound (and the TUN association, for a fake-ip-mapped name) resolves a name through the session `hosts` table and DNS runtime with the proxy's `ip-version` (`engine::proxy_udp_destination`, the pinned `Base.ResolveUDP` + `resolveIPWithResolver`) before framing; `send` itself only accepts an IP and never falls back to the system resolver. `udp_enabled()` reports it; the mixed inbound and the TUN data plane both build it; a `dialer-proxy` chain loads (T32 convention) and the association refuses it by name. | `tests/mihomo_peers.rs::trusttunnel_udp_reaches_the_echo_through_mihomo`, `tests/mihomo_peers.rs::trusttunnel_udp_domain_destination_uses_the_session_resolver` (domain only in `hosts`, v6 listed first, `ip-version: ipv4`), `src/outbound/trusttunnel.rs::tests::udp_packet_framing_matches_the_pinned_layout`, `tests/config.rs::trusttunnel_options_are_strict` |
| trusttunnel | `client-fingerprint` | Parsed into the shared TLS settings, rustls profile approximation. | `tests/config.rs::trusttunnel_options_are_strict`, matrix `impl` row |
| gost-relay | `client-fingerprint` | Parsed and applied to the optional TLS layer (with TLS off the pinned client ignores it and the kernel accepts it the same way). | `tests/config.rs::gost_relay_options_are_strict`, matrix `impl` row |
| masque | `bbr-profile` | Validated (conservative/standard/aggressive) and mapped to quinn BBR's initial window via `tuic::congestion_tuning_profile`; exactly like the pinned `SetCongestionController` switch it only changes behaviour together with a bbr controller. | `src/outbound/quic.rs::tests::bbr_profile_selects_the_initial_window`, `tests/config.rs::t28_masque_quic_controller_and_trojan_ss_opts_are_parsed`, matrix `impl` row |
| masque | `congestion-controller: bbr_meta_v1` | Accepted as quinn's BBR sender (closest available). `congestion_tuning` now selects BBR for `bbr_meta_v1` too, so TUIC/ShadowQUIC/masque agree; `bbr-profile` remains effective for `bbr`/`bbr_meta_v2` only. | `src/outbound/tuic.rs::tests::cwnd_only_applies_to_bbr`, same config test, matrix `impl` row |
| sudoku | `udp: true` | KIP `StartUot`: `Handshake::StartUot` advertises `OPEN_TCP|UOT` and sends `TYPE_START_UOT` after the rekey; `SudokuUdp` then carries `u16 address length | u16 payload length | SOCKS5 address | payload` frames (same layout back, address padding past the encoded form tolerated). One association serves every destination; mixed inbound and TUN both build it; one SOCKS5 `dialer-proxy` hop is supported like TCP. | `tests/mihomo_peers.rs::sudoku_udp_reaches_the_echo_through_mihomo`, `src/outbound/udp.rs::tests::sudoku_uot_frame_round_trips_over_a_stream`, `tests/config.rs::sudoku_options_are_strict` |

`client-fingerprint` and the masque BBR rows are **approximations counted as
residuals**, not uTLS/byte-for-byte parity — the same convention as
`t30-option-closure.json` and `t32-option-closure.md`. No other row in this
table is accepted without its behaviour being covered by a test.

## Named residuals (rust=reject, Mihomo accepts)

| family | option | why it is not implemented | pinned source |
| --- | --- | --- | --- |
| masque | `network: h2` | The pinned variant is an HTTP/2 CONNECT-IP client (h2c-mode transport, CONNECT-IP capsules over h2 DATA frames). The kernel implements CONNECT-IP over HTTP/3 only; the h2 carrier is a second capsule transport, not an option mapping. | `adapter/outbound/masque.go:180`, `transport/masque/client_h2.go` |
| masque | `network: h3-l4proxy` | A separate L4 encapsulation with its own client/SNI, not RFC 9484 CONNECT-IP. | `adapter/outbound/masque.go:158,257-263`, `transport/masque/l4proxy.go` |
| masque | `ip-stack.mode: gvisor` | gVisor is the pinned binary's build-tagged stack (`with_gvisor`); the kernel's in-tree stack terminates UDP only and is not a gVisor replacement. `auto`/`mips`/empty still load. | `adapter/outbound/wireguard.go:164,196-203`, `constant/features/with_gvisor.go` |
| mieru | `udp: true` | `ListenPacketContext` dials the enfein/mieru client and wraps it in `NewUDPAssociateWrapper(NewPacketOverStreamTunnel(c))`; that packet-over-stream framing lives in the external locked module. The kernel's mieru is a clean-room TCP stream client with no packet/associate layer. | `adapter/outbound/mieru.go:88-99` |
| mieru | `multiplexing: LOW/MIDDLE/HIGH` | The levels select the external mieru client's session multiplexer; the kernel opens one encoded session per underlay connection and has no mieru mux layer. | `adapter/outbound/mieru.go:279-284` |
| mieru | `traffic-pattern` | Decoded/validated and applied inside the external `enfein/mieru` trafficpattern package (padding, nonce rewriting, low-entropy payloads, TCP fragmentation); no kernel-side implementation. The probe value is also rejected by Mihomo, so that row is not a disagreement. | `adapter/outbound/mieru.go:287-289,345-352` |
| sudoku | `http-mask-mode: stream/poll/auto/ws` | A mihomo extension over Sudoku (split-stream/poll/WebSocket tunnel clients with preconnect/retry/ready handshakes); not ported. The legacy header mask and the session mux are implemented. | `transport/sudoku/obfs/httpmask/{tunnel_dial,tunnel_conn_split,tunnel_ws,tunnel_preconnect,tunnel_retry,tunnel_ready}.go` |

These are registered in `evidence/rust-mapping.json` under each family's
`notImplemented`, with the same source paths, so the probe's
"rejected but not registered" check stays green.

## Regression validation

- Default suite: `cargo test --locked --manifest-path native-kernel/Cargo.toml
  -- --test-threads=1` in an independent `CARGO_TARGET_DIR`; every suite passes
  (208 lib, 56 config, protocols/quic/dns/tunnel suites).
- Pinned peer (`KC_MIHOMO_BIN=.cache/baseline/mihomo-a55a9073f9b7`,
  `--ignored`): the new trojan ShadowTLS/JLS, trusttunnel UDP, trusttunnel
  UDP-domain (`hosts` + `ip-version`) and sudoku UDP tests pass; the
  pre-existing trojan/trusttunnel peer tests still pass. The domain case would
  fail with a system-resolver fallback or without the `ip-version` filter
  because the name exists only in `hosts` and its v6 address is listed first.
- Differentials re-run against the same debug binary: t22 22/23 pass + 1 skip,
  t23 28/28 (incl. persistence), t24 36/38 pass + 2 skip, t25 47/49 + 2
  recorded divergences, t5 12/12; 0 differ/unexpected.
- `node --test tool/kernel-compat/runner.test.mjs`: 10/10.

## Boundaries left to the Owner

- Mieru `udp`/`multiplexing`/`traffic-pattern` are protocol/client-profile work
  inside the external GPL module; they are not “environment-impossible”, they
  are simply not implemented in this attempt. If the Owner wants them closed,
  they need a dedicated task with the enfein/mieru client surface pinned.
- masque `network: h2`/`h3-l4proxy` are additional CONNECT-IP/L4 carriers; the
  current RFC 9298 CONNECT-UDP + HTTP/3 CONNECT-IP paths are unaffected.
- `ip-stack.mode: gvisor` is a build-dependency decision (gVisor), not a parser
  gap.

## T33-A2 repair: trusttunnel domain resolution

T33-A1 resolved a trusttunnel UDP domain destination inside
`TrustTunnelUdp::send` with the ordinary system resolver (`outbound/udp.rs::resolve`,
fixed IPv4 preference). The pinned `Base.ResolveUDP` instead uses the session
hosts/DNS runtime and the proxy's `ip-version`; the mixed inbound keeps the
domain in `outgoing.host`, so SOCKS5 UDP domain datagrams bypassed the session
resolver.

The association/engine path now resolves first:
`engine::proxy_udp_destination` mirrors `Base.ResolveUDP` +
`resolveIPWithResolver` — a metadata-resolved `ip` wins, a literal is checked
against `ip-version`, and a name goes through the session `hosts` table, the
DNS runtime (`resolve_direct`), and only then (when no DNS runtime is
configured) the system resolver, with v4/v6 filtering and preference.
`TrustTunnelUdp::send` now accepts an IP only and never falls back to a system
resolver; the TUN association resolves a fake-ip-mapped name with the same
helper before sending (ordinary TUN flows already carry an IP).

Verified by `tests/mihomo_peers.rs::trusttunnel_udp_domain_destination_uses_the_session_resolver`:
a mixed-inbound SOCKS5 UDP datagram whose destination exists only in `hosts`
(`t33-probe.test: ['::1', '127.0.0.1']`) with `ip-version: ipv4` reaches the
IPv4 echo — a system-resolver fallback or a missing `ip-version` filter would
fail. The option matrix is unchanged (291 no-op / 119 implemented / 90 enabled,
0 problems).
