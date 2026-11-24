# T30 option closure: anytls / vless / ss / hysteria2 / vmess

Matrix: `evidence/option-matrix.txt` (289 no-op, 75 implemented, 131 enabled,
87 disagreements overall, 11 inside the five target families, **0 problems**).
Before T30: 151 enabled / 55 implemented; the target families had 31
rust=reject rows (vless 5, anytls 9, ss 2, hysteria2 7, vmess 8).

## Implemented and verified against the pinned Mihomo v1.19.34

| family | options | evidence |
| --- | --- | --- |
| vless | `udp` (XUDP is the pinned default), `xudp`, `packet-addr`, `packet-encoding: packetaddr\|packet\|xudp` | `tests/mihomo_peers.rs::vless_udp_xudp_reaches_the_echo_through_mihomo`, `...::vless_udp_packet_addr_reaches_the_echo_through_mihomo` |
| anytls | `udp` (UoT, one stream per destination), `client-metadata`, `idle-session-check-interval`, `idle-session-timeout`, `min-idle-session`, `disable-reuse` | `...::anytls_udp_uot_reaches_the_echo_through_mihomo`, `...::anytls_udp_reaches_two_destinations_from_one_association`, `...::chained_anytls_udp_with_a_dead_hop_never_reaches_the_echo` |
| ss | `udp-over-tcp`, `udp-over-tcp-version: 1\|2` (one stream per destination) | `...::shadowsocks_uot_reaches_the_echo_through_mihomo`, `...::shadowsocks_uot_v1_reaches_the_echo_through_mihomo`, `...::shadowsocks_uot_v2_reaches_two_destinations_from_one_association` |
| vmess | `udp`, `xudp`, `packet-addr`, `packet-encoding` (plain command-2 opens one association per destination) | `...::vmess_udp_modes_reach_the_echo_through_mihomo`, `...::vmess_plain_udp_reaches_two_destinations_from_one_association`, `...::chained_vmess_udp_with_a_dead_hop_never_reaches_the_echo` |

The UDP modes use the same SOCKS5 UDP ASSOCIATE harness as ss/trojan: one
association, a loopback UDP echo, and the pinned listener forwarding `DIRECT`
to it. A wrong password / wrong uuid cases stay in the peer suite.

## Approximated, counted as residual

`client-fingerprint` on vless/anytls/vmess/hysteria2 (4 matrix rows plus the
shared TLS note) is **not** byte parity. rustls cannot emit a uTLS ClientHello:
the pinned names are accepted and applied as the closest rustls profile
(browser key-exchange list), but extension order, GREASE and the exact cipher
list are not reproduced. The option matrix still counts the rows as loadable
(they must be accepted), while this closure records them as approximations and
never as verified parity.

## Named residuals (registered, never silently ignored)

- anytls `shadow-tls-opts`, `jls-opts`: the pinned outbound wraps TLS in
  ShadowTLS/JLS, which needs a client-chosen ClientHello session id or a
  rewritten ServerHello random. rustls exposes neither, so a non-empty block is
  rejected with the option named.
- vmess `mkcp-opts`, `mekya-opts`, `tlsmirror-opts`: separate transports.
- hysteria2 `up` (Brutal TX cap), `ports`/`hop-interval` (port hopping),
  `obfs` (Salamander/Gecko), `realm-opts`, `udp-mtu`, `bbr-profile`: quinn has
  no Brutal sender/profile selector and the engine has no Hysteria2 UDP
  association/packet layer; rejected with the reason.
- ss `plugin`/`plugin-opts` and the other pre-existing family gaps stay as
  before.

## Repair T30-A2 (review blockers)

1. **anytls/vmess UDP now honours `dialer-proxy`.** `AnytlsUot::connect` and
   `VmessUdp::connect` receive the same `chain_for` hops as the TCP path and
   build the server connection through `server_stream`: direct with one hop, a
   single SOCKS5 tunnel for the one-hop chain validated at load time, otherwise
   an explicit chain rejection. The dead-hop regressions prove a bypass is
   impossible: with the bypass forced, the anytls case reaches the echo and
   fails.
2. **One association per destination.** anytls UoT, ss UoT (v1/v2) and vmess
   plain `command 2` no longer bind to the first destination. The relay keeps a
   `(proxy, target) -> writer` map plus one reader task per association and an
   event channel back to the relay; readers are aborted with the association and
   a failed write retires its entry. The three `two_destinations` cases and a
   constant-key mutation (which makes the anytls case lose the second
   destination) cover this.
3. **AnyTLS session pool.** A background ticker now sweeps idle sessions every
   `idle-session-check-interval`; it starts on the first pooled session and is
   aborted on pool drop, which also closes idle sessions. Intervals and timeouts
   `<= 5s` normalize to 30s exactly like `session.NewClient`. The lazy
   acquire/release sweep remains as a fallback outside a runtime.
4. **AnytlsStream waker race.** `poll_read` re-checks the inbox and close state
   after publishing its waker, so a frame or close queued in that window cannot
   be lost.
5. **DNS test port race.** dns fixtures now reserve their ephemeral TCP/UDP
   ports (`common::bind_loopback{,_udp}`), so a parallel `free_port` cannot hand
   a UDP fixture port to a fixed `dns.listen`; the dns suite passed 12 repeated
   runs.

## Verification

- `CARGO_TARGET_DIR=<independent> cargo test --manifest-path
  native-kernel/Cargo.toml --locked`: all suites pass (165 lib, 50 config, 15
  controller, 19 dns, 32 groups, 60 protocols, 32 quic, 15 resources, 11
  sessions, 11 cli, 10 family_cli, 1 doc-test; 77 ignored peer cases).
- `tool/kernel-compat/peer-tests.sh`: **77 passed, 0 failed** (the A1 72 plus
  five new regressions) against the pinned Mihomo v1.19.34 binary.
- `node tool/kernel-compat/option-probe.mjs`: 289 / 75 / 131, 11 target-family
  disagreements, **0 problems**.
- `node --test tool/kernel-compat/runner.test.mjs`: 10 passed.
- Differentials re-run against the same pinned binary: t22 22 pass / 1 skipped
  / 0 differ; t23 28 pass / 0 differ; t24 36 pass / 2 skipped / 0 differ / 6
  recorded inbound framing differences; t25 47/49 equal / 2 recorded
  divergences / 0 unexpected; t5 12/12 scenarios / 0 differ. Every summary
  equals the previously recorded one.
