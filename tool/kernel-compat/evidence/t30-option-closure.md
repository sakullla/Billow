# T30 option closure: anytls / vless / ss / hysteria2 / vmess

Matrix: `evidence/option-matrix.txt` (289 no-op, 75 implemented, 131 enabled,
87 disagreements overall, 11 inside the five target families, **0 problems**).
Before T30: 151 enabled / 55 implemented; the target families had 31
rust=reject rows (vless 5, anytls 9, ss 2, hysteria2 7, vmess 8).

## Implemented and verified against the pinned Mihomo v1.19.34

| family | options | evidence |
| --- | --- | --- |
| vless | `udp` (XUDP is the pinned default), `xudp`, `packet-addr`, `packet-encoding: packetaddr\|packet\|xudp` | `tests/mihomo_peers.rs::vless_udp_xudp_reaches_the_echo_through_mihomo`, `...::vless_udp_packet_addr_reaches_the_echo_through_mihomo` |
| anytls | `udp` (UoT), `client-metadata`, `idle-session-check-interval`, `idle-session-timeout`, `min-idle-session`, `disable-reuse` | `...::anytls_udp_uot_reaches_the_echo_through_mihomo`, existing `anytls_outbound...` / wrong-password peer cases |
| ss | `udp-over-tcp`, `udp-over-tcp-version: 1\|2` | `...::shadowsocks_uot_reaches_the_echo_through_mihomo`, `...::shadowsocks_uot_v1_reaches_the_echo_through_mihomo` |
| vmess | `udp`, `xudp`, `packet-addr`, `packet-encoding` | `...::vmess_udp_modes_reach_the_echo_through_mihomo` (plain, packet-addr, XUDP) |
| vless/anytls/vmess/hysteria2 | `client-fingerprint` accepted and applied as the closest rustls profile | `tests/config.rs::t30_datagram_and_fingerprint_options_are_accepted`; pushes/cases for anytls/vless TCP handshakes |

The UDP modes use the same SOCKS5 UDP ASSOCIATE harness as ss/trojan:
one association, a loopback UDP echo, and the pinned listener forwarding
`DIRECT` to it. A wrong password / wrong uuid cases stay in the peer suite.

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

## uTLS approximation

`client-fingerprint` names from the pinned `component/tls` table are accepted;
an unknown name also loads (pinned `GetFingerprint` warns and falls back).
Known names remove P-384 from rustls' key-exchange list to approximate the
browser ClientHello. Extension order, GREASE and the exact cipher list are not
reproduced; this is recorded in `rust-mapping.json` and README rather than
claimed as byte parity.
