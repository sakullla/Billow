# T27 option parity (first batch)

Driven by the `rust=reject/mihomo=accept` rows of
`evidence/t8-option-matrix.txt` (304 enabled cases, 250 disagreements). The
current matrix is `evidence/option-matrix.txt`, produced with the pinned Mihomo
v1.19.34 binary and a release build of `billow-kernel`:

```
node tool/kernel-compat/option-probe.mjs \
  --rust <built billow-kernel> \
  --mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
  --out tool/kernel-compat/evidence/option-matrix.txt
```

| cases | before | after |
| --- | ---: | ---: |
| enabled (must be rejected) | 304 | 179 |
| rust reject / mihomo accept | 250 | 135 |
| implemented (must load) | - | 50 |
| problems | 0 | 0 |

The probe gained an `impl` group: options that are now implemented must load,
so the matrix records the positive direction instead of only counting gaps.
Every `impl` row is `rust=accept mihomo=accept`. `certificate`/`private-key`
have no PEM fixture in the probe, so their positive evidence is the mTLS
handshake test below rather than an `impl` row.

## Repair after the first review (T27-A2)

Two blocking findings were fixed in the implementation; the counts above are
unchanged because both were already counted as implemented, and the fix is
about the paths actually using them.

- **SSH no longer bypasses the shared dialer.** `outbound/ssh.rs` opened its
  server connection with `russh::client::connect`, which builds its own
  `TcpStream` and never saw `tfo`/`mptcp`/`interface-name`/`routing-mark`.
  It now dials through `outbound::connect_tcp` and hands that stream to
  `russh::client::connect_stream`, so the same socket knobs (and `ip-version`)
  apply as for every other outbound. New test:
  `tests/protocols.rs::ssh_outbound_basic_options_use_the_shared_dialer` (a
  valid interface reaches the peer; an unbindable interface fails before any
  SSH bytes, proving the shared socket owns the connection).
- **socks5 `udp: true` works on the TUN data plane.** `tunnel/udp.rs` now maps
  `Protocol::Socks5` to the same `Socks5Udp` association the mixed inbound
  uses (control connection + RFC 1928 datagrams through the server relay),
  instead of dropping the flow as unsupported. New test:
  `tests/ios_tunnel.rs::socks5_udp_datagrams_cross_the_tunnel_in_both_directions`
  (device IP packet -> SOCKS5 association -> relay -> echo -> device packet,
  with `unsupported_protocols == 0`).

## Implemented in this batch

`BasicOption` socket knobs are parsed once for every outbound and applied to
the connection to the proxy server (TCP dial, UDP association socket and QUIC
endpoint):

- `tfo`, `mptcp`, `interface-name`, `routing-mark`, `ip-version` for
  socks5, http, ss, trojan, vless, anytls, vmess, snell, trusttunnel,
  gost-relay, ssh, ssr, tuic, hysteria and hysteria2.
- TLS identities for the TLS families: `fingerprint` (SHA-256 pin),
  `name-cert-verify`, `certificate` and `private-key` (inline PEM or file,
  loaded when the handshake is built). The client identity is exercised by a
  real mTLS handshake:
  `tests/protocols.rs::certificate_and_private_key_present_a_client_certificate`
  (a CA-signed client certificate is accepted by a server that requires one;
  the same server refuses a client without it).
- QUIC transport tuning: `congestion-controller` (cubic/new_reno/bbr),
  `cwnd`, receive windows and `disable-mtu-discovery` for TUIC; `cwnd`, the
  initial/max stream/connection receive windows for hysteria2 (BBR is always
  selected, as the pinned client does); `recv-window*` and
  `disable-mtu-discovery` for hysteria v1. TUIC applies `cwnd` only when the
  selected controller is `bbr`, matching the pinned `SetCongestionController`.
- vless `ws-headers`: declared by the pinned type but never read (the applied
  map is `ws-opts.headers`), so accepting it is exact parity.
- socks5 `udp: true`: RFC 1928 `UDP ASSOCIATE` (control connection plus the
  relay socket, the same framing the mixed inbound serves) on both the mixed
  inbound and the iOS/Android TUN data plane; a `dialer-proxy` chain is
  rejected for this UDP form because the association dials the server
  directly.

## Per-family remaining gaps

Only families in this batch:

| family | before | after | remaining (named rejections) |
| --- | ---: | ---: | --- |
| vmess | 17 | 8 | udp, packet-addr, xudp, packet-encoding, tlsmirror-opts, mekya-opts, mkcp-opts, client-fingerprint |
| tuic | 21 | 9 | token(v4), udp-relay-mode, reduce-rtt, fast-open, udp-over-stream, congestion-controller (bbr_meta_v1/bbr_meta_v2 values), bbr-profile, max-datagram-frame-size, max-udp-relay-packet-size, client-fingerprint |
| hysteria2 | 19 | 7 | up, ports, hop-interval, realm-opts, udp-mtu, bbr-profile, client-fingerprint |
| trusttunnel | 11 | 2 | udp, client-fingerprint |
| anytls | 17 | 9 | udp, client-metadata, idle-session-check-interval, idle-session-timeout, min-idle-session, disable-reuse, shadow-tls-opts, jls-opts, client-fingerprint |
| hysteria | 16 | 6 | ports, hop-interval, obfs, protocol, fast-open, client-fingerprint |
| vless | 11 | 5 | udp, packet-addr, xudp, packet-encoding, client-fingerprint |
| ss | 7 | 2 | udp-over-tcp, udp-over-tcp-version |
| socks5 | 8 | 0 | - |
| http | 7 | 0 | - |
| trojan | 9 | 4 | ss-opts, shadow-tls-opts, jls-opts, client-fingerprint |
| snell | 5 | 0 | - |
| gost-relay | 10 | 1 | client-fingerprint |
| ssh | 5 | 0 | - |
| ssr | 5 | 0 | - |

These stay registered in `evidence/rust-mapping.json` and are rejected with
their field name; accepting them while the behaviour is missing would be a
false compatibility claim.

UDP `dialer-proxy` chains scope the locally dialled socket to the hop, as TCP
does: `SsUdp`/`SsrUdp` enter the SOCKS5 hop inside `with_dialer(hop.dialer)`,
so the hop's `interface-name`/`routing-mark`/`ip-version` own the socket that
leaves the host, not the exit's. New test:
`tests/protocols.rs::shadowsocks_udp_hop_dialer_options_own_the_hop_socket`.

## Ownership of the remaining first-batch gaps

The 135 `enabled` rows stay visible in the matrix. T27 does not claim them as
implemented; the following ownership is proposed for the Owner to record in the
plan (no task was started here):

- **T28 (second batch)**: the protocol-family gaps listed above that fit its
  scope or can be added to it — vmess `udp`/`packet-addr`/`xudp`/
  `packet-encoding`/`mkcp`/`tlsmirror`/`mekya`, vless/anytls UoT
  (`packet-addr`/`xudp`/`client-metadata`/session pool), trojan
  `ss-opts`/`shadow-tls-opts`/`jls-opts`, ss `udp-over-tcp`, trusttunnel `udp`,
  gost-relay `client-fingerprint` (shared uTLS limitation), tuic
  `udp-relay-mode`/`udp-over-stream`/`reduce-rtt`/`fast-open`/datagram sizing,
  hysteria/hysteria2 `ports`/`hop-interval`/`obfs`/`realm-opts`/`udp-mtu`,
  TUIC meta BBR profiles, and the `client-fingerprint` family-wide gap.
- **T28 or a new task**: the TUN data-plane transports still missing for
  families whose `udp_enabled()` says yes (`gost-relay`, `wireguard`/
  `openvpn`/`tailscale`/`zerotier`/`easytier`), and the `udp: true` +
  `dialer-proxy` socks5 exit restriction.
- **T29 (platform evidence)**: Windows `interface-name` (the dialer rejects it
  by name; the pinned `bind_windows.go` implements `IP_UNICAST_IF`) and
  Windows/Linux device runs for the socket-knob paths that macOS exercised.
- **Unassigned / needs a decision**: pinned-only options with no observable
  local behaviour (`snell`-specific forms, `xhttp`/`grpc` transports for vmess
  without a pinned listener) — the Owner must decide between implementation
  and requirement narrowing.

## Platform notes

- `routing-mark`: Linux `SO_MARK`; other platforms accept and log once, exactly
  like the pinned `component/dialer/mark_nonlinux.go`.
- `mptcp`: Linux `IPPROTO_MPTCP`, TCP fallback; other platforms log and use
  TCP.
- `tfo`: Linux `TCP_FASTOPEN_CONNECT`; macOS `TCP_FASTOPEN` before connect
  (this kernel does not use `connectx`, so the first write is not placed in the
  SYN as `tfo-go` does). It is set only when `tfo: true`; on any other platform
  a configured `tfo` logs once and uses a normal connect (never a silent
  success).
- `interface-name`: Linux `SO_BINDTODEVICE`; macOS `IP_BOUND_IF` /
  `IPV6_BOUND_IF`. On other platforms (Windows included) the load accepts the
  key but every dial fails with the name in an `Unsupported` error; the pinned
  Windows dialer uses `IP_UNICAST_IF`, which this build does not implement.
- `certificate`/`private-key`: file paths resolve against the process working
  directory (Mihomo resolves against the config directory); prefer inline PEM
  or launch the kernel from the config directory.
- `client-fingerprint` remains a named gap: rustls cannot reproduce a uTLS
  ClientHello.

## Verification

- `cargo test --manifest-path native-kernel/Cargo.toml --locked` (all targets)
- `cargo test --manifest-path native-kernel/Cargo.toml --locked --features ios-vpn --test ios_tunnel`
  and `--features android-vpn --test android_tunnel` (device data plane)
- new cases: `tests/config.rs::t27_tls_identity_options_are_parsed`, `tests/config.rs::t27_socks5_udp_is_accepted_and_chain_is_named`, `tests/protocols.rs::socks5_udp_association_reaches_the_peer_relay`,
  `tests/config.rs::t27_quic_transport_tuning_is_parsed`,
  `tests/protocols.rs::basic_dialer_options_are_applied_to_the_proxy_connection`,
  `tests/protocols.rs::fingerprint_pins_the_leaf_certificate`,
  `tests/protocols.rs::name_cert_verify_checks_the_configured_name`,
  `tests/protocols.rs::certificate_and_private_key_present_a_client_certificate`,
  `tests/protocols.rs::ssh_outbound_basic_options_use_the_shared_dialer`,
  `tests/protocols.rs::shadowsocks_udp_hop_dialer_options_own_the_hop_socket`,
  `tests/ios_tunnel.rs::socks5_udp_datagrams_cross_the_tunnel_in_both_directions`
- `evidence/t27-option-parity.json` holds the machine-readable before/after
  table and the same gap list; `evidence/t27-a2/` holds the raw test,
  option-probe and differential logs of this repair run.
