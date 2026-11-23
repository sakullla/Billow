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
Every `impl` row is `rust=accept mihomo=accept`.

## Implemented in this batch

`BasicOption` socket knobs are parsed once for every outbound and applied to
the connection to the proxy server (TCP dial, UDP association socket and QUIC
endpoint):

- `tfo`, `mptcp`, `interface-name`, `routing-mark`, `ip-version` for
  socks5, http, ss, trojan, vless, anytls, vmess, snell, trusttunnel,
  gost-relay, ssh, ssr, tuic, hysteria and hysteria2.
- TLS identities for the TLS families: `fingerprint` (SHA-256 pin),
  `name-cert-verify`, `certificate` and `private-key` (inline PEM or file,
  loaded when the handshake is built).
- QUIC transport tuning: `congestion-controller` (cubic/new_reno/bbr),
  `cwnd`, receive windows and `disable-mtu-discovery` for TUIC; `cwnd`, the
  initial/max stream/connection receive windows for hysteria2 (BBR is always
  selected, as the pinned client does); `recv-window*` and
  `disable-mtu-discovery` for hysteria v1.
- vless `ws-headers`: declared by the pinned type but never read (the applied
  map is `ws-opts.headers`), so accepting it is exact parity.
- socks5 `udp: true`: RFC 1928 `UDP ASSOCIATE` (control connection plus the
  relay socket, the same framing the mixed inbound serves); a `dialer-proxy`
  chain is rejected for this UDP form because the association dials the server
  directly.

## Per-family remaining gaps

Only families in this batch:

| family | before | after | remaining (named rejections) |
| --- | ---: | ---: | --- |
| vmess | 17 | 8 | udp, packet-addr, xudp, packet-encoding, tlsmirror-opts, mekya-opts, mkcp-opts, client-fingerprint |
| tuic | 21 | 9 | token(v4), udp-relay-mode, reduce-rtt, fast-open, udp-over-stream, bbr-profile, max-datagram-frame-size, max-udp-relay-packet-size, client-fingerprint |
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

## Platform notes

- `routing-mark`: Linux `SO_MARK`; other platforms accept and log once, exactly
  like the pinned `component/dialer/mark_nonlinux.go`.
- `mptcp`: Linux `IPPROTO_MPTCP`, TCP fallback; other platforms log and use
  TCP.
- `tfo`: Linux `TCP_FASTOPEN_CONNECT`; macOS `TCP_FASTOPEN` before connect
  (this kernel does not use `connectx`, so the first write is not placed in the
  SYN as `tfo-go` does).
- `interface-name`: Linux `SO_BINDTODEVICE`; macOS `IP_BOUND_IF` /
  `IPV6_BOUND_IF`.
- `certificate`/`private-key`: file paths resolve against the process working
  directory (Mihomo resolves against the config directory); prefer inline PEM
  or launch the kernel from the config directory.
- `client-fingerprint` remains a named gap: rustls cannot reproduce a uTLS
  ClientHello.

## Verification

- `cargo test --manifest-path native-kernel/Cargo.toml --locked` (all targets)
- new cases: `tests/config.rs::t27_tls_identity_options_are_parsed`, `tests/config.rs::t27_socks5_udp_is_accepted_and_chain_is_named`, `tests/protocols.rs::socks5_udp_association_reaches_the_peer_relay`,
  `tests/config.rs::t27_quic_transport_tuning_is_parsed`,
  `tests/protocols.rs::basic_dialer_options_are_applied_to_the_proxy_connection`,
  `tests/protocols.rs::fingerprint_pins_the_leaf_certificate`,
  `tests/protocols.rs::name_cert_verify_checks_the_configured_name`
- `evidence/t27-option-parity.json` holds the machine-readable before/after
  table and the same gap list.
