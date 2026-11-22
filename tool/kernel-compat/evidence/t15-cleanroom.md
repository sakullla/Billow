# T15 ShadowQUIC transport provenance and clean-room record

Scope: the ShadowQUIC framing in
`native-kernel/crates/billow-kernel/src/outbound/shadowquic.rs` and the JLS
authentication in `.../outbound/jls.rs`. The JLS vector provenance and the
BSD-3-Clause text are in `native-kernel/THIRD_PARTY_NOTICES.md`.

## What the implementation is based on

The ShadowQUIC data path is a small, observable protocol:

- TCP: one bidirectional QUIC stream, `command = 0x01`, then a SOCKS5 address
  (`ATYP + address + port`), then raw bytes.
- UDP datagram carrier: `command = 0x03` plus a 7-byte unspecified IPv4
  address (`0.0.0.0:0`) on a bidirectional control stream; control entries are
  `SOCKS5 address + u16 id`; datagrams are `u16 id + payload`.
- UDP stream carrier (`udp-over-stream: true`): `command = 0x04` plus the same
  unspecified address; each destination uses one uni stream whose first two
  bytes are the id, followed by repeated `u16 length + payload`.
- QUIC itself is RFC 9000 (streams) and RFC 9221 (datagrams); the JLS
  authentication replaces the TLS 1.3 random (see `jls.rs`).

The Rust implementation was written from that protocol description and the
following black-box observations, not from a Go translation:

| observation | evidence |
| --- | --- |
| the pinned Mihomo listener accepts `0x01 + SOCKS5 address` and relays TCP | `tests/mihomo_peers.rs::shadowquic_outbound_reaches_the_receiving_side_through_mihomo` |
| the pinned listener accepts `0x03` + unspecified address and echoes UDP datagrams over QUIC datagrams | `tests/mihomo_peers.rs::shadowquic_udp_reaches_the_receiving_side_through_mihomo` |
| the pinned listener accepts `0x04` + unspecified address and uses the uni-stream length framing | `tests/mihomo_peers.rs::shadowquic_udp_over_stream_reaches_the_receiving_side_through_mihomo` |
| a wrong JLS account is forwarded to the camouflage upstream and no request reaches the sink | `tests/mihomo_peers.rs::shadowquic_wrong_password_never_reaches_the_sink` |
| a controlled independent QUIC peer observes the command byte, id mapping, uni-stream id/len framing, and accepts a rebuilt control stream after the old one is closed | `tests/shadowquic_stream.rs::udp_over_stream_reopens_a_stopped_uni_stream_and_control` |
| the real QUIC datagram limit is the path MTU, not only `max-datagram-frame-size`; oversized payloads use `udp-over-stream` | `shadowquic_udp_*` peer cases with a 1000-byte datagram and the `send` boundary error |
| the JLS seal matches real hello messages from the locked BSD package | `src/outbound/jls.rs::tests::verifies_locked_jls_client_and_server_hellos` plus `tests/data/shadowquic-jls.txt` |

The `tests/shadowquic_stream.rs` peer is written from the same observable
protocol, not from the kernel's client code: it reads the command, the address,
the id and the lengths from the wire and records them independently. It closes
the client's uni stream and control send half to prove the recovery behaviour.
For example, the peer observes `0x04` + `01 00000000 0000` (command 0x04 and
the unspecified address for the stream association), a control entry
`01 7f000001 2711 0000` (target `127.0.0.1:10001` + id 0), and the uni header
`0000 0003` followed by `one`; after a control rebuild it observes the
re-registered old target plus the new target `127.0.0.1:10002` with id 1.

## No-copy audit

Commands run on the candidate:

```text
$ find native-kernel -name '*.go' | wc -l
0
$ grep -rn 'connState\|WriteUDPControl\|ReadUDPControl\|transport/shadowquic' \
    native-kernel/crates/billow-kernel/src/outbound/shadowquic.rs
(no match; the header cites this evidence record and the BSD notice, not the GPL file)
```

- No Go source is vendored or linked by `native-kernel/`.
- No GPL-3.0 header, file path, or Go function/type name is copied into the
  Rust modules. The code uses new names and data structures (`ShadowQuicUdp`,
  `Shared`, `SharedState`, `read_address`, `open_control`, ...). The two
  modules do not cite the GPL files as a source; their headers cite this record
  and the BSD notice.
- The only protocol-level names shared with any implementation are the command
  byte values and the two integer widths, which are functional wire facts, not
  creative expression.
- The committed JLS vectors are the only upstream bytes; they are hex hello
  messages, not source. Their generator and its module license are recorded in
  `native-kernel/THIRD_PARTY_NOTICES.md` and
  `peers/shadowquic-jls-vectors/LICENSE`.

## Residual caveat / process history

When the first version of the framing was written, the pinned
`transport/shadowquic` files (GPL-3.0) were consulted to confirm the command
bytes and the control/uni framing. That is a source-consultation step, so this
is not a strict no-source clean-room. The implementation is a new Rust
expression of a functional wire format (not a line-by-line translation), and
the current behaviour is verified as a black box above. If the project requires
a formally documented clean-room, a separate spec/observer exercise is needed;
it is not claimed here. The functionality does not depend on GPL code at build
time or runtime.

## License

- JLS: the pinned `github.com/metacubex/jls-tls` is BSD-3-Clause (Copyright
  2009 The Go Authors). The full text is in
  `native-kernel/THIRD_PARTY_NOTICES.md`; the vectors are test fixtures only.
- ShadowQUIC framing: no GPL-3.0 source is copied; the residual process caveat
  above is recorded rather than hidden.
- At T15 the kernel workspace remained MIT; T17-A2 later relicensed the
  workspace to GPL-3.0-only because of the translated `transport/sudoku`
  (see `t17-translation.md` and `native-kernel/THIRD_PARTY_NOTICES.md`).
