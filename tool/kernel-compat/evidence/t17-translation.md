# T17: source-derived Sudoku translation (GPL-3.0)

Attempts: `T17-A1` (clean-room attempt, blocked; record in
[`t17-cleanroom.md`](t17-cleanroom.md)) and `T17-A2` (this record).
Date: 2026-11-22.
Scope: `native-kernel/`, `tool/kernel-compat/`.

## Authorization and licence

`T17-A1` found that the Sudoku wire format (keyed table, KIP handshake, record
epochs) is not described at byte level in public material, and asked the Owner
to choose between keeping `type: sudoku` rejected and translating the pinned
GPL-3.0 source. The Owner chose the translation option; the authorization is
recorded in `docs/coordination/t17-handoff.md` (updated 2026-11-22 to authorise
the source translation), in
`docs/sakullla-workflow/2026-11-20-native-rust-kernel/02-technical-solution.md`
("用户已明确授权 `sudoku`（T17）… 直接依据锁定源码翻译实现") and in the T17
recipe outcomes
(`03-execution-plan.md#tasks/T17`, "依据锁定 transport/sudoku 源码翻译实现必要子集").

Consequences, and how they are recorded in the repository:

- The translated module is a derivative work of Mihomo's GPL-3.0
  `transport/sudoku`. The kernel workspace is therefore **GPL-3.0-only**:
  `native-kernel/Cargo.toml` declares `license = "GPL-3.0-only"`,
  `native-kernel/COPYING.GPL-3.0` carries the full text (identical to the
  repository root `LICENSE`), and `native-kernel/THIRD_PARTY_NOTICES.md` lists
  every translated file with its upstream source and the distribution
  obligations.
- Every standalone translated module file starts with
  `SPDX-License-Identifier: GPL-3.0-only` and a `Derived from Mihomo
  transport/sudoku (GPL-3.0)` header naming the pinned version, commit and
  source paths. `keys.rs` (`sudoku_seed`) and `proxies.rs` (`SudokuOutbound`,
  `parse_sudoku`) are mixed files: the same header sits on the GPL item and the
  module docs state that only that item is derived, while the rest of those
  files is original MIT code.
- `native-kernel/README.md` states the licence and no longer claims the module
  is MIT or unimplemented.
- The earlier T13-A3 removal audit
  ([`t13-a3-sudoku-removal.md`](t13-a3-sudoku-removal.md)) remains the history
  of the first, unlabelled port; it is superseded by this record, not erased.

Pinned source: Mihomo `v1.19.34`, commit
`0455d0d28c4526937380505153e65a843d8612e8`, tree
`tool/kernel-compat/.cache/source/tree-v1.19.34/transport/sudoku` (gitignored).
The same tree is the controlled test peer; the Go vector generator is
test-only and is never linked into the kernel.

## Translation scope

| layer | implemented | upstream source |
| --- | --- | --- |
| table/hint | 288 4x4 solution grids enumerated with Go `math/rand`'s `rngSource`/`Shuffle`, key -> table derivation, byte codebook, clue-set pool, 8-symbol style layouts (`x`/`p`/`v`), `prefer_ascii`/`prefer_entropy`/directional, custom patterns, table hint + probing | `transport/sudoku/obfs/sudoku/{table,layout,ascii_mode,grid,encode,conn,packed,downlink,padding_prob,rand,...}.go`, `tables.go`, `table_probe.go` |
| KIP | client hello (timestamp, user hash, nonce, X25519 public key, feature bits, table hint), server hello, HKDF session keys, rekey, `OpenTCP`/`StartMux` selection, keepalive frames | `transport/sudoku/{kip,handshake,handshake_kip,session_keys}.go` |
| record layer | `u16 length | epoch(4) | seq(8) | AEAD(header as nonce/AAD, plaintext)` with HMAC-SHA256 epoch subkeys, sequence check and replay rejection, chacha20-poly1305 / aes-128-gcm / none | `transport/sudoku/crypto/record_conn.go` |
| legacy HTTP mask | per-connection browser request header (path root, host, user agent, headers) before the stream | `transport/sudoku/obfs/httpmask/{masker,pathroot}.go` |
| pure/packed | pure downlink (4 wire bytes per byte) and packed 6-bit downlink with padding pool | `transport/sudoku/obfs/sudoku/{conn,packed}.go` |
| multiplex | session mux client (`multiplex: on`): open/data/close/reset/ping/pong frames, one cached session per configuration, whole-frame queueing, half-close and reset propagation | `transport/sudoku/multiplex/session.go`, `multiplex_dialer.go` |

Explicitly rejected at load time, with the reason recorded:

- `udp: true` — the UDP-over-TCP (UoT) association (`KIPTypeStartUoT`,
  `transport/sudoku/uot.go`) is not ported.
- `http-mask-mode: stream|poll|auto|ws` — the HTTP tunnel layer
  (`transport/sudoku/obfs/httpmask/tunnel_*`, a mihomo extension) is not
  ported. `legacy` (the default) is.

`sudoku` is TCP-only in the kernel; `multiplex: auto` behaves like `off`
because it only reuses an HTTP tunnel connection.

## Repairs (T17-A3 and T17-A4)

Review found five defects; all are fixed here.

- **`dialer-proxy` dropped the exit.** `dial_chain` sliced the chain from the
  first hop without a `dialer-proxy` and dialled that hop straight to the
  target, so a sudoku exit (and every other exit) was bypassed by a hop. It now
  keeps `chain[0]`: `connect_via_hops` tunnels the exit's server connection
  through the hop chain (the last hop is dialled locally, every earlier hop is
  negotiated over the stream produced by the hop below it), and `dial_over`
  runs the exit protocol over that stream toward the target. An exit whose
  protocol cannot run over a stream fails with a named chain error instead of
  letting a hop dial the target; the exit is never dropped. The T4/T12 UDP
  chain cases still pass (UDP uses its own association path).
- **`multiplex: on` + `dialer-proxy` failed every time (T17-A4).** The mux
  branch handed the raw hop stream to `MuxClient`, which only splits it; the
  KIP `StartMux` handshake was missing, so the pinned listener answered
  `INVALID_SUDOKU_MAP_MISS`. A new session now runs
  `connect_stream(option, Handshake::StartMux, None, hop_stream, server)` before
  the mux client is created, and the hop connection is opened lazily: a live
  cached session is reused without dialling the exit server and closing it
  again. The mux cache key includes the hop chain.
- **Regression tests.** `tests/protocols.rs::tcp_dialer_proxy_reaches_the_exit_
  through_the_hop` (socks5 exit + socks5 hop: the hop is asked for the exit
  server and the exit for the final target) and `...::tcp_dialer_proxy_never_
  bypasses_an_unsupported_exit`; `tests/mihomo_peers.rs::sudoku_dialer_proxy_
  carries_the_exit_through_the_socks5_hop` (sudoku exit + recording SOCKS5 hop
  + pinned Mihomo listener: exactly one hop CONNECT, addressed to the sudoku
  server, and the sink receives the marker);
  `...::sudoku_multiplex_over_a_dialer_proxy_reaches_the_receiving_side` (three
  sequential tunnels over one mux session, one hop CONNECT) and its wrong-key
  negative. The pre-existing two-hop peer case
  (`dialer_proxy_chain_connects_through_both_hops_seen_by_mihomo`) had passed
  only because the bypass delivered the marker; it now uses a recording hop
  and asserts the hop's sole CONNECT is the exit server.
- **Mux session lifetime.** `mux::close_all()` closes every cached session and
  `Kernel::stop` calls it, so a restarted engine in the same process never
  reuses a dead session; the mux cache key also includes the hop chain.
- **WriteQueue wake window.** `pop` signals with `notify_one` (which leaves a
  permit) instead of `notify_waiters`, so a sender between a failed `try_push`
  and `notified().await` cannot lose the wake.
- **GPL labelling.** `keys.rs::sudoku_seed` and `proxies.rs`'s
  `SudokuOutbound`/`parse_sudoku` now carry `SPDX-License-Identifier:
  GPL-3.0-only` item headers; `THIRD_PARTY_NOTICES.md` lists both mixed files
  with their derived range, and the stale "session mux not implemented"
  comment is corrected.

## Files

- `native-kernel/crates/billow-kernel/src/outbound/sudoku/mod.rs` — option
  validation, table cache, handshake, stream adapter, dial.
- `.../sudoku/table.rs` — grid enumeration, Go-compatible RNG, table
  construction, encoder/decoder, padding, custom layouts.
- `.../sudoku/record.rs` — record layer and epoch keys.
- `.../sudoku/kip.rs` — KIP messages and key schedule.
- `.../sudoku/mux.rs` — session multiplexer client.
- `.../sudoku/codec.rs` — pure/packed downlink and legacy HTTP mask.
- `.../sudoku/go_rand.rs` — Go `math/rand` `rngSource`/`rngCooked`/`Shuffle`
  (BSD-3-Clause, notice kept on top of the GPL-3.0 header).
- `native-kernel/crates/billow-kernel/src/proxies.rs` — `SudokuOutbound` option
  table and `parse_sudoku` (strict; rejects the names above). GPL-3.0-derived
  items only; the rest of the file is original MIT code.
- `native-kernel/crates/billow-kernel/src/keys.rs` — `sudoku_seed`, the
  canonical AEAD seed translated from `sudoku.ClientAEADSeed`. GPL-3.0-derived
  item only; the rest of the file is original MIT code.
- `native-kernel/crates/billow-kernel/src/outbound/mod.rs` — `dial_chain` /
  `connect_via_hops` (not a translation): the `dialer-proxy` dispatcher that
  carries the exit's server connection through the hop chain.
- `tool/kernel-compat/peers/sudoku-vectors/` — test-only Go differential
  generator built against the pinned tree.
- `native-kernel/COPYING.GPL-3.0`,
  `native-kernel/THIRD_PARTY_NOTICES.md` — licence text and file list.

## Verification

The peer cases use the pinned release binary as `listeners: type: sudoku`
(`tests/mihomo_peers.rs`); the codec differential uses the locked Go packages
through `tool/kernel-compat/peers/sudoku-vectors`
(`tests/protocols.rs::sudoku_codec_matches_the_pinned_implementation`).

| check | command | result |
| --- | --- | --- |
| pinned peer, 13 positive cases | `tool/kernel-compat/peer-tests.sh` | default session, no HTTP mask, ascii + packed downlink, directional table, custom table, table rotation, aes-128-gcm, `none`, private/public key material, sequential mux, concurrent mux, a `dialer-proxy` chain through a recording SOCKS5 hop, and `multiplex: on` over that chain |
| pinned peer, 3 negative cases | same | a wrong key, a mismatched `table-type`, and a wrong key over the mux+chain path fail the dial and never reach the sink |
| codec differential | `cargo test --test protocols -- --ignored sudoku_codec_matches_the_pinned_implementation` | pinned encode -> Rust decode and Rust encode -> pinned decode, pure and packed, padding 0-0 and 10-30, for entropy/ascii/directional/custom layouts |
| default suite | `cargo test --manifest-path native-kernel/Cargo.toml --locked` | table/record/KIP/mux unit tests and `tests/config.rs::sudoku_options_are_strict` |
| option matrix | `node tool/kernel-compat/option-probe.mjs ...` | `multiplex: on`, `httpmask`, `http-mask` and `enable-pure-downlink` load; `udp: true` and `http-mask-mode: stream` are rejected by name |

Recorded results (2026-11-22, `macos-aarch64`, runs with a dedicated
`CARGO_TARGET_DIR` so a concurrent unrelated build cannot hold the shared
target lock):

| run | result |
| --- | --- |
| `cargo test --manifest-path native-kernel/Cargo.toml --locked` | 286 passed, 0 failed, 89 ignored (15 test binaries; T17-A4 rerun) |
| `tool/kernel-compat/peer-tests.sh` | 66 passed, 0 failed (`evidence/protocol-peers-run.log`) |
| `tool/kernel-compat/family-peers.sh` | exit 0; sudoku hint/padding vectors match and the codec differential passes (`evidence/family-peers-run.log`) |
| `node --test tool/kernel-compat/runner.test.mjs` | 10 passed, 0 failed |
| `node tool/kernel-compat/option-probe.mjs --rust <release> --mihomo <pinned>` | 287 no-op / 304 enabled / 0 problems (`evidence/option-matrix.txt`) |

One defect was found and fixed while verifying: the read paths registered a
`Notify::notified()` future, polled it once and dropped it on `Pending`, which
unregistered the waker and left a delivered record unread (the mux unit test
hung forever). `Wakers` now keeps the registered wakers across `Pending` for
the stream, the mux streams and the write queue's capacity waiters.

The exact counts of each run are in the sibling logs
(`t17-tests.log`, `protocol-peers-run.log`, `family-peers-run.log`,
`option-matrix.txt`) and in the task run record.

Platform: `macos-aarch64`. The peer harness binds loopback ports only and
terminates both Mihomo processes in a `finally` block; the Go vector generator
needs `go` and the gitignored module cache.

## Byte-level differences from the pinned implementation

Interoperability is verified against the pinned peer, but the wire is not
claimed byte-for-byte identical:

- **Padding slots.** The pinned `appendSudokuPayload` draws one candidate slot
  before each hint and keeps none after the last hint; this encoder also draws
  a slot after every hint, so a write can carry one extra trailing padding slot
  (decoders skip padding, so both sides interoperate).
- **KIP features.** The client advertises `FEATURE_OPEN_TCP` (plus
  `FEATURE_MUX` for `StartMux`) rather than every `KIPFeatAll` bit. The server
  masks the offer with `KIPFeatAll` and only the requested command matters.
- **Mux keepalive.** The pinned session sends an empty `DATA` frame on stream 0
  every 15 s; this client sends a `PING` frame (the peer answers `PONG`), which
  keeps the session alive without claiming identical keepalive bytes.

## Known limitations

- Only the pinned Go `math/rand` algorithm is translated; a different Go
  toolchain with a changed `rngSource`/`rngCooked` would break table parity,
  which is why the version and commit are pinned and the differential runs on
  every `family-peers.sh` invocation.
- `go_rand.rs` reproduces Go standard-library data (`rngCooked`) under its own
  BSD-3-Clause notice.
- `padding-min/max` are validated and applied as percentages like the pinned
  option; the padding pool and threshold follow the pinned `padding_prob`.
- The HTTP tunnel modes and UoT are rejected rather than stubbed, so a
  configuration that needs them fails at load instead of falling back.
- No Android/Windows host run of the sudoku peers is recorded; the module is
  platform-independent Rust with no native dependency.
