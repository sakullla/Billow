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
recorded in
`docs/sakullla-workflow/2026-11-20-native-rust-kernel/02-technical-solution.md`
("用户已明确授权 `sudoku`（T17）… 直接依据锁定源码翻译实现") and in the T17
recipe outcomes
(`03-execution-plan.md#tasks/T17`, "依据锁定 transport/sudoku 源码翻译实现必要子集").
The `docs/coordination/t17-handoff.md` interface file still states the earlier
`T17-A1` clean-room rule and has not been updated; it is Owner material, so the
contradiction is reported rather than edited here.

Consequences, and how they are recorded in the repository:

- The translated module is a derivative work of Mihomo's GPL-3.0
  `transport/sudoku`. The kernel workspace is therefore **GPL-3.0-only**:
  `native-kernel/Cargo.toml` declares `license = "GPL-3.0-only"`,
  `native-kernel/COPYING.GPL-3.0` carries the full text (identical to the
  repository root `LICENSE`), and `native-kernel/THIRD_PARTY_NOTICES.md` lists
  every translated file with its upstream source and the distribution
  obligations.
- Every translated file starts with `SPDX-License-Identifier: GPL-3.0-only`
  and a `Derived from Mihomo transport/sudoku (GPL-3.0)` header naming the
  pinned version, commit and source paths.
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
  parsing (strict, rejects the names above).
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
| pinned peer, 11 positive cases | `tool/kernel-compat/peer-tests.sh` | default session, no HTTP mask, ascii + packed downlink, directional table, custom table, table rotation, aes-128-gcm, `none`, private/public key material, sequential mux, concurrent mux |
| pinned peer, 2 negative cases | same | a wrong key and a mismatched `table-type` fail the dial and never reach the sink |
| codec differential | `cargo test --test protocols -- --ignored sudoku_codec_matches_the_pinned_implementation` | pinned encode -> Rust decode and Rust encode -> pinned decode, pure and packed, padding 0-0 and 10-30, for entropy/ascii/directional/custom layouts |
| default suite | `cargo test --manifest-path native-kernel/Cargo.toml --locked` | table/record/KIP/mux unit tests and `tests/config.rs::sudoku_options_are_strict` |
| option matrix | `node tool/kernel-compat/option-probe.mjs ...` | `multiplex: on`, `httpmask`, `http-mask` and `enable-pure-downlink` load; `udp: true` and `http-mask-mode: stream` are rejected by name |

Recorded results (2026-11-22, `macos-aarch64`, runs with a dedicated
`CARGO_TARGET_DIR` so a concurrent unrelated build cannot hold the shared
target lock):

| run | result |
| --- | --- |
| `cargo test --manifest-path native-kernel/Cargo.toml --locked` | 284 passed, 0 failed, 86 ignored (15 test binaries; first canonical attempt hit the documented peer-start flake in the unrelated `trojan_without_skip_cert_verify_fails_on_an_untrusted_certificate` case with an empty peer log, the immediate rerun passed, and the same case also passed in the isolated run) |
| `tool/kernel-compat/peer-tests.sh` | 63 passed, 0 failed in 60 s (`evidence/protocol-peers-run.log`) |
| `tool/kernel-compat/family-peers.sh` | exit 0; sudoku hint/padding vectors match and the codec differential passes (`evidence/family-peers-run.log`) |
| `node --test tool/kernel-compat/runner.test.mjs` | 10 passed, 0 failed |
| `node tool/kernel-compat/option-probe.mjs --rust <release> --mihomo <pinned>` | 261 no-op / 283 enabled / 0 problems (`evidence/option-matrix.txt`) |

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
