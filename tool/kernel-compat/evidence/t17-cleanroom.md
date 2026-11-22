# T17: clean-room Sudoku client attempt (blocked)

> Superseded by [`t17-translation.md`](t17-translation.md): after this
> clean-room attempt failed, the Owner authorised translating the pinned
> GPL-3.0 `transport/sudoku`, and attempt `T17-A2` delivered it under the
> GPL-3.0 obligations recorded there. This file is kept as the history of why
> the clean-room route could not produce a client.

Attempt: `T17-A1` (message `T17-A1-M1`).
Date: 2026-11-22.
Scope: `native-kernel/`, `tool/kernel-compat/`.

## Outcome in one paragraph

No wire-compatible Sudoku client was produced. The protocol is not described at
byte level anywhere in public material, and the parts that are missing are the
ones the peer validates: the key-derived puzzle table, the KIP handshake key
schedule and the record layer's key epochs. Black-box observation against the
pinned peer (this document's measurements) recovers the *shape* of the wire but
not the transforms: the same plaintext under the same key is encoded
differently on every connection, and a foreign handshake is rejected by name
(`INVALID_SUDOKU_MAP_MISS`). `type: sudoku` therefore stays rejected at load
time, now with the finding recorded. Reproducing the missing transforms needs a
decision from the Owner (see [Decision needed](#decision-needed)); it is not
something the current clean-room rules allow to be read out of the GPL-3.0
implementation.

This is a `needs_context` result, not a claim of partial compatibility: no
Sudoku code, vector or test was added, because nothing that cannot complete a
handshake is worth shipping as a protocol implementation.

## Clean-room posture applied

T13-A3 removed the first `sudoku` port because it was translated from the
pinned `transport/sudoku` (GPL-3.0); see
`tool/kernel-compat/evidence/t13-a3-sudoku-removal.md`. For this attempt:

- No Go source from the pinned tree was opened. Only the package's *file names*
  were listed, to confirm which layers exist (`tables.go`, `kip.go`,
  `handshake*.go`, `crypto/record_conn.go`, `httpmask_tunnel.go`, `uot.go`,
  `multiplex*.go`, `obfs/{sudoku,httpmask}`); a search for markdown in the
  pinned tree returns nothing about Sudoku.
- The only sources read are the upstream project's own documentation
  (README, `apis/README.md`, `configs/README.md`, `doc/getting-started.en.md`),
  the Mihomo documentation page for the proxy type, the Mihomo PR that
  integrated it, and the wire.
- No code, table, constant, vector or attribute data from the pinned tree or
  from the removed port was copied into the repository. The deleted
  `outbound/sudoku/` module was not restored from git history.

## Search for a public specification

Before concluding that the encoding is undocumented, these were checked
(2026-11-22):

| place | result |
| --- | --- |
| upstream repository, every markup/data file (`git/trees?recursive=1`, 207 blobs) | `README(.zh_CN)`, `apis/README`, `configs/README(.zh_CN)`, `doc/{README,getting-started.en,getting-started.zh,CHANGELOG.zh}` — behaviour and configuration only. The HTTP-mask template pools exist only as `pkg/obfs/httpmask/masker_*.txt` data inside the GPL-3.0 tree; they are not reproduced here |
| upstream issue/PR search (`search/issues?q=sudoku+repo:MetaCubeX/mihomo`, 31 hits) | release-sync PRs ("align to sudoku v0.4.x", "migrate sudoku kernel code to mihomo", "add uot", "customized byte style"); none carries a wire specification |
| repository search (`search/repositories?q=sudoku+proxy+mihomo`) | two deployment scripts; no independent implementation |
| mihomo docs site, Sudoku proxy page | field names and defaults only |

The upstream project's other clients are the same project (Android, desktop),
closed source (Anywhere), or explicitly incompatible (Xray's unrelated
`sudoku`).

## What the public material does specify

| source | what it gives |
| --- | --- |
| upstream project README (`SUDOKU-ASCII/sudoku`, GPL-3.0) | the idea: map a data stream into uniquely solvable 4x4 Sudoku puzzles built from four clues; 288 grids; "arbitrary padding" through unsolvable states; AEAD (AES-128-GCM / ChaCha20-Poly1305, `none` for tests); PFS with per-connection keys and rotation; anti-replay; pure vs packed downlink; fallback; UoT; mux |
| upstream `apis/README.md` | configuration surface: `NewTable(seed, prefer_ascii\|prefer_entropy)`, `NewTableWithCustom(seed, style, "xpxvvpvv")` (2x`x`, 2x`p`, 4x`v`), `Key`, `AEADMethod`, `PaddingMin/Max` as percentages, `EnablePureDownlink`, HTTP tunnel modes `stream`/`poll`/`auto`/`ws`, mux, reverse proxy, UoT |
| upstream `configs/README.md`, `doc/getting-started.en.md` | the JSON/YAML field names and which sides must match (`key`, `aead`, `padding_*`, `ascii`, `custom_table(s)`, `enable_pure_downlink`, `httpmask.*`) |
| mihomo docs, "Sudoku" proxy page | the Mihomo field names (`key`, `aead-method`, `padding-min/max`, `table-type`, `custom-table(s)`, `multiplex`, `httpmask.{disable,mode,tls,host,path-root,multiplex}`, `enable-pure-downlink`) and that a `key` may be either a Sudoku-generated private key or the same UUID on both ends |
| Mihomo PR "Add Sudoku protocol inbound & outbound support" | that the inbound implements the "standard/pure" mode only and that the outbound keeps on-wire compatibility with the upstream project |

None of these documents the *encoding*: not the table construction, not the
clue codebook, not the KIP messages, not the record framing, not the mask
template pool. They describe behaviour and configuration only.

## What was observed

Harness: `tool/kernel-compat/sudoku-observe.py` (added by this attempt). It
spawns the pinned release binary twice — once as `listeners: type: sudoku`,
once as a client with one `sudoku` proxy — and records the bytes a real session
puts on the wire through a loopback relay. Raw output:
`tool/kernel-compat/evidence/t17-observe.log`.

Fixture: `key: 27efbf96-8f28-4090-8bc8-d35a379d76ee`, `padding-min/max: 0`,
`table-type: prefer_ascii`, `httpmask.disable: true` unless stated, one
`GET /AAAA HTTP/1.1` request to a loopback HTTP target (82 target request
bytes).

| observation | command | result |
| --- | --- | --- |
| a session completes | `sudoku-observe.py probe` | `status 200`, uplink 676 bytes, downlink 512 bytes |
| uplink expansion | `sudoku-observe.py sweep-paths` | 680 / 688 / 696 / 712 / 744 / 808 / 936 bytes for path lengths 6/8/10/14/22/38/70, i.e. exactly **4 wire bytes per plaintext byte**; `uplink/4` is `164 + path_len`, and subtracting the 87-byte prefix (handshake + target address) leaves exactly the request the target received (83 bytes at path length 6) |
| downlink expansion | `sudoku-observe.py sweep-bodies` | 512 / 868 / 2468 / 4472 bytes for response bodies of 12/100/500/1000 bytes, i.e. exactly **4 wire bytes per response byte**, with a ~117-byte prefix |
| alphabet | `probe` | exactly **64 distinct symbols** in each direction; the only non-printable byte is `0x0a` (LF); the rest are `0x40..0x7e`; 98-99.7% of bytes are printable ASCII. 64 symbols = 6 bits per clue, four clues per byte |
| encoding is randomized | `repeat --repeats 2` | both captures are 676 bytes (= 169 clue quadruples) but differ in ~640 of 676 positions; the two captures share 2 quadruples, and each capture itself has 168-169 distinct values. Plaintext bytes that repeat inside the request do not repeat on the wire |
| the table is key-derived | `probe --key 11111111-2222-3333-4444-555555555555` | a different key keeps the lengths and the 64-symbol alphabet but changes every byte |
| AEAD adds framing | `probe --aead chacha20-poly1305` | uplink 676 -> 1036 bytes, downlink 512 -> 752 bytes for the same payload |
| legacy HTTP mask | `probe --httpmask legacy` | the first ~520 bytes are a plaintext, per-connection randomized browser request (`POST /api/v1/upload HTTP/1.1`, `Host: <server>`, a Chrome `User-Agent`, `Content-Length: 6410488`, ...) followed by the same Sudoku-encoded stream; total uplink 1194 = 676 + 518 |
| a client without the table is rejected | `sudoku-observe.py reject` | `GET / HTTP/1.1` -> connection closed, no reply, no target request; 64 zero bytes -> `[Sudoku] suspicious handshake ... INVALID_SUDOKU_MAP_MISS`; 256 high-entropy bytes -> same |

Reading of the measurements: one plaintext byte becomes one "clue
quadruple" drawn from a 64-symbol alphabet, and the encoder picks a *different*
quadruple for the same byte on every occurrence. That is consistent with a
key-derived table that enumerates the 288 solution grids and their valid
four-clue presentations, with the table itself used for decoding. The peer's
decoder error for a foreign stream is literally `INVALID_SUDOKU_MAP_MISS`.

## What is blocked, and why observation cannot supply it

| field | why it cannot be derived from public material or the wire |
| --- | --- |
| table construction from `key` (`key` -> 256-entry puzzle codebook, clue-set pool, 64-symbol style order) | the mapping is keyed. The wire symbol -> `(cell, digit)` style order is part of the table, so a captured quadruple cannot even be read as a puzzle without it; and even a codebook recovered for one key by exhaustive probing would not generalise to a *user's* key, because what is missing is exactly the derivation `key -> table`. Nothing public states the grid enumeration order, the byte->grid assignment, the clue selection, the style permutation or the hash/PRNG behind them |
| KIP handshake (X25519 + HKDF, message layout, `table`/`custom-tables` hint, timestamp and nonce handling, replay window) | the handshake lives inside the same table-obfuscated stream, so it cannot be separated from the data without the table; its HKDF `info` labels, salt and transcript are internal. Only the *size* is visible (~87 bytes uplink, ~117 downlink including the address) |
| record layer (record framing, epoch counters, HMAC derivation, sequence validation, key rotation cadence) | the extra 360 uplink / 240 downlink bytes with ChaCha20-Poly1305 show that records exist, but the tag inputs and the epoch key schedule are internal; with `aead-method: none` the layer is not exercised at all |
| legacy HTTP mask header generation | the template family is observable (paths, browser `User-Agent`s, header order, the fake `Content-Length`), but reproducing it is worthless without the stream layer above, and the pool of templates is not published |
| pure vs packed downlink framing | pure downlink is measurable (4 bytes per byte); the packed 6-bit downlink needs the same table/style pool and its chunk framing is not observable with `aead-method: none` (the documented mode "must be enabled" with AEAD) |
| multiplex (`multiplex: on`), HTTP tunnel modes (`stream`/`poll`/`auto`/`ws`), UoT | all of them wrap the same handshake and record layer, so they inherit every blocker above |

## Entry points

Both ways into the kernel reject the type with the same text, and each is
asserted by a test:

- embedded library: `billow-kernel`'s configuration load, asserted by
  `native-kernel/crates/billow-kernel/tests/config.rs::deferred_families_name_their_decision`
  (the message, the licence history, the T17 record path and the named
  `multiplex`/`UoT` layers);
- CLI process: `billow-kernel`'s process path, asserted by
  `native-kernel/crates/billow-kernel-cli/tests/cli.rs::process_loads_mieru_and_rejects_sudoku`
  (the process exits non-zero with `type 'sudoku' is not implemented` and never
  falls back to DIRECT).

## Verification run

```sh
$ cargo test --manifest-path native-kernel/Cargo.toml --locked
85 lib + 37 config + 48 protocols + 18 quic_peers + 11 sessions + 1
shadowquic_stream + 7 cli + 7 family_cli + 1 doc-test passed, 0 failed
(67 ignored peer cases)
$ tool/kernel-compat/peer-tests.sh
50 passed, 0 failed
$ tool/kernel-compat/family-peers.sh
wireguard_peer 5 passed, openvpn_peer 4 passed, 0 failed (+ the Go SSR/gost peers)
$ node --test tool/kernel-compat/runner.test.mjs
10 passed, 0 failed
$ node tool/kernel-compat/option-probe.mjs --rust <billow-kernel> --mihomo <mihomo>
213 no-op / 239 enabled / 0 problems (unchanged: no option row was added)
```

The harness runs in the same session as the tests and leaves no process behind
(both Mihomo processes are terminated in a `finally` block); it needs loopback
ports only.

## Decision needed

The remaining work cannot proceed under the current rule "implement only from
public documentation and black-box observation". The Owner has to choose:

1. **Keep Sudoku rejected** (current state). `type: sudoku` fails at load with
   the reason; T9 must record the family as unsupported, so a configuration
   using it is not "compatible".
2. **Authorise a specification-consultation process** for the pinned
   `transport/sudoku` (GPL-3.0): read the pinned implementation to write a
   written specification, then implement the specification without copying.
   That is not a strict no-source clean-room and must be recorded as such (the
   T15 `shadowquic` record already carries a comparable caveat). It still ends
   in an MIT kernel that derives from a GPL-3.0 work; whether that is
   acceptable is a licensing decision, not an implementation one.
3. **Wait for an upstream byte-level specification or a permissively licensed
   implementation.** Nothing of that kind exists today: the upstream project is
   GPL-3.0 with an additional name clause, and the other clients named on its
   page are either the same project (Android/desktop), closed (Anywhere), or
   explicitly incompatible (Xray).

Under (1) there is nothing further this task can implement; under (2) the
observation harness in this task is the recording tool for the resulting wire
checks; under (3) the task resumes when the specification exists.

## No-copy audit

Commands run from the repository root on 2026-11-22.

```sh
$ find native-kernel -name '*.go' | wc -l
0
$ grep -rn "transport/sudoku\|INVALID_SUDOKU_MAP\|NewTableWithCustom" \
    native-kernel --include='*.rs' --include='*.toml'
native-kernel/crates/billow-kernel/src/proxies.rs   # the rejection message only
$ git ls-files | grep -i sudoku
tool/kernel-compat/evidence/t13-a3-sudoku-removal.md   # the T13-A3 audit, no code
$ git status --porcelain | grep -i sudoku
nothing restored; the T13-A3 deletion stays in place (only the new harness and
evidence files mention Sudoku)
```

- The harness only spawns the pinned binary and records socket bytes; it
  contains no Sudoku algorithm, table or constant.
- `native-kernel/THIRD_PARTY_NOTICES.md` is unchanged: no new third-party code
  was added.
- The upstream project and the pinned Mihomo tree are both GPL-3.0. This
  repository ships neither and links neither; the pinned binary is a test peer
  only.

## Reproducing

```sh
$ node tool/kernel-compat/baseline.mjs --json          # pinned release binary
$ python3 tool/kernel-compat/sudoku-observe.py probe
$ python3 tool/kernel-compat/sudoku-observe.py reject
$ cargo test --manifest-path native-kernel/Cargo.toml --locked
$ node --test tool/kernel-compat/runner.test.mjs
```

The harness needs `python3`, `curl` and `node`; it binds loopback ports only and
cleans up both Mihomo processes in a `finally` block. The complete output of
the commands above is in `tool/kernel-compat/evidence/t17-observe.log`.
