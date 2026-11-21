# T13-A3: removal of the GPL-derived Sudoku port

Attempt: `T13-A3` (message `T13-A3-M1`).
Date: 2026-11-22.
Scope: `native-kernel/`, `tool/kernel-compat/`.

## Why

The T13-A1 review (`evidence/history/20.json`, finding P1) established that the
first `sudoku` port was not clean-room:

- `src/outbound/sudoku/table.rs` declared itself a "straight reimplementation
  of the pinned algorithm", `record.rs`/`kip.rs`/`codec.rs` reproduced the
  pinned functions and even the pinned HTTP-mask path/User-Agent tables, and
  `go_rand.rs` copied Go's `math/rand` `rngCooked` table.
- The locked Mihomo tree that these files were derived from is licensed
  GPL-3.0, not MIT:
  `tool/kernel-compat/.cache/source/tree-v1.19.34/LICENSE` starts with
  "GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007", and
  `transport/sudoku` carries no separate MIT notice.
- The kernel itself is MIT (`native-kernel/Cargo.toml`), so distributing a
  translated GPL-3.0 subtree would be a license violation.

The narrowed T13 recipe therefore keeps the clean-room mieru client and removes
the sudoku implementation; a clean-room sudoku rewrite is T17.

## Removed

| path | what it was |
| --- | --- |
| `native-kernel/crates/billow-kernel/src/outbound/sudoku/mod.rs` | dial, stream, table cache, handshake driver |
| `native-kernel/crates/billow-kernel/src/outbound/sudoku/table.rs` | translated table/layout/hint-set construction and both codecs |
| `native-kernel/crates/billow-kernel/src/outbound/sudoku/go_rand.rs` | Go `math/rand` `rngSource` + `rngCooked` copy |
| `native-kernel/crates/billow-kernel/src/outbound/sudoku/record.rs` | translated record layer |
| `native-kernel/crates/billow-kernel/src/outbound/sudoku/kip.rs` | translated KIP handshake |
| `native-kernel/crates/billow-kernel/src/outbound/sudoku/codec.rs` | translated obfuscation framing + pinned HTTP-mask header tables |
| `tool/kernel-compat/peers/sudoku-vectors/` (`go.mod`, `go.sum`, `main.go`) | Go codec/vector peer built from the GPL tree |
| tests: `mihomo_peers.rs` sudoku cases (11), `protocols.rs::sudoku_codec_matches_the_pinned_implementation` and its helpers, `config.rs::sudoku_options_are_strict` | they exercised the removed implementation |
| `keys.rs::sudoku_seed` and its test | canonicalisation used only by sudoku |
| `proxies.rs`: `SudokuOutbound`/`SudokuAead`/`SudokuMultiplex`/`parse_sudoku`/`sudoku_padding`, `Protocol::Sudoku` and its match arms, `supported_protocol_names` entry | the type is rejected by name again |
| `Cargo.toml` `curve25519-dalek` (workspace + crate) and the corresponding lock entry | only the sudoku key canonicalisation used it; `x25519-dalek` stays because the T15 JLS and T16 WireGuard outbounds use it |
| `family-peers.sh` sudoku section, `option-probe.mjs` sudoku bases/rows, `runner.test.mjs` sudoku claim | they pointed at the removed code and peer |

`type: sudoku` in a configuration now fails at load time with:

```text
[unsupported] proxies[0] (name=..., type=sudoku): protocol type 'sudoku' is
not implemented: the earlier port was a GPL-3.0 derivative of the pinned
`transport/sudoku` and has been removed; a clean-room implementation is T17
```

## Audit

Commands run from the repository root on 2026-11-22.

```sh
$ git ls-files | grep -i sudoku
native-kernel/crates/billow-kernel/src/outbound/sudoku/{codec,go_rand,kip,mod,record,table}.rs
tool/kernel-compat/peers/sudoku-vectors/{go.mod,go.sum,main.go}
```

Those are the tracked files scheduled for deletion; the working tree already
has them removed (`git status` shows ` D`, and the Runtime commits the
deletion). After the commit, `git ls-files | grep -i sudoku` returns nothing.
No other sudoku file is tracked (no `tests/data` sudoku fixture, no vectors).

```sh
$ grep -rn "outbound::sudoku\|outbound/sudoku\|sudoku-vectors\|rngCooked\|RNG_COOKED\|sudoku_seed" \
    native-kernel tool/kernel-compat --exclude-dir=.cache
tool/kernel-compat/evidence/rust-mapping.json        # (fixed: generatedFrom no longer lists outbound/sudoku)
tool/kernel-compat/evidence/t11-feasibility.json     # upstream path only: .cache/source/.../adapter/outbound/sudoku.go
tool/kernel-compat/evidence/protocol-peers.json      # this removal record and the deleted-path inventory
```

The only remaining matches are evidence text: the T11 feasibility note points
at the *upstream* file inside the gitignored locked cache, and
`protocol-peers.json#t13.removal` records what was deleted. There is no code,
test, fixture, peer or build dependency left.

```sh
$ grep -rln "sudoku" native-kernel --include='*.rs' --include='*.toml' --include='*.go'
native-kernel/crates/billow-kernel/src/proxies.rs            # the rejection message (GPL-3.0 ... T17)
native-kernel/crates/billow-kernel/tests/config.rs           # asserts the rejection names the removal and T17
native-kernel/crates/billow-kernel-cli/tests/cli.rs          # asserts the CLI rejects it with that message
```

```sh
$ grep -n "curve25519-dalek" native-kernel/Cargo.lock
563: name = "curve25519-dalek"           # transitive dependency of x25519-dalek
681: "curve25519-dalek",                  # required by x25519-dalek 2.0.1
```

`billow-kernel`'s own dependency list in `Cargo.lock` no longer contains
`curve25519-dalek`; it remains only through `x25519-dalek`, which T15
(`jls.rs`) and T16 (`wireguard.rs`) use and which is already recorded in
`native-kernel/THIRD_PARTY_NOTICES.md` and `protocol-peers.json#t13.license`.

### Locked source cache

`tool/kernel-compat/.cache/` is gitignored (`.cache/` in
`tool/kernel-compat/.gitignore`) and holds the pinned upstream tree used by the
differential harness as a black-box peer. The GPL-3.0 tree is not part of the
kernel distribution and no file from it is copied into the repository. After
this change nothing under `native-kernel/` or `tool/kernel-compat/peers/`
derives from it for sudoku.

## mieru re-verification

The mieru client was written from the module's published `docs/protocol.md` and
wire observations only; its source in
`native-kernel/crates/billow-kernel/src/outbound/mieru.rs` never referenced the
GPL module. It is unchanged by this removal and still verified against the
pinned `listeners: type: mieru` peer:

```sh
$ tool/kernel-compat/peer-tests.sh
test result: ok. 50 passed; 0 failed; 0 ignored
```

The five mieru cases are the TCP session, `port-range`, the idle session across
the five-second heartbeat, the wrong password (silent drop, bounded handshake)
and the closed peer port. Rejected options are unchanged: `transport: UDP`,
`udp: true`, the multiplexing levels and `traffic-pattern`.

## Evidence updated

- `native-kernel/README.md`: mieru stays in the status/table/tests; sudoku is
  described only as removed (no implemented/compatible claim remains), the
  family counts drop to twelve implemented, the license paragraph records the
  removal, and `peer-tests.sh` is stated as 50 cases.
- `evidence/rust-mapping.json`: `proxies.sudoku` is `unimplemented` with the
  removal reason and T17 owner; `familiesNotImplemented.sudoku` re-registered;
  `generatedFrom` no longer mentions the removed module.
- `evidence/protocol-peers.json`: the `sudoku` family and its cases are gone;
  `result` is 50; `t13` records the removal, the T17 hand-off and the license
  boundary; `t11`'s limitation note and `controlledPeers.note` are corrected.
- `evidence/source-capabilities.json`: regenerated from the mapping
  (`node tool/kernel-compat/capability.mjs --out ...`), sudoku now
  `unimplemented`.
- `evidence/option-matrix.txt`: regenerated (213 no-op / 239 enabled /
  0 problems) without sudoku rows.
- `evidence/t11-feasibility.json`: the sudoku `next_steps` carry an `outcome`
  note requiring a clean-room approach (T17); the mieru entry records that
  T13 delivered the clean-room TCP client.
- `evidence/protocol-peers-run.log`, `evidence/family-peers-run.log`:
  regenerated with the new suites.
