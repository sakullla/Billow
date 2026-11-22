# T23 — proxy groups, selection and health checks

Status: **implemented** for `select`, `url-test`, `fallback` and `load-balance`
(with nested groups, provider `use`, filters/include-all, interval health
checks and a selection cache). `relay` is a named rejection because pinned
Mihomo v1.19.34 removed the type. The boundaries are listed at the end.

## Environment

- date: 2026-11-22 (Asia/Shanghai), macOS arm64.
- pinned engine: `tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7`
  (`sha256:a55a9073f9b7b1fa596a82c034d2dae3407ec34732102b6e42c5513ce3033f34`),
  whose `adapter/outboundgroup` and `adapter/provider` trees are identical to
  `tree-v1.19.34`.
- Rust engine: `cargo build --locked -p billow-kernel-cli` (debug,
  `sha256:2026213d8503e261cf4531de8721d693703f4132b47a7902716bcfe18f0f2f65`).

## Command

```sh
node tool/kernel-compat/t23-differential.mjs \
  --mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
  --rust native-kernel/target/debug/billow-kernel \
  --out tool/kernel-compat/evidence/t23-differential.json
```

The probe starts loopback HTTP CONNECT nodes as members. A health node answers
the probe `HEAD` with a fixed delay/status and forwards ordinary tunnels; a
dead member is an unbound loopback port. Mihomo is driven through
`GET /proxies/<group>` and `PUT /proxies/<group>`; the Rust kernel through
`--select GROUP=MEMBER`, `--probe-groups`, `--wait-ms N` and `--print-groups`
(one `GROUPS {json}` line). Result: **18/18 pass, 0 differ** (`summary` in the
JSON).

## Cases

| case | what it pins | observed (Mihomo / Rust) |
| --- | --- | --- |
| select-default-first | selector defaults to the first member | `A` / `A`, all `[A,B]` |
| select-default-selected | `default-selected` fixes the selector | `B` / `B` |
| select-after-put | fixed selection changes the next dial | `B` / `B` |
| url-test-picks-fastest | lowest probe delay wins (300 ms vs 10 ms) | `fast` / `fast`, delays 304 ms / 11 ms |
| fallback-moves-off-dead | failed probe is skipped | `backup` / `backup`, `dead` not alive |
| expected-status-excludes-code | `expected-status: 204` rejects a 500 answer | `ok` / `ok`, `err` not alive |
| expected-status-default-accepts-any-code | no `expected-status` accepts any HTTP code | `err` / `err` (5 ms beats 100 ms) |
| tolerance-keeps-sticky | difference inside `tolerance` keeps the current member | `first` / `first` (104 ms vs 183 ms, tolerance 200) |
| nested-group-inner-selection | `now` of a selector reports the nested group name | `INNER` / `INNER` |
| nested-group-dials-inner-selection | a dial follows the inner fallback choice | `backup` / `backup` |
| include-all-proxies-filter | sorted proxy names through `filter` | `[Alpha]` / `[Alpha]` |
| include-all-expands-everything | include-all turns on proxies and providers | `[Alpha,Zebra]` / `[Alpha,Zebra]` |
| exclude-type-uses-adapter-name | `exclude-type: Http` removes the http adapter | `[S]` / `[S]` |
| provider-use-filter | `use` provider members through the group filter | `[Node-B]` / `[Node-B]` |
| load-balance-round-robin | round-robin order over four CONNECTs | `A,B,A,B` / `A,B,A,B` |
| select-rule-target-traffic | a rule naming the group dials the selected member | `A,A` / `A,A` |
| relay-rejected | pinned and Rust both refuse the removed type | both exit non-zero with `relay type was removed ... dialer-proxy` |
| selection-persisted-across-restart | `profile.store-selected` survives a restart | `B -> B` / `B -> B` |

## Regression runs

- `cargo test --manifest-path native-kernel/Cargo.toml --locked` — exit 0
  (all suites; group suite 16 tests).
- `tool/kernel-compat/peer-tests.sh` — 66/66 pinned-peer cases pass.
- `node tool/kernel-compat/t24-differential.mjs ... --out /tmp/t24-final.json`
  — 37 cases, 35 pass + 2 skipped (`--mmdb-dir` not given), 0 differ.
- `node --test tool/kernel-compat/runner.test.mjs` — 10/10.
- One parallel full-suite run ended with
  `ssr_outbound_wrong_password_never_reaches_the_target` failing on its
  peer-log timing assertion; it passed 3/3 isolated runs and in the final full
  run. It is unrelated to T23 (no groups in that configuration).

## Unit/integration coverage (`native-kernel/crates/billow-kernel/tests/groups.rs`)

- every group type and its fields (`default-selected`, interval, timeout, lazy,
  max-failed-times, expected-status ranges, tolerance, hidden/icon,
  disable-udp), defaults (interval 300 for automatic types, 0 for select);
- `relay` rejection with the pinned message; unknown types, missing
  `use`/`proxies`, unknown members/providers, duplicate names/group-vs-proxy,
  cycles, unknown strategy, `hash-key: in-user`, invalid expected-status and
  unknown empty-fallback all fail by name;
- filter/exclude-filter backtick split, exclude-type `|` split, include-all and
  include-all-proxies sorted expansion;
- rule target naming a group (`Action::Group`) and group dial routing;
- url-test failover by measured delay, fallback off a dead node, nested group
  dialing, round-robin cycling and consistent-hashing pinning, `use` provider
  members with a group filter, exclude-type adapter names;
- selection persistence across a kernel restart (`cache.yaml`);
- CLI: `--select`/`--print-groups`/`--cache-dir` round trip
  (`crates/billow-kernel-cli/tests/cli.rs`).

## Normalization and boundaries

- Mihomo type names are normalized (`Selector`→`select`, `URLTest`→`url-test`,
  `Fallback`→`fallback`, `LoadBalance`→`load-balance`). `now` and `all` are
  compared; latency values are not compared byte-wise (probe ports and tick
  phases differ). Liveness is asserted through `now`, the reported alive flags
  and the observed echo.
- Pinned consistent-hashing uses Go `maphash` with a per-process random seed, so
  its bucket assignment is not reproducible across runs. The Rust key is a
  deterministic FNV-1a hash over the effective domain (last two labels; no
  public-suffix table). Only round-robin is compared as an ordered sequence;
  pinning per destination is asserted by unit test.
- Pinned stores fixed selections in bbolt `cache.db`; the Rust kernel writes
  `<cache-dir>/cache.yaml` with the same group→member map. The files are not
  interchangeable; the persistence effect is compared.
- Not claimed: `hash-key: in-user` (rejected by name), `dialer-proxy` naming a
  group/provider proxy (rejected by name; only inline proxy names resolve,
  including for provider members), `relay` (removed by pinned), and the
  public-suffix-accurate hashing key.
