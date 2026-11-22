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
- Rust engine: `cargo build --locked -p billow-kernel-cli` (debug; with the
  repository `.cargo` configuration the binary is
  `~/.cache/cargo-target/debug/billow-kernel`).

## Command

```sh
node tool/kernel-compat/t23-differential.mjs \
  --mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
  --rust ~/.cache/cargo-target/debug/billow-kernel \
  --out tool/kernel-compat/evidence/t23-differential.json
```

The probe starts loopback HTTP CONNECT nodes as members. A health node answers
the probe `HEAD` with a fixed delay/status (one node uses a per-HEAD delay
sequence) and forwards ordinary tunnels; a dead member is an unbound loopback
port. Mihomo is driven through `GET /proxies/<group>` and
`PUT /proxies/<group>`; the Rust kernel through `--select GROUP=MEMBER`,
`--probe-groups`, `--wait-ms N` and `--print-groups` (one `GROUPS {json}`
line). Result: **27/27 pass, 0 differ** (`summary` in the JSON; 26 cases +
persistence).

## Startup and lazy semantics (pinned `healthcheck.go` / `provider.go`)

Pinned `NewHealthCheck` does not check in its constructor. The first check is
`go hc.check()` at the top of `HealthCheck.process`, started by
`baseProvider.Initial()` (the executor calls `Initial` for every provider,
including each group's compatible provider). `baseProvider.setProxies` starts
another `go hc.check()` after every provider snapshot swap. Both runs happen
regardless of `lazy`; the interval ticker afterwards applies `lazy` against
the task's own `lastTouch`.

The Rust kernel now reproduces that:

- every built task starts with `next_due = now` and a forced `initial` flag;
  the supervisor's first scheduler tick probes groups (nested groups have
  their own tasks), their inline members and every enabled provider;
- `HealthTarget::Provider` lazy gating reads the provider's own `health_check.lazy`
  and the provider `lastTouch`, never the group's flag; a provider task with no
  touch since start stays skipped, exactly like pinned `time.Since(zero) >= interval`;
- `Kernel::update_proxy_provider` (and a provider generation change observed by
  the scheduler) forces the provider-targeted tasks to run once, matching
  `setProxies`; a touched provider is the only way a later lazy tick runs;
- a real dial touches every group on the resolved path (outer and nested) and
  every `use` provider of those groups (`GroupBase.GetProxies(true)` /
  `GroupBase.Touch`); `now`/status reads do not touch;
- a probe of a nested group member also touches it: pinned `Proxy.URLTest`
  runs the member's `DialContext`, and a group's `DialContext` calls
  `GetProxies(true)` (`URLTest.fast(true)`, `Selector`/`Fallback` with `true`),
  so each group the probe actually dials is touched with its `use` providers.
  Without that, a lazily-configured nested group whose parent was probed or
  dialed never re-probes and its health/selection freezes at the startup
  values.

Differential evidence for this section:

| case | what it pins | observed (Mihomo / Rust) |
| --- | --- | --- |
| url-test-probes-with-default-lazy | no `lazy`/`interval` keys; the startup check still runs and the 10 ms member wins over 300 ms | `fast` / `fast` |
| provider-health-check-default-lazy | enabled file provider with default `lazy`; `Initial` probes at startup, the `use` group ranks the result | `fast` / `fast` |
| nested-auto-driven-by-outer-traffic | a nested url-test group probes at startup; an outer selector dial follows its fast member | `fast` / `fast` |
| nested-lazy-tick-runs-after-outer-touch | one dial through A=`url-test[leaf,B]` (interval 2) at 1 s; the parent probe at 2 s touches B=`url-test[n1,n2]` (interval 3); B's 3 s lazy tick re-probes n1 at 500 ms, so at 11.5 s (past the 10 s `fastSingle` cache) B reports n2 on both engines | `leaf\|now=n2` / `leaf\|now=n2` |
| provider-use-filter | `use` provider members through the group filter | `[Node-B]` / `[Node-B]` |

## url-test computation cache (pinned `URLTest.fastSingle`)

Pinned `URLTest.fast(false)` (`Now()`) and `fast(true)` (`DialContext`) run
inside `singledo.NewSingle(10s)`: a resolution within ten seconds of the last
computation returns the cached `fastNode` object unchanged, even when the
health data changed meanwhile. `URLTest.healthCheck` (the callback a dial
failure triggers) resets it before and after the check; `ForceSet` resets it;
the periodic `HealthCheck` does not. The Rust `fast_member` reproduces that
with a cached `(Member, Instant)` and a ten-second window. A test can replace
the clock through `GroupRegistry::set_clock` (and shorten the window with
`set_fast_cache_window`) so the window is crossed without sleeping.

`tests/groups.rs::url_test_fast_cache_holds_the_computed_member_for_the_window`
starts `changing` at 5 ms and `steady` at 100 ms, resolves `changing`, probes
again (400 ms), and asserts `now` still reports `changing`; after the injected
11 s jump it reports `steady`, and that result is cached too. The differential
case `url-test-cache-window` pins the same window against the binary: the 90 ms
member appears during the second health round, the 5 s dial still serves the
cached 100 ms member, and the 12.5 s dial switches (`steady,steady,changing`
on both).

## Extra group-URL probe (pinned `registerHealthCheckTask`)

An explicit group `url` with `use` providers registers that URL on each
provider's own `HealthCheck`:

- the URL is trimmed and ignored when empty or equal to the provider's
  `health-check.url` (the provider's own task already probes it);
- the probe executes with the provider's `hc.timeout`
  (`health-check.timeout`, 5000 default), never the group's `timeout`;
- an enabled provider keeps its own interval/ticker; a provider without one
  borrows the group interval (pinned sets `hc.interval` before `Initial`);
  `lazy` and `lastTouch` are the provider's.

`tests/groups.rs::explicit_group_url_uses_the_provider_health_check_timeout`
(150 ms node, provider timeout 500 ms, group timeout 40 ms) and
`::explicit_group_url_equal_to_the_provider_url_registers_no_probe`
(`enable: false` + equal URL probes nothing) pin both rules.

## Empty-fallback naming (pinned `parser.go` / `GroupBase.GetProxies`)

`include-all-proxies` with an empty expansion appends the configured
`empty-fallback` name, not a hard-coded `COMPATIBLE`; `empty-fallback: REJECT`
therefore resolves to the REJECT member and blocks the CONNECT instead of
routing directly. The same naming rule applies when filters/exclude-filters
empty a group's resolved list: the default/`COMPATIBLE` member is named
`COMPATIBLE`, explicit `DIRECT` stays `DIRECT`, and proxy names keep their
name. `config.rs` keeps `Compatible` and `Direct` as separate variants so the
reported `all`/`emptyFallback` names match pinned.

## Cases

| case | what it pins | observed (Mihomo / Rust) |
| --- | --- | --- |
| select-default-first | selector defaults to the first member | `A` / `A`, all `[A,B]` |
| select-default-selected | `default-selected` fixes the selector | `B` / `B` |
| select-after-put | fixed selection changes the next dial | `B` / `B` |
| url-test-picks-fastest | lowest probe delay wins (300 ms vs 10 ms) | `fast` / `fast`, delays 303 ms / 13 ms |
| url-test-probes-with-default-lazy | startup check runs with the default lazy config | `fast` / `fast` |
| fallback-moves-off-dead | failed probe is skipped | `backup` / `backup`, `dead` not alive |
| expected-status-excludes-code | `expected-status: 204` rejects a 500 answer | `ok` / `ok`, `err` not alive |
| expected-status-default-accepts-any-code | no `expected-status` accepts any HTTP code | `err` / `err` (6 ms beats 102 ms) |
| tolerance-keeps-previous-fast | first resolution sets `steady` (100 ms); `changing` later becomes 90 ms, inside tolerance 50, so the previous fastNode stays | `steady,steady` / `steady,steady` |
| tolerance-zero-switches | the same delays with tolerance 0 switch to the faster member | `steady,changing` / `steady,changing` |
| url-test-cache-window | after the first computation the 7 s probe changes `changing` to 90 ms; the 9 s dial is still served by the cached `steady`, and only the 12.5 s dial (past the 10 s `fastSingle` window) switches | `steady,steady,changing` / `steady,steady,changing` |
| nested-group-inner-selection | `now` of a selector reports the nested group name | `INNER` / `INNER` |
| nested-group-dials-inner-selection | a dial follows the inner fallback choice | `backup` / `backup` |
| nested-auto-driven-by-outer-traffic | nested url-test startup + outer dial | `fast` / `fast` |
| nested-lazy-tick-runs-after-outer-touch | parent probe touches the nested group; its lazy tick re-probes and `now` flips to n2 after the 10 s cache | `leaf\|now=n2` / `leaf\|now=n2` |
| include-all-proxies-filter | sorted proxy names through `filter` | `[Alpha]` / `[Alpha]` |
| include-all-proxies-empty-fallback-reject | `proxies: []` + include-all-proxies uses the configured `empty-fallback`, not COMPATIBLE | `now=REJECT`, all `[REJECT]` on both |
| include-all-proxies-empty-fallback-direct | `empty-fallback: DIRECT` keeps the DIRECT member name (default is COMPATIBLE) | `now=DIRECT`, all `[DIRECT]` on both |
| include-all-proxies-empty-fallback-reject-blocked | the same group blocks the CONNECT instead of dialing DIRECT | blocked outcome class on both (403 / close / timeout depending on the race; no echo) |
| include-all-expands-everything | include-all turns on proxies and providers | `[Alpha,Zebra]` / `[Alpha,Zebra]` |
| exclude-type-uses-adapter-name | `exclude-type: Http` removes the http adapter | `[S]` / `[S]` |
| provider-use-filter | `use` provider members through the group filter | `[Node-B]` / `[Node-B]` |
| provider-health-check-default-lazy | provider `Initial` startup check with default lazy | `fast` / `fast` |
| load-balance-round-robin | round-robin order over four CONNECTs | `A,B,A,B` / `A,B,A,B` |
| select-rule-target-traffic | a rule naming the group dials the selected member | `A,A` / `A,A` |
| relay-rejected | pinned and Rust both refuse the removed type | both exit non-zero with `relay type was removed ... dialer-proxy` |
| selection-persisted-across-restart | `profile.store-selected` survives a restart | `B -> B` / `B -> B` |

### Tolerance evidence

`tolerance-keeps-previous-fast` / `tolerance-zero-switches` run two traffic
attempts per engine on the same nodes. The first member answers its first
probe in 200 ms and every later probe in 90 ms; the second member always
answers in 100 ms. The first attempt (300 ms after start) resolves `steady`
(100 ms) because `changing` is still 200 ms. The second attempt is at 10.5 s:
pinned `URLTest.fastSingle` caches the first computation for 10 s, so the
second computation happens then; with tolerance 50 the previous 100 ms
`steady` stays (`100 > 90 + 50` is false), with tolerance 0 it switches to the
90 ms `changing`. The Rust kernel keeps the same `fastNode` state and the same
ten-second computation cache, so the second resolution is also the first
recomputation and applies the same comparison. Both tolerances were previously
tested with delays where tolerance could not change the outcome; these two
cases distinguish the two states.

## Dialer-proxy probe fix

`GroupRegistry::probe_one` used to dial only the selected member
(`dial_chain(&[proxy], ...)`). It now builds the member's whole
`dialer-proxy` chain (the loader accepts inline proxy names only) and passes
the same hop list to `outbound::dial_chain` as a real dial, so a probe cannot
bypass a hop. `tests/groups.rs::health_probe_uses_the_dialer_proxy_chain`
starts a SOCKS5 hop and a SOCKS5 exit, probes a group member with
`dialer-proxy: hop`, and asserts both the hop and the exit accepted a
connection (a single-hop probe would leave the hop at zero).

## Regression runs (this attempt)

- `node tool/kernel-compat/t23-differential.mjs ...` — 27/27 pass (26 cases +
  persistence), 0 differ (`evidence/t23-differential.json`); the new
  `nested-lazy-tick-runs-after-outer-touch` and `url-test-cache-window` cases
  are included.
- `cargo test --manifest-path native-kernel/Cargo.toml --locked` — exit 0
  (17 suites; group suite 28 tests, 0 failed, including the four new cases).
- `node tool/kernel-compat/t24-differential.mjs ... --out /tmp/t24-a3.json`
  — 37 cases, 35 pass + 2 skipped (`--mmdb-dir` not given), 0 differ.
- `tool/kernel-compat/peer-tests.sh dialer_proxy_chain` — 2/2 pinned-peer spot
  check (the full 66-case peer run was not repeated in this attempt).
- `node --test tool/kernel-compat/runner.test.mjs` — 10/10.

## Unit/integration coverage (`native-kernel/crates/billow-kernel/tests/groups.rs`)

- every group type and its fields (`default-selected`, interval, timeout, lazy,
  max-failed-times, expected-status ranges, tolerance, hidden/icon,
  disable-udp), defaults (interval 300 for automatic types, 0 for select);
- `relay` rejection with the pinned message; unknown types, missing
  `use`/`proxies`, unknown members/providers, duplicate names/group-vs-proxy,
  cycles, unknown strategy, `hash-key: in-user`, invalid expected-status and
  unknown empty-fallback all fail by name;
- filter/exclude-filter backtick split, exclude-type `|` split, include-all and
  include-all-proxies sorted expansion, and the configured `empty-fallback`
  name in an empty include-all-proxies expansion (`REJECT` stays blocking),
  plus filtered-empty member names (`COMPATIBLE` default vs explicit `DIRECT`);
- rule target naming a group (`Action::Group`) and group dial routing;
- url-test failover by measured delay, startup probes with default lazy (group,
  provider and nested), provider snapshot update forcing a check, tolerance
  keeping/switching the previous fastNode, the ten-second computation cache
  (with an injectable clock), a nested probe touching its lazy group, fallback
  off a dead node, nested group dialing, round-robin cycling and
  consistent-hashing pinning, `use` provider members with a group filter,
  exclude-type adapter names;
- the extra group-URL probe on a `use` provider using the provider's timeout,
  and an equal provider URL registering no probe;
- probe through a `dialer-proxy` SOCKS5 hop/exit chain;
- selection persistence across a kernel restart (`cache.yaml`);
- CLI: `--select`/`--print-groups`/`--cache-dir` round trip
  (`crates/billow-kernel-cli/tests/cli.rs`).

## Normalization and boundaries

- Mihomo type names are normalized (`Selector`→`select`, `URLTest`→`url-test`,
  `Fallback`→`fallback`, `LoadBalance`→`load-balance`). `now` and `all` are
  compared; latency values are not compared byte-wise (probe ports and tick
  phases differ). Liveness is asserted through `now`, the reported alive flags
  and the observed echo.
- `tolerance-*` cases compare the served node sequence, not latency values;
  the second sample is bound to pinned's 10 s `fastSingle` TTL.
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
