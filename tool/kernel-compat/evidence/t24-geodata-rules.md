# T24 rules, providers, GEO/MRS and effective-config evidence

Task: `03-execution-plan.md#tasks/T24`. Baseline: the pinned Mihomo v1.19.34
binary/source used by the rest of `tool/kernel-compat`
(`src-tauri/desktop-kernel.json`, `src-tauri/android-kernel.json`).

## Result

| Area | Result | Evidence |
| --- | --- | --- |
| Rule types and first-match semantics | implemented; 31/31 differential cases agree on the normalized rule outcome | `tests/resources.rs::every_rule_type_matches_with_the_pinned_metadata`, `evidence/t24-differential.json` |
| Rule providers: file/http/inline, yaml/text/mrs, domain/ipcidr/classical | implemented; the declared interval is parsed but hosts/T25 drive updates through the explicit API | `tests/resources.rs::rule_providers_cover_every_vehicle_and_format` |
| Provider update success/failure | new snapshot on success; old generation kept and released on failure | `tests/resources.rs::http_provider_update_replaces_and_failure_keeps_the_old_generation`; Mihomo control API observation in `evidence/t24-differential.json` (`mihomo-provider-update`) |
| Proxy providers: file/http/inline, filter/exclude/dialer-proxy/health-check fields | loaded and exposed; latency probing and group `use`/`providers` are T23 | `tests/config.rs::proxy_providers_parse_filters_and_health_checks`, `tests/resources.rs::proxy_provider_file_applies_filter_exclude_and_dialer` |
| GeoSite.dat/GeoIP.dat protobuf, text/JSON geosite, MRS | implemented | `src/geodata.rs` tests; `tests/resources.rs::geosite_and_geoip_dat_rules_match_the_pinned_forms`; differential `geosite-dat-hit`/`geoip-dat-hit` |
| MaxMind DB (`Country.mmdb`, `ASN.mmdb`) | implemented (v2 reader; GeoLite2/Country/Meta-geoip0/sing-geoip and GeoLite2-ASN/ipinfo shapes) | `tests/resources.rs::real_mmdb_reads_the_bundled_geodata` (ignored by default, run with `BILLOW_MMDB_DIR`); differential `geoip-mmdb-hit`/`ip-asn-mmdb-hit` |
| geodata-mode / geodata-loader / geosite-matcher | true=GeoIP.dat, false=Country.mmdb; standard/memconservative/memc and succinct/mph/hybrid accepted with shared match semantics | `tests/config.rs::geodata_options_are_parsed_and_named_gaps_rejected` |
| Billow effective (override-merged) configuration | loads the same YAML shape and keeps the override/profile rule order | `tests/resources.rs::billow_override_merged_configuration_loads_and_keeps_rule_order` |
| Unimplemented shapes | rejected with the type/field named (UID, DSCP, IN-USER, IN-NAME, REMATCH-NAME, PROCESS-*-WILDCARD, PASS/PASS-RULE, proxy groups, `geo-auto-update: true`, HTTP providers through `proxy`) | `tests/config.rs`, `tests/resources.rs` |

## Differential method

`tool/kernel-compat/t24-differential.mjs` writes one config per case, starts
the two kernels on independent loopback ports, and sends one HTTP CONNECT
through each to a local echo with a fixed `Content-Length`. It records the
CONNECT status, whether the echo received the payload, and (for the provider
update case) the Mihomo control response.

- Offline provider HTTP: one loopback HTTP server serves every `http` provider
  URL; it can change the body and return 500 for the update case.
- GeoSite/GeoIP fixtures are encoded from the pinned protobuf messages
  (`GeoSiteList`/`GeoIPList`), including `CN` so Mihomo's `Verify` succeeds.
- MRS uses the checked-in `src-tauri/testdata/domain.mrs` (produced by the
  pinned `mihomo convert-ruleset`).
- MaxMind cases use the decompressed bundled
  `src-tauri/resources/runtime/geo/*.mmdb.br` files (`brotli -dk`), passed with
  `--mmdb-dir`; without that flag those two cases are recorded as skipped.

Command (the Rust binary is the debug CLI; a release binary is equivalent):

```sh
cargo build --manifest-path native-kernel/Cargo.toml -p billow-kernel-cli
node tool/kernel-compat/t24-differential.mjs \
  --mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
  --rust ~/.cache/cargo-target/debug/billow-kernel \
  --out tool/kernel-compat/evidence/t24-differential.json \
  --mmdb-dir <dir-with-Country.mmdb-and-ASN.mmdb>
```

Latest run: `31/31` cases pass, `0` differ, `0` unexpected, `0` skipped,
`0` startup failures. The report keeps every config, status and echo category;
`summary.framingDifferences` counts the cases where the raw category differs where Mihomo wrote
`200 Connection established` before rule evaluation and the Rust inbound wrote
`403`/`502` instead. The normalized rule outcome is identical; the CONNECT
reply framing is an inbound/T2 concern, not a T24 compatibility claim.

## Update semantics

Mihomo: the server first served `+.localhost` (rule hit → blocked), then
`+.other.invalid`; `PUT /providers/rules/remote` returned `204` and `localhost`
then reached the echo. The server then returned `500`; the same `PUT` returned
`503` and the previous `+.other.invalid` snapshot kept `localhost` reachable.
`mihomo-provider-update` in the report records all three phases.

Rust: `Kernel::update_rule_provider` returns the fetch error, leaves
`generation` unchanged and keeps evaluating the old snapshot; the same test
also asserts that a successful update moves `+.second.example` to REJECT while
`+.first.example` becomes DIRECT. The old snapshot is an `Arc` swapped out under
a `RwLock`, so it is freed when the last session/evaluation holding it returns.

## Coverage boundaries not claimed as pass

- Proxy groups and their `use`/`providers` references, group selection and
  health-check probing are T23. Provider health-check fields are parsed,
  validated and exposed; no probe is scheduled here.
- Name resolution for GEOIP/IP-ASN/IP-CIDR rules without `no-resolve` needs DNS
  (T22). This kernel matches only a destination that is already an IP and emits
  a load warning; differential IP/GEOIP cases use IP targets.
- Process rules match host-supplied metadata (`Target::with_process`). The
  mixed inbound has no process lookup, so differential process cases are not
  claimed; unit tests cover name/path/regex matching.
- The control API (`external-controller`, `PUT /providers/rules`) is T25. The
  Rust update path is exercised through the library, not over HTTP.
- `geo-auto-update: true` is rejected by name; there is no geodata download
  scheduler. `geo-update-interval` is parsed but only meaningful with it.
- HTTP providers support plain HTTP/1.1 GET with redirects, chunked bodies and
  a `path` cache. A configured `proxy` for the fetch, compressed responses and
  other HTTP versions are rejected by name.
- Geosite regex entries and `DOMAIN-REGEX`/`PROCESS-*-REGEX` use Rust `regex`;
  look-around/backreferences accepted by the pinned `regexp2` are rejected at
  load rather than never matching.
- MRS decoding is a port of the Tauri `src-tauri/src/mrs.rs` algorithm, not a
  shared dependency; the Tauri file and its tests are unchanged.

## Regression result

`cargo test --manifest-path native-kernel/Cargo.toml --locked` exits 0 with
every default suite green (the pinned-peer cases stay `#[ignore]` as designed;
they are not counted as passes). `node --test tool/kernel-compat/runner.test.mjs`
exits 0. The ignored real-MMDB case also passes when run explicitly with
`BILLOW_MMDB_DIR`.

## Regression commands

```sh
cargo test --manifest-path native-kernel/Cargo.toml --locked
BILLOW_MMDB_DIR=<dir> cargo test --manifest-path native-kernel/Cargo.toml \
  --test resources real_mmdb -- --ignored
node --test tool/kernel-compat/runner.test.mjs
```
