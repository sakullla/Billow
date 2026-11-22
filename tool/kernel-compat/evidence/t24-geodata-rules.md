# T24 rules, providers, GEO/MRS and effective-config evidence

Task: `03-execution-plan.md#tasks/T24`. Baseline: the pinned Mihomo v1.19.34
binary/source used by the rest of `tool/kernel-compat`
(`src-tauri/desktop-kernel.json`, `src-tauri/android-kernel.json`).

## Result

| Area | Result | Evidence |
| --- | --- | --- |
| Rule types and first-match semantics | implemented; 37/37 differential cases agree on the normalized rule outcome | `tests/resources.rs::every_rule_type_matches_with_the_pinned_metadata`, `evidence/t24-differential.json` |
| Rule providers: file/http/inline, yaml/text/mrs, domain/ipcidr/classical | implemented; provider paths are confined to the configuration root/`SAFE_PATHS`, a classical provider rejects an unsupported or malformed entry by name, and `path-in-bundle` is named; the declared interval is parsed but hosts/T25 drive updates through the explicit API | `tests/resources.rs::rule_providers_cover_every_vehicle_and_format`, `tests/resources.rs::provider_paths_are_confined_to_the_configuration_root`, `tests/resources.rs::classical_provider_names_unsupported_rule_types_instead_of_dropping_them` |
| Provider update success/failure | new snapshot on success; old generation kept and released on failure | `tests/resources.rs::http_provider_update_replaces_and_failure_keeps_the_old_generation`; Mihomo control API observation in `evidence/t24-differential.json` (`mihomo-provider-update`) |
| Proxy providers: file/http/inline, filters, `override`, health-check fields | loaded and exposed; filters split on a backtick, `exclude-type` on `\|`, supported `override` fields applied, unsupported override fields/`age-secret-key` named; latency probing and group `use`/`providers` are T23 | `tests/config.rs::proxy_providers_follow_the_pinned_filter_override_and_bundle_schema`, `tests/resources.rs::proxy_provider_override_and_filter_lists_follow_pinned_semantics` |
| GeoSite.dat/GeoIP.dat protobuf, text/JSON geosite, MRS | implemented | `src/geodata.rs` tests; `tests/resources.rs::geosite_and_geoip_dat_rules_match_the_pinned_forms`; differential `geosite-dat-hit`/`geoip-dat-hit` |
| MaxMind DB (`Country.mmdb`, `ASN.mmdb`) | implemented (v2 reader; GeoLite2/Country/Meta-geoip0/sing-geoip and GeoLite2-ASN/ipinfo shapes) | `tests/resources.rs::real_mmdb_reads_the_bundled_geodata` (ignored by default, run with `BILLOW_MMDB_DIR`); differential `geoip-mmdb-hit`/`ip-asn-mmdb-hit` |
| geodata-mode / geodata-loader / geosite-matcher | true=GeoIP.dat, false=Country.mmdb; standard/memconservative/memc and succinct/mph/hybrid accepted with shared match semantics | `tests/config.rs::geodata_options_are_parsed_and_named_gaps_rejected` |
| Billow effective (override-merged) configuration | **not** claimed to load directly: its rule/provider/proxy subset loads in override order; disabled `tun`/`sniffer` and `geox-url` are registered inert with warnings; `external-controller`, `dns`/`hosts`, `proxy-groups`, and enabled `tun`/`sniffer` are named rejections | `tests/resources.rs::billow_effective_configuration_registers_cross_task_keys_explicitly`, `tests/resources.rs::billow_effective_configuration_rule_subset_keeps_override_order` |
| Unimplemented shapes | rejected with the type/field named (UID, DSCP, IN-USER, IN-NAME, REMATCH-NAME, PASS/PASS-RULE, proxy groups, `geo-auto-update: true`, HTTP providers through `proxy`, `path-in-bundle`, `age-secret-key`, unsupported `override.<field>`) | `tests/config.rs`, `tests/resources.rs` |

## Differential method

`tool/kernel-compat/t24-differential.mjs` writes one config per case, starts
the two kernels on independent loopback ports, and sends one HTTP CONNECT
through each to a local echo with a fixed `Content-Length`. It records the
CONNECT status, whether the echo received the payload, and (for the provider
update case) the Mihomo control response. Cases include domain, DST-PORT,
SRC-PORT, network and inbound rules, `SRC-IP-CIDR`,
`IP-CIDR`, `IP-CIDR6`, `IP-SUFFIX`, `IP-CIDR,no-resolve` with an IP target,
all five rule-provider vehicles/formats, logic rules, `SUB-RULE`, GeoSite/
GeoIP `.dat`, and the MaxMind country/ASN shapes.

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

Latest run: `37/37` cases pass, `0` differ, `0` unexpected, `0` skipped,
`0` startup failures. The report keeps every config, status and echo category;
`summary.framingDifferences` counts the cases where the raw category differs:
Mihomo writes `200 Connection established` before rule evaluation and can then
leave the echo write waiting (`timeout`), while the Rust inbound closes the
tunnel or answers `403`/`502` itself. The normalized rule outcome is identical;
the CONNECT reply framing is an inbound/T2 concern, not a T24 compatibility
claim.

The normalization is deliberately asymmetric and recorded in
`normalizationNote`: `closed` becomes `blocked` for both engines; a Mihomo
`timeout` also becomes `blocked` (its 200-then-close rejection can leave the
echo write waiting), while a Rust `timeout` stays a real difference because the
Rust inbound answers `403`/`502`. `no-resolve` is compared only with an IP
target: over HTTP CONNECT the pinned hosts/DNS path can pre-resolve a hostname
before matching, while this kernel leaves the domain unresolved until T22, so a
domain-target no-resolve case would measure DNS rather than rule semantics.

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

## Path confinement and provider rejections

`provider.rs::resolve_provider_path` implements the pinned
`C.Path.IsSafePath` rule lexically (`constant/path.go`): a relative path is
resolved against the configuration directory, then the normalized candidate
must be a subpath of that root or an entry in `SAFE_PATHS`. Absolute paths
outside those roots and `..` escapes are rejected by name for both file
providers and the HTTP cache `path` (the cache path is validated before the
fetch/write). Tests cover a legal relative path, a legal absolute path inside
the root, `../outside.txt`, an absolute path in another temp directory, an
HTTP cache escape, and the CLI `--check` exit code.

A classical rule-provider is no longer allowed to drop a rule. Every entry is
parsed; an unsupported pinned type (for example `DSCP`) or a malformed entry
fails the load with `rule-provider '<name>' entry '<line>': ...`, and `MATCH`
is rejected as Mihomo's classical strategy does. `PROCESS-NAME-WILDCARD`/
`PROCESS-PATH-WILDCARD` are implemented with the pinned wildcard semantics
(case-insensitive), so they are no longer rejected. Domain `sub.*.example.com`
and `+.sub.*.example.com` patterns now follow `component/trie/domain.go`: a
`*` label matches exactly one label (and suffix forms match the tail).

## Billow effective YAML

Billow's `profile.rs` output is reproduced as a test fixture (the fields
`prepare`, `apply_settings` and `finish_yaml_for` insert) instead of a
hand-written Mihomo config. The full fixture is **not** asserted to load: its
cross-task blocks are registered explicitly.

- `tun: {enable: false}` and `sniffer: {enable: false}` load with a warning;
  `enable: true` is rejected by name (device/TUN is T6/T7, sniffer is T22).
- `geox-url` loads with a warning that no downloader runs.
- `external-controller` (T25), `dns`/`hosts` (T22) and `proxy-groups` (T23) are
  rejected by name.
- `port: 0`/`socks-port: 0` are disabled aliases; with a positive `mixed-port`
  the configuration loads, and an all-zero listener set fails instead of
  binding an ephemeral port.
- Removing only those registered keys yields the rule/provider/proxy subset;
  the override's prepended rule, profile rules and `MATCH` retain their order.

## Coverage boundaries not claimed as pass

- Proxy groups and their `use`/`providers` references, group selection and
  health-check probing are T23. Provider health-check fields are parsed,
  validated and exposed; no probe is scheduled here.
- Name resolution for GEOIP/IP-ASN/IP-CIDR rules without `no-resolve` needs DNS
  (T22). This kernel matches only a destination that is already an IP and emits
  a load warning; differential IP/GEOIP cases use IP targets. The `no-resolve`
  differential case therefore uses an IP target; a domain-target miss is not a
  differential claim because the pinned hosts/DNS path can resolve the CONNECT
  host before matching.
- Process rules match host-supplied metadata (`Target::with_process`). The
  mixed inbound has no process lookup, so differential process cases are not
  claimed; unit tests cover name/path/regex and wildcard matching. The same
  applies to `DSCP`/`UID`, which are rejected by name (no inbound metadata)
  rather than silently skipped inside a classical provider.
- `SRC-IP-SUFFIX` is implemented by the same suffix matcher as `IP-SUFFIX`,
  but the differential probe cannot choose a source address; the prefix forms
  `SRC-PORT`/`SRC-IP-CIDR` are covered.
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
