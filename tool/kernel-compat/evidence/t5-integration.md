# T5 integration differential

Combined configuration differential for the native Rust kernel on the pinned
Mihomo `v1.19.34` baseline. R2 compatibility is **not** claimed here; T8 /
Delivery decide it on the complete candidate. This record covers the combined
config plane (DNS/hosts, groups, rules/providers, controller) and the real
outbounds in one candidate, plus Billow's generated effective YAML.

## Command

```sh
node tool/kernel-compat/t5-differential.mjs \
  --mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
  --rust   <CARGO_TARGET_DIR>/debug/billow-kernel \
  --out tool/kernel-compat/evidence/t5-integration.json \
  --effective-dir tool/kernel-compat/evidence/t5-effective
```

Raw report: `t5-integration.json`; run output: `t5-run.log`, generated
artifacts: `t5-effective/`. The Rust binary was built with an independent
`CARGO_TARGET_DIR`; the SSR peer (`tool/kernel-compat/.cache/peers/ssr-server`)
is built on first use from `peers/ssr-server` against the locked source.

## Result

`12/12` scenarios pass, `0` differ, `0` startup failures, `exitOk: true`.
Both engines run the same YAML; only the mixed/DNS/controller ports differ per
engine.

| Scenario | Result |
| --- | --- |
| `startup-mihomo`, `startup-rust` | both accept the combined config and start mixed + controller |
| `dns-fake-ip-hosts-alias` | equal answers (below) |
| `groups-initial` | same members/selection for `PROXY`, `AUTO`, `FALLBACK`, `SUB` |
| `proxy-provider-registered` | `pp-sub` resolves to `sub-a` in `/providers/proxies` |
| `group-select`, `group-select-switch` | `PUT /proxies/PROXY` 204 / unknown 400 / `now` follows |
| `combined-egress-and-rules` | equal reachability through every rule/outbound path (below) |
| `provider-update-failure-keeps-old` | update 204 then 503; the updated provider snapshot stays |
| `reload-success-and-failure` | reload 204 / invalid 400; new rules stay live after failure, DNS/controller alive |
| `reject-out-of-range-provider-path` | both config testers reject `../escape.yaml` |
| `reject-unimplemented-option-tun` | Rust names the TUN gap; pinned accepts the block at test time |

### DNS and hosts (`dns.listen`, fake-ip + hosts + controlled upstream)

| Query | both engines |
| --- | --- |
| `fake.test` | `A 198.18.0.4` TTL 1 (fake-ip allocation) |
| `host-only.test` | `A 127.0.0.1` TTL 10 (hosts) |
| `alias.test` | `CNAME alias-target.test` TTL 10 + `A 9.9.9.9` TTL 60 (domain hosts) |
| `real.test` | `A 5.5.5.5` TTL 60 (`fake-ip-filter` forwards to the upstream) |
| `absent.test` | NXDOMAIN |

### Rules and real outbounds

Peers are controlled local servers: pinned Mihomo `listeners:` for
`shadowsocks` (aes-256-gcm) and `trojan` (self-signed cert + `skip-cert-verify`),
and `peers/ssr-server` (origin/plain, aes-256-cfb). Each path used its own
destination port so the rules could be ordered deterministically:

| Request | Matched path | Result |
| --- | --- | --- |
| `localhost` (rule-set yaml) | `PROXY` selector = `trojan-node` | marker echoed through the Trojan peer |
| `127.0.0.1:echoA` | `GEOIP,zz` → `ss-node` | marker echoed through the Shadowsocks peer |
| `127.0.0.1:echoB` | `DST-PORT` → `trojan-node` | marker echoed through the Trojan peer |
| `127.0.0.1:echoC` | `MATCH` → `ssr-node` | marker echoed through the Go SSR peer |
| `bad.localhost` | `BAD` selector = `bad-ss` (wrong password) | never echoed |
| `text-probe.test` | file/text rule-set | blocked |
| `www.google.com` | MRS rule-set (`src-tauri/testdata/domain.mrs`) | blocked |
| `geo.test` | `GEOSITE,t5site` (generated `GeoSite.dat`) | blocked |
| `http-probe.test` | HTTP rule-set | blocked |

Switching `PROXY` to `ss-node` and repeating `localhost` still echoed
(`t5-proxy-ss`), and selecting a missing member answered 400 on both sides.

### Provider update and reload

- HTTP rule-provider update: initial payload only matches `http-probe.test`;
  after `PUT /providers/rules/rp-http` (204) it matches `localhost`, which the
  earlier rule-set had sent to `PROXY`; the next `localhost` request is blocked.
- The server then returns 500: `PUT` answers 503 and `localhost` still blocks,
  i.e. the previously swapped snapshot is kept (old generation lives while
  `Arc`s reference it).
- Reload accepts a new rule set (204): `localhost` becomes blocked. An invalid
  payload is 400 and the reloaded config stays live (`localhost` still blocked,
  `mixed-port` unchanged, `DNS` still answers).
- Unique generation stamping under the write lock is covered by
  `tests/resources.rs::concurrent_provider_updates_stamp_unique_generations`.

### Configuration acceptance

| Shape | pinned `-t` | Rust `--check` |
| --- | --- | --- |
| provider `path: ../escape.yaml` | rejects (unsafe path) | rejects, names `rule-provider 'escape'` |
| `tun: {enable: true}` | accepts at config-test time | rejects by name (device/TUN is T6/T7) |

The accepted/disabled forms are exercised through Billow's artifact below.

## Billow effective YAML

`tool/kernel-compat/t5-effective.mjs` mirrors
`src-tauri/src/profile.rs::kernel_yaml_for(Engine::Rust, tun_enable=false)` and
the steps around it (`prepare_named`, `apply_settings`, `strip_launcher_tun`,
`ensure_tun_dns`, `finish_yaml_for`) from
`fixtures/t5-billow-profile.json`; it does not change `profile.rs`. Both
artifacts are generated, not hand-written:

| Artifact | Shape |
| --- | --- |
| `t5-effective/billow-desktop.yaml` | profile + settings; no launcher `tun` (the desktop block is stripped because the profile wrote none); no controller |
| `t5-effective/billow-android.yaml` | profile + settings; `port`/`socks-port`/`redir-port`/`tproxy-port: 0`, private `external-controller`, no `tun` |

Setting `sniffer: true` (the user toggle) makes the only remaining named
rejection on both platforms:

```
[unsupported] unsupported configuration: top-level key 'sniffer' with enable: true is not implemented (sniffing is T7)
```

Removing only that block (`t5-effective/billow-*-reduced.yaml`) makes both
artifacts load (`--check` exit 0) and register `PROXY`, `AUTO` and `FALLBACK`
with their members (`--print-groups`). Pinned `-t` accepts the full artifact
(including the enabled sniffer), so the artifact is a genuinely valid Mihomo
configuration.

Keys accepted with a warning because their tuning is not applied: `unified-delay`,
`tcp-concurrent`, `find-process-mode: off`, `keep-alive-interval`,
`disable-keep-alive`, `redir-port: 0`/`tproxy-port: 0`, `geo-update-interval`
while `geo-auto-update: false`, and `geox-url` (no downloader). Keys still
rejected by name outside this artifact: an enabled `tun`/`sniffer`,
`find-process-mode` other than `off`, non-zero `redir-port`/`tproxy-port`,
`skip-auth-prefixes`/`lan-allowed-ips` (LAN auth/allow-list injection is only
present when the user configures LAN access), and the already-registered
cross-task gaps.

## T5 cross-task P3 closures

- **T23**: `tests/groups.rs::provider_registration_keeps_the_first_expected_status_for_a_shared_url`
  registers one URL twice with `expected-status: 500` then `204` and merged
  filters; the 204 answer stays dead, so the first status wins.
- **T22**: `hosts-domain-servfail-no-cname` (differential, 22/22 pass + 1 known
  difference) and `tests/dns.rs::failed_domain_hosts_alias_reports_servfail_without_a_cname`
  stop synthesizing a CNAME for a SERVFAIL transport failure. The mmdb
  `!geoip-code` anomaly is now an executed, exact-value `known-difference`
  (pinned NXDOMAIN vs the kernel's main answer for a non-AU address).
- **T25**: bind failures also emit `tracing::error!` (stderr visible without
  `/logs`); provider generations increment under the slot write lock.
- **T24**: the effective fixture wording now matches the Rust input
  (`strip_launcher_tun`, Android-only ports/controller), a rule naming a group
  resolves to `Action::Group`, and the provider-root vs Mihomo `-d` home
  interface is recorded in `t24-geodata-rules.md` for T6/T7. A real
  compatibility bug found here is fixed: `GEOSITE,CN` (uppercase) now resolves
  against the lowercase dat code (`geodata.rs`), with the T24 differential
  `geosite-dat-uppercase-hit` case.
- **T9**: `protocol-peers.json` points partial families at
  `rust-mapping.json` `proxies.<type>.reason`/`notImplemented` and no longer
  says DNS/hosts/groups/controller are unimplemented.

## Regression runs (same candidate)

| Run | Result |
| --- | --- |
| `cargo test --locked` (independent `CARGO_TARGET_DIR`) | all suites green (`t5-default-tests.log`, 19 `test result: ok`, 0 failed) |
| T22 differential (with decompressed mmdb) | 22 pass + 1 known difference, 0 differ/unexpected |
| T23 differential | 28/28 pass |
| T24 differential (with decompressed mmdb) | 38/38 pass, 0 differ (incl. uppercase GEOSITE) |
| T25 differential | 47/49 equal + 2 registered divergences |
| `peer-tests.sh` | 66/66 pass (`t5-peer-tests.log`) |
| `node --test runner.test.mjs` | 10/10 pass |

## Boundaries

- Platform: macOS arm64. Android/iOS/Windows watchers are not part of this run.
- `AUTO`/`FALLBACK` `now` was identical here, but url-test ranks measured
  delays; the differential compares membership, not a winner guarantee.
- Failure framing differs by inbound design (pinned 200-then-close vs Rust
  403/502); the combined scenario compares whether the receiver was reached.
- TUN/sniffer/process lookup/LAN-auth injection, UDP beyond the configured
  associations, and the T10/T14–T21 family gaps stay registered elsewhere; this
  report does not promote them.
