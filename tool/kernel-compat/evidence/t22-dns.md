# T22 DNS, hosts and fake-ip differential

Pinned baseline: Mihomo v1.19.34 (`tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7`),
source tree at `.cache/source/tree-v1.19.34`. Candidate: `billow-kernel` from
`native-kernel/` (library plus CLI). Every DNS upstream is a loopback fixture
started by the probe with fixed answers; no external resolver, certificate or
network is used.

Command:

```sh
node tool/kernel-compat/t22-differential.mjs \
  --mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
  --rust $CARGO_TARGET_DIR/debug/billow-kernel \
  --out tool/kernel-compat/evidence/t22-dns.json
```

## Environment

| fixture | shape | answers |
| --- | --- | --- |
| `main` | UDP | `a.test`, `loop.test`, `filtered.test`, `public.test`, `only.test`, `fake.test`, `real.test`, `fake-host.test`, `host-only.test`, `tcp.test`, `dot.test`, `doh.test`, `policy.test`, `deep.policy.test`, `rule.test`, `hosts-only.test`, `alias-target.test`, `geoip-zz.test`, `geoip-other.test`; everything else NXDOMAIN |
| `policy` | UDP | `policy.test`, `deep.policy.test` |
| `fallback` | UDP | `filtered.test`, `only.test`, `geoip-zz.test`, `geoip-other.test` |
| `tcp` | TCP, length-prefixed | same map as `main` |
| `dot` | DoT, self-signed certificate | same map as `main` |
| `doh` | HTTPS HTTP/1.1, `?dns=` base64url | same map as `main` |
| `silent` | UDP, never answers | timeout case |
| `socks` | SOCKS5 CONNECT | `respect-rules` hop |
| `echo` | HTTP echo with Content-Length | CONNECT cases |

DoT/DoH use a freshly generated self-signed certificate with
`#skip-cert-verify=true`, the pinned parameter that both engines honour. Each
engine binds its own `dns.listen` and `mixed-port`; the same effective YAML is
written for both (only the reserved ports differ).

## Result (21 cases)

| case | what is compared | Mihomo | Rust |
| --- | --- | --- | --- |
| `a-record-udp` | A answer, TTL 60, UDP upstream | 1.2.3.4 / 60 | same |
| `nxdomain` | NXDOMAIN rcode and empty answer | rcode 3 | same |
| `tcp-upstream` | `tcp://` upstream | 10.0.0.2 | same |
| `nameserver-policy` | `+.policy.test` selects the policy server; a name outside it uses the main server | 10.0.0.3 / 10.0.0.3 / 1.2.3.4 | same |
| `fallback-ipcidr` | main 1.1.1.1 inside `ipcidr: 1.0.0.0/8` falls back; 8.8.8.8 does not; `domain: '+.only.test'` goes to the fallback only | 7.7.7.7 / 8.8.8.8 / 6.6.6.6 | same |
| `fallback-geoip-code` | generated `GeoIP.dat` puts 1.2.3.4 in `zz`; `geoip-code: zz` keeps the main answer for it and falls back for 8.8.8.8 | 1.2.3.4 / 6.6.6.6 | same |
| `fallback-geoip-code-negated` | `geoip-code: '!zz'` must invert: fallback for 1.2.3.4, main for 8.8.8.8 | 7.7.7.7 / 8.8.8.8 | same |
| `hosts-answer` | configured `hosts` entry, TTL 10 | 1.2.3.4 / 10 | same |
| `use-hosts-false` | the same name goes to the upstream | 5.5.5.5 | same |
| `hosts-redir-host` | `redir-host`: built-in `localhost`, a configured entry, then an upstream name on the same listener | 127.0.0.1/10, 1.2.3.4/10, 1.2.3.4/60 | same |
| `hosts-fake-ip` | `fake-ip`: built-in `localhost`, a configured entry, then a fake allocation on the same listener | 127.0.0.1/10, 1.2.3.4/10, 198.18.0.4/3 | same |
| `hosts-domain-alias` | `hosts: {alias.test: alias-target.test}`: replace the question name, resolve it and prepend a CNAME | CNAME alias-target.test/10 + A 9.9.9.9/60 | same |
| `fake-ip` | first/second allocation, stability, next host, filter with a real answer, TTL 3 | 198.18.0.4, 198.18.0.4, 198.18.0.5, 127.0.0.1 | same |
| `ipv6-disabled-aaaa` | `dns.ipv6: false` AAAA is an empty success | empty, rcode 0 | same |
| `dot-upstream` | `tls://` with certificate verification | 10.2.0.1 | same |
| `doh-upstream` | `https://` over HTTP/1.1 | 10.2.0.2 | same |
| `timeout-is-servfail` | silent upstream: callers get the failure rcode, no address | SERVFAIL after 5.0s | SERVFAIL after 5.0s |
| `respect-rules` | `tcp://` upstream routed through `IP-CIDR,127.0.0.1/32,RULES` and a SOCKS5 hop | answer + 1 SOCKS connection | answer + 1 SOCKS connection |
| `engine-ip-rule` | CONNECT `loop.test` with `IP-CIDR,127.0.0.0/8,REJECT`: the rule-time lookup makes the rule match | blocked | blocked |
| `engine-no-resolve` | the same rule with `no-resolve`: the connection is allowed and the DIRECT dial resolves it | echoed | echoed |
| `engine-fake-ip` | query `fake.test` on the DNS listener, then CONNECT the fake IP: the destination is rebuilt to the host | echoed, fake 198.18.0.4 | same |

`21/21` pass, `0` differ, `0` unexpected, `0` startup failures. JSON:
`evidence/t22-dns.json`. The default Rust suite that backs the unit claims is
recorded in `evidence/t22-tests.log` (`cargo test --manifest-path
native-kernel/Cargo.toml --locked`: 380 passed, 0 failed, 18 test binaries;
`tests/dns.rs` 18/18). CONNECT framing is normalized as in T24 (Mihomo
answers 200 and then closes a rejected tunnel; the Rust inbound answers
403/502).

## T22-A2 repair

Three review findings were fixed and are covered above:

- **Listener self-deadlock (P1)**: `answer_query` held the `enhancer`
  `std::sync::Mutex` guard in the hosts middleware and locked it again to write
  the redir-host mapping, which is not reentrant. The checkpoint source
  (`a9c2b47`) reproduced it live: `hosts-answers` on `localhost` never answered,
  a `sample` showed the runtime thread in `__ulock_wait`, and the listener
  stayed wedged for every later query in `redir-host`/`fake-ip` (normal mode
  was unaffected because mapping is off). The guard is now taken once and
  reused, and the mapping TTL is the pinned 10 s. `hosts-redir-host` and
  `hosts-fake-ip` query `localhost`, a user entry and another name on one
  listener; both engines answer all three.
- **Domain-valued hosts on the listener (P2)**: the listener only handled a
  matched entry, so `hosts: {alias.test: alias-target.test}` was forwarded
  upstream as `alias.test` (NXDOMAIN). It now mirrors pinned `withHosts`:
  replace `Question[0].Name` with the target, run the remaining fake-ip/mapping/
  resolver middleware, and prepend a CNAME (TTL 10). `hosts-domain-alias`
  compares the CNAME + A answer with the pinned binary; the Rust listener test
  also checks the same chain through `pre_handle`.
- **`fallback-filter.geoip-code: '!xx'` (P3)**: the leading `!` was stripped
  before building a positive matcher, while the fallback filter inverts the
  matcher again, so the negation silently became its opposite. The raw code is
  now passed to `geoip_matcher` (pinned `LoadGeoIPMatcher` not-matcher +
  `dnsFallbackFilter`), and `fallback-geoip-code`/`-negated` compare both
  directions against the pinned binary.

## Additional verification

`tests/dns.rs` (18 cases in the default suite) covers the same behaviours
without the pinned binary plus the shapes the probe cannot drive: plain
`http://` DoH,  the pinned hosts trie priority
(exact > `*` > `.`/`+`), domain-valued hosts with cycle rejection, strict
named rejections (DoQ, system, `h3=true`, ECS, `#proxy`, fake-ip rule mode,
respect-rules without/with UDP), DoT/DoH certificate verification with a
private CA, cache TTL reuse (one upstream query for two lookups, including a negative SOA TTL), fallback
geoip/ipcidr/domain (including `geoip-code: zz` vs `!zz`), `direct-nameserver`/
`policy` selection helpers, hosts
feeding IP rules without DNS, `no-resolve` with a DNS-resolved target,
fake-ip rebuild through a real mixed-inbound CONNECT, the hosts middleware in
`normal`/`redir-host`/`fake-ip` on a real TCP listener (built-in `localhost`
and a configured entry, followed by a name that proves the listener is not
wedged), and a domain-valued hosts entry on the listener (CNAME + A) checked
against the rule-time `pre_handle` chain.

## No regressions

The same candidate binary was re-run against the other differentials of the
workflow after the T22-A2 changes:

- T24 rules/providers/GEO: `37/37` pass, `0` differ, `0` skipped with
  `--mmdb-dir` (`evidence/t24-differential.json`).
- T23 groups/selection/health: `27` cases + persistence, `28/28` pass, `0` differ
  (`evidence/t23-differential.json`). The first rerun hit the known transient
  pinned-Mihomo startup failure in `select-default-selected`; the clean rerun
  passed.
- `node --test tool/kernel-compat/runner.test.mjs`: `10/10` pass.

Residual note: the `geoip-code` fix follows the pinned **geodata** path
(`geodata-mode: true`, `LoadGeoIPMatcher` not-matcher + `dnsFallbackFilter`),
which is the mode the differential compares. Pinned's mmdb path
(`geodata-mode: false`) lowercases the code but looks up `!xx` as an ISO code
that never matches, so its fallback filter fires for every non-LAN answer; the
kernel keeps the negation in both modes instead of reproducing that accident.
No mmdb `!xx` differential case is recorded.

## Named gaps (rejected or recorded, never silent)

- DoQ (`quic://`), `system://`, `dhcp://`, Tailscale/EasyTier overlay DNS,
  `rcode://` nameservers — rejected at load.
- `#proxy` nameserver suffix — rejected; `respect-rules` with UDP upstreams is
  rejected (proxy UDP routing is not implemented).
- `#h3=true`, `name-cert-verify`, EDNS client subnet (`ecs`/`ecs-override`) —
  rejected; `prefer-h3` is accepted and recorded, DoH uses HTTP/1.1.
- `fake-ip-filter-mode: rule`, negated `fallback-filter.geosite`,
  `profile.store-fake-ip: true` persistence — the first two are rejected, the
  last is accepted with a warning and an in-memory pool.
- The DNS server answers A/AAAA/CNAME; other qtypes get NOTIMP (fake-ip mode
  still answers HTTPS/SVCB with an empty success).
- `cache-algorithm: arc` is accepted but served by the LRU (answers/TTLs are
  unchanged; only eviction order differs).

These are also recorded in `tool/kernel-compat/evidence/rust-mapping.json`
(`configFields.dns`, `configFields.hosts`, `configFields.ipv6`, `dns`) and
`native-kernel/README.md`.
