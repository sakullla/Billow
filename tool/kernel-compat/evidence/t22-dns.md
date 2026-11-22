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
| `main` | UDP | `a.test`, `loop.test`, `filtered.test`, `public.test`, `only.test`, `fake.test`, `real.test`, `fake-host.test`, `host-only.test`, `tcp.test`, `dot.test`, `doh.test`, `policy.test`, `deep.policy.test`, `rule.test`, `hosts-only.test`; everything else NXDOMAIN |
| `policy` | UDP | `policy.test`, `deep.policy.test` |
| `fallback` | UDP | `filtered.test`, `only.test` |
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

## Result (16 cases)

| case | what is compared | Mihomo | Rust |
| --- | --- | --- | --- |
| `a-record-udp` | A answer, TTL 60, UDP upstream | 1.2.3.4 / 60 | same |
| `nxdomain` | NXDOMAIN rcode and empty answer | rcode 3 | same |
| `tcp-upstream` | `tcp://` upstream | 10.0.0.2 | same |
| `nameserver-policy` | `+.policy.test` selects the policy server; a name outside it uses the main server | 10.0.0.3 / 10.0.0.3 / 1.2.3.4 | same |
| `fallback-ipcidr` | main 1.1.1.1 inside `ipcidr: 1.0.0.0/8` falls back; 8.8.8.8 does not; `domain: '+.only.test'` goes to the fallback only | 7.7.7.7 / 8.8.8.8 / 6.6.6.6 | same |
| `hosts-answer` | configured `hosts` entry, TTL 10 | 1.2.3.4 / 10 | same |
| `use-hosts-false` | the same name goes to the upstream | 5.5.5.5 | same |
| `fake-ip` | first/second allocation, stability, next host, filter with a real answer, TTL 3 | 198.18.0.4, 198.18.0.4, 198.18.0.5, 127.0.0.1 | same |
| `ipv6-disabled-aaaa` | `dns.ipv6: false` AAAA is an empty success | empty, rcode 0 | same |
| `dot-upstream` | `tls://` with certificate verification | 10.2.0.1 | same |
| `doh-upstream` | `https://` over HTTP/1.1 | 10.2.0.2 | same |
| `timeout-is-servfail` | silent upstream: callers get the failure rcode, no address | SERVFAIL after 5.0s | SERVFAIL after 5.0s |
| `respect-rules` | `tcp://` upstream routed through `IP-CIDR,127.0.0.1/32,RULES` and a SOCKS5 hop | answer + 1 SOCKS connection | answer + 1 SOCKS connection |
| `engine-ip-rule` | CONNECT `loop.test` with `IP-CIDR,127.0.0.0/8,REJECT`: the rule-time lookup makes the rule match | blocked | blocked |
| `engine-no-resolve` | the same rule with `no-resolve`: the connection is allowed and the DIRECT dial resolves it | echoed | echoed |
| `engine-fake-ip` | query `fake.test` on the DNS listener, then CONNECT the fake IP: the destination is rebuilt to the host | echoed, fake 198.18.0.4 | same |

`16/16` pass, `0` differ, `0` unexpected, `0` startup failures. JSON:
`evidence/t22-dns.json`. The default Rust suite that backs the unit claims is
recorded in `evidence/t22-tests.log` (`cargo test --manifest-path
native-kernel/Cargo.toml --locked`: 377 passed, 0 failed, 18 test binaries;
`tests/dns.rs` 15/15). CONNECT framing is normalized as in T24 (Mihomo
answers 200 and then closes a rejected tunnel; the Rust inbound answers
403/502).

## Additional verification

`tests/dns.rs` (15 cases in the default suite) covers the same behaviours
without the pinned binary plus the shapes the probe cannot drive: plain
`http://` DoH,  the pinned hosts trie priority
(exact > `*` > `.`/`+`), domain-valued hosts with cycle rejection, strict
named rejections (DoQ, system, `h3=true`, ECS, `#proxy`, fake-ip rule mode,
respect-rules without/with UDP), DoT/DoH certificate verification with a
private CA, cache TTL reuse (one upstream query for two lookups, including a negative SOA TTL), fallback
geoip/ipcidr/domain, `direct-nameserver`/`policy` selection helpers, hosts
feeding IP rules without DNS, `no-resolve` with a DNS-resolved target, and
fake-ip rebuild through a real mixed-inbound CONNECT.

## No regressions

The same candidate binary was re-run against the other differentials of the
workflow after the T22 changes:

- T24 rules/providers/GEO: `37/37` pass, `0` differ (`evidence/t24-differential.json`).
- T23 groups/selection/health: `27` cases + persistence, `28/28` pass, `0` differ
  (`evidence/t23-differential.json`).
- `node --test tool/kernel-compat/runner.test.mjs`: `10/10` pass.

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
