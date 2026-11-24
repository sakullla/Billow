# Billow native Rust kernel

An embeddable proxy engine plus a standalone process entry. No Tauri or other
GUI dependency; the library crate also builds as a `staticlib` so the iOS
Network Extension (T3/T7) can link it directly.

Status: one mixed inbound on the configured address (TCP CONNECT,
SOCKS5 and SOCKS5 `UDP ASSOCIATE`), a strict subset of the clash
configuration, `DIRECT`/`REJECT` and the protocol outbounds below with their
transports and UDP associations. T9 added `vmess` (AEAD header), `snell`
(v1-v3) and `trusttunnel` (TLS + HTTP/2 CONNECT). T11 added `gost-relay`
(relay v2: TCP/TLS/auth/`forward`), `ssh` (password and inline-PEM key auth,
host-key pinning, `direct-tcpip`) and `ssr` (every pinned stream cipher,
protocol plugin and obfs plugin, plus the UDP association). T12 completed the
SSR plugin layers and the gost-relay UDP association and smux session. T10
added the QUIC families `tuic` (v5 `uuid`/`password`), `hysteria` (v1) and
`hysteria2` (HTTP/3 auth + TCP), all over `quinn` 0.11. T27 implemented the
per-outbound `BasicOption` dialer knobs, the TLS certificate-identity options,
the QUIC congestion/window tuning and socks5 `UDP ASSOCIATE`. T13 added `mieru`
(single-session TCP, an independent implementation of the published protocol).
T17 added `sudoku` as a translation of the pinned GPL-3.0 `transport/sudoku`
(TCP with the legacy HTTP mask, the pure and packed downlink codecs, the three
record AEAD methods and the session mux; the HTTP tunnel modes and UoT are
rejected by name), so the kernel workspace is now GPL-3.0-only (see
[License](#license) and `THIRD_PARTY_NOTICES.md`). T14 added
`masque` as an RFC 9298 CONNECT-UDP client over HTTP/3, reusing the T10
`quinn` profile for the UDP association. T18 added the pinned Cloudflare WARP
shape: RFC 9484 CONNECT-IP with the key-derived client certificate, endpoint-key
pinning, `ADDRESS_ASSIGN`/`ROUTE_ADVERTISEMENT` capsules, IPv4/IPv6 packets in
HTTP Datagrams, a minimal in-tree IPv4/IPv6/UDP stack and tunnel DNS. T21 added
TCP over CONNECT-IP with an in-tree minimal TCP client (active open, data/ACK,
retransmission, half-close); the RFC 9298 CONNECT-UDP subset still carries UDP
only, and the `h2`/`h3-l4proxy` modes stay rejected by name. T15 added `shadowquic`: the JLS ClientHello /
ServerHello random seal is an independent implementation of the locked
`jls-tls` algorithm, injected into rustls's own ClientHello through a
recorded-random replay, over the same `quinn` transport. T16 added the
protocol halves of `wireguard` (Noise IK handshake, cookie reply, transport
keys, replay window and keepalive, verified against the locked
`metacubex/wireguard-go` device) and `openvpn` (UDP/TCP control channel,
TLS 1.2/1.3 client authentication, key-method 2 and the AEAD data channel,
verified against OpenVPN 2.7.9). T19 added the mesh adapters: `tailscale`
(control-base Noise IK, the HTTP/2 `/machine/map` control request and the DERP
greeting/client-info/ping/packet frames) and `zerotier` (identity proof of work,
planet/moon parsing, VL1 armor and HELLO/OK/WHOIS/ECHO, VL2 frame payload).
Device/TUN ownership and the userspace IP stack stay with T6/T7, so both
families load a valid configuration and refuse every `dial()` with that gap
named. T20 translates EasyTier's locked LGPL-3.0-or-later source for the
cleartext host/discovery path: the real `DefaultHasher`-based
`network_secret_digest`, peer-manager frame, `HandshakeRequest`,
`PeerManagerHeader` and PingPong are implemented and verified against the
pinned wasm core. The Noise XX handshake and secure-datagram AES-GCM/ChaCha20
data path are also translated and verified against the pinned core with
`secure-mode: true`/`enable-encryption: true`. `outbound/easytier.rs` is an
LGPL derivative; the workspace is distributed under GPL-3.0-only. See
`THIRD_PARTY_NOTICES.md` and
`third_party/EasyTier-LGPL-3.0.txt`. The T10/T14/T15/T16/T19/T20
families are partial: their gaps are named in
[Not implemented](#not-implemented) and in
`tool/kernel-compat/evidence/rust-mapping.json`.
T22 added DNS and `hosts`: the pinned domain trie, UDP/TCP/DoT/DoH upstreams,
nameserver policies, fallback filters, `respect-rules`, the three enhanced
modes, fake-ip allocation and destination rebuild, and the optional DNS server
on `dns.listen` (see [DNS and hosts](#dns-and-hosts-t22)). T25 implements the
Billow-consumed RESTful control interface (see [Control API](#control-api-t25)):
`/version`, `/configs` (GET/PATCH/PUT reload), `/proxies` (list/detail/select/
delay), `/rules`, `/connections` (list + close), `/providers/proxies` and
`/providers/rules` (list/update), `/logs`, `/traffic`, `/memory`, `secret`
auth, CORS, and the TCP/Unix/TLS controller listeners. **Not implemented
yet** (rejected with
`[unsupported]`, never ignored): `tun`/`redir`/`tproxy`, the
families listed under
[Protocol families outside this slice](#protocol-families-outside-this-slice),
and the protocol options listed in [Not implemented](#not-implemented). T24
implements the rule types, rule/proxy providers, GEO/MRS reads and Billow's
effective override configuration, T23 implements proxy groups, selection and
health checks (`select`/`url-test`/`fallback`/`load-balance`, nested groups,
provider `use`, filters, latency probes and a selection cache), and T25 exposes
the control API. The remaining configuration-plane ownership is split across
T22/T25 and is named at each boundary.

T7 added the iOS Packet Tunnel data plane; T26 generalised the same userspace
stack behind `--features device-vpn`, with `ios-vpn` and `android-vpn` as the
two device entries (all off by default, so desktop builds and the mixed
listener are unchanged). `src/ios_vpn.rs` is the `billow_ios_vpn_*` C ABI of
`src-tauri/gen/apple/network-extension/RustExtension/include/billow_ios_vpn.h`,
and `src/tunnel/` is the shared userspace IP stack. It terminates the device's TCP
(passive open in `tunnel/tcp_server.rs`) and UDP (the same outbound
associations the mixed listener uses, including the SOCKS5 relay) in userspace, routes every flow through
the engine (rules, proxy groups, `dialer-proxy`, DIRECT, `:53` DNS hijack
through the configured resolver), and shares `outbound/ipstack` with MASQUE so
a desktop TUN (T6) can reuse the same codec. `IN-TYPE,TUN` now loads and
matches. Bounds (flows, queues, associations, buffers) and the
`billow_ios_vpn_stats` high-water counters are recorded in
`tool/kernel-compat/evidence/t7-ios-ffi.md`; the device memory/reclaim entry
(R3/R4) is `docs/testing/2026-11-23-ios-rust-extension-memory.md`. Everything
was verified on macOS and in the iOS simulator; no physical device was
available, so the extension's device peak and termination evidence are pending.

T26 added the Android VpnService entry behind `--features android-vpn`
(`src/android_vpn.rs`). Android's host process owns the `VpnService` TUN
`ParcelFileDescriptor`, clears `FD_CLOEXEC` and reports the fd; the Rust host
`profile.rs`/`process` launch then passes it as `--tun-fd <fd>` instead of
writing `tun.file-descriptor` into the YAML (the YAML `tun` block is stripped
for this engine on every platform). The CLI starts `AndroidVpn`, whose reader
thread polls the fd and feeds `Tunnel::ingest`, and whose bounded writer queue
writes emitted IP packets back. `stop`/`Drop` joins both threads, closes the
fd and stops the engine. The host stops the Android Rust child before it
closes its own descriptor on disconnect, engine switch and a failed restart
(a reload of the same stripped YAML would otherwise be a no-op); on a revoke
the system invalidates the fd first, the pump reports `running: false`, and the
CLI exits non-zero so the host no longer sees a live process with a dead data
plane. The `billow_android_vpn_*` C ABI in the same module is the in-process
embed point (`start(fd, home)`, `stop`, `reload`, `stats`); a successful
`start` takes the fd and a failed one leaves it open for the caller to close
once. The packaged Android kernel uses the `--tun-fd` process route. Host-side
tests use a `UnixDatagram` pair as the packet descriptor and cover TCP
bidirectional data, UDP, DNS hijack, reload, stop/release, revoked fd, failed
start ownership and invalid fds (`tests/android_tunnel.rs`), and the host
wiring is covered in `src-tauri/src/profile.rs` tests. The Android target build
needs the NDK and is not available in this environment; the exact failure and
the device entry are recorded in
`tool/kernel-compat/evidence/t26-android-tunnel.{json,md}`, and real-device
traffic remains pending.

Desktop Rust sessions do **not** take over a TUN device: the `tun` block is
stripped for `Engine::Rust` on every platform and desktop TUN belongs to the
T6/Mihomo path. A desktop Rust session serves the mixed listener only, so
status/snapshots must not be read as desktop Rust TUN support.

## License

The kernel workspace is **GPL-3.0-only**. The `sudoku` outbound is a
translation of Mihomo's GPL-3.0 `transport/sudoku`; no permissive licence can
cover that derivative, so `native-kernel/Cargo.toml` declares
`license = "GPL-3.0-only"`, `COPYING.GPL-3.0` carries the full text (identical
to the repository root `LICENSE`), and `THIRD_PARTY_NOTICES.md` lists every
translated file and its upstream source. A binary that links `billow-kernel`
must therefore be distributed under the GPL-3.0, including source availability
for the combined work. `src/keys.rs` (`sudoku_seed`) and `src/proxies.rs`
(`SudokuOutbound`, `parse_sudoku`) are mixed files: the GPL-derived item
carries its own `SPDX-License-Identifier: GPL-3.0-only` header and the rest of
the file is original MIT code. The other vendored or derived material and its
licences
(Go standard library `math/rand` data under BSD-3-Clause, `jls-tls`, the Rust
crate licences) are recorded in the same notices file.

## Layout

```
native-kernel/
├── Cargo.toml, Cargo.lock          # workspace (resolver 2), lockfile committed
└── crates/
    ├── billow-kernel/              # library (rlib + staticlib)
    │   ├── src/config.rs           # strict YAML/rule/provider parsing
    │   ├── src/dns.rs              # hosts, DNS clients (UDP/TCP/DoT/DoH), policies,
    │   │                           # fake-ip, DNS server, rule-time resolution
    │   ├── src/geodata.rs          # MRS, GeoSite.dat/GeoIP.dat protobuf, MaxMind DB
    │   ├── src/provider.rs         # file/http/inline providers, filters, generation swaps
    │   ├── src/proxies.rs          # strict `proxies:` option tables
    │   ├── src/outbound/           # socks5, http, ss, trojan, vless, anytls, vmess, snell,
    │   │                           # trusttunnel, gost-relay, ssh, ssr, mieru, sudoku,
    │   │                           # masque
    │   │                           # (CONNECT-UDP; CONNECT-IP in masque_ip with
    │   │                           # ipstack, the WARP key/certificate in warp
    │   │                           # and the TCP client in tcp),
    │   │                           # shadowquic + jls (recorded-random TLS hook),
    │   │                           # wireguard (Noise IK/transport), openvpn
    │   │                           # (control/TLS/key-method 2/AEAD data channel),
    │   │                           # tailscale (control Noise/HTTP2 + DERP),
    │   │                           # zerotier (identity/planet/VL1/VL2) and
    │   │                           # easytier (LGPL cleartext host/discovery),
    │   │                           # quic, h3 + tls, ws, h2
    │   ├── src/keys.rs             # EVP_BytesToKey, HKDF-SHA1, trojan key, uuid
    │   ├── src/rules.rs            # compiled rule set, logic, SUB-RULE, RULE-SET
    │   ├── src/inbound.rs          # SOCKS5 + HTTP CONNECT handshake, authentication
    │   ├── src/engine.rs           # listener, sessions, bounded relay, lifecycle
    │   ├── src/ios_vpn.rs          # billow_ios_vpn_* C ABI (feature `ios-vpn`)
    │   ├── src/android_vpn.rs      # VpnService fd pump + billow_android_vpn_* ABI
    │   │                           # (feature `android-vpn`, CLI `--tun-fd`)
    │   ├── src/tunnel/             # shared userspace IPv4/IPv6 data plane (feature
    │   │                           # `device-vpn`): passive TCP (tcp_server.rs),
    │   │                           # UDP associations (udp.rs), rule/group/outbound
    │   │                           # routing (route.rs), device config staging
    │   │                           # (stage.rs)
    │   ├── src/identity.rs         # uuid / pid / version / listener / config digest
    │   ├── examples/embed.rs       # embedding example
    │   └── tests/                  # config, resources (rules/providers/GEO/updates),
    │                               # protocols (loopback peers), sessions,
    │                               # mihomo_peers (pinned Mihomo),
    │                               # ios_tunnel/android_tunnel (device data planes),
    │                               # shadowquic_stream (stream/control reopen),
    │                               # wireguard_peer/openvpn_peer (controlled peers),
    │                               # data/shadowquic-jls.txt (locked JLS hello vectors),
    │                               # cli/family args, common/ helpers
    └── billow-kernel-cli/          # binary `billow-kernel`
        └── tests/cli.rs            # drives the real process: inbound, outbound, restart
```

## Supported configuration

Top-level keys: `mixed-port`, `port` (recorded, does not bind a separate
listener), `socks-port` (legacy alias for `mixed-port`), `allow-lan`,
`bind-address`, `mode: rule`, `log-level`, `authentication`, `tls` (extra
trust roots, plus `certificate`/`private-key` for the controller TLS listener),
`external-controller`, `external-controller-unix`, `external-controller-tls`,
`external-controller-cors`, `secret`, `proxies`, `proxy-groups`, `profile`
(`store-selected`), `rules`, `sub-rules`,
`rule-providers`, `proxy-providers`, `geodata-mode`, `geodata-loader`,
`geosite-matcher`, `geo-auto-update` (`false` only), `geo-update-interval`
(parsed), `hosts` and `dns` (T22), and `ipv6` (general switch, default `true`).
A listener
port of `0` means disabled (Mihomo's meaning); if every listener key is 0 the
load fails by name instead of binding an ephemeral port.

Billow's `profile.rs` effective YAML (`prepare`/`apply_settings`/
`strip_launcher_tun`/`ensure_tun_dns`/`finish_yaml_for`) is the input shape this
loader is tested against. T5 generates that artifact from the real
`kernel_yaml_for(Engine::Rust, tun_enable=false)` steps
(`tool/kernel-compat/t5-effective.mjs`, profile fixture
`fixtures/t5-billow-profile.json`) and loads it with `--check`: the desktop and
Android artifacts both name only the enabled `sniffer` (T7); removing that one
block makes the whole artifact load and register its groups. The launcher keys
are handled explicitly: the `tun` block is stripped before the kernel sees it
for the Rust engine (the device route belongs to the launcher and the Android
fd arrives as `--tun-fd`; a `tun` block reaching the loader is still rejected
with `enable: true`), `geox-url` is
recorded with a warning, `port: 0`/`socks-port: 0`/`redir-port: 0`/
`tproxy-port: 0` are inert disabled listeners, `unified-delay`,
`tcp-concurrent`, `find-process-mode: off` and the global keep-alive keys are
accepted with a warning that their tuning is not applied, the controller keys
load (T25), and `hosts`/`dns` load through the T22 runtime (see
[DNS and hosts](#dns-and-hosts-t22)). `proxy-groups` is implemented by T23
(see [Proxy groups](#proxy-groups-t23)); `tests/resources.rs` keeps the
replica fixture, and a rule naming a group resolves to `Action::Group`.
`tool/kernel-compat/evidence/t5-integration.json` records the combined
differential and the two generated artifacts.

Rules (T24): `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `DOMAIN-REGEX`,
`DOMAIN-WILDCARD`, `GEOSITE`, `GEOIP`, `SRC-GEOIP`, `IP-ASN`, `SRC-IP-ASN`,
`IP-CIDR`, `IP-CIDR6`, `SRC-IP-CIDR`, `IP-SUFFIX`, `SRC-IP-SUFFIX`,
`SRC-PORT`, `DST-PORT`, `IN-PORT`, `PROCESS-NAME`, `PROCESS-PATH`,
`PROCESS-NAME-REGEX`, `PROCESS-PATH-REGEX`, `PROCESS-NAME-WILDCARD`,
`PROCESS-PATH-WILDCARD`, `NETWORK`, `IN-TYPE`, `SUB-RULE`,
`AND`, `OR`, `NOT`, `RULE-SET` and `MATCH`. Outbounds are `DIRECT`, `REJECT`,
`REJECT-DROP` (close without an inbound reply) or the name of a configured
proxy or proxy group. The optional `no-resolve`/`src` parameters are accepted
on IP/GEOIP/IP-ASN/RULE-SET rules. Evaluation resolves a destination name
lazily when the first IP-based rule that is allowed to resolve is reached
(pinned `RuleMatchHelper.ResolveIP`), then continues with that address; a
`no-resolve` rule never queries DNS, and a failed lookup is remembered so later
IP rules do not retry. The first matching rule wins; without a `MATCH` rule the
built-in fallback is `DIRECT`, as in Mihomo. `SUB-RULE` uses the same
outermost-group syntax as the pinned parser (`SUB-RULE,(NETWORK,TCP),branch`)
and the named list selects the outbound; circular references are rejected.
The listener binds `127.0.0.1` unless `allow-lan: true` is set.

`GEOSITE,<key>`, `GEOSITE,<key>/<tag>`, `GEOSITE,<key>@attr` and
`GEOSITE,!<key>` read `GeoSite.dat` (protobuf, `@attr` filters attribute keys)
or the text `domain`/`sub_domain`/`domain_keyword` form from `--geosite-dir`.
`GEOIP,<country>` reads `GeoIP.dat` when `geodata-mode: true` (the default is
`false`, which reads `Country.mmdb`); `GEOIP,lan` is built in.
`geodata-loader` accepts `standard`/`memconservative`/`memc` (the read-only
decoders have identical match semantics) and `geosite-matcher` accepts
`succinct`/`mph`/`hybrid`. `IP-ASN,<number>` reads `ASN.mmdb`. The `.mmdb`
reader is a minimal MaxMind DB v2 implementation (Country/ASN shapes,
`Meta-geoip0` and `sing-geoip` country shapes); malformed files are reported,
never treated as empty data.

Rule providers: `type: file|http|inline`, `behavior:
domain|ipcidr|classical`, `format: yaml|text|mrs` (default yaml), `payload`
fallback, `path`, `url`, `header`, `size-limit` and `interval` (recorded).
Provider paths (`file` and the HTTP cache `path`) follow the pinned
`C.Path.IsSafePath` rule: a relative path resolves against the configuration
file's directory and must stay under it or a `SAFE_PATHS` entry; absolute paths
outside those roots and `..` escapes are rejected by name. A domain provider
accepts `x`, `+.x`, `.x`, `*.x` and `*` labels in the middle
(`sub.*.example.com`, one label); an IP provider accepts CIDR prefixes. A
classical provider parses target-less rules and **never silently drops one**:
a pinned type this kernel cannot evaluate (DSCP/UID/IN-USER/IN-NAME/
REMATCH-NAME) or a malformed entry fails the load with the provider, entry and
rule type named. `http` providers use a bounded HTTP/1.1 GET over the platform
trust store (redirects, chunked bodies and `path` caching); a response through
a configured `proxy` is rejected by name, as is `path-in-bundle` (no 7z
bundle reader). `Kernel::update_rule_provider`/`update_all_rule_providers`
fetch again and swap the snapshot atomically: a failed update returns its
reason and keeps the previous generation, which is released when the last
session that used it finishes. Inline provider updates are a timestamp-only
no-op, as in Mihomo.

Proxy providers: `type: file|http|inline`, `url`/`path`, `header`,
`filter`/`exclude-filter` (each split on a backtick into multiple Rust regexes;
look-around/backreferences are rejected), `exclude-type` (`|`-separated, as in
the pinned schema), `dialer-proxy`, `size-limit`, `interval`, the
`health-check` fields (`enable`, `url`, `interval`, `timeout`, `lazy`,
`expected-status`), and `override` with `udp`, `skip-cert-verify`,
`dialer-proxy`, `additional-prefix`, `additional-suffix` and `proxy-name`.
Other pinned override fields (`tfo`, `mptcp`, `udp-over-tcp`, `up`/`down`,
`name-cert-verify`, `interface-name`, `routing-mark`, `ip-version`,
`override-expr`) are rejected with `override.<field>`; a non-empty
`age-secret-key` is rejected because age decryption is not implemented. The
proxies and filters are loaded and exposed; group `use` references and latency
probing are T23 (see [Proxy groups](#proxy-groups-t23)).
`Kernel::update_proxy_provider` applies the same
success-replaces/failure-keeps-old rule.

`authentication: ["user:pass", ...]` guards the mixed inbound (SOCKS5 RFC 1929
and HTTP `Proxy-Authorization: Basic`). `tls: {custom-cert: [...], certificate:
<dir>}` adds trust anchors for outbound TLS: they are built into the kernel
instance at start and used by every TLS dial of that instance (the platform
store stays the base, and a second kernel in the same process keeps its own
anchors). `skip-cert-verify: true` accepts any certificate instead. The
per-proxy TLS identities are implemented: `fingerprint` is a SHA-256
certificate pin (a leaf match is accepted, a non-leaf match verifies the chain
with the pinned certificate as the anchor), `name-cert-verify` verifies the
chain against a name that differs from SNI, and `certificate`/`private-key`
add a client certificate from inline PEM or a file loaded at handshake time.
`client-fingerprint` (uTLS) stays a named gap. The private-CA case is covered
by `tests/protocols.rs::custom_ca_roots_are_installed_for_outbound_tls`; the
T27 identity cases are `fingerprint_pins_the_leaf_certificate` and
`name_cert_verify_checks_the_configured_name`.
Process rules match metadata supplied by the embedding host
(`Target::with_process`); the mixed inbound has no process lookup, and
`find-process-mode` remains T6/T22 scope.

Example:

```yaml
mixed-port: 17890
allow-lan: false
mode: rule
log-level: info
authentication:
  - "alice:secret"
proxies:
  - {name: ss1, type: ss, server: 203.0.113.10, port: 8388,
     cipher: aes-256-gcm, password: "..."}
  - {name: tj1, type: trojan, server: 203.0.113.11, port: 443,
     password: "...", sni: example.org, udp: true}
  - {name: jump, type: socks5, server: 127.0.0.1, port: 1080}
  - {name: vl1, type: vless, server: 203.0.113.12, port: 443,
     uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, tls: true, network: ws,
     ws-opts: {path: /ws}}
rules:
  - DOMAIN,blocked.example,REJECT
  - DOMAIN-SUFFIX,corp.example,tj1
  - MATCH,ss1
```

A key the pinned version declares but this kernel does not implement (a
top-level key such as `external-controller-pipe`, or a proxy option such as `obfs`)
fails when its value asks for something; a key the pinned version does not declare at all
is ignored with a warning, exactly as Mihomo's decoder ignores it, so a valid
upstream configuration is not rejected (R2). Errors are categorized by a stable tag: `invalid_yaml`,
`invalid_value`, `unsupported`, plus `bind` and `limits` at start-up. Example:

```
error: [unsupported] unsupported configuration: top-level key 'external-controller-pipe' is not implemented by the Rust kernel slice (the control API is T25; a Windows named pipe is not implemented, use external-controller, external-controller-unix or external-controller-tls)
error: [unsupported] proxies[0] (name=s1, type=vless): option 'flow' value 'xtls-rprx-vision' is not implemented
```

## DNS and hosts (T22)

`dns.rs` implements the pinned v1.19.34 resolver and `hosts` table; the engine
uses them for rule-time resolution, DIRECT dials, proxy-server names and
SOCKS5 UDP destinations.

**hosts** is a domain trie with the pinned `component/trie/domain.go` forms and
priority (exact label > `*` label > `.`/`+` suffix node): an exact name,
`*.example.com` (one label), `.example.com` (subdomains only),
`+.example.com` (the name and any depth) and `sub.*.example.com`. Values are
one IP, an IP list, or a domain that is followed (cycles are rejected at load).
The built-in `localhost -> 127.0.0.1` exists even without a `hosts` block, and
`use-system-hosts: true` adds `/etc/hosts` (read with a five-second cache when
the file's mtime/size change). `hosts` is applied to rule matching even when
`dns.enable` is false, exactly like the pinned `updateHosts`.

**dns** supports `enable`, `listen`, `ipv6` (+`ipv6-timeout`), `use-hosts`,
`use-system-hosts`, `respect-rules`, `nameserver`, `default-nameserver`,
`fallback`, `fallback-filter` (`geoip`, `geoip-code`, `ipcidr`, `domain`,
`geosite`), `fallback-lazy-query`, `nameserver-policy`, `proxy-server-nameserver`
(+`-policy`), `direct-nameserver` (+`-follow-policy`), `enhanced-mode`,
`fake-ip-range`/`fake-ip-range6`, `fake-ip-filter`/`-mode`/`-ttl`,
`cache-algorithm`/`cache-max-size` and `prefer-h3`.

- **Upstreams** are `udp://` (default), `tcp://`, `tls://` (DoT, SNI = the
  nameserver host) and `http://`/`https://` (DoH over HTTP/1.1 GET `?dns=`,
  Accept `application/dns-message`; `http://` is plain TCP). A nameserver hostname is bootstrapped through
  `default-nameserver` (validated as pure IPs). `skip-cert-verify`,
  `disable-ipv4`/`disable-ipv6`/`disable-qtype-<n>` are honoured; a truncated
  UDP reply is retried over TCP. `#h3=true`, `quic://`, `system://`,
  `dhcp://`, `ts://`/`et://`, `rcode://`, `ecs`/`ecs-override`,
  `name-cert-verify` and a `#proxy` name are rejected with the form named.
- **Selection** mirrors the pinned resolver: a `nameserver-policy` match wins
  first (plain-domain keys use the pinned trie specificity; `geosite:` and
  domain-behavior `rule-set:` use their domain sets in declaration order), a
  matching `fallback-filter.domain`/`geosite` sends the query only to the
  fallback, and otherwise main and fallback race. A main answer that is LAN is
  never replaced; an address inside `fallback-filter.ipcidr`, or failing the
  `fallback-filter.geoip` matcher, falls back. `geoip-code` keeps a leading
  `!` (the pinned `LoadGeoIPMatcher` builds a *not* matcher and
  `dnsFallbackFilter` inverts it again), so `!CN` falls back for a CN answer
  and `CN` for a non-CN one. All servers of one list race and the first
  non-SERVFAIL/REFUSED answer wins.
- **Cache**: question-keyed, minimal TTL over the answer and authority
  sections (so an NXDOMAIN/NODATA SOA caches the negative answer), SERVFAIL
  cached for five seconds, bounded by `cache-max-size` (4096 default).
  `cache-algorithm: arc` is accepted but served by the same LRU (answers/TTLs
  unchanged).
- **Fake-ip** allocates gateway+3 onward (`198.18.0.4` for the default range),
  wraps at the broadcast address and evicts a reused slot; the in-memory host
  store is bounded at 1000 entries (arbitrary eviction under pressure, unlike
  the pinned LRU, but the same bound); `fake-ip-ttl` is set
  on answers and `fake-ip-filter` (blacklist/whitelist) plus the fallback
  nameserver hostnames decide which names are real. An inbound destination
  that is a fake IP is mapped back to its host before rules
  (`preHandleMetadata`), then resolved through the direct/proxy resolver; an
  unknown fake IP fails with `fake DNS record <ip> missing`. `redir-host` maps
  every answer IP back to its host for the answer TTL (ten seconds for a hosts
  answer, as pinned `withHosts`), bounded at 4096 entries.
  `profile.store-fake-ip: true` is accepted with a warning: the pool is
  in-memory, so allocations do not survive a restart (the pinned cache.db
  persistence is a named gap).
- **DNS server**: `dns.listen` binds UDP and TCP and applies the pinned
  middleware order hosts → fake-ip → mapping → resolver in every enhanced mode.
  A hosts entry answers directly (TTL 10); a domain-valued entry replaces the
  question name with the target, resolves it through the remaining middleware
  and prepends a CNAME (TTL 10), as pinned `withHosts` does. It answers
  A/AAAA/CNAME; other qtypes get NOTIMP (a named gap).
- **respect-rules** routes TCP/TLS/HTTPS upstreams through the rule set and
  proxy groups (the same `DnsRoute` the engine uses for sessions). A UDP
  upstream with `respect-rules` is rejected by name because proxy UDP routing
  is not implemented.
- **Engine integration**: IP-based rules (`GEOIP`, `IP-ASN`, `IP-CIDR`,
  `IP-SUFFIX`, IP/CIDR `RULE-SET`s and their logic combinations) resolve
  lazily in first-match order and honour `no-resolve`; a failed resolution is
  remembered. DIRECT dials use `direct-nameserver` (or the main list) when DNS
  is on; proxy server names use `proxy-server-nameserver` (+policy) when
  configured, otherwise the main list. Without `dns.enable` the OS resolver is
  the pinned `SystemResolver` equivalent.

Named gaps: DoQ, DHCP/system/overlay/rcode nameservers, `#proxy` names, EDNS
client subnet, `name-cert-verify`, HTTP/2/3 DoH (`prefer-h3` is recorded),
`fake-ip-filter-mode: rule`, `profile.store-fake-ip` persistence, negated
`fallback-filter.geosite`, and DNS-server qtypes beyond A/AAAA/CNAME.

## Proxy groups (T23)

`proxy-groups` implements the pinned `adapter/outboundgroup` semantics. Every
member expansion follows `GroupBase.GetProxies`: the inline `proxies` list is
the "compatible" block and comes first, then each `use` provider snapshot; a
group `filter` (backtick-separated regexes, matched case-sensitively like
`regexp2.None`) selects from named providers only, `exclude-filter` removes by
name, and `exclude-type` (`|`-separated) compares the pinned adapter name
(`Http`, `Shadowsocks`, `Socks5`, ...), not the YAML `type`. Multiple providers
with multiple filters reorder the combined list by filter and append the rest,
exactly as pinned. An empty result selects `empty-fallback` (default
`COMPATIBLE`, which routes like `DIRECT`). `include-all` implies both
`include-all-proxies` (sorted proxy names through `filter`) and
`include-all-providers` (sorted provider names). Nested groups may be declared
in any order; cycles are rejected (`loop detected`) and the member list is
rebuilt when a provider generation changes.

Types: `select` (first member, `default-selected`, or a fixed selection),
`url-test` (the pinned `fast()` algorithm: lowest `LastDelayForTestUrl` among
alive members, `tolerance` keeps the current node, a fixed selection wins while
alive; a `now`/dial resolution reuses the previous computation for ten seconds,
pinned `URLTest.fastSingle` — `select` (pinned `ForceSet`, which resets only
the computation cache and keeps `fastNode` as the tolerance baseline) and a
dial-failure-triggered health check reset it, the periodic probe does not),
`fallback` (first alive member; a
fixed member that died is cleared and scanning continues) and `load-balance`
(`consistent-hashing` default, `round-robin`, `sticky-sessions`, all using the
pinned `jumpHash`; a dead bucket is retried up to five times and then the list
is traversed). Pinned v1.19.34 removed `relay` ("please using dialer-proxy
instead"), so the Rust kernel rejects that type with the same named reason
instead of implementing a shape the pinned engine refuses. `hash-key: in-user`
is rejected (the mixed inbound does not propagate the authenticated user to the
outbound), and `routing-mark`/`interface-name`/`dialer-proxy` on a group are
recorded as warnings exactly as pinned logs them.

Health checks: `interval`, `timeout` (milliseconds, default 5000),
`max-failed-times` (default 5), `lazy` (default true), `url` (default
`https://www.gstatic.com/generate_204` or the first `use` provider's
health-check URL) and `expected-status` (pinned `/`/`,` range syntax) are
honoured. A `select` group has no automatic probe; other types default to a
300 s interval. Pinned `HealthCheck.process` checks once immediately
(`go hc.check()`) and `baseProvider.setProxies` checks again after every
provider snapshot swap, both regardless of `lazy`; the Rust scheduler runs the
same forced probe at startup and after `Kernel::update_proxy_provider` (or an
observed generation change), for every group (nested groups have their own
tasks), its inline members and every enabled provider. Afterwards each task
probes on its own interval boundary, and `lazy` skips a boundary when that
task was not touched since the previous one. A group task uses the group
timestamp; a provider task uses the provider's own `lazy`/`lastTouch`. A real
dial touches every group on the resolved path (outer and nested) and every
`use` provider of those groups. A probe touches every nested group it dials
(pinned `Proxy.URLTest` runs the member's `DialContext`, and a group's
`DialContext` calls `GetProxies(true)`), so a nested group's lazy interval
keeps probing after the parent was probed or dialed; `now`/status reads never
touch. Probes dial through the member's full `dialer-proxy` chain (including
nested groups) and issue `HEAD`, then record the per-URL alive flag and delay.
The initial state matches pinned: a member with no probe record yet
is alive and its delay is `65535`. A failed dial triggers the pinned
`onDialFailed` thresholds (a connection-refused error triggers immediately,
otherwise `max-failed-times` within `timeout` trigger a health check; success
resets the count). Provider `health-check` drives `use` provider members; an
explicit group `url` registers on each provider's single `HealthCheck`
(`registerHealthCheckTask`): one interval/ticker and one deduped-by-URL extra
list per provider (the first `expected-status` wins, later filters merge), with
the provider's `lazy`/`lastTouch` and `health-check.timeout`
(`HealthCheck.execute`), while a URL equal to the provider's
`health-check.url` registers nothing. A registration activates a provider whose
`health-check.enable` is false (pinned `Initial()` starts `process()` once
`hc.interval` becomes the group interval), and that provider's `check()` probes
its own `hc.url` as well as the registered URLs in the same tick. The
registration interval is the group interval as written (pinned
`addTestUrlToProviders` runs before the parser defaults a group with inline
members to 300 s), and a provider that already has an interval keeps it.
UDP datagrams through a group with `disable-udp` are dropped and logged.

Selection persistence: `profile.store-selected` (default true) writes fixed
selections to `<cache-dir>/cache.yaml` and restores them before traffic, like
pinned `patchSelectGroup`. The file holds the same group→member map as pinned's
bbolt `cache.db` (the files are not interchangeable). Hosts pass a cache
directory through `KernelOptions`; the CLI uses the configuration directory and
warns when no directory is available. `profile.store-fake-ip` is accepted with
a warning: the fake-ip pool and mapping are in-memory, so allocations do not
survive a restart (the pinned cache.db store is a named gap).

Rule targets and API: a rule or `MATCH` may name a group; the engine resolves
nested groups on each dial and reports the group path in the session log.
`Kernel::group_statuses()`, `Kernel::groups().group_status(name)`,
`Kernel::select_group(group, member)` and the async
`GroupRegistry::probe_group/probe_all` are the T25-facing surface. `GroupStatus`
carries `type`, `now`, the ordered `all` list, `fixed`/`default-selected`,
`testUrl`, `expectedStatus`, `hidden`/`icon`, `emptyFallback` and per-member
alive/delay, which is what pinned `/proxies` exposes.

Not claimed: `dialer-proxy` still resolves only inline proxy names (a group or
provider proxy as the dialer target is rejected at load), consistent-hashing
buckets are not byte-identical to pinned (pinned `maphash` is seeded per
process; the Rust key is deterministic FNV-1a over the effective domain), the
public-suffix approximation for the hash key is the last two labels (no PSL
table in the kernel), and `load-balance.Now()` is empty exactly as pinned.
Evidence: `tests/groups.rs` (parsing, filters/include-all and the configured
empty fallback, nesting, selection, startup probes under the default lazy
config, probing a nested group touching its lazy tick, the ten-second url-test
computation cache, provider snapshot re-checks, extra group-URL probe
timeout/dedupe, tolerance state changes, dialer-proxy probe chains,
round-robin/consistent-hashing, provider `use`, persistence) and
`tool/kernel-compat/evidence/t23-differential.json` (26 pinned-Mihomo cases +
persistence, all matching; the tolerance cases sample twice because pinned
caches `fastSingle` for 10 s, `url-test-cache-window` samples at 0.9/9/12.5 s,
and the nested-touch case dials once at 1 s and reads the nested group at
11.5 s).

## Control API (T25)

`controller.rs` serves the pinned `hub/route` surface Billow consumes. A
listener starts automatically when the configuration sets
`external-controller` (TCP), `external-controller-unix` (Unix socket) or
`external-controller-tls` (TLS, using top-level `tls.certificate` and
`tls.private-key`). A hostless address such as `external-controller: ":9090"`
binds every interface (`[::]:9090`, IPv4 wildcard fallback), like the pinned
`net.Listen`. A control listener that cannot bind is logged
(`External controller listen error …`) and skipped without failing the kernel
(the mixed inbound and the other listeners keep running), matching pinned
`hub/route.start*`. The TLS listener speaks HTTP/1.1 only and advertises only
`http/1.1` in ALPN: pinned also serves h2 through Go's http server, but this
router has no HTTP/2 frame layer, so an h2 offer would negotiate a protocol
that never sends SETTINGS. `external-controller-cors` defaults to the pinned
`allow-origins: ["*"]`, `allow-private-network: true`.

Implemented endpoints (statuses and JSON shapes follow pinned v1.19.34):

| Endpoint | Methods | Notes |
| --- | --- | --- |
| `/` | GET | `{"hello":"mihomo"}` |
| `/version` | GET | `{"meta":false,"version":"<crate version>"}` (the boolean shape is pinned; the string is this kernel's version, not an upstream claim) |
| `/configs` | GET/PATCH/PUT | GET reports `mixed-port`, `tun.enable`, `mode`, `log-level`, `ipv6`, `authentication`, geodata fields; PATCH accepts `tun.enable:false` (and rejects real changes by name); PUT with `payload` reloads |
| `/proxies` | GET | `proxies` map: `DIRECT`/`REJECT`/`REJECT-DROP`, inline proxies, groups; provider nodes stay under `/providers/proxies` |
| `/proxies/:name` | GET/PUT/DELETE | detail, selector update, clear `url-test`/`fallback` fixed member (a Selector answers 400 like pinned) |
| `/proxies/:name/delay` | GET | `timeout` required, `url`/`expected` parsed; 400/404/503/504 match pinned |
| `/rules` | GET | index/type/payload/proxy/size; pinned `extra` hit counters are not tracked and omitted |
| `/connections` | GET/DELETE | live routed tunnels with pinned metadata keys, byte counters, chains, rule; DELETE closes one/all; `connections: null` when empty |
| `/providers/proxies` | GET | real proxy providers plus `Compatible` group/default providers |
| `/providers/proxies/:name` | GET/PUT | detail and update; a failed update is 503 and keeps the old snapshot |
| `/providers/proxies/:name/healthcheck` | GET | provider health check (a `Compatible` group probes its members in the background; `default` is a 204 no-op) |
| `/providers/proxies/:p/:name` | GET/healthcheck | provider node detail/latency; for a `Compatible` provider (group or `default`) the node resolves through the group's member list / all adapters, so group members and `DIRECT` keep the pinned 200 shape instead of 404 |
| `/providers/rules` | GET | behavior/format/ruleCount/vehicleType/updatedAt (inline providers report `format: ""` and `payload`) |
| `/providers/rules/:name` | PUT | re-read one provider; 503 on failure with the old snapshot kept |
| `/logs` | GET (stream/WS) | NDJSON `{"type","payload"}` (or `format=structured`), level filter; `level` is validated against the pinned `error`/`warning`/`info`/`debug`/`silent` keys before the 200 stream starts (a bogus level is the pinned 400 `Body invalid`), and the CLI forwards tracing events to the bus |
| `/traffic` | GET (stream/WS) | `{"up","down","upTotal","downTotal"}` each second |
| `/memory` | GET (stream/WS) | `{"inuse","oslimit"}`; `inuse` is the process peak RSS (`getrusage`) |

Auth: when `secret` is non-empty, TCP/TLS requests need
`Authorization: Bearer <secret>`; a WebSocket upgrade may use `?token=`; the
Unix socket is unauthenticated (pinned starts it with an empty secret and
relies on the socket permission, here `0666`). Routing resolves before auth, so
an unknown path is the pinned plain-text `404 page not found` even without
credentials, and a wrong method is 405 with `Allow`. CORS headers are added to
every response (`Vary: Origin`), and preflight `OPTIONS` answers 200 without
auth.

Reload (`PUT /configs`) builds a complete replacement generation (providers,
GEO, DNS, hosts, groups, rules) and only then swaps it; a failure leaves the old
generation live. Provider reads and the reload build use blocking file/socket
I/O (`std::net::TcpStream` with 15s connect / 30s read); both run on a
`spawn_blocking` worker so the controller's current_thread runtime keeps
accepting and answering `/version`, `/traffic`, `/proxies` and `/connections`
while a provider stalls. In-flight sessions keep the generation they started
with, so a reload frees the previous rules/providers/DNS objects when their
last session ends (R4). Pinned recreates the mixed listener/DNS server on
reload while this kernel refuses a changed `mixed-port`/`bind-address`/
`dns.listen` or controller listener/secret with a named 400 (restart
required). `/configs/geo`, `/upgrade/geo`, `/group`, `/cache`, `/storage` and
`/dns/query` are not implemented and return an explicit 404, recorded in
`tool/kernel-compat/evidence/t25-controller.md`.

## Protocol outbounds

Every proxy establishes a real TCP connection to the configured server
(optionally over TLS / WebSocket), performs the handshake and hands a byte
stream to the session. A failed handshake, TLS verification or authentication
aborts the session and the client receives the inbound failure reply. The
identities of the servers are logged as the session exit.

| type | transport options implemented | UDP | verified against the pinned Mihomo |
| --- | --- | --- | --- |
| `socks5` | plain, `tls: true` (+ `sni`, `skip-cert-verify`, `alpn`), RFC 1929 auth; the server socket is dialled by the shared dialer so `BasicOption` knobs apply | `udp: true`: RFC 1928 `UDP ASSOCIATE` (mixed inbound and TUN data plane) | `listeners: type: socks` (with users), wrong password |
| `http` | plain, `tls: true`, Basic auth, extra `headers` | no | `listeners: type: http` (with users) |
| `ss` | AEAD 2017 `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`; every other pinned ss method is rejected by name (the shadowstream list, ChaCha8/CCM/GCM-SIV/AEGIS/AEZ/Deoxys/LEA/Ascon AEADs, `none`, and `2022-blake3-aes-128-gcm`/`2022-blake3-aes-256-gcm`/`2022-blake3-chacha20-poly1305`/`2022-blake3-chacha8-poly1305`/`2022-blake3-aes-128-ccm`/`2022-blake3-aes-256-ccm` — full list in `tool/kernel-compat/evidence/t28-option-parity.md`) | `udp: true`: AEAD-2017 datagrams | `listeners: type: shadowsocks`, wrong password (TCP and UDP) |
| `trojan` | TLS, `network: tcp` / `ws` (`ws-opts.path`, `headers`, `v2ray-http-upgrade`), optional `ss-opts` Shadowsocks AEAD layer (`aes-128/192/256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`; every other pinned `PickCipher` name, including `DUMMY`, is rejected by name) | `udp: true`: `addr|len|CRLF|payload` frames over the TLS stream | `listeners: type: trojan`, wrong password, untrusted certificate (TCP and UDP) |
| `vless` | `tls: true`, `network: tcp` / `ws` (`ws-opts.path`), `encryption: none` | no | `listeners: type: vless` (tcp and `ws-path`), wrong uuid |
| `anytls` | TLS, one stream per connection, protocol version 2 | no | `listeners: type: anytls`, wrong password, untrusted certificate |
| `vmess` | AEAD request header (`alterId: 0`), `cipher: auto`/`aes-128-gcm`/`chacha20-poly1305`/`none`, `tls: true`, `network: tcp`/`ws` (`ws-opts.path`, `headers`), `sni`/`servername` | no | `listeners: type: vmess` (aes-128-gcm, chacha20-poly1305, domain target), wrong uuid |
| `snell` | v1 (chacha20-poly1305) / v2 / v3 (aes-128-gcm), Argon2id KDF, `obfs-opts: {mode: http, host}` | no | `listeners: type: snell` v1/v2/v3, v3 + http obfs, wrong psk |
| `trusttunnel` | TLS + HTTP/2 `CONNECT`, Basic `Proxy-Authorization`, ALPN `h2`, `sni`, `skip-cert-verify` | no | `listeners: type: trusttunnel` (`network: [tcp]`), wrong password |
| `gost-relay` | relay v2 over TCP, `tls: true` (`sni`, `skip-cert-verify`), `username`/`password`, `forward` (no address feature), `mux` (smux v1 session, one stream per dial) | `udp: true`: one association bound to the target, `length(u16 BE) || payload` frames | controlled relay-v2 server (header vectors, auth/forward/TLS/status, UDP and smux cases); no Mihomo listener exists |
| `ssh` | password and inline-PEM public-key auth, `private-key-passphrase`, `host-key` pinning, `host-key-algorithms`, one `direct-tcpip` channel per dial; the server socket is dialled by the shared dialer (BasicOption applies) | no | controlled `russh` server (password/key/host-key/basic-option cases); no Mihomo listener exists |
| `ssr` | stream ciphers (`rc4-md5`, `aes-128/192/256-cfb`, `aes-128/192/256-ctr`, `chacha20`, `chacha20-ietf`, `xchacha20`, `none`), every protocol plugin (`origin`, `auth_sha1_v4`, `auth_aes128_md5`, `auth_aes128_sha1`, `auth_chain_a`, `auth_chain_b`), every obfs plugin (`plain`, `http_simple`, `http_post`, `random_head`, `tls1.2_ticket_auth`, `tls1.2_ticket_fastauth`) | `udp: true`: the pinned `cipher.PacketConn` + `protocol.PacketConn` association (no obfs, as in the pinned outbound). Pinned limit: `auth_aes128_*` datagrams are sealed with the derived user key but opened with the cipher key, so `protocol-param` breaks the UDP path; the UDP cases use no `protocol-param` | pinned Go cipher vectors; the Go plugin peer, which the *pinned* client packages also accept for all 36 protocol/obfs combinations; wrong-password and UDP cases; no Mihomo listener exists |
| `tuic` | QUIC (`quinn` 0.11, TLS 1.3, ALPN `h3`), v5 `uuid`/`password` authentication via the TLS exporter, one TCP stream per dial, `ip`/`sni`/`skip-cert-verify`/`disable-sni`/`heartbeat-interval`/`request-timeout` (bounds the auth/Connect stream operations) | no | `listeners: type: tuic` (users map), wrong password; controlled `quinn` peer for the default suite |
| `hysteria` | QUIC (ALPN `hysteria`), binary control hello (`auth`/`auth-str`, `up`/`down`), one TCP stream per dial | no | controlled `quinn` server implementing the pinned `transport/hysteria/core` framing (no Mihomo listener exists) |
| `hysteria2` | QUIC (ALPN `h3`), HTTP/3 `POST /auth` (status 233), `0x401` TCP request frame, `down` (sent as `Hysteria-CC-RX`), `handshake-timeout` | no | `listeners: type: hysteria2` (users map), wrong password, unreachable target |
| `mieru` | TCP single session: PBKDF2-SHA256 time-salt key, XChaCha20-Poly1305 implicit nonce with the user hint, 32-byte metadata, session/data segments, a five-second `ackClientToServer` heartbeat, `port`/`port-range`, `handshake-mode` | no | `listeners: type: mieru` (transport TCP, users map), wrong password, closed peer port, port range, idle session across the heartbeat |
| `sudoku` | table-driven obfuscation: key-derived 4x4 Sudoku table, KIP X25519 + HKDF handshake, record layer (chacha20-poly1305 / aes-128-gcm / none with epoch keys and sequence validation), legacy HTTP mask, pure and packed downlink, `table-type` (entropy/ascii/directional), `custom-table(s)` rotation, `padding-min/max`, `path-root`, `multiplex: on` session mux, `dialer-proxy` through a SOCKS5 hop (**GPL-3.0-derived translation**) | no: `udp: true` (UoT) rejected at load | `listeners: type: sudoku` (default, no mask, ascii + packed downlink, directional, custom table, table rotation, aes-128-gcm, none, private/public key material, two-stream and concurrent session mux, a `dialer-proxy` chain through a recording SOCKS5 hop, `multiplex: on` over that chain, wrong key, mismatched table type); pinned Go codec differential in `tool/kernel-compat/peers/sudoku-vectors` |
| `masque` | two shapes over HTTP/3 (`quinn` 0.11, TLS 1.3, ALPN `h3`): (1) RFC 9484 CONNECT-IP for the pinned Cloudflare WARP configuration — base64 SEC1 P-256 client key → the pinned adapter's self-signed client certificate, `public-key` (DER SPKI) pinning the endpoint, `:protocol cf-connect-ip`, `uri` (default `https://cloudflareaccess.com`), `capsule-protocol: ?1`, a `ROUTE_ADVERTISEMENT` for every IPv4/IPv6 destination, `ADDRESS_ASSIGN`/`ROUTE_ADVERTISEMENT` parsing, whole IP packets in HTTP Datagrams (quarter stream ID + context ID 0), a minimal IPv4/IPv6/UDP stack with header/UDP checksums and a per-destination UDP flow table (32 flows, LRU eviction), `mtu` (default 1280), `ip-stack` mode selection, tunnel DNS (`remote-dns-resolve`/`dns`) and TCP termination with the in-tree minimal client (`src/outbound/tcp.rs`: active open, SYN/SYN-ACK/ACK, data/ACK, FIN/RST, MSS/window limits, RTO backoff and fast retransmit, reordering, half-close; one tunnel and one connection per `dial`); (2) the RFC 9298 CONNECT-UDP subset (`:protocol connect-udp`, one request stream per destination, `DATAGRAM` capsules, UDP only by protocol) | `udp: true` for both shapes; TCP needs the WARP CONNECT-IP shape (CONNECT-UDP cannot carry TCP) | controlled HTTP/3 peers in `tests/quic_peers.rs` (CONNECT-IP: request shape, client certificate and SPKI, endpoint pin, route advertisement, ADDRESS_ASSIGN, IPv4/IPv6 UDP echo with an independent IP codec, tunnel DNS, missing datagram settings, ADDRESS_REQUEST, 403, TCP echo/refusal/timeout/half-close with an independent TCP codec; CONNECT-UDP: request headers, per-destination flows, capsule echo, refusal, missing extended CONNECT/capsule negotiation, untrusted certificate, peer-FIN reopen, 32 closed flows then a new destination) plus the shipped CLI's SOCKS5 UDP ASSOCIATE and HTTP CONNECT (TCP) tunnels in `family_cli.rs`; no Mihomo listener exists and a WARP registration endpoint is not reachable offline |

The mieru module the pinned outbound wraps is GPL-3.0: this repository contains
no mieru source, links no mieru code and derives nothing from its
implementation beyond the published protocol description (`docs/protocol.md`
in that module) and wire observations against the pinned binary, which is used
only as the controlled peer.

`sudoku` is different: under the Owner authorization recorded in
`docs/sakullla-workflow/2026-11-20-native-rust-kernel/02-technical-solution.md`
(T17 recipe), T17 translated the pinned GPL-3.0
`transport/sudoku` (Mihomo v1.19.34, commit
`0455d0d28c4526937380505153e65a843d8612e8`) into
`src/outbound/sudoku/`. Every file carries `SPDX-License-Identifier:
GPL-3.0-only` with the upstream path, the workspace `license` field is
`GPL-3.0-only`, and `COPYING.GPL-3.0` plus `THIRD_PARTY_NOTICES.md` record the
file list and the GPL-3.0 obligations of distributing a binary that links this
crate. The translation and its verification are in
`tool/kernel-compat/evidence/t17-translation.md`; the earlier removal audit is
`tool/kernel-compat/evidence/t13-a3-sudoku-removal.md`.

Every outbound also parses Mihomo's `BasicOption` socket knobs. `tfo`,
`mptcp`, `interface-name`, `routing-mark` and `ip-version` are applied to the
connection to the proxy server (TCP dial, UDP association socket and the QUIC
endpoint; SSH now hands the shared dialer's stream to
`russh::client::connect_stream`): `ip-version` filters/orders the resolved
addresses, `interface-name` binds the socket (Linux `SO_BINDTODEVICE`, macOS
`IP_BOUND_IF`/`IPV6_BOUND_IF`; other platforms fail the dial with the option
named), `routing-mark` is `SO_MARK` on Linux and accepted+logged elsewhere (as
the pinned dialer does), `mptcp` uses `IPPROTO_MPTCP` on Linux with a TCP
fallback, and `tfo` (only when `tfo: true`) sets Linux
`TCP_FASTOPEN_CONNECT` / macOS `TCP_FASTOPEN` and logs once with a normal
connect on other platforms. The mesh adapters
(wireguard/openvpn/masque/mieru/sudoku/shadowquic/easytier) still name forms
they cannot apply. T27 evidence: `tool/kernel-compat/evidence/t27-option-parity.md`.

`dialer-proxy` chains are supported when every hop before the exit is `socks5`
(the hop is entered through the previous hop's SOCKS5 tunnel); any other chain
is rejected at load time or at dial time with a `[unsupported]`/chain error,
never silently bypassed. The exit itself must also be `socks5` or `sudoku`
(the exits whose handshake can run over a stream a hop produced); any other
exit is refused at dial time with a named chain error and is never replaced by
a hop. UDP follows the same rule: a `udp: true` proxy with a
`dialer-proxy` must name exactly one SOCKS5 hop, whose UDP relay carries the
datagrams (TCP and UDP then take the same path, matching Mihomo's
`proxydialer.ListenPacket`). Anything else - a hop without a UDP association,
or a longer chain that would need nested associations - fails at load time with
the hop named, instead of a UDP association dialling the server directly.

### UDP

The mixed inbound serves SOCKS5 `UDP ASSOCIATE`: the reply names the relay
socket, each datagram carries the RFC 1928 address header, and every datagram
is evaluated by the same rule set as TCP before it is forwarded. Per family:

| family | UDP behaviour |
| --- | --- |
| `DIRECT` / `REJECT` | forwarded from one unconnected UDP socket per address family (wildcard-bound, so a loopback listener still reaches remote targets) / dropped before any socket |
| `ss` with `udp: true` | AEAD-2017 datagrams to the server (directly, or through one SOCKS5 `dialer-proxy` hop), replies decrypted and returned with their source address |
| `trojan` with `udp: true` | command `3` over TLS (the server connection is established through the `dialer-proxy` chain like TCP), `addr|length|CRLF|payload` frames both ways |
| `socks5` with `udp: true` | RFC 1928 `UDP ASSOCIATE`: the control connection stays open and datagrams travel through the server relay (also the TUN data-plane transport); a `dialer-proxy` chain is rejected at load time because the association dials the server directly |
| `http`, `vless`, `anytls` | **no association**: `udp: true` is rejected at load time; `udp: false` (or absent) loads, and an association routed to such a proxy drops the datagram and logs it |

`vless` UDP would need `packet-addr`/XUDP and `anytls` needs UoT: both are
explicit gaps recorded in
`tool/kernel-compat/evidence/rust-mapping.json`, not silent successes.
`gost-relay` and the mesh families are still missing a TUN transport even
though `udp_enabled()` says yes; that path-specific gap is registered for T28.
Fragmented datagrams (`FRAG != 0`) are dropped. Destination names follow the
same path as TCP: a fake-ip/redir-host mapping is applied first, the rule set
may resolve the name lazily, and a DIRECT send uses `direct-nameserver` (or the
main DNS list) when `dns.enable` is true, the OS resolver otherwise. Proxy
datagrams keep the domain, as the pinned adapters do. For a chained association the *server* name is resolved
once and the whole address set is kept: a multi-A record (or a server answering
from another of its addresses) is accepted, while a reply from an address the
name did not resolve to is dropped. A resolver that returns only one family
(`AI_ADDRCONFIG` on a host without global IPv6, for example) yields a
single-entry set, which is what this host does for `localhost`. Memory per association is bounded: one 64 KiB client
datagram buffer plus one 64 KiB reply buffer per transport actually used, and
the association ends with its control connection or after
`Limits.udp_idle_timeout` (default 60 s).

### Protocol families outside this slice

The pinned parser lists 28 outbound types, matching the status recorded in
`tool/kernel-compat/evidence/rust-mapping.json`:

- **implemented (11)**: `ss`, `socks5`, `http`, `trojan`, `vless`, `anytls`,
  `vmess`, `snell`, `trusttunnel`, `gost-relay`, `ssr`;
- **partial (10)**: `ssh` (one client per dial, no private-key file paths),
  `mieru` (TCP slice), `sudoku` (TCP, legacy HTTP mask, pure/packed downlink and
  the session mux; the HTTP tunnel modes and UoT are rejected, and the module
  is a GPL-3.0-derived translation) and `masque` (CONNECT-UDP for UDP;
  CONNECT-IP for UDP and TCP with a minimal in-tree TCP client; `h2`,
  `h3-l4proxy`, gVisor and the pinned TCP-stack behaviour are not reproduced),
  `tuic`, `hysteria` and
  `hysteria2` (their T10 gaps), `shadowquic` (TCP/UDP and JLS, but `zero-rtt`,
  QUIC `v2` and the private Brutal congestion options are rejected), and
  `wireguard`/`openvpn` (protocol transports implemented, TCP/UDP dial needs
  the T6/T7 userspace IP stack and TUN device);
- **partial (2 more)**: `tailscale` (control/DERP protocol halves; the tunnel
  still needs T6/T7 and registration-only options are rejected) and `zerotier`
  (identity/planet/VL1/VL2 protocol halves; the controller membership exchange
  is T22/T23, the TCP fallback transport is rejected and the tunnel needs T6/T7);
- **partial (1 more)**: `easytier` (cleartext host/discovery plus Noise
  XX/secure-datagram AES-GCM/ChaCha20, translated from the locked LGPL source
  and verified against the pinned core; the tunnel needs T6/T7);
- **built-ins (4)**: `direct`, `dns`, `reject` and `rematch` as `proxies`
  entries (the `dns` proxy adapter is separate from the T22 resolver; none of
  the four is implemented as an outbound).

Every unimplemented type is rejected by name at load time, so no configuration
is silently reduced:

| families | why not here | task / decision |
| --- | --- | --- |
| `wireguard`, `openvpn` | the protocol halves are implemented (`src/outbound/wireguard.rs`, `src/outbound/openvpn.rs`) and verified against controlled peers, but turning their IP packets into TCP streams needs the userspace IP stack and TUN device owned by T6/T7 | **T16**: transport + configuration semantics; a `dial()` names the T6/T7 device gap. `outbound::wireguard::WireguardTunnel` and `outbound::openvpn::OpenVpnTunnel` are the interfaces for that layer |
| `tailscale`, `zerotier` | the protocol/configuration adapters are implemented in `src/outbound/{tailscale,zerotier}.rs` and verified against controlled peers built from the locked Go modules; the tunnel's TCP/UDP socket layer needs the T6/T7 userspace IP stack and TUN device | **T19 partial**: control/DERP and identity/planet/VL1/VL2 are available to T6/T7/T22/T23; `dial()` names the device gap; registration-only Tailscale prefs and ZeroTier TCP fallback are rejected by name |
| `easytier` | `src/outbound/easytier.rs` is an LGPL-3.0-or-later translation of the locked EasyTier source: cleartext host/discovery, Noise XX and secure-datagram AES-GCM/ChaCha20; the userspace IP stack/TUN and OSPF/route identity belong to T6/T7 | **T20 partial**: cleartext and secure handshakes/encrypted data verified against the pinned core; distribution must honor LGPL |
| `direct`, `dns`, `reject`, `rematch` as `proxies` entries | built-ins of Mihomo; the kernel already has `DIRECT`/`REJECT` rules, group members may name `DIRECT`/`REJECT`/`COMPATIBLE`, and there are no `dns`/`rematch` outbound adapters (T22 implements the resolver configuration, not `type: dns`) | `direct`/`dns`/`reject`/`rematch` proxy entries stay rejected by name |

T13 delivered `mieru` in the single-session TCP slice: an independent
implementation of the published protocol (the module is GPL-3.0, so no mieru
code is vendored or linked; only the pinned binary runs it as a peer). T17
delivered `sudoku` as an explicitly GPL-3.0-derived translation of the pinned
`transport/sudoku` (Owner authorization recorded in the T17 recipe,
`docs/sakullla-workflow/2026-11-20-native-rust-kernel/02-technical-solution.md`);
its
HTTP tunnel modes and UoT are rejected by name, and the licence obligations are
in [License](#license). Both families' rejected pieces are named in
[Not implemented](#not-implemented).

T14's `masque` is the RFC 9298 CONNECT-UDP subset and T18's is the pinned
Cloudflare WARP CONNECT-IP client, both written from the RFCs over the same
`quinn`/`rustls` stack as T10 (no `h3`/`connect-ip-go`/mipstack/gVisor code is
vendored, linked or copied). The pinned `adapter/outbound/masque.go` pins the
endpoint's ECDSA key, presents a certificate generated from the base64 private
key, sends `:protocol cf-connect-ip` and terminates the returned IP packets in a
userspace stack (`connect-ip-go`/mipstack or gVisor), which is how it serves both
TCP and UDP. This kernel implements that shape's data path for UDP:
`src/outbound/warp.rs` parses the SEC1 P-256 key and the SPKI pin (DER/base64
written out, signature from `ring`), builds the one-day self-signed certificate,
and installs a verifier that compares the endpoint certificate's
SubjectPublicKeyInfo with `public-key` (the chain and name are not verified,
exactly like the pinned `InsecureSkipVerify` + pin; `skip-cert-verify: true`
drops the pin). `src/outbound/masque_ip.rs` opens the CONNECT-IP request, sends
`ROUTE_ADVERTISEMENT` for `0.0.0.0`–`255.255.255.255` and `::`–the all-ones
address, reads `ADDRESS_ASSIGN`/`ROUTE_ADVERTISEMENT`, and carries IP packets as
HTTP Datagrams (QUIC DATAGRAM frames with the quarter stream ID and context ID
0; inbound `DATAGRAM` capsules are accepted too). `src/outbound/ipstack.rs` is
the minimal stack: IPv4 (20-byte headers, header checksum, fragments refused),
IPv6 (40-byte headers, extension headers refused), UDP checksums both ways, and
a UDP socket table keyed by the local source port, so replies reach the SOCKS5
association. `ip`/`ipv6` are the local addresses, `mtu` bounds one packet,
`ip-stack.mode auto|mips` selects the stack (the in-tree UDP-only one; gVisor is
the pinned build-tagged dependency and is refused), `remote-dns-resolve`/`dns`
send A/AAAA queries through the tunnel, and TCP is refused by name because a TCP
state machine is not part of this kernel. The request stream accepts capsules in
DATA frames up to 2 KiB (larger frames fail the association, a local bound) and
at most 32 UDP flows are open per association (the least recently used is
evicted). The CONNECT-UDP subset still serves a plain server: one request stream
per destination (`:protocol connect-udp`,
`/.well-known/masque/udp/<host>/<port>/`), `DATAGRAM` capsules with context ID
0, one maximal UDP datagram per capsule, and reclaimed closed flows. Memory: one
CONNECT-IP association is bounded by T10's QUIC windows (512 KiB stream receive,
2 MiB connection receive, 2 MiB send), 64 KiB datagram receive/send buffers, one
request stream with a 2 KiB frame and a 3 KiB capsule bound, four queued inbound
packets, 32 flows and at most eight held datagrams during a DNS lookup; the
worst case is recorded in `tool/kernel-compat/evidence/t18-feasibility.json`
(about 5.2 MB decimal per association) and T7 must cap concurrent associations.
The T14 bound is in `tool/kernel-compat/evidence/t14-feasibility.json`.

T21 adds TCP to the CONNECT-IP path. `src/outbound/tcp.rs` is a minimal
active-open client: SYN with an MSS option of `mtu` minus the IP and TCP
headers (40 bytes for IPv4, 60 for IPv6), SYN-ACK/ACK,
data/ACK bounded by the peer's MSS and advertised window, FIN/RST and
half-close, in-order delivery with a bounded out-of-order map, retransmission of
the oldest unacked segment with an RFC 6298-style fixed 1 s initial RTO and
exponential backoff (8 retries), fast retransmit after three duplicate ACKs and
immediate ACKs. It does not negotiate window scaling, SACK or timestamps, has no
RTT estimation, congestion control or zero-window persist timer, and only opens
connections (no passive or simultaneous open); those limits are named in
[Not implemented](#not-implemented) and `evidence/t21-feasibility.json`. Each
`dial` opens its own tunnel and one TCP connection (no pooling): the actor in
`masque_ip.rs` shares the CONNECT-IP handshake, capsules and datagram framing
with the UDP path, feeds inbound IP packets to the state machine, and turns the
application's writes into packets. A target host is resolved like the UDP path
(literal, local resolver, or an A/AAAA query through the tunnel with
`remote-dns-resolve`). The RFC 9298 CONNECT-UDP subset cannot carry TCP at all
(RFC 9298 is UDP-only), so a TCP dial through that shape is refused by name and
the WARP shape is required. Memory: a TCP dial is one tunnel (~5.14 MB of
analytic bounds, dominated by the QUIC windows) plus the TCP buffers (64 KiB
send, 64 KiB receive, bounded channels), recorded for T7 as ~5.24 MB decimal per
concurrent dial in `tool/kernel-compat/evidence/t21-feasibility.json`.

T15's `shadowquic` is an independent implementation of the JLS random seal,
written from the locked `jls-tls` behaviour and observed on the wire. JLS is not
an RFC 6066 extension: it replaces the 32-byte TLS 1.3 ClientHello/ServerHello
`random` with `AES-256-GCM(SHA-256(password || hello-with-zero-random),
SHA-256(username || hello-with-zero-random), random[0..16])`. `rustls` does not
expose a ClientHello hook, so the client builds the hello twice with a recorded
OS-seeded randomness stream and substitutes the one fill that produced the
`random`; the replay is checked byte-for-byte against the dry hello before the
connection proceeds. The locked `jls-tls` package is used only by
`tool/kernel-compat/peers/shadowquic-jls-vectors` to emit real hello vectors
(`native-kernel/crates/billow-kernel/tests/data/shadowquic-jls.txt`); no Go
code is linked or copied. The pinned `jls-tls` package is BSD-3-Clause
(Copyright 2009 The Go Authors); its complete copyright, conditions and
disclaimer are in `native-kernel/THIRD_PARTY_NOTICES.md`. The transport framing
provenance, the black-box observation matrix and the no-copy audit — including
the residual caveat that the first framing constants were confirmed against the
pinned GPL source — are in
`tool/kernel-compat/evidence/t15-cleanroom.md`; no GPL-3.0 source is vendored,
linked, or copied. The QUIC wire format is ordinary QUIC v1 (the pinned
`jls-quic-go` modifications are the server-side camouflage forwarding and the
TLS hook), so `quinn` carries it unchanged. TCP uses `CommandConnect` + a
SOCKS5 address; UDP uses `CommandAssociateDatagram` + QUIC datagrams or
`CommandAssociateStream` + one uni stream per destination. QUIC datagram
payloads are bounded by the path MTU as well as `max-datagram-frame-size`
(quinn starts at 1200 bytes); a larger payload fails with a named error and
`udp-over-stream` carries large packets as `u16`-length frames. A peer-stopped
uni stream is detected on the next write and reopened; a closed control stream
is rebuilt with all live target ids re-registered. Both paths are covered by
`tests/shadowquic_stream.rs` against an independent quinn peer. `quinn-proto` and
`typenum` became direct dependencies for the session wrapper and the 32-byte
GCM nonce; both versions were already in the lockfile (no new download).
`recv-window-conn`/`recv-window` default to the kernel's T7 budget (512 KiB
stream / 2 MiB connection) instead of the pinned 1.57 MiB / 6.4 MiB initial
windows; these are local flow-control choices, not wire fields. `rustls` still
verifies the CertificateVerify signature after JLS
authentication (the pinned Go client skips it), but a real server's camouflage
certificate is a valid key pair, so the handshake succeeds; the pinned peer
tests confirm it. A JLS failure aborts before any shadowquic request is sent,
even if `skip-cert-verify` was supplied (the pinned type does not declare that
key, so it is ignored like Mihomo ignores it).

The remaining gaps are named in [Not implemented](#not-implemented):
`ssh` rejects private-key file paths and opens one SSH client per dial;
`gost-relay` rejects only `client-fingerprint` among the TLS identities; the
`BasicOption` transport knobs are implemented for these families (T27). `ssh` uses `russh` 0.56 with the `ring` backend; `russh` 0.64
requires Rust 1.89 and its default `aws-lc-rs` backend would add a C/CMake
build, so it is not used. `russh` 0.56 declares MSRV 1.85 but its transitive
`home` 0.5.12 declares 1.88 and the Windows-only `pageant` 0.2.5 declares 1.89
(`uuid` 1.29.3 already declared 1.89 in the previous lock), so T11 raised the
workspace `rust-version` to 1.89 instead of shipping an inconsistent MSRV.
`03-execution-plan.md`
defines T9/T11 (non-QUIC), T10 (QUIC), T16 (device-family protocol halves;
device/TUN and the IP stack remain T6/T7) and the configuration-plane tasks
T22 (DNS/hosts), T24 (rules/providers/GEO) and T25 (control interface). T22,
T23 and T25 are implemented; the remaining boundaries are named below. The capability index
records each family at the status the kernel actually reaches: `implemented`,
`partial` (with the missing options named) or `unimplemented`; none can be
reported as compatible.

### Not implemented

Configuration-plane gaps not claimed by T24 (each is rejected with the key or
value named): `find-process-mode` (T22/T6 process lookup),
`external-controller-pipe`/`external-controller-routing-mark`, `external-ui*`,
`geo-auto-update: true`,
an HTTP provider fetched through a configured `proxy`, compressed provider
responses, `path-in-bundle`, `age-secret-key`, unsupported `override.<field>`
values, geosite/process regex look-around or backreferences that Rust `regex`
cannot express, and unknown MaxMind DB data types (the reader covers the
Country/ASN shapes above). Provider `health-check` fields drive the T23 health
scheduler; `profile.store-fake-ip` is accepted with a warning (the fake-ip pool is
in-memory; cache.db persistence is not implemented). Rule names
`UID`, `DSCP`,
`IN-USER`, `IN-NAME`, `REMATCH-NAME` and `PASS`/`PASS-RULE` are rejected by
name; `PROCESS-NAME-WILDCARD`/`PROCESS-PATH-WILDCARD` are implemented with the
pinned `component/wildcard` semantics (case-insensitive).

Every option a proxy entry contains must be one this kernel honours: the
loader reads only implemented keys and rejects the rest with the key named.
With the pinned option tables that means the trojan/vless `smux` block,
`udp-over-tcp`, `udp-over-tcp-version`, `ech-opts`,
`shadow-tls-opts`, `restls-opts`, `jls-opts`, `reality-opts`, `grpc-opts`,
`http-opts`, `h2-opts`, `xhttp-opts`, a non-AEAD `ss-opts.method`, `plugin`/`plugin-opts`, ws
early data and `v2ray-http-upgrade-fast-open`, `client-fingerprint`, vless
`flow`/`packet-addr`/`xudp`/`packet-encoding`, anytls
`client-metadata`/`idle-session-*`/`min-idle-session`/`disable-reuse`, vmess
`alterId > 0`/`packet-addr`/`xudp`/`packet-encoding`/`global-padding`/
`authenticated-length` and the vmess mux/TLS-mirror blocks, snell
`version: 4-6`/`reuse`/`mode`/obfs `tls`, trusttunnel
`udp`/`quic`/`health-check`/`max-connections`/`min-streams`/`max-streams`/
`congestion-controller`/`cwnd`/`bbr-profile`, gost-relay
`client-fingerprint`, ssh private-key file paths, and `udp: true` on
`vless`/`anytls`/`vmess`/`snell`/`trusttunnel` (no UDP association for those
families; socks5 UDP is implemented). T10's families reject the options
they do not implement by name: `tuic` `token` (v4/BLAKE3), `udp-relay-mode:
quic`, `udp-over-stream`, `reduce-rtt`, `fast-open`, the meta BBR v1 controller and the
UDP datagram sizing; the cubic/new_reno/bbr/bbr_meta_v2 controller (v2 is the pinned alias of bbr), `cwnd`, receive
windows and `disable-mtu-discovery` are applied to quinn; `cwnd` becomes a BBR initial window of
`cwnd × 1280` for TUIC (quic-go's default `InitialPacketSize`) and `cwnd × 1242` for masque (the pinned
masque `quic.Config` value); `bbr_meta_v1` and
`bbr-profile` are named. `hysteria`
`ports`/`hop-interval` (port hopping), `obfs` (XPlus), `protocol:
faketcp|wechat`, `fast-open`; `recv-window*` and `disable-mtu-discovery` are
applied. `hysteria2` `ports`/`hop-interval`, `obfs` (Salamander/Gecko),
`realm-opts`, `up` (the pinned Brutal TX-rate cap; quinn has no Brutal
controller), `udp-mtu`, `bbr-profile`; BBR with `cwnd` and the receive windows
are applied. `mieru` rejects `transport: UDP`,
`udp: true`, the multiplexing levels (one session per underlay) and
`traffic-pattern` (padding/nonce/low-entropy shaping). `sudoku` rejects
`udp: true` (the UDP-over-TCP/UoT association) and the HTTP tunnel modes
`http-mask-mode: stream|poll|auto|ws` (a mihomo extension over the protocol,
`transport/sudoku/obfs/httpmask/tunnel_*`); the legacy header mask, pure and
packed downlink, table rotation and `multiplex: on` are implemented, and the
module is a GPL-3.0-derived translation (`evidence/t17-translation.md`).
`masque` rejects
TCP through the RFC 9298 CONNECT-UDP subset (the protocol carries UDP only; TCP
needs the WARP CONNECT-IP shape, whose TCP client is in `src/outbound/tcp.rs`
and does not negotiate window scaling/SACK/timestamps, passive open or urgent
data), both non-HTTP/3 networks (`h2`, `h3-l4proxy`), `ip-stack.mode: gvisor`
(the pinned build-tagged dependency), `ip-stack.congestion-controller` beyond
validation (TCP-stack only), `bbr_meta_v1`/`bbr-profile` (quinn has one BBR
controller but no v1/profile selector) and `dialer-proxy` (a QUIC endpoint is
dialled locally), DNS name servers that are not `udp://` IP
literals, and URI templates (IP flow forwarding); its `udp: false` form loads
and refuses UDP dials while TCP still uses the tunnel. `shadowquic` rejects `zero-rtt` (JLS 0-RTT needs the pinned
authenticated session ticket), `quic-versions: v2` (quinn 0.11 implements v1
only), `congestion-controller`/`bbr-profile`/a non-default `cwnd`/`up`/`down`
(the private Brutal controller is not in quinn) and `dialer-proxy`; its
`skip-cert-verify`/`udp`/`tls` keys are not declared by the pinned type, so
they load and are ignored exactly as Mihomo ignores them. `wireguard` rejects
`amnezia-wg-option` (AmneziaWG's header obfuscation is a different device,
implemented by the pinned `amneziawg-go`), an explicit `ip-stack` mode /
congestion controller, `remote-dns-resolve`/`dns` (the stack resolver),
`refresh-server-ip-interval` (the runtime endpoint loop) and `dialer-proxy`;
its `mtu`/`workers`/`udp`/`persistent-keepalive` and both peer forms are
accepted and used by the transport. `openvpn` rejects `tls-auth`/`tls-crypt`/
`tls-crypt-v2` (the static-key control-packet codec), `comp-lzo: yes|adaptive`
(compression), the CBC data ciphers and a non-`tun` `dev`; it implements the
AEAD data ciphers, the `data-ciphers` negotiation, inline `ca`/`cert`/`key`,
username/password, `peer-info`, UDP and TCP framing. The mesh
families are partial: `tailscale` exposes the control-base Noise/HTTP2 and DERP
layers but rejects `hostname`, `auth-key`, `state-dir`, `ephemeral`,
`accept-routes: true`, `exit-node` and `exit-node-allow-lan-access: true`
because node registration/control-plane prefs are not implemented; `zerotier`
accepts the identity, planet, MTU, port, orbit, low-bandwidth and
encrypted-HELLO options, rejects an explicit `ip-stack`,
`remote-dns-resolve`/`dns`, remote trace and the TCP fallback transport
(`force`/non-empty relay) with the T6/T7/T22/T23 boundary. `easytier` accepts the
cleartext and `secure-mode`/`enable-encryption` options (Noise XX + AES-GCM/
ChaCha20); `enable-encryption: true` requires `secure-mode: true` (the source
encrypts only through the secure session) — the pair loads, while encryption
alone is rejected by name. It rejects OSPF/route host identity, KCP/QUIC,
exit-node/DNS and remaining data-plane options by name; its module is an
LGPL-3.0-or-later derivative. Every loadable mesh `dial()` names the T6/T7
gap.
`udp: false` is accepted for a family that has no UDP association because it
states the same thing this kernel does; `udp` is not a
Mihomo HTTP option at all and is rejected there. Unsupported protocol types are
listed in the error message.

The rule is mechanical: `reject_unknown` accepts only keys the parser read and
honoured, so a new option cannot be "documented as rejected" while being let
through by an option table. The only keys accepted without an effect are
boolean no-ops that ask for nothing (`udp: false`, `disable-reuse: false`,
`packet-addr: false`, `xudp: false`, `v2ray-http-upgrade-fast-open: false`),
empty blocks (`grpc-opts: {}`, `ech-opts: {enable: false}`, `smux: {enabled:
false}`, `ss-opts: {}`, `shadow-tls-opts: {}`, `restls-opts: {}`, `plugin-opts:
{}`) and TLS-only options when TLS is off (`skip-cert-verify`, `sni`, `alpn`,
`fingerprint`, `certificate`, `private-key`, `name-cert-verify`,
`client-fingerprint`, `ech-opts`). `ech-opts` is disabled unless `enable: true`
(other fields are then ignored, as in Mihomo), and `plugin-opts` is ignored
unless a plugin is configured. `vmess` requires `alterId` and `cipher` (Mihomo's
decoder reports them as unset fields when absent) and only accepts
`alterId: 0`; `snell` accepts versions 1-3 and the HTTP obfs mode; `ssr`
requires `cipher`, `password`, `protocol` and `obfs` (the pinned type declares
them without `omitempty`), accepts every value the pinned plugins register, and
passes `*-param` to the plugin that defines it (`protocol-param` names the user
id/key for `auth_aes128_*`/`auth_chain_*`, `obfs-param` the HTTP host/body and
the TLS SNI). Their
unimplemented options (`udp: true`, `packet-addr`, `xudp`, `packet-encoding`,
`global-padding`, `authenticated-length`, `grpc-opts`/`h2-opts`/`http-opts`,
`reality-opts`/`ech-opts`/`shadow-tls-opts`/`restls-opts`/`jls-opts`,
`tlsmirror-opts`/`mekya-opts`/`mkcp-opts`, snell `version: 4-6`/`reuse`/`mode`,
and the snell obfs `tls` mode) are rejected with the key named. Keys the pinned type does not declare at all
(`smux`, `ss-opts` on vless, `udp` on http, any unknown name) are ignored, which
is what Mihomo does with them. Three cases are rejected even when "empty":
`reality-opts` and `jls-opts` require fields (Mihomo rejects the empty block),
and `reality-opts`/`shadow-tls-opts`/`restls-opts`/`jls-opts` require
`tls: true` (Mihomo rejects them without TLS, so they are not ignored). The
same keys are ignored on a type whose option table does not declare them
(`socks5`/`http`/`ss`); `anytls` does declare them and applies them as a
security mode, so there a content block stays a registered rejection.

A transport block for a transport the configuration did not select
(`grpc-opts`, `http-opts`, `h2-opts`, `xhttp-opts` with `network: tcp|ws`) is
ignored by Mihomo even when it has content, so it is accepted here too; the
selected transport itself (`network: grpc|http|h2|xhttp`) is rejected.

`tool/kernel-compat/option-probe.mjs` runs the matrix against the pinned
Mihomo `-t`: every no-op form (including unknown keys and disabled switches
with extra fields) must be accepted by both engines, and every enabled form
must be rejected by the kernel with the field named **and** be registered in
`rust-mapping.json` (a rejection of an unregistered key is reported as a
problem, so the matrix cannot hide an over-strict parser). Mihomo's own verdict
is recorded; forms it rejects need no implementation. The result and its counts
are in `tool/kernel-compat/evidence/option-matrix.txt`.

## CLI

```
cargo run -p billow-kernel-cli -- <config.yaml> [--port N] [--geosite-dir DIR] \
    [--buffer-bytes N] [--max-sessions N] [--cache-dir DIR] \
    [--select GROUP=MEMBER]... [--probe-groups] [--wait-ms N] [--print-groups] [--check]
```

`--geosite-dir` (alias `--geodata-dir`) is the geodata directory. Relative
provider paths resolve against the configuration file's directory (and must
stay under it or `SAFE_PATHS`), never the process cwd. `--check` validates the
configuration and rule set, starts the listener to prove
the bind, prints the identity and exits. `--cache-dir` holds the T23 selection
cache (`profile.store-selected`; the default is the configuration directory),
`--select GROUP=MEMBER` fixes a selection before traffic, `--probe-groups` runs
every health check once, and `--wait-ms N --print-groups` waits and prints one
`GROUPS {json}` status line (type, now, all, per-member alive/delay) instead of
serving until a signal; the differential probe uses that shape. A normal run prints one identity line,
serves until SIGINT/SIGTERM (on Windows the host drives the library API; T6),
then prints a session summary:

```
instance=<uuid> pid=<pid> version=0.1.0 listen=127.0.0.1:17890 overridden_port=- config=sha256:<digest> rules=3 geosite_dir=- state_dir=-
features: mixed-inbound(tcp,http-connect,socks5); rules=inline(3 entries); rule-providers=0; proxy-providers=0; proxy-groups=0; sub-rules=0; outbounds=DIRECT,REJECT; protocols=ss1=ss,tj1=trojan,jump=socks5,vl1=vless; hosts=0; dns=off
stopped instance=<uuid> accepted=4 active=0 completed=2 rejected=2 failed=0 bytes_up=40 bytes_down=40
```

SIGINT stops accepting, closes live tunnels and joins every session task before
the process exits, so a restart can immediately rebind the same port.

## Library API

```rust
use billow_kernel::{Kernel, Limits};

let yaml = "mixed-port: 17890\nproxies:\n  - {name: p, type: socks5, server: 127.0.0.1, port: 1080}\nrules:\n  - 'MATCH,p'\n";
let (mut kernel, warnings) = Kernel::start_from_yaml(yaml, None, Limits::default())?;
println!("{}", kernel.identity().to_line());   // uuid, pid, version, listen, digest, features
let (action, rule) = kernel.evaluate("example.com", None);
kernel.stop()?;                                // no live sessions or tasks remain
```

Stable entry points:

- `Kernel::start(path, geosite_dir, limits)` / `Kernel::start_from_yaml(yaml, geosite_dir, limits)`
  / `Kernel::start_with_yaml(&LoadedConfig, geosite_dir, limits)` — the last one
  lets a host adjust the listener before binding and keeps the warnings.
- `Kernel::start_with_options(&LoadedConfig, geosite_dir, base_dir, limits, &KernelOptions)`
  — `KernelOptions { cache_dir, log_bus }` locates the T23 selection cache and
  optionally shares the host's `/logs` bus.
- `Kernel::identity()`, `Kernel::listen_addr()`, `Kernel::stats()`,
  `Kernel::evaluate(host, ip)`, `Kernel::config()`, `Kernel::stop()`.
- `Kernel::reload(yaml)`, `Kernel::controller_addrs()` and `Kernel::log_bus()`
  expose the T25 reload path, the bound controller addresses and the log bus.
  `KernelOptions::log_bus` lets a host logger publish engine events to `/logs`.
- `Kernel::groups()` / `Kernel::group_statuses()` / `Kernel::select_group(group, member)`
  — group list, current selection, fixed selection and per-member health for
  T25; `GroupRegistry::probe_group(name).await` / `probe_all().await` run an
  explicit latency test.
- `load_config` / `parse_rule` for validation without starting.
- `Limits { buffer_size, max_sessions, handshake_timeout, dial_timeout, half_close_timeout, udp_idle_timeout }`.

`Drop` stops a kernel that was not stopped explicitly; `stop()` is synchronous
and waits for the listener thread and all session tasks.

`examples/embed.rs` shows the same path a host (or the iOS extension) takes:
`cargo run -p billow-kernel --example embed -- <config.yaml>`. Both entries
carry protocol outbounds: `tests/protocols.rs` (`embedded_api_*`) and
`crates/billow-kernel-cli/tests/cli.rs` (`process_forwards_through_a_protocol_outbound`)
exercise a real tunnel through a configured `socks5` proxy from each side.

## Resource and concurrency invariants

- One fixed buffer per relay direction (`buffer_size`, default 16 KiB) and at
  most `max_sessions` sessions (default 256). Further connections stay in the
  listening backlog until a slot frees.
- Both relay directions run inside the session future (a `select` over two
  pinned copies); a stop request drops them with the session, so no task, buffer
  or socket outlives `stop()`.
- A tunnel ends when both directions finish; EOF is forwarded as a write-side
  shutdown (half-close). If the second direction stalls after the first ends, it
  is cut after `half_close_timeout` (default 30 s) so no session waits forever.
- A SOCKS5 UDP association owns one 64 KiB client buffer, one 64 KiB reply
  buffer per transport used and its sockets; it ends with the control
  connection or after `udp_idle_timeout`, and `stop()` joins it like any other
  session.
- Handshake and dial have their own deadlines. Handshake failures reply to the
  client (SOCKS5 reply code / HTTP status) before the socket closes.
- Every accepted connection increments `active` and decrements it exactly once;
  `stop()` joins all session tasks, so `active == 0` afterwards.

## Tests

Default suite (no external binaries; real loopback listeners):

```sh
cargo test --manifest-path native-kernel/Cargo.toml --locked
```

T22's DNS/hosts differential is separate too:
`node tool/kernel-compat/t22-differential.mjs --mihomo <binary> --rust
<billow-kernel> --out tool/kernel-compat/evidence/t22-dns.json`
(see `evidence/t22-dns.md`; it starts fixed UDP/TCP/DoT/DoH DNS fixtures and
compares listener answers, fallback/policy/fake-ip behaviour, `respect-rules`
and CONNECT cases). T24's rules/providers/GEO differential needs the pinned
Mihomo binary and a loopback provider server:
`node tool/kernel-compat/t24-differential.mjs --mihomo <binary> --rust
<billow-kernel> --out tool/kernel-compat/evidence/t24-differential.json`
(see `evidence/t24-geodata-rules.md`, including the `--mmdb-dir` cases). The T23
group differential runs the same pinned binary with loopback CONNECT nodes:
`node tool/kernel-compat/t23-differential.mjs --mihomo <binary> --rust
<billow-kernel> --out tool/kernel-compat/evidence/t23-differential.json`
(27 cases plus persistence; see `evidence/t23-groups.md`).

- `tests/config.rs` — parsing, strict option tables, error tags.
- `tests/controller.rs` — the T25 control API over a real TCP (and Unix)
  listener: auth forms, route/405/404 semantics, CORS preflight,
  `/configs` GET/PATCH/PUT reload, selection/delay, provider update failure,
  connection listing/close and `/traffic`/`/logs` frames.
- `tests/groups.rs` — T23: every group type/field, relay rejection, cycles,
  filter/exclude/include-all expansion and the configured empty fallback,
  `use` provider members, rule targets naming a group, url-test/fallback
  failover with controlled delays, startup probing with the default lazy
  config, provider snapshot re-checks, tolerance keep/switch, nested groups,
  probe through a dialer-proxy SOCKS5 chain, load-balance
  round-robin/consistent-hashing and selection persistence across a restart.
- `tests/resources.rs` — T24: every implemented rule type against the
  connection metadata, `SUB-RULE` action selection, all rule-provider
  vehicles/formats (including MRS), proxy-provider filters, generated
  `GeoSite.dat`/`GeoIP.dat`, HTTP provider update success/failure with the old
  generation kept, concurrent updates stamping unique generations, provider
  path containment, proxy-provider filter/override semantics, the bundled
  `Country.mmdb`/`ASN.mmdb` (ignored unless `BILLOW_MMDB_DIR` is set), and
  Billow's effective YAML: its rule/provider/proxy subset loads in override
  order (including a rule naming a group) while the launcher keys are
  registered as inert-with-warning or named rejections.
- `tests/dns.rs` — T22: pinned hosts trie forms/priority and domain chains,
  strict nameserver/fake-ip/hosts rejections, UDP/TCP/DoT/DoH resolution,
  cache TTL, nameserver policy, fallback IP/domain filters, timeout, fake-ip
  pool/allocation/filter/TTL and the DNS listener, plus engine cases for
  rule-time `IP-CIDR` resolution, `no-resolve` and fake-ip destination rebuild.
- `tests/sessions.rs` — inbound sessions, half-close, stop/restart, limits.
- `tests/quic_peers.rs` — T10/T14 QUIC loopback peers: TUIC v5 (auth token,
  domain and IP targets, wrong password, v4 token rejection, unimplemented
  options, `request-timeout` bounding a blocked stream open), Hysteria v1
  (control hello, `auth-str` and base64 auth, wrong auth,
  port-hopping/XPlus/faketcp rejection, rate validation), the Hysteria2 `up`
  rejection, and the MASQUE CONNECT-UDP peer (request headers and proxy
  authority, one flow per destination, capsule echo, a refused request, a peer
  without extended CONNECT, a 200 without the capsule protocol, an untrusted
  certificate, and the named TCP refusal). The peers are `quinn` servers
  written from the pinned Go framing or the RFCs; they need `openssl` for the
  loopback certificate.
- `tests/protocols.rs` — loopback peers for socks5/http/ss/trojan/vless
  (tcp, websocket, `v2ray-http-upgrade`), trojan websocket, the SOCKS5
  `UDP ASSOCIATE` relay (DIRECT, REJECT and ss datagrams), a private-CA TLS
  case for three families, positive and negative cases, plus the embedded-API
  entry. `vmess`, `snell` and `trusttunnel` have no loopback peer here: their
  wire formats are covered by the Go-pinned unit vectors in
  `src/outbound/{vmess,snell,trusttunnel}.rs` and by the real-peer cases below.
  The T11/T12 families have controlled loopback peers here: `gost-relay` (relay
  v2 header/auth/forward/TLS/status, the UDP association, and the smux session),
  `ssh` (a real `russh` server with password, Ed25519 key and pinned-host-key
  cases), `ssr` (origin/plain server plus pinned Go cipher vectors) and
  `gost-relay`'s smux session (`cli_process_tunnels_through_gost_relay_mux`;
  the SSR plugin layers run through the real binary in the controlled entry,
  `cli_process_tunnels_through_an_ssr_plugin`); they are also the explicit entry
  point of `tool/kernel-compat/family-peers.sh`.
  `random_head` locates the peer's head by scanning the CRC from the longest
  candidate: the pinned check is not unique for every length
  (`crc32(head[:n-1])` can equal the four bytes at `n-1`), and an ascending scan
  occasionally took the head one byte short and misaligned the cipher stream.
  The regression test is `random_head_length_picks_the_real_boundary`. The
  peer's address read and the client roundtrips are bounded, so a wrong
  password fails in seconds instead of leaving both sides waiting.
  `family-peers.sh` additionally builds the two independent Go SSR peers
  (`peers/ssr-server` for origin/plain and `peers/ssr-plugins` for every
  protocol and obfs plugin plus UDP), requires the *pinned* client packages to
  accept `peers/ssr-plugins` for all 36 protocol/obfs combinations, runs
  `tests/independent_peers.rs` (matrix, wrong passwords, protocol-param with
  large payloads, UDP), and builds `peers/gost-relay-harness` — the *pinned*
  `gost.NewRelayDialer` with `mux` and the UDP association — to drive the same
  gost-relay peer. The framing is therefore checked against the locked
  implementations, not only against the Rust client.
- `tests/mihomo_peers.rs` — real-peer interop: each case starts the pinned
  Mihomo v1.19.34 binary with one `listeners:` entry, the Rust kernel dials it
  as a client and the test asserts what a controlled sink received (and, for
  the negative cases, that it received nothing). The cases are `#[ignore]`d so
  the default suite reports them as ignored instead of passing or failing
  without the peer. The controlled command needs the pinned binary and the
  `openssl` CLI (or `KC_CERT_DIR`):

  ```sh
  # resolves the repo root and the pinned binary, then runs the cases serially
  tool/kernel-compat/peer-tests.sh

  # or explicitly (the cargo test process runs from native-kernel/crates/billow-kernel,
  # so a relative KC_MIHOMO_BIN would not resolve)
  KC_MIHOMO_BIN=/Users/yanggeng/github/Billow/tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
    cargo test --manifest-path native-kernel/Cargo.toml --locked \
    --test mihomo_peers -- --ignored --test-threads=1
  ```

  Without `KC_MIHOMO_BIN` each case prints `SKIP <case> (not verified): ...` and
  returns; a skipped case is **not** a pass. `KC_KERNEL_LOG=1` prints the
  kernel's own warnings, `KC_KERNEL_LOG=debug` its debug events, and a failing
  case prints the peer's config and log. The family coverage (TCP and UDP) is
  summarised in `tool/kernel-compat/evidence/protocol-peers.json`; T9 added
  `vmess` (aes-128-gcm, chacha20-poly1305, `none`, websocket, domain target,
  wrong uuid), `snell` (v1, v2, v3 + http obfs, wrong psk) and `trusttunnel`
  (HTTP/2 CONNECT, domain target, wrong password), 36 cases in total. T10
  added TUIC v5 and Hysteria2 against their Mihomo listeners (success and wrong
  password), 40 cases in total; Hysteria v1 has no Mihomo listener and is
  covered by `tests/quic_peers.rs`.
  T11's `gost-relay`, `ssh` and `ssr` have no Mihomo listener, so their peer
  cases live in `tests/protocols.rs` / `tests/independent_peers.rs` and are
  recorded under `controlledPeers` in
  `tool/kernel-compat/evidence/protocol-peers.json`. The
  CLI crate also drives a real success tunnel through each of the three
  (`crates/billow-kernel-cli/tests/family_cli.rs`), not only a config load; the
  same file now drives TUIC, Hysteria v1 and Hysteria2 through the real
  `billow-kernel` process as well.

  T13 added 5 mieru cases against `listeners: type: mieru`: the TCP session,
  `port-range`, an idle session across the five-second heartbeat, a wrong
  password and a closed peer port. T17 added 16 sudoku cases against
  `listeners: type: sudoku`: the default session, no HTTP mask, ascii + packed
  downlink, directional tables, a custom table, table rotation, aes-128-gcm,
  `none`, private/public key material, two sequential and two concurrent
  session-mux streams, a `dialer-proxy` chain through a recording SOCKS5 hop,
  `multiplex: on` over the same chain (three sequential tunnels over one
  session, plus a wrong-key failure),
  a wrong key and a mismatched table type (the last two must never reach the
  sink). The locked Go codec
  (`tool/kernel-compat/peers/sudoku-vectors`, GPL-3.0, test-only) is run by
  `tests/protocols.rs::sudoku_codec_matches_the_pinned_implementation` in both
  directions (pinned encode -> Rust decode, Rust encode -> pinned decode,
  pure and packed, with and without padding) for the entropy, ascii,
  directional and custom table layouts. `peer-tests.sh` runs 66 cases in total.
  T15 added 4 shadowquic cases: TCP, UDP over QUIC datagrams, UDP over
  `udp-over-stream`, and a wrong-password case that is forwarded to the
  camouflage upstream and never reaches the sink. The JLS seal is also
  cross-checked against real hello messages from the locked Go package via
  `tool/kernel-compat/peers/shadowquic-jls-vectors`; the vectors are committed
  at `native-kernel/crates/billow-kernel/tests/data/shadowquic-jls.txt` and
  consumed by `src/outbound/jls.rs::tests::verifies_locked_jls_client_and_server_hellos`
  (a default-suite test; the generator needs `go` and the module cache).
  `tests/shadowquic_stream.rs` is a default-suite controlled quinn peer that
  stops a client uni stream and closes the control send half; it proves the
  client reopens the uni stream and rebuilds the control association with the
  live ids. `tool/kernel-compat/peer-tests.sh` runs 66 cases in total (the T17 sudoku
  additions included). `masque` has
  no Mihomo listener (the pinned adapter is a Cloudflare WARP client) and no
  reachable WARP endpoint offline, so its twenty default-suite cases run against
  two controlled HTTP/3 peers in `tests/quic_peers.rs` (RFC 9298 CONNECT-UDP and
  RFC 9484 CONNECT-IP, the latter requiring the client certificate and echoing
  IP/UDP packets and terminating TCP with its own codec) and are recorded under
  `families.masque` in `protocol-peers.json`; the dependency/memory boundary is
  in `evidence/t14-feasibility.json` (CONNECT-UDP), `evidence/t18-feasibility.json`
  (CONNECT-IP UDP/WARP) and `evidence/t21-feasibility.json` (TCP). mieru has
  no Go vector tool because the module is GPL-3.0: the client is written from
  `docs/protocol.md` and is only verified against the pinned server, with the
  locally computed PBKDF2/time-salt vectors in `src/outbound/mieru.rs`.

  Observed host behaviour: starting the peer for many cases in one test process
  occasionally ends with a case where the kernel established the tunnel but the
  sink received nothing (the peer's own log shows its listener up and no
  connection). The same cases pass in isolation and in complete runs (recorded
  in `tool/kernel-compat/evidence/protocol-peers-run.log`); the suite is run
  with `--test-threads=1` and a rerun of the same command is the documented
  recovery. A rerun is never recorded as a first-attempt pass.

The cases share one process; each allocates its own loopback ports from a
process-wide registry and the suite serialises the peer runs (one kernel plus
one Mihomo process at a time), because several in flight starve a
just-accepted session on a loaded host and make a positive case look like a
missing marker.

## Coordination

The immutable coordination inputs are in `docs/coordination/`: `t11-handoff.md`
(this subset), `t12-handoff.md` (SSR plugin layers and gost UDP/smux),
`t13-handoff.md` (mieru), `t17-handoff.md` (the sudoku family; it authorises
the source translation and records the GPL-3.0 obligations),
`t14-handoff.md` (CONNECT-UDP) and
`t18-handoff.md` (CONNECT-IP, IP stack and WARP shape) and `t21-handoff.md`
(masque TCP termination). They are
Owner material and are not modified by the kernel tasks. The concrete blockers
and next steps for the families still deferred by T10 are in
`tool/kernel-compat/evidence/t10-feasibility.json`; T13's handoff covers mieru,
T17's translation authorization is recorded in the T17 handoff, the T17 recipe
(`02-technical-solution.md`) and `evidence/t17-translation.md`; T14's and
T18's cover
`masque` (the CONNECT-UDP subset in `evidence/t14-feasibility.json` and the
CONNECT-IP/WARP UDP path with its `h2`/`h3-l4proxy` gaps in
`evidence/t18-feasibility.json`); T21's covers TCP termination and its named
limits in `evidence/t21-feasibility.json`, and T15's covers
`shadowquic` (the JLS subset and its named rejections). With T15 the T9 list
has an entry for every family, though `masque` and `shadowquic` remain partial;
neither is claimed as compatible.

## Controlled verification commands

```sh
# the differential harness (same fixtures against Mihomo and billow-kernel)
cargo build --release --manifest-path native-kernel/Cargo.toml --locked -p billow-kernel-cli
node tool/kernel-compat/runner.mjs \
  --mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
  --rust native-kernel/target/release/billow-kernel \
  --cache tool/kernel-compat/.cache --report-dir tool/kernel-compat/evidence

# the harness's own acceptance command
node --test tool/kernel-compat/runner.test.mjs

# T25 control API differential (auth, reload, providers, connections, streams,
# Unix socket and TLS controller)
node tool/kernel-compat/t25-differential.mjs \
  --mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
  --rust native-kernel/target/release/billow-kernel \
  --out tool/kernel-compat/evidence/t25-differential.json

# T23 group/selection/health differential (27 cases + persistence)
node tool/kernel-compat/t23-differential.mjs \
  --mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
  --rust native-kernel/target/release/billow-kernel \
  --out tool/kernel-compat/evidence/t23-differential.json

# controlled peers for the families with no Mihomo listener (gost-relay, ssh,
# ssr), the independent Go SSR peers (including the pinned-client cross-check)
# and the pinned SSR cipher vectors; T16 adds the wireguard-go device peer and
# the OpenVPN 2.7.9 binary peer; needs `go`
tool/kernel-compat/family-peers.sh
```

## Platform notes

- macOS arm64 is the platform where sessions and every protocol family were run
  against the pinned Mihomo (T4/T9/T10 evidence in
  `tool/kernel-compat/evidence/protocol-peers.json`). Linux/Android compile
  from the same Unix code path; Windows compiles, but the platform session
  path (TUN/system proxy ownership, no `dup(2)` use anymore) is T6.
- The QUIC families use `quinn` 0.11.12 (quinn-proto 0.11.19, quinn-udp
  0.5.16) with `rustls` 0.23 and TLS 1.3 only. One endpoint and connection are
  created per dial; there is no connection pool yet. The dependency profile is
  recorded in `tool/kernel-compat/evidence/rust-mapping.json` (`quicProfile`)
  and `protocol-peers.json` (`t10`); T7 must measure the whole iOS extension
  against the 40,000,000-byte budget. There is no JLS crate and no
  WireGuard/mesh/OpenVPN crate in the offline cargo cache; `shadowquic`
  implements the JLS seal in-tree and the locked Go package is a vector
  generator only. T16 implements the WireGuard Noise IK/transport in-tree with
  the already-locked `blake2` 0.10.6 (new direct dependency), `x25519-dalek`,
  `chacha20poly1305` and `rand`, and the OpenVPN control/data channel with
  `rustls`+`ring`, `aes-gcm`, `chacha20poly1305`, `hmac`/`sha1` and the MD5
  already in `keys.rs`. Their peer runs are macOS arm64 only (the OpenVPN
  binary is the Homebrew 2.7.9 bottle; the WireGuard peer is built from the
  cached MIT module). The pinned GPL-3.0 adapters were read for option/wire
  facts only; no source is vendored or linked, and the audit plus its
  clean-room limits are in `tool/kernel-compat/evidence/t16-provenance.md`.
  `quinn-proto` and `typenum` are direct dependencies because
  the JLS session wrapper needs `quinn_proto::crypto::Session` and the
  32-byte GCM nonce; both were already in the lockfile. The JLS ClientHello is
  produced by a recorded-random replay of rustls's own hello; if a future
  rustls changes the draw order the replay check aborts the connection with a
  named error instead of sending an unauthenticated request.
- Outbound TLS uses `rustls` with the platform trust store plus configured
  extra roots. `tls: {custom-cert}` roots are process-wide: a second kernel in
  the same process with different roots is rejected instead of silently keeping
  the first anchors.
- The crate builds `crate-type = ["rlib", "staticlib"]`; no Tauri, UIKit or
  NetworkExtension symbols are referenced.
