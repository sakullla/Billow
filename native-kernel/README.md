# Billow native Rust kernel

An embeddable proxy engine plus a standalone process entry. No Tauri or other
GUI dependency; the library crate also builds as a `staticlib` so the iOS
Network Extension (T3/T7) can link it directly.

Status after T10: one mixed inbound on the configured address (TCP CONNECT,
SOCKS5 and SOCKS5 `UDP ASSOCIATE`), a strict subset of the clash
configuration, `DIRECT`/`REJECT` and the protocol outbounds below with their
transports and UDP associations. T9 added `vmess` (AEAD header), `snell`
(v1-v3) and `trusttunnel` (TLS + HTTP/2 CONNECT). T11 added `gost-relay`
(relay v2: TCP/TLS/auth/`forward`), `ssh` (password and inline-PEM key auth,
host-key pinning, `direct-tcpip`) and the `ssr` stream-cipher subset
(`protocol: origin`, `obfs: plain`). T10 added the QUIC families `tuic` (v5
`uuid`/`password`), `hysteria` (v1) and `hysteria2` (HTTP/3 auth + TCP), all
over `quinn` 0.11; `shadowquic` (JLS-TLS) and the device families
(`wireguard`, `tailscale`, `zerotier`, `easytier`, `openvpn`) are rejected by
name, with device/TUN ownership assigned to T6/T7. The T10 families are
partial: their gaps are named in [Not implemented](#not-implemented) and in
`tool/kernel-compat/evidence/rust-mapping.json`. `mieru`, `masque` and
`sudoku` remain rejected by name with the decisions recorded below.
**Not implemented yet** (rejected with
`[unsupported]`, never ignored): DNS and `hosts`, proxy groups and providers,
the control API (`external-controller`, `proxy-providers`, rules beyond the
listed types), `tun`/`redir`/`tproxy`, the families listed under
[Protocol families outside this slice](#protocol-families-outside-this-slice),
and the protocol options listed in [Not implemented](#not-implemented). T5 owns
DNS, groups, providers, rules and the control interface.

## Layout

```
native-kernel/
├── Cargo.toml, Cargo.lock          # workspace (resolver 2), lockfile committed
└── crates/
    ├── billow-kernel/              # library (rlib + staticlib)
    │   ├── src/config.rs           # strict YAML/geosite parsing
    │   ├── src/proxies.rs          # strict `proxies:` option tables
    │   ├── src/outbound/           # socks5, http, ss, trojan, vless, anytls, vmess, snell,
    │   │                           # trusttunnel, gost-relay, ssh, ssr + tls, ws, h2
    │   ├── src/keys.rs             # EVP_BytesToKey, HKDF-SHA1, trojan key, uuid
    │   ├── src/rules.rs            # rule set evaluation
    │   ├── src/inbound.rs          # SOCKS5 + HTTP CONNECT handshake, authentication
    │   ├── src/engine.rs           # listener, sessions, bounded relay, lifecycle
    │   ├── src/identity.rs         # uuid / pid / version / listener / config digest
    │   ├── examples/embed.rs       # embedding example
    │   └── tests/                  # config, protocols (loopback peers), sessions,
    │                               # mihomo_peers (pinned Mihomo), common/ helpers
    └── billow-kernel-cli/          # binary `billow-kernel`
        └── tests/cli.rs            # drives the real process: inbound, outbound, restart
```

## Supported configuration

Top-level keys: `mixed-port`, `port` (recorded, does not bind a separate
listener), `socks-port` (legacy alias for `mixed-port`), `allow-lan`,
`bind-address`, `mode: rule`, `log-level`, `authentication`, `tls` (extra
roots only), `proxies`, `rules`.

Rules: `DOMAIN`, `DOMAIN-SUFFIX`, `GEOSITE`, `IP-CIDR`, `IP-CIDR6`, `MATCH`,
with the outbounds `DIRECT`, `REJECT` or the name of a configured proxy, and
the optional `no-resolve` suffix on IP rules. The first matching rule wins;
without a `MATCH` rule the built-in fallback is `DIRECT`, as in Mihomo. The
listener binds `127.0.0.1` unless `allow-lan: true` is set.

`GEOSITE,<key>` / `GEOSITE,<key>/<tag>` read a text database from
`--geosite-dir` (`<key>`, `<key>.yaml`, `<key>.dat` or `<key>.json` in YAML
form) with `domain`, `sub_domain` (literal or a single leading `*.`) and
`domain_keyword` entries. Compiled MRS/protobuf geosite files and other geosite
rule kinds are rejected until T5.

`authentication: ["user:pass", ...]` guards the mixed inbound (SOCKS5 RFC 1929
and HTTP `Proxy-Authorization: Basic`). `tls: {custom-cert: [...], certificate:
<dir>}` adds trust anchors for outbound TLS: they are built into the kernel
instance at start and used by every TLS dial of that instance (the platform
store stays the base, and a second kernel in the same process keeps its own
anchors). `skip-cert-verify: true` accepts any certificate instead (only
`true`; `fingerprint`/`certificate`/`private-key`/`name-cert-verify` are
rejected). The private-CA case is covered by
`tests/protocols.rs::custom_ca_roots_are_installed_for_outbound_tls`.

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
top-level key such as `dns`/`hosts`, or a proxy option such as `tfo`) fails when
its value asks for something; a key the pinned version does not declare at all
is ignored with a warning, exactly as Mihomo's decoder ignores it, so a valid
upstream configuration is not rejected (R2). Errors are categorized by a stable tag: `invalid_yaml`,
`invalid_value`, `unsupported`, plus `bind` and `limits` at start-up. Example:

```
error: [unsupported] unsupported configuration: top-level key 'dns' is not implemented by the Rust kernel slice
error: [unsupported] proxies[0] (name=s1, type=vless): option 'flow' value 'xtls-rprx-vision' is not implemented
```

## Protocol outbounds

Every proxy establishes a real TCP connection to the configured server
(optionally over TLS / WebSocket), performs the handshake and hands a byte
stream to the session. A failed handshake, TLS verification or authentication
aborts the session and the client receives the inbound failure reply. The
identities of the servers are logged as the session exit.

| type | transport options implemented | UDP | verified against the pinned Mihomo |
| --- | --- | --- | --- |
| `socks5` | plain, `tls: true` (+ `sni`, `skip-cert-verify`, `alpn`), RFC 1929 auth | no | `listeners: type: socks` (with users), wrong password |
| `http` | plain, `tls: true`, Basic auth, extra `headers` | no | `listeners: type: http` (with users) |
| `ss` | AEAD 2017 `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305` | `udp: true`: AEAD-2017 datagrams | `listeners: type: shadowsocks`, wrong password (TCP and UDP) |
| `trojan` | TLS, `network: tcp` / `ws` (`ws-opts.path`, `headers`, `v2ray-http-upgrade`) | `udp: true`: `addr|len|CRLF|payload` frames over the TLS stream | `listeners: type: trojan`, wrong password, untrusted certificate (TCP and UDP) |
| `vless` | `tls: true`, `network: tcp` / `ws` (`ws-opts.path`), `encryption: none` | no | `listeners: type: vless` (tcp and `ws-path`), wrong uuid |
| `anytls` | TLS, one stream per connection, protocol version 2 | no | `listeners: type: anytls`, wrong password, untrusted certificate |
| `vmess` | AEAD request header (`alterId: 0`), `cipher: auto`/`aes-128-gcm`/`chacha20-poly1305`/`none`, `tls: true`, `network: tcp`/`ws` (`ws-opts.path`, `headers`), `sni`/`servername` | no | `listeners: type: vmess` (aes-128-gcm, chacha20-poly1305, domain target), wrong uuid |
| `snell` | v1 (chacha20-poly1305) / v2 / v3 (aes-128-gcm), Argon2id KDF, `obfs-opts: {mode: http, host}` | no | `listeners: type: snell` v1/v2/v3, v3 + http obfs, wrong psk |
| `trusttunnel` | TLS + HTTP/2 `CONNECT`, Basic `Proxy-Authorization`, ALPN `h2`, `sni`, `skip-cert-verify` | no | `listeners: type: trusttunnel` (`network: [tcp]`), wrong password |
| `gost-relay` | relay v2 over TCP, `tls: true` (`sni`, `skip-cert-verify`), `username`/`password`, `forward` (no address feature) | no | controlled relay-v2 server (header vectors + auth/forward/TLS/status cases); no Mihomo listener exists |
| `ssh` | password and inline-PEM public-key auth, `private-key-passphrase`, `host-key` pinning, `host-key-algorithms`, one `direct-tcpip` channel per dial | no | controlled `russh` server (password/key/host-key cases); no Mihomo listener exists |
| `ssr` | stream ciphers (`rc4-md5`, `aes-128/192/256-cfb`, `aes-128/192/256-ctr`, `chacha20`, `chacha20-ietf`, `xchacha20`, `none`), `protocol: origin`, `obfs: plain` | no | pinned Go cipher vectors + controlled origin/plain server; no Mihomo listener exists |
| `tuic` | QUIC (`quinn` 0.11, TLS 1.3, ALPN `h3`), v5 `uuid`/`password` authentication via the TLS exporter, one TCP stream per dial, `ip`/`sni`/`skip-cert-verify`/`disable-sni`/`heartbeat-interval`/`request-timeout` | no | `listeners: type: tuic` (users map), wrong password; controlled `quinn` peer for the default suite |
| `hysteria` | QUIC (ALPN `hysteria`), binary control hello (`auth`/`auth-str`, `up`/`down`), one TCP stream per dial | no | controlled `quinn` server implementing the pinned `transport/hysteria/core` framing (no Mihomo listener exists) |
| `hysteria2` | QUIC (ALPN `h3`), HTTP/3 `POST /auth` (status 233), `0x401` TCP request frame, `up`/`down`, `handshake-timeout` | no | `listeners: type: hysteria2` (users map), wrong password |

`dialer-proxy` chains are supported when every hop before the exit is `socks5`
(the hop is entered through the previous hop's SOCKS5 tunnel); any other chain
is rejected at load time or at dial time with a `[unsupported]`/chain error,
never silently bypassed. UDP follows the same rule: a `udp: true` proxy with a
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
| `socks5`, `http`, `vless`, `anytls` | **no association**: `udp: true` is rejected at load time; `udp: false` (or absent) loads, and an association routed to such a proxy drops the datagram and logs it |

`vless` UDP would need `packet-addr`/XUDP, `anytls` needs UoT, and a SOCKS5
outbound would need its own UDP relay: all three are explicit gaps recorded in
`tool/kernel-compat/evidence/rust-mapping.json`, not silent successes.
Fragmented datagrams (`FRAG != 0`) are dropped. Destination names are resolved
with the system resolver because there is no in-kernel DNS before T5 (a
datagram to a name therefore leaves with the resolved address, as Mihomo's
system resolver does). For a chained association the *server* name is resolved
once and the whole address set is kept: a multi-A record (or a server answering
from another of its addresses) is accepted, while a reply from an address the
name did not resolve to is dropped. A resolver that returns only one family
(`AI_ADDRCONFIG` on a host without global IPv6, for example) yields a
single-entry set, which is what this host does for `localhost`. Memory per association is bounded: one 64 KiB client
datagram buffer plus one 64 KiB reply buffer per transport actually used, and
the association ends with its control connection or after
`Limits.udp_idle_timeout` (default 60 s).

### Protocol families outside this slice

The pinned parser lists 28 outbound types. Nine are implemented
(`ss`, `socks5`, `http`, `trojan`, `vless`, `anytls`, `vmess`, `snell`,
`trusttunnel`) and three are partial after T11 (`gost-relay`, `ssh`, `ssr`).
The rest are rejected by name at load time, so no configuration is silently
reduced:

| families | why not here | task / decision |
| --- | --- | --- |
| `mieru` | the pinned outbound wraps the external `enfein/mieru` v3.39.0 module (encrypted underlay, padding, handshake modes, multiplexing); no Rust port exists in this tree | **T11 deferred**: vendor/port the module or keep it explicitly deferred; a partial port would not be wire-compatible |
| `masque` | HTTP/3 CONNECT-IP/CONNECT-UDP with an IP stack (or HTTP/2 capsules); the QUIC/IP-stack dependency profile overlaps T10 | **T11 deferred**: align the QUIC stack with T10/T7 before implementing (the 40 MB budget is measured there) |
| `sudoku` | 13.6k lines of custom crypto/KIP/HTTP-mask/multiplexing in the pinned tree | **T11 deferred**: split into its own task or explicitly defer; a partial port would not be wire-compatible |
| `shadowquic` | QUIC with JLS, a custom TLS extension; the pinned client uses `jls-tls` + a modified `jls-quic-go`. `rustls`/`quinn` cannot express the extension and no JLS crate is in the offline cache | **T10 rejected by name**; implement only with a JLS-capable TLS/QUIC stack |
| `wireguard`, `tailscale`, `zerotier`, `easytier`, `openvpn` | full VPN protocols that terminate a tunnel and expose TCP/UDP through an IP stack (gVisor in the pinned build); device/TUN ownership is T6/T7, and no WireGuard/mesh/OpenVPN crate is in the offline cache | **T10 rejected by name**; device/TUN ownership is T6/T7, the transport would be a separate task |
| `direct`, `dns`, `reject`, `rematch` as `proxies` entries | built-ins of Mihomo; the kernel already has `DIRECT`/`REJECT` rules and no `dns`/`rematch` adapters | **T5** (rules/rematch integration) |

The partial families have their remaining gaps named in
[Not implemented](#not-implemented): `gost-relay` rejects `udp`/`mux`;
`ssh` rejects private-key file paths and opens one SSH client per dial;
`ssr` implements only `protocol: origin` and `obfs: plain` with the stream
ciphers. `ssh` uses `russh` 0.56 with the `ring` backend; `russh` 0.64
requires Rust 1.89 and its default `aws-lc-rs` backend would add a C/CMake
build, so it is not used. `russh` 0.56 declares MSRV 1.85 but its transitive
`home` 0.5.12 declares 1.88 and the Windows-only `pageant` 0.2.5 declares 1.89
(`uuid` 1.29.3 already declared 1.89 in the previous lock), so T11 raised the
workspace `rust-version` to 1.89 instead of shipping an inconsistent MSRV.
`03-execution-plan.md`
defines T9/T11 (non-QUIC), T10 (QUIC and device families) and T5's integration
of their output. The capability index
records the implemented families as `implemented`, the T11 ones as `partial`
with the missing options, and the rest as `unimplemented`; none can be
reported as compatible.

### Not implemented

Every option a proxy entry contains must be one this kernel honours: the
loader reads only implemented keys and rejects the rest with the key named.
With the pinned option tables that means `tfo`, `mptcp`, `interface-name`,
`routing-mark`, `smux`, `udp-over-tcp`, `udp-over-tcp-version`, `ech-opts`,
`shadow-tls-opts`, `restls-opts`, `jls-opts`, `fingerprint`, `certificate`,
`private-key`, `name-cert-verify`, `reality-opts`, `grpc-opts`, `http-opts`,
`h2-opts`, `xhttp-opts`, `ss-opts`, `plugin`/`plugin-opts`, ws early data and
`v2ray-http-upgrade-fast-open`, `client-fingerprint`, `ip-version`, vless
`flow`/`packet-addr`/`xudp`/`packet-encoding`/`ws-headers`, anytls
`client-metadata`/`idle-session-*`/`min-idle-session`/`disable-reuse`, vmess
`alterId > 0`/`packet-addr`/`xudp`/`packet-encoding`/`global-padding`/
`authenticated-length` and the vmess mux/TLS-mirror blocks, snell
`version: 4-6`/`reuse`/`mode`/obfs `tls`, trusttunnel
`udp`/`quic`/`health-check`/`max-connections`/`min-streams`/`max-streams`/
`congestion-controller`/`cwnd`/`bbr-profile`, gost-relay
`udp`/`mux`/`name-cert-verify`/`fingerprint`/`certificate`/`private-key`/
`client-fingerprint`, ssh private-key file paths, ssr
`protocol: auth_sha1_v4/auth_aes128_md5/auth_aes128_sha1/auth_chain_a/auth_chain_b`
and `obfs: http_simple/http_post/random_head/tls1.2_ticket_auth/tls1.2_ticket_fastauth`,
and `udp: true` on
`socks5`/`vless`/`anytls`/`vmess`/`snell`/`trusttunnel`/`gost-relay`/`ssr`
(no UDP association for those families). T10's families reject the options
they do not implement by name: `tuic` `token` (v4/BLAKE3), `udp-relay-mode:
quic`, `udp-over-stream`, `reduce-rtt`, `fast-open`, congestion/window tuning;
`hysteria` `ports`/`hop-interval` (port hopping), `obfs` (XPlus),
`protocol: faketcp|wechat`, `fast-open`, receive-window/MTU tuning;
`hysteria2` `ports`/`hop-interval`, `obfs` (Salamander/Gecko), `realm-opts`,
`udp-mtu`, congestion/window tuning. `shadowquic` and the device families are
rejected as whole types with the missing stack named (JLS-TLS, WireGuard
Noise/IP stack, mesh control planes, OpenVPN), never loaded as if compatible.
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
them without `omitempty`), and its `origin`/`plain` layers ignore their
`*-param` values exactly as the pinned plugins do. Their
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
    [--buffer-bytes N] [--max-sessions N] [--check]
```

`--check` validates the configuration and rule set, starts the listener to prove
the bind, prints the identity and exits. A normal run prints one identity line,
serves until SIGINT/SIGTERM (on Windows the host drives the library API; T6),
then prints a session summary:

```
instance=<uuid> pid=<pid> version=0.1.0 listen=127.0.0.1:17890 overridden_port=- config=sha256:<digest> rules=3 geosite_dir=- state_dir=-
features: mixed-inbound(tcp,http-connect,socks5); rules=inline(3 entries); outbounds=DIRECT,REJECT; protocols=ss1=ss,tj1=trojan,jump=socks5,vl1=vless; dns=none
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
- `Kernel::identity()`, `Kernel::listen_addr()`, `Kernel::stats()`,
  `Kernel::evaluate(host, ip)`, `Kernel::config()`, `Kernel::stop()`.
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

- `tests/config.rs` — parsing, strict option tables, error tags.
- `tests/sessions.rs` — inbound sessions, half-close, stop/restart, limits.
- `tests/quic_peers.rs` — T10 QUIC loopback peers: TUIC v5 (auth token, domain
  and IP targets, wrong password, v4 token rejection, unimplemented options)
  and Hysteria v1 (control hello, `auth-str` and base64 auth, wrong auth,
  port-hopping/XPlus/faketcp rejection, rate validation). The peers are
  `quinn` servers written from the pinned Go framing; they need `openssl` for
  the loopback certificate.
- `tests/protocols.rs` — loopback peers for socks5/http/ss/trojan/vless
  (tcp, websocket, `v2ray-http-upgrade`), trojan websocket, the SOCKS5
  `UDP ASSOCIATE` relay (DIRECT, REJECT and ss datagrams), a private-CA TLS
  case for three families, positive and negative cases, plus the embedded-API
  entry. `vmess`, `snell` and `trusttunnel` have no loopback peer here: their
  wire formats are covered by the Go-pinned unit vectors in
  `src/outbound/{vmess,snell,trusttunnel}.rs` and by the real-peer cases below.
  The T11 families have controlled loopback peers here: `gost-relay` (relay v2
  header/auth/forward/TLS/status), `ssh` (a real `russh` server with password,
  Ed25519 key and pinned-host-key cases) and `ssr` (origin/plain server plus
  pinned Go cipher vectors); they are also the explicit entry point of
  `tool/kernel-compat/family-peers.sh`. `family-peers.sh` additionally builds
  the independent Go SSR server (`tool/kernel-compat/peers/ssr-server`) and
  runs `tests/independent_peers.rs`, so IV/address/framing are checked against
  the pinned `shadowstream` implementation rather than the Rust client code.
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
  cases live in `tests/protocols.rs` and are recorded under
  `controlledPeers` in `tool/kernel-compat/evidence/protocol-peers.json`. The
  CLI crate also drives a real success tunnel through each of the three
  (`crates/billow-kernel-cli/tests/family_cli.rs`), not only a config load.

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
`t13-handoff.md` (mieru and sudoku) and `t14-handoff.md` (masque). They are
Owner material and are not modified by the kernel tasks. The concrete blockers
and next steps for the three deferred families are in
`tool/kernel-compat/evidence/t11-feasibility.json`; the current
`03-execution-plan.md`/`00-state.yaml` still list them under T11, so the
Owner/Runtime must reconcile that with the T13/T14 handoffs.

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

# controlled peers for the families with no Mihomo listener (gost-relay, ssh,
# ssr), the independent Go SSR server and the pinned SSR cipher vectors;
# needs `go`
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
  against the 40,000,000-byte budget. `h3`/`qpack`, JLS, WireGuard, mesh and
  OpenVPN crates are not in the offline cargo cache.
- Outbound TLS uses `rustls` with the platform trust store plus configured
  extra roots. `tls: {custom-cert}` roots are process-wide: a second kernel in
  the same process with different roots is rejected instead of silently keeping
  the first anchors.
- The crate builds `crate-type = ["rlib", "staticlib"]`; no Tauri, UIKit or
  NetworkExtension symbols are referenced.
