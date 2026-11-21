# Billow native Rust kernel

An embeddable proxy engine plus a standalone process entry. No Tauri or other
GUI dependency; the library crate also builds as a `staticlib` so the iOS
Network Extension (T3/T7) can link it directly.

Status after T4: one mixed inbound on the configured address (TCP CONNECT,
SOCKS5 and SOCKS5 `UDP ASSOCIATE`), a strict subset of the clash
configuration, `DIRECT`/`REJECT` and the protocol outbounds below with their
transports and UDP associations. **Not implemented yet** (rejected with
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
    │   ├── src/outbound/           # socks5, http, ss, trojan, vless, anytls + tls, ws
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

Errors are categorized by a stable tag: `invalid_yaml`, `invalid_value`,
`unsupported`, plus `bind` and `limits` at start-up. Example:

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

`dialer-proxy` chains are supported when every hop before the exit is `socks5`
(the hop is entered through the previous hop's SOCKS5 tunnel); any other chain
is rejected at load time or at dial time with a `[unsupported]`/chain error,
never silently bypassed.

### UDP

The mixed inbound serves SOCKS5 `UDP ASSOCIATE`: the reply names the relay
socket, each datagram carries the RFC 1928 address header, and every datagram
is evaluated by the same rule set as TCP before it is forwarded. Per family:

| family | UDP behaviour |
| --- | --- |
| `DIRECT` / `REJECT` | forwarded from one unconnected UDP socket per address family (wildcard-bound, so a loopback listener still reaches remote targets) / dropped before any socket |
| `ss` with `udp: true` | AEAD-2017 datagrams to the server, replies decrypted and returned with their source address |
| `trojan` with `udp: true` | command `3` over TLS, `addr|length|CRLF|payload` frames both ways |
| `socks5`, `http`, `vless`, `anytls` | **no association**: `udp: true` is rejected at load time; `udp: false` (or absent) loads, and an association routed to such a proxy drops the datagram and logs it |

`vless` UDP would need `packet-addr`/XUDP, `anytls` needs UoT, and a SOCKS5
outbound would need its own UDP relay: all three are explicit gaps recorded in
`tool/kernel-compat/evidence/rust-mapping.json`, not silent successes.
Fragmented datagrams (`FRAG != 0`) are dropped. Destination names are resolved
with the system resolver because there is no in-kernel DNS before T5 (a
datagram to a name therefore leaves with the resolved address, as Mihomo's
system resolver does). Memory per association is bounded: one 64 KiB client
datagram buffer plus one 64 KiB reply buffer per transport actually used, and
the association ends with its control connection or after
`Limits.udp_idle_timeout` (default 60 s).

### Protocol families outside this slice

The pinned parser lists 28 outbound types; this slice implements six
(`ss`, `socks5`, `http`, `trojan`, `vless`, `anytls`). The rest are rejected by
name at load time, so no configuration is silently reduced, but they are still
a compatibility gap for R2 and need an owner:

| families | why not here | proposed owner |
| --- | --- | --- |
| `vmess`, `ssr`, `snell`, `ssh`, `mieru` | separate handshakes/muxes with their own tests and peer fixtures; VMess alone needs AEAD header, alterId-free protocol and an MD5-of-UUID user id | T4 follow-up (the T4 goal says "complete the proxy protocols at the pinned version") or a new protocol task before T8 |
| `hysteria`, `hysteria2`, `tuic`, `shadowquic` | QUIC-based transports (`quinn`/QUIC stack, congestion, UDP relay); a different dependency and memory profile | T4 follow-up, ideally after T7 measures the QUIC stack against the 40 MB budget |
| `wireguard`, `tailscale`, `zerotier`, `easytier`, `openvpn` | full VPN protocols with their own device/TUN ownership; they also overlap T6's takeover work | T6/T7 (they need the tunnel ownership model), or a dedicated task |
| `masque`, `trusttunnel`, `gost-relay`, `sudoku` | newer pinned transport variants without a stable public interop fixture in this repository | T4 follow-up with a pinned fixture per family |
| `direct`, `dns`, `reject`, `rematch` as `proxies` entries | built-ins of Mihomo; the kernel already has `DIRECT`/`REJECT` rules and no `dns`/`rematch` adapters | T5 (groups/rules/rematch) |

The capability index records each of them as `unimplemented` with this note, so
they cannot be reported as compatible. T5's scope in the execution plan covers
DNS, groups, providers, rules and the control interface, not these protocol
families; deciding whether they extend T4 or move to another task is an owner
decision, recorded as a concern on this task.

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
`client-metadata`/`idle-session-*`/`min-idle-session`/`disable-reuse`, and
`udp: true` on `socks5`/`vless`/`anytls` (no UDP association for those
families). `udp: false` is accepted for those families because it states the
same thing this kernel does; `udp` is not a Mihomo HTTP option at all and is
rejected there. Unsupported protocol types are listed in the error message.

The rule is mechanical: `reject_unknown` accepts only keys the parser read and
honoured, so a new option cannot be "documented as rejected" while being let
through by an option table. The only keys accepted without an effect are
boolean no-ops that ask for nothing (`udp: false`, `disable-reuse: false`,
`packet-addr: false`, `xudp: false`, `v2ray-http-upgrade-fast-open: false`);
their `true` form fails with the key named. `tool/kernel-compat/option-probe.mjs`
probes every rejected key through the CLI's own `--check` and records the
result in `tool/kernel-compat/evidence/option-rejection.txt`.

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
- `tests/protocols.rs` — loopback peers for socks5/http/ss/trojan/vless
  (tcp, websocket, `v2ray-http-upgrade`), trojan websocket, the SOCKS5
  `UDP ASSOCIATE` relay (DIRECT, REJECT and ss datagrams), a private-CA TLS
  case for three families, positive and negative cases, plus the embedded-API
  entry.
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
  summarised in `tool/kernel-compat/evidence/protocol-peers.json`.

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
```

## Platform notes

- macOS arm64 is the platform where sessions and every protocol family were run
  against the pinned Mihomo (T4 evidence in
  `tool/kernel-compat/evidence/protocol-peers.json`). Linux/Android compile
  from the same Unix code path; Windows compiles, but the platform session
  path (TUN/system proxy ownership, no `dup(2)` use anymore) is T6.
- Outbound TLS uses `rustls` with the platform trust store plus configured
  extra roots. `tls: {custom-cert}` roots are process-wide: a second kernel in
  the same process with different roots is rejected instead of silently keeping
  the first anchors.
- The crate builds `crate-type = ["rlib", "staticlib"]`; no Tauri, UIKit or
  NetworkExtension symbols are referenced.
