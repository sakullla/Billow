# Billow native Rust kernel — first slice (T2)

An embeddable proxy engine plus a standalone process entry. No Tauri or other
GUI dependency; the library crate also builds as a `staticlib` so the iOS
Network Extension (T3/T7) can link it directly.

This is the first running slice, intentionally narrow: one mixed inbound on
localhost, a strict subset of the clash configuration, and one rule decision
(`DIRECT` / `REJECT`). Protocol outbounds (T4), DNS, proxy groups, providers and
the control API (T5) are **not** implemented here. Anything outside the subset
fails configuration loading with an explicit error instead of being ignored.

## Layout

```
native-kernel/
├── Cargo.toml, Cargo.lock          # workspace (resolver 2), lockfile committed
└── crates/
    ├── billow-kernel/              # library (rlib + staticlib)
    │   ├── src/config.rs           # strict YAML/geosite parsing
    │   ├── src/rules.rs            # rule set evaluation
    │   ├── src/inbound.rs          # SOCKS5 + HTTP CONNECT handshake, one port
    │   ├── src/engine.rs           # listener, sessions, bounded relay, lifecycle
    │   ├── src/identity.rs         # uuid / pid / version / listener / config digest
    │   ├── examples/embed.rs       # embedding example
    │   └── tests/                  # config + end-to-end session tests (common/ holds helpers)
    └── billow-kernel-cli/          # binary `billow-kernel`
        └── tests/cli.rs            # drives the real process, SIGINT, restart
```

## Supported configuration

Top-level keys: `mixed-port`, `port` (recorded, does not bind a separate
listener), `socks-port` (legacy alias for `mixed-port`), `allow-lan`,
`bind-address`, `mode: rule`, `log-level`, `rules`.

Rules: `DOMAIN`, `DOMAIN-SUFFIX`, `GEOSITE`, `IP-CIDR`, `IP-CIDR6`, `MATCH`,
with outbounds `DIRECT` / `REJECT` and the optional `no-resolve` suffix on IP
rules. The first matching rule wins; without a `MATCH` rule the built-in
fallback is `DIRECT`, as in Mihomo. The listener binds `127.0.0.1` unless
`allow-lan: true` is set.

`GEOSITE,<key>` / `GEOSITE,<key>/<tag>` read a text database from
`--geosite-dir` (`<key>`, `<key>.yaml`, `<key>.dat` or `<key>.json` in YAML
form) with `domain`, `sub_domain` (literal or a single leading `*.`) and
`domain_keyword` entries. Compiled MRS/protobuf geosite files and other geosite
rule kinds are rejected until T5.

Example:

```yaml
mixed-port: 17890
allow-lan: false
mode: rule
log-level: info
rules:
  - DOMAIN,blocked.example,REJECT
  - DOMAIN-SUFFIX,ads.example,REJECT
  - GEOSITE,test,REJECT
  - IP-CIDR,10.0.0.0/8,REJECT,no-resolve
  - MATCH,DIRECT
```

Errors are categorized by a stable tag: `invalid_yaml`, `invalid_value`,
`unsupported`, plus `bind` and `limits` at start-up. Examples:

```
error: [unsupported] unsupported configuration: top-level key 'dns' is not implemented by the Rust kernel slice
error: [unsupported] unsupported configuration: rules[0] ('GEOIP,CN,DIRECT'): rule type 'GEOIP'
```

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
instance=<uuid> pid=<pid> version=0.1.0 listen=127.0.0.1:17890 overridden_port=- config=sha256:<digest> rules=2 geosite_dir=- state_dir=-
features: mixed-inbound(tcp,http-connect,socks5); rules=inline(2 entries); outbounds=DIRECT,REJECT; protocols=none; dns=none
stopped instance=<uuid> accepted=4 active=0 completed=2 rejected=2 failed=0 bytes_up=40 bytes_down=40
```

SIGINT stops accepting, closes live tunnels and joins every session task before
the process exits, so a restart can immediately rebind the same port.

The full reproducible command for either crate:

```sh
cargo test --manifest-path native-kernel/Cargo.toml --locked
cargo run  --manifest-path native-kernel/Cargo.toml --locked -p billow-kernel-cli -- <config.yaml>
```

## Library API

```rust
use billow_kernel::{Kernel, Limits};

let yaml = "mixed-port: 17890\nrules:\n  - 'MATCH,DIRECT'\n";
let (mut kernel, warnings) = Kernel::start_from_yaml(yaml, None, Limits::default())?;
println!("{}", kernel.identity().to_line());   // uuid, pid, version, listen, digest
let (action, rule) = kernel.evaluate("example.com", None);
kernel.stop()?;                                // no live sessions or tasks remain
```

Stable entry points:

- `Kernel::start(path, geosite_dir, limits)` / `Kernel::start_from_yaml(yaml, geosite_dir, limits)`
  / `Kernel::start_with_yaml(&LoadedConfig, geosite_dir, limits)` — the last one
  lets a host adjust the listener before binding and keeps the warnings.
- `Kernel::identity()`, `Kernel::listen_addr()`, `Kernel::stats()`,
  `Kernel::evaluate(host, ip)`, `Kernel::stop()`.
- `load_config` / `parse_rule` for validation without starting.
- `Limits { buffer_size, max_sessions, handshake_timeout, dial_timeout, half_close_timeout }`.

`Drop` stops a kernel that was not stopped explicitly; `stop()` is synchronous
and waits for the listener thread and all session tasks.

`examples/embed.rs` shows the same path a host (or the iOS extension) takes:
`cargo run -p billow-kernel --example embed -- <config.yaml>`.

## Resource and concurrency invariants

- One fixed buffer per relay direction (`buffer_size`, default 16 KiB) and at
  most `max_sessions` sessions (default 256). Further connections stay in the
  listening backlog until a slot frees.
- A tunnel ends when both directions finish; EOF is forwarded as a write-side
  shutdown (half-close). If the second direction stalls after the first ends, it
  is cut after `half_close_timeout` (default 30 s) so no session waits forever.
- Handshake and dial have their own deadlines. Handshake failures reply to the
  client (SOCKS5 reply code / HTTP status) before the socket closes.
- Every accepted connection increments `active` and decrements it exactly once;
  `stop()` joins all session tasks, so `active == 0` afterwards.

## Platform notes

- macOS arm64 is the verified platform (`cargo test` runs real loopback
  listeners). Linux/Android compile from the same Unix code path; Windows
  compiles, but the relay's socket duplication (`dup(2)`) has no Windows
  implementation yet, so sessions fail explicitly with 502 until T6 provides
  the platform path. No macOS-only dependency is used.
- The crate builds `crate-type = ["rlib", "staticlib"]`; no Tauri, UIKit or
  NetworkExtension symbols are referenced.
