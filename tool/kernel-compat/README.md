# Kernel compatibility harness

Differential entry point for T1 (R2): it reads the shipped-kernel manifests, locks the
matching Mihomo v1.19.34 source, indexes its configuration surface, and runs the same fixture
against two explicitly provided kernel executables while recording what a controlled local
endpoint actually received.

## Commands

```sh
# Baseline binary named by src-tauri/desktop-kernel.json (checksum from the manifest)
node tool/kernel-compat/baseline.mjs --json --cache tool/kernel-compat/.cache

# Lock the Android-pinned source commit, verify its archive checksum and build the probe
node tool/kernel-compat/source.mjs --cache tool/kernel-compat/.cache

# Static capability index (fields, protocols, listeners, groups, rules, platforms, unmapped)
node tool/kernel-compat/capability.mjs --cache tool/kernel-compat/.cache \
  --out tool/kernel-compat/evidence/source-capabilities.json

# Rust kernel CLI (workspace member billow-kernel-cli, binary billow-kernel)
cargo build --release --manifest-path native-kernel/Cargo.toml --locked -p billow-kernel-cli

# Differential run; pass each kernel explicitly (repeatable --fixture, --report-name)
node tool/kernel-compat/runner.mjs \
  --mihomo <path-to-mihomo> --rust <path-to-billow-kernel> \
  --cache tool/kernel-compat/.cache --report-dir tool/kernel-compat/evidence \
  --fixture tool/kernel-compat/fixtures/direct-ip.yaml
```

The Rust binary's path follows the cargo target directory: `native-kernel/target/release/billow-kernel`
in a default checkout, or `$CARGO_TARGET_DIR/release/billow-kernel` (for example
`~/.cache/cargo-target/release/billow-kernel`) when that variable is set. The runner never
guesses: pass the built path with `--rust`.

`node --test tool/kernel-compat/runner.test.mjs` is the acceptance command in the execution
plan. It downloads the pinned baseline and source on first use and caches them under
`tool/kernel-compat/.cache/` (gitignored); no source tree or binary is committed.

Exit status: 0 only when every provided engine passes every fixture and the locked-source
reference either passes or is not applicable. A missing engine (for example before T2 ships a
Rust executable) is recorded as `missing`, makes the run exit 2, and is never reported as
compatible.

## Engine command lines

The two engines are called differently; the runner adapts per engine and does not relax any
judgement for either:

| Engine | identity | config test | run | stop |
| --- | --- | --- | --- | --- |
| mihomo | `-v` (banner) | `-t -d <dir> -f <config>` | `-d <dir> -f <config>` | SIGTERM |
| rust (`billow-kernel`) | `--version` | `<config> --check --port <port>` | `<config> --port <port>` | SIGTERM |

The Rust CLI rejects `mixed-port: 0`, so the runner always passes the allocated port with
`--port` as well as writing it into the YAML. A Rust kernel start that fails before listening
is recorded as `startup-failed` with the CLI's own stderr (for example
`[unsupported] unsupported configuration: top-level key 'hosts' is not implemented by the Rust
kernel slice`); that is the coverage gap for T4/T5, never a pass. The Rust CLI accepts only
HTTP CONNECT (a forward GET is rejected with `405`/`unsupported_protocol`), so fixtures for it
use `method: connect`.

## Fixture knobs

- `connect` (default) tunnels GET through HTTP CONNECT; `forward` sends a plain absolute-form
  GET. Each tag host is a valid domain under `probe.invalid`.
- `connect-host`/`connect-port`: the CONNECT authority; use it when a fixture must not
  depend on a hosts entry.
- `forward-host`: the authority for a forward request when the fixture brings its own
  `hosts` table (the runner then leaves that table untouched).
- Both `connect-host` and `forward-host` present: the runner injects no hosts table.
- `reference-only: true`: a request only the locked-source reference sends (it always relays
  to the running echo); kernels skip it, and it is not a pass claim for a kernel.
- `reference-only` requests and REJECT/control expectations are `not-applicable` for the
  reference, which has no rule engine and no controller.
- `request-port`: pins the echo port (used by fixtures whose rule routes a fixed address).

## What a run does

- Each engine gets its own loopback ports, temporary directory and YAML file (the fixture's
  `mixed-port`/`external-controller` are replaced; nothing else is edited).
- Tagged requests are sent to that engine: `connect` (HTTP CONNECT through the mixed inbound)
  or `forward` (plain absolute-form GET). Each tag host is a valid domain mapped by the
  fixture `hosts` entry to the loopback echo, so the echo's receipt of the same tag proves
  the request crossed the engine and reached the controlled endpoint.
- Config rejection is checked with the engine's own config test, and the locked source's
  parser must agree; a divergence is reported instead of a silent pass.
- Children are stopped with SIGTERM then SIGKILL, the listening port must be released, and
  the temporary directory is removed. Failures, timeouts and missing markers are recorded
  with a category, never converted into a pass.

## Reference scope

The reference is a probe built from the locked source (`probe/src/main.go`). It uses the
pinned parser for config acceptance and item parsing, and a small mixed-inbound replica that
relays one TCP session to the echo. It has no rule engine and no controller, so REJECT cases
and control-API cases are reported as `not-applicable` rather than as passes.

## Coverage boundary

Covered by the current fixtures: config acceptance/rejection, HTTP CONNECT and forward
requests on the mixed inbound through a hosts-mapped DIRECT exit, an address-routed CONNECT
accepted by both engines, REJECT, selector switching through the control API, and unknown
proxy targets. A valid configuration using `hosts`, `proxies`/`proxy-groups`, `lan-allowed-ips`
and a forward request (`fixtures/full-config.yaml`) is accepted by Mihomo and rejected by the
current Rust slice with `[unsupported]`; the report keeps that difference as an open gap.

Not covered: SOCKS5 inbound and UDP, remote proxy peers and handshakes, DNS answer contents,
rule families beyond the fixtures, TUN/system-proxy takeover, other platforms, and the Rust
side until a kernel executable is provided by a later task. The capability index also keeps
every free-form field and platform-only construct under `unmapped`; T1 records the baseline,
so no entry is claimed as compatible.
