# T25 — Billow-consumed control interface

Reference: pinned Mihomo **v1.19.34** (`hub/route/*.go`, binary
`tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7`). Implementation:
`native-kernel/crates/billow-kernel/src/controller.rs` with engine hooks in
`engine.rs` (`RuntimeSnapshot`/`SharedRuntime`, `ConnectionRegistry`, live byte
counters) and `config.rs` (`ControllerConfig`, `CorsConfig`).

Machine-readable form: `evidence/t25-controller.json`. Differential:
`evidence/t25-differential.json`.

## Endpoints and status codes

| Endpoint | Methods | Result |
| --- | --- | --- |
| `/` | GET | `{"hello":"mihomo"}` |
| `/version` | GET | `{"meta":false,"version":"<crate>"}` (shape aligned; this is not a pinned-version claim) |
| `/configs` | GET / PATCH / PUT | GET reports `mixed-port`, `tun.enable`, `mode`, `log-level`, `ipv6`, `authentication`, geodata fields; PATCH applies the no-op shapes (`tun.enable:false`) and names real changes as 400; PUT reloads |
| `/proxies` | GET | `DIRECT`/`REJECT`/`REJECT-DROP`, inline proxies and groups; provider nodes stay under `/providers/proxies` like pinned |
| `/proxies/:name` | GET / PUT / DELETE | detail; selector update; clear `url-test`/`fallback` (Selector DELETE is 400) |
| `/proxies/:name/delay` | GET | `timeout` required (400), unknown proxy 404, failed test 503, timeout 504 |
| `/rules` | GET | index/type/payload/proxy/size; pinned `extra` hit counters are not tracked |
| `/connections` | GET / DELETE | live rows with pinned metadata keys, byte counters, chains and rule; DELETE closes one/all; `connections: null` when empty |
| `/providers/proxies` | GET | real proxy providers + `Compatible` group/`default` entries |
| `/providers/proxies/:name` | GET / PUT | update failure is 503 and keeps the old snapshot |
| `/providers/proxies/:name/healthcheck` | GET | provider probe; a Compatible group probes its members in the background and `default` is a 204 no-op |
| `/providers/proxies/:p/:name` | GET / healthcheck | provider node detail/latency; Compatible providers resolve group members and `DIRECT` instead of 404 |
| `/providers/rules` | GET | behavior/format/ruleCount/vehicleType/updatedAt (inline: `format:""` + `payload`) |
| `/providers/rules/:name` | PUT | re-read; 503 on failure with the old snapshot kept |
| `/logs` | GET stream/WS | NDJSON `{type,payload}` (or `format=structured`), level filter; `level` is validated before the 200 stream (`error`/`warning`/`info`/`debug`/`silent`; a bogus level is the pinned 400 `Body invalid`) |
| `/traffic` | GET stream/WS | `{up,down,upTotal,downTotal}` once a second |
| `/memory` | GET stream/WS | `{inuse,oslimit}`; `inuse` is peak RSS via `getrusage` |
| `/configs/geo`, `/upgrade/geo`, `/group`, `/cache`, `/storage`, `/dns/query`, `/restart` | — | explicit 404; registered in `t25-controller.json` |

Unknown paths are the pinned plain-text `404 page not found`; a known path with
another method is 405 plus `Allow`. JSON error bodies are
`{"message":"…"}` with the pinned strings (`Unauthorized`, `Body invalid`,
`Resource not found`, `Timeout`, `An error occurred in the delay test`).

## Auth, CORS and listeners

- `secret`: `Authorization: Bearer <secret>` on TCP/TLS; `?token=` only for a
  WebSocket upgrade (pinned behaviour). Routing resolves before auth, so a 404
  does not require credentials and a 405 does not either.
- A hostless `external-controller: ":9090"` binds all interfaces (`[::]:9090`
  with an IPv4 wildcard fallback), like pinned `net.Listen`. The IPv4-mapped
  acceptance depends on the platform IPv6 default (dual-stack on macOS/Linux;
  Windows defaults to v6-only). A control listener that cannot bind (port in
  use, bad address) publishes `External controller listen error …` to the
  `/logs` bus **and** emits it through `tracing::error!`, so a bare CLI run
  (whose logger is the one-way tracing→bus sink) shows the reason on stderr; the
  listener is skipped and the mixed inbound plus the other control listeners
  keep starting, matching pinned `hub/route.start*`.
- Unix socket: no Bearer secret (pinned starts the Unix router with an empty
  secret); the socket is created `0666` after unlinking a stale path.
- `external-controller-tls`: top-level `tls.certificate`/`tls.private-key`;
  missing/invalid PEMs log an error and skip the TLS listener, like pinned. The
  listener speaks HTTP/1.1 only and advertises only `http/1.1` in ALPN. Pinned
  advertises `["h2","http/1.1"]` because Go's http server also serves h2; this
  router has no HTTP/2 frame layer, so offering h2 made `curl` (default offer
  `h2,http/1.1`) negotiate h2 and then fail with `expected SETTINGS frame`.
- `external-controller-cors`: `allow-origins`/`allow-private-network` defaults
  `["*"]`/`true`; `Vary: Origin` on every response; unauthenticated preflight
  `OPTIONS` returns 200 with `Access-Control-Max-Age: 300`.
- `external-controller-pipe` (Windows) and `external-controller-routing-mark`
  remain named rejections.

## Kernel linkage and reload generations

- Group selection through `PUT /proxies/:group` uses the same
  `SelectionCache` as `--select` (`profile.store-selected`).
- Delay tests dial through the configured proxy chain (including
  `dialer-proxy`), DIRECT/hosts/DNS, or the group's selected member, so a bad
  password/dead server is a real 503.
- Provider update failure reuses T24's swap discipline: the old `Arc` snapshot
  remains live. Provider reads use blocking sockets (`std::net::TcpStream`,
  15s connect / 30s read), so `PUT /providers/{proxies,rules}/:name` and the
  `PUT /configs` build run on `tokio::task::spawn_blocking`; the controller's
  current_thread runtime keeps accepting and answering `/version`, `/proxies`,
  `/connections`, `/traffic` while a provider stalls.
- `PUT /configs` builds providers, geodata, DNS, hosts, groups and rules into a
  new `RuntimeSnapshot`, then swaps it. New sessions take the new generation;
  in-flight sessions keep the old one, so the old rules/providers/DNS objects
  are released when their last session ends (R4). A rejected build never
  touches the live generation.

## Differential result

`node tool/kernel-compat/t25-differential.mjs --mihomo <pinned> --rust
<billow-kernel> --out evidence/t25-differential.json`

49 cases: **47 compared equal, 2 recorded divergences, 0 unexpected**. The
sequence covers auth failures, unknown path/405, CORS preflight, `/configs`
GET/PATCH/PUT reload (success, invalid YAML keeps the old config), proxies
shape/selection/delay, rules, provider list/update success/update failure,
connection list/close, `/traffic` and `/logs` first frames, Unix socket and TLS
listener.

Recorded divergences (not claimed as compatibility):

1. **Listener move on reload** — pinned recreates the mixed listener (204); the
   Rust kernel answers 400 naming `mixed-port`/`bind-address` because it keeps
   one bound listener per process (restart required).
2. **`PATCH /configs {"tun":{"enable":true}}`** — pinned answers 204 and tries
   to create a TUN device; the Rust kernel has no device layer before T6/T7 and
   rejects it by name (400).
3. **TLS ALPN** — pinned offers `["h2","http/1.1"]` and serves both via Go's
   http server; the Rust TLS listener serves HTTP/1.1 only, so it offers only
   `http/1.1`. h2-capable clients now fall back to HTTP/1.1 instead of
   negotiating a protocol whose SETTINGS frame never arrives (T25-A2).

Additional pinned/Rust differences that the differential normalizes or omits
(registered in `t25-controller.json`):

- `/configs` omits pinned General keys the kernel does not honour
  (`unified-delay`, `routing-mark`, `geox-url`, `sniffing`,
  `find-process-mode`, `tcp-concurrent`, keep-alive) instead of fabricating
  defaults.
- `/proxies` omits pinned's `GLOBAL`/`PASS`/`COMPATIBLE` builtin adapters.
- `/rules` has no `extra` hit/miss statistics.
- `/proxies` history is only filled from group health results, not per-URL
  histories.

## Tests run

- `cargo test --manifest-path native-kernel/Cargo.toml --locked --workspace` —
  all default suites green; `tests/controller.rs` 15/15 (8 original + 7
  T25-A2 regressions).
- `tool/kernel-compat/peer-tests.sh` — 66/66 protocol peer cases.
- `node tool/kernel-compat/runner.test.mjs` — 10/10.
- `node tool/kernel-compat/t25-differential.mjs` — 47/49 equal, 2 recorded
  divergences, 0 unexpected (unchanged from T25-A1).

### T25-A2 regression evidence

- **TLS ALPN** (`tls_alpn_advertises_only_http11_and_serves_version`): a rustls
  client offering `["h2","http/1.1"]` negotiates `http/1.1` and receives
  `200 {"meta":false,"version":"0.1.0"}`. Live `curl -skv` against the CLI
  showed `ALPN: curl offers h2,http/1.1`, `ALPN: server accepted http/1.1`,
  `using HTTP/1.x`, `HTTP/1.1 200 OK`; before the fix curl negotiated h2 and
  failed with `expected SETTINGS frame` (code 000).
- **Blocking provider I/O**
  (`provider_update_stall_does_not_freeze_the_control_plane`): the provider URL
  answers once and then holds the update connection without a response. While
  `PUT /providers/proxies/pp` is inside that read, a concurrent
  `GET /version` completes in <1s with 200; the update then returns 503 when
  the fake endpoint closes. Running the same test against the pre-A2 direct
  call would block the current_thread runtime for the read duration.
  `config_reload_stall_does_not_freeze_the_control_plane` repeats this for
  `PUT /configs`: the reload build introduces a stalled http proxy-provider,
  `/version` answers in <1s, and the reload ends as the pinned-style 400 from
  the failed build.
- **`/logs?level=bogus`** returns 400 `Body invalid` before streaming
  (`logs_level_is_validated_before_streaming`; also `warn`/`INFO`, which pinned's
  exact-key mapping rejects).
- **Compatible provider nodes**
  (`compatible_provider_nodes_and_healthchecks_resolve_members`): group member
  detail is 200 and `Sel/n1` / `Sel/DIRECT` / `default/DIRECT` healthchecks
  resolve (dead node yields the delay 503, not 404; DIRECT yields 200 +
  `delay`).
- **Hostless bind** (`hostless_controller_address_binds_all_interfaces`):
  `external-controller: ":PORT"` binds an unspecified address on that port and
  `/version` answers over `[::1]`.
- **Busy control port** (`busy_controller_port_does_not_fail_kernel_start`):
  the kernel starts with the mixed listener live and `controller_addrs().0 ==
  None` when the configured control port is already bound. T5 also added the
  `tracing::error!` mirror so the reason is visible without `/logs`; provider
  generation stamping now happens under the slot write lock
  (`tests/resources.rs::concurrent_provider_updates_stamp_unique_generations`).

Platform: macOS arm64 for every runtime case (TCP, Unix, TLS, reload,
connections, streams). Linux/Android/iOS compile from the same code path but
were not run here; controller ownership on Android/iOS is host work (T6/T7).

## Not covered

- HTTP/2 on the control listener: the TLS ALPN offer is `http/1.1` only, so an
  h2-only client cannot use this listener (pinned serves h2 via Go's http
  server). The REST surface Billow consumes is HTTP/1.1.
- TLS client-certificate auth (`tls.client-auth-type`, `client-auth-cert`,
  `ech-key`) is rejected at load; only server certificates are implemented.
- `external-controller-pipe`, `external-controller-routing-mark`, `external-ui*`
  are explicit named rejections.
- UDP SOCKS5 associations are not individual `/connections` rows (they close
  with the kernel).
- WebSocket client frames (ping/close) are not parsed; the implemented streams
  are server-to-client and `/connections?interval=` WebSocket mode is exercised
  only by the Rust unit path, not the differential.
