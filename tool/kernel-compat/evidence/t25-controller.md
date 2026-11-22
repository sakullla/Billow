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
| `/providers/proxies/:name/healthcheck` | GET | provider probe |
| `/providers/proxies/:p/:name` | GET / healthcheck | provider node detail/latency |
| `/providers/rules` | GET | behavior/format/ruleCount/vehicleType/updatedAt (inline: `format:""` + `payload`) |
| `/providers/rules/:name` | PUT | re-read; 503 on failure with the old snapshot kept |
| `/logs` | GET stream/WS | NDJSON `{type,payload}` (or `format=structured`), level filter |
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
- Unix socket: no Bearer secret (pinned starts the Unix router with an empty
  secret); the socket is created `0666` after unlinking a stale path.
- `external-controller-tls`: top-level `tls.certificate`/`tls.private-key`;
  missing/invalid PEMs log an error and skip the TLS listener, like pinned.
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
  remains live.
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

- `cargo test --manifest-path native-kernel/Cargo.toml --locked` — all default
  suites green (including new `tests/controller.rs`, 8/8).
- `tool/kernel-compat/peer-tests.sh` — 66/66 protocol peer cases.
- `node tool/kernel-compat/runner.test.mjs` — 10/10.
- `node tool/kernel-compat/t25-differential.mjs` — 47/49 equal, 2 recorded
  divergences.

Platform: macOS arm64 for every runtime case (TCP, Unix, TLS, reload,
connections, streams). Linux/Android/iOS compile from the same code path but
were not run here; controller ownership on Android/iOS is host work (T6/T7).

## Not covered

- TLS client-certificate auth (`tls.client-auth-type`, `client-auth-cert`,
  `ech-key`) is rejected at load; only server certificates are implemented.
- `external-controller-pipe`, `external-controller-routing-mark`, `external-ui*`
  are explicit named rejections.
- UDP SOCKS5 associations are not individual `/connections` rows (they close
  with the kernel).
- WebSocket client frames (ping/close) are not parsed; the implemented streams
  are server-to-client and `/connections?interval=` WebSocket mode is exercised
  only by the Rust unit path, not the differential.
