# T31 transport closure: anytls security modes, hysteria2, vmess

Baseline: `evidence/t30-option-closure.md` (11 residual rows inside anytls,
hysteria2 and vmess: hy2 6, anytls 2, vmess 3). Matrix:
`evidence/option-matrix.txt` — **289 no-op / 77 implemented / 129 enabled,
0 problems**. Inside the three target families, 9 rows are still
`enabled rust=reject mihomo=accept` (registered residuals, never silent).

## anytls — implemented and verified

| option | implementation | evidence |
| --- | --- | --- |
| `jls-opts` (`username`, `password`) | `src/outbound/jls.rs::tcp_client` builds the rustls ClientHello twice with a recorded randomness stream and replaces the one fill that produced the 32-byte `random` with the AES-256-GCM sealed value (the same derivation the QUIC path uses), byte-checking the replay against the dry ClientHello. `src/outbound/tls_io.rs` drives that `ClientConnection`, verifies the first cleartext ServerHello random before the certificate verifier runs (`JlsVerifier`), and fails the dial if the account did not authenticate (pinned `ErrJLSAuthFailed`). TLS 1.3 only, no resumption (a PSK binder would have to be re-sealed). | `tests/mihomo_peers.rs::anytls_over_jls_reaches_the_receiving_side_through_mihomo`, `...::anytls_over_jls_with_a_wrong_password_never_reaches_the_sink`, `src/outbound/jls.rs::tests::tcp_client_seals_the_serialised_client_hello` |
| `shadow-tls-opts` `version: 1` | The camouflage TLS 1.2 handshake (pinned `MaxVersionTLS12`: the v1 relay cannot follow a TLS 1.3 server flight, which it cannot see as a cleartext `Finished`) is performed over the connection and the raw stream is handed to the AnyTLS framing, exactly like the pinned `DialContextConn` case 1 and `serverV1`. | `tests/mihomo_peers.rs::anytls_over_shadow_tls_v1_reaches_the_receiving_side_through_mihomo`, `...::anytls_over_shadow_tls_v1_with_a_wrong_anytls_password_never_reaches_the_sink` |

Peer shape: a second pinned AnyTLS listener (`certificate`/`private-key`,
`allow-insecure: true`) is the camouflage TLS server; the tested listener
carries `jls-config: {users, sni, dest, proxy: DIRECT}` or
`shadow-tls: {enable, version: 1, password, handshake: {dest, proxy: DIRECT}}`.
The negative cases prove the account check: a wrong JLS password never reaches
the sink (the server falls back to the camouflage host and the client refuses
the dial), and with ShadowTLS v1 (which authenticates nothing itself) a wrong
AnyTLS password never reaches the sink.

## anytls — named residuals (with the observed blocker)

- `shadow-tls-opts` version 2 (**the pinned default**, `version: 0` → 2): the
  v2 client implementation exists (`src/outbound/shadow_tls.rs`: read-hash
  HMAC-SHA1 prefix, application-data framing) but the pinned server rejected the
  first frame (`[ShadowTLS] hashcode mismatch`) in every verification run,
  including with a 250 ms post-handshake drain (which read 0 bytes: our
  read-hash therefore covered exactly the camouflage flight). A client whose
  read-ahead differs from Go's commits to a different HMAC than the server's
  current/previous write hash; until that is pinned down the option stays a
  **named rejection** instead of an unverified accept.
- `shadow-tls-opts` version 3: the account is carried in the ClientHello
  session id and the post-handshake records chain HMAC/kdf state. rustls
  generates the session id internally; rewriting it invalidates the handshake
  transcript, so this needs a ClientHello hook rustls does not expose.
- `restls-opts`, `ech-opts`: unchanged from T30.

## hysteria2 — registered residuals (not implemented this pass)

| option | pinned requirement | gap |
| --- | --- | --- |
| `ports`, `hop-interval` | `sing-quic` dials a random port from the pool and hops the live connection on `hop-interval` (min 5 s, default 30 s) | needs a `quinn::AsyncUdpSocket` wrapper that rewrites the send destination and maps the receive source back to the connection's remote address, plus a connection pool (this kernel creates one QUIC connection per dial) |
| `up` (Brutal) | the pinned client enables Brutal congestion control with `up` as the TX rate | quinn has no Brutal controller; a TX-rate-capped socket reproduces the rate but not Brutal's loss behaviour, so it is not claimed as parity and the option stays rejected |
| `udp-mtu` | MTU of Hysteria's UDP session packets (`0x403` frames with fragmentation headers) | the engine has no Hysteria2 UDP session layer at all (`udp` is already a registered gap), so there is nothing to apply the MTU to |
| `bbr-profile` | `standard`/`conservative`/`aggressive` passed to quic-go's BBR | quinn's `BbrConfig` has no profile selector |
| `realm-opts` | HTTP rendezvous (`/v1/{id}` register, events, heartbeat, connect/connect-response) plus STUN UDP punching; the pinned client lives in the `sing-quic` module, which has no material in this repository | full realm client + STUN punching, no compatible source to derive the wire format from |

`hysteria2 obfs`/`obfs-password`/`ech-opts` stay rejected by both engines
(Mihomo also rejects them), so they are not divergences.

## vmess — registered residuals (not implemented this pass)

| option | pinned requirement | gap |
| --- | --- | --- |
| `mkcp-opts` | `transport/mkcp`: KCP over UDP with a 24-byte header, `seed`-derived AES-128-GCM header obfuscation, `header: none\|srtp\|utp\|wechat-video\|dtls\|wireguard`, MTU/TTI/capacity knobs and a session per stream | a full KCP state machine plus the obfuscation layer and a pinned `mkcp` listener harness |
| `tlsmirror-opts` | `transport/tlsmirror`: a mirror/enrollment service, a record layer with its own AEAD and padding, plus `url`/`enroll`/token configuration | an entire transport (record codec, enrollment, traffic shaping) |
| `mekya-opts` | `transport/mekya`: an HTTP/2-based multiplexer (`url`, `h2-pool-size`, write delay, timeouts) over the VMess stream | an H2 mux client with the pinned pool/delay semantics |

Each stays a named rejection with the field named, so no configuration that
selects a behaviour is silently accepted.

## Verification

- `CARGO_TARGET_DIR=<independent> cargo test --manifest-path native-kernel/Cargo.toml --locked`: all suites pass (168 lib, 50 config, 15 controller, 19 dns, 32 groups, 60 protocols, 32 quic, 15 resources, 11 sessions, 11 cli, 10 family_cli, 1 doc-test; 81 ignored peer cases).
- `tool/kernel-compat/peer-tests.sh`: **81 passed, 0 failed** (the T30 77 plus the four new anytls JLS/ShadowTLS cases) against the pinned Mihomo v1.19.34 binary.
- `node tool/kernel-compat/option-probe.mjs --rust <billow-kernel> --mihomo <mihomo>`: 289 / 77 / 129, 0 problems. Nine target-family rows remain `enabled rust=reject mihomo=accept` (hysteria2 6, vmess 3), all registered here and in `rust-mapping.json`.
- `node --test tool/kernel-compat/runner.test.mjs`: 10 passed.
- Differentials against the same pinned binary: t22 22 pass / 1 skipped / 0 differ; t23 28 pass / 1 persistence / 0 differ (one run under parallel load differed in the known nested-lazy-probe timing case, then matched on a clean run); t24 36 pass / 2 skipped / 0 differ / 6 recorded inbound framing differences; t25 47/49 equal / 2 recorded divergences / 0 unexpected; t5 12/12 scenarios / 0 differ.
