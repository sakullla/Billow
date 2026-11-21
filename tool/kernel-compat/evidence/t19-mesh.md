# T19 mesh protocol adapters: scope, peers, dependencies and boundaries

Task: `2026-11-20-native-rust-kernel#T19`. Scope: `tailscale`, `zerotier` and
`easytier` protocol/configuration adapters. Platform for every result below:
macOS arm64, 2026-11-22. Device/TUN and the userspace IP stack remain T6/T7;
EasyTier's controller/DNS integration remains T5.

## Tailscale

Implemented in `native-kernel/crates/billow-kernel/src/outbound/tailscale.rs`:

* control-base transport: Noise `IK_25519_ChaChaPoly_BLAKE2s`, the
  `Tailscale Control Protocol v<version>` prologue, the 101-byte initiation,
  51-byte response and 4096-byte record framing with the 12-byte nonce
  (four zero bytes then a big-endian counter);
* the `POST /ts2021` HTTP/1.1 upgrade with `X-Tailscale-Handshake`, followed by
  an HTTP/2 request over the Noise stream (`/machine/map` in the test);
* DERP: `DERP🔑` server-key greeting, NaCl-boxed `ClientInfo`, frame header,
  ping/pong and send/recv packet frames.

The pinned option table (`hostname`, `auth-key`, `control-url`, `state-dir`,
`ephemeral`, `udp`, `accept-routes`, `exit-node`, `exit-node-allow-lan-access`)
is parsed and validated. The control server key is not a pinned option (the
real client learns it from the control-plane DNS record), so the library API
takes it as a parameter. Basic socket-shaping options and `dialer-proxy` are
rejected with the T6/T7 boundary.

Verification (controlled peer `tool/kernel-compat/peers/tailscale-peer`, built
from the locked BSD-3-Clause `github.com/metacubex/tailscale` module):

```sh
KC_TAILSCALE_PEER_BIN=... cargo test --manifest-path native-kernel/Cargo.toml \
  --locked --test mesh_peers -- --ignored --test-threads=1
# tailscale_control_noise_and_http2 ... ok
# tailscale_derp_greeting_and_ping ... ok
```

`tailscale_control_noise_and_http2` proves the Noise handshake and an HTTP/2
200 response; a wrong control key fails in the handshake. The DERP case checks
the greeting, the boxed client info, ping/pong, a send-packet echo and a wrong
server-key rejection.

## ZeroTier

Implemented in `native-kernel/crates/billow-kernel/src/outbound/zerotier.rs`:

* identity: 40-bit address proof of work over the combined X25519 + Ed25519
  public key (2 MiB Salsa20/20 memory-hard hash), the
  `address:0:public[:private]` text form, binary form, validation and the
  48-byte X25519 agreement secret;
* planet/moon parsing (world type, timestamp, update key, signature, roots,
  tagged IPv4/IPv6 endpoints, moon dictionary);
* VL1 packet framing, Salsa20/12 + Poly1305 armor, protocol-13 extended HELLO
  armor (AES-256-CTR) and the secondary HELLO field stream;
* HELLO/OK, WHOIS/ECHO builders and the VL2 `VerbFrame` payload
  (`network id | ethertype | payload`).

The pinned option table is parsed: `network`, `state-dir`, `identity-secret`,
`planet`, `mtu`, `physical-mtu`, `udp`, `low-bandwidth`, `encrypted-hello`,
`primary-port`, `secondary-port`, `tcp-fallback-mode`, `tcp-fallback-relay` and
`orbit`. An explicit `ip-stack`, `remote-dns-resolve`/`dns` and remote trace
are rejected with the T6/T7/T5 boundary. The controller membership exchange is
T5; the packet transport is available to T6/T7.

Verification (controlled peer `tool/kernel-compat/peers/zerotier-peer`, using
the locked MPL-2.0 `github.com/metacubex/zerotier-go` parser/armor):

```sh
KC_ZEROTIER_PEER_BIN=... cargo test ... --test mesh_peers -- --ignored
# zerotier_hello_success_and_failure ... ok
```

The peer parses the Rust HELLO with the pinned packet/identity code, verifies
the address proof of work and the MAC, and builds the OK with the pinned armor.
The test covers a successful HELLO/OK, a wrong-key OK (client authentication
failure) and a truncated reply (client timeout).

## EasyTier

Implemented in `native-kernel/crates/billow-kernel/src/outbound/easytier.rs`:

* the peer-manager frame: little-endian total length, big-endian source and
  destination peer ids, type/flags/version, little-endian body length;
* `HandshakeRequest` (magic `0xd1e1a5e1`, peer id, version,
  `liveness-echo-v1`, network name, network-secret digest);
* the `PeerManagerHeader` protobuf for data/route packets;
* type 4/5 PingPong.

The cleartext host/discovery path is what the pinned core uses when
`enable_encryption` is false. The secure-datagram path (AES-GCM/ChaCha20 and
Noise XX) is rejected at load with the missing wasm-only layer named.

Verification:

```sh
KC_EASYTIER_PEER_BIN=... cargo test ... --test mesh_peers -- --ignored
# easytier_cleartext_handshake_and_authentication ... ok
# easytier_pinned_core_rejects_a_non_matching_digest ... ok
```

`easytier_cleartext_handshake_and_authentication` uses the controlled protobuf
peer: success, wrong-secret rejection and an explicit `-reject` boundary.
`easytier_pinned_core_rejects_a_non_matching_digest` runs the pinned wasm core
with `enable_encryption=false`, completes the cleartext reply, and records the
core resetting the connection because its `network_secret_digest` is derived
inside the wasm artifact by a routine that is not in the public source tree.
This is an explicit boundary, not a claim that the encrypted/authenticated
EasyTier path is compatible.

## Offline dependency and licence decisions

* No `tailscale`, `zerotier` or `easytier` Rust crate is in the offline cargo
  cache. The implementation uses crates already in `Cargo.lock`:
  `x25519-dalek` 2, `ed25519-dalek` 2.2, `salsa20` 0.10, `poly1305` 0.8,
  `blake2` 0.10, `chacha20poly1305` 0.10, `hmac` 0.12, `sha2` 0.10,
  `aes` 0.8 and `ctr` 0.9, plus the existing `h2`/`http` for the control
  request. No dependency was downloaded.
* The locked Go module cache has `github.com/metacubex/tailscale`
  (BSD-3-Clause), `github.com/metacubex/zerotier-go` (MPL-2.0) and
  `github.com/easytier/easytier/easytier-go` (LGPL-3.0, wasm core). They are
  built only as controlled test peers; no Go or wasm code is vendored, linked
  or translated into the Rust kernel.
* `tailscale` and `zerotier` protocol facts came from the public protocol
  descriptions and black-box packet captures; `easytier` framing/protobuf came
  from the pinned generated protobuf schema and captures of the pinned core.
  The no-copy audit is `find native-kernel -name '*.go'` = 0 and no wasm file
  under `native-kernel/`.

## Boundaries

* `dial()` for all three families refuses with the T6/T7 IP-stack/TUN gap. The
  protocol objects (`TailscaleControl`, `DerpClient`, `zerotier::handshake`,
  `EasytierSession`) are the interfaces for that layer.
* Tailscale `state-dir`/`auth-key`/`accept-routes`/`exit-node` shape the control
  plane; node registration and the WireGuard data path are not run here.
* ZeroTier's controller membership/config, TCP fallback relay and DNS resolver
  are not implemented (T5/T6/T7); `encrypted-hello` uses protocol-13 extended
  armor but the surrounding node/path machinery is T6/T7.
* EasyTier's secure datagram/Noise path, KCP/QUIC proxies, private mode,
  exit nodes, DNS and key material are rejected by name. The pinned core's
  digest derivation gap is recorded above.
