# T19 mesh protocol adapters: scope, peers, dependencies and boundaries

Task: `2026-11-20-native-rust-kernel#T19`. Scope: `tailscale`, `zerotier` and
`easytier` protocol/configuration adapters. Platform for every result below:
macOS arm64, 2026-11-22. Device/TUN and the userspace IP stack remain T6/T7;
EasyTier's controller/DNS integration remains T5.

## Tailscale (partial)

Implemented in `native-kernel/crates/billow-kernel/src/outbound/tailscale.rs`:

* control-base transport: Noise `IK_25519_ChaChaPoly_BLAKE2s`, the
  `Tailscale Control Protocol v<version>` prologue, the 101-byte initiation,
  51-byte response and 4096-byte record framing with the 12-byte nonce
  (four zero bytes then a big-endian counter);
* the `POST /ts2021` HTTP/1.1 upgrade with `X-Tailscale-Handshake`, followed by
  an HTTP/2 request over the Noise stream (`/machine/map` in the test);
* DERP: `DERP🔑` server-key greeting, NaCl-boxed `ClientInfo`, frame header,
  ping/pong and send/recv packet frames.

The control server key is not a pinned option (the real client learns it from
the control-plane DNS record), so the library API takes it as a parameter.
`control-url` is used by the protocol layer. Node registration and
control-plane preferences are not implemented: `hostname`, `auth-key`,
`state-dir`, `ephemeral`, `accept-routes: true`, `exit-node` and
`exit-node-allow-lan-access: true` are rejected at load with the missing
registration named. Basic socket-shaping options and `dialer-proxy` are
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

## ZeroTier (partial)

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
`orbit`. An explicit `ip-stack`, `remote-dns-resolve`/`dns`, remote trace and
the TCP fallback transport (`tcp-fallback-mode: force` or a non-empty
`tcp-fallback-relay`) are rejected with the T6/T7/T5 boundary; `auto`/`disable`
with an empty relay asks for no transport and still loads. The controller
membership exchange is T5; the packet transport is available to T6/T7.

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

## EasyTier (T20: cleartext translated)

T19 rejected EasyTier because its cleartext `network_secret_digest` did not
interoperate. T20 translated the locked LGPL-3.0-or-later source for the
cleartext host/discovery path: the real `DefaultHasher` digest, 16-byte
little-endian peer-manager frame, `HandshakeRequest`, `PeerManagerHeader` and
PingPong are in `native-kernel/crates/billow-kernel/src/outbound/easytier.rs`
and verified against the pinned wasm core with `enable_encryption=false`. The
secure-datagram/Noise XX layer remains unimplemented and
`enable-encryption: true`/secure mode are rejected at load. See
`evidence/t20-easytier.md`. No EasyTier compatibility is claimed for the
secure/encrypted path; device/TUN remains T6/T7.

## Offline dependency and licence decisions

* No `tailscale`, `zerotier` or `easytier` Rust crate is in the offline cargo
  cache. T20 translated EasyTier from the locked upstream source under
  LGPL-3.0-or-later; see `evidence/t20-easytier.md`. The implementation uses crates already in `Cargo.lock`:
  `x25519-dalek` 2, `ed25519-dalek` 2.2, `salsa20` 0.10, `poly1305` 0.8,
  `blake2` 0.10, `chacha20poly1305` 0.10, `hmac` 0.12, `sha2` 0.10,
  `aes` 0.8 and `ctr` 0.9, plus the existing `h2`/`http` for the control
  request. No dependency was downloaded.
* The locked Go module cache has `github.com/metacubex/tailscale`
  (BSD-3-Clause) and `github.com/metacubex/zerotier-go` (MPL-2.0). They are
  built only as controlled test peers; no Go code is vendored, linked or
  translated into the Rust kernel. The EasyTier Go module (LGPL-3.0) is used
  only as a test fixture for the T20 cleartext translation.
* `tailscale` and `zerotier` protocol facts came from the public protocol
  descriptions and black-box packet captures. The no-copy audit is
  `find native-kernel -name '*.go'` = 0 and no wasm file under `native-kernel/`.

## Boundaries

* `dial()` for both loadable families refuses with the T6/T7 IP-stack/TUN gap.
  The protocol objects (`TailscaleControl`, `DerpClient`,
  `zerotier::handshake`) are the interfaces for that layer.
* Tailscale registration/state persistence and control-plane prefs are rejected
  by name; the WireGuard data path is not run here.
* ZeroTier's controller membership/config, TCP fallback relay, DNS resolver and
  real TCP/UDP exits are not implemented (T5/T6/T7); `encrypted-hello` uses
  protocol-13 extended armor but the surrounding node/path machinery is T6/T7.
* EasyTier's cleartext host/discovery path is implemented under LGPL; secure
  datagram/Noise and the device/TUN path are not.
