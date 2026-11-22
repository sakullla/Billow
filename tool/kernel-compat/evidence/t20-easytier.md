# T20 EasyTier translation (LGPL-3.0-or-later)

Task: `2026-11-20-native-rust-kernel#T20`. Platform: macOS arm64, 2026-11-22.
Owner-authorized translation of the locked EasyTier source.

## Source and license

The Go module `github.com/easytier/easytier/easytier-go`
`v0.0.0-20261111015056-2abb1676b475` embeds a wasm core whose provenance file
names commit `5f1eaa7c9f9d3e89e9b75a6d87531a436fae40c4`. That commit is not in
the public GitHub history, so the translation was made from the public
`EasyTier/EasyTier` `main` tree (same `easytier-core` layout) and verified
against the pinned wasm binary. The upstream license is LGPL-3.0-or-later; the
full text is committed at `native-kernel/third_party/EasyTier-LGPL-3.0.txt`.

Translated file and sources:

| Rust file | upstream source |
| --- | --- |
| `native-kernel/crates/billow-kernel/src/outbound/easytier.rs` | `easytier-core/src/config/mod.rs` (`generate_digest_from_str`/`network_secret_digest`), `easytier-core/src/packet/mod.rs` (`PeerManagerHeader`, `TCPTunnelHeader`, `PacketType`, `DefaultEndian = LittleEndian`), `easytier-core/src/peers/conn/peer_conn.rs` (cleartext `HandshakeRequest`), `easytier-core/src/peers/conn/peer_conn_ping.rs` (Ping/Pong) |

The Rust file carries an `SPDX-License-Identifier: LGPL-3.0-or-later` header and
the workspace is distributed as GPL-3.0-only (the sudoku translation already
requires that). No upstream Go/wasm code is vendored or linked into the kernel;
`tool/kernel-compat/peers/easytier-peer` runs the locked wasm core as a
test-only fixture.

## What was wrong in T19

T19 used `SHA-256(secret)` for `network_secret_digest` and a controlled peer
that used the same placeholder, so it passed without interop. The locked source
uses `std::collections::hash_map::DefaultHasher` (SipHash-1-3 with zero keys):

```text
h = DefaultHasher::new()
h.write(network_name)
h.write(network_secret)
for i in 0..4:
    digest[i*8..(i+1)*8] = h.finish().to_be_bytes()
    h.write(digest[..(i+1)*8])
```

Known vectors from the pinned core's cleartext captures:

* `("capprobe", "test")` -> `5e7befbd5bcab40df260b8b9f03230e014a13608a8dfd2a477d0c360a02ffc08`
* `("capprobe2", "test")` -> `0304950fd1e219b26a7996b818ab1d15dfe4ecb2b234a22dead4d537b6dce4d2`

## Wire format implemented

* TCP tunnel: 4-byte little-endian record length, then a packed 16-byte
  `PeerManagerHeader` (`from`, `to`, `packet_type`, `flags`,
  `forward_counter`, `reserved`, `payload_len`, all little-endian), then the
  protobuf payload.
* Cleartext handshake: `HandshakeRequest` (`magic = 0xd1e1a5e1`, peer id,
  version 1, `liveness-echo-v1`, network name, 32-byte digest), frame type 2.
* Ping/Pong: type 4/5 with a 4-byte little-endian sequence.
* `PeerManagerHeader` packet types are read from the locked enum (Noise msg1/2/3
  are 13/14/15, not the T19 guesses).

## Verification

```sh
KC_EASYTIER_PEER_BIN=target/t20-easytier-peer cargo test --locked \
  --test mesh_peers easytier_pinned_core_cleartext -- --ignored --test-threads=1
# easytier_pinned_core_cleartext_handshake ... ok
```

The test runs the pinned wasm core with `enable_encryption=false` and no secure
mode, completes the cleartext handshake, sends a Ping and receives the Pong. It
also checks a wrong secret (core returns `network identity not match`) and a
foreign network name (client rejects the `fg-*` reply). The core log in the run
shows `handshake request: HandshakeRequest { ... network_secret_digest: ... }`
and `add tunnel as server done`.

## Explicitly not implemented

* Secure datagram / Noise XX (`enable-encryption: true`, `secure-mode: true`,
  local Noise key material) is rejected at load. The source is available but
  this task stopped at the cleartext host/discovery path.
* KCP/QUIC proxies, private mode, exit nodes, TLD DNS, accept-DNS,
  mapped listeners, proxied networks and real TCP/UDP exits are rejected or
  owned by T5/T6/T7. `hostname`/`ipv4`/`dhcp` are rejected because the
  OSPF/route host-identity and address-assignment exchange is not translated.
* The userspace IP stack/TUN remains T6/T7; every `dial()` names the gap.
