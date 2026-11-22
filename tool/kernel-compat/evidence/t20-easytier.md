# T20 EasyTier translation (LGPL-3.0-or-later)

Task: `2026-11-20-native-rust-kernel#T20`. Platform: macOS arm64, 2026-11-22.
Owner-authorized translation of the locked EasyTier source.

## Source and license

The Go module `github.com/easytier/easytier/easytier-go`
`v0.0.0-20261111015056-2abb1676b475` embeds a wasm core whose provenance file
names commit `5f1eaa7c9f9d3e89e9b75a6d87531a436fae40c4`. That commit is not in
the public GitHub history. The translation therefore used the public
`EasyTier/EasyTier` `main` revision
`45a6b6f1769f95590a396f4962e58d654b6e0380` (fetched 2026-11-22), whose
`easytier-core` layout matches the wasm, and verified every layer against the
pinned wasm binary. The upstream license is LGPL-3.0-or-later; the full text is
committed at `native-kernel/third_party/EasyTier-LGPL-3.0.txt`. The workspace
is distributed under GPL-3.0-only (the sudoku translation), so a binary
containing this module must satisfy both GPL and LGPL obligations.

Translated file and sources:

| Rust file | upstream source |
| --- | --- |
| `native-kernel/crates/billow-kernel/src/outbound/easytier.rs` | `easytier-core/src/config/mod.rs` (`generate_digest_from_str`/`network_secret_digest`), `easytier-core/src/packet/mod.rs` (`PeerManagerHeader`, `TCPTunnelHeader`, `PacketType`, `DefaultEndian = LittleEndian`), `easytier-core/src/peers/conn/peer_conn.rs` (cleartext handshake, Noise XX msg1/2/3, secret proof), `easytier-core/src/peers/conn/peer_conn_ping.rs` (Ping/Pong), `easytier-core/src/peers/conn/peer_session.rs` + `easytier-core/src/tunnel/secure_datagram.rs` (root key, traffic keys, epoch/seq), `easytier-core/src/tunnel/encrypt/{aes_gcm,chacha20}.rs` (AEAD tail) |

The Rust file carries an `SPDX-License-Identifier: LGPL-3.0-or-later` header
and the public revision. No upstream Go/wasm code is vendored or linked into
the kernel; `tool/kernel-compat/peers/easytier-peer` runs the locked wasm core
as a test-only fixture.

## network_secret_digest

The locked source uses `std::collections::hash_map::DefaultHasher`
(SipHash-1-3 with zero keys), not SHA-256:

```text
h = DefaultHasher::new()
h.write(network_name)
h.write(network_secret)
for i in 0..4:
    digest[i*8..(i+1)*8] = h.finish().to_be_bytes()
    h.write(digest[..(i+1)*8])
```

Known vectors from the pinned core:

* `("capprobe", "test")` -> `5e7befbd5bcab40df260b8b9f03230e014a13608a8dfd2a477d0c360a02ffc08`
* `("capprobe2", "test")` -> `0304950fd1e219b26a7996b818ab1d15dfe4ecb2b234a22dead4d537b6dce4d2`

## Wire format implemented

* TCP tunnel: 4-byte little-endian record length, then a packed 16-byte
  `PeerManagerHeader` (`from`, `to`, `packet_type`, `flags`,
  `forward_counter`, `reserved`, `payload_len`, all little-endian), then the
  protobuf/Noise payload.
* Cleartext: `HandshakeRequest` (`magic = 0xd1e1a5e1`, peer id, version 1,
  `liveness-echo-v1`, network name, 32-byte digest), frame type 2; Ping/Pong
  type 4/5 with a 4-byte little-endian sequence.
* Noise XX (`Noise_XX_25519_ChaChaPoly_SHA256`, prologue
  `easytier-peerconn-noise`): `PeerConnNoiseMsg1Pb` type 13,
  `PeerConnNoiseMsg2Pb` type 14, `PeerConnNoiseMsg3Pb` type 15; static X25519
  keys, handshake hash, HMAC-SHA256 secret proof
  (`"easytier secret proof" || handshake_hash`), root key and session
  generation/epoch from msg2.
* Secure datagram: HKDF-SHA256 traffic key
  (`HMAC(zeros32, root_key)` then info `et-traffic | epoch BE | dir`), epoch
  and sequence as the 12-byte nonce, direction by peer-id ordering, AES-128-GCM
  (`aes-gcm`) or ChaCha20-Poly1305 (`chacha20`), `tag(16) || nonce(12)` tail,
  `PeerManagerHeader.flags` `ENCRYPTED` bit.
* `PeerManagerHeader` packet types are read from the locked enum (Noise msg1/2/3
  are 13/14/15).

## Verification

```sh
KC_EASYTIER_PEER_BIN=target/t20-easytier-peer cargo test --locked \
  --test mesh_peers easytier_pinned_core_cleartext -- --ignored --test-threads=1
# easytier_pinned_core_cleartext_handshake ... ok

KC_EASYTIER_PEER_BIN=target/t20-easytier-peer cargo test --locked \
  --test mesh_peers easytier_pinned_core_secure -- --ignored --test-threads=1
# easytier_pinned_core_secure_datagram ... ok
```

The cleartext test runs the pinned wasm core with `enable_encryption=false` and
no secure mode, completes the handshake, sends Ping and receives Pong. The
secure test runs `SecureMode()` + `Encryption(true)`, completes Noise XX, sends
Ping/Pong, sends 12 AES-GCM encrypted data frames and asserts the peer log has
no decrypt failure and the session survives. Wrong secret/foreign network must
produce an error and no session; the assertion is intentionally tolerant of a
core closing the connection (`Io`/`Timeout`) as well as a named mismatch. The
peer log in the run records `handshake request`, `add tunnel as server done`
and no `secure datagram decrypt failed`.

## Not translated / retained boundaries

* OSPF/route host identity (`hostname`/`ipv4`/`dhcp`), exit nodes, proxied
  networks, TLD DNS, accept-DNS, mapped listeners and real TCP/UDP exits are
  rejected or owned by T5/T6/T7.
* KCP/QUIC proxies, private mode, latency-first and local key files beyond the
  Noise static key options are rejected by name.
* The userspace IP stack/TUN remains T6/T7; every `dial()` names the gap.
