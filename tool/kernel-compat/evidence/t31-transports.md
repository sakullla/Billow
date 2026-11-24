# T31 transport closure: anytls security modes, hysteria2, vmess

Baseline: `evidence/t30-option-closure.md` (11 residual rows inside anytls,
hysteria2 and vmess: hy2 6, anytls 2, vmess 3). Matrix:
`evidence/option-matrix.txt` — **289 no-op / 86 implemented / 120 enabled,
0 problems**. All nine target-family rows are now implemented/impl rows.
`hysteria2 realm-opts` loads (impl row) but its dial path is still refused; it
is the only accepted-but-not-dialable T31 option and is called out below.

## anytls — implemented and verified

| option | implementation | evidence |
| --- | --- | --- |
| `jls-opts` (`username`, `password`) | `src/outbound/jls.rs::tcp_client` builds the rustls ClientHello twice with a recorded randomness stream and replaces the one fill that produced the 32-byte `random` with the AES-256-GCM sealed value (the same derivation the QUIC path uses), byte-checking the replay against the dry ClientHello. `src/outbound/tls_io.rs` drives that `ClientConnection`, verifies the first cleartext ServerHello random before the certificate verifier runs (`JlsVerifier`), and fails the dial if the account did not authenticate (pinned `ErrJLSAuthFailed`). TLS 1.3 only, no resumption (a PSK binder would have to be re-sealed). | `tests/mihomo_peers.rs::anytls_over_jls_reaches_the_receiving_side_through_mihomo`, `...::anytls_over_jls_with_a_wrong_password_never_reaches_the_sink`, `src/outbound/jls.rs::tests::tcp_client_seals_the_serialised_client_hello` |
| `shadow-tls-opts` `version: 1` | The camouflage TLS 1.2 handshake (pinned `MaxVersionTLS12`: the v1 relay cannot follow a TLS 1.3 server flight, which it cannot see as a cleartext `Finished`) is performed over the connection and the raw stream is handed to the AnyTLS framing, exactly like the pinned `DialContextConn` case 1 and `serverV1`. | `tests/mihomo_peers.rs::anytls_over_shadow_tls_v1_reaches_the_receiving_side_through_mihomo`, `...::anytls_over_shadow_tls_v1_with_a_wrong_anytls_password_never_reaches_the_sink` |
| `shadow-tls-opts` `version: 2` (the pinned default) | `src/outbound/shadow_tls.rs::ShadowFramed` now frames `HMAC-SHA1(read bytes)[..8]` **inside** the first TLS application-data record, exactly like the pinned `clientConn.Write(prefixed)`; the earlier code wrote the digest before the record header, so the pinned server parsed the digest as a record length and never reached the hash comparison. The camouflage config (`tls::shadow_tls_client_config`) disables TLS 1.3 session tickets: the pinned uTLS client has no session cache, and a ticket the server hashes as a later write makes the read digest unrecognisable (`[ShadowTLS] hashcode mismatch`). | `tests/mihomo_peers.rs::anytls_over_shadow_tls_v2_reaches_the_receiving_side_through_mihomo`, `src/outbound/shadow_tls.rs::tests::framing_prefixes_the_hmac_and_uses_application_data_records` |

Peer shape: a second pinned AnyTLS listener (`certificate`/`private-key`,
`allow-insecure: true`) is the camouflage TLS server; the tested listener
carries `jls-config: {users, sni, dest, proxy: DIRECT}` or
`shadow-tls: {enable, version: 1|2, password, handshake: {dest, proxy: DIRECT}}`.
The negative cases prove the account check: a wrong JLS password never reaches
the sink (the server falls back to the camouflage host and the client refuses
the dial), and with ShadowTLS v1 (which authenticates nothing itself) a wrong
AnyTLS password never reaches the sink.

## anytls — named residuals

- `shadow-tls-opts` version 3: the account is carried in the ClientHello session
  id and the post-handshake records chain HMAC/kdf state. rustls generates the
  session id internally; rewriting it invalidates the handshake transcript, so
  this needs a ClientHello hook rustls does not expose.
- `restls-opts`, `ech-opts`: unchanged from T30.

## hysteria2 — implemented and verified

| option | implementation | evidence |
| --- | --- | --- |
| `obfs: salamander` | `src/outbound/quic.rs::LayeredSocket` wraps the runtime's `quinn::AsyncUdpSocket`: each datagram gets an 8-byte random salt and is XORed with BLAKE2b-256(password ‖ salt), and replies are decoded before quinn sees them. | `tests/mihomo_peers.rs::hysteria2_obfs_and_brutal_reach_the_receiving_side_through_mihomo`, `outbound::quic::tests::layered_socket_obfuscates_and_rewrites_the_hop_port` |
| `ports`, `hop-interval` | The same wrapper rewrites the destination port to a randomly selected entry of the expanded `ports` range set, and maps replies from that port back to the configured base address (quinn drops a client packet from a changed remote address). A tokio task changes the port every `hop-interval` (pinned defaults: 30 s, minimum 5 s, reversed range collapses to its start). | `tests/mihomo_peers.rs::hysteria2_port_pool_selects_the_listed_port_through_mihomo`, `outbound::quic::tests::layered_socket_obfuscates_and_rewrites_the_hop_port`, `outbound::quic::tests::hop_interval_is_clamped_and_randomised` |
| `up` (Brutal) | `src/outbound/quic.rs::Brutal` implements the pinned `transport/hysteria2/congestion/brutal.go` window: `bps * smoothed_rtt * 2 / ack_rate`, with the five one-second ACK/loss slots and the 0.8 ACK-rate floor, exposed through quinn's `Controller::window` (quinn has no separate pacing callback). | `tests/mihomo_peers.rs::hysteria2_obfs_and_brutal_reach_the_receiving_side_through_mihomo` |
| `udp-mtu` | Applied as the QUIC initial path MTU (`udp_mtu + 3`, clamped to 1200..1452; the pinned default 1197 is 1200 - 3). The engine still has no Hysteria2 UDP session relay, so the session MTU itself has no carrier. | `tests/mihomo_peers.rs::hysteria2_obfs_and_brutal_reach_the_receiving_side_through_mihomo`, `tests/quic_peers.rs::hysteria2_transport_options_are_parsed` |
| `bbr-profile` | quinn's BBR has no upstream profile selector; the profile maps to the BBR initial window (conservative/standard/aggressive = 24/32/40 packets). This is a recorded approximation, not profile parity. | the same two tests as `udp-mtu` |

The pinned hysteria2 listener does not share one QUIC transport across a
comma-separated `listen` list, so a true multi-port hop cannot be exercised
against it. The pinned peer case therefore uses a single-port pool (proving the
selection path); the multi-port rewrite and reply mapping are covered at the
`AsyncUdpSocket` layer.

## hysteria2 — partial / named residuals

- `realm-opts` (**accepted but not dialable**): `parse_hysteria2_realm` loads
  `enable`, `server-url`, `token`, `realm-id`, `stun-servers`, the TLS identity
  fields, `alpn` and `proxy`, and the option matrix records it as accepted by
  both engines. The dial path refuses it by name because the pinned
  rendezvous needs an HTTP control client, STUN discovery and UDP hole punching
  (sing-quic `hysteria2/realm`), none of which this kernel implements.
- `obfs: gecko` is refused at dial by name (Salamander is implemented; Gecko
  adds per-message fragmentation/reassembly and packet-size padding).
- `udp` remains a registered gap; `ech-opts` is rejected by both engines.

## vmess — implemented and verified

| option | implementation | evidence |
| --- | --- | --- |
| `network: mkcp` / `kcp`, `mkcp-opts` | `src/outbound/mkcp.rs` is a direct translation of the pinned `transport/mkcp` client: one KCP segment per UDP datagram, send window with retransmission, ACK assembly and receive reordering, RTT estimator, ping/terminate, the `simpleAuthenticator` (FNV-1a + length, 4-byte XOR chain) or seeded AES-128-GCM, and all six packet headers (`none`, `srtp`, `utp`, `wechat-video`, `dtls`, `wireguard`). Tuning fields (`mtu`, `tti`, capacities, buffers, `congestion`) are applied. | `tests/mihomo_peers.rs::vmess_over_mkcp_reaches_the_receiving_side_through_mihomo`, `src/outbound/mkcp.rs::tests::{simple_authenticator_round_trips_and_pads_without_changing_the_length,segment_round_trip_carries_all_fields}` |
| `network: mekya`, `mekya-opts` | `src/outbound/mekya.rs` opens an HTTP/2 connection (TLS when `tls: true`, ALPN `h2`), runs `h2-pool-size` request lanes that POST `[u16 length][packet]` bundles with `X-Session-ID: base64url(16 random bytes)`, parses the streaming response bundles, and runs the same KCP worker over that packet transport (`mkcp::connect_packet_io`). `.kcp` reuses the mKCP knobs. | `tests/mihomo_peers.rs::vmess_over_mekya_reaches_the_receiving_side_through_mihomo`, `src/outbound/mekya.rs::tests::{base64url_matches_the_unpadded_alphabet,bundle_layout_is_the_pinned_two_byte_length}` |

Peer shape: a pinned `listeners: type: vmess` listener with
`mkcp-config: {enable: true, seed, header}` or
`mekya-config: {enable: true, max-write-duration-ms}`; the client carries the
same credentials/seed/header. Both cases forward a marker through the sink.

## vmess — tlsmirror

`tlsmirror-opts` is implemented as the pinned carrier/hidden record design:
`src/outbound/tlsmirror.rs` drives a real rustls TLS 1.3 carrier session over the
raw TCP stream, parses both handshake randoms from the exact records, derives
the hidden AES-128-GCM key/nonce mask with HKDF-SHA256 (`primary-key` as PRK,
`:c2s`/`:s2c` tags) and injects hidden VMess bytes as extra TLS
application-data records. Incoming records are tried with the stateful
XOR-nonce decryptor; hidden records are delivered to VMess and carrier records
are fed back to rustls. The pinned vmess listener's `tlsmirror-config` relays
the carrier to a real TLS destination and diverts the hidden records; the peer
case uses a pinned AnyTLS camouflage listener as that destination.

Implemented subset: primary-key, TLS 1.3, no padding, no enrollment, no
traffic generator, no sequence watermarking, no TLS 1.2 explicit-nonce cipher
suites. The unimplemented extras are rejected by name at load when enabled, and
a block with no `primary-key` (for example the option matrix's
`{enabled: true}`) is a no-op exactly like the pinned decoder.

Evidence: `tests/mihomo_peers.rs::vmess_over_tlsmirror_reaches_the_receiving_side_through_mihomo`,
`src/outbound/tlsmirror.rs::tests::{primary_key_decodes_standard_base64,xor_nonce_encryptor_and_decryptor_share_the_counter,client_and_server_randoms_are_parsed_at_the_pinned_offsets}`.

## Verification

- `CARGO_TARGET_DIR=<independent> cargo test --manifest-path native-kernel/Cargo.toml --locked`: all suites pass (179 lib, 50 config, 15 controller, 19 dns, 32 groups, 60 protocols, 32 quic, 15 resources, 11 sessions, 11 cli, 10 family_cli, 1 doc-test; 86 ignored peer cases).
- `tool/kernel-compat/peer-tests.sh`: **87 passed, 0 failed** against the pinned Mihomo v1.19.34 binary (the T30 77 plus JLS/ShadowTLS v1, ShadowTLS v2, hy2 obfs/Brutal, hy2 port pool, vmess mkcp/mekya/tlsmirror).
- `node tool/kernel-compat/option-probe.mjs --rust <billow-kernel> --mihomo <mihomo>`: 289 / 86 / 120, 0 problems; no T31 target row remains as an enabled rejection.
- `node --test tool/kernel-compat/runner.test.mjs`: 10 passed.
- Differentials against the same pinned binary: t22 22 pass / 1 skipped / 0 differ; t23 28 pass / 1 persistence / 0 differ; t24 36 pass / 2 skipped / 0 differ / 9 recorded inbound framing differences; t25 47/49 equal / 2 recorded divergences / 0 unexpected; t5 12/12 scenarios / 0 differ.
