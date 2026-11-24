# T31 transport closure: anytls security modes, hysteria2, vmess

Baseline: `evidence/t30-option-closure.md` (11 residual rows inside anytls,
hysteria2 and vmess: hy2 6, anytls 2, vmess 3). Matrix:
`evidence/option-matrix.txt` — **291 no-op / 87 implemented / 119 enabled,
0 problems**. All T31 target-family rows are implemented/impl rows, including
`hysteria2 obfs: gecko` and `realm-opts` at dial time.

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
| `udp` (QUIC datagram session) | `src/outbound/udp.rs::Hysteria2Udp` implements the pinned `sing-quic/hysteria2` datagram session (not the legacy `0x403` stream): `session id (u32 BE) \| packet id (u16 BE) \| fragment id \| fragment count \| varint address length \| "host:port" \| data`, one session id per association, where the server routes each message by its own destination. Replies are reassembled by packet id. `Proxy::udp_enabled()` reports hysteria2 as UDP-capable unconditionally (the pinned outbound sets `UDP: true` and has no `udp` field), and the mixed SOCKS5 path and the TUN path both relay through it. A `dialer-proxy` chain is refused by name because a QUIC socket cannot ride a SOCKS5 UDP hop. | `tests/mihomo_peers.rs::hysteria2_udp_reaches_the_receiving_side_through_mihomo`, `tests/mihomo_peers.rs::hysteria2_udp_fragments_a_large_datagram_through_mihomo`, `tests/config.rs::t31_hysteria2_udp_is_always_enabled_and_a_chain_is_refused`, `outbound::udp::tests::{hysteria2_datagram_layout_matches_the_pinned_udpmessage,hysteria2_fragments_reassemble_by_packet_id,hysteria2_authority_round_trips_ipv4_and_ipv6}` |
| `udp-mtu` | Applied both as the QUIC initial path MTU (`udp_mtu + 3`, clamped to 1200..1452; the pinned default 1197 is 1200 - 3) and as the Hysteria2 session fragmentation bound: each datagram that exceeds `udp-mtu - header` is split into `fragment count` messages and reassembled by `packet id`. The effective limit is `min(udp-mtu, quinn max_datagram_size)`. | `tests/mihomo_peers.rs::hysteria2_udp_fragments_a_large_datagram_through_mihomo`, `tests/quic_peers.rs::hysteria2_transport_options_are_parsed` |
| `obfs: gecko` | `quic.rs::Gecko` wraps Salamander and fragments every QUIC long-header packet into 2..8 padded chunks (`0x80 \| msg id \| index<<4 \| total \| pad length \| pad \| chunk`), each inside its own Salamander frame; replies are reassembled with the pinned 8 s TTL, per-source (8) and global (4096) caps. `obfs-min-packet-size`/`obfs-max-packet-size` select the on-wire range (defaults 512/1200, validated like the pinned client). | `tests/mihomo_peers.rs::hysteria2_gecko_obfs_reaches_the_receiving_side_through_mihomo`, `outbound::quic::tests::gecko_fragments_long_headers_and_reassembles_them` |
| `bbr-profile` | quinn's BBR has no upstream profile selector; the profile maps to the BBR initial window (conservative/standard/aggressive = 24/32/40 packets) and now takes precedence over `cwnd` in the BBR arm. A2 set `cwnd` unconditionally, which made the profile branch unreachable; the mapping is still a recorded approximation, not gain parity. | `tests/mihomo_peers.rs::hysteria2_bbr_profile_without_brutal_reaches_the_receiving_side_through_mihomo`, `outbound::quic::tests::bbr_profile_selects_the_initial_window` |

The pinned hysteria2 listener does not share one QUIC transport across a
comma-separated `listen` list, so a true multi-port hop cannot be exercised
against it. The pinned peer case therefore uses a single-port pool (proving the
selection path); the multi-port rewrite and reply mapping are covered at the
`AsyncUdpSocket` layer.

## hysteria2 — realm rendezvous

`src/outbound/hysteria2_realm.rs` implements the pinned client side: URL
parsing (http/https, path prefix), one UDP socket per address family,
STUN binding requests with XOR-MAPPED-ADDRESS and the pinned 500 ms/2 s/4 s
retransmission, `POST /v1/{realm-id}/connect` with the 16-byte nonce and
32-byte key as hex, `HYRLMv1` punch packets (`salt[8] || SHA256(key||salt) XOR`
body with HELLO/ACK and up to 1 KiB padding, 100 ms interval, 10 s cap,
symmetric-NAT port expansion), and the QUIC handshake over the winning punched
socket (`quic::connect_over_socket`) before the normal `/auth` and `0x401`
stream. The control request uses the realm TLS block; a plain `http://` URL
skips TLS. The control TLS identity is parsed, not dropped: `fingerprint` is
the pinned SHA-256 of the presented certificate DER and is installed before
`skip-cert-verify`, so a pin still protects the control channel when that flag
is true (the pinned `ca.GetTLSConfig` order); `certificate`/`private-key` are
loaded and presented as the control mTLS client identity. An unsupported shape
(only one half of the pair, a relative path, or unparsable material) is a named
load-time rejection. `realm-opts` together with a non-empty `ports` pool is
rejected with the pinned `realm and port hopping are mutually exclusive`,
because the punch owns the UDP socket. The control client speaks HTTP/1.1: it
offers `http/1.1` when the block has no ALPN, and refuses a negotiated protocol
other than `http/1.1` instead of silently mis-framing (the pinned HTTP client
also enables h2; every hysteria-realm control server written against the pinned
API serves HTTP/1.1).

Peer shape: the pinned `type: hysteria2-realm` listener is the control server
(token required), and a second pinned `type: hysteria2` listener carries
`realm-opts: {enable, server-url, token, realm-id, stun-servers}` and registers
to it. A loopback STUN fixture answers both sides; the test waits for the
pinned server's registration, then the kernel's `realm-opts` dial reaches the
sink through the punched QUIC connection. The control endpoint is HTTPS
(`skip-cert-verify` on both sides), so the TLS control path is exercised too.
The pin cases set `skip-cert-verify: true` and prove that a matching
`fingerprint` still succeeds and a wrong one never reaches the sink; the mTLS
cases run the control listener with `client-auth-type: require-any`, so the
kernel without `certificate`/`private-key` is rejected while the same control
listener accepts the configured client identity. Evidence:
`tests/mihomo_peers.rs::{hysteria2_realm_reaches_the_receiving_side_through_mihomo,hysteria2_realm_fingerprint_pins_the_control_certificate_through_mihomo,hysteria2_realm_wrong_fingerprint_never_reaches_the_sink,hysteria2_realm_client_certificate_authenticates_to_the_control_server,hysteria2_realm_without_the_required_client_certificate_never_reaches_the_sink}`,
`tests/quic_peers.rs::hysteria2_realm_rejects_port_hopping_and_keeps_its_tls_identity`,
`src/outbound/hysteria2_realm.rs::tests::{punch_packets_round_trip_and_reject_a_wrong_key,stun_response_decodes_the_xor_mapped_address,http_responses_decode_content_length_and_chunked_bodies}`.

## hysteria2 — named residuals

- `ech-opts` is rejected by both engines.
- A `dialer-proxy` chain is refused by name for hysteria2 (QUIC over a SOCKS5
  UDP hop is not implemented); the association is never dialled around it.

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

- `cargo test --manifest-path native-kernel/Cargo.toml --locked`: all default suites pass (189 lib + 1 ignored, 53 config, 15 controller, 19 dns, 32 groups, 60 protocols, 33 quic, 15 resources, 11 sessions, 1 shadowquic, 11 cli, 10 family_cli, 1 doc-test; 96 ignored mihomo peer cases).
- `tool/kernel-compat/peer-tests.sh`: **96 passed, 0 failed** against the pinned Mihomo v1.19.34 binary (the T30 77 plus JLS/ShadowTLS v1, ShadowTLS v2, hy2 obfs/Brutal, hy2 gecko, hy2 bbr-profile, hy2 realm, hy2 realm fingerprint pin (matching and wrong), hy2 realm control mTLS (present and missing), hy2 port pool, vmess mkcp/mekya/tlsmirror, and the two hysteria2 UDP cases).
- `node tool/kernel-compat/option-probe.mjs --rust <billow-kernel> --mihomo <mihomo>`: 291 / 87 / 119, 0 problems (re-run on this build; the matrix is byte-identical apart from the rust binary path comment); no T31 target row remains as an enabled rejection.
- `node --test tool/kernel-compat/runner.test.mjs`: 10 passed.
- Differentials against the same pinned binary: t22 22 pass / 1 skipped / 0 differ; t23 28 pass / 1 persistence / 0 differ; t24 36 pass / 2 skipped / 0 differ / 0 unexpected (8 recorded inbound framing differences on this run; one initial-attempt timeout-vs-close normalization differs from the previous 7, with no outcome difference); t25 47/49 equal / 2 recorded divergences / 0 unexpected; t5 12/12 scenarios / 0 differ.
