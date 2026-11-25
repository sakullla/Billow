# T32 option closure: TUIC v4/UDP, ShadowQUIC Brutal, Hysteria v1 transports

Baseline: `evidence/option-matrix.txt` (T31: 291 no-op / 88 implemented / 119
enabled, 0 problems). After T32 the same matrix is **291 no-op / 107
implemented / 100 enabled, 0 problems**, produced with the pinned Mihomo
v1.19.34 binary and a release build of the `billow-kernel` CLI:

```
cargo build --release --manifest-path native-kernel/Cargo.toml --locked -p billow-kernel-cli
node tool/kernel-compat/option-probe.mjs \
  --rust <built billow-kernel> \
  --mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
  --out tool/kernel-compat/evidence/option-matrix.txt
```

| target family | before (rust=reject rows) | after |
| --- | ---: | ---: |
| tuic | 9 | 2 (`reduce-rtt`, `ech-opts`) |
| shadowquic | 6 | 2 (`zero-rtt`, `quic-versions: v2`) |
| hysteria v1 | 6 | 1 (`ech-opts`) |

`ech-opts` is rejected by the pinned engine as well, so those rows are not
disagreements. The remaining rows are named residuals below, not silent
acceptance.

## TUIC — implemented and verified

| option | implementation | evidence |
| --- | --- | --- |
| `token` (v4) | A non-empty `token` selects v4 exactly like the pinned `NewTuic`. `src/outbound/blake3.rs` implements BLAKE3 (the crate is absent from the offline cache); the authenticate stream is `0x04 0x00 || BLAKE3(token)` and the connect response is `0x04 0xff rep` (the earlier 2-byte read was caught by the pinned peer). | `tests/mihomo_peers.rs::tuic_v4_token_reaches_the_receiving_side_through_mihomo`, `...::tuic_v4_wrong_token_never_reaches_the_sink`, `src/outbound/blake3.rs::tests::chunk_boundaries_follow_the_tree_mode` (vectors from the pinned `metacubex/blake3`) |
| `udp-relay-mode` | `native` sends one v5/v4 Packet per QUIC datagram (v5 fragmented by packet id, reassembled with the pinned 10 s age); `quic` sends one Packet per uni stream. Both use one association per proxy and serve every destination. | `tests/mihomo_peers.rs::tuic_udp_native_reaches_the_echo_through_mihomo`, `...::tuic_udp_quic_mode_reaches_the_echo_through_mihomo` |
| `udp-over-stream` | A TUIC Connect stream to `sp[.v2].udp-over-tcp.arpa`; version 1 prepends the destination to every `u16 length` frame, version 2 sends the UoT request (`isConnect = 1`, destination) once. The engine installs one reader task and one writer per target. | `tests/mihomo_peers.rs::tuic_udp_over_stream_reaches_the_echo_through_mihomo`, `src/outbound/tuic.rs::tests::uot_address_round_trips` |
| `max-datagram-frame-size` / `max-udp-relay-packet-size` | The pinned `NewTuic` derivation: overhead 27 (v4) / 29 (v5), frame default = packet + overhead, capped at 1400, packet = frame − overhead and the v5 form clamped to `MaxFragSizeV5` (1168). The frame bound is enforced on every send; quinn's socket buffers stay 64 KiB so a multi-fragment message can queue (the option is a frame bound, not a queue size). | `tests/quic_peers.rs::tuic_udp_options_load_and_reduce_rtt_is_named`, `tests/mihomo_peers.rs::tuic_udp_fragments_a_large_datagram_through_mihomo`, `src/outbound/tuic.rs::tests::v5_packet_round_trips_with_the_pinned_layout` |
| `fast-open` | v4 hands the stream back before the connect response and replays it on the first read (pinned `NewEarlyConn`); v5 has no early response in the pinned client (the flag only reaches the TCP dialer, which a QUIC socket never uses). | `tests/mihomo_peers.rs::tuic_v4_token_reaches_the_receiving_side_through_mihomo` |
| `bbr-profile` | quinn's BBR has no profile selector; conservative/standard/aggressive map to 24/32/40 packets of the pinned initial window and take precedence over `cwnd`. A documented approximation (same as T31 hysteria2). | `src/outbound/tuic.rs::tests::bbr_profile_maps_to_the_initial_window` |
| `client-fingerprint` | Parsed and applied as the closest rustls profile (T30 residual category). | option matrix `impl` row, `tests/quic_peers.rs::tuic_udp_options_load_and_reduce_rtt_is_named` |
| `reduce-rtt` | **Named residual**: quinn needs a TLS session-ticket cache and a pooled connection to send 0-RTT data; this kernel dials a fresh endpoint per session, so the option is rejected by name instead of silently degrading. | option matrix `enabled` row |

## ShadowQUIC — implemented and verified

| option | implementation | evidence |
| --- | --- | --- |
| `up` / `down` (Brutal) | `up` installs the T31 Brutal controller before the handshake; the private mihomo extension is then written on its own bidi stream (`0xff`, opcode `0x6d69686f6d6f0001`, `version 1 | flags | length 8 | rx`) and the response drives the peer. The pinned client swaps its controller after the negotiation; quinn cannot swap a live transport, so the final rate is selected up front. `down` alone leaves BBR, matching the pinned fallback. | `tests/mihomo_peers.rs::shadowquic_brutal_and_bbr_profile_reach_the_receiving_side_through_mihomo` |
| `congestion-controller` | cubic/new_reno/bbr, with `bbr_meta_v2` as the pinned alias; `bbr_meta_v1` stays named. | same peer test, `tests/config.rs::shadowquic_transport_options_are_parsed_and_jls_gaps_named` |
| `cwnd` / `bbr-profile` | Initial window (packets × quic-go's 1280-byte InitialPacketSize); profile maps to 24/32/40 packets (documented approximation). | same tests |
| `zero-rtt`, `quic-versions: v2` | **Named residuals**: JLS 0-RTT needs the pinned authenticated session ticket/cache; quinn 0.11 implements QUIC v1 only. | option matrix `enabled` rows |

## Hysteria v1 — implemented; pinned listener dependency gap

| option | implementation | evidence |
| --- | --- | --- |
| `ports` / `hop-interval` | Comma/range expansion (pinned default 10 s) rewrites the destination port through `LayeredSocket`; replies from the hop port are mapped back to the configured address. | `tests/quic_peers.rs::hysteria_v1_transport_options_load`, `src/outbound/quic.rs::tests::hop_interval_is_clamped_and_randomised` |
| `obfs` (XPlus) | 16-byte random salt; every datagram is `salt || payload XOR SHA-256(key || salt)`, applied at the UDP socket boundary and usable together with the hop. | `src/outbound/quic.rs::tests::xplus_unframes_the_pinned_go_frames` — frames generated with the pinned `transport/hysteria/obfs` package and verified with its `Deobfuscate` |
| `protocol: wechat` / `wechat-video` | 13-byte Wenxin-style header (`a1 08 | sn | 00 10 11 18 30 22 30`) then the XPlus payload, or the identity payload when no `obfs` is set (pinned dummy obfuscator). | `src/outbound/quic.rs::tests::wechat_framing_strips_the_pinned_header` |
| `fast-open` | The session response is replayed on the first read (pinned `NewEarlyConn`). | `tests/quic_peers.rs::hysteria_v1_fast_open_defers_the_response`, `tests/quic_peers.rs::hysteria_v1_transport_options_load` |
| `client-fingerprint` | rustls approximation (T30 residual category). | load test |
| `protocol: faketcp` | Loads like the pinned decoder; refused at dial time with a named error because it needs a raw-socket TCP stack, and the pinned non-Linux build is unsupported too. | load test |
| UDP session | **Named residual**: the pinned Hysteria v1 datagram session is not implemented; UDP datagrams still take the recorded drop path. | `udp` note in `rust-mapping.json` |

Dependency gap: the pinned Mihomo v1.19.34 source and binary have **no Hysteria
v1 listener** (only `hysteria2` and `hysteria2-realm`). The plan's "verify with
a pinned Mihomo hysteria listener" cannot be executed against the pinned
artifact. The wire codecs are verified against the pinned Go implementation
(XPlus), the local protocol peer covers the TCP path, and the configuration
plane is verified by load tests. This is registered rather than claimed as peer
parity.

## Non-regression

| suite | command | result |
| --- | --- | --- |
| default native-kernel | `cargo test --manifest-path native-kernel/Cargo.toml --locked -p billow-kernel` | 441 passed, 0 failed (ignored suites are the pinned-peer/device cases) |
| pinned peers | `KC_MIHOMO_BIN=<pinned> cargo test ... --test mihomo_peers -- --ignored --test-threads=1` | 104 passed, 0 failed |
| T22 DNS | `node tool/kernel-compat/t22-differential.mjs ...` | 22/23 pass, 1 skipped (mmdb fixture), 0 differ, 0 unexpected |
| T23 groups | `node tool/kernel-compat/t23-differential.mjs ...` | 28 pass, 0 differ, 0 unexpected |
| T24 rules/geodata | `node tool/kernel-compat/t24-differential.mjs ...` | 36 pass, 2 skipped (mmdb), 0 differ, 0 unexpected |
| T25 controller | `node tool/kernel-compat/t25-differential.mjs ...` | 47/49 equal, 2 recorded divergences, 0 unexpected |
| T5 integration | `node tool/kernel-compat/t5-differential.mjs ...` | 12/12 scenarios, 0 differ |
| compat runner | `node --test tool/kernel-compat/runner.test.mjs` | 10/10 pass |
| option matrix | `node tool/kernel-compat/option-probe.mjs ...` | 291/107/100, 0 problems |

`native-kernel/Cargo.toml` dependencies are unchanged; BLAKE3 is in-tree and
its constants/vectors are checked against the pinned Go module. The first T24
run was under concurrent load and showed one mihomo startup failure plus one
provider-update flake; a clean serial re-run wrote the evidence file above.
