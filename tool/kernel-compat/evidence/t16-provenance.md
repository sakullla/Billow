# T16 WireGuard/OpenVPN provenance and no-copy audit

Scope: `native-kernel/crates/billow-kernel/src/outbound/wireguard.rs` and
`native-kernel/crates/billow-kernel/src/outbound/openvpn.rs`, plus the
controlled peers under `tool/kernel-compat/peers/`.

## WireGuard

The WireGuard implementation follows the public protocol description
(Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s, the BLAKE2s MAC/cookie construction,
the transport message padding/replay rules). The protocol facts used to
implement it are:

* message layouts and constants from the WireGuard whitepaper;
* MAC1/MAC2 key derivation from the public protocol description;
* key-method/transport semantics checked at the byte level against the MIT
  `github.com/metacubex/wireguard-go` device built as a controlled peer
  (`tool/kernel-compat/peers/wireguard-peer`).

That peer is MIT/BSD-3-Clause and is a test program only. `wireguard.rs` is a
new Rust expression; it does not vendor, link, or translate Go source. The
configuration option table and defaults (`private-key`, `peers`, `mtu` 1408,
`reserved`, `amnezia-wg-option` rejection) were read from the pinned
`adapter/outbound/wireguard.go` as functional facts (option names, defaults,
rejections), not copied as code.

## OpenVPN

The OpenVPN implementation follows the public OpenVPN wire protocol and was
verified against the real OpenVPN 2.7.9 server with `--dev null`. The
protocol/layout facts used are:

* P_CONTROL_HARD_RESET_CLIENT_V2/SERVER_V2, session ids, reliable message ids
  and ACK arrays;
* the TLS-in-control-channel model and the key-method-2 record layout;
* the OpenVPN MD5+SHA1 PRF (`OpenVPN master secret` / `OpenVPN key expansion`);
* P_DATA_V1/V2 layout, AEAD additional data, implicit IV, and the
  `PING_STRING` payload.

Because the pinned Mihomo `transport/openvpn` (GPL-3.0) is the closest
implementation, it was consulted for functional wire facts (field order,
the 16-byte ping constant, the AEAD tag-before-ciphertext layout, the implicit
IV source). This is not a strict clean-room: the Rust code is an independent
expression with new names and structure, and it is verified as a black box
against a real OpenVPN server. No Go source is vendored, linked, or
line-by-line translated. This residual caveat mirrors the T15 record.

## No-copy audit

```text
$ find native-kernel -name '*.go' | wc -l
0
$ grep -rn 'transport/openvpn\|adapter/outbound/wireguard.go' \
    native-kernel/crates/billow-kernel/src
(no match; the modules describe protocol facts and cite this record)
```

- No Go or OpenVPN C source is vendored or linked by `native-kernel/`.
- The WireGuard peer is built from the cached MIT module at test time only.
- The OpenVPN server is the Homebrew binary at test time only.

## License summary

| material | license | role |
| --- | --- | --- |
| `github.com/metacubex/wireguard-go` | MIT (`SPDX-License-Identifier: MIT`) | controlled test peer |
| `golang.org/x/crypto` | BSD-3-Clause | transitivity of the WireGuard peer |
| OpenVPN 2.7.9 binary | GPL-2.0 | controlled test server, not linked |
| pinned Mihomo v1.19.34 | GPL-3.0 | read for functional facts only |
| Rust kernel | MIT | the implementation |
