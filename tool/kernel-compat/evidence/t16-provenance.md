# T16 WireGuard/OpenVPN provenance and source-consultation record

Scope: `native-kernel/crates/billow-kernel/src/outbound/wireguard.rs` and
`native-kernel/crates/billow-kernel/src/outbound/openvpn.rs`, plus the
controlled peers under `tool/kernel-compat/peers/`.

This is not a formal clean-room record. The pinned Mihomo v1.19.34 tree is
GPL-3.0 and parts of it were **read** for functional wire facts before the Rust
modules were written. No Mihomo/Go/OpenVPN source is vendored, linked, or
line-by-line translated into `native-kernel/`; the audit below records what
was checked and, just as importantly, what the check cannot prove. The kernel
is MIT; that licence covers the Rust expression, not the upstream material
that was consulted.

## WireGuard

The implementation follows the public WireGuard protocol description
(Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s, the BLAKE2s MAC/cookie construction,
transport padding and the replay rules). The protocol facts used are:

* message layouts and constants from the WireGuard whitepaper;
* MAC1/MAC2 and cookie key derivation from the public protocol description;
* byte-level behaviour checked against the MIT `github.com/metacubex/wireguard-go`
  device built as a controlled peer (`tool/kernel-compat/peers/wireguard-peer`).

The configuration option table and defaults (`private-key`, both peer forms,
`mtu` 1408, `reserved`, the `amnezia-wg-option` rejection) were read from the
pinned `adapter/outbound/wireguard.go` as functional facts (option names,
defaults and required fields), not copied as code. `wireguard.rs` uses new
Rust names and structure; the peer is MIT/BSD-3-Clause and is a test program
only.

## OpenVPN

The implementation follows the public OpenVPN wire protocol and was verified
against the real OpenVPN 2.7.9 server with `--dev null`. The protocol facts
used are:

* P_CONTROL_HARD_RESET_CLIENT_V2/SERVER_V2, session ids, reliable message ids
  and ACK arrays;
* the TLS-in-control-channel model and the key-method-2 record layout;
* the OpenVPN MD5+SHA1 PRF (`OpenVPN master secret` / `OpenVPN key expansion`);
* P_DATA_V1/V2 layout, AEAD additional data, implicit IV, and the
  `PING_STRING` payload.

Because the pinned Mihomo `transport/openvpn` (GPL-3.0) is the closest
implementation, it was **consulted** for functional wire facts (field order,
the 16-byte ping constant, the AEAD tag-before-ciphertext layout and the
implicit IV source). This is source consultation, not a clean-room process.
The Rust module is an independent expression with new names and structure and
is verified as a black box against a real OpenVPN server; no Go source is
vendored, linked, or copied line-by-line. This residual caveat is the same
kind of limitation recorded for T15 (`t15-cleanroom.md`).

## Audit (what was actually run)

All commands were run from the repository root on 2026-11-22.

```text
$ find native-kernel -name '*.go' | wc -l
0

$ grep -rn 'transport/openvpn\|adapter/outbound/wireguard.go' native-kernel/crates/billow-kernel/src
native-kernel/crates/billow-kernel/src/outbound/openvpn.rs:4://! (`adapter/outbound/openvpn.go` wrapping `transport/openvpn`):
native-kernel/crates/billow-kernel/src/outbound/wireguard.rs:4://! (`adapter/outbound/wireguard.go`): it terminates the WireGuard tunnel at
native-kernel/crates/billow-kernel/src/proxies.rs:328:/// (`adapter/outbound/wireguard.go` `WireGuardPeerOption`).
native-kernel/crates/billow-kernel/src/proxies.rs:344:/// WireGuard (`adapter/outbound/wireguard.go` + the pinned `wireguard-go`
native-kernel/crates/billow-kernel/src/proxies.rs:374:/// OpenVPN (`adapter/outbound/openvpn.go` + `transport/openvpn`).
```

There are five hits, all documentation lines (`//!` or `///`) that cite the
upstream option/wire surface as provenance. The same query restricted to
non-comment lines is empty:

```text
$ grep -rn 'transport/openvpn\|adapter/outbound/wireguard.go' native-kernel/crates/billow-kernel/src \
    | grep -vE ':[0-9]+:[[:space:]]*//' || true
(no output: every hit is a documentation reference)
```

No characteristic Go identifiers from the consulted packages appear in the
Rust sources:

```text
$ grep -rnE 'MessageInitiation|DataChannelTagSize|reliable_ack|openVPNPingPacket|CreateMessageInitiation|CookieChecker|BeginSymmetricSession|InstallScriptOptionsString|MarshalClient|DeriveClientKeyMaterial|KeySource2|PDataV2' \
    native-kernel/crates/billow-kernel/src || echo '(no match)'
(no match)
```

## Limits of this audit

- The grep checks are syntactic. They show that no Go file or characteristic
  Go identifier was copied into the Rust tree; they cannot prove that no
  idea or constant order was carried over from reading the GPL source.
- The OpenVPN implementation is therefore **not** a certified clean-room.
  A formal clean-room would require a written spec/observer separation and an
  implementer who did not read the pinned implementation. That work was not
  done in T16.
- The WireGuard implementation is closer to the public whitepaper and the
  MIT test peer; the only pinned GPL read there was the option table/defaults
  in `adapter/outbound/wireguard.go`.
- The GPL-3.0 Mihomo tree remains GPL-3.0 and is used only at test time
  through its binary; the GPL-2.0 OpenVPN binary is likewise a test peer only.

## License summary

| material | license | role |
| --- | --- | --- |
| `github.com/metacubex/wireguard-go` | MIT (`SPDX-License-Identifier: MIT`) | controlled test peer |
| `golang.org/x/crypto` | BSD-3-Clause | transitivity of the WireGuard peer |
| OpenVPN 2.7.9 binary | GPL-2.0 | controlled test server, not linked |
| pinned Mihomo v1.19.34 | GPL-3.0 | read for functional facts only; not linked or distributed |
| Rust kernel | MIT | the implementation |
