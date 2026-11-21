# Billow native Rust kernel

An embeddable proxy engine plus a standalone process entry. No Tauri or other
GUI dependency; the library crate also builds as a `staticlib` so the iOS
Network Extension (T3/T7) can link it directly.

Status: one mixed inbound on the configured address (TCP CONNECT,
SOCKS5 and SOCKS5 `UDP ASSOCIATE`), a strict subset of the clash
configuration, `DIRECT`/`REJECT` and the protocol outbounds below with their
transports and UDP associations. T9 added `vmess` (AEAD header), `snell`
(v1-v3) and `trusttunnel` (TLS + HTTP/2 CONNECT). T11 added `gost-relay`
(relay v2: TCP/TLS/auth/`forward`), `ssh` (password and inline-PEM key auth,
host-key pinning, `direct-tcpip`) and `ssr` (every pinned stream cipher,
protocol plugin and obfs plugin, plus the UDP association). T12 completed the
SSR plugin layers and the gost-relay UDP association and smux session. T10
added the QUIC families `tuic` (v5 `uuid`/`password`), `hysteria` (v1) and
`hysteria2` (HTTP/3 auth + TCP), all over `quinn` 0.11. T13 added `mieru`
(single-session TCP, an independent implementation of the published protocol);
its earlier `sudoku` port was removed because it was a GPL-3.0 derivative of
the pinned `transport/sudoku`; T17's clean-room attempt found the protocol's
keyed table, handshake and record layers are not publicly specified, so the
type stays rejected (see [Not implemented](#not-implemented)). T14 added
`masque` as an RFC 9298 CONNECT-UDP client over HTTP/3, reusing the T10
`quinn` profile for the UDP association;
the pinned Cloudflare WARP CONNECT-IP flow (`cf-connect-ip` + a userspace IP
stack) is rejected by name and owned by T18. T15 added `shadowquic`: the JLS ClientHello /
ServerHello random seal is an independent implementation of the locked
`jls-tls` algorithm, injected into rustls's own ClientHello through a
recorded-random replay, over the same `quinn` transport. T16 added the
protocol halves of `wireguard` (Noise IK handshake, cookie reply, transport
keys, replay window and keepalive, verified against the locked
`metacubex/wireguard-go` device) and `openvpn` (UDP/TCP control channel,
TLS 1.2/1.3 client authentication, key-method 2 and the AEAD data channel,
verified against OpenVPN 2.7.9). T19 added the mesh adapters: `tailscale`
(control-base Noise IK, the HTTP/2 `/machine/map` control request and the DERP
greeting/client-info/ping/packet frames) and `zerotier` (identity proof of work,
planet/moon parsing, VL1 armor and HELLO/OK/WHOIS/ECHO, VL2 frame payload).
Device/TUN ownership and the userspace IP stack stay with T6/T7, so both
families load a valid configuration and refuse every `dial()` with that gap
named. EasyTier is rejected as a whole type: the pinned core derives
`network_secret_digest` inside its wasm artifact and that derivation is not
reproducible offline, so neither the cleartext host/discovery path nor
`enable-encryption: true` is loaded as compatible. The T10/T14/T15/T16/T19
families are partial: their gaps are named in
[Not implemented](#not-implemented) and in
`tool/kernel-compat/evidence/rust-mapping.json`.
**Not implemented yet** (rejected with
`[unsupported]`, never ignored): DNS and `hosts`, proxy groups and providers,
the control API (`external-controller`, `proxy-providers`, rules beyond the
listed types), `tun`/`redir`/`tproxy`, the families listed under
[Protocol families outside this slice](#protocol-families-outside-this-slice),
and the protocol options listed in [Not implemented](#not-implemented). T5 owns
DNS, groups, providers, rules and the control interface.

## Layout

```
native-kernel/
├── Cargo.toml, Cargo.lock          # workspace (resolver 2), lockfile committed
└── crates/
    ├── billow-kernel/              # library (rlib + staticlib)
    │   ├── src/config.rs           # strict YAML/geosite parsing
    │   ├── src/proxies.rs          # strict `proxies:` option tables
    │   ├── src/outbound/           # socks5, http, ss, trojan, vless, anytls, vmess, snell,
    │   │                           # trusttunnel, gost-relay, ssh, ssr, mieru, masque,
    │   │                           # shadowquic + jls (recorded-random TLS hook),
    │   │                           # wireguard (Noise IK/transport), openvpn
    │   │                           # (control/TLS/key-method 2/AEAD data channel),
    │   │                           # tailscale (control Noise/HTTP2 + DERP),
    │   │                           # zerotier (identity/planet/VL1/VL2),
    │   │                           # quic, h3 + tls, ws, h2
    │   ├── src/keys.rs             # EVP_BytesToKey, HKDF-SHA1, trojan key, uuid
    │   ├── src/rules.rs            # rule set evaluation
    │   ├── src/inbound.rs          # SOCKS5 + HTTP CONNECT handshake, authentication
    │   ├── src/engine.rs           # listener, sessions, bounded relay, lifecycle
    │   ├── src/identity.rs         # uuid / pid / version / listener / config digest
    │   ├── examples/embed.rs       # embedding example
    │   └── tests/                  # config, protocols (loopback peers), sessions,
    │                               # mihomo_peers (pinned Mihomo),
    │                               # shadowquic_stream (stream/control reopen),
    │                               # wireguard_peer/openvpn_peer (controlled peers),
    │                               # data/shadowquic-jls.txt (locked JLS hello vectors),
    │                               # cli/family args, common/ helpers
    └── billow-kernel-cli/          # binary `billow-kernel`
        └── tests/cli.rs            # drives the real process: inbound, outbound, restart
```

## Supported configuration

Top-level keys: `mixed-port`, `port` (recorded, does not bind a separate
listener), `socks-port` (legacy alias for `mixed-port`), `allow-lan`,
`bind-address`, `mode: rule`, `log-level`, `authentication`, `tls` (extra
roots only), `proxies`, `rules`.

Rules: `DOMAIN`, `DOMAIN-SUFFIX`, `GEOSITE`, `IP-CIDR`, `IP-CIDR6`, `MATCH`,
with the outbounds `DIRECT`, `REJECT` or the name of a configured proxy, and
the optional `no-resolve` suffix on IP rules. The first matching rule wins;
without a `MATCH` rule the built-in fallback is `DIRECT`, as in Mihomo. The
listener binds `127.0.0.1` unless `allow-lan: true` is set.

`GEOSITE,<key>` / `GEOSITE,<key>/<tag>` read a text database from
`--geosite-dir` (`<key>`, `<key>.yaml`, `<key>.dat` or `<key>.json` in YAML
form) with `domain`, `sub_domain` (literal or a single leading `*.`) and
`domain_keyword` entries. Compiled MRS/protobuf geosite files and other geosite
rule kinds are rejected until T5.

`authentication: ["user:pass", ...]` guards the mixed inbound (SOCKS5 RFC 1929
and HTTP `Proxy-Authorization: Basic`). `tls: {custom-cert: [...], certificate:
<dir>}` adds trust anchors for outbound TLS: they are built into the kernel
instance at start and used by every TLS dial of that instance (the platform
store stays the base, and a second kernel in the same process keeps its own
anchors). `skip-cert-verify: true` accepts any certificate instead (only
`true`; `fingerprint`/`certificate`/`private-key`/`name-cert-verify` are
rejected). The private-CA case is covered by
`tests/protocols.rs::custom_ca_roots_are_installed_for_outbound_tls`.

Example:

```yaml
mixed-port: 17890
allow-lan: false
mode: rule
log-level: info
authentication:
  - "alice:secret"
proxies:
  - {name: ss1, type: ss, server: 203.0.113.10, port: 8388,
     cipher: aes-256-gcm, password: "..."}
  - {name: tj1, type: trojan, server: 203.0.113.11, port: 443,
     password: "...", sni: example.org, udp: true}
  - {name: jump, type: socks5, server: 127.0.0.1, port: 1080}
  - {name: vl1, type: vless, server: 203.0.113.12, port: 443,
     uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, tls: true, network: ws,
     ws-opts: {path: /ws}}
rules:
  - DOMAIN,blocked.example,REJECT
  - DOMAIN-SUFFIX,corp.example,tj1
  - MATCH,ss1
```

A key the pinned version declares but this kernel does not implement (a
top-level key such as `dns`/`hosts`, or a proxy option such as `tfo`) fails when
its value asks for something; a key the pinned version does not declare at all
is ignored with a warning, exactly as Mihomo's decoder ignores it, so a valid
upstream configuration is not rejected (R2). Errors are categorized by a stable tag: `invalid_yaml`,
`invalid_value`, `unsupported`, plus `bind` and `limits` at start-up. Example:

```
error: [unsupported] unsupported configuration: top-level key 'dns' is not implemented by the Rust kernel slice
error: [unsupported] proxies[0] (name=s1, type=vless): option 'flow' value 'xtls-rprx-vision' is not implemented
```

## Protocol outbounds

Every proxy establishes a real TCP connection to the configured server
(optionally over TLS / WebSocket), performs the handshake and hands a byte
stream to the session. A failed handshake, TLS verification or authentication
aborts the session and the client receives the inbound failure reply. The
identities of the servers are logged as the session exit.

| type | transport options implemented | UDP | verified against the pinned Mihomo |
| --- | --- | --- | --- |
| `socks5` | plain, `tls: true` (+ `sni`, `skip-cert-verify`, `alpn`), RFC 1929 auth | no | `listeners: type: socks` (with users), wrong password |
| `http` | plain, `tls: true`, Basic auth, extra `headers` | no | `listeners: type: http` (with users) |
| `ss` | AEAD 2017 `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305` | `udp: true`: AEAD-2017 datagrams | `listeners: type: shadowsocks`, wrong password (TCP and UDP) |
| `trojan` | TLS, `network: tcp` / `ws` (`ws-opts.path`, `headers`, `v2ray-http-upgrade`) | `udp: true`: `addr|len|CRLF|payload` frames over the TLS stream | `listeners: type: trojan`, wrong password, untrusted certificate (TCP and UDP) |
| `vless` | `tls: true`, `network: tcp` / `ws` (`ws-opts.path`), `encryption: none` | no | `listeners: type: vless` (tcp and `ws-path`), wrong uuid |
| `anytls` | TLS, one stream per connection, protocol version 2 | no | `listeners: type: anytls`, wrong password, untrusted certificate |
| `vmess` | AEAD request header (`alterId: 0`), `cipher: auto`/`aes-128-gcm`/`chacha20-poly1305`/`none`, `tls: true`, `network: tcp`/`ws` (`ws-opts.path`, `headers`), `sni`/`servername` | no | `listeners: type: vmess` (aes-128-gcm, chacha20-poly1305, domain target), wrong uuid |
| `snell` | v1 (chacha20-poly1305) / v2 / v3 (aes-128-gcm), Argon2id KDF, `obfs-opts: {mode: http, host}` | no | `listeners: type: snell` v1/v2/v3, v3 + http obfs, wrong psk |
| `trusttunnel` | TLS + HTTP/2 `CONNECT`, Basic `Proxy-Authorization`, ALPN `h2`, `sni`, `skip-cert-verify` | no | `listeners: type: trusttunnel` (`network: [tcp]`), wrong password |
| `gost-relay` | relay v2 over TCP, `tls: true` (`sni`, `skip-cert-verify`), `username`/`password`, `forward` (no address feature), `mux` (smux v1 session, one stream per dial) | `udp: true`: one association bound to the target, `length(u16 BE) || payload` frames | controlled relay-v2 server (header vectors, auth/forward/TLS/status, UDP and smux cases); no Mihomo listener exists |
| `ssh` | password and inline-PEM public-key auth, `private-key-passphrase`, `host-key` pinning, `host-key-algorithms`, one `direct-tcpip` channel per dial | no | controlled `russh` server (password/key/host-key cases); no Mihomo listener exists |
| `ssr` | stream ciphers (`rc4-md5`, `aes-128/192/256-cfb`, `aes-128/192/256-ctr`, `chacha20`, `chacha20-ietf`, `xchacha20`, `none`), every protocol plugin (`origin`, `auth_sha1_v4`, `auth_aes128_md5`, `auth_aes128_sha1`, `auth_chain_a`, `auth_chain_b`), every obfs plugin (`plain`, `http_simple`, `http_post`, `random_head`, `tls1.2_ticket_auth`, `tls1.2_ticket_fastauth`) | `udp: true`: the pinned `cipher.PacketConn` + `protocol.PacketConn` association (no obfs, as in the pinned outbound). Pinned limit: `auth_aes128_*` datagrams are sealed with the derived user key but opened with the cipher key, so `protocol-param` breaks the UDP path; the UDP cases use no `protocol-param` | pinned Go cipher vectors; the Go plugin peer, which the *pinned* client packages also accept for all 36 protocol/obfs combinations; wrong-password and UDP cases; no Mihomo listener exists |
| `tuic` | QUIC (`quinn` 0.11, TLS 1.3, ALPN `h3`), v5 `uuid`/`password` authentication via the TLS exporter, one TCP stream per dial, `ip`/`sni`/`skip-cert-verify`/`disable-sni`/`heartbeat-interval`/`request-timeout` (bounds the auth/Connect stream operations) | no | `listeners: type: tuic` (users map), wrong password; controlled `quinn` peer for the default suite |
| `hysteria` | QUIC (ALPN `hysteria`), binary control hello (`auth`/`auth-str`, `up`/`down`), one TCP stream per dial | no | controlled `quinn` server implementing the pinned `transport/hysteria/core` framing (no Mihomo listener exists) |
| `hysteria2` | QUIC (ALPN `h3`), HTTP/3 `POST /auth` (status 233), `0x401` TCP request frame, `down` (sent as `Hysteria-CC-RX`), `handshake-timeout` | no | `listeners: type: hysteria2` (users map), wrong password, unreachable target |
| `mieru` | TCP single session: PBKDF2-SHA256 time-salt key, XChaCha20-Poly1305 implicit nonce with the user hint, 32-byte metadata, session/data segments, a five-second `ackClientToServer` heartbeat, `port`/`port-range`, `handshake-mode` | no | `listeners: type: mieru` (transport TCP, users map), wrong password, closed peer port, port range, idle session across the heartbeat |
| `masque` | RFC 9298 CONNECT-UDP over HTTP/3 (`quinn` 0.11, TLS 1.3, ALPN `h3`): extended CONNECT (`SETTINGS_ENABLE_CONNECT_PROTOCOL`), one request stream per destination (`:protocol connect-udp`, `/.well-known/masque/udp/<host>/<port>/`), `capsule-protocol: ?1`, `DATAGRAM` capsules with context ID 0 (at most one UDP datagram per capsule), at most 32 destinations per association, a DATA frame larger than one maximal capsule refused, closed flows reclaimed, `sni`/`skip-cert-verify`/`handshake-timeout`, one QUIC connection per UDP association | `udp: true`: CONNECT-UDP flows | controlled HTTP/3 peer in `tests/quic_peers.rs` (request headers, per-destination flows, capsule echo, refusal, missing extended CONNECT/capsule negotiation, untrusted certificate, peer-FIN reopen, 32 closed flows then a new destination) plus the shipped CLI's SOCKS5 UDP ASSOCIATE in `family_cli.rs`; no Mihomo listener exists and the pinned adapter is a Cloudflare WARP CONNECT-IP client |

The mieru module the pinned outbound wraps is GPL-3.0: this repository contains
no mieru source, links no mieru code and derives nothing from its
implementation beyond the published protocol description (`docs/protocol.md`
in that module) and wire observations against the pinned binary, which is used
only as the controlled peer. The earlier `sudoku` port and its Go codec peer
were removed in T13-A3: they were translated from the pinned `transport/sudoku`,
which is part of the GPL-3.0 Mihomo tree, so they were GPL derivatives. No
sudoku code, vectors or attribution data remain. T17 observed the pinned peer
from the outside only (`tool/kernel-compat/sudoku-observe.py`, record in
`tool/kernel-compat/evidence/t17-cleanroom.md`) and produced no client: the
key-derived puzzle table, the KIP handshake and the record layers are not
publicly specified, the encoding randomizes each byte per connection, and a
foreign handshake is rejected with `INVALID_SUDOKU_MAP_MISS`. `type: sudoku`
therefore stays rejected; the audit of the removal is
`tool/kernel-compat/evidence/t13-a3-sudoku-removal.md`.

`dialer-proxy` chains are supported when every hop before the exit is `socks5`
(the hop is entered through the previous hop's SOCKS5 tunnel); any other chain
is rejected at load time or at dial time with a `[unsupported]`/chain error,
never silently bypassed. UDP follows the same rule: a `udp: true` proxy with a
`dialer-proxy` must name exactly one SOCKS5 hop, whose UDP relay carries the
datagrams (TCP and UDP then take the same path, matching Mihomo's
`proxydialer.ListenPacket`). Anything else - a hop without a UDP association,
or a longer chain that would need nested associations - fails at load time with
the hop named, instead of a UDP association dialling the server directly.

### UDP

The mixed inbound serves SOCKS5 `UDP ASSOCIATE`: the reply names the relay
socket, each datagram carries the RFC 1928 address header, and every datagram
is evaluated by the same rule set as TCP before it is forwarded. Per family:

| family | UDP behaviour |
| --- | --- |
| `DIRECT` / `REJECT` | forwarded from one unconnected UDP socket per address family (wildcard-bound, so a loopback listener still reaches remote targets) / dropped before any socket |
| `ss` with `udp: true` | AEAD-2017 datagrams to the server (directly, or through one SOCKS5 `dialer-proxy` hop), replies decrypted and returned with their source address |
| `trojan` with `udp: true` | command `3` over TLS (the server connection is established through the `dialer-proxy` chain like TCP), `addr|length|CRLF|payload` frames both ways |
| `socks5`, `http`, `vless`, `anytls` | **no association**: `udp: true` is rejected at load time; `udp: false` (or absent) loads, and an association routed to such a proxy drops the datagram and logs it |

`vless` UDP would need `packet-addr`/XUDP, `anytls` needs UoT, and a SOCKS5
outbound would need its own UDP relay: all three are explicit gaps recorded in
`tool/kernel-compat/evidence/rust-mapping.json`, not silent successes.
Fragmented datagrams (`FRAG != 0`) are dropped. Destination names are resolved
with the system resolver because there is no in-kernel DNS before T5 (a
datagram to a name therefore leaves with the resolved address, as Mihomo's
system resolver does). For a chained association the *server* name is resolved
once and the whole address set is kept: a multi-A record (or a server answering
from another of its addresses) is accepted, while a reply from an address the
name did not resolve to is dropped. A resolver that returns only one family
(`AI_ADDRCONFIG` on a host without global IPv6, for example) yields a
single-entry set, which is what this host does for `localhost`. Memory per association is bounded: one 64 KiB client
datagram buffer plus one 64 KiB reply buffer per transport actually used, and
the association ends with its control connection or after
`Limits.udp_idle_timeout` (default 60 s).

### Protocol families outside this slice

The pinned parser lists 28 outbound types, matching the status recorded in
`tool/kernel-compat/evidence/rust-mapping.json`:

- **implemented (11)**: `ss`, `socks5`, `http`, `trojan`, `vless`, `anytls`,
  `vmess`, `snell`, `trusttunnel`, `gost-relay`, `ssr`;
- **partial (9)**: `ssh` (one client per dial, no private-key file paths),
  `mieru` and `masque` (TCP slice / CONNECT-UDP only), `tuic`, `hysteria` and
  `hysteria2` (their T10 gaps), `shadowquic` (TCP/UDP and JLS, but `zero-rtt`,
  QUIC `v2` and the private Brutal congestion options are rejected), and
  `wireguard`/`openvpn` (protocol transports implemented, TCP/UDP dial needs
  the T6/T7 userspace IP stack and TUN device);
- **partial (2 more)**: `tailscale` (control/DERP protocol halves; the tunnel
  still needs T6/T7 and registration-only options are rejected) and `zerotier`
  (identity/planet/VL1/VL2 protocol halves; the controller membership exchange
  is T5, the TCP fallback transport is rejected and the tunnel needs T6/T7);
- **unimplemented (2)**: `sudoku` (the clean-room port is blocked; rejected by
  name) and `easytier` (the pinned core's `network_secret_digest` is not
  reproducible offline; both cleartext and encrypted forms are rejected);
- **built-ins (4)**: `direct`, `dns`, `reject` and `rematch` as `proxies`
  entries (T5).

Every unimplemented type is rejected by name at load time, so no configuration
is silently reduced:

| families | why not here | task / decision |
| --- | --- | --- |
| `wireguard`, `openvpn` | the protocol halves are implemented (`src/outbound/wireguard.rs`, `src/outbound/openvpn.rs`) and verified against controlled peers, but turning their IP packets into TCP streams needs the userspace IP stack and TUN device owned by T6/T7 | **T16**: transport + configuration semantics; a `dial()` names the T6/T7 device gap. `outbound::wireguard::WireguardTunnel` and `outbound::openvpn::OpenVpnTunnel` are the interfaces for that layer |
| `tailscale`, `zerotier` | the protocol/configuration adapters are implemented in `src/outbound/{tailscale,zerotier}.rs` and verified against controlled peers built from the locked Go modules; the tunnel's TCP/UDP socket layer needs the T6/T7 userspace IP stack and TUN device | **T19 partial**: control/DERP and identity/planet/VL1/VL2 are available to T6/T7/T5; `dial()` names the device gap; registration-only Tailscale prefs and ZeroTier TCP fallback are rejected by name |
| `easytier` | the pinned core's cleartext `network_secret_digest` is derived inside the wasm artifact and no source/crate is in the offline cache; a placeholder digest is rejected by the real core | **T19 rejected by name**; no cleartext or encrypted compatibility is claimed; device/TUN remains T6/T7 |
| `direct`, `dns`, `reject`, `rematch` as `proxies` entries | built-ins of Mihomo; the kernel already has `DIRECT`/`REJECT` rules and no `dns`/`rematch` adapters | **T5** (rules/rematch integration) |

T13 delivered `mieru` in the single-session TCP slice: an independent
implementation of the published protocol (the module is GPL-3.0, so no mieru
code is vendored or linked; only the pinned binary runs it as a peer). The
earlier `sudoku` port was removed in T13-A3 because it was translated from the
GPL-3.0 pinned `transport/sudoku`; `type: sudoku` is rejected by name, and
T17's clean-room attempt recorded why it stays that way: the table, handshake
and record layers are not publicly specified (see
[Not implemented](#not-implemented)). mieru's rejected pieces are named in
[Not implemented](#not-implemented).

T14's `masque` is the RFC 9298 CONNECT-UDP subset, written from the RFCs over
the same `quinn`/`rustls` stack as T10 (no `h3`/`connect-ip-go`/IP-stack code
is vendored). The pinned `adapter/outbound/masque.go` is a Cloudflare WARP
client: it sends `:protocol cf-connect-ip` after pinning the endpoint's ECDSA
key and presenting a generated client certificate, then terminates the returned
IP packets in a userspace stack (`connect-ip-go`/mipstack or gVisor). That is
what serves TCP, and it is not implemented here (T18): the `private-key`,
`public-key`, `uri`, `network: h2|h3-l4proxy`, `ip`, `ipv6`, `mtu`,
`ip-stack`, `remote-dns-resolve` and `dns` options are rejected by name at load
time, and a TCP dial through `masque` fails with the CONNECT-IP/IP-stack
reason. Because the pinned options describe that WARP registration, an
RFC 9298 endpoint is configured with `server`/`port` plus `udp: true` and has
no `private-key`/`public-key`; the evidence file records this as the boundary
rather than claiming the pinned shape. One association opens at most 32
destination streams, each with a two-payload queue and a one-datagram capsule
and DATA-frame bound (65,535-byte UDP payload; a larger DATA frame is refused); the worst-case per-association
memory, including T10's QUIC windows, is recorded for T7
(`tool/kernel-compat/evidence/t14-feasibility.json`) and is below 20 MB
(decimal) for one association; T7 must cap concurrent associations. CONNECT-IP, the IP stack and the pinned WARP
shape are T18.

T15's `shadowquic` is an independent implementation of the JLS random seal,
written from the locked `jls-tls` behaviour and observed on the wire. JLS is not
an RFC 6066 extension: it replaces the 32-byte TLS 1.3 ClientHello/ServerHello
`random` with `AES-256-GCM(SHA-256(password || hello-with-zero-random),
SHA-256(username || hello-with-zero-random), random[0..16])`. `rustls` does not
expose a ClientHello hook, so the client builds the hello twice with a recorded
OS-seeded randomness stream and substitutes the one fill that produced the
`random`; the replay is checked byte-for-byte against the dry hello before the
connection proceeds. The locked `jls-tls` package is used only by
`tool/kernel-compat/peers/shadowquic-jls-vectors` to emit real hello vectors
(`native-kernel/crates/billow-kernel/tests/data/shadowquic-jls.txt`); no Go
code is linked or copied. The pinned `jls-tls` package is BSD-3-Clause
(Copyright 2009 The Go Authors); its complete copyright, conditions and
disclaimer are in `native-kernel/THIRD_PARTY_NOTICES.md`. The transport framing
provenance, the black-box observation matrix and the no-copy audit — including
the residual caveat that the first framing constants were confirmed against the
pinned GPL source — are in
`tool/kernel-compat/evidence/t15-cleanroom.md`; no GPL-3.0 source is vendored,
linked, or copied. The QUIC wire format is ordinary QUIC v1 (the pinned
`jls-quic-go` modifications are the server-side camouflage forwarding and the
TLS hook), so `quinn` carries it unchanged. TCP uses `CommandConnect` + a
SOCKS5 address; UDP uses `CommandAssociateDatagram` + QUIC datagrams or
`CommandAssociateStream` + one uni stream per destination. QUIC datagram
payloads are bounded by the path MTU as well as `max-datagram-frame-size`
(quinn starts at 1200 bytes); a larger payload fails with a named error and
`udp-over-stream` carries large packets as `u16`-length frames. A peer-stopped
uni stream is detected on the next write and reopened; a closed control stream
is rebuilt with all live target ids re-registered. Both paths are covered by
`tests/shadowquic_stream.rs` against an independent quinn peer. `quinn-proto` and
`typenum` became direct dependencies for the session wrapper and the 32-byte
GCM nonce; both versions were already in the lockfile (no new download).
`recv-window-conn`/`recv-window` default to the kernel's T7 budget (512 KiB
stream / 2 MiB connection) instead of the pinned 1.57 MiB / 6.4 MiB initial
windows; these are local flow-control choices, not wire fields. `rustls` still
verifies the CertificateVerify signature after JLS
authentication (the pinned Go client skips it), but a real server's camouflage
certificate is a valid key pair, so the handshake succeeds; the pinned peer
tests confirm it. A JLS failure aborts before any shadowquic request is sent,
even if `skip-cert-verify` was supplied (the pinned type does not declare that
key, so it is ignored like Mihomo ignores it).

The remaining gaps are named in [Not implemented](#not-implemented):
`ssh` rejects private-key file paths and opens one SSH client per dial;
`gost-relay` rejects the certificate-pinning knobs (`name-cert-verify`,
`fingerprint`, `certificate`, `private-key`, `client-fingerprint`); `ssr` and
`gost-relay` reject only the transport knobs Mihomo accepts and ignores
(`ip-version`, `tfo`, `mptcp`, `interface-name`, `routing-mark`). `ssh` uses `russh` 0.56 with the `ring` backend; `russh` 0.64
requires Rust 1.89 and its default `aws-lc-rs` backend would add a C/CMake
build, so it is not used. `russh` 0.56 declares MSRV 1.85 but its transitive
`home` 0.5.12 declares 1.88 and the Windows-only `pageant` 0.2.5 declares 1.89
(`uuid` 1.29.3 already declared 1.89 in the previous lock), so T11 raised the
workspace `rust-version` to 1.89 instead of shipping an inconsistent MSRV.
`03-execution-plan.md`
defines T9/T11 (non-QUIC), T10 (QUIC), T16 (device-family protocol halves;
device/TUN and the IP stack remain T6/T7) and T5's integration of their output. The capability index
records each family at the status the kernel actually reaches: `implemented`,
`partial` (with the missing options named) or `unimplemented`; none can be
reported as compatible.

### Not implemented

Every option a proxy entry contains must be one this kernel honours: the
loader reads only implemented keys and rejects the rest with the key named.
With the pinned option tables that means `tfo`, `mptcp`, `interface-name`,
`routing-mark`, the trojan/vless `smux` block, `udp-over-tcp`,
`udp-over-tcp-version`, `ech-opts`,
`shadow-tls-opts`, `restls-opts`, `jls-opts`, `fingerprint`, `certificate`,
`private-key`, `name-cert-verify`, `reality-opts`, `grpc-opts`, `http-opts`,
`h2-opts`, `xhttp-opts`, `ss-opts`, `plugin`/`plugin-opts`, ws early data and
`v2ray-http-upgrade-fast-open`, `client-fingerprint`, `ip-version`, vless
`flow`/`packet-addr`/`xudp`/`packet-encoding`/`ws-headers`, anytls
`client-metadata`/`idle-session-*`/`min-idle-session`/`disable-reuse`, vmess
`alterId > 0`/`packet-addr`/`xudp`/`packet-encoding`/`global-padding`/
`authenticated-length` and the vmess mux/TLS-mirror blocks, snell
`version: 4-6`/`reuse`/`mode`/obfs `tls`, trusttunnel
`udp`/`quic`/`health-check`/`max-connections`/`min-streams`/`max-streams`/
`congestion-controller`/`cwnd`/`bbr-profile`, gost-relay
`name-cert-verify`/`fingerprint`/`certificate`/`private-key`/
`client-fingerprint`, ssh private-key file paths, and `udp: true` on
`socks5`/`vless`/`anytls`/`vmess`/`snell`/`trusttunnel`
(no UDP association for those families). T10's families reject the options
they do not implement by name: `tuic` `token` (v4/BLAKE3), `udp-relay-mode:
quic`, `udp-over-stream`, `reduce-rtt`, `fast-open`, congestion/window tuning;
`hysteria` `ports`/`hop-interval` (port hopping), `obfs` (XPlus),
`protocol: faketcp|wechat`, `fast-open`, receive-window/MTU tuning;
`hysteria2` `ports`/`hop-interval`, `obfs` (Salamander/Gecko), `realm-opts`,
`up` (the pinned Brutal TX-rate cap; quinn has no Brutal controller),
`udp-mtu`, congestion/window tuning. `mieru` rejects `transport: UDP`,
`udp: true`, the multiplexing levels (one session per underlay) and
`traffic-pattern` (padding/nonce/low-entropy shaping); `sudoku` is rejected as
a whole type because its earlier port was a GPL-3.0 derivative and was removed
in T13-A3, and T17's clean-room attempt found the keyed table, the KIP
handshake and the record layers are not publicly specified
(`tool/kernel-compat/evidence/t17-cleanroom.md`). `masque` rejects the
pinned CONNECT-IP/WARP pieces (`private-key`, `public-key`, `uri`, `ip`,
`ipv6`, `mtu`, `ip-stack`, `remote-dns-resolve`, `dns`), both non-HTTP/3
networks (`h2`, `h3-l4proxy`), the congestion knobs and `dialer-proxy` (a QUIC
endpoint is dialled locally); its `udp: false` form loads and refuses every
dial. `shadowquic` rejects `zero-rtt` (JLS 0-RTT needs the pinned
authenticated session ticket), `quic-versions: v2` (quinn 0.11 implements v1
only), `congestion-controller`/`bbr-profile`/a non-default `cwnd`/`up`/`down`
(the private Brutal controller is not in quinn) and `dialer-proxy`; its
`skip-cert-verify`/`udp`/`tls` keys are not declared by the pinned type, so
they load and are ignored exactly as Mihomo ignores them. `wireguard` rejects
`amnezia-wg-option` (AmneziaWG's header obfuscation is a different device,
implemented by the pinned `amneziawg-go`), an explicit `ip-stack` mode /
congestion controller, `remote-dns-resolve`/`dns` (the stack resolver),
`refresh-server-ip-interval` (the runtime endpoint loop) and `dialer-proxy`;
its `mtu`/`workers`/`udp`/`persistent-keepalive` and both peer forms are
accepted and used by the transport. `openvpn` rejects `tls-auth`/`tls-crypt`/
`tls-crypt-v2` (the static-key control-packet codec), `comp-lzo: yes|adaptive`
(compression), the CBC data ciphers and a non-`tun` `dev`; it implements the
AEAD data ciphers, the `data-ciphers` negotiation, inline `ca`/`cert`/`key`,
username/password, `peer-info`, UDP and TCP framing. The mesh
families are partial: `tailscale` exposes the control-base Noise/HTTP2 and DERP
layers but rejects `hostname`, `auth-key`, `state-dir`, `ephemeral`,
`accept-routes: true`, `exit-node` and `exit-node-allow-lan-access: true`
because node registration/control-plane prefs are not implemented; `zerotier`
accepts the identity, planet, MTU, port, orbit, low-bandwidth and
encrypted-HELLO options, rejects an explicit `ip-stack`,
`remote-dns-resolve`/`dns`, remote trace and the TCP fallback transport
(`force`/non-empty relay) with the T6/T7/T5 boundary. `easytier` is rejected as
a whole type with the pinned core digest gap named. Every loadable mesh
`dial()` names the T6/T7 gap.
`udp: false` is accepted for a family that has no UDP association because it
states the same thing this kernel does; `udp` is not a
Mihomo HTTP option at all and is rejected there. Unsupported protocol types are
listed in the error message.

The rule is mechanical: `reject_unknown` accepts only keys the parser read and
honoured, so a new option cannot be "documented as rejected" while being let
through by an option table. The only keys accepted without an effect are
boolean no-ops that ask for nothing (`udp: false`, `disable-reuse: false`,
`packet-addr: false`, `xudp: false`, `v2ray-http-upgrade-fast-open: false`),
empty blocks (`grpc-opts: {}`, `ech-opts: {enable: false}`, `smux: {enabled:
false}`, `ss-opts: {}`, `shadow-tls-opts: {}`, `restls-opts: {}`, `plugin-opts:
{}`) and TLS-only options when TLS is off (`skip-cert-verify`, `sni`, `alpn`,
`fingerprint`, `certificate`, `private-key`, `name-cert-verify`,
`client-fingerprint`, `ech-opts`). `ech-opts` is disabled unless `enable: true`
(other fields are then ignored, as in Mihomo), and `plugin-opts` is ignored
unless a plugin is configured. `vmess` requires `alterId` and `cipher` (Mihomo's
decoder reports them as unset fields when absent) and only accepts
`alterId: 0`; `snell` accepts versions 1-3 and the HTTP obfs mode; `ssr`
requires `cipher`, `password`, `protocol` and `obfs` (the pinned type declares
them without `omitempty`), accepts every value the pinned plugins register, and
passes `*-param` to the plugin that defines it (`protocol-param` names the user
id/key for `auth_aes128_*`/`auth_chain_*`, `obfs-param` the HTTP host/body and
the TLS SNI). Their
unimplemented options (`udp: true`, `packet-addr`, `xudp`, `packet-encoding`,
`global-padding`, `authenticated-length`, `grpc-opts`/`h2-opts`/`http-opts`,
`reality-opts`/`ech-opts`/`shadow-tls-opts`/`restls-opts`/`jls-opts`,
`tlsmirror-opts`/`mekya-opts`/`mkcp-opts`, snell `version: 4-6`/`reuse`/`mode`,
and the snell obfs `tls` mode) are rejected with the key named. Keys the pinned type does not declare at all
(`smux`, `ss-opts` on vless, `udp` on http, any unknown name) are ignored, which
is what Mihomo does with them. Three cases are rejected even when "empty":
`reality-opts` and `jls-opts` require fields (Mihomo rejects the empty block),
and `reality-opts`/`shadow-tls-opts`/`restls-opts`/`jls-opts` require
`tls: true` (Mihomo rejects them without TLS, so they are not ignored). The
same keys are ignored on a type whose option table does not declare them
(`socks5`/`http`/`ss`); `anytls` does declare them and applies them as a
security mode, so there a content block stays a registered rejection.

A transport block for a transport the configuration did not select
(`grpc-opts`, `http-opts`, `h2-opts`, `xhttp-opts` with `network: tcp|ws`) is
ignored by Mihomo even when it has content, so it is accepted here too; the
selected transport itself (`network: grpc|http|h2|xhttp`) is rejected.

`tool/kernel-compat/option-probe.mjs` runs the matrix against the pinned
Mihomo `-t`: every no-op form (including unknown keys and disabled switches
with extra fields) must be accepted by both engines, and every enabled form
must be rejected by the kernel with the field named **and** be registered in
`rust-mapping.json` (a rejection of an unregistered key is reported as a
problem, so the matrix cannot hide an over-strict parser). Mihomo's own verdict
is recorded; forms it rejects need no implementation. The result and its counts
are in `tool/kernel-compat/evidence/option-matrix.txt`.

## CLI

```
cargo run -p billow-kernel-cli -- <config.yaml> [--port N] [--geosite-dir DIR] \
    [--buffer-bytes N] [--max-sessions N] [--check]
```

`--check` validates the configuration and rule set, starts the listener to prove
the bind, prints the identity and exits. A normal run prints one identity line,
serves until SIGINT/SIGTERM (on Windows the host drives the library API; T6),
then prints a session summary:

```
instance=<uuid> pid=<pid> version=0.1.0 listen=127.0.0.1:17890 overridden_port=- config=sha256:<digest> rules=3 geosite_dir=- state_dir=-
features: mixed-inbound(tcp,http-connect,socks5); rules=inline(3 entries); outbounds=DIRECT,REJECT; protocols=ss1=ss,tj1=trojan,jump=socks5,vl1=vless; dns=none
stopped instance=<uuid> accepted=4 active=0 completed=2 rejected=2 failed=0 bytes_up=40 bytes_down=40
```

SIGINT stops accepting, closes live tunnels and joins every session task before
the process exits, so a restart can immediately rebind the same port.

## Library API

```rust
use billow_kernel::{Kernel, Limits};

let yaml = "mixed-port: 17890\nproxies:\n  - {name: p, type: socks5, server: 127.0.0.1, port: 1080}\nrules:\n  - 'MATCH,p'\n";
let (mut kernel, warnings) = Kernel::start_from_yaml(yaml, None, Limits::default())?;
println!("{}", kernel.identity().to_line());   // uuid, pid, version, listen, digest, features
let (action, rule) = kernel.evaluate("example.com", None);
kernel.stop()?;                                // no live sessions or tasks remain
```

Stable entry points:

- `Kernel::start(path, geosite_dir, limits)` / `Kernel::start_from_yaml(yaml, geosite_dir, limits)`
  / `Kernel::start_with_yaml(&LoadedConfig, geosite_dir, limits)` — the last one
  lets a host adjust the listener before binding and keeps the warnings.
- `Kernel::identity()`, `Kernel::listen_addr()`, `Kernel::stats()`,
  `Kernel::evaluate(host, ip)`, `Kernel::config()`, `Kernel::stop()`.
- `load_config` / `parse_rule` for validation without starting.
- `Limits { buffer_size, max_sessions, handshake_timeout, dial_timeout, half_close_timeout, udp_idle_timeout }`.

`Drop` stops a kernel that was not stopped explicitly; `stop()` is synchronous
and waits for the listener thread and all session tasks.

`examples/embed.rs` shows the same path a host (or the iOS extension) takes:
`cargo run -p billow-kernel --example embed -- <config.yaml>`. Both entries
carry protocol outbounds: `tests/protocols.rs` (`embedded_api_*`) and
`crates/billow-kernel-cli/tests/cli.rs` (`process_forwards_through_a_protocol_outbound`)
exercise a real tunnel through a configured `socks5` proxy from each side.

## Resource and concurrency invariants

- One fixed buffer per relay direction (`buffer_size`, default 16 KiB) and at
  most `max_sessions` sessions (default 256). Further connections stay in the
  listening backlog until a slot frees.
- Both relay directions run inside the session future (a `select` over two
  pinned copies); a stop request drops them with the session, so no task, buffer
  or socket outlives `stop()`.
- A tunnel ends when both directions finish; EOF is forwarded as a write-side
  shutdown (half-close). If the second direction stalls after the first ends, it
  is cut after `half_close_timeout` (default 30 s) so no session waits forever.
- A SOCKS5 UDP association owns one 64 KiB client buffer, one 64 KiB reply
  buffer per transport used and its sockets; it ends with the control
  connection or after `udp_idle_timeout`, and `stop()` joins it like any other
  session.
- Handshake and dial have their own deadlines. Handshake failures reply to the
  client (SOCKS5 reply code / HTTP status) before the socket closes.
- Every accepted connection increments `active` and decrements it exactly once;
  `stop()` joins all session tasks, so `active == 0` afterwards.

## Tests

Default suite (no external binaries; real loopback listeners):

```sh
cargo test --manifest-path native-kernel/Cargo.toml --locked
```

- `tests/config.rs` — parsing, strict option tables, error tags.
- `tests/sessions.rs` — inbound sessions, half-close, stop/restart, limits.
- `tests/quic_peers.rs` — T10/T14 QUIC loopback peers: TUIC v5 (auth token,
  domain and IP targets, wrong password, v4 token rejection, unimplemented
  options, `request-timeout` bounding a blocked stream open), Hysteria v1
  (control hello, `auth-str` and base64 auth, wrong auth,
  port-hopping/XPlus/faketcp rejection, rate validation), the Hysteria2 `up`
  rejection, and the MASQUE CONNECT-UDP peer (request headers and proxy
  authority, one flow per destination, capsule echo, a refused request, a peer
  without extended CONNECT, a 200 without the capsule protocol, an untrusted
  certificate, and the named TCP refusal). The peers are `quinn` servers
  written from the pinned Go framing or the RFCs; they need `openssl` for the
  loopback certificate.
- `tests/protocols.rs` — loopback peers for socks5/http/ss/trojan/vless
  (tcp, websocket, `v2ray-http-upgrade`), trojan websocket, the SOCKS5
  `UDP ASSOCIATE` relay (DIRECT, REJECT and ss datagrams), a private-CA TLS
  case for three families, positive and negative cases, plus the embedded-API
  entry. `vmess`, `snell` and `trusttunnel` have no loopback peer here: their
  wire formats are covered by the Go-pinned unit vectors in
  `src/outbound/{vmess,snell,trusttunnel}.rs` and by the real-peer cases below.
  The T11/T12 families have controlled loopback peers here: `gost-relay` (relay
  v2 header/auth/forward/TLS/status, the UDP association, and the smux session),
  `ssh` (a real `russh` server with password, Ed25519 key and pinned-host-key
  cases), `ssr` (origin/plain server plus pinned Go cipher vectors) and
  `gost-relay`'s smux session (`cli_process_tunnels_through_gost_relay_mux`;
  the SSR plugin layers run through the real binary in the controlled entry,
  `cli_process_tunnels_through_an_ssr_plugin`); they are also the explicit entry
  point of `tool/kernel-compat/family-peers.sh`.
  `random_head` locates the peer's head by scanning the CRC from the longest
  candidate: the pinned check is not unique for every length
  (`crc32(head[:n-1])` can equal the four bytes at `n-1`), and an ascending scan
  occasionally took the head one byte short and misaligned the cipher stream.
  The regression test is `random_head_length_picks_the_real_boundary`. The
  peer's address read and the client roundtrips are bounded, so a wrong
  password fails in seconds instead of leaving both sides waiting.
  `family-peers.sh` additionally builds the two independent Go SSR peers
  (`peers/ssr-server` for origin/plain and `peers/ssr-plugins` for every
  protocol and obfs plugin plus UDP), requires the *pinned* client packages to
  accept `peers/ssr-plugins` for all 36 protocol/obfs combinations, runs
  `tests/independent_peers.rs` (matrix, wrong passwords, protocol-param with
  large payloads, UDP), and builds `peers/gost-relay-harness` — the *pinned*
  `gost.NewRelayDialer` with `mux` and the UDP association — to drive the same
  gost-relay peer. The framing is therefore checked against the locked
  implementations, not only against the Rust client.
- `tests/mihomo_peers.rs` — real-peer interop: each case starts the pinned
  Mihomo v1.19.34 binary with one `listeners:` entry, the Rust kernel dials it
  as a client and the test asserts what a controlled sink received (and, for
  the negative cases, that it received nothing). The cases are `#[ignore]`d so
  the default suite reports them as ignored instead of passing or failing
  without the peer. The controlled command needs the pinned binary and the
  `openssl` CLI (or `KC_CERT_DIR`):

  ```sh
  # resolves the repo root and the pinned binary, then runs the cases serially
  tool/kernel-compat/peer-tests.sh

  # or explicitly (the cargo test process runs from native-kernel/crates/billow-kernel,
  # so a relative KC_MIHOMO_BIN would not resolve)
  KC_MIHOMO_BIN=/Users/yanggeng/github/Billow/tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
    cargo test --manifest-path native-kernel/Cargo.toml --locked \
    --test mihomo_peers -- --ignored --test-threads=1
  ```

  Without `KC_MIHOMO_BIN` each case prints `SKIP <case> (not verified): ...` and
  returns; a skipped case is **not** a pass. `KC_KERNEL_LOG=1` prints the
  kernel's own warnings, `KC_KERNEL_LOG=debug` its debug events, and a failing
  case prints the peer's config and log. The family coverage (TCP and UDP) is
  summarised in `tool/kernel-compat/evidence/protocol-peers.json`; T9 added
  `vmess` (aes-128-gcm, chacha20-poly1305, `none`, websocket, domain target,
  wrong uuid), `snell` (v1, v2, v3 + http obfs, wrong psk) and `trusttunnel`
  (HTTP/2 CONNECT, domain target, wrong password), 36 cases in total. T10
  added TUIC v5 and Hysteria2 against their Mihomo listeners (success and wrong
  password), 40 cases in total; Hysteria v1 has no Mihomo listener and is
  covered by `tests/quic_peers.rs`.
  T11's `gost-relay`, `ssh` and `ssr` have no Mihomo listener, so their peer
  cases live in `tests/protocols.rs` / `tests/independent_peers.rs` and are
  recorded under `controlledPeers` in
  `tool/kernel-compat/evidence/protocol-peers.json`. The
  CLI crate also drives a real success tunnel through each of the three
  (`crates/billow-kernel-cli/tests/family_cli.rs`), not only a config load; the
  same file now drives TUIC, Hysteria v1 and Hysteria2 through the real
  `billow-kernel` process as well.

  T13 added 5 mieru cases against `listeners: type: mieru`: the TCP session,
  `port-range`, an idle session across the five-second heartbeat, a wrong
  password and a closed peer port. The sudoku cases and their locked-codec
  differential were removed with the GPL-derived implementation in T13-A3;
  T17 recorded what the pinned Sudoku peer does with foreign traffic
  (`tool/kernel-compat/sudoku-observe.py`, `evidence/t17-observe.log`) but has
  no peer case because no Sudoku client exists.
  T15 added 4 shadowquic cases: TCP, UDP over QUIC datagrams, UDP over
  `udp-over-stream`, and a wrong-password case that is forwarded to the
  camouflage upstream and never reaches the sink. The JLS seal is also
  cross-checked against real hello messages from the locked Go package via
  `tool/kernel-compat/peers/shadowquic-jls-vectors`; the vectors are committed
  at `native-kernel/crates/billow-kernel/tests/data/shadowquic-jls.txt` and
  consumed by `src/outbound/jls.rs::tests::verifies_locked_jls_client_and_server_hellos`
  (a default-suite test; the generator needs `go` and the module cache).
  `tests/shadowquic_stream.rs` is a default-suite controlled quinn peer that
  stops a client uni stream and closes the control send half; it proves the
  client reopens the uni stream and rebuilds the control association with the
  live ids. `tool/kernel-compat/peer-tests.sh` runs 50 cases in total. T14's
  `masque` has no Mihomo listener (the pinned adapter is a Cloudflare WARP
  client) and no reachable HTTP/3 masque endpoint offline, so its six cases run
  against the controlled HTTP/3 peer in the default `tests/quic_peers.rs` suite
  and are recorded under `families.masque` in `protocol-peers.json`; the
  dependency/memory boundary is in `evidence/t14-feasibility.json`. mieru has
  no Go vector tool because the module is GPL-3.0: the client is written from
  `docs/protocol.md` and is only verified against the pinned server, with the
  locally computed PBKDF2/time-salt vectors in `src/outbound/mieru.rs`.

  Observed host behaviour: starting the peer for many cases in one test process
  occasionally ends with a case where the kernel established the tunnel but the
  sink received nothing (the peer's own log shows its listener up and no
  connection). The same cases pass in isolation and in complete runs (recorded
  in `tool/kernel-compat/evidence/protocol-peers-run.log`); the suite is run
  with `--test-threads=1` and a rerun of the same command is the documented
  recovery. A rerun is never recorded as a first-attempt pass.

The cases share one process; each allocates its own loopback ports from a
process-wide registry and the suite serialises the peer runs (one kernel plus
one Mihomo process at a time), because several in flight starve a
just-accepted session on a loaded host and make a positive case look like a
missing marker.

## Coordination

The immutable coordination inputs are in `docs/coordination/`: `t11-handoff.md`
(this subset), `t12-handoff.md` (SSR plugin layers and gost UDP/smux),
`t13-handoff.md` (mieru and sudoku) and `t14-handoff.md` (masque). They are
Owner material and are not modified by the kernel tasks. The concrete blockers
and next steps for the families still deferred by T10 are in
`tool/kernel-compat/evidence/t10-feasibility.json`; T13's handoff covers mieru
(sudoku was removed in T13-A3; T17's clean-room attempt recorded the protocol
as not publicly specified, `evidence/t17-cleanroom.md`), T14's covers
`masque` (the CONNECT-UDP subset and the CONNECT-IP
gap recorded in `evidence/t14-feasibility.json`), and T15's covers
`shadowquic` (the JLS subset and its named rejections). With T15 the T9 list
has an entry for every family, though `masque` and `shadowquic` remain partial;
neither is claimed as compatible.

## Controlled verification commands

```sh
# the differential harness (same fixtures against Mihomo and billow-kernel)
cargo build --release --manifest-path native-kernel/Cargo.toml --locked -p billow-kernel-cli
node tool/kernel-compat/runner.mjs \
  --mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
  --rust native-kernel/target/release/billow-kernel \
  --cache tool/kernel-compat/.cache --report-dir tool/kernel-compat/evidence

# the harness's own acceptance command
node --test tool/kernel-compat/runner.test.mjs

# controlled peers for the families with no Mihomo listener (gost-relay, ssh,
# ssr), the independent Go SSR peers (including the pinned-client cross-check)
# and the pinned SSR cipher vectors; T16 adds the wireguard-go device peer and
# the OpenVPN 2.7.9 binary peer; needs `go`
tool/kernel-compat/family-peers.sh
```

## Platform notes

- macOS arm64 is the platform where sessions and every protocol family were run
  against the pinned Mihomo (T4/T9/T10 evidence in
  `tool/kernel-compat/evidence/protocol-peers.json`). Linux/Android compile
  from the same Unix code path; Windows compiles, but the platform session
  path (TUN/system proxy ownership, no `dup(2)` use anymore) is T6.
- The QUIC families use `quinn` 0.11.12 (quinn-proto 0.11.19, quinn-udp
  0.5.16) with `rustls` 0.23 and TLS 1.3 only. One endpoint and connection are
  created per dial; there is no connection pool yet. The dependency profile is
  recorded in `tool/kernel-compat/evidence/rust-mapping.json` (`quicProfile`)
  and `protocol-peers.json` (`t10`); T7 must measure the whole iOS extension
  against the 40,000,000-byte budget. There is no JLS crate and no
  WireGuard/mesh/OpenVPN crate in the offline cargo cache; `shadowquic`
  implements the JLS seal in-tree and the locked Go package is a vector
  generator only. T16 implements the WireGuard Noise IK/transport in-tree with
  the already-locked `blake2` 0.10.6 (new direct dependency), `x25519-dalek`,
  `chacha20poly1305` and `rand`, and the OpenVPN control/data channel with
  `rustls`+`ring`, `aes-gcm`, `chacha20poly1305`, `hmac`/`sha1` and the MD5
  already in `keys.rs`. Their peer runs are macOS arm64 only (the OpenVPN
  binary is the Homebrew 2.7.9 bottle; the WireGuard peer is built from the
  cached MIT module). The pinned GPL-3.0 adapters were read for option/wire
  facts only; no source is vendored or linked, and the audit plus its
  clean-room limits are in `tool/kernel-compat/evidence/t16-provenance.md`.
  `quinn-proto` and `typenum` are direct dependencies because
  the JLS session wrapper needs `quinn_proto::crypto::Session` and the
  32-byte GCM nonce; both were already in the lockfile. The JLS ClientHello is
  produced by a recorded-random replay of rustls's own hello; if a future
  rustls changes the draw order the replay check aborts the connection with a
  named error instead of sending an unauthenticated request.
- Outbound TLS uses `rustls` with the platform trust store plus configured
  extra roots. `tls: {custom-cert}` roots are process-wide: a second kernel in
  the same process with different roots is rejected instead of silently keeping
  the first anchors.
- The crate builds `crate-type = ["rlib", "staticlib"]`; no Tauri, UIKit or
  NetworkExtension symbols are referenced.
