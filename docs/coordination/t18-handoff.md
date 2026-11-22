# T18 coordination handoff

Immutable inputs for Task T18 (masque CONNECT-IP, IP stack, WARP shape).

- Scope: RFC 9484 CONNECT-IP (IPv4/IPv6 capsules), a minimal IP stack, and the pinned Cloudflare WARP config shape (private-key/public-key/uri/ip/ipv6/mtu/ip-stack/remote-dns-resolve/dns). The RFC 9298 CONNECT-UDP subset from T14 must keep working.
- Integration owner: T9. Align the QUIC/h3 profile with T10/T14 and record memory for T7's 40,000,000-byte budget.
- Write scope: `native-kernel/`, `tool/kernel-compat/`.
- Do not copy GPL-3.0 code; implement from public RFCs and black-box observations.
- Unimplemented paths must be explicit rejections with reasons.
- Do not modify this file.
