# T12 coordination handoff

Immutable inputs for Task T12 (complete ssr plugin layers and gost-relay transport options).

- Families: `ssr` (protocol auth_sha1_v4/auth_aes128_md5/auth_aes128_sha1/auth_chain_a/auth_chain_b; obfs http_simple/http_post/random_head/tls1.2_ticket_auth/tls1.2_ticket_fastauth) and `gost-relay` (UDP association, smux).
- Integration owner: T11. T11 verifies the combined candidate.
- Write scope: `native-kernel/`, `tool/kernel-compat/`.
- Use the pinned Mihomo source under `tool/kernel-compat/.cache/source/` for wire formats and build controlled peers; record how each peer is built.
- Keep unimplemented options explicit; do not claim compatibility without a peer case.
- Do not modify this file.
