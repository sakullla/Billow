# T14 coordination handoff

Immutable inputs for Task T14 (masque).

- Family: `masque` (HTTP/3 CONNECT-IP/CONNECT-UDP plus an IP stack).
- Integration owner: T11. QUIC dependency profile is shared with T10; align versions and record the memory cost for T7's 40 MB budget.
- Write scope: `native-kernel/`, `tool/kernel-compat/`.
- Verify against pinned Mihomo or a controlled HTTP/3 peer; keep unimplemented paths explicit.
- Do not modify this file.
