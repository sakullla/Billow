# T15 coordination handoff

Immutable inputs for Task T15 (ShadowQUIC).

- Family: `shadowquic` (JLS custom TLS extension + modified QUIC; pinned implementation uses jls-tls/jls-quic-go).
- Integration owner: T5.
- Write scope: `native-kernel/`, `tool/kernel-compat/`.
- If the JLS/QUIC dependency cannot be obtained offline, record the exact dependency decision and keep explicit rejection; do not fake wire compatibility.
- Do not modify this file.
