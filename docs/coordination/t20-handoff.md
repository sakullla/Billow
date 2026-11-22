# T20 coordination handoff

Immutable inputs for Task T20 (EasyTier).

- Family: `easytier`. The pinned wasm core derives `network_secret_digest` inside the artifact; that derivation is not reproducible offline, so T19 rejects the whole type explicitly.
- Integration owner: T9.
- Write scope: `native-kernel/`, `tool/kernel-compat/`.
- Implement only if the digest derivation becomes reproducible from public documentation or a compatible artifact; otherwise keep the explicit rejection and record the material gap.
- Do not copy GPL/LGPL code; the locked EasyTier module may only be a test-only separate process.
- Device/TUN ownership remains with T6/T7.
- Do not modify this file.
