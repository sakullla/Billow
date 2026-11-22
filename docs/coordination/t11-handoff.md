# T11 coordination handoff

Immutable inputs for Task T11 (remaining non-QUIC protocol families).

- Families: `ssr`, `ssh`, `mieru`, `masque`, `gost-relay`, `sudoku`.
- Integration owner: T9. T11 delivers implementations and per-family evidence; T9 verifies the combined candidate.
- Write scope: `native-kernel/`, `tool/kernel-compat/`.
- Interface expectations:
  - Add outbound modules under `native-kernel/crates/billow-kernel/src/outbound/` and wire them in `outbound/mod.rs` and `proxies.rs`.
  - Keep unimplemented options explicit (`[unsupported]` with the field name); never load a config as compatible when behavior differs from pinned Mihomo v1.19.34.
  - Record per-family peers in `tool/kernel-compat/evidence/protocol-peers.json` and capability status in `rust-mapping.json`.
- Unresolved decisions:
  - `ssr` and `gost-relay` have no Mihomo listener; build a controlled local peer from the pinned source or a documented independent implementation.
  - `ssh` needs an MSRV decision (russh 0.64 requires Rust 1.89; workspace MSRV is 1.85).
  - `mieru` wraps external `enfein/mieru` v3.39.0; decide vendor/port vs explicit deferral.
  - `masque` needs HTTP/3 and an IP stack; align with T10's QUIC dependency profile.
  - `sudoku` is ~13.6k lines of custom crypto/KIP/multiplexing; split or defer with an explicit decision.
- Do not modify this file. Report progress and gaps through the Task result.
