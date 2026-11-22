# T13 coordination handoff

Immutable inputs for Task T13 (vendor/port mieru and sudoku).

- Families: `mieru` (external enfein/mieru v3.39.0: encrypted underlay, padding, handshake modes, multiplexing) and `sudoku` (custom crypto/KIP/HTTP-mask/multiplexing, ~13.6k lines).
- Integration owner: T11.
- Write scope: `native-kernel/`, `tool/kernel-compat/`.
- Prefer a pinned, reproducible vendor/port; if a family cannot be completed, record the exact split and decision instead of a partial wire-incompatible port.
- Do not modify this file.
