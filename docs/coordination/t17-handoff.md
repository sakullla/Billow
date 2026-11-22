# T17 coordination handoff

Immutable inputs for Task T17 (sudoku).

- Family: `sudoku`.
- The user has explicitly authorized translating the locked Mihomo `transport/sudoku` source (GPL-3.0) into this repository for T17. This is a GPL-3.0 derivative; every translated file and `THIRD_PARTY_NOTICES` must record the source and GPL-3.0 obligations, and distribution must comply with GPL-3.0.
- Integration owner: T9.
- Write scope: `native-kernel/`, `tool/kernel-compat/`.
- Use the pinned source under `tool/kernel-compat/.cache/source/` as the reference; record the source commit in each translated file.
- Layers that are not translated (multiplex/HTTP tunnel/UoT, BasicOption gaps) must be explicit rejections with reasons.
- Do not modify this file.
