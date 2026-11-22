# T21 coordination handoff

Immutable inputs for Task T21 (masque TCP termination).

- Scope: serve TCP targets over CONNECT-IP/CONNECT-UDP by a minimal TCP state machine or the T6/T7 userspace IP stack. UDP/IP paths from T14/T18 must keep working.
- Integration owner: T9.
- Write scope: `native-kernel/`, `tool/kernel-compat/`.
- Verify with a controlled HTTP/3 peer; record memory and platform conditions for T7.
- Unimplemented paths are explicit rejections, never silent fallbacks.
- Do not copy GPL-3.0 code; implement from public RFCs and observations.
- Do not modify this file.
