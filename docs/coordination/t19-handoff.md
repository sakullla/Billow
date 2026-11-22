# T19 coordination handoff

Immutable inputs for Task T19 (mesh protocol adapters).

- Families: `tailscale`, `zerotier`, `easytier`: control planes, identity, discovery and encrypted transport.
- Integration owner: T9. Device/TUN ownership remains with T6/T7.
- Write scope: `native-kernel/`, `tool/kernel-compat/`.
- Implement from public protocol documentation and controlled peers; do not copy GPL-3.0 code or vendor incompatible control planes.
- Offline dependency gaps must be recorded with exact crate/version/purpose; unimplemented paths are explicit rejections.
- Do not modify this file.
