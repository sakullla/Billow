# T16 coordination handoff

Immutable inputs for Task T16 (device-family protocol adapters).

- Families: `wireguard`, `tailscale`, `zerotier`, `easytier`, `openvpn`.
- Integration owner: T5. Device/TUN ownership and switching remain with T6/T7; T16 delivers the protocol adapters and their controlled peers.
- Write scope: `native-kernel/`, `tool/kernel-compat/`.
- Record per-family dependency decisions (offline crates, control planes, IP stack) and keep unimplemented paths explicit.
- Do not modify this file.
