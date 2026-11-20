#ifndef BILLOW_IOS_VPN_H
#define BILLOW_IOS_VPN_H

#include <stdint.h>

// C ABI of the Rust kernel on iOS (src-tauri/src/ios_vpn.rs). T6/T7 implement
// it; BillowRust reaches it through RustKernelBridge.c only when
// tool/ios/build.sh found a libapp.a exporting billow_ios_vpn_start.
//
// The Rust side must also soft-link the shared Swift glue of the extension so
// both engines report one error domain and the same status files:
//   _BillowVPNErrorMake(code, message) -> NSError(domain: BillowVPNError.domain, code)
//   _BillowProviderWriteStatus(json, length) -> writes status/<engine>.json
// The JSON keys are the Shared/BillowVPNError.swift ProviderMessageKey
// constants (ok, running, engine, engineId, embedded, version, error, code,
// domain, loopbackPort, loopbackListen).

// rust_tunnel_port_t comes from billow_rust_bridge.h; the Rust implementation
// sees the same start/write/stop layout.
struct rust_tunnel_port;

// 0 on success. A malloc'd human-readable *error on failure (free with
// billow_ios_vpn_free_error). port/write are used for egress in the kernel
// route; main-route output is read with billow_ios_vpn_drain.
int32_t billow_ios_vpn_start(rust_tunnel_port_t *port, void *ctx, char *home, char **error);

// Copies up to max_count IP packets into packets as
// [4-byte big-endian length][IP packet] records; returns 0 with *packet_count,
// -1 when no tunnel runs, -2 when packetFlow reported nil (stopping).
int32_t billow_ios_vpn_drain(uint8_t *packets, uint32_t max_count, uint32_t *packet_count);

// Replays one record (as produced by drain) into the packetFlow.
int32_t billow_ios_vpn_write(void *packet, uint32_t length);

// Stops the tunnel and releases its threads.
void billow_ios_vpn_stop(void);

// Writes the kernel version (e.g. "billow-rust 0.1.0") as a C string and
// returns its length. The extension uses it to detect a linked archive.
int32_t billow_ios_vpn_version(char *buf, int32_t size);

// 1 when the active engine of the app state is the Rust kernel, 0 for
// Mihomo, -1 when no profile state is loaded yet.
int32_t billow_ios_vpn_selected(void);

void billow_ios_vpn_free_error(char *error);

#endif
