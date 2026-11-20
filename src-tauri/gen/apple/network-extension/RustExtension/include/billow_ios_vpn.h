#ifndef BILLOW_IOS_VPN_H
#define BILLOW_IOS_VPN_H

#include <stdint.h>

// C ABI of the Rust kernel on iOS (src-tauri/src/ios_vpn.rs). T6/T7 implement
// it; BillowRust reaches it through RustKernelBridge.c only after the
// "Resolve Rust kernel" phase found a libapp.a exporting
// billow_ios_vpn_start (gate: billow_ios_vpn_version + the linked flag, see
// tool/ios/README.md "Rust extension wiring").
//
// The Rust side must also soft-link the shared Swift glue of the extension so
// both engines report one error domain and the same status files:
//   _BillowVPNErrorMake(code, message) -> NSError(domain: BillowVPNError.domain, code)
//   _BillowProviderWriteStatus(json, length) -> writes status/<engine>.json
// The JSON keys are the Shared/BillowVPNError.swift ProviderMessageKey
// constants (ok, running, engine, engineId, embedded, version, error, code,
// domain, loopbackPort, loopbackListen).

// Port shared with the extension. Defined here (guarded) so this header is
// self-contained and the layout does not depend on include order with
// billow_rust_bridge.h.
#ifndef BILLOW_RUST_TUNNEL_PORT_T_DEFINED
#define BILLOW_RUST_TUNNEL_PORT_T_DEFINED
typedef struct rust_tunnel_port {
    // start(ctx, home): loads the App Group directory and prepares routing.
    int32_t (*start)(void *ctx, const char *home);
    // write(ctx, packet, length): hands one egress IP packet back; the buffer
    // is owned by the caller and stays valid only until this call returns, so
    // the callee must copy (packetFlow.writePackets is synchronous).
    int64_t (*write)(void *ctx, void *packet, uint32_t length);
    // stop(ctx): releases kernel resources.
    void (*stop)(void *ctx);
} rust_tunnel_port_t;
#endif

// 0 on success. A malloc'd human-readable *error on failure (free with
// billow_ios_vpn_free_error). port->write is used for egress; the main route
// returns output through billow_ios_vpn_drain instead.
int32_t billow_ios_vpn_start(rust_tunnel_port_t *port, void *ctx, char *home, char **error);

// Copies up to max_count IP packets into packets as
// [4-byte big-endian length][IP packet] records and returns 0 with
// *packet_count; -1 when no tunnel runs, -2 when packetFlow reported nil.
// `packets` must stay writable and untouched until the call returns; the
// callee neither keeps the pointer nor any pointer into it.
int32_t billow_ios_vpn_drain(uint8_t *packets, uint32_t max_count, uint32_t *packet_count);

// Replays one record (as produced by drain) into the kernel input. `packet`
// and its contents stay valid only for the duration of the call.
int32_t billow_ios_vpn_write(void *packet, uint32_t length);

// Stops the tunnel, joins its threads and releases all buffers. No callback
// or packet pointer from earlier calls may be used afterwards.
void billow_ios_vpn_stop(void);

// Writes the kernel version (e.g. "billow-rust 0.1.0") as a C string into
// buf (size bytes, NUL-terminated) and returns its length. The extension uses
// a non-empty answer plus BILLOW_RUST_KERNEL_LINKED as the link gate.
int32_t billow_ios_vpn_version(char *buf, int32_t size);

// 1 when the active engine of the app state is the Rust kernel, 0 for
// Mihomo, -1 when no profile state is loaded yet (BillowRust reports
// hostNotReady, code 10).
int32_t billow_ios_vpn_selected(void);

// Releases an error string returned by billow_ios_vpn_start.
void billow_ios_vpn_free_error(char *error);

#endif
