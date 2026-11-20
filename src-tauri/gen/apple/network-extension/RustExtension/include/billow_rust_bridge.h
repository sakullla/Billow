#ifndef BILLOW_RUST_BRIDGE_H
#define BILLOW_RUST_BRIDGE_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// Port layout shared with the libapp.a C ABI (include/billow_ios_vpn.h).
//   start(ctx, home) loads the App Group directory; 0 on success.
//   write(ctx, packet, length) hands one egress IP packet to NEPacketTunnelFlow.
//   stop(ctx) releases kernel resources.
typedef struct rust_tunnel_port {
    int32_t (*start)(void *ctx, const char *home);
    int64_t (*write)(void *ctx, void *packet, uint32_t length);
    void (*stop)(void *ctx);
} rust_tunnel_port_t;


// Engine operations implemented in libapp.a (src-tauri/src/ios_vpn.rs),
// declared by src-tauri/include/billow_ios_vpn.h and re-declared here for the
// extension's bridging header.
//   billow_ios_vpn_start(port, ctx, home, error) -> 0 or negative
//   billow_ios_vpn_drain(packets, maxCount, produced) -> 0, -1, -2 (nil)
//   billow_ios_vpn_write(packet, length) -> 0, -1
//   billow_ios_vpn_stop()
//   billow_ios_vpn_version(buf, size) -> length
//   billow_ios_vpn_selected() -> 1 when the active engine of the app state is
//       the Rust kernel; 0 for Mihomo; -1 when no profile state is loaded.

// C-side egress callback type (RustKernelBridge.c).
typedef int64_t (*billow_rust_write_fn)(void *ctx, void *packet, uint32_t length);

// Shims implemented by RustKernelBridge.c (linked path calls libapp.a, the
// unlinked path reports the kernel as absent). Declared here so Swift sees
// them through the bridging header as ordinary C functions.
int billow_rust_kernel_image_present(void);
int32_t billow_rust_kernel_selected(void);
int32_t billow_rust_kernel_version(char *buf, int size);
int32_t billow_rust_kernel_start(void *ctx, char *home, billow_rust_write_fn write, char **error);
int32_t billow_rust_kernel_drain(void *packet, uint32_t length, uint32_t *produced);
void billow_rust_kernel_stop(void);

int32_t billow_rust_start(const char *home, rust_tunnel_port_t *port, void *ctx, void **error);
int64_t billow_rust_write(void *ctx, void *packet, uint32_t length);
void billow_rust_stop(void *ctx);
void billow_rust_free(void *p);

#ifdef __cplusplus
}
#endif

#endif
