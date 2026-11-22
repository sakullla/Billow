#ifndef BILLOW_RUST_BRIDGE_H
#define BILLOW_RUST_BRIDGE_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// rust_tunnel_port_t and the libapp.a entry points live in one contract header
// so the layout cannot depend on include order.
#include "billow_ios_vpn.h"

// The libapp.a entry points (billow_ios_vpn_*) are declared there.

// C-side egress callback type (RustKernelBridge.c).
typedef int64_t (*billow_rust_write_fn)(void *ctx, void *packet, uint32_t length);

// Shims implemented by RustKernelBridge.c (linked path calls libapp.a, the
// unlinked path reports the kernel as absent). Declared here so Swift sees
// them through the bridging header as ordinary C functions.
int billow_rust_kernel_image_present(void);
int32_t billow_rust_kernel_selected(void);
int32_t billow_rust_kernel_version(char *buf, int size);
// Records the App Group version directory for billow_rust_kernel_selected.
void billow_rust_kernel_set_home(const char *home);
int32_t billow_rust_kernel_start(void *ctx, char *home, billow_rust_write_fn write, char **error);
// Feeds one [4B big-endian length][IP packet] record from packetFlow.readPackets.
int32_t billow_rust_kernel_write(void *packet, uint32_t length);
// Polls egress when the callback route is not used (tests/diagnostics).
int32_t billow_rust_kernel_drain(void *packet, uint32_t length, uint32_t *produced);
// Reloads the configuration; *error is malloc'd (free()).
int32_t billow_rust_kernel_reload(char **error);
// JSON counters + peak RSS; returns the length written.
int32_t billow_rust_kernel_stats(char *buf, int size);
void billow_rust_kernel_stop(void);

int32_t billow_rust_start(const char *home, rust_tunnel_port_t *port, void *ctx, void **error);
int64_t billow_rust_write(void *ctx, void *packet, uint32_t length);
void billow_rust_stop(void *ctx);
void billow_rust_free(void *p);

#ifdef __cplusplus
}
#endif

#endif
