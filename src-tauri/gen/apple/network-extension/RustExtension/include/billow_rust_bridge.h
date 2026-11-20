#ifndef BILLOW_RUST_BRIDGE_H
#define BILLOW_RUST_BRIDGE_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// Implemented by the Rust data plane (T7). The extension never sees Rust
// types; T7 installs one implementation table from BillowRustEngine.swift.
typedef struct {
    // start loads the App Group home directory (config.yaml + assets) and
    // prepares routing. Return 0 on success, negative on failure.
    int32_t (*start)(void *ctx, const char *home);
    // writePin: one egress IP packet produced by the data plane; return 0 on
    // success. T7 writes it back with NEPacketTunnelFlow.writePackets.
    int64_t (*write)(void *ctx, void *packet, uint32_t length);
    // stop releases everything; the context must not be used afterwards.
    void (*stop)(void *ctx);
} rust_tunnel_port_t;

extern rust_tunnel_port_t *rust_port;

int32_t billow_rust_start(const char *home, rust_tunnel_port_t *port, void *ctx, void **error);
int64_t billow_rust_write(void *ctx, void *packet, uint32_t length);
void billow_rust_stop(void *ctx);
void billow_rust_free(void *p);

#ifdef __cplusplus
}
#endif

#endif
