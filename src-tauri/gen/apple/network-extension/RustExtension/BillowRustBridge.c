// C glue for the Rust Packet Tunnel extension.
//
// The Rust data plane lives in libapp.a (the host target's archive, which
// carries the kernel plus the billow_ios_vpn_* C ABI of
// src-tauri/src/ios_vpn.rs). Every Rust symbol is reached through
// RustKernelBridge.c, which links that archive when tool/ios/build.sh (or
// the "Resolve Rust kernel" phase) found it under Externals/arm64/rust/.
// Without the archive the extension still starts and reports
// engineNotAvailable (code 4) from the start path.
#include "billow_rust_bridge.h"

rust_tunnel_port_t *rust_port = 0;

int32_t billow_rust_start(const char *home, rust_tunnel_port_t *port, void *ctx, void **error) {
    *error = 0;
    if (port == 0 || port->start == 0) {
        return -3;
    }
    rust_port = port;
    return port->start((void *)ctx, home);
}

int64_t billow_rust_write(void *ctx, void *packet, uint32_t length) {
    if (rust_port == 0 || rust_port->write == 0) {
        return -1;
    }
    return rust_port->write(ctx, packet, length);
}

void billow_rust_stop(void *ctx) {
    if (rust_port != 0 && rust_port->stop != 0) {
        rust_port->stop(ctx);
    }
    rust_port = 0;
}

void billow_rust_free(void *p) { free(p); }
