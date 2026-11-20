// C bridge for the Rust Packet Tunnel extension. T7 links billow-ios.a (or a
// static library exported from native-kernel/) here and sets rust_port.
#include "billow_rust_bridge.h"

rust_tunnel_port_t *rust_port = 0;

int32_t billow_rust_start(const char *home, rust_tunnel_port_t *port, void *ctx, void **error) {
    *error = 0;
    if (port == 0 || port->start == 0) {
        return -1;
    }
    rust_port = port;
    return port->start(ctx, home);
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
