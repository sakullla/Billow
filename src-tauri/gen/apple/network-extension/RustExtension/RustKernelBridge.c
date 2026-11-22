// C shims over libapp.a for BillowRust.
//
// libapp.a is optional (T7 builds it with tool/ios/build.sh): the compile
// phase always compiles this file, and the define below switches between
// calling the Rust kernel and reporting that it is absent. The paths are
// listed explicitly because no linker flags (-all_load) are needed for these
// few symbols.
//
// Linked path: build/rust-kernel/linked.xcconfig (written by
// resolve-mihomo.sh) adds libapp.a with -force_load and defines
// BILLOW_RUST_KERNEL_LINKED=1 in this file and in Swift; without the archive
// the unlinked branch reports the kernel as absent (code 4 at start).
#include <stdio.h>

#include "include/billow_rust_bridge.h"
#include "include/billow_ios_vpn.h"

#ifndef BILLOW_RUST_KERNEL_LINKED

int billow_rust_kernel_image_present(void) { return 0; }
int32_t billow_rust_kernel_selected(void) { return -1; }
int32_t billow_rust_kernel_version(char *buf, int size) {
    if (buf != NULL && size > 0) {
        buf[0] = 0;
    }
    return 0;
}
void billow_rust_kernel_set_home(const char *home) { (void)home; }
int32_t billow_rust_kernel_start(void *ctx, char *home, billow_rust_write_fn write, char **error) {
    (void)ctx; (void)home; (void)write;
    if (error != NULL) {
        // Caller releases with free().
        *error = malloc(64);
        if (*error != NULL) {
            int n = snprintf(*error, 64, "libapp.a is not linked into BillowRust");
            (void)n;
        }
    }
    return -2;
}
int32_t billow_rust_kernel_write(void *packet, uint32_t length) {
    (void)packet; (void)length;
    return -1;
}
int32_t billow_rust_kernel_drain(void *packet, uint32_t length, uint32_t *produced) {
    (void)packet; (void)length;
    if (produced != NULL) {
        *produced = 0;
    }
    return -1;
}
int32_t billow_rust_kernel_reload(char **error) {
    if (error != NULL) {
        *error = malloc(64);
        if (*error != NULL) {
            int n = snprintf(*error, 64, "libapp.a is not linked into BillowRust");
            (void)n;
        }
    }
    return -2;
}
int32_t billow_rust_kernel_stats(char *buf, int size) {
    if (buf != NULL && size > 0) {
        buf[0] = 0;
    }
    return 0;
}
void billow_rust_kernel_stop(void) {}

#else

// The adapter below maps the extension port model onto the one-shot libapp.a
// model.
int billow_rust_kernel_image_present(void) { return 1; }
int32_t billow_rust_kernel_selected(void) { return billow_ios_vpn_selected(); }

int32_t billow_rust_kernel_version(char *buf, int size) {
    return billow_ios_vpn_version(buf, size);
}

void billow_rust_kernel_set_home(const char *home) { billow_ios_vpn_set_home(home); }

int32_t billow_rust_kernel_start(void *ctx, char *home, billow_rust_write_fn write, char **error) {
    rust_tunnel_port_t port;
    port.start = 0;
    port.write = (int64_t (*)(void *, void *, uint32_t))write;
    port.stop = 0;
    return billow_ios_vpn_start(&port, ctx, home, error);
}

int32_t billow_rust_kernel_write(void *packet, uint32_t length) {
    return billow_ios_vpn_write(packet, length);
}

int32_t billow_rust_kernel_drain(void *packet, uint32_t length, uint32_t *produced) {
    // `length` is the caller's writable byte capacity. One record is at most
    // 4 + 65535 bytes, so this is the only count that cannot overrun it; a
    // buffer smaller than one worst-case record yields 0 records.
    uint32_t max_count = length / (4u + 65535u);
    if (max_count == 0) {
        if (produced != NULL) {
            *produced = 0;
        }
        return 0;
    }
    return billow_ios_vpn_drain((uint8_t *)packet, max_count, produced);
}

int32_t billow_rust_kernel_reload(char **error) { return billow_ios_vpn_reload(error); }

int32_t billow_rust_kernel_stats(char *buf, int size) { return billow_ios_vpn_stats(buf, size); }

void billow_rust_kernel_stop(void) { billow_ios_vpn_stop(); }

#endif
