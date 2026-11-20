#import <Foundation/Foundation.h>

#include "billow_mihomo_bridge.h"

// libresolv compatibility for the Go runtime (definitions compiled once).
#define BILLOW_IOS_STUB_IMPLEMENTATION
#include "mihomo-resolv-stub.c"

// Thin C shim over the Go exports of libmihomo_ios.a
// (src-tauri/gen/apple/mihomo-ios/bridge.go, declared in
// include/billow_mihomo_bridge.h). Swift entry points are in
// BillowMihomoEngine.swift.
int32_t billow_mihomo_start(const char *home, void *writeCB, void *checkCB, void *ctx,
                            char **errOut, char *version, int versionLen) {
    *errOut = NULL;
    if (version != NULL && versionLen > 0) {
        version[0] = 0;
    }
    int rc = GoMihomoStart((char *)home, (uintptr_t)writeCB, (uintptr_t)checkCB, ctx, errOut);
    if (rc == 0 && version != NULL && versionLen > 0) {
        GoMihomoVersion(version, versionLen);
    }
    return rc;
}

void billow_mihomo_free(char *p) { free(p); }
