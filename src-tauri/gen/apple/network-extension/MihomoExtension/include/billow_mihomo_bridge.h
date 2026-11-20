#ifndef BILLOW_MIHOMO_BRIDGE_H
#define BILLOW_MIHOMO_BRIDGE_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// Go exports from libmihomo_ios.a (c-archive built from
// src-tauri/gen/apple/mihomo-ios/bridge.go). Swift declares them with
// @_silgen_name (BillowMihomoEngine.swift / bridge.pch).

// Starts the embedded engine with `home` (CLASH_HOME_DIR). writeCB and
// checkCB are Swift @convention(c) function pointers:
//   writeCB(ctx, packet, length) -> 0 on success
//   checkCB(ctx) -> 0 when the network path is usable
// Returns 0 on success; on failure *errOut is a Go-allocated message released
// with billow_mihomo_free.
int GoMihomoStart(char *home, uintptr_t writeCB, uintptr_t checkCB, void *ctx, char **errOut);
int GoMihomoVersion(char *buf, int size);
int GoMihomoReload(char **errOut);
int GoMihomoNetworkChanged(void);
void GoMihomoShutdown(void);
// One record: [4-byte big-endian length][IP packet]. Returns the packet length,
// 0 when malformed, -1 when no engine runs.
int GoMihomoReadPacket(void *record, uint32_t size);
int GoMihomoWritePackets(void *packet, uint32_t length);
int GoMihomoLoopbackStart(char *listen, double fraction);
void GoMihomoLoopbackStop(void);

int32_t billow_mihomo_start(const char *home, void *writeCB, void *checkCB, void *ctx,
                            char **errOut, char *version, int versionLen);
void billow_mihomo_free(char *p);

#ifdef __cplusplus
}
#endif

#endif
