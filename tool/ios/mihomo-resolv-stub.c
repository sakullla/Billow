// libresolv compatibility for the embedded Go runtime.
//
// The Go runtime for darwin references res_9_ninit / res_9_nclose /
// res_9_nsearch. macOS resolves them through libresolv.dylib, which iOS does
// not ship, so an iOS binary linking the archive (c-archive) fails with
// undefined symbols unless something provides them. Mihomo never exercises
// the cgo resolver inside the tunnel (net.DefaultResolver is Go-based and
// DNS goes through mihomo's own resolver), so these stubs only satisfy the
// linker: ninit succeeds, nsearch reports "not found".
//
// Canonical source. The BillowMihomo extension ships a copy at
// src-tauri/gen/apple/network-extension/MihomoExtension/mihomo-resolv-stub.c
// (compiled with BILLOW_IOS_STUB_IMPLEMENTATION from its bridge file), and
// tool/ios/verify-mihomo-archive.sh compiles this file for its probe.
//
#ifdef BILLOW_IOS_STUB_IMPLEMENTATION
// Exactly one translation unit (the BillowMihomo target) defines this.
struct __res_state;

int res_9_ninit(struct __res_state *state) {
    (void)state;
    return 0;
}

void res_9_nclose(struct __res_state *state) {
    (void)state;
}

int res_9_nsearch(struct __res_state *state, const char *name, int a, int b,
                  unsigned char *answer, int answerLen) {
    (void)state;
    (void)name;
    (void)a;
    (void)b;
    (void)answer;
    (void)answerLen;
    return -1;
}
#endif
