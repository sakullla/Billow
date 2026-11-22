// Smoke test of the Rust kernel C ABI on iOS (T7).
//
// It links libapp.a exactly like the BillowRust extension does and exercises
// the documented contract:
//   * billow_ios_vpn_version is non-empty (the extension's link gate);
//   * billow_ios_vpn_stats reports a JSON object (two-call sizing protocol);
//   * billow_ios_vpn_selected is -1 before the host wrote engine.json;
//   * billow_ios_vpn_start fails with a malloc'd message when config.yaml is
//     missing, and frees with billow_ios_vpn_free_error;
//   * a real configuration starts, a device UDP datagram reaches a local echo
//     server through the DIRECT outbound and the reply comes back through
//     port->write;
//   * billow_ios_vpn_stop releases everything and start can run again.
//
// Usage: rust-kernel-smoke [udp-echo-port]
// Exit status 0 when every check passed.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "billow_ios_vpn.h"

static int failures = 0;

#define CHECK(condition, name)                                                 \
    do {                                                                       \
        if (condition) {                                                       \
            printf("ok %s\n", name);                                           \
        } else {                                                               \
            printf("fail %s\n", name);                                         \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static uint8_t last_packet[4096];
static size_t last_length;
static int emitted;

static int64_t on_write(void *ctx, void *packet, uint32_t length) {
    (void)ctx;
    if (length <= sizeof(last_packet)) {
        memcpy(last_packet, packet, length);
        last_length = length;
        emitted++;
    }
    return 0;
}

static uint16_t ip_checksum(const uint8_t *bytes, size_t length) {
    uint32_t sum = 0;
    for (size_t index = 0; index + 1 < length; index += 2) {
        sum += (uint32_t)((bytes[index] << 8) | bytes[index + 1]);
    }
    if (length & 1) {
        sum += (uint32_t)(bytes[length - 1] << 8);
    }
    while (sum > 0xffff) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

/// Build one IPv4/UDP packet with device source 198.18.0.2 and a zero UDP
/// checksum (allowed for IPv4 and accepted by the kernel).
static size_t build_udp(uint8_t *out, const uint8_t dst[4], uint16_t src_port,
                        uint16_t dst_port, const uint8_t *payload, size_t payload_length) {
    size_t total = 20 + 8 + payload_length;
    memset(out, 0, total);
    out[0] = 0x45;
    out[2] = (uint8_t)(total >> 8);
    out[3] = (uint8_t)total;
    out[6] = 0x40; // DF
    out[8] = 64;   // TTL
    out[9] = 17;   // UDP
    out[12] = 198;
    out[13] = 18;
    out[14] = 0;
    out[15] = 2;
    memcpy(out + 16, dst, 4);
    uint16_t checksum = ip_checksum(out, 20);
    out[10] = (uint8_t)(checksum >> 8);
    out[11] = (uint8_t)checksum;
    out[20] = (uint8_t)(src_port >> 8);
    out[21] = (uint8_t)src_port;
    out[22] = (uint8_t)(dst_port >> 8);
    out[23] = (uint8_t)dst_port;
    out[24] = (uint8_t)((8 + payload_length) >> 8);
    out[25] = (uint8_t)(8 + payload_length);
    memcpy(out + 28, payload, payload_length);
    return total;
}

static char *write_config(const char *dir, uint16_t mixed_port) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/config.yaml", dir);
    FILE *file = fopen(path, "w");
    if (file == NULL) {
        return NULL;
    }
    fprintf(file, "mixed-port: %u\nrules:\n  - MATCH,DIRECT\n", mixed_port);
    fclose(file);
    return strdup(path);
}

int main(int argc, char **argv) {
    char buf[1024];
    int length = billow_ios_vpn_version(buf, sizeof(buf));
    CHECK(length > 0 && buf[0] != 0, "version is reported");
    printf("version: %s\n", buf);

    length = billow_ios_vpn_stats(NULL, 0);
    CHECK(length > 0, "stats reports the required size");
    char *stats = calloc(1, (size_t)length + 1);
    if (stats != NULL) {
        int written = billow_ios_vpn_stats(stats, length + 1);
        CHECK(written > 0 && stats[0] == '{' && strstr(stats, "peakRssBytes") != NULL,
              "stats is a JSON object with peakRssBytes");
        printf("stats(before start): %s\n", stats);
        free(stats);
    }

    CHECK(billow_ios_vpn_selected() == -1, "selected is -1 before the host writes engine.json");
    CHECK(billow_ios_vpn_drain((uint8_t *)buf, 1, NULL) == -2, "drain rejects a null count");
    CHECK(billow_ios_vpn_write(NULL, 0) == -2, "write rejects an empty packet");

    // A start without config.yaml fails with the path in the message.
    char missing[] = "/tmp/billow-smoke-missing";
    mkdir(missing, 0700);
    char *home = strdup(missing);
    char *error = NULL;
    int rc = billow_ios_vpn_start(NULL, NULL, home, &error);
    CHECK(rc != 0 && error != NULL, "start fails without config.yaml");
    if (error != NULL) {
        printf("start error: %s\n", error);
        CHECK(strstr(error, "config.yaml") != NULL, "the error names config.yaml");
        billow_ios_vpn_free_error(error);
        error = NULL;
    }
    free(home);

    // A real configuration starts and relays one UDP datagram both ways.
    char template[] = "/tmp/billow-smoke-XXXXXX";
    char *dir = mkdtemp(template);
    CHECK(dir != NULL, "temp directory");
    if (dir == NULL) {
        return 1;
    }
    struct sockaddr_in probe;
    memset(&probe, 0, sizeof(probe));
    probe.sin_family = AF_INET;
    probe.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int probe_fd = socket(AF_INET, SOCK_STREAM, 0);
    socklen_t probe_length = sizeof(probe);
    uint16_t mixed_port = 0;
    if (probe_fd >= 0 && bind(probe_fd, (struct sockaddr *)&probe, sizeof(probe)) == 0 &&
        getsockname(probe_fd, (struct sockaddr *)&probe, &probe_length) == 0) {
        mixed_port = ntohs(probe.sin_port);
    }
    if (probe_fd >= 0) {
        close(probe_fd);
    }
    CHECK(write_config(dir, mixed_port) != NULL, "config.yaml written");

    rust_tunnel_port_t port;
    port.start = NULL;
    port.write = on_write;
    port.stop = NULL;
    billow_ios_vpn_set_home(dir);
    home = strdup(dir);
    rc = billow_ios_vpn_start(&port, (void *)1, home, &error);
    CHECK(rc == 0, "start with a real configuration");
    if (rc != 0) {
        printf("start failed: %s\n", error != NULL ? error : "(no error)");
        if (error != NULL) {
            billow_ios_vpn_free_error(error);
            error = NULL;
        }
        free(home);
        return 1;
    }

    uint16_t echo_port = argc > 1 ? (uint16_t)atoi(argv[1]) : 0;
    if (echo_port != 0) {
        uint8_t packet[256];
        uint8_t target[4] = {127, 0, 0, 1};
        size_t packet_length = build_udp(packet, target, 51000, echo_port,
                                         (const uint8_t *)"billow-tunnel", 13);
        emitted = 0;
        last_length = 0;
        CHECK(billow_ios_vpn_write(packet, (uint32_t)packet_length) == 0,
              "device packet accepted");
        for (int attempt = 0; attempt < 200 && emitted == 0; attempt++) {
            usleep(10000);
        }
        CHECK(emitted > 0, "the UDP reply came back through port->write");
        if (emitted > 0 && last_length >= 28 && last_packet[9] == 17) {
            uint16_t reply_length = (uint16_t)((last_packet[24] << 8) | last_packet[25]);
            CHECK(reply_length == 8 + 13 &&
                      memcmp(last_packet + 28, "billow-tunnel", 13) == 0,
                  "the reply carries the echoed payload");
            CHECK(last_packet[22] == (uint8_t)(51000 >> 8) &&
                      last_packet[23] == (uint8_t)51000,
                  "the reply is addressed to the device port");
        } else {
            CHECK(0, "the reply is a UDP packet");
        }
    }

    length = billow_ios_vpn_stats(NULL, 0);
    stats = calloc(1, (size_t)length + 1);
    if (stats != NULL && length > 0) {
        billow_ios_vpn_stats(stats, length + 1);
        printf("stats(running): %s\n", stats);
        CHECK(strstr(stats, "\"running\":true") != NULL, "stats reports a running tunnel");
        CHECK(strstr(stats, "\"inPackets\":") != NULL, "stats carries the packet counters");
        free(stats);
    }

    // A reload of the same file keeps the tunnel running.
    rc = billow_ios_vpn_reload(&error);
    CHECK(rc == 0, "reload succeeds");
    if (rc != 0 && error != NULL) {
        printf("reload error: %s\n", error);
        billow_ios_vpn_free_error(error);
        error = NULL;
    }

    billow_ios_vpn_stop();
    CHECK(billow_ios_vpn_drain((uint8_t *)buf, 1, &(uint32_t){0}) == -1,
          "drain returns -1 after stop");

    // Start/stop can run again (the extension restarts on network changes).
    rc = billow_ios_vpn_start(&port, (void *)1, home, &error);
    CHECK(rc == 0, "restart after stop");
    if (rc != 0 && error != NULL) {
        printf("restart failed: %s\n", error);
        billow_ios_vpn_free_error(error);
        error = NULL;
    }
    billow_ios_vpn_stop();

    free(home);
    // Keep the directory: the case is inspected on failure by the runner.
    printf("%s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}
