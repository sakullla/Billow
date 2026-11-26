# Reproducible routable OpenVPN peer for the T35 payload test.
#
# Ubuntu 22.04's OpenVPN runs as a real `--dev tun0` server (not `--dev null`),
# so a client IP packet can reach 10.8.0.1 and be echoed by socat. The client
# connects over TCP because Docker Desktop's UDP port forwarding is unreliable
# on macOS; OpenVPN's UDP and TCP control framing share the same data channel.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        openssl \
        openvpn \
        socat \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/openvpn-echo-entrypoint
RUN chmod 0755 /usr/local/bin/openvpn-echo-entrypoint

EXPOSE 1194/tcp
ENTRYPOINT ["/usr/local/bin/openvpn-echo-entrypoint"]
