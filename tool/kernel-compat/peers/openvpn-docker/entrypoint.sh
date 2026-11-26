#!/bin/sh
# Start a real OpenVPN server on tun0 and two echoes bound to the tunnel
# address. The test mounts the host-generated CA/server/client certificates at
# /certs; the server certificate SAN contains IP:127.0.0.1,DNS:localhost so the
# Rust client's chain check accepts the endpoint it connected to.
set -eu

CERT_DIR=${CERT_DIR:-/certs}
cat >/tmp/server.conf <<EOF
dev tun0
mode server
tls-server
ca $CERT_DIR/ca.crt
cert $CERT_DIR/server.crt
key $CERT_DIR/server.key
dh none
proto tcp4-server
local 0.0.0.0
port 1194
topology subnet
server 10.8.0.0 255.255.255.0
data-ciphers AES-256-GCM
auth SHA256
ping 1
verb 3
EOF

openvpn --config /tmp/server.conf &
OPENVPN_PID=$!

# Wait for the server to install 10.8.0.1/24 on tun0 before binding echoes.
i=0
while [ "$i" -lt 150 ]; do
    if ip -4 addr show dev tun0 2>/dev/null | grep -q '10\.8\.0\.1/'; then
        break
    fi
    if ! kill -0 "$OPENVPN_PID" 2>/dev/null; then
        echo "OPENVPN_EXITED"
        exit 1
    fi
    i=$((i + 1))
    sleep 0.1
done
if ! ip -4 addr show dev tun0 2>/dev/null | grep -q '10\.8\.0\.1/'; then
    echo "TUN_NOT_READY"
    exit 1
fi

socat TCP-LISTEN:7777,bind=10.8.0.1,reuseaddr,fork EXEC:cat &
TCP_PID=$!
socat UDP4-RECVFROM:7778,bind=10.8.0.1,fork EXEC:cat &
UDP_PID=$!

term() {
    kill "$TCP_PID" "$UDP_PID" "$OPENVPN_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    exit 0
}
trap term TERM INT

# The test polls for this marker before it starts the Rust client.
echo READY
wait
