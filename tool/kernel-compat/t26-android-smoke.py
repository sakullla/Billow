#!/usr/bin/env python3
"""Host smoke of the Android VpnService process route (`--tun-fd`).

Build first:
    cargo build -p billow-kernel-cli --features android-vpn \
        --manifest-path native-kernel/Cargo.toml

Run:
    BILLOW_KERNEL_BIN=<target>/debug/billow-kernel \
        python3 tool/kernel-compat/t26-android-smoke.py

A Unix datagram socket pair plays the packet-oriented TUN fd. The script
starts the kernel with the inherited fd, forwards one UDP packet to a loopback
echo server, checks the reply came back through the fd, then sends SIGTERM and
checks the exit code and the staged-file cleanup.

A second process then loses the device side of the fd (a revoked VPN): the CLI
must exit non-zero instead of keeping a live process with a dead data plane,
because the host samples only process liveness for the Rust engine.

It is a host check only; it is not a substitute for the Android device run.
"""

import json
import os
import queue
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

BIN = os.environ.get("BILLOW_KERNEL_BIN", "billow-kernel")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ip_udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 17, len(udp))
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), checksum(pseudo + udp)) + payload
    total = 20 + len(udp)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, checksum(ip),
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    return ip + udp


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def start_kernel(config: str, fd: int):
    """Spawns the CLI with the inherited fd and waits for its readiness lines."""
    process = subprocess.Popen(
        [BIN, config, "--tun-fd", str(fd)],
        pass_fds=(fd,),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    lines = queue.Queue()

    def pump():
        for line in process.stdout:
            lines.put(line.rstrip())

    threading.Thread(target=pump, daemon=True).start()
    collected = []
    identity = None
    ready = False
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            if process.poll() is not None:
                break
            continue
        collected.append(line)
        if line.startswith("instance="):
            identity = line
        if line.startswith("tun_fd:"):
            ready = True
            break
    return process, collected, identity, ready


def main() -> int:
    echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    echo.bind(("127.0.0.1", 0))
    echo_addr = echo.getsockname()

    def echo_server():
        data, addr = echo.recvfrom(2048)
        echo.sendto(data, addr)

    threading.Thread(target=echo_server, daemon=True).start()

    with tempfile.TemporaryDirectory(prefix="t26-cli-smoke-") as tmp:
        config = os.path.join(tmp, "config.yaml")
        with open(config, "w") as handle:
            handle.write(
                f"mixed-port: {free_port()}\nmode: rule\nrules:\n  - MATCH,DIRECT\n"
            )
        host, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        peer.settimeout(10.0)
        process, collected, identity, ready = start_kernel(config, host.fileno())
        if identity is None or not ready:
            process.kill()
            print(json.dumps({"ok": False, "stdout": collected,
                              "stderr": process.stderr.read()}, indent=2))
            return 2

        peer.send(ip_udp("172.19.0.1", "127.0.0.1", 40123, echo_addr[1], b"pong"))
        reply = peer.recv(65535)
        ihl = (reply[0] & 0x0F) * 4
        protocol = reply[9]
        payload = reply[ihl + 8:]
        destination_port = struct.unpack("!H", reply[ihl + 2:ihl + 4])[0]
        result = {
            "ok": protocol == 17 and payload == b"pong" and destination_port == 40123,
            "identity": identity,
            "stdout": collected,
            "replyProto": protocol,
            "replySrc": socket.inet_ntoa(reply[12:16]),
            "replyDstPort": destination_port,
            "replyPayload": payload.decode(errors="replace"),
        }
        process.send_signal(signal.SIGTERM)
        try:
            code = process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            code = process.wait()
        time.sleep(0.3)
        result["exitCode"] = code
        result["stagedFileRemoved"] = not os.path.exists(
            os.path.join(tmp, "config.rust.yaml")
        )
        result["stderrTail"] = process.stderr.read().strip().splitlines()[-6:]

        # Second process: the device side disappears (a revoked VPN). The host
        # only samples process liveness for the Rust engine, so the CLI must
        # exit non-zero rather than keep polling a dead descriptor.
        host2, peer2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        process2, collected2, identity2, ready2 = start_kernel(config, host2.fileno())
        host2.close()
        peer2.close()
        try:
            fd_code = process2.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process2.kill()
            fd_code = process2.wait()
        fd_stderr = process2.stderr.read().strip()
        result["fdLoss"] = {
            "ready": ready2 and identity2 is not None,
            "exitCode": fd_code,
            "reported": "stopped carrying packets" in fd_stderr,
            "stderrTail": fd_stderr.splitlines()[-4:],
        }
        result["ok"] = (
            result["ok"]
            and code == 0
            and result["stagedFileRemoved"]
            and result["fdLoss"]["ready"]
            and fd_code != 0
            and result["fdLoss"]["reported"]
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
