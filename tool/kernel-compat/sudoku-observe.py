#!/usr/bin/env python3
"""Black-box wire observation harness for the pinned Sudoku transport.

The Sudoku protocol has no public byte-level specification: the only public
material is the upstream project's description of its building blocks (4x4
Sudoku puzzles built from four clues, a puzzle table derived from the
pre-shared key, AEAD framing, HTTP masking). This harness records what can be
observed from the outside, using the pinned Mihomo release binary as both the
Sudoku client and the Sudoku listener and a loopback TCP relay as the only
observer.

Nothing here reads, ports or links Sudoku source. The pinned binary is spawned
as a separate process (the same posture as `peer-tests.sh`); the relay only
records bytes that a real session put on the wire.

Results feed `tool/kernel-compat/evidence/t17-cleanroom.md`.

Usage (from the repository root):

    # one session, one capture
    python3 tool/kernel-compat/sudoku-observe.py probe

    # identical request, three times: is the encoding deterministic?
    python3 tool/kernel-compat/sudoku-observe.py repeat --repeats 3

    # what a client without the keyed table gets from the listener
    python3 tool/kernel-compat/sudoku-observe.py reject

    # expansion factor: uplink against request size, downlink against body size
    python3 tool/kernel-compat/sudoku-observe.py sweep-paths
    python3 tool/kernel-compat/sudoku-observe.py sweep-bodies

    # other layers
    python3 tool/kernel-compat/sudoku-observe.py probe --aead chacha20-poly1305
    python3 tool/kernel-compat/sudoku-observe.py probe --httpmask legacy
    python3 tool/kernel-compat/sudoku-observe.py probe --key 1111...

Every command prints JSON on stdout; `--workdir` keeps the generated Mihomo
configs and logs for inspection.
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_KEY = "27efbf96-8f28-4090-8bc8-d35a379d76ee"


def pinned_binary():
    node = shutil.which("node")
    if node is None:
        raise SystemExit("node is required to resolve the pinned Mihomo baseline")
    out = subprocess.run(
        [node, os.path.join(HERE, "baseline.mjs"), "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        raise SystemExit(f"baseline.mjs failed: {out.stderr.strip()}")
    start = out.stdout.find("{")
    if start < 0:
        raise SystemExit("baseline.mjs did not report a binary")
    data = json.loads(out.stdout[start:])
    if data.get("binary"):
        return data["binary"]
    raise SystemExit("baseline.mjs did not report a binary")


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def wait_port(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.05)
    return False


class Observer:
    """Loopback HTTP target plus a recording TCP relay in front of the listener."""

    def __init__(self, body_bytes):
        self.body = b"x" * body_bytes
        self.requests = []
        self.captures = []
        self._stop = threading.Event()
        self._threads = []

    def _pump(self, src, dst, sink):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                sink[0] += data
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _handle_connection(self, conn, upstream_port):
        upstream = socket.create_connection(("127.0.0.1", upstream_port), timeout=3)
        up = [b""]
        down = [b""]
        thread = threading.Thread(target=self._pump, args=(conn, upstream, up), daemon=True)
        thread.start()
        self._pump(upstream, conn, down)
        thread.join(timeout=2)
        conn.close()
        upstream.close()
        self.captures.append((up[0], down[0]))

    def _answer(self, conn):
        conn.settimeout(2)
        request = b""
        try:
            request = conn.recv(65536)
        except OSError:
            pass
        self.requests.append(request)
        try:
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                % (len(self.body), self.body)
            )
        except OSError:
            pass
        conn.close()

    def start_target(self):
        return self._start(None)

    def start_relay(self, upstream_port):
        return self._start(upstream_port)

    def _start(self, upstream_port):
        holder = {}

        def run():
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(16)
            listener.settimeout(0.2)
            holder["port"] = listener.getsockname()[1]
            while not self._stop.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                if upstream_port is None:
                    threading.Thread(target=self._answer, args=(conn,), daemon=True).start()
                else:
                    threading.Thread(
                        target=self._handle_connection, args=(conn, upstream_port), daemon=True
                    ).start()
            listener.close()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        while "port" not in holder:
            time.sleep(0.01)
        self._threads.append(thread)
        return holder["port"]

    def stop(self):
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=2)


def proxy_fields(key, options):
    fields = {
        "key": f'"{key}"',
        "aead-method": options.aead,
        "padding-min": str(options.padding_min),
        "padding-max": str(options.padding_max),
        "table-type": options.table_type,
    }
    if options.httpmask == "legacy":
        fields["httpmask"] = {"disable": "false", "mode": "legacy"}
    else:
        fields["httpmask"] = {"disable": "true"}
    if options.custom_table:
        fields["custom-table"] = options.custom_table
    return fields


def yaml_block(fields, indent):
    lines = []
    for name, value in fields.items():
        if isinstance(value, dict):
            lines.append(f"{indent}{name}:")
            for inner, inner_value in value.items():
                lines.append(f"{indent}  {inner}: {inner_value}")
        else:
            lines.append(f"{indent}{name}: {value}")
    return "\n".join(lines) + "\n"


def start_listener(binary, workdir, options, port):
    server_yaml = os.path.join(workdir, "server.yaml")
    with open(server_yaml, "w") as handle:
        handle.write(
            "listeners:\n  - name: sudoku-in\n    type: sudoku\n    listen: 127.0.0.1\n"
            f"    port: {port}\n"
        )
        handle.write(yaml_block(proxy_fields(options.key, options), "    "))
        handle.write("mode: rule\nlog-level: debug\nrules:\n  - MATCH,DIRECT\n")
    log = open(os.path.join(workdir, "server.log"), "w")
    server = subprocess.Popen([binary, "-d", workdir, "-f", server_yaml], stdout=log, stderr=subprocess.STDOUT)
    if not wait_port(port):
        raise SystemExit("the Sudoku listener did not open its port")
    return server


def run_once(options, workdir):
    binary = options.bin or pinned_binary()
    observer = Observer(options.body)
    target_port = observer.start_target()
    server_port = free_port()
    fields = proxy_fields(options.key, options)
    server = start_listener(binary, workdir, options, server_port)

    relay_port = observer.start_relay(server_port)
    mixed_port = free_port()
    client_yaml = os.path.join(workdir, "client.yaml")
    with open(client_yaml, "w") as handle:
        handle.write(
            f"mixed-port: {mixed_port}\nmode: rule\nlog-level: debug\nproxies:\n  - name: su\n"
            f"    type: sudoku\n    server: 127.0.0.1\n    port: {relay_port}\n"
        )
        handle.write(yaml_block(fields, "    "))
        handle.write("rules:\n  - MATCH,su\n")
    client = subprocess.Popen(
        [binary, "-d", workdir, "-f", client_yaml],
        stdout=open(os.path.join(workdir, "client.log"), "w"),
        stderr=subprocess.STDOUT,
    )
    if not wait_port(mixed_port):
        raise SystemExit("the Sudoku client did not open its mixed port")

    def request():
        result = subprocess.run(
            [
                "curl", "-sS", "-m", "10", "--noproxy", "", "-o", os.devnull, "-w", "%{http_code}",
                "-x", f"http://127.0.0.1:{mixed_port}",
                f"http://127.0.0.1:{target_port}{options.path}",
            ],
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    try:
        # A freshly started client answers the first requests before its rule
        # engine is ready; retry until one session succeeds.
        status = ""
        for _ in range(25):
            status = request()
            if status == "200":
                break
            time.sleep(0.4)
        time.sleep(0.4)
        up, down = observer.captures[-1] if observer.captures else (b"", b"")
        target_request = observer.requests[-1] if observer.requests else b""
        return {
            "status": status,
            "up_bytes": len(up),
            "down_bytes": len(down),
            "up_hex": up.hex(),
            "down_hex": down.hex(),
            "target_request_bytes": len(target_request),
            "target_request_head": target_request[:120].decode("latin-1"),
        }
    finally:
        for proc in (client, server):
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        observer.stop()


def command_reject(options):
    """Send non-Sudoku payloads to a pinned listener and record its answer."""

    def probe(port, payload):
        conn = socket.create_connection(("127.0.0.1", port), timeout=3)
        conn.settimeout(2.0)
        conn.sendall(payload)
        received = b""
        closed = False
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    closed = True
                    break
                received += data
        except socket.timeout:
            pass
        conn.close()
        return {"sent_bytes": len(payload), "received_bytes": len(received), "peer_closed": closed, "received_head": received[:120].decode("latin-1")}

    def run(workdir):
        binary = options.bin or pinned_binary()
        port = free_port()
        server = start_listener(binary, workdir, options, port)
        try:
            probes = {
                "plain_http": probe(port, b"GET / HTTP/1.1\r\nHost: probe.example\r\n\r\n"),
                "zero_bytes": probe(port, bytes(64)),
                "high_entropy": probe(port, bytes(range(256))),
            }
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
        with open(os.path.join(workdir, "server.log")) as handle:
            lines = [line.strip() for line in handle if "Sudoku" in line]
        return {"probes": probes, "listener_log": lines}

    return with_workdir(options, run)


def alphabet(blob):
    counts = {}
    for byte in blob:
        counts[byte] = counts.get(byte, 0) + 1
    printable = sum(count for byte, count in counts.items() if 0x20 <= byte < 0x7F)
    return {
        "length": len(blob),
        "distinct": len(counts),
        "printable": printable,
        "non_printable": sorted(byte for byte in counts if not 0x20 <= byte < 0x7F),
    }


def with_workdir(options, run):
    workdir = options.workdir
    temporary = workdir is None
    if temporary:
        workdir = tempfile.mkdtemp(prefix="sudoku-observe-")
    else:
        os.makedirs(workdir, exist_ok=True)
    try:
        return run(workdir)
    finally:
        if temporary:
            shutil.rmtree(workdir, ignore_errors=True)


def command_probe(options):
    def run(workdir):
        capture = run_once(options, workdir)
        capture["up"] = alphabet(bytes.fromhex(capture["up_hex"]))
        capture["down"] = alphabet(bytes.fromhex(capture["down_hex"]))
        return capture

    return with_workdir(options, run)


def command_repeat(options):
    captures = []

    def run(workdir):
        for _ in range(options.repeats):
            captures.append(run_once(options, workdir))
        return captures

    with_workdir(options, run)
    first = bytes.fromhex(captures[0]["up_hex"])

    def groups(blob):
        return [blob[index : index + 4] for index in range(0, len(blob) - 3, 4)]

    first_groups = groups(first)
    report = {
        "repeats": len(captures),
        "lengths": [capture["up_bytes"] for capture in captures],
        "identical": [bytes.fromhex(capture["up_hex"]) == first for capture in captures],
        "differing_positions": [
            sum(1 for a, b in zip(first, bytes.fromhex(capture["up_hex"])) if a != b)
            for capture in captures
        ],
        # Four wire bytes are one clue quadruple. Repeats show whether the same
        # plaintext position is encoded the same way on a new connection.
        "groups": len(first_groups),
        "distinct_groups": [len(set(groups(bytes.fromhex(capture["up_hex"])))) for capture in captures],
        "shared_groups_with_first": [
            len(set(first_groups) & set(groups(bytes.fromhex(capture["up_hex"]))))
            for capture in captures
        ],
        "captures": [capture["up_hex"] for capture in captures],
    }
    return report


def command_sweep_paths(options):
    lengths = [1, 3, 5, 9, 17, 33, 65]
    results = []

    def run(workdir):
        base = options.path
        for extra in lengths:
            options.path = base + "A" * extra
            capture = run_once(options, workdir)
            results.append(
                {
                    "path_bytes": len(options.path),
                    "up_bytes": capture["up_bytes"],
                    "down_bytes": capture["down_bytes"],
                    "target_request_bytes": capture["target_request_bytes"],
                }
            )
        return results

    with_workdir(options, run)
    return {"results": results}


def command_sweep_bodies(options):
    results = []

    def run(workdir):
        for body in (12, 100, 500, 1000):
            options.body = body
            capture = run_once(options, workdir)
            results.append(
                {
                    "body_bytes": body,
                    "up_bytes": capture["up_bytes"],
                    "down_bytes": capture["down_bytes"],
                }
            )
        return results

    with_workdir(options, run)
    return {"results": results}


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "command", choices=["probe", "repeat", "reject", "sweep-paths", "sweep-bodies"]
    )
    parser.add_argument("--bin", help="pinned Mihomo binary (default: resolve baseline.mjs)")
    parser.add_argument("--key", default=DEFAULT_KEY, help="Sudoku key shared by both ends")
    parser.add_argument("--aead", default="none", choices=["none", "chacha20-poly1305", "aes-128-gcm"])
    parser.add_argument("--padding-min", type=int, default=0)
    parser.add_argument("--padding-max", type=int, default=0)
    parser.add_argument("--table-type", default="prefer_ascii")
    parser.add_argument("--custom-table", default=None)
    parser.add_argument("--httpmask", default="disabled", choices=["disabled", "legacy"])
    parser.add_argument("--path", default="/AAAA")
    parser.add_argument("--body", type=int, default=12)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--workdir", default=None)
    options = parser.parse_args(argv)

    handlers = {
        "probe": command_probe,
        "repeat": command_repeat,
        "reject": command_reject,
        "sweep-paths": command_sweep_paths,
        "sweep-bodies": command_sweep_bodies,
    }
    print(json.dumps(handlers[options.command](options), indent=2))


if __name__ == "__main__":
    main(sys.argv[1:])
