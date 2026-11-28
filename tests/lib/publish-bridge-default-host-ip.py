#!/usr/bin/env python3
"""Check that a bridge's default host IP applies to dynamically published ports."""

import json
import os
import platform
import socket
import subprocess
import sys
import time
import uuid

CLI = sys.argv[1]
NAME = "bridge-host-ip-" + uuid.uuid4().hex
REQUEST = b"bridge-host-ip-probe"
REPLY = b"bridge-host-ip-reply"
GUEST = r'''
import select, socket
request = b"bridge-host-ip-probe"
reply = b"bridge-host-ip-reply"
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind(("0.0.0.0", 8080))
tcp.listen(16)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("0.0.0.0", 8080))
while True:
    ready, _, _ = select.select([tcp, udp], [], [])
    if tcp in ready:
        conn, _ = tcp.accept()
        with conn:
            conn.settimeout(1)
            try:
                if conn.recv(1024) == request:
                    conn.sendall(reply)
            except OSError:
                pass
    if udp in ready:
        data, addr = udp.recvfrom(1024)
        if data == request:
            udp.sendto(reply, addr)
'''


def docker(*args, timeout=4):
    result = subprocess.run([CLI, *args], text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def probe(host, port, protocol, timeout=0.3):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    try:
        with socket.socket(family, kind) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(REQUEST)
            return sock.recv(1024) == REPLY
    except OSError:
        return False


def main():
    network_id = None
    container_id = None
    cleanup_errors = []
    runtime = f"context={os.getenv('DOCKER_CONTEXT', '')!r} socket={os.getenv('KIRI_SOCKET', '')!r}"
    try:
        network_id = docker("network", "create", "--driver", "bridge", "--opt",
                            "com.docker.network.bridge.host_binding_ipv4=127.0.0.1", NAME, timeout=6)
        print(f"fixture={NAME} network_id={network_id} {runtime}", flush=True)
        container_id = docker("create", "--pull=never", "--name", NAME,
                              "--network", network_id, "-p", "8080/tcp", "-p", "8080/udp",
                              "python:3.13-alpine", "python", "-u", "-c", GUEST, timeout=6)
        print(f"fixture={NAME} container_id={container_id} {runtime}", flush=True)
        docker("start", container_id, timeout=8)
        info = json.loads(docker("inspect", container_id))[0]
        requested = info["HostConfig"]["PortBindings"]
        applied = info["NetworkSettings"]["Ports"]
        ports = {}
        reports = {}
        for protocol in ("tcp", "udp"):
            key = "8080/" + protocol
            reported = docker("port", container_id, key)
            print(f"{key}: requested={requested.get(key)!r} applied={applied.get(key)!r} docker port={reported!r}", flush=True)
            reports[protocol] = reported
        for protocol in ("tcp", "udp"):
            key = "8080/" + protocol
            reported = reports[protocol]
            bindings = applied.get(key) or []
            if len(requested.get(key) or []) != 1 or requested[key][0]["HostIp"] != "":
                raise AssertionError(f"{key}: expected one requested binding with an empty HostIp")
            if len(bindings) != 1 or bindings[0]["HostIp"] != "127.0.0.1":
                raise AssertionError(f"{key}: expected one applied binding on loopback")
            ports[protocol] = int(bindings[0]["HostPort"])
            if reported != f"127.0.0.1:{ports[protocol]}":
                raise AssertionError(f"{key}: docker port mismatch: {reported!r}")

        for protocol, port in ports.items():
            deadline = time.monotonic() + 5
            while not probe("127.0.0.1", port, protocol):
                if time.monotonic() >= deadline:
                    raise AssertionError(f"{protocol}: loopback fixture did not become ready")
                time.sleep(0.1)
            print(f"{protocol}: loopback fixture reachable", flush=True)

        addresses = []
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
                sock.bind(("::1", 0))
            addresses.append("::1")
        except OSError:
            print("IPv6 loopback unavailable; skipping IPv6 negative probes", flush=True)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("192.0.2.1", 9))
                address = sock.getsockname()[0]
            if not address.startswith("127.") and address != "0.0.0.0":
                addresses.append(address)
        except OSError:
            print("Nonloopback IPv4 route unavailable; skipping IPv4 negative probes", flush=True)
        release = platform.release().lower()
        wsl = "microsoft" in release or "wsl" in release
        for address in addresses:
            for protocol, port in ports.items():
                if wsl and ":" not in address and protocol == "udp":
                    # kiri-win uses an auxiliary WSL eth0 listener for Windows
                    # loopback UDP. A probe within WSL cannot test Windows host exposure.
                    print(f"udp: skipping WSL nonloopback IPv4 probe at {address}:{port} (Windows host exposure is not tested from WSL)", flush=True)
                    continue
                if probe(address, port, protocol):
                    raise AssertionError(f"{protocol}: fixture unexpectedly reachable at {address}:{port}")
                print(f"{protocol}: fixture unreachable at {address}:{port}", flush=True)
    finally:
        if container_id:
            try:
                docker("stop", "--time", "1", container_id, timeout=3)
            except Exception as exc:
                cleanup_errors.append(f"container stop {container_id}: {exc}")
            try:
                docker("rm", container_id, timeout=3)
                remaining = docker("ps", "-aq", "--no-trunc", timeout=3).splitlines()
                if container_id in remaining:
                    raise RuntimeError("container still present")
            except Exception as exc:
                cleanup_errors.append(f"container removal/verification {container_id}: {exc}")
        if network_id:
            try:
                docker("network", "rm", network_id, timeout=3)
                remaining = docker("network", "ls", "-q", "--no-trunc", timeout=3).splitlines()
                if network_id in remaining:
                    raise RuntimeError("network still present")
            except Exception as exc:
                cleanup_errors.append(f"network removal/verification {network_id}: {exc}")
        if cleanup_errors:
            raise RuntimeError("cleanup failed: " + "; ".join(cleanup_errors))
    print("bridge-default-host-ip-ok")


if __name__ == "__main__":
    main()
