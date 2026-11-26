#!/usr/bin/env python3
"""Head-to-head Linux benchmark: Kiri Engine vs Docker Engine (`dockerd`).

Measures real-world container lifecycle and developer-workflow workloads on the
same Linux machine (alternating iterations so scheduler noise affects both
equally), producing a transparent markdown summary and JSON artifact (#776):

  1. Ephemeral lifecycle (`docker run --rm alpine:3.21 true`, median & p95)
  2. Multi-layer PHP app cold start (`php:8.2-cli-alpine` + 1,000-file bind mount
     + published port + HTTP readiness, modeling Lando / Compose dev stacks)
  3. Warm app restart (`POST /containers/{id}/restart` + HTTP readiness)
  4. Container `exec` (`100x php -r "echo 'ok';"` over Engine API)
  5. Bind-mount filesystem I/O (`1,000` PHP files `glob` + `file_get_contents`)
  6. Published-port HTTP latency (`250` GET requests)
  7. App teardown (`stop` + `DELETE`, `SIGINT` stop signal)
  8. Idle & post-benchmark engine RSS memory

Usage:
  python3 scripts/bench-linux-docker.py --docker-sock /var/run/docker.sock \\
      --kiri-sock /tmp/kiri-bench/docker.sock --kiri-pid <PID> \\
      [--out results.json] [--report report.md]

Standard library only.
"""

import argparse
import http.client
import json
import os
import re
import socket
import statistics
import subprocess
import tempfile
import time
import urllib.request

ALPINE_IMG, ALPINE_TAG = "alpine", "3.21"
PHP_IMG, PHP_TAG = "php", "8.2-cli-alpine"


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=120)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(120)
        self.sock.connect(self.path)


class Client:
    def __init__(self, name, sock):
        self.name = name
        self.sock = sock
        self.conn = UnixHTTP(sock)

    def reset(self):
        try:
            self.conn.close()
        except Exception:
            pass
        self.conn = UnixHTTP(self.sock)

    def call(self, method, path, body=None, want=(200, 201, 204, 304)):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        for attempt in range(2):
            try:
                self.conn.request(method, path, body=data, headers=headers)
                r = self.conn.getresponse()
                out = r.read()
                break
            except (http.client.HTTPException, OSError):
                self.reset()
                if attempt:
                    raise
        if r.status not in want:
            raise RuntimeError(f"[{self.name}] {method} {path}: {r.status} {out[:300]!r}")
        return out

    def pull(self, image, tag):
        self.call("POST", f"/images/create?fromImage={image}&tag={tag}")

    def run_ephemeral(self):
        cid = json.loads(
            self.call("POST", "/containers/create", {"Image": f"{ALPINE_IMG}:{ALPINE_TAG}", "Cmd": ["true"]})
        )["Id"]
        self.call("POST", f"/containers/{cid}/start")
        self.call("POST", f"/containers/{cid}/wait")
        self.call("DELETE", f"/containers/{cid}?force=1")

    def exec_run(self, cid, cmd):
        eid = json.loads(
            self.call(
                "POST",
                f"/containers/{cid}/exec",
                {"AttachStdout": True, "AttachStderr": True, "Cmd": cmd},
            )
        )["Id"]
        return self.call("POST", f"/exec/{eid}/start", {"Detach": False, "Tty": False})


def proc_tree_rss_kib(pids):
    seen = set()
    queue = [p for p in pids if p and p > 0]
    while queue:
        pid = queue.pop()
        if pid in seen:
            continue
        seen.add(pid)
        try:
            with open(f"/proc/{pid}/task/{pid}/children") as f:
                for tok in f.read().split():
                    queue.append(int(tok))
        except OSError:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                try:
                    with open(f"/proc/{entry}/stat") as sf:
                        st = sf.read()
                    ppid = int(st.rsplit(")", 1)[1].split()[1])
                    if ppid == pid:
                        queue.append(int(entry))
                except OSError:
                    pass
    total = 0
    for pid in seen:
        try:
            with open(f"/proc/{pid}/status") as f:
                m = re.search(r"VmRSS:\s+(\d+)", f.read())
                if m:
                    total += int(m.group(1))
        except OSError:
            pass
    return total


def pidof_names(names):
    out = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/comm") as f:
                comm = f.read().strip()
            if comm in names:
                out.append(int(entry))
        except OSError:
            pass
    return out


def wait_http_ok(port, timeout_s=15.0):
    deadline = time.perf_counter() + timeout_s
    url = f"http://127.0.0.1:{port}/"
    while time.perf_counter() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                if resp.status == 200 and b"ok" in resp.read():
                    return
        except Exception:
            time.sleep(0.01)
    raise RuntimeError(f"HTTP server on port {port} did not become ready within {timeout_s}s")


def create_php_app(client, app_dir):
    body = {
        "Image": f"{PHP_IMG}:{PHP_TAG}",
        "Cmd": ["php", "-S", "0.0.0.0:80", "-t", "/app"],
        "StopSignal": "SIGINT",
        "ExposedPorts": {"80/tcp": {}},
        "HostConfig": {
            "Binds": [f"{app_dir}:/app"],
            "PortBindings": {"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "0"}]},
        },
    }
    cid = json.loads(client.call("POST", "/containers/create", body))["Id"]
    client.call("POST", f"/containers/{cid}/start")
    info = json.loads(client.call("GET", f"/containers/{cid}/json"))
    port = int(info["NetworkSettings"]["Ports"]["80/tcp"][0]["HostPort"])
    wait_http_ok(port)
    return cid, port


def destroy_php_app(client, cid):
    client.call("POST", f"/containers/{cid}/stop?t=5")
    client.call("DELETE", f"/containers/{cid}?force=1")


def restart_php_app(client, cid):
    client.call("POST", f"/containers/{cid}/restart?t=5")
    info = json.loads(client.call("GET", f"/containers/{cid}/json"))
    port = int(info["NetworkSettings"]["Ports"]["80/tcp"][0]["HostPort"])
    wait_http_ok(port)
    return port


def summary(xs):
    xs = sorted(xs)
    p95_idx = max(0, int(len(xs) * 0.95) - 1)
    return {"median": statistics.median(xs), "mean": statistics.mean(xs), "p95": xs[p95_idx], "n": len(xs)}


def extract_digits(raw):
    # Strip Docker multiplexed stream headers (8-byte frames) and extract trailing integer.
    clean = re.sub(rb"[\x00-\x08]", b"", raw).decode("utf-8", errors="ignore").strip().splitlines()
    for line in reversed(clean):
        digits = "".join(ch for ch in line if ch.isdigit())
        if digits:
            return float(digits)
    raise RuntimeError(f"could not parse numeric output from {raw!r}")


def http_burst_ms(port, count=250):
    t0 = time.perf_counter()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        for _ in range(count):
            conn.request("GET", "/")
            r = conn.getresponse()
            r.read()
    finally:
        conn.close()
    return (time.perf_counter() - t0) * 1000.0


def run_benchmark(args):
    docker = Client("docker", args.docker_sock)
    kiri = Client("kiri", args.kiri_sock)
    engines = [("docker", docker), ("kiri", kiri)]

    d_ver = json.loads(docker.call("GET", "/version"))
    if "kiri" in json.dumps(d_ver).lower():
        raise RuntimeError(f"--docker-sock ({args.docker_sock}) answered as Kiri ({d_ver.get('Platform')}); start dockerd first")

    for _, c in engines:
        c.call("GET", "/_ping")
        c.pull(ALPINE_IMG, ALPINE_TAG)
        c.pull(PHP_IMG, PHP_TAG)
        for _ in range(5):
            c.run_ephemeral()

    time.sleep(1.0)
    docker_pids = pidof_names({"dockerd", "containerd"})
    kiri_pids = [args.kiri_pid] if args.kiri_pid else pidof_names({"kiri", "kiri-init"})

    res = {
        "kiri_version": args.version or "HEAD",
        "docker": {"rss_idle_kib": proc_tree_rss_kib(docker_pids)},
        "kiri": {"rss_idle_kib": proc_tree_rss_kib(kiri_pids)},
    }

    # 1. Alternating `docker run --rm alpine true`
    ephemeral = {"docker": [], "kiri": []}
    for i in range(args.ephemeral_runs):
        pair = engines if i % 2 == 0 else list(reversed(engines))
        for name, c in pair:
            t0 = time.perf_counter()
            c.run_ephemeral()
            ephemeral[name].append((time.perf_counter() - t0) * 1000.0)
    for name in ("docker", "kiri"):
        res[name]["ephemeral_run_ms"] = summary(ephemeral[name])

    # Prepare 1,000-file PHP fixture app (matching Xilonz/lando-engine-kiri)
    with tempfile.TemporaryDirectory(prefix="kiri-php-bench-") as app_dir:
        with open(os.path.join(app_dir, "index.php"), "w") as f:
            f.write("<?php echo 'ok';\n")
        fixtures = os.path.join(app_dir, "fixtures")
        os.makedirs(fixtures, exist_ok=True)
        for i in range(1, 1001):
            with open(os.path.join(fixtures, f"file_{i}.php"), "w") as f:
                f.write(f"<?php return 'fixture_data_{i}';\n")

        cold = {"docker": [], "kiri": []}
        destroy = {"docker": [], "kiri": []}
        active = {}

        # 2. Cold start & teardown (alternating)
        for i in range(args.app_runs):
            pair = engines if i % 2 == 0 else list(reversed(engines))
            for name, c in pair:
                t0 = time.perf_counter()
                cid, port = create_php_app(c, app_dir)
                cold[name].append((time.perf_counter() - t0) * 1000.0)
                if i < args.app_runs - 1:
                    t1 = time.perf_counter()
                    destroy_php_app(c, cid)
                    destroy[name].append((time.perf_counter() - t1) * 1000.0)
                else:
                    active[name] = (cid, port)

        # 3. Warm restart (alternating)
        warm = {"docker": [], "kiri": []}
        for i in range(args.app_runs):
            pair = engines if i % 2 == 0 else list(reversed(engines))
            for name, c in pair:
                cid, _ = active[name]
                t0 = time.perf_counter()
                port = restart_php_app(c, cid)
                warm[name].append((time.perf_counter() - t0) * 1000.0)
                active[name] = (cid, port)

        # 4. 100x exec (`php -r "echo 'ok';"`)
        for name, c in engines:
            cid, _ = active[name]
            t0 = time.perf_counter()
            for _ in range(args.exec_runs):
                c.exec_run(cid, ["php", "-r", "echo 'ok';"])
            res[name]["exec_total_ms"] = (time.perf_counter() - t0) * 1000.0
            res[name]["exec_runs"] = args.exec_runs

        # 5. Bind-mount I/O (1,000 files, 10 passes inside PHP)
        php_io = (
            "$total = 0; "
            "for ($p = 0; $p < 10; $p++) { "
            "  $t = microtime(true); "
            "  $files = glob('/app/fixtures/*.php'); "
            "  $sum = 0; "
            "  foreach ($files as $f) { $sum += strlen(file_get_contents($f)); } "
            "  $total += (microtime(true) - $t); "
            "} "
            "echo round(($total / 10) * 1000000);"
        )
        for name, c in engines:
            cid, _ = active[name]
            raw = c.exec_run(cid, ["php", "-r", php_io])
            res[name]["bind_io_ms"] = extract_digits(raw) / 1000.0

        # 6. Published-port HTTP latency (250 GET requests)
        for name, _ in engines:
            _, port = active[name]
            res[name]["http_250_ms"] = http_burst_ms(port, 250)

        # Final teardown sample
        for name, c in engines:
            cid, _ = active[name]
            t1 = time.perf_counter()
            destroy_php_app(c, cid)
            destroy[name].append((time.perf_counter() - t1) * 1000.0)

        for name in ("docker", "kiri"):
            res[name]["app_cold_start_ms"] = summary(cold[name])
            res[name]["app_warm_restart_ms"] = summary(warm[name])
            res[name]["app_teardown_ms"] = summary(destroy[name])

    res["docker"]["rss_after_kib"] = proc_tree_rss_kib(pidof_names({"dockerd", "containerd"}))
    res["kiri"]["rss_after_kib"] = proc_tree_rss_kib([args.kiri_pid] if args.kiri_pid else pidof_names({"kiri", "kiri-init"}))
    return res


def format_diff(d_val, k_val, unit="ms", decimals=2):
    if d_val <= 0:
        return "—"
    pct = (k_val - d_val) / d_val * 100.0
    word = "faster ⚡" if pct < -1.0 else ("slower" if pct > 1.0 else "on par")
    return f"{k_val - d_val:+.{decimals}f} {unit} ({abs(pct):.1f}% {word})"


def render_markdown(res):
    d, k = res["docker"], res["kiri"]
    lines = [
        f"## Linux Benchmark: Kiri (`{res.get('kiri_version', 'HEAD')}`) vs Docker Engine",
        "",
        "Alternating head-to-head runs on the same Linux host (ephemeral `alpine:3.21` + `php:8.2-cli-alpine` app stack with 1,000 bind-mounted files and published HTTP port).",
        "",
        "| Workload | Docker Engine | Kiri Engine | Comparison |",
        "| :--- | ---: | ---: | :--- |",
        f"| `docker run --rm alpine true` (median) | {d['ephemeral_run_ms']['median']:.2f} ms | {k['ephemeral_run_ms']['median']:.2f} ms | {format_diff(d['ephemeral_run_ms']['median'], k['ephemeral_run_ms']['median'])} |",
        f"| `docker run --rm alpine true` (p95) | {d['ephemeral_run_ms']['p95']:.2f} ms | {k['ephemeral_run_ms']['p95']:.2f} ms | {format_diff(d['ephemeral_run_ms']['p95'], k['ephemeral_run_ms']['p95'])} |",
        f"| PHP app cold start + HTTP ready (avg) | {d['app_cold_start_ms']['mean']:.1f} ms | {k['app_cold_start_ms']['mean']:.1f} ms | {format_diff(d['app_cold_start_ms']['mean'], k['app_cold_start_ms']['mean'], 'ms', 1)} |",
        f"| PHP app warm restart + HTTP ready (avg) | {d['app_warm_restart_ms']['mean']:.1f} ms | {k['app_warm_restart_ms']['mean']:.1f} ms | {format_diff(d['app_warm_restart_ms']['mean'], k['app_warm_restart_ms']['mean'], 'ms', 1)} |",
        f"| `{k['exec_runs']}x` `exec php -r \"echo 'ok';\"` | {d['exec_total_ms']:.1f} ms | {k['exec_total_ms']:.1f} ms | {format_diff(d['exec_total_ms'], k['exec_total_ms'], 'ms', 1)} |",
        f"| Bind-mount I/O (1,000 PHP files, avg) | {d['bind_io_ms']:.2f} ms | {k['bind_io_ms']:.2f} ms | {format_diff(d['bind_io_ms'], k['bind_io_ms'])} |",
        f"| Published-port HTTP (250 GETs) | {d['http_250_ms']:.1f} ms | {k['http_250_ms']:.1f} ms | {format_diff(d['http_250_ms'], k['http_250_ms'], 'ms', 1)} |",
        f"| App teardown (`SIGINT` stop + rm, avg) | {d['app_teardown_ms']['mean']:.1f} ms | {k['app_teardown_ms']['mean']:.1f} ms | {format_diff(d['app_teardown_ms']['mean'], k['app_teardown_ms']['mean'], 'ms', 1)} |",
        f"| Engine RSS at rest | {d['rss_idle_kib'] / 1024:.1f} MiB | {k['rss_idle_kib'] / 1024:.1f} MiB | {format_diff(d['rss_idle_kib'] / 1024, k['rss_idle_kib'] / 1024, 'MiB', 1)} |",
        f"| Engine RSS after benchmark | {d['rss_after_kib'] / 1024:.1f} MiB | {k['rss_after_kib'] / 1024:.1f} MiB | {format_diff(d['rss_after_kib'] / 1024, k['rss_after_kib'] / 1024, 'MiB', 1)} |",
        "",
    ]
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--docker-sock", default="/var/run/docker.sock")
    p.add_argument("--kiri-sock", required=True)
    p.add_argument("--kiri-pid", type=int, default=0)
    p.add_argument("--version", default="")
    p.add_argument("--ephemeral-runs", type=int, default=100)
    p.add_argument("--app-runs", type=int, default=10)
    p.add_argument("--exec-runs", type=int, default=100)
    p.add_argument("--out", default="")
    p.add_argument("--report", default="")
    args = p.parse_args()

    res = run_benchmark(args)
    if args.out:
        with open(args.out, "w") as f:
            json.dump(res, f, indent=2)
    md = render_markdown(res)
    if args.report:
        with open(args.report, "w") as f:
            f.write(md)
    print(md)


if __name__ == "__main__":
    main()
