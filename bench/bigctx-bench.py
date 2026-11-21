#!/usr/bin/env python3
"""Big-context build timings on a running Kiri engine: first build, no
change, one file changed, for contexts of N files of 1 KiB (`COPY . /src`
on alpine:3.21), with the engine's stage timings for each build.

    python3 bigctx-bench.py [--kiri PATH] [--work DIR] [--runs 3] N [N ...]

Needs alpine:3.21 in the engine. Writes the contexts under --work (default
~/kiri-bigctx-bench), reuses one that is already there with the same N.
The stage line of each build is read from the engine's log
(~/.kiri/logs/daemon.log, message "build stages"); on an engine that does
not write it yet the stage column stays empty.

"First build" is a build with --no-cache after the context is rewritten
(new inodes and times, so no index or cache entry can serve it); "no
change" and "one change" are plain rebuilds.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

p = argparse.ArgumentParser()
p.add_argument("sizes", nargs="+", type=int)
p.add_argument("--kiri", default=shutil.which("kiri") or "kiri")
p.add_argument("--work", default=os.path.expanduser("~/kiri-bigctx-bench"))
p.add_argument("--runs", type=int, default=3)
p.add_argument("--log", default=os.path.expanduser("~/.kiri/logs/daemon.log"))
a = p.parse_args()


def load():
    try:
        return open("/proc/loadavg").read().split()[0]
    except OSError:
        out = subprocess.run(["sysctl", "-n", "vm.loadavg"], capture_output=True, text=True).stdout
        return out.strip("{} \n").split()[0] if out else "?"


def gen(root, n):
    if os.path.isdir(root):
        shutil.rmtree(root)
    for i in range(n):
        d, b = divmod(i, 100)
        dd = f"{root}/tree/d{d:04d}"
        if b == 0:
            os.makedirs(dd, exist_ok=True)
        out = bytearray()
        k = 0
        while len(out) < 1024:
            out += hashlib.sha256(f"big{d}/{b}/{k}".encode()).hexdigest().encode() + b"\n"
            k += 1
        with open(f"{dd}/f{b:02d}.txt", "wb") as f:
            f.write(out[:1024])
    os.makedirs(f"{root}/src", exist_ok=True)
    with open(f"{root}/src/change.txt", "w") as f:
        f.write("start\n")
    with open(f"{root}/Dockerfile", "w") as f:
        f.write('FROM alpine:3.21\nCOPY . /src\nCMD ["true"]\n')


def log_size():
    try:
        return os.path.getsize(a.log)
    except OSError:
        return 0


def stages_since(off):
    """The last "build stages" line written to the log after `off`."""
    try:
        with open(a.log, "rb") as f:
            f.seek(off)
            lines = f.read().decode(errors="replace").splitlines()
    except OSError:
        return ""
    for line in reversed(lines):
        try:
            v = json.loads(line)
        except ValueError:
            continue
        if v.get("msg") == "build stages":
            return v.get("fields", {}).get("stages", "")
    return ""


def build(ctx, tag, *extra):
    off = log_size()
    t = time.monotonic()
    r = subprocess.run([a.kiri, "build", "-q", *extra, "-t", tag, ctx], capture_output=True, text=True)
    dt = time.monotonic() - t
    if r.returncode != 0:
        sys.exit(f"build failed:\n{r.stdout}\n{r.stderr}")
    time.sleep(0.05)
    return dt, stages_since(off)


rows = []
for n in a.sizes:
    ctx = os.path.join(a.work, f"ctx{n}")
    tag = f"kiri-bigctx-bench:{n}"
    for run in range(a.runs):
        gen(ctx, n)
        # past the index's racy tick (2 s), as a context edited a while ago
        time.sleep(2.5)
        res = [("first", *build(ctx, tag, "--no-cache"))]
        res.append(("no change", *build(ctx, tag)))
        res.append(("no change", *build(ctx, tag)))
        with open(f"{ctx}/src/change.txt", "w") as f:
            f.write(f"changed {run}\n")
        res.append(("one change", *build(ctx, tag)))
        with open(f"{ctx}/tree/d0000/f00.txt", "a") as f:
            f.write("x")
        res.append(("one change", *build(ctx, tag)))
        for what, dt, st in res:
            line = f"{n:>7} files  run {run + 1}  {what:<10} {dt:7.2f} s  load {load():>5}  {st}"
            print(line, flush=True)
            rows.append((n, what, dt))

print("\nbest of runs:")
for n in a.sizes:
    for what in ["first", "no change", "one change"]:
        best = min(dt for m, w, dt in rows if m == n and w == what)
        print(f"{n:>7} files  {what:<10} {best:7.2f} s")
