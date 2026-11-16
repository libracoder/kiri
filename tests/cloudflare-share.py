#!/usr/bin/env python3
"""Exercise the real CLI/helper with a fake cloudflared; no public network.

python3 tests/cloudflare-share.py target/debug/kiri
"""
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import tempfile
import threading
import time

BINARY = str(Path(sys.argv[1]).resolve())
FAKE = r'''
import http.server, json, os, pathlib, sys, time
args = sys.argv[1:]
arg = lambda name: args[args.index(name) + 1]
root = pathlib.Path(os.environ["KIRI_CF_TEST"])
config = pathlib.Path(arg("--config"))
runtime = config.parent
(root / (str(os.getpid()) + ".json")).write_text(json.dumps({"pid":os.getpid(), "args":args, "config":json.loads(config.read_text()), "token":os.environ.get("TUNNEL_TOKEN"), "runtime":str(runtime)}))
if (root / "fail").exists():
    print(json.dumps({"message":"private-token-must-not-leak"}), file=sys.stderr, flush=True)
    sys.exit(7)
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        self.send_response(503 if (root / "offline").exists() else 200)
        self.end_headers()
    def log_message(self, *args): pass
server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
print(json.dumps({"message":f"Starting metrics server on 127.0.0.1:{server.server_port}/metrics"}), file=sys.stderr, flush=True)
if "--url" in args:
    print(json.dumps({"message":"| https://test-river.trycloudflare.com |"}), file=sys.stderr, flush=True)
pathlib.Path(arg("--pidfile")).write_text(str(os.getpid()))
server.serve_forever()
'''


def eventually(fn, timeout=8):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if fn():
            return
        time.sleep(.05)
    raise AssertionError("condition did not become true")


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


class Share:
    def __init__(self, env, *args):
        self.process = subprocess.Popen([BINARY, "share", "3000", *args, "--json"], env=env,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.events = queue.Queue()
        self.seen = []

        def read():
            for line in self.process.stdout:
                try:
                    self.events.put(json.loads(line))
                except ValueError:
                    self.events.put({"bad": line})
        threading.Thread(target=read, daemon=True).start()

    def event(self, name, timeout=10):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                e = self.events.get(timeout=max(.01, end - time.monotonic()))
            except queue.Empty:
                break
            self.seen.append(e)
            assert "bad" not in e, e
            if e.get("event") == name:
                return e
            assert e.get("event") != "ended", e
        raise AssertionError(f"no {name} event: {self.seen}")


def main():
    with tempfile.TemporaryDirectory(prefix="kiri-cf-test-") as temp:
        root = Path(temp)
        fake = root / "cloudflared"
        fake.write_text("#!" + sys.executable + "\n" + FAKE)
        fake.chmod(0o700)
        config = root / "share.json"
        env = {**os.environ, "KIRI_SHARE_CONFIG": str(config), "KIRI_CF_TEST": temp,
               "TUNNEL_TOKEN": "unrelated-token-must-be-removed"}
        children = []

        def save(extra=None):
            config.write_text(json.dumps({"provider": "cloudflare", "cloudflare": {"executable": str(fake), **(extra or {})}}))

        def cli(*args, ok=True):
            p = subprocess.run([BINARY, "share", *args], env=env, capture_output=True, text=True, timeout=10)
            if ok:
                assert p.returncode == 0, (p.stdout, p.stderr)
            return p

        def start(*args):
            share = Share(env, *args)
            children.append(share.process)
            return share

        def captures():
            return [json.loads(p.read_text()) for p in root.glob("[0-9]*.json")]

        def closed(capture):
            eventually(lambda: not alive(capture["pid"]))
            eventually(lambda: not Path(capture["runtime"]).exists())

        try:
            save()
            unrelated = root / "keep-this-directory"
            unrelated.mkdir()
            marker = unrelated / "keep.txt"
            marker.write_text("keep")
            rejected = subprocess.run([BINARY, "__share-cloudflared", str(unrelated)], env=env, capture_output=True, text=True, timeout=5)
            assert rejected.returncode != 0 and marker.read_text() == "keep"
            assert json.loads(cli("status", "--json").stdout)["provider"] == "cloudflare"
            share = start()
            assert share.event("live")["url"] == "https://test-river.trycloudflare.com"
            capture = captures()[-1]
            assert capture["token"] is None
            assert capture["config"] == {}
            assert capture["args"][-2:] == ["--url", "http://localhost:3000"]
            (root / "offline").touch()
            share.event("reconnecting")
            (root / "offline").unlink()
            share.event("live")
            entries = json.loads(cli("list", "--json").stdout)["items"]
            assert len(entries) == 1 and entries[0]["kind"] == "cli", entries
            cli("stop", entries[0]["name"])
            assert share.event("ended")["error"] is False
            assert share.process.wait(timeout=5) == 0
            closed(capture)
            assert json.loads(cli("list", "--json").stdout)["items"] == []
            print("PASS temporary URL, readiness/reconnect, list and stop")

            before = {c["pid"] for c in captures()}
            share = start()
            share.event("live")
            capture = next(c for c in captures() if c["pid"] not in before)
            share.process.kill()
            share.process.wait(timeout=5)
            closed(capture)
            print("PASS parent SIGKILL closes and reaps cloudflared")

            before = {c["pid"] for c in captures()}
            (root / "offline").touch()
            share = start()
            share.event("connecting")
            eventually(lambda: any(c["pid"] not in before for c in captures()))
            capture = next(c for c in captures() if c["pid"] not in before)
            cli("stop", Path(capture["runtime"]).name)
            assert share.event("ended")["error"] is False
            assert not any(e.get("event") == "live" for e in share.seen)
            share.process.wait(timeout=5)
            closed(capture)
            (root / "offline").unlink()
            print("PASS cancellation before readiness and helper directory validation")

            tunnel = "01234567-89ab-cdef-0123-456789abcdef"
            credentials = root / "credentials.json"
            credentials.write_text(json.dumps({"TunnelID": tunnel, "TunnelSecret": "not-a-real-secret"}))
            save({"base_domain": "example.com", "tunnels": {"web": {"id": tunnel, "credentials_file": str(credentials)}}})
            before = {c["pid"] for c in captures()}
            share = start("--name", "web")
            assert share.event("live")["url"] == "https://web.example.com"
            capture = next(c for c in captures() if c["pid"] not in before)
            assert capture["config"]["ingress"] == [{"hostname": "web.example.com", "service": "http://localhost:3000"}, {"service": "http_status:404"}]
            assert "not-a-real-secret" not in json.dumps(capture)
            duplicate = start("--name", "web")
            assert "already running" in duplicate.event("ended")["reason"]
            assert duplicate.process.wait(timeout=5) != 0
            missing = cli("3000", "--name", "missing", "--json", ok=False)
            assert missing.returncode != 0 and "configure cloudflare.tunnels.missing" in missing.stdout
            assert cli("login", ok=False).returncode != 0
            entry = json.loads(cli("list", "--json").stdout)["items"][0]
            cli("stop", entry["name"])
            assert share.event("ended")["error"] is False
            share.process.wait(timeout=5)
            closed(capture)
            print("PASS named ingress, credential isolation, duplicate lock and missing-name errors")

            save()
            (root / "fail").touch()
            share = start()
            ended = share.event("ended")
            assert ended["error"] is True
            assert share.process.wait(timeout=5) != 0
            assert "private-token-must-not-leak" not in json.dumps(share.seen)
            (root / "fail").unlink()
            cli("provider", "kiri")
            assert json.loads(config.read_text())["provider"] == "kiri"
            print("PASS child failure, log redaction and switching providers")
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
            # A failed assertion must still leave no tunnel fixture behind.
            for capture in captures():
                if alive(capture["pid"]):
                    eventually(lambda c=capture: not alive(c["pid"]))


if __name__ == "__main__":
    main()
