#!/usr/bin/env python3
"""Checks that a `docker load` whose last bytes arrive late gets an answer,
not a broken pipe, both when it loads and when it's refused.

Usage: load-trailer.py SOCKET ARCHIVE
"""
import socket
import sys
import time


def end_of_entries(data):
    """The offset of the archive's first zero block."""
    at = 0
    while data[at:at + 512] != b"\0" * 512:
        size = int(data[at + 124:at + 136].rstrip(b"\0 ") or b"0", 8)
        at += 512 + (size + 511) // 512 * 512
    return at


def load(path, first, rest):
    """Sends `first`, then `rest` 0.5 s later. Returns (status, body)."""
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(30)
    s.connect(path)
    s.sendall(b"POST /v1.47/images/load?quiet=1 HTTP/1.1\r\nHost: kiri\r\n"
              b"Content-Type: application/x-tar\r\nTransfer-Encoding: chunked\r\n\r\n")

    def chunk(b):
        s.sendall(b"%x\r\n%s\r\n" % (len(b), b))

    chunk(first)
    time.sleep(0.5)
    try:
        for at in range(0, len(rest), 65536):
            chunk(rest[at:at + 65536])
        s.sendall(b"0\r\n\r\n")
    except OSError as e:
        return None, f"the rest of the body could not be sent: {e}"
    answer = b""
    while True:
        got = s.recv(65536)
        if not got:
            break
        answer += got
    status, _, body = answer.partition(b"\r\n")
    return status.decode(), body.decode(errors="replace")


def main(path, archive):
    data = open(archive, "rb").read()
    end = end_of_entries(data) + 512
    # Valid archive, end sent late.
    status, body = load(path, data[:end], b"\0" * (512 + 10240))
    if status is None or " 200 " not in status:
        print(f"load: {status or body}")
        return
    # Bad header, then 2 MiB more.
    status, body = load(path, b"x" * 512, b"x" * (2 << 20))
    if status is None or " 400 " not in status or "message" not in body:
        print(f"refusal: {status or body}")
        return
    print("ok")


if __name__ == "__main__":
    main(*sys.argv[1:3]) if len(sys.argv) == 3 else sys.exit(__doc__)
