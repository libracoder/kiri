#!/usr/bin/env python3
"""Copies the tar archive on stdin to stdout with a directory added,
/empty-numbers, whose size, uid and gid fields are all NUL bytes, its
checksum right, and a file in it, /empty-numbers/ok, holding "ok". Some image
builders write directories so (mcr.microsoft.com/azure-messaging/
servicebus-emulator): Docker reads an empty number as 0 (#618).

    docker export c | python3 tests/lib/tar-empty-numbers.py | docker import - img
"""
import io
import sys
import tarfile

src = tarfile.open(fileobj=sys.stdin.buffer, mode="r|*")
buf = io.BytesIO()
dst = tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT)
for m in src:
    dst.addfile(m, src.extractfile(m) if m.isreg() else None)
at = dst.offset
d = tarfile.TarInfo("empty-numbers")
d.type, d.mode, d.mtime = tarfile.DIRTYPE, 0o755, 1
dst.addfile(d)
f = tarfile.TarInfo("empty-numbers/ok")
f.size, f.mode, f.mtime = 3, 0o644, 1
dst.addfile(f, io.BytesIO(b"ok\n"))
dst.close()

out = bytearray(buf.getvalue())
# Its header, after a PAX header if tarfile wrote one.
at = next(i for i in range(at, len(out), 512) if out[i:i + 100].rstrip(b"\0") in (b"empty-numbers", b"empty-numbers/"))
h = out[at:at + 512]
h[108:136] = bytes(28)  # uid, gid and size
h[148:156] = b" " * 8
h[148:156] = b"%06o\0 " % sum(h)
out[at:at + 512] = h
sys.stdout.buffer.write(out)
