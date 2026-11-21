#!/usr/bin/env python3
"""Reads a `docker save` archive on stdin and says whether the image's layers
carry anything Rosetta made: prints BUILD-CLEAN, or what it found.

    docker save IMAGE | python3 tests/rosetta-layers.py BASE_LAYERS [DIR...]

The layers are read, not a container of the image: an amd64 container on
Apple silicon runs under Rosetta, which makes $HOME/.cache/rosetta before
anything in it can look. Found:
- any entry `.cache/rosetta` (or below it) and any `tmp/rosetta.*`;
- anything below each DIR (default `root/` and `home/app/`): the test's
  Dockerfile puts nothing there, so a `.cache` there is Rosetta's;
- each DIR recorded again by a layer made by a step (the layers after the
  first BASE_LAYERS) when an earlier layer already had it: a folder a step
  never touched is only in a step's layer when something was made in it.
"""
import io
import json
import sys
import tarfile


def layer_names(save, path):
    data = save.extractfile(path).read()
    # docker save writes layers uncompressed; r:* also takes gzip.
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as t:
        return [m.name for m in t.getmembers()]


def norm(name):
    while name.startswith("./"):
        name = name[2:]
    return name.strip("/")


def main():
    base = int(sys.argv[1])
    dirs = [norm(d) for d in (sys.argv[2:] or ["root/", "home/app/"])]
    with tarfile.open(fileobj=io.BytesIO(sys.stdin.buffer.read()), mode="r:*") as save:
        manifest = json.load(save.extractfile("manifest.json"))
        layers = [layer_names(save, p) for p in manifest[0]["Layers"]]
    found = []
    seen = set()
    for i, names in enumerate(layers):
        step = i >= base
        for raw in names:
            n = norm(raw)
            leaf = n.rsplit("/", 1)[-1]
            if leaf.startswith(".wh."):
                continue
            # .cache/rosetta at any depth, or below it; /tmp/rosetta.<pid>.<uid>
            if "/.cache/rosetta/" in "/" + n + "/" or (n.startswith("tmp/") and leaf.startswith("rosetta.")):
                found.append(f"layer {i}: {n}")
            for d in dirs:
                if n.startswith(d + "/"):
                    found.append(f"layer {i}: {n}")
                elif n == d and d in seen and step:
                    found.append(f"layer {i}: {n}/ recorded again")
        seen.update(d for d in dirs if any(norm(r) == d for r in names))
    print("BUILD-CLEAN" if not found else "; ".join(dict.fromkeys(found)))


main()
