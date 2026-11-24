"""Writes OCI image-layout archives from a `docker save` tarball (stdin or file),
for the e2e checks of issue 465 and fast-path verification (#782).
Usage: oci-image.py SRC.tar OUT.tar <ref|untagged|multi|tampered> [TAG]"""
import hashlib, io, json, sys, tarfile

src, out, mode = sys.argv[1:4]
tag = sys.argv[4] if len(sys.argv) > 4 else ""

with tarfile.open(src, mode="r:*") as t:
    members = {m.name.lstrip("./"): t.extractfile(m).read() for m in t.getmembers() if m.isfile()}

entry = json.loads(members["manifest.json"])[0]
cfg_bytes = members[entry["Config"].lstrip("./")]
layer_bytes = members[entry["Layers"][0].lstrip("./")]

def add_blob(blobs, data):
    h = hashlib.sha256(data).hexdigest()
    blobs[f"blobs/sha256/{h}"] = data
    return f"sha256:{h}", len(data)

def make_manifest(blobs, cfg, layer, layer_mt):
    cd, cs = add_blob(blobs, cfg)
    ld, ls = add_blob(blobs, layer)
    man = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cd, "size": cs},
        "layers": [{"mediaType": layer_mt, "digest": ld, "size": ls}],
    }).encode()
    md, ms = add_blob(blobs, man)
    return md, ms

layer_mt = (
    "application/vnd.oci.image.layer.v1.tar+gzip" if layer_bytes[:2] == b"\x1f\x8b"
    else "application/vnd.oci.image.layer.v1.tar+zstd" if layer_bytes[:4] == b"\x28\xb5\x2f\xfd"
    else "application/vnd.oci.image.layer.v1.tar"
)
blobs = {}
descriptors = []

if mode == "ref":
    md, ms = make_manifest(blobs, cfg_bytes, layer_bytes, layer_mt)
    descriptors.append({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": md, "size": ms,
        "annotations": {"org.opencontainers.image.ref.name": tag},
    })
elif mode == "untagged":
    cfg_doc = json.loads(cfg_bytes)
    cfg_doc = dict(cfg_doc, created="2026-11-24T00:00:01Z")
    md, ms = make_manifest(blobs, json.dumps(cfg_doc).encode(), layer_bytes, layer_mt)
    descriptors.append({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": md, "size": ms,
    })
elif mode == "multi":
    cfg_doc = json.loads(cfg_bytes)
    children = []
    for arch in ("amd64", "arm64"):
        c = dict(cfg_doc, architecture=arch, os="linux", created="2026-11-24T00:00:02Z")
        md, ms = make_manifest(blobs, json.dumps(c).encode(), layer_bytes, layer_mt)
        children.append({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": md, "size": ms,
            "platform": {"os": "linux", "architecture": arch},
        })
    children.append({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": "sha256:" + "9" * 64, "size": 123,
        "platform": {"os": "unknown", "architecture": "unknown"},
        "annotations": {"vnd.docker.reference.type": "attestation-manifest"},
    })
    idx = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": children}).encode()
    idg, isz = add_blob(blobs, idx)
    descriptors.append({
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "digest": idg, "size": isz,
        "annotations": {
            "io.containerd.image.name": f"docker.io/{tag}",
            "org.opencontainers.image.ref.name": tag.rsplit(":", 1)[-1],
        },
    })
elif mode == "tampered":
    md, ms = make_manifest(blobs, cfg_bytes, layer_bytes, layer_mt)
    ld = "blobs/sha256/" + hashlib.sha256(layer_bytes).hexdigest()
    tampered = bytes([layer_bytes[0] ^ 0xff]) + layer_bytes[1:]
    blobs[ld] = tampered
    descriptors.append({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": md, "size": ms,
        "annotations": {"org.opencontainers.image.ref.name": tag},
    })
else:
    raise SystemExit(f"unknown mode: {mode}")

blobs["oci-layout"] = b'{"imageLayoutVersion":"1.0.0"}'
blobs["index.json"] = json.dumps({"schemaVersion": 2, "manifests": descriptors}).encode()

with tarfile.open(out, mode="w") as t:
    for name, data in blobs.items():
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mode = 0o644
        t.addfile(info, io.BytesIO(data))
