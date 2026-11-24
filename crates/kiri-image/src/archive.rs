//! `docker load` and `docker save`: image tarballs in Docker's format
//! (`manifest.json` naming a config and layer files per image), which is
//! also what `docker buildx build --load` produces, and in the OCI image
//! layout (`index.json` plus `blobs/sha256/...`), which is what
//! `docker buildx build --output type=oci` and `skopeo` produce. Archives are
//! streamed: each file goes straight into the blob store as it is read, and
//! content-addressed blobs already in the store are verified in memory without
//! rewriting disk files.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::reference::Reference;
use crate::registry::Platform;
use crate::store::{Image, Layer, RunConfig, Store};

/// Largest JSON file kept in memory while reading an archive.
const MAX_JSON: u64 = 4 << 20;
/// Maximum recursion depth and total descriptors walked in an OCI index tree.
const MAX_OCI_DEPTH: usize = 8;
const MAX_OCI_STEPS: usize = 1024;

/// Reads an archive into the store. Returns the images it named.
pub fn load(store: &Store, archive: impl Read) -> io::Result<Vec<Image>> {
    load_platforms(store, archive, &[])
}

/// As [`load`], but picks the matching entry of a multi-platform OCI index
/// when `platform` is given (`docker load --platform`).
pub fn load_with_platform(store: &Store, archive: impl Read, platform: Option<&Platform>) -> io::Result<Vec<Image>> {
    load_platforms(store, archive, platform.map_or(&[], std::slice::from_ref))
}

/// As [`load`], filtering a multi-platform OCI index to `platforms` when non-empty.
pub fn load_platforms(store: &Store, archive: impl Read, platforms: &[Platform]) -> io::Result<Vec<Image>> {
    let mut tar = tar::Archive::new(archive);
    // Archive path → blob digest and size, for every regular file.
    let mut files: HashMap<String, (String, u64)> = HashMap::new();
    let mut manifest: Option<Vec<u8>> = None;
    let mut index: Option<Vec<u8>> = None;
    let mut oci_layout: Option<Vec<u8>> = None;
    let before: Vec<Image> = store.images()?;
    let existed = |d: &str| before.iter().any(|i| i.referenced_digests().any(|r| r == d));
    let mut ingested: Vec<String> = Vec::new();
    let mut pins = Vec::new();
    let read = (|| -> io::Result<Vec<Image>> {
        for entry in tar.entries()? {
            let mut entry = entry?;
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let path = entry.path()?.to_string_lossy().trim_start_matches("./").to_owned();
            if path == "manifest.json" || path == "index.json" || path == "oci-layout" {
                let mut buf = Vec::new();
                (&mut entry).take(MAX_JSON + 1).read_to_end(&mut buf)?;
                if buf.len() as u64 > MAX_JSON {
                    return Err(invalid(format!("{path} is larger than {MAX_JSON} bytes")));
                }
                match path.as_str() {
                    "manifest.json" => manifest = Some(buf),
                    "index.json" => index = Some(buf),
                    _ => oci_layout = Some(buf),
                }
                continue;
            }
            // Fast path for content-addressed blobs (`blobs/sha256/<hex>`):
            // pin first so a concurrent removal cannot delete the blob while
            // we inspect it, check it is already on disk with the right size,
            // and hash every byte of the tar entry in memory instead of writing
            // a temp file and fsyncing.
            if let Some(hex) = path.strip_prefix("blobs/sha256/")
                && hex.len() == 64
                && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            {
                let size = entry.header().size()?;
                let digest = format!("sha256:{hex}");
                let pin = store.pin(&digest);
                if store.has_blob(&digest, size) {
                    let (computed_digest, computed_size) = crate::store::hash_stream(&mut entry)?;
                    if computed_size != size || computed_digest != digest {
                        return Err(invalid(format!("archive blob {digest} is damaged: its bytes hash to {computed_digest}")));
                    }
                    pins.push(pin);
                    files.insert(path, (digest, size));
                    continue;
                }
            }
            // Every other file is kept, `.json` ones too: in the classic layout
            // (podman save, older docker save) the image config is a top-level
            // `<hex>.json`. Files no image names are removed after the manifest.
            let mut w = store.ingest()?;
            io::copy(&mut entry, &mut w)?;
            // Held until its image is recorded: a removal of another image
            // that shares the blob must not delete it meanwhile.
            let (digest, size, pin) = w.finish_pinned()?;
            pins.push(pin);
            if !existed(&digest) && !ingested.contains(&digest) {
                ingested.push(digest.clone());
            }
            files.insert(path, (digest, size));
        }
        // A docker-archive has manifest.json; an OCI layout has index.json. A
        // hybrid has both, and docker's wins: that keeps existing loads intact.
        if let Some(manifest) = manifest {
            load_docker(store, &files, &manifest)
        } else if let Some(index) = index {
            load_oci(store, &files, &index, oci_layout.as_deref(), platforms)
        } else {
            Err(invalid("not an image archive: no manifest.json or index.json"))
        }
    })();
    // Files no image uses (OCI index blobs, skipped platforms, or all of a refused archive) do not stay.
    let used = |d: &str| read.as_ref().is_ok_and(|loaded| loaded.iter().any(|i| i.config_digest == d || i.layers.iter().any(|l| l.digest == d)));
    // The images are recorded: what they name is safe, and what nothing
    // names goes unless another image or writer has it now.
    drop(pins);
    for d in ingested.iter().filter(|d| !used(d)) {
        store.remove_if_unused(d)?;
    }
    read
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn lookup(files: &HashMap<String, (String, u64)>, path: &str) -> io::Result<(String, u64)> {
    files.get(path.trim_start_matches("./")).cloned().ok_or_else(|| invalid(format!("archive is missing {path}")))
}

fn parse_repo_tag(tag: &str) -> io::Result<String> {
    let r = Reference::parse(tag).map_err(|e| invalid(e.to_string()))?;
    if tag.contains('@') || r.is_digest() {
        return Err(invalid(format!("invalid repo tag: {tag}")));
    }
    Ok(r.short())
}

fn load_docker(store: &Store, files: &HashMap<String, (String, u64)>, manifest: &[u8]) -> io::Result<Vec<Image>> {
    let entries: Vec<Value> = serde_json::from_slice(manifest).map_err(|e| invalid(format!("manifest.json: {e}")))?;
    let mut loaded = Vec::new();
    for m in &entries {
        let (config_digest, _) = lookup(files, m["Config"].as_str().unwrap_or_default())?;
        let config: Value = serde_json::from_slice(&store.read_config(&config_digest)?)
            .map_err(|e| invalid(format!("image config: {e}")))?;
        let mut layers = Vec::new();
        for l in m["Layers"].as_array().into_iter().flatten() {
            let (digest, size) = lookup(files, l.as_str().unwrap_or_default())?;
            let media_type = media_type_of(&store.blob_path(&digest)?)?;
            layers.push(Layer { digest, size, media_type: media_type.to_owned() });
        }
        let mut names = Vec::new();
        for t in m["RepoTags"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            names.push(parse_repo_tag(t)?);
        }
        // An untagged image is known by its id.
        let names = if names.is_empty() { vec![config_digest.clone()] } else { names };
        for name in names {
            loaded.push(from_config(name, &config_digest, &config, layers.clone()));
        }
    }
    for image in &loaded {
        store.put_image(image.clone())?;
    }
    Ok(loaded)
}

/// The digest and size of the blob a descriptor points to, checked against
/// the bytes in the archive: validates the digest via [`crate::store::digest_hex`]
/// and verifies the actual hash and declared size.
fn descriptor_blob(files: &HashMap<String, (String, u64)>, descriptor: &Value) -> io::Result<(String, u64)> {
    let digest = descriptor["digest"].as_str().ok_or_else(|| invalid("OCI descriptor has no digest"))?;
    let hex = crate::store::digest_hex(digest).map_err(|e| invalid(e.to_string()))?;
    if !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(invalid(format!("invalid sha256 digest {digest:?}")));
    }
    let (actual, size) = lookup(files, &format!("blobs/sha256/{hex}"))?;
    if actual != digest {
        return Err(invalid(format!("OCI blob {digest} is damaged: its bytes hash to {actual}")));
    }
    if let Some(v) = descriptor.get("size").filter(|v| !v.is_null())
        && v.as_u64() != Some(size)
    {
        return Err(invalid(format!("OCI blob {digest} is damaged: expected size {v}, got {size}")));
    }
    Ok((actual, size))
}

/// The os/architecture an OCI image config says it runs on.
fn config_platform(store: &Store, config_digest: &str) -> io::Result<(String, String)> {
    let config: Value = serde_json::from_slice(&store.read_config(config_digest)?).map_err(|e| invalid(format!("image config: {e}")))?;
    Ok((config["os"].as_str().unwrap_or("linux").to_owned(), config["architecture"].as_str().unwrap_or_default().to_owned()))
}

#[derive(Debug, Clone)]
struct Candidate {
    manifest: String,
    tag: Option<String>,
}

/// Whether `descriptor` is a non-image artifact or Buildx provenance attestation.
fn is_attestation(descriptor: &Value) -> bool {
    descriptor["annotations"]["vnd.docker.reference.type"].as_str() == Some("attestation-manifest")
        || descriptor["platform"]["os"].as_str() == Some("unknown")
        || descriptor["platform"]["architecture"].as_str() == Some("unknown")
        || descriptor["artifactType"].is_string()
}

/// Image reference from OCI annotations: `io.containerd.image.name` (the full
/// reference written by BuildKit/containerd, where `org.opencontainers.image.ref.name`
/// may carry only the tag) first, falling back to `org.opencontainers.image.ref.name`.
fn descriptor_tag(descriptor: &Value, parent_tag: Option<&str>) -> io::Result<Option<String>> {
    let ann = &descriptor["annotations"];
    if let Some(full) = ann["io.containerd.image.name"].as_str().filter(|s| !s.is_empty()) {
        return parse_repo_tag(full).map(Some);
    }
    if let Some(p) = parent_tag {
        return Ok(Some(p.to_owned()));
    }
    match ann["org.opencontainers.image.ref.name"].as_str().filter(|s| !s.is_empty()) {
        Some(tag) => parse_repo_tag(tag).map(Some),
        None => Ok(None),
    }
}

fn platform_matches(p: &Value, target: &Platform) -> bool {
    p["os"].as_str() == Some(target.os.as_str()) && p["architecture"].as_str() == Some(target.architecture.as_str())
}

fn resolve_index(
    store: &Store,
    files: &HashMap<String, (String, u64)>,
    descriptors: &[Value],
    platforms: &[Platform],
    parent_tag: Option<&str>,
    depth: usize,
    steps: &mut usize,
) -> io::Result<Vec<Candidate>> {
    if !platforms.is_empty() {
        let mut found = Vec::new();
        for child in descriptors {
            if is_attestation(child) {
                continue;
            }
            let p = &child["platform"];
            if (p["os"].as_str().is_some() || p["architecture"].as_str().is_some())
                && !platforms.iter().any(|want| platform_matches(p, want))
            {
                continue;
            }
            found.extend(oci_candidates(store, files, child, platforms, parent_tag, depth, steps)?);
        }
        return Ok(found);
    }
    // Group descriptors by their resolved image tag (preserving order) so that
    // multiple distinct images in one archive all load, while multiple
    // platforms for the same image (or untagged multi-arch) prefer the host.
    let mut groups: Vec<(Option<String>, Vec<&Value>)> = Vec::new();
    for child in descriptors {
        if is_attestation(child) {
            continue;
        }
        let tag = descriptor_tag(child, parent_tag)?;
        match groups.iter_mut().find(|(t, _)| *t == tag) {
            Some((_, list)) => list.push(child),
            None => groups.push((tag, vec![child])),
        }
    }
    let host = Platform::host_linux();
    let mut found = Vec::new();
    for (tag, group) in groups {
        let host_only: Vec<&Value> = group.iter().copied().filter(|d| platform_matches(&d["platform"], &host)).collect();
        let chosen = if host_only.is_empty() { group } else { host_only };
        for child in chosen {
            found.extend(oci_candidates(store, files, child, platforms, tag.as_deref(), depth, steps)?);
        }
    }
    Ok(found)
}

/// Walks an OCI index down to image manifests. A nested index is a
/// multi-platform image: take the host's entry (or those asked for), not
/// every architecture.
fn oci_candidates(
    store: &Store,
    files: &HashMap<String, (String, u64)>,
    descriptor: &Value,
    platforms: &[Platform],
    parent_tag: Option<&str>,
    depth: usize,
    steps: &mut usize,
) -> io::Result<Vec<Candidate>> {
    if depth > MAX_OCI_DEPTH {
        return Err(invalid("OCI index is nested too deeply"));
    }
    if *steps >= MAX_OCI_STEPS {
        return Err(invalid("OCI index has too many entries"));
    }
    *steps += 1;
    let tag = descriptor_tag(descriptor, parent_tag)?;
    let (digest, _) = descriptor_blob(files, descriptor)?;
    let doc: Value = serde_json::from_slice(&store.read_config(&digest)?).map_err(|e| invalid(format!("OCI blob: {e}")))?;
    if let Some(manifests) = doc["manifests"].as_array() {
        return resolve_index(store, files, manifests, platforms, tag.as_deref(), depth + 1, steps);
    }
    if doc["config"].is_object() && doc["layers"].is_array() {
        if !platforms.is_empty() {
            let config_digest = descriptor_blob(files, &doc["config"])?.0;
            let (os, arch) = config_platform(store, &config_digest)?;
            if !platforms.iter().any(|want| os == want.os && arch == want.architecture) {
                return Ok(Vec::new());
            }
        }
        return Ok(vec![Candidate { manifest: digest, tag }]);
    }
    Err(invalid(format!("OCI blob {digest} is neither an image manifest nor an index")))
}

fn load_oci(
    store: &Store,
    files: &HashMap<String, (String, u64)>,
    index: &[u8],
    oci_layout: Option<&[u8]>,
    platforms: &[Platform],
) -> io::Result<Vec<Image>> {
    if let Some(layout) = oci_layout {
        let v: Value = serde_json::from_slice(layout).map_err(|e| invalid(format!("oci-layout: {e}")))?;
        if v["imageLayoutVersion"].as_str() != Some("1.0.0") {
            return Err(invalid("unsupported oci-layout version"));
        }
    }
    let index: Value = serde_json::from_slice(index).map_err(|e| invalid(format!("index.json: {e}")))?;
    let descriptors = index["manifests"].as_array().ok_or_else(|| invalid("index.json has no manifests"))?;
    let mut steps = 0usize;
    let candidates = resolve_index(store, files, descriptors, platforms, None, 0, &mut steps)?;
    if candidates.is_empty() {
        if !platforms.is_empty() {
            let wanted = platforms.iter().map(Platform::to_string).collect::<Vec<_>>().join(", ");
            return Err(invalid(format!("requested platform ({wanted}) not found: image might be filtered out")));
        }
        return Err(invalid("OCI index contains no image manifests"));
    }
    let mut loaded = Vec::new();
    for candidate in candidates {
        let manifest: Value = serde_json::from_slice(&store.read_config(&candidate.manifest)?).map_err(|e| invalid(format!("OCI manifest: {e}")))?;
        let config_digest = descriptor_blob(files, &manifest["config"])?.0;
        let config: Value = serde_json::from_slice(&store.read_config(&config_digest)?).map_err(|e| invalid(format!("image config: {e}")))?;
        let mut layers = Vec::new();
        for l in manifest["layers"].as_array().into_iter().flatten() {
            let (digest, size) = descriptor_blob(files, l)?;
            let media_type = match l["mediaType"]
                .as_str()
                .filter(|m| m.starts_with("application/vnd.") && !m.bytes().any(|b| b.is_ascii_control() || b.is_ascii_whitespace()))
            {
                Some(m) => m.to_owned(),
                None => media_type_of(&store.blob_path(&digest)?)?.to_owned(),
            };
            layers.push(Layer { digest, size, media_type });
        }
        let name = candidate.tag.unwrap_or_else(|| config_digest.clone());
        loaded.push(from_config(name, &config_digest, &config, layers));
    }
    for image in &loaded {
        store.put_image(image.clone())?;
    }
    Ok(loaded)
}

/// Holds every blob `images` name ([`Store::pin`]) and checks each is
/// there, for a save or a push: an image removed while it is still being
/// sent (another client's `rmi` of it or of an image sharing its blobs, a
/// slow reader) must not lose a blob under it. Pinned first, then checked,
/// so a removal in between is seen. A caller that streams calls this before
/// it starts, so a missing blob is an error reply, not a cut archive.
pub fn hold(store: &Store, images: &[Image]) -> io::Result<Vec<crate::store::Pin>> {
    let mut pins = Vec::new();
    for i in images {
        for d in std::iter::once(&i.config_digest).chain(i.layers.iter().map(|l| &l.digest)) {
            pins.push(store.pin(d));
            if !store.blob_path(d)?.is_file() {
                return Err(io::Error::new(io::ErrorKind::NotFound, format!("not found: blob {d} of {}", i.name)));
            }
        }
    }
    Ok(pins)
}

/// Writes `images` as one archive `docker load` reads back.
pub fn save(store: &Store, images: &[Image], out: impl Write) -> io::Result<()> {
    let _held = hold(store, images)?;
    let mut tar = tar::Builder::new(out);
    let mut written: Vec<String> = Vec::new();
    let mut manifest = Vec::new();
    // Images that share a config are one entry with several tags.
    let mut by_config: Vec<(&Image, Vec<String>)> = Vec::new();
    for i in images {
        match by_config.iter_mut().find(|(first, _)| first.config_digest == i.config_digest) {
            Some((_, tags)) => tags.push(i.name.clone()),
            None => by_config.push((i, if i.name.starts_with("sha256:") { vec![] } else { vec![i.name.clone()] })),
        }
    }
    for (image, tags) in &by_config {
        let blob = |d: &str| format!("blobs/sha256/{}", d.strip_prefix("sha256:").unwrap_or(d));
        for d in std::iter::once(&image.config_digest).chain(image.layers.iter().map(|l| &l.digest)) {
            if written.contains(d) {
                continue;
            }
            let path = store.blob_path(d)?;
            let mut f = std::fs::File::open(&path)?;
            let mut h = tar::Header::new_ustar();
            h.set_size(f.metadata()?.len());
            h.set_mode(0o644);
            h.set_mtime(0);
            h.set_entry_type(tar::EntryType::Regular);
            tar.append_data(&mut h, blob(d), &mut f)?;
            written.push(d.clone());
        }
        manifest.push(json!({
            "Config": blob(&image.config_digest),
            "RepoTags": tags.iter().map(|t| tagged(t)).collect::<Vec<_>>(),
            "Layers": image.layers.iter().map(|l| blob(&l.digest)).collect::<Vec<_>>(),
        }));
    }
    let bytes = serde_json::to_vec(&manifest).map_err(io::Error::other)?;
    let mut h = tar::Header::new_ustar();
    h.set_size(bytes.len() as u64);
    h.set_mode(0o644);
    h.set_mtime(0);
    h.set_entry_type(tar::EntryType::Regular);
    tar.append_data(&mut h, "manifest.json", bytes.as_slice())?;
    tar.into_inner()?.flush()
}

/// `alpine` → `alpine:latest`, as RepoTags spell it.
fn tagged(name: &str) -> String {
    let last = name.rsplit('/').next().unwrap_or(name);
    if last.contains(':') || name.contains('@') { name.to_owned() } else { format!("{name}:latest") }
}

/// What kind of tar a layer file is, from its first bytes.
fn media_type_of(path: &std::path::Path) -> io::Result<&'static str> {
    let mut magic = [0u8; 4];
    let n = std::fs::File::open(path)?.read(&mut magic)?;
    Ok(match &magic[..n] {
        [0x1f, 0x8b, ..] => "application/vnd.oci.image.layer.v1.tar+gzip",
        [0x28, 0xb5, 0x2f, 0xfd] => "application/vnd.oci.image.layer.v1.tar+zstd",
        _ => "application/vnd.oci.image.layer.v1.tar",
    })
}

/// An image record from its config JSON.
pub fn from_config(name: String, config_digest: &str, config: &Value, layers: Vec<Layer>) -> Image {
    let c = &config["config"];
    let strings = |v: &Value| v.as_array().map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect()).unwrap_or_default();
    let text = |v: &Value| v.as_str().unwrap_or_default().to_owned();
    let os = config["os"].as_str().unwrap_or("linux");
    // A config that names no architecture was made for this machine.
    let host = crate::registry::Platform::host_linux();
    let arch = config["architecture"].as_str().unwrap_or(&host.architecture);
    Image { mirror: None,
        name,
        // Loaded images have no registry manifest; the config names them.
        digest: config_digest.to_owned(),
        index_digest: None,
        config_digest: config_digest.to_owned(),
        size: layers.iter().map(|l| l.size).sum(),
        layers,
        platform: format!("{os}/{arch}"),
        created: text(&config["created"]),
        pulled_at: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        config: RunConfig {
            env: strings(&c["Env"]),
            entrypoint: strings(&c["Entrypoint"]),
            cmd: strings(&c["Cmd"]),
            working_dir: text(&c["WorkingDir"]),
            user: text(&c["User"]),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> std::path::PathBuf {
        // Tests run in parallel: each gets its own directory.
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("kiri-archive-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// An image removed while its save is still streaming (a slow client,
    /// another client's `rmi`): the archive still comes out whole, its
    /// blobs held until the save ends.
    #[test]
    fn a_save_keeps_its_blobs_while_the_image_is_removed() {
        let dir = scratch();
        let store = Store::open(&dir).unwrap();
        let put = |bytes: &[u8]| {
            let mut w = store.ingest().unwrap();
            w.write_all(bytes).unwrap();
            w.finish().unwrap()
        };
        let config = json!({"os": "linux", "architecture": "amd64", "config": {}, "rootfs": {"type": "layers", "diff_ids": []}});
        let (cfg, _) = put(&serde_json::to_vec(&config).unwrap());
        let (a, sa) = put(&[1u8; 4096]);
        let (b, sb) = put(&[2u8; 4096]);
        let gz = "application/vnd.docker.image.rootfs.diff.tar.gzip";
        let image = from_config("solo:1".into(), &cfg, &config, vec![Layer { digest: a, size: sa, media_type: gz.into() }, Layer { digest: b, size: sb, media_type: gz.into() }]);
        store.put_image(image.clone()).unwrap();
        // A writer that lets the image go once the first bytes are out.
        struct Slow<'a> {
            out: Vec<u8>,
            store: &'a Store,
            removed: bool,
        }
        impl Write for Slow<'_> {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                if !self.removed {
                    self.removed = true;
                    self.store.remove_image("solo:1").unwrap();
                }
                self.out.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut w = Slow { out: Vec::new(), store: &store, removed: false };
        save(&store, &[image], &mut w).unwrap();
        let other = Store::open(dir.join("other")).unwrap();
        let loaded = load(&other, w.out.as_slice()).unwrap();
        assert_eq!(loaded[0].layers.len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Two archives sharing a layer, loaded and removed at once over and
    /// over: a removal of one never deletes a blob the other's load wrote
    /// or found, between the write and the image being recorded.
    #[test]
    fn loads_and_removals_of_images_sharing_a_layer_do_not_race() {
        let dir = scratch();
        let store = Store::open(&dir).unwrap();
        let archive = |name: &str, cmd: &str| {
            let src = Store::open(dir.join(format!("src-{name}"))).unwrap();
            let put = |bytes: &[u8]| {
                let mut w = src.ingest().unwrap();
                w.write_all(bytes).unwrap();
                w.finish().unwrap()
            };
            let config = json!({"os": "linux", "architecture": "amd64", "created": "2026-01-01T00:00:00Z", "config": {"Cmd": [cmd]}, "rootfs": {"type": "layers", "diff_ids": []}});
            let (cfg, _) = put(&serde_json::to_vec(&config).unwrap());
            let (layer, size) = put(&vec![7u8; 64 * 1024]);
            let image = from_config(name.into(), &cfg, &config, vec![Layer { digest: layer, size, media_type: "application/vnd.oci.image.layer.v1.tar".into() }]);
            src.put_image(image.clone()).unwrap();
            let mut tarball = Vec::new();
            save(&src, &[image], &mut tarball).unwrap();
            tarball
        };
        let (a, b) = (archive("a:1", "a"), archive("b:1", "b"));
        std::thread::scope(|s| {
            for (tarball, name) in [(&a, "a:1"), (&b, "b:1")] {
                let store = &store;
                s.spawn(move || {
                    for round in 0..300 {
                        let loaded = load(store, tarball.as_slice()).unwrap_or_else(|e| panic!("{name} round {round}: {e}"));
                        for l in &loaded[0].layers {
                            assert!(store.blob_path(&l.digest).unwrap().exists(), "{name} round {round}: its layer is gone");
                        }
                        store.remove_image(name).unwrap();
                    }
                });
            }
        });
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = scratch();
        let store = Store::open(&dir).unwrap();
        let put = |bytes: &[u8]| {
            let mut w = store.ingest().unwrap();
            w.write_all(bytes).unwrap();
            w.finish().unwrap()
        };
        let config = json!({"os": "linux", "architecture": "arm64", "created": "2026-01-01T00:00:00Z", "config": {"Cmd": ["echo", "hi"], "Env": ["A=1"]}});
        let (cfg, _) = put(&serde_json::to_vec(&config).unwrap());
        let (layer, size) = put(b"\x1f\x8bnot really gzip");
        let image = from_config("demo:1".into(), &cfg, &config, vec![Layer { digest: layer.clone(), size, media_type: media_type_of(&store.blob_path(&layer).unwrap()).unwrap().into() }]);
        store.put_image(image.clone()).unwrap();

        let mut tarball = Vec::new();
        save(&store, &[image.clone()], &mut tarball).unwrap();

        let other = Store::open(dir.join("other")).unwrap();
        let loaded = load(&other, tarball.as_slice()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "demo:1");
        assert_eq!(loaded[0].config.cmd, ["echo", "hi"]);
        assert_eq!(loaded[0].layers[0].digest, layer);
        assert!(loaded[0].layers[0].media_type.ends_with("gzip"));
        assert_eq!(other.find("demo:1").unwrap().unwrap().config_digest, cfg);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_archives_without_a_manifest() {
        let dir = scratch();
        let store = Store::open(&dir).unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_ustar();
        h.set_size(1);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, "x", &b"x"[..]).unwrap();
        let bytes = b.into_inner().unwrap();
        assert!(load(&store, bytes.as_slice()).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The classic docker-archive layout (podman save, older docker save):
    /// the config is a top-level `<hex>.json`, layers are `<hex>.tar`, with
    /// a `repositories` file and, in the legacy layout, per-layer json.
    #[test]
    fn loads_classic_archives_with_a_top_level_config_json() {
        let dir = scratch();
        let store = Store::open(&dir).unwrap();
        let add = |b: &mut tar::Builder<Vec<u8>>, name: &str, data: &[u8]| {
            let mut h = tar::Header::new_ustar();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            b.append_data(&mut h, name, data).unwrap();
        };
        let mut layer = tar::Builder::new(Vec::new());
        add(&mut layer, "etc/hello.txt", b"hello kiri\n");
        let layer = layer.into_inner().unwrap();
        let config = json!({"architecture": "arm64", "os": "linux", "created": "2026-11-09T00:00:00Z",
            "config": {"Env": ["PATH=/usr/bin"], "Cmd": ["/bin/true"]},
            "rootfs": {"type": "layers", "diff_ids": ["sha256:00"]}});
        let config = serde_json::to_vec(&config).unwrap();
        let manifest = json!([{"Config": "91df036f.json", "RepoTags": ["minirepro:flat"], "Layers": ["5e1a.tar"]}]);

        let mut b = tar::Builder::new(Vec::new());
        add(&mut b, "91df036f.json", &config); // before manifest.json, as tar sorts it
        add(&mut b, "5e1a.tar", &layer);
        add(&mut b, "5e1a/json", b"{\"id\":\"5e1a\"}");
        add(&mut b, "index.json", b"{\"schemaVersion\":2}");
        add(&mut b, "manifest.json", &serde_json::to_vec(&manifest).unwrap());
        add(&mut b, "repositories", b"{\"minirepro\":{\"flat\":\"5e1a\"}}");
        let bytes = b.into_inner().unwrap();

        let images = load(&store, bytes.as_slice()).unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].name, "minirepro:flat");
        assert_eq!(store.read_config(&images[0].config_digest).unwrap(), config);
        assert_eq!(images[0].layers.len(), 1);
        // Only the config and the layer stay in the store.
        let blobs = std::fs::read_dir(store.blob_path(&images[0].config_digest).unwrap().parent().unwrap()).unwrap().count();
        assert_eq!(blobs, 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn add_file(b: &mut tar::Builder<Vec<u8>>, name: &str, data: &[u8]) {
        let mut h = tar::Header::new_ustar();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, name, data).unwrap();
    }

    fn put(store: &Store, data: &[u8]) -> (String, u64) {
        let mut w = store.ingest().unwrap();
        w.write_all(data).unwrap();
        w.finish().unwrap()
    }

    fn add_blob(b: &mut tar::Builder<Vec<u8>>, store: &Store, digest: &str) {
        let hex = digest.strip_prefix("sha256:").unwrap();
        add_file(b, &format!("blobs/sha256/{hex}"), &std::fs::read(store.blob_path(digest).unwrap()).unwrap());
    }

    /// One image manifest and its config/layer blobs, in `b`. Returns the
    /// descriptor an OCI index would use to point at it.
    fn add_image_with_layer(b: &mut tar::Builder<Vec<u8>>, store: &Store, arch: &str, layer: &[u8], media_type: &str) -> Value {
        let config = serde_json::to_vec(&json!({
            "architecture": arch, "os": "linux", "created": "2026-01-01T00:00:00Z",
            "config": {"Cmd": ["echo", "hi"], "Env": ["A=1"]}, "rootfs": {"type": "layers", "diff_ids": []},
        }))
        .unwrap();
        let (config_digest, config_size) = put(store, &config);
        let (layer_digest, layer_size) = put(store, layer);
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config_digest, "size": config_size},
            "layers": [{"mediaType": media_type, "digest": layer_digest, "size": layer_size}],
        }))
        .unwrap();
        let (digest, size) = put(store, &manifest);
        for d in [&config_digest, &layer_digest, &digest] {
            add_blob(b, store, d);
        }
        json!({
            "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": digest, "size": size,
            "platform": {"os": "linux", "architecture": arch},
        })
    }

    fn add_image(b: &mut tar::Builder<Vec<u8>>, store: &Store, arch: &str) -> Value {
        let mut layer = tar::Builder::new(Vec::new());
        add_file(&mut layer, "etc/hi", b"hi");
        let layer = layer.into_inner().unwrap();
        add_image_with_layer(b, store, arch, &layer, "application/vnd.oci.image.layer.v1.tar")
    }

    fn add_index(b: &mut tar::Builder<Vec<u8>>, descriptors: Vec<Value>) {
        add_file(b, "oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#);
        add_file(b, "index.json", &serde_json::to_vec(&json!({"schemaVersion": 2, "manifests": descriptors})).unwrap());
    }

    #[test]
    fn loads_an_oci_layout_archive() {
        let dir = scratch();
        let store = Store::open(&dir).unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let mut d = add_image(&mut b, &store, "arm64");
        d["annotations"] = json!({"org.opencontainers.image.ref.name": "demo/oci:1"});
        add_index(&mut b, vec![d]);
        let bytes = b.into_inner().unwrap();

        let other = Store::open(dir.join("other")).unwrap();
        let images = load(&other, bytes.as_slice()).unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].name, "demo/oci:1");
        assert_eq!(images[0].platform, "linux/arm64");
        assert_eq!(images[0].config.cmd, ["echo", "hi"]);
        assert_eq!(images[0].config.env, ["A=1"]);
        assert_eq!(images[0].layers.len(), 1);
        assert!(images[0].layers[0].media_type.ends_with("tar"));
        assert_eq!(other.find("demo/oci:1").unwrap().unwrap().config_digest, images[0].config_digest);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn loads_oci_archive_with_containerd_image_name_over_tag_only_ref_name() {
        let dir = scratch();
        let store = Store::open(&dir).unwrap();
        let mut b = tar::Builder::new(Vec::new());
        // BuildKit/containerd writes full ref in io.containerd.image.name and only the tag in ref.name.
        let mut d = add_image(&mut b, &store, "amd64");
        d["annotations"] = json!({
            "io.containerd.image.name": "docker.io/kiri-test/oci:1",
            "org.opencontainers.image.ref.name": "1",
        });
        add_index(&mut b, vec![d]);
        let bytes = b.into_inner().unwrap();

        let other = Store::open(dir.join("other")).unwrap();
        let images = load(&other, bytes.as_slice()).unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].name, "kiri-test/oci:1");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn loads_an_untagged_oci_image_by_id() {
        let dir = scratch();
        let store = Store::open(&dir).unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let d = add_image(&mut b, &store, "arm64");
        let mut d_empty = add_image(&mut b, &store, "amd64");
        d_empty["annotations"] = json!({"org.opencontainers.image.ref.name": ""});
        // Two distinct untagged descriptors would prefer host; test a single untagged one alone.
        add_index(&mut b, vec![d]);
        let bytes = b.into_inner().unwrap();

        let other = Store::open(dir.join("other")).unwrap();
        let images = load(&other, bytes.as_slice()).unwrap();
        assert_eq!(images.len(), 1);
        assert!(images[0].name.starts_with("sha256:"));
        assert_eq!(images[0].name, images[0].config_digest);

        let mut b2 = tar::Builder::new(Vec::new());
        let mut d_empty2 = add_image(&mut b2, &store, "amd64");
        d_empty2["annotations"] = json!({"org.opencontainers.image.ref.name": ""});
        add_index(&mut b2, vec![d_empty2]);
        let other2 = Store::open(dir.join("other2")).unwrap();
        let images2 = load(&other2, b2.into_inner().unwrap().as_slice()).unwrap();
        assert_eq!(images2.len(), 1);
        assert!(images2[0].name.starts_with("sha256:"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn loads_oci_layers_with_gzip_zstd_and_uncompressed() {
        let dir = scratch();
        let store = Store::open(&dir).unwrap();
        let config = serde_json::to_vec(&json!({
            "architecture": "amd64", "os": "linux", "created": "2026-01-01T00:00:00Z",
            "config": {"Cmd": ["true"]}, "rootfs": {"type": "layers", "diff_ids": []},
        }))
        .unwrap();
        let (cfg, cfg_sz) = put(&store, &config);
        let (raw, raw_sz) = put(&store, b"plain tar bytes");
        let (gz, gz_sz) = put(&store, b"\x1f\x8bgzip bytes");
        let (zst, zst_sz) = put(&store, b"\x28\xb5\x2f\xfdzstd bytes");
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg, "size": cfg_sz},
            "layers": [
                {"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": raw, "size": raw_sz},
                {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": gz, "size": gz_sz},
                {"mediaType": "application/vnd.oci.image.layer.v1.tar+zstd", "digest": zst, "size": zst_sz},
            ],
        }))
        .unwrap();
        let (man, man_sz) = put(&store, &manifest);
        let mut b = tar::Builder::new(Vec::new());
        for d in [&cfg, &raw, &gz, &zst, &man] {
            add_blob(&mut b, &store, d);
        }
        add_index(&mut b, vec![json!({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": man, "size": man_sz,
            "annotations": {"org.opencontainers.image.ref.name": "demo/layers:1"},
        })]);

        let other = Store::open(dir.join("other")).unwrap();
        let loaded = load(&other, b.into_inner().unwrap().as_slice()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].layers[0].media_type, "application/vnd.oci.image.layer.v1.tar");
        assert_eq!(loaded[0].layers[1].media_type, "application/vnd.oci.image.layer.v1.tar+gzip");
        assert_eq!(loaded[0].layers[2].media_type, "application/vnd.oci.image.layer.v1.tar+zstd");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn picks_a_platform_from_a_nested_oci_index_and_skips_attestations() {
        let dir = scratch();
        let store = Store::open(&dir).unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let host = Platform::host_linux();
        let other_arch = if host.architecture == "amd64" { "arm64" } else { "amd64" };
        let host_d = add_image(&mut b, &store, &host.architecture);
        let other_d = add_image(&mut b, &store, other_arch);
        let att_d = json!({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": format!("sha256:{}", "9".repeat(64)),
            "size": 123,
            "platform": {"os": "unknown", "architecture": "unknown"},
            "annotations": {"vnd.docker.reference.type": "attestation-manifest"},
        });
        let nested = serde_json::to_vec(&json!({"schemaVersion": 2, "manifests": [host_d, other_d, att_d]})).unwrap();
        let (nested_digest, nested_size) = put(&store, &nested);
        add_blob(&mut b, &store, &nested_digest);
        add_index(&mut b, vec![json!({
            "mediaType": "application/vnd.oci.image.index.v1+json", "digest": nested_digest, "size": nested_size,
            "annotations": {
                "io.containerd.image.name": "docker.io/demo/multi:1",
                "org.opencontainers.image.ref.name": "1",
            },
        })]);
        let bytes = b.into_inner().unwrap();

        // With no platform, this machine's entry wins.
        let native = Store::open(dir.join("native")).unwrap();
        let images = load(&native, bytes.as_slice()).unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].name, "demo/multi:1");
        assert_eq!(images[0].platform, format!("linux/{}", host.architecture));

        // An explicit platform picks that entry instead.
        let foreign = Store::open(dir.join("foreign")).unwrap();
        let wanted = Platform { os: "linux".into(), architecture: other_arch.into() };
        let images = load_with_platform(&foreign, bytes.as_slice(), Some(&wanted)).unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].name, "demo/multi:1");
        assert_eq!(images[0].platform, format!("linux/{other_arch}"));

        // And a platform nobody carries is a clear error, not a silent load or attestation fallback.
        let missing = Store::open(dir.join("missing")).unwrap();
        let wanted = Platform { os: "linux".into(), architecture: "s390x".into() };
        let err = load_with_platform(&missing, bytes.as_slice(), Some(&wanted)).unwrap_err();
        assert!(err.to_string().contains("linux/s390x"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn picks_host_from_flat_oci_index_and_keeps_distinct_tags() {
        let dir = scratch();
        let store = Store::open(&dir).unwrap();
        let host = Platform::host_linux();
        let other_arch = if host.architecture == "amd64" { "arm64" } else { "amd64" };

        // Flat multi-arch index with same tag (and missing foreign blobs).
        let mut b = tar::Builder::new(Vec::new());
        let mut host_d = add_image(&mut b, &store, &host.architecture);
        host_d["annotations"] = json!({"org.opencontainers.image.ref.name": "demo/flat:1"});
        let other_d = json!({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": format!("sha256:{}", "7".repeat(64)),
            "size": 99,
            "platform": {"os": "linux", "architecture": other_arch},
            "annotations": {"org.opencontainers.image.ref.name": "demo/flat:1"},
        });
        add_index(&mut b, vec![other_d, host_d]);
        let native = Store::open(dir.join("native")).unwrap();
        let images = load(&native, b.into_inner().unwrap().as_slice()).unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].platform, format!("linux/{}", host.architecture));

        // Multiple distinct images in index.json all load.
        let mut b2 = tar::Builder::new(Vec::new());
        let mut a = add_image(&mut b2, &store, &host.architecture);
        a["annotations"] = json!({"org.opencontainers.image.ref.name": "demo/a:1"});
        let mut c = add_image(&mut b2, &store, other_arch);
        c["annotations"] = json!({"org.opencontainers.image.ref.name": "demo/b:1"});
        add_index(&mut b2, vec![a, c]);
        let multi = Store::open(dir.join("multi")).unwrap();
        let images = load(&multi, b2.into_inner().unwrap().as_slice()).unwrap();
        assert_eq!(images.len(), 2);
        assert_eq!(images[0].name, "demo/a:1");
        assert_eq!(images[1].name, "demo/b:1");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_a_damaged_or_traversal_oci_blob() {
        let dir = scratch();
        let store = Store::open(&dir).unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let mut d = add_image(&mut b, &store, "arm64");
        d["digest"] = json!(format!("sha256:{}", "0".repeat(64)));
        add_file(&mut b, &format!("blobs/sha256/{}", "0".repeat(64)), b"not that blob");
        add_index(&mut b, vec![d]);
        let bytes = b.into_inner().unwrap();

        let other = Store::open(dir.join("other")).unwrap();
        assert!(load(&other, bytes.as_slice()).unwrap_err().to_string().contains("damaged"));
        assert_eq!(std::fs::read_dir(dir.join("other/blobs/sha256")).unwrap().count(), 0);

        // Traversal and uppercase digests in index.json are rejected by digest_hex / lowercase check.
        for bad_digest in ["sha256:../../evil".to_owned(), format!("sha256:{}", "A".repeat(64))] {
            let mut b2 = tar::Builder::new(Vec::new());
            add_file(&mut b2, "evil", b"{}");
            add_index(&mut b2, vec![json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": bad_digest,
                "size": 2,
            })]);
            let other2 = Store::open(dir.join("other2")).unwrap();
            let err = load(&other2, b2.into_inner().unwrap().as_slice()).unwrap_err();
            assert!(err.to_string().contains("invalid sha256 digest"), "{err}");
            let _ = std::fs::remove_dir_all(dir.join("other2"));
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_cyclic_oci_index_without_overflow() {
        let dir = scratch();
        let store = Store::open(&dir).unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let leaf = add_image(&mut b, &store, "amd64");
        let mut prev = leaf;
        for _ in 0..10 {
            let idx = serde_json::to_vec(&json!({"schemaVersion": 2, "manifests": [prev]})).unwrap();
            let (d, sz) = put(&store, &idx);
            add_blob(&mut b, &store, &d);
            prev = json!({"mediaType": "application/vnd.oci.image.index.v1+json", "digest": d, "size": sz});
        }
        add_index(&mut b, vec![prev]);
        let other = Store::open(dir.join("other")).unwrap();
        let err = load(&other, b.into_inner().unwrap().as_slice()).unwrap_err();
        assert!(err.to_string().contains("nested too deeply"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn fast_path_skips_disk_write_for_existing_blobs() {
        let dir = scratch();
        let store = Store::open(&dir).unwrap();
        let mut layer_builder = tar::Builder::new(Vec::new());
        add_file(&mut layer_builder, "data.txt", b"fast path test content\n");
        let layer_bytes = layer_builder.into_inner().unwrap();
        let layer_digest = crate::store::sha256_digest(&layer_bytes);
        let layer_hex = layer_digest.strip_prefix("sha256:").unwrap();

        let config = json!({"architecture": "arm64", "os": "linux", "created": "2026-11-23T00:00:00Z",
            "config": {"Cmd": ["/bin/sh"]},
            "rootfs": {"type": "layers", "diff_ids": []}});
        let config_bytes = serde_json::to_vec(&config).unwrap();
        let config_digest = crate::store::sha256_digest(&config_bytes);
        let config_hex = config_digest.strip_prefix("sha256:").unwrap();

        let manifest = json!([{
            "Config": format!("blobs/sha256/{config_hex}"),
            "RepoTags": ["fastpath:v1"],
            "Layers": [format!("blobs/sha256/{layer_hex}")]
        }]);

        let mut archive = tar::Builder::new(Vec::new());
        add_file(&mut archive, &format!("blobs/sha256/{config_hex}"), &config_bytes);
        add_file(&mut archive, &format!("blobs/sha256/{layer_hex}"), &layer_bytes);
        add_file(&mut archive, "manifest.json", &serde_json::to_vec(&manifest).unwrap());
        let tar_data = archive.into_inner().unwrap();

        let first = load(&store, tar_data.as_slice()).unwrap();
        assert_eq!(first.len(), 1);
        let blob_path = store.blob_path(&layer_digest).unwrap();
        let mtime_before = std::fs::metadata(&blob_path).unwrap().modified().unwrap();

        // Second load hits the fast-path without rewriting the blob on disk.
        let second = load(&store, tar_data.as_slice()).unwrap();
        assert_eq!(second.len(), 1);
        let mtime_after = std::fs::metadata(&blob_path).unwrap().modified().unwrap();
        assert_eq!(mtime_before, mtime_after);

        // Also test fast-path on an OCI layout archive sharing the same layer.
        let oci_manifest = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config_digest, "size": config_bytes.len()},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layer_digest, "size": layer_bytes.len()}],
        }))
        .unwrap();
        let oci_manifest_digest = crate::store::sha256_digest(&oci_manifest);
        let oci_manifest_hex = oci_manifest_digest.strip_prefix("sha256:").unwrap();
        let mut oci_archive = tar::Builder::new(Vec::new());
        add_file(&mut oci_archive, &format!("blobs/sha256/{config_hex}"), &config_bytes);
        add_file(&mut oci_archive, &format!("blobs/sha256/{layer_hex}"), &layer_bytes);
        add_file(&mut oci_archive, &format!("blobs/sha256/{oci_manifest_hex}"), &oci_manifest);
        add_index(&mut oci_archive, vec![json!({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": oci_manifest_digest, "size": oci_manifest.len(),
            "annotations": {"org.opencontainers.image.ref.name": "fastpath-oci:v1"},
        })]);
        let third = load(&store, oci_archive.into_inner().unwrap().as_slice()).unwrap();
        assert_eq!(third.len(), 1);
        assert_eq!(std::fs::metadata(&blob_path).unwrap().modified().unwrap(), mtime_before);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn fast_path_rejects_tampered_tar_entry_matching_existing_blob_size() {
        let dir = scratch();
        let store = Store::open(&dir).unwrap();
        let real_layer = b"authentic layer bytes!!";
        let (layer_digest, layer_size) = put(&store, real_layer);
        let layer_hex = layer_digest.strip_prefix("sha256:").unwrap();
        let config = serde_json::to_vec(&json!({"architecture": "amd64", "os": "linux", "config": {}})).unwrap();
        let (cfg_digest, _cfg_size) = put(&store, &config);
        let cfg_hex = cfg_digest.strip_prefix("sha256:").unwrap();

        // Keep an image referencing the authentic layer in the store.
        let existing = from_config("legit:1".into(), &cfg_digest, &serde_json::from_slice(&config).unwrap(), vec![Layer {
            digest: layer_digest.clone(), size: layer_size, media_type: "application/vnd.oci.image.layer.v1.tar".into(),
        }]);
        store.put_image(existing).unwrap();

        // Adversarial archive claims path blobs/sha256/<H> with the same byte size
        // as the existing blob in the store, but different content.
        let tampered_layer = b"tampered! layer bytes!!";
        assert_eq!(tampered_layer.len() as u64, layer_size);
        let manifest = json!([{
            "Config": format!("blobs/sha256/{cfg_hex}"),
            "RepoTags": ["spoof:1"],
            "Layers": [format!("blobs/sha256/{layer_hex}")]
        }]);
        let mut archive = tar::Builder::new(Vec::new());
        add_file(&mut archive, &format!("blobs/sha256/{cfg_hex}"), &config);
        add_file(&mut archive, &format!("blobs/sha256/{layer_hex}"), tampered_layer);
        add_file(&mut archive, "manifest.json", &serde_json::to_vec(&manifest).unwrap());

        let err = load(&store, archive.into_inner().unwrap().as_slice()).unwrap_err();
        assert!(err.to_string().contains("damaged"), "{err}");
        assert!(store.find("spoof:1").unwrap().is_none());
        assert_eq!(std::fs::read(store.blob_path(&layer_digest).unwrap()).unwrap(), real_layer);

        // Same adversarial check against an OCI layout archive.
        let oci_manifest = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg_digest, "size": config.len()},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layer_digest, "size": layer_size}],
        }))
        .unwrap();
        let oci_digest = crate::store::sha256_digest(&oci_manifest);
        let oci_hex = oci_digest.strip_prefix("sha256:").unwrap();
        let mut oci_archive = tar::Builder::new(Vec::new());
        add_file(&mut oci_archive, &format!("blobs/sha256/{cfg_hex}"), &config);
        add_file(&mut oci_archive, &format!("blobs/sha256/{layer_hex}"), tampered_layer);
        add_file(&mut oci_archive, &format!("blobs/sha256/{oci_hex}"), &oci_manifest);
        add_index(&mut oci_archive, vec![json!({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": oci_digest, "size": oci_manifest.len(),
            "annotations": {"org.opencontainers.image.ref.name": "spoof-oci:1"},
        })]);
        let err = load(&store, oci_archive.into_inner().unwrap().as_slice()).unwrap_err();
        assert!(err.to_string().contains("damaged"), "{err}");
        assert!(store.find("spoof-oci:1").unwrap().is_none());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_invalid_oci_tags_and_cleans_up_new_blobs() {
        let dir = scratch();
        let store = Store::open(&dir).unwrap();
        // Pre-seed one blob in store; it must survive a refused load.
        let (kept_layer, kept_size) = put(&store, b"preexisting layer");
        let kept_hex = kept_layer.strip_prefix("sha256:").unwrap();
        let config = serde_json::to_vec(&json!({"architecture": "amd64", "os": "linux", "config": {}})).unwrap();
        let (cfg_digest, _cfg_size) = put(&store, &config);
        let cfg_hex = cfg_digest.strip_prefix("sha256:").unwrap();
        store.put_image(from_config("kept:1".into(), &cfg_digest, &serde_json::from_slice(&config).unwrap(), vec![Layer {
            digest: kept_layer.clone(), size: kept_size, media_type: "application/vnd.oci.image.layer.v1.tar".into(),
        }])).unwrap();

        let fresh_config = serde_json::to_vec(&json!({"architecture": "amd64", "os": "linux", "config": {"Cmd": ["/bin/bad"]}})).unwrap();
        let fresh_cfg_digest = crate::store::sha256_digest(&fresh_config);
        let fresh_cfg_hex = fresh_cfg_digest.strip_prefix("sha256:").unwrap();
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": fresh_cfg_digest, "size": fresh_config.len()},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": kept_layer, "size": kept_size}],
        }))
        .unwrap();
        let man_digest = crate::store::sha256_digest(&manifest);
        let man_hex = man_digest.strip_prefix("sha256:").unwrap();

        let mut b = tar::Builder::new(Vec::new());
        add_file(&mut b, &format!("blobs/sha256/{cfg_hex}"), &config);
        add_file(&mut b, &format!("blobs/sha256/{kept_hex}"), b"preexisting layer");
        add_file(&mut b, &format!("blobs/sha256/{fresh_cfg_hex}"), &fresh_config);
        add_file(&mut b, &format!("blobs/sha256/{man_hex}"), &manifest);
        add_index(&mut b, vec![json!({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": man_digest, "size": manifest.len(),
            "annotations": {"org.opencontainers.image.ref.name": format!("alpine@sha256:{}", "a".repeat(64))},
        })]);

        assert!(load(&store, b.into_inner().unwrap().as_slice()).is_err());
        assert!(store.has_blob(&kept_layer, kept_size));
        assert!(!store.has_blob(&fresh_cfg_digest, fresh_config.len() as u64));
        assert!(!store.has_blob(&man_digest, manifest.len() as u64));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tags_get_latest() {
        assert_eq!(tagged("alpine"), "alpine:latest");
        assert_eq!(tagged("localhost:5000/app"), "localhost:5000/app:latest");
        assert_eq!(tagged("app:1"), "app:1");
    }

    #[test]
    fn rejects_invalid_repo_tags_and_cleans_up_blobs() {
        let dir = scratch();
        let store = Store::open(&dir).unwrap();
        let config = br#"{"architecture":"amd64","os":"linux","config":{},"rootfs":{"type":"layers","diff_ids":[]}}"#;
        let digest_tag = format!("alpine@sha256:{}", "a".repeat(64));
        for bad_tag in ["evil\".com/x:1", digest_tag.as_str()] {
            let manifest = json!([{"Config": "cfg.json", "RepoTags": [bad_tag], "Layers": []}]);
            let mut b = tar::Builder::new(Vec::new());
            add_file(&mut b, "cfg.json", config);
            add_file(&mut b, "manifest.json", &serde_json::to_vec(&manifest).unwrap());
            let bytes = b.into_inner().unwrap();

            assert!(load(&store, bytes.as_slice()).is_err(), "{bad_tag}");
            assert!(store.images().unwrap().is_empty(), "{bad_tag}");
            assert_eq!(std::fs::read_dir(dir.join("blobs/sha256")).unwrap().count(), 0, "{bad_tag}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
