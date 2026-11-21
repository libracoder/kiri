//! The builder core's three plug-in points (`kiri_forge::ports`) on Kiri's
//! own engine: steps run as containers on the normal runtime, layers and
//! images live in the image store as it is, base images come from the store
//! or Kiri's own pull.
//!
//! A layer's id is its blob's digest in the store. For a layer made here the
//! blob is the uncompressed tar, so its id is its diff_id; for a pulled one
//! the id is the compressed blob's and the diff_id comes from an image's
//! config.
//!
//! On today's store: a step's layer is sent from the guest as a tar and
//! kept as a blob (the store's record of it, for push, save and a guest that
//! lost it), and the guest keeps the step's folder as the unpacked layer in
//! place, so the next step on it is not sent the tar back to unpack. What
//! is still paid per step is the tar's trip to the host; a layer whose tar
//! is made only when something needs it removes that too.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use kiri_forge::ports::{
    Content, CopyKind, CopyLayer, Digest, Error, FolderTime, ImageRecord, ImageSource, LayerBlob, LayerId, LayerStore, MountKind, NewLayer, Network,
    Platform, PreviousLayer, Removals, ResolvedImage, Sharing, StepOutcome, StepRequest, StepRunner, Stream, WritableFolder,
};
use kiri_forge::splice::{Bodies, Previous, Run, Spliced, Splicer};
use kiri_proto::layertar::{self, Entry, Kind};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use super::engine::{Engine, StepNetwork, StepSpec};

/// The media type of every layer made here: an uncompressed tar.
const TAR: &str = "application/vnd.oci.image.layer.v1.tar";

/// The agent's first stderr line for a step it could not start
/// (kiri-init `sys::STEP_START_FAILED`).
const STEP_START_FAILED: &str = "kiri: cannot start step: ";

/// How a step's writable folder is named between the runner and the store.
const STEP_PREFIX: &str = "kiri-step/";

#[derive(Debug, Clone)]
struct Known {
    diff_id: Digest,
    media_type: String,
    size: u64,
}

/// Kiri's engine as the builder core's runner, layer store and image source.
pub struct Ports {
    engine: Arc<Engine>,
    /// What is known of each layer by blob digest, from images' configs and
    /// from layers made here.
    known: Mutex<HashMap<String, Known>>,
    /// Each finished step's mount targets, for its layer (their stubs stay out).
    step_mounts: Mutex<HashMap<String, String>>,
    /// Every layer this build was given or made, kept from deletion until
    /// the build ends: a `docker rmi` meanwhile must not take a layer the
    /// build took from the step cache.
    pins: Mutex<Vec<kiri_image::store::Pin>>,
    /// The build's ssh agent session (`kiri build --ssh`), checked to be the
    /// caller's own when the build started.
    pub ssh_session: Option<String>,
    /// How many times this build decompressed a pulled layer whole.
    unpacked: std::sync::atomic::AtomicU64,
}

/// Takes every lock in `locks`, in their order, waiting while another
/// step holds one; `None`, with none held, once `cancel` is set.
fn hold_locks<'l>(locks: &'l [Arc<Mutex<()>>], cancel: &kiri_forge::ports::Cancel) -> Option<Vec<MutexGuard<'l, ()>>> {
    let mut held = Vec::with_capacity(locks.len());
    for l in locks {
        loop {
            match l.try_lock() {
                Ok(g) => break held.push(g),
                Err(std::sync::TryLockError::Poisoned(e)) => break held.push(e.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => {
                    if cancel.is_cancelled() {
                        return None;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            }
        }
    }
    Some(held)
}

/// Where the guest keeps cache mounts: its own disk, never a layer.
pub(super) const CACHE_ROOT: &str = "/var/lib/kiri/build-cache";

/// Cache folders in use now, by folder: `private` sharing gives a step
/// that finds one in use a folder of its own. The engine's, not a build's:
/// every build running at once counts here.
static CACHES_IN_USE: std::sync::LazyLock<Mutex<HashMap<String, usize>>> = std::sync::LazyLock::new(Mutex::default);

/// One lock per `locked` cache id, shared by every build.
static CACHE_LOCKS: std::sync::LazyLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> = std::sync::LazyLock::new(Mutex::default);

/// A secret is sent to the guest inside the step's start, which a frame
/// limits; BuildKit's own limit is 500 KiB.
const MAX_SECRET: usize = 256 << 10;

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Calls `f` with whether a step uses a cache folder (by name) now; no step
/// takes one meanwhile. For prune.
pub(super) fn cache_folders_in_use(f: &mut super::buildcache::Visitor<'_>) {
    let in_use = CACHES_IN_USE.lock().unwrap_or_else(|e| e.into_inner());
    f(&|name| in_use.contains_key(&format!("{CACHE_ROOT}/{name}")))
}

/// A cache folder held by a running step, given back when it ends.
struct CacheUse {
    folder: String,
}

impl Drop for CacheUse {
    fn drop(&mut self) {
        let mut in_use = CACHES_IN_USE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = in_use.get_mut(&self.folder) {
            *n -= 1;
            if *n == 0 {
                in_use.remove(&self.folder);
            }
        }
    }
}

impl std::fmt::Debug for Ports {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ports").finish_non_exhaustive()
    }
}

fn engine_error(e: super::engine::Error) -> Error {
    match e {
        super::engine::Error::NotFound(m) => Error::NotFound(m),
        super::engine::Error::Io(e) => Error::Io(e),
        super::engine::Error::Conflict(m) | super::engine::Error::BadRequest(m) | super::engine::Error::Unauthorized(m) => Error::Io(io::Error::other(m)),
    }
}

fn bad_digest(d: &str) -> Error {
    Error::Refused(format!("not a layer of this store: {d}"))
}

impl Ports {
    pub fn new(engine: Arc<Engine>) -> Ports {
        // The first native build turns on what only the builder needs in
        // the image store (its blob checks, the unpack on the way of pulled
        // layers); until then pulls, runs and saves are as before it.
        engine.store.use_native_checks();
        Ports {
            engine,
            pins: Mutex::new(Vec::new()),
            known: Mutex::new(HashMap::new()),
            step_mounts: Mutex::new(HashMap::new()),
            ssh_session: None,
            unpacked: Default::default(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Known>> {
        self.known.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Learns the diff_id of every layer of every image in the store.
    fn learn_images(&self) -> Result<(), Error> {
        let images = self.engine.store.images()?;
        let mut found = Vec::new();
        for image in &images {
            if image.layers.iter().all(|l| self.lock().contains_key(&l.digest)) {
                continue;
            }
            let Ok(bytes) = self.engine.store.read_config(&image.config_digest) else { continue };
            let Ok(cfg) = serde_json::from_slice::<Value>(&bytes) else { continue };
            let diff_ids = cfg["rootfs"]["diff_ids"].as_array().cloned().unwrap_or_default();
            if diff_ids.len() != image.layers.len() {
                continue;
            }
            for (l, d) in image.layers.iter().zip(diff_ids) {
                if let Some(d) = d.as_str().and_then(|d| Digest::parse(d).ok()) {
                    found.push((l.digest.clone(), Known { diff_id: d, media_type: l.media_type.clone(), size: l.size }));
                }
            }
        }
        let mut known = self.lock();
        for (k, v) in found {
            known.entry(k).or_insert(v);
        }
        Ok(())
    }

    fn info(&self, layer: &LayerId) -> Result<Known, Error> {
        if let Some(k) = self.lock().get(&layer.0) {
            return Ok(k.clone());
        }
        self.learn_images()?;
        if let Some(k) = self.lock().get(&layer.0) {
            return Ok(k.clone());
        }
        // An uncompressed blob is its own diff_id: a layer made here, kept
        // across a restart of the daemon.
        let d = Digest::parse(&layer.0).map_err(|_| bad_digest(&layer.0))?;
        let path = self.engine.store.blob_path(d.as_str())?;
        match std::fs::metadata(&path) {
            Ok(m) => {
                let k = Known { diff_id: d, media_type: TAR.into(), size: m.len() };
                self.lock().insert(layer.0.clone(), k.clone());
                Ok(k)
            }
            Err(_) => Err(Error::NotFound(format!("layer {}", layer.0))),
        }
    }

    /// Writes a new layer's tar through `write` into the store, and only
    /// then makes it known: the blob is synced and renamed by the store,
    /// then the blob folder is synced, so a layer that exists is on disk.
    /// The layer with this diff_id the store has, before it is held.
    fn find_unpinned(&self, diff_id: &Digest) -> Result<Option<LayerId>, Error> {
        let hit = |known: &HashMap<String, Known>| {
            known.iter().filter(|(_, k)| &k.diff_id == diff_id).find(|(d, k)| self.engine.store.has_blob(d, k.size)).map(|(d, _)| LayerId(d.clone()))
        };
        if let Some(l) = hit(&self.lock()) {
            return Ok(Some(l));
        }
        self.learn_images()?;
        if let Some(l) = hit(&self.lock()) {
            return Ok(Some(l));
        }
        let own = LayerId(diff_id.as_str().to_owned());
        // Known is not enough: the blob must still be whole.
        Ok(self.info(&own).ok().filter(|k| self.engine.store.has_blob(&own.0, k.size)).map(|_| own))
    }

    /// Keeps blob `digest` from deletion until this build ends.
    /// Puts a written blob in place, held from before it is there: the
    /// same blob of another image (an identical step's tar, a twin build's
    /// config) removed by its `rmi` at that moment cannot take it away
    /// before this build's image names it.
    fn finish(&self, ingest: kiri_image::store::Ingest) -> Result<(String, u64), Error> {
        let (digest, size, pin) = ingest.finish_pinned()?;
        self.pins.lock().unwrap_or_else(|e| e.into_inner()).push(pin);
        Ok((digest, size))
    }

    fn pin(&self, digest: &str) {
        let p = self.engine.store.pin(digest);
        self.pins.lock().unwrap_or_else(|e| e.into_inner()).push(p);
    }

    fn take(&self, write: impl FnOnce(&mut dyn Write) -> Result<(), Error>) -> Result<NewLayer, Error> {
        let mut ingest = self.engine.store.ingest()?;
        let t = kiri_forge::timing::span("tar+digest");
        write(&mut ingest)?;
        drop(t);
        let _t = kiri_forge::timing::span("blob-sync");
        let (digest, size) = self.finish(ingest)?;
        self.sync_blobs()?;
        let d = Digest::parse(&digest).map_err(|_| bad_digest(&digest))?;
        self.lock().insert(digest.clone(), Known { diff_id: d, media_type: TAR.into(), size });
        Ok(NewLayer::new(LayerId(digest)))
    }

    /// The guest folder a cache mount uses, counted as in use until the
    /// returned guard goes. `locked` adds its id's lock to `locks`;
    /// `private` takes the first folder of the id no step uses now, chosen
    /// and counted under one lock so two steps never pick the same one.
    fn cache_folder(&self, id: &str, sharing: Sharing, locks: &mut Vec<Arc<Mutex<()>>>) -> CacheUse {
        let key = hexs(&Sha256::digest(id.as_bytes()));
        if sharing == Sharing::Locked {
            let lock = CACHE_LOCKS.lock().unwrap_or_else(|e| e.into_inner()).entry(key.clone()).or_default().clone();
            if !locks.iter().any(|l| Arc::ptr_eq(l, &lock)) {
                locks.push(lock);
            }
        }
        let mut in_use = CACHES_IN_USE.lock().unwrap_or_else(|e| e.into_inner());
        let folder = match sharing {
            Sharing::Private => (0..)
                .map(|n| if n == 0 { format!("{CACHE_ROOT}/{key}") } else { format!("{CACHE_ROOT}/{key}.{n}") })
                .find(|f| !in_use.contains_key(f))
                .expect("an unused folder"),
            Sharing::Shared | Sharing::Locked => format!("{CACHE_ROOT}/{key}"),
        };
        *in_use.entry(folder.clone()).or_default() += 1;
        super::buildcache::mount_used(&folder);
        CacheUse { folder }
    }

    /// A COPY's xattrs beyond the capability (`user.*`) are not in its
    /// layer tar, as BuildKit's are not, but BuildKit's snapshot keeps them
    /// and a later step sees them: set on the guest's copy of the layer now.
    /// Failing costs only those xattrs (logged), never the layer.
    fn keep_xattrs(&self, copy: &CopyLayer, layer: &LayerId) {
        let lines: Vec<String> = copy
            .entries
            .iter()
            .filter(|e| !matches!(e.kind, CopyKind::Symlink { .. }))
            .flat_map(|e| e.xattrs.iter().filter(|(k, _)| k != "security.capability").map(move |(k, v)| format!("{}\t{k}\t{}", e.path, hexs(v))))
            .filter(|l| !l.contains('\n'))
            .collect();
        if lines.is_empty() {
            return;
        }
        if let Err(e) = self.engine.layer_xattrs(&layer.0, TAR, &lines) {
            crate::diag::warn!("a COPY's extended attributes were not kept for the next steps", layer = layer.0, error = format!("{e:?}"));
        }
    }

    /// A COPY's layer, its bodies taken from `previous` where it has the
    /// same ones and `runs` of unchanged entries copied from its tar.
    fn copy_layer(&self, copy: &CopyLayer, previous: Option<PreviousLayer>, runs: &[Run]) -> Result<(NewLayer, Option<Bodies>), Error> {
        // Only a layer made here is a plain tar whose bodies the record
        // points into; any other previous layer is not used.
        let base_id = previous.as_ref().map(|p| p.layer.0.clone());
        let prev = previous.and_then(|p| {
            let k = self.info(&p.layer).ok().filter(|k| k.media_type == TAR)?;
            // Its bytes are copied into the new layer, so it must be whole:
            // checked as every read of a blob is, and each body and run against its recorded
            // sha256 as it is copied.
            let f = File::open(self.engine.store.verified_blob_path(&p.layer.0).ok()?).ok()?;
            (f.metadata().ok()?.len() == k.size).then_some((f, p.bodies))
        });
        // Runs need the layer they come from; without it the layer is
        // written whole (the same bytes).
        let runs = if prev.is_some() { runs } else { &[] };
        let mut done = None;
        let layer = self.take(|out| {
            let previous = prev.as_ref().map(|(tar, bodies)| Previous { tar, bodies });
            done = Some(write_spliced(copy, out, previous, runs)?);
            Ok(())
        })?;
        let (bodies, stats) = done.unwrap_or_default();
        kiri_forge::timing::count("bodies-reused", stats.reused);
        kiri_forge::timing::count("bodies-read", stats.read);
        kiri_forge::timing::count("bodies-held", stats.held);
        if let Some((_, prev_bodies)) = &prev {
            self.send_delta(base_id.as_deref(), &layer.id, prev_bodies, &bodies, runs);
        }
        self.keep_xattrs(copy, &layer.id);
        Ok((layer, Some(bodies)))
    }

    fn sync_blobs(&self) -> io::Result<()> {
        File::open(self.engine.store.root().join("blobs/sha256"))?.sync_all()
    }

    /// The blob's uncompressed tar, checked against its diff_id as it goes.
    fn copy_out(&self, digest: &str, k: &Known, out: &mut dyn Write) -> Result<u64, Error> {
        let file = io::BufReader::with_capacity(256 * 1024, File::open(self.engine.store.blob_path(digest)?)?);
        if k.media_type != TAR {
            self.unpacked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let mut reader: Box<dyn Read> = if k.media_type.ends_with("gzip") {
            Box::new(flate2::read::MultiGzDecoder::new(file))
        } else if k.media_type.ends_with("zstd") {
            Box::new(kiri_image::compress::ZstdFrames::new(file))
        } else {
            Box::new(file)
        };
        let mut hashing = Hashing { out, hash: Sha256::new(), n: 0 };
        io::copy(&mut reader, &mut hashing)?;
        let got = Digest::from_hash(&hashing.hash.finalize());
        if got != k.diff_id {
            return Err(Error::Mismatch(format!("layer {digest} unpacks to {got}, not {}", k.diff_id)));
        }
        Ok(hashing.n)
    }
}

struct Hashing<'a> {
    out: &'a mut dyn Write,
    hash: Sha256,
    n: u64,
}

impl Write for Hashing<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.out.write(buf)?;
        self.hash.update(&buf[..n]);
        self.n += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

// ---- 1. Running a step ----

impl StepRunner for Ports {
    fn run(&self, step: StepRequest, output: &mut dyn FnMut(Stream, &[u8])) -> Result<StepOutcome, Error> {
        let mut mount_lines = Vec::with_capacity(step.mounts.len());
        let mut mount_layers = Vec::new();
        let mut targets = String::new();
        let mut locks: Vec<Arc<Mutex<()>>> = Vec::new();
        let mut uses: Vec<CacheUse> = Vec::new();
        // The step's agent tokens: gone when the run returns.
        let mut ssh_agents: Vec<super::buildssh::StepAgent> = Vec::new();
        // Context binds staged for this step; detached when it is over.
        #[cfg(target_os = "linux")]
        let mut staged: Vec<super::bindstage::Staged> = Vec::new();
        for m in &step.mounts {
            if !m.target.starts_with('/') || m.target.contains(['\t', '\n']) || m.target.split('/').any(|c| c == "..") {
                return Err(Error::Refused(format!("bad mount target {:?}", m.target)));
            }
            let ro = if m.read_only { ",ro" } else { "" };
            targets.push_str(&m.target);
            targets.push('\n');
            match &m.kind {
                MountKind::Tmpfs => mount_lines.push(format!("\t{}\ttmpfs,nosuid{}", m.target, if m.read_only { ",ro" } else { "" })),
                MountKind::TmpfsSized { bytes } => mount_lines.push(format!("\t{}\ttmpfs,nosuid,size={bytes}{}", m.target, if m.read_only { ",ro" } else { "" })),
                MountKind::HostBind { path, handle } => {
                    // Linux: the tree the caller check went through, not
                    // whatever the path names now (bindstage.rs).
                    #[cfg(target_os = "linux")]
                    let path = &match handle {
                        Some(h) => {
                            let s = super::bindstage::Staged::new(std::os::fd::AsFd::as_fd(&*h.0), &super::state_dir().map_err(Error::Io)?.join("build/binds")).map_err(Error::Io)?;
                            let p = s.path().to_path_buf();
                            staged.push(s);
                            p
                        }
                        None => path.clone(),
                    };
                    #[cfg(not(target_os = "linux"))]
                    let _ = handle;
                    let p = path.to_str().filter(|p| p.starts_with('/') && !p.contains(['\t', '\n'])).ok_or_else(|| Error::Refused(format!("bad bind source {}", path.display())))?;
                    let guest = super::api::guest_bind_source(p);
                    if cfg!(target_os = "macos") && guest == p {
                        return Err(Error::Unsupported(format!("a bind of {p}, which the VM cannot see (not under the shared folders)")));
                    }
                    mount_lines.push(format!("{guest}\t{}\t{}", m.target, if m.read_only { "ro" } else { "lower,rw" }));
                }
                MountKind::Bind { layers, path } => {
                    if path.contains(['\t', '\n']) {
                        return Err(Error::Refused(format!("bad bind path {path:?}")));
                    }
                    if layers.is_empty() {
                        // A stage with no files: an empty folder, as BuildKit's scratch.
                        if !path.trim_matches('/').is_empty() {
                            return Err(Error::NotFound(format!("{path} in a stage with no files")));
                        }
                        mount_lines.push(format!("\t{}\ttmpfs,nosuid{}", m.target, if m.read_only { ",ro" } else { "" }));
                        continue;
                    }
                    let mut hexes = Vec::with_capacity(layers.len());
                    for l in layers.iter().rev() {
                        let k = self.info(l)?;
                        mount_layers.push((l.0.clone(), k.media_type));
                        hexes.push(l.0.trim_start_matches("sha256:").to_owned());
                    }
                    mount_lines.push(format!("{path}\t{}\tlayers={},{}", m.target, hexes.join(":"), if m.read_only { "ro" } else { "rw" }));
                }
                MountKind::Cache { id } => {
                    let u = self.cache_folder(id, Sharing::Shared, &mut locks);
                    mount_lines.push(format!("{}\t{}\tmkdir=0:0:755{ro}", u.folder, m.target));
                    uses.push(u);
                }
                MountKind::CacheFolder { id, sharing, uid, gid, mode, seed, prune_first } => {
                    // from=: what a new cache folder starts as.
                    let mut seeded = String::new();
                    if let Some((from, path)) = seed.as_ref().filter(|(l, _)| !l.is_empty()) {
                        let mut hexes = Vec::with_capacity(from.len());
                        for l in from.iter().rev() {
                            mount_layers.push((l.0.clone(), self.info(l)?.media_type));
                            hexes.push(l.0.trim_start_matches("sha256:").to_owned());
                        }
                        seeded = format!(",seed={},seedpath={}", hexes.join(":"), hexs(path.as_bytes()));
                    }
                    let u = self.cache_folder(id, *sharing, &mut locks);
                    let prune = if *prune_first { ",prune" } else { "" };
                    mount_lines.push(format!("{}\t{}\tmkdir={uid}:{gid}:{:o}{seeded}{prune}{ro}", u.folder, m.target, mode & 0o7777));
                    uses.push(u);
                }
                MountKind::SshAgent { id, uid, gid, mode } => {
                    // A token for this step alone, live until the run
                    // returns: the guest makes the socket at the target and
                    // relays each connection to it with the token; the
                    // client hands over the agent connection (buildssh.rs).
                    // The engine never opens an agent by its path.
                    let session = self.ssh_session.as_deref().ok_or_else(|| Error::NotFound(format!("no SSH key {id:?} forwarded from the client")))?;
                    let agent = super::buildssh::step_agent(session, id).map_err(Error::NotFound)?;
                    mount_lines.push(format!("\t{}\tssh={},uid={uid},gid={gid},mode={:o}", m.target, agent.token, mode & 0o7777));
                    ssh_agents.push(agent);
                }
                MountKind::Secret { data, uid, gid, mode } => {
                    if data.0.len() > MAX_SECRET {
                        return Err(Error::Refused(format!("secret for {} is {} bytes; at most {MAX_SECRET} can be mounted", m.target, data.0.len())));
                    }
                    mount_lines.push(format!("\t{}\tsecret={},uid={uid},gid={gid},mode={:o}", m.target, hexs(&data.0), mode & 0o7777));
                }
            }
        }
        // Held for the whole step: `locked` caches one step at a time (the
        // folders in use, `uses`, are counted until the step ends).
        // Always in one order, so two steps that each lock two never wait on each other.
        locks.sort_by_key(|l| Arc::as_ptr(l) as usize);
        // The locks are the engine's: another build may hold one for long,
        // so a cancelled build stops waiting (its step ends as killed).
        let Some(_held) = hold_locks(&locks, &step.cancel) else {
            return Ok(StepOutcome { exit_code: 137, changes: None, failure: None });
        };
        let mut layers = Vec::with_capacity(step.root_layers.len());
        for l in step.root_layers.iter().rev() {
            layers.push((l.0.clone(), self.info(l)?.media_type));
        }
        let network = match step.network {
            Network::Default => StepNetwork::Bridge,
            Network::None => StepNetwork::None,
            Network::Host => StepNetwork::Host,
        };
        let id = format!("{}{}", super::engine::STEP_ID_PREFIX, super::engine::random_hex(16));
        let hostname = if step.hostname.is_empty() { "buildkitsandbox" } else { step.hostname.as_str() };
        let opts = super::hostopts::step_rlimit_lines(&step.ulimits).map_err(Error::Refused)?;
        let spec = StepSpec { id: &id, layers: &layers, argv: &step.argv, env: &step.env, cwd: &step.workdir, user: &step.user, hostname, network, mounts: &mount_lines, mount_layers: &mount_layers, opts: &opts, privileged: step.insecure };
        // A start that failed says so on its first stderr line (see
        // run_flags::STEP): that is the step's failure, not its output.
        let mut start_failure: Option<String> = None;
        let mut said_anything = false;
        let cancel = step.cancel.clone();
        let ran = self.engine.step_run(&spec, &|| cancel.is_cancelled(), &mut |s, data| {
            if !said_anything && s == kiri_proto::Stream::Stderr
                && let Some(why) = data.strip_prefix(STEP_START_FAILED.as_bytes())
            {
                start_failure = Some(String::from_utf8_lossy(why).trim_end().to_owned());
                said_anything = true;
                return;
            }
            said_anything = true;
            output(if s == kiri_proto::Stream::Stdout { Stream::Stdout } else { Stream::Stderr }, data)
        });
        match ran {
            Ok((0, _)) => Ok({
                self.step_mounts.lock().unwrap_or_else(|e| e.into_inner()).insert(id.clone(), targets);
                StepOutcome {
                exit_code: 0,
                changes: Some(WritableFolder { path: PathBuf::from(format!("{STEP_PREFIX}{id}")), removals: Removals::Overlay }),
                failure: None,
            }}),
            Ok((code, _)) => {
                self.engine.step_remove(&id);
                Ok(StepOutcome { exit_code: code, changes: None, failure: start_failure.filter(|_| code == 127) })
            }
            Err(e) => {
                self.engine.step_remove(&id);
                Err(engine_error(e))
            }
        }
    }

    /// With Rosetta shared into the VM (Apple silicon), amd64 programs run
    /// in a step as they do in `docker run --platform linux/amd64`: the
    /// kernel hands them to Rosetta (kiri-init's binfmt entry), as it does
    /// for the managed BuildKit's steps, which run with no QEMU here
    /// (builder.rs hide_amd64_qemu).
    fn platforms(&self) -> Vec<Platform> {
        if cfg!(all(target_os = "macos", target_arch = "aarch64")) && kiri_vmm::rosetta_installed() {
            return vec![Platform { os: "linux".into(), architecture: "amd64".into(), variant: String::new() }];
        }
        Vec::new()
    }
}

impl Ports {
    /// Makes the new COPY layer in the guest from the previous one it has
    /// unpacked and the entries that changed, so only those bytes cross
    /// (`copy_op::LAYER_DELTA`). Only while the VM runs: a guest that is
    /// off, or lost the base, gets the whole layer when a step or a
    /// container first needs it, as before.
    fn send_delta(&self, base: Option<&str>, new: &LayerId, prev: &Bodies, bodies: &Bodies, runs: &[Run]) {
        let (Some(base), true) = (base, self.engine.is_awake()) else { return };
        let d = if runs.is_empty() { kiri_forge::splice::delta(prev, bodies) } else { kiri_forge::splice::delta_runs(prev, bodies, runs) };
        let Some(d) = d else { return };
        let mut t = kiri_forge::timing::span("guest-delta");
        let sent = (|| -> Result<u64, Error> {
            let file = File::open(self.engine.store.blob_path(&new.0)?)?;
            let mut r = Ranges { file, ranges: d.ranges.iter().copied().collect(), end: layertar::END.len(), sent: 0 };
            self.engine.layer_delta(base, &new.0, &d.removed, &mut r).map_err(engine_error)?;
            Ok(r.sent)
        })();
        match sent {
            Ok(n) => t.items(n),
            Err(e) => crate::diag::info!("layer delta not sent", error = e.to_string()),
        }
    }
}

/// Byte ranges of a file, then the tar's end blocks: a layer's delta tar.
struct Ranges {
    file: File,
    ranges: std::collections::VecDeque<(u64, u64)>,
    end: usize,
    sent: u64,
}

impl Read for Ranges {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::unix::fs::FileExt as _;
        while let Some(&(a, b)) = self.ranges.front() {
            if a >= b {
                self.ranges.pop_front();
                continue;
            }
            let want = buf.len().min(usize::try_from(b - a).unwrap_or(usize::MAX));
            let n = self.file.read_at(&mut buf[..want], a)?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the layer is shorter than its record"));
            }
            self.ranges[0].0 += n as u64;
            self.sent += n as u64;
            return Ok(n);
        }
        let n = buf.len().min(self.end);
        buf[..n].fill(0);
        self.end -= n;
        self.sent += n as u64;
        Ok(n)
    }
}

/// The guest's `copy_op::STEP_LAYER` chunks: `len: u32 LE | bytes`, ended by
/// an empty one.
struct Chunks<R> {
    inner: R,
    left: u32,
    done: bool,
}

impl<R: Read> Read for Chunks<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.left == 0 {
            if self.done || buf.is_empty() {
                return Ok(0);
            }
            let mut len = [0u8; 4];
            self.inner.read_exact(&mut len)?;
            self.left = u32::from_le_bytes(len);
            self.done = self.left == 0;
        }
        let want = buf.len().min(self.left as usize);
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the layer ended inside a chunk"));
        }
        self.left -= n as u32;
        Ok(n)
    }
}

/// The guest's folder times after a step's tar (`copy_op::STEP_LAYER`):
/// `len: u32 LE | path | sec: i64 LE | nsec: u32 LE`. A path that is not
/// UTF-8 is left out (the views name paths as text): it keeps the tar's time.
fn folder_times(mut b: &[u8]) -> Result<Vec<FolderTime>, Error> {
    let bad = || Error::Io(io::Error::other("the guest's folder times do not read back"));
    let mut out = Vec::new();
    while !b.is_empty() {
        let len = u32::from_le_bytes(b.get(..4).ok_or_else(bad)?.try_into().map_err(|_| bad())?) as usize;
        let rec = b.get(4..4 + len + 12).ok_or_else(bad)?;
        let (path, t) = rec.split_at(len);
        let sec = i64::from_le_bytes(t[..8].try_into().map_err(|_| bad())?);
        let nsec = u32::from_le_bytes(t[8..12].try_into().map_err(|_| bad())?);
        if let Ok(path) = std::str::from_utf8(path) {
            out.push(FolderTime { path: path.to_owned(), mtime_ns: sec.saturating_mul(1_000_000_000).saturating_add(i64::from(nsec)) });
        }
        b = &b[4 + len + 12..];
    }
    Ok(out)
}

fn guest_answer(f: &mut File) -> Result<(), Error> {
    let frame = super::api::guest_frame(f)?;
    match kiri_proto::decode(&frame) {
        Ok(kiri_proto::Msg::CopyDone) => Ok(()),
        Ok(kiri_proto::Msg::Error(m)) => Err(match m.strip_prefix("refused: ") {
            Some(why) => Error::Refused(why.to_owned()),
            None => Error::Io(io::Error::other(m.to_owned())),
        }),
        other => Err(Error::Io(io::Error::other(format!("unexpected answer from the guest: {other:?}")))),
    }
}

// ---- 2. The layer store ----

impl LayerStore for Ports {
    fn find_layer(&self, diff_id: &Digest) -> Result<Option<LayerId>, Error> {
        let Some(l) = self.find_unpinned(diff_id)? else { return Ok(None) };
        // Held first, then looked at again: a removal between the two
        // makes it a miss, never a layer that goes under the build. The
        // second look checks the blob is still whole, not only there: the
        // store may just have found it damaged and removed it.
        self.pin(&l.0);
        Ok(self.info(&l).ok().filter(|k| self.engine.store.has_blob(&l.0, k.size)).map(|_| l))
    }

    fn diff_id(&self, layer: &LayerId) -> Result<Digest, Error> {
        Ok(self.info(layer)?.diff_id)
    }

    fn read_layer(&self, layer: &LayerId, out: &mut dyn Write) -> Result<u64, Error> {
        let k = self.info(layer)?;
        self.copy_out(&layer.0, &k, out)
    }

    fn take_step_layer(&self, folder: WritableFolder, lower: &[LayerId]) -> Result<NewLayer, Error> {
        let id = folder
            .path
            .to_str()
            .and_then(|p| p.strip_prefix(STEP_PREFIX))
            .ok_or_else(|| Error::Refused(format!("{} is not a step folder of this engine", folder.path.display())))?
            .to_owned();
        if folder.removals != Removals::Overlay {
            return Err(Error::Unsupported("a step folder that lists its removals".into()));
        }
        let layers: Vec<String> = lower.iter().rev().map(|l| l.0.clone()).collect();
        let result = (|| {
            let targets = self.step_mounts.lock().unwrap_or_else(|e| e.into_inner()).remove(&id).unwrap_or_default();
            let stream = self.engine.step_layer(&id, &layers, &targets).map_err(engine_error)?;
            let mut f = File::from(stream.fd.try_clone()?);
            guest_answer(&mut f)?;
            let mut ingest = self.engine.store.ingest()?;
            let _t = kiri_forge::timing::span("guest-layer");
            io::copy(&mut Chunks { inner: &mut f, left: 0, done: false }, &mut ingest)?;
            let mut times = Vec::new();
            io::Read::read_to_end(&mut Chunks { inner: &mut f, left: 0, done: false }, &mut times)?;
            // Only a layer the guest says it wrote whole is kept.
            guest_answer(&mut f)?;
            let folder_times = folder_times(&times)?;
            let (digest, size) = self.finish(ingest)?;
            self.sync_blobs()?;
            let d = Digest::parse(&digest).map_err(|_| bad_digest(&digest))?;
            self.lock().insert(digest.clone(), Known { diff_id: d, media_type: TAR.into(), size });
            drop(stream);
            // The guest keeps the folder as the layer, so the next step on it
            // is not sent the tar back to unpack. If that fails it only
            // costs the copy: the tar is in the store.
            if let Err(e) = self.engine.step_adopt(&id, &digest) {
                crate::diag::warn!("a build step's layer was not kept in place; it will be sent again", layer = digest, error = format!("{e:?}"));
            }
            Ok(NewLayer { id: LayerId(digest), folder_times })
        })();
        self.engine.step_remove(&id);
        result
    }

    fn take_copy_layer(&self, copy: CopyLayer) -> Result<NewLayer, Error> {
        Ok(self.take_copy_layer_from(copy, None)?.0)
    }

    fn take_copy_layer_from(&self, copy: CopyLayer, previous: Option<PreviousLayer>) -> Result<(NewLayer, Option<Bodies>), Error> {
        self.copy_layer(&copy, previous, &[])
    }

    fn take_copy_layer_patched(&self, copy: &CopyLayer, previous: PreviousLayer, runs: &[Run]) -> Result<(NewLayer, Option<Bodies>), Error> {
        self.copy_layer(copy, Some(previous), runs)
    }

    fn import_layer(&self, diff_id: &Digest, fill: &mut dyn FnMut(&mut dyn Write) -> Result<(), Error>) -> Result<LayerId, Error> {
        let had = self.engine.store.blob_path(diff_id.as_str()).is_ok_and(|p| p.exists());
        let new = self.take(|out| fill(out))?;
        if new.id.0 != diff_id.as_str() {
            if !had {
                // Named after what it held; nobody asked for that blob.
                self.lock().remove(&new.id.0);
                let _ = std::fs::remove_file(self.engine.store.blob_path(&new.id.0)?);
            }
            return Err(Error::Mismatch(format!("layer {diff_id} came as {}", new.id.0)));
        }
        Ok(new.id)
    }

    /// A layer made here (or any uncompressed blob) is kept as its tar. A
    /// pulled, compressed one is unpacked once into the store's cache of
    /// layer tars and read there from then on, by every view of every
    /// build: a stage on a large base reads a view for each WORKDIR, COPY
    /// and `COPY --from`, and decompressing the base for each cost seconds
    /// per build (5.5 s for each view of a 1.4 GB base).
    fn layer_file(&self, layer: &LayerId) -> Option<PathBuf> {
        let k = self.info(layer).ok()?;
        if k.media_type == TAR {
            // Checked as every read of a blob is: one changed since it was
            // verified is hashed again, a damaged one is not given.
            return Digest::parse(&layer.0).is_ok_and(|d| d == k.diff_id).then(|| self.engine.store.verified_blob_path(&layer.0).ok()).flatten();
        }
        let made = self.engine.store.layer_tar(&layer.0, k.diff_id.as_str(), &mut |w| {
            self.copy_out(&layer.0, &k, w).map(|_| ()).map_err(|e| match e {
                Error::Io(e) => e,
                e => io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
            })
        });
        match made {
            Ok((path, pin)) => {
                self.pins.lock().unwrap_or_else(|e| e.into_inner()).push(pin);
                Some(path)
            }
            Err(e) => {
                // The view reads the blob itself then, as before.
                crate::diag::warn!("a pulled layer was not kept unpacked", layer = layer.0, error = format!("{e}"));
                None
            }
        }
    }

    fn record_image(&self, image: ImageRecord) -> Result<Digest, Error> {
        let cfg: Value = serde_json::from_slice(&image.config).map_err(|e| Error::Refused(format!("image config: {e}")))?;
        let diff_ids: Vec<&str> = cfg["rootfs"]["diff_ids"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        if diff_ids.len() != image.layers.len() {
            return Err(Error::Mismatch(format!("the config names {} layers, the image has {}", diff_ids.len(), image.layers.len())));
        }
        let mut layers = Vec::with_capacity(image.layers.len());
        for (l, want) in image.layers.iter().zip(&diff_ids) {
            let k = self.info(l)?;
            if k.diff_id.as_str() != *want {
                return Err(Error::Mismatch(format!("layer {} is {}, the config says {want}", l.0, k.diff_id)));
            }
            if !self.engine.store.has_blob(&l.0, k.size) {
                return Err(Error::NotFound(format!("layer {}", l.0)));
            }
            layers.push(kiri_image::Layer { digest: l.0.clone(), size: k.size, media_type: k.media_type });
        }
        let mut ingest = self.engine.store.ingest()?;
        ingest.write_all(&image.config)?;
        // The config too, until the image naming it is recorded.
        let (config_digest, _) = self.finish(ingest)?;
        self.sync_blobs()?;
        let names: Vec<String> = if image.names.is_empty() {
            vec![config_digest.clone()]
        } else {
            image
                .names
                .iter()
                .map(|n| kiri_image::Reference::parse(n).map(|r| r.short()).map_err(|e| Error::Refused(format!("invalid reference format: {e}"))))
                .collect::<Result<_, _>>()?
        };
        for name in names {
            self.engine.store.put_image(kiri_image::archive::from_config(name.clone(), &config_digest, &cfg, layers.clone()))?;
            self.engine.emit_image("tag", &config_digest, &name);
        }
        Digest::parse(&config_digest).map_err(|_| bad_digest(&config_digest))
    }
}

/// A COPY's files as one layer tar, in the order given. Context files are
/// hashed in the same read that copies them, and the layer is refused if
/// the bytes are not the ones the cache key was made from.
#[cfg(test)]
fn write_copy_layer(copy: &CopyLayer, out: &mut dyn Write) -> Result<(), Error> {
    write_spliced(copy, out, None, &[]).map(|_| ())
}

/// [`write_copy_layer`] with bodies taken from the previous layer of the
/// same COPY where it has them; where the new tar's bodies sit.
fn write_spliced(copy: &CopyLayer, out: &mut dyn Write, previous: Option<Previous<'_>>, runs: &[Run]) -> Result<(Bodies, Spliced), Error> {
    let mut s = Splicer::new(out, previous);
    let mut head = Vec::with_capacity(3 * layertar::BLOCK);
    kiri_forge::splice::write_entries(&mut s, &copy.entries, runs, &mut |out, e| {
        let base = e.path.rsplit('/').next().unwrap_or_default();
        if base.starts_with(".wh.") {
            return Err(Error::Refused(format!("/{}: names starting .wh. cannot be kept in a layer", e.path)));
        }
        if e.path.is_empty() || e.path.starts_with('/') || e.path.ends_with('/') || e.path.split('/').any(|c| c.is_empty() || c == "." || c == "..") {
            return Err(Error::Refused(format!("bad path in a copy: {:?}", e.path)));
        }
        let (kind, link, size, name) = match &e.kind {
            CopyKind::Dir => (Kind::Dir, &b""[..], 0, format!("{}/", e.path)),
            CopyKind::File(Content::Inline(bytes)) => (Kind::File, &b""[..], bytes.len() as u64, e.path.clone()),
            // A body the previous layer holds is taken from there and
            // checked by its sha256: the file is not looked at.
            CopyKind::File(Content::Context { sha256, .. }) if out.known_size(sha256).is_some() => {
                (Kind::File, &b""[..], out.known_size(sha256).unwrap_or(0), e.path.clone())
            }
            CopyKind::File(Content::Context { path, .. }) => {
                let m = std::fs::symlink_metadata(path)?;
                if !m.is_file() {
                    return Err(Error::Mismatch(format!("{} is no longer a file", path.display())));
                }
                (Kind::File, &b""[..], m.len(), e.path.clone())
            }
            CopyKind::Symlink { target } => (Kind::Symlink, target.as_bytes(), 0, e.path.clone()),
            CopyKind::Hardlink { target } => (Kind::HardLink, target.as_bytes(), 0, e.path.clone()),
            CopyKind::Device { block, .. } => (if *block { Kind::Block } else { Kind::Char }, &b""[..], 0, e.path.clone()),
            CopyKind::Fifo => (Kind::Fifo, &b""[..], 0, e.path.clone()),
        };
        let (devmajor, devminor) = match e.kind {
            CopyKind::Device { major, minor, .. } => (major, minor),
            _ => (0, 0),
        };
        head.clear();
        // Of the source's xattrs only the capability reaches a layer.
        let records: Vec<(&str, &[u8])> =
            e.xattrs.iter().filter(|(k, v)| k == "security.capability" && !v.is_empty()).map(|(_, v)| ("SCHILY.xattr.security.capability", &v[..])).collect();
        let entry = Entry {
            name: name.as_bytes(),
            kind,
            link,
            mode: e.mode & 0o7777,
            uid: u64::from(e.uid),
            gid: u64::from(e.gid),
            size,
            mtime: e.mtime,
            devmajor,
            devminor,
            records: &records,
        };
        layertar::header(&mut head, &entry);
        out.header(name.as_bytes(), &head)?;
        match &e.kind {
            CopyKind::File(Content::Inline(bytes)) => out.inline_body(bytes)?,
            // Read once, checked to be the file stat'd here and the bytes
            // the key was made of; or checked bytes of the previous layer.
            CopyKind::File(Content::Context { path, sha256 }) => out.context_body(path, sha256, size)?,
            _ => {}
        }
        out.raw(&[0u8; layertar::BLOCK][..layertar::padding(size)])?;
        Ok(())
    })?;
    s.end(&layertar::END)?;
    Ok(s.finish()?)
}

// ---- 3. The source of base images ----

impl Ports {
    fn resolved(&self, reference: &str, image: &kiri_image::Image) -> Result<ResolvedImage, Error> {
        let parse = |d: &str| Digest::parse(d).map_err(|_| bad_digest(d));
        let cfg: Value = serde_json::from_slice(&self.engine.store.read_config(&image.config_digest)?).map_err(|e| Error::Io(io::Error::other(e)))?;
        let diff_ids = cfg["rootfs"]["diff_ids"].as_array().cloned().unwrap_or_default();
        if diff_ids.len() != image.layers.len() {
            return Err(Error::Mismatch(format!("{reference}: the config names {} layers, the manifest {}", diff_ids.len(), image.layers.len())));
        }
        let mut layers = Vec::with_capacity(image.layers.len());
        for (l, d) in image.layers.iter().zip(diff_ids) {
            let diff_id = parse(d.as_str().unwrap_or_default())?;
            self.lock().entry(l.digest.clone()).or_insert(Known { diff_id: diff_id.clone(), media_type: l.media_type.clone(), size: l.size });
            layers.push(LayerBlob { digest: parse(&l.digest)?, media_type: l.media_type.clone(), size: l.size, diff_id });
        }
        Ok(ResolvedImage {
            reference: reference.to_owned(),
            root_digest: parse(image.index_digest.as_deref().unwrap_or(&image.digest))?,
            manifest_digest: parse(&image.digest)?,
            config_digest: parse(&image.config_digest)?,
            layers,
        })
    }
}

impl Ports {
    /// The store's image `name` for one of `platforms`, its config and
    /// layers held for the rest of the build ([`Ports::pin`]): another
    /// build or `docker rmi` may remove or replace the name meanwhile
    /// (a base image rebuilt while a child builds on it). Held first, then
    /// looked up again: an image still recorded after its blobs are held
    /// keeps them, since a removal takes it out of the index before it
    /// deletes anything. None when the store has no such image.
    fn resolve_local(&self, reference: &str, name: &str, platforms: &[&str]) -> Result<Option<ResolvedImage>, Error> {
        let find = || -> Result<Option<kiri_image::Image>, Error> { Ok(self.engine.store.find(name)?.filter(|i| platforms.contains(&i.platform.as_str()))) };
        let mut image = find()?;
        while let Some(i) = image {
            self.pin(&i.config_digest);
            for l in &i.layers {
                self.pin(&l.digest);
            }
            match find()? {
                Some(again) if again.config_digest == i.config_digest && again.layers == i.layers => return self.resolved(reference, &again).map(Some),
                other => image = other,
            }
        }
        Ok(None)
    }
}

impl ImageSource for Ports {
    fn resolve(&self, reference: &str, platform: &Platform) -> Result<ResolvedImage, Error> {
        let r = kiri_image::Reference::parse(reference).map_err(|e| Error::Refused(format!("invalid reference format: {e}")))?;
        let want = if platform.variant.is_empty() { format!("{}/{}", platform.os, platform.architecture) } else { format!("{}/{}/{}", platform.os, platform.architecture, platform.variant) };
        let plain = format!("{}/{}", platform.os, platform.architecture);
        // An image already in the store is used as it is: no second pull.
        if let Some(image) = self.resolve_local(reference, &r.short(), &[&want, &plain])? {
            return Ok(image);
        }
        let wanted = kiri_image::Platform { os: platform.os.clone(), architecture: platform.architecture.clone() };
        // The build needs the VM anyway: up now, the layers unpack in it as
        // they arrive rather than at the first step.
        let _ = self.engine.vm();
        let tee = self.engine.layer_tee();
        let image = kiri_image::Client::new()
            .pull_tee(&self.engine.store, &r, &wanted, &|_| {}, &kiri_image::Cancel::new(), tee.as_ref().map(|t| t as &dyn kiri_image::registry::LayerTee))
            .map_err(|e| match e {
                kiri_image::registry::Error::NotFound(m) => Error::NotFound(m),
                e => Error::Io(io::Error::other(e.to_string())),
            })?;
        self.engine.emit_image("pull", &image.config_digest, &image.name);
        // Held as a local image is, from here to the end of the build.
        match self.resolve_local(reference, &image.name, &[&image.platform])? {
            Some(resolved) => Ok(resolved),
            None => self.resolved(reference, &image),
        }
    }

    fn fetch_config(&self, image: &ResolvedImage) -> Result<Vec<u8>, Error> {
        let bytes = self.engine.store.read_config(image.config_digest.as_str())?;
        if Digest::of(&bytes) != image.config_digest {
            return Err(Error::Mismatch(format!("config {}", image.config_digest)));
        }
        Ok(bytes)
    }

    fn fetch_layer(&self, _image: &ResolvedImage, layer: &LayerBlob, out: &mut dyn Write) -> Result<(), Error> {
        let k = Known { diff_id: layer.diff_id.clone(), media_type: layer.media_type.clone(), size: layer.size };
        if !self.engine.store.has_blob(layer.digest.as_str(), layer.size) {
            return Err(Error::NotFound(format!("layer {}", layer.digest)));
        }
        self.copy_out(layer.digest.as_str(), &k, out).map(drop)
    }
}

/// `POST /kiri/build/steps`, only in a build with the `build-test-routes`
/// feature and an engine started with `KIRI_BUILD_PORTS_TEST=1`: drives the
/// plug-in points the way the builder core will, so they can be checked on
/// a real engine before the build driver exists. Body: `{"from": ref,
/// "steps": [{"argv": [...], "env": [...], "user": "", "workdir": "/",
/// "network": "default"|"none"|"host"}], "tag": name}`. Each step runs on
/// the layers so far and its folder becomes the next layer; the image is
/// the base config with the new diff_ids.
#[cfg(feature = "build-test-routes")]
pub(super) fn try_steps(body: &[u8], engine: &Arc<Engine>) -> Result<Value, super::engine::Error> {
    use serde_json::json;
    let bad = |m: String| super::engine::Error::BadRequest(m);
    let fail = |e: Error| super::engine::Error::Io(io::Error::other(e.to_string()));
    if std::env::var("KIRI_BUILD_PORTS_TEST").as_deref() != Ok("1") {
        return Err(super::engine::Error::NotFound("page not found".into()));
    }
    let v: Value = serde_json::from_slice(body).map_err(|e| bad(e.to_string()))?;
    let strings = |v: &Value| -> Vec<String> { v.as_array().map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect()).unwrap_or_default() };
    let ports = Ports::new(engine.clone());
    let host = kiri_image::Platform::host_linux();
    let platform = Platform { os: host.os.clone(), architecture: host.architecture.clone(), variant: String::new() };
    let base = ports.resolve(v["from"].as_str().unwrap_or_default(), &platform).map_err(fail)?;
    let mut cfg: Value = serde_json::from_slice(&ports.fetch_config(&base).map_err(fail)?).map_err(|e| bad(e.to_string()))?;
    let mut layers = Vec::new();
    for l in &base.layers {
        layers.push(ports.find_layer(&l.diff_id).map_err(fail)?.ok_or_else(|| super::engine::Error::NotFound(format!("base layer {}", l.diff_id)))?);
    }
    let base_layers = layers.clone();
    let mut report = Vec::new();
    for s in v["steps"].as_array().cloned().unwrap_or_default() {
        let network = match s["network"].as_str().unwrap_or("default") {
            "none" => Network::None,
            "host" => Network::Host,
            _ => Network::Default,
        };
        // `{"target", "type": tmpfs|cache|host|layers|secret, "id", "sharing",
        // "path", "data", "rw", "uid", "gid", "mode"}`; `layers` binds a path
        // of the base image's layers.
        let mut mounts = Vec::new();
        for m in s["mounts"].as_array().into_iter().flatten() {
            let text = |k: &str| m[k].as_str().unwrap_or_default().to_owned();
            let num = |k: &str, d: u64| m[k].as_u64().unwrap_or(d) as u32;
            let kind = match m["type"].as_str().unwrap_or_default() {
                "tmpfs" => kiri_forge::ports::MountKind::Tmpfs,
                "host" => kiri_forge::ports::MountKind::HostBind { path: PathBuf::from(text("path")), handle: None },
                "layers" => kiri_forge::ports::MountKind::Bind { layers: base_layers.clone(), path: text("path") },
                // An agent comes from a client's session only, never a path.
                "ssh" => return Err(super::engine::Error::BadRequest("an ssh mount needs a build's ssh session".into())),
                "secret" => kiri_forge::ports::MountKind::Secret { data: kiri_forge::ports::SecretBytes(text("data").into_bytes()), uid: num("uid", 0), gid: num("gid", 0), mode: num("mode", 0o400) },
                _ => kiri_forge::ports::MountKind::CacheFolder {
                    id: text("id"),
                    sharing: match m["sharing"].as_str() {
                        Some("locked") => Sharing::Locked,
                        Some("private") => Sharing::Private,
                        _ => Sharing::Shared,
                    },
                    uid: num("uid", 0),
                    gid: num("gid", 0),
                    mode: num("mode", 0o755),
                    seed: m["seed"].as_str().map(|p| (base_layers.clone(), p.to_owned())),
                    prune_first: m["prune"].as_bool() == Some(true),
                },
            };
            mounts.push(kiri_forge::ports::Mount { target: text("target"), kind, read_only: m["rw"].as_bool() != Some(true) && m["type"] != "cache" && m["type"] != "tmpfs" });
        }
        let step = StepRequest {
            root_layers: layers.clone(),
            argv: strings(&s["argv"]),
            env: strings(&s["env"]),
            user: s["user"].as_str().unwrap_or_default().to_owned(),
            workdir: s["workdir"].as_str().unwrap_or("/").to_owned(),
            network,
            mounts,
            hostname: String::new(),
            ulimits: vec![],
            cancel: Default::default(),
            insecure: false,
        };
        let mut out = Vec::new();
        let started = std::time::Instant::now();
        let outcome = ports.run(step, &mut |_, d| out.extend_from_slice(d)).map_err(fail)?;
        let run_ms = started.elapsed().as_secs_f64() * 1e3;
        let mut line = json!({"exit": outcome.exit_code, "output": String::from_utf8_lossy(&out), "run_ms": run_ms});
        let Some(folder) = outcome.changes else {
            report.push(line);
            return Ok(json!({"steps": report}));
        };
        let started = std::time::Instant::now();
        let new = ports.take_step_layer(folder, &layers).map_err(fail)?;
        line["commit_ms"] = json!(started.elapsed().as_secs_f64() * 1e3);
        let diff_id = ports.diff_id(&new.id).map_err(fail)?;
        line["layer"] = json!({"id": new.id.0, "diff_id": diff_id.as_str()});
        cfg["rootfs"]["diff_ids"].as_array_mut().ok_or_else(|| bad("base config has no diff_ids".into()))?.push(json!(diff_id.as_str()));
        layers.push(new.id);
        report.push(line);
    }
    let names = v["tag"].as_str().map(|t| vec![t.to_owned()]).unwrap_or_default();
    let config = serde_json::to_vec(&cfg).map_err(|e| bad(e.to_string()))?;
    let id = ports.record_image(ImageRecord { config, layers, names }).map_err(fail)?;
    Ok(json!({"steps": report, "image": id.as_str()}))
}

/// `POST /kiri/build/golden`, only in a build with the `build-test-routes`
/// feature and an engine started with `KIRI_BUILD_PORTS_TEST=1`: builds
/// a Dockerfile with the builder core on these plug-in points, every step
/// run (no cache), and answers what the golden RUN vectors record: each
/// step's output and error by its progress name, the build's error, and
/// the tar of every image layer after the first `skip`. Body:
/// `{"dockerfile": text, "context": absolute path, "build_args": {..},
/// "target": name, "skip": n}`.
#[cfg(feature = "build-test-routes")]
pub(super) fn golden_build(body: &[u8], engine: &Arc<Engine>, caller: Option<kiri_forge::context::Caller>) -> Result<Value, super::engine::Error> {
    use kiri_forge::build::{self, Event, Outcome};
    use serde_json::json;
    let bad = |m: String| super::engine::Error::BadRequest(m);
    if std::env::var("KIRI_BUILD_PORTS_TEST").as_deref() != Ok("1") {
        return Err(super::engine::Error::NotFound("page not found".into()));
    }
    let v: Value = serde_json::from_slice(body).map_err(|e| bad(e.to_string()))?;
    let ports = Ports::new(engine.clone());
    let work = std::env::temp_dir().join(format!("kiri-golden-{}", super::engine::random_hex(8)));
    let cache = kiri_forge::cache::StepCache::open(&work.join("cache.json")).map_err(|e| bad(e.to_string()))?;
    let host = kiri_image::Platform::host_linux();
    // What POST /kiri/build builds natively, every step run.
    let opts = build::Options {
        target: v["target"].as_str().unwrap_or_default().to_owned(),
        build_args: v["build_args"].as_object().into_iter().flatten().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned()))).collect(),
        no_cache: true,
        work: work.join("copy"),
        // The context is read as the one who asked, as POST /kiri/build reads it.
        caller,
        ..build::Options::for_engine(Platform { os: host.os, architecture: host.architecture, variant: String::new() })
    };
    let context = PathBuf::from(v["context"].as_str().unwrap_or_default());
    let mut names: HashMap<usize, String> = HashMap::new();
    let mut steps: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    let mut on_event = |e: Event<'_>| match e {
        Event::Start { vertex, name } => {
            names.insert(vertex, name.to_owned());
            steps.entry(name.to_owned()).or_insert_with(|| json!({"name": name, "stdout": "", "stderr": ""}));
        }
        Event::Log { vertex, stream, data } => {
            if let Some(s) = names.get(&vertex).and_then(|n| steps.get_mut(n)) {
                let key = if stream == Stream::Stdout { "stdout" } else { "stderr" };
                let text = format!("{}{}", s[key].as_str().unwrap_or_default(), String::from_utf8_lossy(data));
                s[key] = json!(text);
            }
        }
        Event::Error { vertex, message } => {
            if let Some(s) = names.get(&vertex).and_then(|n| steps.get_mut(n)) {
                s["error"] = json!(message);
            }
        }
        _ => {}
    };
    let dockerfile = v["dockerfile"].as_str().unwrap_or_default().as_bytes().to_vec();
    let result = build::build(&dockerfile, &context, &opts, build::Ports { runner: &ports, store: &ports, images: &ports, cache: &cache }, &mut on_event);
    let _ = std::fs::remove_dir_all(&work);
    let steps: Vec<Value> = steps.into_values().collect();
    let id = match result {
        Err(e) => return Ok(json!({"steps": steps, "error": e.0})),
        Ok(Outcome::Unsupported(why)) => return Ok(json!({"steps": steps, "unsupported": why})),
        Ok(Outcome::Built(b)) => b.id,
    };
    let image = engine.store.images()?.into_iter().find(|i| i.config_digest == id.as_str()).ok_or_else(|| super::engine::Error::NotFound(format!("image {id}")))?;
    let skip = v["skip"].as_u64().unwrap_or(0) as usize;
    let mut layers = Vec::new();
    for l in image.layers.iter().skip(skip) {
        let mut tar = Vec::new();
        ports.read_layer(&LayerId(l.digest.clone()), &mut tar).map_err(|e| super::engine::Error::Io(io::Error::other(e.to_string())))?;
        layers.push(json!(kiri_image::b64::encode(&tar)));
    }
    let config: Value = serde_json::from_slice(&engine.store.read_config(&image.config_digest)?).unwrap_or(Value::Null);
    let _ = engine.store.remove_image(&image.name);
    Ok(json!({"steps": steps, "image": id.as_str(), "layers": layers, "config": config}))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two builds recording images with the same config under their own
    /// names, each removed right after (sibling cases of the builder test
    /// data): a removal of one never deletes the config the other has just
    /// written and not yet recorded (`docker save`: unexpected EOF).
    /// A step waiting for a `locked` cache another build holds stops
    /// waiting when its build is cancelled (the lock is engine-wide, so the
    /// holder may run for long); uncancelled, it gets the lock once free.
    #[test]
    fn a_cancelled_step_stops_waiting_for_a_locked_cache() {
        let lock = Arc::new(Mutex::new(()));
        let held = lock.lock().unwrap();
        let cancel = kiri_forge::ports::Cancel::default();
        let t = std::time::Instant::now();
        std::thread::scope(|s| {
            let w = s.spawn(|| hold_locks(std::slice::from_ref(&lock), &cancel).is_none());
            std::thread::sleep(std::time::Duration::from_millis(200));
            cancel.cancel();
            assert!(w.join().unwrap(), "a cancelled waiter took the lock");
        });
        assert!(t.elapsed() < std::time::Duration::from_secs(2), "{:?}", t.elapsed());
        let free = kiri_forge::ports::Cancel::default();
        std::thread::scope(|s| {
            let w = s.spawn(|| hold_locks(std::slice::from_ref(&lock), &free).map(|g| g.len()));
            std::thread::sleep(std::time::Duration::from_millis(100));
            drop(held);
            assert_eq!(w.join().unwrap(), Some(1));
        });
    }

    /// Cache mounts are the engine's, not a build's: a `private` step of
    /// one build gets its own folder while another build's step uses the
    /// shared one, and two builds' `locked` steps on one id share its lock
    /// (each build
    /// has its own `Ports`).
    #[test]
    fn cache_sharing_holds_across_builds() {
        let root = std::env::temp_dir().join(format!("kiri-cache-sharing-{}", super::super::engine::random_hex(8)));
        let engine = super::super::engine::boot_without_vm(&root);
        let id = format!("//c-{}", super::super::engine::random_hex(8));
        let (a, b) = (Ports::new(engine.clone()), Ports::new(engine.clone()));
        let (mut la, mut lb) = (Vec::new(), Vec::new());
        let held = a.cache_folder(&id, Sharing::Shared, &mut la);
        let private = b.cache_folder(&id, Sharing::Private, &mut lb);
        assert_ne!(private.folder, held.folder, "a private step took the folder another build's step uses");
        drop((held, private));
        let (mut la, mut lb) = (Vec::new(), Vec::new());
        let _ua = a.cache_folder(&id, Sharing::Locked, &mut la);
        let _ub = b.cache_folder(&id, Sharing::Locked, &mut lb);
        assert!(Arc::ptr_eq(&la[0], &lb[0]), "two builds' locked steps on one id have different locks");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_image_recorded_while_its_twin_is_removed_keeps_its_config() {
        let root = std::env::temp_dir().join(format!("kiri-record-race-{}", super::super::engine::random_hex(8)));
        let engine = super::super::engine::boot_without_vm(&root);
        let config = serde_json::to_vec(&serde_json::json!({"os": "linux", "architecture": "amd64", "config": {}, "rootfs": {"type": "layers", "diff_ids": []}})).unwrap();
        std::thread::scope(|s| {
            for name in ["localhost:1/twin-a:1", "localhost:1/twin-b:1"] {
                let (engine, config) = (&engine, &config);
                s.spawn(move || {
                    for round in 0..100 {
                        let ports = Ports::new(engine.clone());
                        let id = ports.record_image(ImageRecord { config: config.clone(), layers: Vec::new(), names: vec![name.into()] }).unwrap();
                        drop(ports);
                        assert!(engine.store.blob_path(id.as_str()).unwrap().exists(), "{name} round {round}: its config is gone");
                        engine.store.remove_image(name).unwrap();
                    }
                });
            }
        });
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A build resolving a local image by name while another build removes
    /// and records that name again (a base image rebuilt, mac/onbuild-*):
    /// once resolved, its config and layers stay readable for the build.
    #[test]
    fn a_resolved_local_image_stays_whole_while_its_name_is_removed() {
        use std::io::Write as _;
        let root = std::env::temp_dir().join(format!("kiri-resolve-race-{}", super::super::engine::random_hex(8)));
        let engine = super::super::engine::boot_without_vm(&root);
        let layer_tar = {
            let mut b = tar::Builder::new(Vec::new());
            let mut h = tar::Header::new_ustar();
            h.set_size(3);
            h.set_mode(0o644);
            b.append_data(&mut h, "f", &b"abc"[..]).unwrap();
            b.into_inner().unwrap()
        };
        let put = |bytes: &[u8]| {
            let mut w = engine.store.ingest().unwrap();
            w.write_all(bytes).unwrap();
            w.finish().unwrap()
        };
        let diff_id = kiri_image::store::sha256_digest(&layer_tar);
        let config = serde_json::json!({"os": "linux", "architecture": kiri_image::Platform::host_linux().architecture, "config": {}, "rootfs": {"type": "layers", "diff_ids": [diff_id]}});
        let record = || {
            let (cfg, _) = put(&serde_json::to_vec(&config).unwrap());
            let (layer, size) = put(&layer_tar);
            let mut image = kiri_image::archive::from_config("localhost:1/base:1".into(), &cfg, &config, vec![kiri_image::Layer { digest: layer, size, media_type: TAR.into() }]);
            image.digest = cfg.clone();
            engine.store.put_image(image).unwrap();
        };
        record();
        let platform = format!("linux/{}", kiri_image::Platform::host_linux().architecture);
        // Removed right after the build resolved it: the build still has it.
        {
            let ports = Ports::new(engine.clone());
            let image = ports.resolve_local("localhost:1/base:1", "localhost:1/base:1", &[&platform]).unwrap().unwrap();
            engine.store.remove_image("localhost:1/base:1").unwrap();
            ports.fetch_config(&image).unwrap();
            let l = ports.find_layer(&image.layers[0].diff_id).unwrap().expect("the layer is held");
            ports.read_layer(&l, &mut Vec::new()).unwrap();
        }
        record();
        let stop = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|s| {
            s.spawn(|| {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    engine.store.remove_image("localhost:1/base:1").unwrap();
                    record();
                }
            });
            for round in 0..2000 {
                let ports = Ports::new(engine.clone());
                // The local half of resolve: no pull is ever tried here.
                let image = match ports.resolve_local("localhost:1/base:1", "localhost:1/base:1", &[&platform]) {
                    Ok(Some(i)) => i,
                    Ok(None) => continue,
                    Err(e) => panic!("round {round}: resolve: {e:?}"),
                };
                let config = ports.fetch_config(&image).unwrap_or_else(|e| panic!("round {round}: config: {e}"));
                assert!(!config.is_empty());
                let l = ports.find_layer(&image.layers[0].diff_id).unwrap().unwrap_or_else(|| panic!("round {round}: the layer is gone"));
                let mut out = Vec::new();
                ports.read_layer(&l, &mut out).unwrap_or_else(|e| panic!("round {round}: layer: {e}"));
            }
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A pulled base image as `docker pull` leaves it: a gzip layer
    /// holding `f` (with `body`) and a folder, recorded as `name`.
    fn pulled(engine: &Engine, name: &str, body: &[u8]) -> Digest {
        use std::io::Write as _;
        let layer_tar = {
            let mut b = tar::Builder::new(Vec::new());
            let mut h = tar::Header::new_ustar();
            h.set_entry_type(tar::EntryType::Directory);
            h.set_mode(0o755);
            h.set_size(0);
            b.append_data(&mut h, "etc/", &[][..]).unwrap();
            let mut h = tar::Header::new_ustar();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            b.append_data(&mut h, "etc/f", body).unwrap();
            b.into_inner().unwrap()
        };
        let gz = {
            let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            z.write_all(&layer_tar).unwrap();
            z.finish().unwrap()
        };
        let put = |bytes: &[u8]| {
            let mut w = engine.store.ingest().unwrap();
            w.write_all(bytes).unwrap();
            w.finish().unwrap()
        };
        let diff_id = kiri_image::store::sha256_digest(&layer_tar);
        let config = serde_json::json!({"os": "linux", "architecture": kiri_image::Platform::host_linux().architecture, "config": {}, "rootfs": {"type": "layers", "diff_ids": [diff_id]}});
        let (cfg, _) = put(&serde_json::to_vec(&config).unwrap());
        let (layer, size) = put(&gz);
        let mut image = kiri_image::archive::from_config(name.into(), &cfg, &config, vec![kiri_image::Layer { digest: layer, size, media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into() }]);
        image.digest = cfg.clone();
        engine.store.put_image(image).unwrap();
        Digest::parse(&diff_id).unwrap()
    }

    /// What `etc/f` holds in a view of `layers`.
    fn read_f(ports: &Ports, layers: &[LayerId]) -> Vec<u8> {
        let work = std::env::temp_dir();
        let view = ports.root_view(layers, &[], &work).unwrap();
        let tree = view.tree().expect("a view held as a tree");
        let Some(kiri_forge::copy::TreeEntry { kind: kiri_forge::copy::TreeKind::File(body), .. }) = tree.lookup("etc/f") else { panic!("no etc/f in the view") };
        let mut out = Vec::new();
        body.open().unwrap().read_to_end(&mut out).unwrap();
        out
    }

    /// A view of a pulled (compressed) layer, which every WORKDIR, COPY
    /// and `COPY --from` of a stage on it reads, decompresses the layer
    /// once, not once per view and per build: a base of 1.4 GB unpacked
    /// cost 5.5 s per view, on every build, even one with nothing changed.
    #[test]
    fn a_pulled_layer_is_decompressed_once_whatever_reads_a_view_of_it() {
        let root = std::env::temp_dir().join(format!("kiri-view-once-{}", super::super::engine::random_hex(8)));
        let engine = super::super::engine::boot_without_vm(&root);
        let diff_id = pulled(&engine, "localhost:1/big:1", b"first");
        for build in 0..3 {
            let ports = Ports::new(engine.clone());
            let l = ports.find_layer(&diff_id).unwrap().expect("the layer is there");
            for _ in 0..3 {
                assert_eq!(read_f(&ports, std::slice::from_ref(&l)), b"first");
            }
            let n = ports.unpacked.load(std::sync::atomic::Ordering::Relaxed);
            assert_eq!(n, u64::from(build == 0), "build {build}: decompressed {n} times");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// What a view of a pulled layer keeps follows the layer: removing the
    /// image removes it, the tag pulled again with other content gives the
    /// new content, and a kept copy damaged on disk is never used.
    #[test]
    fn what_a_view_keeps_of_a_pulled_layer_goes_with_it_and_is_checked() {
        let root = std::env::temp_dir().join(format!("kiri-view-gone-{}", super::super::engine::random_hex(8)));
        let engine = super::super::engine::boot_without_vm(&root);
        let first = pulled(&engine, "localhost:1/big:1", b"first");
        let kept = |d: &Digest| -> Vec<PathBuf> {
            let ports = Ports::new(engine.clone());
            let l = ports.find_layer(d).unwrap().unwrap();
            vec![engine.store.layer_tar_path(&l.0).unwrap()]
        };
        {
            let ports = Ports::new(engine.clone());
            let l = ports.find_layer(&first).unwrap().unwrap();
            assert_eq!(read_f(&ports, std::slice::from_ref(&l)), b"first");
        }
        let paths = kept(&first);
        assert!(paths[0].exists(), "a view keeps the layer unpacked");
        engine.store.remove_image("localhost:1/big:1").unwrap();
        assert!(!paths[0].exists(), "removing the image removes what was kept of its layer");
        // The same tag again, other content.
        let second = pulled(&engine, "localhost:1/big:1", b"second");
        assert_ne!(first, second);
        {
            let ports = Ports::new(engine.clone());
            assert!(ports.find_layer(&first).unwrap().is_none());
            let l = ports.find_layer(&second).unwrap().unwrap();
            assert_eq!(read_f(&ports, std::slice::from_ref(&l)), b"second");
        }
        // Damaged on disk: found by its stat, unpacked again, never read.
        let path = kept(&second).remove(0);
        let mut bytes = std::fs::read(&path).unwrap();
        let at = bytes.windows(6).position(|w| w == b"second").unwrap();
        bytes[at..at + 6].copy_from_slice(b"SECOND");
        std::fs::write(&path, &bytes).unwrap();
        {
            let ports = Ports::new(engine.clone());
            let l = ports.find_layer(&second).unwrap().unwrap();
            assert_eq!(read_f(&ports, std::slice::from_ref(&l)), b"second");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    fn entry(path: &str, kind: CopyKind) -> kiri_forge::ports::CopyEntry {
        kiri_forge::ports::CopyEntry { path: path.into(), mode: 0o644, uid: 0, gid: 0, mtime: 1_700_000_000, kind, xattrs: Vec::new() }
    }

    fn names(tar_bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        tar::Archive::new(tar_bytes)
            .entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let mut body = Vec::new();
                e.read_to_end(&mut body).unwrap();
                (String::from_utf8_lossy(&e.path_bytes()).into_owned(), body)
            })
            .collect()
    }

    #[test]
    fn a_copy_layer_holds_its_entries_in_order_and_ends_with_two_zero_blocks() {
        // a real path, as the engine names context files: open_real refuses
        // a link on the way, and macOS's temp folder is under the /var link
        let dir = std::env::temp_dir().canonicalize().unwrap().join(format!("kiri-copylayer-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ctx"), b"from the context").unwrap();
        let copy = CopyLayer {
            entries: vec![
                entry("app", CopyKind::Dir),
                entry("app/a", CopyKind::File(Content::Inline(b"inline".to_vec()))),
                entry("app/b", CopyKind::File(Content::Context { path: dir.join("ctx"), sha256: Digest::of(b"from the context") })),
                entry("app/c", CopyKind::Symlink { target: "a".into() }),
            ],
        };
        let mut out = Vec::new();
        write_copy_layer(&copy, &mut out).unwrap();
        assert_eq!(&out[out.len() - 1024..], &[0u8; 1024][..]);
        let got = names(&out);
        assert_eq!(got.iter().map(|e| e.0.as_str()).collect::<Vec<_>>(), ["app/", "app/a", "app/b", "app/c"]);
        assert_eq!(got[2].1, b"from the context");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_context_file_that_changed_since_it_was_hashed_is_a_mismatch() {
        // a real path, as the engine names context files: open_real refuses
        // a link on the way, and macOS's temp folder is under the /var link
        let dir = std::env::temp_dir().canonicalize().unwrap().join(format!("kiri-copylayer-mm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ctx"), b"new bytes").unwrap();
        let copy = CopyLayer { entries: vec![entry("f", CopyKind::File(Content::Context { path: dir.join("ctx"), sha256: Digest::of(b"old bytes") }))] };
        assert!(matches!(write_copy_layer(&copy, &mut Vec::new()), Err(Error::Mismatch(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_wh_name_or_a_path_out_of_the_layer_is_refused() {
        for p in [".wh.x", "a/.wh..wh..opq", "../x", "/abs", "a//b"] {
            let copy = CopyLayer { entries: vec![entry(p, CopyKind::File(Content::Inline(Vec::new())))] };
            assert!(matches!(write_copy_layer(&copy, &mut Vec::new()), Err(Error::Refused(_))), "{p}");
        }
    }

    /// The capability as a PAX record, `user.*` never.
    #[test]
    fn only_the_capability_of_a_copied_file_reaches_the_layer() {
        let cap = vec![1, 0, 0, 2, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut e = entry("ping", CopyKind::File(Content::Inline(b"x".to_vec())));
        e.xattrs = vec![("security.capability".into(), cap.clone()), ("user.note".into(), b"hi".to_vec())];
        let mut out = Vec::new();
        write_copy_layer(&CopyLayer { entries: vec![e] }, &mut out).unwrap();
        let mut a = tar::Archive::new(&out[..]);
        let mut entries = a.entries().unwrap();
        let mut first = entries.next().unwrap().unwrap();
        let recs: Vec<(String, Vec<u8>)> =
            first.pax_extensions().unwrap().unwrap().map(|r| r.unwrap()).map(|r| (r.key().unwrap().to_owned(), r.value_bytes().to_vec())).collect();
        assert_eq!(recs, vec![("SCHILY.xattr.security.capability".to_owned(), cap)]);
    }

    /// Device numbers in the header, a FIFO with size 0.
    #[test]
    fn devices_and_fifos_are_written_with_their_numbers() {
        let copy = CopyLayer {
            entries: vec![
                entry("dev/null", CopyKind::Device { block: false, major: 1, minor: 3 }),
                entry("dev/loop9", CopyKind::Device { block: true, major: 7, minor: 9 }),
                entry("pipe", CopyKind::Fifo),
            ],
        };
        let mut out = Vec::new();
        write_copy_layer(&copy, &mut out).unwrap();
        let mut a = tar::Archive::new(&out[..]);
        let got: Vec<(u8, Option<u32>, Option<u32>, u64)> = a
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                let h = e.header();
                (h.entry_type().as_byte(), h.device_major().unwrap(), h.device_minor().unwrap(), h.size().unwrap())
            })
            .collect();
        assert_eq!(got, vec![(b'3', Some(1), Some(3), 0), (b'4', Some(7), Some(9), 0), (b'6', Some(0), Some(0), 0)]);
    }

    #[test]
    fn an_empty_copy_is_the_empty_layer() {
        let mut out = Vec::new();
        write_copy_layer(&CopyLayer { entries: Vec::new() }, &mut out).unwrap();
        // 1024 zero bytes.
        assert_eq!(Digest::of(&out).as_str(), "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef");
    }
}
