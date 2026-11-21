//! Content-addressed blob store and the image index on the host.
//!
//! Layout under the data directory:
//!
//! ```text
//! blobs/sha256/<hex>     compressed layers and configs, exactly as the registry served them
//! images.json            the image index
//! images.lock            held while the index is read, changed and rewritten
//! tmp/                   in-flight downloads, renamed into blobs/ once verified
//! ```
//!
//! The index is only ever replaced whole, by renaming a finished temporary
//! file over it, so a reader sees the old index or the new one, never a mix.
//! A change reads the index and writes it back with the lock held, so two
//! pulls or builds finishing together cannot lose each other's image. An
//! index that does not parse (written by an older Kiri, or damaged) is moved
//! aside as `images.json.corrupt-*` and what can be read from it is kept.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

/// The most an image config may be: real ones are a few KB.
pub const MAX_CONFIG: u64 = 16 << 20;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::reference::Reference;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Layer {
    pub digest: String,
    pub size: u64,
    pub media_type: String,
}

/// What a container needs from the image config to start.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunConfig {
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub entrypoint: Vec<String>,
    #[serde(default)]
    pub cmd: Vec<String>,
    #[serde(default)]
    pub working_dir: String,
    #[serde(default)]
    pub user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Image {
    /// Short reference, e.g. `alpine:latest`.
    pub name: String,
    /// Digest of the platform manifest.
    pub digest: String,
    /// Digest of the multi-arch index the manifest was picked from, when the
    /// registry served one. Docker lists it in RepoDigests, and a pull by
    /// that digest must find the image by it.
    #[serde(default)]
    pub index_digest: Option<String>,
    pub config_digest: String,
    pub layers: Vec<Layer>,
    /// Compressed size of all layers, which is what `docker images` reports too.
    pub size: u64,
    pub platform: String,
    /// When the image was built, as written in its config (RFC 3339).
    #[serde(default)]
    pub created: String,
    /// Unix seconds when this image was pulled.
    pub pulled_at: u64,
    pub config: RunConfig,
}

impl Image {
    /// The repository part of `name`: `alpine`, `ghcr.io/o/r`.
    pub fn repo(&self) -> &str {
        if let Some((repo, _)) = self.name.split_once('@') {
            return repo;
        }
        match self.name.rsplit_once(':') {
            Some((repo, tag)) if !tag.contains('/') => repo,
            _ => &self.name,
        }
    }

    /// `repo@digest` as Docker shows it, by the index's digest if there was one.
    /// None for an image no registry has yet (built, loaded, committed, tagged
    /// for another repository): its digest is its config's, which a manifest's
    /// can never be, as the manifest holds it.
    pub fn repo_digest(&self) -> Option<String> {
        let d = self.index_digest.as_deref().unwrap_or(&self.digest);
        (d != self.config_digest).then(|| format!("{}@{d}", self.repo()))
    }

    /// This image under another name (`docker tag`). Its registry digests
    /// belong to its repository: in another one it has none until a push.
    pub fn tagged(&self, name: String) -> Image {
        let mut i = Image { name, ..self.clone() };
        if i.repo() != self.repo() {
            i.digest = self.config_digest.clone();
            i.index_digest = None;
        }
        i
    }

    /// True if `r` names this image: its name, or a digest of its repository
    /// that is the image's manifest or the index it came from.
    pub fn matches(&self, r: &Reference) -> bool {
        if !r.is_digest() {
            return self.name == r.short();
        }
        let same_repo = Reference::parse(&self.name).is_ok_and(|n| n.registry == r.registry && n.repository == r.repository);
        same_repo && (self.digest == r.reference || self.index_digest.as_deref() == Some(r.reference.as_str()))
    }
}

#[derive(Debug)]
pub struct Store {
    root: PathBuf,
    /// Loaded on first use, so opening a store reads nothing.
    stamps: SharedStamps,
    hashed: AtomicU64,
    /// The stamps of the unpacked layer tars ([`Store::layer_tar`]), in
    /// `layer-tars/stamps`, loaded on first use.
    tar_stamps: SharedStamps,
    /// How many layer tars this store has unpacked.
    tars_made: AtomicU64,
    /// Whether the native builder uses this store ([`Store::use_native_checks`]).
    native: std::sync::atomic::AtomicBool,
}

/// Where the unpacked tars of compressed layer blobs are kept
/// ([`Store::layer_tar`]), one file per blob, named as the blob is.
const LAYER_TARS: &str = "layer-tars";

type SharedStamps = std::sync::Arc<Mutex<Option<crate::stamps::Stamps>>>;

fn with_stamps<T>(stamps: &SharedStamps, root: &Path, f: impl FnOnce(&mut crate::stamps::Stamps) -> T) -> T {
    with_stamps_at(stamps, &root.join("blobs/stamps"), f)
}

fn with_stamps_at<T>(stamps: &SharedStamps, file: &Path, f: impl FnOnce(&mut crate::stamps::Stamps) -> T) -> T {
    let mut s = stamps.lock().unwrap_or_else(|e| e.into_inner());
    f(s.get_or_insert_with(|| crate::stamps::Stamps::load(file.to_path_buf())))
}

/// One lock per layer tar being made, so two builds needing the same one
/// unpack it once.
static MAKING_TARS: Mutex<std::collections::BTreeMap<String, std::sync::Arc<Mutex<()>>>> = Mutex::new(std::collections::BTreeMap::new());

/// Records that the blob at `path`, as it is now, holds what its name says.
fn stamp_blob(stamps: &SharedStamps, root: &Path, hex: &str, path: &Path, diff_id: Option<String>) {
    if let Ok(stat) = crate::stamps::Stat::of(path) {
        with_stamps(stamps, root, |s| {
            let diff_id = diff_id.or_else(|| s.get(hex).and_then(|old| old.diff_id.clone()));
            s.set(hex, crate::stamps::Stamp { stat, diff_id });
        });
    }
}

/// The diff_ids the store has seen blobs unpack to, recorded in their
/// stamps ([`Store::diff_ids`]): a handle that outlives a borrow of the
/// store, for a pull's unpack on the way.
#[derive(Debug, Clone)]
pub struct DiffIds {
    stamps: SharedStamps,
    root: PathBuf,
}

impl DiffIds {
    /// The diff_id the blob `digest` was seen to unpack to, while the blob
    /// is still the file it was seen as (its stat is its stamp's).
    pub fn get(&self, digest: &str) -> Option<String> {
        let hex = digest_hex(digest).ok()?;
        let stat = crate::stamps::Stat::of(&self.root.join("blobs/sha256").join(hex)).ok()?;
        with_stamps(&self.stamps, &self.root, |s| s.get(hex).filter(|st| st.stat == stat).and_then(|st| st.diff_id.clone()))
    }

    /// Records that the blob `digest` unpacks to `diff_id`, as computed
    /// from its bytes (never as some config claims it). Only on a blob
    /// stamped as whole and unchanged since: this adds to a stamp, it never
    /// makes one.
    pub fn record(&self, digest: &str, diff_id: &str) {
        let (Ok(hex), Ok(_)) = (digest_hex(digest), digest_hex(diff_id)) else { return };
        let Ok(stat) = crate::stamps::Stat::of(&self.root.join("blobs/sha256").join(hex)) else { return };
        with_stamps(&self.stamps, &self.root, |s| {
            if s.get(hex).is_some_and(|st| st.stat == stat) {
                s.set(hex, crate::stamps::Stamp { stat, diff_id: Some(diff_id.to_owned()) });
            }
        });
    }
}

/// Held while a blob is renamed into place or a damaged one removed, so a
/// removal never takes a good copy another writer has just put there.
static BLOB_LOCK: Mutex<()> = Mutex::new(());

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Serializes index changes between the threads of this process; the lock
/// file does it between processes (the CLI opens the store too).
static INDEX_LOCK: Mutex<()> = Mutex::new(());

/// Blobs a build in this process is using, by path, with how many hold
/// each: removing an image leaves these in place. A build takes its layers
/// from the step cache, not from an image, so without this a `docker rmi`
/// at the same time deletes a layer under the build.
static PINNED: Mutex<std::collections::BTreeMap<PathBuf, usize>> = Mutex::new(std::collections::BTreeMap::new());

/// A blob kept from deletion until this is dropped ([`Store::pin`]).
#[derive(Debug)]
pub struct Pin(Option<PathBuf>);

impl Drop for Pin {
    fn drop(&mut self) {
        let Some(p) = self.0.take() else { return };
        let mut m = PINNED.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = m.get_mut(&p) {
            *n -= 1;
            if *n == 0 {
                m.remove(&p);
            }
        }
    }
}

fn pinned(p: &Path) -> bool {
    PINNED.lock().unwrap_or_else(|e| e.into_inner()).contains_key(p)
}

/// Where the program writes error-level lines.
pub type ErrorLog = fn(&str);
static ERROR_LOG: OnceLock<ErrorLog> = OnceLock::new();

/// Called once by the daemon, so a damaged index is reported in its log.
pub fn set_error_log(f: ErrorLog) {
    let _ = ERROR_LOG.set(f);
}

fn log_error(message: &str) {
    match ERROR_LOG.get() {
        Some(log) => log(message),
        None => eprintln!("kiri: {message}"),
    }
}

/// Held while the index is changed. The file goes first so the process-wide
/// lock is the last one released.
#[derive(Debug)]
struct IndexLock {
    _file: Option<File>,
    _guard: MutexGuard<'static, ()>,
}

/// What `images.json` holds.
enum Index {
    Valid(Vec<Image>),
    Corrupt(Vec<u8>, serde_json::Error),
}

/// The images that can still be read from a damaged index, see
/// [`crate::jsonfile::salvage`].
fn salvage(bytes: &[u8]) -> Vec<Image> {
    crate::jsonfile::salvage(bytes)
}

/// The name of every image record in an index, damaged or not, including a
/// record cut short after its name: what a person needs to know was lost.
/// A record's `name` is its first field, so only a `"name"` right after a
/// record's `{` (itself after `[` or `,`) counts, not a label called name.
fn record_names(bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let before = |end: usize| text[..end].trim_end().chars().next_back();
    let mut names = Vec::new();
    for (at, _) in text.match_indices("\"name\"") {
        let brace = text[..at].trim_end().len();
        if before(brace) != Some('{') || !matches!(before(brace - 1), Some('[' | ',')) {
            continue;
        }
        let Some(value) = text[at + 6..].trim_start().strip_prefix(':') else { continue };
        if let Some(Ok(name)) = serde_json::Deserializer::from_str(value).into_iter::<String>().next() {
            names.push(name);
        }
    }
    names
}

/// The images a damaged index held that are not in `images`.
fn missing(bytes: &[u8], images: &[Image]) -> Vec<String> {
    let mut names = record_names(bytes);
    names.retain(|n| !images.iter().any(|i| &i.name == n));
    names.dedup();
    names
}

/// The copies of damaged indexes kept beside `images.json`, and the images
/// they name that the index no longer has. See [`Store::index_damage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexDamage {
    pub copies: Vec<PathBuf>,
    pub missing: Vec<String>,
}

/// The filesystem-safe hexadecimal part of a SHA-256 digest.
pub fn digest_hex(digest: &str) -> io::Result<&str> {
    let h = digest.strip_prefix("sha256:").unwrap_or_default();
    if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("invalid sha256 digest {digest:?}")));
    }
    Ok(h)
}

impl Store {
    /// The per-user data directory: `~/Library/Application Support/Kiri` on
    /// macOS, `$XDG_DATA_HOME/kiri` (or `~/.local/share/kiri`) elsewhere.
    /// `KIRI_DATA_DIR` overrides both.
    pub fn default_root() -> io::Result<PathBuf> {
        if let Some(dir) = std::env::var_os("KIRI_DATA_DIR") {
            return Ok(PathBuf::from(dir));
        }
        let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| io::Error::other("HOME is not set"))?;
        Ok(if cfg!(target_os = "macos") {
            home.join("Library/Application Support/Kiri")
        } else if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            PathBuf::from(xdg).join("kiri")
        } else {
            home.join(".local/share/kiri")
        })
    }

    pub fn open(root: impl Into<PathBuf>) -> io::Result<Store> {
        let root = root.into();
        fs::create_dir_all(root.join("blobs/sha256"))?;
        fs::create_dir_all(root.join("tmp"))?;
        Ok(Store { root, stamps: SharedStamps::default(), hashed: AtomicU64::new(0), tar_stamps: SharedStamps::default(), tars_made: AtomicU64::new(0), native: std::sync::atomic::AtomicBool::new(false) })
    }

    /// Turns on what only the native builder needs, for the rest of this
    /// process: a blob's content is checked against its digest before it
    /// is relied on (once, then trusted while its stat matches its stamp),
    /// plain-tar layers leave gzipped as BuildKit's do, pulled layers
    /// unpack on the way, and the start-up check looks at the images'
    /// blobs. Off (the default, the builder switched off), the store reads,
    /// sends, saves and pushes blobs as it did before the builder existed:
    /// presence and size, nothing read whole.
    pub fn use_native_checks(&self) {
        self.native.store(true, Ordering::Relaxed);
    }

    /// The diff_ids seen for this store's blobs ([`DiffIds`]).
    pub fn diff_ids(&self) -> DiffIds {
        DiffIds { stamps: self.stamps.clone(), root: self.root.clone() }
    }

    /// Whether [`Store::use_native_checks`] was called.
    pub fn native_checks(&self) -> bool {
        self.native.load(Ordering::Relaxed)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// An image config, read whole for parsing. Configs are small JSON; a
    /// registry could serve a huge blob under that name, so anything over
    /// `MAX_CONFIG` is refused rather than loaded into memory.
    pub fn read_config(&self, digest: &str) -> std::io::Result<Vec<u8>> {
        let path = self.blob_path(digest)?;
        let len = std::fs::metadata(&path)?.len();
        if len > MAX_CONFIG {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("image config {digest} is {len} bytes; the limit is {MAX_CONFIG}")));
        }
        std::fs::read(path)
    }

    pub fn blob_path(&self, digest: &str) -> io::Result<PathBuf> {
        Ok(self.root.join("blobs/sha256").join(digest_hex(digest)?))
    }

    /// True if the blob is present, of the expected size and whole. Blobs
    /// are renamed into place only after their digest was checked, but a
    /// file can change after that: a blob whose stat differs from its stamp
    /// is read again and, if its digest is wrong, removed with every image
    /// naming it An unchanged blob costs one stat.
    ///
    /// Without [`Store::use_native_checks`]: present with the expected size,
    /// as before the builder (blobs are renamed into place only after their
    /// digest was checked), nothing read.
    pub fn has_blob(&self, digest: &str, size: u64) -> bool {
        if !self.native_checks() {
            return self.blob_path(digest).is_ok_and(|p| fs::metadata(p).is_ok_and(|m| m.len() == size));
        }
        self.verified(digest, Some(size)).is_ok()
    }

    /// The path of a whole blob, checked as [`Store::has_blob`] checks it,
    /// for a caller that is about to read it; an error that names the blob
    /// when it is missing or was damaged (and is now removed).
    ///
    /// Without [`Store::use_native_checks`]: the blob's path, as
    /// [`Store::blob_path`] gives it, nothing looked at.
    pub fn verified_blob_path(&self, digest: &str) -> io::Result<PathBuf> {
        if !self.native_checks() {
            return self.blob_path(digest);
        }
        self.verified(digest, None)
    }

    /// How many blobs this store has read whole to check them.
    pub fn blobs_hashed(&self) -> u64 {
        self.hashed.load(Ordering::Relaxed)
    }

    fn with_stamps<T>(&self, f: impl FnOnce(&mut crate::stamps::Stamps) -> T) -> T {
        with_stamps(&self.stamps, &self.root, f)
    }

    /// Where the unpacked tar of the compressed layer blob `digest` is kept.
    pub fn layer_tar_path(&self, digest: &str) -> io::Result<PathBuf> {
        Ok(self.root.join(LAYER_TARS).join(digest_hex(digest)?))
    }

    /// What the kept uncompressed tar of layer blob `digest` takes on
    /// disk (0 when none is kept): part of its image's size, as Docker
    /// counts an image's unpacked snapshots, and freed with it.
    pub fn layer_tar_size(&self, digest: &str) -> u64 {
        self.layer_tar_path(digest).ok().and_then(|p| fs::metadata(p).ok()).map_or(0, |m| m.len())
    }

    /// How many layer tars [`Store::layer_tar`] has unpacked.
    pub fn layer_tars_made(&self) -> u64 {
        self.tars_made.load(Ordering::Relaxed)
    }

    fn with_tar_stamps<T>(&self, f: impl FnOnce(&mut crate::stamps::Stamps) -> T) -> T {
        with_stamps_at(&self.tar_stamps, &self.root.join(LAYER_TARS).join("stamps"), f)
    }

    /// The uncompressed tar of the compressed layer blob `digest`, which
    /// unpacks to `diff_id`, as a file to read in place, held from deletion
    /// while the pin lives. It is made once by `unpack` (which writes the
    /// blob's uncompressed bytes), checked against `diff_id` as it is
    /// written, and kept beside the blobs as a cache: it never becomes a
    /// blob, so no image ever names it and what is pushed or saved is the
    /// blob as pulled. A kept tar is trusted while its stat is the one
    /// stamped when it was checked (one stat), read whole and checked again
    /// otherwise, and made again if it is not `diff_id`. It goes when its
    /// blob does (an image removed, a blob found damaged), and the start-up
    /// check removes any whose blob is gone.
    pub fn layer_tar(&self, digest: &str, diff_id: &str, unpack: &mut dyn FnMut(&mut dyn Write) -> io::Result<()>) -> io::Result<(PathBuf, Pin)> {
        let hex = digest_hex(digest)?.to_owned();
        let want = digest_hex(diff_id)?.to_owned();
        let path = self.layer_tar_path(digest)?;
        let pin = {
            let _one = BLOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            *PINNED.lock().unwrap_or_else(|e| e.into_inner()).entry(path.clone()).or_insert(0) += 1;
            Pin(Some(path.clone()))
        };
        let making = MAKING_TARS.lock().unwrap_or_else(|e| e.into_inner()).entry(path.to_string_lossy().into_owned()).or_default().clone();
        let _making = making.lock().unwrap_or_else(|e| e.into_inner());
        if let Ok(stat) = crate::stamps::Stat::of(&path) {
            let stamped = self.with_tar_stamps(|s| s.get(&hex).is_some_and(|st| st.stat == stat && st.diff_id.as_deref() == Some(want.as_str())));
            if stamped {
                return Ok((path, pin));
            }
            self.hashed.fetch_add(1, Ordering::Relaxed);
            let mut h = Sha256::new();
            io::copy(&mut File::open(&path)?, &mut HashWriter(&mut h))?;
            if hex_of(&h.finalize()) == want && crate::stamps::Stat::of(&path).ok().as_ref() == Some(&stat) {
                self.with_tar_stamps(|s| s.set(&hex, crate::stamps::Stamp { stat, diff_id: Some(want.clone()) }));
                return Ok((path, pin));
            }
            log_error(&format!("the unpacked copy of layer {digest} was not {diff_id}; unpacking it again"));
        }
        fs::create_dir_all(self.root.join(LAYER_TARS))?;
        let tmp = self.root.join("tmp").join(format!("layertar.{hex}.{}.{}", std::process::id(), TMP_SEQ.fetch_add(1, Ordering::Relaxed)));
        let file = File::create(&tmp)?;
        let mut w = TarWriter { f: io::BufWriter::with_capacity(256 << 10, file), h: Sha256::new() };
        let written = unpack(&mut w).and_then(|()| w.f.flush());
        let got = hex_of(&w.h.finalize());
        let file = w.f.into_inner().map_err(|e| e.into_error());
        let done = written.and(file).and_then(|f| {
            if got != want {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("layer {digest} unpacks to sha256:{got}, not {diff_id}")));
            }
            // Synced before it is renamed and stamped: a crash never
            // leaves a stamped tar with lost bytes.
            f.sync_all()
        });
        if let Err(e) = done {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        {
            let _one = BLOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            fs::rename(&tmp, &path)?;
        }
        self.tars_made.fetch_add(1, Ordering::Relaxed);
        if let Ok(stat) = crate::stamps::Stat::of(&path) {
            self.with_tar_stamps(|s| s.set(&hex, crate::stamps::Stamp { stat, diff_id: Some(want) }));
        }
        // Unpacked from the blob and hashed: what the blob unpacks to.
        self.diff_ids().record(digest, diff_id);
        Ok((path, pin))
    }

    /// Removes the unpacked tar of blob `digest`, if one is kept and
    /// nothing holds it. Callers hold [`BLOB_LOCK`].
    fn remove_layer_tar(&self, digest: &str) {
        let Ok(path) = self.layer_tar_path(digest) else { return };
        if !pinned(&path) && fs::remove_file(&path).is_ok()
            && let Ok(h) = digest_hex(digest)
        {
            self.with_tar_stamps(|s| s.remove(h));
        }
    }

    fn stamp(&self, hex: &str, path: &Path, diff_id: Option<String>) {
        stamp_blob(&self.stamps, &self.root, hex, path, diff_id);
    }

    fn verified(&self, digest: &str, size: Option<u64>) -> io::Result<PathBuf> {
        let hex = digest_hex(digest)?;
        let path = self.blob_path(digest)?;
        let stat = crate::stamps::Stat::of(&path).map_err(|e| io::Error::new(e.kind(), format!("blob {digest}: {e}")))?;
        if size.is_some_and(|s| s != stat.size) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("blob {digest} is {} bytes, not {}", stat.size, size.unwrap_or(0))));
        }
        if self.with_stamps(|s| s.get(hex).is_some_and(|st| st.stat == stat)) {
            return Ok(path);
        }
        self.hashed.fetch_add(1, Ordering::Relaxed);
        let mut f = File::open(&path)?;
        let mut h = Sha256::new();
        io::copy(&mut f, &mut HashWriter(&mut h))?;
        let got = hex_of(&h.finalize());
        // Stat again: a blob replaced while it was read is judged next time.
        if crate::stamps::Stat::of(&path).ok().as_ref() != Some(&stat) {
            return Ok(path);
        }
        if got == hex {
            self.stamp(hex, &path, None);
            return Ok(path);
        }
        self.remove_damaged(digest, stat.ino, &format!("its content hashes to sha256:{got}"));
        Err(io::Error::new(io::ErrorKind::InvalidData, format!("layer {digest} was damaged in the image store and has been removed; pull or build the image again")))
    }

    /// Removes a blob found damaged, if it is still the file that was
    /// checked, and drops every image naming it.
    fn remove_damaged(&self, digest: &str, ino: u64, why: &str) {
        let Ok(path) = self.blob_path(digest) else { return };
        {
            let _one = BLOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            if crate::stamps::Stat::of(&path).is_ok_and(|s| s.ino == ino) {
                let _ = fs::remove_file(&path);
            }
            self.remove_layer_tar(digest);
        }
        if let Ok(h) = digest_hex(digest) {
            self.with_stamps(|s| s.remove(h));
        }
        let dropped = self.drop_images_naming(&[digest.to_owned()]).unwrap_or_default();
        log_error(&format!("removed damaged blob {digest} ({why}){}", dropped_text(&dropped)));
    }

    /// Drops every image that names one of `digests` as its config or a layer.
    fn drop_images_naming(&self, digests: &[String]) -> io::Result<Vec<String>> {
        let _lock = self.lock_index()?;
        let mut images = self.read_locked()?;
        let names = |i: &Image| digests.iter().any(|d| &i.config_digest == d || i.layers.iter().any(|l| &l.digest == d));
        let dropped: Vec<String> = images.iter().filter(|i| names(i)).map(|i| i.name.clone()).collect();
        if !dropped.is_empty() {
            images.retain(|i| !names(i));
            self.write_index(&images)?;
        }
        Ok(dropped)
    }

    /// Makes the renames of blobs written so far durable: one fsync of the
    /// blob folder, before a record names them.
    pub fn sync_blobs(&self) -> io::Result<()> {
        File::open(self.root.join("blobs/sha256"))?.sync_all()
    }

    /// The start-up check. It deletes a file in exactly three cases:
    ///
    /// - in `tmp/` (or a `*.tmp` beside the index): what a write that never
    ///   finished left, its writing process gone ([`leftover`]);
    /// - in `layer-tars/`: an unpacked tar whose blob is surely absent and
    ///   that no build holds;
    /// - in `blobs/sha256/`: a blob whose content no longer hashes to its
    ///   name. Only a blob whose stat differs from the stamp recorded when
    ///   it was last known whole is read to find out; one never stamped
    ///   (written before stamps existed) is left to its first use.
    ///
    /// What an image's record or a manifest says about a blob (its size)
    /// never decides anything: a blob is judged by its own digest. An image
    /// naming a blob that is surely absent, or that was just found damaged,
    /// is dropped from the index (no file of it is deleted then). A blob
    /// that cannot be looked at for any other reason keeps its images.
    /// Costs one listing of `tmp/` and of `layer-tars/` and one stat per
    /// blob an image names, plus a read of each blob changed since its
    /// stamp. Returns what it removed or dropped, also logged.
    pub fn check(&self) -> io::Result<Vec<String>> {
        let mut repairs = Vec::new();
        for (dir, is_tmp) in [(self.root.join("tmp"), true), (self.root.clone(), false)] {
            let Ok(entries) = fs::read_dir(&dir) else { continue };
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if (is_tmp || name.ends_with(".tmp")) && leftover(&name, &e.path()) {
                    let p = e.path();
                    let gone = if p.is_dir() { fs::remove_dir_all(&p) } else { fs::remove_file(&p) };
                    if gone.is_ok() {
                        repairs.push(format!("removed {}, left by a write that never finished", p.display()));
                    }
                }
            }
        }
        // An unpacked layer tar whose blob is gone (removed while a build
        // held the tar) goes too.
        if let Ok(entries) = fs::read_dir(self.root.join(LAYER_TARS)) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if name == "stamps" || !surely_absent(&self.root.join("blobs/sha256").join(&name)) {
                    continue;
                }
                let _one = BLOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                if !pinned(&e.path()) && fs::remove_file(e.path()).is_ok() {
                    self.with_tar_stamps(|s| s.remove(&name));
                }
            }
        }
        let images = self.images()?;
        let mut bad: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for i in &images {
            for d in std::iter::once(i.config_digest.as_str()).chain(i.layers.iter().map(|l| l.digest.as_str())) {
                if !seen.insert(d) {
                    continue;
                }
                let (Ok(hex), Ok(path)) = (digest_hex(d), self.blob_path(d)) else { continue };
                let stat = match crate::stamps::Stat::of(&path) {
                    Ok(stat) => stat,
                    Err(e) if absent(&e) => {
                        repairs.push(format!("blob {d} is missing"));
                        bad.push(d.to_owned());
                        continue;
                    }
                    // Not readable now is not gone: the image is kept, and
                    // a use of the blob reports the error.
                    Err(e) => {
                        repairs.push(format!("blob {d} could not be looked at ({e}); its images are kept"));
                        continue;
                    }
                };
                let stamp = self.with_stamps(|s| s.get(hex).map(|st| st.stat.clone()));
                match stamp {
                    // Unchanged since it was known whole, or never stamped:
                    // nothing read.
                    Some(st) if st == stat => {}
                    None => {}
                    // Changed since: its own digest says whether it is whole.
                    Some(_) => {
                        self.hashed.fetch_add(1, Ordering::Relaxed);
                        let mut h = Sha256::new();
                        let read = File::open(&path).and_then(|mut f| io::copy(&mut f, &mut HashWriter(&mut h)));
                        let got = hex_of(&h.finalize());
                        if read.is_err() || crate::stamps::Stat::of(&path).ok().as_ref() != Some(&stat) {
                            continue;
                        }
                        if got == hex {
                            self.stamp(hex, &path, None);
                            continue;
                        }
                        {
                            let _one = BLOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                            if crate::stamps::Stat::of(&path).is_ok_and(|s| s.ino == stat.ino) && fs::remove_file(&path).is_ok() {
                                repairs.push(format!("removed blob {d}: its content hashes to sha256:{got}"));
                            }
                            self.remove_layer_tar(d);
                        }
                        self.with_stamps(|s| s.remove(hex));
                        bad.push(d.to_owned());
                    }
                }
            }
        }
        if !bad.is_empty() {
            for n in self.drop_images_naming(&bad)? {
                repairs.push(format!("dropped image {n}: a blob it names is missing or damaged; pull or build it again"));
            }
        }
        for r in &repairs {
            log_error(&format!("store check at start: {r}"));
        }
        Ok(repairs)
    }

    pub fn blob_writer(&self, digest: &str) -> io::Result<BlobWriter> {
        let tmp = self.root.join("tmp").join(format!("{}.{}.{}", digest_hex(digest)?, std::process::id(), TMP_SEQ.fetch_add(1, Ordering::Relaxed)));
        Ok(BlobWriter {
            stamps: self.stamps.clone(),
            root: self.root.clone(),
            file: File::create(&tmp)?,
            hasher: Sha256::new(),
            tmp,
            dest: self.blob_path(digest)?,
            expected: digest.to_owned(),
            written: 0,
        })
    }

    /// A writer for a blob whose digest is not known yet (`docker load`):
    /// it is named after what was written once `finish` is called.
    pub fn ingest(&self) -> io::Result<Ingest> {
        let tmp = self.root.join("tmp").join(format!("ingest.{}.{}", std::process::id(), TMP_SEQ.fetch_add(1, Ordering::Relaxed)));
        Ok(Ingest { stamps: self.stamps.clone(), file: File::create(&tmp)?, hasher: Sha256::new(), tmp, root: self.root.clone(), written: 0 })
    }

    /// The image index. One that does not parse is repaired first, see
    /// [`Store::recover`], rather than failing every caller from then on.
    pub fn images(&self) -> io::Result<Vec<Image>> {
        match self.read_index()? {
            Index::Valid(images) => Ok(images),
            Index::Corrupt(..) => {
                let _lock = self.lock_index()?;
                self.read_locked()
            }
        }
    }

    fn read_index(&self) -> io::Result<Index> {
        match fs::read(self.root.join("images.json")) {
            Ok(bytes) => Ok(match serde_json::from_slice(&bytes) {
                Ok(images) => Index::Valid(images),
                Err(e) => Index::Corrupt(bytes, e),
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Index::Valid(Vec::new())),
            Err(e) => Err(e),
        }
    }

    /// Takes the index lock. Everything that rewrites the index holds it from
    /// reading the index to renaming the new one into place.
    fn lock_index(&self) -> io::Result<IndexLock> {
        let guard = INDEX_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let file = File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.root.join("images.lock"))?;
        let file = match file.lock() {
            Ok(()) => Some(file),
            // A filesystem without file locks still has the process-wide one.
            Err(e) if e.kind() == io::ErrorKind::Unsupported => None,
            Err(e) => return Err(e),
        };
        Ok(IndexLock {
            _file: file,
            _guard: guard,
        })
    }

    /// The index, read with the lock held, repairing it if it is damaged.
    fn read_locked(&self) -> io::Result<Vec<Image>> {
        match self.read_index()? {
            Index::Valid(images) => Ok(images),
            Index::Corrupt(bytes, error) => Ok(self.recover(&bytes, &error)),
        }
    }

    /// Moves a damaged index aside as `images.json.corrupt-<seconds>-<n>`,
    /// writes back the images that can still be read from it and logs at
    /// error level. Never fails: with the index unwritable the caller still
    /// gets what could be read, and its own write reports the problem.
    ///
    /// Blobs are untouched, so an image lost with the index is pulled again
    /// from the cached layers. The registry's manifests, and so the names and
    /// layer lists, are not kept on the host: only the index itself can say
    /// which image a blob belongs to.
    fn recover(&self, bytes: &[u8], error: &serde_json::Error) -> Vec<Image> {
        let moved = crate::jsonfile::move_aside(&self.root.join("images.json"));
        let images = salvage(bytes);
        let written = if images.is_empty() {
            Ok(())
        } else {
            self.write_index(&images)
        };
        let kept = match &moved {
            Ok(aside) => format!("moved to {}", aside.display()),
            Err(e) => format!("not moved aside: {e}"),
        };
        let wrote = match &written {
            Ok(()) => String::new(),
            Err(e) => format!("; the repaired index was not written: {e}"),
        };
        let lost = missing(bytes, &images);
        let lost = if lost.is_empty() {
            String::new()
        } else {
            format!("; dropped from the list: {} (their layers are kept while the copy is)", lost.join(", "))
        };
        log_error(&format!(
            "image index unreadable ({error}): {kept}, {} image(s) recovered{lost}{wrote}",
            images.len()
        ));
        images
    }

    /// The `images.json.corrupt-*` copies kept beside the index, and the
    /// images they name that it no longer lists; `None` with no copy. While
    /// a copy is kept, the layers of the images it may still hold are not
    /// someone else's to delete: the daemon keeps every unpacked layer and
    /// says so in `docker info`. Removing the copies ends it.
    pub fn index_damage(&self) -> io::Result<Option<IndexDamage>> {
        // Read first: a damaged index is moved aside by this very read.
        let images = self.images()?;
        let copies = crate::jsonfile::kept_copies(&self.root.join("images.json"))?;
        if copies.is_empty() {
            return Ok(None);
        }
        let mut names = Vec::new();
        for c in &copies {
            for n in missing(&fs::read(c).unwrap_or_default(), &images) {
                if !names.contains(&n) {
                    names.push(n);
                }
            }
        }
        Ok(Some(IndexDamage { copies, missing: names }))
    }

    pub fn find(&self, name: &str) -> io::Result<Option<Image>> {
        let r = Reference::parse(name).ok();
        Ok(self.images()?.into_iter().find(|i| i.name == name || i.digest == name || r.as_ref().is_some_and(|r| i.matches(r))))
    }

    /// Adds `image`, replacing any image with the same name.
    pub fn put_image(&self, image: Image) -> io::Result<()> {
        let _lock = self.lock_index()?;
        let mut images = self.read_locked()?;
        images.retain(|i| i.name != image.name);
        images.push(image);
        self.write_index(&images)
    }

    /// Records the manifest a push of `name` left in its registry, so
    /// RepoDigests names what the registry has, as Docker's does: deploy tools
    /// pin to it. Every tag of the image in that repository gets it, as there.
    /// Not if `name` became another image during the push.
    pub fn set_pushed(&self, name: &str, config_digest: &str, digest: &str) -> io::Result<()> {
        let _lock = self.lock_index()?;
        let mut images = self.read_locked()?;
        let Some(repo) = images.iter().find(|i| i.name == name && i.config_digest == config_digest).map(|i| i.repo().to_owned()) else { return Ok(()) };
        for i in images.iter_mut().filter(|i| i.config_digest == config_digest && i.repo() == repo) {
            i.digest = digest.to_owned();
            i.index_digest = None;
        }
        self.write_index(&images)
    }

    /// Keeps the blob `digest` from deletion while the pin lives. Pin first,
    /// then check the blob is there: a pin taken after the check could
    /// miss a removal in between.
    pub fn pin(&self, digest: &str) -> Pin {
        let Ok(p) = self.blob_path(digest) else { return Pin(None) };
        *PINNED.lock().unwrap_or_else(|e| e.into_inner()).entry(p.clone()).or_insert(0) += 1;
        Pin(Some(p))
    }

    /// Removes the image and deletes blobs no remaining image uses and no
    /// build holds ([`Store::pin`]).
    pub fn remove_image(&self, name: &str) -> io::Result<Option<Image>> {
        let _lock = self.lock_index()?;
        let mut images = self.read_locked()?;
        let Some(pos) = images.iter().position(|i| i.name == name) else { return Ok(None) };
        let removed = images.remove(pos);
        self.write_index(&images)?;
        let in_use = |d: &str| images.iter().any(|i| i.config_digest == d || i.layers.iter().any(|l| l.digest == d));
        for d in std::iter::once(&removed.config_digest).chain(removed.layers.iter().map(|l| &l.digest)) {
            if !in_use(d) {
                self.remove_unpinned(d);
            }
        }
        Ok(Some(removed))
    }

    /// Deletes the blob `digest` if no image uses it and nothing holds it
    /// ([`Store::pin`]), as [`Store::remove_image`] deletes the blobs it
    /// frees: for a writer that put a blob in that nothing came to name.
    pub fn remove_if_unused(&self, digest: &str) -> io::Result<()> {
        let _lock = self.lock_index()?;
        let images = self.read_locked()?;
        if !images.iter().any(|i| i.config_digest == digest || i.layers.iter().any(|l| l.digest == digest)) {
            self.remove_unpinned(digest);
        }
        Ok(())
    }

    /// The pin check and the removal under the blob lock, which a writer's
    /// pin and rename take too ([`Ingest::finish_pinned`]): a blob written
    /// or found again by a writer between the two is never deleted.
    fn remove_unpinned(&self, digest: &str) {
        let Ok(path) = self.blob_path(digest) else { return };
        let _one = BLOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !pinned(&path) {
            let _ = fs::remove_file(path);
        }
        self.remove_layer_tar(digest);
    }

    /// Replaces the index with `images`, see [`crate::jsonfile::replace`].
    /// Callers hold the index lock.
    fn write_index(&self, images: &[Image]) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(images).map_err(io::Error::other)?;
        crate::jsonfile::replace_at(&self.root.join("images.json"), &bytes, crate::jsonfile::Durable::Now, "index")
    }
}

/// Writes a blob to a temporary file, hashing as it goes, and only moves it
/// into the store if the digest matches.
#[derive(Debug)]
pub struct BlobWriter {
    stamps: SharedStamps,
    root: PathBuf,
    file: File,
    hasher: Sha256,
    tmp: PathBuf,
    dest: PathBuf,
    expected: String,
    written: u64,
}

impl Write for BlobWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.file.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl BlobWriter {
    /// Verifies the digest and publishes the blob. Returns bytes written.
    pub fn finish(mut self) -> io::Result<u64> {
        let actual = format!("sha256:{}", hex(&std::mem::take(&mut self.hasher).finalize()));
        if actual != self.expected {
            let _ = fs::remove_file(&self.tmp);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("digest mismatch: expected {}, got {actual}", self.expected),
            ));
        }
        self.file.sync_all()?;
        crate::fault::point("blob-tmp");
        {
            let _one = BLOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            fs::rename(&self.tmp, &self.dest)?;
        }
        crate::fault::point("blob-renamed");
        // Hashed as it was written: its stamp says so, and nothing reads it
        // again to check until it changes.
        if let Some(h) = self.expected.strip_prefix("sha256:") {
            stamp_blob(&self.stamps, &self.root, h, &self.dest, None);
        }
        Ok(self.written)
    }
}

impl Drop for BlobWriter {
    fn drop(&mut self) {
        // A writer dropped without finish() leaves no partial blob behind.
        // After a successful finish() the tmp path no longer exists.
        let _ = fs::remove_file(&self.tmp);
    }
}

/// See [`Store::ingest`].
#[derive(Debug)]
pub struct Ingest {
    stamps: SharedStamps,
    file: File,
    hasher: Sha256,
    tmp: PathBuf,
    root: PathBuf,
    written: u64,
}

impl Write for Ingest {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.file.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Ingest {
    /// Publishes the blob under its digest. Returns (digest, size).
    pub fn finish(mut self) -> io::Result<(String, u64)> {
        let hex = hex(&std::mem::take(&mut self.hasher).finalize());
        self.file.sync_all()?;
        crate::fault::point("blob-tmp");
        {
            let _one = BLOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            fs::rename(&self.tmp, self.root.join("blobs/sha256").join(&hex))?;
        }
        crate::fault::point("blob-renamed");
        stamp_blob(&self.stamps, &self.root, &hex, &self.root.join("blobs/sha256").join(&hex), None);
        Ok((format!("sha256:{hex}"), self.written))
    }

    /// As [`Ingest::finish`], the blob held ([`Store::pin`]) from before
    /// it is in place: a removal of the last image using a blob of the
    /// same digest cannot delete it between the rename and the writer
    /// recording an image that names it (`docker load`).
    pub fn finish_pinned(mut self) -> io::Result<(String, u64, Pin)> {
        let hex = hex(&std::mem::take(&mut self.hasher).finalize());
        self.file.sync_all()?;
        crate::fault::point("blob-tmp");
        let dest = self.root.join("blobs/sha256").join(&hex);
        let pin = {
            let _one = BLOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            *PINNED.lock().unwrap_or_else(|e| e.into_inner()).entry(dest.clone()).or_insert(0) += 1;
            let pin = Pin(Some(dest.clone()));
            fs::rename(&self.tmp, &dest)?;
            pin
        };
        crate::fault::point("blob-renamed");
        stamp_blob(&self.stamps, &self.root, &hex, &dest, None);
        Ok((format!("sha256:{hex}"), self.written, pin))
    }
}

impl Drop for Ingest {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.tmp);
    }
}

pub fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(bytes)))
}

pub(crate) fn hex_of(bytes: &[u8]) -> String {
    hex(bytes)
}

/// `; dropped images: a, b` for a log line, or nothing.
fn dropped_text(names: &[String]) -> String {
    if names.is_empty() { String::new() } else { format!("; dropped the images naming it: {}", names.join(", ")) }
}

/// Whether a file in `tmp/` (or a `*.tmp` beside the index) is what a write
/// that never finished left: its name carries the writing process's id
/// (`<hex>.<pid>.<n>`, `ingest.<pid>.<n>`, `images.json.<pid>.<n>.tmp`,
/// `scan-<pid>-<hex>`), and that process is gone. A name that carries no id
/// is gone enough when a day old.
fn leftover(name: &str, path: &Path) -> bool {
    let pid = name.split(['.', '-']).find_map(|p| p.parse::<u32>().ok().filter(|n| *n > 1 && p.len() < 11));
    let old = || fs::metadata(path).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|a| a.as_secs() > 86_400);
    match pid {
        Some(p) if p == std::process::id() => false,
        Some(p) => !crate::proc::alive(p),
        None => old(),
    }
}

/// Whether an error says the file is not there: a definite "no such file",
/// or a component of its path that is not a folder (so nothing can be
/// there). Permission, I/O and other errors say nothing about it.
fn absent(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory)
}

/// True only when the file at `path` is known not to exist.
fn surely_absent(path: &Path) -> bool {
    fs::metadata(path).err().is_some_and(|e| absent(&e))
}

/// Writes a layer tar to its file, hashing it as it goes.
struct TarWriter {
    f: io::BufWriter<File>,
    h: Sha256,
}

impl Write for TarWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.f.write(buf)?;
        self.h.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.f.flush()
    }
}

struct HashWriter<'a>(&'a mut Sha256);

impl Write for HashWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pinned_blob_outlives_the_removal_of_its_image() {
        let root = std::env::temp_dir().join(format!("kiri-store-pin-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let store = Store::open(&root).unwrap();
        let mut ingest = store.ingest().unwrap();
        ingest.write_all(b"a layer a build is using").unwrap();
        let (layer, size) = ingest.finish().unwrap();
        let image = |name: &str| Image {
            name: name.into(),
            digest: "sha256:manifest".into(),
            index_digest: None,
            config_digest: format!("sha256:{}", "3".repeat(64)),
            layers: vec![Layer { digest: layer.clone(), size, media_type: "application/vnd.oci.image.layer.v1.tar".into() }],
            size,
            platform: "linux/amd64".into(),
            created: String::new(),
            pulled_at: 0,
            config: RunConfig::default(),
        };
        store.put_image(image("a:1")).unwrap();
        let pin = store.pin(&layer);
        store.remove_image("a:1").unwrap();
        assert!(store.has_blob(&layer, size), "a build still holds it");
        drop(pin);
        store.put_image(image("b:1")).unwrap();
        store.remove_image("b:1").unwrap();
        assert!(!store.has_blob(&layer, size), "no one holds it any more");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rejects_paths_instead_of_digests() {
        let root = std::env::temp_dir().join(format!("kiri-store-path-test-{}", std::process::id()));
        let store = Store::open(&root).unwrap();
        let outside = root.with_extension("outside");
        fs::write(&outside, b"do not touch").unwrap();
        let path = outside.to_string_lossy().into_owned();
        assert!(store.blob_path(&path).is_err());
        assert!(store.blob_path("sha256:../outside").is_err());
        assert!(!store.has_blob(&path, 12));
        assert!(store.blob_writer(&path).is_err());
        assert!(store.read_config(&path).is_err());

        let image = Image {
            name: "malicious:latest".into(),
            digest: "sha256:manifest".into(),
            index_digest: None,
            config_digest: path.clone(),
            layers: vec![Layer { digest: path, size: 12, media_type: "application/vnd.oci.image.layer.v1.tar".into() }],
            size: 12,
            platform: "linux/amd64".into(),
            created: String::new(),
            pulled_at: 0,
            config: RunConfig::default(),
        };
        store.put_image(image).unwrap();
        store.remove_image("malicious:latest").unwrap();
        assert_eq!(fs::read(&outside).unwrap(), b"do not touch");
        fs::remove_dir_all(&root).unwrap();
        fs::remove_file(&outside).unwrap();
    }

    #[test]
    fn finds_a_pull_by_index_digest_by_either_digest() {
        let root = std::env::temp_dir().join(format!("kiri-store-index-test-{}", std::process::id()));
        let store = Store::open(&root).unwrap();
        let (index, manifest) = (format!("sha256:{}", "1".repeat(64)), format!("sha256:{}", "2".repeat(64)));
        let image = Image {
            name: format!("kindest/node@{index}"),
            digest: manifest.clone(),
            index_digest: Some(index.clone()),
            config_digest: format!("sha256:{}", "3".repeat(64)),
            layers: Vec::new(),
            size: 0,
            platform: "linux/arm64".into(),
            created: String::new(),
            pulled_at: 0,
            config: RunConfig::default(),
        };
        assert_eq!(image.repo(), "kindest/node");
        assert_eq!(image.repo_digest(), Some(format!("kindest/node@{index}")));
        store.put_image(image).unwrap();
        for name in [format!("kindest/node@{index}"), format!("kindest/node:v1.37.0@{index}"), format!("kindest/node@{manifest}"), manifest.clone()] {
            assert!(store.find(&name).unwrap().is_some(), "{name}");
        }
        assert!(store.find(&format!("other/node@{index}")).unwrap().is_none());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_push_leaves_the_registry_manifest_in_repo_digests() {
        let root = std::env::temp_dir().join(format!("kiri-store-push-test-{}", std::process::id()));
        let store = Store::open(&root).unwrap();
        let d = |c: &str| format!("sha256:{}", c.repeat(64));
        let image = |name: &str, config: &str, index: Option<String>| Image {
            name: name.into(),
            digest: d(config),
            index_digest: index,
            config_digest: d(config),
            layers: Vec::new(),
            size: 0,
            platform: "linux/arm64".into(),
            created: String::new(),
            pulled_at: 0,
            config: RunConfig::default(),
        };
        // Built here: no registry has it yet, so no RepoDigest, as with Docker.
        store.put_image(image("localhost:5000/built:1", "1", None)).unwrap();
        // The same image's other tags: one in its repository, one in another registry.
        store.put_image(image("localhost:5000/built:latest", "1", None)).unwrap();
        store.put_image(image("localhost:5001/built:1", "1", None)).unwrap();
        // Pulled: alpine's index. Tagged in its repository it keeps that; in
        // another it has none there, rather than a digest that one lacks.
        let pulled = Image { digest: d("8"), ..image("alpine:latest", "2", Some(d("9"))) };
        assert_eq!(pulled.tagged("alpine:old".into()).repo_digest(), Some(format!("alpine@{}", d("9"))));
        store.put_image(pulled.tagged("localhost:5000/tagged:1".into())).unwrap();
        store.put_image(image("localhost:5000/other:1", "3", None)).unwrap();
        let repo_digest = |n: &str| store.find(n).unwrap().unwrap().repo_digest();
        for n in ["localhost:5000/built:1", "localhost:5000/tagged:1", "localhost:5000/other:1"] {
            assert_eq!(repo_digest(n), None, "{n}");
        }
        store.set_pushed("localhost:5000/built:1", &d("1"), &d("a")).unwrap();
        store.set_pushed("localhost:5000/tagged:1", &d("2"), &d("b")).unwrap();
        // The name now another image: that one keeps its own.
        store.set_pushed("localhost:5000/other:1", &d("4"), &d("c")).unwrap();
        assert_eq!(repo_digest("localhost:5000/built:1"), Some(format!("localhost:5000/built@{}", d("a"))));
        // Pushing one tag gives the repository's other tags of it the digest; elsewhere it has none.
        assert_eq!(repo_digest("localhost:5000/built:latest"), Some(format!("localhost:5000/built@{}", d("a"))));
        assert_eq!(repo_digest("localhost:5001/built:1"), None);
        assert_eq!(repo_digest("localhost:5000/tagged:1"), Some(format!("localhost:5000/tagged@{}", d("b"))));
        assert_eq!(repo_digest("localhost:5000/other:1"), None);
        // And a pull by the pushed digest finds the image here.
        assert!(store.find(&format!("localhost:5000/built@{}", d("a"))).unwrap().is_some());
        fs::remove_dir_all(&root).unwrap();
    }

    fn scratch(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("kiri-store-{tag}-test-{}", std::process::id()))
    }

    fn named(name: &str) -> Image {
        Image {
            name: name.into(),
            digest: format!("sha256:{}", "1".repeat(64)),
            index_digest: None,
            config_digest: format!("sha256:{}", "2".repeat(64)),
            layers: Vec::new(),
            size: 0,
            platform: "linux/arm64".into(),
            created: String::new(),
            pulled_at: 0,
            config: RunConfig::default(),
        }
    }

    fn names(store: &Store) -> Vec<String> {
        let mut n: Vec<String> = store
            .images()
            .unwrap()
            .into_iter()
            .map(|i| i.name)
            .collect();
        n.sort();
        n
    }

    fn corrupt_files(root: &Path) -> Vec<PathBuf> {
        fs::read_dir(root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("images.json.corrupt-")
            })
            .collect()
    }

    #[test]
    fn a_shorter_rewrite_over_a_longer_index_is_recovered() {
        let root = scratch("interleaved");
        let _ = fs::remove_dir_all(&root);
        let store = Store::open(&root).unwrap();
        let all: Vec<String> = (0..8).map(|i| format!("app{i}:latest")).collect();
        for n in &all {
            store.put_image(named(n)).unwrap();
        }
        // What two interleaved writers left: a shorter document written over
        // the longer one in place, without truncating, so the old tail is still there.
        let path = root.join("images.json");
        let long = fs::read(&path).unwrap();
        let shorter = serde_json::to_vec_pretty(&store.images().unwrap()[..7]).unwrap();
        let mut torn = long.clone();
        torn[..shorter.len()].copy_from_slice(&shorter);
        assert!(torn.len() > shorter.len() && serde_json::from_slice::<Vec<Image>>(&torn).is_err());
        fs::write(&path, &torn).unwrap();

        // The index reads again, with what its first document held, and the damaged file is kept.
        assert_eq!(names(&store), all[..7]);
        let aside = corrupt_files(&root);
        assert_eq!(aside.len(), 1);
        assert_eq!(fs::read(&aside[0]).unwrap(), torn);
        assert!(serde_json::from_slice::<Vec<Image>>(&fs::read(&path).unwrap()).is_ok());
        // And it takes new images as before.
        store.put_image(named("after:1")).unwrap();
        assert_eq!(names(&store).len(), 8);
        assert_eq!(corrupt_files(&root).len(), 1);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_truncated_index_keeps_its_complete_records() {
        let root = scratch("truncated");
        let _ = fs::remove_dir_all(&root);
        let store = Store::open(&root).unwrap();
        for n in ["a:1", "b:1", "c:1"] {
            store.put_image(named(n)).unwrap();
        }
        let path = root.join("images.json");
        let bytes = fs::read(&path).unwrap();
        assert_eq!(store.index_damage().unwrap(), None, "no copy, no damage");
        fs::write(&path, &bytes[..bytes.len() - 40]).unwrap();
        // The image cut off is named while the copy is kept (#440), the
        // first time the index is read too, and is no longer missing once it
        // is back in the list.
        let damage = store.index_damage().unwrap().unwrap();
        assert_eq!(names(&store), ["a:1", "b:1"]);
        assert_eq!(corrupt_files(&root).len(), 1);
        assert_eq!((damage.copies, damage.missing), (corrupt_files(&root), vec!["c:1".to_owned()]));
        store.put_image(named("c:1")).unwrap();
        assert!(store.index_damage().unwrap().unwrap().missing.is_empty());
        for c in corrupt_files(&root) {
            fs::remove_file(c).unwrap();
        }
        assert_eq!(store.index_damage().unwrap(), None, "removing the copy ends it");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn record_names_are_the_records_own() {
        let bytes = serde_json::to_vec_pretty(&vec![named("a:1"), named("b:1"), named("c:1")]).unwrap();
        assert_eq!(record_names(&bytes), ["a:1", "b:1", "c:1"]);
        // A field inside a record that is called name too is not a record.
        assert_eq!(record_names(br#"[{"name": "a:1", "config": {"name": "no"}, "x": [1, {"y": 2}]}, {"name":"b:1"}]"#), ["a:1", "b:1"]);
        let compact = serde_json::to_vec(&vec![named("a:1"), named("b:1")]).unwrap();
        assert_eq!(record_names(&compact), ["a:1", "b:1"]);
        // Cut inside the last record, after its name: still named.
        let at = bytes.windows(9).rposition(|w| w == b"\"digest\":").unwrap();
        assert_eq!(missing(&bytes[..at], &[named("a:1")]), ["b:1", "c:1"]);
        // Cut inside the name itself: no half name.
        let at = bytes.windows(5).rposition(|w| w == b"c:1\",").unwrap() + 1;
        assert_eq!(record_names(&bytes[..at]), ["a:1", "b:1"]);
    }

    #[test]
    fn an_unreadable_index_starts_over_without_failing_requests() {
        let root = scratch("garbage");
        let _ = fs::remove_dir_all(&root);
        let store = Store::open(&root).unwrap();
        fs::write(root.join("images.json"), b"not json at all").unwrap();
        assert!(store.images().unwrap().is_empty());
        assert!(store.find("alpine:3.20").unwrap().is_none());
        assert_eq!(corrupt_files(&root).len(), 1);
        store.put_image(named("alpine:3.20")).unwrap();
        assert_eq!(names(&store), ["alpine:3.20"]);
        // A change that finds the damage first repairs it too.
        fs::write(root.join("images.json"), b"[{").unwrap();
        store.put_image(named("b:1")).unwrap();
        assert_eq!(names(&store), ["b:1"]);
        assert_eq!(corrupt_files(&root).len(), 2);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn concurrent_writes_all_land_and_leave_no_trailing_bytes() {
        let root = scratch("concurrent");
        let _ = fs::remove_dir_all(&root);
        Store::open(&root).unwrap();
        // Each writer has its own Store, as the daemon and the CLI do.
        let writers: Vec<_> = (0..16)
            .map(|t| {
                let root = root.clone();
                std::thread::spawn(move || {
                    let store = Store::open(&root).unwrap();
                    for i in 0..10_u32 {
                        store.put_image(named(&format!("t{t}/img:{i}"))).unwrap();
                        if i % 3 == 0 {
                            store
                                .remove_image(&format!("t{t}/img:{}", i.saturating_sub(1)))
                                .unwrap();
                        }
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap();
        }
        let bytes = fs::read(root.join("images.json")).unwrap();
        let images: Vec<Image> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(bytes, serde_json::to_vec_pretty(&images).unwrap());
        // Per writer: 10 added; at i = 0, 3, 6, 9 one is removed (img:0, 2, 5, 8).
        assert_eq!(images.len(), 16 * (10 - 4));
        assert!(corrupt_files(&root).is_empty());
        let stray: Vec<_> = fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(stray.is_empty(), "{stray:?}");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn repo_strips_a_tag_but_not_a_port() {
        let named = |name: &str| Image {
            name: name.into(),
            digest: String::new(),
            index_digest: None,
            config_digest: String::new(),
            layers: Vec::new(),
            size: 0,
            platform: String::new(),
            created: String::new(),
            pulled_at: 0,
            config: RunConfig::default(),
        };
        assert_eq!(named("alpine:latest").repo(), "alpine");
        assert_eq!(named("localhost:5000/app:1").repo(), "localhost:5000/app");
        assert_eq!(named("localhost:5000/app").repo(), "localhost:5000/app");
        assert_eq!(named(&format!("kindest/node@sha256:{}", "a".repeat(64))).repo(), "kindest/node");
    }
}

/// What a write cut short, a damaged blob or two writers at
/// once leave in the store, and what the store does about it.
#[cfg(test)]
mod integ_tests {
    use super::*;

    fn fresh(tag: &str) -> (PathBuf, Store) {
        let root = std::env::temp_dir().join(format!("kiri-integ-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let store = Store::open(&root).unwrap();
        (root, store)
    }

    fn put_blob(store: &Store, bytes: &[u8]) -> (String, u64) {
        let mut w = store.ingest().unwrap();
        w.write_all(bytes).unwrap();
        w.finish().unwrap()
    }

    fn image(store: &Store, name: &str, layers: &[(String, u64)]) -> Image {
        let (config, _) = put_blob(store, b"{\"rootfs\":{}}");
        Image {
            name: name.into(),
            digest: format!("sha256:{}", "1".repeat(64)),
            index_digest: None,
            config_digest: config,
            layers: layers.iter().map(|(d, s)| Layer { digest: d.clone(), size: *s, media_type: "application/vnd.oci.image.layer.v1.tar".into() }).collect(),
            size: 0,
            platform: "linux/amd64".into(),
            created: String::new(),
            pulled_at: 0,
            config: RunConfig::default(),
        }
    }

    fn names(store: &Store) -> Vec<String> {
        let mut n: Vec<String> = store.images().unwrap().into_iter().map(|i| i.name).collect();
        n.sort();
        n
    }

    fn flip(path: &Path) {
        let mut b = fs::read(path).unwrap();
        let mid = b.len() / 2;
        b[mid] ^= 0x40;
        fs::write(path, b).unwrap();
    }

    #[test]
    fn start_up_removes_what_a_write_cut_short_left() {
        let (root, store) = fresh("leftovers");
        let dead = 999_999_999u32;
        let left = [
            root.join("tmp").join(format!("ingest.{dead}.3")),
            root.join("tmp").join(format!("{}.{dead}.0", "a".repeat(64))),
            root.join(format!("images.json.{dead}.7.tmp")),
        ];
        for p in &left {
            fs::write(p, b"half").unwrap();
        }
        // An ingest of this process, still being written, is not a leftover.
        let mut live = store.ingest().unwrap();
        live.write_all(b"in flight").unwrap();
        let repairs = store.check().unwrap();
        for p in &left {
            assert!(!p.exists(), "{} is removed", p.display());
            assert!(repairs.iter().any(|r| r.contains(&p.file_name().unwrap().to_string_lossy().into_owned())), "{repairs:?} names {}", p.display());
        }
        live.write_all(b" still").unwrap();
        live.finish().unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn start_up_drops_an_image_whose_blob_is_missing_or_short() {
        let (root, store) = fresh("short");
        let a = put_blob(&store, &vec![7u8; 4096]);
        let b = put_blob(&store, &vec![8u8; 4096]);
        store.put_image(image(&store, "good:1", std::slice::from_ref(&a))).unwrap();
        store.put_image(image(&store, "short:1", &[a.clone(), b.clone()])).unwrap();
        store.put_image(image(&store, "gone:1", &[(format!("sha256:{}", "c".repeat(64)), 10)])).unwrap();
        let p = store.blob_path(&b.0).unwrap();
        let bytes = fs::read(&p).unwrap();
        fs::write(&p, &bytes[..100]).unwrap();
        let repairs = store.check().unwrap();
        assert_eq!(names(&store), ["good:1"]);
        assert!(!p.exists(), "the short blob is removed");
        assert!(store.has_blob(&a.0, a.1), "a whole blob is kept");
        for n in ["short:1", "gone:1", &b.0] {
            assert!(repairs.iter().any(|r| r.contains(n)), "{repairs:?} names {n}");
        }
        assert!(store.check().unwrap().is_empty(), "a second check finds nothing");
        fs::remove_dir_all(&root).unwrap();
    }

    /// A blob is judged by its own digest, never by the size an image's
    /// record gives it: an image recorded with a wrong size for a whole,
    /// shared blob (a manifest that lied, pulled by an older engine) costs
    /// neither the blob nor the other images naming it.
    #[test]
    fn start_up_judges_a_blob_by_its_digest_not_by_a_records_size() {
        let (root, store) = fresh("record-size");
        let a = put_blob(&store, &vec![9u8; 8192]);
        store.put_image(image(&store, "good:1", std::slice::from_ref(&a))).unwrap();
        store.put_image(image(&store, "liar:1", &[(a.0.clone(), a.1 + 5)])).unwrap();
        let repairs = store.check().unwrap();
        assert!(repairs.is_empty(), "{repairs:?}");
        assert_eq!(names(&store), ["good:1", "liar:1"]);
        assert_eq!(fs::read(store.blob_path(&a.0).unwrap()).unwrap(), vec![9u8; 8192], "the blob is untouched");
        // Without a stamp (written by an engine before stamps) the same.
        fs::remove_file(root.join("blobs/stamps")).unwrap();
        let again = Store::open(&root).unwrap();
        assert!(again.check().unwrap().is_empty());
        assert!(again.blob_path(&a.0).unwrap().exists());
        fs::remove_dir_all(&root).unwrap();
    }

    /// The start-up check reads a blob only when its stat differs from its
    /// stamp; a whole one is stamped again and kept, one never stamped is
    /// not read at all (its first use judges it).
    #[test]
    fn start_up_reads_only_blobs_changed_since_their_stamp() {
        let (root, store) = fresh("changed-only");
        let blobs: Vec<(String, u64)> = (0..3u8).map(|i| put_blob(&store, &vec![i; 20_000])).collect();
        store.put_image(image(&store, "three:1", &blobs)).unwrap();
        let again = Store::open(&root).unwrap();
        assert!(again.check().unwrap().is_empty());
        assert_eq!(again.blobs_hashed(), 0, "nothing changed: nothing read");
        let p = again.blob_path(&blobs[1].0).unwrap();
        fs::write(&p, fs::read(&p).unwrap()).unwrap();
        let again = Store::open(&root).unwrap();
        assert!(again.check().unwrap().is_empty(), "rewritten whole: kept");
        assert_eq!(again.blobs_hashed(), 1);
        let again = Store::open(&root).unwrap();
        assert!(again.check().unwrap().is_empty());
        assert_eq!(again.blobs_hashed(), 0, "stamped again");
        // Unstamped and damaged: left to its first use.
        fs::remove_file(root.join("blobs/stamps")).unwrap();
        flip(&p);
        let again = Store::open(&root).unwrap();
        assert!(again.check().unwrap().is_empty());
        assert_eq!(again.blobs_hashed(), 0);
        assert!(p.exists());
        fs::remove_dir_all(&root).unwrap();
    }

    /// A diff_id is recorded only on a blob stamped whole and unchanged,
    /// and is forgotten once the blob changes.
    #[test]
    fn a_diff_id_is_kept_only_with_a_stamp_that_still_matches() {
        let (root, store) = fresh("diffids");
        let a = put_blob(&store, b"layer bytes");
        let d = format!("sha256:{}", "d".repeat(64));
        let ids = store.diff_ids();
        assert_eq!(ids.get(&a.0), None);
        ids.record(&a.0, &d);
        assert_eq!(ids.get(&a.0).as_deref(), Some(d.as_str()));
        assert_eq!(Store::open(&root).unwrap().diff_ids().get(&a.0).as_deref(), Some(d.as_str()), "kept across starts");
        let p = store.blob_path(&a.0).unwrap();
        fs::write(&p, b"layer bytes").unwrap();
        assert_eq!(ids.get(&a.0), None, "the blob changed");
        ids.record(&a.0, &d);
        assert_eq!(ids.get(&a.0), None, "no stamp is made by a record");
        fs::remove_dir_all(&root).unwrap();
    }

    /// With the builder switched off the store does what it did before the
    /// builder: presence and size, nothing read, nothing removed.
    #[test]
    fn without_native_checks_a_blob_is_present_by_its_size() {
        let (root, store) = fresh("off");
        let a = put_blob(&store, &vec![1u8; 100_000]);
        store.put_image(image(&store, "kept:1", std::slice::from_ref(&a))).unwrap();
        flip(&store.blob_path(&a.0).unwrap());
        assert!(store.has_blob(&a.0, a.1));
        assert!(!store.has_blob(&a.0, a.1 + 1));
        assert_eq!(store.verified_blob_path(&a.0).unwrap(), store.blob_path(&a.0).unwrap());
        assert_eq!(store.blobs_hashed(), 0);
        assert_eq!(names(&store), ["kept:1"]);
        fs::remove_dir_all(&root).unwrap();
    }

    /// Flipped bytes are found on use; at start-up too, the blob's stat
    /// having moved since its stamp.
    #[test]
    fn a_blob_with_flipped_bytes_is_found_on_use_and_removed() {
        let (root, store) = fresh("flip");
        store.use_native_checks();
        let a = put_blob(&store, &vec![1u8; 100_000]);
        let b = put_blob(&store, &vec![2u8; 100_000]);
        store.put_image(image(&store, "hurt:1", &[a.clone(), b.clone()])).unwrap();
        store.put_image(image(&store, "fine:1", std::slice::from_ref(&b))).unwrap();
        flip(&store.blob_path(&a.0).unwrap());
        // Its stat moved since its stamp, so the start check reads it.
        let repairs = store.check().unwrap();
        assert!(repairs.iter().any(|r| r.contains(&a.0) && r.contains("hashes to")), "{repairs:?}");
        assert!(!store.has_blob(&a.0, a.1), "a damaged blob is never present");
        assert!(!store.blob_path(&a.0).unwrap().exists(), "and is removed");
        assert_eq!(names(&store), ["fine:1"], "images naming it are dropped");
        assert!(store.has_blob(&b.0, b.1));
        // Written again whole, it is a blob again.
        put_blob(&store, &vec![1u8; 100_000]);
        assert!(store.has_blob(&a.0, a.1));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_verified_blob_is_not_read_again_until_it_changes() {
        let (root, store) = fresh("stamps");
        store.use_native_checks();
        let a = put_blob(&store, &vec![3u8; 50_000]);
        for _ in 0..3 {
            assert!(store.has_blob(&a.0, a.1));
        }
        assert_eq!(store.blobs_hashed(), 0, "written here: its stamp says it was verified");
        // A new process trusts the stamp too.
        let again = Store::open(&root).unwrap();
        again.use_native_checks();
        assert!(again.has_blob(&a.0, a.1));
        assert_eq!(again.blobs_hashed(), 0);
        // Rewritten with the same bytes: ctime moved, so it is read again, once.
        let p = again.blob_path(&a.0).unwrap();
        fs::write(&p, fs::read(&p).unwrap()).unwrap();
        assert!(again.has_blob(&a.0, a.1));
        assert!(again.has_blob(&a.0, a.1));
        assert_eq!(again.blobs_hashed(), 1);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_damaged_stamp_file_only_costs_a_hash() {
        let (root, store) = fresh("stamp-damage");
        store.use_native_checks();
        let a = put_blob(&store, &vec![4u8; 50_000]);
        let stamps = root.join("blobs/stamps");
        let mut text = fs::read(&stamps).unwrap();
        let mid = text.len() / 2;
        text[mid] ^= 1;
        text.extend_from_slice(b"garbage line\nsha256 half");
        fs::write(&stamps, text).unwrap();
        let again = Store::open(&root).unwrap();
        again.use_native_checks();
        assert!(again.has_blob(&a.0, a.1));
        assert_eq!(again.blobs_hashed(), 1);
        fs::remove_dir_all(&root).unwrap();
    }

    /// A blob whose stat fails for any reason but "not there" keeps its
    /// image and its unpacked tar: a link that loops is one such error
    /// that stops root too.
    #[test]
    fn start_up_keeps_an_image_whose_blob_cannot_be_looked_at() {
        let (root, store) = fresh("statloop");
        let a = put_blob(&store, &vec![5u8; 4096]);
        store.put_image(image(&store, "kept:1", std::slice::from_ref(&a))).unwrap();
        let p = store.blob_path(&a.0).unwrap();
        let tar = store.layer_tar_path(&a.0).unwrap();
        fs::create_dir_all(tar.parent().unwrap()).unwrap();
        fs::write(&tar, b"unpacked").unwrap();
        fs::remove_file(&p).unwrap();
        std::os::unix::fs::symlink(&p, &p).unwrap();
        let repairs = store.check().unwrap();
        assert_eq!(names(&store), ["kept:1"], "{repairs:?}");
        assert!(tar.exists(), "the unpacked tar is kept");
        assert!(fs::symlink_metadata(&p).is_ok(), "the blob is left alone");
        fs::remove_dir_all(&root).unwrap();
    }

    /// A blob folder the engine may not read (permissions) drops nothing.
    /// Root reads through any mode, so as root this cannot be shown.
    #[test]
    fn start_up_keeps_images_when_the_blob_folder_is_unreadable() {
        use std::os::unix::fs::PermissionsExt;
        if crate::proc::is_root() {
            println!("skipped: running as root, whom a mode-000 folder does not stop");
            return;
        }
        let (root, store) = fresh("statperm");
        let a = put_blob(&store, &vec![6u8; 4096]);
        store.put_image(image(&store, "kept:1", std::slice::from_ref(&a))).unwrap();
        let tar = store.layer_tar_path(&a.0).unwrap();
        fs::create_dir_all(tar.parent().unwrap()).unwrap();
        fs::write(&tar, b"unpacked").unwrap();
        let blobs = root.join("blobs/sha256");
        fs::set_permissions(&blobs, fs::Permissions::from_mode(0o000)).unwrap();
        let repairs = store.check();
        fs::set_permissions(&blobs, fs::Permissions::from_mode(0o755)).unwrap();
        let repairs = repairs.unwrap();
        assert_eq!(names(&store), ["kept:1"], "{repairs:?}");
        assert!(tar.exists(), "the unpacked tar is kept");
        assert!(store.has_blob(&a.0, a.1), "the blob is kept");
        fs::remove_dir_all(&root).unwrap();
    }

    /// A leftover of a process that is gone is found on every host, also
    /// where there is no /proc.
    #[test]
    fn a_leftover_of_a_live_process_is_kept() {
        let (root, _store) = fresh("liveleft");
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let name = format!("ingest.{}.3", child.id());
        let q = root.join("tmp").join(&name);
        fs::write(&q, b"half").unwrap();
        assert!(!leftover(&name, &q), "a live writer's file is not a leftover");
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(leftover(&name, &q), "once the writer is gone it is");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn writers_of_the_same_blob_at_once_leave_it_whole() {
        let (root, store) = fresh("same");
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
        let got: Vec<(String, u64)> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..8).map(|_| s.spawn(|| put_blob(&store, &data))).collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(got.windows(2).all(|w| w[0] == w[1]));
        assert!(store.has_blob(&got[0].0, got[0].1));
        assert_eq!(fs::read(store.blob_path(&got[0].0).unwrap()).unwrap(), data);
        assert_eq!(fs::read_dir(root.join("tmp")).unwrap().count(), 0);
        fs::remove_dir_all(&root).unwrap();
    }

    /// The kill tests run the write in a child process (this test binary
    /// again, one test selected) that dies at the kill point.
    #[cfg(feature = "fault-inject")]
    mod kill_points {
        use super::*;
        use std::process::Command;

        const CHILD: &str = "KIRI_TEST_STORE_CHILD";

        fn in_child(root: &Path, test: &str, point: &str) {
            let st = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &format!("store::integ_tests::kill_points::{test}"), "--test-threads=1"])
                .env(CHILD, root)
                .env("KIRI_TEST_FAULT", point)
                .status()
                .unwrap();
            // Killed by the point, not ended by a panic or by running through.
            assert_eq!(std::os::unix::process::ExitStatusExt::signal(&st), Some(6), "the child died at {point}: {st}");
        }

        #[test]
        fn child_writes_a_blob_and_an_image() {
            let Some(root) = std::env::var_os(CHILD) else { return };
            let store = Store::open(PathBuf::from(root)).unwrap();
            let b = put_blob(&store, &vec![9u8; 200_000]);
            store.put_image(image(&store, "new:1", &[b])).unwrap();
            unreachable!("the kill point was not reached");
        }

        #[test]
        fn a_kill_at_any_point_of_a_commit_leaves_a_whole_store() {
            if std::env::var_os(CHILD).is_some() {
                return;
            }
            let want = sha256_digest(&vec![9u8; 200_000]);
            for point in ["blob-tmp", "blob-renamed", "index-tmp", "index-renamed"] {
                let (root, store) = fresh(&format!("kill-{point}"));
                let old = put_blob(&store, b"old layer");
                store.put_image(image(&store, "old:1", &[old])).unwrap();
                in_child(&root, "child_writes_a_blob_and_an_image", point);
                let store = Store::open(&root).unwrap();
                store.check().unwrap();
                assert_eq!(fs::read_dir(root.join("tmp")).unwrap().count(), 0, "{point}: tmp is empty");
                let leftovers: Vec<_> = fs::read_dir(&root).unwrap().map(|e| e.unwrap().file_name()).filter(|n| n.to_string_lossy().ends_with(".tmp")).collect();
                assert!(leftovers.is_empty(), "{point}: {leftovers:?}");
                let p = store.blob_path(&want).unwrap();
                if p.exists() {
                    assert_eq!(sha256_digest(&fs::read(&p).unwrap()), want, "{point}: a blob under its name is whole");
                }
                let n = names(&store);
                assert!(n == ["old:1"] || n == ["new:1", "old:1"], "{point}: {n:?}");
                if n.len() == 2 {
                    assert!(store.has_blob(&want, 200_000), "{point}: a recorded image has its blob");
                }
                fs::remove_dir_all(&root).unwrap();
            }
        }
    }
}
