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
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::SystemTime;

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
    /// The Docker Hub mirror (`host[:port]`) a pull took the image from,
    /// when it did not come from the registry its name says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror: Option<String>,
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

    /// Every blob digest this image record owns in the store: its config,
    /// its layers, and (when pulled from a registry) its raw manifest and
    /// multi-arch index blobs so Kiri's build mirror can serve exact
    /// digest-verified bytes.
    pub fn referenced_digests(&self) -> impl Iterator<Item = &str> {
        let manifest = (self.digest != self.config_digest).then_some(self.digest.as_str());
        std::iter::once(self.config_digest.as_str())
            .chain(manifest)
            .chain(self.index_digest.as_deref())
            .chain(self.layers.iter().map(|l| l.digest.as_str()))
    }
}

/// Identifies one on-disk version of `images.json`: `(mtime, len, ino)`.
type IndexStamp = (SystemTime, u64, u64);

fn stamp_of(m: &fs::Metadata) -> IndexStamp {
    #[cfg(unix)]
    let ino = std::os::unix::fs::MetadataExt::ino(m);
    #[cfg(not(unix))]
    let ino = 0;
    (m.modified().unwrap_or(SystemTime::UNIX_EPOCH), m.len(), ino)
}

#[derive(Debug)]
pub struct Store {
    root: PathBuf,
    index_cache: Mutex<Option<(Option<IndexStamp>, Arc<Vec<Image>>)>>,
}

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Serializes index changes between the threads of this process; the lock
/// file does it between processes (the CLI opens the store too).
static INDEX_LOCK: Mutex<()> = Mutex::new(());

/// Taken around a blob's rename into place by a writer that holds it
/// ([`BlobWriter::finish_pinned`], [`Ingest::finish_pinned`]), around taking a
/// hold ([`Store::pin`], [`Store::pin_existing`], [`Store::hold_image`]), and
/// around a removal's check of the holds and its delete, so none of them ever
/// interleave.
static BLOB_LOCK: Mutex<()> = Mutex::new(());

/// Blobs something in this process is using that an image's removal must
/// not delete (a save or a push still sending them, a load until its images
/// are recorded), by path, with how many hold each. One table for the
/// process, so every `Store` of one folder shares it.
static PINNED: Mutex<std::collections::BTreeMap<PathBuf, usize>> = Mutex::new(std::collections::BTreeMap::new());

/// A blob kept from deletion until this is dropped ([`Store::pin`]).
#[derive(Debug)]
pub struct Pin(Option<PathBuf>);

impl Pin {
    fn take(path: PathBuf) -> Pin {
        *PINNED.lock().unwrap_or_else(|e| e.into_inner()).entry(path.clone()).or_insert(0) += 1;
        Pin(Some(path))
    }
}

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

/// [`Index`] paired with the file stamp read from the same file descriptor.
enum StampedIndex {
    Valid(Option<IndexStamp>, Vec<Image>),
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
    /// The data directory: `KIRI_DATA_DIR` if set, else the folder chosen
    /// in Settings → Storage (`~/.kiri/storage.json`, see
    /// [`crate::storage`]), else [`Store::os_default_root`]. A chosen folder
    /// without its marker (a drive that isn't connected) is an error that
    /// [`crate::storage::unavailable`] recognises, never a fresh folder.
    pub fn default_root() -> io::Result<PathBuf> {
        if let Some(dir) = std::env::var_os("KIRI_DATA_DIR") {
            return Ok(PathBuf::from(dir));
        }
        crate::storage::resolve(crate::storage::read()?, Self::os_default_root()?)
    }

    /// The per-user data directory when nothing else is chosen:
    /// `~/Library/Application Support/Kiri` on macOS, `$XDG_DATA_HOME/kiri`
    /// (or `~/.local/share/kiri`) elsewhere.
    pub fn os_default_root() -> io::Result<PathBuf> {
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
        let blobs = root.join("blobs/sha256");
        if !blobs.is_dir() {
            fs::create_dir_all(blobs)?;
        }
        let tmp = root.join("tmp");
        if !tmp.is_dir() {
            fs::create_dir_all(tmp)?;
        }
        Ok(Store {
            root,
            index_cache: Mutex::new(None),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// An image config, read whole for parsing. Configs are small JSON; a
    /// registry could serve a huge blob under that name, so anything over
    /// `MAX_CONFIG` is refused rather than loaded into memory.
    pub fn read_config(&self, digest: &str) -> std::io::Result<Vec<u8>> {
        let _pin = self.pin(digest);
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

    /// True if the blob is present with the expected size. Blobs are only
    /// renamed into place after their digest was verified, so presence is proof.
    pub fn has_blob(&self, digest: &str, size: u64) -> bool {
        self.blob_path(digest).is_ok_and(|p| blob_ready(&p, size))
    }

    pub fn blob_writer(&self, digest: &str) -> io::Result<BlobWriter> {
        let tmp = self.root.join("tmp").join(format!("{}.{}.{}", digest_hex(digest)?, std::process::id(), TMP_SEQ.fetch_add(1, Ordering::Relaxed)));
        Ok(BlobWriter {
            file: io::BufWriter::with_capacity(BLOB_WRITE_BUF, File::create(&tmp)?),
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
        Ok(Ingest {
            file: io::BufWriter::with_capacity(BLOB_WRITE_BUF, File::create(&tmp)?),
            hasher: Sha256::new(),
            tmp,
            root: self.root.clone(),
            written: 0,
        })
    }

    /// The image index, shared via `Arc` from an mtime/size/inode-validated
    /// in-memory cache so repeated reads (`/info`, `/images/json`) avoid
    /// re-reading and re-parsing `images.json` when unchanged.
    pub fn images_arc(&self) -> io::Result<Arc<Vec<Image>>> {
        let path = self.root.join("images.json");
        let stamp = match fs::metadata(&path) {
            Ok(m) => Some(stamp_of(&m)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        if let Some((cached_stamp, cached)) = self.index_cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref()
            && *cached_stamp == stamp
        {
            return Ok(Arc::clone(cached));
        }
        match self.read_index_stamped()? {
            StampedIndex::Valid(read_stamp, images) => {
                let arc = Arc::new(images);
                *self.index_cache.lock().unwrap_or_else(|e| e.into_inner()) = Some((read_stamp, Arc::clone(&arc)));
                Ok(arc)
            }
            StampedIndex::Corrupt(..) => {
                *self.index_cache.lock().unwrap_or_else(|e| e.into_inner()) = None;
                let _lock = self.lock_index()?;
                let images = self.read_locked()?;
                let arc = Arc::new(images);
                let new_stamp = fs::metadata(&path).ok().map(|m| stamp_of(&m));
                *self.index_cache.lock().unwrap_or_else(|e| e.into_inner()) = Some((new_stamp, Arc::clone(&arc)));
                Ok(arc)
            }
        }
    }

    /// Number of images in the index without cloning image entries.
    pub fn image_count(&self) -> io::Result<usize> {
        Ok(self.images_arc()?.len())
    }

    /// The image index. One that does not parse is repaired first, see
    /// [`Store::recover`], rather than failing every caller from then on.
    pub fn images(&self) -> io::Result<Vec<Image>> {
        Ok((*self.images_arc()?).clone())
    }

    /// Reads the image index under the in-process index lock and passes it to
    /// `f`, so `f` can pin blobs ([`Store::pin`], [`Store::hold_image`])
    /// atomically before a concurrent [`Store::put_image`] or
    /// [`Store::remove_image`] can replace the index and delete them.
    /// `f` must not call methods that re-acquire the index lock.
    pub fn with_images<T>(&self, f: impl FnOnce(&[Image]) -> T) -> io::Result<T> {
        let guard = INDEX_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = self.root.join("images.json");
        let stamp = match fs::metadata(&path) {
            Ok(m) => Some(stamp_of(&m)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        if let Some((cached_stamp, cached)) = self.index_cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref()
            && *cached_stamp == stamp
        {
            let arc = Arc::clone(cached);
            return Ok(f(&arc));
        }
        let images = match self.read_index_stamped()? {
            StampedIndex::Valid(read_stamp, images) => {
                let arc = Arc::new(images);
                *self.index_cache.lock().unwrap_or_else(|e| e.into_inner()) = Some((read_stamp, Arc::clone(&arc)));
                arc
            }
            StampedIndex::Corrupt(..) => {
                *self.index_cache.lock().unwrap_or_else(|e| e.into_inner()) = None;
                drop(guard);
                let _lock = self.lock_index()?;
                let images = self.read_locked()?;
                return Ok(f(&images));
            }
        };
        Ok(f(&images))
    }

    fn read_index_stamped(&self) -> io::Result<StampedIndex> {
        let path = self.root.join("images.json");
        let mut file = match File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(StampedIndex::Valid(None, Vec::new())),
            Err(e) => return Err(e),
        };
        let stamp = Some(stamp_of(&file.metadata()?));
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(match serde_json::from_slice(&bytes) {
            Ok(images) => StampedIndex::Valid(stamp, images),
            Err(e) => StampedIndex::Corrupt(bytes, e),
        })
    }

    fn read_index(&self) -> io::Result<Index> {
        match self.read_index_stamped()? {
            StampedIndex::Valid(_, images) => Ok(Index::Valid(images)),
            StampedIndex::Corrupt(bytes, e) => Ok(Index::Corrupt(bytes, e)),
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
        let images = self.images_arc()?;
        Ok(images.iter().find(|i| i.name == name || i.digest == name || r.as_ref().is_some_and(|r| i.matches(r))).cloned())
    }

    /// As [`Store::find`], holding every blob the found image references
    /// ([`Store::hold_image`]) before releasing the index lock so a concurrent
    /// tag replacement or removal cannot delete them in between.
    pub fn find_pinned(&self, name: &str) -> io::Result<Option<(Image, Vec<Pin>)>> {
        let r = Reference::parse(name).ok();
        self.with_images(|images| {
            let found = images
                .iter()
                .find(|i| i.name == name || i.digest == name || r.as_ref().is_some_and(|r| i.matches(r)))
                .cloned()?;
            let pins = self.hold_image(&found);
            Some((found, pins))
        })
    }

    /// Adds `image`, replacing any image with the same name. The blobs only
    /// the replaced image used go, as [`Store::remove_image`] deletes them:
    /// nothing would name them any more (#864).
    pub fn put_image(&self, image: Image) -> io::Result<()> {
        self.put_images(vec![image])
    }

    /// Adds every image in `new_images` in a single atomic index rewrite so
    /// multi-image `docker load` archives pay one index lock + fsync instead of N.
    pub fn put_images(&self, new_images: Vec<Image>) -> io::Result<()> {
        if new_images.is_empty() {
            return Ok(());
        }
        let _lock = self.lock_index()?;
        let mut images = self.read_locked()?;
        let mut replaced = Vec::new();
        for image in new_images {
            let mut i = 0;
            while i < images.len() {
                if images[i].name == image.name {
                    replaced.push(images.remove(i));
                } else {
                    i += 1;
                }
            }
            images.push(image);
        }
        self.write_index(&images)?;
        for old in &replaced {
            self.remove_unused_blobs(old, &images);
        }
        Ok(())
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
    /// then check the blob is there: taking the blob lock serialises the pin
    /// with [`Store::remove_unpinned`] so a deletion already past its check
    /// finishes before this returns.
    pub fn pin(&self, digest: &str) -> Pin {
        match self.blob_path(digest) {
            Ok(p) => {
                let _one = BLOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                Pin::take(p)
            }
            Err(_) => Pin(None),
        }
    }

    /// Keeps the blob `digest` from deletion if it is already on disk with
    /// `size` bytes. The presence check and the hold both run under the blob
    /// lock so a concurrent [`Store::put_image`] or [`Store::remove_image`]
    /// cannot delete the blob in between.
    pub fn pin_existing(&self, digest: &str, size: u64) -> Option<Pin> {
        let path = self.blob_path(digest).ok()?;
        let _one = BLOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        blob_ready(&path, size).then(|| Pin::take(path))
    }

    /// Keeps every blob `image` references (config, raw manifest, multi-arch
    /// index, and layers) from deletion until the returned pins are dropped.
    pub fn hold_image(&self, image: &Image) -> Vec<Pin> {
        let _one = BLOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        image.referenced_digests().filter_map(|d| self.blob_path(d).ok()).map(Pin::take).collect()
    }

    /// Removes the image and deletes blobs no remaining image uses and
    /// nothing holds ([`Store::pin`]).
    pub fn remove_image(&self, name: &str) -> io::Result<Option<Image>> {
        let _lock = self.lock_index()?;
        let mut images = self.read_locked()?;
        let Some(pos) = images.iter().position(|i| i.name == name) else { return Ok(None) };
        let removed = images.remove(pos);
        self.write_index(&images)?;
        self.remove_unused_blobs(&removed, &images);
        Ok(Some(removed))
    }

    /// Deletes the blobs of `gone` that no image in `images` uses and
    /// nothing holds ([`Store::pin`]). Called with the index lock held,
    /// once `images` is written.
    fn remove_unused_blobs(&self, gone: &Image, images: &[Image]) {
        let in_use = |d: &str| images.iter().any(|i| i.referenced_digests().any(|r| r == d));
        for d in gone.referenced_digests() {
            if !in_use(d) {
                self.remove_unpinned(d);
            }
        }
    }

    /// Deletes the blob `digest` if no image uses it and nothing holds it,
    /// as [`Store::remove_image`] deletes the blobs it frees: for a writer
    /// that put a blob in that nothing came to name.
    pub fn remove_if_unused(&self, digest: &str) -> io::Result<()> {
        let _lock = self.lock_index()?;
        let images = self.read_locked()?;
        if !images.iter().any(|i| i.referenced_digests().any(|r| r == digest)) {
            self.remove_unpinned(digest);
        }
        Ok(())
    }

    /// The hold check and the delete under the blob lock, which a writer's
    /// pin and rename take too ([`Ingest::finish_pinned`]): a blob written
    /// or found again by a writer between the two is never deleted.
    fn remove_unpinned(&self, digest: &str) {
        let Ok(path) = self.blob_path(digest) else { return };
        let _one = BLOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !pinned(&path) {
            let _ = fs::remove_file(path);
        }
    }

    /// Replaces the index with `images`, see [`crate::jsonfile::replace`].
    /// Callers hold the index lock.
    fn write_index(&self, images: &[Image]) -> io::Result<()> {
        let path = self.root.join("images.json");
        let bytes = serde_json::to_vec_pretty(images).map_err(io::Error::other)?;
        crate::jsonfile::replace(&path, &bytes, crate::jsonfile::Durable::Now)?;
        let stamp = fs::metadata(&path).ok().map(|m| stamp_of(&m));
        *self.index_cache.lock().unwrap_or_else(|e| e.into_inner()) = stamp.map(|s| (Some(s), Arc::new(images.to_vec())));
        Ok(())
    }
}

const BLOB_WRITE_BUF: usize = 128 << 10;

/// Writes a blob to a temporary file, hashing as it goes, and only moves it
/// into the store if the digest matches.
#[derive(Debug)]
pub struct BlobWriter {
    file: io::BufWriter<File>,
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
    pub fn finish(self) -> io::Result<u64> {
        let written = self.written;
        self.finish_pinned()?;
        Ok(written)
    }

    /// As [`BlobWriter::finish`], holding the blob ([`Store::pin`]) from before
    /// it is in place: a concurrent removal or tag replacement cannot delete it
    /// between the rename and the caller recording an image that names it.
    pub fn finish_pinned(mut self) -> io::Result<Pin> {
        let actual = format!("sha256:{}", hex(&std::mem::take(&mut self.hasher).finalize()));
        if actual != self.expected {
            let _ = fs::remove_file(&self.tmp);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("digest mismatch: expected {}, got {actual}", self.expected),
            ));
        }
        self.file.flush()?;
        self.file.get_ref().sync_all()?;
        let _one = BLOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let pin = Pin::take(self.dest.clone());
        if blob_ready(&self.dest, self.written) {
            let _ = fs::remove_file(&self.tmp);
            return Ok(pin);
        }
        fs::rename(&self.tmp, &self.dest)?;
        Ok(pin)
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
    file: io::BufWriter<File>,
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

fn blob_ready(dest: &Path, expected_size: u64) -> bool {
    fs::symlink_metadata(dest).is_ok_and(|m| m.is_file() && m.len() == expected_size)
}

impl Ingest {
    /// Publishes the blob under its digest. Returns (digest, size).
    pub fn finish(mut self) -> io::Result<(String, u64)> {
        let hex = hex(&std::mem::take(&mut self.hasher).finalize());
        let dest = self.root.join("blobs/sha256").join(&hex);
        if blob_ready(&dest, self.written) {
            let _ = fs::remove_file(&self.tmp);
            return Ok((format!("sha256:{hex}"), self.written));
        }
        self.file.flush()?;
        self.file.get_ref().sync_all()?;
        fs::rename(&self.tmp, dest)?;
        Ok((format!("sha256:{hex}"), self.written))
    }

    /// As [`Ingest::finish`], the blob held ([`Store::pin`]) from before
    /// it is in place: a removal of the last image using a blob of the same
    /// digest cannot delete it between the rename and the writer recording
    /// an image that names it (`docker load`).
    pub fn finish_pinned(mut self) -> io::Result<(String, u64, Pin)> {
        let hex = hex(&std::mem::take(&mut self.hasher).finalize());
        let dest = self.root.join("blobs/sha256").join(&hex);
        let _one = BLOB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let pin = Pin::take(dest.clone());
        if blob_ready(&dest, self.written) {
            let _ = fs::remove_file(&self.tmp);
            return Ok((format!("sha256:{hex}"), self.written, pin));
        }
        self.file.flush()?;
        self.file.get_ref().sync_all()?;
        fs::rename(&self.tmp, &dest)?;
        Ok((format!("sha256:{hex}"), self.written, pin))
    }
}

impl Drop for Ingest {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.tmp);
    }
}

/// Hashes every byte of `r` with SHA-256, returning `(digest, bytes_read)`.
pub fn hash_stream(mut r: impl io::Read) -> io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((format!("sha256:{}", hex(&hasher.finalize())), total))
}

pub fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(bytes)))
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

    /// A blob something still uses (a save, a push, a load not yet
    /// recorded) outlives the removal of the image that named it.
    #[test]
    fn a_pinned_blob_outlives_the_removal_of_its_image() {
        let root = std::env::temp_dir().join(format!("kiri-store-pin-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let store = Store::open(&root).unwrap();
        let mut ingest = store.ingest().unwrap();
        ingest.write_all(b"a layer a save is sending").unwrap();
        let (layer, size) = ingest.finish().unwrap();
        let image = |name: &str| Image { mirror: None,
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
        assert!(store.has_blob(&layer, size), "something still holds it");
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

        let image = Image { mirror: None,
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
        let image = Image { mirror: None,
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
    fn removes_raw_manifest_and_index_blobs_when_no_image_references_them() {
        let root = std::env::temp_dir().join(format!("kiri-store-raw-manifest-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let store = Store::open(&root).unwrap();
        let put = |bytes: &[u8]| {
            let mut w = store.ingest().unwrap();
            w.write_all(bytes).unwrap();
            w.finish().unwrap()
        };
        let (cfg, cfg_sz) = put(b"{\"os\":\"linux\",\"architecture\":\"amd64\"}");
        let (man, man_sz) = put(b"{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\"}");
        let (idx, idx_sz) = put(b"{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\"}");
        let img = |name: &str| Image {
            name: name.into(),
            digest: man.clone(),
            index_digest: Some(idx.clone()),
            config_digest: cfg.clone(),
            layers: Vec::new(),
            size: 0,
            platform: "linux/amd64".into(),
            created: String::new(),
            pulled_at: 0,
            config: RunConfig::default(),
            mirror: None,
        };
        store.put_image(img("app:1")).unwrap();
        store.put_image(img("app:latest")).unwrap();
        store.remove_image("app:1").unwrap();
        assert!(store.has_blob(&cfg, cfg_sz) && store.has_blob(&man, man_sz) && store.has_blob(&idx, idx_sz), "second tag still holds all blobs");
        store.remove_image("app:latest").unwrap();
        assert!(!store.has_blob(&cfg, cfg_sz) && !store.has_blob(&man, man_sz) && !store.has_blob(&idx, idx_sz), "last tag frees raw manifest and index blobs");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_push_leaves_the_registry_manifest_in_repo_digests() {
        let root = std::env::temp_dir().join(format!("kiri-store-push-test-{}", std::process::id()));
        let store = Store::open(&root).unwrap();
        let d = |c: &str| format!("sha256:{}", c.repeat(64));
        let image = |name: &str, config: &str, index: Option<String>| Image { mirror: None,
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
        Image { mirror: None,
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
        let named = |name: &str| Image { mirror: None,
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

    #[test]
    fn ingest_skips_rewrite_only_when_existing_blob_matches_size() {
        let root = scratch("ingest-skip");
        let _ = fs::remove_dir_all(&root);
        let store = Store::open(&root).unwrap();
        let data = b"hello content addressed store";
        let mut w = store.ingest().unwrap();
        w.write_all(data).unwrap();
        let (digest, size) = w.finish().unwrap();
        let path = store.blob_path(&digest).unwrap();
        assert_eq!(size, data.len() as u64);

        // Existing matching file: finish_pinned keeps it without replacing it.
        let mut w2 = store.ingest().unwrap();
        w2.write_all(data).unwrap();
        let (d2, s2, _pin) = w2.finish_pinned().unwrap();
        assert_eq!((d2, s2), (digest.clone(), size));
        assert_eq!(fs::read(&path).unwrap(), data);

        // Truncated/corrupted blob of wrong size on disk is repaired by rename.
        fs::write(&path, b"short").unwrap();
        let mut w3 = store.ingest().unwrap();
        w3.write_all(data).unwrap();
        w3.finish().unwrap();
        assert_eq!(fs::read(&path).unwrap(), data);

        fs::remove_dir_all(&root).unwrap();
    }

    /// An image put under a name another image had (a commit, build, pull,
    /// load or tag onto it) takes that image's place, and the blobs only the
    /// old one used go as `remove_image` would delete them. Before, they
    /// stayed with no image naming them and nothing could remove them (#864).
    #[test]
    fn an_image_put_under_a_taken_name_frees_the_blobs_only_the_old_one_used() {
        let root = scratch("replace");
        let _ = fs::remove_dir_all(&root);
        let store = Store::open(&root).unwrap();
        let put = |bytes: &[u8]| {
            let mut w = store.ingest().unwrap();
            w.write_all(bytes).unwrap();
            w.finish().unwrap()
        };
        let layer = |(digest, size): &(String, u64)| Layer { digest: digest.clone(), size: *size, media_type: "application/vnd.oci.image.layer.v1.tar".into() };
        let (shared, old_layer, new_layer) = (put(b"base layer"), put(b"layer of the first build"), put(b"layer of the second build"));
        let (old_cfg, new_cfg) = (put(b"{\"created\":\"first\"}"), put(b"{\"created\":\"second\"}"));
        let (old_man, old_idx) = (put(b"{\"schemaVersion\":2,\"first\":true}"), put(b"{\"schemaVersion\":2,\"manifests\":[]}"));
        let pinned_layer = put(b"layer a save or pull is still using");
        let img = |name: &str, cfg: &(String, u64), manifest: Option<&(String, u64)>, index: Option<&(String, u64)>, layers: &[&(String, u64)]| Image {
            name: name.into(),
            digest: manifest.map_or_else(|| cfg.0.clone(), |m| m.0.clone()),
            index_digest: index.map(|i| i.0.clone()),
            config_digest: cfg.0.clone(),
            layers: layers.iter().map(|l| layer(l)).collect(),
            size: 0,
            platform: "linux/amd64".into(),
            created: String::new(),
            pulled_at: 0,
            config: RunConfig::default(),
            mirror: None,
        };
        let has = |(digest, size): &(String, u64)| store.has_blob(digest, *size);

        // The old image under a second name keeps all its blobs.
        store.put_image(img("app:latest", &old_cfg, Some(&old_man), Some(&old_idx), &[&shared, &old_layer])).unwrap();
        store.put_image(img("app:v1", &old_cfg, Some(&old_man), Some(&old_idx), &[&shared, &old_layer])).unwrap();
        store.put_image(img("app:latest", &new_cfg, None, None, &[&shared, &new_layer])).unwrap();
        assert!(has(&old_cfg) && has(&old_man) && has(&old_idx) && has(&old_layer), "app:v1 still names the old image");

        // Its last name taken: its own config, manifest, index and layer go;
        // the shared layer and the new image's blobs stay.
        store.put_image(img("app:v1", &new_cfg, None, None, &[&shared, &new_layer])).unwrap();
        assert!(!has(&old_cfg) && !has(&old_man) && !has(&old_idx) && !has(&old_layer), "nothing names the old image's blobs any more");
        assert!(has(&shared) && has(&new_cfg) && has(&new_layer), "the new image uses these");

        // Putting the exact same image again under its own name deletes nothing.
        store.put_image(img("app:v1", &new_cfg, None, None, &[&shared, &new_layer])).unwrap();
        assert!(has(&shared) && has(&new_cfg) && has(&new_layer));

        // A blob something still holds outlives the replacement.
        let held_cfg = put(b"{\"created\":\"held\"}");
        store.put_image(img("held:1", &held_cfg, None, None, &[&pinned_layer])).unwrap();
        let pin = store.pin(&pinned_layer.0);
        store.put_image(img("held:1", &new_cfg, None, None, &[&new_layer])).unwrap();
        assert!(has(&pinned_layer), "a pin still holds it");
        assert!(!has(&held_cfg), "unpinned old config went");
        drop(pin);
        assert_eq!(store.images().unwrap().iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["app:latest", "app:v1", "held:1"]);
        fs::remove_dir_all(&root).unwrap();
    }

    /// `pin_existing`, `BlobWriter::finish_pinned`, and `find_pinned` hold
    /// blobs atomically across concurrent `put_image` tag overwrites so no
    /// in-flight pull, build mirror, or container create sees ENOENT.
    #[test]
    fn concurrent_pin_existing_and_finish_pinned_survive_put_image_overwrites() {
        let root = scratch("concurrent-pins");
        let _ = fs::remove_dir_all(&root);
        let store = Store::open(&root).unwrap();

        let shared_bytes = b"shared base layer bytes".to_vec();
        let shared_digest = sha256_digest(&shared_bytes);
        let shared_size = shared_bytes.len() as u64;
        let cfg1_bytes = br#"{"architecture":"amd64","os":"linux","config":{"Cmd":["v1"]}}"#.to_vec();
        let cfg1_digest = sha256_digest(&cfg1_bytes);
        let cfg1_size = cfg1_bytes.len() as u64;
        let cfg2_bytes = br#"{"architecture":"amd64","os":"linux","config":{"Cmd":["v2"]}}"#.to_vec();
        let cfg2_digest = sha256_digest(&cfg2_bytes);
        let layer2_bytes = b"version two unique layer".to_vec();
        let layer2_digest = sha256_digest(&layer2_bytes);
        let layer2_size = layer2_bytes.len() as u64;

        let write_pinned = |digest: &str, bytes: &[u8]| -> Pin {
            let mut w = store.blob_writer(digest).unwrap();
            w.write_all(bytes).unwrap();
            w.finish_pinned().unwrap()
        };

        // 1. Deterministic checks: pin_existing misses when absent or wrong size,
        // hits when matching, and protects against put_image overwrite;
        // BlobWriter::finish_pinned rejects mismatched digests and pins on success.
        assert!(store.pin_existing(&shared_digest, shared_size).is_none());
        let mut bad = store.blob_writer(&shared_digest).unwrap();
        bad.write_all(b"wrong bytes").unwrap();
        assert!(bad.finish_pinned().is_err());
        assert!(store.pin_existing(&shared_digest, shared_size).is_none());

        let p_shared = write_pinned(&shared_digest, &shared_bytes);
        let p_cfg1 = write_pinned(&cfg1_digest, &cfg1_bytes);
        assert!(store.pin_existing(&shared_digest, shared_size + 1).is_none(), "wrong size is not a hit");
        let existing_pin = store.pin_existing(&shared_digest, shared_size).expect("blob present");

        let make_img = |name: &str, cfg_digest: &str, layer_digest: &str, layer_size: u64| Image {
            name: name.into(),
            digest: cfg_digest.into(),
            index_digest: None,
            config_digest: cfg_digest.into(),
            layers: vec![Layer { digest: layer_digest.into(), size: layer_size, media_type: "application/vnd.oci.image.layer.v1.tar".into() }],
            size: layer_size,
            platform: "linux/amd64".into(),
            created: String::new(),
            pulled_at: 0,
            config: RunConfig::default(),
            mirror: None,
        };

        let img1 = make_img("race:latest", &cfg1_digest, &shared_digest, shared_size);
        let img2 = make_img("race:latest", &cfg2_digest, &layer2_digest, layer2_size);
        store.put_image(img1.clone()).unwrap();
        drop((p_shared, p_cfg1));

        // Overwrite race:latest with img2 while existing_pin holds shared_digest.
        let p_cfg2 = write_pinned(&cfg2_digest, &cfg2_bytes);
        let p_l2 = write_pinned(&layer2_digest, &layer2_bytes);
        store.put_image(img2.clone()).unwrap();
        drop((p_cfg2, p_l2));
        assert!(store.has_blob(&shared_digest, shared_size), "pin_existing protects blob across put_image");
        assert!(!store.has_blob(&cfg1_digest, cfg1_size), "unpinned cfg1 was freed");
        drop(existing_pin);

        // 2. Multi-threaded stress: overwrite race:latest back and forth between
        // img1 and img2 while concurrent readers use pin_existing,
        // BlobWriter::finish_pinned, and find_pinned.
        let done = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|s| {
            // Writer thread: repeatedly swaps race:latest between img1 and img2.
            s.spawn(|| {
                for round in 0..150 {
                    if round % 2 == 0 {
                        let p1 = write_pinned(&cfg1_digest, &cfg1_bytes);
                        let p2 = write_pinned(&shared_digest, &shared_bytes);
                        store.put_image(img1.clone()).unwrap();
                        drop((p1, p2));
                    } else {
                        let p1 = write_pinned(&cfg2_digest, &cfg2_bytes);
                        let p2 = write_pinned(&layer2_digest, &layer2_bytes);
                        store.put_image(img2.clone()).unwrap();
                        drop((p1, p2));
                    }
                }
                done.store(true, Ordering::Release);
            });

            // Pull-like thread: alternates pin_existing and BlobWriter::finish_pinned
            // on shared_digest and verifies the bytes remain readable while pinned.
            s.spawn(|| {
                let mut hits = 0usize;
                let mut writes = 0usize;
                while !done.load(Ordering::Acquire) {
                    if let Some(pin) = store.pin_existing(&shared_digest, shared_size) {
                        let got = fs::read(store.blob_path(&shared_digest).unwrap()).expect("blob vanished while pin_existing held");
                        assert_eq!(got, shared_bytes);
                        drop(pin);
                        hits += 1;
                    } else {
                        let pin = write_pinned(&shared_digest, &shared_bytes);
                        let got = fs::read(store.blob_path(&shared_digest).unwrap()).expect("blob vanished while finish_pinned held");
                        assert_eq!(got, shared_bytes);
                        drop(pin);
                        writes += 1;
                    }
                }
                assert!(hits + writes > 0);
            });

            // Reader thread (create/mirror-like): atomically looks up and pins
            // race:latest via find_pinned and reads both its config and layer.
            s.spawn(|| {
                let mut reads = 0usize;
                while !done.load(Ordering::Acquire) {
                    if let Some((img, pins)) = store.find_pinned("race:latest").unwrap() {
                        let cfg = store.read_config(&img.config_digest).expect("config vanished while find_pinned held");
                        let layer = fs::read(store.blob_path(&img.layers[0].digest).unwrap()).expect("layer vanished while find_pinned held");
                        if img.config_digest == cfg1_digest {
                            assert_eq!(cfg, cfg1_bytes);
                            assert_eq!(layer, shared_bytes);
                        } else {
                            assert_eq!(cfg, cfg2_bytes);
                            assert_eq!(layer, layer2_bytes);
                        }
                        drop(pins);
                        reads += 1;
                    }
                }
                assert!(reads > 0);
            });
        });

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn images_arc_caches_unchanged_index_and_invalidates_on_external_write() {
        let root = std::env::temp_dir().join(format!("kiri-store-cache-{}-{}", std::process::id(), TMP_SEQ.fetch_add(1, Ordering::Relaxed)));
        let _ = fs::remove_dir_all(&root);
        let store1 = Store::open(&root).unwrap();
        let store2 = Store::open(&root).unwrap();

        let empty1 = store1.images_arc().unwrap();
        let empty2 = store1.images_arc().unwrap();
        assert_eq!(store1.image_count().unwrap(), 0);
        assert!(Arc::ptr_eq(&empty1, &empty2));

        let mk = |name: &str| Image {
            name: name.into(),
            digest: "sha256:0000000000000000000000000000000000000000000000000000000000000001".into(),
            index_digest: None,
            config_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000001".into(),
            layers: Vec::new(),
            size: 1024,
            platform: "linux/arm64".into(),
            created: "2026-11-27T00:00:00Z".into(),
            pulled_at: 1,
            config: RunConfig::default(),
            mirror: None,
        };
        store2.put_image(mk("alpine:3.21")).unwrap();
        let after_ext = store1.images_arc().unwrap();
        assert_eq!(after_ext.len(), 1);
        assert_eq!(store1.image_count().unwrap(), 1);
        assert!(Arc::ptr_eq(&after_ext, &store1.images_arc().unwrap()));

        store1.put_image(mk("redis:7")).unwrap();
        let after_local = store1.images_arc().unwrap();
        assert_eq!(after_local.len(), 2);
        assert!(!Arc::ptr_eq(&after_ext, &after_local));
        assert!(Arc::ptr_eq(&after_local, &store1.images_arc().unwrap()));

        fs::remove_dir_all(&root).unwrap();
    }
}
