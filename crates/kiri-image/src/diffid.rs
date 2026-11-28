//! Image `rootfs.diff_ids` verification, bounded parallel decompression, and
//! tamper-evident caching on [`Store`].
//!
//! An image's ID is the SHA-256 digest of its config JSON, which is public for
//! any published image. Only `rootfs.diff_ids` (the SHA-256 digests of each
//! layer's uncompressed tar stream, in order) bind that config ID to the
//! image's filesystem contents.
//!
//! Security invariants enforced here:
//! - Layer compression format is sniffed strictly from each blob's own magic
//!   bytes ([`LayerFormat::sniff`]) and decoded with [`kiri_zstd::tar_reader`]
//!   (`CheckedGz` for multi-member gzip rejecting trailing bytes, `Frames` for
//!   multi-frame zstd with skippable frames and XXH64 checksum verification),
//!   matching guest `layers::unpack` byte-for-byte.
//! - Decompression uses at most [`PARALLEL_DIFF_IDS`] (4) worker threads over
//!   deduplicated layer digests, pulling from an [`AtomicUsize`] index and
//!   short-circuiting on the first error, mismatch, or cancellation.
//! - Both per-layer [`UnpackMeter`] (`Gzip`: `2048 * read` in `[1 GiB, 64 GiB]`,
//!   `Zstd`: `32768 * read` in `[1 GiB, 64 GiB]`, `Tar`: `read`) AND a shared
//!   per-image [`AtomicU64`] total decompressed cap ([`MAX_IMAGE_UNPACK_BYTES`]
//!   = 64 GiB) are enforced.
//! - `rootfs.type` must be `"layers"`, and `rootfs.diff_ids` count, order, and
//!   lowercase `sha256:<64 hex>` digests must match each layer's uncompressed
//!   SHA-256.
//! - Verified blobs are cached in `<store>/diff-ids` alongside their on-disk
//!   `(blob_len, mtime_sec, mtime_nsec, unpacked_len, diff_id)` stamp AND raw
//!   blob SHA-256 verification, so [`Store::check_image`] on unchanged blobs is
//!   an O(1) `stat` hit while tampered blobs re-hash and fail.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use kiri_proto::LayerFormat;
pub use kiri_proto::MAX_IMAGE_UNPACK_BYTES;
use kiri_proto::UnpackMeter;
use sha2::{Digest as _, Sha256};

use crate::store::{Image, Layer, Pin, Store, digest_hex, hex};

/// Maximum worker threads decompressing unique layers of an image at once.
pub const PARALLEL_DIFF_IDS: usize = 4;

/// Why a layer blob or image failed `diff_ids` verification.
#[derive(Debug)]
pub enum Error {
    /// The blob is corrupt, truncated, has trailing bytes, or its on-disk bytes
    /// no longer match its content-addressed `sha256` name.
    Invalid {
        digest: String,
        format: LayerFormat,
    },
    /// A single layer exceeded its [`kiri_proto::layer_unpack_cap`].
    OverCap {
        digest: String,
        cap: u64,
    },
    /// Total decompressed bytes across the image's layers exceeded the per-image cap.
    OverImageCap {
        cap: u64,
    },
    /// `rootfs.type`, `rootfs.diff_ids`, or a layer's uncompressed digest did not match.
    Mismatch(String),
    /// Stopped by cancellation.
    Cancelled,
    Io(io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Invalid { digest, format } => {
                write!(f, "layer {digest} is not a valid {} layer", format.name())
            }
            Error::OverCap { digest, cap } => write!(
                f,
                "layer {digest} expands beyond its allowed size of {cap} bytes"
            ),
            Error::OverImageCap { cap } => write!(
                f,
                "image layers expand beyond the allowed total size of {cap} bytes"
            ),
            Error::Mismatch(m) => write!(f, "{m}"),
            Error::Cancelled => write!(f, "cancelled"),
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        match e {
            Error::Io(e) => e,
            Error::Cancelled => io::Error::new(io::ErrorKind::Interrupted, "cancelled"),
            e => io::Error::new(io::ErrorKind::InvalidData, e),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedBlob {
    len: u64,
    mtime_sec: i64,
    mtime_nsec: u32,
    format: LayerFormat,
    unpacked_len: u64,
    diff_id: String,
}

#[derive(Debug, Default)]
struct Records {
    seen: HashMap<String, CachedBlob>,
    busy: HashSet<String>,
    peak: usize,
    hashed: u64,
    stamp: Option<(u64, Option<SystemTime>)>,
    ends_clean: bool,
}

static RECORDS: Mutex<Option<HashMap<PathBuf, Records>>> = Mutex::new(None);
static FREED: Condvar = Condvar::new();

type All = MutexGuard<'static, Option<HashMap<PathBuf, Records>>>;

fn sidecar_path(root: &Path) -> PathBuf {
    root.join("diff-ids")
}

fn sidecar_stamp(root: &Path) -> Option<(u64, Option<SystemTime>)> {
    fs::metadata(sidecar_path(root))
        .ok()
        .map(|m| (m.len(), m.modified().ok()))
}

fn blob_stamp(meta: &fs::Metadata) -> Option<(u64, i64, u32)> {
    let mtime = meta.modified().ok()?;
    let (sec, nsec) = match mtime.duration_since(UNIX_EPOCH) {
        Ok(d) => (i64::try_from(d.as_secs()).ok()?, d.subsec_nanos()),
        Err(e) => {
            let d = e.duration();
            if d.subsec_nanos() == 0 {
                (-i64::try_from(d.as_secs()).ok()?, 0)
            } else {
                (
                    -i64::try_from(d.as_secs()).ok()?.checked_add(1)?,
                    1_000_000_000 - d.subsec_nanos(),
                )
            }
        }
    };
    Some((meta.len(), sec, nsec))
}

pub fn is_lowercase_sha256(s: &str) -> bool {
    s.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

fn format_line(hex: &str, c: &CachedBlob) -> String {
    format!(
        "{} {} {} {} {} {} {}\n",
        hex,
        c.format.name(),
        c.len,
        c.mtime_sec,
        c.mtime_nsec,
        c.unpacked_len,
        c.diff_id
    )
}

fn parse_line(line: &[u8]) -> Option<(String, CachedBlob)> {
    let line = std::str::from_utf8(line).ok()?;
    let mut w = line.split(' ');
    let hex = w.next()?;
    let fmt = LayerFormat::from_name(w.next()?)?;
    let len: u64 = w.next()?.parse().ok()?;
    let mtime_sec: i64 = w.next()?.parse().ok()?;
    let mtime_nsec: u32 = w.next()?.parse().ok()?;
    let unpacked_len: u64 = w.next()?.parse().ok()?;
    let diff_id = w.next()?;
    if w.next().is_some()
        || hex.len() != 64
        || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        || !is_lowercase_sha256(diff_id)
    {
        return None;
    }
    Some((
        hex.to_owned(),
        CachedBlob {
            len,
            mtime_sec,
            mtime_nsec,
            format: fmt,
            unpacked_len,
            diff_id: diff_id.to_owned(),
        },
    ))
}

fn lock_records() -> All {
    RECORDS.lock().unwrap_or_else(|e| e.into_inner())
}

fn entry<'a>(all: &'a mut All, root: &Path) -> &'a mut Records {
    let r = all
        .get_or_insert_default()
        .entry(root.to_owned())
        .or_default();
    let now = sidecar_stamp(root);
    if r.stamp != now {
        let bytes = fs::read(sidecar_path(root)).unwrap_or_default();
        for line in bytes.split(|b| *b == b'\n') {
            if let Some((hex, cached)) = parse_line(line) {
                r.seen.insert(hex, cached);
            }
        }
        r.ends_clean = bytes.last().is_none_or(|b| *b == b'\n');
        r.stamp = now;
    }
    r
}

fn with_records<T>(root: &Path, f: impl FnOnce(&mut Records) -> T) -> T {
    let mut all = lock_records();
    f(entry(&mut all, root))
}

fn save_cached(root: &Path, hex: &str, cached: CachedBlob) {
    with_records(root, |r| {
        if r.seen.get(hex) == Some(&cached) {
            return;
        }
        let replaced = r.seen.insert(hex.to_owned(), cached.clone()).is_some();
        if replaced {
            rewrite_sidecar(root, r);
            return;
        }
        let mut text = format_line(hex, &cached);
        if !r.ends_clean {
            text.insert(0, '\n');
        }
        let wrote = File::options()
            .create(true)
            .append(true)
            .open(sidecar_path(root))
            .and_then(|mut f| f.write_all(text.as_bytes()));
        r.ends_clean = wrote.is_ok();
        r.stamp = sidecar_stamp(root);
    });
}

fn rewrite_sidecar(root: &Path, r: &mut Records) {
    let mut lines: Vec<String> = r.seen.iter().map(|(h, c)| format_line(h, c)).collect();
    lines.sort();
    if crate::jsonfile::replace(
        &sidecar_path(root),
        lines.concat().as_bytes(),
        crate::jsonfile::Durable::Later,
    )
    .is_ok()
    {
        r.ends_clean = true;
    }
    r.stamp = sidecar_stamp(root);
}

/// Sniffs a layer blob's format from its own magic bytes.
pub fn sniff(path: &Path) -> io::Result<LayerFormat> {
    Ok(open_blob(path)?.1)
}

fn open_blob(path: &Path) -> io::Result<(File, LayerFormat, Vec<u8>)> {
    let mut file = File::open(path)?;
    let mut head = Vec::with_capacity(4);
    (&mut file).take(4).read_to_end(&mut head)?;
    let format = LayerFormat::sniff(&head);
    Ok((file, format, head))
}

struct Packed<'a, R> {
    inner: R,
    meter: &'a UnpackMeter,
    raw_hasher: &'a mut Sha256,
    cancelled: &'a dyn Fn() -> bool,
    failed: &'a std::cell::Cell<bool>,
}

impl<R: Read> Read for Packed<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if (self.cancelled)() {
            return Err(io::Error::other("cancelled"));
        }
        let n = self
            .inner
            .read(buf)
            .inspect_err(|e| self.failed.set(e.kind() != io::ErrorKind::Interrupted))?;
        self.meter.packed(n);
        self.raw_hasher.update(&buf[..n]);
        Ok(n)
    }
}

struct Limits<'a> {
    layer_cap: Option<fn(u64) -> u64>,
    image_total: Option<&'a AtomicU64>,
    image_cap: u64,
}

fn unpack_digest(
    blob: impl Read,
    digest: &str,
    format: LayerFormat,
    limits: &Limits<'_>,
    cancelled: &dyn Fn() -> bool,
) -> Result<(String, u64), Error> {
    let meter = limits
        .layer_cap
        .map_or_else(|| UnpackMeter::new(format), UnpackMeter::with_cap);
    let mut raw_hasher = Sha256::new();
    let failed = std::cell::Cell::new(false);
    let mut unpacked_len = 0u64;
    let tar_digest = {
        let packed = BufReader::with_capacity(
            256 * 1024,
            Packed {
                inner: blob,
                meter: &meter,
                raw_hasher: &mut raw_hasher,
                cancelled,
                failed: &failed,
            },
        );
        let mut tar = kiri_zstd::tar_reader(format, packed);
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            match tar.read(&mut buf) {
                Ok(0) => break format!("sha256:{}", hex(&hasher.finalize())),
                Ok(n) => {
                    if !meter.unpacked(n) {
                        return Err(Error::OverCap {
                            digest: digest.to_owned(),
                            cap: meter.cap(),
                        });
                    }
                    unpacked_len = unpacked_len.saturating_add(n as u64);
                    if let Some(total) = limits.image_total {
                        let prev = total.fetch_add(n as u64, Ordering::Relaxed);
                        if prev.saturating_add(n as u64) > limits.image_cap {
                            return Err(Error::OverImageCap {
                                cap: limits.image_cap,
                            });
                        }
                    }
                    hasher.update(&buf[..n]);
                }
                Err(_) if cancelled() => return Err(Error::Cancelled),
                Err(e) if failed.get() => return Err(Error::Io(e)),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => {
                    return Err(Error::Invalid {
                        digest: digest.to_owned(),
                        format,
                    });
                }
            }
        }
    };
    let raw_actual = format!("sha256:{}", hex(&raw_hasher.finalize()));
    if raw_actual != digest {
        return Err(Error::Invalid {
            digest: digest.to_owned(),
            format,
        });
    }
    Ok((tar_digest, unpacked_len))
}

struct Reading<'a> {
    root: &'a Path,
    hex: String,
}

impl Drop for Reading<'_> {
    fn drop(&mut self) {
        with_records(self.root, |r| r.busy.remove(&self.hex));
        FREED.notify_all();
    }
}

/// Parses and validates `rootfs.type == "layers"` and `rootfs.diff_ids`.
pub fn parse_config_diff_ids(config: &serde_json::Value) -> Result<Vec<&str>, String> {
    if config["rootfs"]["type"].as_str() != Some("layers") {
        return Err("image config rootfs.type must be \"layers\"".into());
    }
    match config["rootfs"].get("diff_ids") {
        None | Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(serde_json::Value::Array(arr)) => {
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                let Some(s) = v.as_str().filter(|s| is_lowercase_sha256(s)) else {
                    return Err(format!("invalid diff_id {v} in image config"));
                };
                out.push(s);
            }
            Ok(out)
        }
        Some(_) => Err("image config rootfs.diff_ids must be an array".into()),
    }
}

impl Store {
    /// Returns the verified uncompressed SHA-256 `diff_id` of layer blob `digest`.
    pub fn diff_id(&self, digest: &str) -> Result<String, Error> {
        let limits = Limits {
            layer_cap: None,
            image_total: None,
            image_cap: MAX_IMAGE_UNPACK_BYTES,
        };
        Ok(self.diff_id_limited(digest, &limits, &|| false)?.0)
    }

    fn diff_id_limited(
        &self,
        digest: &str,
        limits: &Limits<'_>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(String, u64), Error> {
        if !is_lowercase_sha256(digest) {
            return Err(Error::Mismatch(format!("invalid layer digest {digest:?}")));
        }
        let hex_str = digest_hex(digest)?.to_owned();
        let path = self.blob_path(digest)?;
        let reading = {
            let meta = fs::metadata(&path)?;
            let stamp = blob_stamp(&meta);
            let mut all = lock_records();
            loop {
                let r = entry(&mut all, self.root());
                if limits.layer_cap.is_none()
                    && let (Some((len, sec, nsec)), Some(c)) = (stamp, r.seen.get(&hex_str))
                    && (c.len, c.mtime_sec, c.mtime_nsec) == (len, sec, nsec)
                {
                    if let Some(total) = limits.image_total {
                        let prev = total.fetch_add(c.unpacked_len, Ordering::Relaxed);
                        if prev.saturating_add(c.unpacked_len) > limits.image_cap {
                            return Err(Error::OverImageCap {
                                cap: limits.image_cap,
                            });
                        }
                    }
                    return Ok((c.diff_id.clone(), c.unpacked_len));
                }
                if r.busy.insert(hex_str.clone()) {
                    r.peak = r.peak.max(r.busy.len());
                    break Reading {
                        root: self.root(),
                        hex: hex_str.clone(),
                    };
                }
                if cancelled() {
                    return Err(Error::Cancelled);
                }
                all = FREED
                    .wait_timeout(all, Duration::from_millis(50))
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            }
        };

        let (blob, format, head) = open_blob(&path)?;
        let stamp_before = blob.metadata().ok().and_then(|m| blob_stamp(&m));
        with_records(self.root(), |r| r.hashed += 1);
        let result = unpack_digest(
            io::Cursor::new(head).chain(blob),
            digest,
            format,
            limits,
            cancelled,
        );
        if let (Ok((diff_id, unpacked_len)), None, Some((len, mtime_sec, mtime_nsec))) =
            (&result, limits.layer_cap, stamp_before)
        {
            // Only cache if the file on disk still matches the stamp we opened.
            if fs::metadata(&path).ok().and_then(|m| blob_stamp(&m))
                == Some((len, mtime_sec, mtime_nsec))
            {
                save_cached(
                    self.root(),
                    &hex_str,
                    CachedBlob {
                        len,
                        mtime_sec,
                        mtime_nsec,
                        format,
                        unpacked_len: *unpacked_len,
                        diff_id: diff_id.clone(),
                    },
                );
            }
        }
        drop(reading);
        result
    }

    /// Returns the cached `diff_id` if `digest` is on disk and unchanged since verification.
    pub fn known_diff_id(&self, digest: &str) -> Option<String> {
        let hex_str = digest_hex(digest).ok()?;
        let meta = fs::metadata(self.blob_path(digest).ok()?).ok()?;
        let (len, sec, nsec) = blob_stamp(&meta)?;
        with_records(self.root(), |r| {
            r.seen
                .get(hex_str)
                .filter(|c| (c.len, c.mtime_sec, c.mtime_nsec) == (len, sec, nsec))
                .map(|c| c.diff_id.clone())
        })
    }

    /// Verifies `rootfs.type == "layers"` and every layer's `diff_id` against `config`.
    pub fn check_diff_ids(
        &self,
        config: &serde_json::Value,
        layers: &[Layer],
    ) -> Result<(), Error> {
        self.check_diff_ids_with(config, layers, &|| false)
    }

    /// As [`Store::check_diff_ids`], aborting early when `cancelled()` returns true.
    pub fn check_diff_ids_with(
        &self,
        config: &serde_json::Value,
        layers: &[Layer],
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), Error> {
        self.check_diff_ids_capped(config, layers, None, MAX_IMAGE_UNPACK_BYTES, cancelled)
    }

    fn check_diff_ids_capped(
        &self,
        config: &serde_json::Value,
        layers: &[Layer],
        layer_cap: Option<fn(u64) -> u64>,
        image_cap: u64,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), Error> {
        let ids = parse_config_diff_ids(config).map_err(Error::Mismatch)?;
        if ids.len() != layers.len() {
            return Err(Error::Mismatch(format!(
                "the image config lists {} layers, the image has {}",
                ids.len(),
                layers.len()
            )));
        }
        if layers.is_empty() {
            return Ok(());
        }

        // Deduplicate unique layer digests before dispatching to bounded worker pool.
        let mut unique: Vec<&str> = Vec::new();
        let mut seen = HashSet::new();
        for l in layers {
            if seen.insert(l.digest.as_str()) {
                unique.push(l.digest.as_str());
            }
        }

        type LayerOutcome = Result<(String, u64), Error>;
        let next = AtomicUsize::new(0);
        let stop = AtomicBool::new(false);
        let stream_total = AtomicU64::new(0);
        let results: Mutex<HashMap<String, LayerOutcome>> =
            Mutex::new(HashMap::with_capacity(unique.len()));
        let expected = |digest: &str, got: &str| {
            layers
                .iter()
                .zip(&ids)
                .all(|(l, want)| l.digest != digest || *want == got)
        };

        let work = || {
            let limits = Limits {
                layer_cap,
                image_total: Some(&stream_total),
                image_cap,
            };
            loop {
                let idx = next.fetch_add(1, Ordering::Relaxed);
                let Some(&digest) = unique.get(idx) else {
                    return;
                };
                if stop.load(Ordering::Relaxed) || cancelled() {
                    return;
                }
                let res = self.diff_id_limited(digest, &limits, &|| {
                    cancelled() || stop.load(Ordering::Relaxed)
                });
                if !res.as_ref().is_ok_and(|(got, _)| expected(digest, got)) {
                    stop.store(true, Ordering::Relaxed);
                }
                results
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(digest.to_owned(), res);
            }
        };

        let workers = PARALLEL_DIFF_IDS.min(unique.len());
        std::thread::scope(|s| {
            for _ in 1..workers {
                let _ = std::thread::Builder::new()
                    .name("kiri-diffid".into())
                    .spawn_scoped(s, work);
            }
            work();
        });

        let mut got = results.into_inner().unwrap_or_else(|e| e.into_inner());
        let mut manifest_unpacked = 0u64;
        let mut stopped = None;
        for (l, want) in layers.iter().zip(ids) {
            match got.get(&l.digest) {
                Some(Ok((d, unpacked))) if d == want => {
                    manifest_unpacked = manifest_unpacked.saturating_add(*unpacked);
                    if manifest_unpacked > image_cap {
                        return Err(Error::OverImageCap { cap: image_cap });
                    }
                }
                Some(Ok((d, _))) => {
                    return Err(Error::Mismatch(format!(
                        "layer {} doesn't match the image config: it unpacks to {d}, the config says {want}",
                        l.digest
                    )));
                }
                Some(Err(Error::Cancelled)) | None if cancelled() => return Err(Error::Cancelled),
                Some(Err(Error::Cancelled)) | None => {
                    stopped = Some(Error::Io(io::Error::other(format!(
                        "layer {} was not read",
                        l.digest
                    ))));
                }
                Some(Err(_)) => {
                    return Err(got
                        .remove(&l.digest)
                        .and_then(Result::err)
                        .unwrap_or(Error::Cancelled));
                }
            }
        }
        stopped.map_or(Ok(()), Err)
    }

    /// Verifies that a recorded [`Image`]'s config and layers match `rootfs.diff_ids`.
    /// Uses the `(blob_len, mtime_sec, mtime_nsec)` sidecar cache so unchanged blobs
    /// verify without re-decompression while tampered or missing blobs fail.
    pub fn check_image(&self, image: &Image) -> io::Result<()> {
        let _pins = self.hold_image(image);
        let config_bytes = self.read_config(&image.config_digest)?;
        let config: serde_json::Value = serde_json::from_slice(&config_bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: image config: {e}", image.name),
            )
        })?;
        self.check_diff_ids(&config, &image.layers)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", image.name)))
    }

    /// Verifies `image` via [`Store::check_image`] and returns its ordered `diff_ids`.
    pub fn checked_diff_ids(&self, image: &Image) -> io::Result<Vec<String>> {
        self.check_image(image)?;
        let config: serde_json::Value =
            serde_json::from_slice(&self.read_config(&image.config_digest)?).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("image config: {e}"))
            })?;
        let ids = parse_config_diff_ids(&config)
            .map_err(|m| io::Error::new(io::ErrorKind::InvalidData, m))?;
        Ok(ids.into_iter().map(str::to_owned).collect())
    }

    /// Stores a tar stream produced locally (`docker commit`) and returns `(Layer, diff_id, Pin)`.
    /// Plain tars stay uncompressed unless their first 4 bytes collide with gzip/zstd magic.
    pub fn ingest_layer_pinned(&self, mut tar: impl Read) -> io::Result<(Layer, String, Pin)> {
        let mut head = Vec::with_capacity(4);
        (&mut tar).take(4).read_to_end(&mut head)?;
        let mut tar = io::Cursor::new(&head).chain(tar);
        if LayerFormat::sniff(&head) == LayerFormat::Tar {
            let mut w = self.ingest()?;
            io::copy(&mut tar, &mut w)?;
            let (digest, size, pin) = w.finish_pinned()?;
            return Ok((
                Layer {
                    digest: digest.clone(),
                    size,
                    media_type: "application/vnd.oci.image.layer.v1.tar".into(),
                },
                digest,
                pin,
            ));
        }
        let mut gz = flate2::write::GzEncoder::new(self.ingest()?, flate2::Compression::fast());
        let mut hasher = Sha256::new();
        let mut unpacked_len = 0u64;
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            let n = match tar.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            unpacked_len = unpacked_len.saturating_add(n as u64);
            hasher.update(&buf[..n]);
            gz.write_all(&buf[..n])?;
        }
        let (digest, size, pin) = gz.finish()?.finish_pinned()?;
        let diff_id = format!("sha256:{}", hex(&hasher.finalize()));
        if let Ok(path) = self.blob_path(&digest)
            && let Some((len, mtime_sec, mtime_nsec)) =
                fs::metadata(&path).ok().and_then(|m| blob_stamp(&m))
        {
            save_cached(
                self.root(),
                digest_hex(&digest)?,
                CachedBlob {
                    len,
                    mtime_sec,
                    mtime_nsec,
                    format: LayerFormat::Gzip,
                    unpacked_len,
                    diff_id: diff_id.clone(),
                },
            );
        }
        Ok((
            Layer {
                digest,
                size,
                media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into(),
            },
            diff_id,
            pin,
        ))
    }

    pub(crate) fn forget_diff_ids(&self, digests: &[String]) {
        let gone: HashSet<&str> = digests.iter().filter_map(|d| digest_hex(d).ok()).collect();
        if gone.is_empty() {
            return;
        }
        with_records(self.root(), |r| {
            let before = r.seen.len();
            r.seen.retain(|h, _| !gone.contains(h.as_str()));
            if r.seen.len() != before {
                rewrite_sidecar(self.root(), r);
            }
        });
    }

    #[cfg(test)]
    pub fn layers_hashed(&self) -> u64 {
        with_records(self.root(), |r| r.hashed)
    }

    #[cfg(test)]
    pub fn layers_read_at_once(&self) -> usize {
        with_records(self.root(), |r| r.peak)
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use std::io::Write as _;

    pub fn sha256(b: &[u8]) -> String {
        crate::store::sha256_digest(b)
    }

    pub fn gzip(b: &[u8]) -> Vec<u8> {
        let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(b).unwrap();
        z.finish().unwrap()
    }

    pub fn zstd(b: &[u8]) -> Vec<u8> {
        ruzstd::encoding::compress_to_vec(b, ruzstd::encoding::CompressionLevel::Fastest)
    }

    pub fn skippable(payload: &[u8]) -> Vec<u8> {
        [
            &0x184D_2A50u32.to_le_bytes()[..],
            &(payload.len() as u32).to_le_bytes(),
            payload,
        ]
        .concat()
    }

    fn header(size: usize) -> tar::Header {
        let mut h = tar::Header::new_ustar();
        h.set_size(size as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        h
    }

    pub fn layer_tar(name: &str, data: &[u8]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        b.append_data(&mut header(data.len()), name, data).unwrap();
        b.into_inner().unwrap()
    }

    /// Valid gzip stream of `real` whose gzip FEXTRA header embeds a valid plain tar of `evil`.
    pub fn polyglot(real: &[u8], evil: &[u8]) -> Vec<u8> {
        let mut first = header(0);
        first.as_mut_bytes()[..10].copy_from_slice(&[0x1f, 0x8b, 8, 4, 0, 0, 0, 0, 0, 3]);
        let rest = layer_tar("evil", evil);
        first.as_mut_bytes()[10..12]
            .copy_from_slice(&((512 - 12 + rest.len()) as u16).to_le_bytes());
        first.set_cksum();
        let mut blob = first.as_bytes().to_vec();
        blob.extend_from_slice(&rest);
        blob.extend_from_slice(&gzip(real)[10..]);
        blob
    }

    /// Zstd RLE stream of `blocks` * 128 KiB of zeros (4 bytes per 128 KiB block).
    pub fn zstd_zeros(blocks: usize) -> Vec<u8> {
        let mut z = vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x68];
        for i in 0..blocks {
            let head = ((128u32 << 10) << 3) | (1 << 1) | u32::from(i + 1 == blocks);
            z.extend_from_slice(&head.to_le_bytes()[..3]);
            z.push(0);
        }
        z
    }

    pub fn scratch(name: &str) -> std::path::PathBuf {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("kiri-diffid-{name}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    pub fn put(store: &crate::Store, bytes: &[u8]) -> (String, u64) {
        let mut w = store.ingest().unwrap();
        w.write_all(bytes).unwrap();
        w.finish().unwrap()
    }

    pub fn restart(store: &crate::Store) {
        if let Some(all) = super::RECORDS.lock().unwrap().as_mut() {
            all.remove(store.root());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use serde_json::json;

    const TAR: &str = "application/vnd.oci.image.layer.v1.tar";
    const GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
    const ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";

    fn put_layer(store: &Store, bytes: &[u8], media_type: &str) -> Layer {
        let (digest, size) = put(store, bytes);
        Layer {
            digest,
            size,
            media_type: media_type.into(),
        }
    }

    fn cfg(diff_ids: &[String]) -> serde_json::Value {
        json!({"architecture": "arm64", "os": "linux", "config": {"Cmd": ["sh"]}, "rootfs": {"type": "layers", "diff_ids": diff_ids}})
    }

    #[test]
    fn polyglot_gzip_tar_has_one_diff_id_and_trailing_gzip_bytes_fail() {
        let real = layer_tar("etc/os-release", b"real\n");
        let blob = polyglot(&real, b"evil\n");
        let store = Store::open(scratch("polyglot")).unwrap();
        let l_tar = put_layer(&store, &blob, TAR);
        assert!(
            store
                .check_diff_ids(
                    &cfg(std::slice::from_ref(&l_tar.digest)),
                    std::slice::from_ref(&l_tar)
                )
                .is_err()
        );
        store
            .check_diff_ids(&cfg(&[sha256(&real)]), std::slice::from_ref(&l_tar))
            .unwrap();
        assert_eq!(store.layers_hashed(), 1);

        // Appending trailing tar/garbage bytes after a valid gzip member must fail!
        let with_trailing = [&gzip(&real)[..], &layer_tar("extra", b"pwn")].concat();
        let bad_gz = put_layer(&store, &with_trailing, GZIP);
        assert!(matches!(
            store.diff_id(&bad_gz.digest),
            Err(Error::Invalid {
                format: LayerFormat::Gzip,
                ..
            })
        ));
        fs::remove_dir_all(store.root()).unwrap();
    }

    #[test]
    fn multi_frame_zstd_and_skippable_frames_hash_whole_and_reject_trailing() {
        let store = Store::open(scratch("zstd-frames")).unwrap();
        let tar = [
            layer_tar("a", &[1u8; 40_000]),
            layer_tar("b", b"two"),
            layer_tar("c", &[3u8; 9_000]),
        ]
        .concat();
        let (p1, rest) = tar.split_at(25_000);
        let (p2, p3) = rest.split_at(15_000);
        for blob in [
            zstd(&tar),
            [zstd(p1), zstd(p2), zstd(p3)].concat(),
            [
                skippable(b"lead"),
                zstd(p1),
                skippable(b"toc"),
                zstd(b""),
                zstd(p2),
                zstd(p3),
                skippable(&[9u8; 1024]),
            ]
            .concat(),
        ] {
            let l = put_layer(&store, &blob, ZSTD);
            assert_eq!(store.diff_id(&l.digest).unwrap(), sha256(&tar));
            store
                .check_diff_ids(&cfg(&[sha256(&tar)]), std::slice::from_ref(&l))
                .unwrap();
        }
        let trailing = put_layer(&store, &[&zstd(&tar)[..], b"trailing"].concat(), ZSTD);
        assert!(matches!(
            store.diff_id(&trailing.digest),
            Err(Error::Invalid {
                format: LayerFormat::Zstd,
                ..
            })
        ));
        fs::remove_dir_all(store.root()).unwrap();
    }

    #[test]
    fn bounded_parallelism_and_per_layer_and_per_image_zip_bomb_caps() {
        let store = Store::open(scratch("caps")).unwrap();
        // 1. Per-layer cap.
        let bomb = put_layer(&store, &zstd_zeros(32), ZSTD); // 32 * 128 KiB = 4 MiB
        fn tiny_cap(read: u64) -> u64 {
            (read * 1024).max(1 << 20) // 1 MiB cap
        }
        let err = store.check_diff_ids_capped(
            &cfg(&[sha256(&vec![0u8; 4 << 20])]),
            std::slice::from_ref(&bomb),
            Some(tiny_cap),
            MAX_IMAGE_UNPACK_BYTES,
            &|| false,
        );
        assert!(
            matches!(err, Err(Error::OverCap { cap: 1_048_576, .. })),
            "{err:?}"
        );

        // 2. Per-image total decompressed cap across multiple layers (and repeated layers).
        let chunk = vec![0u8; 2 << 20];
        let l1 = put_layer(&store, &gzip(&chunk), GZIP);
        let l2 = put_layer(&store, &zstd(&chunk), ZSTD);
        let two_cfg = cfg(&[sha256(&chunk), sha256(&chunk)]);
        let err = store.check_diff_ids_capped(
            &two_cfg,
            &[l1.clone(), l2.clone()],
            None,
            3 << 20,
            &|| false,
        );
        assert!(
            matches!(err, Err(Error::OverImageCap { cap }) if cap == 3 << 20),
            "{err:?}"
        );
        // Passes when image_cap >= 4 MiB.
        store
            .check_diff_ids_capped(&two_cfg, &[l1.clone(), l2], None, 4 << 20, &|| false)
            .unwrap();
        // Repeated layer exceeding manifest image_cap also fails even when cached.
        let repeated_cfg = cfg(&vec![sha256(&chunk); 4]);
        let err =
            store.check_diff_ids_capped(&repeated_cfg, &vec![l1; 4], None, 6 << 20, &|| false);
        assert!(
            matches!(err, Err(Error::OverImageCap { cap }) if cap == 6 << 20),
            "{err:?}"
        );

        // 3. Bounded parallelism (<= PARALLEL_DIFF_IDS = 4) and deduplication.
        let store2 = Store::open(scratch("pool")).unwrap();
        let many: Vec<(Layer, String)> = (0..24u32)
            .map(|i| {
                let t = layer_tar("f", &i.to_le_bytes().repeat(4096));
                (put_layer(&store2, &gzip(&t), GZIP), sha256(&t))
            })
            .collect();
        let (layers, ids): (Vec<Layer>, Vec<String>) = many.into_iter().unzip();
        store2.check_diff_ids(&cfg(&ids), &layers).unwrap();
        assert_eq!(store2.layers_hashed(), 24);
        assert!(
            store2.layers_read_at_once() <= PARALLEL_DIFF_IDS,
            "peak {}",
            store2.layers_read_at_once()
        );

        // Duplicate layer listed 1000 times hashes once.
        let dup_tar = layer_tar("dup", b"hello");
        let dup_l = put_layer(&store2, &gzip(&dup_tar), GZIP);
        store2
            .check_diff_ids(&cfg(&vec![sha256(&dup_tar); 1000]), &vec![dup_l; 1000])
            .unwrap();
        assert_eq!(store2.layers_hashed(), 25);

        fs::remove_dir_all(store.root()).unwrap();
        fs::remove_dir_all(store2.root()).unwrap();
    }

    #[test]
    fn rootfs_type_and_tampered_blob_rehash_and_fail() {
        let store = Store::open(scratch("tamper")).unwrap();
        let tar = layer_tar("etc/app", b"v1");
        let l = put_layer(&store, &gzip(&tar), GZIP);

        // Missing or wrong rootfs.type, uppercase hex, or wrong order fail.
        for bad_cfg in [
            json!({"architecture": "arm64", "os": "linux", "config": {}}),
            json!({"architecture": "arm64", "os": "linux", "rootfs": {"type": "other", "diff_ids": [sha256(&tar)]}}),
            json!({"architecture": "arm64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": [sha256(&tar).to_uppercase()]}}),
            json!({"architecture": "arm64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": "not-array"}}),
        ] {
            assert!(
                store
                    .check_diff_ids(&bad_cfg, std::slice::from_ref(&l))
                    .is_err(),
                "{bad_cfg}"
            );
        }

        let valid_cfg = cfg(&[sha256(&tar)]);
        let (cfg_digest, _) = put(&store, &serde_json::to_vec(&valid_cfg).unwrap());
        let img =
            crate::archive::from_config("app:1".into(), &cfg_digest, &valid_cfg, vec![l.clone()]);
        store.put_image(img.clone()).unwrap();

        store.check_image(&img).unwrap();
        assert_eq!(store.layers_hashed(), 1);
        // Second check and post-restart check hit sidecar cache without re-hashing.
        store.check_image(&img).unwrap();
        assert_eq!(store.layers_hashed(), 1);
        restart(&store);
        store.check_image(&img).unwrap();
        assert_eq!(store.layers_hashed(), 0);

        // Tamper with the blob on disk (different content/length): stamp changes, re-hashes, and fails!
        let blob_path = store.blob_path(&l.digest).unwrap();
        fs::write(
            &blob_path,
            gzip(&layer_tar("etc/app", b"tampered-longer-payload")),
        )
        .unwrap();
        assert!(store.check_image(&img).is_err());

        fs::remove_dir_all(store.root()).unwrap();
    }
}
