//! The guest's layer store: compressed layer blobs arrive from the host over
//! vsock and are unpacked once into `layers/<hex>/`, ready to be stacked by
//! overlayfs. A layer directory only appears, by rename, once it is complete,
//! and is only used once `<hex>.done` beside it says its files are on disk:
//! a VM that stops before the guest flushes can keep a layer's names but
//! lose its contents, leaving every file empty.

use std::ffi::CString;
use std::fs;
use std::io::{self, BufReader, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use sha2::Digest as _;

use kiri_proto::{LayerBegin, LayerStored};

use super::{inroot, sys};

pub fn hex(digest: &str) -> io::Result<&str> {
    let h = digest.strip_prefix("sha256:").unwrap_or(digest);
    if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("bad layer digest {digest}")));
    }
    Ok(h)
}

pub fn dir(root: &Path, digest: &str) -> io::Result<PathBuf> {
    Ok(root.join(hex(digest)?))
}

fn marker(root: &Path, digest: &str) -> io::Result<PathBuf> {
    Ok(root.join(format!("{}.done", hex(digest)?)))
}

pub fn present(root: &Path, digest: &str) -> bool {
    dir(root, digest).is_ok_and(|d| d.is_dir()) && marker(root, digest).is_ok_and(|m| m.is_file())
}

/// A new folder beside the store to unpack the layer `digest` into:
/// `.tmp-<hex>-<pid>-<random>`, made with mkdir (which fails on anything
/// already there, a link included), so no other process can guess the name
/// ahead or have one ready there. `retain` clears what a cut-short unpack
/// leaves (`.tmp-*`).
fn fresh_tmp(root: &Path, digest: &str) -> io::Result<PathBuf> {
    let h = hex(digest)?;
    fs::create_dir_all(root)?;
    for _ in 0..16 {
        let mut r = [0u8; 8];
        // SAFETY: getrandom fills at most `r.len()` bytes of `r`.
        if unsafe { libc::getrandom(r.as_mut_ptr().cast(), r.len(), 0) } != r.len() as isize {
            return Err(io::Error::last_os_error());
        }
        let tmp = root.join(format!(".tmp-{h}-{}-{:016x}", std::process::id(), u64::from_ne_bytes(r)));
        match fs::create_dir(&tmp) {
            Ok(()) => return Ok(tmp),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, "no free temporary layer folder"))
}

/// Reads exactly `begin.size` bytes of blob from `stream` and unpacks them.
/// The stream stays in sync even if unpacking fails part-way.
pub fn receive(stream: &mut impl Read, begin: &LayerBegin<'_>, root: &Path) -> io::Result<LayerStored> {
    let started = Instant::now();
    let final_dir = dir(root, begin.digest)?;
    let tmp = fresh_tmp(root, begin.digest)?;

    let mut limited = stream.take(begin.size);
    let result = unpack(&mut limited, begin.media_type, &tmp, begin.size);
    // Whatever happened, consume the rest of the blob so the next frame lines up.
    io::copy(&mut limited, &mut io::sink())?;

    match result.and_then(|unpacked_bytes| install(root, begin.digest, &tmp, &final_dir).map(|()| unpacked_bytes)) {
        Ok(unpacked_bytes) => Ok(LayerStored { unpacked_bytes, elapsed_ns: started.elapsed().as_nanos() as u64 }),
        Err(e) => {
            let _ = super::rmtree::remove_all(&tmp);
            Err(e)
        }
    }
}

/// A folder that already holds the layer `digest` unpacked (a build step's
/// writable folder, whose whiteouts are already overlayfs's) becomes that
/// layer, by rename. Nothing to do if the layer is there already.
pub fn adopt(root: &Path, digest: &str, folder: &Path) -> io::Result<()> {
    let final_dir = dir(root, digest)?;
    install(root, digest, folder, &final_dir)
}

/// Hashes what is read through it.
struct Hashing<R> {
    inner: R,
    hash: sha2::Sha256,
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        sha2::Digest::update(&mut self.hash, &buf[..n]);
        Ok(n)
    }
}

fn digest_of(h: sha2::Sha256) -> String {
    let out = sha2::Digest::finalize(h);
    let mut s = String::with_capacity(71);
    s.push_str("sha256:");
    for b in out {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A layer unpacked as its blob arrives (`copy_op::LAYER_UNPACK`), into a
/// folder of its own beside the store, not yet a layer. One pass: the
/// blob's bytes are hashed, inflated, the tar hashed and unpacked. The
/// blob must hash to `digest`; the tar's digest (its diff_id) is returned
/// for the caller to check against the image's config before it
/// [`keep`]s the folder.
pub fn unpack_streamed(blob: &mut impl Read, digest: &str, media_type: &str, root: &Path) -> io::Result<(String, PathBuf, LayerStored)> {
    let started = Instant::now();
    let tmp = fresh_tmp(root, digest)?;
    let result = (|| {
        let mut blob = Hashing { inner: blob, hash: sha2::Sha256::new() };
        let buffered = BufReader::with_capacity(256 * 1024, &mut blob);
        let mut tar: Box<dyn Read> = if media_type.ends_with("gzip") {
            Box::new(flate2::read::MultiGzDecoder::new(buffered))
        } else if media_type.ends_with("zstd") {
            // Every frame (zstd:chunked and multi-threaded zstd write many); the
            // copy below reads the stream to its end, so a damaged one fails.
            Box::new(kiri_zstd::Frames::new(buffered))
        } else {
            Box::new(buffered)
        };
        let mut tar_hash = Hashing { inner: &mut tar, hash: sha2::Sha256::new() };
        let n = untar(Capped { inner: &mut tar_hash, left: 64 << 30 }, &tmp)?;
        // The tar's end and anything after it count in its digest.
        io::copy(&mut tar_hash, &mut io::sink())?;
        let diff_id = digest_of(tar_hash.hash);
        drop(tar);
        io::copy(&mut blob, &mut io::sink())?;
        let got = digest_of(blob.hash);
        if got != digest {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("layer {digest} arrived as {got}")));
        }
        Ok((diff_id, n))
    })();
    match result {
        Ok((diff_id, unpacked_bytes)) => Ok((diff_id, tmp, LayerStored { unpacked_bytes, elapsed_ns: started.elapsed().as_nanos() as u64 })),
        Err(e) => {
            let _ = super::rmtree::remove_all(&tmp);
            Err(e)
        }
    }
}

/// Makes a folder from [`unpack_streamed`] the layer `digest`, whose tar
/// the host checked to be `diff_id`: recorded in its marker, so a later
/// pull of the same blob is answered with it (see [`recorded_diff_id`]).
pub fn keep(root: &Path, digest: &str, folder: &Path, diff_id: &str) -> io::Result<()> {
    install(root, digest, folder, &dir(root, digest)?)?;
    record_diff_id(root, digest, diff_id)
}

/// The diff_id a whole layer's marker records, when it records one (layers
/// unpacked by [`keep`]; older markers are empty).
pub fn recorded_diff_id(root: &Path, digest: &str) -> Option<String> {
    if !present(root, digest) {
        return None;
    }
    let s = fs::read_to_string(marker(root, digest).ok()?).ok()?;
    let s = s.trim();
    (s.len() == 71 && s.starts_with("sha256:") && s[7..].bytes().all(|b| b.is_ascii_hexdigit())).then(|| s.to_owned())
}

/// Writes `diff_id` into a whole layer's marker (by a rename, so the marker
/// is never seen half written).
pub fn record_diff_id(root: &Path, digest: &str, diff_id: &str) -> io::Result<()> {
    if !present(root, digest) || recorded_diff_id(root, digest).as_deref() == Some(diff_id) {
        return Ok(());
    }
    let m = marker(root, digest)?;
    let tmp = root.join(format!(".tmp-mark-{}-{}", hex(digest)?, std::process::id()));
    let mut f = fs::File::create(&tmp)?;
    io::Write::write_all(&mut f, diff_id.as_bytes())?;
    f.sync_all()?;
    fs::rename(&tmp, &m)
}

/// The diff_id of a blob (its tar's digest), read whole without unpacking
/// it; the blob must hash to `digest`. For a layer already unpacked whose
/// marker records no diff_id: the host compares it with the image's config
/// as it compares a fresh unpack's.
pub fn diff_id_of(blob: &mut impl Read, digest: &str, media_type: &str) -> io::Result<String> {
    let mut blob = Hashing { inner: blob, hash: sha2::Sha256::new() };
    let diff_id = {
        let buffered = BufReader::with_capacity(256 * 1024, &mut blob);
        let tar: Box<dyn Read> = if media_type.ends_with("gzip") {
            Box::new(flate2::read::MultiGzDecoder::new(buffered))
        } else if media_type.ends_with("zstd") {
            Box::new(kiri_zstd::Frames::new(buffered))
        } else {
            Box::new(buffered)
        };
        let mut tar = Hashing { inner: Capped { inner: tar, left: 64 << 30 }, hash: sha2::Sha256::new() };
        io::copy(&mut tar, &mut io::sink())?;
        digest_of(tar.hash)
    };
    io::copy(&mut blob, &mut io::sink())?;
    let got = digest_of(blob.hash);
    if got != digest {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("layer {digest} arrived as {got}")));
    }
    Ok(diff_id)
}

/// Puts an unpacked layer in place: its files reach the disk first, then
/// the directory is renamed in, then the marker says it is whole.
fn install(root: &Path, digest: &str, tmp: &Path, final_dir: &Path) -> io::Result<()> {
    if present(root, digest) {
        let _ = super::rmtree::remove_all(tmp);
        return Ok(());
    }
    sync_fs(tmp)?;
    if final_dir.exists() {
        // A copy without a marker was cut short and may hold empty files.
        // Moved aside rather than deleted here, which can take a while;
        // the next RetainLayers clears it.
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        fs::rename(final_dir, root.join(format!(".stale-{}-{nanos}", hex(digest)?)))?;
    }
    fs::rename(tmp, final_dir)?;
    fs::File::create(marker(root, digest)?)?.sync_all()?;
    fs::File::open(root)?.sync_all()
}

/// Flushes the filesystem holding `path` to disk.
fn sync_fs(path: &Path) -> io::Result<()> {
    let f = fs::File::open(path)?;
    // SAFETY: a valid descriptor that outlives the call.
    sys::check(unsafe { libc::syncfs(std::os::fd::AsRawFd::as_raw_fd(&f)) } as _, "syncfs")?;
    Ok(())
}

/// Deletes every layer not in `keep` (blob digests), every layer without
/// its marker, and whatever an unpack left half-done. Anything that isn't
/// one of those names is left alone.
pub fn retain<'a>(root: &Path, keep: impl Iterator<Item = &'a str>) {
    let keep: std::collections::HashSet<&str> = keep.filter_map(|d| hex(d).ok()).collect();
    let Ok(entries) = fs::read_dir(root) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let leftover = name.starts_with(".tmp-") || name.starts_with(".stale-");
        let (h, is_marker) = match name.strip_suffix(".done") {
            Some(h) => (h, true),
            None => (name, false),
        };
        let layer = h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit());
        if !leftover && !layer {
            continue;
        }
        let whole = layer && root.join(h).is_dir() && root.join(format!("{h}.done")).is_file();
        if leftover || !keep.contains(h) || !whole {
            let path = entry.path();
            let _ = if is_marker || !path.is_dir() { fs::remove_file(&path) } else { super::rmtree::remove_all(&path) };
        }
    }
}

/// The most a layer may expand to. The blob's digest covers only its
/// compressed bytes, so a tiny, digest-valid layer could otherwise expand
/// without limit onto the disk (on a Linux host or in WSL, the host's own).
/// 256x the compressed size, never below 1 GiB nor above 64 GiB.
fn expansion_cap(compressed: u64) -> u64 {
    compressed.saturating_mul(256).clamp(1 << 30, 64 << 30)
}

/// A reader that fails once more than `left` bytes have come through.
struct Capped<R> {
    inner: R,
    left: u64,
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n as u64 > self.left {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "layer expands beyond its allowed size"));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

fn unpack(blob: &mut impl Read, media_type: &str, dest: &Path, compressed: u64) -> io::Result<u64> {
    unpack_capped(blob, media_type, dest, expansion_cap(compressed))
}

fn unpack_capped(blob: &mut impl Read, media_type: &str, dest: &Path, left: u64) -> io::Result<u64> {
    let buffered = BufReader::with_capacity(256 * 1024, blob);
    if media_type.ends_with("gzip") {
        untar(Capped { inner: flate2::read::MultiGzDecoder::new(buffered), left }, dest)
    } else if media_type.ends_with("zstd") {
        // Every frame, to the end of the stream: what follows the tar's end
        // (zstd:chunked's table of contents, in skippable frames) is read
        // too, so a damaged or cut-short stream is refused as containerd
        // refuses it, and counts toward the cap.
        let mut frames = Capped { inner: kiri_zstd::Frames::new(buffered), left };
        let total = untar(&mut frames, dest)?;
        io::copy(&mut frames, &mut io::sink())?;
        Ok(total)
    } else {
        untar(Capped { inner: buffered, left }, dest)
    }
}

/// Unpacks a layer tarball, translating OCI whiteouts into the form overlayfs
/// reads: `.wh.name` becomes a 0:0 character device `name`, and
/// `.wh..wh..opq` marks its directory opaque.
fn untar(reader: impl Read, dest: &Path) -> io::Result<u64> {
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(true);
    archive.set_preserve_mtime(true);
    // Set below, without trusted.*: the kernel's own records (overlayfs
    // reads trusted.overlay.opaque, redirect and metacopy on these very
    // folders as layers) come from the whiteouts alone, never from what an
    // image's archive claims. Docker's store holds none either.
    archive.set_unpack_xattrs(false);
    archive.set_overwrite(true);
    let mut total = 0u64;
    // Each folder's time from its entry, set once everything is in: a
    // file made in it later would change it again.
    let mut dir_times: Vec<(PathBuf, i64)> = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if entry.header().entry_type().is_dir() {
            dir_times.push((path.clone(), entry.header().mtime().unwrap_or(0) as i64));
        }
        let name = path.file_name().map(|n| n.as_bytes()).unwrap_or_default();
        if let Some(hidden) = name.strip_prefix(b".wh.") {
            // `.wh.`, `.wh..` and `.wh...` would hide the directory itself or its parent.
            if matches!(hidden, b"" | b"." | b"..") {
                return Err(escapes());
            }
            let parent = whiteout_dir(dest, path.parent().unwrap_or(Path::new("")))?;
            if hidden == b".wh..opq" {
                let p = sys::cstr(&parent)?;
                // SAFETY: valid NUL-terminated path, name and a 1-byte value.
                let ret = unsafe {
                    libc::setxattr(p.as_ptr(), c"trusted.overlay.opaque".as_ptr(), b"y".as_ptr().cast(), 1, 0)
                };
                sys::check(ret as _, "mark opaque")?;
            } else {
                let target = parent.join(std::ffi::OsStr::from_bytes(hidden));
                let _ = fs::remove_file(&target);
                let _ = super::rmtree::remove_all(&target);
                sys::mknod(&sys::cstr(&target)?, libc::S_IFCHR, 0, 0)?;
            }
            continue;
        }
        total += entry.size();
        if entry.header().entry_type().is_hard_link() {
            let source = entry.link_name()?.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "hard link has no target"))?;
            let root = inroot::open_root(dest)?;
            let (from, source) = hardlink_parent(root.as_fd(), &source)?;
            let (to, name) = hardlink_parent(root.as_fd(), &path)?;
            // SAFETY: parents are confined directory fds and names are NUL-terminated.
            // A name already there (a layer made from the one below: see
            // `receive_delta`) is replaced, never written through. Flags 0
            // links the symlink itself, without following its absolute target.
            let ret = unsafe {
                libc::unlinkat(to.as_raw_fd(), name.as_ptr(), 0);
                libc::linkat(from.as_raw_fd(), source.as_ptr(), to.as_raw_fd(), name.as_ptr(), 0)
            };
            sys::check(ret as _, "hard link")?;
        } else if let Some(kind) = special_kind(entry.header().entry_type()) {
            make_special(dest, &path, entry.header(), kind)?;
        } else {
            let xattrs = entry_xattrs(&mut entry)?;
            if entry.unpack_in(dest)? {
                keep_zero_time(dest, &path, entry.header())?;
                set_xattrs(dest, &path, &xattrs)?;
            }
        }
    }
    set_dir_times(dest, &dir_times)?;
    Ok(total)
}

/// Whether an extended attribute named so may be set from what an image, a
/// build or a copy says: one rule for every place the agent sets them.
/// `trusted.*` never (overlayfs reads `trusted.overlay.opaque`, `redirect`
/// and `metacopy` on these very folders, so a claimed one would change what
/// a layer shows; Docker's store holds none either). `security.*` is kept,
/// as go-archive and BuildKit keep `security.capability` (file
/// capabilities); `user.*` and the rest are kept.
pub fn xattr_from_input(name: &[u8]) -> bool {
    !name.starts_with(b"trusted.")
}

/// An entry's `SCHILY.xattr.*` records, trusted.* left out.
fn entry_xattrs<R: Read>(entry: &mut tar::Entry<'_, R>) -> io::Result<Vec<(CString, Vec<u8>)>> {
    let mut out = Vec::new();
    if let Some(exts) = entry.pax_extensions()? {
        for ext in exts {
            let ext = ext?;
            let Some(name) = ext.key_bytes().strip_prefix(b"SCHILY.xattr.") else { continue };
            if !xattr_from_input(name) {
                continue;
            }
            let k = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
            out.push((k, ext.value_bytes().to_vec()));
        }
    }
    Ok(out)
}

/// Sets xattrs on what an entry unpacked, found inside the layer the way
/// the tar crate placed it (a leading `/` dropped), by its folder's
/// descriptor and never through a symlink on the way; the object itself is
/// not followed either (lsetxattr), so a link gets them as itself. Never by
/// joining the entry's name to `dest`: an absolute name would then be a
/// path outside the layer. Where the file system or the kind of file takes
/// none, they are left out, as go-archive leaves them.
fn set_xattrs(dest: &Path, path: &Path, xattrs: &[(CString, Vec<u8>)]) -> io::Result<()> {
    if xattrs.is_empty() {
        return Ok(());
    }
    let root = inroot::open_root(dest)?;
    let (parent, name) = inroot::parent_strict(root.as_fd(), path)?;
    let c = inroot::at_path(parent.as_fd(), &name);
    for (k, v) in xattrs {
        // SAFETY: valid NUL-terminated path and name, a value of that length.
        if unsafe { libc::lsetxattr(c.as_ptr(), k.as_ptr(), v.as_ptr().cast(), v.len(), 0) } != 0 {
            let e = io::Error::last_os_error();
            if !matches!(e.raw_os_error(), Some(libc::ENOTSUP | libc::EPERM)) {
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Puts back a time of 0 the tar crate made 1 (it does so for every 0, so
/// that tools which take 0 for "no time" see one). Docker keeps the 0, and
/// what a container or a build reads must be what the archive says. A
/// folder's time is set at the end from its entry, and needs none of this.
pub(crate) fn keep_zero_time(dest: &Path, path: &Path, h: &tar::Header) -> io::Result<()> {
    if h.mtime()? != 0 || h.entry_type().is_dir() || h.entry_type().is_hard_link() {
        return Ok(());
    }
    let root = inroot::open_root(dest)?;
    let (parent, name) = hardlink_parent(root.as_fd(), path)?;
    let t = [libc::timespec { tv_sec: 0, tv_nsec: 0 }, libc::timespec { tv_sec: 0, tv_nsec: 0 }];
    // SAFETY: a confined parent descriptor, a NUL-terminated name and two timespecs.
    sys::check(unsafe { libc::utimensat(parent.as_raw_fd(), name.as_ptr(), t.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) } as _, "set time")?;
    Ok(())
}

/// The file type of a device or fifo entry, which the tar crate would
/// unpack as an empty regular file.
fn special_kind(t: tar::EntryType) -> Option<libc::mode_t> {
    if t.is_character_special() {
        Some(libc::S_IFCHR)
    } else if t.is_block_special() {
        Some(libc::S_IFBLK)
    } else if t.is_fifo() {
        Some(libc::S_IFIFO)
    } else {
        None
    }
}

/// Makes a device node or fifo at `path` inside `dest` with the entry's
/// numbers, owner, mode and time, replacing what is there. The parent is
/// looked up inside the layer, as a hard link's is.
fn make_special(dest: &Path, path: &Path, h: &tar::Header, kind: libc::mode_t) -> io::Result<()> {
    let root = inroot::open_root(dest)?;
    let (parent, name) = hardlink_parent(root.as_fd(), path)?;
    let mode = (h.mode()? & 0o7777) as libc::mode_t;
    let (major, minor) = (h.device_major()?.unwrap_or(0), h.device_minor()?.unwrap_or(0));
    let dev = libc::makedev(major, minor);
    let (uid, gid) = (h.uid()? as libc::uid_t, h.gid()? as libc::gid_t);
    let mtime = h.mtime()? as i64;
    let p = parent.as_raw_fd();
    let t = [libc::timespec { tv_sec: mtime, tv_nsec: 0 }, libc::timespec { tv_sec: mtime, tv_nsec: 0 }];
    // SAFETY: a confined parent descriptor and a single NUL-terminated name.
    unsafe {
        libc::unlinkat(p, name.as_ptr(), 0);
        sys::check(libc::mknodat(p, name.as_ptr(), kind | mode, dev) as _, "mknod")?;
        sys::check(libc::fchownat(p, name.as_ptr(), uid, gid, libc::AT_SYMLINK_NOFOLLOW) as _, "chown")?;
        // mknod applies the umask.
        sys::check(libc::fchmodat(p, name.as_ptr(), mode, 0) as _, "chmod")?;
        sys::check(libc::utimensat(p, name.as_ptr(), t.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) as _, "set time")?;
    }
    Ok(())
}

/// Sets each folder's mtime (and atime), looked up inside `dest`.
fn set_dir_times(dest: &Path, times: &[(PathBuf, i64)]) -> io::Result<()> {
    if times.is_empty() {
        return Ok(());
    }
    let root = inroot::open_root(dest)?;
    for (rel, secs) in times {
        let Ok(at) = inroot::lookup(root.as_fd(), rel) else { continue };
        let at = inroot::Found { fd: at, created: false };
        let t = [libc::timespec { tv_sec: *secs, tv_nsec: 0 }, libc::timespec { tv_sec: *secs, tv_nsec: 0 }];
        // SAFETY: a valid NUL-terminated path (the descriptor's magic link) and two timespecs.
        sys::check(unsafe { libc::utimensat(libc::AT_FDCWD, at.proc_path().as_ptr(), t.as_ptr(), 0) } as _, "set folder time")?;
    }
    Ok(())
}

/// Makes the layer `new` from the unpacked layer `base` and a delta tar:
/// every file of `base` not in `removed` is hard-linked into the new folder
/// (folders are made new), then the delta (every folder entry, every new or
/// changed entry) is unpacked over it, folder times last. A changed file
/// replaces its link, never writes through it, so `base` stays as it is;
/// an unchanged file has the same header in both, so sharing its inode is
/// exact. Only the delta's bytes cross from the host. Reads exactly what
/// `delta` gives; the layer appears whole or not at all, as `receive`'s.
pub fn receive_delta(delta: &mut impl Read, base: &str, new: &str, removed: &[&str], root: &Path) -> io::Result<LayerStored> {
    let started = Instant::now();
    let final_dir = dir(root, new)?;
    if present(root, new) {
        io::copy(delta, &mut io::sink())?;
        return Ok(LayerStored { unpacked_bytes: 0, elapsed_ns: started.elapsed().as_nanos() as u64 });
    }
    if !present(root, base) {
        io::copy(delta, &mut io::sink())?;
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("layer {base} is not unpacked")));
    }
    let tmp = fresh_tmp(root, new)?;
    let removed: std::collections::HashSet<PathBuf> = removed.iter().map(|p| PathBuf::from(p.trim_matches('/'))).collect();
    let result = link_farm(&dir(root, base)?, &tmp, Path::new(""), &removed)
        .and_then(|()| untar(Capped { inner: BufReader::with_capacity(256 * 1024, &mut *delta), left: u64::MAX }, &tmp));
    io::copy(delta, &mut io::sink())?;
    match result.and_then(|n| install(root, new, &tmp, &final_dir).map(|()| n)) {
        Ok(unpacked_bytes) => Ok(LayerStored { unpacked_bytes, elapsed_ns: started.elapsed().as_nanos() as u64 }),
        Err(e) => {
            let _ = super::rmtree::remove_all(&tmp);
            Err(e)
        }
    }
}

/// `base/rel` into `to/rel`: folders made anew with the same owner, mode
/// and xattrs, everything else hard-linked. Nothing is followed: a
/// symlink is linked as itself. The folders still to fill are a list, not
/// a recursion: a layer may be of any depth.
fn link_farm(base: &Path, to: &Path, rel: &Path, removed: &std::collections::HashSet<PathBuf>) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let mut todo = vec![rel.to_path_buf()];
    while let Some(rel) = todo.pop() {
        for e in fs::read_dir(base.join(&rel))? {
            let e = e?;
            let r = rel.join(e.file_name());
            if removed.contains(&r) {
                continue;
            }
            let m = fs::symlink_metadata(e.path())?;
            let dst = to.join(&r);
            if m.is_dir() {
                fs::create_dir(&dst)?;
                let c = sys::cstr(&dst)?;
                // SAFETY: valid NUL-terminated path.
                sys::check(unsafe { libc::lchown(c.as_ptr(), m.uid(), m.gid()) } as _, "chown")?;
                fs::set_permissions(&dst, fs::Permissions::from_mode(m.mode() & 0o7777))?;
                copy_xattrs(&e.path(), &dst)?;
                todo.push(r);
            } else {
                fs::hard_link(e.path(), &dst)?;
            }
        }
    }
    Ok(())
}

/// A folder's xattrs (an overlay opaque mark, `user.*`) onto its copy.
fn copy_xattrs(from: &Path, to: &Path) -> io::Result<()> {
    let (f, t) = (sys::cstr(from)?, sys::cstr(to)?);
    let mut names = vec![0u8; 4096];
    // SAFETY: valid path; at most names.len() bytes written.
    let n = unsafe { libc::llistxattr(f.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
    if n <= 0 {
        return Ok(());
    }
    for name in names[..n as usize].split(|b| *b == 0).filter(|n| !n.is_empty()) {
        let k = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        let mut v = vec![0u8; 65536];
        // SAFETY: valid path and name; at most v.len() bytes written.
        let len = unsafe { libc::lgetxattr(f.as_ptr(), k.as_ptr(), v.as_mut_ptr().cast(), v.len()) };
        if len < 0 {
            continue;
        }
        // SAFETY: valid path, name and value of that length.
        sys::check(unsafe { libc::lsetxattr(t.as_ptr(), k.as_ptr(), v.as_ptr().cast(), len as usize, 0) } as _, "copy xattr")?;
    }
    Ok(())
}

fn escapes() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "archive path escapes the layer")
}

fn hardlink_parent(root: BorrowedFd<'_>, path: &Path) -> io::Result<(OwnedFd, CString)> {
    let mut relative = PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::Normal(name) => relative.push(name),
            std::path::Component::CurDir | std::path::Component::RootDir => {}
            _ => return Err(escapes()),
        }
    }
    let name = relative.file_name().ok_or_else(escapes)?;
    let parent = inroot::open(root, relative.parent().unwrap_or(Path::new("")), inroot::Last::Dir)?;
    Ok((parent.fd, sys::cstr(Path::new(name))?))
}

/// The directory under `dest` a whiteout lives in, made if missing. Every
/// step must be a real directory of this layer: an earlier entry could have
/// made one a symlink, which a check of the path's text cannot see and which
/// would carry the whiteout outside the layer.
fn whiteout_dir(dest: &Path, parent: &Path) -> io::Result<PathBuf> {
    let mut dir = dest.to_path_buf();
    for part in parent.components() {
        match part {
            std::path::Component::Normal(name) => dir.push(name),
            std::path::Component::CurDir => continue,
            _ => return Err(escapes()),
        }
        match fs::symlink_metadata(&dir) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(escapes()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => fs::create_dir(&dir)?,
            Err(e) => return Err(e),
        }
    }
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete header: tar-rs refuses to unpack one with empty uid/gid.
    fn header(size: u64, mode: u32) -> tar::Header {
        let mut h = tar::Header::new_gnu();
        h.set_size(size);
        h.set_mode(mode);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(0);
        h.set_cksum();
        h
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kiri-layers-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// A layer's archive cannot put the kernel's overlay records on what it
    /// unpacks (they would hide or redirect folders of the layers below);
    /// an opaque folder comes from its whiteout; other xattrs are kept.
    /// Run as root (trusted.* needs it), or it checks nothing about them.
    #[test]
    fn a_layer_archive_never_sets_trusted_xattrs() {
        let mut b = tar::Builder::new(Vec::new());
        b.append_pax_extensions([
            ("SCHILY.xattr.trusted.overlay.redirect", &b"/etc"[..]),
            ("SCHILY.xattr.trusted.overlay.opaque", &b"y"[..]),
            ("SCHILY.xattr.user.kept", &b"1"[..]),
        ])
        .unwrap();
        let mut h = header(0, 0o755);
        h.set_entry_type(tar::EntryType::Directory);
        b.append_data(&mut h, "d/", &[][..]).unwrap();
        b.append_pax_extensions([("SCHILY.xattr.trusted.overlay.metacopy", &b""[..])]).unwrap();
        b.append_data(&mut header(1, 0o644), "f", &b"x"[..]).unwrap();
        b.append_data(&mut header(0, 0o644), "o/.wh..wh..opq", &[][..]).unwrap();
        let bytes = b.into_inner().unwrap();
        let dest = scratch("trusted");
        untar(Capped { inner: &bytes[..], left: u64::MAX }, &dest).unwrap();
        let get = |p: &str, n: &std::ffi::CStr| {
            let c = sys::cstr(dest.join(p)).unwrap();
            let mut v = [0u8; 64];
            // SAFETY: valid path and name; at most v.len() bytes written.
            let n = unsafe { libc::lgetxattr(c.as_ptr(), n.as_ptr(), v.as_mut_ptr().cast(), v.len()) };
            (n >= 0).then(|| v[..n as usize].to_vec())
        };
        assert_eq!(get("d", c"trusted.overlay.redirect"), None);
        assert_eq!(get("d", c"trusted.overlay.opaque"), None);
        assert_eq!(get("f", c"trusted.overlay.metacopy"), None);
        // SAFETY: getuid cannot fail.
        if unsafe { libc::getuid() } == 0 {
            assert_eq!(get("o", c"trusted.overlay.opaque"), Some(b"y".to_vec()), "the whiteout's opaque mark");
        }
        let user = get("d", c"user.kept");
        assert!(user.is_none() || user == Some(b"1".to_vec()));
        fs::remove_dir_all(dest).unwrap();
    }

    fn xattr_of(p: &Path, n: &std::ffi::CStr) -> Option<Vec<u8>> {
        let c = sys::cstr(p).unwrap();
        let mut v = [0u8; 64];
        // SAFETY: valid path and name; at most v.len() bytes written.
        let n = unsafe { libc::lgetxattr(c.as_ptr(), n.as_ptr(), v.as_mut_ptr().cast(), v.len()) };
        (n >= 0).then(|| v[..n as usize].to_vec())
    }

    /// An entry whose name is written as given (the tar crate's builder
    /// refuses absolute names and `..`), after a PAX record of `pax`.
    fn raw_entry(b: &mut tar::Builder<Vec<u8>>, name: &[u8], kind: tar::EntryType, link: Option<&str>, pax: &[(&str, &[u8])]) {
        if !pax.is_empty() {
            b.append_pax_extensions(pax.iter().copied()).unwrap();
        }
        let mut h = header(0, if kind.is_dir() { 0o755 } else { 0o644 });
        h.set_entry_type(kind);
        h.as_old_mut().name[..name.len()].copy_from_slice(name);
        if let Some(l) = link {
            h.set_link_name(l).unwrap();
        }
        h.set_cksum();
        b.append(&h, &[][..]).unwrap();
    }

    /// An entry's extended attributes land on what it unpacked inside the
    /// layer, never on a path outside it: an absolute name (in the header
    /// or in a PAX `path` record) is unpacked inside the layer, and its
    /// attributes go there too; `..`, a symlinked folder made earlier in
    /// the same layer and a folder replaced by a symlink by a later entry
    /// lead nowhere outside. Before, `dest.join("/abs")` was `/abs`, and
    /// the agent set the attribute on its own root's file (the host's on a
    /// Linux host).
    #[test]
    fn extended_attributes_stay_inside_the_layer() {
        let base = scratch("xattr-confined");
        let (dest, outside) = (base.join("layer"), base.join("outside"));
        fs::create_dir_all(&dest).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("victim");
        fs::write(&victim, "keep").unwrap();
        // Whether user.* can be set here at all (tmpfs takes it from 6.6).
        let probe = sys::cstr(&base.join("outside")).unwrap();
        // SAFETY: valid path, name and value.
        let user_ok = unsafe { libc::lsetxattr(probe.as_ptr(), c"user.probe".as_ptr(), b"1".as_ptr().cast(), 1, 0) } == 0;
        let abs = victim.as_os_str().as_bytes();
        let rel_up = String::from("../outside/victim");
        let mark: &[(&str, &[u8])] = &[("SCHILY.xattr.user.kiri", b"set")];
        let mut b = tar::Builder::new(Vec::new());
        // 1: an absolute name in the header.
        raw_entry(&mut b, abs, tar::EntryType::Regular, None, mark);
        // 2: an absolute name in a PAX path record.
        b.append_pax_extensions([("path", abs), ("SCHILY.xattr.user.kiri", &b"pax"[..])]).unwrap();
        let mut h = header(0, 0o644);
        h.set_path("short").unwrap();
        h.set_cksum();
        b.append(&h, &[][..]).unwrap();
        // 3: `..`.
        raw_entry(&mut b, rel_up.as_bytes(), tar::EntryType::Regular, None, mark);
        // 4: through a folder that an earlier entry made a symlink to outside.
        raw_entry(&mut b, b"lnk", tar::EntryType::Symlink, Some(outside.to_str().unwrap()), &[]);
        raw_entry(&mut b, b"lnk/victim", tar::EntryType::Regular, None, mark);
        // 5: a folder, then the same name replaced by a symlink, then a file under it.
        raw_entry(&mut b, b"swap/", tar::EntryType::Directory, None, &[]);
        raw_entry(&mut b, b"swap", tar::EntryType::Symlink, Some(outside.to_str().unwrap()), &[]);
        raw_entry(&mut b, b"swap/victim", tar::EntryType::Regular, None, mark);
        // 6: a symlink entry with an attribute: set on the link, never on what it points at.
        raw_entry(&mut b, b"tolink", tar::EntryType::Symlink, Some(victim.to_str().unwrap()), mark);
        let bytes = b.into_inner().unwrap();
        // Some of these the unpack refuses (the tar crate's own checks): an
        // error is fine; what matters is what is left outside.
        let r = untar(Capped { inner: &bytes[..], left: u64::MAX }, &dest);
        assert_eq!(xattr_of(&victim, c"user.kiri"), None, "an attribute was set outside the layer (unpack: {r:?})");
        assert_eq!(xattr_of(&outside, c"user.kiri"), None);
        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
        // Run each kind alone too, so a refusal of one cannot hide another.
        for (i, entries) in [&[0usize][..], &[1], &[2], &[3, 4], &[5, 6, 7], &[8]].iter().enumerate() {
            let mut b = tar::Builder::new(Vec::new());
            for e in *entries {
                match e {
                    0 => raw_entry(&mut b, abs, tar::EntryType::Regular, None, mark),
                    1 => {
                        b.append_pax_extensions([("path", abs), ("SCHILY.xattr.user.kiri", &b"pax"[..])]).unwrap();
                        let mut h = header(0, 0o644);
                        h.set_path("short").unwrap();
                        h.set_cksum();
                        b.append(&h, &[][..]).unwrap();
                    }
                    2 => raw_entry(&mut b, rel_up.as_bytes(), tar::EntryType::Regular, None, mark),
                    3 => raw_entry(&mut b, b"lnk", tar::EntryType::Symlink, Some(outside.to_str().unwrap()), &[]),
                    4 => raw_entry(&mut b, b"lnk/victim", tar::EntryType::Regular, None, mark),
                    5 => raw_entry(&mut b, b"swap/", tar::EntryType::Directory, None, &[]),
                    6 => raw_entry(&mut b, b"swap", tar::EntryType::Symlink, Some(outside.to_str().unwrap()), &[]),
                    7 => raw_entry(&mut b, b"swap/victim", tar::EntryType::Regular, None, mark),
                    _ => raw_entry(&mut b, b"tolink", tar::EntryType::Symlink, Some(victim.to_str().unwrap()), mark),
                }
            }
            let d = base.join(format!("alone-{i}"));
            fs::create_dir_all(&d).unwrap();
            let r = untar(Capped { inner: &b.into_inner().unwrap()[..], left: u64::MAX }, &d);
            assert_eq!(xattr_of(&victim, c"user.kiri"), None, "case {i}: set outside the layer (unpack: {r:?})");
            // The absolute names land inside, with their attribute.
            if user_ok && i < 2 {
                r.unwrap();
                let inside = d.join(victim.strip_prefix("/").unwrap());
                assert_eq!(xattr_of(&inside, c"user.kiri"), Some(if i == 0 { b"set".to_vec() } else { b"pax".to_vec() }), "case {i}: on the unpacked file");
            }
        }
        fs::remove_dir_all(&base).unwrap();
    }

    /// Ordinary images keep the attributes they had: file capabilities on a
    /// binary, user.* on a file and on a folder, on the same objects as
    /// when the tar crate set them itself.
    #[test]
    fn ordinary_extended_attributes_are_kept() {
        // SAFETY: getuid cannot fail.
        if unsafe { libc::getuid() } != 0 {
            eprintln!("skipped: security.capability needs root");
            return;
        }
        // VFS_CAP_REVISION_2 with cap_net_bind_service permitted and effective.
        let cap: [u8; 20] = [0, 0, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut b = tar::Builder::new(Vec::new());
        b.append_pax_extensions([("SCHILY.xattr.user.dir", &b"d"[..])]).unwrap();
        let mut h = header(0, 0o755);
        h.set_entry_type(tar::EntryType::Directory);
        b.append_data(&mut h, "usr/bin/", &[][..]).unwrap();
        b.append_pax_extensions([("SCHILY.xattr.security.capability", &cap[..])]).unwrap();
        b.append_data(&mut header(2, 0o755), "usr/bin/ping", &b"\x7fE"[..]).unwrap();
        b.append_pax_extensions([("SCHILY.xattr.user.file", &b"f"[..])]).unwrap();
        b.append_data(&mut header(1, 0o644), "etc/conf", &b"x"[..]).unwrap();
        let dest = scratch("xattr-ordinary");
        untar(Capped { inner: &b.into_inner().unwrap()[..], left: u64::MAX }, &dest).unwrap();
        assert_eq!(xattr_of(&dest.join("usr/bin/ping"), c"security.capability"), Some(cap.to_vec()));
        let probe = xattr_of(&dest.join("etc/conf"), c"user.file");
        if probe.is_some() {
            assert_eq!(probe, Some(b"f".to_vec()));
            assert_eq!(xattr_of(&dest.join("usr/bin"), c"user.dir"), Some(b"d".to_vec()));
        } else {
            eprintln!("user.* not taken by this file system: only the capability checked");
        }
        fs::remove_dir_all(&dest).unwrap();
    }

    /// A layer's temporary folder has a name no one can guess ahead (the
    /// process and a random part) and is made new: never one that is
    /// already there, a link to elsewhere included.
    #[test]
    fn a_temporary_layer_folder_is_unpredictable_and_new() {
        let root = scratch("tmpname");
        let digest = format!("sha256:{}", "cd".repeat(32));
        let (a, b) = (fresh_tmp(&root, &digest).unwrap(), fresh_tmp(&root, &digest).unwrap());
        assert_ne!(a, b);
        for t in [&a, &b] {
            let name = t.file_name().unwrap().to_str().unwrap();
            assert!(name.starts_with(&format!(".tmp-{}-{}-", "cd".repeat(32), std::process::id())), "{name}");
            assert!(fs::symlink_metadata(t).unwrap().is_dir());
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn hardlinks_preserve_source_inode() {
        use std::os::unix::fs::MetadataExt;

        for (i, link) in [None, Some("target"), Some("/target"), Some("/missing-target")].into_iter().enumerate() {
            let mut b = tar::Builder::new(Vec::new());
            b.append_data(&mut header(2, 0o644), "target", &b"[]"[..]).unwrap();
            let source = if let Some(to) = link {
                let mut h = header(0, 0o777);
                h.set_entry_type(tar::EntryType::Symlink);
                b.append_link(&mut h, "source", to).unwrap();
                "source"
            } else {
                "target"
            };
            let mut h = header(0, 0o777);
            h.set_entry_type(tar::EntryType::Link);
            b.append_link(&mut h, "nested/manifest.nix", source).unwrap();
            let bytes = b.into_inner().unwrap();
            let dest = scratch(&format!("hardlink-{i}"));
            untar(Capped { inner: &bytes[..], left: u64::MAX }, &dest).unwrap();
            let from = fs::symlink_metadata(dest.join(source)).unwrap();
            let to = fs::symlink_metadata(dest.join("nested/manifest.nix")).unwrap();
            assert_eq!((from.dev(), from.ino()), (to.dev(), to.ino()), "{link:?}");
            if let Some(link) = link {
                assert_eq!(fs::read_link(dest.join("nested/manifest.nix")).unwrap(), Path::new(link));
            } else {
                assert_eq!(fs::read(dest.join("nested/manifest.nix")).unwrap(), b"[]");
            }
            fs::remove_dir_all(dest).unwrap();
        }
    }

    #[test]
    fn hardlinks_resolve_parents_inside_layer() {
        use std::os::unix::fs::MetadataExt;

        let mut b = tar::Builder::new(Vec::new());
        b.append_data(&mut header(1, 0o644), "dir/file", &b"x"[..]).unwrap();
        let mut h = header(0, 0o777);
        h.set_entry_type(tar::EntryType::Symlink);
        b.append_link(&mut h, "alias", "dir").unwrap();
        let mut h = header(0, 0o777);
        h.set_entry_type(tar::EntryType::Link);
        b.append_link(&mut h, "alias/copy", "alias/file").unwrap();
        let bytes = b.into_inner().unwrap();
        let dest = scratch("hardlink-parents");
        untar(Capped { inner: &bytes[..], left: u64::MAX }, &dest).unwrap();
        assert_eq!(fs::read(dest.join("dir/copy")).unwrap(), b"x");
        assert_eq!(fs::metadata(dest.join("dir/file")).unwrap().ino(), fs::metadata(dest.join("dir/copy")).unwrap().ino());
        fs::remove_dir_all(dest).unwrap();
    }

    #[test]
    fn hardlink_paths_cannot_escape_layer() {
        use std::os::unix::fs::MetadataExt;

        for (i, (source, target)) in [
            ("../outside/secret", "copied"),
            ("escape/secret", "copied"),
            ("file", "escape/copied"),
            ("file", "../outside/copied"),
        ].into_iter().enumerate() {
            let base = scratch(&format!("hardlink-escape-{i}"));
            let dest = base.join("layer");
            let outside = base.join("outside");
            fs::create_dir(&dest).unwrap();
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("secret"), b"keep").unwrap();
            let mut b = tar::Builder::new(Vec::new());
            b.append_data(&mut header(1, 0o644), "file", &b"x"[..]).unwrap();
            let mut h = header(0, 0o777);
            h.set_entry_type(tar::EntryType::Symlink);
            b.append_link(&mut h, "escape", &outside).unwrap();
            let mut h = header(0, 0o777);
            h.set_entry_type(tar::EntryType::Link);
            h.set_link_name(source).unwrap();
            // The builder refuses a traversal path; an untrusted archive need not.
            h.as_mut_bytes()[..target.len()].copy_from_slice(target.as_bytes());
            h.set_cksum();
            b.append(&h, io::empty()).unwrap();
            let bytes = b.into_inner().unwrap();
            let _ = untar(Capped { inner: &bytes[..], left: u64::MAX }, &dest);
            assert_eq!(fs::read_link(dest.join("escape")).unwrap(), outside);
            assert!(!dest.join("copied").exists());
            assert!(!outside.join("copied").exists());
            assert_eq!(fs::read(outside.join("secret")).unwrap(), b"keep");
            assert_eq!(fs::symlink_metadata(outside.join("secret")).unwrap().nlink(), 1);
            fs::remove_dir_all(base).unwrap();
        }
    }

    /// A layer whose first entry makes `foo` a symlink to `/` and whose
    /// second writes `foo/x` must not write outside the layer directory.
    #[test]
    fn symlink_parent_cannot_escape_layer() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = header(0, 0o777);
        h.set_entry_type(tar::EntryType::Symlink);
        b.append_link(&mut h, "foo", "/").unwrap();
        let mut h = header(1, 0o644);
        b.append_data(&mut h, "foo/x", &b"x"[..]).unwrap();
        let bytes = b.into_inner().unwrap();
        let dest = scratch("escape");
        let err = untar(Capped { inner: &bytes[..], left: u64::MAX }, &dest).expect_err("writing through a symlinked parent must fail");
        // The refusal must be the path check, not some other unpack error.
        assert!(err.to_string().contains("outside"), "unexpected error: {err}");
        assert!(!Path::new("/x").is_file() || fs::read_to_string("/x").map_or(true, |c| c != "x"), "escaped to /x");
        let _ = fs::remove_dir_all(&dest);
    }

    fn whiteout_layer(entries: &[(&str, Option<&str>)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, link) in entries {
            if let Some(to) = link {
                let mut h = header(0, 0o777);
                h.set_entry_type(tar::EntryType::Symlink);
                b.append_link(&mut h, name, to).unwrap();
            } else {
                let mut h = header(0, 0o644);
                b.append_data(&mut h, name, &[][..]).unwrap();
            }
        }
        b.into_inner().unwrap()
    }

    /// A whiteout under a symlink to a directory outside the layer must not
    /// delete, replace or mark anything there.
    #[test]
    fn whiteout_through_symlink_stays_in_layer() {
        let outside = scratch("wh-outside");
        fs::write(outside.join("victim"), "keep").unwrap();
        let to = outside.to_str().unwrap();
        for hidden in ["foo/.wh.victim", "foo/.wh..wh..opq"] {
            let dest = scratch("wh-escape");
            let bytes = whiteout_layer(&[("foo", Some(to)), (hidden, None)]);
            let err = untar(Capped { inner: &bytes[..], left: u64::MAX }, &dest).expect_err(hidden);
            assert!(err.to_string().contains("escapes"), "{hidden}: unexpected error: {err}");
            assert_eq!(fs::read_to_string(outside.join("victim")).unwrap(), "keep", "{hidden}");
            assert!(!outside.join(&hidden[4..]).exists(), "{hidden}: placeholder written outside");
            let _ = fs::remove_dir_all(&dest);
        }
        let _ = fs::remove_dir_all(&outside);
    }

    /// Whiteouts naming the directory itself or its parent are refused
    /// before anything is removed.
    #[test]
    fn whiteout_of_dot_or_dotdot_is_refused() {
        for hidden in ["d/.wh.", "d/.wh..", "d/.wh..."] {
            let dest = scratch("wh-dots");
            fs::create_dir_all(dest.join("d")).unwrap();
            fs::write(dest.join("d/keep"), "x").unwrap();
            let bytes = whiteout_layer(&[(hidden, None)]);
            let err = untar(Capped { inner: &bytes[..], left: u64::MAX }, &dest).expect_err(hidden);
            assert!(err.to_string().contains("escapes"), "{hidden}: unexpected error: {err}");
            assert!(dest.join("d/keep").is_file(), "{hidden}");
            let _ = fs::remove_dir_all(&dest);
        }
    }

    /// A whiteout whose own path is absolute (the tar builder won't write
    /// one, so the header is patched by hand) must not reach outside.
    #[test]
    fn whiteout_path_cannot_escape_layer() {
        let base = scratch("wh-abs");
        let dest = base.join("layer");
        fs::create_dir(&dest).unwrap();
        fs::write(base.join("keep"), "x").unwrap();
        let path = format!("{}/.wh.keep", base.display());
        let mut b = tar::Builder::new(Vec::new());
        b.append_data(&mut header(0, 0o644), "a".repeat(path.len()), &[][..]).unwrap();
        let mut bytes = b.into_inner().unwrap();
        bytes[..100].fill(0);
        bytes[..path.len()].copy_from_slice(path.as_bytes());
        bytes[148..156].fill(b' ');
        let checksum: u32 = bytes[..512].iter().map(|b| u32::from(*b)).sum();
        bytes[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        assert!(untar(Capped { inner: &bytes[..], left: u64::MAX }, &dest).is_err());
        assert!(base.join("keep").is_file());
        let _ = fs::remove_dir_all(&base);
    }

    /// A hard link to `/bin/tool` links the layer's `bin/tool`, as with Docker
    /// (issue 302). `..` is refused; `root` → `/` is followed inside the layer,
    /// where `etc/hostname` doesn't exist; nothing is linked in either case.
    #[test]
    fn absolute_hard_link_is_read_from_the_layer_root() {
        let layer = |to: &str| {
            let mut b = tar::Builder::new(Vec::new());
            b.append_data(&mut header(3, 0o755), "bin/tool", &b"hi\n"[..]).unwrap();
            let mut h = header(0, 0o777);
            h.set_entry_type(tar::EntryType::Symlink);
            b.append_link(&mut h, "root", "/").unwrap();
            let mut h = header(0, 0o755);
            h.set_entry_type(tar::EntryType::Link);
            b.append_link(&mut h, "bin/tool-1.0", to).unwrap();
            b.into_inner().unwrap()
        };
        let dest = scratch("abs-link");
        untar(Capped { inner: &layer("/bin/tool")[..], left: u64::MAX }, &dest).unwrap();
        let (tool, link) = (fs::metadata(dest.join("bin/tool")).unwrap(), fs::metadata(dest.join("bin/tool-1.0")).unwrap());
        assert_eq!(std::os::unix::fs::MetadataExt::ino(&link), std::os::unix::fs::MetadataExt::ino(&tool), "not a hard link");
        let _ = fs::remove_dir_all(&dest);

        for (to, why) in [("/../../etc/hostname", "escapes"), ("/root/etc/hostname", "No such file"), ("/bin/nope", "No such file")] {
            let dest = scratch("abs-link-bad");
            let err = untar(Capped { inner: &layer(to)[..], left: u64::MAX }, &dest).expect_err(to);
            assert!(err.to_string().contains(why), "{to}: unexpected error: {err}");
            assert!(!dest.join("bin/tool-1.0").exists(), "{to}: linked");
            let _ = fs::remove_dir_all(&dest);
        }
    }

    /// An ordinary whiteout becomes overlayfs's 0:0 character device and
    /// leaves no `.wh.` file behind. mknod needs root, as in the guest.
    #[test]
    fn whiteout_becomes_char_device() {
        // SAFETY: a plain getter.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipped: needs root for mknod");
            return;
        }
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let dest = scratch("wh-ok");
        fs::create_dir_all(dest.join("etc")).unwrap();
        fs::write(dest.join("etc/gone"), "x").unwrap();
        let bytes = whiteout_layer(&[("etc/.wh.gone", None)]);
        untar(Capped { inner: &bytes[..], left: u64::MAX }, &dest).unwrap();
        let m = fs::symlink_metadata(dest.join("etc/gone")).unwrap();
        assert!(m.file_type().is_char_device() && m.rdev() == 0, "not a 0:0 char device");
        assert!(!dest.join("etc/.wh.gone").exists(), "placeholder left behind");
        let _ = fs::remove_dir_all(&dest);
        // As `docker commit` writes them: no owner or time, which tar-rs
        // would refuse to unpack. A whiteout is never unpacked, so it works,
        // and missing parents are made.
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(0);
        h.set_mode(0o644);
        b.append_data(&mut h, "usr/share/.wh.doc", std::io::empty()).unwrap();
        let bytes = b.into_inner().unwrap();
        let dest = scratch("wh-bare");
        untar(Capped { inner: &bytes[..], left: u64::MAX }, &dest).unwrap();
        assert!(fs::symlink_metadata(dest.join("usr/share/doc")).unwrap().file_type().is_char_device());
        let _ = fs::remove_dir_all(&dest);
    }

    fn layer_blob(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, data) in files {
            b.append_data(&mut header(data.len() as u64, 0o644), name, *data).unwrap();
        }
        b.into_inner().unwrap()
    }

    const D1: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const D2: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    fn send(root: &Path, digest: &str, blob: &[u8]) -> LayerStored {
        let begin = LayerBegin { digest, media_type: "application/vnd.oci.image.layer.v1.tar", size: blob.len() as u64 };
        receive(&mut &blob[..], &begin, root).unwrap()
    }

    /// A stored layer is present only with its marker; one cut short
    /// (directory, no marker) is not, and is replaced when sent again.
    #[test]
    fn layer_without_marker_is_replaced() {
        let root = scratch("marker");
        let blob = layer_blob(&[("bin/sh", b"real")]);
        send(&root, D1, &blob);
        assert!(present(&root, D1));
        assert_eq!(fs::read(dir(&root, D1).unwrap().join("bin/sh")).unwrap(), b"real");

        // What a VM stopped before the flush leaves: names, empty contents.
        fs::remove_file(marker(&root, D1).unwrap()).unwrap();
        fs::write(dir(&root, D1).unwrap().join("bin/sh"), b"").unwrap();
        assert!(!present(&root, D1));
        send(&root, D1, &blob);
        assert!(present(&root, D1));
        assert_eq!(fs::read(dir(&root, D1).unwrap().join("bin/sh")).unwrap(), b"real");
        let _ = fs::remove_dir_all(&root);
    }

    /// Retain keeps whole layers it is told to and deletes the rest:
    /// unlisted layers, unmarked ones, leftovers. Other names stay.
    #[test]
    fn retain_deletes_unused_and_broken_layers() {
        let root = scratch("retain");
        let blob = layer_blob(&[("f", b"x")]);
        send(&root, D1, &blob);
        send(&root, D2, &blob);
        let broken = "3".repeat(64);
        fs::create_dir(root.join(&broken)).unwrap();
        fs::create_dir(root.join(format!(".stale-{broken}-1"))).unwrap();
        fs::create_dir(root.join(format!(".tmp-{broken}"))).unwrap();
        fs::write(root.join("other"), "keep").unwrap();

        retain(&root, [D1, &format!("sha256:{broken}")].into_iter());
        assert!(present(&root, D1));
        assert!(!dir(&root, D2).unwrap().exists() && !marker(&root, D2).unwrap().exists());
        assert!(!root.join(&broken).exists(), "unmarked layer kept");
        assert!(!root.join(format!(".stale-{broken}-1")).exists() && !root.join(format!(".tmp-{broken}")).exists());
        assert!(root.join("other").is_file());
        let _ = fs::remove_dir_all(&root);
    }

    fn tar_of(entries: &[(&str, char, &[u8], u64)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, kind, data, mtime) in entries {
            let mut h = header(0, 0o644);
            h.set_mtime(*mtime);
            match kind {
                'd' => {
                    h.set_entry_type(tar::EntryType::Directory);
                    h.set_mode(0o755);
                    h.set_cksum();
                    b.append_data(&mut h, name, &[][..]).unwrap();
                }
                'l' | 'h' => {
                    h.set_entry_type(if *kind == 'l' { tar::EntryType::Symlink } else { tar::EntryType::Link });
                    b.append_link(&mut h, name, std::str::from_utf8(data).unwrap()).unwrap();
                }
                _ => {
                    h.set_size(data.len() as u64);
                    h.set_cksum();
                    b.append_data(&mut h, name, *data).unwrap();
                }
            }
        }
        b.into_inner().unwrap()
    }

    /// Everything about each path under `d` a container could see.
    fn tree(d: &Path) -> Vec<String> {
        use std::os::unix::fs::MetadataExt;
        let mut out = Vec::new();
        let mut stack = vec![PathBuf::new()];
        let mut inodes: Vec<u64> = Vec::new();
        while let Some(rel) = stack.pop() {
            let mut names: Vec<_> = fs::read_dir(d.join(&rel)).unwrap().map(|e| e.unwrap().file_name()).collect();
            names.sort();
            for n in names {
                let r = rel.join(&n);
                let m = fs::symlink_metadata(d.join(&r)).unwrap();
                // Which other path shares the inode, as an index in walk order.
                let shared = if m.is_dir() { None } else { inodes.iter().position(|i| *i == m.ino()) };
                if !m.is_dir() {
                    inodes.push(m.ino());
                }
                let body = if m.is_file() { String::from_utf8_lossy(&fs::read(d.join(&r)).unwrap()).into_owned() } else if m.file_type().is_symlink() { fs::read_link(d.join(&r)).unwrap().display().to_string() } else { String::new() };
                out.push(format!("{} {:o} {}:{} {} {} {:?} {body}", r.display(), m.mode(), m.uid(), m.gid(), m.size(), m.mtime(), shared));
                if m.is_dir() {
                    stack.push(r);
                }
            }
        }
        out.sort();
        out
    }

    /// A layer made from the one below it and a delta is the layer the
    /// full tar unpacks to: same tree, same times, same links; the base
    /// keeps its own bytes.
    #[test]
    fn a_layer_from_a_delta_equals_the_full_unpack() {
        // SAFETY: a plain getter.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipped: needs root to keep owners");
            return;
        }
        const D3: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
        let root = scratch("delta");
        let base = tar_of(&[
            ("app/", 'd', b"", 100),
            ("app/a", 'f', b"A", 101),
            ("app/b", 'f', b"B", 102),
            ("app/d/", 'd', b"", 103),
            ("app/d/c", 'f', b"C", 104),
            ("app/h", 'h', b"app/a", 101),
            ("app/l", 'l', b"a", 105),
        ]);
        let full = tar_of(&[
            ("app/", 'd', b"", 200),
            ("app/a", 'f', b"A", 101),
            ("app/b", 'f', b"B2", 202),
            ("app/d/", 'd', b"", 203),
            ("app/e", 'f', b"E", 204),
            ("app/h", 'h', b"app/a", 101),
            ("app/l", 'l', b"a", 105),
        ]);
        let delta = tar_of(&[("app/", 'd', b"", 200), ("app/b", 'f', b"B2", 202), ("app/d/", 'd', b"", 203), ("app/e", 'f', b"E", 204)]);
        send(&root, D1, &base);
        let before = tree(&dir(&root, D1).unwrap());
        receive_delta(&mut &delta[..], D1, D2, &["app/d/c"], &root).unwrap();
        send(&root, D3, &full);
        assert!(present(&root, D2));
        assert_eq!(tree(&dir(&root, D2).unwrap()), tree(&dir(&root, D3).unwrap()));
        assert_eq!(tree(&dir(&root, D1).unwrap()), before, "the base changed");
        let _ = fs::remove_dir_all(&root);
    }

    /// A layer made from a base 1000 folders deep, on a thread with an
    /// ordinary stack (2 MiB): the base's tree is linked in whole.
    #[test]
    fn a_layer_from_a_delta_over_a_base_1000_folders_deep() {
        // SAFETY: a plain getter.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipped: needs root to keep owners");
            return;
        }
        let root = scratch("deepdelta");
        let names: Vec<String> = (1..=1000).map(|n| "d/".repeat(n)).collect();
        let file = format!("{}f", "d/".repeat(1000));
        let mut entries: Vec<(&str, char, &[u8], u64)> = names.iter().map(|n| (n.as_str(), 'd', &b""[..], 100)).collect();
        entries.push((file.as_str(), 'f', b"deep", 100));
        let base = tar_of(&entries);
        let delta = tar_of(&[("top", 'f', b"top", 200)]);
        send(&root, D1, &base);
        let r = root.clone();
        std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(move || receive_delta(&mut &delta[..], D1, D2, &[], &r).unwrap())
            .unwrap()
            .join()
            .unwrap();
        let new = dir(&root, D2).unwrap();
        assert_eq!(fs::read(new.join(&file)).unwrap(), b"deep");
        assert_eq!(fs::read(new.join("top")).unwrap(), b"top");
        let _ = fs::remove_dir_all(&root);
    }

    /// A layer unpacked as it arrives: the blob's digest is checked, the
    /// tar's (diff_id) given back, the folder kept only when asked.
    #[test]
    fn a_streamed_layer_checks_both_digests() {
        // SAFETY: a plain getter.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipped: needs root to keep owners");
            return;
        }
        let root = scratch("streamed");
        let tar = layer_blob(&[("etc/x", b"hello")]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        io::Write::write_all(&mut gz, &tar).unwrap();
        let blob = gz.finish().unwrap();
        let digest = digest_of({
            let mut h = sha2::Sha256::new();
            h.update(&blob);
            h
        });
        let want_diff = digest_of({
            let mut h = sha2::Sha256::new();
            h.update(&tar);
            h
        });
        let (diff_id, folder, _) = unpack_streamed(&mut &blob[..], &digest, "application/vnd.oci.image.layer.v1.tar+gzip", &root).unwrap();
        assert_eq!(diff_id, want_diff);
        assert!(!present(&root, &digest), "not a layer until kept");
        assert_eq!(diff_id_of(&mut &blob[..], &digest, "application/vnd.oci.image.layer.v1.tar+gzip").unwrap(), want_diff, "read whole without unpacking");
        keep(&root, &digest, &folder, &diff_id).unwrap();
        assert!(present(&root, &digest));
        assert_eq!(fs::read(dir(&root, &digest).unwrap().join("etc/x")).unwrap(), b"hello");
        // The marker records the identity the host checked: a later pull of
        // the same blob is answered with it, not with a bare "present".
        assert_eq!(recorded_diff_id(&root, &digest).as_deref(), Some(want_diff.as_str()));
        fs::write(marker(&root, &digest).unwrap(), "").unwrap();
        assert_eq!(recorded_diff_id(&root, &digest), None, "an older, empty marker records none");
        record_diff_id(&root, &digest, &want_diff).unwrap();
        assert_eq!(recorded_diff_id(&root, &digest).as_deref(), Some(want_diff.as_str()));
        // A blob that is not what its digest says leaves nothing.
        let err = unpack_streamed(&mut &blob[..], D2, "application/vnd.oci.image.layer.v1.tar+gzip", &root).unwrap_err();
        assert!(err.to_string().contains("arrived as"), "{err}");
        assert!(fs::read_dir(&root).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().starts_with(".tmp-")));
        let _ = fs::remove_dir_all(&root);
    }

    /// Device nodes and fifos come out as such, numbers, owner and mode kept,
    /// not as the empty files the tar crate would make of them.
    #[test]
    fn devices_and_fifos_are_unpacked_as_themselves() {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        // SAFETY: a plain getter.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipped: needs root for mknod");
            return;
        }
        let mut b = tar::Builder::new(Vec::new());
        for (name, kind, major, minor, mode) in [("dev/null", tar::EntryType::Char, 1, 3, 0o666), ("dev/loop9", tar::EntryType::Block, 7, 9, 0o660), ("pipe", tar::EntryType::Fifo, 0, 0, 0o640)] {
            let mut h = header(0, mode);
            h.set_entry_type(kind);
            h.set_device_major(major).unwrap();
            h.set_device_minor(minor).unwrap();
            h.set_uid(12);
            h.set_mtime(1_600_000_000);
            h.set_cksum();
            b.append_data(&mut h, name, &[][..]).unwrap();
        }
        let bytes = b.into_inner().unwrap();
        let dest = scratch("special");
        untar(Capped { inner: &bytes[..], left: u64::MAX }, &dest).unwrap();
        let m = |p: &str| fs::symlink_metadata(dest.join(p)).unwrap();
        let null = m("dev/null");
        assert!(null.file_type().is_char_device());
        assert_eq!((libc::major(null.rdev()), libc::minor(null.rdev()), null.mode() & 0o7777, null.uid(), null.mtime()), (1, 3, 0o666, 12, 1_600_000_000));
        let lp = m("dev/loop9");
        assert!(lp.file_type().is_block_device());
        assert_eq!((libc::major(lp.rdev()), libc::minor(lp.rdev()), lp.mode() & 0o7777), (7, 9, 0o660));
        let pipe = m("pipe");
        assert!(pipe.file_type().is_fifo());
        assert_eq!(pipe.mode() & 0o7777, 0o640);
        let _ = fs::remove_dir_all(&dest);
    }

    /// A time of 0 in the archive is 0 on disk, as Docker unpacks it. The
    /// tar crate makes it 1 ("0-mtime files ... some tools don't ingest them
    /// well"), which a container then sees, and a build that copies the
    /// file keeps.
    #[test]
    fn a_zero_time_stays_zero() {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: a plain getter.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipped: needs root to keep owners (unshare -r will do)");
            return;
        }
        let bytes = tar_of(&[("d", 'd', b"", 0), ("d/f", 'f', b"x", 0), ("d/l", 'l', b"f", 0), ("g", 'f', b"y", 5)]);
        let dest = scratch("zero-time");
        untar(Capped { inner: &bytes[..], left: u64::MAX }, &dest).unwrap();
        let t = |p: &str| fs::symlink_metadata(dest.join(p)).unwrap().mtime();
        assert_eq!((t("d"), t("d/f"), t("d/l"), t("g")), (0, 0, 0, 5));
        let _ = fs::remove_dir_all(&dest);
    }

    /// A layer that expands past its cap is refused.
    #[test]
    fn expansion_is_capped() {
        let mut b = tar::Builder::new(Vec::new());
        let data = vec![0u8; 4096];
        let mut h = header(data.len() as u64, 0o644);
        b.append_data(&mut h, "big", &data[..]).unwrap();
        let bytes = b.into_inner().unwrap();
        // As in receive(): a layer that fails is discarded, never reused.
        let capped = scratch("cap");
        assert!(untar(Capped { inner: &bytes[..], left: 1024 }, &capped).is_err());
        let _ = fs::remove_dir_all(&capped);
        let fresh = scratch("cap-ok");
        assert_eq!(untar(Capped { inner: &bytes[..], left: u64::MAX }, &fresh).unwrap(), 4096);
        let _ = fs::remove_dir_all(&fresh);
        assert_eq!(expansion_cap(1), 1 << 30);
        assert_eq!(expansion_cap(1 << 40), 64 << 30);
    }

    const ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";

    fn zstd(b: &[u8]) -> Vec<u8> {
        ruzstd::encoding::compress_to_vec(b, ruzstd::encoding::CompressionLevel::Fastest)
    }

    fn skippable(payload: &[u8]) -> Vec<u8> {
        [&0x184D_2A5Fu32.to_le_bytes()[..], &(payload.len() as u32).to_le_bytes(), payload].concat()
    }

    /// 30 files of 1000 bytes (1536 bytes of tar each), and the tar cut into
    /// three at file boundaries, as zstd:chunked cuts it: the last part
    /// holds the tar's end.
    type Files = Vec<(String, Vec<u8>)>;

    fn thirty_files() -> (Files, Vec<u8>, [Vec<u8>; 3]) {
        let files: Vec<(String, Vec<u8>)> = (0..30).map(|i| (format!("zt/f{i:03}"), vec![b'a' + i as u8; 1000])).collect();
        let tar = layer_blob(&files.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect::<Vec<_>>());
        let parts = [tar[..10 * 1536].to_vec(), tar[10 * 1536..20 * 1536].to_vec(), tar[20 * 1536..].to_vec()];
        (files, tar, parts)
    }

    fn send_zstd(root: &Path, blob: &[u8]) -> io::Result<LayerStored> {
        receive(&mut &blob[..], &LayerBegin { digest: D1, media_type: ZSTD, size: blob.len() as u64 }, root)
    }

    /// A zstd layer may be several frames back to back, with skippable and
    /// empty frames among them: every file of every frame is unpacked.
    #[test]
    fn every_frame_of_a_zstd_layer_is_unpacked() {
        let (files, tar, [a, b, c]) = thirty_files();
        let layouts = [
            ("one frame", zstd(&tar)),
            ("three frames", [zstd(&a), zstd(&b), zstd(&c)].concat()),
            ("skippable frames between and after", [zstd(&a), skippable(b"x"), zstd(&b), skippable(&[0; 300]), zstd(&c), skippable(b"toc")].concat()),
            ("empty frames", [zstd(b""), zstd(&a), zstd(b""), zstd(&b), zstd(&c), zstd(b"")].concat()),
        ];
        for (what, blob) in layouts {
            let root = scratch("zstd-frames");
            send_zstd(&root, &blob).unwrap_or_else(|e| panic!("{what}: {e}"));
            for (name, data) in &files {
                let got = fs::read(dir(&root, D1).unwrap().join(name)).unwrap_or_else(|e| panic!("{what}: {name}: {e}"));
                assert!(&got == data, "{what}: {name}");
            }
            let _ = fs::remove_dir_all(&root);
        }
    }

    /// Bytes after the last frame that are not a frame, a last frame cut
    /// short, a wrong checksum: the layer is refused and not stored, as
    /// Docker refuses it, never unpacked short.
    #[test]
    fn a_damaged_zstd_layer_is_refused() {
        let (_, _, [a, b, c]) = thirty_files();
        let whole = [zstd(&a), zstd(&b), zstd(&c)].concat();
        let cut = zstd(&c).len() / 2;
        for (what, blob) in [("garbage after the frames", [&whole[..], b"garbage"].concat()), ("last frame cut short", whole[..whole.len() - cut].to_vec())] {
            let root = scratch("zstd-damaged");
            assert!(send_zstd(&root, &blob).is_err(), "{what}");
            assert!(!present(&root, D1), "{what}");
            let _ = fs::remove_dir_all(&root);
        }
    }

    /// The expansion cap counts every frame, the ones after the tar's end too.
    #[test]
    fn the_expansion_cap_counts_every_frame() {
        let (_, tar, _) = thirty_files();
        let blob = [zstd(&tar), zstd(&vec![0u8; 2 << 20])].concat();
        let dest = scratch("zstd-cap");
        let mut r = &blob[..];
        assert!(unpack(&mut r, ZSTD, &dest, 1 << 12).is_ok(), "within the cap");
        let _ = fs::remove_dir_all(&dest);
        let dest = scratch("zstd-cap2");
        let mut r = &blob[..];
        let left = tar.len() as u64 + (1 << 20);
        assert!(unpack_capped(&mut r, ZSTD, &dest, left).is_err(), "frames after the tar's end count toward the cap");
        let _ = fs::remove_dir_all(&dest);
    }

    /// The streamed unpack (a pull that unpacks as the blob arrives) reads
    /// every frame too, and its diff_id is the whole tar's.
    #[test]
    fn a_streamed_zstd_layer_is_unpacked_from_every_frame() {
        let (files, tar, [a, b, c]) = thirty_files();
        let blob = [zstd(&a), skippable(b"x"), zstd(&b), zstd(&c), skippable(b"toc")].concat();
        let digest = digest_of({
            let mut h = sha2::Sha256::new();
            sha2::Digest::update(&mut h, &blob);
            h
        });
        let root = scratch("zstd-streamed");
        let (diff_id, folder, _) = unpack_streamed(&mut &blob[..], &digest, ZSTD, &root).unwrap();
        assert_eq!(diff_id, digest_of({
            let mut h = sha2::Sha256::new();
            sha2::Digest::update(&mut h, &tar);
            h
        }));
        for (name, data) in &files {
            assert_eq!(&fs::read(folder.join(name)).unwrap(), data, "{name}");
        }
        let bad = [&blob[..], b"trailing"].concat();
        let bad_digest = digest_of({
            let mut h = sha2::Sha256::new();
            sha2::Digest::update(&mut h, &bad);
            h
        });
        assert!(unpack_streamed(&mut &bad[..], &bad_digest, ZSTD, &root).is_err(), "bytes after the last frame");
        let _ = fs::remove_dir_all(&root);
    }
}
