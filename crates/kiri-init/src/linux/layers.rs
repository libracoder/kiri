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

/// Reads exactly `begin.size` bytes of blob from `stream` and unpacks them.
/// The stream stays in sync even if unpacking fails part-way.
pub fn receive(stream: &mut impl Read, begin: &LayerBegin<'_>, root: &Path) -> io::Result<LayerStored> {
    let started = Instant::now();
    let final_dir = dir(root, begin.digest)?;
    let tmp = root.join(format!(".tmp-{}", hex(begin.digest)?));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp)?;

    let mut limited = stream.take(begin.size);
    let result = unpack(&mut limited, begin.media_type, &tmp, begin.size);
    // Whatever happened, consume the rest of the blob so the next frame lines up.
    io::copy(&mut limited, &mut io::sink())?;

    match result.and_then(|unpacked_bytes| install(root, begin.digest, &tmp, &final_dir).map(|()| unpacked_bytes)) {
        Ok(unpacked_bytes) => Ok(LayerStored { unpacked_bytes, elapsed_ns: started.elapsed().as_nanos() as u64 }),
        Err(e) => {
            let _ = fs::remove_dir_all(&tmp);
            Err(e)
        }
    }
}

/// Puts an unpacked layer in place: its files reach the disk first, then
/// the directory is renamed in, then the marker says it is whole.
fn install(root: &Path, digest: &str, tmp: &Path, final_dir: &Path) -> io::Result<()> {
    if present(root, digest) {
        let _ = fs::remove_dir_all(tmp);
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
            let _ = if is_marker || !path.is_dir() { fs::remove_file(&path) } else { fs::remove_dir_all(&path) };
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
    let buffered = BufReader::with_capacity(256 * 1024, blob);
    let left = expansion_cap(compressed);
    if media_type.ends_with("gzip") {
        untar(Capped { inner: flate2::read::MultiGzDecoder::new(buffered), left }, dest)
    } else if media_type.ends_with("zstd") {
        let decoder = ruzstd::decoding::StreamingDecoder::new(buffered)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("zstd: {e}")))?;
        untar(Capped { inner: decoder, left }, dest)
    } else {
        untar(Capped { inner: buffered, left }, dest)
    }
}

/// Unpacks a layer tarball, translating OCI whiteouts into the form overlayfs
/// reads: `.wh.name` becomes a 0:0 character device `name`, and
/// `.wh..wh..opq` marks its directory opaque.
fn untar(reader: impl Read, dest: &Path) -> io::Result<u64> {
    untar_in(reader, dest, in_user_namespace)
}

/// [`untar`], with how a user namespace is detected passed in, so tests can
/// say "in one" without making one.
fn untar_in(reader: impl Read, dest: &Path, detect_userns: fn() -> bool) -> io::Result<u64> {
    // Only looked at once a device or fifo entry turns up.
    let mut userns = None;
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(true);
    archive.set_preserve_mtime(true);
    archive.set_unpack_xattrs(true);
    archive.set_overwrite(true);
    let mut total = 0u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
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
                let _ = fs::remove_dir_all(&target);
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
            // Flags 0 links the symlink itself, without following its absolute target.
            let ret = unsafe { libc::linkat(from.as_raw_fd(), source.as_ptr(), to.as_raw_fd(), name.as_ptr(), 0) };
            sys::check(ret as _, "hard link")?;
        } else if let Some(kind) = special_kind(entry.header().entry_type()) {
            // In a user namespace (nested Docker, Sysbox, rootless, CI) the
            // kernel refuses mknod of a device, so the entry is left out, as
            // Docker leaves it out; a fifo is still made, and left out only
            // if refused.
            let userns = *userns.get_or_insert_with(detect_userns);
            if userns && kind != libc::S_IFIFO {
                continue;
            }
            make_special(dest, &path, entry.header(), kind, userns)?;
        } else if entry.unpack_in(dest)? {
            keep_zero_time(dest, &path, entry.header())?;
        }
    }
    Ok(total)
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
/// looked up inside the layer, as a hard link's is. With `may_be_refused`
/// (a user namespace), a mknod the kernel refuses leaves the entry out.
fn make_special(dest: &Path, path: &Path, h: &tar::Header, kind: libc::mode_t, may_be_refused: bool) -> io::Result<()> {
    let root = inroot::open_root(dest)?;
    let (parent, name) = hardlink_parent(root.as_fd(), path)?;
    let mode = (h.mode()? & 0o7777) as libc::mode_t;
    // A fifo has no device number, and archive writers leave its device
    // fields blank (Python's tarfile does), which is not a number: they are
    // not read for one. Docker unpacks such a fifo.
    let dev = if kind == libc::S_IFIFO {
        0
    } else {
        libc::makedev(h.device_major()?.unwrap_or(0), h.device_minor()?.unwrap_or(0))
    };
    let (uid, gid) = (h.uid()? as libc::uid_t, h.gid()? as libc::gid_t);
    let mtime = h.mtime()? as i64;
    let p = parent.as_raw_fd();
    let t = [libc::timespec { tv_sec: mtime, tv_nsec: 0 }, libc::timespec { tv_sec: mtime, tv_nsec: 0 }];
    // SAFETY: a confined parent descriptor and a single NUL-terminated name.
    unsafe {
        libc::unlinkat(p, name.as_ptr(), 0);
        if libc::mknodat(p, name.as_ptr(), kind | mode, dev) != 0 {
            let e = io::Error::last_os_error();
            if may_be_refused && e.raw_os_error() == Some(libc::EPERM) {
                return Ok(());
            }
            return Err(io::Error::new(e.kind(), format!("mknod: {e}")));
        }
        sys::check(libc::fchownat(p, name.as_ptr(), uid, gid, libc::AT_SYMLINK_NOFOLLOW) as _, "chown")?;
        // mknod applies the umask.
        sys::check(libc::fchmodat(p, name.as_ptr(), mode, 0) as _, "chmod")?;
        sys::check(libc::utimensat(p, name.as_ptr(), t.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) as _, "set time")?;
    }
    Ok(())
}

/// Whether this process runs in a user namespace other than the first, read
/// as Docker reads it (moby/sys/userns): the first user namespace's
/// /proc/self/uid_map is `0 0 4294967295`. No such file means a kernel
/// without user namespaces.
fn in_user_namespace() -> bool {
    match fs::read_to_string("/proc/self/uid_map") {
        Ok(map) => uid_map_in_user_namespace(map.lines().next().unwrap_or("")),
        Err(_) => false,
    }
}

fn uid_map_in_user_namespace(first_line: &str) -> bool {
    // Empty: a namespace just made, its map not written yet.
    if first_line.is_empty() {
        return true;
    }
    let mut fields = first_line.split_whitespace().map(|f| f.parse::<u64>());
    match (fields.next(), fields.next(), fields.next()) {
        (Some(Ok(inside)), Some(Ok(outside)), Some(Ok(count))) => (inside, outside, count) != (0, 0, 4294967295),
        // Not a map: taken as the first namespace, as Docker takes it.
        _ => false,
    }
}

/// Puts back a time of 0 the tar crate made 1 (it does so for every 0, so
/// that tools which take 0 for "no time" see one). Docker keeps the 0, and
/// what a container reads must be what the archive says. Folders are left
/// alone: what is unpacked into one changes its time afterwards anyway.
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

    /// Device nodes and fifos come out as such, numbers, owner and mode kept,
    /// not as the empty files the tar crate would make of them.
    #[test]
    fn devices_and_fifos_are_unpacked_as_themselves() {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        // SAFETY: a plain getter.
        if unsafe { libc::geteuid() } != 0 || in_user_namespace() {
            eprintln!("skipped: needs root outside a user namespace for mknod");
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
        // A fifo whose device fields are blank, as other archive writers
        // leave them.
        let mut h = header(0, 0o600);
        h.set_entry_type(tar::EntryType::Fifo);
        h.as_gnu_mut().unwrap().dev_major = [b' '; 8];
        h.as_gnu_mut().unwrap().dev_minor = [b' '; 8];
        h.set_cksum();
        b.append_data(&mut h, "blankpipe", &[][..]).unwrap();
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
        assert!(m("blankpipe").file_type().is_fifo());
        let _ = fs::remove_dir_all(&dest);
    }

    /// A layer with a character device, a block device, a fifo and a file
    /// after them, all owned by root.
    fn layer_with_devices() -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = header(0, 0o755);
        h.set_entry_type(tar::EntryType::Directory);
        h.set_cksum();
        b.append_data(&mut h, "dev/", &[][..]).unwrap();
        for (name, kind, major, minor) in [("dev/null", tar::EntryType::Char, 1, 3), ("dev/loop9", tar::EntryType::Block, 7, 9), ("pipe", tar::EntryType::Fifo, 0, 0)] {
            let mut h = header(0, 0o640);
            h.set_entry_type(kind);
            h.set_device_major(major).unwrap();
            h.set_device_minor(minor).unwrap();
            h.set_cksum();
            b.append_data(&mut h, name, &[][..]).unwrap();
        }
        b.append_data(&mut header(2, 0o644), "after", &b"ok"[..]).unwrap();
        b.into_inner().unwrap()
    }

    /// What a user namespace gets of [`layer_with_devices`], as Docker
    /// unpacks it there: no file for either device, the fifo, and the rest
    /// of the layer.
    fn assert_unpacked_as_in_a_user_namespace(dest: &Path) {
        use std::os::unix::fs::FileTypeExt;
        for dev in ["dev/null", "dev/loop9"] {
            assert!(fs::symlink_metadata(dest.join(dev)).is_err(), "{dev}: a device is left out in a user namespace");
        }
        assert!(fs::symlink_metadata(dest.join("pipe")).unwrap().file_type().is_fifo(), "a fifo is still made");
        assert_eq!(fs::read(dest.join("after")).unwrap(), b"ok", "the rest of the layer unpacks");
    }

    /// Docker's test of /proc/self/uid_map: only the first namespace's own
    /// map is outside a user namespace.
    #[test]
    fn a_user_namespace_is_told_from_uid_map_as_docker_tells_it() {
        for (line, userns) in [
            ("         0          0 4294967295", false),
            ("0 0 4294967295", false),
            ("0 165536 65536", true),
            ("0 1000 1", true),
            ("0 0 1", true),
            ("0 0 65536", true),
            ("", true),
            ("not a map", false),
        ] {
            assert_eq!(uid_map_in_user_namespace(line), userns, "{line:?}");
        }
    }

    /// The detection seam: told it is in a user namespace, the unpack leaves
    /// out the devices (mknod would fail there and, before, failed the whole
    /// layer) and keeps the rest. Needs no privilege: a fifo is made by
    /// anyone.
    #[test]
    fn devices_are_left_out_when_told_of_a_user_namespace() {
        let bytes = layer_with_devices();
        let dest = scratch("userns-seam");
        untar_in(Capped { inner: &bytes[..], left: u64::MAX }, &dest, || true).expect("a layer with devices unpacks in a user namespace");
        assert_unpacked_as_in_a_user_namespace(&dest);
        let _ = fs::remove_dir_all(&dest);
    }

    /// The same in a real user namespace: the test binary runs this test
    /// again in a new one, root inside mapped to the caller outside, where
    /// the kernel refuses mknod of a device with EPERM. Skipped where no
    /// user namespace can be made (a container's seccomp profile, a
    /// sysctl).
    #[test]
    fn a_layer_with_devices_unpacks_in_a_real_user_namespace() {
        use std::os::unix::process::CommandExt;
        const INSIDE: &str = "KIRI_TEST_IN_USER_NAMESPACE";
        if std::env::var_os(INSIDE).is_some() {
            assert!(in_user_namespace(), "uid_map: {:?}", fs::read_to_string("/proc/self/uid_map"));
            let bytes = layer_with_devices();
            let dest = scratch("userns-real");
            untar(Capped { inner: &bytes[..], left: u64::MAX }, &dest).expect("a layer with devices unpacks in a user namespace");
            assert_unpacked_as_in_a_user_namespace(&dest);
            let _ = fs::remove_dir_all(&dest);
            return;
        }
        // Built before the fork: the child only makes system calls.
        // SAFETY: plain getters.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let uid_map = format!("0 {uid} 1");
        let gid_map = format!("0 {gid} 1");
        let module = module_path!();
        let name = format!("{}::a_layer_with_devices_unpacks_in_a_real_user_namespace", &module[module.find("::").unwrap() + 2..]);
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args([name.as_str(), "--exact", "--nocapture", "--test-threads=1"]).env(INSIDE, "1");
        // SAFETY: between fork and exec only unshare, open, write and close.
        unsafe {
            cmd.pre_exec(move || {
                let write = |path: &std::ffi::CStr, data: &[u8]| -> io::Result<()> {
                    let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                    if fd < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    let n = libc::write(fd, data.as_ptr().cast(), data.len());
                    let e = io::Error::last_os_error();
                    libc::close(fd);
                    if n != data.len() as isize {
                        return Err(e);
                    }
                    Ok(())
                };
                if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                    return Err(io::Error::last_os_error());
                }
                write(c"/proc/self/setgroups", b"deny")?;
                write(c"/proc/self/uid_map", uid_map.as_bytes())?;
                write(c"/proc/self/gid_map", gid_map.as_bytes())
            });
        }
        let status = match cmd.status() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipped: no user namespace can be made here: {e}");
                return;
            }
        };
        assert!(status.success(), "unpacking in a user namespace failed: {status}");
    }

    /// A time of 0 in the archive is 0 on disk, as Docker unpacks it. The
    /// tar crate makes it 1 ("0-mtime files ... some tools don't ingest them
    /// well"), which a container then sees.
    #[test]
    fn a_zero_time_stays_zero() {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: a plain getter.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipped: needs root to keep owners");
            return;
        }
        let mut b = tar::Builder::new(Vec::new());
        let mut f = header(1, 0o644);
        b.append_data(&mut f, "f", &b"x"[..]).unwrap();
        let mut l = header(0, 0o777);
        l.set_entry_type(tar::EntryType::Symlink);
        b.append_link(&mut l, "l", "f").unwrap();
        let mut g = header(1, 0o644);
        g.set_mtime(5);
        g.set_cksum();
        b.append_data(&mut g, "g", &b"y"[..]).unwrap();
        let bytes = b.into_inner().unwrap();
        let dest = scratch("zero-time");
        untar(Capped { inner: &bytes[..], left: u64::MAX }, &dest).unwrap();
        let t = |p: &str| fs::symlink_metadata(dest.join(p)).unwrap().mtime();
        assert_eq!((t("f"), t("l"), t("g")), (0, 0, 5));
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
}
