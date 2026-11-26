//! Copying Kiri's data folder to another place (Settings → Storage).
//!
//! `std::fs::copy` writes a sparse file out whole when it crosses volumes:
//! the VM's 64 GiB `data.img`, of which a few GB hold data, would take all
//! 64 GiB on the new drive. [`copy_sparse`] copies only the file's data
//! (`SEEK_DATA`/`SEEK_HOLE`, or skipping runs of zeros where the system
//! can't say where the holes are), so it stays as small as it was.
//! [`copy_tree`] copies a whole folder that way, keeping what a Linux
//! host's layers need: owners, modes, hard links, device nodes (overlay
//! whiteouts) and extended attributes (`trusted.overlay.opaque`).

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// How much is read at a time.
const CHUNK: usize = 1 << 20;
/// Zeros are skipped in runs of this size, at this alignment: what is left
/// unwritten stays a hole on any filesystem with blocks up to 64 KiB.
const BLOCK: usize = 64 << 10;

/// Told the bytes just copied; an error it returns stops the copy.
pub type Progress<'a> = dyn FnMut(u64) -> io::Result<()> + 'a;

/// Copies the file `src` to `dst`, which must not exist, writing only its
/// data: holes stay holes, and so do runs of zeros. Returns once the copy
/// is on disk. Permissions and owner are the caller's ([`copy_tree`]).
pub fn copy_sparse(src: &Path, dst: &Path, progress: &mut Progress<'_>) -> io::Result<()> {
    let from = File::open(src)?;
    let len = from.metadata()?.len();
    let to = OpenOptions::new().write(true).create_new(true).mode(0o600).open(dst)?;
    let written = match copy_extents(&from, &to, len, progress) {
        // No SEEK_DATA here (an older filesystem): every byte is read, and
        // the zeros are left out.
        Err(e) if unsupported(&e) => {
            to.set_len(0)?;
            copy_range(&from, &to, 0, len, progress)?
        }
        r => r?,
    };
    finish_sparse(&to, len, &written)
}

/// Sets `to`'s length to `len`, punches any unwritten gaps on macOS APFS
/// (where `pwrite` + `ftruncate` + `fsync` can otherwise allocate leading
/// or short trailing zero blocks), and syncs to disk.
fn finish_sparse(to: &File, len: u64, written: &[(u64, u64)]) -> io::Result<()> {
    to.set_len(len)?;
    let mut cursor = 0u64;
    for &(start, end) in written {
        if start > cursor {
            punch_hole(to, cursor, start - cursor);
        }
        cursor = cursor.max(end);
    }
    if len > cursor {
        punch_hole(to, cursor, len - cursor);
    }
    to.sync_all()
}

/// Punches `[offset, offset + len)` as a sparse hole on macOS APFS.
/// Best-effort: filesystems that do not support `F_PUNCHHOLE` ignore it.
#[cfg(target_os = "macos")]
fn punch_hole(f: &File, offset: u64, len: u64) {
    let (Ok(offset), Ok(len)) = (libc::off_t::try_from(offset), libc::off_t::try_from(len)) else { return };
    if len <= 0 {
        return;
    }
    let hole = libc::fpunchhole_t { fp_flags: 0, reserved: 0, fp_offset: offset, fp_length: len };
    // SAFETY: `f` is an open writable file descriptor and `hole` matches F_PUNCHHOLE's struct.
    unsafe { libc::fcntl(f.as_raw_fd(), libc::F_PUNCHHOLE, &hole) };
}

#[cfg(not(target_os = "macos"))]
fn punch_hole(_f: &File, _offset: u64, _len: u64) {}

fn unsupported(e: &io::Error) -> bool {
    let code = e.raw_os_error();
    code == Some(libc::EINVAL) || code == Some(libc::ENOTSUP) || code == Some(libc::EOPNOTSUPP)
}

/// Copies each run of data `SEEK_DATA` finds. Returns sorted written ranges.
fn copy_extents(from: &File, to: &File, len: u64, progress: &mut Progress<'_>) -> io::Result<Vec<(u64, u64)>> {
    let mut pos = 0;
    let mut written = Vec::new();
    while pos < len {
        let data = match seek(from, pos, libc::SEEK_DATA) {
            Ok(at) if at < len => at,
            Ok(_) => break,
            // Only a hole from here to the end.
            Err(e) if e.raw_os_error() == Some(libc::ENXIO) => break,
            Err(e) => return Err(e),
        };
        let hole = seek(from, data, libc::SEEK_HOLE)?.min(len);
        if hole <= data {
            break;
        }
        written.extend(copy_range(from, to, data, hole, progress)?);
        pos = hole;
    }
    Ok(written)
}

fn seek(f: &File, at: u64, whence: libc::c_int) -> io::Result<u64> {
    let at = libc::off_t::try_from(at).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: lseek on a descriptor `f` owns; it only moves its offset.
    let r = unsafe { libc::lseek(f.as_raw_fd(), at, whence) };
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(r as u64) }
}

/// Copies bytes `start..end`, leaving out blocks that are all zeros (the
/// new file reads zeros there anyway). Returns coalesced written ranges.
fn copy_range(from: &File, to: &File, start: u64, end: u64, progress: &mut Progress<'_>) -> io::Result<Vec<(u64, u64)>> {
    let mut buf = vec![0u8; CHUNK];
    let mut at = start;
    let mut written: Vec<(u64, u64)> = Vec::new();
    while at < end {
        let want = usize::try_from(end - at).unwrap_or(CHUNK).min(CHUNK);
        let n = from.read_at(&mut buf[..want], at)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the file got shorter while it was copied"));
        }
        let mut off = 0;
        while off < n {
            // Up to the next BLOCK boundary of the file, so holes line up.
            let file_off = at + off as u64;
            let step = (BLOCK - (file_off % BLOCK as u64) as usize).min(n - off);
            let piece = &buf[off..off + step];
            if piece.iter().any(|&b| b != 0) {
                to.write_all_at(piece, file_off)?;
                let piece_end = file_off + step as u64;
                match written.last_mut() {
                    Some((_, last_end)) if *last_end == file_off => *last_end = piece_end,
                    _ => written.push((file_off, piece_end)),
                }
            }
            off += step;
        }
        at += n as u64;
        progress(n as u64)?;
    }
    Ok(written)
}

/// Copies the folder `src` to `dst`, which must not exist, leaving out the
/// entries of `src` named in `skip`. Sockets are left out (whoever listens
/// makes them again). A folder on another filesystem than `src` (something
/// still mounted) stops the copy rather than copying what is mounted there.
pub fn copy_tree(src: &Path, dst: &Path, skip: &[&str], progress: &mut Progress<'_>) -> io::Result<()> {
    let meta = fs::symlink_metadata(src)?;
    // SAFETY: geteuid cannot fail.
    let as_root = unsafe { libc::geteuid() } == 0;
    let mut c = Copier { progress, links: HashMap::new(), dev: meta.dev(), as_root };
    fs::create_dir(dst)?;
    c.contents(src, dst, skip)?;
    c.finish(&meta, src, dst)
}

struct Copier<'a, 'b> {
    progress: &'a mut Progress<'b>,
    /// Files with more than one name: the first copy of each, by device
    /// and inode, which later names link to.
    links: HashMap<(u64, u64), PathBuf>,
    dev: u64,
    as_root: bool,
}

impl Copier<'_, '_> {
    fn contents(&mut self, src: &Path, dst: &Path, skip: &[&str]) -> io::Result<()> {
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let name = entry.file_name();
            if skip.iter().any(|s| name == *s) {
                continue;
            }
            self.entry(&entry.path(), &dst.join(&name))?;
        }
        Ok(())
    }

    fn entry(&mut self, src: &Path, dst: &Path) -> io::Result<()> {
        let m = fs::symlink_metadata(src)?;
        let kind = m.file_type();
        if kind.is_dir() {
            if m.dev() != self.dev {
                return Err(io::Error::other(format!("{} is a mount point: stop what uses it and try again", src.display())));
            }
            fs::create_dir(dst)?;
            self.contents(src, dst, &[])?;
        } else if kind.is_file() {
            if m.nlink() > 1 {
                if let Some(first) = self.links.get(&(m.dev(), m.ino())) {
                    return fs::hard_link(first, dst);
                }
                self.links.insert((m.dev(), m.ino()), dst.to_owned());
            }
            copy_sparse(src, dst, self.progress)?;
        } else if kind.is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(src)?, dst)?;
        } else if kind.is_socket() {
            return Ok(());
        } else {
            // A FIFO or a device node: an overlay whiteout is a 0/0 one.
            let path = c_path(dst)?;
            // SAFETY: a valid NUL-terminated path; mode and device as stat gave them.
            if unsafe { libc::mknod(path.as_ptr(), m.mode() as libc::mode_t, m.rdev() as libc::dev_t) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        self.finish(&m, src, dst)
    }

    /// The owner (when copying as root), extended attributes, mode and
    /// times of `src` on `dst`. The mode after the owner: a change of
    /// owner clears set-user-ID.
    fn finish(&self, m: &Metadata, src: &Path, dst: &Path) -> io::Result<()> {
        if self.as_root {
            std::os::unix::fs::lchown(dst, Some(m.uid()), Some(m.gid()))?;
        }
        copy_xattrs(src, dst)?;
        let link = m.file_type().is_symlink();
        if !link {
            fs::set_permissions(dst, fs::Permissions::from_mode(m.mode() & 0o7777))?;
        }
        let times = [
            libc::timespec { tv_sec: m.atime() as _, tv_nsec: m.atime_nsec() as _ },
            libc::timespec { tv_sec: m.mtime() as _, tv_nsec: m.mtime_nsec() as _ },
        ];
        let path = c_path(dst)?;
        // SAFETY: a valid NUL-terminated path and two timespecs.
        if unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn c_path(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

/// A Linux host's layers keep overlay attributes (`trusted.overlay.*`)
/// and file capabilities (`security.capability`). The SELinux label is the
/// new place's policy's to give.
#[cfg(target_os = "linux")]
fn copy_xattrs(src: &Path, dst: &Path) -> io::Result<()> {
    let (s, d) = (c_path(src)?, c_path(dst)?);
    // SAFETY: llistxattr with a null buffer asks for the size of the list.
    let size = unsafe { libc::llistxattr(s.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        let e = io::Error::last_os_error();
        return if unsupported(&e) { Ok(()) } else { Err(e) };
    }
    if size == 0 {
        return Ok(());
    }
    let mut names = vec![0u8; size as usize];
    // SAFETY: the buffer is `names.len()` bytes.
    let size = unsafe { libc::llistxattr(s.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
    if size < 0 {
        return Err(io::Error::last_os_error());
    }
    for name in names[..size as usize].split(|&b| b == 0).filter(|n| !n.is_empty() && *n != b"security.selinux") {
        let key = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        // SAFETY: a null buffer asks for the value's size.
        let len = unsafe { libc::lgetxattr(s.as_ptr(), key.as_ptr(), std::ptr::null_mut(), 0) };
        if len < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut value = vec![0u8; len as usize];
        // SAFETY: the buffer is `value.len()` bytes.
        let len = unsafe { libc::lgetxattr(s.as_ptr(), key.as_ptr(), value.as_mut_ptr().cast(), value.len()) };
        if len < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: valid strings and a buffer of `len` bytes.
        if unsafe { libc::lsetxattr(d.as_ptr(), key.as_ptr(), value.as_ptr().cast(), len as usize, 0) } != 0 {
            return Err(io::Error::other(format!("{}: {}: {}", dst.display(), String::from_utf8_lossy(name), io::Error::last_os_error())));
        }
    }
    Ok(())
}

/// A Mac's data folder needs none: Finder's and the quarantine's own
/// attributes aren't Kiri's.
#[cfg(not(target_os = "linux"))]
fn copy_xattrs(_src: &Path, _dst: &Path) -> io::Result<()> {
    Ok(())
}

/// Checks that `dst` holds what `src` does (leaving out `skip` at the top):
/// every file there with the same size, small files with the same bytes,
/// and every blob (`blobs/sha256/<hex>`) matching its digest.
pub fn verify_tree(src: &Path, dst: &Path, skip: &[&str], progress: &mut Progress<'_>) -> io::Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if skip.iter().any(|s| name == *s) {
            continue;
        }
        let (s, d) = (entry.path(), dst.join(&name));
        let m = fs::symlink_metadata(&s)?;
        if m.file_type().is_socket() {
            // `copy_tree` leaves sockets out.
            continue;
        }
        let differs = |what: &str| io::Error::other(format!("the copy of {} {what}", s.display()));
        let got = fs::symlink_metadata(&d).map_err(|_| differs("is missing"))?;
        if m.is_dir() {
            if !got.is_dir() {
                return Err(differs("isn't a folder"));
            }
            verify_tree(&s, &d, &[], progress)?;
        } else if m.is_file() {
            if !got.is_file() || got.len() != m.len() {
                return Err(differs("has another size"));
            }
            let blob = s.parent().is_some_and(|p| p.ends_with("blobs/sha256"));
            let hex = name.to_str().filter(|n| n.len() == 64 && n.bytes().all(|b| b.is_ascii_hexdigit()));
            if let (true, Some(hex)) = (blob, hex) {
                if sha256(&d)? != hex {
                    return Err(differs("doesn't match its digest"));
                }
                progress(m.len())?;
            } else if m.len() <= CHUNK as u64 && fs::read(&s)? != fs::read(&d)? {
                return Err(differs("has other contents"));
            }
        } else if m.file_type().is_symlink() && fs::read_link(&s)? != fs::read_link(&d).map_err(|_| differs("isn't a link"))? {
            return Err(differs("points elsewhere"));
        }
    }
    Ok(())
}

/// The SHA-256 of a file, in hex.
pub fn sha256(path: &Path) -> io::Result<String> {
    use sha2::Digest as _;
    let mut f = File::open(path)?;
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// What the folder `dir` takes on its disk (blocks in use, a hard-linked
/// file once), leaving out `skip` at the top. What can't be read counts as
/// nothing.
pub fn allocated(dir: &Path, skip: &[&str]) -> u64 {
    fn walk(dir: &Path, skip: &[&str], dev: u64, seen: &mut std::collections::HashSet<(u64, u64)>) -> u64 {
        let Ok(entries) = fs::read_dir(dir) else { return 0 };
        let mut total = 0;
        for entry in entries.flatten() {
            if skip.iter().any(|s| entry.file_name() == *s) {
                continue;
            }
            let Ok(m) = entry.metadata() else { continue };
            if m.nlink() > 1 && !m.is_dir() && !seen.insert((m.dev(), m.ino())) {
                continue;
            }
            total += m.blocks() * 512;
            if m.is_dir() && m.dev() == dev {
                total += walk(&entry.path(), &[], dev, seen);
            }
        }
        total
    }
    let Ok(m) = fs::symlink_metadata(dir) else { return 0 };
    walk(dir, skip, m.dev(), &mut std::collections::HashSet::new())
}

/// The nearest folder of `path` that exists: `path` itself, or the one a
/// new folder there would be made in.
pub fn existing_ancestor(path: &Path) -> Option<&Path> {
    path.ancestors().find(|p| p.is_dir())
}

/// The filesystem's name: `apfs`, `msdos`, `exfat` (macOS's names), or on
/// Linux the name of its magic number when it is one Kiri knows.
pub fn fs_name(path: &Path) -> io::Result<String> {
    let c = c_path(path)?;
    // SAFETY: statfs is plain data, filled in by the call.
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a valid path and a statfs to fill.
    if unsafe { libc::statfs(c.as_ptr(), &mut s) } != 0 {
        return Err(io::Error::last_os_error());
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: f_fstypename is a NUL-terminated C string the call filled.
        Ok(unsafe { std::ffi::CStr::from_ptr(s.f_fstypename.as_ptr()) }.to_string_lossy().into_owned())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(linux_fs_name(s.f_type as u64))
    }
}

#[cfg(not(target_os = "macos"))]
fn linux_fs_name(magic: u64) -> String {
    match magic {
        0xEF53 => "ext4".into(),
        0x5846_5342 => "xfs".into(),
        0x9123_683E => "btrfs".into(),
        0x0102_1994 => "tmpfs".into(),
        0x794C_7630 => "overlay".into(),
        0x2FC1_2FC1 => "zfs".into(),
        0x6969 => "nfs".into(),
        0x4d44 => "msdos".into(),
        0x2011_BAB0 => "exfat".into(),
        0x5346_544E => "ntfs".into(),
        0x6573_5546 => "fuseblk".into(),
        m => format!("{m:#x}"),
    }
}

/// FAT and exFAT can't hold Kiri's data: no sparse files (the VM's disk
/// would take its whole 64 GiB, and FAT32 stops at 4 GiB a file), no owners
/// or permissions, no links.
pub fn refused_fs(name: &str) -> bool {
    matches!(name, "msdos" | "vfat" | "exfat")
}

/// Bytes free for this user on the filesystem of `path`.
pub fn free_space(path: &Path) -> io::Result<u64> {
    let c = c_path(path)?;
    // SAFETY: statvfs is plain data, filled in by the call.
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: a valid path and a statvfs to fill.
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(s.f_bavail as u64 * s.f_frsize as u64)
}

/// The device a path is on.
pub fn device(path: &Path) -> io::Result<u64> {
    Ok(fs::metadata(path)?.dev())
}

/// Writes a file into `dir`, syncs it and removes it: whether Kiri can
/// really write there (a read-only volume, or one this user may not write).
pub fn probe_writable(dir: &Path) -> io::Result<()> {
    let probe = dir.join(format!(".kiri-probe-{}", std::process::id()));
    let result = (|| {
        let f = OpenOptions::new().write(true).create_new(true).open(&probe)?;
        f.write_all_at(b"kiri", 0)?;
        f.sync_all()
    })();
    let _ = fs::remove_file(&probe);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kiri-treecopy-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn none(_: u64) -> io::Result<()> {
        Ok(())
    }

    /// A 128 MiB file with two 64 KiB islands of data copies byte for byte
    /// and stays sparse: well under 2 MiB on disk, not 128 MiB (#355: a
    /// 2 GiB file using 16 KB took 2 GiB with std::fs::copy across volumes).
    #[test]
    fn a_sparse_file_stays_sparse() {
        let d = scratch("sparse");
        let (src, dst) = (d.join("data.img"), d.join("copy.img"));
        let f = File::create(&src).unwrap();
        f.set_len(128 << 20).unwrap();
        let island: Vec<u8> = (0..64 << 10).map(|i: u32| (i % 251) as u8 | 1).collect();
        f.write_all_at(&island, 10 << 20).unwrap();
        f.write_all_at(&island, 100 << 20).unwrap();
        f.sync_all().unwrap();
        drop(f);
        let mut copied = 0;
        copy_sparse(&src, &dst, &mut |n| {
            copied += n;
            Ok(())
        })
        .unwrap();
        assert_eq!(sha256(&src).unwrap(), sha256(&dst).unwrap(), "the copy has the same bytes");
        let m = fs::metadata(&dst).unwrap();
        assert_eq!(m.len(), 128 << 20);
        assert!(m.blocks() * 512 < 2 << 20, "the copy takes {} bytes on disk, not under 2 MiB", m.blocks() * 512);
        assert!(copied < 128 << 20, "only the data was read: {copied} bytes");
        let _ = fs::remove_dir_all(&d);
    }

    /// Without SEEK_DATA the zeros are still left out.
    #[test]
    fn runs_of_zeros_are_left_out() {
        let d = scratch("zeros");
        let (src, dst) = (d.join("a"), d.join("b"));
        let mut bytes = vec![0u8; 8 << 20];
        bytes[3 << 20] = 7;
        fs::write(&src, &bytes).unwrap();
        let (from, to) = (File::open(&src).unwrap(), OpenOptions::new().write(true).create_new(true).open(&dst).unwrap());
        let written = copy_range(&from, &to, 0, bytes.len() as u64, &mut none).unwrap();
        finish_sparse(&to, bytes.len() as u64, &written).unwrap();
        assert_eq!(fs::read(&dst).unwrap(), bytes);
        assert!(fs::metadata(&dst).unwrap().blocks() * 512 < 1 << 20);
        let _ = fs::remove_dir_all(&d);
    }

    /// A folder comes over whole: files, links, modes, a hard link as one
    /// file, and nothing of what `skip` names; the check passes, and finds
    /// a changed blob.
    #[test]
    fn a_folder_copies_and_checks_whole() {
        let d = scratch("tree");
        let src = d.join("src");
        let hex = sha256_of(b"layer");
        fs::create_dir_all(src.join("blobs/sha256")).unwrap();
        fs::create_dir_all(src.join("vm")).unwrap();
        fs::write(src.join("blobs/sha256").join(&hex), b"layer").unwrap();
        fs::write(src.join("images.json"), b"[]").unwrap();
        fs::write(src.join("vm/mac"), b"02:00:00:00:00:01").unwrap();
        fs::set_permissions(src.join("vm/mac"), fs::Permissions::from_mode(0o640)).unwrap();
        fs::hard_link(src.join("images.json"), src.join("images.link")).unwrap();
        std::os::unix::fs::symlink("images.json", src.join("current")).unwrap();
        fs::create_dir_all(src.join(".kiri-moving")).unwrap();
        let dst = d.join("dst");
        copy_tree(&src, &dst, &[".kiri-moving"], &mut none).unwrap();
        assert_eq!(fs::read(dst.join("blobs/sha256").join(&hex)).unwrap(), b"layer");
        assert_eq!(fs::metadata(dst.join("vm/mac")).unwrap().permissions().mode() & 0o777, 0o640);
        assert_eq!(fs::metadata(dst.join("images.json")).unwrap().ino(), fs::metadata(dst.join("images.link")).unwrap().ino());
        assert_eq!(fs::read_link(dst.join("current")).unwrap(), Path::new("images.json"));
        assert!(!dst.join(".kiri-moving").exists());
        verify_tree(&src, &dst, &[".kiri-moving"], &mut none).unwrap();
        fs::write(dst.join("blobs/sha256").join(&hex), b"LAYER").unwrap();
        assert!(verify_tree(&src, &dst, &[".kiri-moving"], &mut none).unwrap_err().to_string().contains("digest"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_socket_is_left_out_of_the_copy_and_its_check() {
        let d = scratch("socket");
        let src = d.join("src");
        fs::create_dir_all(src.join("run")).unwrap();
        fs::write(src.join("images.json"), b"[]").unwrap();
        let _listening = std::os::unix::net::UnixListener::bind(src.join("run/app.sock")).unwrap();
        let dst = d.join("dst");
        copy_tree(&src, &dst, &[], &mut none).unwrap();
        assert!(fs::symlink_metadata(dst.join("run/app.sock")).is_err());
        verify_tree(&src, &dst, &[], &mut none).unwrap();
        fs::remove_file(dst.join("images.json")).unwrap();
        assert!(verify_tree(&src, &dst, &[], &mut none).unwrap_err().to_string().contains("missing"));
        let _ = fs::remove_dir_all(&d);
    }

    fn sha256_of(b: &[u8]) -> String {
        use sha2::Digest as _;
        sha2::Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn fat_and_exfat_are_refused() {
        assert!(refused_fs("msdos") && refused_fs("exfat") && refused_fs("vfat"));
        assert!(!refused_fs("apfs") && !refused_fs("ext4"));
        #[cfg(not(target_os = "macos"))]
        assert_eq!((linux_fs_name(0x4d44), linux_fs_name(0x2011_BAB0)), ("msdos".to_owned(), "exfat".to_owned()));
    }
}
