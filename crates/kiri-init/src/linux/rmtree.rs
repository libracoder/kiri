//! Iterative, bounded-stack, bounded-descriptor directory tree removal for
//! container writable layers, volume data, layer unpack staging, and whiteouts.
//!
//! `std::fs::remove_dir_all` recurses once per directory level and holds an
//! open descriptor per level, allowing a deep container-created directory tree
//! (`while :; do mkdir d; cd d; done`) to exhaust stack or file descriptors.
//!
//! Security & resource invariants:
//! - Bounded descriptors: at most [`KEEP_OPEN`] (48) deepest directories stay
//!   open in the active window, plus at most [`ANCHORS`] + [`SUB_ANCHORS`]
//!   spaced ancestor descriptors to re-open evicted parents without ever
//!   traversing `..` (which is quadratic on bind mounts of subdirectories).
//! - Symlinks are never followed: every directory step uses `O_NOFOLLOW`, and
//!   re-opened ancestors verify `(st_dev, mnt_id, st_ino)` identity.
//! - Submounts are never entered: both `st_dev` AND `statx(STATX_MNT_ID)`
//!   (same-filesystem bind mounts on Linux 5.8+) must match the parent/root.
//! - Read-only (`0500` / `0000` / `0400`) directories in unprivileged / userns
//!   environments: on `EACCES` during `openat` (only after confirming `S_IFDIR`
//!   via `fstatat(..., AT_SYMLINK_NOFOLLOW)` and same-mount — NEVER on symlinks)
//!   or `unlinkat` inside the tree, grants `0o700` via `fchmodat` / `fchmod`
//!   and retries once, working at arbitrary depth past `PATH_MAX`.

use std::collections::VecDeque;
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Deepest directories kept open in the active sliding window.
const KEEP_OPEN: usize = 48;
/// Ancestor anchors retained above the window for `..`-free re-open.
const ANCHORS: usize = 24;
const SUB_ANCHORS: usize = 16;
/// Maximum passes when concurrent writers add entries during removal.
const PASSES: usize = 4;
/// Maximum entries visited in a single pass.
const PASS_ENTRIES: u64 = 1 << 26;

type MountId = (libc::dev_t, Option<u64>);

struct Dir {
    dir: *mut libc::DIR,
}

impl Dir {
    fn open(fd: OwnedFd) -> io::Result<Dir> {
        let raw = fd.into_raw_fd();
        // SAFETY: `raw` is an owned directory descriptor; on success `fdopendir` takes ownership.
        let dir = unsafe { libc::fdopendir(raw) };
        if dir.is_null() {
            let e = io::Error::last_os_error();
            // SAFETY: `fdopendir` failed, so `raw` is still ours to close.
            unsafe { libc::close(raw) };
            return Err(e);
        }
        Ok(Dir { dir })
    }

    fn fd(&self) -> RawFd {
        // SAFETY: `self.dir` is a live `DIR` stream.
        unsafe { libc::dirfd(self.dir) }
    }

    fn next(&mut self) -> io::Result<Option<(CString, u8)>> {
        loop {
            // SAFETY: `errno` is thread-local; `readdir` reads a valid open stream.
            unsafe { *libc::__errno_location() = 0 };
            // SAFETY: `self.dir` is valid; entry buffer lives until next `readdir`/`closedir`.
            let e = unsafe { libc::readdir(self.dir) };
            if e.is_null() {
                let err = io::Error::last_os_error();
                return if err.raw_os_error().unwrap_or(0) == 0 {
                    Ok(None)
                } else {
                    Err(err)
                };
            }
            // SAFETY: `d_name` is NUL-terminated.
            let (name, kind) = unsafe { (CStr::from_ptr((*e).d_name.as_ptr()), (*e).d_type) };
            if name == c"." || name == c".." {
                continue;
            }
            return Ok(Some((name.to_owned(), kind)));
        }
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        // SAFETY: owned stream closed once.
        unsafe { libc::closedir(self.dir) };
    }
}

fn check(ret: libc::c_int) -> io::Result<()> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn open_at_raw(dir: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: valid `dir` fd and NUL-terminated `name`.
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC) };
    check(fd)?;
    // SAFETY: fresh descriptor owned solely by us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: zeroed `stat` is valid; `fstat` fills it for a valid `fd`.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    check(unsafe { libc::fstat(fd, &mut st) })?;
    Ok(st)
}

fn fstatat_nofollow(dir: RawFd, name: &CStr) -> io::Result<libc::stat> {
    // SAFETY: zeroed `stat` is valid; `AT_SYMLINK_NOFOLLOW` never follows symlinks.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    check(unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) })?;
    Ok(st)
}

/// Mount ID of `fd` from `statx(STATX_MNT_ID)` (Linux 5.8+); `None` if unsupported.
fn mount_id_fd(fd: RawFd) -> Option<u64> {
    // SAFETY: `statx` is plain data; `AT_EMPTY_PATH` queries `fd` itself.
    unsafe {
        let mut stx: libc::statx = std::mem::zeroed();
        let ret = libc::syscall(
            libc::SYS_statx,
            libc::c_long::from(fd),
            c"".as_ptr(),
            libc::c_long::from(libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW),
            libc::c_long::from(libc::STATX_MNT_ID),
            &mut stx as *mut libc::statx,
        );
        (ret == 0 && stx.stx_mask & libc::STATX_MNT_ID != 0).then_some(stx.stx_mnt_id)
    }
}

/// Mount ID of `(dir, name)` without following symlinks (`statx` on Linux 5.8+).
fn mount_id_at(dir: RawFd, name: &CStr) -> Option<u64> {
    // SAFETY: `statx` is plain data; `AT_SYMLINK_NOFOLLOW` inspects `name` itself.
    unsafe {
        let mut stx: libc::statx = std::mem::zeroed();
        let ret = libc::syscall(
            libc::SYS_statx,
            libc::c_long::from(dir),
            name.as_ptr(),
            libc::c_long::from(libc::AT_SYMLINK_NOFOLLOW),
            libc::c_long::from(libc::STATX_MNT_ID),
            &mut stx as *mut libc::statx,
        );
        (ret == 0 && stx.stx_mask & libc::STATX_MNT_ID != 0).then_some(stx.stx_mnt_id)
    }
}

fn mount_of(fd: RawFd) -> io::Result<(libc::stat, MountId)> {
    let st = fstat(fd)?;
    Ok((st, (st.st_dev, mount_id_fd(fd))))
}

fn same_mount(a: MountId, b: MountId) -> bool {
    a.0 == b.0 && !matches!((a.1, b.1), (Some(x), Some(y)) if x != y)
}

fn mount_err(name: &CStr) -> io::Error {
    io::Error::other(format!(
        "{} is on another mount inside the tree",
        name.to_string_lossy()
    ))
}

fn fchmod_dir(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is an open directory descriptor (`O_DIRECTORY | O_NOFOLLOW`), never a symlink.
    check(unsafe { libc::fchmod(fd, 0o700) })
}

fn unlink_raw(dir: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: valid directory descriptor and single NUL-terminated component.
    check(unsafe { libc::unlinkat(dir, name.as_ptr(), flags) })
}

/// Unlinks `name` inside open tree directory `cur_fd`, retrying once after
/// `fchmod(cur_fd, 0o700)` if `cur_fd` was read-only (`EACCES`).
fn unlink_in_tree(cur_fd: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<()> {
    match unlink_raw(cur_fd, name, flags) {
        Err(e) if e.raw_os_error() == Some(libc::EACCES) => {
            fchmod_dir(cur_fd)?;
            unlink_raw(cur_fd, name, flags)
        }
        r => r,
    }
}

fn is_dir_in_tree(cur_fd: RawFd, name: &CStr) -> io::Result<bool> {
    let st = match fstatat_nofollow(cur_fd, name) {
        Ok(st) => st,
        Err(e) if e.raw_os_error() == Some(libc::EACCES) => {
            fchmod_dir(cur_fd)?;
            fstatat_nofollow(cur_fd, name)?
        }
        Err(e) => return Err(e),
    };
    Ok(st.st_mode & libc::S_IFMT == libc::S_IFDIR)
}

/// Opens child directory `name` under `dir` without following symlinks and
/// verifies it resides on `expected_mnt`. On `EACCES` (e.g. a `0000` directory,
/// or `dir` inside the tree with mode `0400`), confirms `S_IFDIR` via
/// `fstatat(..., AT_SYMLINK_NOFOLLOW)` and same-mount BEFORE calling
/// `fchmodat(dir, name, 0o700, 0)` and retrying once.
fn open_dir_checked(
    dir: RawFd,
    name: &CStr,
    expected_mnt: MountId,
    dir_in_tree: bool,
) -> io::Result<(OwnedFd, libc::stat)> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let fd = match open_at_raw(dir, name, flags) {
        Ok(fd) => fd,
        Err(e) if e.raw_os_error() == Some(libc::EACCES) => {
            if dir_in_tree {
                let _ = fchmod_dir(dir);
            }
            let st = fstatat_nofollow(dir, name)?;
            if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
                return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
            }
            if !same_mount((st.st_dev, mount_id_at(dir, name)), expected_mnt) {
                return Err(mount_err(name));
            }
            // SAFETY: confirmed `S_IFDIR` via `AT_SYMLINK_NOFOLLOW` on `expected_mnt` (never a symlink).
            check(unsafe { libc::fchmodat(dir, name.as_ptr(), 0o700, 0) })?;
            open_at_raw(dir, name, flags)?
        }
        Err(e) => return Err(e),
    };
    let (st, mnt) = mount_of(fd.as_raw_fd())?;
    if !same_mount(mnt, expected_mnt) {
        return Err(mount_err(name));
    }
    Ok((fd, st))
}

/// Removes `path` (a file, symlink, or directory tree of any depth). Returns
/// `NotFound` if `path` does not exist.
pub fn remove_tree(path: &Path) -> io::Result<()> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("cannot remove {}", path.display()),
        )
    })?;
    let name =
        CString::new(name.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let parent = CString::new(parent.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let parent = open_at_raw(libc::AT_FDCWD, &parent, libc::O_PATH | libc::O_DIRECTORY)?;
    let (_, parent_mnt) = mount_of(parent.as_raw_fd())?;

    match unlink_raw(parent.as_raw_fd(), &name, libc::AT_REMOVEDIR) {
        Ok(()) => return Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => {
            return unlink_raw(parent.as_raw_fd(), &name, 0);
        }
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTEMPTY | libc::EEXIST)) => {}
        Err(e) => return Err(e),
    }

    for _ in 0..PASSES {
        let (top, _) = open_dir_checked(parent.as_raw_fd(), &name, parent_mnt, false)?;
        let mut removed = 0u64;
        let pass = empty(Dir::open(top)?, parent_mnt, &mut removed)
            .and_then(|()| unlink_raw(parent.as_raw_fd(), &name, libc::AT_REMOVEDIR));
        match pass {
            Err(e)
                if matches!(e.raw_os_error(), Some(libc::ENOTEMPTY | libc::EEXIST))
                    && removed > 0 =>
            {
                continue;
            }
            r => return r,
        }
    }
    Err(io::Error::other(format!(
        "{} kept getting new entries while it was removed",
        path.display()
    )))
}

/// Best-effort removal for `layers::retain`, ignoring `NotFound` and logging
/// unexpected errors.
pub fn remove_entry(path: &Path) {
    if let Err(e) = remove_tree(path)
        && e.kind() != io::ErrorKind::NotFound
    {
        eprintln!("kiri-init: remove {}: {e}", path.display());
    }
}

fn empty(top: Dir, root_mnt: MountId, removed: &mut u64) -> io::Result<()> {
    let mut open: VecDeque<(usize, Dir)> = VecDeque::new();
    let mut names: Vec<CString> = Vec::new();
    let mut inos: Vec<libc::ino_t> = Vec::new();
    let mut anchors: Vec<(usize, OwnedFd)> = vec![(0, dup(top.fd())?)];
    let mut spacing = KEEP_OPEN;
    open.push_back((0, top));

    loop {
        let (depth, cur) = open.back_mut().expect("at least one open directory");
        let depth = *depth;
        match cur.next()? {
            Some((name, kind)) => {
                *removed += 1;
                if *removed > PASS_ENTRIES {
                    return Err(io::Error::other(
                        "the tree keeps getting new entries while it is removed",
                    ));
                }
                let fd = cur.fd();
                let is_dir = match kind {
                    libc::DT_DIR => true,
                    libc::DT_UNKNOWN => is_dir_in_tree(fd, &name)?,
                    _ => false,
                };
                if !is_dir {
                    match unlink_in_tree(fd, &name, 0) {
                        Ok(()) => continue,
                        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
                        Err(e) if e.raw_os_error() == Some(libc::EISDIR) => {}
                        Err(e) => return Err(e),
                    }
                }
                match unlink_in_tree(fd, &name, libc::AT_REMOVEDIR) {
                    Ok(()) => continue,
                    Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
                    Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => {
                        unlink_in_tree(fd, &name, 0)?;
                        continue;
                    }
                    Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTEMPTY | libc::EEXIST)) => {}
                    Err(e) => return Err(e),
                }
                let (sub, st) = open_dir_checked(fd, &name, root_mnt, true)?;
                names.truncate(depth);
                inos.truncate(depth);
                names.push(name);
                inos.push(st.st_ino);
                open.push_back((depth + 1, Dir::open(sub)?));
                if open.len() > KEEP_OPEN {
                    let (d, gone) = open.pop_front().expect("more than KEEP_OPEN");
                    if d > 0 && d % spacing == 0 && anchors.last().is_none_or(|(a, _)| *a < d) {
                        anchors.push((d, dup(gone.fd())?));
                        if anchors.len() > ANCHORS + SUB_ANCHORS {
                            spacing *= 2;
                            anchors.retain(|(a, _)| *a % spacing == 0);
                        }
                    }
                }
            }
            None => {
                let (d, done) = open.pop_back().expect("at least one open directory");
                if d == 0 {
                    return Ok(());
                }
                drop(done);
                anchors.retain(|(a, _)| *a < d);
                if open.is_empty() {
                    let (a, from) = anchors.last().expect("root anchor stays at 0");
                    let (a, mut fd) = (
                        *a,
                        open_at_raw(from.as_raw_fd(), c".", libc::O_RDONLY | libc::O_DIRECTORY)?,
                    );
                    let sub = ((d - a) / (SUB_ANCHORS + 1)).max(KEEP_OPEN);
                    let mut refill: VecDeque<(usize, OwnedFd)> = VecDeque::new();
                    for k in a + 1..d {
                        if (k - 1 - a) % sub == 0
                            && k - 1 > a
                            && anchors.len() < ANCHORS + SUB_ANCHORS
                        {
                            anchors.push((k - 1, dup(fd.as_raw_fd())?));
                        }
                        refill.push_back((k - 1, fd));
                        if refill.len() > KEEP_OPEN - 1 {
                            refill.pop_front();
                        }
                        let parent = refill.back().expect("just pushed").1.as_raw_fd();
                        let (next_fd, st) =
                            open_dir_checked(parent, &names[k - 1], root_mnt, true)?;
                        if st.st_ino != inos[k - 1] {
                            return Err(io::Error::other("the tree changed while it was removed"));
                        }
                        fd = next_fd;
                    }
                    refill.push_back((d - 1, fd));
                    for (k, fd) in refill {
                        open.push_back((k, Dir::open(fd)?));
                    }
                }
                let (up_depth, up) = open.back().expect("parent directory is open");
                debug_assert_eq!(*up_depth, d - 1);
                unlink_in_tree(up.fd(), &names[d - 1], libc::AT_REMOVEDIR)?;
                names.truncate(d - 1);
                inos.truncate(d - 1);
            }
        }
    }
}

fn dup(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: `fd` is a live open directory descriptor.
    let n = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    check(n)?;
    // SAFETY: fresh duplicated descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(n) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::{Duration, Instant};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kiri-rmtree-{tag}-{}", std::process::id()));
        if d.exists() {
            let _ = remove_tree(&d);
        }
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn deep(root: &Path, depth: usize, every: usize) {
        let mut fd = open_at_raw(
            libc::AT_FDCWD,
            &CString::new(root.as_os_str().as_bytes()).unwrap(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )
        .unwrap();
        for i in 0..depth {
            // SAFETY: confined `*at` calls under owned descriptor.
            unsafe {
                assert_eq!(libc::mkdirat(fd.as_raw_fd(), c"d".as_ptr(), 0o755), 0);
                if every > 0 && i % every == 0 {
                    let f = libc::openat(
                        fd.as_raw_fd(),
                        c"f".as_ptr(),
                        libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC,
                        0o644,
                    );
                    libc::close(f);
                    libc::symlinkat(c"/".as_ptr(), fd.as_raw_fd(), c"l".as_ptr());
                }
            }
            fd = open_at_raw(fd.as_raw_fd(), c"d", libc::O_RDONLY | libc::O_DIRECTORY).unwrap();
        }
    }

    #[test]
    fn removes_files_wide_dirs_and_never_follows_symlinks() {
        let d = scratch("plain");
        let (t, keep) = (d.join("t"), d.join("keep"));
        fs::create_dir_all(t.join("a/b/c")).unwrap();
        fs::create_dir_all(&keep).unwrap();
        fs::write(keep.join("k"), "k").unwrap();
        fs::set_permissions(&keep, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(t.join("a/f"), "f").unwrap();
        fs::write(t.join("a/b/c/g"), "g").unwrap();
        symlink(&keep, t.join("a/b/to_keep")).unwrap();
        symlink(keep.join("k"), t.join("a/b/c/to_keep_file")).unwrap();
        for i in 0..300 {
            fs::create_dir_all(t.join(format!("wide/{i}/x"))).unwrap();
        }
        remove_tree(&t).unwrap();
        assert!(!t.exists());
        assert_eq!(fs::read_to_string(keep.join("k")).unwrap(), "k");
        symlink(&keep, d.join("top_link")).unwrap();
        remove_tree(&d.join("top_link")).unwrap();
        assert!(keep.join("k").exists());
        assert_eq!(
            remove_tree(&d.join("missing")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        remove_entry(&d.join("missing"));
        remove_tree(&d).unwrap();
    }

    #[test]
    fn removes_deep_tree_past_2000_levels_and_readonly_0500_0000_past_path_max() {
        let d = scratch("deep-ro");
        // 1. 2,500-level tree in-process on a small 256 KiB thread stack.
        let t1 = d.join("t1");
        fs::create_dir(&t1).unwrap();
        deep(&t1, 2_500, 113);
        let t1_clone = t1.clone();
        std::thread::Builder::new()
            .stack_size(256 << 10)
            .spawn(move || remove_tree(&t1_clone))
            .unwrap()
            .join()
            .unwrap()
            .unwrap();
        assert!(!t1.exists());

        // 2. Read-only `0500` and `0000` directories at depth 1,200 with 8-char
        // segment names (> 10,000 bytes total path, well past PATH_MAX = 4096),
        // plus symlinks to an external 0555 directory whose mode must not change!
        let outside = d.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret"), "intact").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o555)).unwrap();
        let outside_c = CString::new(outside.as_os_str().as_bytes()).unwrap();

        let t2 = d.join("t2");
        fs::create_dir(&t2).unwrap();
        let mut fds: Vec<OwnedFd> = Vec::with_capacity(1_200);
        let mut cur = open_at_raw(
            libc::AT_FDCWD,
            &CString::new(t2.as_os_str().as_bytes()).unwrap(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )
        .unwrap();
        for i in 0..1_200 {
            // SAFETY: confined `*at` calls on owned descriptors.
            unsafe {
                assert_eq!(
                    libc::mkdirat(cur.as_raw_fd(), c"sub_dir_".as_ptr(), 0o700),
                    0
                );
                if i % 50 == 0 {
                    let f = libc::openat(
                        cur.as_raw_fd(),
                        c"ro_file".as_ptr(),
                        libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC,
                        0o400,
                    );
                    libc::close(f);
                    assert_eq!(
                        libc::symlinkat(outside_c.as_ptr(), cur.as_raw_fd(), c"sym_out".as_ptr()),
                        0
                    );
                }
            }
            let next = open_at_raw(
                cur.as_raw_fd(),
                c"sub_dir_",
                libc::O_RDONLY | libc::O_DIRECTORY,
            )
            .unwrap();
            fds.push(cur);
            cur = next;
        }
        fds.push(cur);
        // Lock permissions bottom-up to alternating 0000 and 0500!
        for (i, fd) in fds.into_iter().enumerate().rev() {
            let mode = if i % 2 == 0 { 0o000 } else { 0o500 };
            // SAFETY: valid owned directory fd.
            assert_eq!(unsafe { libc::fchmod(fd.as_raw_fd(), mode) }, 0);
        }

        remove_tree(&t2).unwrap();
        assert!(!t2.exists());
        assert_eq!(
            fs::symlink_metadata(&outside).unwrap().permissions().mode() & 0o777,
            0o555,
            "symlink target mode untouched"
        );
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            fs::read_to_string(outside.join("secret")).unwrap(),
            "intact"
        );
        remove_tree(&d).unwrap();
    }

    #[test]
    #[ignore]
    fn deep_removal_child() {
        let Some(dir) = std::env::var_os("KIRI_RMTREE_DEEP") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        let r = std::thread::Builder::new()
            .stack_size(256 << 10)
            .spawn(move || remove_tree(&dir).map_err(|e| e.to_string()))
            .unwrap()
            .join()
            .unwrap();
        r.unwrap();
    }

    #[test]
    fn refuses_tmpfs_and_same_fs_bind_mounts_inside_tree() {
        // SAFETY: plain getter.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipped: needs root for mount checks");
            return;
        }
        let d = scratch("mounts");
        let m = d.join("t/a/m");
        fs::create_dir_all(&m).unwrap();
        let mc = CString::new(m.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid C strings.
        assert_eq!(
            unsafe {
                libc::mount(
                    c"tmpfs".as_ptr(),
                    mc.as_ptr(),
                    c"tmpfs".as_ptr(),
                    0,
                    std::ptr::null(),
                )
            },
            0
        );
        fs::write(m.join("kept"), "1").unwrap();
        assert!(remove_tree(&d.join("t")).is_err());
        assert!(m.join("kept").exists());
        // SAFETY: valid C path.
        unsafe { libc::umount2(mc.as_ptr(), libc::MNT_DETACH) };

        // Same-filesystem MS_BIND submount guarded by STATX_MNT_ID.
        let top_fd = open_at_raw(
            libc::AT_FDCWD,
            &CString::new(d.as_os_str().as_bytes()).unwrap(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )
        .unwrap();
        if mount_id_fd(top_fd.as_raw_fd()).is_some() {
            let bind_src = d.join("bind_src");
            fs::create_dir_all(&bind_src).unwrap();
            fs::write(bind_src.join("bind_kept"), "1").unwrap();
            fs::create_dir_all(&m).unwrap();
            let sc = CString::new(bind_src.as_os_str().as_bytes()).unwrap();
            // SAFETY: valid C strings.
            assert_eq!(
                unsafe {
                    libc::mount(
                        sc.as_ptr(),
                        mc.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND,
                        std::ptr::null(),
                    )
                },
                0
            );
            assert!(remove_tree(&d.join("t")).is_err());
            assert!(
                bind_src.join("bind_kept").exists(),
                "same-fs bind mount must not be entered"
            );
            // SAFETY: valid C path.
            unsafe { libc::umount2(mc.as_ptr(), libc::MNT_DETACH) };
        }
        let _ = Duration::from_secs(1);
        let _ = Instant::now();
        remove_tree(&d).unwrap();
    }
}
