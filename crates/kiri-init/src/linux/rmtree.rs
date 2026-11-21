//! Removing a folder tree that a container or a build step shaped: its
//! writable layer, a cache folder, a volume's data, a layer made from a
//! step. Such a tree can be any depth (`while :; do mkdir d; cd d; done`).
//! `std::fs::remove_dir_all` recurses once per level and holds a descriptor
//! per level: with the agent's open-files limit at 1,048,576 a deep enough
//! tree runs the stack out (a crash of the agent, every container with it),
//! and with a low limit it stops at EMFILE half done.
//!
//! Here the walk is a loop. At most `KEEP_OPEN` folders are open at once:
//! the deepest ones, each read as a stream that goes on where it was after
//! a folder below it is gone. A folder closed for want of room is opened
//! again later from the nearest folder kept above it (an anchor: at most
//! `ANCHORS` are kept, spaced evenly down the tree), by the names it was
//! entered by, each checked to be the same folder (device and inode) and
//! opened with `O_NOFOLLOW`; it is then read from its start (what is left
//! in it is only what was not removed yet). `..` is never used: on a mount
//! of a subfolder (a Docker volume, a bind mount) each `..` costs the
//! kernel a walk to the mount's root, and a deep tree took minutes. Nothing
//! is followed: a link is removed as itself, and a folder on another file
//! system (a mount inside the tree) is not entered: the removal stops with
//! an error instead, as it does at the first error of any kind.
//!
//! Something may still write in the tree while it goes (a step in a cache
//! folder being pruned). A folder that is not empty when its turn to go
//! comes starts a new pass over the tree; a pass that removed nothing, more
//! than `PASSES` passes, or more than `PASS_ENTRIES` names in one pass end
//! the removal with an error instead of a walk that never ends.

use std::collections::VecDeque;
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Folders kept open at once (the deepest), at most.
const KEEP_OPEN: usize = 48;

/// Folders kept above them to open closed ones again from, at most: spaced
/// evenly on the way down, and `SUB_ANCHORS` more within the stretch a
/// climb walks again.
const ANCHORS: usize = 24;
const SUB_ANCHORS: usize = 16;

/// Passes over a tree that keeps getting new entries, at most.
const PASSES: usize = 4;

/// Names one pass removes, at most (a writer that never stops).
const PASS_ENTRIES: u64 = 1 << 26;

/// One open folder, read as a stream.
struct Dir {
    dir: *mut libc::DIR,
}

impl Dir {
    fn open(fd: OwnedFd) -> io::Result<Dir> {
        let raw = fd.into_raw_fd();
        // SAFETY: a directory descriptor we own; on success the stream owns it.
        let dir = unsafe { libc::fdopendir(raw) };
        if dir.is_null() {
            let e = io::Error::last_os_error();
            // SAFETY: fdopendir failed, so the descriptor is still ours.
            unsafe { libc::close(raw) };
            return Err(e);
        }
        Ok(Dir { dir })
    }

    fn fd(&self) -> RawFd {
        // SAFETY: a valid stream.
        unsafe { libc::dirfd(self.dir) }
    }

    /// The next name and its type (`DT_*`), `.` and `..` left out.
    fn next(&mut self) -> io::Result<Option<(CString, u8)>> {
        loop {
            // SAFETY: errno is thread-local; readdir sets it only on error.
            unsafe { *libc::__errno_location() = 0 };
            // SAFETY: a valid stream; the entry stays valid until the next call.
            let e = unsafe { libc::readdir(self.dir) };
            if e.is_null() {
                let err = io::Error::last_os_error();
                return if err.raw_os_error() == Some(0) { Ok(None) } else { Err(err) };
            }
            // SAFETY: readdir returned an entry with a NUL-terminated name.
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
        // SAFETY: the stream is ours and closed once.
        unsafe { libc::closedir(self.dir) };
    }
}

fn check(ret: libc::c_int) -> io::Result<()> {
    if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

fn open_at(dir: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: a valid directory descriptor and NUL-terminated name; owned right away.
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC) };
    check(fd)?;
    // SAFETY: a fresh descriptor nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: fstat into a zeroed stat.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    check(unsafe { libc::fstat(fd, &mut st) })?;
    Ok(st)
}

fn unlink_at(dir: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: a valid directory descriptor and a single NUL-terminated name.
    check(unsafe { libc::unlinkat(dir, name.as_ptr(), flags) })
}

fn is_dir_at(dir: RawFd, name: &CStr) -> io::Result<bool> {
    // SAFETY: fstatat of one name under a valid descriptor, not following links.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    check(unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) })?;
    Ok(st.st_mode & libc::S_IFMT == libc::S_IFDIR)
}

/// Removes `path` and everything under it, as `std::fs::remove_dir_all`
/// does (a link is removed as itself; a missing path is NotFound), in
/// bounded stack and descriptors whatever the depth.
pub fn remove_all(path: &Path) -> io::Result<()> {
    let name = path.file_name().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("cannot remove {}", path.display())))?;
    let name = CString::new(name.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let parent = CString::new(parent.as_os_str().as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let parent = open_at(libc::AT_FDCWD, &parent, libc::O_PATH | libc::O_DIRECTORY)?;
    // Not a folder (a link to one included), or an empty one: one call.
    match unlink_at(parent.as_raw_fd(), &name, libc::AT_REMOVEDIR) {
        Ok(()) => return Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => return unlink_at(parent.as_raw_fd(), &name, 0),
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTEMPTY | libc::EEXIST)) => {}
        Err(e) => return Err(e),
    }
    for _ in 0..PASSES {
        let top = open_at(parent.as_raw_fd(), &name, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
        let st = fstat(top.as_raw_fd())?;
        let dev = st.st_dev;
        let mut removed = 0u64;
        let pass = empty(Dir::open(top)?, dev, &mut removed).and_then(|()| unlink_at(parent.as_raw_fd(), &name, libc::AT_REMOVEDIR));
        match pass {
            // Written to while it went: another pass, if this one got anywhere.
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTEMPTY | libc::EEXIST)) && removed > 0 => continue,
            r => return r,
        }
    }
    Err(io::Error::other(format!("{} kept getting new entries while it was removed", path.display())))
}

/// Empties the folder `top` (on device `dev`) of everything; `removed`
/// counts the names it went through.
fn empty(top: Dir, dev: libc::dev_t, removed: &mut u64) -> io::Result<()> {
    // The open window: (depth, folder), depths contiguous, deepest last.
    let mut open: VecDeque<(usize, Dir)> = VecDeque::new();
    // The folder at depth d+1 is names[d] in the one above, inode inos[d].
    let mut names: Vec<CString> = Vec::new();
    let mut inos: Vec<libc::ino_t> = Vec::new();
    // (depth, descriptor) of folders kept to open closed ones again from;
    // the top is always the first. Spaced `spacing` levels apart.
    let mut anchors: Vec<(usize, OwnedFd)> = vec![(0, dup(top.fd())?)];
    let mut spacing = KEEP_OPEN;
    open.push_back((0, top));
    loop {
        let (depth, cur) = open.back_mut().expect("one folder stays open");
        let depth = *depth;
        match cur.next()? {
            Some((name, kind)) => {
                *removed += 1;
                if *removed > PASS_ENTRIES {
                    return Err(io::Error::other("the tree keeps getting new entries while it is removed"));
                }
                let fd = cur.fd();
                let is_dir = match kind {
                    libc::DT_DIR => true,
                    libc::DT_UNKNOWN => is_dir_at(fd, &name)?,
                    _ => false,
                };
                if !is_dir {
                    match unlink_at(fd, &name, 0) {
                        Ok(()) => continue,
                        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
                        // It became a folder meanwhile: taken as one below.
                        Err(e) if e.raw_os_error() == Some(libc::EISDIR) => {}
                        Err(e) => return Err(e),
                    }
                }
                match unlink_at(fd, &name, libc::AT_REMOVEDIR) {
                    Ok(()) => continue,
                    Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
                    Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => {
                        unlink_at(fd, &name, 0)?;
                        continue;
                    }
                    Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTEMPTY | libc::EEXIST)) => {}
                    Err(e) => return Err(e),
                }
                let sub = open_at(fd, &name, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
                let st = fstat(sub.as_raw_fd())?;
                if st.st_dev != dev {
                    return Err(io::Error::other(format!("{} is on another file system (a mount inside the tree)", name.to_string_lossy())));
                }
                names.truncate(depth);
                inos.truncate(depth);
                names.push(name);
                inos.push(st.st_ino);
                open.push_back((depth + 1, Dir::open(sub)?));
                if open.len() > KEEP_OPEN {
                    let (d, gone) = open.pop_front().expect("more than one open");
                    if d > 0 && d % spacing == 0 && anchors.last().is_none_or(|(a, _)| *a < d) {
                        anchors.push((d, dup(gone.fd())?));
                        if anchors.len() > ANCHORS + SUB_ANCHORS {
                            // Half as many, twice as far apart (the top stays).
                            spacing *= 2;
                            anchors.retain(|(a, _)| *a % spacing == 0);
                        }
                    }
                }
            }
            None => {
                let (d, done) = open.pop_back().expect("one folder stays open");
                if d == 0 {
                    return Ok(());
                }
                drop(done);
                anchors.retain(|(a, _)| *a < d);
                if open.is_empty() {
                    // The folder above was closed: opened again from the
                    // nearest anchor above it, by name, each step checked.
                    let (a, from) = anchors.last().expect("the top is an anchor");
                    let (a, mut fd) = (*a, open_at(from.as_raw_fd(), c".", libc::O_RDONLY | libc::O_DIRECTORY)?);
                    // Anchors are left on the way down too, closer together,
                    // so the next climb out of the window walks less: the
                    // walks add up to about depth x log(depth), not depth².
                    let sub = ((d - a) / (SUB_ANCHORS + 1)).max(KEEP_OPEN);
                    let mut refill: VecDeque<(usize, OwnedFd)> = VecDeque::new();
                    for k in a + 1..d {
                        if (k - 1 - a) % sub == 0 && k - 1 > a && anchors.len() < ANCHORS + SUB_ANCHORS {
                            anchors.push((k - 1, dup(fd.as_raw_fd())?));
                        }
                        refill.push_back((k - 1, fd));
                        if refill.len() > KEEP_OPEN - 1 {
                            refill.pop_front();
                        }
                        let parent = refill.back().expect("just pushed").1.as_raw_fd();
                        fd = open_at(parent, &names[k - 1], libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
                        let st = fstat(fd.as_raw_fd())?;
                        if st.st_dev != dev || st.st_ino != inos[k - 1] {
                            return Err(io::Error::other("the tree changed while it was removed"));
                        }
                    }
                    refill.push_back((d - 1, fd));
                    for (k, fd) in refill {
                        open.push_back((k, Dir::open(fd)?));
                    }
                }
                let (up_depth, up) = open.back().expect("the folder above is open");
                debug_assert_eq!(*up_depth, d - 1);
                unlink_at(up.fd(), &names[d - 1], libc::AT_REMOVEDIR)?;
                names.truncate(d - 1);
                inos.truncate(d - 1);
            }
        }
    }
}

/// A second descriptor of the same open folder.
fn dup(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: duplicating a valid descriptor; the copy is owned right away.
    let n = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    check(n)?;
    // SAFETY: a fresh descriptor nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(n) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::time::{Duration, Instant};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kiri-rmtree-{tag}-{}", std::process::id()));
        if d.exists() {
            remove_all(&d).unwrap();
        }
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// `root/d/d/.../d` `depth` folders deep, made through descriptors (the
    /// path is far longer than PATH_MAX), with a file and a link at the
    /// bottom and every `every`-th level.
    fn deep(root: &Path, depth: usize, every: usize) {
        let mut fd = open_at(libc::AT_FDCWD, &CString::new(root.as_os_str().as_bytes()).unwrap(), libc::O_RDONLY | libc::O_DIRECTORY).unwrap();
        for i in 0..depth {
            // SAFETY: plain *at calls under a descriptor we own.
            unsafe {
                assert_eq!(libc::mkdirat(fd.as_raw_fd(), c"d".as_ptr(), 0o755), 0);
                if every > 0 && i % every == 0 {
                    let f = libc::openat(fd.as_raw_fd(), c"f".as_ptr(), libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC, 0o644);
                    libc::close(f);
                    libc::symlinkat(c"/".as_ptr(), fd.as_raw_fd(), c"l".as_ptr());
                }
            }
            fd = open_at(fd.as_raw_fd(), c"d", libc::O_RDONLY | libc::O_DIRECTORY).unwrap();
        }
    }

    #[test]
    fn a_tree_of_files_links_and_folders_goes_and_what_links_point_at_stays() {
        let d = scratch("plain");
        let (t, keep) = (d.join("t"), d.join("keep"));
        fs::create_dir_all(t.join("a/b/c")).unwrap();
        fs::create_dir_all(&keep).unwrap();
        fs::write(keep.join("k"), "k").unwrap();
        fs::write(t.join("a/f"), "f").unwrap();
        fs::write(t.join("a/b/c/g"), "g").unwrap();
        symlink(&keep, t.join("a/b/to_keep")).unwrap();
        symlink(&keep, t.join("a/b/c/to_keep_dir")).unwrap();
        for i in 0..300 {
            fs::create_dir_all(t.join(format!("wide/{i}/x"))).unwrap();
        }
        let c = CString::new(t.join("fifo").as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        remove_all(&t).unwrap();
        assert!(!t.exists());
        assert_eq!(fs::read_to_string(keep.join("k")).unwrap(), "k", "a link is removed, not followed");
        // A link at the top is removed as itself, a file as a file.
        symlink(&keep, d.join("top")).unwrap();
        remove_all(&d.join("top")).unwrap();
        assert!(keep.join("k").exists());
        fs::write(d.join("file"), "").unwrap();
        remove_all(&d.join("file")).unwrap();
        assert_eq!(remove_all(&d.join("missing")).unwrap_err().kind(), io::ErrorKind::NotFound);
        remove_all(&d).unwrap();
    }

    /// The removal itself, run by `a_tree_100000_folders_deep_goes_in_bounded_stack_and_descriptors`
    /// in a process of its own (open-files limit 128) on a thread with a
    /// 256 KiB stack. Does nothing when run on its own.
    #[test]
    #[ignore]
    fn deep_removal_child() {
        let Some(dir) = std::env::var_os("KIRI_RMTREE_DEEP") else { return };
        let dir = std::path::PathBuf::from(dir);
        let r = std::thread::Builder::new().stack_size(256 << 10).spawn(move || remove_all(&dir).map_err(|e| e.to_string())).unwrap().join().unwrap();
        r.unwrap();
    }

    /// A container left `mkdir d; cd d` 100,000 times: removed whole, in a
    /// process that may open only 128 files, on a 256 KiB stack, in bounded
    /// time. (`std::fs::remove_dir_all` needs a descriptor and a stack
    /// frame per level.)
    #[test]
    fn a_tree_100000_folders_deep_goes_in_bounded_stack_and_descriptors() {
        use std::os::unix::process::CommandExt;
        let d = scratch("deep");
        let t = d.join("t");
        fs::create_dir(&t).unwrap();
        deep(&t, 100_000, 997);
        let started = Instant::now();
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", "linux::rmtree::tests::deep_removal_child", "--ignored", "--nocapture", "--test-threads", "1"]).env("KIRI_RMTREE_DEEP", &t);
        // SAFETY: only setrlimit runs between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                let rl = libc::rlimit { rlim_cur: 128, rlim_max: 128 };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &rl) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let out = cmd.output().unwrap();
        let took = started.elapsed();
        assert!(out.status.success(), "the removal failed: {}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(!t.exists(), "the tree is gone");
        assert!(took < Duration::from_secs(120), "took {took:?}");
        eprintln!("100000 levels removed in {took:?}");
        remove_all(&d).unwrap();
    }

    /// The agent killed in the middle of a removal (a crash, a stop) leaves
    /// a tree half gone: the next removal of it (the clean-up at the next
    /// start) finishes it, whatever was left where.
    #[test]
    fn a_removal_cut_short_is_finished_by_the_next() {
        use std::os::unix::process::CommandExt;
        let d = scratch("cut");
        let t = d.join("t");
        fs::create_dir(&t).unwrap();
        deep(&t, 100_000, 499);
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", "linux::rmtree::tests::deep_removal_child", "--ignored", "--nocapture", "--test-threads", "1"]).env("KIRI_RMTREE_DEEP", &t);
        // SAFETY: only setrlimit runs between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                let rl = libc::rlimit { rlim_cur: 128, rlim_max: 128 };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &rl) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().unwrap();
        std::thread::sleep(Duration::from_millis(150));
        let _ = child.kill();
        let _ = child.wait();
        assert!(t.exists(), "killed before it finished");
        let started = Instant::now();
        remove_all(&t).unwrap();
        assert!(!t.exists());
        eprintln!("the rest of a cut-short removal went in {:?}", started.elapsed());
        remove_all(&d).unwrap();
    }

    /// Something that keeps writing in the tree while it goes does not keep
    /// the removal going for ever: it ends, with an error if the tree is
    /// not gone, and once the writing stops the tree goes.
    #[test]
    fn a_tree_written_to_while_it_goes_does_not_hold_the_removal() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let d = scratch("busy");
        let t = d.join("t");
        fs::create_dir_all(t.join("a/b")).unwrap();
        for i in 0..2000 {
            fs::write(t.join(format!("a/b/f{i}")), "").unwrap();
        }
        let stop = Arc::new(AtomicBool::new(false));
        let writer = {
            let (stop, dir) = (stop.clone(), t.join("a/b"));
            std::thread::spawn(move || {
                let mut n = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let _ = fs::create_dir_all(&dir);
                    let _ = fs::write(dir.join(format!("w{n}")), "");
                    n += 1;
                }
            })
        };
        let started = Instant::now();
        let r = remove_all(&t);
        let took = started.elapsed();
        stop.store(true, Ordering::Relaxed);
        writer.join().unwrap();
        assert!(took < Duration::from_secs(60), "took {took:?}");
        eprintln!("with a writer: {:?} after {took:?}", r.as_ref().map_err(|e| e.to_string()));
        let _ = remove_all(&t);
        assert!(!t.exists());
        remove_all(&d).unwrap();
    }

    /// The same tree on a mount of a subfolder (a Docker volume, a bind
    /// mount): there each `..` costs the kernel a walk up to the mount's
    /// root, so climbing back by `..` took minutes for 100,000 levels.
    #[test]
    fn a_deep_tree_on_a_mount_of_a_subfolder_goes_in_bounded_time() {
        // SAFETY: no arguments.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipped: needs root (a bind mount)");
            return;
        }
        let d = scratch("bind");
        let (src, mnt) = (d.join("src/sub"), d.join("mnt"));
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&mnt).unwrap();
        let (s, m) = (CString::new(src.as_os_str().as_bytes()).unwrap(), CString::new(mnt.as_os_str().as_bytes()).unwrap());
        // SAFETY: valid strings.
        assert_eq!(unsafe { libc::mount(s.as_ptr(), m.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) }, 0);
        let t = mnt.join("t");
        fs::create_dir(&t).unwrap();
        deep(&t, 100_000, 997);
        let started = Instant::now();
        let r = remove_all(&t);
        let took = started.elapsed();
        // SAFETY: a valid path.
        unsafe { libc::umount2(m.as_ptr(), libc::MNT_DETACH) };
        r.unwrap();
        assert!(!src.join("t").exists());
        assert!(took < Duration::from_secs(60), "took {took:?}");
        eprintln!("100000 levels on a bind mount removed in {took:?}");
        remove_all(&d).unwrap();
    }

    /// A folder on another file system inside the tree is not entered.
    #[test]
    fn a_mount_inside_the_tree_is_not_entered() {
        // SAFETY: no arguments.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipped: needs root (a tmpfs mount)");
            return;
        }
        let d = scratch("mount");
        let m = d.join("t/a/m");
        fs::create_dir_all(&m).unwrap();
        let c = CString::new(m.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid strings.
        assert_eq!(unsafe { libc::mount(c"tmpfs".as_ptr(), c.as_ptr(), c"tmpfs".as_ptr(), 0, std::ptr::null()) }, 0);
        fs::write(m.join("kept"), "").unwrap();
        fs::create_dir(m.join("sub")).unwrap();
        assert!(remove_all(&d.join("t")).is_err());
        assert!(m.join("kept").exists(), "nothing on the mount was removed");
        // SAFETY: a valid path.
        unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
        remove_all(&d).unwrap();
    }
}
