//! Read-only views into running containers' filesystems, for browsing them
//! from the Mac. Every path is resolved with openat2(RESOLVE_IN_ROOT): the
//! container's root is `/` even for symlinks inside it, so nothing outside
//! the container is reachable.
//!
//! Links are shown as links, never as what they point at (#648): a folder
//! link that leads back up, as in /sys (`virtio5/subsystem/drivers/…/virtio5`)
//! or Debian's `/usr/bin/X11 -> .`, made an endless tree that Spotlight,
//! Finder and backup tools walked until the path got too long, keeping the
//! VM busy. Tree walkers don't follow links. The kernel's own filesystems
//! (/proc, /sys and the like) are not shown at all: they hold the kernel's
//! state, not the container's files, and are large and loop on themselves.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use kiri_proto::FsEntry;

use super::sys;

/// Entries per listing at most: keeps a reply well inside one frame.
pub const MAX_ENTRIES: usize = 5000;
/// Bytes per read at most.
pub const MAX_READ: usize = 512 * 1024;

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_IN_ROOT: u64 = 0x10;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Opens `path` under `root`, every symlink resolved inside `root`.
pub(super) fn open_in(root: RawFd, path: &str, flags: i32) -> io::Result<OwnedFd> {
    let rel = path.trim_start_matches('/');
    let c = CString::new(if rel.is_empty() { "." } else { rel }).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let how = OpenHow { flags: (flags | libc::O_CLOEXEC) as u64, mode: 0, resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS };
    // SAFETY: openat2 with a valid dirfd, path and open_how of the stated size.
    let fd = unsafe { libc::syscall(libc::SYS_openat2, root, c.as_ptr(), &how as *const OpenHow, std::mem::size_of::<OpenHow>()) };
    sys::check(fd, "open")?;
    // SAFETY: openat2 returned a fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

fn root_of(rootfs: &Path) -> io::Result<OwnedFd> {
    let c = sys::cstr(rootfs)?;
    // SAFETY: plain open of a directory; owned right away.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    sys::check(fd as _, "open rootfs")?;
    // SAFETY: fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// What the file browser shows of a file.
#[derive(Debug, Clone, Copy)]
pub struct Meta {
    pub mode: u32,
    pub size: u64,
    pub mtime: i64,
    pub mtime_nsec: u32,
    pub ino: u64,
}

impl From<&libc::stat> for Meta {
    fn from(st: &libc::stat) -> Meta {
        Meta { mode: st.st_mode, size: st.st_size as u64, mtime: st.st_mtime, mtime_nsec: st.st_mtime_nsec as u32, ino: st.st_ino }
    }
}

fn stat_fd(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: fstat into a zeroed stat.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    sys::check(unsafe { libc::fstat(fd, &mut st) } as _, "stat")?;
    Ok(st)
}

/// Whether `fd` is on one of the kernel's own filesystems: proc, sysfs and
/// what is mounted under them (cgroup, debugfs, tracefs, securityfs, bpf,
/// pstore, configfs, binfmt_misc, fusectl), devpts and mqueue.
fn kernel_fs(fd: RawFd) -> bool {
    const MAGIC: [u64; 14] = [
        0x9fa0, 0x6265_6572, 0x0027_e0eb, 0x6367_7270, 0x6462_6720, 0x7472_6163, 0x7365_6673,
        0xcafe_4a11, 0x6165_676c, 0x6265_6570, 0x4249_4e4d, 0x6573_5543, 0x1cd1, 0x1980_0202,
    ];
    // SAFETY: fstatfs into a zeroed statfs.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::fstatfs(fd, &mut st) } == 0;
    ok && MAGIC.contains(&(st.f_type as u64))
}

/// `open_in`, for what the browser shows: the kernel's filesystems are not
/// there.
fn open_shown(root: RawFd, path: &str, flags: i32) -> io::Result<OwnedFd> {
    let fd = open_in(root, path, flags)?;
    if kernel_fs(fd.as_raw_fd()) {
        return Err(io::Error::from_raw_os_error(libc::ENOENT));
    }
    Ok(fd)
}

/// Metadata of `path` itself: a link reports as a link (see the module).
pub fn stat(rootfs: &Path, path: &str) -> io::Result<Meta> {
    let root = root_of(rootfs)?;
    let fd = open_shown(root.as_raw_fd(), path, libc::O_PATH | libc::O_NOFOLLOW)?;
    Ok(Meta::from(&stat_fd(fd.as_raw_fd())?))
}

/// Where the link `path` points, as it says it.
pub fn read_link(rootfs: &Path, path: &str, buf: &mut Vec<u8>) -> io::Result<()> {
    let root = root_of(rootfs)?;
    let fd = open_shown(root.as_raw_fd(), path, libc::O_PATH | libc::O_NOFOLLOW)?;
    buf.resize(libc::PATH_MAX as usize, 0);
    // SAFETY: readlinkat of the link itself (an O_PATH descriptor and an
    // empty name) into a buffer we own.
    let n = unsafe { libc::readlinkat(fd.as_raw_fd(), c"".as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    sys::check(n as _, "readlink")?;
    buf.truncate(n as usize);
    Ok(())
}

/// A directory's entries, sorted by name, at most `MAX_ENTRIES`.
pub fn list(rootfs: &Path, path: &str) -> io::Result<Vec<(String, Meta)>> {
    let root = root_of(rootfs)?;
    let dir = open_shown(root.as_raw_fd(), path, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let dev = stat_fd(dir.as_raw_fd())?.st_dev;
    let mut out = Vec::new();
    // /proc/self/fd/N names the directory we already resolved safely.
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(c) = CString::new(name.as_str()) else { continue };
        // SAFETY: fstatat relative to the resolved directory, not following links.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(dir.as_raw_fd(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            continue;
        }
        // Another filesystem is mounted here: left out if it is the kernel's.
        if st.st_dev != dev && st.st_mode & libc::S_IFMT == libc::S_IFDIR {
            // SAFETY: openat relative to the resolved directory, not following links.
            let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
            if fd >= 0 {
                // SAFETY: openat returned a fresh descriptor.
                let fd = unsafe { OwnedFd::from_raw_fd(fd) };
                if kernel_fs(fd.as_raw_fd()) {
                    continue;
                }
            }
        }
        out.push((name, Meta::from(&st)));
        if out.len() >= MAX_ENTRIES {
            break;
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Up to `len` bytes from `offset` of a regular file. What the path names is
/// looked at before anything is opened for reading: opening a FIFO waits for
/// a writer, and opening a device does whatever its driver does. The read
/// does not wait either (/proc/kmsg is a regular file whose read waits for
/// the next kernel message). The agent has one thread, so a wait here
/// stopped every container's exec and start until it ended.
pub fn read(rootfs: &Path, path: &str, offset: u64, len: usize, buf: &mut Vec<u8>) -> io::Result<()> {
    let root = root_of(rootfs)?;
    let found = open_shown(root.as_raw_fd(), path, libc::O_PATH)?;
    if stat_fd(found.as_raw_fd())?.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
    }
    // The file found, opened by its descriptor: no path is resolved again.
    let c = CString::new(format!("/proc/self/fd/{}", found.as_raw_fd())).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: plain open of a path we made; owned right away.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC) };
    sys::check(fd as _, "open")?;
    // SAFETY: fresh descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    buf.resize(len.min(MAX_READ), 0);
    // SAFETY: pread into a buffer we own.
    let n = unsafe { libc::pread(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), offset as libc::off_t) };
    sys::check(n as _, "read")?;
    buf.truncate(n as usize);
    Ok(())
}

pub fn entry(name: &str, m: Meta) -> FsEntry<'_> {
    FsEntry { name, mode: m.mode, size: m.size, mtime: m.mtime, mtime_nsec: m.mtime_nsec, ino: m.ino }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::time::Duration;

    // A read of what is not a regular file is refused at once. Opening a
    // FIFO that has no writer waits for one, and the agent has one thread:
    // that read stopped every container's exec and start.
    #[test]
    fn a_fifo_is_refused_without_waiting_for_a_writer() {
        let dir = std::env::temp_dir().join(format!("kiri-fsview-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("file"), "hello").unwrap();
        let pipe = std::ffi::CString::new(dir.join("pipe").to_str().unwrap()).unwrap();
        // SAFETY: mkfifo of a path in our own folder.
        assert_eq!(unsafe { libc::mkfifo(pipe.as_ptr(), 0o644) }, 0);

        let (tx, rx) = std::sync::mpsc::channel();
        let root = dir.clone();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = tx.send(super::read(&root, "/pipe", 0, 16, &mut buf).map_err(|e| e.kind()));
        });
        let answer = rx.recv_timeout(Duration::from_secs(5)).expect("the read of a FIFO waited for a writer");
        assert_eq!(answer, Err(ErrorKind::InvalidInput));
        let mut buf = Vec::new();
        assert_eq!(super::read(&dir, "/", 0, 16, &mut buf).map_err(|e| e.kind()), Err(ErrorKind::InvalidInput), "a folder");

        // A regular file reads as before, from any offset.
        super::read(&dir, "/file", 0, 16, &mut buf).unwrap();
        assert_eq!(buf, b"hello");
        super::read(&dir, "/file", 3, 16, &mut buf).unwrap();
        assert_eq!(buf, b"lo");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // #648: a link is a link, so a folder link back up (Debian's
    // /usr/bin/X11 -> .) no longer makes an endless tree.
    #[test]
    fn links_are_shown_as_links() {
        let dir = std::env::temp_dir().join(format!("kiri-fsview-links-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("usr/bin")).unwrap();
        std::os::unix::fs::symlink(".", dir.join("usr/bin/X11")).unwrap();
        std::os::unix::fs::symlink("/usr/bin", dir.join("bin")).unwrap();
        let link = |m: super::Meta| m.mode & libc::S_IFMT == libc::S_IFLNK;

        let list = super::list(&dir, "/usr/bin").unwrap();
        assert_eq!(list.iter().map(|(n, m)| (n.as_str(), link(*m))).collect::<Vec<_>>(), [("X11", true)]);
        assert!(link(super::stat(&dir, "/usr/bin/X11").unwrap()));
        assert!(link(super::stat(&dir, "/bin").unwrap()));
        // A link on the way is still followed inside the container: only
        // the last name is shown as itself.
        assert!(link(super::stat(&dir, "/bin/X11").unwrap()));
        let mut buf = Vec::new();
        super::read_link(&dir, "/usr/bin/X11", &mut buf).unwrap();
        assert_eq!(buf, b".");
        super::read_link(&dir, "/bin", &mut buf).unwrap();
        assert_eq!(buf, b"/usr/bin");
        assert!(super::read_link(&dir, "/usr", &mut buf).is_err(), "not a link");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // #648: /proc and /sys are the kernel's, not the container's files.
    #[test]
    fn the_kernels_filesystems_are_not_shown() {
        let root = std::path::Path::new("/");
        let names: Vec<String> = super::list(root, "/").unwrap().into_iter().map(|(n, _)| n).collect();
        assert!(names.iter().any(|n| n == "etc"), "{names:?}");
        assert!(!names.iter().any(|n| n == "proc" || n == "sys"), "{names:?}");
        for p in ["/proc", "/proc/self/status", "/sys", "/sys/kernel"] {
            assert_eq!(super::stat(root, p).map_err(|e| e.kind()).err(), Some(ErrorKind::NotFound), "{p}");
        }
        assert!(super::list(root, "/sys").is_err());
        let mut buf = Vec::new();
        assert!(super::read(root, "/proc/self/status", 0, 16, &mut buf).is_err());
        assert!(super::stat(root, "/etc").is_ok());
    }
}
