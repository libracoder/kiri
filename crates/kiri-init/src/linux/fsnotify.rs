//! Files changed on the host under bind mounts, raised as inotify events in
//! the guest or WSL 2 userland.
//!
//! On macOS, Apple's virtiofs server tells the guest nothing when a file
//! changes on the Mac, so the daemon watches bind sources with FSEvents and
//! sends `OP\tPATH` lines (`Msg::FsEvents`) to the guest kernel's
//! `/proc/kiri-fsnotify` (guest/kernel/patches/0006). Nothing is written to
//! the files, so nothing goes back to the Mac.
//!
//! On Windows (WSL 2), `C:\` is mounted over 9P (`drvfs` at `/mnt/c/...`) and
//! Microsoft's WSL 2 kernel neither forwards Windows file-change events over
//! 9P nor provides `/proc/kiri-fsnotify`. When `/proc/kiri-fsnotify` is
//! absent and a path is under WSL's automount root (`/mnt/<drive>/...`), the
//! agent raises real Linux VFS inotify events itself, never following a
//! symlink and never writing to a file:
//! - `M`, `C` and `A`: sets the mode the file or directory already has, which
//!   raises `IN_ATTRIB` on it and its watched parent (`raise_vfs_under`).
//! - `D`: the same on the parent directory, whose watchers read it again.
//! - `P` and `U` (from `kiri-win` as it starts and stops watching a root):
//!   hold and release `O_PATH` fds on the root's directories, without which
//!   no inotify watch on `drvfs` hears of anything (`Pins`).

use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::OnceLock;

/// Where the Mac's filesystem is mounted in the VM (mod.rs).
const MAC: &str = "/mnt/mac/";
const PROC: &str = "/proc/kiri-fsnotify";
/// Lines waiting to be raised; past this, new ones are dropped (a watcher
/// that missed a change in a storm hears of the next one).
const MAX_PENDING: usize = 8192;
/// Lines raised per turn of the agent's loop, so a storm of changes on the
/// host doesn't hold up its other messages.
const PER_TURN: usize = 64;
/// Most directories held open under watched WSL roots (see `Pins`).
const MAX_PINS: usize = 16384;
/// Directories opened per turn of the agent's loop while pinning a root.
const PINS_PER_TURN: usize = 64;
/// Skipped when pinning a root: dependency and git trees, which dev servers'
/// watchers ignore by default and which can hold most of a project's folders.
const SKIP_DIRS: [&str; 2] = ["node_modules", ".git"];

/// Changes waiting to be raised. Raised from the agent's own loop, a few at
/// a time, not a thread: the agent must stay single-threaded (it starts
/// containers with clone3, and a thread breaks setuid in the child).
#[derive(Default)]
pub struct Pending {
    lines: VecDeque<String>,
    pins: Pins,
}

impl Pending {
    /// Queues the lines that name a file under the Mac's mount or WSL's
    /// automount root, in order. Each is kept, repeats too: dropping one that
    /// is already queued would lose a delete in `D a, C a, M a, D a`. The
    /// sender merges each batch.
    pub fn add<'a>(&mut self, lines: impl Iterator<Item = &'a str>) {
        for line in valid(lines) {
            if self.lines.len() < MAX_PENDING {
                self.lines.push_back(line);
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty() && self.pins.walk.is_empty()
    }

    /// Raises up to PER_TURN lines. Uses `/proc/kiri-fsnotify` when present
    /// (macOS guest VM); otherwise raises Linux VFS inotify events for valid
    /// WSL automount paths (`/mnt/<drive>/...`) and pins up to PINS_PER_TURN
    /// directories of watched roots.
    pub fn raise_some(&mut self) {
        let count = PER_TURN.min(self.lines.len());
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(PROC) {
            // One write per line: the kernel answers each with its own result,
            // and a file gone again by now (ENOENT) must not drop the rest.
            for line in self.lines.drain(..count) {
                let _ = f.write_all(line.as_bytes());
            }
            return;
        }
        let root = wsl_automount_root();
        for line in self.lines.drain(..count) {
            raise_vfs_line(&line, root, &mut self.pins);
        }
        self.pins.walk_some(root);
    }
}

/// `[automount] root` from `/etc/wsl.conf`, defaulting to `/mnt/`.
fn automount_root(conf: &str) -> String {
    let mut section = String::new();
    let mut root = None;
    for line in conf.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = s.trim().to_ascii_lowercase();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        if section == "automount" && key.trim().eq_ignore_ascii_case("root") {
            let value = value.trim().trim_matches('"').trim();
            if value.starts_with('/') {
                root = Some(value.to_owned());
            }
        }
    }
    let mut root = root.unwrap_or_else(|| "/mnt/".to_owned());
    if !root.ends_with('/') {
        root.push('/');
    }
    root
}

fn wsl_automount_root() -> &'static str {
    static ROOT: OnceLock<String> = OnceLock::new();
    ROOT.get_or_init(|| automount_root(&std::fs::read_to_string("/etc/wsl.conf").unwrap_or_default()))
}

/// Splits a validated WSL automount path (`/mnt/c/Users/a/app.js`) into
/// `(drive_root, rel_path)` (`("/mnt/c", "Users/a/app.js")`).
/// Rejects paths outside `<automount_root><drive>/...`, empty relative paths,
/// control characters (`\n`, `\r`, `\0`), and `.` or `..` traversal components.
fn split_wsl_drive_path<'a>(path: &'a str, automount_root: &str) -> Option<(&'a str, &'a str)> {
    if !automount_root.starts_with('/') || !automount_root.ends_with('/') {
        return None;
    }
    if path.contains(['\n', '\r', '\0']) {
        return None;
    }
    let rest = path.strip_prefix(automount_root)?;
    let bytes = rest.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b'/' {
        return None;
    }
    let rel = &rest[2..];
    let mut has_component = false;
    for part in rel.split('/') {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." {
            return None;
        }
        has_component = true;
    }
    if !has_component {
        return None;
    }
    Some((&path[..automount_root.len() + 1], rel))
}

/// The lines the raiser accepts, each ending in a newline: `C`, `M`, `A` or
/// `D`, a tab, and a path under `/mnt/mac/` or WSL's automount root with no
/// `..`, no NUL and no newline; or `P` or `U` and a path under WSL's
/// automount root.
fn valid<'a>(lines: impl Iterator<Item = &'a str>) -> impl Iterator<Item = String> {
    valid_for(lines, wsl_automount_root())
}

fn valid_for<'a>(lines: impl Iterator<Item = &'a str>, automount_root: &'a str) -> impl Iterator<Item = String> {
    lines.filter_map(move |line| {
        let (op, path) = line.split_once('\t')?;
        let no_bad_chars = !path.contains(['\n', '\r', '\0']) && !path.split('/').any(|part| part == "..");
        let is_mac = path.starts_with(MAC) && path.len() > MAC.len();
        let is_wsl = split_wsl_drive_path(path, automount_root).is_some();
        let ok = no_bad_chars && match op {
            "C" | "M" | "A" | "D" => is_mac || is_wsl,
            "P" | "U" => is_wsl,
            _ => false,
        };
        ok.then(|| format!("{op}\t{path}\n"))
    })
}

/// Raises a single `OP\tPATH` line via Linux VFS syscalls, strictly restricted
/// to paths under `<automount_root><drive>/...`. `P` and `U` pin and unpin a
/// watched root's directories (see `Pins`).
fn raise_vfs_line(line: &str, automount_root: &str, pins: &mut Pins) -> bool {
    let line = line.trim_end_matches('\n');
    let Some((op, path)) = line.split_once('\t') else { return false };
    let Some((base, rel)) = split_wsl_drive_path(path, automount_root) else { return false };
    match op {
        "P" => pins.pin_tree(path),
        "U" => pins.unpin_tree(path),
        "D" => pins.unpin_tree(path),
        // A new directory is pinned before its parent hears of it, so a
        // watcher that adds a watch on it in answer gets the pinned inode.
        "C" if path.rsplit_once('/').is_some_and(|(parent, _)| pins.held.contains_key(parent)) => {
            if let Some(fd) = open_dir_nofollow(base, rel) {
                pins.hold(path, fd);
                pins.walk.push_back(path.to_owned());
            }
        }
        _ => {}
    }
    matches!(op, "P" | "U") || raise_vfs_under(base, rel, op)
}

/// Directories held open under watched WSL roots.
///
/// `drvfs` (9P without metadata caching, `cache=5`) drops a dentry as soon as
/// nothing holds it and makes a new inode on every lookup. An inotify watch
/// sits on the inode it was added to, so once that directory's dentry is
/// gone, no change made later (in WSL or raised here) ever reaches the watch.
/// Holding an `O_PATH` fd on each directory keeps its dentry, and so its
/// inode, for every later lookup. `O_PATH` opens nothing on the Windows side
/// and raises no inotify event.
#[derive(Default)]
struct Pins {
    held: HashMap<String, OwnedFd>,
    /// Directories still to open and list, a few per turn of the agent's loop.
    walk: VecDeque<String>,
}

impl Pins {
    fn pin_tree(&mut self, path: &str) {
        if !self.walk.iter().any(|p| p == path) {
            self.walk.push_back(path.to_owned());
        }
    }

    fn unpin_tree(&mut self, path: &str) {
        let under = |p: &str| p == path || p.strip_prefix(path).is_some_and(|rest| rest.starts_with('/'));
        self.held.retain(|p, _| !under(p));
        self.walk.retain(|p| !under(p));
    }

    fn hold(&mut self, path: &str, fd: OwnedFd) {
        if self.held.len() < MAX_PINS || self.held.contains_key(path) {
            self.held.insert(path.to_owned(), fd);
        }
    }

    /// Opens and lists up to PINS_PER_TURN queued directories, queueing their
    /// subdirectories. Never follows a symlink; skips `SKIP_DIRS`.
    fn walk_some(&mut self, automount_root: &str) {
        for _ in 0..PINS_PER_TURN {
            let Some(dir) = self.walk.pop_front() else { return };
            if self.held.len() >= MAX_PINS {
                self.walk.clear();
                return;
            }
            let Some((base, rel)) = split_wsl_drive_path(&dir, automount_root) else { continue };
            let Some(fd) = open_dir_nofollow(base, rel) else { continue };
            let list = std::fs::read_dir(format!("/proc/self/fd/{}", fd.as_raw_fd()));
            self.hold(&dir, fd);
            for entry in list.into_iter().flatten().flatten() {
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
                if SKIP_DIRS.contains(&name.as_str()) || name.contains(['\n', '\r']) || !entry.file_type().is_ok_and(|t| t.is_dir()) {
                    continue;
                }
                if self.held.len() + self.walk.len() >= MAX_PINS {
                    break;
                }
                self.walk.push_back(format!("{dir}/{name}"));
            }
        }
    }
}

/// Opens `base_dir`, then each directory of `rel_path` but the last, with
/// `O_PATH | O_DIRECTORY | O_NOFOLLOW`: a symlink anywhere on the way fails.
/// Returns the parent directory and the last component.
fn open_parent_nofollow(base_dir: &str, rel_path: &str) -> Option<(OwnedFd, CString)> {
    let comps: Vec<&str> = rel_path.split('/').filter(|s| !s.is_empty()).collect();
    if comps.is_empty() || comps.iter().any(|c| *c == "." || *c == ".." || c.contains('\0')) {
        return None;
    }
    let c_base = CString::new(base_dir).ok()?;
    // SAFETY: `c_base` is a valid NUL-terminated path; the returned fd is
    // immediately wrapped in `OwnedFd` when non-negative.
    let raw = unsafe { libc::open(c_base.as_ptr(), DIR_FLAGS) };
    if raw < 0 {
        return None;
    }
    // SAFETY: `raw` is a newly opened valid file descriptor.
    let mut parent = unsafe { OwnedFd::from_raw_fd(raw) };
    for comp in &comps[..comps.len() - 1] {
        parent = open_at(&parent, &CString::new(*comp).ok()?, DIR_FLAGS)?;
    }
    Some((parent, CString::new(comps[comps.len() - 1]).ok()?))
}

/// The directory at `rel_path` under `base_dir`, opened `O_PATH` without
/// following any symlink.
fn open_dir_nofollow(base_dir: &str, rel_path: &str) -> Option<OwnedFd> {
    let (parent, leaf) = open_parent_nofollow(base_dir, rel_path)?;
    open_at(&parent, &leaf, DIR_FLAGS)
}

const DIR_FLAGS: libc::c_int = libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

fn open_at(dir: &OwnedFd, name: &CStr, flags: libc::c_int) -> Option<OwnedFd> {
    // SAFETY: `dir` is a valid directory fd and `name` is NUL-terminated.
    let raw = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
    // SAFETY: `raw` is a newly opened valid file descriptor when non-negative.
    (raw >= 0).then(|| unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Raises a real Linux VFS inotify event for `op` on `rel_path` under
/// `base_dir` without following symlinks and without writing to the file.
///
/// The event is `IN_ATTRIB`, from setting the mode the file already has:
/// Node's `fs.watch` (libuv), Chokidar, Vite, webpack, nodemon, watchdog and
/// `notify` all listen for it. Nothing reaches Windows: `drvfs` changes no
/// timestamp or attribute and raises no `ReadDirectoryChangesW` event. Writing
/// a timestamp instead loses its sub-second part on `drvfs` and comes back
/// from Windows as a new change; changing the size to raise `IN_MODIFY` could
/// cut off a write Windows makes at the same moment.
fn raise_vfs_under(base_dir: &str, rel_path: &str, op: &str) -> bool {
    let Some((parent, leaf)) = open_parent_nofollow(base_dir, rel_path) else { return false };
    match op {
        "M" | "C" | "A" => {
            let Some(fd) = open_at(&parent, &leaf, libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) else { return false };
            // Never a symlink (`O_PATH | O_NOFOLLOW` opens the link itself),
            // FIFO, socket or device node.
            fstat(&fd).is_some_and(|st| matches!(st.st_mode & libc::S_IFMT, libc::S_IFREG | libc::S_IFDIR) && chmod_same(&fd, &st))
        }
        // The entry is gone: its parent directory raises the event, and a
        // watcher on it reads the directory again.
        "D" => fstat(&parent).is_some_and(|st| chmod_same(&parent, &st)),
        _ => false,
    }
}

fn fstat(fd: &OwnedFd) -> Option<libc::stat> {
    // SAFETY: zeroed `libc::stat` filled by `fstat` on a valid fd.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        (libc::fstat(fd.as_raw_fd(), &mut st) == 0).then_some(st)
    }
}

/// Sets the mode `fd` already has, through `/proc/self/fd` (an `O_PATH` fd
/// can't be `fchmod`ed): the inode is the one `fd` was opened on, never a
/// symlink swapped in since. Raises `IN_ATTRIB` on it and its watched parent.
fn chmod_same(fd: &OwnedFd, st: &libc::stat) -> bool {
    let Ok(path) = CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())) else { return false };
    // SAFETY: valid NUL-terminated path.
    unsafe { libc::chmod(path.as_ptr(), st.st_mode & 0o7777) == 0 }
}

#[cfg(test)]
mod tests {
    use super::{Pending, Pins, automount_root, raise_vfs_line, raise_vfs_under, split_wsl_drive_path, valid, valid_for};
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kiri-fsnotify-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn watch_dir(dir: &std::path::Path, mask: u32) -> OwnedFd {
        // SAFETY: standard Linux inotify syscalls on a valid NUL-terminated path.
        unsafe {
            let fd = libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC);
            assert!(fd >= 0, "inotify_init1 failed");
            let c = CString::new(dir.to_str().unwrap()).unwrap();
            let wd = libc::inotify_add_watch(fd, c.as_ptr(), mask);
            assert!(wd >= 0, "inotify_add_watch failed");
            OwnedFd::from_raw_fd(fd)
        }
    }

    fn read_inotify_masks(fd: &OwnedFd) -> Vec<u32> {
        let mut buf = [0u8; 4096];
        let mut masks = Vec::new();
        loop {
            // SAFETY: `fd` is a valid non-blocking inotify fd and `buf` is writable.
            let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            let n = n as usize;
            let mut off = 0;
            let hdr = std::mem::size_of::<libc::inotify_event>();
            while off + hdr <= n {
                // SAFETY: reading an unaligned `inotify_event` header within bounds.
                let ev: libc::inotify_event = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off).cast()) };
                masks.push(ev.mask);
                off += hdr + ev.len as usize;
            }
        }
        masks
    }

    #[test]
    fn only_paths_under_the_macs_mount() {
        let lines = ["M\t/mnt/mac/Users/a/app/main.js", "D\t/etc/passwd", "C\t/mnt/mac/../etc/x", "X\t/mnt/mac/Users/a", "M\t/mnt/mac/", "nonsense"];
        assert_eq!(valid(lines.into_iter()).collect::<Vec<_>>(), ["M\t/mnt/mac/Users/a/app/main.js\n"]);
    }

    #[test]
    fn a_repeat_is_kept_so_a_delete_is_not_lost() {
        let mut p = Pending::default();
        p.add(["D\t/mnt/mac/a", "C\t/mnt/mac/a", "M\t/mnt/mac/a"].into_iter());
        p.add(["D\t/mnt/mac/a"].into_iter());
        assert_eq!(p.lines.len(), 4);
        assert_eq!(p.lines.back().unwrap(), "D\t/mnt/mac/a\n");
    }

    #[test]
    fn wsl_drive_paths_are_validated_and_traversal_rejected() {
        assert_eq!(split_wsl_drive_path("/mnt/c/Users/me/app.js", "/mnt/"), Some(("/mnt/c", "Users/me/app.js")));
        assert_eq!(split_wsl_drive_path("/windows/d/proj/x", "/windows/"), Some(("/windows/d", "proj/x")));
        assert_eq!(split_wsl_drive_path("/mnt/mac/Users/a", "/mnt/"), None);
        assert_eq!(split_wsl_drive_path("/mnt/c/", "/mnt/"), None);
        assert_eq!(split_wsl_drive_path("/mnt/c", "/mnt/"), None);
        assert_eq!(split_wsl_drive_path("/mnt/c/../etc/shadow", "/mnt/"), None);
        assert_eq!(split_wsl_drive_path("/mnt/c/./app.js", "/mnt/"), None);
        assert_eq!(split_wsl_drive_path("/etc/passwd", "/mnt/"), None);
        assert_eq!(automount_root("[automount]\nroot = /win\n"), "/win/");
        assert_eq!(automount_root(""), "/mnt/");

        let lines = [
            "M\t/mnt/c/Users/me/app.js",
            "D\t/mnt/d/old.txt",
            "M\t/mnt/c/../etc/passwd",
            "M\t/etc/shadow",
            "M\t/mnt/c/",
        ];
        assert_eq!(
            valid_for(lines.into_iter(), "/mnt/").collect::<Vec<_>>(),
            ["M\t/mnt/c/Users/me/app.js\n", "D\t/mnt/d/old.txt\n"]
        );
        let mut pins = Pins::default();
        assert!(!raise_vfs_line("M\t/etc/passwd\n", "/mnt/", &mut pins));
        assert!(!raise_vfs_line("M\t/mnt/c/../etc/passwd\n", "/mnt/", &mut pins));
        assert!(!raise_vfs_line("P\t/etc\n", "/mnt/", &mut pins));
        assert!(pins.walk.is_empty());
    }

    /// Pins a known mtime with nanoseconds, so a raiser that rewrites it shows.
    fn pin_mtime(path: &std::path::Path, sec: i64, nsec: i64) {
        let c = CString::new(path.to_str().unwrap()).unwrap();
        let times = [libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT }, libc::timespec { tv_sec: sec, tv_nsec: nsec }];
        // SAFETY: valid path and timespec array.
        assert_eq!(unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) }, 0);
    }

    /// Holds `dir` open as `Pins` does: on `drvfs` a watch added to a directory
    /// nothing holds hears of nothing (run with TMPDIR on `/mnt/c` to see).
    fn pin(dir: &std::path::Path) -> OwnedFd {
        let c = CString::new(dir.to_str().unwrap()).unwrap();
        // SAFETY: valid path; the fd is wrapped at once.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        assert!(fd >= 0);
        // SAFETY: just opened.
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    fn mtime_and_mode(path: &std::path::Path) -> (i64, i64, u32) {
        let m = std::fs::symlink_metadata(path).unwrap();
        (m.mtime(), m.mtime_nsec(), m.mode())
    }

    #[test]
    fn vfs_fallback_raises_in_attrib_keeping_bytes_mtime_and_mode() {
        let base = temp_dir("attrib");
        let sub = base.join("app");
        std::fs::create_dir_all(&sub).unwrap();
        let file = sub.join("main.js");
        std::fs::write(&file, b"console.log('hi');\n").unwrap();
        pin_mtime(&file, 1_700_000_123, 456_789_123);
        let before = mtime_and_mode(&file);

        let _pin = pin(&sub);
        let inotify = watch_dir(&sub, libc::IN_ALL_EVENTS);
        for op in ["M", "C", "A"] {
            assert!(raise_vfs_under(base.to_str().unwrap(), "app/main.js", op));
            let masks = read_inotify_masks(&inotify);
            assert!(masks.iter().any(|m| m & libc::IN_ATTRIB != 0), "{op}: expected IN_ATTRIB, got {masks:?}");
            // O_PATH opens raise no IN_OPEN, and nothing is written.
            assert!(masks.iter().all(|m| m & (libc::IN_OPEN | libc::IN_MODIFY | libc::IN_CLOSE_WRITE) == 0), "{op}: got {masks:?}");
        }
        assert_eq!(std::fs::read(&file).unwrap(), b"console.log('hi');\n");
        assert_eq!(mtime_and_mode(&file), before);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn vfs_fallback_refuses_symlinks_leaf_and_intermediate() {
        let base = temp_dir("symlink");
        let outside = temp_dir("symlink-outside");
        let secret = outside.join("shadow");
        std::fs::write(&secret, b"top-secret").unwrap();
        std::fs::set_permissions(&secret, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        // drvfs keeps no Unix mode bits: compare with what it reports.
        let mode = std::fs::symlink_metadata(&secret).unwrap().mode();

        std::os::unix::fs::symlink(&secret, base.join("evil")).unwrap();
        std::os::unix::fs::symlink(&outside, base.join("sub")).unwrap();

        let _pin = pin(&outside);
        let inotify = watch_dir(&outside, libc::IN_ALL_EVENTS);
        for op in ["M", "C", "A", "D"] {
            assert!(!raise_vfs_under(base.to_str().unwrap(), "evil", op) || op == "D", "leaf symlink must be refused for {op}");
            assert!(!raise_vfs_under(base.to_str().unwrap(), "sub/shadow", op), "intermediate symlink must be refused for {op}");
        }
        assert!(read_inotify_masks(&inotify).is_empty(), "target outside root must receive zero events");
        assert_eq!(std::fs::symlink_metadata(&secret).unwrap().mode(), mode);
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn vfs_fallback_delete_raises_in_attrib_on_parent_keeping_mtime() {
        let base = temp_dir("delete");
        let sub = base.join("proj");
        std::fs::create_dir_all(&sub).unwrap();
        pin_mtime(&sub, 1_720_000_000, 222_333_444);
        let before = mtime_and_mode(&sub);

        let _pin = pin(&sub);
        let inotify = watch_dir(&sub, libc::IN_ALL_EVENTS);
        assert!(raise_vfs_under(base.to_str().unwrap(), "proj/gone.js", "D"));
        let masks = read_inotify_masks(&inotify);
        assert!(masks.iter().any(|m| m & libc::IN_ATTRIB != 0), "expected IN_ATTRIB on parent dir, got {masks:?}");
        assert_eq!(mtime_and_mode(&sub), before);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn pins_hold_a_roots_directories_but_not_symlinks_or_skipped_trees() {
        // An automount root of our own: `<base>/` with drive `c`.
        let base = temp_dir("pins");
        let root = format!("{}/", base.to_str().unwrap());
        let proj = base.join("c/proj");
        for d in ["src/a", "src/b", "node_modules/x", ".git/objects"] {
            std::fs::create_dir_all(proj.join(d)).unwrap();
        }
        std::fs::write(proj.join("src/file.js"), b"x").unwrap();
        let outside = temp_dir("pins-outside");
        std::os::unix::fs::symlink(&outside, proj.join("link")).unwrap();
        let p = |rel: &str| format!("{root}c/proj{rel}");

        let mut pins = Pins::default();
        assert!(raise_vfs_line(&format!("P\t{}\n", p("")), &root, &mut pins));
        while !pins.walk.is_empty() {
            pins.walk_some(&root);
        }
        let mut held: Vec<&str> = pins.held.keys().map(String::as_str).collect();
        held.sort();
        assert_eq!(held, [p(""), p("/src"), p("/src/a"), p("/src/b")]);

        // A watch added once the tree is pinned hears a change raised later.
        let inotify = watch_dir(&proj.join("src"), libc::IN_ALL_EVENTS);
        assert!(raise_vfs_line(&format!("M\t{}\n", p("/src/file.js")), &root, &mut pins));
        assert!(read_inotify_masks(&inotify).iter().any(|m| m & libc::IN_ATTRIB != 0));

        // A new directory under a pinned one is pinned as it is raised.
        std::fs::create_dir(proj.join("src/new")).unwrap();
        assert!(raise_vfs_line(&format!("C\t{}\n", p("/src/new")), &root, &mut pins));
        assert!(pins.held.contains_key(&p("/src/new")));

        // A deleted directory lets go of its subtree; U lets go of the root.
        std::fs::remove_dir_all(proj.join("src")).unwrap();
        raise_vfs_line(&format!("D\t{}\n", p("/src")), &root, &mut pins);
        assert_eq!(pins.held.keys().collect::<Vec<_>>(), [&p("")]);
        assert!(raise_vfs_line(&format!("U\t{}\n", p("")), &root, &mut pins));
        assert!(pins.held.is_empty());

        let lines = [format!("P\t{}", p("")), "P\t/mnt/mac/Users/a".to_owned(), format!("U\t{}", p(""))];
        assert_eq!(valid_for(lines.iter().map(String::as_str), &root).count(), 2);
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&outside);
    }
}
