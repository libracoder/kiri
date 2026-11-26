//! Thin wrappers over the syscalls the guest uses. Everything unsafe lives
//! here or right next to the one call that needs it.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub fn boottime_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid, writable timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

pub fn check(ret: libc::c_long, what: &str) -> io::Result<libc::c_long> {
    if ret < 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("{what}: {e}")));
    }
    Ok(ret)
}

pub fn cstr(p: impl AsRef<Path>) -> io::Result<CString> {
    CString::new(p.as_ref().as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

pub fn mount(src: &CStr, target: &CStr, fstype: &CStr, flags: libc::c_ulong, data: Option<&CStr>) -> io::Result<()> {
    // SAFETY: every pointer is a valid NUL-terminated string or null.
    let ret = unsafe {
        libc::mount(src.as_ptr(), target.as_ptr(), fstype.as_ptr(), flags, data.map_or(std::ptr::null(), |d| d.as_ptr().cast()))
    };
    check(ret as _, &format!("mount {}", target.to_string_lossy())).map(drop)
}

/// Most of a page: the kernel copies mount options into one page and cuts
/// the rest, so an overlay of many layers would lose its lowest ones.
const MAX_OPTIONS: usize = 4000;

/// An overlay of `lowers` (top first, each a folder path, relative to the
/// working directory or absolute, with no `:` or `,`) at `target`, `rest`
/// the options after the lower list (absolute paths). When the options do
/// not fit in a page (some 60 layers by digest), the lowers are named by
/// short links in a folder beside `target` and the mount is made from a
/// child working in that folder: the same overlay, the agent's own working
/// directory untouched (BuildKit's snapshotter does the same with short
/// snapshot ids). The links go once the overlay holds its folders.
pub fn mount_overlay(target: &Path, lowers: &[String], rest: &str, flags: libc::c_ulong) -> io::Result<()> {
    let opts = format!("lowerdir={}{rest}", lowers.join(":"));
    if opts.len() <= MAX_OPTIONS {
        return mount(c"overlay", &cstr(target)?, c"overlay", flags, Some(&CString::new(opts)?));
    }
    let mut links = target.as_os_str().to_owned();
    links.push(".lowers");
    let links = std::path::PathBuf::from(links);
    let _ = std::fs::remove_dir_all(&links);
    std::fs::create_dir_all(&links)?;
    let here = std::env::current_dir()?;
    for (i, l) in lowers.iter().enumerate() {
        std::os::unix::fs::symlink(here.join(l), links.join(i.to_string()))?;
    }
    let short: Vec<String> = (0..lowers.len()).map(|i| i.to_string()).collect();
    let opts = CString::new(format!("lowerdir={}{rest}", short.join(":")))?;
    let dir = cstr(&links)?;
    let target_c = cstr(target)?;
    let result = (|| {
        if opts.as_bytes().len() > MAX_OPTIONS {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{} layers are more than one overlay can stack", lowers.len())));
        }
        // SAFETY: the child only calls chdir, mount and _exit, all
        // async-signal-safe, on strings made before the fork.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // SAFETY: as above, in the child.
            unsafe {
                if libc::chdir(dir.as_ptr()) != 0 {
                    libc::_exit(*libc::__errno_location());
                }
                let r = libc::mount(c"overlay".as_ptr(), target_c.as_ptr(), c"overlay".as_ptr(), flags, opts.as_ptr().cast());
                libc::_exit(if r == 0 { 0 } else { *libc::__errno_location() });
            }
        }
        check(pid as _, "fork")?;
        let mut status = 0;
        // SAFETY: waits for the child just made, into a local int.
        check(unsafe { libc::waitpid(pid, &mut status, 0) } as _, "waitpid")?;
        match (libc::WIFEXITED(status), libc::WEXITSTATUS(status)) {
            (true, 0) => Ok(()),
            (true, e) => {
                let err = io::Error::from_raw_os_error(e);
                Err(io::Error::new(err.kind(), format!("mount {}: {err}", target.display())))
            }
            _ => Err(io::Error::other(format!("mount {}: the mounting child died", target.display()))),
        }
    })();
    let _ = std::fs::remove_dir_all(&links);
    result
}

/// Mounts with no source or type, for changing propagation (`MS_PRIVATE` …).
pub fn remount(target: &CStr, flags: libc::c_ulong) -> io::Result<()> {
    // SAFETY: `target` is a valid NUL-terminated string; the rest may be null.
    let ret = unsafe { libc::mount(std::ptr::null(), target.as_ptr(), std::ptr::null(), flags, std::ptr::null()) };
    check(ret as _, &format!("remount {}", target.to_string_lossy())).map(drop)
}

pub fn umount(target: &Path) -> io::Result<()> {
    let t = cstr(target)?;
    // SAFETY: `t` is a valid NUL-terminated string.
    check(unsafe { libc::umount2(t.as_ptr(), 0) } as _, "umount").map(drop)
}

pub fn umount_lazy(target: &Path) -> io::Result<()> {
    let t = cstr(target)?;
    // SAFETY: `t` is a valid NUL-terminated string.
    check(unsafe { libc::umount2(t.as_ptr(), libc::MNT_DETACH) } as _, "umount").map(drop)
}

/// Linux's `CGROUP_SUPER_MAGIC` (`<linux/magic.h>`).
const CGROUP_SUPER_MAGIC: i64 = 0x27_e0eb;
/// Linux's `CGROUP2_SUPER_MAGIC` (`<linux/magic.h>`).
const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;

/// OpenZFS's `ZFS_SUPER_MAGIC` (`zpl_super.c`).
pub const ZFS_SUPER_MAGIC: i64 = 0x2fc1_2fc1;

fn fs_magic(path: &Path) -> Option<i64> {
    let c = cstr(path).ok()?;
    // SAFETY: `st` is plain zero-initialized data; `c` is a valid C string.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: statfs writes into `st`.
    (unsafe { libc::statfs(c.as_ptr(), &mut st) } == 0).then_some(st.f_type as i64)
}

/// Whether `path` sits on a mounted `cgroup2` filesystem.
pub fn is_cgroup2(path: &Path) -> bool {
    fs_magic(path) == Some(CGROUP2_SUPER_MAGIC)
}

/// Whether `path` sits on a mounted cgroup v1 or v2 filesystem.
pub fn is_cgroup(path: &Path) -> bool {
    matches!(fs_magic(path), Some(CGROUP_SUPER_MAGIC | CGROUP2_SUPER_MAGIC))
}

/// Linux `<linux/mount.h>` `mount_attr` for `mount_setattr(2)` (Linux 5.12+).
#[repr(C)]
#[derive(Default)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

pub const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
pub const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
pub const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;
pub const MOUNT_ATTR_NOEXEC: u64 = 0x0000_0008;

/// Recursively sets `attr_set` mount attributes on `target` and every mount
/// beneath it via `mount_setattr(2)`.
pub fn mount_setattr_recursive(target: &CStr, attr_set: u64) -> io::Result<()> {
    let attr = MountAttr { attr_set, ..Default::default() };
    // SAFETY: `target` is a valid NUL-terminated path and `attr` is a valid
    // `mount_attr` struct of the passed size.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::AT_RECURSIVE as libc::c_uint,
            &attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    check(ret as _, &format!("mount_setattr {}", target.to_string_lossy())).map(drop)
}

/// Whether `statfs(2)` reports `ZFS_SUPER_MAGIC` on `path`.
pub fn is_statfs_zfs(path: &Path) -> bool {
    let Ok(c) = cstr(path) else { return false };
    // SAFETY: `st` is plain zero-initialized data; `c` is a valid C string.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: statfs writes into `st`.
    unsafe { libc::statfs(c.as_ptr(), &mut st) == 0 && st.f_type as i64 == ZFS_SUPER_MAGIC }
}

/// Why a container storage filesystem is read-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOnlyKind {
    /// Linux ext4 aborted its journal (`errors=remount-ro`) and added `emergency_ro`.
    EmergencyRo,
    /// Mounted read-only (`ro` / `ST_RDONLY`), or overlayfs fell back to read-only.
    ReadOnly,
}

impl ReadOnlyKind {
    pub fn merge(self, other: Self) -> Self {
        if self == Self::EmergencyRo || other == Self::EmergencyRo {
            Self::EmergencyRo
        } else {
            Self::ReadOnly
        }
    }
}

/// Unescapes `/proc/mounts` and `/proc/self/mountinfo` octal escapes (`\040`, `\011`, `\012`, `\134`).
pub fn unescape_mount_path(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4].iter().all(|b| (b'0'..=b'7').contains(b))
        {
            let val = ((bytes[i + 1] - b'0') << 6) | ((bytes[i + 2] - b'0') << 3) | (bytes[i + 3] - b'0');
            out.push(val);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn norm_mount_path(p: &str) -> &str {
    let trimmed = p.trim_end_matches('/');
    if trimmed.is_empty() { "/" } else { trimmed }
}

fn mount_covers(mp: &str, target: &str) -> bool {
    let mp = norm_mount_path(mp);
    let target = norm_mount_path(target);
    mp == "/" || target == mp || (target.starts_with(mp) && target.as_bytes().get(mp.len()) == Some(&b'/'))
}

/// Parses comma-separated mount options (`rw,...,emergency_ro` or `ro,...`)
/// into `ReadOnlyKind`, ignoring substrings such as `errors=remount-ro`.
pub fn parse_opts_readonly(opts: &str) -> Option<ReadOnlyKind> {
    let mut ro = false;
    for opt in opts.split(',') {
        match opt.trim() {
            "emergency_ro" => return Some(ReadOnlyKind::EmergencyRo),
            "ro" => ro = true,
            _ => {}
        }
    }
    ro.then_some(ReadOnlyKind::ReadOnly)
}

/// Inspects `/proc/mounts` text for the active mount covering `target`.
/// Picks the longest ancestor mountpoint, with later lines winning ties (overmounts).
pub fn proc_mounts_readonly(proc_mounts: &str, target: &Path) -> Option<ReadOnlyKind> {
    let target_str = target.to_string_lossy();
    let mut best: Option<(usize, Option<ReadOnlyKind>)> = None;
    for line in proc_mounts.lines() {
        let mut fields = line.split_whitespace();
        let (Some(_spec), Some(mp_raw), Some(_fstype), Some(opts)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let mp = unescape_mount_path(mp_raw);
        let mp_norm = norm_mount_path(&mp);
        if mount_covers(mp_norm, &target_str) && best.is_none_or(|(len, _)| mp_norm.len() >= len) {
            best = Some((mp_norm.len(), parse_opts_readonly(opts)));
        }
    }
    best.and_then(|(_, kind)| kind)
}

/// Inspects `/proc/self/mountinfo` text for the active mount covering `target`.
pub fn mountinfo_readonly(mountinfo: &str, target: &Path) -> Option<ReadOnlyKind> {
    let target_str = target.to_string_lossy();
    let mut best: Option<(usize, Option<ReadOnlyKind>)> = None;
    for line in mountinfo.lines() {
        let Some((before, after)) = line.split_once(" - ") else { continue };
        let mut b = before.split_whitespace();
        let (Some(_id), Some(_parent), Some(_dev), Some(_root), Some(mp_raw), Some(mopts)) =
            (b.next(), b.next(), b.next(), b.next(), b.next(), b.next())
        else {
            continue;
        };
        let mut a = after.split_whitespace();
        let (Some(_fstype), Some(_src), Some(sopts)) = (a.next(), a.next(), a.next()) else { continue };
        let mp = unescape_mount_path(mp_raw);
        let mp_norm = norm_mount_path(&mp);
        if mount_covers(mp_norm, &target_str) && best.is_none_or(|(len, _)| mp_norm.len() >= len) {
            let kind = match (parse_opts_readonly(mopts), parse_opts_readonly(sopts)) {
                (Some(a), Some(b)) => Some(a.merge(b)),
                (Some(a), None) | (None, Some(a)) => Some(a),
                (None, None) => None,
            };
            best = Some((mp_norm.len(), kind));
        }
    }
    best.and_then(|(_, kind)| kind)
}

/// Inspects `/proc/self/mountinfo` text for the filesystem type of the active
/// mount covering `target` (longest ancestor mountpoint, with later lines
/// winning ties for overmounts).
pub fn mountinfo_fstype<'a>(mountinfo: &'a str, target: &Path) -> Option<&'a str> {
    let target_str = target.to_string_lossy();
    let mut best: Option<(usize, &'a str)> = None;
    for line in mountinfo.lines() {
        let Some((before, after)) = line.split_once(" - ") else { continue };
        let Some(mp_raw) = before.split_whitespace().nth(4) else { continue };
        let Some(fstype) = after.split_whitespace().next() else { continue };
        let mp = unescape_mount_path(mp_raw);
        let mp_norm = norm_mount_path(&mp);
        if mount_covers(mp_norm, &target_str) && best.is_none_or(|(len, _)| mp_norm.len() >= len) {
            best = Some((mp_norm.len(), fstype));
        }
    }
    best.map(|(_, fstype)| fstype)
}

/// Whether `/proc/self/mountinfo` reports fstype `"zfs"` for the active mount covering `target`.
pub fn is_zfs_mountinfo(mountinfo: &str, target: &Path) -> bool {
    mountinfo_fstype(mountinfo, target) == Some("zfs")
}

/// Whether `path` (or its nearest existing ancestor) sits on a ZFS filesystem,
/// checked via `statfs(ZFS_SUPER_MAGIC)` with `/proc/self/mountinfo` fallback.
pub fn is_zfs(path: &Path) -> bool {
    let Some(existing) = path.ancestors().find(|p| !p.as_os_str().is_empty() && p.exists()) else {
        return false;
    };
    if is_statfs_zfs(existing) {
        return true;
    }
    let Ok(mi) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    let canon = existing.canonicalize().ok();
    is_zfs_mountinfo(&mi, canon.as_deref().unwrap_or(existing))
}

/// Whether `statvfs(2)` reports `ST_RDONLY` on `path`.
pub fn is_statvfs_readonly(path: &Path) -> io::Result<bool> {
    let c = cstr(path)?;
    // SAFETY: `st` is plain zero-initialized data; `c` is a valid C string.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: statvfs writes into `st`.
    check(unsafe { libc::statvfs(c.as_ptr(), &mut st) } as _, &format!("statvfs {}", path.display()))?;
    Ok((st.f_flag as u64) & (libc::ST_RDONLY as u64) != 0)
}

/// Classifies an already-known read-only path (`EmergencyRo` vs `ReadOnly`)
/// by reading `/proc/self/mountinfo` and `/proc/mounts`.
pub fn inspect_readonly_kind(existing: &Path) -> ReadOnlyKind {
    let canon = existing.canonicalize().ok();
    let targets = [canon.as_deref(), Some(existing)];
    if let Ok(mi) = std::fs::read_to_string("/proc/self/mountinfo") {
        for t in targets.into_iter().flatten() {
            if mountinfo_readonly(&mi, t) == Some(ReadOnlyKind::EmergencyRo) {
                return ReadOnlyKind::EmergencyRo;
            }
        }
    }
    if let Ok(pm) = std::fs::read_to_string("/proc/mounts") {
        for t in targets.into_iter().flatten() {
            if proc_mounts_readonly(&pm, t) == Some(ReadOnlyKind::EmergencyRo) {
                return ReadOnlyKind::EmergencyRo;
            }
        }
    }
    ReadOnlyKind::ReadOnly
}

/// Fast-path read-only filesystem check on `path` (or its nearest existing
/// ancestor): 1 `statvfs` syscall when writable; inspects `/proc/self/mountinfo`
/// and `/proc/mounts` for `emergency_ro` only when `ST_RDONLY` is set.
pub fn detect_readonly_fs(path: &Path) -> Option<ReadOnlyKind> {
    let existing = path.ancestors().find(|p| !p.as_os_str().is_empty() && p.exists())?;
    if is_statvfs_readonly(existing).ok()? {
        Some(inspect_readonly_kind(existing))
    } else {
        None
    }
}

/// Pure helper testing whether `osrelease` or WSL interop markers indicate WSL.
pub fn is_wsl_env(osrelease: &str, interop_exists: bool) -> bool {
    if interop_exists {
        return true;
    }
    let lower = osrelease.to_ascii_lowercase();
    lower.contains("microsoft") || lower.contains("wsl")
}

/// True when running inside WSL 2 (Microsoft or custom WSL kernel / WSLInterop).
pub fn is_wsl() -> bool {
    static WSL: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *WSL.get_or_init(|| {
        let interop = Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists()
            || Path::new("/proc/sys/fs/binfmt_misc/WSLInterop-late").exists()
            || Path::new("/run/WSL").is_dir();
        let osrelease = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        is_wsl_env(&osrelease, interop)
    })
}

/// Formats an actionable error message for a read-only container storage filesystem.
pub fn format_readonly_storage_error(kind: ReadOnlyKind, wsl: bool, host_process: bool) -> String {
    if wsl {
        let state = match kind {
            ReadOnlyKind::EmergencyRo => "was remounted read-only by Linux (emergency_ro)",
            ReadOnlyKind::ReadOnly => "is mounted read-only (emergency_ro)",
        };
        format!(
            "Kiri's WSL2 disk (ext4.vhdx) {state} after an unclean shutdown or filesystem error. \
             To recover: 1) run `wsl --shutdown` in PowerShell; \
             2) attach the disk bare with `wsl --mount <path>\\ext4.vhdx --vhd --bare` (default `%LOCALAPPDATA%\\Kiri\\wsl\\kiri\\ext4.vhdx`); \
             3) from another Linux distro in WSL, find the device with `lsblk` and run `sudo e2fsck -f -y -D /dev/<disk>`, then `wsl --unmount`; \
             or move/recreate storage in Settings -> Storage."
        )
    } else if host_process {
        match kind {
            ReadOnlyKind::EmergencyRo => {
                "Kiri's container storage filesystem (/var/lib/kiri) was remounted read-only by Linux (emergency_ro) after a filesystem error: check `dmesg` and run `fsck` to repair the filesystem, then restart Kiri.".to_owned()
            }
            ReadOnlyKind::ReadOnly => {
                "Kiri's container storage filesystem (/var/lib/kiri) is mounted read-only: check `dmesg` and mount options, or run `fsck` to repair the filesystem, then restart Kiri.".to_owned()
            }
        }
    } else {
        match kind {
            ReadOnlyKind::EmergencyRo => {
                "Kiri's container storage filesystem (/var/lib/kiri) was remounted read-only by Linux (emergency_ro) after a filesystem error: check `dmesg`, restart Kiri, or run `fsck` on the VM data disk.".to_owned()
            }
            ReadOnlyKind::ReadOnly => {
                "Kiri's container storage filesystem (/var/lib/kiri) is mounted read-only: check `dmesg`, restart Kiri, or run `fsck` on the VM data disk.".to_owned()
            }
        }
    }
}

pub fn readonly_storage_error(kind: ReadOnlyKind) -> io::Error {
    let msg = format_readonly_storage_error(kind, is_wsl(), super::transport::is_host_process());
    io::Error::new(io::Error::from_raw_os_error(libc::EROFS).kind(), msg)
}

pub fn mkdir(p: &CStr, mode: libc::mode_t) {
    // SAFETY: `p` is a valid NUL-terminated string. EEXIST is expected and fine.
    unsafe { libc::mkdir(p.as_ptr(), mode) };
}

pub fn mknod(p: &CStr, mode: libc::mode_t, major: u32, minor: u32) -> io::Result<()> {
    // SAFETY: `p` is a valid NUL-terminated string.
    let ret = unsafe { libc::mknod(p.as_ptr(), mode, libc::makedev(major, minor)) };
    check(ret as _, &format!("mknod {}", p.to_string_lossy())).map(drop)
}

pub fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: `fds` has room for the two descriptors pipe2 writes.
    check(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } as _, "pipe2")?;
    // SAFETY: pipe2 succeeded, so both descriptors are fresh and ours.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

pub fn write_file(p: &str, contents: &str) -> io::Result<()> {
    std::fs::write(p, contents).map_err(|e| io::Error::new(e.kind(), format!("write {p}: {e}")))
}

/// Brings the loopback interface up in the current network namespace.
pub fn loopback_up() -> io::Result<()> {
    // SAFETY: plain socket creation; the fd is owned immediately.
    let fd = check(unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) } as _, "socket")?;
    // SAFETY: `fd` is a fresh, valid descriptor that nothing else owns.
    let sock = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
    // SAFETY: ifreq is plain data; all-zero is a valid value.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, src) in req.ifr_name.iter_mut().zip(b"lo\0") {
        *dst = *src as libc::c_char;
    }
    req.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    use std::os::fd::AsRawFd;
    // SAFETY: `req` is a valid ifreq for SIOCSIFFLAGS.
    check(unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS as libc::Ioctl, &req) } as _, "lo up").map(drop)
}

pub fn sethostname(name: &[u8]) -> io::Result<()> {
    // SAFETY: `name` is valid for `name.len()` bytes.
    check(unsafe { libc::sethostname(name.as_ptr().cast(), name.len()) } as _, "sethostname").map(drop)
}

pub fn setdomainname(name: &[u8]) -> io::Result<()> {
    // SAFETY: `name` is valid for `name.len()` bytes.
    check(unsafe { libc::setdomainname(name.as_ptr().cast(), name.len()) } as _, "setdomainname").map(drop)
}

/// Arguments for clone3(2). libc has no definition for it on musl yet.
#[repr(C)]
#[derive(Default)]
pub struct CloneArgs {
    pub flags: u64,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,
    pub set_tid_size: u64,
    pub cgroup: u64,
}

pub const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

/// A started child: its pid, and whether clone3 placed it in its cgroup.
pub struct Cloned {
    pub pid: libc::pid_t,
    /// False when the child was started with clone(2): the caller must move
    /// it into `CloneArgs::cgroup` itself before letting it run.
    pub into_cgroup: bool,
}

/// Whether clone3 is unavailable rather than refusing this request: an old
/// kernel answers ENOSYS, and a seccomp filter (Docker's and Android's) may
/// answer ENOSYS or EPERM. glibc and runc fall back to clone(2) for these.
fn clone3_unavailable(errno: Option<i32>) -> bool {
    matches!(errno, Some(code) if code == libc::ENOSYS || code == libc::EPERM)
}

/// The clone(2) flags for `args`: clone3-only flags above 32 bits
/// (CLONE_INTO_CGROUP, CLONE_CLEAR_SIGHAND) and fields clone(2) has no place
/// for (the cgroup, a pidfd, set_tid, tls) are dropped, and clone3's separate
/// exit signal goes back into the low byte of the flags. CLONE_NEWCGROUP
/// goes too: clone3 places the child in its cgroup before making it, so the
/// namespace is rooted there; clone(2) cannot, and a namespace made now
/// would be rooted at the agent's cgroup. The caller unshares it after
/// moving the child.
fn clone_flags(args: &CloneArgs) -> libc::c_ulong {
    ((args.flags & 0xffff_ffff & !(libc::CLONE_NEWCGROUP as u64)) | (args.exit_signal & 0xff)) as libc::c_ulong
}

/// Like fork(), but straight into new namespaces and a cgroup. Returns 0 in
/// the child and the child's pid in the parent.
///
/// Uses clone3(2), which puts the child in its cgroup atomically. Where
/// clone3 is blocked (an old kernel, or a seccomp filter answering ENOSYS or
/// EPERM, as on Android/Droidspaces, #529), it falls back to clone(2), as
/// glibc and runc do, and reports `into_cgroup: false`. clone(2) cannot make
/// the cgroup namespace either, so the caller must move the child into its
/// cgroup and unshare CLONE_NEWCGROUP before it proceeds.
///
/// # Safety
/// The caller must be single-threaded, as with fork(): the child gets a copy
/// of this thread only, so no other thread may hold a lock it needs.
static CLONE3_STATE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// True once `clone3(..., CLONE_INTO_CGROUP)` has succeeded in this process,
/// allowing later spawns/execs to skip creating the fallback `cgroup_ready` pipe.
pub fn clone3_works() -> bool {
    CLONE3_STATE.load(std::sync::atomic::Ordering::Relaxed) == 1
}

pub unsafe fn clone3(args: &CloneArgs) -> io::Result<Cloned> {
    // SAFETY: `args` is a valid clone_args of the size passed; the caller
    // upholds the single-thread requirement.
    let ret = unsafe { libc::syscall(libc::SYS_clone3, args as *const CloneArgs, std::mem::size_of::<CloneArgs>()) };
    if ret >= 0 {
        if ret > 0 {
            CLONE3_STATE.store(1, std::sync::atomic::Ordering::Relaxed);
        }
        return Ok(Cloned { pid: ret as libc::pid_t, into_cgroup: true });
    }
    let e = io::Error::last_os_error();
    if !clone3_unavailable(e.raw_os_error()) {
        return Err(io::Error::new(e.kind(), format!("clone3: {e}")));
    }
    CLONE3_STATE.store(2, std::sync::atomic::Ordering::Relaxed);
    // SAFETY: as above. clone(2) has no cgroup, pidfd, set_tid, stack or tls
    // arguments here: the child runs on a copy of this thread's stack, like
    // fork(). Passing 0 for the four arguments after `flags` is identical on
    // x86_64 and aarch64 (CONFIG_CLONE_BACKWARDS). The caller upholds
    // single-threadedness, which that requires.
    let ret = unsafe {
        libc::syscall(libc::SYS_clone, clone_flags(args), 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong)
    };
    if ret < 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("clone: {e}")));
    }
    Ok(Cloned { pid: ret as libc::pid_t, into_cgroup: false })
}

/// Makes this thread's namespace view like `unshare(2)`: a new cgroup
/// namespace here is rooted at the caller's cgroup.
pub fn unshare(flags: libc::c_int) -> io::Result<()> {
    // SAFETY: plain syscall on the calling thread.
    check(unsafe { libc::unshare(flags) } as _, "unshare").map(drop)
}

/// The engine's own message as one line of the container's log: a value
/// over several lines (a key a `user:` named) never goes on, unhidden, over
/// the lines after it.
/// Each line break is one space; every other character stays as it is, so
/// what Kiri hides in Logs finds the value as it is.
pub fn one_line(s: &str) -> String {
    s.replace("\r\n", " ").replace(['\n', '\r'], " ")
}

/// Closes every descriptor from `first` up. For the child between clone and
/// exec, which holds a copy of all of the agent's descriptors: close-on-exec
/// closes them only at execve, and until then one is still a way out of the
/// container (a working directory of `/proc/self/fd/N`).
pub fn close_from(first: RawFd) {
    // SAFETY: closing descriptors in this process; nothing is used after.
    unsafe {
        if libc::syscall(libc::SYS_close_range, first as libc::c_uint, libc::c_uint::MAX, 0) == 0 {
            return;
        }
        // close_range is Linux 5.9+; older kernels close one at a time.
        let max = match libc::sysconf(libc::_SC_OPEN_MAX) {
            n if n > 0 => n.min(1 << 20) as RawFd,
            _ => 1 << 16,
        };
        for fd in first..max {
            libc::close(fd);
        }
    }
}

/// Whether the current directory is inside this process's root. The kernel
/// gives a directory outside it as `(unreachable)/…`, which is how a
/// working directory reached through a leaked descriptor shows.
pub fn cwd_inside_root() -> bool {
    let mut buf = [0u8; 4096];
    // SAFETY: getcwd writes at most `buf.len()` bytes into `buf`.
    let n = unsafe { libc::syscall(libc::SYS_getcwd, buf.as_mut_ptr(), buf.len()) };
    n > 0 && buf[0] == b'/'
}

/// Writes `msg` straight to `fd` and exits without unwinding or running any
/// destructors. Only for the child between clone and exec.
pub fn child_fail(fd: RawFd, what: &str, err: io::Error) -> ! {
    let msg = format!("kiri: cannot start container: {}\n", one_line(&format!("{what}: {err}")));
    // SAFETY: writing a valid buffer to a descriptor we hold, then exiting.
    unsafe {
        libc::write(fd, msg.as_ptr().cast(), msg.len());
        libc::_exit(127)
    }
}

/// Reports an execve that failed and exits as Docker ends that container:
/// 126 when the command may not be run, 127 when it is missing, 255 when
/// runc's exec itself fails (a script without a shebang, a missing
/// interpreter). Only for the child between clone and exec. `init`: the
/// program runs under `--init`, which Docker leaves to tini.
pub fn exec_fail(fd: RawFd, exe: &CStr, err: io::Error, init: bool) -> ! {
    let exe = exe.to_string_lossy();
    let path = Path::new(&*exe);
    let found = Found { exists: path.exists(), dir: path.is_dir() };
    let (code, why) = exec_failure(&exe, &err, found, init);
    // runc reports what it refuses before the start as the daemon's error,
    // and a failed exec after it on the container's stderr, as is.
    let msg = if code == 255 { format!("{why}\n") } else { format!("kiri: cannot start container: {}\n", one_line(&why)) };
    // SAFETY: writing a valid buffer to a descriptor we hold, then exiting.
    unsafe {
        libc::write(fd, msg.as_ptr().cast(), msg.len());
        libc::_exit(code)
    }
}

/// What is at the path execve refused.
#[derive(Clone, Copy, Default)]
pub struct Found {
    pub exists: bool,
    pub dir: bool,
}

/// The exit code and message for a command execve would not run, worded
/// as runc words them. Refused before the start: `exec: "/etc/passwd":
/// permission denied` ends 126 (`exec: "/etc": is a directory: permission
/// denied` for a directory, which Linux refuses with EACCES), a missing
/// one 127 (`stat /x: no such file or directory`). Failing in runc's exec
/// after the start, 255: `exec /x: exec format error` for a file that is
/// no program (a script without a shebang), `exec /x: no such file or
/// directory` when the file is there but its interpreter isn't.
/// Under `--init` (tini), a missing interpreter is 127 and the rest 126.
pub fn exec_failure(exe: &str, err: &io::Error, found: Found, init: bool) -> (i32, String) {
    match err.raw_os_error() {
        Some(libc::EACCES | libc::EISDIR) if found.dir => (126, format!("exec: \"{exe}\": is a directory: permission denied")),
        Some(libc::EACCES) => (126, format!("exec: \"{exe}\": permission denied")),
        Some(libc::ENOEXEC) if init => (126, format!("exec: \"{exe}\": exec format error")),
        Some(libc::ENOEXEC) => (255, format!("exec {exe}: exec format error")),
        Some(libc::ENOENT) if found.exists && init => (127, format!("exec {exe}: no such file or directory")),
        Some(libc::ENOENT) if found.exists => (255, format!("exec {exe}: no such file or directory")),
        Some(libc::ENOENT) => (127, format!("exec: \"{exe}\": stat {exe}: no such file or directory")),
        Some(libc::ENOTDIR) => (127, format!("exec: \"{exe}\": stat {exe}: not a directory")),
        _ => (127, format!("exec: \"{exe}\": {err}")),
    }
}

pub fn socketpair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: `fds` has room for the two descriptors socketpair writes.
    check(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) } as _, "socketpair")?;
    // SAFETY: socketpair succeeded, so both descriptors are fresh and ours.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Sends one descriptor over a Unix socket (SCM_RIGHTS).
pub fn send_fd(sock: RawFd, fd: RawFd) -> io::Result<()> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr().cast(), iov_len: 1 };
    // SAFETY: CMSG_SPACE is a pure size computation.
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut control = vec![0u8; space];
    // SAFETY: msghdr is plain data; all-zero is valid before filling it in.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    // SAFETY: `msg` points at a control buffer big enough for one fd.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd);
        check(libc::sendmsg(sock, &msg, 0) as _, "sendmsg").map(drop)
    }
}

/// What came over a socket: a descriptor, or the bytes of an error message.
pub enum Received {
    Fd(OwnedFd),
    Message(String),
}

/// Receives one descriptor, or whatever text the peer sent instead.
pub fn recv_fd(sock: RawFd) -> io::Result<Received> {
    let mut buf = [0u8; 512];
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    // SAFETY: CMSG_SPACE is a pure size computation.
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut control = vec![0u8; space];
    // SAFETY: msghdr is plain data; all-zero is valid before filling it in.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    // SAFETY: `msg` describes buffers we own; MSG_CMSG_CLOEXEC marks the fd.
    let n = check(unsafe { libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) } as _, "recvmsg")?;
    // SAFETY: walking the control messages recvmsg filled in.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if !cmsg.is_null() && (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
            let fd = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>());
            return Ok(Received::Fd(OwnedFd::from_raw_fd(fd)));
        }
    }
    Ok(Received::Message(String::from_utf8_lossy(&buf[..n as usize]).trim().to_owned()))
}

pub fn setns(fd: RawFd, nstype: libc::c_int) -> io::Result<()> {
    // SAFETY: plain syscall on a namespace descriptor we hold.
    check(unsafe { libc::setns(fd, nstype) } as _, "setns").map(drop)
}

pub fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: plain fcntl calls on a descriptor we own.
    unsafe {
        let flags = check(libc::fcntl(fd, libc::F_GETFL) as _, "fcntl")?;
        check(libc::fcntl(fd, libc::F_SETFL, flags as libc::c_int | libc::O_NONBLOCK) as _, "fcntl").map(drop)
    }
}

/// Opens a new pseudo-terminal pair from the current mount namespace's
/// /dev/ptmx. Returns (master, slave).
pub fn open_pty() -> io::Result<(OwnedFd, OwnedFd)> {
    // SAFETY: plain open/ioctl calls; descriptors are owned right away.
    unsafe {
        let master = check(libc::open(c"/dev/ptmx".as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) as _, "open /dev/ptmx")?;
        let master = OwnedFd::from_raw_fd(master as RawFd);
        let unlock: libc::c_int = 0;
        check(libc::ioctl(master.as_raw_fd(), libc::TIOCSPTLCK as libc::Ioctl, &unlock) as _, "unlock pty")?;
        let mut n: libc::c_uint = 0;
        check(libc::ioctl(master.as_raw_fd(), libc::TIOCGPTN as libc::Ioctl, &mut n) as _, "pty number")?;
        let path = CString::new(format!("/dev/pts/{n}")).expect("no NUL");
        let slave = check(libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) as _, "open pty slave")?;
        Ok((master, OwnedFd::from_raw_fd(slave as RawFd)))
    }
}

/// The descriptor ranges to close so that only 0, 1, 2 and `keep` stay
/// open: (first, last), inclusive, in order.
pub fn close_ranges(keep: &[RawFd]) -> Vec<(libc::c_uint, libc::c_uint)> {
    let mut keep: Vec<libc::c_uint> = keep.iter().filter(|&&fd| fd > 2).map(|&fd| fd as libc::c_uint).collect();
    keep.sort_unstable();
    keep.dedup();
    let mut out = Vec::with_capacity(keep.len() + 1);
    let mut next = 3;
    for fd in keep {
        if fd > next {
            out.push((next, fd - 1));
        }
        next = fd + 1;
    }
    out.push((next, libc::c_uint::MAX));
    out
}

/// Closes the ranges `close_ranges` gave, without allocating. Before Linux
/// 5.9 there is no close_range, and the descriptors stay open, as they
/// always did before.
pub fn close_now(ranges: &[(libc::c_uint, libc::c_uint)]) {
    for &(first, last) in ranges {
        // SAFETY: closing descriptors of this process, which the caller
        // no longer uses.
        unsafe { libc::syscall(libc::SYS_close_range, first, last, 0) };
    }
}

pub fn resize_pty(fd: RawFd, rows: u16, cols: u16) {
    let ws = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: TIOCSWINSZ with a valid winsize on a descriptor we own.
    unsafe { libc::ioctl(fd, libc::TIOCSWINSZ as libc::Ioctl, &ws) };
}

#[cfg(test)]
mod tests {
    use std::io;

    /// 131 layers by digest make options longer than a
    /// page: the overlay still stacks them all, the lowest one included.
    #[test]
    fn an_overlay_of_more_layers_than_one_page_names() {
        // SAFETY: a plain getter.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipped: needs root to mount");
            return;
        }
        let d = std::env::temp_dir().join(format!("kiri-many-lowers-{}", std::process::id()));
        let layers = d.join("layers");
        let mut lowers = Vec::new();
        for i in 0..131 {
            let name = format!("{i:064x}");
            std::fs::create_dir_all(layers.join(&name)).unwrap();
            std::fs::write(layers.join(&name).join(format!("f{i}")), b"x").unwrap();
            lowers.insert(0, layers.join(&name).to_str().unwrap().to_owned());
        }
        let target = d.join("root");
        std::fs::create_dir_all(&target).unwrap();
        super::mount_overlay(&target, &lowers, ",index=off", libc::MS_RDONLY).unwrap();
        let seen = target.join("f0").exists() && target.join("f130").exists();
        let _ = super::umount_lazy(&target);
        assert!(seen, "every layer is in the overlay");
        assert!(!d.join("root.lowers").exists(), "the links are gone");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A value over several lines never starts a line of its own in the log.
    #[test]
    fn the_engines_message_is_one_line() {
        assert_eq!(super::one_line("user: unknown user -----BEGIN KEY-----\nAAA\r\n-----END KEY-----"), "user: unknown user -----BEGIN KEY----- AAA -----END KEY-----");
        // A backslash or a quote stays as the value has it.
        assert_eq!(super::one_line("user: unknown user Bs-x\\yy\"4dd4"), "user: unknown user Bs-x\\yy\"4dd4");
        assert_eq!(super::one_line("DOM\\bob\\n"), "DOM\\bob\\n");
        assert_eq!(super::one_line("x\ny\rz"), "x y z");
    }

    #[test]
    fn only_the_kept_descriptors_stay_open() {
        let all = libc::c_uint::MAX;
        assert_eq!(super::close_ranges(&[]), vec![(3, all)]);
        // Standard streams are never closed; order and repeats don't matter.
        assert_eq!(super::close_ranges(&[9, 2, 4, 9, 5, 0]), vec![(3, 3), (6, 8), (10, all)]);
        assert_eq!(super::close_ranges(&[3]), vec![(4, all)]);
        // The real thing, in a child of its own: the kept ones stay open,
        // the rest are closed. Forked from a test with threads, so the
        // child only makes system calls (the ranges are worked out first).
        let (unrelated, unrelated_w) = super::pipe().unwrap();
        let (kept, kept_w) = super::pipe().unwrap();
        let (report, report_w) = super::pipe().unwrap();
        use std::os::fd::AsRawFd;
        let keep = [kept.as_raw_fd(), report_w.as_raw_fd()];
        let ranges = super::close_ranges(&keep);
        let check = [unrelated.as_raw_fd(), unrelated_w.as_raw_fd(), kept_w.as_raw_fd(), report.as_raw_fd()];
        // SAFETY: the child makes only async-signal-safe system calls and
        // leaves with _exit.
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                super::close_now(&ranges);
                let open = |fd| libc::fcntl(fd, libc::F_GETFD) >= 0;
                let mut ok = keep.iter().all(|&fd| open(fd)) && (0..3).all(open);
                ok &= check.iter().all(|&fd| !open(fd));
                libc::write(report_w.as_raw_fd(), if ok { b"y".as_ptr() } else { b"n".as_ptr() }.cast(), 1);
                libc::_exit(0);
            }
            drop(report_w);
            let mut said = [0u8; 1];
            assert_eq!(libc::read(report.as_raw_fd(), said.as_mut_ptr().cast(), 1), 1, "the child said nothing");
            libc::waitpid(pid, std::ptr::null_mut(), 0);
            assert_eq!(&said, b"y", "a kept descriptor was closed, or another left open");
        }
    }

    /// A command that may not be run ends 126 and one that is missing 127,
    /// as with Docker (`docker run alpine /etc/passwd` is 126).
    #[test]
    fn exec_failures_end_as_docker_ends_them() {
        use super::Found;
        let os = io::Error::from_raw_os_error;
        let f = super::exec_failure;
        let file = Found { exists: true, dir: false };
        let dir = Found { exists: true, dir: true };
        let none = Found::default();
        assert_eq!(f("/etc/passwd", &os(libc::EACCES), file, false), (126, "exec: \"/etc/passwd\": permission denied".into()));
        // Linux refuses a directory with EACCES; runc names it.
        assert_eq!(f("/etc", &os(libc::EACCES), dir, false), (126, "exec: \"/etc\": is a directory: permission denied".into()));
        assert_eq!(f("/etc", &os(libc::EISDIR), dir, true).0, 126);
        assert_eq!(f("/nope", &os(libc::ENOENT), none, false), (127, "exec: \"/nope\": stat /nope: no such file or directory".into()));
        // runc's exec fails after the start: 255, its own words.
        assert_eq!(f("/x", &os(libc::ENOEXEC), file, false), (255, "exec /x: exec format error".into()));
        assert_eq!(f("/run.sh", &os(libc::ENOENT), file, false), (255, "exec /run.sh: no such file or directory".into()));
        // tini (--init): a missing interpreter is 127.
        assert_eq!(f("/run.sh", &os(libc::ENOENT), file, true).0, 127);
    }

    /// The real thing: execve of a directory fails with EACCES, which runc
    /// words as a directory.
    #[test]
    fn exec_of_a_directory_says_so() {
        let c = std::ffi::CString::new("/").unwrap();
        let argv = [c.as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null()];
        // SAFETY: valid NULL-terminated arrays; execve fails and returns.
        unsafe { libc::execve(c.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        let err = io::Error::last_os_error();
        assert_eq!(super::exec_failure("/", &err, super::Found { exists: true, dir: true }, false), (126, "exec: \"/\": is a directory: permission denied".into()), "{err}");
    }

    /// The real thing: execve of a file that is not executable fails with
    /// EACCES, which is 126.
    #[test]
    fn exec_of_a_plain_file_is_126() {
        let dir = std::env::temp_dir().join(format!("kiri-exec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("plain");
        std::fs::write(&file, b"not a program").unwrap();
        let c = std::ffi::CString::new(file.to_str().unwrap()).unwrap();
        let argv = [c.as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null()];
        // SAFETY: valid NULL-terminated arrays; execve fails and returns.
        unsafe { libc::execve(c.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        let err = io::Error::last_os_error();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(super::exec_failure(file.to_str().unwrap(), &err, super::Found { exists: true, dir: false }, false).0, 126, "{err}");
    }

    /// Only a clone3 that is blocked (a seccomp filter answering ENOSYS or
    /// EPERM, as Docker's and Android's do, #529) falls back to clone(2);
    /// a refusal of the request itself is reported as it is.
    #[test]
    fn only_a_blocked_clone3_falls_back() {
        let f = super::clone3_unavailable;
        assert!(f(Some(libc::ENOSYS)));
        assert!(f(Some(libc::EPERM)));
        for code in [libc::EINVAL, libc::EBUSY, libc::EAGAIN, libc::ENOMEM] {
            assert!(!f(Some(code)), "errno {code}");
        }
        assert!(!f(None));
    }

    /// clone(2) cannot take CLONE_INTO_CGROUP (or any >32-bit clone3 flag such
    /// as CLONE_CLEAR_SIGHAND), and a CLONE_NEWCGROUP made before the child is
    /// in its cgroup would be rooted at the agent's, so all of those are
    /// dropped; clone3's exit signal goes in the low byte, as clone(2) expects.
    #[test]
    fn clone2_flags_drop_what_it_cannot_place() {
        const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;
        let args = super::CloneArgs {
            flags: (libc::CLONE_NEWPID | libc::CLONE_NEWCGROUP) as u64 | super::CLONE_INTO_CGROUP | CLONE_CLEAR_SIGHAND,
            exit_signal: libc::SIGCHLD as u64,
            ..Default::default()
        };
        let flags = super::clone_flags(&args) as u64;
        assert_eq!(flags & libc::CLONE_NEWPID as u64, libc::CLONE_NEWPID as u64);
        assert_eq!(flags & super::CLONE_INTO_CGROUP, 0);
        assert_eq!(flags & CLONE_CLEAR_SIGHAND, 0);
        assert_eq!(flags & libc::CLONE_NEWCGROUP as u64, 0);
        assert_eq!(flags & 0xff, libc::SIGCHLD as u64);
    }

    /// The real thing: a seccomp filter answering ENOSYS or EPERM for clone3,
    /// as Android's and Docker's do (#529), must fall back to clone(2) instead
    /// of failing the start. The filter is installed in a child process of
    /// this test binary, so it does not outlive the test.
    #[test]
    fn blocked_clone3_falls_back_to_clone() {
        if let Some(val) = std::env::var_os("KIRI_CLONE3_SEccomp") {
            let code = if val == "EPERM" { libc::EPERM } else { libc::ENOSYS };
            install_clone3_denial(code);
            // SAFETY: this helper process runs no other thread, as clone(2)
            // without CLONE_VM needs; the child only calls _exit.
            let cloned = unsafe {
                super::clone3(&super::CloneArgs { exit_signal: libc::SIGCHLD as u64, ..Default::default() })
            }
            .expect("a blocked clone3 must fall back to clone");
            assert!(!cloned.into_cgroup, "clone(2) cannot place the child in a cgroup");
            if cloned.pid == 0 {
                // SAFETY: _exit neither unwinds nor runs destructors.
                unsafe { libc::_exit(0) };
            }
            let mut status = 0;
            // SAFETY: waiting for the child just cloned.
            let waited = unsafe { libc::waitpid(cloned.pid, &mut status, 0) };
            assert_eq!(waited, cloned.pid);
            assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "child status {status}");
            return;
        }
        let module = module_path!();
        let module = module.split_once("::").map_or(module, |(_, m)| m);
        let name = format!("{module}::blocked_clone3_falls_back_to_clone");
        for kind in ["1", "EPERM"] {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture", "--test-threads=1"])
                .env("KIRI_CLONE3_SEccomp", kind)
                .output()
                .expect("spawn this test binary");
            assert!(
                out.status.success(),
                "the clone3-blocked helper ({kind}) failed:\n{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    /// Installs a seccomp filter that makes clone3 return `errno`.
    fn install_clone3_denial(errno: i32) {
        #[repr(C)]
        struct Insn {
            code: u16,
            jt: u8,
            jf: u8,
            k: u32,
        }
        #[repr(C)]
        struct Prog {
            len: u16,
            filter: *const Insn,
        }
        const LD_W_ABS: u16 = 0x20;
        const JEQ_K: u16 = 0x15;
        const RET_K: u16 = 0x06;
        const RET_ALLOW: u32 = 0x7fff_0000;
        const RET_ERRNO: u32 = 0x0005_0000;
        let insns = [
            Insn { code: LD_W_ABS, jt: 0, jf: 0, k: 0 }, // seccomp_data.nr
            Insn { code: JEQ_K, jt: 0, jf: 1, k: libc::SYS_clone3 as u32 },
            Insn { code: RET_K, jt: 0, jf: 0, k: RET_ERRNO | errno as u32 },
            Insn { code: RET_K, jt: 0, jf: 0, k: RET_ALLOW },
        ];
        let prog = Prog { len: insns.len() as u16, filter: insns.as_ptr() };
        // SAFETY: valid prctl calls; `prog` lives until they return.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0, "no_new_privs: {}", io::Error::last_os_error());
            let n = libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER as libc::c_ulong, &prog);
            assert_eq!(n, 0, "seccomp: {}", io::Error::last_os_error());
        }
    }

    #[test]
    fn parses_readonly_mounts_and_formats_wsl_and_linux_diagnostics() {
        use std::path::Path;
        let healthy = "/dev/sdd / ext4 rw,relatime,discard,errors=remount-ro,data=ordered 0 0\n";
        assert_eq!(super::proc_mounts_readonly(healthy, Path::new("/var/lib/kiri")), None);

        let emergency = "/dev/sdd / ext4 rw,relatime,discard,errors=remount-ro,data=ordered,emergency_ro 0 0\ntmpfs /run tmpfs rw,nosuid,nodev,mode=755 0 0\n";
        assert_eq!(super::proc_mounts_readonly(emergency, Path::new("/var/lib/kiri/containers/abc")), Some(super::ReadOnlyKind::EmergencyRo));
        assert_eq!(super::proc_mounts_readonly(emergency, Path::new("/run/kiri")), None);

        let mountinfo = "25 1 8:48 / / rw,relatime - ext4 /dev/sdd rw,discard,errors=remount-ro,data=ordered,emergency_ro\n";
        assert_eq!(super::mountinfo_readonly(mountinfo, Path::new("/var/lib/kiri")), Some(super::ReadOnlyKind::EmergencyRo));

        assert!(super::is_wsl_env("6.6.87.2-microsoft-standard-WSL2\n", false));
        assert!(super::is_wsl_env("6.18.58.1-1\n", true));
        assert!(!super::is_wsl_env("6.18.58.1-1-generic\n", false));

        let wsl = super::format_readonly_storage_error(super::ReadOnlyKind::EmergencyRo, true, true);
        assert!(wsl.contains("ext4.vhdx") && wsl.contains("emergency_ro") && wsl.contains("e2fsck -f -y -D"), "{wsl}");
        let host = super::format_readonly_storage_error(super::ReadOnlyKind::EmergencyRo, false, true);
        assert!(host.contains("/var/lib/kiri") && host.contains("fsck"), "{host}");
        let vm = super::format_readonly_storage_error(super::ReadOnlyKind::ReadOnly, false, false);
        assert!(vm.contains("VM data disk"), "{vm}");
    }
}
