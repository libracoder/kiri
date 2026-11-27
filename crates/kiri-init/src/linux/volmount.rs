//! Volumes with the local driver's options (`type=nfs`, `type=tmpfs`,
//! `type=none,o=bind`, `type=cifs`), plus sparse loopback `ext4` backing for
//! `kiri-k8s` when `/var/lib/kiri/volumes` sits on ZFS (#607): the guest
//! mounts the device at the volume's own path the first time a container
//! starts with it, as Docker's local driver does, and the container binds
//! that path in like any other volume. Driver-option mounts stay until the
//! volume is removed or the VM stops; `kiri-k8s` loopback `ext4` mounts
//! unmount cleanly when the last container using them stops, on volume
//! removal, or on agent sweep.

use std::collections::HashMap;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// Where volumes live; nothing outside it is ever mounted over.
const ROOT: &str = "/var/lib/kiri/volumes/";

/// Data directory of Kiri's Kubernetes (`k3s`) named volume.
pub const K8S_VOLUME_DATA: &str = "/var/lib/kiri/volumes/kiri-k8s/_data";
/// Sparse ext4 backing image stored beside `_data` inside `/var/lib/kiri/volumes/kiri-k8s`.
const K8S_EXT4_IMAGE: &str = "ext4.img";
const K8S_EXT4_TMP: &str = ".ext4.img.tmp";
/// Logical sparse image size (64 GiB; near-zero initial allocated blocks on ZFS).
const K8S_EXT4_SIZE_BYTES: u64 = 64 << 30;

const EXT4_SUPER_OFFSET: u64 = 1024;
const EXT4_SUPER_MAGIC_OFFSET: u64 = 0x38;
const EXT4_SUPER_MAGIC: u16 = 0xEF53;

// Linux <uapi/linux/loop.h> constants (identical across x86_64 and aarch64).
const LOOP_SET_FD: libc::Ioctl = 0x4C00 as libc::Ioctl;
const LOOP_CLR_FD: libc::Ioctl = 0x4C01 as libc::Ioctl;
const LOOP_SET_STATUS64: libc::Ioctl = 0x4C04 as libc::Ioctl;
const LOOP_GET_STATUS64: libc::Ioctl = 0x4C05 as libc::Ioctl;
const LOOP_CTL_GET_FREE: libc::Ioctl = 0x4C82 as libc::Ioctl;
const LO_FLAGS_AUTOCLEAR: u32 = 4;
const LO_NAME_SIZE: usize = 64;
const LO_KEY_SIZE: usize = 32;
const LOOP_MAJOR: u32 = 7;

#[repr(C)]
#[derive(Clone, Copy)]
struct LoopInfo64 {
    lo_device: u64,
    lo_inode: u64,
    lo_rdevice: u64,
    lo_offset: u64,
    lo_sizelimit: u64,
    lo_number: u32,
    lo_encrypt_type: u32,
    lo_encrypt_key_size: u32,
    lo_flags: u32,
    lo_file_name: [u8; LO_NAME_SIZE],
    lo_crypt_name: [u8; LO_NAME_SIZE],
    lo_encrypt_key: [u8; LO_KEY_SIZE],
    lo_init: [u64; 2],
}

impl Default for LoopInfo64 {
    fn default() -> Self {
        // SAFETY: LoopInfo64 is plain integer/byte kernel UAPI data.
        unsafe { std::mem::zeroed() }
    }
}

#[derive(Default)]
struct LoopRefs {
    counts: HashMap<String, usize>,
}

impl LoopRefs {
    fn acquire(&mut self, path: &str) {
        *self.counts.entry(path.to_owned()).or_insert(0) += 1;
    }

    /// Releases one holder; returns true when no holders remain and the mount
    /// should be unmounted.
    fn release(&mut self, path: &str) -> bool {
        match self.counts.get_mut(path) {
            Some(n) if *n > 1 => {
                *n -= 1;
                false
            }
            _ => {
                self.counts.remove(path);
                true
            }
        }
    }

    fn clear(&mut self, path: &str) {
        self.counts.remove(path);
    }
}

fn loop_refs() -> &'static Mutex<LoopRefs> {
    static REFS: OnceLock<Mutex<LoopRefs>> = OnceLock::new();
    REFS.get_or_init(|| Mutex::new(LoopRefs::default()))
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what.to_owned())
}

/// Whether `/proc/self/mountinfo` text lists `path` as an active mount point.
fn mounted_in(mountinfo: &str, path: &str) -> bool {
    mountinfo.lines().any(|line| {
        let Some((before, _)) = line.split_once(" - ") else { return false };
        before.split_whitespace().nth(4).is_some_and(|mp| super::sys::unescape_mount_path(mp) == path)
    })
}

/// Whether `path` is a mount point in this mount namespace.
pub fn mounted(path: &str) -> bool {
    let Ok(info) = fs::read_to_string("/proc/self/mountinfo") else { return false };
    mounted_in(&info, path)
}

/// Whether `path` is the `kiri-k8s` named volume's `_data` directory.
pub fn is_k8s_volume_data(path: &str) -> bool {
    path == K8S_VOLUME_DATA
}

/// Path of the sparse ext4 image stored beside a volume's `_data` directory.
pub fn k8s_ext4_image_path(data_path: &Path) -> Option<PathBuf> {
    if data_path.file_name() != Some(OsStr::new("_data")) {
        return None;
    }
    Some(data_path.parent()?.join(K8S_EXT4_IMAGE))
}

/// Returns true if `path` has a valid ext4 superblock magic (`0xEF53`) at offset 1080.
pub fn has_ext4_superblock(path: &Path) -> io::Result<bool> {
    let mut f = File::open(path)?;
    if f.metadata()?.len() < EXT4_SUPER_OFFSET + EXT4_SUPER_MAGIC_OFFSET + 2 {
        return Ok(false);
    }
    f.seek(SeekFrom::Start(EXT4_SUPER_OFFSET + EXT4_SUPER_MAGIC_OFFSET))?;
    let mut magic = [0u8; 2];
    f.read_exact(&mut magic)?;
    Ok(u16::from_le_bytes(magic) == EXT4_SUPER_MAGIC)
}

/// Creates a new `0o600` sparse file of logical length `size_bytes`.
fn create_sparse_file(path: &Path, size_bytes: u64) -> io::Result<()> {
    let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.set_len(size_bytes)
}

fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file() && (m.mode() & 0o111 != 0))
}

/// Locates `mkfs.ext4` (preferred) or `mke2fs` across standard sbin/bin dirs and `PATH`.
/// Returns `(binary_path, is_mke2fs)`.
fn find_mkfs_ext4_in(extra_dirs: &[&Path], path_env: Option<&OsStr>) -> Option<(PathBuf, bool)> {
    let mut dirs: Vec<PathBuf> = extra_dirs.iter().map(|d| d.to_path_buf()).collect();
    if let Some(p) = path_env {
        for d in std::env::split_paths(p) {
            if !dirs.contains(&d) {
                dirs.push(d);
            }
        }
    }
    for (bin, is_mke2fs) in [("mkfs.ext4", false), ("mke2fs", true)] {
        for dir in &dirs {
            let candidate = dir.join(bin);
            if is_executable_file(&candidate) {
                return Some((candidate, is_mke2fs));
            }
        }
    }
    None
}

fn mkfs_ext4_args(is_mke2fs: bool, img: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::with_capacity(11);
    if is_mke2fs {
        args.push(OsString::from("-t"));
        args.push(OsString::from("ext4"));
    }
    for flag in ["-F", "-q", "-m", "0", "-L", "kiri-k8s", "-E", "lazy_itable_init=1,lazy_journal_init=1"] {
        args.push(OsString::from(flag));
    }
    args.push(img.as_os_str().to_owned());
    args
}

fn format_ext4_image(img: &Path) -> io::Result<()> {
    let standard = [Path::new("/sbin"), Path::new("/usr/sbin"), Path::new("/bin"), Path::new("/usr/bin")];
    let Some((exe, is_mke2fs)) = find_mkfs_ext4_in(&standard, std::env::var_os("PATH").as_deref()) else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Kiri Kubernetes on a ZFS host requires `mkfs.ext4` (`e2fsprogs`) to create the ext4 backing image for `kiri-k8s`; install `e2fsprogs` and retry",
        ));
    };
    let output = Command::new(&exe)
        .args(mkfs_ext4_args(is_mke2fs, img))
        .output()
        .map_err(|e| io::Error::new(e.kind(), format!("running {} on {}: {e}", exe.display(), img.display())))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        let why = if detail.is_empty() { format!("exit status {}", output.status) } else { detail.to_owned() };
        return Err(io::Error::other(format!("{} failed to format {}: {why}", exe.display(), img.display())));
    }
    Ok(())
}

/// Ensures `img_path` exists and contains a valid ext4 filesystem, formatting
/// atomically via a sibling temp file on first creation.
fn ensure_ext4_image(img_path: &Path, size_bytes: u64) -> io::Result<()> {
    if img_path.exists() {
        if has_ext4_superblock(img_path)? {
            return Ok(());
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} is not a valid ext4 image; remove the kiri-k8s volume (`kiri k8s delete`) and start Kubernetes again",
                img_path.display()
            ),
        ));
    }
    let parent = img_path.parent().ok_or_else(|| invalid("ext4 image path has no parent"))?;
    let tmp_path = parent.join(K8S_EXT4_TMP);
    let _ = fs::remove_file(&tmp_path);
    let setup = (|| -> io::Result<()> {
        create_sparse_file(&tmp_path, size_bytes)?;
        format_ext4_image(&tmp_path)?;
        if !has_ext4_superblock(&tmp_path)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("formatted {} does not contain an ext4 superblock", tmp_path.display()),
            ));
        }
        fs::rename(&tmp_path, img_path)
    })();
    if setup.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    setup
}

/// Populates a `LoopInfo64` with `LO_FLAGS_AUTOCLEAR` and a NUL-terminated
/// copy of `backing` (truncated to fit `LO_NAME_SIZE - 1` bytes).
fn make_loop_info64(mut info: LoopInfo64, backing: &Path) -> LoopInfo64 {
    info.lo_flags |= LO_FLAGS_AUTOCLEAR;
    info.lo_file_name = [0u8; LO_NAME_SIZE];
    let bytes = backing.as_os_str().as_bytes();
    let n = bytes.len().min(LO_NAME_SIZE - 1);
    info.lo_file_name[..n].copy_from_slice(&bytes[..n]);
    info
}

fn open_rw_cloexec(path: &Path) -> io::Result<OwnedFd> {
    let c = super::sys::cstr(path)?;
    // SAFETY: `c` is a valid NUL-terminated path; returned fd is owned immediately.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open succeeded, so `fd` is fresh and ours.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

fn mount_loop_ext4(img_path: &Path, target: &Path) -> io::Result<()> {
    let img_fd = open_rw_cloexec(img_path)
        .map_err(|e| io::Error::new(e.kind(), format!("open {}: {e}", img_path.display())))?;
    let ctl_fd = open_rw_cloexec(Path::new("/dev/loop-control")).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "Kiri Kubernetes on a ZFS host needs Linux loop devices (/dev/loop-control: {e}); ensure the `loop` kernel module is loaded (`modprobe loop`) and loop devices are permitted"
            ),
        )
    })?;
    let target_c = super::sys::cstr(target)?;

    let mut last_busy = None;
    for _ in 0..16 {
        // SAFETY: LOOP_CTL_GET_FREE allocates or returns a free loop device number.
        let n = unsafe { libc::ioctl(ctl_fd.as_raw_fd(), LOOP_CTL_GET_FREE, 0 as libc::c_ulong) };
        if n < 0 {
            let e = io::Error::last_os_error();
            return Err(io::Error::new(e.kind(), format!("LOOP_CTL_GET_FREE: {e}")));
        }
        let dev_path = PathBuf::from(format!("/dev/loop{n}"));
        let loop_fd = match open_rw_cloexec(&dev_path) {
            Ok(fd) => fd,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                if let Ok(dev_c) = super::sys::cstr(&dev_path) {
                    let _ = super::sys::mknod(&dev_c, libc::S_IFBLK | 0o660, LOOP_MAJOR, n as u32);
                }
                open_rw_cloexec(&dev_path).map_err(|e| io::Error::new(e.kind(), format!("open {}: {e}", dev_path.display())))?
            }
            Err(e) => return Err(io::Error::new(e.kind(), format!("open {}: {e}", dev_path.display()))),
        };

        // SAFETY: binds `img_fd` to `loop_fd`; EBUSY means another process claimed this loop number.
        let set = unsafe { libc::ioctl(loop_fd.as_raw_fd(), LOOP_SET_FD, img_fd.as_raw_fd() as libc::c_ulong) };
        if set < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EBUSY) {
                last_busy = Some(e);
                continue;
            }
            return Err(io::Error::new(e.kind(), format!("LOOP_SET_FD on {}: {e}", dev_path.display())));
        }

        let mut info = LoopInfo64::default();
        // SAFETY: best-effort read of kernel defaults into `info`.
        let _ = unsafe { libc::ioctl(loop_fd.as_raw_fd(), LOOP_GET_STATUS64, &mut info) };
        info = make_loop_info64(info, img_path);
        // SAFETY: sets LO_FLAGS_AUTOCLEAR and lo_file_name on `loop_fd`.
        if unsafe { libc::ioctl(loop_fd.as_raw_fd(), LOOP_SET_STATUS64, &info) } < 0 {
            let e = io::Error::last_os_error();
            // SAFETY: clear the loop device before dropping `loop_fd` since AUTOCLEAR failed.
            unsafe { libc::ioctl(loop_fd.as_raw_fd(), LOOP_CLR_FD, 0 as libc::c_ulong) };
            return Err(io::Error::new(e.kind(), format!("LOOP_SET_STATUS64 on {}: {e}", dev_path.display())));
        }

        let dev_c = super::sys::cstr(&dev_path)?;
        // noinit_itable matches the VM ext4 mount so the kernel does not slowly
        // write zeros across the sparse 64 GiB image in the background.
        // SAFETY: valid NUL-terminated strings for mount(2).
        let mut r = unsafe {
            libc::mount(dev_c.as_ptr(), target_c.as_ptr(), c"ext4".as_ptr(), 0, c"noinit_itable".as_ptr().cast())
        };
        if r != 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
            // SAFETY: fallback mount with default kernel options.
            r = unsafe { libc::mount(dev_c.as_ptr(), target_c.as_ptr(), c"ext4".as_ptr(), 0, std::ptr::null()) };
        }
        if r != 0 {
            let e = io::Error::last_os_error();
            // SAFETY: defensively clear loop binding on mount failure (AUTOCLEAR also detaches on close).
            unsafe { libc::ioctl(loop_fd.as_raw_fd(), LOOP_CLR_FD, 0 as libc::c_ulong) };
            return Err(io::Error::new(
                e.kind(),
                format!("mount ext4 loop {} on {}: {e}", dev_path.display(), target.display()),
            ));
        }
        // `loop_fd` closes here while the kernel mount keeps the loop device alive
        // and LO_FLAGS_AUTOCLEAR detaches it automatically on unmount.
        return Ok(());
    }
    let e = last_busy.unwrap_or_else(|| io::Error::from_raw_os_error(libc::EBUSY));
    Err(io::Error::new(e.kind(), format!("could not claim a free loop device for {}: {e}", img_path.display())))
}

/// On a Linux host where `/var/lib/kiri/volumes` sits on ZFS, ensures the
/// `kiri-k8s` volume's `_data` directory is loop-mounted from a sparse `ext4`
/// image (`ext4.img`) so k3s's kubelet/cAdvisor and containerd overlayfs run
/// on a real block device instead of ZFS (#607).
///
/// Returns `Ok(true)` when a loopback ext4 mount is held for `data_path` and
/// must be released via [`release_loop`] when the container stops.
pub fn ensure_k8s_ext4(data_path: &str) -> io::Result<bool> {
    if !is_k8s_volume_data(data_path) || !super::transport::is_host_process() {
        return Ok(false);
    }
    let target = Path::new(data_path);
    let vol_dir = target.parent().ok_or_else(|| invalid("k8s volume path has no parent"))?;
    if !super::sys::is_zfs(vol_dir) {
        return Ok(false);
    }
    fs::create_dir_all(target)?;
    if mounted(data_path) {
        loop_refs().lock().unwrap_or_else(|e| e.into_inner()).acquire(data_path);
        return Ok(true);
    }
    let img_path = k8s_ext4_image_path(target).ok_or_else(|| invalid("invalid k8s volume data path"))?;
    ensure_ext4_image(&img_path, K8S_EXT4_SIZE_BYTES)?;
    mount_loop_ext4(&img_path, target)?;
    loop_refs().lock().unwrap_or_else(|e| e.into_inner()).acquire(data_path);
    Ok(true)
}

/// Allowed non-bind volume filesystem types (`SEC-D-04`). Any other fstype
/// (e.g. `overlay`, `ext4`, `devtmpfs`, `proc`, `sysfs`, `virtiofs`) is refused.
const ALLOWED_FS_TYPES: [&str; 5] = ["nfs", "nfs4", "cifs", "smb3", "tmpfs"];

/// Safe mount(2) flags accepted for bind volumes. Propagation and remount/move
/// flags are rejected.
const ALLOWED_BIND_FLAGS: libc::c_ulong = libc::MS_BIND
    | libc::MS_REC
    | libc::MS_RDONLY
    | libc::MS_NOSUID
    | libc::MS_NODEV
    | libc::MS_NOEXEC
    | libc::MS_NOATIME
    | libc::MS_NODIRATIME
    | libc::MS_RELATIME
    | libc::MS_STRICTATIME;

/// Safe mount(2) flags accepted for non-bind local driver volumes.
const ALLOWED_FS_FLAGS: libc::c_ulong = libc::MS_RDONLY
    | libc::MS_NOSUID
    | libc::MS_NODEV
    | libc::MS_NOEXEC
    | libc::MS_NOATIME
    | libc::MS_NODIRATIME
    | libc::MS_RELATIME
    | libc::MS_STRICTATIME
    | libc::MS_SYNCHRONOUS
    | libc::MS_DIRSYNC
    | libc::MS_MANDLOCK
    | libc::MS_SILENT;

/// Flags applied during the bind remount step.
const BIND_REMOUNT_ATTRS: libc::c_ulong = libc::MS_RDONLY
    | libc::MS_NOSUID
    | libc::MS_NODEV
    | libc::MS_NOEXEC
    | libc::MS_NOATIME
    | libc::MS_NODIRATIME
    | libc::MS_RELATIME
    | libc::MS_STRICTATIME;

/// Validates volume mount target, filesystem type, device, and flags before
/// calling `mount(2)`.
fn validate_mount(path: &str, kind: &str, device: &str, flags: libc::c_ulong, host_process: bool) -> io::Result<bool> {
    if !path.starts_with(ROOT) || path.split('/').any(|c| c == "..") {
        return Err(invalid("volume mount outside the volume store"));
    }
    let bind = flags & libc::MS_BIND != 0;
    if bind {
        if kind != "none" && !kind.is_empty() {
            return Err(invalid(&format!("bind volume cannot specify filesystem type {kind:?}")));
        }
        if flags & !ALLOWED_BIND_FLAGS != 0 {
            return Err(invalid(&format!("disallowed bind volume mount flags 0x{flags:x}")));
        }
        if !device.starts_with('/') || device.split('/').any(|c| c == "..") {
            return Err(invalid(&format!("invalid bind volume device path {device:?}")));
        }
        if !host_process && is_vm_share_ancestor(device) {
            return Err(invalid(&format!("bind volume device {device:?} exposes protected VM mount hierarchy")));
        }
    } else {
        if !ALLOWED_FS_TYPES.contains(&kind) {
            return Err(invalid(&format!("unsupported volume filesystem type {kind:?}")));
        }
        if flags & !ALLOWED_FS_FLAGS != 0 {
            return Err(invalid(&format!("disallowed volume mount flags 0x{flags:x}")));
        }
    }
    Ok(bind)
}

/// In VM mode, binding `/` or `/mnt` recursively (`MS_REC`) would expose
/// `/mnt/mac` and `/var/lib/kiri` past the macOS share guard.
pub(super) fn is_vm_share_ancestor(path: &str) -> bool {
    let trimmed = path.trim_end_matches('/');
    matches!(trimmed, "" | "/mnt" | "/mnt/mac")
}

/// Mounts the volume at `path` unless something already is: `kind` is the
/// filesystem (`none` for a bind), `flags_hex` and `data` are `o` split as
/// mount(2) takes it. Errors read as Docker's.
pub fn ensure(path: &str, kind: &str, device: &str, flags_hex: &str, data: &str) -> io::Result<()> {
    let flags = u64::from_str_radix(flags_hex, 16).map_err(|_| invalid("bad volume mount flags"))? as libc::c_ulong;
    let bind = validate_mount(path, kind, device, flags, super::transport::is_host_process())?;
    if mounted(path) {
        return Ok(());
    }
    let fail = |msg: String| io::Error::other(format!("error while mounting volume '{path}': {msg}"));
    if kind.starts_with("nfs") {
        // The daemon resolved the server; one it could not is reported here,
        // at start, as Docker does.
        if let Some(addr) = data.split(',').find_map(|w| w.strip_prefix("addr=")) {
            if addr.parse::<std::net::IpAddr>().is_err() {
                return Err(fail(format!("error resolving passed in network volume address: lookup {addr}: no such host")));
            }
        }
    }
    let c = |s: &str| CString::new(s).map_err(|_| invalid("volume option contains NUL"));
    let (src, target, fstype) = (c(device)?, c(path)?, c(if bind { "none" } else { kind })?);
    let data_c = c(data)?;
    let mount = |flags: libc::c_ulong, data: Option<&CString>| {
        // SAFETY: valid NUL-terminated strings, or null for no data.
        let r = unsafe { libc::mount(src.as_ptr(), target.as_ptr(), fstype.as_ptr(), flags, data.map_or(std::ptr::null(), |d| d.as_ptr().cast())) };
        if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
    };
    let result = if bind {
        // A bind takes no other flags at first; attributes such as ro/nosuid/nodev/noexec are applied by remount.
        let remount_attrs = flags & BIND_REMOUNT_ATTRS;
        mount(flags & (libc::MS_BIND | libc::MS_REC), None).and_then(|()| {
            if remount_attrs != 0 {
                mount(libc::MS_BIND | libc::MS_REMOUNT | remount_attrs | (flags & libc::MS_REC), None)
            } else {
                Ok(())
            }
        })
    } else {
        // Enforce MS_NOSUID | MS_NODEV on network/tmpfs volumes for defense in depth.
        mount(flags | libc::MS_NOSUID | libc::MS_NODEV, (!data.is_empty()).then_some(&data_c))
    };
    result.map_err(|e| {
        // As Docker's mount error: `mount src:target, flags: 0x…, data: …: errno`,
        // with any password hidden.
        let mut msg = format!("failed to mount local volume: mount {device}:{path}");
        if flags != 0 {
            msg.push_str(&format!(", flags: 0x{flags:x}"));
        }
        if !data.is_empty() {
            msg.push_str(&format!(", data: {}", hide_password(data)));
        }
        msg.push_str(&format!(": {}", super::hostopts::errno_text(&e)));
        io::Error::new(e.kind(), format!("error while mounting volume '{path}': {msg}"))
    })
}

fn hide_password(data: &str) -> String {
    data.split(',').map(|w| if w.starts_with("password=") { "password=********" } else { w }).collect::<Vec<_>>().join(",")
}

/// Unmounts `path` synchronously first (with short retries on `EBUSY` while a
/// stopped container's mount namespace tears down) so loopback ext4 flushes
/// and `LO_FLAGS_AUTOCLEAR` detaches before deletion; falls back to lazy
/// unmount (`MNT_DETACH`) if still busy.
fn unmount_clean(path: &str) -> bool {
    let target = Path::new(path);
    for _ in 0..16 {
        if !mounted(path) {
            return true;
        }
        let mut unmounted = false;
        for attempt in 0..10 {
            match super::sys::umount(target) {
                Ok(()) => {
                    unmounted = true;
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::ResourceBusy && attempt < 9 => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
        if !unmounted && super::sys::umount_lazy(target).is_err() {
            break;
        }
    }
    !mounted(path)
}

/// Releases one container's hold on a loopback volume mount and unmounts it
/// cleanly once no running containers still hold it.
pub fn release_loop(path: &str) {
    let last = loop_refs().lock().unwrap_or_else(|e| e.into_inner()).release(path);
    if last {
        let _ = unmount_clean(path);
    }
}

/// Unmounts the `kiri-k8s` loopback ext4 image if mounted on agent startup or
/// shutdown sweep so no orphaned loop mount stays active on the Linux host.
pub fn release_k8s_ext4_if_mounted() {
    let data = Path::new(K8S_VOLUME_DATA);
    let Some(img) = k8s_ext4_image_path(data) else { return };
    if img.exists() && mounted(K8S_VOLUME_DATA) {
        loop_refs().lock().unwrap_or_else(|e| e.into_inner()).clear(K8S_VOLUME_DATA);
        let _ = unmount_clean(K8S_VOLUME_DATA);
    }
}

/// Unmounts whatever is mounted at a volume's path before its data is
/// deleted, so removing a volume never deletes the NFS export or the host
/// folder behind it, and a loopback ext4 volume detaches without `EBUSY`.
/// False if something is still mounted there.
pub fn release(path: &str) -> bool {
    loop_refs().lock().unwrap_or_else(|e| e.into_inner()).clear(path);
    unmount_clean(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_stay_out_of_errors() {
        assert_eq!(hide_password("username=u,password=secret,vers=3.0"), "username=u,password=********,vers=3.0");
    }

    #[test]
    fn only_inside_the_volume_store() {
        assert!(ensure("/etc", "tmpfs", "tmpfs", "0", "").is_err());
        assert!(ensure("/var/lib/kiri/volumes/../../etc/_data", "tmpfs", "tmpfs", "0", "").is_err());
    }

    #[test]
    fn volume_mount_validation_rejects_disallowed_fstypes_flags_and_devices() {
        let vol = "/var/lib/kiri/volumes/v1/_data";
        // Allowed non-bind fstypes.
        for kind in ["nfs", "nfs4", "cifs", "smb3", "tmpfs"] {
            assert!(!validate_mount(vol, kind, "src", libc::MS_RDONLY | libc::MS_NOATIME, false).unwrap(), "{kind}");
        }
        // Disallowed non-bind fstypes (SEC-D-04).
        for bad in ["overlay", "ext4", "devtmpfs", "proc", "sysfs", "virtiofs", "none", ""] {
            assert!(validate_mount(vol, bad, "src", 0, false).is_err(), "{bad:?}");
        }
        // Disallowed flags on non-bind mounts.
        assert!(validate_mount(vol, "tmpfs", "tmpfs", libc::MS_REMOUNT, false).is_err());
        assert!(validate_mount(vol, "tmpfs", "tmpfs", libc::MS_MOVE, false).is_err());
        // Bind volumes: valid under /mnt/mac/Users or host paths.
        assert!(validate_mount(vol, "none", "/mnt/mac/Users/alice/app", libc::MS_BIND | libc::MS_RDONLY, false).unwrap());
        assert!(validate_mount(vol, "none", "/srv/data", libc::MS_BIND | libc::MS_REC, true).unwrap());
        // Bind volumes: reject non-none fstype, relative/traversal device, disallowed flags, and VM share ancestors.
        assert!(validate_mount(vol, "overlay", "/tmp/a", libc::MS_BIND, true).is_err());
        assert!(validate_mount(vol, "none", "relative/path", libc::MS_BIND, true).is_err());
        assert!(validate_mount(vol, "none", "/mnt/mac/Users/..", libc::MS_BIND, false).is_err());
        assert!(validate_mount(vol, "none", "/", libc::MS_BIND | libc::MS_REC, false).is_err());
        assert!(validate_mount(vol, "none", "/mnt", libc::MS_BIND | libc::MS_REC, false).is_err());
        assert!(validate_mount(vol, "none", "/mnt/mac", libc::MS_BIND, false).is_err());
        assert!(validate_mount(vol, "none", "/tmp/a", libc::MS_BIND | libc::MS_REMOUNT, true).is_err());
    }

    #[test]
    fn k8s_ext4_paths_and_loop_info_layout() {
        assert!(is_k8s_volume_data("/var/lib/kiri/volumes/kiri-k8s/_data"));
        assert!(!is_k8s_volume_data("/var/lib/kiri/volumes/other/_data"));
        assert!(!is_k8s_volume_data("/var/lib/kiri/volumes/kiri-k8s/_data/sub"));
        assert!(!is_k8s_volume_data("/var/lib/kiri/volumes/kiri-k8s"));

        assert_eq!(
            k8s_ext4_image_path(Path::new("/var/lib/kiri/volumes/kiri-k8s/_data")),
            Some(PathBuf::from("/var/lib/kiri/volumes/kiri-k8s/ext4.img"))
        );
        assert_eq!(k8s_ext4_image_path(Path::new("/var/lib/kiri/volumes/kiri-k8s")), None);

        // Matches Linux struct loop_info64 ABI size across x86_64 and aarch64.
        assert_eq!(std::mem::size_of::<LoopInfo64>(), 232);

        let mut base = LoopInfo64::default();
        base.lo_flags = 1;
        let info = make_loop_info64(base, Path::new("/var/lib/kiri/volumes/kiri-k8s/ext4.img"));
        assert_eq!(info.lo_flags, 1 | LO_FLAGS_AUTOCLEAR);
        let name = std::ffi::CStr::from_bytes_until_nul(&info.lo_file_name).unwrap().to_str().unwrap();
        assert_eq!(name, "/var/lib/kiri/volumes/kiri-k8s/ext4.img");

        // Paths longer than LO_NAME_SIZE - 1 truncate cleanly and stay NUL-terminated.
        let long = format!("/{}", "a".repeat(120));
        let info_long = make_loop_info64(LoopInfo64::default(), Path::new(&long));
        assert_eq!(info_long.lo_file_name[LO_NAME_SIZE - 1], 0);
        let trunc = std::ffi::CStr::from_bytes_until_nul(&info_long.lo_file_name).unwrap().to_str().unwrap();
        assert_eq!(trunc.len(), LO_NAME_SIZE - 1);
    }

    #[test]
    fn sparse_file_and_ext4_superblock_detection() {
        let dir = std::env::temp_dir().join(format!("kiri-volmount-sparse-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let img = dir.join("ext4.img");
        let size = 4 << 20;
        create_sparse_file(&img, size).unwrap();
        let meta = fs::metadata(&img).unwrap();
        assert_eq!(meta.len(), size);
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert!(!has_ext4_superblock(&img).unwrap());

        // Write ext4 superblock magic 0xEF53 at 1024 + 0x38.
        let mut f = OpenOptions::new().write(true).open(&img).unwrap();
        f.seek(SeekFrom::Start(EXT4_SUPER_OFFSET + EXT4_SUPER_MAGIC_OFFSET)).unwrap();
        std::io::Write::write_all(&mut f, &EXT4_SUPER_MAGIC.to_le_bytes()).unwrap();
        drop(f);
        assert!(has_ext4_superblock(&img).unwrap());

        // Short / empty file is not ext4.
        let short = dir.join("short.img");
        fs::write(&short, b"tiny").unwrap();
        assert!(!has_ext4_superblock(&short).unwrap());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn finds_mkfs_ext4_or_mke2fs_and_builds_args() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kiri-volmount-mkfs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let sbin = dir.join("sbin");
        let usr_sbin = dir.join("usr_sbin");
        fs::create_dir_all(&sbin).unwrap();
        fs::create_dir_all(&usr_sbin).unwrap();

        assert_eq!(find_mkfs_ext4_in(&[&sbin], None), None);

        // Fallback to mke2fs when mkfs.ext4 is absent.
        let mke2fs = usr_sbin.join("mke2fs");
        fs::write(&mke2fs, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&mke2fs, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(find_mkfs_ext4_in(&[&sbin, &usr_sbin], None), Some((mke2fs.clone(), true)));

        // Non-executable mkfs.ext4 is ignored in favor of executable mke2fs.
        let nonexec = sbin.join("mkfs.ext4");
        fs::write(&nonexec, "not exec").unwrap();
        fs::set_permissions(&nonexec, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(find_mkfs_ext4_in(&[&sbin, &usr_sbin], None), Some((mke2fs.clone(), true)));

        // Executable mkfs.ext4 is preferred over mke2fs.
        fs::set_permissions(&nonexec, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(find_mkfs_ext4_in(&[&sbin, &usr_sbin], None), Some((nonexec.clone(), false)));

        let img = Path::new("/var/lib/kiri/volumes/kiri-k8s/ext4.img");
        let direct = mkfs_ext4_args(false, img);
        assert_eq!(direct.first().unwrap(), "-F");
        assert_eq!(direct.last().unwrap(), img.as_os_str());
        assert!(!direct.iter().any(|a| a == "-t"));

        let via_mke2fs = mkfs_ext4_args(true, img);
        assert_eq!(via_mke2fs[0], "-t");
        assert_eq!(via_mke2fs[1], "ext4");
        assert_eq!(via_mke2fs.last().unwrap(), img.as_os_str());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn loop_refs_and_mountinfo_matching() {
        let mut refs = LoopRefs::default();
        refs.acquire(K8S_VOLUME_DATA);
        refs.acquire(K8S_VOLUME_DATA);
        assert!(!refs.release(K8S_VOLUME_DATA), "still held by second container");
        assert!(refs.release(K8S_VOLUME_DATA), "last holder released -> unmount");
        assert!(refs.release(K8S_VOLUME_DATA), "idempotent once released");

        refs.acquire(K8S_VOLUME_DATA);
        refs.acquire(K8S_VOLUME_DATA);
        refs.clear(K8S_VOLUME_DATA);
        assert!(refs.release(K8S_VOLUME_DATA));

        let mi = "\
25 1 0:30 / / rw,relatime - zfs rpool/ROOT/ubuntu rw,xattr,posixacl
91 25 7:3 / /var/lib/kiri/volumes/kiri-k8s/_data rw,relatime - ext4 /dev/loop3 rw,noinit_itable
";
        assert!(mounted_in(mi, K8S_VOLUME_DATA));
        assert!(!mounted_in(mi, "/var/lib/kiri/volumes/kiri-k8s"));
    }
}
