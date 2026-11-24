//! Detection and actionable diagnostics when Kiri's Linux or WSL 2 storage
//! filesystem is mounted read-only (`ST_RDONLY`, `ro`, or ext4 `emergency_ro`
//! after an unclean shutdown or journal abort, #768).

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::path::Path;

/// Why a storage filesystem is read-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOnlyKind {
    /// Linux ext4 aborted its journal (`errors=remount-ro`) and added `emergency_ro`.
    EmergencyRo,
    /// Mounted read-only (`ro` / `ST_RDONLY`).
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

/// OpenZFS's `ZFS_SUPER_MAGIC` (`zpl_super.c`).
pub const ZFS_SUPER_MAGIC: i64 = 0x2fc1_2fc1;

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

/// Pure helper testing whether `osrelease` or WSL interop markers indicate WSL.
pub fn is_wsl_env(osrelease: &str, interop_exists: bool) -> bool {
    if interop_exists {
        return true;
    }
    let lower = osrelease.to_ascii_lowercase();
    lower.contains("microsoft") || lower.contains("wsl")
}

/// Actionable diagnostic message for a read-only storage filesystem on WSL 2 or Linux.
pub fn format_readonly_error(kind: ReadOnlyKind, wsl: bool) -> String {
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
    } else {
        match kind {
            ReadOnlyKind::EmergencyRo => {
                "Kiri's container storage filesystem (/var/lib/kiri) was remounted read-only by Linux (emergency_ro) after a filesystem error: check `dmesg` and run `fsck` to repair the filesystem, then restart Kiri.".to_owned()
            }
            ReadOnlyKind::ReadOnly => {
                "Kiri's container storage filesystem (/var/lib/kiri) is mounted read-only: check `dmesg` and mount options, or run `fsck` to repair the filesystem, then restart Kiri.".to_owned()
            }
        }
    }
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn is_statvfs_readonly(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else { return false };
    // SAFETY: `st` is plain zero-initialized data; `c` is a valid C string.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: statvfs writes into `st`.
    unsafe { libc::statvfs(c.as_ptr(), &mut st) == 0 && (st.f_flag as u64) & (libc::ST_RDONLY as u64) != 0 }
}

#[cfg(target_os = "linux")]
pub fn detect_path_readonly(path: &Path) -> Option<ReadOnlyKind> {
    let existing = path.ancestors().find(|p| !p.as_os_str().is_empty() && p.exists())?;
    let stat_ro = is_statvfs_readonly(existing);
    let canon = existing.canonicalize().ok();
    let targets = [canon.as_deref(), Some(existing)];
    let mut found: Option<ReadOnlyKind> = stat_ro.then_some(ReadOnlyKind::ReadOnly);
    if let Ok(mi) = std::fs::read_to_string("/proc/self/mountinfo") {
        for t in targets.into_iter().flatten() {
            if let Some(k) = mountinfo_readonly(&mi, t) {
                found = Some(found.map_or(k, |prev| prev.merge(k)));
            }
        }
    }
    if let Ok(pm) = std::fs::read_to_string("/proc/mounts") {
        for t in targets.into_iter().flatten() {
            if let Some(k) = proc_mounts_readonly(&pm, t) {
                found = Some(found.map_or(k, |prev| prev.merge(k)));
            }
        }
    }
    found
}

#[cfg(target_os = "linux")]
fn is_statfs_zfs(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else { return false };
    // SAFETY: `st` is plain zero-initialized data; `c` is a valid C string.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: statfs writes into `st`.
    unsafe { libc::statfs(c.as_ptr(), &mut st) == 0 && st.f_type as i64 == ZFS_SUPER_MAGIC }
}

#[cfg(target_os = "linux")]
pub fn detect_path_zfs(path: &Path) -> bool {
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

#[cfg(target_os = "linux")]
fn resolve_agent_path(store_root: Option<&Path>) -> std::path::PathBuf {
    let default_root = kiri_image::Store::os_default_root().ok();
    let owned_root;
    let root = match store_root {
        Some(r) => Some(r),
        None => {
            owned_root = kiri_image::Store::default_root().ok();
            owned_root.as_deref()
        }
    };
    match (root, default_root.as_deref()) {
        (Some(r), Some(def)) => super::storage::agent_dir(r, def).unwrap_or_else(|| std::path::PathBuf::from("/var/lib/kiri")),
        _ => std::path::PathBuf::from("/var/lib/kiri"),
    }
}

#[cfg(target_os = "linux")]
pub fn is_daemon_storage_zfs(store_root: Option<&Path>) -> bool {
    let volumes = resolve_agent_path(store_root).join("volumes");
    detect_path_zfs(&volumes)
}

#[cfg(not(target_os = "linux"))]
pub fn is_daemon_storage_zfs(_store_root: Option<&Path>) -> bool {
    false
}

#[cfg(target_os = "linux")]
pub fn check_daemon_storage(store_root: Option<&Path>) -> Option<String> {
    let owned_root;
    let root = match store_root {
        Some(r) => Some(r),
        None => {
            owned_root = kiri_image::Store::default_root().ok();
            owned_root.as_deref()
        }
    };
    let agent_path = resolve_agent_path(root);
    let state = super::state_dir().ok();
    let mut kind: Option<ReadOnlyKind> = None;
    for p in [Some(agent_path.as_path()), root, state.as_deref()].into_iter().flatten() {
        if let Some(k) = detect_path_readonly(p) {
            kind = Some(kind.map_or(k, |prev| prev.merge(k)));
        }
    }
    kind.map(|k| format_readonly_error(k, is_wsl()))
}

#[cfg(not(target_os = "linux"))]
pub fn check_daemon_storage(_store_root: Option<&Path>) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_mounts_emergency_ro_and_ro_without_false_matching_remount_ro() {
        // Healthy WSL 2 ext4 mount with errors=remount-ro must NOT be flagged read-only.
        let healthy = "\
/dev/sdd / ext4 rw,relatime,discard,errors=remount-ro,data=ordered 0 0
tmpfs /run tmpfs rw,nosuid,nodev,mode=755 0 0
";
        assert_eq!(proc_mounts_readonly(healthy, Path::new("/var/lib/kiri")), None);
        assert_eq!(proc_mounts_readonly(healthy, Path::new("/")), None);

        // Issue #768 exact /proc/mounts state: VFS mount flag still says `rw`, ext4 superblock added `emergency_ro`.
        let emergency = "\
/dev/sdd / ext4 rw,relatime,discard,errors=remount-ro,data=ordered,emergency_ro 0 0
tmpfs /run tmpfs rw,nosuid,nodev,mode=755 0 0
";
        assert_eq!(proc_mounts_readonly(emergency, Path::new("/var/lib/kiri")), Some(ReadOnlyKind::EmergencyRo));
        assert_eq!(proc_mounts_readonly(emergency, Path::new("/var/lib/kiri/containers/abc")), Some(ReadOnlyKind::EmergencyRo));
        // /run is a separate writable tmpfs mount, so /run/kiri is NOT read-only.
        assert_eq!(proc_mounts_readonly(emergency, Path::new("/run/kiri")), None);

        // Separate /var/lib/kiri mounted `ro` while `/` is `rw`, plus space-escaped paths and overmounts.
        let separate_ro = "\
/dev/sda1 / ext4 rw,relatime 0 0
/dev/sdb1 /var/lib/kiri ext4 ro,relatime 0 0
/dev/sdc1 /mnt/data\\040disk ext4 rw,relatime 0 0
/dev/sdc1 /mnt/data\\040disk ext4 ro,relatime 0 0
";
        assert_eq!(proc_mounts_readonly(separate_ro, Path::new("/var/lib/kiri/containers/123")), Some(ReadOnlyKind::ReadOnly));
        assert_eq!(proc_mounts_readonly(separate_ro, Path::new("/var/lib/kiri2")), None);
        assert_eq!(proc_mounts_readonly(separate_ro, Path::new("/mnt/data disk/kiri")), Some(ReadOnlyKind::ReadOnly));
    }

    #[test]
    fn parses_mountinfo_superblock_emergency_ro_and_overmounts() {
        let mountinfo = "\
25 1 8:48 / / rw,relatime - ext4 /dev/sdd rw,discard,errors=remount-ro,data=ordered,emergency_ro
26 25 0:24 / /run rw,nosuid,nodev - tmpfs tmpfs rw,mode=755
40 25 0:55 / /var/lib/kiri/containers/c1/rootfs ro,relatime - overlay overlay ro,lowerdir=abc,upperdir=/var/lib/kiri/containers/c1/upper,workdir=/var/lib/kiri/containers/c1/work,index=off
";
        assert_eq!(mountinfo_readonly(mountinfo, Path::new("/var/lib/kiri/containers/c1")), Some(ReadOnlyKind::EmergencyRo));
        assert_eq!(mountinfo_readonly(mountinfo, Path::new("/var/lib/kiri/containers/c1/rootfs")), Some(ReadOnlyKind::ReadOnly));
        assert_eq!(mountinfo_readonly(mountinfo, Path::new("/run/kiri")), None);
    }

    #[test]
    fn detects_wsl_from_interop_or_kernel_release_and_formats_recovery_steps() {
        assert!(is_wsl_env("6.6.87.2-microsoft-standard-WSL2\n", false));
        // Custom WSL kernel without "microsoft" in osrelease (as in #768: 6.18.58.1-1) detected via WSLInterop.
        assert!(is_wsl_env("6.18.58.1-1\n", true));
        assert!(!is_wsl_env("6.18.58.1-1-generic\n", false));

        let wsl_msg = format_readonly_error(ReadOnlyKind::EmergencyRo, true);
        assert!(wsl_msg.contains("ext4.vhdx") && wsl_msg.contains("emergency_ro"), "{wsl_msg}");
        assert!(wsl_msg.contains("wsl --shutdown") && wsl_msg.contains("wsl --mount") && wsl_msg.contains("e2fsck -f -y -D"), "{wsl_msg}");
        assert!(wsl_msg.contains("Settings -> Storage"), "{wsl_msg}");

        let linux_msg = format_readonly_error(ReadOnlyKind::EmergencyRo, false);
        assert!(linux_msg.contains("/var/lib/kiri") && linux_msg.contains("emergency_ro") && linux_msg.contains("dmesg") && linux_msg.contains("fsck"), "{linux_msg}");
    }

    #[test]
    fn parses_mountinfo_zfs_and_loopback_ext4_overmounts() {
        let zfs_root = "\
25 1 0:30 / / rw,relatime shared:1 - zfs rpool/ROOT/ubuntu_wuq1tk rw,xattr,posixacl,casesensitive
26 25 0:31 / /var/lib rw,relatime shared:2 - zfs rpool/ROOT/ubuntu_wuq1tk/var/lib rw,xattr,posixacl,casesensitive
91 26 7:3 / /var/lib/kiri/volumes/kiri-k8s/_data rw,relatime - ext4 /dev/loop3 rw,noinit_itable
92 25 0:40 / /mnt/zfs\\040pool rw,relatime - zfs tank/pool rw,xattr,posixacl
";
        assert_eq!(mountinfo_fstype(zfs_root, Path::new("/var/lib/kiri/volumes")), Some("zfs"));
        assert!(is_zfs_mountinfo(zfs_root, Path::new("/var/lib/kiri/volumes")));
        assert!(is_zfs_mountinfo(zfs_root, Path::new("/var/lib/kiri/volumes/kiri-k8s")));
        assert!(is_zfs_mountinfo(zfs_root, Path::new("/mnt/zfs pool/kiri/volumes")));
        // Loopback ext4 overmounted onto kiri-k8s/_data wins over parent ZFS dataset.
        assert_eq!(mountinfo_fstype(zfs_root, Path::new("/var/lib/kiri/volumes/kiri-k8s/_data")), Some("ext4"));
        assert!(!is_zfs_mountinfo(zfs_root, Path::new("/var/lib/kiri/volumes/kiri-k8s/_data")));

        let ext4_root = "25 1 8:1 / / rw,relatime - ext4 /dev/nvme0n1p2 rw\n";
        assert_eq!(mountinfo_fstype(ext4_root, Path::new("/var/lib/kiri/volumes")), Some("ext4"));
        assert!(!is_zfs_mountinfo(ext4_root, Path::new("/var/lib/kiri/volumes")));
    }
}
