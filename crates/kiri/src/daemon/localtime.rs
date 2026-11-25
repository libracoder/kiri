//! Ensures `/etc/localtime` (and `/etc/timezone`) is a valid timezone file or
//! symlink rather than missing or an empty directory (#938).
//!
//! Pre-0.2.3 Kiri WSL distros were built from Alpine minirootfs without
//! `tzdata`, so `/etc/localtime` did not exist and `-v /etc/localtime:...`
//! created an empty directory there. On WSL startup and before host bind mounts
//! of `/etc/localtime` or `/etc/timezone`, this module heals empty directories
//! (never non-empty directories) and creates either a symlink into
//! `/usr/share/zoneinfo` or a canonical RFC 8536 `TZif2` UTC binary.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Canonical RFC 8536 `TZif2` binary for UTC (`UTC0`), 114 bytes:
/// v1 header (44 B) + v1 data (10 B) + v2 header (44 B) + v2 data (10 B) +
/// POSIX TZ footer (`\nUTC0\n`, 6 B).
pub const UTC_TZIF2: [u8; 114] = [
    // V1 header (44 bytes): magic "TZif", version '2', 15 reserved zero bytes,
    // isutcnt=0, isstdcnt=0, leapcnt=0, timecnt=0, typecnt=1, charcnt=4.
    b'T', b'Z', b'i', b'f', b'2',
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, // isutcnt = 0
    0, 0, 0, 0, // isstdcnt = 0
    0, 0, 0, 0, // leapcnt = 0
    0, 0, 0, 0, // timecnt = 0
    0, 0, 0, 1, // typecnt = 1
    0, 0, 0, 4, // charcnt = 4
    // V1 data (10 bytes): ttinfo(utoff=0, isdst=0, idx=0) + "UTC\0"
    0, 0, 0, 0, 0, 0,
    b'U', b'T', b'C', 0,
    // V2 header (44 bytes): identical counts
    b'T', b'Z', b'i', b'f', b'2',
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, // isutcnt = 0
    0, 0, 0, 0, // isstdcnt = 0
    0, 0, 0, 0, // leapcnt = 0
    0, 0, 0, 0, // timecnt = 0
    0, 0, 0, 1, // typecnt = 1
    0, 0, 0, 4, // charcnt = 4
    // V2 data (10 bytes): ttinfo(utoff=0, isdst=0, idx=0) + "UTC\0"
    0, 0, 0, 0, 0, 0,
    b'U', b'T', b'C', 0,
    // POSIX TZ footer (6 bytes): "\nUTC0\n"
    b'\n', b'U', b'T', b'C', b'0', b'\n',
];

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Strict validation for relative IANA zone names from `TZ` (e.g.
/// `"Asia/Shanghai"`, `"America/New_York"`, `"Etc/GMT+5"`): non-empty, no
/// leading or trailing `/`, no `.` or `..` components, no `\` or `\0`, and
/// only ASCII `[A-Za-z0-9_+.-/]`.
pub fn valid_tz_name(tz: &str) -> bool {
    if tz.is_empty() || tz.len() > 255 || tz.starts_with('/') || tz.ends_with('/') {
        return false;
    }
    if !tz.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'+' | b'-' | b'.' | b'/')) {
        return false;
    }
    tz.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

/// Checks whether `path` (interpreted within `root`) is a non-empty regular
/// file or a symlink whose target stays confined to `<root>/usr/share/zoneinfo`
/// (or `<root>/etc`) and resolves to a non-empty regular file.
pub fn is_valid_timezone_file_at(root: &Path, path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    let ft = meta.file_type();
    if ft.is_file() {
        return meta.len() > 0;
    }
    if ft.is_symlink() {
        let zinfo = root.join("usr/share/zoneinfo");
        let etc = root.join("etc");
        return resolve_confined_file(root, &[zinfo.as_path(), etc.as_path()], path);
    }
    false
}

/// Lexically normalizes `rel` beneath `root`, returning `None` if `..` would
/// escape above `root`.
fn join_confined(root: &Path, rel: &Path) -> Option<PathBuf> {
    use std::path::Component;
    let mut stack: Vec<std::ffi::OsString> = Vec::new();
    for c in rel.components() {
        match c {
            Component::Normal(p) => stack.push(p.to_owned()),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                stack.pop()?;
            }
        }
    }
    let mut out = root.to_path_buf();
    for s in stack {
        out.push(s);
    }
    Some(out)
}

/// Resolves symlinks starting at `path` within `root` and returns true iff the
/// final target is a non-empty regular file whose canonical path sits inside
/// one of `allowed_bases`.
fn resolve_confined_file(root: &Path, allowed_bases: &[&Path], path: &Path) -> bool {
    let canon_root = fs::canonicalize(root).ok();
    let Some(canon_root_ref) = canon_root.as_deref() else {
        return false;
    };
    let mut cur = path.to_path_buf();
    for _ in 0..16 {
        let Ok(meta) = fs::symlink_metadata(&cur) else {
            return false;
        };
        let ft = meta.file_type();
        if !ft.is_symlink() {
            if !ft.is_file() || meta.len() == 0 {
                return false;
            }
            let Ok(canon_target) = fs::canonicalize(&cur) else {
                return false;
            };
            if !canon_target.starts_with(canon_root_ref) {
                return false;
            }
            return allowed_bases.iter().any(|base| {
                fs::canonicalize(base).is_ok_and(|cb| canon_target.starts_with(&cb))
            });
        }
        let Ok(target) = fs::read_link(&cur) else {
            return false;
        };
        let next = if target.is_absolute() {
            if root != Path::new("/") && target.starts_with(root) {
                let rel = target.strip_prefix(root).unwrap_or(&target);
                join_confined(root, rel)
            } else {
                let rel = target.strip_prefix("/").unwrap_or(&target);
                join_confined(root, rel)
            }
        } else {
            let Some(parent_rel) = cur.parent().and_then(|p| p.strip_prefix(root).ok()) else {
                return false;
            };
            let combined = parent_rel.join(target);
            join_confined(root, &combined)
        };
        let Some(n) = next else {
            return false;
        };
        cur = n;
    }
    false
}

fn resolve_symlink_is_file(root: &Path, path: &Path) -> bool {
    let zinfo = root.join("usr/share/zoneinfo");
    let etc = root.join("etc");
    resolve_confined_file(root, &[zinfo.as_path(), etc.as_path()], path)
}

fn zoneinfo_file_exists(root: &Path, tz: &str) -> bool {
    let zinfo = root.join("usr/share/zoneinfo");
    let Some(candidate) = join_confined(&zinfo, Path::new(tz)) else {
        return false;
    };
    resolve_confined_file(root, &[zinfo.as_path()], &candidate)
}

fn temp_path_in(dir: &Path, prefix: &str) -> PathBuf {
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    dir.join(format!(".{prefix}.kiri.{}.{seq}.tmp", std::process::id()))
}

fn atomic_write_file(dest: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = dest.parent().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(dir)?;
    let tmp = temp_path_in(dir, dest.file_name().and_then(|n| n.to_str()).unwrap_or("tz"));
    let write_res = (|| -> io::Result<()> {
        let mut f = OpenOptions::new().write(true).create_new(true).mode(0o644).open(&tmp)?;
        f.write_all(bytes)?;
        f.set_permissions(fs::Permissions::from_mode(0o644))?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_res {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp, dest) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

fn atomic_symlink(target: &str, dest: &Path) -> io::Result<()> {
    let dir = dest.parent().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(dir)?;
    let tmp = temp_path_in(dir, dest.file_name().and_then(|n| n.to_str()).unwrap_or("tz"));
    symlink(target, &tmp)?;
    if let Err(e) = fs::rename(&tmp, dest) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Writes `<zone>\n` to `<root>/etc/timezone` if it is missing (or an empty
/// directory). Never overwrites an existing valid file or non-empty directory.
fn write_timezone_if_missing(root: &Path, zone: &str) {
    let tz_path = root.join("etc/timezone");
    match fs::symlink_metadata(&tz_path) {
        Ok(meta) if meta.file_type().is_dir() => {
            // Only remove an empty directory; never remove_dir_all.
            if fs::remove_dir(&tz_path).is_err() {
                return;
            }
        }
        Ok(meta) if meta.file_type().is_file() && meta.len() > 0 => return,
        Ok(meta) if meta.file_type().is_symlink() && resolve_symlink_is_file(root, &tz_path) => return,
        Ok(meta) if !meta.file_type().is_file() && !meta.file_type().is_symlink() => return,
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return,
    }
    let _ = atomic_write_file(&tz_path, format!("{zone}\n").as_bytes());
}

/// Ensures `/etc/localtime` on the live root (`/`) is a valid file or symlink.
pub fn ensure_localtime() -> io::Result<()> {
    let tz = std::env::var("TZ").ok();
    ensure_localtime_at(Path::new("/"), tz.as_deref())
}

/// Ensures `<root>/etc/localtime` is a valid timezone file or symlink:
/// 1. If `<root>/etc/localtime` is a directory, removes it ONLY if empty
///    (`remove_dir`, never `remove_dir_all`).
/// 2. If it is already a non-empty regular file or a symlink resolving to a
///    regular file, leaves it untouched.
/// 3. If missing, empty file, or broken symlink:
///    - If `tz_env` is a valid relative zone name and
///      `<root>/usr/share/zoneinfo/<tz>` is a regular file, symlinks
///      `/etc/localtime` -> `/usr/share/zoneinfo/<tz>` and writes `<tz>\n` to
///      `<root>/etc/timezone` if missing.
///    - Else if `<root>/usr/share/zoneinfo/Etc/UTC` is a regular file, symlinks
///      `/etc/localtime` -> `/usr/share/zoneinfo/Etc/UTC` and writes `Etc/UTC\n`
///      to `<root>/etc/timezone` if missing.
///    - Else atomically writes canonical RFC 8536 `UTC_TZIF2` (`0644`) to
///      `<root>/etc/localtime` and writes `UTC\n` to `<root>/etc/timezone` if
///      missing.
pub fn ensure_localtime_at(root: &Path, tz_env: Option<&str>) -> io::Result<()> {
    let localtime = root.join("etc/localtime");
    match fs::symlink_metadata(&localtime) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_dir() {
                // ONLY removes an empty directory; non-empty directories return an error.
                match fs::remove_dir(&localtime) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
            } else if ft.is_file() {
                if meta.len() > 0 {
                    return Ok(());
                }
            } else if ft.is_symlink() {
                if resolve_symlink_is_file(root, &localtime) {
                    return Ok(());
                }
            } else {
                return Err(io::Error::other(format!(
                    "{} is not a regular file, symlink, or empty directory",
                    localtime.display()
                )));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    if let Some(tz) = tz_env.filter(|tz| valid_tz_name(tz))
        && zoneinfo_file_exists(root, tz)
    {
        atomic_symlink(&format!("/usr/share/zoneinfo/{tz}"), &localtime)?;
        write_timezone_if_missing(root, tz);
        return Ok(());
    }

    if zoneinfo_file_exists(root, "Etc/UTC") {
        atomic_symlink("/usr/share/zoneinfo/Etc/UTC", &localtime)?;
        write_timezone_if_missing(root, "Etc/UTC");
        return Ok(());
    }

    atomic_write_file(&localtime, &UTC_TZIF2)?;
    write_timezone_if_missing(root, "UTC");
    Ok(())
}

/// Ensures `/etc/timezone` on the live root (`/`) is a valid file or symlink.
pub fn ensure_timezone() -> io::Result<()> {
    let tz = std::env::var("TZ").ok();
    ensure_timezone_at(Path::new("/"), tz.as_deref())
}

/// Ensures `<root>/etc/timezone` is a valid timezone name file (never a
/// directory), refusing to delete a non-empty directory.
pub fn ensure_timezone_at(root: &Path, tz_env: Option<&str>) -> io::Result<()> {
    let tz_path = root.join("etc/timezone");
    match fs::symlink_metadata(&tz_path) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_dir() {
                match fs::remove_dir(&tz_path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
            } else if ft.is_file() {
                if meta.len() > 0 {
                    return Ok(());
                }
            } else if ft.is_symlink() {
                if resolve_symlink_is_file(root, &tz_path) {
                    return Ok(());
                }
            } else {
                return Err(io::Error::other(format!(
                    "{} is not a regular file, symlink, or empty directory",
                    tz_path.display()
                )));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let inferred = fs::read_link(root.join("etc/localtime"))
        .ok()
        .and_then(|p| p.to_str().map(str::to_owned))
        .and_then(|s| s.split_once("zoneinfo/").map(|(_, z)| z.to_owned()))
        .filter(|z| valid_tz_name(z));
    let zone = inferred
        .as_deref()
        .or_else(|| tz_env.filter(|tz| valid_tz_name(tz)))
        .unwrap_or("UTC");
    atomic_write_file(&tz_path, format!("{zone}\n").as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root(name: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("kiri-localtime-{name}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("etc")).unwrap();
        dir
    }

    /// Minimal RFC 8536 TZif2 parser check verifying header counts, v1/v2 data
    /// block framing, UTC designation, and POSIX TZ footer.
    fn assert_valid_utc_tzif2(bytes: &[u8]) {
        assert_eq!(bytes.len(), 114, "canonical UTC TZif2 is 114 bytes");
        assert!(bytes.starts_with(b"TZif2"), "must start with TZif2 magic");
        assert!(bytes.ends_with(b"\nUTC0\n"), "must end with POSIX UTC0 footer");
        let be_u32 = |off: usize| u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap());
        // Verify both v1 (offset 0) and v2 (offset 54) sections.
        for base in [0usize, 54usize] {
            assert_eq!(&bytes[base..base + 5], b"TZif2");
            assert_eq!(&bytes[base + 5..base + 20], &[0u8; 15]);
            assert_eq!(be_u32(base + 20), 0, "isutcnt");
            assert_eq!(be_u32(base + 24), 0, "isstdcnt");
            assert_eq!(be_u32(base + 28), 0, "leapcnt");
            assert_eq!(be_u32(base + 32), 0, "timecnt");
            assert_eq!(be_u32(base + 36), 1, "typecnt");
            assert_eq!(be_u32(base + 40), 4, "charcnt");
            // Local time type record: utoff=0, isdst=0, desigidx=0
            assert_eq!(&bytes[base + 44..base + 50], &[0u8; 6]);
            // Abbreviation string table: "UTC\0"
            assert_eq!(&bytes[base + 50..base + 54], b"UTC\0");
        }
        assert_eq!(&bytes[108..114], b"\nUTC0\n");
    }

    #[test]
    fn repairs_empty_localtime_directory_into_valid_tzif2_file() {
        let root = test_root("empty-dir");
        let lt = root.join("etc/localtime");
        fs::create_dir(&lt).unwrap();
        assert!(fs::symlink_metadata(&lt).unwrap().file_type().is_dir());

        ensure_localtime_at(&root, None).unwrap();

        let meta = fs::symlink_metadata(&lt).unwrap();
        assert!(meta.file_type().is_file(), "repaired /etc/localtime must be a regular file");
        assert_eq!(meta.permissions().mode() & 0o777, 0o644);
        let bytes = fs::read(&lt).unwrap();
        assert_valid_utc_tzif2(&bytes);
        assert_eq!(fs::read_to_string(root.join("etc/timezone")).unwrap(), "UTC\n");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn refuses_to_delete_non_empty_localtime_directory() {
        let root = test_root("non-empty-dir");
        let lt = root.join("etc/localtime");
        fs::create_dir(&lt).unwrap();
        let keep = lt.join("sentinel.txt");
        fs::write(&keep, b"do-not-delete").unwrap();

        let err = ensure_localtime_at(&root, None).expect_err("non-empty directory must not be removed");
        assert!(lt.is_dir(), "directory must remain intact after error ({err})");
        assert_eq!(fs::read(&keep).unwrap(), b"do-not-delete");

        // Same safety invariant for /etc/timezone.
        let tz = root.join("etc/timezone");
        fs::create_dir(&tz).unwrap();
        let keep_tz = tz.join("keep");
        fs::write(&keep_tz, b"safe").unwrap();
        assert!(ensure_timezone_at(&root, None).is_err());
        assert_eq!(fs::read(&keep_tz).unwrap(), b"safe");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn preserves_existing_valid_localtime_file_and_symlink() {
        let root = test_root("preserve");
        let lt = root.join("etc/localtime");
        let custom = b"TZif2-custom-existing-file";
        fs::write(&lt, custom).unwrap();

        // Even with TZ pointing to a valid zoneinfo file, existing valid file is untouched.
        let shanghai = root.join("usr/share/zoneinfo/Asia/Shanghai");
        fs::create_dir_all(shanghai.parent().unwrap()).unwrap();
        fs::write(&shanghai, &UTC_TZIF2).unwrap();
        ensure_localtime_at(&root, Some("Asia/Shanghai")).unwrap();
        assert!(fs::symlink_metadata(&lt).unwrap().file_type().is_file());
        assert_eq!(fs::read(&lt).unwrap(), custom);
        assert!(!root.join("etc/timezone").exists(), "should not touch /etc/timezone when /etc/localtime is already valid");

        // Valid symlink resolving inside root is also preserved untouched.
        fs::remove_file(&lt).unwrap();
        let ny = root.join("usr/share/zoneinfo/America/New_York");
        fs::create_dir_all(ny.parent().unwrap()).unwrap();
        fs::write(&ny, &UTC_TZIF2).unwrap();
        symlink("/usr/share/zoneinfo/America/New_York", &lt).unwrap();
        ensure_localtime_at(&root, Some("Asia/Shanghai")).unwrap();
        assert_eq!(fs::read_link(&lt).unwrap(), Path::new("/usr/share/zoneinfo/America/New_York"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn links_valid_tz_env_and_rejects_path_traversal() {
        let root = test_root("tz-env");
        let shanghai = root.join("usr/share/zoneinfo/Asia/Shanghai");
        fs::create_dir_all(shanghai.parent().unwrap()).unwrap();
        fs::write(&shanghai, &UTC_TZIF2).unwrap();
        let utc = root.join("usr/share/zoneinfo/Etc/UTC");
        fs::create_dir_all(utc.parent().unwrap()).unwrap();
        fs::write(&utc, &UTC_TZIF2).unwrap();

        // Valid TZ links to /usr/share/zoneinfo/<TZ> and populates /etc/timezone.
        ensure_localtime_at(&root, Some("Asia/Shanghai")).unwrap();
        assert_eq!(fs::read_link(root.join("etc/localtime")).unwrap(), Path::new("/usr/share/zoneinfo/Asia/Shanghai"));
        assert_eq!(fs::read_to_string(root.join("etc/timezone")).unwrap(), "Asia/Shanghai\n");

        // Reject path-traversal and invalid TZ strings; fall back to Etc/UTC.
        for bad in [
            "../etc/shadow",
            "/etc/passwd",
            "Asia/../../etc/passwd",
            "",
            ".",
            "..",
            "Asia/",
            "Asia//Shanghai",
            "Asia\\Shanghai",
            "Asia/Shanghai\0",
            "Asia/Shanghai\n",
            ":Asia/Shanghai",
        ] {
            assert!(!valid_tz_name(bad), "{bad:?} must be rejected");
            let _ = fs::remove_file(root.join("etc/localtime"));
            let _ = fs::remove_file(root.join("etc/timezone"));
            ensure_localtime_at(&root, Some(bad)).unwrap();
            assert_eq!(
                fs::read_link(root.join("etc/localtime")).unwrap(),
                Path::new("/usr/share/zoneinfo/Etc/UTC"),
                "bad TZ {bad:?} must fall back to Etc/UTC"
            );
            assert_eq!(fs::read_to_string(root.join("etc/timezone")).unwrap(), "Etc/UTC\n");
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn replaces_broken_symlink_and_empty_file() {
        let root = test_root("broken-link");
        let lt = root.join("etc/localtime");

        // Dangling symlink pointing to /usr/share/zoneinfo/Etc/UTC when root has no zoneinfo.
        symlink("/usr/share/zoneinfo/Etc/UTC", &lt).unwrap();
        ensure_localtime_at(&root, None).unwrap();
        assert!(fs::symlink_metadata(&lt).unwrap().file_type().is_file());
        assert_valid_utc_tzif2(&fs::read(&lt).unwrap());

        // Symlink pointing to a directory is treated as broken.
        fs::remove_file(&lt).unwrap();
        fs::create_dir_all(root.join("usr/share/zoneinfo")).unwrap();
        symlink("/usr/share/zoneinfo", &lt).unwrap();
        ensure_localtime_at(&root, None).unwrap();
        assert!(fs::symlink_metadata(&lt).unwrap().file_type().is_file());
        assert_valid_utc_tzif2(&fs::read(&lt).unwrap());

        // 0-byte regular file is repaired into a valid TZif2 file.
        fs::write(&lt, b"").unwrap();
        ensure_localtime_at(&root, None).unwrap();
        assert_valid_utc_tzif2(&fs::read(&lt).unwrap());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ensures_timezone_file_and_infers_from_localtime_link() {
        let root = test_root("timezone");
        let berlin = root.join("usr/share/zoneinfo/Europe/Berlin");
        fs::create_dir_all(berlin.parent().unwrap()).unwrap();
        fs::write(&berlin, &UTC_TZIF2).unwrap();
        symlink("/usr/share/zoneinfo/Europe/Berlin", root.join("etc/localtime")).unwrap();
        fs::create_dir(root.join("etc/timezone")).unwrap();

        ensure_timezone_at(&root, None).unwrap();
        assert!(fs::symlink_metadata(root.join("etc/timezone")).unwrap().file_type().is_file());
        assert_eq!(fs::read_to_string(root.join("etc/timezone")).unwrap(), "Europe/Berlin\n");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_symlinks_escaping_zoneinfo_or_root() {
        let root = test_root("confined");
        let zinfo = root.join("usr/share/zoneinfo");
        fs::create_dir_all(&zinfo).unwrap();
        fs::create_dir_all(root.join("var/secret")).unwrap();
        fs::write(root.join("var/secret/token"), b"secret").unwrap();

        // A symlink inside zoneinfo escaping to /var/secret/token is rejected for TZ
        // and falls back to writing UTC_TZIF2 instead of linking to the secret file.
        symlink("../../../var/secret/token", zinfo.join("EvilZone")).unwrap();
        assert!(!super::zoneinfo_file_exists(&root, "EvilZone"));
        ensure_localtime_at(&root, Some("EvilZone")).unwrap();
        let lt = root.join("etc/localtime");
        assert!(fs::symlink_metadata(&lt).unwrap().file_type().is_file());
        assert_valid_utc_tzif2(&fs::read(&lt).unwrap());

        // An /etc/localtime symlink pointing outside /usr/share/zoneinfo and /etc is
        // rejected by is_valid_timezone_file_at and replaced on ensure_localtime_at.
        fs::remove_file(&lt).unwrap();
        symlink("/var/secret/token", &lt).unwrap();
        assert!(!is_valid_timezone_file_at(&root, &lt));
        ensure_localtime_at(&root, None).unwrap();
        assert!(fs::symlink_metadata(&lt).unwrap().file_type().is_file());
        assert_valid_utc_tzif2(&fs::read(&lt).unwrap());

        let _ = fs::remove_dir_all(&root);
    }
}
