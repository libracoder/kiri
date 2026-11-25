//! Ensures `/etc/localtime` (and `/etc/timezone`) is a valid timezone file or
//! symlink rather than missing or an empty directory (#938).
//!
//! Runs in `kiri-init` on WSL startup (self-healing upgraded pre-0.2.3 Kiri WSL
//! distros where Alpine minirootfs lacked `tzdata`) and guards `parse_mounts`
//! so bind-mount source creation never turns `/etc/localtime` or `/etc/timezone`
//! into a directory.

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

/// Strict validation for relative IANA zone names from `TZ`: non-empty, no
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

fn resolve_confined_file(root: &Path, allowed_bases: &[&Path], path: &Path) -> bool {
    let Ok(canon_root) = fs::canonicalize(root) else {
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
            if !canon_target.starts_with(&canon_root) {
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

fn write_timezone_if_missing(root: &Path, zone: &str) {
    let tz_path = root.join("etc/timezone");
    match fs::symlink_metadata(&tz_path) {
        Ok(meta) if meta.file_type().is_dir() => {
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

/// Ensures `/etc/localtime` on `/` is a valid timezone file or symlink.
pub fn ensure_localtime() -> io::Result<()> {
    let tz = std::env::var("TZ").ok();
    ensure_localtime_at(Path::new("/"), tz.as_deref())
}

/// Ensures `<root>/etc/localtime` is a valid timezone file or symlink.
pub fn ensure_localtime_at(root: &Path, tz_env: Option<&str>) -> io::Result<()> {
    let localtime = root.join("etc/localtime");
    match fs::symlink_metadata(&localtime) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_dir() {
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

/// Ensures `/etc/timezone` on `/` is a valid timezone name file.
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
        let dir = std::env::temp_dir().join(format!("kiri-init-localtime-{name}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("etc")).unwrap();
        dir
    }

    #[test]
    fn repairs_empty_dir_and_refuses_non_empty_dir() {
        let root = test_root("dir");
        let lt = root.join("etc/localtime");
        fs::create_dir(&lt).unwrap();
        ensure_localtime_at(&root, None).unwrap();
        let bytes = fs::read(&lt).unwrap();
        assert!(bytes.starts_with(b"TZif2"));
        assert!(bytes.ends_with(b"\nUTC0\n"));
        assert_eq!(bytes.len(), 114);
        assert_eq!(fs::read_to_string(root.join("etc/timezone")).unwrap(), "UTC\n");

        fs::remove_file(&lt).unwrap();
        fs::create_dir(&lt).unwrap();
        fs::write(lt.join("keep"), b"x").unwrap();
        assert!(ensure_localtime_at(&root, None).is_err());
        assert_eq!(fs::read(lt.join("keep")).unwrap(), b"x");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn preserves_valid_and_validates_tz() {
        let root = test_root("tz");
        let shanghai = root.join("usr/share/zoneinfo/Asia/Shanghai");
        fs::create_dir_all(shanghai.parent().unwrap()).unwrap();
        fs::write(&shanghai, &UTC_TZIF2).unwrap();

        ensure_localtime_at(&root, Some("../etc/shadow")).unwrap();
        assert!(fs::symlink_metadata(root.join("etc/localtime")).unwrap().file_type().is_file());

        fs::remove_file(root.join("etc/localtime")).unwrap();
        fs::remove_file(root.join("etc/timezone")).unwrap();
        ensure_localtime_at(&root, Some("Asia/Shanghai")).unwrap();
        assert_eq!(fs::read_link(root.join("etc/localtime")).unwrap(), Path::new("/usr/share/zoneinfo/Asia/Shanghai"));
        assert_eq!(fs::read_to_string(root.join("etc/timezone")).unwrap(), "Asia/Shanghai\n");

        // Second call leaves valid symlink untouched.
        ensure_localtime_at(&root, None).unwrap();
        assert_eq!(fs::read_link(root.join("etc/localtime")).unwrap(), Path::new("/usr/share/zoneinfo/Asia/Shanghai"));
        let _ = fs::remove_dir_all(&root);
    }
}
