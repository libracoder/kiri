//! Settings → Storage on Windows: where Kiri keeps its WSL 2 distro VHDX
//! (`ext4.vhdx`), recorded in `%LOCALAPPDATA%\Kiri\storage.json` when changed
//! from the default `%LOCALAPPDATA%\Kiri\wsl\<distro>`.
//!
//! Users who never change storage have no `storage.json` and zero behavior
//! change. When a custom path is configured, it must hold `.kiri-storage`:
//! if an external drive letter is unplugged or offline, Kiri refuses to
//! wipe or re-create an empty distro, surfaces `state: "unavailable"` in
//! Settings → Storage, and offers Retry, Change…, or Reset to default.
//!
//! Moving the distro tries native `wsl.exe --manage <distro> --move <dir>`
//! first (Windows 11 / modern WSL 2), falling back to `wsl.exe --export`
//! (with `--vhd` when supported, else `.tar`) -> `wsl.exe --unregister` ->
//! `wsl.exe --import <distro> <dir> <file> --version 2`, rolling back to
//! the original folder if `--import` fails.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The settings file, under `%LOCALAPPDATA%\Kiri`.
pub const FILE: &str = "storage.json";

/// Written into a custom storage folder once a move completes so an offline
/// drive or an unrelated non-empty folder is never mistaken for Kiri's data.
pub const MARKER: &str = ".kiri-storage";

const MOVING: &str = ".kiri-moving";
const IGNORED: &[&str] = &["desktop.ini", "Thumbs.db", MOVING, MARKER];

/// What `storage.json` holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    pub path: PathBuf,
    pub previous: Option<PathBuf>,
}

/// Result of checking a target path before moving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub needed: u64,
    pub free: u64,
    pub replaces: bool,
}

/// Whether `dir` holds the marker written by a completed move.
pub fn has_marker(dir: &Path) -> bool {
    dir.join(MARKER).is_file()
}

/// Atomically writes `bytes` to `file` via a sibling temp file + rename.
pub fn write_atomic(file: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = file.with_extension(format!("tmp-{}", std::process::id()));
    let write_res = (|| -> io::Result<()> {
        let mut f = fs::File::create(&tmp)?;
        io::Write::write_all(&mut f, bytes)?;
        f.sync_all()
    })();
    if let Err(e) = write_res {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    // On Windows fs::rename fails if the destination exists; remove and rename
    // only after the temp file is flushed, keeping the window minimal.
    #[cfg(windows)]
    if file.exists() {
        let _ = fs::remove_file(file);
    }
    fs::rename(&tmp, file).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

/// Writes the marker into `dir`.
pub fn write_marker(dir: &Path) -> io::Result<()> {
    write_atomic(&dir.join(MARKER), b"{\"kiri\":1}\n")
}

/// Reads `Choice` from `file`; `None` when absent.
pub fn read_at(file: &Path) -> io::Result<Option<Choice>> {
    match fs::read(file) {
        Ok(bytes) => {
            let v: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", file.display())))?;
            let path = v["path"]
                .as_str()
                .map(PathBuf::from)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("{}: missing path", file.display())))?;
            let previous = v["previous"].as_str().map(PathBuf::from);
            Ok(Some(Choice { path, previous }))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Writes `Choice` atomically to `file`.
pub fn write_at(file: &Path, choice: &Choice) -> io::Result<()> {
    let mut map = serde_json::Map::new();
    map.insert("path".into(), serde_json::Value::String(choice.path.to_string_lossy().into_owned()));
    if let Some(prev) = &choice.previous {
        map.insert("previous".into(), serde_json::Value::String(prev.to_string_lossy().into_owned()));
    }
    let bytes = serde_json::to_vec_pretty(&serde_json::Value::Object(map)).map_err(io::Error::other)?;
    write_atomic(file, &bytes)
}

/// Removes `file` if present.
pub fn clear_at(file: &Path) -> io::Result<()> {
    match fs::remove_file(file) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Resolves whether a configured choice is currently offline / unavailable.
/// Returns `Some(missing_path)` if `choice` points to a non-default folder
/// whose `.kiri-storage` marker is missing (for example an unplugged drive).
pub fn unavailable_for(choice: Option<&Choice>, default: &Path) -> Option<PathBuf> {
    let c = choice?;
    if same_path(&c.path, default) || has_marker(&c.path) {
        None
    } else {
        Some(c.path.clone())
    }
}

/// Case-insensitive normalized comparison suitable for Windows paths.
pub fn same_path(a: &Path, b: &Path) -> bool {
    norm_key(a) == norm_key(b)
}

/// Whether `child` is inside `parent` (strictly or equal), case-insensitively.
pub fn is_within(child: &Path, parent: &Path) -> bool {
    let c = norm_key(child);
    let p = norm_key(parent);
    if c == p {
        return true;
    }
    let prefix = if p.ends_with('/') { p } else { format!("{p}/") };
    c.starts_with(&prefix)
}

fn norm_key(p: &Path) -> String {
    let s = p.to_string_lossy().replace('\\', "/");
    let s = s.trim_end_matches('/');
    // Preserve root drive like "c:" -> "c:/"
    if s.len() == 2 && s.as_bytes()[1] == b':' {
        format!("{}/", s.to_ascii_lowercase())
    } else {
        s.to_ascii_lowercase()
    }
}

/// Whether `raw` is an absolute local Windows drive path (`C:\...`),
/// rejecting relative paths, parent traversal (`..`), and UNC shares (`\\...`).
pub fn is_local_windows_path(raw: &str) -> bool {
    let s = raw.trim();
    if s.starts_with(r"\\") || s.starts_with("//") {
        return false;
    }
    let bytes = s.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || (bytes[2] != b'\\' && bytes[2] != b'/') {
        return false;
    }
    !s.split(['\\', '/']).any(|seg| seg == "..")
}

/// Filesystems that cannot reliably hold a WSL 2 `ext4.vhdx`.
pub fn refused_fs(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    matches!(n.as_str(), "fat" | "fat32" | "exfat" | "msdos" | "vfat")
}

/// Margin kept free beside the data: 10% plus 1 GB.
pub fn headroom(bytes: u64) -> u64 {
    bytes / 10 + 1_000_000_000
}

/// Reclaimable bytes below 64 MiB are reported as 0 to avoid prompting
/// pointless VHDX compaction over filesystem slack.
pub const RECLAIM_THRESHOLD: u64 = 64 << 20;

/// Reclaimable bytes from host `ext4.vhdx` allocated size vs in-use bytes
/// inside WSL, applying [`RECLAIM_THRESHOLD`].
pub fn reclaimable_bytes(disk_host: Option<u64>, disk_in_use: Option<u64>) -> Option<u64> {
    let diff = disk_host?.saturating_sub(disk_in_use?);
    Some(if diff > RECLAIM_THRESHOLD { diff } else { 0 })
}

fn format_gb(bytes: u64) -> String {
    format!("{:.1} GB", bytes as f64 / 1e9)
}

/// Pure validation helper shared between Windows production code and host tests.
pub fn validate_target(
    current: &Path,
    target_raw: &str,
    used_bytes: u64,
    copy: bool,
    fs_type: impl FnOnce(&Path) -> io::Result<String>,
    free_bytes: impl FnOnce(&Path) -> io::Result<u64>,
    probe_write: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<Checked, String> {
    let trimmed = target_raw.trim();
    if !is_local_windows_path(trimmed) {
        return Err(format!("{trimmed} isn't a local drive path: choose a folder on a local drive (for example D:\\Kiri)"));
    }
    let target = PathBuf::from(trimmed);
    if same_path(current, &target) {
        return Err(format!("Kiri's data is already in {}", target.display()));
    }
    if is_within(&target, current) {
        return Err(format!("{} is inside Kiri's data folder {}: choose a folder outside it", target.display(), current.display()));
    }
    if is_within(current, &target) {
        return Err(format!("Kiri's data folder {} is inside {}: choose another folder", current.display(), target.display()));
    }
    let mut replaces = false;
    if target.symlink_metadata().is_ok() {
        if !target.is_dir() {
            return Err(format!("{} isn't a folder", target.display()));
        }
        let others = fs::read_dir(&target)
            .map_err(|e| format!("{}: {e}", target.display()))?
            .flatten()
            .any(|e| {
                let name = e.file_name();
                !IGNORED.iter().any(|n| name.eq_ignore_ascii_case(n))
            });
        if has_marker(&target) {
            replaces = others;
        } else if others {
            return Err(format!("{} isn't empty and doesn't hold Kiri's data: choose an empty folder, or make a new one", target.display()));
        }
    }
    let near = target.ancestors().find(|p| p.is_dir()).ok_or_else(|| format!("{} isn't on any connected drive", target.display()))?;
    let fs = fs_type(near).map_err(|e| format!("{}: {e}", near.display()))?;
    if refused_fs(&fs) {
        return Err(format!("{} is on a {fs} drive, which can't hold Kiri's WSL disk: choose a folder on an NTFS drive", target.display()));
    }
    probe_write(near).map_err(|e| format!("Kiri can't write in {}: {e}", near.display()))?;
    let needed = if copy { used_bytes + headroom(used_bytes) } else { headroom(0) };
    let free = free_bytes(near).map_err(|e| format!("{}: {e}", near.display()))?;
    if free < needed {
        return Err(format!("{} has {} free, and Kiri's data needs {} there", near.display(), format_gb(free), format_gb(needed)));
    }
    Ok(Checked { needed, free, replaces })
}

#[cfg(windows)]
mod imp {
    use super::*;
    use serde_json::{Value, json};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::process::CommandExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, PoisonError};

    use crate::engine::{Cmd, emit, notice, send, tr, trf};

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    #[derive(Default)]
    struct Moving {
        to: Option<PathBuf>,
        phase: &'static str,
        done: u64,
        total: u64,
        error: Option<String>,
    }

    static MOVE: Mutex<Moving> = Mutex::new(Moving { to: None, phase: "", done: 0, total: 0, error: None });
    static ACTIVE: AtomicBool = AtomicBool::new(false);
    static RECLAIMING: AtomicBool = AtomicBool::new(false);

    fn state() -> std::sync::MutexGuard<'static, Moving> {
        MOVE.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn moving() -> bool {
        ACTIVE.load(Ordering::SeqCst)
    }

    fn vhdx_allocated(path: &Path) -> Option<u64> {
        use windows_sys::Win32::Foundation::{GetLastError, NO_ERROR};
        use windows_sys::Win32::Storage::FileSystem::GetCompressedFileSizeW;
        if !path.is_file() {
            return None;
        }
        let w = wide(path);
        let mut high = 0u32;
        // SAFETY: `w` is NUL-terminated UTF-16 and `high` is a valid out pointer.
        let low = unsafe { GetCompressedFileSizeW(w.as_ptr(), &mut high) };
        if low == u32::MAX && unsafe { GetLastError() } != NO_ERROR {
            return fs::metadata(path).ok().map(|m| m.len());
        }
        Some(((high as u64) << 32) | (low as u64))
    }

    fn wsl_disk_usage() -> (Option<u64>, Option<u64>) {
        if !crate::client::alive_quick() {
            return (None, None);
        }
        let Ok(v) = crate::client::get_quick("/kiri/storage") else {
            return (None, None);
        };
        (v["fs_in_use"].as_u64(), v["fs_capacity"].as_u64())
    }

    fn config_path() -> PathBuf {
        crate::setup::dir().join(FILE)
    }

    fn distro_name() -> String {
        crate::engine::distro().unwrap_or_else(|| crate::setup::KIRI_DISTRO.to_owned())
    }

    pub fn default_root() -> PathBuf {
        crate::setup::dir().join("wsl").join(distro_name())
    }

    pub fn read() -> Option<Choice> {
        read_at(&config_path()).ok().flatten()
    }

    /// Returns `Some(missing_path)` if `storage.json` configures a custom
    /// folder whose drive is currently offline / marker is missing.
    pub fn unavailable() -> Option<PathBuf> {
        let choice = read();
        unavailable_for(choice.as_ref(), &default_root())
    }

    pub fn unavailable_message(missing: &Path) -> String {
        format!("Kiri's data folder {} isn't available: connect its drive, or choose Settings → Storage → Reset to default", missing.display())
    }

    fn current_root() -> PathBuf {
        read().map(|c| c.path).unwrap_or_else(default_root)
    }

    pub fn current_vhdx() -> PathBuf {
        current_root().join("ext4.vhdx")
    }

    fn dir_size(dir: &Path) -> u64 {
        let Ok(entries) = fs::read_dir(dir) else { return 0 };
        let mut total = 0u64;
        for e in entries.flatten() {
            let Ok(m) = e.metadata() else { continue };
            if m.is_file() {
                total = total.saturating_add(m.len());
            } else if m.is_dir() {
                total = total.saturating_add(dir_size(&e.path()));
            }
        }
        total
    }

    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    }

    fn free_space(dir: &Path) -> io::Result<u64> {
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
        let w = wide(dir);
        let mut avail = 0u64;
        // SAFETY: `w` is NUL-terminated UTF-16 and `avail` is a valid out pointer.
        if unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut avail, std::ptr::null_mut(), std::ptr::null_mut()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(avail)
    }

    fn fs_name(dir: &Path) -> io::Result<String> {
        use windows_sys::Win32::Storage::FileSystem::{GetVolumeInformationW, GetVolumePathNameW};
        let w = wide(dir);
        let mut root = [0u16; 260];
        // SAFETY: valid UTF-16 path and output buffer of length 260.
        if unsafe { GetVolumePathNameW(w.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut fs_buf = [0u16; 64];
        // SAFETY: `root` is NUL-terminated; `fs_buf` receives the filesystem name.
        if unsafe {
            GetVolumeInformationW(
                root.as_ptr(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                fs_buf.as_mut_ptr(),
                fs_buf.len() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let end = fs_buf.iter().position(|&c| c == 0).unwrap_or(fs_buf.len());
        Ok(String::from_utf16_lossy(&fs_buf[..end]))
    }

    fn probe_writable(dir: &Path) -> io::Result<()> {
        let probe = dir.join(format!(".kiri-probe-{}", std::process::id()));
        let res = (|| {
            let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&probe)?;
            io::Write::write_all(&mut f, b"kiri")?;
            f.sync_all()
        })();
        let _ = fs::remove_file(&probe);
        res
    }

    pub fn report() -> Value {
        let default = default_root();
        let choice = read();
        let missing = unavailable_for(choice.as_ref(), &default);
        let is_missing = missing.is_some();
        let root = missing.unwrap_or_else(|| choice.as_ref().map(|c| c.path.clone()).unwrap_or_else(|| default.clone()));
        let custom = !same_path(&root, &default);
        let old = choice.and_then(|c| c.previous).filter(|p| !same_path(p, &root) && p.is_dir());
        let active = moving();
        let m = state();
        let near = root.ancestors().find(|p| p.is_dir());
        let (disk_host, disk_in_use, disk_limit, reclaimable) = if !is_missing && !active {
            let host = vhdx_allocated(&root.join("ext4.vhdx"));
            let (in_use, limit) = wsl_disk_usage();
            let rec = reclaimable_bytes(host, in_use);
            (host, in_use, limit, rec)
        } else {
            (None, None, None, None)
        };
        json!({
            "type": "storage",
            "path": root,
            "default": default,
            "custom": custom,
            "env": false,
            "state": if is_missing { "unavailable" } else if active { "moving" } else { "ok" },
            "used": (!is_missing && !active).then(|| dir_size(&root)),
            "free": if is_missing { None } else { near.and_then(|p| free_space(p).ok()) },
            "fs": if is_missing { None } else { near.and_then(|p| fs_name(p).ok()) },
            "disk_host": disk_host,
            "disk_in_use": disk_in_use,
            "disk_limit": disk_limit,
            "reclaimable": reclaimable,
            "moving": m.to.as_ref().filter(|_| active).map(|to| json!({"to": to, "phase": m.phase, "done": m.done, "total": m.total})),
            "error": m.error,
            "old": old,
        })
    }

    pub fn emit_report() {
        emit(report().to_string());
    }

    pub fn check_and_emit(path: Option<String>, fresh: bool, reset: bool) {
        let default = default_root();
        let current = current_root();
        let target_str = match path.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(p) => p.to_owned(),
            None => default.to_string_lossy().into_owned(),
        };
        let is_unavail = unavailable().is_some();
        let used = if is_unavail || fresh { 0 } else { dir_size(&current) };
        match validate_target(&current, &target_str, used, !is_unavail && !fresh, fs_name, free_space, probe_writable) {
            Ok(c) => emit(json!({"type": "storagecheck", "path": target_str, "needed": c.needed, "free": c.free, "replaces": c.replaces, "reset": reset}).to_string()),
            Err(e) => emit(json!({"type": "storagecheck", "path": target_str, "error": e, "reset": reset}).to_string()),
        }
    }

    fn wsl_run(args: &[&std::ffi::OsStr]) -> io::Result<String> {
        let mut cmd = crate::win::tool("wsl.exe");
        cmd.creation_flags(CREATE_NO_WINDOW).args(args);
        let out = cmd.output()?;
        let text = crate::setup::wsl_output(&out.stdout, &out.stderr);
        if out.status.success() {
            Ok(text)
        } else {
            let line = text.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("wsl.exe failed");
            Err(io::Error::other(line.to_owned()))
        }
    }

    fn set_phase(phase: &'static str, done: u64, total: u64) {
        {
            let mut m = state();
            m.phase = phase;
            m.done = done;
            m.total = total;
        }
        emit_report();
    }

    pub fn start_move(path: Option<String>, fresh: bool) {
        std::thread::Builder::new()
            .name("kiri-storage-move".into())
            .spawn(move || run_move(path, fresh))
            .ok();
    }

    fn run_move(path: Option<String>, fresh: bool) {
        let default = default_root();
        let current = current_root();
        let distro = distro_name();
        let target_str = match path.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(p) => p.to_owned(),
            None => default.to_string_lossy().into_owned(),
        };
        let is_unavail = unavailable().is_some();
        let used = if is_unavail || fresh { 0 } else { dir_size(&current) };
        if let Err(e) = validate_target(&current, &target_str, used, !is_unavail && !fresh, fs_name, free_space, probe_writable) {
            emit(notice("error", &e));
            emit_report();
            return;
        }
        let target = PathBuf::from(&target_str);
        if ACTIVE.swap(true, Ordering::SeqCst) {
            emit(notice("error", &tr("Kiri's data is moving already")));
            return;
        }
        *state() = Moving { to: Some(target.clone()), phase: "stopping", done: 0, total: used, error: None };
        emit_report();

        let result = (|| -> io::Result<Vec<String>> {
            let running = if !is_unavail && crate::client::alive_quick() {
                let list = crate::client::get_quick("/containers/json").ok();
                let ids: Vec<String> = list
                    .as_ref()
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|c| c["Id"].as_str().map(str::to_owned)).collect())
                    .unwrap_or_default();
                let _ = crate::client::request("POST", "/kiri/stop", None);
                ids
            } else {
                Vec::new()
            };
            crate::serve::renew_bridge();
            let _ = wsl_run(&[std::ffi::OsStr::new("--terminate"), std::ffi::OsStr::new(&distro)]);
            fs::create_dir_all(&target)?;

            if is_unavail || fresh {
                set_phase("switching", 0, 0);
                // Switching to a fresh store on Kiri Linux: verify bundle before touching WSL.
                let tar = crate::setup::verified("kiri-linux.tar.gz")?;
                let _ = wsl_run(&[std::ffi::OsStr::new("--unregister"), std::ffi::OsStr::new(&distro)]);
                wsl_run(&[
                    std::ffi::OsStr::new("--import"),
                    std::ffi::OsStr::new(&distro),
                    target.as_os_str(),
                    tar.as_os_str(),
                    std::ffi::OsStr::new("--version"),
                    std::ffi::OsStr::new("2"),
                ])?;
            } else {
                set_phase("copying", 0, used);
                move_distro(&distro, &current, &target)?;
            }

            set_phase("switching", 0, 0);
            write_marker(&target)?;
            if same_path(&target, &default) {
                clear_at(&config_path())?;
            } else {
                write_at(&config_path(), &Choice { path: target.clone(), previous: None })?;
            }

            set_phase("restarting", 0, 0);
            crate::serve::renew_bridge();
            crate::engine::ensure_daemon()?;
            Ok(if fresh || is_unavail { Vec::new() } else { running })
        })();

        match result {
            Ok(running) => {
                {
                    let mut m = state();
                    m.to = None;
                    m.phase = "";
                    m.error = None;
                }
                ACTIVE.store(false, Ordering::SeqCst);
                for id in &running {
                    let _ = crate::client::request("POST", &format!("/containers/{id}/start"), None);
                }
                emit(notice("ok", &trf("Kiri's data moved to {path}", &[("path", &target.display().to_string())])));
                emit_report();
                send(Cmd::Refresh);
            }
            Err(e) => {
                crate::serve::log(&format!("storage move failed: {e}"));
                {
                    let mut m = state();
                    m.to = None;
                    m.phase = "";
                    m.error = Some(e.to_string());
                }
                ACTIVE.store(false, Ordering::SeqCst);
                let _ = crate::engine::ensure_daemon();
                emit(notice("error", &e.to_string()));
                emit_report();
            }
        }
    }

    /// Moves WSL distro `distro` from `old_dir` to `target`. Tries native
    /// `wsl --manage <distro> --move <target>` first, then falls back to
    /// `--export` -> `--unregister` -> `--import` with rollback on failure.
    fn move_distro(distro: &str, old_dir: &Path, target: &Path) -> io::Result<()> {
        let managed = wsl_run(&[
            std::ffi::OsStr::new("--manage"),
            std::ffi::OsStr::new(distro),
            std::ffi::OsStr::new("--move"),
            target.as_os_str(),
        ]);
        if managed.is_ok() {
            return Ok(());
        }
        // Fallback: export into staging folder inside target, unregister, import.
        let staging = target.join(MOVING);
        let _ = fs::remove_dir_all(&staging);
        fs::create_dir_all(&staging)?;
        let vhd_file = staging.join("distro.vhdx");
        let tar_file = staging.join("distro.tar");
        let (archive, is_vhd) = match wsl_run(&[
            std::ffi::OsStr::new("--export"),
            std::ffi::OsStr::new(distro),
            vhd_file.as_os_str(),
            std::ffi::OsStr::new("--vhd"),
        ]) {
            Ok(_) if vhd_file.is_file() && fs::metadata(&vhd_file).is_ok_and(|m| m.len() > 0) => (vhd_file, true),
            _ => {
                let _ = fs::remove_file(&vhd_file);
                if let Err(e) = wsl_run(&[std::ffi::OsStr::new("--export"), std::ffi::OsStr::new(distro), tar_file.as_os_str()]) {
                    let _ = fs::remove_dir_all(&staging);
                    return Err(e);
                }
                if !tar_file.is_file() || fs::metadata(&tar_file).is_ok_and(|m| m.len() == 0) {
                    let _ = fs::remove_dir_all(&staging);
                    return Err(io::Error::other("WSL export produced an empty archive"));
                }
                (tar_file, false)
            }
        };
        if let Err(e) = wsl_run(&[std::ffi::OsStr::new("--unregister"), std::ffi::OsStr::new(distro)]) {
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }
        let import_to = |dest: &Path| {
            let mut args: Vec<&std::ffi::OsStr> = vec![
                std::ffi::OsStr::new("--import"),
                std::ffi::OsStr::new(distro),
                dest.as_os_str(),
                archive.as_os_str(),
                std::ffi::OsStr::new("--version"),
                std::ffi::OsStr::new("2"),
            ];
            if is_vhd {
                args.push(std::ffi::OsStr::new("--vhd"));
            }
            wsl_run(&args)
        };
        if let Err(e) = import_to(target) {
            // Roll back: restore the distro at its original folder before deleting staging.
            let _ = fs::create_dir_all(old_dir);
            let _ = import_to(old_dir);
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }
        let _ = fs::remove_dir_all(&staging);
        Ok(())
    }

    pub fn retry() {
        std::thread::spawn(|| {
            if let Some(missing) = unavailable() {
                emit(notice("error", &unavailable_message(&missing)));
                emit_report();
                return;
            }
            crate::serve::renew_bridge();
            match crate::engine::ensure_daemon() {
                Ok(()) => {
                    emit(notice("ok", &tr("Storage is available again")));
                    emit_report();
                    send(Cmd::Refresh);
                }
                Err(e) => {
                    emit(notice("error", &e.to_string()));
                    emit_report();
                }
            }
        });
    }

    pub fn reset() {
        if unavailable().is_some() {
            start_move(None, true);
        } else {
            start_move(None, false);
        }
    }

    pub fn remove_old() {
        std::thread::spawn(|| {
            if moving() {
                emit(notice("error", &tr("Kiri's data is moving already")));
                return;
            }
            let Some(mut choice) = read() else { return };
            let Some(old) = choice.previous.clone() else { return };
            let current = current_root();
            if same_path(&old, &current) || is_within(&old, &current) || is_within(&current, &old) {
                emit(notice("error", &format!("{} holds Kiri's data now", old.display())));
                return;
            }
            if old.exists() {
                if !has_marker(&old) {
                    emit(notice("error", &format!("{} doesn't look like Kiri's old data; remove it yourself if you're sure", old.display())));
                    return;
                }
                if let Err(e) = fs::remove_dir_all(&old) {
                    emit(notice("error", &format!("{}: {e}", old.display())));
                    return;
                }
            }
            choice.previous = None;
            let _ = if same_path(&choice.path, &default_root()) { clear_at(&config_path()) } else { write_at(&config_path(), &choice) };
            emit(notice("ok", &tr("Old data removed")));
            emit_report();
        });
    }

    fn compact_vhdx(vhdx: &Path) -> io::Result<()> {
        // First try Hyper-V's Optimize-VHD via PowerShell if installed.
        let escaped = vhdx.to_string_lossy().replace('\'', "''");
        let ps = crate::win::tool("powershell.exe")
            .creation_flags(CREATE_NO_WINDOW)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!("Optimize-VHD -Path '{escaped}' -Mode Full"),
            ])
            .output();
        if ps.as_ref().is_ok_and(|o| o.status.success()) {
            return Ok(());
        }
        // Fallback: diskpart compact vdisk on an offline VHDX.
        let script = std::env::temp_dir().join(format!("kiri-compact-{}.txt", std::process::id()));
        let vhdx_str = vhdx.to_string_lossy().replace('"', "");
        let content = format!(
            "select vdisk file=\"{vhdx_str}\"\r\nattach vdisk readonly\r\ncompact vdisk\r\ndetach vdisk\r\n"
        );
        fs::write(&script, content.as_bytes())?;
        let res = crate::win::tool("diskpart.exe")
            .creation_flags(CREATE_NO_WINDOW)
            .arg("/s")
            .arg(&script)
            .output();
        let _ = fs::remove_file(&script);
        match res {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => {
                let text = crate::setup::wsl_output(&o.stdout, &o.stderr);
                let line = text.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("diskpart compact failed");
                Err(io::Error::other(line.to_owned()))
            }
            Err(e) => Err(e),
        }
    }

    /// Reclaims unused space in Kiri's WSL 2 `ext4.vhdx` via `fstrim` + sparse
    /// mode or offline VHDX compact, restarting the engine and previously
    /// running containers if offline compaction was needed.
    pub fn reclaim() {
        std::thread::Builder::new()
            .name("kiri-storage-reclaim".into())
            .spawn(|| {
                if moving() {
                    emit(json!({"type": "storagereclaimed", "error": tr("Kiri's data is moving already")}).to_string());
                    return;
                }
                if RECLAIMING.swap(true, Ordering::SeqCst) {
                    emit(json!({"type": "storagereclaimed", "error": tr("Disk reclaim is already running")}).to_string());
                    return;
                }
                struct Guard;
                impl Drop for Guard {
                    fn drop(&mut self) {
                        RECLAIMING.store(false, Ordering::SeqCst);
                    }
                }
                let _guard = Guard;
                let t0 = std::time::Instant::now();
                let distro = distro_name();
                let vhdx = current_vhdx();
                let before = vhdx_allocated(&vhdx).unwrap_or(0);
                let running: Vec<String> = if crate::client::alive_quick() {
                    crate::client::get_quick("/containers/json")
                        .ok()
                        .and_then(|v| v.as_array().cloned())
                        .map(|a| a.iter().filter_map(|c| c["Id"].as_str().map(str::to_owned)).collect())
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                // 1. Discard freed ext4 blocks inside WSL.
                let _ = wsl_run(&[
                    std::ffi::OsStr::new("-d"),
                    std::ffi::OsStr::new(&distro),
                    std::ffi::OsStr::new("-u"),
                    std::ffi::OsStr::new("root"),
                    std::ffi::OsStr::new("--"),
                    std::ffi::OsStr::new("sh"),
                    std::ffi::OsStr::new("-c"),
                    std::ffi::OsStr::new("fstrim /var/lib/kiri 2>/dev/null || true; fstrim / 2>/dev/null || true"),
                ]);
                // 2. Enable sparse VHDX if WSL supports it (can reclaim immediately).
                let _ = wsl_run(&[
                    std::ffi::OsStr::new("--manage"),
                    std::ffi::OsStr::new(&distro),
                    std::ffi::OsStr::new("--set-sparse"),
                    std::ffi::OsStr::new("true"),
                    std::ffi::OsStr::new("--allow-unsafe"),
                ]);
                let mid = vhdx_allocated(&vhdx).unwrap_or(before);
                let (in_use_before, _) = wsl_disk_usage();
                let still_reclaimable = reclaimable_bytes(Some(mid), in_use_before).unwrap_or(0) > 0 || mid >= before;
                let mut compact_err: Option<String> = None;
                if still_reclaimable && vhdx.is_file() {
                    if crate::client::alive_quick() {
                        let _ = crate::client::request("POST", "/kiri/stop", None);
                    }
                    crate::serve::renew_bridge();
                    let _ = wsl_run(&[std::ffi::OsStr::new("--terminate"), std::ffi::OsStr::new(&distro)]);
                    if let Err(e) = compact_vhdx(&vhdx) {
                        crate::serve::log(&format!("storage reclaim compact failed: {e}"));
                        compact_err = Some(e.to_string());
                    }
                    crate::serve::renew_bridge();
                    let _ = crate::engine::ensure_daemon();
                    for id in &running {
                        let _ = crate::client::request("POST", &format!("/containers/{id}/start"), None);
                    }
                }
                let after = vhdx_allocated(&vhdx).unwrap_or(mid);
                let reclaimed = before.saturating_sub(after);
                let elapsed_ms = t0.elapsed().as_millis() as u64;
                let (in_use, _) = wsl_disk_usage();
                if let Some(err) = compact_err && reclaimed == 0 {
                    emit(json!({"type": "storagereclaimed", "error": err}).to_string());
                } else {
                    emit(
                        json!({
                            "type": "storagereclaimed",
                            "before": before,
                            "after": after,
                            "reclaimed": reclaimed,
                            "in_use": in_use,
                            "elapsed_ms": elapsed_ms,
                        })
                        .to_string(),
                    );
                }
                emit_report();
                send(Cmd::Refresh);
            })
            .ok();
    }
}

#[cfg(windows)]
pub use imp::*;

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kiri-win-storage-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn offline_custom_drive_is_unavailable_and_never_created() {
        let d = scratch("unavail");
        let file = d.join(FILE);
        let default = d.join("wsl/kiri");
        let offline = d.join("external-drive/kiri");
        write_at(&file, &Choice { path: offline.clone(), previous: None }).unwrap();
        assert_eq!(unavailable_for(read_at(&file).unwrap().as_ref(), &default), Some(offline.clone()));
        assert!(!offline.exists(), "offline path must never be created");
        fs::create_dir_all(&offline).unwrap();
        write_marker(&offline).unwrap();
        assert_eq!(unavailable_for(read_at(&file).unwrap().as_ref(), &default), None);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn no_storage_json_uses_default_without_marker() {
        let d = scratch("default");
        let file = d.join(FILE);
        assert_eq!(read_at(&file).unwrap(), None);
        assert_eq!(unavailable_for(None, &d.join("wsl/kiri")), None);
        assert!(!file.exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn validates_windows_paths_case_insensitively_and_refuses_fat_exfat_unc() {
        assert!(is_local_windows_path(r"D:\Kiri"));
        assert!(is_local_windows_path("E:/kiri/data"));
        assert!(!is_local_windows_path(r"\\nas\share\kiri"));
        assert!(!is_local_windows_path(r"relative\kiri"));
        assert!(!is_local_windows_path(r"D:\Kiri\..\Other"));
        assert!(same_path(Path::new(r"C:\Users\Me\Kiri"), Path::new(r"c:\users\me\kiri\")));
        assert!(is_within(Path::new(r"D:\Kiri\sub"), Path::new(r"d:\kiri")));
        assert!(!is_within(Path::new(r"D:\Kiri2"), Path::new(r"d:\kiri")));
        assert!(refused_fs("FAT32") && refused_fs("exFAT") && refused_fs("FAT"));
        assert!(!refused_fs("NTFS") && !refused_fs("ReFS"));
    }

    #[test]
    fn choice_round_trips_atomically_and_clears() {
        let d = scratch("roundtrip");
        let file = d.join(FILE);
        let c = Choice { path: PathBuf::from(r"E:\Kiri"), previous: Some(PathBuf::from(r"C:\Users\u\AppData\Local\Kiri\wsl\kiri")) };
        write_at(&file, &c).unwrap();
        assert_eq!(read_at(&file).unwrap(), Some(c));
        clear_at(&file).unwrap();
        assert_eq!(read_at(&file).unwrap(), None);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn validate_target_checks_path_fs_space_and_contents() {
        let ok_fs = |_: &Path| Ok("NTFS".to_owned());
        let plenty = |_: &Path| Ok(100_000_000_000u64);
        let writable = |_: &Path| Ok(());
        let cur = Path::new(r"C:\Users\u\AppData\Local\Kiri\wsl\kiri");
        assert!(validate_target(cur, r"relative\path", 0, true, ok_fs, plenty, writable).unwrap_err().contains("local drive path"));
        assert!(validate_target(cur, r"\\nas\share\kiri", 0, true, ok_fs, plenty, writable).unwrap_err().contains("local drive path"));
        assert!(validate_target(cur, r"c:\users\u\appdata\local\kiri\wsl\kiri", 0, true, ok_fs, plenty, writable).unwrap_err().contains("already in"));
        assert!(validate_target(cur, r"C:\Users\u\AppData\Local\Kiri\wsl\kiri\sub", 0, true, ok_fs, plenty, writable).unwrap_err().contains("inside Kiri's data folder"));
        assert!(validate_target(cur, r"C:\Users\u\AppData\Local\Kiri", 0, true, ok_fs, plenty, writable).unwrap_err().contains("is inside"));
        assert_eq!(headroom(10_000_000_000), 2_000_000_000);
        assert_eq!(reclaimable_bytes(Some(10_000_000_000), Some(10_000_000_000)), Some(0));
        assert_eq!(reclaimable_bytes(Some(100 + RECLAIM_THRESHOLD), Some(100)), Some(0));
        assert_eq!(reclaimable_bytes(Some(100 + RECLAIM_THRESHOLD + 1), Some(100)), Some(RECLAIM_THRESHOLD + 1));
        assert_eq!(reclaimable_bytes(None, Some(100)), None);
        // On non-Windows hosts a Windows drive path like D:\ has no existing ancestor, so check the error cleanly.
        let r = validate_target(cur, r"D:\Kiri", 5_000_000_000, true, |_| Ok("exFAT".into()), plenty, writable);
        assert!(r.is_err());
        let _ = (Checked { needed: 0, free: 0, replaces: false }, IGNORED, MOVING, format_gb(1_000_000_000));
    }
}
