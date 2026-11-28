//! Opt-in Windows bind-mount watcher for WSL 2 (`C:\...` -> `/mnt/c/...`).
//!
//! WSL 2 mounts Windows drives over 9P (`drvfs`), and Microsoft's kernel does
//! not forward Windows file-change notifications into Linux inotify. When the
//! user opts in (`%LOCALAPPDATA%\Kiri\settings.json` with
//! `{"watchBindMounts": true}`, or `KIRI_WIN_WATCH_BINDS=1`), this watches
//! active `/mnt/<drive>/...` bind sources of running containers using
//! kernel-blocking `ReadDirectoryChangesW` (0% CPU when idle), debounces
//! changes over 50 ms in batches of at most 512, and posts `OP\t/mnt/...`
//! lines to `POST /kiri/fs-events` so `kiri-init` raises real Linux VFS
//! inotify events. As it starts and stops watching a root it posts
//! `P\t/mnt/...` and `U\t/mnt/...`: `kiri-init` holds the root's directories
//! open meanwhile, without which no inotify watch on `drvfs` hears of
//! anything (a watcher started before that misses changes until it restarts).
//!
//! When opt-in is OFF (the default): zero threads, zero directory handles,
//! and zero polling.

#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::PathBuf;

use serde_json::{Value, json};

/// At most this many coalesced lines per `POST /kiri/fs-events` request.
pub const BATCH: usize = 512;
/// Debounce window before flushing a burst of Windows file-change events.
#[cfg(windows)]
const DEBOUNCE: std::time::Duration = std::time::Duration::from_millis(50);
/// Maximum raw events buffered during one debounce window.
#[cfg(windows)]
const MAX_BURST: usize = 4096;
/// Fallback rescan interval when the watcher is active (container events also
/// wake it immediately).
#[cfg(windows)]
const RESCAN_FALLBACK: std::time::Duration = std::time::Duration::from_secs(5);

/// `%LOCALAPPDATA%\Kiri\settings.json`.
fn settings_path() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("Kiri").join("settings.json"))
}

/// Parses an environment flag (`KIRI_WIN_WATCH_BINDS`).
fn parse_env_bool(val: &str) -> Option<bool> {
    match val.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Resolves whether bind-mount watching is enabled from `settings.json` text
/// and the optional `KIRI_WIN_WATCH_BINDS` override. Off by default.
pub fn parse_settings_enabled(settings_json: Option<&str>, env_override: Option<&str>) -> bool {
    if let Some(b) = env_override.and_then(parse_env_bool) {
        return b;
    }
    settings_json
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.get("watchBindMounts")?.as_bool())
        .unwrap_or(false)
}

/// Whether bind-mount watching is currently enabled (env override or
/// `%LOCALAPPDATA%\Kiri\settings.json`). Off by default.
pub fn is_enabled() -> bool {
    let env = std::env::var("KIRI_WIN_WATCH_BINDS").ok();
    let text = settings_path().and_then(|p| std::fs::read_to_string(p).ok());
    parse_settings_enabled(text.as_deref(), env.as_deref())
}

/// Persists `watchBindMounts` into `%LOCALAPPDATA%\Kiri\settings.json` while
/// preserving any other keys in that file.
pub fn save_enabled(enabled: bool) -> io::Result<()> {
    let Some(path) = settings_path() else {
        return Err(io::Error::other("LOCALAPPDATA is not set"));
    };
    let mut obj: Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));
    obj["watchBindMounts"] = json!(enabled);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, obj.to_string())?;
    std::fs::rename(&tmp, &path)
}

/// Translates a WSL automount path (`/mnt/c/Users/me/app`) to a Windows path
/// (`C:\Users\me\app`). Rejects paths outside `automount_root`, non-drive
/// entries (like `/mnt/mac/...`), control characters, and `..` traversal.
pub fn wsl_to_windows(wsl_path: &str, automount_root: &str) -> Option<String> {
    if !automount_root.starts_with('/') || !automount_root.ends_with('/') {
        return None;
    }
    if wsl_path.contains(['\n', '\r', '\0', '\t']) {
        return None;
    }
    let rest = wsl_path.strip_prefix(automount_root)?;
    let bytes = rest.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_alphabetic() {
        return None;
    }
    let drive = (bytes[0] as char).to_ascii_uppercase();
    if bytes.len() == 1 {
        return Some(format!("{drive}:\\"));
    }
    if bytes[1] != b'/' {
        return None;
    }
    let mut parts = Vec::new();
    for part in rest[2..].split('/') {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." || part.contains(['\\', ':']) {
            return None;
        }
        parts.push(part);
    }
    if parts.is_empty() {
        Some(format!("{drive}:\\"))
    } else {
        Some(format!("{drive}:\\{}", parts.join("\\")))
    }
}

/// Translates a watched Windows root (`C:\Users\me\app`) plus a relative path
/// from `ReadDirectoryChangesW` (`src\main.js`) back to a WSL automount path
/// (`/mnt/c/Users/me/app/src/main.js`). Rejects `..`, `.`, control characters,
/// NTFS Alternate Data Streams (`:`), or malformed roots.
pub fn windows_to_wsl(win_root: &str, rel_win: &str, automount_root: &str) -> Option<String> {
    if !automount_root.starts_with('/') || !automount_root.ends_with('/') {
        return None;
    }
    if win_root.contains(['\n', '\r', '\0', '\t']) || rel_win.contains(['\n', '\r', '\0', '\t']) {
        return None;
    }
    let b = win_root.as_bytes();
    if b.len() < 3 || !b[0].is_ascii_alphabetic() || b[1] != b':' || (b[2] != b'\\' && b[2] != b'/') {
        return None;
    }
    let drive = (b[0] as char).to_ascii_lowercase();
    let mut comps: Vec<&str> = Vec::new();
    for part in win_root[3..].split(['\\', '/']) {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." || part.contains(':') {
            return None;
        }
        comps.push(part);
    }
    let mut rel_count = 0usize;
    for part in rel_win.split(['\\', '/']) {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." || part.contains(':') {
            return None;
        }
        comps.push(part);
        rel_count += 1;
    }
    if rel_count == 0 {
        return None;
    }
    Some(format!("{automount_root}{drive}/{}", comps.join("/")))
}

/// Whether a relative path belongs to high-volume `.git` internals (object
/// store, reflogs, lockfiles) that cause event storms during git operations.
pub fn is_git_storm_path(rel: &str) -> bool {
    let parts: Vec<&str> = rel.split(['\\', '/']).filter(|p| !p.is_empty()).collect();
    for i in 0..parts.len() {
        if parts[i].eq_ignore_ascii_case(".git")
            && let Some(next) = parts.get(i + 1)
            && (next.eq_ignore_ascii_case("objects") || next.eq_ignore_ascii_case("logs") || next.to_ascii_lowercase().ends_with(".lock"))
        {
            return true;
        }
    }
    false
}

/// Decodes a Win32 `FILE_NOTIFY_INFORMATION` buffer (UTF-16LE filenames) into
/// `(op, relative_path)` pairs:
/// - `FILE_ACTION_ADDED (1)` -> `'C'`
/// - `FILE_ACTION_REMOVED (2)` / `FILE_ACTION_RENAMED_OLD_NAME (4)` -> `'D'`
/// - `FILE_ACTION_MODIFIED (3)` / `FILE_ACTION_RENAMED_NEW_NAME (5)` -> `'M'`
pub fn decode_notify_buffer(buf: &[u8]) -> Vec<(char, String)> {
    const ACTION_ADDED: u32 = 1;
    const ACTION_REMOVED: u32 = 2;
    const ACTION_MODIFIED: u32 = 3;
    const ACTION_RENAMED_OLD: u32 = 4;
    const ACTION_RENAMED_NEW: u32 = 5;

    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + 12 <= buf.len() {
        let next_offset = u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]]) as usize;
        let action = u32::from_le_bytes([buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7]]);
        let name_bytes = u32::from_le_bytes([buf[offset + 8], buf[offset + 9], buf[offset + 10], buf[offset + 11]]) as usize;
        let name_start = offset + 12;
        let Some(name_end) = name_start.checked_add(name_bytes) else { break };
        if name_end > buf.len() || !name_bytes.is_multiple_of(2) {
            break;
        }
        let op = match action {
            ACTION_ADDED => Some('C'),
            ACTION_REMOVED | ACTION_RENAMED_OLD => Some('D'),
            ACTION_MODIFIED | ACTION_RENAMED_NEW => Some('M'),
            _ => None,
        };
        if let Some(op) = op && name_bytes > 0 {
            let units: Vec<u16> = buf[name_start..name_end].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
            let name = String::from_utf16_lossy(&units);
            if !name.is_empty() && !name.contains('\0') {
                out.push((op, name));
            }
        }
        if next_offset == 0 {
            break;
        }
        let Some(next) = offset.checked_add(next_offset) else { break };
        if next <= offset || next > buf.len() {
            break;
        }
        offset = next;
    }
    out
}

/// Merges two ops for the same path arriving within one 50 ms debounce window.
fn merge_op(prev: char, next: char) -> char {
    match (prev, next) {
        (_, 'D') | ('D', 'A') => 'D',
        ('C', 'M') | ('M', 'C') | ('C', 'C') | ('C', 'A') | ('A', 'C') => 'C',
        ('D', 'C') | ('D', 'M') | ('M', 'M') | ('M', 'A') | ('A', 'M') => 'M',
        _ => next,
    }
}

/// Coalesces duplicate/burst events within a batch, preserving arrival order
/// and emitting at most one change line per distinct path. A root's pin
/// (`P`) or unpin (`U`) is kept apart from changes to the same path; the
/// later of the two wins.
pub fn coalesce_events(events: &[(char, String)]) -> Vec<String> {
    let mut order: Vec<(bool, String)> = Vec::new();
    let mut ops: HashMap<(bool, String), char> = HashMap::new();
    for (op, path) in events {
        if !matches!(op, 'C' | 'M' | 'A' | 'D' | 'P' | 'U') || path.is_empty() {
            continue;
        }
        let key = (matches!(op, 'P' | 'U'), path.clone());
        if let Some(existing) = ops.get_mut(&key) {
            *existing = if key.0 { *op } else { merge_op(*existing, *op) };
        } else {
            ops.insert(key.clone(), *op);
            order.push(key);
        }
    }
    order.into_iter().filter_map(|k| ops.get(&k).map(|op| format!("{op}\t{}", k.1))).collect()
}

/// The WSL path of a watched Windows directory (`C:\Users\me\app` ->
/// `/mnt/c/Users/me/app`), for its `P` and `U` lines. None for a drive root.
fn wsl_dir(win_dir: &str, automount_root: &str) -> Option<String> {
    let (parent, name) = win_dir.trim_end_matches('\\').rsplit_once('\\')?;
    let parent = if parent.len() == 2 { format!("{parent}\\") } else { parent.to_owned() };
    windows_to_wsl(&parent, name, automount_root)
}

/// A Windows directory watch specification: either a recursive directory tree
/// or a single-file mount watched non-recursively via its parent directory.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct WatchSpec {
    /// Directory opened with `CreateFileW` (`C:\Users\me\app`).
    dir: String,
    /// `true` for a directory bind mount, `false` for a single-file mount.
    recursive: bool,
    /// When `recursive == false`, only match this exact filename (case-insensitive).
    only_file: Option<String>,
}

/// Removes directory specs already covered by a parent recursive directory watch.
fn collapse_specs(specs: Vec<WatchSpec>) -> Vec<WatchSpec> {
    let mut dirs: Vec<String> = specs.iter().filter(|s| s.recursive).map(|s| s.dir.clone()).collect();
    dirs.sort_by_key(|d| d.len());
    dirs.dedup_by(|a, b| a.eq_ignore_ascii_case(b));

    let covered_by_dir = |path: &str, exclude_self: bool| -> bool {
        dirs.iter().any(|parent| {
            if exclude_self && parent.eq_ignore_ascii_case(path) {
                return false;
            }
            if path.len() < parent.len() || !path.is_char_boundary(parent.len()) {
                return false;
            }
            let head = &path[..parent.len()];
            if !head.eq_ignore_ascii_case(parent) {
                return false;
            }
            let rest = &path[parent.len()..];
            parent.ends_with('\\') || rest.is_empty() || rest.starts_with('\\')
        })
    };

    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for s in specs {
        if s.recursive {
            if covered_by_dir(&s.dir, true) {
                continue;
            }
            let key = format!("d:{}", s.dir.to_ascii_lowercase());
            if seen.insert(key) {
                out.push(s);
            }
        } else {
            let full = match &s.only_file {
                Some(f) if s.dir.ends_with('\\') => format!("{}{f}", s.dir),
                Some(f) => format!("{}\\{f}", s.dir),
                None => s.dir.clone(),
            };
            if covered_by_dir(&full, false) {
                continue;
            }
            let key = format!("f:{}", full.to_ascii_lowercase());
            if seen.insert(key) {
                out.push(s);
            }
        }
    }
    out
}

#[cfg(windows)]
mod runtime {
    use super::*;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Condvar, Mutex, PoisonError, mpsc};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED, FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
        FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, ReadDirectoryChangesW,
    };
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
    use windows_sys::Win32::System::Threading::{CreateEventW, INFINITE, SetEvent, WaitForMultipleObjects};

    const NOTIFY_FILTER: u32 = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE;

    struct Coordinator {
        stop: Arc<AtomicBool>,
        wake: Arc<(Mutex<bool>, Condvar)>,
        thread: Option<JoinHandle<()>>,
    }

    static STATE: Mutex<Option<Coordinator>> = Mutex::new(None);

    /// Starts the watcher ONLY if opt-in is enabled. When disabled (the
    /// default), spawns zero threads and opens zero handles.
    pub fn start_if_enabled() {
        if is_enabled() {
            set_enabled(true);
        }
    }

    /// Starts or stops the watcher dynamically. Turning it off cancels all
    /// `ReadDirectoryChangesW` calls, closes every handle, and stops all
    /// watcher threads.
    pub fn set_enabled(enabled: bool) {
        let mut guard = STATE.lock().unwrap_or_else(PoisonError::into_inner);
        if enabled {
            if guard.is_some() {
                return;
            }
            let stop = Arc::new(AtomicBool::new(false));
            let wake = Arc::new((Mutex::new(false), Condvar::new()));
            let stop_c = stop.clone();
            let wake_c = wake.clone();
            let thread = std::thread::Builder::new().name("kiri-win-watch".into()).spawn(move || coordinate(stop_c, wake_c)).ok();
            if thread.is_some() {
                *guard = Some(Coordinator { stop, wake, thread });
            }
        } else if let Some(mut coord) = guard.take() {
            coord.stop.store(true, Ordering::SeqCst);
            {
                let (m, cv) = &*coord.wake;
                *m.lock().unwrap_or_else(PoisonError::into_inner) = true;
                cv.notify_all();
            }
            drop(guard);
            if let Some(t) = coord.thread.take() {
                let _ = t.join();
            }
        }
    }

    /// Wakes the coordinator when running containers change. No-op when off.
    pub fn notify_containers_changed() {
        let guard = STATE.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(coord) = guard.as_ref() {
            let (m, cv) = &*coord.wake;
            *m.lock().unwrap_or_else(PoisonError::into_inner) = true;
            cv.notify_all();
        }
    }

    pub(super) struct DirWatcher {
        /// Manual-reset event: once set, the worker's wait returns at once,
        /// whether it is waiting already or not yet.
        stop: HANDLE,
        thread: Option<JoinHandle<()>>,
        /// Whether `watch_dir_loop` opened the directory and emitted `P`.
        pinned: Arc<AtomicBool>,
        /// The root's WSL path and the channel its `U` line goes out on.
        unpin: Option<(String, mpsc::Sender<(char, String)>)>,
    }

    impl DirWatcher {
        pub(super) fn start(spec: WatchSpec, automount_root: String, tx: mpsc::Sender<(char, String)>) -> Option<Self> {
            // SAFETY: an unnamed manual-reset event, initially not set.
            let stop = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            if stop == 0 {
                return None;
            }
            let pin = if spec.recursive { wsl_dir(&spec.dir, &automount_root) } else { None };
            let pinned = Arc::new(AtomicBool::new(false));
            let pinned_w = pinned.clone();
            let pin_w = pin.clone();
            let tx_c = tx.clone();
            let thread =
                std::thread::Builder::new().name("kiri-win-dirwatch".into()).spawn(move || watch_dir_loop(spec, automount_root, tx_c, stop, pin_w, pinned_w));
            let Ok(thread) = thread else {
                // SAFETY: our own event, never shared.
                unsafe { CloseHandle(stop) };
                return None;
            };
            Some(DirWatcher { stop, thread: Some(thread), pinned, unpin: pin.map(|root| (root, tx)) })
        }

        pub(super) fn stop(mut self) {
            // SAFETY: `self.stop` stays open until after the join below.
            unsafe { SetEvent(self.stop) };
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
            // SAFETY: the worker has exited; nothing else uses the event.
            unsafe { CloseHandle(self.stop) };
            if self.pinned.load(Ordering::Acquire)
                && let Some((root, tx)) = self.unpin.take()
            {
                let _ = tx.send(('U', root));
            }
        }
    }

    /// Reads changes with overlapped `ReadDirectoryChangesW`, waiting on the
    /// read and `stop` together, so a stop ends the wait at once.
    fn watch_dir_loop(spec: WatchSpec, automount_root: String, tx: mpsc::Sender<(char, String)>, stop: HANDLE, pin: Option<String>, pinned: Arc<AtomicBool>) {
        let wide: Vec<u16> = OsStr::new(&spec.dir).encode_wide().chain(std::iter::once(0)).collect();
        // SAFETY: valid NUL-terminated UTF-16 path with standard directory flags.
        let h = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                0,
            )
        };
        if h == INVALID_HANDLE_VALUE || h == 0 {
            return;
        }
        // SAFETY: an unnamed manual-reset event, initially not set.
        let io = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if io == 0 {
            // SAFETY: our own handle.
            unsafe { CloseHandle(h) };
            return;
        }
        if let Some(root) = &pin {
            if tx.send(('P', root.clone())).is_err() {
                // SAFETY: closing our own handles before any read is started.
                unsafe {
                    CloseHandle(io);
                    CloseHandle(h);
                }
                return;
            }
            pinned.store(true, Ordering::Release);
        }

        // 64 KiB DWORD-aligned buffer as required by ReadDirectoryChangesW.
        let mut buf = vec![0u32; 16384];
        let buf_len = (buf.len() * std::mem::size_of::<u32>()) as u32;
        let subtree = i32::from(spec.recursive);

        loop {
            // SAFETY: zeroed OVERLAPPED is valid; its event is ours.
            let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
            ov.hEvent = io;
            // SAFETY: `h`, `buf` and `ov` outlive the read: every path out of
            // this iteration waits for it to complete or be cancelled.
            let ok = unsafe { ReadDirectoryChangesW(h, buf.as_mut_ptr().cast(), buf_len, subtree, NOTIFY_FILTER, std::ptr::null_mut(), &mut ov, None) };
            if ok == 0 {
                break;
            }
            let waits = [io, stop];
            // SAFETY: two valid event handles.
            let woke = unsafe { WaitForMultipleObjects(2, waits.as_ptr(), 0, INFINITE) };
            let mut returned: u32 = 0;
            if woke != WAIT_OBJECT_0 {
                // Stopped (or the wait failed): cancel the read and wait for it
                // to finish before `buf` and `ov` go away.
                // SAFETY: `h` and `ov` are the pending read's.
                unsafe {
                    CancelIoEx(h, &ov);
                    GetOverlappedResult(h, &ov, &mut returned, 1);
                }
                break;
            }
            // SAFETY: the read completed; `ov` is its OVERLAPPED.
            if unsafe { GetOverlappedResult(h, &ov, &mut returned, 0) } == 0 {
                break;
            }
            let n = (returned as usize).min(buf_len as usize);
            // SAFETY: `buf` holds `n` initialized bytes written by Windows.
            let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
            for (op, rel) in decode_notify_buffer(bytes) {
                if let Some(only) = &spec.only_file
                    && !rel.eq_ignore_ascii_case(only)
                {
                    continue;
                }
                if is_git_storm_path(&rel) {
                    continue;
                }
                let Some(wsl_path) = windows_to_wsl(&spec.dir, &rel, &automount_root) else { continue };
                if tx.send((op, wsl_path)).is_err() {
                    break;
                }
            }
        }

        // SAFETY: closing our own handles; no read is pending.
        unsafe {
            CloseHandle(io);
            CloseHandle(h);
        }
    }

    fn flush_loop(rx: mpsc::Receiver<(char, String)>) {
        while let Ok(first) = rx.recv() {
            let mut batch = vec![first];
            let deadline = Instant::now() + DEBOUNCE;
            while batch.len() < MAX_BURST {
                let Some(rem) = deadline.checked_duration_since(Instant::now()) else { break };
                match rx.recv_timeout(rem) {
                    Ok(ev) => batch.push(ev),
                    Err(mpsc::RecvTimeoutError::Timeout) => break,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            if crate::serve::is_stopped() {
                continue;
            }
            let lines = coalesce_events(&batch);
            for chunk in lines.chunks(BATCH) {
                if crate::serve::is_stopped() {
                    break;
                }
                let body = json!({"events": chunk});
                let _ = crate::client::request_within("POST", "/kiri/fs-events", Some(&body), true, Some(Duration::from_secs(3)));
            }
        }
    }

    fn desired_watches() -> Option<(String, Vec<WatchSpec>)> {
        if crate::serve::is_stopped() {
            return None;
        }
        let resp = crate::client::get_quick("/kiri/watch-roots").ok()?;
        let root = resp["automount_root"].as_str().unwrap_or("/mnt/").to_owned();
        let mut specs = Vec::new();
        for wsl in resp["roots"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            let Some(win) = wsl_to_windows(wsl, &root) else { continue };
            let p = std::path::Path::new(&win);
            if p.is_dir() {
                specs.push(WatchSpec { dir: win, recursive: true, only_file: None });
            } else if p.is_file()
                && let (Some(parent), Some(name)) = (p.parent(), p.file_name())
            {
                specs.push(WatchSpec {
                    dir: parent.to_string_lossy().into_owned(),
                    recursive: false,
                    only_file: Some(name.to_string_lossy().into_owned()),
                });
            }
        }
        Some((root, collapse_specs(specs)))
    }

    fn coordinate(stop: Arc<AtomicBool>, wake: Arc<(Mutex<bool>, Condvar)>) {
        let (tx, rx) = mpsc::channel::<(char, String)>();
        let sender = std::thread::Builder::new().name("kiri-win-watch-tx".into()).spawn(move || flush_loop(rx)).ok();
        let mut active: HashMap<WatchSpec, DirWatcher> = HashMap::new();
        let mut last_root = String::from("/mnt/");

        while !stop.load(Ordering::SeqCst) {
            if crate::serve::is_stopped() {
                for (_, w) in active.drain() {
                    w.stop();
                }
            } else if let Some((root, want)) = desired_watches() {
                let root_changed = root != last_root;
                last_root = root.clone();
                let want_set: HashSet<WatchSpec> = want.iter().cloned().collect();
                let remove: Vec<WatchSpec> = active.keys().filter(|k| root_changed || !want_set.contains(*k)).cloned().collect();
                for k in remove {
                    if let Some(w) = active.remove(&k) {
                        w.stop();
                    }
                }
                for spec in want {
                    if !active.contains_key(&spec)
                        && let Some(w) = DirWatcher::start(spec.clone(), root.clone(), tx.clone())
                    {
                        active.insert(spec, w);
                    }
                }
            }
            if stop.load(Ordering::SeqCst) {
                break;
            }
            let (m, cv) = &*wake;
            let mut signaled = m.lock().unwrap_or_else(PoisonError::into_inner);
            if !*signaled {
                let (g, _) = cv.wait_timeout(signaled, RESCAN_FALLBACK).unwrap_or_else(PoisonError::into_inner);
                signaled = g;
            }
            *signaled = false;
        }

        for (_, w) in active.drain() {
            w.stop();
        }
        drop(tx);
        if let Some(t) = sender {
            let _ = t.join();
        }
    }
}

#[cfg(windows)]
pub use runtime::{notify_containers_changed, set_enabled, start_if_enabled};

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_notify_entries(entries: &[(u32, &str)]) -> Vec<u8> {
        let mut buf = Vec::new();
        for (idx, (action, name)) in entries.iter().enumerate() {
            let utf16: Vec<u16> = name.encode_utf16().collect();
            let name_bytes = utf16.len() * 2;
            let raw_len = 12 + name_bytes;
            let padded_len = (raw_len + 3) & !3;
            let next_offset = if idx + 1 < entries.len() { padded_len as u32 } else { 0u32 };
            buf.extend_from_slice(&next_offset.to_le_bytes());
            buf.extend_from_slice(&action.to_le_bytes());
            buf.extend_from_slice(&(name_bytes as u32).to_le_bytes());
            for u in utf16 {
                buf.extend_from_slice(&u.to_le_bytes());
            }
            buf.resize(buf.len() + (padded_len - raw_len), 0);
        }
        buf
    }

    #[test]
    fn opt_in_is_off_by_default_and_honors_settings_and_env() {
        assert!(!parse_settings_enabled(None, None));
        assert!(!parse_settings_enabled(Some("{}"), None));
        assert!(!parse_settings_enabled(Some(r#"{"watchBindMounts": false}"#), None));
        assert!(parse_settings_enabled(Some(r#"{"watchBindMounts": true}"#), None));
        assert!(parse_settings_enabled(None, Some("1")));
        assert!(parse_settings_enabled(Some(r#"{"watchBindMounts": false}"#), Some("true")));
        assert!(!parse_settings_enabled(Some(r#"{"watchBindMounts": true}"#), Some("0")));
        assert!(!parse_settings_enabled(Some("not json"), None));
    }

    #[test]
    fn wsl_and_windows_path_mapping_and_traversal_rejection() {
        assert_eq!(wsl_to_windows("/mnt/c/Users/me/app", "/mnt/").as_deref(), Some(r"C:\Users\me\app"));
        assert_eq!(wsl_to_windows("/mnt/d/My Project/src", "/mnt/").as_deref(), Some(r"D:\My Project\src"));
        assert_eq!(wsl_to_windows("/mnt/c", "/mnt/").as_deref(), Some(r"C:\"));
        assert_eq!(wsl_to_windows("/windows/e/code", "/windows/").as_deref(), Some(r"E:\code"));
        // Reject non-/mnt/, multi-letter mount names, and .. traversal.
        assert_eq!(wsl_to_windows("/home/me/app", "/mnt/"), None);
        assert_eq!(wsl_to_windows("/mnt/mac/Users/a", "/mnt/"), None);
        assert_eq!(wsl_to_windows("/mnt/c/../etc/passwd", "/mnt/"), None);
        assert_eq!(wsl_to_windows("/mnt/c/Users/../../etc/shadow", "/mnt/"), None);
        assert_eq!(wsl_to_windows("/mnt/c/a\nb", "/mnt/"), None);

        assert_eq!(windows_to_wsl(r"C:\Users\me\app", r"src\main.js", "/mnt/").as_deref(), Some("/mnt/c/Users/me/app/src/main.js"));
        assert_eq!(windows_to_wsl(r"C:\", r"test\app.js", "/mnt/").as_deref(), Some("/mnt/c/test/app.js"));
        assert_eq!(windows_to_wsl(r"D:\proj", r"sub\file.ts", "/windows/").as_deref(), Some("/windows/d/proj/sub/file.ts"));
        assert_eq!(windows_to_wsl(r"C:\Users\me\app", r"..\secret.txt", "/mnt/"), None);
        assert_eq!(windows_to_wsl(r"C:\Users\me\app", "", "/mnt/"), None);
        assert_eq!(windows_to_wsl(r"\\server\share", r"a.txt", "/mnt/"), None);
    }

    #[test]
    fn decodes_utf16le_file_notify_information_buffer() {
        let buf = encode_notify_entries(&[
            (1, r"src\new.ts"),
            (2, r"src\old.ts"),
            (3, r"src\app.ts"),
            (4, r"src\before.ts"),
            (5, r"src\after.ts"),
            (3, "src\\caf\u{00e9}.js"),
        ]);
        assert_eq!(
            decode_notify_buffer(&buf),
            vec![
                ('C', r"src\new.ts".into()),
                ('D', r"src\old.ts".into()),
                ('M', r"src\app.ts".into()),
                ('D', r"src\before.ts".into()),
                ('M', r"src\after.ts".into()),
                ('M', "src\\caf\u{00e9}.js".into()),
            ]
        );
        // Truncated buffer does not panic.
        assert!(decode_notify_buffer(&buf[..5]).is_empty());
        assert!(decode_notify_buffer(&[]).is_empty());
    }

    #[test]
    fn coalesces_bursts_and_filters_git_object_storms() {
        assert!(is_git_storm_path(r".git\objects\ab\123456"));
        assert!(is_git_storm_path(r"sub\.git\objects\pack\pack-1.idx"));
        assert!(is_git_storm_path(r".git\logs\HEAD"));
        assert!(is_git_storm_path(r".git\index.lock"));
        assert!(!is_git_storm_path(r".gitignore"));
        assert!(!is_git_storm_path(r"src\app.js"));
        assert!(!is_git_storm_path(r".git\HEAD"));

        let events = vec![
            ('M', "/mnt/c/app/a.js".into()),
            ('M', "/mnt/c/app/a.js".into()),
            ('C', "/mnt/c/app/b.js".into()),
            ('M', "/mnt/c/app/b.js".into()),
            ('D', "/mnt/c/app/c.js".into()),
            ('M', "/mnt/c/app/c.js".into()),
            ('C', "/mnt/c/app/tmp.js".into()),
            ('D', "/mnt/c/app/tmp.js".into()),
            ('P', "/mnt/c/app".into()),
            ('M', "/mnt/c/app".into()),
            ('U', "/mnt/c/app".into()),
        ];
        assert_eq!(
            coalesce_events(&events),
            vec![
                "M\t/mnt/c/app/a.js",
                "C\t/mnt/c/app/b.js",
                "M\t/mnt/c/app/c.js",
                "D\t/mnt/c/app/tmp.js",
                "U\t/mnt/c/app",
                "M\t/mnt/c/app",
            ]
        );
        assert_eq!(wsl_dir(r"C:\Users\me\app", "/mnt/").as_deref(), Some("/mnt/c/Users/me/app"));
        assert_eq!(wsl_dir(r"D:\proj\", "/mnt/").as_deref(), Some("/mnt/d/proj"));
        assert_eq!(wsl_dir(r"C:\", "/mnt/"), None);
    }

    #[test]
    fn collapses_nested_watch_specs() {
        let specs = vec![
            WatchSpec { dir: r"C:\Users\me\app".into(), recursive: true, only_file: None },
            WatchSpec { dir: r"C:\Users\me\app\src".into(), recursive: true, only_file: None },
            WatchSpec { dir: r"C:\Users\me\app".into(), recursive: false, only_file: Some(".env".into()) },
            WatchSpec { dir: r"C:\Users\me\application".into(), recursive: true, only_file: None },
            WatchSpec { dir: r"C:\Users\me".into(), recursive: false, only_file: Some(".env".into()) },
        ];
        let collapsed = collapse_specs(specs);
        assert_eq!(
            collapsed,
            vec![
                WatchSpec { dir: r"C:\Users\me\app".into(), recursive: true, only_file: None },
                WatchSpec { dir: r"C:\Users\me\application".into(), recursive: true, only_file: None },
                WatchSpec { dir: r"C:\Users\me".into(), recursive: false, only_file: Some(".env".into()) },
            ]
        );
    }

    #[test]
    fn preserves_mutations_across_attribute_events_and_rejects_ads_and_tabs() {
        let expected_pairs = [
            (('C', 'C'), 'C'),
            (('C', 'M'), 'C'),
            (('C', 'A'), 'C'),
            (('C', 'D'), 'D'),
            (('M', 'C'), 'C'),
            (('M', 'M'), 'M'),
            (('M', 'A'), 'M'),
            (('M', 'D'), 'D'),
            (('A', 'C'), 'C'),
            (('A', 'M'), 'M'),
            (('A', 'A'), 'A'),
            (('A', 'D'), 'D'),
            (('D', 'C'), 'M'),
            (('D', 'M'), 'M'),
            (('D', 'A'), 'D'),
            (('D', 'D'), 'D'),
        ];
        for ((first, second), want) in expected_pairs {
            assert_eq!(coalesce_events(&[(first, "/mnt/c/app/f.js".into()), (second, "/mnt/c/app/f.js".into())]), vec![format!("{want}\t/mnt/c/app/f.js")]);
        }

        assert_eq!(windows_to_wsl(r"C:\Users\me\app", r"assets\logo.png:Zone.Identifier:$DATA", "/mnt/"), None);
        assert_eq!(windows_to_wsl(r"C:\Users\bad:ads", r"a.js", "/mnt/"), None);
        assert_eq!(windows_to_wsl(r"C:\Users\me\app", "src\\bad\tname.js", "/mnt/"), None);
        assert_eq!(windows_to_wsl("C:\\Users\\bad\troot", r"a.js", "/mnt/"), None);
        assert_eq!(wsl_to_windows("/mnt/c/Users/me/bad\tname", "/mnt/"), None);
        assert_eq!(wsl_to_windows("/mnt/c/Users/me/file:Zone.Identifier", "/mnt/"), None);
    }

    #[cfg(windows)]
    #[test]
    fn dir_watcher_emits_pin_before_events_and_skips_unopened_roots() {
        let (vtx, vrx) = std::sync::mpsc::channel();
        let vanished = WatchSpec { dir: format!(r"C:\kiri-nonexistent-watch-{}", std::process::id()), recursive: true, only_file: None };
        if let Some(w) = runtime::DirWatcher::start(vanished, "/mnt/".into(), vtx) {
            w.stop();
        }
        assert!(vrx.try_recv().is_err(), "unopened directory must emit neither P nor U");

        let dir = std::env::temp_dir().join(format!("kiri-win-watch-pin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let win_dir = dir.to_string_lossy().replace('/', "\\");
        let wsl_root = wsl_dir(&win_dir, "/mnt/").unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let spec = WatchSpec { dir: win_dir, recursive: true, only_file: None };
        let watcher = runtime::DirWatcher::start(spec, "/mnt/".into(), tx).unwrap();

        let first = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(first, ('P', wsl_root.clone()));

        let file = dir.join("app.js");
        std::fs::write(&file, b"1\n").unwrap();
        let _ = std::fs::write(format!("{}:Zone.Identifier", file.display()), b"[ZoneTransfer]\r\nZoneId=3\r\n");

        let want_file = format!("{wsl_root}/app.js");
        let mut saw_file = false;
        while !saw_file {
            let (op, path) = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            assert!(!path.contains(":Zone.Identifier"), "ADS event leaked: {path}");
            if path == want_file {
                assert!(matches!(op, 'C' | 'M'));
                saw_file = true;
            }
        }

        watcher.stop();
        let mut tail = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            assert!(!ev.1.contains(":Zone.Identifier"));
            tail.push(ev);
        }
        assert_eq!(tail.last(), Some(&('U', wsl_root)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn collapse_specs_handles_multibyte_utf8_boundaries() {
        // Parent "C:\proj\ap" (10 bytes) vs sibling "C:\proj\aé" (byte 10 splits 'é'):
        // must not panic on UTF-8 char boundary slicing.
        let specs = vec![
            WatchSpec { dir: r"C:\proj\ap".into(), recursive: true, only_file: None },
            WatchSpec { dir: r"C:\proj\aé".into(), recursive: true, only_file: None },
            WatchSpec { dir: r"C:\proj\ap\sub".into(), recursive: true, only_file: None },
        ];
        let collapsed = collapse_specs(specs);
        assert_eq!(collapsed.len(), 2);
        assert!(collapsed.iter().any(|s| s.dir == r"C:\proj\ap"));
        assert!(collapsed.iter().any(|s| s.dir == r"C:\proj\aé"));
    }
}
