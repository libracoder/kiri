//! Settings → Storage on a Mac and a Linux host: where Kiri keeps its
//! images, containers and volumes, and moving them to another folder (an
//! external drive, say). Windows moves its WSL distro instead
//! (crates/kiri-win/src/storage.rs).
//!
//! `GET /kiri/storage` says where the data is, what it takes and what is
//! free there, and how a move goes. `POST /kiri/storage/check` checks a
//! folder; `POST /kiri/storage` moves the data there:
//!
//! 1. Every container stops (those that ran are noted) and the VM powers
//!    off (`Engine::park_for_move`).
//! 2. The data is copied into `<folder>/.kiri-moving`, keeping holes
//!    (treecopy.rs), and the copy is checked: blobs by digest, every file
//!    by size.
//! 3. The copy is renamed into place and the marker written
//!    (kiri_image::storage::MARKER).
//! 4. `~/.kiri/storage.json` is written: the commit point. Up to here any
//!    failure removes what was made and Kiri carries on where it was.
//! 5. The daemon starts itself again on the new folder and starts the
//!    containers that ran. The old folder is kept until Remove old data.
//!
//! On a Linux host the agent's layers, containers and volumes move too:
//! from /var/lib/kiri to the chosen folder's `agent` folder, which the
//! agent mounts at /var/lib/kiri when it starts (KIRI_AGENT_DATA).
//!
//! A chosen folder without its marker (a drive that isn't connected) gets
//! no empty store made in it: the daemon stays up with nothing but
//! `serve_unavailable`, which offers Retry and Reset to default.

use std::io::{self, BufReader};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use kiri_image::storage::{self as chosen, Choice, MARKER};

use super::engine::{Engine, Error};
use super::http::{self, Request};
use super::treecopy;

/// On a Linux host, where the agent keeps layers, containers and volumes
/// while the data folder is the default one.
#[cfg(target_os = "linux")]
const AGENT_DATA: &str = "/var/lib/kiri";

/// The staging folder of a move, inside the folder moved to.
const MOVING: &str = ".kiri-moving";
/// Kiri data that was in the folder moved to, set aside until the commit.
const REPLACED: &str = ".kiri-replaced";
/// What a folder may hold besides Kiri's data and still count as empty.
const IGNORED: &[&str] = &[".DS_Store", "lost+found", MOVING, REPLACED, MARKER];
/// Set on the daemon a move starts again: the containers to start.
const RESTART_ENV: &str = "KIRI_STORAGE_RESTART";

/// What other requests get while the data moves.
const MOVING_TEXT: &str = "Kiri is moving its data to another folder: try again when Settings → Storage says it's done";

/// The agent's folder on this system, if it has one apart from the data
/// folder.
fn agent_default() -> Option<&'static Path> {
    #[cfg(target_os = "linux")]
    return Some(Path::new(AGENT_DATA));
    #[cfg(not(target_os = "linux"))]
    None
}

/// The agent's data folder for the data folder `root` on a Linux host:
/// /var/lib/kiri for the default folder, else `<root>/agent`. None
/// elsewhere. `guest.rs` hands a chosen one to the agent.
pub fn agent_dir(root: &Path, default: &Path) -> Option<PathBuf> {
    agent_default().map(|agent| if root == default { agent.to_owned() } else { root.join("agent") })
}

/// One folder a move copies: `from` into `to`, leaving out `skip` (names
/// at its top that another part moves).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    pub from: PathBuf,
    pub to: PathBuf,
    pub skip: Vec<&'static str>,
}

/// What moving the data folder `current` to `target` copies, where
/// `default` is the folder without a choice and `agent` the agent's own
/// folder for it (a Linux host's /var/lib/kiri).
pub fn parts(current: &Path, target: &Path, default: &Path, agent: Option<&Path>) -> Vec<Part> {
    let Some(agent) = agent else {
        return vec![Part { from: current.to_owned(), to: target.to_owned(), skip: Vec::new() }];
    };
    let agent_of = |root: &Path| if root == default { agent.to_owned() } else { root.join("agent") };
    vec![
        Part { from: current.to_owned(), to: target.to_owned(), skip: vec!["agent"] },
        Part { from: agent_of(current), to: agent_of(target), skip: Vec::new() },
    ]
}

/// A folder that passed [`check`]: what the data needs there, what is
/// free, and whether Kiri data already there is replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub needed: u64,
    pub free: u64,
    pub replaces: bool,
}

/// `path` with its links resolved as far as it exists.
fn real(path: &Path) -> PathBuf {
    let Some(near) = treecopy::existing_ancestor(path) else { return path.to_owned() };
    let rest = path.strip_prefix(near).unwrap_or(Path::new(""));
    near.canonicalize().unwrap_or_else(|_| near.to_owned()).join(rest)
}

/// "12.3 GB".
fn size(bytes: u64) -> String {
    format!("{:.1} GB", bytes as f64 / 1e9)
}

/// Room left over beside the data: a tenth more, and 1 GB.
fn headroom(bytes: u64) -> u64 {
    bytes / 10 + 1_000_000_000
}

/// Whether the folders can take the data: full paths, apart from where
/// the data is now, empty (or holding Kiri data from before), writable,
/// not FAT or exFAT, with room for what the data takes plus a margin.
#[cfg(test)]
pub fn check(parts: &[Part]) -> Result<Checked, String> {
    check_with(parts, true)
}

/// Like [`check`], but when `copy` is false (`Start fresh`), only checks
/// that the target has baseline headroom (1 GB) rather than the current
/// store's allocated size.
pub fn check_with(parts: &[Part], copy: bool) -> Result<Checked, String> {
    let mut replaces = false;
    // Per filesystem: a folder on it, and the bytes moving there.
    let mut needs: Vec<(u64, PathBuf, u64)> = Vec::new();
    for p in parts {
        let to = &p.to;
        if !to.is_absolute() || to.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(format!("{} isn't a full path: choose a folder", to.display()));
        }
        for q in parts {
            let (from, dest) = (real(&q.from), real(to));
            if from == dest {
                return Err(format!("Kiri's data is already in {}", to.display()));
            }
            if dest.starts_with(&from) {
                return Err(format!("{} is inside Kiri's data folder {}: choose a folder outside it", to.display(), q.from.display()));
            }
            if from.starts_with(&dest) {
                return Err(format!("Kiri's data folder {} is inside {}: choose another folder", q.from.display(), to.display()));
            }
        }
        if to.symlink_metadata().is_ok() {
            if !to.is_dir() {
                return Err(format!("{} isn't a folder", to.display()));
            }
            let others = std::fs::read_dir(to)
                .map_err(|e| format!("{}: {e}", to.display()))?
                .flatten()
                .any(|e| !IGNORED.iter().any(|n| e.file_name() == *n) && !p.skip.iter().any(|n| e.file_name() == *n));
            if chosen::has_marker(to) {
                replaces |= others;
            } else if others {
                return Err(format!("{} isn't empty and doesn't hold Kiri's data: choose an empty folder, or make a new one", to.display()));
            }
        }
        let near = treecopy::existing_ancestor(to).ok_or_else(|| format!("{} isn't on any disk", to.display()))?;
        let fs = treecopy::fs_name(near).map_err(|e| format!("{}: {e}", near.display()))?;
        if treecopy::refused_fs(&fs) {
            let name = if fs == "exfat" { "exFAT" } else { "FAT" };
            return Err(format!("{} is on a {name} drive, which can't hold Kiri's data (no sparse files, owners or links): choose a folder on another drive", to.display()));
        }
        treecopy::probe_writable(near).map_err(|e| format!("Kiri can't write in {}: {e}", near.display()))?;
        let bytes = if copy { treecopy::allocated(&p.from, &p.skip) } else { 0 };
        let dev = treecopy::device(near).map_err(|e| format!("{}: {e}", near.display()))?;
        match needs.iter_mut().find(|(d, _, _)| *d == dev) {
            Some(n) => n.2 += bytes,
            None => needs.push((dev, near.to_owned(), bytes)),
        }
    }
    let (mut needed, mut free) = (0, u64::MAX);
    for (_, near, bytes) in &needs {
        let want = bytes + headroom(*bytes);
        let have = treecopy::free_space(near).map_err(|e| format!("{}: {e}", near.display()))?;
        if have < want {
            return Err(format!("{} has {} free, and Kiri's data needs {} there", near.display(), size(have), size(want)));
        }
        needed += want;
        free = free.min(have);
    }
    Ok(Checked { needed, free, replaces })
}

/// The steps of [`migrate`] the progress callback is told about.
pub const COPYING: &str = "copying";
pub const VERIFYING: &str = "verifying";
pub const SWITCHING: &str = "switching";

/// One part put in place: what to undo if a later step fails.
struct Placed {
    to: PathBuf,
    moved_in: Vec<std::ffi::OsString>,
    set_aside: Vec<std::ffi::OsString>,
    had_marker: bool,
}

/// Steps 2 to 4 of a move: each part copied into `<to>/.kiri-moving` and
/// checked, put in place with the marker, then `choice` written to
/// `config`, the commit. A failure before the commit undoes everything:
/// what was copied goes, Kiri data that was in the way comes back, and
/// the folders the data is in now are as they were (apart from the marker,
/// which says they hold Kiri data). `step` hears each step's bytes; an
/// error from it stops the move.
pub fn migrate(parts: &[Part], config: &Path, choice: &Choice, step: &mut dyn FnMut(&'static str, u64) -> io::Result<()>) -> io::Result<()> {
    let parts: Vec<&Part> = parts.iter().filter(|p| p.from.is_dir()).collect();
    let made: Vec<bool> = parts.iter().map(|p| !p.to.exists()).collect();
    let mut placed: Vec<Placed> = Vec::new();
    let result = (|| -> io::Result<()> {
        for p in &parts {
            // Recognisable as Kiri's later: the old folder is a valid
            // target for a move back.
            chosen::write_marker(&p.from)?;
            std::fs::create_dir_all(&p.to)?;
            let staging = p.to.join(MOVING);
            let _ = std::fs::remove_dir_all(&staging);
            treecopy::copy_tree(&p.from, &staging, &p.skip, &mut |n| step(COPYING, n))?;
        }
        for p in &parts {
            treecopy::verify_tree(&p.from, &p.to.join(MOVING), &p.skip, &mut |n| step(VERIFYING, n))?;
        }
        step(SWITCHING, 0)?;
        for p in &parts {
            placed.push(place(p)?);
        }
        chosen::write_at(config, choice)
    })();
    match result {
        Ok(()) => {
            for p in &placed {
                let _ = std::fs::remove_dir_all(p.to.join(REPLACED));
            }
            Ok(())
        }
        Err(e) => {
            for p in placed.iter().rev() {
                undo(p);
            }
            for (p, made) in parts.iter().zip(made).rev() {
                let _ = std::fs::remove_dir_all(p.to.join(MOVING));
                if made {
                    let _ = std::fs::remove_file(p.to.join(MARKER));
                    let _ = std::fs::remove_dir(&p.to);
                }
            }
            Err(e)
        }
    }
}

/// Switches `config` to an empty store in `parts` (`Start fresh`): marks
/// the old folders so Remove old data works, prepares empty target folders
/// with the marker (setting aside any prior Kiri data until commit), and
/// commits `choice` atomically. A failure before commit restores everything.
pub fn migrate_fresh(parts: &[Part], config: &Path, choice: &Choice, step: &mut dyn FnMut(&'static str, u64) -> io::Result<()>) -> io::Result<()> {
    let made: Vec<bool> = parts.iter().map(|p| !p.to.exists()).collect();
    let mut placed: Vec<Placed> = Vec::new();
    let result = (|| -> io::Result<()> {
        step(SWITCHING, 0)?;
        for p in parts {
            if p.from.is_dir() {
                chosen::write_marker(&p.from)?;
            }
            std::fs::create_dir_all(&p.to)?;
            // Recorded before anything is set aside, so a failure partway
            // through this folder is undone along with the ones before it.
            placed.push(Placed { to: p.to.clone(), moved_in: Vec::new(), set_aside: Vec::new(), had_marker: chosen::has_marker(&p.to) });
            let done = placed.last_mut().expect("just pushed");
            for e in std::fs::read_dir(&p.to)? {
                let name = e?.file_name();
                if IGNORED.iter().any(|n| name == *n) || p.skip.iter().any(|n| name == *n) {
                    continue;
                }
                std::fs::create_dir_all(p.to.join(REPLACED))?;
                std::fs::rename(p.to.join(&name), p.to.join(REPLACED).join(&name))?;
                done.set_aside.push(name);
            }
            chosen::write_marker(&p.to)?;
        }
        chosen::write_at(config, choice)
    })();
    match result {
        Ok(()) => {
            for p in &placed {
                let _ = std::fs::remove_dir_all(p.to.join(REPLACED));
            }
            Ok(())
        }
        Err(e) => {
            for p in placed.iter().rev() {
                undo(p);
            }
            for (p, made) in parts.iter().zip(made).rev() {
                if made {
                    let _ = std::fs::remove_file(p.to.join(MARKER));
                    let _ = std::fs::remove_dir(&p.to);
                }
            }
            Err(e)
        }
    }
}

/// Renames a part's copy into place: what was there (Kiri data from
/// before) into `.kiri-replaced`, then the copy, then the marker.
fn place(p: &Part) -> io::Result<Placed> {
    let staging = p.to.join(MOVING);
    let mut done = Placed { to: p.to.clone(), moved_in: Vec::new(), set_aside: Vec::new(), had_marker: chosen::has_marker(&p.to) };
    let mut step = || -> io::Result<()> {
        for e in std::fs::read_dir(&p.to)? {
            let name = e?.file_name();
            if IGNORED.iter().any(|n| name == *n) || p.skip.iter().any(|n| name == *n) {
                continue;
            }
            std::fs::create_dir_all(p.to.join(REPLACED))?;
            std::fs::rename(p.to.join(&name), p.to.join(REPLACED).join(&name))?;
            done.set_aside.push(name);
        }
        for e in std::fs::read_dir(&staging)? {
            let name = e?.file_name();
            if name == MARKER {
                continue;
            }
            std::fs::rename(staging.join(&name), p.to.join(&name))?;
            done.moved_in.push(name);
        }
        std::fs::remove_dir_all(&staging)?;
        chosen::write_marker(&p.to)
    };
    match step() {
        Ok(()) => Ok(done),
        Err(e) => {
            undo(&done);
            Err(e)
        }
    }
}

/// Takes a placed part back out: the copy removed, what was set aside
/// back where it was.
fn undo(p: &Placed) {
    for name in &p.moved_in {
        let path = p.to.join(name);
        let _ = std::fs::remove_dir_all(&path).or_else(|_| std::fs::remove_file(&path));
    }
    for name in &p.set_aside {
        let _ = std::fs::rename(p.to.join(REPLACED).join(name), p.to.join(name));
    }
    let _ = std::fs::remove_dir(p.to.join(REPLACED));
    if !p.had_marker {
        let _ = std::fs::remove_file(p.to.join(MARKER));
    }
}

/// How a move goes, for `GET /kiri/storage`.
#[derive(Default)]
struct Moving {
    to: Option<PathBuf>,
    phase: &'static str,
    done: u64,
    total: u64,
    /// Why the last move failed; Kiri stayed where it was.
    error: Option<String>,
}

static MOVE: Mutex<Moving> = Mutex::new(Moving { to: None, phase: "", done: 0, total: 0, error: None });
static ACTIVE: AtomicBool = AtomicBool::new(false);
static USED_CACHE: Mutex<Option<(PathBuf, Instant, u64)>> = Mutex::new(None);
#[cfg(target_os = "macos")]
static LAST_IN_USE: Mutex<Option<u64>> = Mutex::new(None);
#[cfg(target_os = "macos")]
static LAST_CAPACITY: Mutex<Option<u64>> = Mutex::new(None);
#[cfg(target_os = "macos")]
static RECLAIMING: AtomicBool = AtomicBool::new(false);

/// Persisted non-trimmable VM disk allocation (`<root>/vm/disk-overhead`),
/// measured right after `FITRIM` so ext4's own journal, bitmaps, and
/// initialized inode tables (up to ~2.5% of disk size, excluded from
/// `statvfs.f_blocks`) are counted as in-use VM disk rather than promised as
/// reclaimable space that `FITRIM` can never free.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
const DISK_OVERHEAD_FILE: &str = "vm/disk-overhead";

/// Reclaimable bytes under this threshold (64 MiB) are reported as 0 so
/// filesystem metadata slack does not prompt pointless trims.
pub const RECLAIM_THRESHOLD: u64 = 64 << 20;

/// Reclaimable bytes from host-allocated disk size vs in-use bytes inside the
/// VM, applying [`RECLAIM_THRESHOLD`].
pub fn reclaimable_bytes(disk_host: Option<u64>, disk_in_use: Option<u64>) -> Option<u64> {
    let diff = disk_host?.saturating_sub(disk_in_use?);
    Some(if diff > RECLAIM_THRESHOLD { diff } else { 0 })
}

/// Allocated bytes (`st_blocks * 512`) and logical byte length (`st_size`) of
/// `<root>/vm/data.img`, if present.
pub fn data_img_stats(root: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(root.join("vm/data.img")).ok()?;
    Some((m.blocks().saturating_mul(512), m.len()))
}

/// Allocated bytes of `<root>/vm/data.img` (`st_blocks * 512`), if present.
pub fn data_img_allocated(root: &Path) -> Option<u64> {
    data_img_stats(root).map(|(alloc, _)| alloc)
}

/// Upper bound on ext4's static metadata overhead (`logical_len - capacity`:
/// superblocks, group descriptors, bitmaps, journal, and inode tables), capped
/// to 1/16th of `capacity` + 512 MiB so an online-grown `data.img` whose guest
/// filesystem has not resized yet never treats the unmounted tail as overhead.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn max_ext4_overhead(logical_len: u64, capacity: u64) -> u64 {
    if capacity == 0 || logical_len <= capacity {
        return 0;
    }
    let cap = (capacity >> 4).saturating_add(512 << 20);
    logical_len.saturating_sub(capacity).min(cap)
}

#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn read_disk_overhead(root: &Path) -> Option<u64> {
    std::fs::read_to_string(root.join(DISK_OVERHEAD_FILE))
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn write_disk_overhead(root: &Path, bytes: u64) {
    let path = root.join(DISK_OVERHEAD_FILE);
    let tmp = root.join("vm/disk-overhead.tmp");
    if std::fs::write(&tmp, format!("{bytes}\n")).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

/// Effective bytes in use inside `data.img`, combining occupied filesystem
/// data blocks (`raw_in_use`) with allocated non-trimmable ext4 metadata so
/// `reclaimable_bytes(disk_host, effective_in_use)` matches what `FITRIM` can
/// actually return to macOS.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn effective_vm_in_use(
    disk_host: Option<u64>,
    logical_len: Option<u64>,
    raw_in_use: Option<u64>,
    capacity: Option<u64>,
    recorded_overhead: Option<u64>,
) -> (Option<u64>, Option<u64>) {
    let Some(raw) = raw_in_use else {
        return (None, None);
    };
    let ext4_meta = match (logical_len, capacity) {
        (Some(len), Some(cap)) => max_ext4_overhead(len, cap),
        _ => 0,
    };
    let overhead = match recorded_overhead {
        Some(saved) => match disk_host {
            // If host allocation minus used data shrank below the saved floor
            // (e.g. newly written files reused previously-allocated blocks),
            // clamp downward and update the saved floor.
            Some(host) => saved.min(host.saturating_sub(raw)),
            None => saved,
        },
        None => {
            // Before the first explicit reclaim records an exact post-FITRIM
            // floor: a fresh disk (< 1 GiB of files) has near-zero initialized
            // inode tables, whereas a mature populated disk (>= 1 GiB of files)
            // has already completed `ext4lazyinit` across its block groups.
            if raw >= (1 << 30) {
                match disk_host {
                    Some(host) => ext4_meta.min(host.saturating_sub(raw)),
                    None => ext4_meta,
                }
            } else {
                0
            }
        }
    };
    let clamped_update = recorded_overhead.filter(|&saved| overhead < saved).map(|_| overhead);
    (Some(raw.saturating_add(overhead)), clamped_update)
}

#[cfg(target_os = "linux")]
fn statvfs_usage(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: statvfs fills a zeroed struct for a valid NUL-terminated path.
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    let frsize = if s.f_frsize > 0 { s.f_frsize as u64 } else { s.f_bsize as u64 };
    let blocks = s.f_blocks as u64;
    let bfree = s.f_bfree as u64;
    Some((blocks.saturating_sub(bfree).saturating_mul(frsize), blocks.saturating_mul(frsize)))
}

#[derive(Default)]
struct DiskInfo {
    disk_host: Option<u64>,
    disk_in_use: Option<u64>,
    disk_limit: Option<u64>,
    reclaimable: Option<u64>,
    #[cfg(target_os = "linux")]
    fs_in_use: Option<u64>,
    #[cfg(target_os = "linux")]
    fs_capacity: Option<u64>,
}

fn moving_state() -> std::sync::MutexGuard<'static, Moving> {
    MOVE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Whether the data is moving: requests that change anything wait.
pub fn moving() -> bool {
    ACTIVE.load(Ordering::SeqCst)
}

/// The refusal while it moves.
pub fn refuse_while_moving(w: &mut UnixStream) -> io::Result<()> {
    http::error(w, 503, MOVING_TEXT)
}

#[cfg(target_os = "macos")]
fn invalidate_used_cache() {
    *USED_CACHE.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// What the data folder takes, kept 30 s: walking a Linux host's layers
/// takes a while.
fn used(root: &Path) -> u64 {
    let mut cached = USED_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((p, at, n)) = cached.as_ref()
        && p == root
        && at.elapsed() < Duration::from_secs(30)
    {
        return *n;
    }
    let default = kiri_image::Store::os_default_root().unwrap_or_default();
    let n = treecopy::allocated(root, &["agent"]) + agent_dir(root, &default).map_or(0, |a| treecopy::allocated(&a, &[]));
    *cached = Some((root.to_owned(), Instant::now(), n));
    n
}

/// `GET /kiri/storage`: for the data folder `root`, or for the chosen
/// folder `missing` that isn't there.
fn status(root: &Path, missing: bool) -> Value {
    status_with(root, missing, DiskInfo::default())
}

fn status_with(root: &Path, missing: bool, disk: DiskInfo) -> Value {
    let default = kiri_image::Store::os_default_root().ok();
    let choice = chosen::read().ok().flatten();
    let custom = choice.as_ref().is_some_and(|c| Some(&c.path) != default.as_ref());
    let old = choice.and_then(|c| c.previous).filter(|p| p != root && p.is_dir());
    let active = moving();
    let m = moving_state();
    let near = treecopy::existing_ancestor(root);
    let mut out = json!({
        "path": root,
        "default": default,
        "custom": custom,
        "env": std::env::var_os("KIRI_DATA_DIR").is_some(),
        "state": if missing { "unavailable" } else if active { "moving" } else { "ok" },
        "used": (!missing && !active).then(|| used(root)),
        "free": if missing { None } else { near.and_then(|p| treecopy::free_space(p).ok()) },
        "fs": if missing { None } else { near.and_then(|p| treecopy::fs_name(p).ok()) },
        "disk_host": if missing || active { None } else { disk.disk_host },
        "disk_in_use": if missing || active { None } else { disk.disk_in_use },
        "disk_limit": if missing || active { None } else { disk.disk_limit },
        "reclaimable": if missing || active { None } else { disk.reclaimable },
        "moving": m.to.as_ref().filter(|_| active).map(|to| json!({"to": to, "phase": m.phase, "done": m.done, "total": m.total})),
        "error": m.error,
        "old": old,
    });
    #[cfg(target_os = "linux")]
    if !missing && !active {
        if let Some(u) = disk.fs_in_use {
            out["fs_in_use"] = json!(u);
        }
        if let Some(c) = disk.fs_capacity {
            out["fs_capacity"] = json!(c);
        }
    }
    out
}

/// `GET /kiri/storage`.
pub fn report(engine: &Engine) -> Value {
    let root = engine.store.root();
    #[cfg(target_os = "macos")]
    let disk = {
        let stats = data_img_stats(root);
        let (disk_host, logical_len) = (stats.map(|(a, _)| a), stats.map(|(_, l)| l));
        let (raw_in_use, capacity) = match engine.disk_usage_if_awake() {
            Some((in_use, cap)) => {
                *LAST_IN_USE.lock().unwrap_or_else(|e| e.into_inner()) = Some(in_use);
                *LAST_CAPACITY.lock().unwrap_or_else(|e| e.into_inner()) = Some(cap);
                (Some(in_use), Some(cap))
            }
            None => (
                *LAST_IN_USE.lock().unwrap_or_else(|e| e.into_inner()),
                *LAST_CAPACITY.lock().unwrap_or_else(|e| e.into_inner()),
            ),
        };
        let recorded = read_disk_overhead(root);
        let (disk_in_use, clamped) = effective_vm_in_use(disk_host, logical_len, raw_in_use, capacity, recorded);
        if let Some(updated) = clamped {
            write_disk_overhead(root, updated);
        }
        let disk_limit = Some(super::engine::vm_disk_gb().saturating_mul(1 << 30));
        let reclaimable = reclaimable_bytes(disk_host, disk_in_use);
        DiskInfo { disk_host, disk_in_use, disk_limit, reclaimable }
    };
    #[cfg(target_os = "linux")]
    let disk = {
        let probe = Path::new(AGENT_DATA);
        let target = if probe.is_dir() { probe } else { root };
        let (fs_in_use, fs_capacity) = match statvfs_usage(target) {
            Some((u, c)) => (Some(u), Some(c)),
            None => (None, None),
        };
        DiskInfo { disk_host: None, disk_in_use: None, disk_limit: None, reclaimable: None, fs_in_use, fs_capacity }
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let disk = DiskInfo::default();
    status_with(root, false, disk)
}

/// `POST /kiri/storage/reclaim`: trims unused blocks in the VM data disk and
/// reports host `data.img` allocated bytes before and after.
#[cfg(target_os = "macos")]
pub fn reclaim(engine: &Engine) -> Result<Value, Error> {
    if RECLAIMING.swap(true, Ordering::SeqCst) {
        return Err(Error::Conflict("Disk reclaim is already running".into()));
    }
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            RECLAIMING.store(false, Ordering::SeqCst);
        }
    }
    let _guard = Guard;
    let t0 = Instant::now();
    let root = engine.store.root();
    let before = data_img_allocated(root).unwrap_or(0);
    let (trimmed, raw_in_use, capacity) = engine.trim_disk().map_err(Error::Io)?;
    // Flush pending VirtioBlock DISCARD hole-punches through XNU/APFS before
    // sampling `st_blocks` so `after` reflects every reclaimed block immediately.
    if let Ok(f) = std::fs::File::open(root.join("vm/data.img")) {
        let _ = f.sync_all();
    }
    *LAST_IN_USE.lock().unwrap_or_else(|e| e.into_inner()) = Some(raw_in_use);
    *LAST_CAPACITY.lock().unwrap_or_else(|e| e.into_inner()) = Some(capacity);
    let after = data_img_allocated(root).unwrap_or(0);
    let overhead = after.saturating_sub(raw_in_use);
    write_disk_overhead(root, overhead);
    let in_use = raw_in_use.saturating_add(overhead);
    invalidate_used_cache();
    let reclaimed = before.saturating_sub(after);
    let elapsed_ms = t0.elapsed().as_millis() as u64;
    crate::diag::info!(
        "reclaimed VM disk space",
        before = before,
        after = after,
        reclaimed = reclaimed,
        trimmed = trimmed,
        in_use = in_use,
        raw_in_use = raw_in_use,
        overhead = overhead,
        elapsed_ms = elapsed_ms
    );
    Ok(json!({
        "before": before,
        "after": after,
        "reclaimed": reclaimed,
        "in_use": in_use,
        "reclaimable": 0,
        "elapsed_ms": elapsed_ms,
    }))
}

/// `POST /kiri/storage/reclaim` on native Linux: no VM disk image to trim.
#[cfg(not(target_os = "macos"))]
pub fn reclaim(_engine: &Engine) -> Result<Value, Error> {
    Ok(json!({
        "before": 0,
        "after": 0,
        "reclaimed": 0,
        "in_use": Value::Null,
        "elapsed_ms": 0,
        "native": true,
        "message": "Native Linux uses the host filesystem directly — deleted images and volumes free space immediately.",
    }))
}

/// The folder a request names (none or empty: the default one), and the
/// parts moving there would copy.
fn plan(root: &Path, requested: Option<&str>) -> Result<(PathBuf, Vec<Part>), Error> {
    if let Some(dir) = std::env::var_os("KIRI_DATA_DIR") {
        return Err(Error::Conflict(format!("KIRI_DATA_DIR sets Kiri's data folder ({}): change it there", Path::new(&dir).display())));
    }
    let default = kiri_image::Store::os_default_root()?;
    let target: PathBuf = match requested.map(str::trim).filter(|s| !s.is_empty()) {
        Some(p) => Path::new(p).components().collect(),
        None => default.clone(),
    };
    if target == root {
        return Err(Error::BadRequest(format!("Kiri's data is already in {}", root.display())));
    }
    let parts = parts(root, &target, &default, agent_default());
    Ok((target, parts))
}

fn requested(req: &Request) -> Result<(Option<String>, bool), Error> {
    if req.body.is_empty() {
        return Ok((None, false));
    }
    let body: Value = serde_json::from_slice(&req.body).map_err(|e| Error::BadRequest(format!("invalid JSON: {e}")))?;
    Ok((body["path"].as_str().map(str::to_owned), body["fresh"].as_bool().unwrap_or(false)))
}

/// `POST /kiri/storage/check {"path": …, "fresh": …}`: whether the data can move there.
pub fn check_request(req: &Request, engine: &Engine) -> Result<Value, Error> {
    let (path, fresh) = requested(req)?;
    let (target, parts) = plan(engine.store.root(), path.as_deref())?;
    let c = check_with(&parts, !fresh).map_err(Error::BadRequest)?;
    Ok(json!({"path": target, "needed": c.needed, "free": c.free, "replaces": c.replaces}))
}

/// `POST /kiri/storage {"path": …, "fresh": …}` (none or empty: back to the
/// default folder): checks the folder, then moves the data there on a thread
/// of its own. `GET /kiri/storage` follows it.
pub fn start(req: &Request, engine: &Arc<Engine>) -> Result<Value, Error> {
    let (path, fresh) = requested(req)?;
    start_to(path.as_deref(), fresh, engine)
}

/// `POST /kiri/storage/reset`: the data back to the default folder.
pub fn start_reset(engine: &Arc<Engine>) -> Result<Value, Error> {
    start_to(None, false, engine)
}

fn start_to(requested: Option<&str>, fresh: bool, engine: &Arc<Engine>) -> Result<Value, Error> {
    let root = engine.store.root().to_owned();
    let (target, parts) = plan(&root, requested)?;
    check_with(&parts, !fresh).map_err(Error::BadRequest)?;
    if ACTIVE.swap(true, Ordering::SeqCst) {
        return Err(Error::Conflict("Kiri's data is moving already".into()));
    }
    let total = if fresh { 0 } else { parts.iter().map(|p| treecopy::allocated(&p.from, &p.skip)).sum() };
    *moving_state() = Moving { to: Some(target.clone()), phase: "stopping", done: 0, total, error: None };
    let answer = status(&root, false);
    let engine = engine.clone();
    std::thread::Builder::new().name("kiri-storage-move".into()).spawn(move || run_move(&engine, &root, &target, &parts, fresh))?;
    Ok(answer)
}

fn run_move(engine: &Engine, root: &Path, target: &Path, parts: &[Part], fresh: bool) {
    crate::diag::info!("moving Kiri's data", from = root.display(), to = target.display(), fresh = fresh);
    let fail = |e: String, resume: Option<(Vec<String>, bool)>| {
        crate::diag::error!("Kiri's data did not move; it stays where it was", to = target.display(), error = &e);
        {
            let mut m = moving_state();
            m.to = None;
            m.error = Some(e);
        }
        ACTIVE.store(false, Ordering::SeqCst);
        if let Some((running, was_stopped)) = resume {
            engine.resume_after_move(was_stopped, running);
        }
    };
    let (running, was_stopped) = match engine.park_for_move() {
        Ok(r) => r,
        Err(e) => return fail(format!("the containers did not stop: {e:?}"), None),
    };
    // The agent has stopped: a chosen folder's mount at /var/lib/kiri
    // comes off, so a move back writes to /var/lib/kiri itself. A move that
    // fails leaves storage.json as it was, and the agent mounts it again.
    #[cfg(target_os = "linux")]
    if kiri_image::Store::os_default_root().is_ok_and(|d| d != root) {
        unmount_agent_data();
    }
    let config = match chosen::config_path() {
        Ok(c) => c,
        Err(e) => return fail(e.to_string(), Some((running, was_stopped))),
    };
    let choice = Choice { path: target.to_owned(), previous: Some(root.to_owned()) };
    let mut on_step = |phase: &'static str, n: u64| {
        let mut m = moving_state();
        if m.phase != phase {
            m.phase = phase;
            m.done = 0;
        }
        m.done += n;
        Ok(())
    };
    let moved = if fresh {
        migrate_fresh(parts, &config, &choice, &mut on_step)
    } else {
        migrate(parts, &config, &choice, &mut on_step)
    };
    if let Err(e) = moved {
        return fail(e.to_string(), Some((running, was_stopped)));
    }
    moving_state().phase = "restarting";
    let restart_ids = if fresh { Vec::new() } else { running };
    crate::diag::info!("Kiri's data moved; the engine starts again on it", to = target.display(), containers = restart_ids.len());
    after_commit(root);
    let e = restart(&restart_ids);
    crate::diag::error!("the engine did not start again after the move; it exits for launchd or systemd to start it", error = e);
    std::process::exit(1);
}

/// After the commit, before the restart: what still points into the old
/// folder.
fn after_commit(old: &Path) {
    // Kiri Lite's docker link and plugin folder are in the data folder.
    #[cfg(target_os = "macos")]
    if let Err(e) = crate::setup::relink_cli(old) {
        crate::diag::warn!("docker's links into the data folder were not updated", error = e);
    }
    // The old agent data comes out from under the new folder's mount,
    // into the old folder, so Remove old data finds it there.
    #[cfg(target_os = "linux")]
    if kiri_image::Store::os_default_root().is_ok_and(|d| d == old) {
        stash_agent_data(old);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = old;
}

/// Moves what is in /var/lib/kiri into `<old>/agent`. Only a rename: when
/// they are on different filesystems it stays, under the mount, until a
/// move back.
#[cfg(target_os = "linux")]
fn stash_agent_data(old: &Path) {
    let to = old.join("agent");
    let result = (|| -> io::Result<()> {
        std::fs::create_dir_all(&to)?;
        for e in std::fs::read_dir(AGENT_DATA)? {
            let name = e?.file_name();
            if name == MARKER {
                continue;
            }
            std::fs::rename(Path::new(AGENT_DATA).join(&name), to.join(&name))?;
        }
        let _ = std::fs::remove_file(Path::new(AGENT_DATA).join(MARKER));
        Ok(())
    })();
    if let Err(e) = result {
        crate::diag::warn!("the old agent data stays in /var/lib/kiri", error = e);
    }
}

/// Takes a chosen folder's mount off /var/lib/kiri.
#[cfg(target_os = "linux")]
fn unmount_agent_data() {
    // SAFETY: a valid NUL-terminated path; MNT_DETACH needs nothing else.
    if unsafe { libc::umount2(c"/var/lib/kiri".as_ptr(), libc::MNT_DETACH) } != 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINVAL) {
            crate::diag::warn!("/var/lib/kiri did not unmount", error = e);
        }
    }
}

/// Starts this daemon again in its place (the same process, so launchd
/// and systemd keep it), on the data folder storage.json now names, with
/// the containers to start again. Returns only if that failed.
fn restart(running: &[String]) -> io::Error {
    use std::os::unix::process::CommandExt;
    #[cfg(target_os = "macos")]
    super::nfs::unmount();
    if let Ok(socket) = super::socket_path() {
        let _ = std::fs::remove_file(&socket);
        let _ = std::fs::remove_file(super::caller::container_socket(&socket));
    }
    match std::env::current_exe() {
        Ok(exe) => {
            let mut cmd = std::process::Command::new(exe);
            cmd.arg("daemon");
            if running.is_empty() {
                cmd.env_remove(RESTART_ENV);
            } else {
                cmd.env(RESTART_ENV, running.join(","));
            }
            cmd.exec()
        }
        Err(e) => e,
    }
}

/// On the daemon a move started again: the containers that ran before it
/// start again.
pub fn after_restart(engine: &Arc<Engine>) {
    let Ok(list) = std::env::var(RESTART_ENV) else { return };
    let ids: Vec<String> = list.split(',').filter(|s| !s.is_empty()).map(str::to_owned).collect();
    crate::diag::info!("Kiri's data is in its new folder", folder = engine.store.root().display(), containers = ids.len());
    if !ids.is_empty() {
        let engine = engine.clone();
        std::thread::spawn(move || engine.start_again(&ids));
    }
}

/// `DELETE /kiri/storage/old`: removes the folder the data was moved from.
pub fn remove_old(engine: &Engine) -> Result<Value, Error> {
    if moving() {
        return Err(Error::Conflict(MOVING_TEXT.into()));
    }
    let root = engine.store.root();
    let mut choice = chosen::read()?.ok_or_else(|| Error::Conflict("there is no old data to remove".into()))?;
    let old = choice.previous.clone().ok_or_else(|| Error::Conflict("there is no old data to remove".into()))?;
    remove_old_folder(&old, root).map_err(Error::Conflict)?;
    choice.previous = None;
    if kiri_image::Store::os_default_root().is_ok_and(|d| d == choice.path) {
        chosen::clear()?;
    } else {
        chosen::write(&choice)?;
    }
    Ok(report(engine))
}

/// Removes `old`, the folder data moved away from, if it is safe to: not
/// the data folder `root`, not around or inside it, and holding the marker
/// a move leaves.
fn remove_old_folder(old: &Path, root: &Path) -> Result<(), String> {
    let (o, r) = (real(old), real(root));
    if o == r || o.starts_with(&r) || r.starts_with(&o) {
        return Err(format!("{} holds Kiri's data now", old.display()));
    }
    if !old.exists() {
        return Ok(());
    }
    if !chosen::has_marker(old) {
        return Err(format!("{} doesn't look like Kiri's old data; remove it yourself if you're sure", old.display()));
    }
    std::fs::remove_dir_all(old).map_err(|e| format!("{}: {e}", old.display()))
}

/// The daemon's API while the chosen data folder `missing` isn't there:
/// `GET /kiri/storage` says so, `POST /kiri/storage/retry` starts again
/// once it is back, `POST /kiri/storage/reset` forgets the choice and
/// starts again on the default folder, and `POST /kiri/storage[/check]`
/// lets the user point to another folder (a drive mounted elsewhere, or
/// a fresh folder). Everything else says why it can't.
pub fn serve_unavailable(stream: UnixStream, missing: &Path) -> io::Result<()> {
    use std::io::Write as _;
    let mut w = stream.try_clone()?;
    let mut r = BufReader::new(stream);
    let unavailable = chosen::Unavailable(missing.to_owned()).to_string();
    loop {
        let req = match http::read_request_with_timeout(&mut r, http::HEADER_TIMEOUT, |_, _| false) {
            Ok(Some(req)) => req,
            Ok(None) => break,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                return http::refuse_bad_request(&mut w, &mut r, &e.to_string()).or(Ok(()));
            }
            Err(e) => return Err(e),
        };
        if req.too_large() {
            return http::refuse_too_large(&req, &mut w, &mut r).or(Ok(()));
        }
        http::serving(&req);
        match (req.method.as_str(), req.path.as_str()) {
            ("GET" | "HEAD", "/_ping") => http::respond(&mut w, 200, "text/plain; charset=utf-8", if req.method == "HEAD" { b"" } else { b"OK" })?,
            ("GET", "/version") => http::json(&mut w, 200, &super::api::version().to_string())?,
            ("GET", "/kiri/storage") => http::json(&mut w, 200, &status(missing, true).to_string())?,
            ("POST", "/kiri/storage/check") => match check_unavailable(&req, missing) {
                Ok(v) => http::json(&mut w, 200, &v.to_string())?,
                Err(e) => http::error(&mut w, 400, &e)?,
            },
            ("POST", "/kiri/storage") => match switch_unavailable(&req, missing) {
                Ok(v) => {
                    http::json(&mut w, 202, &v.to_string())?;
                    let _ = w.flush();
                    restart_soon();
                }
                Err(e) => http::error(&mut w, 400, &e)?,
            },
            ("POST", "/kiri/storage/retry") if chosen::has_marker(missing) => {
                http::empty(&mut w, 204)?;
                let _ = w.flush();
                restart_soon();
            }
            ("POST", "/kiri/storage/retry") => http::error(&mut w, 409, &unavailable)?,
            ("POST", "/kiri/storage/reset") => {
                chosen::clear()?;
                crate::diag::info!("storage choice forgotten: the engine starts on the default folder", was = missing.display());
                http::empty(&mut w, 204)?;
                let _ = w.flush();
                restart_soon();
            }
            _ => http::error(&mut w, 503, &unavailable)?,
        }
        if req.wants_close() || !http::finish_body(&req, &mut r) {
            http::close(&w, &mut r);
            return Ok(());
        }
    }
    Ok(())
}

/// Restarts the daemon after a brief pause so the HTTP response finishes
/// writing to the client before `exec()` tears down the listening socket.
fn restart_soon() {
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(80));
        let _ = restart(&[]);
    });
}

fn check_unavailable(req: &Request, missing: &Path) -> Result<Value, String> {
    let (path, _) = requested(req).map_err(|e| format!("{e:?}"))?;
    let (target, parts) = plan(missing, path.as_deref()).map_err(|e| match e {
        Error::BadRequest(s) | Error::Conflict(s) => s,
        other => format!("{other:?}"),
    })?;
    let c = check_with(&parts, false)?;
    Ok(json!({"path": target, "needed": 0, "free": c.free, "replaces": c.replaces}))
}

fn switch_unavailable(req: &Request, missing: &Path) -> Result<Value, String> {
    let (path, _) = requested(req).map_err(|e| format!("{e:?}"))?;
    let (target, parts) = plan(missing, path.as_deref()).map_err(|e| match e {
        Error::BadRequest(s) | Error::Conflict(s) => s,
        other => format!("{other:?}"),
    })?;
    check_with(&parts, false)?;
    for p in &parts {
        std::fs::create_dir_all(&p.to).map_err(|e| format!("{}: {e}", p.to.display()))?;
        if !chosen::has_marker(&p.to) {
            chosen::write_marker(&p.to).map_err(|e| format!("{}: {e}", p.to.display()))?;
        }
    }
    if kiri_image::Store::os_default_root().is_ok_and(|d| d == target) {
        chosen::clear().map_err(|e| e.to_string())?;
    } else {
        chosen::write(&Choice { path: target.clone(), previous: None }).map_err(|e| e.to_string())?;
    }
    Ok(status(&target, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kiri-storage-move-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.canonicalize().unwrap()
    }

    /// A data folder as the daemon leaves it: an image index, a blob, the
    /// VM's disk (sparse) and its address.
    fn data(root: &Path) {
        use sha2::Digest as _;
        std::fs::create_dir_all(root.join("blobs/sha256")).unwrap();
        std::fs::create_dir_all(root.join("vm")).unwrap();
        std::fs::write(root.join("images.json"), b"[]").unwrap();
        let hex: String = sha2::Sha256::digest(b"x").iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(root.join("blobs/sha256").join(hex), b"x").unwrap();
        std::fs::File::create(root.join("vm/data.img")).unwrap().set_len(64 << 20).unwrap();
        std::fs::write(root.join("vm/mac"), b"02:00:00:00:00:01").unwrap();
    }

    fn one(from: &Path, to: &Path) -> Vec<Part> {
        vec![Part { from: from.to_owned(), to: to.to_owned(), skip: Vec::new() }]
    }

    #[test]
    fn a_relative_path_is_refused() {
        let d = scratch("relative");
        data(&d.join("kiri"));
        let e = check(&one(&d.join("kiri"), Path::new("External/kiri"))).unwrap_err();
        assert!(e.contains("isn't a full path"), "{e}");
        let e = check(&one(&d.join("kiri"), &d.join("a/../kiri2"))).unwrap_err();
        assert!(e.contains("isn't a full path"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_folder_inside_the_data_or_around_it_is_refused() {
        let d = scratch("nested");
        let root = d.join("kiri");
        data(&root);
        let e = check(&one(&root, &root.join("vm/elsewhere"))).unwrap_err();
        assert!(e.contains("is inside Kiri's data folder"), "{e}");
        let e = check(&one(&root, &d)).unwrap_err();
        assert!(e.contains("is inside"), "{e}");
        let e = check(&one(&root, &root)).unwrap_err();
        assert!(e.contains("already in"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_folder_with_other_files_is_refused_and_kiri_data_is_replaced() {
        let d = scratch("nonempty");
        let root = d.join("kiri");
        data(&root);
        let other = d.join("photos");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("cat.jpg"), b"meow").unwrap();
        let e = check(&one(&root, &other)).unwrap_err();
        assert!(e.contains("isn't empty"), "{e}");
        // Empty, or with only what a system puts there: fine.
        let empty = d.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        std::fs::write(empty.join(".DS_Store"), b"").unwrap();
        assert!(!check(&one(&root, &empty)).unwrap().replaces);
        // Kiri data from before (the marker): replaced, and said so.
        let before = d.join("before");
        data(&before);
        chosen::write_marker(&before).unwrap();
        assert!(check(&one(&root, &before)).unwrap().replaces);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A move copies the data, puts the marker there and commits the
    /// choice; the old folder stays until Remove old data, which then
    /// removes it.
    #[test]
    fn a_move_copies_marks_and_commits() {
        let d = scratch("move");
        let (root, target, config) = (d.join("kiri"), d.join("external/kiri"), d.join("state/storage.json"));
        data(&root);
        let choice = Choice { path: target.clone(), previous: Some(root.clone()) };
        let mut copied = 0;
        migrate(&one(&root, &target), &config, &choice, &mut |phase, n| {
            if phase == COPYING {
                copied += n;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(chosen::read_at(&config).unwrap(), Some(choice));
        assert!(chosen::has_marker(&target) && !target.join(MOVING).exists() && !target.join(REPLACED).exists());
        assert_eq!(std::fs::read(target.join("vm/mac")).unwrap(), b"02:00:00:00:00:01");
        assert!(std::os::unix::fs::MetadataExt::blocks(&std::fs::metadata(target.join("vm/data.img")).unwrap()) * 512 < 1 << 20, "the VM's disk stays sparse");
        assert!(copied < 1 << 20, "only data was copied: {copied}");
        assert!(root.join("images.json").is_file(), "the old folder is kept");
        assert!(remove_old_folder(&target, &target).is_err(), "never the data folder itself");
        remove_old_folder(&root, &target).unwrap();
        assert!(!root.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A copy that fails before the commit leaves the data where it was,
    /// storage.json unwritten, and nothing in the folder moved to.
    #[test]
    fn a_failed_copy_leaves_the_store_where_it_was() {
        let d = scratch("fail");
        let (root, target, config) = (d.join("kiri"), d.join("external/kiri"), d.join("state/storage.json"));
        data(&root);
        let before = treecopy::sha256(&root.join("vm/mac")).unwrap();
        let choice = Choice { path: target.clone(), previous: Some(root.clone()) };
        let e = migrate(&one(&root, &target), &config, &choice, &mut |_, _| Err(io::Error::other("the drive went away"))).unwrap_err();
        assert!(e.to_string().contains("went away"));
        assert!(!target.join(MOVING).exists() && !target.exists(), "the staging folder and the folder made for it are gone");
        assert_eq!(chosen::read_at(&config).unwrap(), None, "no commit");
        assert_eq!(treecopy::sha256(&root.join("vm/mac")).unwrap(), before);
        assert!(root.join("images.json").is_file() && root.join("blobs/sha256").read_dir().unwrap().next().is_some());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A commit that fails (storage.json can't be written) undoes the
    /// placing too: Kiri data that was in the folder comes back.
    #[test]
    fn a_failed_commit_puts_back_what_was_there() {
        let d = scratch("commit");
        let (root, target) = (d.join("kiri"), d.join("before"));
        data(&root);
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("images.json"), b"[\"old\"]").unwrap();
        chosen::write_marker(&target).unwrap();
        // A file where storage.json's folder would be.
        std::fs::write(d.join("state"), b"").unwrap();
        let config = d.join("state/storage.json");
        let choice = Choice { path: target.clone(), previous: Some(root.clone()) };
        assert!(migrate(&one(&root, &target), &config, &choice, &mut |_, _| Ok(())).is_err());
        assert_eq!(std::fs::read(target.join("images.json")).unwrap(), b"[\"old\"]");
        assert!(!target.join("vm").exists() && !target.join(REPLACED).exists() && !target.join(MOVING).exists());
        assert!(chosen::has_marker(&target), "it held Kiri data before, and still does");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A Linux host moves the agent's folder too: /var/lib/kiri for the
    /// default data folder, `<folder>/agent` for a chosen one.
    #[test]
    fn a_linux_host_moves_the_agent_folder_too() {
        let (def, ext, agent) = (Path::new("/var/lib/kiri-daemon/.local/share/kiri"), Path::new("/media/ssd/kiri"), Path::new("/var/lib/kiri"));
        let p = parts(def, ext, def, Some(agent));
        assert_eq!(p[0], Part { from: def.into(), to: ext.into(), skip: vec!["agent"] });
        assert_eq!(p[1], Part { from: agent.into(), to: ext.join("agent"), skip: vec![] });
        let back = parts(ext, def, def, Some(agent));
        assert_eq!(back[1], Part { from: ext.join("agent"), to: agent.into(), skip: vec![] });
        assert_eq!(parts(def, ext, def, None), vec![Part { from: def.into(), to: ext.into(), skip: vec![] }]);
    }

    /// Starting fresh writes the marker and commits without copying old
    /// blobs, while keeping the old folder until Remove old data; a commit
    /// failure rolls back cleanly.
    #[test]
    fn start_fresh_switches_without_copying_and_rolls_back_on_error() {
        let d = scratch("fresh");
        let (root, target, config) = (d.join("kiri"), d.join("external/kiri"), d.join("state/storage.json"));
        data(&root);
        let choice = Choice { path: target.clone(), previous: Some(root.clone()) };
        migrate_fresh(&one(&root, &target), &config, &choice, &mut |_, _| Ok(())).unwrap();
        assert_eq!(chosen::read_at(&config).unwrap(), Some(choice));
        assert!(chosen::has_marker(&target));
        assert!(!target.join("images.json").exists(), "fresh target has no copied data");
        assert!(chosen::has_marker(&root) && root.join("images.json").is_file(), "old folder kept and marked");
        remove_old_folder(&root, &target).unwrap();
        assert!(!root.exists());
        // Failed commit on an existing fresh target rolls back cleanly.
        let target2 = d.join("fresh2");
        std::fs::write(d.join("blocked"), b"").unwrap();
        let bad_cfg = d.join("blocked/storage.json");
        let choice2 = Choice { path: target2.clone(), previous: Some(target.clone()) };
        assert!(migrate_fresh(&one(&target, &target2), &bad_cfg, &choice2, &mut |_, _| Ok(())).is_err());
        assert!(!target2.exists(), "newly made fresh folder is removed on rollback");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Starting fresh in a folder that holds earlier Kiri data sets that data
    /// aside; when setting one entry aside fails, the ones already set aside
    /// come back.
    #[test]
    fn start_fresh_failing_partway_brings_back_what_it_set_aside() {
        let d = scratch("fresh-partial");
        let (root, target, config) = (d.join("kiri"), d.join("external/kiri"), d.join("state/storage.json"));
        data(&root);
        data(&target);
        // In the order migrate_fresh will meet them.
        let names: Vec<_> = std::fs::read_dir(&target).unwrap().map(|e| e.unwrap().file_name()).collect();
        let last = names.last().unwrap();
        // What an interrupted earlier move left set aside under that name.
        std::fs::create_dir_all(target.join(REPLACED).join(last).join("left")).unwrap();
        let choice = Choice { path: target.clone(), previous: Some(root.clone()) };
        assert!(migrate_fresh(&one(&root, &target), &config, &choice, &mut |_, _| Ok(())).is_err());
        for n in &names {
            assert!(target.join(n).exists(), "{n:?} not brought back");
        }
        assert!(!config.exists(), "nothing committed");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A broken symlink or regular file at the target path is refused.
    #[test]
    fn non_directory_and_broken_symlink_targets_are_refused() {
        let d = scratch("nondir");
        let root = d.join("kiri");
        data(&root);
        let file = d.join("afile");
        std::fs::write(&file, b"hi").unwrap();
        assert!(check(&one(&root, &file)).unwrap_err().contains("isn't a folder"));
        let broken = d.join("broken");
        std::os::unix::fs::symlink(d.join("missing"), &broken).unwrap();
        assert!(check(&one(&root, &broken)).unwrap_err().contains("isn't a folder"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A chosen folder whose drive isn't connected is reported unavailable,
    /// with nothing made there.
    #[test]
    fn a_missing_marker_reports_storage_unavailable() {
        let d = scratch("unavailable");
        let gone = d.join("Volumes/External/kiri");
        let e = chosen::resolve(Some(Choice { path: gone.clone(), previous: None }), d.join("default")).unwrap_err();
        assert_eq!(chosen::unavailable(&e), Some(gone.as_path()));
        let s = status(&gone, true);
        assert_eq!(s["state"], "unavailable");
        assert_eq!(s["path"], gone.to_string_lossy().as_ref());
        assert!(s["used"].is_null() && s["free"].is_null());
        assert!(!gone.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Requests refused with 503 while storage is unavailable record their
    /// HTTP method and path on the connection thread so failure logs carry
    /// `method=GET path=/containers/json status=503` instead of empty fields.
    #[test]
    fn serve_unavailable_populates_method_and_path_on_503() {
        use std::io::{Read, Write};
        let d = scratch("unavailable-503");
        let gone = d.join("Volumes/External/kiri");
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .write_all(b"GET /v1.47/containers/json HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n")
            .unwrap();
        serve_unavailable(server, &gone).unwrap();
        assert_eq!(http::current_serving(), ("GET".to_owned(), "/containers/json".to_owned()));
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 503 "), "{resp}");
        assert!(resp.contains("Connection: close\r\n"), "{resp}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn reclaimable_threshold_and_data_img_allocated_bytes() {
        assert_eq!(reclaimable_bytes(None, Some(100)), None);
        assert_eq!(reclaimable_bytes(Some(100), None), None);
        assert_eq!(reclaimable_bytes(Some(100), Some(200)), Some(0));
        assert_eq!(reclaimable_bytes(Some(100 + RECLAIM_THRESHOLD), Some(100)), Some(0));
        assert_eq!(
            reclaimable_bytes(Some(100 + RECLAIM_THRESHOLD + 1), Some(100)),
            Some(RECLAIM_THRESHOLD + 1)
        );
        let d = scratch("reclaim-alloc");
        assert_eq!(data_img_allocated(&d), None);
        data(&d);
        let alloc = data_img_allocated(&d).unwrap();
        assert!(alloc < 1 << 20, "sparse data.img should allocate < 1 MiB, got {alloc}");
        let s = status_with(
            &d,
            false,
            DiskInfo {
                disk_host: Some(29_400_000_000),
                disk_in_use: Some(17_300_000_000),
                disk_limit: Some(64 << 30),
                reclaimable: reclaimable_bytes(Some(29_400_000_000), Some(17_300_000_000)),
                #[cfg(target_os = "linux")]
                fs_in_use: None,
                #[cfg(target_os = "linux")]
                fs_capacity: None,
            },
        );
        assert_eq!(s["disk_host"], 29_400_000_000u64);
        assert_eq!(s["disk_in_use"], 17_300_000_000u64);
        assert_eq!(s["disk_limit"], 64u64 << 30);
        assert_eq!(s["reclaimable"], 12_100_000_000u64);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn ext4_metadata_overhead_is_excluded_from_reclaimable_space() {
        // Mature 128 GiB disk (`137.44 GB` logical, `134.15 GB` statvfs capacity ->
        // `3.29 GB` ext4 journal + inode table overhead): `104.0 GB` on macOS with
        // `98.4 GB` of files promises only the `2.31 GB` that FITRIM can free, and
        // reports 0 reclaimable once `101.69 GB` remains after FITRIM.
        let logical = 128u64 << 30;
        let capacity = logical - 3_290_000_000;
        let raw_used = 98_400_000_000u64;
        let (in_use_before, clamped) = effective_vm_in_use(
            Some(104_000_000_000),
            Some(logical),
            Some(raw_used),
            Some(capacity),
            None,
        );
        assert_eq!(clamped, None);
        assert_eq!(in_use_before, Some(101_690_000_000));
        assert_eq!(reclaimable_bytes(Some(104_000_000_000), in_use_before), Some(2_310_000_000));

        // After FITRIM leaves `101.69 GB` on host, recorded overhead is `3.29 GB` and reclaimable is 0.
        let d = scratch("reclaim-overhead");
        std::fs::create_dir_all(d.join("vm")).unwrap();
        write_disk_overhead(&d, 3_290_000_000);
        assert_eq!(read_disk_overhead(&d), Some(3_290_000_000));
        let (in_use_after, _) = effective_vm_in_use(
            Some(101_690_000_000),
            Some(logical),
            Some(raw_used),
            Some(capacity),
            read_disk_overhead(&d),
        );
        assert_eq!(reclaimable_bytes(Some(101_690_000_000), in_use_after), Some(0));

        // Fresh sparse disk (< 1 GiB of files) before first trim does not over-subtract lazy overhead.
        let (fresh_used, _) = effective_vm_in_use(
            Some(2_020_000_000),
            Some(logical),
            Some(20_000_000),
            Some(capacity),
            None,
        );
        assert_eq!(fresh_used, Some(20_000_000));
        assert_eq!(reclaimable_bytes(Some(2_020_000_000), fresh_used), Some(2_000_000_000));

        // Online-grown un-resized disk (`logical >> capacity`) caps static overhead safely.
        assert!(max_ext4_overhead(256 << 30, 64 << 30) <= (4 << 30) + (512 << 20));
        let _ = std::fs::remove_dir_all(&d);
    }
}
