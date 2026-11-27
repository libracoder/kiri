//! Updates: the newest release, downloaded, checked and installed.
//!
//! The release feed is one small JSON file, `{"version", "url", "sha256"}`
//! (and optionally `notes`, Markdown for the window's What's new, and
//! `notes_url`, a runkiri.com page on it), at
//! `KIRI_UPDATE_URL` (default: `download.runkiri.com/latest-mac-arm64.json`,
//! and `latest-mac-x86_64.json` for the Intel build: each Mac has its own app). The
//! download is checked against the SHA-256, the installed app's own signing
//! identity, notarization and the version the feed promised before it is
//! staged beside the app in `.kiri-update/`. Installing swaps the staged app
//! in (checking it again first) and keeps the old one until the new one is
//! in place.
//!
//! The window (ui) downloads in the background, then installs on Restart
//! now, or when it quits after Later (or at its next launch, if that quit
//! never happened). `kiri update` does it all at once; `--check` only
//! reports.

use std::io::{self, Write};
#[cfg(target_os = "macos")]
use std::io::Read;
#[cfg(target_os = "macos")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_os = "macos")]
use sha2::{Digest, Sha256};

/// Each Mac reads its own feed, so a release for one never reaches the other
/// (and check() refuses an app without code for this CPU anyway).
#[cfg(all(target_os = "macos", not(target_arch = "x86_64")))]
const FEED: &str = "https://download.runkiri.com/latest-mac-arm64.json";
/// Intel Macs get the Intel app (`cargo xtask release --arch x86_64`).
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const FEED: &str = "https://download.runkiri.com/latest-mac-x86_64.json";
/// Linux reads only the version: its kiri is a .deb or .rpm installed from
/// runkiri.com, so nothing is downloaded from the feed.
#[cfg(target_os = "linux")]
const FEED: &str = "https://download.runkiri.com/latest.json";
/// Windows CLI checks the architecture's Windows release feed (`kiri-win`
/// performs background MSI updates from the window).
#[cfg(all(windows, not(target_arch = "aarch64")))]
const FEED: &str = "https://download.runkiri.com/latest-windows-x86_64.json";
#[cfg(all(windows, target_arch = "aarch64"))]
const FEED: &str = "https://download.runkiri.com/latest-windows-arm64.json";
/// The biggest download accepted (the app is about 60 MB packed).
#[cfg(target_os = "macos")]
const MAX_DOWNLOAD: u64 = 2 << 30;

#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
pub struct Release {
    pub version: String,
    pub url: String,
    pub sha256: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub notes_url: String,
}

/// Whether `v` reads as a version: `[v]N(.N)*`, optionally `-` and
/// dot-separated alphanumeric identifiers (`0.1.8-dev.42`).
fn is_version(v: &str) -> bool {
    let s = v.strip_prefix('v').unwrap_or(v);
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (s, None),
    };
    let numeric = |seg: &str| !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit());
    let ident = |id: &str| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    core.split('.').all(numeric) && pre.is_none_or(|p| p.split('.').all(ident))
}

/// `1.2.10` > `1.2.9`; a missing part counts as 0, and a test build
/// (`0.1.8-dev.42`, scripts/ci/test-version.sh) sorts above its release.
/// A string that isn't a version is never newer, and nothing is newer
/// than one.
pub fn newer(candidate: &str, current: &str) -> bool {
    if !is_version(candidate) || !is_version(current) {
        return false;
    }
    let parts = |v: &str| -> Vec<u64> { v.trim_start_matches('v').split(['.', '-']).map(|p| p.parse().unwrap_or(0)).collect() };
    let (a, b) = (parts(candidate), parts(current));
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x > y;
        }
    }
    false
}

/// The same guard the registry client (`kiri-image/src/connect.rs`) uses: a
/// read that sits silent this long fails, so a stalled server cannot hang
/// `kiri update`'s feed check or download forever.
const STALL: std::time::Duration = std::time::Duration::from_secs(60);

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(std::time::Duration::from_secs(10)))
        .timeout_per_read(Some(STALL))
        .user_agent(concat!("kiri/", env!("CARGO_PKG_VERSION")))
        // The system's roots merged with webpki's, like the registry client
        // (#303); the feed often sits behind a corporate proxy's CA.
        .tls_config(kiri_image::tls_config(&kiri_image::roots::trusted()))
        .build()
        .into()
}

fn feed_url(env_override: Option<&str>) -> &str {
    env_override.map(str::trim).filter(|u| !u.is_empty()).unwrap_or(FEED)
}

pub fn latest() -> io::Result<Release> {
    let env_val = std::env::var("KIRI_UPDATE_URL").ok();
    latest_from(feed_url(env_val.as_deref()))
}

fn latest_from(url: &str) -> io::Result<Release> {
    let release = (|| -> io::Result<Release> {
        let body = agent().get(url).call().map_err(io::Error::other)?.body_mut().with_config().limit(64 << 10).read_to_vec().map_err(io::Error::other)?;
        serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{url}: {e}")))
    })();
    #[cfg(unix)]
    match &release {
        Ok(r) => crate::diag::info!("update check", latest = r.version, current = env!("CARGO_PKG_VERSION")),
        Err(e) => crate::diag::warn!("update check failed", error = e),
    }
    release
}

/// The running Kiri.app.
#[cfg(target_os = "macos")]
pub fn app() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?.canonicalize()?;
    let app = exe.ancestors().find(|p| p.extension().is_some_and(|e| e == "app")).map(Path::to_path_buf);
    app.ok_or_else(|| io::Error::other("Kiri updates replace Kiri.app; this binary is not running from one"))
}

/// Prefix for private per-user staging directories beside `Kiri.app`.
#[cfg(target_os = "macos")]
const STAGE_PREFIX: &str = ".kiri-update-";

#[cfg(target_os = "macos")]
fn is_loopback_http(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    let (host, port) = if let Some(h) = authority.strip_prefix('[') {
        let Some((addr, after)) = h.split_once(']') else {
            return false;
        };
        let port = if after.is_empty() {
            None
        } else if let Some(p) = after.strip_prefix(':') {
            Some(p)
        } else {
            return false;
        };
        (addr, port)
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    if port.is_some_and(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit())) {
        return false;
    }
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

/// Validates a release download URL: requires `https://` (unless both the feed
/// override `KIRI_UPDATE_URL` and `url` are explicit loopback `http://` test URLs),
/// and rejects control characters or whitespace.
#[cfg(target_os = "macos")]
fn validate_download_url(url: &str, feed_override: Option<&str>) -> io::Result<bool> {
    if url.is_empty() || url.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid release download URL"));
    }
    if url.starts_with("https://") {
        return Ok(true);
    }
    if feed_override.is_some_and(is_loopback_http) && is_loopback_http(url) {
        return Ok(false);
    }
    Err(io::Error::new(io::ErrorKind::InvalidInput, "release download URL must use https://"))
}

/// Creates a unique, owner-only (`0o700`) staging directory beside `app` so
/// another local admin sharing `/Applications` cannot pre-create or swap files.
#[cfg(target_os = "macos")]
fn create_stage_dir(app: &Path) -> io::Result<PathBuf> {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::os::unix::fs::DirBuilderExt;

    let parent = app.parent().ok_or_else(|| io::Error::other("Kiri.app has no parent directory"))?;
    for attempt in 0..32u32 {
        let mut h = RandomState::new().build_hasher();
        h.write_u32(std::process::id());
        h.write_u32(attempt);
        let dir = parent.join(format!("{STAGE_PREFIX}{:016x}", h.finish()));
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, "could not create private update staging directory"))
}

/// True when `dir` is a non-symlink directory owned by this UID with no group
/// or world permissions (`mode & 0o077 == 0`).
#[cfg(target_os = "macos")]
fn is_own_private_dir(dir: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::symlink_metadata(dir) else {
        return false;
    };
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    meta.file_type().is_dir() && meta.uid() == euid && (meta.mode() & 0o077) == 0
}

/// Finds our private staged update directory beside `app`, if any.
#[cfg(target_os = "macos")]
fn find_stage_dir(app: &Path) -> Option<PathBuf> {
    let parent = app.parent()?;
    let entries = std::fs::read_dir(parent).ok()?;
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(STAGE_PREFIX) {
            continue;
        }
        let path = entry.path();
        if !is_own_private_dir(&path) {
            continue;
        }
        let mtime = std::fs::symlink_metadata(&path).and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH);
        if best.as_ref().is_none_or(|(t, _)| mtime >= *t) {
            best = Some((mtime, path));
        }
    }
    best.map(|(_, p)| p)
}

#[cfg(target_os = "macos")]
fn cleanup_own_stage_dirs(app: &Path) {
    let Some(parent) = app.parent() else { return };
    if let Ok(entries) = std::fs::read_dir(parent) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name == ".kiri-update" || name.starts_with(STAGE_PREFIX) {
                let path = entry.path();
                if is_own_private_dir(&path) {
                    let _ = std::fs::remove_dir_all(&path);
                }
            }
        }
    }
}

/// Downloads `release`, checks it and stages it for `install_staged`.
/// `progress` gets the bytes so far and the total when the server says;
/// setting `cancel` stops the download.
#[cfg(target_os = "macos")]
pub fn download(release: &Release, progress: &mut dyn FnMut(u64, Option<u64>), cancel: &AtomicBool) -> io::Result<()> {
    let app = app()?;
    if !newer(&release.version, env!("CARGO_PKG_VERSION")) {
        return Err(io::Error::other(format!("Kiri {} is not newer than this {}", release.version, env!("CARGO_PKG_VERSION"))));
    }
    cleanup_own_stage_dirs(&app);
    let dir = create_stage_dir(&app)?;
    crate::diag::info!("update download started", version = release.version);
    let result = fetch_and_check(release, &app, &dir, progress, cancel);
    match &result {
        Ok(()) => crate::diag::info!("update downloaded and checked", version = release.version),
        Err(e) if e.kind() == io::ErrorKind::Interrupted => crate::diag::info!("update download cancelled", version = release.version),
        Err(e) => crate::diag::warn!("update download failed", version = release.version, error = e),
    }
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    result
}

#[cfg(target_os = "macos")]
fn fetch_and_check(release: &Release, app: &Path, dir: &Path, progress: &mut dyn FnMut(u64, Option<u64>), cancel: &AtomicBool) -> io::Result<()> {
    let feed_override = std::env::var("KIRI_UPDATE_URL").ok();
    let https_only = validate_download_url(&release.url, feed_override.as_deref())?;
    // Download, hashing as it streams to disk. Reject HTTPS→HTTP downgrades on redirects.
    let tgz = dir.join("Kiri.tar.gz");
    let mut resp = agent().get(&release.url).config().https_only(https_only).build().call().map_err(io::Error::other)?;
    let total = resp.headers().get("content-length").and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
    let mut body = resp.body_mut().with_config().limit(MAX_DOWNLOAD).reader();
    let mut out = std::fs::File::create(&tgz)?;
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut got = 0u64;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        let n = body.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
        out.write_all(&buf[..n])?;
        got += n as u64;
        progress(got, total);
    }
    out.sync_all()?;
    let sum: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if !sum.eq_ignore_ascii_case(release.sha256.trim()) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("download does not match its SHA-256 (got {sum})")));
    }
    let unpacked = dir.join("unpacked");
    std::fs::create_dir_all(&unpacked)?;
    // A sparse-aware tar: the VM's disk template inside is mostly holes.
    if !Command::new("/usr/bin/tar").args(["-xzf"]).arg(&tgz).arg("-C").arg(&unpacked).status()?.success() {
        return Err(io::Error::other("could not unpack the update"));
    }
    let _ = std::fs::remove_file(&tgz);
    let new_app = unpacked.join("Kiri.app");
    check(&new_app, app, &release.version)?;
    std::fs::rename(&new_app, dir.join("Kiri.app"))?;
    let _ = std::fs::remove_dir_all(&unpacked);
    std::fs::write(dir.join("version"), &release.version)?;
    Ok(())
}

/// The staged update's version, when there is one newer than this build.
#[cfg(target_os = "macos")]
pub fn staged() -> Option<String> {
    let dir = find_stage_dir(&app().ok()?)?;
    let version = std::fs::read_to_string(dir.join("version")).ok()?.trim().to_owned();
    (dir.join("Kiri.app").is_dir() && newer(&version, env!("CARGO_PKG_VERSION"))).then_some(version)
}

/// Swaps the staged app in for the running one, checking it again first:
/// the folder sat on disk since the download. Returns its version.
#[cfg(target_os = "macos")]
pub fn install_staged() -> io::Result<String> {
    let app = app()?;
    let Some(dir) = find_stage_dir(&app) else {
        return Err(io::Error::other("no update is staged"));
    };
    let Some(version) = std::fs::read_to_string(dir.join("version"))
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|v| dir.join("Kiri.app").is_dir() && newer(v, env!("CARGO_PKG_VERSION")))
    else {
        return Err(io::Error::other("no update is staged"));
    };
    let new_app = dir.join("Kiri.app");
    check(&new_app, &app, &version).inspect_err(|e| crate::diag::error!("staged update failed its checks", version = version, error = e))?;
    // The old app moves aside, the new one takes its place, and the old one
    // is only deleted once the new one is there.
    let old = dir.join("Kiri.old.app");
    let _ = std::fs::remove_dir_all(&old);
    std::fs::rename(&app, &old)?;
    if let Err(e) = std::fs::rename(&new_app, &app) {
        let _ = std::fs::rename(&old, &app);
        crate::diag::error!("update install failed; the old app is back", version = version, error = e);
        return Err(e);
    }
    let _ = std::fs::remove_dir_all(&dir);
    crate::diag::info!("update installed", version = version, from = env!("CARGO_PKG_VERSION"));
    Ok(version)
}

/// Restarts the engine on the app's current binary and waits until it
/// answers as `expect` (the version now installed), which it returns.
/// Running containers stop; those with a restart policy start again.
///
/// The running engine is stopped whoever started it: the LaunchAgent, the
/// window (ensure_daemon, when it got there first) or a terminal. Asking
/// launchd alone (`kickstart -k`) missed the last two: the job it restarted
/// found the old engine still on the socket and exited, and the old one kept
/// running while the window said it had restarted.
#[cfg(target_os = "macos")]
pub fn restart_engine(expect: &str) -> io::Result<String> {
    crate::diag::info!("restarting the engine", version = expect);
    stop_engine()?;
    start_engine()?;
    let found = wait_for_version(expect, std::time::Duration::from_secs(60));
    match found {
        Some(v) if v == expect => {
            crate::diag::info!("engine restarted", version = v);
            Ok(v)
        }
        Some(v) => Err(io::Error::other(format!("the engine came back on {v}, not {expect}"))),
        None => Err(io::Error::other(format!("the engine did not come back; see {}", log_path().display()))),
    }
}

/// Starts the engine if it is not running: through the LaunchAgent when it
/// starts this copy of Kiri, so launchd owns the one engine there is, falling
/// back to spawning the daemon directly when `launchctl kickstart` exits 0
/// without bringing the engine up (#602). Returns once it answers.
#[cfg(target_os = "macos")]
pub fn start_engine() -> io::Result<()> {
    start_engine_with(
        crate::client::alive,
        crate::setup::start_agent,
        spawn_daemon,
        std::thread::sleep,
        || log_path().display().to_string(),
    )
}

#[cfg(any(target_os = "macos", test))]
fn start_engine_with(
    mut alive: impl FnMut() -> bool,
    start_agent: impl FnOnce() -> io::Result<bool>,
    spawn_daemon: impl FnOnce() -> io::Result<()>,
    mut sleep: impl FnMut(std::time::Duration),
    log_display: impl FnOnce() -> String,
) -> io::Result<()> {
    if alive() {
        return Ok(());
    }
    #[cfg(unix)]
    crate::diag::info!("starting the engine");
    if start_agent().unwrap_or(false) {
        for _ in 0..50 {
            if alive() {
                return Ok(());
            }
            sleep(std::time::Duration::from_millis(50));
        }
        #[cfg(unix)]
        crate::diag::warn!("LaunchAgent kickstart did not bring up engine; starting daemon directly");
    }
    spawn_daemon()?;
    for _ in 0..200 {
        if alive() {
            return Ok(());
        }
        sleep(std::time::Duration::from_millis(50));
    }
    Err(io::Error::other(format!("kiri daemon did not start; see {}", log_display())))
}

#[cfg(target_os = "macos")]
fn log_path() -> PathBuf {
    crate::client::socket().ok().and_then(|s| Some(s.parent()?.parent()?.join("daemon.log"))).unwrap_or_else(|| PathBuf::from("daemon.log"))
}

#[cfg(target_os = "macos")]
fn open_private_daemon_log(log_file: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    if let Some(dir) = log_file.parent() {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    }
    let log = std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(log_file)?;
    if log.metadata().is_ok_and(|m| m.is_file()) {
        let _ = log.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    Ok(log)
}

/// `kiri daemon` in its own session, so quitting the window does not take
/// it down; its output goes to daemon.log.
#[cfg(target_os = "macos")]
fn spawn_daemon() -> io::Result<()> {
    let log_file = log_path();
    let log = open_private_daemon_log(&log_file)?;
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.arg("daemon").stdin(std::process::Stdio::null()).stdout(log.try_clone()?).stderr(log);
    // SAFETY: setsid is async-signal-safe and runs in the child before exec.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut cmd, || {
            libc::setsid();
            Ok(())
        });
    }
    cmd.spawn()?;
    Ok(())
}

/// Stops the engine on the socket, if one answers: SIGTERM (it powers the
/// VM off and removes the socket), then SIGKILL if it is still there after
/// 30 seconds.
#[cfg(target_os = "macos")]
pub fn stop_engine() -> io::Result<()> {
    let Some(pid) = engine_pid() else { return Ok(()) };
    crate::diag::info!("stopping the engine", pid = pid);
    for (sig, wait) in [(libc::SIGTERM, 30_000u64), (libc::SIGKILL, 5_000)] {
        // SAFETY: kill on a pid we just read from the socket's peer.
        unsafe { libc::kill(pid, sig) };
        let began = std::time::Instant::now();
        while began.elapsed() < std::time::Duration::from_millis(wait) {
            // SAFETY: signal 0 only asks whether the process is there.
            if unsafe { libc::kill(pid, 0) } != 0 {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    Err(io::Error::other(format!("the engine (process {pid}) did not stop")))
}

/// The process answering on the engine's socket (macOS's LOCAL_PEERPID):
/// the engine itself, however it was started.
#[cfg(target_os = "macos")]
fn engine_pid() -> Option<libc::pid_t> {
    use std::os::fd::AsRawFd;
    let conn = std::os::unix::net::UnixStream::connect(crate::client::socket().ok()?).ok()?;
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: a valid socket, and a pid_t-sized buffer with its length.
    let r = unsafe { libc::getsockopt(conn.as_raw_fd(), libc::SOL_LOCAL, libc::LOCAL_PEERPID, (&mut pid as *mut libc::pid_t).cast(), &mut len) };
    (r == 0 && pid > 0).then_some(pid)
}

/// The engine's version once it answers as `expect`, or the last other
/// version it gave when `limit` runs out (None if it never answered).
#[cfg(target_os = "macos")]
pub fn wait_for_version(expect: &str, limit: std::time::Duration) -> Option<String> {
    let began = std::time::Instant::now();
    let mut last = None;
    while began.elapsed() < limit {
        if let Some(v) = crate::client::request("GET", "/version", None).ok().filter(|r| r.ok()).and_then(|r| crate::client::kiri_version(&r.json()).map(str::to_owned)) {
            if v == expect {
                return Some(v);
            }
            last = Some(v);
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    last
}

/// Whether `new_app` is a genuine Kiri `promised`, newer than this build.
#[cfg(target_os = "macos")]
fn check(new_app: &Path, app: &Path, promised: &str) -> io::Result<()> {
    // A valid signature is not enough: `--verify` alone passes for any
    // self-consistent signature, including an attacker's own Developer ID or
    // an ad-hoc one. Pin the update to the SAME signing identity as the app
    // already installed (its designated requirement), so only a genuine Kiri
    // release is accepted, and require Gatekeeper/notarization acceptance.
    let dr = Command::new("/usr/bin/codesign").args(["-d", "-r", "-"]).arg(app).output()?;
    let requirement = String::from_utf8_lossy(&dr.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("designated => ").map(str::to_owned))
        .filter(|r| !r.trim().is_empty());
    let Some(requirement) = requirement else {
        return Err(io::Error::other("cannot read the installed app's signing identity to check the update against"));
    };
    let mut verify = Command::new("/usr/bin/codesign");
    verify.args(["--verify", "--deep", "--strict"]).arg(format!("-R={requirement}"));
    if !verify.arg(new_app).status()?.success() {
        return Err(io::Error::other("the update is not signed by Kiri's own signing identity"));
    }
    if !Command::new("/usr/sbin/spctl").args(["-a", "-t", "exec"]).arg(new_app).status()?.success() {
        return Err(io::Error::other("the update is not notarized"));
    }
    // A replaced feed could point at an older, genuinely signed release and
    // its known bugs: the bundle must be the version the feed promised, and
    // that must be newer than this one. Read after the signature checks, so
    // only a verified file is parsed.
    // A feed for the other kind of Mac would install an app that does not
    // open here.
    let mut head = vec![0u8; 4096];
    let n = std::fs::File::open(new_app.join("Contents/MacOS/kiri"))?.read(&mut head)?;
    if !runs_here(&head[..n]) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("the update is not built for this Mac ({})", std::env::consts::ARCH)));
    }
    let plist = std::fs::read_to_string(new_app.join("Contents/Info.plist"))?;
    let Some(version) = bundle_version(&plist) else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "the update's Info.plist has no CFBundleShortVersionString"));
    };
    let promised = promised.trim_start_matches('v');
    if version != promised {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("the update is Kiri {version}, but the feed promised {promised}")));
    }
    if !newer(&version, env!("CARGO_PKG_VERSION")) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("the update is Kiri {version}, which is not newer than this {}", env!("CARGO_PKG_VERSION"))));
    }
    Ok(())
}

/// Whether a Mach-O executable (its first bytes) has code for this CPU:
/// a thin binary of this architecture, or a universal one with a slice of it.
#[cfg(any(target_os = "macos", test))]
fn runs_here(head: &[u8]) -> bool {
    const ARM64: u32 = 0x0100_000c;
    const X86_64: u32 = 0x0100_0007;
    let want = if cfg!(target_arch = "x86_64") { X86_64 } else { ARM64 };
    has_cpu(head, want)
}

#[cfg(any(target_os = "macos", test))]
fn has_cpu(head: &[u8], want: u32) -> bool {
    let word = |at: usize, be: bool| -> Option<u32> {
        let b: [u8; 4] = head.get(at..at + 4)?.try_into().ok()?;
        Some(if be { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) })
    };
    match word(0, true) {
        // MH_MAGIC_64, little-endian on disk: cputype follows.
        Some(0xcffa_edfe) => word(4, false) == Some(want),
        // FAT_MAGIC / FAT_MAGIC_64: big-endian, nfat_arch, then fat_arch
        // entries (20 or 32 bytes) that start with the cputype.
        Some(magic @ (0xcafe_babe | 0xcafe_babf)) => {
            let step = if magic == 0xcafe_babe { 20 } else { 32 };
            let count = word(4, true).unwrap_or(0).min(64) as usize;
            (0..count).any(|i| word(8 + i * step, true) == Some(want))
        }
        _ => false,
    }
}

#[cfg(target_os = "macos")]
const USAGE: &str = "usage: kiri update [--check]";
#[cfg(any(target_os = "linux", windows))]
const USAGE: &str = "usage: kiri update --check";

pub fn run(args: &[String]) -> io::Result<()> {
    run_with_lookup(args, crate::flavor::dev(), env!("CARGO_PKG_VERSION"), &mut io::stdout(), latest)
}

fn run_with_lookup(args: &[String], dev: bool, current: &str, out: &mut dyn Write, lookup: impl FnOnce() -> io::Result<Release>) -> io::Result<()> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        return writeln!(out, "{USAGE}");
    }
    if dev {
        return Err(io::Error::other(format!("{} doesn't update itself: rebuild it with `cargo xtask app-dev`", crate::flavor::APP)));
    }
    let release = lookup()?;
    run_release(args, &release, current, out)
}

fn run_release(args: &[String], release: &Release, current: &str, out: &mut dyn Write) -> io::Result<()> {
    if !newer(&release.version, current) {
        writeln!(out, "Kiri {current} is up to date")?;
        return Ok(());
    }
    writeln!(out, "Kiri {} is available (this is {current}){}", release.version, if release.notes.is_empty() { String::new() } else { format!(": {}", release.notes) })?;
    #[cfg(target_os = "linux")]
    {
        let _ = args;
        writeln!(out, "download the new .deb or .rpm from https://runkiri.com/releases/ and install it as before")?;
        Ok(())
    }
    #[cfg(windows)]
    {
        let _ = args;
        writeln!(out, "update from Kiri's window, or download the new installer from https://runkiri.com/releases/")?;
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        if args.iter().any(|a| a == "--check") {
            return Ok(());
        }
        download(release, &mut |_, _| {}, &AtomicBool::new(false))?;
        let version = install_staged()?;
        // The daemon runs from the app: restart it on the new binary.
        restart_engine(&version)?;
        writeln!(out, "updated to Kiri {version}, and the engine runs it")?;
        Ok(())
    }
}

/// `CFBundleShortVersionString` from an Info.plist: the key, then the next
/// `<string>`. The file is our own (xtask writes it as XML), so a scan does.
#[cfg(any(target_os = "macos", test))]
fn bundle_version(plist: &str) -> Option<String> {
    const KEY: &str = "<key>CFBundleShortVersionString</key>";
    let after = &plist[plist.find(KEY)? + KEY.len()..];
    let start = after.find("<string>")? + "<string>".len();
    let end = start + after[start..].find("</string>")?;
    Some(after[start..end].trim().to_owned()).filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read, Write};
    use std::net::TcpListener;

    use super::{Release, USAGE, bundle_version, has_cpu, latest_from, newer, run_with_lookup, runs_here};

    fn run_with(args: &[String], url: &str, current: &str, out: &mut dyn Write) -> io::Result<()> {
        run_with_lookup(args, false, current, out, || latest_from(url))
    }

    fn serve_feed(status: &'static str, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req = [0u8; 1024];
                let _ = stream.read(&mut req);
                let resp = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        format!("http://{addr}/latest.json")
    }

    #[test]
    fn help_skips_release_lookup() {
        #[cfg(target_os = "macos")]
        assert_eq!(USAGE, "usage: kiri update [--check]");
        #[cfg(any(target_os = "linux", windows))]
        assert_eq!(USAGE, "usage: kiri update --check");

        for dev in [false, true] {
            for (args, help) in [
                (&["--help"][..], true),
                (&["-h"], true),
                (&["--check", "--help"], true),
                (&[], false),
                (&["--check"], false),
            ] {
                let args = args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();
                let mut out = Vec::new();
                let mut looked_up = false;
                let result = run_with_lookup(&args, dev, "0.2.0", &mut out, || {
                    looked_up = true;
                    Err(io::Error::other("feed unavailable"))
                });
                if help {
                    assert!(!looked_up, "help must not look up release for {args:?} (dev={dev})");
                    result.unwrap();
                    assert_eq!(String::from_utf8(out).unwrap(), format!("{USAGE}\n"));
                } else if dev {
                    assert!(!looked_up, "dev guard must not look up release for {args:?}");
                    assert!(result.unwrap_err().to_string().contains("doesn't update itself"));
                } else {
                    assert!(looked_up, "expected release lookup for {args:?}");
                    assert_eq!(result.unwrap_err().to_string(), "feed unavailable");
                }
            }
        }
    }

    /// The update agent verifies against the merged roots, every one of
    /// them and in order, not the bundled set only (#303).
    #[test]
    fn the_update_agent_trusts_the_merged_roots() {
        let agent = super::agent();
        let ureq::tls::RootCerts::Specific(certs) = agent.config().tls_config().root_certs() else {
            panic!("the update agent must trust a list of roots of its own");
        };
        let roots = kiri_image::roots::trusted();
        assert_eq!(certs.len(), roots.len());
        assert!(certs.iter().zip(roots.iter()).all(|(a, b)| a.der() == b.as_ref()));
    }

    #[test]
    fn compares_versions() {
        assert!(newer("0.2.0", "0.1.9"));
        assert!(newer("1.2.10", "1.2.9"));
        assert!(newer("v1.0.1", "1.0"));
        assert!(!newer("1.0.0", "1.0"));
        assert!(!newer("0.1.0", "0.1.0"));
        assert!(!newer("0.1.0", "0.2.0"));
        // A test build (scripts/ci/test-version.sh) sorts above its release.
        assert!(newer("0.1.8-dev.42", "0.1.8"));
        assert!(!newer("0.1.8", "0.1.8-dev.42"));
        assert!(newer("0.1.8-dev.43", "0.1.8-dev.42"));
        for bad in ["", "vv1.0.0", "1.+2.0", "1.2.", "1.2.0-", "1.2.0-rc..1", "99.0.0/../../evil", "99.0.0\\evil"] {
            assert!(!newer(bad, "0.2.0"), "accepted invalid candidate {bad:?}");
            assert!(!newer("99.0.0", bad), "accepted invalid current {bad:?}");
        }
    }

    #[test]
    fn reads_the_bundle_version() {
        let plist = "<plist><dict>\n  <key>CFBundleVersion</key><string>7</string>\n  <key>CFBundleShortVersionString</key>\n  <string> 0.3.1 </string>\n</dict></plist>";
        assert_eq!(bundle_version(plist).as_deref(), Some("0.3.1"));
        assert_eq!(bundle_version("<plist><dict><key>CFBundleVersion</key><string>7</string></dict></plist>"), None);
        assert_eq!(bundle_version("<key>CFBundleShortVersionString</key><string></string>"), None);
    }

    #[test]
    fn checks_the_update_is_for_this_mac() {
        let thin = |cpu: u32| [0xcfu8, 0xfa, 0xed, 0xfe].into_iter().chain(cpu.to_le_bytes()).chain([0; 8]).collect::<Vec<u8>>();
        assert!(has_cpu(&thin(0x0100_000c), 0x0100_000c));
        assert!(!has_cpu(&thin(0x0100_0007), 0x0100_000c));
        // Universal: x86_64 then arm64.
        let mut fat = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2];
        for cpu in [0x0100_0007u32, 0x0100_000c] {
            fat.extend(cpu.to_be_bytes());
            fat.extend([0; 16]);
        }
        assert!(has_cpu(&fat, 0x0100_000c) && has_cpu(&fat, 0x0100_0007));
        assert!(!has_cpu(&fat[..12], 0x0100_000c));
        assert!(!has_cpu(b"#!/bin/sh\n", 0x0100_000c));
        // This test binary itself.
        let me = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        assert!(cfg!(not(target_os = "macos")) || runs_here(&me[..4096]));
    }

    #[test]
    fn reads_feeds_with_and_without_notes_url() {
        let r: Release = serde_json::from_str(r#"{"version":"0.1.1","url":"https://x/K.tar.gz","sha256":"ab"}"#).unwrap();
        assert_eq!(r.notes_url, "");
        let r: Release = serde_json::from_str(r#"{"version":"0.1.1","url":"u","sha256":"ab","notes_url":"https://runkiri.com/"}"#).unwrap();
        assert_eq!(r.notes_url, "https://runkiri.com/");
        let r: Release = serde_json::from_str(r###"{"version":"0.1.5","url":"u","sha256":"ab","notes":"## New\n- a line"}"###).unwrap();
        assert_eq!(r.notes, "## New\n- a line");
    }

    #[test]
    fn reports_up_to_date_when_feed_is_not_newer() {
        let url = serve_feed("200 OK", r#"{"version":"0.0.1","url":"https://runkiri.com/download","sha256":""}"#);
        let mut out = Vec::new();
        run_with(&["--check".into()], &url, "0.2.0", &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "Kiri 0.2.0 is up to date\n");

        let url = serve_feed("200 OK", r#"{"version":"0.0.0","url":"https://runkiri.com/download","sha256":""}"#);
        let mut out = Vec::new();
        run_with(&["--check".into()], &url, env!("CARGO_PKG_VERSION"), &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), format!("Kiri {} is up to date\n", env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn reports_newer_version_from_feed() {
        let url = serve_feed("200 OK", r#"{"version":"99.0.0","url":"https://runkiri.com/download","sha256":""}"#);
        let mut out = Vec::new();
        run_with(&["--check".into()], &url, env!("CARGO_PKG_VERSION"), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with(&format!("Kiri 99.0.0 is available (this is {})\n", env!("CARGO_PKG_VERSION"))), "got {text:?}");
        if cfg!(target_os = "linux") {
            assert!(text.contains("download the new .deb or .rpm from https://runkiri.com/releases/ and install it as before\n"), "got {text:?}");
            let url = serve_feed("200 OK", r#"{"version":"99.0.0","url":"https://runkiri.com/download","sha256":""}"#);
            let mut bare_out = Vec::new();
            run_with(&[], &url, env!("CARGO_PKG_VERSION"), &mut bare_out).unwrap();
            assert_eq!(String::from_utf8(bare_out).unwrap(), text);
        }
        if cfg!(windows) {
            assert!(text.contains("update from Kiri's window, or download the new installer from https://runkiri.com/releases/\n"), "got {text:?}");
            let url = serve_feed("200 OK", r#"{"version":"99.0.0","url":"https://runkiri.com/download","sha256":""}"#);
            let mut bare_out = Vec::new();
            run_with(&[], &url, env!("CARGO_PKG_VERSION"), &mut bare_out).unwrap();
            assert_eq!(String::from_utf8(bare_out).unwrap(), text);
        }
    }

    #[test]
    fn rejects_malformed_json_and_http_500() {
        assert_eq!(super::feed_url(None), super::FEED);
        assert_eq!(super::feed_url(Some("")), super::FEED);
        assert_eq!(super::feed_url(Some("   ")), super::FEED);
        assert_eq!(super::feed_url(Some("https://example.com/feed.json")), "https://example.com/feed.json");

        let bad_json = serve_feed("200 OK", "{not json");
        let err = latest_from(&bad_json).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let err_500 = serve_feed("500 Internal Server Error", r#"{"error":"boom"}"#);
        assert!(latest_from(&err_500).is_err());
    }

    #[test]
    fn routes_container_update_to_docker_and_self_update_to_kiri() {
        let a = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(crate::docker::is_container_update(&a(&["--memory", "128m", "c1"])));
        assert!(crate::docker::is_container_update(&a(&["--cpus", "2", "my-ctr"])));
        assert!(!crate::docker::is_container_update(&a(&["--check"])));
        assert!(!crate::docker::is_container_update(&a(&["--help"])));
        assert!(!crate::docker::is_container_update(&a(&["-h"])));
        assert!(!crate::docker::is_container_update(&a(&[])));
    }

    /// Regression test for #602: when `launchctl kickstart` exits 0 without
    /// actually starting the daemon, `start_engine` waits 2.5s (`50 * 50ms`),
    /// then spawns the daemon directly and polls for up to 10s (`200 * 50ms`).
    #[test]
    fn start_engine_falls_back_to_direct_spawn_when_kickstart_leaves_daemon_down() {
        use std::cell::Cell;
        use std::time::Duration;

        let polls = Cell::new(0usize);
        let spawned = Cell::new(false);
        let sleeps = Cell::new(0usize);
        super::start_engine_with(
            || {
                let n = polls.get() + 1;
                polls.set(n);
                n >= 4
            },
            || Ok(true),
            || {
                spawned.set(true);
                Ok(())
            },
            |_| sleeps.set(sleeps.get() + 1),
            || "/tmp/daemon.log".into(),
        )
        .unwrap();
        assert!(!spawned.get(), "healthy LaunchAgent must not spawn a second daemon");
        assert_eq!(sleeps.get(), 2);

        let polls = Cell::new(0usize);
        let spawned = Cell::new(false);
        let total_ms = Cell::new(0u64);
        super::start_engine_with(
            || {
                let n = polls.get() + 1;
                polls.set(n);
                spawned.get() && n >= 55
            },
            || Ok(true),
            || {
                assert_eq!(total_ms.get(), 2500, "fallback runs after 50 * 50ms");
                spawned.set(true);
                Ok(())
            },
            |d: Duration| total_ms.set(total_ms.get() + d.as_millis() as u64),
            || "/tmp/daemon.log".into(),
        )
        .unwrap();
        assert!(spawned.get());

        let total_ms = Cell::new(0u64);
        let err = super::start_engine_with(
            || false,
            || Ok(true),
            || Ok(()),
            |d: Duration| total_ms.set(total_ms.get() + d.as_millis() as u64),
            || "/custom/daemon.log".into(),
        )
        .unwrap_err();
        assert_eq!(total_ms.get(), 12_500);
        assert!(err.to_string().contains("/custom/daemon.log"), "{err}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn update_download_url_requires_https_and_stage_dir_and_log_are_private() {
        use std::os::unix::fs::PermissionsExt;
        use super::{STAGE_PREFIX, create_stage_dir, find_stage_dir, open_private_daemon_log, validate_download_url};

        assert!(validate_download_url("https://download.runkiri.com/Kiri.tar.gz", None).unwrap());
        assert!(validate_download_url("http://download.runkiri.com/Kiri.tar.gz", None).is_err());
        assert!(validate_download_url("http://127.0.0.1:8080/Kiri.tar.gz", None).is_err());
        assert!(validate_download_url("file:///tmp/Kiri.tar.gz", None).is_err());
        assert!(validate_download_url("https://download.runkiri.com/Kiri\r\n.tar.gz", None).is_err());
        // Local test override permits loopback http only when feed override is also loopback http.
        assert!(!validate_download_url("http://127.0.0.1:8080/Kiri.tar.gz", Some("http://127.0.0.1:8080/latest.json")).unwrap());
        assert!(!validate_download_url("http://[::1]:8080/Kiri.tar.gz", Some("http://[::1]:8080/latest.json")).unwrap());
        assert!(validate_download_url("http://[::1]@evil.com/Kiri.tar.gz", Some("http://127.0.0.1:8080/latest.json")).is_err());
        assert!(validate_download_url("http://127.0.0.1@evil.com/Kiri.tar.gz", Some("http://127.0.0.1:8080/latest.json")).is_err());
        assert!(validate_download_url("http://[::1]evil.com/Kiri.tar.gz", Some("http://127.0.0.1:8080/latest.json")).is_err());

        let root = std::env::temp_dir().join(format!("kiri-update-sec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let fake_app = root.join("Kiri.app");
        let stage = create_stage_dir(&fake_app).unwrap();
        assert_eq!(std::fs::metadata(&stage).unwrap().permissions().mode() & 0o777, 0o700);
        assert!(stage.file_name().unwrap().to_str().unwrap().starts_with(STAGE_PREFIX));
        assert_eq!(find_stage_dir(&fake_app).as_deref(), Some(stage.as_path()));

        let log = root.join("state/daemon.log");
        let _f = open_private_daemon_log(&log).unwrap();
        assert_eq!(std::fs::metadata(&log).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(log.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);

        let _ = std::fs::remove_dir_all(&root);
    }
}
