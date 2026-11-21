//! First run on Windows: from a PC with no WSL to `docker run` working, in
//! the window (setup.html; the protocol is in setup-protocol.md). Steps:
//! WSL (downloaded with progress, installed after one administrator
//! approval, then a restart), a Linux for Kiri (Kiri Linux, from the
//! bundle; or Ubuntu, downloaded), the engine, the Docker tools, ready.
//! Progress lives in %LOCALAPPDATA%\Kiri\setup.json, so a restart resumes.

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::app::Handle;
use crate::engine::{tr, trf};

/// A file setup downloads: what it is, from where, and what it must hash to.
#[derive(Debug)]
struct Pin {
    name: &'static str,
    url: &'static str,
    sha256: &'static str,
    size: u64,
    file: &'static str,
}

/// GitHub's asset digest for the release. WSL ships one MSI per
/// architecture; this build's own (see crate::win::arch_mismatch).
#[cfg(not(target_arch = "aarch64"))]
const WSL_MSI: Pin = Pin {
    name: "WSL 3.0.3",
    url: "https://github.com/microsoft/WSL/releases/download/3.0.3/wsl.3.0.3.0.x64.msi",
    sha256: "ae977286974255bd26bf925f00f40f5692c6b2084155cbc0563c09aea091f211",
    size: 367_575_040,
    file: "wsl.3.0.3.0.x64.msi",
};
#[cfg(target_arch = "aarch64")]
const WSL_MSI: Pin = Pin {
    name: "WSL 3.0.3",
    url: "https://github.com/microsoft/WSL/releases/download/3.0.3/wsl.3.0.3.0.arm64.msi",
    sha256: "2937c7ce840bb35ec6e97f052189bdfff27f8c3463bfdd231df9a958212787a3",
    size: 341_086_208,
    file: "wsl.3.0.3.0.arm64.msi",
};

/// Microsoft's WSL distribution list gives the hash (DistributionInfo.json
/// in microsoft/WSL: Amd64Url and Arm64Url).
#[cfg(not(target_arch = "aarch64"))]
const UBUNTU: Pin = Pin {
    name: "Ubuntu 26.04",
    url: "https://releases.ubuntu.com/26.04.1/ubuntu-26.04.1-wsl-amd64.wsl",
    sha256: "48d56724b5c8e60f24893e83e73bbb58c60b3ca22fba3da977075420acd54104",
    size: 418_495_746,
    file: "ubuntu-26.04.1-wsl-amd64.wsl",
};
#[cfg(target_arch = "aarch64")]
const UBUNTU: Pin = Pin {
    name: "Ubuntu 26.04",
    url: "https://cdimages.ubuntu.com/releases/26.04.1/release/ubuntu-26.04.1-wsl-arm64.wsl",
    sha256: "c7d893d7ccb291009e6096c5a946937337b6fd4c426f11b6541f6cd2bf894f7d",
    size: 412_840_386,
    file: "ubuntu-26.04.1-wsl-arm64.wsl",
};
const UBUNTU_DISTRO: &str = "Ubuntu-26.04";
pub(crate) const KIRI_DISTRO: &str = "kiri";

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Saved {
    done: bool,
    /// "kiri" or "ubuntu".
    linux: Option<String>,
    distro: Option<String>,
    /// Unix seconds of the WSL install that needs a restart.
    restart_after: Option<u64>,
    /// Unix seconds of the last time setup turned WSL's optional components
    /// on and went to the restart step for them.
    components_on_at: Option<u64>,
    /// Why setup last stopped, kept so a restart of Kiri doesn't lose it.
    last_error: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Task {
    label: String,
    state: &'static str,
    detail: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct State {
    step: &'static str,
    linux: Option<String>,
    sizes: Value,
    existing_ubuntu: bool,
    other_docker: bool,
    /// The engine besides Kiri, by name (crate::buildwith), for the build question.
    other_engine: Option<&'static str>,
    make_default: bool,
    /// Builds on Kiri: the answer to "Keep building with Docker / Build
    /// with Kiri", asked only with another engine here.
    build_kiri: bool,
    autostart: bool,
    /// A first start: the page asks for the language before anything else.
    ask_lang: bool,
    progress: Option<Value>,
    tasks: Vec<Task>,
    log: Vec<String>,
    error: Option<String>,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);
static BUSY: AtomicBool = AtomicBool::new(false);
static CANCEL: AtomicBool = AtomicBool::new(false);

fn dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("Kiri")).unwrap_or_else(|| PathBuf::from("."))
}

fn saved() -> Saved {
    std::fs::read(dir().join("setup.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

/// The WSL distro setup put the engine in, if it has.
pub(crate) fn saved_distro() -> Option<String> {
    saved().distro
}

fn save(s: &Saved) {
    let _ = std::fs::create_dir_all(dir());
    let _ = std::fs::write(dir().join("setup.json"), serde_json::to_vec_pretty(s).unwrap_or_default());
}

/// The distro setup put Kiri in, for the bridge.
pub fn distro() -> Option<String> {
    saved().distro
}

/// The SHA-256 of each bundle file, embedded at build time by
/// `cargo xtask windows` (`name=hash;…`). A dev build has none.
const BUNDLE_SHA256: Option<&str> = option_env!("KIRI_BUNDLE_SHA256");

/// A file from the bundle, checked against its embedded SHA-256 so a file
/// swapped in the unzipped folder (a drive-by download, another process)
/// is refused rather than imported into WSL or installed on PATH. With no
/// embedded hashes (a dev build) the file is used as is.
pub(crate) fn verified(rel: &str) -> io::Result<PathBuf> {
    let path = bundle().join(rel);
    let Some(want) = BUNDLE_SHA256.and_then(|m| m.split(';').find_map(|e| e.strip_prefix(rel).and_then(|r| r.strip_prefix('=')))) else {
        // A debug build (plain `cargo build`) has no manifest and uses the
        // file as is. A release must have one: otherwise building kiri-win on
        // its own would quietly skip every bundle check.
        if cfg!(debug_assertions) {
            return Ok(path);
        }
        return Err(io::Error::other(format!("this build carries no checksum for {rel}; build the bundle with `cargo xtask windows`")));
    };
    if !path.is_file() {
        return Err(io::Error::other(format!("{rel} is missing from Kiri's folder")));
    }
    let got = sha256(&path)?;
    if got != want {
        return Err(io::Error::other(format!("{rel} in Kiri's folder does not match this build (SHA-256 {got}); download Kiri again")));
    }
    Ok(path)
}

/// Where kiri-win was started from: the unzipped bundle on first run. Debug
/// builds run from target/debug use the bundle made by `cargo xtask windows-dev`.
fn bundle() -> PathBuf {
    let local = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)).unwrap_or_default();
    #[cfg(debug_assertions)]
    if !local.join("kiri-linux.tar.gz").is_file() {
        let bundled = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../target/kiri-windows-{}", std::env::consts::ARCH));
        if bundled.join("kiri-linux.tar.gz").is_file() {
            return bundled;
        }
    }
    local
}

fn quiet(program: &str) -> Command {
    let mut c = crate::win::tool(program);
    std::os::windows::process::CommandExt::creation_flags(&mut c, CREATE_NO_WINDOW);
    c.stdin(Stdio::null());
    c
}

/// WSL's own messages are UTF-16LE, in the language of the Windows it runs
/// on; what a Linux program prints through wsl.exe is UTF-8. WSL's UTF-16
/// always has ASCII in it (its `Wsl/...` error codes, CRLFs, spaces), whose
/// units carry a NUL high byte at an odd offset; UTF-8 text has none. So a
/// byte-order mark, or such NULs in at least a quarter of the units, reads
/// as UTF-16LE, and anything else as UTF-8. UTF-16 with no ASCII and no BOM
/// at all is the one thing this cannot tell from UTF-8. NULs and a leading
/// BOM are dropped either way.
fn wsl_text(bytes: &[u8]) -> String {
    let (bytes, bom) = bytes.strip_prefix(&[0xFF, 0xFE]).map_or((bytes, false), |rest| (rest, true));
    let text = if bom || looks_utf16(bytes) {
        let (pairs, rest) = bytes.as_chunks::<2>();
        let units: Vec<u16> = pairs.iter().map(|&p| u16::from_le_bytes(p)).collect();
        let mut text = String::from_utf16_lossy(&units);
        // Output cut short mid-unit: an ASCII low byte is still its letter.
        if let [last] = rest
            && last.is_ascii()
        {
            text.push(char::from(*last));
        }
        text
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };
    text.trim_start_matches('\u{feff}').replace('\0', "")
}

/// Whether `bytes` (no BOM) has the odd-offset NULs of UTF-16LE ASCII units
/// in at least a quarter of its units. Two at least: a stray NUL in short
/// UTF-8 is not UTF-16.
fn looks_utf16(bytes: &[u8]) -> bool {
    let units = bytes.len() / 2;
    let ascii = bytes.as_chunks::<2>().0.iter().filter(|&&[lo, hi]| lo != 0 && hi == 0).count();
    ascii >= 2 && ascii * 4 >= units
}

/// What `wsl.exe --version` said.
#[derive(Debug, PartialEq)]
enum Wsl {
    /// It answered: WSL is installed.
    There,
    /// It failed, or there is no wsl.exe: WSL is not installed.
    Missing,
    /// It ran past its limit (killed): WSL is there, only not answering;
    /// the text says so.
    Silent(String),
}

/// The most `wsl.exe --version` or `wsl.exe -l -q` may take when Kiri
/// works out whether to open setup, and at which step.
/// It reads WSL's installed version and answers in well under a second;
/// right after Windows starts or wakes the WSL service can take a few
/// seconds more. WSL_LIMIT (60 s) is sized for calls that start the VM and
/// run something in it: too long for a first-run window to sit empty.
const WSL_ANSWER_LIMIT: Duration = Duration::from_secs(15);

fn wsl_check(cmd: &mut Command, limit: Duration) -> Wsl {
    match crate::update::output_within(cmd, limit) {
        Ok(o) if o.status.success() => Wsl::There,
        Err(e) if e.kind() == io::ErrorKind::TimedOut => Wsl::Silent(e.to_string()),
        _ => Wsl::Missing,
    }
}

fn wsl_answer() -> Wsl {
    wsl_check(quiet("wsl.exe").arg("--version"), WSL_ANSWER_LIMIT)
}

/// WSL's distros, or None when WSL did not answer: wsl.exe failed, or ran
/// past WSL_ANSWER_LIMIT. Empty when there is nothing to list: no
/// distros, no WSL turned on, or no wsl.exe at all. `wsl -l` starts no VM,
/// so it gets the same limit as `wsl --version`: needed() asks it before
/// the window opens, which must not sit unseen for WSL_LIMIT.
pub(crate) fn distros() -> Option<Vec<String>> {
    listed_by(quiet("wsl.exe").args(["-l", "-q"]), WSL_ANSWER_LIMIT)
}

/// What `cmd` (wsl.exe -l -q) lists, as distros() says it.
fn listed_by(cmd: &mut Command, limit: Duration) -> Option<Vec<String>> {
    let o = match crate::update::output_within(cmd, limit) {
        Ok(o) => o,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Some(Vec::new()),
        Err(_) => return None,
    };
    if !o.status.success() {
        return (nothing_listed(&o.stdout) || nothing_listed(&o.stderr)).then(Vec::new);
    }
    Some(wsl_text(&o.stdout).lines().map(|l| l.trim().to_owned()).filter(|l| !l.is_empty()).collect())
}

/// Whether WSL's output carries one of its error codes. They are ASCII and
/// read the same in every language: with the NULs gone they match in UTF-16
/// at any length or offset, and in UTF-8, whatever the translated text
/// around them.
fn wsl_says(out: &[u8], codes: &[&str]) -> bool {
    let text = String::from_utf8_lossy(out).replace('\0', "");
    codes.iter().any(|code| text.contains(code))
}

/// Whether a failed `wsl.exe -l` said there is nothing to list, rather than
/// that WSL did not answer.
fn nothing_listed(out: &[u8]) -> bool {
    wsl_says(out, &["WSL_E_DEFAULT_DISTRO_NOT_FOUND", "WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED"])
}

/// Whether WSL's output says its optional component is off.
fn component_required(out: &[u8]) -> bool {
    wsl_says(out, &["WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED"])
}

/// Whether `wsl.exe -l -q` failed because WSL's optional component is off.
fn components_off() -> bool {
    crate::update::output_within(quiet("wsl.exe").args(["-l", "-q"]), WSL_ANSWER_LIMIT).is_ok_and(|o| !o.status.success() && (component_required(&o.stdout) || component_required(&o.stderr)))
}

fn existing_ubuntu() -> Option<String> {
    distros().unwrap_or_default().into_iter().find(|d| d.starts_with("Ubuntu"))
}

/// Another Docker on this PC: Docker Desktop, or a docker CLI on PATH that is not Kiri's.
fn other_docker() -> bool {
    let desktop = std::env::var_os("ProgramFiles").is_some_and(|p| Path::new(&p).join(r"Docker\Docker\Docker Desktop.exe").is_file());
    let ours = dir().join("bin");
    let on_path = std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d != ours && d.join("docker.exe").is_file()));
    desktop || on_path
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Whether Windows has restarted since `at`.
fn restarted_since(at: u64) -> bool {
    // SAFETY: reads the system's uptime.
    let uptime = unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() } / 1000;
    now_secs().saturating_sub(uptime) > at
}

/// Whether the window should open on setup rather than Kiri.
pub fn needed() -> bool {
    let s = saved();
    needs_setup(s.done, s.distro.as_deref(), distros)
}

/// Setup is needed when it never finished, or its distro has gone from
/// WSL's list. A WSL that does not answer (`listed` gives None) is not a
/// missing one: the main window says why the engine is down.
fn needs_setup(done: bool, distro: Option<&str>, listed: impl FnOnce() -> Option<Vec<String>>) -> bool {
    !done || distro.is_none_or(|d| listed().is_some_and(|l| !l.iter().any(|x| x == d)))
}

/// The step to show now, from what is on this PC, and why WSL did not
/// answer when it didn't.
fn current_step(s: &Saved) -> (&'static str, Option<String>) {
    step_from(wsl_answer(), s, restarted_since, components_off, || match &s.distro {
        Some(d) if distros().is_some_and(|l| l.iter().any(|x| x == d)) => {
            if crate::client::alive() {
                "tools"
            } else {
                "engine"
            }
        }
        _ => "choose",
    })
}

/// What setup turned on and a restart did not bring.
const COMPONENTS_STILL_OFF: &str = "WSL's optional components are still off after Windows restarted. Check that Windows Subsystem for Linux and Virtual Machine Platform are on in Windows Features, then try again";

/// current_step from what WSL answered, with the PC's checks passed in:
/// `restarted` (since a time), `components_off`, and `installed`, the step
/// for a WSL that is ready.
fn step_from(answer: Wsl, s: &Saved, restarted: impl Fn(u64) -> bool, components_off: impl FnOnce() -> bool, installed: impl FnOnce() -> &'static str) -> (&'static str, Option<String>) {
    let silent = match answer {
        Wsl::Missing => return ("welcome", None),
        Wsl::There => None,
        Wsl::Silent(why) => Some(why),
    };
    if let Some(at) = s.restart_after
        && !restarted(at)
    {
        return ("restart", None);
    }
    // Not answering is not missing: Choose a Linux, saying why, rather than
    // Install WSL (or asking for its distros, which would hang too).
    if silent.is_some() {
        return ("choose", silent);
    }
    // wsl.exe answers, but WSL's optional component is off (a setup before
    // this one turned on Virtual Machine Platform alone): no distro would
    // import, so step 1 again, which turns the components on. When setup
    // turned them on already and Windows has restarted since, step 1 says
    // so rather than only asking again.
    if components_off() {
        let why = s.components_on_at.is_some_and(&restarted).then(|| COMPONENTS_STILL_OFF.to_owned());
        return ("welcome", why);
    }
    (installed(), None)
}

/// `existing_ubuntu`: whether WSL lists an Ubuntu, asked only of a WSL that answered.
fn fresh_state(step: &'static str, s: &Saved, existing_ubuntu: bool) -> State {
    let other = other_docker();
    State {
        step,
        linux: s.linux.clone(),
        sizes: json!({"wsl": WSL_MSI.size, "ubuntu": UBUNTU.size, "kiri": std::fs::metadata(bundle().join("kiri-linux.tar.gz")).map_or(0, |m| m.len())}),
        existing_ubuntu,
        other_docker: other,
        other_engine: crate::buildwith::other_engine(),
        make_default: !other,
        build_kiri: !other,
        autostart: true,
        ask_lang: crate::engine::fresh() && crate::engine::prefs()["langAsked"] != true,
        progress: None,
        tasks: Vec::new(),
        log: Vec::new(),
        error: None,
    }
}

fn update(f: impl FnOnce(&mut State)) {
    let json = {
        let mut st = STATE.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(s) = st.as_mut() else { return };
        f(s);
        let mut v = serde_json::to_value(&*s).unwrap_or(Value::Null);
        v["type"] = json!("setup");
        v.to_string()
    };
    Handle.eval(format!("window.kiri && kiri.on({json})"));
}

fn tasks(labels: &[String]) -> Vec<Task> {
    labels.iter().map(|l| Task { label: l.clone(), state: "todo", detail: String::new() }).collect()
}

fn task(i: usize, state: &'static str, detail: &str) {
    update(|s| {
        if let Some(t) = s.tasks.get_mut(i) {
            t.state = state;
            t.detail = detail.to_owned();
        }
        // An unsized step's progress follows its tasks.
        let n = s.tasks.len().max(1);
        let done = s.tasks.iter().filter(|t| t.state == "done").count();
        if s.progress.as_ref().is_none_or(|p| p["total"].is_null()) {
            let label = s.tasks.iter().find(|t| t.state == "active").map_or(String::new(), |t| t.label.clone());
            s.progress = Some(json!({"pct": done * 100 / n, "done": null, "total": null, "rate": null, "eta": null, "label": label}));
        }
    });
}

fn log_line(line: &str) {
    let line = line.trim().to_owned();
    if !line.is_empty() {
        update(|s| {
            s.log.push(line);
            let n = s.log.len();
            if n > 8 {
                s.log.drain(..n - 8);
            }
        });
    }
}

/// Runs a step's work on its own thread; an error stays on its screen with "Try again".
fn run(step: &'static str, work: impl FnOnce() -> io::Result<()> + Send + 'static) {
    if BUSY.swap(true, Ordering::SeqCst) {
        return;
    }
    CANCEL.store(false, Ordering::SeqCst);
    update(|s| {
        s.step = step;
        s.error = None;
        s.progress = None;
        s.log.clear();
    });
    std::thread::spawn(move || {
        let r = work();
        BUSY.store(false, Ordering::SeqCst);
        if let Err(e) = r {
            crate::serve::log(&format!("setup {step}: {e}"));
            let cancelled = CANCEL.load(Ordering::SeqCst);
            if !cancelled {
                let mut saved = saved();
                saved.last_error = Some(e.to_string());
                save(&saved);
            }
            update(|s| {
                if cancelled {
                    s.step = if step == "wsl" { "welcome" } else if step == "linux" { "choose" } else { step };
                    s.progress = None;
                    s.tasks.clear();
                } else {
                    s.error = Some(e.to_string());
                    for t in &mut s.tasks {
                        if t.state == "active" {
                            t.state = "error";
                        }
                    }
                }
            });
        }
    });
}

/// Bytes in MB as the page shows them (1 MB = 1,000,000 bytes, rounded),
/// so a task's "4 / 368 MB" agrees with the bar's "4 of 368 MB".
fn mb(bytes: u64) -> u64 {
    (bytes + 500_000) / 1_000_000
}

/// Downloads `pin` into %LOCALAPPDATA%\Kiri\downloads with curl.exe (part
/// of Windows), showing bytes, speed and time left, then checks its SHA-256.
fn download(pin: &Pin, task_index: usize) -> io::Result<PathBuf> {
    let dl = dir().join("downloads");
    std::fs::create_dir_all(&dl)?;
    let dest = dl.join(pin.file);
    if dest.is_file() && sha256(&dest)? == pin.sha256 {
        task(task_index, "done", &trf("{size} MB · already here", &[("size", &mb(pin.size))]));
        return Ok(dest);
    }
    let part = dl.join(format!("{}.part", pin.file));
    let _ = std::fs::remove_file(&part);
    let label = trf("Downloading {name} from {source}", &[("name", &pin.name), ("source", &if pin.url.contains("github.com/microsoft") { "Microsoft" } else { "ubuntu.com" })]);
    task(task_index, "active", &format!("0 / {} MB", mb(pin.size)));
    let mut child = quiet("curl.exe").args(["-fsSL", "--retry", "3", "-o"]).arg(&part).arg(pin.url).spawn()?;
    let (start, mut last, mut rate) = (Instant::now(), (Instant::now(), 0u64), 0f64);
    loop {
        if CANCEL.load(Ordering::SeqCst) {
            let _ = child.kill();
            let _ = std::fs::remove_file(&part);
            return Err(io::Error::other("cancelled"));
        }
        let finished = child.try_wait()?;
        let got = std::fs::metadata(&part).map_or(0, |m| m.len());
        let dt = last.0.elapsed().as_secs_f64();
        if dt >= 0.25 {
            let now = (got - last.1.min(got)) as f64 / dt;
            rate = if rate == 0.0 { now } else { rate * 0.7 + now * 0.3 };
            last = (Instant::now(), got);
        }
        let eta = if rate > 0.0 { ((pin.size.saturating_sub(got)) as f64 / rate).ceil() as u64 } else { 0 };
        update(|s| {
            s.progress = Some(json!({"pct": got * 100 / pin.size.max(1), "done": got, "total": pin.size, "rate": rate as u64, "eta": eta, "label": label}));
            if let Some(t) = s.tasks.get_mut(task_index) {
                t.detail = format!("{} / {} MB", mb(got), mb(pin.size));
            }
        });
        if let Some(status) = finished {
            if !status.success() {
                return Err(io::Error::other(format!("downloading {} failed: check the internet connection", pin.name)));
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    let got = sha256(&part)?;
    if got != pin.sha256 {
        let _ = std::fs::remove_file(&part);
        return Err(io::Error::other(format!("{} did not match its SHA-256 (got {got})", pin.name)));
    }
    std::fs::rename(&part, &dest)?;
    task(task_index, "done", &trf("{size} MB in {secs} s", &[("size", &mb(pin.size)), ("secs", &start.elapsed().as_secs())]));
    Ok(dest)
}

pub(crate) fn sha256(path: &Path) -> io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Runs kiri-admin.ps1 (contrib/windows, installed beside this exe) with
/// `args` in an elevated PowerShell (Windows asks for approval) and returns
/// its exit code; a refusal is "cancelled". A script file checked against
/// this build's SHA-256, not script text in this binary run with
/// -EncodedCommand: an elevated, hidden PowerShell fed an encoded script is
/// what malware droppers do, and Defender quarantined kiri-win.exe 0.1.7 as
/// Trojan:Win32/Bearfoos.A!ml for carrying it.
fn elevated(args: &[&str]) -> io::Result<i32> {
    let script = verified("kiri-admin.ps1")?;
    match crate::win::elevated_script(&script, args) {
        // As before: anything that kept it from starting reads as declined.
        Err(e) => {
            crate::serve::log(&format!("setup: the elevated PowerShell did not start ({e})"));
            Err(io::Error::other("cancelled: Windows' approval was declined"))
        }
        Ok(1223) => Err(io::Error::other("cancelled: Windows' approval was declined")),
        Ok(c) => Ok(c as i32),
    }
}

/// What a `kiri-admin.ps1 -Wsl` or `-Components` exit code says went
/// wrong; None when it succeeded (0, or 3010: Windows must restart). Codes
/// the script does not give a meaning of its own are dism.exe's, passed
/// through.
fn admin_wsl_failed(code: i32) -> Option<String> {
    Some(match code {
        0 | 3010 => return None,
        22 => "the downloaded WSL installer changed on disk; try again".into(),
        23 => "the WSL installer is not validly signed by Microsoft".into(),
        24 => "Windows could not turn on WSL's optional components (dism.exe failed)".into(),
        21 => "the WSL installer failed".into(),
        1 => "the administrator step failed (exit code 1)".into(),
        // An HRESULT (0x800F...) reads as one; a Win32 code as a number.
        dism if dism < 0 => format!("Windows could not turn on WSL's optional components (dism.exe exit code {dism:#010X})"),
        dism => format!("Windows could not turn on WSL's optional components (dism.exe exit code {dism})"),
    })
}

/// Step 1's elevated run: with WSL's installer when WSL is not installed,
/// or, when wsl.exe answers already, its optional components alone.
fn admin_args(msi: Option<&str>) -> Vec<&str> {
    match msi {
        Some(msi) => vec!["-Wsl", "-Msi", msi, "-Sha256", WSL_MSI.sha256],
        None => vec!["-Components"],
    }
}

/// Whether step 1 ends at the restart rather than at Choose a Linux, once
/// the elevated run succeeded: Windows asked for one (3010), WSL does not
/// answer yet, or its optional components still read as off (they take
/// effect at the restart).
fn restart_after_admin(code: i32, answers: impl FnOnce() -> bool, components_off: impl FnOnce() -> bool) -> bool {
    code == 3010 || !answers() || components_off()
}

/// Step 1: download WSL, then in one elevated run turn on WSL's optional
/// components and install WSL; or, when WSL is installed already, turn on
/// the components alone. Exit 3010 means a restart.
fn install_wsl() -> io::Result<()> {
    // WSL already answers, so only its optional components are off (see
    // current_step): turn them on, with no installer to download or run.
    let components_only = wsl_answer() == Wsl::There;
    // Task indexes: Download WSL and Install WSL only with the installer.
    let (approval, components, install) = if components_only {
        update(|s| s.tasks = tasks(&[tr("Administrator approval"), tr("Turn on Virtual Machine Platform")]));
        (0, 1, None)
    } else {
        update(|s| s.tasks = tasks(&[tr("Download WSL"), tr("Administrator approval"), tr("Turn on Virtual Machine Platform"), tr("Install WSL")]));
        (1, 2, Some(3))
    };
    // WSL_MSI is this build's architecture's; on another PC it would not install.
    if let Some(e) = crate::win::arch_mismatch() {
        return Err(io::Error::other(e));
    }
    let msi = if components_only { None } else { Some(download(&WSL_MSI, 0)?) };
    update(|s| s.progress = Some(json!({"pct": null, "done": null, "total": null, "rate": null, "eta": null, "label": tr("Waiting for Windows' approval")})));
    task(approval, "active", &tr("Windows is asking"));
    // The downloaded MSI lives in a user-writable folder, so a process at
    // the user's own integrity could swap it between its SHA-256 check above
    // and the elevated install. kiri-admin.ps1 -Wsl re-verifies it, as admin,
    // on a copy the user cannot touch, and requires it to be Microsoft-signed,
    // before running it; its exit codes are read below.
    let msi_path = msi.as_ref().map(|m| m.to_string_lossy().into_owned());
    let code = elevated(&admin_args(msi_path.as_deref()))?;
    task(approval, "done", &tr("approved"));
    match code {
        0 | 3010 | 1 | 22 | 23 => {}
        21 => {
            task(components, "done", "");
            if let Some(i) = install {
                task(i, "error", "");
            }
        }
        _ => task(components, "error", ""),
    }
    if let Some(why) = admin_wsl_failed(code) {
        return Err(io::Error::other(why));
    }
    task(components, "done", "");
    if let Some(i) = install {
        task(i, "done", "");
    }
    // Just installed and not answering yet, or the components not on until
    // Windows restarts: the restart step.
    if restart_after_admin(code, || wsl_answer() == Wsl::There, components_off) {
        let mut s = saved();
        s.restart_after = Some(now_secs());
        s.components_on_at = s.restart_after;
        save(&s);
        // After the restart, Kiri opens once by itself and carries on.
        if let Ok(exe) = std::env::current_exe() {
            let registered = quiet("reg.exe")
                .args(["add", r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "/v", "KiriSetup", "/t", "REG_SZ", "/d", &format!("\"{}\"", exe.display()), "/f"])
                .status()
                .is_ok_and(|s| s.success());
                if !registered {
                    return Err(io::Error::other("Windows would not register Kiri to carry on after the restart"));
                }
        }
        update(|s| {
            s.step = "restart";
            s.progress = None;
        });
    } else {
        update(|s| {
            s.step = "choose";
            s.progress = None;
        });
    }
    Ok(())
}

/// Step 2: Kiri Linux from the bundle, or Ubuntu (already here, or downloaded).
fn install_linux(kind: &str) -> io::Result<()> {
    // The engine and Kiri Linux in the bundle are this build's architecture.
    if let Some(e) = crate::win::arch_mismatch() {
        return Err(io::Error::other(e));
    }
    let base = dir().join("wsl");
    std::fs::create_dir_all(&base)?;
    let distro = if kind == "kiri" {
        update(|s| s.tasks = tasks(&[tr("Unpack Kiri Linux"), tr("Add it to WSL"), tr("Start it")]));
        task(0, "active", "");
        let tar = verified("kiri-linux.tar.gz")?;
        task(0, "done", &format!("{} MB", std::fs::metadata(&tar)?.len().div_ceil(1_000_000)));
        task(1, "active", "");
        if !distros().unwrap_or_default().iter().any(|d| d == KIRI_DISTRO) {
            log_line(&format!("wsl --import {KIRI_DISTRO} {} kiri-linux.tar.gz --version 2", base.join(KIRI_DISTRO).display()));
            wsl_ok(quiet("wsl.exe").args(["--import", KIRI_DISTRO]).arg(base.join(KIRI_DISTRO)).arg(&tar).args(["--version", "2"]))?;
        }
        task(1, "done", "");
        task(2, "active", "");
        wsl_ok(quiet("wsl.exe").args(["-d", KIRI_DISTRO, "-u", "root", "--", "/usr/local/bin/kiri-start"]))?;
        task(2, "done", "");
        KIRI_DISTRO.to_owned()
    } else {
        let existing = existing_ubuntu();
        let distro = match existing {
            Some(d) => {
                update(|s| s.tasks = tasks(&[tr("Use the Ubuntu already here"), tr("Install Kiri's engine in it"), tr("Start it")]));
                task(0, "done", &d);
                d
            }
            None => {
                update(|s| s.tasks = tasks(&[tr("Download Ubuntu"), tr("Unpack it into WSL"), tr("Install Kiri's engine in it"), tr("Start it")]));
                let file = download(&UBUNTU, 0)?;
                update(|s| s.progress = None);
                task(1, "active", "≈ 1.6 GB");
                // A real Ubuntu, in Start too; older WSL lacks --from-file.
                let installed = quiet("wsl.exe").args(["--install", "--from-file"]).arg(&file).args(["--name", UBUNTU_DISTRO, "--no-launch"]).status().is_ok_and(|s| s.success());
                if !installed {
                    wsl_ok(quiet("wsl.exe").args(["--import", UBUNTU_DISTRO]).arg(base.join(UBUNTU_DISTRO)).arg(&file).args(["--version", "2"]))?;
                }
                task(1, "done", "");
                update(|s| {
                    s.tasks.remove(0);
                });
                UBUNTU_DISTRO.to_owned()
            }
        };
        task(1, "active", "");
        // The engine binaries install.sh copies are checked too.
        verified("kiri")?;
        verified("kiri-init")?;
        let install = to_wsl(&distro, &verified("install.sh")?)?;
        wsl_ok(quiet("wsl.exe").args(["-d", &distro, "-u", "root", "--", "sh", &install]))?;
        task(1, "done", "");
        task(2, "done", "");
        distro
    };
    let mut s = saved();
    s.linux = Some(kind.to_owned());
    s.distro = Some(distro.clone());
    save(&s);
    crate::serve::set_distro(&distro);
    update(|st| st.linux = Some(kind.to_owned()));
    engine()
}

/// A Windows path as `distro` sees it. Killed after WSL_LIMIT, as the
/// other calls into WSL to start or restart the engine.
pub(crate) fn to_wsl(distro: &str, path: &Path) -> io::Result<String> {
    let out = crate::update::output_within(quiet("wsl.exe").args(["-d", distro, "--", "wslpath", "-a"]).arg(path.to_string_lossy().replace('\\', "/")), crate::update::WSL_LIMIT)?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn wsl_ok(cmd: &mut Command) -> io::Result<()> {
    let out = cmd.output()?;
    if out.status.success() {
        return Ok(());
    }
    let text = wsl_text(&out.stdout) + &wsl_text(&out.stderr);
    Err(io::Error::other(text.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("WSL failed").to_owned()))
}

fn docker() -> PathBuf {
    let ours = dir().join("bin").join("docker.exe");
    if ours.is_file() { ours } else { bundle().join("bin").join("docker.exe") }
}

/// Step 3: the engine answers through the pipe and runs a container.
fn engine() -> io::Result<()> {
    update(|s| {
        s.step = "engine";
        s.progress = None;
        s.tasks = tasks(&[tr("Start the engine"), tr("Connect Windows to it"), tr("Run a test container")]);
    });
    task(0, "active", "");
    let t0 = Instant::now();
    // Started here, not only waited for: setup resumed after Kiri or
    // Windows restarted finds Kiri's Linux there but its engine not running,
    // and nothing else starts it while the window is on setup.
    if !crate::client::alive()
        && let Err(e) = crate::engine::ensure_daemon()
    {
        crate::serve::log(&format!("setup engine: {e}; still waiting for it"));
    }
    while !crate::client::alive() {
        if CANCEL.load(Ordering::SeqCst) {
            return Err(io::Error::other("cancelled"));
        }
        if t0.elapsed() > Duration::from_secs(60) {
            return Err(io::Error::other("Kiri's engine did not answer within a minute"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    task(0, "done", &trf("answered in {ms} ms", &[("ms", &t0.elapsed().as_millis())]));
    let pipe = crate::client::pipe();
    task(1, "done", &pipe);
    // Windows' proxy before the first pull, through the relay when it is on
    // Windows' loopback: the minute's refresh may not have come yet.
    crate::engine::send_windows_proxy();
    task(2, "active", &tr("pulling alpine"));
    log_line("$ docker run --rm alpine echo hello");
    // Before the installed copy exists, this runs the bundle's docker.exe:
    // check it first, as the tools step does for the copy it installs.
    if !dir().join("bin").join("docker.exe").is_file() {
        verified("bin/docker.exe")?;
    }
    let out = quiet(&docker().to_string_lossy()).args(["--host", &format!("npipe://{}", pipe.replace('\\', "/")), "run", "--rm", "alpine", "echo", "hello"]).output()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    for l in text.lines().rev().take(3).collect::<Vec<_>>().into_iter().rev() {
        log_line(l);
    }
    if !out.status.success() || !text.contains("hello") {
        // All of docker's words in the log, where the setup page shows a few.
        for l in text.lines().map(str::trim).filter(|l| !l.is_empty()).take(20) {
            crate::serve::log(&format!("setup engine: docker: {l}"));
        }
        return Err(io::Error::other(test_failure(&text)));
    }
    task(2, "done", "hello");
    tools()
}

/// Why `docker run alpine` failed, from what docker printed: the engine's
/// own words, and whether it was the pull.
fn test_failure(text: &str) -> String {
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let said = lines
        .iter()
        .find_map(|l| l.split_once("Error response from daemon:").map(|(_, r)| r))
        .or_else(|| lines.iter().find_map(|l| l.strip_prefix("docker: ")))
        .or_else(|| lines.iter().rev().find(|l| !l.starts_with("See '") && !l.starts_with("Run '")).copied())
        .map(|r| r.trim().trim_end_matches('.').to_owned());
    let pulling = text.contains("Unable to find image") && !text.contains("Status: Downloaded");
    match (said, pulling) {
        (Some(why), true) => trf("couldn't pull alpine: {why}", &[("why", &why)]),
        (Some(why), false) => trf("the test container did not run: {why}", &[("why", &why)]),
        (None, _) => tr("the test container did not run"),
    }
}

/// Step 4: the Docker tools (setup-tools.ps1), task by task.
fn tools() -> io::Result<()> {
    update(|s| {
        s.step = "tools";
        s.progress = None;
        s.tasks = tasks(&["docker 29.9.2".to_owned(), "Compose v5.6.1".to_owned(), "buildx v0.38.1".to_owned(), tr("docker build on Kiri"), tr("Make Kiri the default")]);
    });
    task(0, "active", "");
    for f in ["bin/docker.exe", "bin/kiri.exe", "bin/cli-plugins/docker-compose.exe", "bin/cli-plugins/docker-buildx.exe"] {
        verified(f)?;
    }
    let make_default = STATE.lock().unwrap_or_else(PoisonError::into_inner).as_ref().is_some_and(|s| s.make_default);
    // setup-tools.ps1 (contrib/windows), checked like the bundle's other
    // files and run from its file with its parameters as arguments. Not a
    // copy in this binary run through [scriptblock]::Create from Base64:
    // that is the textbook dropper, and Defender's heuristics flagged
    // kiri-win.exe 0.1.7 for it (Trojan:Win32/Bearfoos.A!ml).
    let script = verified("setup-tools.ps1")?;
    let mut cmd = quiet("powershell.exe");
    cmd.args(crate::win::PS_FILE).arg(&script).arg("-Bundle").arg(bundle());
    if make_default {
        cmd.arg("-Default");
    }
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let stdout = child.stdout.take().ok_or_else(|| io::Error::other("no output"))?;
    // stderr is drained as it comes: docker writes progress there, and a
    // full pipe would stall the script. It is only a fallback for the error.
    let stderr = child.stderr.take().map(|mut e| {
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = e.read_to_string(&mut s);
            s
        })
    });
    // The script reports its own failure as "ERROR <why>" on stdout, so
    // the message is the real one, not whatever docker said on stderr first.
    let mut error = None;
    for line in io::BufRead::lines(io::BufReader::new(stdout)).map_while(Result::ok) {
        let line = line.trim();
        if let Some(n) = line.strip_prefix("TASK ").and_then(|n| n.parse::<usize>().ok()) {
            let detail = if n == 4 && !make_default { tr("skipped") } else { String::new() };
            task(n, "done", &detail);
            task(n + 1, "active", "");
        } else if let Some(why) = line.strip_prefix("ERROR ") {
            error = Some(why.trim().to_owned());
        }
    }
    let status = child.wait()?;
    let err = stderr.and_then(|t| t.join().ok()).unwrap_or_default();
    if !status.success() {
        let why = error
            .filter(|e| !e.is_empty())
            .or_else(|| err.lines().rev().find(|l| !l.trim().is_empty() && !l.contains("Successfully")).map(|l| l.trim().to_owned()))
            .unwrap_or_else(|| "installing the Docker tools failed".to_owned());
        return Err(io::Error::other(why));
    }
    // From here on Kiri runs from %LOCALAPPDATA%\Kiri, not the download folder.
    if let Ok(exe) = std::env::current_exe() {
        let installed = dir().join("kiri-win.exe");
        if exe != installed {
            std::fs::copy(&exe, &installed).map_err(|e| io::Error::other(format!("could not install kiri-win.exe to {}: {e}", installed.display())))?;
        }
    }
    update(|s| {
        s.step = "ready";
        s.progress = None;
    });
    Ok(())
}

/// Ready → Open Kiri: remember setup is done, start at sign-in if asked.
fn finish() {
    let autostart = STATE.lock().unwrap_or_else(PoisonError::into_inner).as_ref().is_none_or(|s| s.autostart);
    // Which builder docker build uses: asked with another engine here, Kiri's without.
    let asked = STATE.lock().unwrap_or_else(PoisonError::into_inner).as_ref().filter(|s| s.other_docker).map(|s| s.build_kiri);
    let built = match asked {
        Some(kiri) => crate::buildwith::choose(if kiri { crate::buildwith::With::Kiri } else { crate::buildwith::With::Docker }),
        None => crate::buildwith::apply(),
    };
    if let Err(e) = built {
        crate::serve::log(&format!("docker build: could not set which builder it uses ({e})"));
    }
    let mut s = saved();
    s.done = true;
    s.restart_after = None;
    s.last_error = None;
    save(&s);
    crate::serve::set_setup_pending(false);
    let exe = dir().join("kiri-win.exe");
    let run_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    if autostart {
        if exe.is_file() {
            let _ = quiet("reg.exe").args(["add", run_key, "/v", "Kiri", "/t", "REG_SZ", "/d", &format!("\"{}\" --background", exe.display()), "/f"]).status();
        } else {
            crate::serve::log("not set to start at sign-in: kiri-win.exe is not installed");
        }
    } else {
        let _ = quiet("reg.exe").args(["delete", run_key, "/v", "Kiri", "/f"]).status();
    }
    let _ = quiet("reg.exe").args(["delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "/v", "KiriSetup", "/f"]).status();
    Handle.run(|ui| ui.navigate_main());
}

fn copy_to_clipboard(text: &str) {
    if let Ok(mut c) = quiet("clip.exe").stdin(Stdio::piped()).spawn() {
        if let Some(mut i) = c.stdin.take() {
            let _ = io::Write::write_all(&mut i, text.as_bytes());
        }
        let _ = c.wait();
    }
}

/// Whether a page message is setup's.
pub fn handles(msg: &str) -> bool {
    serde_json::from_str::<Value>(msg).ok().and_then(|v| v["cmd"].as_str().map(|c| c.starts_with("setup-") || c == "copy")).unwrap_or(false)
}

pub fn on_message(msg: &str) {
    let Ok(v) = serde_json::from_str::<Value>(msg) else { return };
    match v["cmd"].as_str().unwrap_or("") {
        // This arrives on the window's thread. Working out the step asks
        // wsl.exe twice and pings the engine through the pipe, which on a
        // cold WSL can take long (and the ping has no deadline): off the
        // window's thread, so it keeps drawing and answering.
        "setup-ready" => {
            std::thread::spawn(|| {
                let s = saved();
                let (step, silent) = current_step(&s);
                let mut fresh = fresh_state(step, &s, silent.is_none() && existing_ubuntu().is_some());
                if let Some(why) = silent {
                    crate::serve::log(&format!("setup: {why}; showing {step}"));
                    fresh.error = Some(why);
                } else if let Some(e) = &s.last_error {
                    crate::serve::log(&format!("setup: carrying on at {step}; last time it stopped with: {e}"));
                    // A step that carries on by itself shows its own result;
                    // one waiting for a choice shows why setup stopped.
                    if matches!(step, "choose" | "welcome") {
                        fresh.error = Some(e.clone());
                    }
                }
                *STATE.lock().unwrap_or_else(PoisonError::into_inner) = Some(fresh);
                update(|_| {});
                // A restart finished WSL, or the engine is there already: carry on by itself.
                match step {
                    "engine" => run("engine", engine),
                    "tools" => run("tools", tools),
                    _ => {}
                }
            });
        }
        "setup-install-wsl" => run("wsl", install_wsl),
        "setup-restart" => {
            let _ = quiet("shutdown.exe").args(["/r", "/t", "5", "/c", "Kiri: finishing Windows Subsystem for Linux"]).status();
        }
        "setup-later" => Handle.run(crate::app::Ui::hide),
        "setup-choose" => {
            let kind = if v["value"] == "ubuntu" { "ubuntu" } else { "kiri" };
            update(|s| s.linux = Some(kind.to_owned()));
            run("linux", move || install_linux(kind));
        }
        "setup-switch" => {
            CANCEL.store(true, Ordering::SeqCst);
            std::thread::spawn(|| {
                while BUSY.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(100));
                }
                update(|s| s.linux = Some("kiri".into()));
                run("linux", || install_linux("kiri"));
            });
        }
        "setup-cancel" => CANCEL.store(true, Ordering::SeqCst),
        "setup-retry" => {
            let step = STATE.lock().unwrap_or_else(PoisonError::into_inner).as_ref().map_or("welcome", |s| s.step);
            let linux = STATE.lock().unwrap_or_else(PoisonError::into_inner).as_ref().and_then(|s| s.linux.clone()).unwrap_or_else(|| "kiri".into());
            match step {
                "wsl" => run("wsl", install_wsl),
                "linux" => run("linux", move || install_linux(&linux)),
                "engine" => run("engine", engine),
                "tools" => run("tools", tools),
                _ => update(|s| s.error = None),
            }
        }
        "setup-default" => update(|s| s.make_default = v["value"] == true),
        "setup-autostart" => update(|s| s.autostart = v["value"] == true),
        "setup-build" => update(|s| s.build_kiri = v["value"] == "kiri"),
        "setup-open" => finish(),
        // SAFETY: ends this thread's message loop; run on the window's thread.
        "setup-quit" => Handle.run(|_| unsafe { windows::Win32::UI::WindowsAndMessaging::PostQuitMessage(0) }),
        "copy" => copy_to_clipboard(v["value"].as_str().unwrap_or("")),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn wsl_output_is_read_in_any_language() {
        let utf16 = |s: &str| s.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>();
        // WSL appends an ASCII `Wsl/...` code to its errors in every
        // language, so even a fully non-Latin message has NULs in its
        // UTF-16 bytes and the check catches it whatever the script.
        let code = "Error code: Wsl/WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED\r\n";
        let messages = [
            "Error code: Wsl/WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED\r\n".to_owned(),
            format!("Für diese Anwendung ist die Komponente „Windows-Subsystem für Linux“ erforderlich. {code}"),
            format!("Для этого приложения требуется дополнительный компонент подсистемы Windows для Linux. {code}"),
            format!("此应用程序需要适用于 Linux 的 Windows 子系统组件。{code}"),
            format!("このアプリケーションには Windows Subsystem for Linux の追加コンポーネントが必要です。{code}"),
            format!("이 애플리케이션에는 Linux용 Windows 하위 시스템 구성 요소가 필요합니다. {code}"),
            format!("هذا التطبيق يتطلب مكون Windows الفرعي لنظام Linux. {code}"),
            format!("Εφαρμογή: απαιτείται το υποσύστημα Windows για Linux. {code}"),
            format!("יישות זה דורש את רכיב Windows עבור Linux. {code}"),
            format!("Энэ programa Linux üçün Windows podsistemi əlavə komponentini tələb edir. {code}"),
        ];
        for m in &messages {
            assert_eq!(super::wsl_text(&utf16(m)), *m, "UTF-16: {m}");
            assert_eq!(super::wsl_text(m.as_bytes()), *m, "UTF-8: {m}");
            // With a byte-order mark: the mark goes.
            assert_eq!(super::wsl_text(&[&[0xFF, 0xFE][..], &utf16(m)].concat()), *m, "UTF-16 BOM: {m}");
            // Cut short at an odd byte (killed at its limit): no NULs left,
            // and the code still reads.
            let mut cut = utf16(m);
            cut.truncate(cut.len() - 3);
            let got = super::wsl_text(&cut);
            assert!(!got.contains('\0') && m.starts_with(&got) && got.len() + 2 >= m.len(), "odd UTF-16: {got:?}");
            assert!(super::nothing_listed(&cut) && super::component_required(&cut), "{m}");
            assert!(super::nothing_listed(&utf16(m)) && super::component_required(&utf16(m)), "{m}");
        }
        // A distro list cut short at an odd byte keeps its last letter.
        assert_eq!(super::wsl_text(&utf16("kiri\r\nUbuntu")[..23]), "kiri\r\nUbuntu");
        // UTF-16 with no ASCII and no BOM is byte for byte valid UTF-8: only
        // the mark tells it apart.
        assert_eq!(super::wsl_text(&[&[0xFF, 0xFE][..], &utf16("ぁぃぅ")].concat()), "ぁぃぅ");
    }

    #[test]
    fn linux_output_stays_utf8() {
        // What a Linux command run through wsl.exe prints is UTF-8, colour
        // codes and all, whatever its length.
        for m in [
            "\x1b[31merror:\x1b[0m kiri-start: no such file\n",
            "\x1b[1mok\x1b[0m\r\n",
            "Für\n",
            "Für\r\n",
            "Для\r\n",
            // Even lengths with a terminal title (BEL), a spinner (BS), DEL,
            // a C1 control and a literal replacement character.
            "\x1b]0;kiri\x07ok\n",
            "\x1b]8;;https://x\x07link\x1b]8;;\x07\n",
            "|\x08/\x08-ok\n",
            "a\x7fb\n",
            "\u{9b}31mred\n",
            "\u{fffd} ok\n",
        ] {
            assert_eq!(super::wsl_text(m.as_bytes()), m, "{m:?}");
        }
        // An invalid byte, even length: the rest stays as it was.
        assert_eq!(super::wsl_text(b"ok \xff done\n"), "ok \u{fffd} done\n");
        // A stray NUL in UTF-8, at an odd offset or not, even length or odd: dropped.
        assert_eq!(super::wsl_text(b"o\0k\n"), "ok\n");
        assert_eq!(super::wsl_text(b"error: \0 at the end\n"), "error:  at the end\n");
        assert_eq!(super::wsl_text(b"error: \0at the end\n"), "error: at the end\n");
        // A UTF-8 BOM goes too.
        assert_eq!(super::wsl_text("\u{feff}ok\n".as_bytes()), "ok\n");
    }

    #[test]
    fn a_turned_off_component_is_seen_in_any_language() {
        let utf16 = |s: &str| s.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>();
        assert!(super::component_required(&utf16("Для подсистемы Windows для Linux требуется дополнительный компонент.\r\nWsl/WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED\r\n")));
        assert!(super::component_required(b"Error code: Wsl/WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED\r\n"));
        assert!(!super::component_required(&utf16("Windows Subsystem for Linux has no installed distributions.\r\nError code: Wsl/WSL_E_DEFAULT_DISTRO_NOT_FOUND\r\n")));
    }

    /// kiri-admin.ps1 as installed beside kiri-win.exe.
    const ADMIN_SCRIPT: &str = include_str!("../../../contrib/windows/kiri-admin.ps1");

    /// The script's lines that are not comments.
    fn admin_code() -> impl Iterator<Item = &'static str> {
        ADMIN_SCRIPT.lines().filter(|l| !l.trim_start().starts_with('#'))
    }

    /// The code of the script's `if (<mode>) { ... }` block, up to the
    /// next blank line.
    fn admin_block(mode: &str) -> String {
        let open = format!("if (${mode}) {{");
        admin_code().skip_while(|l| !l.starts_with(&open)).take_while(|l| !l.trim().is_empty()).collect::<Vec<_>>().join("\n")
    }

    #[test]
    fn the_admin_script_turns_on_both_wsl_components() {
        let feature = |name: &str| admin_code().any(|l| l.contains(&format!("'/featurename:{name}'")));
        assert!(feature("Microsoft-Windows-Subsystem-Linux"), "kiri-admin.ps1 must turn on the Subsystem for Linux component");
        assert!(feature("VirtualMachinePlatform"), "kiri-admin.ps1 must turn on Virtual Machine Platform");
        let args = admin_code().find(|l| l.starts_with("$featureArgs = ")).unwrap_or_default();
        for a in ["'/online'", "'/enable-feature'", "'/all'", "'/norestart'"] {
            assert!(args.contains(a), "$featureArgs lacks {a}");
        }
        assert!(admin_code().any(|l| l.contains("[switch]$Components")), "kiri-admin.ps1 has no -Components");
        // Both modes run dism.exe with those arguments, and pass its code on.
        for mode in ["Wsl", "Components"] {
            let block = admin_block(mode);
            assert!(block.contains(r#"System32\dism.exe" -ArgumentList $featureArgs"#), "-{mode} does not run dism.exe with $featureArgs:\n{block}");
            assert!(block.contains("exit (DismFailed $features)"), "-{mode} does not pass dism.exe's code on:\n{block}");
        }
        assert!(admin_block("Components").contains("if ($features -eq 0 -or $features -eq 3010) { exit $features }"));
    }

    #[test]
    fn the_admin_script_takes_one_mode_per_run() {
        let check = admin_code().position(|l| l.contains("@($Wsl.IsPresent, $Components.IsPresent, $Dns.IsPresent) -eq $true).Count -ne 1) { throw"));
        let first_mode = admin_code().position(|l| l.starts_with("if ($Wsl) {"));
        assert!(check.is_some() && check < first_mode, "kiri-admin.ps1 must refuse two modes before running either");
    }

    #[test]
    fn every_admin_script_exit_code_is_read() {
        assert_eq!(super::admin_wsl_failed(0), None);
        assert_eq!(super::admin_wsl_failed(3010), None);
        // Every `exit` in the script's code, any case, inline comments and
        // strings aside: a number, or dism.exe's own code passed on.
        let mut codes = Vec::new();
        for line in admin_code() {
            let mut quote = None;
            let code: String = line.chars().take_while(|&c| {
                match (quote, c) {
                    (None, '#') => return false,
                    (None, '\'' | '"') => quote = Some(c),
                    (Some(q), c) if c == q => quote = None,
                    _ => {}
                }
                true
            }).collect();
            let lower = code.to_ascii_lowercase();
            let words: Vec<&str> = lower.split(|c: char| c.is_whitespace() || c == ';' || c == '{' || c == '}').filter(|w| !w.is_empty()).collect();
            for pair in words.windows(2).filter(|w| w[0] == "exit") {
                match pair[1].parse::<i32>() {
                    Ok(n) => codes.push(n),
                    Err(_) => assert!(matches!(pair[1], "$features" | "(dismfailed"), "kiri-admin.ps1 exits with {:?}: {line}", pair[1]),
                }
            }
            assert!(!words.last().is_some_and(|w| *w == "exit"), "a bare exit: {line}");
        }
        assert!(codes.contains(&21) && codes.contains(&22) && codes.contains(&23), "{codes:?}");
        for code in codes.into_iter().chain([24]).filter(|c| *c != 0 && *c != 3010) {
            let why = super::admin_wsl_failed(code).unwrap_or_default();
            assert!(!why.is_empty() && !why.contains("administrator step"), "exit {code} from kiri-admin.ps1 has no message of its own");
        }
        assert!(super::admin_wsl_failed(1).is_some_and(|w| w.contains("exit code 1")));
        // dism.exe's code, passed on, is shown, and does not blame the BIOS.
        assert_eq!(super::admin_wsl_failed(0x800F_081Fu32 as i32).as_deref(), Some("Windows could not turn on WSL's optional components (dism.exe exit code 0x800F081F)"));
        assert_eq!(super::admin_wsl_failed(50).as_deref(), Some("Windows could not turn on WSL's optional components (dism.exe exit code 50)"));
        assert!(!super::admin_wsl_failed(24).unwrap_or_default().contains("BIOS"));
    }

    #[test]
    fn step_one_turns_on_the_components_alone_for_an_installed_wsl() {
        use super::{admin_args, restart_after_admin, step_from, Saved, Wsl, COMPONENTS_STILL_OFF};
        assert_eq!(admin_args(None), ["-Components"]);
        assert_eq!(admin_args(Some(r"C:\wsl.msi")), ["-Wsl", "-Msi", r"C:\wsl.msi", "-Sha256", super::WSL_MSI.sha256]);

        let ready = || "engine";
        let never = |_: u64| false;
        let always = |_: u64| true;
        let fresh = Saved::default();
        // No WSL: step 1, without asking about components.
        assert_eq!(step_from(Wsl::Missing, &fresh, always, || panic!("asked"), ready), ("welcome", None));
        // WSL answers but its component is off: step 1 again.
        assert_eq!(step_from(Wsl::There, &fresh, always, || true, ready), ("welcome", None));
        assert_eq!(step_from(Wsl::There, &fresh, always, || false, ready), ("engine", None));
        // Turned on, and waiting for the restart: the restart step.
        let waiting = Saved { restart_after: Some(5), components_on_at: Some(5), ..Saved::default() };
        assert_eq!(step_from(Wsl::There, &waiting, never, || panic!("asked"), ready), ("restart", None));
        // Restarted and still off: step 1, saying so.
        assert_eq!(step_from(Wsl::There, &waiting, always, || true, ready), ("welcome", Some(COMPONENTS_STILL_OFF.to_owned())));
        assert_eq!(step_from(Wsl::There, &waiting, always, || false, ready), ("engine", None));
        // Silent: Choose a Linux, saying why.
        assert_eq!(step_from(Wsl::Silent("slow".into()), &fresh, always, || panic!("asked"), ready), ("choose", Some("slow".into())));

        // After the elevated run: restart on 3010, on a WSL that does not
        // answer, or when the components still read as off.
        assert!(restart_after_admin(3010, || panic!("asked"), || panic!("asked")));
        assert!(restart_after_admin(0, || false, || panic!("asked")));
        assert!(restart_after_admin(0, || true, || true));
        assert!(!restart_after_admin(0, || true, || false));
    }

    #[test]
    fn a_failed_test_container_says_why() {
        let pull = "Unable to find image 'alpine:latest' locally\ndocker: Error response from daemon: the proxy http://127.0.0.1:7892 refused the connection or closed it: is it running? (network error: io: Connection refused (os error 111)).\nSee 'docker run --help'.\n";
        assert_eq!(super::test_failure(pull), "couldn't pull alpine: the proxy http://127.0.0.1:7892 refused the connection or closed it: is it running? (network error: io: Connection refused (os error 111))");
        let stream = "Unable to find image 'alpine:latest' locally\nlatest: Pulling from library/alpine\ndocker: network error: timeout: connect\n\nRun 'docker run --help' for more information\n";
        assert_eq!(super::test_failure(stream), "couldn't pull alpine: network error: timeout: connect");
        let run = "Unable to find image 'alpine:latest' locally\nlatest: Pulling from library/alpine\nStatus: Downloaded newer image for alpine:latest\ndocker: Error response from daemon: no space left on device.\n";
        assert_eq!(super::test_failure(run), "the test container did not run: no space left on device");
        assert_eq!(super::test_failure("something odd\n"), "the test container did not run: something odd");
        assert_eq!(super::test_failure(""), "the test container did not run");
    }

    #[test]
    fn a_wsl_that_never_answers_is_silent_within_its_limit() {
        use super::{quiet, wsl_check, Wsl};
        use std::time::{Duration, Instant};
        // Stands in for a hung wsl.exe: about ten minutes of pings, killed at the limit.
        let t = Instant::now();
        let got = wsl_check(quiet("ping.exe").args(["-n", "600", "127.0.0.1"]), Duration::from_millis(300));
        assert!(t.elapsed() < Duration::from_secs(10), "waited {:?}", t.elapsed());
        assert!(matches!(&got, Wsl::Silent(why) if why.starts_with("WSL did not finish")), "{got:?}");
        // One that answers is there; one that fails, or isn't there at all, is missing.
        assert_eq!(wsl_check(quiet("cmd.exe").args(["/c", "exit 0"]), Duration::from_secs(10)), Wsl::There);
        assert_eq!(wsl_check(quiet("cmd.exe").args(["/c", "exit 1"]), Duration::from_secs(10)), Wsl::Missing);
        assert_eq!(wsl_check(&mut std::process::Command::new("kiri-no-such-wsl.exe"), Duration::from_secs(10)), Wsl::Missing);
        // The limit a first-run window waits: well under WSL_LIMIT.
        assert!(super::WSL_ANSWER_LIMIT < crate::update::WSL_LIMIT);
    }

    #[test]
    fn a_wsl_that_does_not_answer_is_not_a_missing_wsl() {
        use super::needs_setup;
        let listed = |names: &[&str]| -> Option<Vec<String>> { Some(names.iter().map(|n| n.to_string()).collect()) };
        // First run, or no distro picked yet: setup, without asking WSL.
        assert!(needs_setup(false, Some("kiri"), || panic!("asked WSL")));
        assert!(needs_setup(true, None, || panic!("asked WSL")));
        // Kiri's distro listed: Kiri. Gone from the list: setup again.
        assert!(!needs_setup(true, Some("kiri"), || listed(&["docker-desktop", "kiri"])));
        assert!(needs_setup(true, Some("kiri"), || listed(&["Ubuntu"])));
        assert!(needs_setup(true, Some("kiri"), || listed(&[])));
        // WSL failed or timed out: not a missing distro.
        assert!(!needs_setup(true, Some("kiri"), || None));

        // A failed `wsl -l` that says there is nothing to list, in WSL's
        // UTF-16, translated too, against one that only timed out.
        let utf16 = |s: &str| s.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>();
        assert!(super::nothing_listed(&utf16("Windows Subsystem for Linux has no installed distributions.\r\nError code: Wsl/WSL_E_DEFAULT_DISTRO_NOT_FOUND\r\n")));
        assert!(super::nothing_listed(&utf16("Для подсистемы Windows для Linux требуется дополнительный компонент.\r\nWsl/WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED\r\n")));
        assert!(!super::nothing_listed(&utf16("Error code: Wsl/Service/WSAETIMEDOUT\r\n")));
        assert!(!super::nothing_listed(b""));
    }

    #[test]
    fn a_set_up_kiri_opens_its_window_when_wsl_never_answers() {
        use super::{listed_by, needs_setup, quiet};
        use std::os::windows::process::CommandExt;
        use std::time::{Duration, Instant};
        let ten = Duration::from_secs(10);
        // Setup done, and `wsl -l -q` hangs (about ten minutes of pings
        // stand in for it): the main window, once the limit kills it.
        let t = Instant::now();
        assert!(!needs_setup(true, Some("kiri"), || listed_by(quiet("ping.exe").args(["-n", "600", "127.0.0.1"]), Duration::from_millis(300))));
        assert!(t.elapsed() < ten, "waited {:?}", t.elapsed());
        // It fails with WSL's own time-out: the main window too.
        assert!(!needs_setup(true, Some("kiri"), || listed_by(quiet("cmd.exe").raw_arg("/c echo Error code: Wsl/Service/WSAETIMEDOUT 1>&2 & exit 1"), ten)));
        // It answers: Kiri's distro listed, the main window; gone, setup.
        assert!(!needs_setup(true, Some("kiri"), || listed_by(quiet("cmd.exe").raw_arg("/c echo docker-desktop& echo kiri"), ten)));
        assert!(needs_setup(true, Some("kiri"), || listed_by(quiet("cmd.exe").raw_arg("/c echo Ubuntu"), ten)));
        // No WSL at all lists nothing: setup.
        assert!(needs_setup(true, Some("kiri"), || listed_by(&mut std::process::Command::new("kiri-no-such-wsl.exe"), ten)));
        // A first run never waits on WSL before the window opens.
        assert!(needs_setup(false, Some("kiri"), || panic!("asked WSL")));
    }
}
