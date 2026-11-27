//! `kiri engine start | stop | restart | status [--json]`: start, stop, restart
//! and inspect Kiri's engine from the terminal (#983).
//!
//! `status` uses background requests (`X-Kiri-Background: 1`, and on Windows
//! checks `%LOCALAPPDATA%\Kiri\stopped` and `wsl --list --running --quiet`
//! before querying WSL without `kiri-start`), so inspecting engine status never
//! wakes a sleeping VM or boots a stopped WSL distro. Exits 0 when the engine
//! is `running` or `asleep`, and exits 1 when `stopped` or `not_running`.

use std::io;

use serde::Serialize;
use serde_json::Value;

use crate::client;

pub const USAGE: &str = "\
usage: kiri engine start              start Kiri's engine (waking the VM and held containers)
       kiri engine stop               stop containers and Kiri's engine until `kiri engine start`
       kiri engine restart            restart Kiri's engine (applying updated VM settings)
       kiri engine status [--json]    inspect engine state without waking a sleeping VM (exit 1 when stopped or not running)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Help,
    Start,
    Stop,
    Restart,
    Status { json: bool },
}

pub(crate) fn parse_args(args: &[String]) -> io::Result<Action> {
    if args.iter().any(|a| matches!(a.as_str(), "-h" | "--help"))
        || matches!(args.first().map(String::as_str), Some("help"))
    {
        return Ok(Action::Help);
    }
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["start"] => Ok(Action::Start),
        ["stop"] => Ok(Action::Stop),
        ["restart"] => Ok(Action::Restart),
        ["status"] => Ok(Action::Status { json: false }),
        ["status", "--json"] => Ok(Action::Status { json: true }),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, USAGE)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EngineState {
    Running,
    Asleep,
    Stopped,
    NotRunning,
}

impl EngineState {
    pub(crate) fn is_healthy(self) -> bool {
        matches!(self, EngineState::Running | EngineState::Asleep)
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            EngineState::Running => "running",
            EngineState::Asleep => "asleep",
            EngineState::Stopped => "stopped",
            EngineState::NotRunning => "not running",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct StatusReport {
    pub state: EngineState,
    pub awake: bool,
    pub stopped: bool,
    pub version: Option<String>,
    pub api_version: Option<String>,
    pub cpus: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub containers_running: Option<u64>,
    pub containers_stopped: Option<u64>,
    pub socket: String,
}

impl StatusReport {
    pub(crate) fn not_running(socket: impl Into<String>) -> Self {
        Self {
            state: EngineState::NotRunning,
            awake: false,
            stopped: false,
            version: None,
            api_version: None,
            cpus: None,
            memory_bytes: None,
            containers_running: None,
            containers_stopped: None,
            socket: socket.into(),
        }
    }

    pub(crate) fn stopped_offline(socket: impl Into<String>) -> Self {
        Self {
            state: EngineState::Stopped,
            awake: false,
            stopped: true,
            version: None,
            api_version: None,
            cpus: None,
            memory_bytes: None,
            containers_running: None,
            containers_stopped: None,
            socket: socket.into(),
        }
    }

    pub(crate) fn from_daemon(socket: impl Into<String>, info: &Value, version: Option<&Value>) -> Self {
        let stopped = info["KiriStopped"].as_bool().unwrap_or(false);
        let awake = !stopped && info["KiriVmAwake"].as_bool().unwrap_or(true);
        let state = if stopped {
            EngineState::Stopped
        } else if awake {
            EngineState::Running
        } else {
            EngineState::Asleep
        };
        let kiri_ver = info["KiriVersion"]
            .as_str()
            .or_else(|| version.and_then(client::kiri_version))
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let api_ver = version
            .and_then(|v| v["ApiVersion"].as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let mem = info["KiriMemoryCeiling"]
            .as_u64()
            .filter(|&n| n > 0)
            .or_else(|| info["MemTotal"].as_u64().filter(|&n| n > 0));
        Self {
            state,
            awake,
            stopped,
            version: kiri_ver,
            api_version: api_ver,
            cpus: info["NCPU"].as_u64().filter(|&n| n > 0),
            memory_bytes: mem,
            containers_running: info["ContainersRunning"].as_u64(),
            containers_stopped: info["ContainersStopped"].as_u64(),
            socket: socket.into(),
        }
    }

    pub(crate) fn format_human(&self) -> String {
        let mut head = format!("Kiri engine: {}", self.state.label());
        match self.state {
            EngineState::Asleep => head.push_str(" (VM idle; wakes on next request)"),
            EngineState::Stopped => head.push_str(" (run `kiri engine start` to start)"),
            EngineState::NotRunning => head.push_str(" (run `kiri engine start` or open Kiri)"),
            EngineState::Running => {}
        }
        let mut lines = vec![head];
        if let Some(ver) = &self.version {
            match &self.api_version {
                Some(api) => lines.push(format!("Version:     {ver} (Docker API {api})")),
                None => lines.push(format!("Version:     {ver}")),
            }
        }
        if let Some(cpus) = self.cpus {
            match self.memory_bytes {
                Some(bytes) => lines.push(format!("Resources:   {cpus} CPUs, {}", format_memory(bytes))),
                None => lines.push(format!("Resources:   {cpus} CPUs")),
            }
        }
        if let (Some(running), Some(stopped)) = (self.containers_running, self.containers_stopped) {
            lines.push(format!("Containers:  {running} running, {stopped} stopped"));
        }
        lines.push(format!("Socket:      {}", self.socket));
        lines.join("\n")
    }
}

fn format_memory(bytes: u64) -> String {
    const GIB: f64 = (1u64 << 30) as f64;
    const MIB: u64 = 1u64 << 20;
    if bytes >= (1u64 << 30) && bytes.is_multiple_of(1u64 << 30) {
        format!("{} GiB", bytes >> 30)
    } else if bytes >= (1u64 << 30) {
        format!("{:.1} GiB", bytes as f64 / GIB)
    } else {
        format!("{} MiB", bytes / MIB.max(1))
    }
}

pub fn run(args: &[String]) -> io::Result<()> {
    match parse_args(args)? {
        Action::Help => {
            println!("{USAGE}");
            Ok(())
        }
        Action::Start => {
            start_silent()?;
            println!("Kiri engine started");
            Ok(())
        }
        Action::Stop => {
            if stop_silent()? {
                println!("Kiri engine stopped");
            } else {
                println!("Kiri engine is already stopped");
            }
            Ok(())
        }
        Action::Restart => {
            restart_silent()?;
            println!("Kiri engine restarted");
            Ok(())
        }
        Action::Status { json } => {
            let report = collect_status()?;
            if json {
                println!("{}", serde_json::to_string(&report).map_err(io::Error::other)?);
            } else {
                println!("{}", report.format_human());
            }
            if !report.state.is_healthy() {
                std::process::exit(1);
            }
            Ok(())
        }
    }
}

/// `kiri start`: keeps the existing `"Kiri is started"` message for compatibility.
#[cfg(unix)]
pub fn start_legacy() -> io::Result<()> {
    start_silent()?;
    println!("Kiri is started");
    Ok(())
}

// ---- Unix implementation (macOS, Linux, and WSL daemon) ----

#[cfg(unix)]
fn start_not_running_message() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "Kiri's engine isn't running. Open Kiri, or start it with `kiri daemon`"
    }
    #[cfg(not(target_os = "macos"))]
    {
        client::not_running_message()
    }
}

#[cfg(unix)]
fn start_silent() -> io::Result<()> {
    #[cfg(target_os = "macos")]
    if !client::alive() {
        if let Ok(d) = crate::daemon::state_dir() {
            let _ = std::fs::remove_file(d.join("stopped"));
        }
        crate::update::start_engine()?;
    }
    client::check_alive_with(start_not_running_message())?;
    let r = client::request("POST", "/kiri/wake", None)?;
    if !r.ok() && r.status != 404 {
        return Err(io::Error::other(r.error()));
    }
    Ok(())
}

/// Stops containers and Kiri's engine. Returns `Ok(true)` when a running/active
/// engine was stopped, or `Ok(false)` when it was already stopped/not running.
#[cfg(unix)]
fn stop_silent() -> io::Result<bool> {
    let sock = client::socket()?;
    match client::probe_socket(&sock) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Err(e),
        Err(_) => {
            #[cfg(target_os = "macos")]
            if let Ok(d) = crate::daemon::state_dir() {
                let _ = std::fs::create_dir_all(&d);
                let _ = std::fs::write(d.join("stopped"), b"");
            }
            return Ok(false);
        }
    }
    let was_stopped = client::get_background_at(&sock, "/info")
        .ok()
        .and_then(|v| v["KiriStopped"].as_bool())
        .unwrap_or(false);
    let mut r = client::request("POST", "/kiri/stop", None)?;
    if r.status == 404 {
        r = client::request("POST", "/kiri/sleep", None)?;
    }
    if !r.ok() {
        return Err(io::Error::other(r.error()));
    }
    Ok(!was_stopped)
}

#[cfg(unix)]
fn restart_silent() -> io::Result<()> {
    #[cfg(target_os = "macos")]
    if !client::alive() {
        return start_silent();
    }
    client::check_alive_with(start_not_running_message())?;
    let sleep = client::request("POST", "/kiri/sleep", None)?;
    if !sleep.ok() && sleep.status != 404 {
        return Err(io::Error::other(sleep.error()));
    }
    let wake = client::request("POST", "/kiri/wake", None)?;
    if !wake.ok() && wake.status != 404 {
        return Err(io::Error::other(wake.error()));
    }
    Ok(())
}

#[cfg(unix)]
fn collect_status() -> io::Result<StatusReport> {
    let sock = client::socket()?;
    #[cfg(target_os = "macos")]
    let stopped_marker = crate::daemon::state_dir().ok().map(|d| d.join("stopped"));
    #[cfg(not(target_os = "macos"))]
    let stopped_marker: Option<std::path::PathBuf> = None;
    collect_status_at(&sock, stopped_marker.as_deref())
}

#[cfg(unix)]
pub(crate) fn collect_status_at(sock: &std::path::Path, stopped_marker: Option<&std::path::Path>) -> io::Result<StatusReport> {
    let sock_str = sock.display().to_string();
    match client::probe_socket(sock) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Err(e),
        Err(_) => {
            if stopped_marker.is_some_and(std::path::Path::is_file) {
                return Ok(StatusReport::stopped_offline(sock_str));
            }
            return Ok(StatusReport::not_running(sock_str));
        }
    }
    let info = client::get_background_at(sock, "/info")?;
    let ver = client::get_background_at(sock, "/version").ok();
    Ok(StatusReport::from_daemon(sock_str, &info, ver.as_ref()))
}

// ---- Windows implementation (`kiri-win` pipe + WSL 2) ----

#[cfg(windows)]
fn wsl_exe() -> std::path::PathBuf {
    let system = std::env::var_os("SystemRoot")
        .map_or_else(|| std::path::PathBuf::from(r"C:\Windows"), std::path::PathBuf::from);
    system.join("System32").join("wsl.exe")
}

#[cfg(windows)]
fn running_wsl_distros() -> Option<Vec<String>> {
    let out = std::process::Command::new(wsl_exe())
        .args(["--list", "--running", "--quiet"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(parse_wsl_list(&out.stdout))
}

#[cfg(any(windows, test))]
fn parse_wsl_list(out: &[u8]) -> Vec<String> {
    let s = if out.contains(&0) {
        let words: Vec<u16> = out.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&words)
    } else {
        String::from_utf8_lossy(out).into_owned()
    };
    s.lines()
        .map(|l| l.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}').to_owned())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Checks whether a Windows named pipe server exists without opening a client
/// handle (opening `\\.\pipe\kiri` while not stopped would spawn `wsl.exe`).
#[cfg(windows)]
fn pipe_server_listening(pipe_name: &str) -> bool {
    use std::os::windows::ffi::OsStrExt;
    unsafe extern "system" {
        fn WaitNamedPipeW(lpNamedPipeName: *const u16, nTimeOut: u32) -> i32;
    }
    let wide: Vec<u16> = std::ffi::OsStr::new(pipe_name).encode_wide().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 string.
    unsafe { WaitNamedPipeW(wide.as_ptr(), 1) != 0 }
}

#[cfg(windows)]
fn start_silent() -> io::Result<()> {
    let pipe = client::pipe();
    if let Some(res) = crate::wsl::wake_via_pipe(&pipe) {
        match res {
            Ok(()) => {
                crate::wsl::clear_stopped_marker();
                return Ok(());
            }
            Err(e) if !matches!(e.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe) => {
                return Err(e);
            }
            Err(_) => {}
        }
    }
    crate::wsl::clear_stopped_marker();
    let distro = crate::wsl::distro().ok_or_else(|| io::Error::other("Kiri isn't set up yet. Open Kiri from the Start menu first"))?;
    let args = vec!["engine".to_owned(), "start".to_owned()];
    let status = std::process::Command::new(wsl_exe())
        .args(crate::wsl::wsl_command_args(&distro, &args))
        .stdout(std::process::Stdio::null())
        .status()
        .map_err(|e| io::Error::other(format!("could not run wsl.exe ({e})")))?;
    if !status.success() {
        return Err(io::Error::other("could not start Kiri's engine in WSL"));
    }
    Ok(())
}

#[cfg(windows)]
fn stop_silent() -> io::Result<bool> {
    let was_marked_stopped = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .is_some_and(|d| crate::wsl::stopped_marker_in(&d).is_file());
    let pipe = client::pipe();
    if let Some(res) = crate::wsl::stop_via_pipe(&pipe) {
        match res {
            Ok(()) => {
                crate::wsl::write_stopped_marker();
                return Ok(!was_marked_stopped);
            }
            Err(e) if !matches!(e.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe) => {
                return Err(e);
            }
            Err(_) => {}
        }
    }
    crate::wsl::write_stopped_marker();
    let Some(distro) = crate::wsl::distro() else {
        return Ok(false);
    };
    let is_running = running_wsl_distros()
        .map(|list| list.iter().any(|d| d.eq_ignore_ascii_case(&distro)))
        .unwrap_or(false);
    if !is_running {
        return Ok(false);
    }
    let _ = std::process::Command::new(wsl_exe())
        .args([
            "-d",
            &distro,
            "-u",
            "root",
            "-e",
            "sh",
            "-c",
            "export HOME=/var/lib/kiri-daemon; /usr/local/bin/kiri engine stop >/dev/null 2>&1 || true",
        ])
        .status();
    if distro == "kiri" {
        let _ = std::process::Command::new(wsl_exe()).args(["--terminate", &distro]).status();
    }
    Ok(!was_marked_stopped)
}

#[cfg(windows)]
fn restart_silent() -> io::Result<()> {
    let _ = stop_silent()?;
    start_silent()
}

#[cfg(windows)]
fn collect_status() -> io::Result<StatusReport> {
    let pipe = client::pipe();
    if std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .is_some_and(|d| crate::wsl::stopped_marker_in(&d).is_file())
    {
        return Ok(StatusReport::stopped_offline(pipe));
    }
    let Some(distro) = crate::wsl::distro() else {
        return Ok(StatusReport::not_running(pipe));
    };
    let distro_running = running_wsl_distros()
        .map(|list| list.iter().any(|d| d.eq_ignore_ascii_case(&distro)))
        .unwrap_or(false);
    if !distro_running {
        if pipe_server_listening(&pipe) {
            return Ok(StatusReport {
                state: EngineState::Asleep,
                awake: false,
                stopped: false,
                version: None,
                api_version: None,
                cpus: None,
                memory_bytes: None,
                containers_running: None,
                containers_stopped: None,
                socket: pipe,
            });
        }
        return Ok(StatusReport::not_running(pipe));
    }
    let out = std::process::Command::new(wsl_exe())
        .args([
            "-d",
            &distro,
            "-u",
            "root",
            "-e",
            "sh",
            "-c",
            "export HOME=/var/lib/kiri-daemon; exec /usr/local/bin/kiri engine status --json",
        ])
        .output()
        .map_err(|e| io::Error::other(format!("could not run wsl.exe ({e})")))?;
    if let Ok(mut v) = serde_json::from_slice::<Value>(&out.stdout) {
        let state = match v["state"].as_str() {
            Some("running") => EngineState::Running,
            Some("asleep") => EngineState::Asleep,
            Some("stopped") => EngineState::Stopped,
            _ => EngineState::NotRunning,
        };
        v["socket"] = Value::String(pipe.clone());
        return Ok(StatusReport {
            state,
            awake: v["awake"].as_bool().unwrap_or(false),
            stopped: v["stopped"].as_bool().unwrap_or(false),
            version: v["version"].as_str().map(str::to_owned),
            api_version: v["api_version"].as_str().map(str::to_owned),
            cpus: v["cpus"].as_u64(),
            memory_bytes: v["memory_bytes"].as_u64(),
            containers_running: v["containers_running"].as_u64(),
            containers_stopped: v["containers_stopped"].as_u64(),
            socket: pipe,
        });
    }
    Ok(StatusReport::not_running(pipe))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vec_s(words: &[&str]) -> Vec<String> {
        words.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parses_subcommands_help_and_rejects_unknown_arguments() {
        assert_eq!(parse_args(&vec_s(&["start"])).unwrap(), Action::Start);
        assert_eq!(parse_args(&vec_s(&["stop"])).unwrap(), Action::Stop);
        assert_eq!(parse_args(&vec_s(&["restart"])).unwrap(), Action::Restart);
        assert_eq!(parse_args(&vec_s(&["status"])).unwrap(), Action::Status { json: false });
        assert_eq!(parse_args(&vec_s(&["status", "--json"])).unwrap(), Action::Status { json: true });

        for h in [
            &["--help"][..],
            &["-h"],
            &["help"],
            &["start", "--help"],
            &["stop", "-h"],
            &["restart", "--help"],
            &["status", "--help"],
            &["status", "--json", "-h"],
        ] {
            assert_eq!(parse_args(&vec_s(h)).unwrap(), Action::Help, "{h:?}");
        }

        for bad in [&[][..], &["unknown"], &["start", "extra"], &["status", "--bogus"]] {
            let err = parse_args(&vec_s(bad)).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{bad:?}");
            assert_eq!(err.to_string(), USAGE);
        }
    }

    #[test]
    fn status_report_classifies_running_asleep_stopped_and_not_running() {
        let ver = json!({"KiriVersion": "0.2.3", "ApiVersion": "1.47"});

        // 1. Running (awake VM).
        let running = StatusReport::from_daemon(
            "/Users/test/.kiri/run/docker.sock",
            &json!({
                "KiriStopped": false,
                "KiriVmAwake": true,
                "KiriVersion": "0.2.3",
                "NCPU": 4,
                "KiriMemoryCeiling": 8_589_934_592u64,
                "ContainersRunning": 2,
                "ContainersStopped": 1
            }),
            Some(&ver),
        );
        assert_eq!(running.state, EngineState::Running);
        assert!(running.state.is_healthy());
        assert!(running.awake && !running.stopped);
        assert_eq!(running.version.as_deref(), Some("0.2.3"));
        assert_eq!(running.api_version.as_deref(), Some("1.47"));
        assert_eq!(running.cpus, Some(4));
        assert_eq!(running.memory_bytes, Some(8_589_934_592));
        assert_eq!(running.containers_running, Some(2));
        assert_eq!(running.containers_stopped, Some(1));
        let human = running.format_human();
        assert!(human.contains("Kiri engine: running"), "{human}");
        assert!(human.contains("4 CPUs, 8 GiB"), "{human}");
        assert!(human.contains("2 running, 1 stopped"), "{human}");

        // 2. Asleep (daemon up, VM idle-sleeping): healthy (exit 0).
        let asleep = StatusReport::from_daemon(
            "/Users/test/.kiri/run/docker.sock",
            &json!({
                "KiriStopped": false,
                "KiriVmAwake": false,
                "KiriVersion": "0.2.3",
                "NCPU": 2,
                "KiriMemoryCeiling": 4_294_967_296u64,
                "ContainersRunning": 0,
                "ContainersStopped": 3
            }),
            Some(&ver),
        );
        assert_eq!(asleep.state, EngineState::Asleep);
        assert!(asleep.state.is_healthy());
        assert!(!asleep.awake && !asleep.stopped);
        assert!(asleep.format_human().contains("VM idle; wakes on next request"));

        // 3. Explicitly stopped: unhealthy (exit 1).
        let stopped = StatusReport::from_daemon(
            "/Users/test/.kiri/run/docker.sock",
            &json!({
                "KiriStopped": true,
                "KiriVmAwake": false,
                "KiriVersion": "0.2.3"
            }),
            Some(&ver),
        );
        assert_eq!(stopped.state, EngineState::Stopped);
        assert!(!stopped.state.is_healthy());
        assert!(!stopped.awake && stopped.stopped);
        let j: Value = serde_json::to_value(&stopped).unwrap();
        assert_eq!(j["state"], "stopped");
        assert_eq!(j["stopped"], true);
        assert_eq!(j["awake"], false);

        // 4. Not running: unhealthy (exit 1).
        let down = StatusReport::not_running("/run/kiri/docker.sock");
        assert_eq!(down.state, EngineState::NotRunning);
        assert!(!down.state.is_healthy());
        let j_down: Value = serde_json::to_value(&down).unwrap();
        assert_eq!(j_down["state"], "not_running");
    }

    #[test]
    fn parses_utf16_and_utf8_wsl_running_lists() {
        let utf16: Vec<u8> = "\u{feff}Ubuntu\r\nkiri\r\n"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(parse_wsl_list(&utf16), vec!["Ubuntu", "kiri"]);
        assert_eq!(parse_wsl_list(b"Debian\nkiri\n"), vec!["Debian", "kiri"]);
    }

    #[cfg(unix)]
    #[test]
    fn collect_status_sends_background_header_and_respects_offline_stopped_marker() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;

        let dir = std::env::temp_dir().join(format!("kiri-engine-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let missing = dir.join("missing.sock");
        let marker = dir.join("stopped");
        assert_eq!(collect_status_at(&missing, Some(&marker)).unwrap().state, EngineState::NotRunning);
        std::fs::write(&marker, b"").unwrap();
        let offline_stopped = collect_status_at(&missing, Some(&marker)).unwrap();
        assert_eq!(offline_stopped.state, EngineState::Stopped);
        assert!(offline_stopped.stopped);

        // Live mock socket: every request (`/_ping`, `/info`, `/version`) must carry `X-Kiri-Background: 1`.
        let sock = dir.join("docker.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let handle = std::thread::spawn(move || {
            for expected in ["/_ping", "/info", "/version"] {
                let (mut conn, _) = listener.accept().unwrap();
                let mut req = Vec::new();
                let mut buf = [0u8; 512];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&req);
                assert!(text.starts_with(&format!("GET {expected} HTTP/1.1\r\n")), "unexpected request: {text}");
                assert!(text.to_ascii_lowercase().contains("\r\nx-kiri-background: 1\r\n"), "missing background header: {text}");
                let body = match expected {
                    "/_ping" => "OK".to_owned(),
                    "/info" => json!({"KiriStopped": false, "KiriVmAwake": false, "KiriVersion": "0.2.3", "NCPU": 6, "KiriMemoryCeiling": 12_884_901_888u64, "ContainersRunning": 0, "ContainersStopped": 1}).to_string(),
                    "/version" => json!({"KiriVersion": "0.2.3", "ApiVersion": "1.47"}).to_string(),
                    _ => unreachable!(),
                };
                write!(
                    conn,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });

        let got = collect_status_at(&sock, None).unwrap();
        handle.join().unwrap();
        assert_eq!(got.state, EngineState::Asleep);
        assert!(!got.awake && !got.stopped);
        assert_eq!(got.cpus, Some(6));
        assert_eq!(got.version.as_deref(), Some("0.2.3"));
        assert_eq!(got.api_version.as_deref(), Some("1.47"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
