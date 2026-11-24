//! `kiri k8s`, `kiri machine`, `kiri diag`, `kiri usb`, `kiri domains`,
//! `kiri registry` and `kiri scan` on Windows: the engine's own
//! commands, run by the Linux `kiri` in the WSL distro Kiri's engine lives
//! in, as the engine runs (root, with its HOME), so it finds the daemon's
//! socket and store. `kiri diag report [--out PATH]` writes the report file
//! directly to the Windows filesystem (rather than inside the WSL Linux
//! rootfs), and `kiri machine shell` runs on Windows where it has the console
//! terminal and `docker.exe`.

#![cfg_attr(not(windows), allow(dead_code))]

use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// The commands passed to the engine in WSL.
pub const COMMANDS: &[&str] = &["k8s", "machine", "diag", "usb", "domains", "registry", "scan"];

/// In Kiri Linux, kiri-start wakes the engine if it isn't up; in a distro
/// of the user's own, systemd or wsl.conf runs it.
const SCRIPT: &str = r#"export HOME=/var/lib/kiri-daemon; [ -x /usr/local/bin/kiri-start ] && /usr/local/bin/kiri-start >/dev/null 2>&1; exec /usr/local/bin/kiri "$@""#;

/// Generates the engine's diagnostics report inside WSL into a temporary file
/// and streams the report text back to `kiri.exe` on Windows so `kiri.exe` can
/// write the output file directly on the Windows filesystem.
const REPORT_SCRIPT: &str = r#"export HOME=/var/lib/kiri-daemon; [ -x /usr/local/bin/kiri-start ] && /usr/local/bin/kiri-start >/dev/null 2>&1; tmp="$(mktemp /tmp/kiri-report.XXXXXX 2>/dev/null || mktemp /run/kiri-report.XXXXXX)" || exit $?; trap 'rm -f "$tmp"' EXIT; if [ "$1" = "--send" ]; then /usr/local/bin/kiri diag report --out "$tmp" --send | grep -v '^saved the report to ' >&2 || exit $?; else /usr/local/bin/kiri diag report --out "$tmp" >/dev/null || exit $?; fi; cat "$tmp""#;

/// Parses `kiri diag report` arguments (`[--out PATH | -o PATH | --out=PATH] [--send]`).
/// Returns `None` if unrecognized flags are present so WSL's `kiri diag report`
/// prints usage and exits with its error code.
pub fn parse_diag_report_args(args: &[String]) -> Option<(Option<PathBuf>, bool)> {
    let mut out = None;
    let mut send_it = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" | "-o" => {
                let p = it.next()?.trim();
                if p.is_empty() {
                    return None;
                }
                out = Some(PathBuf::from(p));
            }
            s if s.starts_with("--out=") => {
                let p = s["--out=".len()..].trim();
                if p.is_empty() {
                    return None;
                }
                out = Some(PathBuf::from(p));
            }
            "--send" => send_it = true,
            _ => return None,
        }
    }
    Some((out, send_it))
}

fn default_windows_report_out() -> io::Result<PathBuf> {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("USERPROFILE is not set"))?;
    let desktop = home.join("Desktop");
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let dir = if desktop.is_dir() { desktop } else { home };
    Ok(dir.join(format!("kiri-report-{secs}.txt")))
}

fn redact_windows_home(text: &str) -> String {
    let Some(home) = std::env::var("USERPROFILE").ok().filter(|h| !h.is_empty()) else {
        return text.to_owned();
    };
    let slash = home.replace('\\', "/");
    text.replace(&home, "~").replace(&slash, "~")
}

fn windows_ui_log_section() -> String {
    const TAIL_MAX: u64 = 120 << 10;
    let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") else {
        return String::new();
    };
    let path = PathBuf::from(local_app_data).join("Kiri").join("kiri-win.log");
    let Ok(mut f) = std::fs::File::open(&path) else {
        return String::new();
    };
    let len = f.metadata().map_or(0, |m| m.len());
    let from = len.saturating_sub(TAIL_MAX);
    if f.seek(SeekFrom::Start(from)).is_err() {
        return String::new();
    }
    let mut buf = Vec::new();
    let _ = f.take(TAIL_MAX).read_to_end(&mut buf);
    let raw = String::from_utf8_lossy(&buf);
    let body = match (from > 0, raw.find('\n')) {
        (true, Some(i)) => &raw[i + 1..],
        (true, None) => "",
        (false, _) => &raw,
    };
    if body.trim().is_empty() {
        return String::new();
    }
    let redacted = redact_windows_home(body.trim_end());
    format!("\n==== Windows UI log (%LOCALAPPDATA%\\Kiri\\kiri-win.log) ====\n{redacted}\n")
}

fn diag_report(rest: &[String]) -> io::Result<bool> {
    let Some((chosen_out, send_it)) = parse_diag_report_args(rest) else {
        return Ok(false);
    };
    let out_path = match chosen_out {
        Some(p) => p,
        None => default_windows_report_out()?,
    };
    let distro = distro().ok_or_else(|| io::Error::other("Kiri isn't set up yet. Open Kiri from the Start menu first"))?;
    let system = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    let mut cmd = Command::new(system.join("System32").join("wsl.exe"));
    cmd.args(["-d", &distro, "-u", "root", "-e", "sh", "-c", REPORT_SCRIPT, "kiri"]);
    if send_it {
        cmd.arg("--send");
    }
    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| io::Error::other(format!("could not run wsl.exe ({e})")))?;
    if !output.status.success() {
        std::process::exit(output.status.code().unwrap_or(1));
    }
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    if text.trim().is_empty() {
        text = format!("Kiri diagnostics report\nVersion: {}\n", env!("CARGO_PKG_VERSION"));
    }
    text.push_str(&windows_ui_log_section());
    let text = redact_windows_home(&text);
    if let Some(parent) = out_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&out_path, text.as_bytes())?;
    println!("saved the report to {}", redact_windows_home(&out_path.display().to_string()));
    Ok(true)
}

/// Normalizes `kiri k8s set` arguments before passing them through `wsl.exe`,
/// combining `["--flag", ""]` into `["--flag="]` so `wsl.exe` on Windows never
/// receives a bare empty string token that its command-line splitter could drop.
pub(crate) fn forward_args(args: &[String]) -> Vec<String> {
    if args.first().map(String::as_str) != Some("k8s") || args.get(1).map(String::as_str) != Some("set") {
        return args.to_vec();
    }
    let mut out = vec![args[0].clone(), args[1].clone()];
    let mut it = args[2..].iter();
    while let Some(a) = it.next() {
        if matches!(a.as_str(), "--version" | "--k3s-arg" | "--tls-san" | "--port" | "--lan") {
            if let Some(val) = it.next() {
                if val.is_empty() {
                    out.push(format!("{a}="));
                } else {
                    out.push(a.clone());
                    out.push(val.clone());
                }
            } else {
                out.push(a.clone());
            }
        } else {
            out.push(a.clone());
        }
    }
    out
}

/// Builds the full `wsl.exe` argument vector for forwarding `kiri <args>` into WSL.
pub(crate) fn wsl_command_args(distro: &str, args: &[String]) -> Vec<String> {
    let mut out: Vec<String> = ["-d", distro, "-u", "root", "-e", "sh", "-c", SCRIPT, "kiri"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    out.extend(forward_args(args));
    out
}

/// Default Windows named pipe served by `kiri-win.exe`.
const PIPE: &str = r"\\.\pipe\kiri";

/// Path to the Windows-side stopped marker (`%LOCALAPPDATA%\Kiri\stopped`),
/// shared with `kiri-win.exe`.
pub(crate) fn stopped_marker_in(local_app_data: &Path) -> PathBuf {
    local_app_data.join("Kiri").join("stopped")
}

/// Removes `%LOCALAPPDATA%\Kiri\stopped` if present.
pub(crate) fn clear_stopped_marker_at(path: &Path) {
    let _ = std::fs::remove_file(path);
}

fn clear_stopped_marker() {
    if let Some(dir) = std::env::var_os("LOCALAPPDATA") {
        clear_stopped_marker_at(&stopped_marker_in(&PathBuf::from(dir)));
    }
}

/// Sends `POST /kiri/wake` over an open pipe/stream so a running `kiri-win.exe`
/// clears its in-memory `STOPPED` gate, removes `%LOCALAPPDATA%\Kiri\stopped`,
/// boots WSL, and updates the window/tray immediately.
pub(crate) fn wake_over_stream(mut stream: impl Read + Write) -> io::Result<()> {
    stream.write_all(b"POST /kiri/wake HTTP/1.1\r\nHost: kiri\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")?;
    stream.flush()?;
    let mut r = BufReader::new(stream);
    let mut status_line = String::new();
    if r.read_line(&mut status_line)? == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Kiri closed the connection without answering"));
    }
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Kiri is not answering"))?;
    let mut content_len: Option<usize> = None;
    let mut chunked = false;
    let mut line = String::new();
    loop {
        line.clear();
        if r.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse().ok();
            } else if k.eq_ignore_ascii_case("transfer-encoding") {
                chunked = v.trim().eq_ignore_ascii_case("chunked");
            }
        }
    }
    if (200..300).contains(&status) || status == 404 {
        return Ok(());
    }
    let mut body = Vec::new();
    if let Some(n) = content_len {
        body.resize(n.min(64 * 1024), 0);
        let _ = r.read_exact(&mut body);
    } else if chunked {
        line.clear();
        if r.read_line(&mut line).is_ok()
            && let Ok(n) = usize::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16)
            && n > 0
        {
            body.resize(n.min(64 * 1024), 0);
            let _ = r.read_exact(&mut body);
        }
    } else {
        let _ = r.take(64 * 1024).read_to_end(&mut body);
    }
    let msg = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v["message"].as_str().map(str::to_owned))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            let text = String::from_utf8_lossy(&body).trim().to_owned();
            if text.is_empty() { format!("HTTP {status}") } else { text }
        });
    Err(io::Error::other(msg))
}

#[cfg(windows)]
fn wake_via_pipe(pipe_name: &str) -> Option<io::Result<()>> {
    use std::os::windows::fs::OpenOptionsExt;
    const ERROR_PIPE_BUSY: i32 = 231;
    const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
    for _ in 0..20 {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(pipe_name)
        {
            Ok(file) => return Some(wake_over_stream(file)),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
    None
}

#[cfg(not(windows))]
fn wake_via_pipe(_pipe_name: &str) -> Option<io::Result<()>> {
    None
}

/// Runs `kiri <args>` in WSL and exits with its exit code.
pub fn run(args: &[String]) -> io::Result<()> {
    if let [m, verb, name, rest @ ..] = args
        && m == "machine"
        && verb == "shell"
    {
        return machine_shell(name, rest);
    }
    if let [d, verb, rest @ ..] = args
        && d == "diag"
        && verb == "report"
        && diag_report(rest)?
    {
        return Ok(());
    }
    if args.len() == 1 && args[0] == "start" {
        if let Some(res) = wake_via_pipe(PIPE) {
            match res {
                Ok(()) => {
                    clear_stopped_marker();
                    println!("Kiri is started");
                    return Ok(());
                }
                Err(e) if !matches!(e.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe) => {
                    return Err(e);
                }
                Err(_) => {}
            }
        }
        clear_stopped_marker();
    }
    let distro = distro().ok_or_else(|| io::Error::other("Kiri isn't set up yet. Open Kiri from the Start menu first"))?;
    // wsl.exe from System32, never one found in the current folder.
    let system = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    let status = Command::new(system.join("System32").join("wsl.exe"))
        .args(wsl_command_args(&distro, args))
        .status()
        .map_err(|e| io::Error::other(format!("could not run wsl.exe ({e})")))?;
    std::process::exit(status.code().unwrap_or(1))
}

/// The distro setup put the engine in (crates/kiri-win/src/setup.rs).
fn distro() -> Option<String> {
    let dir = PathBuf::from(std::env::var_os("LOCALAPPDATA")?).join("Kiri");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.join("setup.json")).ok()?).ok()?;
    v["distro"].as_str().map(str::to_owned)
}

/// `kiri machine shell NAME [-- CMD...]` on Windows: Kiri's docker.exe runs
/// the exec, with the console as its terminal, as `kiri exec` does
/// (crates/kiri/src/docker.rs). Kiri's WSL distro has no docker CLI, so the
/// Linux `kiri` could not open it there. The machine was made by root in
/// WSL, so the shell is root's, in /root.
fn machine_shell(name: &str, rest: &[String]) -> io::Result<()> {
    use std::io::IsTerminal;
    let tty = if std::io::stdin().is_terminal() { "-it" } else { "-i" };
    let mut args: Vec<String> = ["exec", tty, "-u", "root", "-w", "/root", "-e", "HOME=/root"].map(str::to_owned).to_vec();
    args.push(format!("machine-{name}"));
    match rest {
        [dd, cmd @ ..] if dd == "--" && !cmd.is_empty() => args.extend(cmd.iter().cloned()),
        // bash when the distro has it, else its sh.
        _ => args.extend(["sh", "-c", "exec $(command -v bash || command -v sh) -l"].map(str::to_owned)),
    }
    crate::docker::run(&args)
}

#[cfg(test)]
mod tests {
    use super::{COMMANDS, SCRIPT, clear_stopped_marker_at, forward_args, parse_diag_report_args, stopped_marker_in, wake_over_stream, wsl_command_args};
    use std::io::{self, Cursor, Read, Write};
    use std::path::PathBuf;

    struct MockPipe {
        sent: Vec<u8>,
        reply: Cursor<Vec<u8>>,
    }

    impl MockPipe {
        fn new(reply: &[u8]) -> Self {
            Self { sent: Vec::new(), reply: Cursor::new(reply.to_vec()) }
        }
    }

    impl Read for MockPipe {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reply.read(buf)
        }
    }

    impl Write for MockPipe {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.sent.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn windows_start_clears_stopped_marker_and_wakes_over_pipe() {
        let dir = std::env::temp_dir().join(format!("kiri-wsl-start-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let marker = stopped_marker_in(&dir);
        assert_eq!(marker, dir.join("Kiri").join("stopped"));
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        std::fs::write(&marker, b"").unwrap();
        assert!(marker.is_file());
        clear_stopped_marker_at(&marker);
        assert!(!marker.exists());
        // Clearing when already absent is a no-op.
        clear_stopped_marker_at(&marker);

        // 204 No Content succeeds and sends POST /kiri/wake.
        let mut pipe = MockPipe::new(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
        wake_over_stream(&mut pipe).unwrap();
        let wire = String::from_utf8(pipe.sent).unwrap();
        assert!(wire.starts_with("POST /kiri/wake HTTP/1.1\r\n"), "{wire}");
        assert!(wire.contains("\r\nConnection: close\r\n"), "{wire}");

        // 404 (older engine without wake) is also accepted cleanly.
        let mut old = MockPipe::new(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        wake_over_stream(&mut old).unwrap();

        // 503 surfaces the daemon/pipe JSON message.
        let body = r#"{"message":"Kiri's setup isn't finished: open Kiri to finish it"}"#;
        let reply = format!("HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let mut refused = MockPipe::new(reply.as_bytes());
        let err = wake_over_stream(&mut refused).unwrap_err();
        assert_eq!(err.to_string(), "Kiri's setup isn't finished: open Kiri to finish it");

        // Closed pipe without response returns UnexpectedEof so caller can fall back.
        let mut eof = MockPipe::new(b"");
        let err = wake_over_stream(&mut eof).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn forwards_scan_to_wsl() {
        assert!(COMMANDS.contains(&"scan"));
    }

    #[test]
    fn forwards_k8s_set_version_and_k3s_args_to_wsl() {
        assert!(COMMANDS.contains(&"k8s"));
        let s = |list: &[&str]| list.iter().map(|x| (*x).to_owned()).collect::<Vec<String>>();
        let args = s(&[
            "k8s",
            "set",
            "--version",
            "v1.31.4-k3s1",
            "--k3s-arg",
            "--flannel-backend=none",
            "--k3s-arg",
            "--disable=traefik",
            "--clear-k3s-args",
        ]);
        assert_eq!(
            wsl_command_args("Kiri", &args),
            s(&[
                "-d",
                "Kiri",
                "-u",
                "root",
                "-e",
                "sh",
                "-c",
                SCRIPT,
                "kiri",
                "k8s",
                "set",
                "--version",
                "v1.31.4-k3s1",
                "--k3s-arg",
                "--flannel-backend=none",
                "--k3s-arg",
                "--disable=traefik",
                "--clear-k3s-args",
            ])
        );
        // Empty string values (`--version ""`, `--tls-san ""`, `--k3s-arg ""`) are combined into
        // `--flag=` so wsl.exe on Windows cannot drop a bare empty token.
        assert_eq!(
            forward_args(&s(&["k8s", "set", "--version", "", "--tls-san", ""])),
            s(&["k8s", "set", "--version=", "--tls-san="])
        );
        assert_eq!(
            forward_args(&s(&["k8s", "set", "--version", "default"])),
            s(&["k8s", "set", "--version", "default"])
        );
    }

    #[test]
    fn parses_windows_diag_report_out_and_send_flags() {
        let s = |list: &[&str]| list.iter().map(|x| (*x).to_owned()).collect::<Vec<String>>();
        assert_eq!(parse_diag_report_args(&s(&[])), Some((None, false)));
        assert_eq!(
            parse_diag_report_args(&s(&["--out", r"C:\Temp\kiri-test-report.txt"])),
            Some((Some(PathBuf::from(r"C:\Temp\kiri-test-report.txt")), false))
        );
        assert_eq!(
            parse_diag_report_args(&s(&["-o", r"C:\Temp\report.txt", "--send"])),
            Some((Some(PathBuf::from(r"C:\Temp\report.txt")), true))
        );
        assert_eq!(
            parse_diag_report_args(&s(&[r"--out=C:\Temp\eq-report.txt"])),
            Some((Some(PathBuf::from(r"C:\Temp\eq-report.txt")), false))
        );
        assert_eq!(parse_diag_report_args(&s(&["--out"])), None);
        assert_eq!(parse_diag_report_args(&s(&["--unknown"])), None);
    }
}
