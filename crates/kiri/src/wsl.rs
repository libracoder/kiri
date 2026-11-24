//! `kiri k8s`, `kiri machine`, `kiri diag`, `kiri usb`, `kiri domains`,
//! `kiri registry` and `kiri scan` on Windows: the engine's own
//! commands, run by the Linux `kiri` in the WSL distro Kiri's engine lives
//! in, as the engine runs (root, with its HOME), so it finds the daemon's
//! socket and store. `kiri diag report [--out PATH]` writes the report file
//! directly to the Windows filesystem (rather than inside the WSL Linux
//! rootfs), and `kiri machine shell` runs on Windows where it has the console
//! terminal and `docker.exe`.

#![cfg_attr(not(windows), allow(dead_code))]

use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;
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
    let distro = distro().ok_or_else(|| io::Error::other("Kiri isn't set up yet. Open Kiri from the Start menu first"))?;
    // wsl.exe from System32, never one found in the current folder.
    let system = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    let status = Command::new(system.join("System32").join("wsl.exe"))
        .args(["-d", &distro, "-u", "root", "-e", "sh", "-c", SCRIPT, "kiri"])
        .args(args)
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
    use super::{COMMANDS, parse_diag_report_args};
    use std::path::PathBuf;

    #[test]
    fn forwards_scan_to_wsl() {
        assert!(COMMANDS.contains(&"scan"));
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
