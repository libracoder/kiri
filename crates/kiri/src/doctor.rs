//! `kiri doctor`: whether this installation works, one line per part, and
//! what to run for a part that doesn't (#747). It asks what the window and
//! `kiri diag report` already ask, as the window's own background requests
//! (they neither wake the VM nor count as use), and changes nothing: each
//! fix stays its own command.
//!
//! On Windows the engine's lines come from the `kiri` in WSL, asked without
//! `kiri-start` so a stopped engine stays stopped, and the docker line from
//! the user's own `docker.exe`.

use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::flavor::CONTEXT;

const USAGE: &str = "usage: kiri doctor [--json]   whether Kiri works here, and what to run when a part doesn't (exit 1 on a failure)";

/// How long the engine gets for all its answers, and docker for its.
const ENGINE_WAIT: Duration = Duration::from_secs(10);
const DOCKER_WAIT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq)]
enum Status {
    Ok,
    /// Works, but not all the way: names, a router moved aside, docker elsewhere.
    Warn,
    /// Kiri can't be used until it is put right: the exit code says so.
    Fail,
}

impl Status {
    fn word(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Warn => "warn",
            Status::Fail => "fail",
        }
    }

    #[cfg(any(windows, test))]
    fn from_word(w: &str) -> Option<Status> {
        [Status::Ok, Status::Warn, Status::Fail]
            .into_iter()
            .find(|s| s.word() == w)
    }
}

#[derive(Debug, PartialEq)]
struct Check {
    name: String,
    status: Status,
    detail: String,
}

fn check(name: impl Into<String>, status: Status, detail: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        status,
        detail: detail.into(),
    }
}

pub fn run(args: &[String]) -> io::Result<()> {
    let json = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => false,
        ["--json"] => true,
        ["-h" | "--help" | "help"] => {
            println!("{USAGE}");
            return Ok(());
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, USAGE)),
    };
    let checks = checks();
    if json {
        println!("{}", to_json(&checks));
    } else {
        print!("{}", render(&checks));
    }
    if checks.iter().any(|c| c.status == Status::Fail) {
        // The lines said what is wrong; a `kiri: …` line after them would only repeat it.
        std::process::exit(1);
    }
    Ok(())
}

// ---- the engine (Mac, Linux, and WSL for Windows) ----

#[cfg(any(unix, test))]
/// An answer from the engine: its JSON, or the error's kind and text. `None`
/// in its slot means no answer within `ENGINE_WAIT`.
type Answer = Option<Result<Value, (io::ErrorKind, String)>>;

#[cfg(unix)]
/// What the engine is asked, in order: once /_ping fails nothing else is.
const ASKED: [&str; 4] = ["/_ping", "/version", "/info", "/kiri/domains"];

#[cfg(unix)]
fn checks() -> Vec<Check> {
    // Set by Windows' `kiri doctor`, which checks docker on its own side.
    let forwarded = std::env::var_os("KIRI_DOCTOR_FORWARDED").is_some();
    let socket = crate::client::socket()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "?".into());
    let got = engine_answers();
    // Down, the engine can't say; a read-only disk is what keeps it down (#768).
    let local = if matches!(got[0], Some(Ok(_))) {
        None
    } else {
        crate::daemon::rofs::check_daemon_storage(None)
    };
    let mut out = engine_checks(&got, &socket, forwarded, local);
    if !forwarded {
        let create = format!(
            "docker context create {c} --docker host=unix://{socket} && docker context use {c}",
            c = CONTEXT.get()
        );
        out.insert(1, docker(&ours_unix, &create));
    }
    #[cfg(target_os = "macos")]
    out.push(names(crate::daemon::dns::installed()));
    out
}

/// The engine's answers, each as soon as it comes, for at most `ENGINE_WAIT`
/// in all: an engine that is hung, or answers a byte at a time, would
/// otherwise keep this waiting (the client's limit is per read).
#[cfg(unix)]
fn engine_answers() -> [Answer; 4] {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for (i, path) in ASKED.into_iter().enumerate() {
            let r = crate::client::get_background(path).map_err(|e| {
                // Nothing there, or a socket this user can't open: say it as other commands do.
                let gone = !matches!(
                    e.kind(),
                    io::ErrorKind::Other | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                );
                let e = if i == 0 && gone {
                    crate::client::check_alive().err().unwrap_or(e)
                } else {
                    e
                };
                (e.kind(), e.to_string())
            });
            let stop = i == 0 && r.is_err();
            if tx.send((i, r)).is_err() || stop {
                return;
            }
        }
    });
    let until = Instant::now() + ENGINE_WAIT;
    let mut got: [Answer; 4] = Default::default();
    while let Ok((i, r)) = rx.recv_timeout(until.saturating_duration_since(Instant::now())) {
        got[i] = Some(r);
    }
    got
}

#[cfg(any(unix, test))]
/// The engine's lines from its answers: engine, http, https, storage.
fn engine_checks(
    got: &[Answer; 4],
    socket: &str,
    forwarded: bool,
    local_storage: Option<String>,
) -> Vec<Check> {
    let mut out = Vec::new();
    let engine = match &got[0] {
        None => check(
            "engine",
            Status::Fail,
            format!(
                "{socket} took the connection but answered nothing in 10 s: the engine may be hung (kiri diag logs --engine)"
            ),
        ),
        Some(Err((io::ErrorKind::Other, m))) => check(
            "engine",
            Status::Fail,
            format!("the engine answers, with an error: {m}"),
        ),
        Some(Err((io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut, _))) => check(
            "engine",
            Status::Fail,
            format!(
                "{socket} took the connection but answered nothing: the engine may be hung (kiri diag logs --engine)"
            ),
        ),
        Some(Err((io::ErrorKind::PermissionDenied, m))) => check("engine", Status::Fail, m.clone()),
        Some(Err(_)) if forwarded => check(
            "engine",
            Status::Fail,
            "the engine isn't running in Kiri's WSL distro: kiri start",
        ),
        Some(Err((_, m))) => check("engine", Status::Fail, m.clone()),
        Some(Ok(_)) => engine_line(&got[1], &got[2], socket),
    };
    out.push(engine);
    if !matches!(got[0], Some(Ok(_))) {
        out.extend(local_storage.map(|m| check("storage", Status::Fail, m)));
        return out;
    }
    out.extend(domains(&got[3]));
    out.extend(storage(&got[2]));
    out
}

#[cfg(any(unix, test))]
fn engine_line(version: &Answer, info: &Answer, socket: &str) -> Check {
    let mut c = match version {
        None => check(
            "engine",
            Status::Warn,
            "answers /_ping but not /version within 10 s: it may be busy or hung",
        ),
        Some(Err((_, m))) => check(
            "engine",
            Status::Warn,
            format!("answers /_ping, but /version failed: {m}"),
        ),
        // A Docker engine of another kind behind KIRI_SOCKET.
        Some(Ok(v)) if v["Platform"]["Name"].as_str().is_some_and(|n| n != "Kiri") => check(
            "engine",
            Status::Warn,
            format!(
                "{socket} is {}, not Kiri",
                v["Platform"]["Name"].as_str().unwrap_or("?")
            ),
        ),
        // KiriVersion, or Version from an engine older than that field (client::kiri_version).
        Some(Ok(v)) => check(
            "engine",
            Status::Ok,
            format!(
                "Kiri {}, socket {socket}",
                v["KiriVersion"]
                    .as_str()
                    .or_else(|| v["Version"].as_str())
                    .unwrap_or("?")
            ),
        ),
    };
    if matches!(info, Some(Ok(i)) if i["KiriStopped"] == true) {
        c.status = Status::Warn;
        c.detail
            .push_str("; stopped (Stop in the window or tray): kiri start starts it");
    }
    c
}

#[cfg(any(unix, test))]
/// The `*.kiri.local` routers, from the engine's `/kiri/domains`.
fn domains(answer: &Answer) -> Vec<Check> {
    let both = |status, detail: String| {
        vec![
            check("http", status, detail.clone()),
            check("https", status, detail),
        ]
    };
    let report = match answer {
        None => return both(Status::Warn, "the engine didn't say within 10 s".into()),
        Some(Err((_, m))) => return both(Status::Warn, format!("the engine didn't say: {m}")),
        Some(Ok(r)) if r["http"].is_object() && r["https"].is_object() => r,
        Some(Ok(_)) => return both(Status::Warn, "the engine's answer wasn't readable".into()),
    };
    ["http", "https"]
        .into_iter()
        .map(|key| {
            let r = &report[key];
            let port = r["port"].as_u64().map_or_else(|| "?".into(), |p| p.to_string());
            // A port set by the environment can't be moved here (domains.rs refuses it).
            let (by, fix) = match r["env"].as_str() {
                Some(var) => (format!(" (set by {var})"), format!("change or unset {var}")),
                None => (String::new(), format!("kiri domains set --{key} N")),
            };
            match (r["running"] == true, r["serving"] != false) {
                (true, true) => check(key, Status::Ok, format!("port {port}{by}")),
                (true, false) => check(key, Status::Warn, format!("port {port}{by}: a container has the port for now; {fix} moves the router")),
                (false, _) => check(key, Status::Warn, format!("off, port {port}{by}: names under kiri.local don't answer over {key}; {fix} tries another port")),
            }
        })
        .collect()
}

#[cfg(any(unix, test))]
/// The engine's storage: read-only means nothing can be written (#768). An
/// engine that predates the field says nothing, and nor does this.
fn storage(info: &Answer) -> Option<Check> {
    match info {
        None => Some(check(
            "storage",
            Status::Warn,
            "the engine didn't say within 10 s",
        )),
        Some(Err((_, m))) => Some(check(
            "storage",
            Status::Warn,
            format!("the engine didn't say: {m}"),
        )),
        Some(Ok(i)) => match i.get("KiriStorageReadOnly") {
            Some(Value::String(why)) => Some(check("storage", Status::Fail, why.clone())),
            Some(_) => Some(check("storage", Status::Ok, "writable")),
            None => None,
        },
    }
}

/// macOS sends `*.kiri.local` lookups to Kiri only with its resolver file.
#[cfg(any(target_os = "macos", test))]
fn names(installed: bool) -> Check {
    if installed {
        check("names", Status::Ok, "*.kiri.local resolves to Kiri")
    } else {
        check(
            "names",
            Status::Warn,
            "*.kiri.local doesn't resolve (/etc/resolver/kiri.local is missing; *.kiri.localhost works): kiri setup --domains",
        )
    }
}

// ---- docker ----

/// Whether a docker host is this Kiri's socket: `Some(false)` only when
/// both are local sockets and resolve to different files (another Kiri,
/// such as the installed one next to Kiri Dev).
#[cfg(unix)]
fn ours_unix(host: &str) -> Option<bool> {
    let theirs = std::fs::canonicalize(host.strip_prefix("unix://")?).ok()?;
    let ours = std::fs::canonicalize(crate::client::socket().ok()?).ok()?;
    Some(theirs == ours)
}

enum Reached {
    /// The server's platform name ("" from an engine that has none).
    Server(String),
    Failed,
    TimedOut,
}

/// Which engine plain `docker` reaches, asked of docker itself, so a
/// context, DOCKER_HOST and a packaged wrapper count as they do for the user.
fn docker(ours: &dyn Fn(&str) -> Option<bool>, create: &str) -> Check {
    let until = Instant::now() + DOCKER_WAIT;
    let docker = || {
        let mut c = Command::new("docker");
        c.env_remove("KIRI_DOCTOR_FORWARDED");
        c
    };
    let version = match run_for(
        docker().args(["version", "--format", "{{.Server.Platform.Name}}"]),
        until,
    ) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return check("docker", Status::Warn, "no `docker` command found on PATH");
        }
        Err(e) => {
            return check(
                "docker",
                Status::Warn,
                format!("`docker` couldn't be run: {e}"),
            );
        }
        Ok(r) => r,
    };
    let (reached, why) = match &version {
        None => (Reached::TimedOut, String::new()),
        Some(r) if r.ok => (
            Reached::Server(first_line(&text(&r.out)).to_owned()),
            String::new(),
        ),
        // docker's own error is its last line; Docker Desktop's WSL shim says why on stdout, first.
        Some(r) => {
            let err = text(&r.err);
            let why = match err.lines().rev().find(|l| !l.trim().is_empty()) {
                Some(last) => first_line(last).to_owned(),
                None => first_line(&text(&r.out)).to_owned(),
            };
            (Reached::Failed, why)
        }
    };
    let context = run_for(
        docker().args([
            "context",
            "inspect",
            "--format",
            "{{.Name}}\t{{.Endpoints.docker.Host}}",
        ]),
        Instant::now() + Duration::from_secs(2),
    )
    .ok()
    .flatten()
    .filter(|r| r.ok)
    .and_then(|r| {
        text(&r.out)
            .lines()
            .next()
            .and_then(|l| l.split_once('\t'))
            .map(|(n, h)| (n.to_owned(), h.to_owned()))
    });
    let env_host = std::env::var("DOCKER_HOST").ok().filter(|s| !s.is_empty());
    let pinned = if env_host.is_some() {
        Some("DOCKER_HOST")
    } else if std::env::var_os("DOCKER_CONTEXT").is_some_and(|s| !s.is_empty()) {
        Some("DOCKER_CONTEXT")
    } else {
        None
    };
    let (name, ctx_host) = context
        .as_ref()
        .map_or((None, None), |(n, h)| (Some(n.as_str()), Some(h.as_str())));
    let host = env_host.as_deref().or(ctx_host);
    let ours = host.and_then(ours);
    let have_ours = || {
        run_for(
            docker().args(["context", "inspect", CONTEXT.get()]),
            Instant::now() + Duration::from_secs(2),
        )
        .ok()
        .flatten()
        .is_some_and(|r| r.ok)
    };
    let fix = match pinned {
        Some(var) => format!("unset {var}, or point it at Kiri"),
        // At this Kiri already: nothing to say, and no time spent asking.
        None if ours != Some(false) && matches!(reached, Reached::Server(ref n) if n == "Kiri") => {
            String::new()
        }
        None if have_ours() => format!("docker context use {}", CONTEXT.get()),
        None => create.to_owned(),
    };
    docker_verdict(&reached, &why, name, host, pinned, ours, &fix)
}

fn docker_verdict(
    reached: &Reached,
    why: &str,
    context: Option<&str>,
    host: Option<&str>,
    pinned: Option<&str>,
    ours: Option<bool>,
    fix: &str,
) -> Check {
    let how = match (pinned, context) {
        (Some(var), _) => format!("{var} is set"),
        (None, Some(c)) => format!("context `{c}`"),
        (None, None) => "context unknown".into(),
    };
    // Already pointed at Kiri: no answer then is the engine's trouble, not docker's.
    let at_kiri = ours == Some(true) || (pinned.is_none() && context == Some(CONTEXT.get()));
    match reached {
        Reached::Server(n) if n == "Kiri" && ours == Some(false) => check(
            "docker",
            Status::Warn,
            format!(
                "`docker` reaches another Kiri ({how}, {}): {fix}",
                host.unwrap_or("?")
            ),
        ),
        Reached::Server(n) if n == "Kiri" => check(
            "docker",
            Status::Ok,
            format!("`docker` reaches Kiri ({how})"),
        ),
        Reached::Server(n) if !n.is_empty() => check(
            "docker",
            Status::Warn,
            format!("`docker` reaches {n}, not Kiri ({how}): {fix}"),
        ),
        Reached::Server(_) => check(
            "docker",
            Status::Warn,
            format!("`docker` reaches an engine that isn't Kiri ({how}): {fix}"),
        ),
        Reached::Failed | Reached::TimedOut if at_kiri => check(
            "docker",
            Status::Warn,
            format!("`docker` is set to Kiri ({how}) but gets no answer: see the engine line"),
        ),
        Reached::Failed => check(
            "docker",
            Status::Warn,
            format!(
                "`docker` reaches no engine ({how}): {}; {fix}",
                if why.is_empty() { "no answer" } else { why }
            ),
        ),
        Reached::TimedOut => check(
            "docker",
            Status::Warn,
            format!("`docker` got no answer in 10 s ({how}): {fix}"),
        ),
    }
}

/// A line of a tool's output fit for one line here: its first non-empty
/// one, cut at 200 characters.
fn first_line(s: &str) -> &str {
    let l = s
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    l.char_indices().nth(200).map_or(l, |(i, _)| &l[..i])
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

struct Ran {
    ok: bool,
    out: Vec<u8>,
    err: Vec<u8>,
}

/// Runs `cmd` until `until` at the latest, its output read as it comes (so
/// a full pipe never stalls it). Past `until` it is killed with what it
/// started, and the answer is `None`.
fn run_for(cmd: &mut Command, until: Instant) -> io::Result<Option<Ran>> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(cmd, 0);
    #[cfg(windows)]
    std::os::windows::process::CommandExt::creation_flags(cmd, 0x0800_0000);
    let mut child = cmd.spawn()?;
    let (out, err) = (reader(child.stdout.take()), reader(child.stderr.take()));
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if Instant::now() >= until {
            kill_tree(&mut child);
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // A process it left holding the pipes doesn't hold this up past `until`.
    let grace = until
        .saturating_duration_since(Instant::now())
        .max(Duration::from_millis(200));
    let take = |rx: mpsc::Receiver<Vec<u8>>| rx.recv_timeout(grace).unwrap_or_default();
    Ok(Some(Ran {
        ok: status.success(),
        out: take(out),
        err: take(err),
    }))
}

fn reader(r: Option<impl Read + Send + 'static>) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut b = Vec::new();
        if let Some(mut r) = r {
            let _ = r.read_to_end(&mut b);
        }
        let _ = tx.send(b);
    });
    rx
}

/// Kills `child` and every process it started (its process group; on
/// Windows, its tree).
fn kill_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: a plain signal to the group this child leads (`process_group(0)`).
        unsafe {
            libc::killpg(pid, libc::SIGKILL);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        let _ = Command::new("taskkill")
            .args(["/F", "/T", "/PID", &child.id().to_string()])
            .creation_flags(0x0800_0000)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

// ---- Windows ----

/// The engine's own `kiri doctor` in WSL, without kiri-start (which would
/// start a stopped engine) and without its docker line.
#[cfg(any(windows, test))]
const FORWARD_SCRIPT: &str = r#"export HOME=/var/lib/kiri-daemon KIRI_DOCTOR_FORWARDED=1; exec /usr/local/bin/kiri doctor --json"#;

#[cfg(windows)]
fn checks() -> Vec<Check> {
    let mut out = engine_from_wsl();
    out.insert(
        1.min(out.len()),
        docker(
            &|_| None,
            &format!(
                "docker context use {} (Kiri creates it at start)",
                CONTEXT.get()
            ),
        ),
    );
    out
}

#[cfg(windows)]
fn engine_from_wsl() -> Vec<Check> {
    let stopped = |why: String| {
        vec![check(
            "engine",
            Status::Warn,
            format!("stopped{why}: kiri start starts it"),
        )]
    };
    let local = std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from);
    if local
        .as_ref()
        .is_some_and(|d| crate::wsl::stopped_marker_in(d).exists())
    {
        return stopped(" (Stop in the window or tray)".into());
    }
    let Some(distro) = crate::wsl::distro() else {
        return vec![check(
            "engine",
            Status::Fail,
            "Kiri isn't set up yet: open Kiri from the Start menu",
        )];
    };
    let system = std::env::var_os("SystemRoot").map_or_else(
        || std::path::PathBuf::from(r"C:\Windows"),
        std::path::PathBuf::from,
    );
    let wsl = system.join("System32").join("wsl.exe");
    // Asking a distro that isn't running would boot it, and the engine with it.
    if let Ok(Some(r)) = run_for(
        Command::new(&wsl).args(["--list", "--running", "--quiet"]),
        Instant::now() + ENGINE_WAIT,
    ) && r.ok
        && !running_distros(&r.out)
            .iter()
            .any(|d| d.eq_ignore_ascii_case(&distro))
    {
        return stopped(format!(" (its WSL distro {distro} isn't running)"));
    }
    match run_for(Command::new(&wsl).args(["-d", &distro, "-u", "root", "-e", "sh", "-c", FORWARD_SCRIPT]), Instant::now() + ENGINE_WAIT * 3) {
        Ok(Some(r)) => from_forwarded(&text(&r.out)).unwrap_or_else(|| {
            let err = text(&r.err);
            let detail = match first_line(&err) {
                // A kiri from before `kiri doctor` prints its usage.
                why if why.is_empty() || why.starts_with("usage: kiri") => "the engine's kiri in WSL has no `kiri doctor` (it is older than this one): update Kiri".to_owned(),
                why => format!("the engine's kiri in WSL gave no doctor answer: {why}"),
            };
            vec![check("engine", Status::Fail, detail)]
        }),
        Ok(None) => vec![check("engine", Status::Fail, "the engine's kiri in WSL didn't answer in 30 s")],
        Err(e) => vec![check("engine", Status::Fail, format!("could not run wsl.exe ({e})"))],
    }
}

/// `wsl --list --quiet` writes UTF-16, one distro a line.
#[cfg(any(windows, test))]
fn running_distros(out: &[u8]) -> Vec<String> {
    let s = if out.contains(&0) {
        String::from_utf16_lossy(
            &out.as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect::<Vec<_>>(),
        )
    } else {
        text(out)
    };
    s.lines()
        .map(|l| {
            l.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
                .to_owned()
        })
        .filter(|l| !l.is_empty())
        .collect()
}

/// The checks from the WSL side's `--json`.
#[cfg(any(windows, test))]
fn from_forwarded(out: &str) -> Option<Vec<Check>> {
    let v: Value = serde_json::from_str(out.trim()).ok()?;
    v["checks"]
        .as_array()?
        .iter()
        .map(|c| {
            Some(check(
                c["name"].as_str()?,
                Status::from_word(c["status"].as_str()?)?,
                c["detail"].as_str()?,
            ))
        })
        .collect()
}

// ---- output ----

fn render(checks: &[Check]) -> String {
    checks
        .iter()
        .map(|c| format!("{:<13} {:<5} {}\n", c.name, c.status.word(), c.detail))
        .collect()
}

fn to_json(checks: &[Check]) -> Value {
    json!({
        "ok": !checks.iter().any(|c| c.status == Status::Fail),
        "checks": checks.iter().map(|c| json!({"name": c.name, "status": c.status.word(), "detail": c.detail})).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(v: Value) -> Answer {
        Some(Ok(v))
    }
    fn err(kind: io::ErrorKind, m: &str) -> Answer {
        Some(Err((kind, m.into())))
    }
    const SOCK: &str = "/run/kiri/docker.sock";
    fn healthy() -> [Answer; 4] {
        [
            ok(Value::Null),
            ok(json!({"KiriVersion": "0.2.3", "Platform": {"Name": "Kiri"}})),
            ok(json!({"KiriStorageReadOnly": null, "KiriStopped": false})),
            ok(
                json!({"http": {"port": 80, "running": true, "serving": true, "env": null}, "https": {"port": 443, "running": true, "serving": true, "env": null}}),
            ),
        ]
    }
    fn names_of(c: &[Check]) -> Vec<&str> {
        c.iter().map(|c| c.name.as_str()).collect()
    }

    #[test]
    fn a_healthy_engine_gives_four_ok_lines() {
        let c = engine_checks(&healthy(), SOCK, false, None);
        assert_eq!(names_of(&c), ["engine", "http", "https", "storage"]);
        assert!(c.iter().all(|c| c.status == Status::Ok), "{c:?}");
        assert_eq!(c[0].detail, "Kiri 0.2.3, socket /run/kiri/docker.sock");
    }

    #[test]
    fn an_engine_that_is_down_hung_or_erroring_says_which() {
        let mut got: [Answer; 4] = Default::default();
        let down = engine_checks(&got, SOCK, false, None);
        assert_eq!((down.len(), down[0].status), (1, Status::Fail));
        assert!(
            down[0].detail.contains("answered nothing in 10 s"),
            "{down:?}"
        );
        got[0] = err(io::ErrorKind::Other, "Internal Server Error");
        assert_eq!(
            engine_checks(&got, SOCK, false, None)[0].detail,
            "the engine answers, with an error: Internal Server Error"
        );
        got[0] = err(io::ErrorKind::NotConnected, "Kiri isn't running. Open Kiri");
        assert_eq!(
            engine_checks(&got, SOCK, false, None)[0].detail,
            "Kiri isn't running. Open Kiri"
        );
        assert_eq!(
            engine_checks(&got, SOCK, true, None)[0].detail,
            "the engine isn't running in Kiri's WSL distro: kiri start"
        );
        got[0] = err(
            io::ErrorKind::PermissionDenied,
            "permission denied. Run `sudo kiri host-access $USER`",
        );
        assert!(
            engine_checks(&got, SOCK, true, None)[0]
                .detail
                .starts_with("permission denied")
        );
        // Down because the disk went read-only: that is the line that says why.
        let ro = engine_checks(&got, SOCK, false, Some("Kiri's disk is read-only".into()));
        assert_eq!(
            ro[1],
            check("storage", Status::Fail, "Kiri's disk is read-only")
        );
    }

    #[test]
    fn a_stopped_or_foreign_or_slow_engine_is_not_ok() {
        let mut got = healthy();
        got[2] = ok(json!({"KiriStorageReadOnly": null, "KiriStopped": true}));
        let c = engine_checks(&got, SOCK, false, None);
        assert_eq!(c[0].status, Status::Warn);
        assert!(
            c[0].detail
                .ends_with("stopped (Stop in the window or tray): kiri start starts it"),
            "{}",
            c[0].detail
        );
        got = healthy();
        got[1] =
            ok(json!({"Version": "27.3.1", "Platform": {"Name": "Docker Engine - Community"}}));
        assert_eq!(
            engine_checks(&got, SOCK, false, None)[0].detail,
            "/run/kiri/docker.sock is Docker Engine - Community, not Kiri"
        );
        got[1] = ok(json!({"Version": "0.1.9"}));
        assert_eq!(
            engine_checks(&got, SOCK, false, None)[0],
            check(
                "engine",
                Status::Ok,
                "Kiri 0.1.9, socket /run/kiri/docker.sock"
            )
        );
        got[1] = None;
        got[2] = None;
        got[3] = None;
        let slow = engine_checks(&got, SOCK, false, None);
        assert_eq!(names_of(&slow), ["engine", "http", "https", "storage"]);
        assert!(slow.iter().all(|c| c.status == Status::Warn), "{slow:?}");
    }

    #[test]
    fn each_router_is_ok_moved_aside_off_or_unreadable() {
        let r = |http: Value| {
            ok(json!({"http": http, "https": {"port": 443, "running": true, "serving": true}}))
        };
        assert_eq!(
            domains(&r(json!({"port": 80, "running": true})))[0],
            check("http", Status::Ok, "port 80")
        );
        let moved = &domains(&r(json!({"port": 80, "running": true, "serving": false})))[0];
        assert_eq!(
            moved.detail,
            "port 80: a container has the port for now; kiri domains set --http N moves the router"
        );
        let pinned = &domains(&r(
            json!({"port": 18780, "running": false, "env": "KIRI_HTTP_PORT"}),
        ))[0];
        assert!(
            pinned
                .detail
                .starts_with("off, port 18780 (set by KIRI_HTTP_PORT)")
                && pinned
                    .detail
                    .ends_with("change or unset KIRI_HTTP_PORT tries another port"),
            "{}",
            pinned.detail
        );
        for bad in [
            ok(json!({})),
            ok(Value::Null),
            ok(json!({"http": 1, "https": 2})),
            err(
                io::ErrorKind::Other,
                "Kiri does not support GET /kiri/domains yet",
            ),
            None,
        ] {
            let c = domains(&bad);
            assert_eq!(names_of(&c), ["http", "https"]);
            assert!(
                c.iter()
                    .all(|c| c.status == Status::Warn && !c.detail.contains("tries another port")),
                "{c:?}"
            );
        }
    }

    #[test]
    fn storage_says_only_what_the_engine_said() {
        assert_eq!(
            storage(&ok(
                json!({"KiriStorageReadOnly": "the store is read-only"})
            )),
            Some(check("storage", Status::Fail, "the store is read-only"))
        );
        assert_eq!(
            storage(&ok(json!({"KiriStorageReadOnly": null}))),
            Some(check("storage", Status::Ok, "writable"))
        );
        assert_eq!(storage(&ok(json!({"Containers": 3}))), None);
        assert_eq!(
            storage(&err(io::ErrorKind::Other, "boom")).unwrap().status,
            Status::Warn
        );
        assert_eq!(storage(&None).unwrap().status, Status::Warn);
    }

    #[test]
    fn docker_is_ok_only_at_this_kiri_and_its_advice_fits_the_case() {
        let ctx = CONTEXT.get();
        let kiri = Reached::Server("Kiri".into());
        assert_eq!(
            docker_verdict(
                &kiri,
                "",
                Some(ctx),
                Some("unix:///x"),
                None,
                Some(true),
                ""
            )
            .status,
            Status::Ok
        );
        let other_kiri = docker_verdict(
            &kiri,
            "",
            Some("default"),
            Some("unix:///var/run/docker.sock"),
            None,
            Some(false),
            "docker context use kiri",
        );
        assert!(
            other_kiri.status == Status::Warn && other_kiri.detail.contains("another Kiri"),
            "{other_kiri:?}"
        );
        let desktop = docker_verdict(
            &Reached::Server("Docker Desktop 4.40.0 (187762)".into()),
            "",
            Some("desktop-linux"),
            None,
            None,
            None,
            "docker context use kiri",
        );
        assert_eq!(
            desktop.detail,
            "`docker` reaches Docker Desktop 4.40.0 (187762), not Kiri (context `desktop-linux`): docker context use kiri"
        );
        assert!(
            docker_verdict(
                &Reached::Server(String::new()),
                "",
                Some("default"),
                None,
                None,
                None,
                "x"
            )
            .detail
            .contains("isn't Kiri")
        );
        // On Kiri's context and nothing answers: the engine is the trouble, not the context.
        let down = docker_verdict(
            &Reached::Failed,
            "Cannot connect",
            Some(ctx),
            None,
            None,
            None,
            "docker context use kiri",
        );
        assert_eq!(
            down.detail,
            format!(
                "`docker` is set to Kiri (context `{ctx}`) but gets no answer: see the engine line"
            )
        );
        let pinned = docker_verdict(
            &Reached::Failed,
            "Cannot connect to the Docker daemon at tcp://10.0.0.9:2375.",
            Some("default"),
            None,
            Some("DOCKER_HOST"),
            None,
            "unset DOCKER_HOST, or point it at Kiri",
        );
        assert_eq!(
            pinned.detail,
            "`docker` reaches no engine (DOCKER_HOST is set): Cannot connect to the Docker daemon at tcp://10.0.0.9:2375.; unset DOCKER_HOST, or point it at Kiri"
        );
        assert!(
            docker_verdict(
                &Reached::TimedOut,
                "",
                Some("remote"),
                None,
                None,
                None,
                "f"
            )
            .detail
            .starts_with("`docker` got no answer in 10 s")
        );
    }

    #[test]
    fn a_tools_message_is_one_line() {
        let shim = "\nThe command 'docker' could not be found in this WSL 2 distro.\nWe recommend to activate the WSL integration in Docker Desktop settings.\n";
        assert_eq!(
            first_line(shim),
            "The command 'docker' could not be found in this WSL 2 distro."
        );
        assert_eq!(first_line(&"x".repeat(500)).len(), 200);
        assert_eq!(first_line("é".repeat(300).as_str()).chars().count(), 200);
    }

    /// A tool that floods its pipes, or hangs leaving a child behind, is
    /// read or stopped within the time it was given.
    #[cfg(unix)]
    #[test]
    fn a_tool_is_read_as_it_writes_and_stopped_with_its_children() {
        let big = run_for(
            Command::new("sh").args(["-c", "head -c 300000 /dev/zero | tr '\\0' x >&2; echo Kiri"]),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap()
        .unwrap();
        assert!(big.ok && big.err.len() == 300_000 && text(&big.out).trim() == "Kiri");
        let marker = format!("kiri-doctor-hang-{}", std::process::id());
        let t = Instant::now();
        let hung = run_for(
            Command::new("sh").args(["-c", &format!("sh -c 'exec sleep 30 {marker}' & sleep 30")]),
            Instant::now() + Duration::from_millis(300),
        )
        .unwrap();
        assert!(
            hung.is_none() && t.elapsed() < Duration::from_secs(3),
            "{:?}",
            t.elapsed()
        );
        let left = Command::new("pgrep")
            .args(["-f", &marker])
            .output()
            .unwrap();
        assert!(
            left.stdout.is_empty(),
            "left running: {}",
            text(&left.stdout)
        );
        assert_eq!(
            run_for(
                &mut Command::new("kiri-doctor-no-such-tool"),
                Instant::now() + Duration::from_secs(1)
            )
            .err()
            .map(|e| e.kind()),
            Some(io::ErrorKind::NotFound)
        );
    }

    #[test]
    fn windows_reads_the_wsl_sides_answer() {
        let out = r#"{"checks":[{"detail":"Kiri 0.2.3","name":"engine","status":"ok"},{"detail":"read-only","name":"storage","status":"fail"}],"ok":false}"#;
        assert_eq!(
            from_forwarded(out).unwrap(),
            vec![
                check("engine", Status::Ok, "Kiri 0.2.3"),
                check("storage", Status::Fail, "read-only")
            ]
        );
        for bad in [
            "",
            "kiri: usage: kiri COMMAND",
            r#"{"checks":[{"name":"engine","status":"maybe","detail":""}]}"#,
        ] {
            assert!(from_forwarded(bad).is_none(), "{bad}");
        }
        let utf16: Vec<u8> = "Kiri\r\nUbuntu\r\n"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(running_distros(&utf16), ["Kiri", "Ubuntu"]);
        assert!(!FORWARD_SCRIPT.contains("kiri-start"));
    }

    #[test]
    fn only_a_failure_makes_it_not_ok() {
        let warn_only = [check("http", Status::Warn, "off"), names(false)];
        assert_eq!(to_json(&warn_only)["ok"], true);
        let failed = [
            check("engine", Status::Ok, "Kiri 0.2.3"),
            check("storage", Status::Fail, "the store is read-only"),
        ];
        let j = to_json(&failed);
        assert_eq!(j["ok"], false);
        assert_eq!(
            j["checks"][1],
            json!({"name": "storage", "status": "fail", "detail": "the store is read-only"})
        );
        assert_eq!(
            render(&failed),
            "engine        ok    Kiri 0.2.3\nstorage       fail  the store is read-only\n"
        );
    }

    #[test]
    fn refuses_what_it_does_not_take() {
        for bad in [&["--fix"][..], &["--json", "--json"], &["engine"]] {
            let args: Vec<String> = bad.iter().map(|s| s.to_string()).collect();
            assert_eq!(
                run(&args).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{bad:?}"
            );
        }
        assert!(!crate::docker::handles("doctor"));
    }
}
