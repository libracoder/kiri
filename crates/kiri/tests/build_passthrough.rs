//! `kiri build` with BuildKit as the builder is `docker build` exactly: the
//! arguments as typed (less Kiri's own `--builder`/`--no-native`) and stdin
//! untouched, with nothing of the build read or sent to the engine first,
//! whichever way BuildKit was chosen (the flag, `KIRI_NATIVE_BUILD`, or the
//! engine's setting). And when Kiri's own builder was chosen but the build
//! goes to BuildKit after all, whatever was read from stdin reaches docker.
//!
//! The engine is a stand-in on a unix socket (`KIRI_SOCKET`) that records
//! every request; docker is a script first on PATH that records its
//! arguments and the bytes on its stdin.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const FAKE_DOCKER: &str = r#"#!/bin/sh
if [ "$1" = build ]; then
  for a in "$@"; do printf '%s\0' "$a"; done > "$KB_OUT/argv"
  for a in "$@"; do
    case "$a" in
      --iidfile=*)
        f="${a#--iidfile=}"
        printf '%s\n' "$f" > "$KB_OUT/iidpath"
        ls -ld "$(dirname "$f")" > "$KB_OUT/iiddir"
        printf 'sha256:0123' > "$f" ;;
    esac
  done
  cat > "$KB_OUT/stdin"
fi
exit 0
"#;

/// What the stand-in engine says.
#[derive(Clone, Copy)]
struct Engine {
    /// The setting (`GET /kiri/builder` `native`).
    native: bool,
    /// Its answer to `POST /kiri/build`.
    build_answer: &'static str,
}

struct Env {
    dir: PathBuf,
    out: PathBuf,
    ctx: PathBuf,
    socket: PathBuf,
    requests: Arc<Mutex<Vec<String>>>,
}

static N: AtomicUsize = AtomicUsize::new(0);

fn setup(engine: Engine) -> Env {
    let dir = std::env::temp_dir().join(format!("kbpt-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let _ = std::fs::remove_dir_all(&dir);
    let (bin, out, ctx, home) = (dir.join("bin"), dir.join("out"), dir.join("ctx"), dir.join("home"));
    for d in [&bin, &out, &ctx, &home] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(ctx.join("Dockerfile"), "FROM scratch\n").unwrap();
    let docker = bin.join("docker");
    std::fs::write(&docker, FAKE_DOCKER).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755)).unwrap();
    let socket = dir.join("s");
    let listener = UnixListener::bind(&socket).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let rec = requests.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(conn) = conn else { return };
            let rec = rec.clone();
            std::thread::spawn(move || serve(conn, engine, &rec));
        }
    });
    Env { dir, out, ctx, socket, requests }
}

fn serve(conn: std::os::unix::net::UnixStream, engine: Engine, rec: &Mutex<Vec<String>>) {
    let mut w = conn.try_clone().unwrap();
    let mut r = BufReader::new(conn);
    let mut first = String::new();
    if r.read_line(&mut first).unwrap_or(0) == 0 {
        return;
    }
    let mut len = 0;
    loop {
        let mut l = String::new();
        if r.read_line(&mut l).unwrap_or(0) == 0 || l.trim_end().is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':')
            && k.eq_ignore_ascii_case("content-length")
        {
            len = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0; len];
    let _ = r.read_exact(&mut body);
    let mut parts = first.split_whitespace();
    let (method, path) = (parts.next().unwrap_or("").to_owned(), parts.next().unwrap_or("").to_owned());
    rec.lock().unwrap().push(format!("{method} {path} {}", String::from_utf8_lossy(&body)));
    let (status, answer) = match (method.as_str(), path.as_str()) {
        ("GET", "/_ping") => (200, "OK".to_owned()),
        ("GET", "/kiri/builder") => (200, format!(r#"{{"native":{},"native_env":null}}"#, engine.native)),
        ("POST", "/kiri/build") => (200, format!("{}\n", engine.build_answer)),
        ("POST", "/kiri/build-path") => (200, "{}".to_owned()),
        _ => (404, r#"{"message":"not here"}"#.to_owned()),
    };
    let _ = write!(w, "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}", answer.len());
}

struct Ran {
    argv: Vec<String>,
    stdin: Vec<u8>,
    requests: Vec<String>,
    stderr: String,
    pid: u32,
}

/// `kiri build ARGS` with these bytes on its stdin and `KIRI_NATIVE_BUILD`
/// as given; fails the test if it does not end within 20 s.
fn kiri_forge(env: &Env, args: &[&str], native_env: Option<&str>, stdin: &[u8]) -> Ran {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kiri"));
    cmd.arg("build").args(args).env_clear();
    cmd.env("PATH", format!("{}:/usr/bin:/bin", env.dir.join("bin").display()))
        .env("HOME", env.dir.join("home"))
        .env("KIRI_SOCKET", &env.socket)
        .env("KB_OUT", &env.out)
        .env("BUILDX_BUILDER", "kb-test");
    if let Some(v) = native_env {
        cmd.env("KIRI_NATIVE_BUILD", v);
    }
    let mut child = cmd.current_dir(&env.dir).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let pid = child.id();
    let mut input = child.stdin.take().unwrap();
    let bytes = stdin.to_vec();
    std::thread::spawn(move || {
        let _ = input.write_all(&bytes);
    });
    let mut err = child.stderr.take().unwrap();
    let errs = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = err.read_to_string(&mut s);
        s
    });
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("kiri build {args:?} did not end (it read something it should have left alone)");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let stderr = errs.join().unwrap();
    let argv = std::fs::read(env.out.join("argv"))
        .map(|b| b.split(|&c| c == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect())
        .unwrap_or_default();
    let stdin = std::fs::read(env.out.join("stdin")).unwrap_or_default();
    let requests = env.requests.lock().unwrap().clone();
    Ran { argv, stdin, requests, stderr, pid }
}

fn build_argv(args: &[&str]) -> Vec<String> {
    std::iter::once("build").chain(args.iter().copied()).map(str::to_owned).collect()
}

/// Every way of choosing BuildKit: kiri's extra arguments, its
/// `KIRI_NATIVE_BUILD`, and the engine's setting.
fn buildkit_ways() -> Vec<(&'static str, Vec<&'static str>, Option<&'static str>, Engine)> {
    let off = Engine { native: false, build_answer: r#"{"native":"off"}"# };
    // An engine set to Kiri's own builder: the flag and environment win over it.
    let on = Engine { native: true, build_answer: r#"{"aux":{"ID":"sha256:native"}}"# };
    vec![
        ("--builder buildkit", vec!["--builder", "buildkit"], None, on),
        ("--no-native", vec!["--no-native"], None, on),
        ("KIRI_NATIVE_BUILD=0", vec![], Some("0"), on),
        ("the engine's setting", vec![], None, off),
    ]
}

/// Builds that must reach docker exactly as typed when BuildKit builds.
fn cases(ctx: &str, df: &str, secret: &str) -> Vec<(Vec<String>, Vec<u8>)> {
    let tar: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let text = b"FROM scratch\nLABEL from=stdin\n".to_vec();
    let s = |a: &[&str]| a.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    vec![
        (s(&["-f", "-", "-t", "app", ctx]), text.clone()),
        (s(&["--file=-", ctx]), text.clone()),
        (s(&["-"]), tar.clone()),
        (s(&["-t", "app", "-"]), text.clone()),
        (s(&["-f", df, "-"]), tar.clone()),
        (s(&["-f", "-", "-"]), text.clone()),
        (s(&["--secret", &format!("id=x,src={secret}"), ctx]), text.clone()),
        (s(&["--ssh", "default", ctx]), text.clone()),
        (s(&["-t", "Bad:Tag", ctx]), text.clone()),
        (s(&["-t", "x:Bad Tag", "-f", "-", ctx]), text.clone()),
        (s(&["/no/such/kiri-context"]), text.clone()),
    ]
}

#[test]
fn with_buildkit_chosen_docker_gets_the_build_exactly_as_typed() {
    let mut failed = Vec::new();
    for (way, extra, native_env, engine) in buildkit_ways() {
        let env = setup(engine);
        // A secret that is a fifo with no writer: opening it blocks, so a
        // build that reads it never ends.
        let secret = env.dir.join("secret.fifo");
        assert!(Command::new("mkfifo").arg(&secret).status().unwrap().success());
        let (ctx, df) = (env.ctx.display().to_string(), env.ctx.join("Dockerfile").display().to_string());
        for (args, stdin) in cases(&ctx, &df, &secret.display().to_string()) {
            env.requests.lock().unwrap().clear();
            let _ = std::fs::remove_file(env.out.join("argv"));
            let _ = std::fs::remove_file(env.out.join("stdin"));
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            let typed: Vec<&str> = extra.iter().copied().chain(a.iter().copied()).collect();
            let ran = match std::panic::catch_unwind(|| kiri_forge(&env, &typed, native_env, &stdin)) {
                Ok(r) => r,
                Err(_) => {
                    failed.push(format!("[{way}] {a:?}: did not end"));
                    continue;
                }
            };
            if ran.argv != build_argv(&a) {
                failed.push(format!("[{way}] {a:?}: docker's arguments were {:?}; stderr: {}", ran.argv, ran.stderr.trim()));
            }
            if ran.stdin != stdin {
                failed.push(format!("[{way}] {a:?}: docker's stdin was {} bytes, not the {} given", ran.stdin.len(), stdin.len()));
            }
            let native: Vec<&String> = ran.requests.iter().filter(|r| !(r.starts_with("GET /_ping ") || r.starts_with("GET /version ") || r.starts_with("GET /kiri/builder "))).collect();
            if !native.is_empty() {
                failed.push(format!("[{way}] {a:?}: the engine was sent {native:?}"));
            }
        }
        let _ = std::fs::remove_dir_all(&env.dir);
    }
    assert!(failed.is_empty(), "{} failures:\n{}", failed.len(), failed.join("\n"));
}

/// The engine was set to Kiri's own builder when asked, but answers that it
/// is off (an older engine, or the setting changed): the Dockerfile read
/// from stdin goes to docker.
#[test]
fn a_native_build_the_engine_turns_away_hands_docker_the_stdin_dockerfile() {
    let env = setup(Engine { native: true, build_answer: r#"{"native":"off"}"# });
    let ctx = env.ctx.display().to_string();
    let text = b"FROM scratch\nLABEL x=\"\xc3\xa9\"\n";
    let ran = kiri_forge(&env, &["-f", "-", &ctx], None, text);
    assert!(ran.requests.iter().any(|r| r.starts_with("POST /kiri/build ")), "{:?}", ran.requests);
    assert_eq!(ran.argv, build_argv(&["-f", "-", &ctx]), "stderr: {}", ran.stderr);
    assert_eq!(ran.stdin, text, "docker gets the Dockerfile read from stdin");
    let _ = std::fs::remove_dir_all(&env.dir);
}

/// A native build that falls back: stdin's Dockerfile reaches docker, and
/// the image id file of its own is in a private folder with a name no one
/// can guess, gone afterwards.
#[test]
fn a_fallback_hands_docker_the_stdin_dockerfile_and_keeps_its_id_file_private() {
    let env = setup(Engine { native: true, build_answer: r#"{"fallback":"a test reason"}"# });
    let ctx = env.ctx.display().to_string();
    let text = b"FROM scratch\n";
    let ran = kiri_forge(&env, &["-f", "-", &ctx], None, text);
    assert_eq!(ran.stdin, text, "stderr: {}", ran.stderr);
    assert_eq!(ran.argv.len(), 5, "{:?}", ran.argv);
    assert_eq!(&ran.argv[2..], &["-f", "-", ctx.as_str()]);
    let iid = PathBuf::from(std::fs::read_to_string(env.out.join("iidpath")).unwrap().trim());
    assert_eq!(ran.argv[1], format!("--iidfile={}", iid.display()));
    assert!(!iid.display().to_string().contains(&ran.pid.to_string()), "the name is not the process id: {}", iid.display());
    let dir = iid.parent().unwrap();
    assert_ne!(dir, std::env::temp_dir().as_path(), "a folder of its own, not the shared one");
    assert!(dir.file_name().unwrap().to_str().unwrap().len() >= 32, "a random name: {}", dir.display());
    let listing = std::fs::read_to_string(env.out.join("iiddir")).unwrap();
    assert!(listing.starts_with("drwx------"), "only the user enters it: {listing}");
    assert!(!iid.exists() && !dir.exists(), "removed after the build");
    assert!(ran.requests.iter().any(|r| r.starts_with("POST /kiri/build-path ") && r.contains("sha256:0123") && r.contains("fallback a test reason")), "{:?}", ran.requests);
    let _ = std::fs::remove_dir_all(&env.dir);
}

/// A context from stdin is decided before stdin is read: docker reads it.
#[test]
fn a_native_build_with_a_stdin_context_leaves_stdin_to_docker() {
    let env = setup(Engine { native: true, build_answer: r#"{"aux":{"ID":"sha256:native"}}"# });
    let tar: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
    let ran = kiri_forge(&env, &["-t", "app", "-"], None, &tar);
    assert_eq!(ran.stdin, tar, "stderr: {}", ran.stderr);
    assert_eq!(&ran.argv[2..], &["-t", "app", "-"]);
    assert!(!ran.requests.iter().any(|r| r.starts_with("POST /kiri/build ")), "{:?}", ran.requests);
    let _ = std::fs::remove_dir_all(&env.dir);
}
