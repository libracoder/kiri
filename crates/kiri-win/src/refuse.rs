//! What a docker client is told when the bridge cannot reach the engine in
//! WSL (crates/kiri/src/bridge.rs closes the connection with why), rather
//! than a pipe that simply breaks. Plain functions, tested on any host.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::Duration;

/// How long a client's request may take to come before it is answered anyway.
pub const REQUEST_WAIT: Duration = Duration::from_secs(2);

/// What a docker client is told while Kiri is stopped (explicit Stop in the
/// window or tray): matches `crates/kiri/src/daemon/engine.rs::STOPPED`.
pub const STOPPED: &str = "Kiri is stopped: run `kiri start`, or press Start in the Kiri window, to run containers again";

/// Strips an optional Docker API version prefix (`/v1.47`) from `path`,
/// matching `crates/kiri/src/daemon/http.rs::strip_version`.
fn strip_version(path: &str) -> &str {
    if let Some(rest) = path.strip_prefix("/v")
        && let Some(i) = rest.find('/')
        && !rest[..i].is_empty()
        && rest[..i].bytes().any(|b| b.is_ascii_digit())
        && rest[..i].bytes().all(|b| b.is_ascii_digit() || b == b'.')
    {
        return &rest[i..];
    }
    path
}

fn matches_post_endpoint(request: &[u8], endpoint: &str) -> bool {
    let line_end = request.iter().position(|&b| b == b'\r' || b == b'\n').unwrap_or(request.len().min(1024));
    let Ok(line) = std::str::from_utf8(&request[..line_end]) else {
        return false;
    };
    let mut parts = line.split_whitespace();
    let Some("POST") = parts.next() else {
        return false;
    };
    let Some(target) = parts.next() else {
        return false;
    };
    if let Some(version) = parts.next()
        && (!version.eq_ignore_ascii_case("HTTP/1.1") && !version.eq_ignore_ascii_case("HTTP/1.0") || parts.next().is_some())
    {
        return false;
    }
    let path = target.split('?').next().unwrap_or(target);
    strip_version(path) == endpoint
}

/// Whether the first HTTP request line in `request` is `POST /kiri/wake`
/// (or versioned `POST /v*/kiri/wake`).
pub fn is_wake_request(request: &[u8]) -> bool {
    matches_post_endpoint(request, "/kiri/wake")
}

/// Whether the first HTTP request line in `request` is `POST /kiri/stop`
/// (or versioned `POST /v*/kiri/stop`).
pub fn is_stop_request(request: &[u8]) -> bool {
    matches_post_endpoint(request, "/kiri/stop")
}

/// Returns `Some(d)` only when `distro` is Kiri's dedicated bundled distro
/// (`kiri_distro`, i.e. `"kiri"`). Never returns a shared user distro such as
/// Ubuntu so explicit Stop / Stop-on-quit never kills unrelated WSL shells.
pub fn terminate_target<'a>(distro: Option<&'a str>, kiri_distro: &str) -> Option<&'a str> {
    distro.filter(|&d| d == kiri_distro)
}

/// Action the Windows pipe server should take for an incoming connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDecision {
    /// Engine is not stopped: forward normally.
    Forward,
    /// Engine was stopped and the request is `POST /kiri/wake` (or `/v*/kiri/wake`):
    /// gate and marker are now cleared; forward the already-read request bytes.
    Wake,
    /// Engine is already stopped and the request is `POST /kiri/stop`: reply
    /// HTTP 204 No Content immediately without spawning `wsl.exe`.
    AlreadyStopped,
    /// Engine is stopped and the request is not a wake: reply HTTP 503 with
    /// [`STOPPED`] without spawning `wsl.exe`.
    Refuse,
}

/// Windows-side stopped gate (`AtomicBool`) mirrored on disk at
/// `%LOCALAPPDATA%\Kiri\stopped` so `kiri-win.exe` keeps WSL off after an
/// explicit Stop and across restarts until Start or `kiri start`.
pub struct StoppedGate {
    stopped: AtomicBool,
}

impl StoppedGate {
    pub const fn new() -> Self {
        Self { stopped: AtomicBool::new(false) }
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// Initializes the stopped flag from `marker`'s existence on disk.
    pub fn init_from(&self, marker: Option<&Path>) -> bool {
        let stopped = marker.is_some_and(Path::is_file);
        self.stopped.store(stopped, Ordering::SeqCst);
        stopped
    }

    /// Updates both the in-memory flag and the on-disk `marker` file.
    pub fn set(&self, stopped: bool, marker: Option<&Path>) {
        if stopped {
            self.stopped.store(true, Ordering::SeqCst);
            if let Some(p) = marker {
                if let Some(dir) = p.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                let _ = std::fs::write(p, b"");
            }
        } else {
            if let Some(p) = marker {
                let _ = std::fs::remove_file(p);
            }
            self.stopped.store(false, Ordering::SeqCst);
        }
    }

    /// Decides what to do with `first_request` when the pipe server saw
    /// `is_stopped()`. Clears the gate and marker on `POST /kiri/wake`.
    pub fn inspect_request(&self, first_request: &[u8], marker: Option<&Path>) -> GateDecision {
        if !self.is_stopped() {
            return GateDecision::Forward;
        }
        if is_wake_request(first_request) {
            self.set(false, marker);
            GateDecision::Wake
        } else if is_stop_request(first_request) {
            GateDecision::AlreadyStopped
        } else {
            GateDecision::Refuse
        }
    }
}

/// What a client the engine cannot serve is told: why the bridge could not
/// reach it, and what to do. A CLOSE with no reason says only what
/// happened: this bridge sends one when the daemon itself closed the
/// connection without a word (a request it would not take), and one from
/// before reasons sends it for an engine it could not reach too.
pub fn message(why: Option<&str>) -> String {
    match why {
        Some(why) if why.contains("emergency_ro") || why.contains("mounted read-only") || why.contains("remounted read-only") => {
            format!("Kiri's engine did not start: {why}")
        }
        Some(why) => format!("Kiri's engine did not start: {why}. Run `kiri start`, or open Kiri and press Start"),
        None => "Kiri's engine closed the connection without answering".to_owned(),
    }
}

/// Whether the request that begins `request` is a HEAD (docker's first
/// `HEAD /_ping`): its reply has no body.
pub fn is_head(request: &[u8]) -> bool {
    request.starts_with(b"HEAD ")
}

/// The 503 a client the engine cannot serve gets: docker prints "Error
/// response from daemon: <message>". A reply to HEAD has the headers only.
pub fn refusal(head: bool, message: &str) -> Vec<u8> {
    let body = serde_json::json!({ "message": message }).to_string();
    let mut reply = format!("HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    if !head {
        reply.extend_from_slice(body.as_bytes());
    }
    reply
}

/// Whether a client's request has come, and is a HEAD: set by the thread
/// reading the client, waited for by the one answering it.
#[derive(Debug, Default)]
pub struct Arrival {
    head: Mutex<Option<bool>>,
    cv: Condvar,
}

impl Arrival {
    /// The request came (`head`: it is a HEAD), or the client went (false).
    /// Only the first call counts.
    pub fn set(&self, head: bool) {
        let mut h = self.head.lock().unwrap_or_else(PoisonError::into_inner);
        if h.is_none() {
            *h = Some(head);
            self.cv.notify_all();
        }
    }

    /// Whether the request is a HEAD, once it has come or `wait` has passed.
    pub fn head(&self, wait: Duration) -> bool {
        let h = self.head.lock().unwrap_or_else(PoisonError::into_inner);
        let (h, _) = self.cv.wait_timeout_while(h, wait, |h| h.is_none()).unwrap_or_else(PoisonError::into_inner);
        h.unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Instant;

    fn split(reply: &[u8]) -> (String, String) {
        let text = String::from_utf8(reply.to_vec()).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        (head.to_owned(), body.to_owned())
    }

    /// What docker prints: the reason, and what to do about it.
    #[test]
    fn a_refusal_says_why_and_what_to_do() {
        let m = message(Some("kiri daemon exited as it started; see /var/log/kiri.log"));
        assert_eq!(m, "Kiri's engine did not start: kiri daemon exited as it started; see /var/log/kiri.log. Run `kiri start`, or open Kiri and press Start");
        let (head, body) = split(&refusal(false, &m));
        assert!(head.starts_with("HTTP/1.1 503 Service Unavailable\r\n"), "{head}");
        assert!(head.contains("Content-Type: application/json") && head.contains("Connection: close"), "{head}");
        let len: usize = head.lines().find_map(|l| l.strip_prefix("Content-Length: ")).unwrap().parse().unwrap();
        assert_eq!(len, body.len());
        assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["message"], m);
    }

    /// A reason with quotes and newlines from the bridge stays one JSON string.
    #[test]
    fn a_reason_is_escaped() {
        let (_, body) = split(&refusal(false, &message(Some("said \"no\"\n\\ then"))));
        assert!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["message"].as_str().unwrap().contains("said \"no\"\n\\ then"));
    }

    /// HEAD /_ping: the same headers, Content-Length included, no body.
    #[test]
    fn a_refusal_to_head_has_no_body() {
        assert!(is_head(b"HEAD /_ping HTTP/1.1\r\nHost: api.moby.localhost\r\n\r\n"));
        assert!(!is_head(b"GET /_ping HTTP/1.1\r\n\r\n"));
        assert!(!is_head(b""));
        let m = message(None);
        let (head, body) = split(&refusal(true, &m));
        assert!(body.is_empty());
        assert_eq!(head, split(&refusal(false, &m)).0);
    }

    /// A CLOSE with no reason (the daemon closed a request it would not
    /// take, or a bridge from before reasons): what happened, true either
    /// way, and no "press Start" for an engine that may well be running.
    #[test]
    fn a_close_with_no_reason_says_only_what_happened() {
        assert_eq!(message(None), "Kiri's engine closed the connection without answering");
        let ro = "Kiri's WSL2 disk (ext4.vhdx) was remounted read-only by Linux (emergency_ro) after an unclean shutdown or filesystem error.";
        let got = message(Some(ro));
        assert_eq!(got, format!("Kiri's engine did not start: {ro}"));
        assert!(!got.contains("press Start"), "{got}");
    }

    /// The refusal waits for the request, and no longer than it is given.
    #[test]
    fn the_answer_waits_for_the_request() {
        let a = Arc::new(Arrival::default());
        let b = a.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            b.set(true);
            b.set(false); // only the first counts
        });
        let began = Instant::now();
        assert!(a.head(REQUEST_WAIT));
        assert!(began.elapsed() >= Duration::from_millis(100) && began.elapsed() < REQUEST_WAIT);
        t.join().unwrap();
        let none = Arrival::default();
        let began = Instant::now();
        assert!(!none.head(Duration::from_millis(100)));
        assert!(began.elapsed() >= Duration::from_millis(100));
    }

    #[test]
    fn stopped_gate_persists_and_initializes_from_marker() {
        let dir = std::env::temp_dir().join(format!("kiri-win-stopped-gate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let marker = dir.join("Kiri").join("stopped");

        let gate = StoppedGate::new();
        assert!(!gate.init_from(Some(&marker)));
        assert!(!gate.is_stopped());

        gate.set(true, Some(&marker));
        assert!(gate.is_stopped());
        assert!(marker.is_file());

        // A fresh process sees the marker at startup without touching WSL.
        let restarted = StoppedGate::new();
        assert!(restarted.init_from(Some(&marker)));
        assert!(restarted.is_stopped());

        restarted.set(false, Some(&marker));
        assert!(!restarted.is_stopped());
        assert!(!marker.exists());

        let after_start = StoppedGate::new();
        assert!(!after_start.init_from(Some(&marker)));

        // POST /kiri/stop while already stopped returns AlreadyStopped and keeps the marker.
        gate.set(true, Some(&marker));
        assert_eq!(gate.inspect_request(b"POST /kiri/stop HTTP/1.1\r\nHost: kiri\r\n\r\n", Some(&marker)), GateDecision::AlreadyStopped);
        assert!(gate.is_stopped());
        assert!(marker.is_file());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stopped_gate_allows_wake_and_refuses_other_requests_with_503() {
        let dir = std::env::temp_dir().join(format!("kiri-win-wake-gate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let marker = dir.join("Kiri").join("stopped");

        // Request matcher coverage.
        assert!(is_wake_request(b"POST /kiri/wake HTTP/1.1\r\nHost: kiri\r\n\r\n"));
        assert!(is_wake_request(b"POST /kiri/wake HTTP/1.0\r\n\r\n"));
        assert!(is_wake_request(b"POST /kiri/wake?from=cli HTTP/1.1\r\n\r\n"));
        assert!(is_wake_request(b"POST /v1.47/kiri/wake HTTP/1.1\r\nHost: kiri\r\n\r\n"));
        assert!(is_wake_request(b"POST /v1.24/kiri/wake?x=1 HTTP/1.1\r\n\r\n"));
        assert!(!is_wake_request(b"GET /kiri/wake HTTP/1.1\r\n\r\n"));
        assert!(!is_wake_request(b"HEAD /_ping HTTP/1.1\r\n\r\n"));
        assert!(!is_wake_request(b"GET /_ping HTTP/1.1\r\n\r\n"));
        assert!(!is_wake_request(b"GET /v1.47/containers/json HTTP/1.1\r\n\r\n"));
        assert!(!is_wake_request(b"POST /containers/create HTTP/1.1\r\n\r\n"));
        assert!(!is_wake_request(b"POST /kiri/stop HTTP/1.1\r\n\r\n"));
        assert!(is_stop_request(b"POST /kiri/stop HTTP/1.1\r\nHost: kiri\r\n\r\n"));
        assert!(is_stop_request(b"POST /v1.47/kiri/stop HTTP/1.1\r\nHost: kiri\r\n\r\n"));
        assert!(!is_stop_request(b"GET /kiri/stop HTTP/1.1\r\n\r\n"));
        assert!(!is_stop_request(b"POST /kiri/wake HTTP/1.1\r\n\r\n"));
        assert!(!is_wake_request(b"POST /kiri/wake/extra HTTP/1.1\r\n\r\n"));
        assert!(!is_wake_request(b"POST /v/kiri/wake HTTP/1.1\r\n\r\n"));
        assert!(!is_wake_request(b"POST /v./kiri/wake HTTP/1.1\r\n\r\n"));
        assert!(!is_wake_request(b""));

        let gate = StoppedGate::new();
        // When running, everything forwards without refusal.
        assert_eq!(gate.inspect_request(b"GET /_ping HTTP/1.1\r\n\r\n", Some(&marker)), GateDecision::Forward);

        // Once stopped, ordinary Docker requests are refused with 503 STOPPED
        // and leave the gate + marker intact.
        gate.set(true, Some(&marker));
        for req in [
            b"GET /_ping HTTP/1.1\r\nHost: kiri\r\n\r\n".as_slice(),
            b"HEAD /_ping HTTP/1.1\r\nHost: kiri\r\n\r\n".as_slice(),
            b"GET /v1.47/containers/json HTTP/1.1\r\n\r\n".as_slice(),
            b"POST /containers/create HTTP/1.1\r\n\r\n".as_slice(),
            b"GET /kiri/wake HTTP/1.1\r\n\r\n".as_slice(),
            b"".as_slice(),
        ] {
            assert_eq!(gate.inspect_request(req, Some(&marker)), GateDecision::Refuse);
            assert!(gate.is_stopped());
            assert!(marker.is_file());
            let (head, body) = split(&refusal(is_head(req), STOPPED));
            assert!(head.starts_with("HTTP/1.1 503 Service Unavailable\r\n"), "{head}");
            if is_head(req) {
                assert!(body.is_empty());
            } else {
                assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["message"], STOPPED);
            }
        }

        // POST /kiri/wake clears the gate and removes the marker.
        assert_eq!(gate.inspect_request(b"POST /kiri/wake HTTP/1.1\r\nHost: kiri\r\n\r\n", Some(&marker)), GateDecision::Wake);
        assert!(!gate.is_stopped());
        assert!(!marker.exists());

        // Versioned POST /v1.47/kiri/wake also wakes and clears the marker.
        gate.set(true, Some(&marker));
        assert_eq!(gate.inspect_request(b"POST /v1.47/kiri/wake HTTP/1.1\r\nHost: kiri\r\n\r\n", Some(&marker)), GateDecision::Wake);
        assert!(!gate.is_stopped());
        assert!(!marker.exists());

        // POST /kiri/stop while already stopped returns AlreadyStopped and keeps the marker.
        gate.set(true, Some(&marker));
        assert_eq!(gate.inspect_request(b"POST /kiri/stop HTTP/1.1\r\nHost: kiri\r\n\r\n", Some(&marker)), GateDecision::AlreadyStopped);
        assert!(gate.is_stopped());
        assert!(marker.is_file());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn terminate_target_only_allows_kiri_distro() {
        assert_eq!(terminate_target(Some("kiri"), "kiri"), Some("kiri"));
        assert_eq!(terminate_target(Some("Ubuntu"), "kiri"), None);
        assert_eq!(terminate_target(Some("Ubuntu-26.04"), "kiri"), None);
        assert_eq!(terminate_target(Some("Debian"), "kiri"), None);
        assert_eq!(terminate_target(Some("kiri-linux"), "kiri"), None);
        assert_eq!(terminate_target(Some("Kiri"), "kiri"), None);
        assert_eq!(terminate_target(Some(""), "kiri"), None);
        assert_eq!(terminate_target(None, "kiri"), None);
    }
}
