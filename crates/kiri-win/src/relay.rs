//! Windows' end of the host and proxy relay (crates/kiri/src/hostrelay.rs):
//! services and proxies on Windows' own loopback (`127.0.0.1` / `[::1]`)
//! can't be reached directly from WSL 2, so `kiri hostrelay` in the distro
//! listens for static proxy ports on `127.0.0.1` and for `host.docker.internal`
//! / `host.kiri.internal` on `192.168.65.254` (via nftables DNAT +
//! `SO_ORIGINAL_DST`), sends each connection here over wsl.exe's stdio, and
//! this dials Windows' loopback (`127.0.0.1`, then `[::1]` on refusal).

use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::os::windows::process::CommandExt;
use std::process::{ChildStdin, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::hostrelay::{self, Out};

/// Minimum interval between automatic background restart attempts after the
/// relay exits or fails to start.
const RETRY_WAIT: Duration = Duration::from_secs(2);

/// Stdin handle to `wsl.exe` that can be closed on demand (`renew`) so the
/// WSL-side `kiri hostrelay` sees EOF and tears down cleanly.
struct CloseableStdin(Option<ChildStdin>);

impl Write for CloseableStdin {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.0.as_mut() {
            Some(w) => w.write(buf),
            None => Err(io::Error::new(io::ErrorKind::BrokenPipe, "relay closed")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.0.as_mut() {
            Some(w) => w.flush(),
            None => Ok(()),
        }
    }
}

struct Relay {
    out: Out,
    stdin: Arc<Mutex<CloseableStdin>>,
    distro: Option<String>,
    kiri: String,
    /// Dynamic host-gateway forwarding (`host.docker.internal` -> any non-zero
    /// Windows loopback port).
    host_enabled: AtomicBool,
    /// Catch-all relay port reported by WSL (`LISTENING_HOST`), or 0.
    host_port: AtomicU16,
    /// Static proxy ports requested via `LISTEN`.
    allowed: Mutex<HashSet<u16>>,
    /// Windows port → the distro's port; 0 when it couldn't listen.
    ports: Mutex<HashMap<u16, u16>>,
    changed: Condvar,
    dead: AtomicBool,
}

impl Relay {
    fn close(&self) {
        self.dead.store(true, Ordering::SeqCst);
        let _ = lock(&self.stdin).0.take();
        self.changed.notify_all();
    }
}

static RELAY: Mutex<Option<Arc<Relay>>> = Mutex::new(None);
/// Last automatic start attempt, to throttle retries if WSL is unavailable.
static LAST_START: Mutex<Option<Instant>> = Mutex::new(None);
/// The last failure logged, so a minute's retry doesn't repeat it.
static LAST_ERROR: Mutex<String> = Mutex::new(String::new());

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn log_once(msg: String) {
    let mut last = lock(&LAST_ERROR);
    if *last != msg {
        crate::serve::log(&msg);
        *last = msg;
    }
}

fn current_distro_and_kiri() -> Option<(String, String)> {
    if crate::serve::is_stopped() || crate::storage::moving() || crate::storage::unavailable().is_some() {
        return None;
    }
    // The bridge's distro, the engine's, or during setup the one setup just made.
    // None before setup has made one: WSL's default distro may be anything.
    let distro = crate::serve::distro().or_else(crate::engine::distro).or_else(crate::setup::distro)?;
    Some((distro, crate::serve::kiri()))
}

fn start(distro: Option<String>, kiri: String) -> io::Result<Arc<Relay>> {
    let mut cmd = crate::win::tool("wsl.exe");
    if let Some(d) = &distro {
        cmd.args(["-d", d]);
    }
    let mut child = cmd
        .args(["-u", "root", "--", &kiri, "hostrelay"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(0x0800_0000)
        .spawn()?;
    let (Some(input), Some(output)) = (child.stdin.take(), child.stdout.take()) else {
        return Err(io::Error::other("wsl.exe has no stdio"));
    };
    let stdin = Arc::new(Mutex::new(CloseableStdin(Some(input))));
    let out: Out = stdin.clone();
    let relay = Arc::new(Relay {
        out,
        stdin,
        distro,
        kiri,
        host_enabled: AtomicBool::new(true),
        host_port: AtomicU16::new(0),
        allowed: Mutex::new(HashSet::new()),
        ports: Mutex::new(HashMap::new()),
        changed: Condvar::new(),
        dead: AtomicBool::new(false),
    });
    // Ask WSL immediately to bind 192.168.65.254 and install its nftables DNAT.
    // An older `kiri hostrelay` ignores unknown frame kinds cleanly.
    let _ = hostrelay::send(&relay.out, hostrelay::LISTEN_HOST, 0, &[]);
    let r = relay.clone();
    std::thread::spawn(move || {
        let (a, p, h) = (r.clone(), r.clone(), r.clone());
        let end = hostrelay::dial_side_with_host(
            output,
            &r.out,
            move |port| port != 0 && (a.host_enabled.load(Ordering::SeqCst) || lock(&a.allowed).contains(&port)),
            move |target, local| {
                lock(&p.ports).insert(target, local);
                p.changed.notify_all();
            },
            move |local| {
                h.host_port.store(local, Ordering::SeqCst);
                h.changed.notify_all();
                if local != 0 {
                    log_once(format!(
                        "host relay: {} -> Windows loopback (WSL port {local})",
                        hostrelay::WSL_HOST_ADDR_STR
                    ));
                } else {
                    log_once(format!(
                        "host relay: WSL could not bind {}",
                        hostrelay::WSL_HOST_ADDR_STR
                    ));
                }
            },
        );
        r.dead.store(true, Ordering::SeqCst);
        r.changed.notify_all();
        let end = match end {
            Ok(()) => "closed".to_owned(),
            Err(e) => format!("{e}"),
        };
        let status = crate::format_wait_status(child.wait());
        log_once(format!("host relay ended: {end}, {status}"));
    });
    Ok(relay)
}

fn ensure_relay(distro: String, kiri: String) -> Option<Arc<Relay>> {
    let distro = Some(distro);
    let mut slot = lock(&RELAY);
    if crate::serve::is_stopped() {
        return None;
    }
    match slot.as_ref() {
        Some(r) if !r.dead.load(Ordering::SeqCst) && r.distro == distro && r.kiri == kiri => Some(r.clone()),
        old => {
            if let Some(old) = old {
                old.close();
            }
            match start(distro, kiri) {
                Ok(r) => {
                    *slot = Some(r.clone());
                    Some(r)
                }
                Err(e) => {
                    log_once(format!("host relay: {e}"));
                    None
                }
            }
        }
    }
}

/// Ensures the WSL host relay is running in the background so CLI-only users
/// (serving `\\.\pipe\kiri` or `\\.\pipe\docker_engine` without opening the
/// window) get `host.docker.internal` automatically. Non-blocking and throttled
/// when a recent attempt just failed.
pub fn ensure_started() {
    if crate::serve::is_stopped() {
        return;
    }
    let Some((distro, kiri)) = current_distro_and_kiri() else {
        return;
    };
    {
        let slot = lock(&RELAY);
        if slot.as_ref().is_some_and(|r| !r.dead.load(Ordering::SeqCst) && r.distro.as_deref() == Some(distro.as_str()) && r.kiri == kiri) {
            return;
        }
    }
    {
        let mut last = lock(&LAST_START);
        if last.is_some_and(|t| t.elapsed() < RETRY_WAIT) {
            return;
        }
        *last = Some(Instant::now());
    }
    let _ = std::thread::Builder::new().name("kiri-hostrelay-start".into()).spawn(move || {
        let _ = ensure_relay(distro, kiri);
    });
}

/// Tears down the running host relay (`kiri hostrelay` in WSL) so no open
/// `wsl.exe` keeps `vmmemWSL` alive after an explicit Stop.
pub fn stop() {
    let old = lock(&RELAY).take();
    *lock(&LAST_START) = None;
    if let Some(old) = old {
        old.close();
    }
}

/// Replaces the running host relay (e.g. after setup picks a distro or an
/// engine update replaces `/usr/local/bin/kiri` in WSL).
pub fn renew() {
    let old = lock(&RELAY).take();
    *lock(&LAST_START) = None;
    let _ = std::thread::Builder::new().name("kiri-hostrelay-renew".into()).spawn(move || {
        if let Some(old) = old {
            old.close();
        }
        if let Some((distro, kiri)) = current_distro_and_kiri() {
            let _ = ensure_relay(distro, kiri);
        }
    });
}

/// For each Windows loopback proxy port, the distro's port that leads to it,
/// starting the relay when it isn't running. Also ensures the `host.docker.internal`
/// catch-all relay is active even when no proxy ports are configured.
pub fn ports(targets: &[u16]) -> HashMap<u16, u16> {
    if crate::serve::is_stopped() {
        return HashMap::new();
    }
    if targets.is_empty() {
        ensure_started();
        return HashMap::new();
    }
    let Some((distro, kiri)) = current_distro_and_kiri() else {
        return HashMap::new();
    };
    let Some(relay) = ensure_relay(distro, kiri) else {
        return HashMap::new();
    };
    for &t in targets {
        if lock(&relay.allowed).insert(t) {
            let _ = hostrelay::send(&relay.out, hostrelay::LISTEN, 0, &t.to_be_bytes());
        }
    }
    // A relay just started answers once WSL has run it: well within this.
    let until = Instant::now() + Duration::from_secs(10);
    let mut ports = lock(&relay.ports);
    while !targets.iter().all(|t| ports.contains_key(t)) && !relay.dead.load(Ordering::SeqCst) {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        ports = relay.changed.wait_timeout(ports, left.min(Duration::from_millis(200))).unwrap_or_else(PoisonError::into_inner).0;
    }
    let map: HashMap<u16, u16> = targets.iter().filter_map(|t| ports.get(t).filter(|&&l| l != 0).map(|&l| (*t, l))).collect();
    drop(ports);
    if map.len() == targets.len() {
        log_once(format!("proxy relay: {}", map.iter().map(|(t, l)| format!("Windows 127.0.0.1:{t} is 127.0.0.1:{l} in WSL")).collect::<Vec<_>>().join(", ")));
    } else {
        log_once(format!("proxy relay: no answer for {targets:?}"));
    }
    map
}
