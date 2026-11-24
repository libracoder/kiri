//! Kiri's images as a registry, for its BuildKit: `FROM myapp:dev` (an
//! image built or loaded here, never pushed) works as it does with Docker.
//!
//! A read-only registry API on 127.0.0.1, which containers reach at
//! host.docker.internal. buildkitd.toml names it as a mirror of every
//! registry Kiri has images from; a mirror that answers 404 is skipped, so
//! anything not here comes from the registry itself. A tag a registry
//! published is not answered here even when Kiri holds it: the registry,
//! not this machine, knows which platforms it has (see `lookup`).
//! Paths carry a secret
//! (`/v2/<token>/<registry>/<repo>/…`), so other local users can't read
//! images through it. Manifests are made from the store's records (layers,
//! config), the same bytes for the same image every time.

use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use serde_json::{Value, json};

use kiri_image::{Image, Layer, Platform, Reference};

use super::engine::Engine;

/// Tried first, so a builder started by buildx after a daemon restart still
/// finds the mirror its config names.
const PORT: u16 = 47_391;
const DEV_PORT: u16 = 47_392;
const MAX_MIRROR_WORKERS: usize = 128;

#[derive(Clone, Copy)]
struct MirrorListen {
    port: u16,
    has_bridge: bool,
}

static LISTENING: OnceLock<Option<MirrorListen>> = OnceLock::new();
static ACTIVE_WORKERS: AtomicUsize = AtomicUsize::new(0);

struct WorkerGuard;

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        ACTIVE_WORKERS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The mirror's secret path segment, kept in the state directory so it
/// survives restarts (the builder's config keeps naming it).
fn token() -> String {
    static TOKEN: OnceLock<String> = OnceLock::new();
    TOKEN
        .get_or_init(|| {
            let path = super::state_dir().ok().map(|d| d.join("build-mirror-token"));
            if let Some(t) = path.as_ref().and_then(|p| std::fs::read_to_string(p).ok()).map(|t| t.trim().to_owned()).filter(|t| t.len() == 32) {
                return t;
            }
            let t = super::engine::random_hex(16);
            if let Some(p) = path {
                let _ = save_token(&p, &t);
            }
            t
        })
        .clone()
}

/// Writes the token readable by its owner only from the moment the file
/// exists: written and then chmod-ed, it was the umask's 0644 in between,
/// and other local users could read it there.
fn save_token(path: &std::path::Path, token: &str) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    // One already there (not a valid token) is replaced, mode and all.
    let _ = std::fs::remove_file(path);
    std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?.write_all(token.as_bytes())
}

/// Starts the server (at the daemon's start: a listening socket costs
/// nothing while no build asks).
pub fn start(engine: &Arc<Engine>) {
    LISTENING.get_or_init(|| {
        let wanted = if crate::flavor::dev() { DEV_PORT } else { PORT };
        let listener = TcpListener::bind(("127.0.0.1", wanted)).or_else(|_| TcpListener::bind(("127.0.0.1", 0))).ok()?;
        let port = listener.local_addr().ok()?.port();
        let me = Arc::downgrade(engine);
        #[cfg(target_os = "linux")]
        let mut has_bridge = false;
        #[cfg(not(target_os = "linux"))]
        let has_bridge = true;
        // On a Linux host the builder reaches the mirror at the default
        // bridge's gateway (mirror_host): containers have no way to the
        // host's loopback there, so it listens on that address too.
        #[cfg(target_os = "linux")]
        if let Some(gateway) = bridge_gateway(&engine.lock_net()) {
            match bind_freely(gateway, port) {
                Ok(l) => {
                    let me = me.clone();
                    if std::thread::Builder::new().name("kiri-build-mirror".into()).spawn(move || serve(l, me)).is_ok() {
                        has_bridge = true;
                    }
                }
                Err(e) => crate::diag::warn!("image mirror not on the bridge; builds pull from registries", error = e),
            }
        }
        std::thread::Builder::new().name("kiri-build-mirror".into()).spawn(move || serve(listener, me)).ok()?;
        crate::diag::info!("image mirror for builds", port = port);
        Some(MirrorListen { port, has_bridge })
    });
}

/// buildkitd.toml lines: this mirror for every registry Kiri has images
/// from (Docker Hub always), over plain HTTP.
#[cfg(target_os = "linux")]
fn mirror_host(networks: &super::network::Networks) -> String {
    bridge_gateway(networks).map_or_else(|| super::ports::HOST_ADDR.into(), super::network::ip_str)
}

/// The default bridge's gateway, which containers reach the host at.
#[cfg(target_os = "linux")]
fn bridge_gateway(networks: &super::network::Networks) -> Option<[u8; 4]> {
    networks.find("bridge").map(|n| n.gateway).filter(|g| *g != [0; 4])
}

/// A listener on `ip:port` before the address exists: the bridge (and
/// its gateway address) is made with the first container (IP_FREEBIND).
#[cfg(target_os = "linux")]
fn bind_freely(ip: [u8; 4], port: u16) -> io::Result<TcpListener> {
    use std::os::fd::{FromRawFd, OwnedFd};
    // SAFETY: plain socket creation; owned at once.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is fresh and ours.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    let one: libc::c_int = 1;
    for opt in [(libc::SOL_SOCKET, libc::SO_REUSEADDR), (libc::IPPROTO_IP, libc::IP_FREEBIND)] {
        // SAFETY: setsockopt with an int of the stated size on a socket we own.
        if unsafe { libc::setsockopt(fd, opt.0, opt.1, (&one as *const libc::c_int).cast(), std::mem::size_of::<libc::c_int>() as libc::socklen_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: sockaddr_in is plain data; all-zero is valid, then filled in.
    let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_port = port.to_be();
    sin.sin_addr.s_addr = u32::from_ne_bytes(ip);
    // SAFETY: bind and listen on our socket with a sockaddr_in of its size.
    unsafe {
        if libc::bind(fd, (&sin as *const libc::sockaddr_in).cast(), std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t) != 0 || libc::listen(fd, 128) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(TcpListener::from(sock))
}

#[cfg(not(target_os = "linux"))]
fn mirror_host(_networks: &super::network::Networks) -> String {
    super::ports::HOST_ADDR.into()
}

/// Where a build reaches this computer: the address `--add-host
/// x:host-gateway` gets, the one the mirror is reached at. On a Linux host
/// (and Windows' engine in WSL2) that's the default bridge's gateway, as
/// for `docker run`; 198.19.248.254 only leads anywhere in the Mac's VM.
pub fn host_addr(engine: &Engine) -> String {
    mirror_host(&engine.lock_net())
}

/// One `[registry."host"]` table of buildkitd.toml. `http` unset leaves
/// BuildKit's default (plain HTTP for `localhost`, HTTPS for the rest).
#[derive(Default, Debug, PartialEq)]
struct Table {
    mirrors: Vec<String>,
    http: Option<bool>,
    insecure: bool,
}

/// The table for `registry`, made if it isn't there yet: BuildKit refuses a
/// buildkitd.toml that names one twice, and Kiri's own mirror, daemon.json's
/// mirrors and its insecure hosts may all cover the same one.
fn table<'a>(tables: &'a mut Vec<(String, Table)>, registry: &str) -> &'a mut Table {
    let i = match tables.iter().position(|(r, _)| r == registry) {
        Some(i) => i,
        None => {
            tables.push((registry.to_owned(), Table::default()));
            tables.len() - 1
        }
    };
    &mut tables[i].1
}

/// Adds `mirror` to `registry`'s list, in order, once.
fn add_mirror(tables: &mut Vec<(String, Table)>, registry: &str, mirror: String) {
    let t = table(tables, registry);
    if !t.mirrors.contains(&mirror) {
        t.mirrors.push(mirror);
    }
}

/// The registries buildkitd.toml has tables for: Docker Hub, and each one
/// an image in the store came from (not this machine's), or came from
/// since the engine started, so removing a registry's last image leaves
/// builds from it as they were.
pub fn registry_names(engine: &Engine) -> Vec<String> {
    let mut names = Vec::new();
    for i in engine.store.images().unwrap_or_default() {
        if let Ok(r) = Reference::parse(&i.name)
            && !names.contains(&r.registry)
            && !kiri_image::reference::is_local(&r.registry)
        {
            names.push(r.registry);
        }
    }
    remembered(names)
}

/// Registries the store's images have named since the engine started: a
/// few dozen at most, bounded all the same.
static SEEN: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
const MAX_SEEN: usize = 256;

/// `now` (the store's registries) with those [`SEEN`] before, Docker Hub
/// first; `now` is remembered too.
fn remembered(now: Vec<String>) -> Vec<String> {
    remembered_in(&mut SEEN.lock().unwrap_or_else(|e| e.into_inner()), now)
}

/// [`remembered`] with `seen` as the memory. Every registry in `now` is
/// always in the answer; past [`MAX_SEEN`] the oldest of those no longer
/// in the store are forgotten. Docker Hub is always there, and takes no
/// place in the memory.
fn remembered_in(seen: &mut Vec<String>, now: Vec<String>) -> Vec<String> {
    for r in &now {
        if r != "docker.io" && !seen.contains(r) {
            seen.push(r.clone());
        }
    }
    while seen.len() > MAX_SEEN {
        let Some(i) = seen.iter().position(|r| !now.contains(r)) else { break };
        seen.remove(i);
    }
    let mut names = vec!["docker.io".to_owned()];
    names.extend(seen.iter().cloned());
    names
}

/// Those of `names` reached without verified TLS by `c`: what buildkitd.toml
/// marks `http` and `insecure` beyond the hosts `c` names itself (a network
/// entry covers a registry only once an image from it has been pulled).
pub fn unverified(c: &kiri_image::RegistryConfig, names: &[String]) -> Vec<String> {
    let mut out: Vec<String> = names.iter().filter(|n| c.is_unverified(n)).cloned().collect();
    out.sort();
    out.dedup();
    out
}

/// A TOML basic string. A name or a mirror goes into buildkitd.toml, and one
/// with a quote, a backslash or a control character in it would close or
/// break the string: buildkitd would refuse the whole file, so every build
/// would fail, and the image that carried the name is recorded, so it would
/// keep failing.
fn quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn format_tables(tables: &[(String, Table)]) -> String {
    let mut out = String::new();
    for (registry, t) in tables {
        out.push_str(&format!("[registry.{}]\n", quoted(registry)));
        if !t.mirrors.is_empty() {
            let list = t.mirrors.iter().map(|m| quoted(m)).collect::<Vec<_>>().join(", ");
            out.push_str(&format!("  mirrors = [{list}]\n"));
        }
        if let Some(http) = t.http {
            out.push_str(&format!("  http = {http}\n"));
        }
        if t.insecure {
            out.push_str("  insecure = true\n");
        }
    }
    out
}

/// The mirror's `host:port` as reached from the builder container (`127.0.0.1`
/// on Linux when the builder uses `--network=host`, else the bridge gateway /
/// VM host address). `None` if the mirror listener for that network mode failed
/// to start.
pub fn upload_endpoint(engine: &Engine, host_net: bool) -> Option<String> {
    let listen = LISTENING.get().copied().flatten()?;
    if cfg!(target_os = "linux") && !host_net && !listen.has_bridge {
        return None;
    }
    let addr = if cfg!(target_os = "linux") && host_net { "127.0.0.1".to_owned() } else { mirror_host(&engine.lock_net()) };
    Some(format!("{addr}:{}", listen.port))
}

/// buildkitd.toml's registry tables, for `c` (daemon.json's settings) and
/// `names` ([`registry_names`]), with `host_net` selecting `127.0.0.1` on
/// Linux when the builder runs in the host network namespace (`--driver-opt
/// network=host`), where the loopback listener is always up even before `kiri0`
/// exists.
pub fn config_for(engine: &Engine, c: &kiri_image::RegistryConfig, names: &[String], host_net: bool) -> String {
    let mut tables: Vec<(String, Table)> = Vec::new();
    if let Some(host) = upload_endpoint(engine, host_net) {
        let token = token();
        for name in names {
            add_mirror(&mut tables, name, format!("{host}/{token}/{name}"));
        }
        table(&mut tables, &host).http = Some(true);
    }
    registries(&mut tables, c, names);
    format_tables(&tables)
}

/// daemon.json's part of buildkitd.toml, so a build reaches each registry
/// the way a pull does. Its Docker Hub mirrors (the usable ones:
/// `RegistryConfig::mirror_allowed`) come after Kiri's own mirror, which
/// serves images built or loaded here and answers 404 for everything else.
///
/// BuildKit (util/resolver) reads `http` and `insecure` together: both set
/// is HTTPS without a certificate check, falling back to plain HTTP when
/// the answer is not TLS (unlike a pull, a portless plain-HTTP registry on
/// port 80 does not fall back when port 443 is closed), which is what a
/// pull does for a host it probes (a listed host, a registry the store
/// names inside a listed network);
/// `http` alone is plain HTTP only; `insecure` alone (with `http = false`,
/// so `localhost` is not sent plain HTTP by default) is unchecked HTTPS
/// only. A mirror is asked over the scheme it was written with, as a pull
/// asks it: `http://` gets `http` alone, `https://` on a host that may go
/// unverified gets `insecure` alone, and one elsewhere keeps verified
/// HTTPS. A host two mirrors name with different schemes is probed. Every
/// other host keeps verified HTTPS, a plain-HTTP mirror's host included
/// (such a mirror is used only when its host is listed). BuildKit has no
/// network form, so a network reaches builds through the registries in
/// `known` (the store's), and a listed host's own table.
fn registries(tables: &mut Vec<(String, Table)>, c: &kiri_image::RegistryConfig, known: &[String]) {
    // Each mirror host and its written scheme (`Some(http)`), `None` where
    // two mirrors on it disagree.
    let mut schemes: Vec<(&str, Option<bool>)> = Vec::new();
    for mirror in c.usable_mirrors() {
        add_mirror(tables, "docker.io", mirror.buildkit());
        match schemes.iter_mut().find(|(h, _)| *h == mirror.host) {
            Some((_, s)) if *s != Some(mirror.http) => *s = None,
            Some(_) => {}
            None => schemes.push((&mirror.host, Some(mirror.http))),
        }
    }
    let probed = |t: &mut Table| {
        t.http = Some(true);
        t.insecure = true;
    };
    for (host, scheme) in &schemes {
        match scheme {
            Some(true) => table(tables, host).http = Some(true),
            Some(false) if c.is_unverified(host) => {
                let t = table(tables, host);
                t.http = Some(false);
                t.insecure = true;
            }
            Some(false) => {}
            None if c.is_unverified(host) => probed(table(tables, host)),
            None => {}
        }
    }
    let listed = c.insecure.iter().filter_map(|e| match e {
        kiri_image::Insecure::Host(h) => Some(h.as_str()),
        kiri_image::Insecure::Net(..) => None,
    });
    for host in listed.chain(known.iter().map(String::as_str)) {
        if c.is_unverified(host) && !schemes.iter().any(|(h, _)| *h == host) {
            probed(table(tables, host));
        }
    }
}

// --- Ephemeral one-shot image load uploads (/v2/load/<nonce>/image/...) ------

const MAX_LOAD_UPLOADS: usize = 256;
const MAX_LOAD_CHILD_MANIFESTS: usize = 64;

struct UploadEntry {
    ingest: kiri_image::store::Ingest,
    written: u64,
}

struct LoadSlot {
    nonce: String,
    engine: Arc<Engine>,
    closed: AtomicBool,
    target_tags: Mutex<Vec<String>>,
    uploads: Mutex<HashMap<String, Arc<Mutex<Option<UploadEntry>>>>>,
    child_manifests: Mutex<HashMap<String, Vec<u8>>>,
    pins: Mutex<Vec<kiri_image::store::Pin>>,
    newly_ingested: Mutex<Vec<String>>,
    used_digests: Mutex<HashSet<String>>,
    committed_digest: Mutex<Option<String>>,
}

impl LoadSlot {
    fn close_and_cleanup(&self) {
        self.closed.store(true, Ordering::Release);
        let uploads = std::mem::take(&mut *self.uploads.lock().unwrap_or_else(|e| e.into_inner()));
        for handle in uploads.values() {
            if let Ok(mut guard) = handle.try_lock() {
                let _ = guard.take();
            }
        }
        drop(uploads);
        self.child_manifests.lock().unwrap_or_else(|e| e.into_inner()).clear();
        let mut pins = self.pins.lock().unwrap_or_else(|e| e.into_inner());
        let newly = std::mem::take(&mut *self.newly_ingested.lock().unwrap_or_else(|e| e.into_inner()));
        let used = self.used_digests.lock().unwrap_or_else(|e| e.into_inner()).clone();
        pins.clear();
        drop(pins);
        for d in newly {
            if !used.contains(&d) {
                let _ = self.engine.store.remove_if_unused(&d);
            }
        }
    }

    fn record_blob(&self, pin: kiri_image::store::Pin, newly_ingested: Option<String>) -> bool {
        let mut pins = self.pins.lock().unwrap_or_else(|e| e.into_inner());
        if self.closed.load(Ordering::Acquire) {
            drop(pins);
            drop(pin);
            if let Some(d) = newly_ingested {
                let _ = self.engine.store.remove_if_unused(&d);
            }
            return false;
        }
        pins.push(pin);
        if let Some(d) = newly_ingested {
            self.newly_ingested.lock().unwrap_or_else(|e| e.into_inner()).push(d);
        }
        true
    }
}

impl Drop for LoadSlot {
    fn drop(&mut self) {
        self.close_and_cleanup();
    }
}

static LOADS: Mutex<Option<HashMap<String, Arc<LoadSlot>>>> = Mutex::new(None);

/// An ephemeral push target in the mirror for one `Solve` call from BuildKit's
/// `docker` driver (`grpc.rs`). Uses a per-build random nonce (never the
/// read-only mirror's secret `token()`), exposes no image reads, and cleans up
/// any uncommitted blobs on drop.
pub struct LoadSession {
    nonce: String,
    slot: Arc<LoadSlot>,
}

impl std::fmt::Debug for LoadSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadSession").field("nonce", &self.nonce).finish()
    }
}

impl LoadSession {
    pub fn new(engine: Arc<Engine>, target_tags: Vec<String>) -> LoadSession {
        let nonce = super::engine::random_hex(16);
        let mut deduped = Vec::with_capacity(target_tags.len());
        let mut seen = HashSet::with_capacity(target_tags.len());
        for t in target_tags {
            if seen.insert(t.clone()) {
                deduped.push(t);
            }
        }
        let slot = Arc::new(LoadSlot {
            nonce: nonce.clone(),
            engine,
            closed: AtomicBool::new(false),
            target_tags: Mutex::new(deduped),
            uploads: Mutex::new(HashMap::new()),
            child_manifests: Mutex::new(HashMap::new()),
            pins: Mutex::new(Vec::new()),
            newly_ingested: Mutex::new(Vec::new()),
            used_digests: Mutex::new(HashSet::new()),
            committed_digest: Mutex::new(None),
        });
        LOADS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_or_insert_with(HashMap::new)
            .insert(nonce.clone(), slot.clone());
        LoadSession { nonce, slot }
    }

    /// Adds extra target tags to this load session (when a solve names multiple
    /// `moby` exporters).
    pub fn add_tags(&self, extra: Vec<String>) {
        let mut tags = self.slot.target_tags.lock().unwrap_or_else(|e| e.into_inner());
        let mut seen: HashSet<String> = tags.iter().cloned().collect();
        for t in extra {
            if seen.insert(t.clone()) {
                tags.push(t);
            }
        }
    }

    /// Reference passed to BuildKit's `image` exporter (`push=true`).
    pub fn repo_ref(&self, endpoint: &str) -> String {
        format!("{endpoint}/load/{}/image:out", self.nonce)
    }

    /// The stored image's config digest once BuildKit has pushed the manifest.
    pub fn committed_digest(&self) -> Option<String> {
        self.slot.committed_digest.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl Drop for LoadSession {
    fn drop(&mut self) {
        if let Some(map) = LOADS.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            map.remove(&self.nonce);
        }
        self.slot.close_and_cleanup();
    }
}

fn is_hex_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn find_load_slot(nonce: &str) -> Option<Arc<LoadSlot>> {
    if !is_hex_id(nonce) {
        return None;
    }
    LOADS.lock().unwrap_or_else(|e| e.into_inner()).as_ref()?.get(nonce).cloned()
}

fn serve(listener: TcpListener, engine: Weak<Engine>) {
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let Some(engine) = engine.upgrade() else { return };
        if ACTIVE_WORKERS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < MAX_MIRROR_WORKERS).then_some(n + 1))
            .is_err()
        {
            continue;
        }
        let guard = WorkerGuard;
        let _ = std::thread::Builder::new().name("kiri-build-mirror".into()).spawn(move || {
            let _guard = guard;
            let _ = conn.set_read_timeout(Some(Duration::from_secs(30)));
            let _ = answer(conn, &engine);
        });
    }
}

#[derive(Clone, Copy)]
enum BodyFraming {
    None,
    Length(u64),
    Chunked,
}

fn read_http_body<R: BufRead, W: Write>(r: &mut R, framing: BodyFraming, out: &mut W, limit: Option<u64>) -> io::Result<u64> {
    let mut total = 0u64;
    let mut buf = [0u8; 32 * 1024];
    let mut copy_exact = |r: &mut R, mut rem: u64, out: &mut W, total: &mut u64| -> io::Result<()> {
        while rem > 0 {
            let want = buf.len().min(rem as usize);
            let n = r.read(&mut buf[..want])?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated request body"));
            }
            *total = total.checked_add(n as u64).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "body overflow"))?;
            if limit.is_some_and(|l| *total > l) {
                return Err(io::Error::new(io::ErrorKind::FileTooLarge, "request body too large"));
            }
            out.write_all(&buf[..n])?;
            rem -= n as u64;
        }
        Ok(())
    };
    match framing {
        BodyFraming::None => Ok(0),
        BodyFraming::Length(n) => {
            copy_exact(r, n, out, &mut total)?;
            Ok(total)
        }
        BodyFraming::Chunked => loop {
            let mut line = String::new();
            if (&mut *r).take(1024).read_line(&mut line)? == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated chunk header"));
            }
            if !line.ends_with('\n') {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk header too long"));
            }
            let raw = line.trim_end_matches(['\r', '\n']);
            let hex = raw.split(';').next().unwrap_or_default().trim();
            let size = u64::from_str_radix(hex, 16).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
            if size == 0 {
                // Drain bounded trailers until blank line.
                for _ in 0..128 {
                    let mut tr = String::new();
                    if (&mut *r).take(4096).read_line(&mut tr)? == 0 || tr == "\r\n" || tr == "\n" {
                        break;
                    }
                }
                return Ok(total);
            }
            copy_exact(r, size, out, &mut total)?;
            let mut crlf = [0u8; 2];
            r.read_exact(&mut crlf)?;
            if crlf != *b"\r\n" {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "bad chunk delimiter"));
            }
        },
    }
}

fn query_param(query: &str, key: &str) -> Option<String> {
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        if k == key {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() && hex(b[i + 1]).is_some() && hex(b[i + 2]).is_some() => {
                out.push(hex(b[i + 1]).unwrap_or(0) << 4 | hex(b[i + 2]).unwrap_or(0));
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One request, then the connection closes.
fn answer(conn: TcpStream, engine: &Engine) -> io::Result<()> {
    let mut w = conn.try_clone()?;
    let mut r = BufReader::new(conn);
    answer_stream(&mut r, &mut w, engine)
}

fn answer_stream<R: BufRead, W: Write>(r: &mut R, w: &mut W, engine: &Engine) -> io::Result<()> {
    let head = |w: &mut W, status: &str, extra: &str, len: u64| write!(w, "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {len}\r\n{extra}\r\n");
    let (method, target, framing, expect_continue) = {
        let mut head_reader = (&mut *r).take(16 << 10);
        let mut raw_line = Vec::new();
        if head_reader.read_until(b'\n', &mut raw_line)? == 0 {
            return Ok(());
        }
        let Ok(line) = std::str::from_utf8(&raw_line) else {
            head(w, "400 Bad Request", "", 0)?;
            return w.flush();
        };
        if !line.ends_with('\n') {
            head(w, "400 Bad Request", "", 0)?;
            return w.flush();
        }
        let mut parts = line.split_whitespace();
        let (method, target) = (parts.next().unwrap_or_default().to_owned(), parts.next().unwrap_or_default().to_owned());
        let mut content_length: Option<u64> = None;
        let mut chunked = false;
        let mut expect_continue = false;
        let mut saw_end = false;
        loop {
            let mut raw_h = Vec::new();
            if head_reader.read_until(b'\n', &mut raw_h)? == 0 {
                break;
            }
            let Ok(h) = std::str::from_utf8(&raw_h) else {
                head(w, "400 Bad Request", "", 0)?;
                return w.flush();
            };
            if !h.ends_with('\n') {
                head(w, "400 Bad Request", "", 0)?;
                return w.flush();
            }
            if h.trim().is_empty() {
                saw_end = true;
                break;
            }
            if let Some((k, v)) = h.split_once(':') {
                let k = k.trim();
                let v = v.trim();
                if k.eq_ignore_ascii_case("content-length") {
                    let Ok(parsed) = v.parse::<u64>() else {
                        head(w, "400 Bad Request", "", 0)?;
                        return w.flush();
                    };
                    if content_length.is_some_and(|prev| prev != parsed) {
                        head(w, "400 Bad Request", "", 0)?;
                        return w.flush();
                    }
                    content_length = Some(parsed);
                } else if k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked") {
                    chunked = true;
                } else if k.eq_ignore_ascii_case("expect") && v.to_ascii_lowercase().contains("100-continue") {
                    expect_continue = true;
                }
            }
        }
        if !saw_end || (chunked && content_length.is_some()) {
            head(w, "400 Bad Request", "", 0)?;
            return w.flush();
        }
        let framing = if chunked {
            BodyFraming::Chunked
        } else if let Some(n) = content_length.filter(|n| *n > 0) {
            BodyFraming::Length(n)
        } else {
            BodyFraming::None
        };
        (method, target, framing, expect_continue)
    };
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));

    // Registry v2 ping (`GET /v2/` / `HEAD /v2/`).
    if matches!(method.as_str(), "GET" | "HEAD") && (path == "/v2/" || path == "/v2") {
        let body = if method == "GET" { b"{}".as_slice() } else { b"".as_slice() };
        head(w, "200 OK", "Docker-Distribution-Api-Version: registry/2.0\r\nContent-Type: application/json\r\n", body.len() as u64)?;
        w.write_all(body)?;
        return w.flush();
    }

    // Ephemeral one-shot image upload for BuildKit's `docker` driver.
    if let Some(rest) = path.strip_prefix("/v2/load/") {
        if let Some((nonce, sub)) = rest.split_once("/image/") {
            return handle_load(engine, nonce, sub, &method, query, framing, expect_continue, r, w);
        }
        head(w, "404 Not Found", "", 0)?;
        return w.flush();
    }

    if method != "GET" && method != "HEAD" {
        head(w, "405 Method Not Allowed", "", 0)?;
        return w.flush();
    }
    match lookup(&engine.store, path, &token()) {
        Some(Found::Manifest(bytes, media_type, digest)) => {
            head(w, "200 OK", &format!("Content-Type: {media_type}\r\nDocker-Content-Digest: {digest}\r\n"), bytes.len() as u64)?;
            if method == "GET" {
                w.write_all(&bytes)?;
            }
        }
        Some(Found::Blob(path, digest)) => {
            let mut f = std::fs::File::open(&path)?;
            let len = f.metadata()?.len();
            head(w, "200 OK", &format!("Content-Type: application/octet-stream\r\nDocker-Content-Digest: {digest}\r\n"), len)?;
            if method == "GET" {
                io::copy(&mut f, w)?;
            }
        }
        None => head(w, "404 Not Found", "", 0)?,
    }
    w.flush()
}

#[allow(clippy::too_many_arguments)]
fn handle_load<R: BufRead, W: Write>(
    engine: &Engine,
    nonce: &str,
    sub: &str,
    method: &str,
    query: &str,
    framing: BodyFraming,
    expect_continue: bool,
    r: &mut R,
    w: &mut W,
) -> io::Result<()> {
    let head = |w: &mut W, status: &str, extra: &str, len: u64| write!(w, "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {len}\r\n{extra}\r\n");
    let Some(slot) = find_load_slot(nonce).filter(|s| !s.closed.load(Ordering::Acquire)) else {
        head(w, "404 Not Found", "", 0)?;
        return w.flush();
    };
    let send_continue = |w: &mut W| -> io::Result<()> {
        if expect_continue {
            w.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
            w.flush()?;
        }
        Ok(())
    };
    let base = format!("/v2/load/{}/image", slot.nonce);

    // HEAD /blobs/<digest>: dedup check for blobs already in Kiri's store.
    if method == "HEAD" && let Some(digest) = sub.strip_prefix("blobs/") {
        let Ok(hex) = kiri_image::store::digest_hex(digest) else {
            head(w, "400 Bad Request", "", 0)?;
            return w.flush();
        };
        let valid_digest = format!("sha256:{}", hex.to_ascii_lowercase());
        let pin = engine.store.pin(&valid_digest);
        if let Ok(path) = engine.store.blob_path(&valid_digest) && let Ok(meta) = std::fs::metadata(&path) && meta.is_file() {
            if !slot.record_blob(pin, None) {
                head(w, "404 Not Found", "", 0)?;
                return w.flush();
            }
            head(w, "200 OK", &format!("Docker-Content-Digest: {valid_digest}\r\n"), meta.len())?;
            return w.flush();
        }
        head(w, "404 Not Found", "", 0)?;
        return w.flush();
    }

    // POST /blobs/uploads/ (start chunked upload, cross-repo mount, or monolithic upload).
    if method == "POST" && matches!(sub, "blobs/uploads/" | "blobs/uploads") {
        if let Some(expected) = query_param(query, "digest") {
            let Ok(hex) = kiri_image::store::digest_hex(&expected) else {
                head(w, "400 Bad Request", "", 0)?;
                return w.flush();
            };
            let expected = format!("sha256:{}", hex.to_ascii_lowercase());
            send_continue(w)?;
            let existed = engine.store.blob_path(&expected).is_ok_and(|p| p.is_file());
            let mut ingest = engine.store.ingest()?;
            read_http_body(r, framing, &mut ingest, None)?;
            let (actual, _, pin) = ingest.finish_pinned()?;
            if actual != expected {
                drop(pin);
                let _ = engine.store.remove_if_unused(&actual);
                head(w, "400 Bad Request", "", 0)?;
                return w.flush();
            }
            if !slot.record_blob(pin, (!existed).then_some(actual)) {
                head(w, "404 Not Found", "", 0)?;
                return w.flush();
            }
            head(w, "201 Created", &format!("Location: {base}/blobs/{expected}\r\nDocker-Content-Digest: {expected}\r\n"), 0)?;
            return w.flush();
        }
        if let Some(mount) = query_param(query, "mount") && let Ok(hex) = kiri_image::store::digest_hex(&mount) {
            let mount = format!("sha256:{}", hex.to_ascii_lowercase());
            let pin = engine.store.pin(&mount);
            if engine.store.blob_path(&mount).is_ok_and(|p| p.is_file()) {
                if !slot.record_blob(pin, None) {
                    head(w, "404 Not Found", "", 0)?;
                    return w.flush();
                }
                head(w, "201 Created", &format!("Location: {base}/blobs/{mount}\r\nDocker-Content-Digest: {mount}\r\n"), 0)?;
                return w.flush();
            }
        }
        let mut uploads = slot.uploads.lock().unwrap_or_else(|e| e.into_inner());
        if slot.closed.load(Ordering::Acquire) {
            drop(uploads);
            head(w, "404 Not Found", "", 0)?;
            return w.flush();
        }
        if uploads.len() >= MAX_LOAD_UPLOADS {
            drop(uploads);
            head(w, "429 Too Many Requests", "", 0)?;
            return w.flush();
        }
        let uuid = super::engine::random_hex(16);
        let entry = UploadEntry { ingest: engine.store.ingest()?, written: 0 };
        uploads.insert(uuid.clone(), Arc::new(Mutex::new(Some(entry))));
        drop(uploads);
        head(w, "202 Accepted", &format!("Location: {base}/blobs/uploads/{uuid}\r\nDocker-Upload-UUID: {uuid}\r\nRange: 0-0\r\n"), 0)?;
        return w.flush();
    }

    // DELETE /blobs/uploads/<uuid>: cancel an in-progress upload.
    if method == "DELETE" && let Some(uuid) = sub.strip_prefix("blobs/uploads/") && is_hex_id(uuid) {
        if slot.uploads.lock().unwrap_or_else(|e| e.into_inner()).remove(uuid).is_some() {
            head(w, "204 No Content", "", 0)?;
        } else {
            head(w, "404 Not Found", "", 0)?;
        }
        return w.flush();
    }

    // PATCH /blobs/uploads/<uuid>: stream chunk into an active upload.
    if method == "PATCH" && let Some(uuid) = sub.strip_prefix("blobs/uploads/") && is_hex_id(uuid) {
        let Some((id, handle)) = slot
            .uploads
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_key_value(uuid)
            .map(|(k, v)| (k.clone(), v.clone()))
        else {
            head(w, "404 Not Found", "", 0)?;
            return w.flush();
        };
        send_continue(w)?;
        let mut guard = handle.lock().unwrap_or_else(|e| e.into_inner());
        if slot.closed.load(Ordering::Acquire) {
            let _ = guard.take();
            head(w, "404 Not Found", "", 0)?;
            return w.flush();
        }
        let Some(entry) = guard.as_mut() else {
            head(w, "404 Not Found", "", 0)?;
            return w.flush();
        };
        let n = read_http_body(r, framing, &mut entry.ingest, None)?;
        entry.written += n;
        let end = entry.written.saturating_sub(1);
        head(w, "202 Accepted", &format!("Location: {base}/blobs/uploads/{id}\r\nDocker-Upload-UUID: {id}\r\nRange: 0-{end}\r\n"), 0)?;
        return w.flush();
    }

    // PUT /blobs/uploads/<uuid>?digest=sha256:... : finalize upload into blob store.
    if method == "PUT" && let Some(uuid) = sub.strip_prefix("blobs/uploads/") && is_hex_id(uuid) {
        let Some(expected) = query_param(query, "digest").and_then(|d| {
            kiri_image::store::digest_hex(&d).ok().map(|h| format!("sha256:{}", h.to_ascii_lowercase()))
        }) else {
            head(w, "400 Bad Request", "", 0)?;
            return w.flush();
        };
        let Some(handle) = slot.uploads.lock().unwrap_or_else(|e| e.into_inner()).remove(uuid) else {
            head(w, "404 Not Found", "", 0)?;
            return w.flush();
        };
        let mut guard = handle.lock().unwrap_or_else(|e| e.into_inner());
        let Some(mut entry) = guard.take() else {
            head(w, "404 Not Found", "", 0)?;
            return w.flush();
        };
        drop(guard);
        if slot.closed.load(Ordering::Acquire) {
            head(w, "404 Not Found", "", 0)?;
            return w.flush();
        }
        send_continue(w)?;
        read_http_body(r, framing, &mut entry.ingest, None)?;
        let existed = engine.store.blob_path(&expected).is_ok_and(|p| p.is_file());
        let (actual, _, pin) = entry.ingest.finish_pinned()?;
        if actual != expected {
            drop(pin);
            let _ = engine.store.remove_if_unused(&actual);
            head(w, "400 Bad Request", "", 0)?;
            return w.flush();
        }
        if !slot.record_blob(pin, (!existed).then_some(actual)) {
            head(w, "404 Not Found", "", 0)?;
            return w.flush();
        }
        head(w, "201 Created", &format!("Location: {base}/blobs/{expected}\r\nDocker-Content-Digest: {expected}\r\n"), 0)?;
        return w.flush();
    }

    // HEAD /manifests/<ref>: always 404 so BuildKit pushes the final manifest.
    if method == "HEAD" && let Some(reference) = sub.strip_prefix("manifests/") && !reference.contains('/') {
        let _ = reference;
        head(w, "404 Not Found", "", 0)?;
        return w.flush();
    }

    // PUT /manifests/<ref>: commit image(s) into Kiri's store.
    if method == "PUT" && let Some(reference) = sub.strip_prefix("manifests/") && !reference.contains('/') {
        send_continue(w)?;
        let mut body = Vec::new();
        if let Err(e) = read_http_body(r, framing, &mut body, Some(MAX_MANIFEST)) {
            let status = if e.kind() == io::ErrorKind::FileTooLarge { "413 Payload Too Large" } else { "400 Bad Request" };
            head(w, status, "", 0)?;
            return w.flush();
        }
        let manifest_digest = kiri_image::store::sha256_digest(&body);
        if reference.starts_with("sha256:") {
            if manifest_digest != reference {
                head(w, "400 Bad Request", "", 0)?;
                return w.flush();
            }
            let mut children = slot.child_manifests.lock().unwrap_or_else(|e| e.into_inner());
            if children.len() >= MAX_LOAD_CHILD_MANIFESTS && !children.contains_key(&manifest_digest) {
                drop(children);
                head(w, "429 Too Many Requests", "", 0)?;
                return w.flush();
            }
            children.insert(manifest_digest.clone(), body);
            drop(children);
            head(w, "201 Created", &format!("Docker-Content-Digest: {manifest_digest}\r\n"), 0)?;
            return w.flush();
        }
        match commit_load_manifest(engine, &slot, &body) {
            Ok(()) => {
                head(w, "201 Created", &format!("Docker-Content-Digest: {manifest_digest}\r\n"), 0)?;
                return w.flush();
            }
            Err(e) => {
                crate::diag::warn!("build mirror image commit failed", error = e);
                head(w, "400 Bad Request", "", 0)?;
                return w.flush();
            }
        }
    }

    head(w, "405 Method Not Allowed", "", 0)?;
    w.flush()
}

fn layer_media_type(path: &std::path::Path) -> &'static str {
    let mut magic = [0u8; 4];
    let n = std::fs::File::open(path).and_then(|mut f| f.read(&mut magic)).unwrap_or(0);
    match &magic[..n] {
        [0x1f, 0x8b, ..] => "application/vnd.oci.image.layer.v1.tar+gzip",
        [0x28, 0xb5, 0x2f, 0xfd] => "application/vnd.oci.image.layer.v1.tar+zstd",
        _ => "application/vnd.oci.image.layer.v1.tar",
    }
}

fn commit_load_manifest(engine: &Engine, slot: &LoadSlot, raw: &[u8]) -> io::Result<()> {
    if slot.closed.load(Ordering::Acquire) {
        return Err(io::Error::new(io::ErrorKind::BrokenPipe, "load session closed"));
    }
    let parsed: Value = serde_json::from_slice(raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("manifest JSON: {e}")))?;
    // If BuildKit pushed an OCI image index (e.g. with attestations), resolve
    // the matching platform image manifest from the previously pushed children.
    let manifest: Value = if let Some(list) = parsed["manifests"].as_array() {
        let host = Platform::host_linux();
        let is_image = |m: &&Value| {
            let ref_type = m["annotations"]["vnd.docker.reference.type"].as_str();
            let os = m["platform"]["os"].as_str().unwrap_or("linux");
            let arch = m["platform"]["architecture"].as_str().unwrap_or("");
            ref_type != Some("attestation-manifest") && os != "unknown" && arch != "unknown"
        };
        let chosen = list
            .iter()
            .filter(is_image)
            .find(|m| {
                m["platform"]["os"].as_str() == Some(host.os.as_str())
                    && m["platform"]["architecture"].as_str() == Some(host.architecture.as_str())
            })
            .or_else(|| list.iter().find(is_image))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "image index contains no runnable manifest"))?;
        let digest = chosen["digest"].as_str().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "index entry missing digest"))?;
        let children = slot.child_manifests.lock().unwrap_or_else(|e| e.into_inner());
        let child_bytes = children.get(digest).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("missing child manifest {digest}")))?;
        serde_json::from_slice(child_bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("child manifest JSON: {e}")))?
    } else {
        parsed
    };

    let config_digest = manifest["config"]["digest"]
        .as_str()
        .filter(|d| kiri_image::store::digest_hex(d).is_ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "manifest missing config digest"))?
        .to_owned();
    let mut extra_pins = vec![engine.store.pin(&config_digest)];
    let config_bytes = engine.store.read_config(&config_digest)?;
    let config_json: Value = serde_json::from_slice(&config_bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("image config: {e}")))?;

    let mut layers = Vec::new();
    let mut used = vec![config_digest.clone()];
    for l in manifest["layers"].as_array().into_iter().flatten() {
        let digest = l["digest"]
            .as_str()
            .filter(|d| kiri_image::store::digest_hex(d).is_ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "layer missing digest"))?
            .to_owned();
        extra_pins.push(engine.store.pin(&digest));
        let path = engine.store.blob_path(&digest)?;
        let size = std::fs::metadata(&path)?.len();
        let media_type = l["mediaType"]
            .as_str()
            .filter(|m| !m.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| layer_media_type(&path).to_owned());
        used.push(digest.clone());
        layers.push(Layer { digest, size, media_type });
    }

    let mut pins = slot.pins.lock().unwrap_or_else(|e| e.into_inner());
    if slot.closed.load(Ordering::Acquire) {
        return Err(io::Error::new(io::ErrorKind::BrokenPipe, "load session closed"));
    }
    let target_tags = slot.target_tags.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let names = if target_tags.is_empty() { vec![config_digest.clone()] } else { target_tags };
    for name in &names {
        let img = kiri_image::archive::from_config(name.clone(), &config_digest, &config_json, layers.clone());
        engine.store.put_image(img)?;
        if !name.starts_with("sha256:") {
            engine.emit_image("tag", &config_digest, name);
        }
    }
    engine.prune_layers();
    pins.extend(extra_pins);
    slot.used_digests.lock().unwrap_or_else(|e| e.into_inner()).extend(used);
    *slot.committed_digest.lock().unwrap_or_else(|e| e.into_inner()) = Some(config_digest);
    Ok(())
}

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const MAX_MANIFEST: u64 = 4 << 20;

#[derive(Debug)]
enum Found {
    Manifest(Vec<u8>, String, String),
    Blob(std::path::PathBuf, String),
}

/// Content-Type for raw manifest or index JSON `bytes`.
fn manifest_media_type(bytes: &[u8]) -> String {
    if let Ok(v) = serde_json::from_slice::<Value>(bytes) {
        if let Some(mt) = v["mediaType"].as_str().map(str::trim).filter(|m| !m.is_empty() && !m.contains(['\r', '\n'])) {
            return mt.to_owned();
        }
        if v.get("manifests").is_some() {
            return OCI_INDEX.to_owned();
        }
    }
    OCI_MANIFEST.to_owned()
}

/// Reads a raw upstream manifest or multi-arch index blob saved during `pull`,
/// verifying that its bytes hash to `digest`.
fn stored_manifest(store: &kiri_image::Store, digest: &str) -> Option<(Vec<u8>, String)> {
    let path = store.blob_path(digest).ok()?;
    let len = std::fs::metadata(&path).ok()?.len();
    if len > MAX_MANIFEST {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    (kiri_image::store::sha256_digest(&bytes) == digest).then(|| {
        let media_type = manifest_media_type(&bytes);
        (bytes, media_type)
    })
}

/// An image's manifest as Kiri serves it, and its digest.
fn manifest(store: &kiri_image::Store, i: &Image) -> Option<(Vec<u8>, String)> {
    let config_size = std::fs::metadata(store.blob_path(&i.config_digest).ok()?).ok()?.len();
    let m = json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": i.config_digest, "size": config_size},
        "layers": i.layers.iter().map(|l| json!({"mediaType": l.media_type, "digest": l.digest, "size": l.size})).collect::<Vec<Value>>(),
    });
    let bytes = serde_json::to_vec(&m).ok()?;
    let digest = kiri_image::store::sha256_digest(&bytes);
    Some((bytes, digest))
}

/// `/v2/<token>/<registry>/<repo…>/manifests/<tag|digest>` or `…/blobs/<digest>`.
fn parse(path: &str, token: &str) -> Option<(String, String, bool, String)> {
    let rest = path.strip_prefix("/v2/")?.strip_prefix(token)?.strip_prefix('/')?;
    let (registry, rest) = rest.split_once('/')?;
    let (repo, kind, reference) = if let Some((repo, r)) = rest.rsplit_once("/manifests/") {
        (repo, true, r)
    } else {
        let (repo, r) = rest.rsplit_once("/blobs/")?;
        (repo, false, r)
    };
    (!repo.is_empty() && !reference.is_empty() && !reference.contains('/')).then(|| (registry.to_owned(), repo.to_owned(), kind, reference.to_owned()))
}

/// Whether the mirror answers for `i` under its tag. It does for an image no
/// registry has (built, loaded, committed: its digest is its config's), which
/// is the one thing a build cannot get anywhere else. An image a registry
/// published is left to that registry, which knows every platform of the tag;
/// answering with the one platform Kiri pulled would hide the rest.
fn serve_tag(i: &Image) -> bool {
    i.repo_digest().is_none()
}

fn lookup(store: &kiri_image::Store, path: &str, token: &str) -> Option<Found> {
    let (registry, repo, is_manifest, reference) = parse(path, token)?;
    let images = store.images().ok()?;
    let in_repo = |i: &&Image| Reference::parse(&i.name).is_ok_and(|n| n.registry == registry && n.repository == repo);
    if is_manifest {
        if reference.starts_with("sha256:") {
            // Serve the exact raw manifest or multi-arch index bytes saved
            // during `docker pull` when an image in this repository owns that
            // digest, so digest-pinned builds (`FROM repo:tag@sha256:…` or
            // `FROM repo@sha256:…`) verify cleanly from Kiri's store (#288, #330).
            if images.iter().filter(in_repo).any(|i| i.digest == reference || i.index_digest.as_deref() == Some(reference.as_str()))
                && let Some((b, mt)) = stored_manifest(store, &reference)
            {
                return Some(Found::Manifest(b, mt, reference));
            }
            return images.iter().filter(in_repo).find_map(|i| manifest(store, i).filter(|(_, d)| *d == reference)).map(|(b, d)| Found::Manifest(b, OCI_MANIFEST.to_owned(), d));
        }
        let wanted = Reference::parse(&format!("{registry}/{repo}:{reference}")).ok()?.short();
        // A tag a registry published is the registry's to answer: Kiri holds
        // the one platform it pulled, and serving that says the tag has no
        // other, so a build for another platform takes these binaries and
        // fails on them (issue #57). 404 here makes the builder skip this
        // mirror and pull the platform it asked for.
        let i = images.iter().find(|i| i.name == wanted && serve_tag(i))?;
        let (b, d) = manifest(store, i)?;
        return Some(Found::Manifest(b, OCI_MANIFEST.to_owned(), d));
    }
    // Only blobs of that repository's images.
    let owned = images.iter().filter(in_repo).any(|i| i.referenced_digests().any(|d| d == reference));
    let path = store.blob_path(&reference).ok()?;
    (owned && path.is_file()).then_some(Found::Blob(path, reference))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A registry the store named once keeps its builder table after its
    /// last image is removed: the builder is not restarted without it.
    #[test]
    fn a_registry_seen_once_keeps_its_builder_table() {
        let first = remembered(vec!["10.77.0.9:5000".into(), "docker.io".into()]);
        assert_eq!(first[0], "docker.io");
        assert_eq!(first.iter().filter(|r| *r == "docker.io").count(), 1);
        let later = remembered(Vec::new());
        assert!(later.contains(&"10.77.0.9:5000".to_owned()), "{later:?}");
        let c = kiri_image::RegistryConfig { insecure: vec![kiri_image::Insecure::parse("10.0.0.0/8").unwrap()], ..Default::default() };
        assert_eq!(unverified(&c, &["10.77.0.9:5000".into(), "10.77.0.9:5000".into()]), ["10.77.0.9:5000"]);
    }

    /// daemon.json's hosts merge into one table each, as BuildKit wants:
    /// every host a pull reaches unverified is http and insecure in builds
    /// too, a network covers the registries the store names inside it, and
    /// nothing else changes.
    /// However many registries were seen before, every one the store names
    /// now has its table; the oldest gone from the store make room.
    #[test]
    fn a_full_memory_still_takes_the_stores_registries() {
        let mut seen = Vec::new();
        // One image at a time, each removed before the next is pulled.
        for i in 0..MAX_SEEN + 40 {
            remembered_in(&mut seen, vec![format!("old-{i}.lan:5000")]);
        }
        assert_eq!(seen.len(), MAX_SEEN);
        let names = remembered_in(&mut seen, vec!["docker.io".into(), "new.lan:5000".into()]);
        assert!(names.contains(&"new.lan:5000".to_owned()), "the new registry has its table");
        assert_eq!(names.iter().filter(|n| *n == "docker.io").count(), 1);
        assert!(seen.len() <= MAX_SEEN && !seen.contains(&"docker.io".to_owned()));
        assert!(!seen.contains(&"old-40.lan:5000".to_owned()) && seen.contains(&format!("old-{}.lan:5000", MAX_SEEN + 39)), "the oldest went");
    }

    #[test]
    fn daemon_json_registries_share_one_table_each() {
        let c = kiri_image::RegistryConfig {
            insecure: ["registry.lan:5000", "mirror.lan:5000", "10.0.0.0/8"].iter().map(|e| kiri_image::Insecure::parse(e).unwrap()).collect(),
            mirrors: vec![kiri_image::Mirror::parse("http://mirror.lan:5000").unwrap(), kiri_image::Mirror::parse("https://m.example.com/docker.io").unwrap()],
        };
        let mut tables = Vec::new();
        add_mirror(&mut tables, "docker.io", "198.19.248.254:1234/t/docker.io".into());
        registries(&mut tables, &c, &["docker.io".into(), "10.1.2.3:5000".into(), "ghcr.io".into()]);
        let names: Vec<&str> = tables.iter().map(|(r, _)| r.as_str()).collect();
        assert_eq!(names, ["docker.io", "mirror.lan:5000", "registry.lan:5000", "10.1.2.3:5000"]);
        assert_eq!(tables[0].1.mirrors, ["198.19.248.254:1234/t/docker.io", "mirror.lan:5000", "m.example.com/docker.io"]);
        // The http:// mirror straight over plain HTTP, as a pull asks it.
        assert_eq!(tables[1].1, Table { mirrors: vec![], http: Some(true), insecure: false });
        for t in &tables[2..] {
            assert_eq!(t.1, Table { mirrors: vec![], http: Some(true), insecure: true });
        }
        let mut none = Vec::new();
        registries(&mut none, &kiri_image::RegistryConfig::default(), &["ghcr.io".into()]);
        assert!(none.is_empty());
    }

    /// A mirror is reached in builds over the scheme it was written with,
    /// as a pull reaches it: an https:// one on a listed host or on this
    /// machine is unchecked HTTPS with no fall back to plain HTTP, an
    /// http:// one plain HTTP with no TLS first, an https:// one elsewhere
    /// verified HTTPS. A listed host with no scheme is probed (both set).
    #[test]
    fn a_build_reaches_a_mirror_over_its_written_scheme() {
        let c = kiri_image::RegistryConfig {
            insecure: ["tls.lan:5000", "plain.lan:5000", "both.lan:5000", "reg.lan:5000"].iter().map(|e| kiri_image::Insecure::parse(e).unwrap()).collect(),
            mirrors: ["https://tls.lan:5000", "http://plain.lan:5000", "https://127.0.0.1:5000", "https://m.example.com", "https://both.lan:5000/a", "http://both.lan:5000/b"].iter().map(|m| kiri_image::Mirror::parse(m).unwrap()).collect(),
        };
        let mut tables = Vec::new();
        registries(&mut tables, &c, &[]);
        let get = |h: &str| tables.iter().find(|(r, _)| r == h).map(|(_, t)| (t.http, t.insecure));
        assert_eq!(get("tls.lan:5000"), Some((Some(false), true)));
        assert_eq!(get("127.0.0.1:5000"), Some((Some(false), true)));
        assert_eq!(get("plain.lan:5000"), Some((Some(true), false)));
        assert_eq!(get("both.lan:5000"), Some((Some(true), true)));
        assert_eq!(get("reg.lan:5000"), Some((Some(true), true)));
        assert_eq!(get("m.example.com"), None);
    }

    /// A plain-HTTP mirror on a host nobody listed: a pull does not use it,
    /// and neither does a build, and its host stays verified HTTPS for
    /// everything else (`FROM mirror.lan:5000/x`, a push).
    #[test]
    fn a_build_and_a_pull_agree_on_a_plain_http_mirror() {
        let c = kiri_image::RegistryConfig { mirrors: vec![kiri_image::Mirror::parse("http://mirror.lan:5000").unwrap()], ..Default::default() };
        let mut tables = Vec::new();
        registries(&mut tables, &c, &[]);
        assert!(tables.is_empty(), "{tables:?}");
        assert_eq!(c.usable_mirrors().count(), 0);
    }

    #[test]
    fn parses_mirror_paths() {
        assert_eq!(parse("/v2/tok/docker.io/library/myapp/manifests/dev", "tok"), Some(("docker.io".into(), "library/myapp".into(), true, "dev".into())));
        assert_eq!(parse("/v2/tok/ghcr.io/o/r/blobs/sha256:ab", "tok"), Some(("ghcr.io".into(), "o/r".into(), false, "sha256:ab".into())));
        assert_eq!(parse("/v2/wrong/docker.io/library/a/manifests/x", "tok"), None);
        assert_eq!(parse("/v2/tok/docker.io/manifests/x", "tok"), None);
        assert_eq!(parse("/v2/", "tok"), None);
    }

    #[test]
    fn mirror_host_matches_the_host_network() {
        let dir = std::env::temp_dir().join(format!("kiri-mirror-host-{}", std::process::id()));
        let networks = super::super::network::Networks::load(&dir).unwrap();
        #[cfg(target_os = "linux")]
        assert_eq!(mirror_host(&networks), super::super::network::ip_str(networks.find("bridge").unwrap().gateway));
        #[cfg(not(target_os = "linux"))]
        assert_eq!(mirror_host(&networks), super::super::ports::HOST_ADDR);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_tag_a_registry_published_is_left_to_it() {
        // Pulled: its digest is its manifest's, so a registry has it.
        let pulled = Image { name: "alpine:3.20".into(), digest: "sha256:manifest".into(), ..made_here() };
        assert!(!serve_tag(&pulled));
        // Pulled through a configured Docker Hub mirror (#119) or from a multi-arch index.
        let mirrored = Image { mirror: Some("mirror.lan:5000".into()), index_digest: Some("sha256:index".into()), ..pulled.clone() };
        assert!(!serve_tag(&mirrored));
        // Another tag in the same repository still carries that repository's digest.
        assert!(!serve_tag(&pulled.tagged("alpine:latest".into())));
        // Built, loaded or committed here: nothing else can serve it, platform or not.
        assert!(serve_tag(&made_here()));
        // Tagged into another repository (docker tag alpine:3.20 mybase:dev):
        // that name is not in any registry, so the mirror answers for it.
        assert!(serve_tag(&pulled.tagged("mybase:dev".into())));
    }

    #[test]
    fn lookup_skips_published_tags_but_serves_local_tags_digests_and_blobs() {
        let dir = std::env::temp_dir().join(format!("kiri-mirror-lookup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = kiri_image::Store::open(&dir).unwrap();
        let write_blob = |bytes: &[u8]| {
            let mut w = store.ingest().unwrap();
            w.write_all(bytes).unwrap();
            w.finish().unwrap()
        };
        let cfg = json!({"architecture": "amd64", "os": "linux", "config": {}});
        let (cfg_digest, _) = write_blob(&serde_json::to_vec(&cfg).unwrap());
        let (layer_digest, layer_size) = write_blob(b"layer-bytes");
        let layers = vec![kiri_image::Layer { digest: layer_digest.clone(), size: layer_size, media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into() }];

        // 1. Registry-pulled image (also when pulled via a #119 mirror): tag
        // lookup returns None (404) so BuildKit falls through to the configured
        // mirror or upstream registry, while digest and blob lookups still hit
        // the local store so cached layers are not re-downloaded.
        let pulled = Image {
            name: "alpine:3.20".into(),
            digest: format!("sha256:{}", "a".repeat(64)),
            index_digest: Some(format!("sha256:{}", "b".repeat(64))),
            mirror: Some("mirror.lan:5000".into()),
            ..kiri_image::archive::from_config("alpine:3.20".into(), &cfg_digest, &cfg, layers.clone())
        };
        let (_, pulled_manifest_digest) = manifest(&store, &pulled).unwrap();
        store.put_image(pulled.clone()).unwrap();

        assert!(lookup(&store, "/v2/tok/docker.io/library/alpine/manifests/3.20", "tok").is_none());
        assert!(matches!(
            lookup(&store, &format!("/v2/tok/docker.io/library/alpine/manifests/{pulled_manifest_digest}"), "tok"),
            Some(Found::Manifest(_, _, d)) if d == pulled_manifest_digest
        ));
        assert!(matches!(
            lookup(&store, &format!("/v2/tok/docker.io/library/alpine/blobs/{layer_digest}"), "tok"),
            Some(Found::Blob(_, d)) if d == layer_digest
        ));
        assert!(matches!(
            lookup(&store, &format!("/v2/tok/docker.io/library/alpine/blobs/{cfg_digest}"), "tok"),
            Some(Found::Blob(_, d)) if d == cfg_digest
        ));
        // Another repository cannot read alpine's blobs.
        assert!(lookup(&store, &format!("/v2/tok/docker.io/library/other/blobs/{layer_digest}"), "tok").is_none());

        // 2. Retagged into a local repository (`docker tag alpine:3.20 mybase:dev`):
        // served by tag and by blob under the new repository.
        store.put_image(pulled.tagged("mybase:dev".into())).unwrap();
        assert!(matches!(
            lookup(&store, "/v2/tok/docker.io/library/mybase/manifests/dev", "tok"),
            Some(Found::Manifest(_, _, d)) if d == pulled_manifest_digest
        ));
        assert!(matches!(
            lookup(&store, &format!("/v2/tok/docker.io/library/mybase/blobs/{layer_digest}"), "tok"),
            Some(Found::Blob(_, d)) if d == layer_digest
        ));

        // 3. Built, loaded or committed here: served by tag until pushed to a registry.
        let local = kiri_image::archive::from_config("localhost:5000/myapp:dev".into(), &cfg_digest, &cfg, layers.clone());
        store.put_image(local).unwrap();
        assert!(matches!(lookup(&store, "/v2/tok/localhost:5000/myapp/manifests/dev", "tok"), Some(Found::Manifest(..))));
        store.set_pushed("localhost:5000/myapp:dev", &cfg_digest, &format!("sha256:{}", "c".repeat(64))).unwrap();
        assert!(lookup(&store, "/v2/tok/localhost:5000/myapp/manifests/dev", "tok").is_none());

        // 4. Digest-pinned multi-arch pull (`docker pull oven/bun:1-alpine@sha256:<index>`):
        // raw index and platform manifest bytes are served verbatim with their
        // upstream Content-Type so BuildKit's SHA-256 verification succeeds (#288, #330).
        let raw_manifest = format!(
            "{{\n  \"schemaVersion\": 2,\n  \"mediaType\": \"application/vnd.docker.distribution.manifest.v2+json\",\n  \"config\": {{\"mediaType\": \"application/vnd.docker.container.image.v1+json\", \"size\": 42, \"digest\": \"{cfg_digest}\"}},\n  \"layers\": [{{\"mediaType\": \"application/vnd.docker.image.rootfs.diff.tar.gzip\", \"size\": {layer_size}, \"digest\": \"{layer_digest}\"}}]\n}}"
        );
        let (raw_man_digest, _) = write_blob(raw_manifest.as_bytes());
        let raw_index = format!(
            "{{\n  \"schemaVersion\": 2,\n  \"mediaType\": \"application/vnd.oci.image.index.v1+json\",\n  \"manifests\": [\n    {{\"mediaType\": \"application/vnd.docker.distribution.manifest.v2+json\", \"size\": {}, \"digest\": \"{raw_man_digest}\", \"platform\": {{\"architecture\": \"amd64\", \"os\": \"linux\"}}}},\n    {{\"mediaType\": \"application/vnd.docker.distribution.manifest.v2+json\", \"size\": 999, \"digest\": \"sha256:{}\", \"platform\": {{\"architecture\": \"arm64\", \"os\": \"linux\"}}}}\n  ]\n}}",
            raw_manifest.len(),
            "e".repeat(64)
        );
        let (raw_idx_digest, _) = write_blob(raw_index.as_bytes());
        let pinned = Image {
            name: format!("oven/bun@{raw_idx_digest}"),
            digest: raw_man_digest.clone(),
            index_digest: Some(raw_idx_digest.clone()),
            ..kiri_image::archive::from_config(format!("oven/bun@{raw_idx_digest}"), &cfg_digest, &cfg, layers)
        };
        store.put_image(pinned).unwrap();
        match lookup(&store, &format!("/v2/tok/docker.io/oven/bun/manifests/{raw_idx_digest}"), "tok") {
            Some(Found::Manifest(b, mt, d)) => {
                assert_eq!(b, raw_index.as_bytes(), "exact upstream index bytes");
                assert_eq!(kiri_image::store::sha256_digest(&b), raw_idx_digest);
                assert_eq!(mt, "application/vnd.oci.image.index.v1+json");
                assert_eq!(d, raw_idx_digest);
            }
            other => panic!("expected raw index manifest, got {other:?}"),
        }
        match lookup(&store, &format!("/v2/tok/docker.io/oven/bun/manifests/{raw_man_digest}"), "tok") {
            Some(Found::Manifest(b, mt, d)) => {
                assert_eq!(b, raw_manifest.as_bytes(), "exact upstream platform manifest bytes");
                assert_eq!(kiri_image::store::sha256_digest(&b), raw_man_digest);
                assert_eq!(mt, "application/vnd.docker.distribution.manifest.v2+json");
                assert_eq!(d, raw_man_digest);
            }
            other => panic!("expected raw platform manifest, got {other:?}"),
        }
        // Unpulled platform digest returns None (404) so BuildKit falls back to the registry.
        assert!(lookup(&store, &format!("/v2/tok/docker.io/oven/bun/manifests/sha256:{}", "e".repeat(64)), "tok").is_none());
        // Cross-repo isolation holds for raw manifests too.
        assert!(lookup(&store, &format!("/v2/tok/docker.io/library/other/manifests/{raw_idx_digest}"), "tok").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An image built here: no registry has it.
    fn made_here() -> Image {
        let config_digest = "sha256:config".to_owned();
        Image {
            name: "myapp:dev".into(),
            digest: config_digest.clone(),
            index_digest: None,
            config_digest,
            layers: Vec::new(),
            size: 0,
            platform: "linux/amd64".into(),
            created: String::new(),
            pulled_at: 0,
            config: kiri_image::RunConfig::default(),
            mirror: None,
        }
    }

    #[test]
    fn token_file_is_private_from_the_start() {
        use std::os::unix::fs::PermissionsExt;
        let p = std::env::temp_dir().join(format!("kiri-mirror-token-{}", std::process::id()));
        // A leftover readable by everyone is replaced, not reused with its mode.
        std::fs::write(&p, "old").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        save_token(&p, "0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "0123456789abcdef0123456789abcdef");
        let _ = std::fs::remove_file(&p);
    }

    /// A registry name from an image reaches buildkitd.toml. A quote, a
    /// backslash or a newline in it must not close the string or inject a
    /// table: buildkitd refuses the whole file, and every build fails until
    /// the image is removed (#746).
    #[test]
    fn names_are_quoted_for_toml() {
        assert_eq!(super::quoted("registry.corp"), "\"registry.corp\"");
        assert_eq!(super::quoted("evil\".com"), "\"evil\\\".com\"");
        assert_eq!(super::quoted("a\\b"), "\"a\\\\b\"");
        assert_eq!(super::quoted("a\nb\rc\td"), "\"a\\nb\\rc\\td\"");
        assert_eq!(super::quoted("a\u{7}b\u{7f}c"), "\"a\\u0007b\\u007Fc\"");
        let mut tables = Vec::new();
        add_mirror(&mut tables, "evil\"].com\n[worker.oci]", "127.0.0.1:47391/tok/evil\"].com\n[worker.oci]".into());
        let toml = super::format_tables(&tables);
        assert_eq!(
            toml,
            "[registry.\"evil\\\"].com\\n[worker.oci]\"]\n  mirrors = [\"127.0.0.1:47391/tok/evil\\\"].com\\n[worker.oci]\"]\n"
        );
        // A name that could have carried one is not a reference any more.
        for bad in ["evil\".com/x:1", "evil\\com/x:1", "host/x:ta\"g", "host/x?y:1", "h#x/y:1"] {
            assert!(kiri_image::Reference::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn load_session_accepts_oci_push_and_cleans_up_aborted_blobs() {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("kiri-mirror-load-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = kiri_image::Store::open(&dir).unwrap();
        let engine = Engine::boot(store).unwrap();

        let send = |req: &[u8]| -> String {
            let mut r = BufReader::new(io::Cursor::new(req));
            let mut w = Vec::new();
            answer_stream(&mut r, &mut w, &engine).unwrap();
            String::from_utf8(w).unwrap()
        };

        // /v2/ ping answers 200.
        assert!(send(b"GET /v2/ HTTP/1.1\r\nHost: d\r\n\r\n").starts_with("HTTP/1.1 200 OK"));

        // Seed an existing base layer to test HEAD dedup.
        let mut bw = engine.store.ingest().unwrap();
        bw.write_all(b"base-layer").unwrap();
        let (base_digest, _) = bw.finish().unwrap();

        let session = LoadSession::new(engine.clone(), vec!["probe-incontainer:latest".into(), "probe-alias:1".into()]);
        let prefix = format!("/v2/load/{}/image", session.nonce);

        // HEAD for existing base blob -> 200; missing blob -> 404.
        let head_ok = send(format!("HEAD {prefix}/blobs/{base_digest} HTTP/1.1\r\nHost: d\r\n\r\n").as_bytes());
        assert!(head_ok.starts_with("HTTP/1.1 200 OK"), "{head_ok}");
        let missing = format!("sha256:{}", "0".repeat(64));
        assert!(send(format!("HEAD {prefix}/blobs/{missing} HTTP/1.1\r\nHost: d\r\n\r\n").as_bytes()).starts_with("HTTP/1.1 404 "));

        // Push a new layer via POST + PATCH (chunked) + PUT with percent-encoded digest.
        let new_layer = b"hello-new-layer";
        let new_digest = kiri_image::store::sha256_digest(new_layer);
        let started = send(format!("POST {prefix}/blobs/uploads/ HTTP/1.1\r\nHost: d\r\nContent-Length: 0\r\n\r\n").as_bytes());
        assert!(started.starts_with("HTTP/1.1 202 Accepted"), "{started}");
        let loc = started.lines().find_map(|l| l.strip_prefix("Location: ")).unwrap().trim().to_owned();
        let patch_req = format!(
            "PATCH {loc} HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nhello-\r\n0\r\n\r\n"
        );
        let patched = send(patch_req.as_bytes());
        assert!(patched.starts_with("HTTP/1.1 202 Accepted"), "{patched}");
        let enc_digest = new_digest.replace(':', "%3A");
        let mut put_req = format!("PUT {loc}?digest={enc_digest} HTTP/1.1\r\nHost: d\r\nContent-Length: 9\r\n\r\n").into_bytes();
        put_req.extend_from_slice(b"new-layer");
        let finished = send(&put_req);
        assert!(finished.starts_with("HTTP/1.1 201 Created"), "{finished}");

        // Push image config via monolithic POST ?digest=...
        let cfg = serde_json::to_vec(&json!({
            "os": "linux",
            "architecture": "amd64",
            "created": "2026-11-24T00:00:00Z",
            "config": {"Cmd": ["sh"]},
            "rootfs": {"type": "layers", "diff_ids": [base_digest, new_digest]}
        }))
        .unwrap();
        let cfg_digest = kiri_image::store::sha256_digest(&cfg);
        let mut cfg_req = format!(
            "POST {prefix}/blobs/uploads/?digest={} HTTP/1.1\r\nHost: d\r\nContent-Length: {}\r\n\r\n",
            cfg_digest.replace(':', "%3A"),
            cfg.len()
        )
        .into_bytes();
        cfg_req.extend_from_slice(&cfg);
        assert!(send(&cfg_req).starts_with("HTTP/1.1 201 Created"));

        // Push child platform manifest by digest, then OCI index with an attestation entry.
        let child = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg_digest, "size": cfg.len()},
            "layers": [
                {"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": base_digest, "size": 10},
                {"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": new_digest, "size": new_layer.len()},
            ]
        }))
        .unwrap();
        let child_digest = kiri_image::store::sha256_digest(&child);
        let mut child_req = format!("PUT {prefix}/manifests/{child_digest} HTTP/1.1\r\nHost: d\r\nContent-Length: {}\r\n\r\n", child.len()).into_bytes();
        child_req.extend_from_slice(&child);
        assert!(send(&child_req).starts_with("HTTP/1.1 201 Created"));

        let index = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": OCI_INDEX,
            "manifests": [
                {"mediaType": OCI_MANIFEST, "digest": child_digest, "size": child.len(), "platform": {"os": "linux", "architecture": "amd64"}},
                {"mediaType": OCI_MANIFEST, "digest": missing, "size": 12, "platform": {"os": "unknown", "architecture": "unknown"}, "annotations": {"vnd.docker.reference.type": "attestation-manifest"}},
            ]
        }))
        .unwrap();
        let mut idx_req = format!("PUT {prefix}/manifests/out HTTP/1.1\r\nHost: d\r\nContent-Length: {}\r\n\r\n", index.len()).into_bytes();
        idx_req.extend_from_slice(&index);
        assert!(send(&idx_req).starts_with("HTTP/1.1 201 Created"));

        assert_eq!(session.committed_digest().as_deref(), Some(cfg_digest.as_str()));
        let img1 = engine.store.find("probe-incontainer:latest").unwrap().expect("tagged image stored");
        let img2 = engine.store.find("probe-alias:1").unwrap().expect("second tag stored");
        assert_eq!(img1.config_digest, cfg_digest);
        assert_eq!(img2.config_digest, cfg_digest);
        assert!(serve_tag(&img1), "locally built image must be served by mirror for subsequent FROM");
        drop(session);

        // Nonce is invalid after drop.
        assert!(send(format!("HEAD {prefix}/blobs/{base_digest} HTTP/1.1\r\nHost: d\r\n\r\n").as_bytes()).starts_with("HTTP/1.1 404 "));

        // Aborted session cleans up its uncommitted uploaded blob on drop.
        let aborted = LoadSession::new(engine.clone(), vec!["never-committed:1".into()]);
        let aprefix = format!("/v2/load/{}/image", aborted.nonce);
        let orphan = b"orphan-uncommitted-blob";
        let orphan_digest = kiri_image::store::sha256_digest(orphan);
        let mut oreq = format!(
            "POST {aprefix}/blobs/uploads/?digest={} HTTP/1.1\r\nHost: d\r\nContent-Length: {}\r\n\r\n",
            orphan_digest.replace(':', "%3A"),
            orphan.len()
        )
        .into_bytes();
        oreq.extend_from_slice(orphan);
        assert!(send(&oreq).starts_with("HTTP/1.1 201 Created"));
        assert!(engine.store.blob_path(&orphan_digest).unwrap().is_file());
        drop(aborted);
        assert!(!engine.store.blob_path(&orphan_digest).unwrap().exists(), "aborted session blob must be removed on drop");

        // Untagged LoadSession stores image under its config_digest, DELETE cancels upload,
        // and invalid digests / path-traversal / conflicting framing are rejected.
        let untagged = LoadSession::new(engine.clone(), Vec::new());
        let uprefix = format!("/v2/load/{}/image", untagged.nonce);
        // Invalid digests and path-traversal attempts on HEAD are rejected with 400 (never touch filesystem).
        assert!(send(format!("HEAD {uprefix}/blobs/sha256:../../etc/passwd HTTP/1.1\r\nHost: d\r\n\r\n").as_bytes()).starts_with("HTTP/1.1 400 "));
        assert!(send(format!("HEAD {uprefix}/blobs/notadigest HTTP/1.1\r\nHost: d\r\n\r\n").as_bytes()).starts_with("HTTP/1.1 400 "));
        // Conflicting Content-Length and Transfer-Encoding is rejected with 400.
        assert!(
            send(format!("POST {uprefix}/blobs/uploads/ HTTP/1.1\r\nHost: d\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n").as_bytes())
                .starts_with("HTTP/1.1 400 ")
        );
        // DELETE cancels an active upload.
        let started2 = send(format!("POST {uprefix}/blobs/uploads/ HTTP/1.1\r\nHost: d\r\nContent-Length: 0\r\n\r\n").as_bytes());
        let loc2 = started2.lines().find_map(|l| l.strip_prefix("Location: ")).unwrap().trim().to_owned();
        assert!(send(format!("DELETE {loc2} HTTP/1.1\r\nHost: d\r\n\r\n").as_bytes()).starts_with("HTTP/1.1 204 "));
        assert!(send(format!("DELETE {loc2} HTTP/1.1\r\nHost: d\r\n\r\n").as_bytes()).starts_with("HTTP/1.1 404 "));
        // Commit single-platform manifest directly into untagged session.
        let mut ureq = format!("PUT {uprefix}/manifests/out HTTP/1.1\r\nHost: d\r\nContent-Length: {}\r\n\r\n", child.len()).into_bytes();
        ureq.extend_from_slice(&child);
        assert!(send(&ureq).starts_with("HTTP/1.1 201 Created"));
        assert_eq!(untagged.committed_digest().as_deref(), Some(cfg_digest.as_str()));
        assert!(engine.store.find(&cfg_digest).unwrap().is_some(), "untagged image stored under config digest");
        drop(untagged);

        drop(engine);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
