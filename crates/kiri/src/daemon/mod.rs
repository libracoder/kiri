//! `kiri daemon`: owns the VM and serves the Docker Engine API on a Unix
//! socket. The docker CLI (context `kiri`), the kiri CLI and the window are
//! all clients of it.

#[cfg(target_os = "linux")]
pub mod access;
mod api;
pub(crate) mod binds;
mod builder;
mod caller;
mod daemon_json;
pub mod dns;
pub mod tls;
pub mod proxy;
pub(crate) mod domains;
pub(crate) mod engine;
mod filters;
mod grpc;
mod health;
mod hostetc;
// A Windows host's roots, for the engine in WSL.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod hostroots;
mod hostopts;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) mod localtime;
mod mirror;
mod http;
mod logfile;
mod names;
mod network;
#[cfg(target_os = "macos")]
pub(crate) mod nfs;
mod ops;
pub(crate) mod ports;
mod pulls;
pub(crate) mod rofs;
mod seccomp;
mod seccomp_names;
mod storage;
pub mod time;
mod top;
mod treecopy;
#[cfg(target_os = "macos")]
mod usb;
mod vmcpu;
mod vmlink;
pub(crate) mod vmnet;
mod volumes;
#[cfg(target_os = "macos")]
mod watch;

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::diag;

/// `~/.kiri` (`~/.kiri-dev` for Kiri Dev): the daemon's state (the CA key, proxy settings). Always under
/// HOME: `KIRI_SOCKET` may point the socket anywhere, but it must not move
/// private state into a directory another user can prepare.
pub fn state_dir() -> io::Result<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| io::Error::other("HOME is not set"))?;
    Ok(home.join(crate::flavor::STATE.get()))
}

static BOUND_SOCKET: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Root on Linux uses `/run/kiri/docker.sock`; other users use `~/.kiri/run/docker.sock`,
/// beside OrbStack's `~/.orbstack/run/docker.sock`.
pub fn socket_path() -> io::Result<PathBuf> {
    if let Some(s) = BOUND_SOCKET.get() {
        return Ok(s.clone());
    }
    // SAFETY: geteuid cannot fail.
    let linux_root = cfg!(target_os = "linux") && unsafe { libc::geteuid() } == 0;
    socket_path_for(std::env::var_os("KIRI_SOCKET").as_deref(), linux_root, std::env::var_os("HOME").as_deref())
}

pub(crate) fn home_socket_path() -> io::Result<PathBuf> {
    home_socket_path_for(std::env::var_os("HOME").as_deref())
}

fn home_socket_path_for(home: Option<&std::ffi::OsStr>) -> io::Result<PathBuf> {
    let home = home.map(PathBuf::from).ok_or_else(|| io::Error::other("HOME is not set"))?;
    Ok(home.join(crate::flavor::STATE.get()).join("run/docker.sock"))
}

fn socket_path_for(override_path: Option<&std::ffi::OsStr>, linux_root: bool, home: Option<&std::ffi::OsStr>) -> io::Result<PathBuf> {
    if let Some(s) = override_path {
        return Ok(PathBuf::from(s));
    }
    if linux_root {
        return Ok(PathBuf::from("/run/kiri/docker.sock"));
    }
    home_socket_path_for(home)
}

/// Raises the soft open-file limit to the hard one, as Go does for dockerd.
/// launchd starts the daemon with 256, and each relayed connection holds
/// four or five descriptors: a LAN client opening ~60 connections to a
/// published port ran it out, and the daemon fell over with its VM.
fn raise_open_files() {
    // SAFETY: rlimit is plain data; get/setrlimit read and write it.
    unsafe {
        let mut lim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return;
        }
        // macOS refuses more than OPEN_MAX for the soft limit.
        let want = if cfg!(target_os = "macos") { lim.rlim_max.min(10240) } else { lim.rlim_max };
        if lim.rlim_cur < want {
            lim.rlim_cur = want;
            libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn ensure_linux_root(euid: u32) -> io::Result<()> {
    if euid != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "on Linux, Kiri runs containers on this machine's kernel and needs root: run `sudo kiri host-access $USER` (or `sudo kiri daemon`)",
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn sudo_uid_from(raw: Option<&std::ffi::OsStr>) -> Option<u32> {
    let uid: u32 = raw?.to_str()?.parse().ok()?;
    (uid != 0 && uid != u32::MAX).then_some(uid)
}

#[cfg(target_os = "linux")]
const RUN_DOCKER_SOCK: &str = "/run/docker.sock";
#[cfg(target_os = "linux")]
const VAR_RUN_DOCKER_SOCK: &str = "/var/run/docker.sock";

#[cfg(any(target_os = "linux", test))]
fn path_occupied(path: &std::path::Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(e) => e.kind() != io::ErrorKind::NotFound,
    }
}

/// Best-effort links `/run/docker.sock -> /run/kiri/docker.sock` when neither
/// `/run/docker.sock` nor `/var/run/docker.sock` exists (no file, socket, or
/// symlink), matching `kiri.service`'s `ExecStartPost`.
#[cfg(any(target_os = "linux", test))]
fn maybe_link_docker_sock(run_link: &std::path::Path, var_run_link: &std::path::Path, target: &std::path::Path) {
    if path_occupied(run_link) || path_occupied(var_run_link) {
        return;
    }
    let _ = std::os::unix::fs::symlink(target, run_link);
}

/// Removes `/run/docker.sock` on clean shutdown only if it still symlinks to
/// `/run/kiri/docker.sock`, matching `kiri.service`'s `ExecStopPost`.
#[cfg(any(target_os = "linux", test))]
fn cleanup_docker_sock_symlink(link: &std::path::Path, target: &std::path::Path) {
    if std::fs::read_link(link).ok().as_deref() == Some(target) {
        let _ = std::fs::remove_file(link);
    }
}

pub fn run(_args: &[String]) -> io::Result<()> {
    // On Linux, fail fast before binding any socket when invoked without root
    // (inside a rootless user namespace such as `unshare -r`, geteuid() == 0).
    // SAFETY: geteuid cannot fail.
    #[cfg(target_os = "linux")]
    ensure_linux_root(unsafe { libc::geteuid() })?;
    let t0 = Instant::now();
    raise_open_files();
    // SIGINT/SIGTERM shut down cleanly: power the guest off, remove the socket.
    // Blocked before anything else starts a thread, so every thread inherits
    // it and one thread waits for them. A thread started before this (the
    // socket group's watcher, on a Linux host) took the signal instead, and
    // the daemon died without a shutdown: the agent was killed with its
    // bridges and nftables table still in place.
    // SAFETY: plain signal-mask calls on a local set.
    let set = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        set
    };
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut socket = socket_path()?;
    #[cfg(target_os = "linux")]
    let mut extra_home_socket = if std::env::var_os("KIRI_SOCKET").is_none() {
        home_socket_path().ok().filter(|p| p != &socket)
    } else {
        None
    };
    if UnixStream::connect(&socket).is_ok() {
        #[cfg(target_os = "linux")]
        if let Some(home_sock) = extra_home_socket.take()
            && UnixStream::connect(&home_sock).is_err()
        {
            socket = home_sock;
        } else {
            // Not an error: launchd (KeepAlive on failure) must not retry it.
            diag::info!("engine already running", socket = socket.display());
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Not an error: launchd (KeepAlive on failure) must not retry it.
            diag::info!("engine already running", socket = socket.display());
            return Ok(());
        }
    }
    let _ = BOUND_SOCKET.set(socket.clone());
    #[cfg(target_os = "linux")]
    if rofs::is_wsl()
        && let Err(e) = localtime::ensure_localtime()
    {
        diag::warn!("could not repair /etc/localtime", error = e);
    }
    if let Some(ref msg) = rofs::check_daemon_storage(None) {
        diag::error!("storage filesystem is read-only", detail = msg);
    }
    let enrich_rofs = |e: io::Error, store_root: Option<&std::path::Path>| -> io::Error {
        if let Some(msg) = rofs::check_daemon_storage(store_root) {
            diag::error!("engine did not start", error = &msg);
            return io::Error::new(e.kind(), msg);
        }
        e
    };
    // On a Linux host the daemon runs as root; `KIRI_SOCKET_GROUP=kiri`
    // lets that group's users in, as the docker group does for dockerd.
    // Without an explicit group, root on Linux uses ordinary 0660 Unix
    // group access (`docker` when present), so containerized SDK clients
    // whose numeric uid has no host account can connect via socket gid.
    let access_group = std::env::var_os("KIRI_SOCKET_GROUP");
    let listener = bind_daemon_socket(&socket, access_group.as_deref()).map_err(|e| enrich_rofs(e, None))?;
    // On a Linux host (and WSL) containers that mount the engine's socket
    // are given this one instead (binds.rs), so the API knows their
    // connections by where they arrive (caller.rs). Made as the daemon's
    // own is, for the same users. A Mac's containers come through the VM's
    // relay (ports::serve_engine_api).
    #[cfg(target_os = "linux")]
    let for_containers = {
        let path = caller::container_socket(&socket);
        let listener = bind_daemon_socket(&path, access_group.as_deref()).map_err(|e| enrich_rofs(e, None))?;
        (listener, path)
    };
    #[cfg(target_os = "linux")]
    let extra_home = extra_home_socket.and_then(|path| {
        if UnixStream::connect(&path).is_ok() {
            return None;
        }
        bind_daemon_socket(&path, access_group.as_deref()).ok().map(|l| (l, path))
    });
    // Each member by name too, so one just added needn't sign in again; and
    // connections are checked against the group when made and while open, so
    // a member removed is let go at once, whatever the list still says.
    #[cfg(target_os = "linux")]
    let gate = match &access_group {
        Some(group) => {
            let mut gated = vec![socket.as_path(), for_containers.1.as_path()];
            if let Some((_, ref home_path)) = extra_home {
                gated.push(home_path.as_path());
            }
            let gate = access::Gate::new(&gated, group)?;
            match gate.grant() {
                Ok(n) => diag::info!("socket access list written", members = n),
                Err(e) => diag::warn!("socket access list not written: new members sign in again first", error = e),
            }
            gate.clone().watch()?;
            Some(gate)
        }
        None => {
            if let Some(uid) = sudo_uid_from(std::env::var_os("SUDO_UID").as_deref()) {
                access::grant_uid(&[socket.as_path(), for_containers.1.as_path()], uid);
            }
            None
        }
    };

    kiri_image::store::set_error_log(|message| diag::error!("image store", detail = message));
    let root = match kiri_image::Store::default_root() {
        Ok(root) => root,
        Err(e) => match kiri_image::storage::unavailable(&e) {
            Some(missing) => {
                return unavailable(
                    &listener,
                    socket,
                    set,
                    missing.to_owned(),
                    #[cfg(target_os = "linux")]
                    &gate,
                );
            }
            None => return Err(e),
        },
    };
    let store = kiri_image::Store::open(&root).map_err(|e| enrich_rofs(e, Some(&root)))?;
    let engine = engine::Engine::boot(store)
        .map_err(|e| enrich_rofs(e, Some(&root)))
        .inspect_err(|e| diag::error!("engine did not start", error = e))?;
    diag::info!("engine ready", version = env!("CARGO_PKG_VERSION"), ms = t0.elapsed().as_millis(), socket = format!("unix://{}", socket.display()));
    // Settings → Storage moved the data and started this daemon on it.
    storage::after_restart(&engine);
    // Crash files from earlier runs, if the person said they may go.
    diag::report::spawn_crash_sender(Duration::from_secs(30), Some(Duration::from_secs(6 * 3600)));
    // Container files in Finder, at ~/Kiri. A Linux host has them on its
    // own disk already.
    #[cfg(target_os = "macos")]
    finder(&engine);
    kiri_image::set_proxy_source(proxy::for_registry);
    // Settings → Registry mirrors: Docker Hub pulls try these first.
    // daemon.json's insecure-registries and registry-mirrors, read again
    // whenever the file changes.
    kiri_image::set_config_source(daemon_json::current);
    // The system's root certificates are read once, here while nothing
    // waits for them, and not by the first pull: asking the macOS keychain
    // about each of its certificates takes a moment (#303).
    let _ = std::thread::Builder::new().name("kiri-tls-roots".into()).spawn(|| {
        // In WSL, the Windows roots kiri-win sent last time (#303).
        #[cfg(target_os = "linux")]
        hostroots::load();
        let _ = kiri_image::roots::trusted();
    });
    // The managed BuildKit stops itself when builds have been idle a while.
    builder::watch(engine.clone());
    // A Kubernetes node the engine restarted gets its kubectl context.
    crate::k8s::sync_at_start();
    // Kiri Dev leaves *.kiri.local and ports 80 and 443 to the installed
    // Kiri, unless given ports of its own (Settings → Domains, or
    // KIRI_HTTP_PORT and KIRI_HTTPS_PORT).
    let routers = !crate::flavor::dev() || domains::own_ports();
    if crate::flavor::dev() {
        if !routers {
            diag::info!(format!("{}: container domains off (ports in Settings → Domains turn them on)", crate::flavor::APP));
        }
    } else if let Err(e) = dns::start() {
        diag::warn!("*.kiri.local off", error = e);
    }
    if routers {
        match domains::start_tls(engine.clone()) {
            Ok(port) => diag::info!("HTTPS for container domains", port = port, trusted = tls::trusted()),
            Err(e) => diag::warn!("HTTPS for container domains off", error = e),
        }
        match domains::start(engine.clone()) {
            Ok(port) => diag::info!(format!(
                "container domains on http://<name>.{}{}",
                if dns::installed() { "kiri.local" } else { "kiri.localhost" },
                if port == 80 { String::new() } else { format!(":{port}") }
            )),
            Err(e) => diag::warn!("container domains off", error = e),
        }
    }

    #[cfg(target_os = "linux")]
    let manage_docker_sock = std::env::var_os("KIRI_SOCKET").is_none() && socket == std::path::Path::new(crate::client::SERVICE_SOCKET);
    #[cfg(target_os = "linux")]
    if manage_docker_sock {
        maybe_link_docker_sock(
            std::path::Path::new(RUN_DOCKER_SOCK),
            std::path::Path::new(VAR_RUN_DOCKER_SOCK),
            std::path::Path::new(crate::client::SERVICE_SOCKET),
        );
    }

    #[cfg(target_os = "linux")]
    let extra_sock = extra_home.as_ref().map(|(_, p)| p.clone());
    #[cfg(not(target_os = "linux"))]
    let extra_sock: Option<PathBuf> = None;
    watch_own_app(
        engine.clone(),
        socket.clone(),
        extra_sock.clone(),
        #[cfg(target_os = "linux")]
        manage_docker_sock,
    );

    init_wsl_sockets(engine.clone());

    let on_signal = engine.clone();
    let sock = socket.clone();
    std::thread::Builder::new().name("kiri-signals".into()).spawn(move || {
        let mut sig = 0;
        // SAFETY: waits on the blocked set; writes the signal number to `sig`.
        unsafe { libc::sigwait(&set, &mut sig) };
        diag::info!("engine shutting down", signal = sig);
        #[cfg(target_os = "macos")]
        nfs::unmount();
        #[cfg(target_os = "linux")]
        if manage_docker_sock {
            cleanup_docker_sock_symlink(std::path::Path::new(RUN_DOCKER_SOCK), std::path::Path::new(crate::client::SERVICE_SOCKET));
        }
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_file(caller::container_socket(&sock));
        if let Some(ref extra) = extra_sock {
            let _ = std::fs::remove_file(extra);
        }
        if let Some(ws) = WSL_SOCKETS.get() {
            ws.remove_socket_files();
        }
        on_signal.shutdown();
        // Give the guest a moment to power off before the VM is released.
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::process::exit(0);
    })?;

    #[cfg(target_os = "linux")]
    {
        if let Some((extra_listener, _)) = extra_home {
            let (engine_extra, gate_extra) = (engine.clone(), gate.clone());
            std::thread::Builder::new().name("kiri-api-home".into()).spawn(move || accept(&extra_listener, &engine_extra, &gate_extra, caller::Caller::Host))?;
        }
        let (engine2, gate2) = (engine.clone(), gate.clone());
        std::thread::Builder::new().name("kiri-api-containers".into()).spawn(move || accept(&for_containers.0, &engine2, &gate2, caller::Caller::Container))?;
        accept(&listener, &engine, &gate, caller::Caller::Host);
    }
    #[cfg(not(target_os = "linux"))]
    accept(&listener, &engine, caller::Caller::Host);
    Ok(())
}

#[cfg(target_os = "linux")]
#[cfg(test)]
fn admit_connection(gate: &Option<std::sync::Arc<access::Gate>>, conn: &UnixStream) -> Result<Option<access::Seat>, ()> {
    admit_connection_for(gate, conn, None, &None)
}

#[cfg(target_os = "linux")]
fn admit_connection_for(
    gate: &Option<std::sync::Arc<access::Gate>>,
    conn: &UnixStream,
    pinned: Option<access::PinnedPeer>,
    container_engine: &Option<std::sync::Arc<engine::Engine>>,
) -> Result<Option<access::Seat>, ()> {
    match gate {
        Some(gate) => {
            let seat = match container_engine {
                Some(eng) => gate.admit_container(conn, pinned, |cg| eng.has_running_container_cgroup(cg)),
                None => gate.admit(conn),
            };
            seat.map(Some).ok_or(())
        }
        None => Ok(None),
    }
}

/// Serves each connection `listener` takes, as `who`'s, on a thread of its own.
fn accept(
    listener: &UnixListener,
    engine: &std::sync::Arc<engine::Engine>,
    #[cfg(target_os = "linux")] gate: &Option<std::sync::Arc<access::Gate>>,
    who: caller::Caller,
) {
    let cap = open_conns_for(&who);
    #[cfg(target_os = "linux")]
    let container_engine = matches!(who, caller::Caller::Container).then(|| engine.clone());
    let engine = engine.clone();
    serve_each_inner(
        listener,
        cap,
        #[cfg(target_os = "linux")]
        gate,
        #[cfg(target_os = "linux")]
        container_engine,
        std::sync::Arc::new(move |conn| {
            let _ = api::serve(conn, engine.clone(), who.clone());
        }),
    );
}

/// Maximum concurrent open client connections from host or WSL callers, kept
/// separate from [`MAX_CONTAINER_OPEN_CONNS`] so a container mounting
/// `/var/run/docker.sock` can never starve host UI `/events`, `docker ps`,
/// `exec`, or `kiri stop`.
const MAX_HOST_OPEN_CONNS: usize = 512;

/// Maximum concurrent open client connections from containers mounting the
/// engine socket (`docker.container.sock` on Linux and the guest vsock relay
/// in `ports::serve_engine_api` on macOS).
const MAX_CONTAINER_OPEN_CONNS: usize = 128;

/// Shared cap on concurrent client connections. Each accepted connection holds
/// a [`ConnPermit`] until its handler exits (or until dropped if thread
/// creation fails), so slots are never leaked.
pub(super) struct ConnCap {
    open: std::sync::atomic::AtomicUsize,
    limit: usize,
    pool: &'static str,
    last_warn: std::sync::Mutex<Option<Instant>>,
}

pub(super) struct ConnPermit(std::sync::Arc<ConnCap>);

impl Drop for ConnPermit {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

impl ConnCap {
    fn new(pool: &'static str, limit: usize) -> Self {
        ConnCap {
            open: std::sync::atomic::AtomicUsize::new(0),
            limit,
            pool,
            last_warn: std::sync::Mutex::new(None),
        }
    }

    fn try_acquire(self: &std::sync::Arc<Self>) -> Option<ConnPermit> {
        self.open
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |n| (n < self.limit).then_some(n + 1),
            )
            .ok()
            .map(|_| ConnPermit(self.clone()))
    }

    fn warn_full(&self) {
        let mut last = self.last_warn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(5)) {
            *last = Some(Instant::now());
            diag::warn!("too many open connections; the new one was not served", pool = self.pool, limit = self.limit);
        }
    }

    #[cfg(test)]
    pub(super) fn open(&self) -> usize {
        self.open.load(std::sync::atomic::Ordering::Acquire)
    }

    #[cfg(test)]
    pub(super) fn for_test(limit: usize) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::new("test", limit))
    }

    #[cfg(test)]
    pub(super) fn try_acquire_for_test(self: &std::sync::Arc<Self>) -> Option<ConnPermit> {
        self.try_acquire()
    }
}

fn host_open_conns() -> &'static std::sync::Arc<ConnCap> {
    static HOST_OPEN_CONNS: std::sync::OnceLock<std::sync::Arc<ConnCap>> = std::sync::OnceLock::new();
    HOST_OPEN_CONNS.get_or_init(|| std::sync::Arc::new(ConnCap::new("host", MAX_HOST_OPEN_CONNS)))
}

fn container_open_conns() -> &'static std::sync::Arc<ConnCap> {
    static CONTAINER_OPEN_CONNS: std::sync::OnceLock<std::sync::Arc<ConnCap>> = std::sync::OnceLock::new();
    CONTAINER_OPEN_CONNS.get_or_init(|| std::sync::Arc::new(ConnCap::new("container", MAX_CONTAINER_OPEN_CONNS)))
}

fn open_conns_for(who: &caller::Caller) -> &'static std::sync::Arc<ConnCap> {
    match who {
        caller::Caller::Container => container_open_conns(),
        caller::Caller::Host | caller::Caller::Wsl(_) => host_open_conns(),
    }
}

fn try_acquire_from(cap: &std::sync::Arc<ConnCap>) -> Option<ConnPermit> {
    let permit = cap.try_acquire();
    if permit.is_none() {
        cap.warn_full();
    }
    permit
}

pub(super) fn try_acquire_host_conn() -> Option<ConnPermit> {
    try_acquire_from(host_open_conns())
}

pub(super) fn try_acquire_container_conn() -> Option<ConnPermit> {
    try_acquire_from(container_open_conns())
}

/// Hands each host connection `listener` takes to `serve`, on a thread of its own.
fn serve_each(
    listener: &UnixListener,
    #[cfg(target_os = "linux")] gate: &Option<std::sync::Arc<access::Gate>>,
    serve: std::sync::Arc<dyn Fn(UnixStream) + Send + Sync>,
) {
    serve_each_with(
        listener,
        host_open_conns(),
        #[cfg(target_os = "linux")]
        gate,
        serve,
    );
}

fn serve_each_with(
    listener: &UnixListener,
    cap: &std::sync::Arc<ConnCap>,
    #[cfg(target_os = "linux")] gate: &Option<std::sync::Arc<access::Gate>>,
    serve: std::sync::Arc<dyn Fn(UnixStream) + Send + Sync>,
) {
    serve_each_inner(
        listener,
        cap,
        #[cfg(target_os = "linux")]
        gate,
        #[cfg(target_os = "linux")]
        None,
        serve,
    );
}

fn serve_each_inner(
    listener: &UnixListener,
    cap: &std::sync::Arc<ConnCap>,
    #[cfg(target_os = "linux")] gate: &Option<std::sync::Arc<access::Gate>>,
    #[cfg(target_os = "linux")] container_engine: Option<std::sync::Arc<engine::Engine>>,
    serve: std::sync::Arc<dyn Fn(UnixStream) + Send + Sync>,
) {
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let Some(permit) = cap.try_acquire() else {
            cap.warn_full();
            drop(conn);
            continue;
        };
        // Capture `/proc/<pid>` credentials + cgroup synchronously at `accept()`
        // before spawning `kiri-api`, preventing short-lived client exit races
        // and PID-reuse TOCTOU (#127).
        #[cfg(target_os = "linux")]
        let pinned = if gate.is_some() && container_engine.is_some() {
            access::PinnedPeer::capture(&conn)
        } else {
            None
        };
        let serve = serve.clone();
        #[cfg(target_os = "linux")]
        let gate = gate.clone();
        #[cfg(target_os = "linux")]
        let container_engine = container_engine.clone();
        let spawned = std::thread::Builder::new().name("kiri-api".into()).spawn(move || {
            let _permit = permit;
            // Checked here, not in the accept loop: a slow user lookup holds up
            // this connection only.
            #[cfg(target_os = "linux")]
            let Ok(_seat) = admit_connection_for(&gate, &conn, pinned, &container_engine) else {
                return;
            };
            serve(conn);
        });
        if let Err(e) = spawned {
            diag::error!("cannot start a connection thread", error = e);
        }
    }
}

/// The data folder chosen in Settings → Storage isn't there (its drive
/// isn't connected): no empty store is made in its place, and the daemon
/// stays up rather than exiting (launchd and systemd would only start it
/// again and again), answering what Settings → Storage needs to say so
/// and offer Retry or Reset to default (storage::serve_unavailable).
fn unavailable(
    listener: &UnixListener,
    socket: PathBuf,
    set: libc::sigset_t,
    missing: PathBuf,
    #[cfg(target_os = "linux")] gate: &Option<std::sync::Arc<access::Gate>>,
) -> io::Result<()> {
    diag::error!("Kiri's data folder isn't available: the engine waits for it, or for Settings → Storage", folder = missing.display());
    std::thread::Builder::new().name("kiri-signals".into()).spawn(move || {
        let mut sig = 0;
        // SAFETY: waits on the blocked set; writes the signal number to `sig`.
        unsafe { libc::sigwait(&set, &mut sig) };
        let _ = std::fs::remove_file(&socket);
        let _ = std::fs::remove_file(caller::container_socket(&socket));
        std::process::exit(0);
    })?;
    serve_each(
        listener,
        #[cfg(target_os = "linux")]
        gate,
        std::sync::Arc::new(move |conn| {
            let _ = storage::serve_unavailable(conn, &missing);
        }),
    );
    Ok(())
}

/// When the app this daemon runs from is deleted (appwatch.rs): docker
/// build handed back (buildwith.rs: what was there before; the choice
/// stays, so the app taken up again takes it again), and the engine stops.
fn watch_own_app(
    engine: std::sync::Arc<engine::Engine>,
    socket: std::path::PathBuf,
    extra_socket: Option<std::path::PathBuf>,
    #[cfg(target_os = "linux")] manage_docker_sock: bool,
) {
    crate::appwatch::watch(move |exe| {
        diag::error!("the app this engine runs from was deleted; stopping and handing docker build back", path = exe.display());
        if let Err(e) = crate::buildwith::places().and_then(|p| p.give_back()) {
            diag::warn!("docker build not handed back", error = e);
        }
        #[cfg(target_os = "macos")]
        nfs::unmount();
        #[cfg(target_os = "linux")]
        if manage_docker_sock {
            cleanup_docker_sock_symlink(std::path::Path::new(RUN_DOCKER_SOCK), std::path::Path::new(crate::client::SERVICE_SOCKET));
        }
        let _ = std::fs::remove_file(&socket);
        let _ = std::fs::remove_file(caller::container_socket(&socket));
        if let Some(ref extra) = extra_socket {
            let _ = std::fs::remove_file(extra);
        }
        engine.shutdown();
        std::thread::sleep(Duration::from_millis(50));
        // 0: launchd restarts the engine on failure only, and there is
        // nothing left to restart.
        std::process::exit(0);
    });
}

/// Serves container files over NFS and mounts them at ~/Kiri.
/// KIRI_NO_FINDER=1 skips the mount.
#[cfg(target_os = "macos")]
fn finder(engine: &std::sync::Arc<engine::Engine>) {
    match nfs::start(engine.clone()) {
        Ok(socket) if std::env::var_os("KIRI_NO_FINDER").is_none() => match nfs::mount(&socket) {
            Ok(dir) => diag::info!("container files in Finder", at = dir.display()),
            Err(e) => diag::warn!("Finder mount failed", error = e, nfs = socket.display()),
        },
        Ok(socket) => diag::info!("container files over NFS", at = socket.display()),
        Err(e) => diag::warn!("container files off", error = e),
    }
}

fn bind_daemon_socket(socket: &std::path::Path, access_group: Option<&std::ffi::OsStr>) -> io::Result<UnixListener> {
    if let Some(dir) = socket.parent() {
        std::fs::create_dir_all(dir)?;
        if dir == std::path::Path::new("/run/kiri") {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
        }
    }
    let _ = std::fs::remove_file(socket); // stale, from a daemon that died
    let _ = std::fs::remove_dir(socket); // empty directory left by a pre-0.2.3 bind mount
    let listener = UnixListener::bind(socket)?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    if let Some(group) = access_group {
        socket_group(socket, group)?;
    } else {
        default_socket_access(socket)?;
    }
    Ok(listener)
}

/// Docker-compatible permissions for a root-run Linux daemon when no explicit
/// `KIRI_SOCKET_GROUP` is configured: mode 0660 (never world-writable), with
/// the `docker` group when present, else `kiri` when present, else root's group.
fn default_socket_access(socket: &std::path::Path) -> io::Result<()> {
    // SAFETY: geteuid cannot fail.
    let linux_root = cfg!(target_os = "linux") && unsafe { libc::geteuid() } == 0;
    default_socket_access_with(socket, linux_root, lookup_group_gid, apply_socket_gid)
}

fn default_socket_access_with(
    socket: &std::path::Path,
    linux_root: bool,
    mut lookup_gid: impl FnMut(&std::ffi::OsStr) -> io::Result<u32>,
    mut apply_gid: impl FnMut(&std::path::Path, Option<u32>) -> io::Result<()>,
) -> io::Result<()> {
    if !linux_root {
        return Ok(());
    }
    let gid = lookup_gid(std::ffi::OsStr::new("docker")).or_else(|_| lookup_gid(std::ffi::OsStr::new("kiri")));
    match gid {
        Ok(gid) => match apply_gid(socket, Some(gid)) {
            Ok(()) => Ok(()),
            // In a single-user namespace where the host's group gid is not
            // mapped, chown returns EINVAL: keep the socket's group at 0660.
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => apply_gid(socket, None),
            Err(e) => Err(e),
        },
        // When `KIRI_SOCKET_GROUP` is unset, `docker` and `kiri` are optional:
        // Alpine / BusyBox `getent group ...` exits 1 (`ErrorKind::Other`) when
        // absent, while glibc exits 2 (`ErrorKind::NotFound`). Keep root's
        // group at 0660 rather than refusing to start the daemon.
        Err(_) => apply_gid(socket, None),
    }
}

fn lookup_group_gid(group: &std::ffi::OsStr) -> io::Result<u32> {
    #[cfg(target_os = "linux")]
    {
        access::group_gid(group)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let name = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(group)).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: getgrnam with a valid C string; the result is read at once.
        unsafe {
            let g = libc::getgrnam(name.as_ptr());
            if g.is_null() {
                return Err(io::Error::new(io::ErrorKind::NotFound, format!("no group {}", group.to_string_lossy())));
            }
            Ok((*g).gr_gid)
        }
    }
}

fn apply_socket_gid(socket: &std::path::Path, gid: Option<u32>) -> io::Result<()> {
    if let Some(gid) = gid {
        std::os::unix::fs::chown(socket, None, Some(gid))?;
    }
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o660))
}

/// Gives `group` read-write access to the socket.
fn socket_group(socket: &std::path::Path, group: &std::ffi::OsStr) -> io::Result<()> {
    let gid = lookup_group_gid(group)?;
    apply_socket_gid(socket, Some(gid))
}

/// One WSL 2 distro enabled for WSL integration: its name and socket group GID.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WslDistroConfig {
    pub name: String,
    pub gid: u32,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct WslConfigFile {
    #[serde(default)]
    distros: Vec<WslDistroConfig>,
}

struct ActiveWslSocket {
    gid: u32,
    dir: PathBuf,
    socket: PathBuf,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Manages per-distro Unix sockets under `/mnt/wsl/kiri/sockets/<NAME>/docker.sock`.
/// Each socket has a `0750` parent directory and a `0660` socket file owned by
/// `0:<gid>`, tagging accepted HTTP requests with `Caller::Wsl("<NAME>")`.
pub struct WslSockets {
    base: PathBuf,
    active: std::sync::Mutex<std::collections::HashMap<String, ActiveWslSocket>>,
    serve: std::sync::Arc<dyn Fn(UnixStream, String) + Send + Sync>,
}

static WSL_SOCKETS: std::sync::OnceLock<WslSockets> = std::sync::OnceLock::new();

fn wsl_base_dir() -> PathBuf {
    PathBuf::from(binds::wsl_kiri_dir())
}

fn init_wsl_sockets(engine: std::sync::Arc<engine::Engine>) {
    let ws = WSL_SOCKETS.get_or_init(|| {
        WslSockets::new(wsl_base_dir(), move |conn, distro| {
            let _ = api::serve(conn, engine.clone(), caller::Caller::Wsl(distro));
        })
    });
    if let Err(e) = ws.load_config() {
        diag::warn!("WSL integration sockets not loaded", error = e);
    }
}

pub fn wsl_report() -> serde_json::Value {
    let distros = WSL_SOCKETS.get().map_or_else(Vec::new, WslSockets::list);
    serde_json::json!({ "distros": distros })
}

pub fn sync_wsl_sockets(distros: &[WslDistroConfig]) -> io::Result<()> {
    let Some(ws) = WSL_SOCKETS.get() else {
        return Err(io::Error::other("WSL socket manager is not initialized"));
    };
    ws.sync(distros)
}

fn chown_gid(path: &std::path::Path, gid: u32) -> io::Result<()> {
    // SAFETY: geteuid only reads this process's effective user ID.
    let uid = if unsafe { libc::geteuid() } == 0 { Some(0) } else { None };
    std::os::unix::fs::chown(path, uid, Some(gid))
}

impl WslSockets {
    pub fn new(base: PathBuf, serve: impl Fn(UnixStream, String) + Send + Sync + 'static) -> Self {
        WslSockets {
            base,
            active: std::sync::Mutex::new(std::collections::HashMap::new()),
            serve: std::sync::Arc::new(serve),
        }
    }

    pub fn load_config(&self) -> io::Result<()> {
        let cfg_path = self.base.join("config.json");
        if !cfg_path.is_file() {
            return Ok(());
        }
        let bytes = std::fs::read(&cfg_path)?;
        let cfg: WslConfigFile = serde_json::from_slice(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid {}: {e}", cfg_path.display())))?;
        self.sync(&cfg.distros)
    }

    pub fn list(&self) -> Vec<WslDistroConfig> {
        let active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<WslDistroConfig> = active
            .iter()
            .map(|(name, a)| WslDistroConfig { name: name.clone(), gid: a.gid })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    pub fn remove_socket_files(&self) {
        let active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        for a in active.values() {
            a.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = std::fs::remove_file(&a.socket);
            let _ = std::fs::remove_dir(&a.dir);
        }
    }

    pub fn sync(&self, distros: &[WslDistroConfig]) -> io::Result<()> {
        for d in distros {
            if !binds::valid_distro_name(&d.name) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid WSL distro name: {}", d.name),
                ));
            }
        }
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let wanted: std::collections::HashMap<&str, u32> = distros.iter().map(|d| (d.name.as_str(), d.gid)).collect();
        let remove_names: Vec<String> = active
            .iter()
            .filter(|(name, a)| wanted.get(name.as_str()) != Some(&a.gid) || !a.socket.exists())
            .map(|(name, _)| name.clone())
            .collect();
        for name in remove_names {
            if let Some(old) = active.remove(&name) {
                old.stop.store(true, std::sync::atomic::Ordering::SeqCst);
                let _ = UnixStream::connect(&old.socket);
                let _ = std::fs::remove_file(&old.socket);
                let _ = std::fs::remove_dir(&old.dir);
            }
        }
        let sockets_dir = self.base.join("sockets");
        if let Ok(entries) = std::fs::read_dir(&sockets_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name_str) = name.to_str() else { continue };
                if !wanted.contains_key(name_str) {
                    let p = entry.path();
                    let _ = std::fs::remove_file(p.join("docker.sock"));
                    let _ = std::fs::remove_dir(&p);
                }
            }
        }
        if !distros.is_empty() {
            let roots_dir = self.base.join("roots");
            for d in [&self.base, &sockets_dir, &roots_dir] {
                std::fs::create_dir_all(d)?;
                std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755))?;
            }
        }
        for d in distros {
            let dir = sockets_dir.join(&d.name);
            let sock = dir.join("docker.sock");
            if active.contains_key(&d.name) {
                chown_gid(&sock, d.gid)?;
                std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o660))?;
                chown_gid(&dir, d.gid)?;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750))?;
                continue;
            }
            std::fs::create_dir_all(&dir)?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            let _ = std::fs::remove_file(&sock);
            let listener = UnixListener::bind(&sock)?;
            std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
            chown_gid(&sock, d.gid)?;
            std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o660))?;
            chown_gid(&dir, d.gid)?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750))?;
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop_loop = stop.clone();
            let serve = self.serve.clone();
            let distro_name = d.name.clone();
            std::thread::Builder::new().name("kiri-api-wsl".into()).spawn(move || {
                for conn in listener.incoming() {
                    if stop_loop.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                    let Ok(conn) = conn else { continue };
                    if stop_loop.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                    let Some(permit) = try_acquire_host_conn() else {
                        drop(conn);
                        continue;
                    };
                    let serve = serve.clone();
                    let distro_name = distro_name.clone();
                    if let Err(e) = std::thread::Builder::new().name("kiri-api".into()).spawn(move || {
                        let _permit = permit;
                        serve(conn, distro_name);
                    }) {
                        diag::error!("cannot start a connection thread", error = e);
                    }
                }
            })?;
            active.insert(
                d.name.clone(),
                ActiveWslSocket {
                    gid: d.gid,
                    dir,
                    socket: sock,
                    stop,
                },
            );
        }
        if self.base.exists() {
            let cfg_path = self.base.join("config.json");
            let tmp_path = self.base.join("config.json.tmp");
            let data = serde_json::to_vec(&WslConfigFile { distros: distros.to_vec() }).unwrap_or_default();
            if std::fs::write(&tmp_path, data).is_ok() {
                let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
                let _ = std::fs::rename(&tmp_path, &cfg_path);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::io::{Read, Write};
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn root_linux_default_socket_and_overrides() {
        assert_eq!(socket_path_for(None, true, Some(OsStr::new("/root"))).unwrap(), PathBuf::from("/run/kiri/docker.sock"));
        assert_eq!(socket_path_for(None, true, None).unwrap(), PathBuf::from("/run/kiri/docker.sock"));
        assert_eq!(
            socket_path_for(Some(OsStr::new("/custom/kiri.sock")), true, Some(OsStr::new("/root"))).unwrap(),
            PathBuf::from("/custom/kiri.sock")
        );
        assert_eq!(
            socket_path_for(None, false, Some(OsStr::new("/home/alice"))).unwrap(),
            PathBuf::from("/home/alice").join(crate::flavor::STATE.get()).join("run/docker.sock")
        );
    }

    #[test]
    fn default_socket_access_uses_0660_never_world_writable_and_selects_docker_group() {
        let dir = std::env::temp_dir().join(format!("kiri-daemon-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("docker.sock");
        let _listener = UnixListener::bind(&sock).unwrap();
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600)).unwrap();

        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;

        // Non-root / macOS default keeps 0600 and is never world-writable.
        default_socket_access_with(&sock, false, |_| unreachable!(), apply_socket_gid).unwrap();
        assert_eq!(mode(&sock), 0o600);
        assert_eq!(mode(&sock) & 0o002, 0, "socket must never be world-writable");

        // Root on Linux with `docker` group present selects `docker` group and 0660 (never 0666).
        // SAFETY: getegid cannot fail.
        let my_gid = unsafe { libc::getegid() };
        let mut applied_gid = None;
        default_socket_access_with(
            &sock,
            true,
            |g| {
                assert_eq!(g, OsStr::new("docker"));
                Ok(my_gid)
            },
            |p, gid| {
                applied_gid = gid;
                apply_socket_gid(p, gid)
            },
        )
        .unwrap();
        assert_eq!(applied_gid, Some(my_gid));
        assert_eq!(mode(&sock), 0o660);
        assert_eq!(mode(&sock) & 0o007, 0, "socket must forbid world access (never 0666)");
        assert_eq!(std::fs::metadata(&sock).unwrap().gid(), my_gid);

        // Root on Linux without `docker` but with `kiri` group selects `kiri` and 0660 (never 0666).
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut looked_up = Vec::new();
        let mut kiri_applied_gid = None;
        default_socket_access_with(
            &sock,
            true,
            |g| {
                looked_up.push(g.to_os_string());
                if g == OsStr::new("kiri") {
                    Ok(my_gid)
                } else {
                    Err(io::Error::new(io::ErrorKind::NotFound, "no group docker"))
                }
            },
            |p, gid| {
                kiri_applied_gid = gid;
                apply_socket_gid(p, gid)
            },
        )
        .unwrap();
        assert_eq!(looked_up, vec![OsStr::new("docker"), OsStr::new("kiri")]);
        assert_eq!(kiri_applied_gid, Some(my_gid));
        assert_eq!(mode(&sock), 0o660);
        assert_eq!(mode(&sock) & 0o007, 0, "socket must forbid world access (never 0666)");

        // Root on Linux without `docker` or `kiri` group keeps existing group and sets 0660 (never 0666).
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut fallback_gid = Some(99999);
        default_socket_access_with(
            &sock,
            true,
            |_| Err(io::Error::new(io::ErrorKind::NotFound, "no group")),
            |p, gid| {
                fallback_gid = gid;
                apply_socket_gid(p, gid)
            },
        )
        .unwrap();
        assert_eq!(fallback_gid, None);
        assert_eq!(mode(&sock), 0o660);
        assert_eq!(mode(&sock) & 0o007, 0, "socket must forbid world access (never 0666)");

        // Unmapped gid in a user namespace (EINVAL) also falls back cleanly to 0660.
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut attempts = Vec::new();
        default_socket_access_with(
            &sock,
            true,
            |_| Ok(999),
            |p, gid| {
                attempts.push(gid);
                if gid.is_some() {
                    return Err(io::Error::from_raw_os_error(libc::EINVAL));
                }
                apply_socket_gid(p, None)
            },
        )
        .unwrap();
        assert_eq!(attempts, vec![Some(999), None]);
        assert_eq!(mode(&sock), 0o660);

        // BusyBox `getent group docker` exits 1 (`ErrorKind::Other`) when absent: must still start at 0660.
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600)).unwrap();
        default_socket_access_with(
            &sock,
            true,
            |_| Err(io::Error::other("getent group docker: exit status: 1")),
            apply_socket_gid,
        )
        .unwrap();
        assert_eq!(mode(&sock), 0o660);

        // Explicit KIRI_SOCKET_GROUP fails closed when the group does not exist.
        assert_eq!(socket_group(&sock, OsStr::new("kiri-no-such-group-127")).unwrap_err().kind(), io::ErrorKind::NotFound);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_authorization_allows_container_uid_when_unmanaged_and_denies_without_gid_or_when_managed() {
        // Container-only numeric UID 54321 must not exist in the host's /etc/passwd.
        #[cfg(target_os = "linux")]
        const PROBE_ID: u32 = 54321;
        let has_host_entry = std::fs::read_to_string("/etc/passwd")
            .unwrap_or_default()
            .lines()
            .any(|l| l.split(':').nth(2) == Some("54321"));
        assert!(!has_host_entry, "54321 must not be a host account");

        let dir = std::env::temp_dir().join(format!("kiri-peer-auth-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sock = dir.join("docker.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        // SAFETY: getegid cannot fail.
        let sock_gid = unsafe { libc::getegid() };
        default_socket_access_with(&sock, true, |_| Ok(sock_gid), apply_socket_gid).unwrap();

        let m = std::fs::metadata(&sock).unwrap();
        let mode = m.permissions().mode() & 0o7777;
        assert_eq!(mode, 0o660);
        // Group rw (0o060) lets a container UID with supplementary `sock_gid` connect;
        // other is 0 (0o007 == 0) so the kernel denies any UID/GID lacking `sock_gid` with EACCES.
        assert_eq!(mode & 0o070, 0o060);
        assert_eq!(mode & 0o007, 0);

        #[cfg(target_os = "linux")]
        {
            let (_client, server) = UnixStream::pair().unwrap();
            // 1. When KIRI_SOCKET_GROUP is unset (`gate` is `None`), a connected peer that
            // passed the kernel's 0660 group check is admitted without requiring an `/etc/passwd` entry.
            assert!(admit_connection(&None, &server).is_ok());

            // 2. When KIRI_SOCKET_GROUP IS explicitly set, managed account-membership check is
            // enforced: container-only numeric `uid=54321` is not a member of that managed group and is DENIED.
            let gate = access::Gate::new(&[sock.as_path()], OsStr::new("root")).unwrap();
            assert!(!gate.allowed_for_test(PROBE_ID).unwrap(), "non-NSS peer must be denied by managed KIRI_SOCKET_GROUP gate");

            // SAFETY: geteuid cannot fail.
            if unsafe { libc::geteuid() } == 0 {
                let try_connect = |with_sock_gid: bool| -> io::ErrorKind {
                    // SAFETY: fork in a test; the child only drops privileges, connects and exits with raw errno.
                    unsafe {
                        let pid = libc::fork();
                        if pid == 0 {
                            let rc = if with_sock_gid {
                                let gids = [sock_gid as libc::gid_t];
                                libc::setgroups(1, gids.as_ptr())
                            } else {
                                libc::setgroups(0, std::ptr::null())
                            };
                            if rc != 0 || libc::setgid(PROBE_ID) != 0 || libc::setuid(PROBE_ID) != 0 {
                                libc::_exit(126);
                            }
                            match UnixStream::connect(&sock) {
                                Ok(_) => libc::_exit(0),
                                Err(e) => libc::_exit(e.raw_os_error().unwrap_or(1).clamp(1, 125)),
                            }
                        }
                        let mut status = 0;
                        libc::waitpid(pid, &mut status, 0);
                        let code = libc::WEXITSTATUS(status);
                        if code == 0 {
                            io::ErrorKind::Other
                        } else {
                            io::Error::from_raw_os_error(code).kind()
                        }
                    }
                };
                // Denied by kernel 0660 when lacking `sock_gid`.
                assert_eq!(try_connect(false), io::ErrorKind::PermissionDenied);
                // Allowed by kernel 0660 when carrying supplementary `sock_gid`, and admitted when KIRI_SOCKET_GROUP is unset.
                assert_eq!(try_connect(true), io::ErrorKind::Other);
                let (accepted, _) = listener.accept().unwrap();
                assert!(admit_connection(&None, &accepted).is_ok());
                // Denied by managed `KIRI_SOCKET_GROUP` gate even after kernel 0660 connect.
                assert!(admit_connection(&Some(gate), &accepted).is_err());
            }
        }
        let _ = listener;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn per_distro_wsl_sockets_have_0660_permissions_and_clean_teardown_on_disable() {
        let base = std::env::temp_dir().join(format!("kiri-wsl-sockets-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        // SAFETY: getegid only reads this process's effective group ID.
        let gid = unsafe { libc::getegid() };
        let ws = WslSockets::new(base.clone(), |mut conn, distro| {
            let _ = conn.write_all(distro.as_bytes());
        });
        ws.sync(&[WslDistroConfig { name: "Ubuntu".into(), gid }]).unwrap();

        let dir = base.join("sockets/Ubuntu");
        let sock = dir.join("docker.sock");
        assert!(sock.exists());
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        let sock_mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o750, "parent directory must be 0750, got {dir_mode:o}");
        assert_eq!(sock_mode, 0o660, "socket must be 0660, got {sock_mode:o}");
        assert_ne!(sock_mode, 0o666, "socket must never be 0666");

        let mut client = UnixStream::connect(&sock).unwrap();
        let mut tagged = String::new();
        client.read_to_string(&mut tagged).unwrap();
        assert_eq!(tagged, "Ubuntu");

        // Disabling removes the socket and its parent directory cleanly.
        ws.sync(&[]).unwrap();
        assert!(!sock.exists(), "socket must be removed when disabled");
        assert!(!dir.exists(), "parent dir must be removed when disabled");

        // Path-traversal distro names are rejected.
        assert!(ws.sync(&[WslDistroConfig { name: "../evil".into(), gid }]).is_err());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn linux_root_check_sudo_uid_and_docker_sock_symlink() {
        // Non-root fails immediately with actionable error; root / rootless userns (euid 0) succeeds.
        assert!(ensure_linux_root(0).is_ok());
        let err = ensure_linux_root(1000).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            err.to_string(),
            "on Linux, Kiri runs containers on this machine's kernel and needs root: run `sudo kiri host-access $USER` (or `sudo kiri daemon`)"
        );

        // SUDO_UID parsing accepts valid non-zero uids only.
        assert_eq!(sudo_uid_from(None), None);
        assert_eq!(sudo_uid_from(Some(OsStr::new(""))), None);
        assert_eq!(sudo_uid_from(Some(OsStr::new("0"))), None);
        assert_eq!(sudo_uid_from(Some(OsStr::new("4294967295"))), None);
        assert_eq!(sudo_uid_from(Some(OsStr::new("abc"))), None);
        assert_eq!(sudo_uid_from(Some(OsStr::new("-1"))), None);
        assert_eq!(sudo_uid_from(Some(OsStr::new("1000"))), Some(1000));

        // /run/docker.sock symlink creation and clean shutdown removal.
        let dir = std::env::temp_dir().join(format!("kiri-docker-sock-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("run/kiri")).unwrap();
        std::fs::create_dir_all(dir.join("var/run")).unwrap();
        let target = dir.join("run/kiri/docker.sock");
        let run_link = dir.join("run/docker.sock");
        let var_run_link = dir.join("var/run/docker.sock");
        std::fs::write(&target, "").unwrap();

        // Creates symlink when neither path is occupied, and removes it when pointing to target.
        maybe_link_docker_sock(&run_link, &var_run_link, &target);
        assert_eq!(std::fs::read_link(&run_link).unwrap(), target);
        cleanup_docker_sock_symlink(&run_link, &target);
        assert!(!path_occupied(&run_link));

        // Does not overwrite an existing /var/run/docker.sock (file, socket, or dangling symlink).
        std::os::unix::fs::symlink("/mnt/wsl/kiri/sockets/Ubuntu/docker.sock", &var_run_link).unwrap();
        maybe_link_docker_sock(&run_link, &var_run_link, &target);
        assert!(!path_occupied(&run_link));
        std::fs::remove_file(&var_run_link).unwrap();

        // Does not overwrite or delete a /run/docker.sock owned by another engine.
        let other = dir.join("other.sock");
        std::os::unix::fs::symlink(&other, &run_link).unwrap();
        maybe_link_docker_sock(&run_link, &var_run_link, &target);
        assert_eq!(std::fs::read_link(&run_link).unwrap(), other);
        cleanup_docker_sock_symlink(&run_link, &target);
        assert_eq!(std::fs::read_link(&run_link).unwrap(), other);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn connection_cap_enforces_limit_and_releases_on_drop() {
        let cap = std::sync::Arc::new(ConnCap::new("test", 2));
        let p1 = cap.try_acquire().expect("first slot");
        let p2 = cap.try_acquire().expect("second slot");
        assert_eq!(cap.open(), 2);
        assert!(cap.try_acquire().is_none(), "third slot must be rejected at cap");
        assert_eq!(cap.open(), 2, "rejected acquire must never exceed limit");

        drop(p1);
        assert_eq!(cap.open(), 1);
        let p3 = cap.try_acquire().expect("slot freed after drop");
        assert_eq!(cap.open(), 2);
        assert!(cap.try_acquire().is_none());

        drop(p2);
        drop(p3);
        assert_eq!(cap.open(), 0);
    }

    #[test]
    fn host_and_container_connection_caps_are_isolated() {
        // Host and WSL callers share the host pool; containers use a separate smaller pool.
        assert!(std::sync::Arc::ptr_eq(open_conns_for(&caller::Caller::Host), host_open_conns()));
        assert!(std::sync::Arc::ptr_eq(open_conns_for(&caller::Caller::Wsl("Ubuntu".into())), host_open_conns()));
        assert!(std::sync::Arc::ptr_eq(open_conns_for(&caller::Caller::Container), container_open_conns()));
        assert!(!std::sync::Arc::ptr_eq(host_open_conns(), container_open_conns()));
        assert_eq!(host_open_conns().limit, MAX_HOST_OPEN_CONNS);
        assert_eq!(container_open_conns().limit, MAX_CONTAINER_OPEN_CONNS);

        // Exhausting every container slot must never starve host or WSL connections.
        let mut container_permits = Vec::with_capacity(MAX_CONTAINER_OPEN_CONNS);
        while let Some(p) = try_acquire_container_conn() {
            container_permits.push(p);
        }
        assert_eq!(container_open_conns().open(), MAX_CONTAINER_OPEN_CONNS);
        assert!(try_acquire_container_conn().is_none(), "container pool must reject once full");

        let host_permit = try_acquire_host_conn().expect("host pool must stay available when container pool is full");
        drop(host_permit);
        drop(container_permits);
        assert_eq!(container_open_conns().open(), 0);
    }

    #[test]
    fn serve_each_enforces_connection_cap_and_reclaims_slots() {
        let dir = std::env::temp_dir().join(format!("kiri-conn-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("docker.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let cap = std::sync::Arc::new(ConnCap::new("test", 2));
        let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
        let cap_srv = cap.clone();
        std::thread::spawn(move || {
            serve_each_with(
                &listener,
                &cap_srv,
                #[cfg(target_os = "linux")]
                &None,
                std::sync::Arc::new(move |mut conn| {
                    let _ = entered_tx.send(());
                    // Wait until the client writes a byte or closes, then reply "ok".
                    let mut b = [0u8; 1];
                    if conn.read(&mut b).is_ok_and(|n| n > 0) {
                        let _ = conn.write_all(b"ok");
                    }
                }),
            );
        });

        let mut c1 = UnixStream::connect(&sock).unwrap();
        let mut c2 = UnixStream::connect(&sock).unwrap();
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(cap.open(), 2);

        // Third concurrent connection is dropped immediately without entering handler.
        let mut c3 = UnixStream::connect(&sock).unwrap();
        c3.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 8];
        match c3.read(&mut buf) {
            Ok(0) => {}
            Err(e) if matches!(e.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe) => {}
            other => panic!("expected immediate close at cap, got {other:?}"),
        }
        assert!(entered_rx.try_recv().is_err(), "capped connection must not invoke handler");
        assert_eq!(cap.open(), 2);

        // Finishing c1 releases its slot so a new connection c4 is served.
        c1.write_all(b"x").unwrap();
        let mut reply = [0u8; 2];
        c1.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"ok");
        drop(c1);

        let deadline = Instant::now() + Duration::from_secs(2);
        while cap.open() >= 2 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(cap.open(), 1, "closing first connection must release its slot");

        let mut c4 = UnixStream::connect(&sock).unwrap();
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        c4.write_all(b"y").unwrap();
        c4.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"ok");
        drop(c4);

        c2.write_all(b"z").unwrap();
        c2.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"ok");
        drop(c2);

        let deadline = Instant::now() + Duration::from_secs(2);
        while cap.open() > 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(cap.open(), 0, "all connection slots must be released");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod hillclimb_bench;
