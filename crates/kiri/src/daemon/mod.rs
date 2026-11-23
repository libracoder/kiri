//! `kiri daemon`: owns the VM and serves the Docker Engine API on a Unix
//! socket. The docker CLI (context `kiri`), the kiri CLI and the window are
//! all clients of it.

#[cfg(target_os = "linux")]
pub mod access;
mod api;
mod binds;
mod builder;
mod caller;
mod daemon_json;
pub mod dns;
pub mod tls;
pub mod proxy;
mod domains;
mod engine;
mod filters;
mod health;
mod hostetc;
mod hostopts;
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
mod seccomp;
mod seccomp_names;
pub mod time;
mod top;
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

pub fn run(_args: &[String]) -> io::Result<()> {
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
    // On a Linux host the daemon runs as root; `KIRI_SOCKET_GROUP=kiri`
    // lets that group's users in, as the docker group does for dockerd.
    // Without an explicit group, root on Linux uses ordinary 0660 Unix
    // group access (`docker` when present), so containerized SDK clients
    // whose numeric uid has no host account can connect via socket gid.
    let access_group = std::env::var_os("KIRI_SOCKET_GROUP");
    let listener = bind_daemon_socket(&socket, access_group.as_deref())?;
    // On a Linux host (and WSL) containers that mount the engine's socket
    // are given this one instead (binds.rs), so the API knows their
    // connections by where they arrive (caller.rs). Made as the daemon's
    // own is, for the same users. A Mac's containers come through the VM's
    // relay (ports::serve_engine_api).
    #[cfg(target_os = "linux")]
    let for_containers = {
        let path = caller::container_socket(&socket);
        let listener = bind_daemon_socket(&path, access_group.as_deref())?;
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
        None => None,
    };

    kiri_image::store::set_error_log(|message| diag::error!("image store", detail = message));
    let store = kiri_image::Store::open(kiri_image::Store::default_root()?)?;
    let engine = engine::Engine::boot(store).inspect_err(|e| diag::error!("engine did not start", error = e))?;
    diag::info!("engine ready", version = env!("CARGO_PKG_VERSION"), ms = t0.elapsed().as_millis(), socket = format!("unix://{}", socket.display()));
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
    let extra_sock = extra_home.as_ref().map(|(_, p)| p.clone());
    #[cfg(not(target_os = "linux"))]
    let extra_sock: Option<PathBuf> = None;
    watch_own_app(engine.clone(), socket.clone(), extra_sock.clone());

    let on_signal = engine.clone();
    let sock = socket.clone();
    std::thread::Builder::new().name("kiri-signals".into()).spawn(move || {
        let mut sig = 0;
        // SAFETY: waits on the blocked set; writes the signal number to `sig`.
        unsafe { libc::sigwait(&set, &mut sig) };
        diag::info!("engine shutting down", signal = sig);
        #[cfg(target_os = "macos")]
        nfs::unmount();
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_file(caller::container_socket(&sock));
        if let Some(ref extra) = extra_sock {
            let _ = std::fs::remove_file(extra);
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
fn admit_connection(gate: &Option<std::sync::Arc<access::Gate>>, conn: &UnixStream) -> Result<Option<access::Seat>, ()> {
    match gate {
        Some(gate) => gate.admit(conn).map(Some).ok_or(()),
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
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let engine = engine.clone();
        #[cfg(target_os = "linux")]
        let gate = gate.clone();
        let spawned = std::thread::Builder::new().name("kiri-api".into()).spawn(move || {
            // Checked here, not in the accept loop: a slow user lookup holds up
            // this connection only.
            #[cfg(target_os = "linux")]
            let Ok(_seat) = admit_connection(&gate, &conn) else {
                return;
            };
            let _ = api::serve(conn, engine, who);
        });
        if let Err(e) = spawned {
            diag::error!("cannot start a connection thread", error = e);
        }
    }
}

/// When the app this daemon runs from is deleted (appwatch.rs): docker
/// build handed back (buildwith.rs: what was there before; the choice
/// stays, so the app taken up again takes it again), and the engine stops.
fn watch_own_app(engine: std::sync::Arc<engine::Engine>, socket: std::path::PathBuf, extra_socket: Option<std::path::PathBuf>) {
    crate::appwatch::watch(move |exe| {
        diag::error!("the app this engine runs from was deleted; stopping and handing docker build back", path = exe.display());
        if let Err(e) = crate::buildwith::places().and_then(|p| p.give_back()) {
            diag::warn!("docker build not handed back", error = e);
        }
        #[cfg(target_os = "macos")]
        nfs::unmount();
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
/// the `docker` group when present on the host.
fn default_socket_access(socket: &std::path::Path) -> io::Result<()> {
    // SAFETY: geteuid cannot fail.
    let linux_root = cfg!(target_os = "linux") && unsafe { libc::geteuid() } == 0;
    default_socket_access_with(socket, linux_root, lookup_group_gid, apply_socket_gid)
}

fn default_socket_access_with(
    socket: &std::path::Path,
    linux_root: bool,
    lookup_gid: impl FnOnce(&std::ffi::OsStr) -> io::Result<u32>,
    apply_gid: impl FnMut(&std::path::Path, Option<u32>) -> io::Result<()>,
) -> io::Result<()> {
    let mut apply_gid = apply_gid;
    if !linux_root {
        return Ok(());
    }
    match lookup_gid(std::ffi::OsStr::new("docker")) {
        Ok(gid) => match apply_gid(socket, Some(gid)) {
            Ok(()) => Ok(()),
            // In a single-user namespace where the host's `docker` gid is not
            // mapped, chown returns EINVAL: keep the socket's group at 0660.
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => apply_gid(socket, None),
            Err(e) => Err(e),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => apply_gid(socket, None),
        Err(e) => Err(e),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
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

        // Root on Linux without a `docker` group keeps existing group and sets 0660 (never 0666).
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut fallback_gid = Some(99999);
        default_socket_access_with(
            &sock,
            true,
            |_| Err(io::Error::new(io::ErrorKind::NotFound, "no group docker")),
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

        // Explicit KIRI_SOCKET_GROUP fails closed when the group does not exist.
        assert_eq!(socket_group(&sock, OsStr::new("kiri-no-such-group-127")).unwrap_err().kind(), io::ErrorKind::NotFound);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_authorization_allows_container_uid_when_unmanaged_and_denies_without_gid_or_when_managed() {
        // Container-only numeric UID 54321 must not exist in the host's /etc/passwd.
        let container_uid: u32 = 54321;
        // SAFETY: getpwuid is read-only here in a single test assertion.
        assert!(unsafe { libc::getpwuid(container_uid) }.is_null(), "uid {container_uid} must not be a host account");

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
            assert!(!gate.allowed_for_test(container_uid).unwrap(), "uid {container_uid} must be denied by managed KIRI_SOCKET_GROUP gate");

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
                            if rc != 0 || libc::setgid(container_uid) != 0 || libc::setuid(container_uid) != 0 {
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
}
