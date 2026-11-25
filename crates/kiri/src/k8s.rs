//! `kiri k8s`: a single-node Kubernetes cluster (k3s) in one privileged
//! Kiri container, as OrbStack and Docker Desktop offer. Its API server is
//! on `127.0.0.1:6443` (or the next free port), its state in the `kiri-k8s` volume, and `kubectl`
//! gets a `kiri` context in its own file (src/kubeconfig.rs), at each start, at the engine's
//! start while the node runs, and by `kiri k8s status`; `delete` takes it out.

use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::json;

use crate::client;
use crate::flavor::CONTEXT;

const IMAGE: (&str, &str) = ("rancher/k3s", "v1.37.1-k3s1");
/// Default k3s image tag shown in Settings → Kubernetes.
pub(crate) const DEFAULT_VERSION: &str = IMAGE.1;
/// The node container; the window reads the cluster through it.
pub(crate) const NAME: &str = "kiri-k8s";
const VOLUME: &str = "kiri-k8s";

fn home() -> io::Result<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| io::Error::other("HOME is not set"))
}

/// The cluster's settings, in `~/.kiri/k8s.json`: whether its API server
/// (and, through the daemon, its LoadBalancer services) answers on every
/// interface rather than 127.0.0.1, extra names for its certificate, its API
/// server port, an optional custom k3s image tag, and optional extra arguments
/// passed to `k3s server`. They are applied when the node container is
/// created, so `kiri k8s set` recreates it; the cluster's state is in the
/// volume and stays.
#[derive(Clone, Default, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Config {
    #[serde(default)]
    pub lan: bool,
    #[serde(default)]
    pub tls_san: Vec<String>,
    /// The Mac port asked for the API server (6443 when unset). When it is
    /// taken the node takes the next free one; `port` in its container says which.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Custom k3s image tag (`rancher/k3s:<version>`), or `None` for `IMAGE.1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Extra arguments appended to `k3s server`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub k3s_args: Vec<String>,
}

/// The API server's port in the node, and the Mac port it is published on by default.
pub(crate) const API_PORT: u16 = 6443;
/// How many ports after the asked-for one a start tries before giving up.
const PORT_TRIES: u16 = 20;
/// Maximum byte length of a single custom `--k3s-arg` value.
const MAX_K3S_ARG_LEN: usize = 512;
/// Maximum number of custom `--k3s-arg` values.
const MAX_K3S_ARGS: usize = 64;
/// Maximum size in bytes of an auto-deployed manifest in `~/.kiri/k8s-manifests`.
const MAX_MANIFEST_BYTES: u64 = 4 << 20;

const USAGE_SET: &str = "usage: kiri k8s set [--lan on|off] [--tls-san NAME,…] [--port N] [--version TAG|default] [--k3s-arg ARG]… [--clear-k3s-args]";
const USAGE_K8S: &str = "usage: kiri k8s start [--use] | stop | status | delete | set [--lan on|off] [--tls-san NAME,…] [--port N] [--version TAG|default] [--k3s-arg ARG]… [--clear-k3s-args]";

impl Config {
    pub(crate) fn api_port(&self) -> u16 {
        self.port.unwrap_or(API_PORT)
    }

    pub(crate) fn version_tag(&self) -> &str {
        self.version.as_deref().filter(|v| valid_version(v)).unwrap_or(IMAGE.1)
    }

    pub(crate) fn image(&self) -> String {
        format!("{}:{}", IMAGE.0, self.version_tag())
    }
}

/// The label that keeps the Mac port a node was made with, for while it's stopped.
const PORT_LABEL: &str = "dev.kiri.k8s.port";

/// The Mac port a node container publishes its API server on: its live
/// binding while it runs, else the one it was made with.
pub(crate) fn bound_port(info: &serde_json::Value) -> Option<u16> {
    let live = &info["NetworkSettings"]["Ports"][format!("{API_PORT}/tcp")][0]["HostPort"];
    let made = &info["Config"]["Labels"][PORT_LABEL];
    live.as_str().or(made.as_str()).and_then(|p| p.parse().ok())
}

/// A port no program on the Mac holds (another Kiri's cluster, Docker
/// Desktop's, a tunnel): nothing answers on it and it can be bound.
fn port_free(port: u16, lan: bool) -> bool {
    let local = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    if std::net::TcpStream::connect_timeout(&local, Duration::from_millis(300)).is_ok() {
        return false;
    }
    let ip = if lan { [0, 0, 0, 0] } else { [127, 0, 0, 1] };
    std::net::TcpListener::bind(std::net::SocketAddr::from((ip, port))).is_ok()
}

/// The asked-for port, or the first free one of the next few.
fn pick_port(want: u16, lan: bool) -> io::Result<u16> {
    let last = want.saturating_add(PORT_TRIES);
    (want..=last).find(|&p| port_free(p, lan)).ok_or_else(|| {
        io::Error::other(format!(
            "ports {want}–{last} are all in use on this Mac, so the cluster's API server has none to take. Choose another in Settings → Kubernetes (or `kiri k8s set --port N`), or stop what holds them, such as another Kiri's Kubernetes"
        ))
    })
}

fn valid_port(p: &str) -> Option<u16> {
    p.parse::<u16>().ok().filter(|&p| p >= 1024)
}

fn config_path() -> io::Result<PathBuf> {
    Ok(home()?.join(crate::flavor::STATE.get()).join("k8s.json"))
}

pub(crate) fn manifests_dir() -> io::Result<PathBuf> {
    Ok(home()?.join(crate::flavor::STATE.get()).join("k8s-manifests"))
}

fn load_config_from(path: &std::path::Path) -> Config {
    std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

/// The settings `kiri k8s set` changes and saves back. Only a missing file is
/// the defaults: one that can't be read or parsed is an error, not replaced.
fn load_config_for_edit(path: &std::path::Path) -> io::Result<Config> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(e) => {
            return Err(io::Error::new(
                e.kind(),
                format!("cannot read {}: {e}", path.display()),
            ));
        }
    };
    serde_json::from_slice(&bytes).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} is not valid Kubernetes settings ({e}); fix or remove it",
                path.display()
            ),
        )
    })
}

fn save_config_to(path: &std::path::Path, cfg: &Config) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec(cfg).map_err(io::Error::other)?)
}

pub(crate) fn config() -> Config {
    config_path().ok().map(|p| load_config_from(&p)).unwrap_or_default()
}

/// An extra certificate name: an IP address or a DNS name (`*.` allowed).
fn valid_san(name: &str) -> bool {
    name.parse::<std::net::IpAddr>().is_ok()
        || (!name.is_empty()
            && name.len() <= 253
            && name.trim_start_matches("*.").split('.').all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')))
}

/// A k3s image tag for `rancher/k3s:<tag>`: 1..=128 ASCII letters, digits,
/// `.`, `_` or `-`, starting with a letter or digit, with no `..`, spaces,
/// slashes, `@`, `:`, or control characters.
pub(crate) fn valid_version(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 128
        && !tag.eq_ignore_ascii_case("default")
        && !tag.contains("..")
        && tag.as_bytes()[0].is_ascii_alphanumeric()
        && tag.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// An extra argument for `k3s server`: non-empty, bounded length, and free of
/// NUL or control characters.
pub(crate) fn valid_k3s_arg(arg: &str) -> bool {
    !arg.trim().is_empty()
        && arg.len() <= MAX_K3S_ARG_LEN
        && !arg.bytes().any(|b| b < 0x20 || b == 0x7f)
        && !arg.chars().any(char::is_control)
}

/// Applies `kiri k8s set` CLI flags to `cfg` without mutating `cfg` on error.
pub(crate) fn apply_set_args(cfg: &mut Config, args: &[String]) -> io::Result<()> {
    let mut next = cfg.clone();
    let mut custom_args: Option<Vec<String>> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let s = a.as_str();
        if s == "--lan" || s.starts_with("--lan=") {
            let Some(raw) = s.strip_prefix("--lan=").or_else(|| it.next().map(String::as_str)) else {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, USAGE_SET));
            };
            next.lan = matches!(raw, "on" | "true" | "1");
        } else if s == "--tls-san" || s.starts_with("--tls-san=") {
            let raw = s.strip_prefix("--tls-san=").or_else(|| it.next().map(String::as_str)).unwrap_or("");
            let list: Vec<String> = raw.split(',').map(|n| n.trim().to_owned()).filter(|n| !n.is_empty()).collect();
            if let Some(bad) = list.iter().find(|n| !valid_san(n)) {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("not an IP address or domain name: {bad}")));
            }
            next.tls_san = list;
        } else if s == "--port" || s.starts_with("--port=") {
            let raw = s.strip_prefix("--port=").or_else(|| it.next().map(String::as_str)).unwrap_or("");
            let Some(port) = valid_port(raw) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("the API server port must be a number from 1024 to 65535, not `{raw}`"),
                ));
            };
            next.port = (port != API_PORT).then_some(port);
        } else if s == "--version" || s.starts_with("--version=") {
            let Some(raw) = s.strip_prefix("--version=").or_else(|| it.next().map(String::as_str)) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--version requires a k3s image tag (for example `v1.31.4-k3s1`, or `default` to reset)",
                ));
            };
            if raw.is_empty() || raw.eq_ignore_ascii_case("default") {
                next.version = None;
            } else if valid_version(raw) {
                next.version = Some(raw.to_owned());
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid k3s version tag `{raw}`: expected a clean image tag such as `v1.31.4-k3s1`, or `default`"),
                ));
            }
        } else if s == "--k3s-arg" || s.starts_with("--k3s-arg=") {
            let Some(raw) = s.strip_prefix("--k3s-arg=").or_else(|| it.next().map(String::as_str)) else {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "--k3s-arg requires a k3s server argument"));
            };
            if !valid_k3s_arg(raw) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid --k3s-arg `{raw}`: arguments must be non-empty, free of control characters, and at most {MAX_K3S_ARG_LEN} bytes"),
                ));
            }
            let list = custom_args.get_or_insert_with(Vec::new);
            if list.len() >= MAX_K3S_ARGS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("too many --k3s-arg values (at most {MAX_K3S_ARGS})"),
                ));
            }
            list.push(raw.to_owned());
        } else if s == "--clear-k3s-args" {
            custom_args = Some(Vec::new());
        } else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, USAGE_SET));
        }
    }
    if let Some(args) = custom_args {
        next.k3s_args = args;
    }
    *cfg = next;
    Ok(())
}

/// Extra kubelet `root-dir` flag passed on Linux ZFS hosts (#607) so kubelet
/// (`nodefs`) lives inside the loopback-ext4 `/var/lib/rancher/k3s` volume
/// alongside containerd (`imagefs`) rather than on the ZFS container rootfs.
pub(crate) const ZFS_KUBELET_ROOT_ARG: &str = "--kubelet-arg=root-dir=/var/lib/rancher/k3s/kubelet";

/// Label recorded on the `kiri-k8s` volume when backed by a loopback ext4 image on ZFS.
const ZFS_BACKING_LABEL: &str = "dev.kiri.k8s.backing";

/// Maximum trailing container log lines included when `kiri-k8s` exits during startup.
const CRASH_LOG_LINES: usize = 15;

/// Whether custom `k3s_args` already specify kubelet's `root-dir`.
pub(crate) fn has_kubelet_root_dir(args: &[String]) -> bool {
    args.iter().filter(|a| valid_k3s_arg(a)).any(|a| {
        let s = a.trim();
        s.contains("root-dir=")
            || s == "root-dir"
            || s == "--root-dir"
            || s.ends_with("=root-dir")
            || s.ends_with("=--root-dir")
    })
}

/// Reads `KiriStorageZfs` from a daemon `/info` response.
pub(crate) fn storage_zfs_from_info(info: &serde_json::Value) -> Option<bool> {
    info["KiriStorageZfs"].as_bool()
}

/// Whether the running daemon's volumes directory sits on ZFS (#607).
fn daemon_storage_zfs() -> bool {
    client::get("/info")
        .ok()
        .and_then(|info| storage_zfs_from_info(&info))
        .unwrap_or_else(|| crate::daemon::rofs::is_daemon_storage_zfs(None))
}

/// Builds the `k3s server` command vector for the node container.
#[cfg(test)]
pub(crate) fn server_cmd(cfg: &Config) -> Vec<String> {
    server_cmd_for(cfg, false)
}

/// Builds the `k3s server` command vector, adding `--kubelet-arg=root-dir=…`
/// on Linux ZFS hosts (#607) unless custom `k3s_args` already configure `root-dir`.
pub(crate) fn server_cmd_for(cfg: &Config, zfs: bool) -> Vec<String> {
    let mut cmd: Vec<String> = [
        "server",
        "--disable",
        "traefik",
        "--tls-san",
        "127.0.0.1",
        "--tls-san",
        "localhost",
        "--write-kubeconfig-mode",
        "644",
    ]
    .map(String::from)
    .to_vec();
    for name in cfg.tls_san.iter().filter(|n| valid_san(n)) {
        cmd.extend(["--tls-san".to_owned(), name.clone()]);
    }
    if zfs && !has_kubelet_root_dir(&cfg.k3s_args) {
        cmd.push(ZFS_KUBELET_ROOT_ARG.to_owned());
    }
    for arg in cfg.k3s_args.iter().filter(|a| valid_k3s_arg(a)) {
        cmd.push(arg.clone());
    }
    cmd
}

/// Formats the cluster's saved settings line printed by `kiri k8s set`.
pub(crate) fn format_settings(cfg: &Config) -> String {
    let port = cfg.api_port();
    let host = if cfg.lan { "every interface" } else { "127.0.0.1" };
    let san = if cfg.tls_san.is_empty() { "none".to_owned() } else { cfg.tls_san.join(", ") };
    let version = match cfg.version.as_deref().filter(|v| valid_version(v)) {
        Some(v) => format!("{v} (custom)"),
        None => format!("{} (default)", IMAGE.1),
    };
    let args = if cfg.k3s_args.is_empty() { "none".to_owned() } else { cfg.k3s_args.join(" ") };
    format!("API server on {host}:{port}; extra certificate names: {san}; k3s version: {version}; extra k3s args: {args}")
}

/// Formats the status summary line printed by `kiri k8s status`.
pub(crate) fn format_status(info: Option<&serde_json::Value>, cfg: &Config) -> String {
    let Some(info) = info else {
        let mut out = format!("Kubernetes: not created (kiri k8s start), k3s {}", cfg.version_tag());
        if !cfg.k3s_args.is_empty() {
            out.push_str(&format!(", k3s args: {}", cfg.k3s_args.join(" ")));
        }
        return out;
    };
    let state = info["State"]["Status"].as_str().unwrap_or("unknown");
    let port = bound_port(info).unwrap_or(API_PORT);
    let want = cfg.api_port();
    let moved = if port != want { format!(" ({want} was in use)") } else { String::new() };
    let version = if state == "running" {
        info["Config"]["Image"]
            .as_str()
            .and_then(|img| img.split_once(':').map(|(_, tag)| tag))
            .unwrap_or_else(|| cfg.version_tag())
    } else {
        cfg.version_tag()
    };
    let mut out = format!("Kubernetes: {state}, k3s {version}, API on 127.0.0.1:{port}{moved}");
    if !cfg.k3s_args.is_empty() {
        out.push_str(&format!(", k3s args: {}", cfg.k3s_args.join(" ")));
    }
    out
}

/// `kiri k8s set [--lan on|off] [--tls-san a,b] [--port N] [--version TAG|default] [--k3s-arg ARG]… [--clear-k3s-args]`:
/// saves the settings and, if the cluster exists and they changed, recreates its node with them.
fn set(args: &[String]) -> io::Result<()> {
    let path = config_path()?;
    let mut cfg = load_config_for_edit(&path)?;
    let before = cfg.clone();
    apply_set_args(&mut cfg, args)?;
    ensure_daemon()?;
    let node = if exists()? { Some(client::get(&format!("/containers/{NAME}/json"))?) } else { None };
    // A port asked for that the node doesn't already hold must be free now.
    let port = cfg.api_port();
    if port != before.api_port() && node.as_ref().and_then(bound_port) != Some(port) && !port_free(port, cfg.lan) {
        return Err(io::Error::other(format!("port {port} is in use on this Mac; choose another")));
    }
    save_config_to(&path, &cfg)?;
    println!("{}", format_settings(&cfg));
    let Some(node) = node else {
        if cfg != before {
            println!("they apply when the cluster next starts");
        }
        return Ok(());
    };
    if cfg == before {
        return Ok(());
    }
    if node["State"]["Running"] != true {
        // A stopped node is made again with them at its next start.
        println!("they apply when the cluster next starts");
        return Ok(());
    }
    println!("recreating the node with them (the cluster's state is kept)…");
    ok(client::request("DELETE", &format!("/containers/{NAME}?force=1"), None))?;
    start(false)
}

/// The label that keeps the settings a node was made with.
const CONFIG_LABEL: &str = "dev.kiri.k8s.config";

/// What of the settings a node is made with, as its label keeps them. The
/// host folders are in it too, so a node made before it had them (or before
/// one existed) is made again at its next start.
#[cfg(test)]
fn made_with(cfg: &Config) -> String {
    made_with_for(cfg, false)
}

fn made_with_for(cfg: &Config, zfs: bool) -> String {
    if !zfs && cfg.version.is_none() && cfg.k3s_args.is_empty() {
        serde_json::to_string(&(cfg.lan, &cfg.tls_san, cfg.api_port(), host_folders())).unwrap_or_default()
    } else if !zfs {
        serde_json::to_string(&(cfg.lan, &cfg.tls_san, cfg.api_port(), host_folders(), cfg.version_tag(), &cfg.k3s_args)).unwrap_or_default()
    } else {
        serde_json::to_string(&(cfg.lan, &cfg.tls_san, cfg.api_port(), host_folders(), cfg.version_tag(), &cfg.k3s_args, "zfs-ext4")).unwrap_or_default()
    }
}

/// The folders of this computer the node sees at their own paths, so a pod's
/// `hostPath` names a file here as it would with k3s on the host itself
/// (Rancher Desktop, k3s): the Mac's /Users and /Volumes, a Linux host's
/// /home, /mnt and /media. Binds are recursive, so what is mounted under
/// them when the node starts comes too.
const HOST_FOLDERS: &[&str] = if cfg!(target_os = "macos") { &["/Users", "/Volumes"] } else { &["/home", "/mnt", "/media"] };

fn host_folders() -> Vec<&'static str> {
    HOST_FOLDERS.iter().copied().filter(|d| std::path::Path::new(d).is_dir()).collect()
}

/// The node's binds: its state, then the host folders.
#[cfg(test)]
fn binds() -> Vec<String> {
    binds_for(false)
}

/// The node's binds for the active storage backend: on ZFS, `:nocopy` skips
/// cloning the container rootfs for initial volume copy-up while `kiri-init`
/// loop-mounts the sparse `ext4.img` onto `/var/lib/kiri/volumes/kiri-k8s/_data`.
pub(crate) fn binds_for(zfs: bool) -> Vec<String> {
    let vol_bind = if zfs {
        format!("{VOLUME}:/var/lib/rancher/k3s:nocopy")
    } else {
        format!("{VOLUME}:/var/lib/rancher/k3s")
    };
    std::iter::once(vol_bind).chain(host_folders().into_iter().map(|d| format!("{d}:{d}"))).collect()
}

/// `POST /volumes/create` body for the `kiri-k8s` volume: keeps `DriverOpts`
/// empty so `kiri-init`'s `volmount::ensure_k8s_ext4` backs `_data` with a
/// sparse loopback `ext4` image when `/var/lib/kiri/volumes` sits on ZFS (#607).
pub(crate) fn volume_create_body(zfs: bool) -> serde_json::Value {
    let labels = if zfs {
        json!({"dev.kiri.k8s": "1", ZFS_BACKING_LABEL: "ext4-loop"})
    } else {
        json!({"dev.kiri.k8s": "1"})
    };
    json!({"Name": VOLUME, "Driver": "local", "Labels": labels})
}

fn ensure_daemon() -> io::Result<()> {
    if client::alive() {
        return Ok(());
    }
    Err(io::Error::other("kiri daemon is not running: open Kiri.app or run `kiri daemon`"))
}

fn ok(r: io::Result<client::Response>) -> io::Result<client::Response> {
    let r = r?;
    if r.ok() { Ok(r) } else { Err(io::Error::other(r.error())) }
}

pub fn run(args: &[String]) -> io::Result<()> {
    let what = args.first().map(String::as_str).unwrap_or("");
    let logged = matches!(what, "start" | "stop" | "delete" | "set");
    // A recreate from the command line (`kiri k8s set`) is attributed to this
    // op, so the node's stop is logged as `k8s set`, not as a memory kill. A
    // child the window started already has its own op (KIRI_OP).
    let _op = (logged && crate::diag::op().is_none()).then(|| crate::diag::enter_op(crate::diag::new_op(&format!("k8s{what}"))));
    if logged {
        crate::diag::info!(format!("Kubernetes {what}"));
    }
    let result = run_inner(args);
    // A failure is logged with the command's error, in main.
    if logged && result.is_ok() {
        crate::diag::info!(format!("Kubernetes {what} done"));
    }
    result
}

fn run_inner(args: &[String]) -> io::Result<()> {
    let flag = |f: &str| args.iter().any(|a| a == f);
    match args.first().map(String::as_str) {
        Some("start") => start(flag("--use")),
        Some("stop") => {
            ensure_daemon()?;
            // Stopped already: Docker's 304, with no body, is done (as Start's is).
            let stopped = client::request("POST", &format!("/containers/{NAME}/stop"), None)?;
            if !stopped.ok() && stopped.status != 304 {
                return Err(io::Error::other(stopped.error()));
            }
            println!("Kubernetes stopped (its state is kept; `kiri k8s start` resumes it)");
            Ok(())
        }
        Some("status") => status(),
        Some("delete") => delete(),
        Some("set") => set(&args[1..]),
        _ => Err(io::Error::other(USAGE_K8S)),
    }
}

fn exists() -> io::Result<bool> {
    Ok(client::request("GET", &format!("/containers/{NAME}/json"), None)?.ok())
}

/// Returns `Some(exit_code)` when `/containers/kiri-k8s/json` shows that the
/// node container is no longer running (`State.Running == false` /
/// `State.Status == "exited"`) or has already crashed and been restarted by its
/// `unless-stopped` policy (`RestartCount > initial_restarts`).
pub(crate) fn node_exit_code(info: &serde_json::Value, initial_restarts: Option<u64>) -> Option<i64> {
    let state = &info["State"];
    let exit_code = state["ExitCode"].as_i64().unwrap_or(1);
    let running = state["Running"].as_bool();
    let status = state["Status"].as_str();
    if running == Some(false) || matches!(status, Some("exited" | "dead" | "created")) {
        return Some(exit_code);
    }
    if let (Some(base), Some(cur)) = (initial_restarts, info["RestartCount"].as_u64())
        && cur > base
    {
        return Some(exit_code);
    }
    None
}

/// Extracts the last `keep` non-empty lines from `/containers/{id}/logs` output,
/// stripping Docker's 8-byte multiplexed stream headers when `!tty`.
pub(crate) fn decode_log_lines(body: &[u8], tty: bool, keep: usize) -> Vec<String> {
    let mut text = Vec::with_capacity(body.len());
    if tty {
        text.extend_from_slice(body);
    } else {
        let mut rest = body;
        while !rest.is_empty() {
            if rest.len() >= 8 && rest[0] <= 2 && rest[1..4] == [0, 0, 0] {
                let len = u32::from_be_bytes([rest[4], rest[5], rest[6], rest[7]]) as usize;
                let end = (8 + len).min(rest.len());
                text.extend_from_slice(&rest[8..end]);
                rest = &rest[end..];
            } else {
                text.extend_from_slice(rest);
                break;
            }
        }
    }
    let decoded = String::from_utf8_lossy(&text);
    let all: Vec<String> = decoded
        .split('\n')
        .map(|l| l.trim_end_matches('\r').to_owned())
        .filter(|l| !l.trim().is_empty())
        .collect();
    all[all.len().saturating_sub(keep)..].to_vec()
}

/// Formats an immediate startup crash error with the exit code and last log lines.
pub(crate) fn format_node_crash_error(exit_code: i64, log_lines: &[String]) -> String {
    let base = format!(
        "the node ({NAME}) exited before becoming ready (exit code {exit_code}); see `docker --context {CONTEXT} logs {NAME}`"
    );
    if log_lines.is_empty() {
        base
    } else {
        format!("{base}:\n  {}", log_lines.join("\n  "))
    }
}

/// Polls until `check_kubectl_ready` succeeds, failing fast with the container's
/// last log lines if `inspect` reports that `kiri-k8s` exited or crash-looped.
pub(crate) fn wait_for_ready_with(
    initial_restarts: Option<u64>,
    timeout: Duration,
    poll_interval: Duration,
    mut inspect: impl FnMut() -> io::Result<serde_json::Value>,
    mut check_kubectl_ready: impl FnMut() -> bool,
    mut fetch_tail_logs: impl FnMut(bool) -> Vec<String>,
    mut on_crash: impl FnMut(),
) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    let mut base_restarts = initial_restarts;
    loop {
        if let Ok(info) = inspect() {
            let base = *base_restarts.get_or_insert_with(|| info["RestartCount"].as_u64().unwrap_or(0));
            if let Some(code) = node_exit_code(&info, Some(base)) {
                let tty = info["Config"]["Tty"].as_bool().unwrap_or(false);
                let lines = fetch_tail_logs(tty);
                on_crash();
                return Err(io::Error::other(format_node_crash_error(code, &lines)));
            }
        }
        if check_kubectl_ready() {
            return Ok(());
        }
        if let Ok(info) = inspect() {
            let base = *base_restarts.get_or_insert_with(|| info["RestartCount"].as_u64().unwrap_or(0));
            if let Some(code) = node_exit_code(&info, Some(base)) {
                let tty = info["Config"]["Tty"].as_bool().unwrap_or(false);
                let lines = fetch_tail_logs(tty);
                on_crash();
                return Err(io::Error::other(format_node_crash_error(code, &lines)));
            }
        }
        if Instant::now() > deadline {
            return Err(io::Error::other(format!(
                "the node was not ready after 3 minutes; see `docker --context {CONTEXT} logs {NAME}`"
            )));
        }
        std::thread::sleep(poll_interval);
    }
}

fn node_tail_logs(tty: bool) -> Vec<String> {
    client::request(
        "GET",
        &format!("/containers/{NAME}/logs?stdout=1&stderr=1&tail={CRASH_LOG_LINES}"),
        None,
    )
    .ok()
    .filter(|r| r.ok())
    .map(|r| decode_log_lines(&r.body, tty, CRASH_LOG_LINES))
    .unwrap_or_default()
}

fn wait_for_ready(initial_restarts: Option<u64>) -> io::Result<()> {
    wait_for_ready_with(
        initial_restarts,
        Duration::from_secs(180),
        Duration::from_secs(1),
        || client::get(&format!("/containers/{NAME}/json")),
        || {
            matches!(
                client::exec(NAME, &["timeout", "-s", "KILL", "20", "kubectl", "get", "nodes", "--no-headers"]),
                Ok((0, out)) if out.split_whitespace().nth(1) == Some("Ready")
            )
        },
        node_tail_logs,
        || {
            let _ = client::request("POST", &format!("/containers/{NAME}/stop"), None);
        },
    )
}

fn start(use_context: bool) -> io::Result<()> {
    ensure_daemon()?;
    let t0 = Instant::now();
    let cfg = config();
    let zfs = daemon_storage_zfs();
    let want = cfg.api_port();
    // A stopped node keeps its port unless something else has taken it since;
    // then it is made again (its state is in the volume) on a free one.
    let mut moved_to = None;
    if exists()? {
        let info = client::get(&format!("/containers/{NAME}/json"))?;
        let made_label = info["Config"]["Labels"][CONFIG_LABEL].as_str();
        let want_made = made_with_for(&cfg, zfs);
        if info["State"]["Running"] != true || (zfs && made_label != Some(want_made.as_str())) {
            // Settings changed while it was stopped (a node from before the label: its port),
            // or a ZFS node made without ext4 loopback + kubelet root-dir support.
            let stale = match made_label {
                Some(made) => made != want_made,
                None => zfs || bound_port(&info) != Some(want),
            };
            if stale {
                println!("applying the changed settings (the cluster's state is kept)…");
                ok(client::request("DELETE", &format!("/containers/{NAME}?force=1"), None))?;
            } else if info["State"]["Running"] != true
                && let Some(held) = bound_port(&info).filter(|&p| !port_free(p, cfg.lan))
            {
                let port = pick_port(want, cfg.lan)?;
                println!("port {held} is in use now; moving the API server to {port}…");
                ok(client::request("DELETE", &format!("/containers/{NAME}?force=1"), None))?;
                moved_to = Some(port);
            }
        }
    }
    if !exists()? {
        let port = match moved_to {
            Some(p) => p,
            None => pick_port(want, cfg.lan)?,
        };
        if port != want {
            println!("port {want} is in use; the API server takes {port}");
        }
        let repo = IMAGE.0;
        let tag = cfg.version_tag();
        println!("pulling {repo}:{tag}…");
        let pulled = ok(client::request("POST", &format!("/images/create?fromImage={repo}&tag={tag}"), None))?;
        if let Some(e) = String::from_utf8_lossy(&pulled.body).lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).find_map(|v| v["error"].as_str().map(str::to_owned)) {
            return Err(io::Error::other(e));
        }
        ok(client::request("POST", "/volumes/create", Some(&volume_create_body(zfs))))?;
        let cmd = server_cmd_for(&cfg, zfs);
        let body = json!({
            "Image": cfg.image(),
            "Cmd": cmd,
            "Hostname": "kiri",
            "Labels": {"dev.kiri.k8s": "1", PORT_LABEL: port.to_string(), CONFIG_LABEL: made_with_for(&cfg, zfs)},
            "ExposedPorts": {"6443/tcp": {}},
            "HostConfig": {
                "Privileged": true,
                "Tmpfs": {"/run": "", "/var/run": ""},
                "Binds": binds_for(zfs),
                "PortBindings": {"6443/tcp": [{"HostIp": if cfg.lan { "0.0.0.0" } else { "127.0.0.1" }, "HostPort": port.to_string()}]},
                "RestartPolicy": {"Name": "unless-stopped"},
            },
        });
        ok(client::request("POST", &format!("/containers/create?name={NAME}"), Some(&body)))?;
    }
    let started = client::request("POST", &format!("/containers/{NAME}/start"), None)?;
    if !started.ok() && started.status != 304 {
        return Err(io::Error::other(started.error()));
    }
    let initial_info = client::get(&format!("/containers/{NAME}/json")).ok();
    let initial_restarts = initial_info.as_ref().and_then(|v| v["RestartCount"].as_u64());
    let mut host_names_written = false;
    if initial_info.as_ref().is_none_or(|v| node_exit_code(v, None).is_none()) {
        // Early, so a new cluster's CoreDNS and user manifests (e.g. a custom CNI) apply right away.
        host_names_written = host_names().unwrap_or_else(|e| {
            if client::get(&format!("/containers/{NAME}/json")).ok().is_none_or(|v| node_exit_code(&v, initial_restarts).is_none()) {
                println!("pods may not resolve host.docker.internal: {e}");
            }
            false
        });
        if let Err(e) = sync_user_manifests()
            && client::get(&format!("/containers/{NAME}/json")).ok().is_none_or(|v| node_exit_code(&v, initial_restarts).is_none())
        {
            println!("user manifests from ~/.kiri/k8s-manifests were not synced: {e}");
        }
    }
    println!("waiting for the node…");
    wait_for_ready(initial_restarts)?;
    if host_names_written {
        if let Err(e) = restart_coredns() {
            println!("pods may not resolve host.docker.internal until CoreDNS restarts: {e}");
        }
    }
    let port = bound_port(&client::get(&format!("/containers/{NAME}/json"))?).unwrap_or(API_PORT);
    kubeconfig(use_context, port)?;
    let moved = if port != want { format!(" ({want} was in use)") } else { String::new() };
    println!("Kubernetes is ready in {:.0} s, API on 127.0.0.1:{port}{moved}: kubectl --context {CONTEXT} get nodes", t0.elapsed().as_secs_f64());
    Ok(())
}

/// k3s' own kubeconfig, from the node.
fn k3s_yaml() -> io::Result<String> {
    let (code, raw) = client::exec(NAME, &["cat", "/etc/rancher/k3s/k3s.yaml"])?;
    if code != 0 || !raw.contains("server:") {
        return Err(io::Error::other("could not read the cluster's kubeconfig"));
    }
    Ok(raw)
}

/// The names every container has in /etc/hosts for the host. A pod's
/// lookups go to CoreDNS, which forwards to the node's resolver, and the
/// node is on the default bridge, which has no embedded DNS: upstream says
/// NXDOMAIN. Docker Desktop's and OrbStack's clusters answer them.
const HOST_NAMES: [&str; 3] = ["host.docker.internal", "host.kiri.internal", "gateway.docker.internal"];
/// Where k3s applies manifests from, at its start and whenever one changes.
/// It is in the cluster's volume, so the file outlives the node container
/// and k3s upgrades (they replace only k3s' own manifests).
const MANIFESTS: &str = "/var/lib/rancher/k3s/server/manifests";
const HOST_MANIFEST: &str = "kiri-host-names.yaml";
/// Isolated subdirectory under k3s's manifests folder for user manifests from
/// `~/.kiri/k8s-manifests`, so syncing user manifests never hides or clobbers
/// k3s's own built-in manifests (`coredns.yaml`, `local-storage.yaml`, etc.)
/// or `kiri-host-names.yaml`.
const USER_MANIFESTS: &str = "/var/lib/rancher/k3s/server/manifests/kiri-user";

/// A safe filename in `~/.kiri/k8s-manifests`: `*.yaml`, `*.yml`, or `*.json`
/// with only ASCII letters, digits, `.`, `_`, or `-`, not starting with `.` or `-`.
pub(crate) fn valid_manifest_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 || name.starts_with('.') || name.starts_with('-') || name.contains("..") {
        return false;
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".yaml") || lower.ends_with(".yml") || lower.ends_with(".json")
}

/// Reads valid manifest files (`*.yaml`, `*.yml`, `*.json`) from `dir`, sorted by filename.
pub(crate) fn collect_user_manifests(dir: &std::path::Path) -> io::Result<Vec<(String, String)>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if !ft.is_file() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !valid_manifest_name(&name) {
            continue;
        }
        if entry.metadata()?.len() > MAX_MANIFEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("manifest `{name}` exceeds {} MiB", MAX_MANIFEST_BYTES >> 20),
            ));
        }
        let body = std::fs::read_to_string(entry.path())?;
        out.push((name, body));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Syncs `~/.kiri/k8s-manifests` into `/var/lib/rancher/k3s/server/manifests/kiri-user`
/// inside the running k3s node container without touching k3s's built-in manifests.
fn sync_user_manifests() -> io::Result<()> {
    let dir = manifests_dir()?;
    let items = collect_user_manifests(&dir)?;
    if items.is_empty() {
        let (code, out) = client::exec(NAME, &["rm", "-rf", USER_MANIFESTS])?;
        if code != 0 {
            return Err(io::Error::other(format!("could not clean {USER_MANIFESTS}: {}", out.trim())));
        }
        return Ok(());
    }
    // Remove any previous user manifests not in the current list, then write changed ones atomically.
    let clean_script = format!(
        "set -e; d={USER_MANIFESTS}; mkdir -p \"$d\"; \
         for f in \"$d\"/*; do [ -e \"$f\" ] || continue; b=$(basename \"$f\"); keep=0; \
         for w in \"$@\"; do [ \"$b\" = \"$w\" ] && keep=1 && break; done; \
         [ \"$keep\" = 1 ] || rm -f \"$f\"; done"
    );
    let mut clean_cmd: Vec<&str> = vec!["sh", "-c", &clean_script, "sh"];
    for (name, _) in &items {
        clean_cmd.push(name.as_str());
    }
    let (code, out) = client::exec(NAME, &clean_cmd)?;
    if code != 0 {
        return Err(io::Error::other(format!("could not prepare {USER_MANIFESTS}: {}", out.trim())));
    }
    let write_script = format!(
        "set -e; d={USER_MANIFESTS}; f=\"$d/$1\"; t=\"$d/.$1.tmp\"; \
         printf '%s' \"$2\" > \"$t\"; \
         if cmp -s \"$t\" \"$f\"; then rm -f \"$t\"; else mv \"$t\" \"$f\"; fi"
    );
    for (name, body) in &items {
        let (code, out) = client::exec(NAME, &["sh", "-c", &write_script, "sh", name.as_str(), body.as_str()])?;
        if code != 0 {
            return Err(io::Error::other(format!("could not write {USER_MANIFESTS}/{name}: {}", out.trim())));
        }
    }
    Ok(())
}

/// k3s' CoreDNS imports `*.server` from the `coredns-custom` ConfigMap as
/// server blocks of their own: one for the host's names answers them with
/// the host's address (A; AAAA has no records), and only them, so
/// everything else resolves as before. A `hosts` block in a `.override`
/// would clash with the NodeHosts one k3s' Corefile already has.
fn host_manifest() -> String {
    let addr = if crate::hostrelay::wsl_host_active() {
        crate::hostrelay::WSL_HOST_ADDR_STR
    } else {
        crate::daemon::ports::HOST_ADDR
    };
    let zones: Vec<String> = HOST_NAMES.iter().map(|n| format!("{n}:53")).collect();
    format!(
        "# Written by Kiri at each `kiri k8s start`: pods resolve the host's names, as containers do.\n\
apiVersion: v1\n\
kind: ConfigMap\n\
metadata:\n\
\x20 name: coredns-custom\n\
\x20 namespace: kube-system\n\
data:\n\
\x20 kiri-host.server: |\n\
\x20   {zones} {{\n\
\x20       hosts {{\n\
\x20           {addr} {names}\n\
\x20       }}\n\
\x20   }}\n",
        zones = zones.join(" "),
        names = HOST_NAMES.join(" "),
    )
}

/// A CoreDNS that was running before the manifest was there doesn't see it
/// (its `reload` watches the Corefile, not what it imports), so once k3s
/// has applied the ConfigMap, CoreDNS is restarted: only when the manifest
/// was just written, so a cluster's first start with it, or a Kiri that
/// changes it.
fn restart_coredns() -> io::Result<()> {
    let script = "k='kubectl -n kube-system'; for i in $(seq 90); do \
         if $k get configmap coredns-custom -o name >/dev/null 2>&1 && $k get deployment coredns -o name >/dev/null 2>&1; then exec $k rollout restart deployment coredns; fi; sleep 1; done; \
         echo 'the coredns-custom ConfigMap was not applied in 90 s'; exit 1";
    let (code, out) = client::exec(NAME, &["timeout", "-s", "KILL", "120", "sh", "-c", script])?;
    if code != 0 {
        return Err(io::Error::other(out.trim().to_owned()));
    }
    Ok(())
}

/// Puts the host-names manifest in the node, unless it is there already as
/// it should be. Whether it was written.
fn host_names() -> io::Result<bool> {
    let script = format!(
        "set -e; d={MANIFESTS}; f=$d/{HOST_MANIFEST}; mkdir -p $d; printf '%s' \"$1\" > $d/.kiri-host-names.tmp; \
         if cmp -s $d/.kiri-host-names.tmp $f; then rm -f $d/.kiri-host-names.tmp; else mv $d/.kiri-host-names.tmp $f; echo written; fi"
    );
    let manifest = host_manifest();
    let (code, out) = client::exec(NAME, &["sh", "-c", &script, "sh", &manifest])?;
    if code != 0 {
        return Err(io::Error::other(format!("could not write {MANIFESTS}/{HOST_MANIFEST}: {}", out.trim())));
    }
    Ok(out.contains("written"))
}

/// The cluster's kubeconfig, renamed to `kiri`, at ~/.kiri/kubeconfig, and
/// its cluster, user and context put into kubectl's file (src/kubeconfig.rs),
/// with no kubectl needed: the app's `kiri k8s start` runs with launchd's
/// PATH, where none is found. Whether kubectl's file changed.
fn kubeconfig(use_context: bool, port: u16) -> io::Result<bool> {
    let ours = crate::kubeconfig::from_k3s(&k3s_yaml()?, CONTEXT.get(), port);
    let own = home()?.join(crate::flavor::STATE.get()).join("kubeconfig");
    std::fs::create_dir_all(own.parent().expect("has a parent"))?;
    std::fs::write(&own, &ours)?;
    std::fs::set_permissions(&own, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    let Some(kube) = crate::kubeconfig::path() else {
        println!("kubeconfig: {} (HOME is not set, so not in ~/.kube/config)", own.display());
        return Ok(false);
    };
    let changed = crate::kubeconfig::install(&kube, &ours, CONTEXT.get(), use_context)?;
    if changed {
        println!("kubectl context `{CONTEXT}` written to {}", kube.display());
    }
    Ok(changed)
}

/// The context of a cluster that is already running, as at the engine's
/// start, which restarts the node without `kiri k8s start`: written once
/// k3s has its kubeconfig (within `wait`), and rewritten if its port or
/// certificate changed. Nothing when there is no running node.
pub(crate) fn sync(wait: Duration) -> io::Result<bool> {
    let r = client::request("GET", &format!("/containers/{NAME}/json"), None)?;
    let initial = r.json();
    if !r.ok() || initial["State"]["Running"] != true {
        return Ok(false);
    }
    let initial_restarts = initial["RestartCount"].as_u64();
    // A cluster made by an older Kiri gets it here too, at the engine's start.
    let host_names_written = host_names().unwrap_or_else(|e| {
        crate::diag::warn!("host names manifest not written", error = e);
        false
    });
    let deadline = Instant::now() + wait;
    while k3s_yaml().is_err() {
        if let Ok(info) = client::get(&format!("/containers/{NAME}/json"))
            && node_exit_code(&info, initial_restarts).is_some()
        {
            return Err(io::Error::other("the node exited before writing its kubeconfig"));
        }
        if Instant::now() > deadline {
            return Err(io::Error::other("the cluster's kubeconfig was not there in time"));
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    if host_names_written {
        if let Err(e) = restart_coredns() {
            crate::diag::warn!("CoreDNS not restarted for the host names", error = e);
        }
    }
    let port = bound_port(&client::get(&format!("/containers/{NAME}/json"))?).unwrap_or(API_PORT);
    kubeconfig(false, port)
}

/// The engine's start: a node it restarts gets its kubectl context, in
/// the background. A daemon running as root (a Linux host's systemd
/// service) has root's home, not the user's, and leaves it to `kiri k8s`.
pub(crate) fn sync_at_start() {
    #[cfg(target_os = "linux")]
    // SAFETY: geteuid cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let _ = std::thread::Builder::new().name("kiri-k8s-context".into()).spawn(|| {
        for _ in 0..50 {
            if client::alive() {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        match sync(Duration::from_secs(180)) {
            Ok(true) => crate::diag::info!(format!("kubectl context `{CONTEXT}` written")),
            Ok(false) => {}
            Err(e) => crate::diag::warn!("kubectl context not written", error = e),
        }
    });
}

/// Takes the cluster's cluster, context and user out of kubectl's file.
pub(crate) fn forget() {
    let Some(kube) = crate::kubeconfig::path() else { return };
    match crate::kubeconfig::uninstall(&kube, CONTEXT.get()) {
        Ok(true) => println!("removed kubectl context `{CONTEXT}` from {}", kube.display()),
        Ok(false) => {}
        Err(e) => println!("could not remove kubectl context `{CONTEXT}` ({e})"),
    }
}

fn status() -> io::Result<()> {
    ensure_daemon()?;
    let cfg = config();
    if !exists()? {
        println!("{}", format_status(None, &cfg));
        return Ok(());
    }
    let info = client::get(&format!("/containers/{NAME}/json"))?;
    let state = info["State"]["Status"].as_str().unwrap_or("unknown").to_owned();
    println!("{}", format_status(Some(&info), &cfg));
    if state == "running" {
        // A context missing or out of date (written by an older Kiri, or not at all) is put right.
        if let Err(e) = sync(Duration::ZERO) {
            println!("kubectl context `{CONTEXT}` not written: {e}");
        }
        if let Ok((_, out)) = client::exec(NAME, &["timeout", "-s", "KILL", "20", "kubectl", "get", "nodes", "-o", "wide"]) {
            print!("{out}");
        }
    }
    Ok(())
}

fn delete() -> io::Result<()> {
    ensure_daemon()?;
    let _ = client::request("DELETE", &format!("/containers/{NAME}?force=1"), None)?;
    // An explicit delete: forced, so a damaged container list (which makes
    // the engine refuse removals it can't vouch for) doesn't keep it; any
    // other refusal is said, not reported as deleted.
    let r = client::request("DELETE", &format!("/volumes/{VOLUME}?force=1"), None)?;
    if !r.ok() && r.status != 404 {
        return Err(io::Error::other(format!("Kubernetes' state (volume {VOLUME}) was not deleted: {}", r.error())));
    }
    let _ = std::fs::remove_file(home()?.join(crate::flavor::STATE.get()).join("kubeconfig"));
    forget();
    println!("Kubernetes deleted, with its state");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn editing_rejects_malformed_settings() {
        let dir = std::env::temp_dir().join(format!("kiri-k8s-edit-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k8s.json");
        let bad = br#"{"lan":true,"port":6445,"tls_san":["#;
        std::fs::write(&path, bad).unwrap();
        let err = super::load_config_for_edit(&path)
            .expect_err("malformed settings must not load as defaults");
        assert!(
            err.to_string().contains(&path.display().to_string()),
            "{err}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), bad);

        // No file yet: the defaults, so a first `kiri k8s set` still saves.
        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            super::load_config_for_edit(&path).unwrap(),
            super::Config::default()
        );

        std::fs::write(
            &path,
            br#"{"lan":true,"port":6445,"tls_san":["k8s.example"]}"#,
        )
        .unwrap();
        let cfg = super::load_config_for_edit(&path).unwrap();
        assert_eq!(
            (cfg.port, cfg.tls_san),
            (Some(6445), vec!["k8s.example".to_owned()])
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_port_comes_from_the_binding_then_the_label() {
        let running = serde_json::json!({"NetworkSettings": {"Ports": {"6443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "6444"}]}}, "Config": {"Labels": {"dev.kiri.k8s.port": "6450"}}});
        assert_eq!(super::bound_port(&running), Some(6444));
        let stopped = serde_json::json!({"NetworkSettings": {"Ports": {}}, "Config": {"Labels": {"dev.kiri.k8s.port": "6450"}}});
        assert_eq!(super::bound_port(&stopped), Some(6450));
        assert_eq!(super::bound_port(&serde_json::json!({})), None);
    }

    #[test]
    fn the_node_sees_the_host_folders_at_their_own_paths() {
        let b = super::binds();
        assert_eq!(b[0], "kiri-k8s:/var/lib/rancher/k3s");
        let home = if cfg!(target_os = "macos") { "/Users" } else { "/home" };
        assert!(b.contains(&format!("{home}:{home}")), "{b:?}");
        // A node made before the folders were bound is made again.
        let old = serde_json::to_string(&(false, Vec::<String>::new(), 6443u16)).unwrap();
        assert_ne!(super::made_with(&super::Config::default()), old);
    }

    #[test]
    fn api_ports_are_unprivileged() {
        assert_eq!(super::valid_port("6444"), Some(6444));
        for bad in ["80", "1023", "65536", "", "x", "-1"] {
            assert_eq!(super::valid_port(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_busy_port_moves_the_api_to_the_next_free_one() {
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = held.local_addr().unwrap().port();
        assert!(!super::port_free(port, false));
        let got = super::pick_port(port, false).unwrap();
        assert!(got > port && got <= port + super::PORT_TRIES, "{got}");
    }

    #[test]
    fn pods_resolve_the_host_names_in_a_server_block_of_their_own() {
        let m = super::host_manifest();
        assert!(m.contains("\n  name: coredns-custom\n  namespace: kube-system\n"), "{m}");
        assert!(m.contains("\n  kiri-host.server: |\n    host.docker.internal:53 host.kiri.internal:53 gateway.docker.internal:53 {\n"), "{m}");
        assert!(m.contains(&format!("\n            {} host.docker.internal host.kiri.internal gateway.docker.internal\n", crate::daemon::ports::HOST_ADDR)), "{m}");
        // No `fallthrough`: the block is for these names only, and nothing else reaches it.
        assert!(!m.contains("fallthrough") && !m.contains('\t'), "{m}");
    }

    #[test]
    fn certificate_names_are_addresses_or_domains() {
        for ok in ["192.168.1.20", "::1", "my-mac.local", "*.example.com", "k8s"] {
            assert!(super::valid_san(ok), "{ok}");
        }
        for bad in ["", "a b", "-x.com", "a..b", "x/y", "--flag"] {
            assert!(!super::valid_san(bad), "{bad}");
        }
    }

    #[test]
    fn k3s_version_tags_are_strictly_validated() {
        for ok in ["v1.31.4-k3s1", "v1.21.14-k3s1", "v1.37.1-k3s1", "v1.31.4-rc1-k3s1", "1.31.4-k3s1", "v1.30.0_k3s1"] {
            assert!(super::valid_version(ok), "{ok}");
        }
        let too_long = format!("v{}", "1".repeat(128));
        for bad in [
            "",
            "default",
            "DEFAULT",
            "v1.31.4 k3s1",
            " v1.31.4-k3s1",
            "v1.31.4-k3s1 ",
            "v1.31.4/k3s1",
            "rancher/k3s:v1.31.4-k3s1",
            "v1.31.4:k3s1",
            "v1.31.4@sha256:1234",
            "v1.31.4?tag=evil",
            "v1.31.4&fromImage=evil",
            "v1.31.4#frag",
            "-v1.31.4-k3s1",
            ".v1.31.4-k3s1",
            "_v1.31.4-k3s1",
            "v1..31-k3s1",
            "v1.31.4\n",
            "v1.31.4\0",
            "v1.31.4\x1b[31m",
            too_long.as_str(),
        ] {
            assert!(!super::valid_version(bad), "{bad:?}");
        }
    }

    #[test]
    fn k3s_server_args_reject_empty_control_and_overlong_values() {
        for ok in [
            "--flannel-backend=none",
            "--disable=traefik",
            "--disable-network-policy",
            "--cluster-cidr=10.42.0.0/16",
            "--kube-apiserver-arg=enable-admission-plugins=NodeRestriction",
        ] {
            assert!(super::valid_k3s_arg(ok), "{ok}");
        }
        let max_ok = format!("--{}", "a".repeat(super::MAX_K3S_ARG_LEN - 2));
        assert!(super::valid_k3s_arg(&max_ok));
        let too_long = format!("--{}", "a".repeat(super::MAX_K3S_ARG_LEN - 1));
        for bad in ["", "   ", "\t", "--arg\0evil", "--arg\nevil", "--arg\revil", "--arg\tevil", "--arg\x7f", "--arg\x1b[31m", too_long.as_str()] {
            assert!(!super::valid_k3s_arg(bad), "{bad:?}");
        }
    }

    #[test]
    fn set_parses_persists_resets_and_builds_k3s_server_command() {
        let s = |items: &[&str]| items.iter().map(|x| (*x).to_owned()).collect::<Vec<String>>();
        let mut cfg = super::Config::default();
        assert_eq!(cfg.version_tag(), super::IMAGE.1);
        assert_eq!(cfg.image(), format!("rancher/k3s:{}", super::IMAGE.1));

        // Configure custom version and repeatable --k3s-arg flags.
        super::apply_set_args(
            &mut cfg,
            &s(&[
                "--version",
                "v1.31.4-k3s1",
                "--k3s-arg",
                "--flannel-backend=none",
                "--k3s-arg",
                "--disable-network-policy",
                "--tls-san",
                "192.168.1.20",
                "--port",
                "6445",
                "--lan",
                "on",
            ]),
        )
        .unwrap();
        assert_eq!(cfg.version.as_deref(), Some("v1.31.4-k3s1"));
        assert_eq!(cfg.version_tag(), "v1.31.4-k3s1");
        assert_eq!(cfg.image(), "rancher/k3s:v1.31.4-k3s1");
        assert_eq!(cfg.k3s_args, vec!["--flannel-backend=none", "--disable-network-policy"]);
        assert!(cfg.lan);
        assert_eq!(cfg.api_port(), 6445);

        let cmd = super::server_cmd(&cfg);
        assert_eq!(
            cmd,
            vec![
                "server",
                "--disable",
                "traefik",
                "--tls-san",
                "127.0.0.1",
                "--tls-san",
                "localhost",
                "--write-kubeconfig-mode",
                "644",
                "--tls-san",
                "192.168.1.20",
                "--flannel-backend=none",
                "--disable-network-policy",
            ]
        );
        assert_ne!(super::made_with(&cfg), super::made_with(&super::Config::default()));

        // Persistence round-trip through k8s.json.
        let dir = std::env::temp_dir().join(format!("kiri-k8s-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("k8s.json");
        super::save_config_to(&path, &cfg).unwrap();
        let loaded = super::load_config_from(&path);
        assert_eq!(loaded, cfg);

        // Updating another flag preserves version and k3s_args.
        let mut updated = loaded;
        super::apply_set_args(&mut updated, &s(&["--lan", "off"])).unwrap();
        assert!(!updated.lan);
        assert_eq!(updated.version.as_deref(), Some("v1.31.4-k3s1"));
        assert_eq!(updated.k3s_args, vec!["--flannel-backend=none", "--disable-network-policy"]);

        // Invalid input does not partially mutate config.
        let snapshot = updated.clone();
        assert!(super::apply_set_args(&mut updated, &s(&["--version", "v1.31.4-k3s1", "--k3s-arg", ""])).is_err());
        assert_eq!(updated, snapshot);
        assert!(super::apply_set_args(&mut updated, &s(&["--version", "bad/tag"])).is_err());
        assert!(super::apply_set_args(&mut updated, &s(&["--version"])).is_err());
        assert!(super::apply_set_args(&mut updated, &s(&["--k3s-arg"])).is_err());

        // Exceeding MAX_K3S_ARGS is rejected.
        let mut many = Vec::new();
        for i in 0..=super::MAX_K3S_ARGS {
            many.push("--k3s-arg".to_owned());
            many.push(format!("--arg-{i}"));
        }
        assert!(super::apply_set_args(&mut updated, &many).is_err());

        // Reset version with "default" and "", and clear custom k3s args with --clear-k3s-args.
        super::apply_set_args(&mut updated, &s(&["--version", "default", "--clear-k3s-args"])).unwrap();
        assert_eq!(updated.version, None);
        assert_eq!(updated.version_tag(), super::IMAGE.1);
        assert!(updated.k3s_args.is_empty());

        super::apply_set_args(&mut updated, &s(&["--version=v1.30.2-k3s1", "--k3s-arg=--disable=servicelb"])).unwrap();
        assert_eq!(updated.version.as_deref(), Some("v1.30.2-k3s1"));
        assert_eq!(updated.k3s_args, vec!["--disable=servicelb"]);

        super::apply_set_args(&mut updated, &s(&["--version", ""])).unwrap();
        assert_eq!(updated.version, None);

        super::apply_set_args(&mut updated, &s(&["--version=v1.30.2-k3s1"])).unwrap();
        super::apply_set_args(&mut updated, &s(&["--version="])).unwrap();
        assert_eq!(updated.version, None);

        super::save_config_to(&path, &super::Config::default()).unwrap();
        let raw_json = std::fs::read_to_string(&path).unwrap();
        assert!(!raw_json.contains("version") && !raw_json.contains("k3s_args"), "{raw_json}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn formats_settings_and_status_with_version_and_k3s_args() {
        let mut cfg = super::Config::default();
        assert_eq!(
            super::format_settings(&cfg),
            format!("API server on 127.0.0.1:6443; extra certificate names: none; k3s version: {} (default); extra k3s args: none", super::IMAGE.1)
        );
        assert_eq!(
            super::format_status(None, &cfg),
            format!("Kubernetes: not created (kiri k8s start), k3s {}", super::IMAGE.1)
        );

        cfg.version = Some("v1.31.4-k3s1".into());
        cfg.k3s_args = vec!["--flannel-backend=none".into(), "--disable=traefik".into()];
        assert_eq!(
            super::format_settings(&cfg),
            "API server on 127.0.0.1:6443; extra certificate names: none; k3s version: v1.31.4-k3s1 (custom); extra k3s args: --flannel-backend=none --disable=traefik"
        );
        let running = serde_json::json!({
            "State": {"Status": "running"},
            "Config": {"Image": "rancher/k3s:v1.31.4-k3s1", "Labels": {"dev.kiri.k8s.port": "6443"}},
            "NetworkSettings": {"Ports": {"6443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "6443"}]}}
        });
        assert_eq!(
            super::format_status(Some(&running), &cfg),
            "Kubernetes: running, k3s v1.31.4-k3s1, API on 127.0.0.1:6443, k3s args: --flannel-backend=none --disable=traefik"
        );
    }

    #[test]
    fn collects_user_manifests_without_clobbering_builtin_manifests() {
        assert_eq!(super::USER_MANIFESTS, "/var/lib/rancher/k3s/server/manifests/kiri-user");
        assert_ne!(super::USER_MANIFESTS, super::MANIFESTS);
        for ok in ["cilium.yaml", "01-cni.yml", " policy_v1.json".trim()] {
            assert!(super::valid_manifest_name(ok), "{ok}");
        }
        for bad in ["", ".hidden.yaml", "-flag.yaml", "../evil.yaml", "a/b.yaml", "notes.txt", "a b.yaml"] {
            assert!(!super::valid_manifest_name(bad), "{bad}");
        }

        let dir = std::env::temp_dir().join(format!("kiri-k8s-manifests-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(super::collect_user_manifests(&dir).unwrap(), Vec::<(String, String)>::new());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("b-app.yml"), "kind: Service\n").unwrap();
        std::fs::write(dir.join("a-cilium.yaml"), "kind: DaemonSet\n").unwrap();
        std::fs::write(dir.join(".ignored.yaml"), "ignored\n").unwrap();
        std::fs::write(dir.join("README.md"), "ignored\n").unwrap();

        let items = super::collect_user_manifests(&dir).unwrap();
        assert_eq!(
            items,
            vec![
                ("a-cilium.yaml".to_owned(), "kind: DaemonSet\n".to_owned()),
                ("b-app.yml".to_owned(), "kind: Service\n".to_owned()),
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn zfs_mode_wires_kubelet_root_dir_and_loopback_ext4_volume_options() {
        // /info KiriStorageZfs parsing.
        assert_eq!(super::storage_zfs_from_info(&serde_json::json!({"KiriStorageZfs": true})), Some(true));
        assert_eq!(super::storage_zfs_from_info(&serde_json::json!({"KiriStorageZfs": false})), Some(false));
        assert_eq!(super::storage_zfs_from_info(&serde_json::json!({})), None);

        // Volume create payload keeps DriverOpts empty (so kiri-init's volmount::ensure_k8s_ext4
        // runs on /var/lib/kiri/volumes/kiri-k8s/_data) and marks ZFS loopback backing in Labels.
        let std_vol = super::volume_create_body(false);
        assert_eq!(std_vol["Name"], "kiri-k8s");
        assert_eq!(std_vol["Driver"], "local");
        assert!(std_vol.get("DriverOpts").is_none());
        assert!(std_vol["Labels"].get(super::ZFS_BACKING_LABEL).is_none());

        let zfs_vol = super::volume_create_body(true);
        assert_eq!(zfs_vol["Name"], "kiri-k8s");
        assert_eq!(zfs_vol["Driver"], "local");
        assert!(zfs_vol.get("DriverOpts").is_none());
        assert_eq!(zfs_vol["Labels"][super::ZFS_BACKING_LABEL], "ext4-loop");

        // Binds use :nocopy on ZFS and plain volume bind otherwise.
        assert_eq!(super::binds_for(false)[0], "kiri-k8s:/var/lib/rancher/k3s");
        assert_eq!(super::binds_for(true)[0], "kiri-k8s:/var/lib/rancher/k3s:nocopy");

        // Default ZFS server_cmd adds --kubelet-arg=root-dir=/var/lib/rancher/k3s/kubelet
        // so kubelet (nodefs) sits on the ext4 loop device instead of ZFS rootfs (#607).
        let mut cfg = super::Config::default();
        assert!(!super::server_cmd_for(&cfg, false).contains(&super::ZFS_KUBELET_ROOT_ARG.to_owned()));
        let zfs_cmd = super::server_cmd_for(&cfg, true);
        assert!(zfs_cmd.contains(&super::ZFS_KUBELET_ROOT_ARG.to_owned()), "{zfs_cmd:?}");

        // Custom user args come after ZFS kubelet root-dir when they don't set root-dir.
        cfg.k3s_args = vec!["--flannel-backend=none".into()];
        let zfs_with_extra = super::server_cmd_for(&cfg, true);
        let root_pos = zfs_with_extra.iter().position(|a| a == super::ZFS_KUBELET_ROOT_ARG).unwrap();
        let extra_pos = zfs_with_extra.iter().position(|a| a == "--flannel-backend=none").unwrap();
        assert!(root_pos < extra_pos, "{zfs_with_extra:?}");

        // User-supplied root-dir in k3s_args is respected and not duplicated.
        for user_args in [
            vec!["--kubelet-arg=root-dir=/custom/kubelet".to_owned()],
            vec!["--kubelet-arg=--root-dir=/custom/kubelet".to_owned()],
            vec!["--kubelet-arg".to_owned(), "root-dir=/custom/kubelet".to_owned()],
            vec!["--kubelet-arg=root-dir".to_owned(), "/custom/kubelet".to_owned()],
        ] {
            cfg.k3s_args = user_args.clone();
            assert!(super::has_kubelet_root_dir(&cfg.k3s_args), "{user_args:?}");
            let cmd = super::server_cmd_for(&cfg, true);
            assert!(!cmd.contains(&super::ZFS_KUBELET_ROOT_ARG.to_owned()), "{cmd:?}");
        }

        // made_with_for distinguishes ZFS from non-ZFS so pre-fix ZFS nodes are recreated,
        // while keeping non-ZFS made_with identical.
        let plain = super::Config::default();
        assert_eq!(super::made_with(&plain), super::made_with_for(&plain, false));
        assert_ne!(super::made_with_for(&plain, true), super::made_with_for(&plain, false));
    }

    #[test]
    fn readiness_wait_fails_fast_when_container_exits_or_crash_loops() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::{Duration, Instant};

        fn docker_frame(stream: u8, line: &str) -> Vec<u8> {
            let mut out = vec![stream, 0, 0, 0];
            out.extend_from_slice(&(line.len() as u32).to_be_bytes());
            out.extend_from_slice(line.as_bytes());
            out
        }

        // Multiplexed Docker log decoding + tail truncation.
        let mut raw_logs = docker_frame(1, "time=\"2026-11-24T17:00:00Z\" level=info msg=\"Starting k3s\"\n");
        raw_logs.extend(docker_frame(
            2,
            "F1124 17:00:01.123456 1 server.go:123] Failed to start ContainerManager: cannot find filesystem info for device \"rpool/ROOT/ubuntu\"\r\n\n",
        ));
        let decoded = super::decode_log_lines(&raw_logs, false, 15);
        assert_eq!(decoded.len(), 2);
        assert!(decoded[1].contains("cannot find filesystem info for device \"rpool/ROOT/ubuntu\""));
        assert_eq!(super::decode_log_lines(&raw_logs, false, 1), vec![decoded[1].clone()]);
        assert_eq!(super::decode_log_lines(b"tty line 1\r\ntty line 2\n", true, 5), vec!["tty line 1", "tty line 2"]);

        // 1) Immediate container exit (State.Running == false, State.Status == "exited") fails fast (< 500ms, not 180s).
        let crashed_stops = AtomicUsize::new(0);
        let t0 = Instant::now();
        let err = super::wait_for_ready_with(
            Some(0),
            Duration::from_secs(180),
            Duration::from_secs(5),
            || {
                Ok(serde_json::json!({
                    "State": {"Status": "exited", "Running": false, "ExitCode": 1},
                    "RestartCount": 0,
                    "Config": {"Tty": false}
                }))
            },
            || false,
            |tty| super::decode_log_lines(&raw_logs, tty, 15),
            || {
                crashed_stops.fetch_add(1, Ordering::SeqCst);
            },
        )
        .unwrap_err();
        assert!(t0.elapsed() < Duration::from_millis(500), "took {:?}", t0.elapsed());
        assert_eq!(crashed_stops.load(Ordering::SeqCst), 1);
        let msg = err.to_string();
        assert!(msg.contains("exit code 1"), "{msg}");
        assert!(msg.contains("cannot find filesystem info for device"), "{msg}");
        // Last line is the fatal k3s log line so ui/k8s.rs surfaces it directly.
        assert!(msg.lines().last().unwrap().contains("cannot find filesystem info for device"), "{msg}");

        // 2) Crash-loop under `RestartPolicy: unless-stopped` (Running == true again, RestartCount > initial_restarts).
        let loop_stops = AtomicUsize::new(0);
        let err_loop = super::wait_for_ready_with(
            Some(2),
            Duration::from_secs(180),
            Duration::from_secs(5),
            || {
                Ok(serde_json::json!({
                    "State": {"Status": "running", "Running": true, "ExitCode": 255},
                    "RestartCount": 3,
                    "Config": {"Tty": true}
                }))
            },
            || false,
            |_| vec!["Error: unknown flag: --bad-k3s-arg".into()],
            || {
                loop_stops.fetch_add(1, Ordering::SeqCst);
            },
        )
        .unwrap_err();
        assert_eq!(loop_stops.load(Ordering::SeqCst), 1);
        assert!(err_loop.to_string().contains("exit code 255") && err_loop.to_string().contains("--bad-k3s-arg"));

        // 3) Healthy startup polls until kubectl reports Ready without false-failing on prior RestartCount.
        let polls = AtomicUsize::new(0);
        let healthy_stops = AtomicUsize::new(0);
        super::wait_for_ready_with(
            Some(2),
            Duration::from_secs(5),
            Duration::from_millis(1),
            || {
                Ok(serde_json::json!({
                    "State": {"Status": "running", "Running": true, "ExitCode": 0},
                    "RestartCount": 2,
                    "Config": {"Tty": false}
                }))
            },
            || polls.fetch_add(1, Ordering::SeqCst) >= 2,
            |_| Vec::new(),
            || {
                healthy_stops.fetch_add(1, Ordering::SeqCst);
            },
        )
        .unwrap();
        assert_eq!(healthy_stops.load(Ordering::SeqCst), 0);
        assert!(polls.load(Ordering::SeqCst) >= 3);
    }
}
