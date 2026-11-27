//! The window's engine, as crates/kiri/src/ui/mod.rs is on the Mac: a client
//! of the daemon that answers the page's commands and sends it the lists
//! whenever an event says they changed, so the page never polls. The page's
//! protocol is the Mac app's, unchanged; what macOS does itself (Finder,
//! Terminal, the keychain, /etc/resolver) has a Windows equivalent here or
//! is reported as not available yet.

use std::io;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use serde_json::{json, Value};

use crate::app::{Handle, Menu};
use crate::client;
use crate::detail;

#[path = "../../kiri/src/ui/brands.rs"]
pub(crate) mod brands;
// Share in the window, the Mac's own file: it needs only emit, notice, crate::client and crate::share.
#[path = "../../kiri/src/ui/sharing.rs"]
pub(crate) mod sharing;
// What an image won't start without, the Mac's own file: it needs only crate::client.
#[path = "../../kiri/src/ui/needs.rs"]
mod needs;
// Compose in the window and what each service is made of, the Mac's own files:
// they need only crate::client, brands and needs, and a docker CLI (compose_cli).
#[path = "../../kiri/src/ui/compose.rs"]
mod compose;
#[path = "../../kiri/src/ui/composetech.rs"]
mod composetech;
// What the window costs, the Mac's own file.
#[path = "../../kiri/src/ui/usage.rs"]
mod usage;
// Signing in to registries, the Mac's own file: it needs only crate::client.
#[path = "../../kiri/src/ui/logins.rs"]
mod logins;
// Signing in through the registry's own page (Pull from's Sign in), also the Mac's file.
#[path = "../../kiri/src/ui/weblogin.rs"]
mod weblogin;

/// How often the VM panel's figures refresh. The lists refresh on events.
const TICK: Duration = Duration::from_secs(2);
/// The lists also come again this often without an event, so "Up 5 min" and
/// "3 min ago" keep counting.
const LIST_EVERY: Duration = Duration::from_secs(30);
/// When the lists last went to the page, by any route.
static LISTED: std::sync::LazyLock<std::sync::Mutex<std::time::Instant>> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::time::Instant::now()));

#[derive(Debug, Clone)]
pub(crate) enum Cmd {
    Start,
    /// Kiri came up: the window opened, or the hidden launch at login.
    /// Start, except that an engine the person stopped stays stopped.
    Launch,
    Stop,
    Refresh,
    Pull(String),
    RemoveImage(String),
    /// An image, and the environment the Run popover asked for.
    Run(String, Vec<String>),
    Container { action: String, id: String },
    RemoveVolume(String),
    RemoveNetwork(String),
    About,
    Ports { id: String, ports: Value },
    Env { id: String, env: Vec<String> },
}

/// A command as the page sends it.
#[derive(serde::Deserialize)]
struct PageCmd {
    cmd: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    ports: Value,
    #[serde(default)]
    path: String,
    #[serde(default)]
    value: Value,
}

/// What the engine needs from the rest of kiri-win.
#[derive(Debug, Clone)]
pub struct Env {
    pub distro: Option<String>,
    pub pipe: String,
}

static TX: Mutex<Option<Sender<Cmd>>> = Mutex::new(None);
static ENV: Mutex<Option<Env>> = Mutex::new(None);
/// The tray's view of running containers: id, name.
static RUNNING: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

pub(crate) fn send(cmd: Cmd) {
    if let Some(tx) = TX.lock().unwrap_or_else(PoisonError::into_inner).as_ref() {
        let _ = tx.send(cmd);
    }
}

fn env() -> Env {
    ENV.lock().unwrap_or_else(PoisonError::into_inner).clone().unwrap_or(Env { distro: None, pipe: r"\\.\pipe\kiri".into() })
}

/// The WSL distro Kiri's engine runs in, when not the default one: the
/// one named at start, or the one setup has just made (a first run starts
/// with none, and setup's distro was otherwise left to WSL's default).
pub(crate) fn distro() -> Option<String> {
    env().distro.or_else(crate::setup::saved_distro)
}

/// Starts the engine thread and the event watcher.
pub fn start(e: Env) {
    *ENV.lock().unwrap_or_else(PoisonError::into_inner) = Some(e);
    let (tx, rx) = mpsc::channel();
    *TX.lock().unwrap_or_else(PoisonError::into_inner) = Some(tx.clone());
    let _ = std::thread::Builder::new().name("kiri-engine".into()).spawn(move || engine(&rx, tx));
}

/// Delivers one JSON event to the page. Callable from any thread.
pub fn emit(json: String) {
    Handle.eval(format!("window.kiri && kiri.on({json})"));
}

/// The window let go of its page (app.rs, Ui::close): the terminals, the
/// log and the live figures it followed end with it, as when Linux's window
/// closes. The page asks for what it needs again when it next loads.
pub fn page_gone() {
    crate::term::handle("closeall", "", &Value::Null, emit);
    crate::detail::stop_logs();
    crate::detail::stop_stats();
}

pub fn notice(kind: &str, text: &str) -> String {
    json!({"type": "notice", "kind": kind, "text": text}).to_string()
}

fn state(name: &str, error: Option<&str>) -> String {
    SHOWN.store(true, Ordering::SeqCst);
    match error {
        Some(e) => json!({"type": "state", "state": name, "error": e}),
        None => json!({"type": "state", "state": name}),
    }
    .to_string()
}

/// Terminates Kiri's dedicated WSL distro (`kiri`) so `vmmemWSL` releases RAM
/// when no other WSL distro is running. Never terminates a shared user distro
/// (e.g. Ubuntu), which would kill unrelated WSL shells.
fn terminate_kiri_distro() {
    if let Some(d) = crate::refuse::terminate_target(distro().as_deref(), crate::setup::KIRI_DISTRO) {
        crate::serve::log(&format!("engine: terminating WSL distro {d}"));
        let mut cmd = crate::win::tool("wsl.exe");
        std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);
        if let Err(e) = crate::update::output_within(cmd.args(["--terminate", d]), crate::update::WSL_LIMIT) {
            crate::serve::log(&format!("engine: wsl --terminate {d} failed: {e}"));
        }
    }
}

/// Emits stopped UI state and updates the tray menu directly without touching WSL.
/// When `zero_vm` is true (on an explicit Stop transition from `"stopping"`),
/// also emits a zeroed `vm` panel before `"stopped"` so counters clear immediately.
fn emit_stopped(zero_vm: bool) {
    RUNNING.lock().unwrap_or_else(PoisonError::into_inner).clear();
    *STORAGE_RO_SHOWN.lock().unwrap_or_else(PoisonError::into_inner) = None;
    if zero_vm {
        emit(json!({
            "type": "vm",
            "awake": false,
            "target_mib": 0,
            "ceiling_mib": 0,
            "used_mib": 0,
            "running": 0,
            "cpus": 0,
            "daemon_kib": 0,
        })
        .to_string());
    }
    emit(state("stopped", None));
    Handle.set_menu(Menu { vm: "Stopped".into(), running: Vec::new() });
}

/// Called after an external `POST /kiri/wake` (for example `kiri start` from
/// the CLI) wakes Kiri through the named pipe while `kiri-win` was stopped.
pub(crate) fn on_external_wake() {
    std::thread::spawn(|| send_windows_roots(true));
    std::thread::spawn(send_windows_proxy);
    std::thread::spawn(crate::update::catch_up_engine);
    crate::wslconfig::sync_wsl_integration_soon();
    crate::watch::notify_containers_changed();
    crate::ports::notify();
    send(Cmd::Refresh);
}

/// Called after an external `POST /kiri/stop` (`kiri engine stop`) stops the
/// WSL daemon through the named pipe: marks `kiri-win` stopped immediately so
/// subsequent pipe/status checks see the stopped gate without a race, then
/// tells the engine thread to tear down bridges/relays, terminate Kiri's
/// dedicated WSL distro, and update the window and tray (#983).
pub(crate) fn on_external_stop() {
    crate::serve::set_stopped(true);
    send(Cmd::Stop);
}

fn engine(rx: &Receiver<Cmd>, tx: Sender<Cmd>) {
    watch(tx);
    // Windows' proxy and root certificates for the daemon, now and every
    // minute.
    std::thread::spawn(|| loop {
        if !crate::serve::is_stopped() {
            send_windows_proxy();
            send_windows_roots(false);
        }
        std::thread::sleep(Duration::from_secs(60));
    });
    let mut pending: Option<Cmd> = None;
    loop {
        let cmd = match pending.take() {
            Some(c) => Ok(c),
            None => rx.recv_timeout(TICK),
        };
        match cmd {
            Ok(Cmd::Start) => bring_up(false),
            Ok(Cmd::Launch) => bring_up(true),
            // Stop means off: every container stopped, the engine off until
            // Start (nothing wakes it meanwhile), this window's shares closed,
            // and Kiri's dedicated WSL distro terminated so vmmemWSL frees RAM.
            Ok(Cmd::Stop) => {
                emit(state("stopping", None));
                sharing::close_all();
                if !crate::serve::is_stopped() {
                    let stopped = match expect_ok(client::request("POST", "/kiri/stop", None)) {
                        // An engine older than Stop: its sleep.
                        Err(e) if e.to_string().contains("404") => expect_ok(client::request("POST", "/kiri/sleep", None)),
                        r => r,
                    };
                    if let Err(e) = stopped {
                        emit(notice("error", &e.to_string()));
                    }
                }
                crate::serve::set_stopped(true);
                crate::serve::stop_bridge();
                crate::relay::stop();
                crate::ports::notify();
                crate::watch::notify_containers_changed();
                terminate_kiri_distro();
                emit_stopped(true);
            }
            Ok(Cmd::Refresh) => {
                // Events come in bursts (create, start, …): one refresh per
                // burst. Anything else that arrives meanwhile runs next.
                loop {
                    match rx.recv_timeout(Duration::from_millis(60)) {
                        Ok(Cmd::Refresh) => {}
                        Ok(other) => {
                            pending = Some(other);
                            break;
                        }
                        Err(_) => break,
                    }
                }
                refresh();
            }
            Ok(Cmd::Pull(name)) => pull(name),
            Ok(Cmd::Run(name, env)) => {
                std::thread::spawn(move || {
                    // The page shows its spinner until this says how it went.
                    let result = run_image(&name, &env);
                    emit(json!({"type": "ran", "name": name, "error": result.is_err()}).to_string());
                    act(result);
                });
            }
            Ok(Cmd::RemoveImage(name)) => {
                std::thread::spawn(move || {
                    match client::request("DELETE", &format!("/images/{}", path_escape(&name)), None) {
                        Ok(r) if r.ok() => {
                            // Only untagged when another name still points at it: nothing freed.
                            let deleted = r.json().as_array().is_some_and(|a| a.iter().any(|v| v.get("Deleted").is_some()));
                            emit(json!({"type": "removed", "name": name, "deleted": deleted}).to_string());
                        }
                        Ok(r) => emit(notice("error", &r.error())),
                        Err(e) => emit(notice("error", &e.to_string())),
                    }
                    send(Cmd::Refresh);
                });
            }
            Ok(Cmd::Container { action, id }) => {
                let (method, path) = match action.as_str() {
                    "remove" => ("DELETE", format!("/containers/{id}?force=1&v=1")),
                    a @ ("start" | "stop" | "restart" | "pause" | "unpause") => ("POST", format!("/containers/{id}/{a}")),
                    _ => continue,
                };
                std::thread::spawn(move || {
                    let result = expect_done(client::request(method, &path, None));
                    // Refused to start (a port taken): the container's page says why.
                    if let (Err(e), "start") = (&result, action.as_str()) {
                        emit(json!({"type": "startfailed", "id": id, "error": e.to_string()}).to_string());
                    }
                    act(result);
                });
            }
            Ok(Cmd::RemoveVolume(name)) => {
                std::thread::spawn(move || act(expect_ok(client::request("DELETE", &format!("/volumes/{}", path_escape(&name)), None))));
            }
            Ok(Cmd::RemoveNetwork(id)) => {
                std::thread::spawn(move || act(expect_ok(client::request("DELETE", &format!("/networks/{id}"), None))));
            }
            Ok(Cmd::Ports { id, ports }) => {
                std::thread::spawn(move || act(set_ports(&id, ports)));
            }
            Ok(Cmd::Env { id, env }) => {
                std::thread::spawn(move || act(set_env(&id, env)));
            }
            Ok(Cmd::About) => {
                std::thread::spawn(about);
            }
            Err(RecvTimeoutError::Disconnected) => return,
            Err(RecvTimeoutError::Timeout) => {
                emit_docker_state_if_changed();
                if !crate::serve::is_stopped() {
                    vm_panel();
                    if LISTED.lock().unwrap_or_else(|e| e.into_inner()).elapsed() >= LIST_EVERY {
                        refresh();
                    }
                }
            }
        }
    }
}

/// Follows the daemon's event stream on its own thread; each event asks
/// the engine for a refresh. Reconnects when the daemon comes back.
fn watch(tx: Sender<Cmd>) {
    let _ = std::thread::Builder::new().name("kiri-ui-events".into()).spawn(move || loop {
        if !crate::serve::is_stopped() && client::alive_quick() {
            if tx.send(Cmd::Refresh).is_err() {
                return;
            }
            // A Kubernetes node already running gets its kubectl context.
            crate::k8s::sync_soon();
            crate::watch::notify_containers_changed();
            crate::ports::notify();
            crate::wslconfig::sync_wsl_integration_soon();
            let _ = client::events(|_| {
                crate::watch::notify_containers_changed();
                crate::ports::notify();
                tx.send(Cmd::Refresh).is_ok()
            });
        }
        std::thread::sleep(Duration::from_secs(1));
    });
}

pub fn expect_ok(r: io::Result<client::Response>) -> io::Result<()> {
    let r = r?;
    if r.ok() { Ok(()) } else { Err(io::Error::other(r.error())) }
}

/// A container action's answer, as on the Mac and Linux: Docker's 304 is
/// "already so" (Stop on a stopped container, Start on a running one), so
/// done, not an empty red toast.
fn expect_done(r: io::Result<client::Response>) -> io::Result<()> {
    let r = r?;
    if r.ok() || r.status == 304 { Ok(()) } else { Err(io::Error::other(r.error())) }
}

fn act(result: io::Result<()>) {
    if let Err(e) = result {
        emit(notice("error", &e.to_string()));
    }
}

pub(crate) fn path_escape(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~:/@".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// Start, or a launch: the daemon is made to answer (so `docker` gets an
/// answer after a restart of Windows) and the engine is woken. A launch
/// leaves an engine the person stopped as it is: only Start ends a Stop.
/// Before, the hidden launch at login, and the window opening before the
/// daemon was up, sent Start and so undid it (#394).
fn bring_up(launch: bool) {
    if launch && crate::serve::is_stopped() {
        emit_stopped(false);
        return;
    }
    if !launch {
        crate::serve::set_stopped(false);
    }
    // Up and stopped already: nothing to bring up, and no "booting" shown.
    if launch && client::alive_quick() && stopped() == Some(true) {
        return refresh();
    }
    emit(state("booting", None));
    // Asked again once the daemon answers: one that has only just started
    // has read the saved Stop by then.
    let woken = ensure_daemon().and_then(|()| if wakes(launch, stopped()) { wake().map(|()| true) } else { Ok(false) });
    match woken {
        Ok(woken) => {
            // Before the first pull, not up to a minute after.
            std::thread::spawn(|| send_windows_roots(true));
            if woken {
                std::thread::spawn(ensure_builder);
                std::thread::spawn(send_windows_proxy);
            }
            crate::watch::notify_containers_changed();
            crate::ports::notify();
            refresh();
        }
        Err(e) => emit(state("stopped", Some(&e.to_string()))),
    }
}

/// Whether bringing Kiri up wakes the engine: Start always does, a launch
/// only when the engine said it was not stopped. Not knowing (its /info
/// did not answer: an engine just started, or a wsl.exe slow after Windows
/// woke) is no reason to wake it: that ended a person's Stop. A docker
/// command wakes an engine that was only asleep anyway.
fn wakes(launch: bool, stopped: Option<bool>) -> bool {
    !launch || stopped == Some(false)
}

/// Whether Kiri was stopped (Stop in the window or the tray): then it stays
/// off until Start. None when the engine's /info did not answer.
fn stopped() -> Option<bool> {
    client::get_background("/info").ok().map(|i| i["KiriStopped"] == true)
}

/// The daemon's wake; a Linux host has no VM to wake, which is fine.
fn wake() -> io::Result<()> {
    let r = client::request("POST", "/kiri/wake", None)?;
    if r.ok() || r.status == 404 { Ok(()) } else { Err(io::Error::other(r.error())) }
}

/// Makes sure the daemon answers, as this app's version: Ubuntu uses the
/// `kiri` systemd service; the small Kiri Linux distro starts
/// /usr/local/bin/kiri-start instead. An engine that answers on another
/// version (started by the boot command or the bridge before an update's
/// engine was copied in) is restarted on this one, once per run, on a
/// thread of its own: this returns as soon as the engine answers.
pub(crate) fn ensure_daemon() -> io::Result<()> {
    if !client::alive() {
        start_daemon()?;
    }
    crate::relay::ensure_started();
    std::thread::spawn(crate::update::catch_up_engine);
    crate::wslconfig::sync_wsl_integration_soon();
    Ok(())
}

/// Checks `/proc/mounts` inside `distro` for a read-only `/` or `/var/lib/kiri`
/// (`ro` or ext4 `emergency_ro`, #768) and formats recovery steps naming the
/// configured `ext4.vhdx` path.
pub(crate) fn probe_wsl_readonly(distro: Option<&str>) -> Option<String> {
    let mut cmd = crate::win::tool("wsl.exe");
    if let Some(d) = distro {
        cmd.args(["-d", d]);
    }
    std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);
    let out = crate::update::output_within(cmd.args(["-u", "root", "-e", "cat", "/proc/mounts"]), Duration::from_secs(10)).ok()?;
    if !out.status.success() {
        return None;
    }
    let text = crate::wslsync::wsl_text(&out.stdout);
    let kind = crate::wslsync::parse_wsl_readonly_mounts(&text)?;
    Some(crate::wslsync::wsl_readonly_message(kind, Some(&crate::storage::current_vhdx())))
}

/// Starts the daemon in WSL, this app's engine copied in first.
fn start_daemon() -> io::Result<()> {
    if let Some(missing) = crate::storage::unavailable() {
        crate::storage::emit_report();
        return Err(io::Error::other(crate::storage::unavailable_message(&missing)));
    }
    crate::serve::log("engine: not answering; starting it in WSL");
    // The engine this app installed, not one an update left behind.
    match crate::update::sync_engine() {
        Ok(true) => {
            crate::serve::log("engine: copied this version's engine into WSL");
            // The bridge was started from the engine that was there before.
            crate::serve::renew_bridge();
        }
        Ok(false) => {}
        Err(e) => crate::serve::log(&format!("engine: could not copy the engine into WSL ({e}); starting the one there")),
    }
    let distro = distro();
    let mut cmd = crate::win::tool("wsl.exe");
    if let Some(d) = &distro {
        cmd.args(["-d", d]);
    }
    std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);
    // Each killed after WSL_LIMIT: a wsl.exe right after Windows wakes can hang.
    let started = crate::update::output_within(cmd.args(["-u", "root", "--", "systemctl", "start", "kiri"]), crate::update::WSL_LIMIT);
    let mut fatal_exit = false;
    let mut start_err = None;
    if !started.is_ok_and(|o| o.status.success()) {
        let mut cmd = crate::win::tool("wsl.exe");
        if let Some(d) = &distro {
            cmd.args(["-d", d]);
        }
        std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);
        if let Ok(out) = crate::update::output_within(cmd.args(["-u", "root", "--", "/usr/local/bin/kiri-start"]), crate::update::WSL_LIMIT)
            && !out.status.success()
        {
            fatal_exit = out.status.code() == Some(2);
            start_err = crate::wslsync::wsl_text(&out.stderr).lines().map(str::trim).rfind(|l| !l.is_empty()).map(str::to_owned);
        }
    }
    let wait = if fatal_exit { Duration::from_millis(200) } else { Duration::from_secs(10) };
    if client::wait_alive(wait, Duration::from_millis(100)) {
        return Ok(());
    }
    if let Some(ro_msg) = probe_wsl_readonly(distro.as_deref()) {
        crate::serve::log(&format!("engine: {ro_msg}"));
        return Err(io::Error::other(ro_msg));
    }
    if let Some(err) = start_err {
        return Err(io::Error::other(format!("Kiri's engine did not start in WSL: {err}")));
    }
    Err(io::Error::other("Kiri's engine did not start in WSL: run contrib\\windows\\kiri.ps1 to install it"))
}

/// `docker build` through Kiri, as on the Mac: BuildKit in a Kiri container
/// (buildx's docker-container driver), loading what it builds into Kiri.
/// That container is the daemon's managed builder, made when buildx first
/// looks for it and stopped when idle (crates/kiri/src/daemon/builder.rs);
/// without buildx the CLI's classic POST /build uses the same BuildKit.
/// kiri.ps1 makes it the builder `docker build` uses (BUILDX_BUILDER) when
/// Kiri is the only engine; beside Docker Desktop, `buildx use` makes it the
/// one for the `kiri` context, and `buildx install` makes plain `docker
/// build` use it, as on the Mac (crates/kiri/src/setup.rs `builder`), or
/// it builds with buildx's fallback for the context, which never loads the
/// image into Kiri. Needs the `kiri` context, which kiri.ps1 makes.
fn ensure_builder() {
    const BUILDER: &str = "kiri-build";
    let docker = crate::detail::docker_cli();
    let run = |args: &[&str]| {
        let mut cmd = crate::win::tool(&docker);
        std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);
        cmd.args(args).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().is_ok_and(|s| s.success())
    };
    if !run(&["context", "inspect", "kiri"]) || !run(&["buildx", "version"]) {
        return;
    }
    if !run(&["buildx", "inspect", BUILDER]) && !run(&["buildx", "create", "--name", BUILDER, "--driver", "docker-container", "--driver-opt", "default-load=true", "kiri"]) {
        crate::serve::log("docker buildx create failed");
        return;
    }
    // `--default`: kept per context, so it stays the builder for `kiri`
    // whatever another context selects later.
    if !run(&["--context", "kiri", "buildx", "use", "--default", BUILDER]) || !run(&["buildx", "install"]) {
        crate::serve::log("docker buildx use or install failed");
    }
}

/// Sends the page every list, from the daemon.
fn refresh() {
    *LISTED.lock().unwrap_or_else(|e| e.into_inner()) = std::time::Instant::now();
    if crate::serve::is_stopped() {
        emit_stopped(false);
        return;
    }
    let lists = (|| -> io::Result<Value> {
        // Quick: a refresh never holds the engine thread behind a start.
        let containers = client::get_quick("/containers/json?all=1")?;
        let images = client::get_quick("/images/json")?;
        let volumes = client::get_quick("/volumes")?;
        let networks = client::get_quick("/networks")?;
        let add_icon = |mut v: Value, name_of: &dyn Fn(&Value) -> String| {
            if let Some(list) = v.as_array_mut() {
                for item in list {
                    item["icon"] = json!(brand(&name_of(item)));
                }
            }
            v
        };
        let containers = add_icon(containers, &|c| c["Image"].as_str().unwrap_or_default().to_owned());
        let images = add_icon(images, &|i| i["RepoTags"][0].as_str().unwrap_or_default().to_owned());
        Ok(json!({"type": "lists", "containers": containers, "images": images, "volumes": volumes["Volumes"], "networks": networks}))
    })();
    match lists {
        Ok(v) => {
            *RUNNING.lock().unwrap_or_else(PoisonError::into_inner) = v["containers"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|c| c["State"] == "running")
                .map(|c| (c["Id"].as_str().unwrap_or("").to_owned(), c["Names"][0].as_str().unwrap_or("").trim_start_matches('/').to_owned()))
                .collect();
            emit(v.to_string());
            vm_panel();
        }
        Err(e) => no_answer(&e),
    }
}

static STORAGE_RO_SHOWN: Mutex<Option<String>> = Mutex::new(None);

/// The sidebar's engine panel and the tray menu's state.
fn vm_panel() {
    if crate::serve::is_stopped() {
        return;
    }
    match client::get_quick("/info") {
        Ok(info) => {
            // A Linux host has no VM to put to sleep: it is always awake.
            let awake = info["KiriVmAwake"].as_bool().unwrap_or(true);
            let mib = |k: &str| info[k].as_u64().unwrap_or(0) >> 20;
            let target = if info["KiriMemoryTarget"].is_null() { info["MemTotal"].as_u64().unwrap_or(0) >> 20 } else { mib("KiriMemoryTarget") };
            let ceiling = if info["KiriMemoryCeiling"].is_null() { info["MemTotal"].as_u64().unwrap_or(0) >> 20 } else { mib("KiriMemoryCeiling") };
            emit(json!({
                "type": "vm", "awake": awake, "target_mib": target, "ceiling_mib": ceiling,
                // Missing from an engine older than the field: 0, not NaN on the page.
                "used_mib": mib("KiriMemoryUsed"),
                "running": info["ContainersRunning"], "cpus": info["NCPU"],
                "daemon_kib": info["KiriAgentMemory"].as_u64().unwrap_or(0) >> 10,
            })
            .to_string());
            // Stopped (Stop in the window): off until Start, unlike asleep.
            let stopped = info["KiriStopped"] == true;
            let awake = awake && !stopped;
            emit(state(if awake { "running" } else if stopped { "stopped" } else { "asleep" }, None));
            let ro = info["KiriStorageReadOnly"].as_str().map(str::to_owned);
            let mut shown = STORAGE_RO_SHOWN.lock().unwrap_or_else(PoisonError::into_inner);
            if ro.as_deref() != shown.as_deref() {
                if let Some(ref msg) = ro {
                    emit(notice("error", msg));
                }
                *shown = ro;
            }
            let running = RUNNING.lock().unwrap_or_else(PoisonError::into_inner).clone();
            Handle.set_menu(Menu { vm: if awake { "Running" } else if stopped { "Stopped" } else { "Asleep" }.into(), running });
        }
        Err(e) => no_answer(&e),
    }
}

/// Whether the window has been told any state yet (`state`).
static SHOWN: AtomicBool = AtomicBool::new(false);

/// What the window and the tray show when a list or the engine panel got
/// no answer (`unanswered`).
fn no_answer(e: &io::Error) {
    match unanswered(e.kind(), SHOWN.load(Ordering::SeqCst)) {
        Some("stopped") => {
            RUNNING.lock().unwrap_or_else(PoisonError::into_inner).clear();
            *STORAGE_RO_SHOWN.lock().unwrap_or_else(PoisonError::into_inner) = None;
            Handle.set_menu(Menu { vm: "Not running".into(), running: Vec::new() });
            emit(state("stopped", None));
        }
        Some(s) => emit(state(s, None)),
        None => {}
    }
}

/// The state to show for a request that failed with `kind`: "stopped"
/// when the engine refused or is not there; when it was only slow (QUICK
/// passed: a loaded engine, or one the bridge is starting), nothing, so
/// the last state stays, or "booting" if none was shown yet.
fn unanswered(kind: io::ErrorKind, shown: bool) -> Option<&'static str> {
    match kind {
        io::ErrorKind::TimedOut if shown => None,
        io::ErrorKind::TimedOut => Some("booting"),
        _ => Some("stopped"),
    }
}

/// The brand logo for an image name like `bitnami/redis:7`: first by the
/// whole repository path, then by its last component.
pub(crate) fn brand(name: &str) -> Option<[&'static str; 2]> {
    let name = name.split_once('@').map_or(name, |(n, _)| n);
    let repo = match name.rfind(':') {
        Some(i) if !name[i..].contains('/') => &name[..i],
        _ => name,
    };
    let last = repo.rsplit('/').next().unwrap_or(repo);
    let slug = [repo, last].into_iter().find_map(|key| brands::IMAGES.binary_search_by_key(&key, |(k, _)| k).ok().map(|i| brands::IMAGES[i].1))?;
    let i = brands::BRANDS.binary_search_by_key(&slug, |(s, _, _)| s).ok()?;
    let (_, hex, path) = brands::BRANDS[i];
    Some([hex, path])
}

/// A pull the page asked for, from the moment it asks: its image, whether
/// its thread has taken it, its connection once open, and whether Cancel
/// was pressed. A pull's entry is the oldest untaken one with its name.
struct Pulling {
    run: u64,
    name: String,
    taken: bool,
    closer: Option<client::Closer>,
    cancelled: bool,
}

static PULLING: Mutex<Vec<Pulling>> = Mutex::new(Vec::new());

/// Cancel on a pull's row: its request to the engine is closed, which stops
/// the engine's pull (unless a `docker pull` is following it too). A read
/// is only stopped while it waits, so this goes on stopping until the pull
/// has ended.
fn cancel_pull(name: &str) {
    let mut found = false;
    for p in PULLING.lock().unwrap_or_else(PoisonError::into_inner).iter_mut().filter(|p| p.name == name) {
        p.cancelled = true;
        found = true;
    }
    if !found {
        return;
    }
    let name = name.to_owned();
    let _ = std::thread::Builder::new().name("kiri-pull-cancel".into()).spawn(move || {
        for _ in 0..600 {
            let closers: Vec<client::Closer> = {
                let pulls = PULLING.lock().unwrap_or_else(PoisonError::into_inner);
                if !pulls.iter().any(|p| p.name == name && p.cancelled) {
                    return;
                }
                pulls.iter().filter(|p| p.name == name && p.cancelled).filter_map(|p| p.closer.clone()).collect()
            };
            for c in closers {
                c.close();
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
}

/// Pulls through the daemon on its own thread; progress shows as a busy row.
fn pull(name: String) {
    let _ = std::thread::Builder::new().name("kiri-pull".into()).spawn(move || {
        let reference = name.trim().to_owned();
        // This pull's entry; dropped when the pull ends, however it ends.
        let mine = PULLING.lock().unwrap_or_else(PoisonError::into_inner).iter_mut().find(|p| p.name == reference && !p.taken).map(|p| {
            p.taken = true;
            p.run
        });
        let entry = |f: &mut dyn FnMut(&mut Pulling)| {
            if let Some(p) = PULLING.lock().unwrap_or_else(PoisonError::into_inner).iter_mut().find(|p| Some(p.run) == mine) {
                f(p);
            }
        };
        let cancelled = || {
            let mut c = false;
            entry(&mut |p| c = p.cancelled);
            c
        };
        let forget = || {
            let mut pulls = PULLING.lock().unwrap_or_else(PoisonError::into_inner);
            pulls.retain(|p| Some(p.run) != mine);
        };
        if reference.is_empty() || reference.contains(char::is_whitespace) {
            forget();
            emit(notice("error", &trf("Not an image name: {reference}", &[("reference", &reference)])));
            return;
        }
        if cancelled() {
            forget();
            emit(json!({"type": "pull", "state": "done", "name": reference, "cancelled": true}).to_string());
            return;
        }
        emit(json!({"type": "pull", "state": "started", "name": reference}).to_string());
        let began = std::time::Instant::now();
        let (image, tag) = match reference.rfind(':') {
            Some(i) if !reference[i..].contains('/') => (&reference[..i], &reference[i + 1..]),
            _ => (reference.as_str(), "latest"),
        };
        // The daemon's progress lines, streamed, make one bar over every
        // layer, as the Mac shows; and the "is ready" toast at the end.
        let result = (|| -> io::Result<()> {
            let mut layers: std::collections::HashMap<String, (u64, u64)> = std::collections::HashMap::new();
            let mut error = None;
            let mut finished = false;
            let mut told = std::time::Instant::now();
            let path = format!("/images/create?fromImage={}&tag={}", path_escape(image), path_escape(tag));
            // Signed in to its registry: the sign-in goes with it, as docker's does.
            let auth = logins::header_for(image);
            // Kept for Cancel; cancelled already, it's closed now.
            let opened = |c: client::Closer| {
                if cancelled() {
                    c.close();
                }
                entry(&mut |p| p.closer = Some(c.clone()));
            };
            let status = client::post_lines_closable(&path, auth.as_deref(), opened, |v| {
                let id = v["id"].as_str().unwrap_or_default().to_owned();
                match v["status"].as_str().unwrap_or_default() {
                    "Pulling fs layer" => {
                        layers.insert(id, (v["size"].as_u64().unwrap_or(0), 0));
                    }
                    "Downloading" => {
                        let d = &v["progressDetail"];
                        layers.insert(id, (d["total"].as_u64().unwrap_or(0), d["current"].as_u64().unwrap_or(0)));
                    }
                    "Pull complete" => {
                        if let Some(l) = layers.get_mut(&id) {
                            l.1 = l.0;
                        }
                    }
                    _ => {}
                }
                if let Some(e) = v["error"].as_str().or(v["message"].as_str()) {
                    error = Some(e.to_owned());
                }
                if v["status"].as_str().is_some_and(|s| s.starts_with("Status: ")) {
                    finished = true;
                }
                // A few updates a second is enough for a bar; none once cancelled.
                if !layers.is_empty() && told.elapsed() >= Duration::from_millis(150) && !cancelled() {
                    told = std::time::Instant::now();
                    let (total, got) = layers.values().fold((0, 0), |(t, g), (size, done)| (t + size, g + done));
                    emit(json!({"type": "pull", "state": "progress", "name": reference, "got": got, "total": total}).to_string());
                }
            });
            // Closed by Cancel before the engine said it was done.
            if !finished && cancelled() {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
            }
            let status = status?;
            match error {
                Some(e) => Err(io::Error::other(e)),
                None if (200..300).contains(&status) => Ok(()),
                None => Err(io::Error::other(format!("pull failed (HTTP {status})"))),
            }
        })();
        let stopped = result.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::Interrupted) && cancelled();
        forget();
        // A failed pull says why on its own row in Images, as on the Mac.
        match result {
            Err(_) if stopped => emit(json!({"type": "pull", "state": "done", "name": reference, "cancelled": true}).to_string()),
            Ok(()) => {
                emit(json!({"type": "pull", "state": "done", "name": reference}).to_string());
                emit(json!({"type": "pulled", "name": reference, "ms": began.elapsed().as_millis() as u64, "icon": brand(&reference)}).to_string());
            }
            Err(e) => emit(json!({"type": "pull", "state": "done", "name": reference, "error": e.to_string()}).to_string()),
        }
    });
}

/// Where a published port answers: `localhost:<port>`, the handy URL, noting
/// that the bind is every interface (the default, as Docker's), or else the
/// address it was bound to (`-p 127.0.0.1:8080:80`).
fn published(b: &Value) -> Option<String> {
    let p = b["HostPort"].as_str()?;
    Some(match b["HostIp"].as_str().unwrap_or("") {
        "" | "0.0.0.0" | "::" => format!("localhost:{p} (all interfaces)"),
        ip => format!("{ip}:{p}"),
    })
}

fn host_ports(info: &Value, with_inner: bool) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(map) = info["NetworkSettings"]["Ports"].as_object() {
        for (inner, list) in map {
            for b in list.as_array().into_iter().flatten() {
                if let Some(at) = published(b) {
                    out.push(if with_inner { format!("{at} → {inner}") } else { at });
                }
            }
        }
    }
    out
}

fn set_ports(id: &str, ports: Value) -> io::Result<()> {
    expect_ok(client::request("POST", &format!("/kiri/containers/{id}/ports"), Some(&json!({"ports": ports}))))?;
    crate::ports::sync_now();
    let now = host_ports(&client::get(&format!("/containers/{id}/json"))?, true);
    emit(notice("ok", &if now.is_empty() { tr("Ports removed") } else { trf("Ports saved: {ports}", &[("ports", &now.join(", "))]) }));
    Ok(())
}

/// A container's environment, as the Mac's: the engine restarts it with the
/// new one if it was running, or starts it with it if it had stopped.
fn set_env(id: &str, env: Vec<String>) -> io::Result<()> {
    let r = client::request("POST", &format!("/kiri/containers/{id}/env"), Some(&json!({"env": env})))?;
    if r.status == 404 && !r.error().contains("No such container") {
        return Err(io::Error::other("This engine can't change a container's environment yet: update Kiri's engine in WSL and try again."));
    }
    expect_ok(Ok(r))?;
    let info = client::get(&format!("/containers/{id}/json"))?;
    let name = info["Name"].as_str().unwrap_or_default().trim_start_matches('/');
    let text = if info["State"]["Running"].as_bool() == Some(true) { trf("{name} restarted with the new environment", &[("name", &name)]) } else { trf("{name} has the new environment", &[("name", &name)]) };
    emit(notice("ok", &text));
    emit(json!({"type": "inspect", "id": id, "info": info}).to_string());
    Ok(())
}

fn run_image(image: &str, env: &[String]) -> io::Result<()> {
    let body = json!({"Image": image, "Tty": true, "OpenStdin": true, "Env": env, "HostConfig": {"PublishAllPorts": true}});
    let began = std::time::Instant::now();
    let created = client::request("POST", "/containers/create", Some(&body))?;
    if !created.ok() {
        return Err(io::Error::other(created.error()));
    }
    let id = created.json()["Id"].as_str().unwrap_or_default().to_owned();
    expect_ok(client::request("POST", &format!("/containers/{id}/start"), None))?;
    let ms = began.elapsed().as_millis() as u64;
    let info = client::get(&format!("/containers/{id}/json"))?;
    let name = info["Name"].as_str().unwrap_or_default().trim_start_matches('/').to_owned();
    let ports = host_ports(&info, false);
    // View on the toast opens the container's page; the list stays put, as on
    // the Mac, and `image` puts it beside that image's Run button.
    let text = if ports.is_empty() { trf("Started {name}", &[("name", &name)]) } else { trf("Started {name} on {ports}", &[("name", &name), ("ports", &ports.join(", "))]) };
    emit(json!({"type": "notice", "kind": "ok", "text": text, "open": id, "image": image, "ms": ms}).to_string());
    Ok(())
}

fn about() {
    let info = client::get("/info").unwrap_or(Value::Null);
    let version = client::get("/version").unwrap_or(Value::Null);
    emit(
        json!({
            "type": "about", "app": env!("CARGO_PKG_VERSION"), "running": !info.is_null(),
            "engine": client::kiri_version(&version), "api": version["ApiVersion"], "kernel": info["KernelVersion"],
            "cpus": info["NCPU"], "memory": info["MemTotal"], "awake": info["KiriVmAwake"].as_bool().unwrap_or(true), "os": info["OperatingSystem"],
        })
        .to_string(),
    );
}

fn npipe_host(pipe: &str) -> String {
    format!("npipe:{}", pipe.replace('\\', "/"))
}

fn context_meta(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    use sha2::Digest as _;
    let sum = sha2::Sha256::digest(name.as_bytes());
    let hex: String = sum.iter().map(|b| format!("{b:02x}")).collect();
    dir.join("contexts/meta").join(hex)
}

fn docker_state() -> (String, String) {
    let endpoint = crate::serve::docker_engine_endpoint();
    let pipe = crate::client::pipe();
    let ours = npipe_host(&pipe);
    let ctx = crate::flavor::CONTEXT.get();
    let cli = crate::dockerctx::current_cli(ctx, &[&ours], &endpoint);
    let status = crate::dockerctx::status_event(env!("CARGO_PKG_VERSION"), false, crate::flavor::APP.get(), ctx, &cli).to_string();
    let sock = crate::dockerctx::sock_event(crate::serve::DOCKER_ENGINE, &endpoint, &ours, false).to_string();
    (status, sock)
}

static LAST_DOCKER_STATE: Mutex<(String, String)> = Mutex::new((String::new(), String::new()));

fn emit_docker_state() {
    let (status, sock) = docker_state();
    *LAST_DOCKER_STATE.lock().unwrap_or_else(PoisonError::into_inner) = (status.clone(), sock.clone());
    emit(status);
    emit(sock);
}

fn emit_docker_state_if_changed() {
    let (status, sock) = docker_state();
    let (send_status, send_sock) = {
        let mut last = LAST_DOCKER_STATE.lock().unwrap_or_else(PoisonError::into_inner);
        let ss = if last.0 != status { last.0 = status.clone(); true } else { false };
        let sd = if last.1 != sock { last.1 = sock.clone(); true } else { false };
        (ss, sd)
    };
    if send_status {
        emit(status);
    }
    if send_sock {
        emit(sock);
    }
}

/// Ensures Kiri's `cliPluginsExtraDirs` and `kiri` context in
/// `%USERPROFILE%\.docker`, repairing `config.json` if another engine's
/// uninstaller (such as Docker Desktop's) removed it (#984).
pub fn heal_docker_config(pipe: &str) {
    let Some(dir) = crate::dockerctx::docker_dir() else { return };
    let exe = std::env::current_exe().ok();
    let local = std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from);
    let plugins = crate::dockerctx::find_windows_cli_plugins(exe.as_deref(), local.as_deref());
    let desktop = std::env::var_os("ProgramFiles").is_some_and(|p| std::path::Path::new(&p).join(r"Docker\Docker\Docker Desktop.exe").is_file());
    let host = npipe_host(pipe);
    match crate::dockerctx::repair_windows_config(
        &dir,
        crate::dockerctx::WindowsRepairOpts {
            ours: crate::flavor::CONTEXT.get(),
            description: "Kiri (WSL2)",
            host: &host,
            plugins_dir: plugins.as_deref(),
            force_context_write: false,
            set_current_if_empty: false,
            force_use: false,
            desktop_installed: desktop,
        },
    ) {
        Ok(r) if r.context_written || r.plugins_added || r.current_context_set => {
            crate::serve::log(&format!(
                "docker config self-healed (context={}, plugins={}, current={})",
                r.context_written, r.plugins_added, r.current_context_set
            ));
        }
        Ok(_) => {}
        Err(e) => crate::serve::log(&format!("docker config: could not self-heal ({e})")),
    }
}

/// Ensures the `kiri` context exists and is plain `docker`'s current context,
/// keeping logins, credential helpers and plugin folders untouched (#369).
pub fn use_kiri_context() -> io::Result<()> {
    let dir = crate::dockerctx::docker_dir().ok_or_else(|| io::Error::other("USERPROFILE is not set"))?;
    let ours = crate::flavor::CONTEXT.get();
    crate::dockerctx::use_ours(&dir, &context_meta(&dir, ours), ours, "Kiri (WSL2)", &npipe_host(&crate::client::pipe()))
}

/// The docker CLI on Kiri's context, without a console window, for Compose
/// in the window.
fn compose_cli() -> io::Result<std::process::Command> {
    let mut cmd = crate::win::tool(&crate::detail::docker_cli());
    std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);
    cmd.args(["--context", crate::flavor::CONTEXT.get()]).env_remove("DOCKER_HOST").env_remove("DOCKER_CONTEXT");
    Ok(cmd)
}

/// The compose files opened in the window: %LOCALAPPDATA%\Kiri\compose.json.
fn compose_store() -> Option<std::path::PathBuf> {
    prefs_path().map(|p| p.with_file_name("compose.json"))
}

fn builds_event() -> String {
    match crate::builds::list() {
        Ok(b) => json!({"type": "builds", "builds": b}),
        Err(e) => json!({"type": "builds", "error": e.to_string()}),
    }
    .to_string()
}

/// Which builder docker build uses, as chosen (crate::buildwith). An older
/// Kiri named its builder in the user's BUILDX_BUILDER, which sent every
/// build to Kiri whatever docker used: that goes, as Kiri's.
fn build_with() {
    // The user's own value (HKCU\Environment) goes only if it is still
    // Kiri's. By reg.exe, not a PowerShell -Command: kiri-win runs no
    // script text it carries (crate::win says why).
    if std::env::var("BUILDX_BUILDER").is_ok_and(|b| b == crate::builds::BUILDER.get()) {
        let reg = |args: &[&str]| {
            let mut cmd = crate::win::tool("reg.exe");
            std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);
            cmd.args(args).output()
        };
        let ours = reg(&["query", r"HKCU\Environment", "/v", "BUILDX_BUILDER"]).is_ok_and(|o| {
            String::from_utf8_lossy(&o.stdout).lines().any(|l| {
                let w: Vec<&str> = l.split_whitespace().collect();
                w.len() == 3 && w[0].eq_ignore_ascii_case("BUILDX_BUILDER") && w[2] == crate::builds::BUILDER.get()
            })
        });
        if ours && reg(&["delete", r"HKCU\Environment", "/v", "BUILDX_BUILDER", "/f"]).is_ok_and(|o| o.status.success()) {
            crate::win::environment_changed();
        }
    }
    if let Err(e) = crate::buildwith::apply() {
        crate::serve::log(&format!("docker build: could not set which builder it uses ({e})"));
    }
}

/// Which engine plain `docker` uses: Kiri (made first if missing), "default",
/// or another context that exists, keeping logins and plugin folders.
fn use_context(name: &str) {
    let result = (|| -> io::Result<()> {
        let dir = crate::dockerctx::docker_dir().ok_or_else(|| io::Error::other("USERPROFILE is not set"))?;
        let ours = crate::flavor::CONTEXT.get();
        crate::dockerctx::switch(&dir, &context_meta(&dir, name), name, ours, "Kiri (WSL2)", &npipe_host(&crate::client::pipe()))
    })();
    emit_docker_state();
    emit(json!({"type": "usedcontext", "name": name, "error": result.as_ref().err().map(|e| e.to_string())}).to_string());
}

/// Which names containers answer at: <name>.kiri.local once its DNS rule
/// is in (crate::dns), else <name>.kiri.localhost, which Windows' browsers
/// resolve to this machine with no setup. HTTPS with Kiri's certificate is
/// the Mac's only.
fn domains_event() -> String {
    // The rule alone is not enough: nothing answers if port 53 was taken.
    let on = crate::dns::installed() && crate::dns::serving();
    json!({"type": "domains", "on": on, "suffix": if on { "kiri.local" } else { "kiri.localhost" }, "https": false}).to_string()
}

/// Settings → Domains, or the welcome: adds or removes the DNS rule.
fn domains(on: bool) {
    let _ = std::thread::Builder::new().name("kiri-domains".into()).spawn(move || {
        if on && !crate::dns::serving() {
            emit(notice("error", &tr("Another program holds 127.0.0.1:53, so Kiri cannot answer for <name>.kiri.local; containers stay at <name>.kiri.localhost")));
            emit(domains_event());
            return;
        }
        match crate::dns::install(on) {
            // Saying no to Windows' prompt is a choice, not an error.
            Err(e) if e.to_string().contains("canceled") => {}
            Err(e) => emit(notice("error", &trf("Could not change container names: {error}", &[("error", &e)]))),
            Ok(()) if on => emit(notice("ok", &tr("Containers now answer at <name>.kiri.local"))),
            Ok(()) => emit(notice("ok", &tr("Containers answer at <name>.kiri.localhost"))),
        }
        emit(domains_event());
        send(Cmd::Refresh);
    });
}

/// Puts `text` on the clipboard, by clip.exe: the page's own clipboard
/// needs a gesture the WebView doesn't always see.
pub(crate) fn clipboard(text: &str) -> io::Result<()> {
    use std::io::Write;
    let mut cmd = crate::win::tool("clip.exe");
    std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);
    let mut child = cmd.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn()?;
    child.stdin.take().ok_or_else(|| io::Error::other("no stdin"))?.write_all(text.as_bytes())?;
    let status = child.wait()?;
    if status.success() { Ok(()) } else { Err(io::Error::other("clip.exe failed")) }
}

/// Kiri opening for the first time on this account: no settings were saved
/// before this run. Worked out on the first read, before anything is saved.
pub(crate) fn fresh() -> bool {
    static FRESH: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *FRESH.get_or_init(|| prefs_path().is_some_and(|p| !p.exists()))
}

/// The language step, once: on a first start, or after an update that
/// brings this computer's language (lang::should_ask). The welcome waits behind it.
fn ask_language() {
    static ASKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if crate::lang::should_ask(fresh(), &prefs(), &crate::lang::os_languages()) && !ASKED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        emit(r#"{"type":"langpick"}"#.to_owned());
    }
}

/// The window's settings, in %LOCALAPPDATA%\Kiri\ui.json.
fn prefs_path() -> Option<std::path::PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|d| std::path::PathBuf::from(d).join("Kiri").join("ui.json"))
}

/// The settings, with the defaults for what the person hasn't picked: Kiri
/// starts dark until Settings → Appearance says otherwise.
pub fn prefs() -> Value {
    fresh();
    let mut p: Value = prefs_path().and_then(|p| std::fs::read(p).ok()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_else(|| json!({}));
    if !p.is_object() {
        p = json!({});
    }
    if p.get("theme").is_none() {
        p["theme"] = "dark".into();
    }
    p["watchBindMounts"] = json!(crate::watch::is_enabled());
    if p.get("startAtLogin").is_none() {
        p["startAtLogin"] = crate::setup::start_at_login().into();
    }
    if p.get("stopOnQuit").is_none() {
        p["stopOnQuit"] = false.into();
    }
    p
}

/// Stops running containers and terminates Kiri's WSL distro when quitting
/// with "Stop the engine when Kiri quits" on.
pub fn stop() {
    sharing::close_all();
    let _ = match expect_ok(client::request("POST", "/kiri/stop", None)) {
        Err(e) if e.to_string().contains("404") => expect_ok(client::request("POST", "/kiri/sleep", None)),
        r => r,
    };
    if let Some(d) = distro() {
        let mut cmd = crate::win::tool("wsl.exe");
        std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);
        let _ = crate::update::output_within(cmd.args(["--terminate", &d]), crate::update::WSL_LIMIT);
    }
}

/// `en` in the window's language (lang.rs), for words sent to the page:
/// notices, and the setup steps.
pub fn tr(en: &str) -> String {
    crate::lang::tr(crate::lang::resolve(prefs()["lang"].as_str()), en)
}

/// [`tr`] with `{name}` placeholders filled, as the page's tr() does.
pub fn trf(en: &str, vars: &[(&str, &dyn std::fmt::Display)]) -> String {
    crate::lang::fill(tr(en), vars)
}

fn set_pref(name: &str, value: Value) {
    if name == "watchBindMounts" {
        let on = value.as_bool().unwrap_or(false);
        if crate::watch::save_enabled(on).is_err() {
            emit(notice("error", &trf("Could not save the setting to {path}", &[("path", &"%LOCALAPPDATA%\\Kiri\\settings.json")])));
            emit(json!({"type": "prefs", "prefs": prefs()}).to_string());
            return;
        }
        crate::watch::set_enabled(crate::watch::is_enabled());
        emit(json!({"type": "prefs", "prefs": prefs()}).to_string());
        return;
    }
    if !matches!(name, "font" | "mono" | "scale" | "termH" | "termFs" | "termFont" | "domainsAsked" | "theme" | "accent" | "starAsked" | "updateAuto" | "lang" | "langAsked" | "closeButton" | "startAtLogin" | "stopOnQuit") {
        return;
    }
    let Some(path) = prefs_path() else { return };
    let mut p = prefs();
    p[name] = value;
    let tmp = path.with_extension("json.tmp");
    let saved = path.parent().map_or(Ok(()), std::fs::create_dir_all).and_then(|()| std::fs::write(&tmp, p.to_string())).and_then(|()| std::fs::rename(&tmp, &path));
    if saved.is_err() {
        emit(notice("error", &trf("Could not save the setting to {path}", &[("path", &"%LOCALAPPDATA%\\Kiri\\ui.json")])));
    }
}

/// A page link: only Kiri's own addresses, as on the Mac.
fn allowed_url(url: &str) -> bool {
    if matches!(
        url,
        "https://kiri.canestack.com"
            | "https://runkiri.com"
            | "https://runkiri.com/releases/"
            | "https://runkiri.com/share/notice"
            | "https://canestack.com"
            | "https://discord.gg/K5A8wuqcC"
            | "https://x.com/runkiri"
            | "https://learn.microsoft.com/windows/wsl/about"
            | "https://github.com/libracoder/kiri/issues/new"
            | "https://github.com/libracoder/kiri"
            | "https://github.com/anchore/grype"
            | "https://login.docker.com/activate"
            | "https://github.com/login/device"
    ) {
        return true;
    }
    // A build warning's rule page (docs.docker.com/go/dockerfile/rule/…).
    if url
        .strip_prefix("https://docs.docker.com/go/")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b"-/".contains(&b)))
    {
        return true;
    }
    let Some(rest) = url.strip_prefix("http://").or_else(|| url.strip_prefix("https://")) else { return false };
    // The authority is up to the first path/query/fragment. Reject credentials
    // (user@host, so the real host is after the @) and backslashes (which some
    // parsers treat as a separator), then take the host before the port.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') || authority.contains('\\') {
        return false;
    }
    let host = authority.split(':').next().unwrap_or("");
    host == "localhost" || host.ends_with(".kiri.localhost") || host.ends_with(".kiri.local")
}

#[cfg(test)]
mod tests {
    use super::{allowed_url, unanswered, wakes};
    use std::io::ErrorKind;

    #[test]
    fn roots_are_sent_when_they_change_or_the_engine_is_new() {
        assert!(super::roots_need_sending(None, "a", false));
        assert!(!super::roots_need_sending(Some("a"), "a", false));
        assert!(super::roots_need_sending(Some("a"), "b", false));
        assert!(super::roots_need_sending(Some("a"), "a", true));
    }

    /// As on the Mac and Linux: Stop on a stopped container, or Start on a
    /// running one, is done (Docker's 304, with no body), not an empty error.
    #[test]
    fn a_container_already_so_is_done_not_an_empty_error() {
        use super::{client::Response, expect_done};
        let answer = |status: u16, body: &str| Ok(Response { status, body: body.as_bytes().to_vec() });
        assert!(expect_done(answer(304, "")).is_ok(), "already stopped, or already running");
        assert!(expect_done(answer(204, "")).is_ok());
        let refused = expect_done(answer(409, r#"{"message":"cannot start a paused container, try unpause instead"}"#));
        assert_eq!(refused.unwrap_err().to_string(), "cannot start a paused container, try unpause instead");
        assert!(expect_done(Err(std::io::Error::other("no engine"))).is_err());
    }

    /// Only Start ends a Stop: Kiri coming up (the window, or hidden at
    /// login) starts the engine unless the person stopped it.
    #[test]
    fn a_launch_does_not_undo_a_stop() {
        assert!(wakes(false, Some(true)), "Start wakes a stopped engine");
        assert!(wakes(false, Some(false)));
        assert!(wakes(false, None), "Start wakes an engine whatever it said");
        assert!(wakes(true, Some(false)), "a launch starts an engine that was not stopped");
        assert!(!wakes(true, Some(true)), "a launch leaves a stopped engine stopped");
        // #93: an /info that did not answer at launch is not "not stopped".
        assert!(!wakes(true, None), "a launch that could not ask leaves a Stop alone");
    }

    /// Only a refused or absent engine shows as stopped; a slow answer
    /// keeps what the window shows, or shows booting at first.
    #[test]
    fn a_slow_engine_is_not_shown_stopped() {
        assert_eq!(unanswered(ErrorKind::TimedOut, true), None);
        assert_eq!(unanswered(ErrorKind::TimedOut, false), Some("booting"));
        assert_eq!(unanswered(ErrorKind::NotFound, true), Some("stopped"));
        assert_eq!(unanswered(ErrorKind::ConnectionRefused, false), Some("stopped"));
        assert_eq!(unanswered(ErrorKind::Other, true), Some("stopped"));
    }

    #[test]
    fn only_kiris_own_urls_open() {
        assert!(allowed_url("http://localhost:8080/app"));
        assert!(allowed_url("https://web.kiri.localhost/"));
        assert!(allowed_url("http://api.kiri.local"));
        assert!(allowed_url("https://runkiri.com"));
        assert!(allowed_url("https://runkiri.com/releases/"));
        assert!(allowed_url("https://runkiri.com/share/notice"));
        assert!(allowed_url("https://canestack.com"));
        assert!(allowed_url("https://discord.gg/K5A8wuqcC"));
        assert!(allowed_url("https://x.com/runkiri"));
        assert!(allowed_url("https://kiri.canestack.com"));
        assert!(allowed_url("https://github.com/libracoder/kiri"));
        assert!(allowed_url("https://github.com/libracoder/kiri/issues/new"));
        assert!(allowed_url("https://github.com/anchore/grype"));
        assert!(allowed_url("https://docs.docker.com/go/dockerfile/rule/from-as-casing/"));
        assert!(!allowed_url("http://evil.example/"));
        assert!(!allowed_url("https://runkiri.com.evil.com"));
        // Bypass attempts the audit found.
        assert!(!allowed_url("http://localhost:1@evil.example/"));
        assert!(!allowed_url("http://evil.example\\x.kiri.localhost"));
        assert!(!allowed_url("https://evil.example/#.kiri.localhost"));
        assert!(!allowed_url("ftp://localhost/"));
    }

    #[test]
    fn background_engine_checks_mark_background_and_wake_does_not() {
        let info = super::client::mock_reply(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n{\"KiriStopped\":true}");
        assert_eq!(super::stopped(), Some(true));
        let req = String::from_utf8(info.lock().unwrap().clone()).unwrap();
        assert!(req.contains("\r\nX-Kiri-Background: 1\r\n"), "stopped() must mark background: {req}");

        let wake_wire = super::client::mock_reply(b"HTTP/1.1 204 No Content\r\n\r\n");
        super::wake().unwrap();
        let req = String::from_utf8(wake_wire.lock().unwrap().clone()).unwrap();
        assert!(req.starts_with("POST /kiri/wake HTTP/1.1\r\n"), "{req}");
        assert!(!req.contains("X-Kiri-Background"), "wake() must not mark background: {req}");

        let proxy_get = super::client::mock_reply(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"settings\":{}}");
        let proxy_put = super::client::mock_reply(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
        super::push_windows_proxy(serde_json::json!({"http": null, "https": null, "no_proxy": [], "pac": false}), |_| std::collections::HashMap::new());
        let get_req = String::from_utf8(proxy_get.lock().unwrap().clone()).unwrap();
        let put_req = String::from_utf8(proxy_put.lock().unwrap().clone()).unwrap();
        assert!(get_req.starts_with("GET /kiri/proxy HTTP/1.1\r\n") && get_req.contains("\r\nX-Kiri-Background: 1\r\n"), "{get_req}");
        assert!(put_req.starts_with("PUT /kiri/proxy/system HTTP/1.1\r\n") && put_req.contains("\r\nX-Kiri-Background: 1\r\n"), "{put_req}");
    }

    #[test]
    fn saves_stop_on_quit_and_start_at_login_prefs() {
        let dir = std::env::temp_dir().join(format!("kiri-win-prefs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let old = std::env::var_os("LOCALAPPDATA");
        // SAFETY: serialized within this test binary's prefs test.
        unsafe { std::env::set_var("LOCALAPPDATA", &dir) };
        assert_eq!(super::prefs()["stopOnQuit"], false);
        super::set_pref("stopOnQuit", serde_json::json!(true));
        assert_eq!(super::prefs()["stopOnQuit"], true);
        super::set_pref("stopOnQuit", serde_json::json!(false));
        assert_eq!(super::prefs()["stopOnQuit"], false);
        super::set_pref("startAtLogin", serde_json::json!(false));
        assert_eq!(super::prefs()["startAtLogin"], false);
        super::set_pref("startAtLogin", serde_json::json!(true));
        assert_eq!(super::prefs()["startAtLogin"], true);
        match old {
            Some(v) => unsafe { std::env::set_var("LOCALAPPDATA", v) },
            None => unsafe { std::env::remove_var("LOCALAPPDATA") },
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn npipe_host_formats_pipe_url() {
        assert_eq!(super::npipe_host(r"\\.\pipe\kiri"), "npipe:////./pipe/kiri");
    }
}

/// The page's "fonts" event, made once (the window asks each time Settings
/// opens without them). Fonts installed later show after a restart.
fn fonts_event() -> &'static str {
    static EVENT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    EVENT.get_or_init(|| json!({"type": "fonts", "families": crate::app::font_families(false), "mono": crate::app::font_families(true)}).to_string())
}

/// Handles one message from the page, on the window's thread: quick things
/// here, the rest on the engine thread or a thread of their own.
pub fn on_message(msg: &str) {
    let Ok(c) = serde_json::from_str::<PageCmd>(msg) else { return };
    // Ids and container names are plain tokens; anything else is not from
    // the page as written, and never reaches a request line.
    let plain = |s: &str| s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b));
    if !plain(&c.id) || (matches!(c.cmd.as_str(), "files" | "preview" | "download" | "terminal") && !plain(&c.name)) {
        return;
    }
    match c.cmd.as_str() {
        // An uncaught error in the page (the shim in app.rs reports it).
        "jserror" => crate::serve::log(&format!("page: {}", c.name.chars().take(300).collect::<String>())),
        "ready" => {
            // Listing the fonts is slow the first time: done now, off the
            // window's thread, so Settings has them at once.
            std::thread::spawn(|| {
                std::thread::sleep(Duration::from_secs(3));
                fonts_event();
            });
            emit(json!({"type": "prefs", "prefs": prefs()}).to_string());
            // KIRI_STAR_PROMPT=1 shows the star card now, as on the Mac.
            if std::env::var_os("KIRI_STAR_PROMPT").is_some() {
                emit(r#"{"type":"starprompt"}"#.to_owned());
            }
            emit(domains_event());
            emit_docker_state();
            std::thread::spawn(crate::storage::emit_report);
            ask_language();
            // The first time, offer <name>.kiri.local, as the Mac does.
            if !crate::dns::installed() && crate::dns::serving() && prefs()["domainsAsked"] != true {
                set_pref("domainsAsked", json!(true));
                emit(r#"{"type":"welcome"}"#.to_owned());
            }
            // Which builder docker build uses: made so, and asked once with
            // another engine here (the Mac's welcome comes first, as there).
            std::thread::spawn(|| {
                build_with();
                if let Some(engine) = crate::buildwith::ask() {
                    emit(json!({"type": "buildask", "engine": engine}).to_string());
                }
                emit(crate::buildwith::event());
            });
            send(Cmd::Refresh);
            // Opening the window starts Kiri, unless it was stopped: that waits
            // for Start (except when quitting stopped it with stopOnQuit).
            send(if prefs()["stopOnQuit"] == true { Cmd::Start } else { Cmd::Launch });
            // Anything newer than this build, and a staged update not yet in.
            crate::update::check_now(false);
            // For checking the page by hand in a debug build.
            if cfg!(debug_assertions) {
                if let Ok(js) = std::env::var("KIRI_UI_EVAL") {
                    Handle.eval(js);
                }
            }
        }
        "start" => send(Cmd::Start),
        "stop" => send(Cmd::Stop),
        "refresh" => send(Cmd::Refresh),
        "pull" => {
            static RUN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let run = RUN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            PULLING.lock().unwrap_or_else(PoisonError::into_inner).push(Pulling { run, name: c.name.trim().to_owned(), taken: false, closer: None, cancelled: false });
            send(Cmd::Pull(c.name));
        }
        // Cancel on a pull's row, as on the Mac.
        "cancelpull" => cancel_pull(c.name.trim()),
        // Pull image's suggestions, from Docker Hub through a cache.
        "hubsearch" => crate::hub::ask(crate::hub::Kind::Search, c.name, emit),
        "hubtags" => crate::hub::ask(crate::hub::Kind::Tags, c.name, emit),
        "rmi" => send(Cmd::RemoveImage(c.name)),
        "run" => {
            let env = c.value.as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect()).unwrap_or_default();
            send(Cmd::Run(c.name, env));
        }
        "container" => send(Cmd::Container { action: c.action, id: c.id }),
        "ports" => send(Cmd::Ports { id: c.id, ports: c.ports }),
        "env" => {
            let env = c.value.as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect()).unwrap_or_default();
            send(Cmd::Env { id: c.id, env });
        }
        "rmvol" => send(Cmd::RemoveVolume(c.name)),
        "rmnet" => send(Cmd::RemoveNetwork(c.id)),
        "about" => send(Cmd::About),
        // Settings → Builds and the first-run question; with a value, switches.
        "buildwith" => {
            let with = c.value.as_str().and_then(crate::buildwith::With::parse);
            std::thread::spawn(move || {
                if let Some(with) = with
                    && let Err(e) = crate::buildwith::choose(with)
                {
                    emit(notice("error", &trf("Couldn't change which builder docker build uses: {error}", &[("error", &e)])));
                }
                emit(crate::buildwith::event());
            });
        }
        "buildprune" => {
            std::thread::spawn(|| {
                let e = match client::request("POST", "/build/prune?all=1", None) {
                    Ok(r) if r.ok() => json!({"type": "buildpruned", "freed": r.json()["SpaceReclaimed"]}),
                    Ok(r) => json!({"type": "buildpruned", "error": r.error()}),
                    Err(e) => json!({"type": "buildpruned", "error": e.to_string()}),
                };
                emit(e.to_string());
                send(Cmd::Refresh);
            });
        }
        "buildersettings" => {
            std::thread::spawn(|| builder_settings(None));
        }
        "setbuildersettings" => {
            let body = c.value;
            std::thread::spawn(move || builder_settings(Some(body)));
        }
        // macOS-only settings: report unsupported cleanly on Windows.
        "vmnet" => emit(json!({"type": "vmnet", "supported": false}).to_string()),
        "setvmnet" => {}
        "shellpath" => emit(json!({"type": "shellpath", "supported": false}).to_string()),
        "setshellpath" => {}
        "uninstall" => emit(notice("error", &tr("Uninstall Kiri from Windows Settings → Apps"))),
        // Config update can be done synchronously or off-thread.
        "usecontext" => {
            std::thread::spawn(move || use_context(&c.name));
        }
        "dockersock" => emit_docker_state(),
        // The Kubernetes section: Pods, Services, a pod's logs, Start.
        "k8s" => crate::k8s::handle(&c.action, &c.value),
        // Share: public links for a port or container, and the Share account.
        "shares" => sharing::list(),
        "share" => sharing::open(c.name, c.value.as_str().unwrap_or_default().to_owned()),
        // A Kubernetes service or pod: value {ip, port, label}.
        "k8sshare" => {
            let v = &c.value;
            let port = v["port"].as_u64().and_then(|p| u16::try_from(p).ok()).unwrap_or(0);
            sharing::open_k8s(c.name, v["ip"].as_str().unwrap_or_default().to_owned(), port, v["label"].as_str().unwrap_or_default().to_owned(), v["name"].as_str().unwrap_or_default().to_owned());
        }
        "shareusage" => sharing::usage(),
        // The account's live tunnels from every computer, and closing one this window didn't open.
        "sharetunnels" => sharing::tunnels(),
        "sharetraffic" => sharing::traffic(),
        "usage" => {
            std::thread::spawn(|| emit(usage::event()));
        }
        "sharestop" => sharing::stop_tunnel(c.name),
        "sharebrowse" => sharing::browse_tunnel(&c.name),
        "unshare" => sharing::close(c.id.parse().unwrap_or(0)),
        "shareopen" => sharing::browse(c.id.parse().unwrap_or(0)),
        "sharelogin" => sharing::sign_in(),
        "sharecancel" => sharing::cancel_sign_in(),
        "sharelogout" => sharing::sign_out(),
        // The built-in terminal: its shells, and its own clipboard and links.
        "term" => match c.name.as_str() {
            // A selection can be a whole screen of output.
            "copy" => {
                if let Some(text) = c.value.as_str().filter(|t| !t.is_empty() && t.len() <= crate::term::COPY_MAX)
                    && clipboard(text).is_err()
                {
                    emit(notice("error", &tr("Couldn't copy to the clipboard")));
                }
            }
            "paste" => {
                let id = c.id;
                crate::term::paste(move |text| emit(crate::term::paste_event(&id, &text)));
            }
            // A link in a shell's output: web pages only, never a file or an app's scheme.
            "link" => {
                if let Some(url) = c.value.as_str().filter(|u| crate::term::web_link(u)) {
                    crate::app::open_url(url);
                }
            }
            action => crate::term::handle(action, &c.id, &c.value, emit),
        },
        // The page can't write the clipboard itself; IDs and short text only.
        "copy" => {
            if !c.name.is_empty() && c.name.len() <= 4096 && clipboard(&c.name).is_err() {
                emit(notice("error", &tr("Couldn't copy to the clipboard")));
            }
        }
        // About's Check now.
        "updatecheck" => crate::update::check_now(true),
        // The update card and the status bar's update chip.
        "updatedownload" => crate::update::download_now(),
        "updatecancel" => crate::update::cancel_download(),
        "updaterestart" => crate::update::restart_now(),
        "restartengine" => crate::update::restart_engine_now(),
        // What's new: the feed names the page, so only runkiri.com's.
        "updatenotes" => {
            if c.name.strip_prefix("https://runkiri.com/").is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~/#".contains(&b))) {
                crate::app::open_url(&c.name);
            }
        }
        "restartvm" => crate::wslconfig::restart(),
        "inspect" => detail::inspect(c.id),
        "logs" => detail::logs(c.id),
        "logsstop" => detail::stop_logs(),
        // Registries signed in to, signing in (checked by the engine first) and out.
        "logins" | "login" | "logout" => logins::handle(&c.cmd, c.name, &c.value, emit, || Ok(())),
        "weblogin" | "webloginopen" | "webloginmfa" | "webloginsso" | "weblogincancel" | "awsprofiles" => weblogin::handle(&c.cmd, c.name, &c.value, emit, || Ok(()), crate::term::captured),
        // Compose: projects, a project's file, what Apply would do, Apply, logs.
        "composeprojects" | "composefile" | "composeplan" | "composeapply" | "composelogs" | "composeforget" | "composecancel" | "composerestore" | "composeaction" => compose::handle(&c.cmd, c.name, &c.value, compose_cli, compose_store, emit),
        // Open a compose file…: Windows' own dialog, on the window's thread;
        // the path it gives stays here, the page gets the project.
        "composeopen" => crate::app::pick_file(&tr("Open a compose file"), &[(tr("Compose files"), compose::FILE_NAMES.join(";")), (tr("YAML files"), "*.yaml;*.yml".to_owned())], |path| compose::picked(path, compose_cli, compose_store, emit)),
        // Before Run: what the image's start script won't start without.
        "needs" => {
            let image = c.name;
            std::thread::spawn(move || emit(needs::event(&image)));
        }
        // A container that stopped: its last lines, for why.
        "lastlogs" => detail::last_logs(c.id),
        "stats" => detail::stats(c.id),
        "statsstop" => detail::stop_stats(),
        "exec" => detail::exec(c.id, c.path),
        "files" => detail::files(c.name, c.path),
        "preview" => detail::preview(c.name, c.path),
        "download" => detail::download(c.name, c.path),
        "reveal" => emit(notice("error", &tr("Container files are not on Windows' disk: use Save to Downloads"))),
        "terminal" => detail::terminal(&c.name, &env().pipe),
        "open" => {
            if allowed_url(&c.name) {
                crate::app::open_url(&c.name);
            }
        }
        "setpref" => {
            if c.name == "theme" {
                let theme = c.value.as_str().unwrap_or("").to_owned();
                Handle.run(move |ui| ui.set_theme(&theme));
            }
            let start_login = (c.name == "startAtLogin").then(|| c.value.as_bool()).flatten();
            set_pref(&c.name, c.value);
            if let Some(on) = start_login {
                std::thread::spawn(move || {
                    if let Err(e) = crate::setup::set_start_at_login(on) {
                        crate::serve::log(&format!("start at sign-in: {e}"));
                        set_pref("startAtLogin", (!on).into());
                        emit(notice("error", &e.to_string()));
                        emit(json!({"type": "prefs", "prefs": prefs()}).to_string());
                    }
                });
            }
        }
        // A language the page doesn't carry yet (the main window and setup open
        // with one; setup's langwords comes here too, not being a setup- command):
        // its words, which the page adds and shows if it's the one picked.
        "langwords" => {
            if let Some(js) = crate::lang::words_js(&c.name) {
                Handle.eval(js);
            }
        }
        // Off the window's thread: GDI lists every installed face, twice.
        "fonts" => {
            std::thread::spawn(|| emit(fonts_event().to_owned()));
        }
        "proxy" => {
            std::thread::spawn(|| proxy(None));
        }
        "setproxy" => {
            let body = c.value;
            std::thread::spawn(move || proxy(Some(body)));
        }
        // Settings → Registries: daemon.json's lists, in the engine's distro.
        "registryconfig" => {
            std::thread::spawn(|| registry_config(None));
        }
        "setregistryconfig" => {
            let body = c.value;
            std::thread::spawn(move || registry_config(Some(body)));
        }
        // Settings → Resources: WSL's CPUs and memory, in .wslconfig.
        "resources" => crate::wslconfig::resources(None),
        "setresources" => crate::wslconfig::resources(Some(c.value)),
        "domains" => domains(c.value.as_bool().unwrap_or(false)),
        "routerports" => {
            std::thread::spawn(|| router_ports(None));
        }
        "setrouterports" => {
            let body = c.value;
            std::thread::spawn(move || router_ports(Some(body)));
        }
        // The USB view: usbipd-win's devices, and which are in WSL.
        "usb" => {
            std::thread::spawn(|| emit(crate::usb::list().to_string()));
        }
        "usbattach" | "usbdetach" | "usbinstall" => crate::usb::handle(if c.cmd == "usbattach" { "usbattach" } else if c.cmd == "usbdetach" { "usbdetach" } else { "usbinstall" }, c.name),
        // The Builds view: BuildKit's history, read only while the view is open.
        "builds" => {
            std::thread::spawn(|| emit(builds_event()));
        }
        "build" => {
            std::thread::spawn(move || {
                emit(match crate::builds::detail(&c.name, &c.id) {
                    Ok(mut b) => {
                        b["type"] = "build".into();
                        b
                    }
                    Err(e) => json!({"type": "build", "builder": c.name, "id": c.id, "error": {"message": e.to_string()}, "steps": [], "failed": true}),
                }
                .to_string());
            });
        }
        // Builds → Layers: the image a build made.
        "buildlayers" => {
            std::thread::spawn(move || {
                emit(match crate::builds::layers(&c.name, &c.id) {
                    Ok(mut l) => {
                        l["type"] = "buildlayers".into();
                        l
                    }
                    Err(e) => json!({"type": "buildlayers", "builder": c.name, "id": c.id, "error": e.to_string()}),
                }
                .to_string());
            });
        }
        // Images → an image's layers, read by the engine in WSL (crate::scan).
        "imagelayers" => {
            std::thread::spawn(move || {
                emit(match crate::scan::image_layers(&c.name) {
                    Ok(mut l) => {
                        l["type"] = "imagelayers".into();
                        l
                    }
                    Err(e) => json!({"type": "imagelayers", "name": c.name, "error": e.to_string()}),
                }
                .to_string());
            });
        }
        // Security: scan an image (name or ID) with Grype, or show its last scan.
        "scan" => {
            std::thread::spawn(move || {
                let name = c.name;
                let mut last = (String::new(), 255u8);
                let r = crate::scan::scan(&name, &mut |phase, pct| {
                    if (phase, pct) != (last.0.as_str(), last.1) {
                        last = (phase.to_owned(), pct);
                        emit(json!({"type": "scanprogress", "name": name, "phase": phase, "pct": pct}).to_string());
                    }
                });
                emit(match r {
                    Ok(res) => json!({"type": "scanresult", "name": name, "result": res}),
                    Err(e) => json!({"type": "scanresult", "name": name, "error": e.to_string()}),
                }
                .to_string());
            });
        }
        // An image's scan history, or one scan of it (`id` its time).
        "scanhistory" => {
            std::thread::spawn(move || {
                emit(match crate::scan::history(&c.name) {
                    Ok(h) => json!({"type": "scanhistory", "name": c.name, "scans": h["scans"]}),
                    Err(e) => json!({"type": "scanhistory", "name": c.name, "error": e.to_string()}),
                }
                .to_string());
            });
        }
        "scanopen" => {
            std::thread::spawn(move || {
                emit(match crate::scan::open(&c.name, c.id.parse::<u64>().ok()) {
                    Ok(res) => json!({"type": "scanresult", "name": c.name, "result": res}),
                    Err(e) => json!({"type": "scanresult", "name": c.name, "error": e.to_string()}),
                }
                .to_string());
            });
        }
        "savesbom" => {
            std::thread::spawn(move || match crate::scan::save_sbom(&c.name, c.id.parse().unwrap_or(0), &c.path) {
                Ok(to) => {
                    emit(notice("ok", &trf("Saved the SBOM to Downloads as {file}", &[("file", &to.file_name().unwrap_or_default().to_string_lossy())])));
                    crate::app::reveal(&to);
                }
                Err(e) => emit(notice("error", &trf("Could not save the SBOM: {error}", &[("error", &e)]))),
            });
        }
        "advisory" => crate::scan::open_advisory(&c.name),
        "rmbuild" => {
            std::thread::spawn(move || {
                if let Err(e) = crate::builds::remove(&c.name, &c.id) {
                    emit(notice("error", &trf("Couldn't remove the build: {error}", &[("error", &e)])));
                }
                emit(builds_event());
            });
        }
        // Settings → Storage: where WSL keeps Kiri's VHDX, and moving it.
        "storage" => {
            std::thread::spawn(crate::storage::emit_report);
        }
        "volumesizes" => {
            spawn_volume_sizes();
        }
        "storagepick" => {
            crate::app::pick_folder(&tr("Choose a storage folder"), |path| {
                if let Some(p) = path {
                    let s = p.to_string_lossy().into_owned();
                    std::thread::spawn(move || crate::storage::check_and_emit(Some(s), false, false));
                }
            });
        }
        "storagecheck" => {
            let path = (!c.path.trim().is_empty()).then(|| c.path.clone());
            let fresh = c.value["fresh"] == true;
            let reset = c.value["reset"] == true;
            std::thread::spawn(move || crate::storage::check_and_emit(path, fresh, reset));
        }
        "storagemove" => {
            let path = (!c.path.trim().is_empty()).then(|| c.path.clone());
            let fresh = c.value["fresh"] == true;
            crate::storage::start_move(path, fresh);
        }
        "storagereset" => crate::storage::reset(),
        "storageretry" => crate::storage::retry(),
        "storageremoveold" => crate::storage::remove_old(),
        "storagereclaim" => crate::storage::reclaim(),
        "storageprune" => {
            std::thread::spawn(storage_prune);
        }
        // Settings → Diagnostics and an error's Details: crate::diag.
        cmd @ ("diaglogs" | "diagreport" | "diagsend" | "diagcrashes" | "diagsendcrash" | "diagfolder") => {
            crate::diag::handle(cmd, c.name, c.id, &c.value);
        }
        // Settings → Import, from Docker Desktop: as on the Mac and Linux.
        "importsources" => {
            std::thread::spawn(|| emit(json!({"type": "importsources", "sources": crate::import::sources()}).to_string()));
        }
        "inventory" => {
            let source = c.name;
            std::thread::spawn(move || {
                let event = match crate::import::inventory(&source) {
                    Ok(mut v) => {
                        v["type"] = "inventory".into();
                        v
                    }
                    Err(e) => json!({"type": "inventory", "source": source, "error": e.to_string()}),
                };
                emit(event.to_string());
            });
        }
        "import" => {
            let (source, picked) = (c.name, c.value);
            std::thread::spawn(move || {
                let (mut done, mut failed) = (0, 0);
                for (kind, f) in [("images", crate::import::image as fn(&str, &str) -> std::io::Result<()>), ("volumes", crate::import::volume), ("containers", crate::import::container)] {
                    for name in picked[kind].as_array().into_iter().flatten().filter_map(|v| v.as_str()) {
                        emit(json!({"type": "importstep", "kind": kind, "name": name, "state": "running"}).to_string());
                        match f(&source, name) {
                            Ok(()) => {
                                done += 1;
                                emit(json!({"type": "importstep", "kind": kind, "name": name, "state": "done"}).to_string());
                            }
                            Err(e) => {
                                failed += 1;
                                emit(json!({"type": "importstep", "kind": kind, "name": name, "state": "error", "error": e.to_string()}).to_string());
                            }
                        }
                    }
                }
                emit(json!({"type": "importdone", "done": done, "failed": failed}).to_string());
                send(Cmd::Refresh);
            });
        }
        "zoom" => Handle.run(crate::app::Ui::toggle_maximized),
        // The window has Windows' own title bar to drag.
        "drag" | "toolsretry" => {}
        _ => {}
    }
}

/// Windows' proxy, from Internet Settings, for the daemon's "system" mode:
/// `{http, https, no_proxy, pac}`. ProxyServer is `host:port` for every
/// protocol, or `http=host:port;https=host:port`.
fn windows_proxy() -> Value {
    let mut cmd = crate::win::tool("reg");
    std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);
    let out = cmd.args(["query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"]).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    let field = |name: &str| out.lines().find_map(|l| {
        let mut p = l.split_whitespace();
        (p.next()? == name).then(|| p.skip(1).collect::<Vec<_>>().join(" "))
    });
    let enabled = field("ProxyEnable").is_some_and(|v| v == "0x1");
    let server = if enabled { field("ProxyServer").unwrap_or_default() } else { String::new() };
    let (mut http, mut https) = (None, None);
    if server.contains('=') {
        for part in server.split(';') {
            match part.split_once('=') {
                Some(("http", v)) => http = Some(v.to_owned()),
                Some(("https", v)) => https = Some(v.to_owned()),
                _ => {}
            }
        }
    } else if !server.is_empty() {
        (http, https) = (Some(server.clone()), Some(server));
    }
    let no_proxy: Vec<String> = if enabled {
        field("ProxyOverride").unwrap_or_default().split(';').map(str::trim).filter(|h| !h.is_empty() && *h != "<local>").map(str::to_owned).collect()
    } else {
        Vec::new()
    };
    json!({"http": http, "https": https, "no_proxy": no_proxy, "pac": field("AutoConfigURL").is_some()})
}

/// Tells the daemon what Windows' proxy is. A proxy on Windows' own
/// 127.0.0.1 (Windows' or one set in Settings → Network) is reached through
/// the relay (relay.rs), and the daemon gets its ports too. Sent every
/// minute, so marked as the window's own: it never keeps the VM awake.
pub(crate) fn send_windows_proxy() {
    push_windows_proxy(windows_proxy(), crate::relay::ports);
}

fn push_windows_proxy(mut body: Value, relay_ports: impl FnOnce(&[u16]) -> std::collections::HashMap<u16, u16>) {
    let custom = client::get_background("/kiri/proxy").map(|v| v["settings"].clone()).unwrap_or_default();
    let mut targets: Vec<u16> = [&body["http"], &body["https"], &custom["http"], &custom["https"]]
        .iter()
        .filter_map(|v| v.as_str())
        .filter_map(|u| crate::hostrelay::loopback(u).map(|l| l.0))
        .collect();
    targets.sort_unstable();
    targets.dedup();
    let relay = relay_ports(&targets);
    body["relay"] = relay.iter().map(|(t, l)| (t.to_string(), json!(l))).collect::<serde_json::Map<_, _>>().into();
    let _ = client::request_with("PUT", "/kiri/proxy/system", Some(&body), true);
}

/// The Windows store's root certificates for the daemon in WSL (#303): the
/// ones the bundled set lacks (a company root, Group Policy's) and the
/// distrusted ones, so pulls trust what Windows trusts, as on the Mac.
/// The daemon keeps them and only acts on a change, so they are sent when
/// they differ from what was last sent, or when `force` (the engine has just
/// started, and may be a new one). Marked as the window's own (background) so
/// periodic sends never keep the VM awake.
pub(crate) fn send_windows_roots(force: bool) {
    static SENT: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
    let host = crate::roots::host_export();
    let list = |l: &[rustls_pki_types::CertificateDer<'static>]| l.iter().map(|c| crate::roots::hex(c)).collect::<Vec<_>>();
    let body = json!({"certs": list(&host.certs), "distrusted": list(&host.distrusted)});
    let digest = {
        use sha2::{Digest, Sha256};
        Sha256::digest(body.to_string().as_bytes()).iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    let mut last = SENT.lock().unwrap_or_else(|e| e.into_inner());
    if !roots_need_sending(last.as_deref(), &digest, force) {
        return;
    }
    // Kept only once the daemon took them, so a failed send is tried again.
    if client::request_with("PUT", "/kiri/roots/host", Some(&body), true).is_ok_and(|r| r.ok()) {
        *last = Some(digest);
    }
}

/// Whether the roots with `digest` go to the daemon: they changed since
/// `last` was sent, nothing was sent yet, or `force`.
fn roots_need_sending(last: Option<&str>, digest: &str, force: bool) -> bool {
    force || last != Some(digest)
}

/// Settings → Domains: reads (or moves, then reads) the routers' ports. The
/// routers listen on WSL's loopback; WSL forwards their port to Windows'.
fn router_ports(set: Option<Value>) {
    if let Some(body) = set {
        match expect_ok(client::request("POST", "/kiri/domains", Some(&body))) {
            Ok(()) => emit(notice("ok", &tr("Ports changed"))),
            Err(e) => emit(notice("error", &trf("Could not change the ports: {error}", &[("error", &e)]))),
        }
    }
    let mut v = client::get("/kiri/domains").unwrap_or_else(|e| json!({"error": e.to_string()}));
    v["type"] = json!("routerports");
    emit(v.to_string());
}

/// Settings → Network: the daemon's proxy settings.
fn proxy(set: Option<Value>) {
    send_windows_proxy();
    if let Some(body) = set {
        match expect_ok(client::request("POST", "/kiri/proxy", Some(&body))) {
            Ok(()) => {
                // A custom proxy on Windows' loopback needs the relay too.
                send_windows_proxy();
                emit(notice("ok", &tr("Proxy settings saved")));
            }
            Err(e) => emit(notice("error", &trf("Could not save the proxy settings: {error}", &[("error", &e)]))),
        }
    }
    let ev = match client::get("/kiri/proxy") {
        Ok(v) => {
            let mut v = v;
            v["type"] = json!("proxy");
            v
        }
        Err(e) => json!({"type": "proxy", "error": e.to_string()}),
    };
    emit(ev.to_string());
}

/// Settings → Registries: the engine's daemon.json (in its WSL distro):
/// insecure registries and Docker Hub mirrors.
/// The answer to a save says whether it was saved (`saved`), so the page
/// knows its own save's answer from a read that crossed it.
fn registry_config(set: Option<Value>) {
    let saved = set.map(|body| match expect_ok(client::request("POST", "/kiri/registries", Some(&body))) {
        Ok(()) => {
            emit(notice("ok", &tr("Registry settings saved")));
            true
        }
        Err(e) => {
            emit(notice("error", &trf("Could not save the registry settings: {error}", &[("error", &e)])));
            false
        }
    });
    let mut ev = match client::get("/kiri/registries") {
        Ok(v) => v,
        Err(e) => json!({"error": e.to_string()}),
    };
    ev["type"] = json!("registryconfig");
    if let Some(saved) = saved {
        ev["saved"] = json!(saved);
    }
    emit(ev.to_string());
}

fn storage_prune() {
    let mut freed = 0u64;
    let mut containers = 0usize;
    let mut images = 0usize;
    let mut err: Option<String> = None;
    for (endpoint, kind) in [("/containers/prune", "c"), ("/images/prune", "i"), ("/build/prune?all=1", "b")] {
        match client::request("POST", endpoint, None) {
            Ok(r) if r.ok() => {
                let v = r.json();
                freed = freed.saturating_add(v["SpaceReclaimed"].as_u64().unwrap_or(0));
                if kind == "c" {
                    containers = v["ContainersDeleted"].as_array().map_or(0, Vec::len);
                } else if kind == "i" {
                    images = v["ImagesDeleted"].as_array().map_or(0, Vec::len);
                }
            }
            Ok(r) => {
                err = Some(r.error());
                break;
            }
            Err(e) => {
                err = Some(e.to_string());
                break;
            }
        }
    }
    let ev = match err {
        Some(e) => json!({"type": "storagepruned", "error": e}),
        None => json!({"type": "storagepruned", "freed": freed, "containers": containers, "images": images}),
    };
    emit(ev.to_string());
    crate::storage::emit_report();
    send(Cmd::Refresh);
}

fn builder_settings(save: Option<Value>) {
    if let Some(body) = save {
        match client::request("POST", "/kiri/builder", Some(&body)) {
            Ok(r) if r.ok() => {
                let mut v = r.json();
                v["type"] = json!("buildersettings");
                emit(v.to_string());
                emit(notice("ok", &tr("Builder settings saved")));
                return;
            }
            Ok(r) => emit(notice("error", &trf("Could not save builder settings: {error}", &[("error", &r.error())]))),
            Err(e) => emit(notice("error", &trf("Could not save builder settings: {error}", &[("error", &e)]))),
        }
    }
    let mut ev = client::get_background("/kiri/builder").unwrap_or_else(|e| json!({"error": e.to_string()}));
    ev["type"] = json!("buildersettings");
    emit(ev.to_string());
}

/// Volumes view: reads each volume's disk usage asynchronously without waking
/// a sleeping VM or touching WSL while stopped. Single-flight with coalesced
/// re-run so repeated UI messages never accumulate background threads.
fn spawn_volume_sizes() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static BUSY: AtomicBool = AtomicBool::new(false);
    static RERUN: AtomicBool = AtomicBool::new(false);

    if BUSY.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
        RERUN.store(true, Ordering::Release);
        return;
    }
    std::thread::spawn(|| {
        struct Guard<'a>(&'a AtomicBool);
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _guard = Guard(&BUSY);
        loop {
            RERUN.store(false, Ordering::Release);
            let sizes = if crate::serve::is_stopped() {
                json!({})
            } else {
                client::get_background("/kiri/volumes/sizes")
                    .ok()
                    .and_then(|v| v.get("sizes").filter(|s| s.is_object()).cloned())
                    .unwrap_or_else(|| json!({}))
            };
            emit(json!({"type": "volumesizes", "sizes": sizes}).to_string());
            if !RERUN.swap(false, Ordering::AcqRel) {
                break;
            }
        }
    });
}

/// The tray's commands.
pub fn on_tray(cmd: &str) {
    match cmd {
        "start" => send(Cmd::Start),
        "stop" => send(Cmd::Stop),
        "update" => crate::update::check_now(true),
        c => {
            if let Some(id) = c.strip_prefix("container:") {
                emit(json!({"type": "detail", "id": id}).to_string());
            }
        }
    }
}
