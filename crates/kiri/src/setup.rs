//! `kiri setup`: makes this Mac use Kiri the way OrbStack's installer does,
//! without touching anything another engine owns.
//!
//! - a `kiri` docker context (`--use` also makes it the current one)
//! - a LaunchAgent that starts `kiri daemon` at login (`--no-agent` skips it)
//! - the app's bundled `docker`, Compose and buildx, when run from Kiri.app
//! - `docker` and `kiri` in `~/.kiri/bin`, which a marked line in the shell
//!   profiles (zsh's, bash's, and fish's if used) adds to the end of PATH
//!   once (`--no-profiles` skips the profile edits and takes back any Kiri
//!   added), so a docker CLI already installed keeps priority; and
//!   `/usr/local/bin/kiri` when that directory is the user's
//! - on a Mac with no other Docker engine, `kiri` as docker's default context
//! - a buildx builder, `kiri-build`, that loads what it builds into Kiri,
//!   and the choice of builder for plain `docker build` (src/buildwith.rs)
//! - `*.kiri.local` names for containers: `/etc/resolver/kiri.local`, which
//!   needs an administrator once (`--no-domains` skips it; `--domains` does
//!   only this)
//! - `/var/run/docker.sock` linked to Kiri's socket, for tools that ignore
//!   docker contexts (docker-py, Go's `client.FromEnv`, docker-java,
//!   Testcontainers, IDE plugins), when no other engine has it: asked for
//!   with `*.kiri.local`'s password (`--docker-socket` does only this), and
//!   put back at boot by a LaunchDaemon. Until then, or if the password is
//!   declined, `~/.testcontainers.properties` points Testcontainers at Kiri,
//!   unless the user has a file of their own there
//!
//! `kiri setup --uninstall` takes back exactly those, and the `kiri` kubectl
//! context that `kiri k8s` adds.
//!
//! Kiri Dev (src/flavor.rs) sets up only its own: the `kiri-dev` context,
//! its LaunchAgent, its builder and `~/.kiri-dev/bin`. PATH, docker's
//! default context and `*.kiri.local` stay the installed Kiri's.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

// The bundle identifier (`APP_ID`) named in the LaunchAgent makes macOS
// say "Kiri" in Login Items, rather than the name on the signing
// certificate.
use crate::flavor::{AGENT, APP_ID, CONTEXT, dev};

use crate::builds::{BUILDER, builder};
pub use crate::builds::ensure_builder;

/// `~/.kiri/bin`, or `~/.kiri-dev/bin`.
fn bin_dir() -> io::Result<PathBuf> {
    Ok(home()?.join(crate::flavor::STATE.get()).join("bin"))
}

use crate::dockerctx::{Endpoint, read_json, write_json};

fn home() -> io::Result<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| io::Error::other("HOME is not set"))
}

fn docker_dir() -> io::Result<PathBuf> {
    crate::dockerctx::docker_dir().ok_or_else(|| io::Error::other("HOME is not set"))
}

/// The docker CLI's directory for a context: named by the SHA-256 of its name.
fn context_dir(name: &str) -> io::Result<PathBuf> {
    let digest = kiri_image::store::sha256_digest(name.as_bytes());
    Ok(docker_dir()?.join("contexts/meta").join(digest.trim_start_matches("sha256:")))
}

/// Kiri.app's `Contents`, when this binary runs from the app.
fn bundle_contents() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
    let contents = exe.parent()?.parent()?.to_path_buf();
    contents.join("Info.plist").is_file().then_some(contents)
}

/// Whether this process is Kiri.app being opened from Finder or the Dock:
/// the app's binary, started by launchd (LaunchServices), not from a shell,
/// where running it bare must not change anything.
pub fn launched_from_app() -> bool {
    // SAFETY: getppid cannot fail.
    bundle_contents().is_some() && unsafe { libc::getppid() } == 1
}

/// The first time the app opens: the same as `kiri setup`, quietly, except
/// `*.kiri.local`, which the window offers and the user chooses. It never
/// stops the window opening (#250): each step runs on its own, and the ones
/// that fail wait in the window's setup checklist (`undone`) with their
/// errors. Without the login item, the window starts the engine itself
/// (update::start_engine).
pub fn first_launch() {
    let set_up = agent_plist().and_then(|p| Ok(p.is_file() && agent_runs_this()?)).map_err(step("checking how Kiri starts at login"));
    // Not knowing is not set up: the steps run, and say what failed.
    let set_up = set_up.unwrap_or_else(|e| {
        crate::diag::warn!("setup step failed", step = "check", error = e);
        false
    });
    if set_up {
        // Set up by an older Kiri: make sure the commands are there too,
        // without re-adding shell profile lines the user removed (#556).
        if !dev()
            && let Ok(h) = home()
        {
            mark_profiles_configured(&h);
        }
        if let Some(contents) = bundle_contents() {
            let _ = bundled_cli(&contents);
        }
        let _ = name_agent();
        if !dev() {
            let _ = crate::daemon::socket_path().map(|s| docker_socket_fallback(&s));
        }
        // Nothing else is touched: a docker context this person removed
        // later stays removed.
        return;
    }
    let mut undone = Vec::new();
    for s in FIRST_STEPS {
        if let Err(e) = first_step(s) {
            crate::diag::warn!("setup step failed", step = s, error = e);
            undone.push((s, e.to_string()));
        }
    }
    // The builder needs the engine, which the login item has just started;
    // without it the window makes the builder once it starts the engine.
    if !undone.iter().any(|(s, _)| *s == "login") {
        let _ = builder();
    }
    if !dev() {
        let _ = crate::daemon::socket_path().map(|s| docker_socket_fallback(&s));
    }
    *UNDONE.lock().unwrap_or_else(|e| e.into_inner()) = undone;
}

/// The first launch's steps, as the window's checklist names them: the
/// docker context (docker reaches Kiri), the kiri and docker commands, and
/// starting the engine at login.
pub const FIRST_STEPS: [&str; 3] = ["context", "commands", "login"];

/// The first launch's steps that failed, with their errors.
static UNDONE: std::sync::Mutex<Vec<(&'static str, String)>> = std::sync::Mutex::new(Vec::new());

pub fn undone() -> Vec<(&'static str, String)> {
    UNDONE.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// One of the steps, the same for `kiri setup` and the first launch, its
/// error saying which step it was (`step`).
fn first_step(name: &str) -> io::Result<()> {
    match name {
        "context" => crate::daemon::socket_path().map_err(step("finding the engine's socket")).and_then(|s| context(&s).map_err(step("adding the kiri docker context"))),
        "commands" => bundle_contents().map_or(Ok(()), |c| bundled_cli(&c).map_err(step("setting up the kiri and docker commands"))),
        "login" => agent().map(drop).map_err(step("starting the engine at login")),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, format!("no setup step {name}"))),
    }
}

/// The checklist's Try again for one step.
pub fn retry(name: &str) -> io::Result<()> {
    let result = first_step(name);
    let mut undone = UNDONE.lock().unwrap_or_else(|e| e.into_inner());
    undone.retain(|(s, _)| *s != name);
    if let (Err(e), Some(s)) = (&result, FIRST_STEPS.iter().find(|s| **s == name)) {
        undone.push((s, e.to_string()));
    }
    result
}

/// Each step's error says which step it was: on first launch it is all the
/// log has to go on (#250).
fn step(what: &'static str) -> impl Fn(io::Error) -> io::Error {
    move |e| io::Error::new(e.kind(), format!("{what}: {e}"))
}

pub fn run(args: &[String]) -> io::Result<()> {
    let flag = |f: &str| args.iter().any(|a| a == f);
    if flag("--uninstall") {
        return uninstall();
    }
    if flag("--domains") {
        return if dev() { Err(io::Error::other(format!("*.kiri.local belongs to the installed Kiri, not {}", crate::flavor::APP))) } else { domains() };
    }
    if flag("--docker-socket") {
        if dev() {
            return Err(io::Error::other(format!("/var/run/docker.sock belongs to the installed Kiri, not {}", crate::flavor::APP)));
        }
        let result = docker_socket();
        println!("{}", docker_socket_fallback(&crate::daemon::socket_path()?));
        return result;
    }
    let socket = crate::daemon::socket_path().map_err(step("finding the engine's socket"))?;
    first_step("context")?;
    println!("docker context `{CONTEXT}` → unix://{}", socket.display());
    if flag("--use") && !dev() {
        let path = docker_dir().map(|d| d.join("config.json")).map_err(step("making kiri docker's current context"))?;
        let mut cfg = read_json(&path).map_err(step("making kiri docker's current context"))?;
        cfg["currentContext"] = CONTEXT.get().into();
        write_json(&path, &cfg).map_err(step("making kiri docker's current context"))?;
        println!("docker now uses Kiri by default (`docker context use default` to switch back)");
    }
    if !dev() {
        let h = home().map_err(step("setting up the kiri and docker commands"))?;
        let z = zdotdir(&h);
        if flag("--no-profiles") {
            opt_out_shell_path(&h, &z).map_err(step("setting up the kiri and docker commands"))?;
        } else if bundle_contents().is_some() {
            shell_path(&h, &z).map_err(step("setting up the kiri and docker commands"))?;
        }
    }
    first_step("commands")?;
    if !flag("--no-agent") {
        first_step("login")?;
        println!("kiri daemon starts at login ({})", agent_plist()?.display());
    }
    match builder() {
        Ok(true) => match crate::buildwith::places().map(|p| p.saved()) {
            Ok(Some(crate::buildwith::With::Kiri)) => println!("docker build uses BuildKit in Kiri (builder `{BUILDER}`)"),
            _ => println!("docker build follows docker's context, and builds on Kiri when docker uses Kiri (`kiri build-with kiri` sends every build to Kiri)"),
        },
        Ok(false) => {}
        Err(e) => println!("docker build: the `{BUILDER}` builder comes later ({e}); the window makes it once Kiri is running"),
    }
    if !flag("--no-domains") && !dev() {
        // domains() asks for /var/run/docker.sock with the same password;
        // with the names already there, it is asked for on its own.
        let named = crate::daemon::dns::installed();
        if let Err(e) = domains() {
            println!("container names stay on *.kiri.localhost ({e}); `kiri setup --domains` tries again");
        } else if named {
            if let Err(e) = docker_socket() {
                println!("{DOCKER_SOCK} stays as it is ({e})");
            }
        }
    }
    if !dev() {
        println!("{}", docker_socket_fallback(&socket));
    }
    Ok(())
}

/// Points macOS at Kiri for `*.kiri.local`. Writing /etc/resolver needs an
/// administrator, so macOS asks for the password, once.
pub fn domains() -> io::Result<()> {
    use crate::daemon::dns;
    if dns::installed() {
        println!("containers answer at http://<name>.kiri.local");
        return Ok(());
    }
    let tmp = std::env::temp_dir().join(format!("kiri-resolver-{}", std::process::id()));
    std::fs::write(&tmp, format!("# Kiri: container names (kiri setup --uninstall removes this)\nnameserver 127.0.0.1\nport {}\n", dns::PORT))?;
    // /var/run/docker.sock with the same password, when it is free. Its
    // failing must not undo the names: how it went is read back after.
    let link = docker_socket_script()?;
    let (command, why) = match &link {
        Some(l) => (
            format!("mkdir -p /etc/resolver && cp '{}' {} && chmod 644 {} && ({l} || true)", tmp.display(), dns::RESOLVER, dns::RESOLVER),
            "Kiri wants to give your containers names like myapp.kiri.local, and to answer at /var/run/docker.sock for tools that look for Docker there.",
        ),
        None => (format!("mkdir -p /etc/resolver && cp '{}' {} && chmod 644 {}", tmp.display(), dns::RESOLVER, dns::RESOLVER), "Kiri wants to give your containers names like myapp.kiri.local."),
    };
    let result = as_admin(&command, why);
    let _ = std::fs::remove_file(&tmp);
    if let Some(l) = &link {
        let _ = std::fs::remove_file(&l.tmp);
        let _ = docker_socket_fallback(&crate::daemon::socket_path()?);
    }
    result?;
    println!("containers answer at http://<name>.kiri.local");
    Ok(())
}

/// Where tools that ignore docker contexts look for Docker: docker-py, Go's
/// `client.FromEnv`, docker-java, Testcontainers, many IDE plugins.
const DOCKER_SOCK: &str = "/var/run/docker.sock";
/// macOS empties /var/run at every boot, so a LaunchDaemon puts Kiri's link
/// back then, only if nothing else has taken the path by that time. Docker
/// Desktop's and OrbStack's helpers replace it when they start, as they
/// replace each other's.
const SOCKET_LABEL: &str = "dev.kiri.docker-socket";
const SOCKET_DAEMON: &str = "/Library/LaunchDaemons/dev.kiri.docker-socket.plist";

/// Who has `/var/run/docker.sock`.
pub fn docker_sock() -> Endpoint {
    let Ok(ours) = crate::daemon::socket_path() else { return Endpoint::Free };
    docker_sock_at_ours(&ours)
}

fn docker_sock_at_ours(ours: &Path) -> Endpoint {
    crate::dockerctx::sock_at(Path::new(DOCKER_SOCK), ours, &other_engine_dirs())
}

/// Settings → Network's Docker socket row for the Mac.
pub fn docker_sock_event() -> Value {
    let (endpoint, hint) = match crate::daemon::socket_path() {
        Ok(ours) => (docker_sock_at_ours(&ours), format!("unix://{}", ours.display())),
        Err(_) => (Endpoint::Free, format!("unix://~/{}/run/docker.sock", crate::flavor::STATE.get())),
    };
    crate::dockerctx::sock_event(DOCKER_SOCK, &endpoint, &hint, !dev())
}

/// The engines whose links stay theirs while the app is installed, running
/// or not: their socket is missing only until they start.
fn other_engine_dirs() -> Vec<PathBuf> {
    let Ok(h) = home() else { return Vec::new() };
    [("/Applications/Docker.app", ".docker"), ("/Applications/OrbStack.app", ".orbstack"), ("/Applications/Rancher Desktop.app", ".rd")]
        .iter()
        .filter(|(app, _)| Path::new(app).exists())
        .map(|(_, dir)| h.join(dir))
        .collect()
}

/// `'…'` for sh.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The root commands that link /var/run/docker.sock to Kiri's socket and
/// install the LaunchDaemon that puts it back at boot.
struct LinkScript {
    command: String,
    /// The LaunchDaemon's plist, written here for the command to copy.
    tmp: PathBuf,
}

impl std::fmt::Display for LinkScript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.command)
    }
}

/// The commands for when /var/run/docker.sock is free; None when it is
/// Kiri's already or another engine's, or for Kiri Dev.
fn docker_socket_script() -> io::Result<Option<LinkScript>> {
    let ours = crate::daemon::socket_path()?;
    if dev() || docker_sock_at_ours(&ours) != Endpoint::Free {
        return Ok(None);
    }
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;");
    let ours_s = ours.to_string_lossy();
    let boot = format!("[ -e {DOCKER_SOCK} ] || [ -L {DOCKER_SOCK} ] || ln -s \"$1\" {DOCKER_SOCK}");
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{SOCKET_LABEL}</string>
  <key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>{}</string><string>kiri-docker-socket</string><string>{}</string></array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
"#,
        esc(&boot),
        esc(&ours_s)
    );
    let tmp = std::env::temp_dir().join(format!("kiri-docker-socket-{}.plist", std::process::id()));
    std::fs::write(&tmp, plist)?;
    // `[ ! -e ]` again as root: another engine may have started since. A
    // link left dangling by a removed engine is replaced.
    let command = format!(
        "cp {} {SOCKET_DAEMON} && chown root:wheel {SOCKET_DAEMON} && chmod 644 {SOCKET_DAEMON} && [ ! -e {DOCKER_SOCK} ] && rm -f {DOCKER_SOCK} && ln -s {} {DOCKER_SOCK}",
        sh_quote(&tmp.to_string_lossy()),
        sh_quote(&ours_s)
    );
    Ok(Some(LinkScript { command, tmp }))
}

/// `kiri setup --docker-socket`: /var/run/docker.sock to Kiri, if free
/// (macOS asks for the password).
pub fn docker_socket() -> io::Result<()> {
    let Some(l) = docker_socket_script()? else { return Ok(()) };
    let result = as_admin(&l.command, "Kiri wants to answer at /var/run/docker.sock, for tools that look for Docker there.");
    let _ = std::fs::remove_file(&l.tmp);
    result
}

/// Says where tools that ignore docker contexts find Kiri, and keeps
/// `~/.testcontainers.properties` for when /var/run/docker.sock is not
/// Kiri's but could be (a declined password, not yet asked).
fn docker_socket_fallback(ours: &Path) -> String {
    match docker_sock_at_ours(ours) {
        Endpoint::Kiri => {
            let _ = testcontainers(ours, false);
            format!("{DOCKER_SOCK} → Kiri (docker-py, Testcontainers and other tools that ignore docker contexts)")
        }
        Endpoint::Taken(t) => {
            let _ = testcontainers(ours, false);
            format!("{DOCKER_SOCK} is another engine's ({t}) and stays so; DOCKER_HOST=unix://{} points a tool at Kiri", ours.display())
        }
        Endpoint::Free => match testcontainers(ours, true) {
            Ok(true) => format!("{DOCKER_SOCK} is not Kiri's yet (`kiri setup --docker-socket` asks for the password); Testcontainers finds Kiri through ~/.testcontainers.properties"),
            _ => format!("{DOCKER_SOCK} is not Kiri's yet (`kiri setup --docker-socket` asks for the password); until then DOCKER_HOST=unix://{} points a tool at Kiri", ours.display()),
        },
    }
}

/// The first line of the `~/.testcontainers.properties` Kiri writes: only a
/// file that starts with it is Kiri's to change or remove.
const TESTCONTAINERS_MARK: &str = "# Written by Kiri while /var/run/docker.sock is not Kiri's (kiri setup --uninstall removes it)";

fn testcontainers_text(ours: &Path) -> String {
    format!("{TESTCONTAINERS_MARK}\ndocker.host=unix://{}\n", ours.display())
}

/// Writes (`on`) or removes Kiri's `~/.testcontainers.properties`. A file
/// the user (or Testcontainers itself) wrote is never touched. True when
/// Kiri's file is there afterwards.
fn testcontainers(ours: &Path, on: bool) -> io::Result<bool> {
    testcontainers_at(&home()?.join(".testcontainers.properties"), ours, on)
}

fn testcontainers_at(path: &Path, ours: &Path, on: bool) -> io::Result<bool> {
    let ours_text = testcontainers_text(ours);
    match std::fs::read_to_string(path) {
        // Only exactly what Kiri wrote: Testcontainers adds keys of its own.
        Ok(text) if text.starts_with(TESTCONTAINERS_MARK) && text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')).all(|l| l.starts_with("docker.host=")) => {
            if on {
                if text != ours_text {
                    std::fs::write(path, ours_text)?;
                }
                Ok(true)
            } else {
                std::fs::remove_file(path)?;
                Ok(false)
            }
        }
        Ok(_) => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if on {
                std::fs::write(path, ours_text)?;
            }
            Ok(on)
        }
        Err(e) => Err(e),
    }
}

/// For the window, after the password prompt: how /var/run/docker.sock
/// went, if it is not Kiri's.
pub fn docker_socket_note() -> Option<String> {
    let ours = crate::daemon::socket_path().ok()?;
    match docker_sock_at_ours(&ours) {
        Endpoint::Free if !dev() => Some(docker_socket_fallback(&ours)),
        _ => None,
    }
}

/// Takes /var/run/docker.sock back, if it is still Kiri's, and the
/// LaunchDaemon that put it there.
fn remove_docker_socket() -> io::Result<()> {
    let ours = crate::daemon::socket_path()?;
    let _ = testcontainers(&ours, false);
    let linked = docker_sock_at_ours(&ours) == Endpoint::Kiri;
    if !linked && !Path::new(SOCKET_DAEMON).exists() {
        return Ok(());
    }
    let mut command = format!("launchctl bootout system/{SOCKET_LABEL} 2>/dev/null; rm -f {SOCKET_DAEMON}");
    if linked {
        command.push_str(&format!("; [ \"$(readlink {DOCKER_SOCK})\" = {} ] && rm -f {DOCKER_SOCK}; true", sh_quote(&ours.to_string_lossy())));
    }
    as_admin(&command, "Kiri wants to remove its /var/run/docker.sock.")?;
    println!("removed {DOCKER_SOCK}");
    Ok(())
}

/// Takes `*.kiri.local` back; containers stay on `*.kiri.localhost`.
pub fn remove_domains() -> io::Result<()> {
    let resolver = crate::daemon::dns::RESOLVER;
    if !Path::new(resolver).exists() {
        return Ok(());
    }
    as_admin(&format!("rm -f {resolver}"), "Kiri wants to remove its *.kiri.local names.")?;
    println!("removed *.kiri.local");
    Ok(())
}

/// Runs a shell command as root through macOS's own password prompt. The
/// script runs in this process, not through `osascript`, so the prompt says
/// "Kiri wants to make changes". AppleScript belongs on the main thread: the
/// window's workers hand it there, and the CLI is already on it.
pub(crate) fn as_admin(command: &str, why: &str) -> io::Result<()> {
    let script = format!("do shell script \"{}\" with prompt \"{}\" with administrator privileges", command.replace('"', "\\\""), why.replace('"', "\\\""));
    // SAFETY: pthread_main_np only reads the calling thread's state.
    if unsafe { libc::pthread_main_np() } == 1 {
        return apple_script(&script);
    }
    let mut result = None;
    dispatch2::DispatchQueue::main().exec_sync(|| result = Some(apple_script(&script)));
    result.unwrap_or_else(|| Err(io::Error::other("the password prompt did not run")))
}

fn apple_script(source: &str) -> io::Result<()> {
    use objc2::AllocAnyThread;
    use objc2_foundation::{NSAppleScript, NSString};
    let script = NSAppleScript::initWithSource(NSAppleScript::alloc(), &NSString::from_str(source)).ok_or_else(|| io::Error::other("bad AppleScript"))?;
    let mut error: Option<objc2::rc::Retained<objc2_foundation::NSDictionary<NSString, objc2::runtime::AnyObject>>> = None;
    // Called directly: the generated binding panics on the nil it returns
    // when the script fails.
    // SAFETY: the selector takes an NSDictionary** out-parameter, and the
    // result is an optional NSAppleEventDescriptor.
    let _: Option<objc2::rc::Retained<objc2::runtime::AnyObject>> = unsafe { objc2::msg_send![&*script, executeAndReturnError: Some(&mut error)] };
    let Some(info) = error else { return Ok(()) };
    // "message (number)"; the number is -128 when the prompt is cancelled.
    let field = |key: &str| {
        info.objectForKey(&NSString::from_str(key)).map(|v| {
            // SAFETY: every object answers -description with an NSString.
            let d: objc2::rc::Retained<NSString> = unsafe { objc2::msg_send![&*v, description] };
            d.to_string()
        })
    };
    Err(io::Error::other(format!("{} ({})", field("NSAppleScriptErrorMessage").unwrap_or_default(), field("NSAppleScriptErrorNumber").unwrap_or_default())))
}

/// Kiri Lite, once its tools are downloaded: the CLI links and the build
/// builder that `kiri setup` could not make without them.
pub fn after_tools() -> io::Result<()> {
    if let Some(contents) = bundle_contents() {
        bundled_cli(&contents)?;
    }
    builder().map(drop)
}

/// After Settings → Storage moved the data folder from `old`: Kiri Lite's
/// docker link (`~/.kiri/bin/docker`) and docker's plugin folder, which
/// point into the data folder, point into the new one.
pub fn relink_cli(old: &Path) -> io::Result<()> {
    let new = kiri_image::Store::default_root()?;
    let link = bin_dir()?.join("docker");
    if let Some(to) = std::fs::read_link(&link).ok().and_then(|t| moved(&t, old, &new)) {
        std::fs::remove_file(&link)?;
        std::os::unix::fs::symlink(to, &link)?;
    }
    let path = docker_dir()?.join("config.json");
    let mut cfg = read_json(&path)?;
    if repoint_plugin_dirs(&mut cfg, old, &new) {
        write_json(&path, &cfg)?;
    }
    Ok(())
}

/// `path` under `new` instead of `old`, if it was under `old`.
fn moved(path: &Path, old: &Path, new: &Path) -> Option<PathBuf> {
    path.strip_prefix(old).ok().map(|rest| new.join(rest))
}

/// Moves docker's plugin folders under `old` to `new`; whether any moved.
fn repoint_plugin_dirs(cfg: &mut Value, old: &Path, new: &Path) -> bool {
    let mut changed = false;
    for d in cfg["cliPluginsExtraDirs"].as_array_mut().into_iter().flatten() {
        if let Some(to) = d.as_str().and_then(|s| moved(Path::new(s), old, new)) {
            *d = to.to_string_lossy().into_owned().into();
            changed = true;
        }
    }
    changed
}

/// The context, as `docker context create kiri --docker host=…` writes it.
fn context(socket: &Path) -> io::Result<()> {
    crate::dockerctx::write_context(&context_dir(CONTEXT.get())?, CONTEXT.get(), crate::flavor::APP.get(), &format!("unix://{}", socket.display()))
}

/// Makes `name` the context plain `docker` uses: Kiri's own (made first if
/// missing), "default", or another context that exists, to switch back to.
pub fn use_context(name: &str) -> io::Result<()> {
    let dir = docker_dir()?;
    let host = format!("unix://{}", crate::daemon::socket_path()?.display());
    crate::dockerctx::switch(&dir, &context_dir(name)?, name, CONTEXT.get(), crate::flavor::APP.get(), &host)
}

/// Links `kiri` and the app's `docker` into `~/.kiri/bin`, puts that
/// directory on PATH, and adds docker's plugins (Compose, buildx) to the
/// CLI's plugin search path. An existing `docker` on PATH is left alone.
/// The docker CLI, Compose and buildx are bundled in Kiri.app, or in Kiri
/// Lite downloaded to tools::dir() (nothing yet if not downloaded); `kiri`
/// is linked either way.
fn bundled_cli(contents: &Path) -> io::Result<()> {
    let ours = bin_dir()?;
    std::fs::create_dir_all(&ours)?;
    // `kiri` itself, for `kiri k8s`, `kiri machine`, `kiri import`…
    let app_kiri = contents.join("MacOS/kiri");
    let kiri = ours.join("kiri");
    let _ = std::fs::remove_file(&kiri);
    std::os::unix::fs::symlink(&app_kiri, &kiri)?;
    let brew_linked = !dev() && homebrew_links_this_app(&app_kiri);
    // Kiri Dev's commands are run by path: ~/.kiri-dev/bin/kiri.
    // When Homebrew's cask `binary` stanza already links `kiri` on PATH to
    // this app (#733), leave shell profiles and Homebrew's symlink untouched.
    if !dev() && !brew_linked {
        let h = home()?;
        shell_path_once(&h, &zdotdir(&h))?;
        system_link(&kiri, &app_kiri);
    }
    let mut bin = contents.join("Resources/bin");
    if !bin.join("docker").is_file() {
        match crate::tools::dir() {
            Ok(d) if crate::tools::installed() => bin = d,
            _ => return Ok(()),
        }
    }
    let link = ours.join("docker");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(bin.join("docker"), &link)?;
    // Kiri Dev's plugins stay its own: `docker --context kiri-dev`, or
    // ~/.kiri-dev/bin/docker.
    if dev() {
        println!("docker and kiri commands: {}", ours.display());
        return Ok(());
    }
    default_context()?;
    let plugins = bin.join("cli-plugins").to_string_lossy().into_owned();
    let path = docker_dir()?.join("config.json");
    let mut cfg = read_json(&path)?;
    let mut dirs: Vec<Value> = cfg["cliPluginsExtraDirs"].as_array().cloned().unwrap_or_default();
    if !dirs.iter().any(|d| d.as_str() == Some(plugins.as_str())) {
        dirs.push(plugins.into());
    }
    cfg["cliPluginsExtraDirs"] = dirs.into();
    write_json(&path, &cfg)?;
    if brew_linked || home().is_ok_and(|h| no_profiles_file(&h).exists()) {
        println!("docker and kiri commands: {}", ours.display());
    } else {
        println!("docker and kiri commands: {} (on PATH in new terminal windows)", ours.display());
    }
    Ok(())
}

/// Candidate Homebrew `bin/kiri` symlink paths on Apple silicon, Intel Macs,
/// and custom `$HOMEBREW_PREFIX` installations (#733).
fn homebrew_kiri_candidates(homebrew_prefix: Option<&std::ffi::OsStr>) -> Vec<PathBuf> {
    let mut out = vec![PathBuf::from("/opt/homebrew/bin/kiri"), PathBuf::from(SYSTEM_LINK)];
    if let Some(prefix) = homebrew_prefix.filter(|p| !p.is_empty()) {
        let cand = PathBuf::from(prefix).join("bin/kiri");
        if !out.contains(&cand) {
            out.push(cand);
        }
    }
    out
}

/// True when any candidate symlink points directly to `app_kiri` (rather than
/// going through `~/.kiri/bin/kiri`, which `system_link` makes on Intel Macs).
fn homebrew_links_app_in(candidates: &[PathBuf], app_kiri: &Path) -> bool {
    let Ok(ours) = std::fs::canonicalize(app_kiri) else { return false };
    let state_bin = format!("/{}/bin/", crate::flavor::STATE.get());
    candidates.iter().any(|cand| {
        let Ok(raw) = std::fs::read_link(cand) else { return false };
        let raw_str = raw.to_string_lossy();
        if raw_str.contains("/.kiri/bin/") || raw_str.contains(&state_bin) {
            return false;
        }
        std::fs::canonicalize(cand).is_ok_and(|real| real == ours)
    })
}

fn homebrew_links_this_app(app_kiri: &Path) -> bool {
    homebrew_links_app_in(&homebrew_kiri_candidates(std::env::var_os("HOMEBREW_PREFIX").as_deref()), app_kiri)
}

/// `/usr/local/bin/kiri`, when the user can write there (Homebrew on Intel
/// Macs makes it theirs). That directory is on every shell's PATH already,
/// so `kiri` works even in a terminal opened before Kiri was. A `kiri`
/// there that isn't Kiri's (or that Homebrew's cask already linked directly to
/// this app) is left alone.
const SYSTEM_LINK: &str = "/usr/local/bin/kiri";

fn system_link(kiri: &Path, app_kiri: &Path) {
    system_link_at(Path::new(SYSTEM_LINK), kiri, app_kiri);
}

fn system_link_at(link: &Path, kiri: &Path, app_kiri: &Path) {
    // Missing, or a link an older Kiri left (to a Kiri.app or ~/.kiri/bin
    // that moved, or to nothing): made again to this one. If Homebrew's cask
    // already linked `/usr/local/bin/kiri` directly to `app_kiri`, keep
    // Homebrew's link so `brew uninstall` owns it (#733).
    if homebrew_links_app_in(&[link.to_path_buf()], app_kiri) {
        return;
    }
    let replace = match std::fs::read_link(link) {
        Ok(target) => target != kiri && (kiri_link(&target) || !link.exists()),
        Err(_) => link.symlink_metadata().is_err(),
    };
    if replace {
        let _ = std::fs::remove_file(link);
        let _ = std::os::unix::fs::symlink(kiri, link);
    }
}

/// A link target that is some Kiri's `kiri`: inside a Kiri app bundle, or a
/// Kiri bin directory (~/.kiri/bin, ~/.kiri-dev/bin).
fn kiri_link(target: &Path) -> bool {
    let t = target.to_string_lossy();
    t.ends_with("/kiri") && (t.contains(".app/Contents/MacOS/") || t.contains("/.kiri/bin/") || t.contains("/.kiri-dev/bin/"))
}

/// Whether `/usr/local/bin/kiri` is the link system_link() makes.
fn system_link_is_ours() -> bool {
    bin_dir().is_ok_and(|b| std::fs::read_link(SYSTEM_LINK).is_ok_and(|t| t == b.join("kiri")))
}

/// Every other process running this app's `kiri` binary, asked to quit,
/// then made to after a few seconds.
fn stop_others() {
    let Some(exe) = std::env::current_exe().ok().and_then(|e| std::fs::canonicalize(e).ok()) else { return };
    let me = std::process::id().to_string();
    let pattern = format!("^{}( |$)", regex_escape(&exe.to_string_lossy()));
    for (sig, wait) in [("-TERM", 3), ("-KILL", 0)] {
        let Ok(out) = Command::new("/usr/bin/pgrep").args(["-f", &pattern]).output() else { return };
        let pids: Vec<String> = String::from_utf8_lossy(&out.stdout).split_whitespace().filter(|p| *p != me).map(str::to_owned).collect();
        if pids.is_empty() {
            return;
        }
        let _ = Command::new("/bin/kill").arg(sig).args(&pids).status();
        std::thread::sleep(std::time::Duration::from_secs(wait));
    }
}

fn regex_escape(s: &str) -> String {
    s.chars().fold(String::new(), |mut out, c| {
        if "\\.^$|?*+()[]{}".contains(c) {
            out.push('\\');
        }
        out.push(c);
        out
    })
}

/// The marked lines Kiri adds to shell profiles, and removes on uninstall.
const PROFILE_MARK: &str = "# Added by Kiri: its docker and kiri commands (kiri setup --uninstall removes this)";

/// Adds `~/.kiri/bin` to the end of PATH once, however many of the
/// profiles a shell reads. Plain sh, for zsh and bash alike.
const SH_LINE: &str = r#"case ":$PATH:" in *":$HOME/.kiri/bin:"*) ;; *) export PATH="$PATH:$HOME/.kiri/bin" ;; esac"#;

/// The line Kiri 0.1.0 wrote, only to `~/.zprofile`; taken back on uninstall.
const OLD_SH_LINE: &str = "export PATH=\"$PATH:$HOME/.kiri/bin\"";

const FISH_LINE: &str = "fish_add_path --append $HOME/.kiri/bin";

/// The shell profiles Kiri puts `~/.kiri/bin` in, so `kiri` is found in
/// every terminal:
/// - zsh (the macOS default) reads `.zprofile` only in login shells, which
///   Terminal opens but VS Code, tmux and IDE terminals do not, and a
///   `.zshrc` that sets PATH runs after it: both files, in `$ZDOTDIR` if set
/// - bash reads the first of `.bash_profile`, `.bash_login` and `.profile`
///   in login shells (`.bash_profile` is made if there is none) and
///   `.bashrc` in others, when the user has one
/// - fish's `conf.d`, when the user has fish
fn profiles(home: &Path, zdotdir: &Path) -> Vec<(PathBuf, &'static str)> {
    let mut v = vec![(zdotdir.join(".zprofile"), SH_LINE), (zdotdir.join(".zshrc"), SH_LINE)];
    let login = [".bash_profile", ".bash_login", ".profile"].iter().map(|f| home.join(f)).find(|p| p.is_file());
    v.push((login.unwrap_or_else(|| home.join(".bash_profile")), SH_LINE));
    if home.join(".bashrc").is_file() {
        v.push((home.join(".bashrc"), SH_LINE));
    }
    if home.join(".config/fish").is_dir() {
        v.push((home.join(".config/fish/conf.d/kiri.fish"), FISH_LINE));
    }
    v
}

fn zdotdir(home: &Path) -> PathBuf {
    std::env::var_os("ZDOTDIR").filter(|d| !d.is_empty()).map_or_else(|| home.to_path_buf(), PathBuf::from)
}

/// Recorded in `~/.kiri` once Kiri has edited shell profiles on initial setup,
/// so subsequent app launches leave removed lines removed (#556).
const PROFILES_CONFIGURED: &str = "profiles-configured";

/// Recorded in `~/.kiri` by `kiri setup --no-profiles` so Kiri never edits
/// shell profiles (#556).
const NO_PROFILES: &str = "no-profiles";

fn profiles_configured_file(home: &Path) -> PathBuf {
    home.join(crate::flavor::STATE.get()).join(PROFILES_CONFIGURED)
}

fn no_profiles_file(home: &Path) -> PathBuf {
    home.join(crate::flavor::STATE.get()).join(NO_PROFILES)
}

fn mark_profiles_configured(home: &Path) {
    let path = profiles_configured_file(home);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, "");
}

/// Puts ~/.kiri/bin on the shell's PATH in each profile, unless the user has
/// opted out with `kiri setup --no-profiles` or a profile already references
/// `.kiri/bin` (#556). A profile that can't be written is passed over (and
/// logged), not the end of setup: a link to a dotfiles folder that moved made
/// the app's first launch quit with only "No such file or directory" (#250).
fn shell_path(home: &Path, zdotdir: &Path) -> io::Result<()> {
    if no_profiles_file(home).exists() {
        return Ok(());
    }
    for (file, line) in profiles(home, zdotdir) {
        // A link to nothing (or to a place Kiri can't reach): writing
        // through it fails when the target's folder is gone (#250), or makes
        // a file where it points. It stays as the user left it.
        if file.symlink_metadata().is_ok() && !file.try_exists().unwrap_or(false) {
            crate::diag::warn!("shell profile skipped: a link to nothing", file = file.display());
            continue;
        }
        // Only a profile Kiri could read, or one that isn't there, is
        // written: a read error (not UTF-8, no read permission) must never
        // turn into a profile holding only Kiri's lines.
        let text = match std::fs::read_to_string(&file) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(e) => {
                crate::diag::warn!("shell profile skipped", file = file.display(), error = e);
                continue;
            }
        };
        if text.contains(PROFILE_MARK) || text.contains(".kiri/bin") {
            continue;
        }
        let sep = if text.is_empty() || text.ends_with('\n') { "" } else { "\n" };
        let written = file.parent().map_or(Ok(()), std::fs::create_dir_all).and_then(|()| std::fs::write(&file, format!("{text}{sep}\n{PROFILE_MARK}\n{line}\n")));
        if let Err(e) = written {
            crate::diag::warn!("shell profile skipped", file = file.display(), error = e);
        }
    }
    mark_profiles_configured(home);
    Ok(())
}

/// Edits shell profiles only on the initial setup: once `profiles-configured`
/// or `no-profiles` is recorded in `~/.kiri`, subsequent app launches leave
/// the user's profiles untouched (#556).
fn shell_path_once(home: &Path, zdotdir: &Path) -> io::Result<()> {
    if profiles_configured_file(home).exists() || no_profiles_file(home).exists() {
        return Ok(());
    }
    shell_path(home, zdotdir)
}

/// `kiri setup --no-profiles`: removes any profile lines Kiri added and
/// records `no-profiles` in `~/.kiri` so future launches and `kiri setup`
/// runs leave shell profiles alone (#556).
fn opt_out_shell_path(home: &Path, zdotdir: &Path) -> io::Result<()> {
    remove_shell_path(home, zdotdir)?;
    let path = no_profiles_file(home);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, "")
}

/// Whether `~/.kiri/bin` is currently managed in the user's shell profiles
/// (Settings → Appearance → Command-line tools in shell, #556).
pub(crate) fn shell_path_enabled() -> bool {
    let Ok(h) = home() else { return false };
    shell_path_enabled_in(&h, &zdotdir(&h))
}

fn shell_path_enabled_in(home: &Path, zdotdir: &Path) -> bool {
    if no_profiles_file(home).exists() {
        return false;
    }
    if profiles_configured_file(home).exists() {
        return true;
    }
    profiles(home, zdotdir).into_iter().any(|(file, _)| {
        std::fs::read_to_string(&file).is_ok_and(|t| t.contains(PROFILE_MARK) || t.contains(".kiri/bin"))
    })
}

/// Turns shell profile management on (`shell_path`) or off (`opt_out_shell_path`,
/// equivalent to `kiri setup --no-profiles`) from Settings → Appearance (#556).
pub(crate) fn set_shell_path(enabled: bool) -> io::Result<()> {
    let h = home()?;
    let z = zdotdir(&h);
    set_shell_path_in(&h, &z, enabled)
}

fn set_shell_path_in(home: &Path, zdotdir: &Path, enabled: bool) -> io::Result<()> {
    if enabled {
        let _ = std::fs::remove_file(no_profiles_file(home));
        shell_path(home, zdotdir)
    } else {
        opt_out_shell_path(home, zdotdir)
    }
}

fn remove_shell_path(home: &Path, zdotdir: &Path) -> io::Result<()> {
    for (file, line) in profiles(home, zdotdir) {
        let Ok(text) = std::fs::read_to_string(&file) else { continue };
        if !text.contains(PROFILE_MARK) {
            continue;
        }
        let mut kept = text;
        for line in [line, OLD_SH_LINE] {
            kept = kept.replace(&format!("\n{PROFILE_MARK}\n{line}\n"), "\n").replace(&format!("{PROFILE_MARK}\n{line}\n"), "");
        }
        if kept.trim().is_empty() && file.extension().is_some_and(|e| e == "fish") {
            std::fs::remove_file(&file)?;
        } else {
            std::fs::write(&file, kept)?;
        }
    }
    let _ = std::fs::remove_file(profiles_configured_file(home));
    let _ = std::fs::remove_file(no_profiles_file(home));
    Ok(())
}

/// On a Mac with no other Docker engine, plain `docker` uses Kiri. With
/// OrbStack or Docker Desktop around, the user's choice stays as it is.
fn default_context() -> io::Result<()> {
    let h = home()?;
    // Kiri's own /var/run/docker.sock is not another engine.
    let ours = crate::daemon::socket_path()?;
    let system = !matches!(docker_sock_at_ours(&ours), Endpoint::Kiri) && Path::new(DOCKER_SOCK).exists();
    let other = system
        || [h.join(".orbstack/run/docker.sock"), h.join(".docker/run/docker.sock")].iter().any(|p| p.exists())
        || Path::new("/Applications/OrbStack.app").exists()
        || Path::new("/Applications/Docker.app").exists();
    let path = docker_dir()?.join("config.json");
    let mut cfg = read_json(&path)?;
    if other || cfg["currentContext"].as_str().is_some_and(|c| !c.is_empty() && c != "default") {
        return Ok(());
    }
    cfg["currentContext"] = CONTEXT.get().into();
    write_json(&path, &cfg)?;
    println!("docker uses Kiri by default (no other Docker engine on this Mac)");
    Ok(())
}

fn agent_plist() -> io::Result<PathBuf> {
    Ok(home()?.join("Library/LaunchAgents").join(format!("{AGENT}.plist")))
}

fn uid() -> u32 {
    // SAFETY: getuid cannot fail.
    unsafe { libc::getuid() }
}

/// A LaunchAgent for `kiri daemon`: started at login when `run_at_load` is
/// true, restarted if it crashes, never restarted after a clean exit.
pub(crate) fn agent_plist_xml(exe: &Path, log: &Path, run_at_load: bool) -> String {
    let esc = |p: &Path| p.to_string_lossy().replace('&', "&amp;").replace('<', "&lt;");
    let run = if run_at_load { "true" } else { "false" };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{AGENT}</string>
  <key>AssociatedBundleIdentifiers</key><array><string>{APP_ID}</string></array>
  <key>ProgramArguments</key><array><string>{}</string><string>daemon</string></array>
  <key>RunAtLoad</key><{run}/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>{}</string>
  <key>StandardErrorPath</key><string>{}</string>
</dict>
</plist>
"#,
        esc(exe),
        esc(log),
        esc(log)
    )
}

/// Reads `<key>RunAtLoad</key>` from a LaunchAgent plist.
pub(crate) fn plist_run_at_load(xml: &str) -> Option<bool> {
    let rest = xml.split_once("<key>RunAtLoad</key>")?.1.trim_start();
    if rest.starts_with("<true/>") {
        Some(true)
    } else if rest.starts_with("<false/>") {
        Some(false)
    } else {
        None
    }
}

/// Flips `<key>RunAtLoad</key>` in a LaunchAgent plist between `<true/>` and `<false/>`.
pub(crate) fn set_plist_run_at_load(xml: &str, on: bool) -> Option<String> {
    let key = "<key>RunAtLoad</key>";
    let at = xml.find(key)? + key.len();
    let after = &xml[at..];
    let ws = after.len() - after.trim_start().len();
    let tag_at = at + ws;
    let old_tag = if xml[tag_at..].starts_with("<true/>") {
        "<true/>"
    } else if xml[tag_at..].starts_with("<false/>") {
        "<false/>"
    } else {
        return None;
    };
    let new_tag = if on { "<true/>" } else { "<false/>" };
    let mut out = String::with_capacity(xml.len() + 1);
    out.push_str(&xml[..tag_at]);
    out.push_str(new_tag);
    out.push_str(&xml[tag_at + old_tag.len()..]);
    Some(out)
}

/// Whether the LaunchAgent is set to start Kiri at sign-in (`RunAtLoad`).
pub fn start_at_login() -> bool {
    agent_plist()
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|xml| plist_run_at_load(&xml))
        .unwrap_or(true)
}

/// Updates `RunAtLoad` in `path` (or writes a valid LaunchAgent plist when missing).
pub(crate) fn set_start_at_login_at(path: &Path, exe: &Path, log: &Path, on: bool) -> io::Result<()> {
    if let Ok(xml) = std::fs::read_to_string(path)
        && let Some(updated) = set_plist_run_at_load(&xml, on)
    {
        return std::fs::write(path, updated);
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, agent_plist_xml(exe, log, on))
}

/// Settings → Appearance → Start Kiri at sign-in: updates `RunAtLoad` in the
/// LaunchAgent plist while keeping the plist valid for on-demand launchd.
pub fn set_start_at_login(on: bool) -> io::Result<()> {
    let path = agent_plist()?;
    let exe = std::env::current_exe()?.canonicalize()?;
    let log = home()?.join(crate::flavor::STATE.get()).join("daemon.log");
    set_start_at_login_at(&path, &exe, &log, on)
}

/// Unloads the LaunchAgent from launchd, stopping `kiri daemon` if launchd runs it.
pub fn bootout_agent() {
    let _ = Command::new("/bin/launchctl")
        .args(["bootout", &format!("gui/{}/{AGENT}", uid())])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// A LaunchAgent for `kiri daemon`: started at login, restarted if it
/// crashes, never restarted after a clean exit.
fn agent() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?.canonicalize()?;
    let log = home()?.join(crate::flavor::STATE.get()).join("daemon.log");
    let plist = agent_plist_xml(&exe, &log, true);
    let path = agent_plist()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, plist)?;
    // Reload, so a new path to the binary takes effect.
    let _ = Command::new("/bin/launchctl").args(["bootout", &format!("gui/{}/{AGENT}", uid())]).stderr(std::process::Stdio::null()).status();
    // bootout returns before launchd has let the old job go, and a
    // bootstrap in that moment fails (error 5): try again for a few seconds.
    let mut ok = false;
    for _ in 0..20 {
        ok = Command::new("/bin/launchctl").args(["bootstrap", &format!("gui/{}", uid())]).arg(&path).stderr(std::process::Stdio::null()).status()?.success();
        if ok {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    if !ok {
        return Err(io::Error::other(format!("launchctl could not load {}", path.display())));
    }
    Ok(path)
}

/// Starts the engine through the LaunchAgent, loading it first if launchd
/// doesn't have it (Login Items turned off and on, or a plist written but
/// never loaded). Ok(false) when there is no agent for this copy of Kiri,
/// and the caller starts the engine itself.
pub fn start_agent() -> io::Result<bool> {
    if !agent_plist()?.is_file() || !agent_runs_this()? {
        return Ok(false);
    }
    let job = format!("gui/{}/{AGENT}", uid());
    let kicked = Command::new("/bin/launchctl").args(["kickstart", &job]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status()?.success();
    if kicked {
        return Ok(true);
    }
    // Not loaded: bootstrap it, then kickstart it (when RunAtLoad is false,
    // bootstrap loads the job without starting it).
    let loaded = Command::new("/bin/launchctl").args(["bootstrap", &format!("gui/{}", uid())]).arg(agent_plist()?).stderr(std::process::Stdio::null()).status()?.success();
    if !loaded {
        crate::diag::info!("the LaunchAgent would not load; starting the engine directly");
        return Ok(false);
    }
    let _ = Command::new("/bin/launchctl").args(["kickstart", &job]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
    Ok(true)
}

/// Whether the LaunchAgent starts this copy of Kiri. One left by another
/// copy (an older download, a build elsewhere) is replaced when this one opens.
fn agent_runs_this() -> io::Result<bool> {
    let exe = std::env::current_exe()?.canonicalize()?;
    let esc = exe.to_string_lossy().replace('&', "&amp;").replace('<', "&lt;");
    Ok(std::fs::read_to_string(agent_plist()?)?.contains(&format!("<string>{esc}</string><string>daemon</string>")))
}

/// Adds the app's name to a LaunchAgent written by an older Kiri. launchd
/// reads it at the next login, so the running daemon is left alone.
fn name_agent() -> io::Result<()> {
    let path = agent_plist()?;
    let text = std::fs::read_to_string(&path)?;
    if text.contains("AssociatedBundleIdentifiers") {
        return Ok(());
    }
    let named = text.replacen("  <key>ProgramArguments</key>", &format!("  <key>AssociatedBundleIdentifiers</key><array><string>{APP_ID}</string></array>\n  <key>ProgramArguments</key>"), 1);
    std::fs::write(&path, named)
}

/// The docker CLI to drive buildx with: on PATH, else the app's.
pub fn docker_cli() -> Option<PathBuf> {
    crate::client::docker_cli()
}

fn uninstall() -> io::Result<()> {
    let _ = Command::new("/bin/launchctl").args(["bootout", &format!("gui/{}/{AGENT}", uid())]).stderr(std::process::Stdio::null()).status();
    // Uninstalling stops everything this Kiri runs: the engine (the agent,
    // just booted out, which stops the VM and its containers) and any window
    // or kiri command still open from this app (`kiri share`, a second
    // daemon). Not this process: it's the one uninstalling.
    stop_others();
    match std::fs::remove_file(agent_plist()?) {
        Ok(()) => println!("removed the LaunchAgent"),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    // Only a context that still points at Kiri's socket is ours to remove.
    let dir = context_dir(CONTEXT.get())?;
    let meta = read_json(&dir.join("meta.json"))?;
    if meta["Endpoints"]["docker"]["Host"].as_str().is_some_and(|h| h.ends_with(&format!("{}/run/docker.sock", crate::flavor::STATE))) {
        std::fs::remove_dir_all(&dir)?;
        println!("removed docker context `{CONTEXT}`");
    }
    let path = docker_dir()?.join("config.json");
    let mut cfg = read_json(&path)?;
    let mut changed = false;
    if cfg["currentContext"].as_str() == Some(CONTEXT.get()) {
        if let Some(o) = cfg.as_object_mut() {
            o.remove("currentContext");
        }
        changed = true;
    }
    // `get_mut`: indexing would add the key to a config that lacks it.
    if let Some(dirs) = cfg.get_mut("cliPluginsExtraDirs").and_then(Value::as_array_mut) {
        let before = dirs.len();
        dirs.retain(|d| !d.as_str().is_some_and(|s| s.contains("Kiri.app/Contents/Resources/bin")));
        changed |= dirs.len() != before;
    }
    if changed {
        write_json(&path, &cfg)?;
    }
    // Docker's builder back as it was, before Kiri's goes.
    if let Err(e) = crate::buildwith::places().and_then(|p| p.uninstall()) {
        println!("could not give docker build back its own builder ({e})");
    }
    if let Some(docker) = docker_cli() {
        let _ = Command::new(docker).args(["buildx", "rm", BUILDER.get()]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
    }
    if !dev() && system_link_is_ours() {
        let _ = std::fs::remove_file(SYSTEM_LINK);
    }
    let _ = std::fs::remove_file(bin_dir()?.join("docker"));
    let _ = std::fs::remove_file(bin_dir()?.join("kiri"));
    // The cluster's kubectl context (`kiri k8s`); the cluster stays in Kiri's data.
    crate::k8s::forget();
    // Every flavor has a helper of its own.
    if let Err(e) = crate::usb::helper::remove() {
        println!("could not remove the USB helper ({e})");
    }
    if dev() {
        println!("{0}'s data stays in ~/Library/Application Support/{0}; delete it to remove images and volumes too", crate::flavor::APP);
        return Ok(());
    }
    match home().and_then(|h| remove_shell_path(&h, &zdotdir(&h))) {
        Ok(()) => println!("removed ~/.kiri/bin from shell profiles"),
        Err(e) => println!("could not tidy the shell profiles ({e})"),
    }
    if let Err(e) = remove_domains() {
        println!("could not remove {} ({e})", crate::daemon::dns::RESOLVER);
    }
    if let Err(e) = remove_docker_socket() {
        println!("could not remove {DOCKER_SOCK} ({e})");
    }
    println!("Kiri's data stays in ~/Library/Application Support/Kiri; delete it to remove images and volumes too");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn runs_apple_script() {
        super::apple_script("do shell script \"true\"").unwrap();
        let e = super::apple_script("error number -128").unwrap_err();
        assert!(e.to_string().contains("-128"), "{e}");
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kiri-setup-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Settings → Storage moved the data folder: Kiri Lite's plugin folder
    /// follows it, and other plugin folders stay.
    #[test]
    fn plugin_folders_follow_the_data_folder() {
        use std::path::Path;
        let (old, new) = (Path::new("/Users/u/Library/Application Support/Kiri"), Path::new("/Volumes/External/kiri"));
        let mut cfg = serde_json::json!({"cliPluginsExtraDirs": ["/opt/homebrew/lib/docker/cli-plugins", "/Users/u/Library/Application Support/Kiri/cli/cli-plugins"]});
        assert!(super::repoint_plugin_dirs(&mut cfg, old, new));
        assert_eq!(cfg["cliPluginsExtraDirs"], serde_json::json!(["/opt/homebrew/lib/docker/cli-plugins", "/Volumes/External/kiri/cli/cli-plugins"]));
        assert!(!super::repoint_plugin_dirs(&mut cfg, old, new), "nothing left to move");
        assert_eq!(super::moved(Path::new("/elsewhere/docker"), old, new), None);
    }

    #[test]
    fn docker_sock_owner() {
        use crate::dockerctx::Endpoint::*;
        let d = scratch("sock");
        let ours = d.join("kiri/run/docker.sock");
        let link = d.join("docker.sock");
        let at = |engines: &[std::path::PathBuf]| crate::dockerctx::sock_at(&link, &ours, engines);
        assert_eq!(at(&[]), Free);
        std::os::unix::fs::symlink(&ours, &link).unwrap();
        assert_eq!(at(&[]), Kiri, "Kiri's link, even with the daemon stopped");
        // OrbStack's link with OrbStack not running: still OrbStack's.
        std::fs::remove_file(&link).unwrap();
        let orb = d.join(".orbstack/run/docker.sock");
        std::os::unix::fs::symlink(&orb, &link).unwrap();
        assert_eq!(at(&[d.join(".orbstack")]), Taken(orb.display().to_string()));
        // ... and free once OrbStack is gone.
        assert_eq!(at(&[]), Free);
        // Another engine's own socket.
        std::fs::remove_file(&link).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&link).unwrap();
        assert!(matches!(at(&[]), Taken(_)));
        drop(listener);
        std::fs::remove_file(&link).unwrap();
        std::fs::write(&link, "").unwrap();
        assert!(matches!(at(&[]), Taken(_)), "a plain file is left alone");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn testcontainers_file_is_kiris_only_when_marked() {
        let d = scratch("tc");
        let path = d.join(".testcontainers.properties");
        let ours = std::path::Path::new("/Users/me/.kiri/run/docker.sock");
        assert!(super::testcontainers_at(&path, ours, true).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), super::testcontainers_text(ours));
        assert!(std::fs::read_to_string(&path).unwrap().contains("docker.host=unix:///Users/me/.kiri/run/docker.sock\n"));
        assert!(!super::testcontainers_at(&path, ours, false).unwrap());
        assert!(!path.exists());
        // The user's own file, or one Testcontainers has added to, stays.
        for text in ["docker.host=tcp://remote:2375\n", &format!("{}testcontainers.reuse.enable=true\n", super::testcontainers_text(ours))] {
            std::fs::write(&path, text).unwrap();
            assert!(!super::testcontainers_at(&path, ours, true).unwrap());
            assert!(!super::testcontainers_at(&path, ours, false).unwrap());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn quotes_for_sh() {
        assert_eq!(super::sh_quote("/Users/o'neil/.kiri"), r"'/Users/o'\''neil/.kiri'");
    }

    // #250: a profile that is a link to nowhere (a dotfiles folder that
    // moved) is passed over, not the end of the app's first launch.
    #[test]
    fn a_dangling_profile_link_does_not_stop_setup() {
        let h = scratch("dangling");
        std::os::unix::fs::symlink(h.join("dotfiles-gone/zshrc"), h.join(".zshrc")).unwrap();
        super::shell_path(&h, &h).unwrap();
        assert!(std::fs::read_link(h.join(".zshrc")).is_ok(), "the user's link stays a link");
        assert!(!h.join("dotfiles-gone").exists(), "nothing made where it points");
        assert!(std::fs::read_to_string(h.join(".zprofile")).unwrap().contains(super::PROFILE_MARK), "the other profiles still get the line");
        super::remove_shell_path(&h, &h).unwrap();
        let _ = std::fs::remove_dir_all(&h);
    }

    // #250, as Nix home-manager sets a Mac up: a profile Kiri can read but
    // not write (a link into a read-only store) is passed over, whether or
    // not Kiri's line is in it already, and the other profiles get the line.
    #[test]
    fn a_read_only_profile_does_not_stop_setup() {
        use std::os::unix::fs::PermissionsExt;
        let with_line = format!("# managed elsewhere\n\n{}\n{}\n", super::PROFILE_MARK, super::SH_LINE);
        for (round, text) in ["# managed elsewhere\n", with_line.as_str()].into_iter().enumerate() {
            let h = scratch(&format!("readonly{round}"));
            let managed = h.join("store/zshrc");
            std::fs::create_dir_all(h.join("store")).unwrap();
            std::fs::write(&managed, text).unwrap();
            std::fs::set_permissions(&managed, std::fs::Permissions::from_mode(0o444)).unwrap();
            // root writes through the mode: nothing read-only to try then.
            if std::fs::OpenOptions::new().append(true).open(&managed).is_ok() {
                let _ = std::fs::remove_dir_all(&h);
                return;
            }
            std::os::unix::fs::symlink(&managed, h.join(".zshrc")).unwrap();
            super::shell_path(&h, &h).unwrap();
            assert_eq!(std::fs::read_to_string(&managed).unwrap(), text, "the read-only profile is as it was");
            assert!(std::fs::read_link(h.join(".zshrc")).is_ok(), "the user's link stays a link");
            assert!(std::fs::read_to_string(h.join(".zprofile")).unwrap().contains(super::PROFILE_MARK), "the other profiles still get the line");
            let _ = std::fs::remove_dir_all(&h);
        }
    }

    // A profile Kiri can't read as text is left exactly as it was, never
    // replaced by Kiri's lines alone.
    #[test]
    fn an_unreadable_profile_is_left_alone() {
        let h = scratch("unreadable");
        let latin1: &[u8] = b"# caf\xe9 settings\nexport EDITOR=vim\n";
        std::fs::write(h.join(".zshrc"), latin1).unwrap();
        super::shell_path(&h, &h).unwrap();
        assert_eq!(std::fs::read(h.join(".zshrc")).unwrap(), latin1);
        assert!(std::fs::read_to_string(h.join(".zprofile")).unwrap().contains(super::PROFILE_MARK));
        let _ = std::fs::remove_dir_all(&h);
    }

    #[test]
    fn shell_profiles_put_kiri_on_path_once_and_take_it_back() {
        let h = scratch("profiles");
        std::fs::write(h.join(".zprofile"), "export A=1").unwrap();
        // An install by Kiri 0.1.0: the old line, in .zprofile only.
        std::fs::write(h.join(".profile"), format!("export B=2\n\n{}\n{}\n", super::PROFILE_MARK, super::OLD_SH_LINE)).unwrap();
        std::fs::write(h.join(".bashrc"), "").unwrap();
        super::shell_path(&h, &h).unwrap();
        super::shell_path(&h, &h).unwrap();
        let read = |f: &str| std::fs::read_to_string(h.join(f)).unwrap();
        for f in [".zprofile", ".zshrc", ".bashrc"] {
            assert_eq!(read(f).matches(super::SH_LINE).count(), 1, "{f}: {}", read(f));
        }
        assert!(read(".zprofile").starts_with("export A=1\n\n"));
        // bash's login file is .profile here: no .bash_profile to shadow it.
        assert!(!h.join(".bash_profile").exists());
        assert!(!read(".profile").contains(super::SH_LINE));
        super::remove_shell_path(&h, &h).unwrap();
        assert_eq!(read(".zprofile").trim_end(), "export A=1");
        assert_eq!(read(".profile").trim_end(), "export B=2");
        assert_eq!(read(".zshrc").trim(), "");
        assert!(!read(".bashrc").contains("kiri"));
        assert!(!super::profiles_configured_file(&h).exists());
        assert!(!super::no_profiles_file(&h).exists());
        let _ = std::fs::remove_dir_all(&h);
    }

    // #556: initial setup records `profiles-configured` in `~/.kiri` so
    // subsequent app launches (`shell_path_once`) do not re-append Kiri's
    // block after the user or a dotfiles manager removes it, until
    // `kiri setup --uninstall` resets state.
    #[test]
    fn first_launch_edits_shell_profiles_only_once() {
        let h = scratch("once");
        std::fs::write(h.join(".zprofile"), "export A=1\n").unwrap();
        std::fs::write(h.join(".zshrc"), "export B=2\n").unwrap();

        super::shell_path_once(&h, &h).unwrap();
        assert!(super::profiles_configured_file(&h).is_file());
        assert!(std::fs::read_to_string(h.join(".zprofile")).unwrap().contains(super::PROFILE_MARK));
        assert!(std::fs::read_to_string(h.join(".zshrc")).unwrap().contains(super::PROFILE_MARK));

        // The user or a dotfiles manager restores the profiles without Kiri's block.
        std::fs::write(h.join(".zprofile"), "export A=1\n").unwrap();
        std::fs::write(h.join(".zshrc"), "export B=2\n").unwrap();

        // Subsequent app launches leave the cleaned-up profiles untouched.
        super::shell_path_once(&h, &h).unwrap();
        assert_eq!(std::fs::read_to_string(h.join(".zprofile")).unwrap(), "export A=1\n");
        assert_eq!(std::fs::read_to_string(h.join(".zshrc")).unwrap(), "export B=2\n");

        // Explicit `kiri setup` from the CLI still adds the lines when asked.
        super::shell_path(&h, &h).unwrap();
        assert!(std::fs::read_to_string(h.join(".zprofile")).unwrap().contains(super::PROFILE_MARK));
        assert!(std::fs::read_to_string(h.join(".zshrc")).unwrap().contains(super::PROFILE_MARK));

        // Uninstall removes the lines and clears the marker so a fresh install sets up again.
        super::remove_shell_path(&h, &h).unwrap();
        assert!(!super::profiles_configured_file(&h).exists());
        std::fs::write(h.join(".zprofile"), "export A=1\n").unwrap();
        std::fs::write(h.join(".zshrc"), "export B=2\n").unwrap();
        super::shell_path_once(&h, &h).unwrap();
        assert!(std::fs::read_to_string(h.join(".zprofile")).unwrap().contains(super::PROFILE_MARK));
        assert!(std::fs::read_to_string(h.join(".zshrc")).unwrap().contains(super::PROFILE_MARK));

        let _ = std::fs::remove_dir_all(&h);
    }

    // #556: a profile that already puts `~/.kiri/bin` on PATH without Kiri's
    // marker comment (such as a dotfiles-managed profile) is not given a
    // duplicate block even on the first setup, and uninstall leaves the user's
    // line alone.
    #[test]
    fn profile_already_referencing_kiri_bin_is_not_duplicated() {
        let h = scratch("dotfiles-path");
        let custom_zsh = "export PATH=\"$HOME/.kiri/bin:$PATH\"\n";
        let custom_bash = "path_prepend ~/.kiri/bin\n";
        let custom_fish = "fish_add_path ~/.kiri/bin\n";
        std::fs::write(h.join(".zshrc"), custom_zsh).unwrap();
        std::fs::write(h.join(".bashrc"), custom_bash).unwrap();
        std::fs::create_dir_all(h.join(".config/fish/conf.d")).unwrap();
        std::fs::write(h.join(".config/fish/conf.d/kiri.fish"), custom_fish).unwrap();

        super::shell_path_once(&h, &h).unwrap();

        // Profiles that already reference `.kiri/bin` are untouched.
        assert_eq!(std::fs::read_to_string(h.join(".zshrc")).unwrap(), custom_zsh);
        assert_eq!(std::fs::read_to_string(h.join(".bashrc")).unwrap(), custom_bash);
        assert_eq!(std::fs::read_to_string(h.join(".config/fish/conf.d/kiri.fish")).unwrap(), custom_fish);
        // Profiles without `.kiri/bin` still get the block on initial setup.
        assert!(std::fs::read_to_string(h.join(".zprofile")).unwrap().contains(super::PROFILE_MARK));

        // Uninstall removes only Kiri's marked block and preserves the user's own `.kiri/bin` lines.
        super::remove_shell_path(&h, &h).unwrap();
        assert_eq!(std::fs::read_to_string(h.join(".zshrc")).unwrap(), custom_zsh);
        assert_eq!(std::fs::read_to_string(h.join(".bashrc")).unwrap(), custom_bash);
        assert_eq!(std::fs::read_to_string(h.join(".config/fish/conf.d/kiri.fish")).unwrap(), custom_fish);
        assert_eq!(std::fs::read_to_string(h.join(".zprofile")).unwrap().trim(), "");

        let _ = std::fs::remove_dir_all(&h);
    }

    // #556: `kiri setup --no-profiles` removes any existing Kiri block, records
    // `no-profiles` in `~/.kiri` so neither subsequent launches nor `kiri setup`
    // touch shell profiles, and `kiri setup --uninstall` clears the opt-out.
    #[test]
    fn no_profiles_opt_out_removes_existing_lines_and_persists_until_uninstall() {
        let h = scratch("no-profiles");
        std::fs::write(h.join(".zprofile"), "export A=1\n").unwrap();
        std::fs::write(h.join(".zshrc"), "export B=2\n").unwrap();

        // Initial setup adds Kiri's lines.
        super::shell_path_once(&h, &h).unwrap();
        assert!(std::fs::read_to_string(h.join(".zprofile")).unwrap().contains(super::PROFILE_MARK));
        assert!(std::fs::read_to_string(h.join(".zshrc")).unwrap().contains(super::PROFILE_MARK));

        // Opting out with `kiri setup --no-profiles` removes Kiri's lines and persists `no-profiles`.
        super::opt_out_shell_path(&h, &h).unwrap();
        assert!(!super::shell_path_enabled_in(&h, &h));
        assert!(super::no_profiles_file(&h).is_file());
        assert!(!super::profiles_configured_file(&h).exists());
        assert_eq!(std::fs::read_to_string(h.join(".zprofile")).unwrap().trim_end(), "export A=1");
        assert_eq!(std::fs::read_to_string(h.join(".zshrc")).unwrap().trim_end(), "export B=2");

        // Neither subsequent app launches nor explicit `kiri setup` edit profiles while opted out.
        super::shell_path_once(&h, &h).unwrap();
        super::shell_path(&h, &h).unwrap();
        assert_eq!(std::fs::read_to_string(h.join(".zprofile")).unwrap().trim_end(), "export A=1");
        assert_eq!(std::fs::read_to_string(h.join(".zshrc")).unwrap().trim_end(), "export B=2");

        // Settings → Appearance toggling On re-enables profiles and clears `no-profiles`; Off opts out again.
        super::set_shell_path_in(&h, &h, true).unwrap();
        assert!(super::shell_path_enabled_in(&h, &h));
        assert!(!super::no_profiles_file(&h).exists());
        assert!(std::fs::read_to_string(h.join(".zprofile")).unwrap().contains(super::PROFILE_MARK));
        super::set_shell_path_in(&h, &h, false).unwrap();
        assert!(!super::shell_path_enabled_in(&h, &h));
        assert!(super::no_profiles_file(&h).is_file());

        // Uninstall clears `no-profiles` so a fresh install after uninstall sets up profiles again.
        super::remove_shell_path(&h, &h).unwrap();
        assert!(!super::no_profiles_file(&h).exists());
        super::shell_path_once(&h, &h).unwrap();
        assert!(std::fs::read_to_string(h.join(".zprofile")).unwrap().contains(super::PROFILE_MARK));
        assert!(std::fs::read_to_string(h.join(".zshrc")).unwrap().contains(super::PROFILE_MARK));

        let _ = std::fs::remove_dir_all(&h);
    }

    #[test]
    fn path_line_works_in_sh_and_adds_once() {
        let out = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("{0}\n{0}\nprintf %s \"$PATH\"", super::SH_LINE))
            .env("HOME", "/h")
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "/usr/bin:/bin:/h/.kiri/bin");
    }

    #[test]
    fn launch_agent_plist_run_at_load_generates_parses_and_toggles() {
        let d = scratch("plist");
        let exe = std::path::Path::new("/Applications/Kiri.app/Contents/MacOS/kiri");
        let log = d.join(".kiri/daemon.log");
        let plist_path = d.join("Library/LaunchAgents/dev.kiri.daemon.plist");

        let xml_on = super::agent_plist_xml(exe, &log, true);
        assert_eq!(super::plist_run_at_load(&xml_on), Some(true));
        assert!(xml_on.contains("<key>RunAtLoad</key><true/>"));

        let xml_off = super::agent_plist_xml(exe, &log, false);
        assert_eq!(super::plist_run_at_load(&xml_off), Some(false));
        assert!(xml_off.contains("<key>RunAtLoad</key><false/>"));

        let flipped_off = super::set_plist_run_at_load(&xml_on, false).unwrap();
        assert_eq!(flipped_off, xml_off);
        assert_eq!(super::plist_run_at_load(&flipped_off), Some(false));

        let flipped_on = super::set_plist_run_at_load(&flipped_off, true).unwrap();
        assert_eq!(flipped_on, xml_on);
        assert_eq!(super::plist_run_at_load(&flipped_on), Some(true));

        // File creation and in-place toggling keep the rest of the plist valid.
        super::set_start_at_login_at(&plist_path, exe, &log, true).unwrap();
        assert_eq!(super::plist_run_at_load(&std::fs::read_to_string(&plist_path).unwrap()), Some(true));
        super::set_start_at_login_at(&plist_path, exe, &log, false).unwrap();
        let saved = std::fs::read_to_string(&plist_path).unwrap();
        assert_eq!(super::plist_run_at_load(&saved), Some(false));
        assert!(saved.contains("<string>/Applications/Kiri.app/Contents/MacOS/kiri</string><string>daemon</string>"));
        super::set_start_at_login_at(&plist_path, exe, &log, true).unwrap();
        assert_eq!(super::plist_run_at_load(&std::fs::read_to_string(&plist_path).unwrap()), Some(true));

        let _ = std::fs::remove_dir_all(&d);
    }

    // #733: when Homebrew's cask `binary` stanza links `$(brew --prefix)/bin/kiri`
    // directly to `Kiri.app/Contents/MacOS/kiri`, setup recognizes it, skips
    // shell profile edits, and preserves Homebrew's `/usr/local/bin/kiri` link,
    // while Kiri's own `~/.kiri/bin/kiri` indirect link is not mistaken for Homebrew's.
    #[test]
    fn homebrew_cask_binary_link_is_detected_and_preserved() {
        let d = scratch("homebrew-link");
        let app_kiri = d.join("Applications/Kiri.app/Contents/MacOS/kiri");
        let other_app = d.join("Downloads/Kiri.app/Contents/MacOS/kiri");
        let our_bin_kiri = d.join(".kiri/bin/kiri");
        let opt_brew_kiri = d.join("opt/homebrew/bin/kiri");
        let usr_local_kiri = d.join("usr/local/bin/kiri");
        for p in [&app_kiri, &other_app, &our_bin_kiri, &opt_brew_kiri, &usr_local_kiri] {
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        }
        std::fs::write(&app_kiri, "#!/bin/sh\n").unwrap();
        std::fs::write(&other_app, "#!/bin/sh\n").unwrap();
        std::os::unix::fs::symlink(&app_kiri, &our_bin_kiri).unwrap();

        // No Homebrew link yet.
        assert!(!super::homebrew_links_app_in(&[opt_brew_kiri.clone(), usr_local_kiri.clone()], &app_kiri));

        // Kiri's own `system_link` (`/usr/local/bin/kiri -> ~/.kiri/bin/kiri`) is NOT a Homebrew cask link.
        super::system_link_at(&usr_local_kiri, &our_bin_kiri, &app_kiri);
        assert_eq!(std::fs::read_link(&usr_local_kiri).unwrap(), our_bin_kiri);
        assert!(!super::homebrew_links_app_in(&[opt_brew_kiri.clone(), usr_local_kiri.clone()], &app_kiri));

        // Homebrew cask link on Apple silicon (`/opt/homebrew/bin/kiri -> .../Kiri.app/Contents/MacOS/kiri`).
        std::os::unix::fs::symlink(&app_kiri, &opt_brew_kiri).unwrap();
        assert!(super::homebrew_links_app_in(&[opt_brew_kiri.clone()], &app_kiri));
        assert!(!super::homebrew_links_app_in(&[opt_brew_kiri.clone()], &other_app));

        // Homebrew cask link on Intel (`/usr/local/bin/kiri -> .../Kiri.app/Contents/MacOS/kiri`) is preserved by `system_link_at`.
        std::fs::remove_file(&usr_local_kiri).unwrap();
        std::os::unix::fs::symlink(&app_kiri, &usr_local_kiri).unwrap();
        assert!(super::homebrew_links_app_in(&[usr_local_kiri.clone()], &app_kiri));
        super::system_link_at(&usr_local_kiri, &our_bin_kiri, &app_kiri);
        assert_eq!(std::fs::read_link(&usr_local_kiri).unwrap(), app_kiri, "Homebrew's direct cask link stays untouched");

        // Custom `$HOMEBREW_PREFIX` adds `<prefix>/bin/kiri` without duplicating standard prefixes.
        let cands = super::homebrew_kiri_candidates(Some(std::ffi::OsStr::new("/custom/brew")));
        assert!(cands.contains(&std::path::PathBuf::from("/custom/brew/bin/kiri")));
        assert_eq!(super::homebrew_kiri_candidates(Some(std::ffi::OsStr::new("/opt/homebrew"))).len(), 2);

        let _ = std::fs::remove_dir_all(&d);
    }
}
