//! kiri-win: Kiri's Windows side. Serves the Docker API on a named pipe,
//! `\\.\pipe\kiri`, and carries each connection into WSL2 over one
//! long-lived `wsl.exe -u root -- kiri bridge`, multiplexed. TCP through
//! WSL's localhost relay loses half-closes, which `docker run` and
//! `attach` depend on; the pipe and the bridge keep them. It is also
//! Kiri's window and tray icon.
//!
//!   kiri-win [--background] [--distro NAME] [--pipe \\.\pipe\kiri] [--socket PATH] [--kiri PATH]
//!
//! `--background` (from the login shortcut) starts with the tray icon only.
//! Starting it again while it runs shows the running one's window.
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod app;
// The address the window's page is served at, from memory: plain code,
// tested on any host.
#[cfg(any(windows, test))]
mod page;
// The window's page, put together as on the Mac and Linux.
#[cfg(windows)]
#[path = "../../kiri/src/ui/assemble.rs"]
mod assemble;
// Its language, and the tray menu's words.
#[cfg(windows)]
#[path = "../../kiri/src/ui/lang.rs"]
mod lang;
#[cfg(any(windows, test))]
mod client;
#[cfg(windows)]
mod detail;
#[cfg(windows)]
mod dns;
#[cfg(windows)]
mod engine;
#[cfg(windows)]
mod pipe;
#[cfg(windows)]
mod serve;
// A proxy on Windows' loopback, reached from WSL: relay.rs, over the
// relay's frames shared with the WSL end.
#[cfg(windows)]
mod relay;
#[cfg(windows)]
#[path = "../../kiri/src/hostrelay.rs"]
mod hostrelay;
#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
#[path = "../../kiri/src/dockerctx.rs"]
mod dockerctx;
#[cfg(windows)]
mod win;
// The window's USB view, through usbipd-win.
#[cfg(windows)]
mod usb;
#[cfg(windows)]
mod setup;
// The built-in terminal's shells, on ConPTY.
#[cfg(windows)]
mod term;
#[cfg(windows)]
mod hub;
#[cfg(windows)]
mod k8s;
#[cfg(windows)]
mod diag;
// The Builds view: BuildKit's history through `docker buildx history`, the
// Mac's own crates/kiri/src/builds.rs, and the time parsing it uses.
#[cfg(windows)]
#[path = "../../kiri/src/builds.rs"]
#[allow(dead_code)]
mod builds;
// Which builder plain `docker build` uses, Docker's or Kiri's: the Mac's
// and Linux's own crates/kiri/src/buildwith.rs.
#[cfg(windows)]
#[path = "../../kiri/src/buildwith.rs"]
#[allow(dead_code)]
mod buildwith;
// Kiri's program moved or deleted from where it started: the Mac's and
// Linux's own crates/kiri/src/appwatch.rs.
#[cfg(windows)]
#[path = "../../kiri/src/appwatch.rs"]
mod appwatch;
// An image's Layers and Security tabs, asked of the engine in WSL.
#[cfg(windows)]
mod scan;
// The Mac's crates/kiri/src/daemon/time.rs, as crate::daemon::time (what
// builds.rs calls it). Pathed at the top level: a #[path] inside an inline
// `mod daemon` resolves from src/daemon/, a folder that does not exist, and
// only Windows' lexical `..` forgives that.
#[cfg(windows)]
#[path = "../../kiri/src/daemon/time.rs"]
#[allow(dead_code)]
mod daemon_time;
#[cfg(windows)]
mod daemon {
    pub(crate) use super::daemon_time as time;
}
#[cfg(windows)]
mod wslconfig;
// Kiri Dev's names (the window on Windows is always Kiri) and Share, the
// Mac's own files: crates/kiri/src/flavor.rs and share.rs. Share's roots
// come from crates/kiri-image/src/roots.rs, mounted here directly as
// crate::roots — the name share.rs reaches it by in kiri, whose main.rs
// aliases kiri_image::roots — so the same file compiles unchanged.
#[cfg(windows)]
#[path = "../../kiri/src/flavor.rs"]
mod flavor;
#[cfg(windows)]
#[path = "../../kiri-image/src/roots.rs"]
#[allow(dead_code)]
mod roots;
#[cfg(windows)]
#[path = "../../kiri/src/share.rs"]
#[allow(dead_code)]
mod share;
#[cfg(windows)]
mod update;
// The engine's files put into WSL, and what a docker client is told when
// the engine there cannot be reached: plain code, tested on any host.
#[cfg(any(windows, test))]
mod wslsync;
#[cfg(any(windows, test))]
mod refuse;
// Opt-in Windows bind-mount watcher (ReadDirectoryChangesW -> /kiri/fs-events):
// path mapping, buffer decoding and coalescing tested on any host.
#[cfg(any(windows, test))]
mod watch;
// Windows inbound published-port forwarder (UDP and non-loopback host-IP TCP
// to WSL 2's eth0 IPv4 address): tested on any host.
#[cfg(any(windows, test))]
mod ports;
// Settings → Storage: custom WSL distro location in %LOCALAPPDATA%\Kiri\storage.json.
#[cfg(any(windows, test))]
mod storage;

#[cfg(any(windows, test))]
pub(crate) fn format_try_wait(res: std::io::Result<Option<std::process::ExitStatus>>) -> Option<String> {
    match res {
        Ok(None) => None,
        Ok(Some(status)) => Some(format!("{status}")),
        Err(e) => Some(format!("{e}")),
    }
}

#[cfg(any(windows, test))]
pub(crate) fn format_wait_status(res: std::io::Result<std::process::ExitStatus>) -> String {
    match res {
        Ok(status) => format!("{status}"),
        Err(e) => format!("{e}"),
    }
}
// Settings → Import from Docker Desktop: the Mac's and Linux's own
// crates/kiri/src/import.rs, through the docker CLI's contexts.
#[cfg(windows)]
#[path = "../../kiri/src/import.rs"]
#[allow(dead_code)]
mod import;

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    // There is no console to print a panic to.
    std::panic::set_hook(Box::new(|info| serve::log(&format!("panic: {info}"))));
    // Load DLLs only from System32, not from the folder kiri-win runs from.
    win::harden_dll_search();
    // Uninstalling (contrib/windows/kiri.ps1): docker build's own builder
    // back as it was before Kiri changed it, and nothing else.
    if std::env::args().any(|a| a == "--uninstall-builds") {
        return match buildwith::places().and_then(|p| p.uninstall()) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                serve::log(&format!("uninstall: docker build's builder: {e}"));
                std::process::ExitCode::FAILURE
            }
        };
    }
    // Uninstalling, too: the cluster's `kiri` kubectl context out of
    // %USERPROFILE%\.kube\config, the rest of the file as it was.
    if std::env::args().any(|a| a == "--uninstall-kubeconfig") {
        return match k8s::forget() {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                serve::log(&format!("uninstall: kubectl context: {e}"));
                std::process::ExitCode::FAILURE
            }
        };
    }
    // An update Later staged that the last quit didn't install: in now, and
    // the helper opens the new Kiri once this process has gone.
    // A staged update goes in before anything else, once: if the helper
    // that was left to install it failed, Kiri starts as it is and the
    // window offers the update again rather than quitting on every launch.
    if update::staged().is_some() && !update::attempted() {
        match update::install_staged() {
            Ok(_) => return std::process::ExitCode::SUCCESS,
            Err(e) => serve::log(&format!("update: the staged update did not install: {e}")),
        }
    }
    let cfg = serve::Config::from_args();
    let background = std::env::args().any(|a| a == "--background");
    // First run (or Kiri's Linux gone): the window opens on setup. Naming a
    // distro (--distro) is for development and skips it.
    let setup = !std::env::args().any(|a| a == "--distro") && setup::needed();
    serve::set_setup_pending(setup);
    serve::init_stopped();
    if let Err(e) = serve::start(cfg.clone()) {
        // Another kiri-win already serves the pipe: show its window instead.
        if app::running() {
            if !background {
                app::show_running();
            }
            return std::process::ExitCode::SUCCESS;
        }
        // No Kiri to show: whatever holds the name is not Kiri, and docker
        // commands would talk to it as if it were. Say so and stop.
        let msg = format!("pipe: {e}; not starting");
        serve::log(&msg);
        eprintln!("kiri-win: {msg}");
        return std::process::ExitCode::FAILURE;
    }
    client::set_pipe(&cfg.pipe);
    if !setup {
        engine::heal_docker_config(&cfg.pipe);
    }
    ports::start();
    if let Err(e) = dns::start() {
        serve::log(&format!("dns on 127.0.0.1:53: {e}"));
    }
    engine::start(engine::Env { distro: cfg.distro.clone(), pipe: cfg.pipe.clone() });
    watch::start_if_enabled();
    // Its folder renamed, moved or deleted around it (Windows won't delete
    // a running program itself): docker build handed back as it was before
    // Kiri took it, the choice kept for when Kiri runs again, and Kiri quits.
    appwatch::watch(|exe| {
        serve::log(&format!("{} is gone from where Kiri started; handing docker build back and quitting", exe.display()));
        if let Err(e) = buildwith::places().and_then(|p| p.give_back()) {
            serve::log(&format!("docker build not handed back: {e}"));
        }
        app::Handle.run(|_| {
            // SAFETY: ends the window's message loop; run on its thread.
            unsafe { windows::Win32::UI::WindowsAndMessaging::PostQuitMessage(0) }
        });
        // No window to quit (it never opened): quit from here.
        std::thread::sleep(std::time::Duration::from_secs(5));
        std::process::exit(0);
    });
    // The engine starts when the page says `ready`, and with the window
    // hidden (--background, as from the login shortcut) no page loads: after
    // kiri-win restarted, docker got no answer until Start was pressed.
    // Bring it up now. ensure_daemon runs kiri-start only when the daemon
    // does not answer, and kiri-start does nothing while one runs, so a
    // daemon already up is left alone and never doubled. An engine the
    // person stopped stays stopped: that waits for Start, as when the
    // window opens.
    if background && !setup {
        engine::send(engine::Cmd::Launch);
    }
    let result = app::run(
        !background || setup,
        setup,
        |msg| if app::in_setup() && setup::handles(&msg) { setup::on_message(&msg) } else { engine::on_message(&msg) },
        engine::on_tray,
    );
    // The window has quit (Restart now on the update card, or Quit after
    // Later): a staged update goes in now, from here only, so the helper
    // is left behind once (it waits for this process to end).
    if update::staged().is_some()
        && let Err(e) = update::install_staged()
    {
        serve::log(&format!("update: the staged update did not install: {e}"));
    }
    if let Err(e) = result {
        serve::log(&format!("window: {e}"));
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("kiri-win runs on Windows only");
    std::process::ExitCode::FAILURE
}

#[cfg(test)]
mod exit_status_tests {
    #[test]
    fn formats_exit_status_with_display_instead_of_nested_debug() {
        let run = |code: i32| {
            #[cfg(windows)]
            let mut cmd = {
                let mut c = std::process::Command::new("cmd");
                c.args(["/C", &format!("exit {code}")]);
                c
            };
            #[cfg(not(windows))]
            let mut cmd = {
                let mut c = std::process::Command::new("sh");
                c.args(["-c", &format!("exit {code}")]);
                c
            };
            cmd.status().unwrap()
        };
        let status = run(15);
        let waited = super::format_wait_status(Ok(status));
        assert!(!waited.contains("Ok(") && !waited.contains("ExitStatus("), "nested Debug leaked: {waited}");
        assert!(waited.contains("15"), "{waited}");
        let polled = super::format_try_wait(Ok(Some(status))).unwrap();
        assert_eq!(polled, waited);
        assert_eq!(super::format_try_wait(Ok(None)), None);
        assert_eq!(super::format_wait_status(Err(std::io::Error::other("wait failed"))), "wait failed");
    }
}
