//! The `kiri` command.

// Share's roots, aliased at the crate root so its crate::roots::trusted()
// resolves; kiri-win mounts the same file by #[path] instead.
#[cfg(any(unix, windows))]
use kiri_image::roots;
use std::process::ExitCode;

#[cfg(target_os = "macos")]
mod bench;
#[cfg(target_os = "macos")]
mod boot;
// builds, cli_pins, scan and tools on Linux too: the daemon reads an
// image's layers and scans it for kiri-win, whose window can't reach the
// store inside WSL (daemon/api.rs).
#[cfg(unix)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod builds;
// The engine stops when its app is deleted under it (kiri-win includes it
// for Windows).
#[cfg(unix)]
mod appwatch;
// Which builder plain `docker build` uses: Docker's or Kiri's.
#[cfg(unix)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod buildwith;
// Linux only, but its tests run anywhere with unix sockets.
#[cfg(any(target_os = "linux", all(test, unix)))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod bridge;
// Linux only (WSL's end of kiri-win's proxy relay); its tests run anywhere.
#[cfg(unix)]
mod hostrelay;
#[cfg(unix)]
mod cli_pins;
#[cfg(unix)]
mod client;
#[cfg(unix)]
mod daemon;
#[cfg(unix)]
mod diag;
#[cfg(any(unix, windows))]
mod docker;
#[cfg(any(target_os = "macos", all(target_os = "linux", feature = "window"), test))]
#[cfg_attr(not(any(target_os = "macos", all(target_os = "linux", feature = "window"))), allow(dead_code))]
mod dockerctx;
// `kiri domains`: the container-domain routers' ports (Windows: in WSL).
#[cfg(unix)]
mod domains_cli;
mod flavor;
mod images;
#[cfg(unix)]
mod guest;
#[cfg(target_os = "linux")]
mod hostaccess;
#[cfg(target_os = "macos")]
mod import;
#[cfg(unix)]
mod k8s;
// kubectl's own file, which `kiri k8s` puts its context in.
#[cfg(unix)]
mod kubeconfig;
#[cfg(unix)]
mod machine;
#[cfg(unix)]
mod registry_cli;
#[cfg(unix)]
mod run;
#[cfg(unix)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod scan;
// `kiri scan`: vulnerability scanning from the terminal (Windows: in WSL).
#[cfg(unix)]
mod scan_cli;
#[cfg(target_os = "macos")]
mod setup;
#[cfg(unix)]
mod usb;
#[cfg(unix)]
mod stale;
#[cfg(target_os = "macos")]
mod vm_cli;
#[cfg(any(windows, test))]
mod wsl;
#[cfg(any(unix, windows))]
mod share;
#[cfg(any(target_os = "macos", all(target_os = "linux", feature = "window")))]
mod ui;
#[cfg(unix)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod tools;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod update;

const USAGE_LINES: &[&str] = &[
    "usage: kiri COMMAND          docker's commands, on Kiri: kiri run, ps, exec,",
    "                             logs, stop, rm, images, pull, build, compose…",
    "       kiri start                 start Kiri after a Stop (the window's Start)",
    #[cfg(unix)]
    "       kiri daemon",
    #[cfg(target_os = "linux")]
    "       kiri bridge [--socket PATH]   (WSL2: the end of kiri-win.exe)",
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    "       kiri ui [--start] [--view containers|images|volumes|networks|builds]",
    #[cfg(target_os = "macos")]
    "       kiri setup [--use] [--no-agent] [--no-profiles] | kiri setup --uninstall",
    #[cfg(unix)]
    "       kiri build-with [docker|kiri]   which builder docker build uses",
    "       kiri domains [set [--http N] [--https N] | reset]   the *.kiri.local routers' ports",
    "       kiri registry [insecure|mirror] [list | add X... | remove X...]   daemon.json's insecure registries and Docker Hub mirrors",
    "       kiri scan [--json] [--history] <image>   known vulnerabilities in an image, found by Grype",
    #[cfg(target_os = "macos")]
    "       kiri update [--check]      update Kiri (with a container: docker's update)",
    #[cfg(target_os = "linux")]
    "       kiri update --check        check for a newer Kiri (with a container: docker's update)",
    "       kiri diag logs [-f] [--ui|--engine|--cli] [--errors] [-n N]",
    "       kiri diag report [--out PATH] [--send]   (a file to send us, tokens taken out)",
    "       kiri PORT [NAME]           share a local port on the internet (same as kiri share PORT)",
    "       kiri share PORT|CONTAINER [--name N] | share login | logout | status",
    "       kiri k8s start [--use] | stop | status | delete | set [--lan on|off] [--tls-san NAME,…] [--port N] [--version TAG|default] [--k3s-arg ARG]… [--clear-k3s-args]",
    "       kiri usb [list] | attach DEVICE | detach DEVICE   USB devices for containers, beta (Mac: pass through to the VM)",
    "       kiri machine create NAME [--distro D] | list | shell NAME | stop | delete NAME",
    #[cfg(target_os = "macos")]
    "       kiri vm [status | set --shared-nat on|off]   VM networking (off avoids macOS InternetSharing)",
    #[cfg(target_os = "macos")]
    "       kiri import [orbstack | desktop-linux] [--list | [--force] [image|volume|container NAME]]",
    #[cfg(target_os = "macos")]
    "       kiri bench [--runs N] [--image IMAGE] [--network none|bridge]",
    #[cfg(target_os = "macos")]
    "       kiri boot [--console] [--pings N]",
    #[cfg(unix)]
    "       kiri raw run [--rm] [-e KEY=VALUE]... IMAGE [COMMAND...]   (its own guest, no daemon)",
    #[cfg(unix)]
    "       kiri raw pull <image> | raw images | raw rmi <image>...",
];

fn usage() -> String {
    USAGE_LINES.join("\n")
}

#[cfg(any(windows, test))]
const WINDOWS_DAEMON_ERROR: &str = "on Windows, Kiri's engine runs in WSL without `kiri daemon`: run `kiri start` or open Kiri";

#[derive(Debug, PartialEq, Eq)]
enum Command<'a> {
    #[cfg(unix)]
    Daemon(&'a [String]),
    #[cfg(windows)]
    Daemon,
    #[cfg(target_os = "linux")]
    Bridge(&'a [String]),
    #[cfg(target_os = "linux")]
    HostRelay,
    #[cfg(target_os = "linux")]
    HostAccess(&'a [String]),
    #[cfg(unix)]
    RawRun(&'a [String]),
    #[cfg(unix)]
    RawPull(&'a [String]),
    #[cfg(unix)]
    RawImages(&'a [String]),
    #[cfg(unix)]
    RawRmi(&'a [String]),
    #[cfg(target_os = "macos")]
    Bench(&'a [String]),
    #[cfg(target_os = "macos")]
    Boot(&'a [String]),
    #[cfg(target_os = "macos")]
    Setup(&'a [String]),
    #[cfg(any(unix, windows))]
    Share(&'a [String]),
    #[cfg(unix)]
    Start,
    #[cfg(windows)]
    Start(&'a [String]),
    #[cfg(unix)]
    BuildWith(&'a [String]),
    #[cfg(unix)]
    Domains(&'a [String]),
    #[cfg(unix)]
    Registry(&'a [String]),
    #[cfg(unix)]
    Scan(&'a [String]),
    #[cfg(unix)]
    K8s(&'a [String]),
    #[cfg(unix)]
    Machine(&'a [String]),
    #[cfg(unix)]
    Usb(&'a [String]),
    #[cfg(target_os = "macos")]
    Import(&'a [String]),
    #[cfg(target_os = "macos")]
    Vm(&'a [String]),
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    Update(&'a [String]),
    #[cfg(unix)]
    Diag(&'a [String]),
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    Ui(&'a [String]),
    #[cfg(any(unix, windows))]
    Docker(&'a [String]),
    #[cfg(windows)]
    Wsl(&'a [String]),
}

impl<'a> Command<'a> {
    fn parse(args: &'a [String]) -> Option<Command<'a>> {
        match args.first().map(String::as_str) {
            #[cfg(unix)]
            Some("daemon") => Some(Command::Daemon(&args[1..])),
            #[cfg(windows)]
            Some("daemon") => Some(Command::Daemon),
            #[cfg(target_os = "linux")]
            Some("bridge") => Some(Command::Bridge(&args[1..])),
            #[cfg(target_os = "linux")]
            Some("hostrelay") => Some(Command::HostRelay),
            #[cfg(target_os = "linux")]
            Some("host-access") => Some(Command::HostAccess(&args[1..])),
            #[cfg(unix)]
            Some("raw") => match args.get(1).map(String::as_str) {
                Some("run") => Some(Command::RawRun(&args[2..])),
                Some("pull") => Some(Command::RawPull(&args[2..])),
                Some("images") => Some(Command::RawImages(&args[2..])),
                Some("rmi") => Some(Command::RawRmi(&args[2..])),
                _ => None,
            },
            #[cfg(target_os = "macos")]
            Some("bench") => Some(Command::Bench(&args[1..])),
            #[cfg(target_os = "macos")]
            Some("boot") => Some(Command::Boot(&args[1..])),
            #[cfg(target_os = "macos")]
            Some("setup") => Some(Command::Setup(&args[1..])),
            #[cfg(any(unix, windows))]
            Some("share") => Some(Command::Share(&args[1..])),
            // `kiri 3000`: share a port straight away.
            #[cfg(any(unix, windows))]
            Some(a) if share::is_shorthand(a) => Some(Command::Share(args)),
            // Bare: the window's Start (`kiri start NAME` is docker's start).
            #[cfg(unix)]
            Some("start") if args.len() == 1 => Some(Command::Start),
            // On Windows, by the `kiri` in WSL, once kiri-start has the daemon up.
            #[cfg(windows)]
            Some("start") if args.len() == 1 => Some(Command::Start(args)),
            #[cfg(unix)]
            Some("build-with") => Some(Command::BuildWith(&args[1..])),
            #[cfg(unix)]
            Some("domains") => Some(Command::Domains(&args[1..])),
            #[cfg(unix)]
            Some("registry") => Some(Command::Registry(&args[1..])),
            #[cfg(unix)]
            Some("scan") => Some(Command::Scan(&args[1..])),
            #[cfg(unix)]
            Some("k8s") => Some(Command::K8s(&args[1..])),
            #[cfg(unix)]
            Some("machine") => Some(Command::Machine(&args[1..])),
            #[cfg(unix)]
            Some("usb") => Some(Command::Usb(&args[1..])),
            #[cfg(target_os = "macos")]
            Some("import") => Some(Command::Import(&args[1..])),
            #[cfg(target_os = "macos")]
            Some("vm") => Some(Command::Vm(&args[1..])),
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            Some("update") if !docker::is_container_update(&args[1..]) => Some(Command::Update(&args[1..])),
            #[cfg(unix)]
            Some("diag") => Some(Command::Diag(&args[1..])),
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            Some("ui") => Some(Command::Ui(args)),
            #[cfg(any(unix, windows))]
            Some(c) if docker::handles(c) => Some(Command::Docker(args)),
            // Windows: the engine's commands, by the `kiri` in WSL.
            #[cfg(windows)]
            Some(c) if wsl::COMMANDS.contains(&c) => Some(Command::Wsl(args)),
            _ => None,
        }
    }
}

fn main() -> ExitCode {
    flavor::init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Which process this is, for its log and crash reports.
    #[cfg(unix)]
    diag::init(match args.first().map(String::as_str) {
        Some("daemon") => diag::Part::Daemon,
        // Only a build with the window: elsewhere `kiri ui` is a plain
        // command whose message must reach the terminal, not the log's pipe.
        #[cfg(any(target_os = "macos", all(target_os = "linux", feature = "window")))]
        Some("ui") => diag::Part::Ui,
        #[cfg(target_os = "macos")]
        None if setup::launched_from_app() => diag::Part::Ui,
        _ => diag::Part::Cli,
    });
    let result: std::io::Result<()> = match Command::parse(&args) {
        #[cfg(unix)]
        Some(Command::Daemon(rest)) => daemon::run(rest),
        #[cfg(windows)]
        Some(Command::Daemon) => Err(std::io::Error::other(WINDOWS_DAEMON_ERROR)),
        #[cfg(target_os = "linux")]
        Some(Command::Bridge(rest)) => bridge::run(rest),
        #[cfg(target_os = "linux")]
        Some(Command::HostRelay) => hostrelay::run(),
        // Linux hosts: what the window's onboarding needs root for (through pkexec).
        #[cfg(target_os = "linux")]
        Some(Command::HostAccess(rest)) => match hostaccess::run(rest) {
            Ok(code) => return ExitCode::from(code),
            Err(e) => Err(e),
        },
        #[cfg(unix)]
        Some(Command::RawRun(rest)) => run::run(rest),
        #[cfg(unix)]
        Some(Command::RawPull(rest)) => images::pull(rest),
        #[cfg(unix)]
        Some(Command::RawImages(rest)) => images::list(rest),
        #[cfg(unix)]
        Some(Command::RawRmi(rest)) => images::remove(rest),
        #[cfg(target_os = "macos")]
        Some(Command::Bench(rest)) => bench::run(rest),
        #[cfg(target_os = "macos")]
        Some(Command::Boot(rest)) => boot::run(rest),
        #[cfg(target_os = "macos")]
        Some(Command::Setup(rest)) => setup::run(rest),
        #[cfg(any(unix, windows))]
        Some(Command::Share(rest)) => share::run(rest),
        #[cfg(unix)]
        Some(Command::Start) => engine_start(),
        #[cfg(windows)]
        Some(Command::Start(all)) => wsl::run(all),
        #[cfg(unix)]
        Some(Command::BuildWith(rest)) => buildwith::cli(rest),
        #[cfg(unix)]
        Some(Command::Domains(rest)) => domains_cli::run(rest),
        #[cfg(unix)]
        Some(Command::Registry(rest)) => registry_cli::run(rest),
        #[cfg(unix)]
        Some(Command::Scan(rest)) => scan_cli::run(rest),
        #[cfg(unix)]
        Some(Command::K8s(rest)) => k8s::run(rest),
        #[cfg(unix)]
        Some(Command::Machine(rest)) => machine::run(rest),
        #[cfg(unix)]
        Some(Command::Usb(rest)) => usb::run(rest),
        #[cfg(target_os = "macos")]
        Some(Command::Import(rest)) => import::run(rest),
        #[cfg(target_os = "macos")]
        Some(Command::Vm(rest)) => vm_cli::run(rest),
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        Some(Command::Update(rest)) => update::run(rest),
        #[cfg(unix)]
        Some(Command::Diag(rest)) => diag::run(rest),
        #[cfg(any(target_os = "macos", all(target_os = "linux", feature = "window")))]
        Some(Command::Ui(all)) => ui::run(
            all.iter().any(|a| a == "--start"),
            all.iter().position(|a| a == "--view").and_then(|i| all.get(i + 1)).cloned(),
        ),
        // The static engine has no window: the package's own build of it.
        #[cfg(all(target_os = "linux", not(feature = "window")))]
        Some(Command::Ui(all)) => window(all),
        #[cfg(any(unix, windows))]
        Some(Command::Docker(all)) => {
            engine_version_check();
            docker::run(all)
        }
        #[cfg(windows)]
        Some(Command::Wsl(all)) => wsl::run(all),
        // Opening Kiri.app: set up on first launch, then the window.
        #[cfg(target_os = "macos")]
        None if args.is_empty() && setup::launched_from_app() => {
            setup::first_launch();
            ui::run(true, None)
        }
        None => {
            eprintln!("{}", usage());
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // The subcommand only: arguments can carry values.
            #[cfg(unix)]
            if !e.to_string().starts_with("usage:") {
                // Opened from Finder or the Dock there is none: "open" (#250).
                diag::warn!("command failed", command = args.first().map_or(Some("open"), |a| (a.len() <= 20 && a.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')).then_some(a.as_str())).unwrap_or(""), error = e);
            }
            eprintln!("kiri: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Where the `kiri` package puts the window: the same command built with
/// GTK and WebKitGTK (packaging/linux/build.sh).
#[cfg(all(target_os = "linux", not(feature = "window")))]
const WINDOW: &str = "/usr/lib/kiri/kiri-window";

/// `kiri ui` on Linux: runs the package's window, or says why there is none.
#[cfg(all(target_os = "linux", not(feature = "window")))]
fn window(args: &[String]) -> std::io::Result<()> {
    use std::os::unix::process::CommandExt;
    if !std::path::Path::new(WINDOW).exists() {
        return Err(std::io::Error::other(
            "this Kiri has no window. It comes with the kiri package for x86-64 (Debian, Ubuntu, Fedora); \
             kiri-lite and the ARM packages are the engine and CLI only",
        ));
    }
    // exec returns only when it failed.
    Err(std::process::Command::new(WINDOW).args(args).exec())
}

#[cfg(unix)]
fn engine_start_not_running_message() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "Kiri's engine isn't running. Open Kiri, or start it with `kiri daemon`"
    }
    #[cfg(not(target_os = "macos"))]
    {
        client::not_running_message()
    }
}

/// `kiri start`: Kiri on again after a Stop (the window's, the tray's or
/// the menu bar's), as the window's Start does; the containers Stop held
/// come back. On an engine that wasn't stopped it only wakes the VM.
#[cfg(unix)]
fn engine_start() -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    if !client::alive() {
        if let Ok(d) = daemon::state_dir() {
            let _ = std::fs::remove_file(d.join("stopped"));
        }
        update::start_engine()?;
    }
    client::check_alive_with(engine_start_not_running_message())?;
    let r = client::request("POST", "/kiri/wake", None)?;
    // 404: a Linux host's engine, which has no VM to wake and no Stop.
    if !r.ok() && r.status != 404 {
        return Err(std::io::Error::other(r.error()));
    }
    println!("Kiri is started");
    Ok(())
}

#[cfg(not(unix))]
fn engine_version_check() {}

/// Before a docker command: when the engine runs another version than this
/// `kiri`, say so (on stderr, so output stays clean). Either an update whose
/// engine restart was put off, or another `kiri` earlier on PATH.
#[cfg(unix)]
fn engine_version_check() {
    let me = env!("CARGO_PKG_VERSION");
    if me == "0.0.0" || !client::alive() {
        return;
    }
    let Some(engine) = client::request("GET", "/version", None).ok().filter(|r| r.ok()).and_then(|r| client::kiri_version(&r.json()).map(str::to_owned)) else { return };
    if engine != me && engine != "0.0.0" {
        let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "kiri".into());
        eprintln!("kiri: this kiri ({exe}) is {me}, but the engine runs {engine}. Restart the engine to use one version (Kiri → Restart engine), or remove the older kiri.");
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, usage};

    fn parse(words: &[&str]) -> Option<Vec<String>> {
        let args: Vec<String> = words.iter().map(|s| (*s).to_owned()).collect();
        Command::parse(&args)?;
        Some(args)
    }

    fn advertised_subcommands(help: &str) -> Vec<&str> {
        help.lines()
            .filter_map(|line| line.strip_prefix("usage: ").unwrap_or(line).trim_start().strip_prefix("kiri "))
            .filter_map(|rest| rest.split_whitespace().next())
            .collect()
    }

    #[test]
    fn usage_lists_scan_command() {
        let help = usage();
        assert!(help.contains("kiri scan [--json] [--history] <image>"));
        assert!(!help.ends_with('\n'));
    }

    #[test]
    fn usage_lists_only_commands_for_this_os() {
        let help = usage();
        let cmds = advertised_subcommands(&help);
        for common in ["COMMAND", "start", "domains", "registry", "scan", "diag", "PORT", "share", "k8s", "usb", "machine"] {
            assert!(cmds.contains(&common), "help missing `{common}`:\n{help}");
        }
        #[cfg(unix)]
        {
            for unix_cmd in ["daemon", "ui", "build-with", "update", "raw"] {
                assert!(cmds.contains(&unix_cmd), "unix help missing `{unix_cmd}`:\n{help}");
            }
            assert!(
                help.contains("kiri ui [--start] [--view containers|images|volumes|networks|builds]"),
                "unix help missing `kiri ui` views (including builds):\n{help}"
            );
        }
        #[cfg(target_os = "macos")]
        {
            for mac_cmd in ["setup", "update", "vm", "import", "bench", "boot"] {
                assert!(cmds.contains(&mac_cmd), "macOS help missing `{mac_cmd}`:\n{help}");
            }
            assert!(
                help.contains("kiri setup [--use] [--no-agent] [--no-profiles] | kiri setup --uninstall"),
                "macOS help missing `kiri setup` flags:\n{help}"
            );
            assert!(help.contains("kiri update [--check]"), "macOS help missing `kiri update [--check]`:\n{help}");
            assert!(!cmds.contains(&"bridge"), "macOS help must not list Linux-only `bridge`:\n{help}");
        }
        #[cfg(target_os = "linux")]
        {
            assert!(cmds.contains(&"bridge"), "Linux help missing `bridge`:\n{help}");
            assert!(cmds.contains(&"update"), "Linux help missing `update`:\n{help}");
            assert!(help.contains("kiri update --check"), "Linux help missing `kiri update --check`:\n{help}");
            assert!(!help.contains("kiri update [--check]"), "Linux help must not list macOS `kiri update [--check]`:\n{help}");
            for mac_cmd in ["setup", "vm", "import", "bench", "boot"] {
                assert!(!cmds.contains(&mac_cmd), "Linux help must not list macOS-only `{mac_cmd}`:\n{help}");
            }
        }
        #[cfg(windows)]
        {
            for unix_or_mac in ["daemon", "bridge", "ui", "setup", "build-with", "update", "vm", "import", "bench", "boot", "raw"] {
                assert!(!cmds.contains(&unix_or_mac), "Windows help must not list `{unix_or_mac}`:\n{help}");
            }
        }
    }

    #[test]
    fn every_advertised_command_dispatches_in_main() {
        let help = usage();
        let mut count = 0;
        for line in help.lines() {
            let Some(rest) = line.strip_prefix("usage: ").unwrap_or(line).trim_start().strip_prefix("kiri ") else {
                continue;
            };
            let mut words = rest.split_whitespace();
            let subcmd = words.next().expect("subcommand after `kiri `");
            count += 1;
            match subcmd {
                "COMMAND" => {
                    let args = ["run".to_owned()];
                    assert!(matches!(Command::parse(&args), Some(Command::Docker(_))));
                }
                "PORT" => {
                    let args = ["3000".to_owned()];
                    assert!(matches!(Command::parse(&args), Some(Command::Share(_))));
                }
                "raw" => {
                    for part in rest.split('|') {
                        let mut p = part.split_whitespace();
                        if p.next() == Some("raw") {
                            let verb = p.next().expect("verb after `raw`");
                            let args = ["raw".to_owned(), verb.to_owned()];
                            let parsed = Command::parse(&args);
                            assert!(
                                parsed.is_some() && !matches!(parsed, Some(Command::Docker(_))),
                                "`kiri raw {verb}` advertised in usage has no dispatch arm in main"
                            );
                        }
                    }
                }
                other => {
                    let args = [other.to_owned()];
                    let parsed = Command::parse(&args);
                    assert!(
                        parsed.is_some() && !matches!(parsed, Some(Command::Docker(_))),
                        "`kiri {other}` advertised in usage has no dispatch arm in main"
                    );
                }
            }
        }
        assert!(count > 0);
        assert!(parse(&["--help"]).is_none());
        assert!(parse(&["-h"]).is_none());
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        for args in [
            vec!["update".to_owned()],
            vec!["update".to_owned(), "--check".to_owned()],
            vec!["update".to_owned(), "--help".to_owned()],
            vec!["update".to_owned(), "-h".to_owned()],
        ] {
            assert!(matches!(Command::parse(&args), Some(Command::Update(_))), "expected Command::Update for {args:?}");
        }
        let container_update = ["update".to_owned(), "--memory".to_owned(), "256m".to_owned(), "web".to_owned()];
        assert!(matches!(Command::parse(&container_update), Some(Command::Docker(_))));
        #[cfg(target_os = "macos")]
        assert!(parse(&["bridge"]).is_none());
        #[cfg(target_os = "linux")]
        for mac_cmd in ["setup", "vm", "import", "bench", "boot"] {
            assert!(parse(&[mac_cmd]).is_none(), "`kiri {mac_cmd}` should not dispatch on Linux");
        }
        #[cfg(windows)]
        {
            for unix_cmd in ["bridge", "ui", "setup", "build-with", "vm", "import", "bench", "boot", "raw"] {
                assert!(parse(&[unix_cmd]).is_none(), "`kiri {unix_cmd}` should not dispatch on Windows");
            }
            let daemon_args = ["daemon".to_owned()];
            assert_eq!(Command::parse(&daemon_args), Some(Command::Daemon));
        }
        assert_eq!(
            super::WINDOWS_DAEMON_ERROR,
            "on Windows, Kiri's engine runs in WSL without `kiri daemon`: run `kiri start` or open Kiri"
        );
    }
}
