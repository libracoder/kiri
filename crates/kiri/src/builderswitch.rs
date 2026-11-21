//! `kiri builder`: which builder `kiri build` uses, Forge (Kiri's own build
//! engine, the kiri-forge library) or BuildKit.
//!
//! Forge is off unless switched on. Three ways, in this order (the first one
//! given wins):
//!
//! 1. `kiri build --builder forge|buildkit`: that build only;
//! 2. `KIRI_NATIVE_BUILD` (`0`, `false` or `off` for BuildKit, anything
//!    else for Forge), where `kiri build` runs or, failing that, for the
//!    engine;
//! 3. the setting, kept by the engine (`GET/POST /kiri/builder`
//!    `{"native": bool}`): `kiri builder use forge|buildkit`, or Settings →
//!    Builds in the window.
//!
//! `kiri`, Forge's name before it had one, is still taken wherever `forge`
//! is (`--builder kiri`, `kiri builder use kiri`).
//!
//! Either way a build Forge cannot do yet goes to BuildKit, and
//! plain `docker build` is not touched: `kiri build-with` picks its builder.
//!
//! `kiri builder` is also docker's command (`docker builder prune`, `ls`,
//! `use NAME`…): only the forms here are Kiri's, everything else goes to
//! docker as before.
//!
//! On Windows `kiri build` is `docker.exe build`, BuildKit's build as
//! always: Forge runs in the engine and reads the build folder from the
//! engine's side, which a build typed in Windows does not reach yet. So
//! there `kiri build --builder forge` and `kiri builder use forge` say
//! so in one line and do nothing, `--builder buildkit` is taken (it is what
//! runs), and `kiri builder` says BuildKit builds (`windows_build`,
//! `windows_builder`).

use std::io;

#[cfg(unix)]
use serde_json::{Value, json};

/// Which builder a `kiri build` uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Builder {
    /// Forge, Kiri's own build engine, in the engine.
    Forge,
    /// BuildKit, as `kiri build` always built.
    Buildkit,
}

impl Builder {
    pub fn parse(s: &str) -> Option<Builder> {
        match s {
            // `kiri`: Forge's name before it had one, still taken.
            "forge" | "kiri" => Some(Builder::Forge),
            "buildkit" => Some(Builder::Buildkit),
            _ => None,
        }
    }

    /// `KIRI_NATIVE_BUILD`'s value: `0`, `false` or `off` is BuildKit,
    /// anything else Forge; empty is not set.
    pub fn from_env(v: &str) -> Option<Builder> {
        match v.trim() {
            "" => None,
            "0" | "false" | "off" => Some(Builder::Buildkit),
            _ => Some(Builder::Forge),
        }
    }
}

/// A `kiri builder` that is Kiri's, not docker's.
#[derive(Debug, PartialEq, Eq)]
pub enum Cmd {
    Status,
    Use(Builder),
    Help,
    /// `kiri builder use` with nothing after it.
    Usage,
}

/// `kiri builder ARGS` (ARGS without `builder`): Kiri's form, or None for
/// docker's (`prune`, `ls`, `use NAME` for a buildx builder…).
pub fn parse(args: &[String]) -> Option<Cmd> {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        [] | ["status"] => Some(Cmd::Status),
        ["-h" | "--help" | "help"] | ["use", "-h" | "--help"] => Some(Cmd::Help),
        ["use"] => Some(Cmd::Usage),
        ["use", b] => Builder::parse(b).map(Cmd::Use),
        _ => None,
    }
}

// Windows has its own (windows_builder).
#[cfg_attr(windows, allow(dead_code))]
pub const HELP: &str = "\
Usage:  kiri builder [status]
        kiri builder use forge|buildkit

Which builder kiri build uses: Forge, Kiri's own build engine, or BuildKit.

Forge makes images in Kiri's engine and reads the folder in place. It is
off by default. When it is on, a build it can't do yet goes to BuildKit,
with a line saying why. BuildKit is always there.

Commands:
  status            Show which builder kiri build uses (the default)
  use forge         Build with Forge from now on (use kiri is the same)
  use buildkit      Build with BuildKit from now on, as before

For one build:   kiri build --builder forge|buildkit ...
For a terminal:  KIRI_NATIVE_BUILD=1 (Forge) or KIRI_NATIVE_BUILD=0 (BuildKit)
The first one given wins: --builder, then KIRI_NATIVE_BUILD, then this setting.

Plain docker build is not changed by this (kiri build-with picks its builder).
Every other kiri builder command is docker's: kiri builder prune, kiri builder ls,
kiri builder use NAME (a buildx builder).
";

/// Why Forge is not there on Windows, in one line.
#[cfg_attr(not(windows), allow(dead_code))]
pub const NOT_ON_WINDOWS: &str = "Forge, Kiri's own build engine, does not run from Windows yet: kiri build here builds with BuildKit";

/// `kiri build ARGS` on Windows (ARGS with `build` first): the docker
/// arguments to run, with `--builder buildkit` and `--no-native` taken out,
/// and a line to print first when `KIRI_NATIVE_BUILD` (`env`) asks for
/// Forge. Asked for by `--builder forge` (or `kiri`): the error line instead.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn windows_build(args: &[String], env: Option<&str>) -> Result<(Vec<String>, Option<String>), String> {
    let (mut chosen, mut out) = (None, Vec::with_capacity(args.len()));
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if a == "--no-native" {
            chosen = Some(Builder::Buildkit);
        } else if let Some(b) = a.strip_prefix("--builder=").and_then(Builder::parse) {
            chosen = Some(b);
        } else if a == "--builder"
            && let Some(b) = args.get(i).and_then(|v| Builder::parse(v))
        {
            chosen = Some(b);
            i += 1;
        } else {
            // Any other `--builder NAME` is a buildx builder's, docker's.
            out.push(a.clone());
        }
    }
    match chosen {
        Some(Builder::Forge) => Err(format!("{NOT_ON_WINDOWS} (leave out --builder)")),
        Some(Builder::Buildkit) => Ok((out, None)),
        None => {
            let note = (env.and_then(Builder::from_env) == Some(Builder::Forge)).then(|| format!("kiri: KIRI_NATIVE_BUILD is set, but {NOT_ON_WINDOWS}"));
            Ok((out, note))
        }
    }
}

/// `kiri builder`'s own forms on Windows: what to print, or the error line.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn windows_builder(cmd: &Cmd) -> Result<String, String> {
    const USES: &str = "kiri build uses BuildKit. Forge, Kiri's own build engine, does not run from Windows yet.";
    match cmd {
        Cmd::Status | Cmd::Use(Builder::Buildkit) => Ok(USES.to_owned()),
        Cmd::Use(Builder::Forge) => Err(NOT_ON_WINDOWS.to_owned()),
        Cmd::Usage => Err("usage: kiri builder use forge|buildkit".to_owned()),
        Cmd::Help => Ok(format!(
            "Usage:  kiri builder [status]\n\n{USES}\n\nEvery other kiri builder command is docker's: kiri builder prune, kiri builder ls,\nkiri builder use NAME (a buildx builder)."
        )),
    }
}

/// `kiri builder ARGS` on Windows: Kiri's forms here, docker's to docker.exe.
#[cfg(windows)]
pub fn run_windows(args: &[String]) -> io::Result<()> {
    let Some(cmd) = parse(args) else {
        let all: Vec<String> = std::iter::once("builder".to_owned()).chain(args.iter().cloned()).collect();
        return crate::docker::run(&all);
    };
    println!("{}", windows_builder(&cmd).map_err(io::Error::other)?);
    Ok(())
}

/// `kiri build ARGS` on Windows (ARGS with `build` first): docker.exe's build.
#[cfg(windows)]
pub fn build_windows(args: &[String]) -> io::Result<()> {
    let (docker, note) = windows_build(args, std::env::var("KIRI_NATIVE_BUILD").ok().as_deref()).map_err(io::Error::other)?;
    if let Some(n) = note {
        eprintln!("{n}");
    }
    crate::docker::run(&docker)
}

/// `kiri builder ARGS`.
#[cfg(unix)]
pub fn run(args: &[String]) -> io::Result<()> {
    let Some(cmd) = parse(args) else {
        let all: Vec<String> = std::iter::once("builder".to_owned()).chain(args.iter().cloned()).collect();
        return crate::docker::run(&all);
    };
    match cmd {
        Cmd::Help => {
            print!("{HELP}");
            return Ok(());
        }
        Cmd::Usage => return Err(io::Error::other("usage: kiri builder use forge|buildkit")),
        _ => {}
    }
    if !crate::client::alive() {
        return Err(io::Error::other("Kiri isn't running. Open Kiri, or start it with `kiri daemon`"));
    }
    let env = std::env::var("KIRI_NATIVE_BUILD").ok();
    let report = match cmd {
        Cmd::Use(b) => {
            let r = crate::client::request("POST", "/kiri/builder", Some(&json!({"native": b == Builder::Forge})))?;
            if !r.ok() {
                return Err(io::Error::other(format!("could not change the builder: {}", r.error())));
            }
            println!("{}", set_line(b));
            r.json()
        }
        _ => crate::client::get("/kiri/builder")?,
    };
    for l in status_lines(&report, env.as_deref(), matches!(cmd, Cmd::Status)) {
        println!("{l}");
    }
    Ok(())
}

/// What `kiri builder use` says it set.
#[cfg(unix)]
fn set_line(b: Builder) -> &'static str {
    match b {
        Builder::Forge => "Set: kiri build uses Forge, Kiri's own build engine, from now on. A build it can't do yet goes to BuildKit.",
        Builder::Buildkit => "Set: kiri build uses BuildKit from now on, as before Forge.",
    }
}

/// `kiri builder`'s lines, from `GET /kiri/builder` and the
/// `KIRI_NATIVE_BUILD` of this terminal. `full` adds the first line (which
/// builder) and BuildKit's facts; after `use`, only what overrides it.
#[cfg(unix)]
fn status_lines(report: &Value, here: Option<&str>, full: bool) -> Vec<String> {
    let setting = if report["native"].as_bool().unwrap_or(false) { Builder::Forge } else { Builder::Buildkit };
    let engine = report["native_env"].as_str();
    let (used, by) = match (here.and_then(Builder::from_env), engine.and_then(Builder::from_env)) {
        (Some(b), _) => (b, Some(format!("KIRI_NATIVE_BUILD={} is set in this terminal", here.unwrap_or_default().trim()))),
        (None, Some(b)) => (b, Some(format!("KIRI_NATIVE_BUILD={} is set for the engine", engine.unwrap_or_default().trim()))),
        (None, None) => (setting, None),
    };
    let mut out = Vec::new();
    if full {
        out.push(match used {
            Builder::Forge => "kiri build uses Forge, Kiri's own build engine. A build it can't do yet goes to BuildKit. Back to BuildKit: kiri builder use buildkit".to_owned(),
            Builder::Buildkit => "kiri build uses BuildKit. Forge, Kiri's own build engine, is off; to turn it on: kiri builder use forge".to_owned(),
        });
    }
    if let Some(by) = by.filter(|_| used != setting) {
        let s = match setting {
            Builder::Forge => "Forge",
            Builder::Buildkit => "BuildKit",
        };
        out.push(format!("{by}, and it wins over the setting ({s})."));
    }
    if full {
        let state = match report["state"].as_str().unwrap_or("none") {
            "none" => "not made yet (made on the first BuildKit build)",
            "running" => "running",
            "paused" => "resting (idle)",
            _ => "stopped",
        };
        let mut facts = format!("BuildKit: {state}");
        if let Some(limit) = report["cache_limit"].as_u64().filter(|l| *l > 0) {
            facts.push_str(&format!(", build cache up to {} GB", limit >> 30));
        }
        match report["idle_secs"].as_u64() {
            Some(0) => facts.push_str(", never stops when idle"),
            Some(s) if s % 3600 == 0 => facts.push_str(&format!(", stops after {} h idle", s / 3600)),
            Some(s) if s % 60 == 0 => facts.push_str(&format!(", stops after {} min idle", s / 60)),
            Some(s) => facts.push_str(&format!(", stops after {s} s idle")),
            None => {}
        }
        out.push(facts);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(a: &[&str]) -> Option<Cmd> {
        parse(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn kiris_forms_and_dockers() {
        assert_eq!(p(&[]), Some(Cmd::Status));
        assert_eq!(p(&["status"]), Some(Cmd::Status));
        assert_eq!(p(&["use", "forge"]), Some(Cmd::Use(Builder::Forge)));
        assert_eq!(p(&["use", "kiri"]), Some(Cmd::Use(Builder::Forge)), "Forge's name before it had one");
        assert_eq!(p(&["use", "buildkit"]), Some(Cmd::Use(Builder::Buildkit)));
        assert_eq!(p(&["--help"]), Some(Cmd::Help));
        assert_eq!(p(&["-h"]), Some(Cmd::Help));
        assert_eq!(p(&["use", "--help"]), Some(Cmd::Help));
        assert_eq!(p(&["use"]), Some(Cmd::Usage));
        // docker's own `docker builder ...`, unchanged
        assert_eq!(p(&["prune", "-af"]), None);
        assert_eq!(p(&["ls"]), None);
        assert_eq!(p(&["use", "kiri-build"]), None, "a buildx builder's name");
        assert_eq!(p(&["use", "kiri", "--global"]), None);
        assert_eq!(p(&["build", "."]), None);
    }

    #[test]
    fn the_environment_value() {
        for off in ["0", "false", "off", " off "] {
            assert_eq!(Builder::from_env(off), Some(Builder::Buildkit), "{off}");
        }
        for on in ["1", "true", "on", "yes"] {
            assert_eq!(Builder::from_env(on), Some(Builder::Forge), "{on}");
        }
        assert_eq!(Builder::from_env(""), None);
    }

    #[test]
    fn help_names_both_builders_and_the_order() {
        assert!(HELP.starts_with("Usage:  kiri builder"));
        for w in ["use forge", "use buildkit", "--builder forge|buildkit", "Forge, Kiri's own build engine", "KIRI_NATIVE_BUILD", "off by default", "docker build is not changed"] {
            assert!(HELP.contains(w), "{w}");
        }
    }

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn windows_build_is_buildkits_and_says_so_when_kiris_is_asked_for() {
        // As before: docker.exe build with the same arguments.
        assert_eq!(windows_build(&v(&["build", "-t", "x", "."]), None), Ok((v(&["build", "-t", "x", "."]), None)));
        // BuildKit asked for: that is what runs; the flag is Kiri's, not docker's.
        for a in [&["build", "--builder", "buildkit", "."][..], &["build", "--builder=buildkit", "."], &["build", "--no-native", "."]] {
            assert_eq!(windows_build(&v(a), Some("1")), Ok((v(&["build", "."]), None)), "{a:?}");
        }
        // A buildx builder's name stays docker's.
        assert_eq!(windows_build(&v(&["build", "--builder", "mine", "."]), None), Ok((v(&["build", "--builder", "mine", "."]), None)));
        // Forge (or `kiri`, its name before): one line, nothing run.
        for a in [&["build", "--builder", "forge", "."][..], &["build", "--builder=forge", "."], &["build", "--builder", "kiri", "."], &["build", "--builder=kiri", "."]] {
            let e = windows_build(&v(a), None).unwrap_err();
            assert!(e.starts_with("Forge, Kiri's own build engine, does not run from Windows yet") && !e.contains('\n'), "{e}");
        }
        // KIRI_NATIVE_BUILD on: BuildKit builds, with a line saying why.
        let (args, note) = windows_build(&v(&["build", "."]), Some("1")).unwrap();
        assert_eq!(args, v(&["build", "."]));
        assert!(note.is_some_and(|n| n.contains("KIRI_NATIVE_BUILD") && n.contains("BuildKit")));
        assert_eq!(windows_build(&v(&["build", "."]), Some("0")), Ok((v(&["build", "."]), None)));
    }

    #[test]
    fn windows_builder_says_buildkit_builds() {
        assert!(windows_builder(&Cmd::Status).unwrap().starts_with("kiri build uses BuildKit."));
        assert_eq!(windows_builder(&Cmd::Use(Builder::Buildkit)), windows_builder(&Cmd::Status));
        assert_eq!(windows_builder(&Cmd::Use(Builder::Forge)), Err(NOT_ON_WINDOWS.to_owned()));
        assert!(windows_builder(&Cmd::Help).unwrap().contains("kiri builder prune"));
        assert!(windows_builder(&Cmd::Usage).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn status_says_which_builder_and_what_overrides_it() {
        let off = json!({"native": false, "state": "none", "cache_limit": 20u64 << 30, "idle_secs": 300});
        let l = status_lines(&off, None, true);
        assert!(l[0].starts_with("kiri build uses BuildKit."), "{l:?}");
        assert_eq!(l[1], "BuildKit: not made yet (made on the first BuildKit build), build cache up to 20 GB, stops after 5 min idle");
        let on = json!({"native": true, "state": "running", "idle_secs": 0});
        let l = status_lines(&on, None, true);
        assert!(l[0].starts_with("kiri build uses Forge, Kiri's own build engine."), "{l:?}");
        assert_eq!(l[1], "BuildKit: running, never stops when idle");
        assert_eq!(status_lines(&json!({"state": "exited", "idle_secs": 86400}), None, true)[1], "BuildKit: stopped, stops after 24 h idle");
        // This terminal's KIRI_NATIVE_BUILD wins over the engine's, which wins over the setting.
        let l = status_lines(&json!({"native": false, "native_env": "0"}), Some("1"), true);
        assert!(l[0].contains("Forge"), "{l:?}");
        assert_eq!(l[1], "KIRI_NATIVE_BUILD=1 is set in this terminal, and it wins over the setting (BuildKit).");
        let l = status_lines(&json!({"native": true, "native_env": "off"}), None, true);
        assert!(l[0].starts_with("kiri build uses BuildKit."), "{l:?}");
        assert_eq!(l[1], "KIRI_NATIVE_BUILD=off is set for the engine, and it wins over the setting (Forge).");
        // An override that agrees with the setting is not news; after `use` only an override shows.
        assert_eq!(status_lines(&json!({"native": true}), Some("1"), false), Vec::<String>::new());
        assert_eq!(status_lines(&json!({"native": true}), Some("0"), false).len(), 1);
    }
}
