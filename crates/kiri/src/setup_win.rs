//! `kiri setup` on Windows: ensures `%USERPROFILE%\.docker\config.json` has
//! Kiri's `cli-plugins` folder (`docker compose`, `docker buildx`), writes the
//! `kiri` Docker context (`npipe:////./pipe/kiri`), and sets `currentContext`
//! to `kiri` when `--use` is given or when `currentContext` is empty or points
//! at a removed engine such as `desktop-linux` after uninstalling Docker
//! Desktop (#984).

#![cfg_attr(not(windows), allow(dead_code))]

use std::io;
use std::path::{Path, PathBuf};

use crate::dockerctx::{
    WindowsRepair, WindowsRepairOpts, find_windows_cli_plugins, repair_windows_config,
};

const USAGE: &str = "usage: kiri setup [--use]";

fn npipe_host(pipe: &str) -> String {
    format!("npipe:{}", pipe.replace('\\', "/"))
}

/// Best-effort background self-heal of `%USERPROFILE%\.docker\config.json` and
/// Kiri's `kiri` Docker context before invoking `docker.exe --context kiri` on
/// Windows (#984).
#[cfg(windows)]
pub fn heal_quietly() {
    let Some(dir) = crate::dockerctx::docker_dir() else {
        return;
    };
    let exe = std::env::current_exe().ok();
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let plugins = find_windows_cli_plugins(exe.as_deref(), local.as_deref());
    let desktop = std::env::var_os("ProgramFiles").is_some_and(|p| {
        Path::new(&p)
            .join(r"Docker\Docker\Docker Desktop.exe")
            .is_file()
    });
    let host = npipe_host(&crate::client::pipe());
    let _ = repair_windows_config(
        &dir,
        WindowsRepairOpts {
            ours: crate::flavor::CONTEXT.get(),
            description: "Kiri (WSL2)",
            host: &host,
            plugins_dir: plugins.as_deref(),
            force_context_write: false,
            set_current_if_empty: false,
            force_use: false,
            desktop_installed: desktop,
        },
    );
}

pub fn run(args: &[String]) -> io::Result<()> {
    if args.iter().any(|a| matches!(a.as_str(), "-h" | "--help"))
        || matches!(args.first().map(String::as_str), Some("help"))
    {
        println!("{USAGE}");
        return Ok(());
    }
    let mut force_use = false;
    for a in args {
        match a.as_str() {
            "--use" => force_use = true,
            _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, USAGE)),
        }
    }
    let dir =
        crate::dockerctx::docker_dir().ok_or_else(|| io::Error::other("USERPROFILE is not set"))?;
    let exe = std::env::current_exe().ok();
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let plugins = find_windows_cli_plugins(exe.as_deref(), local.as_deref());
    let desktop = std::env::var_os("ProgramFiles").is_some_and(|p| {
        Path::new(&p)
            .join(r"Docker\Docker\Docker Desktop.exe")
            .is_file()
    });
    #[cfg(windows)]
    let host = npipe_host(&crate::client::pipe());
    #[cfg(not(windows))]
    let host = "npipe:////./pipe/kiri".to_owned();

    let mut out = Vec::new();
    run_in(
        &dir,
        &host,
        plugins.as_deref(),
        force_use,
        desktop,
        &mut out,
    )?;
    print!("{}", String::from_utf8_lossy(&out));

    #[cfg(windows)]
    if crate::client::alive() {
        match crate::builds::builder() {
            Ok(true) => match crate::buildwith::places().map(|p| p.saved()) {
                Ok(Some(crate::buildwith::With::Kiri)) => {
                    println!(
                        "docker build uses BuildKit in Kiri (builder `{}`)",
                        crate::builds::BUILDER
                    );
                }
                _ => println!(
                    "docker build follows docker's context, and builds on Kiri when docker uses Kiri (`kiri build-with kiri` sends every build to Kiri)"
                ),
            },
            Ok(false) => {}
            Err(e) => println!(
                "docker build: the `{}` builder comes later ({e})",
                crate::builds::BUILDER
            ),
        }
    }
    Ok(())
}

fn run_in(
    dir: &Path,
    host: &str,
    plugins: Option<&Path>,
    force_use: bool,
    desktop_installed: bool,
    out: &mut impl io::Write,
) -> io::Result<WindowsRepair> {
    let ours = crate::flavor::CONTEXT.get();
    let r = repair_windows_config(
        dir,
        WindowsRepairOpts {
            ours,
            description: "Kiri (WSL2)",
            host,
            plugins_dir: plugins,
            force_context_write: true,
            set_current_if_empty: true,
            force_use,
            desktop_installed,
        },
    )?;
    writeln!(out, "docker context `{ours}` → {host}")?;
    if r.current_context_set || force_use {
        writeln!(
            out,
            "docker now uses Kiri by default (`docker context use default` to switch back)"
        )?;
    }
    if let Some(p) = plugins {
        writeln!(out, "docker cli-plugins → {}", p.display())?;
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dockerctx::{context_meta, read_json, write_context, write_json};
    use serde_json::json;

    fn scratch(tag: &str) -> PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "kiri-setup-win-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn help_and_invalid_flags_have_no_side_effects() {
        for h in [&["--help"][..], &["-h"], &["help"], &["--use", "--help"]] {
            let v: Vec<String> = h.iter().map(|s| (*s).to_owned()).collect();
            run(&v).unwrap();
        }
        for bad in [&["--bogus"][..], &["--uninstall"], &["extra"]] {
            let v: Vec<String> = bad.iter().map(|s| (*s).to_owned()).collect();
            let err = run(&v).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(err.to_string(), USAGE);
        }
    }

    #[test]
    fn repairs_wiped_docker_config_and_dangling_desktop_linux_context() {
        let root = scratch("repair");
        let docker = root.join(".docker");
        let plugins = root.join("Kiri/bin/cli-plugins");
        std::fs::create_dir_all(&plugins).unwrap();

        // 1. Fresh / wiped config.json after Docker Desktop uninstall: creates `kiri` context,
        //    registers cliPluginsExtraDirs, and sets currentContext = "kiri".
        let mut out = Vec::new();
        let r = run_in(
            &docker,
            "npipe:////./pipe/kiri",
            Some(&plugins),
            false,
            false,
            &mut out,
        )
        .unwrap();
        assert_eq!(
            r,
            WindowsRepair {
                context_written: true,
                plugins_added: true,
                current_context_set: true
            }
        );
        let cfg = read_json(&docker.join("config.json")).unwrap();
        assert_eq!(cfg["currentContext"], "kiri");
        assert_eq!(
            cfg["cliPluginsExtraDirs"],
            json!([plugins.to_string_lossy()])
        );
        let meta = read_json(&context_meta(&docker, "kiri").join("meta.json")).unwrap();
        assert_eq!(meta["Endpoints"]["docker"]["Host"], "npipe:////./pipe/kiri");
        let printed = String::from_utf8(out).unwrap();
        assert!(
            printed.contains("docker context `kiri` → npipe:////./pipe/kiri"),
            "{printed}"
        );
        assert!(
            printed.contains("docker now uses Kiri by default"),
            "{printed}"
        );
        assert!(printed.contains("docker cli-plugins →"), "{printed}");

        // 2. Existing config with logins and an active `desktop-linux` context while Docker Desktop
        //    is still installed: keeps `desktop-linux` without `--use`, switches with `--use`.
        write_context(
            &context_meta(&docker, "desktop-linux"),
            "desktop-linux",
            "Docker Desktop",
            "npipe:////./pipe/dockerDesktopLinuxEngine",
        )
        .unwrap();
        write_json(
            &docker.join("config.json"),
            &json!({
                "auths": {"ghcr.io": {"auth": "dG9rZW4="}},
                "currentContext": "desktop-linux",
            }),
        )
        .unwrap();
        let mut out = Vec::new();
        let r = run_in(
            &docker,
            "npipe:////./pipe/kiri",
            Some(&plugins),
            false,
            true,
            &mut out,
        )
        .unwrap();
        assert!(!r.current_context_set);
        let cfg = read_json(&docker.join("config.json")).unwrap();
        assert_eq!(cfg["currentContext"], "desktop-linux");
        assert_eq!(cfg["auths"]["ghcr.io"]["auth"], "dG9rZW4=");
        assert_eq!(
            cfg["cliPluginsExtraDirs"],
            json!([plugins.to_string_lossy()])
        );

        // Docker Desktop uninstalled (`desktop_installed = false`), leaving stale `desktop-linux`:
        // `kiri setup` heals `currentContext` to `kiri` automatically!
        let mut out = Vec::new();
        let r = run_in(
            &docker,
            "npipe:////./pipe/kiri",
            Some(&plugins),
            false,
            false,
            &mut out,
        )
        .unwrap();
        assert!(r.current_context_set);
        assert_eq!(
            read_json(&docker.join("config.json")).unwrap()["currentContext"],
            "kiri"
        );

        // With Docker Desktop installed and `--use`: explicitly switches to `kiri`.
        write_json(
            &docker.join("config.json"),
            &json!({"currentContext": "desktop-linux"}),
        )
        .unwrap();
        let mut out = Vec::new();
        let r = run_in(
            &docker,
            "npipe:////./pipe/kiri",
            Some(&plugins),
            true,
            true,
            &mut out,
        )
        .unwrap();
        assert!(r.current_context_set);
        assert_eq!(
            read_json(&docker.join("config.json")).unwrap()["currentContext"],
            "kiri"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
