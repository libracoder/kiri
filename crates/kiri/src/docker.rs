//! `kiri ps`, `kiri run`, `kiri compose up`…: Docker's own commands, run
//! by the docker CLI against Kiri's daemon, whatever docker context is
//! selected. `kiri run -d --name web nginx` is `docker --context kiri run
//! -d --name web nginx`.

use std::io;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[cfg(unix)]
use crate::client;

/// The docker commands `kiri` answers. `import` is left out: `kiri import`
/// brings things over from OrbStack and Docker Desktop.
pub const COMMANDS: &[&str] = &[
    "attach", "build", "builder", "buildx", "commit", "compose", "container", "cp", "create", "diff", "events", "exec", "export", "history", "image", "images",
    "info", "inspect", "kill", "load", "login", "logout", "logs", "manifest", "network", "pause", "port", "ps", "pull", "push", "rename", "restart", "rm", "rmi",
    "run", "save", "search", "start", "stats", "stop", "system", "tag", "top", "unpause", "update", "version", "volume", "wait",
];

/// `kiri update` is two commands. Alone or with `--check` it updates Kiri;
/// with anything else it is Docker's `update`, which always names a
/// container (`kiri update --memory 256m web`).
#[cfg(any(target_os = "macos", test))]
pub fn is_container_update(args: &[String]) -> bool {
    args.iter().any(|a| !matches!(a.as_str(), "--check" | "-h" | "--help"))
}

pub fn handles(command: &str) -> bool {
    COMMANDS.contains(&command)
}

/// Replaces this process with `docker <args>`, so the terminal, signals and
/// the exit code are docker's own. Returns only if that fails.
#[cfg(unix)]
pub fn run(args: &[String]) -> io::Result<()> {
    Err(command(args)?.exec())
}

/// `docker <args>` against Kiri's daemon, as [`run`] runs it.
#[cfg(unix)]
pub fn command(args: &[String]) -> io::Result<std::process::Command> {
    let docker = client::docker_cli().ok_or_else(|| io::Error::other("no docker CLI found; open Kiri once to set it up"))?;
    let socket = client::socket()?;
    if !client::alive() {
        return Err(io::Error::other("Kiri isn't running. Open Kiri, or start it with `kiri daemon`"));
    }
    let mut cmd = std::process::Command::new(docker);
    cmd.args(args).env("DOCKER_HOST", format!("unix://{}", socket.display())).env_remove("DOCKER_CONTEXT");
    // With DOCKER_HOST and no context, buildx would pick the endpoint's own
    // docker-driver builder, which needs BuildKit inside the engine: name
    // Kiri's, if buildx knows it (the window sets it up) and the person
    // hasn't picked one.
    if std::env::var_os("BUILDX_BUILDER").is_none() && buildx_knows(crate::builds::BUILDER.get()) {
        cmd.env("BUILDX_BUILDER", crate::builds::BUILDER.get());
    }
    Ok(cmd)
}

/// On Windows: Kiri's docker.exe, beside this kiri.exe in
/// %LOCALAPPDATA%\Kiri\bin (else one on PATH), with the `kiri` context
/// setup made, which reaches the engine in WSL through kiri-win's pipe.
/// Exits with docker's exit code.
#[cfg(windows)]
pub fn run(args: &[String]) -> io::Result<()> {
    let beside = std::env::current_exe().ok().and_then(|e| Some(e.parent()?.join("docker.exe"))).filter(|d| d.is_file());
    let status = std::process::Command::new(beside.unwrap_or_else(|| "docker.exe".into()))
        .args(["--context", crate::flavor::CONTEXT.get()])
        .args(args)
        .env_remove("DOCKER_HOST")
        .env_remove("DOCKER_CONTEXT")
        .status()
        .map_err(|e| io::Error::other(format!("could not run docker.exe ({e}); open Kiri once to set it up")))?;
    std::process::exit(status.code().unwrap_or(1))
}

/// What `kiri build`'s fallback lacks to reach BuildKit, as one line, or
/// None. `needs` is what in the build only buildx takes (a BuildKit option,
/// a Git context). Without the buildx plugin docker build is the legacy
/// builder: the engine's classic API serves it in the same BuildKit, but
/// the CLI stops at BuildKit's options ("unknown flag") and clones a Git
/// context here, by its own rules and through this machine's names. With
/// the plugin but without Kiri's builder, buildx picks the engine's own
/// docker-driver builder, which Kiri does not serve: every build fails.
#[cfg(unix)]
pub fn buildkit_missing(needs: Option<&str>) -> Option<String> {
    let docker = client::docker_cli()?;
    let builder = std::env::var_os("BUILDX_BUILDER").is_some() || buildx_knows(crate::builds::BUILDER.get());
    buildkit_gap(&docker, has_buildx(&docker), builder, needs)
}

/// The docker CLI builds with buildx: the plugin answers, and
/// DOCKER_BUILDKIT does not ask for the legacy builder.
#[cfg(unix)]
fn has_buildx(docker: &std::path::Path) -> bool {
    if std::env::var("DOCKER_BUILDKIT").is_ok_and(|v| v == "0" || v.eq_ignore_ascii_case("false")) {
        return false;
    }
    let quiet = std::process::Stdio::null;
    std::process::Command::new(docker).args(["buildx", "version"]).stdin(quiet()).stdout(quiet()).stderr(quiet()).status().is_ok_and(|s| s.success())
}

#[cfg(unix)]
fn buildkit_gap(docker: &std::path::Path, buildx: bool, builder: bool, needs: Option<&str>) -> Option<String> {
    let (b, c) = (crate::builds::BUILDER.get(), crate::flavor::CONTEXT.get());
    if buildx && !builder {
        return Some(format!(
            "buildx has no builder `{b}` (`kiri setup` makes it; by hand: docker context create {c} --docker host=unix://<Kiri's socket>, then docker buildx create --name {b} --driver docker-container --driver-opt default-load=true {c})"
        ));
    }
    match needs {
        Some(what) if !buildx => Some(format!(
            "{what} needs docker's buildx plugin, and {} has none (`docker buildx version` fails); put docker-buildx in ~/.docker/cli-plugins ({} has it in Contents/Resources/bin/cli-plugins)",
            docker.display(),
            crate::flavor::APP
        )),
        _ => None,
    }
}

/// buildx has a builder of this name: its instance file, in BUILDX_CONFIG,
/// else DOCKER_CONFIG/buildx, else ~/.docker/buildx.
#[cfg(unix)]
fn buildx_knows(name: &str) -> bool {
    let dir = std::env::var_os("BUILDX_CONFIG")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("DOCKER_CONFIG").map(|d| std::path::PathBuf::from(d).join("buildx")))
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".docker/buildx")));
    dir.is_some_and(|d| d.join("instances").join(name).is_file())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn fake_docker(name: &str, script: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kiri-fake-docker-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("docker");
        std::fs::write(&p, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn buildx_is_found_by_asking_the_cli() {
        assert!(!has_buildx(&fake_docker("none", "exit 1")));
        assert!(has_buildx(&fake_docker("buildx", "[ \"$1 $2\" = \"buildx version\" ] && exit 0; exit 1")));
    }

    #[test]
    fn what_the_fallback_lacks_is_named_in_one_line() {
        let docker = Path::new("/opt/x/docker");
        assert_eq!(buildkit_gap(docker, true, true, Some("--ssh")), None);
        assert_eq!(buildkit_gap(docker, false, false, None), None, "the classic API serves a build that needs nothing of buildx");
        let no_plugin = buildkit_gap(docker, false, false, Some("--ssh")).unwrap();
        assert!(no_plugin.contains("/opt/x/docker") && no_plugin.contains("buildx plugin") && no_plugin.contains("--ssh"), "{no_plugin}");
        let no_builder = buildkit_gap(docker, true, false, None).unwrap();
        let b = crate::builds::BUILDER.get();
        assert!(no_builder.contains(&format!("docker buildx create --name {b} --driver docker-container --driver-opt default-load=true")), "{no_builder}");
        for line in [no_plugin, no_builder] {
            assert!(!line.contains('\n'), "{line}");
        }
    }
}

#[cfg(test)]
mod update_tests {
    use super::is_container_update;

    #[test]
    fn update_alone_is_kiris_and_with_a_container_is_dockers() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(!is_container_update(&a(&[])));
        assert!(!is_container_update(&a(&["--check"])));
        assert!(!is_container_update(&a(&["--help"])));
        assert!(is_container_update(&a(&["--memory", "256m", "web"])));
        assert!(is_container_update(&a(&["web"])));
        assert!(is_container_update(&a(&["--restart", "always", "web"])));
    }
}
