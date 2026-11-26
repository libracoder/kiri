//! `kiri machine`: long-lived Linux machines, as OrbStack has. A machine is
//! a container that keeps running, from a distro image, with the host user's
//! name and uid inside (and passwordless sudo), and the homes folder
//! (`/Users` on a Mac, `/home` on Linux) at the same path as on the host.
//! `kiri machine shell` opens a login shell in it. On Windows the commands
//! run as root in Kiri's WSL distro (crates/kiri/src/wsl.rs), so the
//! machine's user is root there.

use std::io;
use std::process::Command;

use serde_json::json;

use crate::client;

pub(crate) const LABEL: &str = "dev.kiri.machine";

/// `kiri machine create NAME --distro ubuntu` picks one of these.
const DISTROS: [(&str, &str); 7] = [
    ("ubuntu", "ubuntu:24.04"),
    ("debian", "debian:trixie"),
    ("alpine", "alpine:3.22"),
    ("fedora", "fedora:42"),
    ("arch", "archlinux:latest"),
    ("rocky", "rockylinux:9"),
    ("opensuse", "opensuse/tumbleweed:latest"),
];

fn container(name: &str) -> String {
    format!("machine-{name}")
}

fn ok(r: io::Result<client::Response>) -> io::Result<client::Response> {
    let r = r?;
    if r.ok() { Ok(r) } else { Err(io::Error::other(r.error())) }
}

pub(crate) const USAGE: &str = "usage: kiri machine create NAME [--distro ubuntu|debian|alpine|fedora|arch|rocky|opensuse | --image IMAGE] [--systemd]\n       kiri machine list [--json] | shell NAME [-- CMD...] | start | stop | restart | delete NAME";

/// True when `args` asks for `kiri machine`'s own help rather than passing
/// `--help` to a command inside `kiri machine shell NAME -- <cmd> --help`.
pub(crate) fn wants_help(args: &[String]) -> bool {
    if matches!(args.first().map(String::as_str), Some("help")) {
        return true;
    }
    let scan_end = if args.first().map(String::as_str) == Some("shell") {
        args.iter().position(|a| a == "--").unwrap_or(args.len())
    } else {
        args.len()
    };
    args[..scan_end].iter().any(|a| matches!(a.as_str(), "-h" | "--help"))
}

pub fn run(args: &[String]) -> io::Result<()> {
    if wants_help(args) {
        println!("{USAGE}");
        return Ok(());
    }
    if args.is_empty() {
        return Err(io::Error::other(USAGE));
    }
    if !client::alive() {
        return Err(io::Error::other("kiri daemon is not running: open Kiri.app or run `kiri daemon`"));
    }
    let name = args.get(1).map(String::as_str).unwrap_or_default();
    let need_name = || if name.is_empty() || name.starts_with('-') { Err(io::Error::other("name a machine")) } else { Ok(()) };
    match args.first().map(String::as_str) {
        Some("create") => {
            need_name()?;
            let pick = args.iter().position(|a| a == "--distro" || a == "--image").and_then(|i| args.get(i + 1)).map_or("ubuntu", String::as_str);
            create(name, pick, args.iter().any(|a| a == "--systemd"))
        }
        Some("list" | "ls") => list(args.iter().any(|a| a == "--json")),
        Some("shell") => {
            need_name()?;
            let cmd: Vec<&str> = args.iter().position(|a| a == "--").map(|i| args[i + 1..].iter().map(String::as_str).collect()).unwrap_or_default();
            shell(name, &cmd)
        }
        Some(verb @ ("start" | "stop" | "restart")) => {
            need_name()?;
            // Already running, or already stopped: Docker's 304, with no
            // body, is done (it printed an empty `kiri: ` and failed).
            let r = client::request("POST", &format!("/containers/{}/{verb}", container(name)), None)?;
            if !r.ok() && r.status != 304 {
                return Err(io::Error::other(r.error()));
            }
            Ok(())
        }
        Some("delete" | "rm") => {
            need_name()?;
            ok(client::request("DELETE", &format!("/containers/{}?force=1&v=1", container(name)), None))?;
            println!("deleted machine {name}");
            Ok(())
        }
        _ => Err(io::Error::other(USAGE)),
    }
}

/// The host's homes folder, mounted at the same path in every machine.
const HOMES: &str = if cfg!(target_os = "macos") { "/Users" } else { "/home" };

/// The host user's name, uid and gid. root is always `root`: under
/// `wsl -u root` (Windows) USER is not set, and a made-up name with uid 0
/// was a user no machine had ("unknown user user").
fn user() -> (String, u32, u32) {
    // SAFETY: getuid/getgid cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let name = if uid == 0 { "root".to_owned() } else { std::env::var("USER").ok().filter(|u| !u.is_empty()).unwrap_or_else(|| "user".to_owned()) };
    (name, uid, gid)
}

/// The user's home in the machine: under HOMES, as on the host; root's is /root.
fn home(user: &str) -> String {
    if user == "root" { "/root".to_owned() } else { format!("{HOMES}/{user}") }
}

/// A parsed image reference for `kiri machine create`: the full reference
/// passed to `/images/{ref}/json` and `POST /containers/create`, plus the
/// `fromImage` and `tag` query values for `POST /images/create` when pulling.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MachineImage {
    full: String,
    from_image: String,
    tag: String,
}

impl MachineImage {
    fn inspect_path(&self) -> String {
        format!("/images/{}/json", percent_encode_image_ref(&self.full))
    }

    fn pull_path(&self) -> String {
        format!("/images/create?fromImage={}&tag={}", urlish(&self.from_image), urlish(&self.tag))
    }
}

fn percent_encode_image_ref(reference: &str) -> String {
    urlish(reference)
}

fn parse_machine_image(pick: &str) -> MachineImage {
    let image = DISTROS.iter().find(|(d, _)| *d == pick).map_or(pick, |(_, i)| *i);
    if let Some((repo, digest)) = image.split_once('@').filter(|(_, d)| d.starts_with("sha256:")) {
        // Strip an optional `:tag` label before `@sha256:...` for `fromImage`,
        // keeping any registry `:port` before the last `/`.
        let from_image = match repo.rsplit_once(':') {
            Some((r, t)) if !t.contains('/') && !t.is_empty() => r,
            _ => repo,
        };
        return MachineImage {
            full: image.to_owned(),
            from_image: from_image.to_owned(),
            tag: digest.to_owned(),
        };
    }
    let (repo, tag) = match image.rsplit_once(':') {
        Some((r, t)) if !t.contains('/') && !t.is_empty() => (r, t),
        _ => (image, "latest"),
    };
    MachineImage {
        full: format!("{repo}:{tag}"),
        from_image: repo.to_owned(),
        tag: tag.to_owned(),
    }
}

/// Ensures `image` is present in the daemon's image store, matching
/// `docker run --pull=missing`: probes `GET /images/{ref}/json` first and only
/// pulls via `POST /images/create` on `404`. Returns `Ok(true)` if it pulled,
/// or `Ok(false)` if the image was already local.
fn ensure_machine_image_with<F, P>(image: &MachineImage, mut req: F, mut on_pull: P) -> io::Result<bool>
where
    F: FnMut(&str, &str, Option<&serde_json::Value>) -> io::Result<client::Response>,
    P: FnMut(&str),
{
    let probe = req("GET", &image.inspect_path(), None)?;
    if probe.status == 200 {
        return Ok(false);
    }
    if probe.status != 404 {
        return Err(io::Error::other(probe.error()));
    }
    on_pull(&image.full);
    let pulled = ok(req("POST", &image.pull_path(), None))?;
    if let Some(e) = String::from_utf8_lossy(&pulled.body)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find_map(|v| v["error"].as_str().map(str::to_owned))
    {
        return Err(io::Error::other(e));
    }
    Ok(true)
}

fn create_body_for(name: &str, image: &str, user: &str, uid: u32, gid: u32, systemd: bool) -> serde_json::Value {
    let home = home(user);
    // The host user, made once; every distro has one of these tools. An
    // image user that already has the uid (Ubuntu's `ubuntu` is 1000, the
    // first user's uid on most Linux hosts) is renamed to the host user.
    let init = format!(
        r#"set -e
if ! id -u {user} >/dev/null 2>&1; then
  getent group {gid} >/dev/null 2>&1 || groupadd -g {gid} {user} 2>/dev/null || addgroup -g {gid} {user} 2>/dev/null || true
  g=$(getent group {gid} | cut -d: -f1)
  old=$(getent passwd {uid} | cut -d: -f1)
  {{ [ -n "$old" ] && usermod -l {user} -d {home} "$old" 2>/dev/null; }} || useradd -o -M -u {uid} -g "${{g:-{gid}}}" -d {home} -s /bin/sh {user} 2>/dev/null || adduser -D -H -u {uid} -G "${{g:-{user}}}" -h {home} {user} 2>/dev/null || true
fi
mkdir -p /etc/sudoers.d && echo '{user} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/kiri && chmod 440 /etc/sudoers.d/kiri
# Slim images have no sudo: fetch it once, in the background.
command -v sudo >/dev/null 2>&1 || (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo || apk add -q sudo || dnf -y -q install sudo || pacman -Sy --noconfirm sudo || zypper -n -q in sudo) >/dev/null 2>&1 &
{tail}"#,
        tail = if systemd {
            // A full init: systemd as PID 1 (installed first if the image lacks it).
            "wait\nfor i in /lib/systemd/systemd /usr/lib/systemd/systemd; do [ -x $i ] && exec $i; done\n(apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv dbus || dnf -y -q install systemd || pacman -Sy --noconfirm systemd || zypper -n -q in systemd) >/dev/null 2>&1\nfor i in /lib/systemd/systemd /usr/lib/systemd/systemd; do [ -x $i ] && exec $i; done\necho 'no systemd for this distro' >&2; exit 1"
        } else {
            "trap 'exit 0' TERM INT\nwhile :; do sleep 3600 & wait $!; done"
        }
    );
    let mut body = json!({
        "Image": image,
        "Cmd": ["/bin/sh", "-c", init],
        "Hostname": name,
        "Labels": {LABEL: name},
        "HostConfig": {
            "Binds": [format!("{HOMES}:{HOMES}")],
            "RestartPolicy": {"Name": "unless-stopped"},
            "CapAdd": ["NET_ADMIN", "SYS_PTRACE"],
        },
    });
    if systemd {
        // systemd needs its own cgroup tree, tmpfs /run and /tmp (with exec so
        // scripts and helpers in /tmp and /run can run instead of inheriting
        // Docker's default noexec tmpfs flag), and stops on SIGRTMIN+3.
        body["StopSignal"] = "SIGRTMIN+3".into();
        body["Env"] = json!(["container=docker"]);
        body["HostConfig"]["Privileged"] = true.into();
        body["HostConfig"]["Tmpfs"] = json!({"/run": "exec", "/run/lock": "", "/tmp": "exec"});
    }
    body
}

fn create_with<Req, Exec, OnPull>(
    name: &str,
    pick: &str,
    systemd: bool,
    (user, uid, gid): (&str, u32, u32),
    mut req: Req,
    mut exec: Exec,
    on_pull: OnPull,
) -> io::Result<String>
where
    Req: FnMut(&str, &str, Option<&serde_json::Value>) -> io::Result<client::Response>,
    Exec: FnMut(&str, &[&str]) -> io::Result<(i64, String)>,
    OnPull: FnMut(&str),
{
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') || name.starts_with('-') {
        return Err(io::Error::other("a machine name is letters, digits and dashes"));
    }
    let image = parse_machine_image(pick);
    ensure_machine_image_with(&image, &mut req, on_pull)?;
    let body = create_body_for(name, &image.full, user, uid, gid, systemd);
    ok(req("POST", &format!("/containers/create?name={}", container(name)), Some(&body)))?;
    ok(req("POST", &format!("/containers/{}/start", container(name)), None))?;
    // The user is made by the machine's own first command: wait for it, or
    // a `machine shell` straight after was "unknown user" (seen on Fedora).
    let wait = format!("for i in $(seq 300); do id -u {user} >/dev/null 2>&1 && exit 0; sleep 0.1; done; exit 1");
    if exec(&container(name), &["sh", "-c", &wait])?.0 != 0 {
        return Err(io::Error::other(format!("machine {name} is running, but the user {user} could not be added to it")));
    }
    Ok(image.full)
}

fn create(name: &str, pick: &str, systemd: bool) -> io::Result<()> {
    let (user, uid, gid) = user();
    let image = create_with(name, pick, systemd, (&user, uid, gid), client::request, client::exec, |img| println!("pulling {img}…"))?;
    println!("machine {name} ({image}) is running: kiri machine shell {name}");
    Ok(())
}

fn list(json: bool) -> io::Result<()> {
    let filters = format!("{{\"label\":[\"{LABEL}\"]}}");
    let rows = client::get(&format!("/containers/json?all=1&filters={}", urlish(&filters)))?;
    if json {
        println!("{}", list_json(&rows));
        return Ok(());
    }
    println!("{:<16} {:<28} {}", "NAME", "IMAGE", "STATE");
    for c in rows.as_array().into_iter().flatten() {
        println!("{:<16} {:<28} {}", c["Labels"][LABEL].as_str().unwrap_or("?"), c["Image"].as_str().unwrap_or(""), c["Status"].as_str().unwrap_or(""));
    }
    Ok(())
}

/// `kiri machine list --json`: each machine's name, image, state (Docker's
/// `running`, `exited`…) and status (`Up 2 hours`…).
fn list_json(rows: &serde_json::Value) -> serde_json::Value {
    rows.as_array()
        .into_iter()
        .flatten()
        .map(|c| json!({"name": c["Labels"][LABEL], "image": c["Image"], "state": c["State"], "status": c["Status"]}))
        .collect()
}

fn urlish(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// A login shell as the host user, in the same directory as on the host when
/// it is under HOMES, else in the user's home. The docker CLI handles the
/// terminal.
fn shell(name: &str, cmd: &[&str]) -> io::Result<()> {
    let docker = client::docker_cli().ok_or_else(|| io::Error::other("no docker CLI found (Kiri.app bundles one)"))?;
    let (user, _, _) = user();
    let home = home(&user);
    let cwd = std::env::current_dir().ok().filter(|d| d.starts_with(HOMES)).map_or_else(|| home.clone(), |d| d.display().to_string());
    let mut c = Command::new(docker);
    // The engine the other machine commands use (client::socket(), so
    // KIRI_SOCKET too), as `kiri exec` does, not a docker context: with
    // `--context kiri`, a second Kiri's machines (or any, once that context
    // was removed or pointed elsewhere) were "No such container".
    c.env("DOCKER_HOST", format!("unix://{}", client::socket()?.display())).env_remove("DOCKER_CONTEXT");
    // SAFETY: isatty has no preconditions.
    let tty = unsafe { libc::isatty(0) } == 1;
    c.args(["exec", if tty { "-it" } else { "-i" }, "-u", &user, "-w", &cwd, "-e", &format!("HOME={home}"), &container(name)]);
    if cmd.is_empty() {
        // bash when the distro has it, else its sh.
        c.args(["sh", "-c", "exec $(command -v bash || command -v sh) -l"]);
    } else {
        c.args(cmd);
    }
    let status = c.status()?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, body: &[u8]) -> client::Response {
        client::Response { status, body: body.to_vec() }
    }

    #[test]
    fn parse_machine_image_handles_distros_tags_ports_and_digests() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let cases = [
            ("ubuntu", "ubuntu:24.04", "ubuntu", "24.04", "/images/ubuntu%3A24.04/json", "/images/create?fromImage=ubuntu&tag=24.04"),
            (
                "opensuse",
                "opensuse/tumbleweed:latest",
                "opensuse/tumbleweed",
                "latest",
                "/images/opensuse%2Ftumbleweed%3Alatest/json",
                "/images/create?fromImage=opensuse%2Ftumbleweed&tag=latest",
            ),
            ("pmb-copy", "pmb-copy:latest", "pmb-copy", "latest", "/images/pmb-copy%3Alatest/json", "/images/create?fromImage=pmb-copy&tag=latest"),
            ("pmb-copy:latest", "pmb-copy:latest", "pmb-copy", "latest", "/images/pmb-copy%3Alatest/json", "/images/create?fromImage=pmb-copy&tag=latest"),
            (
                "ghcr.io/org/devbox:1",
                "ghcr.io/org/devbox:1",
                "ghcr.io/org/devbox",
                "1",
                "/images/ghcr.io%2Forg%2Fdevbox%3A1/json",
                "/images/create?fromImage=ghcr.io%2Forg%2Fdevbox&tag=1",
            ),
            (
                "localhost:5000/pmb:latest",
                "localhost:5000/pmb:latest",
                "localhost:5000/pmb",
                "latest",
                "/images/localhost%3A5000%2Fpmb%3Alatest/json",
                "/images/create?fromImage=localhost%3A5000%2Fpmb&tag=latest",
            ),
            (
                "localhost:5000/pmb",
                "localhost:5000/pmb:latest",
                "localhost:5000/pmb",
                "latest",
                "/images/localhost%3A5000%2Fpmb%3Alatest/json",
                "/images/create?fromImage=localhost%3A5000%2Fpmb&tag=latest",
            ),
        ];
        for (pick, full, from, tag, inspect, pull) in cases {
            let parsed = parse_machine_image(pick);
            assert_eq!(parsed.full, full, "{pick}");
            assert_eq!(parsed.from_image, from, "{pick}");
            assert_eq!(parsed.tag, tag, "{pick}");
            assert_eq!(parsed.inspect_path(), inspect, "{pick}");
            assert_eq!(parsed.pull_path(), pull, "{pick}");
            assert!(kiri_image::Reference::parse(&parsed.full).is_ok(), "{pick}");
        }

        // Digest references: bare repo@sha256:..., tag+digest, and registry:port@sha256:...
        let digest_cases = [
            (format!("org/box@{digest}"), "org/box"),
            (format!("ghcr.io/org/box:v1@{digest}"), "ghcr.io/org/box"),
            (format!("localhost:5000/org/box@{digest}"), "localhost:5000/org/box"),
        ];
        for (pick, expected_from) in digest_cases {
            let parsed = parse_machine_image(&pick);
            assert_eq!(parsed.full, pick);
            assert_eq!(parsed.from_image, expected_from);
            assert_eq!(parsed.tag, digest);
            assert_eq!(parsed.inspect_path(), format!("/images/{}/json", urlish(&pick)));
            assert_eq!(parsed.pull_path(), format!("/images/create?fromImage={}&tag={}", urlish(expected_from), urlish(&digest)));
            assert!(kiri_image::Reference::parse(&parsed.full).is_ok(), "{pick}");
            // Matches daemon/api.rs `pull()` reconstruction for `sha256:` tags.
            let daemon_pull_name = format!("{}@{}", parsed.from_image, parsed.tag);
            assert!(kiri_image::Reference::parse(&daemon_pull_name).is_ok(), "{daemon_pull_name}");
        }
    }

    #[test]
    fn local_image_skips_pull_and_creates_container_immediately() {
        let digest = format!("sha256:{}", "b".repeat(64));
        let digest_ref = format!("org/box@{digest}");
        let digest_inspect = format!("/images/{}/json", urlish(&digest_ref));
        for (pick, expected_image, expected_inspect) in [
            ("pmb-copy:latest", "pmb-copy:latest", "/images/pmb-copy%3Alatest/json"),
            ("pmb-copy", "pmb-copy:latest", "/images/pmb-copy%3Alatest/json"),
            ("ghcr.io/org/devbox:1", "ghcr.io/org/devbox:1", "/images/ghcr.io%2Forg%2Fdevbox%3A1/json"),
            ("localhost:5000/pmb:latest", "localhost:5000/pmb:latest", "/images/localhost%3A5000%2Fpmb%3Alatest/json"),
            (digest_ref.as_str(), digest_ref.as_str(), digest_inspect.as_str()),
        ] {
            let mut calls: Vec<(String, String, Option<serde_json::Value>)> = Vec::new();
            let mut pulled_notices: Vec<String> = Vec::new();
            let created_image = create_with(
                "devbox",
                pick,
                true,
                ("alice", 1000, 1000),
                |method, path, body| {
                    calls.push((method.to_owned(), path.to_owned(), body.cloned()));
                    match (method, path) {
                        ("GET", p) if p == expected_inspect => Ok(resp(200, br#"{"Id":"sha256:local"}"#)),
                        ("POST", "/containers/create?name=machine-devbox") => Ok(resp(201, br#"{"Id":"c1"}"#)),
                        ("POST", "/containers/machine-devbox/start") => Ok(resp(204, b"")),
                        other => panic!("unexpected daemon call for {pick}: {other:?}"),
                    }
                },
                |cname, _| {
                    assert_eq!(cname, "machine-devbox");
                    Ok((0, String::new()))
                },
                |img| pulled_notices.push(img.to_owned()),
            )
            .unwrap();

            assert_eq!(created_image, expected_image);
            assert!(pulled_notices.is_empty(), "must not announce pulling when image is local: {pick}");
            assert!(!calls.iter().any(|(m, p, _)| m == "POST" && p.starts_with("/images/create")), "must skip /images/create: {calls:?}");
            assert_eq!(calls.len(), 3, "{calls:?}");
            assert_eq!((calls[0].0.as_str(), calls[0].1.as_str()), ("GET", expected_inspect));
            assert_eq!((calls[1].0.as_str(), calls[1].1.as_str()), ("POST", "/containers/create?name=machine-devbox"));
            let create_body = calls[1].2.as_ref().unwrap();
            assert_eq!(create_body["Image"], expected_image);
            assert_eq!(create_body["HostConfig"]["Tmpfs"], json!({"/run": "exec", "/run/lock": "", "/tmp": "exec"}));
            assert_eq!((calls[2].0.as_str(), calls[2].1.as_str()), ("POST", "/containers/machine-devbox/start"));
        }
    }

    #[test]
    fn missing_image_pulls_on_404_and_surfaces_errors() {
        // 1. 404 -> pulls via POST /images/create and creates container.
        let image = parse_machine_image("ghcr.io/org/devbox:1");
        let mut calls = Vec::new();
        let mut pulled_notices = Vec::new();
        let pulled = ensure_machine_image_with(
            &image,
            |method, path, _| {
                calls.push((method.to_owned(), path.to_owned()));
                match (method, path) {
                    ("GET", "/images/ghcr.io%2Forg%2Fdevbox%3A1/json") => Ok(resp(404, br#"{"message":"No such image"}"#)),
                    ("POST", "/images/create?fromImage=ghcr.io%2Forg%2Fdevbox&tag=1") => {
                        Ok(resp(200, b"{\"status\":\"Pulling from org/devbox\"}\n{\"status\":\"Status: Downloaded newer image\"}\n"))
                    }
                    other => panic!("unexpected call: {other:?}"),
                }
            },
            |img| pulled_notices.push(img.to_owned()),
        )
        .unwrap();
        assert!(pulled);
        assert_eq!(pulled_notices, vec!["ghcr.io/org/devbox:1"]);
        assert_eq!(
            calls,
            vec![
                ("GET".to_owned(), "/images/ghcr.io%2Forg%2Fdevbox%3A1/json".to_owned()),
                ("POST".to_owned(), "/images/create?fromImage=ghcr.io%2Forg%2Fdevbox&tag=1".to_owned()),
            ]
        );

        // 2. Pull stream JSON error is surfaced.
        let err = ensure_machine_image_with(
            &image,
            |method, _, _| match method {
                "GET" => Ok(resp(404, br#"{"message":"No such image"}"#)),
                "POST" => Ok(resp(200, b"{\"status\":\"Pulling\"}\n{\"error\":\"pull access denied for ghcr.io/org/devbox\"}\n")),
                _ => unreachable!(),
            },
            |_| {},
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "pull access denied for ghcr.io/org/devbox");

        // 3. Non-2xx pull HTTP error is surfaced.
        let err = ensure_machine_image_with(
            &image,
            |method, _, _| match method {
                "GET" => Ok(resp(404, br#"{"message":"No such image"}"#)),
                "POST" => Ok(resp(400, br#"{"message":"invalid image reference"}"#)),
                _ => unreachable!(),
            },
            |_| {},
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "invalid image reference");

        // 4. Transport error on GET fails immediately without pulling.
        let mut pull_called = false;
        let err = ensure_machine_image_with(
            &image,
            |method, _, _| {
                assert_eq!(method, "GET");
                Err(io::Error::new(io::ErrorKind::ConnectionRefused, "daemon gone"))
            },
            |_| pull_called = true,
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        assert!(!pull_called);

        // 5. Unexpected non-404 status on GET fails without attempting to pull.
        let err = ensure_machine_image_with(
            &image,
            |method, _, _| {
                assert_eq!(method, "GET");
                Ok(resp(500, br#"{"message":"image store unreadable"}"#))
            },
            |_| pull_called = true,
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "image store unreadable");
        assert!(!pull_called);
    }

    #[test]
    fn systemd_create_body_sets_exec_tmpfs_and_systemd_options() {
        let sd = create_body_for("dev", "ubuntu:24.04", "alice", 1000, 1000, true);
        assert_eq!(sd["Image"], "ubuntu:24.04");
        assert_eq!(sd["Hostname"], "dev");
        assert_eq!(sd["Labels"], json!({LABEL: "dev"}));
        assert_eq!(sd["StopSignal"], "SIGRTMIN+3");
        assert_eq!(sd["Env"], json!(["container=docker"]));
        assert_eq!(sd["HostConfig"]["Privileged"], true);
        assert_eq!(sd["HostConfig"]["Tmpfs"], json!({"/run": "exec", "/run/lock": "", "/tmp": "exec"}));
        assert_eq!(sd["HostConfig"]["Binds"], json!([format!("{HOMES}:{HOMES}")]));
        assert_eq!(sd["HostConfig"]["CapAdd"], json!(["NET_ADMIN", "SYS_PTRACE"]));
        assert!(sd["Cmd"][2].as_str().unwrap().contains("/lib/systemd/systemd"));

        let plain = create_body_for("dev", "ubuntu:24.04", "alice", 1000, 1000, false);
        assert!(plain["StopSignal"].is_null());
        assert!(plain["Env"].is_null());
        assert!(plain["HostConfig"]["Privileged"].is_null());
        assert!(plain["HostConfig"]["Tmpfs"].is_null());
        assert!(plain["Cmd"][2].as_str().unwrap().contains("sleep 3600"));
    }

    #[test]
    fn create_with_rejects_invalid_names_before_talking_to_daemon() {
        for bad in ["", "-leading", "bad_name!", "with space"] {
            let err = create_with(
                bad,
                "ubuntu",
                false,
                ("alice", 1000, 1000),
                |_, _, _| panic!("daemon must not be called for invalid name {bad:?}"),
                |_, _| panic!("exec must not be called"),
                |_| panic!("pull must not be called"),
            )
            .unwrap_err();
            assert_eq!(err.to_string(), "a machine name is letters, digits and dashes");
        }
    }

    #[test]
    fn wants_help_stops_at_double_dash_for_shell_commands() {
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<String>>();
        assert!(super::wants_help(&s(&["--help"])));
        assert!(super::wants_help(&s(&["-h"])));
        assert!(super::wants_help(&s(&["help"])));
        assert!(super::wants_help(&s(&["create", "--help"])));
        assert!(super::wants_help(&s(&["shell", "--help"])));
        assert!(super::wants_help(&s(&["shell", "dev", "-h"])));
        assert!(!super::wants_help(&s(&["shell", "dev", "--", "ls", "--help"])));
        assert!(!super::wants_help(&s(&["shell", "dev", "--", "-h"])));
        assert!(!super::wants_help(&s(&[])));
    }

    #[test]
    fn list_json_has_each_machines_name_image_and_state() {
        let rows = json!([{"Labels": {(super::LABEL): "dev"}, "Image": "ubuntu:24.04", "State": "running", "Status": "Up 2 hours"}]);
        assert_eq!(super::list_json(&rows), json!([{"name": "dev", "image": "ubuntu:24.04", "state": "running", "status": "Up 2 hours"}]));
        assert_eq!(super::list_json(&json!([])), json!([]));
    }
}
