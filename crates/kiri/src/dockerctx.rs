//! Which engine plain `docker` reaches, and who has docker's default
//! endpoint, for the window's status bar and Settings → Network on every
//! system (#369, #577).
//!
//! Plain `docker` uses Kiri only through Kiri's context, or through the
//! default endpoint (`/var/run/docker.sock`, `\\.\pipe\docker_engine` on
//! Windows) while Kiri serves it. Another engine's context
//! (`desktop-linux`, `orbstack`, `colima`) is that engine, whatever Kiri
//! serves. Shared with kiri-win by path, so std and serde_json only.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

/// Who serves docker's default endpoint.
#[derive(Debug, Clone, PartialEq)]
pub enum Endpoint {
    Kiri,
    /// Another engine: its name, or the path the endpoint leads to (empty
    /// when nothing says which program it is).
    Taken(String),
    Free,
}

/// What plain `docker` uses, picked as the docker CLI picks it.
#[derive(Debug, PartialEq)]
pub struct Cli {
    /// Its context: "default" for the default endpoint, and for DOCKER_HOST.
    pub context: String,
    /// The environment variable that decides it, when one does: switching
    /// docker's context changes nothing then.
    pub pinned: Option<&'static str>,
    /// Whether that reaches Kiri.
    pub kiri: bool,
}

impl Cli {
    /// The context for the status bar: Kiri's own when docker reaches Kiri
    /// another way (the default endpoint Kiri serves), as the page compares
    /// it with Kiri's.
    pub fn shown<'a>(&'a self, ours: &'a str) -> &'a str {
        if self.kiri { ours } else { &self.context }
    }

    /// The variable to name in the window: only while docker misses Kiri.
    pub fn pinned_shown(&self) -> Option<&'static str> {
        self.pinned.filter(|_| !self.kiri)
    }
}

/// What the docker CLI reads to pick its endpoint.
#[derive(Debug, Default)]
pub struct Env<'a> {
    /// DOCKER_HOST.
    pub host: Option<&'a str>,
    /// DOCKER_CONTEXT.
    pub context: Option<&'a str>,
    /// config.json as read; None when there is none.
    pub config: Option<&'a [u8]>,
}

/// docker's default endpoints, as DOCKER_HOST may name them.
const DEFAULT_HOSTS: [&str; 3] = ["unix:///var/run/docker.sock", "unix:///run/docker.sock", "npipe:////./pipe/docker_engine"];

/// The context `docker` uses, in the docker CLI's order: DOCKER_HOST, then
/// DOCKER_CONTEXT, then config.json's `currentContext`, else "default". A
/// config.json that isn't JSON counts as empty, as the CLI warns and goes
/// on without it. `ours` is Kiri's context and `our_hosts` its endpoints.
pub fn cli(env: &Env, ours: &str, our_hosts: &[&str], endpoint: &Endpoint) -> Cli {
    let set = |v: Option<&str>| v.map(str::trim).filter(|v| !v.is_empty()).map(str::to_owned);
    if let Some(host) = set(env.host) {
        let served = *endpoint == Endpoint::Kiri && DEFAULT_HOSTS.iter().any(|h| same_host(h, &host));
        let kiri = served || our_hosts.iter().any(|h| same_host(h, &host));
        return Cli { context: "default".into(), pinned: Some("DOCKER_HOST"), kiri };
    }
    let (context, pinned) = match set(env.context) {
        Some(c) => (c, Some("DOCKER_CONTEXT")),
        None => (current(env.config).unwrap_or_else(|| "default".into()), None),
    };
    let kiri = if context == "default" { *endpoint == Endpoint::Kiri } else { context == ours };
    Cli { context, pinned, kiri }
}

fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes)
}

/// config.json's `currentContext`, when it names one.
fn current(config: Option<&[u8]>) -> Option<String> {
    let cfg: Value = serde_json::from_slice(strip_bom(config?)).ok()?;
    cfg["currentContext"].as_str().map(str::trim).filter(|c| !c.is_empty()).map(str::to_owned)
}

/// Two docker hosts that are the same endpoint: `npipe:////./pipe/x` and
/// `npipe://./pipe/x`, any case, are one pipe.
fn same_host(a: &str, b: &str) -> bool {
    let norm = |h: &str| match h.split_once(':') {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("npipe") => {
            format!("npipe:{}", rest.replace('\\', "/").trim_matches('/').to_ascii_lowercase())
        }
        Some((scheme, rest)) => format!("{}:{}", scheme.to_ascii_lowercase(), rest.trim_end_matches('/')),
        None => h.trim_end_matches('/').to_owned(),
    };
    norm(a) == norm(b)
}

/// `cli` for this process: its environment and docker's config.json.
pub fn current_cli(ours: &str, our_hosts: &[&str], endpoint: &Endpoint) -> Cli {
    let host = std::env::var("DOCKER_HOST").ok();
    let context = std::env::var("DOCKER_CONTEXT").ok();
    let config = docker_dir().and_then(|d| std::fs::read(d.join("config.json")).ok());
    cli(&Env { host: host.as_deref(), context: context.as_deref(), config: config.as_deref() }, ours, our_hosts, endpoint)
}

/// The engine a socket's path, or a Windows process, belongs to, when it
/// is one Kiri knows.
pub fn engine_name(target: &str) -> Option<&'static str> {
    let t = target.replace('\\', "/").to_ascii_lowercase();
    const KNOWN: [(&str, &str); 9] = [
        ("/.orbstack/", "OrbStack"),
        ("/.docker/", "Docker Desktop"),
        ("docker desktop", "Docker Desktop"),
        ("com.docker.", "Docker Desktop"),
        ("/.rd/", "Rancher Desktop"),
        ("rancher desktop", "Rancher Desktop"),
        ("colima", "Colima"),
        ("podman", "Podman"),
        ("dockerd", "dockerd"),
    ];
    KNOWN.iter().find(|(k, _)| t.contains(k)).map(|(_, name)| *name)
}

/// Settings → Network's Docker socket row: who has `path`, the DOCKER_HOST
/// that points a tool at Kiri instead (`ours`), and whether the window can
/// take it now (`take`: the Mac, while it is free).
pub fn sock_event(path: &str, endpoint: &Endpoint, ours: &str, take: bool) -> Value {
    let (owner, engine, target) = match endpoint {
        Endpoint::Kiri => ("kiri", None, None),
        Endpoint::Free => ("free", None, None),
        Endpoint::Taken(t) => ("other", engine_name(t), Some(t.as_str()).filter(|t| !t.is_empty())),
    };
    json!({"type": "dockersock", "path": path, "owner": owner, "engine": engine, "target": target, "hint": format!("DOCKER_HOST={ours}"), "take": take && *endpoint == Endpoint::Free})
}

/// The window's "status" event: build version, app flavor, and what plain
/// `docker` uses (including `pinned` when DOCKER_HOST or DOCKER_CONTEXT
/// overrides config.json and misses Kiri).
pub fn status_event(version: &str, dev: bool, app: &str, ours: &str, cli: &Cli) -> Value {
    json!({"type": "status", "version": version, "dev": dev, "share": true, "app": app, "ours": ours, "context": cli.shown(ours), "pinned": cli.pinned_shown()})
}

/// Who owns a Unix docker socket path (`path`): Kiri (`ours`), another
/// engine (a socket, plain file, or link to an installed engine in
/// `engines`), or nobody (`Free`, including a dangling link left behind by
/// an engine that was removed).
#[cfg(unix)]
pub fn sock_at(path: &Path, ours: &Path, engines: &[PathBuf]) -> Endpoint {
    let Ok(meta) = std::fs::symlink_metadata(path) else { return Endpoint::Free };
    if meta.file_type().is_symlink() {
        let Ok(target) = std::fs::read_link(path) else { return Endpoint::Taken(path.display().to_string()) };
        let resolved = if target.is_relative() { path.parent().map_or_else(|| target.clone(), |p| p.join(&target)) } else { target.clone() };
        if target == ours || resolved == ours {
            return Endpoint::Kiri;
        }
        if resolved.exists() {
            if let (Ok(a), Ok(b)) = (std::fs::canonicalize(&resolved), std::fs::canonicalize(ours))
                && a == b
            {
                return Endpoint::Kiri;
            }
            return Endpoint::Taken(target.display().to_string());
        }
        if engines.iter().any(|e| target.starts_with(e) || resolved.starts_with(e)) {
            return Endpoint::Taken(target.display().to_string());
        }
        // Left behind by an engine that has been removed.
        return Endpoint::Free;
    }
    // A socket (or anything else) of its own: an engine's, serving or not.
    Endpoint::Taken(path.display().to_string())
}

/// docker's config folder: DOCKER_CONFIG, else `.docker` in the home
/// folder (HOME, or USERPROFILE on Windows).
pub fn docker_dir() -> Option<PathBuf> {
    dir_in(std::env::var_os("DOCKER_CONFIG"), std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }))
}

fn dir_in(config: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    config.filter(|c| !c.is_empty()).map(PathBuf::from).or_else(|| home.filter(|h| !h.is_empty()).map(|h| Path::new(&h).join(".docker")))
}

pub fn read_json(path: &Path) -> io::Result<Value> {
    match std::fs::read(path) {
        Ok(b) => serde_json::from_slice(strip_bom(&b)).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", path.display()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(json!({})),
        Err(e) => Err(e),
    }
}

/// Writes JSON through a temporary file, so a crash never leaves half a config.
pub fn write_json(path: &Path, v: &Value) -> io::Result<()> {
    static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let file = path.file_name().and_then(|n| n.to_str()).unwrap_or("config.json");
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = dir.join(format!(".{file}.kiri-tmp-{}-{seq}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(v).map_err(io::Error::other)?;
    let res = std::fs::write(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, path));
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// A context's meta.json, as `docker context create NAME --docker
/// host=HOST` writes it, in `meta`: contexts/meta/ and the SHA-256 of its
/// name, which the caller works out.
pub fn write_context(meta: &Path, name: &str, description: &str, host: &str) -> io::Result<()> {
    let v = json!({
        "Name": name,
        "Metadata": {"Description": description},
        "Endpoints": {"docker": {"Host": host, "SkipTLSVerify": false}},
    });
    write_json(&meta.join("meta.json"), &v)
}

/// Makes `name` the context in `config` (config.json); "default" takes
/// `currentContext` out. Every other key (registry logins, credential
/// helpers, plugin folders) stays as it was, and a file that isn't a JSON
/// object is left alone, with an error that says so.
pub fn set_current(config: &Path, name: &str) -> io::Result<()> {
    let mut cfg = read_json(config)?;
    let Some(o) = cfg.as_object_mut() else { return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: not a JSON object", config.display()))) };
    if name == "default" {
        o.remove("currentContext");
    } else {
        o.insert("currentContext".into(), name.into());
    }
    write_json(config, &cfg)
}

/// Kiri's context as docker's current one, made first if it's missing (a
/// context someone removed). `dir` is docker's config folder, `meta` the
/// context's folder in it, `host` Kiri's endpoint.
pub fn use_ours(dir: &Path, meta: &Path, name: &str, description: &str, host: &str) -> io::Result<()> {
    if !meta.join("meta.json").is_file() {
        write_context(meta, name, description, host)?;
    }
    set_current(&dir.join("config.json"), name)
}

/// Validates a docker context name so it cannot escape `contexts/meta/`.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

/// Makes `name` the current context in `dir/config.json`: `ours` (created in
/// `meta` first if missing), `"default"`, or another context whose
/// `meta.json` lives in `meta`.
pub fn switch(dir: &Path, meta: &Path, name: &str, ours: &str, description: &str, host: &str) -> io::Result<()> {
    if !valid_name(name) {
        return Err(io::Error::other("not a context name"));
    }
    if name == ours {
        return use_ours(dir, meta, name, description, host);
    }
    if name != "default" && !meta.join("meta.json").is_file() {
        return Err(io::Error::other(format!("there is no docker context `{name}`")));
    }
    set_current(&dir.join("config.json"), name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OURS: &str = "kiri";
    const KIRI_HOST: &str = "unix:///Users/me/.kiri/run/docker.sock";

    fn with_config(config: Option<&str>, endpoint: &Endpoint) -> Cli {
        cli(&Env { config: config.map(str::as_bytes), ..Env::default() }, OURS, &[KIRI_HOST], endpoint)
    }

    #[test]
    fn another_engines_context_is_never_kiri() {
        // #369: Docker Desktop's context, while Kiri holds docker_engine or
        // /var/run/docker.sock: docker talks to Docker Desktop.
        let desktop = Endpoint::Taken("Docker Desktop".into());
        for ctx in ["desktop-linux", "orbstack", "colima"] {
            for endpoint in [Endpoint::Kiri, desktop.clone(), Endpoint::Free] {
                let c = with_config(Some(&format!(r#"{{"currentContext": "{ctx}", "auths": {{}}}}"#)), &endpoint);
                assert_eq!(c, Cli { context: ctx.into(), pinned: None, kiri: false }, "{ctx} with {endpoint:?}");
                assert_eq!(c.shown(OURS), ctx);
            }
        }
    }

    #[test]
    fn kiris_context_is_kiri_whoever_has_the_default_endpoint() {
        for endpoint in [Endpoint::Kiri, Endpoint::Taken("Docker Desktop".into()), Endpoint::Free] {
            let c = with_config(Some(r#"{"currentContext": "kiri"}"#), &endpoint);
            assert!(c.kiri, "{endpoint:?}");
            assert_eq!(c.shown(OURS), "kiri");
        }
    }

    #[test]
    fn the_default_context_is_kiri_only_while_kiri_serves_the_endpoint() {
        // Unset, "default", no config.json, or one docker can't read (it
        // warns and goes on with none): all the default endpoint.
        let configs = [Some(r#"{"currentContext": "default"}"#), Some(r#"{"auths": {}}"#), Some(r#"{"currentContext": ""}"#), None, Some("{not json")];
        for config in configs {
            let c = with_config(config, &Endpoint::Kiri);
            assert_eq!((c.context.as_str(), c.kiri, c.shown(OURS)), ("default", true, "kiri"), "{config:?}");
            for endpoint in [Endpoint::Taken("Docker Desktop".into()), Endpoint::Free] {
                let c = with_config(config, &endpoint);
                assert_eq!((c.context.as_str(), c.kiri, c.shown(OURS)), ("default", false, "default"), "{config:?} with {endpoint:?}");
            }
        }
    }

    #[test]
    fn the_environment_comes_before_config_json() {
        let config = Some(r#"{"currentContext": "kiri"}"#.as_bytes());
        // DOCKER_CONTEXT over currentContext.
        let c = cli(&Env { context: Some("desktop-linux"), config, ..Env::default() }, OURS, &[KIRI_HOST], &Endpoint::Kiri);
        assert_eq!(c, Cli { context: "desktop-linux".into(), pinned: Some("DOCKER_CONTEXT"), kiri: false });
        assert_eq!(c.pinned_shown(), Some("DOCKER_CONTEXT"));
        // DOCKER_HOST over both: Kiri only when it leads to Kiri.
        let host = |h: &'static str, endpoint: &Endpoint| cli(&Env { host: Some(h), context: Some("kiri"), config }, OURS, &[KIRI_HOST, "npipe:////./pipe/kiri"], endpoint);
        let desktop = Endpoint::Taken("Docker Desktop".into());
        assert!(!host("npipe:////./pipe/dockerDesktopLinuxEngine", &Endpoint::Kiri).kiri);
        assert_eq!(host("npipe:////./pipe/dockerDesktopLinuxEngine", &Endpoint::Kiri).pinned_shown(), Some("DOCKER_HOST"));
        assert!(host(KIRI_HOST, &desktop).kiri);
        assert!(host(r"npipe://./pipe/KIRI", &desktop).kiri, "the same pipe, written another way");
        assert_eq!(host(KIRI_HOST, &desktop).pinned_shown(), None, "nothing to say while docker reaches Kiri");
        assert!(host("unix:///var/run/docker.sock", &Endpoint::Kiri).kiri);
        assert!(!host("unix:///var/run/docker.sock", &desktop).kiri);
        assert!(host("npipe:////./pipe/docker_engine", &Endpoint::Kiri).kiri);
        // Empty variables are unset.
        let c = cli(&Env { host: Some(""), context: Some(" "), config }, OURS, &[KIRI_HOST], &Endpoint::Free);
        assert_eq!(c, Cli { context: "kiri".into(), pinned: None, kiri: true });
    }

    #[test]
    fn names_the_engine_behind_an_endpoint() {
        assert_eq!(engine_name("/Users/me/.orbstack/run/docker.sock"), Some("OrbStack"));
        assert_eq!(engine_name("/Users/me/.docker/run/docker.sock"), Some("Docker Desktop"));
        assert_eq!(engine_name("/Users/me/.colima/default/docker.sock"), Some("Colima"));
        assert_eq!(engine_name("/Users/me/.rd/docker.sock"), Some("Rancher Desktop"));
        assert_eq!(engine_name("Docker Desktop.exe"), Some("Docker Desktop"));
        assert_eq!(engine_name("com.docker.backend.exe"), Some("Docker Desktop"));
        assert_eq!(engine_name("Rancher Desktop.exe"), Some("Rancher Desktop"));
        assert_eq!(engine_name("dockerd.exe"), Some("dockerd"));
        assert_eq!(engine_name("/var/run/docker.sock"), None);
    }

    #[test]
    fn the_socket_rows_event() {
        let e = sock_event("/var/run/docker.sock", &Endpoint::Taken("/Users/me/.orbstack/run/docker.sock".into()), KIRI_HOST, true);
        assert_eq!(e["owner"], "other");
        assert_eq!(e["engine"], "OrbStack");
        assert_eq!(e["target"], "/Users/me/.orbstack/run/docker.sock");
        assert_eq!(e["hint"], format!("DOCKER_HOST={KIRI_HOST}"));
        assert_eq!(e["take"], false, "another engine's socket is never taken");
        let e = sock_event("/var/run/docker.sock", &Endpoint::Free, KIRI_HOST, true);
        assert_eq!((e["owner"].as_str(), e["take"].as_bool()), (Some("free"), Some(true)));
        let e = sock_event(r"\\.\pipe\docker_engine", &Endpoint::Taken(String::new()), "npipe:////./pipe/kiri", false);
        assert_eq!((e["owner"].as_str(), e["engine"].is_null(), e["target"].is_null()), (Some("other"), true, true));
        assert_eq!(sock_event("/var/run/docker.sock", &Endpoint::Kiri, KIRI_HOST, true)["take"], false);
    }

    /// A home folder of its own for each test, as HOME or USERPROFILE.
    fn scratch_home(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kiri-dockerctx-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn docker_dir_is_docker_config_or_the_homes() {
        let home = scratch_home("dir");
        assert_eq!(dir_in(None, Some(home.clone().into())), Some(home.join(".docker")));
        assert_eq!(dir_in(Some("".into()), Some(home.clone().into())), Some(home.join(".docker")));
        assert_eq!(dir_in(Some("/elsewhere".into()), Some(home.into())), Some(PathBuf::from("/elsewhere")));
        assert_eq!(dir_in(None, None), None);
        let _ = std::fs::remove_dir_all(scratch_home("dir"));
    }

    #[test]
    fn switching_to_kiri_keeps_logins_helpers_and_plugins() {
        let home = scratch_home("switch");
        let dir = dir_in(None, Some(home.clone().into())).unwrap();
        let meta = dir.join("contexts/meta").join("abc123");
        std::fs::create_dir_all(&dir).unwrap();
        let before = json!({
            "auths": {"ghcr.io": {"auth": "c2VjcmV0"}},
            "credHelpers": {"123.dkr.ecr.eu-west-1.amazonaws.com": "ecr-login"},
            "cliPluginsExtraDirs": ["/Applications/Kiri.app/Contents/Resources/bin/cli-plugins"],
            "currentContext": "desktop-linux",
        });
        write_json(&dir.join("config.json"), &before).unwrap();
        use_ours(&dir, &meta, "kiri", "Kiri (WSL2)", "npipe:////./pipe/kiri").unwrap();
        let after = read_json(&dir.join("config.json")).unwrap();
        assert_eq!(after["currentContext"], "kiri");
        for k in ["auths", "credHelpers", "cliPluginsExtraDirs"] {
            assert_eq!(after[k], before[k], "{k}");
        }
        // The context Kiri made, as `docker context create` does.
        let m = read_json(&meta.join("meta.json")).unwrap();
        assert_eq!((m["Name"].as_str(), m["Endpoints"]["docker"]["Host"].as_str()), (Some("kiri"), Some("npipe:////./pipe/kiri")));
        // docker's choice now, from what was written.
        let config = std::fs::read(dir.join("config.json")).unwrap();
        assert!(cli(&Env { config: Some(&config), ..Env::default() }, "kiri", &[], &Endpoint::Taken("Docker Desktop".into())).kiri);
        // A context already there (setup made it on another pipe) stays.
        write_context(&meta, "kiri", "Kiri (WSL2)", "npipe:////./pipe/kiri-2").unwrap();
        use_ours(&dir, &meta, "kiri", "Kiri (WSL2)", "npipe:////./pipe/kiri").unwrap();
        assert_eq!(read_json(&meta.join("meta.json")).unwrap()["Endpoints"]["docker"]["Host"], "npipe:////./pipe/kiri-2");
        // Back to the default endpoint: currentContext goes, the rest stays.
        set_current(&dir.join("config.json"), "default").unwrap();
        let back = read_json(&dir.join("config.json")).unwrap();
        assert!(back.get("currentContext").is_none());
        assert_eq!(back["auths"], before["auths"]);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn switching_without_a_config_makes_one_and_never_overwrites_a_broken_one() {
        let home = scratch_home("broken");
        let dir = dir_in(Some(home.join("docker-config").into()), None).unwrap();
        let meta = dir.join("contexts/meta").join("abc123");
        use_ours(&dir, &meta, "kiri", "Kiri", KIRI_HOST).unwrap();
        assert_eq!(read_json(&dir.join("config.json")).unwrap(), json!({"currentContext": "kiri"}));
        for broken in ["{\"auths\": {", "[1, 2]"] {
            std::fs::write(dir.join("config.json"), broken).unwrap();
            let e = set_current(&dir.join("config.json"), "kiri").unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{broken}");
            assert_eq!(std::fs::read_to_string(dir.join("config.json")).unwrap(), broken, "left as it was");
        }
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn switch_validates_names_and_existing_contexts() {
        let home = scratch_home("switch-ctx");
        let dir = dir_in(Some(home.join("cfg").into()), None).unwrap();
        let meta = |n: &str| dir.join("contexts/meta").join(n);
        assert!(switch(&dir, &meta(""), "", "kiri", "Kiri", KIRI_HOST).is_err());
        assert!(switch(&dir, &meta(".."), "../etc", "kiri", "Kiri", KIRI_HOST).is_err());
        assert!(switch(&dir, &meta("orbstack"), "orbstack", "kiri", "Kiri", KIRI_HOST).is_err());
        write_context(&meta("orbstack"), "orbstack", "OrbStack", "unix:///tmp/orb.sock").unwrap();
        switch(&dir, &meta("orbstack"), "orbstack", "kiri", "Kiri", KIRI_HOST).unwrap();
        assert_eq!(read_json(&dir.join("config.json")).unwrap()["currentContext"], "orbstack");
        switch(&dir, &meta("kiri"), "kiri", "kiri", "Kiri", KIRI_HOST).unwrap();
        assert_eq!(read_json(&dir.join("config.json")).unwrap()["currentContext"], "kiri");
        switch(&dir, &meta("default"), "default", "kiri", "Kiri", KIRI_HOST).unwrap();
        assert!(read_json(&dir.join("config.json")).unwrap().get("currentContext").is_none());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn status_event_reports_pinned_only_when_not_kiri() {
        let c = cli(&Env { host: Some("unix:///tmp/other.sock"), ..Env::default() }, OURS, &[KIRI_HOST], &Endpoint::Free);
        let s = status_event("0.1.4", false, "Kiri", OURS, &c);
        assert_eq!((s["context"].as_str(), s["pinned"].as_str()), (Some("default"), Some("DOCKER_HOST")));
        let k = cli(&Env { host: Some(KIRI_HOST), ..Env::default() }, OURS, &[KIRI_HOST], &Endpoint::Free);
        let sk = status_event("0.1.4", false, "Kiri", OURS, &k);
        assert_eq!((sk["context"].as_str(), sk["pinned"].is_null()), (Some("kiri"), true));
    }

    #[test]
    fn reads_bom_configs_normalizes_host_schemes_and_isolates_temp_files() {
        let mut bom_cfg = vec![0xEF, 0xBB, 0xBF];
        bom_cfg.extend_from_slice(br#"{"currentContext":"desktop-linux","auths":{"ghcr.io":{}}}"#);
        let c = cli(&Env { config: Some(&bom_cfg), ..Env::default() }, OURS, &[KIRI_HOST], &Endpoint::Kiri);
        assert_eq!((c.context.as_str(), c.kiri), ("desktop-linux", false));

        let home = scratch_home("bom-tmp");
        let cfg_path = home.join("config.json");
        std::fs::write(&cfg_path, &bom_cfg).unwrap();
        set_current(&cfg_path, "kiri").unwrap();
        assert_eq!(read_json(&cfg_path).unwrap()["currentContext"], "kiri");

        write_json(&home.join("ctx.one"), &json!({"n": 1})).unwrap();
        write_json(&home.join("ctx.two"), &json!({"n": 2})).unwrap();
        assert_eq!(read_json(&home.join("ctx.one")).unwrap()["n"], 1);
        assert_eq!(read_json(&home.join("ctx.two")).unwrap()["n"], 2);
        assert_eq!(std::fs::read_dir(&home).unwrap().count(), 3);

        for h in ["UNIX:///var/run/docker.sock", "NPIPE:////./PIPE/DOCKER_ENGINE/", r"npipe://\\.\pipe\docker_engine\"] {
            assert!(cli(&Env { host: Some(h), ..Env::default() }, OURS, &[KIRI_HOST], &Endpoint::Kiri).kiri, "{h}");
        }
        assert!(cli(&Env { host: Some("npipe:////./pipe/kiri/"), ..Env::default() }, OURS, &["npipe:////./pipe/kiri"], &Endpoint::Free).kiri);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[cfg(unix)]
    #[test]
    fn sock_at_detects_kiri_taken_and_free() {
        let d = scratch_home("sock-at");
        let ours_dir = d.join("kiri/run");
        std::fs::create_dir_all(&ours_dir).unwrap();
        let ours = ours_dir.join("docker.sock");
        let link = d.join("docker.sock");
        assert_eq!(sock_at(&link, &ours, &[]), Endpoint::Free);
        std::os::unix::fs::symlink(&ours, &link).unwrap();
        assert_eq!(sock_at(&link, &ours, &[]), Endpoint::Kiri);
        std::fs::remove_file(&link).unwrap();
        // Relative symlink when target exists resolves canonically to Kiri.
        std::fs::write(&ours, "").unwrap();
        std::os::unix::fs::symlink("kiri/run/docker.sock", &link).unwrap();
        assert_eq!(sock_at(&link, &ours, &[]), Endpoint::Kiri);
        std::fs::remove_file(&link).unwrap();
        // Dangling symlink to an installed engine dir stays Taken; without dir, Free.
        let orb = d.join(".orbstack/run/docker.sock");
        std::os::unix::fs::symlink(&orb, &link).unwrap();
        assert_eq!(sock_at(&link, &ours, &[d.join(".orbstack")]), Endpoint::Taken(orb.display().to_string()));
        assert_eq!(sock_at(&link, &ours, &[]), Endpoint::Free);
        let _ = std::fs::remove_dir_all(&d);
    }
}
