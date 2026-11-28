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

/// Lowercase hex SHA-256 of `data`, using `std` only so `dockerctx` stays
/// dependency-free across `kiri`, `kiri-win`, and host-side tests.
pub fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity((data.len() + 9).next_multiple_of(64));
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (dst, add) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *dst = dst.wrapping_add(add);
        }
    }
    let mut out = String::with_capacity(64);
    for word in h {
        use std::fmt::Write as _;
        let _ = write!(out, "{word:08x}");
    }
    out
}

/// The docker CLI's directory for a named context (`contexts/meta/<sha256(name)>`).
pub fn context_meta(dir: &Path, name: &str) -> PathBuf {
    dir.join("contexts/meta").join(sha256_hex(name.as_bytes()))
}

/// Candidate Windows `cli-plugins` folders for Kiri (`cli-plugins` beside
/// `kiri.exe`, `bin\cli-plugins` beside `kiri-win.exe`, `%LOCALAPPDATA%\Kiri\bin\cli-plugins`,
/// and `%LOCALAPPDATA%\Programs\Kiri\cli-plugins`), returning the first existing directory.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub fn find_windows_cli_plugins(exe: Option<&Path>, local_app_data: Option<&Path>) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(exe_dir) = exe.and_then(Path::parent) {
        candidates.push(exe_dir.join("cli-plugins"));
        candidates.push(exe_dir.join("bin").join("cli-plugins"));
    }
    if let Some(local) = local_app_data {
        candidates.push(local.join("Kiri").join("bin").join("cli-plugins"));
        candidates.push(local.join("Kiri").join("cli-plugins"));
        candidates.push(local.join("Programs").join("Kiri").join("bin").join("cli-plugins"));
        candidates.push(local.join("Programs").join("Kiri").join("cli-plugins"));
    }
    candidates.into_iter().find(|p| p.is_dir())
}

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn same_windows_dir(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.replace('\\', "/").trim_end_matches('/').to_ascii_lowercase();
    norm(a) == norm(b)
}

/// What [`repair_windows_config`] changed in `%USERPROFILE%\.docker`.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct WindowsRepair {
    pub context_written: bool,
    pub plugins_added: bool,
    pub current_context_set: bool,
}

/// Options for [`repair_windows_config`].
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
#[derive(Debug, Clone, Copy)]
pub struct WindowsRepairOpts<'a> {
    pub ours: &'a str,
    pub description: &'a str,
    pub host: &'a str,
    pub plugins_dir: Option<&'a Path>,
    /// Always rewrite `contexts/meta/<sha256(ours)>/meta.json` (used by `kiri setup`).
    pub force_context_write: bool,
    /// Set `currentContext` to `ours` whenever `currentContext` is empty (`kiri setup`).
    pub set_current_if_empty: bool,
    /// Unconditionally set `currentContext` to `ours` (`kiri setup --use`).
    pub force_use: bool,
    /// Whether Docker Desktop (`Docker Desktop.exe`) is still installed on this PC.
    pub desktop_installed: bool,
}

/// Ensures Kiri's Windows Docker configuration in `dir` (`%USERPROFILE%\.docker`):
/// - writes `contexts/meta/<sha256(ours)>/meta.json` when missing (or when `force_context_write`),
/// - ensures `cliPluginsExtraDirs` in `config.json` includes `plugins_dir` (preserving logins,
///   credential helpers, aliases, and other plugin dirs), and
/// - sets `currentContext` to `ours` when `force_use` is set, when `currentContext` names a
///   non-existent context (such as a removed `desktop-linux`), when `currentContext` is empty and
///   `set_current_if_empty` is set, or when `config.json` was missing and Docker Desktop is not
///   installed (#984).
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub fn repair_windows_config(dir: &Path, opts: WindowsRepairOpts<'_>) -> io::Result<WindowsRepair> {
    let config_path = dir.join("config.json");
    let config_existed = config_path.exists();
    let mut cfg = read_json(&config_path)?;
    if !cfg.is_object() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: not a JSON object", config_path.display())));
    }
    let mut out = WindowsRepair::default();
    let meta = context_meta(dir, opts.ours);
    let meta_file = meta.join("meta.json");
    let unix_host_on_npipe = opts.host.starts_with("npipe:")
        && read_json(&meta_file)
            .ok()
            .and_then(|v| v["Endpoints"]["docker"]["Host"].as_str().map(|h| h.starts_with("unix:")))
            .unwrap_or(false);
    if opts.force_context_write || !meta_file.is_file() || unix_host_on_npipe {
        write_context(&meta, opts.ours, opts.description, opts.host)?;
        out.context_written = true;
    }
    let mut cfg_changed = false;
    if let Some(plugins) = opts.plugins_dir {
        let want = plugins.to_string_lossy().into_owned();
        let mut dirs: Vec<Value> = cfg.get("cliPluginsExtraDirs").and_then(Value::as_array).cloned().unwrap_or_default();
        if !dirs.iter().any(|d| d.as_str().is_some_and(|s| same_windows_dir(s, &want))) {
            dirs.push(Value::String(want));
            cfg["cliPluginsExtraDirs"] = Value::Array(dirs);
            out.plugins_added = true;
            cfg_changed = true;
        }
    }
    let cur = cfg.get("currentContext").and_then(Value::as_str).map(str::trim).unwrap_or("").to_owned();
    let dangling = !cur.is_empty()
        && cur != "default"
        && cur != opts.ours
        && (!valid_name(&cur)
            || !context_meta(dir, &cur).join("meta.json").is_file()
            || (cur == "desktop-linux" && !opts.desktop_installed));
    let want_ours = opts.force_use
        || dangling
        || (cur.is_empty() && (opts.set_current_if_empty || (!config_existed && !opts.desktop_installed)));
    if want_ours && cur != opts.ours {
        cfg["currentContext"] = Value::String(opts.ours.to_owned());
        out.current_context_set = true;
        cfg_changed = true;
    }
    if cfg_changed {
        write_json(&config_path, &cfg)?;
    }
    Ok(out)
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

    #[test]
    fn sha256_hex_matches_known_vectors_and_docker_context_dir() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            sha256_hex(b"kiri"),
            "80d7688032dda428a5d1e0eea7ad434d219b770b7d3a0646fd58695e40107755"
        );
    }

    #[test]
    fn windows_config_repair_heals_wiped_config_plugins_and_dangling_desktop_context() {
        let root = scratch_home("win-repair");
        let docker = root.join(".docker");
        let exe_dir = root.join("Kiri/bin");
        let plugins = exe_dir.join("cli-plugins");
        std::fs::create_dir_all(&plugins).unwrap();
        let exe = exe_dir.join("kiri.exe");
        std::fs::write(&exe, b"").unwrap();
        assert_eq!(find_windows_cli_plugins(Some(&exe), None).as_deref(), Some(plugins.as_path()));

        // 1. Docker Desktop uninstalled and wiped `%USERPROFILE%\.docker\config.json`:
        //    startup self-heal restores `kiri` context, `cliPluginsExtraDirs`, and `currentContext = "kiri"`.
        let r = repair_windows_config(
            &docker,
            WindowsRepairOpts {
                ours: "kiri",
                description: "Kiri (WSL2)",
                host: "npipe:////./pipe/kiri",
                plugins_dir: Some(&plugins),
                force_context_write: false,
                set_current_if_empty: false,
                force_use: false,
                desktop_installed: false,
            },
        )
        .unwrap();
        assert_eq!(
            r,
            WindowsRepair { context_written: true, plugins_added: true, current_context_set: true }
        );
        let cfg = read_json(&docker.join("config.json")).unwrap();
        assert_eq!(cfg["currentContext"], "kiri");
        assert_eq!(cfg["cliPluginsExtraDirs"], json!([plugins.to_string_lossy()]));
        // Idempotent on subsequent starts (no redundant writes).
        let r2 = repair_windows_config(
            &docker,
            WindowsRepairOpts {
                ours: "kiri",
                description: "Kiri (WSL2)",
                host: "npipe:////./pipe/kiri",
                plugins_dir: Some(&plugins),
                force_context_write: false,
                set_current_if_empty: false,
                force_use: false,
                desktop_installed: false,
            },
        )
        .unwrap();
        assert_eq!(r2, WindowsRepair::default());

        // 2. Dangling `desktop-linux` context (meta removed or Docker Desktop uninstalled) is healed,
        //    preserving registry logins, credHelpers, and aliases.
        write_json(
            &docker.join("config.json"),
            &json!({
                "auths": {"ghcr.io": {"auth": "c2VjcmV0"}},
                "credHelpers": {"ecr": "ecr-login"},
                "aliases": {"builder": "buildx"},
                "currentContext": "desktop-linux",
            }),
        )
        .unwrap();
        let r3 = repair_windows_config(
            &docker,
            WindowsRepairOpts {
                ours: "kiri",
                description: "Kiri (WSL2)",
                host: "npipe:////./pipe/kiri",
                plugins_dir: Some(&plugins),
                force_context_write: false,
                set_current_if_empty: false,
                force_use: false,
                desktop_installed: false,
            },
        )
        .unwrap();
        assert!(r3.plugins_added && r3.current_context_set);
        let after = read_json(&docker.join("config.json")).unwrap();
        assert_eq!(after["currentContext"], "kiri");
        assert_eq!(after["auths"]["ghcr.io"]["auth"], "c2VjcmV0");
        assert_eq!(after["credHelpers"]["ecr"], "ecr-login");
        assert_eq!(after["aliases"]["builder"], "buildx");

        // 2b. A Windows kiri context overwritten with a WSL unix:// socket (through a shared
        //     ~/.docker/contexts symlink) is self-healed back to npipe:// even without force_context_write.
        write_context(&context_meta(&docker, "kiri"), "kiri", "Kiri", "unix:///mnt/wsl/kiri/sockets/Ubuntu/docker.sock").unwrap();
        let r_unix = repair_windows_config(
            &docker,
            WindowsRepairOpts {
                ours: "kiri",
                description: "Kiri (WSL2)",
                host: "npipe:////./pipe/kiri",
                plugins_dir: Some(&plugins),
                force_context_write: false,
                set_current_if_empty: false,
                force_use: false,
                desktop_installed: false,
            },
        )
        .unwrap();
        assert!(r_unix.context_written);
        let healed = read_json(&context_meta(&docker, "kiri").join("meta.json")).unwrap();
        assert_eq!(healed["Endpoints"]["docker"]["Host"], "npipe:////./pipe/kiri");

        // 3. Corrupt config.json is never overwritten.
        std::fs::write(docker.join("config.json"), "{broken").unwrap();
        assert_eq!(
            repair_windows_config(
                &docker,
                WindowsRepairOpts {
                    ours: "kiri",
                    description: "Kiri (WSL2)",
                    host: "npipe:////./pipe/kiri",
                    plugins_dir: Some(&plugins),
                    force_context_write: true,
                    set_current_if_empty: true,
                    force_use: true,
                    desktop_installed: false,
                },
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(std::fs::read_to_string(docker.join("config.json")).unwrap(), "{broken");
        let _ = std::fs::remove_dir_all(&root);
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
