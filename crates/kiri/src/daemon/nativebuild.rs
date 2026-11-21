//! `POST /kiri/build`: `kiri build` on the native builder (Forge, `kiri_forge`),
//! with the folder read in place.
//!
//! The answer is JSON lines: `{"stream": text}` for progress, then
//! `{"aux": {"ID": id}}` or `{"error": text}`. When the native builder does
//! not cover the build, or is switched off, the first and only line says so
//! (`{"fallback": reason}`, `{"native": "off"}`) and nothing has been done:
//! the CLI then runs the build Kiri has always run, unchanged.
//!
//! The daemon reads the folder in place, with the rights of the user at
//! the other end of the socket (peer credentials; see
//! `kiri_forge::context::Root`), so the kernel allows exactly what that
//! user's own client could read; it never takes `/proc`, `/dev`, `/sys`
//! or its own state as a context.
//!
//! Each image the build writes gets a build-path record (`native`, or
//! `fallback <reason>` when the CLI reports a fallback build's image), read
//! by `GET /kiri/build-path?image=` for the builder test data's runs.

use std::collections::BTreeMap;
use std::io::{self, BufReader};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use serde_json::{Value, json};

use kiri_forge::build::{self, Event, Outcome, Plain};
use kiri_forge::cache::StepCache;
use kiri_forge::context;

use super::api::{self, Next};
use super::buildports::Ports;
use super::engine::{Engine, Error};
use super::http::{self, Request};

/// What `kiri build` asks for.
#[derive(Debug, Default)]
struct Ask {
    context: PathBuf,
    /// Relative to the context, or absolute.
    dockerfile: String,
    /// `-f -`: the Dockerfile itself.
    dockerfile_text: Option<String>,
    /// A URL given as the context: fetched by the engine.
    context_url: Option<String>,
    opts: build::Options,
    /// The client asked for the stage timings in the output too.
    timing: bool,
    /// The context is a folder the engine made (a URL context's): read as
    /// the engine. Never set from what a client sends.
    engine_context: bool,
    /// A URL context that is not Git: downloaded by the build itself
    /// (so the client's leaving cancels it) into `context`, a folder of its
    /// own only the engine reads; a Dockerfile, or an archive whose files
    /// are the context (`url_context`).
    url: Option<String>,
    /// `kiri build --ssh`: the client's agent session (buildssh.rs), by its
    /// token; the build may use it only if it is the caller's own.
    ssh_session: Option<String>,
}

fn parse(body: &[u8]) -> Result<Ask, Error> {
    let v: Value = serde_json::from_slice(body).map_err(|e| Error::BadRequest(format!("invalid JSON: {e}")))?;
    let context = v["context"].as_str().filter(|c| c.starts_with('/')).ok_or_else(|| Error::BadRequest("context must be an absolute path".into()))?;
    let pairs = |k: &str| -> BTreeMap<String, String> {
        v[k].as_object().into_iter().flatten().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned()))).collect()
    };
    let strings = |k: &str| -> Vec<String> { v[k].as_array().into_iter().flatten().filter_map(|s| s.as_str().map(str::to_owned)).collect() };
    let dockerfile = v["dockerfile"].as_str().filter(|d| !d.is_empty()).unwrap_or("Dockerfile").to_owned();
    let mut tags = Vec::new();
    for t in strings("tags") {
        let r = kiri_image::Reference::parse(&t).map_err(|_| Error::BadRequest(format!("invalid reference format: {t}")))?;
        if r.is_digest() {
            // moby's tag sanitizing.
            return Err(Error::BadRequest("build tag cannot contain a digest".into()));
        }
        // The full name, as `naming to docker.io/library/app:latest` shows it.
        tags.push(format!("{}/{}:{}", r.registry, r.repository, r.reference));
    }
    let name = Path::new(&dockerfile).file_name().and_then(|n| n.to_str()).unwrap_or("Dockerfile").to_owned();
    let entitlements = granted(&strings("allow"), &engine_entitlements())?;
    Ok(Ask {
        context: PathBuf::from(context),
        dockerfile_text: v["dockerfile_text"].as_str().map(str::to_owned),
        context_url: v["context_url"].as_str().filter(|u| u.starts_with("http://") || u.starts_with("https://")).map(str::to_owned),
        timing: v["timing"].as_bool().unwrap_or(false),
        engine_context: false,
        url: None,
        ssh_session: v["ssh"]["session"].as_str().map(str::to_owned),
        opts: build::Options {
            target: v["target"].as_str().unwrap_or_default().to_owned(),
            build_args: pairs("build_args"),
            labels: pairs("labels"),
            tags,
            no_cache: v["no_cache"].as_bool().unwrap_or(false),
            no_cache_filter: strings("no_cache_filter"),
            platform: v["platform"].as_str().filter(|p| !p.is_empty()).map(str::to_owned),
            dockerfile_name: if v["dockerfile_text"].is_string() { "Dockerfile".into() } else { name },
            secrets: secrets(&v)?,
            named_contexts: named_contexts(&v)?,
            rewrite_timestamp: v["rewrite_timestamp"].as_bool().unwrap_or(false),
            exporter_epoch: v["exporter_epoch"].as_str().map(str::to_owned),
            verify_layers: matches!(std::env::var("KIRI_BUILD_VERIFY").as_deref(), Ok("1" | "true")),
            network: match v["network"].as_str().unwrap_or_default() {
                "" | "default" | "sandbox" => kiri_forge::ports::Network::Default,
                "none" => kiri_forge::ports::Network::None,
                "host" => kiri_forge::ports::Network::Host,
                n => return Err(Error::BadRequest(format!("invalid netmode {n}"))),
            },
            entitlements,
            shm_size: v["shm_size"].as_i64().unwrap_or(0),
            ulimits: ulimits(&v)?,
            copy_context_binds: !hard_links_protected(std::fs::read_to_string("/proc/sys/fs/protected_hardlinks").ok().as_deref()),
            // The mounts the engine's runner takes (buildports.rs), shared
            // with every other entry point of the engine.
            ..build::Options::for_engine(host_platform())
        },
        dockerfile,
    })
}

/// Whether a user can only hard-link files they own or may read and write
/// (`fs.protected_hardlinks` = 1, every distribution's default). Where they
/// can link any file, a folder bound live into a step could gain, after
/// the caller check, a link to a file the caller may not read, and the
/// step, run as root, would read it: context binds are copied then
/// (`Options::copy_context_binds`). On macOS the engine is the user: a
/// link there gives the step nothing the user could not read.
fn hard_links_protected(sysctl: Option<&str>) -> bool {
    if !cfg!(target_os = "linux") {
        return true;
    }
    sysctl.map(str::trim) == Some("1")
}

/// What the engine grants a build that asks (`--allow`): `network.host`,
/// as the BuildKit Kiri runs allows it, and what Settings `entitlements`
/// or `KIRI_BUILD_ENTITLEMENTS` (comma separated) add.
fn engine_entitlements() -> Vec<String> {
    let mut out = vec!["network.host".to_owned()];
    match std::env::var("KIRI_BUILD_ENTITLEMENTS") {
        Ok(v) => out.extend(v.split(',').map(str::trim).filter(|e| !e.is_empty()).map(str::to_owned)),
        Err(_) => out.extend(super::builder::entitlements_setting()),
    }
    out
}

/// The entitlements a build asked for, each one the engine allows; one it
/// does not is refused before anything runs, in BuildKit's words
/// (util/entitlements), as dockerd refuses it.
fn granted(asked: &[String], allowed: &[String]) -> Result<std::collections::BTreeSet<String>, Error> {
    let mut out = std::collections::BTreeSet::new();
    for e in asked {
        if !matches!(e.as_str(), "network.host" | "security.insecure") {
            return Err(Error::BadRequest(format!("invalid entitlement: {e}")));
        }
        if !allowed.contains(e) {
            return Err(Error::BadRequest(format!("granting entitlement {e} is not allowed by build daemon configuration")));
        }
        out.insert(e.clone());
    }
    Ok(out)
}

/// `{"secrets": {"id": "<base64>"}}`: what `kiri build --secret` read as
/// the calling user. At most 256 KiB each, as the engine's runner takes.
fn secrets(v: &Value) -> Result<BTreeMap<String, Vec<u8>>, Error> {
    let mut out = BTreeMap::new();
    for (id, data) in v["secrets"].as_object().into_iter().flatten() {
        let bytes = data.as_str().and_then(kiri_image::b64::decode).ok_or_else(|| Error::BadRequest(format!("secret {id}: not base64")))?;
        if bytes.len() > 256 << 10 {
            return Err(Error::BadRequest(format!("secret {id}: larger than 256 KiB")));
        }
        out.insert(id.clone(), bytes);
    }
    Ok(out)
}

/// `{"ulimits": [{"name": "nofile", "soft": n, "hard": n}]}`, as
/// `kiri build --ulimit` read them (-1 for unlimited).
fn ulimits(v: &Value) -> Result<Vec<kiri_forge::ports::Ulimit>, Error> {
    let mut out = Vec::new();
    for u in v["ulimits"].as_array().into_iter().flatten() {
        match (u["name"].as_str(), u["soft"].as_i64(), u["hard"].as_i64()) {
            (Some(name), Some(soft), Some(hard)) => out.push(kiri_forge::ports::Ulimit { name: name.to_owned(), soft, hard }),
            _ => return Err(Error::BadRequest(format!("invalid ulimit {u}"))),
        }
    }
    Ok(out)
}

/// `{"build_contexts": {"name": {"image": ref} | {"local": abs path}}}`.
fn named_contexts(v: &Value) -> Result<BTreeMap<String, build::NamedContext>, Error> {
    let mut out = BTreeMap::new();
    for (name, c) in v["build_contexts"].as_object().into_iter().flatten() {
        let nc = match (c["image"].as_str(), c["local"].as_str(), c["url"].as_str()) {
            (Some(r), None, None) => build::NamedContext::Image(r.to_owned()),
            (None, Some(p), None) if p.starts_with('/') => build::NamedContext::Local(PathBuf::from(p)),
            (None, None, Some(u)) if kiri_forge::convert::git::is_http_source(u) && matches!(kiri_forge::convert::git::parse_git_ref(u), Ok(None)) => build::NamedContext::Url(u.to_owned()),
            _ => return Err(Error::BadRequest(format!("build context {name}: an image, a URL or an absolute path"))),
        };
        out.insert(name.clone(), nc);
    }
    Ok(out)
}

/// The platform steps run on: the guest's, which is the host's architecture
/// (others it runs as they are: `Ports::platforms`).
fn host_platform() -> kiri_forge::ports::Platform {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        a => a,
    };
    kiri_forge::ports::Platform { os: "linux".into(), architecture: arch.into(), variant: if arch == "arm64" { "v8".into() } else { String::new() } }
}

/// Whether the native builder takes a build. The first one given wins:
/// what the client asked for (`asked`: `kiri build --builder`, or the
/// `KIRI_NATIVE_BUILD` of its terminal), `KIRI_NATIVE_BUILD` for the
/// engine, then Settings (`kiri builder use`; off by default).
pub fn enabled(asked: Option<bool>) -> bool {
    choose(asked, std::env::var("KIRI_NATIVE_BUILD").ok().as_deref(), super::builder::native_setting)
}

fn choose(asked: Option<bool>, env: Option<&str>, setting: impl FnOnce() -> bool) -> bool {
    match (asked, env) {
        (Some(a), _) => a,
        (None, Some("0" | "false" | "off")) => false,
        (None, Some(_)) => true,
        (None, None) => setting(),
    }
}

/// `{"builder": "kiri" | "forge" | "buildkit"}` in a `POST /kiri/build`:
/// the client's choice for this build, if it made one. `kiri` (what `kiri
/// build` sends) and `forge` both name Forge, the native builder.
fn asked(body: &[u8]) -> Option<bool> {
    let v: Value = serde_json::from_slice(body).ok()?;
    match v["builder"].as_str()? {
        "kiri" | "forge" => Some(true),
        "buildkit" => Some(false),
        _ => None,
    }
}

fn build_dir() -> io::Result<PathBuf> {
    Ok(super::state_dir()?.join("build"))
}

/// One step cache for the engine, shared by every build.
pub(super) fn step_cache() -> io::Result<&'static StepCache> {
    static CACHE: OnceLock<StepCache> = OnceLock::new();
    if let Some(c) = CACHE.get() {
        return Ok(c);
    }
    let c = StepCache::open(&build_dir()?.join("steps")).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(CACHE.get_or_init(|| c))
}

/// `POST /kiri/build`.
/// What in a build request goes to BuildKit before anything is read: a
/// git address, as the main context or a named one (Kiri's builder fetches
/// no git repository; BuildKit reads a context as git by dockerui's
/// `DetectGitContext`, which `parse_git_ref` follows, and so does `kiri
/// build` before it asks). `ADD <git address>` in the Dockerfile is the
/// builder's own check (`ADD of a git repository`).
fn git_fallback(body: &[u8]) -> Option<&'static str> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let git = |u: &str| !matches!(kiri_forge::convert::git::parse_git_ref(u), Ok(None));
    if v["context_url"].as_str().is_some_and(git) {
        return Some("a remote context");
    }
    v["build_contexts"].as_object().into_iter().flatten().any(|(_, c)| c["url"].as_str().is_some_and(git)).then_some("--build-context")
}

pub fn build(req: &Request, engine: &Arc<Engine>, w: &mut UnixStream, _r: &mut BufReader<UnixStream>) -> io::Result<Next> {
    // Parsing and planning read input as deep as the client makes it: they
    // run on a thread whose stack is known and large, not on the
    // connection's own (every recursion in them is bounded as well; see
    // kiri-forge's `deep_inputs` tests).
    let body = &req.body;
    let ran = std::thread::scope(|s| std::thread::Builder::new().name("kiri-build".into()).stack_size(BUILD_STACK).spawn_scoped(s, || build_on_thread(body, engine, w)).map(|t| t.join()));
    match ran {
        Ok(Ok(r)) => r,
        // A build that panicked (only where panics unwind: the engine's
        // release build aborts on a panic) fails alone.
        Ok(Err(_)) => Err(io::Error::other("the build stopped on an internal error")),
        Err(e) => api::reply(w, Err(Error::Io(e)), 200),
    }
}

/// The stack of the thread a build runs on: the deepest input the builder
/// takes uses a small part of it.
const BUILD_STACK: usize = 64 << 20;

fn build_on_thread(body: &[u8], engine: &Arc<Engine>, w: &mut UnixStream) -> io::Result<Next> {
    // The VM stays awake from here until the answer is written, whatever
    // the build is doing and however it ends (`Engine::hold_awake`).
    let _awake = engine.hold_awake();
    if !enabled(asked(body)) {
        return api::reply(w, Ok(json!({"native": "off"})), 200);
    }
    // A git address is never fetched as a page, whatever client sent it.
    if let Some(reason) = git_fallback(body) {
        return api::reply(w, Ok(json!({"fallback": reason})), 200);
    }
    let mut ask = match parse(body) {
        Ok(a) => a,
        Err(e) => return api::reply(w, Err(e), 200),
    };
    sweep_once();
    // A URL context: downloaded by the build, in a folder of its own in
    // the engine's build folder.
    if let Some(url) = ask.context_url.clone() {
        // In the engine's own build folder (its disk, not a tmpfs;
        // no other engine's sweep reaches it).
        let dir = match build_dir().and_then(|b| private_dir(&b.join("tmp"), "kiri-url-context")) {
            Ok(d) => d,
            Err(e) => return api::reply(w, Err(Error::Io(e)), 200),
        };
        ask.context = dir.clone();
        ask.url = Some(url);
        ask.engine_context = true;
        let r = build_in(&mut ask, engine, w);
        let _ = std::fs::remove_dir_all(&dir);
        return r;
    }
    build_in(&mut ask, engine, w)
}

/// A new folder in `base` that only the engine can read (0700), made
/// fresh: a name already there is an error, never reused.
fn private_dir(base: &Path, prefix: &str) -> io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::create_dir_all(base)?;
    let dir = base.join(format!("{prefix}-{}", super::engine::random_hex(8)));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
}

/// At engine start, on a thread of its own; the first build waits for it
/// if it is still running.
pub(super) fn sweep_at_start() {
    let _ = std::thread::Builder::new().name("kiri-build-sweep".into()).spawn(sweep_once);
}

/// Before this engine's first build (no build of it running yet, and the
/// others wait): what builds of an engine that stopped mid-build left.
fn sweep_once() {
    static SWEPT: std::sync::Once = std::sync::Once::new();
    SWEPT.call_once(|| {
        if let Ok(d) = build_dir() {
            sweep_build_folders(&d);
        }
    });
}

/// What builds of this engine left in its own build folder `build` (no
/// other engine's): every entry of `tmp`, the builds' work folder (URL
/// contexts, file spools, copy bodies, downloads), and every staged bind
/// in `binds`, detached first. Called only while no build of this engine
/// runs. Nothing is followed out of these folders: a link is removed as a
/// link, and an entry on another filesystem (a mount still in place) is
/// detached, never descended into.
fn sweep_build_folders(build: &Path) {
    use std::os::unix::fs::MetadataExt as _;
    let tmp = build.join("tmp");
    if let (Ok(top), Ok(rd)) = (std::fs::symlink_metadata(&tmp), std::fs::read_dir(&tmp)) {
        for e in rd.flatten() {
            let p = e.path();
            let Ok(m) = p.symlink_metadata() else { continue };
            if m.is_dir() && m.dev() != top.dev() {
                detach(&p);
                if p.symlink_metadata().is_ok_and(|n| n.dev() != top.dev()) {
                    continue;
                }
            }
            let _ = if m.is_dir() { remove_tree_on(&p, top.dev()) } else { std::fs::remove_file(&p) };
        }
    }
    let binds = build.join("binds");
    if let Ok(rd) = std::fs::read_dir(&binds) {
        for e in rd.flatten() {
            let p = e.path();
            if !e.file_name().to_string_lossy().starts_with("bind-") {
                continue;
            }
            detach(&p);
            // empty once detached; one still mounted is left as it is
            let _ = std::fs::remove_dir(&p).or_else(|_| match p.symlink_metadata() {
                Ok(m) if !m.is_dir() => std::fs::remove_file(&p),
                _ => Ok(()),
            });
        }
    }
}

/// Detaches whatever is mounted at `p` (Linux; nothing elsewhere).
fn detach(p: &Path) {
    #[cfg(target_os = "linux")]
    if let Ok(c) = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(p.as_os_str())) {
        // Several mounts may be stacked at one place.
        // SAFETY: a NUL-terminated path; the result is only looked at.
        while unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW) } == 0 {}
    }
    #[cfg(not(target_os = "linux"))]
    let _ = p;
}

/// Removes the tree at `dir`, staying on filesystem `dev`: a folder of
/// another (a mount) is left, with what holds it. Iterative: a tree of any
/// depth.
fn remove_tree_on(dir: &Path, dev: u64) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let mut todo = vec![(dir.to_path_buf(), false)];
    while let Some((d, listed)) = todo.pop() {
        if listed {
            let _ = std::fs::remove_dir(&d);
            continue;
        }
        todo.push((d.clone(), true));
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            match p.symlink_metadata() {
                Ok(m) if m.is_dir() && m.dev() == dev => todo.push((p, false)),
                Ok(m) if m.is_dir() => {}
                Ok(_) => {
                    let _ = std::fs::remove_file(&p);
                }
                Err(_) => {}
            }
        }
    }
    if dir.exists() { Err(io::Error::other("not all removed")) } else { Ok(()) }
}

/// The build of `ask` on its (local) context, streamed to `w`.
fn build_in(ask: &mut Ask, engine: &Arc<Engine>, w: &mut UnixStream) -> io::Result<Next> {
    // A folder the engine never reads as a context is refused before any
    // answer is streamed (/proc, /dev, /sys, the engine's state).
    // A URL context's folder is the engine's own, made in its build
    // folder (refused to every client-named context).
    if let Ok(state) = super::state_dir()
        && let Err(context::ContextError::Refused(p)) = context::check_root(&ask.context, if ask.engine_context { &[] } else { std::slice::from_ref(&state) })
    {
        return api::reply(w, Err(Error::BadRequest(format!("{} cannot be a build context", p.display()))), 200);
    }
    let caller = match known_caller(peer_cred(w)) {
        Ok(c) => c,
        Err(e) => return api::reply(w, Err(e), 200),
    };
    // The agents the client forwards: its own session only, opened by the
    // same user (another user's token, or a guessed one, is refused).
    if let Some(session) = &ask.ssh_session {
        match super::buildssh::session_ids(session, caller.as_ref().map(|c| c.uid)) {
            Ok(ids) => ask.opts.ssh_ids = Some(ids),
            Err(m) => return api::reply(w, Err(Error::BadRequest(m)), 200),
        }
    }
    http::begin_stream(w, 200, "application/json")?;
    // The client gone (Ctrl-C, a killed terminal) cancels the build: its
    // step is ended and nothing of it is kept (owner's item: Ctrl-C leaves
    // nothing behind).
    let _watch = ClientWatch::start(w, ask.opts.cancel.clone());
    let mut out = Lines { w, broken: false };
    match run(ask, engine, caller, &mut out) {
        Ok(Done::Built(id)) => out.line(json!({"aux": {"ID": id}})),
        Ok(Done::Fallback(reason)) => {
            crate::diag::info!("build handed to BuildKit", reason = reason);
            out.line(json!({"fallback": reason}));
        }
        Err(Failed { message, source }) => {
            crate::diag::warn!("native build failed", error = message);
            out.line(json!({"error": message, "source": source}));
        }
    }
    if !out.broken {
        http::end(out.w)?;
    }
    Ok(Next::KeepAlive)
}

/// A URL context that is not Git (dockerui `DetectHTTPContext`): the
/// download, saved as `context` in the build's own folder (`ask.context`)
/// with the build's bounds, is a Dockerfile, or an archive whose files are
/// the context. An archive is unpacked into a tree with ADD's unpacker,
/// within the build's checkout limits, and read through the copy rules
/// only, never by a host path. `SOURCE_DATE_EPOCH=context` takes its
/// `Last-Modified`, else the newest file in the archive, as BuildKit does.
fn url_context(ask: &mut Ask, url: &str, emit: &mut dyn FnMut(Event<'_>)) -> Result<(), String> {
    use std::io::Read as _;
    let v = usize::MAX;
    let began = Instant::now();
    emit(Event::Start { vertex: v, name: "[internal] load remote build context" });
    let r = (|| -> Result<(), String> {
        let file = ask.context.join("context");
        let l = ask.opts.fetch_limits;
        let mut f = std::fs::File::create_new(&file).map_err(|e| e.to_string())?;
        let reply = super::buildfetch::get_bounded(url, &mut f, l.response, l.total_time, l.read_time, &ask.opts.cancel).map_err(|e| e.to_string())?;
        drop(f);
        if !(200..400).contains(&reply.status) {
            return Err(format!("invalid response status {}", reply.status));
        }
        let last_modified = reply.last_modified.as_deref().and_then(kiri_forge::build::http_time);
        let mut head = Vec::with_capacity(1024);
        std::fs::File::open(&file).and_then(|f| f.take(1024).read_to_end(&mut head)).map_err(|e| e.to_string())?;
        if !kiri_forge::copy::is_archive(&head) {
            // No more than one byte past BuildKit's limit: the build then
            // fails on the Dockerfile's size, as BuildKit's does.
            let max = kiri_forge::build::MAX_DOCKERFILE;
            let mut body = Vec::new();
            std::fs::File::open(&file).and_then(|f| f.take(max as u64 + 1).read_to_end(&mut body)).map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(&file);
            ask.dockerfile_text = if body.len() > max { Some(String::from_utf8_lossy(&body).into_owned()) } else { url_body(body)? };
            ask.opts.context_epoch = last_modified;
            return Ok(());
        }
        let tree = kiri_forge::copy::Tree::new(&ask.context);
        let limits = kiri_forge::copy::ContextLimits { bytes: l.bytes, entries: l.entries, time: l.total_time, cancel: ask.opts.cancel.clone() };
        let newest = kiri_forge::copy::unpack_context(&file, &tree, &limits).map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(&file);
        ask.opts.context_epoch = last_modified.or(newest);
        ask.opts.context_tree = Some(tree);
        Ok(())
    })();
    match &r {
        Ok(()) => emit(Event::Done { vertex: v, seconds: began.elapsed().as_secs_f64() }),
        Err(m) => emit(Event::Error { vertex: v, message: m }),
    }
    r
}

/// What BuildKit's dockerui makes of a URL context's body: an archive by
/// its content is the context (None: unpacked into a tree), anything else
/// the Dockerfile.
fn url_body(body: Vec<u8>) -> Result<Option<String>, String> {
    if kiri_forge::copy::is_archive(&body) {
        return Ok(None);
    }
    String::from_utf8(body).map(Some).map_err(|_| "the context URL's Dockerfile is not UTF-8".into())
}

/// A URL context's Dockerfile, read from its archive's tree as dockerui's
/// `ReadEntrypoint` reads it: the `-f` path (default `Dockerfile`), then
/// `dockerfile` when that is missing.
fn tree_dockerfile(tree: &kiri_forge::copy::Tree, ask: &mut Ask) -> Result<Vec<u8>, String> {
    let name = ask.dockerfile.clone();
    let fail = |e: &io::Error, n: &str| format!("failed to read dockerfile: open {n}: {}", go_errno(e));
    let max = kiri_forge::build::MAX_DOCKERFILE as u64 + 1;
    match tree.read_file_max(&name, max) {
        Ok(d) => Ok(d),
        Err(e) if e.kind() == io::ErrorKind::NotFound && Path::new(&name).file_name().is_some_and(|n| n == "Dockerfile") => {
            let lower = name.strip_suffix("Dockerfile").map(|d| format!("{d}dockerfile")).unwrap_or_default();
            let d = tree.read_file_max(&lower, max).map_err(|e2| if e2.kind() == io::ErrorKind::NotFound { fail(&e, &name) } else { fail(&e2, &lower) })?;
            ask.opts.dockerfile_name = "dockerfile".into();
            Ok(d)
        }
        Err(e) => Err(fail(&e, &name)),
    }
}

/// A failed build: the error, and the Dockerfile lines it points at as
/// buildx prints them above it.
struct Failed {
    message: String,
    source: String,
}

impl From<String> for Failed {
    fn from(message: String) -> Failed {
        Failed { message, source: String::new() }
    }
}

enum Done {
    Built(String),
    Fallback(String),
}

/// Watches the client's end of a build's stream and cancels the build when
/// it hangs up. Stops on drop.
struct ClientWatch {
    done: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ClientWatch {
    fn start(w: &UnixStream, cancel: kiri_forge::ports::Cancel) -> Option<ClientWatch> {
        let sock = w.try_clone().ok()?;
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = Arc::clone(&done);
        let thread = std::thread::Builder::new()
            .name("build-client-watch".into())
            .spawn(move || {
                use std::os::fd::AsRawFd;
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    let mut p = libc::pollfd { fd: sock.as_raw_fd(), events: libc::POLLIN, revents: 0 };
                    // SAFETY: one valid pollfd for a descriptor this thread holds.
                    let n = unsafe { libc::poll(&mut p, 1, 200) };
                    if n <= 0 {
                        continue;
                    }
                    // The client sends nothing after its request: readable
                    // with nothing to read is its end closed (portable, the
                    // Mac has no POLLRDHUP).
                    let mut b = 0u8;
                    // SAFETY: peeks at most one byte into a local.
                    let got = unsafe { libc::recv(sock.as_raw_fd(), (&raw mut b).cast(), 1, libc::MSG_PEEK | libc::MSG_DONTWAIT) };
                    if got == 0 || p.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                        crate::diag::info!("build client went away: cancelling the build");
                        cancel.cancel();
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            })
            .ok()?;
        Some(ClientWatch { done, thread: Some(thread) })
    }
}

impl Drop for ClientWatch {
    fn drop(&mut self) {
        self.done.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

struct Lines<'a> {
    w: &'a mut UnixStream,
    broken: bool,
}

impl Lines<'_> {
    fn line(&mut self, v: Value) {
        if !self.broken && http::chunk(self.w, format!("{v}\n").as_bytes()).is_err() {
            self.broken = true;
        }
    }
}

/// A regular file beneath `root` (no link followed, no `..`).
fn read_beneath(root: &context::Root, rel: &Path) -> io::Result<Vec<u8>> {
    let f = root.open_file(rel)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::from_raw_os_error(libc::EISDIR));
    }
    let mut out = Vec::new();
    io::Read::read_to_end(&mut io::Read::take(&f, build::MAX_DOCKERFILE as u64 + 1), &mut out)?;
    Ok(out)
}

/// Opens the build's context and reads its Dockerfile, and sets who the
/// build reads files as (`opts.caller`, `opts.refused`).
fn read_context(ask: &mut Ask, caller: Option<context::Caller>, state: &Path) -> Result<(PathBuf, Vec<u8>), Failed> {
    // A URL context is the engine's own folder, only the engine reads it:
    // that folder alone is read as the engine. A Dockerfile in it is found
    // beneath it, links resolved inside it; a Dockerfile named by an
    // absolute path, named contexts and every other path are read as the
    // caller.
    let engine_made = ask.engine_context;
    let state_list = [state.to_path_buf()];
    let refused: &[PathBuf] = if engine_made { &[] } else { &state_list };
    let root = context::Root::open(&ask.context, if engine_made { None } else { caller.clone() }, refused).map_err(|e| match e {
        context::ContextError::Io(p, e) => format!("unable to prepare context: {}: {}", p.display(), go_errno(&e)),
        e => e.to_string(),
    })?;
    let root_path = root.path().to_path_buf();
    let dockerfile = match ask.dockerfile_text.take() {
        Some(t) => t.into_bytes(),
        None => {
            let absolute = ask.dockerfile.starts_with('/');
            let p = if absolute { PathBuf::from(&ask.dockerfile) } else { root_path.join(&ask.dockerfile) };
            // As a client reads a file named on its command line: by path,
            // links followed, as the user; named as given, as BuildKit
            // names it (`open Dockerfile: ...`). In the engine's own
            // folder: beneath it, links resolved inside it only, a
            // regular file only. At most the size the build takes, and one byte
            // more to say it is too big.
            let read = |p: &Path, name: &str| {
                let got = if engine_made && !absolute {
                    // Links followed only while they stay in the folder
                    // (as BuildKit reads a Dockerfile within the context).
                    let rel = p.strip_prefix(&root_path).unwrap_or(p);
                    match kiri_forge::build::resolve_in_context(&root, &rel.to_string_lossy()) {
                        Some(r) if !r.is_empty() => read_beneath(&root, Path::new(&r)),
                        Some(_) => Err(io::Error::from_raw_os_error(libc::EISDIR)),
                        None => Err(io::Error::from_raw_os_error(libc::ELOOP)),
                    }
                } else {
                    context::read_as(caller.as_ref(), p, build::MAX_DOCKERFILE as u64)
                };
                got.map_err(|e| (e.kind(), format!("failed to read dockerfile: open {name}: {}", go_errno(&e))))
            };
            match read(&p, &ask.dockerfile) {
                Ok(d) => d,
                // A missing `Dockerfile` is read as `dockerfile`.
                Err((io::ErrorKind::NotFound, m)) if p.file_name().is_some_and(|n| n == "Dockerfile") => {
                    let lower = ask.dockerfile.strip_suffix("Dockerfile").map(|d| format!("{d}dockerfile")).unwrap_or_default();
                    let d = read(&p.with_file_name("dockerfile"), &lower).map_err(|(k, m2)| if k == io::ErrorKind::NotFound { m } else { m2 })?;
                    // and named so in the progress, as BuildKit names it
                    ask.opts.dockerfile_name = "dockerfile".into();
                    d
                }
                Err((_, m)) => return Err(m.into()),
            }
        }
    };
    drop(root);
    ask.opts.caller = caller;
    ask.opts.context_is_engines = engine_made;
    ask.opts.refused = vec![state.to_path_buf()];
    Ok((root_path, dockerfile))
}

/// The engine's cap on native builds running at once
/// (`KIRI_NATIVE_BUILDS`, else [`kiri_forge::admit::default_cap`]).
fn build_slots() -> &'static kiri_forge::admit::Slots {
    static SLOTS: OnceLock<kiri_forge::admit::Slots> = OnceLock::new();
    SLOTS.get_or_init(|| {
        let cap = std::env::var("KIRI_NATIVE_BUILDS").ok().and_then(|v| v.parse().ok()).filter(|&n: &usize| n > 0).unwrap_or_else(kiri_forge::admit::default_cap);
        kiri_forge::admit::Slots::new(cap)
    })
}

/// The engine's planner: a child of this binary for each build.
fn planner() -> io::Result<Arc<kiri_forge::isolate::Planner>> {
    static PLANNER: OnceLock<Arc<kiri_forge::isolate::Planner>> = OnceLock::new();
    if let Some(p) = PLANNER.get() {
        return Ok(Arc::clone(p));
    }
    let p = kiri_forge::isolate::Planner::this_binary()?;
    Ok(Arc::clone(PLANNER.get_or_init(|| p)))
}

fn run(ask: &mut Ask, engine: &Arc<Engine>, caller: Option<context::Caller>, out: &mut Lines<'_>) -> Result<Done, Failed> {
    let began = Instant::now();
    let state = super::state_dir().map_err(|e| e.to_string())?;
    // Everything the build reads of the user's files is read with the
    // user's rights (kiri_forge::context::Root): the kernel decides, as it
    // would for a client reading them to send.
    let mut plain = Plain::new();
    // At most so many native builds at once; past it this one waits in
    // line (its client leaving still cancels it), then holds its slot to
    // the end.
    let _slot = build_slots().take(&ask.opts.cancel, &mut |running| {
        out.line(json!({"stream": format!("waiting for a build slot: {running} builds running\n")}));
    })?;
    let work = build_dir().map_err(|e| e.to_string())?.join("tmp");
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    if let Some(url) = ask.url.take() {
        let mut emit = |e: Event<'_>| {
            let text = plain.render(&e);
            if !text.is_empty() {
                out.line(json!({"stream": text}));
            }
        };
        url_context(ask, &url, &mut emit)?;
    }
    let (root_path, dockerfile) = match ask.opts.context_tree.clone() {
        // An archive's files: read through its tree, never a host path.
        // The Dockerfile comes from the tree too, `-f` taken inside it
        // even when absolute (as dockerui reads it from the context);
        // named contexts are still read as the caller.
        Some(tree) => {
            let d = match ask.dockerfile_text.take() {
                Some(t) => t.into_bytes(),
                None => tree_dockerfile(&tree, ask)?,
            };
            ask.opts.caller = caller;
            ask.opts.context_is_engines = true;
            ask.opts.refused = vec![state.to_path_buf()];
            (tree.path().to_path_buf(), d)
        }
        None => read_context(ask, caller, &state)?,
    };
    // Where the build's time goes, one log line per build ("build stages").
    kiri_forge::timing::start();
    ask.opts.work = work;
    // Every Dockerfile is read and planned first in a child of the engine
    // under the kernel's limits: one that would crash or exhaust the
    // planner fails its own build.
    ask.opts.planner = Some(planner().map_err(|e| format!("could not set up the Dockerfile planner: {e}"))?);
    let mut ports = Ports::new(Arc::clone(engine));
    ports.ssh_session = ask.ssh_session.clone();
    let cache = step_cache().map_err(|e| e.to_string())?;
    let sources = Sources(&ports, ask.opts.cancel.clone());
    let p = build::Ports { runner: &ports, store: &ports, images: &sources, cache };
    let mut warnings = Vec::new();
    let outcome = build::build(&dockerfile, &root_path, &ask.opts, p, &mut |e: Event<'_>| {
        if let Event::Warning { text } = e {
            warnings.push(text.to_owned());
            return;
        }
        let text = plain.render(&e);
        if !text.is_empty() {
            out.line(json!({"stream": text}));
        }
    });
    let rest = plain.finish();
    if !rest.is_empty() {
        out.line(json!({"stream": rest}));
    }
    if let Some(st) = kiri_forge::timing::take() {
        let ms = began.elapsed().as_millis();
        if ask.timing {
            out.line(json!({"stream": format!("build stages: {st} total={ms}ms\n")}));
        }
        crate::diag::info!("build stages", stages = st, ms = ms);
    }
    // BuildKit prints its own when it takes the build.
    if !warnings.is_empty() && !matches!(outcome, Ok(Outcome::Unsupported(_))) {
        out.line(json!({"warnings": warnings}));
    }
    match outcome {
        Ok(Outcome::Unsupported(r)) => Ok(Done::Fallback(r)),
        Ok(Outcome::Built(b)) => {
            let id = b.id.to_string();
            let _ = record_path(&id, "native");
            let cached = b.steps.iter().filter(|s| s.cached).count();
            crate::diag::info!("image built natively", tags = ask.opts.tags.join(","), steps = b.steps.len(), cached = cached, ms = began.elapsed().as_millis());
            Ok(Done::Built(id))
        }
        Err(e) => {
            let source = e.1.iter().map(|r| build::source_snippet(&dockerfile, &ask.opts.dockerfile_name, r)).collect();
            Err(Failed { message: e.0, source })
        }
    }
}

/// Base images from the engine's store and registries, and `ADD <url>`
/// fetched from the engine (buildfetch.rs), ended by the build's cancel.
struct Sources<'a>(&'a Ports, kiri_forge::ports::Cancel);

impl kiri_forge::ports::ImageSource for Sources<'_> {
    fn resolve(&self, reference: &str, platform: &kiri_forge::ports::Platform) -> Result<kiri_forge::ports::ResolvedImage, kiri_forge::ports::Error> {
        self.0.resolve(reference, platform)
    }

    fn fetch_config(&self, image: &kiri_forge::ports::ResolvedImage) -> Result<Vec<u8>, kiri_forge::ports::Error> {
        self.0.fetch_config(image)
    }

    fn fetch_layer(&self, image: &kiri_forge::ports::ResolvedImage, layer: &kiri_forge::ports::LayerBlob, out: &mut dyn io::Write) -> Result<(), kiri_forge::ports::Error> {
        self.0.fetch_layer(image, layer, out)
    }

    fn fetch_url(&self, url: &str, out: &mut dyn io::Write) -> Result<kiri_forge::ports::HttpReply, kiri_forge::ports::Error> {
        super::buildfetch::get(url, out, &self.1)
    }
}

// --- Build-path records ---------------------------------------------------

fn record_file(id: &str) -> io::Result<PathBuf> {
    let hex = id.strip_prefix("sha256:").filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())).ok_or_else(|| io::Error::other(format!("not an image id: {id}")))?;
    Ok(build_dir()?.join("paths").join(hex))
}

/// Writes which path built image `id`: `native` or `fallback <reason>`.
pub fn record_path(id: &str, path: &str) -> io::Result<()> {
    let f = record_file(id)?;
    if let Some(d) = f.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = f.with_extension("tmp");
    std::fs::write(&tmp, format!("{path}\n"))?;
    std::fs::rename(&tmp, &f)
}

/// `GET /kiri/build-path?image=<id>`: one line; 404 when there is no
/// record, or the image is gone.
pub fn get_path(req: &Request, engine: &Engine, w: &mut UnixStream) -> io::Result<Next> {
    let asked = req.query("image").unwrap_or_default();
    let images = engine.store.images().unwrap_or_default();
    let ids: Vec<&str> = images.iter().map(|i| i.config_digest.as_str()).collect();
    let by_name = engine.store.find(asked).ok().flatten().map(|i| i.config_digest);
    match resolve_id(asked, &ids, by_name.as_deref()).and_then(|id| record_file(&id).and_then(std::fs::read_to_string).ok()) {
        Some(text) => http::respond(w, 200, "text/plain; charset=utf-8", text.as_bytes())?,
        None => api::error(w, Error::NotFound(format!("no build-path record for {asked}")))?,
    }
    Ok(Next::KeepAlive)
}

/// The image id `asked` names among the store's `ids`: a full id, a
/// short one (`5ecd271f8a0b`, with or without `sha256:`), or a name the
/// store resolved to `by_name`.
fn resolve_id(asked: &str, ids: &[&str], by_name: Option<&str>) -> Option<String> {
    let hex = asked.strip_prefix("sha256:").unwrap_or(asked);
    if !hex.is_empty() && hex.len() <= 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        let found: Vec<&&str> = ids.iter().filter(|i| i.strip_prefix("sha256:").is_some_and(|h| h.starts_with(hex))).collect();
        if let [one] = found.as_slice() {
            return Some((**one).to_owned());
        }
    }
    by_name.filter(|id| ids.contains(id)).map(str::to_owned)
}

/// `POST /kiri/build-path {"image": id, "path": "fallback <reason>"}`: the
/// CLI's report after a build it handed to BuildKit.
pub fn post_path(req: &Request) -> Result<Value, Error> {
    let v: Value = serde_json::from_slice(&req.body).map_err(|e| Error::BadRequest(format!("invalid JSON: {e}")))?;
    let (Some(id), Some(path)) = (v["image"].as_str(), v["path"].as_str()) else {
        return Err(Error::BadRequest("image and path are required".into()));
    };
    if !path.starts_with("fallback ") || path.contains('\n') {
        return Err(Error::BadRequest("path must be one line starting with \"fallback \"".into()));
    }
    record_path(id, path).map_err(Error::Io)?;
    Ok(Value::Null)
}

// --- Reading as the calling user -------------------------------------------

/// An errno as Go prints it: lower case, no " (os error N)".
fn go_errno(e: &io::Error) -> String {
    let s = e.to_string();
    let s = s.split(" (os error ").next().unwrap_or(&s).to_owned();
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().chain(c).collect(),
        None => s,
    }
}

/// Who is at the other end of the connection: uid and gid from
/// SO_PEERCRED, and the supplementary groups as the kernel holds them,
/// never as `/etc/group` lists them.
#[cfg(target_os = "linux")]
pub(super) fn peer_cred(conn: &UnixStream) -> Option<context::Caller> {
    // SAFETY: zeroed storage for the credentials of a connected socket.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the pointers are valid and the buffer is the stated size.
    let r = unsafe { libc::getsockopt(conn.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut cred as *mut libc::ucred).cast(), &mut len) };
    if r != 0 || len as usize != std::mem::size_of::<libc::ucred>() {
        return None;
    }
    let groups = peer_groups(conn).or_else(|| proc_groups(cred.pid, cred.uid, cred.gid)).unwrap_or_default();
    Some(context::Caller { uid: cred.uid, gid: cred.gid, groups })
}

/// Who the build reads files as. On Linux the engine runs as root and a
/// client may be anyone: a connection whose peer cannot be told is
/// refused, never read with the engine's rights. Elsewhere the engine runs
/// as the user who owns it, and reads as that user.
fn known_caller(cred: Option<context::Caller>) -> Result<Option<context::Caller>, Error> {
    if cfg!(target_os = "linux") && cred.is_none() {
        return Err(Error::Unauthorized("the engine cannot tell which user asked for this build".into()));
    }
    Ok(cred)
}

/// SO_PEERGROUPS (Linux 4.13): the groups the peer had when it connected.
#[cfg(target_os = "linux")]
fn peer_groups(conn: &UnixStream) -> Option<Vec<u32>> {
    // asm-generic's value, the same on x86_64 and aarch64
    const SO_PEERGROUPS: libc::c_int = 59;
    let mut g: Vec<libc::gid_t> = vec![0; 64];
    loop {
        let mut len = (g.len() * std::mem::size_of::<libc::gid_t>()) as libc::socklen_t;
        // SAFETY: g is valid for len bytes; the kernel writes at most that.
        let r = unsafe { libc::getsockopt(conn.as_raw_fd(), libc::SOL_SOCKET, SO_PEERGROUPS, g.as_mut_ptr().cast(), &mut len) };
        let n = len as usize / std::mem::size_of::<libc::gid_t>();
        if r == 0 {
            g.truncate(n);
            return Some(g);
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::ERANGE) || n <= g.len() {
            return None;
        }
        g.resize(n, 0);
    }
}

/// The `Groups:` line of the peer's /proc status, for a kernel without
/// SO_PEERGROUPS; taken only if the process there still has the peer's
/// uid and gid (not a pid used again since).
#[cfg(target_os = "linux")]
fn proc_groups(pid: libc::pid_t, uid: u32, gid: u32) -> Option<Vec<u32>> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let field = |k: &str| text.lines().find_map(|l| l.strip_prefix(k)).map(|v| v.split_whitespace().filter_map(|n| n.parse::<u32>().ok()).collect::<Vec<_>>());
    // Uid: real effective saved fs; SO_PEERCRED has the effective ids
    if field("Uid:")?.get(1) != Some(&uid) || field("Gid:")?.get(1) != Some(&gid) {
        return None;
    }
    field("Groups:")
}

/// On macOS the engine runs as the user who started it: the kernel
/// checks its reads as that user, and nothing is switched.
#[cfg(not(target_os = "linux"))]
pub(super) fn peer_cred(_conn: &UnixStream) -> Option<context::Caller> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A build whose client cannot be told is refused on Linux; a known
    /// client is read as itself.
    #[test]
    fn an_unknown_caller_is_refused_on_linux() {
        let c = context::Caller { uid: 1000, gid: 1000, groups: vec![] };
        assert_eq!(known_caller(Some(c.clone())).unwrap().map(|c| c.uid), Some(1000));
        assert_eq!(known_caller(None).is_err(), cfg!(target_os = "linux"));
    }

    /// The client's end closed (Ctrl-C, a killed terminal) cancels the
    /// build within a poll; a client still there does not.
    #[test]
    fn a_client_that_goes_away_cancels_its_build() {
        let (server, client) = UnixStream::pair().unwrap();
        let cancel = kiri_forge::ports::Cancel::default();
        let watch = ClientWatch::start(&server, cancel.clone()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!cancel.is_cancelled());
        drop(client);
        let t = Instant::now();
        while !cancel.is_cancelled() && t.elapsed() < std::time::Duration::from_secs(2) {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(cancel.is_cancelled(), "not cancelled after the client went");
        drop(watch);
    }

    /// A client that goes away while its build waits on a URL context's
    /// download from a server that
    /// says nothing more, or one byte at a time, with nothing sent to the
    /// client meanwhile (quiet, or a silent fetch): the engine notices,
    /// closes the fetch's connection, and the build ends cancelled with
    /// nothing of the fetch left in its folder.
    #[test]
    fn a_client_that_goes_away_closes_its_builds_context_fetch() {
        use super::super::buildfetch::hostile::{self, Stall};
        for stall in [Stall::Body, Stall::Trickle] {
            let s = hostile::serve(stall, 0);
            let (server, client) = UnixStream::pair().unwrap();
            let cancel = kiri_forge::ports::Cancel::default();
            let watch = ClientWatch::start(&server, cancel.clone()).unwrap();
            let outer = private_dir(&std::env::temp_dir(), "kiri-linger-context").unwrap();
            let url = format!("http://127.0.0.1:{}/r", s.port);
            let (o2, c2) = (outer.clone(), cancel.clone());
            let build = std::thread::spawn(move || {
                let mut ask = Ask { context: o2.join("context"), ..Ask::default() };
                ask.opts.cancel = c2.clone();
                let mut text = String::new();
                let mut plain = Plain::new();
                let mut emit = |e: Event<'_>| text.push_str(&plain.render(&e));
                std::fs::create_dir(&ask.context).unwrap();
                url_context(&mut ask, &format!("{url}/ctx.tar"), &mut emit)
            });
            s.stalling();
            let gone = Instant::now();
            drop(client);
            let what = format!("URL context stalled at {stall:?}");
            let end = s.ended().unwrap_or_else(|| panic!("{what}: the fetch's connection was still open after the client went"));
            let after = end.at.saturating_duration_since(gone);
            eprintln!("{what}: closed {after:?} after the client went, reset {}", end.reset);
            assert!(end.reset, "{what}: the engine's end of the connection was left half open");
            assert!(after < std::time::Duration::from_secs(1), "{what}: closed {after:?} after the client went");
            let r = build.join().unwrap();
            assert!(r.as_ref().is_err_and(|e| e.ends_with("context canceled")), "{what}: {r:?}");
            // The context folder (with what came of the download) is its
            // caller's to remove (`build`); nothing is left beside it.
            let left: Vec<_> = walk(&outer).into_iter().filter(|p| !p.is_dir() && !p.starts_with(outer.join("context"))).collect();
            assert!(left.is_empty(), "{what}: left behind: {left:?}");
            drop(watch);
            let _ = std::fs::remove_dir_all(&outer);
        }
    }

    fn walk(p: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(p).into_iter().flatten().flatten() {
            let path = e.path();
            if path.is_dir() {
                out.extend(walk(&path));
            }
            out.push(path);
        }
        out
    }

    /// A tag with a digest is refused in moby's words (its tag
    /// sanitizing), which the client
    /// prints after "failed to solve".
    #[test]
    fn a_tag_with_a_digest_is_refused_as_moby_does() {
        let body = format!(r#"{{"context":"/","tags":["x@sha256:{}"]}}"#, "0".repeat(64));
        match parse(body.as_bytes()) {
            Err(Error::BadRequest(m)) => assert_eq!(m, "build tag cannot contain a digest"),
            Err(e) => panic!("{e:?}"),
            Ok(_) => panic!("taken"),
        }
    }

    /// `--allow` as dockerd takes it: `network.host` always, anything else
    /// only when the engine allows it, refused in BuildKit's words.
    #[test]
    fn an_entitlement_is_granted_only_when_the_engine_allows_it() {
        let asked = |e: &[&str]| e.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let engine = asked(&["network.host"]);
        assert_eq!(granted(&asked(&["network.host"]), &engine).unwrap().len(), 1);
        let e = granted(&asked(&["security.insecure"]), &engine).unwrap_err();
        assert!(format!("{e:?}").contains("granting entitlement security.insecure is not allowed by build daemon configuration"), "{e:?}");
        let engine = asked(&["network.host", "security.insecure"]);
        assert!(granted(&asked(&["security.insecure"]), &engine).unwrap().contains("security.insecure"));
        assert!(granted(&[], &engine).unwrap().is_empty());
    }

    /// fs.protected_hardlinks off, or unreadable: context binds are copies.
    #[test]
    fn context_binds_are_live_only_where_hard_links_are_protected() {
        assert!(hard_links_protected(Some("1\n")));
        if cfg!(target_os = "linux") {
            assert!(!hard_links_protected(Some("0\n")));
            assert!(!hard_links_protected(None), "not known: the safe side");
        }
    }

    #[test]
    fn a_url_context_is_an_archive_by_its_content_as_buildkit_reads_it() {
        let tar_of = |h: &mut tar::Header| {
            h.set_path("foo").unwrap();
            h.set_size(3);
            h.set_mode(0o644);
            h.set_cksum();
            let mut b = tar::Builder::new(Vec::new());
            b.append(h, &b"abc"[..]).unwrap();
            b.into_inner().unwrap()
        };
        // Plain tars of every header format, the old one with no magic too.
        for mut h in [tar::Header::new_old(), tar::Header::new_gnu(), tar::Header::new_ustar()] {
            assert_eq!(url_body(tar_of(&mut h)), Ok(None));
        }
        for compressed in [&[0x1f, 0x8b, 0x08, 0][..], b"BZh91AY", &[0xfd, b'7', b'z', b'X', b'Z', 0], &[0x28, 0xb5, 0x2f, 0xfd]] {
            assert_eq!(url_body(compressed.to_vec()), Ok(None), "{compressed:?}");
        }
        // Anything else is the Dockerfile, even bytes that only look like a
        // tar block (a zero block is the end of an archive, not one).
        assert_eq!(url_body(b"FROM scratch\n".to_vec()), Ok(Some("FROM scratch\n".into())));
        assert_eq!(url_body(vec![0; 1024]), Ok(Some("\0".repeat(1024))));
        let mut bad = tar_of(&mut tar::Header::new_ustar());
        bad[148] ^= 1;
        assert!(matches!(url_body(bad), Ok(Some(_))), "a header whose checksum fails");
    }

    #[test]
    fn an_image_is_found_by_id_short_id_or_name() {
        let a = format!("sha256:{}", "a".repeat(64));
        let b = format!("sha256:5ecd{}", "b".repeat(60));
        let ids = [a.as_str(), b.as_str()];
        assert_eq!(resolve_id(&b, &ids, None).as_deref(), Some(b.as_str()));
        assert_eq!(resolve_id("5ecd", &ids, None).as_deref(), Some(b.as_str()));
        assert_eq!(resolve_id("sha256:aaaa", &ids, None).as_deref(), Some(a.as_str()));
        assert_eq!(resolve_id("hello:native", &ids, Some(&b)).as_deref(), Some(b.as_str()));
        assert_eq!(resolve_id("gone:1", &ids, None), None);
        assert_eq!(resolve_id("hello:native", &ids, Some("sha256:other")), None);
    }

    /// The build's own choice, then KIRI_NATIVE_BUILD, then the setting.
    #[test]
    fn the_builder_is_chosen_by_flag_then_environment_then_setting() {
        let unused = || panic!("the setting is not read when something else decided");
        assert!(choose(Some(true), Some("0"), unused));
        assert!(!choose(Some(false), Some("1"), unused));
        assert!(!choose(Some(false), None, unused));
        assert!(!choose(None, Some("0"), unused));
        assert!(!choose(None, Some("off"), unused));
        assert!(choose(None, Some("1"), unused));
        assert!(choose(None, None, || true));
        assert!(!choose(None, None, || false));
        assert_eq!(asked(br#"{"context":"/w","builder":"kiri"}"#), Some(true));
        assert_eq!(asked(br#"{"context":"/w","builder":"forge"}"#), Some(true));
        assert_eq!(asked(br#"{"context":"/w","builder":"buildkit"}"#), Some(false));
        assert_eq!(asked(br#"{"context":"/w"}"#), None, "an older kiri build asks nothing");
        assert_eq!(asked(br#"{"context":"/w","builder":"other"}"#), None);
        assert_eq!(asked(b"not json"), None);
    }

    #[test]
    fn reads_the_ask() {
        let a = parse(br#"{"context":"/w/app","dockerfile":"sub/Dockerfile.dev","tags":["app"],"build_args":{"A":"1"},"labels":{"l":"v"},"target":"t","no_cache":true}"#).unwrap();
        assert_eq!(a.context, PathBuf::from("/w/app"));
        assert_eq!(a.opts.dockerfile_name, "Dockerfile.dev");
        assert_eq!(a.opts.tags, ["docker.io/library/app:latest"]);
        assert_eq!(a.opts.build_args["A"], "1");
        assert!(a.opts.no_cache);
        let f = parse(br#"{"context":"/w","no_cache_filter":["a","B"]}"#).unwrap();
        assert_eq!(f.opts.no_cache_filter, ["a", "B"]);
        assert!(parse(br#"{"context":"rel"}"#).is_err());
    }

    #[test]
    fn reads_the_build_wide_run_options() {
        use kiri_forge::ports::{Network, Ulimit};
        let a = parse(br#"{"context":"/w","network":"host","allow":["network.host"],"shm_size":134217728,"ulimits":[{"name":"nofile","soft":1062,"hard":-1}]}"#).unwrap();
        assert_eq!(a.opts.network, Network::Host);
        assert!(a.opts.entitlements.contains("network.host"));
        assert_eq!(a.opts.shm_size, 134_217_728);
        assert_eq!(a.opts.ulimits, [Ulimit { name: "nofile".into(), soft: 1062, hard: -1 }]);
        assert_eq!(parse(br#"{"context":"/w","network":"none"}"#).unwrap().opts.network, Network::None);
        assert_eq!(parse(br#"{"context":"/w"}"#).unwrap().opts.network, Network::Default);
        assert!(parse(br#"{"context":"/w","network":"bridge"}"#).is_err());
        assert!(parse(br#"{"context":"/w","ulimits":[{"name":"nofile"}]}"#).is_err());
        let a = parse(br#"{"context":"/w","build_contexts":{"s":{"url":"http://h/s.tar"}}}"#).unwrap();
        assert_eq!(a.opts.named_contexts["s"], build::NamedContext::Url("http://h/s.tar".into()));
        assert!(parse(br#"{"context":"/w","build_contexts":{"s":{"url":"file:///etc"}}}"#).is_err());
    }

    /// Kiri's builder fetches no git repository in this release: a git
    /// address as the context (every form BuildKit reads as git, whatever
    /// the build args, SOURCE_DATE_EPOCH=context too) or as a named context
    /// goes to BuildKit before anything is read; a URL that is no git
    /// address stays the engine's.
    #[test]
    fn a_git_address_as_a_context_goes_to_buildkit() {
        let gits = [
            "https://example.invalid/o/r.git",
            "http://example.invalid/o/r.git#main",
            "https://example.invalid/o/r.git#v1.0:sub/dir",
            "https://example.invalid/o/r.git?ref=main&subdir=sub",
            "http://h:8999/repo.git?tag=v0.0.2#refs/tags/v0.0.2",
            "http://h/repo.git?invalid=1",
            "git@example.invalid:o/r.git",
            "ssh://git@example.invalid/o/r.git",
            "git://example.invalid/o/r.git",
            "github.com/o/r",
        ];
        for u in gits {
            for args in [json!({}), json!({"SOURCE_DATE_EPOCH": "context"})] {
                let body = json!({"context": "/", "context_url": u, "build_args": args}).to_string();
                assert_eq!(git_fallback(body.as_bytes()), Some("a remote context"), "{u}");
            }
            let body = json!({"context": "/w", "build_contexts": {"n": {"url": u}}}).to_string();
            assert_eq!(git_fallback(body.as_bytes()), Some("--build-context"), "{u}");
            assert!(parse(body.as_bytes()).is_err(), "never a URL to download: {u}");
        }
        for u in ["http://h/ctx.tar", "https://h/Dockerfile"] {
            let body = json!({"context": "/", "context_url": u, "build_contexts": {"n": {"url": u}}}).to_string();
            assert_eq!(git_fallback(body.as_bytes()), None, "{u}");
        }
    }

    /// The engine-made context tests read as a non-root caller against a
    /// root engine: as root only. Not root, they fail loudly, unless
    /// KIRI_SKIP_ROOT_TESTS=1 says to skip them, and then they say SKIPPED:
    /// never a silent pass.
    #[cfg(target_os = "linux")]
    fn as_root_or_skip() -> bool {
        if unsafe { libc::geteuid() } == 0 {
            return true;
        }
        if std::env::var_os("KIRI_SKIP_ROOT_TESTS").is_some_and(|v| v == "1") {
            eprintln!("SKIPPED: this test needs root (a root engine read as a non-root caller); KIRI_SKIP_ROOT_TESTS=1 is set");
            return false;
        }
        panic!("this test needs root (a root engine read as a non-root caller): run it as root, or set KIRI_SKIP_ROOT_TESTS=1 to skip it");
    }

    /// A folder like a URL context's: made by the engine (root), 0700, a
    /// Dockerfile in it; beside it a root-only secret.
    #[cfg(target_os = "linux")]
    fn engine_context(name: &str) -> (PathBuf, PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;
        let root = std::env::temp_dir().join(format!("kiri-engine-ctx-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("private/context")).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(root.join("private"), std::fs::Permissions::from_mode(0o700)).unwrap();
        let secret = root.join("secret");
        std::fs::write(&secret, "root:$6$hash:19000:0:99999:7:::\n").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        (root.clone(), root.join("private/context"), secret)
    }

    #[cfg(target_os = "linux")]
    fn engine_ask(ctx: &Path, dockerfile: &str) -> Ask {
        let mut ask = parse(json!({"context": ctx, "dockerfile": dockerfile}).to_string().as_bytes()).unwrap();
        ask.engine_context = true;
        ask
    }

    #[cfg(target_os = "linux")]
    const NOBODY: context::Caller = context::Caller { uid: 4243, gid: 4243, groups: Vec::new() };

    /// `kiri build -f /etc/shadow http://host/ctx.tar` (or `-f ../..`):
    /// a Dockerfile outside the engine's folder is read as the caller, who
    /// may not read it, never as the engine.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_dockerfile_named_outside_an_engine_made_context_is_read_as_the_caller() {
        if !as_root_or_skip() {
            return;
        }
        let (root, ctx, secret) = engine_context("outside");
        let state = root.join("state");
        for df in [secret.display().to_string(), "../../secret".to_owned()] {
            let mut ask = engine_ask(&ctx, &df);
            let r = read_context(&mut ask, Some(NOBODY), &state);
            match r {
                Ok((_, d)) => panic!("{df}: read {:?}", String::from_utf8_lossy(&d)),
                Err(Failed { message, .. }) => assert!(!message.contains("root:$6$"), "{df}: {message}"),
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An engine-made context whose Dockerfile is a link to any file:
    /// the link is not followed (the folder is read beneath, no links); a
    /// plain Dockerfile in the engine's 0700 folder is read.
    #[test]
    #[cfg(target_os = "linux")]
    fn an_engine_made_contexts_dockerfile_that_is_a_link_is_not_followed() {
        if !as_root_or_skip() {
            return;
        }
        let (root, ctx, secret) = engine_context("link");
        let state = root.join("state");
        std::os::unix::fs::symlink(&secret, ctx.join("Dockerfile")).unwrap();
        let mut ask = engine_ask(&ctx, "Dockerfile");
        match read_context(&mut ask, Some(NOBODY), &state) {
            Ok((_, d)) => panic!("read through the link: {:?}", String::from_utf8_lossy(&d)),
            Err(Failed { message, .. }) => assert!(!message.contains("root:$6$"), "{message}"),
        }
        std::fs::remove_file(ctx.join("Dockerfile")).unwrap();
        std::fs::write(ctx.join("Dockerfile"), "FROM scratch\n").unwrap();
        let mut ask = engine_ask(&ctx, "Dockerfile");
        let (_, d) = read_context(&mut ask, Some(NOBODY), &state).unwrap_or_else(|f| panic!("{}", f.message));
        assert_eq!(d, b"FROM scratch\n");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A Dockerfile that is a link to another file of an engine-made
    /// context is followed there, as BuildKit follows it within the
    /// context; a link that leads out of it is resolved inside it (as the
    /// copy rules resolve one), never outside.
    #[test]
    #[cfg(target_os = "linux")]
    fn an_engine_made_contexts_dockerfile_link_is_followed_only_inside_it() {
        if !as_root_or_skip() {
            return;
        }
        let (root, ctx, secret) = engine_context("link-inside");
        let state = root.join("state");
        std::fs::create_dir_all(ctx.join("docker")).unwrap();
        std::fs::write(ctx.join("docker/real.Dockerfile"), "FROM scratch\n").unwrap();
        for target in ["docker/real.Dockerfile", "./docker/../docker/real.Dockerfile", "/docker/real.Dockerfile"] {
            let _ = std::fs::remove_file(ctx.join("Dockerfile"));
            std::os::unix::fs::symlink(target, ctx.join("Dockerfile")).unwrap();
            let mut ask = engine_ask(&ctx, "Dockerfile");
            let (_, d) = read_context(&mut ask, Some(NOBODY), &state).unwrap_or_else(|f| panic!("{target}: {}", f.message));
            assert_eq!(d, b"FROM scratch\n", "{target}");
        }
        // a link in a folder on the way, inside too
        std::os::unix::fs::symlink("docker", ctx.join("d")).unwrap();
        let mut ask = engine_ask(&ctx, "d/real.Dockerfile");
        assert_eq!(read_context(&mut ask, Some(NOBODY), &state).unwrap_or_else(|f| panic!("{}", f.message)).1, b"FROM scratch\n");
        for target in [secret.display().to_string(), "../../secret".to_owned(), "../../../../../../..".to_owned() + &secret.display().to_string()] {
            let _ = std::fs::remove_file(ctx.join("Dockerfile"));
            std::os::unix::fs::symlink(&target, ctx.join("Dockerfile")).unwrap();
            let mut ask = engine_ask(&ctx, "Dockerfile");
            match read_context(&mut ask, Some(NOBODY), &state) {
                Ok((_, d)) => panic!("{target}: read outside the context: {:?}", String::from_utf8_lossy(&d)),
                Err(Failed { message, .. }) => assert!(!message.contains("root:$6$"), "{message}"),
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `--build-context s=/root` with `COPY --from=s`: only the
    /// engine-made context is the engine's; the build keeps the real caller
    /// for named contexts and every other path.
    #[test]
    #[cfg(target_os = "linux")]
    fn an_engine_made_context_build_keeps_the_caller_for_everything_else() {
        if !as_root_or_skip() {
            return;
        }
        let (root, ctx, _) = engine_context("named");
        std::fs::write(ctx.join("Dockerfile"), "FROM scratch\nCOPY --from=s . /\n").unwrap();
        let mut ask = engine_ask(&ctx, "Dockerfile");
        read_context(&mut ask, Some(NOBODY), &root.join("state")).unwrap_or_else(|f| panic!("{}", f.message));
        assert_eq!(ask.opts.caller, Some(NOBODY), "named contexts are read as the caller");
        assert!(ask.opts.context_is_engines, "the engine's folder alone is read as the engine");
        assert_eq!(ask.opts.context_caller(), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// After an engine stopped mid-build, everything its builds made is
    /// swept before the next build: URL contexts, spools, copy bodies and
    /// downloads in `tmp`, staged binds in `binds` (detached first, as root
    /// on Linux). A link is removed as a link, never followed, and another
    /// engine's build folder is not touched.
    #[test]
    fn the_sweep_removes_everything_a_killed_build_left() {
        let base = std::env::temp_dir().join(format!("kiri-sweep-all-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (mine, other, outside) = (base.join("a/build"), base.join("b/build"), base.join("outside"));
        for d in [mine.join("tmp"), mine.join("binds"), other.join("tmp"), outside.clone()] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(outside.join("keep"), b"x").unwrap();
        let bodies = private_dir(&mine.join("tmp"), "kiri-build-bodies").unwrap();
        let mut deep = bodies.clone();
        for _ in 0..50 {
            deep = deep.join("d");
        }
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("body"), b"b").unwrap();
        std::fs::write(mine.join("tmp/kiri-epoch-download-0123"), vec![0u8; 4096]).unwrap();
        std::fs::write(mine.join("tmp/kiri-layer-spool-77"), b"spool").unwrap();
        std::os::unix::fs::symlink(&outside, mine.join("tmp/kiri-link")).unwrap();
        std::os::unix::fs::symlink(&outside, bodies.join("link")).unwrap();
        let url = private_dir(&mine.join("tmp"), "kiri-url-context").unwrap();
        std::fs::write(url.join("Dockerfile"), b"FROM scratch\n").unwrap();
        let bind = mine.join("binds/bind-00aa11bb22cc");
        std::fs::create_dir(&bind).unwrap();
        std::fs::write(mine.join("binds/bind-file0011"), b"").unwrap();
        #[cfg(target_os = "linux")]
        // SAFETY: plain calls with NUL-terminated paths.
        let mounted = unsafe { libc::geteuid() } == 0 && {
            let (from, to) = (std::ffi::CString::new(outside.to_str().unwrap()).unwrap(), std::ffi::CString::new(bind.to_str().unwrap()).unwrap());
            unsafe { libc::mount(from.as_ptr(), to.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) == 0 }
        };
        #[cfg(not(target_os = "linux"))]
        let mounted = false;
        let theirs = private_dir(&other.join("tmp"), "kiri-build-bodies").unwrap();
        sweep_build_folders(&mine);
        let left: Vec<_> = std::fs::read_dir(mine.join("tmp")).unwrap().chain(std::fs::read_dir(mine.join("binds")).unwrap()).flatten().map(|e| e.path()).collect();
        assert!(left.is_empty(), "left behind: {left:?} (bind mounted: {mounted})");
        assert_eq!(std::fs::read(outside.join("keep")).unwrap(), b"x", "a link or a bind was followed");
        assert!(theirs.exists(), "another engine's folder was swept");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A URL context lives in the engine's own build folder, and the
    /// sweep before the first build touches no other engine's folders.
    #[test]
    fn url_contexts_live_in_the_engines_folder_and_the_sweep_touches_no_other() {
        let base = std::env::temp_dir().join(format!("kiri-sweep-own-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (mine, other) = (base.join("engine-a/tmp"), base.join("engine-b/tmp"));
        std::fs::create_dir_all(&mine).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let live = private_dir(&other, "kiri-url-context").unwrap();
        let left = private_dir(&mine, "kiri-url-context").unwrap();
        assert!(left.starts_with(&mine), "{}", left.display());
        sweep_build_folders(mine.parent().unwrap());
        assert!(!left.exists(), "this engine's leftover is swept");
        assert!(live.exists(), "another engine's live context was removed");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// One HTTP answer per connection, from a thread: the bodies in turn,
    /// each with its Last-Modified when given.
    fn serve_answers(answers: Vec<(Option<&'static str>, Vec<u8>)>) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{BufRead as _, BufReader, Write as _};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}/context.tar", l.local_addr().unwrap().port());
        let t = std::thread::spawn(move || {
            for (lm, body) in answers {
                let (mut c, _) = l.accept().unwrap();
                let mut r = BufReader::new(c.try_clone().unwrap());
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    if h == "\r\n" || h.is_empty() {
                        break;
                    }
                }
                let lm = lm.map(|v| format!("Last-Modified: {v}\r\n")).unwrap_or_default();
                let _ = c.write_all(format!("HTTP/1.1 200 OK\r\nConnection: close\r\n{lm}Content-Length: {}\r\n\r\n", body.len()).as_bytes());
                let _ = c.write_all(&body);
            }
        });
        (url, t)
    }

    /// A Dockerfile past BuildKit's 16 MiB is read no further than one
    /// byte past it, from a download or from an archive's tree, so the
    /// build fails on its size (with BuildKit's text) without the whole
    /// body in memory.
    #[test]
    fn a_dockerfile_over_the_limit_is_read_only_past_the_limit() {
        let max = kiri_forge::build::MAX_DOCKERFILE;
        let big = vec![b'#'; max + (4 << 20)];
        let mut t = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(big.len() as u64);
        h.set_mode(0o644);
        t.append_data(&mut h, "Dockerfile", &big[..]).unwrap();
        let tarball = t.into_inner().unwrap();
        let (url, srv) = serve_answers(vec![(None, big.clone()), (None, tarball)]);
        let base = std::env::temp_dir().join(format!("kiri-urlbig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let mut emit = |_: Event<'_>| {};
        let mut ask = url_ask(&private_dir(&base, "kiri-url-context").unwrap(), "Dockerfile");
        url_context(&mut ask, &url, &mut emit).unwrap();
        assert_eq!(ask.dockerfile_text.as_ref().map(String::len), Some(max + 1));
        let mut ask = url_ask(&private_dir(&base, "kiri-url-context").unwrap(), "Dockerfile");
        url_context(&mut ask, &url, &mut emit).unwrap();
        let tree = ask.opts.context_tree.clone().unwrap();
        assert_eq!(tree_dockerfile(&tree, &mut ask).unwrap().len(), max + 1);
        srv.join().unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }

    fn url_ask(dir: &Path, dockerfile: &str) -> Ask {
        let mut ask = parse(json!({"context": "/", "dockerfile": dockerfile}).to_string().as_bytes()).unwrap();
        ask.context = dir.to_path_buf();
        ask
    }

    /// An archive URL context (sde/source-date-epoch-context-http-*): the
    /// download is unpacked into a tree, never onto the host as the engine;
    /// the Dockerfile is read from it by its `-f` path, `dockerfile` when
    /// `Dockerfile` is missing; the context's time is its Last-Modified,
    /// else the newest file of the archive; the download itself is gone.
    #[test]
    fn an_archive_url_context_is_unpacked_into_a_tree_with_its_time() {
        let mut t = tar::Builder::new(Vec::new());
        for (name, data, mtime) in [("sub/dockerfile", &b"FROM scratch\n"[..], 1_700_000_100u64), ("foo", &b"bar"[..], 1_700_000_302)] {
            let mut h = tar::Header::new_ustar();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(mtime);
            h.set_uid(4242);
            t.append_data(&mut h, name, data).unwrap();
        }
        let tarball = t.into_inner().unwrap();
        let (url, srv) = serve_answers(vec![(None, tarball.clone()), (Some("Tue, 14 Nov 2023 22:23:21 GMT"), tarball), (None, b"FROM scratch\n".to_vec())]);
        let base = std::env::temp_dir().join(format!("kiri-urlctx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let mut emit = |_: Event<'_>| {};
        let dir = private_dir(&base, "kiri-url-context").unwrap();
        let mut ask = url_ask(&dir, "sub/Dockerfile");
        url_context(&mut ask, &url, &mut emit).unwrap();
        let tree = ask.opts.context_tree.clone().expect("an archive is a tree");
        assert_eq!(ask.opts.context_epoch, Some(1_700_000_302));
        assert_eq!(tree_dockerfile(&tree, &mut ask).unwrap(), b"FROM scratch\n");
        assert_eq!(ask.opts.dockerfile_name, "dockerfile");
        assert_eq!(tree.lookup("foo").unwrap().uid, 4242);
        assert!(std::fs::read_dir(&dir).unwrap().flatten().all(|e| e.file_name() != "context" && e.file_name() != "foo"), "nothing of it on the host by name");
        let e = tree_dockerfile(&tree, &mut url_ask(&dir, "nope")).unwrap_err();
        assert_eq!(e, "failed to read dockerfile: open nope: no such file or directory");
        let dir = private_dir(&base, "kiri-url-context").unwrap();
        let mut ask = url_ask(&dir, "Dockerfile");
        url_context(&mut ask, &url, &mut emit).unwrap();
        assert_eq!(ask.opts.context_epoch, Some(1_700_000_601), "Last-Modified first");
        // Not an archive: the Dockerfile, with the Last-Modified it had (none).
        let dir = private_dir(&base, "kiri-url-context").unwrap();
        let mut ask = url_ask(&dir, "Dockerfile");
        url_context(&mut ask, &url, &mut emit).unwrap();
        assert!(ask.opts.context_tree.is_none());
        assert_eq!((ask.dockerfile_text.as_deref(), ask.opts.context_epoch), (Some("FROM scratch\n"), None));
        srv.join().unwrap();
        // A URL context left by a build that stopped is swept.
        std::fs::create_dir_all(base.join("tmp")).unwrap();
        let left = private_dir(&base.join("tmp"), "kiri-url-context").unwrap();
        sweep_build_folders(&base);
        assert!(!left.exists());
        let _ = std::fs::remove_dir_all(&base);
    }
}
