//! Builds: BuildKit's history of `docker build`s on Kiri, for the window's
//! Builds view, read through `docker buildx history` (ls, inspect, logs).
//!
//! Only builders whose BuildKit container already exists on Kiri's engine
//! are asked: asking any other would make buildx create one (and pull
//! moby/buildkit). Asking a stopped one starts it, which wakes the VM, so
//! the window asks only while the Builds view is open.

use std::collections::HashMap;
use std::io;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use crate::flavor::{CONTEXT, Name};

/// Kiri's BuildKit builder, a docker-container one on Kiri's context.
pub const BUILDER: Name = Name("kiri-build", "kiri-dev-build");

#[cfg(unix)]
fn kiri_host() -> io::Result<String> {
    Ok(format!("unix://{}", crate::client::socket()?.display()))
}

#[cfg(windows)]
fn kiri_host() -> io::Result<String> {
    Ok(format!("npipe://{}", crate::client::pipe().replace('\\', "/")))
}

fn buildx_command(args: &[&str]) -> io::Result<Command> {
    let docker = crate::client::docker_cli().ok_or_else(|| io::Error::other("no docker CLI found (Kiri.app bundles one)"))?;
    let host = kiri_host()?;
    let mut cmd = Command::new(docker);
    // No console window flashing up from Kiri's window on Windows.
    #[cfg(windows)]
    std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);
    // Clear DOCKER_CONTEXT and point DOCKER_HOST at Kiri's socket/pipe so the
    // implicit "default" builder (used by `docker compose build`) resolves to
    // Kiri's engine while named builders on Kiri's context still work.
    cmd.env_remove("DOCKER_CONTEXT").env("DOCKER_HOST", host).arg("buildx").args(args).stdin(Stdio::null());
    Ok(cmd)
}

fn buildx(args: &[&str]) -> io::Result<(String, String)> {
    let out = buildx_command(args)?.output()?;
    let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned());
    if !out.status.success() {
        let msg = stderr.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("buildx failed").trim_start_matches("ERROR: ").to_owned();
        return Err(io::Error::other(msg));
    }
    Ok((stdout, stderr))
}

/// What `buildx` prints to stderr within `limit`, then the command and the
/// plugin it started are stopped. `history logs` on a running build follows
/// it until it ends: waiting for that left the steps unshown and, with the
/// window asking again every 2 s, a reader piling up per ask (#923).
fn buildx_stderr_for(args: &[&str], limit: std::time::Duration) -> io::Result<String> {
    stderr_for(buildx_command(args)?, limit)
}

fn stderr_for(mut cmd: Command, limit: std::time::Duration) -> io::Result<String> {
    cmd.stdout(Stdio::null()).stderr(Stdio::piped());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    let mut child = cmd.spawn()?;
    let mut err = child.stderr.take().ok_or_else(|| io::Error::other("no stderr"))?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = io::Read::read_to_end(&mut err, &mut b);
        let _ = tx.send(b);
    });
    let until = std::time::Instant::now() + limit;
    while child.try_wait()?.is_none() {
        if std::time::Instant::now() >= until {
            kill_tree(&mut child);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    // The tree is gone, so the pipe closes; the wait only covers a straggler.
    let b = rx.recv_timeout(std::time::Duration::from_secs(1)).unwrap_or_default();
    Ok(String::from_utf8_lossy(&b).into_owned())
}

/// Kills `child` and what it started: docker runs buildx as a child of its
/// own. As ui/compose.rs's, which the Windows build of this file can't reach.
fn kill_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: a plain signal to the group this child leads (`process_group(0)`).
        unsafe {
            libc::killpg(pid, libc::SIGKILL);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        let _ = Command::new("taskkill").args(["/F", "/T", "/PID", &child.id().to_string()]).creation_flags(0x0800_0000).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Every JSON value in `s`, whether one per line or run together.
fn values(s: &str) -> Vec<Value> {
    serde_json::Deserializer::from_str(s).into_iter::<Value>().map_while(Result::ok).collect()
}

fn endpoint_is_kiri(endpoint: Option<&str>, kiri_context: &str, kiri_host: &str) -> bool {
    let Some(ep) = endpoint.filter(|s| !s.is_empty()) else { return false };
    if ep == kiri_context || ep == "default" || ep == kiri_host {
        return true;
    }
    if kiri_host.get(..8).is_some_and(|s| s.eq_ignore_ascii_case("npipe://")) && ep.get(..8).is_some_and(|s| s.eq_ignore_ascii_case("npipe://")) {
        return ep.replace('\\', "/").eq_ignore_ascii_case(&kiri_host.replace('\\', "/"));
    }
    false
}

fn builders_from(buildx_ls: &[Value], containers: &Value, kiri_context: &str, kiri_host: &str) -> Vec<String> {
    let have: Vec<String> = containers
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|c| c["Names"].as_array().into_iter().flatten().filter_map(|n| n.as_str().map(|n| n.trim_start_matches('/').to_owned())))
        .collect();
    let mut found = Vec::new();
    for b in buildx_ls {
        if b["Driver"] != "docker-container" {
            continue;
        }
        let on_kiri = b["Nodes"].as_array().into_iter().flatten().any(|n| {
            endpoint_is_kiri(n["Endpoint"].as_str(), kiri_context, kiri_host)
                && n["Name"].as_str().is_some_and(|name| have.iter().any(|c| *c == format!("buildx_buildkit_{name}")))
        });
        if on_kiri
            && let Some(name) = b["Name"].as_str()
            && !name.is_empty()
            && !found.iter().any(|existing| existing == name)
        {
            found.push(name.to_owned());
        }
    }
    found
}

/// The docker-container builders on Kiri's engine whose BuildKit container exists.
/// No buildx plugin (a distribution's plain docker CLI) means no builds yet, not an error.
fn builders() -> io::Result<Vec<String>> {
    // Without the plugin, docker reads `buildx` as an unknown command or flag.
    if buildx(&["version"]).is_err() {
        return Ok(Vec::new());
    }
    let (out, _) = buildx(&["ls", "--format", "json"])?;
    let containers = crate::client::get_background("/containers/json?all=1")?;
    Ok(builders_from(&values(&out), &containers, CONTEXT.get(), &kiri_host()?))
}

/// The newest builds first, from every builder: {builder, id, name, status,
/// started, completed, steps, cached}.
pub fn list() -> io::Result<Vec<Value>> {
    let mut all = Vec::new();
    for b in builders()? {
        let Ok((out, _)) = buildx(&["history", "ls", "--builder", &b, "--format", "json"]) else { continue };
        for r in values(&out) {
            let id = r["ref"].as_str().unwrap_or_default().rsplit('/').next().unwrap_or_default().to_owned();
            all.push(json!({
                "builder": b, "id": id, "name": r["name"], "status": r["status"],
                "started": r["created_at"], "completed": r["completed_at"],
                "steps": r["total_steps"], "done": r["completed_steps"], "cached": r["cached_steps"],
            }));
        }
    }
    all.sort_by(|a, b| b["started"].as_str().cmp(&a["started"].as_str()));
    all.truncate(300);
    Ok(all)
}

fn valid_build_ref(builder: &str, id: &str) -> bool {
    !builder.is_empty() && !builder.starts_with('-') && !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// One build: the record, its steps in the order they ran (each with its
/// start, end, cached, error and output) and its warnings.
pub fn detail(builder: &str, id: &str) -> io::Result<Value> {
    if !valid_build_ref(builder, id) {
        return Err(io::Error::other("not a build"));
    }
    let (info, _) = buildx(&["history", "inspect", "--builder", builder, id, "--format", "json"])?;
    let info: Value = serde_json::from_str(&info).map_err(io::Error::other)?;
    // The raw progress stream goes to stderr. A running build's is what it
    // has printed so far: the window asks again for the rest.
    let logs_args = ["history", "logs", "--builder", builder, "--progress", "rawjson", id];
    let raw = if info["Status"] == "Running" {
        buildx_stderr_for(&logs_args, std::time::Duration::from_secs(2)).unwrap_or_default()
    } else {
        buildx(&logs_args).map(|(_, e)| e).unwrap_or_default()
    };

    let mut order: Vec<String> = Vec::new();
    let mut steps: HashMap<String, Value> = HashMap::new();
    let mut logs: HashMap<String, String> = HashMap::new();
    let mut warnings = Vec::new();
    for ev in values(&raw) {
        for v in ev["vertexes"].as_array().into_iter().flatten() {
            let Some(d) = v["digest"].as_str() else { continue };
            let s = steps.entry(d.to_owned()).or_insert_with(|| json!({"name": v["name"], "started": null, "completed": null, "cached": false, "error": null}));
            if let Some(t) = v["started"].as_str()
                && (s["started"].is_null() || s["started"].as_str() > Some(t))
            {
                s["started"] = t.into();
                if !order.iter().any(|o| o == d) {
                    order.push(d.to_owned());
                }
            }
            if let Some(t) = v["completed"].as_str()
                && s["completed"].as_str() < Some(t)
            {
                s["completed"] = t.into();
            }
            if v["cached"] == true {
                s["cached"] = true.into();
            }
            if let Some(e) = v["error"].as_str() {
                s["error"] = e.into();
            }
        }
        for l in ev["logs"].as_array().into_iter().flatten() {
            if let (Some(d), Some(data)) = (l["vertex"].as_str(), l["data"].as_str()) {
                let text = logs.entry(d.to_owned()).or_default();
                if text.len() < 256 * 1024 {
                    text.push_str(&String::from_utf8_lossy(&unbase64(data)));
                }
            }
        }
        for w in ev["warnings"].as_array().into_iter().flatten() {
            let text = |v: &Value| String::from_utf8_lossy(&unbase64(v.as_str().unwrap_or_default())).into_owned();
            warnings.push(json!({
                "text": text(&w["short"]),
                "detail": w["detail"].as_array().into_iter().flatten().map(text).collect::<Vec<_>>().join(" "),
                "url": w["url"],
                "line": w["range"][0]["start"]["line"],
            }));
        }
    }
    // Steps that never started (skipped after an error) go last, in the definition's order.
    for d in steps.keys().cloned().collect::<Vec<_>>() {
        if !order.contains(&d) {
            order.push(d);
        }
    }
    let steps: Vec<Value> = order
        .iter()
        .filter_map(|d| {
            let mut s = steps.remove(d)?;
            s["log"] = logs.remove(d).unwrap_or_default().into();
            Some(s)
        })
        .collect();
    let error = &info["Error"];
    Ok(json!({
        "builder": builder, "id": id,
        "name": info["Name"], "status": info["Status"], "started": info["StartedAt"], "completed": info["CompletedAt"],
        "context": info["Context"], "dockerfile": info["Dockerfile"],
        "total": info["NumTotalSteps"], "done": info["NumCompletedSteps"], "cached": info["NumCachedSteps"],
        "error": if error.is_null() { Value::Null } else {
            json!({"message": error["Message"], "step": error["Name"], "source": String::from_utf8_lossy(&unbase64(error["Sources"].as_str().unwrap_or_default()))})
        },
        "steps": steps, "warnings": warnings,
    }))
}

/// The image a build made, per platform: its layers (compressed size, the
/// instruction that made each, whether it came from the base image) and its
/// config, read from the manifest and config BuildKit keeps with the record.
/// Builds that made no image (cache only, or failed) have none.
pub fn layers(builder: &str, id: &str) -> io::Result<Value> {
    if !valid_build_ref(builder, id) {
        return Err(io::Error::other("not a build"));
    }
    let (info, _) = buildx(&["history", "inspect", "--builder", builder, id, "--format", "json"])?;
    let info: Value = serde_json::from_str(&info).map_err(io::Error::other)?;
    let attachment = |digest: &str| -> io::Result<Value> {
        let ok = digest.strip_prefix("sha256:").is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()));
        if !ok {
            return Err(io::Error::other("not a digest"));
        }
        let (out, _) = buildx(&["history", "inspect", "attachment", "--builder", builder, id, digest])?;
        serde_json::from_str(&out).map_err(io::Error::other)
    };
    let mut images = Vec::new();
    for a in info["Attachments"].as_array().into_iter().flatten() {
        if a["Type"] != "application/vnd.oci.image.manifest.v1+json" && a["Type"] != "application/vnd.docker.distribution.manifest.v2+json" {
            continue;
        }
        let Some(digest) = a["Digest"].as_str() else { continue };
        let Ok(manifest) = attachment(digest) else { continue };
        let config = manifest["config"]["digest"].as_str().and_then(|d| attachment(d).ok()).unwrap_or(Value::Null);
        images.push(image(&manifest, &config, a["Platform"].as_str()));
    }
    Ok(json!({"builder": builder, "id": id, "images": images, "materials": info["Materials"]}))
}

/// An image in Kiri's store, pulled or built, the same way: read from the
/// store's files, so the engine isn't asked and the VM isn't woken. Not on
/// Windows, whose store is inside WSL.
#[cfg(not(windows))]
pub fn image_layers(name: &str) -> io::Result<Value> {
    let store = kiri_image::Store::open(kiri_image::Store::default_root()?)?;
    let (i, manifest, config) = stored(&store, name)?;
    Ok(json!({"name": name, "images": [image(&manifest, &config, Some(&i.platform))], "materials": []}))
}

/// An image in the store by name or ID, with a manifest made from its layers
/// and its config.
#[cfg(not(windows))]
pub(crate) fn stored(store: &kiri_image::Store, name: &str) -> io::Result<(kiri_image::Image, Value, Value)> {
    let (i, manifest, config, _pins) = stored_pinned(store, name)?;
    Ok((i, manifest, config))
}

/// As [`stored`], keeping every blob the image references pinned until the
/// returned pins are dropped.
#[cfg(not(windows))]
pub(crate) fn stored_pinned(store: &kiri_image::Store, name: &str) -> io::Result<(kiri_image::Image, Value, Value, Vec<kiri_image::store::Pin>)> {
    let r = kiri_image::Reference::parse(name).ok();
    let id = name.trim_start_matches("sha256:");
    let (i, pins) = store
        .with_images(|images| {
            let found = images
                .iter()
                .find(|i| i.name == name || i.digest == name || r.as_ref().is_some_and(|r| i.matches(r)))
                // An untagged image goes by its ID, whole or the window's short form.
                .or_else(|| images.iter().find(|i| !id.is_empty() && i.config_digest.trim_start_matches("sha256:").starts_with(id)))
                .cloned()?;
            let pins = store.hold_image(&found);
            Some((found, pins))
        })?
        .ok_or_else(|| io::Error::other(format!("no image {name} in Kiri")))?;
    let manifest = json!({"config": {"digest": i.config_digest}, "layers": i.layers.iter().map(|l| json!({"size": l.size, "digest": l.digest})).collect::<Vec<_>>()});
    let config: Value = serde_json::from_slice(&store.read_config(&i.config_digest)?).map_err(io::Error::other)?;
    Ok((i, manifest, config, pins))
}

/// One platform's image: the config's history lines paired with the
/// manifest's layers (lines marked `empty_layer` add none).
pub(crate) fn image(manifest: &Value, config: &Value, platform: Option<&str>) -> Value {
    // BuildKit dates every history line a build writes with the image's own
    // time (cached steps too), the classic builder with each step's: a line
    // dated well before the image (an hour) came with the base image. The base's
    // lines come first, so the first newer line ends them: a COPY whose cache
    // dates from an older build is still this image's own.
    let made = crate::daemon::time::parse_unix(config["created"].as_str().unwrap_or_default());
    let mut sizes = manifest["layers"].as_array().into_iter().flatten().map(|l| (l["size"].as_u64().unwrap_or(0), l["digest"].clone()));
    let mut rows = Vec::new();
    let mut in_base = made > 0;
    for h in config["history"].as_array().into_iter().flatten() {
        let empty = h["empty_layer"] == true;
        let (size, digest) = if empty { (0, Value::Null) } else { sizes.next().unwrap_or((0, Value::Null)) };
        let created = h["created"].as_str().unwrap_or_default();
        in_base = in_base && crate::daemon::time::parse_unix(created) < made - 3600;
        rows.push(json!({
            "by": h["created_by"].as_str().unwrap_or_default().trim_end_matches(" # buildkit"),
            "size": size, "digest": digest, "empty": empty, "created": created,
            "base": in_base,
        }));
    }
    // Layers the history doesn't describe (a config without history).
    for (size, digest) in sizes {
        rows.push(json!({"by": "", "size": size, "digest": digest, "empty": false, "created": "", "base": false}));
    }
    let c = &config["config"];
    json!({
        "platform": platform.map(str::to_owned).unwrap_or_else(|| format!("{}/{}", config["os"].as_str().unwrap_or("linux"), config["architecture"].as_str().unwrap_or("?"))),
        "size": manifest["layers"].as_array().into_iter().flatten().filter_map(|l| l["size"].as_u64()).sum::<u64>(),
        // The image's ID, to find it among Kiri's images.
        "config_digest": manifest["config"]["digest"],
        "layers": rows,
        "config": {
            "cmd": c["Cmd"], "entrypoint": c["Entrypoint"], "workdir": c["WorkingDir"], "user": c["User"],
            "env": c["Env"], "ports": c["ExposedPorts"].as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()),
            "labels": c["Labels"], "volumes": c["Volumes"].as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()),
            "healthcheck": c["Healthcheck"]["Test"], "stopsignal": c["StopSignal"],
        },
    })
}

/// Removes a build from the history.
pub fn remove(builder: &str, id: &str) -> io::Result<()> {
    if !valid_build_ref(builder, id) {
        return Err(io::Error::other("not a build"));
    }
    already_gone(buildx(&["history", "rm", "--builder", builder, id]).map(|_| ()), id, || listed(builder, id))
}

/// A build another removal got to first (a second click, or several removed
/// at once) is removed. BuildKit then answers `lease "ref_<id>": not found`,
/// which showed as "Couldn't remove the build". It answers the same for a
/// build still running, which stays: so only a build `builder`'s history no
/// longer lists counts as removed, and a listing that fails keeps the error.
fn already_gone(result: io::Result<()>, id: &str, listed: impl FnOnce() -> io::Result<bool>) -> io::Result<()> {
    match result {
        Err(e) if e.to_string().contains(&format!("lease \"ref_{id}\": not found")) && matches!(listed(), Ok(false)) => Ok(()),
        r => r,
    }
}

/// Whether `builder`'s history still has build `id` (its refs end in the id).
fn listed(builder: &str, id: &str) -> io::Result<bool> {
    let (out, _) = buildx(&["history", "ls", "--builder", builder, "--format", "json"])?;
    Ok(values(&out).iter().any(|r| r["ref"].as_str().and_then(|r| r.rsplit('/').next()) == Some(id)))
}

/// Standard base64, padding optional; anything else is skipped.
fn unbase64(s: &str) -> Vec<u8> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let (mut out, mut acc, mut bits) = (Vec::with_capacity(s.len() * 3 / 4), 0u32, 0);
    for v in s.bytes().filter_map(val) {
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

/// buildx's docker-container builder `kiri-build` on the Kiri context,
/// loading every build into Kiri. Its BuildKit is the daemon's managed
/// builder (daemon/builder.rs): the daemon makes that container when buildx
/// first looks for it, starts it on demand and stops it when idle, so this
/// only registers the name with buildx and makes it the builder docker uses
/// for Kiri. Without buildx there is nothing to do: `docker build` sends
/// the classic POST /build, which the daemon runs in the same BuildKit.
/// The window calls this once the daemon answers: the builder setup skips
/// when the daemon is not up yet.
pub fn ensure_builder() {
    let _ = builder();
}

pub fn builder() -> io::Result<bool> {
    let Some(docker) = crate::client::docker_cli() else { return Ok(false) };
    // buildx talks to the daemon, and can wait on it for good: give the
    // daemon (just started by the LaunchAgent or systemd) a few seconds, else skip.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !crate::client::alive() {
        if std::time::Instant::now() > deadline {
            return Err(io::Error::other("the Kiri daemon isn't answering yet"));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    let quiet = || std::process::Stdio::null();
    if !Command::new(&docker).args(["buildx", "version"]).stdout(quiet()).stderr(quiet()).status()?.success() {
        println!("docker build: no buildx plugin here, so docker builds with Kiri's classic builder API (the same BuildKit, run by the daemon)");
        return Ok(false);
    }
    let inspect = Command::new(&docker).args(["buildx", "inspect", BUILDER.get()]).stderr(quiet()).output()?;
    let mut exists = inspect.status.success();
    // Without default-load a docker-container builder keeps what it builds
    // to itself: `docker build -t x .` builds and `docker run x` finds
    // nothing. One made without it is made again; --keep-state keeps its
    // cache volume, which the daemon's builder container reuses.
    if exists && !String::from_utf8_lossy(&inspect.stdout).contains("default-load") {
        exists = !Command::new(&docker).args(["buildx", "rm", "--keep-state", BUILDER.get()]).stdout(quiet()).stderr(quiet()).status()?.success();
    }
    if !exists {
        // buildx create takes the Kiri context's name; without that context
        // (Linux makes it only in the optional "docker uses Kiri" step) buildx
        // reads the name as a host and fails on tcp://kiri:2375.
        ensure_context(&docker)?;
        let made = Command::new(&docker)
            .args(["buildx", "create", "--name", BUILDER.get(), "--driver", "docker-container", "--driver-opt", "default-load=true", CONTEXT.get()])
            .stdout(quiet())
            .output()?;
        if !made.status.success() {
            return Err(io::Error::other(failure("docker buildx create failed", &made.stderr)));
        }
    }
    // Which builder plain `docker build` uses, Docker's or Kiri's, as
    // chosen (crate::buildwith): it needs this builder to exist.
    if let Err(e) = crate::buildwith::apply() {
        println!("docker build: could not set which builder it uses ({e})");
    }
    Ok(true)
}

/// The docker context named CONTEXT, pointing at Kiri's socket, made when
/// missing. It is only made, never made current: which engine plain docker
/// uses stays the user's choice.
/// On Windows, setup (kiri.ps1) makes the context, on the pipe.
#[cfg(not(unix))]
fn ensure_context(_docker: impl AsRef<std::ffi::OsStr>) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn ensure_context(docker: impl AsRef<std::ffi::OsStr>) -> io::Result<()> {
    let docker = docker.as_ref();
    let quiet = || std::process::Stdio::null();
    if Command::new(docker).args(["context", "inspect", CONTEXT.get()]).stdout(quiet()).stderr(quiet()).status()?.success() {
        return Ok(());
    }
    let host = format!("host=unix://{}", crate::client::socket()?.display());
    let out = Command::new(docker).args(["context", "create", CONTEXT.get(), "--description", "Kiri", "--docker", &host]).stdout(quiet()).output()?;
    if out.status.success() { Ok(()) } else { Err(io::Error::other(failure("docker context create failed", &out.stderr))) }
}

/// What failed, with the tool's own last error line when it gave one.
fn failure(what: &str, stderr: &[u8]) -> String {
    let err = String::from_utf8_lossy(stderr);
    match err.lines().map(str::trim).filter(|l| !l.is_empty()).last() {
        Some(line) => format!("{what}: {}", line.trim_start_matches("ERROR: ")),
        None => what.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A follower that never exits (a running build's `history logs`, its
    /// plugin a child of docker) gives what it printed and is gone (#923).
    #[cfg(unix)]
    #[test]
    fn a_follower_gives_what_it_printed_and_is_stopped_with_its_children() {
        let marker = format!("kiri-builds-follow-{}", std::process::id());
        let mut cmd = Command::new("sh");
        cmd.args(["-c", &format!("echo '{{\"a\":1}}' >&2; sh -c 'exec sleep 30 {marker}' 2>/dev/null & sleep 30; wait")]);
        let started = std::time::Instant::now();
        let out = stderr_for(cmd, std::time::Duration::from_millis(500)).unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(3), "{:?}", started.elapsed());
        assert_eq!(values(&out), vec![json!({"a": 1})]);
        let left = Command::new("pgrep").args(["-f", &marker]).output().unwrap();
        assert!(left.stdout.is_empty(), "left running: {}", String::from_utf8_lossy(&left.stdout));
    }

    /// A build already removed (a second click, or several removed at once)
    /// is removed: BuildKit's "lease not found" isn't an error to show. But
    /// BuildKit says the same for a build still running, which stays listed:
    /// that one, or one Kiri can't list, still says so.
    #[test]
    fn removing_a_build_already_gone_is_done() {
        let lost = r#"lease "ref_b1d0ne": not found"#;
        let answer = |e: &str| Err(io::Error::other(e.to_owned()));
        let gone = || Ok(false);
        assert!(already_gone(answer(lost), "b1d0ne", gone).is_ok(), "removed by the other click");
        assert!(already_gone(Ok(()), "b1d0ne", || -> io::Result<bool> { panic!("no listing when rm worked") }).is_ok());
        assert_eq!(already_gone(answer(lost), "b1d0ne", || Ok(true)).unwrap_err().to_string(), lost, "still running, still there");
        assert_eq!(already_gone(answer(lost), "b1d0ne", || Err(io::Error::other("no builder"))).unwrap_err().to_string(), lost);
        // Another build's lease, or any other failure, still says so.
        assert!(already_gone(answer(r#"lease "ref_0ther1": not found"#), "b1d0ne", gone).is_err());
        let ro = "write /var/lib/buildkit/runc-overlayfs/containerdmeta.db: read-only file system";
        assert_eq!(already_gone(answer(ro), "b1d0ne", gone).unwrap_err().to_string(), ro);
    }

    #[test]
    fn a_failure_carries_the_tools_last_error_line() {
        assert_eq!(failure("docker buildx create failed", b""), "docker buildx create failed");
        assert_eq!(
            failure("docker buildx create failed", b"Warning: x\nERROR: failed to initialize builder kiri-build (kiri-build0): permission denied\n\n"),
            "docker buildx create failed: failed to initialize builder kiri-build (kiri-build0): permission denied"
        );
    }

    #[test]
    fn pairs_history_with_layers() {
        let manifest = json!({"layers": [{"size": 4000, "digest": "sha256:a"}, {"size": 100, "digest": "sha256:b"}, {"size": 7, "digest": "sha256:c"}]});
        let config = json!({"architecture": "arm64", "os": "linux", "created": "2026-10-28T02:40:31+01:00", "config": {"Cmd": ["sh"]}, "history": [
            {"created": "2026-04-16T23:53:24Z", "created_by": "ADD rootfs.tar.gz / # buildkit"},
            {"created": "2026-04-16T23:53:24Z", "created_by": "CMD [\"/bin/sh\"]", "empty_layer": true},
            {"created": "2026-10-28T01:40:31Z", "created_by": "COPY /app /app # buildkit"},
            {"created": "2026-04-16T23:53:24Z", "created_by": "COPY old.sh / # buildkit"},
        ]});
        let i = image(&manifest, &config, None);
        assert_eq!(i["platform"], "linux/arm64");
        assert_eq!(i["size"], 4107);
        let l = i["layers"].as_array().unwrap();
        assert_eq!((l[0]["size"].as_u64(), l[0]["base"].as_bool(), l[0]["by"].as_str()), (Some(4000), Some(true), Some("ADD rootfs.tar.gz /")));
        assert_eq!((l[1]["empty"].as_bool(), l[1]["size"].as_u64()), (Some(true), Some(0)));
        assert_eq!((l[2]["size"].as_u64(), l[2]["base"].as_bool()), (Some(100), Some(false)));
        // Old, but after this image's own lines: still its own.
        assert_eq!(l[3]["base"].as_bool(), Some(false));
    }

    #[test]
    fn decodes_base64() {
        assert_eq!(unbase64("YnVpbGRpbmcK"), b"building\n");
        assert_eq!(unbase64("YQ=="), b"a");
        assert_eq!(unbase64("YWI="), b"ab");
    }

    #[test]
    fn reads_values_run_together_or_by_line() {
        assert_eq!(values("{\"a\":1}\n{\"a\":2}").len(), 2);
        assert_eq!(values("{\"a\":1}{\"a\":2}").len(), 2);
    }

    #[test]
    fn discovers_every_buildkit_builder_on_kiris_engine() {
        let host = "unix:///Users/alice/.kiri/run/docker.sock";
        let buildx_ls = vec![
            json!({"Name": "kiri-build", "Driver": "docker-container", "Nodes": [{"Name": "kiri-build0", "Endpoint": "kiri"}]}),
            json!({"Name": "default", "Driver": "docker-container", "Nodes": [{"Name": "default", "Endpoint": "default"}]}),
            json!({"Name": "compose-url", "Driver": "docker-container", "Nodes": [{"Name": "compose-url0", "Endpoint": host}]}),
            json!({"Name": "custom-kiri", "Driver": "docker-container", "Nodes": [{"Name": "custom-kiri0", "Endpoint": "kiri"}]}),
            // Duplicate name must appear only once, keeping first-seen order.
            json!({"Name": "kiri-build", "Driver": "docker-container", "Nodes": [{"Name": "kiri-build0", "Endpoint": "kiri"}]}),
            // Builder on Kiri without an existing BuildKit container must be skipped (never wake/create).
            json!({"Name": "not-started", "Driver": "docker-container", "Nodes": [{"Name": "not-started0", "Endpoint": "kiri"}]}),
            json!({"Name": "default-missing", "Driver": "docker-container", "Nodes": [{"Name": "default-missing0", "Endpoint": "default"}]}),
            // Non-docker-container driver must be skipped.
            json!({"Name": "plain-docker", "Driver": "docker", "Nodes": [{"Name": "default", "Endpoint": "default"}]}),
            // Foreign contexts / sockets must be rejected even if a container of that name exists.
            json!({"Name": "desktop-builder", "Driver": "docker-container", "Nodes": [{"Name": "desktop-builder0", "Endpoint": "desktop-linux"}]}),
            json!({"Name": "orb-builder", "Driver": "docker-container", "Nodes": [{"Name": "orb-builder0", "Endpoint": "orbstack"}]}),
            json!({"Name": "other-sock", "Driver": "docker-container", "Nodes": [{"Name": "other-sock0", "Endpoint": "unix:///var/run/other.sock"}]}),
        ];
        let containers = json!([
            {"Names": ["/buildx_buildkit_kiri-build0"], "Image": "moby/buildkit:buildx-stable-1"},
            {"Names": ["/buildx_buildkit_default"], "Image": "moby/buildkit:buildx-stable-1"},
            {"Names": ["/buildx_buildkit_compose-url0"], "Image": "moby/buildkit:buildx-stable-1"},
            {"Names": ["/buildx_buildkit_custom-kiri0"], "Image": "moby/buildkit:buildx-stable-1"},
            {"Names": ["/buildx_buildkit_desktop-builder0"], "Image": "moby/buildkit:buildx-stable-1"},
            {"Names": ["/buildx_buildkit_orb-builder0"], "Image": "moby/buildkit:buildx-stable-1"},
            {"Names": ["/buildx_buildkit_other-sock0"], "Image": "moby/buildkit:buildx-stable-1"},
        ]);
        let found = builders_from(&buildx_ls, &containers, "kiri", host);
        assert_eq!(found, vec!["kiri-build", "default", "compose-url", "custom-kiri"]);
    }

    #[test]
    fn matches_windows_npipe_endpoints_case_and_slash_insensitively() {
        let host = "npipe:////./pipe/kiri";
        let buildx_ls = vec![
            json!({"Name": "default", "Driver": "docker-container", "Nodes": [{"Name": "default", "Endpoint": r"NPIPE://\\.\pipe\KIRI"}]}),
            json!({"Name": "other-pipe", "Driver": "docker-container", "Nodes": [{"Name": "other-pipe0", "Endpoint": "npipe:////./pipe/docker_engine"}]}),
        ];
        let containers = json!([
            {"Names": ["/buildx_buildkit_default"]},
            {"Names": ["/buildx_buildkit_other-pipe0"]},
        ]);
        assert_eq!(builders_from(&buildx_ls, &containers, "kiri", host), vec!["default"]);
    }

    #[test]
    fn rejects_empty_or_flag_like_builder_in_detail_layers_and_remove() {
        for (builder, id) in [("", "abc123"), ("-bad", "abc123"), ("--builder", "abc123"), ("kiri-build", ""), ("kiri-build", "bad/id")] {
            assert_eq!(detail(builder, id).unwrap_err().to_string(), "not a build", "detail({builder:?}, {id:?})");
            assert_eq!(layers(builder, id).unwrap_err().to_string(), "not a build", "layers({builder:?}, {id:?})");
            assert_eq!(remove(builder, id).unwrap_err().to_string(), "not a build", "remove({builder:?}, {id:?})");
        }
    }
}

/// An image in a real store:
/// `KIRI_LIVE_IMAGE=name KIRI_DATA_DIR=... cargo test -p kiri image_layers_live -- --ignored --nocapture`.
/// Not on Windows, where kiri-win includes this file without `image_layers`.
#[cfg(not(windows))]
#[test]
#[ignore]
fn image_layers_live() {
    let name = std::env::var("KIRI_LIVE_IMAGE").unwrap();
    println!("{}", serde_json::to_string_pretty(&image_layers(&name).unwrap()).unwrap());
}
