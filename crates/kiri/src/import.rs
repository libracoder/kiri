//! Moving to Kiri from OrbStack or Docker Desktop: images, volumes and
//! containers, copied through the docker CLI so each engine speaks its own
//! API. The source is only read: `docker save` for images, `inspect` for
//! containers, and for a volume a short-lived official GNU tar helper that
//! mounts it read-only and is removed after (keeping file owners and `user.*`
//! extended attributes, which `docker cp` or a copy through the Finder would
//! lose; falling back to `docker cp` when offline without GNU tar).
//! Containers arrive stopped, with the files they wrote outside their
//! volumes: what `docker diff` lists, read path by path with `docker cp`
//! into the container's writable layer in Kiri (#410).

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use crate::client;

/// The engines Kiri can import from: docker context name, label. Docker
/// Desktop's context has the same name on Windows; OrbStack is Mac-only.
pub const SOURCES: &[(&str, &str)] = if cfg!(windows) { &[("desktop-linux", "Docker Desktop")] } else { &[("orbstack", "OrbStack"), ("desktop-linux", "Docker Desktop")] };

// kiri-win builds this file too, where docker_cli() gives a String.
#[allow(clippy::useless_conversion)]
fn docker() -> io::Result<PathBuf> {
    client::docker_cli().map(PathBuf::from).ok_or_else(|| io::Error::other("no docker CLI found (Kiri bundles one)"))
}

/// The docker CLI, run without a console window of its own (Windows opens
/// one for each console program a windowed one starts).
fn cli() -> io::Result<Command> {
    #[allow(unused_mut)]
    let mut cmd = Command::new(docker()?);
    #[cfg(windows)]
    std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);
    cmd.env_remove("DOCKER_HOST").env_remove("DOCKER_CONTEXT");
    Ok(cmd)
}

/// The name a person knows the source by: "OrbStack".
fn label(id: &str) -> &str {
    SOURCES.iter().find(|(c, _)| *c == id).map_or(id, |(_, l)| *l)
}

fn known(source: &str) -> io::Result<&'static str> {
    SOURCES.iter().find(|(c, _)| *c == source).map(|(c, _)| *c).ok_or_else(|| io::Error::other(format!("unknown source {source}")))
}

/// `docker --context ctx <args>`, its output as JSON lines.
fn json_lines(ctx: &str, args: &[&str]) -> io::Result<Vec<Value>> {
    let out = cli()?.arg("--context").arg(ctx).args(args).stderr(Stdio::piped()).output()?;
    if !out.status.success() {
        return Err(io::Error::other(String::from_utf8_lossy(&out.stderr).trim().to_owned()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| serde_json::from_str(l).ok()).collect())
}

/// [`json_lines`] for `inspect` of several: what was found, though one of
/// them is gone (docker then fails, having printed the others).
fn json_lines_found(ctx: &str, args: &[&str]) -> io::Result<Vec<Value>> {
    let out = cli()?.arg("--context").arg(ctx).args(args).stderr(Stdio::piped()).output()?;
    let found: Vec<Value> = String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    // Only "No such ..." is a container that went; any other failure is one.
    let said = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() && said.lines().any(|l| !l.trim().is_empty() && !l.contains("No such")) {
        return Err(io::Error::other(String::from_utf8_lossy(&out.stderr).trim().to_owned()));
    }
    Ok(found)
}

/// Which sources are installed and answering.
pub fn sources() -> Vec<Value> {
    SOURCES
        .iter()
        .map(|(ctx, label)| {
            json!({"id": ctx, "label": label, "running": answers(ctx)})
        })
        .collect()
}

/// A 64-hex name is an anonymous volume: not worth moving by default.
fn anonymous(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

/// What the source has, and which of it Kiri already has. Containers come
/// oldest first, the order they were made in, so one that joins another's
/// network (`container:`) comes after that one.
pub fn inventory(source: &str) -> io::Result<Value> {
    let ctx = known(source)?;
    let kiri = crate::flavor::CONTEXT.get();
    let mine = |args: &[&str], key: &str| -> Vec<String> {
        json_lines(kiri, args).unwrap_or_default().iter().filter_map(|v| v[key].as_str().map(str::to_owned)).collect()
    };
    let kiri_images = image_names(kiri).unwrap_or_default();
    let kiri_volumes = mine(&["volume", "ls", "--format", "{{json .}}"], "Name");
    let kiri_containers = mine(&["ps", "-a", "--format", "{{json .}}"], "Names");
    // An import's own reader, left by one that was stopped, is no one's.
    let rows: Vec<Value> = json_lines(ctx, &["ps", "-a", "--format", "{{json .}}"])?.into_iter().filter(|v| !v["Labels"].as_str().unwrap_or("").split(',').any(|l| l == HELPER)).collect();
    // The image each names, as created: `ps` shows an untagged one by id.
    // One removed since `ps` is left out, not the whole list.
    let ids: Vec<&str> = rows.iter().filter_map(|v| v["ID"].as_str()).collect();
    let inspected: Vec<Value> = match ids.is_empty() {
        true => Vec::new(),
        false => json_lines_found(ctx, &[&["container", "inspect", "--format", r#"{"id":{{json .Id}},"image":{{json .Config.Image}}}"#][..], &ids].concat())?,
    };
    let rows: Vec<Value> = rows.into_iter().filter(|v| inspected.iter().any(|i| i["id"].as_str().is_some_and(|id| v["ID"].as_str().is_some_and(|short| !short.is_empty() && id.starts_with(short))))).collect();
    let used: Vec<String> = inspected.iter().filter_map(|v| v["image"].as_str().map(str::to_owned)).collect();
    let mut images: Vec<Value> = Vec::new();
    for v in json_lines(ctx, &["image", "ls", "--digests", "--format", "{{json .}}"])? {
        let Some(name) = listed_name(&v) else { continue };
        // Only by digest: an image a container names so (#377), not every
        // one that lost its tag to a newer pull.
        if images.iter().any(|i| i["name"] == name.as_str()) || (name.contains('@') && !used.contains(&name)) {
            continue;
        }
        // Kiri lists an image pinned by digest by that reference, which
        // `image ls` can't show: it is asked for by name.
        let have = kiri_images.contains(&name) || (name.contains('@') && has(kiri, "image", &name));
        images.push(json!({"name": name, "size": v["Size"], "have": have}));
    }
    let names: Vec<String> = json_lines(ctx, &["volume", "ls", "--format", "{{json .}}"])?.into_iter().filter_map(|v| v["Name"].as_str().map(str::to_owned)).collect();
    // "Already in Kiri" only when Kiri's copy has files in and was finished:
    // an empty one, left by a container's create, or one a copy stopped
    // half-way in, is offered again. Without an image to look with, none is
    // taken as there.
    let both: Vec<String> = names.iter().filter(|n| kiri_volumes.contains(n)).cloned().collect();
    let states = match both.is_empty() {
        true => Vec::new(),
        false => match helper_in_kiri() {
            Ok(Some(img)) => kiri_states(&both, &img).unwrap_or_default(),
            _ => Vec::new(),
        },
    };
    let volumes: Vec<Value> = names
        .into_iter()
        .map(|name| {
            let have = states.iter().any(|(n, s)| *n == name && *s == Filled::Yes);
            json!({"name": name, "anonymous": anonymous(&name), "have": have})
        })
        .collect();
    let mut containers: Vec<Value> = rows
        .into_iter()
        .map(|v| {
            let name = v["Names"].as_str().unwrap_or("").to_owned();
            json!({"name": name, "image": v["Image"], "state": v["State"], "have": kiri_containers.contains(&name)})
        })
        .collect();
    containers.reverse();
    Ok(json!({"source": ctx, "images": images, "volumes": volumes, "containers": containers}))
}

/// An `image ls --digests` row's name: `repo:tag`, or `repo@digest` for an
/// image that is only pinned by digest (#377). Dangling images have neither.
fn listed_name(v: &Value) -> Option<String> {
    let s = |k: &str| v[k].as_str().unwrap_or("<none>").to_owned();
    match (s("Repository"), s("Tag"), s("Digest")) {
        (r, _, _) if r == "<none>" => None,
        (r, t, d) if t == "<none>" => d.starts_with("sha256:").then(|| format!("{r}@{d}")),
        (r, t, _) => Some(format!("{r}:{t}")),
    }
}

/// The tagged images `ctx` has, as `repo:tag`.
fn image_names(ctx: &str) -> io::Result<Vec<String>> {
    Ok(json_lines(ctx, &["image", "ls", "--format", "{{json .}}"])?
        .iter()
        .filter(|v| v["Repository"] != "<none>" && v["Tag"] != "<none>")
        .map(|v| format!("{}:{}", v["Repository"].as_str().unwrap_or(""), v["Tag"].as_str().unwrap_or("")))
        .collect())
}

/// Whether `ctx` has the image, container or volume `name`.
fn has(ctx: &str, kind: &str, name: &str) -> bool {
    cli().is_ok_and(|mut c| c.args(["--context", ctx, kind, "inspect", name]).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success()))
}

/// `from` piped through `retar` (in this process) into `to`, both docker
/// commands already set up; the first failure that explains the others.
fn pipe(from: Command, to: Command, from_ctx: &str, retar: impl FnOnce(&mut dyn Read, &mut dyn Write) -> io::Result<()>) -> io::Result<()> {
    pipe_with(from, to, from_ctx, false, retar)
}

/// [`pipe`]; when `allow_file_changed` is set (`--force` with GNU tar), GNU
/// tar's exit status 1 ("file changed as we read it") is accepted once the
/// tar stream itself reached its end and the writer succeeded.
fn pipe_with(mut from: Command, mut to: Command, from_ctx: &str, allow_file_changed: bool, retar: impl FnOnce(&mut dyn Read, &mut dyn Write) -> io::Result<()>) -> io::Result<()> {
    let mut from = from.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let mut out = from.stdout.take().ok_or_else(|| io::Error::other("no output from docker"))?;
    let mut to = match to.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = from.kill();
            let _ = from.wait();
            return Err(e);
        }
    };
    let mut into = to.stdin.take().ok_or_else(|| io::Error::other("no input to docker"))?;
    // Both sides' errors are read while the copy runs: a full stderr pipe
    // would stop either one, and the copy with it.
    let drain = |e: Option<std::process::ChildStderr>| {
        std::thread::spawn(move || {
            let mut said = Vec::new();
            if let Some(mut e) = e {
                let _ = e.read_to_end(&mut said);
            }
            String::from_utf8_lossy(&said).trim().to_owned()
        })
    };
    let (from_said, to_said) = (drain(from.stderr.take()), drain(to.stderr.take()));
    let copied = retar(&mut out, &mut into);
    // A copy cut short must not reach the writer's end as a clean one.
    if copied.is_err() {
        let _ = from.kill();
    }
    drop((out, into));
    let written = to.wait()?.success();
    let from_status = from.wait()?;
    let read = from_status.success() || (allow_file_changed && copied.is_ok() && from_status.code() == Some(1));
    let to_said = to_said.join().unwrap_or_default();
    let from_said = from_said.join().unwrap_or_default();
    // A writer that stopped reading breaks the reader's pipe: its reason first.
    let broke = copied.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::BrokenPipe);
    if !written && (broke || read) {
        return Err(io::Error::other(format!("kiri: {to_said}")));
    }
    // The filter's own reason first; what the reader said, if anything,
    // after it.
    if let Err(e) = copied {
        let also = if from_said.is_empty() { String::new() } else { format!(" ({from_ctx}: {from_said})") };
        return Err(io::Error::other(format!("copying from {}: {e}{also}", label(from_ctx))));
    }
    if !read && !from_said.is_empty() {
        return Err(io::Error::other(format!("{from_ctx}: {from_said}")));
    }
    if !read {
        return Err(io::Error::other(format!("{from_ctx}: the copy stopped")));
    }
    if !written {
        return Err(io::Error::other(format!("kiri: {to_said}")));
    }
    Ok(())
}

/// `docker --context src save IMAGE | docker --context kiri load`. What
/// `docker save` writes for an image pinned by digest (`repo@sha256:…`)
/// has no name, so Kiri would know it only by its id and the container
/// that names it would not find it (#377): its manifest gets the name.
pub fn image(source: &str, name: &str) -> io::Result<()> {
    let ctx = known(source)?;
    let mut save = cli()?;
    save.args(["--context", ctx, "save", name]);
    let mut load = cli()?;
    load.args(["--context", crate::flavor::CONTEXT.get(), "load", "-q"]);
    let named = name.contains('@').then_some(name);
    pipe(save, load, ctx, |from, to| retar(from, to, named))
}

/// A tar number field: octal while it fits, else GNU base-256 (a first
/// byte of 0x80, then the value big-endian), which busybox tar reads too.
fn put_number(field: &mut [u8], v: u64) {
    let digits = field.len() - 1;
    if digits * 3 >= 64 || v >> (digits * 3) == 0 {
        field.copy_from_slice(format!("{v:0digits$o}\0").as_bytes());
    } else {
        field.fill(0);
        field[0] = 0x80;
        for (i, b) in field.iter_mut().skip(1).rev().enumerate() {
            *b = (v.checked_shr(8 * i as u32).unwrap_or(0) & 0xff) as u8;
        }
    }
}

/// A tar number field as written: octal, or base-256.
fn get_number(field: &[u8]) -> Option<u64> {
    if field.first().copied()? & 0x80 != 0 {
        let val = &field[1..];
        if field[0] != 0x80 || val[..val.len().saturating_sub(8)].iter().any(|b| *b != 0) {
            return None;
        }
        return Some(val[val.len().saturating_sub(8)..].iter().fold(0u64, |n, b| n << 8 | u64::from(*b)));
    }
    let text = String::from_utf8_lossy(field.split(|c| *c == 0).next().unwrap_or_default()).trim().to_owned();
    if text.is_empty() { Some(0) } else { u64::from_str_radix(&text, 8).ok() }
}

/// A pax header's records (`LEN key=value\n`), each read by its length:
/// a value may hold anything, `" size="` too.
fn pax_records(data: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = data;
    while let Some(sp) = rest.iter().position(|b| *b == b' ') {
        let Some(len) = std::str::from_utf8(&rest[..sp]).ok().and_then(|l| l.parse::<usize>().ok()).filter(|l| *l > sp + 1 && *l <= rest.len()) else { break };
        let record = &rest[sp + 1..len];
        let record = record.strip_suffix(b"\n").unwrap_or(record);
        if let Some(eq) = record.iter().position(|b| *b == b'=') {
            out.push((String::from_utf8_lossy(&record[..eq]).into_owned(), String::from_utf8_lossy(&record[eq + 1..]).into_owned()));
        }
        rest = &rest[len..];
    }
    out
}

fn pax_record(k: &str, v: &str) -> Vec<u8> {
    let rest = k.len() + v.len() + 3;
    let mut n = rest + 1;
    while rest + n.to_string().len() != n {
        n = rest + n.to_string().len();
    }
    format!("{n} {k}={v}\n").into_bytes()
}

/// Rewrites `size` records in `data` to `new_size`, keeping every other pax
/// record's raw bytes unchanged (including binary `SCHILY.xattr.*` values).
fn rewrite_pax_size(data: &[u8], new_size: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 16);
    let mut rest = data;
    let mut replaced = false;
    while let Some(sp) = rest.iter().position(|b| *b == b' ') {
        let Some(len) = std::str::from_utf8(&rest[..sp]).ok().and_then(|l| l.parse::<usize>().ok()).filter(|l| *l > sp + 1 && *l <= rest.len()) else { break };
        let record = &rest[sp + 1..len];
        let record = record.strip_suffix(b"\n").unwrap_or(record);
        if record.iter().position(|b| *b == b'=').is_some_and(|eq| &record[..eq] == b"size") {
            out.extend_from_slice(&pax_record("size", new_size));
            replaced = true;
        } else {
            out.extend_from_slice(&rest[..len]);
        }
        rest = &rest[len..];
    }
    out.extend_from_slice(rest);
    if !replaced {
        out.extend_from_slice(&pax_record("size", new_size));
    }
    out
}

fn update_checksum(h: &mut [u8; 512]) {
    h[148..156].fill(b' ');
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

fn write_small(to: &mut impl Write, h: &[u8; 512], data: &[u8]) -> io::Result<()> {
    to.write_all(h)?;
    to.write_all(data)?;
    to.write_all(&[0u8; 512][..data.len().next_multiple_of(512) - data.len()])
}

/// Passes a tar stream from `from` to `to`, entry by entry. A pax header's
/// size, uid and gid are written into the next entry's own header as well:
/// `docker cp` puts a size of 8 GiB or more and an owner above 2097151 only
/// there, and busybox tar reads pax for names alone, so it would take a
/// big file's zeros for the archive's end and report success. With `name`,
/// each image in a `docker save` manifest.json gets that name too. The
/// stream must reach the archive's end: one cut short is an error.
fn retar(mut from: impl Read, mut to: impl Write, name: Option<&str>) -> io::Result<()> {
    let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidData, format!("tar stream: {what}"));
    let text = |b: &[u8]| String::from_utf8_lossy(b.split(|c| *c == 0).next().unwrap_or_default()).trim().to_owned();
    let cut = |what: &'static str| move |e: io::Error| if e.kind() == io::ErrorKind::UnexpectedEof { bad(&format!("cut off inside {what}")) } else { e };
    let mut h = [0u8; 512];
    // What a pax header said, for the entry after it.
    let mut pax: Vec<(String, String)> = Vec::new();
    let mut pax_bytes = 0usize;
    let mut pending_pax: Option<([u8; 512], Vec<u8>)> = None;
    loop {
        from.read_exact(&mut h).map_err(cut("a header, before the archive's end"))?;
        if h.iter().all(|b| *b == 0) {
            if let Some((px_h, px_data)) = pending_pax.take() {
                write_small(&mut to, &px_h, &px_data)?;
            }
            to.write_all(&h)?;
            io::copy(&mut from, &mut to)?;
            return to.flush();
        }
        if h[156] == b'x' {
            if let Some((px_h, px_data)) = pending_pax.take() {
                write_small(&mut to, &px_h, &px_data)?;
            }
            let size = get_number(&h[124..136]).ok_or_else(|| bad("a damaged header"))?;
            let padded = size.checked_next_multiple_of(512).ok_or_else(|| bad("a damaged header"))?;
            if size > 16 << 20 || pax_bytes.saturating_add(size as usize) > 16 << 20 {
                return Err(bad("a header or manifest.json too large"));
            }
            let mut data = vec![0u8; padded as usize];
            from.read_exact(&mut data).map_err(cut("a pax header"))?;
            data.truncate(size as usize);
            pax_bytes += data.len();
            pax.extend(pax_records(&data));
            pending_pax = Some((h, data));
            continue;
        }
        let mut changed = false;
        for (key, at) in [("size", 124..136), ("uid", 108..116), ("gid", 116..124)] {
            if let Some(v) = pax.iter().rfind(|(k, _)| k == key).and_then(|(_, v)| v.parse::<u64>().ok()) {
                put_number(&mut h[at], v);
                changed = true;
            }
        }
        let pax_path = pax.iter().rfind(|(k, _)| k == "path").map(|(_, v)| v.clone());
        let size = get_number(&h[124..136]).ok_or_else(|| bad("a damaged header"))?;
        let padded = size.checked_next_multiple_of(512).ok_or_else(|| bad("a damaged header"))?;
        let entry_path = match pax_path {
            Some(p) => p,
            None => match text(&h[345..500]) {
                prefix if &h[257..263] == b"ustar\0" && !prefix.is_empty() => format!("{prefix}/{}", text(&h[..100])),
                _ if text(&h[345..500]).is_empty() || &h[257..265] == b"ustar  \0" => text(&h[..100]),
                _ => String::new(),
            },
        };
        let manifest = name.is_some() && matches!(h[156], b'0' | 0) && entry_path.trim_start_matches("./") == "manifest.json";
        if manifest && size > 16 << 20 {
            return Err(bad("a header or manifest.json too large"));
        }
        let mut data = Vec::new();
        if manifest {
            data = vec![0u8; padded as usize];
            from.read_exact(&mut data).map_err(cut("manifest.json"))?;
            data.truncate(size as usize);
        }
        if let (true, Some(name)) = (manifest, name) {
            let mut m: Value = serde_json::from_slice(&data).map_err(|e| bad(&format!("manifest.json: {e}")))?;
            for e in m.as_array_mut().into_iter().flatten().filter_map(Value::as_object_mut) {
                let mut tags = e.get("RepoTags").and_then(Value::as_array).cloned().unwrap_or_default();
                if !tags.iter().any(|t| t == name) {
                    tags.push(name.into());
                    e.insert("RepoTags".into(), tags.into());
                }
            }
            data = serde_json::to_vec(&m).map_err(io::Error::other)?;
            put_number(&mut h[124..136], data.len() as u64);
            changed = true;
            if let Some((mut px_h, mut px_data)) = pending_pax.take() {
                let new_size = data.len().to_string();
                if pax.iter().any(|(k, v)| k == "size" && v != &new_size) {
                    px_data = rewrite_pax_size(&px_data, &new_size);
                    put_number(&mut px_h[124..136], px_data.len() as u64);
                    update_checksum(&mut px_h);
                }
                write_small(&mut to, &px_h, &px_data)?;
            }
        }
        pax.clear();
        pax_bytes = 0;
        if let Some((px_h, px_data)) = pending_pax.take() {
            write_small(&mut to, &px_h, &px_data)?;
        }
        if changed {
            update_checksum(&mut h);
        }
        if manifest {
            write_small(&mut to, &h, &data)?;
        } else {
            to.write_all(&h)?;
            if io::copy(&mut (&mut from).take(padded), &mut to)? != padded {
                return Err(bad("cut off inside a file's body"));
            }
        }
    }
}

/// Official images with `tar` and `sh`: any of these can inspect volumes or
/// unpack when offline; the GNU tar ones ([`GNU_TAR_IMAGES`]) preserve
/// extended attributes on both ends of a volume copy (#485).
const TAR_IMAGES: [&str; 4] = ["alpine", "busybox", "debian", "ubuntu"];

/// BusyBox tar (alpine, busybox) silently drops `user.*` xattrs, which is
/// where Supabase Storage keeps object metadata: reads then fail with
/// ENODATA. Both ends of a volume copy use an official GNU tar image (#485).
const GNU_TAR_IMAGES: [&str; 2] = ["debian", "ubuntu"];

/// xattrs travel as pax records: the format and `--xattrs` are both needed
/// when writing them, and `--numeric-owner` keeps raw UID/GID across
/// differing `/etc/passwd` tables. Passed as argv, so `*` is literal.
const STORE_XATTRS: [&str; 4] = ["--numeric-owner", "--format=pax", "--xattrs", "--xattrs-include=*"];

/// Only `user.*` is portable to apply on the other engine; system-defined
/// namespaces (security, trusted) are not (GNU tar's extraction default).
/// `--numeric-owner` keeps raw UID/GID across differing `/etc/passwd` tables.
const RESTORE_XATTRS: &str = "--numeric-owner --xattrs '--xattrs-include=user.*'";

/// Whether an official image name is one of [`GNU_TAR_IMAGES`]. An
/// official digest for the very same repository is checked separately in
/// [`pick_helper_matching`], so a look-alike still cannot be run (#506).
fn gnu_tar(name: &str) -> bool {
    let repo = name.rsplit_once(':').filter(|(_, tag)| !tag.contains('/')).map_or(name, |(r, _)| r);
    GNU_TAR_IMAGES.iter().any(|base| repo == *base || repo.ends_with(&format!("/{base}")))
}

/// Whether a `RepoDigests` entry shows the engine pulled the image from an
/// official repository of [`TAR_IMAGES`]: Docker Hub's, or one of its two
/// public mirrors, by digest. A name or a tag says nothing (anyone can give
/// an image one), and neither does any other registry or path.
fn official(repo_digest: &str) -> bool {
    let Some((repo, digest)) = repo_digest.split_once('@') else { return false };
    let hex = digest.strip_prefix("sha256:").unwrap_or_default();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return false;
    }
    let homes = ["", "library/", "docker.io/library/", "mirror.gcr.io/library/", "public.ecr.aws/docker/library/"];
    homes.iter().any(|home| repo.strip_prefix(home).is_some_and(|base| TAR_IMAGES.contains(&base)))
}

/// A `repo:tag` of the first of `images` (`RepoTags`, `RepoDigests`) whose
/// own record shows it was pulled under that name from an official
/// repository ([`official`]). When `only_gnu` is set, only [`GNU_TAR_IMAGES`]
/// qualify.
fn pick_helper_matching(images: &[Value], only_gnu: bool) -> Option<String> {
    let strings = |v: &Value| v.as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_owned).collect::<Vec<_>>();
    images.iter().find_map(|i| {
        let digests = strings(&i["RepoDigests"]);
        strings(&i["RepoTags"]).into_iter().find(|name| {
            let Some((repo, _)) = name.rsplit_once(':').filter(|(_, tag)| !tag.is_empty() && !tag.contains('/')) else { return false };
            (!only_gnu || gnu_tar(name)) && digests.iter().any(|d| official(d) && d.split_once('@').is_some_and(|(r, _)| r == repo))
        })
    })
}

/// Official GNU tar helper (`debian`, `ubuntu`), verified by digest (#506).
fn pick_gnu_helper(images: &[Value]) -> Option<String> {
    pick_helper_matching(images, true)
}

/// The name to run a volume helper by: an official GNU tar image when
/// present, else any official [`TAR_IMAGES`] image (for volume inspection or
/// offline fallback).
fn pick_helper(images: &[Value]) -> Option<String> {
    pick_gnu_helper(images).or_else(|| pick_helper_matching(images, false))
}

/// Kiri's image records (`RepoTags`, `RepoDigests`), read once from its API.
fn kiri_images() -> io::Result<Vec<Value>> {
    let r = client::request("GET", "/images/json", None)?;
    if !r.ok() {
        return Err(io::Error::other(format!("kiri: {}", r.error())));
    }
    Ok(r.json().as_array().cloned().unwrap_or_default())
}

/// [`pick_helper`] of the images Kiri has (GNU tar preferred, else
/// alpine/busybox).
fn helper_in_kiri() -> io::Result<Option<String>> {
    Ok(pick_helper(&kiri_images()?))
}

/// [`pick_gnu_helper`] of the images Kiri has (official debian/ubuntu only).
fn gnu_helper_in_kiri() -> io::Result<Option<String>> {
    Ok(pick_gnu_helper(&kiri_images()?))
}

/// Pull an official GNU tar image (`debian:trixie`) into `ctx`, preferring
/// public mirrors over Docker Hub and never overwriting an existing local
/// `debian:trixie` tag.
fn pull_gnu_image(ctx: &str) -> bool {
    let pull = |name: &str| {
        cli().is_ok_and(|mut c| {
            c.args(["--context", ctx, "pull", "-q", name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        })
    };
    pull("mirror.gcr.io/library/debian:trixie")
        || pull("public.ecr.aws/docker/library/debian:trixie")
        || (!has(ctx, "image", "debian:trixie") && pull("debian:trixie"))
}

/// When Kiri last failed to fetch a GNU tar helper: tried once per import,
/// not once per volume.
static PULL_FAILED: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);

/// [`gnu_helper_in_kiri`], else Debian fetched by Kiri: from a public mirror,
/// else from Docker Hub when no image of the person's is called that. When
/// offline, falls back to an official `alpine`/`busybox` already in Kiri so
/// volume import still works without xattrs (#376). Nothing is taken from
/// the source.
fn helper() -> io::Result<String> {
    if let Some(name) = gnu_helper_in_kiri()? {
        return Ok(name);
    }
    let none = || io::Error::other("Kiri needs one official GNU tar image to unpack volumes with: pull debian in Kiri (docker pull debian:trixie) and import again. A re-tagged or loaded copy does not count");
    let mut failed = PULL_FAILED.lock().unwrap_or_else(|e| e.into_inner());
    if failed.is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(60)) {
        return helper_in_kiri()?.ok_or_else(none);
    }
    let kiri = crate::flavor::CONTEXT.get();
    if pull_gnu_image(kiri)
        && let Some(name) = gnu_helper_in_kiri()?
    {
        return Ok(name);
    }
    *failed = Some(std::time::Instant::now());
    helper_in_kiri()?.ok_or_else(none)
}

/// Official GNU tar image already present on the source engine `ctx`,
/// verified by `RepoDigests` just like Kiri's helper (#506).
fn gnu_helper_in_source(ctx: &str) -> io::Result<Option<String>> {
    let rows = json_lines(ctx, &["image", "ls", "--no-trunc", "--format", "{{json .}}"])?;
    let mut ids: Vec<String> = Vec::new();
    for v in &rows {
        let repo = v["Repository"].as_str().unwrap_or("");
        let id = v["ID"].as_str().unwrap_or("");
        if !id.is_empty() && gnu_tar(repo) && !ids.iter().any(|x| x == id) {
            ids.push(id.to_owned());
        }
    }
    if ids.is_empty() {
        return Ok(None);
    }
    let mut args = vec!["image", "inspect", "--format", r#"{"RepoTags":{{json .RepoTags}},"RepoDigests":{{json .RepoDigests}}}"#];
    let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    args.extend(id_refs);
    let inspected = json_lines_found(ctx, &args)?;
    Ok(pick_gnu_helper(&inspected))
}

/// When pulling the source's GNU tar helper last failed: `(context, when)`.
static SRC_PULL_FAILED: std::sync::Mutex<Option<(String, std::time::Instant)>> = std::sync::Mutex::new(None);

/// An official GNU tar image on `ctx`, pulled if needed and verified by
/// `RepoDigests` (#485, #506). Returns `None` when offline or unable to pull,
/// so volume copy falls back to `docker cp` instead of failing (#376).
fn source_gnu_helper(ctx: &str) -> io::Result<Option<String>> {
    if let Some(name) = gnu_helper_in_source(ctx)? {
        return Ok(Some(name));
    }
    let mut failed = SRC_PULL_FAILED.lock().unwrap_or_else(|e| e.into_inner());
    if failed.as_ref().is_some_and(|(c, t)| c == ctx && t.elapsed() < std::time::Duration::from_secs(60)) {
        return Ok(None);
    }
    if pull_gnu_image(ctx)
        && let Some(name) = gnu_helper_in_source(ctx)?
    {
        return Ok(Some(name));
    }
    *failed = Some((ctx.to_owned(), std::time::Instant::now()));
    Ok(None)
}

/// The label on the containers an import makes for itself.
const HELPER: &str = "dev.kiri.import-helper=1";

/// In a Kiri volume while a copy fills it; gone once the copy is whole.
const UNFINISHED: &str = ".kiri-import-unfinished";

/// What a Kiri volume holds, for an import.
#[derive(Debug, PartialEq, Clone, Copy)]
enum Filled {
    /// Nothing: a copy may go in.
    No,
    /// Files from a copy that did not finish: emptied and copied again.
    Unfinished,
    /// Files, there to stay.
    Yes,
}

/// How full each of `names`, volumes Kiri has, is: one helper mounts them all
/// read-only and says which have files in and which a copy left unfinished.
fn kiri_states(names: &[String], img: &str) -> io::Result<Vec<(String, Filled)>> {
    let mut cmd = cli()?;
    cmd.args(["--context", crate::flavor::CONTEXT.get(), "run", "--rm", "--network", "none", "--label", HELPER]);
    for (i, n) in names.iter().enumerate() {
        cmd.arg("-v").arg(format!("{n}:/v/{i}:ro"));
    }
    let script = format!(r#"for d in /v/*; do if [ -e "$d/{UNFINISHED}" ]; then echo "${{d#/v/}} u"; elif [ -n "$(ls -A "$d")" ]; then echo "${{d#/v/}} y"; fi; done; true"#);
    let out = cmd.args(["--pull", "never", "--entrypoint", "sh", img, "-c", &script]).stderr(Stdio::piped()).output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!("kiri: {}", String::from_utf8_lossy(&out.stderr).trim())));
    }
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    Ok(names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let state = said.lines().find_map(|l| l.strip_prefix(&format!("{i} "))).map_or(Filled::No, |s| if s == "u" { Filled::Unfinished } else { Filled::Yes });
            (n.clone(), state)
        })
        .collect())
}

/// The containers running (or restarting) on `ctx` with the volume `name`.
fn users(ctx: &str, name: &str) -> io::Result<Vec<String>> {
    let users = json_lines(ctx, &["ps", "--filter", &format!("volume={name}"), "--filter", "status=running", "--filter", "status=restarting", "--format", "{{json .Names}}"])?;
    Ok(users.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
}

/// Every container Kiri has with the volume `name`, in any state (a paused
/// one, one waiting on its restart policy, a stopped one all write to it
/// again): (name, whether it is an import's own helper).
fn mounting(ctx: &str, name: &str) -> io::Result<Vec<(String, bool)>> {
    let rows = json_lines(ctx, &["ps", "-a", "--filter", &format!("volume={name}"), "--format", r#"{"name":{{json .Names}},"helper":{{json (.Label "dev.kiri.import-helper")}}}"#])?;
    Ok(rows.iter().filter_map(|v| Some((v["name"].as_str()?.to_owned(), v["helper"] == "1"))).collect())
}

/// Why a volume a copy left unfinished in Kiri is not emptied while
/// containers there have it: what they wrote in it since would go.
fn in_use_in_kiri(name: &str, users: &[(String, bool)]) -> Option<String> {
    if users.is_empty() {
        return None;
    }
    let theirs: Vec<&str> = users.iter().filter(|(_, helper)| !helper).map(|(n, _)| n.as_str()).collect();
    if theirs.is_empty() {
        return Some(format!("another import of {name} is running in Kiri: let it finish, then import again if it did not"));
    }
    let them = if theirs.len() == 1 { "it" } else { "them" };
    Some(format!(
        "{name} holds an unfinished copy in Kiri, and Kiri has {} using it: importing it again would replace what is in it. Remove {them} in Kiri (or remove the volume in Kiri) and import again; importing a container again brings its volumes first",
        theirs.join(", ")
    ))
}

/// Why a volume is not copied while `users` run with it on the source
/// (#345): the copy would be a snapshot taken mid-write. The window has no
/// --force, so stopping them comes first.
fn in_use(name: &str, label: &str, users: &[String]) -> Option<String> {
    let them = if users.len() == 1 { "it" } else { "them" };
    (!users.is_empty()).then(|| {
        format!(
            "{name} is in use by {}, running on {label}: a copy taken now can be cut off mid-write. Stop {them} there and import again for an exact copy (in a terminal, kiri import --force copies it anyway)",
            users.join(", ")
        )
    })
}

/// A volume's files, owners kept.
pub fn volume(source: &str, name: &str) -> io::Result<()> {
    volume_with(source, name, false)
}

/// [`volume`]; `force` copies it even while a running container on the
/// source uses it. A volume Kiri already has files in is left as it is;
/// one a copy left unfinished is emptied and copied again.
pub fn volume_with(source: &str, name: &str, force: bool) -> io::Result<()> {
    let ctx = known(source)?;
    let kiri = crate::flavor::CONTEXT.get();
    // Reading it below would make it on the source.
    if !has(ctx, "volume", name) {
        return Err(io::Error::other(format!("{ctx}: no such volume: {name}")));
    }
    let there = has(kiri, "volume", name);
    let already = || io::Error::new(io::ErrorKind::AlreadyExists, format!("Kiri already has {name} with files in it, and it is left as it is"));
    // Asked first with an image Kiri has, before anything is fetched.
    let kiri_img = helper_in_kiri()?;
    let mut state = match (&kiri_img, there) {
        (_, false) => Some(Filled::No),
        (Some(img), true) => Some(kiri_states(&[name.to_owned()], img)?[0].1),
        (None, true) => None,
    };
    if state == Some(Filled::Yes) {
        return Err(already());
    }
    if !force && let Some(why) = in_use(name, label(ctx), &users(ctx, name)?) {
        return Err(io::Error::other(why));
    }
    let img = match kiri_img {
        Some(img) if gnu_tar(&img) => img,
        _ => helper()?,
    };
    if state.is_none() {
        state = Some(kiri_states(&[name.to_owned()], &img)?[0].1);
    }
    if state == Some(Filled::Yes) {
        return Err(already());
    }
    // Emptying it is safe only while no container in Kiri has it, in any
    // state; --force is about the source and does not change that. A helper
    // of this import that looked into it may take a moment to go.
    if state == Some(Filled::Unfinished) {
        let mut users = mounting(kiri, name)?;
        for _ in 0..10 {
            if users.is_empty() || users.iter().any(|(_, helper)| !helper) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
            users = mounting(kiri, name)?;
        }
        if let Some(why) = in_use_in_kiri(name, &users) {
            return Err(io::Error::other(why));
        }
    }
    let src_gnu = if gnu_tar(&img) { source_gnu_helper(ctx)? } else { None };
    let reader = format!("kiri-import-{name}");
    let leftover = json_lines(ctx, &["inspect", "--type", "container", "--format", "{{json .Config.Labels}}", &reader]).unwrap_or_default();
    if leftover.first().is_some_and(|l| l["dev.kiri.import-helper"] == "1") {
        let _ = cli()?.args(["--context", ctx, "rm", "-fv", &reader]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
    let copied = if let Some(src_img) = src_gnu {
        // GNU tar in an official helper on the source reads the volume
        // read-only (`volume-nocopy`: no image files go in) and puts numeric
        // owners and `user.*` xattrs in the stream; `docker cp` leaves xattrs
        // out (#485).
        let mount = format!("type=volume,src={name},dst=/from,readonly,volume-nocopy");
        let mut read = cli()?;
        read.args(volume_reader_args(ctx, &reader, &mount, &src_img));
        let r = copy_volume(read, ctx, name, &img, force);
        if r.is_err() {
            let _ = cli()?.args(["--context", ctx, "rm", "-fv", &reader]).stdout(Stdio::null()).stderr(Stdio::null()).status();
        }
        r
    } else {
        // Offline / no official GNU tar helper on both engines: fall back to
        // a stopped reader + `docker cp` so volume import still works (#376)
        // without running any unverified image on the source (#506).
        eprintln!("kiri: importing volume {name} without extended attributes (no official Debian or Ubuntu image available on both engines)");
        let names = image_names(ctx)?;
        let reader_image = match names.first() {
            Some(n) => n.clone(),
            None => json_lines(ctx, &["image", "ls", "--format", "{{json .ID}}"])?
                .first()
                .and_then(|v| v.as_str().map(str::to_owned))
                .ok_or_else(|| io::Error::other(format!("{ctx} has no image to read volumes through; pull any image there and import again")))?,
        };
        // At a path no image can have a VOLUME of its own at or under.
        use std::hash::BuildHasher;
        let at = format!("/kiri-import-{:016x}", std::collections::hash_map::RandomState::new().hash_one(name));
        let mount = format!("type=volume,src={name},dst={at},readonly,volume-nocopy");
        let made = cli()?
            .args(["--context", ctx, "create", "--name", &reader, "--pull", "never", "--network", "none", "--label", HELPER, "--entrypoint", &at, "--mount", &mount, &reader_image])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()?;
        if !made.status.success() {
            return Err(io::Error::other(format!("{ctx}: {}", String::from_utf8_lossy(&made.stderr).trim())));
        }
        let mut read = cli()?;
        read.args(["--context", ctx, "cp", &format!("{reader}:{at}/."), "-"]);
        let r = copy_volume(read, ctx, name, &img, false);
        let _ = cli()?.args(["--context", ctx, "rm", "-v", &reader]).stdout(Stdio::null()).stderr(Stdio::null()).status();
        r
    };
    copied.map_err(|e| io::Error::other(format!("{e}; {name} is unfinished in Kiri: the next import empties it and copies it again, replacing what is in it then")))
}

/// GNU tar in an official helper on the source, streaming the volume with
/// numeric owners and xattrs. `--entrypoint tar` guarantees the image's own
/// entrypoint never runs instead of `tar`.
fn volume_reader_args<'a>(ctx: &'a str, reader: &'a str, mount: &'a str, img: &'a str) -> Vec<&'a str> {
    let mut args = vec![
        "--context",
        ctx,
        "run",
        "--rm",
        "--name",
        reader,
        "--network",
        "none",
        "--label",
        HELPER,
        "--pull",
        "never",
        "--mount",
        mount,
        "--entrypoint",
        "tar",
        img,
    ];
    args.extend(STORE_XATTRS);
    args.extend(["-C", "/from", "-cf", "-", "."]);
    args
}

/// Shell script run in Kiri's helper container to clear an unfinished copy,
/// mark the volume unfinished, and unpack the tar stream from stdin.
fn restore_script(with_gnu_tar: bool) -> String {
    let flags = if with_gnu_tar { format!(" {RESTORE_XATTRS}") } else { String::new() };
    format!(
        r#"set -e; cd /to; if [ -e {m} ]; then find . -mindepth 1 -maxdepth 1 ! -name {m} -exec rm -rf -- {{}} + || true; for f in .[!.]* ..?* *; do if [ "$f" != {m} ] && {{ [ -e "$f" ] || [ -L "$f" ]; }}; then echo "could not empty the volume: $f is left" >&2; exit 1; fi; done; fi; touch {m}; tar{flags} -xpf -"#,
        m = UNFINISHED
    )
}

/// A tar stream out of the reader on the source, through [`retar`], untarred
/// into the volume by a helper on Kiri that removes itself. The helper marks
/// the volume unfinished first (emptying what an unfinished copy left), and
/// the mark goes only once every part of the copy succeeded.
fn copy_volume(read: Command, ctx: &str, name: &str, img: &str, allow_file_changed: bool) -> io::Result<()> {
    let kiri = crate::flavor::CONTEXT.get();
    let dst_mount = format!("{name}:/to");
    let mut write = cli()?;
    // Emptied in one pass, all but the mark (a folder by that name counts as
    // it); anything still there after, hidden names too, stops the copy with
    // the mark left on.
    let script = restore_script(gnu_tar(img));
    write.args(["--context", kiri, "run", "--rm", "-i", "--network", "none", "--label", HELPER, "-v", &dst_mount, "--pull", "never", "--entrypoint", "sh", img, "-c", &script]);
    pipe_with(read, write, ctx, allow_file_changed, |from, to| retar(from, to, None))?;
    let done = cli()?.args(["--context", kiri, "run", "--rm", "--network", "none", "--label", HELPER, "-v", &dst_mount, "--pull", "never", "--entrypoint", "rm", img, "-rf", "--", &format!("/to/{UNFINISHED}")]).stdout(Stdio::null()).stderr(Stdio::piped()).output()?;
    if !done.status.success() {
        return Err(io::Error::other(format!("kiri: {}", String::from_utf8_lossy(&done.stderr).trim())));
    }
    Ok(())
}

/// The container, made again in Kiri from the source's `inspect`, stopped.
/// One brought already as the network another joins, earlier in the same
/// run of the window, is done.
pub fn container(source: &str, name: &str) -> io::Result<()> {
    let mut brought = BROUGHT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(i) = brought.iter().position(|(s, n)| s == source && n == name) {
        brought.remove(i);
        if has(crate::flavor::CONTEXT.get(), "container", name) {
            return Ok(());
        }
    }
    drop(brought);
    container_with(source, name, false, &[])
}

/// Containers imported as the network another joins: (source, name).
static BROUGHT: std::sync::Mutex<Vec<(String, String)>> = std::sync::Mutex::new(Vec::new());

/// [`container`]: its image, its volumes with their files (named and
/// anonymous, unless Kiri has them with files already; `force` as for
/// [`volume_with`]), the container whose network it joins and its own
/// networks are brought first. `joining`: the containers waiting on this
/// one for its network, so a loop stops.
pub fn container_with(source: &str, name: &str, force: bool, joining: &[&str]) -> io::Result<()> {
    let ctx = known(source)?;
    let kiri = crate::flavor::CONTEXT.get();
    if joining.contains(&name) {
        return Err(io::Error::other(format!("{name}: the containers {} join each other's network in a loop", joining.join(", "))));
    }
    let info = json_lines(ctx, &["inspect", "--type", "container", "--format", "{{json .}}", name])?.into_iter().next().ok_or_else(|| io::Error::other(format!("{name}: not found in {ctx}")))?;
    let image = info["Config"]["Image"].as_str().unwrap_or("").to_owned();
    if !has(kiri, "image", &image) {
        self::image(source, &image).map_err(|e| io::Error::other(format!("image {image}: {e}")))?;
    }
    // Else create would make them in Kiri, empty.
    for v in volumes_of(&info) {
        match volume_with(source, &v, force) {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            r => r.map_err(|e| io::Error::other(format!("volume {v}: {e}")))?,
        }
    }
    let mut mode = info["HostConfig"]["NetworkMode"].as_str().unwrap_or("default").to_owned();
    let mut networks = serde_json::Map::new();
    if let Some(target) = mode.strip_prefix("container:") {
        // The source's id for it is no name in Kiri; its own name is, once
        // it is there.
        let target = json_lines(ctx, &["inspect", "--type", "container", "--format", "{{json .Name}}", target])?
            .first()
            .and_then(|v| v.as_str().map(|n| n.trim_start_matches('/').to_owned()))
            .ok_or_else(|| io::Error::other(format!("{name}: the container whose network it joins is not in {ctx}")))?;
        if !has(kiri, "container", &target) {
            let chain: Vec<&str> = joining.iter().copied().chain([name]).collect();
            container_with(source, &target, force, &chain)?;
            BROUGHT.lock().unwrap_or_else(|e| e.into_inner()).push((source.to_owned(), target.clone()));
        }
        mode = format!("container:{target}");
    }
    for (net, ep) in info["NetworkSettings"]["Networks"].as_object().into_iter().flatten().filter(|_| !mode.starts_with("container:")) {
        if !["bridge", "host", "none", "default"].contains(&net.as_str()) {
            let _ = cli()?.args(["--context", kiri, "network", "create", net]).stdout(Stdio::null()).stderr(Stdio::null()).status();
        }
        // The source's own short ID is no name in Kiri.
        let short = info["Id"].as_str().unwrap_or("").get(..12).unwrap_or("").to_owned();
        let aliases: Vec<&Value> = ep["Aliases"].as_array().into_iter().flatten().filter(|a| a.as_str() != Some(short.as_str())).collect();
        networks.insert(net.clone(), json!({"Aliases": aliases}));
    }
    let r = client::request("POST", &format!("/containers/create?name={name}"), Some(&create_body(&info, &mode, networks.into())))?;
    if !r.ok() {
        return Err(io::Error::other(create_error(r.status, &r.error())));
    }
    if let Err(e) = writable_layer(ctx, &info, name) {
        // Without the files it wrote, the container is not the one it was:
        // it goes again, and the reason is said. Its volumes stay.
        let _ = client::request("DELETE", &format!("/containers/{name}?force=1"), None);
        return Err(io::Error::other(format!("its writable layer: {e}")));
    }
    Ok(())
}

/// The engine's own files, which each engine makes and mounts over the
/// container's for itself: never carried over.
const ENGINE_FILES: [&str; 4] = ["/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/.dockerenv"];

/// The kernel's filesystems and the engine's `/dev`, mounted in every
/// container: nothing at or under them is carried over.
const KERNEL_TREES: [&str; 3] = ["/proc", "/sys", "/dev"];

/// How many `docker cp` run at once to read the paths a layer changed.
const READERS: usize = 8;

/// A file up to this size is read ahead, in parallel, while the paths
/// before it are written; a bigger one is read when its turn comes.
const READ_AHEAD_FILE: u64 = 1 << 20;

/// What the files read ahead may hold at once, all together.
const READ_AHEAD_TOTAL: u64 = 64 << 20;

/// The container's writable layer on the source (#410): the files it wrote
/// outside its volumes, its changes to the image's files and what it
/// deleted of them, as `docker diff` lists them, become the writable layer
/// of the container just made as `name` in Kiri, before it first runs.
/// Nothing is made on the source: each path is read with `docker cp`, only
/// what changed, never the image's unchanged files, and nothing at or under
/// the container's mounts (volumes are copied as volumes, binds stay where
/// they are). A container that changed nothing costs one `docker diff`.
fn writable_layer(ctx: &str, info: &Value, name: &str) -> io::Result<()> {
    let id = info["Id"].as_str().filter(|id| !id.is_empty()).ok_or_else(|| io::Error::other("the source gave no container id"))?;
    let out = cli()?.args(["--context", ctx, "container", "diff", id]).stdin(Stdio::null()).stderr(Stdio::piped()).output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!("{ctx}: docker diff: {}", String::from_utf8_lossy(&out.stderr).trim())));
    }
    let plan = plan_layer(&parse_diff(&String::from_utf8_lossy(&out.stdout)), &mount_points(info));
    if plan.is_empty() {
        return Ok(());
    }
    let r = client::post_stream(&format!("/kiri/containers/{name}/upper"), "application/x-tar", |w| write_layer(ctx, id, &plan, w))?;
    if !r.ok() {
        return Err(io::Error::other(create_error(r.status, &r.error())));
    }
    Ok(())
}

/// `docker diff`'s lines as (kind, path): `A` added, `C` changed, `D`
/// deleted. A line that is none of these, or names a path that is not
/// absolute and plain (no `.`, `..` or empty steps), is left out.
fn parse_diff(text: &str) -> Vec<(char, String)> {
    text.lines()
        .filter_map(|l| {
            let (kind, path) = l.strip_suffix('\r').unwrap_or(l).split_once(' ')?;
            let kind = match kind {
                "A" => 'A',
                "C" => 'C',
                "D" => 'D',
                _ => return None,
            };
            let plain = path.len() > 1 && path.starts_with('/') && path[1..].split('/').all(|c| !matches!(c, "" | "." | ".."));
            plain.then(|| (kind, path.to_owned()))
        })
        .collect()
}

/// Where the container has something mounted on the source: volumes, binds
/// and tmpfs, as absolute paths without a trailing `/`.
fn mount_points(info: &Value) -> Vec<String> {
    let hc = &info["HostConfig"];
    let mut found: Vec<&str> = info["Mounts"].as_array().into_iter().flatten().filter_map(|m| m["Destination"].as_str()).collect();
    found.extend(hc["Mounts"].as_array().into_iter().flatten().filter_map(|m| m["Target"].as_str()));
    found.extend(hc["Tmpfs"].as_object().into_iter().flatten().map(|(k, _)| k.as_str()));
    let mut points: Vec<String> = Vec::new();
    for p in found {
        let clean = format!("/{}", p.split('/').filter(|c| !c.is_empty() && *c != ".").collect::<Vec<_>>().join("/"));
        if clean != "/" && !points.contains(&clean) {
            points.push(clean);
        }
    }
    points
}

/// Whether `path` is `top` or under it.
fn at_or_under(path: &str, top: &str) -> bool {
    path == top || below(path, top)
}

/// Whether `path` is under `top` (not `top` itself).
fn below(path: &str, top: &str) -> bool {
    path.strip_prefix(top).is_some_and(|rest| rest.starts_with('/'))
}

/// Paths in the order a layer lists them: each directory right before
/// what is under it.
fn path_order(a: &str, b: &str) -> std::cmp::Ordering {
    a.split('/').cmp(b.split('/'))
}

/// What of a container's writable layer is carried over, from what `docker
/// diff` lists. `docker diff` names every path the layer holds (an added
/// directory's contents too) and the directories they are in, so each is
/// read on its own; only a new directory with nothing mounted under it is
/// read whole, in one go.
#[derive(Debug, Default, PartialEq)]
struct LayerPlan {
    /// Deleted on the source: a whiteout each, unless the path is there
    /// again (a directory deleted and made again, which turns opaque).
    deleted: Vec<String>,
    /// Carried over by their own entry: a file whole, a directory with its
    /// mode, owner and time and none of what is in it, which is listed (or
    /// unchanged in the image) on its own. `/etc` changed because a file was
    /// added to it brings that file and `/etc`'s own entry, not all of `/etc`.
    entries: Vec<String>,
    /// New directories, not in the image, carried over whole.
    trees: Vec<String>,
}

impl LayerPlan {
    fn is_empty(&self) -> bool {
        self.deleted.is_empty() && self.entries.is_empty() && self.trees.is_empty()
    }
}

/// The plan for `changes` (`docker diff`'s lines) of a container with
/// `mounts`: nothing at or under a mount, the engine's own files or the
/// kernel's filesystems; a directory listed only for those is left out;
/// every directory a path is in comes too, so the layer keeps its mode
/// and owner.
fn plan_layer(changes: &[(char, String)], mounts: &[String]) -> LayerPlan {
    let left_out = |p: &str| ENGINE_FILES.contains(&p) || KERNEL_TREES.iter().copied().chain(mounts.iter().map(String::as_str)).any(|t| at_or_under(p, t));
    let mut sorted: Vec<&(char, String)> = changes.iter().collect();
    sorted.sort_by(|a, b| path_order(&a.1, &b.1));
    sorted.dedup_by(|a, b| a.1 == b.1);
    let mut plan = LayerPlan::default();
    let mut i = 0;
    while i < sorted.len() {
        let (kind, path) = (sorted[i].0, sorted[i].1.as_str());
        let end = sorted[i + 1..].iter().position(|(_, p)| !below(p, path)).map_or(sorted.len(), |n| i + 1 + n);
        let inside = &sorted[i + 1..end];
        i += 1;
        if left_out(path) {
            continue;
        }
        match kind {
            'D' => plan.deleted.push(path.to_owned()),
            'A' if !inside.is_empty() && inside.iter().all(|(k, p)| *k == 'A' && !left_out(p)) => {
                plan.trees.push(path.to_owned());
                i = end;
            }
            'C' if !inside.is_empty() && inside.iter().all(|(_, p)| left_out(p)) => {}
            _ => plan.entries.push(path.to_owned()),
        }
    }
    let mut have: std::collections::HashSet<String> = plan.deleted.iter().chain(&plan.entries).chain(&plan.trees).cloned().collect();
    let mut parents = Vec::new();
    for p in plan.deleted.iter().chain(&plan.entries).chain(&plan.trees) {
        let mut at = p.as_str();
        while let Some((parent, _)) = at.rsplit_once('/').filter(|(parent, _)| !parent.is_empty()) {
            if have.insert(parent.to_owned()) {
                parents.push(parent.to_owned());
            }
            at = parent;
        }
    }
    plan.entries.extend(parents);
    plan.entries.sort_by(|a, b| path_order(a, b));
    plan
}

/// One path the layer brings, read on its own ahead of its turn.
enum Read1 {
    /// Not there (gone since `docker diff`), or nothing a tar can hold (a socket).
    Missing,
    /// A directory's own entry.
    Dir(Vec<u8>),
    /// Anything else, whole.
    Whole(Vec<u8>),
    /// A file too big to read ahead: read when its turn comes.
    Later,
}

/// Writes the layer `plan` names as an OCI layer tar (whiteouts as `.wh.`
/// files, opaque directories with `.wh..wh..opq`), each path read from the
/// source container `id` with `docker cp`. What the writer refuses keeps
/// its error kind: `client::post_stream` then reads the daemon's reason.
fn write_layer(ctx: &str, id: &str, plan: &LayerPlan, out: &mut dyn Write) -> io::Result<()> {
    let ahead: Vec<&str> = plan.entries.iter().chain(&plan.deleted).map(String::as_str).collect();
    let mut read = read_ahead(ctx, id, &ahead)?.into_iter();
    let mut got: std::collections::HashMap<&str, Read1> = ahead.iter().map(|p| (*p, read.next().unwrap_or(Read1::Later))).collect();
    let mut steps: Vec<(&str, u8)> = plan.entries.iter().map(|p| (p.as_str(), b'e')).collect();
    steps.extend(plan.deleted.iter().map(|p| (p.as_str(), b'd')));
    steps.extend(plan.trees.iter().map(|p| (p.as_str(), b't')));
    steps.sort_by(|a, b| path_order(a.0, b.0));
    for (path, step) in steps {
        if step == b't' {
            read_paths(ctx, id, path, out, true)?;
            continue;
        }
        match (got.remove(path).unwrap_or(Read1::Later), step) {
            (Read1::Missing, b'd') => write_marker(out, &whiteout_name(path))?,
            (Read1::Missing, _) => {}
            // Deleted, and a directory there again: what the image had in it is gone.
            (Read1::Dir(bytes), b'd') => {
                out.write_all(&bytes)?;
                write_marker(out, &format!("{}/.wh..wh..opq", &path[1..]))?;
            }
            (Read1::Dir(bytes) | Read1::Whole(bytes), _) => out.write_all(&bytes)?,
            (Read1::Later, _) => read_paths(ctx, id, path, out, false)?,
        }
    }
    out.write_all(&[0u8; 1024])
}

/// The name of the whiteout that deletes `path`: `.wh.` and its name, in
/// its directory.
fn whiteout_name(path: &str) -> String {
    let (dir, base) = path.rsplit_once('/').unwrap_or(("", path));
    format!("{}.wh.{base}", if dir.is_empty() { String::new() } else { format!("{}/", &dir[1..]) })
}

/// Reads `paths` from the source container, [`READERS`] at a time: each
/// one's entry, in the order given, ready to write.
fn read_ahead(ctx: &str, id: &str, paths: &[&str]) -> io::Result<Vec<Read1>> {
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    let next = AtomicUsize::new(0);
    let held = AtomicU64::new(0);
    let failed = AtomicBool::new(false);
    let slots: Vec<std::sync::Mutex<Option<io::Result<Read1>>>> = paths.iter().map(|_| std::sync::Mutex::new(None)).collect();
    std::thread::scope(|s| {
        for _ in 0..READERS.min(paths.len()) {
            s.spawn(|| {
                while !failed.load(Ordering::Relaxed) {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(path) = paths.get(i) else { break };
                    let r = read_one(ctx, id, path, &held);
                    failed.fetch_or(r.is_err(), Ordering::Relaxed);
                    *slots[i].lock().unwrap_or_else(|e| e.into_inner()) = Some(r);
                }
            });
        }
    });
    slots.into_iter().map(|s| s.into_inner().unwrap_or_else(|e| e.into_inner()).unwrap_or(Ok(Read1::Later))).collect()
}

/// One path's own entry, read ahead: a directory's without what is in it,
/// a small file's whole; a big one is left for later, so what is read
/// ahead stays under [`READ_AHEAD_TOTAL`] (`held`).
fn read_one(ctx: &str, id: &str, path: &str, held: &std::sync::atomic::AtomicU64) -> io::Result<Read1> {
    use std::sync::atomic::Ordering;
    let mut cp = Cp::start(ctx, id, path)?;
    let entry = match read_entry(&mut cp.out) {
        Ok(Some(e)) => e,
        Ok(None) => return cp.finish().map(|_| Read1::Missing),
        Err(e) => return cp.failed(e).map(|()| Read1::Missing),
    };
    let mut bytes = Vec::new();
    write_renamed(&mut bytes, &entry, path)?;
    if entry.header[156] == b'5' {
        cp.stop();
        return Ok(Read1::Dir(bytes));
    }
    if entry.size > READ_AHEAD_FILE {
        cp.stop();
        return Ok(Read1::Later);
    }
    let padded = entry.size.next_multiple_of(512);
    if held.fetch_add(padded, Ordering::Relaxed).saturating_add(padded) > READ_AHEAD_TOTAL {
        cp.stop();
        return Ok(Read1::Later);
    }
    if let Err(e) = copy_body(&mut cp.out, &mut bytes, padded) {
        return cp.failed(e).map(|()| Read1::Missing);
    }
    cp.stop();
    Ok(Read1::Whole(bytes))
}

/// Writes `path` read from the source container now: its own entry (a
/// directory's without what is in it), or with `whole` everything under
/// it. Gone since `docker diff` (a running container), it is left out.
fn read_paths(ctx: &str, id: &str, path: &str, out: &mut dyn Write, whole: bool) -> io::Result<()> {
    let mut cp = Cp::start(ctx, id, path)?;
    loop {
        let entry = match read_entry(&mut cp.out) {
            Ok(Some(e)) => e,
            Ok(None) => return cp.finish().map(|_| ()),
            Err(e) => return cp.failed(e),
        };
        write_renamed(out, &entry, path)?;
        if !whole && entry.header[156] == b'5' {
            cp.stop();
            return Ok(());
        }
        let padded = entry.size.checked_next_multiple_of(512).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "tar stream: a damaged header"))?;
        let mut body = (&mut cp.out).take(padded);
        let copied = io::copy(&mut body, out)?;
        if copied != padded {
            return cp.failed(io::Error::new(io::ErrorKind::UnexpectedEof, "cut off inside a file's body"));
        }
        if !whole {
            cp.stop();
            return Ok(());
        }
    }
}

/// `docker cp` of one path out of the source container, as a tar stream.
struct Cp {
    child: std::process::Child,
    out: std::process::ChildStdout,
    said: Option<std::thread::JoinHandle<String>>,
    path: String,
}

impl Cp {
    fn start(ctx: &str, id: &str, path: &str) -> io::Result<Cp> {
        let mut child = cli()?.args(["--context", ctx, "cp", &format!("{id}:{path}"), "-"]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
        let out = child.stdout.take().ok_or_else(|| io::Error::other("no output from docker"))?;
        // Read meanwhile: a full pipe would stop it.
        let said = child.stderr.take().map(|mut e| {
            std::thread::spawn(move || {
                let mut text = String::new();
                let _ = e.read_to_string(&mut text);
                text.trim().to_owned()
            })
        });
        Ok(Cp { child, out, said, path: path.to_owned() })
    }

    /// Stops it: all that was wanted of it is read.
    fn stop(self) {
        drop(self);
    }

    /// Waits for it to end. `Ok(false)` when the path is not there.
    fn finish(mut self) -> io::Result<bool> {
        let _ = io::copy(&mut self.out, &mut io::sink());
        let status = self.child.wait()?;
        let said = self.said.take().and_then(|t| t.join().ok()).unwrap_or_default();
        if status.success() {
            return Ok(true);
        }
        if gone(&said) {
            return Ok(false);
        }
        Err(io::Error::other(format!("docker cp {}: {}", self.path, if said.is_empty() { "failed" } else { &said })))
    }

    /// After reading its output failed with `e`: `Ok` when the path is
    /// simply not there, else what docker said, or `e`.
    fn failed(mut self, e: io::Error) -> io::Result<()> {
        self.end();
        let said = self.said.take().and_then(|t| t.join().ok()).unwrap_or_default();
        if gone(&said) {
            return Ok(());
        }
        let why = if said.is_empty() { e.to_string() } else { said };
        Err(io::Error::new(if e.kind() == io::ErrorKind::BrokenPipe { io::ErrorKind::Other } else { e.kind() }, format!("docker cp {}: {why}", self.path)))
    }
}

impl Cp {
    fn end(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One stopped early, or left when writing failed, ends with it.
impl Drop for Cp {
    fn drop(&mut self) {
        self.end();
    }
}

/// Whether `docker cp` said the path is not there.
fn gone(said: &str) -> bool {
    let said = said.to_ascii_lowercase();
    said.contains("could not find the file") || said.contains("no such container:path")
}

/// A tar entry as read: its header, its pax records (`path` and
/// `linkpath` taken out into `name` and `link`), and its body's size.
struct TarEntry {
    header: [u8; 512],
    pax: Vec<(String, String)>,
    name: String,
    link: String,
    size: u64,
}

/// The next entry's headers in a tar stream, its body still to read;
/// `None` at the archive's end. Pax and GNU long-name headers are folded
/// into the entry they come before.
fn read_entry(r: &mut dyn Read) -> io::Result<Option<TarEntry>> {
    let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidData, format!("tar stream: {what}"));
    let text = |b: &[u8]| String::from_utf8_lossy(b.split(|c| *c == 0).next().unwrap_or_default()).into_owned();
    let mut pax: Vec<(String, String)> = Vec::new();
    let (mut long_name, mut long_link) = (None, None);
    loop {
        let mut h = [0u8; 512];
        r.read_exact(&mut h).map_err(|e| if e.kind() == io::ErrorKind::UnexpectedEof { bad("cut off before the archive's end") } else { e })?;
        if h.iter().all(|b| *b == 0) {
            return Ok(None);
        }
        let size = get_number(&h[124..136]).ok_or_else(|| bad("a damaged header"))?;
        if matches!(h[156], b'x' | b'g' | b'L' | b'K') {
            if size > 16 << 20 {
                return Err(bad("a header too large"));
            }
            let mut data = vec![0u8; size.next_multiple_of(512) as usize];
            r.read_exact(&mut data).map_err(|e| if e.kind() == io::ErrorKind::UnexpectedEof { bad("cut off inside a header") } else { e })?;
            data.truncate(size as usize);
            match h[156] {
                b'x' => pax.extend(pax_records(&data)),
                b'L' => long_name = Some(text(&data)),
                b'K' => long_link = Some(text(&data)),
                // A global header says nothing about this entry.
                _ => {}
            }
            continue;
        }
        let posix = &h[257..263] == b"ustar\0";
        let mut name = long_name.unwrap_or_else(|| match text(&h[345..500]) {
            prefix if posix && !prefix.is_empty() => format!("{prefix}/{}", text(&h[..100])),
            _ => text(&h[..100]),
        });
        let mut link = long_link.unwrap_or_else(|| text(&h[157..257]));
        let mut size = size;
        pax.retain(|(k, v)| match k.as_str() {
            "path" => {
                name.clone_from(v);
                false
            }
            "linkpath" => {
                link.clone_from(v);
                false
            }
            "size" => {
                size = v.parse().unwrap_or(size);
                true
            }
            _ => true,
        });
        size.checked_next_multiple_of(512).ok_or_else(|| bad("a damaged header"))?;
        return Ok(Some(TarEntry { header: h, pax, name, link, size }));
    }
}

/// Writes `e`, which `docker cp` of `path` named from `path`'s last step
/// (`hosts2` for `/etc/hosts2`), under its path in the layer instead
/// (`etc/hosts2`); a hard link's target likewise. Anything else under
/// that name is not what was asked for.
fn write_renamed(out: &mut dyn Write, e: &TarEntry, path: &str) -> io::Result<()> {
    let base = path.rsplit('/').next().unwrap_or_default();
    let rebase = |name: &str| -> Option<String> {
        let rest = name.trim_start_matches("./").trim_start_matches('/').strip_prefix(base)?;
        (rest.is_empty() || rest.starts_with('/')).then(|| format!("{}{rest}", &path[1..]))
    };
    let name = rebase(&e.name).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("docker cp {path}: an entry named {:?}", e.name)))?;
    let link = if e.header[156] == b'1' { rebase(&e.link).unwrap_or_else(|| e.link.clone()) } else { e.link.clone() };
    write_entry(out, e, &name, &link)
}

/// Writes `e`'s headers as `name` (and `link`): in the header where they
/// fit, else in a pax header before it, which also keeps the records it
/// came with, less overlayfs's own attributes. Size, owner and group a pax
/// record gives go in the header too, as [`retar`] puts them.
fn write_entry(out: &mut dyn Write, e: &TarEntry, name: &str, link: &str) -> io::Result<()> {
    let mut pax: Vec<(String, String)> = e.pax.iter().filter(|(k, _)| !k.starts_with("SCHILY.xattr.trusted.overlay.")).cloned().collect();
    if name.len() > 100 {
        pax.push(("path".into(), name.into()));
    }
    if link.len() > 100 {
        pax.push(("linkpath".into(), link.into()));
    }
    let mut h = e.header;
    put_text(&mut h[..100], name);
    put_text(&mut h[157..257], link);
    if &h[257..263] == b"ustar\0" {
        h[345..500].fill(0);
    }
    for (key, at) in [("size", 124..136), ("uid", 108..116), ("gid", 116..124)] {
        if let Some(v) = pax.iter().rfind(|(k, _)| k == key).and_then(|(_, v)| v.parse::<u64>().ok()) {
            put_number(&mut h[at], v);
        }
    }
    put_checksum(&mut h);
    if !pax.is_empty() {
        let mut data = Vec::new();
        for (k, v) in &pax {
            data.extend_from_slice(&pax_record(k, v));
        }
        let mut x = plain_header(b'x', "././@PaxHeader", data.len() as u64, 0o644);
        put_checksum(&mut x);
        out.write_all(&x)?;
        data.resize(data.len().next_multiple_of(512), 0);
        out.write_all(&data)?;
    }
    out.write_all(&h)
}

/// An empty file named `name`, owned by root: a whiteout or opaque mark.
fn write_marker(out: &mut dyn Write, name: &str) -> io::Result<()> {
    let e = TarEntry { header: plain_header(b'0', "", 0, 0o644), pax: Vec::new(), name: name.to_owned(), link: String::new(), size: 0 };
    write_entry(out, &e, name, "")
}

/// A ustar header of kind `kind`, owned by root, with a time of 0.
fn plain_header(kind: u8, name: &str, size: u64, mode: u32) -> [u8; 512] {
    let mut h = [0u8; 512];
    put_text(&mut h[..100], name);
    put_number(&mut h[100..108], u64::from(mode));
    put_number(&mut h[108..116], 0);
    put_number(&mut h[116..124], 0);
    put_number(&mut h[124..136], size);
    put_number(&mut h[136..148], 0);
    h[156] = kind;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h
}

/// A text field: as much of `s` as fits, the rest NUL.
fn put_text(field: &mut [u8], s: &str) {
    field.fill(0);
    let n = s.len().min(field.len());
    field[..n].copy_from_slice(&s.as_bytes()[..n]);
}

fn put_checksum(h: &mut [u8; 512]) {
    update_checksum(h);
}

/// An entry's body, padded to whole blocks, from `from` to `to`.
fn copy_body(from: &mut dyn Read, to: &mut Vec<u8>, padded: u64) -> io::Result<()> {
    if (&mut *from).take(padded).read_to_end(to)? as u64 != padded {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "cut off inside a file's body"));
    }
    Ok(())
}

/// Non-empty reason for a failed `/containers/create` call, falling back to
/// the HTTP status if the daemon returned an empty body (#411).
fn create_error(status: u16, msg: &str) -> String {
    let trimmed = msg.trim();
    if trimmed.is_empty() { format!("HTTP {status}") } else { trimmed.to_owned() }
}

/// Translates Docker Desktop's VM-internal host-mount paths to host paths Kiri
/// can bind directly (#411):
/// - macOS Docker Desktop: `/host_mnt/<path>` -> `/<path>`
/// - Windows Docker Desktop: `/run/desktop/mnt/host/<drive>/<path>` and
///   `/host_mnt/<drive>/<path>` -> `<DRIVE>:/<path>`
///
/// Bare prefixes (`/host_mnt`, `/host_mnt/`, `/run/desktop/mnt/host/`),
/// look-alike prefixes (`/host_mnt_other/...`), and paths containing `..`
/// segments stay unchanged so normalization never collapses to `/` or
/// traverses outside the intended path.
fn translate_bind_source_for(src: &str, windows: bool) -> String {
    let has_dotdot = |p: &str| p.split('/').any(|s| s == "..");
    let drive_path = |rest: &str| -> Option<String> {
        let trimmed = rest.trim_start_matches('/');
        if trimmed.is_empty() || has_dotdot(trimmed) {
            return None;
        }
        let (drive, tail) = trimmed.split_once('/').unwrap_or((trimmed, ""));
        if drive.len() != 1 || !drive.as_bytes()[0].is_ascii_alphabetic() {
            return None;
        }
        let tail = tail.trim_start_matches('/');
        if tail.is_empty() { Some(format!("{}:/", drive.to_ascii_uppercase())) } else { Some(format!("{}:/{tail}", drive.to_ascii_uppercase())) }
    };
    if windows {
        if let Some(rest) = src.strip_prefix("/run/desktop/mnt/host/") {
            return drive_path(rest).unwrap_or_else(|| src.to_owned());
        }
        if let Some(rest) = src.strip_prefix("/host_mnt/") {
            return drive_path(rest).unwrap_or_else(|| src.to_owned());
        }
        return src.to_owned();
    }
    if let Some(rest) = src.strip_prefix("/host_mnt/") {
        let trimmed = rest.trim_start_matches('/');
        if !has_dotdot(trimmed) && trimmed.split('/').any(|s| !s.is_empty() && s != ".") {
            return format!("/{trimmed}");
        }
    }
    src.to_owned()
}

/// Translates the source side of a `HostConfig.Binds` entry (`SRC:DST[:OPTS]`),
/// preserving the destination and any mount options (`:ro`, `:delegated`, etc.).
fn translate_bind_spec_for(spec: &str, windows: bool) -> String {
    let Some((src, rest)) = spec.split_once(':') else {
        return spec.to_owned();
    };
    if !rest.starts_with('/') {
        return spec.to_owned();
    }
    let translated = translate_bind_source_for(src, windows);
    if translated == src { spec.to_owned() } else { format!("{translated}:{rest}") }
}

/// The volumes a container has on the source, named and anonymous.
fn volumes_of(info: &Value) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for m in info["Mounts"].as_array().into_iter().flatten().filter(|m| m["Type"] == "volume") {
        if let Some(n) = m["Name"].as_str().filter(|n| !n.is_empty() && !names.iter().any(|x| x == n)) {
            names.push(n.to_owned());
        }
    }
    names
}

/// What Kiri's create takes of the source's `inspect`: command, environment,
/// labels, ports, mounts, restart policy, devices, DNS, healthcheck, limits
/// and the rest Kiri keeps, with `mode` its network mode in Kiri and
/// `networks` its endpoints. Anonymous volumes (`-v /path`, an image's
/// VOLUME) are named, as the copies already in Kiri are; else Kiri would make
/// new empty ones. Beside `container:` mode, what Docker and Kiri refuse
/// there is left out: the source fills some of it in itself (#375).
fn create_body(info: &Value, mode: &str, networks: Value) -> Value {
    create_body_for(info, mode, networks, cfg!(windows))
}

fn create_body_for(info: &Value, mode: &str, networks: Value, windows: bool) -> Value {
    let (cfg, hc) = (&info["Config"], &info["HostConfig"]);
    let anon: Vec<(&str, &str, bool)> = info["Mounts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|m| m["Type"] == "volume")
        .filter_map(|m| Some((m["Name"].as_str().filter(|n| anonymous(n))?, m["Destination"].as_str()?, m["RW"] != false)))
        .collect();
    let mut mounts = hc["Mounts"].clone();
    for m in mounts.as_array_mut().into_iter().flatten() {
        if m["Type"] == "volume" && m["Source"].as_str().unwrap_or("").is_empty() {
            if let Some((n, _, _)) = anon.iter().find(|(_, d, _)| m["Target"].as_str() == Some(d)) {
                m["Source"] = (*n).into();
            }
        } else if m["Type"].as_str().unwrap_or("bind") == "bind"
            && let Some(src) = m["Source"].as_str()
        {
            let translated = translate_bind_source_for(src, windows);
            if translated != src {
                m["Source"] = translated.into();
            }
        }
    }
    let mut binds = hc["Binds"].clone();
    for b in binds.as_array_mut().into_iter().flatten() {
        if let Some(spec) = b.as_str() {
            let translated = translate_bind_spec_for(spec, windows);
            if translated != spec {
                *b = translated.into();
            }
        }
    }
    for (n, d, rw) in &anon {
        if !mounts.as_array().into_iter().flatten().any(|m| m["Target"].as_str() == Some(d)) {
            let bind = format!("{n}:{d}{}", if *rw { "" } else { ":ro" });
            match binds.as_array_mut() {
                Some(b) => b.push(bind.into()),
                None => binds = json!([bind]),
            }
        }
    }
    let mut host = json!({
        "Binds": binds, "PortBindings": hc["PortBindings"], "RestartPolicy": hc["RestartPolicy"], "Mounts": mounts,
        "NetworkMode": mode, "Privileged": hc["Privileged"], "CapAdd": hc["CapAdd"], "CapDrop": hc["CapDrop"], "ExtraHosts": hc["ExtraHosts"],
        "Tmpfs": hc["Tmpfs"], "ReadonlyRootfs": hc["ReadonlyRootfs"], "SecurityOpt": hc["SecurityOpt"], "Memory": hc["Memory"],
        "NanoCpus": hc["NanoCpus"], "ShmSize": hc["ShmSize"], "PublishAllPorts": hc["PublishAllPorts"],
        "Devices": hc["Devices"], "DeviceCgroupRules": hc["DeviceCgroupRules"], "GroupAdd": hc["GroupAdd"], "Ulimits": hc["Ulimits"],
        "Sysctls": hc["Sysctls"], "Dns": hc["Dns"], "DnsSearch": hc["DnsSearch"], "DnsOptions": hc["DnsOptions"], "PidMode": hc["PidMode"],
        "CgroupnsMode": hc["CgroupnsMode"],
        "Init": hc["Init"], "LogConfig": hc["LogConfig"], "AutoRemove": hc["AutoRemove"], "CpuShares": hc["CpuShares"],
        "CpuQuota": hc["CpuQuota"], "CpuPeriod": hc["CpuPeriod"], "PidsLimit": hc["PidsLimit"],
    });
    let mut body = json!({
        "Image": cfg["Image"], "Cmd": cfg["Cmd"], "Entrypoint": cfg["Entrypoint"], "Env": cfg["Env"], "Labels": cfg["Labels"],
        "WorkingDir": cfg["WorkingDir"], "User": cfg["User"], "ExposedPorts": cfg["ExposedPorts"], "Tty": cfg["Tty"],
        "OpenStdin": cfg["OpenStdin"], "StopSignal": cfg["StopSignal"], "StopTimeout": cfg["StopTimeout"], "Hostname": cfg["Hostname"],
        "Domainname": cfg["Domainname"], "MacAddress": cfg["MacAddress"], "Healthcheck": cfg["Healthcheck"], "Shell": cfg["Shell"],
        "NetworkingConfig": {"EndpointsConfig": networks},
    });
    if mode.starts_with("container:") {
        for k in ["Hostname", "MacAddress", "ExposedPorts"] {
            body[k] = Value::Null;
        }
        for k in ["PortBindings", "PublishAllPorts", "Dns", "ExtraHosts"] {
            host[k] = Value::Null;
        }
    }
    for v in [&mut host, &mut body] {
        if let Some(o) = v.as_object_mut() {
            o.retain(|_, v| !v.is_null());
        }
    }
    body["HostConfig"] = host;
    body
}

/// Whether `ctx`'s engine answers.
fn answers(ctx: &str) -> bool {
    cli().is_ok_and(|mut c| c.args(["--context", ctx, "version", "--format", "{{.Server.Version}}"]).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success()))
}

/// The engine to import from: the one named, or else the first that
/// answers. Only the engines that need it are asked (`answers` waits on
/// each), and one that isn't there gets a plain message instead of docker's
/// "context not found" (#266).
fn pick(given: Option<&str>, answers: impl Fn(&str) -> bool) -> io::Result<&'static str> {
    match given {
        Some(id) => {
            let id = known(id)?;
            if answers(id) {
                Ok(id)
            } else {
                Err(io::Error::other(format!("{} isn't installed or running here (no docker context \"{id}\" answering)", label(id))))
            }
        }
        None => SOURCES.iter().map(|(c, _)| *c).find(|c| answers(c)).ok_or_else(|| {
            let names: Vec<&str> = SOURCES.iter().map(|(_, l)| *l).collect();
            io::Error::other(format!("nothing to import from: {} isn't installed or running here", names.join(" or ")))
        }),
    }
}

const KINDS: [&str; 3] = ["image", "volume", "container"];
#[cfg(windows)]
const USAGE: &str = "usage: kiri import [desktop-linux] [--images] [--volumes] [--containers] [--list | [--force] [image|volume|container NAME]]";
#[cfg(not(windows))]
const USAGE: &str = "usage: kiri import [orbstack|desktop-linux] [--images] [--volumes] [--containers] [--list | [--force] [image|volume|container NAME]]";

/// Which resource kinds a bulk `kiri import` or `kiri import --list` includes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KindFilter {
    images: bool,
    volumes: bool,
    containers: bool,
}

impl KindFilter {
    const ALL: Self = Self { images: true, volumes: true, containers: true };
}

/// What `kiri import` was asked to do.
#[derive(Debug, PartialEq)]
enum Ask<'a> {
    Everything(KindFilter),
    List(KindFilter),
    One(&'a str, &'a str),
}

/// The source named (if any), what to do, and whether `--force` copies
/// volumes that running containers on the source use. A kind without
/// exactly one name, `--list` with an item or with `--force`, or a flag Kiri
/// doesn't know is a usage error, never "import everything".
fn parse<'a>(args: &[&'a str]) -> io::Result<(Option<&'a str>, Ask<'a>, bool)> {
    let usage = || io::Error::other(USAGE);
    let (mut list, mut force) = (false, false);
    let (mut f_images, mut f_volumes, mut f_containers) = (false, false, false);
    let mut words = Vec::new();
    for a in args {
        match *a {
            "--list" => list = true,
            "--force" => force = true,
            "--images" => f_images = true,
            "--volumes" => f_volumes = true,
            "--containers" => f_containers = true,
            f if f.starts_with('-') => return Err(usage()),
            w => words.push(w),
        }
    }
    let explicit_filter = f_images || f_volumes || f_containers;
    let filter = if explicit_filter {
        KindFilter { images: f_images, volumes: f_volumes, containers: f_containers }
    } else {
        KindFilter::ALL
    };
    let (given, rest) = match words.split_first() {
        Some((first, rest)) if !KINDS.contains(first) => (Some(*first), rest),
        _ => (None, &words[..]),
    };
    let ask = match (rest, list) {
        ([], false) => Ask::Everything(filter),
        ([], true) if !force => Ask::List(filter),
        ([kind, name], false) if !explicit_filter && KINDS.contains(kind) => Ask::One(kind, name),
        _ => return Err(usage()),
    };
    Ok((given, ask, force))
}

#[cfg(windows)]
fn ensure_windows_kiri_context() {
    let Some(dir) = crate::dockerctx::docker_dir() else { return };
    let exe = std::env::current_exe().ok();
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let plugins = crate::dockerctx::find_windows_cli_plugins(exe.as_deref(), local.as_deref());
    let desktop = std::env::var_os("ProgramFiles")
        .is_some_and(|p| std::path::Path::new(&p).join(r"Docker\Docker\Docker Desktop.exe").is_file());
    let host = crate::dockerctx::npipe_host(&client::pipe());
    let _ = crate::dockerctx::repair_windows_config(
        &dir,
        crate::dockerctx::WindowsRepairOpts {
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

/// `kiri import [orbstack|desktop-linux] [--images] [--volumes] [--containers] [--list | [--force] [image|volume|container NAME]]`:
/// one item, or every image, named volume and container Kiri lacks.
#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
pub fn run(args: &[String]) -> io::Result<()> {
    if args.iter().any(|a| matches!(a.as_str(), "-h" | "--help"))
        || matches!(args.first().map(String::as_str), Some("help"))
    {
        println!("{USAGE}");
        return Ok(());
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (given, ask, force) = parse(&args)?;
    #[cfg(windows)]
    ensure_windows_kiri_context();
    let source = pick(given, answers)?;
    if !matches!(ask, Ask::List(_)) {
        client::check_alive()?;
    }
    if given.is_none() {
        println!("from {} ({source})", label(source));
    }
    if let Ask::One(kind, name) = ask {
        let r = match kind {
            "image" => image(source, name),
            "volume" => volume_with(source, name, force),
            _ => container_with(source, name, force, &[]),
        };
        return r.map(|()| println!("{kind} {name}: done"));
    }
    let inv = inventory(source)?;
    let list = |k: &str| inv[k].as_array().cloned().unwrap_or_default();
    if let Ask::List(filter) = ask {
        for (k, on) in [("images", filter.images), ("volumes", filter.volumes), ("containers", filter.containers)] {
            if !on {
                continue;
            }
            println!("{k}:");
            for v in list(k) {
                println!("  {}{}", v["name"].as_str().unwrap_or(""), if v["have"] == true { "  (already in Kiri)" } else { "" });
            }
        }
        return Ok(());
    }
    let Ask::Everything(filter) = ask else { unreachable!() };
    let mut failures: Vec<(&str, String, String)> = Vec::new();
    let mut step = |what: &'static str, name: &str, r: io::Result<()>| match r {
        Ok(()) => println!("{what} {name}: done"),
        Err(e) => {
            let reason = e.to_string();
            let why = if reason.trim().is_empty() { "unknown error" } else { reason.trim() };
            println!("{what} {name}: skipped ({why})");
            failures.push((what, name.to_owned(), why.to_owned()));
        }
    };
    if filter.images {
        for v in list("images").iter().filter(|v| v["have"] != true) {
            let n = v["name"].as_str().unwrap_or("");
            step("image", n, image(source, n));
        }
    }
    if filter.volumes {
        for v in list("volumes").iter().filter(|v| v["have"] != true && v["anonymous"] != true) {
            let n = v["name"].as_str().unwrap_or("");
            step("volume", n, volume_with(source, n, force));
        }
    }
    if filter.containers {
        for v in list("containers") {
            let n = v["name"].as_str().unwrap_or("");
            let already_had = v["have"] == true;
            let already_imported = !already_had && has(crate::flavor::CONTEXT.get(), "container", n);
            if let Some(why) = container_skip_reason(already_had, already_imported) {
                println!("container {n}: skipped ({why})");
                continue;
            }
            step("container", n, container_with(source, n, force, &[]));
        }
    }
    if !failures.is_empty() { Err(io::Error::other(format_failures(&failures))) } else { Ok(()) }
}

/// Why a container in `kiri import` is skipped without calling `container_with` (#411).
fn container_skip_reason(already_had: bool, already_imported: bool) -> Option<&'static str> {
    if already_had {
        Some("already in Kiri")
    } else if already_imported {
        Some("already imported as a network target")
    } else {
        None
    }
}

/// Summary returned when one or more items could not be imported, naming each
/// item and its reason so nothing is skipped silently (#411).
fn format_failures(failures: &[(&str, String, String)]) -> String {
    let n = failures.len();
    let items = if n == 1 { "item" } else { "items" };
    let mut out = format!("{n} {items} could not be imported:");
    for (kind, name, reason) in failures {
        let why = if reason.trim().is_empty() { "unknown error" } else { reason.trim() };
        out.push_str(&format!("\n  {kind} {name}: {why}"));
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn anonymous_volumes() {
        assert!(super::anonymous(&"a1".repeat(32)));
        assert!(!super::anonymous("pgdata"));
    }

    /// #410: what of a container's writable layer `kiri import` reads. `/etc`
    /// changed because a file was added to it brings that file and `/etc`'s
    /// own entry, never the rest of `/etc`; a new directory comes whole in
    /// one read, unless something is mounted under it; nothing at or under a
    /// mount, the engine's own files or the kernel's filesystems; every
    /// directory a path is in comes too.
    #[test]
    fn plans_only_what_the_writable_layer_changed() {
        let diff = "C /etc\nA /etc/hosts2\nC /etc/hosts\nA /app\nA /app/x\nA /app/sub\nA /app/sub/y\nA /srv\nA /srv/cache\nA /srv/keep\nA /data\n\
                    C /usr\nC /usr/share\nD /usr/share/doc\nC /opt\nD /opt/again\nA /opt/again/new\nA /var/lib/x\nC /proc\nA /dev/shm/x\n\
                    C /run\nA /run/tmp\nA /.dockerenv\n";
        let mounts = ["/data".to_owned(), "/srv/cache".to_owned(), "/run/tmp".to_owned()];
        let plan = super::plan_layer(&super::parse_diff(diff), &mounts);
        let v = |s: &[&str]| s.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            plan,
            super::LayerPlan {
                deleted: v(&["/opt/again", "/usr/share/doc"]),
                entries: v(&["/etc", "/etc/hosts2", "/opt", "/opt/again/new", "/srv", "/srv/keep", "/usr", "/usr/share", "/var", "/var/lib", "/var/lib/x"]),
                trees: v(&["/app"]),
            }
        );
        // Nothing changed, or only what each engine makes for itself: one
        // `docker diff`, and nothing sent.
        assert!(super::plan_layer(&[], &mounts).is_empty());
        assert!(super::plan_layer(&super::parse_diff("C /etc\nA /etc/hostname\nC /etc/resolv.conf\nA /data\n"), &mounts).is_empty());
        // A changed directory alone (its mode, say) is its own entry.
        assert_eq!(super::plan_layer(&super::parse_diff("C /tmp\n"), &[]).entries, v(&["/tmp"]));
    }

    #[test]
    fn reads_docker_diff_lines() {
        let got = super::parse_diff("C /etc\r\nA /etc/a b\nX /x\nA relative\nA /a/../b\nA /a//b\nA /\nD /gone\n\n");
        assert_eq!(got, [('C', "/etc".to_owned()), ('A', "/etc/a b".to_owned()), ('D', "/gone".to_owned())]);
    }

    #[test]
    fn finds_where_a_container_has_mounts() {
        let info = serde_json::json!({
            "Mounts": [{"Type": "volume", "Destination": "/data/"}, {"Type": "bind", "Destination": "/src"}],
            "HostConfig": {"Mounts": [{"Type": "tmpfs", "Target": "/cache"}, {"Target": "/src"}], "Tmpfs": {"/run/tmp": "size=1m"}},
        });
        assert_eq!(super::mount_points(&info), ["/data", "/src", "/cache", "/run/tmp"]);
    }

    /// `docker cp ctr:/srv/app -` names its entries from `app`: each is
    /// written under its path in the layer, a hard link's target too, a
    /// symlink's target as it is; long names go in pax; owners and
    /// attributes stay, but overlayfs's own; a stream cut short is an error.
    #[test]
    fn writes_what_docker_cp_read_under_its_path_in_the_layer() {
        use std::io::Read;
        let entry = |kind: u8, name: &str, link: &str, size: u64, pax: &[(&str, &str)]| {
            let mut header = super::plain_header(kind, "", size, if kind == b'5' { 0o750 } else { 0o640 });
            super::put_number(&mut header[108..116], 1000);
            super::put_number(&mut header[116..124], 1001);
            let pax = pax.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
            super::TarEntry { header, pax, name: name.to_owned(), link: link.to_owned(), size }
        };
        let long = format!("app/{}", "n".repeat(120));
        let mut src = Vec::new();
        for (e, body) in [
            (entry(b'5', "app/", "", 0, &[]), &b""[..]),
            (entry(b'0', "app/f", "", 5, &[("SCHILY.xattr.trusted.overlay.redirect", "/x"), ("SCHILY.xattr.user.k", "v")]), b"hello"),
            (entry(b'2', "app/l", "f", 0, &[]), b""),
            (entry(b'1', "app/h", "app/f", 0, &[]), b""),
            (entry(b'0', &long, "", 0, &[]), b""),
        ] {
            super::write_entry(&mut src, &e, &e.name.clone(), &e.link.clone()).unwrap();
            src.extend_from_slice(body);
            src.resize(src.len().div_ceil(512) * 512, 0);
        }
        src.extend_from_slice(&[0u8; 1024]);

        let mut out = Vec::new();
        let mut r = &src[..];
        while let Some(e) = super::read_entry(&mut r).unwrap() {
            super::write_renamed(&mut out, &e, "/srv/app").unwrap();
            let padded = e.size.div_ceil(512) * 512;
            std::io::copy(&mut (&mut r).take(padded), &mut out).unwrap();
        }
        out.extend_from_slice(&[0u8; 1024]);

        let mut r = &out[..];
        let mut got = Vec::new();
        for block in out.chunks(512).filter(|b| b.iter().any(|c| *c != 0) && (b[257..263] == *b"ustar\0")) {
            let mut h: [u8; 512] = block.try_into().unwrap();
            let sum = h[148..156].to_vec();
            super::put_checksum(&mut h);
            assert_eq!(sum, h[148..156], "a valid checksum");
        }
        while let Some(e) = super::read_entry(&mut r).unwrap() {
            let mut body = vec![0u8; (e.size.div_ceil(512) * 512) as usize];
            r.read_exact(&mut body).unwrap();
            body.truncate(e.size as usize);
            let owner = (super::get_number(&e.header[108..116]), super::get_number(&e.header[116..124]));
            got.push((e.name.clone(), e.link.clone(), e.pax.clone(), String::from_utf8(body).unwrap(), owner));
        }
        let none: Vec<(String, String)> = Vec::new();
        let owner = (Some(1000), Some(1001));
        assert_eq!(got[0], ("srv/app/".to_owned(), String::new(), none.clone(), String::new(), owner));
        assert_eq!(got[1], ("srv/app/f".to_owned(), String::new(), vec![("SCHILY.xattr.user.k".to_owned(), "v".to_owned())], "hello".to_owned(), owner));
        assert_eq!(got[2], ("srv/app/l".to_owned(), "f".to_owned(), none.clone(), String::new(), owner));
        assert_eq!(got[3], ("srv/app/h".to_owned(), "srv/app/f".to_owned(), none.clone(), String::new(), owner));
        assert_eq!(got[4].0, format!("srv/{long}"));
        assert_eq!(got.len(), 5);

        // Only what was asked for: an entry by another name is an error.
        let mut sink = Vec::new();
        assert!(super::write_renamed(&mut sink, &entry(b'0', "apples", "", 0, &[]), "/srv/app").is_err());
        assert!(super::write_renamed(&mut sink, &entry(b'0', "app", "", 0, &[]), "/srv/app").is_ok());
        // Cut short, inside a header or before the archive's end.
        assert!(super::read_entry(&mut &src[..300]).is_err());
        assert!(super::read_entry(&mut &src[..0]).is_err());
    }

    #[test]
    fn names_whiteouts_beside_what_they_delete() {
        assert_eq!(super::whiteout_name("/etc/gone"), "etc/.wh.gone");
        assert_eq!(super::whiteout_name("/gone"), ".wh.gone");
        let mut out = Vec::new();
        super::write_marker(&mut out, &format!("d/{}/.wh..wh..opq", "x".repeat(100))).unwrap();
        let e = super::read_entry(&mut &out[..]).unwrap().unwrap();
        assert_eq!((e.name, e.size, e.header[156]), (format!("d/{}/.wh..wh..opq", "x".repeat(100)), 0, b'0'));
    }

    // #266: a fresh machine with neither engine gets a plain answer, not
    // docker's "context not found"; with no source named, the first that
    // answers is used, and only as many engines are asked as needed.
    #[test]
    fn picks_a_running_source() {
        use super::pick;
        let none = |_: &str| false;
        let only_desktop = |c: &str| c == "desktop-linux";
        if cfg!(windows) {
            assert_eq!(pick(None, none).unwrap_err().to_string(), "nothing to import from: Docker Desktop isn't installed or running here");
        } else {
            assert_eq!(pick(None, none).unwrap_err().to_string(), "nothing to import from: OrbStack or Docker Desktop isn't installed or running here");
            assert!(pick(Some("orbstack"), only_desktop).is_err());
            // Named: only that engine is asked.
            let asked = std::cell::RefCell::new(Vec::new());
            assert_eq!(pick(Some("desktop-linux"), |c: &str| { asked.borrow_mut().push(c.to_owned()); true }).unwrap(), "desktop-linux");
            assert_eq!(*asked.borrow(), ["desktop-linux"]);
            // Not named: stops at the first that answers.
            asked.borrow_mut().clear();
            assert_eq!(pick(None, |c: &str| { asked.borrow_mut().push(c.to_owned()); true }).unwrap(), "orbstack");
            assert_eq!(*asked.borrow(), ["orbstack"]);
        }
        assert_eq!(pick(None, only_desktop).unwrap(), "desktop-linux");
        assert!(pick(Some("desktop-linux"), none).unwrap_err().to_string().starts_with("Docker Desktop isn't installed or running here"));
        // An unknown source is refused before any engine is asked.
        assert_eq!(pick(Some("podman"), |_: &str| panic!("asked")).unwrap_err().to_string(), "unknown source podman");
    }

    // A kind without exactly one name is a usage error, never "import
    // everything"; the source may be left out before a kind.
    #[test]
    fn parses_what_to_import() {
        use super::{Ask, KindFilter, parse};
        let all = KindFilter::ALL;
        assert_eq!(parse(&[]).unwrap(), (None, Ask::Everything(all), false));
        assert_eq!(parse(&["orbstack"]).unwrap(), (Some("orbstack"), Ask::Everything(all), false));
        assert_eq!(parse(&["--list"]).unwrap(), (None, Ask::List(all), false));
        assert_eq!(parse(&["orbstack", "--list"]).unwrap(), (Some("orbstack"), Ask::List(all), false));
        assert_eq!(parse(&["image", "nginx"]).unwrap(), (None, Ask::One("image", "nginx"), false));
        assert_eq!(parse(&["desktop-linux", "volume", "pg"]).unwrap(), (Some("desktop-linux"), Ask::One("volume", "pg"), false));
        // #345: --force copies volumes running containers use, one or all.
        assert_eq!(parse(&["orbstack", "volume", "pg", "--force"]).unwrap(), (Some("orbstack"), Ask::One("volume", "pg"), true));
        assert_eq!(parse(&["--force", "container", "db"]).unwrap(), (None, Ask::One("container", "db"), true));
        assert_eq!(parse(&["orbstack", "--force"]).unwrap(), (Some("orbstack"), Ask::Everything(all), true));
        // #984: --images, --volumes, --containers filter bulk import and --list.
        assert_eq!(
            parse(&["desktop-linux", "--images"]).unwrap(),
            (Some("desktop-linux"), Ask::Everything(KindFilter { images: true, volumes: false, containers: false }), false)
        );
        assert_eq!(
            parse(&["--volumes", "--containers"]).unwrap(),
            (None, Ask::Everything(KindFilter { images: false, volumes: true, containers: true }), false)
        );
        assert_eq!(
            parse(&["--list", "--containers"]).unwrap(),
            (None, Ask::List(KindFilter { images: false, volumes: false, containers: true }), false)
        );
        for bad in [
            &["orbstack", "image"][..],
            &["image"],
            &["orbstack", "image", "a", "b"],
            &["orbstack", "photo", "a"],
            // --list with an item would import it.
            &["--list", "image", "nginx"],
            &["image", "nginx", "--list"],
            &["--list", "--force"],
            &["--images", "image", "nginx"],
            // An unknown flag must not start a full import.
            &["--dry-run"],
            &["orbstack", "-l"],
        ] {
            assert!(parse(bad).unwrap_err().to_string().starts_with("usage:"), "{bad:?}");
        }
        assert_eq!(parse(&["podman"]).unwrap(), (Some("podman"), Ask::Everything(all), false));
    }

    // Volume helpers run only an image the engine pulled from an official
    // repository, as its repo digests show: never one that only has a name
    // like one, wherever it came from (#506). GNU tar helpers (debian, ubuntu)
    // are preferred over alpine/busybox (#485); alpine/busybox remain a
    // fallback for inspection or offline use (#376).
    #[test]
    fn only_an_official_image_helps() {
        use super::{official, pick_gnu_helper, pick_helper};
        use serde_json::json;
        let d = format!("@sha256:{}", "ab12".repeat(16));
        for good in ["busybox", "library/alpine", "docker.io/library/debian", "mirror.gcr.io/library/ubuntu", "public.ecr.aws/docker/library/busybox"] {
            assert!(official(&format!("{good}{d}")), "{good}");
        }
        let look_alikes = [
            "ghcr.io/x/library/busybox",
            "localhost:5000/library/alpine",
            "localhost:5000/debian",
            "localhost/x/library/busybox",
            "evil/alpine",
            "evil/debian",
            "docker.io/evil/alpine",
            "mirror.gcr.io/evil/library/alpine",
            "public.ecr.aws/x/library/alpine",
            "alpinelinux",
            "nginx",
            "busybox:1",
        ];
        for bad in look_alikes {
            assert!(!official(&format!("{bad}{d}")), "{bad}");
        }
        for bad in ["busybox", "busybox:1", "busybox@sha256:abc", &format!("busybox@sha512:{}", "a".repeat(64)), &format!("busybox@sha256:{}", "A".repeat(64))] {
            assert!(!official(bad), "{bad}");
        }
        // Image list: one record per name, each with its own digests.
        let rec = |name: &str, digests: &[String]| json!({"Id": format!("sha256:{}", "c".repeat(64)), "RepoTags": [name], "RepoDigests": digests});
        let records = [
            // Untagged: a load or build without a name.
            rec(&format!("sha256:{}", "c".repeat(64)), &[]),
            rec("localhost/imp-x/library/busybox:9", &[]),
            // Re-tagged from an official image: no digest of its own.
            rec("alpine:latest", &[]),
            rec("debian:trixie", &[]),
            // Called busybox/debian, its digest another repository's.
            rec("busybox:1", &[format!("evil/tools{d}")]),
            rec("debian:1", &[format!("evil/debian{d}")]),
            // An official digest under a name of another repository.
            rec("evil/alpine:1", &[format!("alpine{d}")]),
            rec("evil/debian:1", &[format!("debian{d}")]),
            rec("ghcr.io/x/library/busybox:1", &[format!("ghcr.io/x/library/busybox{d}")]),
            rec("mirror.gcr.io/library/alpine:latest", &[format!("mirror.gcr.io/library/alpine{d}")]),
            rec("busybox:latest", &[format!("busybox{d}")]),
            // Official GNU tar images: preferred over alpine/busybox.
            rec("mirror.gcr.io/library/debian:latest", &[format!("mirror.gcr.io/library/debian{d}")]),
            rec("ubuntu:latest", &[format!("ubuntu{d}")]),
        ];
        assert_eq!(pick_helper(&records), Some("mirror.gcr.io/library/debian:latest".into()));
        assert_eq!(pick_gnu_helper(&records), Some("mirror.gcr.io/library/debian:latest".into()));
        assert_eq!(pick_helper(&records[..9]), None);
        assert_eq!(pick_gnu_helper(&records[..11]), None);
        // Offline fallback: alpine/busybox still work for pick_helper when no GNU tar image is present.
        assert_eq!(pick_helper(&records[..11]), Some("mirror.gcr.io/library/alpine:latest".into()));
        assert_eq!(pick_helper(&records[10..11]), Some("busybox:latest".into()));
        assert_eq!(pick_gnu_helper(&records[12..]), Some("ubuntu:latest".into()));
        assert_eq!(pick_helper(&[json!({"RepoTags": null, "RepoDigests": [format!("debian{d}")]})]), None);
    }

    // #485: both ends of a volume copy carry xattrs and numeric owners when
    // using GNU tar helpers, pass `--entrypoint tar` on the source, and fall
    // back to plain `tar -xpf -` when an offline helper is alpine/busybox.
    #[test]
    fn volume_copy_keeps_xattrs() {
        assert!(super::gnu_tar("debian:trixie"));
        assert!(super::gnu_tar("debian"));
        assert!(super::gnu_tar("mirror.gcr.io/library/ubuntu:24.04"));
        assert!(super::gnu_tar("public.ecr.aws/docker/library/debian:trixie"));
        assert!(super::gnu_tar("localhost:5000/debian"));
        assert!(!super::gnu_tar("alpine:latest"));
        assert!(!super::gnu_tar("busybox:latest"));
        assert!(!super::gnu_tar("mydebian:latest"));
        let args = super::volume_reader_args("desktop-linux", "kiri-import-pg", "type=volume,src=pg,dst=/from,readonly,volume-nocopy", "debian:trixie");
        let ep = args.iter().position(|a| *a == "--entrypoint").expect("missing --entrypoint");
        assert_eq!(args.get(ep + 1), Some(&"tar"));
        assert_eq!(args.get(ep + 2), Some(&"debian:trixie"));
        for flag in super::STORE_XATTRS {
            assert!(args.contains(&flag), "missing {flag}");
        }
        assert!(args.contains(&"--numeric-owner"));
        assert!(args.contains(&"--network"));
        assert!(args.contains(&"none"));
        assert!(args.contains(&"--pull"));
        assert!(args.contains(&"never"));
        let gnu_script = super::restore_script(true);
        assert!(gnu_script.contains("--numeric-owner"), "{gnu_script}");
        assert!(gnu_script.contains("--xattrs"), "{gnu_script}");
        assert!(gnu_script.contains("'--xattrs-include=user.*'"), "{gnu_script}");
        assert!(gnu_script.ends_with(" -xpf -"), "{gnu_script}");
        let fallback_script = super::restore_script(false);
        assert!(!fallback_script.contains("--xattrs"), "{fallback_script}");
        assert!(fallback_script.ends_with("tar -xpf -"), "{fallback_script}");
    }

    // #485: `retar` passes `SCHILY.xattr.*` pax records through byte-for-byte
    // (including JSON, empty and binary values) while still propagating high
    // uid/gid into the ustar header.
    #[cfg(not(windows))]
    #[test]
    fn retar_preserves_xattr_pax_records() {
        let mut b = tar::Builder::new(Vec::new());
        let json_meta = br#"{"contentType":"image/png","cacheControl":"max-age=3600"}"#;
        b.append_pax_extensions([
            ("SCHILY.xattr.user.test", &b"hello-xattr"[..]),
            ("SCHILY.xattr.user.metadata", json_meta.as_slice()),
            ("SCHILY.xattr.user.empty", &b""[..]),
            ("uid", &b"3000000"[..]),
            ("gid", &b"3000001"[..]),
        ])
        .unwrap();
        let mut h = tar::Header::new_ustar();
        h.set_size(5);
        h.set_mode(0o640);
        h.set_uid(0);
        h.set_gid(0);
        h.set_cksum();
        b.append_data(&mut h, "obj", &b"hello"[..]).unwrap();
        // Second entry with a binary xattr value containing NUL, high bytes
        // and a newline followed by `size=99` (must not spoof the entry size).
        let bin_val = b"\x00\xff\nsize=99";
        b.append_pax_extensions([("SCHILY.xattr.user.bin", bin_val.as_slice()), ("uid", &b"1234"[..])]).unwrap();
        let mut h2 = tar::Header::new_ustar();
        h2.set_size(2);
        h2.set_mode(0o600);
        h2.set_cksum();
        b.append_data(&mut h2, "bin", &b"ok"[..]).unwrap();
        let input = b.into_inner().unwrap();
        let mut out = Vec::new();
        super::retar(input.as_slice(), &mut out, None).unwrap();
        assert_eq!(out.len(), input.len());
        // The pax blocks pass through byte-for-byte unchanged, including binary values.
        assert_eq!(out[..1024], input[..1024]);
        assert!(out.windows(bin_val.len()).any(|w| w == bin_val));
        let mut ar = tar::Archive::new(out.as_slice());
        let mut e = ar.entries().unwrap().next().unwrap().unwrap();
        assert_eq!(e.header().uid().unwrap(), 3_000_000);
        assert_eq!(e.header().gid().unwrap(), 3_000_001);
        let exts: Vec<(String, Vec<u8>)> = e
            .pax_extensions()
            .unwrap()
            .unwrap()
            .map(|r| {
                let r = r.unwrap();
                (r.key().unwrap().to_owned(), r.value_bytes().to_vec())
            })
            .collect();
        assert!(exts.contains(&("SCHILY.xattr.user.test".into(), b"hello-xattr".to_vec())), "{exts:?}");
        assert!(exts.contains(&("SCHILY.xattr.user.metadata".into(), json_meta.to_vec())), "{exts:?}");
        assert!(exts.contains(&("SCHILY.xattr.user.empty".into(), Vec::new())), "{exts:?}");
    }

    // Source tar failures fail the import rather than silently importing a
    // partial volume; only `--force` (`allow_file_changed`) tolerates GNU tar
    // exit code 1 after a complete, valid archive.
    #[cfg(not(windows))]
    #[test]
    fn pipe_propagates_reader_and_writer_errors() {
        use std::process::Command;
        let sh = |script: &str| {
            let mut c = Command::new("sh");
            c.args(["-c", script]);
            c
        };
        let empty_tar = "dd if=/dev/zero bs=1024 count=1 2>/dev/null";
        let sink = "cat >/dev/null";
        // Clean stream, both exit 0: ok.
        super::pipe_with(sh(empty_tar), sh(sink), "orbstack", false, |r, w| super::retar(r, w, None)).unwrap();
        // Source exits 1 without allow_file_changed: error.
        let err = super::pipe_with(sh(&format!("{empty_tar}; echo changed >&2; exit 1")), sh(sink), "orbstack", false, |r, w| super::retar(r, w, None)).unwrap_err();
        assert!(err.to_string().contains("changed"), "{err}");
        // Source exits 1 WITH allow_file_changed and complete tar: ok.
        super::pipe_with(sh(&format!("{empty_tar}; echo changed >&2; exit 1")), sh(sink), "orbstack", true, |r, w| super::retar(r, w, None)).unwrap();
        // Source exits 1 WITH allow_file_changed but truncated/empty output: error.
        assert!(super::pipe_with(sh("echo boom >&2; exit 1"), sh(sink), "orbstack", true, |r, w| super::retar(r, w, None)).is_err());
        // Source exits 2 (fatal tar error) even WITH allow_file_changed: error.
        let err = super::pipe_with(sh(&format!("{empty_tar}; echo fatal >&2; exit 2")), sh(sink), "orbstack", true, |r, w| super::retar(r, w, None)).unwrap_err();
        assert!(err.to_string().contains("fatal"), "{err}");
        // Writer exits non-zero: error.
        let err = super::pipe_with(sh(empty_tar), sh("cat >/dev/null; echo diskfull >&2; exit 1"), "orbstack", false, |r, w| super::retar(r, w, None)).unwrap_err();
        assert!(err.to_string().contains("diskfull"), "{err}");
    }

    // #377: an image only pinned by digest is listed by that reference.
    #[test]
    fn lists_images_pinned_by_digest() {
        use serde_json::json;
        let d = "sha256:49dbca2bb9fc8e48bfc2cc5e039c0e867ca32012f6c739d07b8b0ad603b0d9c8";
        let name = |r: &str, t: &str, dg: &str| super::listed_name(&json!({"Repository": r, "Tag": t, "Digest": dg}));
        assert_eq!(name("nginx", "alpine", d), Some("nginx:alpine".into()));
        assert_eq!(name("ghcr.io/yetone/magpie", "<none>", d), Some(format!("ghcr.io/yetone/magpie@{d}")));
        assert_eq!(name("<none>", "<none>", "<none>"), None);
        assert_eq!(name("built", "<none>", "<none>"), None);
    }

    // #345: a volume a running container uses is not copied, and the
    // reason says what to do.
    #[test]
    fn refuses_volumes_in_use() {
        assert_eq!(super::in_use("pg", "OrbStack", &[]), None);
        assert_eq!(
            super::in_use("pg", "OrbStack", &["db".into()]).unwrap(),
            "pg is in use by db, running on OrbStack: a copy taken now can be cut off mid-write. Stop it there and import again for an exact copy (in a terminal, kiri import --force copies it anyway)"
        );
        assert!(super::in_use("pg", "Docker Desktop", &["db".into(), "backup".into()]).unwrap().starts_with("pg is in use by db, backup, running on Docker Desktop: a copy taken now can be cut off mid-write. Stop them there"));
    }

    // An unfinished volume in Kiri is not emptied while any container there
    // has it; only our own helpers there means another import is at it.
    #[test]
    fn refuses_to_empty_a_volume_kiri_has_in_use() {
        use super::in_use_in_kiri;
        assert_eq!(in_use_in_kiri("pg", &[]), None);
        assert_eq!(
            in_use_in_kiri("pg", &[("db".into(), false)]).unwrap(),
            "pg holds an unfinished copy in Kiri, and Kiri has db using it: importing it again would replace what is in it. Remove it in Kiri (or remove the volume in Kiri) and import again; importing a container again brings its volumes first"
        );
        let mixed = in_use_in_kiri("pg", &[("db".into(), false), ("kiri-import-pg".into(), true), ("backup".into(), false)]).unwrap();
        assert!(mixed.contains("Kiri has db, backup using it") && mixed.contains("Remove them in Kiri"), "{mixed}");
        assert_eq!(in_use_in_kiri("pg", &[("x".into(), true), ("y".into(), true)]).unwrap(), "another import of pg is running in Kiri: let it finish, then import again if it did not");
    }

    // #375: beside `container:` mode, what Kiri refuses is left out (the
    // source fills in a hostname and the image's ports itself); devices,
    // DNS, healthcheck and the rest Kiri keeps come along.
    #[test]
    fn builds_the_create_body() {
        use serde_json::{Value, json};
        let info = |mode: &str| {
            json!({
                "Config": {"Image": "alpine", "Hostname": "4c1e1a2b3c4d", "ExposedPorts": {"80/tcp": {}}, "Cmd": ["sh"], "Labels": null,
                           "Healthcheck": {"Test": ["CMD", "true"], "Interval": 1_000_000_000_u64}, "Domainname": "lan", "StopTimeout": 5},
                "HostConfig": {"NetworkMode": mode, "PortBindings": {"80/tcp": [{"HostPort": "8080"}]}, "Dns": ["1.1.1.1"], "ExtraHosts": ["h:1.2.3.4"],
                               "Devices": [{"PathOnHost": "/dev/net/tun", "PathInContainer": "/dev/net/tun", "CgroupPermissions": "rwm"}],
                               "GroupAdd": ["audio"], "PidMode": "", "CgroupnsMode": "host", "CapAdd": ["NET_ADMIN"], "Binds": null, "Mounts": null, "Ulimits": [{"Name": "nofile", "Soft": 1024, "Hard": 2048}]},
                "Mounts": []
            })
        };
        let joined = super::create_body(&info("container:4c1e1a2b3c4d5e6f"), "container:vpn", json!({}));
        for gone in ["Hostname", "ExposedPorts", "MacAddress"] {
            assert!(joined[gone].is_null(), "{gone}");
        }
        for gone in ["PortBindings", "PublishAllPorts", "Dns", "ExtraHosts"] {
            assert!(joined["HostConfig"][gone].is_null(), "{gone}");
        }
        assert_eq!(joined["HostConfig"]["NetworkMode"], "container:vpn");
        assert_eq!(joined["HostConfig"]["Devices"][0]["PathOnHost"], "/dev/net/tun");
        assert_eq!(joined["HostConfig"]["GroupAdd"], json!(["audio"]));
        assert_eq!(joined["HostConfig"]["CgroupnsMode"], "host");
        assert_eq!(joined["HostConfig"]["CapAdd"], json!(["NET_ADMIN"]));
        assert_eq!(joined["Healthcheck"]["Test"], json!(["CMD", "true"]));
        assert_eq!(joined["Domainname"], "lan");
        // Its own network: as before, plus what was dropped.
        let own = super::create_body(&info("bridge"), "bridge", json!({"bridge": {"Aliases": []}}));
        assert_eq!(own["Hostname"], "4c1e1a2b3c4d");
        assert_eq!(own["HostConfig"]["PortBindings"]["80/tcp"][0]["HostPort"], "8080");
        assert_eq!(own["HostConfig"]["Dns"], json!(["1.1.1.1"]));
        assert_eq!(own["HostConfig"]["Ulimits"][0]["Name"], "nofile");
        assert_eq!(own["StopTimeout"], 5);
        assert!(own["HostConfig"].as_object().unwrap().values().all(|v| !v.is_null()));
        assert!(own.as_object().unwrap().values().all(|v: &Value| !v.is_null()));
    }

    // #376: a container's anonymous volumes keep their names (their files
    // were copied under them), as a bind or in its --mount.
    #[test]
    fn names_anonymous_volumes() {
        use serde_json::json;
        let anon = "a1".repeat(32);
        let anon2 = "b2".repeat(32);
        let info = json!({
            "Config": {"Image": "postgres"},
            "HostConfig": {"Binds": ["pgconf:/etc/pg:ro"], "Mounts": [{"Type": "volume", "Source": "", "Target": "/cache"}]},
            "Mounts": [
                {"Type": "volume", "Name": "pgconf", "Destination": "/etc/pg", "RW": false},
                {"Type": "volume", "Name": anon, "Destination": "/var/lib/postgresql/data", "RW": true},
                {"Type": "volume", "Name": anon2, "Destination": "/cache", "RW": true},
                {"Type": "bind", "Source": "/Users/me/src", "Destination": "/src", "RW": true}
            ]
        });
        assert_eq!(super::volumes_of(&info), ["pgconf".to_owned(), anon.clone(), anon2.clone()]);
        let body = super::create_body(&info, "bridge", json!({}));
        assert_eq!(body["HostConfig"]["Binds"], json!(["pgconf:/etc/pg:ro", format!("{anon}:/var/lib/postgresql/data")]));
        assert_eq!(body["HostConfig"]["Mounts"][0]["Source"], anon2.as_str());
        // None at all: no Binds made up.
        let plain = super::create_body(&json!({"Config": {"Image": "alpine"}, "HostConfig": {}, "Mounts": []}), "bridge", json!({}));
        assert!(plain["HostConfig"]["Binds"].is_null());
    }

    // #377: an image pinned by digest gets its reference in the archive's
    // manifest, so Kiri knows it by that name; the rest passes unchanged.
    // (The tar crate is a test dependency of crates/kiri only.)
    #[cfg(not(windows))]
    #[test]
    fn names_an_image_pinned_by_digest() {
        let name = "ghcr.io/o/r@sha256:49dbca2bb9fc8e48bfc2cc5e039c0e867ca32012f6c739d07b8b0ad603b0d9c8";
        let layer: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        let mut b = tar::Builder::new(Vec::new());
        let mut add = |path: &str, data: &[u8], pax: bool| {
            if pax {
                b.append_pax_extensions([("size", data.len().to_string().as_bytes())]).unwrap();
            }
            let mut h = tar::Header::new_ustar();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, path, data).unwrap();
        };
        add("blobs/sha256/aa", &layer, true);
        add("manifest.json", br#"[{"Config":"blobs/sha256/cc","RepoTags":null,"Layers":["blobs/sha256/aa"]}]"#, false);
        add("index.json", b"{}", false);
        let input = b.into_inner().unwrap();
        let mut out = Vec::new();
        super::retar(input.as_slice(), &mut out, Some(name)).unwrap();
        let mut seen = Vec::new();
        for e in tar::Archive::new(out.as_slice()).entries().unwrap() {
            let mut e = e.unwrap();
            let path = e.path().unwrap().to_string_lossy().into_owned();
            let mut data = Vec::new();
            std::io::Read::read_to_end(&mut e, &mut data).unwrap();
            match path.as_str() {
                "blobs/sha256/aa" => assert_eq!(data, layer),
                "manifest.json" => {
                    let m: serde_json::Value = serde_json::from_slice(&data).unwrap();
                    assert_eq!(m[0]["RepoTags"], serde_json::json!([name]));
                    assert_eq!(m[0]["Layers"][0], "blobs/sha256/aa");
                }
                _ => assert_eq!(data, b"{}"),
            }
            seen.push(path);
        }
        assert_eq!(seen, ["blobs/sha256/aa", "manifest.json", "index.json"]);
        // Cut short: an error, never a quiet half.
        assert!(super::retar(&input[..1024], &mut Vec::new(), Some(name)).is_err());
        // A manifest that is not a list of objects is left as it is, not a panic.
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_ustar();
        h.set_size(10);
        h.set_cksum();
        b.append_data(&mut h, "manifest.json", &b"[1,\"x\",{}]"[..]).unwrap();
        let odd = b.into_inner().unwrap();
        let mut out = Vec::new();
        super::retar(odd.as_slice(), &mut out, Some(name)).unwrap();
    }
    // Big numbers in tar headers: octal while they fit, GNU base-256 after.
    #[test]
    fn writes_tar_numbers() {
        use super::{get_number, put_number};
        let mut size = [0u8; 12];
        put_number(&mut size, 0o777);
        assert_eq!(&size, b"00000000777\0");
        let big = 9 << 30;
        put_number(&mut size, big);
        assert_eq!(size, [0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x40, 0, 0, 0]);
        assert_eq!(get_number(&size), Some(big));
        let mut uid = [0u8; 8];
        put_number(&mut uid, 2_097_151);
        assert_eq!(&uid, b"7777777\0");
        put_number(&mut uid, 3_000_000);
        assert_eq!(uid, [0x80, 0, 0, 0, 0, 0x2d, 0xc6, 0xc0]);
        assert_eq!(get_number(&uid), Some(3_000_000));
        assert_eq!(get_number(b"0000644 \0"), Some(0o644));
    }

    // A stream cut off anywhere before the archive's end is an error that
    // says where: inside a pax header, inside a file's body, at a header.
    #[cfg(not(windows))]
    #[test]
    fn a_cut_stream_is_an_error() {
        let body: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
        let mut b = tar::Builder::new(Vec::new());
        b.append_pax_extensions([("uid", &b"3000000"[..])]).unwrap();
        let mut h = tar::Header::new_ustar();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "file", body.as_slice()).unwrap();
        let whole = b.into_inner().unwrap();
        // pax header, its records, the file's header, its body: then the end.
        let end = 512 + 512 + 512 + 1536;
        assert!(whole[end..].iter().all(|b| *b == 0));
        let err = |at: usize| super::retar(&whole[..at], &mut Vec::new(), None).unwrap_err().to_string();
        assert!(err(512 + 10).contains("inside a pax header"), "{}", err(512 + 10));
        assert!(err(1536 + 700).contains("inside a file's body"), "{}", err(1536 + 700));
        assert!(err(end).contains("before the archive's end"), "{}", err(end));
        for at in 0..=end {
            assert!(super::retar(&whole[..at], &mut Vec::new(), None).is_err(), "a cut at {at} passed");
        }
        super::retar(whole.as_slice(), &mut Vec::new(), None).unwrap();
    }

    // Records are read by their length: a value holding " size=" is no size.
    #[test]
    fn reads_pax_records() {
        let path = "a size=99 b";
        let rec = |k: &str, v: &str| {
            let body = format!(" {k}={v}\n");
            let mut n = body.len() + 1;
            while format!("{n}{body}").len() != n {
                n += 1;
            }
            format!("{n}{body}")
        };
        let data = format!("{}{}", rec("path", path), rec("uid", "3000000"));
        assert_eq!(super::pax_records(data.as_bytes()), [("path".to_owned(), path.to_owned()), ("uid".to_owned(), "3000000".to_owned())]);
        assert!(super::pax_records(b"garbage").is_empty());
    }

    // What `docker cp` writes for a file of 8 GiB or more, or an owner above
    // 2097151: the value only in pax, the header's field
    // zero. busybox tar reads only names from pax, so the values go into the
    // entry's own header; the bodies pass byte for byte.
    #[cfg(not(windows))]
    #[test]
    fn puts_pax_sizes_and_owners_in_the_header() {
        let body: Vec<u8> = (0..1500u32).map(|i| (i % 253) as u8).collect();
        let mut b = tar::Builder::new(Vec::new());
        // As Go's archive/tar writes it: the pax records, then a header whose
        // fields could not hold them, left zero.
        b.append_pax_extensions([("path", &b"odd size=5 name"[..]), ("size", b"1500"), ("uid", b"3000000"), ("gid", b"3000001")]).unwrap();
        let mut h = tar::Header::new_ustar();
        h.set_size(0);
        h.set_mode(0o640);
        h.set_cksum();
        let mut raw = h.as_bytes().to_vec();
        raw[..4].copy_from_slice(b"file");
        let mut fixed = [0u8; 512];
        fixed.copy_from_slice(&raw);
        let mut h = tar::Header::from_byte_slice(&fixed).clone();
        h.set_cksum();
        b.append(&h, std::io::empty()).unwrap();
        let mut input = b.into_inner().unwrap();
        // The body after the header, as the size in pax says.
        let end = input.len() - 1024;
        input.truncate(end);
        input.extend_from_slice(&body);
        input.extend(std::iter::repeat_n(0u8, 1536usize.div_ceil(512) * 512 - body.len() + 1024));
        let mut h2 = tar::Header::new_ustar();
        h2.set_size(3);
        h2.set_uid(0);
        h2.set_gid(0);
        h2.set_mtime(0);
        h2.set_mode(0o644);
        h2.set_cksum();
        let mut tail = tar::Builder::new(Vec::new());
        tail.append_data(&mut h2, "next", &b"abc"[..]).unwrap();
        let tail = tail.into_inner().unwrap();
        // Before the end blocks of the first archive: the next entry.
        let cut = input.len() - 1024;
        input.truncate(cut);
        input.extend_from_slice(&tail);
        let mut out = Vec::new();
        super::retar(input.as_slice(), &mut out, None).unwrap();
        assert_eq!(out.len(), input.len());
        // Each header as a reader that ignores pax sees it.
        let first = &out[1024..1536];
        assert_eq!(super::get_number(&first[124..136]), Some(1500));
        assert_eq!(super::get_number(&first[108..116]), Some(3_000_000));
        assert_eq!(super::get_number(&first[116..124]), Some(3_000_001));
        let sum: u32 = first.iter().enumerate().map(|(i, b)| if (148..156).contains(&i) { 32 } else { u32::from(*b) }).sum();
        assert_eq!(super::get_number(&first[148..156]), Some(u64::from(sum)));
        // Everything but that header is byte for byte as it came.
        assert_eq!(out[..1024], input[..1024]);
        assert_eq!(out[1536..], input[1536..]);
        let mut seen = Vec::new();
        for e in tar::Archive::new(out.as_slice()).entries().unwrap() {
            let mut e = e.unwrap();
            let mut data = Vec::new();
            std::io::Read::read_to_end(&mut e, &mut data).unwrap();
            seen.push((e.path().unwrap().to_string_lossy().into_owned(), e.header().uid().unwrap(), data));
        }
        assert_eq!(seen, [("odd size=5 name".to_owned(), 3_000_000, body), ("next".to_owned(), 0, b"abc".to_vec())]);
    }

    // #411: Docker Desktop's `/host_mnt/<path>` bind-mount sources map to
    // `/<path>` on macOS in both HostConfig.Binds (keeping mount options) and
    // HostConfig.Mounts, while non-/host_mnt binds and edge cases stay intact.
    #[test]
    fn translates_docker_desktop_host_mnt_binds() {
        use serde_json::json;
        let info = json!({
            "Config": {"Image": "postgres:16"},
            "HostConfig": {
                "Binds": [
                    "/host_mnt/Users/alice/project/docker/volumes/db/data:/var/lib/postgresql/data",
                    "/Users/alice/project/docker/volumes/db/pooler.sql:/docker-entrypoint-initdb.d/99-pooler.sql:ro",
                    "/host_mnt/Users/alice/app:/app:delegated",
                    "/host_mnt/private/tmp/x:/tmp/x:rw,cached",
                    "/host_mnt/Users/alice/cfg:/cfg:ro",
                    "/host_mnt/Users/alice/rw:/rw:rw",
                    "/host_mnt/Users/alice/selinux:/selinux:z",
                    "/host_mnt/Users/alice/selinux2:/selinux2:Z",
                    "/host_mnt/Users/alice/dir..name/file:/file",
                    "/host_mnt//Users/alice/double:/double",
                    "/host_mnt:/bare",
                    "/host_mnt/:/bare-slash",
                    "/host_mnt///:/bare-slashes",
                    "/host_mnt/.:/bare-dot",
                    "/host_mnt/..:/dotdot",
                    "/host_mnt/../etc:/escape",
                    "/host_mnt/Users/../etc:/mid-dotdot",
                    "/host_mnt_other/Users/alice:/other",
                    "pgdata:/pgdata"
                ],
                "Mounts": [
                    {"Type": "bind", "Source": "/host_mnt/Users/alice/data", "Target": "/data", "ReadOnly": true},
                    {"Type": "bind", "Source": "/Users/alice/plain", "Target": "/plain"},
                    {"Type": "bind", "Source": "/host_mnt", "Target": "/m-bare"},
                    {"Type": "bind", "Source": "/host_mnt/", "Target": "/m-slash"},
                    {"Type": "bind", "Source": "/host_mnt/.", "Target": "/m-dot"},
                    {"Type": "bind", "Source": "/host_mnt/..", "Target": "/m-dotdot"},
                    {"Type": "bind", "Source": "/host_mnt_other/x", "Target": "/m-other"},
                    {"Type": "volume", "Source": "pgvol", "Target": "/vol"}
                ]
            },
            "Mounts": []
        });
        let body = super::create_body_for(&info, "bridge", json!({}), false);
        assert_eq!(
            body["HostConfig"]["Binds"],
            json!([
                "/Users/alice/project/docker/volumes/db/data:/var/lib/postgresql/data",
                "/Users/alice/project/docker/volumes/db/pooler.sql:/docker-entrypoint-initdb.d/99-pooler.sql:ro",
                "/Users/alice/app:/app:delegated",
                "/private/tmp/x:/tmp/x:rw,cached",
                "/Users/alice/cfg:/cfg:ro",
                "/Users/alice/rw:/rw:rw",
                "/Users/alice/selinux:/selinux:z",
                "/Users/alice/selinux2:/selinux2:Z",
                "/Users/alice/dir..name/file:/file",
                "/Users/alice/double:/double",
                "/host_mnt:/bare",
                "/host_mnt/:/bare-slash",
                "/host_mnt///:/bare-slashes",
                "/host_mnt/.:/bare-dot",
                "/host_mnt/..:/dotdot",
                "/host_mnt/../etc:/escape",
                "/host_mnt/Users/../etc:/mid-dotdot",
                "/host_mnt_other/Users/alice:/other",
                "pgdata:/pgdata"
            ])
        );
        assert_eq!(
            body["HostConfig"]["Mounts"],
            json!([
                {"Type": "bind", "Source": "/Users/alice/data", "Target": "/data", "ReadOnly": true},
                {"Type": "bind", "Source": "/Users/alice/plain", "Target": "/plain"},
                {"Type": "bind", "Source": "/host_mnt", "Target": "/m-bare"},
                {"Type": "bind", "Source": "/host_mnt/", "Target": "/m-slash"},
                {"Type": "bind", "Source": "/host_mnt/.", "Target": "/m-dot"},
                {"Type": "bind", "Source": "/host_mnt/..", "Target": "/m-dotdot"},
                {"Type": "bind", "Source": "/host_mnt_other/x", "Target": "/m-other"},
                {"Type": "volume", "Source": "pgvol", "Target": "/vol"}
            ])
        );
    }

    // #411: Windows Docker Desktop bind sources under `/run/desktop/mnt/host/<drive>/...`
    // and `/host_mnt/<drive>/...` translate to `<DRIVE>:/...` so Kiri's WSL bind
    // parser maps them to the active automount root; `/mnt/wsl/...`, look-alikes,
    // non-drive prefixes and `..` traversals stay unchanged.
    #[test]
    fn translates_windows_docker_desktop_binds() {
        use serde_json::json;
        let info = json!({
            "Config": {"Image": "alpine"},
            "HostConfig": {
                "Binds": [
                    "/run/desktop/mnt/host/c/Users/alice/app:/app:ro",
                    "/run/desktop/mnt/host/d/work/db:/data:delegated",
                    "/run/desktop/mnt/host/c:/drive-root",
                    "/host_mnt/c/Users/alice/legacy:/legacy:rw",
                    "C:\\Users\\alice\\native:/native",
                    "/mnt/wsl/shared:/shared",
                    "/run/desktop/mnt/host:/bare",
                    "/run/desktop/mnt/host/:/bare-slash",
                    "/run/desktop/mnt/host/..:/dotdot",
                    "/run/desktop/mnt/host/c/../d/secret:/escape",
                    "/run/desktop/mnt/host/wsl/foo:/not-drive",
                    "/run/desktop/mnt/host_other/c/foo:/lookalike",
                    "/host_mnt/Users/alice:/non-drive-host-mnt",
                    "/host_mnt_other/c/foo:/host-mnt-lookalike"
                ],
                "Mounts": [
                    {"Type": "bind", "Source": "/run/desktop/mnt/host/c/Users/alice/cfg", "Target": "/cfg", "ReadOnly": true},
                    {"Type": "bind", "Source": "/host_mnt/e/files", "Target": "/files"},
                    {"Type": "bind", "Source": "/run/desktop/mnt/host/c/../x", "Target": "/bad"},
                    {"Type": "bind", "Source": "/mnt/wsl/shared", "Target": "/shared2"}
                ]
            },
            "Mounts": []
        });
        let body = super::create_body_for(&info, "bridge", json!({}), true);
        assert_eq!(
            body["HostConfig"]["Binds"],
            json!([
                "C:/Users/alice/app:/app:ro",
                "D:/work/db:/data:delegated",
                "C:/:/drive-root",
                "C:/Users/alice/legacy:/legacy:rw",
                "C:\\Users\\alice\\native:/native",
                "/mnt/wsl/shared:/shared",
                "/run/desktop/mnt/host:/bare",
                "/run/desktop/mnt/host/:/bare-slash",
                "/run/desktop/mnt/host/..:/dotdot",
                "/run/desktop/mnt/host/c/../d/secret:/escape",
                "/run/desktop/mnt/host/wsl/foo:/not-drive",
                "/run/desktop/mnt/host_other/c/foo:/lookalike",
                "/host_mnt/Users/alice:/non-drive-host-mnt",
                "/host_mnt_other/c/foo:/host-mnt-lookalike"
            ])
        );
        assert_eq!(
            body["HostConfig"]["Mounts"],
            json!([
                {"Type": "bind", "Source": "C:/Users/alice/cfg", "Target": "/cfg", "ReadOnly": true},
                {"Type": "bind", "Source": "E:/files", "Target": "/files"},
                {"Type": "bind", "Source": "/run/desktop/mnt/host/c/../x", "Target": "/bad"},
                {"Type": "bind", "Source": "/mnt/wsl/shared", "Target": "/shared2"}
            ])
        );
    }

    // #411: every container not imported has an explicit reason (never dropped
    // silently or left with a blank error).
    #[test]
    fn reports_skip_and_failure_reasons() {
        assert_eq!(super::container_skip_reason(true, false), Some("already in Kiri"));
        assert_eq!(super::container_skip_reason(false, true), Some("already imported as a network target"));
        assert_eq!(super::container_skip_reason(false, false), None);
        assert_eq!(super::create_error(400, "bind source path does not exist"), "bind source path does not exist");
        assert_eq!(super::create_error(500, "   "), "HTTP 500");
        assert_eq!(
            super::format_failures(&[("container", "db".into(), "bind source path does not exist".into())]),
            "1 item could not be imported:\n  container db: bind source path does not exist"
        );
        assert_eq!(
            super::format_failures(&[
                ("container", "db".into(), "missing bind".into()),
                ("container", "web".into(), "".into()),
            ]),
            "2 items could not be imported:\n  container db: missing bind\n  container web: unknown error"
        );
    }

    #[test]
    fn updates_pax_size_for_manifest_and_keeps_raw_pax_when_unchanged() {
        let name = "ghcr.io/o/r@sha256:49dbca2bb9fc8e48bfc2cc5e039c0e867ca32012f6c739d07b8b0ad603b0d9c8";
        let manifest = br#"[{"Config":"blobs/sha256/cc","RepoTags":null,"Layers":["blobs/sha256/aa"]}]"#;
        let entry = |prefix: &[u8], path: &[u8], typeflag: u8, body: &[u8]| {
            let mut h = [0u8; 512];
            h[..path.len()].copy_from_slice(path);
            h[345..345 + prefix.len()].copy_from_slice(prefix);
            super::put_number(&mut h[100..108], 0o644);
            super::put_number(&mut h[124..136], body.len() as u64);
            h[156] = typeflag;
            h[257..263].copy_from_slice(b"ustar\0");
            h[263..265].copy_from_slice(b"00");
            super::update_checksum(&mut h);
            let mut out = Vec::new();
            super::write_small(&mut out, &h, body).unwrap();
            out
        };
        let assert_valid_checksums = |tar_bytes: &[u8]| {
            for block in tar_bytes.chunks_exact(512).filter(|b| b.iter().any(|c| *c != 0) && &b[257..263] == b"ustar\0") {
                let mut check: [u8; 512] = block.try_into().unwrap();
                let got = check[148..156].to_vec();
                super::update_checksum(&mut check);
                assert_eq!(got, check[148..156]);
            }
        };

        // 1. PAX header with `size`, `mtime`, `path=./manifest.json`, and raw binary xattr:
        //    rewrites `size` + header size + checksum while keeping binary xattr bytes intact,
        //    and leaves the following `index.json` entry aligned.
        let bin_xattr = b"29 SCHILY.xattr.user.bin=\x00\xff\xfe\n";
        assert_eq!(bin_xattr.len(), 29);
        let mut pax = Vec::new();
        pax.extend_from_slice(&super::pax_record("mtime", "1700000000.5"));
        pax.extend_from_slice(bin_xattr);
        pax.extend_from_slice(&super::pax_record("path", "./manifest.json"));
        pax.extend_from_slice(&super::pax_record("size", &manifest.len().to_string()));
        let mut input = entry(b"", b"PaxHeader/manifest", b'x', &pax);
        input.extend_from_slice(&entry(b"", b"truncated_name", b'0', manifest));
        input.extend_from_slice(&entry(b"", b"index.json", b'0', b"{}"));
        input.extend_from_slice(&[0u8; 1024]);

        let mut out = Vec::new();
        super::retar(input.as_slice(), &mut out, Some(name)).unwrap();
        assert_valid_checksums(&out);

        let pax_len = super::get_number(&out[124..136]).unwrap() as usize;
        let pax_payload = &out[512..512 + pax_len];
        assert!(pax_payload.windows(bin_xattr.len()).any(|w| w == bin_xattr), "raw binary xattr preserved");
        assert!(out[512 + pax_len..1024].iter().all(|b| *b == 0));
        let recs = super::pax_records(pax_payload);
        let pax_size: usize = recs.iter().rfind(|(k, _)| k == "size").unwrap().1.parse().unwrap();
        let ustar_size = super::get_number(&out[1024 + 124..1024 + 136]).unwrap() as usize;
        assert_eq!(pax_size, ustar_size);
        assert!(pax_size > manifest.len());
        let m: serde_json::Value = serde_json::from_slice(&out[1536..1536 + pax_size]).unwrap();
        assert_eq!(m[0]["RepoTags"], serde_json::json!([name]));
        let next_hdr = 1536 + pax_size.next_multiple_of(512);
        assert_eq!(&out[next_hdr..next_hdr + 11], b"index.json\0");
        assert_eq!(&out[next_hdr + 512..next_hdr + 514], b"{}");

        #[cfg(not(windows))]
        {
            let mut seen = Vec::new();
            for e in tar::Archive::new(out.as_slice()).entries().unwrap() {
                let mut e = e.unwrap();
                let p = e.path().unwrap().to_string_lossy().into_owned();
                let mut body = Vec::new();
                std::io::Read::read_to_end(&mut e, &mut body).unwrap();
                seen.push((p, body));
            }
            assert_eq!(seen.len(), 2);
            assert_eq!(seen[0].0.trim_start_matches("./"), "manifest.json");
            let parsed: serde_json::Value = serde_json::from_slice(&seen[0].1).unwrap();
            assert_eq!(parsed[0]["RepoTags"], serde_json::json!([name]));
            assert_eq!(seen[1], ("index.json".to_owned(), b"{}".to_vec()));
        }

        // 2. PAX header WITHOUT `size` on `manifest.json` (matched via USTAR prefix `.` + `manifest.json`
        //    when no PAX `path` is set): raw PAX header & payload stay byte-for-byte unchanged.
        let mut pax_no_size = Vec::new();
        pax_no_size.extend_from_slice(&super::pax_record("mtime", "1700000000.25"));
        pax_no_size.extend_from_slice(bin_xattr);
        let raw_pax_blocks = entry(b"", b"PaxHeader/manifest.json", b'x', &pax_no_size);
        let mut input2 = raw_pax_blocks.clone();
        input2.extend_from_slice(&entry(b".", b"manifest.json", b'0', manifest));
        input2.extend_from_slice(&[0u8; 1024]);
        let mut out2 = Vec::new();
        super::retar(input2.as_slice(), &mut out2, Some(name)).unwrap();
        assert_eq!(&out2[..raw_pax_blocks.len()], raw_pax_blocks.as_slice(), "PAX header untouched when no size record");
        let ustar_size2 = super::get_number(&out2[1024 + 124..1024 + 136]).unwrap() as usize;
        let m2: serde_json::Value = serde_json::from_slice(&out2[1536..1536 + ustar_size2]).unwrap();
        assert_eq!(m2[0]["RepoTags"], serde_json::json!([name]));

        // 3. PAX `size` already matches rewritten `manifest.json` length: raw PAX bytes stay untouched.
        let already = serde_json::to_vec(&serde_json::json!([{"Config":"blobs/sha256/cc","Layers":["blobs/sha256/aa"],"RepoTags":[name]}])).unwrap();
        let mut pax_same = Vec::new();
        pax_same.extend_from_slice(bin_xattr);
        pax_same.extend_from_slice(&super::pax_record("size", &already.len().to_string()));
        let same_pax_blocks = entry(b"", b"PaxHeader/manifest.json", b'x', &pax_same);
        let mut input3 = same_pax_blocks.clone();
        input3.extend_from_slice(&entry(b"", b"manifest.json", b'0', &already));
        input3.extend_from_slice(&[0u8; 1024]);
        let mut out3 = Vec::new();
        super::retar(input3.as_slice(), &mut out3, Some(name)).unwrap();
        assert_eq!(&out3[..same_pax_blocks.len()], same_pax_blocks.as_slice(), "PAX header untouched when size unchanged");
    }

    #[test]
    fn pax_rfind_precedence_and_consecutive_x_headers() {
        let name = "ghcr.io/o/r@sha256:49dbca2bb9fc8e48bfc2cc5e039c0e867ca32012f6c739d07b8b0ad603b0d9c8";
        let manifest = br#"[{"Config":"blobs/sha256/cc","RepoTags":null,"Layers":["blobs/sha256/aa"]}]"#;
        let entry = |path: &[u8], typeflag: u8, size_override: Option<u64>, body: &[u8]| {
            let mut h = [0u8; 512];
            h[..path.len()].copy_from_slice(path);
            super::put_number(&mut h[100..108], 0o644);
            super::put_number(&mut h[124..136], size_override.unwrap_or(body.len() as u64));
            h[156] = typeflag;
            h[257..263].copy_from_slice(b"ustar\0");
            h[263..265].copy_from_slice(b"00");
            super::update_checksum(&mut h);
            let mut out = Vec::new();
            super::write_small(&mut out, &h, body).unwrap();
            out
        };

        // 1. Duplicate keys in one PAX header: last `size`, `uid`, `gid`, and `path` win (`rfind`).
        let mut dup_pax = Vec::new();
        dup_pax.extend_from_slice(&super::pax_record("size", "99999"));
        dup_pax.extend_from_slice(&super::pax_record("size", "5"));
        dup_pax.extend_from_slice(&super::pax_record("uid", "111"));
        dup_pax.extend_from_slice(&super::pax_record("uid", "3000000"));
        dup_pax.extend_from_slice(&super::pax_record("gid", "222"));
        dup_pax.extend_from_slice(&super::pax_record("gid", "3000001"));
        dup_pax.extend_from_slice(&super::pax_record("path", "manifest.json"));
        dup_pax.extend_from_slice(&super::pax_record("path", "sub/manifest.json"));
        let mut input = entry(b"manifest.json", b'x', None, &dup_pax);
        // Even though USTAR says `manifest.json` and the first PAX `path` said `manifest.json`,
        // the last PAX `path` is `sub/manifest.json`, so `retar` must NOT parse `hello` as JSON.
        input.extend_from_slice(&entry(b"manifest.json", b'0', Some(0), b"hello"));
        input.extend_from_slice(&[0u8; 1024]);
        let mut out = Vec::new();
        super::retar(input.as_slice(), &mut out, Some(name)).unwrap();
        let file_hdr = &out[1024..1536];
        assert_eq!(super::get_number(&file_hdr[124..136]), Some(5));
        assert_eq!(super::get_number(&file_hdr[108..116]), Some(3_000_000));
        assert_eq!(super::get_number(&file_hdr[116..124]), Some(3_000_001));
        assert_eq!(&out[1536..1541], b"hello");

        // 2. Consecutive `'x'` headers before `manifest.json`, plus trailing `'x'` before EOF:
        //    first `'x'` carries `path` + `size` + `uid=100`, second `'x'` overrides `uid=3000002`
        //    and has no `size` of its own; both `'x'` headers are emitted and the second gets the
        //    updated `size` so downstream PAX readers see the rewritten manifest length.
        let mut pax1 = Vec::new();
        pax1.extend_from_slice(&super::pax_record("path", "other.txt"));
        pax1.extend_from_slice(&super::pax_record("path", "manifest.json"));
        pax1.extend_from_slice(&super::pax_record("uid", "100"));
        pax1.extend_from_slice(&super::pax_record("gid", "3000005"));
        pax1.extend_from_slice(&super::pax_record("size", &manifest.len().to_string()));
        let mut pax2 = Vec::new();
        pax2.extend_from_slice(&super::pax_record("uid", "3000002"));
        pax2.extend_from_slice(&super::pax_record("mtime", "1700000001"));
        let orphan_pax = super::pax_record("comment", "trailing-before-eof");

        let x1 = entry(b"PaxHeader/1", b'x', None, &pax1);
        let x2 = entry(b"PaxHeader/2", b'x', None, &pax2);
        let x_eof = entry(b"PaxHeader/eof", b'x', None, &orphan_pax);
        let mut input2 = Vec::new();
        input2.extend_from_slice(&x1);
        input2.extend_from_slice(&x2);
        input2.extend_from_slice(&entry(b"ignored", b'0', Some(0), manifest));
        input2.extend_from_slice(&x_eof);
        input2.extend_from_slice(&[0u8; 1024]);

        let mut out2 = Vec::new();
        super::retar(input2.as_slice(), &mut out2, Some(name)).unwrap();
        // First `'x'` flushed intact at offset 0.
        assert_eq!(&out2[..1024], x1.as_slice());
        // Second `'x'` at offset 1024 carries the updated `size` overriding `x1`.
        let pax2_len = super::get_number(&out2[1024 + 124..1024 + 136]).unwrap() as usize;
        let recs2 = super::pax_records(&out2[1536..1536 + pax2_len]);
        let updated_size: usize = recs2.iter().rfind(|(k, _)| k == "size").unwrap().1.parse().unwrap();
        // Manifest USTAR header at offset 2048 has overridden uid from `x2`, gid from `x1`, and updated size.
        let mh = &out2[2048..2560];
        assert_eq!(super::get_number(&mh[108..116]), Some(3_000_002));
        assert_eq!(super::get_number(&mh[116..124]), Some(3_000_005));
        assert_eq!(super::get_number(&mh[124..136]), Some(updated_size as u64));
        let m: serde_json::Value = serde_json::from_slice(&out2[2560..2560 + updated_size]).unwrap();
        assert_eq!(m[0]["RepoTags"], serde_json::json!([name]));
        // Orphan `'x'` before EOF is flushed intact right before the 1024-byte zero trailer.
        let orphan_off = 2560 + updated_size.next_multiple_of(512);
        assert_eq!(&out2[orphan_off..orphan_off + 1024], x_eof.as_slice());
        assert_eq!(&out2[orphan_off + 1024..], &[0u8; 1024]);

        // Also verify `read_entry` resolves consecutive `'x'` headers + rewritten `size` cleanly.
        let mut reader = out2.as_slice();
        let e = super::read_entry(&mut reader).unwrap().unwrap();
        assert_eq!(e.name, "manifest.json");
        assert_eq!(e.size, updated_size as u64);
    }

    #[test]
    fn rejects_malformed_base256_and_overflow_tar_headers() {
        assert_eq!(super::get_number(&[]), None);
        assert_eq!(super::get_number(&[0x80, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), Some(u64::MAX));
        assert_eq!(super::get_number(&[0x80, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00]), Some(u64::MAX - 511));
        for bad_num in [
            [0xff; 12],
            [0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x81, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 2, 0],
            [0x80, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ] {
            assert_eq!(super::get_number(&bad_num), None, "{bad_num:?}");
        }

        // Damaged / overflowing base-256 sizes on both `'0'` and `'x'` headers fail cleanly
        // without wrapping `padded` to 0.
        for typeflag in [b'0', b'x'] {
            for bad in [
                // u64::MAX and u64::MAX - 510: valid u64, overflows `checked_next_multiple_of(512)`
                [0x80, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                [0x80, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x01],
                // Negative base-256 (`field[0] != 0x80`)
                [0xff; 12],
                [0x81, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                // >64-bit positive base-256
                [0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 2, 0],
            ] {
                let mut raw = vec![0u8; 1536];
                raw[..4].copy_from_slice(b"bad\0");
                raw[124..136].copy_from_slice(&bad);
                raw[156] = typeflag;
                raw[257..263].copy_from_slice(b"ustar\0");
                raw[263..265].copy_from_slice(b"00");
                super::update_checksum(raw[..512].as_mut().try_into().unwrap());
                let err = super::retar(raw.as_slice(), &mut Vec::new(), None).unwrap_err();
                assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{typeflag:?} {bad:?}: {err}");
                let mut r = raw.as_slice();
                assert!(super::read_entry(&mut r).is_err(), "read_entry {typeflag:?} {bad:?}");
            }
        }

        // Overflowing size supplied via a PAX `size` record (`u64::MAX`) is also rejected.
        let pax_overflow = super::pax_record("size", &u64::MAX.to_string());
        let mut px_h = super::plain_header(b'x', "PaxHeader/overflow", pax_overflow.len() as u64, 0o644);
        super::update_checksum(&mut px_h);
        let mut f_h = super::plain_header(b'0', "overflow.bin", 0, 0o644);
        super::update_checksum(&mut f_h);
        let mut stream = Vec::new();
        super::write_small(&mut stream, &px_h, &pax_overflow).unwrap();
        stream.extend_from_slice(&f_h);
        stream.extend_from_slice(&[0u8; 1024]);
        assert_eq!(super::retar(stream.as_slice(), &mut Vec::new(), None).unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        let mut sr = stream.as_slice();
        assert!(super::read_entry(&mut sr).is_err());
    }

}
