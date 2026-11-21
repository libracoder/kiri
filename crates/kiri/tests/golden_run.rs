//! The golden RUN vectors (`golden/vectors/run.json`, `xattr.json`,
//! recorded from BuildKit v0.33.1) against Kiri's engine: each case's
//! Dockerfile is built by the builder core on the engine's plug-in points
//! (`POST /kiri/build/golden`, an engine built with `--features
//! build-test-routes` and started with `KIRI_BUILD_PORTS_TEST=1`), so every RUN goes through the engine's step
//! runner and its step layer writer, and the answer is compared with
//! BuildKit's: the layers after the base entry by entry (and byte for byte
//! where the vector pins every byte), whiteouts, failures and their
//! messages, and the process the step saw.
//!
//! It needs a real engine, so it runs only when `KIRI_GOLDEN_SOCKET` names
//! the engine's socket; the base images are pulled from a registry at
//! `KIRI_GOLDEN_REGISTRY` (default `localhost:5000`) that serves the pinned
//! digests (the mirror the builder test data sets up), as
//! `<registry>/library/<name>`. `KIRI_GOLDEN_ONLY` keeps the cases whose name
//! contains it. The vectors come from the builder test data (`test_data`:
//! `KIRI_TEST_DATA` or `tests/data-cache`).
//!
//! What is not compared, and why:
//! - the setup COPY layers' own bytes (COPY is the copy rules' part, checked
//!   by its own vectors); a RUN layer is compared against them as its lower;
//! - mtimes of class `new` (set while the build ran) and `context:` (the
//!   generator's context times, not recorded): only their class;
//! - the process view's fields that belong to BuildKit's own sandbox and not
//!   to the Dockerfile's meaning: `OTEL_*` and `TRACEPARENT` in the env and
//!   the `/dev/otel-grpc.sock` mount (standalone buildkitd adds them, Docker
//!   Desktop's does not), pids, mount sources and the resolver (masked in
//!   the vectors too).
//!
//! Unix only: it reaches the engine on its Unix socket, and on Windows the
//! engine runs inside WSL, where this test runs as the Linux build.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::UnixStream;
use std::path::Path;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[path = "../../../tests/support/test_data.rs"]
mod test_data;

fn post(socket: &str, path: &str, body: &Value) -> Value {
    let mut s = UnixStream::connect(socket).unwrap_or_else(|e| panic!("connect {socket}: {e}"));
    let body = body.to_string();
    write!(s, "POST {path} HTTP/1.1\r\nHost: kiri\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    let at = out.windows(4).position(|w| w == b"\r\n\r\n").expect("an HTTP answer") + 4;
    let head = String::from_utf8_lossy(&out[..at]).to_ascii_lowercase();
    let mut bytes = out[at..].to_vec();
    if head.contains("transfer-encoding: chunked") {
        let mut plain = Vec::new();
        let mut rest = &bytes[..];
        loop {
            let nl = rest.windows(2).position(|w| w == b"\r\n").unwrap();
            let n = usize::from_str_radix(std::str::from_utf8(&rest[..nl]).unwrap().trim(), 16).unwrap();
            if n == 0 {
                break;
            }
            plain.extend_from_slice(&rest[nl + 2..nl + 2 + n]);
            rest = &rest[nl + 4 + n..];
        }
        bytes = plain;
    }
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&bytes)))
}

fn set_xattr(p: &Path, name: &str, value: &[u8]) {
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
    let n = std::ffi::CString::new(name).unwrap();
    // SAFETY: valid NUL-terminated path and name, value of the given length.
    #[cfg(target_os = "linux")]
    let r = unsafe { libc::lsetxattr(c.as_ptr(), n.as_ptr(), value.as_ptr().cast(), value.len(), 0) };
    // macOS has no lsetxattr: the plain call, not following a link.
    // SAFETY: as above.
    #[cfg(not(target_os = "linux"))]
    let r = unsafe { libc::setxattr(c.as_ptr(), n.as_ptr(), value.as_ptr().cast(), value.len(), 0, libc::XATTR_NOFOLLOW) };
    assert_eq!(r, 0, "setxattr {name} on {}: {}", p.display(), std::io::Error::last_os_error());
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The case's context tree, as the generator made it.
fn materialise(v: &Value, dir: &Path, probe: &[u8]) {
    let _ = fs::remove_dir_all(dir);
    fs::create_dir_all(dir).unwrap();
    for e in v["context"].as_array().into_iter().flatten() {
        let p = dir.join(e["path"].as_str().unwrap());
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        match e["type"].as_str().unwrap_or("file") {
            "dir" => fs::create_dir_all(&p).unwrap(),
            "symlink" => symlink(e["target"].as_str().unwrap(), &p).unwrap(),
            "hardlink" => fs::hard_link(dir.join(e["target"].as_str().unwrap()), &p).unwrap(),
            _ => fs::write(&p, e["content"].as_str().unwrap_or_default()).unwrap(),
        }
        if let Some(m) = e["mode"].as_str() {
            fs::set_permissions(&p, fs::Permissions::from_mode(u32::from_str_radix(m, 8).unwrap())).unwrap();
        }
        for (k, x) in e["xattrs"].as_object().into_iter().flatten() {
            set_xattr(&p, k, x.as_str().unwrap().as_bytes());
        }
        for (k, x) in e["xattrs_hex"].as_object().into_iter().flatten() {
            set_xattr(&p, k, &unhex(x.as_str().unwrap()));
        }
    }
    if v["probe"].as_bool() == Some(true) {
        fs::write(dir.join("kp.py"), probe).unwrap();
        fs::set_permissions(dir.join("kp.py"), fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::write(dir.join("Dockerfile"), v["dockerfile"].as_str().unwrap()).unwrap();
}

/// One tar entry as the vectors describe them.
#[derive(Debug, Default, Clone)]
struct TarEntry {
    name: Vec<u8>,
    typeflag: u8,
    format: &'static str,
    mode: u32,
    uid: u64,
    gid: u64,
    size: u64,
    mtime: i64,
    linkname: Vec<u8>,
    devmajor: u64,
    devminor: u64,
    pax: BTreeMap<String, Vec<u8>>,
    pax_header_name: Option<Vec<u8>>,
    body: Vec<u8>,
    /// Offset of the main header, for the mtime normalisation.
    header_at: usize,
}

fn field(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|c| *c == 0).unwrap_or(b.len())]
}

fn octal(b: &[u8]) -> u64 {
    let s = String::from_utf8_lossy(field(b));
    u64::from_str_radix(s.trim(), 8).unwrap_or(0)
}

/// Reads a layer tar block by block, the way Go's reader reports it.
fn read_tar(t: &[u8]) -> Vec<TarEntry> {
    let mut out = Vec::new();
    let mut at = 0;
    let mut pax: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut pax_name = None;
    while at + 512 <= t.len() {
        let h = &t[at..at + 512];
        if h.iter().all(|b| *b == 0) {
            break;
        }
        let size = octal(&h[124..136]);
        let data = &t[at + 512..at + 512 + size as usize];
        let next = at + 512 + (size as usize).div_ceil(512) * 512;
        if h[156] == b'x' {
            let mut rest = data;
            while !rest.is_empty() {
                let sp = rest.iter().position(|c| *c == b' ').unwrap();
                let n: usize = std::str::from_utf8(&rest[..sp]).unwrap().parse().unwrap();
                let rec = &rest[sp + 1..n - 1];
                let eq = rec.iter().position(|c| *c == b'=').unwrap();
                pax.insert(String::from_utf8_lossy(&rec[..eq]).into_owned(), rec[eq + 1..].to_vec());
                rest = &rest[n..];
            }
            pax_name = Some(field(&h[0..100]).to_vec());
            at = next;
            continue;
        }
        let prefix = field(&h[345..500]);
        let mut name = if prefix.is_empty() { field(&h[0..100]).to_vec() } else { [prefix, b"/", field(&h[0..100])].concat() };
        let mut linkname = field(&h[157..257]).to_vec();
        let (mut uid, mut gid, mut mtime) = (octal(&h[108..116]), octal(&h[116..124]), octal(&h[136..148]) as i64);
        let format = if pax.is_empty() { "ustar" } else { "pax" };
        if let Some(p) = pax.get("path") {
            name = p.clone();
        }
        if let Some(p) = pax.get("linkpath") {
            linkname = p.clone();
        }
        let num = |k: &str| pax.get(k).map(|v| String::from_utf8_lossy(v).parse::<i64>().unwrap());
        if let Some(x) = num("uid") {
            uid = x as u64;
        }
        if let Some(x) = num("gid") {
            gid = x as u64;
        }
        if let Some(x) = num("mtime") {
            mtime = x;
        }
        out.push(TarEntry {
            name,
            typeflag: h[156],
            format,
            mode: octal(&h[100..108]) as u32,
            uid,
            gid,
            size,
            mtime,
            linkname,
            devmajor: octal(&h[329..337]),
            devminor: octal(&h[337..345]),
            pax: std::mem::take(&mut pax),
            pax_header_name: pax_name.take(),
            body: data.to_vec(),
            header_at: at,
        });
        at = next;
    }
    out
}

/// Seconds since the epoch of `YYYY-MM-DDTHH:MM:SSZ`.
fn rfc3339(s: &str) -> i64 {
    let n = |a: usize, b: usize| s[a..b].parse::<i64>().unwrap();
    let (y, m, d) = (n(0, 4), n(5, 7), n(8, 10));
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    days * 86_400 + n(11, 13) * 3600 + n(14, 16) * 60 + n(17, 19)
}

/// The tar with every `new` entry's mtime set to 2020-01-01, as the
/// vectors' `diff_id_normalized` is made.
fn normalised(tar: &[u8], ours: &[TarEntry], classes: &[&str]) -> String {
    let mut t = tar.to_vec();
    for (e, c) in ours.iter().zip(classes) {
        if *c != "new" {
            continue;
        }
        let h = &mut t[e.header_at..e.header_at + 512];
        h[136..148].copy_from_slice(b"13602760400\0");
        h[148..156].fill(b' ');
        let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    }
    format!("sha256:{}", hex(&Sha256::digest(&t)))
}

/// What differs between our entry and the vector's (`want`); `lower` is
/// the mtime each path had in the layers below ours.
fn entry_diffs(ours: &TarEntry, want: &Value, lower: &BTreeMap<Vec<u8>, i64>) -> Vec<String> {
    let mut d = Vec::new();
    let name = String::from_utf8_lossy(&ours.name).into_owned();
    let mut check = |what: &str, ok: bool, got: String, w: &Value| {
        if !ok {
            d.push(format!("{name}: {what} {got} != {w}"));
        }
    };
    if let Some(w) = want.get("typeflag") {
        check("typeflag", w.as_str() == Some(&(ours.typeflag as char).to_string()), (ours.typeflag as char).to_string(), w);
    }
    if let Some(w) = want.get("format") {
        check("format", w.as_str() == Some(ours.format), ours.format.into(), w);
    }
    if let Some(w) = want.get("mode") {
        check("mode", w.as_str().map(|m| u32::from_str_radix(m, 8).unwrap()) == Some(ours.mode), format!("{:04o}", ours.mode), w);
    }
    for (k, v) in [("uid", ours.uid), ("gid", ours.gid), ("size", ours.size), ("devmajor", ours.devmajor), ("devminor", ours.devminor)] {
        if let Some(w) = want.get(k) {
            check(k, w.as_u64() == Some(v), v.to_string(), w);
        }
    }
    if let Some(w) = want.get("linkname") {
        check("linkname", w.as_str().map(str::as_bytes) == Some(&ours.linkname[..]), String::from_utf8_lossy(&ours.linkname).into(), w);
    }
    if let Some(w) = want.get("content") {
        check("content", w.as_str().map(str::as_bytes) == Some(&ours.body[..]), format!("{:?}", String::from_utf8_lossy(&ours.body)), w);
    }
    if let Some(w) = want.get("sha256") {
        let got = format!("sha256:{}", hex(&Sha256::digest(&ours.body)));
        check("sha256", w.as_str() == Some(got.as_str()) || w.as_str() == Some(&got[7..]), got.clone(), w);
    }
    if let Some(w) = want.get("pax_header_name") {
        let got = ours.pax_header_name.clone().unwrap_or_default();
        check("pax header name", w.as_str().map(str::as_bytes) == Some(&got[..]), String::from_utf8_lossy(&got).into(), w);
    }
    let text_pax: BTreeMap<&String, &Vec<u8>> = ours.pax.iter().filter(|(k, _)| !k.starts_with("SCHILY.xattr.")).collect();
    let hex_pax: BTreeMap<&String, String> = ours.pax.iter().filter(|(k, _)| k.starts_with("SCHILY.xattr.")).map(|(k, v)| (k, hex(v))).collect();
    let want_text: BTreeMap<String, Vec<u8>> = want["pax"].as_object().into_iter().flatten().map(|(k, v)| (k.clone(), v.as_str().unwrap().as_bytes().to_vec())).collect();
    let want_hex: BTreeMap<String, String> = want["pax_hex"].as_object().into_iter().flatten().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned())).collect();
    if want.get("format").is_some() || want.get("pax").is_some() {
        check("pax", text_pax.iter().map(|(k, v)| ((*k).clone(), (*v).clone())).collect::<BTreeMap<_, _>>() == want_text, format!("{text_pax:?}"), &want["pax"]);
    }
    if want.get("format").is_some() || want.get("pax_hex").is_some() {
        check("pax_hex", hex_pax.iter().map(|(k, v)| ((*k).clone(), v.clone())).collect::<BTreeMap<_, _>>() == want_hex, format!("{hex_pax:?}"), &want["pax_hex"]);
    }
    if let Some(class) = want["mtime"].as_str() {
        if let Some(t) = class.strip_prefix("fixed:") {
            check("mtime", rfc3339(t) == ours.mtime, ours.mtime.to_string(), &want["mtime"]);
        } else if class == "lower" {
            let below = lower.get(ours.name.strip_suffix(b"/").unwrap_or(&ours.name)).copied();
            check("mtime (lower)", below == Some(ours.mtime), format!("{} (below {below:?})", ours.mtime), &want["mtime"]);
        }
    }
    d
}

/// The probe's raw view as the vectors record it (the generator's
/// `maskProbe` in `golden/gen/run.go` of the test data, the fields compared here):
/// /etc/hosts as lines, mountinfo as mount points.
fn recorded(mut v: Value) -> Value {
    if let Some(h) = v["etc_hosts"].as_str() {
        v["etc_hosts"] = json!(h.trim_end_matches('\n').split('\n').collect::<Vec<_>>());
    }
    if let Some(mi) = v["mountinfo"].as_str() {
        let points: Vec<Value> = mi
            .trim()
            .lines()
            .map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                // mountinfo escapes space, tab, newline and backslash as \ooo.
                let p = f.get(4).copied().unwrap_or("<unparsed>").replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\");
                json!({"mount_point": p})
            })
            .collect();
        v["mounts"] = json!(points);
    }
    v
}

/// The probe lines of a step's stdout, parsed, and the rest of it.
fn split_probe(stdout: &str) -> (Vec<Value>, String) {
    let mut probes = Vec::new();
    let mut rest = String::new();
    for line in stdout.split_inclusive('\n') {
        match line.strip_prefix("KIRI-PROBE ") {
            Some(j) => probes.push(recorded(serde_json::from_str(j.trim_end()).unwrap_or(Value::Null))),
            None => rest.push_str(line),
        }
    }
    (probes, rest)
}

/// BuildKit's own sandbox additions, which the vectors record and Kiri
/// must not copy.
fn sandbox_env(e: &str) -> bool {
    e.starts_with("OTEL_") || e.starts_with("TRACEPARENT=")
}

/// What differs between our probe view and BuildKit's, field by field.
fn probe_diffs(ours: &Value, want: &Value) -> Vec<String> {
    let mut d = Vec::new();
    if let Some(x) = want.get("xattrs") {
        if ours.get("xattrs") != Some(x) {
            d.push(format!("xattrs {} != {x}", ours["xattrs"]));
        }
        return d;
    }
    for k in ["argv", "pid1_argv", "parent_argv", "cwd", "uid", "euid", "gid", "egid", "groups", "hostname", "stdin", "stdout", "stderr", "stdin_read", "rlimits", "oom_score_adj", "etc_hosts"] {
        if want.get(k).is_some() && ours.get(k) != want.get(k) {
            d.push(format!("{k}: {} != {}", ours[k], want[k]));
        }
    }
    let env = |v: &Value| -> Vec<String> { v["env"].as_array().into_iter().flatten().filter_map(Value::as_str).filter(|e| !sandbox_env(e)).map(str::to_owned).collect() };
    if env(ours) != env(want) {
        d.push(format!("env: {:?} != {:?}", env(ours), env(want)));
    }
    if ours["env"].as_array().into_iter().flatten().filter_map(Value::as_str).any(sandbox_env) {
        d.push("env carries BuildKit's OTEL/TRACEPARENT".into());
    }
    for k in ["Umask", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp"] {
        if want["status"].get(k).is_some() && ours["status"].get(k) != want["status"].get(k) {
            d.push(format!("status {k}: {} != {}", ours["status"][k], want["status"][k]));
        }
    }
    // As a set: the order is the runtime's mount order, which only
    // /proc/self/mountinfo shows; what is mounted where is compared.
    let points = |v: &Value| -> std::collections::BTreeSet<String> {
        v["mounts"].as_array().into_iter().flatten().filter_map(|m| m["mount_point"].as_str()).filter(|p| *p != "/dev/otel-grpc.sock").map(str::to_owned).collect()
    };
    if want.get("mounts").is_some() && points(ours) != points(want) {
        d.push(format!("mount points: {:?} != {:?}", points(ours), points(want)));
    }
    d
}

/// Cases whose `correct` the parity rule supersedes ("Kiri must not
/// behave in ways Docker does not"): BuildKit's own answer is compared.
/// `layer/mtime-dir`: a folder whose mtime alone changed is left out, as
/// BuildKit's sameDirent leaves it out.
const SUPERSEDED: &[&str] = &["layer/mtime-dir"];

/// Runs one case; the differences, empty when it matches.
fn run_case(socket: &str, registry: &str, v: &Value, probe: &[u8], dir: &Path) -> Vec<String> {
    let mut d = Vec::new();
    materialise(v, dir, probe);
    let mut dockerfile = v["dockerfile"].as_str().unwrap().to_owned();
    // The pinned base images, from the registry that serves those digests.
    for name in ["alpine", "busybox", "python"] {
        dockerfile = dockerfile.replace(&format!("FROM {name}:"), &format!("FROM {registry}/library/{name}:"));
        dockerfile = dockerfile.replace(&format!("--from={name}:"), &format!("--from={registry}/library/{name}:"));
    }
    let skip = v["base"]["diff_ids"].as_array().map_or(0, Vec::len);
    let got = post(
        socket,
        "/kiri/build/golden",
        &json!({"dockerfile": dockerfile, "context": dir.to_str().unwrap(), "build_args": v["build_args"], "target": v["target"], "skip": skip}),
    );
    if let Some(why) = got.get("unsupported") {
        return vec![format!("the native builder does not cover it: {why}")];
    }
    let ours_steps: BTreeMap<String, &Value> = got["steps"].as_array().into_iter().flatten().map(|s| (s["name"].as_str().unwrap_or_default().to_owned(), s)).collect();
    let refused = v["correct"]["kind"].as_str() == Some("refuse_or_escape");
    // The build's outcome.
    match (v.get("error"), got.get("error")) {
        (Some(w), Some(o)) => {
            let want = w["message"].as_str().unwrap().trim_start_matches("failed to solve: ");
            if o.as_str() != Some(want) {
                d.push(format!("error {o} != {want:?}"));
            }
        }
        (Some(w), None) => d.push(format!("built, BuildKit failed: {}", w["message"])),
        (None, Some(o)) if refused => {
            let need = v["correct"]["if_refused"]["error_contains"].as_str().unwrap_or_default();
            if !o.as_str().unwrap_or_default().contains(need) {
                d.push(format!("refused, but the error {o} does not name {need:?}"));
            }
            return d;
        }
        (None, Some(o)) => d.push(format!("failed: {o}")),
        (None, None) if refused => d.push("built with `.wh.` names neither refused nor escaped".into()),
        (None, None) => {}
    }
    // Each RUN step: its error, output and process view.
    for w in v["steps"].as_array().into_iter().flatten() {
        let name = w["name"].as_str().unwrap();
        let Some(o) = ours_steps.get(name) else {
            if got.get("error").is_none() || w.get("error").is_some() {
                d.push(format!("no step named {name:?} (have {:?})", ours_steps.keys().collect::<Vec<_>>()));
            }
            continue;
        };
        if let Some(e) = w.get("error") {
            if o.get("error") != Some(e) {
                d.push(format!("{name}: error {} != {e}", o["error"]));
            }
            // A process that cannot start: exit code 1 and the runtime's
            // own words on stderr, whatever its wording.
            if w["stderr"].as_str().is_some_and(|s| s.starts_with("runc run failed")) && o["stderr"].as_str().unwrap_or_default().trim().is_empty() {
                d.push(format!("{name}: nothing on stderr for a process that could not start"));
            }
        }
        let (probes, stdout) = split_probe(o["stdout"].as_str().unwrap_or_default());
        if let Some(want) = w["stdout"].as_str()
            && stdout != want
        {
            d.push(format!("{name}: stdout {stdout:?} != {want:?}"));
        }
        if let Some(want) = w["stderr"].as_str().filter(|s| !s.starts_with("runc run failed")) {
            let ours = o["stderr"].as_str().unwrap_or_default();
            if ours != want {
                d.push(format!("{name}: stderr {ours:?} != {want:?}"));
            }
        }
        let wanted: Vec<&Value> = w["probe"].as_array().into_iter().flatten().collect();
        if wanted.len() != probes.len() {
            d.push(format!("{name}: {} probe views, BuildKit {}", probes.len(), wanted.len()));
        }
        for (o, w) in probes.iter().zip(wanted) {
            // Where BuildKit is wrong, the step sees what `correct` adds too.
            let mut w = w.clone();
            if let (Some(seen), Some(add)) = (w.get_mut("xattrs").and_then(Value::as_object_mut), v["correct"]["probe_xattrs"].as_object()) {
                for (path, names) in add {
                    if let (Some(at), Some(names)) = (seen.get_mut(path).and_then(Value::as_object_mut), names.as_object()) {
                        at.extend(names.iter().map(|(k, x)| (k.clone(), x.clone())));
                    }
                }
            }
            for x in probe_diffs(o, &w) {
                d.push(format!("{name}: {x}"));
            }
        }
        if let Some(px) = v["correct"].get("probe_xattrs") {
            let seen = probes.iter().find_map(|p| p.get("xattrs"));
            for (path, names) in px.as_object().into_iter().flatten() {
                for (k, hx) in names.as_object().into_iter().flatten() {
                    if seen.and_then(|s| s.get(path)).and_then(|s| s.get(k)) != Some(hx) {
                        d.push(format!("{name}: the step does not see {k} on {path} (correct: {hx})"));
                    }
                }
            }
        }
    }
    // The layers after the base.
    let layers: Vec<Vec<u8>> = got["layers"].as_array().into_iter().flatten().map(|b| kiri_image::b64::decode(b.as_str().unwrap()).expect("base64")).collect();
    let want_layers = v["layers"].as_array().cloned().unwrap_or_default();
    if got.get("error").is_none() && layers.len() != want_layers.len() {
        d.push(format!("{} layers, BuildKit {}", layers.len(), want_layers.len()));
    }
    let mut lower: BTreeMap<Vec<u8>, i64> = BTreeMap::new();
    let last = want_layers.len().saturating_sub(1);
    for (i, (tar, w)) in layers.iter().zip(&want_layers).enumerate() {
        let ours = read_tar(tar);
        let is_run = w["created_by"].as_str().is_some_and(|c| c.starts_with("RUN "));
        let superseded = SUPERSEDED.contains(&v["name"].as_str().unwrap_or_default());
        let correct = (i == last && !superseded && v["correct"]["layer"].as_i64() == Some(-1)).then(|| &v["correct"]["entries"]);
        if is_run {
            let want: Vec<&Value> = match correct {
                Some(c) => c.as_array().into_iter().flatten().collect(),
                None => w["entries"].as_array().into_iter().flatten().collect(),
            };
            let names = |es: &[TarEntry]| es.iter().map(|e| String::from_utf8_lossy(&e.name).into_owned()).collect::<Vec<_>>();
            let want_names: Vec<String> = want.iter().map(|e| e["name"].as_str().unwrap().to_owned()).collect();
            if names(&ours) != want_names {
                d.push(format!("layer {i} ({}): entries {:?} != {:?}", w["created_by"], names(&ours), want_names));
            } else {
                for (o, e) in ours.iter().zip(&want) {
                    for x in entry_diffs(o, e, &lower) {
                        d.push(format!("layer {i}: {x}"));
                    }
                }
                let classes: Vec<&str> = want.iter().map(|e| e["mtime"].as_str().unwrap_or_default()).collect();
                if correct.is_none() && classes.iter().all(|c| *c == "new" || c.starts_with("fixed:")) {
                    let n = normalised(tar, &ours, &classes);
                    if Some(n.as_str()) != w["diff_id_normalized"].as_str() {
                        d.push(format!("layer {i}: normalised digest {n} != {}", w["diff_id_normalized"]));
                    }
                }
            }
            // `correct.layer_entries` names the layer that has the entry
            // (the COPY's, checked below); a RUN layer that has it too must
            // carry the record as well.
            if let Some(le) = v["correct"].get("layer_entries") {
                for (ename, recs) in le.as_object().into_iter().flatten() {
                    let Some(e) = ours.iter().find(|e| e.name == ename.as_bytes()) else { continue };
                    for (k, hx) in recs.as_object().into_iter().flatten() {
                        let has = e.pax.get(k).map(|b| hex(b));
                        if has.as_deref() != hx.as_str() {
                            d.push(format!("layer {i}: {ename} has {k}={has:?}, correct is {hx}"));
                        }
                    }
                }
            }
        } else if let Some(le) = v["correct"].get("layer_entries").filter(|_| w["created_by"].as_str().is_some_and(|c| c.starts_with("COPY"))) {
            for (ename, recs) in le.as_object().into_iter().flatten() {
                for (k, hx) in recs.as_object().into_iter().flatten() {
                    if let Some(e) = ours.iter().find(|e| e.name == ename.as_bytes()) {
                        let has = e.pax.get(k).map(|b| hex(b));
                        if has.as_deref() != hx.as_str() {
                            d.push(format!("layer {i} (COPY): {ename} has {k}={has:?}, correct is {hx}"));
                        }
                    }
                }
            }
        }
        for e in &ours {
            let n = e.name.strip_suffix(b"/").unwrap_or(&e.name).to_vec();
            lower.insert(n, e.mtime);
        }
    }
    d
}

#[test]
fn golden_run_vectors_on_a_real_engine() {
    let Ok(socket) = std::env::var("KIRI_GOLDEN_SOCKET") else {
        eprintln!("skipped: set KIRI_GOLDEN_SOCKET to a test engine's socket");
        return;
    };
    let registry = std::env::var("KIRI_GOLDEN_REGISTRY").unwrap_or_else(|_| "localhost:5000".into());
    let only = std::env::var("KIRI_GOLDEN_ONLY").unwrap_or_default();
    let Some(dir) = test_data::golden() else { return };
    let probe = fs::read(dir.join("corpus/run/probe.py")).unwrap();
    let work = std::env::temp_dir().join(format!("kiri-golden-ctx-{}", std::process::id()));
    let mut score: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut failures = Vec::new();
    for file in ["run.json", "xattr.json"] {
        let all: Value = serde_json::from_slice(&fs::read(dir.join("vectors").join(file)).unwrap()).unwrap();
        for (i, v) in all["vectors"].as_array().unwrap().iter().enumerate() {
            let name = v["name"].as_str().unwrap();
            if !name.contains(&only) {
                continue;
            }
            let d = run_case(&socket, &registry, v, &probe, &work.join(format!("{file}-{i}")));
            let area = name.split('/').next().unwrap().to_owned();
            let s = score.entry(area).or_default();
            s.1 += 1;
            if d.is_empty() {
                s.0 += 1;
                eprintln!("pass {name}");
            } else {
                eprintln!("FAIL {name}");
                for x in &d {
                    eprintln!("    {x}");
                }
                failures.push(name.to_owned());
            }
        }
    }
    let _ = fs::remove_dir_all(&work);
    for (area, (pass, n)) in &score {
        eprintln!("{area}: {pass}/{n}");
    }
    assert!(failures.is_empty(), "{} cases differ from BuildKit: {failures:?}", failures.len());
}
