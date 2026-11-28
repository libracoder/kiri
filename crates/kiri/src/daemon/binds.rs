//! Bind sources as clients send them. The docker CLI and Compose on Windows
//! (through kiri-win's pipe into WSL) send `C:\src:/app`, and tools that
//! drive the engine mount its socket into containers (Testcontainers' Ryuk,
//! CI runners). Both are made into paths this daemon can mount.

use std::path::Path;
use std::sync::OnceLock;

use super::engine::Error;

/// Shared `/mnt/wsl/kiri` directory across all WSL 2 distros.
pub const WSL_KIRI_DIR: &str = "/mnt/wsl/kiri";

/// Active WSL integration base directory (`KIRI_WSL_DIR` override or `/mnt/wsl/kiri`).
pub fn wsl_kiri_dir() -> String {
    std::env::var("KIRI_WSL_DIR")
        .ok()
        .map(|s| s.trim_end_matches('/').to_owned())
        .filter(|s| s.starts_with('/'))
        .unwrap_or_else(|| WSL_KIRI_DIR.to_owned())
}

fn wsl_roots_dir() -> String {
    format!("{}/roots", wsl_kiri_dir())
}

fn wsl_sockets_dir() -> String {
    format!("{}/sockets", wsl_kiri_dir())
}

/// Whether `name` is a safe single-component WSL distro name.
pub fn valid_distro_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', '\0'])
        && !name.bytes().any(|b| b.is_ascii_control())
}

/// Normalizes a path into `/a/b/c`, clamping `..` at `/` so traversal can never
/// climb above the root.
fn lexical_clean(p: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    format!("/{}", out.join("/"))
}

/// Joins `inner` under `root` (`/mnt/wsl/kiri/roots/<distro>`), clamping any
/// `..` traversal so the result cannot escape `root`.
pub fn confine_to_root(root: &str, inner: &str) -> String {
    let root = root.trim_end_matches('/');
    let rel = lexical_clean(inner);
    if rel == "/" {
        root.to_owned()
    } else {
        format!("{root}{rel}")
    }
}

/// When `distro_root` exists on disk, verifies that no existing symlink along
/// `target` escapes `distro_root`.
fn verify_on_disk_confinement(src: &str, distro: &str, distro_root: &Path, target: &Path) -> Result<(), Error> {
    if !distro_root.exists() {
        return Ok(());
    }
    let Ok(canon_root) = std::fs::canonicalize(distro_root) else {
        return Ok(());
    };
    let Ok(rel) = target.strip_prefix(distro_root) else {
        return Err(Error::BadRequest(format!("invalid mount source {src}: escapes WSL distro {distro}")));
    };
    let mut cur = distro_root.to_path_buf();
    for comp in rel.components() {
        cur.push(comp);
        if let Ok(link) = std::fs::read_link(&cur) {
            let link_str = link.to_string_lossy();
            if !cur.exists() && (link.is_absolute() || link_str.split('/').any(|c| c == "..")) {
                return Err(Error::BadRequest(format!("invalid mount source {src}: escapes WSL distro {distro}")));
            }
        }
        if cur.exists() {
            let canon = std::fs::canonicalize(&cur).map_err(Error::Io)?;
            if !canon.starts_with(&canon_root) {
                return Err(Error::BadRequest(format!("invalid mount source {src}: escapes WSL distro {distro}")));
            }
        }
    }
    Ok(())
}

/// Finds `<wsl_kiri_dir>/roots/<distro>` on disk if `<distro>` is integrated and mounted.
fn mounted_distro_root(distro: &str) -> Option<String> {
    if !valid_distro_name(distro) {
        return None;
    }
    let roots_dir = wsl_roots_dir();
    let exact = format!("{roots_dir}/{distro}");
    if Path::new(&exact).is_dir() {
        return Some(exact);
    }
    let entries = std::fs::read_dir(&roots_dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.eq_ignore_ascii_case(distro) && entry.path().is_dir() {
            return Some(entry.path().to_string_lossy().into_owned());
        }
    }
    None
}

fn is_wsl_engine_socket(p: &str) -> bool {
    let sockets_dir = wsl_sockets_dir();
    let matches_prefix = |prefix: &str| {
        p.strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix("/docker.sock"))
            .is_some_and(valid_distro_name)
    };
    matches_prefix(&format!("{sockets_dir}/")) || matches_prefix(&format!("{WSL_KIRI_DIR}/sockets/"))
}

/// Where WSL mounts the Windows drives, and which distro the daemon runs in.
#[derive(Debug, Clone, PartialEq)]
pub struct Wsl {
    /// `/mnt/` unless `[automount] root` in /etc/wsl.conf moves it; ends in `/`.
    pub root: String,
    /// For `\\wsl$\<distro>\…` paths; when unknown, any distro is taken as this one.
    pub distro: Option<String>,
}

/// The WSL the daemon runs in (kiri-win's engine), or None on a Mac or a
/// Linux host, where a Windows path is never a path.
pub fn wsl() -> Option<&'static Wsl> {
    static WSL: OnceLock<Option<Wsl>> = OnceLock::new();
    WSL.get_or_init(detect).as_ref()
}

fn detect() -> Option<Wsl> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    // WSL2's kernel names itself: 5.15.153.1-microsoft-standard-WSL2.
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    if !release.to_ascii_lowercase().contains("microsoft") {
        return None;
    }
    let root = automount_root(&std::fs::read_to_string("/etc/wsl.conf").unwrap_or_default());
    // The boot command that starts the daemon has no WSL_DISTRO_NAME;
    // wslpath knows the name all the same.
    let distro = std::env::var("WSL_DISTRO_NAME").ok().filter(|d| !d.is_empty()).or_else(|| {
        let out = std::process::Command::new("wslpath").args(["-w", "/"]).stderr(std::process::Stdio::null()).output().ok()?;
        distro_of(String::from_utf8_lossy(&out.stdout).trim())
    });
    Some(Wsl { root, distro })
}

/// `[automount] root` from /etc/wsl.conf's text, as WSL reads it.
pub fn automount_root(conf: &str) -> String {
    let mut section = String::new();
    let mut root = None;
    for line in conf.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = s.trim().to_ascii_lowercase();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        if section == "automount" && key.trim().eq_ignore_ascii_case("root") {
            let value = value.trim().trim_matches('"').trim();
            if value.starts_with('/') {
                root = Some(value.to_owned());
            }
        }
    }
    let mut root = root.unwrap_or_else(|| "/mnt/".to_owned());
    if !root.ends_with('/') {
        root.push('/');
    }
    root
}

/// The distro in `\\wsl.localhost\Ubuntu\…` (or `\\wsl$\…`).
fn distro_of(unc: &str) -> Option<String> {
    let s = unc.replace('\\', "/");
    let rest = s.strip_prefix("//")?;
    let (host, path) = rest.split_once('/')?;
    if !(host.eq_ignore_ascii_case("wsl$") || host.eq_ignore_ascii_case("wsl.localhost")) {
        return None;
    }
    let distro = path.split('/').next().filter(|d| !d.is_empty())?;
    Some(distro.to_owned())
}

/// One `-v` spec (HostConfig.Binds) as source, target and options. In WSL a
/// drive letter's colon belongs to the source (`C:\src:/app:ro`), and the
/// source is made a path in this Linux.
#[cfg(test)]
pub fn split(spec: &str, wsl: Option<&Wsl>) -> Result<(String, String, String), Error> {
    split_for(spec, wsl, None)
}

/// [`split`], translating Linux paths from an integrated WSL distro
/// (`wsl_distro = Some("<NAME>")`) into `/mnt/wsl/kiri/roots/<NAME>/…`.
pub fn split_for(spec: &str, wsl: Option<&Wsl>, wsl_distro: Option<&str>) -> Result<(String, String, String), Error> {
    let bad = || Error::BadRequest(format!("invalid volume specification: {spec}"));
    // `c:/app` is the volume `c` at /app, as in moby's Windows parser: a
    // drive is the source only when an absolute target follows it.
    let has_drive = (wsl.is_some() || wsl_distro.is_some())
        && spec[drive_prefix(spec)..].split(':').nth(1).is_some_and(|d| d.starts_with('/'));
    let skip = if has_drive { drive_prefix(spec) } else { 0 };
    let Some(i) = spec[skip..].find(':').map(|i| skip + i) else { return Err(bad()) };
    let (src, rest) = (&spec[..i], &spec[i + 1..]);
    let (dst, opts) = match rest.split(':').collect::<Vec<_>>().as_slice() {
        [d] => (*d, ""),
        [d, o] => (*d, *o),
        _ => return Err(bad()),
    };
    let src = match (wsl, wsl_distro) {
        (_, Some(d)) if src.starts_with('/') || looks_windows(src) => distro_source(src, d, wsl)?,
        // A volume name stays a name; only paths are translated.
        (Some(w), None) if looks_windows(src) => source(src, w)?,
        _ => src.to_owned(),
    };
    Ok((src, dst.to_owned(), opts.to_owned()))
}

/// Whether `src` is a Windows UNC spelling for WSL or Docker pipe (`//wsl$/…`,
/// `//wsl.localhost/…`, `//./pipe/…`) rather than a Linux path with redundant
/// leading slashes (`//etc/shadow`, `///var/lib/kiri`).
fn is_distro_unc(src: &str) -> bool {
    if src.contains('\\') {
        return true;
    }
    let Some(rest) = src.strip_prefix("//") else { return false };
    if rest.starts_with('/') {
        return false;
    }
    let (host, _) = rest.split_once('/').unwrap_or((rest, ""));
    host.eq_ignore_ascii_case("wsl$") || host.eq_ignore_ascii_case("wsl.localhost") || host == "." || host == "?"
}

/// Translates a bind mount source from an integrated WSL distro `<distro>`:
/// - `/var/run/docker.sock` (and engine socket aliases) stays the engine socket
/// - `/mnt/c/proj` (under the Windows automount root) stays `/mnt/c/proj`
/// - `/home/alice/app` becomes `/mnt/wsl/kiri/roots/<distro>/home/alice/app`
/// - `..` traversal is confined so it can never escape `<distro>`'s root
pub fn distro_source(src: &str, distro: &str, wsl: Option<&Wsl>) -> Result<String, Error> {
    if !valid_distro_name(distro) {
        return Err(Error::BadRequest(format!("invalid WSL distro: {distro}")));
    }
    let kiri_dir = wsl_kiri_dir();
    let roots_dir = format!("{kiri_dir}/roots");
    let distro_root = mounted_distro_root(distro).unwrap_or_else(|| format!("{roots_dir}/{distro}"));
    // Collapse redundant leading slashes on Unix paths (`//etc/shadow` -> `/etc/shadow`,
    // `///var/lib/kiri` -> `/var/lib/kiri`) before checking `looks_windows` so they
    // cannot escape confinement through `source_with_roots`.
    let collapsed;
    let unix_or_win = if src.starts_with('/') && drive_prefix(src) == 0 && !is_distro_unc(src) {
        collapsed = format!("/{}", src.trim_start_matches('/'));
        collapsed.as_str()
    } else {
        src
    };
    if looks_windows(unix_or_win) {
        let s = unix_or_win.replace('\\', "/");
        if let Some(rest) = s.strip_prefix("//").filter(|r| !r.starts_with('/')) {
            let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
            if host.eq_ignore_ascii_case("wsl$") || host.eq_ignore_ascii_case("wsl.localhost") {
                let (d, inner) = path.split_once('/').unwrap_or((path, ""));
                if d.is_empty() {
                    return Err(Error::BadRequest(format!("invalid mount source {src}: no WSL distro named")));
                }
                if !d.eq_ignore_ascii_case(distro) {
                    return Err(Error::BadRequest(format!(
                        "invalid mount source {src}: WSL distro {distro} cannot mount files from WSL distro {d}"
                    )));
                }
                let inner_abs = format!("/{inner}");
                return distro_unix_source(src, &inner_abs, distro, &kiri_dir, &distro_root, wsl);
            }
        }
        let default_wsl = Wsl { root: "/mnt/".into(), distro: None };
        let w = wsl.unwrap_or(&default_wsl);
        return source_with_roots(unix_or_win, w, |_| None);
    }
    if !unix_or_win.starts_with('/') {
        return Ok(unix_or_win.to_owned());
    }
    distro_unix_source(src, unix_or_win, distro, &kiri_dir, &distro_root, wsl)
}

fn distro_unix_source(
    raw_src: &str,
    src: &str,
    distro: &str,
    kiri_dir: &str,
    distro_root: &str,
    wsl: Option<&Wsl>,
) -> Result<String, Error> {
    let cleaned = clean(src);
    if ENGINE_SOCKS.contains(&cleaned.as_str()) || is_wsl_engine_socket(&cleaned) || cleaned == SSH_AGENT_SOCK {
        return Ok(cleaned);
    }
    if cleaned == distro_root || cleaned.strip_prefix(distro_root).is_some_and(|r| r.starts_with('/')) {
        let rest = cleaned.strip_prefix(distro_root).unwrap_or("");
        let target = confine_to_root(distro_root, rest);
        verify_on_disk_confinement(raw_src, distro, Path::new(distro_root), Path::new(&target))?;
        return Ok(target);
    }
    let lex = lexical_clean(src);
    if ENGINE_SOCKS.contains(&lex.as_str())
        || is_wsl_engine_socket(&lex)
        || lex == SSH_AGENT_SOCK
        || lex == "/sys"
        || lex.starts_with("/sys/")
    {
        return Ok(lex);
    }
    let is_internal_wsl = |p: &str| {
        p == kiri_dir
            || p.starts_with(&format!("{kiri_dir}/"))
            || p == WSL_KIRI_DIR
            || p.starts_with(&format!("{WSL_KIRI_DIR}/"))
    };
    if is_internal_wsl(&lex) {
        return Err(Error::BadRequest(format!(
            "invalid mount source {raw_src}: cannot mount Kiri's internal WSL directory"
        )));
    }
    let mnt = wsl.map_or("/mnt/", |w| w.root.as_str());
    let mnt_trimmed = mnt.trim_end_matches('/');
    let on_drive = |p: &str| (!mnt_trimmed.is_empty() && (p == mnt_trimmed || p.starts_with(mnt))) && p != "/mnt/wsl" && !is_internal_wsl(p);
    if on_drive(&lex) {
        return Ok(lex);
    }
    // An absolute link in the distro (`/etc/localtime -> /usr/share/zoneinfo/...`)
    // means the distro's own file: follow it inside the distro's root. With
    // only relative links on the way the source stays as given; the kernel
    // follows those inside the root itself.
    let target = match resolve_in_root(Path::new(distro_root), &lex) {
        Some((inside, true)) if on_drive(&inside) => return Ok(inside),
        Some((inside, true)) => confine_to_root(distro_root, &inside),
        Some((_, false)) => confine_to_root(distro_root, &lex),
        None => return Err(Error::BadRequest(format!("invalid mount source {raw_src}: too many levels of symbolic links"))),
    };
    verify_on_disk_confinement(raw_src, distro, Path::new(distro_root), Path::new(&target))?;
    Ok(target)
}

/// `path` (absolute, in a distro whose `/` is `root` on disk) with every
/// symlink on the way followed as the distro would: an absolute target
/// from `root`, `..` stopping at it. The path returned is the distro's
/// spelling, with whether an absolute link was on the way; None after 40
/// links, as Linux gives up.
fn resolve_in_root(root: &Path, path: &str) -> Option<(String, bool)> {
    if !root.is_dir() {
        return Some((lexical_clean(path), false));
    }
    let parts = |p: &str| p.split('/').filter(|c| !c.is_empty() && *c != ".").map(str::to_owned).rev().collect::<Vec<_>>();
    let (mut todo, mut done, mut links, mut absolute) = (parts(path), Vec::<String>::new(), 0, false);
    while let Some(c) = todo.pop() {
        if c == ".." {
            done.pop();
            continue;
        }
        match std::fs::read_link(root.join(done.join("/")).join(&c)) {
            Ok(link) => {
                links += 1;
                if links > 40 {
                    return None;
                }
                let link = link.to_string_lossy().into_owned();
                if link.starts_with('/') {
                    done.clear();
                    absolute = true;
                }
                todo.extend(parts(&link));
            }
            Err(_) => done.push(c),
        }
    }
    Some((format!("/{}", done.join("/")), absolute))
}

/// How many leading bytes hold a colon that is not a separator: `C:` and
/// `\\?\C:` (moby's Windows parser allows both).
fn drive_prefix(spec: &str) -> usize {
    let long = [r"\\?\", "//?/"].iter().find(|p| spec.starts_with(**p)).map_or(0, |p| p.len());
    let b = &spec.as_bytes()[long..];
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/') { long + 2 } else { 0 }
}

/// A source in one of Windows' spellings, rather than a Linux path or a
/// volume name.
fn looks_windows(src: &str) -> bool {
    src.contains('\\') || src.starts_with("//") || drive_prefix(src) > 0
}

/// A bind source from Windows, as a path in this distro:
/// - `C:\src`, `C:/src`, `\\?\C:\src` → `/mnt/c/src`
/// - `//c/src` (Git Bash's spelling) → `/mnt/c/src`
/// - `\\wsl$\<distro>\home\me`, `\\wsl.localhost\<distro>\home\me` → `/home/me`
/// - `\\.\pipe\docker_engine` → `/var/run/docker.sock` (the engine itself)
/// - `//var/run/docker.sock` (Testcontainers on Windows) → `/var/run/docker.sock`
///
/// Anything else (a network share, another distro's files, a relative
/// path) is refused: WSL can't reach it as a path here.
pub fn source(src: &str, wsl: &Wsl) -> Result<String, Error> {
    source_with_roots(src, wsl, mounted_distro_root)
}

pub fn source_with_roots(src: &str, wsl: &Wsl, distro_root: impl Fn(&str) -> Option<String>) -> Result<String, Error> {
    let bad = |why: &str| Error::BadRequest(format!("invalid mount source {src}: {why}"));
    if !looks_windows(src) {
        return Ok(src.to_owned());
    }
    let long = src.strip_prefix(r"\\?\").or_else(|| src.strip_prefix("//?/")).unwrap_or(src);
    if drive_prefix(long) == 2 {
        return Ok(drive(wsl, long.as_bytes()[0], &long[3..]));
    }
    let s = src.replace('\\', "/");
    let Some(rest) = s.strip_prefix("//") else {
        return Err(bad("not an absolute path"));
    };
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    if host.len() == 1 && host.as_bytes()[0].is_ascii_alphabetic() {
        return Ok(drive(wsl, host.as_bytes()[0], path));
    }
    if host.eq_ignore_ascii_case("wsl$") || host.eq_ignore_ascii_case("wsl.localhost") {
        let (distro, inner) = path.split_once('/').unwrap_or((path, ""));
        if distro.is_empty() {
            return Err(bad("no WSL distro named"));
        }
        if let Some(ours) = wsl.distro.as_deref().filter(|d| !d.eq_ignore_ascii_case(distro)) {
            if let Some(root) = distro_root(distro) {
                let target = confine_to_root(&root, inner);
                verify_on_disk_confinement(src, distro, Path::new(&root), Path::new(&target))?;
                return Ok(target);
            }
            return Err(bad(&format!("it is in the WSL distro {distro}, and Kiri runs in {ours}; use a path on a Windows drive or in {ours}")));
        }
        return Ok(clean(&format!("/{inner}")));
    }
    if host == "." && path.eq_ignore_ascii_case("pipe/docker_engine") {
        return Ok("/var/run/docker.sock".to_owned());
    }
    // `//var/run/docker.sock`: a doubled slash, not a server.
    if !src.contains('\\') && host != "." && host != "?" && !host.is_empty() && !path.is_empty() {
        return Ok(clean(&format!("/{rest}")));
    }
    Err(bad("Kiri's WSL can reach the Windows drives (C:\\…) and its own files, not network shares or devices"))
}

/// A path on drive `letter`, under WSL's automount root. `..` stops at the
/// drive's root, as Windows resolves `C:\..` to `C:\`.
fn drive(wsl: &Wsl, letter: u8, rest: &str) -> String {
    confine_to_root(&format!("{}{}", wsl.root, letter.to_ascii_lowercase() as char), &rest.replace('\\', "/"))
}

/// Whether `path` is under WSL's automount root (`<automount_root><drive>/...`,
/// or `<automount_root><drive>` when `allow_drive_root` is true), with no
/// control characters and no `.` or `..` traversal components.
pub fn is_wsl_drive_path(path: &str, automount_root: &str, allow_drive_root: bool) -> bool {
    if !automount_root.starts_with('/') || !automount_root.ends_with('/') {
        return false;
    }
    if path.contains(['\n', '\r', '\0']) {
        return false;
    }
    let Some(rest) = path.strip_prefix(automount_root) else { return false };
    let bytes = rest.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    if bytes.len() == 1 {
        return allow_drive_root;
    }
    if bytes[1] != b'/' {
        return false;
    }
    let mut has_component = false;
    for part in rest[2..].split('/') {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." {
            return false;
        }
        has_component = true;
    }
    has_component || allow_drive_root
}

/// Single slashes, none at the end.
fn clean(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    for c in p.chars() {
        if c == '/' && out.ends_with('/') {
            continue;
        }
        out.push(c);
    }
    if out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

/// Where a container that mounts the engine's socket is given one in the
/// VM: the agent relays it to the daemon (crates/kiri-init/src/linux/relay.rs).
#[cfg(target_os = "macos")]
const VM_ENGINE_SOCK: &str = "/run/host-services/docker.sock";

/// The paths clients mean as "the engine" when they mount it into a
/// container: Docker's own, and on the Mac the socket the client was given
/// (`DOCKER_HOST=unix://~/.kiri/run/docker.sock`, which Testcontainers
/// mounts into Ryuk).
const ENGINE_SOCKS: &[&str] = &["/var/run/docker.sock", "/run/docker.sock", "/private/var/run/docker.sock"];
const SSH_AGENT_SOCK: &str = "/run/host-services/ssh-auth.sock";

/// Where a path really is: its links followed, and the file it leads to
/// as device and inode, which also matches a hard link or another mount of
/// the same file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Real {
    pub path: String,
    pub id: (u64, u64),
}

impl Real {
    /// The same file as `other`, by path or by device and inode.
    pub fn same(&self, other: &Real) -> bool {
        self.path == other.path || self.id == other.id
    }
}

/// [`Real`] for a path that exists, `None` for one that does not.
pub fn real(p: &str) -> Option<Real> {
    use std::os::unix::fs::MetadataExt;
    let path = std::fs::canonicalize(p).ok()?;
    let m = std::fs::metadata(&path).ok()?;
    Some(Real { path: path.into_os_string().into_string().ok()?, id: (m.dev(), m.ino()) })
}

/// What to mount for a bind of `src`, when it is the engine's socket. On a
/// Mac the VM's relay to this daemon, as Docker Desktop and OrbStack give
/// the VM's engine. On a Linux host (and WSL) the socket Kiri gives
/// containers (caller.rs) for a path that is Kiri's socket, by any name,
/// link or hard link (the package's `/var/run/docker.sock` link among
/// them), and for a missing `/var/run/docker.sock` rather than a new empty
/// directory. Another engine's socket at that path (Docker's own) is
/// mounted as it is.
pub fn engine_socket(src: &str) -> Option<String> {
    let own = super::socket_path().ok()?;
    let own = own.to_string_lossy();
    let alias = if std::env::var_os("KIRI_SOCKET").is_none() {
        super::home_socket_path().ok().filter(|p| p.as_os_str() != own.as_ref())
    } else {
        None
    };
    let alias = alias.as_deref().and_then(|p| p.to_str());
    engine_socket_with_alias(src, &own, alias, real)
}

/// [`engine_socket`] for a create request that arrived from `wsl_distro`:
/// inside an integrated WSL distro, `/var/run/docker.sock` (and `/run/docker.sock`)
/// refers to Kiri's engine socket regardless of whether the host or engine
/// distro has another socket at `/var/run/docker.sock`.
pub fn engine_socket_for_distro(src: &str, wsl_distro: Option<&str>) -> Option<String> {
    if wsl_distro.is_some() {
        let text = clean(src);
        if ENGINE_SOCKS.contains(&text.as_str()) || is_wsl_engine_socket(&text) {
            let own = super::socket_path().ok()?;
            #[cfg(target_os = "macos")]
            {
                let _ = own;
                return Some(VM_ENGINE_SOCK.to_owned());
            }
            #[cfg(not(target_os = "macos"))]
            return Some(super::caller::container_socket(&own).to_string_lossy().into_owned());
        }
    }
    engine_socket(src)
}

/// [`engine_socket`], with `resolve` giving where a path that exists
/// really is. The path as given is followed first, as the kernel will
/// follow it; only a path that is not there is compared as text.
#[cfg(test)]
fn engine_socket_for(src: &str, own: &str, resolve: impl Fn(&str) -> Option<Real>) -> Option<String> {
    engine_socket_with_alias(src, own, None, resolve)
}

fn engine_socket_with_alias(src: &str, own: &str, alias: Option<&str>, resolve: impl Fn(&str) -> Option<Real>) -> Option<String> {
    let found = resolve(src);
    let text = clean(src);
    let matches_text = |p: &str| text == clean(p);
    let is_own = found.as_ref().is_some_and(|a| {
        resolve(own).is_some_and(|b| a.same(&b)) || alias.and_then(&resolve).is_some_and(|b| a.same(&b))
    }) || is_wsl_engine_socket(&text)
        || found.as_ref().is_some_and(|r| is_wsl_engine_socket(&r.path));
    #[cfg(target_os = "macos")]
    {
        let named = ENGINE_SOCKS.contains(&text.as_str()) || found.as_ref().is_some_and(|r| ENGINE_SOCKS.contains(&r.path.as_str()));
        (is_own || named || matches_text(own) || alias.is_some_and(matches_text)).then(|| VM_ENGINE_SOCK.to_owned())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let given = || super::caller::container_socket(Path::new(own)).to_string_lossy().into_owned();
        match found {
            Some(_) => is_own.then(given),
            None => (is_own || matches_text(own) || alias.is_some_and(matches_text) || ENGINE_SOCKS.contains(&text.as_str())).then(given),
        }
    }
}

/// Makes a bind mount's missing source (`-v ./missing:/x`) as Docker does
/// (`MkdirAllAndChownNew(source, 0755, root)`): each folder not there yet is
/// 0755 whatever this process's umask, keeps a set-group-ID bit its parent
/// hands down, and is root's when the engine runs as root, not the group
/// such a parent would give it. The Linux unit runs the daemon with
/// UMask=0027, which protects its state, logs and keys but would make these
/// folders 0750 and shut out the user whose mount it is. Folders already
/// there are left as they are.
pub fn make_source(path: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    if path.is_absolute() {
        let norm = lexical_clean(&path.to_string_lossy());
        if norm == "/etc/localtime" {
            return super::localtime::ensure_localtime();
        }
        if norm == "/etc/timezone" {
            return super::localtime::ensure_timezone();
        }
    }
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let missing: Vec<&Path> = path.ancestors().take_while(|a| std::fs::symlink_metadata(a).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)).collect();
    if missing.is_empty() {
        // There but not a folder (a link to nowhere): refused as before.
        return std::fs::create_dir_all(path);
    }
    // SAFETY: geteuid only reads this process's effective user.
    let root = unsafe { libc::geteuid() } == 0;
    for dir in missing.into_iter().rev() {
        match std::fs::DirBuilder::new().mode(0o755).create(dir) {
            Ok(()) => {}
            // Made at the same moment by another container's start: its own.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && dir.is_dir() => continue,
            Err(e) => return Err(e),
        }
        if root {
            std::os::unix::fs::chown(dir, Some(0), Some(0))?;
        }
        let mode = std::fs::metadata(dir)?.permissions().mode() & 0o7777;
        let want = 0o755 | (mode & 0o2000);
        if mode != want {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(want))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A missing source is made 0755 under the Linux unit's umask (0027),
    /// each folder on the way too, and folders already there keep their
    /// mode. The umask is the whole process's, so the check runs in a child
    /// test process of its own, where nothing else runs.
    #[test]
    fn a_missing_bind_source_is_made_0755_whatever_the_umask() {
        use std::os::unix::fs::PermissionsExt;
        const CHILD: &str = "KIRI_TEST_BIND_SOURCE_DIR";
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        if let Some(base) = std::env::var_os(CHILD) {
            let base = Path::new(&base);
            // SAFETY: umask only changes this process's file-creation mask,
            // and this process runs this test alone.
            unsafe { libc::umask(0o027) };
            make_source(&base.join("new/dir")).unwrap();
            make_source(&base.join("new/dir")).unwrap();
            make_source(&base.join("sgid/new/dir")).unwrap();
            std::fs::create_dir(base.join("plain")).unwrap();
            return;
        }
        let base = std::env::temp_dir().join(format!("kiri-bind-source-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        // A set-group-ID parent of another group, as a shared project folder
        // can be: on Linux the bit is handed down, and so is the group,
        // which Docker (as root) puts back to root's.
        let sgid = base.join("sgid");
        std::fs::create_dir(&sgid).unwrap();
        // SAFETY: geteuid only reads this process's effective user.
        let root = unsafe { libc::geteuid() } == 0;
        if root {
            std::os::unix::fs::chown(&sgid, None, Some(1)).unwrap();
        }
        std::fs::set_permissions(&sgid, std::fs::Permissions::from_mode(0o2775)).unwrap();
        let name = "daemon::binds::tests::a_missing_bind_source_is_made_0755_whatever_the_umask";
        let child = std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact", name, "--test-threads=1"]).env(CHILD, &base).output().unwrap();
        assert!(child.status.success(), "{}", String::from_utf8_lossy(&child.stdout));
        // The umask did apply in the child: a folder made without the fix.
        assert_eq!(mode(&base.join("plain")), 0o750, "the child ran under umask 0027");
        let made = (mode(&base.join("new")), mode(&base.join("new/dir")));
        assert_eq!(made, (0o755, 0o755), "made {:o} and {:o}", made.0, made.1);
        assert_eq!(mode(&base), 0o700, "a folder already there is left as it is");
        let handed_down = if cfg!(target_os = "linux") { 0o2755 } else { 0o755 };
        let made = (mode(&sgid.join("new")), mode(&sgid.join("new/dir")));
        assert_eq!(made, (handed_down, handed_down), "made {:o} and {:o}", made.0, made.1);
        if root {
            use std::os::unix::fs::MetadataExt;
            let owner = |p: &Path| std::fs::metadata(p).map(|m| (m.uid(), m.gid())).unwrap();
            assert_eq!((owner(&sgid.join("new")), owner(&sgid.join("new/dir"))), ((0, 0), (0, 0)), "root:root, as Docker makes it");
        }
        // A link to nowhere is refused, as before.
        std::os::unix::fs::symlink(base.join("gone"), base.join("dangling")).unwrap();
        assert!(make_source(&base.join("dangling")).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    fn wsl() -> Wsl {
        Wsl { root: "/mnt/".into(), distro: Some("kiri".into()) }
    }

    fn ok(spec: &str) -> (String, String, String) {
        split(spec, Some(&wsl())).unwrap_or_else(|e| panic!("{spec}: {e:?}"))
    }

    fn t(s: &str, d: &str, o: &str) -> (String, String, String) {
        (s.into(), d.into(), o.into())
    }

    #[test]
    fn windows_drive_binds() {
        assert_eq!(ok(r"C:\src:/app"), t("/mnt/c/src", "/app", ""));
        assert_eq!(ok("C:/src:/app:ro"), t("/mnt/c/src", "/app", "ro"));
        assert_eq!(ok(r"c:\Users\Me\My Project\src:/app:rw"), t("/mnt/c/Users/Me/My Project/src", "/app", "rw"));
        assert_eq!(ok(r"D:\:/data"), t("/mnt/d", "/data", ""));
        assert_eq!(ok(r"C:\src\:/app"), t("/mnt/c/src", "/app", ""));
        assert_eq!(ok(r"\\?\C:\src:/app"), t("/mnt/c/src", "/app", ""));
        assert_eq!(ok("//c/src:/app"), t("/mnt/c/src", "/app", ""));
        assert_eq!(ok("//C/src/:/app:ro,z"), t("/mnt/c/src", "/app", "ro,z"));
        // Compose resolves `./src` against a Windows project directory.
        assert_eq!(ok(r"C:\Users\me\proj\src:/usr/src/app:rw"), t("/mnt/c/Users/me/proj/src", "/usr/src/app", "rw"));
    }

    #[test]
    fn linux_specs_are_unchanged_in_wsl() {
        assert_eq!(ok("/home/me/src:/app"), t("/home/me/src", "/app", ""));
        assert_eq!(ok("/mnt/c/src:/app:ro"), t("/mnt/c/src", "/app", "ro"));
        assert_eq!(ok("data:/var/lib/data"), t("data", "/var/lib/data", ""));
        assert_eq!(ok("data:/var/lib/data:ro,nocopy"), t("data", "/var/lib/data", "ro,nocopy"));
        // A drive with no target after it: the one-letter volume `c` at /app.
        assert_eq!(ok("c:/app"), t("c", "/app", ""));
        assert_eq!(ok("C:/src:ro"), t("C", "/src", "ro"));
    }

    #[test]
    fn wsl_and_pipe_sources() {
        assert_eq!(ok(r"\\wsl$\kiri\home\me:/app"), t("/home/me", "/app", ""));
        assert_eq!(ok(r"\\wsl.localhost\Kiri\home\me\:/app:ro"), t("/home/me", "/app", "ro"));
        assert_eq!(ok("//wsl.localhost/kiri/srv:/srv"), t("/srv", "/srv", ""));
        assert_eq!(ok(r"\\.\pipe\docker_engine:/var/run/docker.sock"), t("/var/run/docker.sock", "/var/run/docker.sock", ""));
        assert_eq!(ok("//var/run/docker.sock:/var/run/docker.sock:rw"), t("/var/run/docker.sock", "/var/run/docker.sock", "rw"));
        // Distro unknown: taken as Kiri's own.
        let any = Wsl { root: "/mnt/".into(), distro: None };
        assert_eq!(split(r"\\wsl$\Ubuntu\home:/h", Some(&any)).unwrap(), t("/home", "/h", ""));
    }

    #[test]
    fn refused_sources() {
        for spec in [
            r"\\wsl$\Ubuntu\home\me:/app",
            r"\\server\share\dir:/app",
            r"\\?\UNC\server\share:/app",
            r"\\.\pipe\other:/app",
            r".\src:/app",
            r"src\app:/app",
            r"C:\src:/app:ro:extra",
            "nocolon",
        ] {
            assert!(split(spec, Some(&wsl())).is_err(), "{spec} should be refused");
        }
    }

    #[test]
    fn automount_root_follows_wsl_conf() {
        let w = Wsl { root: automount_root("[automount]\nroot = /windows/\noptions = \"metadata\"\n"), distro: None };
        assert_eq!(w.root, "/windows/");
        assert_eq!(split(r"C:\src:/app", Some(&w)).unwrap().0, "/windows/c/src");
        assert_eq!(automount_root("[Automount]\n  Root=\"/\"  # all drives at /c, /d\n"), "/");
        assert_eq!(split(r"E:\x:/x", Some(&Wsl { root: "/".into(), distro: None })).unwrap().0, "/e/x");
        assert_eq!(automount_root("[automount]\nroot = /win"), "/win/");
        assert_eq!(automount_root("[boot]\nroot = /nope/\ncommand = kiri daemon\n"), "/mnt/");
        assert_eq!(automount_root(""), "/mnt/");
        assert_eq!(automount_root("[automount]\nroot = relative\n"), "/mnt/");
    }

    #[test]
    fn distro_from_wslpath() {
        assert_eq!(distro_of(r"\\wsl.localhost\kiri\"), Some("kiri".into()));
        assert_eq!(distro_of(r"\\wsl$\Ubuntu-24.04\"), Some("Ubuntu-24.04".into()));
        assert_eq!(distro_of(r"C:\"), None);
    }

    #[test]
    fn outside_wsl_specs_split_on_every_colon() {
        assert_eq!(split("/src:/app:ro", None).unwrap(), t("/src", "/app", "ro"));
        assert_eq!(split("C:/app", None).unwrap(), t("C", "/app", ""));
    }

    #[test]
    fn mounts_sources() {
        let w = wsl();
        assert_eq!(source(r"C:\src", &w).unwrap(), "/mnt/c/src");
        assert_eq!(source("/home/me", &w).unwrap(), "/home/me");
        assert_eq!(source("myvolume", &w).unwrap(), "myvolume");
        assert!(source(r"\\server\share", &w).is_err());
    }

    /// A stand-in for [`real`]: each path is itself, with an id of its own,
    /// unless `links` sends it elsewhere.
    fn fake<'a>(links: &'a [(&'a str, &'a str)], ids: &'a [(&'a str, u64)]) -> impl Fn(&str) -> Option<Real> + 'a {
        move |p: &str| {
            let path = links.iter().find(|(from, _)| *from == p).map_or(p, |(_, to)| *to);
            if path == "-" {
                return None;
            }
            let id = ids.iter().find(|(q, _)| *q == path).map_or(path.len() as u64 * 7919 + path.bytes().map(u64::from).sum::<u64>(), |(_, i)| *i);
            Some(Real { path: path.to_owned(), id: (1, id) })
        }
    }

    #[test]
    fn engine_socket_aliases() {
        let none = |_: &str| None;
        let itself = fake(&[], &[]);
        #[cfg(target_os = "macos")]
        {
            let own = "/Users/me/.kiri/run/docker.sock";
            for s in ["/var/run/docker.sock", "/private/var/run/docker.sock", "/run/docker.sock", own, "/Users/me/.kiri/run//docker.sock"] {
                assert_eq!(engine_socket_for(s, own, &itself).as_deref(), Some(VM_ENGINE_SOCK), "{s}");
            }
            assert_eq!(engine_socket_for("/Users/me/.orbstack/run/docker.sock", own, none), None);
            // A socket path given with a doubled slash is the same socket.
            assert_eq!(engine_socket_for(own, "/Users/me/.kiri/run//docker.sock", none).as_deref(), Some(VM_ENGINE_SOCK));
            // A link to Kiri's socket, and /var as the Mac spells it.
            let to_real = [("/tmp/s.sock", "/private/tmp/real.sock"), (own, "/private/tmp/real.sock")];
            let linked = fake(&to_real, &[]);
            assert_eq!(engine_socket_for("/tmp/s.sock", own, &linked).as_deref(), Some(VM_ENGINE_SOCK));
            let var = fake(&[("/var/x/docker.sock", "/private/var/run/docker.sock")], &[]);
            assert_eq!(engine_socket_for("/var/x/docker.sock", own, &var).as_deref(), Some(VM_ENGINE_SOCK));
        }
        #[cfg(not(target_os = "macos"))]
        {
            let own = "/run/kiri/docker.sock";
            let given = Some("/run/kiri/docker.container.sock");
            let missing = fake(&[("/var/run/docker.sock", "-"), ("/run/docker.sock", "-")], &[]);
            // Kiri's socket, by its own path, a missing Docker path, or a link
            // to it: containers are given their own socket, never the daemon's.
            assert_eq!(engine_socket_for("/var/run/docker.sock", own, &missing).as_deref(), given);
            assert_eq!(engine_socket_for("/run/docker.sock", own, &missing).as_deref(), given);
            assert_eq!(engine_socket_for(own, own, &itself).as_deref(), given);
            let doubled = [("/run/kiri//docker.sock", own)];
            assert_eq!(engine_socket_for("/run/kiri//docker.sock", own, fake(&doubled, &[])).as_deref(), given);
            let to_own = [("/var/run/docker.sock", own)];
            let link = fake(&to_own, &[]);
            assert_eq!(engine_socket_for("/var/run/docker.sock", own, &link).as_deref(), given);
            // Docker's own socket: mounted as it is.
            assert_eq!(engine_socket_for("/var/run/docker.sock", own, &itself), None);
            // A hard link to Kiri's socket: another path, the same file.
            let ids = [("/tmp/hard.sock", 42), (own, 42)];
            let hard = fake(&[], &ids);
            assert_eq!(engine_socket_for("/tmp/hard.sock", own, &hard).as_deref(), given);
            // The path as given is what is followed, before any tidying:
            // here only that spelling leads to Kiri's socket.
            let spelled = [("/tmp/l//../kiri/docker.sock", own)];
            let raw = fake(&spelled, &[]);
            let raw = |p: &str| if p == "/tmp/l//../kiri/docker.sock" || p == own { raw(p) } else { None };
            assert_eq!(engine_socket_for("/tmp/l//../kiri/docker.sock", own, raw).as_deref(), given);
            // Compatibility home socket alias alongside /run/kiri/docker.sock also maps to the container socket.
            let home_alias = "/root/.kiri/run/docker.sock";
            assert_eq!(engine_socket_with_alias(home_alias, own, Some(home_alias), &itself).as_deref(), given);
        }
        assert_eq!(engine_socket_for("/srv/app.sock", "/x/docker.sock", none), None);
        assert_eq!(engine_socket_for("/srv/app.sock", "/x/docker.sock", &itself), None);
    }

    #[test]
    fn wsl_drive_path_validation() {
        assert!(is_wsl_drive_path("/mnt/c/Users/me/app", "/mnt/", false));
        assert!(is_wsl_drive_path("/mnt/c", "/mnt/", true));
        assert!(!is_wsl_drive_path("/mnt/c", "/mnt/", false));
        assert!(!is_wsl_drive_path("/mnt/c/", "/mnt/", false));
        assert!(!is_wsl_drive_path("/mnt/mac/Users/a", "/mnt/", true));
        assert!(!is_wsl_drive_path("/etc/passwd", "/mnt/", true));
        assert!(!is_wsl_drive_path("/mnt/c/../etc/passwd", "/mnt/", true));
        assert!(!is_wsl_drive_path("/mnt/c/a\nb", "/mnt/", true));
        assert!(is_wsl_drive_path("/windows/d/proj", "/windows/", false));
    }

    #[test]
    fn wsl_distro_path_translation_and_confinement() {
        let w = wsl();
        assert_eq!(
            split_for("/home/me/app:/app", Some(&w), Some("Ubuntu")).unwrap(),
            t("/mnt/wsl/kiri/roots/Ubuntu/home/me/app", "/app", "")
        );
        assert_eq!(
            split_for("/home/me/app:/app:ro", None, Some("Ubuntu")).unwrap(),
            t("/mnt/wsl/kiri/roots/Ubuntu/home/me/app", "/app", "ro")
        );
        assert_eq!(
            split_for("/mnt/c/proj:/app", Some(&w), Some("Ubuntu")).unwrap(),
            t("/mnt/c/proj", "/app", "")
        );
        assert_eq!(
            split_for("/var/run/docker.sock:/var/run/docker.sock", Some(&w), Some("Ubuntu")).unwrap(),
            t("/var/run/docker.sock", "/var/run/docker.sock", "")
        );
        assert_eq!(
            split_for("/run/docker.sock:/var/run/docker.sock", Some(&w), Some("Ubuntu")).unwrap(),
            t("/run/docker.sock", "/var/run/docker.sock", "")
        );
        assert_eq!(
            split_for("/run/host-services/ssh-auth.sock:/run/host-services/ssh-auth.sock", Some(&w), Some("Ubuntu")).unwrap(),
            t("/run/host-services/ssh-auth.sock", "/run/host-services/ssh-auth.sock", "")
        );
        assert_eq!(
            split_for("/sys/fs/cgroup:/sys/fs/cgroup", Some(&w), Some("Ubuntu")).unwrap(),
            t("/sys/fs/cgroup", "/sys/fs/cgroup", "")
        );
        assert_eq!(
            split_for("/sys:/hostsys:ro", Some(&w), Some("Ubuntu")).unwrap(),
            t("/sys", "/hostsys", "ro")
        );
        assert_eq!(
            split_for("/sys/fs/./cgroup:/mnt2", Some(&w), Some("Ubuntu")).unwrap(),
            t("/sys/fs/cgroup", "/mnt2", "")
        );
        assert_eq!(
            distro_source("/sys/../etc/passwd", "Ubuntu", Some(&w)).unwrap(),
            "/mnt/wsl/kiri/roots/Ubuntu/etc/passwd"
        );
        assert_eq!(
            split_for("myvol:/data", Some(&w), Some("Ubuntu")).unwrap(),
            t("myvol", "/data", "")
        );
        // `..` traversal confinement: cannot escape `<NAME>`'s root.
        for traversal in [
            "/mnt/wsl/kiri/roots/Ubuntu/../../etc",
            "/mnt/wsl/kiri/roots/Ubuntu/../../../../etc",
            "/../../etc",
            "/home/me/../../../etc",
            "/mnt/c/../../etc",
        ] {
            assert_eq!(
                distro_source(traversal, "Ubuntu", Some(&w)).unwrap(),
                "/mnt/wsl/kiri/roots/Ubuntu/etc",
                "{traversal}"
            );
        }
        // Mounting another distro's root or Kiri's internal WSL dir is refused.
        assert!(distro_source("/mnt/wsl/kiri/roots/Debian/etc", "Ubuntu", Some(&w)).is_err());
        assert!(distro_source("//mnt/wsl/kiri/roots/Debian/etc", "Ubuntu", Some(&w)).is_err());
        assert!(distro_source("///mnt/wsl/kiri/roots/Debian/etc", "Ubuntu", Some(&w)).is_err());
        assert!(distro_source("/mnt/wsl/kiri/sockets/Ubuntu", "Ubuntu", Some(&w)).is_err());
        assert!(distro_source("/home/me", "../evil", Some(&w)).is_err());

        // Redundant leading slashes on Unix paths stay confined to `<distro>`.
        assert_eq!(
            distro_source("//etc/shadow", "Ubuntu", Some(&w)).unwrap(),
            "/mnt/wsl/kiri/roots/Ubuntu/etc/shadow"
        );
        assert_eq!(
            distro_source("///var/lib/kiri", "Ubuntu", Some(&w)).unwrap(),
            "/mnt/wsl/kiri/roots/Ubuntu/var/lib/kiri"
        );
        assert_eq!(
            distro_source("//var/lib/kiri", "Ubuntu", None).unwrap(),
            "/mnt/wsl/kiri/roots/Ubuntu/var/lib/kiri"
        );
        assert_eq!(
            distro_source("//mnt/wsl/kiri/roots/Ubuntu/etc", "Ubuntu", Some(&w)).unwrap(),
            "/mnt/wsl/kiri/roots/Ubuntu/etc"
        );

        // `\\wsl.localhost\<d>` and `//wsl$/<d>` in `distro_source`: only `<d> == <distro>`
        // is allowed (refusing both other user distros and the engine distro `kiri`).
        for own_unc in [
            r"\\wsl.localhost\Ubuntu\home\alice\app",
            r"\\wsl$\ubuntu\home\alice\app",
            "//wsl.localhost/Ubuntu/home/alice/app",
            "//wsl$/UBUNTU/home/alice/app",
        ] {
            assert_eq!(
                distro_source(own_unc, "Ubuntu", Some(&w)).unwrap(),
                "/mnt/wsl/kiri/roots/Ubuntu/home/alice/app",
                "{own_unc}"
            );
        }
        assert_eq!(
            distro_source(r"\\wsl.localhost\Ubuntu\home\alice\..\..\..\etc\shadow", "Ubuntu", Some(&w)).unwrap(),
            "/mnt/wsl/kiri/roots/Ubuntu/etc/shadow"
        );
        for cross_unc in [
            r"\\wsl.localhost\Debian\etc\shadow",
            r"\\wsl$\Debian\home\bob",
            "//wsl.localhost/Debian/etc/shadow",
            r"\\wsl.localhost\kiri\var\lib\kiri",
            r"\\wsl$\kiri\etc\shadow",
            "//wsl.localhost/kiri/var/lib/kiri",
            "//wsl$/kiri/etc/shadow",
            r"\\?\UNC\wsl.localhost\kiri\etc\shadow",
            r"\\server\share\dir",
        ] {
            assert!(distro_source(cross_unc, "Ubuntu", Some(&w)).is_err(), "{cross_unc} with Some(&w)");
            assert!(distro_source(cross_unc, "Ubuntu", None).is_err(), "{cross_unc} with None");
        }

        // From Windows: `\\wsl.localhost\<NAME>\...` is allowed when `<NAME>`'s root is mounted.
        let with_ubuntu = |d: &str| d.eq_ignore_ascii_case("Ubuntu").then(|| "/mnt/wsl/kiri/roots/Ubuntu".to_owned());
        assert_eq!(
            source_with_roots(r"\\wsl.localhost\Ubuntu\home\alice\app", &w, with_ubuntu).unwrap(),
            "/mnt/wsl/kiri/roots/Ubuntu/home/alice/app"
        );
        assert_eq!(
            source_with_roots(r"\\wsl$\ubuntu\home\alice\..\..\etc", &w, with_ubuntu).unwrap(),
            "/mnt/wsl/kiri/roots/Ubuntu/etc"
        );
        assert!(source_with_roots(r"\\wsl.localhost\Debian\home\alice", &w, with_ubuntu).is_err());
    }

    #[test]
    fn dotdot_on_a_drive_stops_at_its_root() {
        assert_eq!(ok(r"C:\..\..\etc:/x:ro"), t("/mnt/c/etc", "/x", "ro"));
        assert_eq!(ok("//c/../../etc:/x"), t("/mnt/c/etc", "/x", ""));
        assert_eq!(ok(r"C:\Users\me\proj\..\other:/x"), t("/mnt/c/Users/me/other", "/x", ""));
    }

    #[test]
    fn a_link_in_a_distro_is_followed_inside_it() {
        let root = std::env::temp_dir().join(format!("kiri-binds-distro-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("usr/share/zoneinfo/Europe")).unwrap();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("usr/share/zoneinfo/Europe/Berlin"), b"TZif").unwrap();
        std::os::unix::fs::symlink("/usr/share/zoneinfo/Europe/Berlin", root.join("etc/localtime")).unwrap();
        std::os::unix::fs::symlink("../../../..", root.join("etc/up")).unwrap();
        std::os::unix::fs::symlink("/mnt/c/Users/me", root.join("etc/win")).unwrap();
        std::os::unix::fs::symlink("loop", root.join("loop")).unwrap();
        let followed = |p: &str| resolve_in_root(&root, p);
        assert_eq!(followed("/etc/localtime").unwrap(), ("/usr/share/zoneinfo/Europe/Berlin".to_owned(), true));
        assert_eq!(followed("/etc/up/etc").unwrap(), ("/etc".to_owned(), false));
        assert_eq!(followed("/etc/win/src").unwrap(), ("/mnt/c/Users/me/src".to_owned(), true));
        assert_eq!(followed("/home/me/app").unwrap(), ("/home/me/app".to_owned(), false));
        assert_eq!(followed("/loop"), None);
        assert_eq!(resolve_in_root(&root.join("missing"), "/etc/../x").unwrap(), ("/x".to_owned(), false));
        let _ = std::fs::remove_dir_all(&root);
    }
}
