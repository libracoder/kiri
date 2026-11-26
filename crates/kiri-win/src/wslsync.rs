//! Putting the engine this app installed into its WSL distro: the binaries,
//! and in Kiri Linux its start script and wsl.conf (whose boot command
//! starts the engine whenever WSL boots the distro). The script is built
//! here and run by crates/kiri-win/src/update.rs; tested on any host.

use std::path::Path;
use std::sync::{Mutex, TryLockError};

/// Kiri Linux's own files, as this version has them.
const KIRI_START: &str = include_str!("../../../contrib/wsl/kiri-linux/kiri-start");
const WSL_CONF: &str = include_str!("../../../contrib/wsl/kiri-linux/wsl.conf");

/// The script, run in WSL as root, that makes the engine in /usr/local/bin
/// (where both distros keep it: kiri-start, install.sh) the one in the
/// Windows folder `from`, and in Kiri Linux (`kiri_linux`) its kiri-start
/// this version's and /etc/wsl.conf's `[boot] command` this version's
/// (the rest of that file is left as it is). Only what differs is copied,
/// each file replaced whole through a temp file of its own (two copies at
/// once never write into one); it prints "copied" when anything was. Any
/// step that fails ends it, exit 1 and why on stderr. `root` is "" but in
/// tests.
pub fn sync_script(from: &Path, root: &str, kiri_linux: bool) -> String {
    let win = |f: &str| sh_quote(&from.join(f).to_string_lossy().replace('\\', "/"));
    let (bin, conf) = (sh_quote(&format!("{root}/usr/local/bin")), sh_quote(&format!("{root}/etc/wsl.conf")));
    let mut s = format!(
        "d=/tmp/kiri-sync.$$; trap 'rm -f $d.*' EXIT; c=0; \
         fail() {{ echo \"$1\" >&2; exit 1; }}; \
         put() {{ cmp -s \"$1\" \"$2\" && return 0; cp -f \"$1\" \"$2.new.$$\" && chmod \"$3\" \"$2.new.$$\" && mv -f \"$2.new.$$\" \"$2\" && c=1 || {{ rm -f \"$2.new.$$\"; fail \"could not put $2 into WSL\"; }}; }}; \
         put \"$(wslpath -a {})\" {bin}/kiri 755; put \"$(wslpath -a {})\" {bin}/kiri-init 755; ",
        win("kiri"),
        win("kiri-init")
    );
    if kiri_linux {
        // As base64, decoded there: the newlines, quotes and `$` of a
        // script passed as they are would rely on how wsl.exe carries an
        // argument's control characters into Linux, which is not documented.
        s += &format!(
            "printf %s {} | base64 -d >$d.start || fail 'could not decode kiri-start in WSL'; put $d.start {bin}/kiri-start 755; \
             if [ -f {conf} ]; then awk -v want={} {} {conf}; else awk -v want={} {} /dev/null; fi >$d.conf || fail 'could not read /etc/wsl.conf in WSL'; put $d.conf {conf} 644; ",
            base64(KIRI_START.as_bytes()),
            sh_quote(boot_command()),
            sh_quote(BOOT_AWK),
            sh_quote(boot_command()),
            sh_quote(BOOT_AWK),
        );
    }
    s + "[ $c = 1 ] && echo copied; true"
}

/// The `command = …` line of this version's wsl.conf.
fn boot_command() -> &'static str {
    WSL_CONF.lines().find(|l| l.starts_with("command =")).unwrap_or_default()
}

/// wsl.conf with `want` as its `[boot] command`: an existing one replaced
/// where it is, else added at the end of `[boot]`, or a `[boot]` added at
/// the end; everything else as it was. A line is matched without its
/// spaces, a `#` comment, or the `\r` of a file saved with CRLF
/// ([[:space:]] has it). On one line, with no backslash, as the rest of
/// the script.
const BOOT_AWK: &str = "function key(l) { if (NR == 1) sub(/^\u{feff}/, \"\", l); sub(/[#;].*/, \"\", l); gsub(/[[:space:]]/, \"\", l); return tolower(l) } \
     function flush() { if (boot && !done) { print want; done = 1 } } \
     NR == 1 { sub(/^\u{feff}/, \"\") } \
     substr(key($0), 1, 1) == \"[\" { flush(); boot = key($0) == \"[boot]\"; print; next } \
     boot && index(key($0), \"command=\") == 1 { if (!done) { print want; done = 1 } next } \
     { print } \
     END { flush(); if (!done) { if (NR) print \"\"; print \"[boot]\"; print want } }";

/// Moving an engine older than this app over to this app's, at most once
/// per run of kiri-win. After an update, Kiri Linux's boot command (or the
/// bridge) starts the engine in WSL before kiri-win can copy the new one in,
/// so finding it answering says nothing about its version: that is asked
/// once it answers. A restart that fails is not tried again in this run
/// (the window offers it again). One asked while another runs returns at
/// once, so two never overlap and none pile up behind a slow one.
pub struct CatchUp(Mutex<bool>);

impl CatchUp {
    pub const fn new() -> CatchUp {
        CatchUp(Mutex::new(false))
    }

    /// Asks `version` for the engine's version (None: it did not say) and,
    /// the first time it says one that is `behind` (older than this app's:
    /// not a newer one, nor a development build's), runs `restart`. Once
    /// any version has been read, nothing is asked again. True if it ran
    /// `restart`.
    pub fn run(&self, version: impl FnOnce() -> Option<String>, behind: impl FnOnce(&str) -> bool, restart: impl FnOnce(&str)) -> bool {
        let mut done = match self.0.try_lock() {
            Ok(g) => g,
            Err(TryLockError::Poisoned(e)) => e.into_inner(),
            Err(TryLockError::WouldBlock) => return false,
        };
        if *done {
            return false;
        }
        let Some(v) = version() else { return false };
        *done = true;
        if !behind(&v) {
            return false;
        }
        restart(&v);
        true
    }
}

/// `s` as one sh word.
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn base64(bytes: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = c.iter().enumerate().fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= c.len() { char::from(ABC[(n >> (18 - 6 * i) & 63) as usize]) } else { '=' });
        }
    }
    out
}

/// wsl.exe's arguments to run `script` with sh as root in `distro`. With
/// `-e` (`--exec`), not `--`: after `--` wsl.exe hands the rest of its
/// command line to the distro's login shell, which expands the script's
/// `$1`, `$(...)` and quotes before `sh -c` sees it; `-e` runs sh itself,
/// with the script as one argument, as given.
pub fn wsl_sh<'a>(distro: &'a str, script: &'a str) -> [&'a str; 8] {
    ["-d", distro, "-u", "root", "-e", "sh", "-c", script]
}

/// Whether `name` is a valid single-component WSL distro name.
pub fn valid_distro_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.starts_with('-')
        && !name.contains(['/', '\\', '\0', ':', '*', '?', '"', '<', '>', '|'])
        && !name.bytes().any(|b| b.is_ascii_control())
}

/// Decodes `wsl.exe` output (UTF-16LE with or without BOM, or UTF-8),
/// dropping any leading BOM and NUL bytes.
pub fn wsl_text(bytes: &[u8]) -> String {
    let (bytes, bom) = bytes.strip_prefix(&[0xFF, 0xFE]).map_or((bytes, false), |rest| (rest, true));
    let units = bytes.len() / 2;
    let ascii = bytes.as_chunks::<2>().0.iter().filter(|&&[lo, hi]| lo != 0 && hi == 0).count();
    let looks_utf16 = ascii >= 2 && ascii * 4 >= units;
    let text = if bom || looks_utf16 {
        let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|&p| u16::from_le_bytes(p)).collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };
    text.trim_start_matches('\u{feff}').replace('\0', "")
}

/// Parses `wsl.exe --list --quiet` output into user distros eligible for WSL
/// integration, filtering out `kiri`, `engine_distro`, `docker-desktop`,
/// `docker-desktop-data` (`docker-desktop*`), empty lines and BOMs.
pub fn parse_wsl_distros(bytes: &[u8], engine_distro: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    for line in wsl_text(bytes).lines() {
        let d = line.trim().trim_matches('\u{feff}').trim();
        if !valid_distro_name(d) {
            continue;
        }
        let lower = d.to_ascii_lowercase();
        if lower == "kiri" || lower.starts_with("docker-desktop") {
            continue;
        }
        if engine_distro.is_some_and(|e| d.eq_ignore_ascii_case(e)) {
            continue;
        }
        if !out.iter().any(|x: &String| x.eq_ignore_ascii_case(d)) {
            out.push(d.to_owned());
        }
    }
    out
}

/// Parses `%LOCALAPPDATA%\Kiri\wsl-integration.json`; off (empty) by default.
pub fn parse_enabled_distros(bytes: &[u8]) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_slice(bytes).unwrap_or(serde_json::Value::Null);
    let arr = v["distros"].as_array().or_else(|| v.as_array());
    let mut out = Vec::new();
    for item in arr.into_iter().flatten() {
        let Some(d) = item.as_str().map(str::trim) else { continue };
        if valid_distro_name(d)
            && !d.eq_ignore_ascii_case("kiri")
            && !d.to_ascii_lowercase().starts_with("docker-desktop")
            && !out.iter().any(|x: &String| x.eq_ignore_ascii_case(d))
        {
            out.push(d.to_owned());
        }
    }
    out
}

/// Encodes the enabled distros for `%LOCALAPPDATA%\Kiri\wsl-integration.json`.
pub fn encode_enabled_distros(distros: &[String]) -> Vec<u8> {
    serde_json::to_vec_pretty(&serde_json::json!({ "distros": distros })).unwrap_or_default()
}

/// Why Kiri's WSL 2 storage filesystem (`/` or `/var/lib/kiri`) is read-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WslReadOnly {
    /// Linux ext4 aborted its journal (`errors=remount-ro`) and added `emergency_ro`.
    EmergencyRo,
    /// Mounted read-only (`ro`).
    ReadOnly,
}

impl WslReadOnly {
    fn merge(self, other: Self) -> Self {
        if self == Self::EmergencyRo || other == Self::EmergencyRo {
            Self::EmergencyRo
        } else {
            Self::ReadOnly
        }
    }
}

fn unescape_proc_mount_path(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4].iter().all(|b| (b'0'..=b'7').contains(b))
        {
            let val = ((bytes[i + 1] - b'0') << 6) | ((bytes[i + 2] - b'0') << 3) | (bytes[i + 3] - b'0');
            out.push(val);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_mount_opts(opts: &str) -> Option<WslReadOnly> {
    let mut ro = false;
    for opt in opts.split(',') {
        match opt.trim() {
            "emergency_ro" => return Some(WslReadOnly::EmergencyRo),
            "ro" => ro = true,
            _ => {}
        }
    }
    ro.then_some(WslReadOnly::ReadOnly)
}

fn mount_for_target(proc_mounts: &str, target: &str) -> Option<WslReadOnly> {
    let mut best: Option<(usize, Option<WslReadOnly>)> = None;
    for line in proc_mounts.lines() {
        let mut f = line.split_whitespace();
        let (Some(_spec), Some(mp_raw), Some(_fstype), Some(opts)) = (f.next(), f.next(), f.next(), f.next()) else {
            continue;
        };
        let mp = unescape_proc_mount_path(mp_raw);
        let mp_norm = {
            let t = mp.trim_end_matches('/');
            if t.is_empty() { "/" } else { t }
        };
        let covers = mp_norm == "/"
            || target == mp_norm
            || (target.starts_with(mp_norm) && target.as_bytes().get(mp_norm.len()) == Some(&b'/'));
        if covers && best.is_none_or(|(len, _)| mp_norm.len() >= len) {
            best = Some((mp_norm.len(), parse_mount_opts(opts)));
        }
    }
    best.and_then(|(_, kind)| kind)
}

/// Checks `/proc/mounts` text from Kiri's WSL distro for `/` or `/var/lib/kiri`
/// mounted read-only (`ro` or ext4 `emergency_ro`, #768).
pub fn parse_wsl_readonly_mounts(proc_mounts: &str) -> Option<WslReadOnly> {
    match (mount_for_target(proc_mounts, "/"), mount_for_target(proc_mounts, "/var/lib/kiri")) {
        (Some(a), Some(b)) => Some(a.merge(b)),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    }
}

/// Formats an actionable recovery message naming `vhdx_path` when known.
pub fn wsl_readonly_message(kind: WslReadOnly, vhdx_path: Option<&Path>) -> String {
    let state = match kind {
        WslReadOnly::EmergencyRo => "was remounted read-only by Linux (emergency_ro)",
        WslReadOnly::ReadOnly => "is mounted read-only (emergency_ro)",
    };
    let vhdx = vhdx_path
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| r"<path>\ext4.vhdx".to_owned());
    format!(
        "Kiri's WSL2 disk (ext4.vhdx) {state} after an unclean shutdown or filesystem error. \
         To recover: 1) run `wsl --shutdown` in PowerShell; \
         2) attach the disk bare with `wsl --mount \"{vhdx}\" --vhd --bare`; \
         3) from another Linux distro in WSL, find the device with `lsblk` and run `sudo e2fsck -f -y -D /dev/<disk>`, then `wsl --unmount`; \
         or move/recreate storage in Settings -> Storage."
    )
}

/// SHA-256 of `"kiri"`, used by the Docker CLI for `~/.docker/contexts/meta/<hash>/meta.json`.
const KIRI_CONTEXT_HASH: &str = "c288b06224b0bc4af8a3d80f683a27a8fc72e45f901a7e6766109e2fc1d5c2b9";

const DEFAULT_USER_AWK: &str = "function k(s) { sub(/#.*/, \"\", s); gsub(/[[:space:]]/, \"\", s); return s } \
    substr(k($0), 1, 1) == \"[\" { u = tolower(k($0)) == \"[user]\"; next } \
    u && index(tolower(k($0)), \"default=\") == 1 { s = k($0); sub(/^[dD][eE][fF][aA][uU][lL][tT]=/, \"\", s); print s; exit }";

const PASSWD_AWK: &str = "def != \"\" && $1 == def && $3 != 0 && $4 ~ /^[0-9]+$/ { print $1 \":\" $3 \":\" $4 \":\" $6; found = 1; exit } \
    $3 == 1000 && $4 ~ /^[0-9]+$/ && !u1000 { u1000 = $1 \":\" $3 \":\" $4 \":\" $6 } \
    $3 >= 1000 && $3 < 65534 && $4 ~ /^[0-9]+$/ && !ufirst { ufirst = $1 \":\" $3 \":\" $4 \":\" $6 } \
    END { if (!found) { if (u1000) print u1000; else if (ufirst) print ufirst } }";

/// The script, run as root inside `distro`, that enables Kiri's WSL integration:
/// 1. Mounts `distro`'s `/` onto `/mnt/wsl/kiri/roots/<distro>`.
/// 2. Determines the socket GID (`docker` group GID if `docker` exists in
///    `/etc/group`, otherwise the default non-root user's primary GID in
///    `/etc/passwd`, so NixOS without `groupadd` works cleanly).
/// 3. Links `/var/run/docker.sock -> /mnt/wsl/kiri/sockets/<distro>/docker.sock`
///    unless `/var/run/docker.sock` belongs to a running `dockerd` inside `distro`,
///    and writes the `kiri` Docker context for the default user.
/// 4. Prints the numeric GID on stdout.
/// `root` is `""` in production and a stand-in directory in unit tests.
pub fn wsl_enable_script(distro: &str, root: &str) -> String {
    let bind_root = sh_quote(&format!("{root}/mnt/wsl/kiri/roots/{distro}"));
    let sock_target = sh_quote(&format!("{root}/mnt/wsl/kiri/sockets/{distro}/docker.sock"));
    let src_root = sh_quote(if root.is_empty() { "/" } else { root });
    let etc_group = sh_quote(&format!("{root}/etc/group"));
    let etc_passwd = sh_quote(&format!("{root}/etc/passwd"));
    let etc_wsl = sh_quote(&format!("{root}/etc/wsl.conf"));
    let var_run = sh_quote(&format!("{root}/var/run"));
    let host_prefix = sh_quote(root);
    let ctx_meta = serde_json::json!({
        "Name": "kiri",
        "Metadata": { "Description": "Kiri" },
        "Endpoints": {
            "docker": {
                "Host": format!("unix://{root}/mnt/wsl/kiri/sockets/{distro}/docker.sock"),
                "SkipTLSVerify": false
            }
        }
    })
    .to_string();
    format!(
        "export PATH=\"$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin\"; \
         r={bind_root}; mkdir -p \"$r\" || exit 1; \
         if ! mountpoint -q \"$r\" 2>/dev/null && ! grep -Fqs \" $r \" /proc/mounts 2>/dev/null; then mount --bind {src_root} \"$r\" || exit 1; fi; \
         defuser=\"\"; [ -f {etc_wsl} ] && defuser=$(awk {} {etc_wsl} 2>/dev/null); \
         uinfo=\"\"; [ -f {etc_passwd} ] && uinfo=$(awk -F: -v def=\"$defuser\" {} {etc_passwd} 2>/dev/null); \
         uname=$(printf %s \"$uinfo\" | cut -d: -f1); \
         uuid=$(printf %s \"$uinfo\" | cut -d: -f2); \
         ugid=$(printf %s \"$uinfo\" | cut -d: -f3); \
         uhome=$(printf %s \"$uinfo\" | cut -d: -f4); \
         dgid=\"\"; [ -f {etc_group} ] && dgid=$(awk -F: '$1 == \"docker\" && $3 ~ /^[0-9]+$/ {{ print $3; exit }}' {etc_group} 2>/dev/null); \
         if [ -n \"$dgid\" ]; then \
           gid=\"$dgid\"; \
           if [ -n \"$uname\" ] && command -v usermod >/dev/null 2>&1; then usermod -aG docker \"$uname\" 2>/dev/null || true; fi; \
         elif [ -n \"$ugid\" ]; then \
           gid=\"$ugid\"; \
         else \
           gid=0; \
         fi; \
         vr={var_run}; mkdir -p \"$vr\" || exit 1; \
         busy=0; \
         if [ -S \"$vr/docker.sock\" ] && [ ! -L \"$vr/docker.sock\" ]; then \
           if [ -f \"$vr/docker.pid\" ] && kill -0 \"$(cat \"$vr/docker.pid\" 2>/dev/null)\" 2>/dev/null; then busy=1; \
           elif pgrep -x dockerd >/dev/null 2>&1 || pidof dockerd >/dev/null 2>&1; then busy=1; fi; \
         fi; \
         [ \"$busy\" = 0 ] && ln -sfn {sock_target} \"$vr/docker.sock\"; \
         if [ -n \"$uhome\" ] && [ -d {host_prefix}\"$uhome\" ]; then \
           cdir={host_prefix}\"$uhome/.docker/contexts/meta/{KIRI_CONTEXT_HASH}\"; \
           mkdir -p \"$cdir\" 2>/dev/null && printf %s {} | base64 -d >\"$cdir/meta.json\" 2>/dev/null; \
           [ -n \"$uuid\" ] && [ -n \"$ugid\" ] && chown -R \"$uuid:$ugid\" {host_prefix}\"$uhome/.docker\" 2>/dev/null || true; \
         fi; \
         echo \"$gid\"",
        sh_quote(DEFAULT_USER_AWK),
        sh_quote(PASSWD_AWK),
        base64(ctx_meta.as_bytes()),
    )
}

/// The script, run as root inside `distro`, that tears down Kiri's WSL
/// integration when `distro` is disabled: removes `/var/run/docker.sock` if it
/// points into `/mnt/wsl/kiri/`, unmounts `/mnt/wsl/kiri/roots/<distro>`, and
/// removes `/mnt/wsl/kiri/sockets/<distro>/docker.sock`.
pub fn wsl_disable_script(distro: &str, root: &str) -> String {
    let bind_root = sh_quote(&format!("{root}/mnt/wsl/kiri/roots/{distro}"));
    let sock_dir = sh_quote(&format!("{root}/mnt/wsl/kiri/sockets/{distro}"));
    let var_run = sh_quote(&format!("{root}/var/run"));
    format!(
        "export PATH=\"$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin\"; \
         vr={var_run}; \
         if [ -L \"$vr/docker.sock\" ]; then \
           t=$(readlink \"$vr/docker.sock\" 2>/dev/null || true); \
           case \"$t\" in */mnt/wsl/kiri/*) rm -f \"$vr/docker.sock\" ;; esac; \
         fi; \
         r={bind_root}; \
         if mountpoint -q \"$r\" 2>/dev/null || grep -Fqs \" $r \" /proc/mounts 2>/dev/null; then \
           umount -l \"$r\" 2>/dev/null || umount \"$r\" 2>/dev/null || true; \
         fi; \
         rmdir \"$r\" 2>/dev/null || true; \
         sd={sock_dir}; rm -f \"$sd/docker.sock\" 2>/dev/null || true; rmdir \"$sd\" 2>/dev/null || true; true"
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    /// The script, in sh, against a stand-in root and a `wslpath` that
    /// gives the path as is: it copies what differs, puts this version's
    /// kiri-start and wsl.conf in, and the second run copies nothing.
    #[test]
    fn sync_puts_the_engine_and_kiri_linux_files_in() {
        let dir = std::env::temp_dir().join(format!("kiri-wslsync-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (from, root, tools) = (dir.join("win"), dir.join("root"), dir.join("tools"));
        for d in [&from, &root.join("usr/local/bin"), &root.join("etc"), &tools] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(from.join("kiri"), "new kiri").unwrap();
        std::fs::write(from.join("kiri-init"), "init").unwrap();
        std::fs::write(root.join("usr/local/bin/kiri"), "old kiri").unwrap();
        std::fs::write(root.join("usr/local/bin/kiri-init"), "init").unwrap();
        std::fs::write(root.join("usr/local/bin/kiri-start"), "old start").unwrap();
        // An older Kiri Linux's, and a user's own line.
        std::fs::write(root.join("etc/wsl.conf"), "[boot]\nsystemd = false\n\n[user]\ndefault = root\n[automount]\noptions = metadata\n").unwrap();
        std::fs::write(tools.join("wslpath"), "#!/bin/sh\n[ \"$1\" = -a ] && shift\necho \"$1\"\n").unwrap();
        std::fs::set_permissions(tools.join("wslpath"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = format!("{}:{}", tools.display(), std::env::var("PATH").unwrap_or_default());
        let script = sync_script(&from, &root.to_string_lossy(), true);
        let run = || Command::new("sh").args(["-c", &script]).env("PATH", &path).output().unwrap();
        let out = run();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "copied");
        let read = |p: &str| std::fs::read_to_string(root.join(p)).unwrap();
        assert_eq!(read("usr/local/bin/kiri"), "new kiri");
        assert_eq!(read("usr/local/bin/kiri-start"), KIRI_START);
        let want = boot_command();
        assert!(want.starts_with("command = /usr/local/bin/kiri-start"), "{want}");
        assert_eq!(read("etc/wsl.conf"), format!("[boot]\nsystemd = false\n\n{want}\n[user]\ndefault = root\n[automount]\noptions = metadata\n"));
        let mode = |p: &str| std::fs::metadata(root.join(p)).unwrap().permissions().mode() & 0o777;
        assert_eq!((mode("usr/local/bin/kiri"), mode("usr/local/bin/kiri-start"), mode("etc/wsl.conf")), (0o755, 0o755, 0o644));
        // No temp file left behind.
        let left: Vec<_> = std::fs::read_dir(root.join("usr/local/bin")).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(left.len(), 3, "{left:?}");
        // Everything is this version's now: nothing copied.
        let out = run();
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "");
        // Ubuntu's: the binaries only.
        std::fs::write(from.join("kiri"), "newer kiri").unwrap();
        std::fs::write(root.join("usr/local/bin/kiri-start"), "keep").unwrap();
        let out = Command::new("sh").args(["-c", &sync_script(&from, &root.to_string_lossy(), false)]).env("PATH", &path).output().unwrap();
        assert!(out.status.success());
        assert_eq!((read("usr/local/bin/kiri").as_str(), read("usr/local/bin/kiri-start").as_str()), ("newer kiri", "keep"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A stand-in root and tools for the script: (Windows folder, root, PATH).
    fn stand_in(name: &str) -> (std::path::PathBuf, std::path::PathBuf, String) {
        let dir = std::env::temp_dir().join(format!("kiri-wslsync-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (from, root, tools) = (dir.join("win"), dir.join("root"), dir.join("tools"));
        for d in [&from, &root.join("usr/local/bin"), &root.join("etc"), &tools] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(from.join("kiri"), "kiri").unwrap();
        std::fs::write(from.join("kiri-init"), "init").unwrap();
        std::fs::write(tools.join("wslpath"), "#!/bin/sh\n[ \"$1\" = -a ] && shift\necho \"$1\"\n").unwrap();
        std::fs::set_permissions(tools.join("wslpath"), std::fs::Permissions::from_mode(0o755)).unwrap();
        (from, root, format!("{}:{}", tools.display(), std::env::var("PATH").unwrap_or_default()))
    }

    /// wsl.conf keeps what a user put in it: only its `[boot] command` is
    /// made this version's, replaced where it is or added; this version's
    /// own wsl.conf is left exactly as it is.
    #[test]
    fn wsl_conf_keeps_the_rest() {
        let (from, root, path) = stand_in("conf");
        let want = boot_command();
        let run = |conf: Option<&str>| {
            let f = root.join("etc/wsl.conf");
            match conf {
                Some(c) => std::fs::write(&f, c).unwrap(),
                None => {
                    let _ = std::fs::remove_file(&f);
                }
            }
            let out = Command::new("sh").args(["-c", &sync_script(&from, &root.to_string_lossy(), true)]).env("PATH", &path).output().unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
            std::fs::read_to_string(&f).unwrap()
        };
        assert_eq!(run(Some(WSL_CONF)), WSL_CONF);
        assert_eq!(run(Some("[network]\nhostname = box\n[boot]\ncommand = /old/start\nsystemd = false\n")), format!("[network]\nhostname = box\n[boot]\n{want}\nsystemd = false\n"));
        assert_eq!(run(Some("[ boot ]\n  command=/a\ncommand = /b\n")), format!("[ boot ]\n{want}\n"));
        assert_eq!(run(Some("[user]\ndefault = root\n")), format!("[user]\ndefault = root\n\n[boot]\n{want}\n"));
        // Saved with CRLF, and a header with a comment: still the one [boot].
        assert_eq!(run(Some("[boot]\r\nsystemd = false\r\ncommand = /old\r\n[user]\r\ndefault = root\r\n")), format!("[boot]\r\nsystemd = false\r\n{want}\n[user]\r\ndefault = root\r\n"));
        assert_eq!(run(Some("[boot] # Kiri's\ncommand=/old # mine\n")), format!("[boot] # Kiri's\n{want}\n"));
        // A commented-out command is left, and one added.
        assert_eq!(run(Some("[boot]\n# command = /off\n")), format!("[boot]\n# command = /off\n{want}\n"));
        // Case-insensitive [Boot]/Command, UTF-8 BOM, and ';' comments.
        assert_eq!(run(Some("[Boot]\nCommand = /old\nsystemd = false\n")), format!("[Boot]\n{want}\nsystemd = false\n"));
        assert_eq!(
            run(Some("\u{feff}[BOOT]\nCOMMAND = /old\n[automount]\noptions = metadata;umask=22\n")),
            format!("[BOOT]\n{want}\n[automount]\noptions = metadata;umask=22\n")
        );
        assert_eq!(
            run(Some("; [boot]\n[boot] ; header\n; command = /off\ncommand = /old ; inline\n")),
            format!("; [boot]\n[boot] ; header\n; command = /off\n{want}\n")
        );
        assert_eq!(run(None), format!("[boot]\n{want}\n"));
        let _ = std::fs::remove_dir_all(root.parent().unwrap());
    }

    /// A step that fails ends the script with why: here base64 -d.
    #[test]
    fn a_failed_step_fails_the_script() {
        let (from, root, path) = stand_in("fail");
        let tools = path.split(':').next().unwrap();
        std::fs::write(format!("{tools}/base64"), "#!/bin/sh\nexit 1\n").unwrap();
        std::fs::set_permissions(format!("{tools}/base64"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let out = Command::new("sh").args(["-c", &sync_script(&from, &root.to_string_lossy(), true)]).env("PATH", &path).output().unwrap();
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(String::from_utf8_lossy(&out.stderr).trim(), "could not decode kiri-start in WSL");
        assert!(!root.join("usr/local/bin/kiri-start").exists());
        let _ = std::fs::remove_dir_all(root.parent().unwrap());
    }

    /// No backslash in the script: how wsl.exe reads one in an argument
    /// is Windows' quoting, not sh's.
    #[test]
    fn the_script_has_no_backslash() {
        assert!(!KIRI_START.contains('\\'));
        assert!(!sync_script(Path::new("C:/Users/x/AppData/Local/Kiri"), "", true).contains('\\'));
    }

    #[test]
    fn kiri_start_refuses_emergency_ro_with_clean_recovery_message() {
        let dir = std::env::temp_dir().join(format!("kiri-start-ro-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mounts = dir.join("mounts");
        std::fs::write(
            &mounts,
            "/dev/sdd / ext4 rw,relatime,discard,errors=remount-ro,data=ordered,emergency_ro 0 0\ntmpfs /run tmpfs rw,nosuid,nodev,mode=755 0 0\n",
        )
        .unwrap();
        let out = Command::new("sh")
            .args(["-c", KIRI_START])
            .env("KIRI_PROC_MOUNTS", &mounts)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("Kiri's WSL2 disk (ext4.vhdx) was remounted read-only by Linux (emergency_ro)"), "{err}");
        assert!(err.contains("wsl --shutdown") && err.contains("wsl --mount") && err.contains("e2fsck -f -y -D"), "{err}");
        assert!(err.contains("Settings -> Storage"), "{err}");
        assert!(!err.contains(r"'\''") && !err.contains('\x1b'), "unescaped quotes or control chars leaked: {err:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An engine older than this app is restarted once: not again after
    /// that (a restart that failed does not loop), not while it does not
    /// answer, not when it is not behind (current, newer, a development
    /// build), and one asked while a restart runs returns at once.
    #[test]
    fn a_stale_engine_is_caught_up_once() {
        let behind = |v: &str| v == "0.1.18";
        let c = CatchUp::new();
        let restarts = std::sync::atomic::AtomicUsize::new(0);
        let restart = |v: &str| {
            assert_eq!(v, "0.1.18");
            restarts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        };
        // Not answering: nothing done, asked again next time.
        assert!(!c.run(|| None, behind, restart));
        assert!(c.run(|| Some("0.1.18".into()), behind, restart));
        // Still old (that restart failed): not again.
        assert!(!c.run(|| Some("0.1.18".into()), behind, restart));
        assert_eq!(restarts.load(std::sync::atomic::Ordering::SeqCst), 1);
        // Not behind: never restarted, and not asked again.
        let c = CatchUp::new();
        assert!(!c.run(|| Some("0.1.20".into()), behind, |_| panic!("restarted an engine that is not behind")));
        assert!(!c.run(|| panic!("asked again"), behind, |_| {}));
        // One asked while a restart runs: back at once, nothing run.
        let c = std::sync::Arc::new(CatchUp::new());
        let (began_tx, began) = std::sync::mpsc::channel();
        let (end, end_rx) = std::sync::mpsc::channel::<()>();
        let first = {
            let c = c.clone();
            std::thread::spawn(move || {
                c.run(
                    || Some("0.1.18".into()),
                    behind,
                    |_| {
                        began_tx.send(()).unwrap();
                        end_rx.recv().unwrap();
                    },
                )
            })
        };
        began.recv().unwrap();
        let t = std::time::Instant::now();
        assert!(!c.run(|| panic!("asked during a restart"), behind, |_| panic!("two restarts")));
        assert!(t.elapsed() < std::time::Duration::from_secs(1));
        end.send(()).unwrap();
        assert!(first.join().unwrap());
    }

    #[test]
    fn base64_as_base64_d_reads_it() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
    }

    /// sh runs the script itself (-e), not the distro's login shell (--),
    /// which would expand its `$` first.
    #[test]
    fn runs_sh_itself() {
        assert_eq!(wsl_sh("kiri", "echo $$"), ["-d", "kiri", "-u", "root", "-e", "sh", "-c", "echo $$"]);
    }

    #[test]
    fn quotes_one_word() {
        assert_eq!(sh_quote("C:/Users/O'Neil/x"), r"'C:/Users/O'\''Neil/x'");
    }

    #[test]
    fn parses_utf16le_wsl_list_and_filters_system_distros() {
        let utf16 = |s: &str| s.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>();
        let raw = "\u{feff}kiri\r\nUbuntu\r\ndocker-desktop\r\ndocker-desktop-data\r\n\r\nNixOS\r\nDebian\r\nUbuntu\r\n";
        assert_eq!(
            parse_wsl_distros(&utf16(raw), Some("kiri")),
            vec!["Ubuntu".to_owned(), "NixOS".to_owned(), "Debian".to_owned()]
        );
        // With explicit UTF-16LE BOM prefix and custom engine distro.
        let mut with_bom = vec![0xFF, 0xFE];
        with_bom.extend_from_slice(&utf16("Ubuntu-26.04\nNixOS\ndocker-desktop\nkiri\n"));
        assert_eq!(
            parse_wsl_distros(&with_bom, Some("Ubuntu-26.04")),
            vec!["NixOS".to_owned()]
        );
        // Enabled distros file defaults to off (empty) and filters system distros.
        assert!(parse_enabled_distros(b"").is_empty());
        let saved = encode_enabled_distros(&["Ubuntu".into(), "NixOS".into()]);
        assert_eq!(parse_enabled_distros(&saved), vec!["Ubuntu".to_owned(), "NixOS".to_owned()]);
    }

    #[test]
    fn wsl_integration_scripts_have_no_backslash() {
        assert!(!wsl_enable_script("Ubuntu", "").contains('\\'));
        assert!(!wsl_disable_script("Ubuntu", "").contains('\\'));
    }

    #[test]
    fn wsl_enable_and_disable_scripts_setup_gid_symlink_and_teardown() {
        use std::os::unix::net::UnixListener;
        let dir = std::env::temp_dir().join(format!("kiri-wsl-integ-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (root, tools) = (dir.join("root"), dir.join("tools"));
        for d in [&root.join("etc"), &root.join("var/run"), &root.join("home/alice"), &tools] {
            std::fs::create_dir_all(d).unwrap();
        }
        // Mock mountpoint, mount and umount in PATH so the test runs unprivileged.
        let mounted_flag = dir.join("mounted");
        std::fs::write(
            tools.join("mountpoint"),
            format!("#!/bin/sh\n[ -f '{}' ]\n", mounted_flag.display()),
        )
        .unwrap();
        std::fs::write(
            tools.join("mount"),
            format!("#!/bin/sh\n[ \"$1\" = --bind ] && [ -d \"$3\" ] && touch '{}'\n", mounted_flag.display()),
        )
        .unwrap();
        std::fs::write(
            tools.join("umount"),
            format!("#!/bin/sh\nrm -f '{}'\n", mounted_flag.display()),
        )
        .unwrap();
        for tool in ["mountpoint", "mount", "umount"] {
            std::fs::set_permissions(tools.join(tool), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = format!("{}:{}", tools.display(), std::env::var("PATH").unwrap_or_default());
        let root_str = root.to_string_lossy();

        // 1. NixOS-like distro without `docker` group: uses default user's primary GID (100).
        std::fs::write(root.join("etc/passwd"), "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:100:Alice:/home/alice:/bin/sh\n").unwrap();
        std::fs::write(root.join("etc/group"), "root:x:0:\nusers:x:100:\n").unwrap();
        let enable = wsl_enable_script("NixOS", &root_str);
        let out = Command::new("sh").args(["-c", &enable]).env("PATH", &path).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "100");
        assert!(mounted_flag.exists(), "root bind mount must be performed");
        assert!(root.join("mnt/wsl/kiri/roots/NixOS").is_dir());
        let link = std::fs::read_link(root.join("var/run/docker.sock")).unwrap();
        assert_eq!(link, root.join("mnt/wsl/kiri/sockets/NixOS/docker.sock"));
        assert!(root.join("home/alice/.docker/contexts/meta").join(KIRI_CONTEXT_HASH).join("meta.json").is_file());

        // 2. Distro with `docker` group in /etc/group: uses `docker` group GID (131).
        std::fs::write(root.join("etc/group"), "root:x:0:\nusers:x:100:\ndocker:x:131:alice\n").unwrap();
        let out = Command::new("sh").args(["-c", &enable]).env("PATH", &path).output().unwrap();
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "131");

        // 3. Disable script unmounts root, removes /var/run/docker.sock symlink and socket dir.
        let sock_dir = root.join("mnt/wsl/kiri/sockets/NixOS");
        std::fs::create_dir_all(&sock_dir).unwrap();
        std::fs::write(sock_dir.join("docker.sock"), "").unwrap();
        let disable = wsl_disable_script("NixOS", &root_str);
        let out = Command::new("sh").args(["-c", &disable]).env("PATH", &path).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert!(!mounted_flag.exists(), "root bind mount must be unmounted");
        assert!(std::fs::symlink_metadata(root.join("var/run/docker.sock")).is_err(), "symlink must be removed");
        assert!(!sock_dir.exists(), "socket dir must be removed");

        // 4. When a live dockerd owns /var/run/docker.sock, enable leaves it untouched.
        let own_sock = root.join("var/run/docker.sock");
        let _listener = UnixListener::bind(&own_sock).unwrap();
        std::fs::write(root.join("var/run/docker.pid"), std::process::id().to_string()).unwrap();
        let out = Command::new("sh").args(["-c", &enable]).env("PATH", &path).output().unwrap();
        assert!(out.status.success());
        assert!(!std::fs::symlink_metadata(&own_sock).unwrap().file_type().is_symlink(), "running dockerd socket must not be overwritten");
        // And disable leaves a real dockerd socket untouched too.
        let out = Command::new("sh").args(["-c", &disable]).env("PATH", &path).output().unwrap();
        assert!(out.status.success());
        assert!(own_sock.exists(), "running dockerd socket must not be removed on disable");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod ro_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn parses_wsl_proc_mounts_and_formats_vhdx_recovery_message() {
        let healthy = "/dev/sdd / ext4 rw,relatime,discard,errors=remount-ro,data=ordered 0 0\n";
        assert_eq!(parse_wsl_readonly_mounts(healthy), None);

        let emergency = "/dev/sdd / ext4 rw,relatime,discard,errors=remount-ro,data=ordered,emergency_ro 0 0\n";
        assert_eq!(parse_wsl_readonly_mounts(emergency), Some(WslReadOnly::EmergencyRo));

        let separate_ro = "/dev/sda1 / ext4 rw,relatime 0 0\n/dev/sdb1 /var/lib/kiri ext4 ro,relatime 0 0\n";
        assert_eq!(parse_wsl_readonly_mounts(separate_ro), Some(WslReadOnly::ReadOnly));

        let overmounted_rw = "/dev/sda1 / ext4 rw,relatime 0 0\n/dev/sdb1 /var/lib/kiri ext4 ro,relatime 0 0\n/dev/sdb1 /var/lib/kiri ext4 rw,relatime 0 0\n";
        assert_eq!(parse_wsl_readonly_mounts(overmounted_rw), None);

        let msg = wsl_readonly_message(WslReadOnly::EmergencyRo, Some(Path::new(r"D:\KiriData\ext4.vhdx")));
        assert!(msg.contains(r#"wsl --mount "D:\KiriData\ext4.vhdx" --vhd --bare"#), "{msg}");
        assert!(msg.contains("wsl --shutdown") && msg.contains("e2fsck -f -y -D") && msg.contains("Settings -> Storage"), "{msg}");
    }

    #[test]
    fn validates_distro_names_and_sync_script_has_no_backslash() {
        for bad in ["", ".", "..", "-e", "--shutdown", "a/b", r"a\b", "bad:distro", "bad*distro", "bad?distro", "bad\"distro", "bad|distro"] {
            assert!(!valid_distro_name(bad), "expected false for {bad:?}");
        }
        for good in ["Ubuntu", "Ubuntu-24.04", "NixOS", "Arch_Linux", "my.distro"] {
            assert!(valid_distro_name(good), "expected true for {good:?}");
        }
        assert_eq!(parse_enabled_distros(br#"{"distros":["Ubuntu","--shutdown","bad:name","NixOS"]}"#), vec!["Ubuntu".to_owned(), "NixOS".to_owned()]);
        assert!(!sync_script(Path::new("C:/Users/x/AppData/Local/Kiri"), "", true).contains('\\'));
    }
}
