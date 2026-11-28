//! AppArmor on a Linux host. Where the kernel has AppArmor enabled, every
//! container and every `docker exec` runs under Kiri's own profile,
//! `kiri-default` (apparmor/kiri-default), as Docker Engine's run under
//! `docker-default`; `--privileged` and `--security-opt apparmor=unconfined`
//! run without one, and `--security-opt apparmor=<name>` under a profile
//! the host's administrator loaded.
//!
//! The engine loads its profile once, when it starts (`init`), with
//! `apparmor_parser`: the kernel takes only compiled policy, and Kiri carries
//! no compiler of its own. What happens on each kind of host:
//!
//! - no AppArmor (macOS's and Windows' VM, whose kernel is built without it;
//!   WSL; SELinux hosts; AppArmor turned off): nothing changes, nothing is
//!   logged. Options naming a profile are kept for inspect and not applied.
//! - AppArmor on, but this engine may not load policy (it runs in a
//!   container, in a user namespace, or without CAP_MAC_ADMIN): one line in
//!   the log, and containers run unconfined, as before.
//! - AppArmor on, the profile loaded: containers get it.
//! - AppArmor on and the engine allowed, but the profile could not be loaded
//!   (no apparmor_parser, or it failed): containers that would get
//!   `kiri-default` are refused with the reason, as Docker refuses them when
//!   `docker-default` is missing. `--security-opt apparmor=unconfined`,
//!   `--privileged` and a profile of the administrator's still start.

// Loading happens on a Linux host only; elsewhere only the option reading is used.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The profile containers get by default.
pub const DEFAULT_PROFILE: &str = "kiri-default";

/// Its text, as `apparmor_parser` reads it.
pub const PROFILE_TEXT: &str = include_str!("apparmor/kiri-default");

/// What this engine found when it started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    /// No AppArmor, or turned off.
    Absent,
    /// On, but this engine may not load policy (why).
    NoPermission(String),
    /// On, and `kiri-default` is in the kernel.
    Loaded,
    /// On, but `kiri-default` could not be loaded (why).
    Failed(String),
}

impl Host {
    /// Whether containers are put under profiles at all.
    pub fn confines(&self) -> bool {
        matches!(self, Host::Loaded | Host::Failed(_))
    }
}

static HOST: OnceLock<Host> = OnceLock::new();

/// What `init` found; `Absent` before it ran (and on macOS and Windows).
pub fn host() -> &'static Host {
    HOST.get().unwrap_or(&Host::Absent)
}

/// What `--security-opt` asks of AppArmor.
#[derive(Debug, PartialEq, Eq)]
pub enum Choice<'a> {
    /// Nothing: `kiri-default`, or none for `--privileged`.
    Default,
    /// `apparmor=unconfined`.
    Unconfined,
    /// `apparmor=<name>`.
    Named(&'a str),
}

/// Reads the AppArmor entry of `--security-opt` (the last one wins).
/// `apparmor=` and `apparmor:` both, as the docker CLI sends either; an
/// empty name is the default, as with Docker.
pub fn choice(security_opt: &[String]) -> Result<Choice<'_>, String> {
    let Some(value) = security_opt.iter().rev().find_map(|o| o.strip_prefix("apparmor=").or_else(|| o.strip_prefix("apparmor:"))) else {
        return Ok(Choice::Default);
    };
    match value.trim() {
        "" => Ok(Choice::Default),
        "unconfined" => Ok(Choice::Unconfined),
        v if v.len() <= 255 && v.bytes().all(|b| b.is_ascii_graphic()) => Ok(Choice::Named(v)),
        v => Err(format!("invalid AppArmor profile name {v:?}")),
    }
}

/// The profile a container's processes (its start and its execs) run under,
/// or `None` to leave them as before. `loaded` says whether the kernel has a
/// profile of that name.
pub fn profile_for(security_opt: &[String], privileged: bool, host: &Host, loaded: impl Fn(&str) -> bool) -> Result<Option<String>, String> {
    if !host.confines() {
        return Ok(None);
    }
    let default = || match host {
        Host::Failed(why) => Err(format!("{why}; to start this container without an AppArmor profile, run it with --security-opt apparmor=unconfined")),
        _ => Ok(Some(DEFAULT_PROFILE.to_owned())),
    };
    match choice(security_opt)? {
        Choice::Unconfined => Ok(None),
        // `--privileged` runs unconfined unless a profile is named, as with Docker.
        Choice::Default if privileged => Ok(None),
        Choice::Default => default(),
        Choice::Named(DEFAULT_PROFILE) => default(),
        Choice::Named(name) if loaded(name) => Ok(Some(name.to_owned())),
        Choice::Named(name) => Err(format!("AppArmor profile {name:?} is not loaded on this host (load it with apparmor_parser first)")),
    }
}

/// `AppArmorProfile` in a container's inspect, as Docker shows it: the
/// profile named, else, once the container has started on a host that
/// confines containers, the one it got; else empty.
pub fn inspect_profile(security_opt: &[String], privileged: bool, started: bool, host: &Host) -> String {
    match choice(security_opt) {
        Ok(Choice::Named(n)) => n.to_owned(),
        Ok(Choice::Unconfined) => "unconfined".to_owned(),
        _ if started && host.confines() => {
            if privileged { "unconfined" } else { DEFAULT_PROFILE }.to_owned()
        }
        _ => String::new(),
    }
}

/// The guest's host-option line for `profile` (kiri-init `hostopts`).
pub fn guest_line(profile: &str) -> String {
    format!("apparmor\t{profile}")
}

/// Whether the kernel's list of profiles (`apparmor/profiles`: one
/// `name (mode)` a line) has `name`.
pub fn listed(profiles: &str, name: &str) -> bool {
    profiles.lines().any(|l| l.rsplit_once(" (").map_or(l, |(n, _)| n) == name)
}

/// The kernel's list of loaded profiles.
pub fn loaded_profiles() -> String {
    std::fs::read_to_string("/sys/kernel/security/apparmor/profiles").unwrap_or_default()
}

/// Whether AppArmor is enabled under `root` (`/` but in tests): the module
/// says so and its filesystem is there to load policy through.
pub fn enabled(root: &Path) -> bool {
    std::fs::read_to_string(root.join("sys/module/apparmor/parameters/enabled")).is_ok_and(|s| s.trim() == "Y") && root.join("sys/kernel/security/apparmor").is_dir()
}

/// Why this process may not load policy, if it may not: it lacks
/// CAP_MAC_ADMIN, it is in a user namespace of its own (a container's), or
/// the policy files refuse it (securityfs mounted read-only).
pub fn may_not_load(root: &Path) -> Option<String> {
    const CAP_MAC_ADMIN: u32 = 33;
    let status = std::fs::read_to_string(root.join("proc/self/status")).unwrap_or_default();
    let caps = status.lines().find_map(|l| l.strip_prefix("CapEff:")).and_then(|v| u64::from_str_radix(v.trim(), 16).ok()).unwrap_or(0);
    if caps & (1 << CAP_MAC_ADMIN) == 0 {
        return Some("the engine does not have CAP_MAC_ADMIN".into());
    }
    let uid_map = std::fs::read_to_string(root.join("proc/self/uid_map")).unwrap_or_default();
    if uid_map.split_whitespace().collect::<Vec<_>>() != ["0", "0", "4294967295"] {
        return Some("the engine runs in a user namespace".into());
    }
    let replace = root.join("sys/kernel/security/apparmor/.replace");
    match std::fs::OpenOptions::new().write(true).open(&replace) {
        Ok(_) => None,
        Err(e) if matches!(e.raw_os_error(), Some(libc::EACCES | libc::EPERM | libc::EROFS)) => Some(format!("{}: {e}", replace.display())),
        // Anything else is for the load itself to report.
        Err(_) => None,
    }
}

/// The hash of `text` kept beside the engine's state once it is loaded, so
/// the next start loads it again only if it changed or the kernel lost it
/// (a reboot).
pub fn stamp(text: &str) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(text.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// `apparmor_parser`: on PATH, else where distributions put it.
pub fn find_parser(path: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    let dirs = path.map(|p| std::env::split_paths(p).collect::<Vec<_>>()).unwrap_or_default();
    dirs.into_iter().chain(["/usr/sbin", "/sbin", "/usr/bin"].map(PathBuf::from)).map(|d| d.join("apparmor_parser")).find(|p| p.is_file())
}

/// Whether what `apparmor_parser` printed means it was not allowed to load
/// policy (rather than that the policy or the tool is at fault).
pub fn refused_for_permission(stderr: &str) -> bool {
    ["Permission denied", "Access denied", "Operation not permitted"].iter().any(|w| stderr.contains(w))
}

/// Loads `text` with `parser`, replacing a profile of the same name.
/// Err(true, why): not allowed; Err(false, why): any other failure.
fn load(parser: &Path, text: &str) -> Result<(), (bool, String)> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    // -r: load, or replace what is loaded; -K: no cache, the text is on stdin.
    let mut child = Command::new(parser)
        .args(["-r", "-K"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| (false, format!("{}: {e}", parser.display())))?;
    let wrote = child.stdin.take().map(|mut i| i.write_all(text.as_bytes()));
    let out = child.wait_with_output().map_err(|e| (false, format!("{}: {e}", parser.display())))?;
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    if out.status.success() && !matches!(wrote, Some(Err(_))) {
        return Ok(());
    }
    let why = if stderr.is_empty() { format!("{} exited with {}", parser.display(), out.status) } else { stderr };
    Err((refused_for_permission(&why), why))
}

/// Finds out what this host allows and loads `text` if it may: under `root`
/// (`/`, or a fake tree in tests), with the stamp kept in `stamp_dir` and
/// the kernel's list of profiles read by `profiles`.
pub fn start(root: &Path, stamp_dir: &Path, text: &str, parser: Option<PathBuf>, profiles: impl Fn() -> String) -> Host {
    if !enabled(root) {
        return Host::Absent;
    }
    if let Some(why) = may_not_load(root) {
        return Host::NoPermission(why);
    }
    let stamp_file = stamp_dir.join("apparmor-kiri-default");
    let want = stamp(text);
    if listed(&profiles(), DEFAULT_PROFILE) && std::fs::read_to_string(&stamp_file).is_ok_and(|s| s.trim() == want) {
        return Host::Loaded;
    }
    let Some(parser) = parser else {
        return Host::Failed(format!(
            "AppArmor is enabled on this host, but apparmor_parser, which loads Kiri's profile {DEFAULT_PROFILE}, was not found (install the apparmor package and restart Kiri)"
        ));
    };
    match load(&parser, text) {
        Ok(()) => {
            let _ = std::fs::create_dir_all(stamp_dir);
            let _ = std::fs::write(&stamp_file, want);
            Host::Loaded
        }
        Err((true, why)) => Host::NoPermission(why),
        Err((false, why)) => {
            let _ = std::fs::remove_file(&stamp_file);
            Host::Failed(format!("Kiri's AppArmor profile {DEFAULT_PROFILE} could not be loaded: {why}"))
        }
    }
}

/// At engine start, on a Linux host: what the host allows, loaded if it
/// may be, logged once. Later calls change nothing.
#[cfg(target_os = "linux")]
pub fn init(state_dir: &Path) -> &'static Host {
    let t0 = std::time::Instant::now();
    let h = start(Path::new("/"), state_dir, PROFILE_TEXT, find_parser(std::env::var_os("PATH").as_deref()), loaded_profiles);
    match &h {
        Host::Absent => {}
        Host::NoPermission(why) => crate::diag::info!("AppArmor is enabled, but this engine may not load policy: containers run without an AppArmor profile", reason = why),
        Host::Loaded => crate::diag::info!(format!("AppArmor: containers run under the {DEFAULT_PROFILE} profile"), ms = t0.elapsed().as_millis()),
        Host::Failed(why) => crate::diag::warn!("AppArmor: containers that need the default profile will not start", reason = why),
    }
    let _ = HOST.set(h);
    host()
}

/// For `docker info`'s SecurityOptions, worded as Docker Engine words it.
pub fn info_option() -> Option<&'static str> {
    host().confines().then_some("name=apparmor,profile=default")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(o: &[&str]) -> Vec<String> {
        o.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn options_are_read_as_docker_reads_them() {
        assert_eq!(choice(&opts(&[])), Ok(Choice::Default));
        assert_eq!(choice(&opts(&["no-new-privileges", "seccomp=unconfined"])), Ok(Choice::Default));
        assert_eq!(choice(&opts(&["apparmor=unconfined"])), Ok(Choice::Unconfined));
        assert_eq!(choice(&opts(&["apparmor:unconfined"])), Ok(Choice::Unconfined));
        assert_eq!(choice(&opts(&["apparmor=my-profile"])), Ok(Choice::Named("my-profile")));
        assert_eq!(choice(&opts(&["apparmor="])), Ok(Choice::Default));
        assert_eq!(choice(&opts(&["apparmor=unconfined", "apparmor=mine"])), Ok(Choice::Named("mine")), "the last one wins");
        assert!(choice(&opts(&["apparmor=two words"])).is_err());
        assert!(choice(&opts(&["apparmor=a\tb"])).is_err());
    }

    #[test]
    fn which_profile_a_container_gets() {
        let loaded = |n: &str| n == "admins-profile";
        let p = |o: &[&str], privileged: bool, h: &Host| profile_for(&opts(o), privileged, h, loaded);
        let on = Host::Loaded;
        assert_eq!(p(&[], false, &on), Ok(Some("kiri-default".into())));
        assert_eq!(p(&["no-new-privileges"], false, &on), Ok(Some("kiri-default".into())));
        assert_eq!(p(&[], true, &on), Ok(None), "--privileged runs unconfined");
        assert_eq!(p(&["apparmor=unconfined"], false, &on), Ok(None));
        assert_eq!(p(&["apparmor=kiri-default"], true, &on), Ok(Some("kiri-default".into())), "a named profile wins over --privileged, as with Docker");
        assert_eq!(p(&["apparmor=admins-profile"], false, &on), Ok(Some("admins-profile".into())));
        assert!(p(&["apparmor=nosuch"], false, &on).unwrap_err().contains("\"nosuch\" is not loaded"));
        // No AppArmor, or no right to load policy: everything as before.
        for off in [Host::Absent, Host::NoPermission("in a container".into())] {
            assert_eq!(p(&[], false, &off), Ok(None));
            assert_eq!(p(&["apparmor=nosuch"], false, &off), Ok(None));
            assert_eq!(p(&["apparmor=unconfined"], true, &off), Ok(None));
        }
        // The profile failed to load: only what needs it is refused.
        let failed = Host::Failed("no apparmor_parser".into());
        let e = p(&[], false, &failed).unwrap_err();
        assert!(e.contains("no apparmor_parser") && e.contains("--security-opt apparmor=unconfined"), "{e}");
        assert!(p(&["apparmor=kiri-default"], false, &failed).is_err());
        assert_eq!(p(&["apparmor=unconfined"], false, &failed), Ok(None));
        assert_eq!(p(&[], true, &failed), Ok(None));
        assert_eq!(p(&["apparmor=admins-profile"], false, &failed), Ok(Some("admins-profile".into())));
        assert!(p(&["apparmor=bad name"], false, &on).is_err());
    }

    #[test]
    fn inspect_shows_what_docker_shows() {
        let i = |o: &[&str], privileged: bool, started: bool, h: &Host| inspect_profile(&opts(o), privileged, started, h);
        assert_eq!(i(&[], false, false, &Host::Loaded), "", "Docker fills it in at the start");
        assert_eq!(i(&[], false, true, &Host::Loaded), "kiri-default");
        assert_eq!(i(&[], true, true, &Host::Loaded), "unconfined");
        assert_eq!(i(&["apparmor=unconfined"], false, false, &Host::Loaded), "unconfined");
        assert_eq!(i(&["apparmor=mine"], false, false, &Host::Absent), "mine");
        assert_eq!(i(&[], false, true, &Host::Absent), "");
        assert_eq!(i(&[], false, true, &Host::NoPermission(String::new())), "");
    }

    #[test]
    fn the_kernels_list_is_read_by_name() {
        let list = "docker-default (enforce)\nkiri-default (enforce)\n/usr/bin/man (complain)\n";
        assert!(listed(list, "kiri-default"));
        assert!(listed(list, "/usr/bin/man"));
        assert!(!listed(list, "kiri"));
        assert!(!listed("", "kiri-default"));
        assert_eq!(guest_line("kiri-default"), "apparmor\tkiri-default");
    }

    /// A fake root with AppArmor's files as a Linux host shows them.
    fn fake_root(name: &str, enabled: &str, fs: bool, cap_eff: &str, uid_map: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("kiri-apparmor-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("sys/module/apparmor/parameters")).unwrap();
        std::fs::write(root.join("sys/module/apparmor/parameters/enabled"), enabled).unwrap();
        if fs {
            std::fs::create_dir_all(root.join("sys/kernel/security/apparmor")).unwrap();
            std::fs::write(root.join("sys/kernel/security/apparmor/.replace"), "").unwrap();
        }
        std::fs::create_dir_all(root.join("proc/self")).unwrap();
        std::fs::write(root.join("proc/self/status"), format!("Name:\tkiri\nCapEff:\t{cap_eff}\n")).unwrap();
        std::fs::write(root.join("proc/self/uid_map"), uid_map).unwrap();
        root
    }
    const ALL_CAPS: &str = "000001ffffffffff";
    const HOST_MAP: &str = "         0          0 4294967295\n";

    #[test]
    fn detection_on_a_fake_sys() {
        let r = fake_root("detect", "Y\n", true, ALL_CAPS, HOST_MAP);
        assert!(enabled(&r));
        assert_eq!(may_not_load(&r), None);
        assert!(!enabled(&fake_root("off", "N\n", true, ALL_CAPS, HOST_MAP)), "turned off on the kernel's command line");
        assert!(!enabled(&fake_root("nofs", "Y\n", false, ALL_CAPS, HOST_MAP)), "securityfs not there: a container's /sys");
        let none = std::env::temp_dir().join(format!("kiri-apparmor-none-{}", std::process::id()));
        assert!(!enabled(&none), "no module at all: macOS's and Windows' VM, WSL, SELinux hosts");
        // CapEff without bit 33.
        assert!(may_not_load(&fake_root("nocap", "Y\n", true, "00000000a80425fb", HOST_MAP)).unwrap().contains("CAP_MAC_ADMIN"));
        assert!(may_not_load(&fake_root("userns", "Y\n", true, ALL_CAPS, "0 100000 65536\n")).unwrap().contains("user namespace"));
    }

    #[test]
    fn what_start_finds() {
        let dir = std::env::temp_dir().join(format!("kiri-apparmor-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let none = || String::new();
        assert_eq!(start(&fake_root("s-off", "N\n", true, ALL_CAPS, HOST_MAP), &dir, PROFILE_TEXT, None, none), Host::Absent);
        assert!(matches!(start(&fake_root("s-nocap", "Y\n", true, "0", HOST_MAP), &dir, PROFILE_TEXT, None, none), Host::NoPermission(_)));
        let r = fake_root("s-on", "Y\n", true, ALL_CAPS, HOST_MAP);
        let Host::Failed(why) = start(&r, &dir, PROFILE_TEXT, None, none) else { panic!() };
        assert!(why.contains("apparmor_parser") && why.contains("apparmor package"), "{why}");
        // Loaded before with this very text, and still in the kernel: not loaded again.
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("apparmor-kiri-default"), stamp(PROFILE_TEXT)).unwrap();
        let listed = || "kiri-default (enforce)\n".to_owned();
        assert_eq!(start(&r, &dir, PROFILE_TEXT, None, listed), Host::Loaded);
        // Another text (a new Kiri), or the kernel lost it (a reboot): loaded again.
        assert!(matches!(start(&r, &dir, "profile kiri-default { }", None, listed), Host::Failed(_)));
        assert!(matches!(start(&r, &dir, PROFILE_TEXT, None, none), Host::Failed(_)));
        // A parser that refuses for want of permission, or for anything else.
        let tools = std::env::temp_dir().join(format!("kiri-apparmor-tools-{}", std::process::id()));
        std::fs::create_dir_all(&tools).unwrap();
        let tool = |name: &str, body: &str| {
            use std::os::unix::fs::PermissionsExt;
            let p = tools.join(name);
            std::fs::write(&p, format!("#!/bin/sh\ncat >/dev/null\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        };
        let ok = tool("ok", "exit 0");
        let _ = std::fs::remove_file(dir.join("apparmor-kiri-default"));
        assert_eq!(start(&r, &dir, PROFILE_TEXT, Some(ok), none), Host::Loaded);
        assert_eq!(std::fs::read_to_string(dir.join("apparmor-kiri-default")).unwrap(), stamp(PROFILE_TEXT), "the stamp is kept");
        let denied = tool("denied", "echo 'apparmor_parser: Unable to replace \"kiri-default\".  Permission denied; attempted to load a profile while confined?' >&2; exit 1");
        assert!(matches!(start(&r, &dir, "x", Some(denied), none), Host::NoPermission(_)));
        let broken = tool("broken", "echo 'AppArmor parser error at line 3: syntax error' >&2; exit 1");
        let Host::Failed(why) = start(&r, &dir, "x", Some(broken), none) else { panic!() };
        assert!(why.contains("syntax error"), "{why}");
        assert!(!dir.join("apparmor-kiri-default").exists(), "a failed load leaves no stamp");
    }

    #[test]
    fn the_stamp_follows_the_text() {
        assert_eq!(stamp(PROFILE_TEXT), stamp(PROFILE_TEXT));
        assert_ne!(stamp(PROFILE_TEXT), stamp(&format!("{PROFILE_TEXT}\n")));
        assert_eq!(stamp("").len(), 64);
    }

    #[test]
    fn the_profile_is_kiris_own_and_complete() {
        assert!(PROFILE_TEXT.contains("profile kiri-default flags=(attach_disconnected, mediate_deleted) {"));
        assert!(!PROFILE_TEXT.contains("#include"), "no includes: it must not depend on the host's policy files");
        for rule in ["deny mount,", "deny umount,", "deny pivot_root,", "deny /proc/{kcore,kmem,mem,sysrq-trigger} rwklx,", "deny /sys/kernel/security/** rwklx,", "deny /sys/fs/cgroup/**release_agent w,", "signal (receive) peer=unconfined,"] {
            assert!(PROFILE_TEXT.contains(rule), "{rule}");
        }
    }

    /// The profile compiles. Needs apparmor_parser; -Q builds the policy
    /// without loading it, so no privileges are needed either.
    #[test]
    fn the_profile_compiles() {
        let Some(parser) = find_parser(std::env::var_os("PATH").as_deref()) else {
            eprintln!("skipped: apparmor_parser is not installed here (it comes with the apparmor package)");
            return;
        };
        use std::io::Write;
        let mut child = std::process::Command::new(&parser)
            .args(["-Q", "-K"])
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(PROFILE_TEXT.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert!(out.stderr.is_empty(), "no warnings: {}", String::from_utf8_lossy(&out.stderr));
    }
}
