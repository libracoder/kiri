mod agent;
mod apparmor;
mod cgroup;
mod container;
mod devices;
mod disk;
mod copy;
mod dns;
mod fsnotify;
mod firewall;
mod fsview;
mod hostopts;
mod inroot;
mod layers;
mod localtime;
mod net;
mod netlink;
mod pid1;
mod relay;
mod rmtree;
mod roots;
mod seccomp;
mod swap;
mod sys;
mod tarnum;
mod transport;
mod trim;
mod usb;
mod usage;
mod volmount;

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

use kiri_proto::{HOST_PORT, Hello, Msg, PROTOCOL};

use sys::{boottime_ns, check, mount};

/// Where images and containers live: the data disk if attached, else tmpfs.
const DATA: &str = "/var/lib/kiri";

pub fn main() {
    install_panic_hook();
    let init_start_ns = boottime_ns();
    let result = run(init_start_ns);
    if let Err(e) = &result {
        // Nothing above us can handle this; say why on the console and stop.
        eprintln!("kiri-init: {e}");
    }
    if transport::is_host_process() {
        std::process::exit(i32::from(result.is_err()));
    }
    power_off();
}

/// Stack buffer size for panic reporting: avoids heap allocation in the panic
/// hook so panics during OOM or inside `eprintln!` still log cleanly.
const PANIC_BUF_LEN: usize = 512;

/// With `panic = "abort"`, a panic in PID 1 or the host agent would otherwise
/// abort without leaving a message on the console/stderr. Format into a fixed
/// stack buffer and write directly to `STDERR_FILENO` via `libc::write` (no
/// heap allocation and no `std::io::stderr()` RefCell/lock, so a panic during
/// OOM or inside `eprintln!` argument formatting cannot double-panic).
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let payload = info
            .payload()
            .downcast_ref::<&'static str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str));
        let location = info.location().map(|l| (l.file(), l.line()));
        let mut buf = [0u8; PANIC_BUF_LEN];
        let msg = format_panic_message(&mut buf, location, payload);
        write_stderr_all(msg);
    }));
}

fn format_panic_message<'a>(
    buf: &'a mut [u8],
    location: Option<(&str, u32)>,
    payload: Option<&str>,
) -> &'a [u8] {
    if buf.is_empty() {
        return &[];
    }
    let what = payload.unwrap_or("a panic payload that is not a string");
    let mut cur = io::Cursor::new(&mut *buf);
    let res = match location {
        Some((file, line)) => write!(cur, "kiri-init: panic at {file}:{line}: {what}\n"),
        None => write!(cur, "kiri-init: panic at <unknown location>: {what}\n"),
    };
    let len = cur.position() as usize;
    if res.is_err() {
        let mut end = len.min(buf.len() - 1);
        // Back up past any UTF-8 continuation bytes so truncation ends on a
        // character boundary before overwriting the final byte with '\n'.
        while end > 0 && (buf[end] & 0b1100_0000) == 0b1000_0000 {
            end -= 1;
        }
        buf[end] = b'\n';
        return &buf[..=end];
    }
    &buf[..len]
}

fn write_stderr_all(mut bytes: &[u8]) {
    while !bytes.is_empty() {
        // SAFETY: writing a valid stack slice directly to STDERR_FILENO.
        let n = unsafe { libc::write(libc::STDERR_FILENO, bytes.as_ptr().cast(), bytes.len()) };
        if n > 0 {
            bytes = &bytes[n as usize..];
        } else if n < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        } else {
            break;
        }
    }
}

fn run(init_start_ns: u64) -> io::Result<()> {
    // Before anything starts: every container and step inherits them.
    engine_rlimits();
    let paths = if transport::is_host_process() {
        // On a Linux host: the host's kernel filesystems, network and clock.
        host_dirs()?
    } else {
        leave_initramfs()?;
        mount_kernel_filesystems()?;
        sys::sethostname(b"kiri")?;
        // Containers may bind the VM's /etc/hostname, as on a Linux host.
        let _ = std::fs::write("/etc/hostname", "kiri\n");
        sys::loopback_up()?;
        data_dirs()?
    };

    let served = serve(&paths, init_start_ns);
    if transport::is_host_process() {
        // However the agent stops (Shutdown, its daemon gone, SIGTERM, an
        // error), nothing of the engine stays behind on a Linux host.
        container::sweep(&paths, &paths.cgroup);
        net::remove_host_network();
    }
    served
}

/// Sets the limits containers and build steps inherit (hostopts::agent_rlimits),
/// each on its own: one refused is said and the others are still set.
fn engine_rlimits() {
    for lim in hostopts::agent_rlimits() {
        if let Err(e) = hostopts::set_rlimits(&[lim]) {
            eprintln!("kiri-init: resource limits: {e}");
        }
    }
}

fn serve(paths: &container::Paths, init_start_ns: u64) -> io::Result<()> {
    let mut conn = dial_host()?;
    let (mem_total_kib, mem_available_kib) = meminfo();
    let mut out = Vec::with_capacity(256);
    Msg::Hello(Hello { protocol: PROTOCOL, init_start_ns, ready_ns: boottime_ns(), mem_total_kib, mem_available_kib })
        .encode(&mut out);
    conn.write_all(&out)?;
    agent::serve(conn, paths)
}

/// Re-roots PID 1 onto a tmpfs. The kernel refuses pivot_root while the
/// current root is the initramfs, and containers need pivot_root (chroot
/// alone can be escaped). This is what switch_root does for normal systems.
fn leave_initramfs() -> io::Result<()> {
    sys::mkdir(c"/root", 0o755);
    mount(c"root", c"/root", c"tmpfs", 0, Some(c"mode=0755"))?;
    // /lib/modules for containers that bind it (kind does); the kernel has
    // no modules, so it stays empty.
    for d in [c"/root/dev", c"/root/proc", c"/root/sys", c"/root/run", c"/root/tmp", c"/root/etc", c"/root/var", c"/root/lib", c"/root/lib/modules"] {
        sys::mkdir(d, 0o755);
    }
    // Free the initramfs copy of this binary; the running image stays mapped.
    let _ = std::fs::remove_file("/init");
    // SAFETY: plain path syscalls with valid NUL-terminated strings.
    unsafe {
        check(libc::chdir(c"/root".as_ptr()) as _, "chdir /root")?;
        check(libc::mount(c".".as_ptr(), c"/".as_ptr(), std::ptr::null(), libc::MS_MOVE, std::ptr::null()) as _, "move root")?;
        check(libc::chroot(c".".as_ptr()) as _, "chroot")?;
        check(libc::chdir(c"/".as_ptr()) as _, "chdir /")?;
    }
    // The console descriptors were opened from the old root's /dev/console
    // and keep working; nothing else refers to the initramfs any more.
    Ok(())
}

fn mount_kernel_filesystems() -> io::Result<()> {
    let nosuid_nodev_noexec = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    let m = |src, target: &std::ffi::CStr, fstype, flags, data| {
        sys::mkdir(target, 0o755);
        mount(src, target, fstype, flags, data)
    };
    m(c"proc", c"/proc", c"proc", nosuid_nodev_noexec, None)?;
    m(c"sysfs", c"/sys", c"sysfs", nosuid_nodev_noexec, None)?;
    m(c"devtmpfs", c"/dev", c"devtmpfs", libc::MS_NOSUID, Some(c"mode=0755"))?;
    m(c"devpts", c"/dev/pts", c"devpts", libc::MS_NOSUID | libc::MS_NOEXEC, Some(c"ptmxmode=0666,mode=0620"))?;
    m(c"shm", c"/dev/shm", c"tmpfs", libc::MS_NOSUID | libc::MS_NODEV, Some(c"mode=1777"))?;
    m(c"cgroup2", c"/sys/fs/cgroup", c"cgroup2", nosuid_nodev_noexec, Some(c"nsdelegate,memory_recursiveprot"))?;
    m(c"run", c"/run", c"tmpfs", libc::MS_NOSUID | libc::MS_NODEV, Some(c"mode=0755"))?;
    m(c"tmp", c"/tmp", c"tmpfs", libc::MS_NOSUID | libc::MS_NODEV, Some(c"mode=1777"))?;
    Ok(())
}

/// On a Linux host: images and containers under /var/lib/kiri, as in the
/// VM, and containers under the `kiri` cgroup.
///
/// /var/lib/kiri is 0710 (the kiri group may pass through it, no one may
/// list it) and what is under it 0700: layer contents and container
/// directories are root's; containers reach them through their mounts. An
/// existing tree is tightened too, in case an older build left it 0755.
/// The umask is set here, not inherited: the unit's UMask=0027 is right for
/// the daemon, but the files this process makes for containers (their
/// /etc/hosts and resolv.conf, bind-mount targets, new volumes) and the
/// umask the containers' own processes start with must stay conventional
/// (022), or nothing running as a non-root user in a container could read
/// its own resolv.conf.
fn host_dirs() -> io::Result<container::Paths> {
    // SAFETY: umask only changes this process's file-creation mask.
    unsafe { libc::umask(0o022) };
    let root = PathBuf::from(DATA);
    let data = std::env::var_os("KIRI_AGENT_DATA").map(PathBuf::from).filter(|p| p.is_absolute() && p != &root);
    let own_root = data.as_deref().unwrap_or(&root);
    // Claim the network namespace BEFORE touching `/var/lib/kiri` mounts so a
    // second engine never detaches a running engine's mount before failing (#443).
    // When this data directory's own `agent.lock` is held (for example by a
    // frozen container child that inherited `@kiri-engine-netns` before closing
    // descriptors when the old agent died), reclaim our own lock and sweep our
    // own recorded cgroup first, then claim the network namespace.
    if let Err(e) = net::claim_host_netns() {
        if e.kind() == io::ErrorKind::AddrInUse && is_file_locked(&own_root.join("agent.lock")) {
            take_over(own_root, || sweep_recorded_cgroup(own_root))?;
            net::claim_host_netns()?;
        } else {
            return Err(e);
        }
    }
    if let Some(data) = &data {
        mount_agent_data(data, &root)?;
    } else {
        detach_deleted_bind_mount(&root);
    }
    if let Some(kind) = sys::detect_readonly_fs(&root) {
        return Err(sys::readonly_storage_error(kind));
    }
    let mkdir = |p: &std::path::Path, mode: u32| -> io::Result<()> {
        std::fs::create_dir_all(p)?;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
    };
    mkdir(&root, 0o710)?;
    mkdir(&root.join("volumes"), 0o700)?;
    // What a dead agent left running can hold its lock (see `take_over`).
    if AGENT_LOCK.get().is_none() {
        take_over(&root, || sweep_recorded_cgroup(&root))?;
    }
    let (cgroup_root, cgroup) = host_cgroup()?;
    let paths = container::Paths {
        layers: root.join("layers"),
        containers: root.join("containers"),
        cgroup,
        cgroup_root,
    };
    mkdir(&paths.layers, 0o700)?;
    mkdir(&paths.containers, 0o700)?;
    // What an agent that died uncleanly left running: under the cgroup it
    // used (recorded below), and under this one.
    let record = root.join("agent.cgroup");
    if let Ok(old) = std::fs::read_to_string(&record) {
        let old = PathBuf::from(old.trim());
        if old != paths.cgroup && is_cgroup2_dir(&old) {
            container::sweep(&paths, &old);
        }
    }
    container::sweep(&paths, &paths.cgroup);
    std::fs::write(&record, paths.cgroup.as_os_str().as_encoded_bytes())?;
    std::env::set_current_dir(&paths.layers)?;
    Ok(paths)
}

/// Bind-mounts `src` (the chosen folder's `agent` directory, from
/// `KIRI_AGENT_DATA`) onto `/var/lib/kiri` so every agent path stays under
/// `/var/lib/kiri` while living on the chosen disk. No-op when `src` is
/// already mounted there; detaches any other mount on `target` first.
fn mount_agent_data(src: &std::path::Path, target: &std::path::Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    std::fs::create_dir_all(src)?;
    std::fs::create_dir_all(target)?;
    let (sm, tm) = (std::fs::metadata(src)?, std::fs::metadata(target)?);
    if (sm.dev(), sm.ino()) == (tm.dev(), tm.ino()) {
        return Ok(());
    }
    let c_target = CString::new(target.as_os_str().as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    if std::fs::read_to_string("/proc/self/mountinfo").is_ok_and(|m| is_mounted_at(&m, target)) {
        // SAFETY: valid NUL-terminated path; detaches a stale mount at `target`.
        unsafe { libc::umount2(c_target.as_ptr(), libc::MNT_DETACH) };
    }
    let c_src = CString::new(src.as_os_str().as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: valid NUL-terminated paths for a bind mount (fstype and data unused).
    check(unsafe { libc::mount(c_src.as_ptr(), c_target.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) } as _, "bind-mount KIRI_AGENT_DATA").map(drop)
}

/// If `target` (`/var/lib/kiri`) is currently covered by a stale bind mount
/// whose backing directory was deleted (`st_nlink == 0`), detaches it so
/// `create_dir_all` can use the underlying `/var/lib/kiri` directory instead
/// of failing with `ENOENT`. Real filesystem roots always have `st_nlink >= 2`.
fn detach_deleted_bind_mount(target: &std::path::Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let Ok(c_target) = CString::new(target.as_os_str().as_bytes()) else { return };
    for _ in 0..4 {
        let Ok(md) = std::fs::symlink_metadata(target) else { break };
        if md.file_type().is_symlink() || md.nlink() != 0 {
            break;
        }
        if !std::fs::read_to_string("/proc/self/mountinfo").is_ok_and(|m| is_mounted_at(&m, target)) {
            break;
        }
        // SAFETY: valid NUL-terminated non-symlink mountpoint; `UMOUNT_NOFOLLOW`
        // prevents following any racing symlink replacement.
        if unsafe { libc::umount2(c_target.as_ptr(), libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW) } != 0 {
            eprintln!("kiri-init: detach deleted bind mount on {}: {}", target.display(), io::Error::last_os_error());
            break;
        }
    }
}

/// Whether `/proc/self/mountinfo` lists a mount whose target is `target`.
fn is_mounted_at(mountinfo: &str, target: &std::path::Path) -> bool {
    let want = target.to_string_lossy();
    mountinfo.lines().any(|line| {
        let Some((before, _)) = line.split_once(" - ") else { return false };
        before.split_whitespace().nth(4).is_some_and(|mp| unescape_mount_path(mp) == want)
    })
}

/// The lock on a Linux host's data directory, held while the agent runs.
static AGENT_LOCK: std::sync::OnceLock<File> = std::sync::OnceLock::new();

/// Whether `path` exists and another open file description currently holds an
/// exclusive `flock` on it, without creating `path` or keeping a lock.
fn is_file_locked(path: &std::path::Path) -> bool {
    use std::os::fd::AsRawFd;
    let Ok(file) = File::open(path) else {
        return false;
    };
    // SAFETY: non-blocking `flock` probe on a descriptor we own.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        false
    } else {
        io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK)
    }
}

/// Sweeps containers recorded in `root/agent.cgroup` by a previous agent of
/// this data directory.
fn sweep_recorded_cgroup(root: &std::path::Path) {
    let Ok(old) = std::fs::read_to_string(root.join("agent.cgroup")) else { return };
    let old = PathBuf::from(old.trim());
    if is_cgroup2_dir(&old) {
        let paths = container::Paths {
            layers: root.join("layers"),
            containers: root.join("containers"),
            cgroup: old.clone(),
            cgroup_root: old.clone(),
        };
        container::sweep(&paths, &old);
    }
}

/// One agent per data directory on a Linux host: takes `agent.lock` (an
/// flock, released when the process ends however it ends). An agent that
/// still holds it is stopped if its daemon is gone (an orphan: SIGTERM, so
/// it cleans up, then SIGKILL), and waited for a few seconds otherwise (a
/// daemon still shutting down); if it stays, starting fails and says why
/// rather than failing later on its sockets and ports.
///
/// The lock can outlive the agent that took it: a child it cloned holds a
/// copy of the descriptor until it closes it, and one that hung before
/// then (a container's first process stuck before its root was in place)
/// kept it for good, so every later agent gave up here. Once the holder is
/// gone, `leftovers` stops what this data directory's containers left
/// running (the old agent's containers, which the start-up sweep stops
/// anyway), once, and the lock is tried again.
fn take_over(root: &std::path::Path, leftovers: impl Fn()) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let path = root.join("agent.lock");
    let mut file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(0o600).open(&path)?;
    let locked = |f: &File| {
        // SAFETY: flock on a descriptor we own.
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
    };
    let start = std::time::Instant::now();
    let mut signalled = None;
    let mut swept = false;
    while !locked(&file) {
        let mut text = String::new();
        let _ = (&file).read_to_string(&mut text);
        let _ = std::io::Seek::rewind(&mut file);
        let old: libc::pid_t = text.trim().parse().unwrap_or(0);
        let daemon = parent_of(old);
        let orphan = old > 0 && !daemon.is_some_and(is_daemon);
        let waited = start.elapsed();
        // Gone: whatever holds the lock now is something it left running.
        if orphan && !swept && daemon.is_none() {
            eprintln!("kiri-init: agent {old} is gone but its lock is held: stopping the containers it left");
            leftovers();
            swept = true;
            continue;
        }
        if orphan && signalled.is_none() {
            eprintln!("kiri-init: stopping agent {old}, left running by a daemon that is gone");
            // SAFETY: signalling the process that holds our data directory's lock.
            unsafe { libc::kill(old, libc::SIGTERM) };
            signalled = Some(waited);
        } else if orphan && signalled.is_some_and(|t| waited - t > std::time::Duration::from_secs(5)) {
            // SAFETY: as above; it did not stop on SIGTERM.
            unsafe { libc::kill(old, libc::SIGKILL) };
        }
        if waited > std::time::Duration::from_secs(8) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("another Kiri engine is running on this machine (agent {old}, daemon {}): stop it first", daemon.unwrap_or(0)),
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    file.set_len(0)?;
    use std::os::unix::fs::FileExt;
    file.write_all_at(format!("{}\n", std::process::id()).as_bytes(), 0)?;
    let _ = AGENT_LOCK.set(file);
    Ok(())
}

/// A live process's parent, from /proc/<pid>/stat.
fn parent_of(pid: libc::pid_t) -> Option<libc::pid_t> {
    if pid <= 0 {
        return None;
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // pid (comm) state ppid …; comm may hold spaces and parentheses.
    stat.rsplit_once(')')?.1.split_whitespace().nth(1)?.parse().ok()
}

/// Whether a process is a `kiri daemon` (by its arguments: the binary may
/// have any name). PID 1 or a subreaper adopting an orphan is not.
fn is_daemon(pid: libc::pid_t) -> bool {
    pid > 1 && std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|c| c.split(|b| *b == 0).any(|a| a == b"daemon"))
}

fn is_cgroup2_dir(path: &std::path::Path) -> bool {
    path.is_absolute() && path.is_dir() && sys::is_cgroup2(path)
}

/// The cgroup v2 path relative to the unified hierarchy root from `/proc/self/cgroup`.
fn cgroup2_rel(proc_cgroup: &str) -> String {
    proc_cgroup.lines().find_map(|l| l.strip_prefix("0::")).unwrap_or("/").trim().trim_start_matches('/').to_owned()
}

/// Unescapes `/proc/self/mountinfo` octal escapes (`\040`, `\011`, `\012`, `\134`).
fn unescape_mount_path(raw: &str) -> String {
    sys::unescape_mount_path(raw)
}

/// Writable `cgroup2` mounts visible in `/proc/self/mountinfo`, ordered by
/// preference: `/sys/fs/cgroup`, `/sys/fs/cgroup/unified` (stock WSL 2 and
/// hybrid systemd), other mounts under `/sys/fs/cgroup/`, then any other
/// top-level (`root == "/"`) mount. Overmounted entries (for example `tmpfs`
/// stacked over an earlier `cgroup2` mount) are excluded because only the last
/// mount on each path is active.
fn cgroup2_mounts(mountinfo: &str) -> Vec<PathBuf> {
    struct Entry {
        fstype: String,
        root: String,
        rw: bool,
    }
    let has_ro = |opts: &str| opts.split(',').any(|o| o == "ro");
    let mut active: std::collections::BTreeMap<String, Entry> = std::collections::BTreeMap::new();
    for line in mountinfo.lines() {
        let Some((before, after)) = line.split_once(" - ") else { continue };
        let mut b = before.split_whitespace();
        let (Some(_id), Some(_parent), Some(_dev), Some(root), Some(mp), Some(mopts)) =
            (b.next(), b.next(), b.next(), b.next(), b.next(), b.next())
        else {
            continue;
        };
        let mut a = after.split_whitespace();
        let (Some(fstype), Some(_src), Some(sopts)) = (a.next(), a.next(), a.next()) else { continue };
        let mp = unescape_mount_path(mp);
        active.insert(
            mp,
            Entry { fstype: fstype.to_owned(), root: unescape_mount_path(root), rw: !has_ro(mopts) && !has_ro(sopts) },
        );
    }
    let mut found: Vec<(u8, PathBuf)> = active
        .into_iter()
        .filter(|(mp, e)| e.fstype == "cgroup2" && e.rw && mp != DATA && !mp.starts_with("/var/lib/kiri/"))
        .map(|(mp, e)| {
            let tier = if mp == "/sys/fs/cgroup" {
                0
            } else if mp == "/sys/fs/cgroup/unified" {
                1
            } else if mp.starts_with("/sys/fs/cgroup/") && e.root == "/" {
                2
            } else if e.root == "/" {
                3
            } else {
                4
            };
            (tier, PathBuf::from(mp))
        })
        .collect();
    found.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    found.into_iter().map(|(_, p)| p).collect()
}

/// Finds an already-mounted writable `cgroup2` hierarchy (unified
/// `/sys/fs/cgroup`, stock WSL 2's `/sys/fs/cgroup/unified`, or another
/// mountpoint), or mounts one when none is present yet.
fn cgroup2_root() -> io::Result<PathBuf> {
    let is_usable = |p: &std::path::Path| sys::is_cgroup2(p) && p.join("cgroup.controllers").exists();
    let default = PathBuf::from("/sys/fs/cgroup");
    if is_usable(&default) {
        return Ok(default);
    }
    if let Ok(mountinfo) = std::fs::read_to_string("/proc/self/mountinfo") {
        for cand in cgroup2_mounts(&mountinfo) {
            if is_usable(&cand) {
                return Ok(cand);
            }
        }
    }
    let unified = PathBuf::from("/sys/fs/cgroup/unified");
    if is_usable(&unified) {
        return Ok(unified);
    }
    mount_cgroup2(&default)
}

/// The cgroup containers go under on a Linux host, chosen as dockerd and
/// containerd choose theirs on cgroup v2:
///
/// - In a cgroup delegated to Kiri (a systemd service with `Delegate=yes`,
///   or one made for it that holds only the daemon and this agent): those
///   processes, and no others, move to its `kiri-host` leaf, so it can hand
///   controllers down; containers go in its `kiri`.
/// - At the root of a cgroup namespace that holds processes (Kiri inside a
///   container): they move to a `kiri-host` leaf, as Docker-in-Docker's
///   entrypoint does; containers go in `kiri` beside it.
/// - Anywhere else (a login session, WSL's `init.scope`: cgroups shared
///   with processes that are not Kiri's): nothing moves, and containers go
///   in `kiri` at the top of the hierarchy, as dockerd's cgroupfs driver
///   puts them in `docker`. Moving every process of a shared cgroup took
///   WSL's own along, one level deeper on every start.
///
/// Started again from inside a `kiri-host` leaf (the daemon stays there
/// when its agent restarts), it is not nested again.
///
/// Returns `(cgroup_root, containers_cgroup)`. On a hybrid cgroup tree
/// (stock WSL 2, where `/sys/fs/cgroup` is a tmpfs holding v1 mounts and
/// `cgroup2` is at `/sys/fs/cgroup/unified`), `cgroup_root` is that
/// `cgroup2` mountpoint rather than `/sys/fs/cgroup`.
fn host_cgroup() -> io::Result<(PathBuf, PathBuf)> {
    let own = std::fs::read_to_string("/proc/self/cgroup")?;
    let rel = cgroup2_rel(&own);
    let root = cgroup2_root()?;
    if root != std::path::Path::new("/sys/fs/cgroup") {
        eprintln!("kiri-init: using cgroup v2 at {}", root.display());
    }
    let own = root.join(&rel);
    let mut base = own.clone();
    while base != root && base.file_name().is_some_and(|n| n == "kiri-host") {
        base.pop();
    }
    let procs = |dir: &std::path::Path| -> Vec<String> {
        std::fs::read_to_string(dir.join("cgroup.procs")).unwrap_or_default().lines().map(str::to_owned).collect()
    };
    // Moves processes to the leaf beside the containers' cgroup.
    let to_leaf = |pids: Vec<String>| {
        let leaf = base.join("kiri-host");
        let _ = std::fs::create_dir(&leaf);
        for pid in pids {
            let _ = std::fs::write(leaf.join("cgroup.procs"), pid);
        }
    };
    let base = if base == root {
        // Only the hierarchy's true root (which has no cgroup.type) may hold
        // processes and hand out controllers; a namespace's root is not it.
        if root.join("cgroup.type").exists() {
            to_leaf(procs(&root));
        }
        root.clone()
    } else if own.is_dir() && delegated(&own, &procs(&own)) {
        if own != base.join("kiri-host") {
            to_leaf(procs(&own));
        }
        base
    } else {
        root.clone()
    };
    let kiri = base.join("kiri");
    containers_cgroup(&kiri);
    Ok((root, kiri))
}

/// Makes the cgroup containers go under, with the controllers handed down
/// to it and from it. Also when a container starts and it is gone: systemd
/// removes a stopped service's cgroups when it sees them empty, and on a
/// restart that can land after the new agent made this one, still empty
/// (Fedora 44's systemd 259 did); `kiri-host`, which holds the daemon,
/// stays, and every container start then failed with ENOENT.
pub fn containers_cgroup(kiri: &std::path::Path) {
    let _ = std::fs::create_dir(kiri);
    let Some(base) = kiri.parent() else { return };
    for c in ["+cpu", "+memory", "+pids", "+cpuset", "+io"] {
        let _ = std::fs::write(base.join("cgroup.subtree_control"), c);
        let _ = std::fs::write(kiri.join("cgroup.subtree_control"), c);
    }
}

/// Mounts `cgroup2` when none is mounted yet:
/// - An empty `/sys/fs/cgroup` (e.g. `ip netns exec` remounted a fresh `/sys`)
///   gets `cgroup2` mounted directly on `/sys/fs/cgroup`.
/// - A non-empty `/sys/fs/cgroup` (e.g. a cgroup v1 tree without
///   `/sys/fs/cgroup/unified` mounted yet) leaves the existing v1 mounts
///   untouched and mounts `cgroup2` at `/sys/fs/cgroup/unified`, falling back
///   to `/run/kiri/cgroup` if `/sys/fs/cgroup` is not writable.
fn mount_cgroup2(root: &std::path::Path) -> io::Result<PathBuf> {
    let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    let is_empty = |p: &std::path::Path| std::fs::read_dir(p).map(|mut d| d.next().is_none());
    let try_mount = |target: &std::path::Path| -> io::Result<()> {
        let t = sys::cstr(target)?;
        mount(c"cgroup2", &t, c"cgroup2", flags, None)
    };
    match is_empty(root) {
        Ok(true) => {
            try_mount(root).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("/sys/fs/cgroup has no cgroup tree (ip netns exec remounts /sys) and mounting cgroup2 there failed: {e}"),
                )
            })?;
            return Ok(root.to_path_buf());
        }
        Ok(false) => {}
        Err(e) => {
            return Err(io::Error::new(e.kind(), format!("/sys/fs/cgroup: {e}; Kiri needs cgroup v2 mounted there")));
        }
    }
    let mut last_err = None;
    for candidate in [root.join("unified"), PathBuf::from("/run/kiri/cgroup")] {
        let _ = std::fs::create_dir_all(&candidate);
        if is_empty(&candidate).unwrap_or(false) {
            match try_mount(&candidate) {
                Ok(()) => return Ok(candidate),
                Err(e) => last_err = Some((candidate, e)),
            }
        }
    }
    match last_err {
        Some((p, e)) => Err(io::Error::new(
            e.kind(),
            format!("Kiri needs cgroup v2; no cgroup2 mount was found and mounting cgroup2 at {} failed: {e}", p.display()),
        )),
        None => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Kiri needs cgroup v2; no cgroup2 mount was found and neither /sys/fs/cgroup/unified nor /run/kiri/cgroup was available",
        )),
    }
}

/// Whether the agent's cgroup is Kiri's own: a systemd service's (with
/// `Delegate=yes`, the whole cgroup is the service's), or one holding no
/// process but this agent and its parent, the daemon.
fn delegated(own: &std::path::Path, pids: &[String]) -> bool {
    if own.extension().is_some_and(|e| e == "service") {
        return true;
    }
    let (me, parent) = (std::process::id().to_string(), std::os::unix::process::parent_id().to_string());
    !pids.is_empty() && pids.iter().all(|p| *p == me || *p == parent)
}

/// Mounts the data disk (or a tmpfs without one), creates the layer and
/// container directories and the cgroup that all containers live under.
fn data_dirs() -> io::Result<container::Paths> {
    sys::mkdir(c"/var/lib", 0o755);
    sys::mkdir(c"/var/lib/kiri", 0o755);
    // noinit_itable: the disk is made with lazy inode tables; zeroing them in
    // the background would only write gigabytes of zeros to the host.
    let disk = mount(c"/dev/vda", c"/var/lib/kiri", c"ext4", libc::MS_NOATIME, Some(c"noinit_itable"));
    if let Err(ref e) = disk {
        eprintln!("kiri-init: no data disk ({e}); keeping images in memory");
        mount(c"kiri", c"/var/lib/kiri", c"tmpfs", libc::MS_NOATIME, Some(c"mode=0755"))?;
    } else {
        if let Err(e) = disk::grow() {
            eprintln!("kiri-init: growing data disk: {e}");
        }
        if let Some(kind) = sys::detect_readonly_fs(std::path::Path::new(DATA)) {
            return Err(sys::readonly_storage_error(kind));
        }
    }
    // The Mac's filesystem over virtiofs, for bind mounts.
    sys::mkdir(c"/mnt", 0o755);
    sys::mkdir(c"/mnt/mac", 0o755);
    if let Err(e) = mount(c"kiri-mac", c"/mnt/mac", c"virtiofs", libc::MS_NOATIME, None) {
        eprintln!("kiri-init: no Mac file share ({e}); bind mounts of Mac paths will fail");
    } else if let Err(e) = mac_readahead() {
        eprintln!("kiri-init: keeping the Mac file share's default read-ahead ({e})");
    }
    // An x86-64 guest (Intel Macs, WSL2) runs amd64 binaries natively.
    #[cfg(target_arch = "aarch64")]
    rosetta();
    std::fs::create_dir_all(format!("{DATA}/volumes"))?;
    let root = PathBuf::from(DATA);
    let paths = container::Paths {
        layers: root.join("layers"),
        containers: root.join("containers"),
        cgroup: PathBuf::from("/sys/fs/cgroup/kiri"),
        cgroup_root: PathBuf::from("/sys/fs/cgroup"),
    };
    std::fs::create_dir_all(&paths.layers)?;
    std::fs::create_dir_all(&paths.containers)?;
    // Stopped containers keep their writable layers across boots; the host
    // sends `Retain` with the ones it still knows about, and the rest go.
    let _ = std::fs::create_dir(&paths.cgroup);
    // cpu, memory and pids for limits; cpuset and io so containers that
    // run their own containers (Kubernetes, Docker in Docker) find them.
    sys::write_file("/sys/fs/cgroup/cgroup.subtree_control", "+cpu +memory +pids")?;
    sys::write_file("/sys/fs/cgroup/kiri/cgroup.subtree_control", "+cpu +memory +pids")?;
    for c in ["+cpuset", "+io"] {
        let _ = sys::write_file("/sys/fs/cgroup/cgroup.subtree_control", c);
        let _ = sys::write_file("/sys/fs/cgroup/kiri/cgroup.subtree_control", c);
    }
    // Overlay lower dirs are given relative to the layer store.
    std::env::set_current_dir(&paths.layers)?;
    if disk.is_ok() {
        // On the data disk only: swap in the tmpfs fallback would be memory.
        swap::start();
        trim::start(DATA);
    }
    Ok(paths)
}

/// Batch sequential reads across virtiofs without changing cache coherence.
/// Only the Mac share's backing device is changed; Rosetta and the data disk
/// keep their own settings. Older kernels may omit this optional tuning.
fn mac_readahead() -> io::Result<()> {
    let device = std::fs::metadata("/mnt/mac")?.dev();
    let path = format!("/sys/class/bdi/{}:{}/read_ahead_kb", libc::major(device), libc::minor(device));
    sys::write_file(&path, "1024\n")
}

/// x86-64 Linux binaries through Rosetta, when the Mac shares it: amd64
/// images then run as they do on Docker Desktop and OrbStack. The `F` flag
/// opens the interpreter now, so it works inside every container's mounts.
#[cfg(target_arch = "aarch64")]
fn rosetta() {
    sys::mkdir(c"/run/rosetta", 0o755);
    if mount(c"rosetta", c"/run/rosetta", c"virtiofs", libc::MS_RDONLY, None).is_err() {
        return;
    }
    if let Err(e) = mount(c"binfmt_misc", c"/proc/sys/fs/binfmt_misc", c"binfmt_misc", 0, None) {
        eprintln!("kiri-init: no binfmt_misc ({e}); amd64 images will not run");
        return;
    }
    const X86_64: &str = concat!(
        ":rosetta:M::",
        r"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00",
        ":",
        r"\xff\xff\xff\xff\xff\xfe\xfe\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff",
        ":/run/rosetta/rosetta:CF",
    );
    if let Err(e) = sys::write_file("/proc/sys/fs/binfmt_misc/register", X86_64) {
        eprintln!("kiri-init: registering Rosetta: {e}");
    }
}

fn dial_host() -> io::Result<File> {
    // The host registers its listener before the VM starts, so the first
    // attempt normally succeeds. Retry briefly in case the vsock device is
    // still being probed.
    let mut last = io::Error::from(io::ErrorKind::NotConnected);
    for attempt in 0..200 {
        match transport::dial(HOST_PORT) {
            Ok(sock) => return Ok(File::from(sock)),
            Err(e) => last = e,
        }
        if attempt > 0 && attempt % 50 == 0 {
            eprintln!("kiri-init: still dialing host: {last}");
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    Err(io::Error::new(last.kind(), format!("dial host: {last}")))
}

/// MemTotal, MemAvailable and (when the kernel reports them) Balloon and
/// Committed_AS in KiB.
fn meminfo_full() -> (u64, u64, Option<u64>, Option<u64>) {
    let Ok(s) = std::fs::read_to_string("/proc/meminfo") else { return (0, 0, None, None) };
    let (total, avail, balloon, committed) = parse_meminfo(&s);
    // Older kernels without `Balloon:` in /proc/meminfo still expose
    // balloon_inflate / balloon_deflate in /proc/vmstat inside the VM.
    let balloon = balloon.or_else(|| (std::process::id() == 1).then(vmstat_balloon_kib).flatten());
    (total, avail, balloon, committed)
}

fn parse_meminfo(s: &str) -> (u64, u64, Option<u64>, Option<u64>) {
    let field = |name: &str| {
        s.lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
    };
    (
        field("MemTotal:").unwrap_or(0),
        field("MemAvailable:").unwrap_or(0),
        field("Balloon:"),
        field("Committed_AS:"),
    )
}

fn vmstat_balloon_kib() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/vmstat").ok()?;
    // SAFETY: sysconf takes no pointers.
    let page_kib = (unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64) >> 10;
    parse_vmstat_balloon_kib(&s, page_kib)
}

fn parse_vmstat_balloon_kib(s: &str, page_kib: u64) -> Option<u64> {
    let mut inflate = None;
    let mut deflate = None;
    for line in s.lines() {
        if let Some(v) = line.strip_prefix("balloon_inflate ") {
            inflate = v.trim().parse::<u64>().ok();
        } else if let Some(v) = line.strip_prefix("balloon_deflate ") {
            deflate = v.trim().parse::<u64>().ok();
        }
    }
    Some(inflate?.saturating_sub(deflate?).saturating_mul(page_kib))
}

/// MemTotal and MemAvailable in KiB.
fn meminfo() -> (u64, u64) {
    let (total, avail, _, _) = meminfo_full();
    (total, avail)
}

fn power_off() -> ! {
    // SAFETY: sync and reboot take no pointers.
    unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
    }
    // reboot only returns on failure; PID 1 must never exit.
    loop {
        // SAFETY: pause takes no arguments.
        unsafe { libc::pause() };
    }
}

#[cfg(test)]
mod take_over_tests {
    /// The agent that took the lock is gone but something it left (here a
    /// child that inherited the locked descriptor and only waits) still
    /// holds it: the leftovers are stopped once and the lock is taken,
    /// where every new agent used to give up after 8 s.
    #[test]
    fn a_lock_held_by_what_a_dead_agent_left_is_taken_over() {
        use std::os::fd::AsRawFd;
        let root = std::env::temp_dir().join(format!("kiri-take-over-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        // The old agent: a process that has exited.
        let mut dead = std::process::Command::new("true").spawn().unwrap();
        let old = dead.id();
        dead.wait().unwrap();
        let lock = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(root.join("agent.lock")).unwrap();
        std::io::Write::write_all(&mut &lock, format!("{old}\n").as_bytes()).unwrap();
        // SAFETY: flock on a descriptor we own.
        assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
        // SAFETY: the child only waits to be killed.
        let left = unsafe { libc::fork() };
        if left == 0 {
            loop {
                // SAFETY: plain pause in the child.
                unsafe { libc::pause() };
            }
        }
        drop(lock);
        let swept = std::cell::Cell::new(0);
        let t = std::time::Instant::now();
        super::take_over(&root, || {
            swept.set(swept.get() + 1);
            // SAFETY: killing and reaping the child forked above.
            unsafe {
                libc::kill(left, libc::SIGKILL);
                libc::waitpid(left, std::ptr::null_mut(), 0);
            }
        })
        .unwrap();
        assert!(t.elapsed() < std::time::Duration::from_secs(2), "took {:?}", t.elapsed());
        assert_eq!(swept.get(), 1);
        let text = std::fs::read_to_string(root.join("agent.lock")).unwrap();
        assert_eq!(text.trim(), std::process::id().to_string());
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod meminfo_tests {
    #[test]
    fn meminfo_reads_balloon_and_committed_as_when_present() {
        let with = "MemTotal:       24656160 kB\nMemFree:        24297640 kB\nMemAvailable:   24122580 kB\nCommitLimit:    12328080 kB\nCommitted_AS:    2097152 kB\nBalloon:          262144 kB\n";
        assert_eq!(super::parse_meminfo(with), (24_656_160, 24_122_580, Some(262_144), Some(2_097_152)));
        let zero = "MemTotal:       8211244 kB\nMemAvailable:   8000000 kB\nCommitted_AS:         0 kB\nBalloon:              0 kB\n";
        assert_eq!(super::parse_meminfo(zero), (8_211_244, 8_000_000, Some(0), Some(0)));
        let only_committed = "MemTotal:       8211244 kB\nMemAvailable:   8000000 kB\nCommitted_AS:   2148352 kB\n";
        assert_eq!(super::parse_meminfo(only_committed), (8_211_244, 8_000_000, None, Some(2_148_352)));
        let without = "MemTotal:       8211244 kB\nMemAvailable:   8000000 kB\n";
        assert_eq!(super::parse_meminfo(without), (8_211_244, 8_000_000, None, None));
    }

    #[test]
    fn vmstat_balloon_fallback_computes_net_kib() {
        let vmstat = "nr_free_pages 100\nballoon_inflate 262144\nballoon_deflate 65536\n";
        assert_eq!(super::parse_vmstat_balloon_kib(vmstat, 4), Some(196_608 * 4));
        assert_eq!(super::parse_vmstat_balloon_kib("balloon_inflate 10\nballoon_deflate 20\n", 4), Some(0));
        assert_eq!(super::parse_vmstat_balloon_kib("nr_free_pages 100\n", 4), None);
    }
}

#[cfg(test)]
mod cgroup_discovery_tests {
    use std::path::{Path, PathBuf};

    #[test]
    fn stock_wsl2_hybrid_mountinfo_picks_unified() {
        let mountinfo = "\
28 24 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,mode=755
29 28 0:27 / /sys/fs/cgroup/unified rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,nsdelegate
30 28 0:28 / /sys/fs/cgroup/cpuset rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,cpuset
31 28 0:29 / /sys/fs/cgroup/cpu rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,cpu
32 28 0:30 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,memory
33 28 0:31 / /sys/fs/cgroup/pids rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,pids
";
        assert_eq!(super::cgroup2_mounts(mountinfo), vec![PathBuf::from("/sys/fs/cgroup/unified")]);
    }

    #[test]
    fn overmounted_cgroup2_at_root_is_skipped_for_unified() {
        // Simulates tmpfs stacked over an earlier /sys/fs/cgroup cgroup2 mount
        // (as happens in a mount namespace or hybrid remount): only the active
        // topmost mount per path counts.
        let mountinfo = "\
37 27 0:32 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:10 - cgroup2 cgroup2 rw,nsdelegate
200 37 0:60 / /sys/fs/cgroup rw,relatime - tmpfs tmpfs rw,mode=755
201 200 0:32 / /sys/fs/cgroup/unified rw,relatime - cgroup2 cgroup2 rw,nsdelegate
";
        assert_eq!(super::cgroup2_mounts(mountinfo), vec![PathBuf::from("/sys/fs/cgroup/unified")]);
    }

    #[test]
    fn pure_v2_mount_is_preferred_over_secondary_mounts() {
        let mountinfo = "\
37 27 0:32 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,nsdelegate
90 27 0:32 / /sys/fs/cgroup/unified rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,nsdelegate
91 27 0:32 / /run/kiri/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw
";
        assert_eq!(
            super::cgroup2_mounts(mountinfo),
            vec![
                PathBuf::from("/sys/fs/cgroup"),
                PathBuf::from("/sys/fs/cgroup/unified"),
                PathBuf::from("/run/kiri/cgroup"),
            ]
        );
    }

    #[test]
    fn readonly_and_container_cgroup2_mounts_are_ignored() {
        let mountinfo = "\
40 28 0:27 / /sys/fs/cgroup/unified ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw
41 28 0:27 / /sys/fs/cgroup/other rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 ro
42 28 0:27 / /var/lib/kiri/containers/abc/rootfs/sys/fs/cgroup rw - cgroup2 cgroup2 rw
43 28 0:27 / /run/kiri/cgroup rw,nosuid,nodev,noexec - cgroup2 cgroup2 rw
";
        assert_eq!(super::cgroup2_mounts(mountinfo), vec![PathBuf::from("/run/kiri/cgroup")]);
    }

    #[test]
    fn mountinfo_octal_escapes_are_decoded() {
        assert_eq!(super::unescape_mount_path(r"/mnt/my\040dir\134sub"), r"/mnt/my dir\sub");
    }

    #[test]
    fn cgroup2_rel_parses_hybrid_proc_cgroup() {
        let wsl_root = "15:name=systemd:/\n2:memory:/\n1:cpuset:/\n0::/\n";
        assert_eq!(super::cgroup2_rel(wsl_root), "");
        let systemd_hybrid = "12:memory:/system.slice/kiri.service\n0::/system.slice/kiri.service\n";
        assert_eq!(super::cgroup2_rel(systemd_hybrid), "system.slice/kiri.service");
    }

    #[test]
    fn delegated_requires_non_empty_pids_for_non_service_cgroup() {
        assert!(!super::delegated(Path::new("/sys/fs/cgroup/unified/init.scope"), &[]));
        assert!(super::delegated(Path::new("/sys/fs/cgroup/unified/system.slice/kiri.service"), &[]));
        assert!(super::delegated(Path::new("/sys/fs/cgroup/unified/custom"), &[std::process::id().to_string()]));
    }

    #[test]
    fn is_mounted_at_finds_exact_mountpoint() {
        let mountinfo = "\
28 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw
55 28 8:2 /kiri/agent /var/lib/kiri rw,relatime - ext4 /dev/sdb1 rw
56 28 8:2 /sub /var/lib/kiri/volumes/x rw,relatime - ext4 /dev/sdb1 rw
";
        assert!(super::is_mounted_at(mountinfo, Path::new("/var/lib/kiri")));
        assert!(!super::is_mounted_at(mountinfo, Path::new("/var/lib")));
        assert!(!super::is_mounted_at(mountinfo, Path::new("/media/ssd")));
    }

    #[test]
    fn is_file_locked_detects_held_flock_without_creating_missing_file() {
        use std::os::fd::AsRawFd;
        let dir = std::env::temp_dir().join(format!("kiri-lock-probe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let lock_path = dir.join("agent.lock");
        assert!(!super::is_file_locked(&lock_path));
        assert!(!lock_path.exists(), "missing lock file must not be created");

        let holder = std::fs::File::create(&lock_path).unwrap();
        assert!(!super::is_file_locked(&lock_path));
        assert_eq!(unsafe { libc::flock(holder.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
        assert!(super::is_file_locked(&lock_path));
        drop(holder);
        assert!(!super::is_file_locked(&lock_path));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod panic_hook_tests {
    #[test]
    fn formats_panic_location_and_payload_into_stack_buffer() {
        let mut buf = [0u8; super::PANIC_BUF_LEN];
        assert_eq!(
            super::format_panic_message(&mut buf, Some(("crates/kiri-init/src/linux/agent.rs", 42)), Some("boom")),
            b"kiri-init: panic at crates/kiri-init/src/linux/agent.rs:42: boom\n"
        );
        assert_eq!(
            super::format_panic_message(&mut buf, None, Some("oops")),
            b"kiri-init: panic at <unknown location>: oops\n"
        );
        assert_eq!(
            super::format_panic_message(&mut buf, Some(("mod.rs", 7)), None),
            b"kiri-init: panic at mod.rs:7: a panic payload that is not a string\n"
        );

        // Oversized messages truncate cleanly inside the fixed stack buffer
        // with a trailing newline and valid UTF-8.
        let long = "x".repeat(super::PANIC_BUF_LEN * 2);
        let out = super::format_panic_message(&mut buf, Some(("a.rs", 1)), Some(&long));
        assert_eq!(out.len(), super::PANIC_BUF_LEN);
        assert!(out.ends_with(b"\n"));
        assert!(std::str::from_utf8(out).is_ok());

        let mut small = [0u8; 34];
        // "kiri-init: panic at a.rs:1: " is 28 bytes; "éééé" has 2-byte UTF-8 chars.
        let out = super::format_panic_message(&mut small, Some(("a.rs", 1)), Some("éééé"));
        assert!(out.ends_with(b"\n"));
        let text = std::str::from_utf8(out).expect("truncated output must stay valid UTF-8");
        assert!(text.starts_with("kiri-init: panic at a.rs:1: "));

        let mut empty = [];
        assert_eq!(super::format_panic_message(&mut empty, Some(("a.rs", 1)), Some("x")), b"");
    }
}
