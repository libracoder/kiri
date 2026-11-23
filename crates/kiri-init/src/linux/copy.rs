//! `docker cp`: files into and out of containers, one vsock connection per
//! copy. Each copy runs in a forked child, so a large archive never stalls
//! the event loop. The child chroots into the container (its live root, or a
//! private mount of its layers when it is not running), so links resolve
//! inside the container and nothing outside it is reachable.
//!
//! A stopped container's root is mounted by the agent, not the child: the
//! child asks for it over a socket pair of its own, so a copy and a start at
//! the same moment share one mount (see `roots`, #227).

use std::cell::RefCell;
use std::error::Error as StdError;
use std::fs;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use kiri_proto::{COPY_PORT, CopySpec, FsEntry, Msg, StrList, copy_flags, copy_op};

use super::container::{self, Paths};
use super::inroot;
use super::sys;

/// A copy child as the agent sees it: its end of the child's socket pair
/// and the container root it was given, released when the child exits.
struct Child {
    pid: libc::pid_t,
    chan: OwnedFd,
    asked: bool,
    root: Option<PathBuf>,
}

thread_local! {
    static CHILDREN: RefCell<Vec<Child>> = const { RefCell::new(Vec::new()) };
}

pub fn listen() -> io::Result<OwnedFd> {
    super::relay::listen_vsock(COPY_PORT)
}

/// Accepts every pending copy and forks a child for each. `running` maps
/// container ids to their init pids.
pub fn accept(listener: &OwnedFd, running: &[(&str, libc::pid_t)], paths: &Paths) {
    loop {
        // SAFETY: accept4 on a listening socket we own; the fd is owned immediately.
        let fd = unsafe { libc::accept4(listener.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
        if fd < 0 {
            return;
        }
        // SAFETY: a fresh descriptor from accept4.
        let sock = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut pair = [0; 2];
        // SAFETY: socketpair fills two descriptors, owned immediately.
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0, pair.as_mut_ptr()) } != 0 {
            eprintln!("kiri-init: copy: socketpair: {}", io::Error::last_os_error());
            continue;
        }
        // SAFETY: fresh descriptors from socketpair.
        let (ours, theirs) = unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) };
        // SAFETY: the agent is single-threaded, so the child is a consistent
        // copy. The child only uses what it inherited, then exits.
        match unsafe { libc::fork() } {
            0 => {
                drop(ours);
                let code = match job(sock, theirs, running, paths) {
                    Ok(()) => 0,
                    Err(e) => {
                        eprintln!("kiri-init: copy: {e}");
                        1
                    }
                };
                // SAFETY: leaving the child without running the parent's destructors.
                unsafe { libc::_exit(code) }
            }
            pid if pid < 0 => eprintln!("kiri-init: copy: fork: {}", io::Error::last_os_error()),
            // The parent's copy closes here; the agent reaps the child like
            // any other and then calls `exited`.
            pid => {
                drop((sock, theirs));
                CHILDREN.with_borrow_mut(|c| c.push(Child { pid, chan: ours, asked: false, root: None }));
            }
        }
    }
}

/// The copy children's sockets the agent waits on: those that haven't
/// asked for a root yet.
pub fn interest(fds: &mut Vec<libc::pollfd>) {
    CHILDREN.with_borrow(|c| {
        for ch in c.iter().filter(|ch| !ch.asked) {
            fds.push(libc::pollfd { fd: ch.chan.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        }
    });
}

/// Whether `fd` is a copy child's socket; if so, answers its request:
/// `m<id>` and the container's layers, one per line, to mount its root or
/// share the mount it has; `h<id>` to only hold a mount there is (a copy
/// into a running container, which must not outlive a restart's unmount).
/// The answer is `+`, or `-` and why not.
pub fn on_readable(fd: i32, paths: &Paths) -> bool {
    CHILDREN.with_borrow_mut(|c| {
        let Some(ch) = c.iter_mut().find(|ch| ch.chan.as_raw_fd() == fd) else { return false };
        let mut buf = vec![0u8; 64 << 10];
        // SAFETY: receiving into a buffer we own from a descriptor we own.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
        if n < 0 && matches!(io::Error::last_os_error().raw_os_error(), Some(libc::EAGAIN | libc::EINTR)) {
            return true;
        }
        ch.asked = true;
        if n <= 0 {
            // It exited without asking; `exited` tidies up.
            return true;
        }
        let text = String::from_utf8_lossy(&buf[..n as usize]).into_owned();
        let (kind, rest) = text.split_at(text.chars().next().map_or(0, char::len_utf8));
        let mut lines = rest.split('\n');
        let id = lines.next().unwrap_or("");
        let layers: Vec<&str> = lines.collect();
        let got = match kind {
            "m" => super::roots::acquire(paths, id, &layers),
            "h" => super::roots::hold(paths, id),
            _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown request")),
        };
        let answer = match got {
            Ok(root) => {
                ch.root = Some(root);
                "+".to_owned()
            }
            Err(e) => format!("-{e}"),
        };
        // A child gone meanwhile can't be answered: its root goes back when
        // it is reaped.
        // SAFETY: sending from a buffer we own on a descriptor we own.
        unsafe { libc::send(fd, answer.as_ptr().cast(), answer.len(), libc::MSG_NOSIGNAL) };
        true
    })
}

/// Linux host, the agent leaving: copies still running end with it, and
/// their roots go back before the exit sweep unmounts what's left.
pub fn stop_all() {
    let pids: Vec<libc::pid_t> = CHILDREN.with_borrow(|c| c.iter().map(|ch| ch.pid).collect());
    for pid in pids {
        // SAFETY: killing and reaping a copy child we forked.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        exited(pid);
    }
}

/// A reaped child: if it was a copy, the root it held is let go.
pub fn exited(pid: libc::pid_t) {
    let gone = CHILDREN.with_borrow_mut(|c| c.iter().position(|ch| ch.pid == pid).map(|i| c.swap_remove(i)));
    if let Some(Child { root: Some(root), .. }) = gone
        && let Some(base) = root.parent()
    {
        super::roots::release(base);
    }
}

fn job(sock: OwnedFd, chan: OwnedFd, running: &[(&str, libc::pid_t)], paths: &Paths) -> io::Result<()> {
    // Only the connection, the socket to the agent and the console stay
    // open: the child must not hold the agent's pipes, which would keep
    // containers' stdin from closing.
    let (lo, hi) = {
        let (a, b) = (sock.as_raw_fd(), chan.as_raw_fd());
        (a.min(b), a.max(b))
    };
    // SAFETY: closing descriptor ranges in this process (an empty range,
    // first above last, is refused and closes nothing).
    unsafe {
        for (first, last) in [(3, lo - 1), (lo + 1, hi - 1), (hi + 1, libc::c_int::MAX)] {
            if first <= last {
                libc::syscall(libc::SYS_close_range, first as libc::c_uint, last as libc::c_uint, 0);
            }
        }
    }
    let mut conn = fs::File::from(sock);
    let mut frame = Vec::new();
    read_frame(&mut conn, &mut frame)?;
    let spec = match kiri_proto::decode(&frame) {
        Ok(Msg::Copy(c)) => c,
        Ok(other) => return reply_error(&mut conn, &format!("expected a copy request, got {other:?}")),
        Err(e) => return reply_error(&mut conn, &format!("bad frame: {e:?}")),
    };
    let result = match spec.op {
        // These read the writable layer itself, next to the image's layers.
        copy_op::DIFF | copy_op::COMMIT => layer_job(&mut conn, &spec, paths),
        _ => {
            let mounts = match enter(&spec, running, paths, &chan) {
                Ok(m) => m,
                Err(e) => return reply_error(&mut conn, &format!("container {}: {e}", spec.id)),
            };
            drop(chan);
            match spec.op {
                copy_op::IN => copy_in(&mut conn, &spec, &mounts),
                copy_op::OUT | copy_op::STAT => copy_out(&mut conn, &spec),
                copy_op::EXPORT => export(&mut conn),
                op => Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unknown copy op {op}"))),
            }
        }
    };
    match result {
        Ok(()) => Ok(()),
        Err(e) => reply_error(&mut conn, &e.to_string()),
    }
}

/// A mount active in the container's root view, used by `copy_in` to refuse
/// writes into read-only mounts and to overwrite bind-mounted files in place.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MountAccess {
    target: PathBuf,
    ro: bool,
    tmpfs: bool,
}

/// Normalizes an absolute mount target path (`"/data/"` → `"/data"`, `"/"` stays `"/"`).
fn clean_mount_target(target: &str) -> String {
    let parts: Vec<&str> = target.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
    format!("/{}", parts.join("/"))
}

/// Pure parsing of `CopySpec::mounts` (no filesystem I/O): validates each line
/// and sorts parent-first, matching `container::parse_mounts`.
fn parse_mount_access(list: StrList<'_>) -> io::Result<Vec<MountAccess>> {
    let mut out = Vec::with_capacity(list.len());
    for m in list.iter() {
        let f: Vec<&str> = m.split('\t').collect();
        if f.len() != 3 && f.len() != 7 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("bad mount {m:?}")));
        }
        let (given_target, words) = (f[1], f[2]);
        if !given_target.starts_with('/') || given_target.split('/').any(|c| c == "..") {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("bad mount target {given_target}")));
        }
        let flags: Vec<&str> = words.split(',').filter(|w| !w.is_empty()).collect();
        let tmpfs = flags.contains(&"tmpfs");
        let ro = if tmpfs { container::tmpfs_flags(&flags) & libc::MS_RDONLY != 0 } else { flags.contains(&"ro") };
        out.push(MountAccess { target: PathBuf::from(clean_mount_target(given_target)), ro, tmpfs });
    }
    out.sort_by_key(|m| m.target.components().count());
    Ok(out)
}

/// Resolves each mount's target inside the container chroot so symlinks in
/// mount target paths (e.g. `/var/run/cfg` → `/run/cfg`) match canonicalized
/// destination paths.
fn resolve_mount_targets(access: &mut [MountAccess]) {
    for m in access {
        if let Ok(real) = fs::canonicalize(&m.target) {
            m.target = real;
        }
    }
}

/// Makes the container's root this process's `/`, assembling non-tmpfs volumes
/// and bind mounts in a private mount namespace when the container is not
/// running (except for `EXPORT`, which reads only the overlay rootfs).
fn enter(spec: &CopySpec<'_>, running: &[(&str, libc::pid_t)], paths: &Paths, chan: &OwnedFd) -> io::Result<Vec<MountAccess>> {
    match running.iter().find(|(id, _)| *id == spec.id) {
        // An export is the container's own filesystem, without its mounts:
        // the overlay the agent mounted for it.
        // It may have stopped since: then the root is mounted for it.
        Some(_) if spec.op == copy_op::EXPORT => {
            if ask(chan, 'h', spec).is_err() {
                if spec.layers.is_empty() {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "the container stopped"));
                }
                ask(chan, 'm', spec)?;
            }
            chroot_into(&paths.containers.join(spec.id).join("rootfs"))?;
            Ok(Vec::new())
        }
        // Through /proc the root shows the container's live mounts (including
        // tmpfs). The copy holds the container's root meanwhile, so a restart
        // can't mount a second one over the same layer while it still writes.
        Some((_, pid)) => {
            let _ = ask(chan, 'h', spec);
            let mut access = parse_mount_access(spec.mounts)?;
            chroot_into(&PathBuf::from(format!("/proc/{pid}/root")))?;
            resolve_mount_targets(&mut access);
            Ok(access)
        }
        None => {
            if spec.layers.is_empty() {
                return Err(io::Error::new(io::ErrorKind::NotFound, "no such container"));
            }
            ask(chan, 'm', spec)?;
            let rootfs = paths.containers.join(spec.id).join("rootfs");
            if spec.op == copy_op::EXPORT {
                chroot_into(&rootfs)?;
                return Ok(Vec::new());
            }
            // A stopped or created container has no live tmpfs mounts.
            let mut access = parse_mount_access(spec.mounts)?;
            access.retain(|m| !m.tmpfs);
            if !access.is_empty() {
                // Assemble mounts strictly inside this short-lived child's own
                // mount namespace so nothing ever leaks into the agent's.
                sys::unshare(libc::CLONE_NEWNS)?;
                sys::remount(c"/", libc::MS_REC | libc::MS_SLAVE)?;
                let mut mounts = container::parse_mounts(spec.mounts)?;
                mounts.retain(|m| !m.is_tmpfs());
                let rootfs_c = sys::cstr(&rootfs)?;
                // SAFETY: valid NUL-terminated path.
                unsafe { sys::check(libc::chdir(rootfs_c.as_ptr()) as _, "chdir")? };
                let root = inroot::open_root(Path::new("."))?;
                let image = if mounts.iter().any(container::Mount::is_copy_up) { container::image_tree() } else { None };
                for m in &mounts {
                    container::apply_mount(root.as_fd(), image.as_ref().map(|f| f.as_fd()), m)?;
                }
                drop(image);
                drop(root);
                if spec.op == copy_op::IN && spec.flags & copy_flags::READONLY_ROOTFS != 0 {
                    // Defense in depth: remount only the rootfs mount read-only
                    // in our private namespace, leaving writable mounts rw.
                    sys::mount(c"none", c".", c"none", libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY, None)?;
                }
                // SAFETY: valid NUL-terminated paths.
                unsafe {
                    sys::check(libc::chroot(c".".as_ptr()) as _, "chroot")?;
                    sys::check(libc::chdir(c"/".as_ptr()) as _, "chdir")?;
                }
            } else {
                chroot_into(&rootfs)?;
            }
            resolve_mount_targets(&mut access);
            Ok(access)
        }
    }
}

fn chroot_into(root: &Path) -> io::Result<()> {
    let c = sys::cstr(root)?;
    // SAFETY: valid NUL-terminated paths.
    unsafe {
        sys::check(libc::chroot(c.as_ptr()) as _, "chroot")?;
        sys::check(libc::chdir(c"/".as_ptr()) as _, "chdir")?;
    }
    Ok(())
}

/// Asks the agent for the container's root (`m`: mounted, or shared with
/// whatever has it mounted now, such as the container starting meanwhile)
/// or to hold the mount a running container has (`h`). Either stays until
/// this child exits.
fn ask(chan: &OwnedFd, kind: char, spec: &CopySpec<'_>) -> io::Result<()> {
    let mut ask = format!("{kind}{}", spec.id);
    if kind == 'm' {
        for l in spec.layers.iter() {
            ask.push('\n');
            ask.push_str(l);
        }
    }
    // SAFETY: sending from a buffer we own on a descriptor we own.
    sys::check(unsafe { libc::send(chan.as_raw_fd(), ask.as_ptr().cast(), ask.len(), libc::MSG_NOSIGNAL) } as _, "ask for the root")?;
    let mut buf = [0u8; 4096];
    // SAFETY: receiving into a buffer we own from a descriptor we own.
    let n = unsafe { libc::recv(chan.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
    match buf[..n.max(0) as usize].split_first() {
        Some((b'+', _)) => Ok(()),
        Some((_, why)) => Err(io::Error::other(String::from_utf8_lossy(why).into_owned())),
        None => Err(io::Error::other("the agent did not answer")),
    }
}

/// Refuses writes when the innermost mount containing `canonical_path` is
/// read-only, or when `canonical_path` is outside every mount and the
/// container has `--read-only`.
fn check_writable(canonical_path: &Path, mounts: &[MountAccess], readonly_rootfs: bool) -> io::Result<()> {
    let innermost = mounts
        .iter()
        .filter(|m| canonical_path == m.target || canonical_path.starts_with(&m.target))
        .max_by_key(|m| m.target.components().count());
    match innermost {
        Some(m) if m.ro => Err(io::Error::new(io::ErrorKind::PermissionDenied, "forbidden: mounted volume is marked read-only")),
        Some(_) => Ok(()),
        None if readonly_rootfs => Err(io::Error::new(io::ErrorKind::PermissionDenied, "forbidden: container rootfs is marked read-only")),
        None => Ok(()),
    }
}

/// Resolves a tar entry's target path under `canonical_dest`, following
/// existing symlinks in parent components (inside the container chroot) while
/// keeping the final component unfollowed (since unpacking replaces a final
/// symlink rather than writing through it).
fn resolve_entry_target(canonical_dest: &Path, entry_path: &Path) -> PathBuf {
    let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
    for c in entry_path.components() {
        match c {
            std::path::Component::Normal(p) => parts.push(p),
            std::path::Component::ParentDir => {
                parts.pop();
            }
            std::path::Component::CurDir | std::path::Component::RootDir | std::path::Component::Prefix(_) => {}
        }
    }
    let Some((last, parents)) = parts.split_last() else {
        return canonical_dest.to_path_buf();
    };
    let mut cur = canonical_dest.to_path_buf();
    let mut exists = true;
    for part in parents {
        cur.push(part);
        if exists {
            match fs::canonicalize(&cur) {
                Ok(real) => cur = real,
                Err(_) => exists = false,
            }
        }
    }
    cur.push(last);
    cur
}

fn is_erofs(e: &io::Error) -> bool {
    if e.raw_os_error() == Some(libc::EROFS) {
        return true;
    }
    let mut cur: Option<&(dyn StdError + 'static)> = e.source();
    while let Some(src) = cur {
        if src.downcast_ref::<io::Error>().is_some_and(|ioe| ioe.raw_os_error() == Some(libc::EROFS)) {
            return true;
        }
        cur = src.source();
    }
    false
}

fn map_erofs(e: io::Error, path: &Path, mounts: &[MountAccess], readonly_rootfs: bool) -> io::Error {
    if !is_erofs(&e) {
        return e;
    }
    match check_writable(path, mounts, readonly_rootfs) {
        Err(ro) => ro,
        Ok(()) => io::Error::new(io::ErrorKind::PermissionDenied, "forbidden: mounted volume is marked read-only"),
    }
}

/// Overwrites an existing bind-mounted regular file in place: `unlink(2)` on a
/// file bind mount fails with `EBUSY`, so `tar::Entry::unpack_in` cannot
/// replace it by remove-and-recreate.
fn unpack_mount_file<R: Read>(entry: &mut tar::Entry<'_, R>, target: &Path, owner: Option<(libc::uid_t, libc::gid_t)>) -> io::Result<()> {
    let c = sys::cstr(target)?;
    // SAFETY: valid NUL-terminated path; O_NOFOLLOW never follows a symlink,
    // and O_NONBLOCK avoids blocking if a FIFO was swapped in.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh descriptor owned only here.
    let mut file = fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    // SAFETY: plain zeroed stat filled from our own descriptor.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    sys::check(unsafe { libc::fstat(file.as_raw_fd(), &mut st) } as _, "fstat")?;
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "mount target is not a regular file"));
    }
    // SAFETY: valid regular-file descriptor we own.
    sys::check(unsafe { libc::ftruncate(file.as_raw_fd(), 0) } as _, "ftruncate")?;
    io::copy(entry, &mut file)?;
    if let Some((uid, gid)) = owner {
        // SAFETY: valid descriptor we own.
        sys::check(unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } as _, "fchown")?;
    } else if let (Ok(uid), Ok(gid)) = (entry.header().uid(), entry.header().gid()) {
        // SAFETY: valid descriptor we own; best-effort like tar::Archive.
        unsafe { libc::fchown(file.as_raw_fd(), uid as libc::uid_t, gid as libc::gid_t) };
    }
    if let Ok(mode) = entry.header().mode() {
        // SAFETY: valid descriptor we own.
        sys::check(unsafe { libc::fchmod(file.as_raw_fd(), (mode & 0o7777) as libc::mode_t) } as _, "fchmod")?;
    }
    if let Ok(mtime) = entry.header().mtime() {
        let times = [
            libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT },
            libc::timespec { tv_sec: mtime as _, tv_nsec: 0 },
        ];
        // SAFETY: valid descriptor and 2-element timespec array.
        unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) };
    }
    Ok(())
}

/// Unpacks the archive that follows into `spec.path`, a directory.
fn copy_in(conn: &mut fs::File, spec: &CopySpec<'_>, mounts: &[MountAccess]) -> io::Result<()> {
    let (path, user) = if spec.flags & copy_flags::KEEP_OWNERS != 0 {
        spec.path.split_once('\0').unwrap_or((spec.path, ""))
    } else {
        (spec.path, "")
    };
    let dest = std::path::Path::new(path);
    match fs::metadata(dest) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("notdir: extraction point is not a directory: {path}"))),
        Err(_) => return Err(io::Error::new(io::ErrorKind::NotFound, format!("notfound: Could not find the file {path} in container {}", spec.id))),
    }
    let canonical_dest = fs::canonicalize(dest)?;
    let readonly_rootfs = spec.flags & copy_flags::READONLY_ROOTFS != 0;
    check_writable(&canonical_dest, mounts, readonly_rootfs)?;
    let owner = if user.is_empty() { None } else { Some(resolve_copy_user_in(std::path::Path::new("/"), user)?) };
    let source: Box<dyn Read + '_> = if spec.flags & copy_flags::CHUNKED != 0 { Box::new(Chunks::new(&mut *conn)) } else { Box::new(&mut *conn) };
    let mut reader = BufReader::with_capacity(256 * 1024, source);
    unpack_in(&mut reader, dest, &canonical_dest, spec.flags, owner, mounts, readonly_rootfs)?;
    // The archive's trailing padding: read it so the host's writes complete.
    io::copy(&mut reader, &mut io::sink())?;
    drop(reader);
    let mut out = Vec::new();
    Msg::CopyDone.encode(&mut out);
    conn.write_all(&out)
}

/// Moby's `applyTarCopyUserOptions` (`getUIDGID`): resolves a container's
/// non-empty `Config.User` (`user[:group]`) against its `/etc/passwd` and
/// `/etc/group` when `copyUIDGID` (`docker cp -a`) is set.
fn resolve_copy_user_in(root: &std::path::Path, user: &str) -> io::Result<(libc::uid_t, libc::gid_t)> {
    let (u, g) = user.split_once(':').unwrap_or((user, ""));
    let (mut uid, mut gid) = (0, 0);
    if !u.is_empty() {
        let passwd = fs::read_to_string(root.join("etc/passwd")).unwrap_or_default();
        if let Ok(id) = u.parse::<u32>()
            && id <= i32::MAX as u32
        {
            uid = id;
            gid = passwd
                .lines()
                .find_map(|l| {
                    let mut f = l.split(':');
                    (f.nth(2)?.parse::<u32>().ok()? == id).then(|| f.next()?.parse::<u32>().ok()).flatten()
                })
                .unwrap_or(0);
        } else {
            (uid, gid) = passwd
                .lines()
                .find_map(|l| {
                    let mut f = l.split(':');
                    if f.next()? != u {
                        return None;
                    }
                    Some((f.nth(1)?.parse::<u32>().ok()?, f.next()?.parse::<u32>().ok()?))
                })
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("failed to look up user {u:?} in container")))?;
        }
    }
    if !g.is_empty() {
        if let Ok(id) = g.parse::<u32>()
            && id <= i32::MAX as u32
        {
            gid = id;
        } else {
            let group = fs::read_to_string(root.join("etc/group")).unwrap_or_default();
            gid = group
                .lines()
                .find_map(|l| {
                    let mut f = l.split(':');
                    if f.next()? != g {
                        return None;
                    }
                    f.nth(1)?.parse::<u32>().ok()
                })
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("failed to look up group {g:?} in container")))?;
        }
    }
    Ok((uid, gid))
}

fn unpack_in(
    reader: impl Read,
    dest: &std::path::Path,
    canonical_dest: &std::path::Path,
    flags: u32,
    owner: Option<(libc::uid_t, libc::gid_t)>,
    mounts: &[MountAccess],
    readonly_rootfs: bool,
) -> io::Result<()> {
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    // Moby's `defaultTarCopyOptions` preserves the archive's header UID/GID
    // (`ChownOpts == nil`); when `copyUIDGID` (`docker cp -a`) is set on a
    // container with a non-empty `Config.User`, `applyTarCopyUserOptions`
    // sets `ChownOpts` (`owner`) to chown every unpacked entry to that user.
    archive.set_preserve_ownerships(owner.is_none());
    archive.set_unpack_xattrs(false);
    archive.set_overwrite(true);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let etype = entry.header().entry_type();
        let check_path = if !etype.is_pax_global_extensions() && !etype.is_pax_local_extensions() {
            let resolved = resolve_entry_target(canonical_dest, &path);
            check_writable(&resolved, mounts, readonly_rootfs)?;
            Some(resolved)
        } else {
            None
        };
        if flags & copy_flags::NO_OVERWRITE_DIR_NON_DIR != 0 {
            let target = dest.join(&path);
            if let Ok(m) = fs::symlink_metadata(&target)
                && m.is_dir() != etype.is_dir()
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("cannot overwrite {} {} with {}", if m.is_dir() { "directory" } else { "non-directory" }, target.display(), if m.is_dir() { "non-directory" } else { "directory" }),
                ));
            }
        }
        if let Some(ref resolved) = check_path
            && etype.is_file()
            && mounts.iter().any(|m| m.target == *resolved)
            && fs::symlink_metadata(resolved).is_ok_and(|m| m.file_type().is_file())
        {
            unpack_mount_file(&mut entry, resolved, owner).map_err(|e| map_erofs(e, resolved, mounts, readonly_rootfs))?;
            continue;
        }
        // `docker cp` and the classic build's context keep a time of 0.
        let target_for_err = check_path.as_deref().unwrap_or(canonical_dest);
        if entry.unpack_in(dest).map_err(|e| map_erofs(e, target_for_err, mounts, readonly_rootfs))? {
            if let Some((uid, gid)) = owner
                && !etype.is_pax_global_extensions()
            {
                let mut file_dst = dest.to_path_buf();
                for part in path.components() {
                    if let std::path::Component::Normal(p) = part {
                        file_dst.push(p);
                    }
                }
                if file_dst != dest {
                    let c = sys::cstr(&file_dst)?;
                    // SAFETY: valid NUL-terminated path inside the container chroot.
                    sys::check(unsafe { libc::lchown(c.as_ptr(), uid, gid) } as _, "lchown")?;
                    if !fs::symlink_metadata(&file_dst)?.file_type().is_symlink()
                        && let Ok(mode) = entry.header().mode()
                        && mode & 0o6000 != 0
                    {
                        // SAFETY: valid NUL-terminated non-symlink path.
                        sys::check(unsafe { libc::chmod(c.as_ptr(), (mode & 0o7777) as libc::mode_t) } as _, "chmod")?;
                    }
                }
            }
            super::layers::keep_zero_time(dest, &path, entry.header())?;
        }
    }
    Ok(())
}

/// A `copy_flags::CHUNKED` archive: chunks of `len: u32 LE | bytes`, read
/// as one stream that ends at the empty chunk, with the connection still
/// open for the answer.
struct Chunks<R> {
    inner: R,
    left: u32,
    done: bool,
}

impl<R: Read> Chunks<R> {
    fn new(inner: R) -> Self {
        Chunks { inner, left: 0, done: false }
    }
}

impl<R: Read> Read for Chunks<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.left == 0 {
            if self.done || buf.is_empty() {
                return Ok(0);
            }
            let mut len = [0u8; 4];
            self.inner.read_exact(&mut len)?;
            self.left = u32::from_le_bytes(len);
            self.done = self.left == 0;
        }
        let want = buf.len().min(self.left as usize);
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the archive ended inside a chunk"));
        }
        self.left -= n as u32;
        Ok(n)
    }
}

/// Answers with the path's metadata; for `OUT` an archive of it follows.
fn copy_out(conn: &mut fs::File, spec: &CopySpec<'_>) -> io::Result<()> {
    // Docker archives a path with its "." and ".." resolved by name, but
    // stats it as given.
    let cleaned;
    let source = if spec.op == copy_op::OUT && !spec.path.is_empty() {
        cleaned = archived(spec.path);
        cleaned.as_str()
    } else {
        spec.path
    };
    let path = std::path::Path::new(source);
    let meta = fs::symlink_metadata(path)
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, format!("notfound: Could not find the file {} in container {}", spec.path, spec.id)))?;
    let link = if meta.file_type().is_symlink() { fs::read_link(path)?.to_string_lossy().into_owned() } else { String::new() };
    let name = base(source);
    let entry = FsEntry {
        name,
        mode: meta.mode(),
        size: meta.len(),
        mtime: meta.mtime(),
        mtime_nsec: meta.mtime_nsec() as u32,
        ino: meta.ino(),
    };
    let mut out = Vec::new();
    Msg::CopyStat { entry, link: &link }.encode(&mut out);
    conn.write_all(&out)?;
    if spec.op == copy_op::STAT {
        return Ok(());
    }
    let mut w = BufWriter::with_capacity(256 * 1024, &mut *conn);
    {
        let mut b = tar::Builder::new(&mut w);
        b.follow_symlinks(false);
        if meta.is_dir() {
            append_tree(&mut b, path, std::path::Path::new(name))?;
        } else {
            append_one(&mut b, path, std::path::Path::new(name), &meta)?;
        }
        b.finish()?;
    }
    w.flush()
}

/// The last component of `path` as Docker names it: "." and ".." are kept,
/// and the root is "/".
fn base(path: &str) -> &str {
    path.trim_end_matches('/').rsplit('/').next().filter(|name| !name.is_empty()).unwrap_or("/")
}

/// The path an archive is read from: `path` with its dots resolved by name.
/// Where that names nothing, `path` as given, so that every path found
/// before is still found: the window follows a start script's relative
/// link by asking for the link's directory, "..", and the rest, and behind
/// a linked directory (/bin on many images) only the kernel finds that.
fn archived(path: &str) -> String {
    let cleaned = clean(path);
    if fs::symlink_metadata(&cleaned).is_ok() { cleaned } else { path.to_owned() }
}

/// `path` from the root, with "." and ".." resolved by name. A final "." (a
/// directory's contents) and a trailing "/" (a link's directory) are kept.
fn clean(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            name => parts.push(name),
        }
    }
    let mut cleaned = format!("/{}", parts.join("/"));
    if base(path) == "." {
        if !cleaned.ends_with('/') {
            cleaned.push('/');
        }
        cleaned.push('.');
    }
    if path.ends_with('/') && !cleaned.ends_with('/') {
        cleaned.push('/');
    }
    cleaned
}

/// Like `append_dir_all`, but sockets (which tar cannot hold) are skipped,
/// and the kernel's /proc and /sys archive as empty directories.
fn append_tree(b: &mut tar::Builder<impl Write>, src: &std::path::Path, name: &std::path::Path) -> io::Result<()> {
    let mut stack = vec![(src.to_path_buf(), name.to_path_buf())];
    while let Some((src, name)) = stack.pop() {
        let meta = fs::symlink_metadata(&src)?;
        append_one(b, &src, &name, &meta)?;
        if meta.is_dir() && !is_kernel_fs(&src) {
            let mut children: Vec<_> = fs::read_dir(&src)?.flatten().collect();
            children.sort_by_key(|e| e.file_name());
            for e in children.into_iter().rev() {
                stack.push((e.path(), name.join(e.file_name())));
            }
        }
    }
    Ok(())
}

/// Whether `dir` is on procfs or sysfs. Asked of the filesystem, not of the
/// path: a link to `/` inside the container leads to them by any name.
fn is_kernel_fs(dir: &std::path::Path) -> bool {
    let Ok(c) = sys::cstr(dir) else { return false };
    // SAFETY: statfs into a zeroed struct, on a valid NUL-terminated path.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return false;
    }
    matches!(st.f_type as i64, PROC_MAGIC | SYSFS_MAGIC)
}

const PROC_MAGIC: i64 = 0x9fa0;
const SYSFS_MAGIC: i64 = 0x6265_6572;

/// What a tar header's mode holds: the permission bits. The file type has
/// its own field, and Docker's archives leave it out of the mode.
fn mode_bits(meta: &fs::Metadata) -> u32 {
    meta.mode() & 0o7777
}

fn append_one(b: &mut tar::Builder<impl Write>, src: &std::path::Path, name: &std::path::Path, meta: &fs::Metadata) -> io::Result<()> {
    let ft = meta.file_type();
    if ft.is_socket() {
        return Ok(());
    }
    // A directory's contents under "./" and the root's under "/" keep those names.
    let verbatim = name.as_os_str().as_bytes().starts_with(b"./") || name.has_root();
    if ft.is_file() {
        let mut h = tar::Header::new_gnu();
        h.set_metadata(meta);
        h.set_mode(mode_bits(meta));
        let mut f = fs::File::open(src)?;
        if verbatim {
            return append_contents(b, &mut h, name, None, &mut f);
        }
        return b.append_data(&mut h, name, &mut f);
    }
    if ft.is_dir() || ft.is_symlink() || ft.is_fifo() || ft.is_char_device() || ft.is_block_device() {
        let mut h = tar::Header::new_gnu();
        h.set_metadata(meta);
        h.set_mode(mode_bits(meta));
        h.set_size(0);
        if ft.is_symlink() {
            let link = fs::read_link(src)?;
            if verbatim {
                return append_contents(b, &mut h, name, Some(&link), io::empty());
            }
            return b.append_link(&mut h, name, link);
        }
        if ft.is_char_device() || ft.is_block_device() {
            let rdev = meta.rdev();
            h.set_device_major(libc::major(rdev))?;
            h.set_device_minor(libc::minor(rdev))?;
        }
        if verbatim {
            return append_contents(b, &mut h, name, None, io::empty());
        }
        return b.append_data(&mut h, name, io::empty());
    }
    Ok(())
}

/// tar's path setter drops "./" and refuses a leading "/". Docker's client
/// needs "./" when it rebases a directory-contents archive into a destination
/// that does not exist, and puts the new name in front of the root's "/".
/// These paths come from append_tree's "." or "/" plus directory entry names.
fn append_contents(b: &mut tar::Builder<impl Write>, h: &mut tar::Header, name: &std::path::Path, link: Option<&std::path::Path>, data: impl Read) -> io::Result<()> {
    fn field(b: &mut tar::Builder<impl Write>, slot: &mut [u8], bytes: &[u8], kind: u8) -> io::Result<()> {
        if bytes.len() > slot.len() {
            let mut long = tar::Header::new_gnu();
            long.set_path("././@LongLink")?;
            long.set_entry_type(tar::EntryType::new(kind));
            long.set_mode(0o644);
            long.set_size(bytes.len() as u64 + 1);
            long.set_cksum();
            b.append(&long, bytes.chain(io::repeat(0).take(1)))?;
        }
        slot.fill(0);
        let count = bytes.len().min(slot.len());
        slot[..count].copy_from_slice(&bytes[..count]);
        Ok(())
    }
    field(b, &mut h.as_old_mut().name, name.as_os_str().as_bytes(), b'L')?;
    if let Some(link) = link {
        field(b, &mut h.as_old_mut().linkname, link.as_os_str().as_bytes(), b'K')?;
    }
    h.set_cksum();
    b.append(h, data)
}

fn done(conn: &mut fs::File) -> io::Result<()> {
    let mut out = Vec::new();
    Msg::CopyDone.encode(&mut out);
    conn.write_all(&out)
}

/// `docker export`: everything under `/` (the chroot), entries named
/// without a leading slash, as Docker writes them.
fn export(conn: &mut fs::File) -> io::Result<()> {
    done(conn)?;
    let mut w = BufWriter::with_capacity(256 * 1024, &mut *conn);
    {
        let mut b = tar::Builder::new(&mut w);
        b.follow_symlinks(false);
        let mut children: Vec<_> = fs::read_dir("/")?.flatten().collect();
        children.sort_by_key(|e| e.file_name());
        for e in children {
            append_tree(&mut b, &e.path(), std::path::Path::new(&e.file_name()))?;
        }
        b.finish()?;
    }
    w.flush()
}

/// An overlay whiteout: a 0:0 character device.
fn is_whiteout(m: &fs::Metadata) -> bool {
    m.file_type().is_char_device() && m.rdev() == 0
}

fn is_opaque(path: &std::path::Path) -> bool {
    let Ok(c) = sys::cstr(path) else { return false };
    let mut v = [0u8; 2];
    // SAFETY: valid path and name; reads at most 2 bytes into `v`.
    let n = unsafe { libc::lgetxattr(c.as_ptr(), c"trusted.overlay.opaque".as_ptr(), v.as_mut_ptr().cast(), v.len()) };
    n == 1 && v[0] == b'y'
}

/// The marker as the agent made it at start: not a change the container
/// made, so Docker shows it in neither `docker diff` nor a committed layer.
/// Once the container has written to it or changed its mode or owner, it is
/// a change like any other.
fn is_marker(rel: &std::path::Path, m: &fs::Metadata) -> bool {
    is_marker_attr(rel, m.file_type().is_file(), m.len(), m.mode(), m.uid(), m.gid())
}

fn is_marker_attr(rel: &std::path::Path, is_file: bool, len: u64, mode: u32, uid: u32, gid: u32) -> bool {
    rel.as_os_str().as_encoded_bytes() == container::MARKER.to_bytes()
        && is_file
        && len == 0
        && mode & 0o7777 == 0o755
        && uid == 0
        && gid == 0
}

fn in_lower_layers(lowers: &[OwnedFd], rel: &std::path::Path) -> bool {
    for l in lowers {
        let Some(rel) = rel.to_str() else { continue };
        let Ok(fd) = super::fsview::open_in(l.as_raw_fd(), rel, libc::O_PATH | libc::O_NOFOLLOW) else { continue };
        // SAFETY: fstat into a zeroed stat on a descriptor we own.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
            continue;
        }
        let whiteout = st.st_mode & libc::S_IFMT == libc::S_IFCHR && st.st_rdev == 0;
        return !whiteout;
    }
    false
}

/// `docker diff` and `docker commit`, from the writable layer.
fn layer_job(conn: &mut fs::File, spec: &CopySpec<'_>, paths: &Paths) -> io::Result<()> {
    if spec.layers.is_empty() {
        return reply_error(conn, "no such container");
    }
    // The image's layers, opened before the chroot below; looked up only
    // with every link resolved inside its own layer.
    let lowers: Vec<OwnedFd> = spec
        .layers
        .iter()
        .filter_map(|d| super::layers::dir(&paths.layers, d).ok())
        .filter_map(|d| {
            let c = sys::cstr(&d).ok()?;
            // SAFETY: plain open of a directory; owned right away.
            let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
            // SAFETY: a fresh descriptor when non-negative.
            (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
        })
        .collect();
    let in_lower = |rel: &std::path::Path| in_lower_layers(&lowers, rel);
    // A running container writes its upper layer while we walk it, and could
    // swap a directory for a link to `/` between our look and our read
    // (`docker diff`, `commit --pause=false`). Inside a chroot of the layer
    // that link leads back into the layer, as `enter` does for the others.
    let layer = paths.containers.join(spec.id).join("upper");
    // A container that never started has no writable layer yet: nothing
    // changed, and there is nothing to enter (the walk below must not run
    // on this process's own root).
    let fresh = matches!(fs::symlink_metadata(&layer), Err(e) if e.kind() == io::ErrorKind::NotFound);
    if !fresh {
        let c = sys::cstr(&layer)?;
        // SAFETY: valid NUL-terminated paths.
        unsafe {
            sys::check(libc::chroot(c.as_ptr()) as _, "chroot")?;
            sys::check(libc::chdir(c"/".as_ptr()) as _, "chdir")?;
        }
    }
    let upper = std::path::PathBuf::from("/");
    // Every path in the writable layer, parents first.
    let mut entries: Vec<(std::path::PathBuf, fs::Metadata)> = Vec::new();
    let mut stack = if fresh { Vec::new() } else { vec![std::path::PathBuf::new()] };
    while let Some(rel) = stack.pop() {
        let dir = upper.join(&rel);
        let Ok(list) = fs::read_dir(&dir) else { continue };
        let mut names: Vec<_> = list.flatten().collect();
        names.sort_by_key(|e| e.file_name());
        for e in names.into_iter().rev() {
            let r = rel.join(e.file_name());
            let Ok(m) = fs::symlink_metadata(e.path()) else { continue };
            if is_marker(&r, &m) && !in_lower(&r) {
                continue;
            }
            if m.is_dir() {
                stack.push(r.clone());
            }
            entries.push((r, m));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    done(conn)?;
    if spec.op == copy_op::DIFF {
        let mut w = BufWriter::new(&mut *conn);
        for (rel, m) in &entries {
            let kind = if is_whiteout(m) {
                'D'
            } else if in_lower(rel) {
                'C'
            } else {
                'A'
            };
            writeln!(w, "{kind} /{}", rel.display())?;
        }
        return w.flush();
    }
    // An OCI layer: whiteouts become `.wh.name`, opaque directories get `.wh..wh..opq`.
    let mut w = BufWriter::with_capacity(256 * 1024, &mut *conn);
    {
        let mut b = tar::Builder::new(&mut w);
        b.follow_symlinks(false);
        let empty = |b: &mut tar::Builder<_>, name: std::path::PathBuf| -> io::Result<()> {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Regular);
            h.set_size(0);
            h.set_mode(0o644);
            b.append_data(&mut h, name, io::empty())
        };
        for (rel, m) in &entries {
            if is_whiteout(m) {
                let name = format!(".wh.{}", rel.file_name().map(|n| n.to_string_lossy()).unwrap_or_default());
                empty(&mut b, rel.with_file_name(name))?;
                continue;
            }
            append_one(&mut b, &upper.join(rel), rel, m)?;
            if m.is_dir() && is_opaque(&upper.join(rel)) {
                empty(&mut b, rel.join(".wh..wh..opq"))?;
            }
        }
        b.finish()?;
    }
    w.flush()
}

fn reply_error(conn: &mut fs::File, msg: &str) -> io::Result<()> {
    let mut out = Vec::new();
    Msg::Error(msg).encode(&mut out);
    conn.write_all(&out)
}

fn read_frame(conn: &mut impl Read, buf: &mut Vec<u8>) -> io::Result<()> {
    buf.resize(4, 0);
    conn.read_exact(&mut buf[..4])?;
    let len = kiri_proto::frame_len(buf[..4].try_into().expect("4 bytes")).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;
    buf.resize(len, 0);
    conn.read_exact(&mut buf[4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contents_keep_dot_prefix_and_long_names() {
        for length in [4, 98, 99, 100, 101, 255] {
            let name = format!("./{}", "a".repeat(length));
            let link = "../".to_owned() + &"b".repeat(length);
            let mut bytes = Vec::new();
            {
                let mut archive = tar::Builder::new(&mut bytes);
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                append_contents(&mut archive, &mut header, std::path::Path::new(&name), Some(std::path::Path::new(&link)), io::empty()).unwrap();
                archive.finish().unwrap();
            }
            let mut archive = tar::Archive::new(bytes.as_slice());
            let mut entries = archive.entries().unwrap();
            let entry = entries.next().unwrap().unwrap();
            assert_eq!(entry.path_bytes().as_ref(), name.as_bytes());
            assert_eq!(entry.link_name_bytes().unwrap().as_ref(), link.as_bytes());
            assert!(entries.next().is_none());
        }
    }

    #[test]
    fn archived_paths_resolve_dots_by_name_and_stats_keep_them() {
        for (path, cleaned, name) in [
            ("/t/dir", "/t/dir", "dir"),
            ("/t/dir/", "/t/dir/", "dir"),
            ("/t/dir/.", "/t/dir/.", "."),
            ("/t/dir/./", "/t/dir/./", "."),
            ("/t/dir//.", "/t/dir/.", "."),
            ("/t/dir/sub/..", "/t/dir", "dir"),
            ("/t/dir/sub/../", "/t/dir/", "dir"),
            ("/t/dir/sub/../.", "/t/dir/.", "."),
            ("/t/link/../dir", "/t/dir", "dir"),
            ("t/dir/..", "/t", "t"),
            ("../../t/dir/.", "/t/dir/.", "."),
            ("/", "/", "/"),
            ("//", "/", "/"),
            ("/.", "/.", "."),
            ("/..", "/", "/"),
            ("/etc/..", "/", "/"),
            ("/etc/../.", "/.", "."),
            (".", "/.", "."),
            ("..", "/", "/"),
        ] {
            assert_eq!(clean(path), cleaned, "{path}");
            assert_eq!(base(cleaned), name, "{path}");
        }
        for (path, name) in [("/t/dir/sub/..", ".."), ("/t/dir/sub/../", ".."), ("/t/dir/.", "."), ("/t/dir/", "dir"), ("/", "/"), ("//", "/"), ("/..", "..")] {
            assert_eq!(base(path), name, "{path}");
        }
    }

    #[test]
    fn a_path_only_the_kernel_finds_is_archived_as_given() {
        let dir = std::env::temp_dir().join(format!("kiri-archived-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("usr/bin")).unwrap();
        fs::create_dir_all(dir.join("usr/share")).unwrap();
        fs::create_dir_all(dir.join("share")).unwrap();
        fs::write(dir.join("usr/share/start.sh"), "").unwrap();
        fs::write(dir.join("usr/share/both"), "").unwrap();
        fs::write(dir.join("share/both"), "").unwrap();
        std::os::unix::fs::symlink("usr/bin", dir.join("bin")).unwrap();
        let at = |rest: &str| format!("{}/{rest}", dir.display());
        // By name this is share/start.sh, which is not there: the kernel's stays.
        assert_eq!(archived(&at("bin/../share/start.sh")), at("bin/../share/start.sh"));
        // Where the path by name is there, it is the one, as in Docker.
        assert_eq!(archived(&at("bin/../share/both")), at("share/both"));
        assert_eq!(archived(&at("usr/bin/..")), at("usr"));
        // Nothing either way: the path as given, for the error to name.
        assert_eq!(archived(&at("bin/../none")), at("bin/../none"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn root_and_contents_entries_keep_their_prefix() {
        let root = std::path::Path::new("/");
        let meta = fs::symlink_metadata(root).unwrap();
        let names = ["/", "/etc", ".", "./etc", "etc"];
        let mut bytes = Vec::new();
        {
            let mut archive = tar::Builder::new(&mut bytes);
            for name in names {
                append_one(&mut archive, root, std::path::Path::new(name), &meta).unwrap();
            }
            archive.finish().unwrap();
        }
        let mut archive = tar::Archive::new(bytes.as_slice());
        let got: Vec<_> = archive.entries().unwrap().map(|entry| String::from_utf8(entry.unwrap().path_bytes().into_owned()).unwrap()).collect();
        assert_eq!(got, names);
    }

    #[test]
    fn chunks_end_at_the_empty_chunk_and_leave_the_rest() {
        let wire = [&3u32.to_le_bytes()[..], b"abc", &2u32.to_le_bytes(), b"de", &0u32.to_le_bytes(), b"after"].concat();
        let mut conn = &wire[..];
        let mut got = Vec::new();
        Chunks::new(&mut conn).read_to_end(&mut got).unwrap();
        assert_eq!(got, b"abcde");
        assert_eq!(conn, b"after");
    }

    #[test]
    fn chunks_cut_short_are_an_error() {
        let wire = [&5u32.to_le_bytes()[..], b"ab"].concat();
        let err = Chunks::new(&wire[..]).read_to_end(&mut Vec::new()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn unpack_in_keeps_owners_and_does_not_chown_symlink_targets() {
        // SAFETY: a plain getter.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipped: needs root to keep owners");
            return;
        }
        let dest = std::env::temp_dir().join(format!("kiri-copy-owners-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dest);
        fs::create_dir_all(&dest).unwrap();
        fs::write(dest.join("target"), b"stay").unwrap();
        std::os::unix::fs::symlink("target", dest.join("replaced")).unwrap();

        let mut b = tar::Builder::new(Vec::new());
        let h = |kind: tar::EntryType, size: u64, mode: u32| {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(kind);
            h.set_size(size);
            h.set_mode(mode);
            h.set_uid(1234);
            h.set_gid(1235);
            h.set_mtime(1_700_000_000);
            h.set_cksum();
            h
        };
        b.append_data(&mut h(tar::EntryType::Directory, 0, 0o750), "dir", &[][..]).unwrap();
        b.append_data(&mut h(tar::EntryType::Regular, 3, 0o600), "dir/owned.pem", &b"key"[..]).unwrap();
        b.append_link(&mut h(tar::EntryType::Symlink, 0, 0o777), "link", "target").unwrap();
        b.append_data(&mut h(tar::EntryType::Regular, 3, 0o640), "replaced", &b"new"[..]).unwrap();
        let bytes = b.into_inner().unwrap();

        unpack_in(&bytes[..], &dest, &dest, 0, None, &[], false).unwrap();

        let meta = |p: &str| fs::symlink_metadata(dest.join(p)).unwrap();
        let dir = meta("dir");
        assert_eq!((dir.uid(), dir.gid(), dir.mode() & 0o777), (1234, 1235, 0o750));
        let pem = meta("dir/owned.pem");
        assert_eq!((pem.uid(), pem.gid(), pem.mode() & 0o777), (1234, 1235, 0o600));
        assert_eq!(fs::read(dest.join("dir/owned.pem")).unwrap(), b"key");
        let link = meta("link");
        assert!(link.file_type().is_symlink());
        assert_eq!((link.uid(), link.gid()), (1234, 1235));
        let replaced = meta("replaced");
        assert!(replaced.file_type().is_file());
        assert_eq!((replaced.uid(), replaced.gid(), replaced.mode() & 0o777), (1234, 1235, 0o640));
        assert_eq!(fs::read(dest.join("replaced")).unwrap(), b"new");
        let target = meta("target");
        assert_eq!((target.uid(), target.gid()), (0, 0));
        assert_eq!(fs::read(dest.join("target")).unwrap(), b"stay");

        unpack_in(&bytes[..], &dest, &dest, 0, Some((2375, 2376)), &[], false).unwrap();
        assert_eq!((meta("dir").uid(), meta("dir").gid()), (2375, 2376));
        assert_eq!((meta("dir/owned.pem").uid(), meta("dir/owned.pem").gid(), meta("dir/owned.pem").mode() & 0o777), (2375, 2376, 0o600));
        assert_eq!((meta("link").uid(), meta("link").gid()), (2375, 2376));
        assert_eq!((meta("target").uid(), meta("target").gid()), (0, 0));

        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn resolve_copy_user_matches_moby_get_uid_gid() {
        let root = std::env::temp_dir().join(format!("kiri-copy-user-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::write(root.join("etc/passwd"), "root:x:0:0:root:/root:/bin/sh\ntestuser:x:2375:2376::/home/testuser:/bin/sh\n").unwrap();
        fs::write(root.join("etc/group"), "root:x:0:\ntestgroup:x:2376:\n").unwrap();

        for (spec, want) in [
            ("7777:", (7777, 0)),
            (":7777", (0, 7777)),
            ("2375", (2375, 2376)),
            ("7777", (7777, 0)),
            ("2375:2376", (2375, 2376)),
            ("testuser:testgroup", (2375, 2376)),
            ("testuser", (2375, 2376)),
            ("testuser:7777", (2375, 7777)),
            ("7777:testgroup", (7777, 2376)),
        ] {
            assert_eq!(resolve_copy_user_in(&root, spec).unwrap(), want, "{spec}");
        }
        assert!(resolve_copy_user_in(&root, "nosuchuser").is_err());
        assert!(resolve_copy_user_in(&root, "testuser:nosuchgroup").is_err());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn only_an_untouched_root_marker_is_skipped_by_diff_and_commit() {
        use std::os::unix::fs::PermissionsExt;

        let p = std::path::Path::new;
        assert!(is_marker_attr(p(".dockerenv"), true, 0, 0o100755, 0, 0));
        assert!(!is_marker_attr(p("sub/.dockerenv"), true, 0, 0o100755, 0, 0));
        assert!(!is_marker_attr(p("added"), true, 0, 0o100755, 0, 0));
        assert!(!is_marker_attr(p(".dockerenv"), false, 0, 0o120755, 0, 0));
        assert!(!is_marker_attr(p(".dockerenv"), true, 2, 0o100755, 0, 0));
        // `chmod 600 /.dockerenv`, `rm && touch` (0644), or special mode bits.
        assert!(!is_marker_attr(p(".dockerenv"), true, 0, 0o100600, 0, 0));
        assert!(!is_marker_attr(p(".dockerenv"), true, 0, 0o100644, 0, 0));
        assert!(!is_marker_attr(p(".dockerenv"), true, 0, 0o101755, 0, 0));
        assert!(!is_marker_attr(p(".dockerenv"), true, 0, 0o104755, 0, 0));
        // `chown 1000:1000 /.dockerenv` (or uid-only / gid-only changes).
        assert!(!is_marker_attr(p(".dockerenv"), true, 0, 0o100755, 1000, 0));
        assert!(!is_marker_attr(p(".dockerenv"), true, 0, 0o100755, 0, 1000));
        assert!(!is_marker_attr(p(".dockerenv"), true, 0, 0o100755, 1000, 1000));

        let base = std::env::temp_dir().join(format!("kiri-copy-marker-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("sub")).unwrap();
        let meta = |rel: &str| fs::symlink_metadata(base.join(rel)).unwrap();

        fs::write(base.join(".dockerenv"), b"").unwrap();
        fs::set_permissions(base.join(".dockerenv"), fs::Permissions::from_mode(0o755)).unwrap();
        let m = meta(".dockerenv");
        assert_eq!(is_marker(p(".dockerenv"), &m), m.uid() == 0 && m.gid() == 0);
        assert!(!is_marker(p("sub/.dockerenv"), &m));
        assert!(!is_marker(p("added"), &m));

        fs::set_permissions(base.join(".dockerenv"), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!is_marker(p(".dockerenv"), &meta(".dockerenv")));

        fs::set_permissions(base.join(".dockerenv"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(base.join(".dockerenv"), b"hi").unwrap();
        assert!(!is_marker(p(".dockerenv"), &meta(".dockerenv")));

        fs::remove_file(base.join(".dockerenv")).unwrap();
        std::os::unix::fs::symlink("/outside", base.join(".dockerenv")).unwrap();
        assert!(!is_marker(p(".dockerenv"), &meta(".dockerenv")));

        fs::remove_file(base.join(".dockerenv")).unwrap();
        fs::create_dir(base.join(".dockerenv")).unwrap();
        assert!(!is_marker(p(".dockerenv"), &meta(".dockerenv")));

        // Truncating an image-provided `/.dockerenv` to 0 bytes leaves an empty
        // `0755 0:0` file in `upper`, which must not be skipped when a lower
        // layer already has `/.dockerenv`.
        let lower_clean = base.join("lower-clean");
        let lower_image = base.join("lower-image");
        fs::create_dir_all(&lower_clean).unwrap();
        fs::create_dir_all(&lower_image).unwrap();
        fs::write(lower_image.join(".dockerenv"), b"from-image\n").unwrap();
        let open_dir = |dir: &std::path::Path| {
            let c = sys::cstr(dir).unwrap();
            // SAFETY: plain open of a temp directory we just created.
            let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
            assert!(fd >= 0);
            // SAFETY: fresh descriptor.
            unsafe { OwnedFd::from_raw_fd(fd) }
        };
        let clean_lowers = [open_dir(&lower_clean)];
        let image_lowers = [open_dir(&lower_image)];
        assert!(!in_lower_layers(&clean_lowers, p(".dockerenv")));
        assert!(in_lower_layers(&image_lowers, p(".dockerenv")));
        let skip = |lowers: &[OwnedFd]| is_marker_attr(p(".dockerenv"), true, 0, 0o100755, 0, 0) && !in_lower_layers(lowers, p(".dockerenv"));
        assert!(skip(&clean_lowers));
        assert!(!skip(&image_lowers));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn parse_mount_access_sorts_parents_first_and_tracks_ro_and_tmpfs() {
        let mut buf = Vec::new();
        kiri_proto::encode_copy(
            &mut buf,
            copy_op::IN,
            "c1",
            "/",
            0,
            &["sha256:a"],
            &[
                "/v/sub\t/app/sub/\tro",
                "/v/app\t/app\tcreate,copyup",
                "tmpfs\t/tmp\ttmpfs,noexec,ro",
                "tmpfs\t/run\ttmpfs,ro,rw",
            ],
        );
        let Msg::Copy(spec) = kiri_proto::decode(&buf).unwrap() else { panic!() };
        let got = parse_mount_access(spec.mounts).unwrap();
        assert_eq!(
            got,
            [
                MountAccess { target: PathBuf::from("/app"), ro: false, tmpfs: false },
                MountAccess { target: PathBuf::from("/tmp"), ro: true, tmpfs: true },
                MountAccess { target: PathBuf::from("/run"), ro: false, tmpfs: true },
                MountAccess { target: PathBuf::from("/app/sub"), ro: true, tmpfs: false },
            ]
        );
        let mut bad = Vec::new();
        kiri_proto::encode_copy(&mut bad, copy_op::IN, "c1", "/", 0, &[], &["/src\t../escape\tro"]);
        let Msg::Copy(bad_spec) = kiri_proto::decode(&bad).unwrap() else { panic!() };
        assert!(parse_mount_access(bad_spec.mounts).is_err());
    }

    #[test]
    fn check_writable_enforces_innermost_mount_and_readonly_rootfs() {
        let m = |target: &str, ro: bool| MountAccess { target: PathBuf::from(target), ro, tmpfs: false };
        let mounts = [m("/app", false), m("/app/ro", true), m("/app/ro/rw", false), m("/ro", true)];
        let err = |p: &str, ro_root: bool| check_writable(Path::new(p), &mounts, ro_root).unwrap_err().to_string();

        assert_eq!(err("/ro", false), "forbidden: mounted volume is marked read-only");
        assert_eq!(err("/ro/sub/f", false), "forbidden: mounted volume is marked read-only");
        assert_eq!(err("/app/ro", false), "forbidden: mounted volume is marked read-only");
        assert_eq!(err("/app/ro/file", false), "forbidden: mounted volume is marked read-only");
        // Component boundary: `/app/ro2` is under `/app` (rw), not `/app/ro`.
        assert!(check_writable(Path::new("/app/ro2/file"), &mounts, true).is_ok());
        // Writable nested mount inside a read-only mount succeeds.
        assert!(check_writable(Path::new("/app/ro/rw"), &mounts, true).is_ok());
        assert!(check_writable(Path::new("/app/ro/rw/x"), &mounts, true).is_ok());
        // Path outside every mount: refused iff `--read-only`.
        assert!(check_writable(Path::new("/etc"), &mounts, false).is_ok());
        assert_eq!(err("/etc", true), "forbidden: container rootfs is marked read-only");
        // Writable mount on a `--read-only` rootfs succeeds.
        assert!(check_writable(Path::new("/app/file"), &mounts, true).is_ok());
        // `:ro` mount on a `--read-only` rootfs reports the mounted volume error.
        assert_eq!(err("/ro/x", true), "forbidden: mounted volume is marked read-only");
    }

    #[test]
    fn unpack_in_refuses_ro_mounts_and_overwrites_file_mounts_in_place() {
        let base = std::env::temp_dir().join(format!("kiri-copy-ro-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let root = base.join("root");
        fs::create_dir_all(root.join("ro")).unwrap();
        fs::create_dir_all(root.join("rw")).unwrap();
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::write(root.join("etc/app.conf"), b"old").unwrap();
        fs::write(root.join("etc/ro.conf"), b"stay").unwrap();
        std::os::unix::fs::symlink(root.join("etc"), root.join("rw/to_etc")).unwrap();
        let canonical_root = fs::canonicalize(&root).unwrap();
        let mounts = [
            MountAccess { target: canonical_root.join("ro"), ro: true, tmpfs: false },
            MountAccess { target: canonical_root.join("rw"), ro: false, tmpfs: false },
            MountAccess { target: canonical_root.join("etc/app.conf"), ro: false, tmpfs: false },
            MountAccess { target: canonical_root.join("etc/ro.conf"), ro: true, tmpfs: false },
        ];
        let tar_file = |name: &str, data: &[u8]| {
            let mut b = tar::Builder::new(Vec::new());
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Regular);
            h.set_size(data.len() as u64);
            h.set_mode(0o640);
            h.set_mtime(0);
            h.set_cksum();
            b.append_data(&mut h, name, data).unwrap();
            b.into_inner().unwrap()
        };

        // Entry targeting a `:ro` file bind mount is refused before writing.
        let bytes = tar_file("ro.conf", b"pwn");
        let err = unpack_in(&bytes[..], &canonical_root.join("etc"), &canonical_root.join("etc"), 0, None, &mounts, false).unwrap_err();
        assert_eq!(err.to_string(), "forbidden: mounted volume is marked read-only");
        assert_eq!(fs::read(canonical_root.join("etc/ro.conf")).unwrap(), b"stay");

        // Entry escaping a `:rw` volume through a symlink to a `--read-only` rootfs is refused.
        let bytes = tar_file("to_etc/pwn", b"bad");
        let err = unpack_in(&bytes[..], &canonical_root.join("rw"), &canonical_root.join("rw"), 0, None, &mounts, true).unwrap_err();
        assert_eq!(err.to_string(), "forbidden: container rootfs is marked read-only");
        assert!(!canonical_root.join("etc/pwn").exists());

        // Entry targeting a `:rw` file bind mount overwrites in place (keeping inode and zero mtime).
        let before_ino = fs::symlink_metadata(canonical_root.join("etc/app.conf")).unwrap().ino();
        let bytes = tar_file("app.conf", b"updated");
        unpack_in(&bytes[..], &canonical_root.join("etc"), &canonical_root.join("etc"), 0, None, &mounts, false).unwrap();
        let after = fs::symlink_metadata(canonical_root.join("etc/app.conf")).unwrap();
        assert_eq!(after.ino(), before_ino, "file bind mount must be overwritten in place, not unlinked");
        assert_eq!(fs::read(canonical_root.join("etc/app.conf")).unwrap(), b"updated");
        assert_eq!(after.mtime(), 0);
        assert_eq!(after.mode() & 0o777, 0o640);

        let _ = fs::remove_dir_all(&base);
    }
}
