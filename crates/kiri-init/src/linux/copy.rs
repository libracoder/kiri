//! `docker cp`: files into and out of containers, one vsock connection per
//! copy. Each copy runs in a forked child, so a large archive never stalls
//! the event loop. The child chroots into the container (its live root, or a
//! private mount of its layers when it is not running), so links resolve
//! inside the container and nothing outside it is reachable.
//!
//! A stopped container's root is mounted by the agent, not the child: the
//! child asks for it over a socket pair of its own, so a copy and a start at
//! the same moment share one mount (see `roots`, #227).

use std::fs;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};

use kiri_proto::{COPY_PORT, CopySpec, FsEntry, Msg, copy_flags, copy_op};

use std::cell::RefCell;
use std::path::PathBuf;

use super::container::Paths;
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
            if let Err(e) = enter(&spec, running, paths, &chan) {
                return reply_error(&mut conn, &format!("container {}: {e}", spec.id));
            }
            match spec.op {
                copy_op::IN => copy_in(&mut conn, &spec),
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

/// Makes the container's root this process's `/`.
fn enter(spec: &CopySpec<'_>, running: &[(&str, libc::pid_t)], paths: &Paths, chan: &OwnedFd) -> io::Result<()> {
    let root = match running.iter().find(|(id, _)| *id == spec.id) {
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
            paths.containers.join(spec.id).join("rootfs")
        }
        // Through /proc the root shows the container's mounts (volumes) too.
        // The copy holds the container's root meanwhile, so a restart can't
        // mount a second one over the same layer while it still writes.
        Some((_, pid)) => {
            let _ = ask(chan, 'h', spec);
            std::path::PathBuf::from(format!("/proc/{pid}/root"))
        }
        None => {
            if spec.layers.is_empty() {
                return Err(io::Error::new(io::ErrorKind::NotFound, "no such container"));
            }
            ask(chan, 'm', spec)?;
            paths.containers.join(spec.id).join("rootfs")
        }
    };
    let c = sys::cstr(&root)?;
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

/// Unpacks the archive that follows into `spec.path`, a directory.
fn copy_in(conn: &mut fs::File, spec: &CopySpec<'_>) -> io::Result<()> {
    let dest = std::path::Path::new(spec.path);
    match fs::metadata(dest) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("notdir: extraction point is not a directory: {}", spec.path))),
        Err(_) => return Err(io::Error::new(io::ErrorKind::NotFound, format!("notfound: Could not find the file {} in container {}", spec.path, spec.id))),
    }
    let source: Box<dyn Read + '_> = if spec.flags & copy_flags::CHUNKED != 0 { Box::new(Chunks::new(&mut *conn)) } else { Box::new(&mut *conn) };
    let mut reader = BufReader::with_capacity(256 * 1024, source);
    {
        let mut archive = tar::Archive::new(&mut reader);
        archive.set_preserve_permissions(true);
        archive.set_preserve_mtime(true);
        archive.set_preserve_ownerships(spec.flags & copy_flags::KEEP_OWNERS != 0);
        archive.set_unpack_xattrs(false);
        archive.set_overwrite(true);
        for entry in archive.entries()? {
            let mut entry = entry?;
            if spec.flags & copy_flags::NO_OVERWRITE_DIR_NON_DIR != 0 {
                let target = dest.join(entry.path()?);
                if let Ok(m) = fs::symlink_metadata(&target) {
                    if m.is_dir() != entry.header().entry_type().is_dir() {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            format!("cannot overwrite {} {} with {}", if m.is_dir() { "directory" } else { "non-directory" }, target.display(), if m.is_dir() { "non-directory" } else { "directory" }),
                        ));
                    }
                }
            }
            entry.unpack_in(dest)?;
        }
    }
    // The archive's trailing padding: read it so the host's writes complete.
    io::copy(&mut reader, &mut io::sink())?;
    drop(reader);
    let mut out = Vec::new();
    Msg::CopyDone.encode(&mut out);
    conn.write_all(&out)
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
        if meta.is_dir() && src != std::path::Path::new("/proc") && src != std::path::Path::new("/sys") {
            let mut children: Vec<_> = fs::read_dir(&src)?.flatten().collect();
            children.sort_by_key(|e| e.file_name());
            for e in children.into_iter().rev() {
                stack.push((e.path(), name.join(e.file_name())));
            }
        }
    }
    Ok(())
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
        let mut f = fs::File::open(src)?;
        if verbatim {
            return append_contents(b, &mut h, name, None, &mut f);
        }
        return b.append_data(&mut h, name, &mut f);
    }
    if ft.is_dir() || ft.is_symlink() || ft.is_fifo() || ft.is_char_device() || ft.is_block_device() {
        let mut h = tar::Header::new_gnu();
        h.set_metadata(meta);
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
    // A running container writes its upper layer while we walk it, and could
    // swap a directory for a link to `/` between our look and our read
    // (`docker diff`, `commit --pause=false`). Inside a chroot of the layer
    // that link leads back into the layer, as `enter` does for the others.
    let c = sys::cstr(&paths.containers.join(spec.id).join("upper"))?;
    // SAFETY: valid NUL-terminated paths.
    unsafe {
        sys::check(libc::chroot(c.as_ptr()) as _, "chroot")?;
        sys::check(libc::chdir(c"/".as_ptr()) as _, "chdir")?;
    }
    let upper = std::path::PathBuf::from("/");
    // Every path in the writable layer, parents first.
    let mut entries: Vec<(std::path::PathBuf, fs::Metadata)> = Vec::new();
    let mut stack = vec![std::path::PathBuf::new()];
    while let Some(rel) = stack.pop() {
        let dir = upper.join(&rel);
        let Ok(list) = fs::read_dir(&dir) else { continue };
        let mut names: Vec<_> = list.flatten().collect();
        names.sort_by_key(|e| e.file_name());
        for e in names.into_iter().rev() {
            let r = rel.join(e.file_name());
            let Ok(m) = fs::symlink_metadata(e.path()) else { continue };
            if m.is_dir() {
                stack.push(r.clone());
            }
            entries.push((r, m));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    done(conn)?;
    if spec.op == copy_op::DIFF {
        let in_lower = |rel: &std::path::Path| {
            for l in &lowers {
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
        };
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
        for (path, name) in [("/t/dir/sub/..", ".."), ("/t/dir/sub/../", ".."), ("/t/dir/.", "."), ("/t/dir/", "dir"), ("/", "/"), ("//", "/")] {
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
}
