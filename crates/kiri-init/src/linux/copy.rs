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
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};

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
        copy_op::STEP_LAYER => step_layer(&mut conn, &spec, paths),
        copy_op::STEP_ADOPT => step_adopt(&mut conn, &spec, paths),
        copy_op::LAYER_DELTA => layer_delta(&mut conn, &spec, paths),
        copy_op::LAYER_UNPACK => layer_unpack(&mut conn, &spec, paths),
        copy_op::LAYER_XATTRS => layer_xattrs(&mut conn, &spec, paths),
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
                // What is there now, looked up inside `dest` as the tar crate
                // places the entry (a leading `/` dropped, no link followed on
                // the way), never `dest.join(name)`: an absolute name would be
                // a path outside it.
                let target = dest.join(entry.path()?.components().filter(|c| matches!(c, std::path::Component::Normal(_))).collect::<std::path::PathBuf>());
                if let Some(is_dir) = existing_is_dir(dest, &entry.path()?) {
                    if is_dir != entry.header().entry_type().is_dir() {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            format!("cannot overwrite {} {} with {}", if is_dir { "directory" } else { "non-directory" }, target.display(), if is_dir { "non-directory" } else { "directory" }),
                        ));
                    }
                }
            }
            let path = entry.path()?.into_owned();
            // `docker cp` and the classic build's context keep a time of 0.
            if entry.unpack_in(dest)? {
                super::layers::keep_zero_time(dest, &path, entry.header())?;
            }
        }
    }
    // The archive's trailing padding: read it so the host's writes complete.
    io::copy(&mut reader, &mut io::sink())?;
    drop(reader);
    let mut out = Vec::new();
    Msg::CopyDone.encode(&mut out);
    conn.write_all(&out)
}

/// Whether what an archive entry named `path` would replace inside `dest`
/// is a folder: None when nothing is there, or the way there is not plain
/// folders (a link, `..`: the tar crate's unpack refuses those itself).
fn existing_is_dir(dest: &std::path::Path, path: &std::path::Path) -> Option<bool> {
    let root = super::inroot::open_root(dest).ok()?;
    let (dir, name) = super::inroot::parent_strict(root.as_fd(), path).ok()?;
    // SAFETY: fstatat of one name under a valid descriptor, not following it, into a zeroed stat.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstatat(dir.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } == 0).then_some(st.st_mode & libc::S_IFMT == libc::S_IFDIR)
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
    let path = std::path::Path::new(spec.path);
    let meta = fs::symlink_metadata(path)
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, format!("notfound: Could not find the file {} in container {}", spec.path, spec.id)))?;
    let link = if meta.file_type().is_symlink() { fs::read_link(path)?.to_string_lossy().into_owned() } else { String::new() };
    let name = path.file_name().map_or_else(|| "/".to_owned(), |n| n.to_string_lossy().into_owned());
    let entry = FsEntry {
        name: &name,
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
        // The root itself archives as its contents under ".".
        let top = if name == "/" { "." } else { name.as_str() };
        if meta.is_dir() {
            append_tree(&mut b, path, std::path::Path::new(top))?;
        } else {
            append_one(&mut b, path, std::path::Path::new(top), &meta)?;
        }
        b.finish()?;
    }
    w.flush()
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
    if ft.is_file() {
        let mut h = tar::Header::new_gnu();
        h.set_metadata(meta);
        h.set_mode(mode_bits(meta));
        // Not followed and never waited on: a running container can swap
        // the file for a link or a FIFO between the look above and here.
        let mut f = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY).open(src)?;
        if !f.metadata()?.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{} changed while it was copied", src.display())));
        }
        return b.append_data(&mut h, name, &mut f);
    }
    if ft.is_dir() || ft.is_symlink() || ft.is_fifo() || ft.is_char_device() || ft.is_block_device() {
        let mut h = tar::Header::new_gnu();
        h.set_metadata(meta);
        h.set_mode(mode_bits(meta));
        h.set_size(0);
        if ft.is_symlink() {
            return b.append_link(&mut h, name, fs::read_link(src)?);
        }
        if ft.is_char_device() || ft.is_block_device() {
            let rdev = meta.rdev();
            h.set_device_major(libc::major(rdev))?;
            h.set_device_minor(libc::minor(rdev))?;
        }
        return b.append_data(&mut h, name, io::empty());
    }
    Ok(())
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

/// A build step's layer (`copy_op::STEP_LAYER`), from its upper folder.
/// The layers below are seen as one tree: the layer itself when there is
/// one, else a read-only overlay of them mounted in this child's own mount
/// namespace, gone with the child.
fn step_layer(conn: &mut fs::File, spec: &CopySpec<'_>, paths: &Paths) -> io::Result<()> {
    super::container::valid_id(spec.id)?;
    let base_dir = paths.containers.join(spec.id);
    let upper = base_dir.join("upper");
    if !upper.is_dir() {
        return reply_error(conn, &format!("step {} has no writable layer", spec.id));
    }
    let mut lowers: Vec<&str> = Vec::new();
    for d in spec.layers.iter() {
        if !super::layers::present(&paths.layers, d) {
            return reply_error(conn, &format!("layer {d} is not unpacked"));
        }
        let h = super::layers::hex(d)?;
        // As mount_rootfs: overlayfs refuses a folder listed twice.
        if !lowers.contains(&h) {
            lowers.push(h);
        }
    }
    let base = match lowers.len() {
        0 => None,
        1 => Some(super::stepdiff::Base::open(&paths.layers.join(lowers[0]))?),
        _ => {
            let below = base_dir.join("below");
            fs::create_dir_all(&below)?;
            // SAFETY: plain syscalls on this child alone.
            unsafe {
                sys::check(libc::unshare(libc::CLONE_NEWNS) as _, "unshare")?;
            }
            sys::mount(c"none", c"/", c"", libc::MS_REC | libc::MS_PRIVATE, None)?;
            // Relative to the layer store, as mount_rootfs keeps the option short.
            std::env::set_current_dir(&paths.layers)?;
            let lowers: Vec<String> = lowers.iter().map(|l| l.to_string()).collect();
            sys::mount_overlay(&below, &lowers, ",index=off,redirect_dir=nofollow,metacopy=off", libc::MS_RDONLY)?;
            Some(super::stepdiff::Base::open(&below)?)
        }
    };
    done(conn)?;
    let written = {
        let mut out = BufWriter::with_capacity(256 * 1024, ChunkWriter(&mut *conn));
        // The step's mount targets, one per line (see copy_op::STEP_LAYER).
        let mounts: Vec<&[u8]> = spec.path.as_bytes().split(|b| *b == b'\n').filter(|m| !m.is_empty() && *m != b"/").collect();
        // And what Rosetta made, when it ran the step's program.
        let rosetta = super::rosetta::marked(&base_dir);
        super::stepdiff::write_step(&upper, base.as_ref(), &mounts, rosetta, &mut out).and_then(|stubs| {
            out.flush()?;
            // The upper may become the layer itself (STEP_ADOPT): it must
            // hold what the tar holds, so the runtime's stubs go from it too.
            stubs.clean(&upper)?;
            stubs.folder_times(&upper)
        })
    };
    // The tar's last chunk, then the folder times as chunks of their own.
    conn.write_all(&0u32.to_le_bytes())?;
    match written {
        Ok(times) => {
            ChunkWriter(&mut *conn).write_all(&times)?;
            conn.write_all(&0u32.to_le_bytes())?;
            done(conn)
        }
        Err(e) => {
            conn.write_all(&0u32.to_le_bytes())?;
            reply_error(conn, &e.to_string())
        }
    }
}

/// A finished step's writable folder becomes the unpacked layer `spec.path`
/// (its digest) in place, so the next step on it needs no unpack
/// (`copy_op::STEP_ADOPT`). The layer store's own install: its files reach
/// the disk, then it is renamed in, then marked whole.
fn step_adopt(conn: &mut fs::File, spec: &CopySpec<'_>, paths: &Paths) -> io::Result<()> {
    super::container::valid_id(spec.id)?;
    let upper = paths.containers.join(spec.id).join("upper");
    if !upper.is_dir() {
        return reply_error(conn, &format!("step {} has no writable layer", spec.id));
    }
    super::layers::adopt(&paths.layers, spec.path, &upper)?;
    done(conn)
}

/// `copy_op::LAYER_XATTRS`: xattrs on the unpacked layer's files, each
/// looked up inside the layer, a link never followed.
fn layer_xattrs(conn: &mut fs::File, spec: &CopySpec<'_>, paths: &Paths) -> io::Result<()> {
    if !super::layers::present(&paths.layers, spec.path) {
        return reply_error(conn, &format!("layer {} is not unpacked", spec.path));
    }
    match set_layer_xattrs(&super::layers::dir(&paths.layers, spec.path)?, spec.layers.iter()) {
        Ok(()) => done(conn),
        Err(e) => reply_error(conn, &e),
    }
}

/// `path\tname\thex value` lines onto the tree at `dir`. A name the layer
/// unpacker would not set from an archive (`layers::xattr_from_input`:
/// `trusted.*`) is left out here too.
fn set_layer_xattrs<'a>(dir: &std::path::Path, lines: impl Iterator<Item = &'a str>) -> Result<(), String> {
    let root = super::inroot::open_root(dir).map_err(|e| e.to_string())?;
    for line in lines {
        let mut f = line.splitn(3, '\t');
        let (Some(rel), Some(name), Some(hex)) = (f.next(), f.next(), f.next()) else {
            return Err("bad xattr line".into());
        };
        let value: Option<Vec<u8>> = (0..hex.len()).step_by(2).map(|i| hex.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok())).collect();
        let (Some(value), Ok(cname)) = (value, std::ffi::CString::new(name)) else {
            return Err("bad xattr line".into());
        };
        if !super::layers::xattr_from_input(name.as_bytes()) {
            continue;
        }
        let at = match super::inroot::lookup(root.as_fd(), std::path::Path::new(rel)) {
            Ok(fd) => super::inroot::Found { fd, created: false },
            Err(e) => return Err(format!("{rel}: {e}")),
        };
        // SAFETY: a valid NUL-terminated path (the descriptor's magic link), name and value.
        if unsafe { libc::setxattr(at.proc_path().as_ptr(), cname.as_ptr(), value.as_ptr().cast(), value.len(), 0) } != 0 {
            return Err(format!("{rel}: {}", io::Error::last_os_error()));
        }
    }
    Ok(())
}

/// `copy_op::LAYER_UNPACK`: a layer unpacked as its blob arrives, kept
/// only once the host has checked its diff_id.
fn layer_unpack(conn: &mut fs::File, spec: &CopySpec<'_>, paths: &Paths) -> io::Result<()> {
    let Some((digest, media_type)) = spec.path.split_once('\n') else {
        return reply_error(conn, "a layer unpack names its digest and media type");
    };
    let mut chunks = Chunks::new(&mut *conn);
    if super::layers::present(&paths.layers, digest) {
        // Kept only once the host has compared the layer's identity with the
        // image's config, as for a fresh unpack: the diff_id its marker
        // records, or (an older marker records none) the blob's, read whole.
        let diff_id = match super::layers::recorded_diff_id(&paths.layers, digest) {
            Some(d) => io::copy(&mut chunks, &mut io::sink()).map(|_| d),
            None => super::layers::diff_id_of(&mut chunks, digest, media_type),
        };
        io::copy(&mut chunks, &mut io::sink())?;
        let diff_id = match diff_id {
            Ok(d) => d,
            Err(e) => return reply_error(conn, &e.to_string()),
        };
        done(conn)?;
        conn.write_all(format!("{diff_id}\n").as_bytes())?;
        let mut answer = [0u8; 1];
        if conn.read_exact(&mut answer).is_ok() && answer[0] == b'y' {
            let _ = super::layers::record_diff_id(&paths.layers, digest, &diff_id);
            return done(conn);
        }
        return reply_error(conn, "dropped: the layer's diff_id is not the image's");
    }
    let unpacked = super::layers::unpack_streamed(&mut chunks, digest, media_type, &paths.layers);
    // Whatever happened, the rest of the blob is read, so the answer lines
    // up; a host that went away leaves nothing behind.
    if let Err(e) = io::copy(&mut chunks, &mut io::sink()) {
        if let Ok((_, folder, _)) = &unpacked {
            let _ = super::rmtree::remove_all(folder);
        }
        return Err(e);
    }
    let (diff_id, folder) = match unpacked {
        Ok((d, f, _)) => (d, f),
        Err(e) => return reply_error(conn, &e.to_string()),
    };
    done(conn)?;
    conn.write_all(format!("{diff_id}\n").as_bytes())?;
    let mut answer = [0u8; 1];
    let keep = conn.read_exact(&mut answer).is_ok() && answer[0] == b'y';
    if !keep {
        let _ = super::rmtree::remove_all(&folder);
        return reply_error(conn, "dropped: the layer's diff_id is not the image's");
    }
    match super::layers::keep(&paths.layers, digest, &folder, &diff_id) {
        Ok(()) => done(conn),
        Err(e) => {
            let _ = super::rmtree::remove_all(&folder);
            reply_error(conn, &e.to_string())
        }
    }
}

/// `copy_op::LAYER_DELTA`: the new layer from the base the guest has and
/// the delta that follows.
fn layer_delta(conn: &mut fs::File, spec: &CopySpec<'_>, paths: &Paths) -> io::Result<()> {
    let Some((base, new)) = spec.path.split_once('\n') else {
        return reply_error(conn, "a layer delta names its base and its new layer");
    };
    let removed: Vec<&str> = spec.layers.iter().collect();
    let mut chunks = Chunks::new(&mut *conn);
    let made = super::layers::receive_delta(&mut chunks, base, new, &removed, &paths.layers);
    match made {
        Ok(_) => done(conn),
        Err(e) => reply_error(conn, &e.to_string()),
    }
}

/// Writes each buffer as one `len: u32 LE | bytes` chunk (see `Chunks`).
struct ChunkWriter<'a>(&'a mut fs::File);

impl Write for ChunkWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min(u32::MAX as usize);
        self.0.write_all(&(n as u32).to_le_bytes())?;
        self.0.write_all(&buf[..n])?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
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
    fn chunks_end_at_the_empty_chunk_and_leave_the_rest() {
        let wire = [&3u32.to_le_bytes()[..], b"abc", &2u32.to_le_bytes(), b"de", &0u32.to_le_bytes(), b"after"].concat();
        let mut conn = &wire[..];
        let mut got = Vec::new();
        Chunks::new(&mut conn).read_to_end(&mut got).unwrap();
        assert_eq!(got, b"abcde");
        assert_eq!(conn, b"after");
    }

    /// A COPY's xattrs set on a layer (`LAYER_XATTRS`) follow the layer
    /// unpacker's rule: `trusted.*` (an overlay opaque mark, a redirect) is
    /// never set from input; `user.*` is. Run as root (trusted.* needs it),
    /// or it checks nothing about them.
    #[test]
    fn layer_xattrs_never_set_trusted_names() {
        let d = std::env::temp_dir().join(format!("kiri-copy-xattrs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("dir")).unwrap();
        fs::write(d.join("f"), "").unwrap();
        let lines = ["dir\ttrusted.overlay.opaque\t79", "f\ttrusted.overlay.metacopy\t", "dir\ttrusted.overlay.redirect\t2f657463", "f\tuser.kept\t31"];
        set_layer_xattrs(&d, lines.iter().copied()).unwrap();
        let get = |p: &str, n: &std::ffi::CStr| {
            let c = std::ffi::CString::new(d.join(p).as_os_str().as_encoded_bytes()).unwrap();
            let mut v = [0u8; 16];
            // SAFETY: valid strings, a buffer of that length.
            let n = unsafe { libc::lgetxattr(c.as_ptr(), n.as_ptr(), v.as_mut_ptr().cast(), v.len()) };
            (n >= 0).then(|| v[..n as usize].to_vec())
        };
        assert_eq!(get("dir", c"trusted.overlay.opaque"), None);
        assert_eq!(get("dir", c"trusted.overlay.redirect"), None);
        assert_eq!(get("f", c"trusted.overlay.metacopy"), None);
        assert_eq!(get("f", c"user.kept"), Some(b"1".to_vec()));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn chunks_cut_short_are_an_error() {
        let wire = [&5u32.to_le_bytes()[..], b"ab"].concat();
        let err = Chunks::new(&wire[..]).read_to_end(&mut Vec::new()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
