//! A build step's ssh agent socket (`RUN --mount=type=ssh`): a socket made
//! with the mount's owner and mode, bound at the target in that step's own
//! mount namespace, that relays each connection to the host with the step's
//! token (`kiri_proto::BUILD_SSH_PORT`). The host relays it on to the agent
//! the build's client handed over; nothing here ever sees a key or a path
//! of the client's.
//!
//! The socket is served by a child forked from the agent (which must stay
//! single-threaded; the child may use threads). The child holds nothing of
//! the agent's but the listener and the pipe it waits on: when the agent
//! closes its end of that pipe (the step's process exited, its start
//! failed, or the step was removed: [`forget`]), the child exits and every
//! connection it relays ends with it.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use super::sys;

thread_local! {
    /// The agent's end of each child's pipe, by step id.
    static ALIVE: RefCell<HashMap<String, Vec<OwnedFd>>> = RefCell::new(HashMap::new());
}

/// A step token as the host makes one: 32 hex digits.
fn valid_token(t: &str) -> bool {
    t.len() == 32 && t.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Makes `<dir>/s` owned `uid:gid` with `mode`, on a tmpfs of its own at
/// `dir`, and forks the child that relays it for step `id` with `token`.
/// Returns the socket's path, for the step's bind.
pub fn start(id: &str, dir: &Path, token: &str, uid: u32, gid: u32, mode: u32) -> io::Result<PathBuf> {
    if !valid_token(token) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad ssh token"));
    }
    std::fs::create_dir_all(dir)?;
    sys::mount(c"tmpfs", &sys::cstr(dir)?, c"tmpfs", libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, Some(c"mode=0700,size=64k"))?;
    let socket = dir.join("s");
    // Bound through the folder's descriptor: a step's folder can be longer
    // than a socket address holds.
    let d = std::fs::File::open(dir)?;
    let listener = UnixListener::bind(format!("/proc/self/fd/{}/s", d.as_raw_fd()))?;
    drop(d);
    let c = sys::cstr(&socket)?;
    // SAFETY: valid NUL-terminated path; plain ownership and mode calls.
    unsafe {
        sys::check(libc::chown(c.as_ptr(), uid, gid) as _, "ssh socket owner")?;
        sys::check(libc::chmod(c.as_ptr(), (mode & 0o7777) as libc::mode_t) as _, "ssh socket mode")?;
    }
    let (r, w) = pipe()?;
    // the child says on this whether it closed the agent's descriptors
    let (ready_r, ready_w) = pipe()?;
    let line = format!("{token}\n");
    let ranges = sys::close_ranges(&[listener.as_raw_fd(), r.as_raw_fd(), ready_w.as_raw_fd()]);
    // SAFETY: the agent is single-threaded, so the child is a consistent
    // copy; it closes everything but what it was given, then serves.
    match unsafe { libc::fork() } {
        0 => {
            drop(w);
            drop(ready_r);
            let ok = only_fds(&ranges);
            let b = [if ok { b'1' } else { b'0' }];
            // SAFETY: one byte to the parent on a pipe this child holds.
            unsafe { libc::write(ready_w.as_raw_fd(), b.as_ptr().cast(), 1) };
            drop(ready_w);
            if !ok {
                // SAFETY: leaving the child; it never served.
                unsafe { libc::_exit(1) }
            }
            // The agent blocks SIGCHLD for its signalfd; the child takes
            // signals as a plain process does.
            // SAFETY: an empty set, applied to this thread.
            unsafe {
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
            }
            serve(&listener, &r, line.as_bytes(), std::sync::Arc::new(|| super::transport::dial_within(kiri_proto::BUILD_SSH_PORT, std::time::Duration::from_secs(5))));
            // SAFETY: leaving the child without the agent's destructors.
            unsafe { libc::_exit(0) }
        }
        pid if pid < 0 => Err(io::Error::last_os_error()),
        // The agent reaps the child like any other.
        _ => {
            drop(ready_w);
            // The mount fails unless the child holds nothing of the agent's.
            let mut b = [0u8; 1];
            let n = loop {
                // SAFETY: a read of one byte into a local buffer.
                let n = unsafe { libc::read(ready_r.as_raw_fd(), b.as_mut_ptr().cast(), 1) };
                if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break n;
            };
            if n != 1 || b[0] != b'1' {
                return Err(io::Error::other("the ssh relay could not close the agent's descriptors"));
            }
            ALIVE.with(|a| a.borrow_mut().entry(id.to_owned()).or_default().push(w));
            Ok(socket)
        }
    }
}

/// Ends step `id`'s relays: the step's process exited, its start failed,
/// or it was removed.
pub fn forget(id: &str) {
    ALIVE.with(|a| a.borrow_mut().remove(id));
}

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut p = [0; 2];
    // SAFETY: pipe2 fills two descriptors, owned immediately.
    sys::check(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) } as _, "pipe")?;
    // SAFETY: fresh descriptors from pipe2.
    Ok(unsafe { (OwnedFd::from_raw_fd(p[0]), OwnedFd::from_raw_fd(p[1])) })
}

/// Closes every descriptor above 2 in `ranges` (from `sys::close_ranges`,
/// made before the fork): the child must hold none of the agent's
/// (another container's pipes, the agent's own sockets). Without
/// close_range (before Linux 5.9) each one up to the highest open is
/// closed. False when that cannot be done or found: the caller then does
/// not serve.
fn only_fds(ranges: &[(libc::c_uint, libc::c_uint)]) -> bool {
    for &(first, last) in ranges {
        // SAFETY: closing descriptors of this process, which owns no Rust
        // object for them any more (the child never returns).
        if unsafe { libc::syscall(libc::SYS_close_range, first, last, 0) } == 0 {
            continue;
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS) {
            return false;
        }
        let Some(high) = highest_fd() else { return false };
        for fd in first..=last.min(high) {
            // SAFETY: as above; EBADF for one not open is fine.
            unsafe { libc::close(fd as RawFd) };
        }
    }
    true
}

/// The highest descriptor that may be open: from /proc/self/fd, else the
/// descriptor limit.
fn highest_fd() -> Option<libc::c_uint> {
    if let Ok(list) = std::fs::read_dir("/proc/self/fd") {
        return list.flatten().filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok())).max();
    }
    // SAFETY: getrlimit into a local struct.
    let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } != 0 || rl.rlim_cur == libc::RLIM_INFINITY {
        return None;
    }
    libc::c_uint::try_from(rl.rlim_cur).ok()
}

/// Connections relayed at once for one step, at most: each takes two
/// threads and a host connection. One past it is closed at once (an ssh
/// client then fails that connection, as with an agent that went away);
/// a build's ssh needs a few at a time.
const MAX_RELAYS: usize = 32;

/// The host connection for one relay.
type Dial = std::sync::Arc<dyn Fn() -> io::Result<OwnedFd> + Send + Sync>;

/// Each connection in a thread of its own, relayed through `dial` after
/// the token line, until `alive` reads EOF. In the child the caller exits
/// then, which ends every relay at once.
fn serve(listener: &UnixListener, alive: &OwnedFd, line: &[u8], dial: Dial) {
    serve_with(listener, alive, line, dial, &mut || listener.accept().map(|(c, _)| c));
}

/// [`serve`] with the accept given. An accept that fails for want of
/// descriptors or memory leaves the listener readable: the next one waits,
/// from 10 ms doubling to a second, still ending at once on `alive`.
fn serve_with(listener: &UnixListener, alive: &OwnedFd, line: &[u8], dial: Dial, accept: &mut dyn FnMut() -> io::Result<UnixStream>) {
    let line: std::sync::Arc<[u8]> = line.into();
    let live = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut pause = 0i32;
    loop {
        if pause > 0 {
            let mut a = libc::pollfd { fd: alive.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            // SAFETY: one pollfd we own.
            if unsafe { libc::poll(&mut a, 1, pause) } > 0 {
                return;
            }
        }
        let mut fds = [libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 }, libc::pollfd { fd: alive.as_raw_fd(), events: libc::POLLIN, revents: 0 }];
        // SAFETY: two pollfds we own.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if fds[1].revents != 0 {
            return;
        }
        if fds[0].revents & libc::POLLIN == 0 {
            continue;
        }
        let c = match accept() {
            Ok(c) => {
                pause = 0;
                c
            }
            Err(e) => {
                if matches!(e.raw_os_error(), Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)) {
                    pause = (pause * 2).clamp(10, 1000);
                }
                continue;
            }
        };
        use std::sync::atomic::Ordering;
        if live.fetch_add(1, Ordering::SeqCst) >= MAX_RELAYS {
            live.fetch_sub(1, Ordering::SeqCst);
            drop(c);
            continue;
        }
        let (dial, line, count) = (std::sync::Arc::clone(&dial), std::sync::Arc::clone(&line), std::sync::Arc::clone(&live));
        let spawned = std::thread::Builder::new().name("ssh-relay".into()).spawn(move || {
            if let Ok(host) = dial() {
                let _ = relay(c, UnixStream::from(host), &line);
            }
            count.fetch_sub(1, Ordering::SeqCst);
        });
        if spawned.is_err() {
            live.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// One connection: the token line to the host, then both ways until
/// either side closes.
fn relay(c: UnixStream, mut host: UnixStream, line: &[u8]) -> io::Result<()> {
    host.write_all(line)?;
    let (mut c2, mut host2) = (c.try_clone()?, host.try_clone()?);
    let up = std::thread::spawn(move || {
        let _ = io::copy(&mut c2, &mut host2);
        let _ = host2.shutdown(std::net::Shutdown::Write);
    });
    let (mut c, mut host) = (c, host);
    let _ = io::copy(&mut host, &mut c);
    let _ = c.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// Each connection to the step's socket reaches the host with the
    /// token first, and the bytes go both ways; once the pipe closes the
    /// socket is served no more.
    #[test]
    fn connections_carry_the_token_then_the_agent() {
        let dir = std::env::temp_dir().join(format!("kiri-stepssh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("s");
        let listener = UnixListener::bind(&sock).unwrap();
        let host = dir.join("host");
        let host_l = UnixListener::bind(&host).unwrap();
        let (r, w) = pipe().unwrap();
        let hp = host.clone();
        let server = std::thread::spawn(move || serve(&listener, &r, b"0123456789abcdef0123456789abcdef\n", std::sync::Arc::new(move || Ok(UnixStream::connect(&hp)?.into()))));
        let echo = std::thread::spawn(move || {
            let (mut c, _) = host_l.accept().unwrap();
            let mut first = [0; 33];
            c.read_exact(&mut first).unwrap();
            let mut rest = [0; 5];
            c.read_exact(&mut rest).unwrap();
            c.write_all(b"agent:").unwrap();
            c.write_all(&rest).unwrap();
            first
        });
        let mut c = UnixStream::connect(&sock).unwrap();
        c.write_all(b"hello").unwrap();
        c.shutdown(std::net::Shutdown::Write).unwrap();
        let mut got = Vec::new();
        c.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"agent:hello");
        assert_eq!(&echo.join().unwrap(), b"0123456789abcdef0123456789abcdef\n");
        drop(w);
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An accept that fails (out of descriptors) on a listener that
    /// stays readable backs off instead of spinning a core, and the pipe
    /// still ends the serving at once.
    #[test]
    fn a_failing_accept_backs_off() {
        let dir = std::env::temp_dir().join(format!("kiri-stepssh-emfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("s");
        let listener = UnixListener::bind(&sock).unwrap();
        // a connection that waits: the listener stays readable throughout
        let _pending = UnixStream::connect(&sock).unwrap();
        let (r, w) = pipe().unwrap();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counted = std::sync::Arc::clone(&calls);
        let server = std::thread::spawn(move || {
            let mut accept = || {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Err(io::Error::from_raw_os_error(libc::EMFILE))
            };
            serve_with(&listener, &r, b"t\n", std::sync::Arc::new(|| Err(io::Error::other("no host"))), &mut accept);
        });
        std::thread::sleep(std::time::Duration::from_millis(500));
        let n = calls.load(std::sync::atomic::Ordering::SeqCst);
        let t = std::time::Instant::now();
        drop(w);
        server.join().unwrap();
        assert!((1..30).contains(&n), "{n} accepts in 500 ms");
        assert!(t.elapsed() < std::time::Duration::from_secs(5), "the pipe ends a backing-off serve");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The relay child closes every descriptor but what it keeps, and
    /// says so; it does not carry on with the agent's descriptors when
    /// it cannot list them.
    #[test]
    fn the_child_keeps_only_its_own_descriptors() {
        let (keep_r, keep_w) = pipe().unwrap();
        let (other_r, other_w) = pipe().unwrap();
        let ranges = sys::close_ranges(&[keep_w.as_raw_fd()]);
        // SAFETY: the child only makes syscalls on descriptors it holds
        // (and, without close_range, reads /proc) then leaves with _exit.
        match unsafe { libc::fork() } {
            0 => {
                let ok = only_fds(&ranges);
                // SAFETY: F_GETFD on descriptors that must be closed.
                let gone = unsafe { libc::fcntl(other_r.as_raw_fd(), libc::F_GETFD) == -1 && libc::fcntl(other_w.as_raw_fd(), libc::F_GETFD) == -1 && libc::fcntl(keep_r.as_raw_fd(), libc::F_GETFD) == -1 };
                let b = [if ok && gone { b'1' } else { b'0' }];
                // SAFETY: a write of one byte to the kept pipe, then leaving.
                unsafe {
                    libc::write(keep_w.as_raw_fd(), b.as_ptr().cast(), 1);
                    libc::_exit(0);
                }
            }
            pid => {
                assert!(pid > 0);
                drop(keep_w);
                let mut got = [0u8; 1];
                let mut f = std::fs::File::from(keep_r);
                f.read_exact(&mut got).unwrap();
                // SAFETY: reaping the child forked here.
                unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
                assert_eq!(&got, b"1");
            }
        }
    }

    /// Many connections at once: at most `MAX_RELAYS` are relayed (each
    /// is two threads and a host connection); the rest are closed at once,
    /// and a slot freed is used again.
    #[test]
    fn relays_at_once_are_capped() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = std::env::temp_dir().join(format!("kiri-stepssh-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("s");
        let listener = UnixListener::bind(&sock).unwrap();
        let (r, w) = pipe().unwrap();
        let dials = std::sync::Arc::new(AtomicUsize::new(0));
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = std::sync::Arc::new(std::sync::Mutex::new(release_rx));
        let (d, rel) = (dials.clone(), release_rx.clone());
        // A host that does not answer until told: every relay stays open.
        let dial: Dial = std::sync::Arc::new(move || {
            d.fetch_add(1, Ordering::SeqCst);
            let _ = rel.lock().unwrap().recv();
            Err(io::Error::other("released"))
        });
        let server = std::thread::spawn(move || serve(&listener, &r, b"t\n", dial));
        let clients: Vec<UnixStream> = (0..100).map(|_| UnixStream::connect(&sock).unwrap()).collect();
        let t = std::time::Instant::now();
        while dials.load(Ordering::SeqCst) < MAX_RELAYS && t.elapsed() < std::time::Duration::from_secs(5) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(dials.load(Ordering::SeqCst), MAX_RELAYS, "relays started at once");
        // One relay ends: one more connection can be relayed.
        release_tx.send(()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let _late = UnixStream::connect(&sock).unwrap();
        let t = std::time::Instant::now();
        while dials.load(Ordering::SeqCst) < MAX_RELAYS + 1 && t.elapsed() < std::time::Duration::from_secs(5) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(dials.load(Ordering::SeqCst), MAX_RELAYS + 1);
        for _ in 0..MAX_RELAYS {
            let _ = release_tx.send(());
        }
        drop(w);
        server.join().unwrap();
        drop(clients);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_a_host_token_is_taken() {
        assert!(valid_token("0123456789abcdef0123456789abcdef"));
        assert!(!valid_token("0123456789abcdef0123456789abcde"));
        assert!(!valid_token("0123456789abcdef0123456789abcdeg"));
        assert!(!valid_token("../../x"));
    }
}
