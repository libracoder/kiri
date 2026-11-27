//! `kiri hostrelay`: lets Kiri's engine and containers in WSL2 reach services
//! on Windows' own loopback (`127.0.0.1` / `[::1]`): both Windows loopback
//! proxies (`127.0.0.1:7892`, where most Windows proxy apps listen) and
//! `host.docker.internal` / `host.kiri.internal` (`192.168.65.254`). In
//! WSL's default NAT networking the distro's 127.0.0.1 is its own, and
//! Windows' firewall keeps the WSL network away from Windows' ports, so a
//! service or proxy on Windows' loopback was unreachable from WSL and
//! containers.
//!
//! The connections take the way kiri-win already talks to WSL: a wsl.exe
//! process's stdin and stdout. kiri-win (crates/kiri-win/src/relay.rs)
//! starts this and asks it to LISTEN for static proxy ports (on the distro's
//! 127.0.0.1) and LISTEN_HOST for the dynamic `192.168.65.254` catch-all
//! host-gateway listener (using `SO_ORIGINAL_DST` with nftables DNAT on
//! `iifname "kiri*"` and local `OUTPUT` for TCP ports != 53). Each connection
//! goes back as frames, and kiri-win dials Windows' loopback (`127.0.0.1`,
//! falling back to `[::1]` on `ConnectionRefused`).
//!
//! Both ends share this file. Frames are the bridge's (crates/kiri/src/bridge.rs):
//! kind, connection id (u32 BE), length (u32 BE), then the data.

// Each build uses one end: the WSL end in Linux's kiri, the Windows end in
// kiri-win. The tests run both.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{self, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// WSL → Windows: a connection to the proxy or host-gateway on the port in the data (u16 BE).
pub const OPEN: u8 = 1;
pub const DATA: u8 = 2;
/// No more data from this side (a half-close).
pub const EOF: u8 = 3;
/// The connection is gone, both ways.
pub const CLOSE: u8 = 4;
/// Windows → WSL: listen for this Windows port (u16 BE).
pub const LISTEN: u8 = 6;
/// WSL → Windows: the Windows port, then the distro's port that leads to
/// it (both u16 BE); 0 when it could not listen.
pub const LISTENING: u8 = 7;
/// Windows → WSL: start the dynamic `192.168.65.254` catch-all host-gateway
/// listener (empty data, or 4-byte IPv4 override).
pub const LISTEN_HOST: u8 = 8;
/// WSL → Windows: the distro's catch-all host-gateway port (u16 BE), or 0
/// when it could not listen or configure nftables.
pub const LISTENING_HOST: u8 = 9;

/// What `host.docker.internal`, `host.kiri.internal`, and `host-gateway`
/// resolve to inside WSL 2 containers when the Windows host relay is active,
/// matching Docker Desktop.
pub const WSL_HOST_ADDR: [u8; 4] = [192, 168, 65, 254];
pub const WSL_HOST_ADDR_STR: &str = "192.168.65.254";

/// True when running under Microsoft's WSL 2 kernel.
pub fn is_wsl() -> bool {
    #[cfg(target_os = "linux")]
    {
        static WSL: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *WSL.get_or_init(|| {
            std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .is_ok_and(|r| r.to_ascii_lowercase().contains("microsoft"))
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(unix)]
const HOST_LOCK_FILE: &str = "/run/kiri-hostrelay.lock";
#[cfg(unix)]
const HOST_PID_FILE: &str = "/run/kiri-hostrelay.pid";

/// Checks whether a Linux `/proc/<pid>/cmdline` (NUL-separated argv) belongs
/// to `kiri hostrelay` (empty cmdline also excludes unreaped zombies).
fn is_hostrelay_cmdline(cmdline: &[u8]) -> bool {
    let mut args = cmdline.split(|&b| b == 0);
    let Some(argv0) = args.next() else { return false };
    let Some(argv1) = args.next() else { return false };
    !argv0.is_empty() && argv1 == b"hostrelay"
}

#[cfg(unix)]
fn read_pid_file(path: &std::path::Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse::<u32>().ok().filter(|&p| p > 0)
}

#[cfg(unix)]
fn write_pid_file(path: &std::path::Path, pid: u32) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".{pid}.tmp"));
    let tmp = std::path::PathBuf::from(tmp);
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o644).open(&tmp)?;
    if let Err(e) = file.write_all(format!("{pid}\n").as_bytes()).and_then(|()| file.flush()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    drop(file);
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

#[cfg(unix)]
fn pid_is_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    // SAFETY: signal 0 checks process existence without sending a signal.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(unix)]
fn pid_file_alive(path: &std::path::Path, verify: impl FnOnce(u32) -> bool) -> bool {
    read_pid_file(path).is_some_and(|pid| pid_is_alive(pid) && verify(pid))
}

#[cfg(target_os = "linux")]
fn hostrelay_pid_matches(pid: u32) -> bool {
    std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|c| is_hostrelay_cmdline(&c))
}

/// True when running on WSL 2 with a live `kiri hostrelay` process owning
/// `192.168.65.254` (verified via `/run/kiri-hostrelay.pid`, `kill(pid, 0)`,
/// and `/proc/<pid>/cmdline`, catching unclean exits without `getifaddrs()`).
pub fn wsl_host_active() -> bool {
    #[cfg(target_os = "linux")]
    {
        is_wsl() && pid_file_alive(std::path::Path::new(HOST_PID_FILE), hostrelay_pid_matches)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Neither end sends more data than this in a frame; a longer one is refused
/// before it is allocated.
const CHUNK: usize = 64 * 1024;
const MAX_FRAME: usize = 1 << 20;
/// Frames waiting for one connection's writer. Dispatched non-blockingly so a
/// stalled peer closes only its own connection rather than freezing the relay.
const QUEUE: usize = 64;
/// Maximum concurrent connections multiplexed over one relay.
const MAX_CONNS: usize = 512;
/// Write timeout on relayed TCP sockets so a wedged peer cannot pin a writer thread forever.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

pub type Out = Arc<Mutex<dyn Write + Send>>;

pub fn send(out: &Out, kind: u8, id: u32, data: &[u8]) -> io::Result<()> {
    let mut frame = Vec::with_capacity(9 + data.len());
    frame.push(kind);
    frame.extend_from_slice(&id.to_be_bytes());
    frame.extend_from_slice(&(data.len() as u32).to_be_bytes());
    frame.extend_from_slice(data);
    let mut w = out.lock().unwrap_or_else(PoisonError::into_inner);
    w.write_all(&frame)?;
    w.flush()
}

/// The next frame, or None when the other end has gone.
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<(u8, u32, Vec<u8>)>> {
    let mut h = [0u8; 9];
    match r.read_exact(&mut h) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let id = u32::from_be_bytes([h[1], h[2], h[3], h[4]]);
    let len = u32::from_be_bytes([h[5], h[6], h[7], h[8]]) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("frame of {len} bytes")));
    }
    let mut data = vec![0u8; len];
    r.read_exact(&mut data)?;
    Ok(Some((h[0], id, data)))
}

fn port_of(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

enum Op {
    Data(Vec<u8>),
    Eof,
}

struct Entry {
    tx: SyncSender<Op>,
    /// Set once the connection is made; a CLOSE before then just forgets it.
    stream: Option<TcpStream>,
}

#[derive(Default)]
struct State {
    closed: bool,
    entries: HashMap<u32, Entry>,
}

/// The connections open through one relay, by id.
#[derive(Default)]
pub struct Conns(Mutex<State>);

struct CloseAll(Arc<Conns>);

impl Drop for CloseAll {
    fn drop(&mut self) {
        self.0.close_all();
    }
}

enum OpenOutcome {
    Opened(Receiver<Op>),
    Full,
    Closed,
}

impl Conns {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A new connection: what arrives for it waits here until it is made.
    fn open(&self, id: u32) -> OpenOutcome {
        let (tx, rx) = sync_channel(QUEUE);
        let prev = {
            let mut s = self.state();
            if s.closed {
                return OpenOutcome::Closed;
            }
            if s.entries.len() >= MAX_CONNS && !s.entries.contains_key(&id) {
                return OpenOutcome::Full;
            }
            s.entries.insert(id, Entry { tx, stream: None })
        };
        if let Some(prev) = prev
            && let Some(stream) = prev.stream
        {
            let _ = stream.shutdown(Shutdown::Both);
        }
        OpenOutcome::Opened(rx)
    }

    fn close(&self, id: u32) -> bool {
        let Some(e) = self.state().entries.remove(&id) else { return false };
        if let Some(s) = e.stream {
            let _ = s.shutdown(Shutdown::Both);
        }
        true
    }

    fn close_all(&self) {
        let entries = {
            let mut s = self.state();
            s.closed = true;
            std::mem::take(&mut s.entries)
        };
        for (_, e) in entries {
            if let Some(s) = e.stream {
                let _ = s.shutdown(Shutdown::Both);
            }
        }
    }

    /// A frame for one of the connections. Never blocks the multiplexer loop:
    /// if a connection's bounded queue is full, only that stalled connection is closed.
    fn dispatch(&self, out: &Out, kind: u8, id: u32, data: Vec<u8>) {
        let op = match kind {
            DATA => Op::Data(data),
            EOF => Op::Eof,
            CLOSE => {
                self.close(id);
                return;
            }
            _ => return,
        };
        let tx = self.state().entries.get(&id).map(|e| e.tx.clone());
        if let Some(tx) = tx {
            match tx.try_send(op) {
                Ok(()) => {}
                Err(std::sync::mpsc::TrySendError::Full(_)) => {
                    if self.close(id) {
                        let _ = send(out, CLOSE, id, &[]);
                    }
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                    self.close(id);
                }
            }
        }
    }
}

fn enable_keepalive(stream: &TcpStream) {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let on: libc::c_int = 1;
        // SAFETY: SO_KEEPALIVE on a live TCP socket we own.
        unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_KEEPALIVE,
                (&raw const on).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    #[cfg(not(unix))]
    let _ = stream;
}

/// Joins `stream` to connection `id`: what it reads goes to the other end
/// as DATA, then EOF; what arrives for it (`rx`) is written to it.
fn attach(conns: &Arc<Conns>, out: &Out, id: u32, rx: Receiver<Op>, stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    enable_keepalive(&stream);
    let (Ok(reader), Ok(writer)) = (stream.try_clone(), stream.try_clone()) else {
        conns.close(id);
        let _ = send(out, CLOSE, id, &[]);
        return;
    };
    let (attached, to_shutdown) = {
        let mut s = conns.state();
        match s.entries.get_mut(&id) {
            Some(e) => (true, e.stream.replace(stream)),
            // Closed while it was being made.
            None => (false, Some(stream)),
        }
    };
    if let Some(s) = to_shutdown {
        let _ = s.shutdown(Shutdown::Both);
    }
    if !attached {
        return;
    }
    // Each half that ends counts; the second one forgets the connection.
    let halves = Arc::new(AtomicU8::new(0));
    let done = {
        let conns = conns.clone();
        let halves = halves.clone();
        move || {
            if halves.fetch_add(1, Ordering::SeqCst) == 1 {
                conns.close(id);
            }
        }
    };
    let done2 = done.clone();
    let (c, o) = (conns.clone(), out.clone());
    if std::thread::Builder::new()
        .name("kiri-relay-w".into())
        .spawn(move || {
            let mut writer = writer;
            for op in rx {
                match op {
                    Op::Data(d) => {
                        if writer.write_all(&d).is_err() {
                            let _ = writer.shutdown(Shutdown::Both);
                            c.close(id);
                            let _ = send(&o, CLOSE, id, &[]);
                            return;
                        }
                    }
                    Op::Eof => {
                        let _ = writer.shutdown(Shutdown::Write);
                        break;
                    }
                }
            }
            done2();
        })
        .is_err()
    {
        if conns.close(id) {
            let _ = send(out, CLOSE, id, &[]);
        }
        return;
    }
    let o = out.clone();
    let c = conns.clone();
    if std::thread::Builder::new()
        .name("kiri-relay-r".into())
        .spawn(move || {
            let mut reader = reader;
            let mut buf = vec![0u8; CHUNK];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => {
                        if send(&o, EOF, id, &[]).is_err() {
                            c.close(id);
                        }
                        break;
                    }
                    Ok(n) => {
                        if send(&o, DATA, id, &buf[..n]).is_err() {
                            c.close(id);
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        // Gone while the other end may still be sending: say so.
                        if c.close(id) {
                            let _ = send(&o, CLOSE, id, &[]);
                        }
                        break;
                    }
                }
            }
            done();
        })
        .is_err()
        && conns.close(id)
    {
        let _ = send(out, CLOSE, id, &[]);
    }
}

/// The WSL end (`kiri hostrelay`): listens as kiri-win asks and sends each
/// connection over `out`, until kiri-win goes, and the listeners with it.
pub fn listen_side(input: impl Read, out: &Out) -> io::Result<()> {
    // Declared before `_close` so open connections drop (freeing FDs) before
    // `HostGateway::drop` acquires the teardown lock.
    #[cfg(target_os = "linux")]
    let mut host_gateway: Option<HostGateway> = None;
    let conns = Arc::new(Conns::default());
    let _close = CloseAll(conns.clone());
    let next = Arc::new(AtomicU32::new(1));
    let mut listening: HashMap<u16, u16> = HashMap::new();
    let mut r = BufReader::with_capacity(CHUNK, input);
    while let Some((kind, id, data)) = read_frame(&mut r)? {
        match kind {
            LISTEN => {
                let Some(target) = port_of(&data, 0) else { continue };
                let local = match listening.get(&target) {
                    Some(&p) => p,
                    None => {
                        let p = listen(target, &conns, out, &next).unwrap_or(0);
                        if p != 0 {
                            listening.insert(target, p);
                        }
                        p
                    }
                };
                let mut reply = target.to_be_bytes().to_vec();
                reply.extend_from_slice(&local.to_be_bytes());
                send(out, LISTENING, 0, &reply)?;
            }
            LISTEN_HOST => {
                #[cfg(target_os = "linux")]
                let port = match &host_gateway {
                    Some(hg) => hg.port,
                    None => {
                        let addr: [u8; 4] = data.get(..4).and_then(|b| b.try_into().ok()).unwrap_or(WSL_HOST_ADDR);
                        match start_host_gateway(addr, &conns, out, &next) {
                            Ok(hg) => {
                                let p = hg.port;
                                host_gateway = Some(hg);
                                p
                            }
                            Err(_) => 0,
                        }
                    }
                };
                #[cfg(not(target_os = "linux"))]
                let port: u16 = 0;
                send(out, LISTENING_HOST, 0, &port.to_be_bytes())?;
            }
            _ => conns.dispatch(out, kind, id, data),
        }
    }
    Ok(())
}

/// Backoff on transient `accept()` errors (such as `EMFILE` / `ENFILE`) so
/// listener threads never busy-spin.
const ACCEPT_ERR_BACKOFF: Duration = Duration::from_millis(50);

/// Listens on the distro's loopback for `target`; its port.
fn listen(target: u16, conns: &Arc<Conns>, out: &Out, next: &Arc<AtomicU32>) -> io::Result<u16> {
    let l = TcpListener::bind(("127.0.0.1", 0))?;
    let port = l.local_addr()?.port();
    let (conns, out, next) = (conns.clone(), out.clone(), next.clone());
    std::thread::spawn(move || {
        for s in l.incoming() {
            let s = match s {
                Ok(s) => s,
                Err(e) => {
                    if e.kind() != io::ErrorKind::Interrupted {
                        std::thread::sleep(ACCEPT_ERR_BACKOFF);
                    }
                    continue;
                }
            };
            let id = next.fetch_add(1, Ordering::SeqCst);
            let rx = match conns.open(id) {
                OpenOutcome::Opened(rx) => rx,
                OpenOutcome::Full => {
                    let _ = s.shutdown(Shutdown::Both);
                    continue;
                }
                OpenOutcome::Closed => {
                    let _ = s.shutdown(Shutdown::Both);
                    return;
                }
            };
            if send(&out, OPEN, id, &target.to_be_bytes()).is_err() {
                conns.close(id);
                let _ = s.shutdown(Shutdown::Both);
                return;
            }
            attach(&conns, &out, id, rx, s);
        }
    });
    Ok(port)
}

/// Acquires an exclusive `flock` on `lock_path` (never unlinked so concurrent
/// setup and teardown always synchronize on the same inode).
#[cfg(unix)]
fn lock_host_gateway(lock_path: &std::path::Path) -> io::Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(lock_path)?;
    loop {
        // SAFETY: `file` owns a valid open descriptor.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(file);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Serializes host-gateway setup under `lock_path`, publishing `pid` to
/// `pid_path` only after `setup` succeeds and rolling back if publishing fails.
#[cfg(unix)]
fn acquire_host_gateway<T>(
    lock_path: &std::path::Path,
    pid_path: &std::path::Path,
    pid: u32,
    setup: impl FnOnce() -> io::Result<T>,
    rollback: impl FnOnce(T),
) -> io::Result<T> {
    let _lock = lock_host_gateway(lock_path)?;
    let val = setup()?;
    if let Err(e) = write_pid_file(pid_path, pid) {
        if read_pid_file(pid_path) == Some(pid) {
            let _ = std::fs::remove_file(pid_path);
        }
        rollback(val);
        return Err(e);
    }
    Ok(val)
}

/// Serializes host-gateway teardown under `lock_path`, removing `pid_path` and
/// running `teardown` only after verifying `pid` is still the active owner.
#[cfg(unix)]
fn release_host_gateway(lock_path: &std::path::Path, pid_path: &std::path::Path, pid: u32, teardown: impl FnOnce()) {
    let Ok(_lock) = lock_host_gateway(lock_path) else { return };
    if read_pid_file(pid_path) == Some(pid) {
        let _ = std::fs::remove_file(pid_path);
        teardown();
    }
}

/// Active catch-all host-gateway state on Linux (WSL 2): keeps `192.168.65.254/32`
/// on `lo` and `table ip kiri_host` alive until `listen_side` ends, then cleans
/// them up if no newer `kiri hostrelay` has taken ownership.
#[cfg(target_os = "linux")]
struct HostGateway {
    addr: [u8; 4],
    port: u16,
    pid: u32,
}

#[cfg(target_os = "linux")]
impl Drop for HostGateway {
    fn drop(&mut self) {
        // Serialize with any concurrent `start_host_gateway` so an exiting
        // relay can never tear down a newer relay's `lo` address or nftables.
        release_host_gateway(
            std::path::Path::new(HOST_LOCK_FILE),
            std::path::Path::new(HOST_PID_FILE),
            self.pid,
            || {
                let _ = host_net::remove_nft();
                let _ = host_net::del_lo_addr(self.addr);
            },
        );
    }
}

/// Checks whether `SO_ORIGINAL_DST` returned a valid host-gateway target port
/// destined to `host_addr` (non-zero and not TCP port 53).
fn host_gateway_target(dst_ip: [u8; 4], dst_port: u16, host_addr: [u8; 4]) -> Option<u16> {
    (dst_ip == host_addr && dst_port != 0 && dst_port != 53).then_some(dst_port)
}

#[cfg(target_os = "linux")]
fn original_dst_port(fd: std::os::fd::RawFd, host_addr: [u8; 4]) -> Option<u16> {
    const SO_ORIGINAL_DST: libc::c_int = 80;
    // SAFETY: `SO_ORIGINAL_DST` fills `sockaddr_in` with the pre-DNAT destination.
    unsafe {
        let mut dst: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        if libc::getsockopt(fd, libc::SOL_IP, SO_ORIGINAL_DST, (&mut dst as *mut libc::sockaddr_in).cast(), &mut len) != 0 {
            return None;
        }
        host_gateway_target(dst.sin_addr.s_addr.to_ne_bytes(), u16::from_be(dst.sin_port), host_addr)
    }
}

/// Assigns `addr/32` to `lo`, binds a catch-all TCP listener on `addr:0`,
/// installs `table ip kiri_host` nftables DNAT + input guard rules, and spawns
/// the accept loop that extracts each connection's target port via
/// `SO_ORIGINAL_DST`.
#[cfg(target_os = "linux")]
fn start_host_gateway(addr: [u8; 4], conns: &Arc<Conns>, out: &Out, next: &Arc<AtomicU32>) -> io::Result<HostGateway> {
    use std::os::fd::AsRawFd;
    let pid = std::process::id();
    let (listener, port, added) = acquire_host_gateway(
        std::path::Path::new(HOST_LOCK_FILE),
        std::path::Path::new(HOST_PID_FILE),
        pid,
        || {
            let added = host_net::add_lo_addr(addr)?;
            let listener = match TcpListener::bind((std::net::Ipv4Addr::from(addr), 0)) {
                Ok(l) => l,
                Err(e) => {
                    if added {
                        let _ = host_net::del_lo_addr(addr);
                    }
                    return Err(e);
                }
            };
            let port = match listener.local_addr() {
                Ok(a) => a.port(),
                Err(e) => {
                    if added {
                        let _ = host_net::del_lo_addr(addr);
                    }
                    return Err(e);
                }
            };
            if let Err(e) = host_net::install_nft(addr, port) {
                if added {
                    let _ = host_net::del_lo_addr(addr);
                }
                return Err(e);
            }
            Ok((listener, port, added))
        },
        |(_listener, _port, added)| {
            let _ = host_net::remove_nft();
            if added {
                let _ = host_net::del_lo_addr(addr);
            }
        },
    )?;
    let (conns, out, next) = (conns.clone(), out.clone(), next.clone());
    if let Err(e) = std::thread::Builder::new().name("kiri-hostrelay-gw".into()).spawn(move || {
        for s in listener.incoming() {
            let s = match s {
                Ok(s) => s,
                Err(e) => {
                    if e.kind() != io::ErrorKind::Interrupted {
                        std::thread::sleep(ACCEPT_ERR_BACKOFF);
                    }
                    continue;
                }
            };
            let Some(target) = original_dst_port(s.as_raw_fd(), addr) else {
                let _ = s.shutdown(Shutdown::Both);
                continue;
            };
            let id = next.fetch_add(1, Ordering::SeqCst);
            let rx = match conns.open(id) {
                OpenOutcome::Opened(rx) => rx,
                OpenOutcome::Full => {
                    let _ = s.shutdown(Shutdown::Both);
                    continue;
                }
                OpenOutcome::Closed => {
                    let _ = s.shutdown(Shutdown::Both);
                    return;
                }
            };
            if send(&out, OPEN, id, &target.to_be_bytes()).is_err() {
                conns.close(id);
                let _ = s.shutdown(Shutdown::Both);
                return;
            }
            attach(&conns, &out, id, rx, s);
        }
    }) {
        release_host_gateway(
            std::path::Path::new(HOST_LOCK_FILE),
            std::path::Path::new(HOST_PID_FILE),
            pid,
            || {
                let _ = host_net::remove_nft();
                if added {
                    let _ = host_net::del_lo_addr(addr);
                }
            },
        );
        return Err(e);
    }
    Ok(HostGateway { addr, port, pid })
}

/// Minimal rtnetlink and nf_tables netlink helpers for WSL 2's catch-all
/// `192.168.65.254` host-gateway listener (`kiri hostrelay` runs in minimal
/// WSL distros with neither `ip` nor `nft` binaries).
#[cfg(target_os = "linux")]
mod host_net {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    const NLMSG_ERROR: u16 = 2;
    const NLMSG_DONE: u16 = 3;
    const NLM_F_REQUEST: u16 = 0x1;
    const NLM_F_ACK: u16 = 0x4;
    const NLM_F_EXCL: u16 = 0x200;
    const NLM_F_CREATE: u16 = 0x400;
    const NLM_F_APPEND: u16 = 0x800;

    const RTM_NEWADDR: u16 = 20;
    const RTM_DELADDR: u16 = 21;
    const IFA_ADDRESS: u16 = 1;
    const IFA_LOCAL: u16 = 2;

    const NFNL_SUBSYS_NFTABLES: u16 = 10;
    const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
    const NFNL_MSG_BATCH_END: u16 = 0x11;
    const NFT_MSG_NEWTABLE: u16 = 0;
    const NFT_MSG_DELTABLE: u16 = 2;
    const NFT_MSG_NEWCHAIN: u16 = 3;
    const NFT_MSG_NEWRULE: u16 = 6;

    pub const TABLE: &str = "kiri_host";
    const BRIDGE_PREFIX: &[u8] = b"kiri";
    /// Runs after conntrack (-200) and before `table ip kiri` (-100) so
    /// host-gateway traffic is never caught by published-port DNAT rules.
    const NAT_PRIORITY: i32 = -110;

    pub struct Msg {
        pub buf: Vec<u8>,
        nests: Vec<usize>,
    }

    fn pad(buf: &mut Vec<u8>) {
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
    }

    impl Msg {
        fn new(ty: u16, flags: u16) -> Self {
            let mut buf = vec![0u8; 16];
            buf[4..6].copy_from_slice(&ty.to_ne_bytes());
            buf[6..8].copy_from_slice(&(flags | NLM_F_REQUEST).to_ne_bytes());
            Self { buf, nests: Vec::new() }
        }

        fn raw(&mut self, bytes: &[u8]) -> &mut Self {
            self.buf.extend_from_slice(bytes);
            pad(&mut self.buf);
            self
        }

        fn attr(&mut self, ty: u16, data: &[u8]) -> &mut Self {
            self.buf.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
            self.buf.extend_from_slice(&ty.to_ne_bytes());
            self.buf.extend_from_slice(data);
            pad(&mut self.buf);
            self
        }

        fn attr_str(&mut self, ty: u16, s: &str) -> &mut Self {
            let mut v = s.as_bytes().to_vec();
            v.push(0);
            self.attr(ty, &v)
        }

        fn attr_be32(&mut self, ty: u16, v: u32) -> &mut Self {
            self.attr(ty, &v.to_be_bytes())
        }

        fn nest(&mut self, ty: u16) -> &mut Self {
            self.nests.push(self.buf.len());
            self.buf.extend_from_slice(&[0, 0]);
            self.buf.extend_from_slice(&(ty | 0x8000).to_ne_bytes());
            self
        }

        fn end(&mut self) -> &mut Self {
            let start = self.nests.pop().expect("nest() before end()");
            let len = (self.buf.len() - start) as u16;
            self.buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
            self
        }

        fn finish(&mut self, seq: u32) -> &[u8] {
            let len = self.buf.len() as u32;
            self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
            self.buf[8..12].copy_from_slice(&seq.to_ne_bytes());
            &self.buf
        }
    }

    struct Netlink {
        fd: OwnedFd,
        seq: u32,
        buf: Vec<u8>,
    }

    impl Netlink {
        fn open(protocol: i32) -> io::Result<Self> {
            // SAFETY: plain socket creation; owned immediately.
            let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, protocol) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `fd` is a fresh descriptor owned only here.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            Ok(Self { fd, seq: 1, buf: vec![0u8; 16 * 1024] })
        }

        fn request(&mut self, msgs: &mut [Msg]) -> io::Result<()> {
            let mut out = Vec::new();
            let first = self.seq;
            for m in msgs.iter_mut() {
                out.extend_from_slice(m.finish(self.seq));
                self.seq += 1;
            }
            // SAFETY: sending our own buffer on our own socket.
            if unsafe { libc::send(self.fd.as_raw_fd(), out.as_ptr().cast(), out.len(), 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut acked = 0;
            let want = msgs.iter().filter(|m| u16::from_ne_bytes([m.buf[6], m.buf[7]]) & NLM_F_ACK != 0).count();
            while acked < want {
                // SAFETY: receiving into our own buffer on our own socket.
                let n = unsafe { libc::recv(self.fd.as_raw_fd(), self.buf.as_mut_ptr().cast(), self.buf.len(), 0) };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                let n = n as usize;
                let mut off = 0;
                while off + 16 <= n {
                    let len = u32::from_ne_bytes(self.buf[off..off + 4].try_into().expect("4")) as usize;
                    let ty = u16::from_ne_bytes(self.buf[off + 4..off + 6].try_into().expect("2"));
                    let seq = u32::from_ne_bytes(self.buf[off + 8..off + 12].try_into().expect("4"));
                    if len < 16 || off + len > n {
                        break;
                    }
                    if ty == NLMSG_ERROR && seq >= first && seq < self.seq {
                        let code = i32::from_ne_bytes(self.buf[off + 16..off + 20].try_into().expect("4"));
                        acked += 1;
                        if code != 0 {
                            return Err(io::Error::from_raw_os_error(-code));
                        }
                    } else if ty == NLMSG_DONE {
                        acked = want;
                    }
                    off += (len + 3) & !3;
                }
            }
            Ok(())
        }
    }

    fn lo_index() -> io::Result<u32> {
        // SAFETY: valid NUL-terminated static C string.
        let i = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
        if i == 0 {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no lo interface"));
        }
        Ok(i)
    }

    fn lo_addr_msg(ty: u16, flags: u16, index: u32, addr: [u8; 4]) -> Msg {
        let mut m = Msg::new(ty, flags);
        let mut ifa = [0u8; 8];
        ifa[0] = libc::AF_INET as u8;
        ifa[1] = 32;
        ifa[3] = libc::RT_SCOPE_HOST;
        ifa[4..8].copy_from_slice(&index.to_ne_bytes());
        m.raw(&ifa).attr(IFA_LOCAL, &addr).attr(IFA_ADDRESS, &addr);
        m
    }

    /// Adds `addr/32` to `lo`. Returns `Ok(true)` if added, `Ok(false)` if already present.
    pub fn add_lo_addr(addr: [u8; 4]) -> io::Result<bool> {
        let index = lo_index()?;
        let mut nl = Netlink::open(libc::NETLINK_ROUTE)?;
        let msg = lo_addr_msg(RTM_NEWADDR, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, index, addr);
        match nl.request(&mut [msg]) {
            Ok(()) => Ok(true),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Removes `addr/32` from `lo`; already absent is fine.
    pub fn del_lo_addr(addr: [u8; 4]) -> io::Result<()> {
        let index = lo_index()?;
        let mut nl = Netlink::open(libc::NETLINK_ROUTE)?;
        let msg = lo_addr_msg(RTM_DELADDR, NLM_F_ACK, index, addr);
        match nl.request(&mut [msg]) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EADDRNOTAVAIL) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn nfgen(family: u8, res_id: u16) -> [u8; 4] {
        let mut b = [0u8; 4];
        b[0] = family;
        b[2..4].copy_from_slice(&res_id.to_be_bytes());
        b
    }

    fn nft(msg: u16, flags: u16) -> Msg {
        let mut m = Msg::new((NFNL_SUBSYS_NFTABLES << 8) | msg, flags);
        m.raw(&nfgen(libc::NFPROTO_IPV4 as u8, 0));
        m
    }

    /// Linux 3.13+ compatible table clear: add (no-op if present), then delete.
    fn clear_table() -> [Msg; 2] {
        let mut add = nft(NFT_MSG_NEWTABLE, NLM_F_ACK | NLM_F_CREATE);
        add.attr_str(1, TABLE);
        let mut delete = nft(NFT_MSG_DELTABLE, NLM_F_ACK);
        delete.attr_str(1, TABLE);
        [add, delete]
    }

    fn chain(name: &str, hook: u32, priority: i32, kind: &str) -> Msg {
        let mut c = nft(NFT_MSG_NEWCHAIN, NLM_F_ACK | NLM_F_CREATE);
        c.attr_str(1, TABLE).attr_str(3, name);
        c.nest(4).attr_be32(1, hook).attr_be32(2, priority as u32).end();
        c.attr_be32(5, libc::NF_ACCEPT as u32).attr_str(7, kind);
        c
    }

    /// `[iifname "kiri*"] ip daddr <addr> tcp dport != 53 dnat to <addr>:<port>`.
    pub fn dnat_rule(chain: &str, addr: [u8; 4], port: u16, from_bridges: bool) -> Msg {
        let mut rule = nft(NFT_MSG_NEWRULE, NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND);
        rule.attr_str(1, TABLE).attr_str(2, chain);
        rule.nest(4);
        if from_bridges {
            // meta iifname (6) => reg 1; cmp eq "kiri" prefix
            rule.nest(1).attr_str(1, "meta").nest(2).attr_be32(1, 1).attr_be32(2, 6).end().end();
            rule.nest(1).attr_str(1, "cmp").nest(2).attr_be32(1, 1).attr_be32(2, 0).nest(3).attr(1, BRIDGE_PREFIX).end().end().end();
        }
        // payload network header + 16 (daddr), 4 bytes => reg 1; cmp eq addr
        rule.nest(1).attr_str(1, "payload").nest(2).attr_be32(1, 1).attr_be32(2, 1).attr_be32(3, 16).attr_be32(4, 4).end().end();
        rule.nest(1).attr_str(1, "cmp").nest(2).attr_be32(1, 1).attr_be32(2, 0).nest(3).attr(1, &addr).end().end().end();
        // meta l4proto (16) => reg 1; cmp eq tcp
        rule.nest(1).attr_str(1, "meta").nest(2).attr_be32(1, 1).attr_be32(2, 16).end().end();
        rule.nest(1).attr_str(1, "cmp").nest(2).attr_be32(1, 1).attr_be32(2, 0).nest(3).attr(1, &[libc::IPPROTO_TCP as u8]).end().end().end();
        // payload transport header + 2 (dport), 2 bytes => reg 1; cmp neq 53
        rule.nest(1).attr_str(1, "payload").nest(2).attr_be32(1, 1).attr_be32(2, 2).attr_be32(3, 2).attr_be32(4, 2).end().end();
        rule.nest(1).attr_str(1, "cmp").nest(2).attr_be32(1, 1).attr_be32(2, 1).nest(3).attr(1, &53u16.to_be_bytes()).end().end().end();
        // immediate reg 1 = addr, reg 2 = port; nat dnat ip addr reg 1 proto reg 2
        rule.nest(1).attr_str(1, "immediate").nest(2).attr_be32(1, 1).nest(2).attr(1, &addr).end().end().end();
        rule.nest(1).attr_str(1, "immediate").nest(2).attr_be32(1, 2).nest(2).attr(1, &port.to_be_bytes()).end().end().end();
        rule.nest(1).attr_str(1, "nat").nest(2).attr_be32(1, 1).attr_be32(2, libc::AF_INET as u32).attr_be32(3, 1).attr_be32(5, 2).attr_be32(7, 2).end().end();
        rule.end();
        rule
    }

    /// `ip daddr <addr> iifname != "kiri*" iifname != "lo" drop`: keeps
    /// external LAN / non-container interfaces off the host-gateway relay.
    pub fn input_guard_rule(addr: [u8; 4]) -> Msg {
        let mut lo_full = [0u8; 16];
        lo_full[..2].copy_from_slice(b"lo");
        let mut rule = nft(NFT_MSG_NEWRULE, NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND);
        rule.attr_str(1, TABLE).attr_str(2, "input");
        rule.nest(4);
        // payload network header + 16 (daddr), 4 bytes => reg 1; cmp eq addr
        rule.nest(1).attr_str(1, "payload").nest(2).attr_be32(1, 1).attr_be32(2, 1).attr_be32(3, 16).attr_be32(4, 4).end().end();
        rule.nest(1).attr_str(1, "cmp").nest(2).attr_be32(1, 1).attr_be32(2, 0).nest(3).attr(1, &addr).end().end().end();
        // meta iifname (6) => reg 1; cmp neq "kiri" prefix
        rule.nest(1).attr_str(1, "meta").nest(2).attr_be32(1, 1).attr_be32(2, 6).end().end();
        rule.nest(1).attr_str(1, "cmp").nest(2).attr_be32(1, 1).attr_be32(2, 1).nest(3).attr(1, BRIDGE_PREFIX).end().end().end();
        // meta iifname (6) => reg 1; cmp neq "lo" exact (16-byte NUL-padded)
        rule.nest(1).attr_str(1, "meta").nest(2).attr_be32(1, 1).attr_be32(2, 6).end().end();
        rule.nest(1).attr_str(1, "cmp").nest(2).attr_be32(1, 1).attr_be32(2, 1).nest(3).attr(1, &lo_full).end().end().end();
        // verdict DROP
        rule.nest(1).attr_str(1, "immediate").nest(2).attr_be32(1, 0).nest(2).nest(2).attr_be32(1, libc::NF_DROP as u32).end().end().end().end();
        rule.end();
        rule
    }

    pub fn install_batch(addr: [u8; 4], port: u16) -> Vec<Msg> {
        let mut begin = Msg::new(NFNL_MSG_BATCH_BEGIN, 0);
        begin.raw(&nfgen(libc::AF_UNSPEC as u8, NFNL_SUBSYS_NFTABLES));
        let [add, delete] = clear_table();
        let mut table = nft(NFT_MSG_NEWTABLE, NLM_F_ACK | NLM_F_CREATE);
        table.attr_str(1, TABLE);
        let pre = chain("prerouting", 0, NAT_PRIORITY, "nat");
        let out = chain("output", 3, NAT_PRIORITY, "nat");
        let input = chain("input", 1, 0, "filter");
        let mut end = Msg::new(NFNL_MSG_BATCH_END, 0);
        end.raw(&nfgen(libc::AF_UNSPEC as u8, NFNL_SUBSYS_NFTABLES));
        vec![
            begin,
            add,
            delete,
            table,
            pre,
            out,
            input,
            dnat_rule("prerouting", addr, port, true),
            dnat_rule("output", addr, port, false),
            input_guard_rule(addr),
            end,
        ]
    }

    pub fn install_nft(addr: [u8; 4], port: u16) -> io::Result<()> {
        let mut nl = Netlink::open(libc::NETLINK_NETFILTER)?;
        nl.request(&mut install_batch(addr, port))
    }

    pub fn remove_nft() -> io::Result<()> {
        let mut nl = Netlink::open(libc::NETLINK_NETFILTER)?;
        let mut begin = Msg::new(NFNL_MSG_BATCH_BEGIN, 0);
        begin.raw(&nfgen(libc::AF_UNSPEC as u8, NFNL_SUBSYS_NFTABLES));
        let [add, delete] = clear_table();
        let mut end = Msg::new(NFNL_MSG_BATCH_END, 0);
        end.raw(&nfgen(libc::AF_UNSPEC as u8, NFNL_SUBSYS_NFTABLES));
        nl.request(&mut [begin, add, delete, end])
    }
}

/// The Windows end: dials the proxy for each connection the WSL end sends,
/// on the ports `allowed` names, and hands LISTENING replies to `listening`.
pub fn dial_side(input: impl Read, out: &Out, allowed: impl Fn(u16) -> bool, listening: impl Fn(u16, u16)) -> io::Result<()> {
    dial_side_with_host(input, out, allowed, listening, |_| {})
}

/// Like [`dial_side`], also delivering `LISTENING_HOST` replies (the WSL
/// catch-all host-gateway relay port, or 0 on failure) to `listening_host`.
pub fn dial_side_with_host(
    input: impl Read,
    out: &Out,
    allowed: impl Fn(u16) -> bool,
    listening: impl Fn(u16, u16),
    listening_host: impl Fn(u16),
) -> io::Result<()> {
    let conns = Arc::new(Conns::default());
    let _close = CloseAll(conns.clone());
    let mut r = BufReader::with_capacity(CHUNK, input);
    while let Some((kind, id, data)) = read_frame(&mut r)? {
        match kind {
            OPEN => {
                let target = port_of(&data, 0).filter(|&p| p != 0 && allowed(p));
                let Some(target) = target else {
                    send(out, CLOSE, id, &[])?;
                    continue;
                };
                // Data that arrives while it dials waits in the queue.
                let rx = match conns.open(id) {
                    OpenOutcome::Opened(rx) => rx,
                    OpenOutcome::Full | OpenOutcome::Closed => {
                        let _ = send(out, CLOSE, id, &[]);
                        continue;
                    }
                };
                let (c, o) = (conns.clone(), out.clone());
                if std::thread::Builder::new()
                    .name("kiri-relay-dial".into())
                    .spawn(move || match dial(target) {
                        Ok(s) => attach(&c, &o, id, rx, s),
                        Err(_) => {
                            c.close(id);
                            let _ = send(&o, CLOSE, id, &[]);
                        }
                    })
                    .is_err()
                {
                    conns.close(id);
                    let _ = send(out, CLOSE, id, &[]);
                }
            }
            LISTENING => {
                if let (Some(target), Some(local)) = (port_of(&data, 0), port_of(&data, 2)) {
                    listening(target, local);
                }
            }
            LISTENING_HOST => {
                if let Some(local) = port_of(&data, 0) {
                    listening_host(local);
                }
            }
            _ => conns.dispatch(out, kind, id, data),
        }
    }
    Ok(())
}

/// This machine's loopback at `port`: `127.0.0.1` first, falling back to
/// `[::1]` on `ConnectionRefused` (for IPv6-only localhost servers such as
/// Node/Vite on Windows).
fn dial(port: u16) -> io::Result<TcpStream> {
    let wait = Duration::from_secs(5);
    match TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), wait) {
        Ok(s) => Ok(s),
        Err(e) if matches!(e.kind(), io::ErrorKind::ConnectionRefused | io::ErrorKind::AddrNotAvailable) => {
            TcpStream::connect_timeout(&(std::net::Ipv6Addr::LOCALHOST, port).into(), wait).map_err(|_| e)
        }
        Err(e) => Err(e),
    }
}

/// Where in a proxy address its host and port are, when the host is this
/// machine's loopback: `http://user:pw@127.0.0.1:7892/` → (7892, the span of
/// `127.0.0.1:7892`). Without a port there is nothing to relay.
pub fn loopback(url: &str) -> Option<(u16, std::ops::Range<usize>)> {
    let start = url.find("://").map_or(0, |i| i + 3);
    let rest = &url[start..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let at = rest[..end].rfind('@').map_or(0, |i| i + 1);
    let hostport = &rest[at..end];
    let (host, port) = hostport.rsplit_once(':')?;
    let port: u16 = port.parse().ok().filter(|&p| p != 0)?;
    let host = host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    let is_loopback = host == "localhost" || host == "::1" || host.parse::<std::net::Ipv4Addr>().is_ok_and(|a| a.is_loopback());
    is_loopback.then_some((port, start + at..start + end))
}

/// The distro's own address for a Windows loopback proxy, through the relay.
pub fn relayed(url: &str, map: &HashMap<u16, u16>) -> Option<String> {
    let (port, span) = loopback(url)?;
    let local = map.get(&port)?;
    Some(format!("{}127.0.0.1:{local}{}", &url[..span.start], &url[span.end..]))
}

pub fn run() -> io::Result<()> {
    let out: Out = Arc::new(Mutex::new(io::stdout()));
    listen_side(io::stdin(), &out)
}

// Over unix socket pairs: these run with kiri's tests, not kiri-win's.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn proxy_addresses_on_loopback() {
        assert_eq!(loopback("127.0.0.1:7892").map(|l| l.0), Some(7892));
        let url = "http://user:p@ss@localhost:8080/";
        let (port, span) = loopback(url).unwrap();
        assert_eq!((port, &url[span]), (8080, "localhost:8080"));
        assert_eq!(loopback("http://[::1]:3128").map(|l| l.0), Some(3128));
        assert_eq!(loopback("socks5://127.0.0.2:1080").map(|l| l.0), Some(1080));
        for none in ["http://10.0.0.1:3128", "http://proxy.corp:8080", "http://127.0.0.1", "http://127.0.0.1:0", "", "http://127.0.0.1:x"] {
            assert_eq!(loopback(none), None, "{none}");
        }
        let map = HashMap::from([(7892, 41234)]);
        assert_eq!(relayed("http://u:p@127.0.0.1:7892/x", &map).as_deref(), Some("http://u:p@127.0.0.1:41234/x"));
        assert_eq!(relayed("127.0.0.1:7892", &map).as_deref(), Some("127.0.0.1:41234"));
        assert_eq!(relayed("http://127.0.0.1:9999", &map), None);
        assert_eq!(relayed("http://proxy.corp:7892", &map), None);
    }

    /// Both ends over a pair of sockets, as wsl.exe's stdin and stdout carry
    /// them: a "proxy" on this machine's loopback, reached through the relay.
    fn relay(allowed: u16) -> (Arc<Mutex<HashMap<u16, u16>>>, Out) {
        let (wsl, win) = UnixStream::pair().unwrap();
        let wsl_out: Out = Arc::new(Mutex::new(wsl.try_clone().unwrap()));
        let win_out: Out = Arc::new(Mutex::new(win.try_clone().unwrap()));
        std::thread::spawn(move || listen_side(wsl, &wsl_out));
        let ports = Arc::new(Mutex::new(HashMap::new()));
        let p = ports.clone();
        let o = win_out.clone();
        std::thread::spawn(move || dial_side(win, &o, move |t| t == allowed, move |t, l| { p.lock().unwrap().insert(t, l); }));
        (ports, win_out)
    }

    fn listen_for(ports: &Arc<Mutex<HashMap<u16, u16>>>, out: &Out, target: u16) -> u16 {
        send(out, LISTEN, 0, &target.to_be_bytes()).unwrap();
        for _ in 0..200 {
            if let Some(&l) = ports.lock().unwrap().get(&target) {
                return l;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("no LISTENING for {target}");
    }

    #[test]
    fn connections_reach_the_proxy_and_back() {
        // The proxy: echoes each connection, upper-cased, until its half-close.
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = proxy.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in proxy.incoming() {
                let mut s = s.unwrap();
                std::thread::spawn(move || {
                    let mut all = Vec::new();
                    s.read_to_end(&mut all).unwrap();
                    s.write_all(&all.to_ascii_uppercase()).unwrap();
                });
            }
        });
        let (ports, out) = relay(target);
        let local = listen_for(&ports, &out, target);
        assert_ne!(local, 0);
        assert_eq!(listen_for(&ports, &out, target), local, "asking again keeps the port");
        // Several at once, one bigger than many frames and the queue.
        let big: Vec<u8> = (0..3_000_000u32).map(|i| b'a' + (i % 26) as u8).collect();
        let handles: Vec<_> = (0..6)
            .map(|i| {
                let body = if i == 0 { big.clone() } else { format!("hello {i}").into_bytes() };
                std::thread::spawn(move || {
                    let mut c = TcpStream::connect(("127.0.0.1", local)).unwrap();
                    let mut w = c.try_clone().unwrap();
                    let b = body.clone();
                    let t = std::thread::spawn(move || {
                        w.write_all(&b).unwrap();
                        w.shutdown(Shutdown::Write).unwrap();
                    });
                    let mut got = Vec::new();
                    c.read_to_end(&mut got).unwrap();
                    t.join().unwrap();
                    assert_eq!(got, body.to_ascii_uppercase());
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn only_the_ports_asked_for_are_dialled() {
        let other = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = other.local_addr().unwrap().port();
        // kiri-win allows some other port; the WSL end listens for this one anyway.
        let (ports, out) = relay(1);
        let local = listen_for(&ports, &out, target);
        let mut c = TcpStream::connect(("127.0.0.1", local)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 1];
        assert!(matches!(c.read(&mut buf), Ok(0) | Err(_)), "closed without reaching the port");
        other.set_nonblocking(true).unwrap();
        assert!(other.accept().is_err(), "nothing dialled the port");
    }

    #[test]
    fn a_proxy_that_is_not_running_closes_the_connection() {
        let gone = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = gone.local_addr().unwrap().port();
        drop(gone);
        let (ports, out) = relay(target);
        let local = listen_for(&ports, &out, target);
        let mut c = TcpStream::connect(("127.0.0.1", local)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut buf = [0u8; 1];
        assert!(matches!(c.read(&mut buf), Ok(0) | Err(_)));
    }

    fn assert_closed(conn: &mut TcpStream) {
        conn.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let mut buf = [0u8; 1];
        let res = conn.read(&mut buf);
        assert!(
            matches!(res, Ok(0))
                || matches!(res, Err(ref e) if !matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)),
            "expected closed socket, got {res:?}"
        );
    }

    #[test]
    fn ending_the_relay_closes_its_open_connections() {
        // dial_side: open proxy socket closes when the frame stream hits EOF.
        let proxy = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = proxy.local_addr().unwrap().port();
        let (in_rx, in_tx) = io::pipe().unwrap();
        let (mut out_rx, out_tx) = io::pipe().unwrap();
        let in_out: Out = Arc::new(Mutex::new(in_tx));
        let dial_out: Out = Arc::new(Mutex::new(out_tx));
        let o = dial_out.clone();
        let h = std::thread::spawn(move || dial_side(in_rx, &o, move |p| p == port, |_, _| {}));

        send(&in_out, OPEN, 1, &port.to_be_bytes()).unwrap();
        let (mut conn, _) = proxy.accept().unwrap();
        conn.write_all(b"x").unwrap();
        assert_eq!(read_frame(&mut out_rx).unwrap(), Some((DATA, 1, b"x".to_vec())));

        drop(in_out);
        h.join().unwrap().unwrap();
        drop(dial_out);
        assert_closed(&mut conn);

        // listen_side: open client socket closes when the frame stream hits EOF.
        let (in_rx, in_tx) = io::pipe().unwrap();
        let (mut out_rx, out_tx) = io::pipe().unwrap();
        let in_out: Out = Arc::new(Mutex::new(in_tx));
        let listen_out: Out = Arc::new(Mutex::new(out_tx));
        let o = listen_out.clone();
        let h = std::thread::spawn(move || listen_side(in_rx, &o));

        send(&in_out, LISTEN, 0, &port.to_be_bytes()).unwrap();
        let Some((LISTENING, 0, reply)) = read_frame(&mut out_rx).unwrap() else { panic!("expected LISTENING") };
        let local = port_of(&reply, 2).unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", local)).unwrap();
        assert_eq!(read_frame(&mut out_rx).unwrap(), Some((OPEN, 1, port.to_be_bytes().to_vec())));
        client.write_all(b"y").unwrap();
        assert_eq!(read_frame(&mut out_rx).unwrap(), Some((DATA, 1, b"y".to_vec())));

        drop(in_out);
        h.join().unwrap().unwrap();
        drop(listen_out);
        assert_closed(&mut client);
    }

    #[test]
    fn ending_the_relay_with_a_full_queue_tears_down_without_deadlocking() {
        let proxy = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = proxy.local_addr().unwrap().port();
        let (in_rx, in_tx) = io::pipe().unwrap();
        let (mut out_rx, out_tx) = io::pipe().unwrap();
        let in_out: Out = Arc::new(Mutex::new(in_tx));
        let dial_out: Out = Arc::new(Mutex::new(out_tx));
        let o = dial_out.clone();
        let h = std::thread::spawn(move || dial_side(in_rx, &o, move |p| p == port, |_, _| {}));

        send(&in_out, OPEN, 1, &port.to_be_bytes()).unwrap();
        let (mut conn, _) = proxy.accept().unwrap();
        conn.write_all(b"x").unwrap();
        assert_eq!(read_frame(&mut out_rx).unwrap(), Some((DATA, 1, b"x".to_vec())));

        // Fill the socket send buffer and the sync_channel(QUEUE) buffer without reading from conn.
        let chunk = vec![b'a'; CHUNK * 4];
        for _ in 0..QUEUE {
            send(&in_out, DATA, 1, &chunk).unwrap();
        }

        drop(in_out);
        h.join().unwrap().unwrap();
        drop(dial_out);
        // Drain any kernel-buffered bytes and confirm the socket was shut down.
        conn.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let mut buf = vec![0u8; CHUNK * 4];
        loop {
            match conn.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(e) => {
                    assert!(
                        !matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock),
                        "expected closed socket after full queue EOF, got {e:?}"
                    );
                    break;
                }
            }
        }

        // Also verify teardown when all QUEUE slots of sync_channel(QUEUE) are 100% full (TrySendError::Full).
        let conns = Arc::new(Conns::default());
        let (_out_rx, out_tx) = io::pipe().unwrap();
        let out: Out = Arc::new(Mutex::new(out_tx));
        let OpenOutcome::Opened(rx) = conns.open(1) else { panic!("expected Opened") };
        let client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (mut peer, _) = proxy.accept().unwrap();
        attach(&conns, &out, 1, rx, client);
        let tx = conns.state().entries.get(&1).unwrap().tx.clone();
        while tx.try_send(Op::Data(chunk.clone())).is_ok() {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(matches!(tx.try_send(Op::Data(vec![b'z'])), Err(std::sync::mpsc::TrySendError::Full(_))));
        drop(tx);
        conns.close_all();
        assert!(conns.state().entries.is_empty());
        assert!(matches!(conns.open(2), OpenOutcome::Closed));
        peer.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        loop {
            match peer.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(e) => {
                    assert!(!matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock));
                    break;
                }
            }
        }
    }

    #[test]
    fn broken_frame_output_pipe_cleans_up_the_connection() {
        let proxy = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = proxy.local_addr().unwrap().port();
        let (in_rx, in_tx) = io::pipe().unwrap();
        let (mut out_rx, out_tx) = io::pipe().unwrap();
        let in_out: Out = Arc::new(Mutex::new(in_tx));
        let dial_out: Out = Arc::new(Mutex::new(out_tx));
        let o = dial_out.clone();
        let h = std::thread::spawn(move || dial_side(in_rx, &o, move |p| p == port, |_, _| {}));

        send(&in_out, OPEN, 1, &port.to_be_bytes()).unwrap();
        let (mut conn, _) = proxy.accept().unwrap();
        conn.write_all(b"x").unwrap();
        assert_eq!(read_frame(&mut out_rx).unwrap(), Some((DATA, 1, b"x".to_vec())));

        // Break the output pipe while the input stream stays open.
        drop(out_rx);
        let _ = conn.write_all(b"y");
        assert_closed(&mut conn);

        drop(in_out);
        h.join().unwrap().unwrap();

        // Direct Conns check: a broken output pipe removes the entry from Conns.
        let conns = Arc::new(Conns::default());
        let (out_rx, out_tx) = io::pipe().unwrap();
        drop(out_rx);
        let out: Out = Arc::new(Mutex::new(out_tx));
        let OpenOutcome::Opened(rx) = conns.open(1) else { panic!("expected Opened") };
        let client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (mut peer, _) = proxy.accept().unwrap();
        attach(&conns, &out, 1, rx, client);
        assert!(conns.state().entries.contains_key(&1));
        peer.write_all(b"z").unwrap();
        assert_closed(&mut peer);
        assert!(conns.state().entries.is_empty());
    }

    #[test]
    fn connections_attaching_or_arriving_after_close_all_are_shut_down() {
        let proxy = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = proxy.local_addr().unwrap().port();
        let (_out_rx, out_tx) = io::pipe().unwrap();
        let out: Out = Arc::new(Mutex::new(out_tx));

        // 1. An in-flight connection opened before close_all() that reaches attach() after close_all().
        let conns = Arc::new(Conns::default());
        let OpenOutcome::Opened(rx) = conns.open(1) else { panic!("expected Opened") };
        conns.close_all();
        let client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (mut peer, _) = proxy.accept().unwrap();
        attach(&conns, &out, 1, rx, client);
        assert_closed(&mut peer);
        assert!(conns.state().entries.is_empty());

        // 2. A new TCP connection arriving at listen_side's listener after listen_side has torn down.
        let (in_rx, in_tx) = io::pipe().unwrap();
        let (mut out_rx, out_tx) = io::pipe().unwrap();
        let in_out: Out = Arc::new(Mutex::new(in_tx));
        let listen_out: Out = Arc::new(Mutex::new(out_tx));
        let o = listen_out.clone();
        let h = std::thread::spawn(move || listen_side(in_rx, &o));

        send(&in_out, LISTEN, 0, &port.to_be_bytes()).unwrap();
        let Some((LISTENING, 0, reply)) = read_frame(&mut out_rx).unwrap() else { panic!("expected LISTENING") };
        let local = port_of(&reply, 2).unwrap();

        drop(in_out);
        h.join().unwrap().unwrap();
        drop(listen_out);

        if let Ok(mut late) = TcpStream::connect(("127.0.0.1", local)) {
            assert_closed(&mut late);
        }
        assert!(read_frame(&mut out_rx).unwrap().is_none(), "no OPEN frame emitted after teardown");
    }

    #[test]
    fn host_gateway_target_validates_ip_and_port() {
        assert_eq!(host_gateway_target(WSL_HOST_ADDR, 17433, WSL_HOST_ADDR), Some(17433));
        assert_eq!(host_gateway_target(WSL_HOST_ADDR, 80, WSL_HOST_ADDR), Some(80));
        assert_eq!(host_gateway_target(WSL_HOST_ADDR, 0, WSL_HOST_ADDR), None, "port 0 rejected");
        assert_eq!(host_gateway_target(WSL_HOST_ADDR, 53, WSL_HOST_ADDR), None, "DNS port 53 excluded");
        assert_eq!(host_gateway_target([172, 17, 0, 1], 17433, WSL_HOST_ADDR), None, "wrong IP rejected");
        assert_eq!(host_gateway_target([127, 0, 0, 1], 17433, WSL_HOST_ADDR), None, "loopback rejected");
    }

    #[test]
    fn dial_side_with_host_allows_dynamic_ipv4_and_ipv6_ports_and_rejects_port_zero() {
        let srv4 = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port4 = srv4.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = srv4.accept() {
                let _ = s.write_all(b"v4-ok");
            }
        });
        let srv6 = TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0)).ok();
        let port6 = srv6.as_ref().map(|l| l.local_addr().unwrap().port());
        if let Some(l) = srv6 {
            std::thread::spawn(move || {
                if let Ok((mut s, _)) = l.accept() {
                    let _ = s.write_all(b"v6-ok");
                }
            });
        }
        let (in_rx, in_tx) = io::pipe().unwrap();
        let (mut out_rx, out_tx) = io::pipe().unwrap();
        let in_out: Out = Arc::new(Mutex::new(in_tx));
        let dial_out: Out = Arc::new(Mutex::new(out_tx));
        let o = dial_out.clone();
        let got_host = Arc::new(std::sync::atomic::AtomicU16::new(0));
        let gh = got_host.clone();
        let h = std::thread::spawn(move || {
            dial_side_with_host(in_rx, &o, |_| true, |_, _| {}, move |p| gh.store(p, Ordering::SeqCst))
        });

        // LISTENING_HOST delivers the reported relay port.
        send(&in_out, LISTENING_HOST, 0, &41234u16.to_be_bytes()).unwrap();
        // Port 0 is always refused even when `allowed` returns true.
        send(&in_out, OPEN, 1, &0u16.to_be_bytes()).unwrap();
        assert_eq!(read_frame(&mut out_rx).unwrap(), Some((CLOSE, 1, vec![])));
        assert_eq!(got_host.load(Ordering::SeqCst), 41234);

        // IPv4 loopback server reachable dynamically without prior LISTEN.
        send(&in_out, OPEN, 2, &port4.to_be_bytes()).unwrap();
        assert_eq!(read_frame(&mut out_rx).unwrap(), Some((DATA, 2, b"v4-ok".to_vec())));
        assert_eq!(read_frame(&mut out_rx).unwrap(), Some((EOF, 2, vec![])));

        // IPv6-only loopback server reachable via ConnectionRefused fallback.
        if let Some(p6) = port6 {
            send(&in_out, OPEN, 3, &p6.to_be_bytes()).unwrap();
            assert_eq!(read_frame(&mut out_rx).unwrap(), Some((DATA, 3, b"v6-ok".to_vec())));
            assert_eq!(read_frame(&mut out_rx).unwrap(), Some((EOF, 3, vec![])));
        }

        drop(in_out);
        h.join().unwrap().unwrap();
    }

    #[test]
    fn host_gateway_lock_serializes_setup_and_teardown_and_checks_owner_pid() {
        let dir = std::env::temp_dir().join(format!("kiri-hostrelay-lock-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let lock = dir.join("kiri-hostrelay.lock");
        let pid_path = dir.join("kiri-hostrelay.pid");

        // 1. Failed setup never creates a stale pidfile.
        let err = acquire_host_gateway(&lock, &pid_path, 111, || Err::<(), _>(io::Error::other("boom")), |_| panic!("rollback on setup err"));
        assert!(err.is_err());
        assert!(!pid_path.exists(), "failed setup must not leave a pidfile");

        // 2. Relay 1 acquires; a concurrent failed start of relay 2 must not clobber relay 1's pidfile.
        acquire_host_gateway(&lock, &pid_path, 111, || Ok(()), |_| {}).unwrap();
        assert_eq!(read_pid_file(&pid_path), Some(111));
        assert!(acquire_host_gateway(&lock, &pid_path, 222, || Err::<(), _>(io::Error::other("bind failed")), |_| {}).is_err());
        assert_eq!(read_pid_file(&pid_path), Some(111));

        // 3. Rollback fires if writing the pidfile fails (e.g., pid_path is a directory).
        let bad_pid = dir.join("pid-dir");
        std::fs::create_dir_all(&bad_pid).unwrap();
        let rolled_back = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let rb = rolled_back.clone();
        assert!(acquire_host_gateway(&lock, &bad_pid, 333, || Ok(42u32), move |v| {
            assert_eq!(v, 42);
            rb.store(true, Ordering::SeqCst);
        })
        .is_err());
        assert!(rolled_back.load(Ordering::SeqCst));

        // 4. Simulate the Drop race: relay 2 holds the flock while taking over;
        //    relay 1's Drop waits on the flock, then sees relay 2's PID and does NOT tear down.
        let guard = lock_host_gateway(&lock).unwrap();
        let lock2 = lock.clone();
        let pid2 = pid_path.clone();
        let old_tore_down = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let otd = old_tore_down.clone();
        let drop_thread = std::thread::spawn(move || {
            release_host_gateway(&lock2, &pid2, 111, move || otd.store(true, Ordering::SeqCst));
        });
        std::thread::sleep(Duration::from_millis(30));
        assert!(!old_tore_down.load(Ordering::SeqCst), "old Drop must wait for the flock");
        write_pid_file(&pid_path, 222).unwrap();
        drop(guard);
        drop_thread.join().unwrap();
        assert!(!old_tore_down.load(Ordering::SeqCst), "old Drop must not tear down newer relay");
        assert_eq!(read_pid_file(&pid_path), Some(222), "newer relay's pidfile preserved");

        // 5. When relay 2 itself drops, it is the active owner so it removes the pidfile and tears down.
        let new_tore_down = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ntd = new_tore_down.clone();
        release_host_gateway(&lock, &pid_path, 222, move || ntd.store(true, Ordering::SeqCst));
        assert!(new_tore_down.load(Ordering::SeqCst));
        assert!(!pid_path.exists());

        // 6. A missing pidfile must NEVER trigger teardown for a stale Drop.
        let ghost_tore_down = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gtd = ghost_tore_down.clone();
        release_host_gateway(&lock, &pid_path, 111, move || gtd.store(true, Ordering::SeqCst));
        assert!(!ghost_tore_down.load(Ordering::SeqCst));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn host_gateway_liveness_detects_live_and_dead_pids_and_cmdline() {
        let dir = std::env::temp_dir().join(format!("kiri-hostrelay-live-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pid_path = dir.join("kiri-hostrelay.pid");

        // Missing or invalid pidfile -> inactive.
        assert!(!pid_file_alive(&pid_path, |_| true));
        std::fs::write(&pid_path, "not-a-pid\n").unwrap();
        assert!(!pid_file_alive(&pid_path, |_| true));
        std::fs::write(&pid_path, "0\n").unwrap();
        assert!(!pid_file_alive(&pid_path, |_| true));

        // Live PID (current test process) -> active iff cmdline verifier passes.
        write_pid_file(&pid_path, std::process::id()).unwrap();
        assert!(pid_file_alive(&pid_path, |_| true));
        assert!(!pid_file_alive(&pid_path, |_| false));

        // Dead PID (exited & reaped child, simulating kill -9 leaving stale pidfile) -> inactive.
        let mut child = std::process::Command::new("/bin/sh").args(["-c", "exit 0"]).spawn().unwrap();
        let dead_pid = child.id();
        let _ = child.wait().unwrap();
        write_pid_file(&pid_path, dead_pid).unwrap();
        assert!(!pid_file_alive(&pid_path, |_| true), "dead PID must be treated as inactive");

        // Cmdline matching: accepts `kiri hostrelay`, rejects zombies and reused PIDs.
        assert!(is_hostrelay_cmdline(b"/usr/local/bin/kiri\0hostrelay\0"));
        assert!(is_hostrelay_cmdline(b"kiri\0hostrelay"));
        assert!(!is_hostrelay_cmdline(b"/usr/local/bin/kiri\0daemon\0"));
        assert!(!is_hostrelay_cmdline(b"/bin/sh\0-c\0hostrelay\0"));
        assert!(!is_hostrelay_cmdline(b""));
        assert!(!is_hostrelay_cmdline(b"\0hostrelay\0"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stalled_connection_does_not_freeze_multiplexer_and_conn_cap_is_enforced() {
        let conns = Arc::new(Conns::default());
        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        struct SharedVec(Arc<Mutex<Vec<u8>>>);
        impl Write for SharedVec {
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let out: Out = Arc::new(Mutex::new(SharedVec(buf.clone())));

        let OpenOutcome::Opened(_rx1_stalled) = conns.open(1) else {
            panic!("conn 1 should open");
        };
        let OpenOutcome::Opened(rx2_healthy) = conns.open(2) else {
            panic!("conn 2 should open");
        };

        // Flood conn 1 past QUEUE (64 frames) with nobody reading _rx1_stalled:
        // dispatch MUST NOT block, must close conn 1 and emit a CLOSE frame for id 1.
        for _ in 0..(QUEUE + 8) {
            conns.dispatch(&out, DATA, 1, vec![0xaa; 16]);
        }
        // Conn 2 must still receive frames immediately.
        conns.dispatch(&out, DATA, 2, b"ok".to_vec());
        match rx2_healthy.recv_timeout(Duration::from_secs(1)).unwrap() {
            Op::Data(d) => assert_eq!(d, b"ok"),
            Op::Eof => panic!("unexpected EOF on conn 2"),
        }
        // Verify CLOSE frame for conn 1 was emitted.
        let wire = buf.lock().unwrap().clone();
        let mut cursor = io::Cursor::new(wire);
        let (kind, id, data) = read_frame(&mut cursor).unwrap().unwrap();
        assert_eq!((kind, id, data.len()), (CLOSE, 1, 0));

        // Verify MAX_CONNS cap rejects excess opens without closing existing ones.
        let mut held = Vec::new();
        for id in 10..(10 + MAX_CONNS as u32) {
            match conns.open(id) {
                OpenOutcome::Opened(rx) => held.push(rx),
                OpenOutcome::Full => break,
                OpenOutcome::Closed => panic!("unexpected closed"),
            }
        }
        assert!(matches!(conns.open(999_999), OpenOutcome::Full));
        conns.close_all();
        assert!(matches!(conns.open(1_000_000), OpenOutcome::Closed));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_gateway_nft_batch_matches_bridges_output_and_guards_input() {
        let batch = host_net::install_batch(WSL_HOST_ADDR, 45678);
        assert_eq!(batch.len(), 11);
        let has = |m: &host_net::Msg, needle: &[u8]| m.buf.windows(needle.len()).any(|w| w == needle);
        let pre = &batch[7];
        let out = &batch[8];
        let guard = &batch[9];
        // prerouting DNAT matches iifname "kiri*", daddr 192.168.65.254, tcp dport != 53 -> :45678
        assert!(has(pre, b"kiri_host\0") && has(pre, b"prerouting\0"));
        assert!(has(pre, b"kiri") && has(pre, &WSL_HOST_ADDR) && has(pre, &53u16.to_be_bytes()) && has(pre, &45678u16.to_be_bytes()));
        // output DNAT has no bridge iifname match, still skips port 53
        assert!(has(out, b"output\0") && has(out, &WSL_HOST_ADDR) && has(out, &53u16.to_be_bytes()) && has(out, &45678u16.to_be_bytes()));
        // input guard drops non-kiri*, non-lo traffic to 192.168.65.254
        let mut lo_full = [0u8; 16];
        lo_full[..2].copy_from_slice(b"lo");
        assert!(has(guard, b"input\0") && has(guard, &WSL_HOST_ADDR) && has(guard, &lo_full));
    }
}
