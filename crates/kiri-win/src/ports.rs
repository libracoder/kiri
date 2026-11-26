//! Published container ports on Windows (`#640`, `#218`).
//!
//! WSL 2's built-in `localhostForwarding` (`wslrelay.exe`) only forwards TCP on
//! Windows loopback (`127.0.0.1:<port>/tcp` and `[::1]:<port>/tcp`):
//! - It never forwards UDP at all (`#640`).
//! - It never binds non-loopback Windows host interface addresses (`<WinLANIP>`)
//!   for `-p 0.0.0.0:port:cport` or `-p <WinLANIP>:port:cport` (`#218`).
//!
//! This module pushes the Windows host's interface IPs to the WSL daemon via
//! `POST /kiri/win-ports` (so `-p <WinLANIP>:port:cport` binds WSL's internal
//! `eth0` IP without leaking `127.0.0.1:port` on Windows, while bogus IPs still
//! fail with `Address not available (os error 99)`), and maintains Windows-side
//! UDP and non-loopback TCP forwarders to `<wsl_eth0_ip>:<port>`.

#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::{BTreeSet, HashMap};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Idle timeout for a per-client UDP forwarding session, matching conntrack.
const UDP_IDLE: Duration = Duration::from_secs(60);
/// Read timeout on UDP sockets so the loop can check `stop` and reap idle sessions.
const UDP_POLL: Duration = Duration::from_millis(250);
/// Poll interval on non-blocking `TcpListener::accept` so `stop()` joins within ~100ms
/// without needing a self-connect that could hang if the bound IP disappeared.
const TCP_ACCEPT_POLL: Duration = Duration::from_millis(100);
/// Maximum concurrent UDP client sessions per published UDP port.
const MAX_UDP_SESSIONS: usize = 1024;
/// Connect timeout when dialing the WSL 2 `eth0` target for a forwarded TCP connection.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PublishedPort {
    pub proto: String,
    pub host_ip: String,
    pub host_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ForwardSpec {
    pub proto: Proto,
    pub bind_addr: SocketAddr,
    pub target_addr: SocketAddr,
}

/// Parses a bare or bracketed IPv4/IPv6 address, stripping any `%scope` suffix.
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    let bare = s.trim().strip_prefix('[').and_then(|i| i.strip_suffix(']')).unwrap_or(s.trim());
    let bare = bare.split('%').next().unwrap_or(bare);
    bare.parse::<IpAddr>().ok().map(|a| a.to_canonical())
}

/// Computes the Windows-side TCP and UDP listeners needed for `published`,
/// forwarding to `wsl_ip:<host_port>`:
/// - UDP: every published UDP port (`0.0.0.0:port`, `[::]:port`, `127.0.0.1:port`,
///   `[::1]:port`, or `<host_ip>:port`), since `wslrelay.exe` never forwards UDP.
/// - TCP:
///   - `127.0.0.1` and `::1` are left to `wslrelay.exe`.
///   - `0.0.0.0` (or `""`) expands to every non-loopback Windows IPv4 interface
///     address in `win_ipv4` so `-p 0.0.0.0:port:cport` answers on both
///     `127.0.0.1:port` (via `wslrelay.exe`) and `<WinLANIP>:port`.
///   - `::` expands to every non-loopback global Windows IPv6 interface address
///     in `win_ipv6`.
///   - A specific non-loopback `<WinLANIP>` binds `<WinLANIP>:port` alone.
pub fn plan_forwards(
    wsl_ip: Ipv4Addr,
    published: &[PublishedPort],
    win_ipv4: &[Ipv4Addr],
    win_ipv6: &[Ipv6Addr],
) -> Vec<ForwardSpec> {
    // In WSL 2 mirrored or bridged networking mode, `wsl_ip` is itself one of
    // the Windows host's interface addresses; skip Windows-side forwarding so
    // we never create a self-forwarding loop.
    if wsl_ip.is_loopback() || wsl_ip.is_unspecified() || win_ipv4.contains(&wsl_ip) {
        return Vec::new();
    }
    let mut specs = BTreeSet::new();
    for p in published {
        if p.host_port == 0 {
            continue;
        }
        let target_addr = SocketAddr::V4(SocketAddrV4::new(wsl_ip, p.host_port));
        let host_ip = p.host_ip.trim();
        let proto = p.proto.to_ascii_lowercase();
        match proto.as_str() {
            "udp" => {
                if host_ip.is_empty() || host_ip == "0.0.0.0" {
                    specs.insert(ForwardSpec {
                        proto: Proto::Udp,
                        bind_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, p.host_port)),
                        target_addr,
                    });
                } else if host_ip == "::" || host_ip == "[::]" {
                    specs.insert(ForwardSpec {
                        proto: Proto::Udp,
                        bind_addr: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, p.host_port, 0, 0)),
                        target_addr,
                    });
                } else if let Some(ip) = parse_ip(host_ip)
                    && ip != IpAddr::V4(wsl_ip)
                {
                    specs.insert(ForwardSpec {
                        proto: Proto::Udp,
                        bind_addr: SocketAddr::new(ip, p.host_port),
                        target_addr,
                    });
                }
            }
            "tcp" => {
                if host_ip.is_empty() || host_ip == "0.0.0.0" {
                    for &ip4 in win_ipv4 {
                        if !ip4.is_loopback()
                            && !ip4.is_unspecified()
                            && !ip4.is_multicast()
                            && !(ip4.octets()[0] == 169 && ip4.octets()[1] == 254)
                            && ip4 != wsl_ip
                        {
                            specs.insert(ForwardSpec {
                                proto: Proto::Tcp,
                                bind_addr: SocketAddr::V4(SocketAddrV4::new(ip4, p.host_port)),
                                target_addr,
                            });
                        }
                    }
                } else if host_ip == "::" || host_ip == "[::]" {
                    for &ip6 in win_ipv6 {
                        if !ip6.is_loopback()
                            && !ip6.is_unspecified()
                            && !ip6.is_multicast()
                            && (ip6.segments()[0] & 0xffc0) != 0xfe80
                        {
                            specs.insert(ForwardSpec {
                                proto: Proto::Tcp,
                                bind_addr: SocketAddr::V6(SocketAddrV6::new(ip6, p.host_port, 0, 0)),
                                target_addr,
                            });
                        }
                    }
                } else if let Some(ip) = parse_ip(host_ip)
                    && !ip.is_loopback()
                    && !ip.is_unspecified()
                    && !ip.is_multicast()
                    && ip != IpAddr::V4(wsl_ip)
                {
                    specs.insert(ForwardSpec {
                        proto: Proto::Tcp,
                        bind_addr: SocketAddr::new(ip, p.host_port),
                        target_addr,
                    });
                }
            }
            _ => {}
        }
    }
    specs.into_iter().collect()
}

/// Whether the initial bytes of an HTTP request on Kiri's pipe represent a
/// container or engine lifecycle mutation that can create, start, stop, or
/// update published ports.
pub fn is_port_affecting_request(head: &[u8]) -> bool {
    let line_end = head.iter().position(|&b| b == b'\r' || b == b'\n').unwrap_or(head.len().min(256));
    let Ok(line) = std::str::from_utf8(&head[..line_end]) else {
        return false;
    };
    let mut parts = line.split_whitespace();
    let Some(method) = parts.next() else {
        return false;
    };
    let Some(path) = parts.next() else {
        return false;
    };
    if !matches!(method, "POST" | "DELETE") {
        return false;
    }
    let path = path.split('?').next().unwrap_or(path);
    path.contains("/containers")
        || matches!(path, "/kiri/stop" | "/kiri/sleep" | "/kiri/wake")
}

fn wake_connect_addr(bound: SocketAddr) -> SocketAddr {
    match bound {
        SocketAddr::V4(v4) if v4.ip().is_unspecified() => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, v4.port())),
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, v6.port(), 0, 0)),
        other => other,
    }
}

pub struct TcpForwarder {
    local_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl TcpForwarder {
    pub fn start(bind_addr: SocketAddr, target_addr: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(bind_addr)?;
        listener.set_nonblocking(true)?;
        let local_addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_loop = stop.clone();
        let thread = std::thread::Builder::new()
            .name(format!("kiri-win-tcp-{}", local_addr.port()))
            .spawn(move || tcp_accept_loop(listener, target_addr, stop_loop))?;
        Ok(TcpForwarder {
            local_addr,
            stop,
            thread: Some(thread),
        })
    }

    #[cfg(test)]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stop(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for TcpForwarder {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

fn tcp_accept_loop(listener: TcpListener, target_addr: SocketAddr, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::SeqCst) {
        let (client, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(TCP_ACCEPT_POLL);
                continue;
            }
            Err(_) => {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(TCP_ACCEPT_POLL);
                continue;
            }
        };
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let _ = client.set_nonblocking(false);
        let _ = std::thread::Builder::new().name("kiri-win-tcp-conn".into()).spawn(move || {
            let _ = relay_tcp_conn(client, target_addr);
        });
    }
}

fn relay_tcp_conn(client: TcpStream, target_addr: SocketAddr) -> io::Result<()> {
    let backend = TcpStream::connect_timeout(&target_addr, TCP_CONNECT_TIMEOUT)?;
    let _ = client.set_nodelay(true);
    let _ = backend.set_nodelay(true);
    let mut client_read = client.try_clone()?;
    let mut backend_write = backend.try_clone()?;
    let up = std::thread::Builder::new().name("kiri-win-tcp-up".into()).spawn(move || {
        let how = if copy_stream(&mut client_read, &mut backend_write).is_ok() {
            Shutdown::Write
        } else {
            Shutdown::Both
        };
        let _ = backend_write.shutdown(how);
    })?;
    let mut backend_read = backend;
    let mut client_write = client;
    let how = if copy_stream(&mut backend_read, &mut client_write).is_ok() {
        Shutdown::Write
    } else {
        Shutdown::Both
    };
    let _ = client_write.shutdown(how);
    let _ = up.join();
    Ok(())
}

fn copy_stream(from: &mut impl Read, to: &mut impl Write) -> io::Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        to.write_all(&buf[..n])?;
    }
}

struct UdpClientSession {
    backend: UdpSocket,
    target_addr: SocketAddr,
    last: Arc<Mutex<Instant>>,
    stop: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
}

impl UdpClientSession {
    fn open(listener: &UdpSocket, target_addr: SocketAddr, client_addr: SocketAddr) -> io::Result<Self> {
        let bind_any = if target_addr.is_ipv6() {
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
        } else {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        };
        let backend = UdpSocket::bind(bind_any)?;
        disable_udp_connreset(&backend);
        let backend_read = backend.try_clone()?;
        backend_read.set_read_timeout(Some(UDP_POLL))?;
        let reply_sock = listener.try_clone()?;
        let last = Arc::new(Mutex::new(Instant::now()));
        let last_r = last.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_r = stop.clone();
        let reader = std::thread::Builder::new().name("kiri-win-udp-reply".into()).spawn(move || {
            let mut rbuf = vec![0u8; 65_536];
            while !stop_r.load(Ordering::SeqCst) {
                match backend_read.recv_from(&mut rbuf) {
                    Ok((n, from)) => {
                        if stop_r.load(Ordering::SeqCst) {
                            break;
                        }
                        if from == target_addr {
                            *last_r.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now();
                            let _ = reply_sock.send_to(&rbuf[..n], client_addr);
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::ConnectionReset | io::ErrorKind::Interrupted
                        ) =>
                    {
                        if last_r.lock().unwrap_or_else(PoisonError::into_inner).elapsed() >= UDP_IDLE {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        })?;
        Ok(UdpClientSession { backend, target_addr, last, stop, reader: Some(reader) })
    }

    fn send(&self, payload: &[u8]) -> io::Result<usize> {
        self.backend.send_to(payload, self.target_addr)
    }

    fn is_finished(&self) -> bool {
        self.reader.as_ref().is_none_or(JoinHandle::is_finished)
    }

    fn last_active(&self) -> Instant {
        *self.last.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn touch(&self) {
        *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now();
    }

    fn stop_inner(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(r) = self.reader.take() {
            if !r.is_finished()
                && let Ok(local) = self.backend.local_addr()
            {
                let wake_target = wake_connect_addr(local);
                let bind_any = if wake_target.is_ipv6() {
                    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
                } else {
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
                };
                if let Ok(waker) = UdpSocket::bind(bind_any) {
                    let _ = waker.send_to(&[], wake_target);
                }
            }
            let _ = r.join();
        }
    }

    fn close(mut self) {
        self.stop_inner();
    }
}

impl Drop for UdpClientSession {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

pub struct UdpForwarder {
    local_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl UdpForwarder {
    pub fn start(bind_addr: SocketAddr, target_addr: SocketAddr) -> io::Result<Self> {
        let listener = UdpSocket::bind(bind_addr)?;
        disable_udp_connreset(&listener);
        listener.set_read_timeout(Some(UDP_POLL))?;
        let local_addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_loop = stop.clone();
        let thread = std::thread::Builder::new()
            .name(format!("kiri-win-udp-{}", local_addr.port()))
            .spawn(move || udp_forward_loop(listener, target_addr, stop_loop))?;
        Ok(UdpForwarder {
            local_addr,
            stop,
            thread: Some(thread),
        })
    }

    #[cfg(test)]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stop(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let wake_target = wake_connect_addr(self.local_addr);
        let bind_any = if wake_target.is_ipv6() {
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
        } else {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        };
        if let Ok(waker) = UdpSocket::bind(bind_any) {
            let _ = waker.send_to(&[], wake_target);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for UdpForwarder {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

fn udp_forward_loop(listener: UdpSocket, target_addr: SocketAddr, stop: Arc<AtomicBool>) {
    let mut sessions: HashMap<SocketAddr, UdpClientSession> = HashMap::new();
    let mut buf = vec![0u8; 65_536];
    let mut last_reap = Instant::now();
    while !stop.load(Ordering::SeqCst) {
        match listener.recv_from(&mut buf) {
            Ok((len, peer)) => {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let stale = sessions.get(&peer).is_some_and(UdpClientSession::is_finished);
                if stale && let Some(old) = sessions.remove(&peer) {
                    old.close();
                }
                if !sessions.contains_key(&peer) {
                    if sessions.len() >= MAX_UDP_SESSIONS
                        && let Some(oldest) = sessions.iter().min_by_key(|(_, s)| s.last_active()).map(|(k, _)| *k)
                        && let Some(old) = sessions.remove(&oldest)
                    {
                        old.close();
                    }
                    match UdpClientSession::open(&listener, target_addr, peer) {
                        Ok(s) => {
                            sessions.insert(peer, s);
                        }
                        Err(_) => continue,
                    }
                }
                if let Some(s) = sessions.get(&peer) {
                    s.touch();
                    if s.send(&buf[..len]).is_err()
                        && let Some(dead) = sessions.remove(&peer)
                    {
                        dead.close();
                    }
                }
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::ConnectionReset | io::ErrorKind::Interrupted) => {}
            Err(_) => {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
            }
        }
        if last_reap.elapsed() >= Duration::from_secs(1) {
            last_reap = Instant::now();
            let expired: Vec<SocketAddr> = sessions.iter().filter(|(_, s)| s.last_active().elapsed() >= UDP_IDLE || s.is_finished()).map(|(k, _)| *k).collect();
            for k in expired {
                if let Some(s) = sessions.remove(&k) {
                    s.close();
                }
            }
        }
    }
    for (_, s) in sessions.drain() {
        s.close();
    }
}

/// Disables WinSock's `SIO_UDP_CONNRESET` on `sock` so an ICMP Port Unreachable
/// from one closed client does not make the next `recv_from` return `WSAECONNRESET`.
#[cfg(windows)]
fn disable_udp_connreset(sock: &UdpSocket) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{WSAIoctl, SOCKET};
    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;
    let enable: u32 = 0;
    let mut bytes_returned: u32 = 0;
    // SAFETY: valid socket handle and 4-byte boolean buffer for SIO_UDP_CONNRESET.
    unsafe {
        let _ = WSAIoctl(
            sock.as_raw_socket() as SOCKET,
            SIO_UDP_CONNRESET,
            (&enable as *const u32).cast(),
            std::mem::size_of::<u32>() as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            None,
        );
    }
}

#[cfg(not(windows))]
fn disable_udp_connreset(_sock: &UdpSocket) {}

#[cfg(windows)]
mod runtime {
    use super::*;
    use std::collections::HashSet;
    use std::os::windows::io::AsRawSocket;
    use std::sync::Condvar;
    use serde_json::json;
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, SIO_ADDRESS_LIST_QUERY, SOCKADDR_IN, SOCKADDR_IN6, SOCKET, SOCKET_ADDRESS_LIST, WSAIoctl,
    };

    const RESYNC_INTERVAL: Duration = Duration::from_secs(3);

    enum ActiveForwarder {
        Tcp(TcpForwarder),
        Udp(UdpForwarder),
    }

    impl ActiveForwarder {
        fn stop(self) {
            match self {
                ActiveForwarder::Tcp(f) => f.stop(),
                ActiveForwarder::Udp(f) => f.stop(),
            }
        }
    }

    static ACTIVE: AtomicBool = AtomicBool::new(false);
    static WAKE: std::sync::LazyLock<(Mutex<bool>, Condvar)> = std::sync::LazyLock::new(|| (Mutex::new(false), Condvar::new()));
    static SYNC_LOCK: Mutex<()> = Mutex::new(());
    static LAST_SYNC: Mutex<Option<Instant>> = Mutex::new(None);
    static FORWARDERS: std::sync::LazyLock<Mutex<HashMap<ForwardSpec, ActiveForwarder>>> = std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

    /// Queries WinSock `SIO_ADDRESS_LIST_QUERY` for all active local IPv4 and
    /// IPv6 interface addresses on the Windows host.
    pub fn query_windows_host_ips() -> (Vec<String>, Vec<Ipv4Addr>, Vec<Ipv6Addr>) {
        let mut all = BTreeSet::from(["127.0.0.1".to_owned(), "::1".to_owned()]);
        let mut v4_set = BTreeSet::new();
        let mut v6_set = BTreeSet::new();

        if let Ok(sock4) = UdpSocket::bind("127.0.0.1:0") {
            let mut buf = vec![0usize; 2048];
            let cap = (buf.len() * std::mem::size_of::<usize>()) as u32;
            let mut returned = 0u32;
            // SAFETY: `buf` is usize-aligned and sized to `cap` bytes for SOCKET_ADDRESS_LIST.
            let rc = unsafe {
                WSAIoctl(
                    sock4.as_raw_socket() as SOCKET,
                    SIO_ADDRESS_LIST_QUERY,
                    std::ptr::null(),
                    0,
                    buf.as_mut_ptr().cast(),
                    cap,
                    &mut returned,
                    std::ptr::null_mut(),
                    None,
                )
            };
            if rc == 0 && (returned as usize) >= std::mem::size_of::<SOCKET_ADDRESS_LIST>() {
                // SAFETY: WSAIoctl succeeded and filled ` SOCKET_ADDRESS_LIST` inside `buf`.
                unsafe {
                    let list = &*(buf.as_ptr() as *const SOCKET_ADDRESS_LIST);
                    let count = (list.iAddressCount.max(0) as usize).min(256);
                    let addrs = std::slice::from_raw_parts(list.Address.as_ptr(), count);
                    for entry in addrs {
                        if !entry.lpSockaddr.is_null()
                            && (entry.iSockaddrLength as usize) >= std::mem::size_of::<SOCKADDR_IN>()
                            && (*entry.lpSockaddr).sa_family == AF_INET
                        {
                            let sin = &*(entry.lpSockaddr as *const SOCKADDR_IN);
                            let ip = Ipv4Addr::from(sin.sin_addr.S_un.S_addr.to_ne_bytes());
                            if !ip.is_unspecified() && !ip.is_multicast() {
                                all.insert(ip.to_string());
                                if !ip.is_loopback() && !(ip.octets()[0] == 169 && ip.octets()[1] == 254) {
                                    v4_set.insert(ip);
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Ok(sock6) = UdpSocket::bind("[::1]:0") {
            let mut buf = vec![0usize; 2048];
            let cap = (buf.len() * std::mem::size_of::<usize>()) as u32;
            let mut returned = 0u32;
            // SAFETY: `buf` is usize-aligned and sized to `cap` bytes for SOCKET_ADDRESS_LIST.
            let rc = unsafe {
                WSAIoctl(
                    sock6.as_raw_socket() as SOCKET,
                    SIO_ADDRESS_LIST_QUERY,
                    std::ptr::null(),
                    0,
                    buf.as_mut_ptr().cast(),
                    cap,
                    &mut returned,
                    std::ptr::null_mut(),
                    None,
                )
            };
            if rc == 0 && (returned as usize) >= std::mem::size_of::<SOCKET_ADDRESS_LIST>() {
                // SAFETY: WSAIoctl succeeded and filled `SOCKET_ADDRESS_LIST` inside `buf`.
                unsafe {
                    let list = &*(buf.as_ptr() as *const SOCKET_ADDRESS_LIST);
                    let count = (list.iAddressCount.max(0) as usize).min(256);
                    let addrs = std::slice::from_raw_parts(list.Address.as_ptr(), count);
                    for entry in addrs {
                        if !entry.lpSockaddr.is_null()
                            && (entry.iSockaddrLength as usize) >= std::mem::size_of::<SOCKADDR_IN6>()
                            && (*entry.lpSockaddr).sa_family == AF_INET6
                        {
                            let sin6 = &*(entry.lpSockaddr as *const SOCKADDR_IN6);
                            let ip = Ipv6Addr::from(sin6.sin6_addr.u.Byte);
                            if !ip.is_unspecified() && !ip.is_multicast() {
                                all.insert(ip.to_string());
                                if !ip.is_loopback() && (ip.segments()[0] & 0xffc0) != 0xfe80 {
                                    v6_set.insert(ip);
                                }
                            }
                        }
                    }
                }
            }
        }

        (
            all.into_iter().collect(),
            v4_set.into_iter().collect(),
            v6_set.into_iter().collect(),
        )
    }

    fn clear_all_forwarders() {
        let old: Vec<ActiveForwarder> = FORWARDERS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
            .map(|(_, f)| f)
            .collect();
        for f in old {
            f.stop();
        }
    }

    /// Synchronizes Windows host interface IPs and published container port
    /// forwarders with the WSL daemon right now.
    pub fn sync_now() {
        if !ACTIVE.load(Ordering::Relaxed) {
            return;
        }
        let _guard = SYNC_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        if crate::serve::is_stopped() {
            clear_all_forwarders();
            return;
        }
        let (all_ips, win_v4, win_v6) = query_windows_host_ips();
        let body = json!({ "host_ips": all_ips });
        let resp = match crate::client::request_within("POST", "/kiri/win-ports", Some(&body), true, Some(Duration::from_secs(3))) {
            Ok(r) => r,
            // Do not tear down active port forwarders on a transient HTTP
            // read timeout when WSL is still running and busy.
            Err(e) if matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => return,
            Err(_) => {
                clear_all_forwarders();
                return;
            }
        };
        if !resp.ok() {
            if resp.status == 503 || resp.error().contains("stopped") || resp.error().contains("did not start") {
                clear_all_forwarders();
            }
            return;
        }
        *LAST_SYNC.lock().unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
        let payload = resp.json();
        let Some(wsl_ip) = payload["wsl_ip"].as_str().and_then(|s| s.parse::<Ipv4Addr>().ok()) else {
            clear_all_forwarders();
            return;
        };
        let mut published = Vec::new();
        for item in payload["ports"].as_array().into_iter().flatten() {
            let Some(proto) = item["proto"].as_str() else { continue };
            let host_ip = item["host_ip"].as_str().unwrap_or("").to_owned();
            let Some(host_port) = item["host_port"].as_u64().and_then(|p| u16::try_from(p).ok()) else { continue };
            published.push(PublishedPort {
                proto: proto.to_owned(),
                host_ip,
                host_port,
            });
        }
        let want = plan_forwards(wsl_ip, &published, &win_v4, &win_v6);
        let want_set: HashSet<ForwardSpec> = want.iter().cloned().collect();

        let to_stop: Vec<ActiveForwarder> = {
            let mut active = FORWARDERS.lock().unwrap_or_else(PoisonError::into_inner);
            let remove_keys: Vec<ForwardSpec> = active.keys().filter(|k| !want_set.contains(*k)).cloned().collect();
            remove_keys.into_iter().filter_map(|k| active.remove(&k)).collect()
        };
        for f in to_stop {
            f.stop();
        }

        let mut active = FORWARDERS.lock().unwrap_or_else(PoisonError::into_inner);
        for spec in want {
            if active.contains_key(&spec) {
                continue;
            }
            let started = match spec.proto {
                Proto::Tcp => TcpForwarder::start(spec.bind_addr, spec.target_addr).map(ActiveForwarder::Tcp),
                Proto::Udp => UdpForwarder::start(spec.bind_addr, spec.target_addr).map(ActiveForwarder::Udp),
            };
            match started {
                Ok(fwd) => {
                    active.insert(spec, fwd);
                }
                Err(e) => {
                    crate::serve::log(&format!("ports: could not bind {:?} {} -> {}: {e}", spec.proto, spec.bind_addr, spec.target_addr));
                }
            }
        }
    }

    /// Ensures the WSL daemon has received the Windows host's current interface
    /// IPs before a container create/start request is processed.
    pub fn before_container_op() {
        if !ACTIVE.load(Ordering::Relaxed) {
            return;
        }
        let stale = LAST_SYNC
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none_or(|t| t.elapsed() >= Duration::from_secs(2));
        if stale {
            sync_now();
        }
    }

    /// Synchronizes Windows TCP and UDP port forwarders immediately after a
    /// container start/stop/remove/ports request completes, before the HTTP
    /// response returns to the Docker client.
    pub fn after_container_op() {
        if !ACTIVE.load(Ordering::Relaxed) {
            return;
        }
        sync_now();
    }

    /// Wakes the background port forwarder thread to synchronize with WSL.
    pub fn notify() {
        if !ACTIVE.load(Ordering::Relaxed) {
            return;
        }
        let (m, cv) = &*WAKE;
        *m.lock().unwrap_or_else(PoisonError::into_inner) = true;
        cv.notify_all();
    }

    /// Starts the background Windows port forwarder synchronization loop.
    pub fn start() {
        if ACTIVE.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = std::thread::Builder::new().name("kiri-win-ports".into()).spawn(|| {
            loop {
                sync_now();
                let (m, cv) = &*WAKE;
                let mut signaled = m.lock().unwrap_or_else(PoisonError::into_inner);
                if !*signaled {
                    let (g, _) = cv.wait_timeout(signaled, RESYNC_INTERVAL).unwrap_or_else(PoisonError::into_inner);
                    signaled = g;
                }
                *signaled = false;
            }
        });
    }
}

#[cfg(windows)]
pub use runtime::{after_container_op, before_container_op, notify, start, sync_now};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_udp_and_non_loopback_tcp_forwards() {
        let wsl_ip = Ipv4Addr::new(198, 51, 100, 107);
        let win_v4 = vec![
            Ipv4Addr::new(192, 0, 2, 50),
            Ipv4Addr::new(198, 51, 100, 1),
            Ipv4Addr::new(169, 254, 10, 20), // link-local APIPA ignored for 0.0.0.0 expansion
        ];
        let win_v6 = vec![
            "2001:db8::42".parse::<Ipv6Addr>().unwrap(),
            "fe80::1".parse::<Ipv6Addr>().unwrap(), // link-local ignored for :: expansion
        ];
        let published = vec![
            // -p 18120:18120/udp (produces 0.0.0.0 and :: in daemon)
            PublishedPort { proto: "udp".into(), host_ip: "0.0.0.0".into(), host_port: 18120 },
            PublishedPort { proto: "udp".into(), host_ip: "::".into(), host_port: 18120 },
            // -p 127.0.0.1:18121:18121/udp
            PublishedPort { proto: "udp".into(), host_ip: "127.0.0.1".into(), host_port: 18121 },
            // -p 192.0.2.50:18122:18122/udp
            PublishedPort { proto: "udp".into(), host_ip: "192.0.2.50".into(), host_port: 18122 },
            // -p 127.0.0.1:18079:8080/tcp (left to wslrelay.exe)
            PublishedPort { proto: "tcp".into(), host_ip: "127.0.0.1".into(), host_port: 18079 },
            PublishedPort { proto: "tcp".into(), host_ip: "::1".into(), host_port: 18079 },
            // -p 192.0.2.50:18080:8080/tcp (specific Windows host IP only)
            PublishedPort { proto: "tcp".into(), host_ip: "192.0.2.50".into(), host_port: 18080 },
            // -p 0.0.0.0:18082:8080/tcp (expands to non-loopback Windows IPv4 interfaces)
            PublishedPort { proto: "tcp".into(), host_ip: "0.0.0.0".into(), host_port: 18082 },
            PublishedPort { proto: "tcp".into(), host_ip: "::".into(), host_port: 18082 },
        ];
        let specs = plan_forwards(wsl_ip, &published, &win_v4, &win_v6);
        let expected = vec![
            ForwardSpec {
                proto: Proto::Tcp,
                bind_addr: "192.0.2.50:18080".parse().unwrap(),
                target_addr: "198.51.100.107:18080".parse().unwrap(),
            },
            ForwardSpec {
                proto: Proto::Tcp,
                bind_addr: "192.0.2.50:18082".parse().unwrap(),
                target_addr: "198.51.100.107:18082".parse().unwrap(),
            },
            ForwardSpec {
                proto: Proto::Tcp,
                bind_addr: "198.51.100.1:18082".parse().unwrap(),
                target_addr: "198.51.100.107:18082".parse().unwrap(),
            },
            ForwardSpec {
                proto: Proto::Tcp,
                bind_addr: "[2001:db8::42]:18082".parse().unwrap(),
                target_addr: "198.51.100.107:18082".parse().unwrap(),
            },
            ForwardSpec {
                proto: Proto::Udp,
                bind_addr: "0.0.0.0:18120".parse().unwrap(),
                target_addr: "198.51.100.107:18120".parse().unwrap(),
            },
            ForwardSpec {
                proto: Proto::Udp,
                bind_addr: "127.0.0.1:18121".parse().unwrap(),
                target_addr: "198.51.100.107:18121".parse().unwrap(),
            },
            ForwardSpec {
                proto: Proto::Udp,
                bind_addr: "192.0.2.50:18122".parse().unwrap(),
                target_addr: "198.51.100.107:18122".parse().unwrap(),
            },
            ForwardSpec {
                proto: Proto::Udp,
                bind_addr: "[::]:18120".parse().unwrap(),
                target_addr: "198.51.100.107:18120".parse().unwrap(),
            },
        ];
        assert_eq!(specs, expected);
    }

    #[test]
    fn skips_self_forwarding_in_mirrored_or_bridged_wsl_mode() {
        let mirrored_ip = Ipv4Addr::new(192, 0, 2, 50);
        let win_v4 = vec![mirrored_ip, Ipv4Addr::new(203, 0, 113, 10)];
        let win_v6 = vec!["2001:db8::42".parse::<Ipv6Addr>().unwrap()];
        let published = vec![
            PublishedPort { proto: "udp".into(), host_ip: "0.0.0.0".into(), host_port: 18120 },
            PublishedPort { proto: "udp".into(), host_ip: "127.0.0.1".into(), host_port: 18121 },
            PublishedPort { proto: "tcp".into(), host_ip: "0.0.0.0".into(), host_port: 18082 },
            PublishedPort { proto: "tcp".into(), host_ip: "192.0.2.50".into(), host_port: 18080 },
        ];
        assert!(plan_forwards(mirrored_ip, &published, &win_v4, &win_v6).is_empty());
    }

    #[test]
    fn detects_port_affecting_http_requests() {
        assert!(is_port_affecting_request(b"POST /v1.47/containers/create HTTP/1.1\r\nHost: kiri\r\n\r\n"));
        assert!(is_port_affecting_request(b"POST /containers/abc123/start HTTP/1.1\r\n"));
        assert!(is_port_affecting_request(b"POST /containers/abc123/stop?t=10 HTTP/1.1\r\n"));
        assert!(is_port_affecting_request(b"DELETE /v1.47/containers/abc123?force=1 HTTP/1.1\r\n"));
        assert!(is_port_affecting_request(b"POST /kiri/containers/abc123/ports HTTP/1.1\r\n"));
        assert!(is_port_affecting_request(b"POST /kiri/stop HTTP/1.1\r\n"));
        assert!(!is_port_affecting_request(b"GET /containers/json?all=1 HTTP/1.1\r\n"));
        assert!(!is_port_affecting_request(b"GET /_ping HTTP/1.1\r\n"));
        assert!(!is_port_affecting_request(b"POST /kiri/win-ports HTTP/1.1\r\n"));
    }

    #[test]
    fn udp_forwarder_relays_datagrams_and_replies_per_client_session() {
        // Stand-in for the container's UDP echo service reachable on WSL's eth0 IP.
        let backend = UdpSocket::bind("127.0.0.1:0").unwrap();
        backend.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let echo_thread = std::thread::spawn(move || {
            let mut buf = [0u8; 1024];
            let mut seen_peers = Vec::new();
            for _ in 0..2 {
                let (n, peer) = backend.recv_from(&mut buf).unwrap();
                seen_peers.push(peer);
                let mut reply = b"echo:".to_vec();
                reply.extend_from_slice(&buf[..n]);
                backend.send_to(&reply, peer).unwrap();
            }
            seen_peers
        });

        let fwd = UdpForwarder::start("127.0.0.1:0".parse().unwrap(), backend_addr).unwrap();
        let fwd_addr = fwd.local_addr();

        let client1 = UdpSocket::bind("127.0.0.1:0").unwrap();
        client1.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let client2 = UdpSocket::bind("127.0.0.1:0").unwrap();
        client2.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        client1.send_to(b"one", fwd_addr).unwrap();
        client2.send_to(b"two", fwd_addr).unwrap();

        let mut r1 = [0u8; 64];
        let (n1, from1) = client1.recv_from(&mut r1).unwrap();
        assert_eq!(&r1[..n1], b"echo:one");
        assert_eq!(from1, fwd_addr);

        let mut r2 = [0u8; 64];
        let (n2, from2) = client2.recv_from(&mut r2).unwrap();
        assert_eq!(&r2[..n2], b"echo:two");
        assert_eq!(from2, fwd_addr);

        // Two distinct clients get distinct backend session sockets.
        let peers = echo_thread.join().unwrap();
        assert_ne!(peers[0], peers[1]);
        fwd.stop();
    }

    #[test]
    fn tcp_forwarder_relays_streams_and_releases_port_on_stop() {
        let backend = TcpListener::bind("127.0.0.1:0").unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = backend.accept().unwrap();
            let mut req = Vec::new();
            s.read_to_end(&mut req).unwrap();
            s.write_all(b"reply:").unwrap();
            s.write_all(&req).unwrap();
            let _ = s.shutdown(Shutdown::Write);
        });

        let fwd = TcpForwarder::start("127.0.0.1:0".parse().unwrap(), backend_addr).unwrap();
        let fwd_addr = fwd.local_addr();

        let mut client = TcpStream::connect(fwd_addr).unwrap();
        client.write_all(b"hello-win-tcp").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).unwrap();
        assert_eq!(resp, b"reply:hello-win-tcp");

        server.join().unwrap();
        fwd.stop();
        // Port is immediately free to bind again after stop().
        let rebound = TcpListener::bind(fwd_addr);
        assert!(rebound.is_ok(), "port should be released after TcpForwarder::stop()");
    }

    #[test]
    fn udp_forwarder_releases_bound_port_on_stop_and_plans_uppercase_protos() {
        for explicit_stop in [true, false] {
            let backend = UdpSocket::bind("127.0.0.1:0").unwrap();
            backend.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let backend_addr = backend.local_addr().unwrap();
            let spoofer = UdpSocket::bind("127.0.0.1:0").unwrap();
            let echo = std::thread::spawn(move || {
                let mut buf = [0u8; 64];
                let (n, peer) = backend.recv_from(&mut buf).unwrap();
                spoofer.send_to(b"spoofed", peer).unwrap();
                backend.send_to(&buf[..n], peer).unwrap();
            });

            let fwd = UdpForwarder::start("127.0.0.1:0".parse().unwrap(), backend_addr).unwrap();
            let fwd_addr = fwd.local_addr();
            let client = UdpSocket::bind("127.0.0.1:0").unwrap();
            client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            client.send_to(b"ping", fwd_addr).unwrap();
            let mut rbuf = [0u8; 64];
            let (n, from) = client.recv_from(&mut rbuf).unwrap();
            assert_eq!(&rbuf[..n], b"ping");
            assert_eq!(from, fwd_addr);
            echo.join().unwrap();

            if explicit_stop {
                fwd.stop();
            } else {
                drop(fwd);
            }
            let rebound = UdpSocket::bind(fwd_addr);
            assert!(rebound.is_ok(), "port should be released immediately after UdpForwarder shutdown");
        }

        let upper = vec![
            PublishedPort { proto: "UDP".into(), host_ip: "127.0.0.1".into(), host_port: 19123 },
            PublishedPort { proto: "TCP".into(), host_ip: "192.0.2.50".into(), host_port: 19124 },
        ];
        let specs = plan_forwards(Ipv4Addr::new(198, 51, 100, 107), &upper, &[Ipv4Addr::new(192, 0, 2, 50)], &[]);
        assert_eq!(specs.len(), 2);
    }
}
