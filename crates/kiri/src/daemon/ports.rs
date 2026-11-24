//! Published ports, host side: a listener per `-p` binding on the Mac. Each
//! client connection is passed on over the VM's NAT network to a port the
//! guest kernel forwards (DNAT) to the container, so the guest copies
//! nothing; vsock is several times slower in Virtualization.framework. Where
//! that network is unreachable (a VPN that takes over its routes, an older
//! agent), the connection gets its own vsock stream into the VM instead,
//! whose agent connects to the container and relays. No root either way.
//!
//! On a Linux host the daemon shares the kernel with the containers: the
//! kernel forwards (DNAT) every published port reached on a non-loopback
//! address, and the daemon relays the host's own loopback connections
//! itself, with splice(2), as Docker's userland proxy does. A relay ends
//! the client's TCP connection on `lo` and opens a second one to the
//! container, so the work of one stream is split across two flows and
//! CPUs; through the bridge alone, one CPU carried it all and the port
//! ran at about half of Docker's speed on 127.0.0.1.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::vmlink::VmLink;

/// The guest agent's vsock port for forwarded connections.
const RELAY_PORT: u32 = 1025;
/// …and for forwarded UDP, one stream per client address.
const UDP_RELAY_PORT: u32 = 1029;
/// Forwarded connections whose replies come back framed, so their end is
/// a frame and not the stream's half-close, which Virtualization.framework
/// sometimes drops; agents before it have only `RELAY_PORT`.
const RELAY_FRAMED_PORT: u32 = 1030;
static NO_FRAMED_RELAY: AtomicBool = AtomicBool::new(false);
/// A UDP client quiet this long has its session closed, as conntrack does.
const UDP_IDLE: Duration = Duration::from_secs(60);
/// A TCP peer that takes none of the relay's bytes for this long is given up
/// on. Quiet is not stuck: nothing limits how long a connection may idle,
/// as with docker-proxy (#388).
const TCP_STALL: Duration = Duration::from_secs(300);
/// Keepalive finds a peer that went away without a word (a laptop that
/// slept, a pulled cable), so its session is freed. Go's defaults, which
/// docker-proxy runs with.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(15);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEPALIVE_PROBES: libc::c_int = 9;
const MAX_TCP_SESSIONS: usize = 1024;
static TCP_SESSIONS: AtomicUsize = AtomicUsize::new(0);
/// Connections from other machines (a port published on 0.0.0.0 is open
/// to the LAN): each may hold this many at once, and all of them together
/// half of `MAX_TCP_SESSIONS`, so a LAN host keeping idle connections open
/// can neither use up the Mac's own (loopback is not limited by these) nor
/// every other machine's.
const MAX_PEER_SESSIONS: usize = 64;
const MAX_REMOTE_SESSIONS: usize = MAX_TCP_SESSIONS / 2;
static REMOTE_SESSIONS: Mutex<BTreeMap<IpAddr, usize>> = Mutex::new(BTreeMap::new());
/// Guest ports the VM's kernel forwards published TCP ports on, one per
/// binding: above Linux's ephemeral range (32768-60999), so never a port
/// the guest picks for a connection of its own.
const NAT_PORTS: std::ops::RangeInclusive<u16> = 61000..=65535;
static NAT_IN_USE: Mutex<BTreeSet<u16>> = Mutex::new(BTreeSet::new());
/// A connect over the NAT network answers in well under a millisecond, or
/// not at all when something else has its route. A SYN the network dropped
/// would be sent again only after 1 s: the connection goes over vsock
/// instead, where the agent connects within the guest.
const NAT_CONNECT: Duration = Duration::from_millis(300);
/// After a connect found no route (a VPN, or macOS's Local Network
/// permission not given), or two in a row had no answer, connections go
/// over vsock this long before the NAT network is tried again.
const NAT_RETRY: Duration = Duration::from_secs(30);
static NAT_DOWN_UNTIL: Mutex<Option<Instant>> = Mutex::new(None);
static NAT_TIMEOUTS: AtomicUsize = AtomicUsize::new(0);
/// Set once this run has warned that the NAT network is unreachable.
static NAT_WARNED: AtomicBool = AtomicBool::new(false);
/// New connections over the NAT network: a burst of `NAT_BURST`, then
/// `NAT_RATE` a second; the rest go over vsock, which takes thousands a
/// second (bulk transfers are what the NAT network is for). Each connection
/// there is a flow in the Mac's packet filter, whose state table (10,000
/// entries, shared by the whole Mac) keeps it for up to 90 s after it
/// closes. Once that is full the Mac drops every new SYN on the network
/// until entries expire: ab against a host-network nginx in the guest
/// stopped after 9,706 connections. And the guest masquerades each one to
/// a random port of the bridge address, which, past a few hundred a second,
/// lands on ports the container still holds in TIME_WAIT with timestamps
/// from another connection: the SYN is dropped (PAWS) and retried after 1 s.
const NAT_BURST: f64 = 512.0;
const NAT_RATE: f64 = 32.0;
static NAT_BUDGET: Mutex<Option<(f64, Instant)>> = Mutex::new(None);
/// Per read and write in the relays: a buffer that starts small, so an
/// idle or chatty connection holds little, and doubles each time a read
/// fills it, so a bulk transfer makes fewer, larger system calls (1 MiB
/// costs a quarter less CPU per byte than 256 KiB from the VM to the Mac).
const COPY_BUF: usize = 64 * 1024;
const COPY_BUF_MAX: usize = 1024 * 1024;

/// A guest port in `NAT_PORTS`, free again when dropped.
struct NatPort(u16);

impl Drop for NatPort {
    fn drop(&mut self) {
        NAT_IN_USE.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.0);
    }
}

fn nat_port() -> Option<NatPort> {
    let mut used = NAT_IN_USE.lock().unwrap_or_else(|e| e.into_inner());
    // The lowest free one: a port is reused only once its rule is gone.
    let port = NAT_PORTS.clone().find(|p| !used.contains(p))?;
    used.insert(port);
    Some(NatPort(port))
}

fn nat_usable() -> bool {
    let mut down = NAT_DOWN_UNTIL.lock().unwrap_or_else(|e| e.into_inner());
    match *down {
        Some(t) if Instant::now() < t => false,
        Some(_) => {
            *down = None;
            true
        }
        None => true,
    }
}

/// Takes one new connection's place from the NAT network's budget, if one is left.
fn nat_budget() -> bool {
    let mut budget = NAT_BUDGET.lock().unwrap_or_else(|e| e.into_inner());
    let (left, ok) = take_budget(*budget, Instant::now());
    *budget = Some(left);
    ok
}

/// A token bucket: `NAT_BURST` full, `NAT_RATE` a second back.
fn take_budget(state: Option<(f64, Instant)>, now: Instant) -> ((f64, Instant), bool) {
    let (tokens, at) = state.unwrap_or((NAT_BURST, now));
    let tokens = (tokens + now.saturating_duration_since(at).as_secs_f64() * NAT_RATE).min(NAT_BURST);
    if tokens >= 1.0 { ((tokens - 1.0, now), true) } else { ((tokens, now), false) }
}

/// One relayed connection; `peer` is set for one from another machine.
struct TcpPermit {
    peer: Option<IpAddr>,
}

impl Drop for TcpPermit {
    fn drop(&mut self) {
        TCP_SESSIONS.fetch_sub(1, Ordering::AcqRel);
        if let Some(peer) = self.peer {
            let mut peers = REMOTE_SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(n) = peers.get_mut(&peer) {
                *n -= 1;
                if *n == 0 {
                    peers.remove(&peer);
                }
            }
        }
    }
}

fn tcp_permit(peer: IpAddr) -> Option<TcpPermit> {
    let peer = peer.to_canonical();
    let mut remote = (!peer.is_loopback()).then(|| REMOTE_SESSIONS.lock().unwrap_or_else(|e| e.into_inner()));
    if let Some(peers) = &remote {
        if peers.get(&peer).copied().unwrap_or(0) >= MAX_PEER_SESSIONS || peers.values().sum::<usize>() >= MAX_REMOTE_SESSIONS {
            return None;
        }
    }
    let mut current = TCP_SESSIONS.load(Ordering::Relaxed);
    loop {
        if current >= MAX_TCP_SESSIONS {
            return None;
        }
        match TCP_SESSIONS.compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
    if let Some(peers) = &mut remote {
        *peers.entry(peer).or_default() += 1;
    }
    Some(TcpPermit { peer: remote.map(|_| peer) })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub container_port: u16,
    /// `tcp` or `udp`.
    pub proto: String,
    /// Empty means all interfaces, as Docker does.
    pub host_ip: String,
    /// 0 asks for any free port; the chosen one is reported once bound.
    pub host_port: u16,
}

/// A running forward for one container; dropping it closes every listener.
pub struct Forwards {
    wake: Vec<OwnedFd>,
    threads: Vec<JoinHandle<()>>,
    /// Linux host: the kernel forwards these (sockets stay bound so the
    /// ports read as taken); dropping tells the agent to stop.
    kernel: Option<(Arc<VmLink>, String, Vec<TcpListener>, Vec<UdpSocket>)>,
    /// In the VM: the guest ports its kernel forwards for these listeners;
    /// dropping tells the agent to stop, then frees the ports.
    nat: Option<(Arc<VmLink>, String, Vec<NatPort>)>,
    /// In the VM: the ports also published on the VM's own loopback, for
    /// `--network host` containers (`loopback_ports`); dropping tells the
    /// agent to stop if `nat` didn't already unpublish the container.
    loopback: Option<(Arc<VmLink>, String)>,
    /// What was actually bound: (binding, host address, host port).
    pub bound: Vec<(Binding, String, u16)>,
}

impl std::fmt::Debug for Forwards {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Forwards").field("bound", &self.bound).finish()
    }
}

impl Drop for Forwards {
    fn drop(&mut self) {
        let mut unpublished = false;
        if let Some((vm, id, ..)) = self.kernel.take() {
            let _ = vm.unpublish(&id);
            unpublished = true;
        }
        if let Some((vm, id, _ports)) = self.nat.take() {
            let _ = vm.unpublish(&id);
            unpublished = true;
        }
        if let Some((vm, id)) = self.loopback.take()
            && !unpublished
        {
            let _ = vm.unpublish(&id);
        }
        // Closing the write ends wakes every listener thread.
        self.wake.clear();
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

/// A wake pipe: closing the write end stops a listener's thread. Both ends
/// are close-on-exec: a child the daemon starts later (on a Linux host, the
/// agent) would otherwise hold a copy of the write end, the pipe would never
/// close, and stopping the listener would wait forever.
pub(super) fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: `fds` has room for the two descriptors pipe writes.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe succeeded, so both are fresh and ours.
    let (r, w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in [&r, &w] {
        // SAFETY: F_SETFD on a descriptor we own.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok((r, w))
}

fn kernel_host_ip(ip: &str) -> Option<[u8; 4]> {
    if ip.is_empty() || ip == "0.0.0.0" { Some([0; 4]) } else { ip.parse::<std::net::Ipv4Addr>().ok().map(|a| a.octets()) }
}

/// Linux host: whether the kernel forwards a binding on `ip`. Every IPv4
/// address but loopback (the rule for 0.0.0.0 skips 127.0.0.0/8 too):
/// loopback is relayed, so the bridges never need `route_localnet`.
fn kernel_forwards(ip: &str) -> bool {
    kernel_host_ip(ip).is_some_and(|a| a[0] != 127)
}

/// Linux host: whether a binding's listener also relays, for the
/// connections the kernel leaves to it: loopback, IPv6, and the 127.0.0.1
/// share of one on every address.
fn relays_too(ip: &str) -> bool {
    !kernel_forwards(ip) || kernel_host_ip(ip) == Some([0; 4])
}

/// A socket bound to `addr`; an IPv6 one with IPV6_V6ONLY, so `[::]:port`
/// sits beside `0.0.0.0:port` (as Docker binds both) instead of clashing
/// with it, and serves IPv6 alone.
fn bind_socket(addr: SocketAddr, udp: bool) -> io::Result<OwnedFd> {
    let (family, ty) = (if addr.is_ipv6() { libc::AF_INET6 } else { libc::AF_INET }, if udp { libc::SOCK_DGRAM } else { libc::SOCK_STREAM });
    // SAFETY: plain socket creation; owned at once.
    let fd = unsafe { libc::socket(family, ty, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is fresh and ours.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    let one: libc::c_int = 1;
    let set = |level, opt| {
        // SAFETY: setsockopt with an int of the stated size.
        unsafe { libc::setsockopt(sock.as_raw_fd(), level, opt, (&one as *const libc::c_int).cast(), std::mem::size_of::<libc::c_int>() as libc::socklen_t) }
    };
    // As std's TcpListener::bind does: a port in TIME_WAIT can be bound again.
    if !udp {
        set(libc::SOL_SOCKET, libc::SO_REUSEADDR);
    }
    if addr.is_ipv6() && set(libc::IPPROTO_IPV6, libc::IPV6_V6ONLY) != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the sockaddr storage is filled for `addr`'s family and sized to match.
    let (storage, len) = sockaddr_of(addr);
    if unsafe { libc::bind(sock.as_raw_fd(), (&storage as *const libc::sockaddr_storage).cast(), len) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: listen on a bound stream socket we own.
    if !udp && unsafe { libc::listen(sock.as_raw_fd(), 1024) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sock)
}

fn sockaddr_of(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: sockaddr_storage is plain data; all-zero is valid.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(a) => {
            // SAFETY: sockaddr_storage is large and aligned enough for a sockaddr_in.
            let sin = unsafe { &mut *(&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = a.port().to_be();
            sin.sin_addr.s_addr = u32::from_ne_bytes(a.ip().octets());
            #[cfg(target_os = "macos")]
            {
                sin.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
            }
            std::mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            // SAFETY: as above, for a sockaddr_in6.
            let sin6 = unsafe { &mut *(&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>() };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = a.port().to_be();
            sin6.sin6_addr.s6_addr = a.ip().octets();
            sin6.sin6_scope_id = a.scope_id();
            #[cfg(target_os = "macos")]
            {
                sin6.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
            }
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (storage, len as libc::socklen_t)
}

/// `host_ip` and `port` as a socket address: `::1` and `[::1]` both work,
/// as the CLI sends `-p [::1]:8080:80` bare and the API may bracket it.
fn host_addr(ip: &str, port: u16) -> io::Result<SocketAddr> {
    let bare = ip.strip_prefix('[').and_then(|i| i.strip_suffix(']')).unwrap_or(ip);
    bare.parse::<IpAddr>().map(|a| SocketAddr::new(a, port)).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("bad host address {ip}")))
}

/// What one binding listens on: its own address, or with no address both
/// 0.0.0.0 and `::` (the IPv6 one only when the host has IPv6), as Docker
/// binds them and lists them in `docker port`.
fn listen_addrs(b: &Binding) -> Vec<(String, bool)> {
    match b.host_ip.as_str() {
        "" => vec![("0.0.0.0".to_owned(), true), ("::".to_owned(), false)],
        ip => vec![(ip.strip_prefix('[').and_then(|i| i.strip_suffix(']')).unwrap_or(ip).to_owned(), true)],
    }
}

/// The program that has `port` on this Mac, when it is another program:
/// an engine left running beside Kiri (the one containers were imported
/// from) or a server on the Mac holds the port, and "already allocated"
/// alone reads as if Kiri had lost track of its own containers. None when
/// Kiri itself has it, or when lsof says nothing.
#[cfg(target_os = "macos")]
fn holder(port: u16, udp: bool) -> Option<String> {
    let spec = if udp { format!("-iUDP:{port}") } else { format!("-iTCP:{port}") };
    let mut cmd = std::process::Command::new("/usr/sbin/lsof");
    cmd.args(["-nP", &spec, "-Fc"]);
    if !udp {
        cmd.arg("-sTCP:LISTEN");
    }
    let out = cmd.stderr(std::process::Stdio::null()).output().ok()?;
    holder_in(&String::from_utf8_lossy(&out.stdout))
}

#[cfg(not(target_os = "macos"))]
fn holder(_port: u16, _udp: bool) -> Option<String> {
    None
}

/// The first command in `lsof -Fc` output (`p<pid>` and `c<command>`
/// lines) that is not Kiri's own.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn holder_in(lsof: &str) -> Option<String> {
    lsof.lines().filter_map(|l| l.strip_prefix('c')).map(str::trim).find(|c| !c.is_empty() && !c.to_ascii_lowercase().starts_with("kiri")).map(str::to_owned)
}

/// Binds every port first (so a clash fails the start cleanly), then starts
/// one accept thread per listener.
pub fn start(vm: Arc<VmLink>, id: &str, bindings: &[Binding], target_ip: [u8; 4]) -> io::Result<Forwards> {
    let mut listeners = Vec::with_capacity(bindings.len());
    let mut udp = Vec::new();
    for b in bindings {
        // A port picked by the kernel (0) is picked once: the `::` listener
        // takes the one 0.0.0.0 got.
        let mut port = b.host_port;
        for (ip, required) in listen_addrs(b) {
            let addr = host_addr(&ip, port)?;
            let taken = |e: io::Error| {
                if e.kind() == io::ErrorKind::AddrInUse {
                    let shown = if addr.is_ipv6() { format!("[{ip}]") } else { ip.clone() };
                    // Docker's words, then who has the port when it is not Kiri.
                    let by = holder(b.host_port, b.proto == "udp").map(|name| format!(" (in use by {name})")).unwrap_or_default();
                    io::Error::new(e.kind(), format!("Bind for {shown}:{} failed: port is already allocated{by}", b.host_port))
                } else {
                    e
                }
            };
            // Kiri's own container-domain router on this port lets it go
            // (domains::step_aside), and the bind goes again.
            let bound = bind_socket(addr, b.proto == "udp").or_else(|e| {
                if e.kind() == io::ErrorKind::AddrInUse && b.proto == "tcp" && port != 0 && super::domains::step_aside(port) { bind_socket(addr, false) } else { Err(e) }
            });
            let sock = match bound {
                Ok(s) => s,
                Err(e) if required => return Err(taken(e)),
                // No IPv6 on this host, or `::` of this port held by something
                // else: IPv4 alone, as Docker does without IPv6.
                Err(e) => {
                    crate::diag::debug!("published port has no IPv6 listener", port = port, error = e);
                    continue;
                }
            };
            if b.proto == "udp" {
                let s = UdpSocket::from(sock);
                s.set_nonblocking(true)?;
                port = s.local_addr()?.port();
                udp.push((b.clone(), ip, port, s));
                continue;
            }
            let l = TcpListener::from(sock);
            l.set_nonblocking(true)?;
            port = l.local_addr()?.port();
            listeners.push((b.clone(), ip, port, l));
        }
    }
    let mut fw = Forwards { wake: Vec::new(), threads: Vec::new(), kernel: None, nat: None, loopback: None, bound: Vec::new() };
    // On a Linux host the daemon shares the kernel with the containers, so
    // the kernel can rewrite the packets (nftables DNAT) instead of two
    // user-space relays copying every byte; that serves every address but
    // loopback. The listeners below relay the rest. A target on loopback (a
    // --network host container) stays relayed: that is a local socket.
    if cfg!(target_os = "linux") && target_ip != [127, 0, 0, 1] {
        let all = udp.iter().map(|(b, ip, port, _)| (b, ip, *port, true)).chain(listeners.iter().map(|(b, ip, port, _)| (b, ip, *port, false)));
        let mut published = Ok(false);
        for (b, ip, port, is_udp) in all.filter(|(_, ip, ..)| kernel_forwards(ip)) {
            let p = kiri_proto::Publish { id, udp: is_udp, host_ip: kernel_host_ip(ip).expect("checked IPv4 binding"), host_port: port, to_ip: target_ip, to_port: b.container_port };
            published = vm.publish(p).map(|()| true);
            if published.is_err() {
                break;
            }
        }
        match published {
            Ok(any) => {
                // Sockets only the kernel serves stay bound, so the ports read as taken.
                let (kernel_udp, relay_udp): (Vec<_>, Vec<_>) = udp.into_iter().partition(|(_, ip, ..)| !relays_too(ip));
                let (kernel_tcp, relay_tcp): (Vec<_>, Vec<_>) = listeners.into_iter().partition(|(_, ip, ..)| !relays_too(ip));
                fw.bound.extend(kernel_udp.iter().map(|(b, ip, port, _)| (b.clone(), ip.clone(), *port)));
                fw.bound.extend(kernel_tcp.iter().map(|(b, ip, port, _)| (b.clone(), ip.clone(), *port)));
                if any {
                    fw.kernel = Some((vm.clone(), id.to_owned(), kernel_tcp.into_iter().map(|(.., s)| s).collect(), kernel_udp.into_iter().map(|(.., s)| s).collect()));
                }
                udp = relay_udp;
                listeners = relay_tcp;
            }
            Err(e) => {
                let _ = vm.unpublish(id);
                crate::diag::warn!("kernel port forwarding failed; relaying in user space", id = &id[..id.len().min(12)], error = e);
            }
        }
    }
    for (b, ip, port, sock) in udp {
        let (wake_r, wake_w) = pipe()?;
        fw.wake.push(wake_w);
        let vm = vm.clone();
        let container_port = b.container_port;
        fw.threads.push(std::thread::Builder::new().name(format!("kiri-udp-{port}")).spawn(move || {
            udp_loop(&sock, &wake_r, &vm, target_ip, container_port);
        })?);
        fw.bound.push((b, ip, port));
    }
    // In the VM: the guest kernel forwards each TCP binding from a port of
    // its own on the NAT network. A target on loopback stays relayed.
    let mut nat = vec![None; listeners.len()];
    if cfg!(target_os = "macos") && target_ip != [127, 0, 0, 1] && !listeners.is_empty() {
        match publish_nat(&vm, id, &listeners.iter().map(|(b, ..)| b.container_port).collect::<Vec<_>>(), target_ip) {
            Ok((addrs, ports)) => {
                nat = addrs.into_iter().map(Some).collect();
                fw.nat = Some((vm.clone(), id.to_owned(), ports));
            }
            Err(e) => crate::diag::warn!("NAT port forwarding unavailable; relaying over vsock", id = &id[..id.len().min(12)], error = e),
        }
    }
    // In the VM: a `--network host` container shares the VM's network, not
    // the Mac's, so the VM's 127.0.0.1 has none of these ports. Each TCP
    // port the Mac has on its loopback is published there too: the agent
    // sends the VM's own connections to it through the host relay, to this
    // listener. As on Docker, where a published port is bound in the host's
    // namespace. A target on loopback is itself a host-network container.
    if cfg!(target_os = "macos") && target_ip != [127, 0, 0, 1] {
        let ports = loopback_ports(listeners.iter().map(|(b, ip, port, _)| (b.container_port, ip.as_str(), *port)));
        let mut published = false;
        for (to_port, host_port) in ports {
            let p = kiri_proto::Publish { id, udp: false, host_ip: [127, 0, 0, 1], host_port, to_ip: target_ip, to_port };
            match vm.publish(p) {
                Ok(()) => published = true,
                Err(e) => crate::diag::warn!("published port not reachable from host-network containers", port = host_port, error = e),
            }
        }
        if published {
            fw.loopback = Some((vm.clone(), id.to_owned()));
        }
    }
    for ((b, ip, port, listener), nat) in listeners.into_iter().zip(nat) {
        let (wake_r, wake_w) = pipe()?;
        fw.wake.push(wake_w);
        let vm = vm.clone();
        let container_port = b.container_port;
        fw.threads.push(std::thread::Builder::new().name(format!("kiri-port-{port}")).spawn(move || {
            accept_loop(&listener, &wake_r, &vm, target_ip, container_port, nat);
        })?);
        fw.bound.push((b, ip, port));
    }
    Ok(fw)
}

/// The TCP ports (container port, port bound on the Mac) that are on the
/// Mac's loopback: bound on 127.0.0.1 or on every IPv4 address, once each.
/// A port on one other address, or on IPv6 only, is not.
fn loopback_ports<'a>(bound: impl Iterator<Item = (u16, &'a str, u16)>) -> Vec<(u16, u16)> {
    let mut out: Vec<(u16, u16)> = Vec::new();
    for (container_port, ip, port) in bound {
        if matches!(ip, "" | "0.0.0.0" | "127.0.0.1") && !out.iter().any(|(_, p)| *p == port) {
            out.push((container_port, port));
        }
    }
    out
}

/// Asks the agent to forward a guest port to each container port, from the
/// Mac only; returns the address the Mac dials for each. All or nothing.
fn publish_nat(vm: &VmLink, id: &str, container_ports: &[u16], target_ip: [u8; 4]) -> io::Result<(Vec<SocketAddr>, Vec<NatPort>)> {
    let (guest_ip, gateway) = vm.uplink()?;
    set_vm_subnet(gateway, VM_UPLINK_PREFIX);
    let mut addrs = Vec::with_capacity(container_ports.len());
    let mut ports = Vec::with_capacity(container_ports.len());
    for &to_port in container_ports {
        let Some(p) = nat_port() else {
            let _ = vm.unpublish(id);
            return Err(io::Error::other("no free guest port"));
        };
        let publish = kiri_proto::Publish { id, udp: false, host_ip: guest_ip, host_port: p.0, to_ip: target_ip, to_port };
        if let Err(e) = vm.publish(publish) {
            let _ = vm.unpublish(id);
            return Err(e);
        }
        addrs.push(SocketAddr::from((guest_ip, p.0)));
        ports.push(p);
    }
    Ok((addrs, ports))
}

/// One client address's session: a stream into the guest relay.
struct UdpSession {
    to_guest: std::fs::File,
    last: Instant,
    reader: JoinHandle<()>,
    // Keeps the connection open until the session ends.
    _guest: kiri_vmm::VsockStream,
}

impl UdpSession {
    fn close(self) {
        // SAFETY: shutting down a socket we own wakes the reader with EOF.
        unsafe { libc::shutdown(self.to_guest.as_raw_fd(), libc::SHUT_RDWR) };
        let _ = self.reader.join();
    }
}

/// Datagrams from each client go to the container over its own session;
/// replies come back to that client. Quiet sessions close.
fn udp_loop(sock: &UdpSocket, wake: &OwnedFd, vm: &Arc<VmLink>, ip: [u8; 4], port: u16) {
    let mut sessions: std::collections::HashMap<SocketAddr, UdpSession> = std::collections::HashMap::new();
    let mut buf = vec![0u8; 65_536];
    loop {
        let mut fds = [
            libc::pollfd {
                fd: sock.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: polling two descriptors we own; wake up now and then to reap.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, 5_000) };
        if n < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            break;
        }
        if fds[1].revents != 0 {
            break; // the container stopped
        }
        while let Ok((len, peer)) = sock.recv_from(&mut buf) {
            if !sessions.contains_key(&peer) {
                // Cap sessions so a source-spoofing flood cannot exhaust
                // threads and guest connections; drop the oldest to make room.
                if sessions.len() >= 1024 {
                    if let Some(old) = sessions.iter().min_by_key(|(_, s)| s.last).map(|(p, _)| *p) {
                        if let Some(s) = sessions.remove(&old) {
                            s.close();
                        }
                    }
                }
                match open_udp_session(sock, vm, ip, port, peer) {
                    Ok(s) => {
                        sessions.insert(peer, s);
                    }
                    Err(_) => continue,
                }
            }
            let s = sessions.get_mut(&peer).expect("just inserted");
            s.last = Instant::now();
            let mut frame = Vec::with_capacity(len + 2);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
            frame.extend_from_slice(&buf[..len]);
            if s.to_guest.write_all(&frame).is_err() {
                if let Some(s) = sessions.remove(&peer) {
                    s.close();
                }
            }
        }
        let idle: Vec<SocketAddr> = sessions.iter().filter(|(_, s)| s.last.elapsed() >= UDP_IDLE || s.reader.is_finished()).map(|(a, _)| *a).collect();
        for a in idle {
            if let Some(s) = sessions.remove(&a) {
                s.close();
            }
        }
    }
    for (_, s) in sessions.drain() {
        s.close();
    }
}

fn open_udp_session(sock: &UdpSocket, vm: &VmLink, ip: [u8; 4], port: u16, peer: SocketAddr) -> io::Result<UdpSession> {
    let guest = vm.connect(UDP_RELAY_PORT)?;
    let mut to_guest = std::fs::File::from(guest.fd.try_clone()?);
    let mut header = [0u8; 6];
    header[..4].copy_from_slice(&ip);
    header[4..].copy_from_slice(&port.to_be_bytes());
    to_guest.write_all(&header)?;
    let mut from_guest = std::fs::File::from(guest.fd.try_clone()?);
    // A clone shares the socket (and its non-blocking mode); a send to a
    // client rarely has to wait, and a dropped reply is UDP's to lose.
    let reply = sock.try_clone()?;
    let reader = std::thread::Builder::new().name("kiri-udp-reply".into()).spawn(move || {
        let mut len = [0u8; 2];
        let mut data = vec![0u8; 65_536];
        while from_guest.read_exact(&mut len).is_ok() {
            let n = u16::from_be_bytes(len) as usize;
            if from_guest.read_exact(&mut data[..n]).is_err() {
                break;
            }
            let _ = reply.send_to(&data[..n], peer);
        }
    })?;
    Ok(UdpSession {
        to_guest,
        last: Instant::now(),
        reader,
        _guest: guest,
    })
}

fn accept_loop(listener: &TcpListener, wake: &OwnedFd, vm: &Arc<VmLink>, ip: [u8; 4], port: u16, nat: Option<SocketAddr>) {
    loop {
        let mut fds = [
            libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: polling two descriptors we own.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if fds[1].revents != 0 {
            return; // the container stopped
        }
        while let Ok((client, from)) = listener.accept() {
            let Some(permit) = tcp_permit(from.ip()) else {
                continue;
            };
            let vm = vm.clone();
            let _ = std::thread::Builder::new().name("kiri-conn".into()).spawn(move || {
                // Held until the connection is done.
                let _permit = permit;
                let _ = relay(client, &vm, ip, port, nat);
            });
        }
    }
}

/// One client connection: a vsock stream to the agent, the target address,
/// then bytes both ways until both sides are done.
/// A vsock stream to the guest relay, already pointed at `ip:port`.
pub fn open_relay(vm: &VmLink, ip: [u8; 4], port: u16) -> io::Result<kiri_vmm::VsockStream> {
    let guest = vm.connect(RELAY_PORT)?;
    let mut header = [0u8; 6];
    header[..4].copy_from_slice(&ip);
    header[4..].copy_from_slice(&port.to_be_bytes());
    std::fs::File::from(guest.fd.try_clone()?).write_all(&header)?;
    Ok(guest)
}

/// `open_relay` on the agent's framed port, where it has one; true if so.
fn open_framed_relay(vm: &VmLink, ip: [u8; 4], port: u16) -> io::Result<(kiri_vmm::VsockStream, bool)> {
    if !NO_FRAMED_RELAY.load(Ordering::Relaxed) {
        match vm.connect(RELAY_FRAMED_PORT) {
            Ok(guest) => {
                let mut header = [0u8; 6];
                header[..4].copy_from_slice(&ip);
                header[4..].copy_from_slice(&port.to_be_bytes());
                std::fs::File::from(guest.fd.try_clone()?).write_all(&header)?;
                return Ok((guest, true));
            }
            // An older agent: nothing listens there.
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => NO_FRAMED_RELAY.store(true, Ordering::Relaxed),
            Err(e) => return Err(e),
        }
    }
    Ok((open_relay(vm, ip, port)?, false))
}

fn relay(client: TcpStream, vm: &VmLink, ip: [u8; 4], port: u16, nat: Option<SocketAddr>) -> io::Result<()> {
    client.set_nonblocking(false)?;
    relayed_tcp(&client)?;
    // A Linux host reaches the container's address itself.
    if cfg!(target_os = "linux") {
        return relay_direct(client, ip, port);
    }
    if let Some(addr) = nat.filter(|_| nat_usable() && nat_budget()) {
        match TcpStream::connect_timeout(&addr, NAT_CONNECT) {
            Ok(guest) => {
                NAT_TIMEOUTS.store(0, Ordering::Relaxed);
                return relay_tcp(client, guest);
            }
            // Refused is the container (not listening yet), and vsock gets
            // the same answer; no route is the network itself, and so is no
            // answer twice running. This connection goes over vsock either way.
            Err(e) if e.kind() != io::ErrorKind::ConnectionRefused => {
                let timed_out = e.kind() == io::ErrorKind::TimedOut;
                if !timed_out || NAT_TIMEOUTS.fetch_add(1, Ordering::Relaxed) >= 1 {
                    NAT_TIMEOUTS.store(0, Ordering::Relaxed);
                    *NAT_DOWN_UNTIL.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now() + NAT_RETRY);
                    // Once a run as a warning, with what usually causes it;
                    // each retry after that only notes it.
                    if NAT_WARNED.swap(true, Ordering::Relaxed) {
                        crate::diag::info!("the VM's NAT network is still unreachable; published ports keep going over vsock", to = addr, error = e);
                    } else {
                        crate::diag::warn!("the VM's NAT network is unreachable, so published ports go over vsock (they still work); a VPN, or Kiri not allowed under Local Network in Privacy & Security, usually causes this", to = addr, error = e);
                    }
                }
            }
            Err(_) => {}
        }
    }
    let (guest, framed) = open_framed_relay(vm, ip, port)?;
    vsock_stall(guest.fd.as_raw_fd())?;
    let mut to_guest = std::fs::File::from(guest.fd.try_clone()?);
    let mut from_guest = std::fs::File::from(guest.fd.try_clone()?);
    let mut client_read = client.try_clone()?;
    let mut client_write = client;
    let up = std::thread::Builder::new().name("kiri-conn-up".into()).spawn(move || {
        let how = match pass_on(copy(&mut client_read, &mut to_guest)) {
            Shutdown::Write => libc::SHUT_WR,
            _ => libc::SHUT_RDWR,
        };
        // SAFETY: shutting down a socket we own.
        unsafe { libc::shutdown(to_guest.as_raw_fd(), how) };
    })?;
    let down = if framed { copy_frames(&mut from_guest, &mut client_write) } else { copy(&mut from_guest, &mut client_write) };
    let _ = client_write.shutdown(pass_on(down));
    let _ = up.join();
    // `guest` drops here: the vsock connection is released on the VM's queue.
    drop(guest);
    Ok(())
}

/// A client connection passed on over the NAT network: two sockets, with
/// each half-close passed on.
fn relay_tcp(client: TcpStream, guest: TcpStream) -> io::Result<()> {
    relayed_tcp(&guest)?;
    let (mut client_read, mut guest_write) = (client.try_clone()?, guest.try_clone()?);
    let up = std::thread::Builder::new().name("kiri-conn-up".into()).spawn(move || {
        let how = pass_on(copy(&mut client_read, &mut guest_write));
        let _ = guest_write.shutdown(how);
    })?;
    let (mut guest_read, mut client_write) = (guest, client);
    let how = pass_on(copy(&mut guest_read, &mut client_write));
    let _ = client_write.shutdown(how);
    let _ = up.join();
    Ok(())
}

/// How long a Linux host waits for a container to answer a connect: it is
/// on a local bridge, so it answers at once or refuses, unless it is busy.
const DIRECT_CONNECT: Duration = Duration::from_secs(2);
/// The pipe each spliced direction moves bytes through (Go's size, which
/// docker-proxy uses): fewer, larger system calls for a bulk transfer.
#[cfg(target_os = "linux")]
const SPLICE_PIPE: libc::c_int = 1 << 20;

/// Linux host: one client connection to the container's address, the bytes
/// moved by splice(2) through a pipe each way (never copied to user space),
/// one thread per direction, each half-close passed on.
fn relay_direct(client: TcpStream, ip: [u8; 4], port: u16) -> io::Result<()> {
    let target = TcpStream::connect_timeout(&SocketAddr::from((ip, port)), DIRECT_CONNECT)?;
    relayed_tcp(&target)?;
    let (client_read, target_write) = (client.try_clone()?, target.try_clone()?);
    let up = std::thread::Builder::new().name("kiri-conn-up".into()).spawn(move || {
        let _ = target_write.shutdown(pass_on(splice_all(&client_read, &target_write)));
    })?;
    let _ = client.shutdown(pass_on(splice_all(&target, &client)));
    let _ = up.join();
    Ok(())
}

/// Moves everything `from` sends to `to` until its end (only a Linux host
/// relays directly; splice(2) is Linux's).
#[cfg(not(target_os = "linux"))]
fn splice_all(mut from: &TcpStream, mut to: &TcpStream) -> io::Result<()> {
    copy(&mut from, &mut to)
}

/// Moves everything `from` sends to `to` until its end, through a pipe.
#[cfg(target_os = "linux")]
fn splice_all(from: &TcpStream, to: &TcpStream) -> io::Result<()> {
    let mut fds = [0; 2];
    // SAFETY: `fds` has room for the two descriptors pipe2 writes.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 succeeded, so both are fresh and ours.
    let (r, w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // A bigger pipe is an optimisation only; the default 64 KiB works too.
    // SAFETY: fcntl on a pipe we own.
    let size = match unsafe { libc::fcntl(w.as_raw_fd(), libc::F_SETPIPE_SZ, SPLICE_PIPE) } {
        n if n > 0 => n as usize,
        _ => 64 * 1024,
    };
    let splice = |from: i32, to: i32, len: usize| loop {
        // SAFETY: splice between descriptors we own, no offsets.
        let n = unsafe { libc::splice(from, std::ptr::null_mut(), to, std::ptr::null_mut(), len, libc::SPLICE_F_MOVE) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    };
    loop {
        let n = splice(from.as_raw_fd(), w.as_raw_fd(), size)?;
        if n == 0 {
            return Ok(());
        }
        let mut left = n;
        while left > 0 {
            left -= splice(r.as_raw_fd(), to.as_raw_fd(), left)?;
        }
    }
}

fn copy(from: &mut impl Read, to: &mut impl Write) -> io::Result<()> {
    let mut buf = vec![0u8; COPY_BUF];
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        to.write_all(&buf[..n])?;
        if n == buf.len() && buf.len() < COPY_BUF_MAX {
            buf.resize(buf.len() * 2, 0);
        }
    }
}

/// What the agent sends on `RELAY_FRAMED_PORT`: `u32 len | bytes` frames,
/// an empty one last.
#[derive(Default)]
struct Deframer {
    head: [u8; 4],
    have: usize,
    left: usize,
}

impl Deframer {
    /// Passes the payload in `data` on to `to`; true once the end frame is in.
    fn feed(&mut self, mut data: &[u8], to: &mut impl Write) -> io::Result<bool> {
        while !data.is_empty() {
            if self.left > 0 {
                let n = self.left.min(data.len());
                to.write_all(&data[..n])?;
                self.left -= n;
                data = &data[n..];
                continue;
            }
            let n = (4 - self.have).min(data.len());
            self.head[self.have..self.have + n].copy_from_slice(&data[..n]);
            self.have += n;
            data = &data[n..];
            if self.have == 4 {
                self.have = 0;
                self.left = u32::from_be_bytes(self.head) as usize;
                if self.left == 0 {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

/// `copy` from a framed relay, up to its end frame (or the stream's end).
fn copy_frames(from: &mut impl Read, to: &mut impl Write) -> io::Result<()> {
    let mut buf = vec![0u8; COPY_BUF];
    let mut frames = Deframer::default();
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 || frames.feed(&buf[..n], to)? {
            return Ok(());
        }
        if n == buf.len() && buf.len() < COPY_BUF_MAX {
            buf.resize(buf.len() * 2, 0);
        }
    }
}

/// How a relay direction's end reaches the other socket. An end of stream is
/// a half-close, passed on as one. A failure (keepalive found the peer gone,
/// a write stalled) closes the other socket both ways, which also wakes the
/// opposite direction: with no read deadline it would otherwise wait on a
/// quiet peer forever, holding the session.
fn pass_on(copied: io::Result<()>) -> Shutdown {
    if copied.is_ok() { Shutdown::Write } else { Shutdown::Both }
}

/// Either end of a relayed TCP connection: no read deadline, a write one, and
/// keepalive.
fn relayed_tcp(s: &TcpStream) -> io::Result<()> {
    s.set_nodelay(true)?;
    s.set_write_timeout(Some(TCP_STALL))?;
    #[cfg(target_os = "macos")]
    let idle = libc::TCP_KEEPALIVE;
    #[cfg(not(target_os = "macos"))]
    let idle = libc::TCP_KEEPIDLE;
    let fd = s.as_raw_fd();
    let set = |level, name, v: libc::c_int| {
        // SAFETY: setting an int option on a socket we own, from a local.
        let r = unsafe { libc::setsockopt(fd, level, name, (&v as *const libc::c_int).cast(), std::mem::size_of::<libc::c_int>() as libc::socklen_t) };
        if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
    };
    set(libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)?;
    set(libc::IPPROTO_TCP, idle, KEEPALIVE_IDLE.as_secs() as _)?;
    set(libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, KEEPALIVE_INTERVAL.as_secs() as _)?;
    set(libc::IPPROTO_TCP, libc::TCP_KEEPCNT, KEEPALIVE_PROBES)
}

/// The vsock end: no read deadline, so a quiet connection stays (#388). The
/// client's end has keepalive; when it fails, the relay ends this one too.
fn vsock_stall(fd: std::os::fd::RawFd) -> io::Result<()> {
    let timeout = libc::timeval {
        tv_sec: TCP_STALL.as_secs() as _,
        tv_usec: 0,
    };
    // SAFETY: timeout is valid for the duration of the call on an owned socket.
    let result = unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDTIMEO, (&timeout as *const libc::timeval).cast(), std::mem::size_of::<libc::timeval>() as libc::socklen_t) };
    if result == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// What containers reach as `host.docker.internal`.
pub const HOST_ADDR: &str = "198.19.248.254";
/// vsock port the guest dials for host-bound connections.
pub const HOST_BOUND_PORT: u32 = 1026;

/// One host-bound connection from a container: the guest sends
/// `ip[4] port[2]` (always 127.0.0.1 today), and we connect there on the Mac.
pub fn serve_host_bound(stream: kiri_vmm::VsockStream) {
    let _ = std::thread::Builder::new().name("kiri-host-bound".into()).spawn(move || {
        let _ = host_bound(stream);
    });
}

fn host_bound(stream: kiri_vmm::VsockStream) -> io::Result<()> {
    let mut from_guest = std::fs::File::from(stream.fd.try_clone()?);
    let mut header = [0u8; 6];
    from_guest.read_exact(&mut header)?;
    let ip = std::net::Ipv4Addr::new(header[0], header[1], header[2], header[3]);
    let port = u16::from_be_bytes([header[4], header[5]]);
    if !host_bound_allowed(ip, port, super::domains::routes) {
        crate::diag::warn!("refused a host-bound connection; only 127.0.0.1 is relayed, and never to a container-domain router", to = format!("{ip}:{port}"));
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "not relayed"));
    }
    // Refused or unreachable: dropping closes the container's connection,
    // which is what it would see from a real host too.
    let target = TcpStream::connect((ip, port))?;
    target.set_nodelay(true)?;
    let mut to_guest = std::fs::File::from(stream.fd.try_clone()?);
    let mut target_read = target.try_clone()?;
    let mut target_write = target;
    let down = std::thread::Builder::new().name("kiri-host-bound-down".into()).spawn(move || {
        let _ = copy(&mut target_read, &mut to_guest);
        // SAFETY: half-closing a socket we own.
        unsafe { libc::shutdown(to_guest.as_raw_fd(), libc::SHUT_WR) };
    })?;
    let _ = copy(&mut from_guest, &mut target_write);
    let _ = target_write.shutdown(Shutdown::Write);
    let _ = down.join();
    drop(stream);
    Ok(())
}

/// The guest's relay only ever asks for the Mac's loopback; anything else is
/// a guest process speaking the protocol itself. A router's port is refused
/// too: it serves this Mac, and would take a container to any container.
fn host_bound_allowed(ip: std::net::Ipv4Addr, port: u16, router: impl Fn(u16) -> bool) -> bool {
    ip == std::net::Ipv4Addr::LOCALHOST && !router(port)
}

/// How long an outbound host-dialed TCP connection waits to connect.
const EGRESS_CONNECT: Duration = Duration::from_secs(10);
/// Default macOS `VZNATNetworkDeviceAttachment` (`bridge100`) subnet.
pub const DEFAULT_VM_SUBNET: ([u8; 4], u8) = ([192, 168, 64, 0], 24);
/// RFC 2544 benchmarking range used as a synthetic Fake-IP pool by macOS
/// security network extensions (#367).
pub const FAKE_IP_CIDR: ([u8; 4], u8) = ([198, 18, 0, 0], 15);
/// Prefix of the VM's NAT uplink: `VZNATNetworkDeviceAttachment` leases a /24.
pub const VM_UPLINK_PREFIX: u8 = 24;
/// Additional VM NAT bridge subnets learned at runtime (`bridge100`, guest
/// uplink), via `set_vm_subnet`.
static VM_SUBNETS: Mutex<Vec<([u8; 4], u8)>> = Mutex::new(Vec::new());

pub fn ipv4_mask(prefix: u8) -> u32 {
    let p = prefix.min(32);
    if p == 0 { 0 } else { u32::MAX << (32 - p) }
}

pub fn mask_ipv4(ip: [u8; 4], prefix: u8) -> [u8; 4] {
    (u32::from_be_bytes(ip) & ipv4_mask(prefix)).to_be_bytes()
}

pub fn cidr_contains(net: [u8; 4], prefix: u8, ip: [u8; 4]) -> bool {
    let mask = ipv4_mask(prefix);
    (u32::from_be_bytes(ip) & mask) == (u32::from_be_bytes(net) & mask)
}

/// Whether the host egress dialer may connect to `ip:port` on behalf of a
/// container. Rejects loopback (`127.0.0.0/8`), unspecified (`0.0.0.0/8`),
/// link-local (`169.254.0.0/16`), multicast and reserved (`224.0.0.0/4`,
/// `240.0.0.0/4`, broadcast), `host.docker.internal` (`198.19.248.254`),
/// port 0, and the VM's own NAT bridge subnet (`192.168.64.0/24` and any
/// subnet in `vm_subnets`).
pub fn egress_allowed(ip: std::net::Ipv4Addr, port: u16, vm_subnets: &[([u8; 4], u8)]) -> bool {
    let o = ip.octets();
    if port == 0
        || o[0] == 0
        || o[0] == 127
        || (o[0] == 169 && o[1] == 254)
        || o[0] >= 224
        || o == [198, 19, 248, 254]
        || cidr_contains(DEFAULT_VM_SUBNET.0, DEFAULT_VM_SUBNET.1, o)
        || vm_subnets.iter().any(|&(net, prefix)| cidr_contains(net, prefix, o))
    {
        return false;
    }
    true
}

/// Records the VM's NAT uplink subnet, learned from the agent's `Uplink`
/// (its gateway is the Mac's side of the NAT network), so the host egress
/// dialer refuses it as it does `DEFAULT_VM_SUBNET` even when macOS picked
/// another bridge subnet.
pub fn set_vm_subnet(gateway: [u8; 4], prefix: u8) {
    let prefix = prefix.min(32);
    let net = (mask_ipv4(gateway, prefix), prefix);
    let mut subnets = VM_SUBNETS.lock().unwrap_or_else(|e| e.into_inner());
    if !subnets.contains(&net) {
        subnets.push(net);
    }
}

fn current_vm_subnets() -> Vec<([u8; 4], u8)> {
    VM_SUBNETS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Whether the host egress dialer may connect to `ip:port` now, given the VM
/// NAT subnets learned so far.
fn egress_target_allowed(ip: std::net::Ipv4Addr, port: u16) -> bool {
    egress_allowed(ip, port, &current_vm_subnets())
}

/// One outbound TCP connection redirected from a container to the host
/// dialer (`kiri_proto::EGRESS_TCP_PORT`): the guest sends `ip[4] port[2]`,
/// and the daemon dials it from the host process so macOS split-tunnel VPN
/// routes (`utun*`, `ipsec*`, `ppp*`, #319) and NetworkExtension socket
/// filters (#367, #616) carry the connection.
pub fn serve_egress(stream: kiri_vmm::VsockStream) {
    let Some(permit) = tcp_permit(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)) else {
        return;
    };
    let _ = std::thread::Builder::new().name("kiri-egress".into()).spawn(move || {
        let _permit = permit;
        let _ = egress(stream);
    });
}

fn egress(stream: kiri_vmm::VsockStream) -> io::Result<()> {
    vsock_stall(stream.fd.as_raw_fd())?;
    let mut from_guest = std::fs::File::from(stream.fd.try_clone()?);
    let mut header = [0u8; 6];
    from_guest.read_exact(&mut header)?;
    let ip = std::net::Ipv4Addr::new(header[0], header[1], header[2], header[3]);
    let port = u16::from_be_bytes([header[4], header[5]]);
    if !egress_target_allowed(ip, port) {
        crate::diag::warn!("refused an outbound egress connection to a restricted address", to = format!("{ip}:{port}"));
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "egress target not allowed"));
    }
    let target = TcpStream::connect_timeout(&SocketAddr::from((ip, port)), EGRESS_CONNECT)?;
    relayed_tcp(&target)?;
    let mut to_guest = std::fs::File::from(stream.fd.try_clone()?);
    let mut target_read = target.try_clone()?;
    let mut target_write = target;
    let down = std::thread::Builder::new().name("kiri-egress-down".into()).spawn(move || {
        let how = match pass_on(copy(&mut target_read, &mut to_guest)) {
            Shutdown::Write => libc::SHUT_WR,
            _ => libc::SHUT_RDWR,
        };
        // SAFETY: shutting down a socket we own.
        unsafe { libc::shutdown(to_guest.as_raw_fd(), how) };
    })?;
    let up = copy(&mut from_guest, &mut target_write);
    let _ = target_write.shutdown(pass_on(up));
    let _ = down.join();
    drop(stream);
    Ok(())
}

/// Whether `name` is a tunnel interface that macOS `InternetSharing` does not
/// NAT `bridge100` out of (`utun*`, `ipsec*`, `ppp*`, `gpd*`, `feth*`).
pub fn is_tunnel_iface(name: &str) -> bool {
    ["utun", "ipsec", "ppp", "gpd", "feth"]
        .iter()
        .any(|prefix| name.strip_prefix(prefix).is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())))
}

/// Collapses a set of IPv4 CIDRs, removing duplicates and any sub-prefix
/// already covered by a broader prefix in the set.
pub fn collapse_cidrs(cidrs: impl IntoIterator<Item = ([u8; 4], u8)>) -> Vec<([u8; 4], u8)> {
    let mut list: Vec<([u8; 4], u8)> = cidrs
        .into_iter()
        .map(|(ip, prefix)| {
            let p = prefix.min(32);
            (mask_ipv4(ip, p), p)
        })
        .collect();
    list.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    list.dedup();
    let mut out: Vec<([u8; 4], u8)> = Vec::with_capacity(list.len());
    for (net, prefix) in list {
        if !out.iter().any(|&(broader_net, broader_prefix)| broader_prefix <= prefix && cidr_contains(broader_net, broader_prefix, net)) {
            out.push((net, prefix));
        }
    }
    out
}

/// Parses a macOS `sysctl([CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0])`
/// binary routing table buffer and returns the collapsed IPv4 CIDR prefixes
/// whose outgoing interface is a tunnel (`is_tunnel_iface`), skipping
/// loopback, link-local and multicast/reserved destinations.
pub fn parse_macos_routes(buf: &[u8], ifname_of: impl Fn(u16) -> Option<String>) -> Vec<([u8; 4], u8)> {
    const RTM_HDR_LEN: usize = 92;
    const RTM_VERSION: u8 = 5;
    const RTF_UP: i32 = 0x1;
    const RTF_HOST: i32 = 0x4;
    const RTF_LLINFO: i32 = 0x400;
    const RTF_WASCLONED: i32 = 0x20000;
    const RTF_IFSCOPE: i32 = 0x1000000;
    const AF_INET_U8: u8 = libc::AF_INET as u8;

    #[cfg(target_os = "macos")]
    const _: () = assert!(std::mem::size_of::<libc::rt_msghdr>() == RTM_HDR_LEN);

    let mut entries: Vec<([u8; 4], u8, String)> = Vec::new();
    let mut off = 0;
    while off + RTM_HDR_LEN <= buf.len() {
        let msglen = u16::from_ne_bytes([buf[off], buf[off + 1]]) as usize;
        if msglen < RTM_HDR_LEN || off + msglen > buf.len() {
            break;
        }
        let msg = &buf[off..off + msglen];
        off += msglen;

        let version = msg[2];
        if version != RTM_VERSION {
            continue;
        }
        let ifindex = u16::from_ne_bytes([msg[4], msg[5]]);
        let flags = i32::from_ne_bytes([msg[8], msg[9], msg[10], msg[11]]);
        let addrs = i32::from_ne_bytes([msg[12], msg[13], msg[14], msg[15]]);
        if flags & RTF_UP == 0 || flags & (RTF_WASCLONED | RTF_LLINFO | RTF_IFSCOPE) != 0 || addrs & 0x1 == 0 {
            continue;
        }
        let mut pos = RTM_HDR_LEN;
        let mut dst: Option<[u8; 4]> = None;
        let mut mask_prefix: Option<u8> = None;
        let mut ok = true;
        for bit in 0..8 {
            if addrs & (1 << bit) == 0 {
                continue;
            }
            if pos + 2 > msg.len() {
                ok = false;
                break;
            }
            let sa_len = msg[pos];
            let sa_family = msg[pos + 1];
            let step = if sa_len == 0 { 4 } else { ((sa_len as usize) + 3) & !3 };
            if bit == 0 {
                if sa_family != AF_INET_U8 || sa_len < 8 || pos + 8 > msg.len() {
                    ok = false;
                    break;
                }
                dst = Some([msg[pos + 4], msg[pos + 5], msg[pos + 6], msg[pos + 7]]);
            } else if bit == 2 {
                let mut mask = [0u8; 4];
                let avail = (sa_len as usize).min(msg.len().saturating_sub(pos)).saturating_sub(4).min(4);
                if avail > 0 {
                    mask[..avail].copy_from_slice(&msg[pos + 4..pos + 4 + avail]);
                }
                mask_prefix = Some(u32::from_be_bytes(mask).leading_ones() as u8);
            }
            if pos + step > msg.len() {
                break;
            }
            pos += step;
        }
        if !ok {
            continue;
        }
        let Some(dst_ip) = dst else { continue };
        let prefix = if flags & RTF_HOST != 0 {
            32
        } else {
            mask_prefix.unwrap_or(0)
        };
        let Some(ifname) = ifname_of(ifindex).filter(|s| !s.is_empty()) else { continue };
        entries.push((mask_ipv4(dst_ip, prefix), prefix, ifname));
    }

    let mut routes = Vec::new();
    for (dst, prefix, ifname) in entries {
        if !is_tunnel_iface(&ifname) {
            continue;
        }
        // Every tunnel route is kept, the default route too when a full
        // tunnel VPN replaced the primary interface. Skip loopback, link-local, multicast/reserved and 0.0.0.0/32.
        if dst[0] == 127
            || (dst[0] == 169 && dst[1] == 254)
            || dst[0] >= 224
            || (dst == [0, 0, 0, 0] && prefix == 32)
        {
            continue;
        }
        routes.push((dst, prefix));
    }
    collapse_cidrs(routes)
}

/// Whether `identifier` (and optional extension points blob/text) is a pure
/// packet-tunnel VPN extension whose routes live in the kernel routing table
/// on `utun*`, rather than a transparent proxy, content filter or DNS proxy.
fn is_pure_packet_tunnel_ext(identifier: &str, ext_points_haystack: &[u8]) -> bool {
    if identifier.starts_with("io.tailscale.") || identifier.starts_with("com.wireguard.") {
        return true;
    }
    let has_bytes = |needle: &[u8]| ext_points_haystack.windows(needle.len()).any(|w| w == needle);
    let has_packet_tunnel = has_bytes(b"com.apple.networkextension.packet-tunnel");
    let has_filter_or_proxy = has_bytes(b"com.apple.networkextension.filter-data")
        || has_bytes(b"com.apple.networkextension.filter-packet")
        || has_bytes(b"com.apple.networkextension.app-proxy")
        || has_bytes(b"com.apple.networkextension.dns-proxy")
        || has_bytes(b"com.apple.networkextension.transparent-proxy");
    has_packet_tunnel && !has_filter_or_proxy
}

fn is_network_ext_category(cat: &str) -> bool {
    matches!(
        cat,
        "com.apple.system_extension.network_extension" | "com.apple.developer.networking.networkextension"
    )
}

/// Parses `/Library/SystemExtensions/db.plist` (either XML plist or `bplist00`
/// binary plist) and returns true when an active (`activated_enabled`)
/// third-party macOS NetworkExtension content filter, transparent proxy or
/// DNS proxy is enabled (#367, #616).
pub fn has_active_network_extension(plist: &[u8]) -> bool {
    if plist.starts_with(b"bplist00") {
        has_active_network_extension_bplist(plist)
    } else if let Ok(xml) = std::str::from_utf8(plist) {
        has_active_network_extension_xml(xml)
    } else {
        false
    }
}

fn has_active_network_extension_xml(xml: &str) -> bool {
    // Walk top-level <dict> entries inside <key>extensions</key><array>...</array>
    // (or any <dict> if the snippet is not wrapped in <key>extensions</key>).
    let scope = match xml.find("<key>extensions</key>") {
        Some(idx) => &xml[idx..],
        None => xml,
    };
    for dict in xml_extension_dicts(scope) {
        let Some(id) = xml_key_string(dict, "identifier") else { continue };
        let Some(state) = xml_key_string(dict, "state") else { continue };
        if state != "activated_enabled" || id.is_empty() || id.starts_with("com.apple.") {
            continue;
        }
        let has_net_cat = dict.contains("com.apple.system_extension.network_extension")
            || dict.contains("com.apple.developer.networking.networkextension");
        if !has_net_cat {
            continue;
        }
        if is_pure_packet_tunnel_ext(id, dict.as_bytes()) {
            continue;
        }
        return true;
    }
    false
}

/// Extracts each extension `<dict>...</dict>` block from `xml`, tracking
/// nested `<dict>` depth so sub-dictionaries (`bundleVersion`, `container`,
/// `stagedBundleURL`) stay inside their parent extension block.
fn xml_extension_dicts(xml: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let base_depth = if xml.trim_start().starts_with("<key>extensions</key>") { 1 } else { 2 };
    let mut depth = 0usize;
    let mut start: Option<usize> = None;
    let mut i = 0;
    let bytes = xml.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'<' {
            if xml[i..].starts_with("<dict>") || xml[i..].starts_with("<dict ") {
                depth += 1;
                if depth == base_depth && start.is_none() {
                    start = Some(i);
                }
                i += 6;
                continue;
            } else if xml[i..].starts_with("</dict>") {
                if depth == base_depth
                    && let Some(s) = start.take()
                {
                    out.push(&xml[s..i + 7]);
                }
                depth = depth.saturating_sub(1);
                i += 7;
                continue;
            }
        }
        i += 1;
    }
    if out.is_empty() && base_depth == 2 {
        // Fallback for a bare `<dict>...</dict>` fixture at depth 1.
        return xml_extension_dicts_at(xml, 1);
    }
    out
}

fn xml_extension_dicts_at(xml: &str, target_depth: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start: Option<usize> = None;
    let mut i = 0;
    let bytes = xml.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'<' {
            if xml[i..].starts_with("<dict>") || xml[i..].starts_with("<dict ") {
                depth += 1;
                if depth == target_depth && start.is_none() {
                    start = Some(i);
                }
                i += 6;
                continue;
            } else if xml[i..].starts_with("</dict>") {
                if depth == target_depth
                    && let Some(s) = start.take()
                {
                    out.push(&xml[s..i + 7]);
                }
                depth = depth.saturating_sub(1);
                i += 7;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn xml_key_string<'a>(dict: &'a str, key: &str) -> Option<&'a str> {
    let pattern = format!("<key>{key}</key>");
    let idx = dict.find(&pattern)?;
    let rest = dict[idx + pattern.len()..].trim_start();
    let rest = rest.strip_prefix("<string>")?;
    let end = rest.find("</string>")?;
    Some(rest[..end].trim())
}

#[derive(Debug)]
enum BplistObj<'a> {
    Str(&'a str),
    Data(&'a [u8]),
    Array(Vec<usize>),
    Dict(Vec<(usize, usize)>),
    Other,
}

fn read_be_uint(b: &[u8]) -> Option<usize> {
    if b.is_empty() || b.len() > 8 {
        return None;
    }
    let mut v = 0usize;
    for &byte in b {
        v = (v << 8) | (byte as usize);
    }
    Some(v)
}

fn bplist_len(buf: &[u8], pos: usize, low: u8) -> Option<(usize, usize)> {
    if low != 0x0f {
        return Some((low as usize, pos));
    }
    let marker = *buf.get(pos)?;
    if (marker >> 4) != 0x1 {
        return None;
    }
    let nbytes = 1usize << (marker & 0x0f);
    let end = pos.checked_add(1)?.checked_add(nbytes)?;
    let len = read_be_uint(buf.get(pos + 1..end)?)?;
    Some((len, end))
}

fn parse_bplist(buf: &[u8]) -> Option<(usize, Vec<BplistObj<'_>>)> {
    if buf.len() < 40 || !buf.starts_with(b"bplist00") {
        return None;
    }
    let trailer = &buf[buf.len() - 32..];
    let offset_size = trailer[6] as usize;
    let ref_size = trailer[7] as usize;
    if !(1..=8).contains(&offset_size) || !(1..=8).contains(&ref_size) {
        return None;
    }
    let num_objects = read_be_uint(&trailer[8..16])?;
    let top_object = read_be_uint(&trailer[16..24])?;
    let offset_table = read_be_uint(&trailer[24..32])?;
    if num_objects == 0 || num_objects > 65_536 || top_object >= num_objects {
        return None;
    }
    let table_end = offset_table.checked_add(num_objects.checked_mul(offset_size)?)?;
    if table_end > buf.len() - 32 {
        return None;
    }
    let mut objs = Vec::with_capacity(num_objects);
    for i in 0..num_objects {
        let off_pos = offset_table + i * offset_size;
        let obj_off = read_be_uint(buf.get(off_pos..off_pos + offset_size)?)?;
        let marker = *buf.get(obj_off)?;
        let kind = marker >> 4;
        let low = marker & 0x0f;
        let obj = match kind {
            0x4 => {
                let (len, start) = bplist_len(buf, obj_off + 1, low)?;
                BplistObj::Data(buf.get(start..start.checked_add(len)?)?)
            }
            0x5 => {
                let (len, start) = bplist_len(buf, obj_off + 1, low)?;
                let s = std::str::from_utf8(buf.get(start..start.checked_add(len)?)?).ok()?;
                BplistObj::Str(s)
            }
            0xa => {
                let (count, start) = bplist_len(buf, obj_off + 1, low)?;
                if count > 65_536 {
                    return None;
                }
                let mut items = Vec::with_capacity(count);
                for j in 0..count {
                    let p = start.checked_add(j.checked_mul(ref_size)?)?;
                    items.push(read_be_uint(buf.get(p..p.checked_add(ref_size)?)?)?);
                }
                BplistObj::Array(items)
            }
            0xd => {
                let (count, start) = bplist_len(buf, obj_off + 1, low)?;
                if count > 65_536 {
                    return None;
                }
                let vals_start = start.checked_add(count.checked_mul(ref_size)?)?;
                let mut pairs = Vec::with_capacity(count);
                for j in 0..count {
                    let kp = start + j * ref_size;
                    let vp = vals_start + j * ref_size;
                    let k = read_be_uint(buf.get(kp..kp.checked_add(ref_size)?)?)?;
                    let v = read_be_uint(buf.get(vp..vp.checked_add(ref_size)?)?)?;
                    pairs.push((k, v));
                }
                BplistObj::Dict(pairs)
            }
            _ => BplistObj::Other,
        };
        objs.push(obj);
    }
    Some((top_object, objs))
}

fn has_active_network_extension_bplist(buf: &[u8]) -> bool {
    let Some((top, objs)) = parse_bplist(buf) else { return false };
    let get_dict_field = |pairs: &[(usize, usize)], key: &str| -> Option<usize> {
        pairs.iter().find_map(|&(k, v)| match objs.get(k) {
            Some(BplistObj::Str(s)) if *s == key => Some(v),
            _ => None,
        })
    };
    let get_str = |idx: usize| -> Option<&str> {
        match objs.get(idx) {
            Some(BplistObj::Str(s)) => Some(*s),
            _ => None,
        }
    };
    let Some(BplistObj::Dict(root)) = objs.get(top) else { return false };
    let Some(ext_idx) = get_dict_field(root, "extensions") else { return false };
    let Some(BplistObj::Array(items)) = objs.get(ext_idx) else { return false };
    for &item in items {
        let Some(BplistObj::Dict(pairs)) = objs.get(item) else { continue };
        let Some(id) = get_dict_field(pairs, "identifier").and_then(get_str) else { continue };
        let Some(state) = get_dict_field(pairs, "state").and_then(get_str) else { continue };
        if state != "activated_enabled" || id.is_empty() || id.starts_with("com.apple.") {
            continue;
        }
        let has_net_cat = get_dict_field(pairs, "categories").is_some_and(|cidx| match objs.get(cidx) {
            Some(BplistObj::Array(cats)) => cats.iter().any(|&c| get_str(c).is_some_and(is_network_ext_category)),
            _ => false,
        });
        if !has_net_cat {
            continue;
        }
        let launchd_data = get_dict_field(pairs, "additionalLaunchdPlistEntries")
            .and_then(|didx| match objs.get(didx) {
                Some(BplistObj::Data(d)) => Some(*d),
                _ => None,
            })
            .unwrap_or(&[]);
        if is_pure_packet_tunnel_ext(id, launchd_data) {
            continue;
        }
        return true;
    }
    false
}

fn parse_cidr_str(s: &str) -> Option<([u8; 4], u8)> {
    let (ip, prefix) = s.trim().split_once('/')?;
    let ip = ip.parse::<std::net::Ipv4Addr>().ok()?.octets();
    let prefix: u8 = prefix.parse().ok().filter(|&p| p <= 32)?;
    Some((mask_ipv4(ip, prefix), prefix))
}

/// Computes the egress CIDR strings to send to the guest given:
/// - `env_mode`: `KIRI_HOST_EGRESS` (`auto`, `always`, `off`, or comma-separated CIDRs)
/// - `has_net_ext`: whether an active third-party macOS NetworkExtension filter/proxy is enabled
/// - `tunnel_routes`: IPv4 prefixes routed over tunnel interfaces (`utun*`, `ipsec*`, `ppp*`, `gpd*`, `feth*`)
/// - `is_macos`: whether the host is macOS
pub fn host_egress_routes_for(
    env_mode: Option<&str>,
    has_net_ext: bool,
    tunnel_routes: &[([u8; 4], u8)],
    is_macos: bool,
) -> Vec<String> {
    let mode = env_mode.map(str::trim).unwrap_or("auto");
    if mode.eq_ignore_ascii_case("off") || mode.eq_ignore_ascii_case("0") || mode.eq_ignore_ascii_case("false") || mode.eq_ignore_ascii_case("no") {
        return Vec::new();
    }
    if mode.eq_ignore_ascii_case("always") || mode.eq_ignore_ascii_case("1") || mode.eq_ignore_ascii_case("true") || mode.eq_ignore_ascii_case("all") {
        return vec!["0.0.0.0/0".into()];
    }
    if mode.contains('/') {
        let parsed: Vec<([u8; 4], u8)> = mode.split(',').filter_map(parse_cidr_str).collect();
        return collapse_cidrs(parsed)
            .into_iter()
            .map(|(ip, p)| format!("{}.{}.{}.{}/{p}", ip[0], ip[1], ip[2], ip[3]))
            .collect();
    }
    if !is_macos {
        return Vec::new();
    }
    if has_net_ext {
        return vec!["0.0.0.0/0".into()];
    }
    let mut all = tunnel_routes.to_vec();
    all.push(FAKE_IP_CIDR);
    collapse_cidrs(all)
        .into_iter()
        .map(|(ip, p)| format!("{}.{}.{}.{}/{p}", ip[0], ip[1], ip[2], ip[3]))
        .collect()
}

#[cfg(target_os = "macos")]
fn dump_macos_route_table() -> Option<Vec<u8>> {
    let mut mib = [libc::CTL_NET, libc::PF_ROUTE, 0, libc::AF_INET, libc::NET_RT_DUMP, 0];
    let mut len: libc::size_t = 0;
    // SAFETY: sysctl with null oldp queries the required buffer size.
    if unsafe { libc::sysctl(mib.as_mut_ptr(), 6, std::ptr::null_mut(), &mut len, std::ptr::null_mut(), 0) } != 0 || len == 0 {
        return None;
    }
    // Add headroom in case a route is added between the two calls.
    len = len.saturating_add(4096);
    let mut buf = vec![0u8; len];
    // SAFETY: sysctl writes at most `len` bytes into `buf`.
    if unsafe { libc::sysctl(mib.as_mut_ptr(), 6, buf.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0) } != 0 {
        return None;
    }
    buf.truncate(len);
    Some(buf)
}

#[cfg(target_os = "macos")]
fn macos_ifname(index: u16) -> Option<String> {
    let mut buf = [0 as libc::c_char; libc::IFNAMSIZ];
    // SAFETY: `buf` is IFNAMSIZ bytes, as if_indextoname requires.
    let ptr = unsafe { libc::if_indextoname(index as libc::c_uint, buf.as_mut_ptr()) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: if_indextoname NUL-terminates `buf` on success.
    Some(unsafe { std::ffi::CStr::from_ptr(ptr) }.to_string_lossy().into_owned())
}

pub fn current_egress_routes() -> Vec<String> {
    let env_mode = std::env::var("KIRI_HOST_EGRESS").ok();
    #[cfg(target_os = "macos")]
    let (has_ext, tunnel_routes) = {
        let ext = std::fs::read("/Library/SystemExtensions/db.plist")
            .ok()
            .is_some_and(|b| has_active_network_extension(&b));
        let routes = dump_macos_route_table()
            .map(|b| parse_macos_routes(&b, macos_ifname))
            .unwrap_or_default();
        (ext, routes)
    };
    #[cfg(not(target_os = "macos"))]
    let (has_ext, tunnel_routes) = (false, Vec::new());
    host_egress_routes_for(env_mode.as_deref(), has_ext, &tunnel_routes, cfg!(target_os = "macos"))
}

/// Sends the initial egress routes to `vm` and, on macOS, watches `PF_ROUTE`
/// for routing table changes (a VPN connecting or disconnecting while Kiri
/// runs) so `Msg::SetEgressRoutes` stays current without restarting the VM.
pub fn sync_egress_routes(vm: &Arc<VmLink>) {
    let initial = current_egress_routes();
    if !initial.is_empty() {
        let _ = vm.set_egress_routes(&initial);
    }
    #[cfg(target_os = "macos")]
    {
        let weak = Arc::downgrade(vm);
        let _ = std::thread::Builder::new().name("kiri-route-watch".into()).spawn(move || {
            watch_macos_routes(weak, initial);
        });
    }
}

#[cfg(target_os = "macos")]
fn watch_macos_routes(weak: std::sync::Weak<VmLink>, mut last: Vec<String>) {
    // SAFETY: opening a raw PF_ROUTE socket to hear kernel routing changes.
    let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
    let sock = if fd >= 0 {
        // SAFETY: `fd` is a fresh descriptor owned only here.
        unsafe {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            let tv = libc::timeval { tv_sec: 2, tv_usec: 0 };
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&tv as *const libc::timeval).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
            Some(OwnedFd::from_raw_fd(fd))
        }
    } else {
        None
    };
    let mut buf = [0u8; 4096];
    loop {
        match &sock {
            Some(s) => {
                // SAFETY: reading into a local buffer with SO_RCVTIMEO set.
                let n = unsafe { libc::read(s.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                if n > 0 {
                    // Drain any burst of route messages before dumping once.
                    // SAFETY: non-blocking recv into a local buffer.
                    while unsafe { libc::recv(s.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) } > 0 {}
                }
            }
            None => std::thread::sleep(Duration::from_secs(2)),
        }
        let Some(vm) = weak.upgrade().filter(|v| !v.is_disconnected()) else {
            return;
        };
        let next = current_egress_routes();
        if next != last {
            last = next;
            let _ = vm.set_egress_routes(&last);
        }
    }
}

/// vsock port the guest dials for SSH agent connections.
pub const SSH_AGENT_PORT: u32 = 1027;

/// The Mac's SSH agent socket: `$SSH_AUTH_SOCK`, or launchd's if the daemon
/// was not started from a shell that has it.
fn ssh_auth_sock() -> Option<std::path::PathBuf> {
    if let Some(p) = std::env::var_os("SSH_AUTH_SOCK") {
        return Some(p.into());
    }
    let out = std::process::Command::new("/bin/launchctl").args(["getenv", "SSH_AUTH_SOCK"]).output().ok()?;
    let p = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (!p.is_empty()).then(|| p.into())
}

/// One container connection to the SSH agent, relayed to the Mac's agent.
pub fn serve_ssh_agent(stream: kiri_vmm::VsockStream) {
    let _ = std::thread::Builder::new().name("kiri-ssh-agent".into()).spawn(move || {
        let Some(path) = ssh_auth_sock() else { return };
        let Ok(agent) = std::os::unix::net::UnixStream::connect(path) else {
            return;
        };
        let (Ok(mut agent_read), Ok(from_guest), Ok(to_guest)) = (agent.try_clone(), stream.fd.try_clone(), stream.fd.try_clone()) else {
            return;
        };
        let mut from_guest = std::fs::File::from(from_guest);
        let mut to_guest = std::fs::File::from(to_guest);
        let mut agent_write = agent;
        let down = std::thread::spawn(move || {
            let _ = copy(&mut agent_read, &mut to_guest);
            // SAFETY: half-closing a socket we own.
            unsafe { libc::shutdown(to_guest.as_raw_fd(), libc::SHUT_WR) };
        });
        let _ = copy(&mut from_guest, &mut agent_write);
        let _ = agent_write.shutdown(Shutdown::Write);
        let _ = down.join();
        drop(stream);
    });
}

/// vsock port the guest dials for the engine's API: containers that mount
/// the docker socket (crates/kiri/src/daemon/binds.rs).
pub const ENGINE_API_PORT: u32 = 1036;

/// One container connection to the engine's API, served like any other
/// client's, marked as a container's.
pub fn serve_engine_api(stream: kiri_vmm::VsockStream, engine: std::sync::Weak<super::engine::Engine>) {
    let _ = std::thread::Builder::new().name("kiri-engine-api".into()).spawn(move || {
        // Served here rather than through the daemon's socket, so the API
        // knows these requests are a container's (caller.rs).
        let Some(engine) = engine.upgrade() else { return };
        let Ok((api, ours)) = std::os::unix::net::UnixStream::pair() else { return };
        let served = std::thread::Builder::new().name("kiri-api".into()).spawn(move || {
            let _ = super::api::serve(ours, engine, super::caller::Caller::Container);
        });
        if served.is_err() {
            return;
        }
        let (Ok(mut api_read), Ok(from_guest), Ok(to_guest)) = (api.try_clone(), stream.fd.try_clone(), stream.fd.try_clone()) else {
            return;
        };
        let mut from_guest = std::fs::File::from(from_guest);
        let mut to_guest = std::fs::File::from(to_guest);
        let mut api_write = api;
        let down = std::thread::spawn(move || {
            let _ = copy(&mut api_read, &mut to_guest);
            // SAFETY: half-closing a socket we own.
            unsafe { libc::shutdown(to_guest.as_raw_fd(), libc::SHUT_WR) };
        });
        let _ = copy(&mut from_guest, &mut api_write);
        let _ = api_write.shutdown(Shutdown::Write);
        let _ = down.join();
        drop(stream);
    });
}

/// The TCP ports in a container's `/proc/net/tcp` and `tcp6` lines that are
/// listening: those a published port reaches, then those it does not. The
/// relay dials the container's IPv4 address, so a socket bound to loopback
/// alone, or to one IPv6 address, is out of its reach; with host networking
/// it dials 127.0.0.1, so loopback is in reach there. Each port once, sorted.
pub fn listening<S: AsRef<str>>(lines: &[S], host_network: bool) -> (Vec<u16>, Vec<u16>) {
    use std::collections::BTreeSet;
    use std::net::{Ipv4Addr, Ipv6Addr};
    let v4_reach = |ip: Ipv4Addr| !ip.is_loopback() || host_network;
    let (mut reach, mut local) = (BTreeSet::new(), BTreeSet::new());
    for line in lines {
        let f: Vec<&str> = line.as_ref().split_whitespace().collect();
        // The fourth field is the state; 0A is LISTEN.
        if f.get(3) != Some(&"0A") {
            continue;
        }
        let Some((addr, port)) = f.get(1).and_then(|a| a.split_once(':')) else { continue };
        let Ok(port) = u16::from_str_radix(port, 16) else { continue };
        // The kernel prints each 32-bit word of the address in the guest's
        // own byte order, which is little-endian on every guest we run.
        let words: Option<Vec<[u8; 4]>> = (0..addr.len() / 8).map(|i| addr.get(i * 8..i * 8 + 8).and_then(|w| u32::from_str_radix(w, 16).ok()).map(u32::to_le_bytes)).collect();
        let ok = match (addr.len(), words) {
            (8, Some(w)) => v4_reach(Ipv4Addr::from(w[0])),
            (32, Some(w)) => {
                let ip = Ipv6Addr::from(<[u8; 16]>::try_from(w.concat()).unwrap_or_default());
                ip.is_unspecified() || ip.to_ipv4_mapped().is_some_and(v4_reach)
            }
            _ => continue,
        };
        if port != 0 {
            if ok { reach.insert(port) } else { local.insert(port) };
        }
    }
    let local = local.difference(&reach).copied().collect();
    (reach.into_iter().collect(), local)
}

#[cfg(test)]
mod tests {
    use super::{MAX_PEER_SESSIONS, MAX_REMOTE_SESSIONS, MAX_TCP_SESSIONS, NAT_PORTS, REMOTE_SESSIONS, TCP_SESSIONS, host_bound_allowed, kernel_forwards, kernel_host_ip, listening, nat_port, relays_too, tcp_permit};
    use std::net::IpAddr;
    use std::sync::atomic::Ordering;

    /// host.docker.internal reaches the Mac's loopback, but never the
    /// container-domain router there: its Host header would take a container
    /// to any other container, past the networks that keep them apart.
    #[test]
    fn containers_never_reach_the_domain_routers() {
        let local = std::net::Ipv4Addr::LOCALHOST;
        let router = |p: u16| p == 80 || p == 443;
        assert!(!host_bound_allowed(local, 80, router));
        assert!(!host_bound_allowed(local, 443, router));
        assert!(host_bound_allowed(local, 5432, router), "other loopback services stay reachable");
        assert!(!host_bound_allowed(std::net::Ipv4Addr::new(10, 0, 0, 1), 5432, router), "loopback only");
    }

    /// A clash names the other program holding the port, never Kiri itself.
    #[test]
    fn a_taken_port_names_the_program_that_has_it() {
        use super::holder_in;
        assert_eq!(holder_in("p85299\ncPython\nf3\n").as_deref(), Some("Python"));
        assert_eq!(holder_in("p10\nckiri\nf7\np11\ncOrbStack Helper\nf9\n").as_deref(), Some("OrbStack Helper"));
        assert_eq!(holder_in("p10\nckiri\nf7\n"), None);
        assert_eq!(holder_in("p10\ncKiri Dev\n"), None);
        assert_eq!(holder_in(""), None);
    }

    #[test]
    fn non_ipv4_bindings_never_become_wildcard() {
        assert_eq!(kernel_host_ip(""), Some([0; 4]));
        assert_eq!(kernel_host_ip("0.0.0.0"), Some([0; 4]));
        assert_eq!(kernel_host_ip("127.0.0.1"), Some([127, 0, 0, 1]));
        for ip in ["::", "::1", "[::1]", "2001:db8::1", "not-an-ip"] {
            assert_eq!(kernel_host_ip(ip), None, "{ip}");
        }
    }

    #[test]
    fn linux_hosts_relay_loopback_and_forward_the_rest() {
        // The kernel takes every IPv4 address but loopback.
        for ip in ["", "0.0.0.0", "192.168.1.5", "10.0.0.1"] {
            assert!(kernel_forwards(ip), "{ip}");
        }
        for ip in ["127.0.0.1", "127.0.0.2", "::1", "::", "not-an-ip"] {
            assert!(!kernel_forwards(ip), "{ip}");
        }
        // The relay takes loopback, IPv6, and every-address's 127.0.0.1 share.
        for ip in ["", "0.0.0.0", "127.0.0.1", "::1", "::"] {
            assert!(relays_too(ip), "{ip}");
        }
        assert!(!relays_too("192.168.1.5"));
    }

    const TCP: [&str; 5] = [
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
        "   0: 00000000:11D7 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4101 1 0000000000000000 100 0 0 10 0",
        "   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4102 1 0000000000000000 100 0 0 10 0",
        "   2: 0200A8C0:11D7 0100A8C0:C350 01 00000000:00000000 00:00000000 00000000     0        0 4103 1 0000000000000000 20 4 30 10 -1",
        "   3: 0200A8C0:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4104 1 0000000000000000 100 0 0 10 0",
    ];
    const TCP6: [&str; 5] = [
        "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
        "   0: 00000000000000000000000000000000:11D7 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4201 1 0000000000000000 100 0 0 10 0",
        "   1: 00000000000000000000000001000000:0CEA 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4202 1 0000000000000000 100 0 0 10 0",
        "   2: 0000000000000000FFFF00000100007F:2382 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4203 1 0000000000000000 100 0 0 10 0",
        "   3: 0000000000000000FFFF00000200A8C0:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4204 1 0000000000000000 100 0 0 10 0",
    ];

    #[test]
    fn ipv4_listeners_only_and_loopback_apart() {
        // 4567 on every address, 443 on the container's own; 8080 on loopback
        // only; the established 4567 connection and the header are skipped.
        assert_eq!(listening(&TCP, false), (vec![443, 4567], vec![8080]));
        assert_eq!(listening(&TCP, true), (vec![443, 4567, 8080], vec![]));
    }

    #[test]
    fn ipv6_listeners() {
        // [::]:4567 and ::ffff:192.168.0.2:80 are reachable over IPv4; [::1]:3306
        // and ::ffff:127.0.0.1:9090 are loopback.
        assert_eq!(listening(&TCP6, false), (vec![80, 4567], vec![3306, 9090]));
        // The relay's 127.0.0.1 reaches a mapped loopback socket, never ::1.
        assert_eq!(listening(&TCP6, true), (vec![80, 4567, 9090], vec![3306]));
    }

    #[test]
    fn a_port_on_both_families_counts_once() {
        let both: Vec<&str> = TCP.iter().chain(TCP6.iter()).copied().collect();
        assert_eq!(listening(&both, false), (vec![80, 443, 4567], vec![3306, 8080, 9090]));
        // Bound to loopback and to every address: reachable, not listed twice.
        let lines = [TCP[1], TCP[3].replace("0200A8C0:11D7", "0100007F:11D7").replace(" 01 ", " 0A ").as_str()].map(str::to_owned);
        assert_eq!(listening(&lines, false), (vec![4567], vec![]));
        assert_eq!(listening(&["garbage", "1: zz:11D7 0:0 0A", ""], false), (vec![], vec![]));
    }

    /// A quiet connection stays open, as through docker-proxy (#388); keepalive
    /// finds a peer that went away instead.
    #[test]
    fn relayed_tcp_waits_out_quiet_peers_and_probes_for_gone_ones() {
        use super::{KEEPALIVE_IDLE, TCP_STALL, relayed_tcp};
        use std::os::fd::AsRawFd;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let s = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        relayed_tcp(&s).unwrap();
        assert_eq!(s.read_timeout().unwrap(), None);
        assert_eq!(s.write_timeout().unwrap(), Some(TCP_STALL));
        assert!(s.nodelay().unwrap());
        let opt = |level, name| {
            let mut v: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: reading an int option of a socket we own into a local.
            assert_eq!(unsafe { libc::getsockopt(s.as_raw_fd(), level, name, (&mut v as *mut libc::c_int).cast(), &mut len) }, 0);
            v
        };
        assert_ne!(opt(libc::SOL_SOCKET, libc::SO_KEEPALIVE), 0);
        #[cfg(target_os = "macos")]
        let idle = libc::TCP_KEEPALIVE;
        #[cfg(not(target_os = "macos"))]
        let idle = libc::TCP_KEEPIDLE;
        assert_eq!(opt(libc::IPPROTO_TCP, idle), KEEPALIVE_IDLE.as_secs() as libc::c_int);
    }

    #[test]
    fn tcp_permits_are_bounded_and_released() {
        let local: IpAddr = "127.0.0.1".parse().unwrap();
        let held: Vec<_> = (0..MAX_TCP_SESSIONS).map(|_| tcp_permit(local).expect("permit below limit")).collect();
        assert!(tcp_permit(local).is_none());
        drop(held);
        assert_eq!(TCP_SESSIONS.load(Ordering::Relaxed), 0);
        assert!(tcp_permit(local).is_some());
        assert_eq!(TCP_SESSIONS.load(Ordering::Relaxed), 0);

        // One LAN host: its own share only, and the Mac still gets in.
        let lan: IpAddr = "192.168.2.50".parse().unwrap();
        let flood: Vec<_> = (0..MAX_PEER_SESSIONS).map(|_| tcp_permit(lan).expect("below the peer limit")).collect();
        assert!(tcp_permit(lan).is_none());
        assert!(tcp_permit("::ffff:192.168.2.50".parse().unwrap()).is_none(), "a v4-mapped address is the same peer");
        assert!(tcp_permit("192.168.2.51".parse().unwrap()).is_some());
        assert!(tcp_permit(local).is_some());
        assert!(tcp_permit("::1".parse().unwrap()).is_some());
        // Many LAN hosts: half the sessions at most, the rest stay for the Mac.
        let many: Vec<_> = (0..MAX_REMOTE_SESSIONS)
            .filter_map(|i| tcp_permit(IpAddr::from([10, 0, (i / 250) as u8, (i % 250) as u8 + 1])))
            .collect();
        assert_eq!(flood.len() + many.len(), MAX_REMOTE_SESSIONS);
        assert!(tcp_permit("10.9.9.9".parse().unwrap()).is_none());
        let mac: Vec<_> = (0..MAX_TCP_SESSIONS - MAX_REMOTE_SESSIONS).map(|_| tcp_permit(local).expect("the Mac's share")).collect();
        assert!(tcp_permit(local).is_none());
        drop((flood, many, mac));
        assert_eq!(TCP_SESSIONS.load(Ordering::Relaxed), 0);
        assert!(REMOTE_SESSIONS.lock().unwrap().is_empty());
    }

    #[test]
    fn the_nat_budget_is_a_burst_then_a_rate() {
        use std::time::{Duration, Instant};
        // How many connections get through at `at`, and the state after.
        let drain = |mut state: Option<(f64, Instant)>, at: Instant| {
            let mut n = 0;
            while let (next, true) = super::take_budget(state, at) {
                state = Some(next);
                n += 1;
            }
            (n, state.unwrap_or_else(|| super::take_budget(state, at).0))
        };
        let t0 = Instant::now();
        let (took, state) = drain(None, t0);
        assert_eq!(took, super::NAT_BURST as usize);
        assert!(!super::take_budget(Some(state), t0).1);
        // A second later, `NAT_RATE` more; never more than the burst.
        let later = |secs| t0 + Duration::from_secs(secs);
        assert_eq!(drain(Some(state), later(1)).0, super::NAT_RATE as usize);
        assert_eq!(super::take_budget(None, later(3600)).0 .0, super::NAT_BURST - 1.0);
        assert_eq!(super::take_budget(Some(state), later(3600)).0 .0, super::NAT_BURST - 1.0);
    }

    #[test]
    fn frames_pass_their_payload_and_stop_at_the_empty_one() {
        let mut stream = Vec::new();
        for part in [&b"HTTP/1.0 200 OK\r\n"[..], b"", b"after the end"] {
            stream.extend_from_slice(&(part.len() as u32).to_be_bytes());
            stream.extend_from_slice(part);
        }
        // Whole, and cut at every byte: frames and lengths split across reads.
        for cut in 0..stream.len() {
            let (mut d, mut out) = (super::Deframer::default(), Vec::new());
            let ended = d.feed(&stream[..cut], &mut out).unwrap() || d.feed(&stream[cut..], &mut out).unwrap();
            assert!(ended, "cut at {cut}");
            assert_eq!(out, b"HTTP/1.0 200 OK\r\n", "cut at {cut}");
        }
        let mut out = Vec::new();
        super::copy_frames(&mut &stream[..], &mut out).unwrap();
        assert_eq!(out, b"HTTP/1.0 200 OK\r\n");
        // A stream that stops without its end frame ends the copy too.
        let mut out = Vec::new();
        super::copy_frames(&mut &stream[..10], &mut out).unwrap();
        assert_eq!(out, b"HTTP/1");
    }

    #[test]
    fn loopback_ports_are_the_ones_on_the_macs_loopback() {
        let bound = [(80, "0.0.0.0", 8080), (80, "::", 8080), (81, "", 8081), (5000, "127.0.0.1", 5999), (5000, "127.0.0.1", 5999), (443, "192.168.1.5", 8443), (53, "::1", 5353)];
        assert_eq!(super::loopback_ports(bound.into_iter()), vec![(80, 8080), (81, 8081), (5000, 5999)]);
    }

    #[test]
    fn nat_ports_are_the_lowest_free_and_released() {
        let a = nat_port().expect("free port");
        let b = nat_port().expect("free port");
        assert!(NAT_PORTS.contains(&a.0) && NAT_PORTS.contains(&b.0));
        assert_ne!(a.0, b.0);
        // Above Linux's ephemeral range, so never a guest connection's own.
        assert!(*NAT_PORTS.start() > 60999);
        let freed = a.0;
        drop(a);
        let c = nat_port().expect("free port");
        assert_eq!(c.0, freed);
    }

    #[test]
    fn host_egress_dialer_rejects_ssrf_and_allows_vpn_and_public_targets() {
        use super::egress_allowed;
        use std::net::Ipv4Addr;
        let extra = [([192, 168, 105, 0], 24)];
        // Loopback, unspecified, link-local (cloud metadata), multicast, broadcast,
        // host.docker.internal, port 0, and the VM NAT bridge subnets are rejected.
        for bad in [
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(127, 0, 0, 53),
            Ipv4Addr::new(127, 255, 255, 254),
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(0, 1, 2, 3),
            Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(169, 254, 0, 1),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(239, 255, 255, 250),
            Ipv4Addr::new(240, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 255),
            Ipv4Addr::new(198, 19, 248, 254),
            Ipv4Addr::new(192, 168, 64, 1),
            Ipv4Addr::new(192, 168, 64, 18),
            Ipv4Addr::new(192, 168, 105, 1),
        ] {
            assert!(!egress_allowed(bad, 443, &extra), "{bad} must be rejected");
        }
        assert!(!egress_allowed(Ipv4Addr::new(10, 0, 5, 10), 0, &extra), "port 0 must be rejected");

        // Split-tunnel VPN RFC1918 targets, Tailscale CGNAT, NetworkExtension
        // Fake-IP (198.18.0.0/15), and public internet targets are allowed.
        for ok in [
            Ipv4Addr::new(10, 0, 5, 10),
            Ipv4Addr::new(172, 16, 4, 20),
            Ipv4Addr::new(192, 168, 1, 50),
            Ipv4Addr::new(100, 64, 1, 2),
            Ipv4Addr::new(198, 18, 2, 3),
            Ipv4Addr::new(35, 190, 46, 17),
            Ipv4Addr::new(1, 1, 1, 1),
        ] {
            assert!(egress_allowed(ok, 443, &extra), "{ok} must be allowed");
        }
    }

    #[test]
    fn host_egress_dialer_rejects_the_learned_vm_subnet() {
        use std::net::Ipv4Addr;
        // macOS picked another NAT bridge subnet than the default one.
        let inside = Ipv4Addr::new(192, 168, 205, 7);
        let gateway = Ipv4Addr::new(192, 168, 205, 1);
        let outside = Ipv4Addr::new(192, 168, 206, 7);
        assert!(super::egress_target_allowed(inside, 443), "not learned yet");
        super::set_vm_subnet(gateway.octets(), super::VM_UPLINK_PREFIX);
        super::set_vm_subnet(gateway.octets(), super::VM_UPLINK_PREFIX);
        assert_eq!(super::current_vm_subnets().iter().filter(|&&s| s == ([192, 168, 205, 0], 24)).count(), 1);
        assert!(!super::egress_target_allowed(inside, 443), "{inside} is in the VM's NAT subnet");
        assert!(!super::egress_target_allowed(gateway, 443), "{gateway} is the Mac's side of the NAT");
        assert!(super::egress_target_allowed(outside, 443), "{outside} is outside it");
    }

    /// Builds a BSD `rt_msghdr` (92 bytes) followed by `RTA_DST`, optional
    /// `RTA_GATEWAY`, and optional truncated `RTA_NETMASK` sockaddrs, matching
    /// macOS `sysctl([CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0])`.
    fn bsd_rtm(ifindex: u16, flags: i32, dst: [u8; 4], mask: Option<&[u8]>) -> Vec<u8> {
        let mut msg = vec![0u8; 92];
        msg[2] = 5; // RTM_VERSION
        msg[3] = 4; // RTM_GET
        msg[4..6].copy_from_slice(&ifindex.to_ne_bytes());
        msg[8..12].copy_from_slice(&flags.to_ne_bytes());
        let mut addrs: i32 = 0x1 | 0x2; // RTA_DST | RTA_GATEWAY
        if mask.is_some() {
            addrs |= 0x4; // RTA_NETMASK
        }
        msg[12..16].copy_from_slice(&addrs.to_ne_bytes());
        // RTA_DST: sockaddr_in (16 bytes)
        let mut sa_dst = [0u8; 16];
        sa_dst[0] = 16;
        sa_dst[1] = libc::AF_INET as u8;
        sa_dst[4..8].copy_from_slice(&dst);
        msg.extend_from_slice(&sa_dst);
        // RTA_GATEWAY: sockaddr_in (16 bytes)
        let mut sa_gw = [0u8; 16];
        sa_gw[0] = 16;
        sa_gw[1] = libc::AF_INET as u8;
        sa_gw[4..8].copy_from_slice(&[192, 168, 1, 1]);
        msg.extend_from_slice(&sa_gw);
        // RTA_NETMASK: BSD radix-tree variable-length sockaddr
        if let Some(m) = mask {
            if m.is_empty() {
                // sa_len = 0 (/0 default route mask) occupies 4 rounded bytes.
                msg.extend_from_slice(&[0, 0, 0, 0]);
            } else {
                let sa_len = (4 + m.len()) as u8;
                let padded = ((sa_len as usize) + 3) & !3;
                let mut sa_mask = vec![0u8; padded];
                sa_mask[0] = sa_len;
                sa_mask[1] = libc::AF_INET as u8;
                sa_mask[4..4 + m.len()].copy_from_slice(m);
                msg.extend_from_slice(&sa_mask);
            }
        }
        let msglen = msg.len() as u16;
        msg[0..2].copy_from_slice(&msglen.to_ne_bytes());
        msg
    }

    #[test]
    fn macos_net_rt_dump_extracts_vpn_tunnel_prefixes_and_skips_ifscope_and_cloned() {
        const RTF_UP: i32 = 0x1;
        const RTF_GATEWAY: i32 = 0x2;
        const RTF_HOST: i32 = 0x4;
        const RTF_LLINFO: i32 = 0x400;
        const RTF_STATIC: i32 = 0x800;
        const RTF_WASCLONED: i32 = 0x20000;
        const RTF_IFSCOPE: i32 = 0x1000000;

        let mut dump = Vec::new();
        // Primary default route on en0 (index 1): 0.0.0.0/0
        dump.extend_from_slice(&bsd_rtm(1, RTF_UP | RTF_GATEWAY | RTF_STATIC, [0, 0, 0, 0], Some(&[])));
        // Interface-scoped default route on utun4 (index 2): must be ignored!
        dump.extend_from_slice(&bsd_rtm(2, RTF_UP | RTF_IFSCOPE, [0, 0, 0, 0], Some(&[])));
        // OpenVPN split-tunnel route 10.0.5.0/24 on utun4 (index 2), truncated 3-byte radix mask
        dump.extend_from_slice(&bsd_rtm(2, RTF_UP | RTF_STATIC, [10, 0, 5, 0], Some(&[255, 255, 255])));
        // Redundant /32 host route inside 10.0.5.0/24 on utun4: collapsed into 10.0.5.0/24
        dump.extend_from_slice(&bsd_rtm(2, RTF_UP | RTF_HOST, [10, 0, 5, 10], None));
        // Corporate /16 route on ipsec0 (index 3), truncated 2-byte radix mask
        dump.extend_from_slice(&bsd_rtm(3, RTF_UP | RTF_STATIC, [172, 20, 0, 0], Some(&[255, 255])));
        // Tailscale CGNAT 100.64.0.0/10 on utun5 (index 4), truncated 2-byte radix mask
        dump.extend_from_slice(&bsd_rtm(4, RTF_UP | RTF_STATIC, [100, 64, 0, 0], Some(&[255, 192])));
        // Multicast 224.0.0.0/4 and loopback on utun4: must be ignored
        dump.extend_from_slice(&bsd_rtm(2, RTF_UP, [224, 0, 0, 0], Some(&[240])));
        dump.extend_from_slice(&bsd_rtm(2, RTF_UP | RTF_HOST, [127, 0, 0, 1], None));
        // Cloned ARP entry on utun4 and regular LAN route on en0: must be ignored
        dump.extend_from_slice(&bsd_rtm(2, RTF_UP | RTF_WASCLONED | RTF_LLINFO, [10, 99, 0, 1], None));
        dump.extend_from_slice(&bsd_rtm(1, RTF_UP, [192, 168, 1, 0], Some(&[255, 255, 255])));

        let ifname = |idx: u16| match idx {
            1 => Some("en0".into()),
            2 => Some("utun4".into()),
            3 => Some("ipsec0".into()),
            4 => Some("utun5".into()),
            _ => None,
        };
        let routes = super::parse_macos_routes(&dump, ifname);
        assert_eq!(
            routes,
            vec![
                ([100, 64, 0, 0], 10),
                ([172, 20, 0, 0], 16),
                ([10, 0, 5, 0], 24),
            ]
        );
    }

    #[test]
    fn system_extensions_plist_detects_active_security_extensions_and_ignores_inactive_or_tailscale() {
        let active_kaspersky_and_forticlient = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>extensions</key>
    <array>
        <dict>
            <key>bundleVersion</key>
            <dict>
                <key>CFBundleShortVersionString</key>
                <string>26.0.0</string>
            </dict>
            <key>categories</key>
            <array>
                <string>com.apple.system_extension.network_extension</string>
            </array>
            <key>identifier</key>
            <string>com.kaspersky.kav.sysext</string>
            <key>state</key>
            <string>activated_enabled</string>
        </dict>
        <dict>
            <key>categories</key>
            <array>
                <string>com.apple.developer.networking.networkextension</string>
            </array>
            <key>identifier</key>
            <string>com.fortinet.forticlient.macos.vpn.nwextension</string>
            <key>state</key>
            <string>terminated_waiting_to_uninstall_on_reboot</string>
        </dict>
    </array>
</dict>
</plist>"#;
        assert!(super::has_active_network_extension(active_kaspersky_and_forticlient));

        let deactivated_or_tailscale = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>extensions</key>
    <array>
        <dict>
            <key>categories</key>
            <array>
                <string>com.apple.developer.networking.networkextension</string>
            </array>
            <key>identifier</key>
            <string>com.fortinet.forticlient.macos.vpn.nwextension</string>
            <key>state</key>
            <string>terminated_waiting_to_uninstall_on_reboot</string>
        </dict>
        <dict>
            <key>categories</key>
            <array>
                <string>com.apple.system_extension.network_extension</string>
            </array>
            <key>identifier</key>
            <string>io.tailscale.ipn.macsys.network-extension</string>
            <key>state</key>
            <string>activated_enabled</string>
        </dict>
        <dict>
            <key>categories</key>
            <array>
                <string>com.apple.system_extension.endpoint_security</string>
            </array>
            <key>identifier</key>
            <string>com.example.edr.esext</string>
            <key>state</key>
            <string>activated_enabled</string>
        </dict>
    </array>
</dict>
</plist>"#;
        assert!(!super::has_active_network_extension(deactivated_or_tailscale));

        assert_eq!(
            super::host_egress_routes_for(Some("auto"), false, &[([10, 0, 5, 0], 24)], true),
            vec!["198.18.0.0/15", "10.0.5.0/24"]
        );
        assert_eq!(
            super::host_egress_routes_for(Some("auto"), true, &[([10, 0, 5, 0], 24)], true),
            vec!["0.0.0.0/0"]
        );
        assert_eq!(
            super::host_egress_routes_for(Some("always"), false, &[], false),
            vec!["0.0.0.0/0"]
        );
        assert!(super::host_egress_routes_for(Some("off"), true, &[([10, 0, 5, 0], 24)], true).is_empty());
        assert_eq!(
            super::host_egress_routes_for(Some("10.254.99.0/24"), false, &[], false),
            vec!["10.254.99.0/24"]
        );
    }
}
