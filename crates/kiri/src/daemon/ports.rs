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

/// One active published port binding reported to `kiri-win` (`/kiri/win-ports`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PublishedPort {
    pub proto: String,
    pub host_ip: String,
    pub host_port: u16,
}

static WINDOWS_HOST_IPS: Mutex<Option<BTreeSet<IpAddr>>> = Mutex::new(None);
static LAST_IPCONFIG_PROBE: Mutex<Option<Instant>> = Mutex::new(None);

/// Parses a bare or bracketed IPv4/IPv6 host address, stripping any `%scope`
/// suffix and canonicalizing IPv4-mapped IPv6 addresses.
pub fn parse_host_ip(s: &str) -> Option<IpAddr> {
    let bare = s.trim().strip_prefix('[').and_then(|i| i.strip_suffix(']')).unwrap_or(s.trim());
    let bare = bare.split('%').next().unwrap_or(bare);
    bare.parse::<IpAddr>().ok().map(|a| a.to_canonical())
}

/// Records the Windows host interface IPs pushed by `kiri-win` and persists
/// them in the daemon state directory when the list changes so container
/// starts after a daemon restart still recognize Windows interface addresses.
pub fn set_windows_host_ips(ips: &[String]) {
    let mut set = BTreeSet::from([
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
    ]);
    for s in ips {
        if let Some(ip) = parse_host_ip(s)
            && !ip.is_unspecified()
            && !ip.is_multicast()
        {
            set.insert(ip);
        }
    }
    {
        let mut guard = WINDOWS_HOST_IPS.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            *guard = load_persisted_windows_host_ips();
        }
        if guard.as_ref() == Some(&set) {
            return;
        }
        *guard = Some(set.clone());
    }
    if let Ok(dir) = super::state_dir() {
        let list: Vec<String> = set.iter().map(ToString::to_string).collect();
        if let Ok(bytes) = serde_json::to_vec(&list) {
            let tmp = dir.join("win-host-ips.json.tmp");
            let path = dir.join("win-host-ips.json");
            if std::fs::write(&tmp, bytes).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
        }
    }
}

fn load_persisted_windows_host_ips() -> Option<BTreeSet<IpAddr>> {
    let path = super::state_dir().ok()?.join("win-host-ips.json");
    let bytes = std::fs::read(path).ok()?;
    let list: Vec<String> = serde_json::from_slice(&bytes).ok()?;
    let mut set = BTreeSet::from([
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
    ]);
    for s in &list {
        if let Some(ip) = parse_host_ip(s)
            && !ip.is_unspecified()
            && !ip.is_multicast()
        {
            set.insert(ip);
        }
    }
    Some(set)
}

/// Extracts Windows host interface IPv4 and IPv6 addresses from `ipconfig.exe`
/// output in a locale-independent way: in every Windows locale, each adapter's
/// IPv4 address line is immediately followed by its `255.x.x.x` subnet mask
/// line, whereas the default gateway comes after the subnet mask.
pub fn parse_ipconfig_addrs(output: &str) -> BTreeSet<IpAddr> {
    let mut set = BTreeSet::from([
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
    ]);
    let mut pending_v4: Option<std::net::Ipv4Addr> = None;
    let mut seen_mask_in_section = false;
    for raw_line in output.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        // Adapter section header (e.g. `Ethernet adapter vEthernet (WSL):`).
        if line.ends_with(':') && !line.contains(". :") && !line.contains(" : ") {
            pending_v4 = None;
            seen_mask_in_section = false;
            continue;
        }
        let val = match line.split_once(": ") {
            Some((_, right)) => right.trim(),
            None => match line.strip_suffix(':') {
                Some(_) => continue,
                None => line,
            },
        };
        let token = val.split(['(', '%', ' ']).next().unwrap_or("").trim();
        if token.is_empty() {
            continue;
        }
        if let Ok(v4) = token.parse::<std::net::Ipv4Addr>() {
            if v4.octets()[0] == 255 {
                seen_mask_in_section = true;
                if let Some(interface_ip) = pending_v4.take()
                    && !interface_ip.is_unspecified()
                    && !interface_ip.is_multicast()
                {
                    set.insert(IpAddr::V4(interface_ip));
                }
            } else {
                pending_v4 = Some(v4);
            }
        } else if !seen_mask_in_section
            && let Some(IpAddr::V6(v6)) = parse_host_ip(token)
            && !v6.is_unspecified()
            && !v6.is_multicast()
        {
            set.insert(IpAddr::V6(v6));
        }
    }
    set
}

fn probe_windows_host_ips_from_wsl() -> Option<BTreeSet<IpAddr>> {
    let wsl = super::binds::wsl()?;
    {
        let mut last = LAST_IPCONFIG_PROBE.lock().unwrap_or_else(|e| e.into_inner());
        if last.is_some_and(|t| t.elapsed() < Duration::from_secs(2)) {
            return None;
        }
        *last = Some(Instant::now());
    }
    let ipconfig = format!("{}c/Windows/System32/ipconfig.exe", wsl.root);
    let out = std::process::Command::new(ipconfig)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let parsed = parse_ipconfig_addrs(&text);
    (parsed.len() > 2).then_some(parsed)
}

/// Whether `ip` is a valid interface address on the Windows host when running
/// inside WSL 2.
pub fn is_windows_host_ip(ip: &str) -> bool {
    let Some(addr) = parse_host_ip(ip) else {
        return false;
    };
    if addr.is_unspecified() || addr.is_multicast() {
        return false;
    }
    {
        let mut guard = WINDOWS_HOST_IPS.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            *guard = load_persisted_windows_host_ips();
        }
        if let Some(set) = guard.as_ref()
            && set.contains(&addr)
        {
            return true;
        }
    }
    if let Some(probed) = probe_windows_host_ips_from_wsl() {
        let mut guard = WINDOWS_HOST_IPS.lock().unwrap_or_else(|e| e.into_inner());
        let set = guard.get_or_insert_with(BTreeSet::new);
        set.extend(probed);
        return set.contains(&addr);
    }
    false
}

/// The WSL 2 distro's primary internal IPv4 address (`eth0` / default route
/// interface), which `kiri-win` on Windows forwards TCP and UDP ports to.
pub fn wsl_ipv4() -> Option<std::net::Ipv4Addr> {
    let default_iface = std::fs::read_to_string("/proc/net/route")
        .ok()
        .and_then(|routes| {
            routes.lines().skip(1).find_map(|l| {
                let mut f = l.split_whitespace();
                let iface = f.next()?;
                let dst = f.next()?;
                (dst == "00000000").then(|| iface.to_owned())
            })
        });
    let addrs: Vec<(String, std::net::Ipv4Addr)> = super::network::host_interface_ipv4()
        .into_iter()
        .filter(|(_, ip)| !ip.is_loopback() && !ip.is_unspecified())
        .collect();
    if let Some(def) = default_iface.as_deref()
        && let Some((_, ip)) = addrs.iter().find(|(n, _)| n == def)
    {
        return Some(*ip);
    }
    if let Some((_, ip)) = addrs.iter().find(|(n, _)| n == "eth0") {
        return Some(*ip);
    }
    addrs
        .into_iter()
        .find(|(n, _)| {
            !n.starts_with("lo")
                && !n.starts_with("kiri")
                && !n.starts_with("veth")
                && !n.starts_with("docker")
                && !n.starts_with("br-")
                && !n.starts_with("cni")
                && !n.starts_with("flannel")
        })
        .map(|(_, ip)| ip)
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
    let in_wsl = super::binds::wsl().is_some();
    // In WSL 2 NAT mode, `wsl_ipv4()` is WSL's dedicated internal `eth0` IP.
    // In mirrored/bridged mode, `wsl_ipv4()` is itself one of the Windows host
    // interface IPs; filter it out so we never bind an extra LAN socket for a
    // loopback-only (`-p 127.0.0.1:port/udp`) binding.
    let wsl_eth0 = if in_wsl {
        wsl_ipv4().filter(|ip| !is_windows_host_ip(&ip.to_string()))
    } else {
        None
    };
    let mut listeners: Vec<(Binding, Option<String>, String, u16, TcpListener)> = Vec::with_capacity(bindings.len());
    let mut udp: Vec<(Binding, Option<String>, String, u16, UdpSocket)> = Vec::new();
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
            let is_udp = b.proto == "udp";
            // Kiri's own container-domain router on this port lets it go
            // (domains::step_aside), and the bind goes again.
            let try_bind = |a: SocketAddr| {
                bind_socket(a, is_udp).or_else(|e| {
                    if e.kind() == io::ErrorKind::AddrInUse && !is_udp && port != 0 && super::domains::step_aside(port) {
                        bind_socket(a, false)
                    } else {
                        Err(e)
                    }
                })
            };
            let (bound, bind_ip) = match try_bind(addr) {
                Ok(s) => (Ok(s), ip.clone()),
                // In WSL 2, a Windows host interface IP (`-p <WinLANIP>:port:cport`)
                // is not assigned inside the Linux VM (`EADDRNOTAVAIL` / os error 99).
                // When the IP belongs to a Windows host interface and WSL has a
                // distinct internal `eth0` IPv4 address, bind WSL's `eth0` address
                // (never 0.0.0.0, which would make wslrelay.exe expose 127.0.0.1:port
                // on Windows) while `kiri-win` binds `<WinLANIP>:port` on Windows and
                // forwards to `<wsl_eth0>:<port>`.
                Err(e)
                    if in_wsl
                        && (e.kind() == io::ErrorKind::AddrNotAvailable || e.raw_os_error() == Some(libc::EADDRNOTAVAIL))
                        && is_windows_host_ip(&ip) =>
                {
                    if let Some(fallback_ip) = wsl_eth0 {
                        let fallback_addr = SocketAddr::new(IpAddr::V4(fallback_ip), port);
                        (try_bind(fallback_addr), fallback_ip.to_string())
                    } else {
                        (Err(e), ip.clone())
                    }
                }
                Err(e) => (Err(e), ip.clone()),
            };
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
            if is_udp {
                let s = UdpSocket::from(sock);
                s.set_nonblocking(true)?;
                port = s.local_addr()?.port();
                udp.push((b.clone(), Some(ip), bind_ip.clone(), port, s));
                // WSL 2's localhostForwarding never forwards UDP, so `kiri-win`
                // forwards Windows UDP ports (including 127.0.0.1:port/udp) to
                // `<wsl_eth0>:<port>/udp`. Ensure `<wsl_eth0>:<port>/udp` is
                // also bound/DNATed inside WSL when the primary bind was loopback
                // or IPv6-only.
                if let Some(eth0) = wsl_eth0 {
                    let eth0_str = eth0.to_string();
                    if bind_ip != "0.0.0.0"
                        && bind_ip != eth0_str
                        && !udp.iter().any(|(_, _, bip, p, _)| *p == port && (bip == "0.0.0.0" || bip == &eth0_str))
                        && let Ok(aux_fd) = bind_socket(SocketAddr::new(IpAddr::V4(eth0), port), true)
                    {
                        let aux = UdpSocket::from(aux_fd);
                        let _ = aux.set_nonblocking(true);
                        udp.push((b.clone(), None, eth0_str, port, aux));
                    }
                }
                continue;
            }
            let l = TcpListener::from(sock);
            l.set_nonblocking(true)?;
            port = l.local_addr()?.port();
            listeners.push((b.clone(), Some(ip.clone()), bind_ip.clone(), port, l));
            if let Some(eth0) = wsl_eth0 {
                let eth0_str = eth0.to_string();
                if ip == "::"
                    && !listeners.iter().any(|(_, _, bip, p, _)| *p == port && (bip == "0.0.0.0" || bip == &eth0_str))
                    && let Ok(aux_fd) = bind_socket(SocketAddr::new(IpAddr::V4(eth0), port), false)
                {
                    let aux = TcpListener::from(aux_fd);
                    let _ = aux.set_nonblocking(true);
                    listeners.push((b.clone(), None, eth0_str, port, aux));
                }
            }
        }
    }
    let mut fw = Forwards { wake: Vec::new(), threads: Vec::new(), kernel: None, nat: None, loopback: None, bound: Vec::new() };
    // On a Linux host the daemon shares the kernel with the containers, so
    // the kernel can rewrite the packets (nftables DNAT) instead of two
    // user-space relays copying every byte; that serves every address but
    // loopback. The listeners below relay the rest.
    if cfg!(target_os = "linux") && target_ip != [127, 0, 0, 1] {
        let all = udp
            .iter()
            .map(|(b, _, bind_ip, port, _)| (b, bind_ip, *port, true))
            .chain(listeners.iter().map(|(b, _, bind_ip, port, _)| (b, bind_ip, *port, false)));
        let mut published = Ok(false);
        for (b, bind_ip, port, is_udp) in all.filter(|(_, bind_ip, ..)| kernel_forwards(bind_ip)) {
            let p = kiri_proto::Publish {
                id,
                udp: is_udp,
                host_ip: kernel_host_ip(bind_ip).expect("checked IPv4 binding"),
                host_port: port,
                to_ip: target_ip,
                to_port: b.container_port,
            };
            published = vm.publish(p).map(|()| true);
            if published.is_err() {
                break;
            }
        }
        match published {
            Ok(any) => {
                // Sockets only the kernel serves stay bound, so the ports read as taken.
                let (kernel_udp, relay_udp): (Vec<_>, Vec<_>) = udp.into_iter().partition(|(_, _, bind_ip, ..)| !relays_too(bind_ip));
                let (kernel_tcp, relay_tcp): (Vec<_>, Vec<_>) = listeners.into_iter().partition(|(_, _, bind_ip, ..)| !relays_too(bind_ip));
                fw.bound.extend(kernel_udp.iter().filter_map(|(b, rep_ip, _, port, _)| rep_ip.as_ref().map(|ip| (b.clone(), ip.clone(), *port))));
                fw.bound.extend(kernel_tcp.iter().filter_map(|(b, rep_ip, _, port, _)| rep_ip.as_ref().map(|ip| (b.clone(), ip.clone(), *port))));
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
    for (b, rep_ip, _bind_ip, port, sock) in udp {
        let (wake_r, wake_w) = pipe()?;
        fw.wake.push(wake_w);
        let vm = vm.clone();
        let container_port = b.container_port;
        fw.threads.push(std::thread::Builder::new().name(format!("kiri-udp-{port}")).spawn(move || {
            udp_loop(&sock, &wake_r, &vm, target_ip, container_port);
        })?);
        if let Some(ip) = rep_ip {
            fw.bound.push((b, ip, port));
        }
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
        let ports = loopback_ports(listeners.iter().filter_map(|(b, rep_ip, _, port, _)| rep_ip.as_deref().map(|ip| (b.container_port, ip, *port))));
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
    for ((b, rep_ip, _bind_ip, port, listener), nat) in listeners.into_iter().zip(nat) {
        let (wake_r, wake_w) = pipe()?;
        fw.wake.push(wake_w);
        let vm = vm.clone();
        let container_port = b.container_port;
        fw.threads.push(std::thread::Builder::new().name(format!("kiri-port-{port}")).spawn(move || {
            accept_loop(&listener, &wake_r, &vm, target_ip, container_port, nat);
        })?);
        if let Some(ip) = rep_ip {
            fw.bound.push((b, ip, port));
        }
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
/// `ip[4] port[2]` (always 127.0.0.1 today), and we connect to the Mac's
/// loopback at that port.
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
    let target = dial_loopback(port)?;
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

/// The Mac's loopback at `port`: IPv4, then IPv6 for a server on `::1` only (#258).
fn dial_loopback(port: u16) -> io::Result<TcpStream> {
    TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).or_else(|e| TcpStream::connect((std::net::Ipv6Addr::LOCALHOST, port)).map_err(|_| e))
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

/// Host SSH agent socket last bind-mounted explicitly by a host-side create
/// (or restored at start from a strict user agent mount) on macOS. Validated
/// before storing (canonicalized, owned Unix socket, allowed SSH agent path,
/// never Kiri's own socket) and re-checked on every connection.
static PREFERRED_SSH_AUTH_SOCK: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

/// Normalizes an absolute path lexically (`//`, `/./`, `/../`) without
/// touching the filesystem.
fn lexical_clean_path(p: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    format!("/{}", out.join("/"))
}

/// Whether `path` is Apple launchd's default per-session SSH agent socket:
/// `/private/tmp/com.apple.launchd.<id>/Listeners`,
/// `/tmp/com.apple.launchd.<id>/Listeners`,
/// `/private/var/run/com.apple.launchd.<id>/Listeners`, or
/// `/var/run/com.apple.launchd.<id>/Listeners`.
pub(crate) fn is_launchd_ssh_sock(path: &std::path::Path) -> bool {
    let Some(s) = path.to_str() else { return false };
    if !s.starts_with('/') {
        return false;
    }
    let clean = lexical_clean_path(s);
    const PREFIXES: &[&str] = &["/private/tmp/", "/tmp/", "/private/var/run/", "/var/run/"];
    let Some(rest) = PREFIXES.iter().find_map(|p| clean.strip_prefix(p)) else {
        return false;
    };
    let Some(dir) = rest.strip_suffix("/Listeners") else {
        return false;
    };
    dir.starts_with("com.apple.launchd.")
        && !dir.contains('/')
        && dir.len() > "com.apple.launchd.".len()
}

/// Whether `path` exists as a Unix domain socket owned by this process's
/// effective UID (follows symlinks, matching `UnixStream::connect`).
pub(crate) fn is_owned_unix_socket(path: &std::path::Path) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    // SAFETY: geteuid only reads this process's effective user ID.
    meta.file_type().is_socket() && meta.uid() == unsafe { libc::geteuid() }
}

fn is_kiri_run_dir(dir: &std::path::Path) -> bool {
    match dir.file_name().and_then(|n| n.to_str()) {
        Some("kiri") => true,
        Some("run") => dir
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(".kiri") || n == "kiri"),
        _ => false,
    }
}

/// Whether `path` is Kiri's own daemon socket or sits inside Kiri's runtime
/// socket directory (`~/.kiri*/run/` or `/run/kiri/`). Never allowed as an SSH
/// agent upstream.
pub(crate) fn is_kiri_socket_path(path: &std::path::Path) -> bool {
    let Some(s) = path.to_str() else { return false };
    if super::binds::engine_socket(s).is_some() {
        return true;
    }
    let clean = std::path::PathBuf::from(lexical_clean_path(s));
    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| clean.clone());
    for own in [super::socket_path().ok(), super::home_socket_path().ok()].into_iter().flatten() {
        let own_clean = std::path::PathBuf::from(lexical_clean_path(&own.to_string_lossy()));
        let own_canon = std::fs::canonicalize(&own).unwrap_or_else(|_| own_clean.clone());
        if canon == own_canon || clean == own_clean {
            return true;
        }
        if let Some(dir) = own_canon.parent()
            && is_kiri_run_dir(dir)
            && canon.starts_with(dir)
        {
            return true;
        }
        if let Some(dir) = own_clean.parent()
            && is_kiri_run_dir(dir)
            && clean.starts_with(dir)
        {
            return true;
        }
    }
    false
}

/// Whether `path` (already canonicalized when on disk, or lexically cleaned
/// otherwise) names a well-known macOS SSH agent socket:
/// - Apple launchd's `com.apple.launchd.*/Listeners`
/// - GnuPG's `S.gpg-agent.ssh` under a Mac user or temp share
/// - 1Password's `~/.1password/agent.sock` or
///   `~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock`
pub(crate) fn is_known_mac_ssh_agent_sock_path(path: &std::path::Path) -> bool {
    if is_launchd_ssh_sock(path) {
        return true;
    }
    let Some(s) = path.to_str() else { return false };
    if !s.starts_with('/') {
        return false;
    }
    let clean = lexical_clean_path(s);
    if clean.ends_with("/S.gpg-agent.ssh") {
        const SHARES: &[&str] = &[
            "/Users/",
            "/Volumes/",
            "/private/tmp/",
            "/tmp/",
            "/private/var/folders/",
            "/var/folders/",
        ];
        if SHARES.iter().any(|p| clean.starts_with(p)) {
            return true;
        }
        for var in ["HOME", "GNUPGHOME"] {
            if let Some(dir) = std::env::var_os(var).filter(|v| !v.is_empty()) {
                let base = lexical_clean_path(&dir.to_string_lossy());
                if clean.strip_prefix(&base).is_some_and(|r| r.starts_with('/')) {
                    return true;
                }
            }
        }
        return false;
    }
    const ONE_PASSWORD_SUFFIXES: &[&str] = &[
        "/.1password/agent.sock",
        "/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock",
    ];
    for suffix in ONE_PASSWORD_SUFFIXES {
        if let Some(prefix) = clean.strip_suffix(suffix) {
            if prefix.starts_with("/Users/") || prefix.starts_with("/Volumes/") {
                return true;
            }
            if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty())
                && prefix == lexical_clean_path(&home.to_string_lossy())
            {
                return true;
            }
        }
    }
    false
}

/// Strict allowlist used when restoring a preferred SSH agent socket on
/// container start (without caller context): only permits launchd's
/// `Listeners`, 1Password's `agent.sock` directly under the user's `$HOME`,
/// or GnuPG's `S.gpg-agent.ssh` inside `~/.gnupg`, `$GNUPGHOME`, or
/// `gpgconf --list-dirs agent-ssh-socket`.
fn is_strict_mac_ssh_agent_sock_path_for(
    path: &std::path::Path,
    home: Option<&std::path::Path>,
    gnupg_home: Option<&std::path::Path>,
    gpgconf_sock: Option<&std::path::Path>,
) -> bool {
    if is_launchd_ssh_sock(path) {
        return true;
    }
    let Some(s) = path.to_str() else { return false };
    if !s.starts_with('/') {
        return false;
    }
    let clean = lexical_clean_path(s);
    let same = |candidate: std::path::PathBuf| -> bool {
        let cand_clean = lexical_clean_path(&candidate.to_string_lossy());
        if clean == cand_clean {
            return true;
        }
        std::fs::canonicalize(&candidate)
            .ok()
            .and_then(|c| c.to_str().map(lexical_clean_path))
            .is_some_and(|c| c == clean)
    };
    if let Some(h) = home {
        for rel in [
            ".gnupg/S.gpg-agent.ssh",
            ".1password/agent.sock",
            "Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock",
        ] {
            if same(h.join(rel)) {
                return true;
            }
        }
    }
    if let Some(g) = gnupg_home
        && same(g.join("S.gpg-agent.ssh"))
    {
        return true;
    }
    if let Some(sock) = gpgconf_sock
        && same(sock.to_path_buf())
    {
        return true;
    }
    false
}

/// Whether a `gpg-agent.conf` file enables SSH agent support via an
/// uncommented `enable-ssh-support` directive.
fn gpg_agent_ssh_enabled(conf: &str) -> bool {
    let mut enabled = false;
    for line in conf.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        match line.split_whitespace().next() {
            Some("enable-ssh-support") => enabled = true,
            Some("no-enable-ssh-support") => enabled = false,
            _ => {}
        }
    }
    enabled
}

fn launchctl_getenv(var: &str) -> Option<std::path::PathBuf> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let out = std::process::Command::new("/bin/launchctl")
        .args(["getenv", var])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let p = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (!p.is_empty()).then(|| p.into())
}

fn gpgconf_candidates() -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            if !dir.as_os_str().is_empty() {
                out.push(dir.join("gpgconf"));
            }
        }
    }
    for fallback in [
        "/opt/homebrew/bin/gpgconf",
        "/usr/local/bin/gpgconf",
        "/usr/local/MacGPG2/bin/gpgconf",
    ] {
        let p = std::path::PathBuf::from(fallback);
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

fn is_executable_file(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && (m.permissions().mode() & 0o111 != 0))
}

fn gpgconf_agent_ssh_socket(gnupg_home: Option<&std::path::Path>) -> Option<std::path::PathBuf> {
    let bin = gpgconf_candidates().into_iter().find(|p| is_executable_file(p))?;
    let mut cmd = std::process::Command::new(bin);
    cmd.args(["--list-dirs", "agent-ssh-socket"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Some(dir) = gnupg_home {
        cmd.env("GNUPGHOME", dir);
    }
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (!s.is_empty()).then(|| std::path::PathBuf::from(s))
}

/// Checks whether GPG SSH support is enabled in `$GNUPGHOME/gpg-agent.conf`
/// (when `GNUPGHOME` is set) or `~/.gnupg/gpg-agent.conf`, and if so returns
/// candidate GPG SSH agent socket paths in preference order.
fn gather_gpg_ssh_info(
    gnupg_home: Option<&std::path::Path>,
    home: Option<&std::path::Path>,
    gpgconf_sock: impl FnOnce(Option<&std::path::Path>) -> Option<std::path::PathBuf>,
) -> (bool, Vec<std::path::PathBuf>) {
    let conf_dir = gnupg_home.map(std::path::Path::to_path_buf).or_else(|| home.map(|h| h.join(".gnupg")));
    let enabled = conf_dir
        .as_deref()
        .and_then(|d| std::fs::read_to_string(d.join("gpg-agent.conf")).ok())
        .is_some_and(|text| gpg_agent_ssh_enabled(&text));
    if !enabled {
        return (false, Vec::new());
    }
    let mut socks = Vec::new();
    let mut push_unique = |p: std::path::PathBuf| {
        if !p.as_os_str().is_empty() && !socks.contains(&p) {
            socks.push(p);
        }
    };
    if let Some(g) = gnupg_home {
        push_unique(g.join("S.gpg-agent.ssh"));
    }
    if let Some(s) = gpgconf_sock(gnupg_home) {
        push_unique(s);
    }
    if let Some(h) = home {
        push_unique(h.join(".gnupg/S.gpg-agent.ssh"));
    }
    (true, socks)
}

/// Inputs to [`resolve_ssh_auth_sock_candidates`], factored out so the macOS
/// resolution order can be unit-tested without touching process environment or
/// spawning `launchctl`/`gpgconf`.
#[derive(Default)]
struct SshAuthInputs {
    preferred: Option<std::path::PathBuf>,
    env_sock: Option<std::path::PathBuf>,
    launchctl_sock: Option<std::path::PathBuf>,
    gpg_ssh_enabled: bool,
    gpg_sockets: Vec<std::path::PathBuf>,
}

/// Orders live host SSH agent socket candidates on macOS:
/// 1. Explicit host SSH agent socket recorded from a Mac bind mount.
/// 2. Explicit non-launchd `$SSH_AUTH_SOCK` in this process's environment.
/// 3. Explicit non-launchd `launchctl getenv SSH_AUTH_SOCK`.
/// 4. GnuPG's `S.gpg-agent.ssh` when `gpg-agent.conf` has `enable-ssh-support`.
/// 5. Fallback to launchd's default `com.apple.launchd.*/Listeners` socket.
fn resolve_ssh_auth_sock_candidates(
    inputs: &SshAuthInputs,
    is_live: impl Fn(&std::path::Path) -> bool,
) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut push_unique = |p: &std::path::Path| {
        if !p.as_os_str().is_empty() && !out.iter().any(|existing: &std::path::PathBuf| existing == p) {
            out.push(p.to_path_buf());
        }
    };
    // 1) Explicit host SSH agent socket recorded from a Mac bind mount.
    if let Some(p) = inputs.preferred.as_deref()
        && is_live(p)
    {
        push_unique(p);
    }
    // 2) Explicit non-launchd $SSH_AUTH_SOCK from daemon environment.
    if let Some(p) = inputs.env_sock.as_deref()
        && !is_launchd_ssh_sock(p)
        && is_live(p)
    {
        push_unique(p);
    }
    // 3) Explicit non-launchd `launchctl getenv SSH_AUTH_SOCK`.
    if let Some(p) = inputs.launchctl_sock.as_deref()
        && !is_launchd_ssh_sock(p)
        && is_live(p)
    {
        push_unique(p);
    }
    // 4) GPG SSH agent socket when `enable-ssh-support` is configured.
    if inputs.gpg_ssh_enabled {
        for p in &inputs.gpg_sockets {
            if is_live(p) {
                push_unique(p);
            }
        }
    }
    // 5) Fallback to launchd's Listeners socket from env or launchctl.
    for p in [inputs.env_sock.as_deref(), inputs.launchctl_sock.as_deref()].into_iter().flatten() {
        if is_live(p) {
            push_unique(p);
        }
    }
    out
}

#[cfg(test)]
fn resolve_ssh_auth_sock(
    inputs: &SshAuthInputs,
    is_live: impl Fn(&std::path::Path) -> bool,
) -> Option<std::path::PathBuf> {
    resolve_ssh_auth_sock_candidates(inputs, is_live).into_iter().next()
}

fn gather_ssh_auth_inputs(include_preferred: bool) -> SshAuthInputs {
    let preferred = if include_preferred {
        PREFERRED_SSH_AUTH_SOCK.lock().unwrap_or_else(|e| e.into_inner()).clone()
    } else {
        None
    };
    let env_sock = std::env::var_os("SSH_AUTH_SOCK")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from);
    if !cfg!(target_os = "macos") {
        return SshAuthInputs {
            preferred: None,
            env_sock,
            launchctl_sock: None,
            gpg_ssh_enabled: false,
            gpg_sockets: Vec::new(),
        };
    }
    let launchctl_sock = launchctl_getenv("SSH_AUTH_SOCK");
    let home = std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from);
    let gnupg_home = std::env::var_os("GNUPGHOME")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(|| launchctl_getenv("GNUPGHOME"));
    let (gpg_ssh_enabled, gpg_sockets) = gather_gpg_ssh_info(
        gnupg_home.as_deref(),
        home.as_deref(),
        gpgconf_agent_ssh_socket,
    );
    SshAuthInputs {
        preferred,
        env_sock,
        launchctl_sock,
        gpg_ssh_enabled,
        gpg_sockets,
    }
}

fn ssh_auth_sock_candidates_for(include_preferred: bool) -> Vec<std::path::PathBuf> {
    let inputs = gather_ssh_auth_inputs(include_preferred);
    if cfg!(target_os = "macos") {
        resolve_ssh_auth_sock_candidates(&inputs, is_owned_unix_socket)
    } else {
        // On Linux the daemon may run as root while $SSH_AUTH_SOCK belongs
        // to a non-root user, so keep the existing env behavior.
        inputs.env_sock.into_iter().collect()
    }
}

/// The host's discovered SSH agent socket, ignoring any previously recorded
/// bind-mount preference (so bind-mount validation cannot bootstrap itself).
pub(crate) fn default_ssh_auth_sock() -> Option<std::path::PathBuf> {
    ssh_auth_sock_candidates_for(false).into_iter().next()
}

/// Whether `canon` (already canonicalized) matches the daemon's discovered
/// host SSH agent socket (`default_ssh_auth_sock()`).
pub(crate) fn matches_default_ssh_auth_sock(canon: &std::path::Path) -> bool {
    let Some(default) = default_ssh_auth_sock() else { return false };
    let default_canon = std::fs::canonicalize(&default).unwrap_or(default);
    canon == default_canon
}

fn set_preferred_ssh_auth_sock_inner(path: &std::path::Path, strict: bool) -> bool {
    let Ok(canon) = std::fs::canonicalize(path) else {
        return false;
    };
    if !is_owned_unix_socket(&canon) || is_kiri_socket_path(&canon) {
        return false;
    }
    let allowed = if strict {
        let home = std::env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .map(std::path::PathBuf::from);
        let gnupg_home = std::env::var_os("GNUPGHOME")
            .filter(|v| !v.is_empty())
            .map(std::path::PathBuf::from)
            .or_else(|| launchctl_getenv("GNUPGHOME"));
        let gpgconf_sock = canon
            .file_name()
            .is_some_and(|n| n == "S.gpg-agent.ssh")
            .then(|| gpgconf_agent_ssh_socket(gnupg_home.as_deref()))
            .flatten();
        is_strict_mac_ssh_agent_sock_path_for(&canon, home.as_deref(), gnupg_home.as_deref(), gpgconf_sock.as_deref())
            || matches_default_ssh_auth_sock(&canon)
    } else {
        is_known_mac_ssh_agent_sock_path(&canon) || matches_default_ssh_auth_sock(&canon)
    };
    if !allowed {
        return false;
    }
    *PREFERRED_SSH_AUTH_SOCK.lock().unwrap_or_else(|e| e.into_inner()) = Some(canon);
    true
}

/// Records an explicitly bind-mounted Mac SSH agent socket (from a host
/// caller) as the preferred upstream for `serve_ssh_agent`, after verifying
/// canonical path, Unix socket type, current-UID ownership, allowlist, and
/// that it is never Kiri's own daemon socket.
pub(crate) fn set_preferred_ssh_auth_sock(path: &std::path::Path) -> bool {
    set_preferred_ssh_auth_sock_inner(path, false)
}

/// Strict variant used on container start (when caller identity is no longer
/// present): only records sockets under the user's own GPG/1Password/launchd
/// locations or matching `default_ssh_auth_sock()`.
pub(crate) fn set_preferred_ssh_auth_sock_strict(path: &std::path::Path) -> bool {
    set_preferred_ssh_auth_sock_inner(path, true)
}

#[cfg(test)]
pub(crate) static PREFERRED_SSH_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
pub(crate) fn current_preferred_ssh_auth_sock() -> Option<std::path::PathBuf> {
    PREFERRED_SSH_AUTH_SOCK.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

#[cfg(test)]
pub(crate) fn clear_preferred_ssh_auth_sock() {
    *PREFERRED_SSH_AUTH_SOCK.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// One container connection to the SSH agent, relayed to the Mac's agent.
pub fn serve_ssh_agent(stream: kiri_vmm::VsockStream) {
    let _ = std::thread::Builder::new().name("kiri-ssh-agent".into()).spawn(move || {
        let Some(agent) = ssh_auth_sock_candidates_for(true)
            .into_iter()
            .find_map(|path| std::os::unix::net::UnixStream::connect(path).ok())
        else {
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
    let Some(permit) = super::try_acquire_container_conn() else {
        drop(stream);
        return;
    };
    let _ = std::thread::Builder::new().name("kiri-engine-api".into()).spawn(move || {
        let _permit = permit;
        // Served here rather than through the daemon's socket, so the API
        // knows these requests are a container's (caller.rs).
        let Some(engine) = engine.upgrade() else { return };
        let _ = relay_engine_api(&stream.fd, move |ours| {
            let _ = super::api::serve(ours, engine, super::caller::Caller::Container);
        });
        drop(stream);
    });
}

/// Relays one guest engine-API stream to `serve` over a local `UnixStream`
/// pair. Once `serve` exits (after `HEADER_TIMEOUT`, `Connection: close`, 400,
/// 403, 413, or EOF) and any buffered response has been written to `guest`,
/// both directions of `guest` are shut down (`SHUT_RDWR`) so a half-open guest
/// connection can never leave `from_guest` blocked or pin a container permit.
fn relay_engine_api(
    guest: &OwnedFd,
    serve: impl FnOnce(std::os::unix::net::UnixStream) + Send + 'static,
) -> io::Result<()> {
    struct ShutdownWriteOnDrop(std::os::unix::net::UnixStream);
    impl Drop for ShutdownWriteOnDrop {
        fn drop(&mut self) {
            let _ = self.0.shutdown(Shutdown::Write);
        }
    }

    let _ = vsock_stall(guest.as_raw_fd());
    let (api, ours) = std::os::unix::net::UnixStream::pair()?;
    let ours_end = ShutdownWriteOnDrop(ours.try_clone()?);
    let (mut api_read, from_guest, to_guest) = (api.try_clone()?, guest.try_clone()?, guest.try_clone()?);
    let mut from_guest = std::fs::File::from(from_guest);
    let mut to_guest = std::fs::File::from(to_guest);
    let mut api_write = api;
    let served = std::thread::Builder::new().name("kiri-api".into()).spawn(move || {
        let _end = ours_end;
        serve(ours);
    })?;
    let (served_tx, served_rx) = std::sync::mpsc::sync_channel::<JoinHandle<()>>(1);
    let down = match std::thread::Builder::new().name("kiri-engine-api-down".into()).spawn(move || {
        let copied = copy(&mut api_read, &mut to_guest);
        if copied.is_err() {
            // Guest stopped reading or disconnected: wake `kiri-api` and `from_guest`.
            let _ = api_read.shutdown(Shutdown::Both);
            // SAFETY: shutting down both directions on a socket we own.
            unsafe { libc::shutdown(to_guest.as_raw_fd(), libc::SHUT_RDWR) };
            if let Ok(served) = served_rx.recv() {
                let _ = served.join();
            }
            return;
        }
        // `serve` shut down its write half (clean exit or `http::close`
        // linger): signal write-EOF to the guest now, wait for `serve` to
        // finish, then shut down both directions so a half-open guest cannot
        // pin `from_guest` (and the container connection permit) forever.
        // SAFETY: shutting down a socket we own.
        unsafe { libc::shutdown(to_guest.as_raw_fd(), libc::SHUT_WR) };
        if let Ok(served) = served_rx.recv() {
            let _ = served.join();
        }
        // SAFETY: shutting down both directions wakes `from_guest`.
        unsafe { libc::shutdown(to_guest.as_raw_fd(), libc::SHUT_RDWR) };
    }) {
        Ok(t) => t,
        Err(e) => {
            // SAFETY: tear down both ends if the downlink thread could not spawn.
            unsafe { libc::shutdown(guest.as_raw_fd(), libc::SHUT_RDWR) };
            let _ = api_write.shutdown(Shutdown::Both);
            let _ = served.join();
            return Err(e);
        }
    };
    let _ = served_tx.send(served);
    let _ = copy(&mut from_guest, &mut api_write);
    let _ = api_write.shutdown(Shutdown::Write);
    let _ = down.join();
    Ok(())
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
    use super::{MAX_PEER_SESSIONS, MAX_REMOTE_SESSIONS, MAX_TCP_SESSIONS, NAT_PORTS, REMOTE_SESSIONS, TCP_SESSIONS, dial_loopback, host_bound_allowed, kernel_forwards, kernel_host_ip, listening, nat_port, relays_too, tcp_permit};
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

    /// A Mac server on `::1` only (Node's `localhost`) is reached; one on
    /// both loopbacks is reached on 127.0.0.1, as before (#258).
    #[test]
    fn host_docker_internal_reaches_a_server_on_either_loopback() {
        let v6 = std::net::TcpListener::bind("[::1]:0").unwrap();
        let port = v6.local_addr().unwrap().port();
        assert_eq!(dial_loopback(port).unwrap().peer_addr().unwrap().ip(), IpAddr::from(std::net::Ipv6Addr::LOCALHOST));
        let v4 = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
        assert_eq!(dial_loopback(port).unwrap().peer_addr().unwrap().ip(), IpAddr::from(std::net::Ipv4Addr::LOCALHOST));
        drop((v4, v6));
        assert_eq!(dial_loopback(port).unwrap_err().kind(), std::io::ErrorKind::ConnectionRefused);
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

    #[test]
    fn ipconfig_parser_extracts_windows_interface_ips_and_excludes_gateways_and_masks() {
        let sample = "\
Windows IP Configuration\r\n\
\r\n\
Ethernet adapter vEthernet (WSL):\r\n\
\r\n\
   Connection-specific DNS Suffix  . : \r\n\
   Link-local IPv6 Address . . . . . : fe80::1234:5678:9abc:def0%42\r\n\
   IPv4 Address. . . . . . . . . . . : 198.51.100.1\r\n\
   Subnet Mask . . . . . . . . . . . : 255.255.240.0\r\n\
   Default Gateway . . . . . . . . . : \r\n\
\r\n\
Wireless LAN adapter Wi-Fi:\r\n\
\r\n\
   Connection-specific DNS Suffix  . : lan\r\n\
   IPv6 Address. . . . . . . . . . . : 2001:db8::42(Preferred)\r\n\
   Link-local IPv6 Address . . . . . : fe80::abcd:ef01:2345:6789%18\r\n\
   IPv4 Address. . . . . . . . . . . : 192.0.2.50(Preferred)\r\n\
   Subnet Mask . . . . . . . . . . . : 255.255.255.0\r\n\
   Default Gateway . . . . . . . . . : fe80::1%18\r\n\
                                       192.0.2.1\r\n";
        let ips = super::parse_ipconfig_addrs(sample);
        assert!(ips.contains(&"127.0.0.1".parse().unwrap()));
        assert!(ips.contains(&"::1".parse().unwrap()));
        assert!(ips.contains(&"198.51.100.1".parse().unwrap()));
        assert!(ips.contains(&"192.0.2.50".parse().unwrap()));
        assert!(ips.contains(&"2001:db8::42".parse().unwrap()));
        // Subnet masks, default gateways, and arbitrary bogus IPs must not match.
        assert!(!ips.contains(&"255.255.255.0".parse().unwrap()));
        assert!(!ips.contains(&"255.255.240.0".parse().unwrap()));
        assert!(!ips.contains(&"192.0.2.1".parse().unwrap()));
        assert!(!ips.contains(&"fe80::1".parse().unwrap()));
        assert!(!ips.contains(&"203.0.113.99".parse().unwrap()));
    }

    #[test]
    fn engine_api_relay_tears_down_half_open_guest_and_releases_permit() {
        use std::io::{BufReader, Read, Write};
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;
        use std::time::{Duration, Instant};

        let cap = super::super::ConnCap::for_test(1);

        // 1. Idle guest that never sends and never closes: when `api::serve`
        //    exits after HEADER_TIMEOUT, both directions shut down promptly and
        //    the container permit is released.
        {
            let permit = cap.try_acquire_for_test().unwrap();
            let (mut guest_client, guest_server) = UnixStream::pair().unwrap();
            guest_client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let guest_fd = OwnedFd::from(guest_server);
            let t0 = Instant::now();
            let t = std::thread::spawn(move || {
                let _permit = permit;
                super::relay_engine_api(&guest_fd, |ours| {
                    let mut r = BufReader::new(ours);
                    let _ = super::super::http::read_request_with_timeout(&mut r, Duration::from_millis(60), |_, _| false);
                })
                .unwrap();
            });
            // Keep `guest_client` open (half-open) until the relay finishes.
            let mut reply = Vec::new();
            guest_client.read_to_end(&mut reply).unwrap();
            t.join().unwrap();
            assert!(reply.is_empty());
            assert!(t0.elapsed() < Duration::from_secs(2), "idle relay hung for {:?}", t0.elapsed());
            assert_eq!(cap.open(), 0, "container permit must be released after timeout");
            drop(guest_client);
        }

        // 2. Guest sends a request that ends the connection (403 / Next::Close)
        //    and keeps its write side open: guest still receives the full 403
        //    response, and the relay exits promptly without pinning the permit.
        {
            let permit = cap.try_acquire_for_test().unwrap();
            let (mut guest_client, guest_server) = UnixStream::pair().unwrap();
            guest_client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let guest_fd = OwnedFd::from(guest_server);
            let t0 = Instant::now();
            let t = std::thread::spawn(move || {
                let _permit = permit;
                super::relay_engine_api(&guest_fd, |ours| {
                    let mut w = ours.try_clone().unwrap();
                    let mut r = BufReader::new(ours);
                    let req = super::super::http::read_request_with_timeout(&mut r, Duration::from_secs(2), |_, _| false)
                        .unwrap()
                        .unwrap();
                    super::super::http::serving(&req);
                    super::super::http::error(&mut w, 403, "forbidden").unwrap();
                })
                .unwrap();
            });
            guest_client.write_all(b"POST /kiri/stop HTTP/1.1\r\nHost: d\r\n\r\n").unwrap();
            // Intentionally do NOT shut down guest_client's write half.
            let mut reply = Vec::new();
            guest_client.read_to_end(&mut reply).unwrap();
            t.join().unwrap();
            let text = String::from_utf8_lossy(&reply);
            assert!(text.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{text}");
            assert!(text.contains("forbidden"), "{text}");
            assert!(t0.elapsed() < Duration::from_secs(2), "403 relay hung for {:?}", t0.elapsed());
            assert_eq!(cap.open(), 0, "container permit must be released after 403");
            drop(guest_client);
        }

        // 3. Guest sends a 413 Too Large request with `http::close` linger while
        //    keeping its write side open: guest receives the full 413 response
        //    and the relay finishes after linger instead of hanging forever.
        {
            let permit = cap.try_acquire_for_test().unwrap();
            let (mut guest_client, guest_server) = UnixStream::pair().unwrap();
            guest_client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let guest_fd = OwnedFd::from(guest_server);
            let t0 = Instant::now();
            let t = std::thread::spawn(move || {
                let _permit = permit;
                super::relay_engine_api(&guest_fd, |ours| {
                    let mut w = ours.try_clone().unwrap();
                    let mut r = BufReader::new(ours);
                    let req = super::super::http::read_request_with_timeout(&mut r, Duration::from_secs(2), |_, _| false)
                        .unwrap()
                        .unwrap();
                    assert!(req.too_large());
                    let _ = super::super::http::refuse_too_large(&req, &mut w, &mut r);
                })
                .unwrap();
            });
            guest_client
                .write_all(b"POST /containers/create HTTP/1.1\r\nHost: d\r\nContent-Length: 100000000\r\n\r\n")
                .unwrap();
            // Intentionally do NOT close guest_client's write half.
            let mut reply = Vec::new();
            guest_client.read_to_end(&mut reply).unwrap();
            t.join().unwrap();
            let text = String::from_utf8_lossy(&reply);
            assert!(text.starts_with("HTTP/1.1 413 Request Entity Too Large\r\n"), "{text}");
            assert!(t0.elapsed() < Duration::from_secs(3), "413 relay hung for {:?}", t0.elapsed());
            assert_eq!(cap.open(), 0, "container permit must be released after 413");
            drop(guest_client);
        }

        // 4. Normal guest half-close (`SHUT_WR` after sending request) still
        //    receives the full HTTP response cleanly.
        {
            let permit = cap.try_acquire_for_test().unwrap();
            let (mut guest_client, guest_server) = UnixStream::pair().unwrap();
            guest_client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let guest_fd = OwnedFd::from(guest_server);
            let t = std::thread::spawn(move || {
                let _permit = permit;
                super::relay_engine_api(&guest_fd, |ours| {
                    let mut w = ours.try_clone().unwrap();
                    let mut r = BufReader::new(ours);
                    let req = super::super::http::read_request_with_timeout(&mut r, Duration::from_secs(2), |_, _| false)
                        .unwrap()
                        .unwrap();
                    super::super::http::serving(&req);
                    super::super::http::respond(&mut w, 200, "text/plain", b"OK").unwrap();
                    assert!(super::super::http::read_request_with_timeout(&mut r, Duration::from_secs(2), |_, _| false).unwrap().is_none());
                })
                .unwrap();
            });
            guest_client.write_all(b"GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n").unwrap();
            guest_client.shutdown(std::net::Shutdown::Write).unwrap();
            let mut reply = Vec::new();
            guest_client.read_to_end(&mut reply).unwrap();
            t.join().unwrap();
            let text = String::from_utf8_lossy(&reply);
            assert!(text.starts_with("HTTP/1.1 200 OK\r\n") && text.ends_with("\r\n\r\nOK"), "{text}");
            assert_eq!(cap.open(), 0);
        }
    }

    #[test]
    fn ssh_auth_sock_resolution_prefers_gpg_over_launchd_and_honors_explicit_overrides() {
        use std::path::{Path, PathBuf};
        let p = PathBuf::from;
        let launchd_tmp = p("/private/tmp/com.apple.launchd.abc123/Listeners");
        let launchd_var = p("/var/run/com.apple.launchd.xyz789/Listeners");
        let gpg = p("/Users/alice/.gnupg/S.gpg-agent.ssh");
        let onepass = p("/Users/alice/.1password/agent.sock");
        let custom = p("/Users/alice/.ssh/custom-agent.sock");
        let all_live = |_: &Path| true;

        // 1) GPG with enable-ssh-support wins over launchd Listeners (both /private/tmp and /var/run forms).
        for launchd in [&launchd_tmp, &launchd_var] {
            let inputs = super::SshAuthInputs {
                preferred: None,
                env_sock: Some(launchd.clone()),
                launchctl_sock: Some(launchd.clone()),
                gpg_ssh_enabled: true,
                gpg_sockets: vec![gpg.clone()],
            };
            assert_eq!(super::resolve_ssh_auth_sock(&inputs, all_live), Some(gpg.clone()), "{launchd:?}");
            // Launchd remains as fallback candidate behind GPG if GPG's socket is stale.
            assert_eq!(super::resolve_ssh_auth_sock_candidates(&inputs, all_live), vec![gpg.clone(), launchd.clone()]);
        }

        // 2) Without enable-ssh-support, launchd stays selected even if S.gpg-agent.ssh exists.
        let disabled_gpg = super::SshAuthInputs {
            preferred: None,
            env_sock: Some(launchd_tmp.clone()),
            launchctl_sock: Some(launchd_tmp.clone()),
            gpg_ssh_enabled: false,
            gpg_sockets: vec![gpg.clone()],
        };
        assert_eq!(super::resolve_ssh_auth_sock(&disabled_gpg, all_live), Some(launchd_tmp.clone()));

        // 3) Explicit non-launchd `launchctl getenv SSH_AUTH_SOCK` wins over launchd env and GPG.
        let launchctl_override = super::SshAuthInputs {
            preferred: None,
            env_sock: Some(launchd_var.clone()),
            launchctl_sock: Some(onepass.clone()),
            gpg_ssh_enabled: true,
            gpg_sockets: vec![gpg.clone()],
        };
        assert_eq!(super::resolve_ssh_auth_sock(&launchctl_override, all_live), Some(onepass.clone()));

        // 4) Explicit non-launchd process env `$SSH_AUTH_SOCK` wins over launchctl and GPG.
        let env_override = super::SshAuthInputs {
            preferred: None,
            env_sock: Some(custom.clone()),
            launchctl_sock: Some(onepass.clone()),
            gpg_ssh_enabled: true,
            gpg_sockets: vec![gpg.clone()],
        };
        assert_eq!(super::resolve_ssh_auth_sock(&env_override, all_live), Some(custom.clone()));

        // 5) Recorded bind-mount `preferred` wins over everything when live,
        //    and falls through cleanly when missing/dead.
        let with_preferred = super::SshAuthInputs {
            preferred: Some(gpg.clone()),
            env_sock: Some(custom.clone()),
            launchctl_sock: Some(onepass.clone()),
            gpg_ssh_enabled: true,
            gpg_sockets: vec![gpg.clone()],
        };
        assert_eq!(super::resolve_ssh_auth_sock(&with_preferred, all_live), Some(gpg.clone()));
        assert_eq!(
            super::resolve_ssh_auth_sock(&with_preferred, |cand| cand != gpg.as_path()),
            Some(custom.clone())
        );

        // 6) Dead explicit env_sock falls through to live GPG socket.
        let dead_env = super::SshAuthInputs {
            preferred: None,
            env_sock: Some(custom.clone()),
            launchctl_sock: Some(launchd_tmp.clone()),
            gpg_ssh_enabled: true,
            gpg_sockets: vec![gpg.clone()],
        };
        assert_eq!(
            super::resolve_ssh_auth_sock(&dead_env, |cand| cand != custom.as_path()),
            Some(gpg)
        );
    }

    #[test]
    fn gpg_agent_conf_parsing_and_socket_discovery() {
        use std::path::PathBuf;
        assert!(super::gpg_agent_ssh_enabled("enable-ssh-support\n"));
        assert!(super::gpg_agent_ssh_enabled("  enable-ssh-support  # for git\n"));
        assert!(super::gpg_agent_ssh_enabled("default-cache-ttl 600\nenable-ssh-support\n"));
        assert!(!super::gpg_agent_ssh_enabled("# enable-ssh-support\n"));
        assert!(!super::gpg_agent_ssh_enabled("#enable-ssh-support\n"));
        assert!(!super::gpg_agent_ssh_enabled("   # enable-ssh-support\n"));
        assert!(!super::gpg_agent_ssh_enabled("enable-ssh-support-extra\n"));
        assert!(!super::gpg_agent_ssh_enabled("enable-ssh-support\nno-enable-ssh-support\n"));
        assert!(!super::gpg_agent_ssh_enabled(""));

        let root = std::env::temp_dir().join(format!("kiri-gpg-conf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("home");
        let custom_gnupg = root.join("custom-gnupg");
        std::fs::create_dir_all(home.join(".gnupg")).unwrap();
        std::fs::create_dir_all(&custom_gnupg).unwrap();

        // Commented-out enable-ssh-support does NOT enable GPG discovery or run gpgconf.
        std::fs::write(home.join(".gnupg/gpg-agent.conf"), "# enable-ssh-support\n").unwrap();
        let (enabled, socks) = super::gather_gpg_ssh_info(None, Some(&home), |_| panic!("gpgconf must not be called when disabled"));
        assert!(!enabled);
        assert!(socks.is_empty());

        // Uncommented enable-ssh-support under ~/.gnupg discovers gpgconf socket then ~/.gnupg/S.gpg-agent.ssh.
        std::fs::write(home.join(".gnupg/gpg-agent.conf"), "default-cache-ttl 300\nenable-ssh-support # on\n").unwrap();
        let gpgconf_path = PathBuf::from("/private/var/folders/aa/bb/T/gnupg/S.gpg-agent.ssh");
        let (enabled, socks) = super::gather_gpg_ssh_info(None, Some(&home), |_| Some(gpgconf_path.clone()));
        assert!(enabled);
        assert_eq!(socks, vec![gpgconf_path.clone(), home.join(".gnupg/S.gpg-agent.ssh")]);

        // Custom GNUPGHOME takes precedence over ~/.gnupg and orders $GNUPGHOME -> gpgconf -> ~/.gnupg.
        std::fs::write(custom_gnupg.join("gpg-agent.conf"), "enable-ssh-support\n").unwrap();
        let (enabled, socks) = super::gather_gpg_ssh_info(Some(&custom_gnupg), Some(&home), |dir| {
            assert_eq!(dir, Some(custom_gnupg.as_path()));
            Some(gpgconf_path.clone())
        });
        assert!(enabled);
        assert_eq!(socks, vec![custom_gnupg.join("S.gpg-agent.ssh"), gpgconf_path, home.join(".gnupg/S.gpg-agent.ssh")]);

        // Custom GNUPGHOME without enable-ssh-support does NOT silently inherit ~/.gnupg/gpg-agent.conf.
        std::fs::write(custom_gnupg.join("gpg-agent.conf"), "# enable-ssh-support\n").unwrap();
        let (enabled, socks) = super::gather_gpg_ssh_info(Some(&custom_gnupg), Some(&home), |_| panic!("should not run gpgconf"));
        assert!(!enabled);
        assert!(socks.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mac_ssh_agent_socket_allowlist_and_preferred_security() {
        use std::os::unix::net::UnixListener;
        use std::path::Path;

        // Launchd detection covers both /tmp and /var/run (+ /private/*) layouts.
        for ok in [
            "/private/tmp/com.apple.launchd.abc123/Listeners",
            "/tmp/com.apple.launchd.abc123/Listeners",
            "/private/var/run/com.apple.launchd.oQTvCAtcQS/Listeners",
            "/var/run/com.apple.launchd.oQTvCAtcQS/Listeners",
            "/var/run//com.apple.launchd.abc/Listeners",
        ] {
            assert!(super::is_launchd_ssh_sock(Path::new(ok)), "{ok}");
            assert!(super::is_known_mac_ssh_agent_sock_path(Path::new(ok)), "{ok}");
        }
        for bad in [
            "/tmp/com.apple.launchd./Listeners",
            "/tmp/com.apple.launchd.abc/sub/Listeners",
            "/Users/alice/com.apple.launchd.abc/Listeners",
            "/var/run/docker.sock",
            "tmp/com.apple.launchd.abc/Listeners",
        ] {
            assert!(!super::is_launchd_ssh_sock(Path::new(bad)), "{bad}");
        }

        // Known Mac agent socket paths vs rejected non-SSH paths.
        for ok in [
            "/Users/alice/.gnupg/S.gpg-agent.ssh",
            "/Users/alice/.config/gnupg/S.gpg-agent.ssh",
            "/Users/alice/.1password/agent.sock",
            "/Users/alice/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock",
        ] {
            assert!(super::is_known_mac_ssh_agent_sock_path(Path::new(ok)), "{ok}");
        }
        for bad in [
            "/Users/alice/.kiri/run/docker.sock",
            "/var/run/docker.sock",
            "/tmp/postgres.sock",
            "/etc/S.gpg-agent.ssh",
            "/Users/alice/S.gpg-agent",
        ] {
            assert!(!super::is_known_mac_ssh_agent_sock_path(Path::new(bad)), "{bad}");
        }

        // Strict path allowlist only permits user's own GPG/1Password/launchd paths.
        let fake_home = Path::new("/Users/alice");
        let fake_gnupg = Path::new("/Users/alice/.config/gnupg");
        let fake_gpgconf = Path::new("/private/var/folders/aa/bb/T/d.1234/S.gpg-agent.ssh");
        assert!(super::is_strict_mac_ssh_agent_sock_path_for(Path::new("/Users/alice/.gnupg/S.gpg-agent.ssh"), Some(fake_home), None, None));
        assert!(super::is_strict_mac_ssh_agent_sock_path_for(Path::new("/Users/alice/.config/gnupg/S.gpg-agent.ssh"), Some(fake_home), Some(fake_gnupg), None));
        assert!(super::is_strict_mac_ssh_agent_sock_path_for(fake_gpgconf, Some(fake_home), None, Some(fake_gpgconf)));
        assert!(super::is_strict_mac_ssh_agent_sock_path_for(Path::new("/Users/alice/.1password/agent.sock"), Some(fake_home), None, None));
        assert!(!super::is_strict_mac_ssh_agent_sock_path_for(Path::new("/tmp/untrusted/S.gpg-agent.ssh"), Some(fake_home), None, None));
        assert!(!super::is_strict_mac_ssh_agent_sock_path_for(Path::new("/Users/alice/.kiri/run/docker.sock"), Some(fake_home), None, None));

        // Live Unix socket security checks for set_preferred_ssh_auth_sock.
        let _guard = super::PREFERRED_SSH_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        super::clear_preferred_ssh_auth_sock();

        let dir = std::env::temp_dir().join(format!("kiri-ssh-pref-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Regular file named S.gpg-agent.ssh is rejected (not a socket).
        let reg = dir.join("reg");
        std::fs::create_dir_all(&reg).unwrap();
        let reg_file = reg.join("S.gpg-agent.ssh");
        std::fs::write(&reg_file, b"not a socket").unwrap();
        assert!(!super::set_preferred_ssh_auth_sock(&reg_file));
        assert!(super::current_preferred_ssh_auth_sock().is_none());

        // Arbitrary socket named docker.sock is rejected, AND a symlink named
        // S.gpg-agent.ssh pointing to docker.sock is ALSO rejected after canonicalize.
        let docker_sock = dir.join("docker.sock");
        let _docker_listener = UnixListener::bind(&docker_sock).unwrap();
        assert!(!super::set_preferred_ssh_auth_sock(&docker_sock));
        let evil_link_dir = dir.join("evil");
        std::fs::create_dir_all(&evil_link_dir).unwrap();
        let evil_link = evil_link_dir.join("S.gpg-agent.ssh");
        std::os::unix::fs::symlink(&docker_sock, &evil_link).unwrap();
        assert!(!super::set_preferred_ssh_auth_sock(&evil_link), "symlink to docker.sock must be rejected");
        assert!(super::current_preferred_ssh_auth_sock().is_none());

        // A real owned S.gpg-agent.ssh Unix socket is accepted by set_preferred_ssh_auth_sock
        // (for host callers), while set_preferred_ssh_auth_sock_strict rejects temp paths
        // outside ~/.gnupg / $GNUPGHOME / gpgconf.
        let gpg_sock = dir.join("S.gpg-agent.ssh");
        let _gpg_listener = UnixListener::bind(&gpg_sock).unwrap();
        assert!(!super::set_preferred_ssh_auth_sock_strict(&gpg_sock));
        assert!(super::current_preferred_ssh_auth_sock().is_none());
        assert!(super::set_preferred_ssh_auth_sock(&gpg_sock));
        assert_eq!(super::current_preferred_ssh_auth_sock(), Some(std::fs::canonicalize(&gpg_sock).unwrap()));

        super::clear_preferred_ssh_auth_sock();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
