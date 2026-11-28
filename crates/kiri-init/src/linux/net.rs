//! Guest networking: the uplink (eth0, configured by DHCP from Apple's NAT),
//! container bridges with masquerade, and each container's veth.

use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use super::firewall;
use super::netlink::{self, Netlink};
use super::sys;

pub const UPLINK: &str = "eth0";
/// What `host.docker.internal` resolves to inside containers in the VM.
/// Connections to it are redirected to the agent and relayed to the Mac's localhost.
pub const HOST_ADDR: [u8; 4] = [198, 19, 248, 254];
/// What `host.docker.internal`, `host.kiri.internal`, and `host-gateway`
/// resolve to on Windows (WSL 2) when `kiri hostrelay` is active, matching
/// Docker Desktop.
pub const WSL_HOST_ADDR: [u8; 4] = [192, 168, 65, 254];
/// Where the redirect lands: the agent's listener for host-bound connections.
pub const HOST_RELAY_PORT: u16 = 1026;

/// True when running inside WSL 2.
pub fn is_wsl() -> bool {
    sys::is_wsl()
}

const HOST_RELAY_PID_FILE: &str = "/run/kiri-hostrelay.pid";

/// Checks whether a Linux `/proc/<pid>/cmdline` (NUL-separated argv) belongs
/// to `kiri hostrelay` (empty cmdline also excludes unreaped zombies).
fn is_hostrelay_cmdline(cmdline: &[u8]) -> bool {
    let mut args = cmdline.split(|&b| b == 0);
    let Some(argv0) = args.next() else { return false };
    let Some(argv1) = args.next() else { return false };
    !argv0.is_empty() && argv1 == b"hostrelay"
}

fn read_pid_file(path: &std::path::Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse::<u32>().ok().filter(|&p| p > 0)
}

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

fn pid_file_alive(path: &std::path::Path, verify: impl FnOnce(u32) -> bool) -> bool {
    read_pid_file(path).is_some_and(|pid| pid_is_alive(pid) && verify(pid))
}

fn hostrelay_pid_matches(pid: u32) -> bool {
    std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|c| is_hostrelay_cmdline(&c))
}

/// True when running on WSL 2 with a live `kiri hostrelay` process owning
/// `192.168.65.254` (verified via `/run/kiri-hostrelay.pid`, `kill(pid, 0)`,
/// and `/proc/<pid>/cmdline`, catching unclean exits without `getifaddrs()`).
pub fn wsl_host_relay_active() -> bool {
    is_wsl() && pid_file_alive(std::path::Path::new(HOST_RELAY_PID_FILE), hostrelay_pid_matches)
}

/// Address answered for `host.docker.internal` / `host.kiri.internal` /
/// `gateway.docker.internal` in the embedded DNS: `192.168.65.254` on WSL 2
/// when the Windows host relay is active, else `HOST_ADDR`.
pub fn effective_host_addr() -> [u8; 4] {
    effective_host_addr_for(super::transport::is_host_process(), wsl_host_relay_active())
}

pub fn effective_host_addr_for(host_process: bool, wsl_relay_active: bool) -> [u8; 4] {
    if host_process && wsl_relay_active { WSL_HOST_ADDR } else { HOST_ADDR }
}
/// Where outbound container TCP connections to VPN tunnel prefixes or under
/// host egress land, to be relayed over vsock to the host dialer.
pub const EGRESS_RELAY_PORT: u16 = 1038;
/// Container interfaces stay below this, so any uplink MTU fits.
const CONTAINER_MTU: u32 = 1500;

#[derive(Debug, Clone, Default)]
pub struct Lease {
    pub ip: [u8; 4],
    pub prefix: u8,
    pub gateway: [u8; 4],
    pub dns: Vec<[u8; 4]>,
}

pub fn ip_str(a: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

pub fn parse_ip(s: &str) -> Option<[u8; 4]> {
    s.parse::<std::net::Ipv4Addr>().ok().map(|a| a.octets())
}

/// A container's IPv6 side on an IPv6 network: its address and prefix, and
/// the gateway (the bridge's own address).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ip6 {
    pub ip: [u8; 16],
    pub prefix: u8,
    pub gateway: [u8; 16],
}

impl Ip6 {
    /// From a network's `ip6=` and `gw6=` settings; None on IPv4-only ones.
    pub fn from_opts(opts: kiri_proto::StrList<'_>) -> Option<Ip6> {
        use kiri_proto::net_opts as k;
        let (ip, prefix) = k::values(opts, k::IP6).next()?.split_once('/')?;
        let gateway = k::values(opts, k::GW6).next()?;
        Some(Ip6 {
            ip: ip.parse::<std::net::Ipv6Addr>().ok()?.octets(),
            prefix: prefix.parse().ok().filter(|p| *p <= 128)?,
            gateway: gateway.parse::<std::net::Ipv6Addr>().ok()?.octets(),
        })
    }

    /// The network's subnet, as the masquerade rule matches it.
    fn subnet(&self) -> [u8; 16] {
        let bits = u128::from_be_bytes(self.gateway);
        let mask = if self.prefix == 0 { 0 } else { u128::MAX << (128 - self.prefix as u32) };
        (bits & mask).to_be_bytes()
    }
}

/// How a container is plugged into one network, from its settings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Plug {
    /// `--internal`: no default route.
    pub internal: bool,
    /// IPv6-only: no IPv4 address on the container or the bridge.
    pub no_ipv4: bool,
}

impl Plug {
    pub fn from_opts(opts: kiri_proto::StrList<'_>) -> Plug {
        use kiri_proto::net_opts as k;
        Plug { internal: k::values(opts, k::INTERNAL).next().is_some(), no_ipv4: k::values(opts, k::NO_IPV4).next().is_some() }
    }
}

/// A network a container can reach the outside through: one that is not
/// `--internal`, with the gateways it offers. Kept per running container, in
/// the order its networks were plugged in, so that a disconnect can hand the
/// default route on to the next one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uplink {
    /// Host side of its veth, which names the attachment on a disconnect.
    pub veth: String,
    /// Its interface in the container: `eth0`, `eth1` …
    pub ifname: String,
    pub v4: Option<[u8; 4]>,
    pub v6: Option<[u8; 16]>,
}

impl Uplink {
    /// None for an internal network, which never gives a default route.
    pub fn of(veth: &str, ifname: &str, gateway: [u8; 4], v6: Option<Ip6>, plug: Plug) -> Option<Uplink> {
        let v4 = (!plug.internal && !plug.no_ipv4).then_some(gateway);
        let v6 = v6.filter(|_| !plug.internal).map(|v| v.gateway);
        (v4.is_some() || v6.is_some()).then(|| Uplink { veth: veth.to_owned(), ifname: ifname.to_owned(), v4, v6 })
    }
}

/// The uplinks that hold the IPv4 and the IPv6 default route: for each, the
/// first one plugged in that has it. `attach` adds every uplink's route and
/// the kernel keeps the first (the later ones are EEXIST), so this is the
/// same choice. Docker would take the network whose name sorts first among
/// equals; keeping the first is steadier: plugging in a network never moves
/// a running container's traffic.
pub fn route_holders(uplinks: &[Uplink]) -> (Option<&Uplink>, Option<&Uplink>) {
    (uplinks.iter().find(|u| u.v4.is_some()), uplinks.iter().find(|u| u.v6.is_some()))
}

/// Takes the attachment whose host veth is `veth` out of `uplinks`, after it
/// was unplugged. If it held a default route, the next uplink gets it, as
/// Docker moves the default gateway when a container leaves that network;
/// with none left the container has no default route, as on internal-only
/// networks. The kernel dropped the old route with the interface.
pub fn hand_over_default_routes(pid: libc::pid_t, uplinks: &mut Vec<Uplink>, veth: &str) -> io::Result<()> {
    let (old4, old6) = route_holders(uplinks);
    let (was4, was6) = (old4.is_some_and(|u| u.veth == veth), old6.is_some_and(|u| u.veth == veth));
    uplinks.retain(|u| u.veth != veth);
    if !was4 && !was6 {
        return Ok(());
    }
    let (new4, new6) = route_holders(uplinks);
    let (new4, new6) = (new4.filter(|_| was4), new6.filter(|_| was6));
    if new4.is_none() && new6.is_none() {
        return Ok(());
    }
    let netns = std::fs::File::open(format!("/proc/{pid}/ns/net"))?;
    let mut inner = Netlink::open_in(&netns)?;
    if let Some(u) = new4 {
        netlink::replace_default_route(&mut inner, netlink::index_in(&netns, &u.ifname)?, u.v4.unwrap_or_default())?;
    }
    if let Some(u) = new6 {
        netlink::replace_default_route6(&mut inner, netlink::index_in(&netns, &u.ifname)?, u.v6.unwrap_or_default())?;
    }
    Ok(())
}

pub fn ip6_str(a: [u8; 16]) -> String {
    std::net::Ipv6Addr::from(a).to_string()
}

/// The MAC a container gets on an address unless one is asked for, made
/// from that address as Docker does (`02:42` then the four bytes). A
/// container that takes over a freed address then takes over its MAC too,
/// so the host and the other containers, which may still hold the old
/// container's entry in their neighbour tables, reach the new one at once.
/// With a random MAC they would send to the old one until the entry expired,
/// several seconds, and connections through a published port failed.
pub fn mac_for(ip: [u8; 4]) -> [u8; 6] {
    [0x02, 0x42, ip[0], ip[1], ip[2], ip[3]]
}

/// `02:42:ac:11:00:02`.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = s.split(':');
    for b in &mut mac {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(mac)
}

/// Resolves active default-route interface names across all routing tables and
/// address families (primary NICs, failover NICs, Tailscale/WireGuard VPNs, etc.).
fn default_route_ifaces() -> Vec<String> {
    netlink::default_route_ifindices().unwrap_or_default().into_iter().filter_map(netlink::name_of).collect()
}

/// Scans `sys_net` (`/sys/class/net`) for non-Kiri Linux bridges that are not
/// themselves holding a default route (e.g. Proxmox `vmbr0`), returning a
/// sorted list of local bridges (`docker0`, `br-*`, `virbr*`, etc.) to isolate.
fn collect_foreign_bridges(sys_net: &std::path::Path, default_ifaces: &[String]) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(sys_net) else { return Vec::new() };
    let mut out: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_owned();
            if name.starts_with("kiri") || default_ifaces.iter().any(|u| u == &name) {
                return None;
            }
            e.path().join("bridge").is_dir().then_some(name)
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Refreshes `netlink::FOREIGN_BRIDGES`, returning `true` if the set changed.
fn update_foreign_bridges() -> bool {
    let default_ifaces = default_route_ifaces();
    let bridges = collect_foreign_bridges(std::path::Path::new("/sys/class/net"), &default_ifaces);
    let mut g = netlink::FOREIGN_BRIDGES.lock().unwrap_or_else(|e| e.into_inner());
    if *g == bridges {
        false
    } else {
        *g = bridges;
        true
    }
}

/// Abstract Unix-domain socket name guarding Kiri's host networking (`kiri0`
/// and `nft table ip/ip6 kiri`) within a Linux network namespace (#443).
/// Abstract socket addresses are scoped per network namespace and released by
/// the kernel automatically when the agent exits or crashes.
const HOST_NETNS_LOCK_NAME: &[u8] = b"kiri-engine-netns";

static HOST_NETNS_LOCK: std::sync::OnceLock<OwnedFd> = std::sync::OnceLock::new();
static HOST_NETNS_CLAIMED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn make_abstract_sockaddr(name: &[u8]) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    // SAFETY: zeroed `sockaddr_un` is valid; `sun_path[0] = 0` followed by `name`
    // forms a Linux abstract socket address of length `offsetof(sun_path) + 1 + name.len()`.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if 1 + name.len() > addr.sun_path.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "netns lock name too long"));
    }
    for (dst, &src) in addr.sun_path[1..1 + name.len()].iter_mut().zip(name) {
        *dst = src as libc::c_char;
    }
    let addr_len = (std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + name.len()) as libc::socklen_t;
    Ok((addr, addr_len))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockProbe {
    /// Connected and `SO_PEERCRED.uid == owner`.
    OwnedByOwner,
    /// Connected and `SO_PEERCRED.uid != owner` (unprivileged squatter).
    OwnedByOther,
    /// `connect()` failed transiently (`EAGAIN` backlog full, `ECONNREFUSED`
    /// bind-to-listen window or closing holder, `EINTR`, etc.). Never treated
    /// as an unprivileged squatter.
    TransientBusy,
}

/// Probes an active listener on `name` to distinguish a legitimate `owner`
/// engine from an unprivileged squatter or transient backlog/startup state.
fn probe_abstract_lock(name: &[u8], owner: u32) -> LockProbe {
    let Ok((addr, addr_len)) = make_abstract_sockaddr(name) else { return LockProbe::TransientBusy };
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
    if raw < 0 {
        return LockProbe::TransientBusy;
    }
    // SAFETY: `raw` is a freshly created socket descriptor owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: `addr` is initialized through `addr_len` bytes.
    if unsafe { libc::connect(fd.as_raw_fd(), (&raw const addr).cast(), addr_len) } != 0 {
        return LockProbe::TransientBusy;
    }
    // SAFETY: zeroed `ucred` is valid for `getsockopt(SO_PEERCRED)`.
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut peer).cast(),
            &mut len,
        )
    };
    if rc != 0 || len != std::mem::size_of::<libc::ucred>() as libc::socklen_t {
        return LockProbe::TransientBusy;
    }
    if peer.uid == owner {
        LockProbe::OwnedByOwner
    } else {
        LockProbe::OwnedByOther
    }
}

fn try_bind_abstract_socket(name: &[u8]) -> Result<OwnedFd, i32> {
    let (addr, addr_len) = make_abstract_sockaddr(name).map_err(|_| libc::EINVAL)?;
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO));
    }
    // SAFETY: `raw` is a freshly created socket descriptor owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: `addr` is initialized through `addr_len` bytes.
    if unsafe { libc::bind(fd.as_raw_fd(), (&raw const addr).cast(), addr_len) } != 0 {
        return Err(io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO));
    }
    // SAFETY: `fd` is a bound `SOCK_STREAM` socket owned here.
    if unsafe { libc::listen(fd.as_raw_fd(), 128) } != 0 {
        return Err(io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO));
    }
    Ok(fd)
}

/// Descriptor of the held abstract netns lock socket, polled by the
/// single-threaded `agent::serve_loop` (`kiri-init` never spawns threads, so
/// `signalfd` and `clone3` stay single-threaded).
pub fn netns_lock_fd() -> Option<std::os::fd::RawFd> {
    HOST_NETNS_LOCK.get().map(AsRawFd::as_raw_fd)
}

/// Drains up to 64 pending `SO_PEERCRED` probe connections per `poll()` tick so
/// `sk_max_ack_backlog` does not fill under normal retries while a local
/// `connect()` flood can never starve `agent::serve_loop`.
pub fn drain_netns_lock(fd: std::os::fd::RawFd) {
    for _ in 0..64 {
        // SAFETY: `fd` is a non-blocking listening `AF_UNIX` socket.
        let cfd = unsafe { libc::accept4(fd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) };
        if cfd >= 0 {
            // SAFETY: `cfd` is a freshly accepted descriptor owned here.
            unsafe { libc::close(cfd) };
            continue;
        }
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(libc::EAGAIN);
        if err == libc::EMFILE || err == libc::ENFILE {
            std::thread::sleep(Duration::from_millis(1));
        }
        break;
    }
}

const NETNS_BUSY_MSG: &str =
    "another Kiri engine is already running in this network namespace (for example in another WSL 2 distribution): stop it first";
const MAX_NETNS_LOCK_SLOTS: usize = 64;

fn netns_slot_name(base: &[u8], idx: usize) -> Vec<u8> {
    if idx == 0 {
        base.to_vec()
    } else {
        let mut v = Vec::with_capacity(base.len() + 8);
        v.extend_from_slice(base);
        v.extend_from_slice(format!("-{idx}").as_bytes());
        v
    }
}

/// Claims ownership of Kiri's bridge and firewall tables in the current Linux
/// network namespace (#443). All WSL 2 distributions share one network
/// namespace; refusing early prevents a second engine from overwriting
/// `nft table ip kiri` or deleting `kiri0` when stopping.
pub fn claim_host_netns() -> io::Result<()> {
    claim_host_netns_on(HOST_NETNS_LOCK_NAME, &HOST_NETNS_LOCK, &HOST_NETNS_CLAIMED)
}

fn claim_host_netns_on(
    base: &[u8],
    slot: &std::sync::OnceLock<OwnedFd>,
    claimed: &std::sync::atomic::AtomicBool,
) -> io::Result<()> {
    use std::sync::atomic::Ordering;
    if claimed.load(Ordering::Acquire) {
        return Ok(());
    }
    // SAFETY: `geteuid` has no preconditions.
    let me = unsafe { libc::geteuid() };
    let mut idx = 0usize;
    while idx < MAX_NETNS_LOCK_SLOTS {
        let candidate = netns_slot_name(base, idx);
        let start = Instant::now();
        loop {
            match try_bind_abstract_socket(&candidate) {
                Ok(fd) => {
                    let _ = slot.set(fd);
                    claimed.store(true, Ordering::Release);
                    return Ok(());
                }
                Err(code) if code == libc::EADDRINUSE => match probe_abstract_lock(&candidate, me) {
                    LockProbe::OwnedByOther => {
                        // Unprivileged squatter on `candidate`: advance to the next
                        // deterministic slot so the first root engine still binds a
                        // real lock and a second root engine hits that bound slot
                        // (preventing split-brain without arming `claimed` unlocked).
                        eprintln!("kiri-init: skipping unprivileged squatter on abstract netns socket slot {idx}");
                        idx += 1;
                        break;
                    }
                    LockProbe::OwnedByOwner | LockProbe::TransientBusy => {
                        if start.elapsed() < Duration::from_millis(500) {
                            std::thread::sleep(Duration::from_millis(25));
                            continue;
                        }
                        return Err(io::Error::new(io::ErrorKind::AddrInUse, NETNS_BUSY_MSG));
                    }
                },
                Err(code) => return Err(io::Error::from_raw_os_error(code)),
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::AddrInUse, NETNS_BUSY_MSG))
}

/// On a Linux host: claims the network namespace, enables IPv4 forwarding,
/// detects foreign local bridges, installs Kiri's nftables table, and adapts
/// to any host firewall. Does not require a main-table default route at boot
/// (policy-routed VPNs such as Tailscale or delayed interfaces work as routes
/// appear).
pub fn host_uplink() -> io::Result<()> {
    claim_host_netns()?;
    sys::write_file("/proc/sys/net/ipv4/ip_forward", "1")?;
    // No host.docker.internal loopback redirect on a Linux host: it would
    // let containers reach the real machine's 127.0.0.1 services. host.docker
    // .internal maps to the bridge gateway instead (write_etc_files).
    let _ = HOST_UPLINK_INDEX.set(0);
    let _ = update_foreign_bridges();
    through_firewall(firewall::Why::Start);
    install_nat(Nat { uplink: 0, redirect: false, dnat: Vec::new(), gateway: [0; 4] })
}

/// Linux host: a socket that hears of every nf_tables change, so a firewall
/// started, reloaded or flushed after the engine (Docker's, ufw, firewalld,
/// nftables.service) is brought in line at once. None if the kernel refuses it.
pub fn firewall_events() -> Option<OwnedFd> {
    netlink::nftables_events().inspect_err(|e| eprintln!("kiri-init: not watching the host's firewall: {e}")).ok()
}

/// Linux host: a socket that hears of link and route changes so dynamic
/// foreign bridges (`docker0`, `br-*`, `virbr*`) and default-route bridges
/// stay current in Kiri's forward filters.
pub fn link_route_events() -> Option<OwnedFd> {
    netlink::link_route_events().inspect_err(|e| eprintln!("kiri-init: not watching host links/routes: {e}")).ok()
}

/// `firewall_events` heard of a change: reads it and brings the host's
/// firewall, and Kiri's own tables, in line.
pub fn firewall_changed(events: &OwnedFd) {
    netlink::drain(events);
    let foreign_changed = update_foreign_bridges();
    through_firewall(firewall::Why::Event);
    if foreign_changed {
        rebuild_nat_all();
    }
}

/// `link_route_events` heard a link or route change: updates foreign-bridge
/// isolation and rebuilds Kiri's forward filters when the bridge set changed.
pub fn link_route_changed(events: &OwnedFd) {
    netlink::drain(events);
    if update_foreign_bridges() {
        rebuild_nat_all();
    }
}

fn rebuild_nat_all() {
    if let Err(e) = refresh_nat() {
        eprintln!("kiri-init: NAT: {e}");
    }
    let nat6 = NAT6.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if !nat6.0.is_empty()
        && let Err(e) = refresh_nat6(&nat6.0, &nat6.1)
    {
        eprintln!("kiri-init: IPv6 NAT: {e}");
    }
}

/// `firewall::sync`, with Kiri's own tables built again as last built when
/// it asks: a flush of the whole ruleset (`nft flush ruleset`, as
/// nftables.service runs it) took them, and containers had no masquerade,
/// no published ports and no forward filter keeping the LAN off their
/// unpublished ports; or the forward chain's firewalld guard changed.
fn through_firewall(why: firewall::Why) {
    firewall::sync(why, |[v4, v6]| {
        // Built before (`refresh_nat` takes the lock itself).
        let built = NAT.lock().unwrap_or_else(|e| e.into_inner()).is_some();
        if v4
            && built
            && let Err(e) = refresh_nat()
        {
            eprintln!("kiri-init: NAT: {e}");
        }
        let nat6 = NAT6.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if v6
            && !nat6.0.is_empty()
            && let Err(e) = refresh_nat6(&nat6.0, &nat6.1)
        {
            eprintln!("kiri-init: IPv6 NAT: {e}");
        }
    });
}

/// What Kiri's IPv6 table was last built from (`install_nat6`), to build it
/// again after a flush.
#[allow(clippy::type_complexity)]
static NAT6: std::sync::Mutex<(Vec<([u8; 16], u8)>, Vec<String>)> = std::sync::Mutex::new((Vec::new(), Vec::new()));

/// Rebuilds Kiri's IPv6 table from `subnets`/`bridges` and, in the VM, the
/// loopback redirect and input guard for `HOST_RELAY_PORT`.
fn refresh_nat6(subnets: &[([u8; 16], u8)], bridges: &[String]) -> io::Result<()> {
    let (redirect, dnat) = NAT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map_or((false, Vec::new()), |n| (n.redirect, n.dnat.clone()));
    netlink::install_nat6(subnets, bridges, HOST_RELAY_PORT, redirect, &dnat)
}

/// What Kiri's IPv4 table was last built from, so it can be rebuilt when a
/// bridge comes or goes (the forward filter has a rule per bridge).
struct Nat {
    uplink: i32,
    redirect: bool,
    dnat: Vec<netlink::Dnat>,
    gateway: [u8; 4],
}

static NAT: std::sync::Mutex<Option<Nat>> = std::sync::Mutex::new(None);
/// Egress IPv4 CIDR prefixes redirected to `EGRESS_RELAY_PORT`.
static EGRESS_ROUTES: std::sync::Mutex<Vec<([u8; 4], u8)>> = std::sync::Mutex::new(Vec::new());
/// Active bridge IPv4 subnets `(name, network, prefix)`, exempt from egress redirect.
static BRIDGE_SUBNETS: std::sync::Mutex<Vec<(String, [u8; 4], u8)>> = std::sync::Mutex::new(Vec::new());
/// The VM uplink's IPv4 subnet `(network, prefix)`, exempt from egress redirect.
static UPLINK_SUBNET: std::sync::Mutex<Option<([u8; 4], u8)>> = std::sync::Mutex::new(None);
/// The kernel has no nft_fib_ipv4 (`fib daddr type local`): ports
/// published on every address are matched per address of this machine.
static NO_FIB4: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn parse_cidr(s: &str) -> Option<([u8; 4], u8)> {
    let (ip, prefix) = s.trim().split_once('/')?;
    let ip = parse_ip(ip)?;
    let prefix: u8 = prefix.parse().ok().filter(|&p| p <= 32)?;
    Some((netlink::mask_ipv4(ip, prefix), prefix))
}

pub fn parse_egress_routes(list: kiri_proto::StrList<'_>) -> Vec<([u8; 4], u8)> {
    let mut out = Vec::new();
    for s in list.iter() {
        if let Some(c) = parse_cidr(s)
            && !out.contains(&c)
        {
            out.push(c);
        }
    }
    out
}

/// Whether `routes` includes full host egress (`0.0.0.0/0`), in which case
/// guest upstream DNS lookups should go straight through the host DNS relay.
pub fn egress_prefers_dns_relay(routes: &[([u8; 4], u8)]) -> bool {
    routes.iter().any(|&(_, prefix)| prefix == 0)
}

/// Updates the IPv4 CIDR prefixes redirected to the host egress dialer and
/// rebuilds Kiri's IPv4 nftables table.
pub fn set_egress_routes(routes: Vec<([u8; 4], u8)>) -> io::Result<()> {
    *EGRESS_ROUTES.lock().unwrap_or_else(|e| e.into_inner()) = routes;
    refresh_nat()
}

fn egress_skip_subnets() -> Vec<([u8; 4], u8)> {
    let mut skip = vec![
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([224, 0, 0, 0], 3),
    ];
    if let Some(up) = *UPLINK_SUBNET.lock().unwrap_or_else(|e| e.into_inner())
        && !skip.contains(&up)
    {
        skip.push(up);
    }
    for &(_, net, prefix) in BRIDGE_SUBNETS.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        if !skip.contains(&(net, prefix)) {
            skip.push((net, prefix));
        }
    }
    skip
}

/// Builds Kiri's IPv4 table from `nat` and the bridges made so far, and
/// keeps `nat` for `refresh_nat`. In the VM (`nat.redirect`), also installs
/// the IPv6 `::1` loopback redirect and input guard on a best-effort basis.
fn install_nat(nat: Nat) -> io::Result<()> {
    use std::sync::atomic::Ordering;
    let bridges = MADE_BRIDGES.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let egress = EGRESS_ROUTES.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let skip = if egress.is_empty() { Vec::new() } else { egress_skip_subnets() };
    let any_addr = nat.dnat.iter().any(|d| d.host_ip == [0; 4]);
    let wsl_host = (!nat.redirect && is_wsl()).then_some(WSL_HOST_ADDR);
    let bridge_subnets: Vec<([u8; 4], u8)> = if nat.redirect {
        Vec::new()
    } else {
        BRIDGE_SUBNETS.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|&(_, net, prefix)| (net, prefix)).collect()
    };
    let allow_prerouting_dnat = nat.redirect || !firewall::forwarding_blocked();
    let install = |local: Option<&[[u8; 4]]>| {
        netlink::install_nat_full(
            nat.uplink,
            HOST_ADDR,
            HOST_RELAY_PORT,
            nat.redirect,
            &nat.dnat,
            nat.gateway,
            &bridges,
            local,
            EGRESS_RELAY_PORT,
            &egress,
            &skip,
            wsl_host,
            &bridge_subnets,
            allow_prerouting_dnat,
        )
    };
    let r = if any_addr && NO_FIB4.load(Ordering::Relaxed) {
        install(Some(&local_addrs()))
    } else {
        match install(None) {
            Err(e) if any_addr && e.raw_os_error() == Some(libc::ENOENT) => {
                eprintln!("kiri-init: no nft_fib_ipv4 in this kernel; ports published on every address match this machine's addresses one by one");
                NO_FIB4.store(true, Ordering::Relaxed);
                install(Some(&local_addrs()))
            }
            r => r,
        }
    };
    if r.is_ok() {
        let redirect = nat.redirect;
        *NAT.lock().unwrap_or_else(|e| e.into_inner()) = Some(nat);
        if redirect {
            let nat6 = NAT6.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let _ = refresh_nat6(&nat6.0, &nat6.1);
        }
    }
    r
}

/// Rebuilds Kiri's IPv4 table as last built, for the bridges there are now.
fn refresh_nat() -> io::Result<()> {
    let nat = NAT.lock().unwrap_or_else(|e| e.into_inner()).take();
    match nat {
        Some(n) => {
            let keep = Nat { uplink: n.uplink, redirect: n.redirect, dnat: n.dnat.clone(), gateway: n.gateway };
            let r = install_nat(n);
            if r.is_err() {
                *NAT.lock().unwrap_or_else(|e| e.into_inner()) = Some(keep);
            }
            r
        }
        None => Ok(()),
    }
}

/// Whether one of `servers` is an address of this machine itself, as WSL's
/// DNS forwarder is (10.255.255.254, on `lo`). Containers on a bridge can't
/// count on such a resolver: under WSL a third of the queries from a
/// container's namespace go unanswered, while the host's own are fine. Their
/// queries then go through the agent's resolver, at the bridge's gateway
/// (container.rs embedded_address), which asks it from the host's side.
pub fn local_resolver(servers: &[[u8; 4]]) -> bool {
    !servers.is_empty() && local_resolver_among(servers, &local_addrs())
}

/// `local_resolver`, given this machine's addresses. Loopback stubs
/// (`127.0.0.53`, systemd-resolved) and Tailscale's MagicDNS (`100.100.100.100`)
/// live in the host's network namespace too, so bridged containers reach them
/// through the agent at the bridge gateway rather than naming them directly.
pub fn local_resolver_among(servers: &[[u8; 4]], local: &[[u8; 4]]) -> bool {
    servers.iter().any(|s| s[0] == 127 || *s == [100, 100, 100, 100] || local.contains(s))
}

/// The IPv4 address of interface `name`, if it has one: a bridge's gateway.
pub fn bridge_ipv4(name: &str) -> Option<[u8; 4]> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.contains('\0') {
        return None;
    }
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return None;
    }
    // SAFETY: all-zero is a valid `ifreq`; `ifr_name` gets an ASCII name shorter than IFNAMSIZ.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, &src) in ifr.ifr_name.iter_mut().zip(name.as_bytes()) {
        *dst = src as libc::c_char;
    }
    // SAFETY: `SIOCGIFADDR` fills `ifr_ifru.ifru_addr` with an `AF_INET` `sockaddr` for `ifr_name`.
    let rc = unsafe { libc::ioctl(fd, libc::SIOCGIFADDR as _, &mut ifr) };
    unsafe { libc::close(fd) };
    if rc != 0 {
        return None;
    }
    // SAFETY: `SIOCGIFADDR` initialized `ifru_addr`; in `sockaddr_in`, `sa_data[2..6]` is `sin_addr`.
    let addr = unsafe { ifr.ifr_ifru.ifru_addr };
    (i32::from(addr.sa_family) == libc::AF_INET).then(|| {
        let d = addr.sa_data;
        [d[2] as u8, d[3] as u8, d[4] as u8, d[5] as u8]
    })
}

/// This machine's IPv4 addresses but loopback, what `fib daddr type local`
/// matches.
fn local_addrs() -> Vec<[u8; 4]> {
    let mut out = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list`, freed below; entries are read only while it lives.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return out;
    }
    let mut p = list;
    while !p.is_null() {
        // SAFETY: `p` is an entry of the list getifaddrs returned.
        let ifa = unsafe { &*p };
        if !ifa.ifa_addr.is_null() && i32::from(unsafe { (*ifa.ifa_addr).sa_family }) == libc::AF_INET {
            // SAFETY: an AF_INET address is a sockaddr_in.
            let a = unsafe { (*(ifa.ifa_addr as *const libc::sockaddr_in)).sin_addr.s_addr }.to_ne_bytes();
            // Exclude loopback and (on WSL 2) the Windows host-gateway address so
            // published-port DNAT fallback rules never hijack host.docker.internal.
            if a[0] != 127 && (!is_wsl() || a != WSL_HOST_ADDR) && !out.contains(&a) {
                out.push(a);
            }
        }
        p = ifa.ifa_next;
    }
    // SAFETY: the list getifaddrs returned, freed once.
    unsafe { libc::freeifaddrs(list) };
    out
}

/// The Linux host's uplink interface, once `host_uplink` found it.
static HOST_UPLINK_INDEX: std::sync::OnceLock<i32> = std::sync::OnceLock::new();

/// Linux host: makes these, and only these, the published ports the kernel
/// forwards (see `netlink::Dnat`). Returns an error when host firewall
/// `FORWARD` chains block kernel forwarding so the daemon serves them via
/// user-space `INPUT` relays instead of blackholing SYNs in `prerouting`.
pub fn publish(dnat: &[netlink::Dnat]) -> io::Result<()> {
    let index = *HOST_UPLINK_INDEX.get().ok_or_else(|| io::Error::other("no uplink"))?;
    if !dnat.is_empty() && firewall::forwarding_blocked() {
        return Err(io::Error::other("kernel forwarding is blocked by host firewall"));
    }
    install_nat(Nat { uplink: index, redirect: false, dnat: dnat.to_vec(), gateway: [0; 4] })
}

/// Linux host: updates Kiri's nftables table after unpublishing a container's
/// ports, even while `firewall::forwarding_blocked()` is true, so exiting
/// containers never leave stale `output` DNAT rules behind when other
/// containers remain published.
pub fn unpublish(dnat: &[netlink::Dnat]) -> io::Result<()> {
    let index = *HOST_UPLINK_INDEX.get().ok_or_else(|| io::Error::other("no uplink"))?;
    install_nat(Nat { uplink: index, redirect: false, dnat: dnat.to_vec(), gateway: [0; 4] })
}

/// Raises a numeric sysctl file to at least `min`, ignoring missing entries.
fn raise_sysctl_min(path: &std::path::Path, min: u64) {
    let Ok(raw) = std::fs::read_to_string(path) else { return };
    if raw.trim().parse::<u64>().is_ok_and(|cur| cur < min) {
        let _ = std::fs::write(path, min.to_string());
    }
}

/// Counts sysfs `rx-*` queues exposed for `iface`.
pub(crate) fn rx_queue_count(iface: &str) -> usize {
    let queues_dir = std::path::PathBuf::from(format!("/sys/class/net/{iface}/queues"));
    let Ok(entries) = std::fs::read_dir(&queues_dir) else { return 0 };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_str().is_some_and(|n| n.starts_with("rx-")))
        .count()
}

/// Formats a Linux sysfs `rps_cpus` hex bitmask from actual `online_cpus` IDs.
/// With >= 4 online CPUs, excludes the first online CPU (dedicated to
/// `virtio-net` hardirq/NAPI polling) so the remaining CPUs handle `NET_RX`
/// softirq work; with 2-3 CPUs, includes all online CPUs so steering still fans
/// out across multiple cores.
fn format_rps_cpu_mask(online_cpus: &[usize]) -> Option<String> {
    if online_cpus.len() <= 1 {
        return None;
    }
    let selected = if online_cpus.len() >= 4 { &online_cpus[1..] } else { online_cpus };
    let max_cpu = *selected.iter().max()?;
    let words = max_cpu / 32 + 1;
    let mut chunks = vec![0u32; words];
    for &cpu in selected {
        chunks[cpu / 32] |= 1u32 << (cpu % 32);
    }
    let mut out = String::new();
    for &bits in chunks.iter().rev() {
        if out.is_empty() {
            out.push_str(&format!("{bits:x}"));
        } else {
            out.push_str(&format!(",{bits:08x}"));
        }
    }
    Some(out)
}

/// Enables Receive Packet Steering (RPS) on the VM's uplink interface so Apple
/// Virtualization.framework's single-queue `virtio-net` spreads `NET_RX`
/// softirq work across vCPUs instead of pinning it onto CPU 0. When >= 4 CPUs
/// isolate CPU 0 from `rps_cpus`, RFS (`rps_flow_cnt`) is intentionally left
/// disabled so Linux's RFS lookup cannot steer packets back onto CPU 0.
/// Best-effort: silently skipped if the kernel omits `CONFIG_RPS`.
fn configure_uplink_rps(iface: &str) {
    const RFS_FLOW_ENTRIES: u64 = 32_768;
    let cpus = super::online_cpu_ids();
    let Some(mask) = format_rps_cpu_mask(&cpus) else { return };
    let queues_dir = std::path::PathBuf::from(format!("/sys/class/net/{iface}/queues"));
    let Ok(entries) = std::fs::read_dir(&queues_dir) else { return };
    let rx_queues: Vec<std::path::PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("rx-")))
        .collect();
    if rx_queues.is_empty() {
        return;
    }
    let enable_rfs = cpus.len() < 4;
    if enable_rfs {
        raise_sysctl_min(std::path::Path::new("/proc/sys/net/core/rps_sock_flow_entries"), RFS_FLOW_ENTRIES);
    }
    let per_queue = (RFS_FLOW_ENTRIES / rx_queues.len() as u64).max(1).to_string();
    for q in rx_queues {
        let _ = std::fs::write(q.join("rps_cpus"), &mask);
        if enable_rfs {
            let _ = std::fs::write(q.join("rps_flow_cnt"), &per_queue);
        }
    }
}

/// Brings the uplink up and returns a DHCP client for it, or None if the VM
/// has no network card (shared NAT disabled: installs the VM nftables table
/// and a fallback default route on `lo` so host-network and bridged containers
/// route outbound TCP through the host egress relay over vsock).
pub fn uplink() -> io::Result<Option<Dhcp>> {
    sys::write_file("/proc/sys/net/ipv4/ip_forward", "1")?;
    // The tunnel drivers are built in, and each would add its idle fallback
    // device (tunl0, gre0, sit0, ip6tnl0...) to every container's network:
    // they stay in the VM's own, as on a machine that loads them as modules.
    let _ = sys::write_file("/proc/sys/net/core/fb_tunnels_only_for_init_net", "1");
    // In the VM root netns, bypass L2 bridge-netfilter hooks and conntrack for
    // same-bridge container-to-container packets (such as Kong -> PostgREST on
    // a user network), and raise `nf_conntrack_max` for sustained load (#509).
    let _ = sys::write_file("/proc/sys/net/bridge/bridge-nf-call-iptables", "0");
    let _ = sys::write_file("/proc/sys/net/bridge/bridge-nf-call-ip6tables", "0");
    raise_sysctl_min(std::path::Path::new("/proc/sys/net/netfilter/nf_conntrack_max"), 262_144);
    match netlink::index_of(UPLINK) {
        Ok(index) => {
            let mut nl = Netlink::open(libc::NETLINK_ROUTE)?;
            netlink::set_up(&mut nl, index)?;
            configure_uplink_rps(UPLINK);
            install_nat(Nat { uplink: index, redirect: true, dnat: Vec::new(), gateway: [0; 4] })?;
            let _ = VM_UPLINK_INDEX.set(index);
            Ok(Some(Dhcp::start(index)?))
        }
        Err(_) => {
            // Without an `eth0` NIC, locally originated connects in the VM root
            // netns (`--network host` containers) perform IPv4 route lookup
            // before NF_INET_LOCAL_OUT nftables redirect rules run. Add a
            // fallback default route on `lo` so `connect()` reaches the output
            // egress/host-relay redirect rules instead of failing ENETUNREACH.
            if let Ok(lo) = netlink::index_of("lo")
                && let Ok(mut nl) = Netlink::open(libc::NETLINK_ROUTE)
                && let Err(e) = netlink::add_device_default_route(&mut nl, lo, Some(netlink::LOOPBACK))
            {
                eprintln!("kiri-init: fallback default route on lo: {e}");
            }
            install_nat(Nat { uplink: 0, redirect: true, dnat: Vec::new(), gateway: [0; 4] })?;
            let _ = VM_UPLINK_INDEX.set(0);
            Ok(None)
        }
    }
}

/// The VM's uplink (eth0), or 0 when booted without a NIC (shared NAT off).
static VM_UPLINK_INDEX: std::sync::OnceLock<i32> = std::sync::OnceLock::new();

/// In the VM: makes these the published ports the kernel forwards from the
/// uplink, for connections the Mac makes from `gateway` (its address on the
/// NAT network), and loopback redirects for `--network host` containers.
/// The table is rebuilt whole, so the host.docker.internal and egress
/// redirects stay.
pub fn publish_vm(dnat: &[netlink::Dnat], gateway: [u8; 4]) -> io::Result<()> {
    let index = *VM_UPLINK_INDEX.get().ok_or_else(|| io::Error::other("no uplink"))?;
    if index == 0 && dnat.iter().any(|d| d.host_ip != netlink::LOOPBACK) {
        return Err(io::Error::other("no uplink"));
    }
    install_nat(Nat { uplink: index, redirect: true, dnat: dnat.to_vec(), gateway })
}

enum DhcpState {
    Discovering,
    Requesting { offered: [u8; 4], server: [u8; 4] },
    Bound,
}

/// A small DHCP client run from the agent's poll loop: the agent must stay
/// single-threaded, and boot should never wait for a lease.
pub struct Dhcp {
    sock: OwnedFd,
    index: i32,
    mac: [u8; 6],
    xid: u32,
    state: DhcpState,
    next_send: Instant,
    attempt: u32,
    pub lease: Option<Lease>,
}

impl Dhcp {
    fn start(index: i32) -> io::Result<Dhcp> {
        // SAFETY: plain socket setup; the fd is owned immediately.
        let sock = unsafe {
            let fd = sys::check(libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) as _, "dhcp socket")?;
            OwnedFd::from_raw_fd(fd as i32)
        };
        let one: libc::c_int = 1;
        let set = |opt, val: &[u8]| {
            // SAFETY: setsockopt with a buffer of the stated length.
            unsafe { libc::setsockopt(sock.as_raw_fd(), libc::SOL_SOCKET, opt, val.as_ptr().cast(), val.len() as u32) }
        };
        set(libc::SO_BROADCAST, &one.to_ne_bytes());
        set(libc::SO_REUSEADDR, &one.to_ne_bytes());
        set(libc::SO_BINDTODEVICE, b"eth0\0");
        let addr = sockaddr([0, 0, 0, 0], 68);
        // SAFETY: binding to a valid sockaddr_in.
        sys::check(unsafe { libc::bind(sock.as_raw_fd(), (&addr as *const libc::sockaddr_in).cast(), std::mem::size_of::<libc::sockaddr_in>() as u32) } as _, "dhcp bind")?;
        let mut d = Dhcp {
            mac: mac_of(UPLINK)?,
            sock,
            index,
            xid: random_u32(),
            state: DhcpState::Discovering,
            next_send: Instant::now(),
            attempt: 0,
            lease: None,
        };
        d.send()?;
        Ok(d)
    }

    pub fn fd(&self) -> i32 {
        self.sock.as_raw_fd()
    }

    /// Milliseconds until the next retransmission, for poll's timeout.
    pub fn timeout_ms(&self) -> i32 {
        if matches!(self.state, DhcpState::Bound) {
            return -1;
        }
        self.next_send.saturating_duration_since(Instant::now()).as_millis().min(i32::MAX as u128) as i32
    }

    pub fn on_timer(&mut self) -> io::Result<()> {
        if !matches!(self.state, DhcpState::Bound) && Instant::now() >= self.next_send {
            self.send()?;
        }
        Ok(())
    }

    fn send(&mut self) -> io::Result<()> {
        let mut p = vec![0u8; 240];
        p[0] = 1; // BOOTREQUEST
        p[1] = 1; // Ethernet
        p[2] = 6;
        p[4..8].copy_from_slice(&self.xid.to_be_bytes());
        p[10] = 0x80; // ask for broadcast replies: we have no address yet
        p[28..34].copy_from_slice(&self.mac);
        p[236..240].copy_from_slice(&[99, 130, 83, 99]);
        match self.state {
            DhcpState::Discovering => p.extend_from_slice(&[53, 1, 1]),
            DhcpState::Requesting { offered, server } => {
                p.extend_from_slice(&[53, 1, 3, 50, 4]);
                p.extend_from_slice(&offered);
                p.extend_from_slice(&[54, 4]);
                p.extend_from_slice(&server);
            }
            DhcpState::Bound => return Ok(()),
        }
        p.extend_from_slice(&[55, 3, 1, 3, 6, 255]);
        p.resize(300, 0);
        let to = sockaddr([255, 255, 255, 255], 67);
        // SAFETY: sending a buffer we own to a valid sockaddr_in.
        unsafe { libc::sendto(self.sock.as_raw_fd(), p.as_ptr().cast(), p.len(), 0, (&to as *const libc::sockaddr_in).cast(), std::mem::size_of::<libc::sockaddr_in>() as u32) };
        self.attempt += 1;
        self.next_send = Instant::now() + Duration::from_millis((250u64 << self.attempt.min(5)).min(4000));
        Ok(())
    }

    /// Configures `eth0` from host-supplied settings when DHCP did not answer.
    /// No-op (`Ok(false)`) if a lease is already active.
    pub fn apply_static(&mut self, ip: [u8; 4], prefix: u8, gateway: [u8; 4], dns: [u8; 4]) -> io::Result<bool> {
        let index = self.index;
        self.apply_static_with(ip, prefix, gateway, dns, |lease| {
            let mut nl = Netlink::open(libc::NETLINK_ROUTE)?;
            netlink::add_address(&mut nl, index, lease.ip, lease.prefix)?;
            netlink::add_default_route(&mut nl, index, lease.gateway)
        })
    }

    fn apply_static_with(&mut self, ip: [u8; 4], prefix: u8, gateway: [u8; 4], dns: [u8; 4], configure: impl FnOnce(&Lease) -> io::Result<()>) -> io::Result<bool> {
        if self.lease.is_some() {
            return Ok(false);
        }
        if !valid_uplink(ip, prefix, gateway) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid uplink settings"));
        }
        let lease = Lease { ip, prefix, gateway, dns: if dns == [0; 4] { Vec::new() } else { vec![dns] } };
        configure(&lease)?;
        self.state = DhcpState::Bound;
        self.lease = Some(lease);
        Ok(true)
    }

    /// Handles a reply. Returns true once a lease has been configured.
    pub fn on_readable(&mut self) -> io::Result<bool> {
        let mut buf = [0u8; 1500];
        loop {
            // SAFETY: receiving into a buffer we own.
            let n = unsafe { libc::recv(self.sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n <= 0 {
                return Ok(false);
            }
            let p = &buf[..n as usize];
            if p.len() < 240 || p[0] != 2 || p[4..8] != self.xid.to_be_bytes() || p[236..240] != [99, 130, 83, 99] {
                continue;
            }
            let yiaddr: [u8; 4] = p[16..20].try_into().expect("4");
            let (mut kind, mut mask, mut router, mut server, mut dns) = (0u8, [255, 255, 255, 0], [0u8; 4], [0u8; 4], Vec::new());
            let mut i = 240;
            while i + 1 < p.len() && p[i] != 255 {
                if p[i] == 0 {
                    i += 1;
                    continue;
                }
                let (code, len) = (p[i], p[i + 1] as usize);
                let Some(v) = p.get(i + 2..i + 2 + len) else { break };
                match code {
                    53 if len == 1 => kind = v[0],
                    1 if len == 4 => mask = v.try_into().expect("4"),
                    3 if len >= 4 => router = v[..4].try_into().expect("4"),
                    54 if len == 4 => server = v.try_into().expect("4"),
                    6 => dns = v.chunks_exact(4).map(|c| c.try_into().expect("4")).collect(),
                    _ => {}
                }
                i += 2 + len;
            }
            match (&self.state, kind) {
                (DhcpState::Discovering, 2) => {
                    self.state = DhcpState::Requesting { offered: yiaddr, server };
                    self.attempt = 0;
                    self.send()?;
                }
                (DhcpState::Requesting { .. }, 5) => {
                    let lease = Lease { ip: yiaddr, prefix: u32::from_be_bytes(mask).count_ones() as u8, gateway: router, dns };
                    let mut nl = Netlink::open(libc::NETLINK_ROUTE)?;
                    netlink::add_address(&mut nl, self.index, lease.ip, lease.prefix)?;
                    netlink::add_default_route(&mut nl, self.index, lease.gateway)?;
                    *UPLINK_SUBNET.lock().unwrap_or_else(|e| e.into_inner()) = Some((netlink::mask_ipv4(lease.ip, lease.prefix), lease.prefix));
                    let _ = refresh_nat();
                    self.state = DhcpState::Bound;
                    self.lease = Some(lease);
                    return Ok(true);
                }
                (DhcpState::Requesting { .. }, 6) => {
                    // NAK: start over.
                    self.state = DhcpState::Discovering;
                    self.attempt = 0;
                    self.send()?;
                }
                _ => {}
            }
        }
    }
}

fn valid_uplink(ip: [u8; 4], prefix: u8, gateway: [u8; 4]) -> bool {
    if !(1..=30).contains(&prefix) || ip == [0; 4] || gateway == [0; 4] || ip == gateway {
        return false;
    }
    if ip[0] == 127 || gateway[0] == 127 || ip[0] >= 224 || gateway[0] >= 224 {
        return false;
    }
    let mask = u32::MAX << (32 - u32::from(prefix));
    let (ip_u, gw_u) = (u32::from_be_bytes(ip), u32::from_be_bytes(gateway));
    (ip_u & mask) == (gw_u & mask) && (ip_u & !mask) != 0 && (ip_u & !mask) != !mask && (gw_u & !mask) != 0 && (gw_u & !mask) != !mask
}

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    let _ = std::fs::File::open("/dev/urandom").and_then(|mut f| std::io::Read::read_exact(&mut f, &mut b));
    u32::from_ne_bytes(b) | 1
}

fn sockaddr(ip: [u8; 4], port: u16) -> libc::sockaddr_in {
    // SAFETY: sockaddr_in is plain data; all-zero is valid.
    let mut a: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    a.sin_family = libc::AF_INET as libc::sa_family_t;
    a.sin_port = port.to_be();
    a.sin_addr.s_addr = u32::from_ne_bytes(ip);
    a
}

fn mac_of(name: &str) -> io::Result<[u8; 6]> {
    // SAFETY: plain socket + SIOCGIFHWADDR on a zeroed ifreq.
    unsafe {
        let fd = sys::check(libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) as _, "socket")?;
        let sock = OwnedFd::from_raw_fd(fd as i32);
        let mut req: libc::ifreq = std::mem::zeroed();
        for (d, s) in req.ifr_name.iter_mut().zip(name.bytes()) {
            *d = s as libc::c_char;
        }
        sys::check(libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFHWADDR as libc::Ioctl, &mut req) as _, "hwaddr")?;
        let mut mac = [0u8; 6];
        for (d, s) in mac.iter_mut().zip(req.ifr_ifru.ifru_hwaddr.sa_data.iter()) {
            *d = *s as u8;
        }
        Ok(mac)
    }
}

/// The IPv6 gateway and prefix a bridge has, if its network has IPv6.
type Bridge6 = Option<([u8; 16], u8)>;

/// Bridges that exist so far: name → (index, gateway (none when
/// IPv6-only), prefix, IPv6), plus a persistent host `NETLINK_ROUTE` socket.
#[derive(Default)]
pub struct Bridges {
    made: HashMap<String, (i32, Option<[u8; 4]>, u8, Bridge6)>,
    route: Option<Netlink>,
}

/// What `Bridges::ensure` needs to do for a bridge given its cached state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BridgePlan {
    /// Already up with everything asked for.
    Reuse(i32),
    /// Already up with the same IPv4 gateway/prefix; add IPv6 in place so
    /// existing sockets and containers on the bridge are not disrupted.
    AddV6(i32),
    /// A different subnet took the bridge name: tear down and recreate.
    Recreate,
    /// Not created yet.
    Create,
}

impl Bridges {
    fn route_nl(&mut self) -> io::Result<&mut Netlink> {
        if self.route.is_none() {
            self.route = Some(Netlink::open(libc::NETLINK_ROUTE)?);
        }
        Ok(self.route.as_mut().expect("opened above"))
    }

    /// Whether `name` currently exists with an IPv6 subnet configured.
    pub fn has_ipv6(&self, name: &str) -> bool {
        matches!(self.made.get(name), Some((.., Some(_))))
    }

    fn plan(&self, name: &str, gateway: Option<[u8; 4]>, prefix: u8, want6: Bridge6) -> BridgePlan {
        match self.made.get(name) {
            Some(&(i, g, p, b6)) if (g, p) == (gateway, prefix) => match (b6, want6) {
                (None, None) => BridgePlan::Reuse(i),
                (None, Some(_)) => BridgePlan::AddV6(i),
                // Already has IPv6 (e.g. a later container with IPv6 disabled,
                // or a host-network caller that only needs IPv4): keep it.
                (Some(_), None) => BridgePlan::Reuse(i),
                (Some(a), Some(b)) if a == b => BridgePlan::Reuse(i),
                (Some(_), Some(_)) => BridgePlan::Recreate,
            },
            Some(_) => BridgePlan::Recreate,
            None => BridgePlan::Create,
        }
    }

    /// Creates the bridge (once) with its gateway address (and IPv6 one)
    /// and brings it up, with its rules in Kiri's tables. All or nothing: on
    /// an error the bridge is gone again and not recorded, so the next
    /// container tries afresh rather than starting with half the rules.
    pub fn ensure(&mut self, name: &str, gateway: Option<[u8; 4]>, prefix: u8, v6: Option<Ip6>) -> io::Result<i32> {
        let want6 = v6.map(|v| (v.gateway, v.prefix));
        match self.plan(name, gateway, prefix, want6) {
            BridgePlan::Reuse(i) => return Ok(i),
            BridgePlan::AddV6(i) => return self.add_v6(name, i, gateway, prefix, v6.expect("AddV6 requires v6")),
            // The network was removed and its bridge name reused for one
            // with another subnet: start the bridge afresh.
            BridgePlan::Recreate => self.remove(name),
            BridgePlan::Create => {}
        }
        let mut created = false;
        let r = self.bring_up(name, gateway, prefix, v6, &mut created);
        if r.is_err() {
            if created && let Ok(mut nl) = Netlink::open(libc::NETLINK_ROUTE) {
                let _ = netlink::delete_link(&mut nl, name);
            }
            MADE_BRIDGES.lock().unwrap_or_else(|e| e.into_inner()).retain(|m| m != name);
            BRIDGE_SUBNETS.lock().unwrap_or_else(|e| e.into_inner()).retain(|(m, ..)| m != name);
            let had6 = matches!(self.made.remove(name), Some((.., Some(_))));
            let _ = refresh_nat();
            if had6 {
                let _ = self.update_v6(None);
            }
        }
        r
    }

    fn add_v6(&mut self, name: &str, index: i32, gateway: Option<[u8; 4]>, prefix: u8, v: Ip6) -> io::Result<i32> {
        let mut nl = Netlink::open(libc::NETLINK_ROUTE)?;
        netlink::add_address6(&mut nl, index, v.gateway, v.prefix)?;
        self.made.insert(name.to_owned(), (index, gateway, prefix, Some((v.gateway, v.prefix))));
        if let Err(e) = self.update_v6(Some(v)) {
            self.made.insert(name.to_owned(), (index, gateway, prefix, None));
            return Err(e);
        }
        Ok(index)
    }

    fn bring_up(&mut self, name: &str, gateway: Option<[u8; 4]>, prefix: u8, v6: Option<Ip6>, created: &mut bool) -> io::Result<i32> {
        let mut nl = Netlink::open(libc::NETLINK_ROUTE)?;
        *created = netlink::create_bridge(&mut nl, name)?;
        let mut made = MADE_BRIDGES.lock().unwrap_or_else(|e| e.into_inner());
        if !made.iter().any(|m| m == name) {
            made.push(name.to_owned());
        }
        drop(made);
        {
            let mut subs = BRIDGE_SUBNETS.lock().unwrap_or_else(|e| e.into_inner());
            subs.retain(|(m, ..)| m != name);
            if let Some(g) = gateway {
                subs.push((name.to_owned(), netlink::mask_ipv4(g, prefix), prefix));
            }
        }
        let index = netlink::index_of(name)?;
        if let Some(g) = gateway {
            netlink::add_address(&mut nl, index, g, prefix)?;
        }
        if let Some(v) = v6 {
            netlink::add_address6(&mut nl, index, v.gateway, v.prefix)?;
        }
        netlink::set_up(&mut nl, index)?;
        if super::transport::is_host_process() {
            // Published ports on a Linux host are relayed on loopback, never
            // DNATed from 127.0.0.1, so the bridge needs no `route_localnet`;
            // an older engine set it on bridges that may still exist.
            let _ = sys::write_file(&format!("/proc/sys/net/ipv4/conf/{name}/route_localnet"), "0");
            let _ = update_foreign_bridges();
            // A firewall started after the engine, in iptables-legacy
            // (which makes no nf_tables event) too.
            through_firewall(firewall::Why::Bridge);
        }
        // The forward filter's rule for this bridge.
        refresh_nat()?;
        self.made.insert(name.to_owned(), (index, gateway, prefix, v6.map(|v| (v.gateway, v.prefix))));
        if let Some(v) = v6 {
            self.update_v6(Some(v))?;
        }
        Ok(index)
    }

    /// A removed network's bridge: deleting it takes its addresses and
    /// routes along; the IPv6 NAT rule for it goes too.
    pub fn remove(&mut self, name: &str) {
        if let Ok(mut nl) = Netlink::open(libc::NETLINK_ROUTE) {
            let _ = netlink::delete_link(&mut nl, name);
        }
        MADE_BRIDGES.lock().unwrap_or_else(|e| e.into_inner()).retain(|m| m != name);
        BRIDGE_SUBNETS.lock().unwrap_or_else(|e| e.into_inner()).retain(|(m, ..)| m != name);
        if let Err(e) = refresh_nat() {
            eprintln!("kiri-init: NAT: {e}");
        }
        if let Some((.., Some(_))) = self.made.remove(name) {
            if let Err(e) = self.update_v6(None) {
                eprintln!("kiri-init: IPv6 NAT: {e}");
            }
        }
    }

    /// Brings the IPv6 table in line with the IPv6 bridges: forwarding on
    /// with the first, the table rebuilt for each, and both undone with
    /// the last, so an engine without IPv6 networks has none of it.
    fn update_v6(&mut self, added: Option<Ip6>) -> io::Result<()> {
        let mut subnets: Vec<([u8; 16], u8)> = Vec::new();
        let mut names: Vec<String> = Vec::new();
        for (name, (.., b6)) in &self.made {
            if let Some((g, p)) = *b6 {
                subnets.push((Ip6 { ip: g, prefix: p, gateway: g }.subnet(), p));
                names.push(name.clone());
            }
        }
        if added.is_some() {
            ipv6_forwarding(true)?;
        }
        let r = refresh_nat6(&subnets, &names);
        if r.is_ok() {
            *NAT6.lock().unwrap_or_else(|e| e.into_inner()) = (subnets.clone(), names.clone());
        }
        if subnets.is_empty() {
            let _ = ipv6_forwarding(false);
        }
        r
    }
}

/// What `ipv6_forwarding` changed, to put back: the old `all.forwarding`
/// and the interfaces whose `accept_ra` went from 1 to 2.
static V6_SAVED: std::sync::Mutex<Option<(String, Vec<String>)>> = std::sync::Mutex::new(None);

/// Turns IPv6 forwarding on (once) or back to how it was. A router ignores
/// router advertisements unless `accept_ra` is 2, so interfaces that took
/// them (the VM's uplink, a Linux host's own) are set to 2 first and keep
/// their IPv6 addresses and default route.
fn ipv6_forwarding(on: bool) -> io::Result<()> {
    let mut saved = V6_SAVED.lock().unwrap_or_else(|e| e.into_inner());
    let conf = "/proc/sys/net/ipv6/conf";
    if on {
        if saved.is_some() {
            return Ok(());
        }
        let old = std::fs::read_to_string(format!("{conf}/all/forwarding")).unwrap_or_default().trim().to_owned();
        if old == "1" {
            *saved = Some((old, Vec::new()));
            return Ok(());
        }
        let mut raised = Vec::new();
        for entry in std::fs::read_dir(conf)?.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if matches!(name.as_str(), "all" | "default" | "lo") || name.starts_with("kiri") || name.starts_with("kv") {
                continue;
            }
            let path = format!("{conf}/{name}/accept_ra");
            if std::fs::read_to_string(&path).is_ok_and(|v| v.trim() == "1") && sys::write_file(&path, "2").is_ok() {
                raised.push(name);
            }
        }
        sys::write_file(&format!("{conf}/all/forwarding"), "1")?;
        *saved = Some((old, raised));
    } else if let Some((old, raised)) = saved.take() {
        if old != "1" {
            let _ = sys::write_file(&format!("{conf}/all/forwarding"), if old.is_empty() { "0" } else { &old });
        }
        for name in raised {
            let _ = sys::write_file(&format!("{conf}/{name}/accept_ra"), "1");
        }
    }
    Ok(())
}

/// Every bridge this agent brought up, for `remove_bridges`.
static MADE_BRIDGES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Linux host, stopping: removes the bridges this agent brought up (only
/// those: another engine's may share the network namespace) and Kiri's
/// nftables table, so nothing of the engine is left in the host's network.
pub fn remove_host_network() {
    if !HOST_NETNS_CLAIMED.load(std::sync::atomic::Ordering::Acquire) {
        return;
    }
    let names = std::mem::take(&mut *MADE_BRIDGES.lock().unwrap_or_else(|e| e.into_inner()));
    BRIDGE_SUBNETS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    EGRESS_ROUTES.lock().unwrap_or_else(|e| e.into_inner()).clear();
    if let Ok(mut nl) = Netlink::open(libc::NETLINK_ROUTE) {
        for name in names {
            let _ = netlink::delete_link(&mut nl, &name);
        }
    }
    if let Err(e) = netlink::remove_nat() {
        eprintln!("kiri-init: removing the nftables table: {e}");
    }
    let _ = netlink::install_nat6(&[], &[], HOST_RELAY_PORT, false, &[]);
    let _ = ipv6_forwarding(false);
    through_firewall(firewall::Why::Stop);
}

/// Gives a freshly cloned container its network: a veth pair whose peer
/// appears inside the container's namespace as eth0 with `ip`, a default
/// route through the bridge, and loopback up.
#[allow(clippy::too_many_arguments)]
pub fn attach_container(
    bridges: &mut Bridges,
    bridge: &str,
    host_ifname: &str,
    pid: libc::pid_t,
    netns: Option<&std::fs::File>,
    ip: [u8; 4],
    prefix: u8,
    gateway: [u8; 4],
    mac: Option<[u8; 6]>,
    v6: Option<Ip6>,
    plug: Plug,
) -> io::Result<()> {
    attach_with_ns(bridges, bridge, host_ifname, pid, netns, 0, ip, prefix, gateway, mac, v6, plug)
}

/// Plugs the container into `bridge` as `eth{n}`. The first non-internal
/// network with IPv4 gives the IPv4 default route, even when it is not
/// `eth0` (an internal network first, an outside one second); later ones
/// keep it, and only add their subnets. The same goes for IPv6. An
/// `internal` network never gives a default route, so traffic beyond it
/// fails at once (unreachable), as with Docker. `hand_over_default_routes`
/// moves a route on when its network is disconnected. On a network without IPv6 the
/// interface has IPv6 off (no link-local address), as Docker does. On an
/// IPv6-only network `ip` is only the name the container is kept by (its
/// MAC is made from it): neither the interface nor the bridge gets it.
#[allow(clippy::too_many_arguments)]
pub fn attach(bridges: &mut Bridges, bridge: &str, host_ifname: &str, pid: libc::pid_t, n: u32, ip: [u8; 4], prefix: u8, gateway: [u8; 4], mac: Option<[u8; 6]>, v6: Option<Ip6>, plug: Plug) -> io::Result<()> {
    attach_with_ns(bridges, bridge, host_ifname, pid, None, n, ip, prefix, gateway, mac, v6, plug)
}

#[allow(clippy::too_many_arguments)]
fn attach_with_ns(
    bridges: &mut Bridges,
    bridge: &str,
    host_ifname: &str,
    pid: libc::pid_t,
    netns_fd: Option<&std::fs::File>,
    n: u32,
    ip: [u8; 4],
    prefix: u8,
    gateway: [u8; 4],
    mac: Option<[u8; 6]>,
    v6: Option<Ip6>,
    plug: Plug,
) -> io::Result<()> {
    let Plug { internal, no_ipv4 } = plug;
    let mac = Some(mac.unwrap_or_else(|| mac_for(ip)));
    let bridge_index = bridges.ensure(bridge, (!no_ipv4).then_some(gateway), prefix, v6)?;
    let opened_ns;
    let netns = match netns_fd {
        Some(f) => f,
        None => {
            opened_ns = std::fs::File::open(format!("/proc/{pid}/ns/net"))?;
            &opened_ns
        }
    };
    let ifname = format!("eth{n}");
    {
        let host = bridges.route_nl()?;
        // A stopped container's veth may still hold this address and MAC.
        delete_retired(host);
        netlink::create_veth(host, host_ifname, bridge_index, netns, CONTAINER_MTU, &ifname, mac)?;
    }
    // Enter the container's network namespace once to resolve the peer index,
    // disable IPv6 link-local when IPv6 is off, and open the inner route socket.
    let (index, mut inner) = netlink::in_netns(netns, || {
        let idx = netlink::index_of(&ifname)?;
        if v6.is_none() {
            let _ = sys::write_file(&format!("/proc/sys/net/ipv6/conf/{ifname}/disable_ipv6"), "1");
        }
        let nl = Netlink::open(libc::NETLINK_ROUTE)?;
        Ok((idx, nl))
    })?;
    if n == 0 {
        let mut batch = Vec::with_capacity(4);
        batch.push(netlink::set_up_msg(1)); // lo
        if !no_ipv4 {
            batch.push(netlink::add_address_msg(index, ip, prefix));
        }
        if let Some(v) = v6 {
            batch.push(netlink::add_address6_msg(index, v.ip, v.prefix));
        }
        batch.push(netlink::set_up_msg(index));
        inner.request(&mut batch)?;
    } else {
        netlink::set_up(&mut inner, 1)?; // lo
        if !no_ipv4 {
            netlink::add_address(&mut inner, index, ip, prefix)?;
        }
        if let Some(v) = v6 {
            netlink::add_address6(&mut inner, index, v.ip, v.prefix)?;
        }
        netlink::set_up(&mut inner, index)?;
    }
    if !internal && !no_ipv4 {
        netlink::add_default_route(&mut inner, index, gateway)?;
    }
    if let Some(v) = v6.filter(|_| !internal) {
        netlink::add_default_route6(&mut inner, index, v.gateway)?;
    }
    Ok(())
}

/// Host-side veths of stopped containers, deleted by the next `attach`.
static RETIRED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
static HAS_RETIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Notes a stopped container's host-side veths for the next `attach` to
/// delete. Deleting one waits out RCU, 15-40 ms that every request after
/// the exit would queue behind on the agent's loop; and the agent stays
/// single-threaded, as clone3 without CLONE_VM needs. Left to the kernel
/// they went only as the namespace did, a second or more later: by then the
/// next container had the same address and MAC, the bridge sent its replies
/// to the old namespace, and that answered with resets (a download that
/// broke mid-TLS or stalled).
pub fn retire(veths: &[String]) {
    if veths.is_empty() {
        return;
    }
    RETIRED.lock().unwrap_or_else(|e| e.into_inner()).extend_from_slice(veths);
    HAS_RETIRED.store(true, std::sync::atomic::Ordering::Release);
}

/// Deletes the veths `retire` noted. Gone already (the kernel took them
/// with their namespace) is fine.
fn delete_retired(nl: &mut Netlink) {
    if !HAS_RETIRED.swap(false, std::sync::atomic::Ordering::AcqRel) {
        return;
    }
    for v in std::mem::take(&mut *RETIRED.lock().unwrap_or_else(|e| e.into_inner())) {
        let _ = netlink::delete_link(nl, &v);
    }
}

/// Unplugs a container's extra network by its host-side veth.
pub fn detach(host_ifname: &str) -> io::Result<()> {
    let mut host = Netlink::open(libc::NETLINK_ROUTE)?;
    netlink::delete_link(&mut host, host_ifname)
}

/// The LISTEN lines of a process's network namespace, IPv4 and IPv6, as the
/// kernel writes them; the host reads the ports out. Read from /proc, so the
/// container needs no tools of its own. Only listeners are kept: a busy
/// server's connections would not fit in a frame.
pub fn listening(pid: libc::pid_t) -> Vec<String> {
    let mut out = Vec::new();
    for file in ["tcp", "tcp6"] {
        let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/net/{file}")) else { continue };
        // The fourth field is the state; 0A is TCP_LISTEN.
        out.extend(text.lines().filter(|l| l.split_whitespace().nth(3) == Some("0A")).take(512).map(str::to_owned));
    }
    out
}

/// Routes `dst/prefix` through `via` in the VM, or removes that route: how
/// the host's relay reaches a Kubernetes node's pods and services.
pub fn route(dst: [u8; 4], prefix: u8, via: [u8; 4], add: bool) -> io::Result<()> {
    let mut host = Netlink::open(libc::NETLINK_ROUTE)?;
    netlink::set_route(&mut host, dst, prefix, via, add)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_settings_come_from_the_options() {
        let mut buf = Vec::new();
        kiri_proto::encode_net_attach(&mut buf, "c1", "eth1", "kiri2", [10, 5, 0, 2], 24, [10, 5, 0, 1], &["web"], &["ip6=fd00:1::2/64", "gw6=fd00:1::1"]);
        let Ok(kiri_proto::Msg::NetAttach { net, .. }) = kiri_proto::decode(&buf) else { panic!() };
        let v = Ip6::from_opts(net.opts).unwrap();
        assert_eq!(ip6_str(v.ip), "fd00:1::2");
        assert_eq!(ip6_str(v.gateway), "fd00:1::1");
        assert_eq!(v.prefix, 64);
        assert_eq!(ip6_str(v.subnet()), "fd00:1::");
        let mut buf = Vec::new();
        kiri_proto::encode_net_attach::<&str>(&mut buf, "c1", "eth1", "kiri2", [10, 5, 0, 2], 24, [10, 5, 0, 1], &[], &[]);
        let Ok(kiri_proto::Msg::NetAttach { net, .. }) = kiri_proto::decode(&buf) else { panic!() };
        assert_eq!(Ip6::from_opts(net.opts), None);
    }

    #[test]
    fn collect_foreign_bridges_skips_kiri_non_bridges_and_default_route_bridges() {
        let dir = std::env::temp_dir().join(format!("kiri-net-foreign-bridges-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for dev in ["kiri0", "kiri1", "docker0", "br-1234", "virbr0", "vmbr0"] {
            std::fs::create_dir_all(dir.join(dev).join("bridge")).unwrap();
        }
        for dev in ["eth0", "tailscale0", "wg0", "lo"] {
            std::fs::create_dir_all(dir.join(dev)).unwrap();
        }
        let defaults = vec!["eth0".to_owned(), "tailscale0".to_owned(), "vmbr0".to_owned()];
        assert_eq!(collect_foreign_bridges(&dir, &defaults), vec!["br-1234", "docker0", "virbr0"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn raise_sysctl_min_raises_only_below_threshold() {
        let path = std::env::temp_dir().join(format!("kiri-net-sysctl-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        raise_sysctl_min(&path, 262_144);
        assert!(!path.exists());
        std::fs::write(&path, "65536\n").unwrap();
        raise_sysctl_min(&path, 262_144);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "262144");
        std::fs::write(&path, "524288\n").unwrap();
        raise_sysctl_min(&path, 262_144);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "524288\n");
        let _ = std::fs::remove_file(&path);
    }

    fn up(veth: &str, v4: bool, v6: bool) -> Uplink {
        Uplink { veth: veth.into(), ifname: veth.into(), v4: v4.then_some([10, 0, 0, 1]), v6: v6.then_some([0xfd; 16]) }
    }

    #[test]
    fn internal_networks_are_no_uplink() {
        let v6 = Some(Ip6 { ip: [0xfd; 16], prefix: 64, gateway: [0xfd; 16] });
        assert_eq!(Uplink::of("kv1", "eth0", [10, 0, 0, 1], v6, Plug { internal: true, no_ipv4: false }), None);
        let u = Uplink::of("kv1", "eth1", [10, 0, 0, 1], None, Plug::default()).unwrap();
        assert_eq!((u.ifname.as_str(), u.v4, u.v6), ("eth1", Some([10, 0, 0, 1]), None));
        let u = Uplink::of("kv1", "eth1", [10, 0, 0, 1], v6, Plug { internal: false, no_ipv4: true }).unwrap();
        assert_eq!((u.v4, u.v6), (None, Some([0xfd; 16])));
    }

    #[test]
    fn the_first_uplink_with_each_family_holds_its_default_route() {
        let ups = [up("a", false, true), up("b", true, false), up("c", true, true)];
        let (r4, r6) = route_holders(&ups);
        assert_eq!((r4.map(|u| u.veth.as_str()), r6.map(|u| u.veth.as_str())), (Some("b"), Some("a")));
        assert_eq!(route_holders(&[]), (None, None));
    }

    #[test]
    fn leaving_first_of_three_networks_promotes_first_attached_external_gateway_and_ifname() {
        let gw_a = [10, 98, 0, 1];
        let gw_zeta = [10, 98, 1, 1];
        let gw_beta = [10, 98, 2, 1];
        let mut ups = Vec::new();
        ups.extend(Uplink::of("kva0", "eth0", gw_a, None, Plug::default()));
        // An internal network attached in between produces no uplink.
        ups.extend(Uplink::of("kxi1", "eth1", [10, 98, 9, 1], None, Plug { internal: true, no_ipv4: false }));
        ups.extend(Uplink::of("kxz2", "eth2", gw_zeta, None, Plug::default()));
        ups.extend(Uplink::of("kxb3", "eth3", gw_beta, None, Plug::default()));

        let (r4, _) = route_holders(&ups);
        assert_eq!(r4.map(|u| (u.ifname.as_str(), u.v4)), Some(("eth0", Some(gw_a))));

        // Disconnecting `a` promotes `zeta` on eth2 (first-plugged external), not `beta` on eth3.
        ups.retain(|u| u.veth != "kva0");
        let (r4, _) = route_holders(&ups);
        assert_eq!(r4.map(|u| (u.ifname.as_str(), u.v4)), Some(("eth2", Some(gw_zeta))));

        // Disconnecting `zeta` promotes `beta` on eth3.
        ups.retain(|u| u.veth != "kxz2");
        let (r4, _) = route_holders(&ups);
        assert_eq!(r4.map(|u| (u.ifname.as_str(), u.v4)), Some(("eth3", Some(gw_beta))));
    }

    #[test]
    fn a_disconnect_that_takes_no_default_route_touches_nothing() {
        // The pid is never used: nothing to hand over, so no namespace is opened.
        let mut ups = vec![up("a", true, true), up("b", true, true)];
        hand_over_default_routes(-1, &mut ups, "b").unwrap();
        assert_eq!(ups, [up("a", true, true)]);
        hand_over_default_routes(-1, &mut ups, "a").unwrap();
        assert!(ups.is_empty());
    }

    #[test]
    fn bridge_ipv4_reads_an_interfaces_address() {
        assert_eq!(bridge_ipv4("lo"), Some([127, 0, 0, 1]));
        assert_eq!(bridge_ipv4("kiri-no-such-if"), None);
    }

    #[test]
    fn bridges_ensure_is_idempotent_and_adds_ipv6_in_place() {
        let gw4 = [172, 17, 0, 1];
        let gw6 = [0xfd, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        let other6 = [0xfd, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1];
        let v6 = Ip6 { ip: gw6, prefix: 64, gateway: gw6 };

        let mut bridges = Bridges::default();
        assert_eq!(bridges.plan("kiri0", Some(gw4), 16, None), BridgePlan::Create);

        // Once kiri0 is brought up IPv4-only (e.g. by host-network DNS on a fresh VM),
        // a repeat ensure reuses it without touching netlink, and a later IPv6 attach
        // upgrades it in place rather than tearing it down.
        bridges.made.insert("kiri0".into(), (42, Some(gw4), 16, None));
        assert_eq!(bridges.ensure("kiri0", Some(gw4), 16, None).unwrap(), 42);
        assert_eq!(bridges.plan("kiri0", Some(gw4), 16, Some((gw6, 64))), BridgePlan::AddV6(42));
        assert_eq!(bridges.plan("kiri0", Some([172, 18, 0, 1]), 16, None), BridgePlan::Recreate);
        assert_eq!(bridges.plan("kiri0", Some(gw4), 24, None), BridgePlan::Recreate);
        assert_eq!(bridges.plan("kiri0", None, 16, Some((gw6, 64))), BridgePlan::Recreate);

        // Once IPv6 is configured on kiri0, both matching IPv6 callers and IPv4-only
        // callers reuse the existing bridge; a different IPv6 subnet recreates it.
        bridges.made.insert("kiri0".into(), (42, Some(gw4), 16, Some((gw6, 64))));
        assert_eq!(bridges.ensure("kiri0", Some(gw4), 16, Some(v6)).unwrap(), 42);
        assert_eq!(bridges.ensure("kiri0", Some(gw4), 16, None).unwrap(), 42);
        assert_eq!(bridges.plan("kiri0", Some(gw4), 16, Some((other6, 64))), BridgePlan::Recreate);
    }

    fn test_dhcp() -> Dhcp {
        let (r, _w) = sys::pipe().unwrap();
        Dhcp { sock: r, index: 2, mac: [2, 0, 0, 0, 0, 1], xid: 1, state: DhcpState::Discovering, next_send: Instant::now() + Duration::from_secs(1), attempt: 1, lease: None }
    }

    #[test]
    fn set_uplink_applies_skips_when_leased_and_validates() {
        let mut dhcp = test_dhcp();
        for (ip, prefix, gw) in [
            ([0; 4], 24, [192, 168, 64, 1]),
            ([192, 168, 64, 2], 0, [192, 168, 64, 1]),
            ([192, 168, 64, 2], 31, [192, 168, 64, 1]),
            ([192, 168, 64, 2], 32, [192, 168, 64, 1]),
            ([192, 168, 64, 2], 33, [192, 168, 64, 1]),
            ([127, 0, 0, 2], 8, [127, 0, 0, 1]),
            ([224, 0, 0, 2], 24, [224, 0, 0, 1]),
            ([240, 0, 0, 2], 24, [240, 0, 0, 1]),
            ([192, 168, 64, 1], 24, [192, 168, 64, 1]),
            ([192, 168, 64, 255], 24, [192, 168, 64, 1]),
            ([192, 168, 64, 0], 24, [192, 168, 64, 1]),
            ([192, 168, 65, 2], 24, [192, 168, 64, 1]),
        ] {
            assert!(dhcp.apply_static_with(ip, prefix, gw, [0; 4], |_| panic!("must not configure")).is_err());
        }
        assert!(dhcp.apply_static_with([192, 168, 64, 2], 24, [192, 168, 64, 1], [192, 168, 64, 1], |_| Ok(())).unwrap());
        assert_eq!(dhcp.timeout_ms(), -1);
        let l = dhcp.lease.as_ref().unwrap();
        assert_eq!((l.ip, l.prefix, l.gateway, l.dns.as_slice()), ([192, 168, 64, 2], 24, [192, 168, 64, 1], &[[192, 168, 64, 1]][..]));
        // No-op when a lease (from DHCP or SetUplink) is already active.
        assert!(!dhcp.apply_static_with([192, 168, 64, 9], 24, [192, 168, 64, 1], [0; 4], |_| panic!("must not reconfigure")).unwrap());
        assert_eq!(dhcp.lease.as_ref().unwrap().ip, [192, 168, 64, 2]);
    }

    #[test]
    fn effective_host_addr_uses_wsl_host_addr_only_when_wsl_relay_active() {
        assert_eq!(effective_host_addr_for(false, false), HOST_ADDR);
        assert_eq!(effective_host_addr_for(false, true), HOST_ADDR);
        assert_eq!(effective_host_addr_for(true, false), HOST_ADDR);
        assert_eq!(effective_host_addr_for(true, true), WSL_HOST_ADDR);
        assert!(is_hostrelay_cmdline(b"/usr/local/bin/kiri\0hostrelay\0"));
        assert!(!is_hostrelay_cmdline(b"/usr/local/bin/kiri\0daemon\0"));
        assert!(!is_hostrelay_cmdline(b""));
        let pid_path = std::env::temp_dir().join(format!("kiri-net-hostrelay-{}.pid", std::process::id()));
        let _ = std::fs::remove_file(&pid_path);
        assert!(!pid_file_alive(&pid_path, |_| true));
        std::fs::write(&pid_path, format!("{}\n", std::process::id())).unwrap();
        assert!(pid_file_alive(&pid_path, |_| true));
        assert!(!pid_file_alive(&pid_path, |_| false));
        let _ = std::fs::remove_file(&pid_path);
    }

    #[test]
    fn abstract_netns_lock_rejects_second_holder_across_full_retry_loop() {
        use std::sync::atomic::AtomicBool;
        use std::sync::OnceLock;
        let name = format!("kiri-netns-test-{}", std::process::id());
        let slot1 = OnceLock::new();
        let claimed1 = AtomicBool::new(false);
        claim_host_netns_on(name.as_bytes(), &slot1, &claimed1).expect("first holder claims abstract netns lock");

        // Run 8 full 500ms `claim_host_netns_on` retry loops (> 160 probes,
        // exceeding `listen(128)` when drained between ticks as `agent::serve_loop`
        // does) to verify `drain_netns_lock` prevents `EAGAIN` false negatives.
        for _ in 0..8 {
            let slot2 = OnceLock::new();
            let claimed2 = AtomicBool::new(false);
            let err = claim_host_netns_on(name.as_bytes(), &slot2, &claimed2)
                .expect_err("second holder in same netns must fail after full retry window");
            assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
            assert!(!claimed2.load(std::sync::atomic::Ordering::Acquire));
            drain_netns_lock(slot1.get().unwrap().as_raw_fd());
        }

        let me = unsafe { libc::geteuid() };
        assert_eq!(probe_abstract_lock(name.as_bytes(), me), LockProbe::OwnedByOwner);
        assert_eq!(probe_abstract_lock(name.as_bytes(), me.wrapping_add(1)), LockProbe::OwnedByOther);

        drop(slot1);
        // Unbound socket returns TransientBusy (`ECONNREFUSED`), never OwnedByOther.
        assert_eq!(probe_abstract_lock(name.as_bytes(), me), LockProbe::TransientBusy);
        let rebound = try_bind_abstract_socket(name.as_bytes()).expect("rebind succeeds once first fd closes");
        drop(rebound);
    }

    #[test]
    fn rps_cpu_mask_formats_single_and_multi_word_cpumasks() {
        let seq = |n: usize| (0..n).collect::<Vec<_>>();
        assert_eq!(format_rps_cpu_mask(&[]), None);
        assert_eq!(format_rps_cpu_mask(&[0]), None);
        assert_eq!(format_rps_cpu_mask(&seq(2)).as_deref(), Some("3"));
        assert_eq!(format_rps_cpu_mask(&seq(3)).as_deref(), Some("7"));
        assert_eq!(format_rps_cpu_mask(&seq(4)).as_deref(), Some("e"));
        assert_eq!(format_rps_cpu_mask(&seq(8)).as_deref(), Some("fe"));
        assert_eq!(format_rps_cpu_mask(&[0, 2, 4, 6]).as_deref(), Some("54"));
        assert_eq!(format_rps_cpu_mask(&seq(32)).as_deref(), Some("fffffffe"));
        assert_eq!(format_rps_cpu_mask(&seq(33)).as_deref(), Some("1,fffffffe"));
        assert_eq!(format_rps_cpu_mask(&seq(64)).as_deref(), Some("ffffffff,fffffffe"));
    }
}
