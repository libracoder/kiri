//! Settings → Network → Container addresses: the pool new networks take
//! their subnets from (`~/.kiri/addresses.json`), 172.16.0.0/12 unless
//! changed. People change it when their office network or VPN uses the same
//! range and containers can't reach it.
//!
//! With the default, networks are given what Docker would give them
//! (network.rs `free_subnet`). With a pool of their own, each new network
//! gets a /16 from it when the pool is a /15 or larger, else a /24, and the
//! default bridge takes the first block. Networks that already exist keep
//! their addresses; the default bridge, which is picked when the engine
//! starts, moves into the pool at the next start (nothing runs on it then),
//! or stays on Docker's if the pool has no room.
//!
//! The window checks a pool against this computer's own networks and VPNs,
//! which come from here too: the interfaces' IPv4 networks on a Mac or a
//! Linux host, and Windows' as kiri-win sends them when the engine runs in
//! WSL2. New networks skip those as well as the routes a Linux host has.

use std::path::PathBuf;
use std::sync::Mutex;

use serde_json::{Value, json};

use super::network::{ip_str, parse_ip};

/// Docker's default address pools start here: 172.17–31 and Kiri's 10.89.
pub const DEFAULT: ([u8; 4], u8) = ([172, 16, 0, 0], 12);

/// The private ranges a pool must sit in (RFC 1918).
const PRIVATE: [([u8; 4], u8); 3] = [([10, 0, 0, 0], 8), ([172, 16, 0, 0], 12), ([192, 168, 0, 0], 16)];

pub fn cidr(p: ([u8; 4], u8)) -> String {
    format!("{}/{}", ip_str(p.0), p.1)
}

/// `10.200.0.0/16`: a range from /8 to /24 inside a private one. The base
/// is taken to the range's start, as the window shows it.
pub fn parse(s: &str) -> Result<([u8; 4], u8), String> {
    let bad = || format!("not a range Kiri can use: {s}. Write it like 10.200.0.0/16 (from /8 to /24)");
    let (ip, bits) = s.trim().split_once('/').ok_or_else(bad)?;
    let ip = parse_ip(ip).filter(|_| ip.split('.').count() == 4).ok_or_else(bad)?;
    let bits: u8 = bits.parse().ok().filter(|b| (8..=24).contains(b)).ok_or_else(bad)?;
    let base = (u32::from_be_bytes(ip) & (u32::MAX << (32 - bits))).to_be_bytes();
    if !PRIVATE.iter().any(|r| bits >= r.1 && super::network::in_subnet(base, r.0, r.1)) {
        return Err(format!("{s} is not a private range: use one inside 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16"));
    }
    Ok((base, bits))
}

/// Each network's size in `pool`: a /16 from a /15 or larger, else a /24.
pub fn block(pool: ([u8; 4], u8)) -> u8 {
    if pool.1 <= 15 { 16 } else { 24 }
}

/// How many networks `pool` has room for.
pub fn room(pool: ([u8; 4], u8)) -> u32 {
    1 << (block(pool) - pool.1)
}

fn path() -> Option<PathBuf> {
    #[cfg(test)]
    return None;
    #[cfg(not(test))]
    super::state_dir().ok().map(|d| d.join("addresses.json"))
}

/// The pool set in Settings, or None for the default.
pub fn custom() -> Option<([u8; 4], u8)> {
    let saved: Value = serde_json::from_slice(&std::fs::read(path()?).ok()?).ok()?;
    parse(saved["pool"].as_str()?).ok().filter(|p| *p != DEFAULT)
}

pub fn current() -> ([u8; 4], u8) {
    custom().unwrap_or(DEFAULT)
}

/// Saves `pool`; the default leaves no file behind.
pub fn save(pool: ([u8; 4], u8)) -> std::io::Result<()> {
    let path = path().ok_or_else(|| std::io::Error::other("HOME is not set"))?;
    if pool == DEFAULT {
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json!({"pool": cidr(pool)}).to_string())?;
    std::fs::rename(&tmp, &path)
}

/// One of this computer's networks: `Wi-Fi (en0)`, `VPN (utun4)`.
#[derive(Clone, Debug, PartialEq)]
pub struct HostNet {
    pub name: String,
    pub net: ([u8; 4], u8),
}

/// Windows' networks when the engine runs in WSL2: kiri-win sends them
/// with Windows' proxy (`PUT /kiri/proxy/system`).
static WINDOWS: Mutex<Option<Vec<HostNet>>> = Mutex::new(None);

pub fn set_windows(list: Vec<HostNet>) {
    *WINDOWS.lock().unwrap_or_else(|e| e.into_inner()) = Some(list);
}

/// `[{"name": "Wi-Fi", "net": "192.168.1.0/24"}]`, as kiri-win sends them.
pub fn read_list(v: &Value) -> Vec<HostNet> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|n| {
            let (ip, bits) = n["net"].as_str()?.split_once('/')?;
            let bits: u8 = bits.parse().ok().filter(|b| *b <= 32)?;
            let ip = parse_ip(ip)?;
            let base = (u32::from_be_bytes(ip) & if bits == 0 { 0 } else { u32::MAX << (32 - bits) }).to_be_bytes();
            Some(HostNet { name: n["name"].as_str().unwrap_or("").to_owned(), net: (base, bits) })
        })
        .collect()
}

/// This computer's networks, for the window: Windows' if kiri-win sent
/// them, else this machine's interfaces.
pub fn host_networks() -> Vec<HostNet> {
    if let Some(w) = WINDOWS.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        return w;
    }
    interfaces().into_iter().map(|(iface, net)| HostNet { name: label(&iface), net }).collect()
}

/// What new networks keep clear of beyond a Linux host's routes, as
/// (network, mask): this machine's interfaces and Windows' networks.
pub fn avoid() -> Vec<(u32, u32)> {
    let mut nets: Vec<([u8; 4], u8)> = interfaces().into_iter().map(|(_, n)| n).collect();
    nets.extend(WINDOWS.lock().unwrap_or_else(|e| e.into_inner()).iter().flatten().map(|h| h.net));
    nets.into_iter()
        .filter(|n| n.1 > 0)
        .map(|(s, p)| {
            let mask = u32::MAX << (32 - p as u32);
            (u32::from_be_bytes(s) & mask, mask)
        })
        .collect()
}

/// A VPN's interface says so: `VPN (utun4)`; a Mac's hardware port is
/// named as System Settings names it: `Wi-Fi (en0)`.
fn label(iface: &str) -> String {
    const VPN: [&str; 7] = ["utun", "ipsec", "ppp", "tun", "tap", "wg", "tailscale"];
    if VPN.iter().any(|p| iface.starts_with(p)) {
        return format!("VPN ({iface})");
    }
    match port_name(iface) {
        Some(port) => format!("{port} ({iface})"),
        None => iface.to_owned(),
    }
}

/// `networksetup -listallhardwareports`: Wi-Fi for en0 and so on, read once.
#[cfg(target_os = "macos")]
fn port_name(iface: &str) -> Option<String> {
    static PORTS: std::sync::OnceLock<Vec<(String, String)>> = std::sync::OnceLock::new();
    let ports = PORTS.get_or_init(|| {
        let out = std::process::Command::new("/usr/sbin/networksetup").arg("-listallhardwareports").output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
        let mut list = Vec::new();
        let mut port = None;
        for l in out.lines() {
            if let Some(p) = l.strip_prefix("Hardware Port: ") {
                port = Some(p.trim().to_owned());
            } else if let (Some(d), Some(p)) = (l.strip_prefix("Device: "), port.take()) {
                list.push((d.trim().to_owned(), p));
            }
        }
        list
    });
    ports.iter().find(|(d, _)| d == iface).map(|(_, p)| p.clone())
}

#[cfg(not(target_os = "macos"))]
fn port_name(_: &str) -> Option<String> {
    None
}

/// This machine's IPv4 interface networks, but loopback, link-local and
/// Kiri's own bridges, one per network.
fn interfaces() -> Vec<(String, ([u8; 4], u8))> {
    let mut out: Vec<(String, ([u8; 4], u8))> = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list`, freed below; entries are read only while it lives.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return out;
    }
    let mut p = list;
    while !p.is_null() {
        // SAFETY: `p` is an entry of the list getifaddrs returned.
        let ifa = unsafe { &*p };
        p = ifa.ifa_next;
        // SAFETY: a non-null ifa_addr points at a sockaddr.
        if ifa.ifa_addr.is_null() || ifa.ifa_netmask.is_null() || i32::from(unsafe { (*ifa.ifa_addr).sa_family }) != libc::AF_INET {
            continue;
        }
        // SAFETY: an AF_INET address and its netmask are sockaddr_ins.
        let (addr, mask) = unsafe { ((*(ifa.ifa_addr as *const libc::sockaddr_in)).sin_addr.s_addr, (*(ifa.ifa_netmask as *const libc::sockaddr_in)).sin_addr.s_addr) };
        let (addr, mask) = (u32::from_be(addr), u32::from_be(mask));
        // SAFETY: ifa_name is a NUL-terminated string while the list lives.
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().into_owned();
        let first = addr.to_be_bytes();
        if first[0] == 127 || (first[0] == 169 && first[1] == 254) || name.starts_with("kiri") {
            continue;
        }
        let net = ((addr & mask).to_be_bytes(), mask.leading_ones() as u8);
        if !out.iter().any(|(_, n)| *n == net) {
            out.push((name, net));
        }
    }
    // SAFETY: the list getifaddrs returned, freed once.
    unsafe { libc::freeifaddrs(list) };
    out
}

/// For Settings → Network: the pool, the default, where the default bridge
/// is now, and this computer's networks for the clash check.
pub fn report(bridge: Option<([u8; 4], u8)>) -> Value {
    json!({
        "pool": cidr(current()),
        "default": cidr(DEFAULT),
        "bridge": bridge.map(cidr),
        "host": host_networks().iter().map(|h| json!({"name": h.name, "net": cidr(h.net)})).collect::<Vec<_>>(),
    })
}

/// Whether `pool` overlaps any of `host`: the window's amber.
#[cfg(test)]
fn clash(pool: ([u8; 4], u8), host: &[HostNet]) -> Option<&HostNet> {
    host.iter().find(|h| super::network::overlaps(pool, h.net))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pools_are_read_and_checked() {
        assert_eq!(parse("172.16.0.0/12"), Ok(DEFAULT));
        assert_eq!(parse(" 10.200.0.0/16 "), Ok(([10, 200, 0, 0], 16)));
        // The base is taken to the range's start.
        assert_eq!(parse("10.200.7.9/16"), Ok(([10, 200, 0, 0], 16)));
        assert_eq!(parse("192.168.200.0/21"), Ok(([192, 168, 200, 0], 21)));
        assert_eq!(parse("10.0.0.0/8"), Ok(([10, 0, 0, 0], 8)));
        for bad in ["", "10.200.0.0", "10.200.0/16", "10.200.0.0/25", "10.0.0.0/7", "300.1.0.0/16", "10.200.0.0/x", "a.b.c.d/16"] {
            assert!(parse(bad).unwrap_err().contains("Write it like 10.200.0.0/16"), "{bad}");
        }
        for public in ["8.8.0.0/16", "172.32.0.0/16", "172.0.0.0/8", "192.0.0.0/8", "100.64.0.0/10"] {
            assert!(parse(public).unwrap_err().contains("not a private range"), "{public}");
        }
    }

    #[test]
    fn blocks_and_room_follow_the_pool_size() {
        assert_eq!((block(DEFAULT), room(DEFAULT)), (16, 16));
        assert_eq!((block(([10, 0, 0, 0], 8)), room(([10, 0, 0, 0], 8))), (16, 256));
        assert_eq!((block(([10, 200, 0, 0], 15)), room(([10, 200, 0, 0], 15))), (16, 2));
        assert_eq!((block(([10, 200, 0, 0], 16)), room(([10, 200, 0, 0], 16))), (24, 256));
        assert_eq!((block(([10, 200, 0, 0], 20)), room(([10, 200, 0, 0], 20))), (24, 16));
        assert_eq!((block(([192, 168, 5, 0], 24)), room(([192, 168, 5, 0], 24))), (24, 1));
    }

    #[test]
    fn host_networks_are_read_and_clashes_found() {
        let host = read_list(&json!([{"name": "VPN (utun4)", "net": "172.20.0.5/16"}, {"name": "Wi-Fi", "net": "192.168.1.0/24"}, {"name": "bad", "net": "x"}]));
        assert_eq!(host, vec![HostNet { name: "VPN (utun4)".into(), net: ([172, 20, 0, 0], 16) }, HostNet { name: "Wi-Fi".into(), net: ([192, 168, 1, 0], 24) }]);
        assert_eq!(clash(DEFAULT, &host).map(|h| h.name.as_str()), Some("VPN (utun4)"));
        assert_eq!(clash(([10, 200, 0, 0], 16), &host), None);
        assert_eq!(clash(([192, 168, 0, 0], 16), &host).map(|h| h.name.as_str()), Some("Wi-Fi"));
        assert_eq!(label("utun4"), "VPN (utun4)");
        assert_eq!(label("wg0"), "VPN (wg0)");
    }

    #[test]
    fn interfaces_skip_loopback_and_link_local() {
        for (name, (net, _)) in interfaces() {
            assert!(net[0] != 127 && !(net[0] == 169 && net[1] == 254) && !name.starts_with("kiri"), "{name}");
        }
    }
}
