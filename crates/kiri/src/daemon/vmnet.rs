//! macOS `vmnet` (`VZNATNetworkDeviceAttachment`) network discovery and IP
//! selection for the VM uplink fallback (#435).

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;

/// A host bridge interface serving Apple's shared NAT network (`bridge100`, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bridge {
    pub name: String,
    pub gateway: [u8; 4],
    pub prefix: u8,
}

pub fn mask_to_prefix(mask: [u8; 4]) -> Option<u8> {
    let bits = u32::from_be_bytes(mask);
    let ones = bits.leading_ones();
    ((1..=30).contains(&ones) && bits == (u32::MAX << (32 - ones))).then_some(ones as u8)
}

fn mask_from_prefix(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix)) }
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    s.trim().parse::<Ipv4Addr>().ok().map(|a| a.octets())
}

pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = s.trim().split(':');
    for b in &mut mac {
        let p = parts.next().filter(|p| !p.is_empty() && p.len() <= 2)?;
        *b = u8::from_str_radix(p, 16).ok()?;
    }
    parts.next().is_none().then_some(mac)
}

fn usable_gateway(ip: [u8; 4]) -> bool {
    ip != [0; 4] && ip[0] != 127 && !(ip[0] == 169 && ip[1] == 254)
}

/// Extracts `Shared_Net_Address` and `Shared_Net_Mask` from `com.apple.vmnet.plist`.
pub fn parse_vmnet_plist(xml: &str) -> Option<([u8; 4], u8)> {
    let val = |k: &str| {
        let after = xml.split_once(&format!("<key>{k}</key>"))?.1.trim_start();
        after.strip_prefix("<string>")?.split_once("</string>").map(|(v, _)| v.trim()).filter(|v| !v.is_empty())
    };
    let addr = parse_ipv4(val("Shared_Net_Address")?).filter(|&a| usable_gateway(a))?;
    let prefix = match val("Shared_Net_Mask") {
        Some(m) => mask_to_prefix(parse_ipv4(m)?)?,
        None => 24,
    };
    let (mask, raw) = (mask_from_prefix(prefix), u32::from_be_bytes(addr));
    Some((if raw & !mask == 0 { (raw | 1).to_be_bytes() } else { addr }, prefix))
}

/// Parses macOS `/var/db/dhcpd_leases` blocks into `(ip, mac)` pairs.
pub fn parse_dhcpd_leases(text: &str) -> Vec<([u8; 4], Option<[u8; 6]>)> {
    let (mut out, mut in_block, mut ip, mut mac) = (Vec::new(), false, None, None);
    for raw in text.lines() {
        match raw.trim() {
            "{" => (in_block, ip, mac) = (true, None, None),
            "}" => {
                if in_block && let Some(a) = ip.take() {
                    out.push((a, mac));
                }
                in_block = false;
            }
            line if in_block => match line.split_once('=') {
                Some((k, v)) if k.trim() == "ip_address" => ip = parse_ipv4(v),
                Some((k, v)) if k.trim() == "hw_address" => mac = parse_mac(v.trim().split_once(',').map_or(v.trim(), |(_, r)| r)),
                _ => {}
            },
            _ => {}
        }
    }
    out
}

/// Parses `netstat -anv -p udp` output for listeners bound to UDP port 67.
pub fn parse_udp67_listeners(netstat: &str) -> Vec<(Option<String>, u32)> {
    let (mut out, mut pid_col) = (Vec::new(), None);
    for line in netstat.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Some((_, after)) = line.split_once("(state)") {
            pid_col = after.split_whitespace().position(|c| c == "pid" || c == "process:pid");
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 || !matches!(f[0], "udp4" | "udp46" | "udp6") || !f[3].ends_with(".67") {
            continue;
        }
        let named = |t: &str| {
            let (n, p) = t.rsplit_once(':')?;
            (!n.is_empty() && !n.starts_with("0x") && !n.contains(':')).then(|| p.parse::<u32>().ok().filter(|&p| p > 0))?.map(|p| (Some(n.to_owned()), p))
        };
        let tail = &f[5..];
        let entry = pid_col
            .and_then(|i| tail.get(i).copied())
            .and_then(|t| named(t).or_else(|| t.parse::<u32>().ok().filter(|&p| p > 0).map(|p| (None, p))))
            .or_else(|| tail.iter().copied().find_map(named));
        if let Some(e) = entry && !out.contains(&e) {
            out.push(e);
        }
    }
    out
}

/// Picks the host bridge backing Apple's shared NAT network (`bridge100+`).
pub fn pick_bridge(ifaces: &[Bridge], plist: Option<([u8; 4], u8)>) -> Option<Bridge> {
    let num = |n: &str| n.strip_prefix("bridge")?.parse::<u32>().ok();
    let valid: Vec<&Bridge> = ifaces.iter().filter(|b| b.name.starts_with("bridge") && (8..=30).contains(&b.prefix) && usable_gateway(b.gateway)).collect();
    if let Some((p_gw, p_prefix)) = plist {
        let p_mask = mask_from_prefix(p_prefix);
        let p_net = u32::from_be_bytes(p_gw) & p_mask;
        if let Some(b) = valid.iter().copied().filter(|b| (u32::from_be_bytes(b.gateway) & p_mask) == p_net).min_by_key(|b| (b.name != "bridge100", num(&b.name).unwrap_or(u32::MAX))) {
            return Some(b.clone());
        }
    }
    valid
        .into_iter()
        .filter(|b| num(&b.name).is_some_and(|n| n >= 100))
        .min_by_key(|b| (b.name != "bridge100", num(&b.name).unwrap_or(u32::MAX)))
        .cloned()
        .or_else(|| plist.map(|(gateway, prefix)| Bridge { name: "bridge100".into(), gateway, prefix }))
}

/// Picks an IPv4 host address inside `gateway/prefix` avoiding the network,
/// gateway, broadcast, and other hosts' leases in `/var/db/dhcpd_leases`.
pub fn pick_ip(gateway: [u8; 4], prefix: u8, our_mac: Option<[u8; 6]>, leases: &[([u8; 4], Option<[u8; 6]>)]) -> Option<[u8; 4]> {
    if !(1..=30).contains(&prefix) || !usable_gateway(gateway) {
        return None;
    }
    let (mask, gw) = (mask_from_prefix(prefix), u32::from_be_bytes(gateway));
    let (net, bcast) = (gw & mask, (gw & mask) | !mask);
    let in_sub = |ip: [u8; 4]| {
        let v = u32::from_be_bytes(ip);
        v > net && v < bcast && v != gw
    };
    let other: HashSet<[u8; 4]> = leases.iter().filter(|&&(ip, mac)| in_sub(ip) && (our_mac.is_none() || mac != our_mac)).map(|&(ip, _)| ip).collect();
    if let Some(m) = our_mac
        && let Some(&(ip, _)) = leases.iter().find(|&&(ip, mac)| mac == Some(m) && in_sub(ip) && !other.contains(&ip))
    {
        return Some(ip);
    }
    ((net + 1)..bcast).filter(|&h| h != gw).map(u32::to_be_bytes).find(|ip| !other.contains(ip))
}

pub fn format_udp67_summary(listeners: &[(Option<String>, u32)]) -> Option<String> {
    let mut items: Vec<(bool, String)> = Vec::new();
    for (name, pid) in listeners {
        let label = name.as_ref().map_or_else(|| format!("pid {pid}"), |n| format!("{n} (pid {pid})"));
        let sys = name.as_deref().is_some_and(|n| matches!(n, "bootpd" | "launchd"));
        if !items.iter().any(|(_, s)| s == &label) {
            items.push((sys, label));
        }
    }
    items.sort_by_key(|(sys, _)| *sys);
    (!items.is_empty()).then(|| items.into_iter().map(|(_, s)| s).collect::<Vec<_>>().join(", "))
}

/// Extracts the IPv4 octets (`sin_addr`, bytes `4..8` of BSD `sockaddr_in`)
/// from a raw BSD `sockaddr` slice (`raw[0] == sa_len`), zero-padding
/// truncated netmasks (`sa_len` 5..8 on macOS) without reading past `sa_len`.
pub fn parse_bsd_sockaddr_ipv4(raw: &[u8], min_len: usize) -> Option<[u8; 4]> {
    let len = usize::from(*raw.first()?).min(raw.len());
    if len < min_len || len <= 4 {
        return None;
    }
    let mut out = [0u8; 4];
    let n = (len - 4).min(4);
    out[..n].copy_from_slice(&raw[4..4 + n]);
    Some(out)
}

#[cfg(target_os = "macos")]
unsafe fn sockaddr_ipv4(sa: *const libc::sockaddr, min_len: usize) -> Option<[u8; 4]> {
    if sa.is_null() {
        return None;
    }
    let len = usize::from(unsafe { (*sa).sa_len });
    // SAFETY: `getifaddrs` allocates at least `sa_len` bytes at `sa`.
    parse_bsd_sockaddr_ipv4(unsafe { std::slice::from_raw_parts(sa as *const u8, len) }, min_len)
}

#[cfg(target_os = "macos")]
fn live_bridges() -> Vec<Bridge> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list`, freed below; entries are read only while it lives.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Vec::new();
    }
    let (mut out, mut p) = (Vec::new(), list);
    while let Some(ifa) = unsafe { p.as_ref() } {
        let up = (ifa.ifa_flags as i32) & libc::IFF_UP != 0;
        if up && !ifa.ifa_name.is_null() && !ifa.ifa_addr.is_null() && i32::from(unsafe { (*ifa.ifa_addr).sa_family }) == libc::AF_INET {
            let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().into_owned();
            if name.starts_with("bridge")
                && let (Some(gateway), Some(mask)) = (unsafe { sockaddr_ipv4(ifa.ifa_addr, 8) }, unsafe { sockaddr_ipv4(ifa.ifa_netmask, 5) })
                && let Some(prefix) = mask_to_prefix(mask)
            {
                out.push(Bridge { name, gateway, prefix });
            }
        }
        p = ifa.ifa_next;
    }
    // SAFETY: freed once for the list returned by getifaddrs.
    unsafe { libc::freeifaddrs(list) };
    out
}

#[cfg(target_os = "macos")]
pub fn current_bridge() -> Option<Bridge> {
    let plist = std::fs::read_to_string("/Library/Preferences/SystemConfiguration/com.apple.vmnet.plist").ok().and_then(|s| parse_vmnet_plist(&s));
    pick_bridge(&live_bridges(), plist)
}

#[cfg(not(target_os = "macos"))]
pub fn current_bridge() -> Option<Bridge> {
    None
}

#[cfg(target_os = "macos")]
pub fn discover_uplink(store_root: &Path) -> Result<(Bridge, [u8; 4]), String> {
    let bridge = current_bridge().ok_or_else(|| "no macOS vmnet bridge interface (bridge100) found".to_owned())?;
    let vm_mac = std::fs::read_to_string(store_root.join("vm/mac")).ok().and_then(|s| parse_mac(&s));
    let leases = std::fs::read_to_string("/var/db/dhcpd_leases").map(|t| parse_dhcpd_leases(&t)).unwrap_or_default();
    let ip = pick_ip(bridge.gateway, bridge.prefix, vm_mac, &leases)
        .ok_or_else(|| format!("no free IPv4 address left on {} ({}/{})", bridge.name, Ipv4Addr::from(bridge.gateway), bridge.prefix))?;
    Ok((bridge, ip))
}

#[cfg(not(target_os = "macos"))]
pub fn discover_uplink(_store_root: &Path) -> Result<(Bridge, [u8; 4]), String> {
    Err("vmnet uplink discovery is only available on macOS".into())
}

#[cfg(target_os = "macos")]
pub fn udp67_holder() -> Option<String> {
    let out = std::process::Command::new("/usr/sbin/netstat").args(["-anv", "-p", "udp"]).stderr(std::process::Stdio::null()).output().ok()?;
    let mut listeners = parse_udp67_listeners(&String::from_utf8_lossy(&out.stdout));
    for (name, pid) in &mut listeners {
        if name.is_none() {
            *name = std::process::Command::new("/bin/ps")
                .args(["-p", &pid.to_string(), "-o", "comm="])
                .stderr(std::process::Stdio::null())
                .output()
                .ok()
                .and_then(|o| {
                    let raw = String::from_utf8_lossy(&o.stdout).trim().to_owned();
                    (!raw.is_empty()).then(|| Path::new(&raw).file_name().and_then(|f| f.to_str()).unwrap_or(&raw).to_owned())
                });
        }
    }
    format_udp67_summary(&listeners)
}

#[cfg(not(target_os = "macos"))]
pub fn udp67_holder() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vmnet_plist_and_picks_bridge() {
        let xml = "<dict><key>Shared_Net_Address</key><string>192.168.64.1</string><key>Shared_Net_Mask</key><string>255.255.255.0</string></dict>";
        assert_eq!(parse_vmnet_plist(xml), Some(([192, 168, 64, 1], 24)));
        assert_eq!(parse_vmnet_plist("<dict><key>Shared_Net_Address</key><string>10.20.30.0</string></dict>"), Some(([10, 20, 30, 1], 24)));
        assert_eq!(parse_vmnet_plist("<dict><key>Shared_Net_Address</key><string>127.0.0.1</string></dict>"), None);
        let (tb, b100, b101) = (
            Bridge { name: "bridge0".into(), gateway: [10, 0, 0, 1], prefix: 24 },
            Bridge { name: "bridge100".into(), gateway: [192, 168, 64, 1], prefix: 24 },
            Bridge { name: "bridge101".into(), gateway: [192, 168, 65, 1], prefix: 24 },
        );
        assert_eq!(pick_bridge(&[tb.clone(), b101.clone(), b100.clone()], None), Some(b100.clone()));
        assert_eq!(pick_bridge(std::slice::from_ref(&tb), None), None);
        assert_eq!(pick_bridge(&[b100, b101.clone()], Some(([192, 168, 65, 1], 24))), Some(b101));
    }

    #[test]
    fn parses_leases_and_picks_collision_free_ip() {
        let leases = parse_dhcpd_leases("{\n\tip_address=192.168.64.2\n\thw_address=1,2:48:44:4d:d8:13\n}\n{\n\tip_address=192.168.64.28\n\thw_address=1,f6:49:47:3e:68:51\n}\n");
        let our_mac = [0xf6, 0x49, 0x47, 0x3e, 0x68, 0x51];
        assert_eq!(pick_ip([192, 168, 64, 1], 24, Some(our_mac), &leases), Some([192, 168, 64, 28]));
        assert_eq!(pick_ip([192, 168, 64, 1], 24, None, &leases[..1]), Some([192, 168, 64, 3]));
        assert_eq!(pick_ip([192, 168, 64, 1], 30, None, &leases[..1]), None);
    }

    #[test]
    fn parses_udp67_listeners_from_netstat() {
        let netstat = "Proto Recv-Q Send-Q Local Address Foreign Address (state) rhiwat shiwat process:pid state\n\
                       udp4 0 0 *.67 *.* 786896 9216 kavd:412 0x0000\n\
                       udp4 0 0 192.168.64.1.67 *.* 786896 9216 bootpd:510 0x0000\n";
        assert_eq!(format_udp67_summary(&parse_udp67_listeners(netstat)).as_deref(), Some("kavd (pid 412), bootpd (pid 510)"));
    }

    #[test]
    fn decodes_truncated_bsd_netmask_sockaddrs() {
        assert_eq!(parse_bsd_sockaddr_ipv4(&[4, 2, 0, 0], 5), None);
        assert_eq!(parse_bsd_sockaddr_ipv4(&[7, 2, 0, 0, 255, 255, 255], 8), None);
        assert_eq!(parse_bsd_sockaddr_ipv4(&[5, 2, 0, 0, 255], 5).and_then(mask_to_prefix), Some(8));
        assert_eq!(parse_bsd_sockaddr_ipv4(&[7, 2, 0, 0, 255, 255, 255], 5).and_then(mask_to_prefix), Some(24));
        assert_eq!(parse_bsd_sockaddr_ipv4(&[8, 2, 0, 0, 255, 255, 255, 252], 5).and_then(mask_to_prefix), Some(30));
        assert_eq!(parse_bsd_sockaddr_ipv4(&[16, 2, 0, 0, 192, 168, 64, 1, 0, 0, 0, 0, 0, 0, 0, 0], 8), Some([192, 168, 64, 1]));
    }
}
