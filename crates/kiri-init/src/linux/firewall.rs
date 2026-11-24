//! A Linux host's own firewall, which must let Kiri's containers through.
//!
//! Every base chain on the forward hook sees each forwarded packet, and an
//! accept in one is not final: any other that drops it wins. Kiri's own
//! table accepting its containers' traffic is not enough when the host has
//! another forward chain that drops what it does not know:
//!
//! - iptables' FORWARD with policy drop (or an unconditional trailing
//!   `DROP`/`REJECT` rule): set by Docker when it turns ip_forward on, by
//!   ufw (its default), or by hand. Kiri adds three rules (`kiri_rules`) with
//!   the host's own iptables, into Docker's DOCKER-USER chain when it is
//!   there, else at the top of FORWARD, and allows gateway DNS on INPUT when
//!   INPUT's policy is drop (ufw).
//! - firewalld: Kiri's bridges go into a runtime `kiri` zone with target
//!   ACCEPT plus a `kiri-forwarding` policy (`ANY -> kiri`, target ACCEPT) so
//!   both outbound multi-NIC/VPN traffic and inbound published-port DNAT work;
//!   Kiri's own forward chain keeps containers off other programs' bridges.
//! - any other nftables chain on the forward hook with policy drop (an
//!   /etc/nftables.conf of the administrator's own): Kiri does not change
//!   another program's nftables chain. It says once in its log, and in
//!   `docker info`, which rules let its containers through, and while
//!   forwarding is blocked falls back to user-space relays for published ports.
//!
//! Only what Kiri's containers need passes: new connections out through the
//! uplink Kiri masquerades on, replies, and traffic into Kiri's bridges,
//! which Kiri's own forward chain judges (replies, published ports, the same
//! network). No new connection into another program's bridge (Docker's,
//! libvirt's) is accepted by these rules.
//!
//! Checked when the engine starts, when it brings up a bridge, and after
//! every nf_tables change (`changed`), so a firewall started, reloaded or
//! flushed after the engine is covered: the rules are added again, and
//! Kiri's own table too when a flush took it. A check is one netlink dump of
//! the chains; a program runs only when something must change. On a host
//! with none of these firewalls nothing runs. Taken out when the engine
//! stops; rules an engine that crashed left behind are reused, not doubled.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::netlink::{self, Chain};

/// Why the firewall is looked at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    Start,
    Bridge,
    /// An nf_tables change. iptables-legacy's tables make no such event, so
    /// they are looked at only on the others.
    Event,
    Stop,
}

/// Kiri's rules in iptables' filter table FORWARD/DOCKER-USER chains, as
/// iptables arguments after the chain: containers out to any non-Kiri
/// interface (primary NIC, VPNs, secondary NICs — while Kiri's own forward
/// chain blocks other programs' bridges), their replies wherever they go,
/// and anything into Kiri's bridges, which Kiri's own forward chain judges.
pub fn kiri_rules() -> [Vec<&'static str>; 3] {
    [
        vec!["-i", "kiri+", "!", "-o", "kiri+", "-m", "comment", "--comment", "kiri", "-j", "ACCEPT"],
        vec!["-i", "kiri+", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "kiri", "-j", "ACCEPT"],
        vec!["-o", "kiri+", "-m", "comment", "--comment", "kiri", "-j", "ACCEPT"],
    ]
}

/// Kiri's rules in iptables' `INPUT` chain when the host's `INPUT` policy is
/// `DROP` (e.g. ufw): allow only DNS (UDP/TCP port 53) from `kiri+` so
/// containers reach the gateway's embedded DNS without opening host services.
pub fn dns_input_rules() -> [Vec<&'static str>; 2] {
    [
        vec!["-i", "kiri+", "-p", "udp", "-m", "udp", "--dport", "53", "-m", "comment", "--comment", "kiri", "-j", "ACCEPT"],
        vec!["-i", "kiri+", "-p", "tcp", "-m", "tcp", "--dport", "53", "-m", "comment", "--comment", "kiri", "-j", "ACCEPT"],
    ]
}

/// Docker's chain for other software's rules in iptables' `filter` table.
const DOCKER_USER: &str = "DOCKER-USER";
const FORWARD: &str = "FORWARD";
const INPUT: &str = "INPUT";

/// Where Kiri's rules go in iptables' filter table of one family: Docker's
/// DOCKER-USER when it is there (Docker jumps to it first and never empties
/// it, also when it restarts), else the top of FORWARD when its policy is
/// drop or it carries an unconditional trailing `DROP`/`REJECT` rule.
pub fn iptables_target(docker_user: bool, forward_drop: bool) -> Option<&'static str> {
    if docker_user {
        Some(DOCKER_USER)
    } else if forward_drop {
        Some(FORWARD)
    } else {
        None
    }
}

const NFPROTO_INET: u8 = 1;
const NFPROTO_IPV4: u8 = libc::NFPROTO_IPV4 as u8;
const NFPROTO_IPV6: u8 = libc::NFPROTO_IPV6 as u8;
const NF_INET_FORWARD: u32 = 2;
const NF_DROP: u32 = 0;

/// What the host's nf_tables chains say about its forward and input hooks.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Hook {
    /// Per family (IPv4, IPv6): where Kiri's rules go in iptables-nft's
    /// filter table.
    pub iptables: [Option<&'static str>; 2],
    /// Per family (IPv4, IPv6): whether iptables-nft's `INPUT` chain has
    /// policy `DROP` (e.g. ufw).
    pub input_drop: [bool; 2],
    /// firewalld runs (its `inet firewalld` table), by the handle of a chain
    /// of it: a new one after firewalld reloads or restarts, which drops the
    /// runtime zone Kiri's bridges were put in.
    pub firewalld: Option<u64>,
    /// Whether `inet firewalld` has a `filter_FORWARD_POLICIES` chain
    /// (firewalld >= 0.9), requiring an ingress forwarding policy for `kiri`.
    pub firewalld_policies: bool,
    /// Kiri's own forward chain, IPv4 and IPv6: gone after an `nft flush
    /// ruleset` (nftables.service starting or reloading).
    pub kiri: [bool; 2],
    /// Other base chains on the forward hook with policy drop, as (family,
    /// table, chain): an nftables.conf of the administrator's.
    pub foreign: Vec<(u8, String, String)>,
}

pub fn read_hook(chains: &[Chain]) -> Hook {
    let mut h = Hook::default();
    for (i, family) in [NFPROTO_IPV4, NFPROTO_IPV6].into_iter().enumerate() {
        let has = |table: &str, name: &str| chains.iter().find(|c| c.family == family && c.table == table && c.name == name);
        let forward_drop = has("filter", FORWARD).is_some_and(|c| c.policy == Some(NF_DROP));
        h.iptables[i] = iptables_target(has("filter", DOCKER_USER).is_some(), forward_drop);
        h.input_drop[i] = has("filter", INPUT).is_some_and(|c| c.policy == Some(NF_DROP));
        h.kiri[i] = has("kiri", "forward").is_some();
    }
    h.firewalld = chains.iter().filter(|c| c.family == NFPROTO_INET && c.table == "firewalld").map(|c| c.handle).min();
    h.firewalld_policies = chains.iter().any(|c| c.family == NFPROTO_INET && c.table == "firewalld" && c.name == "filter_FORWARD_POLICIES");
    for c in chains {
        let iptables = matches!(c.family, NFPROTO_IPV4 | NFPROTO_IPV6) && c.table == "filter" && c.name == FORWARD;
        let ours = c.table == "kiri" && c.family != NFPROTO_INET;
        let firewalld = c.family == NFPROTO_INET && c.table == "firewalld";
        if c.hook == Some(NF_INET_FORWARD) && c.policy == Some(NF_DROP) && matches!(c.family, NFPROTO_INET | NFPROTO_IPV4 | NFPROTO_IPV6) && !iptables && !ours && !firewalld {
            h.foreign.push((c.family, c.table.clone(), c.name.clone()));
        }
    }
    h
}

/// Kiri's rules in an `iptables -S` listing, as (chain, arguments after
/// it): the lines with the comment `kiri`, quotes taken off.
pub fn kiri_lines(listing: &str) -> Vec<(String, Vec<String>)> {
    listing
        .lines()
        .filter_map(|l| {
            let words: Vec<String> = l.split_whitespace().map(|w| w.trim_matches('"').to_owned()).collect();
            let ours = words.windows(2).any(|w| w[0] == "--comment" && w[1] == "kiri");
            (ours && words.len() > 2 && words[0] == "-A").then(|| (words[1].clone(), words[2..].to_vec()))
        })
        .collect()
}

/// Whether an `iptables -S` listing contains an unconditional `DROP` or
/// `REJECT` rule in `FORWARD` (ignoring any rule commented with `kiri`).
fn listed_forward_unconditional_drop(listing: &str) -> bool {
    listing.lines().any(|l| {
        let words: Vec<&str> = l.split_whitespace().collect();
        if words.len() < 4 || words[0] != "-A" || words[1] != FORWARD {
            return false;
        }
        if words.windows(2).any(|w| w[0] == "--comment" && w[1].trim_matches('"') == "kiri") {
            return false;
        }
        let mut i = 2;
        let mut drops = false;
        while i < words.len() {
            match words[i] {
                "-j" => match words.get(i + 1).copied() {
                    Some("DROP" | "REJECT") => {
                        drops = true;
                        i += 2;
                    }
                    _ => return false,
                },
                "--reject-with" => i += 2,
                "-m" => match words.get(i + 1).copied() {
                    Some("comment") => i += 2,
                    _ => return false,
                },
                "--comment" => i += 2,
                _ => return false,
            }
        }
        drops
    })
}

/// Whether an `iptables -S` listing has `INPUT` policy `DROP`.
pub fn listed_input_drop(listing: &str) -> bool {
    listing.lines().any(|l| l.trim_end() == format!("-P {INPUT} DROP"))
}

/// Where Kiri's rules go, from an `iptables -S` listing of the filter
/// table (iptables-legacy, which only the program reads).
pub fn listed_target(listing: &str) -> Option<&'static str> {
    let docker_user = listing.lines().any(|l| l.trim_end() == format!("-N {DOCKER_USER}"));
    let forward_drop = listing.lines().any(|l| l.trim_end() == format!("-P {FORWARD} DROP")) || listed_forward_unconditional_drop(listing);
    iptables_target(docker_user, forward_drop)
}

/// The changes that bring Kiri's rules in `listing` in line: `kiri_rules()` in
/// `target` (None: nowhere, the engine stopping) and `dns_input_rules()` in
/// `INPUT` when `allow_dns_input` is true, as iptables arguments (`-D chain …`,
/// then `-I chain …`). Rules an engine that crashed left behind are kept where
/// they belong, and taken out of a chain they no longer belong in. Inserted
/// last rule first, so each chain keeps its rules in order at the top.
pub fn iptables_changes(listing: &str, target: Option<&str>, allow_dns_input: bool) -> Vec<Vec<String>> {
    let have = kiri_lines(listing);
    let mut want: Vec<(String, Vec<String>)> = target
        .map_or_else(Vec::new, |t| kiri_rules().iter().map(|r| (t.to_owned(), r.iter().map(|w| (*w).to_owned()).collect())).collect());
    if allow_dns_input {
        want.extend(dns_input_rules().iter().map(|r| (INPUT.to_owned(), r.iter().map(|w| (*w).to_owned()).collect())));
    }
    let mut out = Vec::new();
    for (chain, args) in &have {
        if !want.contains(&(chain.clone(), args.clone())) {
            out.push([vec!["-D".to_owned(), chain.clone()], args.clone()].concat());
        }
    }
    for (chain, args) in want.iter().rev() {
        if !have.contains(&(chain.clone(), args.clone())) {
            out.push([vec!["-I".to_owned(), chain.clone()], args.clone()].concat());
        }
    }
    out
}

/// What the administrator's own forward chain needs to let Kiri's
/// containers through, as `nft` commands.
pub fn foreign_advice(family: u8, table: &str, chain: &str) -> String {
    let fam = match family {
        NFPROTO_INET => "inet",
        NFPROTO_IPV6 => "ip6",
        _ => "ip",
    };
    let rules = [
        "iifname \"kiri*\" oifname != \"kiri*\" accept",
        "iifname \"kiri*\" ct state established,related accept",
        "oifname \"kiri*\" accept",
    ];
    let cmds: Vec<String> = rules.iter().map(|r| format!("nft insert rule {fam} {table} {chain} {r}")).collect();
    format!(
        "the firewall's nftables chain '{fam} {table} {chain}' (policy drop) drops the traffic of Kiri's containers, so they have no internet; Kiri does not change another program's chain. To let them through, run: {} (and add the same rules to that chain in /etc/nftables.conf to keep them)",
        cmds.join("; ")
    )
}

/// What Kiri did in one place: nothing yet, its rules are in (the chain
/// or zone), or adding them there failed (said once, and not tried again on
/// every change while that is still where they go).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Rules {
    #[default]
    None,
    In(&'static str),
    Failed(&'static str),
}

impl Rules {
    fn failed(self) -> bool {
        matches!(self, Rules::Failed(_))
    }
}

#[derive(Default)]
struct State {
    /// iptables-nft and iptables-legacy, each for IPv4 and IPv6.
    iptables: [[Rules; 2]; 2],
    /// Whether Kiri installed INPUT DNS port 53 rules (nft/legacy x v4/v6).
    input_dns: [[bool; 2]; 2],
    firewalld: Rules,
    /// The firewalld (by `Hook::firewalld`) that `firewalld` is about.
    firewalld_seen: Option<u64>,
    /// Whether firewalld blocks ingress forwarding into Kiri bridges (e.g.
    /// `filter_FORWARD_POLICIES` present without an `ANY -> kiri` policy).
    firewalld_blocked: bool,
    /// Whether host kernel forwarding into Kiri bridges is blocked (by an
    /// unmanaged foreign nftables forward drop chain, failed iptables, or
    /// firewalld without an ingress policy), triggering user-space relay fallback.
    forwarding_blocked: bool,
    /// Foreign chains already told about in the log.
    told: Vec<String>,
    /// What `docker info` shows, as last written.
    warnings: String,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

/// Whether the host firewall blocks kernel `FORWARD` into Kiri's bridges,
/// in which case published ports must be relayed in user space (`INPUT`)
/// rather than DNATed in `prerouting`.
pub fn forwarding_blocked() -> bool {
    STATE.lock().unwrap_or_else(|e| e.into_inner()).as_ref().is_some_and(|st| st.forwarding_blocked)
}

/// Checks whether forwarding is blocked given active firewall state and
/// unmanaged foreign nftables chains.
fn compute_forwarding_blocked(iptables_v4_failed: bool, firewalld_blocked: bool, unmanaged_foreign_v4: bool) -> bool {
    iptables_v4_failed || firewalld_blocked || unmanaged_foreign_v4
}

/// Brings the host's firewall in line with Kiri's needs (see the module
/// documentation), or takes Kiri's part out of it (`Why::Stop`). `rebuild`
/// builds Kiri's own tables (IPv4, IPv6) again as last built, when a flush
/// took them or their forwarding policy changed; it does nothing for a
/// table Kiri has not built.
pub fn sync(why: Why, rebuild: impl Fn([bool; 2])) {
    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let st = guard.get_or_insert_with(State::default);
    if why == Why::Stop {
        stop(st);
        return;
    }
    let chains = match netlink::chains() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("kiri-init: cannot list the firewall's nftables chains: {e}");
            Vec::new()
        }
    };
    let hook = read_hook(&chains);
    let mut warnings = Vec::new();
    let families = [(NFPROTO_IPV4, "iptables", "/proc/net/ip_tables_names"), (NFPROTO_IPV6, "ip6tables", "/proc/net/ip6_tables_names")];
    for (i, (family, tool, legacy_names)) in families.into_iter().enumerate() {
        // Detect unconditional trailing DROP/REJECT in FORWARD even when policy is ACCEPT (#649).
        let nft_target = hook.iptables[i].or_else(|| netlink::has_unconditional_forward_drop(family).ok().filter(|&d| d).map(|_| FORWARD));
        let want_dns = hook.input_drop[i];
        // iptables-nft: its filter table is in nf_tables, read above.
        let rules = &mut st.iptables[0][i];
        if let Rules::In(chain) = *rules {
            // Gone with a flush, `iptables -F`, a restore of saved rules, or Docker appearing (FORWARD -> DOCKER-USER).
            if nft_target != Some(chain) || netlink::rules_with(family, "filter", chain, b"kiri\0").unwrap_or(0) < 3 {
                *rules = Rules::None;
            }
        }
        if st.input_dns[0][i] && (!want_dns || netlink::rules_with(family, "filter", INPUT, b"kiri\0").unwrap_or(0) < 2) {
            st.input_dns[0][i] = false;
        }
        // Tried again when the engine starts or makes a bridge, or when
        // the place changed (the chain it failed in went, Docker came).
        if let Rules::Failed(t) = *rules
            && (why != Why::Event || nft_target != Some(t))
        {
            *rules = Rules::None;
        }
        let need_nft = (matches!(*rules, Rules::None) && nft_target.is_some()) || (want_dns && !st.input_dns[0][i]);
        if need_nft {
            match sbin(&format!("{tool}-nft")).or_else(|| sbin(tool)) {
                Some(path) => {
                    let (r, dns_ok) = iptables_sync(&path, None, nft_target, want_dns);
                    if nft_target.is_some() {
                        *rules = r;
                    }
                    st.input_dns[0][i] = want_dns && dns_ok;
                }
                None => {
                    if let Some(target) = nft_target {
                        eprintln!("kiri-init: iptables' {target} chain drops forwarded traffic on this host, but there is no {tool} to let Kiri's containers through it");
                        *rules = Rules::Failed(target);
                    }
                }
            }
        }
        if rules.failed() {
            warnings.push(format!("{tool}: Kiri could not add its rules to the filter table, whose FORWARD chain drops the traffic of Kiri's containers; see the engine log"));
        }
        // iptables-legacy: in x_tables, which only the program reads, and
        // which makes no nf_tables event.
        let rules = &mut st.iptables[1][i];
        if why != Why::Event
            && std::fs::read_to_string(legacy_names).is_ok_and(|t| t.lines().any(|l| l == "filter"))
            && let Some(path) = sbin(&format!("{tool}-legacy")).or_else(|| sbin(tool))
            && let Some(listing) = run(&path, &["-S"])
        {
            // Where they go, or where they are when nothing drops any more.
            let keep = match (*rules, listed_target(&listing)) {
                (Rules::In(c), None) => Some(c),
                (_, target) => target,
            };
            let legacy_dns = listed_input_drop(&listing);
            if keep.is_some() || legacy_dns || st.input_dns[1][i] {
                let (r, dns_ok) = iptables_sync(&path, Some(&listing), keep, legacy_dns);
                if keep.is_some() || matches!(*rules, Rules::In(_)) {
                    *rules = r;
                }
                st.input_dns[1][i] = legacy_dns && dns_ok;
            }
        }
        if rules.failed() {
            warnings.push(format!("{tool}-legacy: Kiri could not add its rules to the filter table, whose FORWARD chain drops the traffic of Kiri's containers; see the engine log"));
        }
    }
    firewalld(st, hook.firewalld, hook.firewalld_policies, why, &mut warnings);
    let mut unmanaged_foreign_v4 = false;
    for (family, table, chain) in &hook.foreign {
        // Already let through (a rule naming Kiri's bridges).
        if netlink::rules_with(*family, table, chain, b"kiri").unwrap_or(0) > 0 {
            continue;
        }
        if matches!(*family, NFPROTO_INET | NFPROTO_IPV4) {
            unmanaged_foreign_v4 = true;
        }
        let advice = foreign_advice(*family, table, chain);
        let key = format!("{family} {table} {chain}");
        if !st.told.contains(&key) {
            eprintln!("kiri-init: {advice}");
            st.told.push(key);
        }
        warnings.push(format!("Linux host: {advice}"));
    }
    let new_blocked = compute_forwarding_blocked(st.iptables[0][0].failed() || st.iptables[1][0].failed(), st.firewalld_blocked, unmanaged_foreign_v4);
    let blocked_changed = st.forwarding_blocked != new_blocked;
    st.forwarding_blocked = new_blocked;
    // A flush of the whole ruleset (nftables.service starting or
    // reloading) took Kiri's own tables. The IPv6 one is there only with an
    // IPv6 network, which `rebuild` knows.
    let gone = [why == Why::Event && !hook.kiri[0], why == Why::Event && !hook.kiri[1]];
    if gone[0] {
        eprintln!("kiri-init: Kiri's nftables table was removed (a flush of the whole ruleset?); building it again");
    }
    write_warnings(st, warnings.join("\n"));
    drop(guard);
    if blocked_changed || gone[0] || gone[1] {
        rebuild([blocked_changed || gone[0], gone[1]]);
    }
}

/// Brings Kiri's rules in iptables' filter table (`listing`, or listed
/// now) in line with `target` and `allow_dns_input`; see `iptables_changes`.
/// Returns `(forward_rules, all_succeeded)`.
fn iptables_sync(tool: &Path, listing: Option<&str>, target: Option<&'static str>, allow_dns_input: bool) -> (Rules, bool) {
    let listed;
    let listing = match listing {
        Some(l) => l,
        None => match run(tool, &["-S"]) {
            Some(l) => {
                listed = l;
                &listed
            }
            None => {
                eprintln!("kiri-init: {} cannot list the filter table, so Kiri's containers may not pass the host's firewall", tool.display());
                return (target.map_or(Rules::None, Rules::Failed), false);
            }
        },
    };
    let mut ok = true;
    for change in iptables_changes(listing, target, allow_dns_input) {
        let args: Vec<&str> = change.iter().map(String::as_str).collect();
        ok &= run(tool, &args).is_some();
    }
    let r = match (target, ok) {
        (Some(t), true) => {
            eprintln!("kiri-init: the host's firewall drops forwarded traffic: Kiri's containers pass it by rules in iptables' {t} chain ({})", tool.display());
            Rules::In(t)
        }
        (Some(t), false) => {
            eprintln!("kiri-init: {} rules for Kiri's containers could not be added to {t}", tool.display());
            Rules::Failed(t)
        }
        (None, ok) => {
            if !ok {
                eprintln!("kiri-init: {} rules for Kiri's containers could not all be removed", tool.display());
            }
            Rules::None
        }
    };
    (r, ok)
}

const ZONE_KIRI: &str = "kiri";
const ZONE_TRUSTED: &str = "trusted";
const POLICY_FORWARDING: &str = "kiri-forwarding";

fn firewall_cmd_out(cmd: &Path, args: &[&str]) -> Result<String, String> {
    match std::process::Command::new(cmd).args(args).stdin(std::process::Stdio::null()).output() {
        Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).into_owned()),
        Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_owned()),
        Err(e) => Err(e.to_string()),
    }
}

/// Ensures `kiri` zone (`target=ACCEPT`) and `kiri-forwarding` policy (`ANY -> kiri`,
/// `target=ACCEPT`) exist in firewalld runtime, falling back gracefully on older
/// firewalld without policies or if `kiri` zone creation is rejected.
/// Returns `(rules_state, forwarding_blocked)`.
fn configure_firewalld(cmd: &Path, policies_hook: bool) -> (Rules, bool) {
    let rt_zones = firewall_cmd_out(cmd, &["--get-zones"]).unwrap_or_default();
    let has_kiri_rt = rt_zones.split_whitespace().any(|z| z == ZONE_KIRI);
    let rt_policies = firewall_cmd_out(cmd, &["--get-policies"]);
    let policies_supported = rt_policies.is_ok();
    let has_policy_rt = rt_policies.as_deref().is_ok_and(|p| p.split_whitespace().any(|n| n == POLICY_FORWARDING));

    let mut need_reload = false;
    let mut zone_ready = has_kiri_rt;
    if !has_kiri_rt {
        let perm_zones = firewall_cmd_out(cmd, &["--permanent", "--get-zones"]).unwrap_or_default();
        let mut perm_ok = perm_zones.split_whitespace().any(|z| z == ZONE_KIRI);
        if !perm_ok {
            perm_ok = firewall_cmd_out(cmd, &["--permanent", "--new-zone=kiri"]).is_ok()
                && firewall_cmd_out(cmd, &["--permanent", "--zone=kiri", "--set-target=ACCEPT"]).is_ok();
        }
        if perm_ok {
            need_reload = true;
            zone_ready = true;
        }
    }

    let mut policy_ready = has_policy_rt;
    if zone_ready && policies_supported && !has_policy_rt {
        let perm_policies = firewall_cmd_out(cmd, &["--permanent", "--get-policies"]).unwrap_or_default();
        let mut perm_ok = perm_policies.split_whitespace().any(|p| p == POLICY_FORWARDING);
        if !perm_ok {
            perm_ok = firewall_cmd_out(cmd, &["--permanent", "--new-policy=kiri-forwarding"]).is_ok()
                && firewall_cmd_out(cmd, &["--permanent", "--policy=kiri-forwarding", "--add-ingress-zone=ANY"]).is_ok()
                && firewall_cmd_out(cmd, &["--permanent", "--policy=kiri-forwarding", "--add-egress-zone=kiri"]).is_ok()
                && firewall_cmd_out(cmd, &["--permanent", "--policy=kiri-forwarding", "--set-target=ACCEPT"]).is_ok();
        }
        if perm_ok {
            need_reload = true;
            policy_ready = true;
        }
    }

    if need_reload && firewall_cmd_out(cmd, &["--reload"]).is_err() {
        zone_ready = has_kiri_rt;
        policy_ready = has_policy_rt;
    }

    let target_zone = if zone_ready { ZONE_KIRI } else { ZONE_TRUSTED };
    let add_arg = format!("--zone={target_zone}");
    match firewall_cmd_out(cmd, &[&add_arg, "--add-interface=kiri+"]) {
        Ok(_) => {
            let blocked = policies_hook && (!zone_ready || !policy_ready);
            eprintln!("kiri-init: firewalld runs: Kiri's bridges (kiri+) are in its {target_zone} zone until the engine stops");
            (Rules::In(target_zone), blocked)
        }
        Err(why) if why.contains("ZONE_CONFLICT") => {
            eprintln!("kiri-init: firewalld runs, and Kiri's bridges (kiri+) are in a zone of the administrator's already, which decides what Kiri's containers may reach");
            let blocked = policies_hook && netlink::rules_with(NFPROTO_INET, "firewalld", "filter_FORWARD_POLICIES", b"kiri").unwrap_or(0) == 0;
            (Rules::None, blocked)
        }
        Err(why) => {
            eprintln!("kiri-init: firewalld runs, but Kiri's bridges could not be put in its {target_zone} zone: {why}");
            (Rules::Failed(target_zone), true)
        }
    }
}

/// Puts Kiri's bridges into firewalld's `kiri` zone (plus `kiri-forwarding`
/// policy when supported, falling back to `trusted` on older installations),
/// runtime interface attachment only, once per firewalld run.
fn firewalld(st: &mut State, seen: Option<u64>, policies_hook: bool, why: Why, warnings: &mut Vec<String>) {
    if seen.is_none() {
        st.firewalld = Rules::None;
        st.firewalld_seen = None;
        st.firewalld_blocked = false;
        return;
    }
    if st.firewalld_seen != seen || (st.firewalld.failed() && why != Why::Event) {
        st.firewalld_seen = seen;
        match sbin("firewall-cmd") {
            None => {
                eprintln!("kiri-init: firewalld runs, but there is no firewall-cmd to put Kiri's bridges in a Kiri zone");
                st.firewalld = Rules::Failed(ZONE_KIRI);
                st.firewalld_blocked = true;
            }
            Some(cmd) => {
                let (rules, blocked) = configure_firewalld(&cmd, policies_hook);
                st.firewalld = rules;
                st.firewalld_blocked = blocked;
            }
        }
    }
    if st.firewalld.failed() {
        warnings.push("firewalld: Kiri could not put its bridges (kiri+) in a firewalld zone, so firewalld may reject its containers' traffic; see the engine log".into());
    } else if st.firewalld_blocked {
        warnings.push("firewalld: Kiri could not install an ingress forwarding policy for kiri+, so published ports will be relayed in user space".into());
    }
}

/// The engine stopping: Kiri's rules out of iptables (where it put them)
/// and its bridges out of firewalld's zone, unless the administrator put
/// them there for good (the permanent configuration).
fn stop(st: &mut State) {
    for (backend, suffix) in ["-nft", "-legacy"].into_iter().enumerate() {
        for (i, tool) in ["iptables", "ip6tables"].into_iter().enumerate() {
            if (matches!(st.iptables[backend][i], Rules::In(_)) || st.input_dns[backend][i])
                && let Some(path) = sbin(&format!("{tool}{suffix}")).or_else(|| sbin(tool))
            {
                iptables_sync(&path, None, None, false);
            }
            st.iptables[backend][i] = Rules::None;
            st.input_dns[backend][i] = false;
        }
    }
    if let Rules::In(zone) = st.firewalld
        && let Some(cmd) = sbin("firewall-cmd")
    {
        let kept = run(&cmd, &["--permanent", &format!("--zone={zone}"), "--query-interface=kiri+"]).is_some_and(|o| o.trim() == "yes");
        if !kept && run(&cmd, &[&format!("--zone={zone}"), "--remove-interface=kiri+"]).is_none() {
            eprintln!("kiri-init: Kiri's bridges could not be taken out of firewalld's {zone} zone");
        }
    }
    st.firewalld = Rules::None;
    st.firewalld_seen = None;
    st.firewalld_blocked = false;
    st.forwarding_blocked = false;
    *netlink::FOREIGN_BRIDGES.lock().unwrap_or_else(|e| e.into_inner()) = Vec::new();
    write_warnings(st, String::new());
}

/// Runs an administrator's program; its output when it succeeded.
fn run(tool: &Path, args: &[&str]) -> Option<String> {
    let mut cmd = std::process::Command::new(tool);
    if tool.file_name().is_some_and(|n| n.to_string_lossy().contains("tables")) {
        // Waits for another program holding the xtables lock (ufw, Docker).
        cmd.args(["-w", "5"]);
    }
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Where the warnings go for `docker info`: a file in the agent's folder,
/// which the engine reads.
pub const WARNINGS_FILE: &str = "firewall-warnings";

fn write_warnings(st: &mut State, text: String) {
    if st.warnings == text {
        return;
    }
    if let Some(dir) = super::transport::host_dir() {
        let path = dir.join(WARNINGS_FILE);
        let _ = if text.is_empty() { std::fs::remove_file(path) } else { std::fs::write(path, &text) };
    }
    st.warnings = text;
}

/// An administrator's program (iptables) by name, wherever the host keeps
/// it: the agent's PATH may lack the sbin folders.
fn sbin(name: &str) -> Option<PathBuf> {
    let path = std::env::var("PATH").unwrap_or_default();
    path.split(':')
        .chain(["/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin", "/bin"])
        .filter(|d| !d.is_empty())
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(family: u8, table: &str, name: &str, hook: Option<u32>, policy: Option<u32>) -> Chain {
        Chain { family, table: table.into(), name: name.into(), handle: 1, hook, policy }
    }

    #[test]
    fn kiri_rules_accept_only_kiris_own_traffic() {
        let [out, replies, into] = kiri_rules();
        // New connections out of Kiri's bridges to any non-Kiri interface (VPNs, secondary NICs, WAN), replies anywhere.
        assert_eq!(out.join(" "), "-i kiri+ ! -o kiri+ -m comment --comment kiri -j ACCEPT");
        assert_eq!(replies.join(" "), "-i kiri+ -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment kiri -j ACCEPT");
        // Into Kiri's bridges, where Kiri's forward chain judges.
        assert_eq!(into.join(" "), "-o kiri+ -m comment --comment kiri -j ACCEPT");
    }

    #[test]
    fn a_host_without_a_firewall_needs_nothing() {
        let chains = [chain(2, "kiri", "forward", Some(2), Some(1)), chain(2, "kiri", "postrouting", Some(4), Some(1)), chain(10, "kiri", "forward", Some(2), Some(1))];
        assert_eq!(read_hook(&chains), Hook { kiri: [true, true], ..Hook::default() });
    }

    #[test]
    fn a_forward_policy_of_drop_gets_rules_at_the_top_of_forward() {
        // ufw (iptables-nft), or `iptables -P FORWARD DROP` by hand: no DOCKER-USER.
        let mut chains = vec![chain(2, "filter", "FORWARD", Some(2), Some(0)), chain(2, "filter", "ufw-before-forward", None, None), chain(10, "filter", "FORWARD", Some(2), Some(0))];
        assert_eq!(read_hook(&chains).iptables, [Some("FORWARD"), Some("FORWARD")]);
        assert!(read_hook(&chains).foreign.is_empty(), "iptables' own chain is not a foreign one");
        // IPv4 only, by hand.
        chains[2].policy = Some(1);
        assert_eq!(read_hook(&chains).iptables, [Some("FORWARD"), None]);
        // Policy accept: nothing.
        chains[0].policy = Some(1);
        assert_eq!(read_hook(&chains).iptables, [None, None]);
    }

    #[test]
    fn with_docker_the_rules_stay_in_docker_user() {
        let chains = [chain(2, "filter", "FORWARD", Some(2), Some(0)), chain(2, "filter", "DOCKER-USER", None, None)];
        assert_eq!(read_hook(&chains).iptables, [Some("DOCKER-USER"), None]);
        // Docker's chain is used even while FORWARD accepts (Docker started after Kiri turned forwarding on).
        let chains = [chain(2, "filter", "FORWARD", Some(2), Some(1)), chain(2, "filter", "DOCKER-USER", None, None)];
        assert_eq!(read_hook(&chains).iptables, [Some("DOCKER-USER"), None]);
    }

    #[test]
    fn firewalld_and_an_nftables_conf_of_ones_own_are_told_apart() {
        let mut fwd = chain(1, "firewalld", "filter_FORWARD", Some(2), Some(1));
        fwd.handle = 7;
        let mut zones = chain(1, "firewalld", "filter_FORWARD_POLICIES", None, None);
        zones.handle = 9;
        let own = chain(1, "filter", "forward", Some(2), Some(0));
        let own_input = chain(1, "filter", "input", Some(1), Some(0));
        let own_accepting = chain(2, "mine", "fwd", Some(2), Some(1));
        let h = read_hook(&[fwd, zones, own, own_input, own_accepting]);
        assert_eq!(h.firewalld, Some(7));
        assert!(h.firewalld_policies);
        assert_eq!(h.foreign, vec![(1, "filter".to_owned(), "forward".to_owned())]);
        assert_eq!(h.iptables, [None, None]);
    }

    #[test]
    fn kiris_lines_and_trailing_drops_and_input_drop_are_found_in_a_listing() {
        let listing = "-P INPUT DROP\n-P FORWARD DROP\n-N ufw-before-forward\n-A FORWARD -o kiri+ -m comment --comment kiri -j ACCEPT\n-A FORWARD -j ufw-before-forward\n-A ufw-before-forward -i kiri+ -j ACCEPT\n-A DOCKER-USER -i kiri+ ! -o kiri+ -m comment --comment \"kiri\" -j ACCEPT\n";
        assert_eq!(
            kiri_lines(listing),
            vec![
                ("FORWARD".to_owned(), "-o kiri+ -m comment --comment kiri -j ACCEPT".split(' ').map(String::from).collect()),
                ("DOCKER-USER".to_owned(), "-i kiri+ ! -o kiri+ -m comment --comment kiri -j ACCEPT".split(' ').map(String::from).collect()),
            ]
        );
        assert_eq!(listed_target(listing), Some("FORWARD"));
        assert!(listed_input_drop(listing));
        assert_eq!(listed_target("-P FORWARD DROP\n-N DOCKER-USER\n"), Some("DOCKER-USER"));
        assert_eq!(listed_target("-P FORWARD ACCEPT\n"), None);
        assert_eq!(listed_target("-P FORWARD ACCEPT\n-A FORWARD -j REJECT --reject-with icmp-host-prohibited\n"), Some("FORWARD"));
        assert_eq!(listed_target("-P FORWARD ACCEPT\n-A FORWARD -j DROP\n"), Some("FORWARD"));
        assert_eq!(listed_target("-P FORWARD ACCEPT\n-A FORWARD -s 10.0.0.1 -j DROP\n"), None);
    }

    #[test]
    fn rules_left_by_a_crashed_engine_are_reused_not_doubled() {
        let all = |chain: &str| kiri_rules().iter().map(|r| format!("-A {chain} {}\n", r.join(" "))).collect::<String>();
        let listing = format!("-P FORWARD DROP\n{}", all("FORWARD"));
        assert!(iptables_changes(&listing, Some("FORWARD"), false).is_empty());
        // One missing: only it is added.
        let partial: String = listing.lines().filter(|l| !l.contains("RELATED")).map(|l| format!("{l}\n")).collect();
        let changes = iptables_changes(&partial, Some("FORWARD"), false);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0][..3], ["-I", "FORWARD", "-i"]);
        assert!(changes[0].contains(&"RELATED,ESTABLISHED".to_owned()));
        // Stopping: all three out.
        let out = iptables_changes(&listing, None, false);
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|c| c[0] == "-D" && c[1] == "FORWARD"));
    }

    #[test]
    fn rules_in_the_wrong_chain_move_and_input_dns_tracks_drop_policy() {
        let all = |chain: &str| kiri_rules().iter().map(|r| format!("-A {chain} {}\n", r.join(" "))).collect::<String>();
        // Left in FORWARD; Docker came since: move to DOCKER-USER.
        let changes = iptables_changes(&all("FORWARD"), Some("DOCKER-USER"), false);
        assert_eq!(changes.iter().filter(|c| c[0] == "-D" && c[1] == "FORWARD").count(), 3);
        assert_eq!(changes.iter().filter(|c| c[0] == "-I" && c[1] == "DOCKER-USER").count(), 3);
        // Inserted last first, so they end up in order at the top.
        let changes = iptables_changes("-P FORWARD DROP\n", Some("FORWARD"), false);
        assert_eq!(changes.iter().map(|c| c[2].as_str()).collect::<Vec<_>>(), ["-o", "-i", "-i"]);
        // Old single-uplink rule left behind is replaced by `-i kiri+ ! -o kiri+`.
        let old = "-P FORWARD DROP\n-A FORWARD -i kiri+ -o eth0 -m comment --comment kiri -j ACCEPT\n";
        let changes = iptables_changes(old, Some("FORWARD"), false);
        assert!(changes.iter().any(|c| c[0] == "-D" && c.contains(&"eth0".to_owned())));
        assert!(changes.iter().any(|c| c[0] == "-I" && c.windows(3).any(|w| w == ["!", "-o", "kiri+"])));
        // Under ufw / INPUT DROP, DNS port 53 UDP/TCP rules are added in INPUT only and removed on stop.
        let dns_changes = iptables_changes("-P INPUT DROP\n-P FORWARD DROP\n", Some("FORWARD"), true);
        assert_eq!(dns_changes.iter().filter(|c| c[0] == "-I" && c[1] == "INPUT").count(), 2);
        assert!(dns_changes.iter().any(|c| c[1] == "INPUT" && c.contains(&"udp".to_owned()) && c.contains(&"53".to_owned())));
        assert!(dns_changes.iter().any(|c| c[1] == "INPUT" && c.contains(&"tcp".to_owned()) && c.contains(&"53".to_owned())));
        // Once in place, no duplicate DNS or FORWARD rules are added.
        let existing = format!(
            "-P INPUT DROP\n-P FORWARD DROP\n{}{}",
            all("FORWARD"),
            dns_input_rules().iter().map(|r| format!("-A INPUT {}\n", r.join(" "))).collect::<String>()
        );
        assert!(iptables_changes(&existing, Some("FORWARD"), true).is_empty());
        assert_eq!(iptables_changes(&existing, None, false).len(), 5);
    }

    #[test]
    fn advice_for_an_nftables_conf_uses_non_kiri_uplinks() {
        let a = foreign_advice(1, "filter", "forward");
        assert!(a.contains("nft insert rule inet filter forward iifname \"kiri*\" oifname != \"kiri*\" accept"));
        assert!(a.contains("nft insert rule inet filter forward iifname \"kiri*\" ct state established,related accept"));
        assert!(a.contains("nft insert rule inet filter forward oifname \"kiri*\" accept"));
        assert!(foreign_advice(10, "f", "fwd").contains("nft insert rule ip6 f fwd iifname \"kiri*\" oifname != \"kiri*\" accept"));
    }

    #[test]
    fn forwarding_blocked_reflects_foreign_iptables_or_firewalld_block() {
        assert!(!compute_forwarding_blocked(false, false, false));
        assert!(compute_forwarding_blocked(true, false, false));
        assert!(compute_forwarding_blocked(false, true, false));
        assert!(compute_forwarding_blocked(false, false, true));
    }
}
