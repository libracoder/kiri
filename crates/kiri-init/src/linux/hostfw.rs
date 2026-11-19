//! A Linux host's own firewall, where it would drop what Kiri forwards.
//!
//! Kiri's table accepts its containers' traffic, but every base chain on
//! the forward hook is traversed and a drop in any of them is final: an
//! accept in `table ip kiri` cannot overrule the `policy drop` that Docker
//! (when it turned forwarding on itself) or ufw gives iptables' FORWARD
//! chain. Containers on Kiri's bridges then have no internet, and their
//! DNS to the host's resolver times out (`lookup registry-1.docker.io on
//! 168.63.129.16:53: i/o timeout` from a BuildKit builder, #247).
//!
//! So on such a host Kiri adds two rules where that firewall will see them,
//! with the host's own `iptables` (legacy or nf_tables, as Docker does):
//!
//! ```text
//! -A DOCKER-USER -i kiri+ -o <uplink> -j ACCEPT   # out to the internet
//! -A DOCKER-USER -o kiri+ -j ACCEPT               # in: Kiri's table judges
//! ```
//!
//! in `DOCKER-USER`, the chain Docker keeps for rules of the host's own and
//! jumps to first, or else at the head of `FORWARD`. Into a Kiri bridge,
//! Kiri's forward chain still lets only replies, published ports and the
//! bridge's own traffic through; out, only to the uplink Kiri masquerades
//! on, so Docker's own containers stay as closed to Kiri's as Docker keeps
//! them. A host whose FORWARD policy is ACCEPT, without Docker, is left as
//! it is. The rules go when the engine stops.

use std::process::{Command, Stdio};
use std::sync::Mutex;

/// The tools for the IPv4 and the IPv6 table.
const TOOLS: [&str; 2] = ["iptables", "ip6tables"];
/// Docker's chain for the host's own rules, jumped to first from FORWARD.
const DOCKER_USER: &str = "DOCKER-USER";
const FORWARD: &str = "FORWARD";

/// The rules this engine put in (tool, chain, rule), to take out on stop.
static ADDED: Mutex<Vec<(&'static str, String, Vec<String>)>> = Mutex::new(Vec::new());

/// The rules Kiri needs for egress through `uplink`, as `iptables -S`
/// prints them after the chain name.
fn rules(uplink: &str) -> [Vec<String>; 2] {
    let r = |s: &str| s.split(' ').map(str::to_owned).collect::<Vec<_>>();
    [r(&format!("-i kiri+ -o {uplink} -j ACCEPT")), r("-o kiri+ -j ACCEPT")]
}

/// Where Kiri's rules go given the filter table as `iptables -S` lists it:
/// Docker's chain if there is one, FORWARD if its policy drops, else
/// nowhere (the host forwards what Kiri's own table lets through).
fn chain(listing: &str) -> Option<&'static str> {
    let lines = || listing.lines().map(str::trim);
    if lines().any(|l| l == format!("-N {DOCKER_USER}")) {
        Some(DOCKER_USER)
    } else if lines().any(|l| l == format!("-P {FORWARD} DROP")) {
        Some(FORWARD)
    } else {
        None
    }
}

/// The rules of `want` that `chain` in `listing` does not hold yet.
fn missing<'a>(listing: &str, chain: &str, want: &'a [Vec<String>]) -> Vec<&'a Vec<String>> {
    want.iter().filter(|rule| !listing.lines().any(|l| l.trim() == format!("-A {chain} {}", rule.join(" ")))).collect()
}

fn run(tool: &str, args: &[&str]) -> Option<String> {
    // -w: wait for the xtables lock rather than fail while Docker holds it.
    let out = Command::new(tool).arg("-w").args(args).stdin(Stdio::null()).stderr(Stdio::piped()).output().ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        eprintln!("kiri-init: {tool} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
        None
    }
}

/// Makes the host's firewall forward Kiri's containers' traffic through
/// `uplink`, if it would drop it. Without `iptables` there is nothing to do.
pub fn sync(uplink: &str) {
    let want = rules(uplink);
    for tool in TOOLS {
        let Some(listing) = run(tool, &["-S"]) else { continue };
        let Some(chain) = chain(&listing) else { continue };
        // Inserted last rule first, so they keep `rules`' order at the head.
        for rule in missing(&listing, chain, &want).into_iter().rev() {
            let mut args = vec!["-I", chain];
            args.extend(rule.iter().map(String::as_str));
            if run(tool, &args).is_some() {
                eprintln!("kiri-init: {tool}: the host's FORWARD chain may drop the containers' traffic; added to {chain}: {}", rule.join(" "));
            }
        }
        // Ours to take out on stop, also ones a previous run left behind.
        let mut added = ADDED.lock().unwrap_or_else(|e| e.into_inner());
        for rule in &want {
            if !added.iter().any(|(t, c, r)| *t == tool && c == chain && r == rule) {
                added.push((tool, chain.to_owned(), rule.clone()));
            }
        }
    }
}

/// Takes Kiri's rules out of the host's firewall again.
pub fn remove() {
    let added = std::mem::take(&mut *ADDED.lock().unwrap_or_else(|e| e.into_inner()));
    for (tool, chain, rule) in added {
        let mut args = vec!["-D", chain.as_str()];
        args.extend(rule.iter().map(String::as_str));
        // Quietly: one may be gone already (a flushed chain, a restarted Docker).
        let _ = Command::new(tool).arg("-w").args(&args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCKER: &str = "-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-N DOCKER-FORWARD\n-N DOCKER-USER\n-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER-FORWARD\n";
    const UFW: &str = "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-N ufw-before-forward\n-A FORWARD -j ufw-before-forward\n";
    const OPEN: &str = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n";

    #[test]
    fn docker_user_is_where_the_rules_go_when_docker_is_there() {
        assert_eq!(chain(DOCKER), Some(DOCKER_USER));
        // Docker that found forwarding on already left the policy ACCEPT; a
        // restart that finds it off would make it DROP: its chain anyway.
        assert_eq!(chain(&DOCKER.replace("-P FORWARD DROP", "-P FORWARD ACCEPT")), Some(DOCKER_USER));
    }

    #[test]
    fn forward_when_its_policy_drops_without_docker() {
        assert_eq!(chain(UFW), Some(FORWARD));
    }

    #[test]
    fn a_host_that_forwards_is_left_alone() {
        assert_eq!(chain(OPEN), None);
        assert_eq!(chain(""), None);
    }

    #[test]
    fn egress_only_to_the_uplink_and_ingress_left_to_kiris_table() {
        let [out, back] = rules("eth0");
        assert_eq!(out.join(" "), "-i kiri+ -o eth0 -j ACCEPT");
        assert_eq!(back.join(" "), "-o kiri+ -j ACCEPT");
    }

    #[test]
    fn rules_already_there_are_not_added_twice() {
        let want = rules("eth0");
        assert_eq!(missing(DOCKER, DOCKER_USER, &want).len(), 2);
        let one = format!("{DOCKER}-A DOCKER-USER -o kiri+ -j ACCEPT\n");
        assert_eq!(missing(&one, DOCKER_USER, &want), vec![&want[0]]);
        let both = format!("{one}-A DOCKER-USER -i kiri+ -o eth0 -j ACCEPT\n");
        assert!(missing(&both, DOCKER_USER, &want).is_empty());
        // The same rule in another chain, or for another uplink, is not it.
        let elsewhere = format!("{DOCKER}-A FORWARD -o kiri+ -j ACCEPT\n-A DOCKER-USER -i kiri+ -o wlan0 -j ACCEPT\n");
        assert_eq!(missing(&elsewhere, DOCKER_USER, &want).len(), 2);
    }
}
