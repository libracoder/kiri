//! `kiri scan <image>`: scan an image in Kiri's store for known
//! vulnerabilities, without the daemon. The same scan the window's Security
//! tab runs (crate::scan): Grype reads the image through an OCI layout of
//! the store's own blobs, so the VM isn't woken and nothing is uploaded.
//! The first scan downloads Grype and its database (about 230 MB, 3 GB
//! unpacked), kept for every scan after.

use std::io;

use serde_json::Value;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

/// When a scan was run, for the history table: `2026-11-16 20:07`.
fn stamp(at: u64) -> String {
    let r = crate::daemon::time::rfc3339(std::time::UNIX_EPOCH + std::time::Duration::from_secs(at));
    r[..16].replace('T', " ")
}

/// The severity counts as one line, worst first, in crate::scan's order:
/// `1 Critical, 3 Medium`, or `no vulnerabilities found`.
fn count_line(vulns: &[Value]) -> String {
    let mut counts = std::collections::BTreeMap::new();
    for v in vulns {
        let s = v["severity"].as_str().unwrap_or("Unknown").to_owned();
        *counts.entry(s).or_insert(0u64) += 1;
    }
    let mut parts = Vec::new();
    for s in ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"] {
        if let Some(n) = counts.remove(s).filter(|n| *n > 0) {
            parts.push(format!("{n} {s}"));
        }
    }
    // A severity grype may add some day, after this list.
    for (s, n) in counts {
        if n > 0 {
            parts.push(format!("{n} {s}"));
        }
    }
    if parts.is_empty() { "no vulnerabilities found".to_owned() } else { parts.join(", ") }
}

const USAGE: &str = "usage: kiri scan [--json] [--history] <image>";

/// One of the image's scans, printed: `kiri scan` runs a fresh one and
/// `--history` lists the ones kept (the newest KEEP, crate::scan).
pub fn run(args: &[String]) -> io::Result<()> {
    let mut json = false;
    let mut history = false;
    let mut names: Vec<String> = Vec::new();
    for a in args {
        match a.as_str() {
            "--json" => json = true,
            "--history" => history = true,
            "-h" | "--help" => {
                println!("{USAGE}\n       --json     the full report, as JSON\n       --history  the image's kept scans, newest first, without scanning again");
                return Ok(());
            }
            s if s.starts_with('-') => return Err(invalid(format!("unknown flag {s}; {USAGE}"))),
            s => names.push(s.to_owned()),
        }
    }
    let name = names.first().ok_or_else(|| invalid(USAGE))?.to_owned();
    if names.len() > 1 {
        return Err(invalid(format!("one image at a time; {USAGE}")));
    }
    if history {
        let h = crate::scan::history(&name)?;
        if json {
            println!("{}", serde_json::to_string_pretty(&h).map_err(io::Error::other)?);
            return Ok(());
        }
        return print_history(&h);
    }
    let report = crate::scan::scan(&name, &mut |phase, pct| {
        if pct == 0 || pct == 100 {
            eprintln!("{phase} {pct}%");
        }
    })?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report).map_err(io::Error::other)?);
        return Ok(());
    }
    print_report(&name, &report)
}

fn print_history(h: &serde_json::Value) -> io::Result<()> {
    let scans = h["scans"].as_array().ok_or_else(|| io::Error::other("no scans"))?;
    if scans.is_empty() {
        println!("no scans yet");
        return Ok(());
    }
    println!("{0:<25} {1:<30} {2:>6} {3:>8} {4:>9}", "scanned", "found", "vulns", "fixable", "packages");
    for s in scans {
        let counts = s["counts"].as_object().map(|c| {
            c.iter().filter(|(_, n)| n.as_u64().unwrap_or(0) > 0).map(|(k, n)| format!("{n} {k}")).collect::<Vec<_>>().join(", ")
        }).unwrap_or_default();
        println!(
            "{0:<25} {1:<30} {2:>6} {3:>8} {4:>9}",
            stamp(s["scanned"].as_u64().unwrap_or(0)),
            counts,
            s["vulns"].as_u64().unwrap_or(0),
            s["fixable"].as_u64().unwrap_or(0),
            s["packages"].as_u64().unwrap_or(0),
        );
    }
    Ok(())
}

/// The summary a scan prints: the counts first, then one row per finding,
/// worst severity first as crate::scan ordered them.
fn print_report(name: &str, report: &serde_json::Value) -> io::Result<()> {
    let vulns = report["vulns"].as_array().ok_or_else(|| io::Error::other("the scan wrote no report"))?;
    let fixable = vulns.iter().filter(|v| v["fixed"].as_array().is_some_and(|f| !f.is_empty())).count();
    let db = report["db"].as_str().unwrap_or("").to_owned();
    println!(
        "{name}: {} packages, {} finding{}, {} with a fix available, database built {}",
        report["packages"].as_u64().unwrap_or(0),
        vulns.len(),
        if vulns.len() == 1 { "" } else { "s" },
        fixable,
        db,
    );
    let counts = count_line(vulns);
    println!("{counts}");
    if vulns.is_empty() {
        return Ok(());
    }
    println!();
    println!("{0:<12} {1:<34} {2:<22} {3:<18} fix", "severity", "vulnerability", "package", "version");
    for v in vulns {
        let fixed = v["fixed"].as_array().map(|f| f.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default();
        println!(
            "{0:<12} {1:<34} {2:<22} {3:<18} {4}",
            v["severity"].as_str().unwrap_or("Unknown"),
            v["id"].as_str().unwrap_or(""),
            format!("{} ({})", v["package"].as_str().unwrap_or(""), v["kind"].as_str().unwrap_or("")),
            v["version"].as_str().unwrap_or(""),
            if fixed.is_empty() { "-".to_owned() } else { format!("fixed in {fixed}") },
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::count_line;
    use serde_json::json;

    #[test]
    fn counts_worst_first() {
        let vulns = json!([
            {"severity": "Medium"},
            {"severity": "Critical"},
            {"severity": "Medium"},
            {"severity": "High"},
        ]);
        assert_eq!(count_line(vulns.as_array().unwrap()), "1 Critical, 1 High, 2 Medium");
    }

    #[test]
    fn counts_empty() {
        assert_eq!(count_line(&[]), "no vulnerabilities found");
    }
}
