//! `kiri scan <image>`: scan an image in Kiri's store for known
//! vulnerabilities from the terminal. The same scan the window's Security
//! tab runs (`crate::scan`): Grype reads the image through an OCI layout of
//! the store's own blobs, so the VM isn't woken and nothing is uploaded.
//! The first scan downloads Grype and its database (about 230 MB, 3 GB
//! unpacked), kept for every scan after.
//!
//! On Windows this runs inside WSL by the engine's own `kiri` (`wsl.rs`).
//! On a Linux host running the `kiri` system service (`/run/kiri/docker.sock`),
//! a user without direct access to `/var/lib/kiri-daemon` scans through the
//! daemon's `/kiri/images/scan` and `/kiri/images/scans` endpoints.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io;
use std::time::{Duration, UNIX_EPOCH};

use serde_json::{Map, Value};

const USAGE: &str = "usage: kiri scan [--json] [--history] <image>";

const SEVERITIES: [&str; 6] = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"];

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Help,
    Scan { image: String, json: bool },
    History { image: String, json: bool },
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

fn parse(args: &[String]) -> Result<Action, String> {
    let mut json = false;
    let mut history = false;
    let mut names: Vec<String> = Vec::new();
    for a in args {
        match a.as_str() {
            "--json" => json = true,
            "--history" => history = true,
            "-h" | "--help" => return Ok(Action::Help),
            s if s.starts_with('-') => return Err(format!("unknown flag {s}; {USAGE}")),
            s if s.trim().is_empty() => return Err(USAGE.to_owned()),
            s => names.push(s.to_owned()),
        }
    }
    let Some(image) = names.first().cloned() else {
        return Err(USAGE.to_owned());
    };
    if names.len() > 1 {
        return Err(format!("one image at a time; {USAGE}"));
    }
    if history {
        Ok(Action::History { image, json })
    } else {
        Ok(Action::Scan { image, json })
    }
}

/// Strips ANSI CSI escape sequences and control characters from untrusted
/// image metadata before printing to a terminal.
fn sanitize(s: &str) -> String {
    let stripped = crate::scan::strip_ansi(s);
    let mut out = String::with_capacity(stripped.len());
    for c in stripped.chars() {
        if c == '\r' || c == '\n' || c == '\t' {
            out.push(' ');
        } else if !c.is_control() {
            out.push(c);
        }
    }
    out
}

/// When a scan was run, in UTC for the history table: `2026-11-16 20:07 UTC`.
fn stamp(at: u64) -> String {
    let Some(t) = UNIX_EPOCH.checked_add(Duration::from_secs(at)) else {
        return at.to_string();
    };
    let r = crate::daemon::time::rfc3339(t);
    match r.get(..16) {
        Some(prefix) => format!("{} UTC", prefix.replace('T', " ")),
        None => r,
    }
}

/// Formats severity counts worst-first (`1 Critical, 3 Medium`) or
/// `no vulnerabilities found` when none are present.
fn format_counts(mut counts: BTreeMap<String, u64>) -> String {
    let mut parts = Vec::new();
    for s in SEVERITIES {
        if let Some(n) = counts.remove(s).filter(|&n| n > 0) {
            parts.push(format!("{n} {s}"));
        }
    }
    // Any severity Grype may add later, sorted after the known list.
    for (s, n) in counts {
        if n > 0 {
            parts.push(format!("{n} {}", sanitize(&s)));
        }
    }
    if parts.is_empty() {
        "no vulnerabilities found".to_owned()
    } else {
        parts.join(", ")
    }
}

/// The severity counts from a report's `vulns` list, worst first.
fn count_line(vulns: &[Value]) -> String {
    let mut counts = BTreeMap::new();
    for v in vulns {
        let s = v["severity"].as_str().unwrap_or("Unknown").to_owned();
        *counts.entry(s).or_insert(0u64) += 1;
    }
    format_counts(counts)
}

/// The severity counts from a saved history summary's `counts` object, worst first.
fn count_line_from_map(map: Option<&Map<String, Value>>) -> String {
    let mut counts = BTreeMap::new();
    if let Some(obj) = map {
        for (k, v) in obj {
            if let Some(n) = v.as_u64()
                && n > 0
            {
                *counts.entry(k.clone()).or_insert(0u64) += n;
            }
        }
    }
    format_counts(counts)
}

/// Formats `scan::history`'s output as a table, newest scan first.
pub(crate) fn format_history(h: &Value) -> io::Result<String> {
    let scans = h["scans"].as_array().ok_or_else(|| io::Error::other("no scans"))?;
    if scans.is_empty() {
        return Ok("no scans yet\n".to_owned());
    }
    let rows: Vec<(String, String, u64, u64, u64)> = scans
        .iter()
        .map(|s| {
            (
                stamp(s["scanned"].as_u64().unwrap_or(0)),
                count_line_from_map(s["counts"].as_object()),
                s["vulns"].as_u64().unwrap_or(0),
                s["fixable"].as_u64().unwrap_or(0),
                s["packages"].as_u64().unwrap_or(0),
            )
        })
        .collect();
    let w_scanned = rows.iter().map(|r| r.0.len()).max().unwrap_or(0).max("scanned".len());
    let w_found = rows.iter().map(|r| r.1.len()).max().unwrap_or(0).max("found".len());
    let mut out = String::new();
    let _ = writeln!(out, "{:<w_scanned$}  {:<w_found$}  {:>6}  {:>7}  {:>8}", "scanned", "found", "vulns", "fixable", "packages");
    for (when, counts, vulns, fixable, packages) in rows {
        let _ = writeln!(out, "{when:<w_scanned$}  {counts:<w_found$}  {vulns:>6}  {fixable:>7}  {packages:>8}");
    }
    Ok(out)
}

/// Formats `scan::scan`'s report: summary counts first, then one aligned row
/// per finding, worst severity first as `crate::scan` ordered them.
pub(crate) fn format_report(name: &str, report: &Value) -> io::Result<String> {
    let vulns = report["vulns"].as_array().ok_or_else(|| io::Error::other("the scan wrote no report"))?;
    let packages = report["packages"].as_u64().unwrap_or(0);
    let fixable = vulns.iter().filter(|v| v["fixed"].as_array().is_some_and(|f| !f.is_empty())).count();
    let db = sanitize(report["db"].as_str().unwrap_or(""));
    let display_name = sanitize(name);
    let mut out = String::new();
    let _ = write!(
        out,
        "{display_name}: {packages} package{}, {} finding{}, {fixable} with a fix available",
        if packages == 1 { "" } else { "s" },
        vulns.len(),
        if vulns.len() == 1 { "" } else { "s" },
    );
    if !db.is_empty() {
        let _ = write!(out, ", database built {db}");
    }
    out.push('\n');
    let _ = writeln!(out, "{}", count_line(vulns));
    if vulns.is_empty() {
        return Ok(out);
    }
    let rows: Vec<[String; 5]> = vulns
        .iter()
        .map(|v| {
            let sev = sanitize(v["severity"].as_str().unwrap_or("Unknown"));
            let id = sanitize(v["id"].as_str().unwrap_or(""));
            let pkg = sanitize(v["package"].as_str().unwrap_or(""));
            let kind = sanitize(v["kind"].as_str().unwrap_or(""));
            let package = if kind.is_empty() { pkg } else { format!("{pkg} ({kind})") };
            let version = sanitize(v["version"].as_str().unwrap_or(""));
            let fixed: Vec<String> = v["fixed"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(sanitize)
                .filter(|s| !s.is_empty())
                .collect();
            let fix = if fixed.is_empty() { "-".to_owned() } else { format!("fixed in {}", fixed.join(", ")) };
            [sev, id, package, version, fix]
        })
        .collect();
    let w0 = rows.iter().map(|r| r[0].len()).max().unwrap_or(0).max("severity".len());
    let w1 = rows.iter().map(|r| r[1].len()).max().unwrap_or(0).max("vulnerability".len());
    let w2 = rows.iter().map(|r| r[2].len()).max().unwrap_or(0).max("package".len());
    let w3 = rows.iter().map(|r| r[3].len()).max().unwrap_or(0).max("version".len());
    out.push('\n');
    let _ = writeln!(out, "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  fix", "severity", "vulnerability", "package", "version");
    for [sev, id, pkg, ver, fix] in rows {
        let _ = writeln!(out, "{sev:<w0$}  {id:<w1$}  {pkg:<w2$}  {ver:<w3$}  {fix}");
    }
    Ok(out)
}

/// On a Linux host running `kiri.service`, the store lives under
/// `/var/lib/kiri-daemon` (root-owned); regular users scan via the daemon's
/// socket instead of reading `~/.local/share/kiri`.
#[cfg(target_os = "linux")]
fn use_service_daemon() -> bool {
    std::env::var_os("KIRI_DATA_DIR").is_none()
        && std::env::var_os("KIRI_SOCKET").is_none()
        && std::env::var_os("HOME").as_deref() != Some(std::ffi::OsStr::new("/var/lib/kiri-daemon"))
        && std::path::Path::new(crate::client::SERVICE_SOCKET).exists()
        && crate::client::alive()
}

#[cfg(target_os = "linux")]
fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn daemon_history(name: &str) -> io::Result<Value> {
    crate::client::get(&format!("/kiri/images/scans?name={}", query_escape(name)))
}

#[cfg(target_os = "linux")]
fn daemon_scan(name: &str, progress: &mut dyn FnMut(&str, u8)) -> io::Result<Value> {
    let mut end = None;
    let status = crate::client::post_lines_unbounded(&format!("/kiri/images/scan?name={}", query_escape(name)), |v| {
        if let Some(phase) = v["phase"].as_str() {
            progress(phase, v["pct"].as_u64().unwrap_or(0).min(100) as u8);
        } else if let Some(e) = v["error"].as_str() {
            end = Some(Err(io::Error::other(e.to_owned())));
        } else if let Some(m) = v["message"].as_str() {
            end = Some(Err(io::Error::other(m.to_owned())));
        } else if v.get("result").is_some() {
            end = Some(Ok(v["result"].clone()));
        }
    })?;
    if !(200..300).contains(&status) {
        return Err(io::Error::other(format!("scan failed (HTTP {status})")));
    }
    end.unwrap_or_else(|| Err(io::Error::other("the scan stopped before it finished")))
}

fn run_history(name: &str) -> io::Result<Value> {
    #[cfg(target_os = "linux")]
    if use_service_daemon() {
        return daemon_history(name);
    }
    crate::scan::history(name)
}

fn run_scan(name: &str, progress: &mut dyn FnMut(&str, u8)) -> io::Result<Value> {
    #[cfg(target_os = "linux")]
    if use_service_daemon() {
        return daemon_scan(name, progress);
    }
    crate::scan::scan(name, progress)
}

/// Runs `kiri scan [--json] [--history] <image>`.
pub fn run(args: &[String]) -> io::Result<()> {
    match parse(args).map_err(invalid)? {
        Action::Help => {
            println!(
                "{USAGE}\n       --json     the full report, as JSON\n       --history  the image's kept scans, newest first, without scanning again"
            );
            Ok(())
        }
        Action::History { image, json } => {
            let h = run_history(&image)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&h).map_err(io::Error::other)?);
                return Ok(());
            }
            print!("{}", format_history(&h)?);
            Ok(())
        }
        Action::Scan { image, json } => {
            let mut last = (String::new(), 255u8);
            let report = run_scan(&image, &mut |phase, pct| {
                if (pct == 0 || pct == 100) && (phase, pct) != (last.0.as_str(), last.1) {
                    last = (phase.to_owned(), pct);
                    eprintln!("{phase} {pct}%");
                }
            })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report).map_err(io::Error::other)?);
                return Ok(());
            }
            print!("{}", format_report(&image, &report)?);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn parses_scan_flags_and_image() {
        assert_eq!(parse(&argv("alpine:latest")), Ok(Action::Scan { image: "alpine:latest".into(), json: false }));
        assert_eq!(parse(&argv("--json alpine:latest")), Ok(Action::Scan { image: "alpine:latest".into(), json: true }));
        assert_eq!(parse(&argv("alpine:latest --json")), Ok(Action::Scan { image: "alpine:latest".into(), json: true }));
        assert_eq!(parse(&argv("--history alpine:latest")), Ok(Action::History { image: "alpine:latest".into(), json: false }));
        assert_eq!(parse(&argv("--history --json alpine:latest")), Ok(Action::History { image: "alpine:latest".into(), json: true }));
        assert_eq!(parse(&argv("alpine --json --history")), Ok(Action::History { image: "alpine".into(), json: true }));
        assert_eq!(parse(&argv("-h")), Ok(Action::Help));
        assert_eq!(parse(&argv("--help")), Ok(Action::Help));
    }

    #[test]
    fn rejects_invalid_flags_and_missing_or_extra_images() {
        assert_eq!(parse(&[]).unwrap_err(), USAGE);
        assert_eq!(parse(&argv("--json")).unwrap_err(), USAGE);
        assert_eq!(parse(&argv("--history")).unwrap_err(), USAGE);
        assert_eq!(parse(&["".to_owned()]).unwrap_err(), USAGE);
        assert_eq!(parse(&["   ".to_owned()]).unwrap_err(), USAGE);

        let bad_flag = parse(&argv("--bogus alpine")).unwrap_err();
        assert!(bad_flag.starts_with("unknown flag --bogus;"), "{bad_flag}");
        assert!(bad_flag.contains(USAGE), "{bad_flag}");

        let short_flag = parse(&argv("-q alpine")).unwrap_err();
        assert!(short_flag.starts_with("unknown flag -q;"), "{short_flag}");

        let extra = parse(&argv("alpine nginx")).unwrap_err();
        assert!(extra.starts_with("one image at a time;"), "{extra}");
    }

    #[test]
    fn not_a_docker_command() {
        assert!(!crate::docker::handles("scan"));
    }

    #[test]
    fn counts_worst_first_and_empty() {
        let vulns = json!([
            {"severity": "Negligible"},
            {"severity": "Medium"},
            {"severity": "Critical"},
            {"severity": "Low"},
            {"severity": "Medium"},
            {"severity": "High"},
            {"severity": "Unknown"},
        ]);
        assert_eq!(
            count_line(vulns.as_array().unwrap()),
            "1 Critical, 1 High, 2 Medium, 1 Low, 1 Negligible, 1 Unknown"
        );
        assert_eq!(count_line(&[]), "no vulnerabilities found");
    }

    #[test]
    fn formats_report_table_all_severities_with_and_without_fixes() {
        let report = json!({
            "id": "sha256:0000000000000000000000000000000000000000000000000000000000000001",
            "scanned": 1_794_859_620u64,
            "packages": 14,
            "db": "2026-11-16T00:00:00Z",
            "grype": "0.120.1",
            "vulns": [
                {"id": "CVE-2026-0001", "severity": "Critical", "package": "openssl", "kind": "apk", "version": "3.1.0-r0", "fixed": ["3.1.1-r0"]},
                {"id": "CVE-2026-0002", "severity": "High", "package": "zlib", "kind": "apk", "version": "1.3.0", "fixed": ["1.3.1", "1.3.2"]},
                {"id": "CVE-2026-0003", "severity": "Medium", "package": "busybox", "kind": "apk", "version": "1.36.1", "fixed": []},
                {"id": "CVE-2026-0004", "severity": "Low", "package": "curl", "kind": "", "version": "8.4.0", "fixed": ["8.5.0"]},
                {"id": "CVE-2026-0005", "severity": "Negligible", "package": "musl", "kind": "apk", "version": "1.2.4", "fixed": []},
            ]
        });
        let out = format_report("alpine:3.21", &report).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines[0],
            "alpine:3.21: 14 packages, 5 findings, 3 with a fix available, database built 2026-11-16T00:00:00Z"
        );
        assert_eq!(lines[1], "1 Critical, 1 High, 1 Medium, 1 Low, 1 Negligible");
        assert_eq!(lines[2], "");
        assert!(lines[3].starts_with("severity"), "{}", lines[3]);
        assert!(lines[4].contains("Critical") && lines[4].contains("CVE-2026-0001") && lines[4].contains("openssl (apk)") && lines[4].ends_with("fixed in 3.1.1-r0"));
        assert!(lines[5].contains("High") && lines[5].ends_with("fixed in 1.3.1, 1.3.2"));
        assert!(lines[6].contains("Medium") && lines[6].ends_with("  -"));
        assert!(lines[7].contains("Low") && lines[7].contains("curl") && !lines[7].contains("curl ()") && lines[7].ends_with("fixed in 8.5.0"));
        assert!(lines[8].contains("Negligible") && lines[8].ends_with("  -"));
    }

    #[test]
    fn formats_clean_report_and_singular_counts() {
        let report = json!({
            "packages": 1,
            "db": "",
            "vulns": []
        });
        let out = format_report("scratch:latest", &report).unwrap();
        assert_eq!(out, "scratch:latest: 1 package, 0 findings, 0 with a fix available\nno vulnerabilities found\n");
    }

    #[test]
    fn sanitizes_control_and_ansi_sequences_in_table() {
        let report = json!({
            "packages": 1,
            "db": "2026-11-16\x1b[31m",
            "vulns": [{
                "id": "CVE-1\nFAKE",
                "severity": "High",
                "package": "\x1b[31mevil\x1b[0m",
                "kind": "apk",
                "version": "1.0\r",
                "fixed": ["1.1\x07"]
            }]
        });
        let out = format_report("img\x1b[2J:1", &report).unwrap();
        assert!(!out.contains('\x1b'), "escape sequence leaked: {out:?}");
        assert!(!out.contains('\r'), "CR leaked: {out:?}");
        assert!(!out.contains('\x07'), "BEL leaked: {out:?}");
        assert!(out.contains("CVE-1 FAKE"), "newline not flattened: {out}");
        assert!(out.contains("evil (apk)"), "ANSI not stripped: {out}");
    }

    #[test]
    fn formats_history_worst_first_and_empty() {
        let empty = json!({"id": "sha256:0", "scans": []});
        assert_eq!(format_history(&empty).unwrap(), "no scans yet\n");

        let history = json!({
            "id": "sha256:0",
            "scans": [
                {
                    "scanned": 1_794_859_620u64,
                    "counts": {"Low": 1, "Critical": 2, "Medium": 3, "High": 1},
                    "vulns": 7,
                    "fixable": 4,
                    "packages": 20
                },
                {
                    "scanned": 1_794_773_220u64,
                    "counts": {},
                    "vulns": 0,
                    "fixable": 0,
                    "packages": 20
                }
            ]
        });
        let out = format_history(&history).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "{out}");
        assert!(lines[0].contains("scanned") && lines[0].contains("found") && lines[0].contains("packages"));
        // Worst-first order: Critical before High before Medium before Low (not alphabetical!).
        assert!(lines[1].contains("2026-11-16 20:07 UTC"), "{}", lines[1]);
        assert!(lines[1].contains("2 Critical, 1 High, 3 Medium, 1 Low"), "{}", lines[1]);
        assert!(lines[2].contains("no vulnerabilities found"), "{}", lines[2]);
    }

    #[test]
    fn stamp_never_panics_on_extreme_values() {
        assert_eq!(stamp(0), "1970-01-01 00:00 UTC");
        assert_eq!(stamp(u64::MAX), u64::MAX.to_string());
    }
}
