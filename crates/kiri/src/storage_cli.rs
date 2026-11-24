//! `kiri storage`: show storage location, VM disk usage, and reclaim unused VM
//! disk space back to the host (`kiri storage reclaim`, #879).

use std::io;

use serde_json::Value;

use crate::client;

const USAGE: &str = "\
usage: kiri storage [status]   show storage location, disk usage, and reclaimable space
       kiri storage reclaim    reclaim unused VM disk space back to the host";

#[derive(Debug, PartialEq, Eq)]
enum Cmd {
    Help,
    Status,
    Reclaim,
}

fn parse(args: &[String]) -> Result<Cmd, String> {
    match args.first().map(String::as_str) {
        None => Ok(Cmd::Status),
        Some("status") if args.len() == 1 => Ok(Cmd::Status),
        Some("reclaim") if args.len() == 1 => Ok(Cmd::Reclaim),
        Some("-h" | "--help" | "help") if args.len() == 1 => Ok(Cmd::Help),
        Some("reclaim") if args.len() == 2 && matches!(args[1].as_str(), "-h" | "--help") => Ok(Cmd::Help),
        Some("status") if args.len() == 2 && matches!(args[1].as_str(), "-h" | "--help") => Ok(Cmd::Help),
        _ => Err(USAGE.into()),
    }
}

fn format_bytes(bytes: u64) -> String {
    const GB: f64 = 1e9;
    const MB: f64 = 1e6;
    const KB: f64 = 1e3;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.1} GB", b / GB)
    } else if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{bytes} B")
    }
}

fn format_limit(bytes: u64) -> String {
    const GIB: u64 = 1 << 30;
    if bytes > 0 && bytes % GIB == 0 {
        format!("{} GB", bytes / GIB)
    } else {
        format_bytes(bytes)
    }
}

fn host_label() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(windows) {
        "Windows"
    } else {
        "host"
    }
}

fn format_status(v: &Value, host: &str) -> String {
    let mut out = String::new();
    let path = v["path"].as_str().unwrap_or("");
    let state = v["state"].as_str().unwrap_or("ok");
    let mut tags = Vec::new();
    if v["env"] == true {
        tags.push("KIRI_DATA_DIR".to_owned());
    } else if v["custom"] == true {
        tags.push("custom".to_owned());
    } else {
        tags.push("default".to_owned());
    }
    if let Some(fs) = v["fs"].as_str().filter(|s| !s.is_empty()) {
        let pretty = if fs.eq_ignore_ascii_case("apfs") {
            "APFS".to_owned()
        } else if fs.eq_ignore_ascii_case("ntfs") {
            "NTFS".to_owned()
        } else {
            fs.to_owned()
        };
        tags.push(pretty);
    }
    if state == "unavailable" {
        out.push_str(&format!("Location         {path} (unavailable)\n"));
        return out;
    }
    out.push_str(&format!("Location         {path} ({})\n", tags.join(", ")));
    if let Some(limit) = v["disk_limit"].as_u64() {
        out.push_str(&format!("Disk limit       {}\n", format_limit(limit)));
    }
    if let Some(disk_host) = v["disk_host"].as_u64() {
        if let Some(in_use) = v["disk_in_use"].as_u64() {
            out.push_str(&format!("Used in VM       {}\n", format_bytes(in_use)));
        } else {
            out.push_str("Used in VM       asleep (run `kiri storage reclaim` to trim)\n");
        }
        let taken_label = format!("Taken on {host}");
        let detail = match (v["reclaimable"].as_u64(), v["disk_in_use"].as_u64()) {
            (Some(r), _) if r > 0 => format!("   {} reclaimable", format_bytes(r)),
            (Some(0), Some(_)) => "   nothing to reclaim".to_owned(),
            _ => String::new(),
        };
        out.push_str(&format!("{taken_label:<17}{}{detail}\n", format_bytes(disk_host)));
    } else {
        if let Some(used) = v["used"].as_u64() {
            out.push_str(&format!("Used             {}\n", format_bytes(used)));
        }
        if let Some(free) = v["free"].as_u64() {
            out.push_str(&format!("Free             {}\n", format_bytes(free)));
        }
    }
    out
}

fn format_reclaim(v: &Value, host: &str) -> String {
    if v["native"] == true {
        let msg = v["message"]
            .as_str()
            .unwrap_or("Native Linux uses the host filesystem directly — deleted images and volumes free space immediately.");
        return format!("{msg}\n");
    }
    let before = v["before"].as_u64().unwrap_or(0);
    let after = v["after"].as_u64().unwrap_or(0);
    let reclaimed = v["reclaimed"].as_u64().unwrap_or_else(|| before.saturating_sub(after));
    let elapsed_s = v["elapsed_ms"].as_u64().unwrap_or(0) as f64 / 1000.0;
    if reclaimed > 0 {
        format!(
            "Reclaimed {} in {:.1} s ({} → {} on {host}).\n",
            format_bytes(reclaimed),
            elapsed_s,
            format_bytes(before),
            format_bytes(after)
        )
    } else {
        format!(
            "Nothing to reclaim ({} on {host}, checked in {:.1} s).\n",
            format_bytes(after),
            elapsed_s
        )
    }
}

pub fn run(args: &[String]) -> io::Result<()> {
    let cmd = parse(args).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if cmd == Cmd::Help {
        println!("{USAGE}");
        return Ok(());
    }
    client::check_alive()?;
    match cmd {
        Cmd::Help => unreachable!(),
        Cmd::Status => {
            let v = client::get_background("/kiri/storage")?;
            print!("{}", format_status(&v, host_label()));
            Ok(())
        }
        Cmd::Reclaim => {
            let r = client::request("POST", "/kiri/storage/reclaim", None)?;
            if !r.ok() {
                return Err(io::Error::other(r.error()));
            }
            print!("{}", format_reclaim(&r.json(), host_label()));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn parses_status_reclaim_and_help() {
        assert_eq!(parse(&[]), Ok(Cmd::Status));
        assert_eq!(parse(&args("status")), Ok(Cmd::Status));
        assert_eq!(parse(&args("reclaim")), Ok(Cmd::Reclaim));
        assert_eq!(parse(&args("--help")), Ok(Cmd::Help));
        assert_eq!(parse(&args("-h")), Ok(Cmd::Help));
        assert_eq!(parse(&args("help")), Ok(Cmd::Help));
        assert_eq!(parse(&args("reclaim --help")), Ok(Cmd::Help));
        assert_eq!(parse(&args("status -h")), Ok(Cmd::Help));
        for bad in ["bogus", "status extra", "reclaim --now"] {
            assert!(parse(&args(bad)).unwrap_err().starts_with("usage:"), "{bad}");
        }
    }

    #[test]
    fn not_a_docker_command() {
        assert!(!crate::docker::handles("storage"));
    }

    #[test]
    fn formats_macos_and_linux_status_and_reclaim() {
        let mac = format_status(
            &json!({
                "path": "/Users/me/.kiri/data",
                "custom": false,
                "env": false,
                "state": "ok",
                "fs": "apfs",
                "disk_limit": 64u64 << 30,
                "disk_host": 29_400_000_000u64,
                "disk_in_use": 17_300_000_000u64,
                "reclaimable": 12_100_000_000u64,
            }),
            "macOS",
        );
        assert!(mac.contains("Location         /Users/me/.kiri/data (default, APFS)"), "{mac}");
        assert!(mac.contains("Disk limit       64 GB"), "{mac}");
        assert!(mac.contains("Used in VM       17.3 GB"), "{mac}");
        assert!(mac.contains("Taken on macOS   29.4 GB   12.1 GB reclaimable"), "{mac}");

        let clean = format_status(
            &json!({
                "path": "/Users/me/.kiri/data",
                "custom": false,
                "env": false,
                "state": "ok",
                "fs": "apfs",
                "disk_host": 17_400_000_000u64,
                "disk_in_use": 17_300_000_000u64,
                "reclaimable": 0u64,
            }),
            "macOS",
        );
        assert!(clean.contains("nothing to reclaim"), "{clean}");

        let linux = format_status(
            &json!({
                "path": "/var/lib/kiri",
                "custom": false,
                "env": false,
                "state": "ok",
                "fs": "ext4",
                "used": 4_200_000_000u64,
                "free": 120_000_000_000u64,
            }),
            "host",
        );
        assert!(linux.contains("Location         /var/lib/kiri (default, ext4)"), "{linux}");
        assert!(linux.contains("Used             4.2 GB"), "{linux}");

        let freed = format_reclaim(
            &json!({"before": 29_400_000_000u64, "after": 17_300_000_000u64, "reclaimed": 12_100_000_000u64, "in_use": 17_300_000_000u64, "elapsed_ms": 800}),
            "macOS",
        );
        assert_eq!(freed, "Reclaimed 12.1 GB in 0.8 s (29.4 GB → 17.3 GB on macOS).\n");

        let zero = format_reclaim(
            &json!({"before": 17_300_000_000u64, "after": 17_300_000_000u64, "reclaimed": 0, "in_use": 17_300_000_000u64, "elapsed_ms": 200}),
            "macOS",
        );
        assert_eq!(zero, "Nothing to reclaim (17.3 GB on macOS, checked in 0.2 s).\n");

        let native = format_reclaim(
            &json!({"native": true, "message": "Native Linux uses the host filesystem directly."}),
            "host",
        );
        assert_eq!(native, "Native Linux uses the host filesystem directly.\n");
    }
}
