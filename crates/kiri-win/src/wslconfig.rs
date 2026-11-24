//! Settings → Resources on Windows. Kiri's engine runs in WSL's one VM,
//! whose CPUs and memory are `processors` and `memory` under `[wsl2]` in
//! %USERPROFILE%\.wslconfig (memory is half of the PC's when unset). Saving
//! writes those two keys and keeps the rest of the file; they apply when
//! WSL restarts, which stops every WSL distro, not only Kiri's.

use std::io;
use std::path::PathBuf;

use serde_json::{Value, json};

use crate::engine::{emit, notice, tr, trf};

fn path() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE").map(|h| PathBuf::from(h).join(".wslconfig"))
}

fn integration_path() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("Kiri").join("wsl-integration.json"))
}

/// Enabled WSL integration distros from `%LOCALAPPDATA%\Kiri\wsl-integration.json`
/// (off by default).
pub fn enabled_distros() -> Vec<String> {
    integration_path()
        .and_then(|p| std::fs::read(p).ok())
        .map(|b| crate::wslsync::parse_enabled_distros(&b))
        .unwrap_or_default()
}

fn save_enabled_distros(distros: &[String]) -> io::Result<()> {
    let p = integration_path().ok_or_else(|| io::Error::other("LOCALAPPDATA is not set"))?;
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = p.with_extension("json.tmp");
    std::fs::write(&tmp, crate::wslsync::encode_enabled_distros(distros))?;
    std::fs::rename(&tmp, &p)
}

/// User WSL distros discovered by `wsl.exe --list --quiet` (excluding `kiri`
/// and `docker-desktop*`).
fn user_distros() -> Vec<String> {
    let mut cmd = crate::win::tool("wsl.exe");
    std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);
    let Ok(out) = crate::update::output_within(cmd.args(["-l", "-q"]), std::time::Duration::from_secs(15)) else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    crate::wslsync::parse_wsl_distros(&out.stdout, crate::engine::distro().as_deref())
}

fn run_distro_script(distro: &str, script: &str) -> io::Result<String> {
    let mut cmd = crate::win::tool("wsl.exe");
    std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);
    let out = crate::update::output_within(
        cmd.args(crate::wslsync::wsl_sh(distro, script)),
        crate::update::WSL_LIMIT,
    )?;
    if !out.status.success() {
        let err = crate::wslsync::wsl_text(&out.stderr);
        let msg = err.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("WSL command failed");
        return Err(io::Error::other(format!("{distro}: {msg}")));
    }
    Ok(crate::wslsync::wsl_text(&out.stdout).trim().to_owned())
}

static WSL_SYNC_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Applies the current WSL integration settings to all enabled distros and updates
/// the daemon's per-distro sockets in `/mnt/wsl/kiri/sockets/<NAME>/docker.sock`.
pub fn apply_wsl_integration(disabled: Option<&str>, background: bool) -> io::Result<()> {
    if background && crate::serve::is_stopped() {
        return Ok(());
    }
    let _guard = WSL_SYNC_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let enabled = enabled_distros();
    if enabled.is_empty() && disabled.is_none() {
        if background && crate::client::alive_quick() {
            if let Ok(v) = crate::client::get_background("/kiri/wsl")
                && v["distros"].as_array().is_some_and(|a| !a.is_empty())
            {
                let _ = crate::client::request_with("POST", "/kiri/wsl", Some(&json!({"distros": []})), true);
            }
        }
        return Ok(());
    }
    if !background {
        crate::engine::ensure_daemon()?;
    } else if !crate::client::alive_quick() {
        return Ok(());
    }
    let available = user_distros();
    let mut active = Vec::new();
    let mut first_err: Option<io::Error> = None;
    for want in &enabled {
        let Some(name) = available.iter().find(|a| a.eq_ignore_ascii_case(want)) else {
            continue;
        };
        let script = crate::wslsync::wsl_enable_script(name, "");
        match run_distro_script(name, &script) {
            Ok(out) => {
                let gid = out.lines().next_back().and_then(|l| l.trim().parse::<u32>().ok()).unwrap_or(0);
                active.push(json!({"name": name, "gid": gid}));
            }
            Err(e) => {
                crate::serve::log(&format!("wsl integration ({name}): {e}"));
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }
    let res = crate::client::request_with("POST", "/kiri/wsl", Some(&json!({"distros": active})), background);
    if let Err(e) = crate::engine::expect_ok(res)
        && first_err.is_none()
    {
        first_err = Some(e);
    }
    if let Some(off) = disabled {
        let script = crate::wslsync::wsl_disable_script(off, "");
        if let Err(e) = run_distro_script(off, &script) {
            crate::serve::log(&format!("wsl integration disable ({off}): {e}"));
            if first_err.is_none() {
                first_err = Some(e);
            }
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Re-applies enabled WSL distros in the background when Kiri starts or
/// reconnects to the engine (handling `wsl --shutdown`).
pub fn sync_wsl_integration_soon() {
    std::thread::spawn(|| {
        if let Err(e) = apply_wsl_integration(None, true) {
            crate::serve::log(&format!("wsl integration sync: {e}"));
        }
    });
}

fn toggle_distro(distro: &str, on: bool) -> io::Result<()> {
    if !crate::wslsync::valid_distro_name(distro) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid WSL distro name"));
    }
    let mut list = enabled_distros();
    list.retain(|d| !d.eq_ignore_ascii_case(distro));
    if on {
        list.push(distro.to_owned());
    }
    save_enabled_distros(&list)?;
    apply_wsl_integration((!on).then_some(distro), false)
}

/// `32GB`, `8192MB`, `512m` → MiB.
fn mib(v: &str) -> Option<u64> {
    let v = v.trim().to_ascii_uppercase();
    let digits = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
    let n: u64 = v[..digits].parse().ok()?;
    match v[digits..].trim().trim_end_matches('B') {
        "T" => Some(n << 20),
        "G" => Some(n << 10),
        "M" => Some(n),
        "K" => Some(n >> 10),
        "" => Some(n >> 20),
        _ => None,
    }
}

/// A key's value under `[wsl2]`.
fn get(text: &str, key: &str) -> Option<String> {
    let mut in_wsl2 = false;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            in_wsl2 = l.eq_ignore_ascii_case("[wsl2]");
        } else if in_wsl2 && let Some((k, v)) = l.split_once('=') && k.trim().eq_ignore_ascii_case(key) {
            return Some(v.split('#').next().unwrap_or_default().trim().to_owned());
        }
    }
    None
}

/// The file with `key=value` under `[wsl2]`, replacing the key if it is
/// there and adding the section if it isn't.
fn set(text: &str, key: &str, value: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let (mut in_wsl2, mut seen_wsl2, mut done) = (false, false, false);
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            if in_wsl2 && !done {
                // The section's end, after its last non-blank line.
                let at = out.iter().rposition(|x| !x.trim().is_empty()).map_or(out.len(), |i| i + 1);
                out.insert(at, format!("{key}={value}"));
                done = true;
            }
            in_wsl2 = l.eq_ignore_ascii_case("[wsl2]");
            seen_wsl2 |= in_wsl2;
        } else if in_wsl2 && !done && l.split_once('=').is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case(key)) {
            out.push(format!("{key}={value}"));
            done = true;
            continue;
        }
        out.push(line.to_owned());
    }
    if !done {
        if !seen_wsl2 {
            if out.last().is_some_and(|l| !l.trim().is_empty()) {
                out.push(String::new());
            }
            out.push("[wsl2]".into());
        }
        out.push(format!("{key}={value}"));
    }
    out.join("\r\n") + "\r\n"
}

fn physical_mib() -> u64 {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    // SAFETY: a plain struct with its length set, filled by the call.
    unsafe {
        let mut m: MEMORYSTATUSEX = std::mem::zeroed();
        m.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(&mut m) != 0 { m.ullTotalPhys >> 20 } else { 0 }
    }
}

/// What the running VM has: CPUs, and memory in MiB as Linux reports it
/// (MemTotal; see `as_set`). None while Kiri's engine isn't running, so
/// that Settings never starts WSL.
fn running() -> Option<(u64, u64)> {
    if crate::serve::is_stopped() || !crate::client::alive() {
        return None;
    }
    let mut cmd = crate::win::tool("wsl.exe");
    if let Some(d) = crate::engine::distro() {
        cmd.args(["-d", &d]);
    }
    std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);
    let out = cmd.args(["-u", "root", "--", "sh", "-c", "nproc; head -1 /proc/meminfo"]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut lines = text.lines();
    let cpus: u64 = lines.next()?.trim().parse().ok()?;
    let kib: u64 = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    Some((cpus, kib >> 10))
}

/// The memory the VM runs with, as Settings shows it. Linux reports less
/// than WSL gave it: the kernel keeps some back, 1.2 GB of 64 GB, more than
/// rounding up to a whole GB makes good, and Settings said "up to 63 GB"
/// and offered a restart that changed nothing. Up to a sixteenth under
/// the setting is the setting; anything else is rounded up to a whole GB.
fn as_set(running_mib: u64, set_mib: u64) -> u64 {
    if running_mib <= set_mib && running_mib + set_mib / 16 >= set_mib {
        set_mib
    } else {
        running_mib.div_ceil(1024) * 1024
    }
}

fn event() -> Value {
    let text = path().and_then(|p| std::fs::read_to_string(p).ok()).unwrap_or_default();
    let max_cpus = std::thread::available_parallelism().map_or(1, |n| n.get() as u64);
    let max_mib = physical_mib();
    let cpus = get(&text, "processors").and_then(|v| v.parse().ok()).unwrap_or(max_cpus).clamp(1, max_cpus);
    let memory = get(&text, "memory").and_then(|v| mib(&v)).unwrap_or(max_mib / 2);
    let now = running();
    let enabled = enabled_distros();
    let wsl_distros: Vec<Value> = user_distros()
        .into_iter()
        .map(|name| {
            let on = enabled.iter().any(|e| e.eq_ignore_ascii_case(&name));
            json!({ "name": name, "on": on })
        })
        .collect();
    json!({
        "type": "resources",
        "cpus": cpus,
        "memory_mib": memory,
        "running_cpus": now.map_or(cpus, |r| r.0),
        "running_memory_mib": now.map_or(memory, |r| as_set(r.1, memory)),
        "awake": now.is_some(),
        "max_cpus": max_cpus,
        "max_memory_mib": max_mib,
        "overridden": false,
        "restart_note": "Restarting restarts WSL: every WSL distro stops, not only Kiri's, and Kiri's containers start again as they're set to.",
        "wsl_distros": wsl_distros,
    })
}

fn save(body: &Value) -> io::Result<()> {
    let p = path().ok_or_else(|| io::Error::other("USERPROFILE is not set"))?;
    let mut text = std::fs::read_to_string(&p).unwrap_or_default();
    if let Some(n) = body["cpus"].as_u64().filter(|&n| n >= 1) {
        text = set(&text, "processors", &n.to_string());
    }
    if let Some(m) = body["memory_mib"].as_u64().filter(|&m| m >= 1024) {
        text = set(&text, "memory", &if m % 1024 == 0 { format!("{}GB", m / 1024) } else { format!("{m}MB") });
    }
    std::fs::write(&p, text)
}

/// Reads (or saves, then reads) the CPUs, memory and WSL integration for Settings.
pub fn resources(body: Option<Value>) {
    std::thread::spawn(move || {
        if let Some(b) = &body
            && let Some(distro) = b["wsl_distro"].as_str()
        {
            let on = b["on"].as_bool().unwrap_or(false);
            if let Err(e) = toggle_distro(distro, on) {
                emit(notice("error", &e.to_string()));
            }
            emit(event().to_string());
            return;
        }
        let saved = body.map(|b| save(&b));
        let ev = event();
        match saved {
            // While Kiri's engine runs, the toast offers to restart WSL now.
            Some(Ok(())) => emit(json!({"type": "notice", "kind": "ok", "text": tr("Saved in .wslconfig. WSL uses these from its next start"), "act": if ev["awake"] == true { "restartvm" } else { "" }}).to_string()),
            Some(Err(e)) => emit(notice("error", &trf("Could not save .wslconfig: {error}", &[("error", &e)]))),
            None => {}
        }
        emit(ev.to_string());
    });
}

/// Restart to apply: WSL stops and Kiri's engine starts again.
pub fn restart() {
    std::thread::spawn(|| {
        let mut cmd = crate::win::tool("wsl.exe");
        std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);
        let r = cmd.arg("--shutdown").status().and_then(|s| if s.success() { Ok(()) } else { Err(io::Error::other("wsl --shutdown failed")) }).and_then(|()| crate::engine::ensure_daemon());
        if r.is_ok() {
            let _ = apply_wsl_integration(None, true);
        }
        emit(match r {
            Ok(()) => notice("ok", &tr("WSL restarted with the new resources")),
            Err(e) => notice("error", &trf("Could not restart WSL: {error}", &[("error", &e)])),
        });
        emit(event().to_string());
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vm_running_as_set_shows_its_setting() {
        // WSL given 64 GB: Linux's MemTotal is 65843312 kB.
        assert_eq!(as_set(65843312 >> 10, 65536), 65536);
        assert_eq!(as_set(8000, 8192), 8192);
        // Given less, or more, than the setting now says: what it has.
        assert_eq!(as_set(65843312 >> 10, 32768), 63 * 1024);
        assert_eq!(as_set(16000, 65536), 16 * 1024);
    }

    #[test]
    fn reads_sizes() {
        assert_eq!(mib("32GB"), Some(32768));
        assert_eq!(mib("8192MB"), Some(8192));
        assert_eq!(mib("4g"), Some(4096));
        assert_eq!(mib("lots"), None);
    }

    #[test]
    fn sets_keys_under_wsl2_and_keeps_the_rest() {
        let text = "[wsl2]\r\nmemory=32GB\r\n\r\n[experimental]\r\nsparseVhd=true\r\n";
        assert_eq!(get(text, "memory").as_deref(), Some("32GB"));
        let t = set(&set(text, "memory", "16GB"), "processors", "8");
        assert_eq!(t, "[wsl2]\r\nmemory=16GB\r\nprocessors=8\r\n\r\n[experimental]\r\nsparseVhd=true\r\n");
        assert_eq!(get(&t, "processors").as_deref(), Some("8"));
        assert_eq!(set("", "memory", "4GB"), "[wsl2]\r\nmemory=4GB\r\n");
        assert_eq!(set("[boot]\r\nx=1\r\n", "memory", "4GB"), "[boot]\r\nx=1\r\n\r\n[wsl2]\r\nmemory=4GB\r\n");
    }
}
