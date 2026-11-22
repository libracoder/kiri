//! Settings → Web UI: start and stop a `kiri ui --web` child, keep its URL
//! in `~/.kiribra/web-ui.json`, and open it in the browser.

use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::{emit, notice, open, prefs, set_pref, state_dir, tr, trf, web};

/// Child we started from Settings (not a `kiri ui --web` the person ran).
static CHILD: Mutex<Option<Child>> = Mutex::new(None);

fn status_path() -> Option<std::path::PathBuf> {
    Some(state_dir()?.join("web-ui.json"))
}

/// Whether a process id is still running on this computer.
fn pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        // signal 0: exists, no delivery. ESRCH = gone.
        // SAFETY: kill(pid, 0) only probes; we don't send a signal.
        let r = unsafe { libc::kill(pid as i32, 0) };
        r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

/// Reads `~/.kiribra/web-ui.json` when its pid is still live.
fn read_status() -> Option<serde_json::Value> {
    let path = status_path()?;
    let raw = std::fs::read(&path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let pid = v["pid"].as_u64()? as u32;
    if !pid_alive(pid) {
        let _ = std::fs::remove_file(&path);
        return None;
    }
    Some(v)
}

/// What the page shows: on/off, URL, LAN, port, and whether this page is the web UI.
pub fn event() -> String {
    let st = read_status();
    let prefs = prefs();
    let port = prefs["webUiPort"].as_u64().unwrap_or(u64::from(web::DEFAULT_PORT)) as u16;
    let lan = prefs["webUiLan"] == true;
    let want = prefs["webUi"] == true;
    serde_json::json!({
        "type": "webui",
        "on": st.is_some(),
        "want": want,
        "url": st.as_ref().and_then(|s| s["url"].as_str()),
        "lan": st.as_ref().and_then(|s| s["lan"].as_bool()).unwrap_or(lan),
        "port": st.as_ref().and_then(|s| s["port"].as_u64()).unwrap_or(u64::from(port)),
        "here": web::serving(),
    })
    .to_string()
}

pub fn emit_status() {
    emit(event());
}

/// Writes the status file while `kiri ui --web` is serving (CLI or Settings).
pub fn write_serving(url: &str, port: u16, lan: bool, token: &str) {
    let Some(path) = status_path() else { return };
    let body = serde_json::json!({
        "url": url,
        "port": port,
        "lan": lan,
        "token": token,
        "pid": std::process::id(),
    });
    let tmp = path.with_extension("json.tmp");
    let _ = std::fs::write(&tmp, body.to_string()).and_then(|()| std::fs::rename(&tmp, &path));
}

pub fn clear_serving() {
    if let Some(path) = status_path() {
        let _ = std::fs::remove_file(path);
    }
}

fn stop_child() {
    if let Ok(mut g) = CHILD.lock() {
        if let Some(mut c) = g.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
    if let Some(st) = read_status() {
        if let Some(pid) = st["pid"].as_u64() {
            #[cfg(unix)]
            // SAFETY: SIGTERM to a kiri ui --web we own or found in the status file.
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            let _ = pid;
        }
    }
    clear_serving();
}

/// Starts `kiri ui --web` as a sibling process, or refreshes status if one is up.
pub fn start(lan: bool, port: u16) -> Result<(), String> {
    if web::serving() {
        return Err(tr("This window is already the web UI."));
    }
    if let Some(st) = read_status() {
        // Already up: keep it, unless LAN/port disagree — then restart.
        let same_port = st["port"].as_u64() == Some(u64::from(port));
        let same_lan = st["lan"].as_bool() == Some(lan);
        if same_port && same_lan {
            set_pref("webUi", true.into());
            set_pref("webUiLan", lan.into());
            set_pref("webUiPort", port.into());
            return Ok(());
        }
        stop_child();
        std::thread::sleep(Duration::from_millis(200));
    } else {
        stop_child();
    }

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut cmd = Command::new(&exe);
    cmd.arg("ui").arg("--web").arg("--port").arg(port.to_string()).arg("--start");
    if lan {
        cmd.arg("--lan");
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    // Detach from the window's process group so closing the window doesn't kill it
    // until Settings turns it off (or the person quits the child).
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: before exec; sets a new session so SIGHUP to the window doesn't follow.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    let child = cmd.spawn().map_err(|e| trf("Could not start the web UI: {error}", &[("error", &e)]))?;
    if let Ok(mut g) = CHILD.lock() {
        *g = Some(child);
    }

    set_pref("webUi", true.into());
    set_pref("webUiLan", lan.into());
    set_pref("webUiPort", port.into());

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if read_status().is_some() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(tr("The web UI did not start. Try again, or run kiri ui --web in a terminal."))
}

pub fn stop() {
    stop_child();
    set_pref("webUi", false.into());
}

pub fn open_browser() {
    if let Some(url) = read_status().and_then(|s| s["url"].as_str().map(str::to_owned)) {
        open(&url);
    } else {
        emit(notice("error", &tr("The web UI is not running.")));
    }
}

/// When the native window opens: bring the web UI back if Settings left it on.
pub fn autostart_if_wanted() {
    if web::serving() {
        return;
    }
    let p = prefs();
    if p["webUi"] != true {
        // Still report status (maybe a CLI instance is up).
        emit_status();
        return;
    }
    let lan = p["webUiLan"] == true;
    let port = p["webUiPort"].as_u64().unwrap_or(u64::from(web::DEFAULT_PORT)) as u16;
    std::thread::spawn(move || {
        match start(lan, port) {
            Ok(()) => emit_status(),
            Err(e) => {
                emit(notice("error", &e));
                emit_status();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn event_json_names_the_page_type() {
        let v: serde_json::Value = serde_json::from_str(&super::event()).unwrap();
        assert_eq!(v["type"], "webui");
        assert!(v["port"].as_u64().unwrap() >= 1);
    }
}
