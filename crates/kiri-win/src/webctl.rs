//! Settings → Web UI on Windows: start `kiri ui --web` inside Kiribra's WSL
//! distro, read `~/.kiribra/web-ui.json` from there, open the URL in the
//! browser. Same page commands as crates/kiri/src/ui/webctl.rs.

use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::engine::{emit, notice, prefs, set_pref, tr, trf};
use crate::app;

const DEFAULT_PORT: u16 = 7676;

static CHILD: Mutex<Option<Child>> = Mutex::new(None);

fn distro() -> Option<String> {
    crate::engine::distro().or_else(crate::setup::saved_distro)
}

fn wsl(args: &[&str]) -> Command {
    let mut cmd = crate::win::tool("wsl.exe");
    if let Some(d) = distro() {
        cmd.args(["-d", &d]);
    }
    cmd.args(args);
    cmd
}

fn read_status() -> Option<Value> {
    let out = wsl(&["--", "sh", "-c", "cat /root/.kiribra/web-ui.json 2>/dev/null || cat \"$HOME/.kiribra/web-ui.json\" 2>/dev/null"]).output().ok()?;
    if !out.status.success() || out.stdout.is_empty() {
        return None;
    }
    serde_json::from_slice(&out.stdout).ok()
}

fn pid_in_wsl_alive(pid: u64) -> bool {
    wsl(&["--", "kill", "-0", &pid.to_string()]).status().is_ok_and(|s| s.success())
}

fn live_status() -> Option<Value> {
    let v = read_status()?;
    let pid = v["pid"].as_u64()?;
    if !pid_in_wsl_alive(pid) {
        return None;
    }
    Some(v)
}

pub fn event() -> String {
    let st = live_status();
    let p = prefs();
    let port = p["webUiPort"].as_u64().unwrap_or(u64::from(DEFAULT_PORT)) as u16;
    let lan = p["webUiLan"] == true;
    json!({
        "type": "webui",
        "on": st.is_some(),
        "want": p["webUi"] == true,
        "url": st.as_ref().and_then(|s| s["url"].as_str()).map(|u| u.replace("127.0.0.1", "localhost")),
        "lan": st.as_ref().and_then(|s| s["lan"].as_bool()).unwrap_or(lan),
        "port": st.as_ref().and_then(|s| s["port"].as_u64()).unwrap_or(u64::from(port)),
        "here": false,
    })
    .to_string()
}

pub fn emit_status() {
    emit(event());
}

fn stop_child() {
    if let Ok(mut g) = CHILD.lock() {
        if let Some(mut c) = g.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
    if let Some(st) = live_status() {
        if let Some(pid) = st["pid"].as_u64() {
            let _ = wsl(&["--", "kill", &pid.to_string()]).status();
        }
    }
}

pub fn start(lan: bool, port: u16) -> Result<(), String> {
    if distro().is_none() {
        return Err(tr("Kiribra's Linux is not set up yet."));
    }
    if let Some(st) = live_status() {
        let same = st["port"].as_u64() == Some(u64::from(port)) && st["lan"].as_bool() == Some(lan);
        if same {
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

    let port_s = port.to_string();
    let mut args: Vec<&str> = vec!["--", "kiri", "ui", "--web", "--port", &port_s, "--start"];
    if lan {
        args.push("--lan");
    }
    let mut cmd = wsl(&args);
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    let child = cmd.spawn().map_err(|e| trf("Could not start the web UI: {error}", &[("error", &e)]))?;
    if let Ok(mut g) = CHILD.lock() {
        *g = Some(child);
    }
    set_pref("webUi", true.into());
    set_pref("webUiLan", lan.into());
    set_pref("webUiPort", port.into());

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if live_status().is_some() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(tr("The web UI did not start. Try again, or run kiri ui --web in WSL."))
}

pub fn stop() {
    stop_child();
    set_pref("webUi", false.into());
}

pub fn open_browser() {
    if let Some(url) = live_status().and_then(|s| s["url"].as_str().map(|u| u.replace("127.0.0.1", "localhost"))) {
        app::open_url(&url);
    } else {
        emit(notice("error", &tr("The web UI is not running.")));
    }
}

pub fn autostart_if_wanted() {
    let p = prefs();
    if p["webUi"] != true {
        emit_status();
        return;
    }
    let lan = p["webUiLan"] == true;
    let port = p["webUiPort"].as_u64().unwrap_or(u64::from(DEFAULT_PORT)) as u16;
    std::thread::spawn(move || match start(lan, port) {
        Ok(()) => emit_status(),
        Err(e) => {
            emit(notice("error", &e));
            emit_status();
        }
    });
}
