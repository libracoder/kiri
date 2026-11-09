//! The window's USB view on Windows: WSL 2, where Kiri's containers run,
//! gets USB devices through usbipd-win (Microsoft's recommended tool). A
//! device is shared once (`usbipd bind`, which Windows asks an
//! administrator to approve) and then attached to WSL (`usbipd attach
//! --wsl`), where it shows up like on any Linux machine. The page is the
//! same as on a Mac (crates/kiri/src/ui/index.html, renderUsb).

use std::io;
use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

use crate::engine::{emit, notice};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn usbipd_path() -> Option<PathBuf> {
    let installed = std::env::var_os("ProgramFiles").map(|p| PathBuf::from(p).join("usbipd-win").join("usbipd.exe"));
    if let Some(p) = installed.filter(|p| p.is_file()) {
        return Some(p);
    }
    // On PATH, from another install.
    std::env::var_os("PATH").and_then(|path| std::env::split_paths(&path).map(|d| d.join("usbipd.exe")).find(|p| p.is_file()))
}

fn run(args: &[&str]) -> io::Result<String> {
    let exe = usbipd_path().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "usbipd-win is not installed"))?;
    let mut c = Command::new(exe);
    c.args(args);
    std::os::windows::process::CommandExt::creation_flags(&mut c, CREATE_NO_WINDOW);
    let out = c.output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let text = if err.trim().is_empty() { String::from_utf8_lossy(&out.stdout).into_owned() } else { err.into_owned() };
        // usbipd says "usbipd: error: …".
        return Err(io::Error::other(text.trim().trim_start_matches("usbipd: ").trim_start_matches("error: ").to_owned()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The page's rows from `usbipd state`'s JSON.
fn rows(state: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    for d in state["Devices"].as_array().into_iter().flatten() {
        // Remembered but not plugged in: nothing to attach.
        let Some(bus) = d["BusId"].as_str().filter(|b| !b.is_empty()) else { continue };
        let instance = d["InstanceId"].as_str().unwrap_or("").to_ascii_uppercase();
        let hex = |key: &str| instance.split(['\\', '&']).find_map(|p| p.strip_prefix(key)).map(|v| v.to_ascii_lowercase());
        let id = match (hex("VID_"), hex("PID_")) {
            (Some(v), Some(p)) => format!("{v}:{p}"),
            _ => String::new(),
        };
        let inside = !d["ClientIPAddress"].is_null();
        out.push(json!({
            "key": bus, "name": d["Description"].as_str().unwrap_or("USB device"), "id": id, "speed": "",
            "state": if inside { "kiri" } else { "host" }, "path": "", "shared": !d["PersistedGuid"].is_null(),
        }));
    }
    out
}

pub fn list() -> Value {
    if usbipd_path().is_none() {
        return json!({"type": "usb", "devices": [], "missing": true});
    }
    match run(&["state"]).and_then(|s| serde_json::from_str::<Value>(&s).map_err(io::Error::other)) {
        Ok(state) => json!({"type": "usb", "devices": rows(&state), "can": "attach",
            "note": crate::engine::tr("A device in Kiri is gone from Windows until you detach it. In a container: --device /dev/ttyUSB0 (serial), /dev/input (HID) or /dev/bus/usb (raw).")}),
        Err(e) => json!({"type": "usb", "devices": [], "error": e.to_string()}),
    }
}

fn valid(bus: &str) -> bool {
    bus.len() <= 16 && bus.split('-').count() == 2 && bus.split('-').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn attach(bus: &str) -> io::Result<String> {
    if !valid(bus) {
        return Err(io::Error::other(format!("bad bus id {bus:?}")));
    }
    let state: Value = serde_json::from_str(&run(&["state"])?).map_err(io::Error::other)?;
    let row = rows(&state).into_iter().find(|r| r["key"] == bus).ok_or_else(|| io::Error::other("that device is gone"))?;
    let name = row["name"].as_str().unwrap_or("The device").to_owned();
    // Sharing a device is an administrator's call, once per device.
    if row["shared"] != true {
        let exe = usbipd_path().ok_or_else(|| io::Error::other("usbipd-win is not installed"))?;
        match crate::win::elevated(&exe, &["bind", "--busid", bus]) {
            Ok(0) => {}
            Ok(code) => return Err(io::Error::other(format!("usbipd could not share {name} (exit {code})"))),
            Err(e) if e.raw_os_error() == Some(1223) => return Err(io::Error::other("cancelled")),
            Err(e) => return Err(e),
        }
    }
    run(&["attach", "--wsl", "--busid", bus]).map_err(|e| io::Error::other(format!("{name} was not attached: {e}")))?;
    Ok(crate::engine::trf("{name} is in Kiri", &[("name", &name)]))
}

fn detach(bus: &str) -> io::Result<String> {
    if !valid(bus) {
        return Err(io::Error::other(format!("bad bus id {bus:?}")));
    }
    run(&["detach", "--busid", bus])?;
    Ok(crate::engine::tr("Given back to Windows"))
}

/// winget installs it; its installer asks for approval itself.
fn install() -> io::Result<()> {
    let mut c = crate::win::tool("winget.exe");
    c.args(["install", "--exact", "--id", "dorssel.usbipd-win", "--silent", "--accept-package-agreements", "--accept-source-agreements"]);
    std::os::windows::process::CommandExt::creation_flags(&mut c, CREATE_NO_WINDOW);
    let out = c.output().map_err(|e| io::Error::other(format!("winget did not start ({e}): install usbipd-win from github.com/dorssel/usbipd-win")))?;
    if !out.status.success() && usbipd_path().is_none() {
        let text = String::from_utf8_lossy(&out.stdout);
        let last = text.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").trim().to_owned();
        return Err(io::Error::other(format!("usbipd-win was not installed{}", if last.is_empty() { String::new() } else { format!(": {last}") })));
    }
    Ok(())
}

/// The page's USB commands.
pub fn handle(cmd: &'static str, key: String) {
    std::thread::spawn(move || {
        match cmd {
            "usbattach" | "usbdetach" => {
                let r = if cmd == "usbattach" { attach(&key) } else { detach(&key) };
                emit(match r {
                    Ok(text) => json!({"type": "usbdone", "key": key, "text": text}),
                    Err(e) if e.to_string() == "cancelled" => json!({"type": "usbdone", "key": key}),
                    Err(e) => json!({"type": "usbdone", "key": key, "error": e.to_string()}),
                }
                .to_string());
            }
            "usbinstall" => match install() {
                Ok(()) => emit(notice("ok", &crate::engine::tr("usbipd-win is installed"))),
                Err(e) => emit(notice("error", &e.to_string())),
            },
            _ => {}
        }
        emit(list().to_string());
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_from_usbipd_state() {
        let state: Value = serde_json::from_str(r#"{"Devices":[
            {"BusId":"1-3","ClientIPAddress":null,"Description":"CP210x USB to UART Bridge (COM3)","InstanceId":"USB\\VID_10C4&PID_EA60\\0001","IsForced":false,"PersistedGuid":null,"StubInstanceId":null},
            {"BusId":"2-1","ClientIPAddress":"172.20.0.2","Description":"USB Input Device","InstanceId":"USB\\VID_046D&PID_C077\\5&2A","IsForced":false,"PersistedGuid":"6a1c1d1e-0000-0000-0000-000000000000","StubInstanceId":"x"},
            {"BusId":null,"ClientIPAddress":null,"Description":"Unplugged","InstanceId":"USB\\VID_1111&PID_2222\\9","PersistedGuid":"7b"}]}"#).unwrap();
        let r = rows(&state);
        assert_eq!(r.len(), 2);
        assert_eq!((r[0]["key"].as_str(), r[0]["id"].as_str(), r[0]["state"].as_str(), r[0]["shared"].as_bool()), (Some("1-3"), Some("10c4:ea60"), Some("host"), Some(false)));
        assert_eq!((r[1]["id"].as_str(), r[1]["state"].as_str(), r[1]["shared"].as_bool()), (Some("046d:c077"), Some("kiri"), Some(true)));
    }

    #[test]
    fn bus_ids_are_checked() {
        assert!(valid("1-3") && valid("12-10"));
        assert!(!valid("") && !valid("1-3 & calc") && !valid("--busid"));
    }
}
