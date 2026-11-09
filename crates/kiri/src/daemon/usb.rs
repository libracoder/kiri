//! USB passthrough, the daemon's part: a pipe between `kiri usb serve` (the
//! root helper that owns the captured device and speaks USB/IP for it) and
//! the guest's vhci_hcd, plus the list of what is attached.
//!
//! `POST /kiri/usb?location=…&name=…&speed=…&devid=…` opens the guest's USB
//! port, asks it to attach, then upgrades the connection and copies bytes
//! both ways until either side closes. `GET /kiri/usb` lists the attached
//! devices; `DELETE /kiri/usb/<location>` detaches one by closing its pipe,
//! which makes the helper give the device back to macOS.

use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use super::api::{Next, error, reply};
use super::engine::{Engine, Error};
use super::http::{self, Request};

struct Session {
    location: String,
    name: String,
    port: i32,
    /// Both ends, so a detach (or the VM going away) can close them.
    helper: UnixStream,
    guest: OwnedFd,
}

static SESSIONS: Mutex<Vec<Session>> = Mutex::new(Vec::new());
/// Locations being attached right now.
static PENDING: Mutex<std::collections::BTreeSet<String>> = Mutex::new(std::collections::BTreeSet::new());

/// Whether a device is attached: the VM must not sleep under it.
pub fn any_attached() -> bool {
    !SESSIONS.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
}

pub fn list() -> Value {
    let s = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    Value::Array(s.iter().map(|s| json!({"Location": s.location, "Name": s.name, "Port": s.port})).collect())
}

pub fn detach(location: &str) -> Result<Value, Error> {
    let s = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(found) = s.iter().find(|s| s.location == location) else {
        return Err(Error::NotFound(format!("no USB device {location} is attached")));
    };
    let _ = found.helper.shutdown(Shutdown::Both);
    // SAFETY: shutting down a socket we own; the session's copy threads
    // see the end and remove it.
    unsafe { libc::shutdown(found.guest.as_raw_fd(), libc::SHUT_RDWR) };
    Ok(json!({"Location": location}))
}

/// Detaches every device and waits (up to 5 s) for their sessions to end:
/// for Stop and sleep, which would otherwise unplug them mid-transfer.
pub fn detach_all() {
    let locations: Vec<String> = SESSIONS.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|s| s.location.clone()).collect();
    for l in &locations {
        let _ = detach(l);
    }
    for _ in 0..50 {
        if !any_attached() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn attach(req: &Request, engine: &Arc<Engine>, w: &mut UnixStream, r: &mut BufReader<UnixStream>) -> io::Result<Next> {
    let location = req.query("location").unwrap_or_default().to_owned();
    let name: String = req.query("name").unwrap_or_default().replace('+', " ").chars().filter(|c| !c.is_control()).take(80).collect();
    let speed: u32 = req.query("speed").and_then(|s| s.parse().ok()).unwrap_or(0);
    let devid: u32 = req.query("devid").and_then(|s| s.parse().ok()).unwrap_or(0);
    if location.is_empty() || location.len() > 64 || !location.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') || !(1..=6).contains(&speed) {
        return reply(w, Err(Error::BadRequest("location (letters, digits, dashes) and speed (1-6) are required".into())), 200);
    }
    // Claimed before the guest is asked, so two attaches of one device
    // can't both get through.
    if !PENDING.lock().unwrap_or_else(|e| e.into_inner()).insert(location.clone())
        || SESSIONS.lock().unwrap_or_else(|e| e.into_inner()).iter().any(|s| s.location == location)
    {
        return reply(w, Err(Error::Conflict(format!("USB device {location} is already attached"))), 200);
    }
    let result = attach_claimed(&location, &name, speed, devid, engine, w, r);
    PENDING.lock().unwrap_or_else(|e| e.into_inner()).remove(&location);
    result
}

#[allow(clippy::too_many_arguments)]
fn attach_claimed(location: &str, name: &str, speed: u32, devid: u32, engine: &Arc<Engine>, w: &mut UnixStream, r: &mut BufReader<UnixStream>) -> io::Result<Next> {
    let (location, name) = (location.to_owned(), name.to_owned());
    let opened = (|| -> io::Result<(kiri_vmm::VsockStream, i32)> {
        let vm = engine.vm()?;
        // A VM this request just woke may not have its agent listening yet.
        let mut tries = 0;
        let stream = loop {
            match vm.connect(kiri_proto::USB_PORT) {
                Ok(s) => break s,
                Err(_) if tries < 50 => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => return Err(e),
            }
        };
        let mut f = File::from(stream.fd.try_clone()?);
        let mut head = [0u8; 8];
        head[..4].copy_from_slice(&speed.to_le_bytes());
        head[4..].copy_from_slice(&devid.to_le_bytes());
        f.write_all(&head)?;
        let mut answer = [0u8; 4];
        set_timeout(&stream.fd, Some(Duration::from_secs(5)));
        f.read_exact(&mut answer)?;
        set_timeout(&stream.fd, None);
        let port = i32::from_le_bytes(answer);
        if port < 0 {
            return Err(io::Error::other(format!("the VM could not attach the device: {}", io::Error::from_raw_os_error(-port))));
        }
        Ok((stream, port))
    })();
    let (stream, port) = match opened {
        Ok(v) => v,
        Err(e) => {
            // The helper reads the answer to the end: close it.
            error(w, Error::Io(e))?;
            return Ok(Next::Close);
        }
    };
    http::upgrade(w)?;
    engine.touch();
    crate::diag::info!("USB device attached", location = location, name = name, port = port);
    SESSIONS.lock().unwrap_or_else(|e| e.into_inner()).push(Session {
        location: location.clone(),
        name,
        port,
        helper: w.try_clone()?,
        guest: stream.fd.try_clone()?,
    });

    // Anything the helper sent right behind the request is already buffered.
    let early = r.buffer().to_vec();
    let mut to_guest = File::from(stream.fd.try_clone()?);
    let mut from_helper = r.get_ref().try_clone()?;
    let up = std::thread::Builder::new().name("kiri-usb-up".into()).spawn(move || {
        let _ = to_guest.write_all(&early).and_then(|()| io::copy(&mut from_helper, &mut to_guest));
        // SAFETY: shutting down a socket we own.
        unsafe { libc::shutdown(to_guest.as_raw_fd(), libc::SHUT_RDWR) };
        let _ = from_helper.shutdown(Shutdown::Both);
    })?;
    let mut from_guest = File::from(stream.fd.try_clone()?);
    let _ = io::copy(&mut from_guest, w);
    let _ = w.shutdown(Shutdown::Both);
    // SAFETY: shutting down a socket we own.
    unsafe { libc::shutdown(from_guest.as_raw_fd(), libc::SHUT_RDWR) };
    let _ = up.join();
    drop(stream);
    SESSIONS.lock().unwrap_or_else(|e| e.into_inner()).retain(|s| s.location != location);
    crate::diag::info!("USB device detached", location = location);
    Ok(Next::Close)
}

fn set_timeout(fd: &OwnedFd, t: Option<Duration>) {
    let tv = t.map_or(libc::timeval { tv_sec: 0, tv_usec: 0 }, |d| libc::timeval { tv_sec: d.as_secs() as _, tv_usec: 0 });
    // SAFETY: setsockopt with a valid timeval on a socket we own.
    unsafe {
        libc::setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&raw const tv).cast(), size_of::<libc::timeval>() as libc::socklen_t);
    }
}
