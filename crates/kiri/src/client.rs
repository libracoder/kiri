//! The window and `kiri` subcommands talk to `kiri daemon` the way the docker CLI does: HTTP over
//! the daemon's unix socket (or `\\.\pipe\kiri` on Windows). One short connection per request,
//! and one long-lived one for `/events`.

// Parts of this serve only the Mac (the window, boot timings).
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

#[cfg(any(unix, test))]
use std::ffi::OsStr;
use std::io::{self, BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(any(unix, test))]
use std::path::Component;
use std::path::PathBuf;
#[cfg(any(unix, test))]
use std::path::Path;
use std::time::Duration;

use serde_json::Value;

#[cfg(windows)]
pub const DEFAULT_PIPE: &str = r"\\.\pipe\kiri";

/// The Windows named pipe `kiri-win` serves the Docker API on.
#[cfg(windows)]
pub fn pipe() -> String {
    std::env::var("KIRI_PIPE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_PIPE.to_owned())
}

#[cfg(unix)]
pub fn socket() -> io::Result<PathBuf> {
    let kiri_socket = std::env::var_os("KIRI_SOCKET");
    let home = std::env::var_os("HOME");
    #[cfg(target_os = "linux")]
    {
        let wsl_distro = std::env::var_os("WSL_DISTRO_NAME");
        let wsl_sockets_dir = PathBuf::from(crate::daemon::binds::wsl_kiri_dir()).join("sockets");
        socket_for(
            kiri_socket.as_deref(),
            Some(Path::new(SERVICE_SOCKET)),
            wsl_distro.as_deref(),
            Some(wsl_sockets_dir.as_path()),
            &[Path::new("/var/run/docker.sock"), Path::new("/run/docker.sock")],
            home.as_deref(),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        socket_for(kiri_socket.as_deref(), None, None, None, &[], home.as_deref())
    }
}

#[cfg(any(unix, test))]
fn safe_wsl_distro(name: &str) -> bool {
    #[cfg(unix)]
    {
        crate::daemon::binds::valid_distro_name(name) && !name.contains("..")
    }
    #[cfg(not(unix))]
    {
        !name.is_empty()
            && !name.contains("..")
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    }
}

#[cfg(any(unix, test))]
fn is_wsl_socket_path(target: &Path, wsl_sockets_dir: &Path) -> bool {
    let Ok(rel) = target.strip_prefix(wsl_sockets_dir) else {
        return false;
    };
    let mut comps = rel.components();
    match (comps.next(), comps.next(), comps.next()) {
        (Some(Component::Normal(distro)), Some(Component::Normal(file)), None) => {
            distro.to_str().is_some_and(safe_wsl_distro) && file == "docker.sock"
        }
        _ => false,
    }
}

/// Whether a socket path is present on disk, treating `EACCES` on a parent
/// directory (such as a `0750` WSL integration socket directory) as present so
/// `check_alive` surfaces a clear permission-denied error instead of falling
/// back to a missing home socket.
#[cfg(any(unix, test))]
fn socket_present(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(_) => true,
        Err(e) => e.kind() == io::ErrorKind::PermissionDenied,
    }
}

#[cfg(any(unix, test))]
fn socket_for(
    kiri_socket: Option<&OsStr>,
    service_socket: Option<&Path>,
    wsl_distro: Option<&OsStr>,
    wsl_sockets_dir: Option<&Path>,
    docker_sock_links: &[&Path],
    home: Option<&OsStr>,
) -> io::Result<PathBuf> {
    if let Some(s) = kiri_socket {
        return Ok(PathBuf::from(s));
    }
    // Linux: the engine is the `kiri` system service (contrib/linux/kiri.service)
    // or a root-run `sudo kiri daemon` at `/run/kiri/docker.sock`.
    if let Some(service) = service_socket
        && socket_present(service)
    {
        return Ok(service.to_path_buf());
    }
    // WSL 2 integration: Kiri for Windows exposes per-distro sockets under
    // `/mnt/wsl/kiri/sockets/<distro>/docker.sock` and symlinks
    // `/var/run/docker.sock` to them.
    if let Some(wsl_dir) = wsl_sockets_dir {
        if let Some(distro) = wsl_distro.and_then(|d| d.to_str()).filter(|d| safe_wsl_distro(d)) {
            let candidate = wsl_dir.join(distro).join("docker.sock");
            if socket_present(&candidate) {
                return Ok(candidate);
            }
        }
        for link in docker_sock_links {
            if let Ok(target) = std::fs::read_link(link)
                && is_wsl_socket_path(&target, wsl_dir)
                && socket_present(&target)
            {
                return Ok(target);
            }
        }
    }
    let home = home.map(PathBuf::from).ok_or_else(|| io::Error::other("HOME is not set"))?;
    Ok(home.join(crate::flavor::STATE.get()).join("run/docker.sock"))
}

/// Where the Linux service's engine listens, for members of the `kiri` group.
#[cfg(target_os = "linux")]
pub const SERVICE_SOCKET: &str = "/run/kiri/docker.sock";

/// An answer: status and body.
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    /// The daemon's `{"message": …}` on failure, or the body as text.
    pub fn error(&self) -> String {
        self.json()["message"].as_str().map(str::to_owned).unwrap_or_else(|| String::from_utf8_lossy(&self.body).into_owned())
    }

    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

#[cfg(unix)]
fn op_header() -> String {
    crate::diag::op_header()
}

#[cfg(windows)]
fn op_header() -> String {
    String::new()
}

#[cfg(unix)]
fn connect_to(sock: &Path, timeout: Option<Duration>) -> io::Result<UnixStream> {
    let s = UnixStream::connect(sock)?;
    s.set_read_timeout(timeout)?;
    Ok(s)
}

#[cfg(unix)]
fn connect(timeout: Option<Duration>) -> io::Result<UnixStream> {
    connect_to(&socket()?, timeout)
}

#[cfg(windows)]
struct WinPipe(std::fs::File);

#[cfg(windows)]
impl WinPipe {
    fn open(name: &str) -> io::Result<Self> {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        const ERROR_PIPE_BUSY: i32 = 231;
        const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
        const PIPE_READMODE_MESSAGE: u32 = 0x0000_0002;
        unsafe extern "system" {
            fn SetNamedPipeHandleState(
                hNamedPipe: *mut core::ffi::c_void,
                lpMode: *const u32,
                lpMaxCollectionCount: *const u32,
                lpCollectDataTimeout: *const u32,
            ) -> i32;
        }
        for _ in 0..20 {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(0)
                .security_qos_flags(SECURITY_IDENTIFICATION)
                .open(name)
            {
                Ok(file) => {
                    // `kiri-win` serves `\\.\pipe\kiri` in message mode and ends
                    // unframed HTTP responses with a 0-byte message.
                    let mode = PIPE_READMODE_MESSAGE;
                    // SAFETY: `file` owns a valid handle for the duration of the call.
                    unsafe {
                        SetNamedPipeHandleState(
                            file.as_raw_handle(),
                            &mode,
                            std::ptr::null(),
                            std::ptr::null(),
                        );
                    }
                    return Ok(Self(file));
                }
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, format!("pipe {name} stayed busy")))
    }
}

#[cfg(windows)]
impl Read for WinPipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        const ERROR_BROKEN_PIPE: i32 = 109;
        const ERROR_PIPE_NOT_CONNECTED: i32 = 233;
        const ERROR_MORE_DATA: i32 = 234;
        match self.0.read(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.raw_os_error() == Some(ERROR_MORE_DATA) => Ok(buf.len()),
            Err(e) if matches!(e.raw_os_error(), Some(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED)) => Ok(0),
            Err(e) => Err(e),
        }
    }
}

#[cfg(windows)]
impl Write for WinPipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

fn head(r: &mut impl BufRead) -> io::Result<(u16, Option<usize>, bool)> {
    let mut line = String::new();
    r.read_line(&mut line)?;
    let status = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad status line"))?;
    let (mut len, mut chunked) = (None, false);
    loop {
        line.clear();
        if r.read_line(&mut line)? == 0 {
            break;
        }
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            match k.to_ascii_lowercase().as_str() {
                "content-length" => len = v.trim().parse().ok(),
                "transfer-encoding" => chunked = v.trim().eq_ignore_ascii_case("chunked"),
                _ => {}
            }
        }
    }
    Ok((status, len, chunked))
}

/// Reads one chunk of a chunked body; `None` at the end.
fn chunk(r: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let n = usize::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk"))?;
    if n == 0 {
        return Ok(None);
    }
    let mut buf = vec![0; n + 2];
    r.read_exact(&mut buf)?;
    buf.truncate(n);
    Ok(Some(buf))
}

/// One request; the whole body is read, chunked or not.
pub fn request(method: &str, path: &str, body: Option<&Value>) -> io::Result<Response> {
    send(method, path, body, "")
}

/// A GET the window makes on its own (status, lists): it doesn't count as
/// use, so it never keeps an idle VM awake.
pub fn get_background(path: &str) -> io::Result<Value> {
    let r = send("GET", path, None, "X-Kiri-Background: 1\r\n")?;
    if !r.ok() {
        return Err(io::Error::other(r.error()));
    }
    Ok(r.json())
}

#[cfg(unix)]
fn send(method: &str, path: &str, body: Option<&Value>, extra: &str) -> io::Result<Response> {
    send_to(&socket()?, method, path, body, extra)
}

#[cfg(unix)]
fn send_to(sock: &Path, method: &str, path: &str, body: Option<&Value>, extra: &str) -> io::Result<Response> {
    let mut s = connect_to(sock, Some(Duration::from_secs(120)))?;
    let payload = body.map(Value::to_string).unwrap_or_default();
    // The window's action this is part of, for the engine's log lines.
    let op = op_header();
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: kiri\r\nConnection: close\r\n{extra}{op}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{payload}",
        payload.len()
    )?;
    answer(s)
}

#[cfg(windows)]
fn send(method: &str, path: &str, body: Option<&Value>, extra: &str) -> io::Result<Response> {
    send_to_pipe(&pipe(), method, path, body, extra)
}

#[cfg(windows)]
fn send_to_pipe(name: &str, method: &str, path: &str, body: Option<&Value>, extra: &str) -> io::Result<Response> {
    let mut s = WinPipe::open(name)?;
    let payload = body.map(Value::to_string).unwrap_or_default();
    let op = op_header();
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: kiri\r\nConnection: close\r\n{extra}{op}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{payload}",
        payload.len()
    )?;
    s.flush()?;
    answer(s)
}

/// The answer to a request just sent; the whole body is read, chunked or not.
fn answer(s: impl Read) -> io::Result<Response> {
    let mut r = BufReader::new(s);
    let (status, len, chunked) = head(&mut r)?;
    let mut body = Vec::new();
    // These never have a body, and the daemon keeps the connection open.
    if status == 204 || status == 304 {
        return Ok(Response { status, body });
    }
    if chunked {
        while let Some(c) = chunk(&mut r)? {
            body.extend_from_slice(&c);
        }
    } else if let Some(n) = len {
        body.resize(n, 0);
        r.read_exact(&mut body)?;
    } else {
        r.read_to_end(&mut body)?;
    }
    Ok(Response { status, body })
}

/// A POST whose body `write` streams, chunked, so its length need not be
/// known first: `kiri import`'s copy of a container's writable layer. A
/// body `write` gives up on is never ended, so the daemon sees it cut
/// short, not as a whole one; if the daemon stopped reading first (it
/// refused the request), its answer is returned, which says why.
#[cfg(unix)]
pub fn post_stream(path: &str, content_type: &str, write: impl FnOnce(&mut dyn Write) -> io::Result<()>) -> io::Result<Response> {
    let s = connect(Some(Duration::from_secs(300)))?;
    let op = op_header();
    (&s).write_all(format!("POST {path} HTTP/1.1\r\nHost: kiri\r\nConnection: close\r\n{op}Content-Type: {content_type}\r\nTransfer-Encoding: chunked\r\n\r\n").as_bytes())?;
    match stream_body(&s, write) {
        Ok(()) => answer(&s),
        Err(e) if refused(&e) => match answer(&s) {
            Ok(r) if !r.ok() => Ok(r),
            _ => Err(e),
        },
        Err(e) => Err(e),
    }
}

#[cfg(windows)]
pub fn post_stream(path: &str, content_type: &str, write: impl FnOnce(&mut dyn Write) -> io::Result<()>) -> io::Result<Response> {
    let mut s = WinPipe::open(&pipe())?;
    let op = op_header();
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: kiri\r\nConnection: close\r\n{op}Content-Type: {content_type}\r\nTransfer-Encoding: chunked\r\n\r\n"
    )?;
    match stream_body(&mut s, write) {
        Ok(()) => answer(s),
        Err(e) if refused(&e) => match answer(s) {
            Ok(r) if !r.ok() => Ok(r),
            _ => Err(e),
        },
        Err(e) => Err(e),
    }
}

/// Writes a body chunked, in chunks of up to 256 KiB, and ends it only when
/// `write` succeeds.
pub(crate) fn stream_body(to: impl Write, write: impl FnOnce(&mut dyn Write) -> io::Result<()>) -> io::Result<()> {
    let mut body = io::BufWriter::with_capacity(256 << 10, Chunked(to));
    write(&mut body)?;
    let mut chunked = body.into_inner().map_err(io::IntoInnerError::into_error)?;
    chunked.0.write_all(b"0\r\n\r\n")?;
    chunked.0.flush()
}

/// Whether a write failed because the other end closed: the daemon may
/// have answered before reading the whole body.
fn refused(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted)
}

/// HTTP/1.1 chunked transfer coding: each write is one chunk.
struct Chunked<W: Write>(W);

impl<W: Write> Write for Chunked<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        write!(self.0, "{:x}\r\n", buf.len())?;
        self.0.write_all(buf)?;
        self.0.write_all(b"\r\n")?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// Kiri's own version from a `/version` answer: `KiriVersion`, or `Version`
/// from an engine older than that field (it reported Kiri's version there;
/// it is now the Docker Engine version clients gate on).
pub fn kiri_version(version: &Value) -> Option<&str> {
    version["KiriVersion"].as_str().or_else(|| version["Version"].as_str())
}

pub fn get(path: &str) -> io::Result<Value> {
    let r = request("GET", path, None)?;
    if !r.ok() {
        return Err(io::Error::other(r.error()));
    }
    Ok(r.json())
}

/// Whether the daemon answers at all.
pub fn alive() -> bool {
    send("GET", "/_ping", None, "X-Kiri-Background: 1\r\n").is_ok_and(|r| r.ok())
}

#[cfg(any(target_os = "linux", test))]
fn is_wsl_env(wsl_distro: Option<&OsStr>, wsl_interop_paths: &[&Path]) -> bool {
    wsl_distro.is_some_and(|s| !s.is_empty()) || wsl_interop_paths.iter().any(|p| p.exists())
}

fn not_running_message_for(is_linux: bool, is_wsl: bool) -> &'static str {
    if !is_linux {
        "Kiri isn't running. Open Kiri, or start it with `kiri daemon`"
    } else if is_wsl {
        "Kiri isn't running. Open Kiri on Windows (and enable this distro in Settings -> Resources -> WSL integration), or run `sudo kiri host-access $USER`"
    } else {
        "Kiri isn't running. Open Kiri, or run `sudo kiri host-access $USER` (or `sudo kiri daemon`)"
    }
}

/// Actionable OS-specific error text when the engine is not running.
pub fn not_running_message() -> &'static str {
    #[cfg(windows)]
    {
        "Kiri isn't running. Open Kiri, or start it with `kiri start`"
    }
    #[cfg(not(windows))]
    {
        #[cfg(target_os = "linux")]
        let wsl = is_wsl_env(
            std::env::var_os("WSL_DISTRO_NAME").as_deref(),
            &[Path::new("/proc/sys/fs/binfmt_misc/WSLInterop"), Path::new("/proc/sys/fs/binfmt_misc/WSLInterop-late")],
        );
        #[cfg(not(target_os = "linux"))]
        let wsl = false;
        not_running_message_for(cfg!(target_os = "linux"), wsl)
    }
}

#[cfg(any(unix, test))]
fn permission_denied_error(sock: &Path, is_linux: bool) -> io::Error {
    let msg = if is_linux {
        format!(
            "cannot connect to Kiri's socket ({}): permission denied. Run `sudo kiri host-access $USER` (or open Kiri) to grant access",
            sock.display()
        )
    } else {
        format!("cannot connect to Kiri's socket ({}): permission denied", sock.display())
    };
    io::Error::new(io::ErrorKind::PermissionDenied, msg)
}

#[cfg(unix)]
fn check_alive_at(sock: &Path, not_running: &str) -> io::Result<()> {
    match send_to(sock, "GET", "/_ping", None, "X-Kiri-Background: 1\r\n") {
        Ok(r) if r.ok() => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Err(permission_denied_error(sock, cfg!(target_os = "linux"))),
        _ => Err(io::Error::new(io::ErrorKind::NotConnected, not_running)),
    }
}

/// Probes the engine socket, distinguishing `PermissionDenied` (`EACCES`) from
/// the daemon not running and formatting OS-appropriate guidance.
pub fn check_alive() -> io::Result<()> {
    check_alive_with(not_running_message())
}

/// Like [`check_alive`], using `not_running` when the daemon is not running.
#[cfg(unix)]
pub fn check_alive_with(not_running: &str) -> io::Result<()> {
    let sock = socket()?;
    check_alive_at(&sock, not_running)
}

#[cfg(windows)]
pub fn check_alive_with(not_running: &str) -> io::Result<()> {
    let p = pipe();
    match send_to_pipe(&p, "GET", "/_ping", None, "X-Kiri-Background: 1\r\n") {
        Ok(r) if r.ok() => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("cannot connect to Kiri's pipe ({p}): permission denied"),
        )),
        _ => Err(io::Error::new(io::ErrorKind::NotConnected, not_running)),
    }
}

/// A POST whose answer is JSON lines arriving over time (a pull's
/// progress): `on_line` sees each as it comes. Returns the HTTP status.
/// `auth` is a registry sign-in for a pull (`X-Registry-Auth`, base64url).
/// `opened` gets the connection once it is made, so another thread can
/// shut it down to stop the request (Cancel on a pull).
#[cfg(unix)]
pub fn post_lines_closable(path: &str, auth: Option<&str>, opened: impl FnOnce(&UnixStream), on_line: impl FnMut(Value)) -> io::Result<u16> {
    post_lines_inner(path, auth, Some(Duration::from_secs(120)), opened, on_line)
}

/// Like `post_lines_closable` without a read timeout, for long-running
/// streamed operations such as `/kiri/images/scan` (first-time DB download).
#[cfg(target_os = "linux")]
pub fn post_lines_unbounded(path: &str, on_line: impl FnMut(Value)) -> io::Result<u16> {
    post_lines_inner(path, None, None, |_| {}, on_line)
}

#[cfg(unix)]
fn post_lines_inner(path: &str, auth: Option<&str>, timeout: Option<Duration>, opened: impl FnOnce(&UnixStream), mut on_line: impl FnMut(Value)) -> io::Result<u16> {
    if auth.is_some_and(|a| a.contains(['\r', '\n'])) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "header contains a line break"));
    }
    let auth = auth.map(|a| format!("X-Registry-Auth: {a}\r\n")).unwrap_or_default();
    let mut s = connect(timeout)?;
    opened(&s);
    write!(s, "POST {path} HTTP/1.1\r\nHost: kiri\r\nConnection: close\r\n{auth}{}Content-Type: application/json\r\nContent-Length: 0\r\n\r\n", op_header())?;
    let mut r = BufReader::new(s);
    let (status, len, chunked) = head(&mut r)?;
    let mut pending = Vec::new();
    let mut lines = |pending: &mut Vec<u8>| {
        while let Some(i) = pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = pending.drain(..=i).collect();
            if let Ok(v) = serde_json::from_slice::<Value>(&line) {
                on_line(v);
            }
        }
    };
    if chunked {
        while let Some(c) = chunk(&mut r)? {
            pending.extend_from_slice(&c);
            lines(&mut pending);
        }
    } else if let Some(n) = len {
        pending.resize(n, 0);
        r.read_exact(&mut pending)?;
    } else if status != 204 {
        r.read_to_end(&mut pending)?;
    }
    // A last line with no newline, or a plain error body.
    pending.push(b'\n');
    lines(&mut pending);
    Ok(status)
}

/// Calls `on_event` for each event until the connection ends or it returns false.
#[cfg(unix)]
pub fn events(mut on_event: impl FnMut(Value) -> bool) -> io::Result<()> {
    let mut s = connect(None)?;
    write!(s, "GET /events HTTP/1.1\r\nHost: kiri\r\nX-Kiri-Background: 1\r\n\r\n")?;
    let mut r = BufReader::new(s);
    let (status, _, chunked) = head(&mut r)?;
    if status != 200 || !chunked {
        return Err(io::Error::other(format!("events: HTTP {status}")));
    }
    let mut pending = Vec::new();
    while let Some(c) = chunk(&mut r)? {
        pending.extend_from_slice(&c);
        while let Some(i) = pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = pending.drain(..=i).collect();
            if let Ok(v) = serde_json::from_slice::<Value>(&line) {
                if !on_event(v) {
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}

/// A long-lived streamed response, such as `logs?follow=1`, read chunk by
/// chunk. `closer` ends it from another thread.
#[cfg(unix)]
pub struct Stream {
    reader: BufReader<UnixStream>,
}

#[cfg(unix)]
impl Stream {
    pub fn open(path: &str) -> io::Result<Stream> {
        let mut s = connect(None)?;
        write!(s, "GET {path} HTTP/1.1\r\nHost: kiri\r\n\r\n")?;
        let mut reader = BufReader::new(s);
        let (status, _, chunked) = head(&mut reader)?;
        if status != 200 || !chunked {
            return Err(io::Error::other(format!("{path}: HTTP {status}")));
        }
        Ok(Stream { reader })
    }

    /// A handle whose `shutdown` makes `next` return `None`.
    pub fn closer(&self) -> io::Result<UnixStream> {
        self.reader.get_ref().try_clone()
    }

    pub fn next(&mut self) -> Option<Vec<u8>> {
        chunk(&mut self.reader).ok().flatten()
    }
}

/// Runs `cmd` in a running container and returns (exit code, output),
/// through the exec API with a terminal, so output arrives unframed.
#[cfg(unix)]
pub fn exec(container: &str, cmd: &[&str]) -> io::Result<(i64, String)> {
    let created = request("POST", &format!("/containers/{container}/exec"), Some(&serde_json::json!({"Cmd": cmd, "AttachStdout": true, "AttachStderr": true, "Tty": true})))?;
    if !created.ok() {
        return Err(io::Error::other(created.error()));
    }
    let id = created.json()["Id"].as_str().unwrap_or_default().to_owned();
    let mut s = connect(Some(Duration::from_secs(120)))?;
    let body = r#"{"Detach":false,"Tty":true}"#;
    write!(
        s,
        "POST /exec/{id}/start HTTP/1.1\r\nHost: kiri\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )?;
    let mut r = BufReader::new(s);
    let (status, _, _) = head(&mut r)?;
    if status != 101 && status != 200 {
        return Err(io::Error::other(format!("exec: HTTP {status}")));
    }
    let mut out = Vec::new();
    r.read_to_end(&mut out)?;
    let code = get(&format!("/exec/{id}/json"))?["ExitCode"].as_i64().unwrap_or(-1);
    Ok((code, String::from_utf8_lossy(&out).replace("\r\n", "\n")))
}

/// A docker CLI: on PATH, else the one bundled in Kiri.app (or Kiri's bin folder on Windows).
#[cfg(unix)]
pub fn docker_cli() -> Option<PathBuf> {
    let on_path = std::env::var_os("PATH").and_then(|p| std::env::split_paths(&p).map(|d| d.join("docker")).find(|d| d.is_file()));
    on_path
        .or_else(|| {
            let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
            Some(exe.parent()?.join("../Resources/bin/docker")).filter(|d| d.is_file())
        })
        .or_else(lite_cli)
}

#[cfg(windows)]
pub fn docker_cli() -> Option<PathBuf> {
    let beside = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("docker.exe")))
        .filter(|d| d.is_file());
    let local = || {
        let base = PathBuf::from(std::env::var_os("LOCALAPPDATA")?);
        [
            base.join("Kiri").join("bin").join("docker.exe"),
            base.join("Programs").join("Kiri").join("bin").join("docker.exe"),
            base.join("Programs").join("Kiri").join("docker.exe"),
        ]
        .into_iter()
        .find(|d| d.is_file())
    };
    let on_path = || {
        std::env::var_os("PATH")
            .and_then(|p| std::env::split_paths(&p).map(|d| d.join("docker.exe")).find(|d| d.is_file()))
    };
    beside.or_else(local).or_else(on_path)
}

/// Kiri Lite's downloaded CLI.
#[cfg(target_os = "macos")]
fn lite_cli() -> Option<PathBuf> {
    crate::tools::dir().ok().map(|d| d.join("docker")).filter(|d| d.is_file())
}

#[cfg(not(target_os = "macos"))]
fn lite_cli() -> Option<PathBuf> {
    None
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::ffi::OsStr;
    #[cfg(unix)]
    use std::io::{Read, Write};
    use std::io;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::os::unix::net::UnixListener;
    #[cfg(unix)]
    use std::path::{Path, PathBuf};
    #[cfg(unix)]
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    fn temp_dir(tag: &str) -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("kiri-client-{tag}-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// `kiri import` streams a container's writable layer (#410): the body
    /// is chunked, and ended only when all of it was written, so the daemon
    /// never takes a copy cut short for a whole one.
    #[test]
    fn a_streamed_body_is_chunked_and_ended_only_when_whole() {
        let mut wire = Vec::new();
        super::stream_body(&mut wire, |w| {
            w.write_all(b"hello")?;
            w.write_all(b" world")
        })
        .unwrap();
        assert_eq!(wire, b"b\r\nhello world\r\n0\r\n\r\n");
        let mut wire = Vec::new();
        let e = super::stream_body(&mut wire, |w| {
            w.write_all(b"part")?;
            Err(io::Error::other("the source failed"))
        })
        .unwrap_err();
        assert_eq!(e.to_string(), "the source failed");
        assert!(!wire.ends_with(b"0\r\n\r\n"), "{:?}", String::from_utf8_lossy(&wire));
        assert!(super::refused(&io::Error::from(io::ErrorKind::BrokenPipe)) && !super::refused(&io::Error::other("x")));
    }

    #[cfg(unix)]
    #[test]
    fn socket_for_discovers_wsl_integration_sockets_and_symlinks() {
        let root = temp_dir("wsl-sock");
        let home = root.join("home/alice");
        let service = root.join("run/kiri/docker.sock");
        let wsl_sockets = root.join("mnt/wsl/kiri/sockets");
        let ubuntu_sock = wsl_sockets.join("Ubuntu/docker.sock");
        let var_run_link = root.join("var/run/docker.sock");
        let run_link = root.join("run/docker.sock");
        for d in [home.as_path(), service.parent().unwrap(), ubuntu_sock.parent().unwrap(), var_run_link.parent().unwrap(), run_link.parent().unwrap()] {
            std::fs::create_dir_all(d).unwrap();
        }
        let home_sock = home.join(crate::flavor::STATE.get()).join("run/docker.sock");

        // 1. Nothing exists yet: falls back to HOME socket.
        assert_eq!(
            super::socket_for(None, Some(&service), Some(OsStr::new("Ubuntu")), Some(&wsl_sockets), &[&var_run_link, &run_link], Some(home.as_os_str())).unwrap(),
            home_sock
        );

        // 2. WSL integration socket for WSL_DISTRO_NAME exists: discovered cleanly.
        std::fs::write(&ubuntu_sock, "").unwrap();
        assert_eq!(
            super::socket_for(None, Some(&service), Some(OsStr::new("Ubuntu")), Some(&wsl_sockets), &[&var_run_link, &run_link], Some(home.as_os_str())).unwrap(),
            ubuntu_sock
        );

        // 3. Unsafe WSL_DISTRO_NAME values are ignored (never traverse outside wsl_sockets).
        for bad in ["", ".", "..", "../Ubuntu", "Ubuntu/..", "a/b", r"a\b", "foo..bar", "Ubuntu\n"] {
            assert_eq!(
                super::socket_for(None, Some(&service), Some(OsStr::new(bad)), Some(&wsl_sockets), &[&var_run_link, &run_link], Some(home.as_os_str())).unwrap(),
                home_sock,
                "unsafe distro name must be ignored: {bad:?}"
            );
        }

        // 4. When WSL_DISTRO_NAME is stripped (sudo/ssh/cron), /var/run/docker.sock -> /mnt/wsl/kiri/sockets/<distro>/docker.sock resolves.
        std::os::unix::fs::symlink(&ubuntu_sock, &var_run_link).unwrap();
        assert_eq!(
            super::socket_for(None, Some(&service), None, Some(&wsl_sockets), &[&var_run_link, &run_link], Some(home.as_os_str())).unwrap(),
            ubuntu_sock
        );
        // Same through /run/docker.sock when /var/run/docker.sock is absent.
        std::fs::remove_file(&var_run_link).unwrap();
        std::os::unix::fs::symlink(&ubuntu_sock, &run_link).unwrap();
        assert_eq!(
            super::socket_for(None, Some(&service), None, Some(&wsl_sockets), &[&var_run_link, &run_link], Some(home.as_os_str())).unwrap(),
            ubuntu_sock
        );

        // 5. Symlinks outside wsl_sockets or with traversal are ignored.
        std::fs::remove_file(&run_link).unwrap();
        let other_sock = root.join("other.sock");
        std::fs::write(&other_sock, "").unwrap();
        std::os::unix::fs::symlink(&other_sock, &var_run_link).unwrap();
        let traversal = wsl_sockets.join("../other/docker.sock");
        std::os::unix::fs::symlink(&traversal, &run_link).unwrap();
        assert_eq!(
            super::socket_for(None, Some(&service), None, Some(&wsl_sockets), &[&var_run_link, &run_link], Some(home.as_os_str())).unwrap(),
            home_sock
        );

        // 6. Service socket (/run/kiri/docker.sock) takes precedence over WSL sockets.
        std::fs::write(&service, "").unwrap();
        assert_eq!(
            super::socket_for(None, Some(&service), Some(OsStr::new("Ubuntu")), Some(&wsl_sockets), &[&var_run_link, &run_link], Some(home.as_os_str())).unwrap(),
            service
        );

        // 7. Explicit KIRI_SOCKET takes precedence over everything.
        assert_eq!(
            super::socket_for(Some(OsStr::new("/custom/kiri.sock")), Some(&service), Some(OsStr::new("Ubuntu")), Some(&wsl_sockets), &[&var_run_link, &run_link], Some(home.as_os_str())).unwrap(),
            PathBuf::from("/custom/kiri.sock")
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn check_alive_distinguishes_alive_not_running_and_permission_denied() {
        let dir = temp_dir("alive");
        let missing = dir.join("missing.sock");
        let err = super::check_alive_at(&missing, "not running msg").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
        assert_eq!(err.to_string(), "not running msg");

        // Live server responding 200 OK to /_ping succeeds.
        let live = dir.join("live.sock");
        let listener = UnixListener::bind(&live).unwrap();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 256];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match conn.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => req.extend_from_slice(&buf[..n]),
                }
            }
            conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK").unwrap();
            let _ = conn.flush();
            let _ = conn.shutdown(std::net::Shutdown::Write);
        });
        super::check_alive_at(&live, "not running msg").unwrap();
        server.join().unwrap();

        // Linux permission-denied message guides user to host-access.
        let linux_perm = super::permission_denied_error(Path::new("/run/kiri/docker.sock"), true);
        assert_eq!(linux_perm.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            linux_perm.to_string(),
            "cannot connect to Kiri's socket (/run/kiri/docker.sock): permission denied. Run `sudo kiri host-access $USER` (or open Kiri) to grant access"
        );

        // Unprivileged connect to a 0000 socket surfaces PermissionDenied directly.
        // SAFETY: geteuid cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            let locked = dir.join("locked.sock");
            let _listener = UnixListener::bind(&locked).unwrap();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            let err = super::check_alive_at(&locked, "not running msg").unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
            assert!(err.to_string().contains("permission denied"), "got: {err}");
            assert!(err.to_string().contains(&locked.display().to_string()), "got: {err}");
        }

        // OS- and WSL-specific not-running messages.
        assert_eq!(
            super::not_running_message_for(false, false),
            "Kiri isn't running. Open Kiri, or start it with `kiri daemon`"
        );
        assert_eq!(
            super::not_running_message_for(true, true),
            "Kiri isn't running. Open Kiri on Windows (and enable this distro in Settings -> Resources -> WSL integration), or run `sudo kiri host-access $USER`"
        );
        assert_eq!(
            super::not_running_message_for(true, false),
            "Kiri isn't running. Open Kiri, or run `sudo kiri host-access $USER` (or `sudo kiri daemon`)"
        );

        // WSL detection via WSL_DISTRO_NAME or binfmt_misc interop file.
        let interop = dir.join("WSLInterop");
        assert!(!super::is_wsl_env(None, &[&interop]));
        assert!(!super::is_wsl_env(Some(OsStr::new("")), &[&interop]));
        assert!(super::is_wsl_env(Some(OsStr::new("Ubuntu")), &[&interop]));
        std::fs::write(&interop, "enabled\n").unwrap();
        assert!(super::is_wsl_env(None, &[&interop]));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
