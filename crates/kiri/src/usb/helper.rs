//! The USB helper: capturing a device from macOS takes root, so the first
//! attach installs a small LaunchDaemon (one administrator prompt, once),
//! and every attach after that just asks it.
//!
//! The helper is a root-owned copy of this binary in
//! /Library/PrivilegedHelperTools, run by launchd as `kiri usb helper`. It
//! listens on a socket in /var/run and takes requests only from the user
//! who installed it. A request is a device's location plus a connection,
//! passed as a file descriptor: the caller (`kiri usb attach`, the window)
//! makes the connection to its own daemon, so the helper never opens a path
//! a user named. For each device the helper starts `kiri usb serve`, which
//! captures it and serves it over that connection until either side lets
//! go, then gives it back to macOS.
//!
//! The helper is replaced when it differs from the Kiri asking (an update):
//! that is one more prompt.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::flavor::Name;

/// The LaunchDaemon's label, and the name of everything it installs.
pub const LABEL: Name = Name("dev.kiri.usb", "dev.kiri.usb.dev");

/// Devices one helper serves at once; vhci has 8 ports per speed.
const MAX_SESSIONS: usize = 32;
/// Concurrent authenticated handler threads (including in-flight requests).
const MAX_HANDLERS: usize = MAX_SESSIONS * 2;

fn binary() -> PathBuf {
    PathBuf::from(format!("/Library/PrivilegedHelperTools/{LABEL}"))
}
fn plist() -> PathBuf {
    PathBuf::from(format!("/Library/LaunchDaemons/{LABEL}.plist"))
}
fn socket() -> PathBuf {
    PathBuf::from(format!("/var/run/{LABEL}.sock"))
}

/// The Kiri build the installed helper was copied from, written beside it.
fn source() -> PathBuf {
    PathBuf::from(format!("/Library/PrivilegedHelperTools/{LABEL}.source"))
}

/// This binary's SHA-256, as hex.
fn digest(path: &Path) -> io::Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)?;
    Ok(Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect())
}

/// Whether the installed helper was copied from this Kiri. (Not compared
/// byte for byte: the copy is signed again on its own, see `install`.)
fn current() -> bool {
    if !binary().exists() || !plist().exists() {
        return false;
    }
    let (Ok(me), Ok(installed)) = (std::env::current_exe(), std::fs::read_to_string(source())) else { return false };
    digest(&me).is_ok_and(|d| d == installed.trim())
}

/// Reads the running binary's designated code-signing requirement when it is
/// signed with a non-ad-hoc identity (e.g. Developer ID), or `None` for local
/// unsigned/ad-hoc development builds.
fn designated_requirement(me: &Path) -> Option<String> {
    let out = Command::new("/usr/bin/codesign").args(["-d", "-r", "-"]).arg(me).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let req = String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("designated => ").map(str::trim).map(str::to_owned))
        .filter(|r| !r.is_empty())?;
    // Ad-hoc signatures have `cdhash H"..."` only; still verifiable against `me`!
    Some(req)
}

/// Builds the privileged shell script that installs the USB helper binary and
/// LaunchDaemon plist via a root-only `0700` staging directory, verifying the
/// copied binary's SHA-256 (and code signature when present) *as root* before
/// re-signing and atomically moving it into place.
#[allow(clippy::too_many_arguments)]
fn install_command(
    me: &Path,
    bin: &Path,
    src: &Path,
    plist: &Path,
    label: &str,
    uid: u32,
    sum: &str,
    designated_req: Option<&str>,
) -> String {
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key><array><string>{}</string><string>usb</string><string>helper</string><string>{label}</string><string>{uid}</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardErrorPath</key><string>/var/log/{label}.log</string>
</dict>
</plist>
"#,
        esc(&bin.to_string_lossy())
    );
    let plist_b64 = crate::setup::b64_encode(body.as_bytes());
    let q = |p: &Path| sh_quote(&p.to_string_lossy());
    let me_q = q(me);
    let codesign_check = match designated_req {
        Some(req) => format!("/usr/bin/codesign --verify --strict -R={} {me_q}; ", sh_quote(req)),
        None => String::new(),
    };
    // The copy is root's: a helper that ran a binary in the user's app
    // bundle would run whatever replaced it, as root. Copy into a root-only
    // 0700 staging directory first, verify its SHA-256 against the digest
    // computed before the prompt (and the source binary's code signature when
    // present) to defeat any TOCTOU swap during the admin prompt, then re-sign
    // the standalone copy (Kiri's own signature seals Info.plist, which the
    // standalone copy is without) and atomically move everything into place.
    format!(
        "set -e; stage=$(/usr/bin/mktemp -d /var/root/.kiri-usb-install.XXXXXX); \
         trap 'rm -rf \"$stage\"' EXIT; chmod 700 \"$stage\"; \
         [ -f {me} ] && [ ! -L {me} ]; \
         {codesign_check}cp {me} \"$stage/bin\"; \
         got=$(/usr/bin/shasum -a 256 \"$stage/bin\" | /usr/bin/awk '{{print $1}}'); \
         [ \"$got\" = {sum_q} ]; \
         /usr/bin/codesign --force --sign - --identifier {label_q} \"$stage/bin\"; \
         chown root:wheel \"$stage/bin\"; chmod 755 \"$stage/bin\"; \
         mkdir -p /Library/PrivilegedHelperTools; mv -f \"$stage/bin\" {bin}; \
         printf '%s\\n' {sum_q} > \"$stage/source\"; chown root:wheel \"$stage/source\"; chmod 644 \"$stage/source\"; mv -f \"$stage/source\" {src}; \
         printf '%s' '{plist_b64}' | /usr/bin/base64 -D > \"$stage/plist\"; chown root:wheel \"$stage/plist\"; chmod 644 \"$stage/plist\"; mv -f \"$stage/plist\" {plist}; \
         launchctl bootout system/{label} 2>/dev/null || true; launchctl bootstrap system {plist}",
        me = me_q,
        bin = q(bin),
        src = q(src),
        plist = q(plist),
        sum_q = sh_quote(sum),
        label_q = sh_quote(label),
    )
}

/// Installs (or replaces) the helper: the one administrator prompt.
fn install() -> io::Result<()> {
    let me = std::env::current_exe()?.canonicalize()?;
    let (bin, plist, label) = (binary(), plist(), LABEL.get());
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    let sum = digest(&me)?;
    let req = designated_requirement(&me);
    let command = install_command(&me, &bin, &source(), &plist, label, uid, &sum, req.as_deref());
    crate::setup::as_admin(&command, "Kiri wants to install its USB helper, so it can connect USB devices to its Linux VM. It asks once.")
}

/// Removes the helper (`kiri usb helper remove`, and uninstalling Kiri).
pub fn remove() -> io::Result<()> {
    if !plist().exists() && !binary().exists() {
        return Ok(());
    }
    let (bin, plist) = (binary(), plist());
    let command = format!(
        "launchctl bootout system/{} 2>/dev/null; rm -f {} {} {} {}",
        LABEL.get(),
        sh_quote(&plist.to_string_lossy()),
        sh_quote(&bin.to_string_lossy()),
        sh_quote(&source().to_string_lossy()),
        sh_quote(&socket().to_string_lossy())
    );
    crate::setup::as_admin(&command, "Kiri wants to remove its USB helper.")?;
    println!("removed the USB helper");
    Ok(())
}

/// A connection to the helper, installing or replacing it first if it
/// isn't this Kiri.
fn connect() -> io::Result<UnixStream> {
    if !current() {
        install()?;
    }
    // launchd starts it on bootstrap; give it a moment to listen.
    let mut last = None;
    for _ in 0..50 {
        match UnixStream::connect(socket()) {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(io::Error::other(format!("the USB helper isn't answering ({})", last.map(|e| e.to_string()).unwrap_or_default())))
}

/// Attaches the device at `location`: the connection to the daemon is made
/// here and handed to the helper, which captures the device and serves it.
/// Returns once the device is captured, or with why it couldn't be.
pub fn attach(location: &str, name: &str, speed: u32, devid: u32) -> io::Result<()> {
    attach_through(connect()?, location, name, speed, devid)
}

/// The same, for the daemon attaching a device again when it comes back:
/// never the administrator prompt, so only through a helper that is
/// already this Kiri's.
pub fn reattach(location: &str, name: &str, speed: u32, devid: u32) -> io::Result<()> {
    if !current() {
        return Err(io::Error::other("the USB helper is not this Kiri's (attach it once from the window to update it)"));
    }
    attach_through(UnixStream::connect(socket())?, location, name, speed, devid)
}

fn attach_through(helper: UnixStream, location: &str, name: &str, speed: u32, devid: u32) -> io::Result<()> {
    let (stream, _reader) = super::usbip::connect(&crate::client::socket()?, location, name, speed, devid)?;
    send_fd(&helper, format!("attach {location}\n").as_bytes(), stream.as_raw_fd())?;
    // The helper and its server hold the connection now.
    drop(stream);
    helper.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut line = String::new();
    BufReader::new(&helper).read_line(&mut line)?;
    match line.trim_end() {
        "ok" => Ok(()),
        "" => Err(io::Error::other("the USB helper stopped before it took the device")),
        l => Err(io::Error::other(l.strip_prefix("error: ").unwrap_or(l).to_owned())),
    }
}

// --- The helper itself (root, under launchd) ----------------------------------------

/// Checks synchronously whether `conn`'s peer UID is `uid` or `0` (root).
fn peer_authorized(conn: &UnixStream, uid: libc::uid_t) -> io::Result<bool> {
    let (mut peer_uid, mut peer_gid) = (0, 0);
    // SAFETY: getpeereid on a connected UnixStream we own, writing two ids.
    if unsafe { libc::getpeereid(conn.as_raw_fd(), &mut peer_uid, &mut peer_gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(peer_uid == uid || peer_uid == 0)
}

/// Drop guard that decrements an `AtomicUsize` concurrency slot on exit.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn try_acquire_slot(counter: &Arc<AtomicUsize>, limit: usize) -> Option<Slot> {
    let mut cur = counter.load(Ordering::SeqCst);
    loop {
        if cur >= limit {
            return None;
        }
        match counter.compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return Some(Slot(counter.clone())),
            Err(next) => cur = next,
        }
    }
}

/// `kiri usb helper LABEL UID`: serves attach requests from UID until
/// launchd stops it.
pub fn serve(label: &str, uid: &str) -> io::Result<()> {
    // SAFETY: getuid has no preconditions.
    if unsafe { libc::getuid() } != 0 {
        return Err(io::Error::other("the USB helper runs as root, under launchd"));
    }
    let uid: libc::uid_t = uid.parse().map_err(|_| io::Error::other("bad uid"))?;
    if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
        return Err(io::Error::other("bad label"));
    }
    let path = PathBuf::from(format!("/var/run/{label}.sock"));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    // Anyone may connect; only `uid` (and root) is answered.
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o666))?;
    // Children are reaped by their own threads; a dead one's device has
    // already gone back to macOS.
    let exe = std::env::current_exe()?;
    let sessions = Arc::new(AtomicUsize::new(0));
    let handlers = Arc::new(AtomicUsize::new(0));
    super::mac::log(&format!("helper listening for uid {uid}"));
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        // Authorize peer UID synchronously on the accept thread so an
        // unauthorized local user cannot spawn threads in the root helper.
        match peer_authorized(&conn, uid) {
            Ok(true) => {}
            Ok(false) => {
                let _ = conn.set_write_timeout(Some(Duration::from_millis(100)));
                let _ = writeln!(&conn, "error: not your USB helper");
                continue;
            }
            Err(_) => continue,
        }
        let Some(slot) = try_acquire_slot(&handlers, MAX_HANDLERS) else {
            let _ = conn.set_write_timeout(Some(Duration::from_millis(100)));
            let _ = writeln!(&conn, "error: too many concurrent requests");
            continue;
        };
        let (exe, sessions) = (exe.clone(), sessions.clone());
        let _ = std::thread::Builder::new().name("kiri-usb-req".into()).spawn(move || {
            let _slot = slot;
            if let Err(e) = request(&conn, uid, &exe, &sessions) {
                let _ = writeln!(&conn, "error: {e}");
            }
        });
    }
    Ok(())
}

fn request(conn: &UnixStream, uid: libc::uid_t, exe: &Path, sessions: &Arc<AtomicUsize>) -> io::Result<()> {
    if !peer_authorized(conn, uid)? {
        return Err(io::Error::other("not your USB helper"));
    }
    conn.set_read_timeout(Some(Duration::from_secs(10)))?;
    let (line, fd) = recv_fd(conn)?;
    let line = String::from_utf8_lossy(&line).into_owned();
    let Some(location) = line.trim_end().strip_prefix("attach ") else { return Err(io::Error::other("unknown request")) };
    let Some(fd) = fd else { return Err(io::Error::other("no connection came with the request")) };
    let valid = location.strip_prefix("0x").is_some_and(|h| !h.is_empty() && h.len() <= 8 && h.bytes().all(|b| b.is_ascii_hexdigit()));
    if !valid {
        return Err(io::Error::other(format!("bad location {location:?}")));
    }
    // The connection must be a socket: the server speaks USB/IP over it.
    // SAFETY: fstat into a zeroed stat.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 || st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(io::Error::other("the connection isn't a socket"));
    }
    if sessions.fetch_add(1, Ordering::SeqCst) >= MAX_SESSIONS {
        sessions.fetch_sub(1, Ordering::SeqCst);
        return Err(io::Error::other("too many devices attached"));
    }
    let status = conn.try_clone()?;
    let result = spawn(exe, location, fd, status);
    let mut child = match result {
        Ok(c) => c,
        Err(e) => {
            sessions.fetch_sub(1, Ordering::SeqCst);
            return Err(e);
        }
    };
    let _ = child.wait();
    sessions.fetch_sub(1, Ordering::SeqCst);
    Ok(())
}

/// Relocates descriptors `a` and `b` to FDs 3 and 4 inside `pre_exec`.
/// Uses `F_DUPFD` with minimum FD 5 so the temporary copies can never collide
/// with target FDs 3 or 4 (avoiding closing 3/4 when either was free).
///
/// # Safety
/// Must only be called in a child process after `fork` (async-signal-safe).
unsafe fn relocate_child_fds(a: RawFd, b: RawFd) -> io::Result<()> {
    let ta = unsafe { libc::fcntl(a, libc::F_DUPFD, 5) };
    if ta < 0 {
        return Err(io::Error::last_os_error());
    }
    let tb = unsafe { libc::fcntl(b, libc::F_DUPFD, 5) };
    if tb < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(ta) };
        return Err(err);
    }
    let ok = unsafe { libc::dup2(ta, 3) >= 0 && libc::dup2(tb, 4) >= 0 };
    let err = if ok { None } else { Some(io::Error::last_os_error()) };
    unsafe {
        libc::close(ta);
        libc::close(tb);
    }
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// `kiri usb serve LOCATION --fd 3 --status 4`, with the USB/IP
/// connection as fd 3 and the requester's connection as fd 4 for its "ok".
fn spawn(exe: &Path, location: &str, conn: OwnedFd, status: UnixStream) -> io::Result<std::process::Child> {
    let (a, b) = (conn.as_raw_fd(), status.as_raw_fd());
    let mut cmd = Command::new(exe);
    cmd.args(["usb", "serve", location, "--fd", "3", "--status", "4"])
        .env_clear()
        .env("HOME", "/var/root")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    // SAFETY: `relocate_child_fds` calls only async-signal-safe `fcntl`/`dup2`/`close`.
    unsafe {
        cmd.pre_exec(move || relocate_child_fds(a, b));
    }
    let child = cmd.spawn();
    drop(conn);
    drop(status);
    child
}

// --- Descriptor passing ------------------------------------------------------------

fn send_fd(sock: &UnixStream, data: &[u8], fd: RawFd) -> io::Result<()> {
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut control = vec![0u8; space];
    let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut _, iov_len: data.len() };
    // SAFETY: a msghdr over buffers that outlive the call, with one
    // SCM_RIGHTS header written inside `control`.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(c).cast::<RawFd>(), fd);
        if libc::sendmsg(sock.as_raw_fd(), &msg, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// One request line and the descriptor sent with it, if any.
fn recv_fd(sock: &UnixStream) -> io::Result<(Vec<u8>, Option<OwnedFd>)> {
    let mut buf = vec![0u8; 256];
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut control = vec![0u8; space];
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    let mut fd = None;
    // SAFETY: recvmsg into buffers we own; only SCM_RIGHTS headers that fit
    // are read, and each descriptor received is owned from here on.
    let n = unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        let n = libc::recvmsg(sock.as_raw_fd(), &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let ctrl_start = control.as_ptr() as usize;
        let ctrl_end = ctrl_start.saturating_add((msg.msg_controllen as usize).min(control.len()));
        let hdr_len = libc::CMSG_LEN(0) as usize;
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET
                && (*c).cmsg_type == libc::SCM_RIGHTS
                && let Some(payload_len) = ((*c).cmsg_len as usize).checked_sub(hdr_len)
            {
                let data_ptr = libc::CMSG_DATA(c);
                let avail = ctrl_end.saturating_sub(data_ptr as usize);
                let count = payload_len.min(avail) / std::mem::size_of::<RawFd>();
                for i in 0..count {
                    let raw = std::ptr::read_unaligned(data_ptr.cast::<RawFd>().add(i));
                    if raw >= 0 {
                        let owned = OwnedFd::from_raw_fd(raw);
                        // One is expected; any more are closed immediately on drop.
                        if fd.is_none() {
                            fd = Some(owned);
                        }
                    }
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            drop(fd);
            return Err(io::Error::other("the request carried too many descriptors"));
        }
        n as usize
    };
    buf.truncate(n);
    // The rest of the line, if it came in pieces (it doesn't, in practice).
    if !buf.ends_with(b"\n") && buf.len() < 256 {
        let mut more = [0u8; 1];
        let mut s = sock;
        while buf.len() < 256 && s.read(&mut more)? == 1 {
            buf.push(more[0]);
            if more[0] == b'\n' {
                break;
            }
        }
    }
    Ok((buf, fd))
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_descriptor_crosses_with_its_line() {
        let (a, b) = UnixStream::pair().unwrap();
        let (x, mut y) = UnixStream::pair().unwrap();
        send_fd(&a, b"attach 0x01100000\n", x.as_raw_fd()).unwrap();
        drop(x);
        let (line, fd) = recv_fd(&b).unwrap();
        assert_eq!(line, b"attach 0x01100000\n");
        let mut got = UnixStream::from(fd.unwrap());
        got.write_all(b"hi").unwrap();
        let mut buf = [0u8; 2];
        y.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hi");
    }

    #[test]
    fn a_line_without_a_descriptor() {
        let (a, b) = UnixStream::pair().unwrap();
        (&a).write_all(b"attach 0x1\n").unwrap();
        let (line, fd) = recv_fd(&b).unwrap();
        assert_eq!(line, b"attach 0x1\n");
        assert!(fd.is_none());
    }

    #[test]
    fn install_command_avoids_temp_dir_and_verifies_sha256_and_codesign() {
        let tmp_str = std::env::temp_dir().to_string_lossy().into_owned();
        let cmd = install_command(
            Path::new("/Applications/Kiri.app/Contents/MacOS/kiri"),
            Path::new("/Library/PrivilegedHelperTools/dev.kiri.usb"),
            Path::new("/Library/PrivilegedHelperTools/dev.kiri.usb.source"),
            Path::new("/Library/LaunchDaemons/dev.kiri.usb.plist"),
            "dev.kiri.usb",
            501,
            "0123456789abcdef",
            Some("identifier \"dev.kiri.app\""),
        );
        assert!(!cmd.contains(&tmp_str), "must not stage in temp_dir: {cmd}");
        assert!(cmd.contains("/var/root/.kiri-usb-install."), "{cmd}");
        assert!(cmd.contains("/usr/bin/shasum -a 256 \"$stage/bin\""), "{cmd}");
        assert!(cmd.contains("/usr/bin/codesign --verify --strict"), "{cmd}");
        assert!(cmd.contains("/usr/bin/base64 -D > \"$stage/plist\""), "{cmd}");
        let sha_pos = cmd.find("/usr/bin/shasum").unwrap();
        let sign_pos = cmd.find("/usr/bin/codesign --force").unwrap();
        assert!(sha_pos < sign_pos, "must verify SHA-256 before re-signing");
    }

    #[test]
    fn recv_fd_rejects_truncated_multi_fd_control_without_panicking() {
        let (a, b) = UnixStream::pair().unwrap();
        let (x1, _y1) = UnixStream::pair().unwrap();
        let (x2, _y2) = UnixStream::pair().unwrap();
        let fds = [x1.as_raw_fd(), x2.as_raw_fd()];
        let data = b"attach 0x1\n";
        let space = unsafe { libc::CMSG_SPACE((std::mem::size_of_val(&fds)) as u32) } as usize;
        let mut control = vec![0u8; space];
        let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut _, iov_len: data.len() };
        unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN((std::mem::size_of_val(&fds)) as u32) as _;
            std::ptr::copy_nonoverlapping(fds.as_ptr().cast::<u8>(), libc::CMSG_DATA(c), std::mem::size_of_val(&fds));
            assert!(libc::sendmsg(a.as_raw_fd(), &msg, 0) >= 0);
        }
        // Buffer only fits 1 FD, so kernel sets MSG_CTRUNC; recv_fd must error cleanly.
        let err = recv_fd(&b).unwrap_err();
        assert!(err.to_string().contains("too many descriptors"), "{err}");
    }

    #[test]
    fn relocate_child_fds_preserves_fd_3_and_4_even_when_free() {
        let (a_in, mut a_out) = UnixStream::pair().unwrap();
        let (b_in, mut b_out) = UnixStream::pair().unwrap();
        let (a_fd, b_fd) = (a_in.as_raw_fd(), b_in.as_raw_fd());
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "printf 'A' >&3 && printf 'B' >&4"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            cmd.pre_exec(move || {
                // Close 3 and 4 first if they aren't a_fd/b_fd so `dup()` would
                // have collided with 3/4 and closed them!
                if a_fd != 3 && b_fd != 3 {
                    libc::close(3);
                }
                if a_fd != 4 && b_fd != 4 {
                    libc::close(4);
                }
                relocate_child_fds(a_fd, b_fd)
            });
        }
        let status = cmd.status().unwrap();
        drop(a_in);
        drop(b_in);
        assert!(status.success(), "child failed: {status}");
        let mut got_a = String::new();
        let mut got_b = String::new();
        a_out.read_to_string(&mut got_a).unwrap();
        b_out.read_to_string(&mut got_b).unwrap();
        assert_eq!(got_a, "A");
        assert_eq!(got_b, "B");
    }

    #[test]
    fn handler_slots_enforce_limit() {
        let c = Arc::new(AtomicUsize::new(0));
        let s1 = try_acquire_slot(&c, 2).unwrap();
        let s2 = try_acquire_slot(&c, 2).unwrap();
        assert!(try_acquire_slot(&c, 2).is_none());
        drop(s1);
        let s3 = try_acquire_slot(&c, 2).unwrap();
        drop(s2);
        drop(s3);
        assert_eq!(c.load(Ordering::SeqCst), 0);
    }
}
