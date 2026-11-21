//! `ADD <url>` for the native builder: the GET BuildKit's HTTP source makes
//! (source/http/source.go), from the engine, as buildkitd makes it from its
//! own network.
//!
//! One request, no retry (BuildKit v0.33.1 has none); redirects followed,
//! at most 10, as Go's client does; the body as the server sent it, never
//! decoded (no `Accept-Encoding` is sent, so there is nothing to undo);
//! proxies from the environment, as Go's default transport takes them. The
//! core does the rest: the status rule, the checksum, the file's name, mode
//! and time.

use std::io::{self, Write};
use std::time::Duration;

use kiri_forge::ports::{Cancel, Error, HttpReply};

/// Engine-side bounds of a request, whatever the core asks.
#[derive(Clone, Copy)]
struct Bounds {
    global: Option<Duration>,
    per_read: Option<Duration>,
}

/// An agent for one request of a build: its connections are made by
/// [`Tcp`], so the build's cancel ends a connect, and closes a connection
/// at once (`while_not_cancelled` shuts it down; dropped, it is reset).
fn agent_with(bounds: Bounds, cancel: &Cancel) -> ureq::Agent {
    use ureq::unversioned::transport::{ConnectProxyConnector, Connector as _, RustlsConnector};
    let config = ureq::Agent::config_builder()
        // Any status is the core's to judge (`invalid response status N`).
        .http_status_as_error(false)
        // At most 10, as Go's client follows them.
        .max_redirects(10)
        // An Authorization header never follows a redirect ureq makes: a
        // URL's own password is sent again only where its user is kept (a
        // relative Location), as Go's client does under BuildKit.
        .redirect_auth_headers(ureq::config::RedirectAuthHeaders::Never)
        .timeout_connect(Some(Duration::from_secs(30)))
        .timeout_global(bounds.global)
        .timeout_per_read(bounds.per_read)
        .user_agent(concat!("kiri/", env!("CARGO_PKG_VERSION")))
        .build();
    // ureq's own chain (a CONNECT proxy, TCP, TLS), with the TCP step ours.
    let connector = ().chain(ConnectProxyConnector::default()).chain(Tcp { cancel: cancel.clone() }).chain(RustlsConnector::default());
    if cfg!(target_os = "macos") {
        return ureq::Agent::with_parts(config, connector, HostNames);
    }
    ureq::Agent::with_parts(config, connector, ureq::unversioned::resolver::DefaultResolver::default())
}

fn canceled() -> io::Error {
    io::Error::other(kiri_forge::fetch::CANCELED)
}

/// The TCP step of a build's request: a connect the build's cancel ends
/// (looked at every 50 ms while the server has not answered the SYN), and
/// a connection that is reset, never left half open, when the build is
/// cancelled.
#[derive(Debug)]
struct Tcp {
    cancel: Cancel,
}

impl<In: ureq::unversioned::transport::Transport> ureq::unversioned::transport::Connector<In> for Tcp {
    type Out = ureq::unversioned::transport::Either<In, Conn>;

    fn connect(&self, details: &ureq::unversioned::transport::ConnectionDetails, chained: Option<In>) -> Result<Option<Self::Out>, ureq::Error> {
        use ureq::unversioned::transport::Either;
        if let Some(t) = chained {
            return Ok(Some(Either::A(t)));
        }
        let start = std::time::Instant::now();
        let total = details.timeout.not_zero().map(|d| *d);
        // ureq's own share of the connect time between a name's addresses:
        // 1, 1/2, 1/4... of it, each at least 10 ms, so a first address that
        // never answers leaves time for the next.
        let n = details.addrs.len() as i32;
        let total_weight = 2.0 * (1.0 - 0.5_f64.powi(n));
        let mut weight = 1.0_f64;
        let mut last = None;
        for addr in &details.addrs {
            let deadline = total.map(|t| std::time::Instant::now() + t.mul_f64(weight / total_weight).max(Duration::from_millis(10)));
            weight /= 2.0;
            match connect(addr, deadline, &self.cancel) {
                Ok(stream) => {
                    if details.config.no_delay() {
                        stream.set_nodelay(true)?;
                    }
                    let stream = std::sync::Arc::new(Abortable(stream));
                    let handle: std::sync::Weak<dyn ureq::unversioned::transport::ShutdownHandle> = std::sync::Arc::downgrade(&stream) as _;
                    (details.register_shutdown)(handle)?;
                    let buffers = ureq::unversioned::transport::LazyBuffers::new(details.config.input_buffer_size(), details.config.output_buffer_size());
                    return Ok(Some(Either::B(Conn { stream, buffers, cancel: self.cancel.clone(), read: None, write: None })));
                }
                Err(e) if self.cancel.is_cancelled() => return Err(e.into()),
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                    if total.is_some_and(|t| start.elapsed() >= t) {
                        return Err(ureq::Error::Timeout(details.timeout.reason));
                    }
                    last = Some(ureq::Error::Timeout(details.timeout.reason));
                }
                // Refused or unreachable: the next address, as ureq does.
                Err(e) if matches!(e.kind(), io::ErrorKind::ConnectionRefused | io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable | io::ErrorKind::AddrNotAvailable) => last = Some(e.into()),
                Err(e) => return Err(e.into()),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::ConnectionRefused, "Connection refused").into()))
    }
}

/// A connect to `addr` that ends at `deadline` (TimedOut) or when `cancel`
/// is set (`context canceled`), the socket then closed.
fn connect(addr: &std::net::SocketAddr, deadline: Option<std::time::Instant>, cancel: &Cancel) -> io::Result<std::net::TcpStream> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    if cancel.is_cancelled() {
        return Err(canceled());
    }
    let family = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
    #[cfg(target_os = "linux")]
    let kind = libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    #[cfg(not(target_os = "linux"))]
    let kind = libc::SOCK_STREAM;
    // SAFETY: a new socket; its descriptor is owned below.
    let fd = unsafe { libc::socket(family, kind, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a socket just made and owned by nothing else.
    let stream = std::net::TcpStream::from(unsafe { OwnedFd::from_raw_fd(fd) });
    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: flags of a descriptor this function owns.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        stream.set_nonblocking(true)?;
        // No SIGPIPE from a write to a reset connection (Linux has
        // MSG_NOSIGNAL in std's writes; the Mac needs the socket option).
        let on: libc::c_int = 1;
        // SAFETY: an int option of a socket this function owns.
        unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_NOSIGPIPE, (&raw const on).cast(), std::mem::size_of::<libc::c_int>() as libc::socklen_t) };
    }
    let (sa, len) = sockaddr(addr);
    // SAFETY: `sa` holds a sockaddr of `len` bytes for this family.
    if unsafe { libc::connect(fd, (&raw const sa).cast(), len) } != 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINPROGRESS) && e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
        loop {
            if cancel.is_cancelled() {
                return Err(canceled());
            }
            let mut wait = 50;
            if let Some(d) = deadline {
                let left = d.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                wait = wait.min(left.as_millis().max(1) as libc::c_int);
            }
            let mut p = libc::pollfd { fd: stream.as_raw_fd(), events: libc::POLLOUT, revents: 0 };
            // SAFETY: one valid pollfd for a descriptor this function owns.
            let n = unsafe { libc::poll(&mut p, 1, wait) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if n > 0 {
                break;
            }
        }
        if let Some(e) = stream.take_error()? {
            return Err(e);
        }
    }
    stream.set_nonblocking(false)?;
    Ok(stream)
}

/// `addr` as the C socket API takes it.
fn sockaddr(addr: &std::net::SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: an all-zero sockaddr_storage is a valid value.
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        std::net::SocketAddr::V4(a) => {
            // SAFETY: sockaddr_storage is large and aligned enough for any sockaddr.
            let sin = unsafe { &mut *(&raw mut ss).cast::<libc::sockaddr_in>() };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = a.port().to_be();
            sin.sin_addr = libc::in_addr { s_addr: u32::from_ne_bytes(a.ip().octets()) };
            #[cfg(not(target_os = "linux"))]
            {
                sin.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
            }
            std::mem::size_of::<libc::sockaddr_in>()
        }
        std::net::SocketAddr::V6(a) => {
            // SAFETY: as above.
            let sin6 = unsafe { &mut *(&raw mut ss).cast::<libc::sockaddr_in6>() };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = a.port().to_be();
            sin6.sin6_addr = libc::in6_addr { s6_addr: a.ip().octets() };
            sin6.sin6_flowinfo = a.flowinfo();
            sin6.sin6_scope_id = a.scope_id();
            #[cfg(not(target_os = "linux"))]
            {
                sin6.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
            }
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (ss, len as libc::socklen_t)
}

/// A connection the build's cancel shuts down from another thread: reset
/// (no linger), so neither end is left half open waiting on the other.
#[derive(Debug)]
struct Abortable(std::net::TcpStream);

impl Abortable {
    fn reset_on_close(&self) {
        use std::os::fd::AsRawFd as _;
        let l = libc::linger { l_onoff: 1, l_linger: 0 };
        // SAFETY: a linger option of a socket this value owns.
        unsafe { libc::setsockopt(self.0.as_raw_fd(), libc::SOL_SOCKET, libc::SO_LINGER, (&raw const l).cast(), std::mem::size_of::<libc::linger>() as libc::socklen_t) };
    }
}

impl ureq::unversioned::transport::ShutdownHandle for Abortable {
    fn shutdown(&self) {
        self.reset_on_close();
        // Wakes a read or write blocked on it in the request's thread.
        let _ = self.0.shutdown(std::net::Shutdown::Both);
    }
}

/// One connection of a build's request (ureq's TCP transport, on a
/// socket [`connect`] made).
#[derive(Debug)]
struct Conn {
    stream: std::sync::Arc<Abortable>,
    buffers: ureq::unversioned::transport::LazyBuffers,
    cancel: Cancel,
    /// The timeouts set on the socket, so each is set only when it changes.
    read: Option<Duration>,
    write: Option<Duration>,
}

/// The limit of one read or write: None for none; a spent one is ureq's
/// timeout error.
fn io_limit(t: &ureq::unversioned::transport::NextTimeout) -> Result<Option<Duration>, ureq::Error> {
    if !t.after.is_not_happening() && t.after.is_zero() {
        return Err(ureq::Error::Timeout(t.reason));
    }
    Ok(t.not_zero().map(|d| *d))
}

fn io_error(e: io::Error, reason: ureq::Timeout) -> ureq::Error {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => ureq::Error::Timeout(reason),
        _ => e.into(),
    }
}

impl ureq::unversioned::transport::Transport for Conn {
    fn buffers(&mut self) -> &mut dyn ureq::unversioned::transport::Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: ureq::unversioned::transport::NextTimeout) -> Result<(), ureq::Error> {
        let t = timeout.for_write();
        let limit = io_limit(&t)?;
        if limit != self.write {
            self.stream.0.set_write_timeout(limit)?;
            self.write = limit;
        }
        let out = &ureq::unversioned::transport::Buffers::output(&mut self.buffers)[..amount];
        (&self.stream.0).write_all(out).map_err(|e| io_error(e, t.reason))
    }

    fn await_input(&mut self, timeout: ureq::unversioned::transport::NextTimeout) -> Result<bool, ureq::Error> {
        use std::io::Read as _;
        let t = timeout.for_read();
        let limit = io_limit(&t)?;
        if limit != self.read {
            self.stream.0.set_read_timeout(limit)?;
            self.read = limit;
        }
        let buf = ureq::unversioned::transport::Buffers::input_append_buf(&mut self.buffers);
        let n = loop {
            match (&self.stream.0).read(buf) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                r => break r,
            }
        }
        .map_err(|e| io_error(e, t.reason))?;
        ureq::unversioned::transport::Buffers::input_appended(&mut self.buffers, n);
        Ok(n > 0)
    }

    fn is_open(&mut self) -> bool {
        use std::io::Read as _;
        // Open: nothing to read and no end (as ureq's own transport probes).
        if self.stream.0.set_nonblocking(true).is_err() {
            return false;
        }
        let mut b = [0u8];
        let open = matches!((&self.stream.0).read(&mut b), Err(e) if e.kind() == io::ErrorKind::WouldBlock);
        self.stream.0.set_nonblocking(false).is_ok() && open
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        // A cancelled build's connection is reset as it closes, however
        // its request ended.
        if self.cancel.is_cancelled() {
            self.stream.reset_on_close();
        }
    }
}

/// The names containers reach the Mac by (engine.rs writes them in every
/// container's /etc/hosts, the guest's DNS answers them for build steps).
const HOST_NAMES: [&str; 3] = ["host.docker.internal", "host.kiri.internal", "gateway.docker.internal"];

/// On a Mac those names lead to the Mac's own loopback, through the VM's
/// relay (ports.rs host_bound), and this daemon runs on the Mac: it reaches
/// the same place at 127.0.0.1. So the native `ADD <url>` fetched here
/// finds what a step's `curl` or the fallback BuildKit's ADD finds, with no
/// line for the name in the Mac's /etc/hosts. Any other name is the
/// system's to resolve.
#[derive(Debug)]
struct HostNames;

impl ureq::unversioned::resolver::Resolver for HostNames {
    fn resolve(&self, uri: &ureq::http::Uri, config: &ureq::config::Config, timeout: ureq::unversioned::transport::NextTimeout) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        if let Some(addr) = host_name_addr(uri) {
            let mut out = self.empty();
            out.push(addr);
            return Ok(out);
        }
        ureq::unversioned::resolver::DefaultResolver::default().resolve(uri, config, timeout)
    }
}

/// 127.0.0.1 at the URL's port, for one of `HOST_NAMES`.
fn host_name_addr(uri: &ureq::http::Uri) -> Option<std::net::SocketAddr> {
    let a = uri.authority()?;
    if !HOST_NAMES.iter().any(|n| a.host().eq_ignore_ascii_case(n)) {
        return None;
    }
    let port = a.port_u16().unwrap_or(if uri.scheme_str() == Some("https") { 443 } else { 80 });
    Some(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
}

/// GET `url` for `ADD <url>` (a named URL context, a SOURCE_DATE_EPOCH
/// source too); the body goes to `out` for a 2xx answer only. Bounded
/// here whatever the core asks: at most `ADD_MAX_BODY` body bytes, the
/// whole request within `ADD_MAX_TIME`, each read within `FETCH_MAX_READ`,
/// and the build's cancel ending it, whatever the server does. The core
/// adds the build's own, smaller bounds (`kiri_forge::fetch::Limits`).
pub(super) fn get(url: &str, out: &mut dyn Write, cancel: &Cancel) -> Result<HttpReply, Error> {
    fetch(url, out, ADD_MAX_BODY, Bounds { global: Some(ADD_MAX_TIME), per_read: Some(FETCH_MAX_READ) }, cancel)
}

/// GET `url` for a URL build context: as [`get`] (redirects followed, the
/// same errors), with the build's bounds: at most `max` body bytes, the
/// whole request within `total`, each read within `per_read`, and the
/// build's cancel ending it. The body goes to `out` for a 2xx answer only.
pub(super) fn get_bounded(url: &str, out: &mut dyn Write, max: u64, total: Duration, per_read: Duration, cancel: &Cancel) -> Result<HttpReply, Error> {
    fetch(url, out, max.min(FETCH_MAX_BODY), Bounds { global: Some(total.min(FETCH_MAX_TIME)), per_read: Some(per_read.min(FETCH_MAX_READ)) }, cancel)
}

/// One GET within `bounds`, at most `limit` body bytes, ended by `cancel`.
fn fetch(url: &str, out: &mut dyn Write, limit: u64, bounds: Bounds, cancel: &Cancel) -> Result<HttpReply, Error> {
    // Go names the request in a transport error: `Get "url": ...`.
    let failed = |e: &dyn std::fmt::Display| Error::Io(io::Error::other(format!("Get {:?}: {e}", redact(url))));
    if cancel.is_cancelled() {
        return Err(Error::Io(canceled()));
    }
    let agent = agent_with(bounds, cancel);
    let got = while_not_cancelled(&agent, cancel, || -> Result<HttpReply, Error> {
        let mut resp = agent.get(url).call().map_err(|e| failed(&e))?;
        let status = resp.status().as_u16();
        let last_modified = resp.headers().get("last-modified").and_then(|v| v.to_str().ok()).map(str::to_owned);
        if (200..300).contains(&status) {
            let mut w = Bounded { out: &mut *out, left: limit, limit, cancel };
            io::copy(&mut resp.body_mut().with_config().limit(u64::MAX).reader(), &mut w).map_err(|e| failed(&e))?;
        }
        Ok(HttpReply { status, last_modified })
    });
    if cancel.is_cancelled() {
        return Err(Error::Io(canceled()));
    }
    got
}

/// The most a URL context's download may be, whatever the core asks (its
/// own default is lower: `kiri_forge::fetch::Limits::response`).
const FETCH_MAX_BODY: u64 = 4 << 30;
/// The longest that download may take in all, and wait for one read (any
/// download's).
const FETCH_MAX_TIME: Duration = Duration::from_secs(30 * 60);
const FETCH_MAX_READ: Duration = Duration::from_secs(60);
/// The most any other download of a build may be, and take: BuildKit sets
/// no bound of its own; these only stop a server that never ends. The
/// body goes to the build's own folder, never memory.
const ADD_MAX_BODY: u64 = 64 << 30;
const ADD_MAX_TIME: Duration = Duration::from_secs(4 * 60 * 60);

/// A writer that stops at `limit` bytes and when `cancel` is set.
struct Bounded<'a> {
    out: &'a mut dyn Write,
    left: u64,
    limit: u64,
    cancel: &'a kiri_forge::ports::Cancel,
}

impl Write for Bounded<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self.cancel.is_cancelled() {
            return Err(io::Error::other(kiri_forge::fetch::CANCELED));
        }
        if b.len() as u64 > self.left {
            return Err(io::Error::other(format!("the answer is larger than the limit of {} bytes", self.limit)));
        }
        let n = self.out.write(b)?;
        self.left -= n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Runs `f` (one request on `agent`, its body read) while a watcher
/// looks at the build's cancel every 100 ms: a cancel shuts the agent's
/// connection down, so a server that says nothing holds the build no
/// longer than that, whatever the per-read limit.
fn while_not_cancelled<T>(agent: &ureq::Agent, cancel: &kiri_forge::ports::Cancel, f: impl FnOnce() -> T) -> T {
    let done = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|s| {
        let watcher = s.spawn(|| {
            while !done.load(std::sync::atomic::Ordering::SeqCst) {
                if cancel.is_cancelled() {
                    agent.clone().shutdown();
                    return;
                }
                std::thread::park_timeout(Duration::from_millis(100));
            }
        });
        let r = f();
        done.store(true, std::sync::atomic::Ordering::SeqCst);
        watcher.thread().unpark();
        r
    })
}

/// A password in the URL shown as `xxxxx`, as Go's `url.Redacted` does.
fn redact(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else { return url.to_owned() };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    match rest[..end].rsplit_once('@') {
        Some((user, host)) if user.contains(':') => {
            let u = user.split_once(':').map_or(user, |(u, _)| u);
            format!("{scheme}://{u}:xxxxx@{host}{}", &rest[end..])
        }
        _ => url.to_owned(),
    }
}

/// A server that never finishes an answer, for the tests of a build that
/// goes away while a fetch waits on it: it records how its connection
/// ended, so a test proves the engine closed it, without a clock.
#[cfg(test)]
pub(super) mod hostile {
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// Where the answer stops.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Stall {
        /// After the client's first TLS bytes: no ServerHello ever.
        Tls,
        /// Half way through the status line and headers.
        Headers,
        /// After the headers and 10 of 100,000 body bytes.
        Body,
        /// A body with no end, one byte every 200 ms.
        Trickle,
    }

    /// How the stalled connection ended.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct End {
        pub at: Instant,
        /// The client's end is gone (reset), not half-closed: nothing of
        /// the connection is left on its side.
        pub reset: bool,
    }

    pub struct Server {
        pub port: u16,
        stalling: mpsc::Receiver<Instant>,
        ended: mpsc::Receiver<End>,
    }

    /// A guard against a hang only: the property is that the stall, which
    /// never ends on its own, ended at all.
    const GUARD: Duration = Duration::from_secs(30);

    impl Server {
        /// When the stalled connection reached its stall.
        pub fn stalling(&self) -> Instant {
            self.stalling.recv_timeout(GUARD).expect("the request never reached the stall")
        }

        /// How the stalled connection ended (None: it did not).
        pub fn ended(&self) -> Option<End> {
            self.ended.recv_timeout(GUARD).ok()
        }
    }

    /// Reads a request's head (and a body of Content-Length bytes).
    fn read_request(c: &mut TcpStream) -> String {
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match c.read(&mut b) {
                Ok(1) => head.push(b[0]),
                _ => break,
            }
        }
        let text = String::from_utf8_lossy(&head).into_owned();
        let len = text.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok())).unwrap_or(0);
        let mut body = vec![0; len];
        let _ = c.read_exact(&mut body);
        text
    }

    /// Serves: the first `redirects` requests answer a 302 to the next
    /// hop (each on a connection of its own), the one after stalls.
    pub fn serve(stall: Stall, redirects: usize) -> Server {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (stalled, stalling) = mpsc::channel();
        let (end, ended) = mpsc::channel();
        std::thread::spawn(move || {
            for hop in 0..redirects {
                let (mut c, _) = l.accept().unwrap();
                read_request(&mut c);
                let _ = c.write_all(format!("HTTP/1.1 302 Found\r\nLocation: /hop{}/r\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", hop + 1).as_bytes());
            }
            let (mut c, _) = l.accept().unwrap();
            if stall == Stall::Tls {
                let mut b = [0u8; 5];
                let _ = c.read_exact(&mut b);
            } else {
                read_request(&mut c);
            }
            let _ = match stall {
                Stall::Tls => Ok(()),
                Stall::Headers => c.write_all(b"HTTP/1.1 200 OK\r\nContent-"),
                Stall::Body => c.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 100000\r\n\r\n0123456789"),
                Stall::Trickle => c.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n1"),
            };
            let _ = stalled.send(Instant::now());
            c.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
            let mut last = Instant::now();
            let mut buf = [0u8; 4096];
            let started = Instant::now();
            // Until the client's end closes: a read that ends, or a write
            // the client's end refuses.
            let mut at = None;
            while started.elapsed() < GUARD {
                match c.read(&mut buf) {
                    Ok(0) => {
                        at = Some(Instant::now());
                        break;
                    }
                    Ok(_) => {}
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                    Err(_) => {
                        let _ = end.send(End { at: Instant::now(), reset: true });
                        return;
                    }
                }
                if stall == Stall::Trickle && last.elapsed() >= Duration::from_millis(200) {
                    last = Instant::now();
                    if c.write_all(b"1").is_err() {
                        let _ = end.send(End { at: Instant::now(), reset: true });
                        return;
                    }
                }
            }
            let Some(at) = at else { return };
            // Half-closed (the client's FIN): is its end gone too (it
            // reset: this end is closed), or does it linger, half open,
            // while this end waits in CLOSE-WAIT?
            let t = Instant::now();
            let mut reset = false;
            while t.elapsed() < Duration::from_secs(2) {
                if peer_gone(&c) {
                    reset = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = end.send(End { at, reset });
            // The server keeps its end until the test is over.
            std::thread::sleep(GUARD);
        });
        Server { port, stalling, ended }
    }

    /// The connection is closed at this end: the other end reset it (after
    /// a FIN only, it would wait in CLOSE-WAIT). Elsewhere than Linux the
    /// state is not read: taken as gone.
    #[cfg(target_os = "linux")]
    fn peer_gone(c: &TcpStream) -> bool {
        use std::os::fd::AsRawFd as _;
        // SAFETY: an all-zero tcp_info is a valid value.
        let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
        // SAFETY: reads TCP_INFO of a socket this server holds into `info`.
        let r = unsafe { libc::getsockopt(c.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_INFO, (&raw mut info).cast(), &mut len) };
        // TCP_CLOSE is 7.
        r == 0 && info.tcpi_state == 7
    }

    #[cfg(not(target_os = "linux"))]
    fn peer_gone(_: &TcpStream) -> bool {
        true
    }

    /// A listener whose queue is full: a connect to it waits (the SYN is
    /// dropped) and never completes. Linux only (its backlog rule).
    #[cfg(target_os = "linux")]
    pub fn full_listener() -> (TcpListener, Vec<TcpStream>, u16) {
        use std::os::fd::AsRawFd as _;
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        // SAFETY: listen again on a listening socket this test owns: only
        // its backlog changes.
        assert_eq!(unsafe { libc::listen(l.as_raw_fd(), 0) }, 0);
        let port = l.local_addr().unwrap().port();
        let addr = l.local_addr().unwrap();
        let mut held = Vec::new();
        // Fill the queue: a connect that does not complete says it is full.
        for _ in 0..16 {
            match TcpStream::connect_timeout(&addr, Duration::from_millis(300)) {
                Ok(s) => held.push(s),
                Err(_) => return (l, held, port),
            }
        }
        panic!("the listener's queue never filled");
    }

    /// The local sockets in SYN-SENT to `port` (Linux: /proc/net/tcp).
    #[cfg(target_os = "linux")]
    pub fn connecting(port: u16) -> usize {
        let t = std::fs::read_to_string("/proc/net/tcp").unwrap_or_default();
        let want = format!(":{port:04X}");
        t.lines().skip(1).filter(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            f.len() > 3 && f[2].ends_with(&want) && f[3] == "02"
        }).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_names_for_the_mac_are_its_loopback() {
        let at = |u: &str| host_name_addr(&u.parse().unwrap()).map(|a| a.to_string());
        assert_eq!(at("http://host.docker.internal:8999/x").as_deref(), Some("127.0.0.1:8999"));
        assert_eq!(at("https://Host.Kiri.Internal/x").as_deref(), Some("127.0.0.1:443"));
        assert_eq!(at("http://gateway.docker.internal/").as_deref(), Some("127.0.0.1:80"));
        assert_eq!(at("http://example.com:8999/x"), None);
        assert_eq!(at("http://host.docker.internal.example.com/x"), None);
    }

    #[test]
    fn passwords_are_redacted() {
        assert_eq!(redact("https://u:pw@h:1/x?y"), "https://u:xxxxx@h:1/x?y");
        assert_eq!(redact("https://u@h/x"), "https://u@h/x");
        assert_eq!(redact("http://h/a@b"), "http://h/a@b");
    }

    #[test]
    fn a_body_reaches_out_and_its_status_and_last_modified_come_back() {
        use std::io::{BufRead as _, BufReader};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let srv = std::thread::spawn(move || {
            for (path_ok, answer) in [(true, "HTTP/1.1 200 OK\r\nConnection: close\r\nLast-Modified: Thu, 02 Jan 2020 03:04:05 GMT\r\nContent-Length: 5\r\n\r\nhello"), (true, "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 4\r\n\r\ngone")] {
                let (mut c, _) = l.accept().unwrap();
                let mut r = BufReader::new(c.try_clone().unwrap());
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                assert_eq!(path_ok, line.starts_with("GET /f "), "{line}");
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    if h == "\r\n" || h.is_empty() {
                        break;
                    }
                }
                c.write_all(answer.as_bytes()).unwrap();
            }
        });
        let url = format!("http://127.0.0.1:{port}/f");
        let mut body = Vec::new();
        let r = get(&url, &mut body, &Default::default()).unwrap();
        assert_eq!((r.status, r.last_modified.as_deref(), body.as_slice()), (200, Some("Thu, 02 Jan 2020 03:04:05 GMT"), &b"hello"[..]));
        let mut body = Vec::new();
        assert_eq!(get(&url, &mut body, &Default::default()).unwrap().status, 404);
        assert!(body.is_empty());
        srv.join().unwrap();
    }

    /// Per request: the port, the request line, whether credentials came.
    type Seen = std::thread::JoinHandle<Vec<(u16, String, bool)>>;

    /// A server on two ports that redirects as asked and records, per
    /// request, the request line and whether credentials came with it.
    fn redirect_server(hops: usize, answer: impl Fn(&str, u16, u16) -> String + Send + 'static) -> (u16, u16, Seen) {
        use std::io::{BufRead as _, BufReader};
        let a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (pa, pb) = (a.local_addr().unwrap().port(), b.local_addr().unwrap().port());
        a.set_nonblocking(true).unwrap();
        b.set_nonblocking(true).unwrap();
        let h = std::thread::spawn(move || {
            let mut seen = Vec::new();
            let t0 = std::time::Instant::now();
            while seen.len() < hops && t0.elapsed() < std::time::Duration::from_secs(10) {
                for (l, port) in [(&a, pa), (&b, pb)] {
                    let Ok((mut c, _)) = l.accept() else { continue };
                    c.set_nonblocking(false).unwrap();
                    let mut r = BufReader::new(c.try_clone().unwrap());
                    let mut line = String::new();
                    r.read_line(&mut line).unwrap();
                    let mut auth = false;
                    loop {
                        let mut h = String::new();
                        r.read_line(&mut h).unwrap();
                        auth |= h.to_ascii_lowercase().starts_with("authorization:");
                        if h == "\r\n" || h.is_empty() {
                            break;
                        }
                    }
                    let path = line.split(' ').nth(1).unwrap_or("").to_owned();
                    seen.push((port, path.clone(), auth));
                    c.write_all(answer(&path, pa, pb).as_bytes()).unwrap();
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            seen
        });
        (pa, pb, h)
    }

    fn moved(to: &str) -> String {
        format!("HTTP/1.1 302 Found\r\nConnection: close\r\nLocation: {to}\r\nContent-Length: 0\r\n\r\n")
    }

    const OK: &str = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok";

    /// `ADD http://user:pw@host/...` and redirects: which hop gets the
    /// credentials. As Go's client under BuildKit (client.go: the
    /// password is the URL's, and only a relative Location keeps the
    /// URL's user): a relative redirect keeps them, an absolute one drops
    /// them, even to the same origin; never another port or host.
    #[test]
    fn add_url_credentials_follow_a_redirect_only_to_the_same_scheme_host_and_port() {
        // /rel -> /end (relative), /abs -> http://127.0.0.1:A/end,
        // /port -> http://127.0.0.1:B/end, /host -> http://localhost:A/end.
        let (pa, pb, srv) = redirect_server(8, |path, pa, pb| match path {
            "/rel" => moved("/end"),
            "/abs" => moved(&format!("http://127.0.0.1:{pa}/end")),
            "/port" => moved(&format!("http://127.0.0.1:{pb}/end")),
            "/host" => moved(&format!("http://localhost:{pa}/end")),
            _ => OK.to_owned(),
        });
        let _ = pb;
        for p in ["rel", "abs", "port", "host"] {
            let mut out = Vec::new();
            let r = get(&format!("http://u:pw@127.0.0.1:{pa}/{p}"), &mut out, &Default::default()).unwrap();
            assert_eq!((r.status, out.as_slice()), (200, &b"ok"[..]), "{p}");
        }
        let seen = srv.join().unwrap();
        let hops: Vec<(bool, bool)> = seen.chunks(2).map(|c| (c[0].2, c[1].2)).collect();
        eprintln!("seen: {seen:?}");
        assert_eq!(hops, [(true, true), (true, false), (true, false), (true, false)], "{seen:?}");
    }

    /// The build's cancel is seen within a second while a server says
    /// nothing, whatever the per-read limit.
    #[test]
    fn the_cancel_is_seen_within_a_second_while_a_server_is_silent() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        // The server takes the request and says nothing (until the test
        // ends); the cancel comes once it has the request.
        let (accepted, on_accept) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (c, _) = l.accept().unwrap();
            let _ = accepted.send(());
            std::thread::sleep(Duration::from_secs(120));
            drop(c);
        });
        let cancel = kiri_forge::ports::Cancel::default();
        let c2 = cancel.clone();
        let cancelled_at = std::sync::Arc::new(std::sync::Mutex::new(None));
        let at2 = std::sync::Arc::clone(&cancelled_at);
        std::thread::spawn(move || {
            on_accept.recv().unwrap();
            *at2.lock().unwrap() = Some(std::time::Instant::now());
            c2.cancel()
        });
        let url = format!("http://127.0.0.1:{port}/x");
        let mut out = Vec::new();
        let limit = Duration::from_secs(60);
        let r = get_bounded(&url, &mut out, 1 << 20, limit, limit, &cancel);
        let after = cancelled_at.lock().unwrap().expect("cancelled").elapsed();
        // Ended by the cancel (BuildKit's error), not by a limit: a watcher
        // looks every 100 ms; a generous margin for a loaded machine, far
        // inside the 60 s per-read limit that would end it otherwise.
        assert_eq!(r.unwrap_err().to_string(), kiri_forge::fetch::CANCELED);
        assert!(after < Duration::from_secs(10), "seen {after:?} after the cancel");
    }

    /// The engine's ways out for a build: `ADD <url>` and a URL context
    /// (and a remote Dockerfile, the same download).
    #[derive(Debug, Clone, Copy)]
    enum Route {
        AddUrl,
        UrlContext,
    }

    const ROUTES: [Route; 2] = [Route::AddUrl, Route::UrlContext];

    /// One request of `route` to `base` with limits far beyond the test (an
    /// hour; the engine's per-read cap of 60 s): only the cancel can end it
    /// early.
    fn fetch(route: Route, base: &str, cancel: &kiri_forge::ports::Cancel) -> Result<(), String> {
        let hour = Duration::from_secs(3600);
        let mut out = Vec::new();
        match route {
            Route::AddUrl => get(&format!("{base}/r/file"), &mut out, cancel).map(drop),
            Route::UrlContext => get_bounded(&format!("{base}/r/ctx.tar"), &mut out, 1 << 30, hour, hour, cancel).map(drop),
        }
        .map_err(|e| e.to_string())
    }

    /// The build goes away (its cancel) while `route` waits on a server
    /// stalled at `stall`, after `redirects` hops: the request ends with
    /// BuildKit's words, and the stalled connection is closed by the
    /// engine (the server sees it end, and the client's end gone, not
    /// left half open), within a second of the cancel.
    fn closes_on_cancel(route: Route, stall: hostile::Stall, redirects: usize) -> Result<(), String> {
        let s = hostile::serve(stall, redirects);
        let scheme = if stall == hostile::Stall::Tls { "https" } else { "http" };
        let base = format!("{scheme}://127.0.0.1:{}", s.port);
        let cancel = kiri_forge::ports::Cancel::default();
        let c2 = cancel.clone();
        let req = std::thread::spawn(move || fetch(route, &base, &c2));
        s.stalling();
        let cancelled = std::time::Instant::now();
        cancel.cancel();
        let end = s.ended();
        let what = format!("{route:?} stalled at {stall:?} after {redirects} redirects");
        let Some(end) = end else { return Err(format!("{what}: the connection was still open after the cancel")) };
        let after = end.at.saturating_duration_since(cancelled);
        eprintln!("{what}: closed {after:?} after the cancel, reset {}", end.reset);
        if !end.reset {
            return Err(format!("{what}: the engine's end of the connection was left half open"));
        }
        if after >= Duration::from_secs(1) {
            return Err(format!("{what}: closed {after:?} after the cancel"));
        }
        let r = req.join().unwrap();
        if r != Err(kiri_forge::fetch::CANCELED.to_owned()) {
            return Err(format!("{what}: {r:?}"));
        }
        Ok(())
    }

    /// Every case run, then the failures named together.
    fn all(cases: impl IntoIterator<Item = Result<(), String>>) {
        let failed: Vec<String> = cases.into_iter().filter_map(Result::err).collect();
        assert!(failed.is_empty(), "{}", failed.join("\n"));
    }

    #[test]
    fn a_cancel_closes_a_connection_stalled_in_the_tls_handshake() {
        all(ROUTES.map(|r| closes_on_cancel(r, hostile::Stall::Tls, 0)));
    }

    #[test]
    fn a_cancel_closes_a_connection_stalled_in_the_headers() {
        all(ROUTES.map(|r| closes_on_cancel(r, hostile::Stall::Headers, 0)));
    }

    #[test]
    fn a_cancel_closes_a_connection_stalled_in_the_body() {
        all(ROUTES.map(|r| closes_on_cancel(r, hostile::Stall::Body, 0)));
    }

    #[test]
    fn a_cancel_closes_a_connection_that_trickles() {
        all(ROUTES.map(|r| closes_on_cancel(r, hostile::Stall::Trickle, 0)));
    }

    /// The stalled connection at the end of a chain of redirects.
    #[test]
    fn a_cancel_closes_a_connection_stalled_after_redirects() {
        all(ROUTES.into_iter().flat_map(|r| [closes_on_cancel(r, hostile::Stall::Body, 3), closes_on_cancel(r, hostile::Stall::Trickle, 2)]));
    }

    /// A server that never completes the connect (its queue full: the SYN
    /// is dropped): the cancel ends the connect, the request ends with
    /// BuildKit's words, and no connect is left pending; the connect
    /// limit (30 s) is far off.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_cancel_ends_a_connect_that_never_completes() {
        all(ROUTES.map(|route| -> Result<(), String> {
            let (_l, _held, port) = hostile::full_listener();
            assert_eq!(hostile::connecting(port), 0);
            let cancel = kiri_forge::ports::Cancel::default();
            let c2 = cancel.clone();
            let (done, ended) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = done.send(fetch(route, &format!("http://127.0.0.1:{port}"), &c2));
            });
            // The request's connect is pending once its SYN-SENT socket is.
            let t = std::time::Instant::now();
            while hostile::connecting(port) == 0 {
                assert!(t.elapsed() < Duration::from_secs(20), "{route:?}: no connect began");
                std::thread::sleep(Duration::from_millis(10));
            }
            let cancelled = std::time::Instant::now();
            cancel.cancel();
            // A guard only: the connect limit (30 s) would end it later.
            let r = ended.recv_timeout(Duration::from_secs(20)).map_err(|_| format!("{route:?}: the connect did not end on the cancel"))?;
            let after = cancelled.elapsed();
            eprintln!("{route:?}: the connect ended {after:?} after the cancel: {r:?}");
            if r != Err(kiri_forge::fetch::CANCELED.to_owned()) {
                return Err(format!("{route:?}: {r:?}"));
            }
            if hostile::connecting(port) != 0 {
                return Err(format!("{route:?}: a connect is left pending"));
            }
            if after >= Duration::from_secs(1) {
                return Err(format!("{route:?}: ended {after:?} after the cancel"));
            }
            Ok(())
        }));
    }

    /// A URL context's download keeps the build's bounds: past its size it
    /// fails, a stalled server ends at the per-read limit, a cancelled
    /// build sends nothing; a whole answer comes with its Last-Modified.
    #[test]
    fn a_url_context_download_stops_at_its_size_a_stall_and_the_cancel() {
        use std::io::{BufRead as _, BufReader};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let srv = std::thread::spawn(move || {
            for i in 0..3 {
                let (mut c, _) = l.accept().unwrap();
                let mut r = BufReader::new(c.try_clone().unwrap());
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    if h == "\r\n" || h.is_empty() {
                        break;
                    }
                }
                if i == 2 {
                    let _ = c.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\nLast-Modified: Tue, 14 Nov 2023 22:18:22 GMT\r\nContent-Length: 3\r\n\r\nabc");
                    continue;
                }
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 100000\r\n\r\n");
                let _ = c.write_all(&[b'a'; 1000]);
                std::thread::sleep(Duration::from_secs(if i == 0 { 0 } else { 3 }));
                let _ = c.write_all(&[b'a'; 99000]);
            }
        });
        let url = format!("http://127.0.0.1:{port}/context.tar");
        let none = kiri_forge::ports::Cancel::default();
        let e = get_bounded(&url, &mut Vec::new(), 500, Duration::from_secs(30), Duration::from_secs(30), &none).unwrap_err();
        assert!(e.to_string().contains("larger than the limit of 500 bytes"), "{e}");
        let t = std::time::Instant::now();
        assert!(get_bounded(&url, &mut Vec::new(), 1 << 20, Duration::from_secs(30), Duration::from_millis(300), &none).is_err());
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        let cancel = kiri_forge::ports::Cancel::default();
        cancel.cancel();
        assert_eq!(get_bounded(&url, &mut Vec::new(), 1 << 20, Duration::from_secs(30), Duration::from_secs(30), &cancel).unwrap_err().to_string(), kiri_forge::fetch::CANCELED);
        let mut out = Vec::new();
        let r = get_bounded(&url, &mut out, 1 << 20, Duration::from_secs(30), Duration::from_secs(30), &none).unwrap();
        assert_eq!((r.status, r.last_modified.as_deref(), out.as_slice()), (200, Some("Tue, 14 Nov 2023 22:18:22 GMT"), &b"abc"[..]));
        srv.join().unwrap();
    }
}
