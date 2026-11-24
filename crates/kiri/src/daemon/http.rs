//! Just enough HTTP/1.1 for Docker clients: keep-alive, Content-Length and
//! chunked bodies, streamed (chunked) responses and connection upgrades for
//! `attach`. Docker clients keep a few connections open, so the server runs
//! one thread per connection and never parses more than it needs.

use std::cell::Cell;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;

/// API version this daemon speaks. The Docker CLI negotiates down to it.
pub const API_VERSION: &str = "1.47";
/// The oldest API version served; a request path naming an older one is
/// refused, as Docker does. A newer one than [`API_VERSION`] is still
/// served: clients built against a newer Docker that don't negotiate work
/// today, and refusing them would gain nothing.
pub const MIN_API_VERSION: (u32, u32) = (1, 24);

/// Largest request body read into memory (container create, etc.). Archives
/// and image loads are streamed with [`Body`] instead, at any size.
const MAX_BODY: usize = 8 << 20;
/// Cap on upfront buffer reservation for buffered request bodies so headers or
/// a chunk size line alone never pre-allocate [`MAX_BODY`] before bytes arrive.
const INITIAL_BODY_CAP: usize = 64 << 10;
/// The request line and headers together may not exceed this: an endless
/// header line must not grow memory without bound.
const MAX_HEAD: u64 = 64 << 10;
/// Maximum size of a single chunk-size line (hex length plus optional `;ext`).
const MAX_CHUNK_LINE: u64 = 1024;
/// Maximum total bytes in a chunked body's trailer section (including its
/// terminating blank line), so an endless trailer cannot exhaust memory or
/// hold a connection open forever.
const MAX_TRAILERS: u64 = 8 << 10;
/// Maximum number of trailer header lines before the terminating blank line.
const MAX_TRAILER_LINES: usize = 128;
/// Most of a streamed body its handler left unread that is read out so the
/// connection can serve the next request; past this it closes. Go's
/// net/http server, so Docker's, reads out as much.
const MAX_UNREAD: u64 = 256 << 10;
/// How long, and how much, a connection that ends while its client may still
/// be sending reads out and drops before it closes ([`close`]). Enough for a
/// client to take in the answer and stop; one that sends on past it gets the
/// reset it would have got without the wait.
const LINGER_TIME: std::time::Duration = std::time::Duration::from_secs(1);
const LINGER_BYTES: u64 = 16 << 20;

#[derive(Debug)]
pub struct Request {
    pub method: String,
    /// Path without the `/v1.xx` prefix or the query string, percent-decoded
    /// (`%2F` in an image name is the `/` the router must resolve).
    pub path: String,
    /// The `/v1.xx` prefix, when the path had one.
    pub api_version: Option<(u32, u32)>,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Sent as HTTP/1.0: its connection closes after the response unless it
    /// asks to keep it.
    http10: bool,
    /// Whether `HTTP/1.1 100 Continue` still needs to be sent before reading a
    /// streamed body (RFC 9110 §10.1.1). Cleared once written.
    needs_continue: Cell<bool>,
    /// How much of a streamed body has been read, through [`Body`].
    streamed: Cell<Streamed>,
}

/// A streamed request body's progress: whether the connection can serve
/// another request after it ([`finish_body`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Streamed {
    /// The body was read with the head (or there is none to stream).
    No,
    Unread,
    Started,
    Done,
    /// Larger than [`MAX_BODY`] for a request whose body is read whole: not
    /// read (or read only up to the limit), and never routed ([`too_large`]).
    TooLarge,
}

impl Request {
    pub fn query(&self, key: &str) -> Option<&str> {
        self.query.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// Every value of a repeated key (`names=a&names=b`).
    pub fn queries<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.query.iter().filter(move |(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// Docker sends booleans as `1`/`true`/`0`/`false`.
    pub fn flag(&self, key: &str) -> bool {
        matches!(self.query(key), Some("1" | "true" | "True"))
    }

    pub fn header(&self, key: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v.as_str())
    }

    /// The connection closes after this request's response: the client
    /// sent `Connection: close` (Docker.DotNet does on every request), or
    /// spoke HTTP/1.0 without `Connection: keep-alive` (RFC 9112 §9.3), as
    /// Go's net/http in dockerd decides it. A client that reads a 204 to the
    /// end of the stream waits for that close and times out if it never comes.
    pub fn wants_close(&self) -> bool {
        let has = |token: &str| self.header("Connection").is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)));
        has("close") || (self.http10 && !has("keep-alive"))
    }

    fn expects_continue(&self) -> bool {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("expect"))
            .any(|(_, v)| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("100-continue")))
    }

    /// A request the daemon makes of itself (the managed builder's
    /// container create), so it goes through the same code as a client's.
    pub fn internal(method: &str, path: &str, query: &[(&str, &str)], body: Vec<u8>) -> Request {
        let query = query.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
        Request { method: method.to_owned(), path: path.to_owned(), api_version: None, query, headers: Vec::new(), body, http10: false, needs_continue: Cell::new(false), streamed: Cell::new(Streamed::No) }
    }

    /// Whether a streamed body is still waiting for `HTTP/1.1 100 Continue`.
    pub fn needs_continue(&self) -> bool {
        self.needs_continue.get()
    }

    #[cfg(test)]
    pub fn with_header(mut self, key: &str, value: &str) -> Request {
        self.headers.push((key.to_owned(), value.to_owned()));
        self
    }
}

/// Reads the next request on a connection. `Ok(None)` is a clean close.
/// When `stream(method, path)` is true the body stays unread: the handler
/// reads it through [`Body`].
pub fn read_request(r: &mut BufReader<UnixStream>, stream: impl Fn(&str, &str) -> bool) -> io::Result<Option<Request>> {
    SERVING.with(|s| *s.borrow_mut() = (String::new(), String::new()));
    CLOSING.with(|c| c.set(false));
    PENDING_CONTINUE.with(|c| c.set(false));
    // The request line and headers are read through a cap, so a client
    // cannot exhaust memory with an endless line. The body is read after.
    let (method, path, api_version, query, headers, http10) = {
        let mut head = (&mut *r).take(MAX_HEAD);
        let mut line = String::new();
        if head.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        let Some(req_line) = line.strip_suffix('\n').map(|l| l.strip_suffix('\r').unwrap_or(l)) else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad request line"));
        };
        let mut parts = req_line.split(' ');
        let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad request line"));
        };
        if [method, target, version].iter().any(|p| p.is_empty() || p.chars().any(|c| c.is_ascii_control() || c.is_whitespace())) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad request line"));
        }
        if !version.eq_ignore_ascii_case("HTTP/1.1") && !version.eq_ignore_ascii_case("HTTP/1.0") {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad request line"));
        }
        let http10 = version.eq_ignore_ascii_case("HTTP/1.0");
        let method = method.to_owned();
        let Some((raw_path, raw_query)) = parse_target(target) else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad request target"));
        };
        // Decoded once, here, so every route that reads a name from the
        // path — an image's `%2F` repository slash above all — resolves the
        // name, not its encoding, as Docker's router does.
        let unversioned = strip_version(raw_path);
        let api_version = version_of(&raw_path[..raw_path.len() - unversioned.len()]);
        let path = percent_decode_path(unversioned);
        let query: Vec<(String, String)> = raw_query
            .split('&')
            .filter(|kv| !kv.is_empty())
            .map(|kv| {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                (percent_decode(k), percent_decode(v))
            })
            .collect();
        let mut headers = Vec::new();
        loop {
            line.clear();
            if head.read_line(&mut line)? == 0 {
                let kind = if head.limit() == 0 { io::ErrorKind::InvalidData } else { io::ErrorKind::UnexpectedEof };
                return Err(io::Error::new(kind, "headers too large or cut short"));
            }
            let Some(l) = line.strip_suffix('\n').map(|l| l.strip_suffix('\r').unwrap_or(l)) else {
                let kind = if head.limit() == 0 { io::ErrorKind::InvalidData } else { io::ErrorKind::UnexpectedEof };
                return Err(io::Error::new(kind, "headers too large or cut short"));
            };
            if l.is_empty() {
                break;
            }
            // RFC 9112 §5.1 / §5.2: reject obs-fold (leading whitespace),
            // lines without ':', empty or non-token field-names (including
            // whitespace before ':'), and control characters in values.
            if l.starts_with([' ', '\t']) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "bad header"));
            }
            let Some((k, v)) = l.split_once(':') else {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "bad header"));
            };
            if k.is_empty() || !k.bytes().all(is_tchar) || v.bytes().any(is_ctl) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "bad header"));
            }
            headers.push((k.to_owned(), v.trim_matches([' ', '\t']).to_owned()));
        }
        (method, path, api_version, query, headers, http10)
    };
    let streamed = stream(&method, &path);
    let mut req = Request { method, path, api_version, query, headers, body: Vec::new(), http10, needs_continue: Cell::new(false), streamed: Cell::new(Streamed::No) };
    let body_framing = framing(&req)?;
    if !streamed && matches!(body_framing, Framing::Length(len) if len > MAX_BODY as u64) {
        return Ok(Some(too_large(req)));
    }
    let wants_continue = !req.http10 && req.expects_continue() && !matches!(body_framing, Framing::None);
    if streamed {
        // Defer `100 Continue` until the handler actually reads the streamed
        // body (RFC 9110 §10.1.1), so early 4xx rejections close without
        // asking the client to upload a multi-GB archive.
        req.needs_continue.set(wants_continue);
        req.streamed.set(if matches!(body_framing, Framing::None) { Streamed::Done } else { Streamed::Unread });
        return Ok(Some(req));
    }
    // RFC 9110 §10.1.1: an HTTP/1.1 client sending `Expect: 100-continue`
    // waits for `100 Continue` before transmitting the body (as .NET's
    // HttpClient and curl do on large uploads). HTTP/1.0 requests, bodiless
    // requests, and already-rejected requests must not get a 100 response.
    if wants_continue {
        let w = r.get_mut();
        w.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
        w.flush()?;
    }
    match body_framing {
        Framing::None => {}
        Framing::Chunked => loop {
            let n = read_chunk_len(r)?;
            // A zero chunk has no data and no CRLF of its own: its line's
            // CRLF is already read, and the trailer section follows
            // (RFC 9112 §7.1.2).
            if n == 0 {
                read_trailers(r)?;
                break;
            }
            if n > MAX_BODY as u64 || req.body.len().checked_add(n as usize).is_none_or(|t| t > MAX_BODY) {
                return Ok(Some(too_large(req)));
            }
            let want = n as usize;
            req.body.reserve(want.min(INITIAL_BODY_CAP));
            let got = (&mut *r).take(n).read_to_end(&mut req.body)?;
            if got != want {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "request body cut short"));
            }
            read_chunk_crlf(r)?;
        },
        Framing::Length(len) => {
            let want = len as usize;
            req.body = Vec::with_capacity(want.min(INITIAL_BODY_CAP));
            let got = (&mut *r).take(len).read_to_end(&mut req.body)?;
            if got != want {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "request body cut short"));
            }
        }
    }
    Ok(Some(req))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Framing {
    None,
    Chunked,
    Length(u64),
}

/// Validates and determines request body framing per RFC 9112 §6.1 & §6.3.
/// Rejects conflicting `Transfer-Encoding` + `Content-Length` headers,
/// unsupported transfer codings, and malformed or conflicting `Content-Length`
/// values with `InvalidData` so the connection answers 400 and closes.
fn framing(req: &Request) -> io::Result<Framing> {
    let mut has_te = false;
    let mut te = Vec::new();
    for (_, raw) in req.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding")) {
        has_te = true;
        for part in raw.split(',') {
            let s = part.trim();
            if !s.is_empty() {
                te.push(s);
            }
        }
    }
    let has_cl = req.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
    if has_te {
        if has_cl {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "conflicting transfer-encoding and content-length"));
        }
        if req.http10 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "transfer-encoding is not valid in HTTP/1.0"));
        }
        if te.len() == 1 && te[0].eq_ignore_ascii_case("chunked") {
            return Ok(Framing::Chunked);
        }
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported transfer-encoding"));
    }
    let mut len: Option<u64> = None;
    for (_, raw) in req.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
        for part in raw.split(',') {
            let s = part.trim();
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "bad content-length"));
            }
            let n = s.parse::<u64>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad content-length"))?;
            if let Some(prev) = len && prev != n {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "conflicting content-length"));
            }
            len = Some(n);
        }
    }
    Ok(match len {
        None | Some(0) => Framing::None,
        Some(n) => Framing::Length(n),
    })
}

fn read_chunk_len(r: &mut BufReader<UnixStream>) -> io::Result<u64> {
    let mut line = Vec::new();
    let mut lim = (&mut *r).take(MAX_CHUNK_LINE);
    if lim.read_until(b'\n', &mut line)? == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "request body cut short"));
    }
    let Some(raw) = line.strip_suffix(b"\n") else {
        let (kind, msg) = if lim.limit() == 0 {
            (io::ErrorKind::InvalidData, "chunk size line too large")
        } else {
            (io::ErrorKind::UnexpectedEof, "request body cut short")
        };
        return Err(io::Error::new(kind, msg));
    };
    let Some(raw) = raw.strip_suffix(b"\r") else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad chunk size line"));
    };
    // A chunk size may carry extensions after a semicolon (RFC 9112 §7.1.1);
    // reject control characters (including NUL and bare CR) in any extension.
    let (size, ext) = match raw.iter().position(|&b| b == b';') {
        Some(i) => (&raw[..i], Some(&raw[i + 1..])),
        None => (raw, None),
    };
    if let Some(ext) = ext && ext.iter().any(|&b| is_ctl(b)) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad chunk extension"));
    }
    let size = &size[..size.iter().rposition(|b| !matches!(b, b' ' | b'\t')).map_or(0, |i| i + 1)];
    if size.is_empty() || !size.iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"));
    }
    let s = std::str::from_utf8(size).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
    u64::from_str_radix(s, 16).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))
}

fn read_chunk_crlf(r: &mut BufReader<UnixStream>) -> io::Result<()> {
    let mut crlf = [0u8; 2];
    r.read_exact(&mut crlf)?;
    if crlf != *b"\r\n" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad chunk delimiter"));
    }
    Ok(())
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(b, b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~')
}

/// Control characters disallowed in HTTP field values and chunk extensions:
/// C0 controls except HTAB (`0x09`), plus DEL (`0x7F`).
fn is_ctl(b: u8) -> bool {
    (b < 0x20 && b != b'\t') || b == 0x7f
}

/// Reads out a chunked body's trailer section: trailer header lines until the
/// terminating blank line (RFC 9112 §7.1.2). Bounded in total bytes and line
/// count so an endless trailer section cannot exhaust memory or hang.
fn read_trailers(r: &mut BufReader<UnixStream>) -> io::Result<()> {
    let mut lim = (&mut *r).take(MAX_TRAILERS);
    let mut line = Vec::new();
    let mut count = 0usize;
    loop {
        line.clear();
        if lim.read_until(b'\n', &mut line)? == 0 {
            let (kind, msg) = if lim.limit() == 0 {
                (io::ErrorKind::InvalidData, "trailers too large")
            } else {
                (io::ErrorKind::UnexpectedEof, "trailers cut short")
            };
            return Err(io::Error::new(kind, msg));
        }
        let Some(raw) = line.strip_suffix(b"\n") else {
            let (kind, msg) = if lim.limit() == 0 {
                (io::ErrorKind::InvalidData, "trailers too large")
            } else {
                (io::ErrorKind::UnexpectedEof, "trailers cut short")
            };
            return Err(io::Error::new(kind, msg));
        };
        let Some(raw) = raw.strip_suffix(b"\r") else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad trailer line"));
        };
        if raw.is_empty() {
            return Ok(());
        }
        count += 1;
        if count > MAX_TRAILER_LINES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "too many trailer headers"));
        }
        if !raw.iter().position(|&b| b == b':').is_some_and(|i| i > 0 && raw[..i].iter().all(|&b| is_tchar(b)) && !raw[i + 1..].iter().any(|&b| is_ctl(b))) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad trailer header"));
        }
    }
}

/// A request whose body is past [`MAX_BODY`]: what was read of it is dropped
/// and the rest stays unread, for the connection's [`close`] to read out.
fn too_large(mut req: Request) -> Request {
    req.body = Vec::new();
    req.streamed.set(Streamed::TooLarge);
    req
}

/// Answers a request whose body is too large to read ([`Request::too_large`])
/// and ends the connection. Docker sets no limit (its handlers decode the
/// body whatever its size, and a route that does not read it answers as
/// usual); holding all of it is not safe here, and routing the request
/// without it would run a handler on a body it never saw (a create with an
/// empty config). So it is refused, in Docker's error shape, and the client,
/// which may still be sending, gets the whole answer and a clean end.
pub fn refuse_too_large(req: &Request, w: &mut UnixStream, r: &mut BufReader<UnixStream>) -> io::Result<()> {
    serving(req);
    let sent = error_closing(w, 413, &format!("request body too large: more than the {} MiB a request may send", MAX_BODY >> 20));
    close(w, r);
    sent
}

/// Answers a malformed request (bad request line, target, or chunk size)
/// with `400 Bad Request` and ends the connection.
pub fn refuse_bad_request(w: &mut UnixStream, r: &mut BufReader<UnixStream>, message: &str) -> io::Result<()> {
    SERVING.with(|s| *s.borrow_mut() = (String::new(), String::new()));
    let sent = error_closing(w, 400, message);
    close(w, r);
    sent
}

/// Sends `HTTP/1.1 100 Continue` if this request is still waiting on one,
/// clearing the pending flag so it is emitted at most once. Handlers that
/// stream a final response header before reading [`Body`] (such as `POST /build`)
/// call this right before starting the response.
pub fn send_continue(req: &Request, r: &mut BufReader<UnixStream>) -> io::Result<()> {
    if req.needs_continue.get() {
        let w = r.get_mut();
        w.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
        w.flush()?;
        req.needs_continue.set(false);
        PENDING_CONTINUE.with(|c| c.set(false));
    }
    Ok(())
}

/// After a streamed request's response: whether the connection can serve
/// the client's next request. A body its handler left unread (a pull sent
/// with one, as docker-modem sends its options) is read out first, up to
/// [`MAX_UNREAD`], or its bytes would be taken for the next request's head.
/// One read partly, too large, or waiting on an unsent `100 Continue` cannot
/// be; the connection closes.
pub fn finish_body(req: &Request, r: &mut BufReader<UnixStream>) -> bool {
    match req.streamed.get() {
        Streamed::No | Streamed::Done => true,
        Streamed::Started | Streamed::TooLarge => false,
        Streamed::Unread if req.needs_continue.get() => false,
        Streamed::Unread => {
            let mut body = Body::new(req, r);
            io::copy(&mut (&mut body).take(MAX_UNREAD), &mut io::sink()).is_ok() && body.read(&mut [0; 1]).is_ok_and(|n| n == 0)
        }
    }
}

impl Request {
    /// A streamed body its handler did not read to its end: the client may
    /// still be sending it.
    pub fn body_left(&self) -> bool {
        matches!(self.streamed.get(), Streamed::Unread | Streamed::Started | Streamed::TooLarge)
    }

    /// A body past [`MAX_BODY`] on a route that reads it whole: the request
    /// is answered by [`refuse_too_large`], never routed.
    pub fn too_large(&self) -> bool {
        self.streamed.get() == Streamed::TooLarge
    }
}

/// Ends a connection after a whole response, as Go's net/http server (so
/// Docker's) does: the write side is shut first, so the client sees the end
/// of the stream at once, even while anything else still holds a copy of the
/// socket; then whatever the client is still sending (a body the handler left
/// unread, a pipelined request) is read and dropped, up to [`LINGER_BYTES`]
/// and [`LINGER_TIME`], until the client closes its side. Closing a socket
/// with unread data in it resets the connection on Linux: the client's read
/// fails with "connection reset" after the answer instead of ending cleanly.
pub fn close(w: &UnixStream, r: &mut BufReader<UnixStream>) {
    let _ = w.shutdown(std::net::Shutdown::Write);
    let deadline = std::time::Instant::now() + LINGER_TIME;
    let mut left = LINGER_BYTES;
    r.consume(r.buffer().len());
    let s = r.get_mut();
    let mut buf = vec![0u8; 64 << 10];
    while left > 0 {
        let Some(wait) = deadline.checked_duration_since(std::time::Instant::now()).filter(|d| !d.is_zero()) else { break };
        if s.set_read_timeout(Some(wait)).is_err() {
            break;
        }
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => left = left.saturating_sub(n as u64),
        }
    }
}

/// A streamed request body: Content-Length or chunked, read as it arrives.
pub struct Body<'a> {
    r: &'a mut BufReader<UnixStream>,
    chunked: bool,
    /// Bytes left in the body (or in the current chunk).
    left: u64,
    done: bool,
    bad: Option<io::ErrorKind>,
    /// The request's record of how far its body was read.
    progress: &'a Cell<Streamed>,
    /// Whether `100 Continue` still needs to be written on first read.
    needs_continue: &'a Cell<bool>,
}

impl<'a> Body<'a> {
    pub fn new(req: &'a Request, r: &'a mut BufReader<UnixStream>) -> Body<'a> {
        match framing(req) {
            Ok(Framing::None) => {
                req.streamed.set(Streamed::Done);
                Body { r, chunked: false, left: 0, done: true, bad: None, progress: &req.streamed, needs_continue: &req.needs_continue }
            }
            Ok(Framing::Chunked) => {
                Body { r, chunked: true, left: 0, done: false, bad: None, progress: &req.streamed, needs_continue: &req.needs_continue }
            }
            Ok(Framing::Length(n)) => {
                Body { r, chunked: false, left: n, done: false, bad: None, progress: &req.streamed, needs_continue: &req.needs_continue }
            }
            Err(e) => {
                req.streamed.set(Streamed::Started);
                Body { r, chunked: false, left: 0, done: false, bad: Some(e.kind()), progress: &req.streamed, needs_continue: &req.needs_continue }
            }
        }
    }
}

impl Read for Body<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(kind) = self.bad {
            return Err(io::Error::new(kind, "bad request framing"));
        }
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        self.progress.set(Streamed::Started);
        if self.needs_continue.get() {
            let w = self.r.get_mut();
            if let Err(e) = w.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").and_then(|()| w.flush()) {
                self.bad = Some(e.kind());
                return Err(e);
            }
            self.needs_continue.set(false);
            PENDING_CONTINUE.with(|c| c.set(false));
        }
        if self.chunked && self.left == 0 {
            self.left = match read_chunk_len(self.r) {
                Ok(n) => n,
                Err(e) => {
                    self.bad = Some(e.kind());
                    return Err(e);
                }
            };
            if self.left == 0 {
                if let Err(e) = read_trailers(self.r) {
                    self.bad = Some(e.kind());
                    return Err(e);
                }
                self.done = true;
                self.progress.set(Streamed::Done);
                return Ok(0);
            }
        }
        let want = buf.len().min(self.left.min(usize::MAX as u64) as usize);
        let n = self.r.read(&mut buf[..want])?;
        if n == 0 {
            self.bad = Some(io::ErrorKind::UnexpectedEof);
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "request body cut short"));
        }
        self.left -= n as u64;
        if self.left == 0 {
            if self.chunked {
                if let Err(e) = read_chunk_crlf(self.r) {
                    self.bad = Some(e.kind());
                    return Err(e);
                }
            } else {
                self.done = true;
                self.progress.set(Streamed::Done);
            }
        }
        Ok(n)
    }
}

/// Splits an RFC 9112 §3.2.1 `origin-form` or §3.2.2 `absolute-form`
/// request-target into `(path, query)`. Clients such as docker-modem send
/// `GET http://127.0.0.1:2376/containers/json HTTP/1.1` over the Unix socket
/// or named pipe when configured with a default host and port (#757).
fn parse_target(target: &str) -> Option<(&str, &str)> {
    if target.contains('#') {
        return None;
    }
    if target.starts_with('/') {
        return Some(target.split_once('?').unwrap_or((target, "")));
    }
    let (scheme, rest) = target.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let (authority, tail) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if !valid_authority(authority) {
        return None;
    }
    match tail.strip_prefix('?') {
        Some(q) => Some(("/", q)),
        None if tail.is_empty() => Some(("/", "")),
        None => Some(tail.split_once('?').unwrap_or((tail, ""))),
    }
}

fn valid_authority(authority: &str) -> bool {
    let valid_port = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok_and(|n| n > 0);
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((v6, after)) = rest.split_once(']') else { return false };
        return v6.parse::<std::net::Ipv6Addr>().is_ok() && (after.is_empty() || after.strip_prefix(':').is_some_and(valid_port));
    }
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    !host.is_empty()
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && port.is_none_or(valid_port)
}

/// `/v1.47/containers/json` → `/containers/json`.
fn strip_version(path: &str) -> &str {
    if let Some(rest) = path.strip_prefix("/v")
        && let Some(i) = rest.find('/')
            && rest[..i].bytes().all(|b| b.is_ascii_digit() || b == b'.') {
                return &rest[i..];
            }
    path
}

/// `/v1.47` → (1, 47). None for no prefix, or one that isn't two numbers.
fn version_of(prefix: &str) -> Option<(u32, u32)> {
    let (major, minor) = prefix.strip_prefix("/v")?.split_once('.')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// Percent-decodes a query value, where `+` means a space.
fn percent_decode(s: &str) -> String {
    unescape(s, true)
}

/// Percent-decodes the request path. A client may send a name's slash or
/// colon encoded (`/images/mongodb%2Fmongodb-atlas-local:8.0/json`), and the
/// router has to see the name, not its encoding. A `+` is a plus here, not
/// a space; an invalid escape stays written, as in a query value.
fn percent_decode_path(s: &str) -> String {
    unescape(s, false)
}

fn unescape(s: &str, plus_space: bool) -> String {
    let b = s.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' if plus_space => out.push(b' '),
            b'%' if i + 2 < b.len() && hex(b[i + 1]).is_some() && hex(b[i + 2]).is_some() => {
                out.push(hex(b[i + 1]).unwrap_or(0) << 4 | hex(b[i + 2]).unwrap_or(0));
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn reason(status: u16) -> &'static str {
    match status {
        101 => "UPGRADED",
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        304 => "Not Modified",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Request Entity Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        _ => "",
    }
}

thread_local! {
    /// The request this connection thread is answering, for the log.
    static SERVING: std::cell::RefCell<(String, String)> = const { std::cell::RefCell::new((String::new(), String::new())) };
    /// Whether the connection closes after the request being answered: its
    /// response then says so (`Connection: close`), as Docker's does.
    static CLOSING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Whether the streamed request being answered still has an unsent
    /// `100 Continue`: answering before reading the body closes the connection.
    static PENDING_CONTINUE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Notes the request being answered: a failure status written for it is
/// logged with its method and path (never its query or body), and its
/// response carries `Connection: close` when the connection ends after it.
pub fn serving(req: &Request) {
    SERVING.with(|s| *s.borrow_mut() = (req.method.clone(), req.path.clone()));
    CLOSING.with(|c| c.set(req.wants_close()));
    PENDING_CONTINUE.with(|c| c.set(req.needs_continue.get()));
}

/// Engine API failures in the log: 5xx as errors, 4xx as warnings, except
/// 404s, which clients use to ask (does this image exist yet?).
fn note_failure(status: u16) {
    SERVING.with(|s| {
        let (method, path) = &*s.borrow();
        if method.is_empty() && path.is_empty() {
            match status {
                404 => crate::diag::debug!("request failed", status = status),
                400..=499 => crate::diag::warn!("request failed", status = status),
                _ => crate::diag::error!("request failed", status = status),
            }
        } else {
            match status {
                404 => crate::diag::debug!("request failed", method = method, path = path, status = status),
                400..=499 => crate::diag::warn!("request failed", method = method, path = path, status = status),
                _ => crate::diag::error!("request failed", method = method, path = path, status = status),
            }
        }
    });
}

#[cfg(test)]
pub fn current_serving() -> (String, String) {
    SERVING.with(|s| s.borrow().clone())
}

fn head(w: &mut impl Write, status: u16, extra: &str) -> io::Result<()> {
    if status >= 400 {
        note_failure(status);
    }
    // A response that names its own Connection (an upgrade, `CLOSE`) keeps it.
    let closing = if (CLOSING.with(std::cell::Cell::get) || PENDING_CONTINUE.with(std::cell::Cell::get)) && !extra.contains("Connection:") { CLOSE } else { "" };
    write!(
        w,
        "HTTP/1.1 {status} {}\r\nApi-Version: {API_VERSION}\r\nDocker-Experimental: false\r\nOstype: linux\r\nServer: Kiri/{} (linux)\r\n{extra}{closing}\r\n",
        reason(status),
        env!("CARGO_PKG_VERSION")
    )
}

pub fn respond(w: &mut impl Write, status: u16, content_type: &str, body: &[u8]) -> io::Result<()> {
    let extra = if status == 204 || status == 304 {
        String::new()
    } else {
        format!("Content-Type: {content_type}\r\nContent-Length: {}\r\n", body.len())
    };
    head(w, status, &extra)?;
    w.write_all(body)?;
    w.flush()
}

/// `respond` plus extra header lines, each ending in CRLF.
pub fn respond_with(w: &mut impl Write, status: u16, content_type: &str, extra: &str, body: &[u8]) -> io::Result<()> {
    head(w, status, &format!("Content-Type: {content_type}\r\nContent-Length: {}\r\n{extra}", body.len()))?;
    w.write_all(body)?;
    w.flush()
}

pub fn json(w: &mut impl Write, status: u16, body: &str) -> io::Result<()> {
    respond(w, status, "application/json", body.as_bytes())
}

/// A success with no body, under the status the route names.
pub fn empty(w: &mut impl Write, status: u16) -> io::Result<()> {
    respond(w, status, "", b"")
}

/// Docker's error shape: `{"message": "..."}`.
pub fn error(w: &mut impl Write, status: u16, message: &str) -> io::Result<()> {
    json(w, status, &serde_json::json!({ "message": message }).to_string())
}

/// The header of a response after which the server closes the connection
/// (a request body may be left unread). Without it an HTTP/1.1 client keeps
/// the connection for its next request and writes into a closed socket:
/// docker-java's pool (Testcontainers) failed the `start` after a copy into
/// the container with "Broken pipe".
pub const CLOSE: &str = "Connection: close\r\n";

/// `error` on a connection that closes after it (`CLOSE`).
pub fn error_closing(w: &mut impl Write, status: u16, message: &str) -> io::Result<()> {
    respond_with(w, status, "application/json", CLOSE, serde_json::json!({ "message": message }).to_string().as_bytes())
}

/// Starts a streamed response; follow with [`chunk`] calls and [`end`].
pub fn begin_stream(w: &mut impl Write, status: u16, content_type: &str) -> io::Result<()> {
    begin_stream_with(w, status, content_type, "")
}

/// `begin_stream` plus extra header lines, each ending in CRLF.
pub fn begin_stream_with(w: &mut impl Write, status: u16, content_type: &str, extra: &str) -> io::Result<()> {
    head(w, status, &format!("Content-Type: {content_type}\r\nTransfer-Encoding: chunked\r\n{extra}"))?;
    w.flush()
}

/// Headers only, for HEAD: `extra` lines end in CRLF.
pub fn head_only(w: &mut impl Write, status: u16, extra: &str) -> io::Result<()> {
    head(w, status, &format!("Content-Length: 0\r\n{extra}"))?;
    w.flush()
}

pub fn chunk(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    write!(w, "{:x}\r\n", data.len())?;
    w.write_all(data)?;
    w.write_all(b"\r\n")?;
    w.flush()
}

pub fn end(w: &mut impl Write) -> io::Result<()> {
    w.write_all(b"0\r\n\r\n")?;
    w.flush()
}

/// Switches the connection to Docker's raw stream for `attach`. After this
/// the connection carries multiplexed output frames until it closes.
pub fn upgrade(w: &mut impl Write) -> io::Result<()> {
    head(w, 101, "Content-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n")?;
    w.flush()
}

/// Starts the raw stream for Docker's `attach` and `exec` start. As Docker
/// does (it checks that the `Upgrade` header is present, not its value), a
/// client that asked for the upgrade (the docker CLI) gets `101`; one that did
/// not (docker-java, so Testcontainers) gets `200 OK` with the stream as the
/// body. A `101` to a client that never asked for it can end its read before
/// the process's exit code is recorded, and it then sees an exec with no
/// `ExitCode`.
pub fn upgrade_if_asked(req: &Request, w: &mut impl Write) -> io::Result<()> {
    if req.header("Upgrade").is_some() {
        return upgrade(w);
    }
    head(w, 200, "Content-Type: application/vnd.docker.raw-stream\r\n")?;
    w.flush()
}

/// Docker's multiplexed stream framing: `[stream, 0, 0, 0, len u32 BE] data`.
pub fn mux_frame(w: &mut impl Write, stream: u8, data: &[u8]) -> io::Result<()> {
    let mut header = [0u8; 8];
    header[0] = stream;
    header[4..].copy_from_slice(&(data.len() as u32).to_be_bytes());
    w.write_all(&header)?;
    w.write_all(data)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_connection(value: Option<&str>) -> Request {
        let headers = value.map(|v| vec![("connection".to_owned(), v.to_owned())]).unwrap_or_default();
        Request { method: "POST".to_owned(), path: "/containers/x/start".to_owned(), api_version: None, query: Vec::new(), headers, body: Vec::new(), http10: false, needs_continue: Cell::new(false), streamed: Cell::new(Streamed::No) }
    }

    /// A request as `read_request` reads it off the wire.
    fn parsed(raw: &str) -> Request {
        use std::io::Write;
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(raw.as_bytes()).unwrap();
        drop(a);
        read_request(&mut BufReader::new(b), |_, _| false).unwrap().unwrap()
    }

    /// Docker.DotNet sends `Connection: close` on every request and reads a
    /// 204 to the end of the stream: the connection must close after it.
    #[test]
    fn connection_close_is_asked_for_in_any_case_and_list() {
        assert!(with_connection(Some("close")).wants_close());
        assert!(with_connection(Some("Close")).wants_close());
        assert!(with_connection(Some("keep-alive, close")).wants_close());
    }

    #[test]
    fn keep_alive_or_no_header_keeps_the_connection() {
        assert!(!with_connection(Some("keep-alive")).wants_close());
        assert!(!with_connection(Some("Upgrade")).wants_close());
        assert!(!with_connection(None).wants_close());
    }

    /// HTTP/1.0 closes after each response unless it asks to keep the
    /// connection; HTTP/1.1 keeps it unless it asks to close.
    #[test]
    fn the_close_follows_the_http_version_and_header() {
        let closes = |raw: &str| parsed(raw).wants_close();
        assert!(closes("POST /v1.44/containers/x/start HTTP/1.1\r\nHost: d\r\nConnection: close\r\n\r\n"));
        assert!(closes("GET /_ping HTTP/1.1\r\nHost: d\r\nconnection: Upgrade, Close\r\n\r\n"));
        assert!(closes("POST /containers/x/start HTTP/1.0\r\nHost: d\r\n\r\n"));
        assert!(closes("GET /_ping HTTP/1.0\r\n\r\n"));
        assert!(closes("GET /_ping HTTP/1.0\r\nConnection: keep-alive, close\r\n\r\n"));
        assert!(!closes("GET /_ping HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n"));
        assert!(!closes("GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n"));
        assert!(!closes("GET /_ping HTTP/1.1\r\nHost: d\r\nConnection: keep-alive\r\n\r\n"));
        assert!(!closes("POST /containers/x/attach HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"));
        // The daemon's own requests keep nothing open, but never ask to close.
        assert!(!Request::internal("POST", "/containers/create", &[], Vec::new()).wants_close());
    }

    /// The response to a request whose connection closes says so, as
    /// Docker's does; a kept-alive one says nothing, and an upgrade or a
    /// response that already names its Connection is not given a second.
    #[test]
    fn a_closing_response_says_connection_close() {
        let answer = |raw: &str, write: &dyn Fn(&mut Vec<u8>) -> io::Result<()>| {
            serving(&parsed(raw));
            let mut out = Vec::new();
            write(&mut out).unwrap();
            String::from_utf8(out).unwrap()
        };
        let close11 = "POST /containers/x/start HTTP/1.1\r\nHost: d\r\nConnection: close\r\n\r\n";
        let start10 = "POST /containers/x/start HTTP/1.0\r\n\r\n";
        let kept = "POST /containers/x/start HTTP/1.1\r\nHost: d\r\n\r\n";

        let r = answer(close11, &|w| empty(w, 204));
        assert!(r.starts_with("HTTP/1.1 204 No Content\r\n") && r.ends_with("Connection: close\r\n\r\n"), "{r}");
        let r = answer(start10, &|w| empty(w, 204));
        assert_eq!(r.matches("Connection: close\r\n").count(), 1, "{r}");
        let r = answer(close11, &|w| json(w, 200, "{}"));
        assert!(r.contains("Content-Length: 2\r\nConnection: close\r\n\r\n{}"), "{r}");
        let r = answer(close11, &|w| begin_stream(w, 200, "application/json"));
        assert!(r.contains("Transfer-Encoding: chunked\r\nConnection: close\r\n"), "{r}");
        let r = answer(close11, &|w| error_closing(w, 409, "busy"));
        assert_eq!(r.matches("Connection:").count(), 1, "{r}");
        let r = answer(close11, &|w| upgrade(w));
        assert!(r.contains("Connection: Upgrade\r\n") && !r.contains("Connection: close"), "{r}");

        let r = answer(kept, &|w| empty(w, 204));
        assert!(!r.contains("Connection:"), "{r}");
        let r = answer(kept, &|w| json(w, 200, "{}"));
        assert!(!r.contains("Connection:"), "{r}");
    }

    #[test]
    fn strips_api_version() {
        assert_eq!(strip_version("/v1.47/containers/json"), "/containers/json");
        assert_eq!(strip_version("/_ping"), "/_ping");
        assert_eq!(version_of("/v1.47"), Some((1, 47)));
        assert_eq!(version_of("/v1.12"), Some((1, 12)));
        assert_eq!(version_of(""), None);
        assert_eq!(version_of("/v2"), None);
        assert!((1, 12) < MIN_API_VERSION && (1, 24) >= MIN_API_VERSION && (1, 99) > MIN_API_VERSION);
        assert_eq!(strip_version("/volumes"), "/volumes");
    }

    #[test]
    fn decodes_query_values() {
        assert_eq!(percent_decode("docker.io%2Flibrary%2Falpine"), "docker.io/library/alpine");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%7B%22a%22%3A1%7D"), "{\"a\":1}");
    }

    /// The path a request is routed by, read from a real request line so
    /// the decoding `read_request` does is what's checked.
    #[test]
    fn decodes_request_paths() {
        use std::io::Write;
        let path_of = |target: &str| {
            let (mut a, b) = UnixStream::pair().unwrap();
            a.write_all(format!("GET {target} HTTP/1.1\r\nHost: d\r\n\r\n").as_bytes())
                .unwrap();
            drop(a);
            let mut r = BufReader::new(b);
            read_request(&mut r, |_, _| false).unwrap().unwrap().path
        };
        // A repository slash a client percent-encoded names the same image
        // as its plain form, with or without the /v1.xx prefix.
        assert_eq!(
            path_of("/v1.44/images/mongodb%2Fmongodb-atlas-local:8.0/json"),
            "/images/mongodb/mongodb-atlas-local:8.0/json"
        );
        assert_eq!(
            path_of("/images/mongodb/mongodb-atlas-local:8.0/json"),
            "/images/mongodb/mongodb-atlas-local:8.0/json"
        );
        // The same hole, everywhere else a name is read from the path.
        assert_eq!(
            path_of("/v1.44/containers/db%3A5/json"),
            "/containers/db:5/json"
        );
        assert_eq!(path_of("/volumes/data%2Fset"), "/volumes/data/set");
        assert_eq!(path_of("/networks/seg%3Anet"), "/networks/seg:net");
        // A `+` is a plus in a path, not the space it is in a query value.
        assert_eq!(path_of("/images/a+b/json"), "/images/a+b/json");
        // An invalid escape stays written, as in query values.
        assert_eq!(path_of("/images/100%/json"), "/images/100%/json");
    }

    /// Clients such as docker-modem send an RFC 9112 §3.2.2 absolute-form
    /// request-target over the Unix socket or named pipe when configured with
    /// a default host and port (#757).
    #[test]
    fn reads_absolute_form_request_targets() {
        use std::io::Write;
        let try_parse = |target: &str| {
            let (mut a, b) = UnixStream::pair().unwrap();
            a.write_all(format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:2376\r\n\r\n").as_bytes())
                .unwrap();
            drop(a);
            read_request(&mut BufReader::new(b), |_, _| false)
        };

        let req = try_parse("http://127.0.0.1:2376/containers/json?all=1").unwrap().unwrap();
        assert_eq!(req.path, "/containers/json");
        assert_eq!(req.api_version, None);
        assert_eq!(req.query("all"), Some("1"));

        let req = try_parse("HTTP://[::1]:2375/v1.47/version").unwrap().unwrap();
        assert_eq!(req.path, "/version");
        assert_eq!(req.api_version, Some((1, 47)));

        let req = try_parse("https://docker:2376/_ping").unwrap().unwrap();
        assert_eq!(req.path, "/_ping");
        assert_eq!(req.api_version, None);

        let req = try_parse("http://localhost:2375").unwrap().unwrap();
        assert_eq!(req.path, "/");
        assert!(req.query.is_empty());

        let req = try_parse("http://localhost:2375?foo=bar").unwrap().unwrap();
        assert_eq!(req.path, "/");
        assert_eq!(req.query("foo"), Some("bar"));

        let req = try_parse("http://127.0.0.1:2376//v1.47/containers/json").unwrap().unwrap();
        assert_eq!(req.path, "//v1.47/containers/json");
        assert_eq!(req.api_version, None);

        let req = try_parse("http://127.0.0.1:2376/v1.44/images/mongodb%2Fmongodb-atlas-local:8.0/json").unwrap().unwrap();
        assert_eq!(req.path, "/images/mongodb/mongodb-atlas-local:8.0/json");
        assert_eq!(req.api_version, Some((1, 44)));

        for bad in [
            "http:///containers/json",
            "https:///containers/json",
            "http://",
            "http://?a=1",
            "ftp://127.0.0.1:2376/_ping",
            "unix:///var/run/docker.sock",
            "http:/containers/json",
            "containers/json",
            "http://:2376/_ping",
            "http://127.0.0.1:/_ping",
            "http://127.0.0.1:99999/_ping",
            "http://[::1/_ping",
            "http://[not-an-ip]/_ping",
            "http://user@127.0.0.1:2376/_ping",
            "http://127.0.0.1:2376/_ping#frag",
            "/_ping#frag",
            "http://127.0.0.1:2376/containers/json extra",
            "/_ping\u{00a0}extra",
            "/_ping\x7f",
        ] {
            assert!(try_parse(bad).is_err(), "accepted malformed target: {bad}");
        }

        let try_raw = |raw: &str| {
            let (mut a, b) = UnixStream::pair().unwrap();
            a.write_all(raw.as_bytes()).unwrap();
            drop(a);
            read_request(&mut BufReader::new(b), |_, _| false)
        };
        for bad_line in [
            "GET  http://127.0.0.1:2376/_ping HTTP/1.1\r\nHost: d\r\n\r\n",
            "GET http://127.0.0.1:2376/_ping  HTTP/1.1\r\nHost: d\r\n\r\n",
            " GET http://127.0.0.1:2376/_ping HTTP/1.1\r\nHost: d\r\n\r\n",
            "GET http://127.0.0.1:2376/_ping HTTP/1.1 \r\nHost: d\r\n\r\n",
            "GET\thttp://127.0.0.1:2376/_ping HTTP/1.1\r\nHost: d\r\n\r\n",
            "GET http://127.0.0.1:2376/_ping\tHTTP/1.1\r\nHost: d\r\n\r\n",
            "GET  HTTP/1.1\r\nHost: d\r\n\r\n",
            "GET /_ping HTTP/2.0\r\nHost: d\r\n\r\n",
        ] {
            assert!(try_raw(bad_line).is_err(), "accepted malformed request line: {bad_line:?}");
        }
    }

    /// `attach` and `exec` start answer `101` only to a client that asked to
    /// upgrade (the docker CLI). docker-java, so Testcontainers, does not, and
    /// gets `200 OK` with the raw stream as the body, as from Docker.
    #[test]
    fn upgrades_only_when_asked() {
        let reply = |headers: Vec<(String, String)>| {
            let req = Request { method: "POST".into(), path: "/exec/x/start".into(), api_version: None, query: Vec::new(), headers, body: Vec::new(), http10: false, needs_continue: Cell::new(false), streamed: Cell::new(Streamed::No) };
            let mut out = Vec::new();
            upgrade_if_asked(&req, &mut out).unwrap();
            String::from_utf8(out).unwrap()
        };
        let asked = reply(vec![("Upgrade".into(), "tcp".into()), ("Connection".into(), "Upgrade".into())]);
        assert!(asked.starts_with("HTTP/1.1 101 "), "{asked}");
        assert!(asked.contains("Upgrade: tcp\r\n"), "{asked}");
        let other = reply(vec![("upgrade".into(), "h2c".into())]);
        assert!(other.starts_with("HTTP/1.1 101 "), "{other}");
        let plain = reply(Vec::new());
        assert!(plain.starts_with("HTTP/1.1 200 OK\r\n"), "{plain}");
        assert!(plain.contains("Content-Type: application/vnd.docker.raw-stream\r\n"), "{plain}");
        assert!(!plain.contains("Upgrade"), "{plain}");
    }

    fn sock(bytes: &[u8]) -> BufReader<UnixStream> {
        let (mut a, b) = UnixStream::pair().unwrap();
        let data = bytes.to_vec();
        // Write on a helper thread so payloads larger than macOS's 8 KiB
        // UnixStream socket buffer never deadlock before the reader starts.
        std::thread::spawn(move || {
            let _ = a.write_all(&data);
        });
        BufReader::new(b)
    }

    /// Chunked bodies (both buffered and streamed) consume their full trailer
    /// section and closing blank line (RFC 9112 §7.1.2) so pipelined keep-alive
    /// requests start at the exact next request line (#745).
    #[test]
    fn chunked_trailers_preserve_keep_alive_boundaries() {
        let head = "POST /containers/create HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n";
        let ping = "GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n";
        for tail in [
            "\r\n",
            "X-Checksum: 1\r\n\r\n",
            "X-Checksum: deadbeef\r\nX-Signature: sig-v1\r\nX-Time: 12:34:56\r\n\r\n",
        ] {
            let raw = format!("{head}{tail}{ping}");
            let mut r = sock(raw.as_bytes());
            let first = read_request(&mut r, |_, _| false).unwrap().unwrap();
            assert_eq!(first.body, b"{}", "{tail:?}");
            let second = read_request(&mut r, |_, _| false).unwrap().unwrap();
            assert_eq!((second.method.as_str(), second.path.as_str()), ("GET", "/_ping"), "{tail:?}");
        }

        // Chunk extensions + multiple chunks + multi-line trailers on both
        // buffered and streamed endpoints, plus a zero-length chunked body.
        let streamed_raw = concat!(
            "PUT /containers/abc/archive?path=/tmp HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n",
            "5;ext=1\r\nhello\r\n",
            "6\r\n world\r\n",
            "0;last=yes\r\n",
            "X-Checksum: sha256:abc\r\n",
            "X-Trailer-Two: ok\r\n",
            "\r\n",
            "GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n",
        );
        let mut r = sock(streamed_raw.as_bytes());
        let first = read_request(&mut r, |m, p| m == "PUT" && p.ends_with("/archive")).unwrap().unwrap();
        let mut data = Vec::new();
        Body::new(&first, &mut r).read_to_end(&mut data).unwrap();
        assert_eq!(data, b"hello world");
        assert!(finish_body(&first, &mut r));
        let second = read_request(&mut r, |_, _| false).unwrap().unwrap();
        assert_eq!((second.method.as_str(), second.path.as_str()), ("GET", "/_ping"));

        let empty_chunked = "POST /images/load HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Empty: 1\r\n\r\nGET /_ping HTTP/1.1\r\nHost: d\r\n\r\n";
        let mut r = sock(empty_chunked.as_bytes());
        let first = read_request(&mut r, |_, p| p == "/images/load").unwrap().unwrap();
        let mut data = Vec::new();
        Body::new(&first, &mut r).read_to_end(&mut data).unwrap();
        assert!(data.is_empty());
        assert!(finish_body(&first, &mut r));
        let second = read_request(&mut r, |_, _| false).unwrap().unwrap();
        assert_eq!((second.method.as_str(), second.path.as_str()), ("GET", "/_ping"));
    }

    /// Trailer sections and chunk framing are bounded and validated in both
    /// buffered and streamed paths so endless, oversized, truncated, or
    /// malformed trailers and chunk delimiters fail cleanly (#745).
    #[test]
    fn chunked_trailers_and_delimiters_are_bounded_and_validated() {
        let prefix = "POST /containers/create HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n";

        // Single giant trailer line past MAX_TRAILERS -> InvalidData.
        let giant = format!("{prefix}X-Big: {}\r\n\r\n", "a".repeat(MAX_TRAILERS as usize + 64));
        assert_eq!(read_request(&mut sock(giant.as_bytes()), |_, _| false).unwrap_err().kind(), io::ErrorKind::InvalidData);

        // Many trailer lines summing past MAX_TRAILERS -> InvalidData.
        let mut many_bytes = String::from(prefix);
        for i in 0..100 {
            many_bytes.push_str(&format!("X-Pad-{i:03}: {}\r\n", "b".repeat(100)));
        }
        many_bytes.push_str("\r\n");
        assert_eq!(read_request(&mut sock(many_bytes.as_bytes()), |_, _| false).unwrap_err().kind(), io::ErrorKind::InvalidData);

        // Exceeding MAX_TRAILER_LINES even while well under MAX_TRAILERS -> InvalidData.
        let mut many_lines = String::from(prefix);
        for i in 0..=MAX_TRAILER_LINES {
            many_lines.push_str(&format!("X-{i}: 1\r\n"));
        }
        many_lines.push_str("\r\n");
        assert!(many_lines.len() < MAX_TRAILERS as usize + prefix.len());
        assert_eq!(read_request(&mut sock(many_lines.as_bytes()), |_, _| false).unwrap_err().kind(), io::ErrorKind::InvalidData);

        // Same oversized-trailer rejection on the streamed Body path.
        let streamed_big = format!(
            "POST /images/load HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Big: {}\r\n\r\n",
            "z".repeat(MAX_TRAILERS as usize + 16),
        );
        let mut r = sock(streamed_big.as_bytes());
        let req = read_request(&mut r, |_, p| p == "/images/load").unwrap().unwrap();
        assert_eq!(Body::new(&req, &mut r).read_to_end(&mut Vec::new()).unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(!finish_body(&req, &mut r));

        // Truncated trailers hit UnexpectedEof and prevent keep-alive reuse.
        for cut_raw in [
            "POST /images/load HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Incomplete: 1",
            "POST /images/load HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Incomplete: 1\r\n",
            "POST /images/load HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n",
        ] {
            let mut r = sock(cut_raw.as_bytes());
            let req = read_request(&mut r, |_, p| p == "/images/load").unwrap().unwrap();
            assert_eq!(Body::new(&req, &mut r).read_to_end(&mut Vec::new()).unwrap_err().kind(), io::ErrorKind::UnexpectedEof, "{cut_raw:?}");
            assert!(!finish_body(&req, &mut r));
        }

        // Malformed trailer headers, bad chunk delimiters, funky-chunk bare LF
        // lines, control characters in chunk extensions/trailers, and invalid sizes.
        let huge_ext = format!(
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n0;{}\r\n\r\n",
            "e".repeat(MAX_CHUNK_LINE as usize + 16),
        );
        for bad in [
            format!("{prefix}GET /_ping HTTP/1.1\r\n\r\n"),
            format!("{prefix}: missing-name\r\n\r\n"),
            format!("{prefix}X-T: 1\n\r\n"),
            format!("{prefix}\n"),
            format!("{prefix}X-T: a\rb\r\n\r\n"),
            format!("{prefix}X-T: a\0b\r\n\r\n"),
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n".to_owned(),
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n".to_owned(),
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n 5\r\nhello\r\n0\r\n\r\n".to_owned(),
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n5\nhello\r\n0\r\n\r\n".to_owned(),
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n0\n\r\n".to_owned(),
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\nhello\r\n0\r\n\r\n".to_owned(),
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=a\rb\r\nhello\r\n0\r\n\r\n".to_owned(),
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n5;ext\r\r\nhello\r\n0\r\n\r\n".to_owned(),
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=\0x\r\nhello\r\n0\r\n\r\n".to_owned(),
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=\x01\r\nhello\r\n0\r\n\r\n".to_owned(),
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=\x1f\r\nhello\r\n0\r\n\r\n".to_owned(),
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=\x7f\r\nhello\r\n0\r\n\r\n".to_owned(),
            huge_ext,
        ] {
            assert_eq!(read_request(&mut sock(bad.as_bytes()), |_, _| false).unwrap_err().kind(), io::ErrorKind::InvalidData, "buffered: {bad:?}");
            let mut r = sock(bad.as_bytes());
            let req = read_request(&mut r, |_, _| true).unwrap().unwrap();
            assert_eq!(Body::new(&req, &mut r).read_to_end(&mut Vec::new()).unwrap_err().kind(), io::ErrorKind::InvalidData, "streamed: {bad:?}");
        }

        // HTAB in chunk extensions remains valid per RFC 9112 §7.1.1.
        let htab_ext = "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=\t1\r\nhello\r\n0\r\n\r\n";
        let req = read_request(&mut sock(htab_ext.as_bytes()), |_, _| false).unwrap().unwrap();
        assert_eq!(req.body, b"hello");

        // Truncated buffered Content-Length and chunked bodies return UnexpectedEof.
        for short in [
            "POST /x HTTP/1.1\r\nHost: d\r\nContent-Length: 10\r\n\r\nabc",
            "POST /x HTTP/1.1\r\nHost: d\r\nContent-Length: 8388608\r\n\r\n",
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel",
        ] {
            assert_eq!(read_request(&mut sock(short.as_bytes()), |_, _| false).unwrap_err().kind(), io::ErrorKind::UnexpectedEof, "{short:?}");
        }
    }

    /// RFC 9112 §5.1 / §5.2: malformed header lines (obs-fold leading whitespace,
    /// missing ':', whitespace before ':', empty or non-token field names, and
    /// control characters in values) are rejected with InvalidData.
    #[test]
    fn rejects_malformed_header_lines() {
        for bad in [
            "POST /x HTTP/1.1\r\nHost: d\r\n Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "POST /x HTTP/1.1\r\nHost: d\r\n\tTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n",
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding\t: chunked\r\n\r\n0\r\n\r\n",
            "GET /_ping HTTP/1.1\r\nHost: d\r\nNoColonHeader\r\n\r\n",
            "GET /_ping HTTP/1.1\r\nHost: d\r\n   \r\n\r\n",
            "GET /_ping HTTP/1.1\r\nHost: d\r\n: value\r\n\r\n",
            "GET /_ping HTTP/1.1\r\nHost: d\r\nBad Name: value\r\n\r\n",
            "GET /_ping HTTP/1.1\r\nHost: d\r\nBad(Name): value\r\n\r\n",
            "GET /_ping HTTP/1.1\r\nHost: d\r\nBad\0Name: value\r\n\r\n",
            "GET /_ping HTTP/1.1\r\nHost: d\r\nX-Foo: a\rb\r\n\r\n",
            "GET /_ping HTTP/1.1\r\nHost: d\r\nX-Foo: a\0b\r\n\r\n",
            "GET /_ping HTTP/1.1\r\nHost: d\r\nX-Foo: a\x7fb\r\n\r\n",
        ] {
            assert_eq!(read_request(&mut sock(bad.as_bytes()), |_, _| false).unwrap_err().kind(), io::ErrorKind::InvalidData, "buffered: {bad:?}");
            assert_eq!(read_request(&mut sock(bad.as_bytes()), |_, _| true).unwrap_err().kind(), io::ErrorKind::InvalidData, "streamed: {bad:?}");
        }

        // Valid headers with OWS tabs/spaces around values and empty values pass.
        let ok = parsed("GET /_ping HTTP/1.1\r\nHost: d\r\nX-Empty:\r\nX-Tab: \tval \t\r\n\r\n");
        assert_eq!(ok.header("X-Empty"), Some(""));
        assert_eq!(ok.header("X-Tab"), Some("val"));
    }

    /// HTTP/1.1 requests with `Expect: 100-continue` receive `HTTP/1.1 100 Continue`
    /// eagerly for buffered bodies and lazily on first `Body` read for streamed
    /// routes (so early 4xx rejections never ask the client to upload), while
    /// HTTP/1.0, bodiless, and oversized requests never receive 100 Continue (#134).
    #[test]
    fn expect_100_continue_handshakes_before_reading_body() {
        use std::sync::mpsc;
        use std::time::Duration;

        // 1. Buffered Content-Length: client waits for 100 Continue before writing body.
        {
            let (mut client, server) = UnixStream::pair().unwrap();
            client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let t = std::thread::spawn(move || {
                let mut r = BufReader::new(server);
                let first = read_request(&mut r, |_, _| false).unwrap().unwrap();
                let second = read_request(&mut r, |_, _| false).unwrap().unwrap();
                (first.body, second.method, second.path)
            });
            client.write_all(b"POST /containers/create HTTP/1.1\r\nHost: d\r\nExpect: 100-continue\r\nContent-Length: 11\r\n\r\n").unwrap();
            let mut interim = [0u8; 25];
            client.read_exact(&mut interim).unwrap();
            assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
            client.write_all(b"{\"a\":12345}GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n").unwrap();
            drop(client);
            let (body, m, p) = t.join().unwrap();
            assert_eq!(body, b"{\"a\":12345}");
            assert_eq!((m.as_str(), p.as_str()), ("GET", "/_ping"));
        }

        // 2. Streamed chunked upload (as .NET/curl send for PUT /archive) with trailers:
        //    read_request does NOT emit 100 Continue; Body::read emits it lazily.
        {
            let (mut client, server) = UnixStream::pair().unwrap();
            client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let (head_done_tx, head_done_rx) = mpsc::channel();
            let (go_read_tx, go_read_rx) = mpsc::channel();
            let t = std::thread::spawn(move || {
                let mut r = BufReader::new(server);
                let req = read_request(&mut r, |m, p| m == "PUT" && p.ends_with("/archive")).unwrap().unwrap();
                assert!(req.needs_continue());
                head_done_tx.send(()).unwrap();
                go_read_rx.recv().unwrap();
                let mut data = Vec::new();
                Body::new(&req, &mut r).read_to_end(&mut data).unwrap();
                assert!(!req.needs_continue());
                assert!(finish_body(&req, &mut r));
                let next = read_request(&mut r, |_, _| false).unwrap().unwrap();
                (data, next.path)
            });
            client.write_all(b"PUT /containers/c/archive?path=/tmp HTTP/1.1\r\nHost: d\r\nExpect: 100-Continue\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
            head_done_rx.recv().unwrap();
            // Confirm nothing was written before the handler reads Body.
            client.set_nonblocking(true).unwrap();
            let mut peek = [0u8; 1];
            assert_eq!(client.read(&mut peek).unwrap_err().kind(), io::ErrorKind::WouldBlock);
            client.set_nonblocking(false).unwrap();
            client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            go_read_tx.send(()).unwrap();
            let mut interim = [0u8; 25];
            client.read_exact(&mut interim).unwrap();
            assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
            client.write_all(b"7\r\ntarball\r\n0\r\nX-Hash: abc\r\n\r\nGET /_ping HTTP/1.1\r\nHost: d\r\n\r\n").unwrap();
            drop(client);
            let (data, next_path) = t.join().unwrap();
            assert_eq!(data, b"tarball");
            assert_eq!(next_path, "/_ping");
        }

        // 3. Streamed unread body with Expect: 100-continue does NOT emit 100 Continue;
        //    answering adds Connection: close and finish_body closes the connection.
        {
            let (mut client, server) = UnixStream::pair().unwrap();
            client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let t = std::thread::spawn(move || {
                let mut w = server.try_clone().unwrap();
                let mut r = BufReader::new(server);
                let req = read_request(&mut r, |m, p| m == "PUT" && p.ends_with("/archive")).unwrap().unwrap();
                assert!(req.needs_continue());
                serving(&req);
                error(&mut w, 404, "No such container").unwrap();
                assert!(!finish_body(&req, &mut r));
                close(&w, &mut r);
            });
            client.write_all(b"PUT /containers/missing/archive?path=/tmp HTTP/1.1\r\nHost: d\r\nExpect: 100-continue\r\nContent-Length: 1073741824\r\n\r\n").unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).unwrap();
            drop(client);
            t.join().unwrap();
            let reply = String::from_utf8_lossy(&reply);
            assert!(reply.starts_with("HTTP/1.1 404 Not Found\r\n"), "{reply}");
            assert!(reply.contains("Connection: close\r\n"), "{reply}");
            assert!(!reply.contains("100 Continue"), "{reply}");
        }

        // 4. Oversized buffered body, HTTP/1.0, and bodiless requests must NOT send 100 Continue.
        for (raw, check_too_large) in [
            (format!("POST /x HTTP/1.1\r\nHost: d\r\nExpect: 100-continue\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1), true),
            ("POST /x HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n{}".to_owned(), false),
            ("GET /_ping HTTP/1.1\r\nHost: d\r\nExpect: 100-continue\r\n\r\n".to_owned(), false),
            ("POST /x HTTP/1.1\r\nHost: d\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\n".to_owned(), false),
        ] {
            let (mut client, server) = UnixStream::pair().unwrap();
            client.write_all(raw.as_bytes()).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            let req = read_request(&mut BufReader::new(server), |_, _| false).unwrap().unwrap();
            assert_eq!(req.too_large(), check_too_large, "{raw:?}");
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).unwrap();
            assert!(reply.is_empty(), "unexpected 100 Continue for {raw:?}: {:?}", String::from_utf8_lossy(&reply));
        }
    }

    /// Ambiguous Transfer-Encoding + Content-Length combinations and malformed
    /// or conflicting Content-Length headers are rejected with InvalidData so
    /// the server responds 400 Bad Request and closes the connection (#134).
    #[test]
    fn rejects_ambiguous_transfer_encoding_and_content_length_framing() {
        for bad in [
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n",
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n",
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: \r\nContent-Length: 5\r\n\r\nhello",
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked, chunked\r\n\r\n0\r\n\r\n",
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: identity\r\n\r\n",
            "POST /x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: \r\n\r\n",
            "POST /x HTTP/1.0\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "POST /x HTTP/1.1\r\nHost: d\r\nContent-Length: 4\r\nContent-Length: 8\r\n\r\nabcd",
            "POST /x HTTP/1.1\r\nHost: d\r\nContent-Length: 4, 8\r\n\r\nabcd",
            "POST /x HTTP/1.1\r\nHost: d\r\nContent-Length: 99999999999999999999999999999\r\n\r\n",
            "POST /x HTTP/1.1\r\nHost: d\r\nContent-Length: -1\r\n\r\n",
            "POST /x HTTP/1.1\r\nHost: d\r\nContent-Length: +4\r\n\r\nabcd",
            "POST /x HTTP/1.1\r\nHost: d\r\nContent-Length: abc\r\n\r\n",
            "POST /x HTTP/1.1\r\nHost: d\r\nContent-Length: \r\n\r\n",
        ] {
            assert_eq!(read_request(&mut sock(bad.as_bytes()), |_, _| false).unwrap_err().kind(), io::ErrorKind::InvalidData, "buffered accepted: {bad:?}");
            assert_eq!(read_request(&mut sock(bad.as_bytes()), |_, _| true).unwrap_err().kind(), io::ErrorKind::InvalidData, "streamed accepted: {bad:?}");
        }

        // TE+CL with Expect: 100-continue must reject without sending 100 Continue.
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(b"POST /x HTTP/1.1\r\nHost: d\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n").unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(read_request(&mut BufReader::new(server), |_, _| false).unwrap_err().kind(), io::ErrorKind::InvalidData);
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert!(reply.is_empty());

        // Identical duplicate Content-Length values remain valid per RFC 9112 §6.3.
        for dup in [
            "POST /x HTTP/1.1\r\nHost: d\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nabcd",
            "POST /x HTTP/1.1\r\nHost: d\r\nContent-Length: 4, 4\r\n\r\nabcd",
        ] {
            let req = read_request(&mut sock(dup.as_bytes()), |_, _| false).unwrap().unwrap();
            assert_eq!(req.body, b"abcd", "{dup:?}");
        }
    }
}
