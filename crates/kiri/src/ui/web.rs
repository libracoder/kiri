//! Browser UI over HTTP: the same page as the native window, reached at
//! localhost or on the LAN. The page talks JSON over a WebSocket the way it
//! talks `webkit.messageHandlers.kiri` in the window; [`super::handle`] and
//! [`super::emit`] are shared.
//!
//! `kiri ui --web` binds here. A one-time token in the URL gates every
//! request so an open LAN port is not an open Docker API.

use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::{Cmd, PAGE, assemble, engine, handle, prefs};

/// True while [`run`] is serving; [`super::emit`] fans events here then.
static SERVING: AtomicBool = AtomicBool::new(false);

/// Connected WebSocket clients: each gets every event as a text frame.
static CLIENTS: Mutex<Vec<Client>> = Mutex::new(Vec::new());
static CLIENT_ID: AtomicU64 = AtomicU64::new(1);

struct Client {
    id: u64,
    tx: Sender<String>,
}

/// Whether the browser UI is the active host (no AppKit/GTK main loop).
pub fn serving() -> bool {
    SERVING.load(Ordering::Relaxed)
}

/// Push one JSON event to every open browser tab.
pub fn broadcast(json: &str) {
    let Ok(mut clients) = CLIENTS.lock() else { return };
    clients.retain(|c| c.tx.send(json.to_owned()).is_ok());
}

/// Run JS in every browser tab (language words, and nothing else today).
pub fn eval(js: &str) {
    broadcast(&serde_json::json!({"type": "eval", "js": js}).to_string());
}

/// Ask every tab to put `text` on the clipboard (`navigator.clipboard`).
pub fn copy(text: &str) {
    broadcast(&serde_json::json!({"type": "clipboard", "text": text}).to_string());
}

/// Ask the focused tab to read the clipboard and paste into terminal `id`.
pub fn paste(id: &str) {
    broadcast(&serde_json::json!({"type": "clipboardask", "id": id}).to_string());
}

/// Default port when none is given: unlikely to collide with a container publish.
pub const DEFAULT_PORT: u16 = 7676;

pub struct Opts {
    pub host: String,
    pub port: u16,
    pub lan: bool,
    pub autostart: bool,
    pub view: Option<String>,
}

/// `kiri ui --web [--lan] [--host ADDR] [--port N] [--start] [--view …]`.
pub fn parse_opts(args: &[String]) -> Result<Opts, String> {
    let mut opts = Opts {
        host: "127.0.0.1".into(),
        port: DEFAULT_PORT,
        lan: false,
        autostart: args.iter().any(|a| a == "--start"),
        view: args.iter().position(|a| a == "--view").and_then(|i| args.get(i + 1)).cloned(),
    };
    if args.iter().any(|a| a == "--lan") {
        opts.lan = true;
        opts.host = "0.0.0.0".into();
    }
    if let Some(i) = args.iter().position(|a| a == "--host") {
        let h = args.get(i + 1).ok_or("usage: kiri ui --web --host ADDR")?.clone();
        opts.host = h;
        opts.lan = opts.host != "127.0.0.1" && opts.host != "::1" && opts.host != "localhost";
    }
    if let Some(i) = args.iter().position(|a| a == "--port") {
        let p = args.get(i + 1).ok_or("usage: kiri ui --web --port N")?;
        opts.port = p.parse().map_err(|_| format!("bad --port {p}"))?;
    }
    Ok(opts)
}

/// Serve the page until the process is killed (Ctrl-C).
pub fn run(opts: Opts) -> io::Result<()> {
    let addr: SocketAddr = format!("{}:{}", opts.host, opts.port).parse().map_err(io::Error::other)?;
    let listener = TcpListener::bind(addr)?;
    let bound = listener.local_addr()?;
    let token = new_token();
    SERVING.store(true, Ordering::Relaxed);

    let (tx, rx) = std::sync::mpsc::channel();
    let engine_tx = tx.clone();
    let engine = std::thread::Builder::new().name("kiri-engine".into()).spawn(move || engine(rx, engine_tx))?;

    let page = page_html();
    let state = Arc::new(State { token: token.clone(), page, autostart: opts.autostart, view: opts.view });

    let url = open_url(bound, &token, opts.lan);
    super::webctl::write_serving(&url, bound.port(), opts.lan, &token);
    eprintln!("kiri: web UI at {url}");
    if opts.lan {
        for ip in lan_ips() {
            eprintln!("       also http://{ip}:{}?token={token}", bound.port());
        }
    }
    eprintln!("kiri: Ctrl-C to stop");

    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let _ = stream.set_nodelay(true);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
        let (state, page_tx) = (state.clone(), tx.clone());
        let _ = std::thread::Builder::new().name("kiri-web".into()).spawn(move || {
            let _ = serve(stream, &state, &page_tx);
        });
    }

    SERVING.store(false, Ordering::Relaxed);
    super::webctl::clear_serving();
    let _ = tx.send(Cmd::Quit);
    let _ = engine.join();
    Ok(())
}

struct State {
    token: String,
    page: String,
    autostart: bool,
    view: Option<String>,
}

fn page_html() -> String {
    let mut html = assemble::page(PAGE, prefs()["lang"].as_str());
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(windows) {
        "windows"
    } else {
        "macos"
    };
    let shim = format!(
        r#"<script>window.KIRI_WEB=true;window.KIRI_OS="{os}";</script>"#
    );
    if let Some(i) = html.find("<head>") {
        html.insert_str(i + "<head>".len(), &shim);
    } else {
        html.insert_str(0, &shim);
    }
    html
}

fn open_url(bound: SocketAddr, token: &str, lan: bool) -> String {
    let host = if lan {
        lan_ips().into_iter().next().unwrap_or_else(|| match bound.ip() {
            std::net::IpAddr::V4(v) if !v.is_unspecified() => v.to_string(),
            _ => "127.0.0.1".into(),
        })
    } else if bound.ip().is_loopback() || bound.ip().is_unspecified() {
        "127.0.0.1".into()
    } else {
        bound.ip().to_string()
    };
    format!("http://{host}:{}?token={token}", bound.port())
}

fn lan_ips() -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    if let Ok(ifaces) = list_ipv4() {
        for ip in ifaces {
            if seen.insert(ip.clone()) {
                out.push(ip);
            }
        }
    }
    out
}

/// Non-loopback IPv4 addresses on this machine, for the printed LAN URL.
fn list_ipv4() -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    // UDP connect picks the route's local address without sending packets.
    for probe in ["8.8.8.8:80", "1.1.1.1:80"] {
        if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if s.connect(probe).is_ok() {
                if let Ok(local) = s.local_addr() {
                    let ip = local.ip();
                    if let std::net::IpAddr::V4(v4) = ip {
                        if !v4.is_loopback() && !v4.is_unspecified() {
                            out.push(v4.to_string());
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

fn new_token() -> String {
    let mut buf = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    } else {
        // Last resort when urandom is missing (unusual on the hosts Kiribra runs on).
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((t >> (i * 8)) ^ u128::from(std::process::id())).to_le_bytes()[i % 16];
        }
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn serve(mut stream: TcpStream, state: &State, tx: &Sender<Cmd>) -> io::Result<()> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 2048];
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 64 << 10 {
            return Ok(());
        }
        if let Some(i) = find_headers_end(&buf) {
            let head = String::from_utf8_lossy(&buf[..i]).into_owned();
            let rest = buf[i..].to_vec();
            return route(stream, &head, rest, state, tx);
        }
    }
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn route(stream: TcpStream, head: &str, _body: Vec<u8>, state: &State, tx: &Sender<Cmd>) -> io::Result<()> {
    let mut lines = head.split("\r\n");
    let req = lines.next().unwrap_or("");
    let mut parts = req.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let headers: Vec<(&str, &str)> = lines.filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim(), v.trim()))).collect();
    let header = |name: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| *v);

    if !authorized(query, header("Cookie"), &state.token) {
        return respond(stream, 401, "text/plain; charset=utf-8", b"unauthorized: open the URL kiri printed (it has ?token=...)");
    }

    if method == "GET" && (path == "/" || path.is_empty()) {
        // Persist the token as a cookie so the WebSocket upgrade (no query) still passes.
        let mut extra = format!("Set-Cookie: kiri_token={}; Path=/; SameSite=Lax; HttpOnly\r\n", state.token);
        if !query.contains("token=") {
            // Redirect once so the address bar carries the token for bookmarking.
            extra.push_str(&format!("Location: /?token={}\r\n", state.token));
            return respond_headers(stream, 302, "text/plain; charset=utf-8", &extra, b"");
        }
        return respond_headers(stream, 200, "text/html; charset=utf-8", &extra, state.page.as_bytes());
    }

    if method == "GET" && path == "/ws" {
        return ws_accept(stream, &headers, state, tx);
    }

    respond(stream, 404, "text/plain; charset=utf-8", b"not found")
}

fn authorized(query: &str, cookie: Option<&str>, token: &str) -> bool {
    query_token(query).as_deref() == Some(token)
        || cookie.and_then(cookie_token).as_deref() == Some(token)
}

fn query_token(query: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix("token=") {
            return Some(v.to_owned());
        }
    }
    None
}

fn cookie_token(cookie: &str) -> Option<String> {
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("kiri_token=") {
            return Some(v.to_owned());
        }
    }
    None
}

fn respond(stream: TcpStream, status: u16, ctype: &str, body: &[u8]) -> io::Result<()> {
    respond_headers(stream, status, ctype, "", body)
}

fn respond_headers(mut stream: TcpStream, status: u16, ctype: &str, extra: &str, body: &[u8]) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        302 => "Found",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
        body.len()
    )?;
    stream.write_all(body)
}

fn ws_accept(mut stream: TcpStream, headers: &[(&str, &str)], state: &State, tx: &Sender<Cmd>) -> io::Result<()> {
    let key = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("Sec-WebSocket-Key")).map(|(_, v)| *v).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no websocket key"))?;
    if !headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("Upgrade") && v.eq_ignore_ascii_case("websocket")) {
        return respond(stream, 400, "text/plain; charset=utf-8", b"expected websocket upgrade");
    }
    let accept = ws_accept_key(key);
    write!(
        stream,
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    )?;
    stream.flush()?;

    let (out_tx, out_rx) = std::sync::mpsc::channel::<String>();
    let id = CLIENT_ID.fetch_add(1, Ordering::Relaxed);
    {
        let Ok(mut clients) = CLIENTS.lock() else {
            return Ok(());
        };
        clients.push(Client { id, tx: out_tx });
    }

    let mut writer = stream.try_clone()?;
    let writer_thread = std::thread::spawn(move || {
        while let Ok(msg) = out_rx.recv() {
            if write_text(&mut writer, &msg).is_err() {
                break;
            }
        }
    });

    let mut reader = stream;
    let _ = reader.set_read_timeout(Some(Duration::from_secs(300)));
    loop {
        match read_text(&mut reader) {
            Ok(Some(text)) => handle(&text, tx, state.autostart, state.view.as_deref()),
            Ok(None) => break, // close
            Err(_) => break,
        }
    }
    if let Ok(mut clients) = CLIENTS.lock() {
        clients.retain(|c| c.id != id);
    }
    let _ = writer_thread.join();
    Ok(())
}

fn ws_accept_key(key: &str) -> String {
    let mut data = Vec::with_capacity(key.len() + 36);
    data.extend_from_slice(key.as_bytes());
    data.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    b64(&sha1(&data))
}

fn write_text(stream: &mut TcpStream, text: &str) -> io::Result<()> {
    let payload = text.as_bytes();
    let mut frame = Vec::with_capacity(2 + payload.len() + 8);
    frame.push(0x81); // FIN + text
    if payload.len() < 126 {
        frame.push(payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        frame.push(126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    stream.write_all(&frame)?;
    stream.flush()
}

/// Next text message, or `None` on close. Control frames are handled inline.
fn read_text(stream: &mut TcpStream) -> io::Result<Option<String>> {
    loop {
        let mut hdr = [0u8; 2];
        stream.read_exact(&mut hdr)?;
        let opcode = hdr[0] & 0x0f;
        let masked = hdr[1] & 0x80 != 0;
        let mut len = (hdr[1] & 0x7f) as u64;
        if len == 126 {
            let mut b = [0u8; 2];
            stream.read_exact(&mut b)?;
            len = u64::from(u16::from_be_bytes(b));
        } else if len == 127 {
            let mut b = [0u8; 8];
            stream.read_exact(&mut b)?;
            len = u64::from_be_bytes(b);
        }
        if len > 8 << 20 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
        }
        let mut mask = [0u8; 4];
        if masked {
            stream.read_exact(&mut mask)?;
        }
        let mut payload = vec![0u8; len as usize];
        if len > 0 {
            stream.read_exact(&mut payload)?;
        }
        if masked {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        match opcode {
            0x1 => return Ok(Some(String::from_utf8_lossy(&payload).into_owned())),
            0x8 => return Ok(None),
            0x9 => {
                // pong
                let mut pong = Vec::with_capacity(2 + payload.len());
                pong.push(0x8a);
                pong.push(payload.len() as u8);
                pong.extend_from_slice(&payload);
                stream.write_all(&pong)?;
            }
            0xA => {} // pong
            _ => {}
        }
    }
}

fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            out.push(if i <= c.len() { T[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

/// SHA-1 for the WebSocket handshake only (RFC 6455).
fn sha1(message: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;
    let bit_len = (message.len() as u64) * 8;
    let mut msg = message.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, h) in [h0, h1, h2, h3, h4].into_iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&h.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn websocket_accept_matches_rfc_example() {
        // RFC 6455 §1.3
        assert_eq!(super::ws_accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }
}
