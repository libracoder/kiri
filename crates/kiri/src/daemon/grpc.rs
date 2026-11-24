//! Docker's BuildKit endpoints (`POST /grpc` and `POST /session`): lets buildx
//! (including a docker CLI inside a container mounting `/var/run/docker.sock`)
//! use its `docker` driver against Kiri's managed BuildKit container
//! (`buildx_buildkit_kiri-build0`), landing built images directly into Kiri's
//! image store without creating a separate unconfigured `default` builder.
//!
//! Zero external crates: minimal HTTP/2 framing, a passive RFC 7541 HPACK
//! decoder for tracking `Control/Solve` streams, and a wire-preserving
//! protobuf rewriter for `SolveRequest` / `SolveResponse` / `BytesMessage`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use kiri_image::Reference;
use kiri_proto::Stream;

use super::api::{self, Next};
use super::builder;
use super::engine::{Engine, Error};
use super::http::{self, Request};
use super::mirror::{self, LoadSession};

const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_PING: u8 = 0x6;
const FRAME_GOAWAY: u8 = 0x7;
const FRAME_WINDOW_UPDATE: u8 = 0x8;
const FRAME_CONTINUATION: u8 = 0x9;

const FLAG_END_STREAM: u8 = 0x01;
const FLAG_ACK: u8 = 0x01;
const FLAG_END_HEADERS: u8 = 0x04;
const FLAG_PADDED: u8 = 0x08;
const FLAG_PRIORITY: u8 = 0x20;

const SETTING_INITIAL_WINDOW_SIZE: u16 = 0x4;
const SETTING_MAX_FRAME_SIZE: u16 = 0x5;

const DEFAULT_MAX_FRAME_SIZE: usize = 16_384;
const INITIAL_FRAME_CAP: usize = 64 << 10;
const MAX_FRAME_LIMIT: usize = 4 << 20;
const MAX_SOLVE_BODY: usize = 16 << 20;
const MAX_SOLVE_REQ_BYTES: usize = MAX_SOLVE_BODY;
const MAX_TOTAL_SOLVE_REQ_BYTES: usize = 32 << 20;
const MAX_CONCURRENT_SOLVE_STREAMS: usize = 16;
const MAX_CONTINUATION_FRAMES: usize = 32;
const MAX_HEADER_BLOCK: usize = 1 << 20;
const MAX_HPACK_TABLE_SIZE: usize = 1 << 20;
const MAX_DECODED_HEADERS: usize = 2 << 20;
const EXEC_STDIN_CHUNK: usize = 32 * 1024;

const SOLVE_PATH: &str = "/moby.buildkit.v1.Control/Solve";
const SESSION_PATH: &str = "/moby.buildkit.v1.Control/Session";

fn has_h2c_upgrade(req: &Request) -> bool {
    req.header("Upgrade")
        .is_some_and(|u| u.split(',').any(|t| t.trim().eq_ignore_ascii_case("h2c")))
}

/// `POST /grpc` (`Upgrade: h2c`): proxies BuildKit gRPC to Kiri's managed
/// BuildKit container via `buildctl dial-stdio`, rewriting `moby` exporter
/// solves into Kiri's store (or direct registry pushes when `push=true`).
pub fn grpc(req: &Request, engine: &Arc<Engine>, w: &mut UnixStream, r: &mut BufReader<UnixStream>) -> io::Result<Next> {
    if !has_h2c_upgrade(req) {
        api::error(w, Error::BadRequest("POST /grpc requires Upgrade: h2c".into()))?;
        return Ok(Next::KeepAlive);
    }
    http::upgrade_h2c(w)?;

    // buildx's driver priority probe dials `/grpc`, checks for 101, and closes
    // immediately without sending any HTTP/2 bytes: wait for the first byte
    // before touching the builder so probes never wake or pull BuildKit.
    let mut initial = r.buffer().to_vec();
    r.consume(initial.len());
    let mut client_r = r.get_ref().try_clone()?;
    if initial.is_empty() {
        api::wait_readable(&client_r);
        let mut buf = [0u8; 4096];
        match client_r.read(&mut buf) {
            Ok(0) | Err(_) => return Ok(Next::Close),
            Ok(n) => initial.extend_from_slice(&buf[..n]),
        }
    }

    let (builder_id, _busy) = match builder::ensure_running(engine, &mut |_| {}) {
        Ok(v) => v,
        Err(e) => {
            let _ = send_goaway(w, &format!("{e:?}"));
            return Ok(Next::Close);
        }
    };
    let host_net = builder::builder_host_net(engine, &builder_id);
    let argv = vec!["buildctl".to_owned(), "dial-stdio".to_owned()];
    let exec = match engine.exec_create(&builder_id, builder::internal_exec(&argv, true, Vec::new())) {
        Ok(id) => id,
        Err(e) => {
            let _ = send_goaway(w, &format!("{e:?}"));
            return Ok(Next::Close);
        }
    };
    let (_, rx) = match engine.exec_start(&exec) {
        Ok(v) => v,
        Err(e) => {
            engine.forget_exec(&exec);
            let _ = send_goaway(w, &format!("{e:?}"));
            return Ok(Next::Close);
        }
    };

    let client_reader = PrefixReader::new(initial, PollUnixReader(client_r.try_clone()?));
    let exec_reader = StdoutReader::new(rx);
    let exec_writer = ExecStdinWriter { engine: engine.clone(), exec: exec.clone() };
    let _ = proxy_grpc(
        client_reader,
        w.try_clone()?,
        exec_reader,
        exec_writer,
        engine,
        host_net,
        || {
            let _ = engine.close_stdin(&exec);
        },
        || {
            let _ = engine.close_stdin(&exec);
            let _ = client_r.shutdown(Shutdown::Both);
        },
    );
    let _ = engine.close_stdin(&exec);
    engine.forget_exec(&exec);
    Ok(Next::Close)
}

/// `POST /session` (`Upgrade: h2c`): bridges BuildKit's reverse h2c session
/// stream into `moby.buildkit.v1.Control/Session` (`BytesMessage`) on Kiri's
/// managed BuildKit container.
pub fn session(req: &Request, engine: &Arc<Engine>, w: &mut UnixStream, r: &mut BufReader<UnixStream>) -> io::Result<Next> {
    if !has_h2c_upgrade(req) {
        api::error(w, Error::BadRequest("POST /session requires Upgrade: h2c".into()))?;
        return Ok(Next::KeepAlive);
    }
    let session_headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter(|(k, _)| k.to_ascii_lowercase().starts_with("x-docker-expose-session-"))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();
    http::upgrade_h2c(w)?;

    let early = r.buffer().to_vec();
    r.consume(early.len());
    let client_r = r.get_ref().try_clone()?;

    let (builder_id, _busy) = match builder::ensure_running(engine, &mut |_| {}) {
        Ok(v) => v,
        Err(_) => return Ok(Next::Close),
    };
    let argv = vec!["buildctl".to_owned(), "dial-stdio".to_owned()];
    let exec = match engine.exec_create(&builder_id, builder::internal_exec(&argv, true, Vec::new())) {
        Ok(id) => id,
        Err(_) => return Ok(Next::Close),
    };
    let (_, rx) = match engine.exec_start(&exec) {
        Ok(v) => v,
        Err(_) => {
            engine.forget_exec(&exec);
            return Ok(Next::Close);
        }
    };

    let client_reader = PrefixReader::new(early, PollUnixReader(client_r.try_clone()?));
    let exec_reader = StdoutReader::new(rx);
    let exec_writer = ExecStdinWriter { engine: engine.clone(), exec: exec.clone() };
    let _ = bridge_session(
        &session_headers,
        client_reader,
        w.try_clone()?,
        exec_reader,
        exec_writer,
        || {
            let _ = engine.close_stdin(&exec);
        },
        || {
            let _ = engine.close_stdin(&exec);
            let _ = client_r.shutdown(Shutdown::Both);
        },
    );
    let _ = engine.close_stdin(&exec);
    engine.forget_exec(&exec);
    Ok(Next::Close)
}

// --- I/O adapters ------------------------------------------------------------

struct PollUnixReader(UnixStream);

impl Read for PollUnixReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        api::wait_readable(&self.0);
        self.0.read(buf)
    }
}

struct PrefixReader<R> {
    prefix: Vec<u8>,
    pos: usize,
    inner: R,
}

impl<R> PrefixReader<R> {
    fn new(prefix: Vec<u8>, inner: R) -> PrefixReader<R> {
        PrefixReader { prefix, pos: 0, inner }
    }
}

impl<R: Read> Read for PrefixReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.prefix.len() {
            let n = out.len().min(self.prefix.len() - self.pos);
            out[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.inner.read(out)
    }
}

struct StdoutReader {
    rx: Receiver<(Stream, Vec<u8>)>,
    buf: Vec<u8>,
    pos: usize,
}

impl StdoutReader {
    fn new(rx: Receiver<(Stream, Vec<u8>)>) -> StdoutReader {
        StdoutReader { rx, buf: Vec::new(), pos: 0 }
    }
}

impl Read for StdoutReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.buf.len() {
            match self.rx.recv() {
                Ok((Stream::Stdout, data)) if !data.is_empty() => {
                    self.buf = data;
                    self.pos = 0;
                }
                Ok((Stream::Stdout, _)) => {}
                Ok((Stream::Stderr, data)) => {
                    let msg = String::from_utf8_lossy(&data);
                    let msg = msg.trim();
                    if !msg.is_empty() {
                        crate::diag::debug!("buildctl dial-stdio stderr", text = msg);
                    }
                }
                Err(_) => return Ok(0),
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

struct ExecStdinWriter {
    engine: Arc<Engine>,
    exec: String,
}

impl Write for ExecStdinWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for chunk in buf.chunks(EXEC_STDIN_CHUNK) {
            self.engine.input(&self.exec, chunk).map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("{e:?}")))?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// --- HTTP/2 framing ----------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct Frame {
    ty: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

fn read_frame(r: &mut impl Read) -> io::Result<Option<Frame>> {
    let mut head = [0u8; 9];
    let mut read = 0;
    while read < head.len() {
        match r.read(&mut head[read..])? {
            0 if read == 0 => return Ok(None),
            0 => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated HTTP/2 frame header")),
            n => read += n,
        }
    }
    let len = ((head[0] as usize) << 16) | ((head[1] as usize) << 8) | (head[2] as usize);
    if len > MAX_FRAME_LIMIT {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP/2 frame exceeds limit"));
    }
    let ty = head[3];
    let flags = head[4];
    let stream_id = u32::from_be_bytes([head[5] & 0x7f, head[6], head[7], head[8]]);
    let mut payload = Vec::with_capacity(len.min(INITIAL_FRAME_CAP));
    let got = r.take(len as u64).read_to_end(&mut payload)?;
    if got != len {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated HTTP/2 frame payload"));
    }
    Ok(Some(Frame { ty, flags, stream_id, payload }))
}

fn write_frame(w: &mut impl Write, f: &Frame) -> io::Result<()> {
    let len = f.payload.len();
    if len > 0x00ff_ffff {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "HTTP/2 frame too large"));
    }
    let mut head = [0u8; 9];
    head[0] = ((len >> 16) & 0xff) as u8;
    head[1] = ((len >> 8) & 0xff) as u8;
    head[2] = (len & 0xff) as u8;
    head[3] = f.ty;
    head[4] = f.flags;
    head[5..9].copy_from_slice(&(f.stream_id & 0x7fff_ffff).to_be_bytes());
    w.write_all(&head)?;
    w.write_all(&f.payload)?;
    w.flush()
}

fn send_goaway(w: &mut impl Write, debug: &str) -> io::Result<()> {
    let mut payload = Vec::with_capacity(8 + debug.len().min(256));
    payload.extend_from_slice(&0u32.to_be_bytes()); // last_stream_id = 0
    payload.extend_from_slice(&2u32.to_be_bytes()); // INTERNAL_ERROR
    payload.extend_from_slice(&debug.as_bytes()[..debug.len().min(256)]);
    write_frame(w, &Frame { ty: FRAME_GOAWAY, flags: 0, stream_id: 0, payload })
}

fn window_update_frame(stream_id: u32, inc: u32) -> Frame {
    Frame { ty: FRAME_WINDOW_UPDATE, flags: 0, stream_id, payload: (inc & 0x7fff_ffff).to_be_bytes().to_vec() }
}

fn unpad_data(flags: u8, payload: &[u8]) -> io::Result<&[u8]> {
    if flags & FLAG_PADDED == 0 {
        return Ok(payload);
    }
    if payload.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty padded DATA frame"));
    }
    let pad = payload[0] as usize;
    if 1 + pad > payload.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid DATA padding"));
    }
    Ok(&payload[1..payload.len() - pad])
}

fn headers_fragment(flags: u8, payload: &[u8]) -> io::Result<&[u8]> {
    let mut start = 0;
    let mut end = payload.len();
    if flags & FLAG_PADDED != 0 {
        if payload.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty padded HEADERS frame"));
        }
        let pad = payload[0] as usize;
        start += 1;
        if start + pad > end {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid HEADERS padding"));
        }
        end -= pad;
    }
    if flags & FLAG_PRIORITY != 0 {
        if start + 5 > end {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated HEADERS priority"));
        }
        start += 5;
    }
    Ok(&payload[start..end])
}

// --- `/grpc` HTTP/2 proxy ----------------------------------------------------

struct SolveRewrite {
    session: LoadSession,
    orig_name: String,
    resp_buf: Vec<u8>,
    resp_rewritten: bool,
}

struct GrpcShared {
    solve_streams: HashMap<u32, Option<SolveRewrite>>,
    server_max_frame_size: usize,
}

#[allow(clippy::too_many_arguments)]
fn proxy_grpc<CR, CW, SR, SW>(
    mut client_r: CR,
    client_w: CW,
    mut server_r: SR,
    server_w: SW,
    engine: &Arc<Engine>,
    host_net: bool,
    on_client_done: impl Fn() + Send + Sync,
    on_server_done: impl Fn() + Send + Sync,
) -> io::Result<()>
where
    CR: Read + Send,
    CW: Write + Send,
    SR: Read + Send,
    SW: Write + Send,
{
    let mut preface = [0u8; 24];
    client_r.read_exact(&mut preface)?;
    if &preface != H2_PREFACE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad HTTP/2 client preface"));
    }

    let client_w = Mutex::new(client_w);
    let server_w = Mutex::new(Some(server_w));
    {
        let mut guard = server_w.lock().unwrap_or_else(|e| e.into_inner());
        let sw = guard.as_mut().unwrap();
        sw.write_all(&preface)?;
        sw.flush()?;
    }
    let write_server_frame = |f: &Frame| -> io::Result<()> {
        let mut guard = server_w.lock().unwrap_or_else(|e| e.into_inner());
        let sw = guard.as_mut().ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "server stdin closed"))?;
        write_frame(sw, f)
    };

    let shared = Mutex::new(GrpcShared {
        solve_streams: HashMap::new(),
        server_max_frame_size: DEFAULT_MAX_FRAME_SIZE,
    });

    std::thread::scope(|scope| {
        let c2s = scope.spawn(|| -> io::Result<()> {
            let mut hpack = HpackDecoder::new();
            let mut header_stream: Option<u32> = None;
            let mut header_end_stream = false;
            let mut header_continuations = 0usize;
            let mut header_block = Vec::new();
            let mut solve_req_bufs: HashMap<u32, (Vec<u8>, usize)> = HashMap::new();
            let mut total_solve_req_bytes = 0usize;

            let res = (|| -> io::Result<()> {
                while let Some(frame) = read_frame(&mut client_r)? {
                    if header_stream.is_some() && frame.ty != FRAME_CONTINUATION {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "expected CONTINUATION frame"));
                    }
                    match frame.ty {
                        FRAME_HEADERS | FRAME_CONTINUATION => {
                            let frag = if frame.ty == FRAME_HEADERS {
                                header_stream = Some(frame.stream_id);
                                header_end_stream = frame.flags & FLAG_END_STREAM != 0;
                                header_continuations = 0;
                                header_block.clear();
                                headers_fragment(frame.flags, &frame.payload)?
                            } else {
                                if header_stream != Some(frame.stream_id) {
                                    return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected CONTINUATION"));
                                }
                                header_continuations += 1;
                                if header_continuations > MAX_CONTINUATION_FRAMES {
                                    return Err(io::Error::new(io::ErrorKind::InvalidData, "too many CONTINUATION frames"));
                                }
                                &frame.payload
                            };
                            if header_block.len().saturating_add(frag.len()) > MAX_HEADER_BLOCK {
                                return Err(io::Error::new(io::ErrorKind::InvalidData, "HPACK header block too large"));
                            }
                            header_block.extend_from_slice(frag);
                            if frame.flags & FLAG_END_HEADERS != 0 {
                                let headers = hpack.decode(&header_block)?;
                                if header_end_stream {
                                    if let Some((buf, _)) = solve_req_bufs.remove(&frame.stream_id) {
                                        total_solve_req_bytes = total_solve_req_bytes.saturating_sub(buf.len());
                                    }
                                    shared.lock().unwrap_or_else(|e| e.into_inner()).solve_streams.remove(&frame.stream_id);
                                } else if headers.iter().any(|(k, v)| k == b":path" && v == SOLVE_PATH.as_bytes()) {
                                    let active_solves = shared.lock().unwrap_or_else(|e| e.into_inner()).solve_streams.len();
                                    if !solve_req_bufs.contains_key(&frame.stream_id)
                                        && (solve_req_bufs.len() >= MAX_CONCURRENT_SOLVE_STREAMS || active_solves >= MAX_CONCURRENT_SOLVE_STREAMS)
                                    {
                                        return Err(io::Error::new(io::ErrorKind::InvalidData, "too many concurrent Solve streams"));
                                    }
                                    if let Some((old_buf, _)) = solve_req_bufs.insert(frame.stream_id, (Vec::new(), 0)) {
                                        total_solve_req_bytes = total_solve_req_bytes.saturating_sub(old_buf.len());
                                    }
                                    shared.lock().unwrap_or_else(|e| e.into_inner()).solve_streams.insert(frame.stream_id, None);
                                }
                                header_stream = None;
                                header_end_stream = false;
                                header_continuations = 0;
                                header_block.clear();
                            }
                            write_server_frame(&frame)?;
                        }
                        FRAME_DATA if solve_req_bufs.contains_key(&frame.stream_id) => {
                            let sid = frame.stream_id;
                            let wire_len = frame.payload.len();
                            let unpadded = unpad_data(frame.flags, &frame.payload)?;
                            let (buf, credited) = solve_req_bufs.get_mut(&sid).unwrap();
                            if buf.len().saturating_add(unpadded.len()) > MAX_SOLVE_REQ_BYTES
                                || total_solve_req_bytes.saturating_add(unpadded.len()) > MAX_TOTAL_SOLVE_REQ_BYTES
                            {
                                return Err(io::Error::new(io::ErrorKind::InvalidData, "SolveRequest exceeds limit"));
                            }
                            buf.extend_from_slice(unpadded);
                            total_solve_req_bytes += unpadded.len();
                            let end_stream = frame.flags & FLAG_END_STREAM != 0;
                            if !end_stream {
                                // Keep client send window open while buffering a multi-frame SolveRequest.
                                if wire_len > 0 {
                                    let inc = wire_len.min(0x7fff_ffff) as u32;
                                    *credited = credited.saturating_add(inc as usize);
                                    let mut cw = client_w.lock().unwrap_or_else(|e| e.into_inner());
                                    write_frame(&mut *cw, &window_update_frame(0, inc))?;
                                    write_frame(&mut *cw, &window_update_frame(sid, inc))?;
                                }
                                continue;
                            }
                            let (raw_grpc, credited) = solve_req_bufs.remove(&sid).unwrap();
                            total_solve_req_bytes = total_solve_req_bytes.saturating_sub(raw_grpc.len());
                            let orig_len = raw_grpc.len();
                            let (out_grpc, rewrite_state) = rewrite_grpc_solve_request(&raw_grpc, engine, host_net)?;
                            if let Some(rw) = rewrite_state {
                                shared.lock().unwrap_or_else(|e| e.into_inner()).solve_streams.insert(sid, Some(rw));
                            } else {
                                shared.lock().unwrap_or_else(|e| e.into_inner()).solve_streams.remove(&sid);
                            }
                            let max_frame = shared.lock().unwrap_or_else(|e| e.into_inner()).server_max_frame_size;
                            {
                                let mut guard = server_w.lock().unwrap_or_else(|e| e.into_inner());
                                let sw = guard.as_mut().ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "server stdin closed"))?;
                                write_data_frames(sw, sid, &out_grpc, max_frame, true)?;
                            }
                            // If rewriting shrank the payload beyond what was already
                            // credited on non-final frames, return the difference to the
                            // client's connection window so long-lived connections never drift.
                            let returned = out_grpc.len().saturating_add(credited);
                            if orig_len > returned {
                                let delta = (orig_len - returned).min(0x7fff_ffff) as u32;
                                write_frame(&mut *client_w.lock().unwrap_or_else(|e| e.into_inner()), &window_update_frame(0, delta))?;
                            }
                        }
                        FRAME_RST_STREAM => {
                            if let Some((buf, _)) = solve_req_bufs.remove(&frame.stream_id) {
                                total_solve_req_bytes = total_solve_req_bytes.saturating_sub(buf.len());
                            }
                            shared.lock().unwrap_or_else(|e| e.into_inner()).solve_streams.remove(&frame.stream_id);
                            write_server_frame(&frame)?;
                        }
                        _ => {
                            write_server_frame(&frame)?;
                        }
                    }
                }
                Ok(())
            })();
            if let Err(ref e) = res {
                let _ = send_goaway(&mut *client_w.lock().unwrap_or_else(|e| e.into_inner()), &e.to_string());
            }
            let _ = server_w.lock().unwrap_or_else(|e| e.into_inner()).take();
            on_client_done();
            res
        });

        let s2c = scope.spawn(|| -> io::Result<()> {
            let res = (|| -> io::Result<()> {
                while let Some(frame) = read_frame(&mut server_r)? {
                    match frame.ty {
                        FRAME_SETTINGS if frame.flags & FLAG_ACK == 0 => {
                            for chunk in frame.payload.as_chunks::<6>().0 {
                                let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                                let val = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
                                if id == SETTING_MAX_FRAME_SIZE && (DEFAULT_MAX_FRAME_SIZE..=0x00ff_ffff).contains(&(val as usize)) {
                                    shared.lock().unwrap_or_else(|e| e.into_inner()).server_max_frame_size = (val as usize).min(MAX_FRAME_LIMIT);
                                }
                            }
                            write_frame(&mut *client_w.lock().unwrap_or_else(|e| e.into_inner()), &frame)?;
                        }
                        FRAME_DATA => {
                            let sid = frame.stream_id;
                            let end_stream = frame.flags & FLAG_END_STREAM != 0;
                            let action = {
                                let mut st = shared.lock().unwrap_or_else(|e| e.into_inner());
                                if let Some(Some(rw)) = st.solve_streams.get_mut(&sid) {
                                    if rw.resp_rewritten {
                                        None
                                    } else {
                                        let data = unpad_data(frame.flags, &frame.payload)?;
                                        if rw.resp_buf.len() + data.len() > MAX_SOLVE_BODY {
                                            return Err(io::Error::new(io::ErrorKind::InvalidData, "SolveResponse exceeds limit"));
                                        }
                                        rw.resp_buf.extend_from_slice(data);
                                        let ready = end_stream || grpc_frame_complete(&rw.resp_buf);
                                        if ready {
                                            rw.resp_rewritten = true;
                                            let orig = std::mem::take(&mut rw.resp_buf);
                                            let rewritten = rewrite_grpc_solve_response(&orig, &rw.orig_name, rw.session.committed_digest().as_deref())?;
                                            Some(Some((orig.len(), rewritten, end_stream)))
                                        } else {
                                            Some(None)
                                        }
                                    }
                                } else {
                                    None
                                }
                            };
                            match action {
                                Some(None) => {}
                                Some(Some((orig_len, rewritten, end))) => {
                                    {
                                        let mut cw = client_w.lock().unwrap_or_else(|e| e.into_inner());
                                        write_data_frames(&mut *cw, sid, &rewritten, DEFAULT_MAX_FRAME_SIZE, end)?;
                                    }
                                    if orig_len > rewritten.len() {
                                        let delta = (orig_len - rewritten.len()).min(0x7fff_ffff) as u32;
                                        let _ = write_server_frame(&window_update_frame(0, delta));
                                    }
                                    if end {
                                        shared.lock().unwrap_or_else(|e| e.into_inner()).solve_streams.remove(&sid);
                                    }
                                }
                                None => {
                                    write_frame(&mut *client_w.lock().unwrap_or_else(|e| e.into_inner()), &frame)?;
                                }
                            }
                        }
                        FRAME_HEADERS if frame.flags & FLAG_END_STREAM != 0 => {
                            let sid = frame.stream_id;
                            let leftover = {
                                let mut st = shared.lock().unwrap_or_else(|e| e.into_inner());
                                st.solve_streams
                                    .remove(&sid)
                                    .flatten()
                                    .filter(|rw| !rw.resp_buf.is_empty())
                                    .map(|rw| rw.resp_buf)
                            };
                            let mut cw = client_w.lock().unwrap_or_else(|e| e.into_inner());
                            if let Some(buf) = leftover {
                                write_data_frames(&mut *cw, sid, &buf, DEFAULT_MAX_FRAME_SIZE, false)?;
                            }
                            write_frame(&mut *cw, &frame)?;
                        }
                        FRAME_RST_STREAM => {
                            shared.lock().unwrap_or_else(|e| e.into_inner()).solve_streams.remove(&frame.stream_id);
                            write_frame(&mut *client_w.lock().unwrap_or_else(|e| e.into_inner()), &frame)?;
                        }
                        _ => {
                            write_frame(&mut *client_w.lock().unwrap_or_else(|e| e.into_inner()), &frame)?;
                        }
                    }
                }
                Ok(())
            })();
            let _ = server_w.lock().unwrap_or_else(|e| e.into_inner()).take();
            on_client_done();
            on_server_done();
            res
        });

        let r1 = c2s.join().unwrap_or(Ok(()));
        let r2 = s2c.join().unwrap_or(Ok(()));
        r1.and(r2)
    })
}

fn write_data_frames(w: &mut impl Write, stream_id: u32, data: &[u8], max_frame: usize, end_stream: bool) -> io::Result<()> {
    let chunk_size = max_frame.max(1);
    if data.is_empty() {
        return write_frame(w, &Frame { ty: FRAME_DATA, flags: if end_stream { FLAG_END_STREAM } else { 0 }, stream_id, payload: Vec::new() });
    }
    let total = data.len();
    let mut off = 0;
    while off < total {
        let end = (off + chunk_size).min(total);
        let flags = if end_stream && end == total { FLAG_END_STREAM } else { 0 };
        write_frame(w, &Frame { ty: FRAME_DATA, flags, stream_id, payload: data[off..end].to_vec() })?;
        off = end;
    }
    Ok(())
}

fn grpc_frame_complete(buf: &[u8]) -> bool {
    if buf.len() < 5 {
        return false;
    }
    let msg_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    5usize.checked_add(msg_len).is_some_and(|need| buf.len() >= need)
}

// --- `/session` <-> `Control/Session` HTTP/2 bridge --------------------------

struct SessionFlow {
    peer_conn_window: i64,
    peer_stream_window: i64,
    peer_initial_window: u32,
    peer_max_frame_size: usize,
    closed: bool,
}

#[allow(clippy::too_many_arguments)]
fn bridge_session<CR, CW, SR, SW>(
    session_headers: &[(String, String)],
    mut client_r: CR,
    mut client_w: CW,
    mut server_r: SR,
    server_w: SW,
    on_client_abort: impl Fn() + Send + Sync,
    on_server_done: impl Fn() + Send + Sync,
) -> io::Result<()>
where
    CR: Read + Send,
    CW: Write + Send,
    SR: Read + Send,
    SW: Write + Send,
{
    const OUR_INITIAL_WINDOW: u32 = 1 << 20;
    const OUR_CONN_WINDOW_INC: u32 = (4 << 20) - 65_535;
    const WINDOW_REFILL_THRESHOLD: u32 = 32 * 1024;

    let server_w = Mutex::new(server_w);
    {
        let mut sw = server_w.lock().unwrap_or_else(|e| e.into_inner());
        sw.write_all(H2_PREFACE)?;
        // Client SETTINGS: raise initial stream window to 1 MiB.
        let mut settings = Vec::with_capacity(6);
        settings.extend_from_slice(&SETTING_INITIAL_WINDOW_SIZE.to_be_bytes());
        settings.extend_from_slice(&OUR_INITIAL_WINDOW.to_be_bytes());
        write_frame(&mut *sw, &Frame { ty: FRAME_SETTINGS, flags: 0, stream_id: 0, payload: settings })?;
        write_frame(&mut *sw, &window_update_frame(0, OUR_CONN_WINDOW_INC))?;

        // Open stream 1: POST /moby.buildkit.v1.Control/Session
        let mut hdrs: Vec<(&str, &str)> = vec![
            (":method", "POST"),
            (":scheme", "http"),
            (":path", SESSION_PATH),
            (":authority", "localhost"),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
        ];
        for (k, v) in session_headers {
            hdrs.push((k.as_str(), v.as_str()));
        }
        let block = hpack_encode_literal(&hdrs);
        let mut off = 0;
        let mut first = true;
        while off < block.len() || first {
            let end = (off + DEFAULT_MAX_FRAME_SIZE).min(block.len());
            let mut flags = 0;
            if end == block.len() {
                flags |= FLAG_END_HEADERS;
            }
            let ty = if first { FRAME_HEADERS } else { FRAME_CONTINUATION };
            write_frame(&mut *sw, &Frame { ty, flags, stream_id: 1, payload: block[off..end].to_vec() })?;
            off = end;
            first = false;
        }
    }

    let flow = (
        Mutex::new(SessionFlow {
            peer_conn_window: 65_535,
            peer_stream_window: 65_535,
            peer_initial_window: 65_535,
            peer_max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            closed: false,
        }),
        Condvar::new(),
    );

    std::thread::scope(|scope| {
        // Client raw h2c bytes -> stream 1 gRPC BytesMessage DATA frames.
        let c2s = scope.spawn(|| -> io::Result<()> {
            let mut buf = vec![0u8; 16 * 1024];
            let res = (|| -> io::Result<()> {
                loop {
                    let n = client_r.read(&mut buf)?;
                    if n == 0 {
                        let mut sw = server_w.lock().unwrap_or_else(|e| e.into_inner());
                        let _ = write_frame(&mut *sw, &Frame { ty: FRAME_DATA, flags: FLAG_END_STREAM, stream_id: 1, payload: Vec::new() });
                        break;
                    }
                    let grpc_msg = wrap_grpc_message(&encode_bytes_message(&buf[..n]));
                    let mut off = 0;
                    while off < grpc_msg.len() {
                        let allowed = {
                            let (mu, cv) = &flow;
                            let mut st = mu.lock().unwrap_or_else(|e| e.into_inner());
                            while !st.closed && (st.peer_conn_window <= 0 || st.peer_stream_window <= 0) {
                                st = cv.wait(st).unwrap_or_else(|e| e.into_inner());
                            }
                            if st.closed {
                                return Ok(());
                            }
                            let avail = st.peer_conn_window.min(st.peer_stream_window) as usize;
                            let take = (grpc_msg.len() - off).min(st.peer_max_frame_size).min(avail).max(1);
                            st.peer_conn_window -= take as i64;
                            st.peer_stream_window -= take as i64;
                            take
                        };
                        let mut sw = server_w.lock().unwrap_or_else(|e| e.into_inner());
                        write_frame(&mut *sw, &Frame { ty: FRAME_DATA, flags: 0, stream_id: 1, payload: grpc_msg[off..off + allowed].to_vec() })?;
                        off += allowed;
                    }
                }
                Ok(())
            })();
            if res.is_err() {
                // Cancel stream 1 and close the exec stdin so `s2c` never blocks
                // waiting for BuildKit after an abrupt client disconnect.
                let _ = write_frame(
                    &mut *server_w.lock().unwrap_or_else(|e| e.into_inner()),
                    &Frame { ty: FRAME_RST_STREAM, flags: 0, stream_id: 1, payload: 8u32.to_be_bytes().to_vec() },
                );
                on_client_abort();
            }
            res
        });

        // Stream 1 gRPC BytesMessage DATA frames -> client raw h2c bytes.
        let s2c = scope.spawn(|| -> io::Result<()> {
            let mut deframer = Vec::new();
            let mut unacked: u32 = 0;
            let res = (|| -> io::Result<()> {
                while let Some(frame) = read_frame(&mut server_r)? {
                    match frame.ty {
                        FRAME_SETTINGS if frame.flags & FLAG_ACK == 0 => {
                            {
                                let (mu, cv) = &flow;
                                let mut st = mu.lock().unwrap_or_else(|e| e.into_inner());
                                for chunk in frame.payload.as_chunks::<6>().0 {
                                    let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                                    let val = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
                                    match id {
                                        SETTING_INITIAL_WINDOW_SIZE => {
                                            let delta = val as i64 - st.peer_initial_window as i64;
                                            st.peer_initial_window = val;
                                            st.peer_stream_window += delta;
                                            cv.notify_all();
                                        }
                                        SETTING_MAX_FRAME_SIZE if (DEFAULT_MAX_FRAME_SIZE..=0x00ff_ffff).contains(&(val as usize)) => {
                                            st.peer_max_frame_size = (val as usize).min(MAX_FRAME_LIMIT);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            let mut sw = server_w.lock().unwrap_or_else(|e| e.into_inner());
                            write_frame(&mut *sw, &Frame { ty: FRAME_SETTINGS, flags: FLAG_ACK, stream_id: 0, payload: Vec::new() })?;
                        }
                        FRAME_PING if frame.flags & FLAG_ACK == 0 && frame.payload.len() == 8 => {
                            let mut sw = server_w.lock().unwrap_or_else(|e| e.into_inner());
                            write_frame(&mut *sw, &Frame { ty: FRAME_PING, flags: FLAG_ACK, stream_id: 0, payload: frame.payload })?;
                        }
                        FRAME_WINDOW_UPDATE if frame.payload.len() == 4 => {
                            let inc = (u32::from_be_bytes([frame.payload[0], frame.payload[1], frame.payload[2], frame.payload[3]]) & 0x7fff_ffff) as i64;
                            let (mu, cv) = &flow;
                            let mut st = mu.lock().unwrap_or_else(|e| e.into_inner());
                            if frame.stream_id == 0 {
                                st.peer_conn_window += inc;
                                cv.notify_all();
                            } else if frame.stream_id == 1 {
                                st.peer_stream_window += inc;
                                cv.notify_all();
                            }
                        }
                        FRAME_DATA if frame.stream_id == 1 => {
                            let wire_len = frame.payload.len() as u32;
                            unacked = unacked.saturating_add(wire_len);
                            if unacked >= WINDOW_REFILL_THRESHOLD {
                                let inc = unacked.min(0x7fff_ffff);
                                unacked -= inc;
                                let mut sw = server_w.lock().unwrap_or_else(|e| e.into_inner());
                                write_frame(&mut *sw, &window_update_frame(0, inc))?;
                                write_frame(&mut *sw, &window_update_frame(1, inc))?;
                            }
                            let data = unpad_data(frame.flags, &frame.payload)?;
                            if deframer.len().saturating_add(data.len()) > MAX_FRAME_LIMIT + 65_536 {
                                return Err(io::Error::new(io::ErrorKind::InvalidData, "session deframer buffer exceeded"));
                            }
                            deframer.extend_from_slice(data);
                            while deframer.len() >= 5 {
                                let compressed = deframer[0];
                                if compressed != 0 {
                                    return Err(io::Error::new(io::ErrorKind::InvalidData, "compressed session gRPC message unsupported"));
                                }
                                let msg_len = u32::from_be_bytes([deframer[1], deframer[2], deframer[3], deframer[4]]) as usize;
                                if msg_len > MAX_FRAME_LIMIT {
                                    return Err(io::Error::new(io::ErrorKind::InvalidData, "session gRPC message too large"));
                                }
                                let Some(total) = 5usize.checked_add(msg_len) else {
                                    return Err(io::Error::new(io::ErrorKind::InvalidData, "session gRPC message length overflow"));
                                };
                                if deframer.len() < total {
                                    break;
                                }
                                let raw = decode_bytes_message(&deframer[5..total])?;
                                deframer.drain(..total);
                                if !raw.is_empty() {
                                    client_w.write_all(&raw)?;
                                    client_w.flush()?;
                                }
                            }
                            if frame.flags & FLAG_END_STREAM != 0 {
                                break;
                            }
                        }
                        FRAME_HEADERS if frame.stream_id == 1 && frame.flags & FLAG_END_STREAM != 0 => break,
                        FRAME_RST_STREAM if frame.stream_id == 1 => break,
                        FRAME_GOAWAY => break,
                        _ => {}
                    }
                }
                Ok(())
            })();
            {
                let (mu, cv) = &flow;
                mu.lock().unwrap_or_else(|e| e.into_inner()).closed = true;
                cv.notify_all();
            }
            on_server_done();
            res
        });

        let r1 = c2s.join().unwrap_or(Ok(()));
        let r2 = s2c.join().unwrap_or(Ok(()));
        r1.and(r2)
    })
}

// --- SolveRequest / SolveResponse protobuf rewriting -------------------------

fn wrap_grpc_message(msg: &[u8]) -> Vec<u8> {
    wrap_grpc_frame(0, msg)
}

fn wrap_grpc_frame(flag: u8, msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + msg.len());
    out.push(flag);
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg);
    out
}

fn rewrite_grpc_solve_request(raw_grpc: &[u8], engine: &Arc<Engine>, host_net: bool) -> io::Result<(Vec<u8>, Option<SolveRewrite>)> {
    if raw_grpc.len() < 5 || raw_grpc[0] > 1 {
        return Ok((raw_grpc.to_vec(), None));
    }
    let flag = raw_grpc[0];
    let msg_len = u32::from_be_bytes([raw_grpc[1], raw_grpc[2], raw_grpc[3], raw_grpc[4]]) as usize;
    if 5usize.checked_add(msg_len) != Some(raw_grpc.len()) {
        return Ok((raw_grpc.to_vec(), None));
    }
    let payload = if flag == 1 {
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(&raw_grpc[5..])
            .take((MAX_SOLVE_REQ_BYTES + 1) as u64)
            .read_to_end(&mut decoded)?;
        if decoded.len() > MAX_SOLVE_REQ_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "decompressed SolveRequest exceeds limit"));
        }
        decoded
    } else {
        raw_grpc[5..].to_vec()
    };
    let (rewritten, state) = rewrite_solve_request(&payload, engine, host_net)?;
    let out = if flag == 1 {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&rewritten)?;
        wrap_grpc_frame(1, &enc.finish()?)
    } else {
        wrap_grpc_message(&rewritten)
    };
    Ok((out, state))
}

fn rewrite_grpc_solve_response(raw_grpc: &[u8], orig_name: &str, committed_digest: Option<&str>) -> io::Result<Vec<u8>> {
    if raw_grpc.len() < 5 || raw_grpc[0] > 1 {
        return Ok(raw_grpc.to_vec());
    }
    let flag = raw_grpc[0];
    let msg_len = u32::from_be_bytes([raw_grpc[1], raw_grpc[2], raw_grpc[3], raw_grpc[4]]) as usize;
    let Some(end) = 5usize.checked_add(msg_len).filter(|e| *e <= raw_grpc.len()) else {
        return Ok(raw_grpc.to_vec());
    };
    let payload = if flag == 1 {
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(&raw_grpc[5..end])
            .take((MAX_SOLVE_REQ_BYTES + 1) as u64)
            .read_to_end(&mut decoded)?;
        if decoded.len() > MAX_SOLVE_REQ_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "decompressed SolveResponse exceeds limit"));
        }
        decoded
    } else {
        raw_grpc[5..end].to_vec()
    };
    let rewritten = rewrite_solve_response(&payload, orig_name, committed_digest)?;
    let mut out = if flag == 1 {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&rewritten)?;
        wrap_grpc_frame(1, &enc.finish()?)
    } else {
        wrap_grpc_message(&rewritten)
    };
    out.extend_from_slice(&raw_grpc[end..]);
    Ok(out)
}

fn parse_go_bool(s: &str) -> bool {
    matches!(s, "1" | "t" | "T" | "TRUE" | "true" | "True")
}

/// Parses `name` from a `moby` exporter attribute (`a:1,b:2`) into Kiri's short
/// normalized image references.
fn parse_export_tags(name: &str) -> io::Result<Vec<String>> {
    let mut tags = Vec::new();
    let mut seen = HashSet::new();
    for part in name.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let r = Reference::parse(part).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid image name {part:?}: {e}")))?;
        if r.is_digest() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("invalid image tag {part:?}: digest reference")));
        }
        let short = r.short();
        if seen.insert(short.clone()) {
            tags.push(short);
        }
    }
    Ok(tags)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExporterSpec {
    ty: String,
    attrs: Vec<(String, String)>,
}

fn rewrite_exporter(
    mut exp: ExporterSpec,
    engine: &Arc<Engine>,
    host_net: bool,
    load_state: &mut Option<SolveRewrite>,
) -> io::Result<ExporterSpec> {
    if exp.ty != "moby" {
        return Ok(exp);
    }
    let push = exp.attrs.iter().rev().find(|(k, _)| k == "push").is_some_and(|(_, v)| parse_go_bool(v));
    if push {
        exp.ty = "image".to_owned();
        exp.attrs.retain(|(k, _)| !matches!(k.as_str(), "unpack" | "dangling-name-prefix" | "name-canonical" | "store"));
        return Ok(exp);
    }
    let orig_name = exp.attrs.iter().rev().find(|(k, _)| k == "name").map(|(_, v)| v.clone()).unwrap_or_default();
    let target_tags = parse_export_tags(&orig_name)?;
    let endpoint = mirror::upload_endpoint(engine, host_net)
        .ok_or_else(|| io::Error::other("Kiri's build image mirror is not running"))?;
    let mirror_ref = if let Some(existing) = load_state.as_mut() {
        existing.session.add_tags(target_tags);
        if !orig_name.is_empty() {
            if existing.orig_name.is_empty() {
                existing.orig_name = orig_name;
            } else if !existing.orig_name.split(',').any(|p| p == orig_name) {
                existing.orig_name.push(',');
                existing.orig_name.push_str(&orig_name);
            }
        }
        existing.session.repo_ref(&endpoint)
    } else {
        let session = LoadSession::new(engine.clone(), target_tags);
        let r = session.repo_ref(&endpoint);
        *load_state = Some(SolveRewrite { session, orig_name, resp_buf: Vec::new(), resp_rewritten: false });
        r
    };
    exp.ty = "image".to_owned();
    exp.attrs.retain(|(k, _)| {
        !matches!(
            k.as_str(),
            "name" | "push" | "registry.insecure" | "unpack" | "push-by-digest" | "dangling-name-prefix" | "name-canonical" | "store"
        )
    });
    exp.attrs.push(("name".to_owned(), mirror_ref));
    exp.attrs.push(("push".to_owned(), "true".to_owned()));
    Ok(exp)
}

/// Rewrites `moby` exporters inside a protobuf-encoded `SolveRequest`, keeping
/// every other field byte-for-byte untouched.
fn rewrite_solve_request(msg: &[u8], engine: &Arc<Engine>, host_net: bool) -> io::Result<(Vec<u8>, Option<SolveRewrite>)> {
    let fields = pb_split_fields(msg)?;
    let mut has_exporters = false;
    let mut has_moby = false;
    let mut dep_type = String::new();
    let mut dep_attrs: Vec<(String, String)> = Vec::new();
    let mut exporters: Vec<ExporterSpec> = Vec::new();

    for f in &fields {
        match (f.num, f.wire) {
            (3, 2) => {
                dep_type = String::from_utf8_lossy(f.val).into_owned();
                if dep_type == "moby" {
                    has_moby = true;
                }
            }
            (4, 2) => {
                dep_attrs.push(pb_decode_map_entry(f.val)?);
            }
            (13, 2) => {
                has_exporters = true;
                let exp = pb_decode_exporter(f.val)?;
                if exp.ty == "moby" {
                    has_moby = true;
                }
                exporters.push(exp);
            }
            _ => {}
        }
    }
    if !has_moby {
        return Ok((msg.to_vec(), None));
    }

    let mut load_state: Option<SolveRewrite> = None;
    let mut new_exporters = Vec::with_capacity(exporters.len());
    for exp in exporters {
        new_exporters.push(rewrite_exporter(exp, engine, host_net, &mut load_state)?);
    }
    let new_dep = if !dep_type.is_empty() {
        if has_exporters {
            new_exporters.first().cloned()
        } else {
            Some(rewrite_exporter(ExporterSpec { ty: dep_type, attrs: dep_attrs }, engine, host_net, &mut load_state)?)
        }
    } else {
        None
    };

    let mut out = Vec::with_capacity(msg.len() + 128);
    for f in &fields {
        if matches!(f.num, 3 | 4 | 13) {
            continue;
        }
        out.extend_from_slice(f.raw);
    }
    if let Some(dep) = &new_dep {
        pb_write_string(&mut out, 3, &dep.ty);
        for (k, v) in &dep.attrs {
            pb_write_map_entry(&mut out, 4, k, v);
        }
    }
    for exp in &new_exporters {
        let encoded = pb_encode_exporter(exp);
        pb_write_bytes(&mut out, 13, &encoded);
    }
    Ok((out, load_state))
}

/// Rewrites `SolveResponse.ExporterResponse` so `image.name` names the target
/// tag(s) (never the internal mirror URL) and `containerimage.digest` carries
/// the stored image's ID (`config_digest`).
fn rewrite_solve_response(msg: &[u8], orig_name: &str, committed_digest: Option<&str>) -> io::Result<Vec<u8>> {
    let fields = pb_split_fields(msg)?;
    let mut out = Vec::with_capacity(msg.len() + 64);
    let mut saw_digest = false;
    let mut saw_name = false;
    for f in &fields {
        if f.num == 1 && f.wire == 2 {
            let (k, v) = pb_decode_map_entry(f.val)?;
            if k == "image.name" {
                saw_name = true;
                if !orig_name.is_empty() {
                    pb_write_map_entry(&mut out, 1, &k, orig_name);
                }
            } else if k == "containerimage.digest" {
                saw_digest = true;
                let digest = committed_digest.unwrap_or(&v);
                pb_write_map_entry(&mut out, 1, &k, digest);
            } else {
                pb_write_map_entry(&mut out, 1, &k, &v);
            }
        } else {
            out.extend_from_slice(f.raw);
        }
    }
    if !saw_name && !orig_name.is_empty() {
        pb_write_map_entry(&mut out, 1, "image.name", orig_name);
    }
    if !saw_digest && let Some(digest) = committed_digest {
        pb_write_map_entry(&mut out, 1, "containerimage.digest", digest);
    }
    Ok(out)
}

// --- Minimal protobuf wire helpers -------------------------------------------

struct RawField<'a> {
    num: u32,
    wire: u8,
    raw: &'a [u8],
    val: &'a [u8],
}

fn pb_read_varint(buf: &[u8], pos: &mut usize) -> io::Result<u64> {
    let mut val = 0u64;
    let mut shift = 0u32;
    loop {
        let &b = buf.get(*pos).ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated protobuf varint"))?;
        *pos += 1;
        val |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(val);
        }
        shift += 7;
        if shift >= 64 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "protobuf varint overflow"));
        }
    }
}

fn pb_write_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

fn pb_split_fields(buf: &[u8]) -> io::Result<Vec<RawField<'_>>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        let start = pos;
        let tag = pb_read_varint(buf, &mut pos)?;
        let num = (tag >> 3) as u32;
        let wire = (tag & 7) as u8;
        if num == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid protobuf field 0"));
        }
        let val = match wire {
            0 => {
                let s = pos;
                let _ = pb_read_varint(buf, &mut pos)?;
                &buf[s..pos]
            }
            1 => {
                let end = pos.checked_add(8).filter(|e| *e <= buf.len()).ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated fixed64"))?;
                let v = &buf[pos..end];
                pos = end;
                v
            }
            2 => {
                let len = pb_read_varint(buf, &mut pos)? as usize;
                let end = pos.checked_add(len).filter(|e| *e <= buf.len()).ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated length-delimited field"))?;
                let v = &buf[pos..end];
                pos = end;
                v
            }
            5 => {
                let end = pos.checked_add(4).filter(|e| *e <= buf.len()).ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated fixed32"))?;
                let v = &buf[pos..end];
                pos = end;
                v
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unsupported protobuf wire type {wire}"))),
        };
        out.push(RawField { num, wire, raw: &buf[start..pos], val });
    }
    Ok(out)
}

fn pb_write_bytes(out: &mut Vec<u8>, field: u32, data: &[u8]) {
    pb_write_varint(out, (u64::from(field) << 3) | 2);
    pb_write_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

fn pb_write_string(out: &mut Vec<u8>, field: u32, s: &str) {
    if !s.is_empty() {
        pb_write_bytes(out, field, s.as_bytes());
    }
}

fn pb_write_map_entry(out: &mut Vec<u8>, field: u32, k: &str, v: &str) {
    let mut entry = Vec::with_capacity(k.len() + v.len() + 8);
    pb_write_string(&mut entry, 1, k);
    pb_write_string(&mut entry, 2, v);
    pb_write_bytes(out, field, &entry);
}

fn pb_decode_map_entry(buf: &[u8]) -> io::Result<(String, String)> {
    let mut k = String::new();
    let mut v = String::new();
    for f in pb_split_fields(buf)? {
        match (f.num, f.wire) {
            (1, 2) => k = String::from_utf8_lossy(f.val).into_owned(),
            (2, 2) => v = String::from_utf8_lossy(f.val).into_owned(),
            _ => {}
        }
    }
    Ok((k, v))
}

fn pb_decode_exporter(buf: &[u8]) -> io::Result<ExporterSpec> {
    let mut ty = String::new();
    let mut attrs = Vec::new();
    for f in pb_split_fields(buf)? {
        match (f.num, f.wire) {
            (1, 2) => ty = String::from_utf8_lossy(f.val).into_owned(),
            (2, 2) => attrs.push(pb_decode_map_entry(f.val)?),
            _ => {}
        }
    }
    Ok(ExporterSpec { ty, attrs })
}

fn pb_encode_exporter(exp: &ExporterSpec) -> Vec<u8> {
    let mut out = Vec::new();
    pb_write_string(&mut out, 1, &exp.ty);
    for (k, v) in &exp.attrs {
        pb_write_map_entry(&mut out, 2, k, v);
    }
    out
}

fn encode_bytes_message(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 8);
    if !data.is_empty() {
        pb_write_bytes(&mut out, 1, data);
    }
    out
}

fn decode_bytes_message(buf: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    for f in pb_split_fields(buf)? {
        if f.num == 1 && f.wire == 2 {
            out.extend_from_slice(f.val);
        }
    }
    Ok(out)
}

// --- RFC 7541 HPACK encoder (literal) & passive decoder ----------------------

fn hpack_encode_int(out: &mut Vec<u8>, prefix_bits: u8, first_mask: u8, value: usize) {
    let max_prefix = (1usize << prefix_bits) - 1;
    if value < max_prefix {
        out.push(first_mask | (value as u8));
        return;
    }
    out.push(first_mask | (max_prefix as u8));
    let mut rem = value - max_prefix;
    while rem >= 128 {
        out.push(((rem & 0x7f) as u8) | 0x80);
        rem >>= 7;
    }
    out.push(rem as u8);
}

fn hpack_encode_literal(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(k, v) in headers {
        // Literal Header Field without Indexing — New Name (RFC 7541 §6.2.2).
        out.push(0x00);
        hpack_encode_int(&mut out, 7, 0x00, k.len());
        out.extend_from_slice(k.as_bytes());
        hpack_encode_int(&mut out, 7, 0x00, v.len());
        out.extend_from_slice(v.as_bytes());
    }
    out
}

const STATIC_TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// RFC 7541 Appendix B canonical Huffman code bit lengths (symbols 0..=255).
const HUFFMAN_LEN: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];

#[derive(Clone, Copy)]
struct HuffNode {
    child: [u16; 2],
    sym: Option<u8>,
}

fn huffman_trie() -> &'static [HuffNode] {
    static TRIE: OnceLock<Vec<HuffNode>> = OnceLock::new();
    TRIE.get_or_init(|| {
        let mut syms: Vec<(u8, u8)> = HUFFMAN_LEN.iter().enumerate().map(|(s, &len)| (len, s as u8)).collect();
        syms.sort_unstable();
        let mut nodes = vec![HuffNode { child: [0, 0], sym: None }];
        let mut code = 0u32;
        let mut prev_len = 0u8;
        for (len, sym) in syms {
            if prev_len != 0 {
                code = (code + 1) << (len - prev_len);
            }
            prev_len = len;
            let mut cur = 0usize;
            for bit_i in (0..len).rev() {
                let bit = ((code >> bit_i) & 1) as usize;
                let next = nodes[cur].child[bit] as usize;
                if next == 0 {
                    let id = nodes.len() as u16;
                    nodes.push(HuffNode { child: [0, 0], sym: None });
                    nodes[cur].child[bit] = id;
                    cur = id as usize;
                } else {
                    cur = next;
                }
            }
            nodes[cur].sym = Some(sym);
        }
        nodes
    })
}

fn huffman_decode(src: &[u8]) -> io::Result<Vec<u8>> {
    let trie = huffman_trie();
    let mut out = Vec::with_capacity(src.len().min(INITIAL_FRAME_CAP));
    let mut cur = 0usize;
    let mut pending_bits = 0u8;
    let mut all_ones = true;
    for &byte in src {
        for bit_i in (0..8).rev() {
            let bit = ((byte >> bit_i) & 1) as usize;
            let next = trie[cur].child[bit] as usize;
            if next == 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid HPACK Huffman code"));
            }
            cur = next;
            pending_bits += 1;
            all_ones &= bit == 1;
            if let Some(sym) = trie[cur].sym {
                if out.len() >= MAX_DECODED_HEADERS {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "HPACK Huffman string too large"));
                }
                out.push(sym);
                cur = 0;
                pending_bits = 0;
                all_ones = true;
            }
        }
    }
    if cur != 0 && (pending_bits > 7 || !all_ones) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid HPACK Huffman padding"));
    }
    Ok(out)
}

struct HpackDecoder {
    dynamic: VecDeque<(Vec<u8>, Vec<u8>)>,
    size: usize,
    max_size: usize,
}

impl HpackDecoder {
    fn new() -> HpackDecoder {
        HpackDecoder { dynamic: VecDeque::new(), size: 0, max_size: 4096 }
    }

    fn set_max_size(&mut self, max_size: usize) -> io::Result<()> {
        if max_size > MAX_HPACK_TABLE_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HPACK dynamic table size exceeds limit"));
        }
        self.max_size = max_size;
        while self.size > self.max_size {
            if let Some((k, v)) = self.dynamic.pop_back() {
                self.size = self.size.saturating_sub(k.len() + v.len() + 32);
            } else {
                break;
            }
        }
        Ok(())
    }

    fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) {
        let entry_size = name.len().saturating_add(value.len()).saturating_add(32);
        if entry_size > self.max_size {
            self.dynamic.clear();
            self.size = 0;
            return;
        }
        while self.size + entry_size > self.max_size {
            if let Some((k, v)) = self.dynamic.pop_back() {
                self.size = self.size.saturating_sub(k.len() + v.len() + 32);
            } else {
                break;
            }
        }
        self.size += entry_size;
        self.dynamic.push_front((name, value));
    }

    fn lookup(&self, idx: usize) -> io::Result<(Vec<u8>, Vec<u8>)> {
        if idx == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HPACK index 0"));
        }
        if idx <= STATIC_TABLE.len() {
            let (k, v) = STATIC_TABLE[idx - 1];
            return Ok((k.as_bytes().to_vec(), v.as_bytes().to_vec()));
        }
        let dyn_idx = idx - STATIC_TABLE.len() - 1;
        self.dynamic
            .get(dyn_idx)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("HPACK index {idx} out of range")))
    }

    fn decode(&mut self, block: &[u8]) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut pos = 0;
        let mut out = Vec::new();
        let mut decoded_bytes = 0usize;
        let mut push = |out: &mut Vec<(Vec<u8>, Vec<u8>)>, k: Vec<u8>, v: Vec<u8>| -> io::Result<()> {
            decoded_bytes = decoded_bytes.saturating_add(k.len()).saturating_add(v.len()).saturating_add(32);
            if decoded_bytes > MAX_DECODED_HEADERS {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "decoded HPACK headers exceed limit"));
            }
            out.push((k, v));
            Ok(())
        };
        while pos < block.len() {
            let b = block[pos];
            if b & 0x80 != 0 {
                let idx = decode_int(block, &mut pos, 7)?;
                let (k, v) = self.lookup(idx)?;
                push(&mut out, k, v)?;
            } else if b & 0xc0 == 0x40 {
                let idx = decode_int(block, &mut pos, 6)?;
                let name = if idx == 0 { decode_str(block, &mut pos)? } else { self.lookup(idx)?.0 };
                let val = decode_str(block, &mut pos)?;
                self.insert(name.clone(), val.clone());
                push(&mut out, name, val)?;
            } else if b & 0xe0 == 0x20 {
                let new_max = decode_int(block, &mut pos, 5)?;
                self.set_max_size(new_max)?;
            } else {
                let idx = decode_int(block, &mut pos, 4)?;
                let name = if idx == 0 { decode_str(block, &mut pos)? } else { self.lookup(idx)?.0 };
                let val = decode_str(block, &mut pos)?;
                push(&mut out, name, val)?;
            }
        }
        Ok(out)
    }
}

fn decode_int(buf: &[u8], pos: &mut usize, prefix_bits: u8) -> io::Result<usize> {
    let &first = buf.get(*pos).ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated HPACK int"))?;
    *pos += 1;
    let mask = (1u8 << prefix_bits) - 1;
    let mut val = usize::from(first & mask);
    if val < usize::from(mask) {
        return Ok(val);
    }
    let mut shift = 0u32;
    loop {
        let &b = buf.get(*pos).ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated HPACK int"))?;
        *pos += 1;
        let add = usize::from(b & 0x7f)
            .checked_shl(shift)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HPACK int overflow"))?;
        val = val.checked_add(add).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HPACK int overflow"))?;
        if b & 0x80 == 0 {
            return Ok(val);
        }
        shift += 7;
        if shift >= usize::BITS {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HPACK int overflow"));
        }
    }
}

fn decode_str(buf: &[u8], pos: &mut usize) -> io::Result<Vec<u8>> {
    let &first = buf.get(*pos).ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated HPACK string"))?;
    let huffman = first & 0x80 != 0;
    let len = decode_int(buf, pos, 7)?;
    let end = pos.checked_add(len).filter(|e| *e <= buf.len()).ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated HPACK string bytes"))?;
    let raw = &buf[*pos..end];
    *pos = end;
    if huffman { huffman_decode(raw) } else { Ok(raw.to_vec()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn test_engine(tag: &str) -> (Arc<Engine>, std::path::PathBuf) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("kiri-grpc-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = kiri_image::Store::open(&dir).unwrap();
        let engine = Engine::boot(store).unwrap();
        mirror::start(&engine);
        (engine, dir)
    }

    #[test]
    fn hpack_decodes_rfc7541_huffman_and_dynamic_table() {
        // RFC 7541 Appendix C.4.1: Huffman-encoded `:authority: www.example.com`,
        // indexed `:method: GET`, `:scheme: http`, `:path: /`.
        let block1: &[u8] = &[
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        let mut dec = HpackDecoder::new();
        let h1 = dec.decode(block1).unwrap();
        assert_eq!(
            h1,
            vec![
                (b":method".to_vec(), b"GET".to_vec()),
                (b":scheme".to_vec(), b"http".to_vec()),
                (b":path".to_vec(), b"/".to_vec()),
                (b":authority".to_vec(), b"www.example.com".to_vec()),
            ]
        );
        // RFC 7541 Appendix C.4.2: reuses dynamic entry 62 (`:authority: www.example.com`)
        // and adds `cache-control: no-cache`.
        let block2: &[u8] = &[0x82, 0x86, 0x84, 0xbe, 0x58, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];
        let h2 = dec.decode(block2).unwrap();
        assert_eq!(h2[3], (b":authority".to_vec(), b"www.example.com".to_vec()));
        assert_eq!(h2[4], (b"cache-control".to_vec(), b"no-cache".to_vec()));
        // Round-trip our literal encoder for gRPC paths.
        let enc = hpack_encode_literal(&[(":method", "POST"), (":path", SOLVE_PATH), ("content-type", "application/grpc")]);
        let h3 = dec.decode(&enc).unwrap();
        assert_eq!(h3[1], (b":path".to_vec(), SOLVE_PATH.as_bytes().to_vec()));
    }

    #[test]
    fn rewrites_moby_solve_request_and_preserves_other_fields() {
        let (engine, dir) = test_engine("rewrite");

        // Build a SolveRequest with Ref (1), ExporterDeprecated (3),
        // ExporterAttrsDeprecated (4), Session (5), Frontend (6), Exporters (13).
        let mut req = Vec::new();
        pb_write_string(&mut req, 1, "ref-abc");
        pb_write_string(&mut req, 3, "moby");
        pb_write_map_entry(&mut req, 4, "name", "docker.io/library/probe-incontainer:latest");
        pb_write_map_entry(&mut req, 4, "unpack", "true");
        pb_write_string(&mut req, 5, "sess-123");
        pb_write_string(&mut req, 6, "dockerfile.v0");
        let exp = pb_encode_exporter(&ExporterSpec {
            ty: "moby".into(),
            attrs: vec![
                ("name".into(), "docker.io/library/probe-incontainer:latest".into()),
                ("unpack".into(), "true".into()),
                ("annotation.foo".into(), "bar".into()),
            ],
        });
        pb_write_bytes(&mut req, 13, &exp);

        let (rewritten, state) = rewrite_solve_request(&req, &engine, false).unwrap();
        let state = state.expect("moby exporter triggers local LoadSession");
        assert_eq!(state.orig_name, "docker.io/library/probe-incontainer:latest");

        let fields = pb_split_fields(&rewritten).unwrap();
        // Non-exporter fields stayed intact.
        assert!(fields.iter().any(|f| f.num == 1 && f.val == b"ref-abc"));
        assert!(fields.iter().any(|f| f.num == 5 && f.val == b"sess-123"));
        assert!(fields.iter().any(|f| f.num == 6 && f.val == b"dockerfile.v0"));
        // Exporters[0] became image + push=true + mirror URL, without moby-only unpack.
        let exp_field = fields.iter().find(|f| f.num == 13).unwrap();
        let decoded = pb_decode_exporter(exp_field.val).unwrap();
        assert_eq!(decoded.ty, "image");
        assert!(decoded.attrs.iter().any(|(k, v)| k == "push" && v == "true"));
        assert!(!decoded.attrs.iter().any(|(k, _)| k == "registry.insecure"));
        assert!(decoded.attrs.iter().any(|(k, v)| k == "annotation.foo" && v == "bar"));
        assert!(!decoded.attrs.iter().any(|(k, _)| k == "unpack"));
        let target_name = decoded.attrs.iter().find(|(k, _)| k == "name").map(|(_, v)| v.as_str()).unwrap();
        assert!(target_name.contains("/load/") && target_name.ends_with("/image:out"), "{target_name}");

        // SolveResponse rewrite restores original name and swaps digest to config_digest.
        let mut resp = Vec::new();
        pb_write_map_entry(&mut resp, 1, "image.name", target_name);
        pb_write_map_entry(&mut resp, 1, "containerimage.digest", "sha256:manifest000");
        pb_write_map_entry(&mut resp, 1, "containerimage.config.digest", "sha256:config111");
        let fixed = rewrite_solve_response(&resp, &state.orig_name, Some("sha256:config111")).unwrap();
        let resp_map: HashMap<String, String> = pb_split_fields(&fixed)
            .unwrap()
            .into_iter()
            .filter(|f| f.num == 1)
            .map(|f| pb_decode_map_entry(f.val).unwrap())
            .collect();
        assert_eq!(resp_map.get("image.name").map(String::as_str), Some("docker.io/library/probe-incontainer:latest"));
        assert_eq!(resp_map.get("containerimage.digest").map(String::as_str), Some("sha256:config111"));
        assert_eq!(resp_map.get("containerimage.config.digest").map(String::as_str), Some("sha256:config111"));

        // Moby exporter with push=true rewrites to image exporter keeping the real registry target.
        let mut push_req = Vec::new();
        let push_exp = pb_encode_exporter(&ExporterSpec {
            ty: "moby".into(),
            attrs: vec![("name".into(), "localhost:5000/app:1".into()), ("push".into(), "true".into())],
        });
        pb_write_bytes(&mut push_req, 13, &push_exp);
        let (push_out, push_state) = rewrite_solve_request(&push_req, &engine, false).unwrap();
        assert!(push_state.is_none(), "direct push does not register a local LoadSession");
        let push_decoded = pb_decode_exporter(pb_split_fields(&push_out).unwrap().iter().find(|f| f.num == 13).unwrap().val).unwrap();
        assert_eq!(push_decoded.ty, "image");
        assert!(push_decoded.attrs.iter().any(|(k, v)| k == "name" && v == "localhost:5000/app:1"));
        assert!(push_decoded.attrs.iter().any(|(k, v)| k == "push" && v == "true"));

        // Non-moby exporter (`local`) passes through untouched.
        let mut local_req = Vec::new();
        let local_exp = pb_encode_exporter(&ExporterSpec { ty: "local".into(), attrs: vec![("dest".into(), "/out".into())] });
        pb_write_bytes(&mut local_req, 13, &local_exp);
        let (local_out, local_state) = rewrite_solve_request(&local_req, &engine, false).unwrap();
        assert!(local_state.is_none());
        assert_eq!(local_out, local_req);

        drop(state);
        drop(engine);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_grpc_rewrites_solve_stream_over_http2() {
        let (engine, dir) = test_engine("proxy");

        // Build client -> proxy byte stream: preface + HEADERS(/Control/Solve) + DATA(SolveRequest).
        let mut solve_req = Vec::new();
        pb_write_string(&mut solve_req, 1, "r1");
        pb_write_bytes(
            &mut solve_req,
            13,
            &pb_encode_exporter(&ExporterSpec {
                ty: "moby".into(),
                attrs: vec![("name".into(), "docker.io/library/demo:v1".into())],
            }),
        );
        let mut c2p = Vec::new();
        c2p.extend_from_slice(H2_PREFACE);
        write_frame(&mut c2p, &Frame { ty: FRAME_SETTINGS, flags: 0, stream_id: 0, payload: Vec::new() }).unwrap();
        let hdr = hpack_encode_literal(&[(":method", "POST"), (":path", SOLVE_PATH), ("content-type", "application/grpc")]);
        write_frame(&mut c2p, &Frame { ty: FRAME_HEADERS, flags: FLAG_END_HEADERS, stream_id: 1, payload: hdr }).unwrap();
        write_frame(&mut c2p, &Frame { ty: FRAME_DATA, flags: FLAG_END_STREAM, stream_id: 1, payload: wrap_grpc_message(&solve_req) }).unwrap();

        // Pair sockets so fake buildkitd receives the rewritten SolveRequest, then replies SolveResponse.
        let (mut fake_srv_r, fake_srv_w) = UnixStream::pair().unwrap();
        let (mut client_w_recv, client_w_send) = UnixStream::pair().unwrap();
        let (fake_reply_w, fake_reply_r) = UnixStream::pair().unwrap();

        let fake_buildkit = std::thread::spawn(move || {
            let mut pref = [0u8; 24];
            fake_srv_r.read_exact(&mut pref).unwrap();
            assert_eq!(&pref, H2_PREFACE);
            let mut got_req = Vec::new();
            while let Some(f) = read_frame(&mut fake_srv_r).unwrap() {
                if f.ty == FRAME_DATA && f.stream_id == 1 {
                    got_req.extend_from_slice(&f.payload);
                    if f.flags & FLAG_END_STREAM != 0 {
                        break;
                    }
                }
            }
            // Verify the proxy rewrote the exporter to image + push=true + mirror URL.
            assert_eq!(got_req[0], 0);
            let fields = pb_split_fields(&got_req[5..]).unwrap();
            let exp = pb_decode_exporter(fields.iter().find(|f| f.num == 13).unwrap().val).unwrap();
            assert_eq!(exp.ty, "image");
            let mirror_name = exp.attrs.iter().find(|(k, _)| k == "name").unwrap().1.clone();
            assert!(mirror_name.contains("/load/") && mirror_name.ends_with("/image:out"));

            // Reply with SolveResponse carrying the internal mirror name.
            let mut resp_pb = Vec::new();
            pb_write_map_entry(&mut resp_pb, 1, "image.name", &mirror_name);
            pb_write_map_entry(&mut resp_pb, 1, "containerimage.digest", "sha256:manifest");
            let mut w = fake_reply_w;
            write_frame(&mut w, &Frame { ty: FRAME_HEADERS, flags: FLAG_END_HEADERS, stream_id: 1, payload: hpack_encode_literal(&[(":status", "200")]) }).unwrap();
            write_frame(&mut w, &Frame { ty: FRAME_DATA, flags: 0, stream_id: 1, payload: wrap_grpc_message(&resp_pb) }).unwrap();
            write_frame(&mut w, &Frame { ty: FRAME_HEADERS, flags: FLAG_END_HEADERS | FLAG_END_STREAM, stream_id: 1, payload: hpack_encode_literal(&[("grpc-status", "0")]) }).unwrap();
            let _ = w.shutdown(Shutdown::Write);
        });

        let (mut cli_send_req, cli_recv_req) = UnixStream::pair().unwrap();
        let client_writer = std::thread::spawn(move || {
            cli_send_req.write_all(&c2p).unwrap();
            // Keep the connection open until the proxy shuts down or the test ends.
            let mut drain = [0u8; 64];
            let _ = cli_send_req.read(&mut drain);
        });
        let fake_srv_w_done = fake_srv_w.try_clone().unwrap();
        let client_w_done = client_w_send.try_clone().unwrap();
        let cli_recv_req_done = cli_recv_req.try_clone().unwrap();
        proxy_grpc(
            cli_recv_req,
            client_w_send,
            fake_reply_r,
            fake_srv_w,
            &engine,
            false,
            move || {
                let _ = fake_srv_w_done.shutdown(Shutdown::Write);
            },
            move || {
                let _ = client_w_done.shutdown(Shutdown::Write);
                let _ = cli_recv_req_done.shutdown(Shutdown::Both);
            },
        )
        .unwrap();
        fake_buildkit.join().unwrap();
        client_writer.join().unwrap();

        // Read client-visible response frames and confirm mirror URL was replaced with original name.
        let mut resp_data = Vec::new();
        while let Some(f) = read_frame(&mut client_w_recv).unwrap() {
            if f.ty == FRAME_DATA && f.stream_id == 1 {
                resp_data.extend_from_slice(&f.payload);
            }
        }
        let resp_map: HashMap<String, String> = pb_split_fields(&resp_data[5..])
            .unwrap()
            .into_iter()
            .filter(|f| f.num == 1)
            .map(|f| pb_decode_map_entry(f.val).unwrap())
            .collect();
        assert_eq!(resp_map.get("image.name").map(String::as_str), Some("docker.io/library/demo:v1"));

        drop(engine);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bridge_session_wraps_and_unwraps_bytes_messages() {
        let (mut srv_r, srv_w) = UnixStream::pair().unwrap();
        let (srv_reply_w, srv_reply_r) = UnixStream::pair().unwrap();
        let (mut cli_recv, cli_send) = UnixStream::pair().unwrap();

        let fake_bk = std::thread::spawn(move || {
            let mut pref = [0u8; 24];
            srv_r.read_exact(&mut pref).unwrap();
            assert_eq!(&pref, H2_PREFACE);
            let mut dec = HpackDecoder::new();
            let mut saw_headers = Vec::new();
            let mut got_payload = Vec::new();
            while let Some(f) = read_frame(&mut srv_r).unwrap() {
                match f.ty {
                    FRAME_HEADERS if f.stream_id == 1 => {
                        saw_headers = dec.decode(&f.payload).unwrap();
                    }
                    FRAME_DATA if f.stream_id == 1 => {
                        if f.payload.len() >= 5 {
                            got_payload.extend_from_slice(&decode_bytes_message(&f.payload[5..]).unwrap());
                        }
                        if f.flags & FLAG_END_STREAM != 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            assert!(saw_headers.iter().any(|(k, v)| k == b":path" && v == SESSION_PATH.as_bytes()));
            assert!(saw_headers.iter().any(|(k, v)| k == b"x-docker-expose-session-uuid" && v == b"sess-42"));
            assert_eq!(
                saw_headers.iter().filter(|(k, _)| k == b"x-docker-expose-session-grpc-method").count(),
                2,
                "repeated session method headers must be preserved"
            );
            assert_eq!(got_payload, b"hello-from-client");

            let mut w = srv_reply_w;
            write_frame(&mut w, &Frame { ty: FRAME_SETTINGS, flags: 0, stream_id: 0, payload: Vec::new() }).unwrap();
            let msg = wrap_grpc_message(&encode_bytes_message(b"hello-from-buildkit"));
            write_frame(&mut w, &Frame { ty: FRAME_DATA, flags: FLAG_END_STREAM, stream_id: 1, payload: msg }).unwrap();
            let _ = w.shutdown(Shutdown::Write);
            // Keep reading until peer finishes writing SETTINGS ACK.
            while read_frame(&mut srv_r).ok().flatten().is_some() {}
        });

        let headers = vec![
            ("x-docker-expose-session-uuid".to_owned(), "sess-42".to_owned()),
            ("x-docker-expose-session-grpc-method".to_owned(), "/moby.filesync.v1.Auth/Credentials".to_owned()),
            ("x-docker-expose-session-grpc-method".to_owned(), "/fsutil.filesync.FileSync/DiffCopy".to_owned()),
        ];
        let cli_send_done = cli_send.try_clone().unwrap();
        bridge_session(
            &headers,
            Cursor::new(b"hello-from-client".to_vec()),
            cli_send,
            srv_reply_r,
            srv_w,
            || {},
            move || {
                let _ = cli_send_done.shutdown(Shutdown::Write);
            },
        )
        .unwrap();
        fake_bk.join().unwrap();

        let mut received = Vec::new();
        cli_recv.read_to_end(&mut received).unwrap();
        assert_eq!(received, b"hello-from-buildkit");
    }

    #[test]
    fn rewrites_untagged_and_multi_tag_field13_only_solve_requests() {
        let (engine, dir) = test_engine("edges");

        // Modern buildx sends only Exporters (field 13) with no deprecated fields 3/4.
        // Untagged build (`docker build .`) omits `name` and sets `dangling-name-prefix`.
        let mut untagged = Vec::new();
        pb_write_string(&mut untagged, 1, "ref-untagged");
        pb_write_map_entry(&mut untagged, 7, "target", "builder");
        pb_write_map_entry(&mut untagged, 7, "build-arg:FOO", "bar");
        pb_write_bytes(
            &mut untagged,
            13,
            &pb_encode_exporter(&ExporterSpec {
                ty: "moby".into(),
                attrs: vec![
                    ("unpack".into(), "true".into()),
                    ("dangling-name-prefix".into(), "moby-dangling".into()),
                ],
            }),
        );
        let (out, state) = rewrite_solve_request(&untagged, &engine, false).unwrap();
        let state = state.expect("untagged moby triggers LoadSession");
        assert!(state.orig_name.is_empty());
        let fields = pb_split_fields(&out).unwrap();
        assert!(!fields.iter().any(|f| matches!(f.num, 3 | 4)), "must not synthesize deprecated fields when absent");
        assert!(fields.iter().any(|f| f.num == 7 && pb_decode_map_entry(f.val).unwrap() == ("target".into(), "builder".into())));
        assert!(fields.iter().any(|f| f.num == 7 && pb_decode_map_entry(f.val).unwrap() == ("build-arg:FOO".into(), "bar".into())));
        let exp = pb_decode_exporter(fields.iter().find(|f| f.num == 13).unwrap().val).unwrap();
        assert_eq!(exp.ty, "image");
        assert!(!exp.attrs.iter().any(|(k, _)| k == "dangling-name-prefix" || k == "unpack"));
        // Untagged SolveResponse strips internal mirror `image.name` and returns committed config_digest.
        let mut resp = Vec::new();
        pb_write_map_entry(&mut resp, 1, "image.name", &exp.attrs.iter().find(|(k, _)| k == "name").unwrap().1);
        pb_write_map_entry(&mut resp, 1, "containerimage.digest", "sha256:manifest");
        let fixed = rewrite_solve_response(&resp, &state.orig_name, Some("sha256:cfg999")).unwrap();
        let map: HashMap<String, String> = pb_split_fields(&fixed).unwrap().into_iter().filter(|f| f.num == 1).map(|f| pb_decode_map_entry(f.val).unwrap()).collect();
        assert!(!map.contains_key("image.name"), "untagged response must not leak mirror URL: {map:?}");
        assert_eq!(map.get("containerimage.digest").map(String::as_str), Some("sha256:cfg999"));
        drop(state);

        // Multi-tag (`-t probe-a:1 -t probe-b:2`) preserves all tags and rejects digest refs.
        assert_eq!(
            parse_export_tags("docker.io/library/probe-a:1, docker.io/library/probe-b:2, probe-a:1").unwrap(),
            vec!["probe-a:1".to_owned(), "probe-b:2".to_owned()]
        );
        assert!(parse_export_tags("alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000").is_err());

        drop(engine);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enforces_frame_and_hpack_bounds() {
        // Oversized HTTP/2 frame header (> MAX_FRAME_LIMIT) is rejected before reading payload.
        let huge_len = (MAX_FRAME_LIMIT + 1) as u32;
        let head = [
            ((huge_len >> 16) & 0xff) as u8,
            ((huge_len >> 8) & 0xff) as u8,
            (huge_len & 0xff) as u8,
            FRAME_DATA,
            0,
            0,
            0,
            0,
            1,
        ];
        assert_eq!(read_frame(&mut Cursor::new(head)).unwrap_err().kind(), io::ErrorKind::InvalidData);

        // Truncated large-claim frame returns UnexpectedEof without allocating the claimed size.
        let claim = (MAX_FRAME_LIMIT - 1) as u32;
        let mut trunc = vec![
            ((claim >> 16) & 0xff) as u8,
            ((claim >> 8) & 0xff) as u8,
            (claim & 0xff) as u8,
            FRAME_DATA,
            0,
            0,
            0,
            0,
            1,
        ];
        trunc.extend_from_slice(b"short");
        assert_eq!(read_frame(&mut Cursor::new(trunc)).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);

        // HPACK dynamic table size update past MAX_HPACK_TABLE_SIZE is rejected.
        let mut dec = HpackDecoder::new();
        let mut bad_update = Vec::new();
        hpack_encode_int(&mut bad_update, 5, 0x20, MAX_HPACK_TABLE_SIZE + 1);
        assert_eq!(dec.decode(&bad_update).unwrap_err().kind(), io::ErrorKind::InvalidData);

        // HPACK decompression bomb (repeating a large indexed dynamic entry) is rejected.
        let mut bomb = Vec::new();
        // Insert a ~3.5 KiB header into dynamic table (index 62): literal with incremental indexing (0x40), new name.
        bomb.push(0x40);
        hpack_encode_int(&mut bomb, 7, 0x00, 1);
        bomb.push(b'x');
        hpack_encode_int(&mut bomb, 7, 0x00, 3500);
        bomb.extend(std::iter::repeat_n(b'a', 3500));
        // Repeat index 62 (0x80 | 62 = 0xbe) 1000 times -> ~3.5 MiB > MAX_DECODED_HEADERS (2 MiB).
        bomb.extend(std::iter::repeat_n(0xbe, 1000));
        assert_eq!(dec.decode(&bomb).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn bridge_session_aborts_cleanly_on_client_error() {
        struct FailReader;
        impl Read for FailReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::ConnectionReset, "peer reset"))
            }
        }
        let (mut srv_r, srv_w) = UnixStream::pair().unwrap();
        let (srv_reply_w, srv_reply_r) = UnixStream::pair().unwrap();
        let (_cli_recv, cli_send) = UnixStream::pair().unwrap();
        let abort_w = srv_reply_w.try_clone().unwrap();
        let srv_w_close = srv_w.try_clone().unwrap();

        let drain = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while srv_r.read(&mut buf).unwrap_or(0) > 0 {}
        });
        let res = bridge_session(
            &[],
            FailReader,
            cli_send,
            srv_reply_r,
            srv_w,
            move || {
                // Simulates closing exec stdin so buildctl exits and closes server stdout.
                let _ = srv_w_close.shutdown(Shutdown::Write);
                let _ = abort_w.shutdown(Shutdown::Write);
            },
            || {},
        );
        drop(srv_reply_w);
        drain.join().unwrap();
        assert!(res.is_err());
    }

    #[test]
    fn grpc_probe_returns_101_without_waking_builder() {
        let (engine, dir) = test_engine("probe");
        let (mut client, server) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn({
            let engine = engine.clone();
            move || super::super::api::serve(server, engine, super::super::caller::Caller::Container)
        });
        client
            .write_all(b"POST /grpc HTTP/1.1\r\nHost: \r\nContent-Length: 0\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n")
            .unwrap();
        // Read the full HTTP/1.1 101 response head, then close immediately as buildx's Priority() probe does.
        let mut resp = Vec::new();
        let mut buf = [0u8; 512];
        while !resp.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = client.read(&mut buf).unwrap();
            assert!(n > 0, "unexpected EOF before end of 101 headers: {:?}", String::from_utf8_lossy(&resp));
            resp.extend_from_slice(&buf[..n]);
        }
        let resp = String::from_utf8_lossy(&resp);
        assert!(resp.starts_with("HTTP/1.1 101 "), "{resp}");
        assert!(resp.contains("Upgrade: h2c\r\n"), "{resp}");
        drop(client);
        handle.join().unwrap().unwrap();
        // No builder container was created by a probe.
        assert!(engine.each(|c| Some(c.name.clone())).is_empty());
        drop(engine);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rewrites_gzip_compressed_solve_request() {
        let (engine, dir) = test_engine("gzip");

        let mut solve_req = Vec::new();
        pb_write_string(&mut solve_req, 1, "ref-gzip");
        pb_write_bytes(
            &mut solve_req,
            13,
            &pb_encode_exporter(&ExporterSpec {
                ty: "moby".into(),
                attrs: vec![("name".into(), "docker.io/library/gzip-demo:1".into()), ("unpack".into(), "true".into())],
            }),
        );
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&solve_req).unwrap();
        let compressed_req = wrap_grpc_frame(1, &enc.finish().unwrap());

        let (out_grpc, state) = rewrite_grpc_solve_request(&compressed_req, &engine, false).unwrap();
        let state = state.expect("gzipped moby SolveRequest must be rewritten");
        assert_eq!(state.orig_name, "docker.io/library/gzip-demo:1");
        assert_eq!(out_grpc[0], 1, "rewritten frame keeps gRPC compression flag consistent with grpc-encoding: gzip");
        let msg_len = u32::from_be_bytes([out_grpc[1], out_grpc[2], out_grpc[3], out_grpc[4]]) as usize;
        assert_eq!(5 + msg_len, out_grpc.len());

        let mut decompressed = Vec::new();
        flate2::read::GzDecoder::new(&out_grpc[5..]).read_to_end(&mut decompressed).unwrap();
        let fields = pb_split_fields(&decompressed).unwrap();
        let exp = pb_decode_exporter(fields.iter().find(|f| f.num == 13).unwrap().val).unwrap();
        assert_eq!(exp.ty, "image");
        assert!(exp.attrs.iter().any(|(k, v)| k == "push" && v == "true"));
        assert!(!exp.attrs.iter().any(|(k, _)| k == "unpack"));
        assert!(exp.attrs.iter().any(|(k, v)| k == "name" && v.contains("/load/") && v.ends_with("/image:out")));

        drop(state);
        drop(engine);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_empty_continuation_flood_and_caps_concurrent_solve_streams() {
        let (engine, dir) = test_engine("dos-caps");

        // 1. Empty CONTINUATION frame flood past MAX_CONTINUATION_FRAMES is rejected.
        {
            let mut c2p = Vec::new();
            c2p.extend_from_slice(H2_PREFACE);
            let hdr = hpack_encode_literal(&[(":method", "POST"), (":path", SOLVE_PATH)]);
            write_frame(&mut c2p, &Frame { ty: FRAME_HEADERS, flags: 0, stream_id: 1, payload: hdr }).unwrap();
            for _ in 0..=MAX_CONTINUATION_FRAMES {
                write_frame(&mut c2p, &Frame { ty: FRAME_CONTINUATION, flags: 0, stream_id: 1, payload: Vec::new() }).unwrap();
            }
            let (_srv_r, srv_w) = UnixStream::pair().unwrap();
            let (reply_w, reply_r) = UnixStream::pair().unwrap();
            let mut client_out = Vec::new();
            let err = proxy_grpc(
                Cursor::new(c2p),
                &mut client_out,
                reply_r,
                srv_w,
                &engine,
                false,
                || { let _ = reply_w.shutdown(Shutdown::Both); },
                || {},
            )
            .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert!(err.to_string().contains("CONTINUATION"), "{err}");
        }

        // 2. Empty END_STREAM HEADERS clears solve_req_bufs, while exceeding MAX_CONCURRENT_SOLVE_STREAMS is rejected.
        {
            let mut c2p = Vec::new();
            c2p.extend_from_slice(H2_PREFACE);
            let solve_hdr = hpack_encode_literal(&[(":method", "POST"), (":path", SOLVE_PATH)]);
            let empty_end_hdr = hpack_encode_literal(&[("grpc-status", "0")]);
            // Open stream 1, then immediately close it via END_STREAM HEADERS so its slot is freed.
            write_frame(&mut c2p, &Frame { ty: FRAME_HEADERS, flags: FLAG_END_HEADERS, stream_id: 1, payload: solve_hdr.clone() }).unwrap();
            write_frame(&mut c2p, &Frame { ty: FRAME_HEADERS, flags: FLAG_END_HEADERS | FLAG_END_STREAM, stream_id: 1, payload: empty_end_hdr }).unwrap();
            // Open MAX_CONCURRENT_SOLVE_STREAMS concurrent Solve streams (streams 3..=33), then one more (stream 35) to trigger the cap.
            for i in 0..=MAX_CONCURRENT_SOLVE_STREAMS {
                let sid = (i as u32 + 1) * 2 + 1;
                write_frame(&mut c2p, &Frame { ty: FRAME_HEADERS, flags: FLAG_END_HEADERS, stream_id: sid, payload: solve_hdr.clone() }).unwrap();
            }
            let (mut srv_r, srv_w) = UnixStream::pair().unwrap();
            let (reply_w, reply_r) = UnixStream::pair().unwrap();
            let drain = std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while srv_r.read(&mut buf).unwrap_or(0) > 0 {}
            });
            let mut client_out = Vec::new();
            let err = proxy_grpc(
                Cursor::new(c2p),
                &mut client_out,
                reply_r,
                srv_w,
                &engine,
                false,
                || { let _ = reply_w.shutdown(Shutdown::Both); },
                || {},
            )
            .unwrap_err();
            drain.join().unwrap();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert!(err.to_string().contains("concurrent Solve streams"), "{err}");
        }

        drop(engine);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
