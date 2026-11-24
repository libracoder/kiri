//! The daemon's BuildKit: buildx's `docker` driver speaks gRPC straight at
//! this socket, and buildkitd in the guest answers it.
//!
//! The control path (`/grpc`) is a plain byte tunnel: buildx and buildkitd
//! each speak h2 and the framed bytes pass through untouched.
//!
//! The session path (`/session`) cannot be a byte tunnel. buildkitd registers
//! a session only when a `Control.Session` gRPC stream is opened carrying the
//! `X-Docker-Expose-Session-*` metadata — moby normally does this in-process
//! and hijacks the stream into a connection so buildkitd can call back into
//! buildx's session services (auth, ssh, local contexts). We do the same here:
//! open that stream on buildkitd, pass the upgrade headers as its metadata,
//! and carry buildx's h2 bytes as the stream's `BytesMessage` payloads.

use std::future::poll_fn;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::io::unix::AsyncFd;

use super::builder;
use super::engine::Engine;
use crate::diag;

/// Who is on a BuildKit connection now, and when someone last was (Unix
/// seconds; 0 = nobody has yet). `builder::idle_secs()` of quiet with nobody
/// connected, and the guest's buildkitd is stopped again.
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static LAST_USE: AtomicU64 = AtomicU64::new(0);

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// The tokio island: the relays are the one thing in the daemon that wants
/// real concurrency, so they borrow two threads that everyone else agrees
/// never to touch.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("kiri-grpc")
            .enable_all()
            .build()
            .expect("cannot start the BuildKit runtime")
    })
}

/// A buildx connection arrives here from the socket accept loop. `session`
/// holds the upgrade headers for `/session`, which buildkitd needs to register
/// the session; `/grpc` arrives with None and is tunneled byte for byte.
pub fn serve(conn: UnixStream, engine: Arc<Engine>, session: Option<Vec<(String, String)>>) {
    let outcome: io::Result<()> = runtime().block_on(async move {
        // A build can export for longer than the VM's idle window: keep it
        // awake for as long as buildx holds a connection.
        let keepalive = {
            let e = engine.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(15)).await;
                    e.touch();
                }
            })
        };
        let result = async {
            let guest = dial(&engine).await?;
            match session {
                Some(headers) => {
                    let (request, connection) = match h2::client::handshake(GuestStream::new(guest)?).await {
                        Ok(pair) => pair,
                        Err(e) => return Err(grpc_error(e)),
                    };
                    let driver = tokio::spawn(async move {
                        if let Err(e) = connection.await {
                            diag::info!("the BuildKit stream went nowhere", error = e.to_string());
                        }
                    });
                    let result = session_tunnel(OwnedFd::from(conn), request, headers).await;
                    driver.abort();
                    result
                }
                None => tunnel(OwnedFd::from(conn), guest).await,
            }
        }.await;
        keepalive.abort();
        result
    });
    if let Err(e) = outcome {
        diag::info!("a BuildKit connection ended", error = e.to_string());
    }
}

/// Lowers the active count on every exit, including the early error returns.
struct ActiveGuard;

impl ActiveGuard {
    fn new() -> Self {
        ACTIVE.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A connection into the guest's BuildKit relay, with patience. The guest
/// accepts vsock connections before buildkitd is listening, so a successful
/// connect is not the cue that it is ready — but buildkitd's unix socket is
/// only created once it is up, so a connect that reaches the guest and is
/// relayed on is enough. `BuildkitStart` is sent first; `ensure` is idempotent.
async fn dial(engine: &Engine) -> io::Result<OwnedFd> {
    let config = builder::guest_config(engine);
    let layers = builder::guest_layers(engine, &mut |_| {}).map_err(|e| io::Error::other(format!("cannot list the BuildKit image layers: {e:?}")))?;
    engine.buildkit_start(&layers, &config).map_err(|e| io::Error::other(format!("cannot start buildkitd: {e:?}")))?;

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match engine.buildkit_connect() {
            Ok(stream) => return stream.fd.try_clone(),
            Err(e) => diag::debug!("the BuildKit dial failed", error = format!("{e:?}")),
        }
        if Instant::now() > deadline {
            return Err(io::Error::other("the guest never answered the BuildKit dial"));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The control path: copy both directions at once. buildx and buildkitd each
/// have their own h2 connection; the bytes between them are opaque to us.
async fn tunnel(buildx_fd: OwnedFd, guest_fd: OwnedFd) -> io::Result<()> {
    let _active = ActiveGuard::new();
    LAST_USE.store(now_secs(), Ordering::Relaxed);

    let (mut from_buildx, mut to_buildx) = tokio::io::split(RawFdStream::new(buildx_fd)?);
    let (mut from_guest, mut to_guest) = tokio::io::split(RawFdStream::new(guest_fd)?);
    let up = tokio::spawn(async move { copy(&mut from_buildx, &mut to_guest).await });
    let down = tokio::spawn(async move { copy(&mut from_guest, &mut to_buildx).await });
    let up = up.await.map_err(join_error)?;
    let down = down.await.map_err(join_error)?;
    diag::info!("BuildKit tunnel ended", up = format!("{up:?}"), down = format!("{down:?}"));
    up?;
    down?;
    Ok(())
}

/// The session path. buildkitd's `Control.Session` handler hijacks the stream
/// into a net.Conn: what goes in as gRPC `BytesMessage` payloads comes out as
/// raw bytes for its gRPC client, and vice versa. That is exactly the bridge
/// between buildx's session services and buildkitd.
async fn session_tunnel(buildx_fd: OwnedFd, request: h2::client::SendRequest<Bytes>, headers: Vec<(String, String)>) -> io::Result<()> {
    let _active = ActiveGuard::new();
    LAST_USE.store(now_secs(), Ordering::Relaxed);

    let mut builder = http::Request::builder()
        .method("POST")
        .uri("http://localhost/moby.buildkit.v1.Control/Session")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        // The session crosses a VM relay, so a slow export can outlast
        // buildkitd's 15 s healthcheck and tear down a healthy session.
        .header("x-buildkit-session-health-custom-timeout", "300000");
    for (name, value) in headers {
        let name = name.to_ascii_lowercase();
        if name.starts_with("x-docker-expose-session-") {
            builder = builder.header(name, value);
        }
    }
    let req = builder.body(()).map_err(io::Error::other)?;
    let mut ready = request.ready().await.map_err(grpc_error)?;
    let (reply, mut to_buildkit) = ready.send_request(req, false).map_err(grpc_error)?;

    let (mut from_buildx, mut to_buildx) = tokio::io::split(RawFdStream::new(buildx_fd)?);
    let up = tokio::spawn(async move {
        let mut buf = [0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let n = from_buildx.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            LAST_USE.store(now_secs(), Ordering::Relaxed);
            send_framed(&mut to_buildkit, &bytes_message(&buf[..n])).await?;
            total += n as u64;
        }
        to_buildkit.send_data(Bytes::new(), true).map_err(grpc_error)?;
        Ok::<u64, io::Error>(total)
    });
    let down = tokio::spawn(async move {
        let (_, mut from_buildkit) = reply.await.map_err(grpc_error)?.into_parts();
        let mut frames = Frames::default();
        let mut total = 0u64;
        while let Some(chunk) = poll_fn(|cx| from_buildkit.poll_data(cx)).await {
            let chunk = chunk.map_err(grpc_error)?;
            from_buildkit.flow_control().release_capacity(chunk.len()).map_err(grpc_error)?;
            frames.push(&chunk);
            while let Some(message) = frames.next() {
                LAST_USE.store(now_secs(), Ordering::Relaxed);
                to_buildx.write_all(&message).await?;
                total += message.len() as u64;
            }
        }
        let _ = poll_fn(|cx| from_buildkit.poll_trailers(cx)).await;
        Ok::<u64, io::Error>(total)
    });
    let up = up.await.map_err(join_error)?;
    let down = down.await.map_err(join_error)?;
    diag::info!("BuildKit session ended", up = format!("{up:?}"), down = format!("{down:?}"));
    up?;
    down?;
    Ok(())
}

fn grpc_error(e: h2::Error) -> io::Error {
    io::Error::other(e.to_string())
}

/// One gRPC message of `controlapi.BytesMessage { bytes data = 1; }`: the
/// 5-byte gRPC frame, then protobuf field 1 and a varint length.
fn bytes_message(data: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(5 + 1 + 10 + data.len());
    out.push(0); // uncompressed
    let body = 1 + varint_len(data.len()) + data.len();
    out.extend_from_slice(&(body as u32).to_be_bytes());
    out.push(0x0a); // field 1, length-delimited
    put_varint(&mut out, data.len());
    out.extend_from_slice(data);
    Bytes::from(out)
}

fn varint_len(mut n: usize) -> usize {
    let mut len = 1;
    while n >= 128 {
        n >>= 7;
        len += 1;
    }
    len
}

fn put_varint(out: &mut Vec<u8>, mut n: usize) {
    while n >= 128 {
        out.push((n as u8) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

/// h2 DATA frames do not line up with gRPC messages: reassemble them.
#[derive(Default)]
struct Frames {
    buf: Vec<u8>,
}

impl Frames {
    fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    fn next(&mut self) -> Option<Vec<u8>> {
        if self.buf.len() < 5 {
            return None;
        }
        let len = u32::from_be_bytes(self.buf[1..5].try_into().ok()?) as usize;
        if self.buf.len() < 5 + len {
            return None;
        }
        let frame = &self.buf[5..5 + len];
        // An empty BytesMessage is a zero-length protobuf payload. Never let
        // a frame we cannot parse sit in the buffer: that stalls the stream.
        let data = read_bytes_message(frame).unwrap_or_default();
        self.buf.drain(..5 + len);
        Some(data)
    }
}

fn read_bytes_message(frame: &[u8]) -> Option<Vec<u8>> {
    if frame.is_empty() {
        return Some(Vec::new());
    }
    if frame.first() != Some(&0x0a) {
        return None;
    }
    let (len, used) = get_varint(&frame[1..])?;
    let start = 1 + used;
    if start + len > frame.len() {
        return None;
    }
    Some(frame[start..start + len].to_vec())
}

fn get_varint(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut n = 0usize;
    for (i, b) in bytes.iter().enumerate() {
        n |= ((b & 0x7f) as usize) << (7 * i);
        if b & 0x80 == 0 {
            return Some((n, i + 1));
        }
        if i >= 9 {
            return None;
        }
    }
    None
}

async fn send_framed(to: &mut SendStream<Bytes>, msg: &[u8]) -> io::Result<()> {
    let mut rest = msg;
    while !rest.is_empty() {
        to.reserve_capacity(rest.len());
        let n = match poll_fn(|cx| to.poll_capacity(cx)).await {
            Some(Ok(n)) if n > 0 => n.min(rest.len()),
            Some(Ok(_)) => continue,
            Some(Err(e)) => return Err(grpc_error(e)),
            None => return Err(io::Error::other("the send stream closed before the message did")),
        };
        let (part, tail) = rest.split_at(n);
        to.send_data(Bytes::copy_from_slice(part), false).map_err(grpc_error)?;
        rest = tail;
    }
    Ok(())
}

fn join_error(e: tokio::task::JoinError) -> io::Error {
    io::Error::other(e.to_string())
}

async fn copy<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(from: &mut R, to: &mut W) -> io::Result<u64> {
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            return Ok(total);
        }
        LAST_USE.store(now_secs(), Ordering::Relaxed);
        to.write_all(&buf[..n]).await?;
        total += n as u64;
    }
}

fn set_nonblocking(fd: i32) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_raw(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

fn write_raw(fd: i32, buf: &[u8]) -> io::Result<usize> {
    loop {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// A socket fd as an async stream, for both the raw tunnel and h2.
struct RawFdStream {
    fd: AsyncFd<OwnedFd>,
}

impl RawFdStream {
    fn new(fd: OwnedFd) -> io::Result<Self> {
        set_nonblocking(fd.as_raw_fd())?;
        #[allow(deprecated)]
        Ok(Self { fd: AsyncFd::new(fd)? })
    }
}

/// The h2 client's view of the guest socket.
type GuestStream = RawFdStream;

impl AsyncRead for RawFdStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let ready = match this.fd.poll_read_ready(cx) {
            Poll::Ready(Ok(g)) => g,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        let unfilled = buf.initialize_unfilled();
        let mut ready = ready;
        ready.clear_ready();
        match read_raw(this.fd.as_raw_fd(), unfilled) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl AsyncWrite for RawFdStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let ready = match this.fd.poll_write_ready(cx) {
            Poll::Ready(Ok(g)) => g,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        let mut ready = ready;
        ready.clear_ready();
        match write_raw(this.fd.as_raw_fd(), buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Never `builder::idle_secs()` without a BuildKit connection, and the
/// guest's buildkitd keeps running; quiet for that long, and it stops.
pub fn watch(engine: Arc<Engine>) {
    let spawned = std::thread::Builder::new().name("kiri-buildkit-idle".into()).spawn(move || loop {
        std::thread::sleep(Duration::from_secs(15));
        if ACTIVE.load(Ordering::Relaxed) != 0 {
            continue;
        }
        let last = LAST_USE.load(Ordering::Relaxed);
        if last == 0 || now_secs() < last + builder::idle_secs() {
            continue;
        }
        LAST_USE.store(0, Ordering::Relaxed);
        let _ = engine.buildkit_stop();
    });
    if let Err(e) = spawned {
        diag::warn!("cannot start the BuildKit idle watcher", error = e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_relay_runtime_has_io_and_time_drivers() {
        super::runtime().block_on(async {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            let (socket, _peer) = tokio::net::UnixStream::pair().unwrap();
            #[allow(deprecated)]
            tokio::io::unix::AsyncFd::new(socket).unwrap();
        });
    }

    #[test]
    fn grpc_bytes_messages_survive_fragmentation() {
        let data = b"the session services are here";
        let frame = bytes_message(data);
        let mut frames = Frames::default();
        assert_eq!(frames.next(), None);
        frames.push(&frame[..3]);
        assert_eq!(frames.next(), None);
        frames.push(&frame[3..frame.len() - 1]);
        assert_eq!(frames.next(), None);
        frames.push(&frame[frame.len() - 1..]);
        assert_eq!(frames.next(), Some(data.to_vec()));
        assert_eq!(frames.next(), None);
    }

    #[test]
    fn tunnel_copies_bytes_both_ways() {
        super::runtime().block_on(async {
            let (buildx, buildx_peer) = UnixStream::pair().unwrap();
            let (guest, guest_peer) = UnixStream::pair().unwrap();
            set_nonblocking(buildx_peer.as_raw_fd()).unwrap();
            set_nonblocking(guest_peer.as_raw_fd()).unwrap();
            let buildx_peer = tokio::net::UnixStream::from_std(buildx_peer).unwrap();
            let guest_peer = tokio::net::UnixStream::from_std(guest_peer).unwrap();

            let fake = tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(guest_peer);
                let mut seen = vec![0u8; 8];
                r.read_exact(&mut seen).await.unwrap();
                w.write_all(b"echo:pingecho:pong").await.unwrap();
                seen
            });
            let client = tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(buildx_peer);
                w.write_all(b"ping").await.unwrap();
                w.write_all(b"pong").await.unwrap();
                let mut got = [0u8; 18];
                r.read_exact(&mut got).await.unwrap();
                got.to_vec()
            });

            tunnel(OwnedFd::from(buildx), OwnedFd::from(guest)).await.unwrap();
            assert_eq!(fake.await.unwrap(), b"pingpong");
            assert_eq!(client.await.unwrap(), b"echo:pingecho:pong");
        });
    }
}
