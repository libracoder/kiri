//! The daemon's BuildKit: buildx's `docker` driver speaks gRPC straight at
//! this socket, and a stream into the guest's buildkitd answers each one.
//!
//! buildx dials the engine socket with HTTP/2 cleartext (prior knowledge:
//! exactly how grpc-go behaves against Docker Desktop on a unix socket) and
//! runs both the BuildKit control API and its session services over that
//! one connection — auth, ssh, local contexts and all; those parts live in
//! buildx itself, so the daemon only has to be the tunnel. One h2 connection
//! per buildx dial, one vsock stream into the guest for it, and every gRPC
//! request, reply and trailer goes between them untouched.
//!
//! buildkitd starts on demand in the guest; the first dial may ride over
//! the exchange that boots it, which is why `dial` retries.

use std::future::poll_fn;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use h2::client::SendRequest;
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use tokio::io::unix::AsyncFd;

use super::builder;
use super::engine::Engine;
use crate::diag;

/// Who is on a BuildKit connection now, and when someone last was (Unix
/// seconds; 0 = nobody has yet). `builder::idle_secs()` of quiet with
/// nobody connected, and the guest's buildkitd is stopped again.
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static LAST_USE: AtomicU64 = AtomicU64::new(0);

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// The tokio island: BuildKit relays are the one thing in the daemon that
/// wants real concurrency, so they borrow two threads that everyone else
/// agrees never to touch.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("kiri-grpc")
            .build()
            .expect("cannot start the BuildKit runtime")
    })
}

/// A buildx connection arrives here from the socket accept loop when the
/// connection opens with h2's preface. One thread per connection, as the
/// engine is thread-based: the vsock dial may boot the whole VM first, so
/// this thread blocks politely until what follows wants tokio. Runs until
/// buildx goes (or its VM does), then falls off the end.
pub fn serve(conn: UnixStream, engine: Arc<Engine>) {
    let outcome: io::Result<()> = runtime().block_on(async move {
        let guest = dial(&engine).await?;
        session(conn, guest).await
    });
    if let Err(e) = outcome {
        // buildx walking away mid-build, the VM going to sleep: all
        // ordinary, so this is a line, not an error report.
        diag::info!("a BuildKit connection ended", error = e.to_string());
    }
}

/// The relay: one buildx connection's journey to buildkitd. `conn` is the
/// buildx end (its h2 cleartext, served by us), `guest_fd` the vsock stream
/// whose other end speaks h2 back (buildkitd serving). The framing is
/// understood by h2 both ways; the tunnel in the middle is all ours.
pub(crate) async fn session(conn: UnixStream, guest_fd: OwnedFd) -> io::Result<()> {
    ACTIVE.fetch_add(1, Ordering::Relaxed);
    LAST_USE.store(now_secs(), Ordering::Relaxed);

    // The client half dials buildkitd, whose h2 handshake answers; the
    // server half answers buildx's. The client half needs a driver, since
    // no window update moves on its own.
    let (request, connection) = h2::client::handshake(GuestStream::new(guest_fd)?)
        .await
        .map_err(grpc_error)?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            diag::info!("the BuildKit stream went nowhere", error = e.to_string());
        }
    });

    conn.set_nonblocking(true)?;
    let mut server = h2::server::handshake(tokio::net::UnixStream::from_std(conn)?)
        .await
        .map_err(grpc_error)?;

    // buildx's RPCs, each onto its own task, so answers come in whatever
    // order buildkitd finishes them.
    while let Some(received) = server.accept().await {
        match received {
            Ok((call, respond)) => {
                let (parts, from_buildx) = call.into_parts();
                tokio::spawn(relay_one(parts, from_buildx, respond, request.clone()));
            }
            Err(e) => return Err(grpc_error(e)),
        }
    }
    ACTIVE.fetch_sub(1, Ordering::Relaxed);
    Ok(())
}

/// One gRPC call in and out: the request's headers told to buildkitd first
/// (so it works while our message is still arriving from buildx), then the
/// message itself, then the reply in whatever length it is, then any
/// trailers to finish with. Flow windows are opened back up both ways as
/// the bytes are taken, so long streams never stall.
async fn relay_one(parts: http::request::Parts, mut from_buildx: RecvStream, respond: SendResponse<Bytes>, mut request: SendRequest<Bytes>) {
    let out = relay(&parts, &mut from_buildx, respond, &mut request).await;
    if let Err(e) = out {
        // buildx and buildkitd each see their own half of this.
        diag::info!("a BuildKit RPC was cut short", path = parts.uri.path(), error = e.to_string());
    }
}

async fn relay(
    parts: &http::request::Parts,
    from_buildx: &mut RecvStream,
    mut respond: SendResponse<Bytes>,
    request: &mut SendRequest<Bytes>,
) -> io::Result<()> {
    // The headers first.
    let (reply, mut to_builder) = request
        .send_request(http::Request::from_parts(parts.to_owned(), ()), false)
        .map_err(grpc_error)?;
    // The message itself.
    let message = capture(from_buildx).await?;
    send_all(&mut to_builder, message).await?;
    // The reply's headers, then its bytes as they come, and lastly trailers.
    let (reply_parts, mut from_builder) = reply.await.map_err(grpc_error)?.into_parts();
    let mut to_buildx = respond
        .send_response(http::Response::from_parts(reply_parts, ()), false)
        .map_err(grpc_error)?;
    while let Some(chunk) = poll_fn(|cx| from_builder.poll_data(cx)).await {
        let chunk = chunk.map_err(grpc_error)?;
        from_builder.flow_control().release_capacity(chunk.len()).map_err(grpc_error)?;
        send_all(&mut to_buildx, chunk).await?;
    }
    // gRPC finishes every reply with trailers: the status.
    match poll_fn(|cx| from_builder.poll_trailers(cx)).await {
        Ok(Some(trailers)) => to_buildx.send_trailers(trailers).map_err(grpc_error)?,
        Ok(None) => send_all(&mut to_buildx, Bytes::new()).await?,
        Err(e) => return Err(grpc_error(e)),
    }
    Ok(())
}

/// The whole of what buildx sends for its one message: every DATA chunk,
/// with the flow window released as each is taken.
async fn capture(from_buildx: &mut RecvStream) -> io::Result<Bytes> {
    let mut message = BytesMut::new();
    while let Some(chunk) = poll_fn(|cx| from_buildx.poll_data(cx)).await {
        let chunk = chunk.map_err(grpc_error)?;
        from_buildx.flow_control().release_capacity(chunk.len()).map_err(grpc_error)?;
        message.extend_from_slice(&chunk);
    }
    Ok(message.freeze())
}

/// Sends a body down a stream, waiting on its send window as it goes and
/// ending the stream with the last chunk. An empty body still sends one
/// empty DATA chunk, whose whole point is to say the stream ends.
async fn send_all(to: &mut SendStream<Bytes>, mut body: Bytes) -> io::Result<()> {
    while !body.is_empty() {
        to.reserve_capacity(body.len());
        match poll_fn(|cx| to.poll_capacity(cx)).await {
            Some(Ok(n)) if n > 0 => {
                let n = n.min(body.len());
                let end = n == body.len();
                to.send_data(body.split_to(n), end).map_err(grpc_error)?;
            }
            Some(Ok(_)) => continue,
            Some(Err(e)) => return Err(grpc_error(e)),
            None => return Err(io::Error::other("the send stream closed before the body did")),
        }
    }
    Ok(())
}

fn grpc_error(e: h2::Error) -> io::Error {
    io::Error::other(e.to_string())
}

/// A vsock fd, served to h2 as a stream. Virtualization.framework's sockets
/// want to be in nonblocking mode before AsyncFd's readiness means anything,
/// which `new` attends to.
struct GuestStream {
    fd: AsyncFd<OwnedFd>,
}

impl GuestStream {
    fn new(fd: OwnedFd) -> io::Result<Self> {
        set_nonblocking(fd.as_raw_fd())?;
        #[allow(deprecated)]
        Ok(Self { fd: AsyncFd::new(fd)? })
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

/// One read on the vsock, raw: OwnedFd has no `Read`, and the read has to
/// stay in the family anyway — the guard above has the fd's readiness.
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

impl tokio::io::AsyncRead for GuestStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let ready = match this.fd.poll_read_ready(cx) {
            Poll::Ready(Ok(g)) => g,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        let mut dst = buf.initialize_unfilled();
        match read_raw(this.fd.as_raw_fd(), &mut dst) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                let mut ready = ready;
                ready.clear_ready();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl tokio::io::AsyncWrite for GuestStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let ready = match this.fd.poll_write_ready(cx) {
            Poll::Ready(Ok(g)) => g,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        match write_raw(this.fd.as_raw_fd(), buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                let mut ready = ready;
                ready.clear_ready();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    /// Closing the half: on a vsock there is no half-close, so this says
    /// well enough.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A dial into the guest's BuildKit relay, with patience: the first failed
/// connect is answered by starting buildkitd (its config and layers go
/// along with the `BuildkitStart` itself), after which the dial retries
/// until the agent answers that the process is living.
async fn dial(engine: &Engine) -> io::Result<OwnedFd> {
    let mut started = false;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match engine.buildkit_connect() {
            Ok(stream) => return Ok(stream.fd.try_clone()?),
            Err(_) if !started => {
                let config = builder::guest_config(engine);
                match builder::guest_layers(engine, &mut |_| {}) {
                    Ok(layers) => {
                        engine
                            .buildkit_start(&layers, &config)
                            .map_err(|e| io::Error::other(format!("cannot start buildkitd: {e:?}")))?;
                        started = true;
                    }
                    Err(e) => return Err(io::Error::other(format!("cannot start buildkitd: {e:?}"))),
                }
            }
            Err(_) if Instant::now() > deadline => {
                return Err(io::Error::other("the guest never answered the BuildKit dial"));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
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
