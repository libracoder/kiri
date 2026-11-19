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

use bytes::Bytes;
use h2::client::SendRequest;
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use tokio::io::unix::AsyncFd;

use super::builder;
use super::engine::Engine;
use crate::diag;

/// The h2 driver half of the guest connection, kept alive for the session.
type GuestConnection = h2::client::Connection<GuestStream, Bytes>;

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
        let (request, connection) = dial(&engine).await?;
        // h2 needs its connection polled while requests are in flight: the
        // window updates and PINGs happen here, not in `relay`.
        let driver = tokio::spawn(async move {
            if let Err(e) = connection.await {
                diag::info!("the BuildKit stream went nowhere", error = e.to_string());
            }
        });
        let result = session(conn, request).await;
        driver.abort();
        result
    });
    if let Err(e) = outcome {
        // buildx walking away mid-build, the VM going to sleep: all
        // ordinary, so this is a line, not an error report.
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

/// The relay: one buildx connection's journey to buildkitd. `conn` is the
/// buildx end (its h2 cleartext, served by us); `request` sends onto the
/// guest's h2 stream, whose other end speaks h2 back (buildkitd serving). The
/// framing is understood by h2 both ways; the tunnel in the middle is all ours.
pub(crate) async fn session(conn: UnixStream, request: SendRequest<Bytes>) -> io::Result<()> {
    let _active = ActiveGuard::new();
    LAST_USE.store(now_secs(), Ordering::Relaxed);

    // The server half answers buildx's h2 connection. The client half (the
    // h2 driver and its `SendRequest`) was set up by `dial` and is polled by
    // `serve`.
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
    Ok(())
}

/// One gRPC call in and out: the request's headers told to buildkitd first
/// (so it works while our message is still arriving from buildx), then the
/// message itself, then the reply in whatever length it is, then any
/// trailers to finish with. Flow windows are opened back up both ways as
/// the bytes are taken, so long streams never stall.
async fn relay_one(parts: http::request::Parts, from_buildx: RecvStream, respond: SendResponse<Bytes>, request: SendRequest<Bytes>) {
    let out = relay(&parts, from_buildx, respond, request).await;
    if let Err(e) = out {
        // buildx and buildkitd each see their own half of this.
        diag::info!("a BuildKit RPC was cut short", path = parts.uri.path(), error = e.to_string());
    }
}

async fn relay(
    parts: &http::request::Parts,
    from_buildx: RecvStream,
    mut respond: SendResponse<Bytes>,
    mut request: SendRequest<Bytes>,
) -> io::Result<()> {
    // The headers first, so buildkitd can answer while our request is still
    // arriving: BuildKit's session and status calls stay open for a whole
    // build and are two-way, not one message then one reply.
    let (reply, mut to_builder) = request
        .send_request(http::Request::from_parts(parts.to_owned(), ()), false)
        .map_err(grpc_error)?;

    // buildx -> buildkitd.
    let up = tokio::spawn(async move {
        let mut from_buildx = from_buildx;
        while let Some(chunk) = poll_fn(|cx| from_buildx.poll_data(cx)).await {
            let chunk = chunk.map_err(grpc_error)?;
            from_buildx.flow_control().release_capacity(chunk.len()).map_err(grpc_error)?;
            send_all(&mut to_builder, chunk, false).await?;
        }
        // No more data from buildx: end the request stream.
        send_all(&mut to_builder, Bytes::new(), true).await
    });

    // buildkitd -> buildx. Runs at the same time as `up`, so a long-lived
    // duplex call never waits for the request side to finish.
    let down = tokio::spawn(async move {
        let (reply_parts, mut from_builder) = reply.await.map_err(grpc_error)?.into_parts();
        let mut to_buildx = respond
            .send_response(http::Response::from_parts(reply_parts, ()), false)
            .map_err(grpc_error)?;
        while let Some(chunk) = poll_fn(|cx| from_builder.poll_data(cx)).await {
            let chunk = chunk.map_err(grpc_error)?;
            from_builder.flow_control().release_capacity(chunk.len()).map_err(grpc_error)?;
            send_all(&mut to_buildx, chunk, false).await?;
        }
        // gRPC finishes every reply with trailers: the status.
        match poll_fn(|cx| from_builder.poll_trailers(cx)).await {
            Ok(Some(trailers)) => to_buildx.send_trailers(trailers).map_err(grpc_error),
            Ok(None) => send_all(&mut to_buildx, Bytes::new(), true).await,
            Err(e) => Err(grpc_error(e)),
        }
    });

    let up = up.await.map_err(join_error)?;
    let down = down.await.map_err(join_error)?;
    up?;
    down?;
    Ok(())
}

fn join_error(e: tokio::task::JoinError) -> io::Error {
    io::Error::other(e.to_string())
}

/// Sends one chunk down a stream, waiting on its send window as it goes.
/// `end` closes the stream; long streams send chunks with `end = false` and
/// close once, with an empty final DATA frame or the trailers.
async fn send_all(to: &mut SendStream<Bytes>, mut body: Bytes, end: bool) -> io::Result<()> {
    while !body.is_empty() {
        to.reserve_capacity(body.len());
        match poll_fn(|cx| to.poll_capacity(cx)).await {
            Some(Ok(n)) if n > 0 => {
                let n = n.min(body.len());
                to.send_data(body.split_to(n), false).map_err(grpc_error)?;
            }
            Some(Ok(_)) => continue,
            Some(Err(e)) => return Err(grpc_error(e)),
            None => return Err(io::Error::other("the send stream closed before the body did")),
        }
    }
    if end {
        to.send_data(Bytes::new(), true).map_err(grpc_error)?;
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

/// A dial into the guest's BuildKit relay, with patience. The guest accepts
/// vsock connections even before buildkitd is listening (it relays to a unix
/// socket), so a failed connect cannot be the cue to start it: send
/// `BuildkitStart` up front, then retry the h2 handshake until buildkitd's
/// socket is accepting. The guest's `ensure` is idempotent, so an already
/// running buildkitd is simply left alone.
async fn dial(engine: &Engine) -> io::Result<(SendRequest<Bytes>, GuestConnection)> {
    let config = builder::guest_config(engine);
    let layers = builder::guest_layers(engine, &mut |_| {}).map_err(|e| io::Error::other(format!("cannot list the BuildKit image layers: {e:?}")))?;
    engine.buildkit_start(&layers, &config).map_err(|e| io::Error::other(format!("cannot start buildkitd: {e:?}")))?;

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match engine.buildkit_connect() {
            Ok(stream) => match h2::client::handshake(GuestStream::new(stream.fd.try_clone()?)?).await {
                Ok(pair) => return Ok(pair),
                Err(e) => diag::debug!("buildkitd is not answering yet", error = e.to_string()),
            },
            Err(e) => diag::debug!("the BuildKit dial failed", error = format!("{e:?}")),
        }
        if Instant::now() > deadline {
            return Err(io::Error::other("the guest never answered the BuildKit dial"));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
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

    /// A fake buildkitd that answers each request chunk with a response chunk
    /// before the request has ended: BuildKit's session and status RPCs are
    /// two-way streams that stay open for a whole build.
    #[test]
    fn relay_streams_both_ways() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let (buildx_io, our_server_io) = tokio::io::duplex(64 * 1024);
            let (our_client_io, fake_io) = tokio::io::duplex(64 * 1024);

            let fake = tokio::spawn(async move {
                let mut server = h2::server::handshake(fake_io).await.unwrap();
                let (call, mut respond) = server.accept().await.unwrap().unwrap();
                tokio::spawn(async move {
                    while server.accept().await.is_some() {}
                });
                let (parts, mut from_buildx) = call.into_parts();
                assert_eq!(parts.uri.path(), "/buildkit.Session");
                let mut to_buildx = respond
                    .send_response(http::Response::builder().status(200).header("content-type", "application/grpc").body(()).unwrap(), false)
                    .unwrap();
                let mut seen = Vec::new();
                while let Some(chunk) = poll_fn(|cx| from_buildx.poll_data(cx)).await {
                    let chunk = chunk.unwrap();
                    from_buildx.flow_control().release_capacity(chunk.len()).unwrap();
                    seen.extend_from_slice(&chunk);
                    if chunk.is_empty() {
                        continue;
                    }
                    // Answer now, without waiting for the request to end.
                    to_buildx.reserve_capacity(chunk.len());
                    poll_fn(|cx| to_buildx.poll_capacity(cx)).await.unwrap().unwrap();
                    let mut echoed = b"echo:".to_vec();
                    echoed.extend_from_slice(&chunk);
                    to_buildx.send_data(Bytes::from(echoed), false).unwrap();
                }
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
                to_buildx.send_trailers(trailers).unwrap();
                seen
            });

            let buildx = tokio::spawn(async move {
                let (mut request, connection) = h2::client::handshake(buildx_io).await.unwrap();
                tokio::spawn(async move { let _ = connection.await; });
                let req = http::Request::builder().method("POST").uri("http://localhost/buildkit.Session").header("content-type", "application/grpc").body(()).unwrap();
                let (reply, mut to_builder) = request.send_request(req, false).unwrap();
                for piece in [&b"ping"[..], &b"pong"[..]] {
                    to_builder.reserve_capacity(piece.len());
                    poll_fn(|cx| to_builder.poll_capacity(cx)).await.unwrap().unwrap();
                    to_builder.send_data(Bytes::copy_from_slice(piece), false).unwrap();
                }
                to_builder.send_data(Bytes::new(), true).unwrap();
                let (_, mut from_builder) = reply.await.unwrap().into_parts();
                let mut got = Vec::new();
                while let Some(chunk) = poll_fn(|cx| from_builder.poll_data(cx)).await {
                    let chunk = chunk.unwrap();
                    from_builder.flow_control().release_capacity(chunk.len()).unwrap();
                    got.extend_from_slice(&chunk);
                }
                let trailers = poll_fn(|cx| from_builder.poll_trailers(cx)).await.unwrap().unwrap();
                assert_eq!(trailers["grpc-status"], "0");
                got
            });

            let (our_request, our_connection) = h2::client::handshake(our_client_io).await.unwrap();
            tokio::spawn(async move { let _ = our_connection.await; });
            let mut server = h2::server::handshake(our_server_io).await.unwrap();
            let (call, respond) = server.accept().await.unwrap().unwrap();
            tokio::spawn(async move {
                while server.accept().await.is_some() {}
            });
            let (parts, from_buildx) = call.into_parts();
            relay(&parts, from_buildx, respond, our_request).await.unwrap();

            let seen = fake.await.unwrap();
            let got = buildx.await.unwrap();
            assert_eq!(seen, b"pingpong");
            assert_eq!(got, b"echo:pingecho:pong");
        });
    }
}
