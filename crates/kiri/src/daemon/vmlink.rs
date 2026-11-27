//! One vsock connection to the guest agent, shared by every daemon thread.
//!
//! The agent answers requests in the order it receives them, and tags
//! container output and exits with the container id. So: senders take the
//! write lock, queue a reply slot and write; a single reader thread hands each
//! reply to the oldest waiting slot and each container event to the engine.

// The file-view replies serve the Finder view, which only macOS has.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Condvar, Mutex};

use kiri_proto::{HEADER, LayerBegin, Msg, Stats, Stream};
use kiri_vmm::Vm;

/// A reply to one request.
#[derive(Debug)]
pub enum Reply {
    LayerStatus(bool),
    LayerStored,
    /// The process's PID, as the agent's kernel numbers it, and whether
    /// its root is still being made (see `VmLink::run`).
    Started(u32, bool),
    Stats(Stats),
    Pong,
    FsStat(FileInfo),
    FsList(Vec<FileInfo>),
    FsData(Vec<u8>),
    Ack,
    ContainerStats(kiri_proto::ContainerStats),
    Top(Vec<String>),
    Listening(Vec<String>),
    UsbNodes(Vec<String>),
    Uplink([u8; 4], [u8; 4]),
    DiskUsage { in_use: u64, capacity: u64 },
    DiskTrimmed { trimmed: u64, in_use: u64, capacity: u64 },
    Error(String),
}

/// One file inside a container, as the file browser sees it.
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub name: String,
    pub mode: u32,
    pub size: u64,
    pub mtime: i64,
    pub mtime_nsec: u32,
}

impl From<kiri_proto::FsEntry<'_>> for FileInfo {
    fn from(e: kiri_proto::FsEntry<'_>) -> FileInfo {
        FileInfo { name: e.name.to_owned(), mode: e.mode, size: e.size, mtime: e.mtime, mtime_nsec: e.mtime_nsec }
    }
}


/// Something a container did, routed to the engine.
#[derive(Debug)]
pub enum Event<'a> {
    Output { id: &'a str, stream: Stream, data: &'a [u8] },
    /// `oom` when the kernel killed a process in it for memory.
    Exited { id: &'a str, code: i32, oom: bool },
    /// The guest is short of memory right now, and what it can see: the
    /// readings that go with a memory kill.
    Pressure { mem_available_kib: u64, mem_stall: u64 },
    /// The connection is gone: the VM stopped.
    Lost,
}

const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const FAST_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const LONG_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

pub struct VmLink {
    rpc: Channel,
    /// Layer digests confirmed unpacked in this guest instance, avoiding
    /// repeated `LayerQuery` round-trips across `create` and `start`.
    layers: Mutex<std::collections::HashSet<String>>,
    /// Kept so the VM lives as long as the link. Behind a mutex only so the
    /// link can be shared between threads; nothing touches it after boot.
    _vm: Mutex<Vm>,
    /// Opens vsock streams without that mutex, so connects run side by side.
    connector: kiri_vmm::Connector,
    /// The agent's folder on a Linux host, where it leaves what `docker
    /// info` should warn about (`host_warnings`).
    #[cfg(target_os = "linux")]
    agent_dir: std::path::PathBuf,
}

impl std::fmt::Debug for VmLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VmLink")
    }
}

/// Transport state and reader loop for the single guest control stream,
/// separated from `kiri_vmm::Vm` so socket timeout and FIFO loss invariants
/// can be unit-tested over a `UnixStream` pair.
struct Channel {
    writer: Mutex<Writer>,
    /// Duplicate of the stream socket used to `shutdown(SHUT_RDWR)` without
    /// acquiring `writer` when a call times out or (on Linux) the agent exits.
    abort_conn: Arc<File>,
    /// Stdin credit per running process; see `input`.
    windows: Arc<Windows>,
    /// The guest's latest `Usage` lines, for `usage`.
    usage: Arc<UsageSlot>,
    pending: Arc<Mutex<VecDeque<SyncSender<Reply>>>>,
    fast_timeout: std::time::Duration,
    long_timeout: std::time::Duration,
    /// Count of long RPCs (`send_layer`, `run`, `AwaitStart`, `trim_disk`)
    /// currently in flight so concurrent fast RPCs queued behind them on the
    /// single-threaded guest do not time out prematurely.
    long_in_flight: std::sync::atomic::AtomicUsize,
}

struct LongCallGuard<'a>(&'a std::sync::atomic::AtomicUsize);

impl Drop for LongCallGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::Release);
    }
}

struct Writer {
    conn: File,
    out: Vec<u8>,
    blob: Vec<u8>,
    write_timeout: std::time::Duration,
}

impl Writer {
    fn new(conn: File, write_timeout: std::time::Duration) -> Writer {
        use std::os::fd::AsRawFd;
        let fd = conn.as_raw_fd();
        // SAFETY: setting O_NONBLOCK on the stream socket so `write_all_timeout`
        // never blocks indefinitely in the kernel (macOS XNU ignores MSG_DONTWAIT
        // on blocking AF_UNIX/AF_VSOCK sockets); `read_frame` polls POLLIN on
        // the reader's dup.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags >= 0 {
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        #[cfg(target_os = "macos")]
        {
            let one: libc::c_int = 1;
            // SAFETY: sets SO_NOSIGPIPE on a descriptor we own so writes return
            // EPIPE instead of raising SIGPIPE when the peer is gone.
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    (&one as *const libc::c_int).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }
        Writer { conn, out: Vec::with_capacity(4096), blob: vec![0; 256 * 1024], write_timeout }
    }

    /// Whether the encoded request is within the agent's frame limit: one
    /// over it ends the agent, and every container with it, so it fails
    /// here alone, before anything is queued or sent.
    fn fits(&self) -> io::Result<()> {
        if self.out.len() > kiri_proto::MAX_FRAME {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("the request is too large for the engine ({} bytes, the limit is {})", self.out.len(), kiri_proto::MAX_FRAME)));
        }
        Ok(())
    }

    fn write(&mut self, windows: &Windows, body: Option<(File, u64)>) -> io::Result<()> {
        self.fits()?;
        let result = self.write_request(body);
        if result.is_err() {
            // A partial frame cannot be retried on this stream. Publish
            // loss now, then wake the reader to do the exit accounting.
            windows.lose();
            use std::os::fd::AsRawFd;
            // SAFETY: conn owns a live stream socket for this entire call.
            unsafe { libc::shutdown(self.conn.as_raw_fd(), libc::SHUT_RDWR); }
        }
        result
    }

    fn write_request(&mut self, body: Option<(File, u64)>) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let fd = self.conn.as_raw_fd();
        write_all_timeout(fd, &self.out, self.write_timeout)?;
        if let Some((mut file, size)) = body {
            let mut left = size;
            while left > 0 {
                let want = left.min(self.blob.len() as u64) as usize;
                let n = file.read(&mut self.blob[..want])?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "layer blob shrank while sending"));
                }
                write_all_timeout(fd, &self.blob[..n], self.write_timeout)?;
                left -= n as u64;
            }
        }
        Ok(())
    }
}

/// Writes `buf` to non-blocking stream socket `fd`, bounding any single stall
/// with `chunk_timeout` so `Writer`'s mutex can never be held forever when the
/// guest agent wedges (#948).
fn write_all_timeout(fd: std::os::fd::RawFd, mut buf: &[u8], chunk_timeout: std::time::Duration) -> io::Result<()> {
    let mut deadline = std::time::Instant::now() + chunk_timeout;
    let mut polled_would_block = false;
    while !buf.is_empty() {
        let step = buf.len().min(64 * 1024);
        #[cfg(target_os = "linux")]
        // SAFETY: `fd` is a live stream socket owned by `Writer`; `buf` is valid.
        let n = unsafe { libc::send(fd, buf.as_ptr().cast(), step, libc::MSG_NOSIGNAL) };
        #[cfg(not(target_os = "linux"))]
        // SAFETY: `fd` is a live non-blocking socket owned by `Writer`; `buf` is valid.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), step) };
        if n > 0 {
            buf = &buf[n as usize..];
            polled_would_block = false;
            if !buf.is_empty() {
                deadline = std::time::Instant::now() + chunk_timeout;
            }
            continue;
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "failed to write whole buffer"));
        }
        let e = io::Error::last_os_error();
        match e.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => {
                let now = std::time::Instant::now();
                if now >= deadline {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "timed out writing to guest agent"));
                }
                if polled_would_block {
                    std::thread::sleep((deadline - now).min(std::time::Duration::from_millis(1)));
                }
                let timeout_ms = deadline
                    .saturating_duration_since(std::time::Instant::now())
                    .as_micros()
                    .div_ceil(1000)
                    .min(i32::MAX as u128) as i32;
                let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
                // SAFETY: one valid pollfd.
                let ready = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
                if ready == 0 {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "timed out writing to guest agent"));
                }
                if ready < 0 {
                    let pe = io::Error::last_os_error();
                    if pe.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(pe);
                }
                polled_would_block = true;
            }
            _ => return Err(e),
        }
    }
    Ok(())
}

/// How much stdin each running process may still be sent before the guest
/// reports some of it consumed. An entry exists from `run`/`exec` until
/// `Exited`; `input` for a process without one is discarded.
#[derive(Default)]
struct Windows {
    credit: Mutex<Credits>,
    changed: Condvar,
}

#[derive(Default)]
struct Credits {
    by_id: HashMap<String, usize>,
    /// The link is gone; nothing will ever be consumed.
    lost: bool,
    loss_handled: bool,
}

impl Windows {
    fn lock(&self) -> std::sync::MutexGuard<'_, Credits> {
        self.credit.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn open(&self, id: &str) {
        self.lock().by_id.insert(id.to_owned(), kiri_proto::INPUT_WINDOW);
    }
    fn close(&self, id: &str) {
        self.lock().by_id.remove(id);
        self.changed.notify_all();
    }
    fn add(&self, id: &str, n: usize) {
        if let Some(c) = self.lock().by_id.get_mut(id) {
            *c = (*c + n).min(kiri_proto::INPUT_WINDOW);
        }
        self.changed.notify_all();
    }
    fn lose(&self) {
        let mut g = self.lock();
        g.lost = true;
        g.by_id.clear();
        drop(g);
        self.changed.notify_all();
    }
    fn finish_loss(&self) {
        self.lock().loss_handled = true;
        self.changed.notify_all();
    }

    /// Wait for exit accounting before replacing the VM. The caller must
    /// hold no state lock needed by Lost, and Lost must not wait for link.
    fn is_lost(&self) -> bool {
        let mut g = self.lock();
        while g.lost && !g.loss_handled {
            g = self.changed.wait(g).unwrap_or_else(|e| e.into_inner());
        }
        g.lost
    }
    /// Waits until `n` bytes may be sent to `id` and takes them. `Ok(false)`:
    /// the process is not running, the bytes should be dropped.
    fn take(&self, id: &str, n: usize) -> io::Result<bool> {
        let mut g = self.lock();
        loop {
            if g.lost {
                return Err(io::Error::other("the VM stopped"));
            }
            let Some(c) = g.by_id.get_mut(id) else { return Ok(false) };
            if *c >= n {
                *c -= n;
                return Ok(true);
            }
            g = self.changed.wait(g).unwrap_or_else(|e| e.into_inner());
        }
    }
}

/// Where the reader thread leaves `Usage` for whoever asked: a count of
/// answers so far, and the latest one.
#[derive(Default)]
struct UsageSlot {
    lines: Mutex<(u64, Option<Vec<String>>)>,
    arrived: Condvar,
}

impl Channel {
    fn new(
        conn: File,
        write_timeout: std::time::Duration,
        fast_timeout: std::time::Duration,
        long_timeout: std::time::Duration,
        on_event: impl Fn(Event<'_>) + Send + 'static,
    ) -> io::Result<Channel> {
        let pending: Arc<Mutex<VecDeque<SyncSender<Reply>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let mut reader = conn.try_clone()?;
        let abort_conn = Arc::new(conn.try_clone()?);
        let queue = pending.clone();
        let windows = Arc::new(Windows::default());
        let wins = windows.clone();
        let usage = Arc::new(UsageSlot::default());
        let slot = usage.clone();
        std::thread::Builder::new().name("kiri-vm-reader".into()).spawn(move || {
            let mut frame = Vec::with_capacity(64 * 1024);
            while read_frame(&mut reader, &mut frame).is_ok() {
                let msg = kiri_proto::decode(&frame);
                let reply = match msg {
                    Ok(Msg::Output { id, stream, data }) => {
                        on_event(Event::Output { id, stream, data });
                        continue;
                    }
                    // Not a reply: the guest measures on a thread and sends
                    // this when done, between other replies.
                    Ok(Msg::Usage(lines)) => {
                        let mut g = slot.lines.lock().unwrap_or_else(|e| e.into_inner());
                        g.0 += 1;
                        g.1 = Some(lines.iter().map(str::to_owned).collect());
                        drop(g);
                        slot.arrived.notify_all();
                        continue;
                    }
                    Ok(Msg::Exited(e)) => {
                        wins.close(e.id);
                        on_event(Event::Exited { id: e.id, code: e.code, oom: e.oom_killed });
                        continue;
                    }
                    Ok(Msg::InputConsumed { id, bytes }) => {
                        wins.add(id, bytes as usize);
                        continue;
                    }
                    Ok(Msg::MemoryPressure(p)) => {
                        on_event(Event::Pressure { mem_available_kib: p.mem_available_kib, mem_stall: p.mem_stall });
                        continue;
                    }
                    Ok(Msg::LayerStatus(have)) => Reply::LayerStatus(have),
                    Ok(Msg::LayerStored(_)) => Reply::LayerStored,
                    Ok(Msg::Started { pid, starting, .. }) => Reply::Started(pid, starting),
                    Ok(Msg::Stats(s)) => Reply::Stats(s),
                    Ok(Msg::Pong(_)) => Reply::Pong,
                    Ok(Msg::FsStat(e)) => Reply::FsStat(FileInfo::from(e)),
                    Ok(Msg::FsList { count, raw }) => Reply::FsList(
                        kiri_proto::fs_entries(count, raw)
                            .map(FileInfo::from)
                            .collect(),
                    ),
                    Ok(Msg::FsData(d)) => Reply::FsData(d.to_vec()),
                    Ok(Msg::Ack) => Reply::Ack,
                    Ok(Msg::ContainerStats(s)) => Reply::ContainerStats(s),
                    Ok(Msg::Top(lines)) => Reply::Top(lines.iter().map(str::to_owned).collect()),
                    Ok(Msg::Listening(lines)) => Reply::Listening(lines.iter().map(str::to_owned).collect()),
                    Ok(Msg::UsbNodes(lines)) => Reply::UsbNodes(lines.iter().map(str::to_owned).collect()),
                    Ok(Msg::Uplink { ip, gateway }) => Reply::Uplink(ip, gateway),
                    Ok(Msg::DiskUsage { in_use, capacity }) => Reply::DiskUsage { in_use, capacity },
                    Ok(Msg::DiskTrimmed { trimmed, in_use, capacity }) => Reply::DiskTrimmed { trimmed, in_use, capacity },
                    Ok(Msg::Error(e)) => Reply::Error(e.to_owned()),
                    Ok(other) => Reply::Error(format!("unexpected message from guest: {other:?}")),
                    Err(e) => Reply::Error(format!("bad frame from guest: {e:?}")),
                };
                if let Some(slot) = queue.lock().unwrap_or_else(|e| e.into_inner()).pop_front() {
                    let _ = slot.send(reply);
                }
            }
            // Publish loss before waking callers: a retry must not borrow
            // this dead link while the engine is still accounting exits.
            wins.lose();
            for slot in queue.lock().unwrap_or_else(|e| e.into_inner()).drain(..) {
                let _ = slot.send(Reply::Error("the VM stopped".into()));
            }
            on_event(Event::Lost);
            wins.finish_loss();
        })?;
        Ok(Channel {
            writer: Mutex::new(Writer::new(conn, write_timeout)),
            abort_conn,
            windows,
            usage,
            pending,
            fast_timeout,
            long_timeout,
            long_in_flight: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Marks the link lost and shuts down the socket without locking `writer`,
    /// waking `kiri-vm-reader` (and any stalled writer) so `pending` drains and
    /// `Event::Lost` fires.
    fn disconnect(&self) {
        self.windows.lose();
        use std::os::fd::AsRawFd;
        // SAFETY: `abort_conn` owns a live stream socket for the lifetime of `Channel`.
        unsafe {
            libc::shutdown(self.abort_conn.as_raw_fd(), libc::SHUT_RDWR);
        }
    }

    fn call_with(
        &self,
        timeout: std::time::Duration,
        is_long: bool,
        encode: impl FnOnce(&mut Vec<u8>),
        body: Option<(File, u64)>,
    ) -> io::Result<Reply> {
        let _long = is_long.then(|| {
            self.long_in_flight.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            LongCallGuard(&self.long_in_flight)
        });
        let (tx, rx) = mpsc::sync_channel(1);
        {
            let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            if self.windows.lock().lost {
                return Err(io::Error::other("the VM stopped"));
            }
            w.out.clear();
            encode(&mut w.out);
            // Too large: refused before a reply slot is queued for it.
            w.fits()?;
            // Queue the slot before writing, so the reply can never arrive first.
            {
                let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
                if self.windows.lock().lost {
                    return Err(io::Error::other("the VM stopped"));
                }
                pending.push_back(tx);
            }
            w.write(&self.windows, body)?;
        }
        let began = std::time::Instant::now();
        let mut deadline = began + timeout;
        loop {
            let wait = deadline.saturating_duration_since(std::time::Instant::now());
            match rx.recv_timeout(wait) {
                Ok(Reply::Error(e)) => return Err(io::Error::other(e)),
                Ok(r) => return Ok(r),
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(io::Error::other("the VM stopped")),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let extended = began + self.long_timeout;
                    if !is_long
                        && self.long_in_flight.load(std::sync::atomic::Ordering::Acquire) > 0
                        && std::time::Instant::now() < extended
                    {
                        deadline = deadline.max(extended);
                        continue;
                    }
                    // `pending` is a positional FIFO: never leave the stream
                    // open after abandoning a reply slot (#948).
                    self.disconnect();
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "guest agent timed out"));
                }
            }
        }
    }

    fn call(&self, encode: impl FnOnce(&mut Vec<u8>), body: Option<(File, u64)>) -> io::Result<Reply> {
        self.call_with(self.fast_timeout, false, encode, body)
    }

    fn call_long(&self, encode: impl FnOnce(&mut Vec<u8>), body: Option<(File, u64)>) -> io::Result<Reply> {
        self.call_with(self.long_timeout, true, encode, body)
    }

    fn send(&self, encode: impl FnOnce(&mut Vec<u8>)) -> io::Result<()> {
        let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        if self.windows.lock().lost {
            return Err(io::Error::other("the VM stopped"));
        }
        w.out.clear();
        encode(&mut w.out);
        w.write(&self.windows, None)
    }
}

impl VmLink {
    pub fn is_lost(&self) -> bool {
        self.rpc.windows.is_lost()
    }

    /// Observes disconnection without waiting for the reader's cleanup.
    pub fn is_disconnected(&self) -> bool {
        self.rpc.windows.lock().lost
    }

    /// Starts the reader thread. `on_event` runs on that thread, so it must
    /// not block for long: it holds up every reply behind it.
    pub fn new(vm: Vm, conn: File, on_event: impl Fn(Event<'_>) + Send + 'static) -> io::Result<VmLink> {
        let rpc = Channel::new(conn, WRITE_TIMEOUT, FAST_CALL_TIMEOUT, LONG_CALL_TIMEOUT, on_event)?;
        // On a Linux host the connection is a socket the agent process
        // shares with its children: one that hung before closing its copy
        // kept it open after the agent was gone, so the reader never saw
        // the end, nothing waiting for a reply ever got one, and the agent
        // was never restarted. Its exit ends the connection here instead.
        // (A VM's vsock ends with the VM.)
        #[cfg(target_os = "linux")]
        {
            let weak = Arc::downgrade(&rpc.abort_conn);
            vm.on_stop(Box::new(move || {
                if let Some(c) = weak.upgrade() {
                    use std::os::fd::AsRawFd;
                    // SAFETY: shutdown on a socket this link still owns.
                    unsafe { libc::shutdown(c.as_raw_fd(), libc::SHUT_RDWR) };
                }
            }));
        }
        Ok(VmLink {
            #[cfg(target_os = "linux")]
            agent_dir: vm.agent_dir().to_owned(),
            rpc,
            layers: Mutex::new(std::collections::HashSet::new()),
            connector: vm.connector(),
            _vm: Mutex::new(vm),
        })
    }

    /// Sends one fast request and waits up to `FAST_CALL_TIMEOUT` for its reply.
    /// A body is opened by the caller, before anything is sent: a blob that
    /// can't be read fails this call alone, not the connection (a request
    /// cut off after its header can't be taken back, and loses the VM).
    fn call(&self, encode: impl FnOnce(&mut Vec<u8>), body: Option<(File, u64)>) -> io::Result<Reply> {
        self.rpc.call(encode, body)
    }

    /// Sends a potentially long-running request (`send_layer`, `run`,
    /// `AwaitStart`, `trim_disk`) with `LONG_CALL_TIMEOUT`.
    fn call_long(&self, encode: impl FnOnce(&mut Vec<u8>), body: Option<(File, u64)>) -> io::Result<Reply> {
        self.rpc.call_long(encode, body)
    }

    /// Sends a message that has no reply.
    fn send(&self, encode: impl FnOnce(&mut Vec<u8>)) -> io::Result<()> {
        self.rpc.send(encode)
    }

    /// What the guest's layers, containers and volumes take on disk: the
    /// `KIND NAME BYTES` lines of `Msg::Usage`, or None if they don't come
    /// within `wait` or the VM stops.
    pub fn usage(&self, wait: std::time::Duration) -> Option<Vec<String>> {
        let asked = self.rpc.usage.lines.lock().unwrap_or_else(|e| e.into_inner()).0;
        self.send(|o| Msg::UsageQuery.encode(o)).ok()?;
        let g = self.rpc.usage.lines.lock().unwrap_or_else(|e| e.into_inner());
        let (g, _) = self.rpc.usage.arrived.wait_timeout_while(g, wait, |g| g.0 == asked).unwrap_or_else(|e| e.into_inner());
        if g.0 == asked { None } else { g.1.clone() }
    }

    pub fn has_layer(&self, digest: &str) -> io::Result<bool> {
        if self.layers.lock().unwrap_or_else(|e| e.into_inner()).contains(digest) {
            return Ok(true);
        }
        match self.call(|o| Msg::LayerQuery(digest).encode(o), None)? {
            Reply::LayerStatus(have) => {
                if have {
                    self.layers.lock().unwrap_or_else(|e| e.into_inner()).insert(digest.to_owned());
                }
                Ok(have)
            }
            other => Err(io::Error::other(format!("expected LayerStatus, got {other:?}"))),
        }
    }

    pub fn send_layer(&self, digest: &str, media_type: &str, blob: &Path) -> io::Result<()> {
        // Opened first, its size from the open file, so a missing blob
        // fails here rather than half-way through the request.
        let file = File::open(blob)?;
        let size = file.metadata()?.len();
        self.call_long(|o| Msg::LayerBegin(LayerBegin { digest, media_type, size }).encode(o), Some((file, size)))?;
        self.layers.lock().unwrap_or_else(|e| e.into_inner()).insert(digest.to_owned());
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run(
        &self,
        id: &str,
        layers: &[String],
        argv: &[String],
        env: &[String],
        cwd: &str,
        user: &str,
        hostname: &str,
        flags: u32,
        net: kiri_proto::Net<'_, String>,
        mounts: &[String],
        limits: &kiri_proto::Limits,
        caps: u64,
        opts: &[String],
        seccomp: &[u8],
        cancel: &std::sync::atomic::AtomicBool,
    ) -> io::Result<u32> {
        self.rpc.windows.open(id);
        // Its process runs, but its root may not be in place yet (a new
        // volume is being filled): the agent answered at once rather than
        // stall every other container meanwhile. The start is reported only
        // once an exec can enter it (#311), or fails as a start.
        let r = self
            .call_long(|o| kiri_proto::encode_run(o, id, layers, argv, env, cwd, user, hostname, flags, net, mounts, limits, caps, opts, seccomp), None)
            .and_then(started)
            .and_then(|(pid, starting)| {
                if starting {
                    // Stopped or removed meanwhile (`Engine::cancel_start`):
                    // told again once the guest surely knows the container,
                    // so a cancel sent before its `Run` arrived still counts.
                    let mut told = false;
                    let ask = || {
                        if !told && cancel.load(std::sync::atomic::Ordering::SeqCst) {
                            told = true;
                            self.cancel_start(id)?;
                        }
                        self.call_long(|o| Msg::AwaitStart { id }.encode(o), None)
                    };
                    wait_started(ask, std::thread::sleep)?;
                }
                Ok(pid)
            });
        if r.is_err() {
            self.rpc.windows.close(id);
        }
        r
    }

    fn ack(&self, encode: impl FnOnce(&mut Vec<u8>)) -> io::Result<()> {
        match self.call(encode, None)? {
            Reply::Ack => Ok(()),
            other => Err(io::Error::other(format!("expected Ack, got {other:?}"))),
        }
    }

    pub fn update(&self, id: &str, limits: kiri_proto::Limits) -> io::Result<()> {
        self.ack(|o| Msg::Update { id, limits }.encode(o))
    }

    pub fn freeze(&self, id: &str, frozen: bool) -> io::Result<()> {
        self.ack(|o| Msg::Freeze { id, frozen }.encode(o))
    }

    pub fn container_stats(&self, id: &str) -> io::Result<kiri_proto::ContainerStats> {
        match self.call(|o| Msg::StatsQuery { id }.encode(o), None)? {
            Reply::ContainerStats(s) => Ok(s),
            other => Err(io::Error::other(format!("expected ContainerStats, got {other:?}"))),
        }
    }

    pub fn top(&self, id: &str) -> io::Result<Vec<String>> {
        match self.call(|o| Msg::TopQuery { id }.encode(o), None)? {
            Reply::Top(lines) => Ok(lines),
            other => Err(io::Error::other(format!("expected Top, got {other:?}"))),
        }
    }

    /// The container's LISTEN lines from /proc/net/tcp and tcp6.
    pub fn listening(&self, id: &str) -> io::Result<Vec<String>> {
        match self.call(|o| Msg::ListenQuery { id }.encode(o), None)? {
            Reply::Listening(lines) => Ok(lines),
            other => Err(io::Error::other(format!("expected Listening, got {other:?}"))),
        }
    }

    /// `PORT\tPATH\tWHAT` for the nodes of the USB devices attached to the
    /// VM (`Msg::UsbNodes`).
    pub fn usb_nodes(&self) -> io::Result<Vec<String>> {
        match self.call(|o| Msg::UsbNodesQuery.encode(o), None)? {
            Reply::UsbNodes(lines) => Ok(lines),
            other => Err(io::Error::other(format!("expected UsbNodes, got {other:?}"))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    /// Routes `dst/prefix` through `via` in the VM, or removes that route.
    pub fn route(&self, dst: [u8; 4], prefix: u8, via: [u8; 4], add: bool) -> io::Result<()> {
        self.ack(|o| Msg::Route { dst, prefix, via, add }.encode(o))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn net_attach(&self, id: &str, n: u32, bridge: &str, ip: [u8; 4], prefix: u8, gateway: [u8; 4], dns_names: &[String], opts: &[String]) -> io::Result<()> {
        let ifname = format!("eth{n}");
        self.ack(|o| kiri_proto::encode_net_attach(o, id, &ifname, bridge, ip, prefix, gateway, dns_names, opts))
    }

    pub fn net_detach(&self, id: &str, n: u32, bridge: &str, ip: [u8; 4]) -> io::Result<()> {
        let ifname = format!("eth{n}");
        self.ack(|o| Msg::NetDetach { id, ifname: &ifname, bridge, ip }.encode(o))
    }

    /// Replaces the DNS names the guest resolves for a container's address
    /// on a bridge after `docker rename`; `v4` is whether the network has
    /// IPv4 addresses. No reply, which is why the protocol is 8: an older
    /// agent would answer an unknown frame with an error, and the next
    /// request would take it for its own reply. The guest refuses a frame
    /// that names no running container's address.
    pub fn dns_rename(&self, id: &str, bridge: &str, ip: [u8; 4], ip6: Option<[u8; 16]>, v4: bool, names: &[String]) -> io::Result<()> {
        self.send(|o| kiri_proto::encode_dns_rename(o, id, bridge, ip, ip6, v4, names))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn exec(&self, container_id: &str, exec_id: &str, argv: &[String], env: &[String], cwd: &str, user: &str, flags: u32, caps: u64, opts: &[String]) -> io::Result<u32> {
        self.rpc.windows.open(exec_id);
        let r = self.call(|o| kiri_proto::encode_exec(o, container_id, exec_id, argv, env, cwd, user, flags, caps, opts), None).and_then(started).map(|(pid, _)| pid);
        if r.is_err() {
            self.rpc.windows.close(exec_id);
        }
        r
    }

    /// Sends stdin for a process. Blocks while the guest already holds
    /// `INPUT_WINDOW` bytes it has not consumed, so the pressure reaches the
    /// client (its write blocks) instead of the agent dropping input.
    pub fn input(&self, id: &str, data: &[u8]) -> io::Result<()> {
        // Frames are bounded, so large writes go in pieces.
        for piece in data.chunks(kiri_proto::MAX_OUTPUT_CHUNK) {
            if !self.rpc.windows.take(id, piece.len())? {
                return Ok(());
            }
            self.send(|o| Msg::Input { id, data: piece }.encode(o))?;
        }
        Ok(())
    }

    pub fn close_stdin(&self, id: &str) -> io::Result<()> {
        self.send(|o| Msg::CloseStdin { id }.encode(o))
    }

    pub fn resize(&self, id: &str, rows: u16, cols: u16) -> io::Result<()> {
        self.send(|o| Msg::Resize { id, rows, cols }.encode(o))
    }

    /// The VM's address on the NAT network and its gateway (the Mac's own
    /// address there). `Err` with no lease yet, or from an older agent.
    pub fn uplink(&self) -> io::Result<([u8; 4], [u8; 4])> {
        match self.call(|o| Msg::UplinkQuery.encode(o), None)? {
            Reply::Uplink(ip, gateway) => Ok((ip, gateway)),
            Reply::Error(e) => Err(io::Error::other(e)),
            other => Err(io::Error::other(format!("expected Uplink, got {other:?}"))),
        }
    }

    /// Configures the VM's uplink (`eth0`) directly when macOS DHCP did not
    /// answer. Ignored by the guest if it already obtained a DHCP lease.
    pub fn set_uplink(&self, ip: [u8; 4], prefix: u8, gateway: [u8; 4], dns: [u8; 4]) -> io::Result<()> {
        self.ack(|o| Msg::SetUplink { ip, prefix, gateway, dns }.encode(o))
    }

    /// Forwards a published port in the kernel (on a Linux host; in the VM,
    /// from the NAT network). `Err` means the agent could not; the caller
    /// falls back to relaying.
    pub fn publish(&self, p: kiri_proto::Publish<'_>) -> io::Result<()> {
        match self.call(|o| Msg::Publish(p).encode(o), None)? {
            Reply::Ack => Ok(()),
            Reply::Error(e) => Err(io::Error::other(e)),
            other => Err(io::Error::other(format!("expected Ack, got {other:?}"))),
        }
    }
    pub fn unpublish(&self, id: &str) -> io::Result<()> {
        // No reply: this runs when a container exits, on the link's own reader
        // thread, which could not wait for one.
        self.send(|o| Msg::Unpublish { id }.encode(o))
    }
    pub fn remove_volume(&self, name: &str) -> io::Result<()> {
        self.send(|o| Msg::RemoveVolume { name }.encode(o))
    }

    /// A removed network's bridge goes, with its addresses, routes and DNS
    /// server (and the IPv6 NAT table with the last IPv6 network).
    pub fn remove_bridge(&self, bridge: &str) -> io::Result<()> {
        self.send(|o| Msg::RemoveBridge { bridge }.encode(o))
    }

    /// Files the Mac changed under bind mounts (`OP\tPATH` lines, PATH in
    /// the VM), for the guest to raise as inotify events. No reply.
    pub fn fs_events<S: AsRef<str>>(&self, lines: &[S]) -> io::Result<()> {
        self.send(|o| kiri_proto::encode_fs_events(o, lines))
    }

    /// Sets the IPv4 CIDR prefixes (`a.b.c.d/prefix`) whose outbound container
    /// TCP connections the guest redirects to the host egress dialer. No reply.
    pub fn set_egress_routes<S: AsRef<str>>(&self, routes: &[S]) -> io::Result<()> {
        self.send(|o| kiri_proto::encode_set_egress_routes(o, routes))
    }

    /// The Mac's wall clock, for the guest. Sent at boot, and again while it
    /// runs: the VM's clock stops while the Mac sleeps.
    pub fn set_time(&self) -> io::Result<()> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        self.send(|o| Msg::SetTime(now.as_nanos() as u64).encode(o))
    }

    /// Tells the guest which stopped containers still exist; it deletes the rest.
    pub fn retain(&self, ids: &[String]) -> io::Result<()> {
        self.send(|o| kiri_proto::encode_retain(o, ids))
    }

    /// Evicts `digests` from the in-memory unpacked-layer cache so the next
    /// `has_layer` asks the guest directly (used when `run` reports a layer
    /// missing on disk inside a running guest).
    pub fn forget_layers(&self, digests: &[String]) {
        let mut cached = self.layers.lock().unwrap_or_else(|e| e.into_inner());
        for d in digests {
            cached.remove(d.as_str());
        }
    }

    /// Tells the guest which unpacked layers are still used; it deletes the rest.
    pub fn retain_layers(&self, digests: &[String]) -> io::Result<()> {
        {
            let keep: std::collections::HashSet<&str> = digests.iter().map(String::as_str).collect();
            self.layers.lock().unwrap_or_else(|e| e.into_inner()).retain(|d| keep.contains(d.as_str()));
        }
        self.send(|o| kiri_proto::encode_retain_layers(o, digests))
    }

    /// Waits for every earlier no-reply frame (such as `retain_layers`) to
    /// finish on the guest: the agent processes frames in order.
    pub fn ping(&self) -> io::Result<()> {
        match self.call(|o| Msg::Ping(0).encode(o), None)? {
            Reply::Pong => Ok(()),
            other => Err(io::Error::other(format!("expected Pong, got {other:?}"))),
        }
    }

    pub fn kill(&self, id: &str, signal: u32) -> io::Result<()> {
        self.send(|o| Msg::Kill { id, signal }.encode(o))
    }

    /// See `Msg::CancelStart`. No reply: the start's own `AwaitStart` hears
    /// how it ended.
    pub fn cancel_start(&self, id: &str) -> io::Result<()> {
        self.send(|o| Msg::CancelStart { id }.encode(o))
    }

    pub fn remove(&self, id: &str) -> io::Result<()> {
        self.send(|o| Msg::Remove { id }.encode(o))
    }

    /// Sets the balloon so the guest runs in `bytes`; returns the old target.
    pub fn set_memory_target(&self, bytes: u64) -> Option<u64> {
        self._vm.lock().unwrap_or_else(|e| e.into_inner()).set_memory_target(bytes)
    }

    /// Accepts guest-initiated streams on `port`.
    pub fn listen(&self, port: u32, handler: kiri_vmm::Handler) -> io::Result<()> {
        self._vm.lock().unwrap_or_else(|e| e.into_inner()).listen(port, handler)
    }

    /// A new stream to a port the guest agent listens on.
    pub fn connect(&self, port: u32) -> io::Result<kiri_vmm::VsockStream> {
        self.connector.connect(port)
    }

    pub fn fs_stat(&self, id: &str, path: &str) -> io::Result<FileInfo> {
        match self.call(|o| Msg::FsStatRequest { id, path }.encode(o), None)? {
            Reply::FsStat(f) => Ok(f),
            other => Err(io::Error::other(format!("expected FsStat, got {other:?}"))),
        }
    }

    pub fn fs_list(&self, id: &str, path: &str) -> io::Result<Vec<FileInfo>> {
        match self.call(|o| Msg::FsListRequest { id, path }.encode(o), None)? {
            Reply::FsList(v) => Ok(v),
            other => Err(io::Error::other(format!("expected FsList, got {other:?}"))),
        }
    }

    pub fn fs_read(&self, id: &str, path: &str, offset: u64, len: u32) -> io::Result<Vec<u8>> {
        match self.call(|o| Msg::FsRead { id, path, offset, len }.encode(o), None)? {
            Reply::FsData(d) => Ok(d),
            other => Err(io::Error::other(format!("expected FsData, got {other:?}"))),
        }
    }

    pub fn fs_read_link(&self, id: &str, path: &str) -> io::Result<Vec<u8>> {
        match self.call(|o| Msg::FsReadLink { id, path }.encode(o), None)? {
            Reply::FsData(d) => Ok(d),
            other => Err(io::Error::other(format!("expected FsData, got {other:?}"))),
        }
    }

    pub fn stats(&self) -> io::Result<Stats> {
        match self.call(|o| Msg::StatsRequest.encode(o), None)? {
            Reply::Stats(s) => Ok(s),
            other => Err(io::Error::other(format!("expected Stats, got {other:?}"))),
        }
    }

    pub fn disk_usage(&self) -> io::Result<(u64, u64)> {
        match self.call(|o| Msg::DiskUsageQuery.encode(o), None)? {
            Reply::DiskUsage { in_use, capacity } => Ok((in_use, capacity)),
            other => Err(io::Error::other(format!("expected DiskUsage, got {other:?}"))),
        }
    }

    pub fn trim_disk(&self) -> io::Result<(u64, u64, u64)> {
        match self.call_long(|o| Msg::TrimDisk.encode(o), None)? {
            Reply::DiskTrimmed { trimmed, in_use, capacity } => Ok((trimmed, in_use, capacity)),
            other => Err(io::Error::other(format!("expected DiskTrimmed, got {other:?}"))),
        }
    }

    /// What the agent on a Linux host found wrong with the host for `docker
    /// info`: a firewall that drops the containers' traffic and that Kiri
    /// may not change (an nftables.conf's chain), with the rules that let
    /// them through. A VM has no host firewall to warn about.
    pub fn host_warnings(&self) -> Vec<String> {
        #[cfg(target_os = "linux")]
        if let Ok(text) = std::fs::read_to_string(self.agent_dir.join("firewall-warnings")) {
            return text.lines().filter(|l| !l.is_empty()).map(str::to_owned).collect();
        }
        Vec::new()
    }

    /// Asks the guest to power off. The VM itself is released when the link drops.
    pub fn shutdown(&self) {
        let _ = self.send(|o| Msg::Shutdown.encode(o));
    }

    /// Success confirms both shutdown and release of the old generation's
    /// resources, even while relay threads retain this link.
    pub fn retire(&self) -> io::Result<()> {
        self._vm.lock().unwrap_or_else(|e| e.into_inner())
            .retire(std::time::Duration::from_secs(10), std::time::Duration::from_secs(10))
    }

    #[cfg(test)]
    pub(super) fn hold_retirement(&self) -> std::sync::MutexGuard<'_, Vm> {
        self._vm.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[cfg(test)]
    pub(super) fn interrupted_layer(&self, blob: &Path) -> io::Result<()> {
        self.call(|out| Msg::LayerBegin(LayerBegin {
            digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip", size: 1,
        }).encode(out), Some((File::open(blob)?, 1))).map(|_| ())
    }

    /// Waits for the guest to stop after `shutdown`, and forces it if it has
    /// not within `timeout`. False if it had to be forced.
    ///
    /// In a VM the guest flushes its disk before powering off; stopping the
    /// VM before then (as dropping it does) loses what was still cached, and
    /// files written shortly before come back empty. On a Linux host the
    /// agent kills what is left and removes its bridges and nftables table
    /// first; an agent left behind kept its containers, ports and sockets,
    /// and the next daemon could not start.
    pub fn wait_stopped(&self, timeout: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        let vm = self._vm.lock().unwrap_or_else(|e| e.into_inner());
        while vm.is_running() {
            if std::time::Instant::now() >= deadline {
                vm.force_stop();
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        true
    }
}

/// The PID a `Run` or `Exec` was answered with, and whether its root is
/// still being made.
fn started(r: Reply) -> io::Result<(u32, bool)> {
    match r {
        Reply::Started(pid, starting) => Ok((pid, starting)),
        other => Err(io::Error::other(format!("expected Started, got {other:?}"))),
    }
}

/// The pauses between `AwaitStart` asks: the first at once, then 1, 2, 4,
/// 8, 16 ms, then every 25 ms. Most volumes fill within the first few; a
/// big one is noticed within 25 ms of being done.
fn await_backoff() -> impl Iterator<Item = std::time::Duration> {
    [0, 1, 2, 4, 8, 16].into_iter().chain(std::iter::repeat(25)).map(std::time::Duration::from_millis)
}

/// Asks (`ask` sends `AwaitStart`) until the agent says the root is in
/// place. An error fails the start, as it would have failed the `Run`
/// itself: the child ended before its root was ready (the agent answers
/// with the child's own reason, and sends no `Exited`), or the VM stopped.
/// No lock is held while it sleeps: `call` takes and lets go of its own for
/// each ask.
fn wait_started(mut ask: impl FnMut() -> io::Result<Reply>, mut sleep: impl FnMut(std::time::Duration)) -> io::Result<()> {
    for pause in await_backoff() {
        if !pause.is_zero() {
            sleep(pause);
        }
        match ask()? {
            Reply::Started(_, true) => {}
            Reply::Started(_, false) => return Ok(()),
            other => return Err(io::Error::other(format!("expected Started, got {other:?}"))),
        }
    }
    unreachable!("the backoff never ends")
}

fn read_exact_blocking(fd: std::os::fd::RawFd, mut buf: &mut [u8]) -> io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: `fd` is a valid descriptor and `buf` is owned mutable memory.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            buf = &mut buf[n as usize..];
            continue;
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
        }
        let e = io::Error::last_os_error();
        match e.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => {
                let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
                // SAFETY: one valid pollfd; wakes on incoming bytes or SHUT_RDWR/EOF.
                let ready = unsafe { libc::poll(&mut pfd, 1, -1) };
                if ready < 0 {
                    let pe = io::Error::last_os_error();
                    if pe.kind() != io::ErrorKind::Interrupted {
                        return Err(pe);
                    }
                }
            }
            _ => return Err(e),
        }
    }
    Ok(())
}

fn read_frame(conn: &mut File, buf: &mut Vec<u8>) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = conn.as_raw_fd();
    buf.resize(4, 0);
    read_exact_blocking(fd, &mut buf[..4])?;
    let len = kiri_proto::frame_len(buf[..4].try_into().expect("4 bytes"))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;
    buf.resize(len.max(HEADER), 0);
    read_exact_blocking(fd, &mut buf[4..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn a_starting_container_is_asked_about_until_its_root_is_in_place() {
        use std::time::Duration;
        let ms = |v: &[u64]| v.iter().map(|&m| Duration::from_millis(m)).collect::<Vec<_>>();
        assert_eq!(await_backoff().take(9).collect::<Vec<_>>(), ms(&[0, 1, 2, 4, 8, 16, 25, 25, 25]));
        // Starting twice, then in place: three asks, the first at once.
        let mut answers = vec![Reply::Started(7, false), Reply::Started(7, true), Reply::Started(7, true)];
        let (mut asks, mut slept) = (0, Vec::new());
        assert!(wait_started(|| { asks += 1; Ok(answers.pop().unwrap()) }, |d| slept.push(d)).is_ok());
        assert_eq!((asks, slept), (3, ms(&[1, 2])));
        // An error (the child failed before its root was ready, the VM
        // stopped) ends the wait and fails the start with it.
        let mut answers = vec![Err(io::Error::other("run c1: mount /payload: No space left on device")), Ok(Reply::Started(7, true))];
        let mut asks = 0;
        let e = wait_started(|| { asks += 1; answers.pop().unwrap() }, |_| {}).unwrap_err();
        assert_eq!((asks, e.to_string().as_str()), (2, "run c1: mount /payload: No space left on device"));
    }

    #[test]
    fn a_failed_write_disconnects_before_the_reader_accounts_loss() {
        let (socket, peer) = UnixStream::pair().unwrap();
        socket.shutdown(std::net::Shutdown::Write).unwrap();
        let mut writer = Writer::new(std::os::fd::OwnedFd::from(socket).into(), std::time::Duration::from_millis(50));
        writer.out = vec![1];
        let windows = Windows::default();
        assert!(writer.write(&windows, None).is_err());
        assert!(windows.lock().lost, "a writer failure must publish loss before a start can record an ordinary failure");
        assert!(!windows.lock().loss_handled, "only the reader owns exit accounting");
        let mut peer = peer;
        assert_eq!(peer.read(&mut [0]).unwrap(), 0, "the failed transport is closed in both directions");
    }

    /// The agent ends on a frame over its limit (every container with it):
    /// a request that large, such as a container whose environment is over
    /// 1 MiB, fails alone and nothing of it is sent.
    #[test]
    fn a_request_over_the_agents_frame_limit_is_refused_unsent() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        // Never blocks on a peer that does not read: a request that were
        // sent fills the socket and fails with WouldBlock instead.
        socket.set_nonblocking(true).unwrap();
        let mut writer = Writer::new(std::os::fd::OwnedFd::from(socket).into(), std::time::Duration::from_millis(50));
        writer.out = vec![0; kiri_proto::MAX_FRAME + 1];
        let windows = Windows::default();
        let e = writer.write(&windows, None).unwrap_err();
        assert!(e.to_string().contains("too large"), "{e}");
        assert!(!windows.lock().lost, "the link stays");
        assert_eq!(peer.read(&mut [0; 16]).map_err(|e| e.kind()), Err(io::ErrorKind::WouldBlock), "nothing sent");
        writer.out = vec![7; 8];
        assert!(writer.write(&windows, None).is_ok());
        peer.set_nonblocking(false).unwrap();
        let mut got = [0; 8];
        peer.read_exact(&mut got).unwrap();
        assert_eq!(got, [7; 8], "the link carries the next request");
    }

    /// A request of exactly the agent's limit is still sent.
    #[test]
    fn a_request_at_the_agents_frame_limit_fits() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let mut writer = Writer::new(std::os::fd::OwnedFd::from(socket).into(), std::time::Duration::from_millis(50));
        writer.out = vec![0; kiri_proto::MAX_FRAME];
        assert!(writer.fits().is_ok());
        writer.out.push(0);
        assert!(writer.fits().is_err());
    }

    /// Regression test for #948(a): when the peer reads a request frame and
    /// never replies, `call` times out instead of blocking forever, shuts down
    /// the socket (preserving the positional `pending` FIFO invariant), marks
    /// `windows.lost`, wakes `kiri-vm-reader` to emit `Event::Lost`, and wakes
    /// any concurrent callers without deadlocking.
    #[test]
    fn wedged_peer_that_never_replies_times_out_and_closes_transport() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::{Duration, Instant};

        let (socket, peer) = UnixStream::pair().unwrap();
        let mut peer_file: File = std::os::fd::OwnedFd::from(peer).into();
        let lost_events = Arc::new(AtomicUsize::new(0));
        let lost_events_cb = lost_events.clone();
        let channel = Arc::new(
            Channel::new(
                std::os::fd::OwnedFd::from(socket).into(),
                Duration::from_millis(200),
                Duration::from_millis(60),
                Duration::from_millis(250),
                move |ev| {
                    if matches!(ev, Event::Lost) {
                        lost_events_cb.fetch_add(1, Ordering::SeqCst);
                    }
                },
            )
            .unwrap(),
        );

        let reader_peer = std::thread::spawn(move || {
            let mut frame = Vec::new();
            read_frame(&mut peer_file, &mut frame).unwrap();
            assert!(matches!(kiri_proto::decode(&frame), Ok(Msg::Ping(0))));
            let mut sink = [0u8; 64];
            while peer_file.read(&mut sink).unwrap() > 0 {}
        });

        let ch2 = channel.clone();
        let second = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            ch2.call_with(Duration::from_secs(5), false, |o| Msg::StatsRequest.encode(o), None)
        });

        let began = Instant::now();
        let err = channel.call(|o| Msg::Ping(0).encode(o), None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
        assert!(began.elapsed() < Duration::from_secs(2));
        assert!(channel.windows.lock().lost, "timeout must mark windows.lost immediately");

        let second_err = second.join().unwrap().unwrap_err();
        assert!(
            second_err.to_string().contains("the VM stopped"),
            "second caller woken by pending drain without waiting 5s: {second_err}"
        );
        assert!(began.elapsed() < Duration::from_secs(2));
        reader_peer.join().unwrap();
        assert!(channel.windows.is_lost(), "reader finished loss accounting without deadlock");
        assert_eq!(lost_events.load(Ordering::SeqCst), 1, "Event::Lost emitted exactly once");
    }

    /// Regression test for #948(b): when the socket send buffer is full and
    /// the peer never reads, `Writer::write` fails within `write_timeout`
    /// instead of holding `Channel::writer` mutex forever and piling up
    /// hundreds of `kiri-api` threads.
    #[test]
    fn full_socket_buffer_times_out_write_and_releases_writer_mutex() {
        use std::time::{Duration, Instant};

        let (socket, _peer) = UnixStream::pair().unwrap();
        let channel = Arc::new(
            Channel::new(
                std::os::fd::OwnedFd::from(socket).into(),
                Duration::from_millis(50),
                Duration::from_millis(200),
                Duration::from_millis(400),
                |_| {},
            )
            .unwrap(),
        );

        {
            use std::os::fd::AsRawFd;
            let fd = channel.abort_conn.as_raw_fd();
            let chunk = [0xabu8; 4096];
            loop {
                // SAFETY: valid buffer and non-blocking stream socket fd.
                let n = unsafe { libc::write(fd, chunk.as_ptr().cast(), chunk.len()) };
                if n <= 0 {
                    break;
                }
            }
        }

        let ch2 = channel.clone();
        let contender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            ch2.send(|o| Msg::Ping(1).encode(o))
        });

        let began = Instant::now();
        let big = vec![b'x'; 256 * 1024];
        let err = channel.send(|o| Msg::Input { id: "c1", data: &big }.encode(o)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
        assert!(began.elapsed() < Duration::from_secs(2), "writer mutex released promptly");
        assert!(channel.windows.lock().lost, "stalled write marks link lost");

        let contender_err = contender.join().unwrap().unwrap_err();
        assert!(contender_err.to_string().contains("the VM stopped") || contender_err.kind() == io::ErrorKind::TimedOut, "{contender_err}");
        assert!(channel.windows.is_lost(), "reader exited after SHUT_RDWR");
    }

    #[test]
    fn forget_layers_evicts_only_requested_digests() {
        let layers = Mutex::new(std::collections::HashSet::from([
            "sha256:aaa".to_owned(),
            "sha256:bbb".to_owned(),
            "sha256:ccc".to_owned(),
        ]));
        {
            let mut cached = layers.lock().unwrap();
            for d in &["sha256:aaa".to_owned(), "sha256:ccc".to_owned()] {
                cached.remove(d.as_str());
            }
        }
        let left = layers.into_inner().unwrap();
        assert_eq!(left.len(), 1);
        assert!(left.contains("sha256:bbb"));
    }
}
