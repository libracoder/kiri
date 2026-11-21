//! Accepts docker clients on the pipe and carries them over the bridge.

use std::collections::HashMap;
use std::io::{self, BufReader, Read, Write};
use std::os::windows::process::CommandExt;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::pipe::Pipe;
use crate::refuse::{is_head, refusal, Arrival, REQUEST_WAIT};

/// A frame: kind, connection id (u32 BE), length (u32 BE), then the data.
/// The same as in crates/kiri/src/bridge.rs.
const OPEN: u8 = 1;
const DATA: u8 = 2;
/// No more data from this side (a half-close).
const EOF: u8 = 3;
/// The connection is gone, both ways. From a bridge, its data (when there
/// is any) is why it could not reach the engine.
const CLOSE: u8 = 4;
/// Credit back: how many bytes of this connection the ACK's sender has
/// handed on (u32 BE). For connection 0, the bridge's hello: it does flow
/// control (crates/kiri/src/bridge.rs says how), and with 1 as its data it
/// answers PING.
const ACK: u8 = 5;
/// From the bridge, on connection 0: a line of what it did to reach the
/// engine (started it, and how that went), for this side's log.
const NOTE: u8 = 6;
/// On connection 0: asks a bridge that said it answers for a PING back.
const PING: u8 = 7;

/// Bytes of one connection one way that may be unacknowledged; the same
/// as the bridge's.
const WINDOW: usize = 4 << 20;
const ACK_EVERY: usize = WINDOW / 4;
/// A connection with credit that is sent past it is closed once this much
/// is queued; one without (an older bridge) at what was 256 frames.
const LIMIT: usize = 2 * WINDOW;
const LIMIT_NO_CREDIT: usize = 256 * 64 * 1024;
/// How long a bridge may take to say hello after wsl.exe was started for
/// it. Every bridge says it as it starts, so one that has not by then is a
/// wsl.exe that hangs (as it can right after Windows wakes): it is ended and
/// a new one started. Long enough for WSL to start from cold.
const HELLO_WAIT: Duration = Duration::from_secs(20);
/// A bridge not heard from for this long is asked for a PING before a new
/// connection goes on it, and ended when none comes within PING_WAIT: a
/// wsl.exe that outlived what it was connected to (WSL restarted while
/// Windows slept) takes connections and never answers them.
const QUIET: Duration = Duration::from_secs(2);
const PING_WAIT: Duration = Duration::from_secs(10);
/// How many bridges in a row a connection finds not answering before its
/// client is told why.
const SILENT_MOST: u32 = 2;
/// After a client was told WSL is not answering, those that come within
/// this are told the same once the bridge they find has had TOLD_GRACE to
/// say hello and has not: docker asks twice for one command (its ping,
/// then the request), and the second is not made to wait as long again.
/// A WSL that answers again says hello well within the grace, so the
/// error does not outlast its cause.
const TOLD_HOLD: Duration = Duration::from_secs(15);
const TOLD_GRACE: Duration = Duration::from_millis(1500);
/// How long a new connection keeps starting a bridge that dies at once
/// (wsl.exe right after Windows wakes, while WSL itself starts again)
/// before the client is told why; one try every BRIDGE_RETRY.
const BRIDGE_WAIT: Duration = Duration::from_secs(10);
const BRIDGE_RETRY: Duration = Duration::from_millis(500);

/// wsl.exe without a console window flashing up.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone)]
pub struct Config {
    pub distro: Option<String>,
    pub pipe: String,
    pub socket: String,
    pub kiri: String,
}

impl Config {
    pub fn from_args() -> Config {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
        Config {
            // The distro setup chose, unless one is named.
            distro: flag("--distro").or_else(crate::setup::distro),
            pipe: flag("--pipe").unwrap_or_else(|| r"\\.\pipe\kiri".into()),
            // Where contrib/wsl/install.sh runs the daemon.
            socket: flag("--socket").unwrap_or_else(|| "/var/lib/kiri-daemon/.kiri/run/docker.sock".into()),
            kiri: flag("--kiri").unwrap_or_else(|| "/usr/local/bin/kiri".into()),
        }
    }
}

static HUB: std::sync::OnceLock<Arc<Hub>> = std::sync::OnceLock::new();

/// Setup isn't finished: a docker command with no engine to answer it is
/// told so, rather than having its connection simply closed.
static SETUP_PENDING: AtomicBool = AtomicBool::new(false);

pub fn set_setup_pending(pending: bool) {
    SETUP_PENDING.store(pending, Ordering::SeqCst);
}

const SETUP_UNFINISHED: &str = "Kiri's setup isn't finished: open Kiri to finish it";

fn setup_pending() -> bool {
    SETUP_PENDING.load(Ordering::SeqCst)
}

/// What a client the engine cannot serve is told (see `refuse::message`),
/// unless setup is unfinished: then that is why.
fn message(why: Option<&str>) -> String {
    if setup_pending() { SETUP_UNFINISHED.to_owned() } else { crate::refuse::message(why) }
}

/// Answers a client the engine cannot serve. True if it answered.
fn refuse(pipe: &Pipe, head: bool, message: &str) -> bool {
    if pipe.write(&refusal(head, message)).is_err() {
        return false;
    }
    pipe.flush();
    let _ = pipe.write(&[]);
    true
}

/// `refuse`, for a client whose request has not been read: read first, as
/// a reply that comes before the request is one Go's HTTP client calls
/// unsolicited and drops.
fn refuse_new(pipe: &Pipe, message: &str) -> bool {
    let mut buf = vec![0u8; 64 * 1024];
    let n = pipe.read_within(&mut buf, Some(REQUEST_WAIT)).unwrap_or(0);
    refuse(pipe, is_head(&buf[..n]), message)
}

/// Docker's own pipe. docker-py, the Go and Java SDKs, Testcontainers and
/// IDE plugins open it without reading docker contexts, so Kiri serves it
/// too while no other engine does.
pub const DOCKER_ENGINE: &str = r"\\.\pipe\docker_engine";

/// Processes that serve docker_engine themselves: while one runs, the pipe
/// is theirs, and Kiri lets go of it (Docker Desktop cannot start its own
/// while any instance of Kiri's is open).
const OTHER_ENGINES: &[&str] = &["Docker Desktop.exe", "com.docker.backend.exe", "dockerd.exe", "Rancher Desktop.exe"];

/// Carries connections to `distro` from now on (setup has just made it);
/// the bridge to the old one is left to end.
pub fn set_distro(distro: &str) {
    if let Some(hub) = HUB.get() {
        hub.cfg.lock().unwrap_or_else(PoisonError::into_inner).distro = Some(distro.to_owned());
        hub.retire();
    }
}

/// The engine in WSL was replaced by this version's: connections from now
/// on go over a bridge run from the new one. The old bridge, started from
/// the engine that was there before, carries the connections it has to
/// their end.
pub fn renew_bridge() {
    if let Some(hub) = HUB.get()
        && hub.retire()
    {
        log("bridge: the engine in WSL was replaced; new connections get a bridge from the new one");
    }
}

/// Serves the pipe on threads of its own. Fails if another kiri-win
/// already serves it.
pub fn start(cfg: Config) -> io::Result<()> {
    let first = Pipe::create(&cfg.pipe, true)?;
    log(&format!("serving {} ({})", cfg.pipe, cfg.distro.as_deref().unwrap_or("default distro")));
    let pipe_name = cfg.pipe.clone();
    let hub = Arc::new(Hub::new(cfg, Box::new(Bridge::start), Limits::default()));
    let _ = HUB.set(hub.clone());
    let h = hub.clone();
    thread::Builder::new().name("kiri-docker-engine".into()).spawn(move || docker_engine(&h))?;
    // Start WSL now, so the first docker command does not wait for it.
    let h = hub.clone();
    thread::spawn(move || {
        if let Err(e) = h.bridge() {
            if e.kind() != io::ErrorKind::NotConnected {
                log(&format!("bridge: {e}"));
            }
        }
    });
    thread::Builder::new().name("kiri-pipe".into()).spawn(move || {
        let mut pipe = first;
        loop {
            if let Err(e) = pipe.connect() {
                log(&format!("connect: {e}"));
            } else {
                let hub = hub.clone();
                thread::spawn(move || serve(&hub, pipe));
            }
            // Every instance in use (ERROR_PIPE_BUSY) is not fatal: wait for a
            // client to go. Nothing here may take the whole Windows side down.
            let mut warned = false;
            pipe = loop {
                match Pipe::create(&pipe_name, false) {
                    Ok(p) => break p,
                    Err(e) => {
                        if !warned {
                            log(&format!("{pipe_name}: {e}; waiting for a free instance"));
                            warned = true;
                        }
                        thread::sleep(std::time::Duration::from_millis(100));
                    }
                }
            };
        }
    })?;
    Ok(())
}

/// Serves docker_engine whenever it is free, and hands it back when another
/// engine starts.
fn docker_engine(hub: &Arc<Hub>) {
    let mut said = String::new();
    let mut say = |msg: String| {
        if msg != said {
            log(&msg);
            said = msg;
        }
    };
    loop {
        if let Some(other) = other_engine() {
            say(format!("{DOCKER_ENGINE} left to {other}"));
            thread::sleep(std::time::Duration::from_secs(5));
            continue;
        }
        let first = match Pipe::create(DOCKER_ENGINE, true) {
            Ok(p) => p,
            Err(e) => {
                say(format!("{DOCKER_ENGINE} left to whatever serves it: {e}"));
                thread::sleep(std::time::Duration::from_secs(5));
                continue;
            }
        };
        say(format!("serving {DOCKER_ENGINE} as well (no other engine has it)"));
        serve_while_free(hub, first);
    }
}

/// Accepts clients on docker_engine until another engine starts. The
/// clients connected then keep their connections until they close.
fn serve_while_free(hub: &Arc<Hub>, first: Pipe) {
    let stop = Arc::new(AtomicBool::new(false));
    // The instance waiting for a client, for the watcher to cancel.
    let waiting: Arc<Mutex<Option<Arc<Pipe>>>> = Arc::new(Mutex::new(None));
    let (st, w) = (stop.clone(), waiting.clone());
    let watcher = thread::spawn(move || {
        while !st.load(Ordering::SeqCst) {
            if let Some(other) = other_engine() {
                log(&format!("{other} started: handing {DOCKER_ENGINE} back"));
                st.store(true, Ordering::SeqCst);
                if let Some(p) = w.lock().unwrap_or_else(PoisonError::into_inner).take() {
                    p.cancel();
                }
                return;
            }
            thread::sleep(std::time::Duration::from_secs(2));
        }
    });
    let mut pipe = Arc::new(first);
    'serve: loop {
        *waiting.lock().unwrap_or_else(PoisonError::into_inner) = Some(pipe.clone());
        let connected = pipe.connect();
        waiting.lock().unwrap_or_else(PoisonError::into_inner).take();
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match connected {
            Ok(()) => {
                let hub = hub.clone();
                let p = pipe.clone();
                thread::spawn(move || serve_shared(&hub, p));
            }
            Err(e) => log(&format!("{DOCKER_ENGINE} connect: {e}")),
        }
        // Every instance in use: wait for a client to go, as for Kiri's pipe.
        pipe = loop {
            if stop.load(Ordering::SeqCst) {
                break 'serve;
            }
            match Pipe::create(DOCKER_ENGINE, false) {
                Ok(p) => break Arc::new(p),
                Err(_) => thread::sleep(std::time::Duration::from_millis(100)),
            }
        };
    }
    let _ = watcher.join();
}

/// The first of OTHER_ENGINES that is running.
fn other_engine() -> Option<&'static str> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
    // SAFETY: a process snapshot read entry by entry into a zeroed,
    // correctly sized PROCESSENTRY32W, and closed once.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = None;
        let mut more = Process32FirstW(snap, &mut e) != 0;
        while more && found.is_none() {
            let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
            let name = String::from_utf16_lossy(&e.szExeFile[..len]);
            found = OTHER_ENGINES.iter().copied().find(|o| o.eq_ignore_ascii_case(&name));
            more = Process32NextW(snap, &mut e) != 0;
        }
        CloseHandle(snap);
        found
    }
}

/// The processes named `name` that `parent` started.
fn children(parent: u32, name: &str) -> Vec<u32> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
    let mut found = Vec::new();
    // SAFETY: a process snapshot read entry by entry into a zeroed,
    // correctly sized PROCESSENTRY32W, and closed once.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return found;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(snap, &mut e) != 0;
        while more {
            let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
            if e.th32ParentProcessID == parent && String::from_utf16_lossy(&e.szExeFile[..len]).eq_ignore_ascii_case(name) {
                found.push(e.th32ProcessID);
            }
            more = Process32NextW(snap, &mut e) != 0;
        }
        CloseHandle(snap);
    }
    found
}

/// Ends the process `pid`, if this user may.
fn terminate(pid: u32) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    // SAFETY: a handle opened here, used once and closed; 0 is no handle.
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if h != 0 {
            TerminateProcess(h, 1);
            CloseHandle(h);
        }
    }
}

/// What the bridge sends back for one connection.
#[derive(Debug)]
enum Reply {
    Data(Vec<u8>),
    Eof,
    /// With the bridge's reason, when it gave one.
    Close(Option<String>),
}

/// One connection, as the bridge's reply reader sees it.
#[derive(Debug)]
struct Conn {
    /// To the thread writing to the client. Unbounded, but `queued` is kept
    /// under the window by the credit the bridge waits for.
    tx: Sender<Reply>,
    queued: Arc<AtomicUsize>,
    /// Credit for the client's input, when the bridge does flow control.
    window: Option<Arc<Window>>,
}

impl Conn {
    fn close(&self) {
        if let Some(w) = &self.window {
            w.close();
        }
    }
}

/// The credit one way on one connection: bytes sent and not yet acknowledged.
#[derive(Debug, Default)]
struct Window {
    state: Mutex<(usize, bool)>,
    cv: Condvar,
}

impl Window {
    /// Waits while a whole window is unacknowledged, then counts `n` more;
    /// false once the connection has closed or `alive` says the client has gone.
    fn take(&self, n: usize, alive: impl Fn() -> bool) -> bool {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        while s.0 >= WINDOW && !s.1 {
            let (g, t) = self.cv.wait_timeout(s, Duration::from_millis(500)).unwrap_or_else(PoisonError::into_inner);
            s = g;
            if t.timed_out() && !alive() {
                return false;
            }
        }
        if s.1 {
            return false;
        }
        s.0 += n;
        true
    }

    fn ack(&self, n: usize) {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        s.0 = s.0.saturating_sub(n);
        self.cv.notify_all();
    }

    fn close(&self) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).1 = true;
        self.cv.notify_all();
    }
}

/// Starts a bridge: wsl.exe, or a stand-in in tests.
type Spawn = Box<dyn Fn(&Config) -> io::Result<Arc<Bridge>> + Send + Sync>;

/// How long a bridge is waited for; shorter in tests.
#[derive(Debug, Clone, Copy)]
struct Limits {
    hello: Duration,
    quiet: Duration,
    ping: Duration,
    told_hold: Duration,
    told_grace: Duration,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { hello: HELLO_WAIT, quiet: QUIET, ping: PING_WAIT, told_hold: TOLD_HOLD, told_grace: TOLD_GRACE }
    }
}

struct Hub {
    /// Setup may change the distro while kiri-win runs.
    cfg: Mutex<Config>,
    /// The running bridge; a new one starts when it has died (WSL shut down).
    current: Mutex<Option<Arc<Bridge>>>,
    next_id: AtomicU32,
    spawn: Spawn,
    limits: Limits,
    /// When a client was last told WSL is not answering, and in what words.
    silent: Mutex<Option<(Instant, String)>>,
}

impl Hub {
    fn new(cfg: Config, spawn: Spawn, limits: Limits) -> Hub {
        Hub { cfg: Mutex::new(cfg), current: Mutex::new(None), next_id: AtomicU32::new(1), spawn, limits, silent: Mutex::new(None) }
    }

    /// What a client was told within `told_hold`: WSL is not answering.
    fn told_silent(&self) -> Option<String> {
        self.silent.lock().unwrap_or_else(PoisonError::into_inner).as_ref().filter(|(at, _)| at.elapsed() < self.limits.told_hold).map(|(_, why)| why.clone())
    }

    /// Takes the running bridge out of use for new connections; true if
    /// there was one. It ends once the connections it has are over.
    fn retire(&self) -> bool {
        let Some(b) = self.current.lock().unwrap_or_else(PoisonError::into_inner).take() else { return false };
        b.retired.store(true, Ordering::SeqCst);
        b.dead.store(true, Ordering::SeqCst);
        b.end_if_unused();
        true
    }

    fn bridge(&self) -> io::Result<Arc<Bridge>> {
        let mut current = self.current.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(b) = current.as_ref().filter(|b| !b.dead.load(Ordering::SeqCst)) {
            return Ok(b.clone());
        }
        let cfg = self.cfg.lock().unwrap_or_else(PoisonError::into_inner).clone();
        // Until setup has made Kiri's Linux there is nothing to bridge to.
        if cfg.distro.is_none() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "Kiri is not set up yet"));
        }
        // The last one has gone (WSL restarted, Windows slept): a docker
        // client is waiting, so a new one starts now, and the log says why;
        // once, not again for each try while new ones die as they start.
        if current.as_ref().is_some_and(|b| b.started.elapsed() > 2 * BRIDGE_RETRY) {
            log("bridge: the last one has gone; starting a new one for a docker client");
        }
        let b = (self.spawn)(&cfg)?;
        *current = Some(b.clone());
        Ok(b)
    }
}

/// What runs a bridge: wsl.exe, or a stand-in in tests.
trait Process: Send {
    fn kill(&mut self);
    /// How it exited, once it has.
    fn exited(&mut self) -> Option<String>;
}

/// wsl.exe as kiri-win starts it: System32's, which runs the real one
/// (under Program Files) as its child and relays to it.
struct Wsl(Child);

impl Process for Wsl {
    /// The child first: it is the one that hangs, and it outlives the one
    /// kiri-win started when it is not reading what that relays.
    fn kill(&mut self) {
        for pid in children(self.0.id(), "wsl.exe") {
            terminate(pid);
        }
        let _ = self.0.kill();
    }

    fn exited(&mut self) -> Option<String> {
        match self.0.try_wait() {
            Ok(None) => None,
            status => Some(format!("{status:?}")),
        }
    }
}

/// Whether a bridge can take a new connection.
#[derive(Debug, PartialEq)]
enum Answer {
    Yes,
    /// It has exited, or is on its way out.
    Gone,
    /// It runs and says nothing: how that showed.
    No(String),
}

struct Bridge {
    input: Mutex<Box<dyn Write + Send>>,
    process: Mutex<Box<dyn Process>>,
    conns: Mutex<HashMap<u32, Conn>>,
    dead: AtomicBool,
    /// Ended here (`kill`), not by exiting.
    killed: AtomicBool,
    /// The log has said that this one, started after one that did not
    /// answer, does.
    announced: AtomicBool,
    /// Out of use for new connections (`Hub::retire`), and ended once the
    /// ones it has are over.
    retired: AtomicBool,
    /// The bridge said hello: it does flow control.
    credit: AtomicBool,
    /// Its hello said it answers PING.
    pings: AtomicBool,
    started: Instant,
    /// When its last frame came, in ms after `started`.
    heard: AtomicU64,
    /// What clients were last told the engine could not do, logged once
    /// until a client is served again.
    said: Mutex<Option<String>>,
}

impl Bridge {
    fn start(cfg: &Config) -> io::Result<Arc<Bridge>> {
        let mut cmd = crate::win::tool("wsl.exe");
        if let Some(d) = &cfg.distro {
            cmd.args(["-d", d]);
        }
        let mut child = cmd
            .args(["-u", "root", "--", &cfg.kiri, "bridge", "--socket", &cfg.socket])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()?;
        let (Some(input), Some(output)) = (child.stdin.take(), child.stdout.take()) else { return Err(io::Error::other("wsl.exe has no stdio")) };
        log("bridge started");
        Ok(Bridge::over(Box::new(input), output, Box::new(Wsl(child))))
    }

    /// A bridge over `process`'s input and output.
    fn over(input: Box<dyn Write + Send>, output: impl Read + Send + 'static, process: Box<dyn Process>) -> Arc<Bridge> {
        let bridge = Arc::new(Bridge {
            input: Mutex::new(input),
            process: Mutex::new(process),
            conns: Mutex::new(HashMap::new()),
            dead: AtomicBool::new(false),
            killed: AtomicBool::new(false),
            announced: AtomicBool::new(false),
            retired: AtomicBool::new(false),
            credit: AtomicBool::new(false),
            pings: AtomicBool::new(false),
            started: Instant::now(),
            heard: AtomicU64::new(0),
            said: Mutex::new(None),
        });
        let b = bridge.clone();
        thread::spawn(move || b.replies(output));
        bridge
    }

    /// Milliseconds since it started.
    fn clock(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// Hands each reply to its connection, until the bridge exits.
    fn replies(&self, output: impl Read) {
        let mut r = BufReader::with_capacity(64 * 1024, output);
        while let Ok(Some((kind, id, data))) = read_frame(&mut r) {
            self.heard.store(self.clock(), Ordering::SeqCst);
            if kind == PING {
                continue;
            }
            if kind == NOTE {
                if id == 0 {
                    log(&format!("engine in WSL: {}", String::from_utf8_lossy(&data)));
                }
                continue;
            }
            if kind == ACK {
                if id == 0 {
                    self.pings.store(data.first() == Some(&1), Ordering::SeqCst);
                    self.credit.store(true, Ordering::SeqCst);
                } else if let Some(n) = data.get(..4).and_then(|b| b.try_into().ok()).map(u32::from_be_bytes)
                    && let Some(w) = self.conns.lock().unwrap_or_else(PoisonError::into_inner).get(&id).and_then(|c| c.window.clone())
                {
                    w.ack(n as usize);
                }
                continue;
            }
            let reply = match kind {
                DATA => Reply::Data(data),
                EOF => Reply::Eof,
                _ => Reply::Close((kind == CLOSE && !data.is_empty()).then(|| String::from_utf8_lossy(&data).into_owned())),
            };
            let mut conns = self.conns.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(c) = conns.get(&id) else { continue };
            // Never block here: this thread serves every connection. With
            // credit the bridge never sends past the window; without it, a
            // client that has stopped reading is dropped, so it cannot stall
            // the others.
            let len = if let Reply::Data(d) = &reply { d.len() } else { 0 };
            let limit = if c.window.is_some() { LIMIT } else { LIMIT_NO_CREDIT };
            if c.queued.fetch_add(len, Ordering::SeqCst) + len > limit {
                log(&format!("connection {id}: client stopped reading; closing it"));
                if let Some(c) = conns.remove(&id) {
                    c.close();
                }
                drop(conns);
                let _ = self.send(CLOSE, id, &[]);
            } else {
                let _ = c.tx.send(reply);
            }
        }
        self.dead.store(true, Ordering::SeqCst);
        self.close_all();
        // Its output has ended: it has exited, or does within a moment. One
        // that still runs after that is of no use, and is not left behind.
        let until = Instant::now() + Duration::from_secs(2);
        let status = loop {
            let mut p = self.process.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(status) = p.exited() {
                break status;
            }
            if Instant::now() >= until {
                p.kill();
                break "still running with its output closed; ended".to_owned();
            }
            drop(p);
            thread::sleep(Duration::from_millis(20));
        };
        if !self.killed.load(Ordering::SeqCst) {
            log(&format!("bridge exited: {status}"));
        }
    }

    /// Every connection still open ends now.
    fn close_all(&self) {
        for (_, c) in self.conns.lock().unwrap_or_else(PoisonError::into_inner).drain() {
            c.close();
        }
    }

    /// Ends a bridge whose wsl.exe runs and does nothing (`why`), with the
    /// connections on it: nothing else would. Its exit never comes, so
    /// nothing waits for one; a write stuck in its full input ends as it goes.
    fn kill(&self, why: &str) {
        if self.killed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.dead.store(true, Ordering::SeqCst);
        log(&format!("bridge: {why}; ending its wsl.exe"));
        self.process.lock().unwrap_or_else(PoisonError::into_inner).kill();
        self.close_all();
    }

    /// Ends a retired bridge that has no connections left.
    fn end_if_unused(&self) {
        if self.retired.load(Ordering::SeqCst) && self.conns.lock().unwrap_or_else(PoisonError::into_inner).is_empty() && !self.killed.swap(true, Ordering::SeqCst) {
            self.process.lock().unwrap_or_else(PoisonError::into_inner).kill();
        }
    }

    /// Whether it has said hello, waiting until it is `grace` old.
    fn hello_within(&self, grace: Duration) -> bool {
        while !self.credit.load(Ordering::SeqCst) {
            if self.dead.load(Ordering::SeqCst) || self.started.elapsed() > grace {
                return false;
            }
            thread::sleep(Duration::from_millis(5));
        }
        true
    }

    /// Whether this bridge can take a new connection: it has said hello
    /// (waited for while it has only just started), and when it has been
    /// quiet, it answers a PING now. An engine from before PING is taken at
    /// its hello.
    fn answers(self: &Arc<Self>, limits: &Limits) -> Answer {
        while !self.credit.load(Ordering::SeqCst) {
            if self.dead.load(Ordering::SeqCst) {
                return Answer::Gone;
            }
            if self.started.elapsed() > limits.hello {
                return Answer::No(format!("wsl.exe was started {} s ago and Kiri's Linux has not answered", self.started.elapsed().as_secs()));
            }
            thread::sleep(Duration::from_millis(5));
        }
        let asked = self.clock();
        if !self.pings.load(Ordering::SeqCst) || asked.saturating_sub(self.heard.load(Ordering::SeqCst)) < limits.quiet.as_millis() as u64 {
            return Answer::Yes;
        }
        // On a thread of its own: a wsl.exe that has stopped reading leaves
        // the write waiting, until `kill`.
        let b = self.clone();
        thread::spawn(move || b.send(PING, 0, &[]));
        let began = Instant::now();
        while self.heard.load(Ordering::SeqCst) < asked {
            if self.dead.load(Ordering::SeqCst) {
                return Answer::Gone;
            }
            if began.elapsed() > limits.ping {
                return Answer::No(format!("its wsl.exe runs, but Kiri's Linux did not answer in {} s", limits.ping.as_secs()));
            }
            thread::sleep(Duration::from_millis(2));
        }
        Answer::Yes
    }

    fn send(&self, kind: u8, id: u32, data: &[u8]) -> io::Result<()> {
        let mut w = self.input.lock().unwrap_or_else(PoisonError::into_inner);
        let r = w.write_all(&header(kind, id, data.len())).and_then(|()| w.write_all(data)).and_then(|()| w.flush());
        if r.is_err() {
            self.dead.store(true, Ordering::SeqCst);
        }
        r
    }

    /// Logs what a client was told, unless it is what the last one was.
    /// None: a client was served, so the next refusal is logged again.
    fn told(&self, message: Option<&str>) {
        let mut said = self.said.lock().unwrap_or_else(PoisonError::into_inner);
        if said.as_deref() != message {
            if let Some(m) = message {
                log(&format!("engine: told docker clients: {m}"));
            }
            *said = message.map(str::to_owned);
        }
    }

}

/// One docker client: its requests go over the bridge, on this thread, and
/// the replies come back on another.
fn serve(hub: &Hub, pipe: Pipe) {
    serve_shared(hub, Arc::new(pipe));
}

fn serve_shared(hub: &Hub, pipe: Arc<Pipe>) {
    // A bridge can die between hub.bridge() and the insert below: while WSL
    // is still booting, wsl.exe exits at once. `replies` ends every
    // connection it finds when that happens, but one registered after that
    // sweep sat in the dead bridge's map for good: no thread would ever
    // write its reply or cancel its read, so the client waited forever,
    // with the window's engine thread (and every Start click) behind it.
    // So the insert checks `dead` under the lock the sweep takes, and a
    // bridge found dead is left for the next one.
    //
    // A bridge that runs and says nothing (a wsl.exe that hangs after
    // Windows wakes) is ended and the connection goes on the next one: its
    // request has not been read yet, so nothing is lost. After SILENT_MOST
    // of those in a row the client is told why.
    let began = Instant::now();
    // Since the last bridge that was ended for saying nothing: what the
    // wait for one that dies as it starts is counted from.
    let mut dying_since = began;
    let mut silent = 0;
    let (bridge, id, window, rx, queued) = loop {
        let bridge = match hub.bridge() {
            Ok(b) => b,
            Err(e) => {
                let answered = if e.kind() == io::ErrorKind::NotConnected {
                    setup_pending() && refuse_new(&pipe, SETUP_UNFINISHED)
                } else {
                    log(&format!("bridge: {e}"));
                    refuse_new(&pipe, &message(Some(&format!("WSL did not start Kiri's Linux ({e})"))))
                };
                if answered {
                    linger(&pipe);
                }
                return;
            }
        };
        // A client was just told WSL is not answering. A bridge started
        // back then that has said nothing is ended for a new one, and one
        // that says nothing in the moment a working one needs means this
        // client is told too, without waiting as long again.
        let age = bridge.started.elapsed();
        if let Some(why) = hub.told_silent()
            && !bridge.hello_within(hub.limits.told_grace)
        {
            if age > hub.limits.told_grace {
                bridge.kill("it was started while WSL was not answering, and has said nothing");
                continue;
            }
            if refuse_new(&pipe, &message(Some(&why))) {
                linger(&pipe);
            }
            return;
        }
        if let Answer::No(why) = bridge.answers(&hub.limits) {
            bridge.kill(&why);
        }
        // Ended for saying nothing, here or by another connection that
        // waited on it too: not one that dies as it starts, so the next is
        // started at once.
        if bridge.killed.load(Ordering::SeqCst) && !bridge.retired.load(Ordering::SeqCst) {
            silent += 1;
            dying_since = Instant::now();
            if silent >= SILENT_MOST {
                let why = format!("WSL is not answering (wsl.exe ran {silent} times, {} s in all, and Kiri's Linux said nothing)", began.elapsed().as_secs());
                // Logged once for the clients that waited together.
                let mut told = hub.silent.lock().unwrap_or_else(PoisonError::into_inner);
                if !told.as_ref().is_some_and(|(at, _)| at.elapsed() < hub.limits.told_hold) {
                    log(&format!("bridge: {silent} in a row did not answer, over {} s; told the docker client", began.elapsed().as_secs()));
                }
                *told = Some((Instant::now(), why.clone()));
                drop(told);
                if refuse_new(&pipe, &message(Some(&why))) {
                    linger(&pipe);
                }
                return;
            }
            continue;
        }
        let id = hub.next_id.fetch_add(1, Ordering::SeqCst);
        // The client's input waits for the bridge's credit (the daemon holds
        // back an attach's stdin until the container reads it), and its
        // replies are bounded by the credit this side gives (see `to_client`).
        let window = bridge.credit.load(Ordering::SeqCst).then(|| Arc::new(Window::default()));
        let (tx, rx) = channel();
        let queued = Arc::new(AtomicUsize::new(0));
        let registered = {
            let mut conns = bridge.conns.lock().unwrap_or_else(PoisonError::into_inner);
            if bridge.dead.load(Ordering::SeqCst) {
                false
            } else {
                conns.insert(id, Conn { tx, queued: queued.clone(), window: window.clone() });
                true
            }
        };
        if registered && bridge.send(OPEN, id, if window.is_some() { &[1] } else { &[] }).is_ok() {
            if silent > 0 && !bridge.announced.swap(true, Ordering::SeqCst) {
                log(&format!("bridge: the new one answers; the docker client that waited {} s is served on it", began.elapsed().as_secs()));
            }
            break (bridge, id, window, rx, queued);
        }
        bridge.conns.lock().unwrap_or_else(PoisonError::into_inner).remove(&id);
        if gave_up(dying_since.elapsed()) {
            log(&format!("bridge: kept stopping as soon as it started, for {} s; told the docker client", BRIDGE_WAIT.as_secs()));
            if refuse_new(&pipe, &message(Some("Kiri's Linux in WSL kept stopping as the command came in"))) {
                linger(&pipe);
            }
            return;
        }
        thread::sleep(BRIDGE_RETRY);
    };
    // Whether the client's request has come, and is a HEAD: a refusal
    // waits for it (see `refuse_new`).
    let request = Arc::new(Arrival::default());
    let (p, b, w, r) = (pipe.clone(), bridge.clone(), window.clone(), request.clone());
    let writer = thread::spawn(move || to_client(&p, &rx, &queued, &b, w.as_deref().map(|w| (id, w)), &r));
    let mut buf = vec![0u8; 64 * 1024];
    let end = loop {
        match pipe.read(&mut buf) {
            Ok(0) => break EOF,
            Ok(n) => {
                request.set(is_head(&buf[..n]));
                // Out of credit with the client gone (nothing to read its
                // reply), or the connection closed: stop.
                if window.as_ref().is_some_and(|w| !w.take(n, || pipe.alive())) {
                    break CLOSE;
                }
                if bridge.send(DATA, id, &buf[..n]).is_err() {
                    break CLOSE;
                }
            }
            // The client closed the pipe.
            Err(_) => break CLOSE,
        }
    };
    // Gone before a word: nothing for a refusal to wait for.
    request.set(false);
    let _ = bridge.send(end, id, &[]);
    let replies_ended = writer.join().unwrap_or(false);
    if end == EOF && replies_ended {
        linger(&pipe);
    }
    if let Some(c) = bridge.conns.lock().unwrap_or_else(PoisonError::into_inner).remove(&id) {
        c.close();
    }
    bridge.end_if_unused();
}

/// Whether a connection whose bridge keeps dying as it starts has waited
/// long enough (`waited`) to be told why: about BRIDGE_WAIT, rather than
/// three tries within milliseconds while WSL was still coming back.
fn gave_up(waited: Duration) -> bool {
    waited + BRIDGE_RETRY > BRIDGE_WAIT
}

/// Writes the bridge's replies to the client, acknowledging them to the
/// bridge (`credit`) as they go when it does flow control. True if they
/// ended with EOF, or the client was told why the engine could not serve
/// it (once its `request` had come).
fn to_client(pipe: &Pipe, rx: &Receiver<Reply>, queued: &AtomicUsize, bridge: &Bridge, credit: Option<(u32, &Window)>, request: &Arrival) -> bool {
    let mut done = 0usize;
    let mut answered = false;
    for reply in rx {
        match reply {
            Reply::Data(d) => {
                if pipe.write(&d).is_err() {
                    return false;
                }
                if !answered {
                    bridge.told(None);
                }
                answered = true;
                queued.fetch_sub(d.len(), Ordering::SeqCst);
                done += d.len();
                if let Some((id, _)) = credit
                    && done >= ACK_EVERY {
                        let _ = bridge.send(ACK, id, &(done as u32).to_be_bytes());
                        done = 0;
                    }
            }
            // The docker CLI reads in byte mode, where the empty message
            // that is EOF reads as one only with no data queued ahead of
            // it; behind data it is merged away and the client waits on.
            Reply::Eof => {
                pipe.flush();
                return pipe.write(&[]).is_ok();
            }
            // Closed before a word: the bridge could not reach the engine
            // (and says why), the daemon closed it unanswered (no reason),
            // or setup is unfinished. Said to a client still there, after
            // its request.
            Reply::Close(why) if !answered && pipe.alive() => {
                let message = message(why.as_deref());
                if refuse(pipe, request.head(REQUEST_WAIT), &message) {
                    bridge.told(Some(&message));
                    return true;
                }
                break;
            }
            Reply::Close(_) => break,
        }
    }
    // The daemon closed the connection, or the bridge died with it open
    // (the engine restarting): end the client's side too. Its reader above
    // waits on the client, and a client waiting for its reply (the window's
    // own requests, a docker command) would otherwise wait forever, with
    // the window's engine thread behind it. Its input may be waiting for
    // credit rather than on the client: that ends too.
    if let Some((_, w)) = credit {
        w.close();
    }
    pipe.cancel();
    false
}

/// Waits a while for a client that has had both half-closes to close its
/// end. Disconnecting the instance discards what the client has not read
/// yet, and FlushFileBuffers does not wait for the empty message that is
/// its EOF: a client that had not read it yet (often at the end of 200 MB
/// of `docker run` output) then read ERROR_PIPE_NOT_CONNECTED, "No process
/// is on the other end of the pipe", instead of EOF, about one run in twenty.
fn linger(pipe: &Pipe) {
    let until = Instant::now() + Duration::from_secs(2);
    while pipe.alive() && Instant::now() < until {
        thread::sleep(Duration::from_millis(2));
    }
}

/// The largest frame either side accepts. Both send at most 64 KiB of
/// data per frame; without a bound, a length of up to 4 GiB was allocated
/// as read.
const MAX_FRAME: usize = 1 << 20;

fn header(kind: u8, id: u32, len: usize) -> [u8; 9] {
    let mut h = [0u8; 9];
    h[0] = kind;
    h[1..5].copy_from_slice(&id.to_be_bytes());
    h[5..].copy_from_slice(&(len as u32).to_be_bytes());
    h
}

fn read_frame(r: &mut impl Read) -> io::Result<Option<(u8, u32, Vec<u8>)>> {
    let mut h = [0u8; 9];
    match r.read_exact(&mut h) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let id = u32::from_be_bytes([h[1], h[2], h[3], h[4]]);
    let len = u32::from_be_bytes([h[5], h[6], h[7], h[8]]) as usize;
    // The length comes off the wire: refuse it before allocating it.
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("frame of {len} bytes")));
    }
    let mut data = vec![0u8; len];
    r.read_exact(&mut data)?;
    Ok(Some((h[0], id, data)))
}

/// Appends to %LOCALAPPDATA%\Kiri\kiri-win.log: there is no console.
pub fn log(msg: &str) {
    let Some(dir) = std::env::var_os("LOCALAPPDATA").map(|d| std::path::PathBuf::from(d).join("Kiri")) else { return };
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("kiri-win.log")) {
        // UTC to the millisecond, as the engine's /var/log/kiri.log writes
        // it, so a moment reads the same in both.
        let t = crate::daemon::time::rfc3339(std::time::SystemTime::now());
        let stamp = format!("{}Z", t.get(..23).unwrap_or(&t));
        // One write per line: separate writes from two threads interleave
        // in the file and Diagnostics then cannot parse the line.
        let _ = f.write_all(format!("{stamp} {msg}\n").as_bytes());
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn frames_round_trip() {
        let mut wire = super::header(super::DATA, 7, 3).to_vec();
        wire.extend_from_slice(b"abc");
        let mut r = &wire[..];
        assert_eq!(super::read_frame(&mut r).unwrap(), Some((super::DATA, 7, b"abc".to_vec())));
        assert_eq!(super::read_frame(&mut r).unwrap(), None);
    }

    /// A bridge that dies as it starts (WSL coming back after Windows
    /// slept) is started again for about BRIDGE_WAIT, not given up on
    /// after three tries within milliseconds (#93).
    #[test]
    fn a_dying_bridge_is_retried_for_a_bounded_while() {
        use std::time::Duration;
        assert!(!super::gave_up(Duration::from_millis(30)));
        assert!(!super::gave_up(super::BRIDGE_WAIT / 2));
        assert!(super::gave_up(super::BRIDGE_WAIT));
        // About twenty tries, not three.
        assert!(super::BRIDGE_WAIT.as_millis() / super::BRIDGE_RETRY.as_millis() >= 10);
    }

    use super::{header, read_frame, Answer, Bridge, Config, Hub, Limits, Process, ACK, DATA, EOF, PING};
    use crate::pipe::Pipe;
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// What stands in for wsl.exe: ended by `kill`, which also closes the
    /// output it holds, as the real one's exit does.
    struct Stub {
        killed: Arc<AtomicBool>,
        output: Option<std::io::PipeWriter>,
    }

    impl Process for Stub {
        fn kill(&mut self) {
            self.killed.store(true, Ordering::SeqCst);
            self.output.take();
        }

        fn exited(&mut self) -> Option<String> {
            self.killed.load(Ordering::SeqCst).then(|| "killed".to_owned())
        }
    }

    /// A wsl.exe that runs and never says a word, hello included, as one
    /// can right after Windows wakes. Returns whether it was killed.
    fn silent() -> (Arc<Bridge>, Arc<AtomicBool>) {
        let (output, held) = std::io::pipe().unwrap();
        let killed = Arc::new(AtomicBool::new(false));
        let b = Bridge::over(Box::new(std::io::sink()), output, Box::new(Stub { killed: killed.clone(), output: Some(held) }));
        (b, killed)
    }

    /// A bridge that says hello, answers PING, and answers each request
    /// with `name`, until `frozen`: then it takes what it is sent and says
    /// nothing, as a wsl.exe that outlived its WSL.
    fn answering(name: &'static str, frozen: Arc<AtomicBool>) -> (Arc<Bridge>, Arc<AtomicBool>) {
        let (output, mut out) = std::io::pipe().unwrap();
        let (mut input, to_bridge) = std::io::pipe().unwrap();
        let killed = Arc::new(AtomicBool::new(false));
        let held = out.try_clone().unwrap();
        std::thread::spawn(move || {
            let mut say = |kind, id, data: &[u8]| {
                let _ = out.write_all(&header(kind, id, data.len()));
                let _ = out.write_all(data);
            };
            say(ACK, 0, &[1]);
            while let Ok(Some((kind, id, _))) = read_frame(&mut input) {
                if frozen.load(Ordering::SeqCst) {
                    continue;
                }
                match kind {
                    PING => say(PING, 0, &[]),
                    DATA => {
                        say(DATA, id, format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{name}", name.len()).as_bytes());
                        say(EOF, id, &[]);
                    }
                    _ => {}
                }
            }
        });
        let b = Bridge::over(Box::new(to_bridge), output, Box::new(Stub { killed: killed.clone(), output: Some(held) }));
        (b, killed)
    }

    fn limits() -> Limits {
        Limits { hello: Duration::from_millis(300), quiet: Duration::from_millis(50), ping: Duration::from_millis(300), told_hold: Duration::from_secs(10), told_grace: Duration::from_millis(100) }
    }

    /// A hub whose bridges come from `next`, and how many it has started.
    fn hub(next: impl Fn(usize) -> Arc<Bridge> + Send + Sync + 'static) -> (Arc<Hub>, Arc<AtomicUsize>) {
        let started = Arc::new(AtomicUsize::new(0));
        let n = started.clone();
        let cfg = Config { distro: Some("test".into()), pipe: String::new(), socket: String::new(), kiri: String::new() };
        (Arc::new(Hub::new(cfg, Box::new(move |_| Ok(next(n.fetch_add(1, Ordering::SeqCst)))), limits())), started)
    }

    /// One docker client's request through `hub`, as over Kiri's pipe:
    /// what it read back, and how long that took. Panics after 20 s
    /// without an end, where the client once waited for good.
    fn request(hub: &Arc<Hub>) -> (String, Duration) {
        static N: AtomicUsize = AtomicUsize::new(0);
        let name = format!(r"\\.\pipe\kiri-test-serve-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst));
        let server = Pipe::create(&name, true).unwrap();
        let h = hub.clone();
        std::thread::spawn(move || {
            server.connect().unwrap();
            super::serve(&h, server);
        });
        let began = Instant::now();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let client = Pipe::open(&name).unwrap();
            client.write(b"GET /_ping HTTP/1.1\r\nHost: kiri\r\n\r\n").unwrap();
            let mut reply = Vec::new();
            let _ = (&client).read_to_end(&mut reply);
            let _ = tx.send(String::from_utf8_lossy(&reply).into_owned());
        });
        let reply = rx.recv_timeout(Duration::from_secs(20)).expect("the docker client was left waiting on a bridge that never answers");
        (reply, began.elapsed())
    }

    /// A wsl.exe that hangs without a word (#93, after Windows wakes): the
    /// bridge is ended once its hello is overdue, and the client that
    /// waited on it is served by the next one.
    #[test]
    fn a_bridge_that_never_says_hello_is_replaced() {
        let first_killed = Arc::new(Mutex::new(None));
        let k = first_killed.clone();
        let (hub, started) = hub(move |n| {
            if n == 0 {
                let (b, killed) = silent();
                *k.lock().unwrap() = Some(killed);
                b
            } else {
                answering("second", Arc::default()).0
            }
        });
        let (reply, took) = request(&hub);
        assert!(reply.starts_with("HTTP/1.1 200 OK") && reply.ends_with("second"), "{reply}");
        assert_eq!(started.load(Ordering::SeqCst), 2);
        assert!(first_killed.lock().unwrap().as_ref().unwrap().load(Ordering::SeqCst), "the silent wsl.exe was left running");
        assert!(took < Duration::from_secs(5), "{took:?}");
    }

    /// A bridge that served, then stopped answering (its wsl.exe outlived
    /// the WSL it was connected to): the next connection asks it for a
    /// PING, ends it when none comes, and is served by a new one.
    #[test]
    fn a_bridge_that_stops_answering_is_replaced() {
        let frozen = Arc::new(AtomicBool::new(false));
        let first_killed = Arc::new(Mutex::new(None));
        let (f, k) = (frozen.clone(), first_killed.clone());
        let (hub, started) = hub(move |n| {
            if n == 0 {
                let (b, killed) = answering("first", f.clone());
                *k.lock().unwrap() = Some(killed);
                b
            } else {
                answering("second", Arc::default()).0
            }
        });
        assert!(request(&hub).0.ends_with("first"));
        // Quiet, and still answering: asked, and kept.
        std::thread::sleep(limits().quiet * 2);
        assert!(request(&hub).0.ends_with("first"));
        assert_eq!(started.load(Ordering::SeqCst), 1);
        frozen.store(true, Ordering::SeqCst);
        std::thread::sleep(limits().quiet * 2);
        let (reply, took) = request(&hub);
        assert!(reply.ends_with("second"), "{reply}");
        assert_eq!(started.load(Ordering::SeqCst), 2);
        assert!(first_killed.lock().unwrap().as_ref().unwrap().load(Ordering::SeqCst), "the frozen wsl.exe was left running");
        assert!(took < Duration::from_secs(5), "{took:?}");
    }

    /// WSL that answers nothing however often wsl.exe is started: the
    /// client is told so after two, rather than left waiting.
    #[test]
    fn a_client_is_told_when_no_bridge_answers() {
        let (hub, started) = hub(|_| silent().0);
        let (reply, took) = request(&hub);
        assert!(reply.starts_with("HTTP/1.1 503 ") && reply.contains("WSL is not answering"), "{reply}");
        assert!(reply.contains("kiri start"), "{reply}");
        assert_eq!(started.load(Ordering::SeqCst), 2);
        assert!(took < Duration::from_secs(8), "{took:?}");
        // docker's next request for the same command is told at once,
        // not made to wait as long again.
        let (again, took) = request(&hub);
        assert_eq!(again, reply);
        assert!(took < Duration::from_millis(250), "{took:?}");
    }

    /// The error does not outlast its cause: once WSL answers again, the
    /// next client is served, though one was just told it is not answering.
    #[test]
    fn a_client_is_served_as_soon_as_a_bridge_answers_again() {
        let back = Arc::new(AtomicBool::new(false));
        let b = back.clone();
        let (hub, _) = hub(move |_| if b.load(Ordering::SeqCst) { answering("back", Arc::default()).0 } else { silent().0 });
        assert!(request(&hub).0.contains("WSL is not answering"));
        // One started while it was not answering, as another client's
        // would be, and still there when WSL answers again.
        assert!(request(&hub).0.contains("WSL is not answering"));
        std::thread::sleep(limits().told_grace * 3);
        back.store(true, Ordering::SeqCst);
        let (reply, took) = request(&hub);
        assert!(reply.ends_with("back"), "{reply}");
        assert!(took < Duration::from_secs(2), "{took:?}");
    }

    /// The real wsl.exe is a child of the one kiri-win starts: found by
    /// its parent and name, so both are ended.
    #[test]
    fn a_process_s_children_are_found_by_name() {
        let mut cmd = crate::win::tool("cmd.exe");
        let mut child = cmd.args(["/c", "ping -n 30 127.0.0.1 >NUL"]).spawn().unwrap();
        let began = Instant::now();
        let found = loop {
            let found = super::children(child.id(), "PING.EXE");
            if !found.is_empty() || began.elapsed() > Duration::from_secs(5) {
                break found;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(found.len(), 1);
        assert!(super::children(child.id(), "wsl.exe").is_empty());
        super::terminate(found[0]);
        // Its only child gone, cmd.exe ends by itself.
        assert!(child.wait().is_ok());
        assert!(began.elapsed() < Duration::from_secs(10));
    }

    /// An engine from before PING (its hello has no data) is never asked
    /// for one, and is taken at its hello.
    #[test]
    fn a_bridge_from_before_ping_is_not_asked() {
        let (output, mut out) = std::io::pipe().unwrap();
        let b = Bridge::over(Box::new(std::io::sink()), output, Box::new(Stub { killed: Arc::default(), output: None }));
        out.write_all(&header(ACK, 0, 0)).unwrap();
        std::thread::sleep(limits().quiet * 3);
        assert_eq!(b.answers(&limits()), Answer::Yes);
    }

    /// The engine in WSL was replaced: the bridge run from the old one is
    /// out of use for new connections, and ended as nothing is on it.
    #[test]
    fn a_retired_bridge_is_ended_and_replaced() {
        let killed = Arc::new(Mutex::new(Vec::new()));
        let k = killed.clone();
        let (hub, started) = hub(move |_| {
            let (b, was) = answering("any", Arc::default());
            k.lock().unwrap().push(was);
            b
        });
        assert!(request(&hub).0.ends_with("any"));
        assert!(hub.retire());
        // At once, or as the connection just served leaves it.
        let began = Instant::now();
        while !killed.lock().unwrap()[0].load(Ordering::SeqCst) {
            assert!(began.elapsed() < Duration::from_secs(5), "the retired bridge was left running");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(request(&hub).0.ends_with("any"));
        assert_eq!(started.load(Ordering::SeqCst), 2);
        assert!(!killed.lock().unwrap()[1].load(Ordering::SeqCst));
    }

    #[test]
    fn oversized_frames_are_refused() {
        let mut wire = super::header(super::DATA, 7, super::MAX_FRAME).to_vec();
        wire.resize(wire.len() + super::MAX_FRAME, 0);
        assert_eq!(super::read_frame(&mut &wire[..]).unwrap().map(|f| f.2.len()), Some(super::MAX_FRAME));
        // 4 GiB claimed, nothing behind it: an error at once, not an allocation.
        let huge = super::header(super::DATA, 7, u32::MAX as usize);
        assert_eq!(super::read_frame(&mut &huge[..]).unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }
}
