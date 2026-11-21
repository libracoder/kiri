//! `RUN --mount=type=ssh` in Kiri's own builder: the client's SSH agents,
//! reached by a build step through a socket that relays to them.
//!
//! An agent socket forwarded into a step is a credential, so:
//!
//! - The engine never opens an agent by a path. `kiri build --ssh` holds a
//!   session connection to the engine (`POST /kiri/build/ssh`, then raw;
//!   see sshfwd.rs) and hands over one fresh agent connection, as a
//!   descriptor, each time the engine asks for an id it forwards.
//! - A session is named by a random token only its client knows, and a
//!   build may use it only when it comes from the same user (on a Linux
//!   host, by the peer credentials of both connections).
//! - Each step's mount gets a token of its own, live only while the step's
//!   run lasts ([`StepAgent`], dropped when the run returns). The guest
//!   agent puts a socket with the mount's owner and mode at the target, in
//!   that step's mount namespace alone, and dials [`BUILD_SSH_PORT`] with
//!   the token for each connection a process of the step makes to it.
//! - Nothing of it is written anywhere: no file, no layer (the target is
//!   a mount, kept out of the step's layer), no cache key (the id and
//!   options only), no log line.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use serde_json::{Value, json};

use super::api::Next;
use super::http::{self, Request};

/// vsock port the guest dials for each connection a build step makes to
/// its ssh agent socket: `<step token>\n`, then the agent's bytes.
pub const BUILD_SSH_PORT: u32 = kiri_proto::BUILD_SSH_PORT;

/// The most ids one session forwards.
const MAX_IDS: usize = 64;
/// The most agent connections one step's mount has open at once.
const MAX_CONNECTIONS: usize = 32;
/// How long the client has to answer for a connection.
const CLIENT_ANSWER: Duration = Duration::from_secs(30);

/// A connection asked of a session's client.
struct Ask {
    id: String,
    reply: mpsc::Sender<Option<OwnedFd>>,
}

struct Session {
    /// Who opened it: a build must come from the same user. None on the
    /// Mac, whose engine serves its one user alone.
    uid: Option<u32>,
    ids: Vec<String>,
    asks: Mutex<mpsc::Sender<Ask>>,
}

struct Step {
    session: Arc<Session>,
    id: String,
    open: Arc<AtomicUsize>,
    relays: Arc<Mutex<Relays>>,
}

/// The relays a step has open, by a number of their own: a copy of each
/// one's guest and agent descriptors, to shut down when the step ends.
#[derive(Default)]
struct Relays {
    ended: bool,
    next: u64,
    open: HashMap<u64, [OwnedFd; 2]>,
}

/// Shuts both ways down on each descriptor: the copies of the relay on
/// them see the end of their streams at once.
fn shut(fds: &[OwnedFd; 2]) {
    for fd in fds {
        // SAFETY: shutdown of a socket we hold a descriptor of.
        unsafe { libc::shutdown(fd.as_raw_fd(), libc::SHUT_RDWR) };
    }
}

/// One relay in its step's list, taken out of it when the relay ends.
struct Listed {
    relays: Arc<Mutex<Relays>>,
    key: u64,
}

impl Listed {
    /// None when the step has ended already: the relay must not start.
    fn new(relays: &Arc<Mutex<Relays>>, fds: [OwnedFd; 2]) -> Option<Listed> {
        let mut r = relays.lock().unwrap_or_else(|e| e.into_inner());
        if r.ended {
            return None;
        }
        r.next += 1;
        let key = r.next;
        r.open.insert(key, fds);
        Some(Listed { relays: Arc::clone(relays), key })
    }
}

impl Drop for Listed {
    fn drop(&mut self) {
        self.relays.lock().unwrap_or_else(|e| e.into_inner()).open.remove(&self.key);
    }
}

fn sessions() -> &'static Mutex<HashMap<String, Arc<Session>>> {
    static S: OnceLock<Mutex<HashMap<String, Arc<Session>>>> = OnceLock::new();
    S.get_or_init(Default::default)
}

fn steps() -> &'static Mutex<HashMap<String, Step>> {
    static S: OnceLock<Mutex<HashMap<String, Step>>> = OnceLock::new();
    S.get_or_init(Default::default)
}

/// 128 random bits as hex, or an error: a token is never made from
/// anything guessable.
fn token() -> io::Result<String> {
    use ring::rand::SecureRandom as _;
    let mut b = [0u8; 16];
    ring::rand::SystemRandom::new().fill(&mut b).map_err(|_| io::Error::other("no random bytes for an ssh session"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= crate::sshfwd::MAX_ID && !id.contains(['\n', '\r', '\0'])
}

/// `POST /kiri/build/ssh` `{"ids": [...]}`: opens a session, answers with
/// its token, then serves the client's agent connections to the builds that
/// name it, until the client goes. The connection is the session's from
/// then on.
pub(super) fn open_session(req: &Request, w: &mut UnixStream, uid: Option<u32>) -> io::Result<Next> {
    let v: Value = serde_json::from_slice(&req.body).unwrap_or_default();
    let ids: Vec<String> = v["ids"].as_array().into_iter().flatten().filter_map(|i| i.as_str().map(str::to_owned)).collect();
    if ids.is_empty() || ids.len() > MAX_IDS || !ids.iter().all(|i| valid_id(i)) {
        http::error(w, 400, "bad ssh ids")?;
        return Ok(Next::Close);
    }
    let t = match token() {
        Ok(t) => t,
        Err(e) => {
            http::error(w, 500, &e.to_string())?;
            return Ok(Next::Close);
        }
    };
    let (tx, rx) = mpsc::channel();
    sessions().lock().unwrap_or_else(|e| e.into_inner()).insert(t.clone(), Arc::new(Session { uid, ids, asks: Mutex::new(tx) }));
    let answered = http::json(w, 200, &json!({ "session": t }).to_string());
    if answered.is_ok() {
        serve_session(w, &rx);
    }
    let gone = sessions().lock().unwrap_or_else(|e| e.into_inner()).remove(&t);
    // Steps of builds still running that named it find it gone.
    if let Some(gone) = gone {
        steps().lock().unwrap_or_else(|e| e.into_inner()).retain(|_, s| !Arc::ptr_eq(&s.session, &gone));
    }
    answered.map(|()| Next::Close)
}

/// Asks the client for each connection, one at a time, until it goes.
fn serve_session(w: &mut UnixStream, asks: &mpsc::Receiver<Ask>) {
    loop {
        match asks.recv_timeout(Duration::from_millis(500)) {
            Ok(a) => {
                let _ = w.set_read_timeout(Some(CLIENT_ANSWER));
                let got = writeln!(w, "{}", a.id).and_then(|()| crate::sshfwd::recv_fd(w));
                match got {
                    Ok(Some((b'1', Some(fd)))) if is_socket(&fd) => {
                        let _ = a.reply.send(Some(fd));
                    }
                    Ok(Some(_)) => {
                        let _ = a.reply.send(None);
                    }
                    // Gone, or no answer in time: the session ends.
                    Ok(None) | Err(_) => return,
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if client_gone(w) {
                    return;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// The client sends nothing unasked: anything to read is its end closing.
fn client_gone(w: &UnixStream) -> bool {
    let mut p = libc::pollfd { fd: w.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    // SAFETY: one pollfd we own, no wait.
    let n = unsafe { libc::poll(&mut p, 1, 0) };
    n != 0
}

/// Only a socket is relayed: whatever else a client sends is refused.
fn is_socket(fd: &OwnedFd) -> bool {
    // SAFETY: fstat into storage we own on a descriptor we own.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::fstat(fd.as_raw_fd(), &mut st) == 0 && st.st_mode & libc::S_IFMT == libc::S_IFSOCK }
}

/// The ids a build that names `session` may mount, if it is live and was
/// opened by the same user as the build.
pub(super) fn session_ids(session: &str, uid: Option<u32>) -> Result<Vec<String>, String> {
    let s = sessions().lock().unwrap_or_else(|e| e.into_inner()).get(session).cloned();
    match s {
        Some(s) if s.uid == uid => Ok(s.ids.clone()),
        _ => Err("the build's ssh session is not open (it ends with the kiri build that opened it)".into()),
    }
}

/// One step's mount of an agent: its token, live until this is dropped.
pub(super) struct StepAgent {
    pub token: String,
}

impl Drop for StepAgent {
    /// No new connection, and every open one shut down: the step's end
    /// closes its relays even if the guest side lingers.
    fn drop(&mut self) {
        let step = steps().lock().unwrap_or_else(|e| e.into_inner()).remove(&self.token);
        if let Some(step) = step {
            let mut r = step.relays.lock().unwrap_or_else(|e| e.into_inner());
            r.ended = true;
            for fds in r.open.values() {
                shut(fds);
            }
        }
    }
}

/// A token for one step's mount of `id` in `session`.
pub(super) fn step_agent(session: &str, id: &str) -> Result<StepAgent, String> {
    let s = sessions().lock().unwrap_or_else(|e| e.into_inner()).get(session).cloned();
    let s = s.ok_or_else(|| format!("no SSH key {id:?} forwarded from the client"))?;
    if !s.ids.iter().any(|i| i == id) {
        return Err(format!("unset ssh forward key {id}"));
    }
    let token = token().map_err(|e| e.to_string())?;
    steps().lock().unwrap_or_else(|e| e.into_inner()).insert(token.clone(), Step { session: s, id: id.to_owned(), open: Arc::default(), relays: Arc::default() });
    Ok(StepAgent { token })
}

/// A connection for a live step token: a fresh one to its agent, from the
/// client, counted against the mount's limit while it is open.
fn connect(token: &str) -> Option<(OwnedFd, Counted, Arc<Mutex<Relays>>)> {
    let (session, id, open, relays) = {
        let steps = steps().lock().unwrap_or_else(|e| e.into_inner());
        let s = steps.get(token)?;
        (Arc::clone(&s.session), s.id.clone(), Arc::clone(&s.open), Arc::clone(&s.relays))
    };
    if open.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
        open.fetch_sub(1, Ordering::SeqCst);
        return None;
    }
    let counted = Counted(open);
    let (tx, rx) = mpsc::channel();
    session.asks.lock().unwrap_or_else(|e| e.into_inner()).send(Ask { id, reply: tx }).ok()?;
    let fd = rx.recv_timeout(CLIENT_ANSWER + Duration::from_secs(5)).ok()??;
    Some((fd, counted, relays))
}

struct Counted(Arc<AtomicUsize>);

impl Drop for Counted {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The step token a guest connection starts with: 32 hex digits and `\n`.
fn read_token(r: &mut impl Read) -> Option<String> {
    let mut b = [0u8; 33];
    r.read_exact(&mut b).ok()?;
    (b[32] == b'\n' && b[..32].iter().all(u8::is_ascii_hexdigit)).then(|| String::from_utf8_lossy(&b[..32]).into_owned())
}

/// One guest connection on [`BUILD_SSH_PORT`]: relayed to the agent of the
/// step whose token it starts with, or closed.
pub fn serve_step(stream: kiri_vmm::VsockStream) {
    let _ = std::thread::Builder::new().name("kiri-build-ssh".into()).spawn(move || {
        let (Ok(a), Ok(b)) = (stream.fd.try_clone(), stream.fd.try_clone()) else { return };
        relay_step(std::fs::File::from(a), std::fs::File::from(b));
        drop(stream);
    });
}

/// The relay of one guest connection, given as its two halves.
fn relay_step(mut from_guest: std::fs::File, mut to_guest: std::fs::File) {
    // A connection that names no live token within a few seconds is dropped.
    // SAFETY: setsockopt on a descriptor we own, with a timeval we own.
    unsafe {
        let tv = libc::timeval { tv_sec: 5, tv_usec: 0 };
        libc::setsockopt(from_guest.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&tv as *const libc::timeval).cast(), std::mem::size_of::<libc::timeval>() as _);
    }
    let Some(t) = read_token(&mut from_guest) else { return };
    let Some((agent, _counted, relays)) = connect(&t) else { return };
    let (Ok(g), Ok(a)) = (from_guest.try_clone(), agent.try_clone()) else { return };
    // Listed for the step's end; a step that ended meanwhile gets nothing.
    let Some(_listed) = Listed::new(&relays, [g.into(), a]) else { return };
    // SAFETY: as above; no limit once relaying.
    unsafe {
        let tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
        libc::setsockopt(from_guest.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&tv as *const libc::timeval).cast(), std::mem::size_of::<libc::timeval>() as _);
    }
    let agent = UnixStream::from(agent);
    let (Ok(mut agent_read), mut agent_write) = (agent.try_clone(), agent) else { return };
    let down = std::thread::spawn(move || {
        let _ = io::copy(&mut agent_read, &mut to_guest);
        // SAFETY: half-closing a socket we own.
        unsafe { libc::shutdown(to_guest.as_raw_fd(), libc::SHUT_WR) };
    });
    let _ = io::copy(&mut from_guest, &mut agent_write);
    let _ = agent_write.shutdown(std::net::Shutdown::Write);
    let _ = down.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    /// A session as a client opens one, on a socket pair: the engine's end
    /// and the client's agents served on the other.
    fn session(uid: Option<u32>, ids: &[&str]) -> (String, std::thread::JoinHandle<()>, UnixStream) {
        let (mut engine, client) = UnixStream::pair().unwrap();
        let body = json!({ "ids": ids }).to_string();
        let req = Request::internal("POST", "/kiri/build/ssh", &[], body.into_bytes());
        let t = std::thread::spawn(move || {
            let _ = open_session(&req, &mut engine, uid);
        });
        let mut r = BufReader::new(client.try_clone().unwrap());
        let mut head = String::new();
        let mut len = 0;
        loop {
            let mut l = String::new();
            std::io::BufRead::read_line(&mut r, &mut l).unwrap();
            if let Some(v) = l.to_ascii_lowercase().strip_prefix("content-length:") {
                len = v.trim().parse().unwrap();
            }
            head.push_str(&l);
            if l == "\r\n" {
                break;
            }
        }
        let mut b = vec![0; len];
        r.read_exact(&mut b).unwrap();
        let v: Value = serde_json::from_slice(&b).unwrap();
        (v["session"].as_str().unwrap().to_owned(), t, client)
    }

    /// The client's side: answers each id with a connection that, asked
    /// anything, says `id:<id>` and closes (an agent speaks only when
    /// spoken to); `refuse` gets `0`.
    fn answer(client: UnixStream) -> std::thread::JoinHandle<Vec<String>> {
        std::thread::spawn(move || {
            let mut r = BufReader::new(client.try_clone().unwrap());
            let mut asked = Vec::new();
            loop {
                let mut l = String::new();
                if std::io::BufRead::read_line(&mut r, &mut l).unwrap_or(0) == 0 {
                    return asked;
                }
                let id = l.trim_end().to_owned();
                asked.push(id.clone());
                if id == "refuse" {
                    crate::sshfwd::send_fd(&client, b'0', None).unwrap();
                    continue;
                }
                let (mut mine, theirs) = UnixStream::pair().unwrap();
                crate::sshfwd::send_fd(&client, b'1', Some(theirs.as_raw_fd())).unwrap();
                drop(theirs);
                std::thread::spawn(move || {
                    let mut asked = [0u8; 1];
                    if mine.read_exact(&mut asked).is_ok() {
                        let _ = mine.write_all(format!("id:{id}").as_bytes());
                    }
                });
            }
        })
    }

    /// A guest connection through the relay: what it reads back.
    fn through(first: &[u8]) -> Vec<u8> {
        let (guest, engine) = UnixStream::pair().unwrap();
        let a = std::fs::File::from(OwnedFd::from(engine.try_clone().unwrap()));
        let b = std::fs::File::from(OwnedFd::from(engine));
        let t = std::thread::spawn(move || relay_step(a, b));
        let mut guest = guest;
        guest.write_all(first).unwrap();
        guest.shutdown(std::net::Shutdown::Write).unwrap();
        let mut out = Vec::new();
        let _ = guest.read_to_end(&mut out);
        t.join().unwrap();
        out
    }

    /// The step reaches the agent the client named for that id, for as long
    /// as its token lives: after the step (the token dropped), a stale or
    /// made-up token gets nothing, and the client is never asked.
    #[test]
    fn a_step_reaches_its_agent_only_while_its_token_lives() {
        let (s, t, client) = session(None, &["default", "refuse"]);
        let closer = client.try_clone().unwrap();
        let asked = answer(client);
        let step = step_agent(&s, "default").unwrap();
        assert_eq!(through(format!("{}\n?", step.token).as_bytes()), b"id:default");
        let gone = step.token.clone();
        drop(step);
        assert_eq!(through(format!("{gone}\n?").as_bytes()), b"", "a step's socket after the step");
        assert_eq!(through(b"00000000000000000000000000000000\n"), b"", "a made-up token");
        assert_eq!(through(b"not a token"), b"");
        // The client may refuse; only a socket is relayed.
        let refused = step_agent(&s, "refuse").unwrap();
        assert_eq!(through(format!("{}\n", refused.token).as_bytes()), b"");
        // Ids the session does not forward are not mounted.
        assert_eq!(step_agent(&s, "other").err().unwrap(), "unset ssh forward key other");
        drop(refused);
        // The client going ends the session: its tokens go with it.
        let late = step_agent(&s, "default").unwrap();
        closer.shutdown(std::net::Shutdown::Both).unwrap();
        asked.join().unwrap();
        let started = std::time::Instant::now();
        while session_ids(&s, None).is_ok() && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(50));
        }
        t.join().unwrap();
        assert!(session_ids(&s, None).is_err());
        assert_eq!(through(format!("{}\n", late.token).as_bytes()), b"");
        assert!(step_agent(&s, "default").is_err());
    }

    /// A step's end closes the relays it has open, not only new
    /// connections: with an agent that stays open and a guest that never
    /// closes its end (a child that lingers), dropping the step's mount
    /// still ends the relay and the guest sees its connection close.
    #[test]
    fn a_steps_end_closes_its_open_relays() {
        let (s, _t, client) = session(None, &["default"]);
        // the client's side: a connection per id that it keeps open, silent
        let kept = Arc::new(Mutex::new(Vec::new()));
        let held = Arc::clone(&kept);
        std::thread::spawn(move || {
            let mut r = std::io::BufReader::new(client.try_clone().unwrap());
            loop {
                let mut l = String::new();
                if std::io::BufRead::read_line(&mut r, &mut l).unwrap_or(0) == 0 {
                    return;
                }
                let (mine, theirs) = UnixStream::pair().unwrap();
                crate::sshfwd::send_fd(&client, b'1', Some(theirs.as_raw_fd())).unwrap();
                held.lock().unwrap().push(mine);
            }
        });
        let step = step_agent(&s, "default").unwrap();
        let (mut guest, engine) = UnixStream::pair().unwrap();
        let a = std::fs::File::from(OwnedFd::from(engine.try_clone().unwrap()));
        let b = std::fs::File::from(OwnedFd::from(engine));
        let relay = std::thread::spawn(move || relay_step(a, b));
        guest.write_all(format!("{}\n", step.token).as_bytes()).unwrap();
        let started = std::time::Instant::now();
        while kept.lock().unwrap().is_empty() && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(kept.lock().unwrap().len(), 1, "the relay reached the agent");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = guest.read_to_end(&mut out);
            let _ = tx.send(out);
        });
        drop(step);
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).expect("the guest's connection closes with the step"), b"");
        let started = std::time::Instant::now();
        while !relay.is_finished() && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(relay.is_finished(), "the relay ended with the step");
        // the agent's end saw it close too
        let mut agent = kept.lock().unwrap().pop().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(agent.read(&mut [0u8; 1]).ok());
        });
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Some(0));
    }

    /// Another user's build cannot name a session, nor can one that guesses.
    #[test]
    fn a_session_is_for_the_user_who_opened_it() {
        let (s, _t, client) = session(Some(1000), &["default"]);
        let _asked = answer(client);
        assert_eq!(session_ids(&s, Some(1000)).unwrap(), ["default"]);
        assert!(session_ids(&s, Some(1001)).is_err());
        assert!(session_ids(&s, None).is_err());
        assert!(session_ids(&token().unwrap(), Some(1000)).is_err());
        // Two tokens are never the same.
        assert_ne!(step_agent(&s, "default").unwrap().token, step_agent(&s, "default").unwrap().token);
    }

    /// A file sent in place of a socket is refused.
    #[test]
    fn only_a_socket_is_relayed() {
        let f = std::fs::File::open("/dev/null").unwrap();
        assert!(!is_socket(&OwnedFd::from(f)));
        let (a, _b) = UnixStream::pair().unwrap();
        assert!(is_socket(&OwnedFd::from(a)));
    }

    /// A step opens at most MAX_CONNECTIONS at once.
    #[test]
    fn a_step_has_a_limit_of_open_connections() {
        let (s, _t, client) = session(None, &["default"]);
        let _asked = answer(client);
        let step = step_agent(&s, "default").unwrap();
        let held: Vec<_> = (0..MAX_CONNECTIONS).map(|_| connect(&step.token).unwrap()).collect();
        assert!(connect(&step.token).is_none());
        drop(held);
        assert!(connect(&step.token).is_some());
    }
}
