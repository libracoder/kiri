//! Docker Swarm on one node: `docker swarm init`, `docker service`, `docker
//! stack`, nodes, tasks, secrets and configs. Kiri is the swarm's only node,
//! always its leader. A service's tasks are ordinary containers, named and
//! labelled as Docker names them, which `reconcile` keeps as the service's
//! spec says: replicas, restart policy, rolling updates and rollbacks.
//! Overlay networks are bridge networks that say `overlay` and `swarm`; a
//! service's name resolves to its tasks on each of its networks.
//!
//! Not here: more than one node (`swarm join`), Raft, encryption at rest
//! and autolock, job services, and a virtual IP per service (names resolve
//! to the tasks' own addresses, as with `--endpoint-mode dnsrr`).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::api::{Next, filters, reply};
use super::engine::{Engine, Error, Status};
use super::http::{self, Request};
use super::time;

/// What every Swarm endpoint answers before `docker swarm init` (moby's
/// `errNoSwarm`), with 503.
pub const NOT_MANAGER: &str = "This node is not a swarm manager. Use \"docker swarm init\" or \"docker swarm join\" to connect this node to swarm and try again.";
const ALREADY: &str = "This node is already part of a swarm. Use \"docker swarm leave\" to leave this swarm and join another one.";
const NOT_PART: &str = "This node is not part of a swarm";
const LEAVE_MANAGER: &str = "You are attempting to leave the swarm on a node that is participating as a manager. Removing the last manager erases all current state of the swarm. Use `--force` to ignore this message.";
/// Ended tasks kept per slot, as Docker's default `TaskHistoryRetentionLimit`.
const HISTORY: usize = 5;
/// Ports Docker hands out for `--publish target=80` with no published port.
const AUTO_PORTS: std::ops::RangeInclusive<u16> = 30000..=32767;

/// An error with the status Docker answers it with: 503 for "not a
/// manager", 403 for an overlay network outside a swarm, else the API's.
pub enum Fail {
    Unavailable(String),
    Forbidden(String),
    Api(Error),
}

impl From<Error> for Fail {
    fn from(e: Error) -> Self {
        Fail::Api(e)
    }
}

fn bad(m: impl Into<String>) -> Fail {
    Fail::Api(Error::BadRequest(m.into()))
}

fn not_found(m: impl Into<String>) -> Fail {
    Fail::Api(Error::NotFound(m.into()))
}

fn answer(w: &mut UnixStream, r: Result<Value, Fail>, ok: u16) -> io::Result<Next> {
    match r {
        Ok(v) => reply(w, Ok(v), ok),
        Err(Fail::Api(e)) => reply(w, Err(e), ok),
        Err(Fail::Unavailable(m)) => {
            http::error(w, 503, &m)?;
            Ok(Next::KeepAlive)
        }
        Err(Fail::Forbidden(m)) => {
            http::error(w, 403, &m)?;
            Ok(Next::KeepAlive)
        }
    }
}

fn now_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64)
}

fn stamp(ns: u64) -> String {
    time::rfc3339(UNIX_EPOCH + Duration::from_nanos(ns))
}

/// A swarmkit-style object ID: 25 characters of lowercase base 36.
fn new_id() -> String {
    let hex = super::engine::random_hex(16);
    let mut n = u128::from_str_radix(&hex, 16).unwrap_or_else(|_| now_ns() as u128);
    let digits = b"0123456789abcdefghijklmnopqrstuvwxyz";
    (0..25)
        .map(|_| {
            let d = digits[(n % 36) as usize] as char;
            n /= 36;
            d
        })
        .collect()
}

fn b64_encode(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            s.push(if i <= c.len() { A[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    s
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    };
    let clean: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=').collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for c in clean.chunks(4) {
        if c.len() == 1 {
            return None;
        }
        let mut n = 0u32;
        for (i, b) in c.iter().enumerate() {
            n |= (val(*b)? as u32) << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if c.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if c.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// Durations in a spec are nanoseconds.
fn nanos(v: &Value, default: Duration) -> Duration {
    v.as_u64().map(Duration::from_nanos).unwrap_or(default)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Cluster {
    id: String,
    node_id: String,
    created: u64,
    updated: u64,
    version: u64,
    spec: Value,
    /// The address `--advertise-addr` gave, without a port.
    addr: String,
    worker_token: String,
    manager_token: String,
    /// The one node's own spec (Role, Availability, Labels) and version.
    node_spec: Value,
    node_version: u64,
    node_updated: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Service {
    id: String,
    version: u64,
    created: u64,
    updated: u64,
    spec: Value,
    #[serde(default)]
    previous: Option<Value>,
    /// `UpdateStatus`, while an update or rollback runs and after.
    #[serde(default)]
    update: Option<Value>,
    /// The `X-Registry-Auth` the service was created or updated with, to
    /// pull its image for each task.
    #[serde(default)]
    auth: String,
    /// `Endpoint.Ports`: the spec's, with ingress ports handed out.
    #[serde(default)]
    ports: Vec<Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Task {
    id: String,
    version: u64,
    created: u64,
    updated: u64,
    service: String,
    slot: u64,
    /// The service's `TaskTemplate` when this task was made: a task whose
    /// spec differs from the service's is out of date.
    spec: Value,
    desired: String,
    state: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    err: String,
    timestamp: u64,
    #[serde(default)]
    container: String,
    #[serde(default)]
    exit: Option<i64>,
    /// When it was first seen running (and healthy, if it has a healthcheck).
    #[serde(default)]
    running_since: Option<u64>,
}

impl Task {
    fn ended(&self) -> bool {
        matches!(self.state.as_str(), "complete" | "shutdown" | "failed" | "rejected" | "remove" | "orphaned")
    }

    /// Wanted running and not over yet.
    fn live(&self) -> bool {
        self.desired == "running" && !self.ended()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Blob {
    id: String,
    version: u64,
    created: u64,
    updated: u64,
    /// Name, Labels (and Driver, Templating) as given; never Data.
    spec: Value,
    data: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    #[serde(default)]
    cluster: Option<Cluster>,
    /// One counter for every object's `Version.Index`, as Raft's.
    #[serde(default)]
    index: u64,
    #[serde(default)]
    services: BTreeMap<String, Service>,
    #[serde(default)]
    tasks: BTreeMap<String, Task>,
    #[serde(default)]
    secrets: BTreeMap<String, Blob>,
    #[serde(default)]
    configs: BTreeMap<String, Blob>,
    /// Networks made with `--driver overlay`, by name.
    #[serde(default)]
    overlays: BTreeSet<String>,
}

impl State {
    fn next(&mut self) -> u64 {
        self.index += 1;
        self.index
    }

    fn cluster(&self) -> Result<&Cluster, Fail> {
        self.cluster.as_ref().ok_or_else(|| Fail::Unavailable(NOT_MANAGER.into()))
    }

    fn service_name(&self, id: &str) -> String {
        self.services.get(id).and_then(|s| s.spec["Name"].as_str()).unwrap_or_default().to_owned()
    }

    /// A service by ID, unique ID prefix or name, as Docker looks it up.
    fn find_service(&self, key: &str) -> Result<String, Fail> {
        if self.services.contains_key(key) {
            return Ok(key.to_owned());
        }
        if let Some((id, _)) = self.services.iter().find(|(_, s)| s.spec["Name"] == key) {
            return Ok(id.clone());
        }
        let prefixed: Vec<&String> = self.services.keys().filter(|id| !key.is_empty() && id.starts_with(key)).collect();
        match prefixed.as_slice() {
            [one] => Ok((*one).clone()),
            [] => Err(not_found(format!("service {key} not found"))),
            _ => Err(bad(format!("service {key} is ambiguous ({} matches found)", prefixed.len()))),
        }
    }

    fn find_task(&self, key: &str) -> Result<String, Fail> {
        if self.tasks.contains_key(key) {
            return Ok(key.to_owned());
        }
        let prefixed: Vec<&String> = self.tasks.keys().filter(|id| !key.is_empty() && id.starts_with(key)).collect();
        match prefixed.as_slice() {
            [one] => Ok((*one).clone()),
            [] => Err(not_found(format!("task {key} not found"))),
            _ => Err(bad(format!("task {key} is ambiguous ({} matches found)", prefixed.len()))),
        }
    }
}

fn find_blob(map: &BTreeMap<String, Blob>, key: &str, kind: &str) -> Result<String, Fail> {
    if map.contains_key(key) {
        return Ok(key.to_owned());
    }
    if let Some((id, _)) = map.iter().find(|(_, b)| b.spec["Name"] == key) {
        return Ok(id.clone());
    }
    let prefixed: Vec<&String> = map.keys().filter(|id| !key.is_empty() && id.starts_with(key)).collect();
    match prefixed.as_slice() {
        [one] => Ok((*one).clone()),
        _ => Err(not_found(format!("{kind} {key} not found"))),
    }
}

/// The swarm's state, kept in `swarm.json` beside `networks.json`.
pub struct Swarm {
    path: PathBuf,
    state: Mutex<State>,
    /// Wakes the reconciler early (a service changed, a container exited).
    kick: Mutex<bool>,
    kicked: Condvar,
    /// Tasks whose container is being made (an image pull can be slow):
    /// the reconciler leaves them alone until that is done.
    starting: Mutex<BTreeSet<String>>,
    /// Ingress ports: (published port, protocol) → the task it reaches and
    /// its forward from the host.
    ingress: Mutex<HashMap<(u16, String), (String, super::ports::Forwards)>>,
    /// Ingress ports that could not be bound, warned about once each.
    refused: Mutex<BTreeSet<(u16, String)>>,
}

impl Swarm {
    pub fn load(root: &Path) -> io::Result<Swarm> {
        let path = root.join("swarm.json");
        let state = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                crate::diag::warn!("swarm state unreadable; starting without a swarm", error = e);
                State::default()
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e),
        };
        Ok(Swarm { path, state: Mutex::new(state), kick: Mutex::new(false), kicked: Condvar::new(), starting: Mutex::default(), ingress: Mutex::default(), refused: Mutex::default() })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Written whole to a new file, then renamed over the old one; readable
    /// only by its owner, since secrets are in it.
    fn save(&self, st: &State) {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = self.path.with_extension("json.tmp");
        let result = (|| {
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            f.write_all(&serde_json::to_vec(st).map_err(io::Error::other)?)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.path)
        })();
        if let Err(e) = result {
            crate::diag::warn!("swarm state not saved", error = e);
        }
    }

    pub fn wake(&self) {
        *self.kick.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.kicked.notify_all();
    }

    fn wait(&self, d: Duration) {
        let g = self.kick.lock().unwrap_or_else(|e| e.into_inner());
        let (mut g, _) = self.kicked.wait_timeout_while(g, d, |k| !*k).unwrap_or_else(|e| e.into_inner());
        *g = false;
    }

    pub fn active(&self) -> bool {
        self.lock().cluster.is_some()
    }

    /// Whether `network` was made as an overlay network.
    pub fn is_overlay(&self, network: &str) -> bool {
        self.lock().overlays.contains(network)
    }

    /// The `Swarm` field of `GET /info`.
    pub fn info(&self) -> Value {
        let st = self.lock();
        let Some(c) = &st.cluster else {
            return json!({"NodeID": "", "NodeAddr": "", "LocalNodeState": "inactive", "ControlAvailable": false, "Error": "", "RemoteManagers": null});
        };
        json!({
            "NodeID": c.node_id,
            "NodeAddr": c.addr,
            "LocalNodeState": "active",
            "ControlAvailable": true,
            "Error": "",
            "RemoteManagers": [{"NodeID": c.node_id, "Addr": format!("{}:2377", c.addr)}],
            "Nodes": 1,
            "Managers": 1,
            "Cluster": cluster_info(c),
        })
    }
}

fn default_swarm_spec() -> Value {
    json!({
        "Name": "default",
        "Labels": {},
        "Orchestration": {"TaskHistoryRetentionLimit": HISTORY},
        "Raft": {"SnapshotInterval": 10000, "KeepOldSnapshots": 0, "LogEntriesForSlowFollowers": 500, "ElectionTick": 10, "HeartbeatTick": 1},
        "Dispatcher": {"HeartbeatPeriod": 5_000_000_000u64},
        "CAConfig": {"NodeCertExpiry": 7_776_000_000_000_000u64},
        "TaskDefaults": {},
        "EncryptionConfig": {"AutoLockManagers": false},
    })
}

fn cluster_info(c: &Cluster) -> Value {
    json!({
        "ID": c.id,
        "Version": {"Index": c.version},
        "CreatedAt": stamp(c.created),
        "UpdatedAt": stamp(c.updated),
        "Spec": c.spec,
        "TLSInfo": {"TrustRoot": "", "CertIssuerSubject": "", "CertIssuerPublicKey": ""},
        "RootRotationInProgress": false,
        "DefaultAddrPool": ["10.0.0.0/8"],
        "SubnetSize": 24,
        "DataPathPort": 4789,
    })
}

/// Routes the Swarm endpoints; `None` for every other request. An overlay
/// network's create comes here too.
pub fn route(req: &Request, engine: &Arc<Engine>, w: &mut UnixStream) -> Option<io::Result<Next>> {
    let p = req.path.as_str();
    let m = req.method.as_str();
    let sw = &engine.swarm;
    Some(match (m, p) {
        ("GET", "/swarm") => answer(w, inspect_swarm(sw), 200),
        ("POST", "/swarm/init") => answer(w, init(req, engine), 200),
        ("POST", "/swarm/join") => answer(w, Err(bad("Kiri runs a swarm of one node: it cannot join another swarm")), 200),
        ("POST", "/swarm/leave") => answer(w, leave(req, engine).map(|()| Value::Null), 200),
        ("POST", "/swarm/update") => answer(w, update_swarm(req, sw).map(|()| Value::Null), 200),
        ("GET", "/swarm/unlockkey") => answer(w, sw.lock().cluster().map(|_| json!({"UnlockKey": ""})), 200),
        ("POST", "/swarm/unlock") => answer(w, Err(bad("swarm is not locked")), 200),
        ("GET", "/nodes") => answer(w, nodes(req, engine), 200),
        ("GET", "/services") => answer(w, services(req, engine), 200),
        ("POST", "/services/create") => answer(w, service_create(req, engine), 201),
        ("GET", "/tasks") => answer(w, tasks(req, engine), 200),
        ("GET", "/secrets") => answer(w, blobs(req, sw, false), 200),
        ("POST", "/secrets/create") => answer(w, blob_create(req, sw, false), 201),
        ("GET", "/configs") => answer(w, blobs(req, sw, true), 200),
        ("POST", "/configs/create") => answer(w, blob_create(req, sw, true), 201),
        ("POST", "/networks/create") => {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            if body["Driver"] != "overlay" {
                return None;
            }
            answer(w, overlay_create(req, engine, &body), 201)
        }
        _ => {
            let (kind, rest) = p.strip_prefix('/')?.split_once('/')?;
            let (id, action) = rest.split_once('/').unwrap_or((rest, ""));
            match (kind, m, action) {
                ("nodes", "GET", "") => answer(w, node(engine, id), 200),
                ("nodes", "POST", "update") => answer(w, node_update(req, sw, id).map(|()| Value::Null), 200),
                ("nodes", "DELETE", "") => answer(w, Err(bad("can not remove node, it is the only manager of this swarm")), 200),
                ("services", "GET", "") => answer(w, service_inspect(engine, id), 200),
                ("services", "DELETE", "") => answer(w, service_remove(engine, id).map(|()| Value::Null), 200),
                ("services", "POST", "update") => answer(w, service_update(req, engine, id), 200),
                ("services", "GET", "logs") => logs(req, engine, Some(id), None, w),
                ("tasks", "GET", "") => answer(w, task_inspect(engine, id), 200),
                ("tasks", "GET", "logs") => logs(req, engine, None, Some(id), w),
                ("secrets", "GET", "") => answer(w, blob_inspect(sw, id, false), 200),
                ("secrets", "DELETE", "") => answer(w, blob_remove(sw, id, false).map(|()| Value::Null), 204),
                ("secrets", "POST", "update") => answer(w, blob_update(req, sw, id, false).map(|()| Value::Null), 200),
                ("configs", "GET", "") => answer(w, blob_inspect(sw, id, true), 200),
                ("configs", "DELETE", "") => answer(w, blob_remove(sw, id, true).map(|()| Value::Null), 204),
                ("configs", "POST", "update") => answer(w, blob_update(req, sw, id, true).map(|()| Value::Null), 200),
                _ => return None,
            }
        }
    })
}

fn body_of(req: &Request) -> Result<Value, Fail> {
    if req.body.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(&req.body).map_err(|e| bad(format!("invalid JSON: {e}")))
}

fn version_param(req: &Request) -> Result<u64, Fail> {
    req.query("version").and_then(|v| v.parse().ok()).ok_or_else(|| bad("invalid swarm version: the version parameter is required"))
}

fn out_of_sequence(kind: &str) -> Fail {
    bad(format!("update out of sequence: the {kind} was changed since it was read; read it again and retry"))
}

// --- The swarm and its node -------------------------------------------------

fn inspect_swarm(sw: &Swarm) -> Result<Value, Fail> {
    let st = sw.lock();
    let c = st.cluster()?;
    let mut v = cluster_info(c);
    v["JoinTokens"] = json!({"Worker": c.worker_token, "Manager": c.manager_token});
    Ok(v)
}

fn init(req: &Request, engine: &Engine) -> Result<Value, Fail> {
    let body = body_of(req)?;
    let sw = &engine.swarm;
    let mut st = sw.lock();
    if st.cluster.is_some() {
        return Err(Fail::Unavailable(ALREADY.into()));
    }
    // `--advertise-addr` may be an address, an address and port, or an
    // interface name, which only has meaning on a Linux host.
    let advertise = body["AdvertiseAddr"].as_str().filter(|a| !a.is_empty()).unwrap_or("127.0.0.1");
    let host = advertise.rsplit_once(':').filter(|(h, p)| !h.contains(':') || h.starts_with('[') || p.parse::<u16>().is_err()).map_or(advertise, |(h, p)| {
        if p.parse::<u16>().is_ok() { h } else { advertise }
    });
    let addr = if host.parse::<std::net::IpAddr>().is_ok() { host.trim_matches(['[', ']']).to_owned() } else { "127.0.0.1".to_owned() };
    let mut spec = default_swarm_spec();
    if let Value::Object(given) = &body["Spec"] {
        for (k, v) in given {
            if !v.is_null() {
                spec[k] = v.clone();
            }
        }
    }
    let now = now_ns();
    let version = st.next();
    let id = new_id();
    let node_id = new_id();
    let token = |kind: &str| format!("SWMTKN-1-{}-{kind}", super::engine::random_hex(25));
    st.cluster = Some(Cluster {
        id,
        node_id: node_id.clone(),
        created: now,
        updated: now,
        version,
        spec,
        addr,
        worker_token: token("worker"),
        manager_token: token("manager"),
        node_spec: json!({"Labels": {}, "Role": "manager", "Availability": "active"}),
        node_version: version,
        node_updated: now,
    });
    sw.save(&st);
    drop(st);
    crate::diag::info!("swarm initialized", node = node_id);
    engine.emit("node", "create", &node_id, serde_json::Map::new(), None);
    Ok(Value::String(node_id))
}

fn leave(req: &Request, engine: &Engine) -> Result<(), Fail> {
    let sw = &engine.swarm;
    let (tasks, overlays) = {
        let st = sw.lock();
        if st.cluster.is_none() {
            return Err(Fail::Unavailable(NOT_PART.into()));
        }
        if !req.flag("force") {
            return Err(Fail::Unavailable(LEAVE_MANAGER.into()));
        }
        (st.tasks.values().map(|t| t.container.clone()).filter(|c| !c.is_empty()).collect::<Vec<_>>(), st.overlays.clone())
    };
    let labelled = engine.each(|c| c.spec.labels.get("com.docker.swarm.task.id").map(|_| c.id.clone()));
    for c in tasks.into_iter().chain(labelled) {
        let _ = engine.remove(&c, true, false);
    }
    for n in overlays {
        let _ = engine.network_remove(&n);
    }
    sw.ingress.lock().unwrap_or_else(|e| e.into_inner()).clear();
    let mut st = sw.lock();
    let index = st.index;
    *st = State { index, ..State::default() };
    sweep_files(engine.store.root(), &st);
    sw.save(&st);
    crate::diag::info!("left the swarm");
    Ok(())
}

fn update_swarm(req: &Request, sw: &Swarm) -> Result<(), Fail> {
    let version = version_param(req)?;
    let body = body_of(req)?;
    let mut st = sw.lock();
    st.cluster()?;
    let next = st.next();
    let c = st.cluster.as_mut().expect("checked");
    if c.version != version {
        return Err(out_of_sequence("swarm"));
    }
    if body.is_object() {
        let mut spec = default_swarm_spec();
        for (k, v) in body.as_object().into_iter().flatten() {
            spec[k] = v.clone();
        }
        c.spec = spec;
    }
    if req.flag("rotateWorkerToken") {
        c.worker_token = format!("SWMTKN-1-{}-worker", super::engine::random_hex(25));
    }
    if req.flag("rotateManagerToken") {
        c.manager_token = format!("SWMTKN-1-{}-manager", super::engine::random_hex(25));
    }
    c.version = next;
    c.updated = now_ns();
    sw.save(&st);
    Ok(())
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for its length; gethostname NUL-terminates
    // what fits.
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0;
    let name = if ok { String::from_utf8_lossy(&buf[..buf.iter().position(|b| *b == 0).unwrap_or(0)]).into_owned() } else { String::new() };
    let short = name.split('.').next().unwrap_or_default().to_owned();
    if short.is_empty() { "kiri".into() } else { short }
}

/// `uname -m`, as Docker's node description has it.
fn arch() -> &'static str {
    std::env::consts::ARCH
}

fn node_json(engine: &Engine, c: &Cluster) -> Value {
    let (mem, _) = engine.guest_memory().unwrap_or((0, 0));
    json!({
        "ID": c.node_id,
        "Version": {"Index": c.node_version},
        "CreatedAt": stamp(c.created),
        "UpdatedAt": stamp(c.node_updated),
        "Spec": c.node_spec,
        "Description": {
            "Hostname": hostname(),
            "Platform": {"Architecture": arch(), "OS": "linux"},
            "Resources": {"NanoCPUs": engine.cpus() as u64 * 1_000_000_000, "MemoryBytes": mem},
            "Engine": {"EngineVersion": super::api::ENGINE_VERSION, "Plugins": [
                {"Type": "Log", "Name": "json-file"}, {"Type": "Log", "Name": "local"},
                {"Type": "Network", "Name": "bridge"}, {"Type": "Network", "Name": "host"}, {"Type": "Network", "Name": "null"}, {"Type": "Network", "Name": "overlay"},
                {"Type": "Volume", "Name": "local"},
            ]},
            "TLSInfo": {"TrustRoot": "", "CertIssuerSubject": "", "CertIssuerPublicKey": ""},
        },
        "Status": {"State": "ready", "Addr": c.addr},
        "ManagerStatus": {"Leader": true, "Reachability": "reachable", "Addr": format!("{}:2377", c.addr)},
    })
}

fn nodes(req: &Request, engine: &Engine) -> Result<Value, Fail> {
    let f = filters(req, &["id", "label", "membership", "name", "node.label", "role"])?;
    let st = engine.swarm.lock();
    let c = st.cluster()?;
    let n = node_json(engine, c);
    let labels = &c.node_spec["Labels"];
    let keep = f.any("id", |v| c.node_id.starts_with(v))
        && f.any("name", |v| n["Description"]["Hostname"].as_str().is_some_and(|h| h.contains(v)))
        && f.any("role", |v| v == "manager")
        && f.any("membership", |v| v == "accepted")
        && f.values("node.label").is_none_or(|vs| vs.iter().all(|want| label_has(labels, want)));
    Ok(Value::Array(if keep { vec![n] } else { vec![] }))
}

fn label_has(labels: &Value, want: &str) -> bool {
    match want.split_once('=') {
        Some((k, v)) => labels.get(k).and_then(Value::as_str) == Some(v),
        None => labels.get(want).is_some(),
    }
}

fn node_is(c: &Cluster, key: &str) -> bool {
    key == c.node_id || key == "self" || key == hostname() || (!key.is_empty() && c.node_id.starts_with(key))
}

fn node(engine: &Engine, key: &str) -> Result<Value, Fail> {
    let st = engine.swarm.lock();
    let c = st.cluster()?;
    if !node_is(c, key) {
        return Err(not_found(format!("node {key} not found")));
    }
    Ok(node_json(engine, c))
}

fn node_update(req: &Request, sw: &Swarm, key: &str) -> Result<(), Fail> {
    let version = version_param(req)?;
    let body = body_of(req)?;
    let mut st = sw.lock();
    let c = st.cluster()?;
    if !node_is(c, key) {
        return Err(not_found(format!("node {key} not found")));
    }
    if c.node_version != version {
        return Err(out_of_sequence("node"));
    }
    if body["Role"].as_str().is_some_and(|r| r != "manager") {
        return Err(bad("attempting to demote the last manager of the swarm"));
    }
    let next = st.next();
    let c = st.cluster.as_mut().expect("checked");
    c.node_spec = json!({
        "Name": body["Name"],
        "Labels": if body["Labels"].is_object() { body["Labels"].clone() } else { json!({}) },
        "Role": "manager",
        "Availability": body["Availability"].as_str().unwrap_or("active"),
    });
    c.node_version = next;
    c.node_updated = now_ns();
    sw.save(&st);
    drop(st);
    sw.wake();
    Ok(())
}

// --- Services ---------------------------------------------------------------

/// Defaults Docker fills in where a spec leaves them out, checked for what
/// Kiri can run.
fn checked_spec(mut spec: Value) -> Result<Value, Fail> {
    let name = spec["Name"].as_str().unwrap_or_default().to_owned();
    if name.is_empty() {
        return Err(bad("name must be valid as a DNS name component"));
    }
    if name.len() > 63 || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') || name.starts_with(['-', '.']) {
        return Err(bad(format!("invalid name {name:?}: name must be valid as a DNS name component")));
    }
    if spec["TaskTemplate"]["ContainerSpec"]["Image"].as_str().unwrap_or_default().is_empty() {
        return Err(bad("ContainerSpec: image reference must be provided"));
    }
    if spec["TaskTemplate"]["PluginSpec"].is_object() || spec["TaskTemplate"]["NetworkAttachmentSpec"].is_object() {
        return Err(bad("Kiri runs container services only"));
    }
    let mode = &spec["Mode"];
    if mode["ReplicatedJob"].is_object() || mode["GlobalJob"].is_object() {
        return Err(bad("Kiri does not support job services (--mode replicated-job or global-job) yet"));
    }
    if !mode["Replicated"].is_object() && !mode["Global"].is_object() {
        spec["Mode"] = json!({"Replicated": {"Replicas": 1}});
    } else if mode["Replicated"].is_object() && mode["Replicated"]["Replicas"].is_null() {
        spec["Mode"]["Replicated"]["Replicas"] = json!(1);
    }
    // The old place for networks (before API 1.25) moves to the template.
    if spec["TaskTemplate"]["Networks"].is_null() && spec["Networks"].is_array() {
        spec["TaskTemplate"]["Networks"] = spec["Networks"].take();
        spec.as_object_mut().map(|o| o.remove("Networks"));
    }
    if spec["Labels"].is_null() {
        spec["Labels"] = json!({});
    }
    // What Docker's service inspect always has: clients read and bump
    // ForceUpdate (Dokploy sends `ForceUpdate + 1` on every redeploy).
    let tt = &mut spec["TaskTemplate"];
    if !tt["ForceUpdate"].is_u64() {
        tt["ForceUpdate"] = json!(0);
    }
    if tt["Runtime"].is_null() {
        tt["Runtime"] = json!("container");
    }
    if tt["Resources"].is_null() {
        tt["Resources"] = json!({"Limits": {}, "Reservations": {}});
    }
    for p in spec["EndpointSpec"]["Ports"].as_array().into_iter().flatten() {
        if p["TargetPort"].as_u64().is_none_or(|t| t == 0 || t > 65535) {
            return Err(bad("EndpointSpec: a published port needs a target port"));
        }
    }
    if spec["EndpointSpec"]["Mode"].as_str().is_some_and(|m| m != "vip" && m != "dnsrr") {
        return Err(bad("EndpointSpec: invalid endpoint mode"));
    }
    Ok(spec)
}

/// The networks a template names, as names; each must exist and be an
/// overlay network (or attachable, as Docker requires of a service's).
fn spec_networks(engine: &Engine, spec: &Value) -> Result<Vec<(String, Vec<String>)>, Fail> {
    let mut out = Vec::new();
    for n in spec["TaskTemplate"]["Networks"].as_array().into_iter().flatten() {
        let target = n["Target"].as_str().unwrap_or_default();
        let Some(found) = engine.lock_net().find(target).map(|n| n.name.clone()) else {
            return Err(not_found(format!("network {target} not found")));
        };
        if !engine.swarm.is_overlay(&found) {
            return Err(Fail::Forbidden(format!("network {found} is not eligible for services; only overlay networks can be used by swarm services")));
        }
        let aliases = n["Aliases"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(str::to_owned)).collect();
        out.push((found, aliases));
    }
    Ok(out)
}

/// `Endpoint.Ports`: ingress ports without a published port get one.
fn assign_ports(st: &State, spec: &Value, old: &[Value], me: &str) -> Result<Vec<Value>, Fail> {
    let used: BTreeSet<u64> = st.services.values().filter(|s| s.id != me).flat_map(|s| s.ports.iter().filter_map(|p| p["PublishedPort"].as_u64())).collect();
    let mut taken = used.clone();
    let mut out = Vec::new();
    for p in spec["EndpointSpec"]["Ports"].as_array().into_iter().flatten() {
        let mut p = p.clone();
        let proto = p["Protocol"].as_str().unwrap_or("tcp").to_owned();
        p["Protocol"] = json!(proto);
        let mode = p["PublishMode"].as_str().unwrap_or("ingress").to_owned();
        p["PublishMode"] = json!(mode);
        let published = p["PublishedPort"].as_u64().unwrap_or(0);
        if mode == "ingress" {
            if published == 0 {
                let target = p["TargetPort"].as_u64();
                let keep = old.iter().find(|o| o["TargetPort"].as_u64() == target && o["Protocol"] == proto).and_then(|o| o["PublishedPort"].as_u64());
                let port = keep.or_else(|| AUTO_PORTS.map(u64::from).find(|n| !taken.contains(n))).ok_or_else(|| bad("no free ports in the 30000-32767 range"))?;
                p["PublishedPort"] = json!(port);
                taken.insert(port);
            } else if used.contains(&published) {
                return Err(bad(format!("port '{published}' is already in use by another service")));
            } else {
                taken.insert(published);
            }
        }
        out.push(p);
    }
    Ok(out)
}

fn service_create(req: &Request, engine: &Engine) -> Result<Value, Fail> {
    let spec = checked_spec(body_of(req)?)?;
    spec_networks(engine, &spec)?;
    let sw = &engine.swarm;
    let mut st = sw.lock();
    st.cluster()?;
    let name = spec["Name"].as_str().unwrap_or_default().to_owned();
    if st.services.values().any(|s| s.spec["Name"] == name) {
        return Err(Fail::Api(Error::Conflict(format!("rpc error: code = AlreadyExists desc = name conflicts with an existing object: service {name} already exists"))));
    }
    check_refs(&st, &spec)?;
    let id = new_id();
    let ports = assign_ports(&st, &spec, &[], &id)?;
    let now = now_ns();
    let version = st.next();
    let auth = req.header("x-registry-auth").unwrap_or_default().to_owned();
    st.services.insert(id.clone(), Service { id: id.clone(), version, created: now, updated: now, spec, previous: None, update: None, auth, ports });
    sw.save(&st);
    drop(st);
    crate::diag::info!("service created", service = name, id = id);
    let mut attrs = serde_json::Map::new();
    attrs.insert("name".into(), json!(name));
    engine.emit("service", "create", &id, attrs, None);
    sw.wake();
    Ok(json!({"ID": id, "Warnings": []}))
}

/// Secrets and configs a spec names must exist (by ID or name).
fn check_refs(st: &State, spec: &Value) -> Result<(), Fail> {
    let cs = &spec["TaskTemplate"]["ContainerSpec"];
    for (field, map, kind) in [("Secrets", &st.secrets, "secret"), ("Configs", &st.configs, "config")] {
        for r in cs[field].as_array().into_iter().flatten() {
            let key = r[&format!("{}ID", &field[..field.len() - 1])].as_str().filter(|s| !s.is_empty()).or_else(|| r[&format!("{}Name", &field[..field.len() - 1])].as_str()).unwrap_or_default();
            if find_blob(map, key, kind).is_err() {
                return Err(bad(format!("{kind} not found: {key}")));
            }
        }
    }
    Ok(())
}

fn service_update(req: &Request, engine: &Engine, key: &str) -> Result<Value, Fail> {
    let version = version_param(req)?;
    let rollback = req.query("rollback") == Some("previous");
    let sw = &engine.swarm;
    let given = if rollback { None } else { Some(checked_spec(body_of(req)?)?) };
    if let Some(spec) = &given {
        spec_networks(engine, spec)?;
    }
    let mut st = sw.lock();
    st.cluster()?;
    let id = st.find_service(key)?;
    let current = st.services[&id].clone();
    if current.version != version {
        return Err(out_of_sequence("service"));
    }
    let spec = match given {
        Some(s) => {
            if s["Name"] != current.spec["Name"] {
                return Err(bad("renaming services is not supported"));
            }
            s
        }
        None => current.previous.clone().ok_or_else(|| bad("service does not have a previous spec"))?,
    };
    check_refs(&st, &spec)?;
    let ports = assign_ports(&st, &spec, &current.ports, &id)?;
    let next = st.next();
    let now = now_ns();
    let template_changed = spec["TaskTemplate"] != current.spec["TaskTemplate"];
    let s = st.services.get_mut(&id).expect("found");
    s.previous = Some(std::mem::replace(&mut s.spec, spec));
    s.ports = ports;
    s.version = next;
    s.updated = now;
    if let Some(a) = req.header("x-registry-auth").filter(|a| !a.is_empty()) {
        s.auth = a.to_owned();
    } else if req.query("registryAuthFrom") == Some("previous-spec") {
        // Kept as it was.
    }
    if template_changed {
        let (state, message) = if rollback { ("rollback_started", "manually requested rollback") } else { ("updating", "update in progress") };
        s.update = Some(json!({"State": state, "StartedAt": stamp(now), "Message": message}));
    }
    let name = s.spec["Name"].as_str().unwrap_or_default().to_owned();
    sw.save(&st);
    drop(st);
    let mut attrs = serde_json::Map::new();
    attrs.insert("name".into(), json!(name));
    engine.emit("service", "update", &id, attrs, None);
    sw.wake();
    Ok(json!({"Warnings": []}))
}

fn service_remove(engine: &Engine, key: &str) -> Result<(), Fail> {
    let sw = &engine.swarm;
    let (id, name, containers) = {
        let mut st = sw.lock();
        st.cluster()?;
        let id = st.find_service(key)?;
        let name = st.service_name(&id);
        let svc = st.services.remove(&id).expect("found");
        let containers: Vec<(String, u64)> = st
            .tasks
            .values()
            .filter(|t| t.service == id && !t.container.is_empty())
            .map(|t| (t.container.clone(), grace(&t.spec)))
            .collect();
        st.tasks.retain(|_, t| t.service != id);
        drop(svc);
        sweep_files(engine.store.root(), &st);
        sw.save(&st);
        (id, name, containers)
    };
    unpublish(sw, &id);
    let labelled = engine.each(|c| (c.spec.labels.get("com.docker.swarm.service.id").and_then(|v| v.as_str()) == Some(id.as_str())).then(|| c.id.clone()));
    let containers: Vec<(String, u64)> = containers.into_iter().chain(labelled.into_iter().map(|c| (c, 0))).collect();
    // Docker removes the tasks' containers after it answers; doing it first
    // lets `docker stack rm` remove the stack's networks right after.
    for (c, grace) in containers {
        let _ = engine.stop(&c, Duration::from_secs(grace));
        let _ = engine.remove(&c, true, false);
    }
    crate::diag::info!("service removed", service = name, id = id);
    let mut attrs = serde_json::Map::new();
    attrs.insert("name".into(), json!(name));
    engine.emit("service", "remove", &id, attrs, None);
    Ok(())
}

/// A task's stop grace period in whole seconds (10 by default).
fn grace(template: &Value) -> u64 {
    nanos(&template["ContainerSpec"]["StopGracePeriod"], Duration::from_secs(10)).as_secs()
}

fn replicas(spec: &Value) -> u64 {
    if spec["Mode"]["Global"].is_object() { 1 } else { spec["Mode"]["Replicated"]["Replicas"].as_u64().unwrap_or(1) }
}

fn service_json(st: &State, s: &Service, status: bool, defaults: bool) -> Value {
    let mut spec = s.spec.clone();
    if defaults {
        insert_defaults(&mut spec);
    }
    let mut v = json!({
        "ID": s.id,
        "Version": {"Index": s.version},
        "CreatedAt": stamp(s.created),
        "UpdatedAt": stamp(s.updated),
        "Spec": spec,
        "Endpoint": endpoint(st, s),
    });
    if let Some(p) = &s.previous {
        v["PreviousSpec"] = p.clone();
    }
    if let Some(u) = &s.update {
        v["UpdateStatus"] = u.clone();
    }
    if status {
        let tasks = st.tasks.values().filter(|t| t.service == s.id);
        let running = tasks.clone().filter(|t| t.desired == "running" && t.state == "running").count();
        let completed = tasks.filter(|t| t.state == "complete").count();
        v["ServiceStatus"] = json!({"RunningTasks": running, "DesiredTasks": replicas(&s.spec), "CompletedTasks": completed});
    }
    v
}

fn endpoint(st: &State, s: &Service) -> Value {
    let mut v = json!({"Spec": if s.spec["EndpointSpec"].is_object() { s.spec["EndpointSpec"].clone() } else { json!({"Mode": "vip"}) }});
    let ingress: Vec<Value> = s.ports.iter().filter(|p| p["PublishMode"] == "ingress").cloned().collect();
    if !ingress.is_empty() {
        v["Ports"] = Value::Array(ingress);
    }
    // No virtual IPs here: a service's name resolves to its tasks. Traefik
    // and others read an address from here, so the first running task's
    // address stands for each network.
    let vips: Vec<Value> = st
        .tasks
        .values()
        .filter(|t| t.service == s.id && t.live() && t.state == "running")
        .take(1)
        .flat_map(|t| t.spec["Networks"].as_array().cloned().unwrap_or_default().into_iter().map(move |n| (t, n)))
        .filter_map(|(t, n)| Some(json!({"NetworkID": n["Target"].as_str()?, "Addr": t.message.split_whitespace().next().unwrap_or_default()})))
        .collect();
    if s.spec["EndpointSpec"]["Mode"] != "dnsrr" && !vips.is_empty() {
        v["VirtualIPs"] = Value::Array(vips);
    }
    v
}

/// What `insertDefaults=true` adds, as `docker service inspect --pretty`
/// and `docker service update` read them.
fn insert_defaults(spec: &mut Value) {
    let update = json!({"Parallelism": 1, "FailureAction": "pause", "Monitor": 5_000_000_000u64, "MaxFailureRatio": 0, "Order": "stop-first"});
    for key in ["UpdateConfig", "RollbackConfig"] {
        if !spec[key].is_object() {
            spec[key] = update.clone();
        } else {
            for (k, v) in update.as_object().expect("object") {
                if spec[key][k].is_null() {
                    spec[key][k] = v.clone();
                }
            }
        }
    }
    let rp = &mut spec["TaskTemplate"]["RestartPolicy"];
    if !rp.is_object() {
        *rp = json!({});
    }
    if rp["Condition"].is_null() {
        rp["Condition"] = json!("any");
    }
    if rp["Delay"].is_null() {
        rp["Delay"] = json!(5_000_000_000u64);
    }
    if rp["MaxAttempts"].is_null() {
        rp["MaxAttempts"] = json!(0);
    }
    if spec["EndpointSpec"].is_null() {
        spec["EndpointSpec"] = json!({"Mode": "vip"});
    }
    if spec["TaskTemplate"]["ContainerSpec"]["StopGracePeriod"].is_null() {
        spec["TaskTemplate"]["ContainerSpec"]["StopGracePeriod"] = json!(10_000_000_000u64);
    }
}

fn services(req: &Request, engine: &Engine) -> Result<Value, Fail> {
    let f = filters(req, &["id", "label", "mode", "name"])?;
    let st = engine.swarm.lock();
    st.cluster()?;
    let status = req.flag("status");
    let list = st
        .services
        .values()
        .filter(|s| {
            let name = s.spec["Name"].as_str().unwrap_or_default();
            let mode = if s.spec["Mode"]["Global"].is_object() { "global" } else { "replicated" };
            f.any("id", |v| s.id.starts_with(v))
                && f.any("name", |v| name.starts_with(v))
                && f.any("mode", |v| v == mode)
                && f.labels(&s.spec["Labels"])
        })
        .map(|s| service_json(&st, s, status, false))
        .collect();
    Ok(Value::Array(list))
}

fn service_inspect(engine: &Engine, key: &str) -> Result<Value, Fail> {
    let st = engine.swarm.lock();
    st.cluster()?;
    let id = st.find_service(key)?;
    Ok(service_json(&st, &st.services[&id], false, false))
}

// --- Tasks ------------------------------------------------------------------

fn task_json(st: &State, c: &Cluster, t: &Task) -> Value {
    let svc_name = st.service_name(&t.service);
    let global = st.services.get(&t.service).is_some_and(|s| s.spec["Mode"]["Global"].is_object());
    let mut status = json!({
        "Timestamp": stamp(t.timestamp),
        "State": t.state,
        "Message": t.message.split_once(' ').map_or(t.message.as_str(), |(_, m)| m),
    });
    if !t.err.is_empty() {
        status["Err"] = json!(t.err);
    }
    if !t.container.is_empty() {
        status["ContainerStatus"] = json!({"ContainerID": t.container, "PID": 0, "ExitCode": t.exit.unwrap_or(0)});
    }
    let host_ports: Vec<Value> = st.services.get(&t.service).map(|s| s.ports.iter().filter(|p| p["PublishMode"] == "host").cloned().collect()).unwrap_or_default();
    if !host_ports.is_empty() && t.state == "running" {
        status["PortStatus"] = json!({"Ports": host_ports});
    }
    let addr = t.message.split_whitespace().next().filter(|a| a.contains('/')).unwrap_or_default();
    let attachments: Vec<Value> = t.spec["Networks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|n| {
            let name = n["Target"].as_str()?;
            Some(json!({"Network": {"ID": name, "Spec": {"Name": name, "Driver": "overlay"}}, "Addresses": if addr.is_empty() { json!([]) } else { json!([addr]) }}))
        })
        .collect();
    let mut labels = json!({});
    if let Some(s) = st.services.get(&t.service) {
        labels = s.spec["TaskTemplate"]["ContainerSpec"]["Labels"].clone();
    }
    let mut v = json!({
        "ID": t.id,
        "Version": {"Index": t.version},
        "CreatedAt": stamp(t.created),
        "UpdatedAt": stamp(t.updated),
        "Name": if global { format!("{svc_name}.{}", c.node_id) } else { format!("{svc_name}.{}", t.slot) },
        "Labels": if labels.is_object() { labels } else { json!({}) },
        "Spec": t.spec,
        "ServiceID": t.service,
        "NodeID": c.node_id,
        "Status": status,
        "DesiredState": t.desired,
        "NetworksAttachments": attachments,
    });
    if !global {
        v["Slot"] = json!(t.slot);
    }
    v
}

fn tasks(req: &Request, engine: &Engine) -> Result<Value, Fail> {
    let f = filters(req, &["desired-state", "id", "label", "name", "node", "service", "_up-to-date"])?;
    let st = engine.swarm.lock();
    let c = st.cluster()?;
    let services: Vec<String> = f
        .values("service")
        .map(|vs| vs.iter().filter_map(|v| st.find_service(v).ok()).collect())
        .unwrap_or_default();
    let list = st
        .tasks
        .values()
        .filter(|t| {
            let svc = st.services.get(&t.service);
            let name = format!("{}.{}", st.service_name(&t.service), t.slot);
            f.values("service").is_none_or(|_| services.contains(&t.service))
                && f.any("desired-state", |v| v == t.desired || (v == "accepted" && t.desired == "running" && !t.ended()))
                && f.any("id", |v| t.id.starts_with(v))
                && f.any("name", |v| name.starts_with(v))
                && f.any("node", |v| node_is(c, v))
                && f.labels(svc.map_or(&Value::Null, |s| &s.spec["TaskTemplate"]["ContainerSpec"]["Labels"]))
                && f.bool("_up-to-date").is_none_or(|up| !up || svc.is_some_and(|s| s.spec["TaskTemplate"] == t.spec))
        })
        .map(|t| task_json(&st, c, t))
        .collect();
    Ok(Value::Array(list))
}

fn task_inspect(engine: &Engine, key: &str) -> Result<Value, Fail> {
    let st = engine.swarm.lock();
    let c = st.cluster()?;
    let id = st.find_task(key)?;
    Ok(task_json(&st, c, &st.tasks[&id]))
}

// --- Secrets and configs ----------------------------------------------------

fn blob_map(st: &mut State, configs: bool) -> &mut BTreeMap<String, Blob> {
    if configs { &mut st.configs } else { &mut st.secrets }
}

fn blob_json(b: &Blob, configs: bool) -> Value {
    let mut spec = b.spec.clone();
    if configs {
        spec["Data"] = json!(b.data);
    }
    json!({"ID": b.id, "Version": {"Index": b.version}, "CreatedAt": stamp(b.created), "UpdatedAt": stamp(b.updated), "Spec": spec})
}

fn blobs(req: &Request, sw: &Swarm, configs: bool) -> Result<Value, Fail> {
    let f = filters(req, &["id", "label", "name", "names"])?;
    let mut st = sw.lock();
    st.cluster()?;
    let list = blob_map(&mut st, configs)
        .values()
        .filter(|b| {
            let name = b.spec["Name"].as_str().unwrap_or_default();
            f.any("id", |v| b.id.starts_with(v)) && f.any("name", |v| name.starts_with(v)) && f.any("names", |v| name == v) && f.labels(&b.spec["Labels"])
        })
        .map(|b| blob_json(b, configs))
        .collect();
    Ok(Value::Array(list))
}

fn blob_create(req: &Request, sw: &Swarm, configs: bool) -> Result<Value, Fail> {
    let kind = if configs { "config" } else { "secret" };
    let body = body_of(req)?;
    let name = body["Name"].as_str().unwrap_or_default().to_owned();
    if name.is_empty() || name.len() > 64 || !name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) {
        return Err(bad(format!("invalid name {name:?}: {kind} names may contain only letters, digits, - _ and .")));
    }
    if body["Driver"]["Name"].as_str().is_some_and(|d| !d.is_empty()) {
        return Err(bad(format!("Kiri keeps {kind}s itself: {kind} drivers are not supported")));
    }
    let data = body["Data"].as_str().unwrap_or_default();
    let bytes = b64_decode(data).ok_or_else(|| bad("Data must be base64"))?;
    if bytes.len() > 500 * 1024 {
        return Err(bad(format!("{kind} data must be smaller than 500 KiB")));
    }
    let mut st = sw.lock();
    st.cluster()?;
    if blob_map(&mut st, configs).values().any(|b| b.spec["Name"] == name) {
        return Err(Fail::Api(Error::Conflict(format!("rpc error: code = AlreadyExists desc = {kind} {name} already exists"))));
    }
    let id = new_id();
    let now = now_ns();
    let version = st.next();
    let mut spec = body.clone();
    spec.as_object_mut().map(|o| o.remove("Data"));
    if spec["Labels"].is_null() {
        spec["Labels"] = json!({});
    }
    blob_map(&mut st, configs).insert(id.clone(), Blob { id: id.clone(), version, created: now, updated: now, spec, data: b64_encode(&bytes) });
    sw.save(&st);
    Ok(json!({"ID": id}))
}

fn blob_inspect(sw: &Swarm, key: &str, configs: bool) -> Result<Value, Fail> {
    let mut st = sw.lock();
    st.cluster()?;
    let map = blob_map(&mut st, configs);
    let id = find_blob(map, key, if configs { "config" } else { "secret" })?;
    Ok(blob_json(&map[&id], configs))
}

fn blob_remove(sw: &Swarm, key: &str, configs: bool) -> Result<(), Fail> {
    let kind = if configs { "config" } else { "secret" };
    let mut st = sw.lock();
    st.cluster()?;
    let id = find_blob(blob_map(&mut st, configs), key, kind)?;
    let name = blob_map(&mut st, configs)[&id].spec["Name"].as_str().unwrap_or_default().to_owned();
    let field = if configs { "Configs" } else { "Secrets" };
    let users: Vec<String> = st
        .services
        .values()
        .filter(|s| {
            s.spec["TaskTemplate"]["ContainerSpec"][field].as_array().into_iter().flatten().any(|r| {
                r[if configs { "ConfigID" } else { "SecretID" }] == id.as_str() || r[if configs { "ConfigName" } else { "SecretName" }] == name.as_str()
            })
        })
        .map(|s| s.spec["Name"].as_str().unwrap_or_default().to_owned())
        .collect();
    if !users.is_empty() {
        return Err(bad(format!("rpc error: code = InvalidArgument desc = {kind} '{name}' is in use by the following service: {}", users.join(", "))));
    }
    blob_map(&mut st, configs).remove(&id);
    sw.save(&st);
    Ok(())
}

fn blob_update(req: &Request, sw: &Swarm, key: &str, configs: bool) -> Result<(), Fail> {
    let kind = if configs { "config" } else { "secret" };
    let version = version_param(req)?;
    let body = body_of(req)?;
    let mut st = sw.lock();
    st.cluster()?;
    let id = find_blob(blob_map(&mut st, configs), key, kind)?;
    let next = st.next();
    let b = blob_map(&mut st, configs).get_mut(&id).expect("found");
    if b.version != version {
        return Err(out_of_sequence(kind));
    }
    if body["Data"].as_str().is_some_and(|d| b64_decode(d).map(|v| b64_encode(&v)) != Some(b.data.clone())) {
        return Err(bad("rpc error: code = InvalidArgument desc = only updates to Labels are allowed"));
    }
    b.spec["Labels"] = if body["Labels"].is_object() { body["Labels"].clone() } else { json!({}) };
    b.version = next;
    b.updated = now_ns();
    sw.save(&st);
    Ok(())
}

// --- Overlay networks -------------------------------------------------------

fn overlay_create(req: &Request, engine: &Engine, body: &Value) -> Result<Value, Fail> {
    if !engine.swarm.active() {
        return Err(Fail::Forbidden(NOT_MANAGER.into()));
    }
    let mut local = body.clone();
    local["Driver"] = json!("bridge");
    let name = body["Name"].as_str().unwrap_or_default().to_owned();
    let inner = Request::internal("POST", "/networks/create", &[], local.to_string().into_bytes());
    let made = super::api::network_create(&inner, engine)?;
    let mut st = engine.swarm.lock();
    st.overlays.insert(name);
    engine.swarm.save(&st);
    let _ = req;
    Ok(made)
}

// --- Logs -------------------------------------------------------------------

/// `docker service logs` and the same for one task: the tasks' containers'
/// logs merged by time, each line carrying which task it came from.
fn logs(req: &Request, engine: &Engine, service: Option<&str>, task: Option<&str>, w: &mut UnixStream) -> io::Result<Next> {
    use super::logfile::{Record, parse_tail, parse_time};
    let chosen = {
        let st = engine.swarm.lock();
        let c = match st.cluster() {
            Ok(c) => c.clone(),
            Err(e) => return answer(w, Err(e), 200),
        };
        let picked: Result<Vec<Task>, Fail> = match (service, task) {
            (Some(s), _) => st.find_service(s).map(|id| st.tasks.values().filter(|t| t.service == id && !t.container.is_empty()).cloned().collect()),
            (_, Some(t)) => st.find_task(t).map(|id| vec![st.tasks[&id].clone()]),
            _ => Ok(Vec::new()),
        };
        match picked {
            Ok(p) => (c, p),
            Err(e) => return answer(w, Err(e), 200),
        }
    };
    let (cluster, picked) = chosen;
    let (want_out, want_err, stamps, details) = (req.flag("stdout"), req.flag("stderr"), req.flag("timestamps"), req.flag("details"));
    if !want_out && !want_err {
        return answer(w, Err(bad("Bad parameters: you must choose at least one stream")), 200);
    }
    let tail = parse_tail(req.query("tail"));
    let since = req.query("since").and_then(parse_time);
    let follow = req.flag("follow");
    let mut tty = false;
    let mut past: Vec<(Record, String)> = Vec::new();
    let (tx, rx) = std::sync::mpsc::channel::<(Record, String)>();
    for t in &picked {
        let ctx = format!("com.docker.swarm.node.id={},com.docker.swarm.service.id={},com.docker.swarm.task.id={}", cluster.node_id, t.service, t.id);
        let Ok(Some(l)) = engine.logs(&t.container, follow && t.live()) else { continue };
        tty |= l.tty;
        past.extend(l.past.tail(tail).map(|r| (r, ctx.clone())));
        if let Some(live) = l.live {
            let tx = tx.clone();
            let _ = std::thread::Builder::new().name("kiri-service-logs".into()).spawn(move || {
                while let Ok(r) = live.recv() {
                    if tx.send((r, ctx.clone())).is_err() {
                        return;
                    }
                }
            });
        }
    }
    drop(tx);
    past.sort_by_key(|(r, _)| r.time);
    let content_type = if tty { "application/vnd.docker.raw-stream" } else { "application/vnd.docker.multiplexed-stream" };
    http::begin_stream(w, 200, content_type)?;
    let put = |r: &Record, ctx: &str, out: &mut Vec<u8>| -> io::Result<()> {
        let wanted = match r.stream {
            kiri_proto::Stream::Stdout => want_out,
            kiri_proto::Stream::Stderr => want_err,
        };
        if !wanted || since.is_some_and(|s| r.time < s) {
            return Ok(());
        }
        let mut line = Vec::with_capacity(r.data.len() + 160);
        if stamps {
            line.extend_from_slice(time::rfc3339(UNIX_EPOCH + Duration::from_nanos(r.time)).as_bytes());
            line.push(b' ');
        }
        if details {
            line.extend_from_slice(ctx.as_bytes());
            line.push(b' ');
        }
        line.extend_from_slice(&r.data);
        if tty { out.extend_from_slice(&line) } else { http::mux_frame(out, r.stream as u8, &line)? }
        Ok(())
    };
    let mut out = Vec::new();
    for (r, ctx) in &past {
        put(r, ctx, &mut out)?;
        if out.len() >= 32 << 10 {
            http::chunk(w, &out)?;
            out.clear();
        }
    }
    http::chunk(w, &out)?;
    out.clear();
    if follow {
        while let Ok((r, ctx)) = rx.recv() {
            put(&r, &ctx, &mut out)?;
            http::chunk(w, &out)?;
            out.clear();
        }
    }
    http::end(w)?;
    Ok(Next::KeepAlive)
}

// --- Keeping tasks as their services say ------------------------------------

/// What a task's container is doing now, as the reconciler sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    /// Running, healthy or without a healthcheck; its address(es).
    Running(String),
    /// Running, its healthcheck not passed yet.
    Starting,
    Unhealthy,
    Exited(i64),
    /// No such container any more.
    Gone,
}

/// One step the reconciler takes.
#[derive(Debug, Clone, PartialEq)]
enum Step {
    /// A task's state, from its container.
    Observe { task: String, state: &'static str, err: String, exit: Option<i64>, addr: String },
    /// A new task in a slot of a service, made from its current template.
    Start { service: String, slot: u64 },
    /// Stop a task (scale down, replaced, failed health).
    Shutdown { task: String },
    /// A slot whose task can't be placed: no node meets the constraints.
    Pending { service: String, slot: u64, err: String },
    UpdateStatus { service: String, status: Value, rollback_to_previous: bool },
}

fn restart_policy(t: &Value) -> (String, Duration, u64) {
    let rp = &t["RestartPolicy"];
    (
        rp["Condition"].as_str().unwrap_or("any").to_owned(),
        nanos(&rp["Delay"], Duration::from_secs(5)),
        rp["MaxAttempts"].as_u64().unwrap_or(0),
    )
}

/// Whether the one node meets a service's placement constraints.
fn placeable(c: &Cluster, template: &Value) -> Result<(), String> {
    for raw in template["Placement"]["Constraints"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        let (key, want, equal) = if let Some((k, v)) = raw.split_once("!=") {
            (k.trim(), v.trim(), false)
        } else if let Some((k, v)) = raw.split_once("==") {
            (k.trim(), v.trim(), true)
        } else {
            return Err(format!("invalid constraint {raw:?}"));
        };
        let have: Option<String> = match key {
            "node.role" => Some("manager".into()),
            "node.id" => Some(c.node_id.clone()),
            "node.hostname" => Some(hostname()),
            "node.platform.os" => Some("linux".into()),
            "node.platform.arch" => Some(arch().into()),
            k if k.starts_with("node.labels.") => c.node_spec["Labels"][&k["node.labels.".len()..]].as_str().map(str::to_owned),
            k if k.starts_with("engine.labels.") => None,
            _ => return Err(format!("invalid constraint {raw:?}")),
        };
        let matched = have.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(want));
        if matched != equal {
            return Err("no suitable node (scheduling constraints not satisfied on 1 node)".into());
        }
    }
    if c.node_spec["Availability"] != "active" {
        return Err(format!("no suitable node (1 node not available for new tasks; {} )", c.node_spec["Availability"].as_str().unwrap_or("drain")));
    }
    Ok(())
}

/// The reconciler's decisions for one service, given its tasks and what
/// their containers do. Pure, so it is tested without a VM.
/// A task's state as just observed, else as recorded.
fn state_of<'a>(state: &HashMap<&str, (&'static str, Option<i64>)>, t: &'a Task) -> &'a str {
    state.get(t.id.as_str()).map_or(t.state.as_str(), |(s, _)| s)
}

fn plan<'a>(c: &Cluster, svc: &Service, tasks: &[&'a Task], seen: &HashMap<String, Seen>, now: u64) -> Vec<Step> {
    let mut steps = Vec::new();
    let template = &svc.spec["TaskTemplate"];
    // 1. Tasks' states from their containers.
    let mut state: HashMap<&str, (&'static str, Option<i64>)> = HashMap::new();
    for t in tasks.iter().filter(|t| !t.ended() && !t.container.is_empty()) {
        let (st, err, exit, addr) = match seen.get(&t.container).unwrap_or(&Seen::Gone) {
            Seen::Running(a) => ("running", String::new(), None, a.clone()),
            Seen::Starting => ("starting", String::new(), None, String::new()),
            Seen::Unhealthy => ("failed", "task: non-zero exit (137): dockerexec: unhealthy container".into(), Some(137), String::new()),
            Seen::Exited(0) if t.desired != "running" => ("shutdown", String::new(), Some(0), String::new()),
            Seen::Exited(0) => ("complete", String::new(), Some(0), String::new()),
            Seen::Exited(code) if t.desired != "running" => ("shutdown", String::new(), Some(*code), String::new()),
            Seen::Exited(code) => ("failed", format!("task: non-zero exit ({code})"), Some(*code), String::new()),
            Seen::Gone if t.desired != "running" => ("shutdown", String::new(), None, String::new()),
            Seen::Gone => ("failed", "No such container".to_owned(), None, String::new()),
        };
        state.insert(t.id.as_str(), (st, exit));
        let unchanged = t.state == st && (st != "running" || t.message.split_whitespace().next().unwrap_or_default() == addr);
        if !unchanged {
            steps.push(Step::Observe { task: t.id.clone(), state: st, err, exit, addr });
        }
        if matches!(seen.get(&t.container), Some(Seen::Unhealthy)) {
            steps.push(Step::Shutdown { task: t.id.clone() });
        }
    }
    let now_state = |t: &'a Task| state_of(&state, t);
    let ended = |t: &'a Task| matches!(now_state(t), "complete" | "shutdown" | "failed" | "rejected" | "remove" | "orphaned");
    let want = replicas(&svc.spec);
    // 2. Slots: which task is live in each, and which are past.
    let mut by_slot: BTreeMap<u64, Vec<&Task>> = BTreeMap::new();
    for t in tasks {
        by_slot.entry(t.slot).or_default().push(t);
    }
    // Scale down: every live task above the replica count goes.
    for (slot, ts) in &by_slot {
        if *slot > want {
            for t in ts.iter().filter(|t| t.desired == "running" && !ended(t)) {
                steps.push(Step::Shutdown { task: t.id.clone() });
            }
        }
    }
    let placed = placeable(c, template);
    let (condition, delay, max_attempts) = restart_policy(template);
    let up_to_date = |t: &Task| t.spec == *template;
    // 3. Rolling update: how many out-of-date tasks may be replaced now.
    let rolling = svc.update.as_ref().is_some_and(|u| matches!(u["State"].as_str(), Some("updating" | "rollback_started")));
    let rollback = svc.update.as_ref().is_some_and(|u| u["State"] == "rollback_started");
    let cfg = if rollback { &svc.spec["RollbackConfig"] } else { &svc.spec["UpdateConfig"] };
    let parallelism = cfg["Parallelism"].as_u64().unwrap_or(1);
    let order_start_first = cfg["Order"] == "start-first";
    let monitor = nanos(&cfg["Monitor"], Duration::from_secs(5)).as_nanos() as u64;
    let failure_action = cfg["FailureAction"].as_str().unwrap_or("pause");
    let update_delay = nanos(&cfg["Delay"], Duration::ZERO).as_nanos() as u64;
    let started = svc.update.as_ref().and_then(|u| u["StartedAt"].as_str()).map(|s| time::parse_unix(s) as u64 * 1_000_000_000).unwrap_or(0);
    // New tasks of this update that are not yet stable, and ones that failed.
    let fresh: Vec<&&Task> = tasks.iter().filter(|t| up_to_date(t) && t.created >= started).collect();
    // Old tasks still stopping for the update count as part of its batch.
    let stopping_old = tasks.iter().filter(|t| !up_to_date(t) && t.desired != "running" && !ended(t) && !t.container.is_empty()).count() as u64;
    let in_flight = fresh.iter().filter(|t| t.desired == "running" && !ended(t) && t.running_since.is_none_or(|r| now < r + monitor)).count() as u64 + stopping_old;
    let failed_new = fresh.iter().find(|t| now_state(t) == "failed" || now_state(t) == "rejected");
    let mut paused = false;
    if rolling && let Some(f) = failed_new && failure_action != "continue" {
        let task_name = format!("{}.{}", svc.spec["Name"].as_str().unwrap_or_default(), f.slot);
        if failure_action == "rollback" && !rollback && svc.previous.is_some() {
            steps.push(Step::UpdateStatus { service: svc.id.clone(), status: json!({"State": "rollback_started", "StartedAt": stamp(now), "Message": format!("update rolled back due to failure or early termination of task {task_name}")}), rollback_to_previous: true });
            return steps;
        }
        let state = if rollback { "rollback_paused" } else { "paused" };
        if svc.update.as_ref().is_some_and(|u| u["State"] != state) {
            steps.push(Step::UpdateStatus { service: svc.id.clone(), status: json!({"State": state, "StartedAt": stamp(started), "Message": format!("update paused due to failure or early termination of task {task_name}")}), rollback_to_previous: false });
        }
        paused = true;
    }
    let last_new = fresh.iter().map(|t| t.running_since.unwrap_or(u64::MAX)).filter(|r| *r != u64::MAX).max().unwrap_or(0);
    let mut budget = if !rolling || paused {
        0
    } else if parallelism == 0 {
        u64::MAX
    } else if in_flight == 0 && now >= last_new.saturating_add(monitor).saturating_add(update_delay) || last_new == 0 {
        parallelism.saturating_sub(in_flight)
    } else {
        0
    };
    // 4. Each slot up to the replica count.
    let mut outdated_left = 0u64;
    // Slots without an up-to-date task running yet (one may start now).
    let mut unconverged = 0u64;
    for slot in 1..=want {
        let ts = by_slot.get(&slot).cloned().unwrap_or_default();
        let live: Vec<&&Task> = ts.iter().filter(|t| t.desired == "running" && !ended(t)).collect();
        let current = live.iter().find(|t| up_to_date(t));
        if !current.is_some_and(|c| now_state(c) == "running") {
            unconverged += 1;
        }
        let old: Vec<&&&Task> = live.iter().filter(|t| !up_to_date(t)).collect();
        // A task of this slot still stopping: nothing new starts in it
        // until it has (stop-first, a host port it holds).
        let stopping = ts.iter().any(|t| t.desired != "running" && !ended(t) && !t.container.is_empty());
        if !old.is_empty() || ts.iter().any(|t| !up_to_date(t) && t.desired != "running" && !ended(t) && !t.container.is_empty()) {
            outdated_left += 1;
        }
        if let Some(cur) = current {
            // start-first: the old one goes once the new one runs.
            if now_state(cur) == "running" {
                for o in &old {
                    steps.push(Step::Shutdown { task: o.id.clone() });
                }
            }
            continue;
        }
        if !old.is_empty() {
            if budget == 0 {
                continue;
            }
            budget = budget.saturating_sub(1);
            if !order_start_first {
                // stop-first: the new task starts once the old one has stopped.
                for o in &old {
                    steps.push(Step::Shutdown { task: o.id.clone() });
                }
                continue;
            }
            if let Err(err) = &placed {
                steps.push(Step::Pending { service: svc.id.clone(), slot, err: err.clone() });
            } else {
                steps.push(Step::Start { service: svc.id.clone(), slot });
            }
            continue;
        }
        if stopping {
            continue;
        }
        // No live task in the slot: the restart policy decides.
        if ts.iter().any(|t| t.state == "pending" && t.container.is_empty() && t.desired == "running") {
            // Waiting for a node: tried again when the constraints change.
            if placed.is_ok() {
                steps.push(Step::Start { service: svc.id.clone(), slot });
            }
            continue;
        }
        let last = ts.iter().filter(|t| t.desired == "running" || ended(t)).max_by_key(|t| t.created);
        let restart = match last {
            None => true,
            // Shut down on purpose (an update's stop-first, a scale down
            // undone): replaced at once. One that failed or completed by
            // itself is the restart policy's.
            Some(t) if now_state(t) == "shutdown" => true,
            Some(t) => {
                let s = now_state(t);
                let attempts = ts.iter().filter(|x| up_to_date(x) && matches!(now_state(x), "failed" | "complete" | "rejected")).count() as u64;
                let allowed = match condition.as_str() {
                    "none" => false,
                    "on-failure" => s != "complete",
                    _ => true,
                };
                allowed && (max_attempts == 0 || attempts < max_attempts) && now >= t.timestamp.saturating_add(delay.as_nanos() as u64)
            }
        };
        if !restart {
            continue;
        }
        match &placed {
            Err(err) => steps.push(Step::Pending { service: svc.id.clone(), slot, err: err.clone() }),
            Ok(()) => steps.push(Step::Start { service: svc.id.clone(), slot }),
        }
    }
    // 5. An update is done once nothing is out of date and the new tasks
    // have been stable for the monitor period.
    if rolling && !paused && outdated_left == 0 && in_flight == 0 && unconverged == 0 {
        let (state, message) = if rollback { ("rollback_completed", "rollback completed") } else { ("completed", "update completed") };
        steps.push(Step::UpdateStatus { service: svc.id.clone(), status: json!({"State": state, "StartedAt": stamp(started), "CompletedAt": stamp(now), "Message": message}), rollback_to_previous: false });
    }
    steps
}

/// Starts the thread that keeps every service's tasks as its spec says.
pub fn start(engine: &Arc<Engine>) {
    let me = Arc::downgrade(engine);
    let _ = std::thread::Builder::new().name("kiri-swarm".into()).spawn(move || loop {
        let Some(engine) = me.upgrade() else { return };
        let (busy, wants) = {
            let st = engine.swarm.lock();
            (!st.services.is_empty(), st.services.values().any(|s| replicas(&s.spec) > 0))
        };
        // Services with tasks to run keep the VM up, as running containers
        // do; Stop in the window stops them with everything else.
        if busy && !engine.is_stopped() {
            if wants && engine.awake().is_none() && let Err(e) = engine.vm() {
                crate::diag::warn!("the VM did not start for the swarm's services", error = e);
            }
            if engine.awake().is_some() {
                reconcile(&engine);
            }
        }
        let sw_wait = if busy { Duration::from_secs(1) } else { Duration::from_secs(30) };
        let weak = Arc::downgrade(&engine);
        drop(engine);
        let Some(engine) = weak.upgrade() else { return };
        engine.swarm.wait(sw_wait);
    });
}

fn observe(engine: &Engine, containers: &[String]) -> HashMap<String, Seen> {
    let health = engine.health_statuses();
    containers
        .iter()
        .map(|id| {
            let seen = engine
                .with(id, |c| match c.status {
                    Status::Running => match health.get(&c.id).map(|h| h.status.as_str()) {
                        Some("starting") => Seen::Starting,
                        Some("unhealthy") => Seen::Unhealthy,
                        _ => Seen::Running(c.ip.map(|ip| format!("{}/24", super::network::ip_str(ip))).unwrap_or_default()),
                    },
                    // Created: being started by `run_task`, or it failed.
                    Status::Created => Seen::Starting,
                    Status::Exited => Seen::Exited(c.exit_code as i64),
                })
                .unwrap_or(Seen::Gone);
            (id.clone(), seen)
        })
        .collect()
}

pub(super) fn reconcile(engine: &Arc<Engine>) {
    let sw = &engine.swarm;
    let starting: BTreeSet<String> = sw.starting.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let (cluster, services, tasks) = {
        let st = sw.lock();
        let Some(c) = st.cluster.clone() else { return };
        (c, st.services.values().cloned().collect::<Vec<_>>(), st.tasks.values().cloned().collect::<Vec<_>>())
    };
    let containers: Vec<String> = tasks.iter().filter(|t| !t.container.is_empty() && !t.ended()).map(|t| t.container.clone()).collect();
    let seen = observe(engine, &containers);
    let now = now_ns();
    let mut steps = Vec::new();
    for svc in &services {
        let mine: Vec<&Task> = tasks.iter().filter(|t| t.service == svc.id).collect();
        // While a task is being made, only its siblings' states are
        // recorded: what to start or stop next waits until it has a
        // container, so an update stays one batch at a time.
        if mine.iter().any(|t| starting.contains(&t.id)) {
            let ready: Vec<&Task> = mine.iter().copied().filter(|t| !starting.contains(&t.id)).collect();
            steps.extend(plan(&cluster, svc, &ready, &seen, now).into_iter().filter(|s| matches!(s, Step::Observe { .. })));
            continue;
        }
        steps.extend(plan(&cluster, svc, &mine, &seen, now));
    }
    if steps.is_empty() {
        publish(engine);
        return;
    }
    let mut shutdowns = Vec::new();
    let mut starts = Vec::new();
    {
        let mut st = sw.lock();
        for step in steps {
            match step {
                Step::Observe { task, state, err, exit, addr } => {
                    let next = st.next();
                    if let Some(t) = st.tasks.get_mut(&task) {
                        if state == "running" && t.running_since.is_none() {
                            t.running_since = Some(now);
                        }
                        t.state = state.to_owned();
                        t.message = format!("{} {}", if addr.is_empty() { "-" } else { &addr }, state);
                        t.err = err;
                        t.exit = exit;
                        t.timestamp = now;
                        t.updated = now;
                        t.version = next;
                        if t.ended() {
                            t.desired = "shutdown".into();
                        }
                    }
                }
                Step::Shutdown { task } => {
                    let next = st.next();
                    if let Some(t) = st.tasks.get_mut(&task) {
                        t.desired = "shutdown".into();
                        t.version = next;
                        t.updated = now;
                        if !t.container.is_empty() {
                            shutdowns.push((t.container.clone(), grace(&t.spec)));
                        }
                        // Ended once its container has stopped (Observe).
                        if t.container.is_empty() {
                            t.state = "shutdown".into();
                            t.message = "- shutdown".into();
                            t.timestamp = now;
                        }
                    }
                }
                Step::Pending { service, slot, err } => {
                    let Some(svc) = st.services.get(&service).cloned() else { continue };
                    if st.tasks.values().any(|t| t.service == service && t.slot == slot && t.state == "pending" && t.err == err && t.desired == "running") {
                        continue;
                    }
                    st.tasks.retain(|_, t| !(t.service == service && t.slot == slot && t.state == "pending" && t.container.is_empty()));
                    let id = new_id();
                    let version = st.next();
                    st.tasks.insert(id.clone(), Task {
                        id, version, created: now, updated: now, service, slot, spec: svc.spec["TaskTemplate"].clone(),
                        desired: "running".into(), state: "pending".into(), message: "- pending task scheduling".into(), err, timestamp: now, ..Task::default()
                    });
                }
                Step::Start { service, slot } => {
                    let Some(svc) = st.services.get(&service).cloned() else { continue };
                    st.tasks.retain(|_, t| !(t.service == service && t.slot == slot && t.state == "pending" && t.container.is_empty()));
                    let id = new_id();
                    let version = st.next();
                    let task = Task {
                        id: id.clone(), version, created: now, updated: now, service: service.clone(), slot,
                        spec: svc.spec["TaskTemplate"].clone(), desired: "running".into(), state: "preparing".into(),
                        message: "- preparing".into(), timestamp: now, ..Task::default()
                    };
                    st.tasks.insert(id.clone(), task.clone());
                    starts.push((task, svc));
                }
                Step::UpdateStatus { service, status, rollback_to_previous } => {
                    let next = st.next();
                    if let Some(s) = st.services.get_mut(&service) {
                        if rollback_to_previous && let Some(prev) = s.previous.take() {
                            s.previous = Some(std::mem::replace(&mut s.spec, prev));
                            s.version = next;
                            s.updated = now;
                        }
                        s.update = Some(status);
                    }
                }
            }
        }
        for c in prune_history(&mut st) {
            shutdowns.push((c, 0));
        }
        sweep_files(engine.store.root(), &st);
        sw.save(&st);
    }
    for (c, grace) in shutdowns {
        let engine = engine.clone();
        let _ = std::thread::Builder::new().name("kiri-task-stop".into()).spawn(move || {
            let _ = engine.stop(&c, Duration::from_secs(grace));
            let _ = engine.remove(&c, true, false);
            engine.swarm.wake();
        });
    }
    for (task, svc) in starts {
        sw.starting.lock().unwrap_or_else(|e| e.into_inner()).insert(task.id.clone());
        let engine = engine.clone();
        let cluster = cluster.clone();
        let _ = std::thread::Builder::new().name("kiri-task-start".into()).spawn(move || {
            let result = run_task(&engine, &cluster, &svc, &task);
            let now = now_ns();
            {
                let mut st = engine.swarm.lock();
                let next = st.next();
                if let Some(t) = st.tasks.get_mut(&task.id) {
                    t.version = next;
                    t.updated = now;
                    t.timestamp = now;
                    match result {
                        Ok(container) => {
                            t.container = container;
                            t.state = "starting".into();
                            t.message = "- starting".into();
                        }
                        Err((container, err)) => {
                            t.container = container;
                            t.state = "rejected".into();
                            t.desired = "shutdown".into();
                            t.message = "- rejected".into();
                            t.err = err;
                        }
                    }
                }
                engine.swarm.save(&st);
            }
            engine.swarm.starting.lock().unwrap_or_else(|e| e.into_inner()).remove(&task.id);
            engine.swarm.wake();
        });
    }
    publish(engine);
}

/// Secret and config files of tasks no longer kept.
fn sweep_files(root: &Path, st: &State) {
    let Ok(dir) = std::fs::read_dir(root.join("swarm")) else { return };
    for e in dir.flatten() {
        if !st.tasks.contains_key(e.file_name().to_string_lossy().as_ref()) {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// Ended tasks beyond the history limit go, oldest first, per slot; their
/// containers, returned, go with them.
fn prune_history(st: &mut State) -> Vec<String> {
    let mut gone = Vec::new();
    let limit = st.cluster.as_ref().and_then(|c| c.spec["Orchestration"]["TaskHistoryRetentionLimit"].as_u64()).unwrap_or(HISTORY as u64) as usize;
    let mut by_slot: BTreeMap<(String, u64), Vec<(u64, String)>> = BTreeMap::new();
    for t in st.tasks.values().filter(|t| t.ended() && t.desired != "running") {
        by_slot.entry((t.service.clone(), t.slot)).or_default().push((t.created, t.id.clone()));
    }
    for (_, mut ids) in by_slot {
        ids.sort();
        let extra = ids.len().saturating_sub(limit);
        for (_, id) in ids.into_iter().take(extra) {
            if let Some(t) = st.tasks.remove(&id).filter(|t| !t.container.is_empty()) {
                gone.push(t.container);
            }
        }
    }
    gone
}

/// The container name Docker gives a task.
fn container_name(svc: &Service, cluster: &Cluster, task: &Task) -> String {
    let name = svc.spec["Name"].as_str().unwrap_or_default();
    if svc.spec["Mode"]["Global"].is_object() { format!("{name}.{}.{}", cluster.node_id, task.id) } else { format!("{name}.{}.{}", task.slot, task.id) }
}

/// Makes and starts a task's container: the image pulled if missing, the
/// spec turned into a container create. Ok(container) or Err((container
/// if one was made, why)).
fn run_task(engine: &Arc<Engine>, cluster: &Cluster, svc: &Service, task: &Task) -> Result<String, (String, String)> {
    let cs = &task.spec["ContainerSpec"];
    let image = image_ref(engine, cs["Image"].as_str().unwrap_or_default(), &svc.auth).map_err(|e| (String::new(), e))?;
    let body = create_body(engine, cluster, svc, task, &image).map_err(|e| (String::new(), e))?;
    let name = container_name(svc, cluster, task);
    let req = Request::internal("POST", "/containers/create", &[("name", name.as_str())], body.to_string().into_bytes());
    let made = super::api::create(&req, engine).map_err(|e| (String::new(), error_text(e)))?;
    let id = made["Id"].as_str().unwrap_or_default().to_owned();
    if let Err(e) = engine.start(&id) {
        return Err((id, format!("starting container failed: {}", error_text(e))));
    }
    Ok(id)
}

fn error_text(e: Error) -> String {
    match e {
        Error::NotFound(m) | Error::Conflict(m) | Error::BadRequest(m) | Error::Unauthorized(m) | Error::Forbidden(m) => m,
        Error::Io(e) => e.to_string(),
    }
}

/// The image a task runs, pulled with the service's credentials if it is
/// not here. The CLI pins `name:tag@sha256:…`; the local name is kept when
/// the digest is what is stored.
fn image_ref(engine: &Engine, wanted: &str, auth: &str) -> Result<String, String> {
    let (named, digest) = match wanted.split_once('@') {
        Some((n, d)) => (n, Some(d)),
        None => (wanted, None),
    };
    let have = |name: &str| engine.image(name).ok().flatten();
    if let Some(img) = have(named)
        && digest.is_none_or(|d| img.digest == d || img.index_digest.as_deref() == Some(d) || img.config_digest == d)
    {
        return Ok(named.to_owned());
    }
    if digest.is_some() && have(wanted).is_some() {
        return Ok(wanted.to_owned());
    }
    let reference = kiri_image::Reference::parse(wanted).map_err(|e| format!("invalid reference format: {e}"))?;
    let creds = (!auth.is_empty()).then(|| kiri_image::Credentials::from_header(auth)).flatten();
    let client = kiri_image::Client::new().with_credentials(creds);
    let cancel = kiri_image::Cancel::default();
    let platform = kiri_image::Platform::host_linux();
    crate::diag::info!("pulling a service's image", image = wanted);
    let pulled = client.pull_with(&engine.store, &reference, &platform, &|_| {}, &cancel).or_else(|e| match e {
        kiri_image::registry::Error::NoPlatform { available, .. } if available.iter().any(|a| a == "linux/amd64") => {
            client.pull_with(&engine.store, &reference, &kiri_image::Platform { os: "linux".into(), architecture: "amd64".into() }, &|_| {}, &cancel)
        }
        e => Err(e),
    });
    match pulled {
        Ok(img) => {
            engine.emit_image("pull", &img.config_digest, &img.name);
            // Tagged as the CLI asked for it, so the next task finds it.
            Ok(if have(named).is_some() { named.to_owned() } else { img.name })
        }
        Err(e) => Err(format!("No such image: {wanted}: {e}")),
    }
}

/// Docker's `--mount` entries for a template's secrets and configs: each a
/// file written for the task, bound read-only.
fn secret_mounts(engine: &Engine, task: &Task) -> Result<Vec<Value>, String> {
    let cs = &task.spec["ContainerSpec"];
    let st = engine.swarm.lock();
    let dir = engine.store.root().join("swarm").join(&task.id);
    let mut mounts = Vec::new();
    for (field, map, kind, base) in [("Secrets", &st.secrets, "secret", "/run/secrets/"), ("Configs", &st.configs, "config", "/")] {
        let one = &field[..field.len() - 1];
        for r in cs[field].as_array().into_iter().flatten() {
            let key = r[&format!("{one}ID")].as_str().filter(|s| !s.is_empty()).or_else(|| r[&format!("{one}Name")].as_str()).unwrap_or_default();
            let id = find_blob(map, key, kind).map_err(|_| format!("{kind} not found: {key}"))?;
            let blob = &map[&id];
            let name = blob.spec["Name"].as_str().unwrap_or_default();
            let target = r["File"]["Name"].as_str().filter(|n| !n.is_empty()).unwrap_or(name);
            let target = if target.starts_with('/') { target.to_owned() } else { format!("{base}{target}") };
            let mode = r["File"]["Mode"].as_u64().unwrap_or(0o444) as u32;
            std::fs::create_dir_all(&dir).map_err(|e| format!("{kind} {name}: {e}"))?;
            let file = dir.join(format!("{kind}-{}", mounts.len()));
            let _ = std::fs::remove_file(&file);
            let data = b64_decode(&blob.data).unwrap_or_default();
            write_private(&file, &data, mode | 0o400).map_err(|e| format!("{kind} {name}: {e}"))?;
            mounts.push(json!({"Type": "bind", "Source": file.to_string_lossy(), "Target": target, "ReadOnly": true}));
        }
    }
    Ok(mounts)
}

fn write_private(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(path)?;
    f.write_all(data)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// A task's `POST /containers/create` body, from its service's template.
fn create_body(engine: &Engine, cluster: &Cluster, svc: &Service, task: &Task, image: &str) -> Result<Value, String> {
    let t = &task.spec;
    let cs = &t["ContainerSpec"];
    let svc_name = svc.spec["Name"].as_str().unwrap_or_default();
    let mut labels = serde_json::Map::new();
    if let Value::Object(l) = &cs["Labels"] {
        labels.extend(l.clone());
    }
    let full_name = container_name(svc, cluster, task);
    for (k, v) in [
        ("com.docker.swarm.task", String::new()),
        ("com.docker.swarm.task.id", task.id.clone()),
        ("com.docker.swarm.task.name", full_name),
        ("com.docker.swarm.node.id", cluster.node_id.clone()),
        ("com.docker.swarm.service.id", svc.id.clone()),
        ("com.docker.swarm.service.name", svc_name.to_owned()),
    ] {
        labels.insert(k.into(), json!(v));
    }
    let mut mounts: Vec<Value> = cs["Mounts"].as_array().cloned().unwrap_or_default();
    mounts.extend(secret_mounts(engine, task)?);
    let mut port_bindings = serde_json::Map::new();
    let mut exposed = serde_json::Map::new();
    for p in svc.ports.iter().filter(|p| p["PublishMode"] == "host") {
        let key = format!("{}/{}", p["TargetPort"].as_u64().unwrap_or(0), p["Protocol"].as_str().unwrap_or("tcp"));
        let host = p["PublishedPort"].as_u64().map(|n| n.to_string()).unwrap_or_default();
        if let Some(a) = port_bindings.entry(key.clone()).or_insert_with(|| json!([])).as_array_mut() {
            a.push(json!({"HostIp": "", "HostPort": host}));
        }
        exposed.insert(key, json!({}));
    }
    let networks = spec_networks(engine, &svc.spec).map_err(|e| match e {
        Fail::Api(e) => error_text(e),
        Fail::Forbidden(m) | Fail::Unavailable(m) => m,
    })?;
    let mut endpoints = serde_json::Map::new();
    for (net, aliases) in &networks {
        let mut names = vec![svc_name.to_owned(), format!("tasks.{svc_name}")];
        names.extend(aliases.iter().cloned());
        endpoints.insert(net.clone(), json!({"Aliases": names}));
    }
    let network_mode = networks.first().map(|(n, _)| n.clone()).unwrap_or_else(|| "bridge".into());
    let res = &t["Resources"];
    // `ip host` in a template; `host:ip` for a container.
    let hosts: Vec<String> = cs["Hosts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|h| {
            let mut parts = h.split_whitespace();
            let ip = parts.next()?;
            Some(parts.map(|name| format!("{name}:{ip}")).collect::<Vec<_>>())
        })
        .flatten()
        .collect();
    let mut health = cs["HealthCheck"].clone();
    if health.is_null() {
        health = cs["Healthcheck"].clone();
    }
    let host_config = json!({
        "Mounts": mounts,
        "PortBindings": port_bindings,
        "RestartPolicy": {"Name": "no"},
        "NetworkMode": network_mode,
        "ReadonlyRootfs": cs["ReadOnly"].as_bool().unwrap_or(false),
        "Memory": res["Limits"]["MemoryBytes"].as_i64().unwrap_or(0),
        "MemoryReservation": res["Reservations"]["MemoryBytes"].as_i64().unwrap_or(0),
        "NanoCpus": res["Limits"]["NanoCPUs"].as_i64().unwrap_or(0),
        "PidsLimit": res["Limits"]["Pids"].as_i64().filter(|p| *p > 0),
        "CapAdd": cs["CapabilityAdd"],
        "CapDrop": cs["CapabilityDrop"],
        "Sysctls": cs["Sysctls"],
        "Ulimits": cs["Ulimits"],
        "Init": cs["Init"],
        "GroupAdd": cs["Groups"],
        "ExtraHosts": hosts,
        "Dns": cs["DNSConfig"]["Nameservers"],
        "DnsSearch": cs["DNSConfig"]["Search"],
        "DnsOptions": cs["DNSConfig"]["Options"],
        "LogConfig": if t["LogDriver"].is_object() { json!({"Type": t["LogDriver"]["Name"], "Config": t["LogDriver"]["Options"]}) } else { Value::Null },
        "OomScoreAdj": cs["OomScoreAdj"],
    });
    let mut body = json!({
        "Image": image,
        "Labels": labels,
        "Env": cs["Env"],
        "Entrypoint": cs["Command"],
        "Cmd": cs["Args"],
        "WorkingDir": cs["Dir"],
        "User": cs["User"],
        "Hostname": cs["Hostname"],
        "Tty": cs["TTY"].as_bool().unwrap_or(false),
        "OpenStdin": cs["OpenStdin"].as_bool().unwrap_or(false),
        "StopSignal": cs["StopSignal"],
        "StopTimeout": grace(t),
        "Healthcheck": health,
        "ExposedPorts": exposed,
        "HostConfig": host_config,
        "NetworkingConfig": {"EndpointsConfig": endpoints},
    });
    // Nulls are "not given" to create.
    if let Value::Object(o) = &mut body {
        o.retain(|_, v| !v.is_null());
        if let Some(Value::Object(h)) = o.get_mut("HostConfig") {
            h.retain(|_, v| !v.is_null());
        }
    }
    Ok(body)
}

/// Ingress ports: a forward from the host to one running task of each
/// service that publishes them, moved when that task goes.
fn publish(engine: &Arc<Engine>) {
    // (published port, protocol), the task, its address, the target port.
    type Wanted = ((u16, String), String, [u8; 4], String);
    let wanted: Vec<Wanted> = {
        let st = engine.swarm.lock();
        st.services
            .values()
            .flat_map(|s| {
                let running: Vec<&Task> = st.tasks.values().filter(|t| t.service == s.id && t.live() && t.state == "running").collect();
                s.ports
                    .iter()
                    .filter(|p| p["PublishMode"] == "ingress")
                    .filter_map(|p| {
                        let published = u16::try_from(p["PublishedPort"].as_u64()?).ok()?;
                        let target = p["TargetPort"].as_u64()?.to_string();
                        Some(((published, p["Protocol"].as_str().unwrap_or("tcp").to_owned()), target))
                    })
                    .filter_map(|(key, target)| {
                        let t = running.first()?;
                        let ip = engine.with(&t.container, |c| c.ip).ok().flatten()?;
                        Some((key, t.id.clone(), ip, target))
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    let mut ingress = engine.swarm.ingress.lock().unwrap_or_else(|e| e.into_inner());
    ingress.retain(|k, (task, _)| wanted.iter().any(|(wk, wt, _, _)| wk == k && wt == task));
    let Some(vm) = engine.awake() else { return };
    for ((port, proto), task, ip, target) in wanted {
        if ingress.contains_key(&(port, proto.clone())) {
            continue;
        }
        let Ok(container_port) = target.parse::<u16>() else { continue };
        let b = super::ports::Binding { container_port, proto: proto.clone(), host_ip: String::new(), host_port: port };
        match super::ports::start(vm.clone(), &format!("ingress-{port}-{proto}"), &[b], ip) {
            Ok(fw) => {
                engine.swarm.refused.lock().unwrap_or_else(|e| e.into_inner()).remove(&(port, proto.clone()));
                ingress.insert((port, proto), (task, fw));
            }
            Err(e) => {
                if engine.swarm.refused.lock().unwrap_or_else(|e| e.into_inner()).insert((port, proto.clone())) {
                    crate::diag::warn!("service port not published", port = format!("{port}/{proto}"), error = e);
                }
            }
        }
    }
}

fn unpublish(sw: &Swarm, service: &str) {
    let st = sw.lock();
    let tasks: BTreeSet<String> = st.tasks.values().filter(|t| t.service == service).map(|t| t.id.clone()).collect();
    drop(st);
    sw.ingress.lock().unwrap_or_else(|e| e.into_inner()).retain(|_, (t, _)| !tasks.contains(t));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cluster() -> Cluster {
        Cluster { node_id: "node1".into(), node_spec: json!({"Role": "manager", "Availability": "active", "Labels": {"zone": "a"}}), ..Cluster::default() }
    }

    fn service(spec: Value) -> Service {
        Service { id: "svc".into(), spec: checked_spec(spec).ok().expect("valid"), ..Service::default() }
    }

    fn web(replicas: u64) -> Value {
        json!({"Name": "web", "Mode": {"Replicated": {"Replicas": replicas}}, "TaskTemplate": {"ContainerSpec": {"Image": "nginx"}}})
    }

    fn task(svc: &Service, id: &str, slot: u64, state: &str, container: &str) -> Task {
        Task {
            id: id.into(), service: svc.id.clone(), slot, spec: svc.spec["TaskTemplate"].clone(), desired: "running".into(), state: state.into(),
            container: container.into(), running_since: (state == "running").then_some(1), ..Task::default()
        }
    }

    fn starts(steps: &[Step]) -> Vec<u64> {
        steps.iter().filter_map(|s| if let Step::Start { slot, .. } = s { Some(*slot) } else { None }).collect()
    }

    fn shutdowns(steps: &[Step]) -> Vec<String> {
        steps.iter().filter_map(|s| if let Step::Shutdown { task } = s { Some(task.clone()) } else { None }).collect()
    }

    /// A new service gets one task per replica, in slots 1..N.
    #[test]
    fn a_new_service_starts_a_task_per_replica() {
        let s = service(web(3));
        assert_eq!(starts(&plan(&cluster(), &s, &[], &HashMap::new(), 10)), vec![1, 2, 3]);
    }

    /// A task whose container exited is failed, and with the default
    /// restart policy its slot gets a new task once the delay has passed.
    #[test]
    fn a_failed_task_is_replaced_after_the_restart_delay() {
        let s = service(web(1));
        let t = task(&s, "t1", 1, "running", "c1");
        let seen = HashMap::from([("c1".to_owned(), Seen::Exited(1))]);
        let steps = plan(&cluster(), &s, &[&t], &seen, 10);
        assert!(steps.iter().any(|s| matches!(s, Step::Observe { state: "failed", .. })), "{steps:?}");
        assert!(starts(&steps).is_empty(), "not before the 5 s delay: {steps:?}");
        let mut ended = t.clone();
        ended.state = "failed".into();
        ended.desired = "shutdown".into();
        ended.timestamp = 10;
        let later = plan(&cluster(), &s, &[&ended], &HashMap::new(), 10 + 6_000_000_000);
        assert_eq!(starts(&later), vec![1]);
    }

    /// `--restart-condition none` leaves an ended slot empty, and
    /// on-failure leaves a completed one.
    #[test]
    fn restart_conditions_none_and_on_failure_are_kept() {
        for (condition, exit, restarts) in [("none", 1, false), ("on-failure", 0, false), ("on-failure", 2, true), ("any", 0, true)] {
            let mut spec = web(1);
            spec["TaskTemplate"]["RestartPolicy"] = json!({"Condition": condition, "Delay": 0});
            let s = service(spec);
            let mut t = task(&s, "t1", 1, if exit == 0 { "complete" } else { "failed" }, "c1");
            t.desired = "shutdown".into();
            t.exit = Some(exit);
            assert_eq!(!starts(&plan(&cluster(), &s, &[&t], &HashMap::new(), 10)).is_empty(), restarts, "{condition} exit {exit}");
        }
    }

    /// Scaling down shuts down the tasks in the highest slots.
    #[test]
    fn scaling_down_shuts_down_the_highest_slots() {
        let s = service(web(1));
        let a = task(&s, "a", 1, "running", "c1");
        let b = task(&s, "b", 2, "running", "c2");
        let seen = HashMap::from([("c1".to_owned(), Seen::Running("10.0.0.2/24".into())), ("c2".to_owned(), Seen::Running("10.0.0.3/24".into()))]);
        let steps = plan(&cluster(), &s, &[&a, &b], &seen, 10);
        assert_eq!(shutdowns(&steps), vec!["b".to_owned()]);
        assert!(starts(&steps).is_empty());
    }

    /// An update replaces out-of-date tasks one at a time, stop-first: the
    /// old task goes and a new one starts in its slot; the next waits until
    /// the new one has run for the monitor period.
    #[test]
    fn an_update_replaces_tasks_one_at_a_time() {
        let mut s = service(web(2));
        let old = s.spec["TaskTemplate"].clone();
        s.spec["TaskTemplate"]["ContainerSpec"]["Image"] = json!("nginx:2");
        s.update = Some(json!({"State": "updating", "StartedAt": stamp(0)}));
        let mut a = task(&s, "a", 1, "running", "c1");
        let mut b = task(&s, "b", 2, "running", "c2");
        a.spec = old.clone();
        b.spec = old;
        let seen = HashMap::from([("c1".to_owned(), Seen::Running("x/24".into())), ("c2".to_owned(), Seen::Running("y/24".into()))]);
        let steps = plan(&cluster(), &s, &[&a, &b], &seen, 10);
        assert_eq!(shutdowns(&steps), vec!["a".to_owned()]);
        assert!(starts(&steps).is_empty(), "stop-first: nothing starts while the old task stops: {steps:?}");
        // Still stopping: slot 1 waits, and so does slot 2 (one at a time).
        let mut a_stopping = a.clone();
        a_stopping.desired = "shutdown".into();
        let steps = plan(&cluster(), &s, &[&a_stopping, &b], &seen, 11);
        assert!(starts(&steps).is_empty() && shutdowns(&steps).is_empty(), "{steps:?}");
        // Stopped: slot 1's new task starts.
        let gone = HashMap::from([("c1".to_owned(), Seen::Exited(0)), ("c2".to_owned(), Seen::Running("y/24".into()))]);
        assert_eq!(starts(&plan(&cluster(), &s, &[&a_stopping, &b], &gone, 12)), vec![1]);
        // Slot 1's new task runs, but not yet for 5 s: slot 2 waits.
        let mut a2 = task(&s, "a2", 1, "running", "c3");
        a2.created = 5;
        a2.running_since = Some(20);
        let mut a_old = a.clone();
        a_old.desired = "shutdown".into();
        a_old.state = "shutdown".into();
        let seen2 = HashMap::from([("c3".to_owned(), Seen::Running("z/24".into())), ("c2".to_owned(), Seen::Running("y/24".into()))]);
        assert!(starts(&plan(&cluster(), &s, &[&a_old, &a2, &b], &seen2, 30)).is_empty());
        let steps = plan(&cluster(), &s, &[&a_old, &a2, &b], &seen2, 20 + 5_000_000_001);
        assert_eq!(shutdowns(&steps), vec!["b".to_owned()]);
        assert!(starts(&steps).is_empty());
    }

    /// The tick that starts a slot's new task (its old one has just
    /// stopped) does not say the update is done.
    #[test]
    fn an_update_is_not_done_while_a_slot_waits_for_its_new_task() {
        let mut s = service(web(1));
        let old = s.spec["TaskTemplate"].clone();
        s.spec["TaskTemplate"]["ForceUpdate"] = json!(1);
        s.update = Some(json!({"State": "updating", "StartedAt": stamp(0)}));
        let mut a = task(&s, "a", 1, "running", "c1");
        a.spec = old;
        a.desired = "shutdown".into();
        let stopped = HashMap::from([("c1".to_owned(), Seen::Exited(0))]);
        let steps = plan(&cluster(), &s, &[&a], &stopped, 10);
        assert_eq!(starts(&steps), vec![1]);
        assert!(!steps.iter().any(|s| matches!(s, Step::UpdateStatus { .. })), "{steps:?}");
    }

    /// start-first keeps the old task until the new one runs.
    #[test]
    fn start_first_keeps_the_old_task_until_the_new_one_runs() {
        let mut spec = web(1);
        spec["UpdateConfig"] = json!({"Order": "start-first"});
        let mut s = service(spec);
        let old = s.spec["TaskTemplate"].clone();
        s.spec["TaskTemplate"]["ForceUpdate"] = json!(1);
        s.update = Some(json!({"State": "updating", "StartedAt": stamp(0)}));
        let mut a = task(&s, "a", 1, "running", "c1");
        a.spec = old;
        let seen = HashMap::from([("c1".to_owned(), Seen::Running("x/24".into()))]);
        let steps = plan(&cluster(), &s, &[&a], &seen, 10);
        assert_eq!(starts(&steps), vec![1]);
        assert!(shutdowns(&steps).is_empty(), "{steps:?}");
        let mut b = task(&s, "b", 1, "running", "c2");
        b.created = 5;
        let seen = HashMap::from([("c1".to_owned(), Seen::Running("x/24".into())), ("c2".to_owned(), Seen::Running("y/24".into()))]);
        assert_eq!(shutdowns(&plan(&cluster(), &s, &[&a, &b], &seen, 10)), vec!["a".to_owned()]);
    }

    /// A new task that fails during an update with failure action rollback
    /// starts a rollback to the previous spec.
    #[test]
    fn a_failed_update_rolls_back_when_asked() {
        let mut spec = web(1);
        spec["UpdateConfig"] = json!({"FailureAction": "rollback"});
        let mut s = service(spec);
        s.previous = Some(s.spec.clone());
        s.spec["TaskTemplate"]["ContainerSpec"]["Image"] = json!("broken");
        s.update = Some(json!({"State": "updating", "StartedAt": stamp(0)}));
        let mut t = task(&s, "n", 1, "failed", "c1");
        t.desired = "shutdown".into();
        t.created = 1;
        let steps = plan(&cluster(), &s, &[&t], &HashMap::new(), 10);
        assert!(steps.iter().any(|s| matches!(s, Step::UpdateStatus { rollback_to_previous: true, .. })), "{steps:?}");
    }

    /// Constraints are matched against the one node; a miss leaves the
    /// task pending with Docker's message.
    #[test]
    fn constraints_match_the_one_node() {
        let c = cluster();
        assert!(placeable(&c, &json!({"Placement": {"Constraints": ["node.role==manager", "node.labels.zone == a", "node.role != worker"]}})).is_ok());
        let miss = placeable(&c, &json!({"Placement": {"Constraints": ["node.labels.gpu==true"]}}));
        assert_eq!(miss.unwrap_err(), "no suitable node (scheduling constraints not satisfied on 1 node)");
        let s = service(json!({"Name": "gpu", "TaskTemplate": {"ContainerSpec": {"Image": "x"}, "Placement": {"Constraints": ["node.labels.gpu==true"]}}}));
        assert!(plan(&c, &s, &[], &HashMap::new(), 1).iter().any(|s| matches!(s, Step::Pending { .. })));
    }

    /// Ingress ports without a published port get one from 30000, and a
    /// port another service has is refused.
    #[test]
    fn ingress_ports_are_handed_out_and_not_shared() {
        let mut st = State::default();
        let spec = json!({"EndpointSpec": {"Ports": [{"TargetPort": 80}]}});
        let ports = assign_ports(&st, &spec, &[], "a").ok().expect("assigned");
        assert_eq!(ports[0]["PublishedPort"], 30000);
        assert_eq!(ports[0]["PublishMode"], "ingress");
        st.services.insert("a".into(), Service { id: "a".into(), ports, ..Service::default() });
        let again = json!({"EndpointSpec": {"Ports": [{"TargetPort": 81, "PublishedPort": 30000}]}});
        assert!(assign_ports(&st, &again, &[], "b").is_err());
        let host = json!({"EndpointSpec": {"Ports": [{"TargetPort": 3000, "PublishedPort": 3000, "PublishMode": "host"}]}});
        assert_eq!(assign_ports(&st, &host, &[], "b").ok().expect("host")[0]["PublishMode"], "host");
    }

    /// Docker's defaults are filled in, ForceUpdate above all: clients
    /// redeploy with `ForceUpdate + 1`.
    #[test]
    fn a_spec_gets_force_update_and_one_replica_by_default() {
        let s = checked_spec(json!({"Name": "a", "TaskTemplate": {"ContainerSpec": {"Image": "x"}}})).ok().expect("valid");
        assert_eq!(s["TaskTemplate"]["ForceUpdate"], 0);
        assert_eq!(s["Mode"]["Replicated"]["Replicas"], 1);
        assert!(checked_spec(json!({"Name": "-bad", "TaskTemplate": {"ContainerSpec": {"Image": "x"}}})).is_err());
        assert!(checked_spec(json!({"Name": "j", "Mode": {"ReplicatedJob": {}}, "TaskTemplate": {"ContainerSpec": {"Image": "x"}}})).is_err());
    }

    #[test]
    fn ids_are_25_base36_characters_and_base64_goes_both_ways() {
        let id = new_id();
        assert_eq!(id.len(), 25);
        assert!(id.chars().all(|c| c.is_ascii_digit() || c.is_ascii_lowercase()));
        for s in ["", "a", "ab", "abc", "secret\n", "\u{0}\u{ff}x"] {
            assert_eq!(b64_decode(&b64_encode(s.as_bytes())).as_deref(), Some(s.as_bytes()));
        }
        assert_eq!(b64_encode(b"hunter2"), "aHVudGVyMg==");
    }

    /// Every Swarm endpoint answers Docker's "not a swarm manager" 503
    /// before `swarm init`; `/info` says inactive.
    #[test]
    fn before_init_the_swarm_is_inactive() {
        let root = std::env::temp_dir().join(format!("kiri-swarm-inactive-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let engine = super::super::engine::boot_without_vm(&root);
        assert_eq!(engine.swarm.info()["LocalNodeState"], "inactive");
        let req = Request::internal("GET", "/services", &[], Vec::new());
        assert!(matches!(services(&req, &engine), Err(Fail::Unavailable(m)) if m == NOT_MANAGER));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// init, a service and a secret survive a restart of the daemon (the
    /// state is in swarm.json); a second init is refused; a stale version
    /// is refused.
    #[test]
    fn the_swarm_survives_a_restart_and_versions_are_checked() {
        let root = std::env::temp_dir().join(format!("kiri-swarm-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let engine = super::super::engine::boot_without_vm(&root);
        let init_req = Request::internal("POST", "/swarm/init", &[], br#"{"ListenAddr":"0.0.0.0:2377","AdvertiseAddr":"192.168.1.5"}"#.to_vec());
        let node = init(&init_req, &engine).ok().expect("init");
        assert!(matches!(init(&init_req, &engine), Err(Fail::Unavailable(m)) if m == ALREADY));
        let create = Request::internal("POST", "/services/create", &[], web(2).to_string().into_bytes());
        let made = service_create(&create, &engine).ok().expect("created");
        let dup = service_create(&create, &engine);
        assert!(matches!(dup, Err(Fail::Api(Error::Conflict(_)))));
        let secret = Request::internal("POST", "/secrets/create", &[], br#"{"Name":"pw","Data":"aHVudGVyMg=="}"#.to_vec());
        blob_create(&secret, &engine.swarm, false).ok().expect("secret");
        drop(engine);
        let engine = super::super::engine::boot_without_vm(&root);
        let info = engine.swarm.info();
        assert_eq!(info["NodeID"], node);
        assert_eq!(info["NodeAddr"], "192.168.1.5");
        let svc = service_inspect(&engine, "web").ok().expect("kept");
        assert_eq!(svc["ID"], made["ID"]);
        let stale = Request::internal("POST", "/services/web/update", &[("version", "1")], web(3).to_string().into_bytes());
        assert!(matches!(service_update(&stale, &engine, "web"), Err(Fail::Api(Error::BadRequest(m))) if m.starts_with("update out of sequence")));
        let v = svc["Version"]["Index"].as_u64().unwrap().to_string();
        let fresh = Request::internal("POST", "/services/web/update", &[("version", v.as_str())], web(3).to_string().into_bytes());
        assert!(service_update(&fresh, &engine, "web").is_ok());
        let secret_json = blob_inspect(&engine.swarm, "pw", false).ok().expect("secret kept");
        assert!(secret_json["Spec"]["Data"].is_null(), "a secret's data is never shown");
        let in_use = json!({"Name": "db", "TaskTemplate": {"ContainerSpec": {"Image": "x", "Secrets": [{"SecretName": "pw", "File": {"Name": "pw"}}]}}});
        service_create(&Request::internal("POST", "/services/create", &[], in_use.to_string().into_bytes()), &engine).ok().expect("db");
        assert!(blob_remove(&engine.swarm, "pw", false).is_err(), "a secret in use stays");
        let _ = std::fs::remove_dir_all(&root);
    }
}
