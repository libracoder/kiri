//! Cloudflare sharing through an installed cloudflared. Named tunnels are
//! provisioned separately; Kiri only runs them, with one hostname per tunnel.
//! A small helper owns the child and watches a pipe from Kiri. EOF closes the
//! tunnel even if the CLI/window is killed without running destructors.

use super::*;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, ExitCode, Stdio};

#[path = "cloudflare_settings.rs"]
pub mod settings;

const POLL: Duration = Duration::from_millis(200);
const STARTUP: Duration = Duration::from_secs(90);
pub const HELPER: &str = "__share-cloudflared";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub executable: String,
    pub base_domain: Option<String>,
    pub tunnels: BTreeMap<String, NamedTunnel>,
}

impl Default for Config {
    fn default() -> Self {
        Self { executable: "cloudflared".into(), base_domain: None, tunnels: BTreeMap::new() }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedTunnel {
    pub id: String,
    pub credentials_file: PathBuf,
}

#[derive(Debug)]
struct Route {
    url: Option<String>,
    tunnel: Option<NamedTunnel>,
}

fn dns_label(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.as_bytes()[0].is_ascii_alphanumeric() && s.as_bytes()[s.len() - 1].is_ascii_alphanumeric() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn domain(s: &str) -> io::Result<String> {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.len() > 253 || !s.contains('.') || !s.split('.').all(dns_label) || s.parse::<std::net::IpAddr>().is_ok() {
        return Err(io::Error::other("cloudflare.base_domain must be a DNS name such as example.com, without a scheme, port, path or wildcard"));
    }
    Ok(s)
}

fn uuid(s: &str) -> bool {
    s.len() == 36 && s.bytes().enumerate().all(|(i, b)| if [8, 13, 18, 23].contains(&i) { b == b'-' } else { b.is_ascii_hexdigit() })
}

fn route(cfg: &Config, opts: &Options) -> io::Result<Route> {
    let Some(base) = &cfg.base_domain else {
        if !cfg.tunnels.is_empty() {
            return Err(io::Error::other("set cloudflare.base_domain before using named tunnels"));
        }
        return Ok(Route { url: None, tunnel: None });
    };
    let base = domain(base)?;
    let name = opts.name.as_deref().unwrap_or(&opts.target.label).to_ascii_lowercase();
    if !dns_label(&name) || name.len() + 1 + base.len() > 253 {
        return Err(io::Error::other("choose a DNS label for this share with --name NAME (letters, digits and hyphens, up to 63 characters)"));
    }
    let tunnel = cfg.tunnels.get(&name).ok_or_else(|| io::Error::other(format!("configure cloudflare.tunnels.{name} for {name}.{base}; see docs/cloudflare-sharing.md")))?.clone();
    if !uuid(&tunnel.id) || !tunnel.credentials_file.is_absolute() {
        return Err(io::Error::other("a named Cloudflare tunnel needs a UUID and an absolute credentials_file path"));
    }
    if cfg.tunnels.values().filter(|t| t.id.eq_ignore_ascii_case(&tunnel.id)).count() != 1 {
        return Err(io::Error::other("each share name needs its own Cloudflare tunnel UUID; reusing one sends traffic to the wrong container"));
    }
    Ok(Route { url: Some(format!("https://{name}.{base}")), tunnel: Some(tunnel) })
}

fn root() -> io::Result<PathBuf> {
    Ok(config_path()?.parent().unwrap_or(Path::new(".")).join("cloudflare-shares"))
}

fn private_dir(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Cleanup belongs to the helper once it starts; until then the caller owns it.
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn lock(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
    file.try_lock().map_err(|_| io::Error::other("this Cloudflare tunnel is already running on this computer"))?;
    Ok(file)
}

fn hidden(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    #[cfg(not(windows))]
    let _ = command;
}

#[derive(Serialize, Deserialize)]
struct Plan {
    executable: String,
    args: Vec<String>,
    lock: Option<PathBuf>,
}

fn prepare(cfg: &Config, opts: &Options, route: &Route, dir: &Path) -> io::Result<Plan> {
    // The origin comes from Kiri's resolver, but don't let URL syntax in a
    // host turn a host:port target into credentials, a path or a query.
    let addr = &opts.target.addr;
    if addr.bytes().any(|b| b.is_ascii_whitespace() || b"/@?#\\".contains(&b)) {
        return Err(io::Error::other("invalid Cloudflare origin address"));
    }
    let config = dir.join("config.yml");
    let mut args = vec!["tunnel".into(), "--config".into(), config.to_string_lossy().into_owned(), "--no-autoupdate".into(), "--output".into(), "json".into(), "--loglevel".into(), "info".into(), "--metrics".into(), "127.0.0.1:0".into(), "--pidfile".into(), dir.join("connected.pid").to_string_lossy().into_owned()];
    let (content, lock) = if let Some(t) = &route.tunnel {
        let credentials = std::fs::canonicalize(&t.credentials_file).map_err(|e| io::Error::other(format!("cannot read Cloudflare credentials file: {e}")))?;
        // Check the ID locally; never print or copy the credential contents.
        let credential: Value = serde_json::from_reader(File::open(&credentials)?).map_err(|_| io::Error::other("invalid Cloudflare tunnel credentials JSON"))?;
        if !credential["TunnelID"].as_str().is_some_and(|id| id.eq_ignore_ascii_case(&t.id)) {
            return Err(io::Error::other("Cloudflare credentials TunnelID does not match the configured tunnel UUID"));
        }
        args.extend(["run".into(), t.id.to_ascii_lowercase()]);
        let content = json!({"tunnel": t.id, "credentials-file": credentials, "ingress": [
            {"hostname": route.url.as_ref().unwrap().trim_start_matches("https://"), "service": format!("http://{addr}")},
            {"service": "http_status:404"}
        ]});
        // Beside the credential file, so the CLI and app (even with different
        // share.json paths) cannot accidentally run replicas for different ports.
        let lock = credentials.with_extension("kiri.lock");
        (content, Some(lock))
    } else {
        args.extend(["--url".into(), format!("http://{addr}")]);
        (json!({}), None)
    };
    // JSON is a YAML subset. An explicit file also isolates Quick Tunnels
    // from any unrelated ~/.cloudflared/config.yml the person already has.
    std::fs::write(config, serde_json::to_vec(&content)?)?;
    Ok(Plan { executable: cfg.executable.clone(), args, lock })
}

/// Private entry point, dispatched before normal CLI/UI startup on every OS.
pub fn helper(args: &[String]) -> ExitCode {
    let result = (|| -> io::Result<()> {
        let dir = PathBuf::from(args.first().ok_or_else(|| io::Error::other("missing tunnel runtime directory"))?);
        let id = dir.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if args.len() != 1 || !share_id(id) || dir.canonicalize()?.parent() != Some(root()?.canonicalize()?.as_path()) {
            return Err(io::Error::other("invalid Cloudflare runtime directory"));
        }
        let plan: Plan = serde_json::from_reader(File::open(dir.join("plan.json"))?)?;
        let active = lock(&dir.join("active.lock"))?;
        let _dir = Directory(dir.clone());
        let _active = active; // Close the lock before removing the directory on Windows.
        let _named = plan.lock.as_deref().map(lock).transpose()?;
        let mut command = Command::new(&plan.executable);
        command.args(&plan.args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::inherit());
        // cloudflared's environment must not silently replace our explicit
        // routing, credentials or TLS settings with an unrelated tunnel's.
        for (key, _) in std::env::vars_os() {
            let k = key.to_string_lossy();
            if k.starts_with("TUNNEL_") || k == "NO_TLS_VERIFY" || k == "KIRI_SHARE_TOKEN" {
                command.env_remove(key);
            }
        }
        hidden(&mut command);
        if dir.join("stop").exists() {
            return Ok(());
        }
        let mut child = Process(command.spawn().map_err(|e| io::Error::other(format!("could not start cloudflared: {e}; install it or set cloudflare.executable to its absolute path")))?);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = io::stdin().read(&mut [0u8]);
            let _ = tx.send(());
        });
        loop {
            if rx.try_recv().is_ok() || dir.join("stop").exists() {
                return Ok(()); // Process drops before Directory, closing the public link.
            }
            if let Some(status) = child.0.try_wait()? {
                return Err(io::Error::other(format!("cloudflared exited ({status}); check its installation, tunnel credentials and network connectivity")));
            }
            std::thread::sleep(POLL);
        }
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{}", json!({"kiri_error": e.to_string()}));
            ExitCode::FAILURE
        }
    }
}

#[derive(Default)]
struct Logs {
    url: Option<String>,
    metrics: Option<SocketAddr>,
    error: Option<String>,
}

fn log_line(line: &str, logs: &mut Logs) {
    let Ok(v) = serde_json::from_str::<Value>(line) else {
        return;
    };
    if let Some(e) = v["kiri_error"].as_str() {
        logs.error = Some(e.to_owned());
    }
    let message = v["message"].as_str().unwrap_or("");
    for word in message.split_whitespace() {
        if let Some(host) = word.strip_prefix("https://").and_then(|h| h.strip_suffix(".trycloudflare.com"))
            && dns_label(host)
        {
            logs.url = Some(word.to_owned());
        }
        if let Some(addr) = word.strip_suffix("/metrics").and_then(|a| a.parse::<SocketAddr>().ok())
            && addr.ip().is_loopback()
            && addr.port() != 0
        {
            logs.metrics = Some(addr);
        }
    }
}

fn ready(addr: SocketAddr) -> bool {
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(300)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
    let _ = s.set_write_timeout(Some(Duration::from_millis(300)));
    if write!(s, "GET /ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").is_err() {
        return false;
    }
    let mut status = String::new();
    BufReader::new(s).take(128).read_line(&mut status).is_ok_and(|_| super::parse_status_line(status.as_bytes()) == Some(200))
}

fn record(dir: &Path, cfg: &super::Config, opts: &Options, url: &str) -> io::Result<()> {
    let v = json!({"name": dir.file_name().unwrap().to_string_lossy(), "url": url,
        "label": opts.name.as_deref().unwrap_or(&opts.target.label), "target": opts.target.display,
        "machine": machine_id(&cfg.device), "device": cfg.device, "host": host_name(),
        "kind": if opts.app {"app"} else {"cli"}, "client": format!("{} {}", if opts.app {crate::flavor::APP.get()} else {"kiri"}, env!("CARGO_PKG_VERSION")),
        "started": SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs()});
    let temp = dir.join("live.tmp");
    std::fs::write(&temp, serde_json::to_vec(&v)?)?;
    std::fs::rename(temp, dir.join("live.json"))
}

pub(super) fn start(cfg: super::Config, opts: Options, on_event: impl Fn(Event) + Send + Sync + 'static) -> io::Result<Handle> {
    let cloudflare = cfg.cloudflare.clone().unwrap_or_default();
    let route = route(&cloudflare, &opts)?;
    let root = root()?;
    std::fs::create_dir_all(&root)?;
    let dir = root.canonicalize()?.join(random_hex(16));
    private_dir(&dir)?;
    let cleanup = Directory(dir.clone());
    let plan = prepare(&cloudflare, &opts, &route, &dir)?;
    std::fs::write(dir.join("plan.json"), serde_json::to_vec(&plan)?)?;
    let mut command = Command::new(std::env::current_exe()?);
    command.arg(HELPER).arg(&dir).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped());
    hidden(&mut command);
    let mut child = command.spawn()?;
    let owner = child.stdin.take();
    let stderr = child.stderr.take().unwrap();
    let logs = Arc::new(Mutex::new(Logs::default()));
    let log_state = logs.clone();
    let reader = std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        loop {
            let mut line = String::new();
            // Bound an unexpected log line. Never forward raw cloudflared
            // logs: they can include settings, headers or other private data.
            match reader.by_ref().take(64 * 1024).read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => log_line(&line, &mut log_state.lock().unwrap()),
            }
        }
    });
    let stop = Arc::new(Stopper::default());
    let s = stop.clone();
    let thread = std::thread::spawn(move || {
        let _cleanup = cleanup;
        let on_event = |event: Event| {
            log_event(&event);
            on_event(event);
        };
        on_event(Event::Connecting { server: "Cloudflare Tunnel".into() });
        if route.url.is_none() {
            on_event(Event::Notice("Temporary Cloudflare URL; a requested name does not reserve an address. Configure a base domain and named tunnels for stable links.".into()));
        }
        on_event(Event::Notice("Cloudflare request logs and traffic totals are not available in Kiri.".into()));
        let began = Instant::now();
        let mut live = false;
        let mut ever_live = false;
        let mut failure = None;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        failure = Some("Cloudflare tunnel helper exited".to_owned());
                    }
                    break;
                }
                Err(e) => {
                    failure = Some(format!("could not monitor cloudflared: {e}"));
                    break;
                }
                Ok(None) => {}
            }
            if s.is_stopped() {
                break;
            }
            let (url, metrics) = {
                let l = logs.lock().unwrap();
                (route.url.clone().or_else(|| l.url.clone()), l.metrics)
            };
            let connected = metrics.map(ready).unwrap_or_else(|| dir.join("connected.pid").exists());
            if connected && !live {
                if let Some(url) = url {
                    if let Err(e) = record(&dir, &cfg, &opts, &url) {
                        failure = Some(format!("could not record the Cloudflare share: {e}"));
                        break;
                    }
                    on_event(Event::Live { url, rate: 0, remaining: u64::MAX, warning: false, domains: Vec::new() });
                    live = true;
                    ever_live = true;
                }
            } else if !connected && live {
                live = false;
                on_event(Event::Reconnecting { reason: "Cloudflare Tunnel is reconnecting".into(), delay: POLL });
            }
            if !ever_live && began.elapsed() >= STARTUP {
                failure = Some("Cloudflare Tunnel did not connect within 90 seconds; check cloudflared, credentials and outbound network access".into());
                break;
            }
            if s.sleep(POLL) {
                break;
            }
        }
        // Closing this pipe is also how a crashed/killed parent releases the
        // helper. It kills and reaps only the cloudflared child it owns.
        drop(owner);
        let _ = child.wait();
        let _ = reader.join();
        failure = logs.lock().unwrap().error.clone().or(failure);
        if s.is_stopped() {
            failure = None;
        }
        on_event(Event::Ended { error: failure.is_some(), reason: failure.unwrap_or_else(|| "stopped".into()) });
    });
    Ok(Handle { stop, thread: Some(thread) })
}

fn active(dir: &Path) -> bool {
    let Ok(file) = OpenOptions::new().read(true).write(true).open(dir.join("active.lock")) else {
        return false;
    };
    matches!(file.try_lock(), Err(std::fs::TryLockError::WouldBlock))
}

pub(super) fn tunnels() -> io::Result<LiveTunnels> {
    let mut list = LiveTunnels::default();
    let entries = match std::fs::read_dir(root()?) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(list),
        Err(e) => return Err(e),
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if !active(&dir) {
            continue;
        }
        if let Ok(v) = std::fs::read(dir.join("live.json")).and_then(|b| serde_json::from_slice::<Value>(&b).map_err(io::Error::other)) {
            list.items.push(live_tunnel(&v));
        }
    }
    Ok(list)
}

pub(super) fn close_tunnel(name: &str) -> io::Result<()> {
    if !share_id(name) {
        return Err(io::Error::other("invalid Cloudflare share ID"));
    }
    let dir = root()?.join(name);
    if !active(&dir) {
        return Err(io::Error::other("this Cloudflare share is no longer running"));
    }
    std::fs::write(dir.join("stop"), b"")
}

fn share_id(name: &str) -> bool {
    name.len() == 32 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Also stop CLI shares still connecting, before they have a public URL.
pub fn close_all() {
    let Ok(root) = root() else { return };
    let Ok(entries) = std::fs::read_dir(root) else { return };
    for entry in entries.flatten() {
        if share_id(&entry.file_name().to_string_lossy()) {
            let _ = std::fs::write(entry.path().join("stop"), b"");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn opts(name: Option<&str>) -> Options {
        Options { target: Target { addr: "localhost:3000".into(), label: "web".into(), display: "web".into() }, name: name.map(str::to_owned), app: false }
    }
    fn named() -> Config {
        serde_json::from_value(json!({"base_domain":"Example.com.", "tunnels":{"web":{"id":"01234567-89ab-cdef-0123-456789abcdef","credentials_file":std::env::temp_dir().join("credentials.json")}}})).unwrap()
    }
    #[test]
    fn routes_require_explicit_named_configuration() {
        assert!(route(&Config::default(), &opts(None)).unwrap().url.is_none());
        assert_eq!(route(&named(), &opts(None)).unwrap().url.as_deref(), Some("https://web.example.com"));
        assert!(route(&named(), &opts(Some("missing"))).is_err());
        assert!(route(&named(), &opts(Some("../web"))).is_err());
        let mut c = named();
        c.tunnels.insert("other".into(), c.tunnels["web"].clone());
        assert!(route(&c, &opts(None)).is_err());
        c.base_domain = None;
        assert!(route(&c, &opts(None)).is_err());
    }
    #[test]
    fn invalid_domains_are_rejected() {
        for bad in ["", "localhost", "https://example.com", "example.com:443", "*.example.com", "example.com/path", "-example.com", "a..com", "127.0.0.1", "a_b.com"] {
            assert!(domain(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn only_cloudflare_urls_and_loopback_metrics_are_accepted() {
        let mut logs = Logs::default();
        log_line(r#"{"message":"| https://small-river.trycloudflare.com |"}"#, &mut logs);
        assert_eq!(logs.url.as_deref(), Some("https://small-river.trycloudflare.com"));
        for bad in ["https://evil.com", "https://user@evil.trycloudflare.com", "https://evil.trycloudflare.com/path", "https://a.b.trycloudflare.com"] {
            log_line(&json!({"message":bad}).to_string(), &mut logs);
            assert_eq!(logs.url.as_deref(), Some("https://small-river.trycloudflare.com"));
        }
        log_line(r#"{"message":"Starting metrics server on 0.0.0.0:1234/metrics"}"#, &mut logs);
        assert!(logs.metrics.is_none());
        log_line(r#"{"message":"Starting metrics server on 127.0.0.1:1234/metrics"}"#, &mut logs);
        assert_eq!(logs.metrics, Some("127.0.0.1:1234".parse().unwrap()));
    }
    #[test]
    fn old_configs_keep_kiri_and_unknown_providers_fail() {
        assert_eq!(serde_json::from_value::<super::super::Config>(json!({"device":"old"})).unwrap().provider, Provider::Kiri);
        assert!(serde_json::from_value::<super::super::Config>(json!({"provider":"typo"})).is_err());
    }
}
