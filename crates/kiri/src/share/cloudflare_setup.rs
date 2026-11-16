//! Browser authorization and automatic tunnel/DNS provisioning. cloudflared
//! performs Cloudflare's HTTPS authorization transfer and API requests.
//! Every command is supervised, just like a live share. Failed DNS setup
//! retains the new tunnel's credentials so retries do not create duplicates.
use super::*;
use sha2::Digest;

fn managed_root() -> io::Result<PathBuf> {
    Ok(config_path()?.parent().unwrap_or(Path::new(".")).join("cloudflare-managed"))
}

fn digest(value: &str) -> String {
    sha2::Sha256::digest(value.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn certificate(managed: &Path, base: &str) -> PathBuf {
    managed.join("accounts").join(digest(base)).join(".cloudflared/cert.pem")
}

fn secure_directory(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

fn certificate_available(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.len() > 0)
}

pub fn status(base: &str) -> io::Result<Value> {
    let available = domain(base).ok().is_some_and(|base| managed_root().is_ok_and(|root| certificate_available(&certificate(&root, &base))));
    Ok(json!({"certificate_available": available}))
}

/// Only Cloudflare's generated HTTPS authorization link may reach the UI.
pub fn authorization_url(line: &str) -> Option<String> {
    line.split_whitespace().find(|word| word.starts_with("https://dash.cloudflare.com/argotunnel?") && word.len() < 4096 && word.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~:/?&=%+".contains(&b))).map(str::to_owned)
}

/// Cloudflare returns the actual DNS name, which can differ when the wrong
/// zone was authorized. Never report the requested address ready in that case.
fn routed_hostname(line: &str) -> Option<String> {
    let log: Value = serde_json::from_str(line).ok()?;
    let message = log["message"].as_str()?;
    let hostname = message.strip_prefix("Added CNAME ").and_then(|s| s.strip_suffix(" which will route to this tunnel")).or_else(|| message.strip_suffix(" is already configured to route to your tunnel"))?;
    domain(hostname).ok()
}

fn check_cancel(cancel: &AtomicBool) -> io::Result<()> {
    if cancel.load(Ordering::SeqCst) { Err(io::Error::new(io::ErrorKind::Interrupted, "Cloudflare setup cancelled. Any created tunnel is retained for retry.")) } else { Ok(()) }
}

fn command(cfg: &Config, cert: &Path, args: &[String], cancel: &AtomicBool, notify: &mut dyn FnMut(Value)) -> io::Result<()> {
    check_cancel(cancel)?;
    let runtime = root()?;
    std::fs::create_dir_all(&runtime)?;
    let dir = runtime.canonicalize()?.join(random_hex(16));
    private_dir(&dir)?;
    let _cleanup = Directory(dir.clone());
    std::fs::write(dir.join("config.yml"), b"{}")?;
    let mut flags = vec!["tunnel".into(), "--config".into(), dir.join("config.yml").to_string_lossy().into_owned(), "--no-autoupdate".into(), "--output".into(), "json".into(), "--origincert".into(), cert.to_string_lossy().into_owned()];
    flags.extend_from_slice(args);
    let plan = Plan { executable: cfg.executable.clone(), args: flags, lock: None, allow_exit: true, cloudflared_home: cert.parent().and_then(Path::parent).map(Path::to_owned) };
    std::fs::write(dir.join("plan.json"), serde_json::to_vec(&plan)?)?;
    let mut helper = Command::new(std::env::current_exe()?);
    helper.arg(HELPER).arg(&dir).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped());
    hidden(&mut helper);
    let mut child = helper.spawn()?;
    let owner = child.stdin.take();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        loop {
            let mut line = String::new();
            match reader.by_ref().take(64 * 1024).read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if let Some(url) = authorization_url(&line) {
                        let _ = tx.send((true, url));
                    }
                    if let Some(hostname) = routed_hostname(&line) {
                        let _ = tx.send((false, hostname));
                    }
                }
            }
        }
    });
    let mut routed = None;
    let mut announce = |(auth, value): (bool, String)| {
        if auth {
            notify(json!({"state":"authorizing", "auth_url":value, "message":"Approve the domain in your browser. Kiri will continue automatically."}));
        } else {
            routed = Some(value);
        }
    };
    let began = Instant::now();
    let timeout = if args.first().is_some_and(|a| a == "login") { Duration::from_secs(300) } else { Duration::from_secs(60) };
    let result = (|| {
        loop {
            for url in rx.try_iter() {
                announce(url);
            }
            check_cancel(cancel)?;
            if began.elapsed() > timeout {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "Cloudflare setup timed out. Retry when authorization and connectivity are available."));
            }
            if let Some(status) = child.try_wait()? {
                return if status.success() { Ok(()) } else { Err(io::Error::other("Cloudflare rejected the request or could not be reached. Check domain authorization and your connection.")) };
            }
            std::thread::sleep(POLL);
        }
    })();
    // EOF asks the helper to stop and reap cloudflared, even on cancellation.
    drop(owner);
    let _ = child.wait();
    let _ = reader.join();
    for url in rx.try_iter() {
        announce(url);
    }
    result?;
    if args.first().is_some_and(|a| a == "route") && routed.as_ref() != args.last() {
        return Err(io::Error::other("Cloudflare did not confirm the requested DNS hostname. Reconnect and select the correct domain, then retry."));
    }
    Ok(())
}

fn connect(cert: &Path, reauthorize: bool, run: &mut dyn FnMut(&[String]) -> io::Result<()>) -> io::Result<()> {
    let backup = cert.with_extension("previous");
    // Recover an interrupted reauthorization before starting another one.
    if backup.exists() {
        let _ = std::fs::remove_file(cert);
        std::fs::rename(&backup, cert)?;
    }
    let restore = reauthorize && certificate_available(cert);
    if restore {
        std::fs::rename(cert, &backup)?;
    }
    let result = (|| {
        if !certificate_available(cert) {
            run(&["login".into()])?;
            if !certificate_available(cert) {
                return Err(io::Error::other("Cloudflare authorization did not finish. Try Connect Cloudflare again."));
            }
        }
        // A saved certificate is not proof its authorization is still valid.
        run(&["list".into(), "--output".into(), "json".into()])
    })();
    if restore && result.is_err() {
        let _ = std::fs::remove_file(cert);
        std::fs::rename(&backup, cert)?;
    } else if result.is_ok() {
        let _ = std::fs::remove_file(backup);
    }
    result
}

fn names(base: &str, name: &str) -> io::Result<(String, String)> {
    let base = domain(base)?;
    let name = name.trim().to_ascii_lowercase();
    if !dns_label(&name) || name.len() + 1 + base.len() > 253 {
        return Err(io::Error::other("choose a share name with letters, digits and hyphens, within a 253-character hostname"));
    }
    Ok((base, name))
}

fn compatible(cfg: &Config, base: &str, name: &str, file: &Path) -> io::Result<()> {
    if let Some(old) = cfg.base_domain.as_deref()
        && domain(old)? != base
    {
        return Err(io::Error::other("another base domain is configured; change or clear it in Advanced before creating this address"));
    }
    if let Some(old) = cfg.tunnels.get(name)
        && old.credentials_file != file
    {
        return Err(io::Error::other("this share already has an imported tunnel; keep it or remove its mapping in Advanced before creating a new address"));
    }
    Ok(())
}

fn provision(file: &Path, tunnel_name: &str, hostname: &str, run: &mut dyn FnMut(&[String]) -> io::Result<()>) -> io::Result<NamedTunnel> {
    if !file.exists() {
        run(&["create".into(), "--credentials-file".into(), file.to_string_lossy().into_owned(), tunnel_name.into()]).map_err(|_| io::Error::other(format!("Cloudflare could not create tunnel {tunnel_name}. Check your authorization and connection, then retry.")))?;
    }
    let tunnel = settings::credentials(file)?;
    run(&["route".into(), "dns".into(), tunnel.id.clone(), hostname.into()])
        .map_err(|_| io::Error::other("The tunnel is saved, but Cloudflare could not create its DNS record. Check that you authorized this domain and that the hostname is not already in use. Existing records were not replaced; retry reuses this tunnel."))?;
    Ok(tunnel)
}

pub fn run(action: &str, value: &Value, cancel: &AtomicBool, notify: &mut dyn FnMut(Value)) -> io::Result<Value> {
    let mut cfg = load()?;
    let cloudflare = cfg.cloudflare.clone().unwrap_or_default();
    let base = domain(value["base_domain"].as_str().unwrap_or_default())?;
    let requested = match action {
        "connect" => None,
        "create" => Some(names(value["base_domain"].as_str().unwrap_or_default(), value["name"].as_str().unwrap_or_default())?),
        _ => return Err(io::Error::other("unknown Cloudflare setup action")),
    };
    let managed = managed_root()?;
    secure_directory(&managed)?;
    let managed = managed.canonicalize()?;
    let _operation = lock(&managed.join("setup.lock")).map_err(|_| io::Error::other("another Cloudflare setup is in progress"))?;
    let cert = certificate(&managed, &base);
    secure_directory(cert.parent().unwrap())?;
    let target = if let Some((base, name)) = requested {
        let hash = digest(&format!("{}:{base}:{name}", cfg.device));
        let dir = managed.join(&hash);
        if !dir.exists() {
            private_dir(&dir)?;
        }
        let file = dir.join("credentials.json");
        compatible(&cloudflare, &base, &name, &file)?;
        Some((base, name, file, format!("kiri-{}", &hash[..32])))
    } else {
        None
    };
    notify(json!({"state":"connecting", "message":"Connecting to Cloudflare. Authorize the domain in your browser if asked."}));
    connect(&cert, action == "connect", &mut |args| command(&cloudflare, &cert, args, cancel, notify))?;
    check_cancel(cancel)?;
    if let Some((base, name, file, tunnel_name)) = target {
        let hostname = format!("{name}.{base}");
        notify(json!({"state":"creating", "message":format!("Creating the tunnel and DNS record for {hostname}…")}));
        let tunnel = provision(&file, &tunnel_name, &hostname, &mut |args| command(&cloudflare, &cert, args, cancel, notify))?;
        check_cancel(cancel)?;
        // Browser approval can take minutes: merge into the latest settings.
        cfg = load()?;
        let current = cfg.cloudflare.get_or_insert_with(Config::default);
        compatible(current, &base, &name, &file)?;
        if current.tunnels.iter().any(|(key, t)| key != &name && t.id.eq_ignore_ascii_case(&tunnel.id)) {
            return Err(io::Error::other("this tunnel is already assigned to another share"));
        }
        current.base_domain = Some(base);
        current.tunnels.insert(name, tunnel);
        cfg.provider = Provider::Cloudflare;
        save(&cfg)?;
        Ok(json!({"hostname": hostname, "settings": settings::current()?, "certificate_available":true}))
    } else {
        Ok(json!({"certificate_available":true}))
    }
}

pub fn cli(args: &[&str]) -> io::Result<()> {
    let json_output = args.last() == Some(&"--json");
    let args = if json_output { &args[..args.len() - 1] } else { args };
    let (action, value) = match args {
        ["connect", base] => ("connect", json!({"base_domain":base})),
        ["create", base, name] => ("create", json!({"base_domain":base, "name":name})),
        _ => return Err(io::Error::other("usage: kiri share domain connect BASE_DOMAIN [--json] | create BASE_DOMAIN NAME [--json]")),
    };
    let result = run(action, &value, &AtomicBool::new(false), &mut |event| {
        if json_output {
            println!("{event}");
        } else if let Some(url) = event["auth_url"].as_str() {
            println!("Approve Cloudflare authorization: {url}");
        } else if let Some(message) = event["message"].as_str() {
            println!("{message}");
        }
    })?;
    if json_output {
        println!("{}", json!({"state":"done", "result":result}));
    } else if let Some(host) = result["hostname"].as_str() {
        println!("Ready: https://{host}. Use Share on the container to open its tunnel.");
    } else {
        println!("Connected to Cloudflare.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_links_must_be_cloudflares_authorization_endpoint() {
        let url = "https://dash.cloudflare.com/argotunnel?aud=&callback=https%3A%2F%2Flogin.cloudflareaccess.org%2Fpublic-key";
        assert_eq!(authorization_url(url).as_deref(), Some(url));
        for bad in ["http://dash.cloudflare.com/argotunnel?x=1", "https://dash.cloudflare.com.evil.example/argotunnel?x=1", "https://user@dash.cloudflare.com/argotunnel?x=1", "https://dash.cloudflare.com/argotunnel/other?x=1", "https://dash.cloudflare.com/argotunnel?x=<script>"] {
            assert!(authorization_url(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn dns_confirmation_uses_the_actual_hostname_from_cloudflare() {
        for message in ["Added CNAME web.example.com which will route to this tunnel", "web.example.com is already configured to route to your tunnel"] {
            assert_eq!(routed_hostname(&json!({"message":message}).to_string()).as_deref(), Some("web.example.com"));
        }
        assert_eq!(routed_hostname(&json!({"message":"Added CNAME web.example.com.other.net which will route to this tunnel"}).to_string()).as_deref(), Some("web.example.com.other.net"));
        assert!(routed_hostname("secret-must-not-leak").is_none());
    }

    #[test]
    fn cancelled_reauthorization_restores_the_previous_account_certificate() {
        let dir = Directory(std::env::temp_dir().join(format!("kiri-cf-login-{}", random_hex(8))));
        private_dir(&dir.0).unwrap();
        let cert = dir.0.join("cert.pem");
        std::fs::write(&cert, "previous authorization").unwrap();
        let result = connect(&cert, true, &mut |args| {
            assert_eq!(args, &["login"]);
            assert!(!cert.exists());
            Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read_to_string(&cert).unwrap(), "previous authorization");
        assert!(!cert.with_extension("previous").exists());
        // Simulate a crash after a replacement was written but before verification.
        std::fs::write(cert.with_extension("previous"), "last verified authorization").unwrap();
        std::fs::write(&cert, "unverified replacement").unwrap();
        connect(&cert, false, &mut |args| {
            assert_eq!(args, &["list", "--output", "json"]);
            Ok(())
        })
        .unwrap();
        assert_eq!(std::fs::read_to_string(cert).unwrap(), "last verified authorization");
    }
}
