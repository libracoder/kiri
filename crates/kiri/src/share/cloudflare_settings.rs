//! Domain setup shared by the CLI and window. Only credential paths and
//! tunnel IDs are saved; the secret stays in cloudflared's credentials file.
use super::*;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Draft {
    pub base_domain: Option<String>,
    pub routes: Vec<RouteInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteInput {
    pub name: String,
    pub credentials_file: PathBuf,
}

pub(super) fn draft(cfg: &Config) -> Draft {
    Draft { base_domain: cfg.base_domain.clone(), routes: cfg.tunnels.iter().map(|(name, t)| RouteInput { name: name.clone(), credentials_file: t.credentials_file.clone() }).collect() }
}

pub(super) fn credentials(path: &Path) -> io::Result<NamedTunnel> {
    let expanded = if let Ok(rest) = path.strip_prefix("~") { PathBuf::from(std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).ok_or_else(|| io::Error::other("HOME is not set"))?).join(rest) } else { path.to_owned() };
    let credentials_file = expanded.canonicalize().map_err(|e| io::Error::other(format!("cannot read Cloudflare credentials file: {e}")))?;
    let value: Value = serde_json::from_reader(File::open(&credentials_file)?.take(64 * 1024)).map_err(|_| io::Error::other("choose the tunnel credentials JSON created by cloudflared tunnel create, not cert.pem or a tunnel token"))?;
    let id = value["TunnelID"].as_str().filter(|id| uuid(id)).ok_or_else(|| io::Error::other("Cloudflare credentials must contain a valid TunnelID UUID"))?.to_ascii_lowercase();
    Ok(NamedTunnel { id, credentials_file })
}

fn validate(input: Draft, executable: String) -> io::Result<Config> {
    let base_domain = input.base_domain.as_deref().map(domain).transpose()?;
    if base_domain.is_none() && !input.routes.is_empty() {
        return Err(io::Error::other("set a base domain for named tunnels, or remove the routes to use temporary links"));
    }
    let mut tunnels = BTreeMap::<String, NamedTunnel>::new();
    for entry in input.routes {
        let name = entry.name.trim().to_ascii_lowercase();
        if !dns_label(&name) || name.len() + 1 + base_domain.as_ref().map_or(0, String::len) > 253 {
            return Err(io::Error::other("each share name must be a DNS label (letters, digits and hyphens, up to 63 characters), within a 253-character hostname"));
        }
        if tunnels.contains_key(&name) {
            return Err(io::Error::other(format!("duplicate share name: {name}")));
        }
        let tunnel = credentials(&entry.credentials_file)?;
        if tunnels.values().any(|t| t.id == tunnel.id) {
            return Err(io::Error::other("each share name needs its own Cloudflare tunnel UUID; reusing one sends traffic to the wrong container"));
        }
        tunnels.insert(name, tunnel);
    }
    Ok(Config { executable, base_domain, tunnels })
}

fn snapshot(cfg: &Config) -> Value {
    let routes: Vec<Value> = cfg
        .tunnels
        .iter()
        .map(|(name, tunnel)| {
            json!({
                "name": name, "id": tunnel.id, "credentials_file": tunnel.credentials_file,
                "hostname": cfg.base_domain.as_ref().map(|base| format!("{name}.{base}")),
                "dns_target": format!("{}.cfargotunnel.com", tunnel.id)
            })
        })
        .collect();
    json!({"base_domain": cfg.base_domain, "routes": routes})
}

pub fn current() -> io::Result<Value> {
    Ok(snapshot(&load()?.cloudflare.unwrap_or_default()))
}

/// Validate everything before saving. Existing links retain their routing;
/// changes apply when the user next starts a share.
pub fn update(input: Draft) -> io::Result<Value> {
    let mut cfg = load()?;
    let executable = cfg.cloudflare.as_ref().map(|c| c.executable.clone()).unwrap_or_else(|| Config::default().executable);
    let cloudflare = validate(input, executable)?;
    let result = snapshot(&cloudflare);
    cfg.cloudflare = Some(cloudflare);
    cfg.provider = Provider::Cloudflare;
    save(&cfg)?;
    Ok(result)
}

const USAGE: &str = "usage: kiri share domain add BASE_DOMAIN NAME CREDENTIALS_FILE
       kiri share domain connect BASE_DOMAIN [--json]
       kiri share domain create BASE_DOMAIN NAME [--json]
       kiri share domain list [--json]
       kiri share domain remove NAME
       kiri share domain clear

Connect opens Cloudflare's browser authorization. Create provisions the
tunnel and DNS record automatically. Add imports an existing locally
managed tunnel; configure its DNS separately.
Clear removes local domain mappings and returns to temporary links;
credentials and Cloudflare resources are kept. Existing links stay open.";

pub fn cli(args: &[String]) -> io::Result<()> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    if matches!(args.first(), Some(&"connect" | &"create")) {
        return super::setup::cli(&args);
    }
    let result = match args.as_slice() {
        [] | ["list"] | ["list", "--json"] => current()?,
        ["add", base, name, file] => {
            let base = domain(base)?;
            let cfg = load()?.cloudflare.unwrap_or_default();
            if let Some(old) = cfg.base_domain.as_deref()
                && domain(old)? != base
            {
                return Err(io::Error::other("a different base domain is configured; edit all routes in Share → Custom domain, or run kiri share domain clear first"));
            }
            let mut input = draft(&cfg);
            input.base_domain = Some(base);
            input.routes.retain(|r| !r.name.eq_ignore_ascii_case(name.trim()));
            input.routes.push(RouteInput { name: (*name).into(), credentials_file: PathBuf::from(file) });
            update(input)?
        }
        ["remove", name] => {
            let mut input = draft(&load()?.cloudflare.unwrap_or_default());
            let before = input.routes.len();
            input.routes.retain(|r| !r.name.eq_ignore_ascii_case(name.trim()));
            if before == input.routes.len() {
                return Err(io::Error::other("no Cloudflare route with that share name"));
            }
            update(input)?
        }
        ["clear"] => update(Draft::default())?,
        _ => return Err(io::Error::other(USAGE)),
    };
    if args.as_slice() == ["list", "--json"] {
        println!("{result}");
    } else {
        match result["base_domain"].as_str() {
            None => println!("Cloudflare: temporary trycloudflare.com links"),
            Some(base) => {
                println!("Cloudflare base domain: {base}");
                for r in result["routes"].as_array().into_iter().flatten() {
                    println!("https://{}  →  {}", r["hostname"].as_str().unwrap(), r["name"].as_str().unwrap());
                    println!("  DNS: proxied CNAME {} → {}", r["hostname"].as_str().unwrap(), r["dns_target"].as_str().unwrap());
                }
                println!("Create these DNS records in Cloudflare before sharing. Settings apply to new links.");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Directory, PathBuf) {
        let dir = Directory(std::env::temp_dir().join(format!("kiri-domain-{}", random_hex(8))));
        private_dir(&dir.0).unwrap();
        let file = dir.0.join("tunnel credentials.json");
        std::fs::write(&file, br#"{"TunnelID":"01234567-89AB-CDEF-0123-456789ABCDEF","TunnelSecret":"must-not-be-exported"}"#).unwrap();
        (dir, file)
    }

    fn input(base: Option<&str>, names: &[&str], file: &Path) -> Draft {
        Draft { base_domain: base.map(str::to_owned), routes: names.iter().map(|name| RouteInput { name: (*name).into(), credentials_file: file.to_owned() }).collect() }
    }

    #[test]
    fn setup_normalizes_routes_and_exports_only_credential_paths() {
        let (_dir, file) = fixture();
        let cfg = validate(input(Some(" Apps.Example.com. "), &[" WEB "], &file), "/custom/cloudflared".into()).unwrap();
        assert_eq!(cfg.base_domain.as_deref(), Some("apps.example.com"));
        assert_eq!(cfg.tunnels["web"].id, "01234567-89ab-cdef-0123-456789abcdef");
        assert_eq!(cfg.tunnels["web"].credentials_file, file.canonicalize().unwrap());
        assert_eq!(cfg.executable, "/custom/cloudflared");
        let exported = snapshot(&cfg);
        assert_eq!(exported["routes"][0]["hostname"], "web.apps.example.com");
        assert!(!exported.to_string().contains("must-not-be-exported"));
        let opts = Options { target: Target { label: "web".into(), addr: "localhost:3000".into(), display: "web".into() }, name: None, app: true };
        assert_eq!(route(&cfg, &opts).unwrap().url.as_deref(), Some("https://web.apps.example.com"));
    }

    #[test]
    fn setup_rejects_ambiguous_names_tunnels_and_overlong_hostnames() {
        let (_dir, file) = fixture();
        for names in [&["web", "WEB"][..], &["web", "api"][..], &["bad/name"][..]] {
            assert!(validate(input(Some("example.com"), names, &file), "cloudflared".into()).is_err());
        }
        assert!(validate(input(None, &["web"], &file), "cloudflared".into()).is_err());
        let base = format!("{}.{}.{}.com", "a".repeat(63), "b".repeat(63), "c".repeat(63));
        assert!(validate(input(Some(&base), &[&"d".repeat(63)], &file), "cloudflared".into()).is_err());
    }

    #[test]
    fn invalid_credentials_do_not_echo_their_contents() {
        let (_dir, file) = fixture();
        for contents in ["must-not-be-exported", r#"{"TunnelID":"must-not-be-exported"}"#] {
            std::fs::write(&file, contents).unwrap();
            let error = credentials(&file).unwrap_err().to_string();
            assert!(!error.contains("must-not-be-exported"));
        }
    }
}
