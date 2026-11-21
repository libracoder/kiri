//! A Windows host's root certificates, for the engine in WSL (#303). The
//! daemon runs in a Linux distro there, away from the Windows store, so
//! kiri-win sends the store's roots that the bundled set lacks (a company
//! root, among them) and the ones the administrator distrusted
//! (`PUT /kiri/roots/host`), when the engine starts and every minute. They
//! are kept in `~/.kiri/host-roots.json`, so a pull before the window has
//! sent them (the engine started by the boot command) trusts them too.

use std::io::{self, Read};
use std::path::PathBuf;

use kiri_image::roots::{self, Host};
use serde_json::{Value, json};

/// The file's size at most: every certificate past the caps is dropped
/// anyway.
const MAX_FILE: u64 = 8 << 20;

fn path() -> Option<PathBuf> {
    super::state_dir().ok().map(|d| d.join("host-roots.json"))
}

/// The roots in `body` (`{"certs": [hex DER…], "distrusted": [hex DER…]}`).
pub fn parse(body: &Value) -> Host {
    let list = |k: &str| body[k].as_array().into_iter().flatten().filter_map(Value::as_str).collect::<Vec<_>>();
    Host::from_hex(list("certs"), list("distrusted"))
}

fn to_json(h: &Host) -> Value {
    let list = |l: &[rustls::pki_types::CertificateDer<'static>]| l.iter().map(|c| roots::hex(c)).collect::<Vec<_>>();
    json!({"certs": list(&h.certs), "distrusted": list(&h.distrusted)})
}

/// Takes the roots kiri-win sent, keeping them for the next start when
/// they changed. Answers with how many there are.
pub fn set(body: &Value) -> io::Result<Value> {
    let host = parse(body);
    let (certs, distrusted) = (host.certs.len(), host.distrusted.len());
    let changed = roots::set_host(host.clone());
    if changed && let Some(p) = path() {
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, to_json(&host).to_string())?;
        std::fs::rename(&tmp, &p)?;
    }
    Ok(json!({"certs": certs, "distrusted": distrusted, "changed": changed}))
}

/// The roots kept from the last time, if any: read at start, before the
/// first pull.
pub fn load() {
    let Some(p) = path() else { return };
    let read = || -> io::Result<Value> {
        let f = std::fs::File::open(&p)?;
        if !f.metadata()?.is_file() {
            return Err(io::Error::other("not a file"));
        }
        let mut text = Vec::new();
        f.take(MAX_FILE).read_to_end(&mut text)?;
        serde_json::from_slice(&text).map_err(io::Error::other)
    };
    // Never over roots kiri-win has sent this run already.
    if let Ok(v) = read()
        && roots::host().is_none()
    {
        roots::set_host(parse(&v));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_lists_kiri_win_sends_and_writes_them_back_the_same() {
        let body = json!({"certs": ["3001", 7, "zz"], "distrusted": ["30020a0b"]});

        let host = parse(&body);

        assert_eq!(host.certs.len(), 1);
        assert_eq!(host.distrusted[0].as_ref(), &[0x30, 0x02, 0x0a, 0x0b]);
        assert_eq!(to_json(&host), json!({"certs": ["3001"], "distrusted": ["30020a0b"]}));
    }

    #[test]
    fn a_body_without_lists_is_no_roots() {
        assert_eq!(parse(&json!({})), Host::default());
    }
}
