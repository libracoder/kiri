//! A Windows host's root certificates, for the engine in WSL (#303). The
//! daemon runs in a Linux distro there, away from the Windows store, so
//! kiri-win sends the store's roots that the bundled set lacks (a company
//! root, among them) and the ones the administrator distrusted
//! (`PUT /kiri/roots/host`), when the engine starts and every minute. They
//! are kept in `~/.kiri/host-roots.json`, so a pull before the window has
//! sent them (the engine started by the boot command) trusts them too.

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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
    let list = |k: &str| body[k].as_array().into_iter().flatten().filter_map(Value::as_str);
    Host::from_hex(list("certs"), list("distrusted"))
}

fn to_json(h: &Host) -> Value {
    let list = |l: &[rustls::pki_types::CertificateDer<'static>]| l.iter().map(|c| roots::hex(c)).collect::<Vec<_>>();
    json!({"certs": list(&h.certs), "distrusted": list(&h.distrusted)})
}

/// Whether this daemon is the engine in WSL: the only place kiri-win's
/// roots belong. A native Linux daemon has its own store, and takes
/// neither the roots nor the file they are kept in.
pub fn in_wsl() -> bool {
    super::binds::wsl().is_some()
}

/// Takes the roots kiri-win sent, keeping them for the next start when
/// they changed. Answers with how many there are.
pub fn set(body: &Value) -> io::Result<Value> {
    // One save at a time: they share a temp file and serialize disk + memory updates.
    static SAVING: Mutex<()> = Mutex::new(());
    let _saving = SAVING.lock().unwrap_or_else(|e| e.into_inner());
    let host = parse(body);
    let (certs, distrusted) = (host.certs.len(), host.distrusted.len());
    let same = roots::host().as_ref() == Some(&host);
    if !same && let Some(p) = path() {
        save_to(&p, &host)?;
    }
    let changed = roots::set_host(host);
    Ok(json!({"certs": certs, "distrusted": distrusted, "changed": changed}))
}

/// Atomically writes `host` to `p` with mode `0600`, refusing to write through
/// any pre-existing symlink at the temp path or destination.
fn save_to(p: &Path, host: &Host) -> io::Result<()> {
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = p.with_extension("json.tmp");
    // A stale temp file, or a link put there, is not written through.
    let _ = std::fs::remove_file(&tmp);
    let bytes = to_json(host).to_string();
    if let Err(e) = write_private(&tmp, bytes.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, p) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// A new file only this user can read or write, whatever the umask (the
/// daemon's unit may run with 0027, a shell with 022).
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// The kept file's JSON, if it is a regular file (not a symlink or FIFO) of a
/// sane size.
fn read_kept(p: &Path) -> io::Result<Value> {
    read_kept_limit(p, MAX_FILE)
}

fn read_kept_limit(p: &Path, limit: u64) -> io::Result<Value> {
    use std::os::unix::fs::OpenOptionsExt;
    // O_NOFOLLOW refuses symlinks; O_NONBLOCK opens a FIFO without waiting for
    // a writer so fstat on the open descriptor rejects non-regular files with
    // no TOCTOU race.
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(p)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    let mut text = Vec::new();
    f.take(limit.saturating_add(1)).read_to_end(&mut text)?;
    if text.len() as u64 > limit {
        return Err(io::Error::other("host-roots.json is too large"));
    }
    serde_json::from_slice(&text).map_err(io::Error::other)
}

/// The roots kept from the last time, if any: read at start, before the
/// first pull.
pub fn load() {
    if !in_wsl() {
        return;
    }
    let Some(p) = path() else { return };
    // Never over roots kiri-win has sent this run already (checked atomically
    // under the host-roots lock).
    if let Ok(v) = read_kept(&p) {
        roots::set_host_if_unset(parse(&v));
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
    fn the_kept_roots_are_private_whatever_the_umask() {
        use std::os::unix::fs::PermissionsExt;
        const CHILD: &str = "KIRI_TEST_HOSTROOTS_UMASK_DIR";
        if let Some(d) = std::env::var_os(CHILD) {
            let d = Path::new(&d);
            for (i, mask) in [0o000, 0o022, 0o077].into_iter().enumerate() {
                let f = d.join(format!("host-roots-{i}.json.tmp"));
                // SAFETY: umask only changes this process's file-creation mask,
                // and this child process runs this test alone.
                unsafe { libc::umask(mask) };
                write_private(&f, b"{}").unwrap();
            }
            return;
        }
        let d = std::env::temp_dir().join(format!("kiri-hostroots-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let name = "daemon::hostroots::tests::the_kept_roots_are_private_whatever_the_umask";
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--test-threads=1"])
            .env(CHILD, &d)
            .output()
            .unwrap();
        assert!(child.status.success(), "{}", String::from_utf8_lossy(&child.stdout));
        for i in 0..3 {
            let f = d.join(format!("host-roots-{i}.json.tmp"));
            assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_is_not_opened_as_the_kept_roots() {
        let d = std::env::temp_dir().join(format!("kiri-hostroots-fifo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let fifo = d.join("host-roots.json");
        assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        assert!(read_kept(&fifo).unwrap_err().to_string().contains("regular"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_not_followed_when_reading_or_writing_kept_roots() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("kiri-hostroots-symlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let victim = d.join("victim.json");
        std::fs::write(&victim, r#"{"certs":["3001"],"distrusted":[]}"#).unwrap();
        let link = d.join("host-roots.json");
        let tmp_link = d.join("host-roots.json.tmp");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        std::os::unix::fs::symlink(&victim, &tmp_link).unwrap();

        // Reading refuses a symlink.
        assert!(read_kept(&link).is_err());

        // Saving removes the temp symlink and atomically replaces the target
        // symlink with a 0600 regular file without modifying the victim.
        let host = parse(&json!({"certs": ["3002"], "distrusted": []}));
        save_to(&link, &host).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), r#"{"certs":["3001"],"distrusted":[]}"#);
        let meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(meta.file_type().is_file());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(parse(&read_kept(&link).unwrap()), host);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_oversized_kept_roots_file_is_rejected() {
        let d = std::env::temp_dir().join(format!("kiri-hostroots-size-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("host-roots.json");
        std::fs::write(&f, format!(r#"{{"certs":["{}"],"distrusted":[]}}"#, "00".repeat(64))).unwrap();
        assert!(read_kept_limit(&f, 64).unwrap_err().to_string().contains("too large"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_body_without_lists_is_no_roots() {
        assert_eq!(parse(&json!({})), Host::default());
    }
}
