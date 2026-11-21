//! The roots every outbound TLS connection trusts: the system's own store
//! (the macOS keychain trust settings, the Windows store, `/etc/ssl` on
//! Linux) merged with the Mozilla set Kiri bundles. A company root CA the
//! system trusts then works for pulls, logins and Share (#303), and a
//! Linux host without `ca-certificates` still reaches Docker Hub.
//!
//! `SSL_CERT_FILE` and `SSL_CERT_DIR` are honoured on every platform, like
//! curl and OpenSSL: when either is set, [`system`] reads the certificates
//! from there instead of the platform store. The bundled roots stay in.
//!
//! A root the administrator distrusted stays out even though the bundled
//! set has it: "Never Trust" in the user or admin trust settings on macOS,
//! the Disallowed store on Windows. Linux has no such list to read (a root
//! is distrusted there by taking it out of the bundle), so a Mozilla root
//! removed from `/etc/ssl` is still trusted through the bundled set.
//!
//! On Windows the engine runs in WSL, away from the Windows store: kiri-win
//! sends the daemon the Windows roots the bundled set lacks and the
//! Disallowed list ([`host_export`]), and the daemon adds them
//! ([`set_host`]), so a company root works for pulls as on the Mac.
//!
//! Self-contained on purpose: kiri-win compiles this file by path, as it
//! does share.rs, without depending on kiri-image. Nothing here may name
//! ureq or rustls, only the crates kiri-win has for it (design after
//! brunoselvacj's, issue #303).

use std::panic::{self, UnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use rustls_pki_types::CertificateDer;

/// Which roots to trust, from `KIRI_TLS_ROOTS`. The variable is read when
/// the roots are built, not at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The system's store and the bundled set: the default.
    Merged,
    /// The bundled set only, as it was before the system store was read:
    /// `KIRI_TLS_ROOTS=webpki`, for a system store that causes trouble.
    BundledOnly,
}

/// The mode `var` (an environment lookup) asks for. Every value other than
/// `webpki` — including an unset variable — keeps the merged roots.
pub fn mode(var: impl Fn(&str) -> Option<String>) -> Mode {
    match var("KIRI_TLS_ROOTS").as_deref() {
        Some("webpki") => Mode::BundledOnly,
        _ => Mode::Merged,
    }
}

/// The roots to trust: `platform`'s, unless `mode` leaves them out, then
/// `bundled`. `platform` is only called when its roots are used.
pub fn merge(
    mode: Mode,
    platform: impl FnOnce() -> Vec<CertificateDer<'static>>,
    bundled: &[CertificateDer<'static>],
) -> Vec<CertificateDer<'static>> {
    let mut roots = match mode {
        Mode::Merged => platform(),
        Mode::BundledOnly => Vec::new(),
    };
    roots.extend(bundled.iter().cloned());
    roots
}

/// The Mozilla set Kiri bundles.
pub fn bundled() -> &'static [CertificateDer<'static>] {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
}

/// `roots` without any certificate in `distrusted` (the same DER).
pub fn without(
    mut roots: Vec<CertificateDer<'static>>,
    distrusted: &[CertificateDer<'static>],
) -> Vec<CertificateDer<'static>> {
    if !distrusted.is_empty() {
        roots.retain(|c| !distrusted.contains(c));
    }
    roots
}

/// The roots a Windows host adds to the engine in WSL: the Windows store's
/// roots that the bundled set lacks (a company root, among them), and the
/// ones its administrator distrusted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Host {
    pub certs: Vec<CertificateDer<'static>>,
    pub distrusted: Vec<CertificateDer<'static>>,
}

/// The most certificates a [`Host`] list may hold, and the largest one.
pub const HOST_MAX_CERTS: usize = 1024;
pub const HOST_MAX_CERT_BYTES: usize = 16 << 10;

impl Host {
    /// The lists, each certificate as hex (JSON has no bytes), dropping
    /// what is past the caps.
    pub fn from_hex<'a>(
        certs: impl IntoIterator<Item = &'a str>,
        distrusted: impl IntoIterator<Item = &'a str>,
    ) -> Host {
        let read = |list: &mut dyn Iterator<Item = &'a str>| {
            list.filter(|h| h.len() <= HOST_MAX_CERT_BYTES * 2)
                .filter_map(unhex)
                .filter(|der| !der.is_empty())
                .map(CertificateDer::from)
                .take(HOST_MAX_CERTS)
                .collect::<Vec<_>>()
        };
        Host {
            certs: read(&mut certs.into_iter()),
            distrusted: read(&mut distrusted.into_iter()),
        }
    }
}

/// `der` as lowercase hex.
pub fn hex(der: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(der.len() * 2);
    for b in der {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 15)] as char);
    }
    s
}

/// The bytes `s` spells in hex, or none if it is not hex.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    b.chunks(2).map(|p| Some(digit(p[0])? << 4 | digit(p[1])?)).collect()
}

/// `base` with a host's roots: its certificates added, and every
/// certificate it distrusts taken out, its own included.
pub fn with_host(base: &[CertificateDer<'static>], host: &Host) -> Vec<CertificateDer<'static>> {
    let mut roots = base.to_vec();
    roots.extend(host.certs.iter().filter(|c| !base.contains(c)).cloned());
    without(roots, &host.distrusted)
}

/// This process's mode, read once with its roots.
fn mode_now() -> Mode {
    static MODE: OnceLock<Mode> = OnceLock::new();
    *MODE.get_or_init(|| mode(|k| std::env::var(k).ok()))
}

/// The roots from this machine, read once on first use: reading the macOS
/// keychain asks Security.framework about each certificate.
fn base() -> &'static Arc<[CertificateDer<'static>]> {
    static ROOTS: OnceLock<Arc<[CertificateDer<'static>]>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let mode = mode_now();
        let roots = merge(mode, || guarded(system), bundled());
        match mode {
            Mode::Merged => without(roots, &guarded(distrusted_by_system)),
            Mode::BundledOnly => roots,
        }
        .into()
    })
}

/// A host's roots as last set, with the list they make.
static HOST: Mutex<Option<(Host, Arc<[CertificateDer<'static>]>)>> = Mutex::new(None);
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// Takes a host's roots (from kiri-win), and says whether that changed the
/// roots. `KIRI_TLS_ROOTS=webpki` keeps the bundled set alone, so then
/// they are kept but not used.
pub fn set_host(host: Host) -> bool {
    let mut slot = HOST.lock().unwrap_or_else(|e| e.into_inner());
    if slot.as_ref().is_some_and(|(h, _)| *h == host) {
        return false;
    }
    let roots = with_host(base(), &host).into();
    *slot = Some((host, roots));
    GENERATION.fetch_add(1, Ordering::SeqCst);
    true
}

/// A host's roots as last set, if any.
pub fn host() -> Option<Host> {
    HOST.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|(h, _)| h.clone())
}

/// Counts the changes [`set_host`] made, so a client built on [`trusted`]
/// knows to build again.
pub fn generation() -> u64 {
    GENERATION.load(Ordering::SeqCst)
}

/// The roots to trust: this machine's (read once), with a host's.
pub fn trusted() -> Arc<[CertificateDer<'static>]> {
    let base = base();
    if mode_now() == Mode::BundledOnly {
        return base.clone();
    }
    match HOST.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
        Some((_, roots)) => roots.clone(),
        None => base.clone(),
    }
}

/// What this machine adds to the engine in WSL (kiri-win's side of
/// [`set_host`]): the store's roots the bundled set lacks, and the ones
/// distrusted. Nothing with `KIRI_TLS_ROOTS=webpki`.
pub fn host_export() -> Host {
    if mode_now() == Mode::BundledOnly {
        return Host::default();
    }
    let bundled = bundled();
    let mut certs: Vec<_> = guarded(system).into_iter().filter(|c| !bundled.contains(c)).collect();
    certs.truncate(HOST_MAX_CERTS);
    let mut distrusted = guarded(distrusted_by_system);
    distrusted.truncate(HOST_MAX_CERTS);
    Host { certs, distrusted }
}

/// The roots the administrator distrusted on macOS: "Never Trust" in the
/// user or admin trust settings, a user's setting first, as macOS weighs
/// them. Only those domains: they hold the few certificates someone set,
/// where the system domain would mean asking about every root again.
#[cfg(target_os = "macos")]
fn distrusted_by_system() -> Vec<CertificateDer<'static>> {
    use security_framework::trust_settings::{Domain, TrustSettings, TrustSettingsForCertificate};
    let mut seen: Vec<(Vec<u8>, bool)> = Vec::new();
    for domain in [Domain::User, Domain::Admin] {
        let ts = TrustSettings::new(domain);
        let Ok(iter) = ts.iter() else { continue };
        for cert in iter {
            let der = cert.to_der();
            if seen.iter().any(|(d, _)| *d == der) {
                continue;
            }
            let denied = matches!(
                ts.tls_trust_settings_for_certificate(&cert),
                Ok(Some(TrustSettingsForCertificate::Deny))
            );
            seen.push((der, denied));
        }
    }
    seen.into_iter().filter(|(_, denied)| *denied).map(|(der, _)| CertificateDer::from(der)).collect()
}

/// The roots the administrator distrusted on Windows: the current user's
/// Disallowed store, which takes in the machine's and Group Policy's.
#[cfg(windows)]
fn distrusted_by_system() -> Vec<CertificateDer<'static>> {
    match schannel::cert_store::CertStore::open_current_user("Disallowed") {
        Ok(store) => store.certs().map(|c| CertificateDer::from(c.to_der().to_vec())).collect(),
        Err(_) => Vec::new(),
    }
}

/// Linux keeps no list of distrusted roots (see the module comment).
#[cfg(not(any(target_os = "macos", windows)))]
fn distrusted_by_system() -> Vec<CertificateDer<'static>> {
    Vec::new()
}

/// `load`'s roots, or none if it panics (rustls-native-certs unwraps on
/// Windows), so a broken store costs the system roots, not the process.
fn guarded(
    load: impl FnOnce() -> Vec<CertificateDer<'static>> + UnwindSafe,
) -> Vec<CertificateDer<'static>> {
    panic::catch_unwind(load).unwrap_or_else(|_| {
        eprintln!(
            "kiri: reading the system certificate store failed; trusting the bundled roots only"
        );
        Vec::new()
    })
}

/// The system's roots. With `SSL_CERT_FILE` or `SSL_CERT_DIR` set,
/// rustls-native-certs reads those instead of the store, as OpenSSL does;
/// say so, as a company CA in the keychain is then not trusted.
fn system() -> Vec<CertificateDer<'static>> {
    let set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
    if set("SSL_CERT_FILE") || set("SSL_CERT_DIR") {
        eprintln!(
            "kiri: SSL_CERT_FILE or SSL_CERT_DIR is set, so the system certificate store is not read"
        );
    }
    let found = rustls_native_certs::load_native_certs();
    for e in &found.errors {
        eprintln!("kiri: system certificates: {e}");
    }
    found.certs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn cert(byte: u8) -> CertificateDer<'static> {
        CertificateDer::from(vec![byte])
    }

    #[test]
    fn merges_the_system_roots_with_the_bundled_roots_by_default() {
        let got = merge(Mode::Merged, || vec![cert(1)], &[cert(2)]);

        assert_eq!(got, vec![cert(1), cert(2)]);
    }

    #[test]
    fn kiri_tls_roots_webpki_selects_the_bundled_roots_only() {
        let got = mode(|_| Some("webpki".into()));

        assert_eq!(got, Mode::BundledOnly);
    }

    #[test]
    fn kiri_tls_roots_with_another_value_selects_the_merged_roots() {
        let got = mode(|_| Some("system".into()));

        assert_eq!(got, Mode::Merged);
    }

    #[test]
    fn kiri_tls_roots_unset_selects_the_merged_roots() {
        let got = mode(|_| None);

        assert_eq!(got, Mode::Merged);
    }

    #[test]
    fn keeps_the_bundled_roots_when_the_system_store_is_empty() {
        let got = merge(Mode::Merged, Vec::new, &[cert(2)]);

        assert_eq!(got, vec![cert(2)]);
    }

    #[test]
    fn bundled_only_mode_never_reads_the_system_store() {
        let read = Cell::new(false);

        let got = merge(
            Mode::BundledOnly,
            || {
                read.set(true);
                vec![cert(1)]
            },
            &[cert(2)],
        );

        assert!(!read.get());
        assert_eq!(got, vec![cert(2)]);
    }

    #[test]
    fn keeps_the_bundled_roots_when_reading_the_system_store_panics() {
        let got = merge(
            Mode::Merged,
            || guarded(|| panic!("broken store")),
            &[cert(2)],
        );

        assert_eq!(got, vec![cert(2)]);
    }

    #[test]
    fn keeps_the_system_roots_when_reading_the_system_store_succeeds() {
        let got = guarded(|| vec![cert(1)]);

        assert_eq!(got, vec![cert(1)]);
    }

    #[test]
    fn the_bundled_set_is_not_empty() {
        assert!(!webpki_root_certs::TLS_SERVER_ROOT_CERTS.is_empty());
    }

    /// The merged list holds the bundled roots (real certificates now, not
    /// the bare anchors webpki-roots shipped) plus everything the platform
    /// store has (nothing on a bare container, hundreds on a desktop),
    /// less what the administrator distrusted.
    #[test]
    fn merged_roots_are_the_bundled_set_plus_the_platform_store() {
        // With these set the platform store is replaced or left out, so
        // the count below would not hold.
        let set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
        if set("SSL_CERT_FILE") || set("SSL_CERT_DIR") || mode(|k| std::env::var(k).ok()) != Mode::Merged {
            return;
        }
        let platform = rustls_native_certs::load_native_certs().certs;
        let expected = without(
            platform.into_iter().chain(bundled().iter().cloned()).collect(),
            &distrusted_by_system(),
        );
        assert_eq!(trusted().len(), expected.len());
    }

    #[test]
    fn a_distrusted_root_is_left_out_of_the_bundled_set_too() {
        let got = without(vec![cert(1), cert(2), cert(3)], &[cert(2)]);

        assert_eq!(got, vec![cert(1), cert(3)]);
    }

    #[test]
    fn a_hosts_roots_are_added_and_its_distrusted_ones_taken_out() {
        let host = Host { certs: vec![cert(4), cert(1)], distrusted: vec![cert(2), cert(4)] };

        let got = with_host(&[cert(1), cert(2), cert(3)], &host);

        assert_eq!(got, vec![cert(1), cert(3)]);
    }

    #[test]
    fn hex_goes_both_ways() {
        let der = (0..=255u8).collect::<Vec<_>>();

        assert_eq!(unhex(&hex(&der)).unwrap(), der);
        assert_eq!(unhex("0A"), Some(vec![10]));
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("zz"), None);
    }

    #[test]
    fn host_lists_drop_what_does_not_decode_and_what_is_past_the_caps() {
        let big = "00".repeat(HOST_MAX_CERT_BYTES + 1);
        let many = vec!["01"; HOST_MAX_CERTS + 5];

        let host = Host::from_hex(["0102", "nothex", "", big.as_str()], many.iter().copied());

        assert_eq!(host.certs, vec![CertificateDer::from(vec![1, 2])]);
        assert_eq!(host.distrusted.len(), HOST_MAX_CERTS);
    }
}
