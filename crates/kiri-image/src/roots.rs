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
//! Self-contained on purpose: kiri-win compiles this file by path, as it
//! does share.rs, without depending on kiri-image. Nothing here may name
//! ureq or rustls, only the crates kiri-win has for it (design after
//! brunoselvacj's, issue #303).

use std::panic::{self, UnwindSafe};
use std::sync::OnceLock;

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

/// The process's roots, read once on first use: reading the macOS keychain
/// asks Security.framework about each certificate.
pub fn trusted() -> &'static [CertificateDer<'static>] {
    static ROOTS: OnceLock<Vec<CertificateDer<'static>>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        merge(
            mode(|k| std::env::var(k).ok()),
            || guarded(system),
            webpki_root_certs::TLS_SERVER_ROOT_CERTS,
        )
    })
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
    /// store has (nothing on a bare container, hundreds on a desktop).
    #[test]
    fn merged_roots_are_the_bundled_set_plus_the_platform_store() {
        // With the variables set the platform store is replaced, so the
        // count below would not hold.
        if std::env::var_os("SSL_CERT_FILE").is_some() || std::env::var_os("SSL_CERT_DIR").is_some()
        {
            return;
        }
        assert_eq!(
            trusted().len(),
            webpki_root_certs::TLS_SERVER_ROOT_CERTS.len()
                + rustls_native_certs::load_native_certs().certs.len()
        );
    }
}
