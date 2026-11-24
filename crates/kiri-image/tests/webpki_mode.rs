//! `KIRI_TLS_ROOTS=webpki` keeps the bundled Mozilla set alone, reading
//! nothing from the platform store (or `SSL_CERT_FILE`), exporting nothing
//! to WSL, and ignoring any host roots sent via `set_host` (#303).
//! Its own binary: `MODE` and `ROOTS` are read once per process.

use kiri_image::roots::{Host, bundled, host_export, set_host, trusted};

#[test]
fn kiri_tls_roots_webpki_uses_only_the_bundled_roots() {
    let ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = ca.self_signed(&key).unwrap();
    let file = std::env::temp_dir().join(format!(
        "kiri-roots-webpki-{}.pem",
        std::process::id()
    ));
    std::fs::write(&file, cert.pem()).unwrap();
    // SAFETY: the only test in this binary, so nothing else reads the
    // environment meanwhile.
    unsafe {
        std::env::set_var("KIRI_TLS_ROOTS", "webpki");
        std::env::set_var("SSL_CERT_FILE", &file);
        std::env::remove_var("SSL_CERT_DIR");
    }

    let got = trusted();
    assert_eq!(got.len(), bundled().len());
    assert!(got.iter().zip(bundled()).all(|(a, b)| a.as_ref() == b.as_ref()));

    // host_export reads nothing from the system when webpki-only is set.
    assert_eq!(host_export(), Host::default());

    // Even after set_host adds a CA and distrusts a bundled root, trusted()
    // keeps the bundled set intact while KIRI_TLS_ROOTS=webpki is active.
    assert!(set_host(Host {
        certs: vec![cert.der().clone()],
        distrusted: vec![bundled()[0].clone()],
    }));
    let after = trusted();
    assert_eq!(after.len(), bundled().len());
    assert!(after.iter().zip(bundled()).all(|(a, b)| a.as_ref() == b.as_ref()));

    unsafe {
        std::env::remove_var("KIRI_TLS_ROOTS");
        std::env::remove_var("SSL_CERT_FILE");
    }
    let _ = std::fs::remove_file(&file);
}
