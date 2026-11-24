//! `SSL_CERT_FILE` replaces the platform's roots for everything built on
//! [`kiri_image::roots`] (#303). The variable is read when the roots are
//! built, as with curl and OpenSSL, so a test can set it and see the
//! certificates come out. This lives outside the crate because the crate
//! forbids unsafe code and setting an environment variable is unsafe.

use kiri_image::roots::trusted;

/// The file's certificates replace the platform store, and the bundled
/// roots stay merged in.
#[test]
fn ssl_cert_file_replaces_the_platform_roots() {
    let ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = ca.self_signed(&key).unwrap();
    let file = std::env::temp_dir().join(format!(
        "kiri-roots-ssl-cert-file-{}.pem",
        std::process::id()
    ));
    std::fs::write(&file, cert.pem()).unwrap();
    // SAFETY: the only test in this binary, so nothing else reads the
    // environment meanwhile. KIRI_TLS_ROOTS=webpki would leave the file
    // out, and SSL_CERT_DIR would add its certificates to the file's.
    unsafe {
        std::env::remove_var("KIRI_TLS_ROOTS");
        std::env::remove_var("SSL_CERT_DIR");
        std::env::set_var("SSL_CERT_FILE", &file);
    }
    let certs = trusted();
    unsafe { std::env::remove_var("SSL_CERT_FILE") };
    let _ = std::fs::remove_file(&file);
    assert_eq!(
        certs.len(),
        webpki_root_certs::TLS_SERVER_ROOT_CERTS.len() + 1
    );
    // The file's certificate replaces the platform store at the front of
    // the merged list, the bundled roots unchanged after it. (No root the
    // administrator distrusted is in the bundled set on a test machine.)
    assert_eq!(certs.first().unwrap().as_ref(), cert.der().as_ref());
    assert!(
        certs[1..]
            .iter()
            .zip(webpki_root_certs::TLS_SERVER_ROOT_CERTS)
            .all(|(a, b)| a.as_ref() == b.as_ref())
    );
}
