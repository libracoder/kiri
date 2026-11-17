//! `SSL_CERT_FILE` replaces the platform's roots for everything built on
//! [`kiri_image::roots`] (#303). The variable is read when the roots are
//! built, as with curl and OpenSSL, so a test can set it and see the
//! certificates come out. This lives outside the crate because the crate
//! forbids unsafe code and setting an environment variable is unsafe.

use kiri_image::roots::root_certs;

/// The file's certificates replace the platform store, and webpki's roots
/// stay merged in.
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
    // SAFETY: no other test in this binary reads or writes the variable.
    unsafe { std::env::set_var("SSL_CERT_FILE", &file) };
    let certs = root_certs();
    unsafe { std::env::remove_var("SSL_CERT_FILE") };
    let _ = std::fs::remove_file(&file);
    assert_eq!(certs.len(), webpki_roots::TLS_SERVER_ROOTS.len() + 1);
    // The file's certificate is the last of the merged list, after
    // webpki's; the platform store contributed none.
    assert_eq!(certs.last().unwrap().der(), cert.der().as_ref());
}
