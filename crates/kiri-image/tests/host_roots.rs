//! A Windows host's roots in the engine (#303): kiri-win sends the daemon
//! in WSL the Windows store's roots the bundled set lacks and the ones the
//! administrator distrusted, and every agent built on
//! [`kiri_image::roots::trusted`] then trusts the first and refuses the
//! second. Its own binary: setting a host's roots changes the process's.

use kiri_image::roots::{Host, bundled, generation, set_host, trusted};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use rustls::pki_types::CertificateDer;

#[test]
fn a_hosts_root_is_trusted_and_its_distrusted_root_is_not() {
    // KIRI_TLS_ROOTS=webpki keeps the bundled set alone, on purpose.
    if std::env::var("KIRI_TLS_ROOTS").as_deref() == Ok("webpki") {
        return;
    }
    let (port, ca) = localhost_tls_server();
    let url = format!("https://127.0.0.1:{port}/");
    let agent = || -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_connect(Some(std::time::Duration::from_secs(5)))
            .tls_config(kiri_image::tls_config(&trusted()))
            .build()
            .into()
    };
    assert!(agent().get(&url).call().is_err(), "a root nobody sent is not trusted");

    let distrusted = bundled()[0].clone();
    let before = generation();
    let host = Host { certs: vec![ca.der().clone()], distrusted: vec![distrusted.clone()] };
    assert!(set_host(host.clone()));
    assert_eq!(generation(), before + 1, "agents built on the roots know to build again");
    assert!(!set_host(host), "the same roots again change nothing");
    assert_eq!(generation(), before + 1);

    let roots = trusted();
    assert!(roots.contains(&CertificateDer::from(ca.der().to_vec())));
    assert!(!roots.contains(&distrusted), "a root the host distrusted is out, bundled or not");
    assert_eq!(agent().get(&url).call().unwrap().body_mut().read_to_string().unwrap(), "ok");
}

/// A TLS server on localhost with a certificate for `127.0.0.1`, signed
/// by a fresh self-signed CA. Returns the port and the CA certificate.
fn localhost_tls_server() -> (u16, rcgen::Certificate) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.clone().self_signed(&ca_key).unwrap();
    let server_key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.subject_alt_names = vec![SanType::IpAddress("127.0.0.1".parse().unwrap())];
    let server = p.signed_by(&server_key, &Issuer::new(ca_params, &ca_key)).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![server.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(server_key.serialize_der().into()),
        )
        .unwrap();
    let config = std::sync::Arc::new(config);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let config = config.clone();
            std::thread::spawn(move || {
                use std::io::{Read, Write};
                let mut conn = rustls::ServerConnection::new(config).unwrap();
                let mut stream = stream;
                let mut tls = rustls::Stream::new(&mut conn, &mut stream);
                let mut buf = [0u8; 4096];
                if tls.read(&mut buf).is_ok() {
                    let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                    let _ = tls.flush();
                }
            });
        }
    });
    (port, ca)
}
