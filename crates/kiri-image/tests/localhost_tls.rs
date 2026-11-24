//! `share` accepts a self-signed CA once it is trusted, and rejects the
//! same server before that: the merged roots, handed to a ureq agent
//! through [`kiri_image::tls_config`], are what decide (#303).
//! This lives outside the crate because it spins a live TLS server and
//! agents, not because the crate needs anything but its own roots.

use kiri_image::roots::{Mode, merge, trusted};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, SanType,
};
use rustls::pki_types::CertificateDer;

/// An agent on the bundled set alone rejects the self-signed server, so
/// does an agent on the merged roots without the CA, and the merged roots
/// with the CA added accept it.
#[test]
fn self_signed_localhost_is_rejected_by_default_and_accepted_once_added() {
    let (port, ca) = localhost_tls_server();
    let url = format!("https://127.0.0.1:{port}/");

    let agent_on = |roots: &[CertificateDer<'static>]| {
        ureq::Agent::config_builder()
            .timeout_connect(Some(std::time::Duration::from_secs(5)))
            .tls_config(kiri_image::tls_config(roots))
            .build()
            .into()
    };
    let accepted = |agent: ureq::Agent| {
        let mut resp = agent
            .get(&url)
            .call()
            .expect("merged store accepts the self-signed CA");
        resp.body_mut()
            .with_config()
            .limit(64 << 10)
            .read_to_string()
            .unwrap()
    };
    let rejected = |agent: ureq::Agent| {
        assert!(
            agent.get(&url).call().is_err(),
            "the agent must reject the self-signed CA"
        );
    };

    // Without the CA: the bundled set alone (what `KIRI_TLS_ROOTS=webpki`
    // keeps, and all Kiri had before #303) and the merged store.
    rejected(agent_on(&merge(
        Mode::BundledOnly,
        Vec::new,
        webpki_root_certs::TLS_SERVER_ROOT_CERTS,
    )));
    rejected(agent_on(&trusted()));

    // With the CA among the merged roots.
    let mut certs = trusted().to_vec();
    certs.push(ca.der().clone());
    assert_eq!(accepted(agent_on(&certs)), "ok");
}

/// The bundled roots, being full certificates, sit in a rustls root store
/// as they are: subject, public key and name constraints are the
/// certificate's own, so nothing is rebuilt around them.
#[test]
fn the_bundled_roots_load_into_a_root_store_unchanged() {
    let mut store = rustls::RootCertStore::empty();
    store.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.to_vec());
    assert_eq!(store.len(), webpki_root_certs::TLS_SERVER_ROOT_CERTS.len());
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
    p.subject_alt_names = vec![
        SanType::DnsName("localhost".to_owned().try_into().unwrap()),
        SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1])),
    ];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = p
        .signed_by(&server_key, &Issuer::new(ca_params, ca_key))
        .unwrap();

    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der());
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![
                CertificateDer::from(server_cert.der().to_vec()),
                CertificateDer::from(ca.der().to_vec()),
            ],
            key.into(),
        )
        .unwrap();
    let config = std::sync::Arc::new(config);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        // The test makes a handful of connections (the ones it expects
        // to be rejected dial too); serve a few more than that.
        for _ in 0..8 {
            let Ok((sock, _)) = listener.accept() else {
                return;
            };
            let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(10)));
            let Ok(conn) = rustls::ServerConnection::new(config.clone()) else {
                continue;
            };
            // Reads and writes complete the handshake as they go.
            let mut stream = rustls::StreamOwned::new(conn, sock);
            let mut buf = [0u8; 4096];
            let _ = std::io::Read::read(&mut stream, &mut buf);
            if std::io::Write::write_all(
                &mut stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            )
            .is_ok()
            {
                let _ = std::io::Write::flush(&mut stream);
            }
        }
    });
    (port, ca)
}
