//! The root certificate store registries, the update check and Kiri Share
//! verify against: the platform's own roots (the macOS keychain, the Windows
//! certificate store, `/etc/ssl` on Linux) merged with `webpki-roots`, so a
//! corporate root CA the machine trusts works out of the box (#303) and a
//! headless Linux without `ca-certificates` installed still pulls.
//!
//! `SSL_CERT_FILE` and `SSL_CERT_DIR` are honoured on every platform, like
//! curl and OpenSSL: when either is set, [`rustls_native_certs`] reads the
//! certificates from there instead of the platform store. webpki's roots
//! stay merged in.

/// The roots a TLS client verifies against, ready for ureq's
/// [`ureq::tls::RootCerts::Specific`]: webpki's Mozilla roots first, then
/// the platform's. Share seeds its `RootCertStore` from the same list.
pub fn root_certs() -> Vec<ureq::tls::Certificate<'static>> {
    let mut certs = webpki_anchors_as_certs();
    certs.extend(platform_certs());
    certs
}

/// The platform's certificates, or what `SSL_CERT_FILE` and `SSL_CERT_DIR`
/// name instead of them. Load errors are skipped: an unreadable keychain
/// entry or a missing file should not take every HTTPS call down.
fn platform_certs() -> Vec<ureq::tls::Certificate<'static>> {
    rustls_native_certs::load_native_certs()
        .certs
        .into_iter()
        .map(|der| ureq::tls::Certificate::from_der(der.as_ref()).to_owned())
        .collect()
}

/// webpki's root store as certificates. Its entries are bare trust anchors
/// (subject, public key, optional name constraints); a certificate is built
/// around each one so it can sit in a certificate list.
fn webpki_anchors_as_certs() -> Vec<ureq::tls::Certificate<'static>> {
    webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .map(|a| {
            let der = anchor_cert(
                a.subject.as_ref(),
                a.subject_public_key_info.as_ref(),
                a.name_constraints.as_ref().map(|d| d.as_ref()),
            );
            ureq::tls::Certificate::from_der(&der).to_owned()
        })
        .collect()
}

/// DER contents wrapped in a tag: short-form length up to 127, else a
/// length-of-length byte followed by the big-endian length.
fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match contents.len() {
        len @ ..0x80 => out.push(len as u8),
        len @ 0x80..=0xFF => out.extend([0x81, len as u8]),
        len @ 0x100..=65_535 => {
            let [hi, lo] = (len as u16).to_be_bytes();
            out.extend([0x80 | 2, hi, lo]);
        }
        len => {
            let bytes = (len as u32).to_be_bytes();
            let first = bytes.iter().position(|b| *b != 0).unwrap_or(3);
            out.push(0x80 | (4 - first) as u8);
            out.extend_from_slice(&bytes[first..]);
        }
    }
    out.extend_from_slice(contents);
    out
}

/// ecdsa-with-SHA256, the signature algorithm OID of the built certificates.
const ECDSA_WITH_SHA256: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

/// Builds a self-signed v3 certificate around a webpki trust anchor, so the
/// anchor can go wherever certificates are expected. Only the three fields
/// path building reads from a root are real (subject, public key, name
/// constraints); the rest is fixed filler, as nothing verifies a root's
/// signature or dates.
fn anchor_cert(subject: &[u8], spki: &[u8], name_constraints: Option<&[u8]>) -> Vec<u8> {
    // X.509 validity: two UTCTime values (RFC 5280 4.1.2.5).
    let mut validity = der(0x17, b"260101000000Z");
    validity.extend(der(0x17, b"460101000000Z"));
    let validity = der(0x30, &validity);

    // TBSCertificate contents: version (v3), serial, signature algorithm,
    // issuer, validity, subject, public key, extensions.
    let mut fields = der(0xA0, &der(0x02, &[2]));
    fields.extend(der(0x02, &[1]));
    fields.extend(der(0x30, &der(0x06, &ECDSA_WITH_SHA256)));
    let name = der(0x30, subject);
    fields.extend_from_slice(&name);
    fields.extend_from_slice(&validity);
    fields.extend_from_slice(&name); // issuer = subject: self-signed
    fields.extend_from_slice(&der(0x30, spki));

    // id-ce-basicConstraints 2.5.29.19, critical: cA true.
    let mut basic_constraints = der(0x06, &[0x55, 0x1D, 0x13]);
    basic_constraints.extend(der(0x01, &[0xFF]));
    basic_constraints.extend(der(0x04, &der(0x30, &der(0x01, &[0xFF]))));
    let mut extensions = vec![der(0x30, &basic_constraints)];
    if let Some(nc) = name_constraints {
        // id-ce-nameConstraints 2.5.29.30, critical. The anchor keeps the
        // extension value's SEQUENCE contents, without the SEQUENCE itself.
        let mut ext = der(0x06, &[0x55, 0x1D, 0x1E]);
        ext.extend(der(0x01, &[0xFF]));
        ext.extend(der(0x04, &der(0x30, nc)));
        extensions.push(der(0x30, &ext));
    }
    let extensions = der(0xA3, &der(0x30, &extensions.concat()));
    fields.extend_from_slice(&extensions);

    let tbs = der(0x30, &fields); // TBSCertificate is itself a SEQUENCE
    // Certificate: SEQUENCE of the TBS, the signature algorithm and the
    // signature value.
    let mut out = tbs;
    out.extend(der(0x30, &der(0x06, &ECDSA_WITH_SHA256)));
    // A signature nobody checks (a root's is never verified), but not an
    // empty one: parsers reject a BIT STRING with no unused-bits octet.
    out.extend(der(
        0x03,
        &[0, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5],
    ));
    der(0x30, &out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each webpki anchor, read back out of the certificate built around it:
    /// subject, public key and name constraints all survive.
    #[test]
    fn webpki_anchors_survive_the_certificate_round_trip() {
        let certs = root_certs();
        // webpki's come first, then the platform's (if the machine has any).
        assert!(certs.len() >= webpki_roots::TLS_SERVER_ROOTS.len());
        let mut store = rustls::RootCertStore::empty();
        for (cert, anchor) in certs.iter().zip(webpki_roots::TLS_SERVER_ROOTS.iter()) {
            store
                .add(rustls::pki_types::CertificateDer::from(cert.der().to_vec()))
                .unwrap();
            let back = store.roots.last().unwrap();
            assert_eq!(back.subject.as_ref(), anchor.subject.as_ref());
            assert_eq!(
                back.subject_public_key_info.as_ref(),
                anchor.subject_public_key_info.as_ref()
            );
            assert_eq!(
                back.name_constraints.as_ref().map(|d| d.as_ref()),
                anchor.name_constraints.as_ref().map(|d| d.as_ref())
            );
        }
    }

    /// The merged list is webpki's roots plus everything the platform
    /// store holds (nothing on a bare container, hundreds on a desktop).
    #[test]
    fn merged_roots_are_webpki_plus_the_platform_store() {
        // With the variables set the platform store is replaced, so the
        // count below would not hold.
        if std::env::var_os("SSL_CERT_FILE").is_some() || std::env::var_os("SSL_CERT_DIR").is_some()
        {
            return;
        }
        let certs = root_certs();
        let platform = rustls_native_certs::load_native_certs();
        assert_eq!(
            certs.len(),
            webpki_roots::TLS_SERVER_ROOTS.len() + platform.certs.len()
        );
    }

    /// A localhost server with a self-signed CA: the default agent (webpki
    /// roots only) rejects it, so does an agent on the merged roots alone,
    /// and the merged roots with the CA added accept it.
    #[test]
    fn self_signed_localhost_is_rejected_by_default_and_accepted_once_added() {
        let (port, ca) = localhost_tls_server();
        let url = format!("https://127.0.0.1:{port}/");

        let accepted = |certs: Vec<ureq::tls::Certificate<'static>>| {
            let tls = ureq::tls::TlsConfig::builder()
                .root_certs(ureq::tls::RootCerts::Specific(certs.into()))
                .build();
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .timeout_connect(Some(std::time::Duration::from_secs(5)))
                .tls_config(tls)
                .build()
                .into();
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

        // Without the CA: the default (webpki only) and the merged store.
        rejected(
            ureq::Agent::config_builder()
                .timeout_connect(Some(std::time::Duration::from_secs(5)))
                .build()
                .into(),
        );
        rejected(
            ureq::Agent::config_builder()
                .timeout_connect(Some(std::time::Duration::from_secs(5)))
                .tls_config(
                    ureq::tls::TlsConfig::builder()
                        .root_certs(ureq::tls::RootCerts::Specific(root_certs().into()))
                        .build(),
                )
                .build()
                .into(),
        );

        // With the CA among the merged roots.
        let mut certs = root_certs();
        certs.push(ureq::tls::Certificate::from_der(ca.der().as_ref()).to_owned());
        assert_eq!(accepted(certs), "ok");
    }

    /// A TLS server on localhost with a certificate for `127.0.0.1`, signed
    /// by a fresh self-signed CA. Returns the port and the CA certificate.
    fn localhost_tls_server() -> (u16, rcgen::Certificate) {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.clone().self_signed(&ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.subject_alt_names = vec![
            rcgen::SanType::DnsName("localhost".to_owned().try_into().unwrap()),
            rcgen::SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1])),
        ];
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let server_cert = p
            .signed_by(&server_key, &rcgen::Issuer::new(ca_params, ca_key))
            .unwrap();

        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der());
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![
                    rustls::pki_types::CertificateDer::from(server_cert.der().to_vec()),
                    rustls::pki_types::CertificateDer::from(ca.der().to_vec()),
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
}
