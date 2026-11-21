//! `kiri build --ssh`: the agents the client forwards to a build, as
//! buildx forwards them (BuildKit session/sshforward).
//!
//! `--ssh id=<socket>` (or `$SSH_AUTH_SOCK` with no path) is an agent the
//! client reaches; `--ssh id=<key file>[,<key file>…]` are keys this client
//! serves from an agent of its own, as buildx keeps them in one. Either way
//! a step may do two things only, list the keys and ask for a signature:
//! anything else (adding or removing keys, locking, extensions such as a
//! PKCS#11 load, unknown types) gets SSH_AGENT_FAILURE, so a step can use
//! the keys but never read them out or change the agent.
//!
//! A socket agent is the user's own, so the step never talks to it
//! directly: a filter in this client (as BuildKit's `readOnlyAgent`) reads
//! each request frame whole (at most 256 KiB; a longer, empty or cut-short
//! frame closes the connection), passes on list and sign requests only and
//! answers everything else itself without passing it on. Pipelined
//! requests are read and filtered one at a time; no byte reaches the agent
//! that the filter has not parsed.
//!
//! The engine never opens an agent by a path: the client holds one
//! connection to it for the build (`POST /kiri/build/ssh`, then raw), and
//! for each connection a step makes to its agent socket the engine writes
//! the id as a line and the client answers with one byte, `1` with the
//! descriptor of a fresh connection to that agent (SCM_RIGHTS), or `0`
//! with none. The engine relays that connection to the step and closes it
//! when either side does.

use std::collections::BTreeMap;
use std::io::{self, BufRead as _, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _, RsaKeyPair};

/// Requests and answers (draft-miller-ssh-agent).
const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const RSA_SHA2_256: u32 = 2;
const RSA_SHA2_512: u32 = 4;
/// A request larger than this is not an agent request (OpenSSH's own
/// agent takes at most 256 KiB).
const MAX_MESSAGE: usize = 256 << 10;

/// A private key the agent signs with.
pub enum Key {
    Ed25519(Ed25519KeyPair),
    Rsa(RsaKeyPair),
    Ecdsa(EcdsaKeyPair, Curve),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
}

impl Curve {
    fn name(self) -> &'static str {
        match self {
            Curve::P256 => "nistp256",
            Curve::P384 => "nistp384",
        }
    }

    fn signing(self) -> &'static signature::EcdsaSigningAlgorithm {
        match self {
            Curve::P256 => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            Curve::P384 => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        }
    }

    fn scalar_len(self) -> usize {
        match self {
            Curve::P256 => 32,
            Curve::P384 => 48,
        }
    }

    fn from_name(n: &[u8]) -> Option<Curve> {
        match n {
            b"nistp256" => Some(Curve::P256),
            b"nistp384" => Some(Curve::P384),
            _ => None,
        }
    }

    /// The curve's OID as DER contents (prime256v1, secp384r1).
    fn from_oid(oid: &[u8]) -> Option<Curve> {
        match oid {
            [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => Some(Curve::P256),
            [0x2b, 0x81, 0x04, 0x00, 0x22] => Some(Curve::P384),
            _ => None,
        }
    }
}

impl Key {
    /// The public key as the SSH wire format writes it (`ssh-add -L`).
    pub fn blob(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Key::Ed25519(k) => {
                put_string(&mut b, b"ssh-ed25519");
                put_string(&mut b, k.public_key().as_ref());
            }
            Key::Rsa(k) => {
                let c: signature::RsaPublicKeyComponents<Vec<u8>> = k.public().into();
                put_string(&mut b, b"ssh-rsa");
                put_mpint(&mut b, &c.e);
                put_mpint(&mut b, &c.n);
            }
            Key::Ecdsa(k, c) => {
                put_string(&mut b, format!("ecdsa-sha2-{}", c.name()).as_bytes());
                put_string(&mut b, c.name().as_bytes());
                put_string(&mut b, k.public_key().as_ref());
            }
        }
        b
    }

    /// The signature of `data` as SSH writes it, or None for one this
    /// agent does not make (`ssh-rsa` with SHA-1: OpenSSH has asked for
    /// SHA-2 since 7.2).
    fn sign(&self, data: &[u8], flags: u32) -> Option<Vec<u8>> {
        let rng = SystemRandom::new();
        let mut out = Vec::new();
        match self {
            Key::Ed25519(k) => {
                put_string(&mut out, b"ssh-ed25519");
                put_string(&mut out, k.sign(data).as_ref());
            }
            Key::Rsa(k) => {
                // SHA-256 when both are asked for, as OpenSSH's agent picks.
                let (name, alg): (&[u8], &'static dyn signature::RsaEncoding) = if flags & RSA_SHA2_256 != 0 {
                    (b"rsa-sha2-256", &signature::RSA_PKCS1_SHA256)
                } else if flags & RSA_SHA2_512 != 0 {
                    (b"rsa-sha2-512", &signature::RSA_PKCS1_SHA512)
                } else {
                    return None;
                };
                let mut sig = vec![0; k.public().modulus_len()];
                k.sign(alg, &rng, data, &mut sig).ok()?;
                put_string(&mut out, name);
                put_string(&mut out, &sig);
            }
            Key::Ecdsa(k, c) => {
                let sig = k.sign(&rng, data).ok()?;
                let (r, s) = sig.as_ref().split_at(c.scalar_len());
                let mut inner = Vec::new();
                put_mpint(&mut inner, r);
                put_mpint(&mut inner, s);
                put_string(&mut out, format!("ecdsa-sha2-{}", c.name()).as_bytes());
                put_string(&mut out, &inner);
            }
        }
        Some(out)
    }
}

/// The answer to one request (its type byte and contents, without the
/// length).
fn answer(keys: &[Key], req: &[u8]) -> Vec<u8> {
    let fail = vec![FAILURE];
    match req.split_first() {
        Some((&REQUEST_IDENTITIES, _)) => {
            let mut out = vec![IDENTITIES_ANSWER];
            out.extend_from_slice(&(keys.len() as u32).to_be_bytes());
            for k in keys {
                put_string(&mut out, &k.blob());
                // buildx adds its keys without a comment
                put_string(&mut out, b"");
            }
            out
        }
        Some((&SIGN_REQUEST, rest)) => {
            let mut r = Reader(rest);
            let (Some(blob), Some(data), Some(flags)) = (r.string(), r.string(), r.u32()) else { return fail };
            let Some(key) = keys.iter().find(|k| k.blob() == blob) else { return fail };
            match key.sign(data, flags) {
                Some(sig) => {
                    let mut out = vec![SIGN_RESPONSE];
                    put_string(&mut out, &sig);
                    out
                }
                None => fail,
            }
        }
        _ => fail,
    }
}

/// Requests on one connection until the client closes it.
fn converse(keys: &[Key], mut c: UnixStream) -> io::Result<()> {
    while let Some(req) = read_frame(&mut c)? {
        write_frame(&mut c, &answer(keys, &req))?;
    }
    Ok(())
}

/// One agent message, whole: None when the stream ends before one starts;
/// an error for one that is empty, over [`MAX_MESSAGE`] or cut short.
fn read_frame(c: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0; 4];
    let mut got = 0;
    while got < 4 {
        match c.read(&mut len[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_MESSAGE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not an agent message"));
    }
    let mut m = vec![0; len];
    c.read_exact(&mut m)?;
    Ok(Some(m))
}

fn write_frame(c: &mut UnixStream, m: &[u8]) -> io::Result<()> {
    let mut msg = Vec::with_capacity(4 + m.len());
    msg.extend_from_slice(&(m.len() as u32).to_be_bytes());
    msg.extend_from_slice(m);
    c.write_all(&msg)
}

/// A step's requests to the user's agent at `agent`, filtered: list and
/// sign requests go on and their answers come back; anything else is
/// answered with SSH_AGENT_FAILURE here and never sent. Ends, closing both
/// connections, when either side ends or sends a bad frame.
fn filter(mut step: UnixStream, mut agent: UnixStream) -> io::Result<()> {
    while let Some(req) = read_frame(&mut step)? {
        let a = if matches!(req[0], REQUEST_IDENTITIES | SIGN_REQUEST) {
            write_frame(&mut agent, &req)?;
            match read_frame(&mut agent)? {
                Some(a) => a,
                None => return Ok(()),
            }
        } else {
            vec![FAILURE]
        };
        write_frame(&mut step, &a)?;
    }
    Ok(())
}

// ---------------------------------------------------------------- keys

/// A private key file as buildx reads one (x/crypto/ssh
/// `ParseRawPrivateKey`): OpenSSH's own format, PEM PKCS#1 RSA, SEC 1 EC,
/// or PKCS#8. The errors are its words.
pub fn parse_key(file: &[u8]) -> Result<Key, String> {
    let (label, headers, der) = pem(file).ok_or("ssh: no key found")?;
    if headers.iter().any(|h| h.starts_with("Proc-Type") && h.contains("ENCRYPTED")) || label == "ENCRYPTED PRIVATE KEY" {
        return Err("ssh: this private key is passphrase protected".into());
    }
    let rejected = |e: ring::error::KeyRejected| format!("ssh: {e}");
    match label.as_str() {
        "RSA PRIVATE KEY" => RsaKeyPair::from_der(&der).map(Key::Rsa).map_err(rejected),
        "EC PRIVATE KEY" => sec1(&der),
        "PRIVATE KEY" => pkcs8(&der),
        "OPENSSH PRIVATE KEY" => openssh(&der),
        other => Err(format!("ssh: unsupported key type {other:?}")),
    }
}

fn pkcs8(der: &[u8]) -> Result<Key, String> {
    if let Ok(k) = Ed25519KeyPair::from_pkcs8_maybe_unchecked(der) {
        return Ok(Key::Ed25519(k));
    }
    if let Ok(k) = RsaKeyPair::from_pkcs8(der) {
        return Ok(Key::Rsa(k));
    }
    let rng = SystemRandom::new();
    for c in [Curve::P256, Curve::P384] {
        if let Ok(k) = EcdsaKeyPair::from_pkcs8(c.signing(), der, &rng) {
            return Ok(Key::Ecdsa(k, c));
        }
    }
    Err("x509: unsupported private key type".into())
}

/// `ECPrivateKey` (RFC 5915): version, the scalar, the curve, the point.
fn sec1(der: &[u8]) -> Result<Key, String> {
    let bad = || "x509: failed to parse EC private key".to_owned();
    let mut seq = Der(Der(der).take(0x30).ok_or_else(bad)?);
    seq.take(0x02).ok_or_else(bad)?;
    let scalar = seq.take(0x04).ok_or_else(bad)?;
    let mut curve = None;
    let mut point = None;
    while let Some((tag, v)) = seq.any() {
        match tag {
            0xa0 => curve = Der(v).take(0x06).and_then(Curve::from_oid),
            0xa1 => point = Der(v).take(0x03).and_then(|b| b.split_first().filter(|(unused, _)| **unused == 0).map(|(_, p)| p)),
            _ => {}
        }
    }
    let curve = curve.ok_or("x509: unknown elliptic curve")?;
    let point = point.ok_or("ssh: an EC private key without its public key")?;
    ecdsa(curve, scalar, point)
}

fn ecdsa(c: Curve, scalar: &[u8], point: &[u8]) -> Result<Key, String> {
    let scalar = fixed(scalar, c.scalar_len()).ok_or("ssh: bad ECDSA private key")?;
    EcdsaKeyPair::from_private_key_and_public_key(c.signing(), &scalar, point, &SystemRandom::new()).map(|k| Key::Ecdsa(k, c)).map_err(|e| format!("ssh: {e}"))
}

/// OpenSSH's `openssh-key-v1` (PROTOCOL.key in OpenSSH): the first key.
fn openssh(b: &[u8]) -> Result<Key, String> {
    let bad = || "ssh: malformed OpenSSH key".to_owned();
    let mut r = Reader(b.strip_prefix(b"openssh-key-v1\0").ok_or("ssh: invalid openssh private key format")?);
    let cipher = r.string().ok_or_else(bad)?;
    let _kdf = r.string().ok_or_else(bad)?;
    let _kdf_opts = r.string().ok_or_else(bad)?;
    if cipher != b"none" {
        return Err("ssh: this private key is passphrase protected".into());
    }
    if r.u32() != Some(1) {
        return Err("ssh: multi-key files are not supported".into());
    }
    let _public = r.string().ok_or_else(bad)?;
    let mut p = Reader(r.string().ok_or_else(bad)?);
    let (c1, c2) = (p.u32().ok_or_else(bad)?, p.u32().ok_or_else(bad)?);
    if c1 != c2 {
        return Err("ssh: malformed OpenSSH key".into());
    }
    let kind = p.string().ok_or_else(bad)?;
    match kind {
        b"ssh-ed25519" => {
            let public = p.string().ok_or_else(bad)?;
            let private = p.string().filter(|k| k.len() == 64).ok_or_else(bad)?;
            Ed25519KeyPair::from_seed_and_public_key(&private[..32], public).map(Key::Ed25519).map_err(|e| format!("ssh: {e}"))
        }
        b"ssh-rsa" => {
            let mut next = || p.string().map(trim_zeros).ok_or_else(bad);
            let (n, e, d, iqmp, pp, q) = (next()?, next()?, next()?, next()?, next()?, next()?);
            // OpenSSH keeps no dP or dQ; ring signs by the Chinese
            // remainder theorem and needs them.
            let (dp, dq) = (rem(d, &minus_one(pp)), rem(d, &minus_one(q)));
            let parts = ring::rsa::KeyPairComponents { public_key: signature::RsaPublicKeyComponents { n, e }, d, p: pp, q, dP: &dp[..], dQ: &dq[..], qInv: iqmp };
            RsaKeyPair::from_components(&parts).map(Key::Rsa).map_err(|e| format!("ssh: {e}"))
        }
        k if k.starts_with(b"ecdsa-sha2-") => {
            let curve = p.string().and_then(Curve::from_name).ok_or("ssh: unsupported curve")?;
            let point = p.string().ok_or_else(bad)?;
            let scalar = p.string().ok_or_else(bad)?;
            ecdsa(curve, scalar, point)
        }
        k => Err(format!("ssh: unhandled key type {:?}", String::from_utf8_lossy(k))),
    }
}

/// The first PEM block: its label, header lines, and decoded body.
fn pem(file: &[u8]) -> Option<(String, Vec<String>, Vec<u8>)> {
    let text = String::from_utf8_lossy(file);
    let start = text.find("-----BEGIN ")?;
    let rest = &text[start + 11..];
    let (label, rest) = rest.split_once("-----")?;
    let end = rest.find(&format!("-----END {label}-----"))?;
    let mut headers = Vec::new();
    let mut body = String::new();
    for line in rest[..end].lines().map(str::trim).filter(|l| !l.is_empty()) {
        if line.contains(':') {
            headers.push(line.to_owned());
        } else {
            body.push_str(line);
        }
    }
    Some((label.to_owned(), headers, base64(&body)?))
}

fn base64(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes() {
        acc = (acc << 6) | val(c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Big-endian `v` as exactly `n` bytes, if it fits.
fn fixed(v: &[u8], n: usize) -> Option<Vec<u8>> {
    let v = trim_zeros(v);
    (v.len() <= n).then(|| {
        let mut out = vec![0; n - v.len()];
        out.extend_from_slice(v);
        out
    })
}

fn trim_zeros(v: &[u8]) -> &[u8] {
    let i = v.iter().position(|b| *b != 0).unwrap_or(v.len());
    &v[i..]
}

/// `v - 1` for a big-endian `v > 0`.
fn minus_one(v: &[u8]) -> Vec<u8> {
    let mut out = v.to_vec();
    for b in out.iter_mut().rev() {
        let (x, borrow) = b.overflowing_sub(1);
        *b = x;
        if !borrow {
            break;
        }
    }
    trim_zeros(&out).to_vec()
}

/// `a mod m` for big-endian numbers, a bit at a time (a few thousand
/// steps for an RSA key, once per key).
fn rem(a: &[u8], m: &[u8]) -> Vec<u8> {
    let m = trim_zeros(m);
    let mut r: Vec<u8> = vec![0; m.len() + 1];
    let ge = |r: &[u8]| r[0] != 0 || r[1..] >= *m;
    for byte in a {
        for bit in (0..8).rev() {
            // r = r * 2 + bit
            let mut carry = (byte >> bit) & 1;
            for x in r.iter_mut().rev() {
                let next = *x >> 7;
                *x = (*x << 1) | carry;
                carry = next;
            }
            if ge(&r) {
                // r -= m
                let mut borrow = 0i16;
                for i in (0..r.len()).rev() {
                    let mi = if i == 0 { 0 } else { m[i - 1] as i16 };
                    let mut x = r[i] as i16 - mi - borrow;
                    borrow = 0;
                    if x < 0 {
                        x += 256;
                        borrow = 1;
                    }
                    r[i] = x as u8;
                }
            }
        }
    }
    trim_zeros(&r).to_vec()
}

// ---------------------------------------------------------------- wire

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn u32(&mut self) -> Option<u32> {
        let (h, t) = self.0.split_first_chunk::<4>()?;
        self.0 = t;
        Some(u32::from_be_bytes(*h))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > self.0.len() {
            return None;
        }
        let (h, t) = self.0.split_at(n);
        self.0 = t;
        Some(h)
    }
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// A non-negative big-endian number as an SSH mpint.
fn put_mpint(out: &mut Vec<u8>, v: &[u8]) {
    let v = trim_zeros(v);
    if v.first().is_some_and(|b| b & 0x80 != 0) {
        let mut x = vec![0];
        x.extend_from_slice(v);
        put_string(out, &x);
    } else {
        put_string(out, v);
    }
}

/// Just enough DER for the keys above.
struct Der<'a>(&'a [u8]);

impl<'a> Der<'a> {
    fn any(&mut self) -> Option<(u8, &'a [u8])> {
        let (&tag, rest) = self.0.split_first()?;
        let (&first, mut rest) = rest.split_first()?;
        let len = if first < 0x80 {
            first as usize
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 || rest.len() < n {
                return None;
            }
            let l = rest[..n].iter().fold(0usize, |a, b| (a << 8) | *b as usize);
            rest = &rest[n..];
            l
        };
        if len > rest.len() {
            return None;
        }
        let (v, t) = rest.split_at(len);
        self.0 = t;
        Some((tag, v))
    }

    fn take(&mut self, want: u8) -> Option<&'a [u8]> {
        self.any().filter(|(t, _)| *t == want).map(|(_, v)| v)
    }
}


// ---------------------------------------------------------------- the client

/// One forwarded id's agent.
pub enum Agent {
    /// An agent socket the client reaches as itself.
    Socket(PathBuf),
    /// Keys served by this client.
    Keys(Arc<Vec<Key>>),
}

/// `--ssh default|<id>[=<socket>|<key>[,<key>]]` as buildx reads it.
pub fn parse_spec(spec: &str) -> Result<(String, Vec<PathBuf>), String> {
    let (id, rest) = spec.split_once('=').unwrap_or((spec, ""));
    if id.is_empty() {
        return Err(format!("invalid ssh spec {spec:?}: an id is needed"));
    }
    if id.contains(['\n', '\r', '\0']) || id.len() > MAX_ID {
        return Err(format!("invalid ssh id {id:?}"));
    }
    Ok((id.to_owned(), rest.split(',').filter(|p| !p.is_empty()).map(PathBuf::from).collect()))
}

/// The longest id the engine takes.
pub const MAX_ID: usize = 256;

/// The agent for one id, read as the user who runs `kiri build`: no path is
/// `$SSH_AUTH_SOCK`; a socket is used as it is (alone); anything else is a
/// key file.
pub fn load(paths: &[PathBuf], auth_sock: Option<&str>) -> Result<Agent, String> {
    use std::os::unix::fs::FileTypeExt as _;
    if paths.is_empty() {
        return match auth_sock.filter(|s| !s.is_empty()) {
            Some(s) => Ok(Agent::Socket(PathBuf::from(s))),
            None => Err("invalid empty ssh agent socket: make sure SSH_AUTH_SOCK is set".into()),
        };
    }
    let mut keys = Vec::new();
    for p in paths {
        let meta = std::fs::metadata(p).map_err(|e| format!("failed to stat {}: {e}", p.display()))?;
        if meta.file_type().is_socket() {
            if paths.len() != 1 {
                return Err("a socket path can not be combined with other paths".into());
            }
            return Ok(Agent::Socket(p.clone()));
        }
        let data = std::fs::read(p).map_err(|e| format!("failed to read {}: {e}", p.display()))?;
        keys.push(parse_key(&data).map_err(|e| format!("failed to parse {}: {e}", p.display()))?);
    }
    Ok(Agent::Keys(Arc::new(keys)))
}

/// A fresh connection to `agent`.
fn connect(agent: &Agent) -> io::Result<OwnedFd> {
    match agent {
        Agent::Socket(p) => {
            // never the agent itself: a connection to the filter in front
            let agent = UnixStream::connect(p)?;
            let (mine, theirs) = UnixStream::pair()?;
            std::thread::Builder::new().name("ssh-filter".into()).spawn(move || {
                let _ = filter(mine, agent);
            })?;
            Ok(theirs.into())
        }
        Agent::Keys(keys) => {
            let (mine, theirs) = UnixStream::pair()?;
            let keys = Arc::clone(keys);
            std::thread::Builder::new().name("ssh-keys".into()).spawn(move || {
                let _ = converse(&keys, mine);
            })?;
            Ok(theirs.into())
        }
    }
}

/// Opens the build's agent session on the engine at `socket`: the token
/// the build names it by. A thread answers the engine until it closes the
/// connection or this process ends.
pub fn open(socket: &Path, agents: BTreeMap<String, Agent>) -> io::Result<String> {
    let mut s = UnixStream::connect(socket)?;
    let body = serde_json::json!({ "ids": agents.keys().collect::<Vec<_>>() }).to_string();
    write!(s, "POST /kiri/build/ssh HTTP/1.1\r\nHost: kiri\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len())?;
    let mut r = BufReader::new(s.try_clone()?);
    let mut line = String::new();
    r.read_line(&mut line)?;
    let status = line.split_whitespace().nth(1).unwrap_or("").to_owned();
    let mut len = 0usize;
    loop {
        line.clear();
        if r.read_line(&mut line)? == 0 {
            break;
        }
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':')
            && k.eq_ignore_ascii_case("content-length")
        {
            len = v.trim().parse().unwrap_or(0);
        }
    }
    let mut answer = vec![0; len.min(64 << 10)];
    r.read_exact(&mut answer)?;
    let answer: serde_json::Value = serde_json::from_slice(&answer).unwrap_or_default();
    let token = match (status.as_str(), answer["session"].as_str()) {
        ("200", Some(t)) => t.to_owned(),
        _ => return Err(io::Error::other(format!("the engine did not open an ssh session ({status})"))),
    };
    std::thread::Builder::new().name("ssh-session".into()).spawn(move || answer_engine(r, s, &agents))?;
    Ok(token)
}

/// Each id the engine asks for: a fresh connection to its agent, or `0`.
fn answer_engine(mut r: impl io::BufRead, s: UnixStream, agents: &BTreeMap<String, Agent>) {
    let mut line = String::new();
    loop {
        line.clear();
        match r.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let sent = match agents.get(line.trim_end_matches('\n')).map(connect) {
            Some(Ok(fd)) => send_fd(&s, b'1', Some(fd.as_raw_fd())),
            _ => send_fd(&s, b'0', None),
        };
        if sent.is_err() {
            return;
        }
    }
}

// ---------------------------------------------------------------- descriptors

/// One byte, and `fd` with it when given (SCM_RIGHTS).
pub fn send_fd(sock: &UnixStream, byte: u8, fd: Option<RawFd>) -> io::Result<()> {
    let data = [byte];
    let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut _, iov_len: 1 };
    // SAFETY: CMSG_SPACE is a pure size computation.
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut control = vec![0u8; space];
    // SAFETY: a msghdr over buffers that outlive the call, with at most one
    // SCM_RIGHTS header written inside `control`.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if let Some(fd) = fd {
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(c).cast::<RawFd>(), fd);
        }
        if libc::sendmsg(sock.as_raw_fd(), &msg, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// One byte and the descriptor sent with it, if any; None at the end of
/// the stream. Any descriptor past the first is closed.
pub fn recv_fd(sock: &UnixStream) -> io::Result<Option<(u8, Option<OwnedFd>)>> {
    let mut data = [0u8; 1];
    let mut iov = libc::iovec { iov_base: data.as_mut_ptr().cast(), iov_len: 1 };
    // SAFETY: CMSG_SPACE is a pure size computation.
    let space = unsafe { libc::CMSG_SPACE(4 * std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut control = vec![0u8; space];
    let mut fd = None;
    // SAFETY: recvmsg into buffers we own; each descriptor received is
    // owned from here on.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        #[cfg(target_os = "linux")]
        let flags = libc::MSG_CMSG_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let flags = 0;
        let n = libc::recvmsg(sock.as_raw_fd(), &mut msg, flags);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let count = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / std::mem::size_of::<RawFd>();
                for i in 0..count {
                    let owned = OwnedFd::from_raw_fd(std::ptr::read_unaligned(libc::CMSG_DATA(c).cast::<RawFd>().add(i)));
                    #[cfg(not(target_os = "linux"))]
                    libc::fcntl(owned.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
                    if fd.is_none() {
                        fd = Some(owned);
                    }
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
        if n == 0 {
            return Ok(None);
        }
    }
    Ok(Some((data[0], fd)))
}

#[cfg(test)]
mod tests {
    /// PEM armour, put together here so no key header sits in the source as
    /// one string.
    fn armour(label: &str, body: &str) -> String {
        let key = "KEY";
        format!("-----BEGIN {label} {key}-----\n{body}\n-----END {label} {key}-----\n")
    }

    use super::*;
    use std::process::Command;

    fn req(t: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![t];
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn remainders_of_big_numbers() {
        assert_eq!(rem(&[0x01, 0x00], &[0x07]), [0x04]);
        assert_eq!(rem(&[0x05], &[0x07]), [0x05]);
        assert_eq!(rem(&[0xff, 0xff, 0xff], &[0x01, 0x00]), [0xff]);
        assert!(rem(&[0x0e], &[0x07]).is_empty());
        // 2^64 + 5 mod (2^32 + 1) = 6 (2^64 = (2^32+1)(2^32-1) + 1)
        assert_eq!(rem(&[1, 0, 0, 0, 0, 0, 0, 0, 5], &[1, 0, 0, 0, 1]), [6]);
        assert_eq!(minus_one(&[1, 0]), [0xff]);
        assert_eq!(minus_one(&[2, 0, 1]), [2, 0, 0]);
    }

    #[test]
    fn keys_are_listed_and_sign_with_ring_made_keys() {
        let rng = SystemRandom::new();
        let ed = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let ec = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pem_of = |der: &[u8]| armour("PRIVATE", &b64(der));
        let keys = vec![parse_key(pem_of(ed.as_ref()).as_bytes()).unwrap(), parse_key(pem_of(ec.as_ref()).as_bytes()).unwrap()];
        let list = answer(&keys, &[REQUEST_IDENTITIES]);
        let mut r = Reader(&list[1..]);
        assert_eq!(list[0], IDENTITIES_ANSWER);
        assert_eq!(r.u32(), Some(2));
        let blob = r.string().unwrap().to_vec();
        assert_eq!(Reader(&blob).string(), Some(&b"ssh-ed25519"[..]));
        // sign, then check the signature with the public key
        let mut body = Vec::new();
        put_string(&mut body, &blob);
        put_string(&mut body, b"data");
        body.extend_from_slice(&0u32.to_be_bytes());
        let a = answer(&keys, &req(SIGN_REQUEST, &body));
        assert_eq!(a[0], SIGN_RESPONSE);
        let mut r = Reader(&a[1..]);
        let mut sig = Reader(r.string().unwrap());
        assert_eq!(sig.string(), Some(&b"ssh-ed25519"[..]));
        let Key::Ed25519(k) = &keys[0] else { panic!() };
        signature::UnparsedPublicKey::new(&signature::ED25519, k.public_key().as_ref()).verify(b"data", sig.string().unwrap()).unwrap();
        // an unknown key, adding a key, and removing all of them all fail
        let mut other = Vec::new();
        put_string(&mut other, b"ssh-ed25519\0\0\0\x01x");
        put_string(&mut other, b"data");
        other.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(answer(&keys, &req(SIGN_REQUEST, &other)), [FAILURE]);
        for t in [17u8, 18, 19, 25, 27, 22, 9] {
            assert_eq!(answer(&keys, &[t]), [FAILURE], "{t}");
        }
        assert_eq!(answer(&keys, &[]), [FAILURE]);
    }

    #[test]
    fn files_it_does_not_take_say_why_as_buildx_does() {
        let e = |b: &[u8]| parse_key(b).err().unwrap();
        assert_eq!(e(b"hello"), "ssh: no key found");
        assert_eq!(e(armour("RSA PRIVATE", "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA").as_bytes()), "ssh: this private key is passphrase protected");
        assert_eq!(e(armour("ENCRYPTED PRIVATE", "AAAA").as_bytes()), "ssh: this private key is passphrase protected");
    }

    /// Key files made by OpenSSH and OpenSSL in each format, served on a
    /// socket: OpenSSH's own client lists them and signs with them, and the
    /// signature checks. Skipped where those tools are missing.
    #[test]
    fn openssh_clients_list_and_sign_with_each_key_format() {
        let have = |t: &str| Command::new(t).arg("-V").output().is_ok() || Command::new("sh").args(["-c", &format!("command -v {t}")]).output().is_ok_and(|o| o.status.success());
        if !have("ssh-keygen") || !have("ssh-add") || !have("openssl") {
            eprintln!("skipped: ssh-keygen, ssh-add or openssl missing");
            return;
        }
        let dir = std::env::temp_dir().join(format!("kiri-sshagent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sh = |cmd: &str| {
            let o = Command::new("sh").args(["-c", cmd]).current_dir(&dir).output().unwrap();
            assert!(o.status.success(), "{cmd}: {}", String::from_utf8_lossy(&o.stderr));
            String::from_utf8_lossy(&o.stdout).into_owned()
        };
        // each key file and its public key in OpenSSH's form
        let made = [
            ("ed", "ssh-keygen -q -t ed25519 -N '' -f ed"),
            ("rsa", "ssh-keygen -q -t rsa -b 2048 -N '' -f rsa"),
            ("ec256", "ssh-keygen -q -t ecdsa -b 256 -N '' -f ec256"),
            ("ec384", "ssh-keygen -q -t ecdsa -b 384 -N '' -f ec384"),
            ("rsapem", "openssl genrsa -traditional -out rsapem 2048 2>/dev/null || openssl genrsa -out rsapem 2048"),
            ("rsap8", "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsap8"),
            ("ecsec1", "openssl ecparam -name prime256v1 -genkey -noout -out ecsec1"),
            ("ecp8", "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out ecp8"),
            ("edp8", "openssl genpkey -algorithm ed25519 -out edp8"),
        ];
        let mut keys = Vec::new();
        let mut publics = Vec::new();
        for (name, cmd) in made {
            sh(cmd);
            sh(&format!("chmod 600 {name}"));
            let k = parse_key(&std::fs::read(dir.join(name)).unwrap()).unwrap_or_else(|e| panic!("{name}: {e}"));
            let o = Command::new("ssh-keygen").args(["-y", "-f", name]).current_dir(&dir).output().unwrap();
            let pubkey = if o.status.success() {
                String::from_utf8_lossy(&o.stdout).into_owned()
            } else {
                // An ssh-keygen built with LibreSSL (macOS) reads no PKCS#8
                // Ed25519 file: its public key from openssl, the last 32
                // bytes of the SubjectPublicKeyInfo.
                assert_eq!(name, "edp8", "{}", String::from_utf8_lossy(&o.stderr));
                let o = Command::new("openssl").args(["pkey", "-in", name, "-pubout", "-outform", "DER"]).current_dir(&dir).output().unwrap();
                let mut blob = Vec::new();
                put_string(&mut blob, b"ssh-ed25519");
                put_string(&mut blob, &o.stdout[o.stdout.len() - 32..]);
                format!("ssh-ed25519 {}\n", b64(&blob))
            };
            let words: Vec<&str> = pubkey.split_whitespace().collect();
            assert_eq!(words[1], b64(&k.blob()), "{name}");
            std::fs::write(dir.join(format!("{name}.pub")), format!("{} {}\n", words[0], words[1])).unwrap();
            publics.push(format!("{} {}", words[0], words[1]));
            keys.push(k);
        }
        // a passphrase on an OpenSSH key
        sh("ssh-keygen -q -t ed25519 -N secret -f locked");
        assert_eq!(parse_key(&std::fs::read(dir.join("locked")).unwrap()).err().unwrap(), "ssh: this private key is passphrase protected");

        // served on a socket as `ssh-add` reaches an agent
        let sock = dir.join("agent.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let keys = Arc::new(keys);
        let served = Arc::clone(&keys);
        std::thread::spawn(move || {
            for c in listener.incoming().flatten() {
                let keys = Arc::clone(&served);
                std::thread::spawn(move || converse(&keys, c));
            }
        });
        let env = format!("SSH_AUTH_SOCK={}", sock.display());
        let listed = sh(&format!("{env} ssh-add -L"));
        let listed: Vec<String> = listed.lines().map(|l| l.split_whitespace().take(2).collect::<Vec<_>>().join(" ")).collect();
        assert_eq!(listed, publics);
        std::fs::write(dir.join("msg"), b"signed by the step's agent").unwrap();
        for (name, _) in made {
            sh(&format!("{env} ssh-keygen -q -Y sign -f {name}.pub -n test msg && mv msg.sig {name}.sig"));
            sh(&format!("ssh-keygen -q -Y check-novalidate -n test -f {name}.pub -s {name}.sig < msg"));
        }
        // An agent that is a socket is passed through as it is: the
        // engine gets a connection to it, not its path.
        let agent = load(std::slice::from_ref(&sock), None).unwrap();
        assert!(matches!(&agent, Agent::Socket(p) if *p == sock));
        let mut c = UnixStream::from(connect(&agent).unwrap());
        c.write_all(&[0, 0, 0, 1, REQUEST_IDENTITIES]).unwrap();
        let mut len = [0; 4];
        c.read_exact(&mut len).unwrap();
        let mut a = vec![0; u32::from_be_bytes(len) as usize];
        c.read_exact(&mut a).unwrap();
        assert_eq!(a[0], IDENTITIES_ANSWER);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn b64(b: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for c in b.chunks(3) {
            let n = c.iter().fold(0u32, |a, b| (a << 8) | *b as u32) << (8 * (3 - c.len()));
            for i in 0..4 {
                s.push(if i <= c.len() { A[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
            }
        }
        s
    }

    /// The session the engine asks for connections over: each id it names
    /// gets a fresh connection to that id's agent, with the descriptor; an
    /// id the client does not forward gets `0` and nothing.
    #[test]
    fn the_engine_gets_a_connection_per_id_and_never_a_path() {
        let rng = SystemRandom::new();
        let ed = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pem = armour("PRIVATE", &b64(ed.as_ref()));
        let dir = std::env::temp_dir().join(format!("kiri-sshfwd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("k"), pem).unwrap();
        let mut agents = BTreeMap::new();
        agents.insert("default".to_string(), load(&[dir.join("k")], None).unwrap());
        let (engine, client) = UnixStream::pair().unwrap();
        let reader = BufReader::new(client.try_clone().unwrap());
        let t = std::thread::spawn(move || answer_engine(reader, client, &agents));
        let mut e = engine.try_clone().unwrap();
        e.write_all(b"default\n").unwrap();
        let (byte, fd) = recv_fd(&engine).unwrap().unwrap();
        assert_eq!(byte, b'1');
        let mut c = UnixStream::from(fd.unwrap());
        c.write_all(&[0, 0, 0, 1, REQUEST_IDENTITIES]).unwrap();
        let mut len = [0; 4];
        c.read_exact(&mut len).unwrap();
        let mut a = vec![0; u32::from_be_bytes(len) as usize];
        c.read_exact(&mut a).unwrap();
        assert_eq!((a[0], &a[1..5]), (IDENTITIES_ANSWER, &[0, 0, 0, 1][..]));
        e.write_all(b"other\n").unwrap();
        assert!(matches!(recv_fd(&engine).unwrap(), Some((b'0', None))));
        drop((e, engine));
        t.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn specs_and_sources_as_buildx_reads_them() {
        assert_eq!(parse_spec("default").unwrap(), ("default".to_string(), vec![]));
        assert_eq!(parse_spec("x=/a,/b").unwrap(), ("x".to_string(), vec![PathBuf::from("/a"), PathBuf::from("/b")]));
        assert!(parse_spec("=/a").is_err());
        assert!(parse_spec("a\nb").is_err());
        assert_eq!(load(&[], None).err().unwrap(), "invalid empty ssh agent socket: make sure SSH_AUTH_SOCK is set");
        assert!(matches!(load(&[], Some("/s")), Ok(Agent::Socket(p)) if p == Path::new("/s")));
        assert!(load(&[PathBuf::from("/nonexistent/k")], None).is_err());
    }

    fn short_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ksf{tag}{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A stand-in agent socket that records the type of each request that
    /// reaches it and answers each with SSH_AGENT_SUCCESS (6), or with an
    /// identities answer of no keys for 11.
    fn recording_agent(sock: &Path) -> Arc<std::sync::Mutex<Vec<u8>>> {
        let l = std::os::unix::net::UnixListener::bind(sock).unwrap();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let rec = Arc::clone(&seen);
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(mut c) = c else { return };
                let rec = Arc::clone(&rec);
                std::thread::spawn(move || {
                    loop {
                        let mut len = [0; 4];
                        if c.read_exact(&mut len).is_err() {
                            return;
                        }
                        let mut m = vec![0; u32::from_be_bytes(len) as usize];
                        if c.read_exact(&mut m).is_err() {
                            return;
                        }
                        rec.lock().unwrap().push(m.first().copied().unwrap_or(0));
                        let a: &[u8] = if m.first() == Some(&REQUEST_IDENTITIES) { &[0, 0, 0, 5, IDENTITIES_ANSWER, 0, 0, 0, 0] } else { &[0, 0, 0, 1, 6] };
                        if c.write_all(a).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        seen
    }

    fn frame(msg: &[u8]) -> Vec<u8> {
        let mut m = (msg.len() as u32).to_be_bytes().to_vec();
        m.extend_from_slice(msg);
        m
    }

    fn ask(c: &mut UnixStream, msg: &[u8]) -> Vec<u8> {
        c.write_all(&frame(msg)).unwrap();
        reply(c)
    }

    fn reply(c: &mut UnixStream) -> Vec<u8> {
        let mut len = [0; 4];
        c.read_exact(&mut len).unwrap();
        let mut a = vec![0; u32::from_be_bytes(len) as usize];
        c.read_exact(&mut a).unwrap();
        a
    }

    fn closed(c: &mut UnixStream) -> bool {
        c.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
        let mut rest = Vec::new();
        matches!(c.read_to_end(&mut rest), Ok(0)) || rest.is_empty()
    }

    /// A step reaches a socket agent through a filter in the client
    /// (as BuildKit's readOnlyAgent): only the list of keys (11) and sign
    /// requests (13) reach the agent; adding (17, 20, 25, 26), removing
    /// (18, 19), locking (22, 23), extensions (27, PKCS#11 loads among
    /// them) and unknown types get SSH_AGENT_FAILURE and never arrive.
    #[test]
    fn a_socket_agent_gets_only_list_and_sign_requests() {
        let d = short_dir("f");
        let sock = d.join("a.sock");
        let seen = recording_agent(&sock);
        let mut step = UnixStream::from(connect(&Agent::Socket(sock)).unwrap());
        for t in [17u8, 18, 19, 20, 21, 22, 23, 25, 26, 27, 0, 1, 9, 12, 14, 99, 255] {
            let mut m = vec![t];
            m.extend_from_slice(b"\0\0\0\x05owned");
            assert_eq!(ask(&mut step, &m), [FAILURE], "type {t}");
        }
        assert_eq!(ask(&mut step, &[REQUEST_IDENTITIES]), [IDENTITIES_ANSWER, 0, 0, 0, 0]);
        assert_eq!(ask(&mut step, &[SIGN_REQUEST, 0, 0, 0, 0]), [6], "the agent's own answer");
        assert_eq!(*seen.lock().unwrap(), [REQUEST_IDENTITIES, SIGN_REQUEST]);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Several requests in one write are each read whole and filtered:
    /// nothing past the first frame slips through to the agent unparsed.
    #[test]
    fn pipelined_requests_are_each_filtered() {
        let d = short_dir("p");
        let sock = d.join("a.sock");
        let seen = recording_agent(&sock);
        let mut step = UnixStream::from(connect(&Agent::Socket(sock)).unwrap());
        let mut all = Vec::new();
        for m in [&[19u8][..], &[REQUEST_IDENTITIES], b"\x16\0\0\0\x01x", &[SIGN_REQUEST], &[27, 0, 0, 0, 0]] {
            all.extend_from_slice(&frame(m));
        }
        step.write_all(&all).unwrap();
        let answers: Vec<u8> = (0..5).map(|_| reply(&mut step)[0]).collect();
        assert_eq!(answers, [FAILURE, IDENTITIES_ANSWER, FAILURE, 6, FAILURE]);
        assert_eq!(*seen.lock().unwrap(), [REQUEST_IDENTITIES, SIGN_REQUEST]);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A frame over 256 KiB, of no bytes, or cut short closes the
    /// connection, and nothing of it reaches the agent.
    #[test]
    fn an_oversized_empty_or_truncated_frame_closes_the_connection() {
        let d = short_dir("o");
        let sock = d.join("a.sock");
        let seen = recording_agent(&sock);
        let open = || UnixStream::from(connect(&Agent::Socket(sock.clone())).unwrap());
        let mut c = open();
        c.write_all(&((MAX_MESSAGE as u32 + 1).to_be_bytes())).unwrap();
        let _ = c.write_all(&[REQUEST_IDENTITIES; 64]);
        assert!(closed(&mut c), "oversized");
        let mut c = open();
        c.write_all(&[0xff, 0xff, 0xff, 0xff, REQUEST_IDENTITIES]).unwrap();
        assert!(closed(&mut c), "2^32-1");
        let mut c = open();
        c.write_all(&[0, 0, 0, 0]).unwrap();
        assert!(closed(&mut c), "empty");
        let mut c = open();
        c.write_all(&[0, 0, 0, 100, REQUEST_IDENTITIES, 1, 2]).unwrap();
        c.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(closed(&mut c), "truncated");
        // a frame of exactly the limit is still read (and refused)
        let mut c = open();
        let mut big = vec![17u8];
        big.resize(MAX_MESSAGE, 0);
        assert_eq!(ask(&mut c, &big), [FAILURE]);
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(seen.lock().unwrap().is_empty(), "{:?}", seen.lock().unwrap());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// With a real ssh-agent, a step can list the user's keys but can
    /// neither remove them all nor lock the agent with a password of its
    /// own.
    #[test]
    fn a_step_can_neither_empty_nor_lock_the_users_real_agent() {
        if Command::new("sh").args(["-c", "command -v ssh-agent && command -v ssh-add && command -v ssh-keygen"]).output().map_or(true, |o| !o.status.success()) {
            eprintln!("skipped: ssh-agent, ssh-add or ssh-keygen missing");
            return;
        }
        let d = short_dir("r");
        let agent_sock = d.join("a.sock");
        let mut agent = Command::new("ssh-agent").args(["-D", "-a"]).arg(&agent_sock).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
        for _ in 0..50 {
            if agent_sock.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let run = |cmd: &str| {
            let o = Command::new("sh").args(["-c", cmd]).current_dir(&d).env("SSH_AUTH_SOCK", &agent_sock).output().unwrap();
            (o.status.success(), String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr))
        };
        assert!(run("ssh-keygen -q -t ed25519 -N '' -f k && ssh-add k").0);
        let mut step = UnixStream::from(connect(&load(&[], Some(agent_sock.to_str().unwrap())).unwrap()).unwrap());
        let listed = ask(&mut step, &[REQUEST_IDENTITIES]);
        assert_eq!((listed[0], &listed[1..5]), (IDENTITIES_ANSWER, &[0, 0, 0, 1][..]));
        let removed = ask(&mut step, &[19]);
        let mut lock = vec![22u8];
        lock.extend_from_slice(&5u32.to_be_bytes());
        lock.extend_from_slice(b"owned");
        let locked = ask(&mut step, &lock);
        let after = ask(&mut step, &[REQUEST_IDENTITIES]);
        let seen = run("ssh-add -l").1;
        let _ = agent.kill();
        let _ = agent.wait();
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!((removed[0], locked[0]), (FAILURE, FAILURE));
        assert_eq!(&after[1..5], &[0, 0, 0, 1], "the key is still there");
        assert!(seen.contains("ED25519"), "{seen}");
    }

    /// The key-file agent refuses every type but list and sign, signs
    /// whatever the flags for Ed25519, and closes on a bad length.
    #[test]
    fn the_key_file_agent_refuses_all_but_list_and_sign() {
        let rng = SystemRandom::new();
        let ed = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pem = armour("PRIVATE", &b64(ed.as_ref()));
        let mut step = UnixStream::from(connect(&Agent::Keys(Arc::new(vec![parse_key(pem.as_bytes()).unwrap()]))).unwrap());
        for t in 0u8..=255 {
            if t == REQUEST_IDENTITIES || t == SIGN_REQUEST {
                continue;
            }
            assert_eq!(ask(&mut step, &[t, 0, 0, 0, 0]), [FAILURE], "type {t}");
        }
        let listed = ask(&mut step, &[REQUEST_IDENTITIES]);
        let n = u32::from_be_bytes(listed[5..9].try_into().unwrap()) as usize;
        let blob = listed[9..9 + n].to_vec();
        for flags in [0u32, 1, 2, 4, 6, u32::MAX] {
            let mut m = vec![SIGN_REQUEST];
            put_string(&mut m, &blob);
            m.extend_from_slice(&0u32.to_be_bytes());
            m.extend_from_slice(&flags.to_be_bytes());
            assert_eq!(ask(&mut step, &m)[0], SIGN_RESPONSE, "flags {flags}");
        }
        let mut m = vec![SIGN_REQUEST];
        m.extend_from_slice(&u32::MAX.to_be_bytes());
        m.extend_from_slice(&blob);
        assert_eq!(ask(&mut step, &m), [FAILURE]);
        assert_eq!(ask(&mut step, &[SIGN_REQUEST]), [FAILURE]);
        step.write_all(&[0xff, 0xff, 0xff, 0xff, REQUEST_IDENTITIES]).unwrap();
        assert!(closed(&mut step));
    }

    /// With both RSA SHA-2 flags a signature is SHA-256, as OpenSSH's
    /// agent picks it (ssh-agent.c: the 256 flag is tested first).
    #[test]
    fn both_rsa_sha2_flags_sign_with_sha_256() {
        let d = short_dir("rsa");
        if !Command::new("sh").args(["-c", "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out k 2>/dev/null"]).current_dir(&d).status().is_ok_and(|s| s.success()) {
            eprintln!("skipped: openssl missing");
            return;
        }
        let key = parse_key(&std::fs::read(d.join("k")).unwrap()).unwrap();
        let _ = std::fs::remove_dir_all(&d);
        let name = |flags: u32| {
            let sig = key.sign(b"data", flags).unwrap();
            let mut r = Reader(&sig);
            String::from_utf8(r.string().unwrap().to_vec()).unwrap()
        };
        assert_eq!(name(RSA_SHA2_256 | RSA_SHA2_512), "rsa-sha2-256");
        assert_eq!(name(RSA_SHA2_512), "rsa-sha2-512");
        assert_eq!(name(RSA_SHA2_256), "rsa-sha2-256");
        assert!(key.sign(b"data", 0).is_none(), "no SHA-1");
    }

    /// More descriptors than one in a message: the first is kept, the rest
    /// closed (no leak in the engine). Three copies of a pipe's write end
    /// are sent: once the kept one is dropped too, the read end sees the
    /// end of the stream only if no copy is left open anywhere.
    ///
    /// It runs alone in a process of its own: another test spawning a
    /// child meanwhile could inherit a copy (macOS has no atomic
    /// close-on-exec for received descriptors) and keep the pipe open.
    #[test]
    fn extra_descriptors_are_closed() {
        if std::env::var_os("KIRI_FD_TEST_ALONE").is_none() {
            let o = Command::new(std::env::current_exe().unwrap())
                .args(["sshfwd::tests::extra_descriptors_are_closed", "--exact", "--test-threads=1", "--nocapture"])
                .env("KIRI_FD_TEST_ALONE", "1")
                .output()
                .unwrap();
            let out = String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr);
            assert!(o.status.success() && out.contains("1 passed"), "{out}");
            return;
        }
        let (a, b) = UnixStream::pair().unwrap();
        let mut p = [0; 2];
        // SAFETY: pipe into a local array; both ends are owned below.
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        // SAFETY: fresh descriptors from pipe(2), owned from here; not
        // to be inherited by what other tests spawn meanwhile.
        let (r, w) = unsafe {
            libc::fcntl(p[0], libc::F_SETFD, libc::FD_CLOEXEC);
            libc::fcntl(p[1], libc::F_SETFD, libc::FD_CLOEXEC);
            (OwnedFd::from_raw_fd(p[0]), OwnedFd::from_raw_fd(p[1]))
        };
        let fds = [w.as_raw_fd(); 3];
        // SAFETY: a msghdr over local buffers with one SCM_RIGHTS header
        // of three descriptors.
        unsafe {
            let data = *b"1";
            let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut _, iov_len: 1 };
            let space = libc::CMSG_SPACE(12) as usize;
            let mut control = vec![0u8; space];
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(12) as _;
            std::ptr::copy_nonoverlapping(fds.as_ptr().cast::<u8>(), libc::CMSG_DATA(c), 12);
            assert_eq!(libc::sendmsg(a.as_raw_fd(), &msg, 0), 1);
        }
        drop(w);
        let got = recv_fd(&b).unwrap().unwrap();
        // close-on-exec is set on what is kept
        // SAFETY: F_GETFD on a descriptor we own.
        let flags = unsafe { libc::fcntl(got.1.as_ref().unwrap().as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        drop(got);
        // SAFETY: F_SETFL and read on the read end we own.
        let n = unsafe {
            libc::fcntl(r.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK);
            let mut buf = [0u8; 1];
            libc::read(r.as_raw_fd(), buf.as_mut_ptr().cast(), 1)
        };
        assert_eq!(n, 0, "a copy of the descriptor is still open: {}", io::Error::last_os_error());
    }

    /// Mutated key files never panic the client's parser.
    #[test]
    fn mutated_key_files_do_not_panic_the_parser() {
        let d = short_dir("z");
        let made = Command::new("sh")
            .args(["-c", "ssh-keygen -q -t ed25519 -N '' -f ed && ssh-keygen -q -t rsa -b 2048 -N '' -f rsa && ssh-keygen -q -t ecdsa -b 256 -N '' -f ec && openssl ecparam -name prime256v1 -genkey -noout -out sec1 && openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out p8"])
            .current_dir(&d)
            .stderr(std::process::Stdio::null())
            .status();
        if !made.is_ok_and(|s| s.success()) {
            eprintln!("skipped: ssh-keygen or openssl missing");
            return;
        }
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut total = 0;
        for (name, rounds) in [("ed", 20000), ("ec", 20000), ("sec1", 20000), ("rsa", 3000), ("p8", 3000)] {
            let text = std::fs::read_to_string(d.join(name)).unwrap();
            let label = text.lines().next().unwrap().trim_start_matches("-----BEGIN ").trim_end_matches("-----").to_owned();
            let der = base64(&text.lines().filter(|l| !l.starts_with("-----")).collect::<String>()).unwrap();
            assert!(parse_key(text.as_bytes()).is_ok(), "{name}");
            for _ in 0..rounds {
                let mut m = der.clone();
                match rnd() % 4 {
                    0 => {
                        let i = rnd() as usize % m.len();
                        m[i] = rnd() as u8;
                    }
                    1 => m.truncate(rnd() as usize % m.len()),
                    2 => {
                        let i = rnd() as usize % m.len();
                        let n = (rnd() as usize % 300).min(m.len() - i);
                        let v = if rnd() % 2 == 0 { 0 } else { 0xff };
                        m[i..i + n].fill(v);
                    }
                    _ => {
                        let i = rnd() as usize % m.len();
                        let n = (rnd() as usize % 8).min(m.len() - i);
                        for b in &mut m[i..i + n] {
                            *b = rnd() as u8;
                        }
                    }
                }
                let pem = format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", b64(&m));
                total += 1;
                assert!(std::panic::catch_unwind(|| parse_key(pem.as_bytes()).is_ok()).is_ok(), "{name} #{total}:\n{pem}");
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
