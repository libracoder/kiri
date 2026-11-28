//! Updates on Windows: the newest release, downloaded, cryptographically
//! verified, and installed, matching `crates/kiri/src/update.rs` on macOS.
//!
//! The release feed is a small JSON file (`{"version", "url", "sha256"}` plus
//! optional `"signature"`, `"notes"`, `"notes_url"`, `"size"`) at
//! `KIRI_UPDATE_URL` (default: `https://download.runkiri.com/latest-windows-{arch}.json`).
//!
//! Verification layers before any silent `msiexec /qn` install:
//! 1. Strict HTTPS URL (`https://download.runkiri.com/...` unless
//!    `KIRI_UPDATE_URL` overrides in tests) + strict `.msi` filename + private
//!    per-user staging directory (`%LOCALAPPDATA%\Kiri\updates`, never `%TEMP%`).
//! 2. SHA-256 digest read from a write-locked file handle (`FILE_SHARE_READ`
//!    only) and re-verified before launching `kiri.ps1 -Update -Sha256 ...`.
//! 3. Optional detached Ed25519 signature verification over canonical
//!    `"kiri-update-v1\n{version}\n{url}\n{sha256}"` when compiled with
//!    `KIRI_UPDATE_PUBLIC_KEY` (64-char hex 32-byte Ed25519 public key).
//! 4. Win32 Authenticode (`WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2`
//!    and `WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`) + signer leaf certificate
//!    identity pinned against the running `kiri-win.exe` when `kiri-win.exe`
//!    is Authenticode-signed.
//! 5. MSI database `UpgradeCode`, `Template` architecture, and `ProductVersion`
//!    newer than `CARGO_PKG_VERSION`.
//! 6. Unsigned builds without `KIRI_UPDATE_PUBLIC_KEY` still report available
//!    versions via `latest()` / `--check`, but refuse silent `msiexec /qn`
//!    auto-install and direct the user to `https://runkiri.com/releases/`.

use std::io;
#[cfg(windows)]
use std::io::Read;
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use std::process::{Command, Stdio};
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(windows)]
use std::time::{Duration, Instant};

#[cfg(windows)]
#[path = "../../kiri/src/ui/recheck.rs"]
mod recheck;

#[cfg(windows)]
use serde_json::json;

#[cfg(windows)]
use crate::engine::{emit, notice, trf};

#[cfg(not(target_arch = "aarch64"))]
const FEED: &str = "https://download.runkiri.com/latest-windows-x86_64.json";
#[cfg(target_arch = "aarch64")]
const FEED: &str = "https://download.runkiri.com/latest-windows-arm64.json";
const DEFAULT_HOST: &str = "download.runkiri.com";
const RELEASES_URL: &str = "https://runkiri.com/releases/";
/// The biggest download accepted (the MSI is about 55 MB).
#[cfg(windows)]
const MAX_DOWNLOAD: u64 = 2 << 30;
/// installer/windows/kiri.wxs's UpgradeCode: what makes an MSI a Kiri one.
#[cfg(windows)]
const UPGRADE_CODE: &str = "{7C2E4B9A-5D13-4F8E-9B6A-0E1D3C5A7F21}";
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
#[cfg(windows)]
const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
const CURRENT: &str = env!("CARGO_PKG_VERSION");

#[derive(serde::Deserialize, serde::Serialize, Clone, Debug, Default)]
pub struct Release {
    pub version: String,
    pub url: String,
    pub sha256: String,
    /// Detached Ed25519 signature (hex or base64) over `"kiri-update-v1\n{version}\n{url}\n{sha256}"`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub notes_url: String,
    /// The MSI's size, for the progress bar when the server does not say.
    #[serde(default)]
    pub size: u64,
}

/// Optional build-time 32-byte Ed25519 public key (64 hex characters).
fn compiled_public_key() -> Option<&'static str> {
    option_env!("KIRI_UPDATE_PUBLIC_KEY").map(str::trim).filter(|s| !s.is_empty())
}

/// Whether `v` reads as a version: `[v]N(.N)*`, optionally `-` and
/// dot-separated alphanumeric identifiers (`0.1.8-dev.42`).
fn is_version(v: &str) -> bool {
    let s = v.strip_prefix('v').unwrap_or(v);
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (s, None),
    };
    let numeric = |seg: &str| !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit());
    let ident = |id: &str| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    core.split('.').all(numeric) && pre.is_none_or(|p| p.split('.').all(ident))
}

/// `1.2.10` > `1.2.9`; a missing part counts as 0, and a test build
/// (`0.1.8-dev.42`, scripts/ci/test-version.sh) sorts above its release.
/// A string that isn't a version is never newer, and nothing is newer
/// than one.
pub fn newer(candidate: &str, current: &str) -> bool {
    if !is_version(candidate) || !is_version(current) {
        return false;
    }
    let parts = |v: &str| -> Vec<u64> { v.trim_start_matches('v').split(['.', '-']).map(|p| p.parse().unwrap_or(0)).collect() };
    let (a, b) = (parts(candidate), parts(current));
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x > y;
        }
    }
    false
}

fn valid_sha256_hex(s: &str) -> bool {
    let s = s.trim();
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_msi_filename(name: &str) -> bool {
    name.len() > 4
        && name.len() <= 128
        && name.starts_with("Kiri-")
        && name.ends_with(".msi")
        && !name.contains("..")
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Validates an update feed URL (`https://download.runkiri.com/...` unless
/// `custom_feed` is true for `KIRI_UPDATE_URL`, or `file:///` in debug builds).
fn allowed_feed_url(url: &str, custom_feed: bool) -> io::Result<()> {
    if url.is_empty() || !url.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid update feed URL"));
    }
    if custom_feed && cfg!(debug_assertions) && url.starts_with("file:///") {
        return Ok(());
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(io::Error::other(format!("the update feed points at {url}, which is not https")));
    };
    if rest.contains('\\') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "backslash in update feed URL"));
    }
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    if authority.is_empty() || authority.contains('@') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid authority in update feed URL"));
    }
    let host = authority.split_once(':').map_or(authority, |(h, _)| h);
    if !custom_feed && !host.eq_ignore_ascii_case(DEFAULT_HOST) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("unexpected update feed host {host:?}"),
        ));
    }
    Ok(())
}

/// Kept as `allowed_url` for existing feed tests (`KIRI_UPDATE_URL` override semantics).
#[cfg(test)]
fn allowed_url(url: &str) -> io::Result<()> {
    allowed_feed_url(url, true)
}

/// Validates the MSI download URL from a feed: strict `https://download.runkiri.com/...`
/// (unless `custom_feed` is active via `KIRI_UPDATE_URL`), no credentials or query/fragment
/// tricks, and a clean `Kiri-*.msi` filename.
fn allowed_msi_url(url: &str, custom_feed: bool) -> io::Result<String> {
    if url.is_empty() || !url.bytes().all(|b| b.is_ascii_graphic()) || url.contains('\\') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid update MSI URL"));
    }
    let path = if custom_feed && cfg!(debug_assertions) && let Some(rest) = url.strip_prefix("file:///") {
        if rest.contains(['?', '#']) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "unexpected query or fragment in file MSI URL"));
        }
        rest
    } else if let Some(rest) = url.strip_prefix("https://") {
        if rest.contains(['?', '#']) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "unexpected query or fragment in MSI URL"));
        }
        let Some((authority, p)) = rest.split_once('/') else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "MSI URL has no filename path"));
        };
        if authority.is_empty() || authority.contains('@') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid authority in MSI URL"));
        }
        let host = authority.split_once(':').map_or(authority, |(h, _)| h);
        if !custom_feed && !host.eq_ignore_ascii_case(DEFAULT_HOST) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("refusing update MSI outside {DEFAULT_HOST}: {host}"),
            ));
        }
        p
    } else {
        return Err(io::Error::other(format!("the update MSI URL {url} is not https")));
    };
    let file_name = path.rsplit('/').next().unwrap_or("");
    if !valid_msi_filename(file_name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("refusing unexpected MSI filename {file_name:?}"),
        ));
    }
    Ok(file_name.to_owned())
}

/// Canonical message signed by `KIRI_UPDATE_PUBLIC_KEY`.
fn canonical_update_message(version: &str, url: &str, sha256: &str) -> String {
    format!("kiri-update-v1\n{}\n{}\n{}", version.trim(), url.trim(), sha256.trim().to_ascii_lowercase())
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

fn decode_base64_64(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().trim_end_matches('=');
    if s.is_empty() {
        return None;
    }
    let val = |b: u8| -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &b in s.as_bytes() {
        buf = (buf << 6) | u32::from(val(b)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

fn decode_signature_bytes(sig: &str) -> Option<Vec<u8>> {
    let s = sig.trim();
    if s.len() == 128 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        decode_hex(s)
    } else {
        decode_base64_64(s).filter(|b| b.len() == 64)
    }
}

/// Verifies `release.signature` against a 64-char hex Ed25519 public key.
fn verify_ed25519_with_key(pubkey_hex: &str, release: &Release) -> io::Result<()> {
    let pk = decode_hex(pubkey_hex)
        .filter(|b| b.len() == 32)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "KIRI_UPDATE_PUBLIC_KEY is not a 64-character hex Ed25519 public key"))?;
    let sig = decode_signature_bytes(&release.signature)
        .filter(|b| b.len() == 64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "update feed is missing a valid Ed25519 signature"))?;
    let msg = canonical_update_message(&release.version, &release.url, &release.sha256);
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &pk)
        .verify(msg.as_bytes(), &sig)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "update feed Ed25519 signature verification failed"))
}

/// Whether an MSI's Template summary property (`Arm64;1033`, `x64;1033`:
/// the platform `wix build -arch` set, then the languages) is for `arch`.
fn platform_matches(template: &str, arch: &str) -> bool {
    template.split(';').next().is_some_and(|p| p.trim().eq_ignore_ascii_case(arch))
}

fn staged_in(dir: &Path) -> Option<String> {
    if let Ok(bytes) = std::fs::read(dir.join("release.json"))
        && let Ok(rel) = serde_json::from_slice::<Release>(&bytes)
    {
        let version = rel.version.trim().strip_prefix('v').unwrap_or(rel.version.trim()).to_owned();
        if is_version(&version)
            && valid_sha256_hex(&rel.sha256)
            && dir.join(format!("Kiri-{version}.msi")).is_file()
            && newer(&version, CURRENT)
        {
            return Some(version);
        }
        return None;
    }
    let raw = std::fs::read_to_string(dir.join("version")).ok()?;
    let version = raw.trim().strip_prefix('v').unwrap_or(raw.trim()).to_owned();
    (is_version(&version) && dir.join(format!("Kiri-{version}.msi")).is_file() && newer(&version, CURRENT)).then_some(version)
}

/// `%LOCALAPPDATA%\Kiri` — refuses to fall back to `.` or world-writable `%TEMP%`.
#[cfg(windows)]
fn private_kiri_dir() -> io::Result<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")
        .filter(|d| !d.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "LOCALAPPDATA is not set"))?;
    let p = PathBuf::from(local);
    if !p.is_absolute() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "LOCALAPPDATA must be an absolute path"));
    }
    // Reject staging inside TEMP / TMP if LOCALAPPDATA was pointed there.
    for env_name in ["TEMP", "TMP"] {
        if let Some(t) = std::env::var_os(env_name).filter(|v| !v.is_empty()) {
            let tp = PathBuf::from(t);
            if p == tp {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "refusing to stage updates in TEMP"));
            }
        }
    }
    Ok(p.join("Kiri"))
}

/// `%LOCALAPPDATA%\Kiri`, for non-update callers (`sync_engine`, `catch_up_engine`).
#[cfg(windows)]
fn dir() -> PathBuf {
    private_kiri_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// Private per-user staging directory: `%LOCALAPPDATA%\Kiri\updates`.
#[cfg(windows)]
fn stage_dir() -> io::Result<PathBuf> {
    Ok(private_kiri_dir()?.join("updates"))
}

/// curl.exe, part of Windows: kiri-win has no HTTPS client of its own.
#[cfg(windows)]
fn curl() -> Command {
    let mut c = crate::win::tool("curl.exe");
    std::os::windows::process::CommandExt::creation_flags(&mut c, CREATE_NO_WINDOW);
    c.stdin(Stdio::null());
    c.arg("-A").arg(format!("kiri-win/{CURRENT}"));
    // Redirects stay on HTTPS too: by default curl follows one down to HTTP.
    c.args(["--proto", if cfg!(debug_assertions) { "=https,file" } else { "=https" }, "--proto-redir", "=https"]);
    c
}

#[cfg(windows)]
fn first_line(bytes: &[u8], fallback: &str) -> String {
    String::from_utf8_lossy(bytes).lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or(fallback).to_owned()
}

#[cfg(windows)]
fn custom_feed_url() -> Option<String> {
    std::env::var("KIRI_UPDATE_URL")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

#[cfg(windows)]
pub fn latest() -> io::Result<Release> {
    let custom = custom_feed_url();
    let is_custom = custom.is_some();
    let url = custom.as_deref().unwrap_or(FEED);
    allowed_feed_url(url, is_custom)?;
    let out = curl().args(["-fsSL", "--max-time", "20", "--max-filesize", "65536", "--"]).arg(url).output()?;
    if !out.status.success() {
        return Err(io::Error::other(first_line(&out.stderr, "could not fetch the update feed")));
    }
    let rel: Release = serde_json::from_slice(&out.stdout).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{url}: {e}")))?;
    if let Some(pk) = compiled_public_key() {
        verify_ed25519_with_key(pk, &rel)?;
    }
    Ok(rel)
}

/// The size the server says the file is, if it says.
#[cfg(windows)]
fn content_length(url: &str) -> Option<u64> {
    let out = curl().args(["-sIL", "--max-time", "20", "--"]).arg(url).output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_once(':'))
        .filter(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        .filter_map(|(_, v)| v.trim().parse::<u64>().ok())
        .next_back()
}

/// Opens `path` read-only with `FILE_SHARE_READ` only (no write/delete sharing)
/// so another process cannot mutate the MSI while we hash and verify it.
#[cfg(windows)]
fn open_locked_read(path: &Path) -> io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    std::fs::OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(path)
}

#[cfg(windows)]
fn sha256_of_file(mut file: &std::fs::File) -> io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Seek;
    file.seek(io::SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    file.seek(io::SeekFrom::Start(0))?;
    Ok(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Extracted Authenticode leaf signer identity for pinning `.msi` updates to
/// the running signed `kiri-win.exe`.
#[cfg(windows)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct SignerIdentity {
    spki_alg: String,
    spki_key: Vec<u8>,
    subject_der: Vec<u8>,
    issuer_der: Vec<u8>,
    display_name: String,
}

#[cfg(windows)]
impl SignerIdentity {
    fn matches(&self, other: &Self) -> bool {
        let key_match = !self.spki_key.is_empty() && self.spki_alg == other.spki_alg && self.spki_key == other.spki_key;
        let name_match = !self.subject_der.is_empty()
            && !self.issuer_der.is_empty()
            && self.subject_der == other.subject_der
            && self.issuer_der == other.issuer_der;
        key_match || name_match
    }
}

/// Runs `WinVerifyTrust` (`WINTRUST_ACTION_GENERIC_VERIFY_V2` +
/// `WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`). Returns `Ok(true)` when validly
/// signed, `Ok(false)` when unsigned (`TRUST_E_NOSIGNATURE`), or `Err` when
/// tampered/untrusted/revoked.
#[cfg(windows)]
fn win_verify_trust(path: &Path, file: Option<&std::fs::File>) -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CHOICE_FILE,
        WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    const TRUST_E_NOSIGNATURE: i32 = 0x800B_0100u32 as i32;
    let wide: Vec<u16> = path.to_string_lossy().encode_utf16().chain([0]).collect();
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: file.map_or(0, |f| f.as_raw_handle() as isize),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous = WINTRUST_DATA_0 { pFile: &mut file_info };
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;

    // SAFETY: `data` and `file_info` live across bothVERIFY and CLOSE calls.
    let status = unsafe { WinVerifyTrust(0, &mut action, (&mut data as *mut WINTRUST_DATA).cast()) };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        let _ = WinVerifyTrust(0, &mut action, (&mut data as *mut WINTRUST_DATA).cast());
    }

    match status {
        0 => Ok(true),
        TRUST_E_NOSIGNATURE => Ok(false),
        code => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Authenticode signature verification failed for {} (0x{:08x})", path.display(), code as u32),
        )),
    }
}

/// Extracts the leaf Authenticode signer certificate identity via
/// `CryptQueryObject` + `CryptMsgGetParam` + `CertFindCertificateInStore` +
/// `CertGetNameStringW`.
#[cfg(windows)]
fn extract_authenticode_signer(path: &Path) -> io::Result<SignerIdentity> {
    use windows_sys::Win32::Security::Cryptography::{
        CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, CertGetNameStringW, CryptMsgClose, CryptMsgGetParam,
        CryptQueryObject, CERT_CONTEXT, CERT_FIND_SUBJECT_CERT, CERT_INFO, CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_ENCODING_TYPE, CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE,
        CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, HCERTSTORE,
    };

    struct StoreGuard(HCERTSTORE);
    impl Drop for StoreGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = CertCloseStore(self.0, 0);
                }
            }
        }
    }
    struct MsgGuard(*mut core::ffi::c_void);
    impl Drop for MsgGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = CryptMsgClose(self.0);
                }
            }
        }
    }
    struct CertGuard(*const CERT_CONTEXT);
    impl Drop for CertGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = CertFreeCertificateContext(self.0);
                }
            }
        }
    }

    let wide: Vec<u16> = path.to_string_lossy().encode_utf16().chain([0]).collect();
    let mut encoding: CERT_QUERY_ENCODING_TYPE = 0;
    let mut store: HCERTSTORE = std::ptr::null_mut();
    let mut msg: *mut core::ffi::c_void = std::ptr::null_mut();

    // SAFETY: valid NUL-terminated UTF-16 path and local out-pointers.
    let ok = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide.as_ptr().cast(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &mut encoding,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut store,
            &mut msg,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cannot read embedded Authenticode signature from {}", path.display()),
        ));
    }
    let _store = StoreGuard(store);
    let _msg = MsgGuard(msg);

    let mut signer_len: u32 = 0;
    if unsafe { CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, std::ptr::null_mut(), &mut signer_len) } == 0 || signer_len == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "cannot read Authenticode signer info size"));
    }
    let mut signer_buf = vec![0u8; signer_len as usize];
    if unsafe { CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, signer_buf.as_mut_ptr().cast(), &mut signer_len) } == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "cannot read Authenticode signer info"));
    }
    // SAFETY: `CryptMsgGetParam` populated `CMSG_SIGNER_INFO` into `signer_buf`.
    let signer = unsafe { &*(signer_buf.as_ptr().cast::<CMSG_SIGNER_INFO>()) };
    let mut lookup: CERT_INFO = unsafe { std::mem::zeroed() };
    lookup.Issuer = signer.Issuer;
    lookup.SerialNumber = signer.SerialNumber;

    let cert_ptr = unsafe {
        CertFindCertificateInStore(
            store,
            encoding,
            0,
            CERT_FIND_SUBJECT_CERT,
            (&lookup as *const CERT_INFO).cast(),
            std::ptr::null(),
        )
    };
    if cert_ptr.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "signer certificate missing from Authenticode store"));
    }
    let _cert = CertGuard(cert_ptr);

    // SAFETY: `cert_ptr` is a valid `CERT_CONTEXT` from `CertFindCertificateInStore`.
    unsafe {
        let info = (*cert_ptr).pCertInfo;
        if info.is_null() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "signer certificate has no CERT_INFO"));
        }
        let spki_alg = if (*info).SubjectPublicKeyInfo.Algorithm.pszObjId.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr((*info).SubjectPublicKeyInfo.Algorithm.pszObjId.cast())
                .to_string_lossy()
                .into_owned()
        };
        let spki_key = std::slice::from_raw_parts(
            (*info).SubjectPublicKeyInfo.PublicKey.pbData,
            (*info).SubjectPublicKeyInfo.PublicKey.cbData as usize,
        )
        .to_vec();
        let subject_der = std::slice::from_raw_parts((*info).Subject.pbData, (*info).Subject.cbData as usize).to_vec();
        let issuer_der = std::slice::from_raw_parts((*info).Issuer.pbData, (*info).Issuer.cbData as usize).to_vec();

        let mut name_buf = [0u16; 256];
        let cch = CertGetNameStringW(
            cert_ptr,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            std::ptr::null(),
            name_buf.as_mut_ptr(),
            name_buf.len() as u32,
        );
        let display_name = if cch > 1 {
            String::from_utf16_lossy(&name_buf[..(cch as usize - 1).min(name_buf.len())])
        } else {
            String::new()
        };
        Ok(SignerIdentity { spki_alg, spki_key, subject_der, issuer_der, display_name })
    }
}

#[cfg(windows)]
fn running_exe_signer() -> io::Result<Option<SignerIdentity>> {
    let exe = std::env::current_exe()?;
    if !win_verify_trust(&exe, None)? {
        return Ok(None);
    }
    extract_authenticode_signer(&exe).map(Some)
}

/// Enforces update trust policy before staging or installing `msi_path`:
/// - If `KIRI_UPDATE_PUBLIC_KEY` is compiled in, `release.signature` MUST pass Ed25519 verification.
/// - If the running `kiri-win.exe` is Authenticode-signed, `msi_path` MUST carry a valid
///   Authenticode signature whose leaf certificate matches `kiri-win.exe`.
/// - Otherwise (unsigned `kiri-win.exe`), allow install ONLY if `KIRI_UPDATE_PUBLIC_KEY`
///   is compiled in AND `release.signature` passed Ed25519 verification (or if `msi_path`
///   has a valid Authenticode signature when `KIRI_UPDATE_PUBLIC_KEY` is set); an unsigned
///   build without `KIRI_UPDATE_PUBLIC_KEY` refuses silent `msiexec /qn` auto-install and
///   directs the user to `https://runkiri.com/releases/`.
#[cfg(windows)]
fn verify_msi_trust(msi_path: &Path, msi_file: &std::fs::File, release: &Release) -> io::Result<()> {
    let ed25519_verified = match compiled_public_key() {
        Some(pk) => {
            verify_ed25519_with_key(pk, release)?;
            true
        }
        None => false,
    };

    let msi_signed = win_verify_trust(msi_path, Some(msi_file))?;
    if let Some(exe_signer) = running_exe_signer()? {
        if !msi_signed {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the downloaded MSI is not Authenticode-signed",
            ));
        }
        let msi_signer = extract_authenticode_signer(msi_path)?;
        if !msi_signer.matches(&exe_signer) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "the update MSI signer ({}) does not match this Kiri installation ({})",
                    msi_signer.display_name, exe_signer.display_name
                ),
            ));
        }
        return Ok(());
    }

    if ed25519_verified {
        return Ok(());
    }

    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "cannot verify update authenticity on an unsigned Kiri build; download the latest release from {RELEASES_URL}"
        ),
    ))
}

/// Downloads `release`, checks it and stages it for `install_staged`.
/// `progress` gets the bytes so far and the total when known; setting
/// `cancel` stops the download.
#[cfg(windows)]
pub fn download(release: &Release, progress: &mut dyn FnMut(u64, Option<u64>), cancel: &AtomicBool) -> io::Result<()> {
    if !newer(&release.version, CURRENT) {
        return Err(io::Error::other(format!("Kiri {} is not newer than this {CURRENT}", release.version)));
    }
    if !valid_sha256_hex(&release.sha256) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "update feed has an invalid SHA-256 digest"));
    }
    let is_custom = custom_feed_url().is_some();
    let _msi_name = allowed_msi_url(&release.url, is_custom)?;
    if let Some(pk) = compiled_public_key() {
        verify_ed25519_with_key(pk, release)?;
    } else if running_exe_signer()?.is_none() {
        // Fail fast before downloading 55 MB if this unsigned build cannot auto-install updates.
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "cannot verify update authenticity on an unsigned Kiri build; download the latest release from {RELEASES_URL}"
            ),
        ));
    }
    let dir = stage_dir()?;
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let result = fetch_and_check(release, &dir, progress, cancel);
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    result
}

#[cfg(windows)]
fn fetch_and_check(release: &Release, dir: &Path, progress: &mut dyn FnMut(u64, Option<u64>), cancel: &AtomicBool) -> io::Result<()> {
    let part = dir.join("Kiri.msi.part");
    let total = if release.size > 0 { Some(release.size) } else { content_length(&release.url) };
    let mut child = curl()
        .args(["-fsSL", "--retry", "3", "--max-time", "3600", "--max-filesize", &MAX_DOWNLOAD.to_string(), "-o"])
        .arg(&part)
        .arg("--")
        .arg(&release.url)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stderr = child.stderr.take();
    loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        let got = std::fs::metadata(&part).map_or(0, |m| m.len());
        progress(got, total);
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                let mut err = Vec::new();
                if let Some(mut e) = stderr.take() {
                    let _ = e.read_to_end(&mut err);
                }
                return Err(io::Error::other(first_line(&err, "downloading the update failed: check the internet connection")));
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(150));
    }

    let expected_sha = release.sha256.trim().to_ascii_lowercase();
    {
        let locked = open_locked_read(&part)?;
        let got = locked.metadata()?.len();
        if got > MAX_DOWNLOAD {
            return Err(io::Error::other("the update is larger than any Kiri release"));
        }
        progress(got, Some(total.unwrap_or(got)));
        let sum = sha256_of_file(&locked)?;
        if sum != expected_sha {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("download does not match its SHA-256 (got {sum})")));
        }
        verify_msi_trust(&part, &locked, release)?;
    }
    check(&part, &release.version)?;
    // Re-verify SHA-256 under a fresh read-locked handle after msi.dll inspection.
    {
        let locked = open_locked_read(&part)?;
        if sha256_of_file(&locked)? != expected_sha {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "downloaded MSI changed during verification"));
        }
    }

    let clean_ver = release.version.trim().trim_start_matches('v');
    let msi = dir.join(format!("Kiri-{clean_ver}.msi"));
    std::fs::rename(&part, &msi)?;
    let mut stored = release.clone();
    stored.version = clean_ver.to_owned();
    stored.sha256 = expected_sha;
    std::fs::write(dir.join("release.json"), serde_json::to_vec(&stored).map_err(io::Error::other)?)?;
    std::fs::write(dir.join("version"), clean_ver)?;
    let _ = std::fs::remove_file(dir.join("attempted"));
    Ok(())
}

#[cfg(windows)]
fn staged_msi(dir: &Path, version: &str) -> PathBuf {
    dir.join(format!("Kiri-{version}.msi"))
}

/// The staged update's version, when there is one newer than this build.
#[cfg(windows)]
pub fn staged() -> Option<String> {
    stage_dir().ok().and_then(|d| staged_in(&d))
}

/// Re-verifies the staged MSI's metadata, SHA-256, Authenticode / Ed25519
/// signature, and MSI properties right before launching `kiri.ps1 -Update`.
#[cfg(windows)]
fn verify_staged() -> io::Result<(String, String, PathBuf)> {
    let dir = stage_dir()?;
    let Some(version) = staged_in(&dir) else {
        return Err(io::Error::other("no update is staged"));
    };
    let rel_bytes = std::fs::read(dir.join("release.json"))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "staged update metadata is missing"))?;
    let rel: Release = serde_json::from_slice(&rel_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("staged update metadata is invalid: {e}")))?;
    if !valid_sha256_hex(&rel.sha256) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "staged update has an invalid SHA-256"));
    }
    let _ = allowed_msi_url(&rel.url, custom_feed_url().is_some())?;
    let expected_sha = rel.sha256.trim().to_ascii_lowercase();
    let msi = staged_msi(&dir, &version);
    {
        let locked = open_locked_read(&msi)?;
        let actual_sha = sha256_of_file(&locked)?;
        if actual_sha != expected_sha {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "staged MSI does not match its expected SHA-256"));
        }
        verify_msi_trust(&msi, &locked, &rel)?;
    }
    check(&msi, &version)?;
    {
        let locked = open_locked_read(&msi)?;
        if sha256_of_file(&locked)? != expected_sha {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "staged MSI changed during verification"));
        }
    }
    Ok((version, expected_sha, msi))
}

/// A helper was left to install the staged update; it removes the stage
/// when it is done, so this still being here at a launch means it failed
/// (or has not run yet).
#[cfg(windows)]
pub fn attempted() -> bool {
    stage_dir().is_ok_and(|d| d.join("attempted").is_file())
}

/// Checks the staged MSI again, then leaves `kiri.ps1 -Update` behind to verify
/// SHA-256 + Authenticode and install once this process exits.
#[cfg(windows)]
pub fn install_staged() -> io::Result<String> {
    let stage = stage_dir()?;
    let (version, sha256, msi) = verify_staged()?;
    std::fs::write(stage.join("attempted"), "")?;
    let script = crate::setup::verified("kiri.ps1")?;
    let spawn = |flags: u32| {
        let mut cmd = crate::win::tool("powershell.exe");
        std::os::windows::process::CommandExt::creation_flags(&mut cmd, flags);
        cmd.args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File"])
            .arg(&script)
            .args(["-Update", "-Msi"])
            .arg(&msi)
            .args(["-Sha256", &sha256, "-WaitFor"])
            .arg(std::process::id().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    };
    spawn(CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB).or_else(|_| spawn(CREATE_NO_WINDOW))?;
    crate::serve::log(&format!("update: installing Kiri {version} after quit"));
    Ok(version)
}

/// Puts the engine binaries the MSI installed into the WSL distro and
/// restarts the daemon (and the bridge, which serve restarts on the new
/// binary). Running containers stop; those with a restart policy start again.
#[cfg(windows)]
pub fn restart_engine() -> io::Result<()> {
    let distro = crate::setup::saved_distro().ok_or_else(|| io::Error::other("Kiri's Linux is not set up"))?;
    let script = if distro == crate::setup::KIRI_DISTRO {
        format!("( {} ) >/dev/null || exit 1; pkill -f '/usr/local/bin/[k]iri bridge'; /usr/local/bin/kiri-start --restart", crate::wslsync::sync_script(&dir(), "", true))
    } else {
        let install = crate::setup::to_wsl(&distro, &dir().join("install.sh"))?;
        format!("sh {} && pkill -f '/usr/local/bin/[k]iri bridge'; true", crate::wslsync::sh_quote(&install))
    };
    let mut cmd = crate::win::tool("wsl.exe");
    std::os::windows::process::CommandExt::creation_flags(&mut cmd, CREATE_NO_WINDOW);
    let out = output_within(cmd.args(crate::wslsync::wsl_sh(&distro, &script)), RESTART_LIMIT)?;
    if !out.status.success() {
        if let Some(ro) = crate::engine::probe_wsl_readonly(Some(&distro)) {
            return Err(io::Error::other(ro));
        }
        return Err(io::Error::other(first_line(&out.stderr, "the engine did not restart")));
    }
    let began = Instant::now();
    let mut last = None;
    while began.elapsed() < Duration::from_secs(60) {
        if let Some(v) = crate::client::request("GET", "/version", None).ok().filter(|r| r.ok()).and_then(|r| crate::client::kiri_version(&r.json()).map(str::to_owned)) {
            if v == CURRENT {
                return Ok(());
            }
            last = Some(v);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(io::Error::other(match last {
        Some(v) => format!("the engine came back on {v}, not {CURRENT}"),
        None => "the engine did not come back".to_owned(),
    }))
}

/// Whether `msi` is a Kiri installer of the version `promised`, newer than
/// this build.
#[cfg(windows)]
fn check(msi: &Path, promised: &str) -> io::Result<()> {
    let upgrade = msi_property(msi, "UpgradeCode")?;
    if !upgrade.trim().eq_ignore_ascii_case(UPGRADE_CODE) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "the update is not a Kiri installer"));
    }
    let template = msi_template(msi)?;
    if !platform_matches(&template, crate::win::BUILD_ARCH) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("the update is Kiri for {}, not for this {} Kiri", template.split(';').next().unwrap_or("another platform"), crate::win::BUILD_ARCH)));
    }
    let version = msi_property(msi, "ProductVersion")?;
    let (version, promised) = (version.trim(), promised.trim_start_matches('v'));
    if version != promised {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("the update is Kiri {version}, but the feed promised {promised}")));
    }
    if !newer(version, CURRENT) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("the update is Kiri {version}, which is not newer than this {CURRENT}")));
    }
    Ok(())
}

/// One value from the MSI's Property table, read with Windows Installer
/// itself (msi.dll). `name` is one of our own constants, never input.
#[cfg(windows)]
fn msi_property(msi: &Path, name: &str) -> io::Result<String> {
    use windows_sys::Win32::System::ApplicationInstallationAndServicing::{
        MsiCloseHandle, MsiDatabaseOpenViewW, MsiOpenDatabaseW, MsiRecordGetStringW, MsiViewExecute, MsiViewFetch, MSIDBOPEN_READONLY, MSIHANDLE,
    };
    struct Handle(MSIHANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe { MsiCloseHandle(self.0) };
            }
        }
    }
    const ERROR_MORE_DATA: u32 = 234;
    const ERROR_NO_MORE_ITEMS: u32 = 259;
    let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let fail = |what: &str, code: u32| io::Error::other(format!("cannot read the installer ({what}: error {code})"));
    let path = wide(&msi.to_string_lossy());
    let query = wide(&format!("SELECT `Value` FROM `Property` WHERE `Property` = '{name}'"));
    let mut db = Handle(0);
    unsafe {
        let r = MsiOpenDatabaseW(path.as_ptr(), MSIDBOPEN_READONLY, &mut db.0);
        if r != 0 {
            return Err(fail("open", r));
        }
        let mut view = Handle(0);
        let r = MsiDatabaseOpenViewW(db.0, query.as_ptr(), &mut view.0);
        if r != 0 {
            return Err(fail("query", r));
        }
        let r = MsiViewExecute(view.0, 0);
        if r != 0 {
            return Err(fail("execute", r));
        }
        let mut rec = Handle(0);
        let r = MsiViewFetch(view.0, &mut rec.0);
        if r == ERROR_NO_MORE_ITEMS {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("the installer has no {name}")));
        }
        if r != 0 {
            return Err(fail("fetch", r));
        }
        let mut len: u32 = 1;
        let mut buf: Vec<u16> = vec![0; 1];
        let r = MsiRecordGetStringW(rec.0, 1, buf.as_mut_ptr(), &mut len);
        if r == ERROR_MORE_DATA {
            buf = vec![0; len as usize + 1];
            len += 1;
            let r = MsiRecordGetStringW(rec.0, 1, buf.as_mut_ptr(), &mut len);
            if r != 0 {
                return Err(fail("read", r));
            }
        } else if r != 0 {
            return Err(fail("read", r));
        }
        Ok(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// The MSI's Template summary property, read with msi.dll.
#[cfg(windows)]
fn msi_template(msi: &Path) -> io::Result<String> {
    use windows_sys::Win32::System::ApplicationInstallationAndServicing::{MsiCloseHandle, MsiGetSummaryInformationW, MsiSummaryInfoGetPropertyW, MSIHANDLE};
    struct Handle(MSIHANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe { MsiCloseHandle(self.0) };
            }
        }
    }
    const PID_TEMPLATE: u32 = 7;
    let fail = |what: &str, code: u32| io::Error::other(format!("cannot read the installer ({what}: error {code})"));
    let path: Vec<u16> = msi.to_string_lossy().encode_utf16().chain([0]).collect();
    let mut info = Handle(0);
    unsafe {
        let r = MsiGetSummaryInformationW(0, path.as_ptr(), 0, &mut info.0);
        if r != 0 {
            return Err(fail("summary", r));
        }
        let (mut kind, mut int, mut time) = (0u32, 0i32, std::mem::zeroed());
        let mut buf = [0u16; 256];
        let mut len = buf.len() as u32;
        let r = MsiSummaryInfoGetPropertyW(info.0, PID_TEMPLATE, &mut kind, &mut int, &mut time, buf.as_mut_ptr(), &mut len);
        if r != 0 {
            return Err(fail("template", r));
        }
        Ok(String::from_utf16_lossy(&buf[..(len as usize).min(buf.len())]))
    }
}

// The window's side: what the page is told, and what its card asks for.

#[cfg(windows)]
static CANCEL: AtomicBool = AtomicBool::new(false);
#[cfg(windows)]
static RUNNING: AtomicBool = AtomicBool::new(false);

#[cfg(windows)]
fn update_state(state: &str, latest: Option<&str>, error: Option<String>) {
    let checked = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
    emit(json!({"type": "updatestate", "state": state, "current": CURRENT, "latest": latest, "error": error, "checked": checked}).to_string());
}

#[cfg(windows)]
pub fn check_now(manual: bool) {
    std::thread::spawn(move || {
        if !manual {
            catch_up_engine();
        } else if let Some(v) = engine_version()
            && newer(CURRENT, &v)
        {
            emit(json!({"type": "enginestale", "version": v}).to_string());
        }
        feed_check(manual);
    });
    recheck::start(|| feed_check(false));
}

#[cfg(windows)]
fn feed_check(manual: bool) {
    if CURRENT.contains("-dev") {
        if manual {
            emit(notice("ok", &trf("Kiri {version} is a test build: it doesn't update itself", &[("version", &CURRENT)])));
        }
        update_state("test", None, None);
        return;
    }
    if let Some(v) = staged() {
        emit(json!({"type": "updateready", "version": v}).to_string());
        return;
    }
    if !manual && crate::engine::prefs()["updateAuto"] == false {
        return;
    }
    recheck::checked();
    match latest() {
        Ok(r) if newer(&r.version, CURRENT) => {
            update_state("available", Some(&r.version), None);
            emit(json!({"type": "update", "release": r, "current": CURRENT, "manual": manual}).to_string());
        }
        Ok(_) => {
            update_state("uptodate", None, None);
            if manual {
                emit(notice("ok", &trf("Kiri {version} is the newest version", &[("version", &CURRENT)])));
            }
        }
        Err(e) => {
            update_state("error", None, Some(e.to_string()));
            if manual {
                emit(notice("error", &trf("Couldn't check for updates: {error}", &[("error", &e)])));
            }
        }
    }
}

#[cfg(windows)]
pub fn download_now() {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    CANCEL.store(false, Ordering::Relaxed);
    let _ = std::thread::Builder::new().name("kiri-update".into()).spawn(|| {
        let result = latest().and_then(|r| {
            let mut last = Instant::now() - Duration::from_secs(1);
            download(
                &r,
                &mut |got, total| {
                    if last.elapsed() >= Duration::from_millis(250) {
                        last = Instant::now();
                        emit(json!({"type": "updateprogress", "got": got, "total": total}).to_string());
                    }
                },
                &CANCEL,
            )
            .map(|()| r.version)
        });
        RUNNING.store(false, Ordering::SeqCst);
        emit(match result {
            Ok(v) => json!({"type": "updateready", "version": v}).to_string(),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => r#"{"type":"updatecancelled"}"#.to_owned(),
            Err(e) => json!({"type": "updateerror", "error": e.to_string()}).to_string(),
        });
    });
}

#[cfg(windows)]
pub fn cancel_download() {
    CANCEL.store(true, Ordering::Relaxed);
}

#[cfg(windows)]
pub fn restart_now() {
    match verify_staged() {
        Ok(_) => crate::app::Handle.run(|_| {
            // SAFETY: ends this thread's message loop; run on the window's thread.
            unsafe { windows::Win32::UI::WindowsAndMessaging::PostQuitMessage(0) }
        }),
        Err(e) => emit(json!({"type": "updateerror", "error": e.to_string()}).to_string()),
    }
}

#[cfg(windows)]
pub fn sync_engine() -> io::Result<bool> {
    if !dir().join("kiri").is_file() || !dir().join("kiri-init").is_file() {
        return Ok(false);
    }
    let distro = crate::setup::saved_distro().ok_or_else(|| io::Error::other("Kiri's Linux is not set up"))?;
    let script = crate::wslsync::sync_script(&dir(), "", distro == crate::setup::KIRI_DISTRO);
    let mut cmd = crate::win::tool("wsl.exe");
    std::os::windows::process::CommandExt::creation_flags(&mut cmd, CREATE_NO_WINDOW);
    let out = output_within(cmd.args(crate::wslsync::wsl_sh(&distro, &script)), WSL_LIMIT)?;
    if !out.status.success() {
        if let Some(ro) = crate::engine::probe_wsl_readonly(Some(&distro)) {
            return Err(io::Error::other(ro));
        }
        return Err(io::Error::other(first_line(&out.stderr, "could not copy the engine into WSL")));
    }
    Ok(String::from_utf8_lossy(&out.stdout).contains("copied"))
}

#[cfg(windows)]
pub(crate) const WSL_LIMIT: Duration = Duration::from_secs(60);
#[cfg(windows)]
const RESTART_LIMIT: Duration = Duration::from_secs(240);

#[cfg(windows)]
pub(crate) fn output_within(cmd: &mut Command, limit: Duration) -> io::Result<std::process::Output> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let drain = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut r) = pipe {
                let _ = r.read_to_end(&mut buf);
            }
            buf
        })
    };
    let out_reader = drain(child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
    let err_reader = drain(child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
    let ms = u32::try_from(limit.as_millis()).unwrap_or(u32::MAX - 1);
    let waited = unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(child.as_raw_handle() as _, ms) };
    if waited == WAIT_TIMEOUT {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::new(io::ErrorKind::TimedOut, format!("WSL did not finish in {} s", limit.as_secs())));
    }
    if waited != WAIT_OBJECT_0 {
        let err = io::Error::last_os_error();
        let _ = child.kill();
        let _ = child.wait();
        return Err(err);
    }
    let status = child.wait()?;
    let stdout = out_reader.join().unwrap_or_default();
    let stderr = err_reader.join().unwrap_or_default();
    Ok(std::process::Output { status, stdout, stderr })
}

#[cfg(windows)]
fn engine_version() -> Option<String> {
    if crate::serve::is_stopped() {
        return None;
    }
    crate::client::get_background("/version").ok().and_then(|v| crate::client::kiri_version(&v).map(str::to_owned))
}

#[cfg(windows)]
static CATCH_UP: crate::wslsync::CatchUp = crate::wslsync::CatchUp::new();

#[cfg(windows)]
pub fn catch_up_engine() {
    if !dir().join("kiri").is_file() {
        return;
    }
    CATCH_UP.run(
        engine_version,
        |v| newer(CURRENT, v),
        |v| {
            crate::serve::log(&format!("update: the engine runs {v}, this Kiri is {CURRENT}; restarting it"));
            emit(json!({"type": "state", "state": "booting"}).to_string());
            restart_and_report();
        },
    );
}

#[cfg(windows)]
pub fn restart_engine_now() {
    std::thread::spawn(restart_and_report);
}

#[cfg(windows)]
fn restart_and_report() {
    let began = Instant::now();
    match restart_engine() {
        Ok(()) => {
            emit(r#"{"type":"enginestale","version":null}"#.to_owned());
            emit(json!({"type": "enginerestarted", "version": CURRENT, "ms": began.elapsed().as_millis() as u64}).to_string());
        }
        Err(e) => {
            crate::serve::log(&format!("engine: did not restart ({e})"));
            emit(json!({"type": "enginerestarted", "error": e.to_string()}).to_string());
            emit(notice("error", &trf("Could not restart the engine: {error}", &[("error", &e)])));
            if let Some(v) = engine_version()
                && newer(CURRENT, &v)
            {
                emit(json!({"type": "enginestale", "version": v}).to_string());
            }
        }
    }
    crate::engine::send(crate::engine::Cmd::Refresh);
}

#[cfg(test)]
mod tests {
    use super::{newer, Release};

    #[test]
    fn compares_versions() {
        assert!(newer("0.2.0", "0.1.9"));
        assert!(newer("1.2.10", "1.2.9"));
        assert!(newer("v1.0.1", "1.0"));
        assert!(!newer("1.0.0", "1.0"));
        assert!(!newer("0.1.0", "0.1.0"));
        assert!(!newer("0.1.0", "0.2.0"));
        // A test build (scripts/ci/test-version.sh) sorts above its release.
        assert!(newer("0.1.8-dev.42", "0.1.8"));
        assert!(!newer("0.1.8", "0.1.8-dev.42"));
        assert!(newer("0.1.8-dev.43", "0.1.8-dev.42"));
        for bad in ["", "vv1.0.0", "1.+2.0", "1.2.", "1.2.0-", "1.2.0-rc..1", "99.0.0/../../evil", r"99.0.0\evil", "99.0.0:ads"] {
            assert!(!newer(bad, "0.2.0"), "accepted invalid candidate {bad:?}");
            assert!(!newer("99.0.0", bad), "accepted invalid current {bad:?}");
        }
    }

    #[test]
    fn staged_rejects_traversal_and_verifies_metadata() {
        let tmp = std::env::temp_dir().join(format!("kiri-win-update-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let stage = tmp.join("Kiri").join("updates");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(tmp.join("evil.msi"), b"fake").unwrap();
        std::fs::write(stage.join("version"), "99.0.0/../../../evil").unwrap();
        assert_eq!(super::staged_in(&stage), None);

        std::fs::write(stage.join("Kiri-99.1.2.msi"), b"msi").unwrap();
        std::fs::write(stage.join("version"), "v99.1.2\n").unwrap();
        assert_eq!(super::staged_in(&stage).as_deref(), Some("99.1.2"));
        let _ = std::fs::remove_dir_all(&tmp);

        #[cfg(windows)]
        {
            let mut cmd = crate::win::tool("powershell.exe");
            cmd.args(["-NoProfile", "-NonInteractive", "-Command", "[Console]::Out.Write('A' * 131072); [Console]::Error.Write('B' * 131072)"]);
            let out = super::output_within(&mut cmd, std::time::Duration::from_secs(15)).unwrap();
            assert!(out.status.success());
            assert_eq!(out.stdout.len(), 131_072);
            assert_eq!(out.stderr.len(), 131_072);
        }
    }

    #[test]
    fn reads_feeds_with_and_without_extras() {
        let r: Release = serde_json::from_str(r#"{"version":"0.1.1","url":"https://x/K.msi","sha256":"ab"}"#).unwrap();
        assert_eq!((r.notes_url.as_str(), r.size, r.signature.as_str()), ("", 0, ""));
        let r: Release = serde_json::from_str(r#"{"version":"0.1.1","url":"u","sha256":"ab","signature":"cd","notes_url":"https://runkiri.com/","size":5}"#).unwrap();
        assert_eq!((r.notes_url.as_str(), r.size, r.signature.as_str()), ("https://runkiri.com/", 5, "cd"));
    }

    #[test]
    fn only_https_feeds_and_strict_msi_urls() {
        assert!(super::allowed_url("https://download.runkiri.com/latest-windows-x86_64.json").is_ok());
        assert_eq!(super::allowed_url("file:///C:/t/latest.json").is_ok(), cfg!(debug_assertions));
        assert!(super::allowed_url("http://download.runkiri.com/latest-windows-x86_64.json").is_err());
        assert!(super::allowed_url("ftp://x/y").is_err());
        assert!(super::allowed_feed_url("https://evil.example/latest.json", false).is_err());

        assert_eq!(
            super::allowed_msi_url("https://download.runkiri.com/releases/Kiri-0.9.5-x86_64.msi", false).unwrap(),
            "Kiri-0.9.5-x86_64.msi"
        );
        for bad in [
            "http://download.runkiri.com/Kiri-0.9.5-x86_64.msi",
            "https://evil.example/Kiri-0.9.5-x86_64.msi",
            "https://download.runkiri.com@evil.example/Kiri-0.9.5-x86_64.msi",
            "https://download.runkiri.com/Kiri-0.9.5-x86_64.msi?x=1",
            "https://download.runkiri.com/other.exe",
            "https://download.runkiri.com/Kiri-..msi",
            "https://download.runkiri.com/setup.msi",
        ] {
            assert!(super::allowed_msi_url(bad, false).is_err(), "{bad}");
        }
    }

    #[test]
    fn verifies_detached_ed25519_signatures_in_hex_and_base64() {
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pub_hex: String = kp.public_key().as_ref().iter().map(|b| format!("{b:02x}")).collect();

        let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let url = "https://download.runkiri.com/Kiri-99.0.0-x86_64.msi";
        let msg = super::canonical_update_message("99.0.0", url, sha);
        let sig = kp.sign(msg.as_bytes());
        let sig_hex: String = sig.as_ref().iter().map(|b| format!("{b:02x}")).collect();

        let rel = Release {
            version: "99.0.0".into(),
            url: url.into(),
            sha256: sha.to_ascii_uppercase(),
            signature: sig_hex,
            ..Default::default()
        };
        assert!(super::verify_ed25519_with_key(&pub_hex, &rel).is_ok());

        // Base64 encoding of the same 64-byte signature also verifies.
        const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut sig_b64 = String::new();
        for c in sig.as_ref().chunks(3) {
            let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
            for i in 0..4 {
                sig_b64.push(if i <= c.len() { B64[((n >> (18 - 6 * i)) & 63) as usize] as char } else { '=' });
            }
        }
        let rel_b64 = Release { signature: sig_b64, ..rel.clone() };
        assert!(super::verify_ed25519_with_key(&pub_hex, &rel_b64).is_ok());

        // Tampered version, URL, SHA-256, or missing signature fails.
        let tampered_url = Release { url: "https://download.runkiri.com/Kiri-99.0.1-x86_64.msi".into(), ..rel.clone() };
        assert!(super::verify_ed25519_with_key(&pub_hex, &tampered_url).is_err());
        let no_sig = Release { signature: String::new(), ..rel };
        assert!(super::verify_ed25519_with_key(&pub_hex, &no_sig).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn reads_this_installer_when_built() {
        let name = if cfg!(target_arch = "aarch64") { "arm64" } else { "x86_64" };
        let msi = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target").join(format!("Kiri-{}-{name}.msi", env!("CARGO_PKG_VERSION")));
        if msi.is_file() {
            assert_eq!(super::msi_property(&msi, "ProductVersion").unwrap(), env!("CARGO_PKG_VERSION"));
            assert!(super::msi_property(&msi, "UpgradeCode").unwrap().eq_ignore_ascii_case(super::UPGRADE_CODE));
            assert!(super::platform_matches(&super::msi_template(&msi).unwrap(), crate::win::BUILD_ARCH));
        }
    }

    #[test]
    fn only_this_platforms_installer() {
        assert!(super::platform_matches("x64;1033", "x64"));
        assert!(super::platform_matches("Arm64;1033", "arm64"));
        assert!(!super::platform_matches("x64;1033", "arm64"));
        assert!(!super::platform_matches("Arm64;1033", "x64"));
        assert!(!super::platform_matches("Intel;1033", "x64"));
    }
}
