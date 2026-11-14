//! Pull-through mirrors of Docker Hub, as Settings → Registry mirrors
//! stores them: a host (with an optional port) and, for mirrors that keep
//! the upstream registry in the path (`mirror.example.com/docker.io`, say), a
//! path prefix. As Docker's `registry-mirrors`, they apply to `docker.io`
//! only: other registries are pulled from directly.

use crate::reference::is_local;

/// One mirror: `host` is a bare `host[:port]`, as `Reference::registry` is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mirror {
    pub host: String,
    pub prefix: Option<String>,
}

impl Mirror {
    /// Parses what a person types in Settings or passes to
    /// `kiri registry-mirror add`: `mirror.example.com`, `https://mirror.example.com`,
    /// `https://mirror.example.com/docker.io`, `127.0.0.1:5000`.
    ///
    /// A mirror is HTTPS, as Docker's are; a loopback one is plain HTTP, as
    /// every local registry is. A trailing `/v2` is not part of the address.
    pub fn parse(input: &str) -> Result<Mirror, String> {
        let text = input.trim();
        if text.is_empty() {
            return Err("a mirror address cannot be empty".into());
        }
        let with_scheme = if text.contains("://") { text.to_owned() } else { format!("https://{text}") };
        let uri: ureq::http::Uri = with_scheme.parse().map_err(|_| format!("not an address: {text}"))?;
        let scheme = uri.scheme_str().unwrap_or("https").to_ascii_lowercase();
        let authority = uri.authority().ok_or_else(|| format!("no host in {text}"))?;
        if authority.as_str().contains('@') {
            return Err(format!("a mirror address has no username or password: {text}"));
        }
        let host = authority.as_str().to_ascii_lowercase();
        if host.is_empty() || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b".-[]:_".contains(&b)) {
            return Err(format!("not a host name: {host}"));
        }
        if scheme != "https" && !(scheme == "http" && is_local(&host)) {
            return Err(format!("a mirror must be https (a local one may be http): {text}"));
        }
        // Both `https://host` and `https://host/v2` name the same service.
        let path = uri.path().trim_matches('/');
        let path = if path == "v2" { "" } else { path.strip_suffix("/v2").unwrap_or(path) };
        let path = path.trim_matches('/');
        if !path.is_empty() && !path.bytes().all(|b| b.is_ascii_alphanumeric() || b".-_/".contains(&b)) {
            return Err(format!("not a mirror path: {path}"));
        }
        Ok(Mirror { host, prefix: (!path.is_empty()).then(|| path.to_owned()) })
    }

    /// What Settings shows and `kiri registry-mirror list` prints.
    pub fn as_url(&self) -> String {
        let scheme = if self.is_local() { "http" } else { "https" };
        match &self.prefix {
            Some(prefix) => format!("{scheme}://{}/{prefix}", self.host),
            None => format!("{scheme}://{}", self.host),
        }
    }

    /// BuildKit's `mirrors` entry: `host`, or `host/prefix` for a mirror that
    /// keeps the upstream in the path.
    pub fn buildkit(&self) -> String {
        match &self.prefix {
            Some(prefix) => format!("{}/{prefix}", self.host),
            None => self.host.clone(),
        }
    }

    pub fn is_local(&self) -> bool {
        is_local(&self.host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_addresses_people_type() {
        let m = Mirror::parse("mirror.example.com").unwrap();
        assert_eq!(m.host, "mirror.example.com");
        assert_eq!(m.prefix, None);
        assert_eq!(m.as_url(), "https://mirror.example.com");

        assert_eq!(Mirror::parse("https://Mirror.Example.com/").unwrap().as_url(), "https://mirror.example.com");
        assert_eq!(Mirror::parse("https://mirror.example.net/docker.io").unwrap().prefix.as_deref(), Some("docker.io"));
        assert_eq!(Mirror::parse("https://mirror.example.com/v2").unwrap().prefix, None);
        assert_eq!(Mirror::parse("127.0.0.1:5000").unwrap().as_url(), "http://127.0.0.1:5000");
        assert_eq!(Mirror::parse("https://127.0.0.1:5000").unwrap().as_url(), "http://127.0.0.1:5000");
        assert_eq!(Mirror::parse("https://mirror.example.net/docker.io").unwrap().buildkit(), "mirror.example.net/docker.io");
    }

    #[test]
    fn refuses_what_is_not_a_mirror() {
        for bad in ["", "   ", "https://", "ftp://mirror.example.com", "http://mirror.example.com", "https://user:pw@mirror.example.com", "https://mirror.example.com/a b"] {
            assert!(Mirror::parse(bad).is_err(), "{bad:?} should be refused");
        }
    }
}
