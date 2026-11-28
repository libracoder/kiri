//! Which addresses the window may hand to the person's browser, and which
//! names may become a container's local address. Shared by the Mac and
//! Linux window (crates/kiri) and the Windows app (crates/kiri-win, by
//! `#[path]`), and by the engine for `dev.kiri.domain`.
//!
//! A small hand-written reader of the URL rules, not a general URL parser:
//! it only has to say yes to the few shapes Kiri opens, and no to anything
//! a browser could read as another host.

/// Kiri's own pages, opened as they are written.
const EXACT: [&str; 13] = [
    "https://runkiri.com",
    "https://runkiri.com/releases/",
    "https://runkiri.com/share/notice",
    "https://canestack.com",
    "https://kiri.canestack.com",
    "https://discord.gg/K5A8wuqcC",
    "https://x.com/runkiri",
    "https://github.com/libracoder/kiri",
    "https://github.com/libracoder/kiri/issues/new",
    "https://github.com/anchore/grype",
    "https://github.com/login/device",
    "https://login.docker.com/activate",
    "https://learn.microsoft.com/windows/wsl/about",
];

/// A page link the window may open: one of Kiri's own pages, a build
/// warning's rule page on docs.docker.com/go/, or a container's local
/// address (`localhost`, `*.kiri.localhost`, `*.kiri.local`, any port).
pub fn allowed(url: &str) -> bool {
    // Nothing a browser would strip, fold or read as a separator: no
    // spaces, tabs, line breaks or other control characters, no
    // backslashes and nothing outside ASCII (a look-alike host).
    if url.is_empty() || !url.bytes().all(|b| b.is_ascii_graphic() && b != b'\\') {
        return false;
    }
    if EXACT.contains(&url) {
        return true;
    }
    if let Some(rest) = url.strip_prefix("https://docs.docker.com/go/") {
        return !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b"-/".contains(&b));
    }
    local(url)
}

/// `http(s)://<host>[:port][/path?query#fragment]` with a local host.
fn local(url: &str) -> bool {
    let Some((scheme, rest)) = url.split_once("://") else { return false };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    // The authority ends at the first `/`, `?` or `#` (and `\`, refused above).
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    // `user@host` puts the real host after the `@`; `%` would be decoded
    // into the host; `[` starts an IPv6 literal, never a Kiri name.
    if authority.bytes().any(|b| b"@%[]".contains(&b)) {
        return false;
    }
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    // A port is 1 to 65535 written in at most five digits, never empty.
    if port.is_some_and(|p| p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) || !matches!(p.parse::<u32>(), Ok(1..=65535))) {
        return false;
    }
    let host = host.to_ascii_lowercase();
    if host == "localhost" {
        return true;
    }
    let name = host.strip_suffix(".kiri.localhost").or_else(|| host.strip_suffix(".kiri.local"));
    name.is_some_and(plain_name)
}

/// A plain host name: ASCII letters, digits, `-` and `_` in dot-separated
/// parts of 1 to 63, 253 at most in all, not starting or ending with a dot
/// or a dash. `_` is let through because Docker's own container and
/// Compose names may hold it (and such addresses open today); it cannot
/// end a host or carry anything else. What `dev.kiri.domain` and the names
/// a local address is made from must be.
pub fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && !name.starts_with(['.', '-'])
        && !name.ends_with(['.', '-'])
        && name.split('.').all(|part| !part.is_empty() && part.len() <= 63 && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
}

/// `dev.kiri.domain`'s first name, lower-cased and without a typed
/// `.kiri.localhost`/`.kiri.local`, or "" when it is not a plain name.
/// (The engine's and the Mac and Linux window's; kiri-win, which includes
/// this file for [`allowed`], has no use for it.)
#[cfg_attr(windows, allow(dead_code))]
pub fn chosen_domain(label: &str) -> String {
    let d = label.split(',').next().unwrap_or("").trim().to_ascii_lowercase();
    let d = d.strip_suffix(".kiri.localhost").or_else(|| d.strip_suffix(".kiri.local")).unwrap_or(&d);
    if plain_name(d) { d.to_owned() } else { String::new() }
}

#[cfg(test)]
mod tests {
    use super::{allowed, chosen_domain, plain_name};

    /// Everything the window opened before this check was shared: it must
    /// all still open.
    #[test]
    fn what_opened_before_still_opens() {
        for url in [
            "http://localhost",
            "http://localhost:8080",
            "http://localhost:8080/app?x=1#top",
            "https://localhost:8443/",
            "http://web.kiri.localhost",
            "https://web.kiri.localhost/",
            "http://api.myapp.kiri.localhost:8081/path",
            "http://api.kiri.local",
            "https://web.shop.kiri.local:8443/x",
            "http://my_app.kiri.localhost",
            "http://my-app-1.kiri.local",
            "https://docs.docker.com/go/dockerfile/rule/from-as-casing/",
            "https://runkiri.com",
            "https://runkiri.com/releases/",
            "https://runkiri.com/share/notice",
            "https://canestack.com",
            "https://kiri.canestack.com",
            "https://discord.gg/K5A8wuqcC",
            "https://x.com/runkiri",
            "https://github.com/libracoder/kiri",
            "https://github.com/libracoder/kiri/issues/new",
            "https://github.com/anchore/grype",
            "https://github.com/login/device",
            "https://login.docker.com/activate",
            "https://learn.microsoft.com/windows/wsl/about",
        ] {
            assert!(allowed(url), "{url} must open");
        }
    }

    /// The forms that moved the host out of Kiri's names before, and others
    /// a browser reads differently from a naive split.
    #[test]
    fn bypasses_are_refused() {
        for url in [
            // The audit's: the host ran on past `?`, `#`, `@` and `\`.
            "https://outside.example?x.kiri.local",
            "https://outside.example?.kiri.localhost",
            "https://outside.example#x.kiri.local",
            "https://outside.example/#.kiri.localhost",
            "http://localhost:1@outside.example/",
            "http://x.kiri.local@outside.example/",
            "http://localhost@outside.example",
            "http://outside.example\\x.kiri.localhost",
            "http://outside.example\\.kiri.local",
            // Trailing dot, percent-encoding, IDN and punycode look-alikes.
            "http://web.kiri.localhost.",
            "http://web.kiri.local./",
            "http://localhost.",
            "http://outside%2eexample.kiri.local",
            "http://outside.example%2f.kiri.local",
            "http://web.kiri.loc%61l",
            "http://web.kiri.lоcal",
            "http://web.kirі.localhost",
            "http://xn--web-9cd.kiri.locaI",
            "http://web.kiri.local.xn--outside-9cd.example",
            // Not a Kiri name at all, or only the suffix.
            "http://kiri.localhost",
            "http://.kiri.localhost",
            "http://-x.kiri.local",
            "http://a..b.kiri.local",
            "http://outside.example/",
            "http://localhost.outside.example",
            "http://outsidekiri.local",
            "http://outside.example:80.kiri.local",
            // Ports.
            "http://localhost:",
            "http://localhost:0",
            "http://localhost:65536",
            "http://localhost:080080",
            "http://localhost:80:80",
            "http://localhost:8o",
            // IPv6 and other addresses.
            "http://[::1]:8080/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::1].kiri.local",
            "http://127.0.0.1:8080",
            "http://0x7f000001/",
            // Whitespace and control characters anywhere.
            "http://local host:8080",
            "http://localhost :8080",
            "http://web\t.kiri.local",
            "http://outside.example\t?.kiri.local",
            "http://outside.example\n.kiri.local",
            " http://localhost:8080",
            "http://localhost:8080\r\n",
            "http://web.kiri.local\u{0}",
            // Other schemes, and exact pages with something added.
            "ftp://localhost/",
            "file:///etc/passwd",
            "javascript:alert(1)//.kiri.local",
            "http:/localhost",
            "http:localhost",
            "//localhost:8080",
            "https://runkiri.com.outside.example",
            "https://github.com/libracoder/kiri/../../outside",
            "https://docs.docker.com/go/",
            "https://docs.docker.com/go/x?y",
            "https://docs.docker.com/go/x@y",
            "",
        ] {
            assert!(!allowed(url), "{url:?} must not open");
        }
    }

    /// Case means nothing in a host or a scheme: the same host still opens,
    /// a different one still does not.
    #[test]
    fn case_does_not_change_the_answer() {
        assert!(allowed("HTTP://Web.Kiri.Localhost:8080/"));
        assert!(allowed("http://LOCALHOST:3000"));
        assert!(!allowed("HTTP://Outside.Example?x.KIRI.LOCAL"));
        assert!(!allowed("Https://Outside.Example#.Kiri.Local"));
    }

    #[test]
    fn only_plain_names() {
        for ok in ["web", "api.myapp", "my-app", "a1.b2", "my_app", &"a".repeat(63)] {
            assert!(plain_name(ok), "{ok}");
        }
        let long = format!("{}.{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(62));
        for bad in [
            "", ".", "-web", "web-", ".web", "web.", "a..b", "we b", "web\t", "web/x", "web?x", "web#x", "web@x", "web:80", "web\\x",
            "w%2eb", "<b>", "\"x", "bücher", "wеb", &"a".repeat(64), &long,
        ] {
            assert!(!plain_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_domain_label_gives_a_plain_name_or_none() {
        assert_eq!(chosen_domain("api.myapp"), "api.myapp");
        assert_eq!(chosen_domain(" Api.MyApp.kiri.localhost , other"), "api.myapp");
        assert_eq!(chosen_domain("web.kiri.local"), "web");
        assert_eq!(chosen_domain(""), "");
        assert_eq!(chosen_domain("outside.example/#"), "");
        assert_eq!(chosen_domain("x@outside.example"), "");
        assert_eq!(chosen_domain("\"><img src=x onerror=alert(1)>"), "");
        assert_eq!(chosen_domain("outside.example?"), "");
    }
}
