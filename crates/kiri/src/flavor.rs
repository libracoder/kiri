//! Kiribra Dev: a second Kiribra beside the installed one, for trying changes
//! without touching it (`cargo xtask app-dev` builds `Kiribra Dev.app`).
//!
//! It is the same binary; running from a bundle whose identifier is
//! `dev.kiribra.app.dev` makes it Dev. Everything two Kiribras would share gets
//! its own name: `~/.kiribra-dev` (socket, settings, logs),
//! `~/Library/Application Support/Kiribra Dev` (images, volumes, the VM's
//! disk), the `dev.kiribra.daemon.dev` LaunchAgent, the `kiribra-dev` docker and
//! kubectl contexts and `~/Kiribra Dev` in Finder. It leaves to the installed
//! Kiribra what there is one of on a Mac: `*.kiribra.local`, the container-name
//! routers on ports 80 and 443, docker's default context, the shell PATH
//! and updates.
//!
//! A feature app (`cargo xtask app-dev builds` builds `Kiribra Builds.app`,
//! identifier `dev.kiribra.app.builds`) is a Kiribra Dev of its own, for
//! trying one unreleased feature: every Dev name with `dev` swapped for the
//! feature's (`~/.kiribra-builds`, the `kiribra-builds` context, and so on).

// Some names serve only the Mac (the app, its LaunchAgent).
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::fmt;
use std::sync::OnceLock;

/// Kiribra Dev.app's bundle identifier.
pub const DEV_APP_ID: &str = "dev.kiribra.app.dev";

/// Whether this binary is Kiribra Dev (or a feature app): it runs from a
/// bundle (directly, or through `~/.kiribra-dev/bin/kiri`, a link into it)
/// whose identifier is `DEV_APP_ID`, or `dev.kiribra.app.<feature>`.
pub fn dev() -> bool {
    flavor().is_some()
}

/// `Some("")` for Kiribra Dev, `Some("builds")` for Kiribra Builds, `None` for Kiribra.
fn flavor() -> Option<&'static str> {
    static FLAVOR: OnceLock<Option<String>> = OnceLock::new();
    FLAVOR
        .get_or_init(|| {
            let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
            let plist = std::fs::read_to_string(exe.parent()?.parent()?.join("Info.plist")).ok()?;
            let id = plist.split("<key>CFBundleIdentifier</key>").nth(1)?.split("<string>").nth(1)?.split("</string>").next()?.trim();
            if id == DEV_APP_ID {
                return Some(String::new());
            }
            let f = id.strip_prefix("dev.kiribra.app.")?;
            (!f.is_empty() && f.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())).then(|| f.to_owned())
        })
        .as_deref()
}

/// A Dev name made a feature's: `Kiribra Dev` → `Kiribra Builds`, `kiribra-dev` →
/// `kiribra-builds`, `dev.kiribra.daemon.dev` → `dev.kiribra.daemon.builds`.
fn featured(dev_name: &str, feature: &str) -> String {
    let title = feature[..1].to_ascii_uppercase() + &feature[1..];
    if let Some(head) = dev_name.strip_suffix(".dev") {
        return format!("{head}.{feature}");
    }
    dev_name.replacen(" Dev", &format!(" {title}"), 1).replacen("-dev", &format!("-{feature}"), 1)
}

/// A name with a Dev counterpart. Displays as the one this binary uses.
pub struct Name(pub &'static str, pub &'static str);

impl Name {
    pub fn get(&self) -> &'static str {
        match flavor() {
            None => self.0,
            Some("") => self.1,
            Some(f) => {
                static NAMES: std::sync::Mutex<Vec<(&str, &str)>> = std::sync::Mutex::new(Vec::new());
                let mut names = NAMES.lock().unwrap_or_else(|e| e.into_inner());
                if let Some((_, n)) = names.iter().find(|(d, _)| *d == self.1) {
                    return n;
                }
                let n: &'static str = Box::leak(featured(self.1, f).into_boxed_str());
                names.push((self.1, n));
                n
            }
        }
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.get())
    }
}

/// The app's name, as the window and Finder show it.
pub const APP: Name = Name("Kiribra", "Kiribra Dev");
/// Under HOME: the daemon's socket and state, the window's settings.
pub const STATE: Name = Name(".kiribra", ".kiribra-dev");
/// The docker context, and the kubectl one.
pub const CONTEXT: Name = Name("kiribra", "kiribra-dev");
pub const AGENT: Name = Name("dev.kiribra.daemon", "dev.kiribra.daemon.dev");
pub const APP_ID: Name = Name("dev.kiribra.app", DEV_APP_ID);

/// Kiribra Dev keeps its images, volumes and VM disk apart: `KIRIBRA_DATA_DIR`,
/// which `Store::default_root` reads, set before any thread starts.
pub fn init() {
    if dev() && std::env::var_os("KIRIBRA_DATA_DIR").is_none() {
        if let Some(home) = std::env::var_os("HOME") {
            // SAFETY: called first thing in main, before any other thread.
            unsafe { std::env::set_var("KIRIBRA_DATA_DIR", std::path::Path::new(&home).join("Library/Application Support").join(APP.get())) };
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_test_binary_is_not_dev() {
        assert!(!super::dev());
        assert_eq!((super::STATE.get(), super::CONTEXT.to_string()), (".kiribra", "kiribra".to_owned()));
    }

    #[test]
    fn a_feature_renames_every_dev_name() {
        use super::featured;
        assert_eq!(featured("Kiribra Dev", "builds"), "Kiribra Builds");
        assert_eq!(featured(".kiribra-dev", "builds"), ".kiribra-builds");
        assert_eq!(featured("kiribra-dev", "builds"), "kiribra-builds");
        assert_eq!(featured("kiribra-dev-build", "builds"), "kiribra-builds-build");
        assert_eq!(featured("dev.kiribra.daemon.dev", "builds"), "dev.kiribra.daemon.builds");
        assert_eq!(featured("dev.kiribra.app.dev", "builds"), "dev.kiribra.app.builds");
    }
}
