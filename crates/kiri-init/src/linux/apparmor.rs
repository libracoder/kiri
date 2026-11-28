//! AppArmor: the profile a container's process runs under. The engine sends
//! it, on a Linux host with AppArmor enabled only, as the `apparmor` line of
//! the host options (see `hostopts`); with no line the process keeps the
//! agent's own (unconfined), as everywhere else.
//!
//! The kernel takes the request through the process's own attribute files:
//! `exec <profile>` in `attr/apparmor/exec` switches at the next `execve`,
//! `changeprofile <profile>` in `attr/apparmor/current` switches at once.
//! Kernels before 5.8 have only the older `attr/exec` and `attr/current`.

use std::fs;
use std::io::{self, Write};
use std::os::fd::AsRawFd;

/// `statfs.f_type` of procfs.
const PROC_SUPER_MAGIC: i64 = 0x9fa0;

/// The request for `profile`: which attribute file, and what to write.
/// `now`: switch at once (for the agent's own init, which never calls
/// `execve`); otherwise at the next `execve`.
pub fn request(profile: &str, now: bool) -> (&'static str, String) {
    if now { ("current", format!("changeprofile {profile}")) } else { ("exec", format!("exec {profile}")) }
}

/// Asks the kernel to put this thread under `profile` (see [`request`]).
/// The file must be on procfs: a container's volume mounted over /proc
/// would otherwise take the write and leave the process unconfined.
pub fn apply(profile: &str, now: bool) -> io::Result<()> {
    let (file, text) = request(profile, now);
    let mut f = match fs::OpenOptions::new().write(true).open(format!("/proc/thread-self/attr/apparmor/{file}")) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => fs::OpenOptions::new().write(true).open(format!("/proc/thread-self/attr/{file}"))?,
        r => r?,
    };
    // SAFETY: fstatfs fills a zeroed struct for a descriptor we own.
    let st = unsafe {
        let mut st: libc::statfs = std::mem::zeroed();
        if libc::fstatfs(f.as_raw_fd(), &mut st) != 0 {
            return Err(io::Error::last_os_error());
        }
        st
    };
    #[allow(clippy::unnecessary_cast)]
    if st.f_type as i64 != PROC_SUPER_MAGIC {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the AppArmor attribute file is not on procfs"));
    }
    // One write: the kernel reads the whole request from it.
    f.write_all(text.as_bytes()).map_err(|e| match e.raw_os_error() {
        Some(libc::ENOENT) => io::Error::new(e.kind(), format!("AppArmor profile {profile:?} is not loaded")),
        _ => e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_start_switches_at_exec_and_the_init_at_once() {
        assert_eq!(request("kiri-default", false), ("exec", "exec kiri-default".to_owned()));
        assert_eq!(request("kiri-default", true), ("current", "changeprofile kiri-default".to_owned()));
    }
}
