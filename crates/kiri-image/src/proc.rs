//! The two process questions the store asks the system.

/// Whether process `pid` exists. `kill(pid, 0)` sends nothing: it fails with
/// ESRCH when there is no such process and EPERM when there is one this
/// process may not signal (alive, of another user). Works on every Unix,
/// with or without /proc.
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) fn alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else { return false };
    if pid <= 0 {
        return false;
    }
    // SAFETY: kill with signal 0 only checks that the target exists.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// Elsewhere (the Windows client, which keeps no store of its own) a
/// writer is taken to be alive: its leftovers are never removed by id.
#[cfg(not(unix))]
pub(crate) fn alive(_pid: u32) -> bool {
    true
}

/// Whether this process runs as root, whom file modes do not stop.
#[cfg(all(test, unix))]
#[allow(unsafe_code)]
pub(crate) fn is_root() -> bool {
    // SAFETY: geteuid takes nothing and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(all(test, not(unix)))]
pub(crate) fn is_root() -> bool {
    false
}
