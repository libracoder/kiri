//! Runs Kiri's Linux guest: in a VM with Apple's Virtualization.framework on
//! macOS, and as a plain root process beside the daemon on Linux, where the
//! host's own kernel runs the containers. Both give the daemon the same
//! types: a guest that dials in, and ports to connect to or listen on.

mod stop;

#[cfg(target_os = "macos")]
mod apple;
#[cfg(target_os = "macos")]
pub use apple::*;

#[cfg(any(target_os = "linux", all(test, unix)))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod process;
#[cfg(target_os = "linux")]
pub use process::*;
