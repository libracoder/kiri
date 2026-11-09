//! BuildKit (buildkitd) as a guest root process, not a container: the daemon
//! starts it with [`Msg::BuildkitStart`] and connects to its unix socket through
//! the agent's vsock listener (relay.rs), which is how buildx's docker driver
//! reaches it.
//!
//! The binary comes from the pinned BuildKit image the daemon keeps in its
//! store: its layers are already unpacked in the guest, so buildkitd (a Go
//! binary, static, no libc) and the `buildkit-runc` beside it are execed
//! straight out of the newest layer that has them. The image's registry
//! certificate bundle is handed to Go with `SSL_CERT_FILE`, for live
//! registries over TLS.
//!
//! Nothing is chrooted or namespaced: whatever a `--privileged` container
//! may reach, this process could too, and it nevertheless lives and dies
//! with the guest.

use std::ffi::CString;
use std::io;
use std::path::Path;

use super::{layers, sys};

/// Where the daemon believes buildkitd's unix socket is.
pub const SOCK: &str = super::relay::BUILDKIT_SOCK;
/// On disk: buildkitd's state (`--root`), kept under the guest's own disk
/// content, as a volume's goes with the VM. Also the log's directory, at
/// `buildkitd.log` next to `buildkit/`.
pub const ROOT: &str = "/var/lib/kiri/buildkit";
const LOG: &str = "/var/lib/kiri/buildkitd.log";
/// The daemon's config, written fresh on each start: the cache limits and
/// the mirror address are today's, not a previous run's.
const CONFIG: &str = "/run/kiri/buildkitd.toml";

/// How long a freshly spawned buildkitd is given to prove it stays alive
/// before `BuildkitStart` is answered: long enough for a failed exec to
/// happen, short enough that this adds nothing to the next connection.
const PROBE: std::time::Duration = std::time::Duration::from_millis(150);

#[derive(Debug, Default)]
pub struct Buildkit {
    /// The running process, if any.
    pid: Option<libc::pid_t>,
    /// What to spawn with; kept so a crashed buildkitd is restarted the
    /// same way.
    recipe: Option<(Vec<String>, String)>,
}

impl Buildkit {
    /// The daemon wants it running: spawns it if it is not there yet, and
    /// makes sure a freshly spawned one did not die at once. `Err` ends in
    /// the daemon's session setup, which retries connecting.
    pub fn ensure(&mut self, layer_root: &Path, layers: kiri_proto::StrList<'_>, config: &str) -> io::Result<()> {
        // Same recipe every time, so just remember it for the respawn.
        let layers: Vec<String> = layers.iter().map(str::to_owned).collect();
        self.recipe = Some((layers, config.to_owned()));
        if self.pid.filter(|p| alive(*p)).is_some() {
            return Ok(());
        }
        self.pid = None;
        let Some(recipe) = self.recipe.as_ref() else { unreachable!("was just set") };
        let pid = spawn(layer_root, recipe)?;
        self.pid = Some(pid);
        std::thread::sleep(PROBE);
        if !alive(pid) {
            self.pid = None;
            return Err(io::Error::other(format!("buildkitd exited as soon as it was started (exit {})", exit_code(pid))));
        }
        Ok(())
    }

    /// Nobody is connected any more (idle_secs passed): the daemon asks for
    /// a stop, to keep the guest from holding the cache in memory between
    /// builds. The exit turns up in the agent's reaping.
    pub fn stop(&mut self) {
        let Some(pid) = self.pid.take() else { return };
        // SAFETY: signalling a child the agent started and has not reaped.
        unsafe { libc::kill(pid, libc::SIGTERM) };
    }

    /// A reaped pid that was not one of the containers': buildkitd's.
    pub fn reaped(&mut self, pid: libc::pid_t) {
        if self.pid == Some(pid) {
            self.pid = None;
        }
    }
}

fn alive(pid: libc::pid_t) -> bool {
    // SAFETY: the null signal only probes liveness; the agent is the
    // process's parent, so EPERM cannot come up.
    unsafe { libc::kill(pid, 0) == 0 }
}

fn exit_code(pid: libc::pid_t) -> i32 {
    let mut status = 0;
    // SAFETY: plain waitpid on a child the agent started.
    let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if got != pid {
        return -1;
    }
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        -1
    }
}

/// Writes the config and execs buildkitd from the layers; returns the new
/// process's pid.
fn spawn(layer_root: &Path, recipe: &(Vec<String>, String)) -> io::Result<libc::pid_t> {
    if let Some(parent) = Path::new(ROOT).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(LOG, b"")?;
    std::fs::write(CONFIG, recipe.1.as_bytes())?;

    let binary = which(layer_root, &recipe.0, "usr/bin/buildkitd")
        .map_err(|_| io::Error::other("no layer of the BuildKit image has usr/bin/buildkitd yet (the image is being unpacked, or its pull failed)"))?;
    // Certificates, for live registries over TLS; absent only if the image's
    // upstream package set changed.
    let certs = which(layer_root, &recipe.0, "etc/ssl/certs/ca-certificates.crt").ok();

    let args = [
        CString::new(binary.as_str())?,
        CString::new("--config")?,
        CString::new(CONFIG)?,
        CString::new("--addr")?,
        CString::new(format!("unix://{SOCK}"))?,
        CString::new("--root")?,
        CString::new(ROOT)?,
    ];
    let mut env = vec![CString::new("PATH=/usr/sbin:/usr/bin:/sbin:/bin")?, CString::new("HOME=/root")?];
    if let Some(certs) = &certs {
        env.push(CString::new(format!("SSL_CERT_FILE={certs}"))?);
    }
    let mut argv: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut envp: Vec<*const libc::c_char> = env.iter().map(|a| a.as_ptr()).collect();
    envp.push(std::ptr::null());

    // SAFETY: the agent is single-threaded, so the child is a consistent copy,
    // as fork() requires. The child only execs; never unwinds.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        child_exec(argv.as_ptr(), envp.as_ptr())
    }
    Ok(pid)
}

/// The child between fork and exec: stdio pointed where it should be, every
/// agent descriptor closed, and then the binary runs.
fn child_exec(argv: *const *const libc::c_char, envp: *const *const libc::c_char) -> ! {
    // SAFETY: a fork() child doing its own plain-syscall setup; failure paths
    // write to the log and exit, they never unwind.
    unsafe {
        // stdin from /dev/null; stdout and stderr to the log.
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if null < 0 || libc::dup2(null, libc::STDIN_FILENO) < 0 {
            sys::child_fail(libc::STDERR_FILENO, "buildkitd stdin", io::Error::last_os_error());
        }
        let log = libc::open(c"/var/lib/kiri/buildkitd.log".as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o640);
        if log < 0 || libc::dup2(log, libc::STDOUT_FILENO) < 0 {
            sys::child_fail(libc::STDERR_FILENO, "buildkitd stdout", io::Error::last_os_error());
        }
        if libc::dup2(log, libc::STDERR_FILENO) < 0 {
            sys::child_fail(libc::STDERR_FILENO, "buildkitd stderr", io::Error::last_os_error());
        }
        if log != libc::STDOUT_FILENO && log != libc::STDERR_FILENO {
            libc::close(log);
        }
        // Every other descriptor goes, so nothing of the agent's leaks into
        // the builder.
        libc::syscall(libc::SYS_close_range, 3, libc::c_uint::MAX, 0);
        libc::execve(*argv, argv, envp);
        sys::child_fail(libc::STDERR_FILENO, "exec buildkitd", io::Error::last_os_error());
    }
}

/// The file `path`, inside the first layer of `layers` that has it, as an
/// absolute path in the guest. `layers` are newest first, which is also the
/// order the image's own filesystem sees them in.
pub fn which(root: &Path, layers: &[String], path: &str) -> io::Result<String> {
    for digest in layers {
        let dir = layers::dir(root, digest)?;
        let file = dir.join(path);
        if file.is_file() {
            return Ok(file.to_string_lossy().into_owned());
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, format!("{path} is in none of the BuildKit layers")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn which_takes_the_first_layer_that_has_the_file() {
        let tmp = std::env::temp_dir().join(format!("kiri-buildkit-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let aa = tmp.join(layers::hex("sha256:aa").unwrap());
        let bb = tmp.join(layers::hex("sha256:bb").unwrap()).join("usr/bin");
        fs::create_dir_all(&aa).unwrap();
        fs::create_dir_all(&bb).unwrap();
        fs::write(bb.join("buildkitd"), b"bytes").unwrap();
        // Seen newest first: a binary only in the older layer is still found.
        let found = which(&tmp, &["sha256:aa".into(), "sha256:bb".into()], "usr/bin/buildkitd").unwrap();
        assert!(found.ends_with("usr/bin/buildkitd"));
        assert!(found.contains(&layers::hex("sha256:bb").unwrap()));
        // And a file in no layer is an error.
        assert!(which(&tmp, &["sha256:aa".into()], "usr/bin/absent").is_err());
        let _ = fs::remove_dir_all(&tmp);
    }
}
