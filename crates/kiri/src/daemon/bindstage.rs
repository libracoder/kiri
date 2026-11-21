//! A build step's bind of a context folder, mounted from the handle the
//! caller check opened rather than from its path.
//!
//! The driver opens the bind source beneath the context as the calling
//! user and checks what is under it through that handle
//! (`kiri_forge::context::Root::open_handle`). Mounting by path afterwards
//! would let a folder on the way be swapped for a link out of the context
//! in between. So the daemon mounts the handle's own tree at a folder of
//! its state that no user can name, and the step binds that: with
//! `open_tree(OPEN_TREE_CLONE)` and `move_mount` (Linux 5.2), else a bind
//! from `/proc/self/fd/<handle>`, which the kernel resolves to the object
//! itself. The agent sees the daemon's mounts (on a Linux host it runs in
//! the same mount namespace). The staged mount is detached once the step
//! is over; the step's own mounts hold what they use.
//!
//! On macOS the bind goes through the VM's shared folder by path: the VM
//! cannot take a handle of the Mac. The engine runs as the user there, so
//! a swap can only show the step a file of the same user's, within the
//! shared folders.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

/// A context bind staged at a folder of the engine's state.
pub struct Staged {
    path: PathBuf,
    is_dir: bool,
}

impl Staged {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Mounts what `handle` holds at a new entry of `dir`.
    pub fn new(handle: BorrowedFd<'_>, dir: &Path) -> io::Result<Staged> {
        std::fs::create_dir_all(dir)?;
        // SAFETY: zeroed storage for fstat.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid descriptor and out pointer.
        if unsafe { libc::fstat(handle.as_raw_fd(), &mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let is_dir = st.st_mode & libc::S_IFMT == libc::S_IFDIR;
        let path = dir.join(format!("bind-{}", super::engine::random_hex(12)));
        if is_dir {
            std::fs::create_dir(&path)?;
        } else {
            std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
        }
        let staged = Staged { path, is_dir };
        mount_handle(handle, &staged.path)?;
        // nothing done under it reaches other namespaces, or back
        let c = cstr(&staged.path)?;
        // SAFETY: a NUL-terminated path; no source, type or data.
        unsafe { libc::mount(std::ptr::null(), c.as_ptr(), std::ptr::null(), libc::MS_PRIVATE | libc::MS_REC, std::ptr::null()) };
        Ok(staged)
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if let Ok(c) = cstr(&self.path) {
            // SAFETY: a NUL-terminated path.
            unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
        }
        let _ = if self.is_dir { std::fs::remove_dir(&self.path) } else { std::fs::remove_file(&self.path) };
    }
}

fn cstr(p: &Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

const OPEN_TREE_CLONE: libc::c_uint = 1;
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;

/// Tests take the fallback, to check it the same way.
#[cfg(test)]
static NO_OPEN_TREE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn mount_handle(handle: BorrowedFd<'_>, at: &Path) -> io::Result<()> {
    let to = cstr(at)?;
    #[cfg(test)]
    let skip = NO_OPEN_TREE.load(std::sync::atomic::Ordering::Relaxed);
    #[cfg(not(test))]
    let skip = false;
    if !skip {
        // SAFETY: a valid descriptor, an empty NUL-terminated path; the result is checked.
        let t = unsafe {
            libc::syscall(libc::SYS_open_tree, handle.as_raw_fd(), c"".as_ptr(), OPEN_TREE_CLONE | libc::AT_RECURSIVE as libc::c_uint | libc::AT_EMPTY_PATH as libc::c_uint | libc::O_CLOEXEC as libc::c_uint)
        };
        if t >= 0 {
            // SAFETY: a descriptor just returned, owned by nobody else.
            let tree = unsafe { OwnedFd::from_raw_fd(t as libc::c_int) };
            // SAFETY: valid descriptors and NUL-terminated paths.
            let r = unsafe { libc::syscall(libc::SYS_move_mount, tree.as_raw_fd(), c"".as_ptr(), libc::AT_FDCWD, to.as_ptr(), MOVE_MOUNT_F_EMPTY_PATH) };
            if r == 0 {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::ENOSYS) {
                return Err(e);
            }
        } else {
            let e = io::Error::last_os_error();
            if !matches!(e.raw_os_error(), Some(libc::ENOSYS | libc::EPERM)) {
                return Err(e);
            }
        }
    }
    // the handle's own object, through its magic link: no name looked up
    let from = std::ffi::CString::new(format!("/proc/self/fd/{}", handle.as_raw_fd()))?;
    // SAFETY: NUL-terminated paths; no type or data.
    if unsafe { libc::mount(from.as_ptr(), to.as_ptr(), std::ptr::null(), libc::MS_BIND | libc::MS_REC, std::ptr::null()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kiri_forge::context::Root;
    use std::os::fd::AsFd;

    fn is_root() -> bool {
        // SAFETY: no preconditions.
        unsafe { libc::geteuid() == 0 }
    }

    /// The bind source flipped to a link out of the context between the
    /// check and the mount: the mount still shows what was checked. Needs
    /// root and mount rights (a privileged container); skipped otherwise.
    #[test]
    fn a_source_swapped_after_the_check_mounts_what_was_checked() {
        if !is_root() {
            return;
        }
        for fallback in [false, true] {
            NO_OPEN_TREE.store(fallback, std::sync::atomic::Ordering::Relaxed);
            let t = std::env::temp_dir().join(format!("kiri-bindstage-{}-{fallback}", std::process::id()));
            let _ = std::fs::remove_dir_all(&t);
            let ctx = t.join("ctx");
            std::fs::create_dir_all(ctx.join("d")).unwrap();
            std::fs::write(ctx.join("d/f"), b"inside").unwrap();
            std::fs::create_dir_all(t.join("outside")).unwrap();
            std::fs::write(t.join("outside/f"), b"SECRET").unwrap();
            std::fs::write(ctx.join("g"), b"file inside").unwrap();
            std::fs::write(t.join("outside/g"), b"SECRET").unwrap();
            let root = Root::open(&ctx, None, &[]).unwrap();
            let dir = root.open_handle(b"d").unwrap();
            let file = root.open_handle(b"g").unwrap();
            // after the check, before the mount
            std::fs::rename(ctx.join("d"), t.join("d.old")).unwrap();
            std::os::unix::fs::symlink(t.join("outside"), ctx.join("d")).unwrap();
            std::fs::rename(ctx.join("g"), t.join("g.old")).unwrap();
            std::os::unix::fs::symlink(t.join("outside/g"), ctx.join("g")).unwrap();
            let stage = t.join("stage");
            let sd = Staged::new(dir.as_fd(), &stage).unwrap();
            let sf = Staged::new(file.as_fd(), &stage).unwrap();
            assert_eq!(std::fs::read(sd.path().join("f")).unwrap(), b"inside", "fallback={fallback}");
            assert_eq!(std::fs::read(sf.path()).unwrap(), b"file inside", "fallback={fallback}");
            let (pd, pf) = (sd.path().to_path_buf(), sf.path().to_path_buf());
            drop((sd, sf));
            assert!(!pd.exists() && !pf.exists(), "unmounted and removed");
            let _ = std::fs::remove_dir_all(&t);
        }
        NO_OPEN_TREE.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}
