//! Returns unused ext4 blocks to the Mac's sparse VM disk.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::thread;
use std::time::Duration;

const FIRST_TRIM: Duration = Duration::from_secs(15);
const TRIM_INTERVAL: Duration = Duration::from_secs(60 * 60);

// Linux <linux/fs.h>: _IOWR('X', 121, struct fstrim_range).
const FITRIM: libc::Ioctl = 0xc018_5879_u32 as libc::Ioctl;

#[repr(C)]
struct FstrimRange {
    start: u64,
    len: u64,
    minlen: u64,
}

/// Trims in a process of its own, off the agent loop, once the VM has had
/// time to finish booting and hourly after that. A first pass also returns
/// space left behind by older versions.
///
/// Not a thread: the agent must stay single-threaded, because containers are
/// cloned with clone3 without CLONE_VM, and a copy of the agent that still
/// counts a thread fails or hangs in setuid. The agent reaps this child like
/// any other if it ends.
pub(super) fn start(mountpoint: &'static str) {
    // SAFETY: the agent is still single-threaded here, so the child is a
    // consistent copy. It uses nothing the agent opened, and leaves with _exit.
    match unsafe { libc::fork() } {
        0 => {
            // SAFETY: closing this process's own descriptors and naming it.
            unsafe {
                libc::syscall(libc::SYS_close_range, 3, libc::c_uint::MAX, 0);
                libc::prctl(libc::PR_SET_NAME, c"kiri-trim".as_ptr());
            }
            run(mountpoint);
            // SAFETY: leaving the child without running the parent's destructors.
            unsafe { libc::_exit(0) }
        }
        pid if pid < 0 => eprintln!("kiri-init: cannot start disk trim: {}", io::Error::last_os_error()),
        _ => {}
    }
}

fn run(mountpoint: &str) {
    thread::sleep(FIRST_TRIM);
    loop {
        if let Err(e) = trim(mountpoint) {
            if matches!(e.raw_os_error(), Some(libc::EOPNOTSUPP | libc::ENOTTY)) {
                return;
            }
            eprintln!("kiri-init: trimming data disk: {e}");
        }
        thread::sleep(TRIM_INTERVAL);
    }
}

/// Runs `FITRIM` on `mountpoint` and returns the trimmed byte count reported
/// by the kernel (`fstrim_range.len`). Single-threaded and safe from the agent loop.
pub(super) fn trim(mountpoint: &str) -> io::Result<u64> {
    let disk = File::open(mountpoint)?;
    // Commit any pending ext4 journal transactions (e.g. a `docker image prune`
    // or `docker volume rm` that finished moments ago) before FITRIM scans free
    // block bitmaps; otherwise jbd2 still pins those blocks and marks the block
    // group trimmed.
    // SAFETY: syncfs takes any valid open file descriptor on the filesystem.
    unsafe {
        libc::syncfs(disk.as_raw_fd());
    }
    let mut range = FstrimRange {
        start: 0,
        len: u64::MAX,
        minlen: 0,
    };
    // SAFETY: FITRIM takes a writable fstrim_range and an open mount descriptor.
    if unsafe { libc::ioctl(disk.as_raw_fd(), FITRIM, &mut range) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(range.len)
}

/// Reports `(in_use, capacity)` in bytes for the filesystem mounted at
/// `mountpoint`, using `statvfs` (`in_use = (blocks - bfree) * frsize`,
/// `capacity = blocks * frsize`). Uses `f_bfree` rather than `f_bavail`
/// because `FITRIM` discards free blocks (`f_bfree`), never root-reserved
/// non-free blocks.
pub(super) fn stat(mountpoint: &str) -> io::Result<(u64, u64)> {
    let path = std::ffi::CString::new(mountpoint).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: statvfs fills a zero-initialized struct for a valid NUL-terminated path.
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut s) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let frsize = if s.f_frsize > 0 { s.f_frsize as u64 } else { s.f_bsize as u64 };
    let blocks = s.f_blocks as u64;
    let bfree = s.f_bfree as u64;
    let in_use = blocks.saturating_sub(bfree).saturating_mul(frsize);
    let capacity = blocks.saturating_mul(frsize);
    Ok((in_use, capacity))
}
