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

pub(super) fn start(mountpoint: &'static str) {
    // Batch discards off the agent loop and give the VM time to finish booting.
    // A first pass also returns space left behind by older versions.
    if let Err(e) = thread::Builder::new()
        .name("kiri-trim".into())
        .spawn(move || {
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
        })
    {
        eprintln!("kiri-init: cannot start disk trim: {e}");
    }
}

fn trim(mountpoint: &str) -> io::Result<()> {
    let disk = File::open(mountpoint)?;
    let mut range = FstrimRange {
        start: 0,
        len: u64::MAX,
        minlen: 0,
    };
    // SAFETY: FITRIM takes a writable fstrim_range and an open mount descriptor.
    if unsafe { libc::ioctl(disk.as_raw_fd(), FITRIM, &mut range) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
