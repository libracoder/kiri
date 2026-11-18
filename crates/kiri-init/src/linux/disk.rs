//! Expand the mounted ext4 filesystem to the backing device's capacity.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;

pub fn grow() -> io::Result<()> {
    let mut disk = File::open("/dev/vda")?;
    let bytes = disk.seek(SeekFrom::End(0))?;
    // The data disk has already mounted as ext4. Read its total block
    // count, including metadata (statfs excludes metadata from f_blocks).
    disk.seek(SeekFrom::Start(1024))?;
    let mut sb = [0; 1024];
    disk.read_exact(&mut sb)?;
    let word = |offset: usize| u32::from_le_bytes(sb[offset..offset + 4].try_into().unwrap());
    let mut current = u64::from(word(0x04));
    if word(0x60) & 0x80 != 0 {
        current |= u64::from(word(0x150)) << 32;
    }
    let fs = File::open(super::DATA)?;
    // SAFETY: statfs is plain data; fstatfs writes it before it is read.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: fs is open and stat is valid writable storage.
    super::sys::check(
        unsafe { libc::fstatfs(fs.as_raw_fd(), &mut stat) } as _,
        "data disk statfs",
    )?;
    let blocks = bytes / stat.f_bsize as u64;
    if blocks <= current {
        return Ok(());
    }
    // EXT4_IOC_RESIZE_FS = _IOW('f', 16, __u64), on both guest architectures.
    // SAFETY: fs is the mounted ext4 directory and blocks is a valid u64.
    super::sys::check(
        unsafe { libc::ioctl(fs.as_raw_fd(), 0x40086610 as libc::Ioctl, &blocks) } as _,
        "grow ext4 data disk",
    )?;
    Ok(())
}
