//! Expand the mounted ext4 filesystem to the backing device's capacity.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::path::Path;

const EXT4_SUPER_OFFSET: u64 = 1024;
const EXT4_SUPER_LEN: usize = 1024;
const EXT4_SUPER_MAGIC: u16 = 0xEF53;
const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x80;

// EXT4_IOC_RESIZE_FS = _IOW('f', 16, __u64), on both guest architectures.
const EXT4_IOC_RESIZE_FS: libc::Ioctl = 0x4008_6610_u32 as libc::Ioctl;

/// Parses the ext4 superblock's total block count (including metadata).
/// Returns `InvalidData` if the superblock magic does not match ext4.
fn superblock_blocks(sb: &[u8; EXT4_SUPER_LEN]) -> io::Result<u64> {
    let magic = u16::from_le_bytes([sb[0x38], sb[0x39]]);
    if magic != EXT4_SUPER_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected ext4 superblock magic 0x{magic:04x}"),
        ));
    }
    let word = |offset: usize| u32::from_le_bytes(sb[offset..offset + 4].try_into().unwrap());
    let mut blocks = u64::from(word(0x04));
    if word(0x60) & EXT4_FEATURE_INCOMPAT_64BIT != 0 {
        blocks |= u64::from(word(0x150)) << 32;
    }
    Ok(blocks)
}

pub fn grow() -> io::Result<()> {
    grow_device(Path::new("/dev/vda"), Path::new(super::DATA))
}

pub(crate) fn grow_device(device: &Path, mountpoint: &Path) -> io::Result<()> {
    let mut disk = File::open(device)?;
    let bytes = disk.seek(SeekFrom::End(0))?;
    // The data disk has already mounted as ext4. Read its total block
    // count, including metadata (statfs excludes metadata from f_blocks).
    disk.seek(SeekFrom::Start(EXT4_SUPER_OFFSET))?;
    let mut sb = [0u8; EXT4_SUPER_LEN];
    disk.read_exact(&mut sb)?;
    let current = superblock_blocks(&sb)?;
    let fs = File::open(mountpoint)?;
    // SAFETY: statfs is plain data; fstatfs writes it before it is read.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: fs is open and stat is valid writable storage.
    super::sys::check(
        unsafe { libc::fstatfs(fs.as_raw_fd(), &mut stat) } as _,
        "data disk statfs",
    )?;
    let block_size = stat.f_bsize as u64;
    if block_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ext4 block size",
        ));
    }
    let blocks = bytes / block_size;
    if blocks <= current {
        return Ok(());
    }
    // SAFETY: fs is the mounted ext4 directory and blocks is a valid u64.
    super::sys::check(
        unsafe { libc::ioctl(fs.as_raw_fd(), EXT4_IOC_RESIZE_FS, &blocks) } as _,
        "grow ext4 data disk",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_superblock(lo: u32, hi: u32, is_64bit: bool) -> [u8; EXT4_SUPER_LEN] {
        let mut sb = [0u8; EXT4_SUPER_LEN];
        sb[0x38..0x3a].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        sb[0x04..0x08].copy_from_slice(&lo.to_le_bytes());
        let incompat: u32 = if is_64bit {
            EXT4_FEATURE_INCOMPAT_64BIT
        } else {
            0
        };
        sb[0x60..0x64].copy_from_slice(&incompat.to_le_bytes());
        sb[0x150..0x154].copy_from_slice(&hi.to_le_bytes());
        sb
    }

    #[test]
    fn superblock_reads_32bit_and_64bit_block_counts() {
        let sb32 = fake_superblock(16_777_216, 99, false);
        assert_eq!(superblock_blocks(&sb32).unwrap(), 16_777_216);

        let sb64 = fake_superblock(0x0000_0001, 0x0000_0002, true);
        assert_eq!(superblock_blocks(&sb64).unwrap(), (2u64 << 32) | 1);
    }

    #[test]
    fn superblock_rejects_bad_magic() {
        let sb = [0u8; EXT4_SUPER_LEN];
        assert_eq!(
            superblock_blocks(&sb).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    /// Real online ext4 resize check when driven on a Linux host with a
    /// mounted loop device (`KIRI_TEST_EXT4_DEV` + `KIRI_TEST_EXT4_MOUNT`).
    #[test]
    fn grows_mounted_ext4_online_when_configured() {
        let (Ok(dev), Ok(mnt)) = (
            std::env::var("KIRI_TEST_EXT4_DEV"),
            std::env::var("KIRI_TEST_EXT4_MOUNT"),
        ) else {
            return;
        };
        let dev = Path::new(&dev);
        let mnt = Path::new(&mnt);
        grow_device(dev, mnt).expect("first online ext4 resize must succeed");
        // Calling grow again when already at full capacity must be a no-op.
        grow_device(dev, mnt).expect("second online ext4 resize must be idempotent");
    }
}
