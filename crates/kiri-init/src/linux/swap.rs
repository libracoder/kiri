//! The VM's swap (#326): a file on the data disk, the size the host names
//! on the kernel command line (`kiri.swap=<MiB>`). Docker Desktop gives its
//! VM 1 GiB the same way; without it a container that outgrows the VM's
//! memory is killed even when its pages could wait on disk. zswap is on in
//! the kernel, so pages are compressed in memory first, and its shrinker
//! moves them on to the file.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Where the swap file lives: the data disk's top, beside `layers` and
/// `containers`, so nothing that sweeps those touches it.
pub(super) const FILE: &str = "/var/lib/kiri/swapfile";

/// `<linux/swap.h>`: freed swap pages are discarded, so the Mac's sparse
/// disk image gets their space back as for trimmed ext4 blocks.
const SWAP_FLAG_DISCARD: libc::c_int = 0x10000;

/// Lets zswap write cold pages out to the swap file under memory pressure.
const ZSWAP_SHRINKER: &str = "/sys/module/zswap/parameters/shrinker_enabled";

/// The size the host asked for, in MiB, from the kernel command line. None
/// when it said nothing (an older host): the file is then left as it is.
pub(super) fn requested(cmdline: &str) -> Option<u64> {
    cmdline.split_ascii_whitespace().filter_map(|a| a.strip_prefix("kiri.swap=")).next_back().and_then(|v| v.parse().ok())
}

/// Reads the command line and keeps the swap file as asked; only says why
/// on the console if it can't, since the VM runs without swap all the same.
pub(super) fn start() {
    let Some(mib) = fs::read_to_string("/proc/cmdline").ok().as_deref().and_then(requested) else { return };
    // SAFETY: sysconf has no preconditions.
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(4096);
    let path = Path::new(FILE);
    match ensure(path, mib, page) {
        Ok(false) => {}
        Ok(true) => {
            if let Err(e) = swapon(path) {
                // A file that is not fit for swap (holes, a header the
                // kernel refuses) is made again once.
                let _ = fs::remove_file(path);
                if let Err(e2) = ensure(path, mib, page).and_then(|_| swapon(path)) {
                    let _ = fs::remove_file(path);
                    eprintln!("kiri-init: no swap ({e}; again: {e2})");
                    return;
                }
            }
            // zswap keeps swapped pages compressed in memory, charged to the
            // container. Without its shrinker they never reach the file, and
            // a container over its `--memory` is killed with its swap unused.
            if let Err(e) = super::sys::write_file(ZSWAP_SHRINKER, "Y") {
                eprintln!("kiri-init: zswap's shrinker stays off ({e}); swap may fill memory first");
            }
        }
        Err(e) => {
            let _ = fs::remove_file(path);
            eprintln!("kiri-init: no swap of {mib} MiB ({e})");
        }
    }
}

/// Makes `path` a swap file of `mib` MiB, keeping one already that size,
/// or removes it for 0. Returns whether there is a swap file to turn on.
pub(super) fn ensure(path: &Path, mib: u64, page: usize) -> io::Result<bool> {
    if mib == 0 {
        return match fs::remove_file(path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(false),
        };
    }
    let len = mib.checked_shl(20).ok_or_else(|| io::Error::from_raw_os_error(libc::EFBIG))?;
    if len < (page as u64).saturating_mul(10) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "swap file smaller than kernel minimum (10 pages)"));
    }
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file() && m.len() == len && (m.permissions().mode() & 0o777) == 0o600)
        && has_header(path, page)
    {
        return Ok(true);
    }
    let _ = fs::remove_file(path);
    // Only root may read it: swapped pages are any container's memory.
    let f = OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(path)?;
    // Real blocks, not a sparse file: the kernel refuses swap with holes.
    // ext4 marks them unwritten, so no zeros go to the Mac's disk.
    let size = libc::off_t::try_from(len).map_err(|_| io::Error::from_raw_os_error(libc::EFBIG))?;
    // SAFETY: fallocate on a descriptor this function owns.
    if unsafe { libc::fallocate(f.as_raw_fd(), 0, 0, size) } != 0 {
        return Err(io::Error::last_os_error());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    write_header(&f, len, page)?;
    f.sync_all()?;
    Ok(true)
}

/// mkswap's header, version 1: the page count at 1028 and the magic at the
/// end of the first page.
pub(super) fn header(len: u64, page: usize) -> Vec<u8> {
    let mut h = vec![0u8; page];
    let last_page = u32::try_from((len / page as u64).saturating_sub(1)).unwrap_or(u32::MAX);
    h[1024..1028].copy_from_slice(&1u32.to_ne_bytes());
    h[1028..1032].copy_from_slice(&last_page.to_ne_bytes());
    h[page - 10..].copy_from_slice(b"SWAPSPACE2");
    h
}

fn write_header(mut f: &File, len: u64, page: usize) -> io::Result<()> {
    f.seek(SeekFrom::Start(0))?;
    f.write_all(&header(len, page))
}

/// Whether the regular file starts with a swap header for this page size.
fn has_header(path: &Path, page: usize) -> bool {
    let mut h = vec![0u8; page];
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .and_then(|mut f| f.read_exact(&mut h))
        .is_ok()
        && &h[page - 10..] == b"SWAPSPACE2"
}

fn swapon(path: &Path) -> io::Result<()> {
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    // SAFETY: a NUL-terminated path and flags; the kernel reads nothing else.
    if unsafe { libc::swapon(c.as_ptr(), SWAP_FLAG_DISCARD) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_size_comes_from_the_kernel_command_line() {
        assert_eq!(requested("console=hvc0 rdinit=/init kiri.swap=1024 quiet"), Some(1024));
        assert_eq!(requested("kiri.swap=0"), Some(0));
        assert_eq!(requested("kiri.swap=512 kiri.swap=2048"), Some(2048), "the last one counts, as for the kernel's own");
        assert_eq!(requested("console=hvc0 quiet"), None, "an older host says nothing");
        assert_eq!(requested("kiri.swap=lots"), None);
        assert_eq!(requested("kiri.swapfile=1"), None);
    }

    #[test]
    fn the_header_is_mkswaps() {
        for page in [4096, 16384] {
            let h = header(1 << 30, page);
            assert_eq!(h.len(), page);
            assert_eq!(&h[1024..1028], &1u32.to_ne_bytes(), "version 1");
            assert_eq!(u32::from_ne_bytes(h[1028..1032].try_into().unwrap()) as u64, (1u64 << 30) / page as u64 - 1, "last page");
            assert_eq!(&h[1032..1036], &[0; 4], "no bad pages");
            assert_eq!(&h[page - 10..], b"SWAPSPACE2");
        }
    }

    #[test]
    fn the_file_is_made_kept_resized_and_removed() {
        let dir = std::env::temp_dir().join(format!("kiri-swap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("swapfile");
        let page = 4096;

        assert!(ensure(&path, 2, page).unwrap());
        let m = fs::metadata(&path).unwrap();
        assert_eq!(m.len(), 2 << 20);
        assert_eq!(m.permissions().mode() & 0o777, 0o600, "only root reads swapped memory");
        assert!(has_header(&path, page));
        use std::os::unix::fs::MetadataExt;
        assert!(m.blocks() * 512 >= 2 << 20, "allocated, not sparse: the kernel refuses holes");

        // The same size is kept as it is (its inode too).
        let ino = m.ino();
        assert!(ensure(&path, 2, page).unwrap());
        assert_eq!(fs::metadata(&path).unwrap().ino(), ino);

        // A new size, or a file with no header, is made again.
        assert!(ensure(&path, 3, page).unwrap());
        assert_eq!(fs::metadata(&path).unwrap().len(), 3 << 20);
        fs::write(&path, vec![0u8; 3 << 20]).unwrap();
        assert!(ensure(&path, 3, page).unwrap());
        assert!(has_header(&path, page));

        // A symlink at `path` is never followed; it is replaced by a real 0600 file.
        let target = dir.join("decoy");
        fs::write(&target, vec![0u8; 3 << 20]).unwrap();
        let _ = fs::remove_file(&path);
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(ensure(&path, 3, page).unwrap());
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_file());
        assert!(!has_header(&target, page), "decoy target was never written");

        // 0: no swap file, and none is fine too.
        assert!(!ensure(&path, 0, page).unwrap());
        assert!(!path.exists());
        assert!(!ensure(&path, 0, page).unwrap());
        let _ = fs::remove_dir_all(dir);
    }
}
