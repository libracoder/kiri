//! Grow the Mac's sparse backing file before attaching it to the VM.

use std::fs::OpenOptions;
use std::io;
use std::path::Path;

pub fn requested_size() -> io::Result<Option<u64>> {
    std::env::var_os("KIRI_DISK_GB")
        .map(|value| parse_size(value.to_str().unwrap_or_default()))
        .transpose()
}

fn parse_size(value: &str) -> io::Result<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|gb| *gb > 0)
        .and_then(|gb| gb.checked_mul(1 << 30))
        .filter(|bytes| *bytes <= i64::MAX as u64)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "KIRI_DISK_GB must be a positive whole number of GiB that fits the disk image",
            )
        })
}

pub fn grow(path: &Path, requested: Option<u64>) -> io::Result<()> {
    let Some(bytes) = requested else {
        return Ok(());
    };
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    if file.metadata()?.len() < bytes {
        // Extending creates holes, rather than allocating the requested
        // capacity. The agent grows ext4 after mounting it at the next boot.
        file.set_len(bytes).map_err(|e| {
            io::Error::new(e.kind(), format!("grow data disk {}: {e}", path.display()))
        })?;
        file.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn sizes_are_gib_and_invalid_or_overflowing_values_are_rejected() {
        assert_eq!(parse_size("64").unwrap(), 64 << 30);
        assert_eq!(parse_size("128").unwrap(), 128 << 30);
        for value in [
            "",
            "0",
            "-1",
            "1.5",
            "128GB",
            "18446744073709551615",
            "8589934592",
        ] {
            assert_eq!(
                parse_size(value).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn growth_preserves_data_and_holes_and_never_shrinks() {
        let path = std::env::temp_dir().join(format!("kiri-disk-grow-{}", std::process::id()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        drop(file);
        std::fs::write(&path, b"keep").unwrap();
        grow(&path, None).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 4);
        grow(&path, Some(128 << 20)).unwrap();
        grow(&path, Some(64 << 20)).unwrap();
        grow(&path, None).unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.len(), 128 << 20);
        assert!(metadata.blocks() * 512 < 1 << 20);
        use std::io::Read;
        let mut contents = [0; 8];
        std::fs::File::open(&path)
            .unwrap()
            .read_exact(&mut contents)
            .unwrap();
        assert_eq!(&contents, b"keep\0\0\0\0");
        std::fs::remove_file(path).unwrap();
    }
}
