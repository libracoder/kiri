//! Grow the Mac's sparse backing file before attaching it to the VM.

use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};

/// Default template data disk size in GiB (`cargo xtask disk` makes a 64 GiB
/// sparse ext4 template).
pub const DEFAULT_GB: u64 = 64;
/// Default upper bound for the Settings → Resources disk slider in GiB.
pub const MAX_UI_GB: u64 = 1024;
const GIB: u64 = 1 << 30;

fn invalid_size() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "KIRI_DISK_GB must be a positive whole number of GiB that fits the disk image",
    )
}

/// Converts a positive GiB count to bytes, rejecting zero and values that
/// overflow `u64` or exceed `i64::MAX`.
pub fn size_bytes(gb: u64) -> io::Result<u64> {
    if gb == 0 {
        return Err(invalid_size());
    }
    gb.checked_mul(GIB)
        .filter(|&bytes| bytes <= i64::MAX as u64)
        .ok_or_else(invalid_size)
}

pub fn parse_size_gb(value: &str) -> io::Result<u64> {
    let gb = value.parse::<u64>().map_err(|_| invalid_size())?;
    size_bytes(gb)?;
    Ok(gb)
}

pub fn parse_size(value: &str) -> io::Result<u64> {
    size_bytes(parse_size_gb(value)?)
}

/// Resolves the requested disk size in bytes: `KIRI_DISK_GB` takes precedence
/// over a persistent `vm.json` `"disk_gb"` value. An invalid `KIRI_DISK_GB`
/// returns `InvalidInput` rather than silently falling back.
pub fn resolve_requested_size(
    env_val: Option<&str>,
    configured_gb: Option<u64>,
) -> io::Result<Option<u64>> {
    if let Some(value) = env_val {
        return parse_size(value).map(Some);
    }
    configured_gb.map(size_bytes).transpose()
}

/// Resolves the requested disk size from `KIRI_DISK_GB` in the process
/// environment, falling back to `configured_gb` from `vm.json`.
pub fn requested_size(configured_gb: Option<u64>) -> io::Result<Option<u64>> {
    let env_os = std::env::var_os("KIRI_DISK_GB");
    let env_str = env_os.as_ref().map(|v| v.to_str().unwrap_or_default());
    resolve_requested_size(env_str, configured_gb)
}

/// Resolves the effective disk size in GiB for Settings and status reporting:
/// `KIRI_DISK_GB` (if valid), else `vm.json`'s `disk_gb` (if valid), else
/// `DEFAULT_GB`, and never smaller than the existing `data.img` (`current_gb`).
pub fn effective_gb(env_val: Option<&str>, configured_gb: Option<u64>, current_gb: u64) -> u64 {
    let min_gb = current_gb.max(DEFAULT_GB);
    let wanted = env_val
        .and_then(|v| parse_size_gb(v).ok())
        .or_else(|| configured_gb.filter(|&gb| size_bytes(gb).is_ok()))
        .unwrap_or(DEFAULT_GB);
    wanted.max(min_gb)
}

/// The path to the VM's data disk backing file (`<data_dir>/vm/data.img`).
pub fn data_disk_path() -> Option<PathBuf> {
    kiri_image::Store::default_root()
        .ok()
        .map(|root| root.join("vm/data.img"))
}

/// Current size in GiB of an existing backing file, or `DEFAULT_GB` when the
/// file does not exist yet or is smaller than the template size.
pub fn current_gb_at(path: &Path) -> u64 {
    std::fs::metadata(path)
        .ok()
        .map(|m| m.len().div_ceil(GIB))
        .unwrap_or(DEFAULT_GB)
        .max(DEFAULT_GB)
}

/// Current size in GiB of the default data disk file.
pub fn current_gb() -> u64 {
    data_disk_path()
        .map(|p| current_gb_at(&p))
        .unwrap_or(DEFAULT_GB)
}

/// Allowed `(min_gb, max_gb)` range for Settings → Resources: never shrinks
/// below the current disk image size (or 64 GiB), and expands up to at least
/// `MAX_UI_GB` (1024 GiB).
pub fn ui_bounds(current_gb: u64, effective_gb: u64) -> (u64, u64) {
    let min_gb = current_gb.max(DEFAULT_GB);
    let max_gb = MAX_UI_GB.max(min_gb).max(effective_gb);
    (min_gb, max_gb)
}

/// Grows the sparse backing file to `requested` bytes if it is currently
/// smaller. Never shrinks an existing file.
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
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn sizes_are_gib_and_invalid_or_overflowing_values_are_rejected() {
        assert_eq!(parse_size("64").unwrap(), 64 << 30);
        assert_eq!(parse_size("128").unwrap(), 128 << 30);
        assert_eq!(size_bytes(1024).unwrap(), 1024 << 30);
        assert_eq!(
            size_bytes(0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            size_bytes(8_589_934_592).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            size_bytes(u64::MAX).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
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
                io::ErrorKind::InvalidInput,
                "expected InvalidInput for {value:?}"
            );
        }
    }

    #[test]
    fn env_precedence_over_vm_json_and_invalid_env_is_rejected() {
        // KIRI_DISK_GB wins over vm.json.
        assert_eq!(
            resolve_requested_size(Some("256"), Some(128)).unwrap(),
            Some(256 << 30)
        );
        // Even a smaller KIRI_DISK_GB wins in resolution (grow() then refuses to shrink).
        assert_eq!(
            resolve_requested_size(Some("96"), Some(256)).unwrap(),
            Some(96 << 30)
        );
        // Without KIRI_DISK_GB, vm.json's disk_gb is used.
        assert_eq!(
            resolve_requested_size(None, Some(128)).unwrap(),
            Some(128 << 30)
        );
        // Neither set means keep template/current size.
        assert_eq!(resolve_requested_size(None, None).unwrap(), None);
        // Invalid KIRI_DISK_GB fails loudly rather than silently falling back to vm.json.
        assert_eq!(
            resolve_requested_size(Some("0"), Some(128))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            resolve_requested_size(Some("128GB"), Some(128))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn effective_size_and_ui_bounds_never_shrink() {
        // Default 64 GiB when neither env nor vm.json is set.
        assert_eq!(effective_gb(None, None, 64), 64);
        assert_eq!(effective_gb(None, None, 32), 64);
        // vm.json applies when larger than current.
        assert_eq!(effective_gb(None, Some(128), 64), 128);
        // Env overrides vm.json.
        assert_eq!(effective_gb(Some("256"), Some(128), 64), 256);
        // Lowering vm.json or env below current disk size never reports a smaller disk.
        assert_eq!(effective_gb(None, Some(96), 128), 128);
        assert_eq!(effective_gb(Some("64"), Some(96), 128), 128);
        assert_eq!(effective_gb(Some("32"), None, 64), 64);
        // Bounds never allow shrinking below current disk size or 64 GiB.
        assert_eq!(ui_bounds(64, 64), (64, 1024));
        assert_eq!(ui_bounds(128, 256), (128, 1024));
        assert_eq!(ui_bounds(64, 2048), (64, 2048));
        assert_eq!(ui_bounds(1536, 1536), (1536, 1536));
    }

    #[test]
    fn growth_preserves_data_and_holes_and_never_shrinks() {
        let path = std::env::temp_dir().join(format!(
            "kiri-disk-grow-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        drop(file);
        std::fs::write(&path, b"keep").unwrap();
        grow(&path, None).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 4);
        // Below 64 GiB template floor still reports 64 GiB for UI.
        assert_eq!(current_gb_at(&path), 64);

        grow(&path, Some(128 << 20)).unwrap();
        grow(&path, Some(64 << 20)).unwrap();
        grow(&path, None).unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.len(), 128 << 20);
        assert!(metadata.blocks() * 512 < 1 << 20);
        let mut contents = [0; 8];
        std::fs::File::open(&path)
            .unwrap()
            .read_exact(&mut contents)
            .unwrap();
        assert_eq!(&contents, b"keep\0\0\0\0");

        // Sparse growth to 128 GiB keeps existing bytes, stays sparse, and reports 128 GiB.
        grow(&path, Some(128 << 30)).unwrap();
        grow(&path, Some(64 << 30)).unwrap();
        let big = std::fs::metadata(&path).unwrap();
        assert_eq!(big.len(), 128 << 30);
        assert!(big.blocks() * 512 < 1 << 20);
        assert_eq!(current_gb_at(&path), 128);
        let mut head = [0; 4];
        std::fs::File::open(&path)
            .unwrap()
            .read_exact(&mut head)
            .unwrap();
        assert_eq!(&head, b"keep");

        std::fs::remove_file(path).unwrap();
    }
}
