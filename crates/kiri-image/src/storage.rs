//! Settings → Storage: the folder a person chose for Kiri's data, kept in
//! `~/.kiri/storage.json` (`{"path": "/Volumes/External/kiri"}`), beside
//! `vm.json` and never inside the data folder itself.
//!
//! Nobody who leaves the setting alone has the file: [`crate::Store::default_root`]
//! then gives the folder it always did. With the file, the chosen folder
//! counts only while it holds the [`MARKER`] a finished move writes there:
//! a drive that isn't connected must not get an empty store made in its
//! place under `/Volumes`, so the folder is reported unavailable instead
//! ([`Unavailable`]).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The file, under the state folder (`~/.kiri`).
pub const FILE: &str = "storage.json";

/// Written into a data folder once a move into it is complete: what tells
/// a Kiri data folder from an empty mount point or someone else's files.
pub const MARKER: &str = ".kiri-storage";

/// What `storage.json` holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Choice {
    /// The data folder.
    pub path: PathBuf,
    /// The folder the data was moved from and that still holds a copy,
    /// until Settings → Storage → Remove old data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<PathBuf>,
}

/// The chosen folder isn't there, or isn't Kiri's (its drive isn't
/// connected): the error [`crate::Store::default_root`] gives for it.
#[derive(Debug)]
pub struct Unavailable(pub PathBuf);

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Kiri's data folder {} isn't available: connect its drive, or choose Settings → Storage → Reset to default", self.0.display())
    }
}

impl std::error::Error for Unavailable {}

/// The folder an [`Unavailable`] error names.
pub fn unavailable(e: &io::Error) -> Option<&Path> {
    e.get_ref().and_then(|inner| inner.downcast_ref::<Unavailable>()).map(|u| u.0.as_path())
}

/// `~/.kiri/storage.json`.
pub fn config_path() -> io::Result<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| io::Error::other("HOME is not set"))?;
    Ok(home.join(".kiri").join(FILE))
}

/// The choice in `file`; None when there is no file.
pub fn read_at(file: &Path) -> io::Result<Option<Choice>> {
    match fs::read(file) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", file.display()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// The choice in `~/.kiri/storage.json`, if there is one.
pub fn read() -> io::Result<Option<Choice>> {
    read_at(&config_path()?)
}

/// Writes `choice` to `file` whole: a temporary file renamed over it and
/// synced, so a crash leaves the old choice or the new one. This write is
/// a move's commit point.
pub fn write_at(file: &Path, choice: &Choice) -> io::Result<()> {
    if let Some(dir) = file.parent() {
        fs::create_dir_all(dir)?;
    }
    let bytes = serde_json::to_vec_pretty(choice).map_err(io::Error::other)?;
    crate::jsonfile::replace(file, &bytes, crate::jsonfile::Durable::Now)
}

/// Writes `~/.kiri/storage.json`.
pub fn write(choice: &Choice) -> io::Result<()> {
    write_at(&config_path()?, choice)
}

/// Removes `~/.kiri/storage.json`: back to the default folder, as if the
/// setting had never been changed.
pub fn clear() -> io::Result<()> {
    match fs::remove_file(config_path()?) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Whether `dir` holds the marker of a finished move.
pub fn has_marker(dir: &Path) -> bool {
    dir.join(MARKER).is_file()
}

/// Writes the marker into `dir`.
pub fn write_marker(dir: &Path) -> io::Result<()> {
    crate::jsonfile::replace(&dir.join(MARKER), b"{\"kiri\":1}\n", crate::jsonfile::Durable::Now)
}

/// The data folder `choice` gives, where `default` is the one without
/// it: the chosen folder if it holds the marker, else [`Unavailable`].
/// The default folder needs no marker.
pub fn resolve(choice: Option<Choice>, default: PathBuf) -> io::Result<PathBuf> {
    match choice {
        None => Ok(default),
        Some(c) if c.path == default || has_marker(&c.path) => Ok(c.path),
        Some(c) => Err(io::Error::new(io::ErrorKind::NotFound, Unavailable(c.path))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kiri-storage-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// No file: the default folder, and nothing is written.
    #[test]
    fn no_file_is_the_default_folder() {
        let d = scratch("none");
        let file = d.join(FILE);
        assert_eq!(read_at(&file).unwrap(), None);
        assert_eq!(resolve(read_at(&file).unwrap(), d.join("default")).unwrap(), d.join("default"));
        assert!(!file.exists());
        let _ = fs::remove_dir_all(&d);
    }

    /// A chosen folder counts once it holds the marker; without it (the
    /// drive isn't connected) it is unavailable, never the default and
    /// never made.
    #[test]
    fn a_chosen_folder_needs_its_marker() {
        let d = scratch("marker");
        let file = d.join(FILE);
        let chosen = d.join("external/kiri");
        write_at(&file, &Choice { path: chosen.clone(), previous: None }).unwrap();
        let e = resolve(read_at(&file).unwrap(), d.join("default")).unwrap_err();
        assert_eq!(unavailable(&e), Some(chosen.as_path()));
        assert!(e.to_string().contains("isn't available"), "{e}");
        assert!(!chosen.exists(), "an unavailable folder is never made");
        fs::create_dir_all(&chosen).unwrap();
        write_marker(&chosen).unwrap();
        assert_eq!(resolve(read_at(&file).unwrap(), d.join("default")).unwrap(), chosen);
        let _ = fs::remove_dir_all(&d);
    }

    /// The file is replaced whole, and an old copy's `previous` is kept
    /// only when written.
    #[test]
    fn the_choice_round_trips() {
        let d = scratch("roundtrip");
        let file = d.join(FILE);
        let c = Choice { path: d.join("a"), previous: Some(d.join("b")) };
        write_at(&file, &c).unwrap();
        assert_eq!(read_at(&file).unwrap(), Some(c));
        write_at(&file, &Choice { path: d.join("a"), previous: None }).unwrap();
        assert!(!fs::read_to_string(&file).unwrap().contains("previous"));
        fs::write(&file, b"{not json").unwrap();
        assert_eq!(read_at(&file).unwrap_err().kind(), io::ErrorKind::InvalidData);
        let _ = fs::remove_dir_all(&d);
    }
}
