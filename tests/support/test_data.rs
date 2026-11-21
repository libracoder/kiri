//! Where the builder's test data is: the golden vectors (`golden/`) and the
//! wire captures and vectors (`wire/`), kept outside this repository and
//! fetched by `scripts/fetch-test-data.sh`. Included by the tests that read
//! them (`#[path = ...] mod test_data;`), so there is one copy of the rule:
//!
//! 1. `KIRI_TEST_DATA`, a folder holding `golden/` and `wire/`;
//! 2. else `tests/data-cache/` in this repository (git-ignored);
//! 3. else absent: the test prints one `SKIPPED: ...` line for its file and
//!    returns, or, with `KIRI_TEST_DATA_REQUIRED=1`, fails.

#![allow(dead_code)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Once;

/// The line printed when the data is absent.
pub const SKIP_LINE: &str = "SKIPPED: needs the builder test data (run scripts/fetch-test-data.sh)";

/// What `resolve` found.
#[derive(Debug, PartialEq, Eq)]
pub enum Found {
    /// The folder holding `golden/` and `wire/`.
    At(PathBuf),
    /// No data: the test skips.
    Absent,
}

/// Whether `dir` holds the test data (both folders, with their vectors).
pub fn holds_data(dir: &Path) -> bool {
    dir.join("golden/vectors").is_dir() && dir.join("wire/vectors").is_dir()
}

/// The rule above, without touching the environment: `from_env` is the
/// value of `KIRI_TEST_DATA`, `cache` the repository's cache folder,
/// `required` whether `KIRI_TEST_DATA_REQUIRED=1`. An error is a failure
/// the test must report: a `KIRI_TEST_DATA` that names no data, or data
/// required and absent.
pub fn resolve(from_env: Option<&Path>, cache: &Path, required: bool) -> Result<Found, String> {
    if let Some(dir) = from_env.filter(|d| !d.as_os_str().is_empty()) {
        if holds_data(dir) {
            return Ok(Found::At(dir.to_path_buf()));
        }
        return Err(format!("KIRI_TEST_DATA={} does not hold the builder test data (golden/vectors and wire/vectors)", dir.display()));
    }
    if holds_data(cache) {
        return Ok(Found::At(cache.to_path_buf()));
    }
    if required {
        return Err(format!(
            "the builder test data is required (KIRI_TEST_DATA_REQUIRED=1) and absent from KIRI_TEST_DATA and {}: set KIRI_TEST_DATA to a checkout of it, or run scripts/fetch-test-data.sh",
            cache.display()
        ));
    }
    Ok(Found::Absent)
}

/// The repository's cache folder. Every crate that includes this file sits
/// at `crates/<name>`.
pub fn cache_dir() -> PathBuf {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    crate_dir.parent().and_then(Path::parent).unwrap_or(crate_dir).join("tests/data-cache")
}

/// The data folder, or `None` after printing the skip line once for the
/// calling test file (the caller's file, through `#[track_caller]`). Panics
/// with the reason when the data is required and absent, or
/// `KIRI_TEST_DATA` is wrong.
#[track_caller]
pub fn root() -> Option<PathBuf> {
    let file = std::panic::Location::caller().file();
    let from_env = std::env::var_os("KIRI_TEST_DATA").map(PathBuf::from);
    let required = std::env::var("KIRI_TEST_DATA_REQUIRED").is_ok_and(|v| v == "1");
    match resolve(from_env.as_deref(), &cache_dir(), required) {
        Ok(Found::At(dir)) => Some(dir),
        Ok(Found::Absent) => {
            // Written to the process's stderr, not through eprintln!, so the
            // test harness does not swallow it for a passing test.
            static ONCE: Once = Once::new();
            ONCE.call_once(|| {
                let _ = writeln!(std::io::stderr(), "{SKIP_LINE}: {file}");
            });
            None
        }
        Err(why) => panic!("{file}: {why}"),
    }
}

/// `golden/` of the data, or `None` (skipped, see `root`).
#[track_caller]
pub fn golden() -> Option<PathBuf> {
    root().map(|r| r.join("golden"))
}

/// `wire/` of the data, or `None` (skipped, see `root`).
#[track_caller]
pub fn wire() -> Option<PathBuf> {
    root().map(|r| r.join("wire"))
}
