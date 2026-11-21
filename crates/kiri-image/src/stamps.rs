//! Which blobs the store has verified, so a blob is read whole to check its
//! digest only on its first use after it changed.
//!
//! A stamp is the blob's stat when it was last known good: size, mtime and
//! ctime in nanoseconds and inode, plus, for a pulled layer, the diff_id it
//! unpacked to. A blob whose stat still matches is trusted without being
//! read. Any write through a file system moves ctime, which nothing can set
//! back, so a blob truncated, flipped or replaced since is read again.
//!
//! The stamps live in `blobs/stamps`, one line per stamp, appended without a
//! sync: a stamp lost in a crash only costs a hash. Each line ends with a
//! checksum of itself, so a torn or damaged line is skipped rather than
//! trusted; the last good line for a blob wins. The file is rewritten whole
//! when it holds many more lines than stamps.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    pub size: u64,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
    pub ino: u64,
}

impl Stat {
    pub fn of(path: &Path) -> io::Result<Stat> {
        let m = fs::metadata(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Stat {
                size: m.len(),
                mtime_ns: i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()),
                ctime_ns: i128::from(m.ctime()) * 1_000_000_000 + i128::from(m.ctime_nsec()),
                ino: m.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            // No ctime or inode here: an mtime that never moves backward
            // is all there is, so a stamp is weaker but still a stamp.
            let mtime_ns = m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_nanos() as i128);
            Ok(Stat { size: m.len(), mtime_ns, ctime_ns: mtime_ns, ino: 0 })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
    pub stat: Stat,
    /// For a layer: the sha256 of its decompressed tar, once known.
    pub diff_id: Option<String>,
}

#[derive(Debug)]
pub struct Stamps {
    path: PathBuf,
    by_hex: HashMap<String, Stamp>,
    lines: usize,
}

fn check(text: &str) -> String {
    super::store::hex_of(&Sha256::digest(text.as_bytes())[..8])
}

fn line(hex: &str, s: &Stamp) -> String {
    let body = format!("{hex} {} {} {} {} {}", s.stat.size, s.stat.mtime_ns, s.stat.ctime_ns, s.stat.ino, s.diff_id.as_deref().unwrap_or("-"));
    let sum = check(&body);
    format!("{body} {sum}\n")
}

fn parse(l: &str) -> Option<(String, Stamp)> {
    let (body, sum) = l.rsplit_once(' ')?;
    if check(body) != sum {
        return None;
    }
    let f: Vec<&str> = body.split(' ').collect();
    let [hex, size, mtime, ctime, ino, diff] = f[..] else { return None };
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let diff_id = match diff {
        "-" => None,
        d if super::store::digest_hex(d).is_ok() => Some(d.to_owned()),
        _ => return None,
    };
    let stat = Stat { size: size.parse().ok()?, mtime_ns: mtime.parse().ok()?, ctime_ns: ctime.parse().ok()?, ino: ino.parse().ok()? };
    Some((hex.to_owned(), Stamp { stat, diff_id }))
}

impl Stamps {
    pub fn load(path: PathBuf) -> Stamps {
        let mut by_hex = HashMap::new();
        let mut lines = 0;
        if let Ok(bytes) = fs::read(&path) {
            for l in String::from_utf8_lossy(&bytes).lines() {
                lines += 1;
                if let Some((h, s)) = parse(l) {
                    by_hex.insert(h, s);
                }
            }
        }
        let mut stamps = Stamps { path, by_hex, lines };
        if stamps.lines > 2 * stamps.by_hex.len() + 64 {
            stamps.compact();
        }
        stamps
    }

    pub fn get(&self, hex: &str) -> Option<&Stamp> {
        self.by_hex.get(hex)
    }

    pub fn set(&mut self, hex: &str, stamp: Stamp) {
        if self.by_hex.get(hex) == Some(&stamp) {
            return;
        }
        let l = line(hex, &stamp);
        self.by_hex.insert(hex.to_owned(), stamp);
        // Best effort: a stamp that is not written is a hash next time.
        let _ = OpenOptions::new().create(true).append(true).open(&self.path).and_then(|mut f| f.write_all(l.as_bytes()));
        self.lines += 1;
        if self.lines > 2 * self.by_hex.len() + 64 {
            self.compact();
        }
    }

    /// Forgets a blob's stamp here. Its line stays in the file until the
    /// next rewrite, harmless: a blob written again under the name has
    /// another inode and ctime, so the old line does not match it.
    pub fn remove(&mut self, hex: &str) {
        self.by_hex.remove(hex);
    }

    fn compact(&mut self) {
        let mut text = String::new();
        for (h, s) in &self.by_hex {
            text.push_str(&line(h, s));
        }
        if crate::jsonfile::replace(&self.path, text.as_bytes(), crate::jsonfile::Durable::Later).is_ok() {
            self.lines = self.by_hex.len();
        }
    }
}
