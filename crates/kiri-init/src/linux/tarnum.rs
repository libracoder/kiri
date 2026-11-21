//! Tar numbers as Go's `archive/tar`, so Docker, reads them: a numeric header
//! field that is empty, only NULs or spaces, is 0. tar-rs refuses one
//! ("numeric field was not a number"), and some image builders leave a
//! directory's size, uid and gid empty, so their layers did not unpack (#618).

use std::io::{self, Read};

const BLOCK: usize = 512;

/// The size field, which tar-rs reads in every header, as (start, end).
const SIZE: (usize, usize) = (124, 136);
/// mode, uid, gid and mtime, which it reads for an entry it unpacks, not for
/// an extension header (PAX, GNU long name): tar-rs itself leaves those
/// empty there.
const ENTRY: [(usize, usize); 4] = [(100, 108), (108, 116), (116, 124), (136, 148)];
/// devmajor and devminor, which it reads for a device of a ustar or GNU
/// header only.
const DEVICE: [(usize, usize); 2] = [(329, 337), (337, 345)];

/// Passes a tar stream through, writing each empty number of a header as 0
/// and making that header's checksum again. Only a header whose checksum is
/// right is touched: a broken one goes on as it came, for tar-rs to refuse.
/// Headers are found where tar-rs looks for them: after each entry's data,
/// whose size a PAX `size` record overrides, and after a GNU sparse header's
/// extension blocks. A zero block ends the archive for tar-rs, and from there
/// on everything passes as it is.
pub struct GoNumbers<R> {
    inner: R,
    block: [u8; BLOCK],
    /// The bytes of `block` read, and how many of them have gone out.
    len: usize,
    at: usize,
    /// Bytes of entry data, with padding, before the next header.
    data: u64,
    /// A GNU sparse extension block comes next.
    sparse_ext: bool,
    /// The data of the PAX `x` entry being read.
    pax: Option<Vec<u8>>,
    /// The size a PAX `x` entry gave the entry after it.
    pax_size: Option<u64>,
    passthrough: bool,
}

impl<R: Read> GoNumbers<R> {
    pub fn new(inner: R) -> GoNumbers<R> {
        GoNumbers { inner, block: [0; BLOCK], len: 0, at: 0, data: 0, sparse_ext: false, pax: None, pax_size: None, passthrough: false }
    }

    /// The next block, read whole if the stream has one.
    fn next_block(&mut self) -> io::Result<()> {
        let mut len = 0;
        while len < BLOCK {
            match self.inner.read(&mut self.block[len..]) {
                Ok(0) => break,
                Ok(n) => len += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        (self.len, self.at) = (len, 0);
        if len < BLOCK {
            // The end, or a cut-off block tar-rs will report.
            self.passthrough = true;
        }
        Ok(())
    }

    fn header(&mut self) {
        let h = &mut self.block;
        if h.iter().all(|&b| b == 0) || Some(checksum(h)) != octal(&h[148..156]) {
            self.passthrough = true;
            return;
        }
        let ustar = &h[257..263] == b"ustar\0" && &h[263..265] == b"00";
        let gnu = &h[257..263] == b"ustar " && &h[263..265] == b" \0";
        let kind = h[156];
        let extension = matches!(kind, b'L' | b'K' | b'x' | b'g');
        let device = (ustar || gnu) && matches!(kind, b'3' | b'4');
        let entry: &[(usize, usize)] = if extension { &[] } else { &ENTRY };
        let devices: &[(usize, usize)] = if device { &DEVICE } else { &[] };
        let mut changed = false;
        for &(a, b) in std::iter::once(&SIZE).chain(entry).chain(devices) {
            if h[a..b].iter().all(|&c| c == 0 || c == b' ') {
                h[a..b - 1].fill(b'0');
                h[b - 1] = 0;
                changed = true;
            }
        }
        if changed {
            let sum = format!("{:06o}\0 ", checksum(h));
            h[148..156].copy_from_slice(sum.as_bytes());
        }

        let Some(mut size) = number(&h[SIZE.0..SIZE.1]) else {
            self.passthrough = true;
            return;
        };
        if !extension && let Some(pax) = self.pax_size.take() {
            size = pax;
        }
        self.sparse_ext = kind == b'S' && gnu && h[482] == 1;
        self.data = size.div_ceil(BLOCK as u64).saturating_mul(BLOCK as u64);
        if kind == b'x' && (ustar || gnu) {
            self.pax = Some(Vec::new());
            self.end_of_data();
        }
    }

    /// An entry's data has all gone: a PAX entry's records take effect.
    fn end_of_data(&mut self) {
        if self.data == 0
            && let Some(pax) = self.pax.take()
        {
            self.pax_size = pax_size(&pax);
        }
    }
}

impl<R: Read> Read for GoNumbers<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if buf.is_empty() {
                return Ok(0);
            }
            if self.at < self.len {
                let n = buf.len().min(self.len - self.at);
                buf[..n].copy_from_slice(&self.block[self.at..self.at + n]);
                self.at += n;
                return Ok(n);
            }
            if self.passthrough {
                return self.inner.read(buf);
            }
            if self.sparse_ext {
                self.next_block()?;
                self.sparse_ext = self.len == BLOCK && self.block[504] == 1;
                continue;
            }
            if self.data > 0 {
                let want = buf.len().min(usize::try_from(self.data).unwrap_or(usize::MAX));
                let n = self.inner.read(&mut buf[..want])?;
                if n == 0 {
                    return Ok(0);
                }
                if let Some(pax) = &mut self.pax {
                    pax.extend_from_slice(&buf[..n]);
                }
                self.data -= n as u64;
                self.end_of_data();
                return Ok(n);
            }
            self.next_block()?;
            if !self.passthrough {
                self.header();
            }
        }
    }
}

/// The header's checksum as tar-rs reckons it: its bytes, the checksum field
/// counted as spaces.
fn checksum(h: &[u8; BLOCK]) -> u64 {
    h[..148].iter().chain(&h[156..]).map(|&b| u64::from(b)).sum::<u64>() + 8 * 32
}

/// An octal field as tar-rs reads it: up to its first NUL, spaces trimmed.
fn octal(field: &[u8]) -> Option<u64> {
    let text = field.split(|&b| b == 0).next().unwrap_or_default();
    u64::from_str_radix(std::str::from_utf8(text).ok()?.trim(), 8).ok()
}

/// A numeric field, octal or (high bit set) base-256, as tar-rs reads it.
fn number(field: &[u8]) -> Option<u64> {
    if field[0] & 0x80 == 0 {
        return octal(field);
    }
    let (first, rest) = if field.len() == 8 { (u64::from(field[0] ^ 0x80), &field[1..]) } else { (0, &field[field.len() - 8..]) };
    Some(rest.iter().fold(first, |n, &b| (n << 8) | u64::from(b)))
}

/// The `size` record of PAX extension data, the first one, as tar-rs takes it.
fn pax_size(mut data: &[u8]) -> Option<u64> {
    while let Some(space) = data.iter().position(|&b| b == b' ') {
        let len: usize = std::str::from_utf8(&data[..space]).ok()?.parse().ok()?;
        if len <= space || len > data.len() {
            return None;
        }
        let record = &data[space + 1..len];
        let record = record.strip_suffix(b"\n").unwrap_or(record);
        if let Some(value) = record.strip_prefix(b"size=") {
            return std::str::from_utf8(value).ok()?.parse().ok();
        }
        data = &data[len..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(path: &str, kind: tar::EntryType, size: u64) -> tar::Header {
        let mut h = tar::Header::new_ustar();
        h.set_path(path).unwrap();
        h.set_entry_type(kind);
        h.set_size(size);
        h.set_mode(0o755);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(1);
        h.set_cksum();
        h
    }

    /// What the servicebus-emulator layer has (#618): a directory whose size,
    /// uid and gid are all NULs, its checksum right.
    fn blank(h: &mut tar::Header) {
        let b = h.as_mut_bytes();
        b[108..136].fill(0);
        let sum = format!("{:06o}\0 ", checksum(b));
        b[148..156].copy_from_slice(sum.as_bytes());
    }

    fn archive(blank_dir: bool) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        // A PAX header first, as in the layer, and a long name after it.
        b.append_pax_extensions([("mtime", &b"1.5"[..])]).unwrap();
        let mut dir = header("app", tar::EntryType::Directory, 0);
        if blank_dir {
            blank(&mut dir);
        }
        b.append(&dir, io::empty()).unwrap();
        let long = format!("app/{}", "n".repeat(120));
        b.append_data(&mut header("x", tar::EntryType::Regular, 5), &long, &b"hello"[..]).unwrap();
        b.append(&header("app/b", tar::EntryType::Regular, 600), &[7u8; 600][..]).unwrap();
        b.into_inner().unwrap()
    }

    fn entries(bytes: &[u8]) -> io::Result<Vec<(String, u64, Vec<u8>)>> {
        let mut a = tar::Archive::new(GoNumbers::new(bytes));
        let mut out = Vec::new();
        for e in a.entries()? {
            let mut e = e?;
            let mut data = Vec::new();
            e.read_to_end(&mut data)?;
            out.push((e.path()?.to_string_lossy().into_owned(), e.header().uid()?, data));
        }
        Ok(out)
    }

    #[test]
    fn empty_numbers_read_as_zero_like_go() {
        let bytes = archive(true);
        let err = tar::Archive::new(&bytes[..]).entries().unwrap().find_map(Result::err).expect("tar-rs alone refuses it");
        assert!(err.to_string().contains("numeric field was not a number"), "{err}");
        let got = entries(&bytes).unwrap();
        assert_eq!(got.iter().map(|e| e.0.as_str()).collect::<Vec<_>>(), ["app", &format!("app/{}", "n".repeat(120)), "app/b"]);
        assert_eq!(got[0].1, 0, "an empty uid is root's");
        assert_eq!(got[1].2, b"hello");
        assert_eq!(got[2].2, [7u8; 600]);
    }

    /// Passes `bytes` through, failing at the first byte that changed.
    fn assert_unchanged(bytes: &[u8]) {
        let mut out = Vec::new();
        GoNumbers::new(bytes).read_to_end(&mut out).unwrap();
        if let Some(i) = out.iter().zip(bytes).position(|(a, b)| a != b) {
            panic!("byte {i} (block {}, offset {}) changed: {:?} -> {:?}", i / BLOCK, i % BLOCK, bytes[i] as char, out[i] as char);
        }
        assert_eq!(out.len(), bytes.len());
    }

    #[test]
    fn a_complete_archive_passes_unchanged() {
        let bytes = archive(false);
        assert_unchanged(&bytes);
    }

    #[test]
    fn data_that_looks_like_a_header_is_left_alone() {
        // A file holding a header with empty numbers, then a PAX size that
        // makes the next entry's data longer than its header says.
        let mut inner = header("fake", tar::EntryType::Directory, 0);
        blank(&mut inner);
        let mut b = tar::Builder::new(Vec::new());
        b.append(&header("tarball", tar::EntryType::Regular, 512), &inner.as_bytes()[..]).unwrap();
        b.append_pax_extensions([("size", &b"512"[..])]).unwrap();
        b.append(&header("sized", tar::EntryType::Regular, 0), &inner.as_bytes()[..]).unwrap();
        let bytes = b.into_inner().unwrap();
        assert_unchanged(&bytes);
    }

    #[test]
    fn a_header_with_a_wrong_checksum_is_not_mended() {
        let mut bytes = archive(true);
        // The directory's header follows the PAX header and its data.
        let dir = bytes.chunks(BLOCK).position(|b| b.starts_with(b"app\0")).unwrap() * BLOCK;
        bytes[dir + 150] ^= 1;
        assert_unchanged(&bytes);
        assert!(entries(&bytes).is_err());
    }

    #[test]
    fn numbers_and_pax_records_parse_as_in_tar_rs() {
        assert_eq!(octal(b"0000755\0"), Some(0o755));
        assert_eq!(octal(b" 755 \0\0\0"), Some(0o755));
        assert_eq!(octal(b"\0\0\0\0"), None);
        assert_eq!(number(&[0x80, 0, 0, 0, 0, 0, 1, 0]), Some(256));
        assert_eq!(number(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1]), Some(513));
        assert_eq!(pax_size(b"20 path=a/b/c/d/e/f\n12 size=600\n"), Some(600));
        assert_eq!(pax_size(b"12 size=600\n11 size=10\n"), Some(600));
        assert_eq!(pax_size(b"28 mtime=1768240195.7895585\n\0\0\0"), None);
        assert_eq!(pax_size(b"99 size=1\n"), None);
    }
}
