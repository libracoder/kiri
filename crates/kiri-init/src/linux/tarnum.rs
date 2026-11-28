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
/// realsize, which it reads for a GNU sparse header only.
const REALSIZE: [(usize, usize); 1] = [(483, 495)];

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
    /// The data of the PAX `x` entry being read, and how many unpadded bytes
    /// of it remain (tar-rs skips the block padding after it).
    pax: Option<(Vec<u8>, u64)>,
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
        let continues = (ustar || gnu) && matches!(kind, b'L' | b'K' | b'x');
        let device = (ustar || gnu) && matches!(kind, b'3' | b'4');
        let sparse = gnu && kind == b'S';
        let entry: &[(usize, usize)] = if extension { &[] } else { &ENTRY };
        let devices: &[(usize, usize)] = if device { &DEVICE } else { &[] };
        let realsize: &[(usize, usize)] = if sparse { &REALSIZE } else { &[] };
        let mut changed = false;
        for &(a, b) in std::iter::once(&SIZE).chain(entry).chain(devices).chain(realsize) {
            let lead = h[a..b].iter().take_while(|&&c| c == 0 || c == b' ').count();
            if lead == b - a {
                h[a..b - 1].fill(b'0');
                h[b - 1] = 0;
                changed = true;
            } else if h[a..a + lead].contains(&0) {
                // Leading NULs before the digits: Go skips them (parseOctal
                // trims " \x00"); tar-rs would stop at the first one.
                h[a..a + lead].fill(b'0');
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
        if !continues
            && let Some(pax) = self.pax_size.take()
            && !extension
        {
            size = pax;
        }
        self.sparse_ext = sparse && h[482] == 1;
        self.data = size.div_ceil(BLOCK as u64).saturating_mul(BLOCK as u64);
        if kind == b'x' && (ustar || gnu) {
            self.pax = Some((Vec::new(), size));
            self.end_of_data();
        }
    }

    /// An entry's data has all gone: a PAX entry's records take effect.
    fn end_of_data(&mut self) {
        if self.data == 0
            && let Some((pax, _)) = self.pax.take()
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
                if let Some((pax, left)) = &mut self.pax {
                    let take = (n as u64).min(*left) as usize;
                    pax.extend_from_slice(&buf[..take]);
                    *left -= take as u64;
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
fn pax_size(data: &[u8]) -> Option<u64> {
    for line in data.split(|&b| b == b'\n') {
        if line.is_empty() {
            break;
        }
        let space = line.iter().position(|&b| b == b' ')?;
        let len: usize = std::str::from_utf8(&line[..space]).ok()?.parse().ok()?;
        if line.len() + 1 != len {
            return None;
        }
        let rest = &line[space + 1..];
        let eq = rest.iter().position(|&b| b == b'=')?;
        if &rest[..eq] == b"size" {
            return std::str::from_utf8(&rest[eq + 1..]).ok()?.parse().ok();
        }
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
        assert_eq!(pax_size(b"11 size=512"), None, "missing trailing newline");
        assert_eq!(pax_size(b"24 comment=a\n12 size=512\n"), None, "embedded newline breaks line length");
        assert_eq!(pax_size(b"11 foobar!\n12 size=512\n"), None, "record without '=' aborts parsing");
    }

    /// A reader that yields at most `step` bytes at a time, and `Interrupted`
    /// every other call, as a decompressor or pipe may.
    struct Trickle<'a> {
        bytes: &'a [u8],
        step: usize,
        tick: usize,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.tick += 1;
            if self.tick.is_multiple_of(2) {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            let n = buf.len().min(self.step).min(self.bytes.len());
            buf[..n].copy_from_slice(&self.bytes[..n]);
            self.bytes = &self.bytes[n..];
            Ok(n)
        }
    }

    #[test]
    fn short_reads_and_interrupted_reads_stay_in_sync() {
        let raw = archive(true);
        let mut expected = Vec::new();
        GoNumbers::new(&raw[..]).read_to_end(&mut expected).unwrap();

        for step in [1, 7, 73, 511, 512, 513] {
            let mut r = GoNumbers::new(Trickle { bytes: &raw, step, tick: 0 });
            let mut got = Vec::new();
            let mut chunk = vec![0u8; step];
            loop {
                match r.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => got.extend_from_slice(&chunk[..n]),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => panic!("step {step}: {e}"),
                }
            }
            assert_eq!(got, expected, "step {step}");
        }
    }

    #[test]
    fn pax_size_tracks_tar_rs_across_global_longname_and_padding() {
        let mut fake = header("fake", tar::EntryType::Directory, 0);
        blank(&mut fake);
        let mut real = header("after", tar::EntryType::Directory, 0);
        blank(&mut real);

        // 1. PAX `x` followed by GNU `L` longname: `x`'s size=512 still applies
        //    to the regular file after `L`, so its 512-byte payload (a blank-number
        //    header) is left untouched, while `real` after it is mended.
        let mut b = tar::Builder::new(Vec::new());
        b.append_pax_extensions([("size", &b"512"[..])]).unwrap();
        let long = format!("dir/{}", "l".repeat(120));
        let mut lhdr = tar::Header::new_gnu();
        lhdr.set_entry_type(tar::EntryType::GNULongName);
        lhdr.set_size(long.len() as u64 + 1);
        lhdr.set_cksum();
        let mut ldata = long.clone().into_bytes();
        ldata.push(0);
        b.append(&lhdr, &ldata[..]).unwrap();
        let mut bytes = b.into_inner().unwrap();
        bytes.truncate(bytes.len() - 2 * BLOCK);
        bytes.extend_from_slice(header("short", tar::EntryType::Regular, 0).as_bytes());
        let payload_at = bytes.len();
        bytes.extend_from_slice(fake.as_bytes());
        bytes.extend_from_slice(real.as_bytes());
        bytes.extend_from_slice(&[0u8; 2 * BLOCK]);

        let mut out = Vec::new();
        GoNumbers::new(&bytes[..]).read_to_end(&mut out).unwrap();
        assert_eq!(&out[payload_at..payload_at + BLOCK], fake.as_bytes(), "file payload after PAX x + GNU L must not be touched");
        let got = entries(&bytes).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, long);
        assert_eq!(got[0].2, fake.as_bytes());
        assert_eq!(got[1].0, "after");

        // 2. PAX `x` (size=512) followed by PAX global `g` (size=0): tar-rs
        //    yields `g` and drops `x`'s pax_extensions, so the next entry
        //    ("zero", header size=0) has 0 bytes of data, and `real` right
        //    after it is a header that must be mended.
        let mut b = tar::Builder::new(Vec::new());
        b.append_pax_extensions([("size", &b"512"[..])]).unwrap();
        let mut bytes = b.into_inner().unwrap();
        bytes.truncate(bytes.len() - 2 * BLOCK);
        let mut g = header("pax_global", tar::EntryType::XGlobalHeader, 0);
        g.set_cksum();
        bytes.extend_from_slice(g.as_bytes());
        bytes.extend_from_slice(header("zero", tar::EntryType::Regular, 0).as_bytes());
        bytes.extend_from_slice(real.as_bytes());
        bytes.extend_from_slice(&[0u8; 2 * BLOCK]);

        let got = entries(&bytes).unwrap();
        assert_eq!(got.iter().map(|e| e.0.as_str()).collect::<Vec<_>>(), ["pax_global", "zero", "after"]);

        // 3. PAX `x` whose unpadded size is 11 ("11 foo=bar\n"), with
        //    "12 size=512\n" hidden in the 512-byte block padding after byte 11:
        //    tar-rs reads only 11 bytes of `x`, so "zero" has size 0 and `real`
        //    right after it is a header that must be mended.
        let mut x = tar::Header::new_ustar();
        x.set_entry_type(tar::EntryType::XHeader);
        x.set_size(11);
        x.set_cksum();
        let mut xblock = [0u8; BLOCK];
        xblock[..23].copy_from_slice(b"11 foo=bar\n12 size=512\n");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(x.as_bytes());
        bytes.extend_from_slice(&xblock);
        bytes.extend_from_slice(header("zero", tar::EntryType::Regular, 0).as_bytes());
        bytes.extend_from_slice(real.as_bytes());
        bytes.extend_from_slice(&[0u8; 2 * BLOCK]);

        let got = entries(&bytes).unwrap();
        assert_eq!(got.iter().map(|e| e.0.as_str()).collect::<Vec<_>>(), ["zero", "after"]);
    }

    #[test]
    fn base256_size_and_symlink_with_nonzero_size_keep_payload_untouched() {
        let mut fake = header("fake", tar::EntryType::Directory, 0);
        blank(&mut fake);
        let mut real = header("after", tar::EntryType::Directory, 0);
        blank(&mut real);

        // 1. Regular file with GNU base-256 size = 512 holding `fake` as data.
        let mut h256 = header("big", tar::EntryType::Regular, 0);
        h256.as_mut_bytes()[124..136].copy_from_slice(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0]);
        h256.set_cksum();

        // 2. Symlink (`2`) with non-zero size = 512: tar-rs advances `self.next`
        //    past the 512-byte data block (`fake`), so GoNumbers must treat it
        //    as data and not mutate it, then mend `real` after it.
        let mut sym = header("sym", tar::EntryType::Symlink, 512);
        sym.set_link_name("target").unwrap();
        sym.set_cksum();

        // 3. Character device (`3`) with empty mode, uid, gid, size, mtime,
        //    devmajor and devminor.
        let mut chr = header("null", tar::EntryType::Char, 0);
        {
            let b = chr.as_mut_bytes();
            b[100..148].fill(0);
            b[329..345].fill(0);
            let sum = format!("{:06o}\0 ", checksum(b));
            b[148..156].copy_from_slice(sum.as_bytes());
        }

        let mut bytes = Vec::new();
        bytes.extend_from_slice(h256.as_bytes());
        let p1 = bytes.len();
        bytes.extend_from_slice(fake.as_bytes());
        bytes.extend_from_slice(sym.as_bytes());
        let p2 = bytes.len();
        bytes.extend_from_slice(fake.as_bytes());
        bytes.extend_from_slice(chr.as_bytes());
        bytes.extend_from_slice(real.as_bytes());
        bytes.extend_from_slice(&[0u8; 2 * BLOCK]);

        let mut out = Vec::new();
        GoNumbers::new(&bytes[..]).read_to_end(&mut out).unwrap();
        assert_eq!(&out[p1..p1 + BLOCK], fake.as_bytes(), "base-256 file payload must not be mutated");
        assert_eq!(&out[p2..p2 + BLOCK], fake.as_bytes(), "symlink skipped data block must not be mutated");

        let mut a = tar::Archive::new(GoNumbers::new(&bytes[..]));
        let mut names = Vec::new();
        for e in a.entries().unwrap() {
            let e = e.unwrap();
            if e.header().entry_type().is_character_special() {
                assert_eq!(e.header().device_major().unwrap(), Some(0));
                assert_eq!(e.header().device_minor().unwrap(), Some(0));
            }
            names.push(e.path().unwrap().to_string_lossy().into_owned());
        }
        assert_eq!(names, ["big", "sym", "null", "after"]);
    }

    #[test]
    fn gnu_sparse_extended_headers_and_data_stay_in_sync() {
        let mut fake = header("fake", tar::EntryType::Directory, 0);
        blank(&mut fake);
        let mut real = header("after", tar::EntryType::Directory, 0);
        blank(&mut real);

        // GNU sparse header ('S') with isextended = 1 (offset 482), two
        // GnuExtSparseHeader blocks (first with offset 504 = 1, second with 0),
        // and 1 block (512 bytes) of sparse data holding `fake`.
        let mut sp = tar::Header::new_gnu();
        sp.set_path("sparse.bin").unwrap();
        sp.set_entry_type(tar::EntryType::GNUSparse);
        sp.set_mode(0o644);
        sp.set_uid(0);
        sp.set_gid(0);
        sp.set_mtime(1);
        sp.set_size(512);
        {
            let gnu = sp.as_gnu_mut().unwrap();
            gnu.sparse[0].set_offset(0);
            gnu.sparse[0].set_length(512);
            gnu.set_is_extended(true);
            gnu.set_real_size(512);
        }
        sp.set_cksum();

        let mut ext1 = [0u8; BLOCK];
        ext1[504] = 1;
        let ext2 = [0u8; BLOCK];

        let mut bytes = Vec::new();
        bytes.extend_from_slice(sp.as_bytes());
        bytes.extend_from_slice(&ext1);
        bytes.extend_from_slice(&ext2);
        let payload_at = bytes.len();
        bytes.extend_from_slice(fake.as_bytes());
        bytes.extend_from_slice(real.as_bytes());
        bytes.extend_from_slice(&[0u8; 2 * BLOCK]);

        let mut out = Vec::new();
        GoNumbers::new(&bytes[..]).read_to_end(&mut out).unwrap();
        assert_eq!(&out[payload_at..payload_at + BLOCK], fake.as_bytes(), "sparse file payload must not be mutated");

        let got = entries(&bytes).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, "sparse.bin");
        assert_eq!(got[0].2, fake.as_bytes());
        assert_eq!(got[1].0, "after");
    }

    #[test]
    fn leading_nuls_before_octal_digits_parse_as_in_go() {
        // #993: Go's archive/tar trims both spaces and NULs from the left of
        // numeric fields (`\0\0\00644\0` -> 0o644), whereas tar-rs stops at the
        // first NUL and reads 0.
        let mut h = tar::Header::new_gnu();
        h.set_path("hello.txt").unwrap();
        h.set_entry_type(tar::EntryType::Regular);
        h.as_mut_bytes()[100..108].copy_from_slice(b"\x00\x00\x000644\x00");
        h.as_mut_bytes()[108..116].copy_from_slice(b"\x00\x0001750\x00");
        h.as_mut_bytes()[116..124].copy_from_slice(b"\x00\x0001750\x00");
        h.as_mut_bytes()[124..136].copy_from_slice(b"\x00\x00\x00\x00\x00\x00\x00\x00005\x00");
        h.as_mut_bytes()[136..148].copy_from_slice(b"\x000000001750\x00");
        h.set_cksum();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(h.as_bytes());
        let mut payload = [0u8; BLOCK];
        payload[..5].copy_from_slice(b"world");
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&[0u8; 2 * BLOCK]);

        let mut archive = tar::Archive::new(GoNumbers::new(&bytes[..]));
        let mut list = archive.entries().unwrap();
        let mut entry = list.next().unwrap().unwrap();
        assert_eq!(entry.header().mode().unwrap(), 0o644);
        assert_eq!(entry.header().uid().unwrap(), 0o1750);
        assert_eq!(entry.header().gid().unwrap(), 0o1750);
        assert_eq!(entry.header().size().unwrap(), 5);
        assert_eq!(entry.header().mtime().unwrap(), 0o1750);
        let mut body = Vec::new();
        entry.read_to_end(&mut body).unwrap();
        assert_eq!(body, b"world");
        assert!(list.next().is_none());
    }
}
