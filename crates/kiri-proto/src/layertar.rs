//! Tar headers byte for byte as Go's `archive/tar` writes them for a layer,
//! which is what BuildKit's differ (containerd's `ChangeWriter`, header
//! format PAX requested) puts in every layer it makes.
//! A layer's diff_id is the sha256 of these bytes, so a step built here only
//! hits the same cache and gets the same image id if every byte matches.
//!
//! The `tar` crate is not used for this: it writes the checksum field as
//! seven digits and a NUL where Go writes six, a NUL and a space, and it
//! splits and normalises names by its own rules. The guest (step layers)
//! and the daemon (COPY layers) both write through this one encoder.
//!
//! What Go does, in the order it decides it (archive/tar `writer.go`
//! `writeUSTARHeader`, `writePAXHeader`, `templateV7Plus`, `writeRawFile`;
//! `common.go` `allowedFormats`; `format.go` `setFormat`):
//! - USTAR whenever every field fits: an ASCII name of up to 100 bytes, or
//!   one up to 256 that splits at a `/` into a prefix of up to 155 and a
//!   name of up to 100; an ASCII link name of up to 100; uid and gid below
//!   8^7; size below 8^11; mtime from 0 to 8^11 - 1; no xattr.
//! - Otherwise PAX: an `x` header named `<dir>/PaxHeaders.0/<base>` holding
//!   the records, sorted by key, then the main header with the name cut to
//!   100 bytes of its ASCII, no prefix, and 0 in any number that did not fit.
//!
//! Notice: this file was written from the Go `archive/tar` writer functions
//! named above, to give the same bytes, so it is a changed version of that
//! code and not the original. The Go standard library is Copyright 2009 The
//! Go Authors, licensed under a BSD 3-clause licence. Licence texts and
//! upstream notices are in NOTICE, section "Code ported into Kiri".

use alloc::string::String;
use alloc::vec::Vec;

pub const BLOCK: usize = 512;

/// What Go's `Writer.Close` writes after the last entry.
pub const END: [u8; 2 * BLOCK] = [0; 2 * BLOCK];

/// The tar typeflag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    HardLink,
    Symlink,
    Char,
    Block,
    Dir,
    Fifo,
}

impl Kind {
    fn flag(self) -> u8 {
        match self {
            Kind::File => b'0',
            Kind::HardLink => b'1',
            Kind::Symlink => b'2',
            Kind::Char => b'3',
            Kind::Block => b'4',
            Kind::Dir => b'5',
            Kind::Fifo => b'6',
        }
    }
}

/// One entry's header fields, as containerd fills them in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry<'a> {
    /// Relative, `/`-separated; a directory's ends in `/`.
    pub name: &'a [u8],
    pub kind: Kind,
    pub link: &'a [u8],
    /// Permission bits plus setuid, setgid and sticky.
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    /// 0 for anything but a regular file's body.
    pub size: u64,
    /// Whole seconds.
    pub mtime: i64,
    pub devmajor: u32,
    pub devminor: u32,
    /// Extra PAX records (`SCHILY.xattr.security.capability`); any forces PAX.
    pub records: &'a [(&'a str, &'a [u8])],
}

impl Entry<'_> {
    /// A whiteout as containerd writes one: mode 0, owner 0, time 0.
    pub fn whiteout(name: &[u8]) -> Entry<'_> {
        Entry { name, kind: Kind::File, link: b"", mode: 0, uid: 0, gid: 0, size: 0, mtime: 0, devmajor: 0, devminor: 0, records: &[] }
    }
}

/// Bytes of zeros after a body of `size` bytes, up to the next block.
pub fn padding(size: u64) -> usize {
    ((BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64) as usize
}

fn fits_octal(width: usize, x: i128) -> bool {
    x >= 0 && x < (1i128 << ((width - 1) * 3))
}

/// Go's `formatString`: the bytes, NUL-terminated if shorter than the field.
/// A name too long for its field whose cut ends in `/` loses that slash, so
/// no reader takes a file for a directory.
fn put_str(field: &mut [u8], s: &[u8]) {
    let n = s.len().min(field.len());
    field[..n].copy_from_slice(&s[..n]);
    if s.len() < field.len() {
        field[s.len()] = 0;
    }
    if s.len() > field.len() && field[field.len() - 1] == b'/' {
        let kept = field.len() - 1 - s[..field.len() - 1].iter().rev().take_while(|&&b| b == b'/').count();
        field[kept] = 0;
    }
}

/// Go's `formatOctal`: zero-padded to the field less one byte, then as a
/// string; 0 when it does not fit.
fn put_octal(field: &mut [u8], x: i128) {
    let x = if fits_octal(field.len(), x) { x } else { 0 };
    let mut digits = Vec::with_capacity(24);
    let mut v = x;
    loop {
        digits.push(b'0' + (v % 8) as u8);
        v /= 8;
        if v == 0 {
            break;
        }
    }
    while digits.len() < field.len() - 1 {
        digits.push(b'0');
    }
    digits.reverse();
    put_str(field, &digits);
}

fn ascii(s: &[u8]) -> bool {
    s.iter().all(|b| *b < 0x80)
}

/// Go's `splitUSTARPath`.
fn split_ustar(name: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut len = name.len();
    if len <= 100 || !ascii(name) {
        return None;
    } else if len > 156 {
        len = 156;
    } else if name[len - 1] == b'/' {
        len -= 1;
    }
    let i = name[..len].iter().rposition(|b| *b == b'/')?;
    let (nlen, plen) = (name.len() - i - 1, i);
    if i == 0 || nlen > 100 || nlen == 0 || plen > 155 {
        return None;
    }
    Some((&name[..i], &name[i + 1..]))
}

/// Magic, version and checksum, as Go's `setFormat` for USTAR and PAX.
fn seal(b: &mut [u8; BLOCK]) {
    b[257..263].copy_from_slice(b"ustar\0");
    b[263..265].copy_from_slice(b"00");
    b[148..156].fill(b' ');
    let sum: u32 = b.iter().map(|&x| u32::from(x)).sum();
    put_octal(&mut b[148..155], i128::from(sum));
    b[155] = b' ';
}

/// Go's `templateV7Plus`.
fn template(e: &Entry<'_>, name: &[u8], to_ascii: bool) -> [u8; BLOCK] {
    let mut b = [0u8; BLOCK];
    let clean = |s: &[u8]| -> Vec<u8> { if to_ascii { s.iter().copied().filter(|c| *c < 0x80).collect() } else { s.to_vec() } };
    put_str(&mut b[0..100], &clean(name));
    put_octal(&mut b[100..108], i128::from(e.mode));
    put_octal(&mut b[108..116], i128::from(e.uid));
    put_octal(&mut b[116..124], i128::from(e.gid));
    put_octal(&mut b[124..136], i128::from(e.size));
    put_octal(&mut b[136..148], i128::from(e.mtime));
    b[156] = e.kind.flag();
    put_str(&mut b[157..257], &clean(e.link));
    // uname and gname stay empty: names are never looked up.
    b[265] = 0;
    b[297] = 0;
    put_octal(&mut b[329..337], i128::from(e.devmajor));
    put_octal(&mut b[337..345], i128::from(e.devminor));
    b
}

/// Go's `formatPAXRecord`: `<len> <key>=<value>\n`, the length counting itself.
fn pax_record(out: &mut Vec<u8>, key: &str, value: &[u8]) {
    let base = key.len() + value.len() + 3;
    let mut size = base + decimal_len(base);
    if decimal_len(size) + base != size {
        size = base + decimal_len(size);
    }
    out.extend_from_slice(itoa(size as i128).as_bytes());
    out.push(b' ');
    out.extend_from_slice(key.as_bytes());
    out.push(b'=');
    out.extend_from_slice(value);
    out.push(b'\n');
}

fn decimal_len(n: usize) -> usize {
    itoa(n as i128).len()
}

fn itoa(n: i128) -> String {
    use core::fmt::Write;
    let mut s = String::new();
    let _ = write!(s, "{n}");
    s
}

/// Go's `path.Join(path.Split(name)...)` with `PaxHeaders.0` between, as
/// `writePAXHeader` names the extended header, then `writeRawFile`'s cut.
fn pax_name(name: &[u8]) -> Vec<u8> {
    let (dir, base) = match name.iter().rposition(|b| *b == b'/') {
        Some(i) => (&name[..=i], &name[i + 1..]),
        None => (&name[..0], name),
    };
    let mut parts: Vec<&[u8]> = Vec::new();
    for p in dir.split(|b| *b == b'/').chain([&b"PaxHeaders.0"[..], base]) {
        match p {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    let mut joined = parts.join(&b'/');
    joined.retain(|b| *b < 0x80);
    joined.truncate(100);
    while joined.last() == Some(&b'/') {
        joined.pop();
    }
    joined
}

/// Appends the header block(s) of `e` to `out`: the PAX header and its
/// records first when Go would need them. The body (for a regular file,
/// `e.size` bytes) and its [`padding`] are the caller's to write.
pub fn header(out: &mut Vec<u8>, e: &Entry<'_>) {
    let mut pax: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut ustar = e.records.is_empty();
    let name_long = e.name.len() > 100;
    if !ascii(e.name) || name_long {
        if split_ustar(e.name).is_none() {
            ustar = false;
        }
        pax.push(("path", e.name.to_vec()));
    }
    if !ascii(e.link) || e.link.len() > 100 {
        ustar = false;
        pax.push(("linkpath", e.link.to_vec()));
    }
    for (key, v, width) in [("uid", i128::from(e.uid), 8), ("gid", i128::from(e.gid), 8), ("size", i128::from(e.size), 12)] {
        if !fits_octal(width, v) {
            ustar = false;
            pax.push((key, itoa(v).into_bytes()));
        }
    }
    if !fits_octal(12, i128::from(e.mtime)) {
        ustar = false;
        pax.push(("mtime", itoa(i128::from(e.mtime)).into_bytes()));
    }
    if ustar {
        let (prefix, name) = split_ustar(e.name).unwrap_or((b"", e.name));
        let mut b = template(e, name, false);
        put_str(&mut b[345..500], prefix);
        seal(&mut b);
        out.extend_from_slice(&b);
        return;
    }
    for (k, v) in e.records {
        if !pax.iter().any(|(have, _)| have == k) {
            pax.push((k, v.to_vec()));
        }
    }
    pax.sort_by(|a, b| a.0.cmp(b.0));
    let mut data = Vec::new();
    for (k, v) in &pax {
        pax_record(&mut data, k, v);
    }
    let mut x = [0u8; BLOCK];
    put_str(&mut x[0..100], &pax_name(e.name));
    put_octal(&mut x[100..108], 0);
    put_octal(&mut x[108..116], 0);
    put_octal(&mut x[116..124], 0);
    put_octal(&mut x[124..136], data.len() as i128);
    put_octal(&mut x[136..148], 0);
    x[156] = b'x';
    seal(&mut x);
    out.extend_from_slice(&x);
    let pad = padding(data.len() as u64);
    out.extend_from_slice(&data);
    out.resize(out.len() + pad, 0);
    let mut b = template(e, e.name, true);
    seal(&mut b);
    out.extend_from_slice(&b);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file<'a>(name: &'a [u8], size: u64) -> Entry<'a> {
        Entry { name, kind: Kind::File, link: b"", mode: 0o644, uid: 0, gid: 0, size, mtime: 1_700_000_000, devmajor: 0, devminor: 0, records: &[] }
    }

    fn one(e: &Entry<'_>) -> Vec<u8> {
        let mut v = Vec::new();
        header(&mut v, e);
        v
    }

    /// Field by field what Go 1.26 writes for `hello.txt`, 0644, 0:0, 6
    /// bytes, mtime 1700000000, read off Go's formatter code; the golden
    /// layers from a real BuildKit run check the whole stream.
    #[test]
    fn a_plain_file_is_one_ustar_block_as_go_writes_it() {
        let b = one(&file(b"hello.txt", 6));
        assert_eq!(b.len(), BLOCK);
        assert_eq!(&b[0..10], b"hello.txt\0");
        assert_eq!(&b[100..108], b"0000644\0");
        assert_eq!(&b[108..116], b"0000000\0");
        assert_eq!(&b[124..136], b"00000000006\0");
        assert_eq!(&b[136..148], b"14524770400\0");
        assert_eq!(b[156], b'0');
        assert_eq!(&b[257..265], b"ustar\x0000");
        assert_eq!(&b[329..345], b"0000000\x000000000\x00");
        // Six digits, NUL, space.
        assert_eq!(b[154], 0);
        assert_eq!(b[155], b' ');
        let mut copy = b.clone();
        copy[148..156].fill(b' ');
        let sum: u32 = copy.iter().map(|&x| u32::from(x)).sum();
        assert_eq!(core::str::from_utf8(&b[148..154]).unwrap(), alloc::format!("{sum:06o}"));
    }

    #[test]
    fn a_whiteout_has_mode_owner_and_time_zero() {
        let b = one(&Entry::whiteout(b"etc/.wh.gone"));
        assert_eq!(&b[100..108], b"0000000\0");
        assert_eq!(&b[136..148], b"00000000000\0");
        assert_eq!(b[156], b'0');
    }

    #[test]
    fn a_long_name_splits_into_the_prefix_when_it_can() {
        let name = alloc::format!("{}/{}", "d".repeat(120), "f".repeat(50));
        let b = one(&file(name.as_bytes(), 0));
        assert_eq!(b.len(), BLOCK, "no PAX header");
        assert_eq!(&b[0..51], alloc::format!("{}\0", "f".repeat(50)).as_bytes());
        assert_eq!(&b[345..466], alloc::format!("{}\0", "d".repeat(120)).as_bytes());
    }

    #[test]
    fn an_unsplittable_or_non_ascii_name_goes_in_a_pax_record() {
        let name = "x".repeat(130);
        let b = one(&file(name.as_bytes(), 0));
        assert_eq!(b.len(), 3 * BLOCK);
        assert_eq!(&b[0..13], b"PaxHeaders.0/");
        assert_eq!(b[156], b'x');
        let rec = alloc::format!("140 path={name}\n");
        assert_eq!(&b[BLOCK..BLOCK + rec.len()], rec.as_bytes());
        assert_eq!(&b[2 * BLOCK..2 * BLOCK + 100], &name.as_bytes()[..100]);
        assert_eq!(&b[2 * BLOCK + 345..2 * BLOCK + 346], b"\0", "no prefix in PAX mode");

        let b = one(&file("café".as_bytes(), 0));
        assert_eq!(b.len(), 3 * BLOCK);
        assert_eq!(&b[0..18], b"PaxHeaders.0/caf\0\0");
        assert_eq!(&b[2 * BLOCK..2 * BLOCK + 4], b"caf\0", "the main name keeps only its ASCII");
    }

    #[test]
    fn a_capability_forces_pax_with_records_sorted() {
        let cap: &[u8] = &[1, 0, 0, 2, 0, 0x20, 0, 0];
        let records = [("SCHILY.xattr.security.capability", cap)];
        let mut e = file(b"usr/bin/ping", 0);
        e.records = &records;
        let b = one(&e);
        assert_eq!(&b[0..25], b"usr/bin/PaxHeaders.0/ping");
        let len = 32 + 8 + 3;
        let rec = [alloc::format!("{} SCHILY.xattr.security.capability=", len + 2).as_bytes(), cap, b"\n"].concat();
        assert_eq!(&b[BLOCK..BLOCK + rec.len()], &rec[..]);
        assert_eq!(&b[2 * BLOCK..2 * BLOCK + 13], b"usr/bin/ping\0");
    }

    #[test]
    fn big_ids_and_negative_times_go_in_records_and_zero_in_the_header() {
        let mut e = file(b"f", 0);
        e.uid = 3_000_000;
        e.mtime = -5;
        let b = one(&e);
        let text = core::str::from_utf8(&b[BLOCK..2 * BLOCK]).unwrap();
        assert!(text.starts_with("12 mtime=-5\n15 uid=3000000\n"), "{text:?}");
        assert_eq!(&b[2 * BLOCK + 108..2 * BLOCK + 116], b"0000000\0");
        assert_eq!(&b[2 * BLOCK + 136..2 * BLOCK + 148], b"00000000000\0");
    }

    #[test]
    fn pax_record_lengths_count_their_own_digits() {
        let mut v = Vec::new();
        // 3 + 1 + 4 + 3 = 11 bytes before the length, 13 with it: "13 ".
        pax_record(&mut v, "path", b"abcd");
        assert_eq!(v, b"13 path=abcd\n");
        v.clear();
        // 4 + 89 + 3 = 96 without the length, 98 with two digits: still two.
        pax_record(&mut v, "path", &[b'a'; 89]);
        assert_eq!(&v[..3], b"98 ");
        v.clear();
        // 4 + 91 + 3 = 98, plus two digits is 100, which needs three.
        pax_record(&mut v, "path", &[b'a'; 91]);
        assert_eq!(&v[..4], b"101 ");
        assert_eq!(v.len(), 101);
    }

    #[test]
    fn directory_pax_header_names_drop_the_slash() {
        assert_eq!(pax_name(b"a/b/"), b"a/b/PaxHeaders.0");
        assert_eq!(pax_name(b"top"), b"PaxHeaders.0/top");
    }

    #[test]
    fn padding_reaches_the_next_block() {
        assert_eq!(padding(0), 0);
        assert_eq!(padding(1), 511);
        assert_eq!(padding(512), 0);
    }
}
