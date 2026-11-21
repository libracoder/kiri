//! The layer tar encoder against Go's own archive/tar: the same entries as
//! `data/go_layer.go` writes must give exactly the bytes of `data/go_layer.tar`
//! (made with Go 1.27.3; archive/tar's header rules are unchanged since 1.26,
//! the version BuildKit v0.33.1 is built with).

use kiri_proto::layertar::{self, Entry, Kind};

fn e<'a>(name: &'a [u8], kind: Kind, link: &'a [u8], mode: u32, size: u64) -> Entry<'a> {
    Entry { name, kind, link, mode, uid: 0, gid: 0, size, mtime: 1_700_000_000, devmajor: 0, devminor: 0, records: &[] }
}

#[test]
fn every_kind_of_entry_matches_go_byte_for_byte() {
    let mut out = Vec::new();
    let mut put = |entry: &Entry<'_>, body: &[u8]| {
        layertar::header(&mut out, entry);
        out.extend_from_slice(body);
        out.resize(out.len() + layertar::padding(body.len() as u64), 0);
    };
    put(&e(b"a/", Kind::Dir, b"", 0o755, 0), b"");
    put(&Entry { uid: 1000, gid: 1000, ..e(b"a/hello.txt", Kind::File, b"", 0o644, 6) }, b"hello\n");
    put(&e(b"a/link", Kind::Symlink, b"hello.txt", 0o777, 0), b"");
    put(&e(b"a/hard", Kind::HardLink, b"a/hello.txt", 0o644, 0), b"");
    let split = format!("{}/{}", "d".repeat(120), "f".repeat(50));
    put(&e(split.as_bytes(), Kind::File, b"", 0o644, 0), b"");
    let long = "x".repeat(130);
    put(&e(long.as_bytes(), Kind::File, b"", 0o644, 0), b"");
    let long_dir = format!("{}/", "y".repeat(110));
    put(&e(long_dir.as_bytes(), Kind::Dir, b"", 0o755, 0), b"");
    put(&e("café".as_bytes(), Kind::File, b"", 0o644, 0), b"");
    let cap: &[u8] = b"\x01\x00\x00\x02\x00\x20\x00\x00";
    let records = [("SCHILY.xattr.security.capability", cap)];
    put(&Entry { records: &records, ..e(b"usr/bin/ping", Kind::File, b"", 0o4755, 3) }, b"bin");
    put(&Entry { uid: 3_000_000, gid: 5, ..e(b"big-uid", Kind::File, b"", 0o600, 0) }, b"");
    put(&Entry { mtime: -5, ..e(b"old", Kind::File, b"", 0o644, 0) }, b"");
    put(&Entry { devmajor: 1, devminor: 3, ..e(b"dev/null", Kind::Char, b"", 0o666, 0) }, b"");
    put(&e(b"pipe", Kind::Fifo, b"", 0o644, 0), b"");
    let link = "l".repeat(150);
    put(&e(b"longlink", Kind::Symlink, link.as_bytes(), 0o777, 0), b"");
    put(&e(b"sticky/", Kind::Dir, b"", 0o1777, 0), b"");
    put(&Entry::whiteout(b"etc/.wh.gone"), b"");
    out.extend_from_slice(&layertar::END);

    let go = include_bytes!("data/go_layer.tar");
    assert_eq!(out.len(), go.len(), "length");
    for (i, (a, b)) in out.chunks(512).zip(go.chunks(512)).enumerate() {
        assert_eq!(a, b, "block {i} differs:\n ours {:?}\n go   {:?}", String::from_utf8_lossy(a), String::from_utf8_lossy(b));
    }
}
