//! Shared image-layer stream decoders used identically by host `diff_id`
//! verification and guest `layers::unpack`.
//!
//! - [`Frames`]: decodes every zstd frame in sequence one block at a time
//!   (`decode_blocks`), verifies XXH64 frame content checksums when present,
//!   skips skippable frames (`0x184D2A50..=0x184D2A5F`) without allocating,
//!   and rejects empty input, truncated frames, and trailing non-frame bytes
//!   with [`io::ErrorKind::InvalidData`].
//! - [`CheckedGz`]: decodes multi-member gzip streams member by member and
//!   rejects empty input, truncated members, bad CRC32/ISIZE trailers, and any
//!   trailing non-gzip bytes after the last member with
//!   [`io::ErrorKind::InvalidData`] so gzip+tar polyglots cannot hash only a
//!   gzip prefix while unpacking trailing data or vice-versa.
//! - [`tar_reader`]: dispatches by [`LayerFormat`] (sniffed from the blob's
//!   own magic bytes, never trusted from manifest media types).

use std::io::{self, BufRead, Read};

pub use kiri_proto::LayerFormat;
use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};

/// The magic number a zstd data frame begins with.
const FRAME_MAGIC: u32 = 0xFD2F_B528;
/// Skippable frames: `0x184D2A50` through `0x184D2A5F`.
const SKIPPABLE_MAGIC: u32 = 0x184D_2A50;

/// Whether `head`, the first bytes of a stream, begins a zstd stream: a data
/// frame or a skippable frame (`zstd:chunked` and seekable streams may begin
/// with one).
pub fn is_zstd(head: &[u8]) -> bool {
    match head {
        [a, b, c, d, ..] => {
            let magic = u32::from_le_bytes([*a, *b, *c, *d]);
            magic == FRAME_MAGIC || magic & 0xFFFF_FFF0 == SKIPPABLE_MAGIC
        }
        _ => false,
    }
}

/// Error payload carried inside `io::Error` when the compressed stream itself
/// is malformed, truncated, or has trailing non-frame bytes (as opposed to an
/// underlying I/O failure on the source reader).
#[derive(Debug)]
pub struct Damaged(String);

impl std::fmt::Display for Damaged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Damaged {}

fn damaged(kind: io::ErrorKind, what: impl std::fmt::Display) -> io::Error {
    io::Error::new(kind, Damaged(what.to_string()))
}

/// Decodes every frame of a zstd stream one block at a time.
pub struct Frames<R: BufRead> {
    src: R,
    dec: FrameDecoder,
    in_frame: bool,
    /// Whether at least one zstd frame (data or skippable) has been seen.
    seen: bool,
}

impl<R: BufRead> std::fmt::Debug for Frames<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frames")
            .field("in_frame", &self.in_frame)
            .finish_non_exhaustive()
    }
}

impl<R: BufRead> Frames<R> {
    pub fn new(src: R) -> Frames<R> {
        Frames {
            src,
            dec: FrameDecoder::new(),
            in_frame: false,
            seen: false,
        }
    }
}

impl<R: BufRead> Read for Frames<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bad = |e: FrameDecoderError| damaged(io::ErrorKind::InvalidData, format!("zstd: {e}"));
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.in_frame {
                // One block at a time: memory is bounded to one window (<= 128 MiB) plus one block.
                while self.dec.can_collect() == 0 && !self.dec.is_finished() {
                    self.dec
                        .decode_blocks(&mut self.src, BlockDecodingStrategy::UptoBlocks(1))
                        .map_err(bad)?;
                }
                let n = self.dec.read(buf)?;
                if n > 0 {
                    return Ok(n);
                }
                self.in_frame = false;
                if let (Some(want), Some(got)) = (
                    self.dec.get_checksum_from_data(),
                    self.dec.get_calculated_checksum(),
                ) && want != got
                {
                    return Err(damaged(
                        io::ErrorKind::InvalidData,
                        "zstd: frame content checksum mismatch",
                    ));
                }
                continue;
            }
            if self.src.fill_buf()?.is_empty() {
                if !self.seen {
                    return Err(damaged(io::ErrorKind::InvalidData, "zstd: empty input"));
                }
                return Ok(0);
            }
            self.seen = true;
            match self.dec.init(&mut self.src) {
                Ok(()) => self.in_frame = true,
                Err(FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::SkipFrame {
                    length,
                    ..
                })) => {
                    // Drain skippable payload without allocating.
                    let skipped = io::copy(
                        &mut (&mut self.src).take(u64::from(length)),
                        &mut io::sink(),
                    )?;
                    if skipped < u64::from(length) {
                        return Err(damaged(
                            io::ErrorKind::InvalidData,
                            "zstd: skippable frame truncated",
                        ));
                    }
                }
                Err(e) => return Err(bad(e)),
            }
        }
    }
}

/// Multi-member gzip decoder that rejects trailing non-gzip bytes after the
/// final member, wrapping `flate2::bufread::MultiGzDecoder<R>` and verifying
/// that every byte of `R` belongs to a valid gzip member.
pub struct CheckedGz<R: BufRead> {
    /// Active single-member decoder (`GzDecoder` consumes only the exact bytes
    /// of one member + 8-byte trailer from `R`, whereas `MultiGzDecoder` would
    /// swallow up to 10 bytes of non-gzip trailing data while probing the next
    /// header; we also guard via `MultiGzDecoder` semantics across members).
    dec: Option<flate2::bufread::GzDecoder<R>>,
    src: Option<R>,
    seen: bool,
}

impl<R: BufRead> std::fmt::Debug for CheckedGz<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckedGz")
            .field("seen", &self.seen)
            .finish_non_exhaustive()
    }
}

impl<R: BufRead> CheckedGz<R> {
    pub fn new(src: R) -> CheckedGz<R> {
        CheckedGz {
            dec: Some(flate2::bufread::GzDecoder::new(src)),
            src: None,
            seen: false,
        }
    }
}

impl<R: BufRead> Read for CheckedGz<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(dec) = &mut self.dec {
                match dec.read(buf) {
                    Ok(n) if n > 0 => {
                        self.seen = true;
                        return Ok(n);
                    }
                    Ok(_) => {
                        self.seen = true;
                        self.src = self.dec.take().map(flate2::bufread::GzDecoder::into_inner);
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::InvalidInput
                                | io::ErrorKind::InvalidData
                                | io::ErrorKind::UnexpectedEof
                        ) =>
                    {
                        return Err(damaged(io::ErrorKind::InvalidData, format!("gzip: {e}")));
                    }
                    Err(e) => return Err(e),
                }
            }
            let Some(mut src) = self.src.take() else {
                return Ok(0);
            };
            let rest = src.fill_buf()?;
            if rest.is_empty() {
                if !self.seen {
                    return Err(damaged(io::ErrorKind::InvalidData, "gzip: empty input"));
                }
                return Ok(0);
            }
            // If bytes remain after a member, they MUST begin another valid
            // gzip member (`0x1f 0x8b`); any trailing non-gzip bytes fail here.
            if rest.first() != Some(&0x1f) {
                return Err(damaged(
                    io::ErrorKind::InvalidData,
                    "gzip: trailing non-gzip bytes after stream",
                ));
            }
            self.dec = Some(flate2::bufread::GzDecoder::new(src));
        }
    }
}

/// Returns a reader over the uncompressed tar inside `blob` for `format`.
pub fn tar_reader<'a>(format: LayerFormat, blob: impl BufRead + 'a) -> Box<dyn Read + 'a> {
    match format {
        LayerFormat::Gzip => Box::new(CheckedGz::new(blob)),
        LayerFormat::Zstd => Box::new(Frames::new(blob)),
        LayerFormat::Tar => Box::new(blob),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn unzstd(bytes: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        // Tiny buffer so headers and frame boundaries straddle refills.
        Frames::new(io::BufReader::with_capacity(7, bytes)).read_to_end(&mut out)?;
        Ok(out)
    }

    fn ungz(bytes: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        CheckedGz::new(io::BufReader::with_capacity(7, bytes)).read_to_end(&mut out)?;
        Ok(out)
    }

    fn zstd(b: &[u8]) -> Vec<u8> {
        ruzstd::encoding::compress_to_vec(b, ruzstd::encoding::CompressionLevel::Fastest)
    }

    fn gzip(b: &[u8]) -> Vec<u8> {
        let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(b).unwrap();
        z.finish().unwrap()
    }

    fn skippable(nibble: u32, payload: &[u8]) -> Vec<u8> {
        [
            &(SKIPPABLE_MAGIC + nibble).to_le_bytes()[..],
            &(payload.len() as u32).to_le_bytes(),
            payload,
        ]
        .concat()
    }

    fn raw_frame(blocks: &[&[u8]]) -> Vec<u8> {
        let mut f = FRAME_MAGIC.to_le_bytes().to_vec();
        f.push(0x00);
        f.push(0x00);
        let blocks: Vec<&[u8]> = if blocks.is_empty() {
            vec![&[]]
        } else {
            blocks.to_vec()
        };
        for (i, b) in blocks.iter().enumerate() {
            let last = u32::from(i + 1 == blocks.len());
            let header = last | (b.len() as u32) << 3;
            f.extend_from_slice(&header.to_le_bytes()[..3]);
            f.extend_from_slice(b);
        }
        f
    }

    /// Two CLI zstd frames with XXH64 checksums separated by a skippable frame.
    const CLI_FIXTURE: [u8; 102] = [
        0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x58, 0xd9, 0x00, 0x00, 0x66, 0x69, 0x72, 0x73, 0x74, 0x20,
        0x66, 0x72, 0x61, 0x6d, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x66, 0x69,
        0x78, 0x74, 0x75, 0x72, 0x65, 0x0a, 0xd9, 0xf2, 0xd8, 0x24, 0x5a, 0x2a, 0x4d, 0x18, 0x05,
        0x00, 0x00, 0x00, 0x74, 0x6f, 0x63, 0x21, 0x21, 0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x58, 0x21,
        0x01, 0x00, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x66, 0x72, 0x61, 0x6d, 0x65, 0x2c,
        0x20, 0x61, 0x66, 0x74, 0x65, 0x72, 0x20, 0x61, 0x20, 0x73, 0x6b, 0x69, 0x70, 0x70, 0x61,
        0x62, 0x6c, 0x65, 0x20, 0x6f, 0x6e, 0x65, 0x0a, 0x57, 0xb5, 0x03, 0xea,
    ];
    const CLI_CONTENT: &[u8] = b"first frame of the fixture\nsecond frame, after a skippable one\n";

    fn data() -> Vec<u8> {
        (0..50_000u32)
            .map(|i| (i % 97) as u8 ^ (i / 1000) as u8)
            .collect()
    }

    #[test]
    fn zstd_multi_frame_skippable_and_checksum() {
        let d = data();
        assert_eq!(unzstd(&zstd(&d)).unwrap(), d);
        let multi: Vec<u8> = d.chunks(11_000).flat_map(zstd).collect();
        assert_eq!(unzstd(&multi).unwrap(), d);
        assert_eq!(
            unzstd(&[raw_frame(&[b"ab", b"cd"]), raw_frame(&[b"ef"])].concat()).unwrap(),
            b"abcdef"
        );

        let mut chunked = skippable(0, b"lead");
        for (i, part) in d.chunks(7_000).enumerate() {
            chunked.extend(zstd(part));
            chunked.extend(skippable(i as u32 % 16, &vec![b'x'; i * 250]));
        }
        assert_eq!(unzstd(&chunked).unwrap(), d);
        assert_eq!(unzstd(&skippable(15, b"")).unwrap(), b"");
        assert_eq!(unzstd(&CLI_FIXTURE).unwrap(), CLI_CONTENT);

        let empty_mix = [
            zstd(b""),
            raw_frame(&[]),
            zstd(b"one"),
            raw_frame(&[b"", b"two", b""]),
            zstd(b""),
        ]
        .concat();
        assert_eq!(unzstd(&empty_mix).unwrap(), b"onetwo");

        // Bad XXH64 checksum fails with InvalidData.
        let mut bad_sum = CLI_FIXTURE;
        bad_sum[101] ^= 0x01;
        assert_eq!(
            unzstd(&bad_sum).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        // Trailing non-frame bytes fail with InvalidData.
        for tail in [&b"x"[..], &b"garbage"[..], &[0u8; 16], &[0x28, 0xb5, 0x2f]] {
            let err = unzstd(&[&CLI_FIXTURE[..], tail].concat()).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{tail:?}: {err}");
            assert!(err.get_ref().is_some_and(|i| i.is::<Damaged>()));
        }
        assert_eq!(unzstd(&[]).unwrap_err().kind(), io::ErrorKind::InvalidData);

        // Huge skippable frame length fails fast without allocating 4 GiB.
        let huge = [
            zstd(b"ok"),
            (SKIPPABLE_MAGIC + 3).to_le_bytes().to_vec(),
            u32::MAX.to_le_bytes().to_vec(),
            b"cut".to_vec(),
        ]
        .concat();
        assert_eq!(
            unzstd(&huge).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn checked_gzip_multi_member_and_trailing_byte_rejection() {
        let (a, b, c) = (vec![1u8; 3000], vec![2u8; 19], vec![3u8; 700]);
        let whole = [&a[..], &b, &c].concat();
        assert_eq!(ungz(&gzip(&whole)).unwrap(), whole);
        assert_eq!(
            ungz(&[gzip(&a), gzip(&b), gzip(b""), gzip(&c)].concat()).unwrap(),
            whole
        );
        assert_eq!(ungz(&gzip(b"")).unwrap(), b"");

        // Even 1 trailing byte, NUL padding, a partial gzip header, or trailing tar blocks must fail with InvalidData!
        for tail in [
            &b"x"[..],
            &[0u8; 1],
            &[0u8; 512],
            &[0x1f],
            &[0x1f, 0x8b],
            &b"trailing tar data"[..],
            &gzip(&b)[..12],
        ] {
            let err = ungz(&[&gzip(&a)[..], tail].concat()).unwrap_err();
            assert_eq!(
                err.kind(),
                io::ErrorKind::InvalidData,
                "tail {tail:?}: {err}"
            );
        }
        assert_eq!(ungz(&[]).unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            ungz(&gzip(&a)[..20]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn tar_reader_dispatches_all_formats() {
        let payload = vec![0x42u8; 2048];
        for (fmt, blob) in [
            (LayerFormat::Gzip, gzip(&payload)),
            (LayerFormat::Zstd, zstd(&payload)),
            (LayerFormat::Tar, payload.clone()),
        ] {
            let mut got = Vec::new();
            tar_reader(fmt, io::BufReader::with_capacity(13, &blob[..]))
                .read_to_end(&mut got)
                .unwrap();
            assert_eq!(got, payload, "{fmt:?}");
        }
        assert!(is_zstd(&[0x28, 0xb5, 0x2f, 0xfd]));
        assert!(is_zstd(&skippable(0, b"")));
        assert!(!is_zstd(&[0x1f, 0x8b, 8, 0]));
    }
}
