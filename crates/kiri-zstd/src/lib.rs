//! A zstd stream read whole, as `zstd -d` and containerd read an image
//! layer: every frame one after the other, skippable frames passed over.
//!
//! A zstd stream may be several frames back to back. zstd:chunked layers
//! (written by Podman, Buildah and skopeo) put each file in frames of its
//! own and keep their table of contents in skippable frames at the end;
//! `zstd -T0`, `pzstd` and seekable compressors write many frames too.
//! ruzstd's own reader stops at the end of the first frame.
//!
//! What is refused, as containerd refuses it: bytes after the last frame
//! that are not a frame, a frame cut short, a frame whose content checksum
//! does not match, and an empty input (no frame at all). Every such error
//! carries a [`Damaged`] inside its `io::Error`; errors of the source itself
//! pass through as they are. Memory stays bounded: one frame's window
//! (ruzstd refuses windows over 128 MiB) and one block at a time, whatever
//! the stream's length; a skippable frame is read past, never held.

use std::io::{self, BufRead, Read};

use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};

/// The magic number a zstd data frame begins with.
const FRAME_MAGIC: u32 = 0xFD2F_B528;
/// Skippable frames: 0x184D2A50 to 0x184D2A5F.
const SKIPPABLE_MAGIC: u32 = 0x184D_2A50;

/// Whether `head`, the first bytes of a stream, begins a zstd stream: a data
/// frame or a skippable frame (zstd:chunked and seekable streams may begin
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

/// What a read fails with when the stream itself is at fault (damaged, cut
/// short, not zstd), as opposed to the source it comes from.
#[derive(Debug)]
pub struct Damaged(String);

impl std::fmt::Display for Damaged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "zstd: {}", self.0)
    }
}

impl std::error::Error for Damaged {}

fn damaged(kind: io::ErrorKind, what: impl std::fmt::Display) -> io::Error {
    io::Error::new(kind, Damaged(what.to_string()))
}

/// The decompressed content of a zstd stream, frame after frame.
pub struct Frames<R: BufRead> {
    src: R,
    dec: FrameDecoder,
    in_frame: bool,
    /// Whether any frame (data or skippable) has begun.
    seen: bool,
}

impl<R: BufRead> std::fmt::Debug for Frames<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frames").field("in_frame", &self.in_frame).finish_non_exhaustive()
    }
}

impl<R: BufRead> Frames<R> {
    pub fn new(src: R) -> Frames<R> {
        Frames { src, dec: FrameDecoder::new(), in_frame: false, seen: false }
    }
}

impl<R: BufRead> Read for Frames<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bad = |e: FrameDecoderError| damaged(io::ErrorKind::InvalidData, e);
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.in_frame {
                // One block at a time: memory is the window plus a block.
                while self.dec.can_collect() == 0 && !self.dec.is_finished() {
                    self.dec.decode_blocks(&mut self.src, BlockDecodingStrategy::UptoBlocks(1)).map_err(bad)?;
                }
                let n = self.dec.read(buf)?;
                if n > 0 {
                    return Ok(n);
                }
                // The frame is decoded and handed out whole.
                self.in_frame = false;
                if let (Some(want), Some(got)) = (self.dec.get_checksum_from_data(), self.dec.get_calculated_checksum())
                    && want != got
                {
                    return Err(damaged(io::ErrorKind::InvalidData, "a frame's content checksum does not match"));
                }
                continue;
            }
            if self.src.fill_buf()?.is_empty() {
                if !self.seen {
                    return Err(damaged(io::ErrorKind::UnexpectedEof, "empty input"));
                }
                return Ok(0);
            }
            self.seen = true;
            match self.dec.init(&mut self.src) {
                Ok(()) => self.in_frame = true,
                Err(FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::SkipFrame { length, .. })) => {
                    // Passed over through the buffer, never held whole.
                    let skipped = io::copy(&mut (&mut self.src).take(u64::from(length)), &mut io::sink())?;
                    if skipped < u64::from(length) {
                        return Err(damaged(io::ErrorKind::UnexpectedEof, "a skippable frame is cut short"));
                    }
                }
                Err(e) => return Err(bad(e)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unzstd(bytes: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        // A small buffer, so frames and headers straddle refills.
        Frames::new(io::BufReader::with_capacity(7, bytes)).read_to_end(&mut out)?;
        Ok(out)
    }

    fn zstd(b: &[u8]) -> Vec<u8> {
        ruzstd::encoding::compress_to_vec(b, ruzstd::encoding::CompressionLevel::Fastest)
    }

    fn skippable(nibble: u32, payload: &[u8]) -> Vec<u8> {
        [&(SKIPPABLE_MAGIC + nibble).to_le_bytes()[..], &(payload.len() as u32).to_le_bytes(), payload].concat()
    }

    /// A frame of raw blocks, written by hand: no content size, no
    /// checksum, window 1 KiB (exponent 0). `blocks` may be empty pieces.
    fn raw_frame(blocks: &[&[u8]]) -> Vec<u8> {
        let mut f = FRAME_MAGIC.to_le_bytes().to_vec();
        f.push(0x00); // descriptor: no content size, no single segment, no checksum, no dictionary
        f.push(0x00); // window descriptor: 1 KiB
        let blocks: Vec<&[u8]> = if blocks.is_empty() { vec![&[]] } else { blocks.to_vec() };
        for (i, b) in blocks.iter().enumerate() {
            let last = u32::from(i + 1 == blocks.len());
            let header = last | (b.len() as u32) << 3; // block type 0: raw
            f.extend_from_slice(&header.to_le_bytes()[..3]);
            f.extend_from_slice(b);
        }
        f
    }

    /// Made once with the zstd 1.5.5 command line:
    /// `printf 'first frame of the fixture\n' | zstd -c --check -3`, then a
    /// skippable frame (magic 0x184D2A5A, payload "toc!!"), then
    /// `printf 'second frame, after a skippable one\n' | zstd -c --check -3`.
    /// Both data frames carry an XXH64 content checksum.
    const CLI_FIXTURE: [u8; 102] = [
        0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x58, 0xd9, 0x00, 0x00, 0x66, 0x69, 0x72, 0x73, 0x74, 0x20, 0x66, 0x72, 0x61, 0x6d, 0x65, 0x20, 0x6f, 0x66,
        0x20, 0x74, 0x68, 0x65, 0x20, 0x66, 0x69, 0x78, 0x74, 0x75, 0x72, 0x65, 0x0a, 0xd9, 0xf2, 0xd8, 0x24, 0x5a, 0x2a, 0x4d, 0x18, 0x05, 0x00,
        0x00, 0x00, 0x74, 0x6f, 0x63, 0x21, 0x21, 0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x58, 0x21, 0x01, 0x00, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20,
        0x66, 0x72, 0x61, 0x6d, 0x65, 0x2c, 0x20, 0x61, 0x66, 0x74, 0x65, 0x72, 0x20, 0x61, 0x20, 0x73, 0x6b, 0x69, 0x70, 0x70, 0x61, 0x62, 0x6c,
        0x65, 0x20, 0x6f, 0x6e, 0x65, 0x0a, 0x57, 0xb5, 0x03, 0xea,
    ];
    const CLI_CONTENT: &[u8] = b"first frame of the fixture\nsecond frame, after a skippable one\n";

    fn data() -> Vec<u8> {
        (0..50_000u32).map(|i| (i % 97) as u8 ^ (i / 1000) as u8).collect()
    }

    #[test]
    fn one_frame() {
        let d = data();
        assert_eq!(unzstd(&zstd(&d)).unwrap(), d);
    }

    #[test]
    fn frames_back_to_back_are_all_read() {
        let d = data();
        let s: Vec<u8> = d.chunks(17_000).flat_map(zstd).collect();
        assert_eq!(unzstd(&s).unwrap(), d);
        assert_eq!(unzstd(&[raw_frame(&[b"ab", b"cd"]), raw_frame(&[b"ef"])].concat()).unwrap(), b"abcdef");
    }

    #[test]
    fn skippable_frames_are_passed_over_wherever_they_are() {
        let d = data();
        let mut s = skippable(0, b"at the start");
        for (i, part) in d.chunks(7_000).enumerate() {
            s.extend(zstd(part));
            s.extend(skippable(i as u32 % 16, &vec![b'x'; i * 300]));
        }
        assert_eq!(unzstd(&s).unwrap(), d);
        assert_eq!(unzstd(&skippable(15, b"")).unwrap(), b"", "a stream of one empty skippable frame");
    }

    /// zstd:chunked's layout: each file of the tar in frames of its own, the
    /// tar's end in its last data frame, then the table of contents and the
    /// footer in skippable frames.
    #[test]
    fn a_chunked_layout_is_read_whole() {
        let mut b = Vec::new();
        let mut parts = Vec::new();
        for i in 0..20 {
            let mut h = [0u8; 512];
            h[..7].copy_from_slice(format!("file{i:03}").as_bytes());
            let body = vec![i as u8; 1000 + i * 37];
            let piece = [&h[..], &body].concat();
            b.extend_from_slice(&piece);
            parts.push(piece);
        }
        parts.push(vec![0u8; 1024]);
        b.extend_from_slice(&[0u8; 1024]);
        let mut s: Vec<u8> = parts.iter().flat_map(|p| zstd(p)).collect();
        s.extend(skippable(0, &vec![b'{'; 5000]));
        s.extend(skippable(0, &[7u8; 64]));
        assert_eq!(unzstd(&s).unwrap(), b);
    }

    #[test]
    fn a_stream_from_the_zstd_command_line() {
        assert_eq!(unzstd(&CLI_FIXTURE).unwrap(), CLI_CONTENT);
    }

    #[test]
    fn empty_frames_anywhere() {
        let s = [zstd(b""), raw_frame(&[]), zstd(b"one"), raw_frame(&[b"", b"two", b""]), zstd(b""), raw_frame(&[])].concat();
        assert_eq!(unzstd(&s).unwrap(), b"onetwo");
        assert_eq!(unzstd(&zstd(b"")).unwrap(), b"");
    }

    #[test]
    fn what_is_not_a_frame_after_the_frames_is_an_error() {
        for tail in [&b"garbage"[..], &[0u8; 16], &[0x28, 0xb5, 0x2f]] {
            let e = unzstd(&[&CLI_FIXTURE[..], tail].concat()).unwrap_err();
            assert!(e.get_ref().is_some_and(|i| i.is::<Damaged>()), "{tail:?}: {e}");
        }
        assert!(unzstd(b"not zstd at all").is_err());
        assert!(unzstd(&[]).is_err(), "no frame at all");
    }

    #[test]
    fn a_wrong_content_checksum_is_an_error() {
        let mut bad = CLI_FIXTURE;
        bad[101] ^= 0x01;
        assert!(unzstd(&bad).is_err());
    }

    /// Cut at every byte: an error, or exactly the frames that are whole
    /// (a cut at a frame's end is a shorter valid stream, which only the
    /// blob's digest can tell). Never a panic, never part of a frame.
    #[test]
    fn a_stream_cut_anywhere_is_an_error_or_its_whole_frames() {
        let d = data();
        let pieces: Vec<(Vec<u8>, &[u8])> = vec![
            (zstd(&d[..20_000]), &d[..20_000]),
            (skippable(3, b"between"), b""),
            (CLI_FIXTURE[..40].to_vec(), b"first frame of the fixture\n"),
            (raw_frame(&[b"raw", b""]), b"raw"),
            (zstd(&d[20_000..]), &d[20_000..]),
        ];
        let whole: Vec<u8> = pieces.iter().flat_map(|(b, _)| b.clone()).collect();
        let mut ends = vec![(0usize, Vec::new())];
        let (mut at, mut content) = (0usize, Vec::new());
        for (b, c) in &pieces {
            at += b.len();
            content.extend_from_slice(c);
            ends.push((at, content.clone()));
        }
        assert_eq!(unzstd(&whole).unwrap(), ends.last().unwrap().1);
        for cut in 0..whole.len() {
            match (unzstd(&whole[..cut]), ends.iter().find(|(e, _)| *e == cut)) {
                (Err(_), None) => {}
                (Ok(got), Some((_, want))) if cut > 0 => assert!(&got == want, "cut at {cut}"),
                (Err(_), Some((0, _))) => {}
                (r, end) => panic!("cut at {cut}: {:?} (frame end: {})", r.map(|v| v.len()), end.is_some()),
            }
        }
    }

    /// A skippable frame that says it is 4 GiB long, in a stream of a few
    /// bytes: an error at once, nothing allocated for it.
    #[test]
    fn a_huge_skippable_length_is_read_past_not_held() {
        let s = [zstd(b"before"), (SKIPPABLE_MAGIC + 9).to_le_bytes().to_vec(), u32::MAX.to_le_bytes().to_vec(), b"short".to_vec()].concat();
        let started = std::time::Instant::now();
        let e = unzstd(&s).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    /// Read a byte at a time: the same content.
    #[test]
    fn tiny_reads() {
        let mut r = Frames::new(io::BufReader::with_capacity(1, &CLI_FIXTURE[..]));
        let (mut out, mut b) = (Vec::new(), [0u8; 1]);
        while r.read(&mut b).unwrap() == 1 {
            out.push(b[0]);
        }
        assert_eq!(out, CLI_CONTENT);
    }

    #[test]
    fn magic_numbers() {
        assert!(is_zstd(&[0x28, 0xb5, 0x2f, 0xfd]));
        assert!(is_zstd(&skippable(0, b"")));
        assert!(is_zstd(&skippable(15, b"x")));
        assert!(!is_zstd(&[0x60, 0x2a, 0x4d, 0x18]));
        assert!(!is_zstd(&[0x1f, 0x8b, 8, 0]));
        assert!(!is_zstd(&[0x28, 0xb5, 0x2f]));
    }
}
