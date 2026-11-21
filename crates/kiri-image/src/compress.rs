//! Layers leave the store compressed the way BuildKit's do: a layer the store keeps as a plain tar (one the
//! builder or `docker commit` made) is gzipped at level 6 on its way out,
//! by `docker save` or a push, with the port of Go's `compress/gzip` in
//! goflate.rs, so the blob is the one BuildKit writes for the same tar.
//! Compressed layers (pulled ones) go out as they are.
//!
//! The gzip copy is a temporary file, removed when the save or push is
//! done, so the store never holds a layer twice. The same
//! tar always gives the same bytes, so a pushed layer keeps its digest from
//! one push to the next.

use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest as _, Sha256};

use crate::store::{Layer, Store};

/// The media type of a layer that goes out gzipped.
pub const GZIP_LAYER: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

/// Go's level-6 gzip of the empty layer (1024 zero bytes): the 32-byte blob
/// `sha256:4f4fb700…` every BuildKit image with an empty RUN carries. goflate.rs gives the same bytes; this constant is the
/// shortcut for the most common layer there is.
const EMPTY_TAR_GZIP: [u8; 32] = [
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x62, 0x18, 0x05, 0xa3, 0x60, 0x14, 0x8c, 0x58, 0x00, 0x08, 0x00, 0x00, 0xff,
    0xff, 0x2e, 0xaf, 0xb5, 0xef, 0x00, 0x04, 0x00, 0x00,
];

/// BuildKit's default level (`gzip.DefaultCompression`).
const LEVEL: u32 = 6;

static SEQ: AtomicU64 = AtomicU64::new(0);

/// A zstd stream decompressed whole, as `zstd -d` and the decoder registries'
/// clients use read it: every frame one after the other (`zstd -T0`,
/// `pzstd` and zstd:chunked write many), skippable frames passed over
/// (zstd:chunked keeps its table of contents and footer in them). ruzstd's
/// own reader stops at the end of the first frame.
pub struct ZstdFrames<R: BufRead> {
    src: R,
    dec: ruzstd::decoding::FrameDecoder,
    in_frame: bool,
}

impl<R: BufRead> std::fmt::Debug for ZstdFrames<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZstdFrames").field("in_frame", &self.in_frame).finish_non_exhaustive()
    }
}

impl<R: BufRead> ZstdFrames<R> {
    pub fn new(src: R) -> ZstdFrames<R> {
        ZstdFrames { src, dec: ruzstd::decoding::FrameDecoder::new(), in_frame: false }
    }
}

impl<R: BufRead> Read for ZstdFrames<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};
        let bad = |e: FrameDecoderError| io::Error::new(io::ErrorKind::InvalidData, format!("zstd: {e}"));
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.in_frame {
                while self.dec.can_collect() == 0 && !self.dec.is_finished() {
                    self.dec.decode_blocks(&mut self.src, ruzstd::decoding::BlockDecodingStrategy::UptoBlocks(1)).map_err(bad)?;
                }
                let n = self.dec.read(buf)?;
                if n > 0 {
                    return Ok(n);
                }
                if self.dec.can_collect() == 0 {
                    self.in_frame = false;
                }
                continue;
            }
            if self.src.fill_buf()?.is_empty() {
                return Ok(0);
            }
            match self.dec.init(&mut self.src) {
                Ok(()) => self.in_frame = true,
                Err(FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::SkipFrame { length, .. })) => {
                    let skipped = io::copy(&mut (&mut self.src).take(u64::from(length)), &mut io::sink())?;
                    if skipped < u64::from(length) {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "zstd: a skippable frame is cut short"));
                    }
                }
                Err(e) => return Err(bad(e)),
            }
        }
    }
}

/// Whether a layer of this media type is an uncompressed tar.
pub fn is_plain_tar(media_type: &str) -> bool {
    matches!(media_type, "application/vnd.oci.image.layer.v1.tar" | "application/vnd.docker.image.rootfs.diff.tar")
}

/// A layer as it leaves the store: its descriptor and the file to send.
#[derive(Debug)]
pub struct Outgoing {
    pub layer: Layer,
    pub path: PathBuf,
    temporary: bool,
}

impl Drop for Outgoing {
    fn drop(&mut self) {
        if self.temporary {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Counts and hashes what passes through.
struct Hashing<W> {
    inner: W,
    hasher: Sha256,
    written: u64,
}

impl<W: Write> Write for Hashing<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// The layer as a save or a push sends it.
pub fn outgoing(store: &Store, layer: &Layer) -> io::Result<Outgoing> {
    // Checked as every read of a blob that leaves the engine is: a blob
    // changed on disk since it was verified is hashed again.
    let src = store.verified_blob_path(&layer.digest)?;
    // With the builder switched off, every layer leaves as it is kept, as
    // it did before the builder.
    if !is_plain_tar(&layer.media_type) || !store.native_checks() {
        return Ok(Outgoing { layer: layer.clone(), path: src, temporary: false });
    }
    // In the store's own tmp folder (same disk), named so a crash leaves
    // something the store's cleanup recognises.
    let path = store.root().join("tmp").join(format!("gzip.{}.{}.tmp", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
    let out = Outgoing { layer: layer.clone(), path, temporary: true };
    let file = File::create(&out.path)?;
    let mut sink = Hashing { inner: BufWriter::with_capacity(256 * 1024, file), hasher: Sha256::new(), written: 0 };
    let mut input = File::open(&src)?;
    if input.metadata()?.len() == 1024 && is_zero(&mut input)? {
        sink.write_all(&EMPTY_TAR_GZIP)?;
    } else {
        let mut input = BufReader::with_capacity(256 * 1024, File::open(&src)?);
        let mut gz = crate::goflate::GzipWriter::new(&mut sink, LEVEL)?;
        io::copy(&mut input, &mut gz)?;
        gz.finish()?;
    }
    sink.flush()?;
    let digest = format!("sha256:{}", hex(&sink.hasher.finalize()));
    let size = sink.written;
    let mut out = out;
    out.layer = Layer { digest, size, media_type: GZIP_LAYER.into() };
    Ok(out)
}

fn is_zero(f: &mut File) -> io::Result<bool> {
    let mut buf = [0u8; 1024];
    f.read_exact(&mut buf)?;
    Ok(buf.iter().all(|&b| b == 0))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    /// The shortcut is what the compressor would write anyway.
    #[test]
    fn the_empty_layer_constant_is_what_goflate_writes() {
        let mut g = crate::goflate::GzipWriter::new(Vec::new(), 6).unwrap();
        g.write_all(&[0u8; 1024]).unwrap();
        assert_eq!(g.finish().unwrap(), EMPTY_TAR_GZIP);
    }

    use super::*;

    fn unzstd(bytes: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        ZstdFrames::new(io::BufReader::with_capacity(7, bytes)).read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn every_zstd_frame_is_read_and_skippable_ones_passed_over() {
        let z = |b: &[u8]| ruzstd::encoding::compress_to_vec(b, ruzstd::encoding::CompressionLevel::Fastest);
        let skip = |p: &[u8]| [&0x184D_2A53u32.to_le_bytes()[..], &(p.len() as u32).to_le_bytes(), p].concat();
        let data: Vec<u8> = (0..50_000u32).map(|i| (i % 97) as u8).collect();
        let mut s = skip(b"head");
        for part in data.chunks(7_000) {
            s.extend(z(part));
            s.extend(skip(b"between"));
        }
        assert_eq!(unzstd(&s).unwrap(), data);
        assert_eq!(unzstd(&[]).unwrap(), b"");
        // Cut short anywhere: an error, never a shorter stream read as whole.
        let whole = [z(&data), skip(b"tail")].concat();
        for cut in [3, 20, whole.len() / 2, whole.len() - 3] {
            assert!(unzstd(&whole[..cut]).is_err(), "cut at {cut}");
        }
        assert!(unzstd(b"not zstd at all").is_err());
    }

    fn scratch() -> (PathBuf, Store) {
        static N: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!("kiri-compress-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        let s = Store::open(&d).unwrap();
        (d, s)
    }

    fn put(store: &Store, bytes: &[u8], media_type: &str) -> Layer {
        let mut w = store.ingest().unwrap();
        w.write_all(bytes).unwrap();
        let (digest, size) = w.finish().unwrap();
        Layer { digest, size, media_type: media_type.into() }
    }

    fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, data) in files {
            let mut h = tar::Header::new_ustar();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            b.append_data(&mut h, name, *data).unwrap();
        }
        b.into_inner().unwrap()
    }

    fn blobs(dir: &std::path::Path) -> usize {
        std::fs::read_dir(dir.join("blobs/sha256")).unwrap().count() + std::fs::read_dir(dir.join("tmp")).unwrap().count()
    }

    #[test]
    fn a_plain_layer_goes_out_as_go_style_level_6_gzip() {
        let (dir, store) = scratch();
        store.use_native_checks();
        let text: Vec<u8> = (0..20000).flat_map(|i| format!("line {i} of a compressible file\n").into_bytes()).collect();
        let tar = tar_of(&[("nums", &text)]);
        let layer = put(&store, &tar, "application/vnd.oci.image.layer.v1.tar");
        let before = blobs(&dir);
        let out = outgoing(&store, &layer).unwrap();
        let bytes = std::fs::read(&out.path).unwrap();
        assert_eq!(out.layer.media_type, GZIP_LAYER);
        assert_eq!(out.layer.size, bytes.len() as u64);
        assert_eq!(out.layer.digest, crate::store::sha256_digest(&bytes));
        // Header as Go writes it at the default level: no name, mtime 0, XFL 0, OS 255.
        assert_eq!(bytes[..10], [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff]);
        let mut back = Vec::new();
        flate2::read::GzDecoder::new(&bytes[..]).read_to_end(&mut back).unwrap();
        assert_eq!(back, tar);
        assert!(bytes.len() * 4 < tar.len(), "{} of {}", bytes.len(), tar.len());
        // The same tar gives the same blob; the copies do not stay.
        let again = outgoing(&store, &layer).unwrap();
        assert_eq!(again.layer.digest, out.layer.digest);
        drop((out, again));
        assert_eq!(blobs(&dir), before);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_empty_layer_is_the_well_known_blob() {
        let (dir, store) = scratch();
        store.use_native_checks();
        let layer = put(&store, &[0u8; 1024], "application/vnd.oci.image.layer.v1.tar");
        let out = outgoing(&store, &layer).unwrap();
        assert_eq!(out.layer.digest, "sha256:4f4fb700ef54461cfa02571ae0db9a0dc1e0cdb5577484a6d75e68dc38e8acc1");
        assert_eq!(out.layer.size, 32);
        let mut back = Vec::new();
        flate2::read::GzDecoder::new(File::open(&out.path).unwrap()).read_to_end(&mut back).unwrap();
        assert_eq!(back, [0u8; 1024]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// With the builder switched off a plain-tar layer (one `docker commit`
    /// made) leaves as it is kept, as before the builder.
    #[test]
    fn without_the_builder_a_plain_layer_goes_out_as_it_is() {
        let (dir, store) = scratch();
        let tar = tar_of(&[("f", b"committed")]);
        let layer = put(&store, &tar, "application/vnd.oci.image.layer.v1.tar");
        let out = outgoing(&store, &layer).unwrap();
        assert_eq!(out.layer, layer);
        assert_eq!(out.path, store.blob_path(&layer.digest).unwrap());
        drop(out);
        assert!(store.blob_path(&layer.digest).unwrap().exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn compressed_layers_go_out_as_they_are() {
        let (dir, store) = scratch();
        let layer = put(&store, b"\x1f\x8bpulled", GZIP_LAYER);
        let out = outgoing(&store, &layer).unwrap();
        assert_eq!(out.layer.digest, layer.digest);
        assert_eq!(out.path, store.blob_path(&layer.digest).unwrap());
        drop(out);
        assert!(store.blob_path(&layer.digest).unwrap().exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
