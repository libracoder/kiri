//! Go's `compress/flate` compressor at levels 2 to 9 and `compress/gzip`'s
//! framing, ported so that a layer Kiri gzips is byte for byte the blob
//! BuildKit v0.33.1 writes for the same tar: same
//! digest, same size, and the same compression ratio, which flate2's
//! deflate does not reach on some data (10 % bigger on `seq` output).
//!
//! Ported from Go 1.26.5 (commit c19862e5f8415b4f24b189d065ed739517c548ba),
//! `src/compress/flate/deflate.go`, `huffman_bit_writer.go`,
//! `huffman_code.go`, `token.go` and `src/compress/gzip/gzip.go`. (BuildKit
//! carries the same Go 1.26 code as `util/compression/go126flate` on its
//! main branch; the v0.33.1 tag does not have that folder.)
//! Copyright 2009 The Go Authors. All rights reserved. Use of this source
//! code is governed by a BSD-style license (Go's LICENSE file).
//!
//! Notice: this file is a translation into Rust of the Go files named
//! above, so it is a changed version of that code and not the original.
//! The licence text is in NOTICE, section "Code ported into Kiri".
//!
//! Only what level 6 needs is here: the lazy-matching compressor (levels
//! 4 to 9) and the skipping one (2 and 3), dynamic, fixed and stored blocks,
//! and the final empty stored block Go's Close writes. Level 1 (Go's
//! `deflatefast.go`), Huffman-only and dictionaries are left out.

use std::io::{self, Write};

// ---------------------------------------------------------------- token.go

const LENGTH_SHIFT: u32 = 22;
const OFFSET_MASK: u32 = (1 << LENGTH_SHIFT) - 1;
const MATCH_TYPE: u32 = 1 << 30;

#[rustfmt::skip]
const LENGTH_CODES: [u8; 256] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15,
    16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 18, 18, 18, 18, 18, 18, 18, 18, 19, 19, 19, 19, 19, 19, 19, 19,
    20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21,
    22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
    26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 28,
];

#[rustfmt::skip]
const OFFSET_CODES: [u8; 256] = [
    0, 1, 2, 3, 4, 4, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
    8, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
];

type Token = u32;

fn literal_token(lit: u32) -> Token {
    lit
}

fn match_token(xlength: u32, xoffset: u32) -> Token {
    MATCH_TYPE + (xlength << LENGTH_SHIFT) + xoffset
}

fn token_offset(t: Token) -> u32 {
    t & OFFSET_MASK
}

fn token_length(t: Token) -> u32 {
    (t - MATCH_TYPE) >> LENGTH_SHIFT
}

fn length_code(len: u32) -> u32 {
    u32::from(LENGTH_CODES[len as usize])
}

fn offset_code(off: u32) -> u32 {
    if off < 256 {
        return u32::from(OFFSET_CODES[off as usize]);
    }
    if off >> 7 < 256 {
        return u32::from(OFFSET_CODES[(off >> 7) as usize]) + 14;
    }
    u32::from(OFFSET_CODES[(off >> 14) as usize]) + 28
}

// ---------------------------------------------------------------- huffman_code.go

const MAX_NUM_LIT: usize = 286;
const MAX_BITS_LIMIT: usize = 16;

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
struct HCode {
    code: u16,
    len: u16,
}

#[derive(Clone, Copy, Debug)]
struct LiteralNode {
    literal: u16,
    freq: i32,
}

#[derive(Clone, Copy, Default)]
struct LevelInfo {
    level: i32,
    last_freq: i32,
    next_char_freq: i32,
    next_pair_freq: i32,
    needed: i32,
}

struct HuffmanEncoder {
    codes: Vec<HCode>,
    bit_count: [i32; 17],
}

fn reverse_bits(number: u16, bit_length: u8) -> u16 {
    (number << (16 - u32::from(bit_length))).reverse_bits()
}

impl HuffmanEncoder {
    fn new(size: usize) -> HuffmanEncoder {
        HuffmanEncoder { codes: vec![HCode::default(); size], bit_count: [0; 17] }
    }

    fn fixed_literal() -> HuffmanEncoder {
        let mut h = HuffmanEncoder::new(MAX_NUM_LIT);
        for ch in 0..MAX_NUM_LIT as u16 {
            let (bits, size) = match ch {
                0..144 => (ch + 48, 8),
                144..256 => (ch + 400 - 144, 9),
                256..280 => (ch - 256, 7),
                _ => (ch + 192 - 280, 8),
            };
            h.codes[usize::from(ch)] = HCode { code: reverse_bits(bits, size as u8), len: size };
        }
        h
    }

    fn fixed_offset() -> HuffmanEncoder {
        let mut h = HuffmanEncoder::new(30);
        for (ch, c) in h.codes.iter_mut().enumerate() {
            *c = HCode { code: reverse_bits(ch as u16, 5), len: 5 };
        }
        h
    }

    fn bit_length(&self, freq: &[i32]) -> i64 {
        freq.iter().zip(&self.codes).filter(|(f, _)| **f != 0).map(|(f, c)| i64::from(*f) * i64::from(c.len)).sum()
    }

    /// The number of literals per code length (Go's bitCounts). `list` is
    /// sorted by frequency and has a sentinel after its last node.
    fn bit_counts(&mut self, list: &[LiteralNode], mut max_bits: i32) -> usize {
        let n = (list.len() - 1) as i32;
        if max_bits > n - 1 {
            max_bits = n - 1;
        }
        let mut levels = [LevelInfo::default(); MAX_BITS_LIMIT];
        let mut leaf_counts = [[0i32; MAX_BITS_LIMIT]; MAX_BITS_LIMIT];
        for level in 1..=max_bits as usize {
            levels[level] = LevelInfo {
                level: level as i32,
                last_freq: list[1].freq,
                next_char_freq: list[2].freq,
                next_pair_freq: list[0].freq.wrapping_add(list[1].freq),
                needed: 0,
            };
            leaf_counts[level][level] = 2;
            if level == 1 {
                levels[level].next_pair_freq = i32::MAX;
            }
        }
        levels[max_bits as usize].needed = 2 * n - 4;
        let mut level = max_bits as usize;
        loop {
            let l = levels[level];
            if l.next_pair_freq == i32::MAX && l.next_char_freq == i32::MAX {
                levels[level].needed = 0;
                levels[level + 1].next_pair_freq = i32::MAX;
                level += 1;
                continue;
            }
            let prev_freq = l.last_freq;
            if l.next_char_freq < l.next_pair_freq {
                let nn = leaf_counts[level][level] + 1;
                levels[level].last_freq = l.next_char_freq;
                leaf_counts[level][level] = nn;
                levels[level].next_char_freq = list[nn as usize].freq;
            } else {
                levels[level].last_freq = l.next_pair_freq;
                let (lo, hi) = leaf_counts.split_at_mut(level);
                hi[0][..level].copy_from_slice(&lo[level - 1][..level]);
                levels[l.level as usize - 1].needed = 2;
            }
            levels[level].needed -= 1;
            if levels[level].needed == 0 {
                if levels[level].level == max_bits {
                    break;
                }
                levels[level + 1].next_pair_freq = prev_freq.wrapping_add(levels[level].last_freq);
                level += 1;
            } else {
                while levels[level - 1].needed > 0 {
                    level -= 1;
                }
            }
        }
        assert_eq!(leaf_counts[max_bits as usize][max_bits as usize], n, "flate: leafCounts[maxBits][maxBits] != n");
        let counts = leaf_counts[max_bits as usize];
        for (bits, level) in (1..).zip((1..=max_bits as usize).rev()) {
            self.bit_count[bits] = counts[level] - counts[level - 1];
        }
        max_bits as usize + 1
    }

    fn assign_encoding_and_size(&mut self, nbits: usize, mut list: &mut [LiteralNode]) {
        let mut code: u16 = 0;
        for n in 0..nbits {
            let bits = self.bit_count[n];
            code = code.wrapping_shl(1);
            if n == 0 || bits == 0 {
                continue;
            }
            let at = list.len() - bits as usize;
            let (rest, chunk) = list.split_at_mut(at);
            chunk.sort_unstable_by_key(|x| x.literal);
            for node in chunk.iter() {
                self.codes[usize::from(node.literal)] = HCode { code: reverse_bits(code, n as u8), len: n as u16 };
                code = code.wrapping_add(1);
            }
            list = rest;
        }
    }

    fn generate(&mut self, freq: &[i32], max_bits: i32) {
        let mut list: Vec<LiteralNode> = Vec::with_capacity(freq.len() + 1);
        for (i, &f) in freq.iter().enumerate() {
            if f != 0 {
                list.push(LiteralNode { literal: i as u16, freq: f });
            } else {
                self.codes[i].len = 0;
            }
        }
        if list.len() <= 2 {
            for (i, node) in list.iter().enumerate() {
                self.codes[usize::from(node.literal)] = HCode { code: i as u16, len: 1 };
            }
            return;
        }
        // A total order (frequency, then literal), so any sort gives Go's result.
        list.sort_unstable_by(|a, b| a.freq.cmp(&b.freq).then(a.literal.cmp(&b.literal)));
        list.push(LiteralNode { literal: u16::MAX, freq: i32::MAX });
        let nbits = self.bit_counts(&list, max_bits);
        list.pop();
        self.assign_encoding_and_size(nbits, &mut list);
    }
}

// ---------------------------------------------------------------- huffman_bit_writer.go

const OFFSET_CODE_COUNT: usize = 30;
const END_BLOCK_MARKER: u32 = 256;
const LENGTH_CODES_START: usize = 257;
const CODEGEN_CODE_COUNT: usize = 19;
const BAD_CODE: u8 = 255;
const BUFFER_FLUSH_SIZE: usize = 240;
const BUFFER_SIZE: usize = BUFFER_FLUSH_SIZE + 8;

const LENGTH_EXTRA_BITS: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const LENGTH_BASE: [u32; 29] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 255];
const OFFSET_EXTRA_BITS: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
#[rustfmt::skip]
const OFFSET_BASE: [u32; 30] = [
    0x000000, 0x000001, 0x000002, 0x000003, 0x000004, 0x000006, 0x000008, 0x00000c, 0x000010, 0x000018,
    0x000020, 0x000030, 0x000040, 0x000060, 0x000080, 0x0000c0, 0x000100, 0x000180, 0x000200, 0x000300,
    0x000400, 0x000600, 0x000800, 0x000c00, 0x001000, 0x001800, 0x002000, 0x003000, 0x004000, 0x006000,
];
const CODEGEN_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

struct BitWriter<W: Write> {
    writer: W,
    bits: u64,
    nbits: u32,
    bytes: [u8; BUFFER_SIZE],
    codegen_freq: [i32; CODEGEN_CODE_COUNT],
    nbytes: usize,
    literal_freq: Vec<i32>,
    offset_freq: Vec<i32>,
    codegen: Vec<u8>,
    literal_encoding: HuffmanEncoder,
    offset_encoding: HuffmanEncoder,
    codegen_encoding: HuffmanEncoder,
    fixed_literal: HuffmanEncoder,
    fixed_offset: HuffmanEncoder,
    err: Option<io::Error>,
}

impl<W: Write> BitWriter<W> {
    fn new(writer: W) -> Self {
        BitWriter {
            writer,
            bits: 0,
            nbits: 0,
            bytes: [0; BUFFER_SIZE],
            codegen_freq: [0; CODEGEN_CODE_COUNT],
            nbytes: 0,
            literal_freq: vec![0; MAX_NUM_LIT],
            offset_freq: vec![0; OFFSET_CODE_COUNT],
            codegen: vec![0; MAX_NUM_LIT + OFFSET_CODE_COUNT + 1],
            literal_encoding: HuffmanEncoder::new(MAX_NUM_LIT),
            offset_encoding: HuffmanEncoder::new(OFFSET_CODE_COUNT),
            codegen_encoding: HuffmanEncoder::new(CODEGEN_CODE_COUNT),
            fixed_literal: HuffmanEncoder::fixed_literal(),
            fixed_offset: HuffmanEncoder::fixed_offset(),
            err: None,
        }
    }

    fn write(&mut self, n: usize) {
        if self.err.is_none()
            && let Err(e) = self.writer.write_all(&self.bytes[..n])
        {
            self.err = Some(e);
        }
    }

    fn write_slice(&mut self, b: &[u8]) {
        if self.err.is_none()
            && let Err(e) = self.writer.write_all(b)
        {
            self.err = Some(e);
        }
    }

    fn flush(&mut self) {
        if self.err.is_some() {
            self.nbits = 0;
            return;
        }
        let mut n = self.nbytes;
        while self.nbits != 0 {
            self.bytes[n] = self.bits as u8;
            self.bits >>= 8;
            self.nbits = self.nbits.saturating_sub(8);
            n += 1;
        }
        self.bits = 0;
        self.write(n);
        self.nbytes = 0;
    }

    fn spill(&mut self) {
        let bits = self.bits;
        self.bits >>= 48;
        self.nbits -= 48;
        let n = self.nbytes;
        self.bytes[n..n + 6].copy_from_slice(&bits.to_le_bytes()[..6]);
        let n = n + 6;
        if n >= BUFFER_FLUSH_SIZE {
            self.write(n);
            self.nbytes = 0;
        } else {
            self.nbytes = n;
        }
    }

    fn write_bits(&mut self, b: u32, nb: u32) {
        if self.err.is_some() {
            return;
        }
        self.bits |= u64::from(b) << self.nbits;
        self.nbits += nb;
        if self.nbits >= 48 {
            self.spill();
        }
    }

    fn write_code(&mut self, c: HCode) {
        if self.err.is_some() {
            return;
        }
        self.bits |= u64::from(c.code) << self.nbits;
        self.nbits += u32::from(c.len);
        if self.nbits >= 48 {
            self.spill();
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        if self.err.is_some() {
            return;
        }
        let mut n = self.nbytes;
        if self.nbits & 7 != 0 {
            self.err = Some(io::Error::other("flate: writeBytes with unfinished bits"));
            return;
        }
        while self.nbits != 0 {
            self.bytes[n] = self.bits as u8;
            self.bits >>= 8;
            self.nbits -= 8;
            n += 1;
        }
        if n != 0 {
            self.write(n);
        }
        self.nbytes = 0;
        self.write_slice(bytes);
    }

    /// The code lengths of the block's (dynamic) literal and offset codes,
    /// run-length coded (Go's generateCodegen).
    fn generate_codegen(&mut self, num_literals: usize, num_offsets: usize) {
        self.codegen_freq = [0; CODEGEN_CODE_COUNT];
        let codegen = &mut self.codegen;
        for (c, h) in codegen[..num_literals].iter_mut().zip(&self.literal_encoding.codes) {
            *c = h.len as u8;
        }
        for (c, h) in codegen[num_literals..num_literals + num_offsets].iter_mut().zip(&self.offset_encoding.codes) {
            *c = h.len as u8;
        }
        codegen[num_literals + num_offsets] = BAD_CODE;
        let mut size = codegen[0];
        let mut count: i32 = 1;
        let mut out = 0usize;
        let mut input = 1usize;
        while size != BAD_CODE {
            let next = codegen[input];
            input += 1;
            if next == size {
                count += 1;
                continue;
            }
            if size != 0 {
                codegen[out] = size;
                out += 1;
                self.codegen_freq[usize::from(size)] += 1;
                count -= 1;
                while count >= 3 {
                    let n = count.min(6);
                    codegen[out] = 16;
                    codegen[out + 1] = (n - 3) as u8;
                    out += 2;
                    self.codegen_freq[16] += 1;
                    count -= n;
                }
            } else {
                while count >= 11 {
                    let n = count.min(138);
                    codegen[out] = 18;
                    codegen[out + 1] = (n - 11) as u8;
                    out += 2;
                    self.codegen_freq[18] += 1;
                    count -= n;
                }
                if count >= 3 {
                    codegen[out] = 17;
                    codegen[out + 1] = (count - 3) as u8;
                    out += 2;
                    self.codegen_freq[17] += 1;
                    count = 0;
                }
            }
            count -= 1;
            while count >= 0 {
                codegen[out] = size;
                out += 1;
                self.codegen_freq[usize::from(size)] += 1;
                count -= 1;
            }
            size = next;
            count = 1;
        }
        codegen[out] = BAD_CODE;
    }

    fn dynamic_size(&self, extra_bits: i64) -> (i64, usize) {
        let mut num_codegens = self.codegen_freq.len();
        while num_codegens > 4 && self.codegen_freq[CODEGEN_ORDER[num_codegens - 1]] == 0 {
            num_codegens -= 1;
        }
        let header = 3 + 5 + 5 + 4 + 3 * num_codegens as i64
            + self.codegen_encoding.bit_length(&self.codegen_freq)
            + i64::from(self.codegen_freq[16]) * 2
            + i64::from(self.codegen_freq[17]) * 3
            + i64::from(self.codegen_freq[18]) * 7;
        let size = header + self.literal_encoding.bit_length(&self.literal_freq) + self.offset_encoding.bit_length(&self.offset_freq) + extra_bits;
        (size, num_codegens)
    }

    fn fixed_size(&self, extra_bits: i64) -> i64 {
        3 + self.fixed_literal.bit_length(&self.literal_freq) + self.fixed_offset.bit_length(&self.offset_freq) + extra_bits
    }

    fn write_dynamic_header(&mut self, num_literals: usize, num_offsets: usize, num_codegens: usize, eof: bool) {
        if self.err.is_some() {
            return;
        }
        self.write_bits(if eof { 5 } else { 4 }, 3);
        self.write_bits((num_literals - 257) as u32, 5);
        self.write_bits((num_offsets - 1) as u32, 5);
        self.write_bits((num_codegens - 4) as u32, 4);
        for &o in CODEGEN_ORDER.iter().take(num_codegens) {
            let v = u32::from(self.codegen_encoding.codes[o].len);
            self.write_bits(v, 3);
        }
        let mut i = 0;
        loop {
            let word = self.codegen[i];
            i += 1;
            if word == BAD_CODE {
                break;
            }
            let c = self.codegen_encoding.codes[usize::from(word)];
            self.write_code(c);
            let extra = match word {
                16 => 2,
                17 => 3,
                18 => 7,
                _ => 0,
            };
            if extra > 0 {
                let v = u32::from(self.codegen[i]);
                self.write_bits(v, extra);
                i += 1;
            }
        }
    }

    fn write_stored_header(&mut self, length: usize, eof: bool) {
        if self.err.is_some() {
            return;
        }
        self.write_bits(u32::from(eof), 3);
        self.flush();
        self.write_bits(length as u32, 16);
        self.write_bits(u32::from(!(length as u16)), 16);
    }

    fn write_fixed_header(&mut self, eof: bool) {
        if self.err.is_some() {
            return;
        }
        self.write_bits(if eof { 3 } else { 2 }, 3);
    }

    /// Go's writeBlock: `input` is None where Go passes a nil slice (the
    /// block's bytes are no longer in the window, so it cannot be stored).
    fn write_block(&mut self, tokens: &mut Vec<Token>, eof: bool, input: Option<&[u8]>) {
        if self.err.is_some() {
            return;
        }
        tokens.push(END_BLOCK_MARKER);
        let (num_literals, num_offsets) = self.index_tokens(tokens);
        let mut extra_bits: i64 = 0;
        let stored = input.filter(|i| i.len() <= MAX_STORE_BLOCK_SIZE).map(|i| (i.len() as i64 + 5) * 8);
        if stored.is_some() {
            for lc in LENGTH_CODES_START + 8..num_literals {
                extra_bits += i64::from(self.literal_freq[lc]) * i64::from(LENGTH_EXTRA_BITS[lc - LENGTH_CODES_START]);
            }
            for (f, x) in self.offset_freq[..num_offsets].iter().zip(OFFSET_EXTRA_BITS).skip(4) {
                extra_bits += i64::from(*f) * i64::from(x);
            }
        }
        let mut fixed = true;
        let mut size = self.fixed_size(extra_bits);
        self.generate_codegen(num_literals, num_offsets);
        let cf = self.codegen_freq;
        self.codegen_encoding.generate(&cf, 7);
        let (dynamic, num_codegens) = self.dynamic_size(extra_bits);
        if dynamic < size {
            size = dynamic;
            fixed = false;
        }
        if let (Some(ss), Some(input)) = (stored, input)
            && ss < size
        {
            self.write_stored_header(input.len(), eof);
            self.write_bytes(input);
            tokens.pop();
            return;
        }
        if fixed {
            self.write_fixed_header(eof);
        } else {
            self.write_dynamic_header(num_literals, num_offsets, num_codegens, eof);
        }
        self.write_tokens(tokens, fixed);
        tokens.pop();
    }

    fn index_tokens(&mut self, tokens: &[Token]) -> (usize, usize) {
        self.literal_freq.iter_mut().for_each(|f| *f = 0);
        self.offset_freq.iter_mut().for_each(|f| *f = 0);
        for &t in tokens {
            if t < MATCH_TYPE {
                self.literal_freq[t as usize] += 1;
                continue;
            }
            self.literal_freq[LENGTH_CODES_START + length_code(token_length(t)) as usize] += 1;
            self.offset_freq[offset_code(token_offset(t)) as usize] += 1;
        }
        let mut num_literals = self.literal_freq.len();
        while self.literal_freq[num_literals - 1] == 0 {
            num_literals -= 1;
        }
        let mut num_offsets = self.offset_freq.len();
        while num_offsets > 0 && self.offset_freq[num_offsets - 1] == 0 {
            num_offsets -= 1;
        }
        if num_offsets == 0 {
            self.offset_freq[0] = 1;
            num_offsets = 1;
        }
        let (lf, of) = (std::mem::take(&mut self.literal_freq), std::mem::take(&mut self.offset_freq));
        self.literal_encoding.generate(&lf, 15);
        self.offset_encoding.generate(&of, 15);
        self.literal_freq = lf;
        self.offset_freq = of;
        (num_literals, num_offsets)
    }

    fn write_tokens(&mut self, tokens: &[Token], fixed: bool) {
        if self.err.is_some() {
            return;
        }
        for &t in tokens {
            let (le, oe) = if fixed { (&self.fixed_literal, &self.fixed_offset) } else { (&self.literal_encoding, &self.offset_encoding) };
            if t < MATCH_TYPE {
                let c = le.codes[t as usize];
                self.write_code(c);
                continue;
            }
            let length = token_length(t);
            let lc = length_code(length) as usize;
            let c = le.codes[lc + LENGTH_CODES_START];
            let offset = token_offset(t);
            let oc = offset_code(offset) as usize;
            let oce = oe.codes[oc];
            self.write_code(c);
            let extra = u32::from(LENGTH_EXTRA_BITS[lc]);
            if extra > 0 {
                self.write_bits(length - LENGTH_BASE[lc], extra);
            }
            self.write_code(oce);
            let extra = u32::from(OFFSET_EXTRA_BITS[oc]);
            if extra > 0 {
                self.write_bits(offset - OFFSET_BASE[oc], extra);
            }
        }
    }
}

// ---------------------------------------------------------------- deflate.go

const LOG_WINDOW_SIZE: usize = 15;
const WINDOW_SIZE: usize = 1 << LOG_WINDOW_SIZE;
const WINDOW_MASK: usize = WINDOW_SIZE - 1;
const BASE_MATCH_LENGTH: i64 = 3;
const MIN_MATCH_LENGTH: i64 = 4;
const MAX_MATCH_LENGTH: i64 = 258;
const BASE_MATCH_OFFSET: i64 = 1;
const MAX_FLATE_BLOCK_TOKENS: usize = 1 << 14;
const MAX_STORE_BLOCK_SIZE: usize = 65535;
const HASH_BITS: u32 = 17;
const HASH_SIZE: usize = 1 << HASH_BITS;
const HASH_MASK: u32 = (1 << HASH_BITS) - 1;
const MAX_HASH_OFFSET: i64 = 1 << 24;
const SKIP_NEVER: i64 = i32::MAX as i64;
const HASHMUL: u32 = 0x1e35a7bd;

#[derive(Clone, Copy)]
struct Level {
    good: i64,
    lazy: i64,
    nice: i64,
    chain: i64,
    fast_skip_hashing: i64,
}

fn level_params(level: u32) -> Level {
    let (good, lazy, nice, chain, fast_skip_hashing) = match level {
        2 => (4, 0, 16, 8, 5),
        3 => (4, 0, 32, 32, 6),
        4 => (4, 4, 16, 16, SKIP_NEVER),
        5 => (8, 16, 32, 32, SKIP_NEVER),
        6 => (8, 16, 128, 128, SKIP_NEVER),
        7 => (8, 32, 128, 256, SKIP_NEVER),
        8 => (32, 128, 258, 1024, SKIP_NEVER),
        _ => (32, 258, 258, 4096, SKIP_NEVER),
    };
    Level { good, lazy, nice, chain, fast_skip_hashing }
}

fn hash4(b: &[u8]) -> u32 {
    (u32::from(b[3]) | u32::from(b[2]) << 8 | u32::from(b[1]) << 16 | u32::from(b[0]) << 24).wrapping_mul(HASHMUL) >> (32 - HASH_BITS)
}

fn match_len(a: &[u8], b: &[u8], max: usize) -> usize {
    a[..max].iter().zip(&b[..max]).position(|(x, y)| x != y).unwrap_or(max)
}

/// A raw DEFLATE stream writer, byte for byte Go's `flate.NewWriter(w,
/// level)` for levels 2 to 9.
pub struct Deflater<W: Write> {
    p: Level,
    w: BitWriter<W>,
    index: i64,
    window: Vec<u8>,
    window_end: i64,
    block_start: i64,
    byte_available: bool,
    sync: bool,
    tokens: Vec<Token>,
    length: i64,
    offset: i64,
    max_insert_index: i64,
    chain_head: i64,
    hash_head: Vec<u32>,
    hash_prev: Vec<u32>,
    hash_offset: i64,
    closed: bool,
}

impl<W: Write> Deflater<W> {
    /// `level` 2 to 9 (Go's default, -1, is 6).
    pub fn new(writer: W, level: u32) -> Deflater<W> {
        assert!((2..=9).contains(&level), "only levels 2 to 9 are ported");
        Deflater {
            p: level_params(level),
            w: BitWriter::new(writer),
            index: 0,
            window: vec![0; 2 * WINDOW_SIZE],
            window_end: 0,
            block_start: 0,
            byte_available: false,
            sync: false,
            tokens: Vec::with_capacity(MAX_FLATE_BLOCK_TOKENS + 1),
            length: MIN_MATCH_LENGTH - 1,
            offset: 0,
            max_insert_index: 0,
            chain_head: -1,
            hash_head: vec![0; HASH_SIZE],
            hash_prev: vec![0; WINDOW_SIZE],
            hash_offset: 1,
            closed: false,
        }
    }

    /// A write error stays: every later call fails with it, as in Go.
    fn take_err(&self) -> io::Result<()> {
        match &self.w.err {
            Some(e) => Err(io::Error::new(e.kind(), e.to_string())),
            None => Ok(()),
        }
    }

    fn fill(&mut self, b: &[u8]) -> usize {
        if self.index >= (2 * WINDOW_SIZE) as i64 - (MIN_MATCH_LENGTH + MAX_MATCH_LENGTH) {
            self.window.copy_within(WINDOW_SIZE..2 * WINDOW_SIZE, 0);
            self.index -= WINDOW_SIZE as i64;
            self.window_end -= WINDOW_SIZE as i64;
            if self.block_start >= WINDOW_SIZE as i64 {
                self.block_start -= WINDOW_SIZE as i64;
            } else {
                self.block_start = i64::from(i32::MAX);
            }
            self.hash_offset += WINDOW_SIZE as i64;
            if self.hash_offset > MAX_HASH_OFFSET {
                let delta = self.hash_offset - 1;
                self.hash_offset -= delta;
                self.chain_head -= delta;
                for v in self.hash_prev.iter_mut().chain(self.hash_head.iter_mut()) {
                    *v = if i64::from(*v) > delta { (i64::from(*v) - delta) as u32 } else { 0 };
                }
            }
        }
        let end = self.window_end as usize;
        let n = b.len().min(self.window.len() - end);
        self.window[end..end + n].copy_from_slice(&b[..n]);
        self.window_end += n as i64;
        n
    }

    fn write_block(&mut self, index: i64) {
        if index > 0 {
            let mut tokens = std::mem::take(&mut self.tokens);
            if self.block_start <= index {
                let window = std::mem::take(&mut self.window);
                self.w.write_block(&mut tokens, false, Some(&window[self.block_start as usize..index as usize]));
                self.window = window;
            } else {
                self.w.write_block(&mut tokens, false, None);
            }
            self.block_start = index;
            self.tokens = tokens;
        }
    }

    fn find_match(&self, pos: i64, prev_head: i64, prev_length: i64, lookahead: i64) -> Option<(i64, i64)> {
        let min_match_look = MAX_MATCH_LENGTH.min(lookahead);
        let win = &self.window[..(pos + min_match_look) as usize];
        let nice = (win.len() as i64 - pos).min(self.p.nice);
        let mut tries = self.p.chain;
        let mut length = prev_length;
        if length >= self.p.good {
            tries >>= 2;
        }
        let mut w_end = win[(pos + length) as usize];
        let w_pos = &win[pos as usize..];
        let min_index = pos - WINDOW_SIZE as i64;
        let mut found = None;
        let mut i = prev_head;
        while tries > 0 {
            if w_end == win[(i + length) as usize] {
                let n = match_len(&win[i as usize..], w_pos, min_match_look as usize) as i64;
                if n > length && (n > MIN_MATCH_LENGTH || pos - i <= 4096) {
                    length = n;
                    found = Some((n, pos - i));
                    if n >= nice {
                        break;
                    }
                    w_end = win[(pos + n) as usize];
                }
            }
            if i == min_index {
                break;
            }
            i = i64::from(self.hash_prev[i as usize & WINDOW_MASK]) - self.hash_offset;
            if i < min_index || i < 0 {
                break;
            }
            tries -= 1;
        }
        found
    }

    fn insert_hash(&mut self, index: i64) -> u32 {
        let i = index as usize;
        let hash = hash4(&self.window[i..i + MIN_MATCH_LENGTH as usize]);
        let hh = &mut self.hash_head[(hash & HASH_MASK) as usize];
        let prev = *hh;
        self.hash_prev[i & WINDOW_MASK] = prev;
        *hh = (index + self.hash_offset) as u32;
        prev
    }

    fn deflate(&mut self) {
        if self.window_end - self.index < MIN_MATCH_LENGTH + MAX_MATCH_LENGTH && !self.sync {
            return;
        }
        self.max_insert_index = self.window_end - (MIN_MATCH_LENGTH - 1);
        let skip = self.p.fast_skip_hashing;
        loop {
            assert!(self.index <= self.window_end, "index > windowEnd");
            let lookahead = self.window_end - self.index;
            if lookahead < MIN_MATCH_LENGTH + MAX_MATCH_LENGTH {
                if !self.sync {
                    break;
                }
                if lookahead == 0 {
                    if self.byte_available {
                        let lit = self.window[(self.index - 1) as usize];
                        self.tokens.push(literal_token(u32::from(lit)));
                        self.byte_available = false;
                    }
                    if !self.tokens.is_empty() {
                        self.write_block(self.index);
                        if self.w.err.is_some() {
                            return;
                        }
                        self.tokens.clear();
                    }
                    break;
                }
            }
            if self.index < self.max_insert_index {
                self.chain_head = i64::from(self.insert_hash(self.index));
            }
            let prev_length = self.length;
            let prev_offset = self.offset;
            self.length = MIN_MATCH_LENGTH - 1;
            self.offset = 0;
            let min_index = (self.index - WINDOW_SIZE as i64).max(0);
            if self.chain_head - self.hash_offset >= min_index
                && ((skip != SKIP_NEVER && lookahead > MIN_MATCH_LENGTH - 1)
                    || (skip == SKIP_NEVER && lookahead > prev_length && prev_length < self.p.lazy))
                && let Some((l, o)) = self.find_match(self.index, self.chain_head - self.hash_offset, MIN_MATCH_LENGTH - 1, lookahead)
            {
                self.length = l;
                self.offset = o;
            }
            if (skip != SKIP_NEVER && self.length >= MIN_MATCH_LENGTH) || (skip == SKIP_NEVER && prev_length >= MIN_MATCH_LENGTH && self.length <= prev_length) {
                if skip != SKIP_NEVER {
                    self.tokens.push(match_token((self.length - BASE_MATCH_LENGTH) as u32, (self.offset - BASE_MATCH_OFFSET) as u32));
                } else {
                    self.tokens.push(match_token((prev_length - BASE_MATCH_LENGTH) as u32, (prev_offset - BASE_MATCH_OFFSET) as u32));
                }
                if self.length <= skip {
                    let new_index = if skip != SKIP_NEVER { self.index + self.length } else { self.index + prev_length - 1 };
                    let mut index = self.index + 1;
                    while index < new_index {
                        if index < self.max_insert_index {
                            self.insert_hash(index);
                        }
                        index += 1;
                    }
                    self.index = index;
                    if skip == SKIP_NEVER {
                        self.byte_available = false;
                        self.length = MIN_MATCH_LENGTH - 1;
                    }
                } else {
                    self.index += self.length;
                }
                if self.tokens.len() == MAX_FLATE_BLOCK_TOKENS {
                    self.write_block(self.index);
                    if self.w.err.is_some() {
                        return;
                    }
                    self.tokens.clear();
                }
            } else {
                if skip != SKIP_NEVER || self.byte_available {
                    let i = if skip != SKIP_NEVER { self.index } else { self.index - 1 };
                    let lit = self.window[i as usize];
                    self.tokens.push(literal_token(u32::from(lit)));
                    if self.tokens.len() == MAX_FLATE_BLOCK_TOKENS {
                        self.write_block(i + 1);
                        if self.w.err.is_some() {
                            return;
                        }
                        self.tokens.clear();
                    }
                }
                self.index += 1;
                if skip == SKIP_NEVER {
                    self.byte_available = true;
                }
            }
        }
    }

    /// Ends the stream as Go's Close does: the rest of the data, then an
    /// empty final stored block. Returns the inner writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.close()?;
        Ok(self.w.writer)
    }

    fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.sync = true;
        self.deflate();
        self.take_err()?;
        self.w.write_stored_header(0, true);
        self.w.flush();
        self.take_err()?;
        self.closed = true;
        Ok(())
    }
}

impl<W: Write> Write for Deflater<W> {
    fn write(&mut self, mut b: &[u8]) -> io::Result<usize> {
        self.take_err()?;
        let n = b.len();
        while !b.is_empty() {
            self.deflate();
            let k = self.fill(b);
            b = &b[k..];
            self.take_err()?;
        }
        Ok(n)
    }

    /// Nothing is held back that a flush could push out without changing
    /// the stream (Go's Flush writes a sync marker, which Kiri never asks
    /// for); the inner writer is flushed.
    fn flush(&mut self) -> io::Result<()> {
        self.w.writer.flush()
    }
}

impl<W: Write> std::fmt::Debug for Deflater<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deflater").field("index", &self.index).finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------- gzip.go

/// A gzip stream byte for byte as Go's `gzip.NewWriterLevel(w, level)`
/// writes it with an empty header: no name, mtime 0, OS 255, XFL 2 at
/// level 9 and 0 otherwise, then CRC-32 and size.
pub struct GzipWriter<W: Write> {
    inner: Deflater<W>,
    crc: flate2::Crc,
}

impl<W: Write> std::fmt::Debug for GzipWriter<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GzipWriter").finish_non_exhaustive()
    }
}

impl<W: Write> GzipWriter<W> {
    pub fn new(mut writer: W, level: u32) -> io::Result<GzipWriter<W>> {
        let xfl = if level == 9 { 2 } else { 0 };
        writer.write_all(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, xfl, 0xff])?;
        Ok(GzipWriter { inner: Deflater::new(writer, level), crc: flate2::Crc::new() })
    }

    pub fn finish(self) -> io::Result<W> {
        let mut w = self.inner.finish()?;
        w.write_all(&self.crc.sum().to_le_bytes())?;
        w.write_all(&self.crc.amount().to_le_bytes())?;
        Ok(w)
    }
}

impl<W: Write> Write for GzipWriter<W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(b)?;
        self.crc.update(&b[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn gzip(data: &[u8], level: u32) -> Vec<u8> {
        let mut g = GzipWriter::new(Vec::new(), level).unwrap();
        // Go's io.Copy hands the compressor 32 KiB at a time; the result
        // must not depend on that.
        for c in data.chunks(32 * 1024 + 7) {
            g.write_all(c).unwrap();
        }
        g.finish().unwrap()
    }

    fn gunzip(b: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(b).read_to_end(&mut out).unwrap();
        out
    }

    /// Blobs BuildKit v0.33.1 wrote (Go 1.26 compress/gzip, level 6): each
    /// is unpacked and compressed again, and must come back byte for byte.
    #[test]
    fn matches_buildkit_blobs() {
        for (name, blob) in [
            ("empty layer", &include_bytes!("../tests/data/gzip-empty-layer.tar.gz")[..]),
            ("RUN seq 1 20000", &include_bytes!("../tests/data/gzip-seq-layer.tar.gz")[..]),
        ] {
            let tar = gunzip(blob);
            let again = gzip(&tar, 6);
            assert!(again == blob, "{name}: {} bytes, BuildKit wrote {}", again.len(), blob.len());
        }
    }

    #[test]
    fn round_trips_at_every_level() {
        let mut data = Vec::new();
        let mut x: u32 = 1;
        for i in 0..300_000u32 {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            // Text, runs and noise, so every block kind is chosen somewhere.
            data.push(match (i / 5000) % 3 {
                0 => b"the quick brown fox "[i as usize % 20],
                1 => 0,
                _ => (x >> 16) as u8,
            });
        }
        for level in 2..=9 {
            assert_eq!(gunzip(&gzip(&data, level)), data, "level {level}");
        }
        assert_eq!(gunzip(&gzip(&[], 6)), b"");
        assert_eq!(gunzip(&gzip(b"a", 6)), b"a");
    }
}

#[cfg(test)]
mod speed {
    /// `KIRI_GOFLATE_CORPUS=dir cargo test --release -p kiri-image corpus -- --ignored --nocapture`:
    /// every `*.tar.gz` in the folder (blobs BuildKit wrote, Go 1.26 level 6)
    /// must come back byte for byte; prints MB/s against flate2 level 6.
    #[test]
    #[ignore]
    fn corpus() {
        use std::io::{Read, Write};
        let dir = std::env::var("KIRI_GOFLATE_CORPUS").expect("KIRI_GOFLATE_CORPUS");
        let mut names: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).filter(|p| p.to_string_lossy().ends_with(".tar.gz")).collect();
        names.sort();
        let (mut tot, mut t_go, mut t_fl) = (0usize, 0f64, 0f64);
        for p in names {
            let blob = std::fs::read(&p).unwrap();
            let mut tar = Vec::new();
            flate2::read::GzDecoder::new(&blob[..]).read_to_end(&mut tar).unwrap();
            let t = std::time::Instant::now();
            let mut g = super::GzipWriter::new(Vec::new(), 6).unwrap();
            g.write_all(&tar).unwrap();
            let ours = g.finish().unwrap();
            let dg = t.elapsed().as_secs_f64();
            let t = std::time::Instant::now();
            let mut f = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(6));
            f.write_all(&tar).unwrap();
            let fl = f.finish().unwrap();
            let df = t.elapsed().as_secs_f64();
            eprintln!("{}: tar {} go {} ours {} flate2 {} same={} {:.0} vs {:.0} MB/s", p.display(), tar.len(), blob.len(), ours.len(), fl.len(), ours == blob,
                tar.len() as f64 / dg / 1e6, tar.len() as f64 / df / 1e6);
            assert!(ours == blob, "{}", p.display());
            tot += tar.len();
            t_go += dg;
            t_fl += df;
        }
        eprintln!("all: {tot} bytes, ours {:.0} MB/s, flate2 {:.0} MB/s", tot as f64 / t_go / 1e6, tot as f64 / t_fl / 1e6);
    }
}
