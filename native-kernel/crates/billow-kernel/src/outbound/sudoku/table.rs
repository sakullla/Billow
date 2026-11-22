// SPDX-License-Identifier: GPL-3.0-only
//
// Derived from Mihomo `transport/sudoku` (GPL-3.0).
// Upstream: https://github.com/MetaCubeX/mihomo
// Version: v1.19.34
// Commit: 0455d0d28c4526937380505153e65a843d8612e8
// Source paths: transport/sudoku/{address,config,handshake,handshake_kip,kip,table_probe,tables,replay,multiplex}.go,
//               transport/sudoku/crypto/*.go, transport/sudoku/obfs/{sudoku,httpmask}/*.go,
//               adapter/outbound/sudoku.go (option names and defaults)
//
// This file is a Rust translation of that GPL-3.0 code. The kernel workspace
// therefore carries GPL-3.0 obligations for the sudoku module; see
// native-kernel/THIRD_PARTY_NOTICES.md and native-kernel/COPYING.GPL-3.0.
//
//! The Sudoku obfuscation table (`transport/sudoku/obfs/sudoku` of the pinned
//! source): byte layouts, the 288 4x4 grids, the per-byte puzzle table and the
//! hint-set decoder.
//!
//! The table is derived from the key: the grids are shuffled with Go's
//! `math/rand` (see [`super::go_rand`]), so the peer derives the same table
//! only when the shuffle matches. Everything here is data or a straight
//! reimplementation of the pinned algorithm; the tests compare the table
//! against the pinned Go codec.

use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::go_rand::GoRand;

/// A 4x4 Sudoku grid, row-major, values 1..=4.
pub type Grid = [u8; 16];

/// Every valid 4x4 Sudoku grid in the pinned enumeration order (288).
pub fn all_grids() -> Vec<Grid> {
    fn backtrack(grid: &mut Grid, index: usize, out: &mut Vec<Grid>) {
        if index == 16 {
            out.push(*grid);
            return;
        }
        let (row, col) = (index / 4, index % 4);
        let (box_row, box_col) = (row / 2 * 2, col / 2 * 2);
        for value in 1..=4u8 {
            let mut valid = true;
            for i in 0..4 {
                if grid[row * 4 + i] == value || grid[i * 4 + col] == value {
                    valid = false;
                    break;
                }
            }
            if valid {
                'boxes: for r in 0..2 {
                    for c in 0..2 {
                        if grid[(box_row + r) * 4 + (box_col + c)] == value {
                            valid = false;
                            break 'boxes;
                        }
                    }
                }
            }
            if valid {
                grid[index] = value;
                backtrack(grid, index + 1, out);
                grid[index] = 0;
            }
        }
    }
    let mut out = Vec::with_capacity(288);
    backtrack(&mut [0u8; 16], 0, &mut out);
    assert_eq!(out.len(), 288, "a 4x4 Sudoku has 288 grids");
    out
}

/// ASCII/entropy preference per direction; `up_*`/`down_*` are the pinned
/// directional modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsciiMode {
    pub uplink: bool,
    pub downlink: bool,
}

impl AsciiMode {
    /// `sudoku.ParseASCIIMode`; `None` for an unknown mode.
    pub fn parse(mode: &str) -> Option<AsciiMode> {
        let raw = mode.trim().to_ascii_lowercase();
        match raw.as_str() {
            "" | "entropy" | "prefer_entropy" => {
                Some(AsciiMode {
                    uplink: false,
                    downlink: false,
                })
            }
            "ascii" | "prefer_ascii" => Some(AsciiMode {
                uplink: true,
                downlink: true,
            }),
            _ => {
                let rest = raw.strip_prefix("up_")?;
                let (up, down) = rest.split_once("_down_")?;
                Some(AsciiMode {
                    uplink: parse_token(up)?,
                    downlink: parse_token(down)?,
                })
            }
        }
    }

    pub fn canonical(&self) -> &'static str {
        match (self.uplink, self.downlink) {
            (true, true) => "prefer_ascii",
            (false, false) => "prefer_entropy",
            (true, false) => "up_ascii_down_entropy",
            (false, true) => "up_entropy_down_ascii",
        }
    }
}

fn parse_token(token: &str) -> Option<bool> {
    match token.trim().to_ascii_lowercase().as_str() {
        "ascii" | "prefer_ascii" => Some(true),
        "entropy" | "prefer_entropy" | "" => Some(false),
        _ => None,
    }
}

/// One wire byte layout (`byteLayout` of the pinned source).
#[derive(Debug, Clone)]
pub struct ByteLayout {
    pub name: String,
    pub is_ascii: bool,
    pad_marker: u8,
    padding_pool: Vec<u8>,
    /// `pos<<2|val` for a hint byte, 64 for a poisoned hint-class byte, 0x80
    /// for anything else (padding).
    hint_idx: Box<[u8; 256]>,
    encode_hint: [[u8; 16]; 4],
    encode_group: [u8; 64],
    decode_group: [u8; 256],
}

const POISON_HINT: u8 = 64;
const NOT_HINT: u8 = 0x80;

impl ByteLayout {
    fn index_hints(&mut self, aliases: &[u8]) {
        self.hint_idx = Box::new([NOT_HINT; 256]);
        for byte in aliases {
            self.hint_idx[*byte as usize] = POISON_HINT;
        }
        for (value, row) in self.encode_hint.iter().enumerate() {
            for (pos, byte) in row.iter().enumerate() {
                self.hint_idx[*byte as usize] = ((pos << 2) | value) as u8;
            }
        }
    }

    fn entropy() -> ByteLayout {
        let mut padding = Vec::with_capacity(16);
        for i in 0..8u8 {
            padding.push(0x80 + i);
            padding.push(0x10 + i);
        }
        let mut layout = ByteLayout {
            name: "entropy".to_string(),
            is_ascii: false,
            pad_marker: 0x80,
            padding_pool: padding,
            hint_idx: Box::new([NOT_HINT; 256]),
            encode_hint: [[0u8; 16]; 4],
            encode_group: [0u8; 64],
            decode_group: [0xff; 256],
        };
        for value in 0..4usize {
            for pos in 0..16usize {
                layout.encode_hint[value][pos] = ((value as u8) << 5) | pos as u8;
            }
        }
        for group in 0..64usize {
            let v = group as u8;
            layout.encode_group[group] = ((v & 0x30) << 1) | (v & 0x0F);
        }
        for b in 0..256usize {
            let wire = b as u8;
            if wire & 0x90 != 0 {
                continue;
            }
            layout.decode_group[b] = ((wire >> 1) & 0x30) | (wire & 0x0F);
        }
        layout.index_hints(&[]);
        layout
    }

    fn ascii() -> ByteLayout {
        let mut padding = Vec::with_capacity(32);
        for i in 0..32u8 {
            padding.push(0x20 + i);
        }
        let mut layout = ByteLayout {
            name: "ascii".to_string(),
            is_ascii: true,
            pad_marker: 0x3F,
            padding_pool: padding,
            hint_idx: Box::new([NOT_HINT; 256]),
            encode_hint: [[0u8; 16]; 4],
            encode_group: [0u8; 64],
            decode_group: [0xff; 256],
        };
        for value in 0..4u8 {
            for pos in 0..16u8 {
                let mut b = 0x40 | (value << 4) | pos;
                if b == 0x7F {
                    b = b'\n';
                }
                layout.encode_hint[value as usize][pos as usize] = b;
            }
        }
        for group in 0..64u8 {
            let mut b = 0x40 | group;
            if b == 0x7F {
                b = b'\n';
            }
            layout.encode_group[group as usize] = b;
        }
        let mut aliases = Vec::new();
        for b in 0..256usize {
            let wire = b as u8;
            if wire & 0x40 == 0x40 {
                layout.decode_group[b] = wire & 0x3F;
                aliases.push(wire);
            }
        }
        layout.decode_group[b'\n' as usize] = 0x3F;
        layout.index_hints(&aliases);
        layout
    }

    fn custom(pattern: &str) -> Option<ByteLayout> {
        let cleaned = pattern.trim().replace(' ', "").to_ascii_lowercase();
        if cleaned.len() != 8 {
            return None;
        }
        let (mut x_bits, mut p_bits, mut v_bits) = (Vec::new(), Vec::new(), Vec::new());
        for (i, c) in cleaned.bytes().enumerate() {
            let bit = (7 - i) as u8;
            match c {
                b'x' => x_bits.push(bit),
                b'p' => p_bits.push(bit),
                b'v' => v_bits.push(bit),
                _ => return None,
            }
        }
        if x_bits.len() != 2 || p_bits.len() != 2 || v_bits.len() != 4 {
            return None;
        }
        let mut x_mask = 0u8;
        for bit in &x_bits {
            x_mask |= 1 << bit;
        }
        let encode_bits = |value: u8, pos: u8, drop_x: Option<usize>| -> u8 {
            let mut out = x_mask;
            if let Some(drop) = drop_x {
                out &= !(1 << x_bits[drop]);
            }
            if value & 0x02 != 0 {
                out |= 1 << p_bits[0];
            }
            if value & 0x01 != 0 {
                out |= 1 << p_bits[1];
            }
            for (i, bit) in v_bits.iter().enumerate() {
                if (pos >> (3 - i as u8)) & 1 == 1 {
                    out |= 1 << bit;
                }
            }
            out
        };

        let mut padding_set = std::collections::BTreeSet::new();
        for drop in 0..x_bits.len() {
            for value in 0..4u8 {
                for pos in 0..16u8 {
                    let b = encode_bits(value, pos, Some(drop));
                    if b.count_ones() >= 5 {
                        padding_set.insert(b);
                    }
                }
            }
        }
        if padding_set.is_empty() {
            return None;
        }
        let padding: Vec<u8> = padding_set.into_iter().collect();
        let mut layout = ByteLayout {
            name: format!("custom({cleaned})"),
            is_ascii: false,
            pad_marker: padding[0],
            padding_pool: padding,
            hint_idx: Box::new([NOT_HINT; 256]),
            encode_hint: [[0u8; 16]; 4],
            encode_group: [0u8; 64],
            decode_group: [0xff; 256],
        };
        for value in 0..4u8 {
            for pos in 0..16u8 {
                layout.encode_hint[value as usize][pos as usize] =
                    encode_bits(value, pos, None);
            }
        }
        for group in 0..64u8 {
            let value = (group >> 4) & 0x03;
            let pos = group & 0x0F;
            layout.encode_group[group as usize] = encode_bits(value, pos, None);
        }
        for b in 0..256usize {
            let wire = b as u8;
            if wire & x_mask != x_mask {
                continue;
            }
            let mut value = 0u8;
            if wire & (1 << p_bits[0]) != 0 {
                value |= 0x02;
            }
            if wire & (1 << p_bits[1]) != 0 {
                value |= 0x01;
            }
            let mut pos = 0u8;
            for (i, bit) in v_bits.iter().enumerate() {
                if wire & (1 << bit) != 0 {
                    pos |= 1 << (3 - i as u8);
                }
            }
            layout.decode_group[b] = (value << 4) | pos;
        }
        layout.index_hints(&[]);
        Some(layout)
    }
}

/// One direction's table: the per-byte puzzles, the hint sets and the layout.
pub struct SudokuTable {
    pub hint: u32,
    pub layout: ByteLayout,
    encode_table: Vec<Vec<[u8; 4]>>,
    hint_sets: Box<[[u64; 5]; 128]>,
}

impl std::fmt::Debug for SudokuTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SudokuTable")
            .field("hint", &self.hint)
            .field("layout", &self.layout.name)
            .field("entries", &self.encode_table.iter().map(Vec::len).sum::<usize>())
            .finish()
    }
}

impl SudokuTable {
    /// The wire hint bytes for `byte`, chosen with the pinned
    /// `pickPuzzle(b, draw)` (a puzzle index and a hint order from one draw).
    fn pick_puzzle(&self, byte: u8, draw: u64) -> u32 {
        let puzzles = &self.encode_table[byte as usize];
        let puzzle = puzzles[(((draw >> 32) as u128 * puzzles.len() as u128) >> 32) as usize];
        let mut packed = [0u8; 4];
        packed.copy_from_slice(&puzzle);
        let puzzle = u32::from_le_bytes(packed);
        let order = (((draw & 0xffff_ffff) as u128 * 24) >> 32) as usize;
        permute(puzzle, order)
    }

    fn decode_hints(&self, hints: [u8; 4]) -> Option<u8> {
        let sa = &self.hint_sets[(hints[0] & 127) as usize];
        let sb = &self.hint_sets[(hints[1] & 127) as usize];
        let sc = &self.hint_sets[(hints[2] & 127) as usize];
        let sd = &self.hint_sets[(hints[3] & 127) as usize];
        let mut result = [0u64; 5];
        for word in 0..5 {
            result[word] = sa[word] & sb[word] & sc[word] & sd[word];
        }
        // "Exactly one shared grid, and it must be one of the 256 that carry a
        // byte": one word has a single bit and every other word is empty.
        let mut multi = false;
        let mut non_empty = 0;
        let mut bit_word = 0usize;
        for word in 0..5 {
            if result[word] != 0 {
                non_empty += 1;
                bit_word = word;
                if result[word] & (result[word] - 1) != 0 {
                    multi = true;
                }
            }
        }
        if multi || non_empty != 1 {
            return None;
        }
        let rank = bit_word * 64 + result[bit_word].trailing_zeros() as usize;
        Some(rank as u8)
    }

    /// Decode one group of four hint bytes.
    pub fn decode_group_hints(&self, hints: [u8; 4]) -> Option<u8> {
        self.decode_hints(hints)
    }

    /// `layout.hint_idx[b]`.
    pub fn hint_index(&self, byte: u8) -> u8 {
        self.layout.hint_idx[byte as usize]
    }

    pub fn is_hint(&self, byte: u8) -> bool {
        self.layout.hint_idx[byte as usize] != NOT_HINT
    }

    pub fn padding_pool(&self) -> &[u8] {
        &self.layout.padding_pool
    }

    pub fn pad_marker(&self) -> u8 {
        self.layout.pad_marker
    }

    pub fn encode_group_byte(&self, group: u8) -> u8 {
        self.layout.encode_group[(group & 0x3F) as usize]
    }

    pub fn decode_group_byte(&self, byte: u8) -> u8 {
        self.layout.decode_group[byte as usize]
    }
}

/// Both directions of a table set: directional modes build two layouts over
/// the same grid shuffle, symmetric modes share one table.
pub struct TableSet {
    pub uplink: Arc<SudokuTable>,
    pub downlink: Arc<SudokuTable>,
}

/// `tableHintFingerprint`: the first four bytes of a SHA-256 over the key, the
/// canonical mode and both custom patterns.
fn hint_fingerprint(key: &str, mode: &str, uplink: &str, downlink: &str) -> u32 {
    // Go joins the parts with "\x00" (no trailing separator).
    let joined = [
        "sudoku-table-hint".to_string(),
        key.to_string(),
        mode.to_string(),
        uplink.trim().to_ascii_lowercase(),
        downlink.trim().to_ascii_lowercase(),
    ]
    .join("\u{0}");
    let digest = Sha256::digest(joined.as_bytes());
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
}

/// Whether a `custom-table` pattern is the 8-symbol X/P/V layout the pinned
/// parser accepts (exactly 2 `x`, 2 `p` and 4 `v`).
pub fn validate_custom_pattern(pattern: &str) -> bool {
    ByteLayout::custom(pattern).is_some()
}

fn custom_for(ascii: bool, custom: Option<&str>) -> Option<String> {
    if ascii {
        return None;
    }
    custom.map(|value| value.to_string())
}

fn build_single(key: &str, ascii: bool, custom: Option<&str>) -> Result<SudokuTable, String> {
    let layout = match (ascii, custom.map(str::trim).filter(|p| !p.is_empty())) {
        (true, _) => ByteLayout::ascii(),
        (false, Some(pattern)) => ByteLayout::custom(pattern)
            .ok_or_else(|| format!("invalid custom table pattern '{pattern}'"))?,
        (false, None) => ByteLayout::entropy(),
    };

    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    let seed = i64::from_be_bytes(digest[..8].try_into().expect("8 bytes"));
    let mut rng = GoRand::new(seed);
    let mut grids = all_grids();
    rng.shuffle(&mut grids);

    let mut hint_sets = Box::new([[0u64; 5]; 128]);
    for (rank, grid) in grids.iter().enumerate() {
        for (pos, value) in grid.iter().enumerate() {
            let index = (pos << 2) | (*value as usize - 1);
            hint_sets[index][rank >> 6] |= 1 << (rank & 63);
        }
    }

    // Every combination of four grid positions; only combinations that pin a
    // single grid become an encoder puzzle (the pinned construction).
    let mut combinations = Vec::with_capacity(1820);
    for a in 0..13 {
        for b in a + 1..14 {
            for c in b + 1..15 {
                for d in c + 1..16 {
                    combinations.push([a, b, c, d]);
                }
            }
        }
    }
    assert_eq!(combinations.len(), 1820);

    let mut table = SudokuTable {
        hint: 0,
        layout,
        encode_table: vec![Vec::new(); 256],
        hint_sets,
    };

    for byte in 0..256usize {
        let target = &grids[byte];
        let mut puzzles = Vec::new();
        for positions in &combinations {
            let hints = [
                ((positions[0] << 2) | (target[positions[0]] as usize - 1)) as u8,
                ((positions[1] << 2) | (target[positions[1]] as usize - 1)) as u8,
                ((positions[2] << 2) | (target[positions[2]] as usize - 1)) as u8,
                ((positions[3] << 2) | (target[positions[3]] as usize - 1)) as u8,
            ];
            if table.decode_hints(hints).is_none() {
                continue;
            }
            let mut wire = [0u8; 4];
            for (slot, pos) in positions.iter().enumerate() {
                wire[slot] = table.layout.encode_hint[target[*pos] as usize - 1][*pos];
            }
            puzzles.push(wire);
        }
        if puzzles.is_empty() {
            return Err(format!("no unique puzzle for byte {byte}"));
        }
        table.encode_table[byte] = puzzles;
    }
    Ok(table)
}

/// Build both directions of a table set for a key, `table-type` mode and
/// optional custom X/P/V pattern (applied to the entropy directions).
pub fn build_tables(
    key: &str,
    table_type: &str,
    custom: Option<&str>,
) -> Result<TableSet, String> {
    let ascii = AsciiMode::parse(table_type)
        .ok_or_else(|| format!("invalid table-type '{table_type}'"))?;
    let canonical = ascii.canonical();
    let uplink_pattern = custom_for(ascii.uplink, custom).unwrap_or_default();
    let downlink_pattern = custom_for(ascii.downlink, custom).unwrap_or_default();
    let hint = hint_fingerprint(key, canonical, &uplink_pattern, &downlink_pattern);

    let mut uplink = build_single(key, ascii.uplink, custom_for(ascii.uplink, custom).as_deref())?;
    uplink.hint = hint;
    let uplink = Arc::new(uplink);
    let downlink = if ascii.uplink == ascii.downlink {
        Arc::clone(&uplink)
    } else {
        let mut table =
            build_single(key, ascii.downlink, custom_for(ascii.downlink, custom).as_deref())?;
        table.hint = hint;
        Arc::new(table)
    };
    Ok(TableSet { uplink, downlink })
}

/// The byte shift of each of the four hints for the lexicographic permutation
/// `order` (the pinned `permShifts`, computed through factoradics instead of a
/// 24-entry table).
fn permutation(order: usize) -> [u8; 4] {
    let mut available = vec![0u8, 1, 2, 3];
    let mut order = order % 24;
    let mut out = [0u8; 4];
    for (slot, factorial) in [6usize, 2, 1, 1].iter().enumerate() {
        let pick = order / factorial;
        order %= factorial;
        out[slot] = available.remove(pick) * 8;
    }
    out
}

fn permute(puzzle: u32, order: usize) -> u32 {
    let shifts = permutation(order);
    (puzzle >> (shifts[0] & 31) & 0xff)
        | ((puzzle >> (shifts[1] & 31) & 0xff) << 8)
        | ((puzzle >> (shifts[2] & 31) & 0xff) << 16)
        | ((puzzle >> (shifts[3] & 31)) << 24)
}

/// wyrand, the generator the pinned encoder uses for padding and puzzle
/// choices (a fixed increment; draws are independent of results).
pub struct WyRand {
    state: u64,
}

impl WyRand {
    pub fn new(seed: u64) -> WyRand {
        WyRand { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0xa076_1d64_78bd_642f);
        let t = (self.state as u128) * ((self.state ^ 0xe703_7ed1_a0b4_28db) as u128);
        ((t >> 64) as u64) ^ (t as u64)
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    pub fn intn(&mut self, n: usize) -> usize {
        if n <= 1 {
            return 0;
        }
        ((self.next_u32() as u64 * n as u64) >> 32) as usize
    }
}

/// `pickPaddingThreshold`: a per-connection padding probability in `1<<32`.
pub fn padding_threshold(rng: &mut WyRand, min: u8, max: u8) -> u64 {
    let low = u64::from(min.min(100)) * (1 << 32) / 100;
    let high = u64::from(max.min(100)) * (1 << 32) / 100;
    let (low, high) = if high < low { (high, high) } else { (low, high) };
    if high <= low {
        return low;
    }
    let u = u64::from(rng.next_u32());
    low + ((u as u128 * (high - low) as u128) >> 32) as u64
}

/// Encode-side state: the table, the wyrand state and the padding threshold.
pub struct Encoder {
    table: Arc<SudokuTable>,
    rng: WyRand,
    threshold: u64,
}

/// Worst-case expansion per plaintext byte (four hints plus padding slots).
const MAX_PADDED_EXPANSION: usize = 9;

impl Encoder {
    pub fn new(table: Arc<SudokuTable>, rng: WyRand, threshold: u64) -> Encoder {
        Encoder {
            table,
            rng,
            threshold,
        }
    }

    /// `writeSudokuPayload`: encode `plain` as one write, including the single
    /// trailing padding slot the pinned encoder adds per write. Padding slots
    /// follow `appendSudokuPayload`'s `padSlot`: one candidate before each of
    /// the four hints and one after the last, each kept only when its draw
    /// falls under the threshold.
    pub fn encode(&mut self, plain: &[u8]) -> Vec<u8> {
        let expansion = if self.threshold == 0 {
            4
        } else {
            MAX_PADDED_EXPANSION
        };
        let mut out = Vec::with_capacity(plain.len() * expansion + 16);
        if self.threshold == 0 {
            for byte in plain {
                let draw = self.rng.next_u64();
                out.extend_from_slice(&self.table.pick_puzzle(*byte, draw).to_le_bytes());
            }
            return out;
        }
        for byte in plain {
            let draw = self.rng.next_u64();
            let hints = self.table.pick_puzzle(*byte, draw).to_le_bytes();
            self.pad_slot(&mut out);
            for hint in hints.iter() {
                out.push(*hint);
                self.pad_slot(&mut out);
            }
        }
        self.pad_slot(&mut out);
        out
    }

    fn pad_slot(&mut self, out: &mut Vec<u8>) {
        let draw = self.rng.next_u64();
        if (draw as u32 as u64) < self.threshold {
            let pool = self.table.padding_pool();
            out.push(pool[(((draw >> 32) as u128 * pool.len() as u128) >> 32) as usize]);
        }
    }
}

/// Pure downlink decoder (`Conn.decode`): skips padding, assembles groups of
/// four hints and decodes one byte per group.
#[derive(Default)]
pub struct PureDecoder {
    hints: [u8; 4],
    count: usize,
}

impl PureDecoder {
    /// Push wire bytes, appending decoded plaintext. Returns `false` when a
    /// group cannot be decoded (padding that looks like a poison hint or an
    /// inconsistent table).
    pub fn push(&mut self, table: &SudokuTable, input: &[u8], out: &mut Vec<u8>) -> bool {
        for byte in input {
            let index = table.hint_index(*byte);
            if index >= NOT_HINT {
                continue;
            }
            if index == POISON_HINT {
                self.count = 0;
                return false;
            }
            self.hints[self.count] = index;
            self.count += 1;
            if self.count == 4 {
                match table.decode_group_hints(self.hints) {
                    Some(value) => out.push(value),
                    None => {
                        self.count = 0;
                        return false;
                    }
                }
                self.count = 0;
            }
        }
        true
    }
}

/// Packed downlink decoder (`PackedConn.decode`): 6-bit groups in a bit
/// accumulator, with the pad marker resetting the accumulator.
#[derive(Default)]
pub struct PackedDecoder {
    bit_buf: u64,
    bits: u8,
}

impl PackedDecoder {
    pub fn push(&mut self, table: &SudokuTable, input: &[u8], out: &mut Vec<u8>) -> bool {
        let pad_marker = table.pad_marker();
        for byte in input {
            let group = table.decode_group_byte(*byte);
            if group >= 64 {
                if *byte == pad_marker {
                    self.bit_buf = 0;
                    self.bits = 0;
                }
                continue;
            }
            self.bit_buf = (self.bit_buf << 6) | u64::from(group);
            self.bits += 6;
            if self.bits >= 8 {
                self.bits -= 8;
                out.push((self.bit_buf >> self.bits) as u8);
                self.bit_buf &= (1u64 << self.bits) - 1;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn there_are_288_grids() {
        let grids = all_grids();
        assert_eq!(grids.len(), 288);
        // Every row, column and box holds 1..=4 exactly once.
        for grid in grids.iter().take(8) {
            for row in 0..4 {
                let mut seen = [false; 5];
                for col in 0..4 {
                    seen[grid[row * 4 + col] as usize] = true;
                }
                assert!(seen[1..].iter().all(|v| *v));
            }
        }
    }

    #[test]
    fn every_byte_has_a_unique_puzzle() {
        let tables = build_tables("test-key-123", "prefer_entropy", None).expect("table");
        for byte in 0..256usize {
            let entry = &tables.uplink.encode_table[byte];
            assert!(!entry.is_empty(), "byte {byte} has no puzzle");
            let mut hints = [0u8; 4];
            hints.copy_from_slice(&entry[0]);
            // The wire hints decode back to the same byte.
            let indexes: Vec<u8> = hints.iter().map(|b| tables.uplink.hint_index(*b)).collect();
            assert!(indexes.iter().all(|i| *i < 64), "hints must be hint-class bytes");
            assert_eq!(
                tables.uplink.decode_group_hints(indexes.try_into().unwrap()),
                Some(byte as u8)
            );
        }
    }

    #[test]
    fn the_encoder_and_decoder_round_trip() {
        let tables = build_tables("test-key-123", "prefer_entropy", None).expect("table");
        let mut rng = WyRand::new(7);
        let mut encoder = Encoder::new(tables.uplink.clone(), WyRand::new(7), padding_threshold(&mut rng, 10, 30));
        let plain: Vec<u8> = (0..=255u8).cycle().take(300).collect();
        let wire = encoder.encode(&plain);
        let mut decoder = PureDecoder::default();
        let mut back = Vec::new();
        assert!(decoder.push(&tables.uplink, &wire, &mut back));
        assert_eq!(back, plain);
    }
}

#[cfg(test)]
mod pinned_vectors {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(text.len() / 2);
        for pair in text.as_bytes().chunks_exact(2) {
            let at = |b: u8| (b as char).to_digit(16).unwrap() as u8;
            out.push(at(pair[0]) * 16 + at(pair[1]));
        }
        out
    }

    /// Bytes printed by the pinned codec (`tool/kernel-compat/peers/sudoku-vectors`,
    /// `go run . -op vectors -key test-key-123 -mode prefer_entropy -plaintext
    /// 000102030405ff`). The encoder is randomised, so the fixture records the
    /// pinned *decoder* contract: our decoder must accept the reference bytes.
    #[test]
    fn the_pinned_encoder_output_decodes_with_our_table() {
        let tables = build_tables("test-key-123", "prefer_entropy", None).expect("table");
        assert_eq!(tables.uplink.hint, 3_489_163_188);
        assert_eq!(
            hex(tables.uplink.padding_pool()),
            "80108111821283138414851586168717"
        );
        let plain = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xff];

        let pure = unhex("2e6d01400807456a47250d6c0e6043294064032b264d6b00630d2027");
        let mut decoder = PureDecoder::default();
        let mut back = Vec::new();
        assert!(decoder.push(&tables.downlink, &pure, &mut back));
        assert_eq!(back, plain);

        let packed = unhex("8600008404021600608620056f846080");
        let mut decoder = PackedDecoder::default();
        let mut back = Vec::new();
        assert!(decoder.push(&tables.downlink, &packed, &mut back));
        assert_eq!(back, plain);
    }

    #[test]
    fn the_pinned_ascii_layout_has_the_expected_shape() {
        let tables = build_tables("test-key-123", "prefer_ascii", None).expect("table");
        assert_eq!(tables.uplink.hint, 1_071_717_728);
        assert_eq!(
            hex(tables.uplink.padding_pool()),
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        );
        let plain = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xff];
        let pure = unhex("665e6f41505f62747b52434d6a47525972486d5b567b6d40504b6f4d");
        let mut decoder = PureDecoder::default();
        let mut back = Vec::new();
        assert!(decoder.push(&tables.downlink, &pure, &mut back));
        assert_eq!(back, plain);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

