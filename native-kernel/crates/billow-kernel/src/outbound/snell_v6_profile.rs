// SPDX-License-Identifier: GPL-3.0-only

//! Snell v6's PSK-derived record profile, based on Mihomo v1.19.34
//! (GPL-3.0), transport/snell/v6_profile.go.

use blake2::{digest::consts::U32, Blake2b, Digest};

const GAMMA: u64 = 0x9e3779b97f4a7c15;
const DOMAIN_MULTIPLIER: u64 = 0xd6e8feb86659fd93;
const COEF_A: u64 = 0xe7037ed1a0b428db;
const COEF_B: u64 = 0x589965cc75374cc3;
const ADD_A: u64 = 0x8f3907f7b2b80c35;
const ADD_B: u64 = 0x33a213ec50ffe2e9;
const HANDSHAKE_DOMAIN: u32 = 0x7053;
const MIX_HANDSHAKE_DOMAIN: u32 = 0x51a7;
const MAX_EXTRA_PADDING: usize = 0x02da;
const SEED: [u8; 24] = [
    0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94, 0x33, 0x18, 0xc0, 0x6e,
    0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac,
];
const ROTATIONS: [[u8; 16]; 8] = [
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ],
    [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80,
    ],
    [
        0x03, 0x05, 0x09, 0x11, 0x21, 0x41, 0x81, 0x06, 0x0a, 0x12, 0x22, 0x42, 0x82, 0x0c, 0x18,
        0x24,
    ],
    [
        0x07, 0x0b, 0x13, 0x23, 0x43, 0x83, 0x0d, 0x19, 0x31, 0x61, 0xc1, 0x0e, 0x1c, 0x38, 0x70,
        0xe0,
    ],
    [
        0x0f, 0x17, 0x27, 0x47, 0x87, 0x1b, 0x33, 0x63, 0xc3, 0x1d, 0x39, 0x71, 0xe1, 0x3c, 0x78,
        0xf0,
    ],
    [
        0xf8, 0xf4, 0xec, 0xdc, 0xbc, 0x7c, 0xf2, 0xe6, 0xce, 0x9e, 0x3e, 0xf1, 0xe3, 0xc7, 0x8f,
        0x1f,
    ],
    [
        0xfc, 0xfa, 0xf6, 0xee, 0xde, 0xbe, 0x7e, 0xf9, 0xf5, 0xed, 0xdd, 0xbd, 0x7d, 0xf3, 0xe7,
        0xdb,
    ],
    [
        0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f, 0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf,
        0x7f,
    ],
];

fn split_mix(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
    value ^ (value >> 31)
}

fn fold(value: u64) -> u32 {
    (value ^ (value >> 32)) as u32
}

fn prf(namespace: u64, label: u32, first: u32, second: u32) -> u32 {
    fold(split_mix(
        namespace
            ^ u64::from(label).wrapping_mul(GAMMA)
            ^ u64::from(first).wrapping_mul(COEF_A).wrapping_add(ADD_A)
            ^ u64::from(second).wrapping_mul(COEF_B).wrapping_add(ADD_B),
    ))
}

fn pick(value: u32, lo: usize, hi: usize) -> usize {
    lo + value as usize % (hi - lo + 1)
}

#[derive(Clone)]
struct Namespaces([u64; 7]);

impl Namespaces {
    fn new(psk: &[u8]) -> Self {
        let secret = Blake2b::<U32>::new()
            .chain_update(SEED)
            .chain_update(psk)
            .finalize();
        let word =
            |offset: usize| u64::from_le_bytes(secret[offset..offset + 8].try_into().unwrap());
        let common = word(0)
            ^ word(8).wrapping_add(GAMMA)
            ^ word(16).rotate_left(17)
            ^ word(24).rotate_right(11);
        let derive = |label: u64, seed: u64| {
            split_mix(
                common
                    ^ label.wrapping_mul(DOMAIN_MULTIPLIER)
                    ^ seed.wrapping_add(0xa0761d6478bd642f),
            )
        };
        Self([
            derive(5, 0xb46c2e7d9a1538f1),
            derive(0, 0x5d9217c083e64ab9),
            derive(2, 0xa71f0c54d8396e2b),
            derive(3, 0x3e8a91b52740f6cd),
            derive(16, 0xc9f4260b7d1e835a),
            derive(21, 0x62d0b5e19c4a783f),
            derive(28, 0x917b3c48e6a205d4),
        ])
    }

    fn namespace(&self, label: u32) -> u64 {
        self.0[match label {
            0 | 1 | 14 | 15 | 33 | 34 => 1, // record prefix and padding
            2 => 2,                         // padding motif
            3 | 16..=20 => 4,               // ciphertext interleave
            21..=26 | 38 | 39 => 5,         // chunk schedule
            28..=32 | 35..=37 => 6,         // target frame sizes
            _ => 0,
        }]
    }

    fn value(&self, label: u32, seq: u32, domain: u32) -> u32 {
        prf(self.namespace(label), label, seq, domain)
    }

    fn parameter(&self, label: u32, domain: u32, lo: usize, hi: usize) -> usize {
        pick(self.value(label, 0, domain), lo, hi)
    }

    fn fill(&self, label: u32, seq: u32, buffer: &mut [u8]) {
        let mut seed = self.namespace(label)
            ^ u64::from(seq)
                .wrapping_mul(DOMAIN_MULTIPLIER)
                .wrapping_add(0xb57de1f3f82cb33f)
            ^ u64::from(label).wrapping_mul(0xa24baed4963ee407)
            ^ (buffer.len() as u64)
                .wrapping_mul(0x165667b19e3779f9)
                .wrapping_add(0x0d4cd3e7b14a36d7);
        for chunk in buffer.chunks_mut(8) {
            seed = seed.wrapping_add(GAMMA);
            chunk.copy_from_slice(&split_mix(seed).to_le_bytes()[..chunk.len()]);
        }
    }
}

pub(super) struct Profile {
    ns: Namespaces,
    pub salt_block_len: usize,
    salt_permutation: [usize; 16],
    salt_mask: [u8; 16],
    prefix: (usize, usize),
    padding: (usize, usize),
    early_records: u32,
    pad_interval: u32,
    small_limit: usize,
    mix_mode: u32,
    mix_rounds: u32,
    mix_stride: usize,
    mix_offset: usize,
    mix_block: usize,
    padding_generator: u32,
    bit_percent: (usize, usize),
    generator_params: [usize; 6],
    chunk_policy: u32,
    pub chunk_initial: usize,
    chunk_max: usize,
    chunk_step: usize,
    chunk_jitter: usize,
    chunk_buckets: [usize; 8],
    first_record_cap: usize,
    pub idle_reset_sec: u64,
    write_policy: u32,
    write_first: u32,
    write_buckets: [usize; 8],
    write_sequence: [usize; 8],
    write_jitter: usize,
    write_jitter_percent: usize,
}

impl Profile {
    pub fn new(psk: &[u8]) -> Self {
        let ns = Namespaces::new(psk);
        let parameter = |label, lo, hi| ns.parameter(label, 0, lo, hi);
        let prefix_for = |domain, lo, hi| {
            let min = ns.parameter(14, domain, lo, hi);
            let max = (min + ns.parameter(15, domain, 0x10, 0xa0)).min(0x80);
            (min.min(max), max)
        };
        let (salt_min, salt_max) = prefix_for(HANDSHAKE_DOMAIN, 0x10, 0x60);
        let salt_block_len = 16 + ns.parameter(33, HANDSHAKE_DOMAIN, salt_min, salt_max);
        let salt_stride = ns.parameter(18, MIX_HANDSHAKE_DOMAIN, 0x11, 0xfb) as u8;
        let salt_rounds = ns.parameter(17, MIX_HANDSHAKE_DOMAIN, 1, 4) as u32;
        let salt = ns.0[3];
        let mut permutation: Vec<usize> = (0..salt_block_len).collect();
        for round in 0..salt_rounds {
            let domain = u64::from(MIX_HANDSHAKE_DOMAIN + round)
                .wrapping_mul(COEF_A)
                .wrapping_add(ADD_A);
            for i in 0..salt_block_len {
                let value = (i as u64).wrapping_mul(COEF_B).wrapping_add(ADD_B)
                    ^ salt
                    ^ 0xdaa66d2c7ddf743f
                    ^ domain;
                let j = i + fold(split_mix(value)) as usize % (salt_block_len - i);
                permutation.swap(i, j);
            }
        }
        let pad_min = parameter(7, 0x18, 0xa0);
        let chunk_initial = parameter(22, 0x200, 0x05b4);
        let chunk_max = parameter(23, 0x2000, 0x3fff);
        Self {
            salt_block_len,
            salt_permutation: permutation[..16].try_into().unwrap(),
            salt_mask: std::array::from_fn(|i| {
                (i as u8).wrapping_mul(salt_stride)
                    ^ prf(salt, 2, MIX_HANDSHAKE_DOMAIN, i as u32) as u8
            }),
            prefix: prefix_for(0, 0x08, 0x50),
            padding: (
                pad_min,
                (pad_min + parameter(8, 0xa0, 0x3c0)).min(MAX_EXTRA_PADDING),
            ),
            early_records: parameter(9, 2, 8) as u32,
            pad_interval: parameter(10, 2, 0x0b) as u32,
            small_limit: parameter(11, 0x60, 0x300),
            mix_mode: ns.value(16, 0, 0) % 3,
            mix_rounds: parameter(17, 1, 3) as u32,
            mix_stride: parameter(18, 2, 13),
            mix_offset: parameter(19, 0, 15),
            mix_block: parameter(20, 8, 0x40),
            padding_generator: ns.value(6, 0, 0) & 3,
            bit_percent: (parameter(12, 0x18, 0x29), parameter(13, 0x3a, 0x4c)),
            generator_params: [
                ns.parameter(6, 1, 0x18, 0x80),
                ns.parameter(6, 2, 0x10, 0x60),
                ns.parameter(6, 3, 0x10, 0x60),
                ns.parameter(6, 4, 0, 9),
                ns.parameter(6, 5, 1, 8),
                ns.parameter(6, 6, 7, 0x17),
            ],
            chunk_policy: ns.value(21, 0, 0) % 3,
            chunk_initial,
            chunk_max,
            chunk_step: parameter(24, 0x400, 0x1000).min(0x0b68),
            chunk_jitter: parameter(25, 0x10, 0xc0).min(0x0b6),
            chunk_buckets: std::array::from_fn(|i| ns.parameter(26, i as u32, 0x1000, chunk_max)),
            first_record_cap: ns.parameter(22, 0xf17c, 0x100, 0x300).min(chunk_initial),
            idle_reset_sec: parameter(27, 0x0c, 0x5a) as u64,
            write_policy: ns.value(28, 0, 0) % 3,
            write_first: parameter(29, 4, 8) as u32,
            write_buckets: std::array::from_fn(|i| ns.parameter(30, i as u32, 0x140, 0x05b4)),
            write_sequence: std::array::from_fn(|i| ns.parameter(31, i as u32, 0x168, 0x05b4)),
            write_jitter: parameter(32, 0x08, 0x60),
            write_jitter_percent: ns.parameter(28, 0x504c, 8, 0x30),
            ns,
        }
    }

    pub fn prefix_len(&self, seq: u32) -> usize {
        pick(self.ns.value(33, seq, 0), self.prefix.0, self.prefix.1)
    }

    pub fn salt_block(&self, salt: &[u8; 16]) -> Vec<u8> {
        let mut block = vec![0; self.salt_block_len];
        self.fill_padding(u32::MAX, &mut block);
        for i in 0..16 {
            block[self.salt_permutation[i]] = salt[i] ^ self.salt_mask[i];
        }
        block
    }

    pub fn extract_salt(&self, block: &[u8]) -> [u8; 16] {
        std::array::from_fn(|i| block[self.salt_permutation[i]] ^ self.salt_mask[i])
    }

    pub fn payload_limit(&self, seq: u32, chunk: &mut usize) -> usize {
        let size = match self.chunk_policy {
            1 => self.chunk_buckets[self.ns.value(38, seq, *chunk as u32) as usize % 8],
            2 => {
                let value = self.ns.value(39, seq, *chunk as u32);
                (*chunk + value as usize % (2 * self.chunk_jitter + 1))
                    .saturating_sub(self.chunk_jitter)
            }
            _ => *chunk,
        };
        *chunk = (*chunk + self.chunk_step).min(self.chunk_max);
        size.clamp(
            0x40,
            if seq == 0 {
                self.first_record_cap
            } else {
                self.chunk_max
            },
        )
    }

    pub fn padding_len(&self, seq: u32, payload: usize) -> usize {
        let mut padding = 0;
        if seq < self.early_records
            || (payload != 0 && payload <= self.small_limit)
            || seq % self.pad_interval == 0
        {
            padding = pick(
                self.ns.value(34, seq, payload as u32),
                self.padding.0,
                self.padding.1,
            );
        }
        let prefix = self.prefix_len(seq);
        let salt = if seq == 0 { self.salt_block_len } else { 0 };
        let tag = if payload == 0 { 0 } else { 16 };
        let frame_len = salt + prefix + 23 + padding + payload + tag;
        padding += self
            .write_target(seq, frame_len)
            .saturating_sub(frame_len)
            .min(MAX_EXTRA_PADDING);
        if seq == 0 {
            let threshold =
                (((payload + if payload == 0 { 0x27 } else { 0x37 }) * 25 + 0x4a) / 75).max(0xc0);
            padding = padding.max(
                threshold
                    .saturating_sub(salt - 16 + prefix)
                    .min(self.padding.1 + MAX_EXTRA_PADDING),
            );
        }
        padding
    }

    fn write_target(&self, seq: u32, frame_len: usize) -> usize {
        if frame_len > 0x05b3 {
            return frame_len.min(0xffff);
        }
        let mut target = if seq < self.write_first {
            self.write_sequence[seq as usize]
        } else {
            self.write_buckets[self.ns.value(35, seq, frame_len as u32) as usize % 8]
        };
        if self.write_policy == 2 {
            let raw = self.ns.value(36, seq, 0) as usize;
            target = (target + raw % (self.write_jitter * 2 + 1))
                .saturating_sub(self.write_jitter)
                .max(1);
        }
        let spread = MAX_EXTRA_PADDING.min(frame_len * self.write_jitter_percent / 100);
        if self.ns.value(35, seq, spread as u32) & 1 == 0 {
            target = (target + spread).min(0xffff);
        } else if target > spread / 2 {
            target -= spread / 2;
        }
        while frame_len > target {
            let next = self.write_buckets[self.ns.value(37, seq, target as u32) as usize % 8];
            target = if next <= target {
                (target + self.padding.1).min(0xffff)
            } else {
                next
            };
        }
        target
    }

    pub fn fill_padding(&self, seq: u32, out: &mut [u8]) {
        self.ns.fill(0, seq, out);
        let [g1, g2, g3, g4, g5, g6] = self.generator_params;
        match self.padding_generator {
            0 => {
                let scaled = pick(
                    self.ns.value(1, seq, 0),
                    self.bit_percent.0,
                    self.bit_percent.1,
                ) * 8;
                let row = if scaled <= 0x31 {
                    1
                } else if scaled <= 0x02ed {
                    (scaled + 0x32) / 100
                } else {
                    7
                };
                for (i, byte) in out.iter_mut().enumerate() {
                    let raw = byte.wrapping_add(i as u8);
                    let index = usize::from((raw ^ *byte) & 0x0f);
                    *byte = ROTATIONS[row.max(1)][index]
                        .rotate_left(u32::from((raw ^ (*byte >> 4)) & 7));
                }
            }
            1 => {
                for (i, byte) in out.iter_mut().enumerate() {
                    let bucket = usize::from(*byte) % (g1 + g2 + g3);
                    let (value, lo, hi) = if bucket < g1 {
                        (byte.wrapping_add(i as u8), 0x20, 0x7e)
                    } else if bucket < g1 + g2 {
                        (*byte ^ i as u8, 0x80, 0xbf)
                    } else {
                        (byte.wrapping_add((i * 7) as u8), 0xc0, 0xff)
                    };
                    *byte = pick(u32::from(value), lo, hi) as u8;
                }
            }
            2 => {
                for (i, byte) in out.iter_mut().enumerate() {
                    let low = (usize::from(*byte & 0x0f) + g4 + (i & 1)) % 10;
                    let high = (usize::from(*byte) + ((i & 3) << 4) + 0x30) & 0xf0;
                    *byte = (high | low) as u8;
                }
            }
            _ => {
                let mut motif = [0; 32];
                self.ns.fill(2, seq, &mut motif);
                for (i, byte) in out.iter_mut().enumerate() {
                    let offset = i % g6;
                    if offset < g6 - 3 {
                        *byte = ((g5 + 3) * i) as u8 ^ motif[i % (g5 * 4)];
                    } else if offset < g6 - 1 {
                        *byte = 0x30 | (*byte % 10);
                    }
                }
            }
        }
    }

    pub fn mix(&self, seq: u32, padding: &mut [u8], payload: &mut [u8]) {
        let count = padding.len().min(payload.len());
        for round in 0..self.mix_rounds {
            if self.mix_mode == 1 {
                let size = self.mix_block;
                for start in ((round as usize & 1) * size..count).step_by(size * 2) {
                    if start + size <= count {
                        padding[start..start + size]
                            .swap_with_slice(&mut payload[start..start + size]);
                    }
                }
            } else {
                let stride = self.mix_stride + (round % 3) as usize;
                let offset = if self.mix_mode == 2 {
                    self.ns.value(3, seq, round) as usize
                } else {
                    0
                };
                for index in ((self.mix_offset + offset % stride) % stride..count).step_by(stride) {
                    std::mem::swap(&mut padding[index], &mut payload[index]);
                }
            }
        }
    }
}
