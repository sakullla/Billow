//! One-shot BLAKE3 (RFC 7693-style 32-bit compression, BLAKE3 tree mode).
//!
//! TUIC v4 authenticates with `BLAKE3(token)` (`GenTKN` in the pinned
//! `transport/tuic/v4/protocol.go`). The workspace has no BLAKE3 crate in the
//! offline cache, so this module implements the unkeyed hash for the one shape
//! the outbound needs: `Sum256` over an arbitrary byte string, returning the
//! first 32 bytes of the root output. Multi-chunk input is supported with the
//! standard left-subtree split, so a long token hashes exactly like the pinned
//! Go implementation.
//!
//! Constants and the round function follow the BLAKE3 specification:
//! - IV = the BLAKE2s IV;
//! - flags `CHUNK_START=1`, `CHUNK_END=2`, `PARENT=4`, `ROOT=8`;
//! - message permutation `[2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8]`.

const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;

const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[inline(always)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    // Columns.
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    // Diagonals.
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

fn permute(m: &mut [u32; 16]) {
    let mut permuted = [0u32; 16];
    for (index, slot) in permuted.iter_mut().enumerate() {
        *slot = m[MSG_PERMUTATION[index]];
    }
    *m = permuted;
}

/// The BLAKE3 compression function. Returns the full 16-word output; the
/// caller takes the first 8 words for a chaining value or the root bytes.
fn compress(
    cv: &[u32; 8],
    block: &[u8; BLOCK_LEN],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut m = [0u32; 16];
    for (index, word) in m.iter_mut().enumerate() {
        let offset = index * 4;
        *word = u32::from_le_bytes([
            block[offset],
            block[offset + 1],
            block[offset + 2],
            block[offset + 3],
        ]);
    }
    let mut state = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    for _ in 0..7 {
        round(&mut state, &m);
        permute(&mut m);
    }
    let mut out = [0u32; 16];
    for index in 0..8 {
        out[index] = state[index] ^ state[index + 8];
        out[index + 8] = state[index + 8] ^ cv[index];
    }
    out
}

fn chaining_value(output: &[u32; 16]) -> [u32; 8] {
    let mut cv = [0u32; 8];
    cv.copy_from_slice(&output[..8]);
    cv
}

/// Hash one chunk. `blocks` is the chunk's bytes (≤ 1024). When `root` is set
/// the returned words are the first 8 root-output words of the ROOT
/// compression (the caller serialises them little-endian); otherwise they are
/// the chunk's chaining value.
fn chunk_output(chunk: &[u8], counter: u64, root: bool) -> [u32; 16] {
    let mut cv = IV;
    let mut offset = 0;
    let mut block_index = 0;
    loop {
        let remaining = chunk.len() - offset;
        let take = remaining.min(BLOCK_LEN);
        let mut block = [0u8; BLOCK_LEN];
        block[..take].copy_from_slice(&chunk[offset..offset + take]);
        let last = offset + take == chunk.len();
        let mut flags = 0;
        if block_index == 0 {
            flags |= CHUNK_START;
        }
        if last {
            flags |= CHUNK_END;
            if root {
                flags |= ROOT;
            }
        }
        let output = compress(&cv, &block, counter, take as u32, flags);
        if last {
            return output;
        }
        cv = chaining_value(&output);
        offset += take;
        block_index += 1;
    }
}

fn chunk_cv(chunk: &[u8], counter: u64) -> [u32; 8] {
    chaining_value(&chunk_output(chunk, counter, false))
}

/// Combine two child chaining values into a parent chaining value, or the
/// root output when `root` is set.
fn parent_output(left: &[u32; 8], right: &[u32; 8], root: bool) -> [u32; 16] {
    let mut block = [0u8; BLOCK_LEN];
    for index in 0..8 {
        block[index * 4..index * 4 + 4].copy_from_slice(&left[index].to_le_bytes());
        block[32 + index * 4..32 + index * 4 + 4].copy_from_slice(&right[index].to_le_bytes());
    }
    compress(&IV, &block, 0, BLOCK_LEN as u32, PARENT | if root { ROOT } else { 0 })
}

/// Recursively hash the chunk chaining values of `chunks[start..]` and return
/// the 8 root words. The left subtree is the largest power of two strictly
/// smaller than the number of chunks, as the BLAKE3 tree mode specifies.
fn tree_output(chunks: &[[u32; 8]]) -> [u32; 16] {
    debug_assert!(chunks.len() > 1);
    let left_len = largest_power_of_two_less_than(chunks.len());
    let left = tree_cv(&chunks[..left_len]);
    let right = tree_cv(&chunks[left_len..]);
    parent_output(&left, &right, true)
}

fn tree_cv(chunks: &[[u32; 8]]) -> [u32; 8] {
    if chunks.len() == 1 {
        return chunks[0];
    }
    let left_len = largest_power_of_two_less_than(chunks.len());
    let left = tree_cv(&chunks[..left_len]);
    let right = tree_cv(&chunks[left_len..]);
    chaining_value(&parent_output(&left, &right, false))
}

fn largest_power_of_two_less_than(value: usize) -> usize {
    debug_assert!(value > 1);
    1usize << (usize::BITS - 1 - (value - 1).leading_zeros()) as usize
}

/// `BLAKE3(input)` truncated to 32 bytes, matching Go's `blake3.Sum256`.
pub fn hash32(input: &[u8]) -> [u8; 32] {
    let words = if input.is_empty() {
        chunk_output(&[], 0, true)
    } else if input.len() <= CHUNK_LEN {
        chunk_output(input, 0, true)
    } else {
        let chunks: Vec<[u32; 8]> = input
            .chunks(CHUNK_LEN)
            .enumerate()
            .map(|(index, chunk)| chunk_cv(chunk, index as u64))
            .collect();
        tree_output(&chunks)
    };
    let mut out = [0u8; 32];
    for index in 0..8 {
        out[index * 4..index * 4 + 4].copy_from_slice(&words[index].to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn matches_the_published_empty_and_abc_vectors() {
        assert_eq!(
            hex(&hash32(b"")),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            hex(&hash32(b"abc")),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    #[test]
    fn chunk_boundaries_follow_the_tree_mode() {
        // Vectors generated with the pinned `github.com/metacubex/blake3`
        // v0.1.0 module (`blake3.Sum256`), the same package the pinned Mihomo
        // TUIC v4 client calls through `GenTKN`.
        for (input, expected) in [
            (
                vec![b'a'; 63],
                "1a2a060cf56e4a859d80723cac9e2391d3c09a33008483e5424c57fe68629b79",
            ),
            (
                vec![b'a'; 64],
                "472c51290d607f100d2036fdcedd7590bba245e9adeb21364a063b7bb4ca81c7",
            ),
            (
                vec![b'a'; 1024],
                "5a1c9e5d85d9898297037e8e24f69bb0e604a84c91c3b3ef4784a374812900d9",
            ),
            (
                vec![b'a'; 1025],
                "c59d2e12583df14d951e757a42f1734d355c8c5b1db6b6a33ab2bfabeed40c7d",
            ),
            (
                b"legacy-tuic-token".to_vec(),
                "2ca4c3249850b4cb5ab42983e01c82241bde0147aaa2bbcae4f52a074e0b93fd",
            ),
        ] {
            assert_eq!(hex(&hash32(&input)), expected, "input length {}", input.len());
        }
    }
}
