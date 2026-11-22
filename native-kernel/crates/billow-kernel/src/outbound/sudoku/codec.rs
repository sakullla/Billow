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
//! Obfuscation framing around the record layer and the legacy HTTP mask.
//!
//! The uplink encoder and the downlink decoder wrap the record frames: the
//! wire is the Sudoku byte stream, the plaintext of that stream is the record
//! layer. The downlink codec is selected by `enable-pure-downlink`
//! (`true`: four hints per byte, the same codec as the uplink; `false`: the
//! bandwidth-optimised packed layout).

use std::sync::Arc;

use super::table::{Encoder, PackedDecoder, PureDecoder, SudokuTable, WyRand};

/// The downlink byte-stream decoder.
pub trait Downlink: Send {
    /// Push wire bytes, appending record-layer bytes to `out`. Returns `false`
    /// when the stream cannot be decoded.
    fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> bool;
}

pub struct PureDownlink {
    table: Arc<SudokuTable>,
    decoder: PureDecoder,
}

impl PureDownlink {
    pub fn new(table: Arc<SudokuTable>) -> PureDownlink {
        PureDownlink {
            table,
            decoder: PureDecoder::default(),
        }
    }
}

impl Downlink for PureDownlink {
    fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> bool {
        self.decoder.push(&self.table, input, out)
    }
}

pub struct PackedDownlink {
    table: Arc<SudokuTable>,
    decoder: PackedDecoder,
}

impl PackedDownlink {
    pub fn new(table: Arc<SudokuTable>) -> PackedDownlink {
        PackedDownlink {
            table,
            decoder: PackedDecoder::default(),
        }
    }
}

impl Downlink for PackedDownlink {
    fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> bool {
        self.decoder.push(&self.table, input, out)
    }
}

/// Build the uplink encoder for one connection.
pub fn uplink_encoder(
    table: Arc<SudokuTable>,
    padding_min: u8,
    padding_max: u8,
) -> Encoder {
    let mut rng = WyRand::new(rand::random::<u64>());
    let threshold = super::table::padding_threshold(&mut rng, padding_min, padding_max);
    Encoder::new(table, WyRand::new(rand::random::<u64>()), threshold)
}

/// Paths the pinned header generator draws from.
const MASK_PATHS: &[&str] = &[
    "/api/v1/upload",
    "/data/sync",
    "/uploads/raw",
    "/api/report",
    "/feed/update",
    "/v2/events",
    "/v1/telemetry",
    "/session",
    "/stream",
    "/ws",
];

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
];

const ACCEPTS: &[&str] = &[
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "application/json, text/plain, */*",
    "application/octet-stream",
    "*/*",
];

const ACCEPT_LANGUAGES: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "zh-CN,zh;q=0.9,en-US;q=0.8",
    "ja-JP,ja;q=0.9,en-US;q=0.8",
];

const CONTENT_TYPES: &[&str] = &[
    "application/octet-stream",
    "application/x-protobuf",
    "application/json",
];

/// `normalizePathRoot` of the pinned masker: a single `[A-Za-z0-9_-]` segment.
pub fn normalized_path_root(root: &str) -> Option<String> {
    let trimmed = root.trim().trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains('/')
        || !trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return None;
    }
    Some(format!("/{trimmed}"))
}

/// A plausible HTTP/1.1 request header used as the legacy mask. The server
/// consumes everything up to the blank line and switches to the raw stream,
/// so only the shape (a valid method line and terminated headers) matters.
pub fn legacy_header(host: &str, path_root: &str) -> Vec<u8> {
    use rand::Rng as _;
    let mut rng = rand::thread_rng();
    let pick = |list: &[&'static str], rng: &mut rand::rngs::ThreadRng| list[rng.gen_range(0..list.len())];
    let path = pick(MASK_PATHS, &mut rng);
    let path = match normalized_path_root(path_root) {
        Some(root) => format!("{root}{path}"),
        None => path.to_string(),
    };
    let host = match host.split_once(':') {
        Some((name, _)) if !name.starts_with('[') => name.to_string(),
        _ => host.to_string(),
    };
    let mut header = Vec::with_capacity(512);
    if rng.gen_range(0..10) < 2 {
        let key: [u8; 16] = rand::random();
        let key = base64(&key);
        header.extend_from_slice(format!("GET {path} HTTP/1.1\r\n").as_bytes());
        header.extend_from_slice(
            format!(
                "Host: {host}\r\nUser-Agent: {}\r\nAccept: {}\r\nAccept-Language: {}\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\n",
                pick(USER_AGENTS, &mut rng),
                pick(ACCEPTS, &mut rng),
                pick(ACCEPT_LANGUAGES, &mut rng),
            )
            .as_bytes(),
        );
        header.extend_from_slice(
            format!(
                "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n"
            )
            .as_bytes(),
        );
    } else {
        let content_length = rng.gen_range(4096..(10 * 1024 * 1024));
        header.extend_from_slice(format!("POST {path} HTTP/1.1\r\n").as_bytes());
        header.extend_from_slice(
            format!(
                "Host: {host}\r\nUser-Agent: {}\r\nAccept: {}\r\nAccept-Language: {}\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\nContent-Type: {}\r\nContent-Length: {content_length}\r\n\r\n",
                pick(USER_AGENTS, &mut rng),
                pick(ACCEPTS, &mut rng),
                pick(ACCEPT_LANGUAGES, &mut rng),
                pick(CONTENT_TYPES, &mut rng),
            )
            .as_bytes(),
        );
    }
    header
}

fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        out.push(TABLE[(b[0] >> 2) as usize] as char);
        out.push(TABLE[(((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b[1] & 0x0f) << 2) | (b[2] >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b[2] & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_legacy_header_is_a_well_formed_request() {
        for _ in 0..32 {
            let header = legacy_header("example.org:443", "aabbcc");
            let text = String::from_utf8_lossy(&header);
            assert!(text.ends_with("\r\n\r\n"));
            let first = text.lines().next().unwrap();
            assert!(
                first.starts_with("POST /aabbcc/") || first.starts_with("GET /aabbcc/"),
                "{first}"
            );
            assert!(text.contains("Host: example.org\r\n"));
            assert!(text.contains("\r\nContent-Length: ") || text.contains("Sec-WebSocket-Key: "));
        }
    }

    #[test]
    fn an_invalid_path_root_is_ignored() {
        let header = legacy_header("example.org:443", "a/b");
        let text = String::from_utf8_lossy(&header);
        assert!(!text.contains("a/b"));
    }
}
