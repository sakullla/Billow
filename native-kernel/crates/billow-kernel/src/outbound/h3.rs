//! Minimal HTTP/3 client used only by the Hysteria2 authentication request
//! (`sing-quic/hysteria2/client.go` posts to `https://hysteria/auth`).
//!
//! It implements exactly the subset the auth exchange needs: a client control
//! stream with SETTINGS, QPACK encoder/decoder streams, one request stream with
//! a HEADERS frame and a response HEADERS frame. The pinned server's QPACK
//! encoder (github.com/metacubex/qpack) uses the static table and Huffman
//! literals only, so the decoder here supports indexed static fields, literal
//! names/references and Huffman strings; a dynamic-table insert count is
//! rejected instead of being guessed. There is no request body, server push,
//! trailers or 0-RTT.
//!
//! The static table and the RFC 7541 Huffman table are copied from the pinned
//! Go modules (`qpack@v0.6.0/static_table.go`, `x/net/http2/hpack/tables.go`).

use std::collections::HashMap;
use std::io;
use std::sync::OnceLock;

use quinn::{Connection, Endpoint, RecvStream, SendStream};

/// A decoded response header list.
#[derive(Debug, Clone, Default)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

impl Response {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// One HTTP/3 connection's control streams, kept open for the QUIC
/// connection's lifetime (the Hysteria2 session reuses the connection for its
/// TCP streams after authentication).
pub struct Session {
    connection: Connection,
    hold: Vec<SendStream>,
}

impl Session {
    pub async fn open(connection: Connection, _endpoint: Endpoint) -> io::Result<Session> {
        let mut hold = Vec::new();
        // Client control stream: stream type 0x00, SETTINGS frame (empty).
        let mut control = open_uni(&connection).await?;
        control
            .write_all(&[0x00, 0x04, 0x00])
            .await
            .map_err(map_io)?;
        hold.push(control);
        // QPACK encoder stream (0x02) and decoder stream (0x03), empty.
        let mut encoder = open_uni(&connection).await?;
        encoder.write_all(&[0x02]).await.map_err(map_io)?;
        hold.push(encoder);
        let mut decoder = open_uni(&connection).await?;
        decoder.write_all(&[0x03]).await.map_err(map_io)?;
        hold.push(decoder);
        Ok(Session { connection, hold })
    }

    /// Send one request (no body) and return its response headers.
    pub async fn request(&self, headers: &[(&str, &str)]) -> io::Result<Response> {
        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| io::Error::other(format!("open request stream: {e}")))?;
        let block = encode_field_section(headers);
        let mut frame = Vec::with_capacity(block.len() + 10);
        encode_varint(0x01, &mut frame); // HEADERS
        encode_varint(block.len() as u64, &mut frame);
        frame.extend_from_slice(&block);
        send.write_all(&frame).await.map_err(map_io)?;
        send.finish()
            .map_err(|e| io::Error::other(format!("finish request: {e}")))?;

        loop {
            let Some(frame_type) = read_varint_async(&mut recv).await? else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "HTTP/3 stream ended before HEADERS",
                ));
            };
            let Some(length) = read_varint_async(&mut recv).await? else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "HTTP/3 frame length",
                ));
            };
            if length > 1 << 20 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP/3 frame too large",
                ));
            }
            let mut payload = vec![0u8; length as usize];
            recv.read_exact(&mut payload).await.map_err(map_io)?;
            match frame_type {
                0x01 => {
                    let fields = decode_field_section(&payload).map_err(|e| {
                        io::Error::new(io::ErrorKind::InvalidData, format!("QPACK: {e}"))
                    })?;
                    let status = fields
                        .iter()
                        .find(|(name, _)| name == ":status")
                        .and_then(|(_, value)| value.parse::<u16>().ok())
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "response has no :status")
                        })?;
                    return Ok(Response {
                        status,
                        headers: fields,
                    });
                }
                // DATA, SETTINGS and unknown extension frames are skipped.
                _ => continue,
            }
        }
    }

    pub fn into_hold(self) -> Vec<SendStream> {
        self.hold
    }
}

async fn open_uni(connection: &Connection) -> io::Result<SendStream> {
    connection
        .open_uni()
        .await
        .map_err(|e| io::Error::other(format!("open unidirectional stream: {e}")))
}

fn map_io(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

// ---------------------------------------------------------------------------
// QUIC varints and QPACK field sections.
// ---------------------------------------------------------------------------

pub fn encode_varint(value: u64, out: &mut Vec<u8>) {
    if value < 64 {
        out.push(value as u8);
    } else if value < 16_384 {
        out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < 1_073_741_824 {
        out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

#[cfg(test)]
fn decode_varint(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *bytes.get(*pos)?;
    let length = 1 << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for index in 1..length {
        value = (value << 8) | u64::from(*bytes.get(*pos + index)?);
    }
    *pos += length;
    Some(value)
}

pub async fn read_varint_async(recv: &mut RecvStream) -> io::Result<Option<u64>> {
    let mut first = [0u8; 1];
    match recv.read_exact(&mut first).await {
        Ok(()) => {}
        Err(e) if e.to_string().contains("closed") || e.to_string().contains("finished") => {
            return Ok(None)
        }
        Err(_) => return Ok(None),
    }
    let length = 1usize << (first[0] >> 6);
    let mut value = u64::from(first[0] & 0x3f);
    for _ in 1..length {
        let mut byte = [0u8; 1];
        recv.read_exact(&mut byte).await.map_err(map_io)?;
        value = (value << 8) | u64::from(byte[0]);
    }
    Ok(Some(value))
}

fn write_prefixed(out: &mut Vec<u8>, prefix_bits: u8, first: u8, value: usize) {
    let max = (1usize << prefix_bits) - 1;
    if value < max {
        out.push(first | value as u8);
        return;
    }
    out.push(first | max as u8);
    let mut rest = value - max;
    while rest >= 128 {
        out.push((rest % 128) as u8 | 0x80);
        rest /= 128;
    }
    out.push(rest as u8);
}

fn read_prefixed(bytes: &[u8], pos: &mut usize, prefix_bits: u8, first: u8) -> Option<usize> {
    let max = (1usize << prefix_bits) - 1;
    let mut value = usize::from(first) & max;
    *pos += 1;
    if value < max {
        return Some(value);
    }
    let mut shift = 0;
    loop {
        let byte = *bytes.get(*pos)?;
        *pos += 1;
        value += usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift > 56 {
            return None;
        }
    }
}

/// Encode request headers with literal names and no Huffman. The Go QPACK
/// decoder accepts this form.
pub fn encode_field_section(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = vec![0x00, 0x00]; // Required Insert Count 0, Delta Base 0
    for (name, value) in headers {
        // 001 N H, then a 3-bit name length prefix in the same byte.
        write_prefixed(&mut out, 3, 0x20, name.len());
        out.extend_from_slice(name.as_bytes());
        // 7-bit value length prefix.
        write_prefixed(&mut out, 7, 0x00, value.len());
        out.extend_from_slice(value.as_bytes());
    }
    out
}

fn decode_field_section(bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
    let mut pos = 0;
    let required = read_prefixed(bytes, &mut pos, 8, *bytes.first().ok_or("empty block")?)
        .ok_or("bad insert count")?;
    if required != 0 {
        return Err("dynamic table inserts are not supported".to_string());
    }
    // Delta Base: 7-bit prefix with a sign bit; only its size matters here.
    let base = *bytes.get(pos).ok_or("missing delta base")?;
    let _sign = base & 0x80;
    let _ = read_prefixed(bytes, &mut pos, 7, base).ok_or("bad delta base")?;

    let mut headers = Vec::new();
    while pos < bytes.len() {
        let first = bytes[pos];
        if first & 0x80 != 0 {
            let index = read_prefixed(bytes, &mut pos, 6, first).ok_or("bad indexed field")?;
            if first & 0x40 == 0 {
                return Err("dynamic indexed field is not supported".to_string());
            }
            let (name, value) = static_entry(index)?;
            headers.push((name.to_string(), value.to_string()));
        } else if first & 0x40 != 0 {
            let index = read_prefixed(bytes, &mut pos, 4, first).ok_or("bad name reference")?;
            if first & 0x10 == 0 {
                return Err("dynamic name reference is not supported".to_string());
            }
            let (name, _) = static_entry(index)?;
            let value = read_value_string(bytes, &mut pos)?;
            headers.push((name.to_string(), value));
        } else if first & 0x20 != 0 {
            let huffman = first & 0x08 != 0;
            let name_len = read_prefixed(bytes, &mut pos, 3, first).ok_or("bad literal name")?;
            let name = read_bytes(bytes, &mut pos, name_len, huffman)?;
            let name =
                String::from_utf8(name).map_err(|_| "literal name is not UTF-8".to_string())?;
            let value = read_value_string(bytes, &mut pos)?;
            headers.push((name, value));
        } else {
            return Err("post-base / dynamic field line is not supported".to_string());
        }
    }
    Ok(headers)
}

fn static_entry(index: usize) -> Result<(&'static str, &'static str), String> {
    STATIC_TABLE
        .get(index)
        .copied()
        .ok_or_else(|| format!("static table index {index} out of range"))
}

fn read_value_string(bytes: &[u8], pos: &mut usize) -> Result<String, String> {
    let first = *bytes.get(*pos).ok_or("missing value length")?;
    let huffman = first & 0x80 != 0;
    let length = read_prefixed(bytes, pos, 7, first).ok_or("bad value length")?;
    let raw = read_bytes(bytes, pos, length, huffman)?;
    String::from_utf8(raw).map_err(|_| "value string is not UTF-8".to_string())
}

fn read_bytes(
    bytes: &[u8],
    pos: &mut usize,
    length: usize,
    huffman: bool,
) -> Result<Vec<u8>, String> {
    let end = pos.checked_add(length).ok_or("string length overflow")?;
    let raw = bytes.get(*pos..end).ok_or("string runs past the block")?;
    *pos = end;
    if huffman {
        huffman_decode(raw)
    } else {
        Ok(raw.to_vec())
    }
}

fn huffman_decode(bytes: &[u8]) -> Result<Vec<u8>, String> {
    static TABLE: OnceLock<HashMap<(u8, u32), u8>> = OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut map = HashMap::new();
        for (symbol, (&code, &len)) in HUFFMAN_CODES.iter().zip(HUFFMAN_LENGTHS.iter()).enumerate()
        {
            map.insert((len, code), symbol as u8);
        }
        map
    });
    let mut out = Vec::new();
    let mut code: u32 = 0;
    let mut len: u8 = 0;
    for byte in bytes {
        for bit in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> bit) & 1);
            len += 1;
            if len > 30 {
                return Err("huffman code longer than 30 bits".to_string());
            }
            if let Some(symbol) = table.get(&(len, code)) {
                out.push(*symbol);
                code = 0;
                len = 0;
            }
        }
    }
    if len > 0 {
        // RFC 7541: the remaining bits are the EOS prefix, all ones, < 8 bits.
        let mask = (1u32 << len) - 1;
        if len > 7 || code != mask {
            return Err("invalid huffman padding".to_string());
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// QPACK static table (qpack@v0.6.0/static_table.go).
// ---------------------------------------------------------------------------

const STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

// ---------------------------------------------------------------------------
// RFC 7541 Appendix B Huffman table (x/net/http2/hpack/tables.go).
// ---------------------------------------------------------------------------

const HUFFMAN_CODES: [u32; 256] = [
    0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7, 0xfffffe8,
    0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec, 0xfffffed,
    0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3, 0xffffff4,
    0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb, 0x14, 0x3f8,
    0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa, 0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
    0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb,
    0x3fc, 0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0,
    0x1ffc, 0x3ffc, 0x22, 0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26, 0x27, 0x6, 0x74, 0x75,
    0x28, 0x29, 0x2a, 0x7, 0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7ffe,
    0x7fc, 0x3ffd, 0x1ffd, 0xffffffc, 0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4,
    0x3fffd5, 0x7fffd9, 0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb,
    0x7fffdf, 0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
    0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef, 0x3fffda,
    0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde, 0x7fffea, 0x3fffdd,
    0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec, 0x1fffe0, 0x1fffe1, 0x3fffe0,
    0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef, 0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4,
    0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1, 0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7,
    0x7ffff2, 0x3fffe8, 0x1ffffec, 0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf,
    0x3ffffe5, 0xfffff1, 0x1ffffed, 0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7,
    0x7ffffe2, 0xfffff2, 0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4,
    0x7ffffe5, 0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
    0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4, 0x3ffffeb,
    0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea, 0x7ffffeb,
    0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
];

const HUFFMAN_LENGTHS: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip() {
        for value in [0u64, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824] {
            let mut out = Vec::new();
            encode_varint(value, &mut out);
            let mut pos = 0;
            assert_eq!(decode_varint(&out, &mut pos), Some(value));
            assert_eq!(pos, out.len());
        }
    }

    #[test]
    fn field_section_round_trip_with_literals() {
        let headers = [
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "hysteria"),
            (":path", "/auth"),
            ("hysteria-auth", "secret"),
            ("hysteria-padding", &"a".repeat(300)[..]),
        ];
        let block = encode_field_section(&headers);
        let decoded = decode_field_section(&block).unwrap();
        assert_eq!(decoded.len(), headers.len());
        assert_eq!(decoded[0], (":method".to_string(), "POST".to_string()));
        assert_eq!(
            decoded[4],
            ("hysteria-auth".to_string(), "secret".to_string())
        );
        assert_eq!(decoded[5].1.len(), 300);
    }

    #[test]
    fn static_table_index_is_the_qpack_order() {
        assert_eq!(static_entry(0).unwrap(), (":authority", ""));
        assert_eq!(static_entry(17).unwrap(), (":method", "GET"));
        assert_eq!(static_entry(25).unwrap(), (":status", "200"));
        assert_eq!(static_entry(98).unwrap(), ("x-frame-options", "sameorigin"));
    }

    #[test]
    fn huffman_decodes_a_known_string() {
        // HPACK Huffman for "www.example.com" (RFC 7541 C.4.1).
        let encoded = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        assert_eq!(huffman_decode(&encoded).unwrap(), b"www.example.com");
    }
}
