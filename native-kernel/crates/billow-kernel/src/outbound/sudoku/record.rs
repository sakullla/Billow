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
//! Sudoku record layer (`transport/sudoku/crypto/record_conn.go`).
//!
//! Wire format per record:
//!
//! ```text
//! u16 bodyLen | epoch(u32 BE) | seq(u64 BE) | AEAD(header, plaintext)
//! ```
//!
//! `header` is used as both the 12-byte nonce and the additional data. The key
//! for an epoch is `HMAC-SHA256(baseKey, "sudoku-record:" || method || epoch)`
//! (truncated to 16 bytes for aes-128-gcm), so a rekey only changes the base
//! keys. Sending starts from a random non-zero epoch/seq; the send epoch
//! advances after every 32 MiB of plaintext, and the receiver enforces strict
//! sequence order within an epoch and a bounded epoch jump.

use std::io;

use aes_gcm::aead::{Aead as _, KeyInit, Payload};
use aes_gcm::Aes128Gcm;
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const RECORD_HEADER_SIZE: usize = 12;
const MAX_FRAME_BODY: usize = 65535;
/// `KeyUpdateAfterBytes`: 32 MiB of plaintext per send epoch.
const KEY_UPDATE_AFTER_BYTES: i64 = 32 << 20;
const MAX_EPOCH_JUMP: u32 = 8;

/// `aead-method` of the Sudoku configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadMethod {
    Chacha20Poly1305,
    Aes128Gcm,
    None,
}

impl AeadMethod {
    pub fn parse(name: &str) -> Option<AeadMethod> {
        match name {
            "" | "chacha20-poly1305" => Some(AeadMethod::Chacha20Poly1305),
            "aes-128-gcm" => Some(AeadMethod::Aes128Gcm),
            "none" => Some(AeadMethod::None),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AeadMethod::Chacha20Poly1305 => "chacha20-poly1305",
            AeadMethod::Aes128Gcm => "aes-128-gcm",
            AeadMethod::None => "none",
        }
    }

    fn overhead(self) -> usize {
        match self {
            AeadMethod::None => 0,
            _ => 16,
        }
    }

    fn aead(self, key: &[u8]) -> io::Result<Option<Aead>> {
        match self {
            AeadMethod::None => Ok(None),
            AeadMethod::Chacha20Poly1305 => Ok(Some(Aead::Chacha(
                Box::new(ChaCha20Poly1305::new_from_slice(key).expect("32-byte key")),
            ))),
            AeadMethod::Aes128Gcm => Ok(Some(Aead::Aes(Box::new(
                Aes128Gcm::new_from_slice(&key[..16]).expect("16-byte key"),
            )))),
        }
    }
}

enum Aead {
    Chacha(Box<ChaCha20Poly1305>),
    Aes(Box<Aes128Gcm>),
}

impl Aead {
    fn seal(&self, header: &[u8; 12], plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let payload = Payload {
            msg: plaintext,
            aad: header,
        };
        let nonce = Nonce::from_slice(header);
        let sealed = match self {
            Aead::Chacha(cipher) => cipher.encrypt(nonce, payload),
            Aead::Aes(cipher) => cipher.encrypt(nonce, payload),
        };
        sealed.map_err(|_| io::Error::other("sudoku: record seal failed"))
    }

    fn open(&self, header: &[u8; 12], ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        let payload = Payload {
            msg: ciphertext,
            aad: header,
        };
        let nonce = Nonce::from_slice(header);
        let opened = match self {
            Aead::Chacha(cipher) => cipher.decrypt(nonce, payload),
            Aead::Aes(cipher) => cipher.decrypt(nonce, payload),
        };
        opened.map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "sudoku: record open failed"))
    }
}

fn derive_epoch_key(base: &[u8], epoch: u32, method: AeadMethod) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(base).expect("HMAC accepts any key");
    mac.update(b"sudoku-record:");
    mac.update(method.as_str().as_bytes());
    mac.update(&epoch.to_be_bytes());
    mac.finalize().into_bytes().into()
}

fn random_non_zero_u32() -> u32 {
    loop {
        let value = rand::thread_rng().next_u32();
        if value != 0 && value != u32::MAX {
            return value;
        }
    }
}

fn random_non_zero_u64() -> u64 {
    loop {
        let value = rand::thread_rng().next_u64();
        if value != 0 && value != u64::MAX {
            return value;
        }
    }
}

/// Send direction: seals plaintext into whole records.
pub struct RecordSender {
    method: AeadMethod,
    base: Vec<u8>,
    epoch: u32,
    seq: u64,
    bytes: i64,
    epoch_updates: u32,
    aead: Option<(Aead, u32)>,
}

impl RecordSender {
    pub fn new(method: AeadMethod, base_send: Vec<u8>) -> io::Result<RecordSender> {
        validate_key(method, &base_send)?;
        Ok(RecordSender {
            method,
            base: base_send,
            epoch: random_non_zero_u32(),
            seq: random_non_zero_u64(),
            bytes: 0,
            epoch_updates: 0,
            aead: None,
        })
    }

    /// Rekey to the session base key, restarting the counters (the pinned
    /// `Rekey` also rotates the first send epoch and sequence).
    pub fn rekey(&mut self, base_send: Vec<u8>) -> io::Result<()> {
        validate_key(self.method, &base_send)?;
        self.base = base_send;
        self.epoch = random_non_zero_u32();
        self.seq = random_non_zero_u64();
        self.bytes = 0;
        self.epoch_updates = 0;
        self.aead = None;
        Ok(())
    }

    pub fn seal(&mut self, plain: &[u8]) -> io::Result<Vec<u8>> {
        if self.method == AeadMethod::None {
            return Ok(plain.to_vec());
        }
        let mut out = Vec::with_capacity(plain.len() + 14 + plain.len() / 8192 * 2);
        let mut rest = plain;
        while !rest.is_empty() {
            if self.aead.as_ref().map(|(_, epoch)| *epoch) != Some(self.epoch) {
                let key = derive_epoch_key(&self.base, self.epoch, self.method);
                let aead = self.method.aead(&key)?.expect("AEAD method");
                self.aead = Some((aead, self.epoch));
            }
            let max_plain = MAX_FRAME_BODY - RECORD_HEADER_SIZE - aead_overhead(self.method);
            let take = rest.len().min(max_plain);
            let chunk = &rest[..take];
            rest = &rest[take..];

            let mut header = [0u8; RECORD_HEADER_SIZE];
            header[..4].copy_from_slice(&self.epoch.to_be_bytes());
            header[4..].copy_from_slice(&self.seq.to_be_bytes());
            self.seq += 1;

            let ciphertext = {
                let aead = &self.aead.as_ref().expect("epoch key").0;
                aead.seal(&header, chunk)?
            };
            let body_len = RECORD_HEADER_SIZE + ciphertext.len();
            if body_len > MAX_FRAME_BODY {
                return Err(io::Error::other("sudoku: record too large"));
            }
            out.extend_from_slice(&(body_len as u16).to_be_bytes());
            out.extend_from_slice(&header);
            out.extend_from_slice(&ciphertext);

            self.bytes += take as i64;
            let threshold = KEY_UPDATE_AFTER_BYTES * (i64::from(self.epoch_updates) + 1);
            if self.bytes >= threshold {
                self.epoch += 1;
                self.epoch_updates += 1;
                self.seq = random_non_zero_u64();
            }
        }
        Ok(out)
    }
}

fn aead_overhead(method: AeadMethod) -> usize {
    method.overhead()
}

fn validate_key(method: AeadMethod, key: &[u8]) -> io::Result<()> {
    if method != AeadMethod::None && key.len() < 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sudoku: base key must be at least 32 bytes",
        ));
    }
    Ok(())
}

/// Receive direction: parses and authenticates whole records.
pub struct RecordReceiver {
    method: AeadMethod,
    base: Vec<u8>,
    epoch: u32,
    seq: u64,
    initialized: bool,
    aead: Option<(Aead, u32)>,
    pending: Vec<u8>,
}

impl RecordReceiver {
    pub fn new(method: AeadMethod, base_recv: Vec<u8>) -> io::Result<RecordReceiver> {
        validate_key(method, &base_recv)?;
        Ok(RecordReceiver {
            method,
            base: base_recv,
            epoch: 0,
            seq: 0,
            initialized: false,
            aead: None,
            pending: Vec::new(),
        })
    }

    pub fn rekey(&mut self, base_recv: Vec<u8>) -> io::Result<()> {
        validate_key(self.method, &base_recv)?;
        self.base = base_recv;
        self.epoch = 0;
        self.seq = 0;
        self.initialized = false;
        self.aead = None;
        Ok(())
    }

    /// Feed decoded obfuscation bytes; returns every complete record's
    /// plaintext in order.
    pub fn push(&mut self, input: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        if self.method == AeadMethod::None {
            return Ok(if input.is_empty() {
                Vec::new()
            } else {
                vec![input.to_vec()]
            });
        }
        self.pending.extend_from_slice(input);
        let mut out = Vec::new();
        loop {
            if self.pending.len() < 2 {
                break;
            }
            let body_len = u16::from_be_bytes([self.pending[0], self.pending[1]]) as usize;
            if body_len < RECORD_HEADER_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sudoku: record too short",
                ));
            }
            if self.pending.len() < 2 + body_len {
                break;
            }
            let frame: Vec<u8> = self.pending.drain(..2 + body_len).collect();
            let body = &frame[2..];
            let mut header = [0u8; RECORD_HEADER_SIZE];
            header.copy_from_slice(&body[..RECORD_HEADER_SIZE]);
            let epoch = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
            let seq = u64::from_be_bytes([
                header[4], header[5], header[6], header[7], header[8], header[9], header[10],
                header[11],
            ]);
            if self.initialized {
                if epoch < self.epoch {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("sudoku: replayed epoch {epoch} < {}", self.epoch),
                    ));
                }
                if epoch == self.epoch && seq != self.seq {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("sudoku: out of order record {seq} != {}", self.seq),
                    ));
                }
                if epoch - self.epoch > MAX_EPOCH_JUMP {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "sudoku: epoch jump too large",
                    ));
                }
            }
            if self.aead.as_ref().map(|(_, cached)| *cached) != Some(epoch) {
                let key = derive_epoch_key(&self.base, epoch, self.method);
                let aead = self.method.aead(&key)?.expect("AEAD method");
                self.aead = Some((aead, epoch));
            }
            let plain = {
                let aead = &self.aead.as_ref().expect("epoch key").0;
                aead.open(&header, &body[RECORD_HEADER_SIZE..])?
            };
            self.epoch = epoch;
            self.seq = seq + 1;
            self.initialized = true;
            out.push(plain);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(method: AeadMethod, len: usize) {
        let base = vec![7u8; 32];
        let mut sender = RecordSender::new(method, base.clone()).expect("sender");
        let mut receiver = RecordReceiver::new(method, base).expect("receiver");
        let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let wire = sender.seal(&plain).expect("seal");
        let mut delivered = Vec::new();
        for record in receiver.push(&wire).expect("open") {
            delivered.extend_from_slice(&record);
        }
        assert_eq!(delivered, plain);
    }

    #[test]
    fn every_method_round_trips_both_small_and_large_payloads() {
        for method in [
            AeadMethod::Chacha20Poly1305,
            AeadMethod::Aes128Gcm,
            AeadMethod::None,
        ] {
            round_trip(method, 1);
            round_trip(method, 1000);
            round_trip(method, 200_000);
        }
    }

    #[test]
    fn a_tampered_record_is_rejected() {
        let base = vec![3u8; 32];
        let mut sender = RecordSender::new(AeadMethod::Chacha20Poly1305, base.clone()).unwrap();
        let mut receiver = RecordReceiver::new(AeadMethod::Chacha20Poly1305, base).unwrap();
        let mut wire = sender.seal(b"hello world").unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        assert!(receiver.push(&wire).is_err());
    }

    #[test]
    fn a_replayed_record_is_rejected() {
        let base = vec![9u8; 32];
        let mut sender = RecordSender::new(AeadMethod::Chacha20Poly1305, base.clone()).unwrap();
        let mut receiver = RecordReceiver::new(AeadMethod::Chacha20Poly1305, base).unwrap();
        let first = sender.seal(b"one").unwrap();
        let second = sender.seal(b"two").unwrap();
        assert!(receiver.push(&first).is_ok());
        assert!(receiver.push(&second).is_ok());
        assert!(receiver.push(&first).is_err(), "a replayed record must fail");
    }

    #[test]
    fn the_epoch_key_depends_on_the_method_and_epoch() {
        let base = [1u8; 32];
        let a = derive_epoch_key(&base, 1, AeadMethod::Chacha20Poly1305);
        let b = derive_epoch_key(&base, 2, AeadMethod::Chacha20Poly1305);
        let c = derive_epoch_key(&base, 1, AeadMethod::Aes128Gcm);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
