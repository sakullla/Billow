//! TLSMirror (`transport/tlsmirror`) client.
//!
//! The pinned client does not wrap TLS in another TLS session. It opens a
//! *carrier* TLS session to a real destination (relayed by the mirror server),
//! derives an AES-128-GCM key/nonce mask from the primary key and both
//! handshake randoms, and injects the hidden VMess bytes as extra TLS
//! application-data records into the same raw TCP stream. The server's mirror
//! forwards carrier records to the configured destination and diverts records
//! that decrypt with the hidden key.
//!
//! Implemented here: the carrier TLS 1.3 handshake (rustls raw record driver),
//! HKDF-SHA256 key derivation, the stateful XOR-nonce AES-GCM record layer and
//! the interleaved read/write loop. `primary-key` is required for the feature;
//! a block with no recognised value is a no-op exactly like the pinned
//! decoder. TLS 1.2 explicit-nonce cipher suites, transport-layer padding,
//! connection enrollment and the embedded traffic generator are rejected by
//! name at load.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

use super::tls::{self, ClientTls};
use super::BoxStream;
use crate::proxies::{TlsMirrorOptions, TlsSettings};

const RECORD_APPLICATION_DATA: u8 = 23;
const MAX_RECORD: usize = 16384;

const INFO_ENCRYPTION: &str = "v2ray-sp76YMKM-EkGrFUNL-rTJRJMkU:tlsmirror-encryption";
const INFO_NONCE_MASK: &str = "v2ray-sp76YMKM-EkGrFUNL-rTJRJMkU:tlsmirror-noncemask";

/// Decode the pinned base64 primary key (standard alphabet, 32 bytes).
pub fn decode_primary_key(value: &str) -> Result<[u8; 32], String> {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [255u8; 256];
    for (index, byte) in ALPHABET.iter().enumerate() {
        table[*byte as usize] = index as u8;
    }
    let mut out = Vec::with_capacity(value.len());
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for byte in value.bytes() {
        if byte == b'=' {
            break;
        }
        let digit = table[byte as usize];
        if digit == 255 {
            return Err("primary-key is not base64".to_string());
        }
        accumulator = (accumulator << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }
    if out.len() != 32 {
        return Err("tlsmirror primary key must decode to 32 bytes".to_string());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    Ok(key)
}

struct Encryptor {
    aead: Aes128Gcm,
    mask: [u8; 12],
    counter: [u8; 8],
}

impl Encryptor {
    fn new(key: &[u8; 16], mask: [u8; 12]) -> Encryptor {
        Encryptor {
            aead: Aes128Gcm::new_from_slice(key).expect("16-byte key"),
            mask,
            counter: [0xff; 8],
        }
    }

    fn next_nonce(&mut self) -> [u8; 8] {
        for byte in self.counter.iter_mut() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        self.counter
    }

    fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = self.next_nonce();
        let mut mask = self.mask;
        for (index, byte) in nonce.iter().enumerate() {
            mask[4 + index] ^= byte;
        }
        self.aead
            .encrypt(Nonce::from_slice(&mask), plaintext)
            .expect("AES-GCM encryption cannot fail")
    }
}

struct Decryptor {
    aead: Aes128Gcm,
    mask: [u8; 12],
    counter: [u8; 8],
    next: Option<[u8; 8]>,
}

impl Decryptor {
    fn new(key: &[u8; 16], mask: [u8; 12]) -> Decryptor {
        Decryptor {
            aead: Aes128Gcm::new_from_slice(key).expect("16-byte key"),
            mask,
            counter: [0xff; 8],
            next: None,
        }
    }

    fn next_nonce(&mut self) -> [u8; 8] {
        for byte in self.counter.iter_mut() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        self.counter
    }

    fn open(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let nonce = match self.next {
            Some(nonce) => nonce,
            None => {
                let nonce = self.next_nonce();
                self.next = Some(nonce);
                nonce
            }
        };
        let mut mask = self.mask;
        for (index, byte) in nonce.iter().enumerate() {
            mask[4 + index] ^= byte;
        }
        let opened = self.aead.decrypt(Nonce::from_slice(&mask), ciphertext).ok();
        if opened.is_some() {
            self.next = None;
        }
        opened
    }
}

fn derive(primary: &[u8; 32], client: &[u8; 32], server: &[u8; 32]) -> (Encryptor, Decryptor) {
    let (enc_key, enc_mask) = derive_material(primary, client, server, ":c2s");
    let (dec_key, dec_mask) = derive_material(primary, client, server, ":s2c");
    (Encryptor::new(&enc_key, enc_mask), Decryptor::new(&dec_key, dec_mask))
}

/// The pinned `hkdf.Expand(sha256.New, combined, info)`: `combined` is the PRK.
fn derive_material(
    primary: &[u8; 32],
    client: &[u8; 32],
    server: &[u8; 32],
    tag: &str,
) -> ([u8; 16], [u8; 12]) {
    let mut combined = Vec::with_capacity(96);
    combined.extend_from_slice(primary);
    combined.extend_from_slice(client);
    combined.extend_from_slice(server);
    let hkdf = Hkdf::<Sha256>::from_prk(&combined).expect("32-byte PRK");
    let mut key = [0u8; 16];
    let mut mask = [0u8; 12];
    hkdf.expand(format!("{INFO_ENCRYPTION}{tag}").as_bytes(), &mut key)
        .expect("16-byte key material");
    hkdf.expand(format!("{INFO_NONCE_MASK}{tag}").as_bytes(), &mut mask)
        .expect("12-byte nonce mask");
    (key, mask)
}

fn parse_client_random(fragment: &[u8]) -> Option<[u8; 32]> {
    if fragment.len() < 38 || fragment[0] != 1 {
        return None;
    }
    fragment[6..38].try_into().ok()
}

fn parse_server_random(fragment: &[u8]) -> Option<[u8; 32]> {
    if fragment.len() < 38 || fragment[0] != 2 {
        return None;
    }
    fragment[6..38].try_into().ok()
}

struct MirrorStream {
    outgoing: mpsc::UnboundedSender<Vec<u8>>,
    incoming: mpsc::UnboundedReceiver<Vec<u8>>,
    buffered: Vec<u8>,
    at: usize,
}

impl AsyncRead for MirrorStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.at < self.buffered.len() {
                let take = (self.buffered.len() - self.at).min(buf.remaining());
                buf.put_slice(&self.buffered[self.at..self.at + take]);
                self.at += take;
                if self.at == self.buffered.len() {
                    self.buffered.clear();
                    self.at = 0;
                }
                return Poll::Ready(Ok(()));
            }
            match self.incoming.poll_recv(cx) {
                Poll::Ready(Some(payload)) => {
                    self.buffered = payload;
                    self.at = 0;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for MirrorStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.outgoing.send(buf.to_vec()).is_err() {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Wrap `stream` in the TLSMirror carrier/hidden layer. `server` is the VMess
/// server address the raw stream already reaches; the carrier TLS names
/// `sni`/`server` and is relayed by the mirror to its configured destination.
pub async fn wrap(
    stream: BoxStream,
    server: &str,
    settings: &TlsSettings,
    tls: &ClientTls,
    options: &TlsMirrorOptions,
) -> io::Result<BoxStream> {
    let primary = decode_primary_key(&options.primary_key)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let name = settings.sni.clone().unwrap_or_else(|| server.to_string());
    let server_name = rustls_pki_types::ServerName::try_from(name.clone())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, format!("tlsmirror: {error}")))?
        .to_owned();
    let config = tls::quic_client_config(settings, tls, &settings.alpn, true)?;
    let connection = rustls::ClientConnection::new(config, server_name)
        .map_err(|error| io::Error::other(format!("tlsmirror: {error}")))?;
    let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel();
    let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
    tokio::spawn(run(
        stream,
        connection,
        primary,
        outgoing_rx,
        incoming_tx,
    ));
    Ok(Box::new(MirrorStream {
        outgoing: outgoing_tx,
        incoming: incoming_rx,
        buffered: Vec::new(),
        at: 0,
    }))
}

async fn run(
    stream: BoxStream,
    mut carrier: rustls::ClientConnection,
    primary: [u8; 32],
    mut outgoing: mpsc::UnboundedReceiver<Vec<u8>>,
    incoming: mpsc::UnboundedSender<Vec<u8>>,
) {
    let (mut read_half, mut write_half) = tokio::io::split(stream);
    let mut client_random: Option<[u8; 32]> = None;
    let mut server_random: Option<[u8; 32]> = None;
    let mut encryptor: Option<Encryptor> = None;
    let mut decryptor: Option<Decryptor> = None;
    let mut pending: Vec<Vec<u8>> = Vec::new();
    let mut read_buffer = vec![0u8; 64 * 1024];
    let mut raw_pending: Vec<u8> = Vec::new();
    let mut closed = false;

    async fn drain(
        carrier: &mut rustls::ClientConnection,
        write_half: &mut tokio::io::WriteHalf<BoxStream>,
    ) -> io::Result<()> {
        let mut out = Vec::new();
        while carrier.wants_write() {
            let mut target = Vec::with_capacity(32 * 1024);
            match carrier.write_tls(&mut target) {
                Ok(0) => break,
                Ok(_) => out.extend_from_slice(&target),
                Err(error) => return Err(error),
            }
        }
        if !out.is_empty() {
            write_half.write_all(&out).await?;
        }
        Ok(())
    }

    // The first ClientHello carries the client random the hidden key is
    // derived from; parse it from the exact bytes rustls produced.
    {
        let mut hello = Vec::new();
        while carrier.wants_write() {
            let mut target = Vec::with_capacity(32 * 1024);
            match carrier.write_tls(&mut target) {
                Ok(0) => break,
                Ok(_) => hello.extend_from_slice(&target),
                Err(_) => return,
            }
        }
        if hello.len() >= 5 {
            let length = u16::from_be_bytes([hello[3], hello[4]]) as usize;
            if hello.len() >= 5 + length {
                client_random = parse_client_random(&hello[5..5 + length]);
            }
        }
        if write_half.write_all(&hello).await.is_err() {
            return;
        }
    }

    loop {
        tokio::select! {
            write = outgoing.recv() => {
                match write {
                    Some(plain) => {
                        if let Some(encryptor) = encryptor.as_mut() {
                            let fragment = encryptor.seal(&plain);
                            let mut record = Vec::with_capacity(5 + fragment.len());
                            record.push(RECORD_APPLICATION_DATA);
                            record.push(3);
                            record.push(3);
                            record.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
                            record.extend_from_slice(&fragment);
                            if write_half.write_all(&record).await.is_err() {
                                break;
                            }
                        } else {
                            pending.push(plain);
                        }
                    }
                    None => closed = true,
                }
            }
            read = read_half.read(&mut read_buffer) => {
                let read = match read {
                    Ok(0) => break,
                    Ok(read) => read,
                    Err(_) => break,
                };
                raw_pending.extend_from_slice(&read_buffer[..read]);
                let mut at = 0usize;
                while at + 5 <= raw_pending.len() {
                    let length =
                        u16::from_be_bytes([raw_pending[at + 3], raw_pending[at + 4]]) as usize;
                    if length > MAX_RECORD || at + 5 + length > raw_pending.len() {
                        break;
                    }
                    let record_type = raw_pending[at];
                    let fragment = &raw_pending[at + 5..at + 5 + length];
                    let mut hidden = None;
                    if record_type == RECORD_APPLICATION_DATA {
                        if let Some(decryptor) = decryptor.as_mut() {
                            hidden = decryptor.open(fragment);
                        }
                    }
                    if let Some(plain) = hidden {
                        if incoming.send(plain).is_err() {
                            return;
                        }
                    } else {
                        let end = at + 5 + length;
                        let mut slice = &raw_pending[at..end];
                        if carrier.read_tls(&mut slice).is_err()
                            || carrier.process_new_packets().is_err()
                        {
                            return;
                        }
                        if client_random.is_none() {
                            client_random = parse_client_random(fragment);
                        }
                        if server_random.is_none() {
                            server_random = parse_server_random(fragment);
                        }
                    }
                    at += 5 + length;
                }
                if at > 0 {
                    raw_pending.drain(..at);
                }
                if client_random.is_some() && server_random.is_some() && encryptor.is_none() {
                    let (enc, dec) = derive(
                        &primary,
                        &client_random.expect("client random"),
                        &server_random.expect("server random"),
                    );
                    encryptor = Some(enc);
                    decryptor = Some(dec);
                    for plain in pending.drain(..) {
                        let fragment = encryptor.as_mut().expect("encryptor").seal(&plain);
                        let mut record = Vec::with_capacity(5 + fragment.len());
                        record.push(RECORD_APPLICATION_DATA);
                        record.push(3);
                        record.push(3);
                        record.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
                        record.extend_from_slice(&fragment);
                        if write_half.write_all(&record).await.is_err() {
                            return;
                        }
                    }
                }
                if drain(&mut carrier, &mut write_half).await.is_err() {
                    return;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                if closed {
                    break;
                }
                if drain(&mut carrier, &mut write_half).await.is_err() {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primary_key_decodes_standard_base64() {
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert_eq!(decode_primary_key(key).unwrap(), [0u8; 32]);
        assert!(decode_primary_key("not base64!").is_err());
        assert!(decode_primary_key("AAAA").is_err());
    }

    #[test]
    fn xor_nonce_encryptor_and_decryptor_share_the_counter() {
        let (key, mask) = derive_material(&[7u8; 32], &[1u8; 32], &[2u8; 32], ":c2s");
        let mut enc = Encryptor::new(&key, mask);
        let mut dec = Decryptor::new(&key, mask);
        let sealed = enc.seal(b"hello");
        assert_eq!(dec.open(&sealed).unwrap(), b"hello");
        // A carrier ciphertext must not decrypt and must not consume the nonce.
        assert!(dec.open(b"definitely not our record").is_none());
        let next = enc.seal(b"world");
        assert_eq!(dec.open(&next).unwrap(), b"world");
    }

    #[test]
    fn client_and_server_randoms_are_parsed_at_the_pinned_offsets() {
        let mut hello = vec![1u8];
        hello.extend_from_slice(&[0, 0, 0]);
        hello.extend_from_slice(&[3, 3]);
        hello.extend_from_slice(&[9u8; 32]);
        assert_eq!(parse_client_random(&hello), Some([9u8; 32]));
        hello[0] = 2;
        assert_eq!(parse_server_random(&hello), Some([9u8; 32]));
    }
}
