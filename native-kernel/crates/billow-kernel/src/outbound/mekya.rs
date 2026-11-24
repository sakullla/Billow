//! mekya (`transport/mekya`): KCP packets carried in HTTP/2 request/response
//! bundles.
//!
//! The client keeps one HTTP/2 connection (TLS when `tls: true`) and runs two
//! request loops. Each request POSTs `[u16 length][packet]...` bundles to the
//! configured URL with `X-Session-ID: base64url(session id)`; the response body
//! is a stream of the same bundles until the server's write timer or size
//! limit. KCP runs over that packet stream, so the VMess stream is
//! `vmess || kcp || http2 || tls`.
//!
//! This implements the HTTP/2 lane only: the pinned client can also fall back
//! to HTTP/1.1 when ALPN does not select h2, but the pinned server advertises
//! h2 for mekya and this client requests it explicitly.

use std::io;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Uri};

use super::mkcp::{self, PacketIo};
use super::tls::{self, ClientTls};
use super::BoxStream;
use crate::proxies::{MekyaOptions, TlsSettings};

const BUNDLE_OVERHEAD: usize = 2;

/// Encode 16 random bytes as unpadded base64url (the pinned `X-Session-ID`).
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let value = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((value >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((value >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((value >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(value & 0x3f) as usize] as char);
        }
    }
    out
}

fn default_url(server: &str, port: u16) -> String {
    if server.parse::<std::net::IpAddr>().is_ok() {
        format!("https://{server}:{port}/")
    } else {
        format!("https://{server}:{port}/")
    }
}

fn uri_for(url: &str, server: &str, port: u16) -> io::Result<Uri> {
    let url = if url.is_empty() {
        default_url(server, port)
    } else {
        url.to_string()
    };
    let uri: Uri = url
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, format!("mekya url: {error}")))?;
    if uri.scheme_str() != Some("https") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mekya: the url scheme must be https",
        ));
    }
    if uri.authority().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mekya: the url has no host",
        ));
    }
    Ok(uri)
}

/// The packet transport seen by KCP: a non-blocking send queue consumed by the
/// HTTP loops and a blocking receive queue filled from response bodies.
struct MekyaIo {
    outgoing: std::sync::mpsc::Sender<Vec<u8>>,
    incoming: Receiver<Vec<u8>>,
}

impl PacketIo for MekyaIo {
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        self.outgoing
            .send(packet.to_vec())
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }

    fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self.incoming.recv_timeout(Duration::from_millis(50)) {
            Ok(packet) => {
                let take = packet.len().min(buffer.len());
                buffer[..take].copy_from_slice(&packet[..take]);
                Ok(take)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
        }
    }
}

fn write_bundle(body: &mut Vec<u8>, packet: &[u8]) {
    body.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    body.extend_from_slice(packet);
}

/// Dial a mekya session and run KCP over it. `server`/`port` are the address the
/// pinned client dials; the URL only supplies the HTTP authority/path.
pub async fn connect(
    server: &str,
    port: u16,
    settings: &TlsSettings,
    tls: &ClientTls,
    options: &MekyaOptions,
    use_tls: bool,
) -> io::Result<BoxStream> {
    let uri = uri_for(&options.url, server, port)?;
    let tcp = super::connect_tcp(server, port)
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    let stream: BoxStream = if use_tls {
        let mut settings = settings.clone();
        if settings.alpn.is_empty() {
            settings.alpn = vec!["h2".to_string()];
        } else if !settings.alpn.iter().any(|protocol| protocol == "h2") {
            settings.alpn.insert(0, "h2".to_string());
        }
        Box::new(
            tls::wrap_stream(tcp, server, &settings, tls)
                .await
                .map_err(|error| io::Error::other(format!("mekya tls: {error}")))?,
        )
    } else {
        Box::new(tcp)
    };
    let (send_request, connection) = h2::client::handshake(stream)
        .await
        .map_err(|error| io::Error::other(format!("mekya h2: {error}")))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut session_id = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut session_id);
    let session = base64url(&session_id);

    let (outgoing_tx, outgoing_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let (incoming_tx, incoming_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let outgoing = Arc::new(Mutex::new(outgoing_rx));
    // Two request lanes like the pinned `h2-pool-size` default of 2; each lane
    // takes packets from the shared queue and feeds response bundles back.
    let lanes = options.h2_pool_size.max(1).min(8);
    for _ in 0..lanes {
        let mut send_request = send_request.clone();
        let uri = uri.clone();
        let session = session.clone();
        let outgoing = outgoing.clone();
        let incoming_tx = incoming_tx.clone();
        tokio::spawn(async move {
            loop {
                let packet = outgoing
                    .lock()
                    .ok()
                    .and_then(|queue| match queue.try_recv() {
                        Ok(packet) => Some(packet),
                        Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => None,
                    });
                let mut body = Vec::new();
                if let Some(packet) = packet {
                    write_bundle(&mut body, &packet);
                }
                let request = match Request::builder()
                    .method("POST")
                    .uri(uri.clone())
                    .header("x-session-id", session.as_str())
                    .header("content-length", body.len())
                    .body(())
                {
                    Ok(request) => request,
                    Err(_) => return,
                };
                let end = body.is_empty();
                let (response, mut send_body) = match send_request.send_request(request, end) {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                if !end {
                    if send_body.send_data(Bytes::from(body), true).is_err() {
                        return;
                    }
                }
                let mut response = match response.await {
                    Ok(response) => response.into_body(),
                    Err(_) => return,
                };
                let mut pending = Vec::new();
                loop {
                    match response.data().await {
                        Some(Ok(chunk)) => {
                            pending.extend_from_slice(&chunk);
                            while pending.len() >= BUNDLE_OVERHEAD {
                                let length = u16::from_be_bytes([pending[0], pending[1]]) as usize;
                                if pending.len() < BUNDLE_OVERHEAD + length {
                                    break;
                                }
                                let packet = pending[BUNDLE_OVERHEAD..BUNDLE_OVERHEAD + length].to_vec();
                                pending.drain(..BUNDLE_OVERHEAD + length);
                                if incoming_tx.send(packet).is_err() {
                                    return;
                                }
                            }
                        }
                        Some(Err(_)) => return,
                        None => break,
                    }
                }
                // A new request is issued immediately; the server keeps the
                // previous response open until its write timer expires.
            }
        });
    }
    mkcp::connect_packet_io(
        Box::new(MekyaIo {
            outgoing: outgoing_tx,
            incoming: incoming_rx,
        }),
        &options.kcp,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_the_unpadded_alphabet() {
        assert_eq!(base64url(b"hello"), "aGVsbG8");
        assert_eq!(base64url(b"a"), "YQ");
        assert_eq!(base64url(b"ab"), "YWI");
        assert_eq!(base64url(&[0xff, 0xfe, 0xfd]), "__79");
    }

    #[test]
    fn bundle_layout_is_the_pinned_two_byte_length() {
        let mut body = Vec::new();
        write_bundle(&mut body, b"abc");
        assert_eq!(body, vec![0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn default_url_keeps_the_configured_port() {
        assert_eq!(default_url("127.0.0.1", 443), "https://127.0.0.1:443/");
    }
}
