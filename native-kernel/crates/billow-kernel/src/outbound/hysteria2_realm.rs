//! Hysteria2 realm rendezvous client (`sing-quic/hysteria2/realm`).
//!
//! The realm server is reached indirectly:
//!
//! 1. one UDP socket per address family is bound and its public address is
//!    discovered with STUN binding requests (XOR-MAPPED-ADDRESS);
//! 2. `POST {server-url}/v1/{realm-id}/connect` sends those addresses plus a
//!    random 16-byte nonce and 32-byte obfuscation key; the control server
//!    relays a punch event to the registered server, waits for its fresh
//!    addresses and answers with them (the nonce/key are echoed);
//! 3. both sides send `HYRLMv1` HELLO packets (SHA-256(key || salt) XOR with
//!    padding) to the other side's addresses until one is received; a HELLO is
//!    answered with an ACK;
//! 4. the QUIC handshake then runs over the same punched UDP socket to the
//!    peer address, with the Hysteria2 obfuscator (Salamander/Gecko) applied
//!    on top, exactly like the pinned `authenticateAndWrap`.
//!
//! The control connection is plain HTTP/1.1 over TLS when the URL is
//! `https://`; the pinned client enables HTTP/2 as well, but every control
//! server written against the protocol in `hysteria-realm-server` also serves
//! HTTP/1.1.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use quinn::{Connection, Endpoint};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use super::quic::{self, QuicOptions};
use super::tls::{self, ClientTls};
use super::{bind_udp, connect_tcp, resolve_all, DialError};
use crate::proxies::Hysteria2Realm;

const PUNCH_MAGIC: [u8; 8] = *b"HYRLMv1\0";
const PUNCH_HELLO: u8 = 0x01;
const PUNCH_ACK: u8 = 0x02;
const PUNCH_SALT_LEN: usize = 8;
const PUNCH_NONCE_LEN: usize = 16;
const PUNCH_KEY_LEN: usize = 32;
const PUNCH_MIN_BODY_LEN: usize = 8 + 1 + PUNCH_NONCE_LEN;
const PUNCH_MAX_PADDING: usize = 1024;
const PUNCH_MIN_PACKET_LEN: usize = PUNCH_SALT_LEN + PUNCH_MIN_BODY_LEN;
const PUNCH_TIMEOUT: Duration = Duration::from_secs(10);
const PUNCH_INTERVAL: Duration = Duration::from_millis(100);
const STUN_HEADER_LEN: usize = 20;
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const MAX_HTTP_BODY: usize = 1 << 20;

fn handshake(message: impl std::fmt::Display) -> DialError {
    DialError::Handshake {
        protocol: "hysteria2 realm",
        source: io::Error::other(message.to_string()),
    }
}

struct ControlUrl {
    tls: bool,
    host: String,
    port: u16,
    base: String,
}

fn parse_url(url: &str) -> Result<ControlUrl, DialError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| handshake(format!("control server URL '{url}' has no scheme")))?;
    let tls = match scheme {
        "https" => true,
        "http" => false,
        _ => {
            return Err(handshake(format!(
                "unsupported control URL scheme '{scheme}'"
            )))
        }
    };
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let (host, rest) = stripped
            .split_once(']')
            .ok_or_else(|| handshake(format!("invalid control host '{authority}'")))?;
        let port = match rest.strip_prefix(':') {
            Some(port) => port
                .parse()
                .map_err(|_| handshake(format!("invalid control port '{port}'")))?,
            None => default_port(tls),
        };
        (host.to_string(), port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        // A bare IPv6 address is bracketed by the URL syntax, so the last
        // colon is the port separator here.
        let port = port
            .parse()
            .map_err(|_| handshake(format!("invalid control port '{port}'")))?;
        (host.to_string(), port)
    } else {
        (authority.to_string(), default_port(tls))
    };
    if host.is_empty() {
        return Err(handshake("control server URL has no host"));
    }
    Ok(ControlUrl {
        tls,
        host,
        port,
        base: path.trim_end_matches('/').to_string(),
    })
}

fn default_port(tls: bool) -> u16 {
    if tls {
        443
    } else {
        80
    }
}

/// Dial through the realm control server. `server_name` is the TLS name of the
/// Hysteria2 server (the pinned client keeps `option.Server` for the QUIC TLS
/// config even though the address comes from the punch).
pub async fn connect(
    realm: &Hysteria2Realm,
    server_name: &str,
    quic_settings: &crate::proxies::TlsSettings,
    tls_client: &ClientTls,
    options: &QuicOptions,
    timeout: Duration,
    handshake_timeout: Duration,
) -> Result<(Connection, Endpoint), DialError> {
    let control = parse_url(&realm.server_url)?;
    let realm_id = realm.realm_id.clone().unwrap_or_default();
    let stun_servers = resolve_stun_servers(&realm.stun_servers).await?;

    let started = Instant::now();
    let families = open_families().await;
    let mut discovered: Vec<(UdpSocket, Vec<SocketAddr>)> = Vec::new();
    for socket in families {
        let local = socket.local_addr().map_err(|source| DialError::Connect {
            addr: "realm UDP socket".to_string(),
            source,
        })?;
        let servers: Vec<SocketAddr> = stun_servers
            .iter()
            .copied()
            .filter(|server| server.is_ipv4() == local.is_ipv4())
            .collect();
        if servers.is_empty() {
            continue;
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        match tokio::time::timeout(remaining, discover_stun(&socket, &servers)).await {
            Ok(Ok(addresses)) if !addresses.is_empty() => discovered.push((socket, addresses)),
            Ok(Ok(_)) | Err(_) => {}
            Ok(Err(_)) => {}
        }
    }
    if discovered.is_empty() {
        return Err(handshake(
            "STUN discovery found no mapped address (no reachable STUN server)",
        ));
    }
    let local_addresses: Vec<SocketAddr> = discovered
        .iter()
        .flat_map(|(_, addresses)| addresses.iter().copied())
        .collect();

    let metadata = PunchMetadata::generate();
    let response = control_connect(
        &control,
        realm,
        &realm_id,
        &local_addresses,
        &metadata,
        timeout.saturating_sub(started.elapsed()),
        tls_client,
    )
    .await?;
    let peer_addresses = response.addresses;
    if peer_addresses.is_empty() {
        return Err(handshake("realm connect returned no server addresses"));
    }
    let peer_metadata = response.metadata;

    // Punch each family that has a peer address, first success wins.
    let mut winner: Option<(UdpSocket, SocketAddr)> = None;
    let mut last_error = None;
    for (socket, _) in discovered {
        let local = socket.local_addr().map_err(|source| DialError::Connect {
            addr: "realm UDP socket".to_string(),
            source,
        })?;
        let peers: Vec<SocketAddr> = peer_addresses
            .iter()
            .copied()
            .filter(|peer| peer.is_ipv4() == local.is_ipv4())
            .collect();
        if peers.is_empty() {
            continue;
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        match tokio::time::timeout(remaining, punch(&socket, &peers, &peer_metadata)).await {
            Ok(Ok(peer)) => {
                winner = Some((socket, peer));
                break;
            }
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => last_error = Some(handshake("punch timed out")),
        }
    }
    let Some((socket, peer)) = winner else {
        return Err(last_error.unwrap_or_else(|| handshake("realm punch found no peer")));
    };

    let handshake_timeout = handshake_timeout.min(timeout.saturating_sub(started.elapsed()));
    if handshake_timeout.is_zero() {
        return Err(DialError::Timeout(timeout));
    }
    let socket = socket.into_std().map_err(|source| DialError::Connect {
        addr: peer.to_string(),
        source,
    })?;
    quic::connect_over_socket(
        socket,
        peer,
        server_name,
        quic_settings,
        tls_client,
        options,
        handshake_timeout,
    )
    .await
}

async fn open_families() -> Vec<UdpSocket> {
    let mut families = Vec::with_capacity(2);
    if let Ok(socket) = bind_udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await {
        families.push(socket);
    }
    if let Ok(socket) = bind_udp(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)).await {
        families.push(socket);
    }
    families
}

async fn resolve_stun_servers(servers: &[String]) -> Result<Vec<SocketAddr>, DialError> {
    let mut resolved = Vec::new();
    for server in servers {
        let (host, port) = match server.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') || host.starts_with('[') => {
                match port.parse::<u16>() {
                    Ok(port) => (host.trim_matches(['[', ']']), port),
                    Err(_) => (server.as_str(), 3478),
                }
            }
            _ => (server.as_str(), 3478),
        };
        let addresses = resolve_all(host, port).await?;
        for address in addresses {
            if !resolved.contains(&address) {
                resolved.push(address);
            }
        }
    }
    if resolved.is_empty() {
        return Err(handshake("no STUN servers resolved"));
    }
    Ok(resolved)
}

struct StunRequest {
    server: SocketAddr,
    raw: [u8; STUN_HEADER_LEN],
    transaction: [u8; 12],
}

async fn discover_stun(socket: &UdpSocket, servers: &[SocketAddr]) -> io::Result<Vec<SocketAddr>> {
    let requests: Vec<StunRequest> = servers
        .iter()
        .map(|server| {
            let mut raw = [0u8; STUN_HEADER_LEN];
            raw[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
            raw[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            let mut transaction = [0u8; 12];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut transaction);
            raw[8..20].copy_from_slice(&transaction);
            StunRequest {
                server: *server,
                raw,
                transaction,
            }
        })
        .collect();
    let mut pending: Vec<[u8; 12]> = requests.iter().map(|r| r.transaction).collect();
    let mut found = Vec::new();
    let mut buffer = [0u8; 1500];
    for attempt in [500u64, 2000, 4000] {
        if pending.is_empty() {
            break;
        }
        for request in &requests {
            if !pending.contains(&request.transaction) {
                continue;
            }
            let _ = socket.send_to(&request.raw, request.server).await;
        }
        let deadline = Instant::now() + Duration::from_millis(attempt);
        while !pending.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let received = tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await;
            let Ok(Ok((len, _))) = received else {
                break;
            };
            let Ok((transaction, address)) = stun_mapped_address(&buffer[..len]) else {
                continue;
            };
            if let Some(index) = pending.iter().position(|id| *id == transaction) {
                pending.remove(index);
                if !found.contains(&address) {
                    found.push(address);
                }
            }
        }
    }
    Ok(found)
}

fn stun_mapped_address(data: &[u8]) -> Result<([u8; 12], SocketAddr), io::Error> {
    if data.len() < STUN_HEADER_LEN {
        return Err(io::Error::other("STUN message too short"));
    }
    if u32::from_be_bytes([data[4], data[5], data[6], data[7]]) != STUN_MAGIC_COOKIE {
        return Err(io::Error::other("invalid STUN magic cookie"));
    }
    let attribute_len = usize::from(u16::from_be_bytes([data[2], data[3]]));
    if data.len() < STUN_HEADER_LEN + attribute_len {
        return Err(io::Error::other("truncated STUN message"));
    }
    let transaction: [u8; 12] = data[8..20].try_into().expect("transaction id");
    let mut body = &data[STUN_HEADER_LEN..STUN_HEADER_LEN + attribute_len];
    while body.len() >= 4 {
        let attribute = u16::from_be_bytes([body[0], body[1]]);
        let length = usize::from(u16::from_be_bytes([body[2], body[3]]));
        let padded = (length + 3) & !3;
        if 4 + padded > body.len() {
            return Err(io::Error::other("truncated STUN attribute"));
        }
        let value = &body[4..4 + length];
        body = &body[4 + padded..];
        if attribute != STUN_XOR_MAPPED_ADDRESS {
            continue;
        }
        if value.len() < 4 {
            return Err(io::Error::other("short XOR-MAPPED-ADDRESS"));
        }
        let family = value[1];
        let port = u16::from_be_bytes([value[2], value[3]]) ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        let mut key = [0u8; 4 + 12];
        key[0..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        key[4..].copy_from_slice(&transaction);
        let ip = match family {
            0x01 if value.len() == 8 => {
                let mut bytes = [0u8; 4];
                for index in 0..4 {
                    bytes[index] = value[4 + index] ^ key[index];
                }
                IpAddr::V4(Ipv4Addr::from(bytes))
            }
            0x02 if value.len() == 20 => {
                let mut bytes = [0u8; 16];
                for index in 0..16 {
                    bytes[index] = value[4 + index] ^ key[index];
                }
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
            _ => return Err(io::Error::other("unsupported XOR-MAPPED-ADDRESS family")),
        };
        return Ok((transaction, SocketAddr::new(ip, port)));
    }
    Err(io::Error::other("XOR-MAPPED-ADDRESS not found"))
}

#[derive(Clone, Copy)]
struct PunchMetadata {
    nonce: [u8; PUNCH_NONCE_LEN],
    key: [u8; PUNCH_KEY_LEN],
}

impl PunchMetadata {
    fn generate() -> PunchMetadata {
        let mut nonce = [0u8; PUNCH_NONCE_LEN];
        let mut key = [0u8; PUNCH_KEY_LEN];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
        PunchMetadata { nonce, key }
    }
}

fn encode_punch(kind: u8, metadata: &PunchMetadata) -> Vec<u8> {
    let mut random = [0u8; PUNCH_SALT_LEN + 2 + PUNCH_MAX_PADDING];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random);
    let padding_len =
        (usize::from(u16::from_be_bytes([random[8], random[9]]))) % (PUNCH_MAX_PADDING + 1);
    let mut packet = Vec::with_capacity(PUNCH_SALT_LEN + PUNCH_MIN_BODY_LEN + padding_len);
    packet.extend_from_slice(&random[..PUNCH_SALT_LEN]);
    let mut body = Vec::with_capacity(PUNCH_MIN_BODY_LEN + padding_len);
    body.extend_from_slice(&PUNCH_MAGIC);
    body.push(kind);
    body.extend_from_slice(&metadata.nonce);
    body.extend_from_slice(&random[PUNCH_SALT_LEN + 2..PUNCH_SALT_LEN + 2 + padding_len]);
    let key = punch_key(&metadata.key, &random[..PUNCH_SALT_LEN]);
    for (index, byte) in body.iter().enumerate() {
        packet.push(byte ^ key[index % key.len()]);
    }
    packet
}

fn decode_punch(data: &[u8], metadata: &PunchMetadata) -> Option<u8> {
    if data.len() < PUNCH_MIN_PACKET_LEN
        || data.len() > PUNCH_SALT_LEN + PUNCH_MIN_BODY_LEN + PUNCH_MAX_PADDING
    {
        return None;
    }
    let key = punch_key(&metadata.key, &data[..PUNCH_SALT_LEN]);
    let mut body = vec![0u8; data.len() - PUNCH_SALT_LEN];
    for index in 0..body.len() {
        body[index] = data[PUNCH_SALT_LEN + index] ^ key[index % key.len()];
    }
    if body[..8] != PUNCH_MAGIC {
        return None;
    }
    let kind = body[8];
    if kind != PUNCH_HELLO && kind != PUNCH_ACK {
        return None;
    }
    if body[9..9 + PUNCH_NONCE_LEN] != metadata.nonce {
        return None;
    }
    Some(kind)
}

fn punch_key(key: &[u8; PUNCH_KEY_LEN], salt: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(salt);
    hasher.finalize().into()
}

async fn punch(
    socket: &UdpSocket,
    peer_addresses: &[SocketAddr],
    metadata: &PunchMetadata,
) -> Result<SocketAddr, DialError> {
    let candidates = candidate_punch_addresses(peer_addresses);
    if candidates.is_empty() {
        return Err(handshake("no compatible peer addresses"));
    }
    let deadline = Instant::now() + PUNCH_TIMEOUT;
    let mut buffer = [0u8; PUNCH_SALT_LEN + PUNCH_MIN_BODY_LEN + PUNCH_MAX_PADDING];
    let mut next_send = Instant::now();
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(handshake("realm punch timeout"));
        }
        if now >= next_send {
            for candidate in &candidates {
                let hello = encode_punch(PUNCH_HELLO, metadata);
                let _ = socket.send_to(&hello, candidate).await;
            }
            next_send = now + PUNCH_INTERVAL;
        }
        let wake = next_send.min(deadline);
        let remaining = wake.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await {
            Err(_) => continue,
            Ok(Err(error)) => {
                return Err(DialError::Connect {
                    addr: "realm punch".to_string(),
                    source: error,
                })
            }
            Ok(Ok((len, from))) => {
                let Some(kind) = decode_punch(&buffer[..len], metadata) else {
                    continue;
                };
                if kind == PUNCH_HELLO {
                    let ack = encode_punch(PUNCH_ACK, metadata);
                    let _ = socket.send_to(&ack, from).await;
                }
                return Ok(from);
            }
        }
    }
}

fn candidate_punch_addresses(peer_addresses: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut seen = std::collections::HashSet::new();
    let mut candidates: Vec<SocketAddr> = Vec::new();
    for address in peer_addresses {
        if address.port() == 0 {
            continue;
        }
        if seen.insert(*address) {
            candidates.push(*address);
        }
    }
    // Symmetric NAT: a run of ports at most 4 apart is expanded by 4 extra
    // ports (at most 32 per host), the pinned `expandSymmetricNATCandidates`.
    let mut ports_by_ip: std::collections::HashMap<IpAddr, Vec<u16>> =
        std::collections::HashMap::new();
    for address in &candidates {
        if address.is_ipv4() {
            ports_by_ip
                .entry(address.ip())
                .or_default()
                .push(address.port());
        }
    }
    for (ip, mut ports) in ports_by_ip {
        ports.sort_unstable();
        ports.dedup();
        if ports.len() < 2 || ports.windows(2).any(|pair| pair[1] - pair[0] > 4) {
            continue;
        }
        let start = u32::from(ports[0]);
        let mut end = u32::from(ports[ports.len() - 1]) + 4;
        end = end.min(65535);
        let mut added = 0;
        let mut port = start;
        while port <= end && added < 32 {
            let address = SocketAddr::new(ip, port as u16);
            if seen.insert(address) {
                candidates.push(address);
                added += 1;
            }
            port += 1;
        }
    }
    candidates
}

#[derive(Deserialize)]
struct ConnectResponse {
    #[serde(default)]
    addresses: Vec<String>,
    #[serde(default)]
    nonce: String,
    #[serde(default)]
    obfs: String,
}

struct DecodedConnect {
    addresses: Vec<SocketAddr>,
    metadata: PunchMetadata,
}

async fn control_connect(
    url: &ControlUrl,
    realm: &Hysteria2Realm,
    realm_id: &str,
    local_addresses: &[SocketAddr],
    metadata: &PunchMetadata,
    timeout: Duration,
    tls_client: &ClientTls,
) -> Result<DecodedConnect, DialError> {
    if timeout.is_zero() {
        return Err(DialError::Timeout(timeout));
    }
    let body = serde_json::json!({
        "addresses": local_addresses
            .iter()
            .map(|address| address.to_string())
            .collect::<Vec<_>>(),
        "nonce": hex::encode(metadata.nonce),
        "obfs": hex::encode(metadata.key),
    });
    let path = format!("{}/v1/{}/connect", url.base, urlencode_path(realm_id));
    let token = realm.token.as_ref().map(|token| token.expose());
    let (status, response) = tokio::time::timeout(
        timeout,
        http_post(
            url,
            &path,
            token,
            &body.to_string(),
            &realm.tls_settings,
            tls_client,
        ),
    )
    .await
    .map_err(|_| DialError::Timeout(timeout))??;
    if !(200..300).contains(&status) {
        return Err(handshake(format!(
            "realm control connect failed with status {status}: {}",
            String::from_utf8_lossy(&response)
        )));
    }
    let decoded: ConnectResponse = serde_json::from_slice(&response)
        .map_err(|error| handshake(format!("realm control response: {error}")))?;
    let nonce = hex::decode(&decoded.nonce)
        .map_err(|error| handshake(format!("realm control nonce: {error}")))?;
    let key = hex::decode(&decoded.obfs)
        .map_err(|error| handshake(format!("realm control obfs: {error}")))?;
    if nonce.len() != PUNCH_NONCE_LEN || key.len() != PUNCH_KEY_LEN {
        return Err(handshake("realm control metadata has the wrong length"));
    }
    let mut peer = PunchMetadata {
        nonce: [0u8; PUNCH_NONCE_LEN],
        key: [0u8; PUNCH_KEY_LEN],
    };
    peer.nonce.copy_from_slice(&nonce);
    peer.key.copy_from_slice(&key);
    let mut addresses = Vec::with_capacity(decoded.addresses.len());
    for address in decoded.addresses {
        addresses.push(
            address
                .parse()
                .map_err(|_| handshake(format!("realm control address '{address}' is invalid")))?,
        );
    }
    Ok(DecodedConnect {
        addresses,
        metadata: peer,
    })
}

fn urlencode_path(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

async fn http_post(
    url: &ControlUrl,
    path: &str,
    token: Option<&str>,
    body: &str,
    settings: &crate::proxies::TlsSettings,
    tls_client: &ClientTls,
) -> Result<(u16, Vec<u8>), DialError> {
    let stream = connect_tcp(&url.host, url.port).await?;
    let mut stream: Box<dyn super::Stream> = if url.tls {
        // The control client speaks HTTP/1.1. The pinned HTTP client enables
        // h2 as well; this path only offers h2 when the block explicitly asks
        // for it, and refuses a server that then selects it instead of
        // speaking a protocol it does not implement.
        let mut settings = settings.clone();
        if settings.alpn.is_empty() {
            settings.alpn = vec!["http/1.1".to_string()];
        }
        let stream = tls::wrap(stream, &url.host, &settings, tls_client)
            .await
            .map_err(|source| DialError::Handshake {
                protocol: "hysteria2 realm control tls",
                source,
            })?;
        let protocol = stream
            .get_ref()
            .1
            .alpn_protocol()
            .map(|value| value.to_vec())
            .unwrap_or_default();
        if !protocol.is_empty() && protocol != b"http/1.1" {
            return Err(handshake(format!(
                "control server negotiated ALPN {:?}; only HTTP/1.1 is implemented",
                String::from_utf8_lossy(&protocol)
            )));
        }
        Box::new(stream)
    } else {
        Box::new(stream)
    };
    let host = if url.port == default_port(url.tls) {
        url.host.clone()
    } else {
        format!("{}:{}", url.host, url.port)
    };
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(token) = token {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|source| DialError::Connect {
            addr: "realm control".to_string(),
            source,
        })?;
    stream.flush().await.ok();
    let mut response = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|source| DialError::Connect {
                addr: "realm control".to_string(),
                source,
            })?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read]);
        if response.len() > MAX_HTTP_BODY {
            return Err(handshake("realm control response is too large"));
        }
    }
    parse_http_response(&response)
}

fn parse_http_response(response: &[u8]) -> Result<(u16, Vec<u8>), DialError> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| handshake("realm control response has no header"))?;
    let head = String::from_utf8_lossy(&response[..header_end]);
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| handshake("realm control response has no status line"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| handshake(format!("invalid status line '{status_line}'")))?;
    let mut chunked = false;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }
    let body = &response[header_end + 4..];
    if !chunked {
        return Ok((status, body.to_vec()));
    }
    let mut decoded = Vec::new();
    let mut offset = 0;
    while offset < body.len() {
        let line_end = body[offset..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|index| offset + index)
            .ok_or_else(|| handshake("truncated chunked response"))?;
        let size_text = String::from_utf8_lossy(&body[offset..line_end]);
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| handshake("invalid chunk size"))?;
        offset = line_end + 2;
        if size == 0 {
            break;
        }
        if offset + size > body.len() {
            return Err(handshake("truncated chunk"));
        }
        decoded.extend_from_slice(&body[offset..offset + size]);
        offset += size + 2;
    }
    Ok((status, decoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_urls_keep_scheme_port_and_base_path() {
        let url = parse_url("https://realm.example/v1base/").unwrap();
        assert!(url.tls);
        assert_eq!(url.host, "realm.example");
        assert_eq!(url.port, 443);
        assert_eq!(url.base, "/v1base");
        let url = parse_url("http://127.0.0.1:8080").unwrap();
        assert!(!url.tls);
        assert_eq!(url.port, 8080);
        assert_eq!(url.base, "");
        assert!(parse_url("ftp://realm.example").is_err());
        assert!(parse_url("realm.example").is_err());
    }

    #[test]
    fn punch_packets_round_trip_and_reject_a_wrong_key() {
        let metadata = PunchMetadata::generate();
        let hello = encode_punch(PUNCH_HELLO, &metadata);
        assert_eq!(decode_punch(&hello, &metadata), Some(PUNCH_HELLO));
        let ack = encode_punch(PUNCH_ACK, &metadata);
        assert_eq!(decode_punch(&ack, &metadata), Some(PUNCH_ACK));
        let other = PunchMetadata::generate();
        assert_eq!(decode_punch(&hello, &other), None);
        // The pinned magic is part of the XOR-obfuscated body, not the header.
        assert_ne!(&hello[..8], &PUNCH_MAGIC);
    }

    #[test]
    fn stun_response_decodes_the_xor_mapped_address() {
        let transaction = [7u8; 12];
        let mut response = Vec::new();
        response.extend_from_slice(&0x0101u16.to_be_bytes());
        response.extend_from_slice(&12u16.to_be_bytes());
        response.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&transaction);
        response.extend_from_slice(&STUN_XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&8u16.to_be_bytes());
        response.push(0);
        response.push(0x01);
        let port = 1234u16 ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        response.extend_from_slice(&port.to_be_bytes());
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        for (index, byte) in [127u8, 0, 0, 1].iter().enumerate() {
            response.push(byte ^ cookie[index]);
        }
        let (id, address) = stun_mapped_address(&response).unwrap();
        assert_eq!(id, transaction);
        assert_eq!(address, "127.0.0.1:1234".parse().unwrap());
    }

    #[test]
    fn http_responses_decode_content_length_and_chunked_bodies() {
        let response = b"HTTP/1.1 204 No Content\r\n\r\n";
        assert_eq!(parse_http_response(response).unwrap().0, 204);
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let (status, body) = parse_http_response(chunked).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"hello");
        assert!(parse_http_response(b"not http").is_err());
    }

    #[test]
    fn symmetric_nat_candidates_extend_a_close_port_run() {
        let peers: Vec<SocketAddr> = ["127.0.0.1:1000", "127.0.0.1:1002"]
            .iter()
            .map(|address| address.parse().unwrap())
            .collect();
        let candidates = candidate_punch_addresses(&peers);
        assert!(candidates.contains(&"127.0.0.1:1006".parse().unwrap()));
        let far = candidate_punch_addresses(&["127.0.0.1:1000".parse().unwrap()]);
        assert_eq!(far.len(), 1);
    }
}
