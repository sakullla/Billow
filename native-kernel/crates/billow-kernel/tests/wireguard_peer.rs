//! WireGuard transport interoperability with a controlled locked-source peer.
//!
//! The peer is `tool/kernel-compat/peers/wireguard-peer`, a userspace device
//! built from the locked `github.com/metacubex/wireguard-go` (the device the
//! pinned Mihomo runs behind its `wireguard` outbound). Its fake TUN answers
//! IPv4 ICMP echo requests, echoes IPv4 UDP datagrams and runs a minimal IPv4
//! TCP responder, so the Rust side proves the Noise IK handshake, the transport
//! keys, the shared userspace L3 stack's TCP/UDP paths and `allowed-ips` peer
//! selection.
//!
//! Controlled entry point:
//!
//! ```sh
//! tool/kernel-compat/family-peers.sh wireguard_peer
//! # or
//! KC_WIREGUARD_PEER_BIN=/path/to/wireguard-peer cargo test \
//!   --manifest-path native-kernel/Cargo.toml --locked \
//!   --test wireguard_peer -- --ignored --test-threads=1
//! ```
//!
//! Without `KC_WIREGUARD_PEER_BIN` the cases print SKIP and never pass.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use billow_kernel::keys::Secret;
use billow_kernel::outbound::wireguard::{
    connect_carrier, connect_stack, derive_public_key, encode_key, WireguardError, WireguardPeer,
    WireguardTunnel,
};
use billow_kernel::proxies::{WireguardOutbound, WireguardPeerOutbound};

struct Peer {
    child: Child,
    endpoint: SocketAddr,
    public_key: String,
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn peer_bin() -> Option<std::path::PathBuf> {
    std::env::var_os("KC_WIREGUARD_PEER_BIN").map(std::path::PathBuf::from)
}

fn start_peer(client_public_key: &str) -> Option<Peer> {
    start_peer_with(client_public_key, None)
}

fn start_peer_with(client_public_key: &str, preshared_key: Option<&str>) -> Option<Peer> {
    let bin = peer_bin()?;
    let mut command = Command::new(bin);
    command.args(["-listen", "127.0.0.1:0", "-client-key", client_public_key]);
    if let Some(preshared) = preshared_key {
        command.args(["-preshared-key", preshared]);
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn wireguard peer");
    let stdout = child.stdout.take().expect("peer stdout");
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("read peer READY line");
    let fields: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(fields.first().copied(), Some("READY"), "{line}");
    let port: u16 = fields[1].parse().expect("peer port");
    Some(Peer {
        child,
        endpoint: SocketAddr::from(([127, 0, 0, 1], port)),
        public_key: fields[2].to_string(),
    })
}

fn icmp_echo(identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 20 + 8 + payload.len()];
    packet[0] = 0x45;
    let total = packet.len() as u16;
    packet[2..4].copy_from_slice(&total.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1; // ICMP
    packet[12..16].copy_from_slice(&[10, 13, 13, 2]);
    packet[16..20].copy_from_slice(&[10, 13, 13, 1]);
    let header = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header.to_be_bytes());
    packet[20] = 8; // echo request
    packet[24..26].copy_from_slice(&identifier.to_be_bytes());
    packet[26..28].copy_from_slice(&sequence.to_be_bytes());
    packet[28..].copy_from_slice(payload);
    let icmp = checksum(&packet[20..]);
    packet[22..24].copy_from_slice(&icmp.to_be_bytes());
    packet
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn skip(case: &str) {
    eprintln!("SKIP {case}: KC_WIREGUARD_PEER_BIN is not set");
}

const CLIENT_PRIVATE: [u8; 32] = [7u8; 32];

fn client_public_key() -> String {
    encode_key(&derive_public_key(&CLIENT_PRIVATE))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn handshake_and_icmp_round_trip_through_the_locked_peer() {
    let Some(peer) = start_peer(&client_public_key()) else {
        return skip("handshake_and_icmp_round_trip_through_the_locked_peer");
    };
    let mut tunnel = WireguardTunnel::connect_endpoint(
        CLIENT_PRIVATE,
        WireguardPeer::from_base64(peer.endpoint, &peer.public_key, None, [0, 0, 0])
            .expect("peer key"),
        1420,
        0,
        Duration::from_secs(3),
    )
    .await
    .expect("handshake with the locked wireguard-go device");

    let request = icmp_echo(0x1234, 1, b"billow-wireguard");
    tunnel.send_packet(&request).await.expect("send echo");
    let mut buffer = vec![0u8; 1500];
    let length = tunnel.recv_packet(&mut buffer).await.expect("receive reply");
    let reply = &buffer[..length];
    assert_eq!(reply[0] >> 4, 4, "IPv4 reply");
    assert_eq!(reply[9], 1, "ICMP");
    assert_eq!(reply[12..16], [10, 13, 13, 1]);
    assert_eq!(reply[16..20], [10, 13, 13, 2]);
    assert_eq!(reply[20], 0, "echo reply");
    assert_eq!(&reply[28..], b"billow-wireguard");
    assert_eq!(checksum(&reply[..20]), 0, "IPv4 checksum");
    assert_eq!(checksum(&reply[20..]), 0, "ICMP checksum");
    // The transport keeps the counter: a second round trip must decrypt too.
    tunnel
        .send_packet(&icmp_echo(0x1234, 2, b"second"))
        .await
        .expect("send second echo");
    let length = tunnel.recv_packet(&mut buffer).await.expect("second reply");
    assert_eq!(&buffer[..length][28..], b"second");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn wrong_peer_public_key_fails_the_handshake() {
    let Some(peer) = start_peer(&client_public_key()) else {
        return skip("wrong_peer_public_key_fails_the_handshake");
    };
    // Same length and alphabet, but not the peer's key: MAC1 never verifies
    // and the peer drops the initiation, so the bounded handshake times out.
    let wrong = encode_key(&[9u8; 32]);
    let error = WireguardTunnel::connect_endpoint(
        CLIENT_PRIVATE,
        WireguardPeer::from_base64(peer.endpoint, &wrong, None, [0, 0, 0]).expect("key"),
        1420,
        0,
        Duration::from_millis(700),
    )
    .await
    .expect_err("handshake must not complete");
    assert!(
        matches!(error, WireguardError::Timeout(_)),
        "unexpected error: {error}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn an_unregistered_client_key_is_rejected() {
    let Some(peer) = start_peer(&client_public_key()) else {
        return skip("an_unregistered_client_key_is_rejected");
    };
    let other_private = [11u8; 32];
    let error = WireguardTunnel::connect_endpoint(
        other_private,
        WireguardPeer::from_base64(peer.endpoint, &peer.public_key, None, [0, 0, 0]).expect("key"),
        1420,
        0,
        Duration::from_millis(700),
    )
    .await
    .expect_err("the peer has no such public key");
    assert!(
        matches!(error, WireguardError::Timeout(_)),
        "unexpected error: {error}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn preshared_key_is_mixed_into_the_handshake() {
    let preshared = encode_key(&[3u8; 32]);
    let Some(peer) = start_peer_with(&client_public_key(), Some(&preshared)) else {
        return skip("preshared_key_is_mixed_into_the_handshake");
    };
    let mut tunnel = WireguardTunnel::connect_endpoint(
        CLIENT_PRIVATE,
        WireguardPeer::from_base64(peer.endpoint, &peer.public_key, Some(&preshared), [0, 0, 0])
            .expect("key"),
        1420,
        0,
        Duration::from_secs(3),
    )
    .await
    .expect("handshake with the configured pre-shared key");
    tunnel
        .send_packet(&icmp_echo(0x2222, 1, b"psk"))
        .await
        .expect("send");
    let mut buffer = [0u8; 1500];
    let length = tunnel.recv_packet(&mut buffer).await.expect("reply");
    assert_eq!(&buffer[..length][28..], b"psk");

    // A different pre-shared key changes the whole transcript: the peer's
    // response no longer opens, which is an explicit handshake failure.
    let wrong = encode_key(&[4u8; 32]);
    let error = WireguardTunnel::connect_endpoint(
        CLIENT_PRIVATE,
        WireguardPeer::from_base64(peer.endpoint, &peer.public_key, Some(&wrong), [0, 0, 0])
            .expect("key"),
        1420,
        0,
        Duration::from_secs(2),
    )
    .await
    .expect_err("wrong pre-shared key must fail");
    assert!(
        matches!(error, WireguardError::Handshake(_)),
        "unexpected error: {error}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn packets_over_the_mtu_and_short_buffers_are_named_errors() {
    let Some(peer) = start_peer(&client_public_key()) else {
        return skip("packets_over_the_mtu_and_short_buffers_are_named_errors");
    };
    let mut tunnel = WireguardTunnel::connect_endpoint(
        CLIENT_PRIVATE,
        WireguardPeer::from_base64(peer.endpoint, &peer.public_key, None, [0, 0, 0])
            .expect("key"),
        1420,
        0,
        Duration::from_secs(3),
    )
    .await
    .expect("handshake");

    let error = tunnel
        .send_packet(&vec![0x45u8; 1421])
        .await
        .expect_err("oversized packet");
    assert!(matches!(error, WireguardError::PacketTooLarge { .. }));

    tunnel
        .send_packet(&icmp_echo(0x4321, 9, b"short"))
        .await
        .expect("send");
    let mut small = [0u8; 8];
    let error = tunnel
        .recv_packet(&mut small)
        .await
        .expect_err("short buffer");
    assert!(matches!(error, WireguardError::BufferTooSmall { .. }));

    // The failed receive must not corrupt the session: the next call with a
    // large enough buffer still decrypts a fresh reply.
    tunnel
        .send_packet(&icmp_echo(0x4321, 10, b"after"))
        .await
        .expect("send after short buffer");
    let mut buffer = [0u8; 1500];
    let length = tunnel.recv_packet(&mut buffer).await.expect("reply");
    assert_eq!(&buffer[..length][28..], b"after");
}


fn wireguard_outbound(peers: &[(SocketAddr, &str, &str)]) -> WireguardOutbound {
    WireguardOutbound {
        private_key: Secret::new(encode_key(&CLIENT_PRIVATE)),
        ip: Some("10.13.13.2".to_string()),
        ipv6: None,
        workers: 0,
        mtu: 1420,
        udp: true,
        persistent_keepalive: 0,
        peers: peers
            .iter()
            .map(|(endpoint, public_key, allowed)| WireguardPeerOutbound {
                server: endpoint.ip().to_string(),
                port: endpoint.port(),
                public_key: (*public_key).to_string(),
                preshared_key: None,
                reserved: Vec::new(),
                allowed_ips: vec![(*allowed).to_string()],
            })
            .collect(),
    }
}

/// Real UDP through the userspace L3 stack and the locked wireguard-go device:
/// the peer's fake TUN echoes the datagram, so this proves the packet carrier,
/// smoltcp's UDP socket, the source address and the return path together.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn udp_round_trip_through_the_locked_peer_and_l3_stack() {
    let Some(peer) = start_peer(&client_public_key()) else {
        return skip("udp_round_trip_through_the_locked_peer_and_l3_stack");
    };
    let outbound = wireguard_outbound(&[(peer.endpoint, &peer.public_key, "10.13.13.1/32")]);
    let stack = connect_stack(&outbound, Duration::from_secs(3))
        .await
        .expect("stack + handshake");
    let socket = stack.udp_socket().expect("udp socket");
    let remote = SocketAddr::from(([10, 13, 13, 1], 5353));
    socket.send(remote, b"through-wireguard").await.expect("send");
    let mut buffer = [0u8; 1500];
    let (from, read) = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buffer))
        .await
        .expect("reply within 3s")
        .expect("recv");
    assert_eq!(from, remote);
    assert_eq!(&buffer[..read], b"through-wireguard");
}

/// Two peers with disjoint `allowed-ips`: the egress dispatcher must pick the
/// peer by longest prefix instead of always using the first one.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn multiple_peers_select_by_allowed_ips() {
    let Some(first) = start_peer(&client_public_key()) else {
        return skip("multiple_peers_select_by_allowed_ips");
    };
    let Some(second) = start_peer(&client_public_key()) else {
        return;
    };
    let outbound = wireguard_outbound(&[
        (first.endpoint, &first.public_key, "10.13.13.1/32"),
        (second.endpoint, &second.public_key, "10.14.14.1/32"),
    ]);
    let stack = connect_stack(&outbound, Duration::from_secs(3))
        .await
        .expect("stack + two handshakes");
    let socket = stack.udp_socket().expect("udp socket");
    let mut buffer = [0u8; 1500];
    for (octet, payload) in [(13u8, b"peer-one".as_slice()), (14u8, b"peer-two".as_slice())] {
        let remote = SocketAddr::from(([10, octet, octet, 1], 5353));
        socket.send(remote, payload).await.expect("send");
        let (from, read) = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buffer))
            .await
            .expect("reply within 3s")
            .expect("recv");
        assert_eq!(from, remote);
        assert_eq!(&buffer[..read], payload);
    }
}


/// Real TCP through the userspace L3 stack and the locked wireguard-go device.
/// The peer's fake TUN runs a minimal TCP responder, so the SYN/SYN-ACK,
/// data, ACK and echo all cross the real WireGuard transport.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn tcp_round_trip_through_the_locked_peer_and_l3_stack() {
    let Some(peer) = start_peer(&client_public_key()) else {
        return skip("tcp_round_trip_through_the_locked_peer_and_l3_stack");
    };
    let outbound = wireguard_outbound(&[(peer.endpoint, &peer.public_key, "10.13.13.1/32")]);
    let stack = connect_stack(&outbound, Duration::from_secs(3))
        .await
        .expect("stack + handshake");
    let mut stream = stack
        .dial_tcp(
            SocketAddr::from(([10, 13, 13, 1], 8080)),
            Duration::from_secs(3),
        )
        .await
        .expect("tcp connect through wireguard");
    let payload = b"tcp-through-wireguard";
    stream.write_all(payload).await.expect("write");
    let mut echo = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut echo))
        .await
        .expect("echo within 3s")
        .expect("read echo");
    assert_eq!(&echo, payload);
}

/// One live peer and one dead endpoint: building the stack and using the live
/// peer must both succeed, while a dial routed to the dead peer fails by name.
/// This is the lazy per-peer handshake contract: no eager handshake of every
/// configured peer, and no stack-wide failure when one peer is down.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn a_dead_peer_does_not_block_the_live_peer_or_allow_fallback() {
    let Some(live) = start_peer(&client_public_key()) else {
        return skip("a_dead_peer_does_not_block_the_live_peer_or_allow_fallback");
    };
    let dead = "127.0.0.1:1".parse::<SocketAddr>().expect("dead endpoint");
    let outbound = wireguard_outbound(&[
        (live.endpoint, &live.public_key, "10.13.13.1/32"),
        // A public key that is syntactically valid but belongs to nobody; the
        // endpoint is closed too.
        (dead, &client_public_key(), "10.14.14.1/32"),
    ]);
    // Building the carrier must not touch the dead peer.
    let carrier = connect_carrier(&outbound, Duration::from_secs(3))
        .await
        .expect("stack with one dead peer");
    let stack = carrier.stack();

    // UDP to the live peer starts that peer's handshake lazily.
    let socket = stack.udp_socket().expect("udp socket");
    let live_target = SocketAddr::from(([10, 13, 13, 1], 5353));
    socket.send(live_target, b"lazy-live").await.expect("send");
    let mut buffer = [0u8; 1500];
    let (from, read) = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buffer))
        .await
        .expect("live reply within 3s")
        .expect("recv");
    assert_eq!(from, live_target);
    assert_eq!(&buffer[..read], b"lazy-live");

    // A UDP destination outside every allowed-ips prefix is refused by name
    // at the association, not silently dropped by the dispatcher.
    let uncovered = SocketAddr::from(([10, 99, 99, 99], 53));
    let error = socket
        .send(uncovered, b"no-route")
        .await
        .err()
        .expect("UDP destination outside allowed-ips must be refused");
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    assert!(error.to_string().contains("no route"), "{error}");

    // A TCP dial to the live peer (already connected) succeeds.
    let target = billow_kernel::outbound::Target {
        host: "10.13.13.1".to_string(),
        port: 8080,
    };
    let mut stream = tokio::time::timeout(
        Duration::from_secs(3),
        billow_kernel::outbound::wireguard::dial(&outbound, &target, Duration::from_secs(3)),
    )
    .await
    .expect("live dial within 3s")
    .expect("live dial");
    assert_eq!(stream.server, live.endpoint, "Dialed.server is the resolved peer");
    stream.stream.write_all(b"live-tcp").await.expect("write");
    let mut echo = [0u8; 8];
    stream
        .stream
        .read_exact(&mut echo)
        .await
        .expect("live tcp echo");
    assert_eq!(&echo, b"live-tcp");

    // The dead peer is selected by allowed-ips but its handshake fails; the
    // error is a WireGuard handshake failure and it does not fall back.
    let dead_target = billow_kernel::outbound::Target {
        host: "10.14.14.1".to_string(),
        port: 8080,
    };
    let error = billow_kernel::outbound::wireguard::dial(
        &outbound,
        &dead_target,
        Duration::from_millis(700),
    )
    .await
    .err()
    .expect("dead peer must fail");
    let text = error.to_string();
    assert!(text.contains("wireguard"), "{text}");
    assert!(text.contains("handshake"), "{text}");

    // The live peer is unaffected by the dead peer's failure.
    let mut again = tokio::time::timeout(
        Duration::from_secs(3),
        billow_kernel::outbound::wireguard::dial(&outbound, &target, Duration::from_secs(3)),
    )
    .await
    .expect("second live dial")
    .expect("second live dial");
    again.stream.write_all(b"still").await.expect("write");
    let mut echo = [0u8; 5];
    again
        .stream
        .read_exact(&mut echo)
        .await
        .expect("second echo");
    assert_eq!(&echo, b"still");
}
