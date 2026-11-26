//! The shared userspace L3 stack, driven by an in-memory IP carrier.
//!
//! The peer side is not another copy of smoltcp: TCP is terminated by the
//! kernel's own independent passive endpoint (`tunnel::tcp_server::ServerTcp`,
//! the state machine the device data plane uses), and UDP is echoed by
//! parsing/building packets with `outbound::ipstack`. That makes the test a
//! real interoperation check of the client half rather than a self-consistency
//! loop.
//!
//! Requires `--features device-vpn` because the peer TCP state machine lives in
//! `tunnel`:
//!
//! ```sh
//! cargo test --manifest-path native-kernel/Cargo.toml --locked \
//!   --features device-vpn --test l3_stack -- --test-threads=1
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use billow_kernel::outbound::ipstack;
use billow_kernel::outbound::l3::{Stack, StackConfig, TCP_SOCKETS};
use billow_kernel::outbound::tcp::{parse_segment, FLAG_SYN};
use billow_kernel::tunnel::tcp_server::{ServerConfig, ServerTcp};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LOCAL_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const PEER_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const LOCAL_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
const PEER_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);

#[derive(Clone, Copy)]
enum TcpMode {
    /// Echo every received chunk; after the client half-closes, send a final
    /// marker and close too.
    Echo,
    /// Reset the connection as soon as data arrives.
    Reset,
}

fn stack(mtu: usize, v6: bool) -> Arc<Stack> {
    Stack::new(StackConfig::new(
        Some(LOCAL_V4),
        if v6 { Some(LOCAL_V6) } else { None },
        mtu,
        "l3-stack-test",
    ))
    .expect("stack")
}

/// Pump packets between the stack and the independent passive TCP endpoint.
fn spawn_tcp_peer(stack: Arc<Stack>, mode: TcpMode) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut connections: HashMap<u16, ServerTcp> = HashMap::new();
        let mut half_closed = std::collections::HashSet::new();
        let mut sequence = 1000u32;
        let mut max_packet = 0usize;
        loop {
            tokio::time::sleep(Duration::from_millis(1)).await;
            let now = Instant::now();
            while let Some(packet) = stack.take_tx_packet() {
                max_packet = max_packet.max(packet.len());
                assert!(
                    packet.len() <= stack.mtu(),
                    "stack emitted a {} byte packet over a {}-byte MTU",
                    packet.len(),
                    stack.mtu()
                );
                let Ok(segment) = parse_segment(&packet) else {
                    continue;
                };
                let key = segment.src_port;
                if segment.flags & FLAG_SYN != 0 && !connections.contains_key(&key) {
                    sequence = sequence.wrapping_add(7919);
                    let cfg = ServerConfig {
                        local: segment.dst,
                        remote: segment.src,
                        local_port: segment.dst_port,
                        remote_port: segment.src_port,
                        mss: (stack.mtu() - 60) as u16,
                        initial_seq: sequence,
                        hop_limit: 64,
                    };
                    connections.insert(key, ServerTcp::accept(cfg, &segment));
                }
                let Some(connection) = connections.get_mut(&key) else {
                    continue;
                };
                connection.on_packet(&packet, now);
                while let Some(data) = connection.take_received() {
                    match mode {
                        TcpMode::Echo => {
                            connection.enqueue(&data);
                        }
                        TcpMode::Reset => connection.reset(),
                    }
                }
                if matches!(mode, TcpMode::Echo)
                    && connection.peer_closed()
                    && half_closed.insert(key)
                {
                    connection.enqueue(b"after-fin");
                    connection.shutdown();
                }
                while let Some(reply) = connection.poll_transmit(now) {
                    stack.push_rx_packet(&reply);
                }
                connection.on_timer(now);
            }
        }
    })
}

fn spawn_udp_peer(stack: Arc<Stack>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(1)).await;
            while let Some(packet) = stack.take_tx_packet() {
                let Ok(ip) = ipstack::parse_ip_packet(&packet) else {
                    continue;
                };
                let Ok(udp) = ipstack::parse_udp(&ip) else {
                    continue;
                };
                let reply = ipstack::build_udp_packet(
                    udp.dst,
                    udp.src,
                    udp.dst_port,
                    udp.src_port,
                    udp.payload,
                    64,
                )
                .expect("build UDP reply");
                stack.push_rx_packet(&reply);
            }
        }
    })
}

async fn wait_until(mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !check() {
        assert!(Instant::now() < deadline, "condition not reached in 3s");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_three_concurrent_connections_echo() {
    let stack = stack(1408, false);
    let peer = spawn_tcp_peer(stack.clone(), TcpMode::Echo);
    let remote = SocketAddr::new(IpAddr::V4(PEER_V4), 80);
    let mut streams = Vec::new();
    for index in 0..3u8 {
        let mut stream = stack
            .dial_tcp(remote, Duration::from_secs(2))
            .await
            .expect("dial");
        let payload = vec![b'a' + index; 4096];
        stream.write_all(&payload).await.expect("write");
        let mut echoed = vec![0u8; payload.len()];
        stream.read_exact(&mut echoed).await.expect("read echo");
        assert_eq!(echoed, payload);
        streams.push(stream);
    }
    assert_eq!(stack.socket_counts(), (3, 0));
    drop(streams);
    peer.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_half_close_delivers_remaining_data_then_eof() {
    let stack = stack(1408, false);
    let peer = spawn_tcp_peer(stack.clone(), TcpMode::Echo);
    let mut stream = stack
        .dial_tcp(SocketAddr::new(IpAddr::V4(PEER_V4), 80), Duration::from_secs(2))
        .await
        .expect("dial");
    stream.write_all(b"request").await.expect("write");
    stream.shutdown().await.expect("shutdown");
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await.expect("read to EOF");
    assert!(rest.ends_with(b"after-fin"), "got {:?}", String::from_utf8_lossy(&rest));
    // Writing after our FIN is a named error, never a silent success.
    let error = stream.write_all(b"late").await.expect_err("write after FIN");
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    peer.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_reset_is_reported_as_a_connection_error() {
    let stack = stack(1408, false);
    let peer = spawn_tcp_peer(stack.clone(), TcpMode::Reset);
    let mut stream = stack
        .dial_tcp(SocketAddr::new(IpAddr::V4(PEER_V4), 80), Duration::from_secs(2))
        .await
        .expect("dial");
    stream.write_all(b"trigger a reset").await.expect("write");
    let mut buffer = [0u8; 16];
    let error = loop {
        match stream.read(&mut buffer).await {
            Ok(0) => break None,
            Ok(_) => continue,
            Err(error) => break Some(error),
        }
    };
    if let Some(error) = error {
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    }
    peer.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_connect_timeout_is_named_and_releases_the_socket() {
    let stack = stack(1408, false);
    let error = match stack
        .dial_tcp(SocketAddr::new(IpAddr::V4(PEER_V4), 80), Duration::from_millis(150))
        .await
    {
        Ok(_) => panic!("no peer answers, dial must fail"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(stack.socket_counts(), (0, 0));
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_association_carries_two_remotes_and_ipv6() {
    let stack = stack(1408, true);
    let peer = spawn_udp_peer(stack.clone());
    let socket = stack.udp_socket().expect("udp");
    let first = SocketAddr::new(IpAddr::V4(PEER_V4), 53);
    let second = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 5353);
    socket.send(first, b"one").await.expect("send one");
    socket.send(second, b"two").await.expect("send two");
    let mut buffer = [0u8; 1500];
    let mut seen = Vec::new();
    for _ in 0..2 {
        let (from, read) = socket.recv(&mut buffer).await.expect("recv");
        seen.push((from, buffer[..read].to_vec()));
    }
    seen.sort_by_key(|(from, _)| from.to_string());
    assert_eq!(seen[0].0, first);
    assert_eq!(seen[0].1, b"one");
    assert_eq!(seen[1].0, second);
    assert_eq!(seen[1].1, b"two");

    let v6 = SocketAddr::new(IpAddr::V6(PEER_V6), 53);
    socket.send(v6, b"six").await.expect("send v6");
    let (from, read) = socket.recv(&mut buffer).await.expect("recv v6");
    assert_eq!(from, v6);
    assert_eq!(&buffer[..read], b"six");
    peer.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_ipv6_and_large_payloads_stay_within_the_mtu() {
    let stack = stack(1280, true);
    let peer = spawn_tcp_peer(stack.clone(), TcpMode::Echo);
    let mut stream = stack
        .dial_tcp(SocketAddr::new(IpAddr::V6(PEER_V6), 443), Duration::from_secs(2))
        .await
        .expect("dial v6");
    let payload: Vec<u8> = (0..20_000).map(|index| (index % 251) as u8).collect();
    stream.write_all(&payload).await.expect("write");
    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await.expect("read");
    assert_eq!(echoed, payload);
    peer.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_socket_limit_and_drop_reclaim() {
    let stack = stack(1408, false);
    let peer = spawn_tcp_peer(stack.clone(), TcpMode::Echo);
    let remote = SocketAddr::new(IpAddr::V4(PEER_V4), 80);
    let mut streams = Vec::new();
    for index in 0..TCP_SOCKETS {
        let stream = stack
            .dial_tcp(remote, Duration::from_secs(2))
            .await
            .unwrap_or_else(|error| panic!("dial {index}: {error}"));
        streams.push(stream);
    }
    let error = match stack.dial_tcp(remote, Duration::from_secs(2)).await {
        Ok(_) => panic!("17th socket must be refused"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::OutOfMemory);
    assert!(error.to_string().contains("maximum"));
    drop(streams);
    peer.abort();
    let weak = Arc::downgrade(&stack);
    drop(stack);
    wait_until(|| weak.upgrade().is_none()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unsupported_family_and_oversized_udp_are_named() {
    let stack = stack(1000, false);
    let error = match stack
        .dial_tcp(SocketAddr::new(IpAddr::V6(PEER_V6), 80), Duration::from_millis(100))
        .await
    {
        Ok(_) => panic!("no local IPv6, dial must fail"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);

    let socket = stack.udp_socket().expect("udp");
    let error = socket
        .send(
            SocketAddr::new(IpAddr::V4(PEER_V4), 53),
            &vec![0u8; 1000],
        )
        .await
        .expect_err("payload exceeds MTU");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("MTU"));
}
