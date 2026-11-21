//! T19 mesh adapters against controlled locked-source peers.
//!
//! The peers live in `tool/kernel-compat/peers/{zerotier,easytier,tailscale}-peer`
//! and are built by `tool/kernel-compat/family-peers.sh`. Every case is
//! `#[ignore]`d and prints SKIP without its environment variable, so the
//! default `cargo test` stays hermetic.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use billow_kernel::outbound::easytier::{EasytierSession, EasytierError};
use billow_kernel::outbound::tailscale::{
    derp, DerpClient, TailscaleControl, TailscaleError,
};
use billow_kernel::outbound::tls::ClientTls;
use billow_kernel::outbound::zerotier::{self, Identity, ZerotierError};
use tokio::net::{TcpStream, UdpSocket};

struct Peer {
    child: Child,
    port: u16,
    token: String,
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(bin: &str, args: &[&str]) -> Peer {
    let mut child = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn peer");
    let stdout = child.stdout.take().expect("peer stdout");
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("read READY line");
    let fields: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(fields.first().copied(), Some("READY"), "{line}");
    let port = fields
        .get(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("peer port: {line}"));
    let token = fields.get(2).map(|s| s.to_string()).unwrap_or_default();
    Peer { child, port, token }
}

fn env_bin(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn skip(case: &str, name: &str) {
    eprintln!("SKIP {case}: {name} is not set");
}

#[tokio::test]
#[ignore]
async fn zerotier_hello_success_and_failure() {
    let Some(bin) = env_bin("KC_ZEROTIER_PEER_BIN") else {
        return skip("zerotier", "KC_ZEROTIER_PEER_BIN");
    };
    let peer = start(&bin, &["-mode", "ok"]);
    let peer_identity = Identity::parse(&peer.token).expect("peer identity");
    let local = Identity::generate();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address: SocketAddr = format!("127.0.0.1:{}", peer.port).parse().unwrap();
    let hello = zerotier::handshake(
        &socket,
        &local,
        &peer_identity,
        address,
        (1, 2),
        false,
        Duration::from_secs(5),
    )
    .await
    .expect("HELLO/OK");
    assert_eq!(hello.address, peer_identity.address());
    assert_eq!(hello.protocol_version, zerotier::PROTOCOL_VERSION);

    // A peer that arms the OK with a different key must fail authentication.
    let bad = start(&bin, &["-mode", "wrong-key"]);
    let bad_identity = Identity::parse(&bad.token).expect("bad peer identity");
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address: SocketAddr = format!("127.0.0.1:{}", bad.port).parse().unwrap();
    let error = zerotier::handshake(
        &socket,
        &local,
        &bad_identity,
        address,
        (1, 2),
        false,
        Duration::from_secs(3),
    )
    .await
    .expect_err("wrong key must fail");
    assert!(
        matches!(error, ZerotierError::Authentication | ZerotierError::Timeout),
        "{error}"
    );

    // A truncated datagram is a boundary, not a silent success.
    let truncated = start(&bin, &["-mode", "truncated"]);
    let truncated_identity = Identity::parse(&truncated.token).expect("truncated identity");
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address: SocketAddr = format!("127.0.0.1:{}", truncated.port).parse().unwrap();
    let error = zerotier::handshake(
        &socket,
        &local,
        &truncated_identity,
        address,
        (1, 2),
        false,
        Duration::from_secs(2),
    )
    .await
    .expect_err("truncated reply must fail");
    assert!(matches!(error, ZerotierError::Timeout), "{error}");
}

#[tokio::test]
#[ignore]
async fn easytier_cleartext_handshake_and_authentication() {
    let Some(bin) = env_bin("KC_EASYTIER_PEER_BIN") else {
        return skip("easytier", "KC_EASYTIER_PEER_BIN");
    };
    let peer = start(
        &bin,
        &["-mode", "controlled", "-network", "billow", "-secret", "s3cret"],
    );
    let address: SocketAddr = format!("127.0.0.1:{}", peer.port).parse().unwrap();
    let mut session = EasytierSession::connect(
        address,
        "billow",
        "s3cret",
        Duration::from_secs(5),
    )
    .await
    .expect("handshake");
    session.ping(7, Duration::from_secs(3)).await.expect("pong");

    let wrong = start(
        &bin,
        &["-mode", "controlled", "-network", "billow", "-secret", "other"],
    );
    let address: SocketAddr = format!("127.0.0.1:{}", wrong.port).parse().unwrap();
    let error = EasytierSession::connect(address, "billow", "s3cret", Duration::from_secs(3))
        .await
        .expect_err("wrong secret must fail");
    assert!(
        matches!(
            error,
            EasytierError::Timeout | EasytierError::Io(_) | EasytierError::Frame(_)
        ),
        "{error}"
    );

    let rejected = start(
        &bin,
        &[
            "-mode",
            "controlled",
            "-network",
            "billow",
            "-secret",
            "s3cret",
            "-reject",
        ],
    );
    let address: SocketAddr = format!("127.0.0.1:{}", rejected.port).parse().unwrap();
    assert!(
        EasytierSession::connect(address, "billow", "s3cret", Duration::from_secs(2))
            .await
            .is_err()
    );
}

#[tokio::test]
#[ignore]
async fn easytier_pinned_core_rejects_a_non_matching_digest() {
    // Boundary against the real locked core: its `network_secret_digest` is
    // derived inside the wasm artifact by a routine that is not in the public
    // source tree, so this adapter cannot reproduce it offline. The core
    // replies to the cleartext handshake and then resets the connection when
    // the digest does not match; that is the authentication boundary recorded
    // for T19, not a silent success.
    let Some(bin) = env_bin("KC_EASYTIER_PEER_BIN") else {
        return skip("easytier-core", "KC_EASYTIER_PEER_BIN");
    };
    if std::env::var("KC_EASYTIER_CORE").as_deref() == Ok("0") {
        eprintln!("SKIP easytier-core: KC_EASYTIER_CORE=0");
        return;
    }
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let listen = format!("127.0.0.1:{port}");
    let peer = start(
        &bin,
        &[
            "-mode",
            "core",
            "-listen",
            &listen,
            "-network",
            "billow",
            "-secret",
            "s3cret",
        ],
    );
    assert_eq!(peer.port, port);
    let address: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut observed = None;
    for _ in 0..40 {
        match EasytierSession::connect(address, "billow", "s3cret", Duration::from_secs(2)).await {
            Ok(mut session) => {
                if let Err(error) = session.ping(9, Duration::from_secs(2)).await {
                    observed = Some(format!("{error}"));
                    break;
                }
                panic!("the pinned core accepted the placeholder digest");
            }
            Err(error) => {
                observed = Some(format!("{error}"));
                if matches!(error, EasytierError::SecretDigest) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
    let observed = observed.expect("a handshake attempt");
    assert!(
        observed.contains("reset")
            || observed.contains("Timeout")
            || observed.contains("secret")
            || observed.contains("digest")
            || observed.contains("eof")
            || observed.contains("io:"),
        "{observed}"
    );
}

#[tokio::test]
#[ignore]
async fn tailscale_control_noise_and_http2() {
    let Some(bin) = env_bin("KC_TAILSCALE_PEER_BIN") else {
        return skip("tailscale-control", "KC_TAILSCALE_PEER_BIN");
    };
    let peer = start(&bin, &["-mode", "control"]);
    let control_public: [u8; 32] = hex::decode(&peer.token)
        .expect("hex key")
        .try_into()
        .expect("32-byte key");
    let machine = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let machine_private = machine.to_bytes();
    let tls = ClientTls::new(&[]);
    let control = TailscaleControl::connect(
        &format!("http://127.0.0.1:{}", peer.port),
        machine_private,
        control_public,
        39,
        Duration::from_secs(5),
        &tls,
    )
    .await
    .expect("control handshake");
    let (status, body) = control
        .post_json("/machine/map", "{\"Version\":39}", Duration::from_secs(5))
        .await
        .expect("map request");
    assert_eq!(status, 200);
    assert!(String::from_utf8_lossy(&body).contains("\"Node\""));

    // A different control key cannot complete the Noise handshake.
    let mut wrong = control_public;
    wrong[0] ^= 1;
    let error = match TailscaleControl::connect(
        &format!("http://127.0.0.1:{}", peer.port),
        machine_private,
        wrong,
        39,
        Duration::from_secs(3),
        &tls,
    )
    .await
    {
        Ok(_) => panic!("wrong control key must fail"),
        Err(error) => error,
    };
    assert!(
        matches!(
            error,
            TailscaleError::Authentication | TailscaleError::Io(_) | TailscaleError::Handshake(_)
                | TailscaleError::Timeout
        ),
        "{error}"
    );
}

#[tokio::test]
#[ignore]
async fn tailscale_derp_greeting_and_ping() {
    let Some(bin) = env_bin("KC_TAILSCALE_PEER_BIN") else {
        return skip("tailscale-derp", "KC_TAILSCALE_PEER_BIN");
    };
    let peer = start(&bin, &["-mode", "derp"]);
    let server_public: [u8; 32] = hex::decode(&peer.token)
        .expect("hex key")
        .try_into()
        .expect("32-byte key");
    let client = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let stream = TcpStream::connect(("127.0.0.1", peer.port)).await.unwrap();
    let mut derp_client = DerpClient::connect(
        Box::new(stream),
        client.to_bytes(),
        Some(server_public),
        Duration::from_secs(5),
    )
    .await
    .expect("DERP greeting");
    assert_eq!(derp_client.server_public, server_public);
    let pong = derp_client
        .ping([1, 2, 3, 4, 5, 6, 7, 8], Duration::from_secs(5))
        .await
        .expect("pong");
    assert_eq!(pong, [1, 2, 3, 4, 5, 6, 7, 8]);
    derp_client
        .send_packet([9u8; 32], b"packet")
        .await
        .expect("send packet");
    let (kind, body) = derp_client
        .read_frame(Duration::from_secs(5))
        .await
        .expect("recv frame");
    assert_eq!(kind, derp::FRAME_RECV_PACKET);
    assert_eq!(body, b"packet");

    // A pinned server key mismatch is an authentication failure.
    let stream = TcpStream::connect(("127.0.0.1", peer.port)).await.unwrap();
    let mut wrong = server_public;
    wrong[0] ^= 1;
    let error = match DerpClient::connect(
        Box::new(stream),
        client.to_bytes(),
        Some(wrong),
        Duration::from_secs(3),
    )
    .await
    {
        Ok(_) => panic!("wrong DERP key must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, TailscaleError::DerpAuthentication), "{error}");
}
